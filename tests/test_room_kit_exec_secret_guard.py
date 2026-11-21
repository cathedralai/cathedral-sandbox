"""Real guest front, crypto, private files and local HTTP; no live hardware claim."""
from __future__ import annotations

import base64
import copy
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from test_room_kit_sealed_exec import (
    Api, Client, ROOM, _create, _front, _ledger, _post, _receipt, canonical, rr,
)


@pytest.fixture
def guarded(tmp_path, monkeypatch):
    ledger, _ = _ledger(tmp_path, monkeypatch, secrets=True)
    incarnation = _create(ledger)
    root = Path(ledger.secrets.root) / ROOM
    root.mkdir()
    api = Api()
    port = _front(ledger, api.port)

    def envelope(name="TOKEN", version=1, value=b"guard-test-value"):
        return rr.seal_secret(value, ledger.secrets.private.public_key(),
                              binding_sha256=ledger.binding_sha256, sandbox_id=ROOM,
                              room_create_receipt_sha256=incarnation, name=name, version=version)

    doc = envelope()
    ledger.write_sealed_secret(ROOM, doc)
    required = [{"name": "TOKEN", "version": 1, "envelope_sha256": rr.sha(canonical(doc))}]
    return ledger, api, port, Client(ledger), root, envelope, required, doc


def run(guarded, required=None):
    ledger, api, port, client, root, envelope, expected, original = guarded
    request = {"cmd": ["cat", "/run/secrets/TOKEN"], "required_secrets": expected if required is None else required}
    doc, key = client.seal(request=request)
    status, headers, reply = _post(port, doc)
    if status != 200:
        return status, json.loads(reply), headers
    receipt = _receipt(headers)
    Ed25519PublicKey.from_public_bytes(base64.b64decode(ledger.binding["receipt_key_ed25519_b64"])).verify(
        base64.b64decode(receipt["signature_b64"]), canonical(receipt["statement"]))
    assert receipt["statement"]["sealed_request_sha256"] == rr.sha(canonical(doc))
    assert receipt["statement"]["sealed_response_sha256"] == rr.sha(canonical(json.loads(reply)["sealed_response"]))
    return status, client.open(reply, doc, key), headers


def test_exact_file_checked_and_replacement_blocked_during_dispatch(guarded, monkeypatch):
    ledger, api, port, client, root, envelope, required, original = guarded
    upstream = rr.Handler.upstream
    checked = []

    def during(self, *args, **kwargs):
        if kwargs.get("path", "").endswith("/exec-sealed"):
            checked.append((root / "TOKEN").read_bytes())
            with pytest.raises(rr.SecretRefused, match="sealed_secret_in_use"):
                ledger.write_sealed_secret(ROOM, envelope(version=2))
            # Other names and an exact retry of the held write remain usable.
            ledger.write_sealed_secret(ROOM, envelope(name="OTHER"))
            assert ledger.write_sealed_secret(ROOM, original)[0]["status"] == "unchanged"
        return upstream(self, *args, **kwargs)

    monkeypatch.setattr(rr.Handler, "upstream", during)
    assert run(guarded)[1]["status"] == 200
    assert checked == [b"guard-test-value"] and len(api.execs()) == 1
    assert "required_secrets" not in json.loads(api.execs()[0][3])
    assert ledger.write_sealed_secret(ROOM, envelope(version=2))[0]["status"] == "written"


@pytest.mark.parametrize("change", ["missing", "replaced", "symlink", "hardlink", "mode", "edited",
                                     "version", "envelope", "receipt", "untracked", "disabled"])
def test_mismatch_is_signed_sealed_refusal_without_command(guarded, change):
    ledger, api, port, client, root, envelope, required, original = guarded
    path = root / "TOKEN"
    entry = ledger.secrets.accepted(ROOM, ledger.room_incarnation(ROOM))["TOKEN"]
    if change == "missing":
        path.unlink()
    elif change == "replaced":
        path.rename(root / "old")
        path.write_bytes(b"guard-test-value")
        path.chmod(0o444)
    elif change == "symlink":
        path.rename(root / "old")
        path.symlink_to(root / "old")
    elif change == "hardlink":
        os.link(path, root / "alias")
    elif change == "mode":
        path.chmod(0o644)
    elif change == "edited":
        path.chmod(0o644)
        path.write_bytes(b"substituted-value")
        path.chmod(0o444)
    elif change == "version":
        required[0]["version"] += 1
    elif change == "envelope":
        required[0]["envelope_sha256"] = "0" * 64
    elif change == "receipt":
        entry.receipt = None
    elif change == "untracked":
        ledger.secrets.rooms.clear()
    elif change == "disabled":
        ledger.secrets = None
    status, opened, _ = run(guarded)
    assert status == 200 and opened["status"] == 409
    assert opened["answer"]["error"]["code"] == "sealed_exec_secret_unconfirmed"
    assert api.execs() == [] and entry.exec_holds == 0


@pytest.mark.parametrize("bad", [None, [], {}, [None], [True], [{"name": "../TOKEN", "version": 1, "envelope_sha256": "a" * 64}],
                                  [{"name": "TOKEN", "version": True, "envelope_sha256": "a" * 64}],
                                  [{"name": "TOKEN", "version": 0, "envelope_sha256": "a" * 64}],
                                  [{"name": "TOKEN", "version": 1, "envelope_sha256": "a" * 63}],
                                  [{"name": "TOKEN", "version": 1, "envelope_sha256": "a" * 64, "extra": 1}]])
def test_bad_requirement_shape_is_refused_before_upstream(guarded, bad):
    ledger, api, port, client, root, envelope, required, original = guarded
    doc, _ = client.seal(request={"cmd": ["true"], "required_secrets": bad})
    assert _post(port, doc)[0] == 400
    assert api.execs() == []


def test_duplicate_and_oversized_requirements_refuse(guarded):
    required = guarded[6]
    for count in (2, rr.SECRETS_MAX_PER_ROOM + 1):
        assert run(guarded, required * count)[0] == 400
    assert guarded[1].execs() == []


def test_all_requirements_checked_before_any_hold(guarded):
    required = copy.deepcopy(guarded[6])
    required.append({**required[0], "name": "MISSING"})
    assert run(guarded, required)[1]["status"] == 409
    ledger, _, _, _, _, envelope, _, _ = guarded
    # Refusal did not pin the earlier valid entry.
    assert ledger.write_sealed_secret(ROOM, envelope(version=2))[0]["status"] == "written"


@pytest.mark.parametrize("response", ["timeout", "cancelled", "bad_json", "error", "missing_status", "bool_exit", "malformed_result"])
def test_unknown_completion_retains_hold(guarded, response):
    ledger, api, _, _, _, envelope, _, _ = guarded
    if response == "timeout":
        api.answer = canonical({"exit_code": 124, "timed_out": True})
    elif response == "cancelled":
        api.answer = canonical({"exit_code": 143, "timed_out": False, "cancelled": True})
    elif response == "bad_json":
        api.answer = b"broken"
    elif response == "error":
        api.status = 503
    elif response == "missing_status":
        api.answer = canonical({"exit_code": 0})
    elif response == "malformed_result":
        api.answer = canonical({"exit_code": 0, "timed_out": False, "stdout": None, "stderr": ""})
    elif response == "bool_exit":
        api.answer = canonical({"exit_code": True, "timed_out": False})
    run(guarded)
    with pytest.raises(rr.SecretRefused, match="sealed_secret_in_use"):
        ledger.write_sealed_secret(ROOM, envelope(version=2))
    assert len(api.execs()) == 1


def test_two_concurrent_commands_keep_independent_holds(guarded, monkeypatch):
    ledger, _, _, _, _, envelope, _, _ = guarded
    upstream = rr.Handler.upstream
    both = threading.Barrier(3)
    gates = [threading.Event(), threading.Event()]
    counter = []
    counter_lock = threading.Lock()

    def wait(self, *args, **kwargs):
        if kwargs.get("path", "").endswith("/exec-sealed"):
            with counter_lock:
                i = len(counter)
                counter.append(i)
            both.wait(timeout=5)
            assert gates[i].wait(5)
        return upstream(self, *args, **kwargs)

    monkeypatch.setattr(rr.Handler, "upstream", wait)
    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(run, guarded) for _ in range(2)]
        try:
            both.wait(timeout=5)
            with pytest.raises(rr.SecretRefused, match="sealed_secret_in_use"):
                ledger.write_sealed_secret(ROOM, envelope(version=2))
            gates[0].set()
            from concurrent.futures import wait as wait_futures, FIRST_COMPLETED
            done, _ = wait_futures(futures, timeout=5, return_when=FIRST_COMPLETED)
            assert len(done) == 1
            next(iter(done)).result()
            with pytest.raises(rr.SecretRefused, match="sealed_secret_in_use"):
                ledger.write_sealed_secret(ROOM, envelope(version=2))
        finally:
            for gate in gates:
                gate.set()
        for future in futures:
            assert future.result()[1]["status"] == 200
    assert ledger.write_sealed_secret(ROOM, envelope(version=2))[0]["status"] == "written"
