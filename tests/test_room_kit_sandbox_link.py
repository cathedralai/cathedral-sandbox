"""AB#389: the create receipt signs the Cathedral sandbox id the create's labels name.

The Cathedral API puts the sandbox id its customer holds in the cathedral_sandbox_id
label of every sealed create. The guest signs it into the create receipt, so a
customer can tie that id to the room without the API's word. Receipts without it
(older guests, other callers) stay valid.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_room_kit_tunables import _call, _sealed_front

KIT = Path(__file__).resolve().parents[1] / "room-kit"
SANDBOX = "0f1e2d3c-4b5a-4968-8776-655443322110"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rr = _load("room_receipts_link_t", KIT / "room_receipts.py")
vr = _load("verify_receipts_link_t", KIT / "verify_receipts.py")


def _header(headers: dict) -> dict:
    raw = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))


@pytest.mark.parametrize("labels, want", [
    ({"cathedral_sandbox_id": SANDBOX}, SANDBOX),
    ({"cathedral_sandbox_id": SANDBOX, "broker_guest": "polaris", "customer": "ditto"}, SANDBOX),
    ({"cathedral_sandbox_id": SANDBOX.upper()}, None),       # the API writes str(uuid): lower case
    ({"cathedral_sandbox_id": SANDBOX + "\n"}, None),
    ({"cathedral_sandbox_id": " " + SANDBOX}, None),
    ({"cathedral_sandbox_id": SANDBOX.replace("-", "")}, None),
    ({"cathedral_sandbox_id": "sbx_1"}, None),
    ({"cathedral_sandbox_id": 7}, None),
    ({"cathedral_sandbox_id": [SANDBOX]}, None),
    ({"polaris_sandbox_id": SANDBOX}, None),                 # only the one label counts
    ({}, None),
    (None, None),
    ("cathedral_sandbox_id=" + SANDBOX, None),
])
def test_only_a_lower_case_uuid_in_the_label_is_signed(labels, want) -> None:
    req = {"image": "alpine:3.20"} if labels is None else {"image": "alpine:3.20", "labels": labels}
    assert rr.Handler.sandbox_link("create", req) == want


def test_only_a_create_names_the_sandbox() -> None:
    req = {"labels": {"cathedral_sandbox_id": SANDBOX}}
    for action in ("exec", "process_start", "delete", "network_set", "bulk_delete"):
        assert rr.Handler.sandbox_link(action, req) is None
    assert rr.Handler.sandbox_link("create", [req]) is None


def test_the_create_receipt_signs_the_sandbox_id_and_the_verifier_lists_the_link(tmp_path, monkeypatch) -> None:
    front, api, ledger = _sealed_front(tmp_path, monkeypatch, {"id": "r1"})
    port = front.server_address[1]
    try:
        status, headers, _ = _call(port, "POST", "/v1/sandboxes", {
            "image": "alpine:3.20", "labels": {"cathedral_sandbox_id": SANDBOX, "broker_guest": "polaris"}})
        assert status == 202
        created = _header(headers)
        st = created["statement"]
        assert st["action"] == "create" and st["sandbox_id"] == "r1" and st["cathedral_sandbox_id"] == SANDBOX
        # The room's create receipt, as /room/attest serves it, names the sandbox too (this fake
        # API names every room r1, so ask before the next create).
        status, _h, out = _call(port, "POST", "/room/attest", {"report_data_hex": "ab" * 64, "sandbox_id": "r1"})
        assert status == 200 and out["room"]["create_receipt"]["statement"]["cathedral_sandbox_id"] == SANDBOX
        # A create with no such label is signed as before: no field, not null.
        status, headers, _ = _call(port, "POST", "/v1/sandboxes", {"image": "alpine:3.20"})
        assert status == 202
        plain = _header(headers)
        assert "cathedral_sandbox_id" not in plain["statement"]
        # Later receipts of the room do not repeat it.
        status, headers, _ = _call(port, "POST", "/v1/sandboxes/r1/exec", {
            "cmd": ["true"], "labels": {"cathedral_sandbox_id": SANDBOX}})
        assert "cathedral_sandbox_id" not in _header(headers)["statement"]

        att = ledger.attestation()
        assert vr.verify_receipts(att, ledger.chain, ledger.head)["signatures_ok"] == 3
        assert vr.room_links(ledger.chain) == {"r1": SANDBOX}
        # The guest signed the id: another one in its place does not verify.
        moved = json.loads(json.dumps(created))
        moved["statement"]["cathedral_sandbox_id"] = "11111111-2222-4333-8444-555555555555"
        moved["receipt_sha256"] = vr.sha(vr.canonical(moved["statement"]))
        with pytest.raises(vr.Fail, match="signature does not verify"):
            vr.verify_receipts(att, [moved], None)
    finally:
        front.shutdown()
        api.shutdown()


def test_the_verifier_refuses_a_malformed_link_and_skips_a_failed_create() -> None:
    def create(**fields):
        return {"statement": {"sequence": 4, "action": "create", "sandbox_id": "r1", "status": 202, **fields}}

    assert vr.room_links([create()]) == {}, "a receipt from before AB#389 lists no link"
    assert vr.room_links([create(cathedral_sandbox_id=SANDBOX)]) == {"r1": SANDBOX}
    assert vr.room_links([create(cathedral_sandbox_id=SANDBOX, status=409)]) == {}
    for bad in (SANDBOX.upper(), "sbx_1", None, 7):
        with pytest.raises(vr.Fail, match="receipt 4: cathedral_sandbox_id is not a lower-case UUID"):
            vr.room_links([create(cathedral_sandbox_id=bad)])


def test_verifier_cli_checks_the_sandbox_id(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    ledger = rr.Ledger("room-a", str(tmp_path / "store"))
    base = {"target": "POST /v1/sandboxes", "sandbox_id": "sbx_1", "customer_request_sha256": "aa" * 32,
            "command_sha256": None, "image": "alpine:3.20", "image_digest": None, "result_sha256": "bb" * 32}
    ledger.sign({**base, "action": "create", "status": 201, "cathedral_sandbox_id": SANDBOX})
    att = tmp_path / "attestation.json"
    chain = tmp_path / "receipts.json"
    att.write_text(json.dumps(ledger.attestation()))
    chain.write_text(json.dumps({"binding_sha256": ledger.binding_sha256, "head": ledger.head, "receipts": ledger.chain}))

    def run(*flags):
        proc = subprocess.run([sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(att),
                               "--receipts", str(chain), *flags], capture_output=True, text=True, check=False)
        return proc.returncode, json.loads(proc.stdout)

    code, out = run("--cathedral-sandbox", SANDBOX)
    assert code == 0 and out["verdict"] == "PASS", out
    assert out["room_links"] == {"sbx_1": SANDBOX}
    assert out["sandbox_link"] == {"cathedral_sandbox_id": SANDBOX, "rooms": ["sbx_1"]}
    other = "11111111-2222-4333-8444-555555555555"
    code, out = run("--cathedral-sandbox", other)
    assert code == 1 and out == {"verdict": "FAIL", "reason": f"no successful create receipt names Cathedral sandbox {other}"}
    code, out = run()
    assert code == 0 and "sandbox_link" not in out
