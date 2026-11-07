"""Customer-sealed commands on the receipts front (room_receipts.py, AB#417).

A sealed guest with ROOM_SEALED_EXEC=1 names a per-boot X25519 key in its
binding, so REPORT_DATA commits to it. A customer seals one exec (cmd, env,
stdin, cwd, user) to that key; the AAD names the binding, the room, its
incarnation, issued_at, the timeout and the key the answer goes to. The front
opens it, runs it through the room API inside the guest, and seals the room
API's whole answer to the client's key. Relays (our API, the Worker, the
broker) carry only ciphertext. The receipt is an exec receipt that signs
sha256 of the plaintext command, as for any exec, and both envelopes.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

KIT = Path(__file__).resolve().parents[1] / "room-kit"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rr = _load("room_receipts_exec_t", KIT / "room_receipts.py")
vr = _load("verify_receipts_exec_t", KIT / "verify_receipts.py")

KEY = b"k1"
ROOM = "sbx_0123456789ab"
COMMAND = ["sh", "-c", "printf %s \"$TOKEN\"; cat"]
ENV = {"TOKEN": "tok-plaintext-env-4242"}
STDIN = "stdin-plaintext-9191"
OUTPUT = "output-plaintext-7373"
CONFIG_BINDING_KEYS = {"schema", "hotel", "boot_id", "created_at", "receipt_key_ed25519_b64", "measurement", "chip_id",
                       "reported_tcb", "policy", "host_data", "kernel_cmdline", "kernel_release", "software", "tenancy"}
PLAINTEXT = [json.dumps(COMMAND)[1:-1].encode(), b"tok-plaintext-env-4242", b"stdin-plaintext-9191",
             b"output-plaintext-7373", b"printf %s"]


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _fake_report(report_data: bytes) -> bytes:
    report = bytearray(0x4A0)
    report[0:4] = (3).to_bytes(4, "little")
    report[0x08:0x10] = (0x30000).to_bytes(8, "little")
    report[0x50:0x90] = report_data
    report[0x90:0xC0] = bytes.fromhex("ab" * 48)
    report[0xC0:0xE0] = bytes.fromhex("cd" * 32)
    report[0x180:0x188] = bytes.fromhex("01" * 8)
    report[0x1A0:0x1E0] = bytes.fromhex("ef" * 64)
    return bytes(report)


def _ledger(tmp_path, monkeypatch, *, sealed_exec: bool = True, sealed: bool = True, secrets: bool = False):
    asked: list[bytes] = []

    def report(data: bytes) -> bytes:
        asked.append(data)
        return _fake_report(data)

    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest" if sealed else None)
    monkeypatch.setattr(rr, "snp_report", report)
    box = rr.SealedExec() if sealed_exec else None
    root = tmp_path / "room-secrets"
    root.mkdir(parents=True, exist_ok=True)
    ledger = rr.Ledger("room-a", str(tmp_path / "store"), secrets=rr.SealedSecrets(str(root)) if secrets else None,
                       sealed_exec=box)
    return ledger, asked


class Api:
    """The room API behind the front: records every call and answers as told."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, dict, bytes]] = []
        self.status = 200
        self.answer: bytes = canonical({"exit_code": 3, "stdout": OUTPUT, "stderr": "", "duration_ms": 5,
                                        "timed_out": False, "truncated": False})
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def answer(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.seen.append((self.command, self.path, dict(self.headers), self.rfile.read(n) if n else b""))
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(outer.answer)))
                self.end_headers()
                self.wfile.write(outer.answer)

            do_GET = do_POST = do_DELETE = answer  # noqa: N815

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]

    def execs(self):
        return [s for s in self.seen if s[1].endswith(("/exec", "/exec-sealed"))]


def _front(ledger, api_port: int):
    server = rr.Server(("127.0.0.1", 0), ledger, api_port, 1, KEY, "/nonexistent.sock")
    Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def _request(port: int, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    sent = {"Authorization": "Bearer " + KEY.decode(), **(headers or {})}
    if body is not None:
        sent["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=sent)
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _create(ledger, room: str = ROOM) -> str:
    return ledger.sign({"action": "create", "target": "POST /v1/sandboxes", "sandbox_id": room,
                        "status": 202})["receipt_sha256"]


class Client:
    """What ctcli does after checking the attestation: the key from the binding, a fresh answer key."""

    def __init__(self, ledger):
        att = ledger.attestation()
        self.binding = att["binding"]
        self.binding_sha256 = att["binding_sha256"]
        self.recipient = X25519PublicKey.from_public_bytes(
            base64.b64decode(att["binding"]["sealed_exec"]["x25519_public_b64"]))
        self.ledger = ledger

    def seal(self, room: str = ROOM, request: dict | None = None, *, issued_at: int | None = None,
             timeout_seconds: int = 30, incarnation: str | None = None, answer_key: X25519PrivateKey | None = None):
        answer_key = answer_key or X25519PrivateKey.generate()
        doc = rr.seal_exec_request(
            request if request is not None else {"cmd": COMMAND, "env": ENV, "stdin": STDIN, "cwd": "/work"},
            self.recipient, binding_sha256=self.binding_sha256, sandbox_id=room,
            room_create_receipt_sha256=incarnation or self.ledger.room_incarnation(room) or "0" * 64,
            issued_at=int(time.time()) if issued_at is None else issued_at, timeout_seconds=timeout_seconds,
            response_public_b64=base64.b64encode(answer_key.public_key().public_bytes_raw()).decode())
        return doc, answer_key

    def open(self, reply: bytes, doc: dict, answer_key: X25519PrivateKey) -> dict:
        return json.loads(rr.open_exec_response(json.loads(reply)["sealed_response"], answer_key, doc))


def _post(port: int, doc: dict, room: str = ROOM):
    return _request(port, "POST", f"/v1/sandboxes/{room}/sealed-exec", canonical(doc))


def _receipt(headers: dict) -> dict:
    h = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))


def _code(body: bytes) -> str:
    return json.loads(body)["error"]["code"]


@pytest.fixture
def guest(tmp_path, monkeypatch):
    ledger, _ = _ledger(tmp_path, monkeypatch)
    api = Api()
    port = _front(ledger, api.port)
    _create(ledger)
    return ledger, api, port, Client(ledger)


# ---------------------------------------------------------------- the binding

def test_flag_off_leaves_the_binding_as_it_was(tmp_path, monkeypatch) -> None:
    ledger, asked = _ledger(tmp_path, monkeypatch, sealed_exec=False)
    assert set(ledger.binding) == CONFIG_BINDING_KEYS
    assert ledger.sealed_exec is None
    assert asked[-1] == bytes.fromhex(ledger.binding_sha256) + bytes(32)


def test_flag_on_names_the_key_in_the_binding_that_report_data_commits_to(tmp_path, monkeypatch) -> None:
    ledger, asked = _ledger(tmp_path, monkeypatch)
    assert set(ledger.binding) == CONFIG_BINDING_KEYS | {"sealed_exec"}
    assert ledger.binding["sealed_exec"] == {"schema": "cathedral_sealed_exec_v1",
                                             "algorithm": "x25519-hkdf-sha256-aes256gcm-v1",
                                             "x25519_public_b64": ledger.sealed_exec.public_b64}
    raw = ledger.sealed_exec.private.public_key().public_bytes_raw()
    assert base64.b64decode(ledger.sealed_exec.public_b64) == raw
    assert ledger.binding_sha256 == hashlib.sha256(canonical(ledger.binding)).hexdigest()
    assert asked[-1] == bytes.fromhex(ledger.binding_sha256) + bytes(32)
    assert "private" not in repr(ledger.sealed_exec).lower()


def test_level1_never_offers_the_key(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch, sealed=False)
    assert ledger.sealed_exec is None and "sealed_exec" not in ledger.binding


def test_sealed_secrets_and_sealed_exec_use_two_keys(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch, secrets=True)
    assert {"sealed_secrets", "sealed_exec"} <= set(ledger.binding)
    assert ledger.binding["sealed_secrets"]["x25519_public_b64"] != ledger.binding["sealed_exec"]["x25519_public_b64"]


def test_the_current_verifier_passes_the_binding_and_the_sealed_exec_receipt(guest, tmp_path) -> None:
    ledger, api, port, client = guest
    doc, _ = client.seal()
    status, _, _ = _post(port, doc)
    assert status == 200
    att, chain = ledger.attestation(), list(ledger.chain)
    assert vr.verify_attestation(att, "ab" * 48, None, str(tmp_path / "kds"), None, skip_amd=True)["measurement"] == "ab" * 48
    (tmp_path / "att.json").write_text(json.dumps(att))
    (tmp_path / "chain.json").write_text(json.dumps({"receipts": chain, "head": ledger.head}))
    proc = subprocess.run([os.sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(tmp_path / "att.json"),
                           "--receipts", str(tmp_path / "chain.json"), "--skip-amd", "--require-sealed"],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["chain"]["actions"] == {"create": 1, "exec": 1}
    # The verifier hashes the binding whole: a swapped sealed exec key is a REPORT_DATA failure.
    att["binding"]["sealed_exec"]["x25519_public_b64"] = base64.b64encode(bytes(32)).decode()
    att["binding_sha256"] = hashlib.sha256(canonical(att["binding"])).hexdigest()
    with pytest.raises(vr.Fail, match="REPORT_DATA"):
        vr.verify_attestation(att, "ab" * 48, None, str(tmp_path / "kds"), None, skip_amd=True)


# ---------------------------------------------------------------- one sealed exec, end to end through the front

def test_a_sealed_exec_runs_in_the_room_and_only_the_client_reads_the_answer(guest) -> None:
    ledger, api, port, client = guest
    doc, answer_key = client.seal()
    body = canonical(doc)
    status, headers, reply = _post(port, doc)
    assert status == 200, reply

    # The room API, inside the guest, got the plaintext exec on its sealed route, with the authenticated timeout.
    [(method, path, _, sent)] = api.execs()
    assert (method, path) == ("POST", f"/v1/sandboxes/{ROOM}/exec-sealed")
    assert json.loads(sent) == {"cmd": COMMAND, "env": ENV, "stdin": STDIN, "cwd": "/work", "user": None,
                                "timeout_seconds": 30}

    # What a relay sees, request and answer: no command, env, stdin or output.
    for seen in (body, reply, headers["X-Room-Receipt"].encode()):
        for secret in PLAINTEXT:
            assert secret not in seen
    assert set(json.loads(reply)) == {"sealed_response"}

    opened = client.open(reply, doc, answer_key)
    assert opened == {"status": 200, "answer": json.loads(api.answer)}

    # The receipt: an exec receipt over the plaintext command, as today, plus both envelopes.
    receipt = _receipt(headers)
    st = receipt["statement"]
    assert st["action"] == "exec" and st["sealed"] is True and st["status"] == 200
    assert st["sandbox_id"] == ROOM and st["target"] == f"POST /v1/sandboxes/{ROOM}/sealed-exec"
    assert st["command_sha256"] == hashlib.sha256(canonical(COMMAND)).hexdigest()
    assert st["customer_request_sha256"] == hashlib.sha256(body).hexdigest()
    assert st["result_sha256"] == hashlib.sha256(reply).hexdigest()
    assert st["sealed_request_sha256"] == hashlib.sha256(canonical(doc)).hexdigest()
    assert st["sealed_response_sha256"] == hashlib.sha256(canonical(json.loads(reply)["sealed_response"])).hexdigest()
    assert st["room_create_receipt_sha256"] == ledger.room_incarnation(ROOM)
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(ledger.binding["receipt_key_ed25519_b64"]))
    key.verify(base64.b64decode(receipt["signature_b64"]), canonical(st))
    assert receipt["receipt_sha256"] == hashlib.sha256(canonical(st)).hexdigest()


def test_only_the_answer_key_opens_the_answer(guest) -> None:
    _, _, port, client = guest
    doc, answer_key = client.seal()
    _, _, reply = _post(port, doc)
    with pytest.raises(rr.PlantError):
        client.open(reply, doc, X25519PrivateKey.generate())
    # Nor with the guest's own request key: the answer goes to the client's key only.
    with pytest.raises(rr.PlantError):
        client.open(reply, doc, client.ledger.sealed_exec.private)
    assert client.open(reply, doc, answer_key)["status"] == 200


def test_an_answer_never_opens_as_the_answer_to_another_request(guest) -> None:
    _, _, port, client = guest
    key = X25519PrivateKey.generate()
    one, _ = client.seal(answer_key=key)
    two, _ = client.seal(answer_key=key)
    _, _, reply_one = _post(port, one)
    _, _, reply_two = _post(port, two)
    assert client.open(reply_one, one, key)["status"] == 200
    with pytest.raises(rr.PlantError):
        client.open(reply_one, two, key)
    # Same request_sha256 written over: the AAD still names the first request.
    swapped = json.loads(reply_one)
    swapped["sealed_response"]["request_sha256"] = hashlib.sha256(canonical(two)).hexdigest()
    with pytest.raises(rr.PlantError):
        client.open(canonical(swapped), two, key)
    assert client.open(reply_two, two, key)["status"] == 200


def test_every_seal_draws_fresh_keys_and_nonces_both_ways(guest) -> None:
    _, _, port, client = guest
    key = X25519PrivateKey.generate()
    docs = [client.seal(answer_key=key)[0] for _ in range(3)]
    answers = [json.loads(_post(port, d)[2])["sealed_response"] for d in docs]
    for field in ("ephemeral_public_b64", "nonce_b64", "ciphertext_b64"):
        assert len({d[field] for d in docs}) == 3, field
        assert len({a[field] for a in answers}) == 3, field
    assert all(base64.b64decode(d["nonce_b64"]) != bytes(12) for d in docs + answers)


@pytest.mark.parametrize("path", [
    f"/v1/sandboxes/{ROOM}/exec-sealed",
    f"/v1/sandboxes/{ROOM}/exec-sealed;x=1",      # urlparse, as the API parses, drops ";params"
    f"/v1/sandboxes/{ROOM}/exec%2Dsealed",
    f"/v1/sandboxes/{ROOM}/exec-sealed?cmd=true",
    "/v1/sandboxes/a%2Fb/exec-sealed",              # the API's raw match takes a%2Fb as one id
])
def test_no_caller_reaches_the_room_apis_sealed_route(guest, path) -> None:
    # That route runs an exec with no history or log, and the front signs no receipt for it.
    _, api, port, _ = guest
    status, _, body = _request(port, "POST", path, canonical({"cmd": ["true"]}))
    assert (status, _code(body)) == (404, "route_not_found")
    assert api.seen == []


def test_an_api_without_the_sealed_route_runs_nothing(guest) -> None:
    # A guest built with ROOM_SEALED_EXEC=1 and an older pool-room API tarball: the API's
    # 404 comes back sealed, and the command never ran, so it is in no history or log.
    _, api, port, client = guest
    api.status = 404
    api.answer = canonical({"error": {"code": "route_not_found", "message": "no route for POST ..."}})
    doc, key = client.seal()
    status, _, reply = _post(port, doc)
    assert status == 200
    assert client.open(reply, doc, key) == {"status": 404, "answer": json.loads(api.answer)}


def test_a_room_api_error_stays_inside_the_sealed_answer(guest) -> None:
    _, api, port, client = guest
    api.status = 400
    api.answer = canonical({"error": {"code": "invalid_cwd", "message": "path must be absolute: '/srv/plaintext-cwd'"}})
    doc, key = client.seal()
    status, headers, reply = _post(port, doc)
    assert status == 200 and b"plaintext-cwd" not in reply and b"invalid_cwd" not in reply
    assert client.open(reply, doc, key) == {"status": 400, "answer": json.loads(api.answer)}
    assert _receipt(headers)["statement"]["status"] == 200


def test_a_room_api_that_does_not_answer_is_a_sealed_502(guest) -> None:
    ledger, api, port, client = guest
    api.server.shutdown()
    api.server.server_close()
    doc, key = client.seal()
    status, _, reply = _post(port, doc)
    assert status == 200
    opened = client.open(reply, doc, key)
    assert opened["status"] == 502 and opened["answer"]["error"]["code"] == "hotel_api_no_answer"


def test_a_non_json_answer_comes_back_whole(guest) -> None:
    _, api, port, client = guest
    api.answer = b"\x00\xffnot json"
    doc, key = client.seal()
    opened = client.open(_post(port, doc)[2], doc, key)
    assert opened["answer"] is None and base64.b64decode(opened["answer_b64"]) == b"\x00\xffnot json"


def test_a_room_that_died_under_the_command_is_said_in_the_clear(guest) -> None:
    _, api, port, client = guest
    api.answer = canonical({"exit_code": 137, "stdout": OUTPUT, "stderr": "", "duration_ms": 5, "timed_out": False,
                            "truncated": False, "oom_killed": True, "room_alive": False})
    doc, key = client.seal()
    _, _, reply = _post(port, doc)
    outer = json.loads(reply)
    # The API stops billing a dead room on these two; nothing else is in the clear.
    assert (outer["room_alive"], outer["oom_killed"]) == (False, True)
    assert set(outer) == {"sealed_response", "room_alive", "oom_killed"}
    assert OUTPUT.encode() not in reply
    assert client.open(reply, doc, key)["answer"]["exit_code"] == 137


# ---------------------------------------------------------------- replay and freshness

def test_an_envelope_runs_once(guest) -> None:
    _, api, port, client = guest
    doc, _ = client.seal()
    assert _post(port, doc)[0] == 200
    status, _, body = _post(port, doc)
    assert (status, _code(body)) == (409, "sealed_exec_replayed")
    assert len(api.execs()) == 1


def test_two_racing_copies_run_once(guest) -> None:
    ledger, _, _, client = guest
    doc, _ = client.seal()
    outcomes: list[str] = []
    start = threading.Barrier(8)

    def go():
        start.wait()
        try:
            ledger.open_sealed_exec(ROOM, json.loads(canonical(doc)))
            outcomes.append("ran")
        except rr.ExecRefused as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ran") == 1 and outcomes.count("sealed_exec_replayed") == 7


@pytest.mark.parametrize("offset,ok", [(-rr.EXEC_MAX_AGE_SECONDS - 5, False), (-rr.EXEC_MAX_AGE_SECONDS + 5, True),
                                       (rr.EXEC_FUTURE_SKEW_SECONDS - 5, True), (rr.EXEC_FUTURE_SKEW_SECONDS + 5, False)])
def test_issued_at_must_be_in_the_window(guest, offset, ok) -> None:
    _, api, port, client = guest
    doc, _ = client.seal(issued_at=int(time.time()) + offset)
    status, _, body = _post(port, doc)
    if ok:
        assert status == 200
    else:
        assert (status, _code(body)) == (409, "sealed_exec_not_fresh")
        assert abs(json.loads(body)["error"]["guest_time"] - time.time()) < 5
        assert api.execs() == []


def test_an_entry_goes_once_its_issued_at_leaves_the_window(guest) -> None:
    ledger, _, _, client = guest
    now = time.time()
    doc, _ = client.seal(issued_at=int(now))
    ledger.open_sealed_exec(ROOM, doc, now=now)
    assert ledger.sealed_exec.tracked == 1
    later = now + rr.EXEC_MAX_AGE_SECONDS + 1
    # The same envelope later is refused by the window, before the table is asked.
    with pytest.raises(rr.ExecRefused, match="sealed_exec_not_fresh"):
        ledger.open_sealed_exec(ROOM, doc, now=later)
    fresh, _ = client.seal(issued_at=int(later))
    ledger.open_sealed_exec(ROOM, fresh, now=later)
    assert ledger.sealed_exec.tracked == 1


def test_a_full_room_answers_429_and_other_rooms_still_run(guest, monkeypatch) -> None:
    ledger, _, port, client = guest
    monkeypatch.setattr(rr, "EXEC_MAX_PER_ROOM", 2)
    for _ in range(2):
        assert _post(port, client.seal()[0])[0] == 200
    status, headers, body = _post(port, client.seal()[0])
    assert (status, _code(body)) == (429, "sealed_exec_room_busy") and headers["Retry-After"] == "120"
    _create(ledger, "sbx_other")
    assert _post(port, client.seal("sbx_other")[0], "sbx_other")[0] == 200


def test_a_full_boot_table_frees_rooms_that_are_gone(guest, monkeypatch) -> None:
    ledger, _, port, client = guest
    monkeypatch.setattr(rr, "EXEC_MAX_TRACKED", 2)
    monkeypatch.setattr(rr, "SECRETS_SWEEP_SECONDS", 0.0)
    for _ in range(2):
        assert _post(port, client.seal()[0])[0] == 200
    _create(ledger, "sbx_other")
    status, _, body = _post(port, client.seal("sbx_other")[0], "sbx_other")
    assert (status, _code(body)) == (503, "sealed_exec_full")
    # The first room is deleted through the front: its entries go, and the other room runs.
    assert _request(port, "DELETE", f"/v1/sandboxes/{ROOM}")[0] == 200
    assert ledger.sealed_exec.tracked == 0
    assert _post(port, client.seal("sbx_other")[0], "sbx_other")[0] == 200


# ---------------------------------------------------------------- what is refused before anything runs

def test_flag_off_refuses_and_nothing_reaches_the_api(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch, sealed_exec=False)
    api = Api()
    port = _front(ledger, api.port)
    status, _, body = _request(port, "POST", f"/v1/sandboxes/{ROOM}/sealed-exec", b"{}")
    assert (status, _code(body)) == (403, "sealed_exec_disabled") and api.seen == []


def test_no_bearer_is_401(guest) -> None:
    _, api, port, client = guest
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", f"/v1/sandboxes/{ROOM}/sealed-exec", body=canonical(client.seal()[0]))
    assert c.getresponse().status == 401 and api.seen == []


def test_the_room_must_be_live_and_this_incarnation(guest) -> None:
    ledger, api, port, client = guest
    assert _code(_post(port, client.seal("sbx_never", incarnation="1" * 64)[0], "sbx_never")[2]) \
        == "sealed_exec_room_not_found"
    old, _ = client.seal()
    _create(ledger)  # made again under the same id: a new create receipt
    status, _, body = _post(port, old)
    assert (status, _code(body)) == (409, "sealed_exec_wrong_incarnation")
    ledger.sign({"action": "delete", "target": f"DELETE /v1/sandboxes/{ROOM}", "sandbox_id": ROOM, "status": 204})
    status, _, body = _post(port, client.seal(incarnation="2" * 64)[0])
    assert (status, _code(body)) == (404, "sealed_exec_room_not_found")
    assert api.execs() == []


def test_another_boot_or_room_is_refused(guest) -> None:
    ledger, api, port, client = guest
    doc, _ = client.seal()
    other = {**doc, "binding_sha256": "f" * 64}
    assert _code(_post(port, other)[2]) == "sealed_exec_wrong_binding"
    _create(ledger, "sbx_other")
    status, _, body = _post(port, doc, "sbx_other")
    assert (status, _code(body)) == (400, "sealed_exec_wrong_room")
    assert api.execs() == []


def _relay_key() -> str:
    return base64.b64encode(X25519PrivateKey.generate().public_key().public_bytes_raw()).decode()


def _other_room(ledger, doc: dict) -> dict:
    """Point the envelope at another live room, with that room's own incarnation."""
    other = _create(ledger, "sbx_other")
    return {**doc, "sandbox_id": "sbx_other", "room_create_receipt_sha256": other}


def _made_again(ledger, doc: dict) -> dict:
    """The room is made again; the relay names the new incarnation on the old envelope."""
    new = _create(ledger)
    return {**doc, "room_create_receipt_sha256": new}


TAMPER = {
    "timeout_seconds": lambda ledger, doc: {**doc, "timeout_seconds": rr.EXEC_TIMEOUT_MAX},  # would run longer
    "issued_at": lambda ledger, doc: {**doc, "issued_at": doc["issued_at"] - 1},  # would refresh a replay
    "response_public_b64": lambda ledger, doc: {**doc, "response_public_b64": _relay_key()},  # would read the answer
    "sandbox_id": _other_room,
    "room_create_receipt_sha256": _made_again,
}


@pytest.mark.parametrize("field", sorted(TAMPER))
def test_every_header_field_is_bound_into_the_envelope(guest, field) -> None:
    ledger, api, port, client = guest
    doc, _ = client.seal()
    tampered = TAMPER[field](ledger, doc)
    assert tampered[field] != doc[field]
    status, _, body = _post(port, tampered, tampered["sandbox_id"])
    assert (status, _code(body)) == (400, "sealed_exec_does_not_open")
    assert api.execs() == []


@pytest.mark.parametrize("field", ["ephemeral_public_b64", "nonce_b64", "ciphertext_b64"])
def test_a_changed_envelope_does_not_open(guest, field) -> None:
    _, api, port, client = guest
    doc, _ = client.seal()
    raw = bytearray(base64.b64decode(doc[field]))
    raw[0] ^= 1
    status, _, body = _post(port, {**doc, field: base64.b64encode(bytes(raw)).decode()})
    assert status == 400 and _code(body) in ("sealed_exec_does_not_open",)
    assert api.execs() == []


@pytest.mark.parametrize("request_doc", [
    {"cmd": []}, {"cmd": ""}, {"cmd": ["ok", ""]}, {"cmd": ["ok"], "env": {"A": 1}}, {"cmd": ["ok"], "stdin": 3},
    {"cmd": ["ok"], "extra": "x"}, {"env": {}}, ["ok"], "ok", {"cmd": 5}, {"cmd": None}, {"cmd": {"a": "b"}},
])
def test_an_opened_request_must_have_the_exec_shape(guest, request_doc) -> None:
    _, api, port, client = guest
    doc, _ = client.seal(request=request_doc)
    status, _, body = _post(port, doc)
    assert (status, _code(body)) == (400, "sealed_exec_request_invalid") and api.execs() == []


def test_a_refused_request_does_not_burn_its_envelope(guest) -> None:
    ledger, api, port, client = guest
    doc, _ = client.seal(request={"cmd": []})
    assert _post(port, doc)[0] == 400
    assert ledger.sealed_exec.tracked == 0


@pytest.mark.parametrize("field", ["ephemeral_public_b64", "nonce_b64", "ciphertext_b64", "response_public_b64"])
def test_a_lone_surrogate_is_400_and_the_front_keeps_serving(guest, field) -> None:
    _, api, port, client = guest
    doc, _ = client.seal()
    body = canonical(doc).replace(json.dumps(doc[field]).encode(), b'"\\ud800"')
    status, _, out = _request(port, "POST", f"/v1/sandboxes/{ROOM}/sealed-exec", body)
    assert (status, _code(out)) == (400, "sealed_exec_fields_invalid")
    assert _post(port, client.seal()[0])[0] == 200


@pytest.mark.parametrize("key", [bytes(32), b"\x01" + bytes(31), b"short"])
def test_an_unusable_answer_key_is_refused(guest, key) -> None:
    _, api, port, client = guest
    doc, _ = client.seal()
    status, _, body = _post(port, {**doc, "response_public_b64": base64.b64encode(key).decode()})
    assert (status, _code(body)) == (400, "sealed_exec_response_key_invalid") and api.execs() == []


@pytest.mark.parametrize("change", [{"timeout_seconds": 0}, {"timeout_seconds": 14401}, {"timeout_seconds": "30"},
                                    {"issued_at": "1"}, {"issued_at": True}, {"room_create_receipt_sha256": "A" * 64},
                                    {"schema": "cathedral_sealed_exec_v0"}, {"extra": 1}])
def test_malformed_headers_are_refused(guest, change) -> None:
    _, api, port, client = guest
    doc, _ = client.seal()
    status, _, _ = _post(port, {**doc, **change})
    assert status == 400 and api.execs() == []


def test_too_large_is_413(guest) -> None:
    _, api, port, _ = guest
    status, _, body = _request(port, "POST", f"/v1/sandboxes/{ROOM}/sealed-exec", b" " * (rr.EXEC_MAX_BYTES + 1))
    assert (status, _code(body)) == (413, "sealed_exec_too_large") and api.seen == []


# ---------------------------------------------------------------- the real room API behind the real front

@pytest.fixture
def real_room(tmp_path, monkeypatch):
    from cathedral.sandbox_provider import InMemorySandboxProvider
    from cathedral.sandbox_server import SandboxApplication, run

    ledger, _ = _ledger(tmp_path, monkeypatch)
    provider = InMemorySandboxProvider()
    httpd, (_, api_port) = run(SandboxApplication(provider))
    Thread(target=httpd.serve_forever, daemon=True).start()
    port = _front(ledger, api_port)
    status, _, out = _request(port, "POST", "/v1/sandboxes", canonical(
        {"image": "repo/tool:latest", "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 5}}))
    assert status == 202, out
    try:
        yield ledger, port, json.loads(out)["id"], Client(ledger)
    finally:
        httpd.shutdown()
        provider.close()


def test_a_sealed_exec_leaves_nothing_in_the_room_apis_history_or_logs(real_room) -> None:
    ledger, port, room, client = real_room
    doc, key = client.seal(room, {"cmd": ["sh", "-c", 'printf "%s:" "$TOKEN"; cat'], "env": ENV, "stdin": STDIN})
    status, _, reply = _post(port, doc, room)
    assert status == 200, reply
    opened = client.open(reply, doc, key)
    assert opened["status"] == 200
    assert opened["answer"]["stdout"] == f"{ENV['TOKEN']}:{STDIN}" and opened["answer"]["exit_code"] == 0

    status, _, logs = _request(port, "GET", f"/v1/sandboxes/{room}/logs")
    assert status == 200
    record = json.loads(logs)
    assert record["exec_history"] == [] and record["stdout"] == ""
    assert ENV["TOKEN"].encode() not in logs and STDIN.encode() not in logs

    # A plaintext exec is recorded as before, so the change is the sealed one only.
    _request(port, "POST", f"/v1/sandboxes/{room}/exec", canonical({"cmd": ["printf", "plain-visible"]}))
    record = json.loads(_request(port, "GET", f"/v1/sandboxes/{room}/logs")[2])
    assert [r["command"] for r in record["exec_history"]] == ["printf plain-visible"]
    assert "plain-visible" in record["stdout"] and ENV["TOKEN"] not in record["stdout"]


def test_the_timeout_in_the_header_is_the_one_the_room_enforces(real_room) -> None:
    _, port, room, client = real_room
    doc, key = client.seal(room, {"cmd": ["sleep", "5"]}, timeout_seconds=1)
    t0 = time.monotonic()
    opened = client.open(_post(port, doc, room)[2], doc, key)
    assert time.monotonic() - t0 < 4
    assert opened["answer"]["timed_out"] is True


# ---------------------------------------------------------------- review of 58f95a3

def _respellings(value: str) -> list[str]:
    """Every base64 spelling of the same bytes: the last character before the padding varies in its unused bits."""
    raw = base64.b64decode(value, validate=True)
    pad = len(value) - len(value.rstrip("="))
    head, last = value.rstrip("=")[:-1], value.rstrip("=")[-1]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    out = []
    for c in alphabet:
        candidate = head + c + "=" * pad
        if candidate != value and base64.b64decode(candidate, validate=True) == raw:
            out.append(candidate)
    return out


def test_a_respelled_ephemeral_key_is_not_a_new_envelope(guest) -> None:
    # Review finding 1 (HIGH): the 43rd character of a 32-byte key has 2 unused bits. A relay that
    # rewrites them keeps the same key (it still opens) and, keyed on the string, ran it again.
    ledger, api, port, client = guest
    doc, _ = client.seal()
    spellings = _respellings(doc["ephemeral_public_b64"])
    assert len(spellings) == 3
    assert _post(port, doc)[0] == 200
    for spelling in spellings:
        status, _, body = _post(port, {**doc, "ephemeral_public_b64": spelling})
        assert status in (400, 409), body
    assert len(api.execs()) == 1


def test_the_replay_table_is_keyed_on_the_decoded_key(guest) -> None:
    # Even past the spelling check, the table names the key by its bytes.
    ledger, api, _, client = guest
    doc, _ = client.seal()
    ledger.open_sealed_exec(ROOM, doc)
    raw = base64.b64decode(doc["ephemeral_public_b64"])
    [(incarnation, seen)] = ledger.sealed_exec.rooms.values()
    assert list(seen) == [base64.b64encode(raw).decode()]
    assert ledger.sealed_exec.ran(ROOM, incarnation, _respellings(doc["ephemeral_public_b64"])[0])


@pytest.mark.parametrize("field", ["ephemeral_public_b64", "ciphertext_b64"])
def test_a_non_canonical_base64_spelling_is_refused_before_anything_runs(guest, field) -> None:
    # A 12-byte nonce has no spare bits; a ciphertext has them when its length is not a multiple of 3.
    ledger, api, port, client = guest
    for pad in range(3):
        doc, _ = client.seal(request={"cmd": COMMAND, "stdin": "x" * pad})
        respelled = _respellings(doc[field])
        if respelled:
            break
    assert respelled, field
    status, _, body = _post(port, {**doc, field: respelled[0]})
    assert (status, _code(body)) == (400, "sealed_exec_fields_invalid")
    assert api.execs() == [] and ledger.sealed_exec.tracked == 0


def _seal_plaintext(client: "Client", plaintext: bytes, room: str = ROOM) -> dict:
    """An envelope over exact plaintext bytes: what a client that never calls canonical() could send."""
    answer_key = X25519PrivateKey.generate()
    header = rr.exec_header(client.binding_sha256, room, client.ledger.room_incarnation(room), int(time.time()), 30,
                            base64.b64encode(answer_key.public_key().public_bytes_raw()).decode())
    return {**header, **rr._seal_envelope(plaintext, client.recipient, rr.EXEC_HKDF_INFO, rr.exec_aad(header))}


@pytest.mark.parametrize("plaintext", [
    b'{"cmd":["sh","-c","\\ud800"]}',
    b'{"cmd":"echo \\udfff"}',
    b'{"cmd":["true"],"stdin":"\\ud800"}',
    b'{"cmd":["true"],"env":{"A":"\\ud800"}}',
    b'{"cmd":["true"],"env":{"\\ud800":"v"}}',
    b'{"cmd":["true"],"cwd":"/\\ud800"}',
    b'{"cmd":["true"],"user":"\\ud800"}',
])
def test_a_lone_surrogate_in_the_opened_request_is_400_and_burns_nothing(guest, plaintext) -> None:
    # Review finding 2: it parsed, passed the shape check, was recorded as run, and then the
    # front failed to hash it: the connection dropped and the envelope was spent with nothing run.
    ledger, api, port, client = guest
    status, _, body = _post(port, _seal_plaintext(client, plaintext))
    assert (status, _code(body)) == (400, "sealed_exec_request_invalid")
    assert api.execs() == [] and ledger.sealed_exec.tracked == 0
    assert _post(port, client.seal()[0])[0] == 200


def test_a_deeply_nested_body_is_400_and_the_front_keeps_serving(guest) -> None:
    # Review finding 3: json.loads raises RecursionError, which is not a ValueError.
    _, api, port, client = guest
    deep = b"[" * 200_000 + b"]" * 200_000
    status, _, body = _request(port, "POST", f"/v1/sandboxes/{ROOM}/sealed-exec", deep)
    assert (status, _code(body)) == (400, "sealed_exec_fields_invalid")
    assert api.seen == [] and _post(port, client.seal()[0])[0] == 200


def test_a_deeply_nested_opened_request_is_400_and_burns_nothing(guest) -> None:
    ledger, api, port, client = guest
    plaintext = b'{"cmd":["true"],"env":' + b"[" * 200_000 + b"]" * 200_000 + b"}"
    status, _, body = _post(port, _seal_plaintext(client, plaintext))
    assert (status, _code(body)) == (400, "sealed_exec_request_invalid")
    assert api.execs() == [] and ledger.sealed_exec.tracked == 0


@pytest.mark.parametrize("timeout", [1801, 14400])
def test_a_timeout_the_front_cannot_wait_for_is_refused_before_it_runs(guest, timeout) -> None:
    # Review finding 4: the front's wait on the room API is 1,800 s. A longer sealed exec got a
    # sealed 502 while it ran on, and its output was gone: sealed execs are kept out of the log.
    _, api, port, client = guest
    status, _, body = _post(port, client.seal(timeout_seconds=timeout)[0])
    assert (status, _code(body)) == (400, "sealed_exec_timeout_too_long")
    assert api.execs() == []


def test_the_front_waits_past_the_commands_own_limit(guest, monkeypatch) -> None:
    _, api, port, client = guest
    waits = []
    real = rr.http.client.HTTPConnection

    class Recording(real):
        def __init__(self, host, port=None, timeout=None, **kw):
            if port == api.port:
                waits.append(timeout)
            super().__init__(host, port, timeout=timeout, **kw)

    monkeypatch.setattr(rr.http.client, "HTTPConnection", Recording)
    assert _post(port, client.seal(timeout_seconds=rr.EXEC_TIMEOUT_MAX)[0])[0] == 200
    # The room API's own exec limit is the timeout plus 15 s for docker exec; the front waits longer.
    assert waits == [rr.EXEC_TIMEOUT_MAX + rr.EXEC_ANSWER_MARGIN_SECONDS] and rr.EXEC_ANSWER_MARGIN_SECONDS > 15


@pytest.mark.parametrize("path", ["/v1/workspaces/my-exec-sealed-data", "/v1/images/ghcr.io/acme/exec-sealed:1",
                                  f"/v1/sandboxes/{ROOM}/files?path=/work/exec-sealed"])
def test_other_routes_that_name_exec_sealed_still_pass_with_the_flag_off(tmp_path, monkeypatch, path) -> None:
    # Review finding 5: the guard matched the word anywhere, so flag off was not byte for byte as before.
    ledger, _ = _ledger(tmp_path, monkeypatch, sealed_exec=False)
    api = Api()
    port = _front(ledger, api.port)
    status, _, _ = _request(port, "GET", path)
    assert status == 200 and [p for _, p, _, _ in api.seen] == [path]


def test_a_spelling_the_api_does_not_route_reaches_it_and_runs_nothing(real_room) -> None:
    _, port, room, _ = real_room
    status, _, body = _request(port, "POST", f"/v1/sandboxes/{room}/exec-sealed/", canonical({"cmd": ["true"]}))
    assert (status, _code(body)) == (404, "route_not_found")
    assert json.loads(_request(port, "GET", f"/v1/sandboxes/{room}/logs")[2])["exec_history"] == []


def test_a_clock_stepped_back_never_reopens_the_window_of_a_pruned_envelope(guest) -> None:
    # Review finding 6: an envelope's entry goes once its issued_at leaves the window. A host
    # that then steps the guest clock back must not make it fresh again.
    ledger, _, _, client = guest
    t0 = time.time()
    first, _ = client.seal(issued_at=int(t0))
    ledger.open_sealed_exec(ROOM, first, now=t0)
    later = t0 + rr.EXEC_MAX_AGE_SECONDS + 80
    ledger.open_sealed_exec(ROOM, client.seal(issued_at=int(later))[0], now=later)
    assert ledger.sealed_exec.tracked == 1  # the first envelope's entry is gone
    with pytest.raises(rr.ExecRefused) as refused:
        ledger.open_sealed_exec(ROOM, first, now=t0 + 10)  # the clock went back
    assert refused.value.code == "sealed_exec_not_fresh"
    assert refused.value.extra["guest_time"] == int(later)
