"""A room's env overlay set from a customer-sealed envelope on the receipts front (AB#414).

A sealed guest with ROOM_SEALED_SECRETS=1 takes, at POST
/v1/sandboxes/<id>/sealed-env, one envelope sealed to the binding's
sealed_secrets key that holds the room's whole env overlay. The front opens it
inside the guest and puts it on the room API over loopback (PUT .../env-sealed,
a route no caller reaches); every later exec and process start runs with it.
The receipt signs the names and the envelope sha256, never a digest of a value.
"""
from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

KIT = Path(__file__).resolve().parents[1] / "room-kit"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rr = _load("room_receipts_env_t", KIT / "room_receipts.py")
vr = _load("verify_receipts_env_t", KIT / "verify_receipts.py")

KEY = b"k" * 32
ROOM = "sbx_0123456789ab"
VALUE = "env-plaintext-value-6161"
ENV = {"OPENAI_API_KEY": VALUE, "MODE": "fast"}
CONFIG_BINDING_KEYS = {"schema", "hotel", "boot_id", "created_at", "receipt_key_ed25519_b64", "measurement", "chip_id",
                       "reported_tcb", "policy", "host_data", "kernel_cmdline", "kernel_release", "software", "tenancy"}


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


def _ledger(tmp_path, monkeypatch, *, secrets: bool = True, sealed: bool = True):
    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest" if sealed else None)
    monkeypatch.setattr(rr, "snp_report", _fake_report)
    root = tmp_path / "room-secrets"
    root.mkdir(parents=True, exist_ok=True)
    return rr.Ledger("room-a", str(tmp_path / "store"), secrets=rr.SealedSecrets(str(root)) if secrets else None), root


class Api:
    """The room API behind the front: keeps each room's overlay, records every call, answers as told."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, bytes]] = []
        self.env: dict[str, dict] = {}
        self.status = 200
        self.answer: bytes | None = None
        self.delay = 0.0
        self.on_put = None  # called with the room before the answer
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def answer(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                outer.seen.append((self.command, self.path, body))
                status, out = 200, b"{}"
                if self.command == "PUT" and self.path.endswith("/env-sealed"):
                    room = self.path.split("/")[3]
                    time.sleep(outer.delay)
                    if outer.on_put is not None:
                        outer.on_put(room)
                    status = outer.status
                    if 200 <= status < 300:
                        outer.env[room] = json.loads(body)["env"]
                        out = canonical({"sandbox_id": room, "names": sorted(outer.env[room])})
                    else:
                        out = outer.answer or canonical({"error": {"code": "x", "message": "x"}})
                elif self.command == "POST" and self.path == "/v1/sandboxes":
                    status, out = 202, canonical({"id": ROOM})
                elif self.command == "DELETE":
                    status, out = 204, b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = answer  # noqa: N815

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]

    def puts(self) -> list[tuple[str, str, bytes]]:
        return [s for s in self.seen if s[0] == "PUT"]


def _front(ledger, api_port: int) -> int:
    server = rr.Server(("127.0.0.1", 0), ledger, api_port, 1, KEY, "/nonexistent.sock")
    Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def _request(port: int, method: str, path: str, body: bytes | None = None, key: bytes | None = KEY):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    headers = {"Authorization": "Bearer " + key.decode()} if key is not None else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _create(ledger, room: str = ROOM) -> str:
    """The create receipt the front signs when the API made the room. Returns its receipt_sha256."""
    return ledger.sign({"action": "create", "target": "POST /v1/sandboxes", "sandbox_id": room,
                        "status": 202})["receipt_sha256"]


def _seal(ledger, env: dict = ENV, *, room: str = ROOM, version: int = 1, incarnation: str | None = None,
          binding_sha256: str | None = None) -> dict:
    att = ledger.attestation()
    recipient = X25519PublicKey.from_public_bytes(base64.b64decode(att["binding"]["sealed_secrets"]["x25519_public_b64"]))
    return rr.seal_env(env, recipient, binding_sha256=binding_sha256 or att["binding_sha256"], sandbox_id=room,
                       room_create_receipt_sha256=incarnation or ledger.room_incarnation(room) or "0" * 64,
                       version=version)


def _seal_raw(ledger, plaintext: bytes, *, version: int = 1) -> dict:
    """An envelope whose plaintext is chosen byte for byte (a broken or hostile client)."""
    att = ledger.attestation()
    recipient = X25519PublicKey.from_public_bytes(base64.b64decode(att["binding"]["sealed_secrets"]["x25519_public_b64"]))
    header = rr.env_header(att["binding_sha256"], ROOM, ledger.room_incarnation(ROOM), version)
    return {**header, **rr._seal_envelope(plaintext, recipient, rr.ENV_HKDF_INFO, rr.env_aad(header))}


def _post(port: int, doc, room: str = ROOM):
    body = doc if isinstance(doc, bytes) else canonical(doc)
    return _request(port, "POST", f"/v1/sandboxes/{room}/sealed-env", body)


def _receipt(headers: dict) -> dict:
    h = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))


def _code(body: bytes) -> str:
    return json.loads(body)["error"]["code"]


@pytest.fixture
def guest(tmp_path, monkeypatch):
    ledger, root = _ledger(tmp_path, monkeypatch)
    api = Api()
    port = _front(ledger, api.port)
    (root / ROOM).mkdir()
    _create(ledger)
    return ledger, api, port


# ---------------------------------------------------------------- the binding and the flag

def test_the_binding_is_what_sealed_secrets_made_it(tmp_path, monkeypatch) -> None:
    # The env overlay opens with the sealed secrets key: no new key, so no binding change.
    ledger, _ = _ledger(tmp_path, monkeypatch)
    assert set(ledger.binding) == CONFIG_BINDING_KEYS | {"sealed_secrets"}
    assert ledger.sealed_env is not None
    off, _ = _ledger(tmp_path / "off", monkeypatch, secrets=False)
    assert set(off.binding) == CONFIG_BINDING_KEYS and off.sealed_env is None
    level1, _ = _ledger(tmp_path / "l1", monkeypatch, sealed=False)
    assert level1.sealed_env is None


def test_flag_off_is_403_and_nothing_reaches_the_api(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch, secrets=False)
    api = Api()
    port = _front(ledger, api.port)
    _create(ledger)
    status, _, body = _post(port, {"schema": rr.ENV_SCHEMA})
    assert (status, _code(body)) == (403, "sealed_env_disabled") and api.seen == []
    status, _, body = _request(port, "GET", f"/v1/sandboxes/{ROOM}/sealed-env")
    assert (status, _code(body)) == (403, "sealed_env_disabled")


# ---------------------------------------------------------------- the envelope

def test_the_env_envelope_opens_only_as_an_env_envelope() -> None:
    private = X25519PrivateKey.generate()
    doc = rr.seal_env(ENV, private.public_key(), binding_sha256="a" * 64, sandbox_id=ROOM,
                      room_create_receipt_sha256="c" * 64, version=3)
    assert json.loads(rr.open_env(doc, private)) == {"env": ENV}
    header = {k: doc[k] for k in rr.ENV_HEADER}
    for info in (rr.SECRETS_HKDF_INFO, rr.EXEC_HKDF_INFO, rr.PLANT_HKDF_INFO):
        with pytest.raises(rr.PlantError):
            rr._open_envelope(doc, private, info, rr.env_aad(header), max_ciphertext=1 << 20)
    for field, other in (("version", 4), ("sandbox_id", "sbx_other"), ("room_create_receipt_sha256", "d" * 64),
                         ("binding_sha256", "b" * 64)):
        with pytest.raises(rr.EnvRefused):
            rr.open_env({**doc, field: other}, private)


# ---------------------------------------------------------------- a write

def test_a_write_sets_the_overlay_and_signs_names_never_values(guest) -> None:
    ledger, api, port = guest
    doc = _seal(ledger)
    status, headers, body = _post(port, doc)
    assert status == 200, body
    out = json.loads(body)
    assert out == {"sandbox_id": ROOM, "room_create_receipt_sha256": ledger.room_incarnation(ROOM), "version": 1,
                   "envelope_sha256": rr.sha(canonical(doc)), "names": ["MODE", "OPENAI_API_KEY"], "status": "set"}
    assert api.env[ROOM] == ENV
    assert [(m, p) for m, p, _ in api.puts()] == [("PUT", f"/v1/sandboxes/{ROOM}/env-sealed")]
    st = _receipt(headers)["statement"]
    assert st["action"] == "sealed_env_set" and st["sandbox_id"] == ROOM and st["status"] == 200
    assert st["env_names"] == ["MODE", "OPENAI_API_KEY"] and st["env_version"] == 1
    assert st["envelope_sha256"] == rr.sha(canonical(doc))
    assert st["room_create_receipt_sha256"] == ledger.room_incarnation(ROOM)
    # No value and no digest of one anywhere: the answer, the receipt, the chain on disk.
    digests = {rr.sha(v.encode()) for v in ENV.values()}
    chain = (Path(ledger.store.name)).read_bytes()
    for blob in (body, headers["X-Room-Receipt"].encode(), canonical(_receipt(headers)), chain):
        assert VALUE.encode() not in blob and not any(d.encode() in blob for d in digests)
    # The chain still verifies with the verifier customers run.
    result = vr.verify_receipts(ledger.attestation(), list(ledger.chain), head=ledger.head)
    assert result["contiguous"] and result["receipts"] == 2


def test_get_names_the_overlay_and_never_a_value(guest) -> None:
    ledger, _, port = guest
    status, _, body = _request(port, "GET", f"/v1/sandboxes/{ROOM}/sealed-env")
    assert status == 200
    assert json.loads(body)["names"] == [] and json.loads(body)["version"] is None
    doc = _seal(ledger)
    _post(port, doc)
    status, _, body = _request(port, "GET", f"/v1/sandboxes/{ROOM}/sealed-env")
    assert json.loads(body) == {"sandbox_id": ROOM, "binding_sha256": ledger.binding_sha256,
                                "room_create_receipt_sha256": ledger.room_incarnation(ROOM), "version": 1,
                                "envelope_sha256": rr.sha(canonical(doc)), "names": ["MODE", "OPENAI_API_KEY"]}
    assert VALUE.encode() not in body


def test_an_exact_retry_answers_unchanged_with_the_first_receipt(guest) -> None:
    ledger, api, port = guest
    doc = _seal(ledger)
    _, first, _ = _post(port, doc)
    status, again, body = _post(port, doc)
    assert status == 200 and json.loads(body)["status"] == "unchanged"
    assert again["X-Room-Receipt"] == first["X-Room-Receipt"]
    assert len(api.puts()) == 1 and len(ledger.chain) == 2


def test_an_older_or_equal_version_is_a_replay_and_a_newer_one_replaces_the_overlay(guest) -> None:
    ledger, api, port = guest
    _post(port, _seal(ledger, version=5))
    for version in (5, 4):
        status, _, body = _post(port, _seal(ledger, {"OTHER": "x"}, version=version))
        assert (status, _code(body)) == (409, "sealed_env_replayed")
    assert api.env[ROOM] == ENV
    status, _, body = _post(port, _seal(ledger, {"OTHER": "x"}, version=6))
    assert status == 200 and json.loads(body)["names"] == ["OTHER"] and api.env[ROOM] == {"OTHER": "x"}
    status, _, body = _post(port, _seal(ledger, {}, version=7))
    assert status == 200 and json.loads(body)["names"] == [] and api.env[ROOM] == {}


@pytest.mark.parametrize("change, want", [
    ({"binding_sha256": "b" * 64}, (409, "sealed_env_wrong_binding")),
    ({"sandbox_id": "sbx_other"}, (400, "sealed_env_wrong_room")),
    ({"version": 0}, (400, "sealed_env_version_invalid")),
    ({"version": True}, (400, "sealed_env_version_invalid")),
    ({"room_create_receipt_sha256": "zz"}, (400, "sealed_env_incarnation_invalid")),
    ({"room_create_receipt_sha256": "d" * 64}, (409, "sealed_env_wrong_incarnation")),
    ({"schema": "cathedral_sealed_secret_v2"}, (400, "sealed_env_algorithm_unsupported")),
    ({"extra": 1}, (400, "sealed_env_fields_invalid")),
    ({"nonce_b64": "é"}, (400, "sealed_env_fields_invalid")),
])
def test_a_bad_header_is_refused_before_the_api(guest, change, want) -> None:
    ledger, api, port = guest
    status, _, body = _post(port, {**_seal(ledger), **change})
    assert (status, _code(body)) == want and api.puts() == []


def test_a_header_changed_after_sealing_does_not_open(guest) -> None:
    ledger, api, port = guest
    doc = _seal(ledger, version=1)
    status, _, body = _post(port, {**doc, "version": 2})
    assert (status, _code(body)) == (400, "sealed_env_does_not_open") and api.puts() == []


def test_a_respelled_ephemeral_key_is_refused(guest) -> None:
    ledger, api, port = guest
    doc = _seal(ledger)
    eph = doc["ephemeral_public_b64"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    respelled = next(eph[:-2] + c + "=" for c in alphabet
                     if eph[:-2] + c + "=" != eph and base64.b64decode(eph[:-2] + c + "=") == base64.b64decode(eph))
    status, _, body = _post(port, {**doc, "ephemeral_public_b64": respelled})
    assert (status, _code(body)) == (400, "sealed_env_fields_invalid") and api.puts() == []


def test_a_room_with_no_create_receipt_is_404(guest) -> None:
    ledger, api, port = guest
    status, _, body = _post(port, _seal(ledger, room="sbx_never", incarnation="e" * 64), room="sbx_never")
    assert (status, _code(body)) == (404, "sealed_env_room_not_found") and api.puts() == []


@pytest.mark.parametrize("plaintext", [
    canonical({"env": {"PATH": "/x"}}),
    canonical({"env": {"LD_PRELOAD": "/x.so"}}),
    canonical({"env": {"A=B": "1"}}),
    canonical({"env": {"A": "v\u0000x"}}),
    canonical({"env": {"A": 1}}),
    canonical({"env": {f"N{i}": "1" for i in range(65)}}),
    canonical({"env": {"A": "x" * (64 * 1024)}}),
    canonical({"env": {"A": "1"}, "more": 1}),
    canonical({"env": ["A"]}),
    b'{"env": {"A": "\\ud800"}}',
    b"not json",
    b"[" * 100000,
])
def test_an_overlay_the_api_would_not_take_is_refused_unsent(guest, plaintext) -> None:
    ledger, api, port = guest
    status, _, body = _post(port, _seal_raw(ledger, plaintext))
    assert (status, _code(body)) == (400, "sealed_env_request_invalid") and api.puts() == []


def test_too_large_is_413_and_bad_json_is_400(guest) -> None:
    _, api, port = guest
    status, _, body = _post(port, b" " * (rr.ENV_MAX_BYTES + 1))
    assert (status, _code(body)) == (413, "sealed_env_too_large")
    status, _, body = _post(port, b"[" * 100000)
    assert (status, _code(body)) == (400, "sealed_env_fields_invalid")
    assert api.seen == []


def test_the_bearer_is_required(guest) -> None:
    ledger, api, port = guest
    for method, body in (("GET", None), ("POST", canonical(_seal(ledger)))):
        status, _, _ = _request(port, method, f"/v1/sandboxes/{ROOM}/sealed-env", body, key=b"wrong" * 8)
        assert status == 401
    assert api.seen == []


# ---------------------------------------------------------------- the room API's answer

def test_an_api_without_the_route_is_501_and_the_same_envelope_works_once_it_has_it(guest) -> None:
    ledger, api, port = guest
    api.status = 404
    api.answer = canonical({"error": {"code": "route_not_found", "message": "no route for PUT ..."}})
    doc = _seal(ledger)
    status, _, body = _post(port, doc)
    assert (status, _code(body)) == (501, "sealed_env_unsupported")
    assert json.loads(_request(port, "GET", f"/v1/sandboxes/{ROOM}/sealed-env")[2])["names"] == []
    api.status = 200
    status, _, body = _post(port, doc)
    assert status == 200 and json.loads(body)["status"] == "set" and api.env[ROOM] == ENV


def test_an_api_error_never_reaches_the_caller(guest) -> None:
    ledger, api, port = guest
    api.status = 500
    api.answer = canonical({"error": {"code": "internal", "message": f"could not set {VALUE}"}})
    status, headers, body = _post(port, _seal(ledger))
    assert (status, _code(body)) == (502, "sealed_env_apply_failed")
    assert VALUE.encode() not in body and "X-Room-Receipt" not in headers
    assert len(ledger.chain) == 1


def test_a_hung_api_answers_in_the_apply_timeout_and_frees_the_room(guest, monkeypatch) -> None:
    ledger, api, port = guest
    monkeypatch.setattr(rr, "ENV_APPLY_TIMEOUT_SECONDS", 1)
    api.delay = 3
    t0 = time.monotonic()
    status, _, body = _post(port, _seal(ledger))
    assert (status, _code(body)) == (502, "sealed_env_apply_failed") and time.monotonic() - t0 < 2.5
    api.delay = 0
    status, _, _ = _post(port, _seal(ledger, version=2))
    assert status == 200


def test_a_room_made_again_while_the_api_set_it_gets_its_overlay_taken_off(guest) -> None:
    ledger, api, port = guest
    first = ledger.room_incarnation(ROOM)

    def made_again(room: str) -> None:
        api.on_put = None
        _create(ledger, room)

    api.on_put = made_again
    status, _, body = _post(port, _seal(ledger))
    assert (status, _code(body)) == (409, "sealed_env_wrong_incarnation")
    assert ledger.room_incarnation(ROOM) != first
    assert [json.loads(b)["env"] for _, _, b in api.puts()] == [ENV, {}] and api.env[ROOM] == {}
    assert json.loads(_request(port, "GET", f"/v1/sandboxes/{ROOM}/sealed-env")[2])["names"] == []


# ---------------------------------------------------------------- the room's life

def test_a_delete_through_the_front_drops_the_overlay_state(guest) -> None:
    ledger, _, port = guest
    _post(port, _seal(ledger))
    status, _, _ = _request(port, "DELETE", f"/v1/sandboxes/{ROOM}")
    assert status == 204
    assert ROOM not in ledger.sealed_env.rooms
    status, _, body = _request(port, "GET", f"/v1/sandboxes/{ROOM}/sealed-env")
    assert json.loads(body)["names"] == [] and json.loads(body)["room_create_receipt_sha256"] is None


def test_a_create_answered_again_clears_the_overlay_of_the_old_incarnation(guest) -> None:
    # An Idempotency-Key replay answers the same room again and the front signs a new create
    # receipt: the overlay set under the old one must not stay in force unseen.
    ledger, api, port = guest
    _post(port, _seal(ledger))
    assert api.env[ROOM] == ENV
    status, _, _ = _request(port, "POST", "/v1/sandboxes", canonical({"image": "alpine:3.20"}))
    assert status == 202
    assert api.env[ROOM] == {} and ROOM not in ledger.sealed_env.rooms
    status, _, body = _post(port, _seal(ledger, {"NEW": "1"}))
    assert status == 200 and api.env[ROOM] == {"NEW": "1"}


def test_a_create_of_another_room_leaves_this_overlay_alone(guest) -> None:
    ledger, api, port = guest
    _post(port, _seal(ledger))
    _create(ledger, "sbx_other")
    cleared: list[str] = []
    ledger.reconcile_sealed_env(lambda room: (lambda env: cleared.append(room) or (200, None)))
    assert cleared == [] and ROOM in ledger.sealed_env.rooms and api.env[ROOM] == ENV


def test_the_sweep_drops_rooms_that_are_gone(guest) -> None:
    ledger, _, port = guest
    _post(port, _seal(ledger))
    box = ledger.sealed_env
    with box.lock:
        box.sweep(ledger.room_incarnation, lambda r: True, time.monotonic())
    assert ROOM in box.rooms
    with box.lock:
        box.swept_at = float("-inf")
        box.sweep(ledger.room_incarnation, lambda r: False, time.monotonic())  # reaped past the front
    assert ROOM not in box.rooms


@pytest.mark.parametrize("method", ["PUT", "POST", "GET", "DELETE"])
@pytest.mark.parametrize("path", [
    f"/v1/sandboxes/{ROOM}/env-sealed",
    f"/v1/sandboxes/{ROOM}/env-sealed;x=1",
    f"/v1/sandboxes/{ROOM}/env%2Dsealed",
    f"/v1/sandboxes/{ROOM}/env-sealed?env=1",
    "/v1/sandboxes/a%2Fb/env-sealed",
])
def test_no_caller_reaches_the_room_apis_env_route(guest, method, path) -> None:
    _, api, port = guest
    status, _, body = _request(port, method, path, canonical({"env": {"A": VALUE}}))
    assert (status, _code(body)) == (404, "route_not_found")
    assert api.seen == []


# ---------------------------------------------------------------- the real room API behind the real front

def test_a_sealed_env_reaches_the_next_exec_in_the_room(tmp_path, monkeypatch) -> None:
    from cathedral.sandbox_guest import DockerGuestProvider
    from cathedral.sandbox_server import SandboxApplication, run
    from tests.fake_docker_cli import install

    fake = install(tmp_path, monkeypatch)
    fake.add_image("alpine:3.20")
    fake.set(exec_model=True)
    ledger, root = _ledger(tmp_path, monkeypatch)
    monkeypatch.setenv("CATHEDRAL_SEALED_SECRETS_DIR", str(root))
    monkeypatch.setenv("CATHEDRAL_SANDBOX_KEYS", "")
    provider = DockerGuestProvider()
    httpd, (_, api_port) = run(SandboxApplication(provider))
    Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        port = _front(ledger, api_port)
        status, _, out = _request(port, "POST", "/v1/sandboxes", canonical(
            {"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}))
        assert status == 202, out
        room = json.loads(out)["id"]
        status, _, body = _post(port, _seal(ledger, room=room), room)
        assert status == 200, body
        status, _, out = _request(port, "POST", f"/v1/sandboxes/{room}/exec",
                                  canonical({"cmd": ["echo", "e2e-marker"], "env": {"MODE": "mine"}}))
        assert status == 200, out
        (ran,) = [c for c in fake.calls_of("exec") if "e2e-marker" in c]
        pairs = dict(ran[i + 1].split("=", 1) for i, p in enumerate(ran) if p == "-e")
        assert pairs == {"OPENAI_API_KEY": VALUE, "MODE": "mine"}
        _, _, logs = _request(port, "GET", f"/v1/sandboxes/{room}/logs")
        assert VALUE.encode() not in logs
    finally:
        httpd.shutdown()
        provider.close()
