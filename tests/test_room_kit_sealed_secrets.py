"""Customer-sealed secrets on the receipts front (room_receipts.py, AB#417 slice 1).

A sealed guest with ROOM_SEALED_SECRETS=1 names a per-boot X25519 key in its
binding, so REPORT_DATA commits to it. A customer seals a secret to that key
with the guest's one envelope construction (X25519, HKDF-SHA256, AES-256-GCM,
as the plant and the hotel key use); only this guest opens it, and it lands
read-only in the room at /run/secrets/<name>. The flag off must leave the
binding exactly as it was, and both the old and the new binding must pass
verify_receipts.py as it is on main (unchanged by this work).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import stat
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KIT = Path(__file__).resolve().parents[1] / "room-kit"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rr = _load("room_receipts_secrets_t", KIT / "room_receipts.py")
vr = _load("verify_receipts_secrets_t", KIT / "verify_receipts.py")

KEY = b"k" * 32
VALUE = b"example-secret-value-0001"
# The binding fields of a shared config hotel before this change (as in test_room_kit_miner_tls.py).
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
    asked: list[bytes] = []

    def report(data: bytes) -> bytes:
        asked.append(data)
        return _fake_report(data)

    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest" if sealed else None)
    monkeypatch.setattr(rr, "snp_report", report)
    root = tmp_path / "room-secrets"
    root.mkdir(parents=True, exist_ok=True)
    box = rr.SealedSecrets(str(root)) if secrets else None
    ledger = rr.Ledger("room-a", str(tmp_path / "store"), secrets=box)
    return ledger, asked, root


class Api:
    """The room API behind the front. Records every call; a secret route must never reach it."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, bytes]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def answer(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.seen.append((self.command, self.path, self.rfile.read(n) if n else b""))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            do_GET = do_POST = do_DELETE = answer  # noqa: N815

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]


def _front(ledger):
    api = Api()
    server = rr.Server(("127.0.0.1", 0), ledger, api.port, 1, KEY, "/nonexistent.sock")
    Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1], api


def _request(port: int, method: str, path: str, body: bytes | None = None, key: bytes | None = KEY):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Authorization": "Bearer " + key.decode()} if key is not None else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _room(root: Path, room: str = "sbx_0123456789ab") -> str:
    (root / room).mkdir(mode=0o755)
    return room


def _seal(ledger, room: str, *, name: str = "OPENAI_API_KEY", version: int = 1, value: bytes = VALUE,
          binding_sha256: str | None = None) -> dict:
    """What a customer does after checking the attestation: the key from the binding, nothing else."""
    att = ledger.attestation()
    recipient = X25519PublicKey.from_public_bytes(base64.b64decode(att["binding"]["sealed_secrets"]["x25519_public_b64"]))
    return rr.seal_secret(value, recipient, binding_sha256=binding_sha256 or att["binding_sha256"], sandbox_id=room,
                          name=name, version=version)


def _post(port: int, room: str, doc: dict):
    return _request(port, "POST", f"/v1/sandboxes/{room}/sealed-secrets", canonical(doc))


def _receipt(headers: dict) -> dict:
    h = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))


# ---------------------------------------------------------------- the binding

def test_flag_off_leaves_the_binding_as_it_was(tmp_path, monkeypatch) -> None:
    ledger, asked, _ = _ledger(tmp_path, monkeypatch, secrets=False)
    assert set(ledger.binding) == CONFIG_BINDING_KEYS
    assert ledger.secrets is None
    assert asked[-1] == bytes.fromhex(ledger.binding_sha256) + bytes(32)


def test_flag_on_names_the_key_in_the_binding_that_report_data_commits_to(tmp_path, monkeypatch) -> None:
    ledger, asked, _ = _ledger(tmp_path, monkeypatch)
    assert set(ledger.binding) == CONFIG_BINDING_KEYS | {"sealed_secrets"}
    named = ledger.binding["sealed_secrets"]
    assert named == {"schema": "cathedral_sealed_secret_v1", "algorithm": "x25519-hkdf-sha256-aes256gcm-v1",
                     "x25519_public_b64": ledger.secrets.public_b64, "path": "/run/secrets"}
    raw = ledger.secrets.private.public_key().public_bytes_raw()
    assert base64.b64decode(named["x25519_public_b64"]) == raw
    # Same REPORT_DATA rule as before: sha256(canonical(binding)) then 32 zero bytes.
    assert ledger.binding_sha256 == hashlib.sha256(canonical(ledger.binding)).hexdigest()
    assert asked[-1] == bytes.fromhex(ledger.binding_sha256) + bytes(32)
    assert "private" not in repr(ledger.secrets).lower()


def test_level1_never_offers_the_key(tmp_path, monkeypatch) -> None:
    ledger, _, _ = _ledger(tmp_path, monkeypatch, sealed=False)
    assert ledger.secrets is None and "sealed_secrets" not in ledger.binding


def test_each_boot_gets_a_fresh_key(tmp_path, monkeypatch) -> None:
    one, _, _ = _ledger(tmp_path / "a", monkeypatch)
    two, _, _ = _ledger(tmp_path / "b", monkeypatch)
    assert one.secrets.public_b64 != two.secrets.public_b64


@pytest.mark.parametrize("secrets", [False, True])
def test_the_current_verifier_passes_both_bindings_and_the_write_receipt(tmp_path, monkeypatch, secrets) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch, secrets=secrets)
    ledger.sign({"action": "create", "target": "POST /v1/sandboxes", "sandbox_id": "sbx_0123456789ab", "status": 202})
    if secrets:
        room = _room(root)
        out, receipt = ledger.write_sealed_secret(room, _seal(ledger, room))
        assert out["status"] == "written" and receipt is not None
    att, chain = ledger.attestation(), list(ledger.chain)
    assert vr.verify_attestation(att, "ab" * 48, None, str(tmp_path / "kds"), None, skip_amd=True)["measurement"] == "ab" * 48
    result = vr.verify_receipts(att, chain, head=ledger.head)
    assert result["contiguous"] and result["receipts"] == len(chain) == (2 if secrets else 1)
    # And the command-line verifier as customers run it.
    (tmp_path / "att.json").write_text(json.dumps(att))
    (tmp_path / "chain.json").write_text(json.dumps({"receipts": chain, "head": ledger.head}))
    proc = subprocess.run([os.sys.executable, str(KIT / "verify_receipts.py"), "--attestation", str(tmp_path / "att.json"),
                           "--receipts", str(tmp_path / "chain.json"), "--skip-amd", "--require-sealed"],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)
    assert out["verdict"] == "PASS"
    assert out["chain"]["actions"] == ({"create": 1, "sealed_secret_write": 1} if secrets else {"create": 1})
    if secrets:
        # The verifier hashes the binding whole: a swapped secrets key is a REPORT_DATA failure.
        att["binding"]["sealed_secrets"]["x25519_public_b64"] = base64.b64encode(bytes(32)).decode()
        att["binding_sha256"] = hashlib.sha256(canonical(att["binding"])).hexdigest()
        with pytest.raises(vr.Fail, match="REPORT_DATA"):
            vr.verify_attestation(att, "ab" * 48, None, str(tmp_path / "kds"), None, skip_amd=True)


# ---------------------------------------------------------------- the envelope

def test_the_envelope_opens_step_by_step_as_a_browser_would() -> None:
    """Open with X25519, HMAC-SHA256 (HKDF, RFC 5869) and AES-256-GCM only, written out here.

    Each step is one WebCrypto call (deriveBits X25519, HKDF, AES-GCM), so a
    pass pins the wire format a second client must produce, apart from
    room_receipts' own _open_envelope.
    """
    private = X25519PrivateKey.generate()
    doc = rr.seal_secret(VALUE, private.public_key(), binding_sha256="a" * 64, sandbox_id="sbx_1", name="N", version=7)
    assert set(doc) == {"schema", "algorithm", "binding_sha256", "sandbox_id", "name", "version",
                        "ephemeral_public_b64", "nonce_b64", "ciphertext_b64"}
    assert doc["algorithm"] == "x25519-hkdf-sha256-aes256gcm-v1"
    header = {k: doc[k] for k in ("schema", "algorithm", "binding_sha256", "sandbox_id", "name", "version")}
    aad = b"cathedral.sealed-secret.v1\n" + canonical(header)
    eph = base64.b64decode(doc["ephemeral_public_b64"])
    rec = private.public_key().public_bytes_raw()
    shared = private.exchange(X25519PublicKey.from_public_bytes(eph))
    prk = hmac.new(aad, shared, hashlib.sha256).digest()  # HKDF-Extract, salt = AAD
    key = hmac.new(prk, b"cathedral.sealed-secret.v1" + eph + rec + b"\x01", hashlib.sha256).digest()  # one block
    nonce = base64.b64decode(doc["nonce_b64"])
    assert len(nonce) == 12
    assert AESGCM(key).decrypt(nonce, base64.b64decode(doc["ciphertext_b64"]), aad) == VALUE


def test_the_secret_envelope_never_opens_as_a_plant_or_install_envelope() -> None:
    """Same construction, own HKDF info and AAD: no cross-use with the other two."""
    private = X25519PrivateKey.generate()
    doc = rr.seal_secret(VALUE, private.public_key(), binding_sha256="a" * 64, sandbox_id="sbx_1", name="N", version=7)
    envelope = {k: doc[k] for k in ("algorithm", "ephemeral_public_b64", "nonce_b64", "ciphertext_b64")}
    with pytest.raises(rr.PlantError):
        rr._open_envelope(envelope, private, rr.PLANT_HKDF_INFO, rr.secret_aad({k: doc[k] for k in rr.SECRETS_HEADER}))
    with pytest.raises(rr.PlantError):
        rr._open_envelope(envelope, private, rr.INSTALL_HKDF_INFO, rr.install_aad("a" * 64))


@pytest.mark.parametrize("size", [0, 2049, 64 * 1024])
def test_an_empty_and_the_largest_value_open(size) -> None:
    private = X25519PrivateKey.generate()
    value = os.urandom(size)
    doc = rr.seal_secret(value, private.public_key(), binding_sha256="a" * 64, sandbox_id="sbx_1", name="N", version=1)
    assert rr.open_secret(doc, private) == value


def test_the_plant_envelope_keeps_its_own_size_bound() -> None:
    private = X25519PrivateKey.generate()
    big = rr._seal_envelope(b"n" * 2100, private.public_key(), rr.PLANT_HKDF_INFO, b"aad")
    with pytest.raises(rr.PlantError):
        rr._open_envelope(big, private, rr.PLANT_HKDF_INFO, b"aad")


def test_every_header_field_is_authenticated() -> None:
    private = X25519PrivateKey.generate()
    doc = rr.seal_secret(VALUE, private.public_key(), binding_sha256="a" * 64, sandbox_id="sbx_1", name="N", version=7)
    assert rr.open_secret(doc, private) == VALUE
    flipped = base64.b64decode(doc["ciphertext_b64"])
    flipped = base64.b64encode(bytes([flipped[0] ^ 1]) + flipped[1:]).decode()
    for field, other in (("binding_sha256", "b" * 64), ("sandbox_id", "sbx_2"), ("name", "M"), ("version", 8),
                         ("schema", "cathedral_sealed_secret_v2"), ("ciphertext_b64", flipped),
                         ("nonce_b64", base64.b64encode(bytes(12)).decode()),
                         ("ephemeral_public_b64", base64.b64encode(X25519PrivateKey.generate().public_key()
                                                                   .public_bytes_raw()).decode())):
        with pytest.raises(rr.SecretRefused) as refused:
            rr.open_secret({**doc, field: other}, private)
        assert refused.value.code == "sealed_secret_does_not_open"
    # A low-order ephemeral key (all zeros) is refused, not opened to a known key.
    with pytest.raises(rr.SecretRefused):
        rr.open_secret({**doc, "ephemeral_public_b64": base64.b64encode(bytes(32)).decode()}, private)
    with pytest.raises(rr.SecretRefused):
        rr.open_secret(doc, X25519PrivateKey.generate())


# ---------------------------------------------------------------- the route

def test_write_lands_read_only_and_the_receipt_never_names_the_value(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(root)
    port, api = _front(ledger)
    doc = _seal(ledger, room)
    status, headers, body = _post(port, room, doc)
    assert status == 200, body
    answer = json.loads(body)
    envelope_sha256 = hashlib.sha256(canonical(doc)).hexdigest()
    assert answer == {"sandbox_id": room, "name": "OPENAI_API_KEY", "version": 1, "envelope_sha256": envelope_sha256,
                      "path": "/run/secrets/OPENAI_API_KEY", "status": "written"}
    written = root / room / "OPENAI_API_KEY"
    assert written.read_bytes() == VALUE
    assert stat.S_IMODE(written.stat().st_mode) == 0o444
    assert [p.name for p in (root / room).iterdir()] == ["OPENAI_API_KEY"]  # no temp file left
    receipt = _receipt(headers)
    st = receipt["statement"]
    assert st["action"] == "sealed_secret_write" and st["sandbox_id"] == room and st["envelope_sha256"] == envelope_sha256
    assert st["secret_name"] == "OPENAI_API_KEY" and st["secret_version"] == 1 and st["path"] == "/run/secrets/OPENAI_API_KEY"
    Ed25519PublicKey.from_public_bytes(base64.b64decode(ledger.binding["receipt_key_ed25519_b64"])).verify(
        base64.b64decode(receipt["signature_b64"]), canonical(st))
    everything = body + canonical(receipt) + b"".join(canonical(r) for r in ledger.chain)
    for leak in (VALUE, hashlib.sha256(VALUE).hexdigest().encode(), base64.b64encode(VALUE)):
        assert leak not in everything
    assert api.seen == []  # the envelope never reaches the room API


def test_exact_retry_is_unchanged_and_signs_nothing(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(root)
    port, _ = _front(ledger)
    doc = _seal(ledger, room)
    assert _post(port, room, doc)[0] == 200
    status, headers, body = _post(port, room, doc)
    assert status == 200 and json.loads(body)["status"] == "unchanged"
    assert "X-Room-Receipt" not in headers and len(ledger.chain) == 1


def test_an_older_envelope_cannot_roll_the_secret_back(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(root)
    port, _ = _front(ledger)
    old = _seal(ledger, room, version=1, value=b"old-value")
    assert _post(port, room, old)[0] == 200
    assert _post(port, room, _seal(ledger, room, version=2, value=b"new-value"))[0] == 200
    for replay in (old, _seal(ledger, room, version=2, value=b"other-value")):
        status, _, body = _post(port, room, replay)
        assert status == 409 and json.loads(body)["error"]["code"] == "sealed_secret_replayed"
    assert (root / room / "OPENAI_API_KEY").read_bytes() == b"new-value"
    assert len(ledger.chain) == 2


def test_state_outlives_the_room_so_a_recreated_id_refuses_old_envelopes(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(root)
    doc = _seal(ledger, room, version=5)
    ledger.write_sealed_secret(room, doc)
    for f in (root / room).iterdir():
        f.unlink()
    (root / room).rmdir()  # the API dropped the room
    _room(root, room)  # and made one with the same id
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, doc)
    assert refused.value.code == "sealed_secret_replayed"
    assert not (root / room / "OPENAI_API_KEY").exists()
    # The customer reseals with a higher version.
    assert ledger.write_sealed_secret(room, _seal(ledger, room, version=6))[0]["status"] == "written"


def test_an_envelope_for_another_boot_is_refused_so_the_client_reseals(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    other, _, _ = _ledger(tmp_path / "other", monkeypatch)
    room = _room(root)
    port, _ = _front(ledger)
    status, _, body = _post(port, room, _seal(other, room))
    assert status == 409 and json.loads(body)["error"]["code"] == "sealed_secret_wrong_binding"
    # Right binding hash, wrong key (another guest's): it does not open.
    forged = _seal(other, room, binding_sha256=ledger.binding_sha256)
    status, _, body = _post(port, room, forged)
    assert status == 400 and json.loads(body)["error"]["code"] == "sealed_secret_does_not_open"
    assert not (root / room / "OPENAI_API_KEY").exists() and ledger.chain == []


def test_an_envelope_for_one_room_never_opens_in_another(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    a, b = _room(root, "sbx_aaaaaaaaaaaa"), _room(root, "sbx_bbbbbbbbbbbb")
    port, _ = _front(ledger)
    doc = _seal(ledger, a)
    status, _, body = _post(port, b, doc)
    assert status == 400 and json.loads(body)["error"]["code"] == "sealed_secret_wrong_room"
    status, _, body = _post(port, b, {**doc, "sandbox_id": b})  # the relay rewrites the room
    assert status == 400 and json.loads(body)["error"]["code"] == "sealed_secret_does_not_open"
    assert not any((root / b).iterdir())


def test_a_room_without_a_secrets_directory_is_404(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    port, _ = _front(ledger)
    status, _, body = _post(port, "sbx_0123456789ab", _seal(ledger, "sbx_0123456789ab"))
    assert status == 404 and json.loads(body)["error"]["code"] == "sealed_secret_room_not_found"
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "sbx_linkedlinked").symlink_to(outside)
    status, _, _ = _post(port, "sbx_linkedlinked", _seal(ledger, "sbx_linkedlinked"))
    assert status == 404 and not any(outside.iterdir())


@pytest.mark.parametrize("name", ["../escape", ".hidden", "a/b", "", "x" * 129, "white space"])
def test_names_that_are_not_one_plain_file_are_refused(tmp_path, monkeypatch, name) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(root)
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, _seal(ledger, room, name=name))
    assert refused.value.code == "sealed_secret_name_invalid"
    assert not any((root / room).iterdir())


@pytest.mark.parametrize("change", [
    {"version": 0}, {"version": 2**53}, {"version": "1"}, {"version": True}, {"schema": "other"},
    {"algorithm": "hpke-base-x25519-hkdf-sha256-aes-256-gcm"}, {"extra": 1}, {"sealed_b64": "AAAA"},
])
def test_malformed_requests_are_refused_before_any_write(tmp_path, monkeypatch, change) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(root)
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, {**_seal(ledger, room), **change})
    assert refused.value.status == 400
    assert not any((root / room).iterdir())


def test_flag_off_answers_403_and_never_reaches_the_api(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch, secrets=False)
    room = _room(root)
    port, api = _front(ledger)
    status, _, body = _request(port, "POST", f"/v1/sandboxes/{room}/sealed-secrets", b'{"sealed_b64":"AAAA"}')
    assert status == 403 and json.loads(body)["error"]["code"] == "sealed_secrets_disabled"
    assert api.seen == []
    # The rest of the room API still passes through.
    assert _request(port, "GET", f"/v1/sandboxes/{room}")[0] == 200 and api.seen


def test_the_route_needs_the_hotel_key(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(root)
    port, _ = _front(ledger)
    doc = canonical(_seal(ledger, room))
    assert _request(port, "POST", f"/v1/sandboxes/{room}/sealed-secrets", doc, key=None)[0] == 401
    assert _request(port, "POST", f"/v1/sandboxes/{room}/sealed-secrets", doc, key=b"w" * 32)[0] == 401
    assert _request(port, "DELETE", f"/v1/sandboxes/{room}/sealed-secrets")[0] == 405
    assert not any((root / room).iterdir())


def test_too_large_is_413(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(root)
    port, _ = _front(ledger)
    status, _, _ = _request(port, "POST", f"/v1/sandboxes/{room}/sealed-secrets", b"{" + b" " * rr.SECRETS_MAX_BYTES + b"}")
    assert status == 413
    big = _seal(ledger, room, value=b"v" * (rr.SECRET_VALUE_MAX_BYTES + 1))
    with pytest.raises(rr.SecretRefused):
        ledger.write_sealed_secret(room, big)


def test_listing_shows_names_and_versions_only(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(root)
    port, _ = _front(ledger)
    one, two = _seal(ledger, room, name="B", version=3), _seal(ledger, room, name="A", version=9, value=b"another")
    _post(port, room, one)
    _post(port, room, two)
    status, _, body = _request(port, "GET", f"/v1/sandboxes/{room}/sealed-secrets")
    assert status == 200
    doc = json.loads(body)
    assert doc["binding_sha256"] == ledger.binding_sha256
    assert doc["secrets"] == [
        {"name": "A", "version": 9, "envelope_sha256": hashlib.sha256(canonical(two)).hexdigest(), "path": "/run/secrets/A"},
        {"name": "B", "version": 3, "envelope_sha256": hashlib.sha256(canonical(one)).hexdigest(), "path": "/run/secrets/B"},
    ]
    assert VALUE not in body and b"another" not in body


def test_a_room_holds_a_bounded_number_of_secrets(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "SECRETS_MAX_PER_ROOM", 2)
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(root)
    ledger.write_sealed_secret(room, _seal(ledger, room, name="A"))
    ledger.write_sealed_secret(room, _seal(ledger, room, name="B"))
    ledger.write_sealed_secret(room, _seal(ledger, room, name="B", version=2))  # a new version is not a new name
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, _seal(ledger, room, name="C"))
    assert refused.value.code == "sealed_secrets_room_full"


# ---------------------------------------------------------------- the flag through the build and the installer

def test_the_guest_build_puts_the_flag_in_the_measured_room_env() -> None:
    text = (KIT / "sealed" / "build-guest.sh").read_text()
    body = text[text.index('cat > "$R/opt/room-kit/room.env" <<EOF'):]
    assert "ROOM_SEALED_SECRETS=${SEALED_ROOM_SEALED_SECRETS:-0}\n" in body[:body.index("\nEOF\n")]
    assert "SEALED_ROOM_SEALED_SECRETS=0\n" in (KIT / "sealed" / "sealed.env.example").read_text()


@pytest.mark.parametrize("flag,expected", [("1", "CATHEDRAL_SEALED_SECRETS_DIR=/run/room-secrets"), ("0", None)])
def test_the_api_profile_mounts_secrets_only_with_the_flag(flag, expected) -> None:
    script = f'source "{KIT / "profiles" / "v1.sh"}"; ROOM_OPT=/opt/pool-room SIZE_QUOTA=1 ROOM_API_PORT=1 ROOM_ID=r ' \
             f'ROOM_SEALED_SECRETS={flag} ROOM_EGRESS=0 profile_env'
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30, check=True).stdout
    lines = [ln for ln in out.splitlines() if ln.startswith("CATHEDRAL_SEALED_SECRETS_DIR=")]
    assert lines == ([expected] if expected else [])
