"""Customer-sealed secrets on the receipts front (room_receipts.py, AB#417 slice 1).

A sealed guest with ROOM_SEALED_SECRETS=1 names a per-boot X25519 key in its
binding, so REPORT_DATA commits to it. A customer seals a secret to that key
with the guest's one envelope construction (X25519, HKDF-SHA256, AES-256-GCM,
as the plant and the hotel key use); only this guest opens it, only into the
room incarnation its AAD names (the room's create receipt), and it lands
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
ROOM = "sbx_0123456789ab"
# The binding fields of a shared config hotel before this change (as in test_room_kit_miner_tls.py).
CONFIG_BINDING_KEYS = {"schema", "hotel", "boot_id", "created_at", "receipt_key_ed25519_b64", "measurement", "chip_id",
                       "reported_tcb", "policy", "host_data", "kernel_cmdline", "kernel_release", "software", "tenancy"}
HEADER = ("schema", "algorithm", "binding_sha256", "sandbox_id", "room_create_receipt_sha256", "name", "version")


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


def _create(ledger, room: str = ROOM, status: int = 202) -> str:
    """The create receipt the front signs when the API made the room. Returns its receipt_sha256."""
    return ledger.sign({"action": "create", "target": "POST /v1/sandboxes", "sandbox_id": room,
                        "status": status})["receipt_sha256"]


def _delete(ledger, room: str = ROOM, status: int = 204) -> None:
    ledger.sign({"action": "delete", "target": f"DELETE /v1/sandboxes/{room}", "sandbox_id": room, "status": status})


def _room(ledger, root: Path, room: str = ROOM) -> str:
    """What the room API and the front do at create: the room's directory, then its create receipt."""
    (root / room).mkdir(mode=0o755)
    _create(ledger, room)
    return room


def _seal(ledger, room: str, *, name: str = "OPENAI_API_KEY", version: int = 1, value: bytes = VALUE,
          binding_sha256: str | None = None, incarnation: str | None = None) -> dict:
    """What a customer does after checking the attestation: the key from the binding, the room's create receipt."""
    att = ledger.attestation()
    recipient = X25519PublicKey.from_public_bytes(base64.b64decode(att["binding"]["sealed_secrets"]["x25519_public_b64"]))
    return rr.seal_secret(value, recipient, binding_sha256=binding_sha256 or att["binding_sha256"], sandbox_id=room,
                          room_create_receipt_sha256=incarnation or ledger.room_incarnation(room) or "0" * 64,
                          name=name, version=version)


def _seal_with(ledger, room: str, ephemeral: X25519PrivateKey, nonce: bytes, *, name: str = "OPENAI_API_KEY",
               version: int = 1, value: bytes = VALUE) -> dict:
    """A broken client: the envelope with a chosen ephemeral key and nonce, built step by step."""
    att = ledger.attestation()
    recipient = X25519PublicKey.from_public_bytes(base64.b64decode(att["binding"]["sealed_secrets"]["x25519_public_b64"]))
    header = rr.secret_header(att["binding_sha256"], room, ledger.room_incarnation(room), name, version)
    aad = rr.secret_aad(header)
    raw_eph, raw_rec = ephemeral.public_key().public_bytes_raw(), recipient.public_bytes_raw()
    key = rr._wrapping_key(rr.SECRETS_HKDF_INFO, ephemeral.exchange(recipient), aad, raw_eph, raw_rec)
    return {**header, "ephemeral_public_b64": base64.b64encode(raw_eph).decode(),
            "nonce_b64": base64.b64encode(nonce).decode(),
            "ciphertext_b64": base64.b64encode(AESGCM(key).encrypt(nonce, value, aad)).decode()}


def _post(port: int, room: str, doc: dict):
    return _request(port, "POST", f"/v1/sandboxes/{room}/sealed-secrets", canonical(doc))


def _receipt(headers: dict) -> dict:
    h = headers["X-Room-Receipt"]
    return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))


def _code(body: bytes) -> str:
    return json.loads(body)["error"]["code"]


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
    assert named == {"schema": "cathedral_sealed_secret_v2", "algorithm": "x25519-hkdf-sha256-aes256gcm-v1",
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
    if secrets:
        room = _room(ledger, root)
        out, receipt = ledger.write_sealed_secret(room, _seal(ledger, room))
        assert out["status"] == "written" and receipt is not None
    else:
        _create(ledger)
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

def _sealed(private: X25519PrivateKey, value: bytes = VALUE, **kw) -> dict:
    fields = {"binding_sha256": "a" * 64, "sandbox_id": "sbx_1", "room_create_receipt_sha256": "c" * 64, "name": "N",
              "version": 7}
    fields.update(kw)
    return rr.seal_secret(value, private.public_key(), **fields)


def test_the_envelope_opens_step_by_step_as_a_browser_would() -> None:
    """Open with X25519, HMAC-SHA256 (HKDF, RFC 5869) and AES-256-GCM only, written out here.

    Each step is one WebCrypto call (deriveBits X25519, HKDF, AES-GCM), so a
    pass pins the wire format a second client must produce, apart from
    room_receipts' own _open_envelope.
    """
    private = X25519PrivateKey.generate()
    doc = _sealed(private)
    assert set(doc) == set(HEADER) | {"ephemeral_public_b64", "nonce_b64", "ciphertext_b64"}
    assert doc["schema"] == "cathedral_sealed_secret_v2" and doc["algorithm"] == "x25519-hkdf-sha256-aes256gcm-v1"
    header = {k: doc[k] for k in HEADER}
    aad = b"cathedral.sealed-secret.v2\n" + canonical(header)
    eph = base64.b64decode(doc["ephemeral_public_b64"])
    rec = private.public_key().public_bytes_raw()
    shared = private.exchange(X25519PublicKey.from_public_bytes(eph))
    prk = hmac.new(aad, shared, hashlib.sha256).digest()  # HKDF-Extract, salt = AAD
    key = hmac.new(prk, b"cathedral.sealed-secret.v2" + eph + rec + b"\x01", hashlib.sha256).digest()  # one block
    nonce = base64.b64decode(doc["nonce_b64"])
    assert len(nonce) == 12
    assert AESGCM(key).decrypt(nonce, base64.b64decode(doc["ciphertext_b64"]), aad) == VALUE


def test_every_seal_draws_a_fresh_ephemeral_key_and_nonce() -> None:
    """A constant ephemeral key in the sealer lets anyone derive every wrapping key; a constant nonce repeats.

    The same value, header and recipient sealed twice must differ in all three
    envelope fields, and neither the key nor the nonce may be a fixed value.
    """
    private = X25519PrivateKey.generate()
    seals = [_sealed(private) for _ in range(3)]
    for field in ("ephemeral_public_b64", "nonce_b64", "ciphertext_b64"):
        assert len({doc[field] for doc in seals}) == 3, field
    for doc in seals:
        assert base64.b64decode(doc["nonce_b64"]) != bytes(12)
        assert doc["ephemeral_public_b64"] != base64.b64encode(
            X25519PrivateKey.from_private_bytes(bytes(32)).public_key().public_bytes_raw()).decode()
        assert rr.open_secret(doc, private) == VALUE


def test_the_secret_envelope_never_opens_as_a_plant_or_install_envelope() -> None:
    """Same construction, own HKDF info and AAD: no cross-use with the other two."""
    private = X25519PrivateKey.generate()
    doc = _sealed(private)
    envelope = {k: doc[k] for k in ("algorithm", "ephemeral_public_b64", "nonce_b64", "ciphertext_b64")}
    with pytest.raises(rr.PlantError):
        rr._open_envelope(envelope, private, rr.PLANT_HKDF_INFO, rr.secret_aad({k: doc[k] for k in rr.SECRETS_HEADER}))
    with pytest.raises(rr.PlantError):
        rr._open_envelope(envelope, private, rr.INSTALL_HKDF_INFO, rr.install_aad("a" * 64))


@pytest.mark.parametrize("size", [0, 2049, 64 * 1024])
def test_an_empty_and_the_largest_value_open(size) -> None:
    private = X25519PrivateKey.generate()
    value = os.urandom(size)
    assert rr.open_secret(_sealed(private, value, version=1), private) == value


def test_the_plant_envelope_keeps_its_own_size_bound() -> None:
    private = X25519PrivateKey.generate()
    big = rr._seal_envelope(b"n" * 2100, private.public_key(), rr.PLANT_HKDF_INFO, b"aad")
    with pytest.raises(rr.PlantError):
        rr._open_envelope(big, private, rr.PLANT_HKDF_INFO, b"aad")


def test_every_header_field_is_authenticated() -> None:
    private = X25519PrivateKey.generate()
    doc = _sealed(private)
    assert rr.open_secret(doc, private) == VALUE
    flipped = base64.b64decode(doc["ciphertext_b64"])
    flipped = base64.b64encode(bytes([flipped[0] ^ 1]) + flipped[1:]).decode()
    for field, other in (("binding_sha256", "b" * 64), ("sandbox_id", "sbx_2"), ("room_create_receipt_sha256", "d" * 64),
                         ("name", "M"), ("version", 8), ("schema", "cathedral_sealed_secret_v1"),
                         ("ciphertext_b64", flipped), ("nonce_b64", base64.b64encode(bytes(12)).decode()),
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
    room = _room(ledger, root)
    port, api = _front(ledger)
    doc = _seal(ledger, room)
    status, headers, body = _post(port, room, doc)
    assert status == 200, body
    answer = json.loads(body)
    envelope_sha256 = hashlib.sha256(canonical(doc)).hexdigest()
    incarnation = ledger.room_incarnation(room)
    assert incarnation == ledger.create_receipt(room)["receipt_sha256"]
    assert answer == {"sandbox_id": room, "room_create_receipt_sha256": incarnation, "name": "OPENAI_API_KEY",
                      "version": 1, "envelope_sha256": envelope_sha256, "path": "/run/secrets/OPENAI_API_KEY",
                      "status": "written"}
    written = root / room / "OPENAI_API_KEY"
    assert written.read_bytes() == VALUE
    assert stat.S_IMODE(written.stat().st_mode) == 0o444
    assert [p.name for p in (root / room).iterdir()] == ["OPENAI_API_KEY"]  # no temp file left
    receipt = _receipt(headers)
    st = receipt["statement"]
    assert st["action"] == "sealed_secret_write" and st["sandbox_id"] == room and st["envelope_sha256"] == envelope_sha256
    assert st["room_create_receipt_sha256"] == incarnation
    assert st["secret_name"] == "OPENAI_API_KEY" and st["secret_version"] == 1 and st["path"] == "/run/secrets/OPENAI_API_KEY"
    Ed25519PublicKey.from_public_bytes(base64.b64decode(ledger.binding["receipt_key_ed25519_b64"])).verify(
        base64.b64decode(receipt["signature_b64"]), canonical(st))
    everything = body + canonical(receipt) + b"".join(canonical(r) for r in ledger.chain)
    for leak in (VALUE, hashlib.sha256(VALUE).hexdigest().encode(), base64.b64encode(VALUE)):
        assert leak not in everything
    assert api.seen == []  # the envelope never reaches the room API


def test_exact_retry_is_unchanged_and_carries_the_original_receipt(tmp_path, monkeypatch) -> None:
    """Review finding 2: an unchanged answer is provable, so a relay cannot fake one for an envelope it dropped."""
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    port, _ = _front(ledger)
    doc = _seal(ledger, room)
    status, first, _ = _post(port, room, doc)
    assert status == 200
    status, headers, body = _post(port, room, doc)
    assert status == 200 and json.loads(body)["status"] == "unchanged"
    assert headers["X-Room-Receipt"] == first["X-Room-Receipt"]  # the write's own receipt, not a new one
    assert _receipt(headers)["statement"]["envelope_sha256"] == hashlib.sha256(canonical(doc)).hexdigest()
    assert len(ledger.chain) == 2  # create and the one write
    # Direct call: the same receipt object as the write.
    assert ledger.write_sealed_secret(room, doc)[1] == _receipt(first)


def test_an_unchanged_answer_without_its_receipt_says_so(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    port, _ = _front(ledger)
    doc = _seal(ledger, room)
    real = ledger.sign

    def failing(fields):
        if fields.get("action") == "sealed_secret_write":
            raise RuntimeError("sign failed")
        return real(fields)

    monkeypatch.setattr(ledger, "sign", failing)
    for expected in ("written", "unchanged"):
        status, headers, body = _post(port, room, doc)
        assert status == 200 and json.loads(body)["status"] == expected
        assert "X-Room-Receipt" not in headers and headers["X-Room-Receipt-Error"] == "sign_failed"


def test_an_older_envelope_cannot_roll_the_secret_back(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    port, _ = _front(ledger)
    old = _seal(ledger, room, version=1, value=b"old-value")
    assert _post(port, room, old)[0] == 200
    assert _post(port, room, _seal(ledger, room, version=2, value=b"new-value"))[0] == 200
    for replay in (old, _seal(ledger, room, version=2, value=b"other-value")):
        status, _, body = _post(port, room, replay)
        assert status == 409 and _code(body) == "sealed_secret_replayed"
    assert (root / room / "OPENAI_API_KEY").read_bytes() == b"new-value"
    assert len(ledger.chain) == 3


def test_a_reused_ephemeral_key_is_refused(tmp_path, monkeypatch) -> None:
    """A client with a constant ephemeral key fails on its second write to the room, whatever the name."""
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    fixed = X25519PrivateKey.generate()
    first = _seal_with(ledger, room, fixed, os.urandom(12), version=1)
    assert ledger.write_sealed_secret(room, first)[0]["status"] == "written"
    for doc in (_seal_with(ledger, room, fixed, os.urandom(12), version=2),
                _seal_with(ledger, room, fixed, os.urandom(12), name="OTHER")):
        with pytest.raises(rr.SecretRefused) as refused:
            ledger.write_sealed_secret(room, doc)
        assert (refused.value.status, refused.value.code) == (400, "sealed_secret_ephemeral_reused")
    assert (root / room / "OPENAI_API_KEY").read_bytes() == VALUE and not (root / room / "OTHER").exists()
    # A fresh key at the next version is fine.
    assert ledger.write_sealed_secret(room, _seal(ledger, room, version=2))[0]["status"] == "written"


def test_a_room_made_again_under_its_id_refuses_old_envelopes(tmp_path, monkeypatch) -> None:
    """The incarnation (create receipt sha256) is in the AAD and must be the room's current one."""
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    doc = _seal(ledger, room, version=5)
    ledger.write_sealed_secret(room, doc)
    before = ledger.room_incarnation(room)
    for f in (root / room).iterdir():
        f.unlink()
    (root / room).rmdir()  # the API dropped the room
    _delete(ledger, room)
    assert ledger.room_incarnation(room) is None
    _room(ledger, root, room)  # and made one with the same id: a new create receipt
    after = ledger.room_incarnation(room)
    assert after not in (None, before)
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, doc)
    assert (refused.value.status, refused.value.code) == (409, "sealed_secret_wrong_incarnation")
    # The relay rewrites the incarnation: the AAD no longer matches.
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, {**doc, "room_create_receipt_sha256": after})
    assert refused.value.code == "sealed_secret_does_not_open"
    assert not (root / room / "OPENAI_API_KEY").exists()
    # The new room starts its own versions: version 1 is fine there.
    assert ledger.write_sealed_secret(room, _seal(ledger, room, version=1))[0]["status"] == "written"


def test_a_create_replay_of_a_live_room_is_a_new_incarnation(tmp_path, monkeypatch) -> None:
    """An idempotent replay signs another create receipt: envelopes for the earlier one are refused, files stay."""
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    doc = _seal(ledger, room, version=3)
    ledger.write_sealed_secret(room, doc)
    _create(ledger, room)
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, doc)
    assert refused.value.code == "sealed_secret_wrong_incarnation"
    assert (root / room / "OPENAI_API_KEY").read_bytes() == VALUE
    assert ledger.write_sealed_secret(room, _seal(ledger, room, version=4, value=b"v4"))[0]["status"] == "written"
    assert ledger.secrets.tracked == 1  # the earlier incarnation's entry went


def test_a_room_with_no_create_receipt_or_a_delete_after_it_is_404(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    (root / ROOM).mkdir()  # a directory, but this boot signed no create for it
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(ROOM, _seal(ledger, ROOM))
    assert (refused.value.status, refused.value.code) == (404, "sealed_secret_room_not_found")
    _create(ledger, ROOM, status=500)  # a failed create names no room
    with pytest.raises(rr.SecretRefused):
        ledger.write_sealed_secret(ROOM, _seal(ledger, ROOM))
    _create(ledger, ROOM)
    doc = _seal(ledger, ROOM)
    _delete(ledger, ROOM)
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(ROOM, doc)
    assert refused.value.code == "sealed_secret_room_not_found"
    assert not any((root / ROOM).iterdir())


def test_an_envelope_for_another_boot_is_refused_so_the_client_reseals(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    other, _, _ = _ledger(tmp_path / "other", monkeypatch)
    room = _room(ledger, root)
    port, _ = _front(ledger)
    incarnation = ledger.room_incarnation(room)
    status, _, body = _post(port, room, _seal(other, room, incarnation=incarnation))
    assert status == 409 and _code(body) == "sealed_secret_wrong_binding"
    # Right binding hash, wrong key (another guest's): it does not open.
    forged = _seal(other, room, binding_sha256=ledger.binding_sha256, incarnation=incarnation)
    status, _, body = _post(port, room, forged)
    assert status == 400 and _code(body) == "sealed_secret_does_not_open"
    assert not (root / room / "OPENAI_API_KEY").exists() and len(ledger.chain) == 1


def test_an_envelope_for_one_room_never_opens_in_another(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    a, b = _room(ledger, root, "sbx_aaaaaaaaaaaa"), _room(ledger, root, "sbx_bbbbbbbbbbbb")
    port, _ = _front(ledger)
    doc = _seal(ledger, a)
    status, _, body = _post(port, b, doc)
    assert status == 400 and _code(body) == "sealed_secret_wrong_room"
    status, _, body = _post(port, b, {**doc, "sandbox_id": b})  # the relay rewrites the room
    assert status == 409 and _code(body) == "sealed_secret_wrong_incarnation"
    status, _, body = _post(port, b, {**doc, "sandbox_id": b, "room_create_receipt_sha256": ledger.room_incarnation(b)})
    assert status == 400 and _code(body) == "sealed_secret_does_not_open"
    assert not any((root / b).iterdir())


def test_a_room_without_a_secrets_directory_is_404(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    port, _ = _front(ledger)
    _create(ledger, ROOM)
    status, _, body = _post(port, ROOM, _seal(ledger, ROOM))
    assert status == 404 and _code(body) == "sealed_secret_room_not_found"
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "sbx_linkedlinked").symlink_to(outside)
    _create(ledger, "sbx_linkedlinked")
    status, _, _ = _post(port, "sbx_linkedlinked", _seal(ledger, "sbx_linkedlinked"))
    assert status == 404 and not any(outside.iterdir())


@pytest.mark.parametrize("name", ["../escape", ".hidden", "a/b", "", "x" * 129, "white space"])
def test_names_that_are_not_one_plain_file_are_refused(tmp_path, monkeypatch, name) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, _seal(ledger, room, name=name))
    assert refused.value.code == "sealed_secret_name_invalid"
    assert not any((root / room).iterdir())


@pytest.mark.parametrize("change", [
    {"version": 0}, {"version": 2**53}, {"version": "1"}, {"version": True}, {"schema": "other"},
    {"schema": "cathedral_sealed_secret_v1"}, {"algorithm": "hpke-base-x25519-hkdf-sha256-aes-256-gcm"}, {"extra": 1},
    {"sealed_b64": "AAAA"}, {"room_create_receipt_sha256": "C" * 64}, {"room_create_receipt_sha256": None},
    {"nonce_b64": 1}, {"ciphertext_b64": None},
])
def test_malformed_requests_are_refused_before_any_write(tmp_path, monkeypatch, change) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, {**_seal(ledger, room), **change})
    assert refused.value.status == 400
    assert not any((root / room).iterdir())


def test_a_v1_envelope_is_refused(tmp_path, monkeypatch) -> None:
    """v1 (no incarnation) never shipped; its six-field header is not accepted."""
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    doc = _seal(ledger, room)
    v1 = {k: v for k, v in doc.items() if k != "room_create_receipt_sha256"} | {"schema": "cathedral_sealed_secret_v1"}
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, v1)
    assert refused.value.code == "sealed_secret_fields_invalid"


@pytest.mark.parametrize("field", ["ephemeral_public_b64", "nonce_b64", "ciphertext_b64"])
def test_a_lone_surrogate_in_an_envelope_field_is_400_and_the_front_keeps_serving(tmp_path, monkeypatch, field) -> None:
    """Review finding 4: the field is hashed before it is opened; a lone surrogate must not drop the connection."""
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    port, _ = _front(ledger)
    doc = _seal(ledger, room)
    bad = canonical(doc).replace(json.dumps(doc[field]).encode(), b'"\\ud800"')
    assert bad != canonical(doc)
    status, _, body = _request(port, "POST", f"/v1/sandboxes/{room}/sealed-secrets", bad)
    assert status == 400 and _code(body) == "sealed_secret_fields_invalid"
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, json.loads(bad))
    assert refused.value.code == "sealed_secret_fields_invalid"
    status, _, body = _post(port, room, doc)
    assert status == 200, body
    assert len(ledger.chain) == 2


def test_flag_off_answers_403_and_never_reaches_the_api(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch, secrets=False)
    (root / ROOM).mkdir()
    port, api = _front(ledger)
    status, _, body = _request(port, "POST", f"/v1/sandboxes/{ROOM}/sealed-secrets", b'{"sealed_b64":"AAAA"}')
    assert status == 403 and _code(body) == "sealed_secrets_disabled"
    assert api.seen == []
    # The rest of the room API still passes through, and a delete leaves the directory to the API.
    assert _request(port, "GET", f"/v1/sandboxes/{ROOM}")[0] == 200 and api.seen
    assert _request(port, "DELETE", f"/v1/sandboxes/{ROOM}")[0] == 200 and (root / ROOM).is_dir()


def test_the_route_needs_the_hotel_key(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    port, _ = _front(ledger)
    doc = canonical(_seal(ledger, room))
    assert _request(port, "POST", f"/v1/sandboxes/{room}/sealed-secrets", doc, key=None)[0] == 401
    assert _request(port, "POST", f"/v1/sandboxes/{room}/sealed-secrets", doc, key=b"w" * 32)[0] == 401
    assert _request(port, "DELETE", f"/v1/sandboxes/{room}/sealed-secrets")[0] == 405
    assert not any((root / room).iterdir())


def test_too_large_is_413(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    port, _ = _front(ledger)
    status, _, _ = _request(port, "POST", f"/v1/sandboxes/{room}/sealed-secrets", b"{" + b" " * rr.SECRETS_MAX_BYTES + b"}")
    assert status == 413
    big = _seal(ledger, room, value=b"v" * (rr.SECRET_VALUE_MAX_BYTES + 1))
    with pytest.raises(rr.SecretRefused):
        ledger.write_sealed_secret(room, big)


def test_listing_shows_names_and_versions_of_this_incarnation_only(tmp_path, monkeypatch) -> None:
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    port, _ = _front(ledger)
    one, two = _seal(ledger, room, name="B", version=3), _seal(ledger, room, name="A", version=9, value=b"another")
    _post(port, room, one)
    _post(port, room, two)
    status, _, body = _request(port, "GET", f"/v1/sandboxes/{room}/sealed-secrets")
    assert status == 200
    doc = json.loads(body)
    assert doc["binding_sha256"] == ledger.binding_sha256
    assert doc["room_create_receipt_sha256"] == ledger.room_incarnation(room)
    assert doc["secrets"] == [
        {"name": "A", "version": 9, "envelope_sha256": hashlib.sha256(canonical(two)).hexdigest(), "path": "/run/secrets/A"},
        {"name": "B", "version": 3, "envelope_sha256": hashlib.sha256(canonical(one)).hexdigest(), "path": "/run/secrets/B"},
    ]
    assert VALUE not in body and b"another" not in body
    _create(ledger, room)  # made again: nothing accepted for the new incarnation yet
    assert json.loads(_request(port, "GET", f"/v1/sandboxes/{room}/sealed-secrets")[2])["secrets"] == []


def test_a_room_holds_a_bounded_number_of_secrets(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "SECRETS_MAX_PER_ROOM", 2)
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    ledger.write_sealed_secret(room, _seal(ledger, room, name="A"))
    ledger.write_sealed_secret(room, _seal(ledger, room, name="B"))
    ledger.write_sealed_secret(room, _seal(ledger, room, name="B", version=2))  # a new version is not a new name
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, _seal(ledger, room, name="C"))
    assert refused.value.code == "sealed_secrets_room_full"
    # The bound is the room's directory: a re-create does not reset it while the files stay.
    _create(ledger, room)
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, _seal(ledger, room, name="C"))
    assert refused.value.code == "sealed_secrets_room_full"
    assert ledger.write_sealed_secret(room, _seal(ledger, room, name="A", version=1))[0]["status"] == "written"


# ---------------------------------------------------------------- the per-boot table (review finding 1)

def test_entries_of_rooms_that_are_gone_never_fill_the_boot_table(tmp_path, monkeypatch) -> None:
    """Default constants: 65,536 entries of deleted rooms used to refuse every new room (503) until a restart."""
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    assert rr.SECRETS_MAX_TRACKED == 65536
    box = ledger.secrets
    with box.lock:
        for i in range(1024):  # 1,024 rooms written to and gone (the API dropped their directories)
            for j in range(64):
                box.record(f"sbx_dead{i:08x}", "e" * 64, f"N{j}", rr.AcceptedSecret(1, "00" * 32, f"k{i}.{j}", None))
    assert box.tracked == rr.SECRETS_MAX_TRACKED
    fresh = _room(ledger, root, "sbx_freshfresh01")
    out, receipt = ledger.write_sealed_secret(fresh, _seal(ledger, fresh, name="API_KEY"))
    assert out["status"] == "written" and receipt is not None
    assert box.tracked == 1 and list(box.rooms) == [fresh]


@pytest.mark.parametrize("gone", ["delete_through_the_front", "directory_dropped", "made_again"])
def test_a_full_table_frees_the_entries_of_rooms_that_went(tmp_path, monkeypatch, gone) -> None:
    """Real writes at a cap of 4: two rooms with two secrets each go, then a third room writes."""
    monkeypatch.setattr(rr, "SECRETS_MAX_TRACKED", 4)
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    port, _ = _front(ledger)
    for i in range(2):
        room = _room(ledger, root, f"sbx_{i:012x}")
        for name in ("A", "B"):
            assert _post(port, room, _seal(ledger, room, name=name))[0] == 200
        if gone == "delete_through_the_front":
            assert _request(port, "DELETE", f"/v1/sandboxes/{room}")[0] == 200
        elif gone == "directory_dropped":  # expiry or a bulk delete: the API drops it, the front sees no delete
            for f in (root / room).iterdir():
                f.unlink()
            (root / room).rmdir()
        else:
            _create(ledger, room)
    other = _room(ledger, root, "sbx_otherother1")
    status, _, body = _post(port, other, _seal(ledger, other))
    assert status == 200, body
    assert ledger.secrets.tracked == 1


def test_a_full_table_of_live_rooms_still_refuses(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "SECRETS_MAX_TRACKED", 2)
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    for name in ("A", "B"):
        ledger.write_sealed_secret(room, _seal(ledger, room, name=name))
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, _seal(ledger, room, name="C"))
    assert (refused.value.status, refused.value.code) == (503, "sealed_secrets_full")
    # A new version of a name it holds is not a new entry.
    assert ledger.write_sealed_secret(room, _seal(ledger, room, name="A", version=2))[0]["status"] == "written"


# ---------------------------------------------------------------- a write racing a delete (review finding 5)

def test_a_delete_through_the_front_removes_a_file_a_racing_write_left(tmp_path, monkeypatch) -> None:
    """The API's rmtree lost a race with a rename (ENOTEMPTY); the front removes the rest after the receipt."""
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    port, _ = _front(ledger)
    doc = _seal(ledger, room)
    assert _post(port, room, doc)[0] == 200
    assert ledger.secrets.tracked == 1
    status, headers, _ = _request(port, "DELETE", f"/v1/sandboxes/{room}")  # the fake API leaves the directory
    assert status == 200 and _receipt(headers)["statement"]["action"] == "delete"
    assert not (root / room).exists()
    assert ledger.secrets.tracked == 0 and ledger.room_incarnation(room) is None
    (root / room).mkdir()  # whatever comes back under the id, the incarnation is gone
    status, _, body = _post(port, room, _seal(ledger, room, version=2, incarnation=doc["room_create_receipt_sha256"]))
    assert status == 404 and _code(body) == "sealed_secret_room_not_found"
    assert not any((root / room).iterdir())


@pytest.mark.parametrize("room", ["..", ".", "%2e%2e", "sbx_x;y"])
def test_a_delete_of_an_odd_room_id_removes_nothing_outside_its_own_directory(tmp_path, monkeypatch, room) -> None:
    """The delete route matches any path segment and the API answers 2xx for an unknown id."""
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    keep = _room(ledger, root, "sbx_keepkeepkeep")
    (root / keep / "A").write_bytes(b"x")
    port, _ = _front(ledger)
    status, headers, _ = _request(port, "DELETE", f"/v1/sandboxes/{room}")
    assert status == 200 and _receipt(headers)["statement"]["action"] == "delete"
    assert (root / keep / "A").exists() and (tmp_path / "store").is_dir()


def test_a_write_into_a_directory_removed_while_it_opened_is_404(tmp_path, monkeypatch) -> None:
    """Expiry: the API drops the directory while the envelope opens; nothing is written, no traceback, no 500."""
    ledger, _, root = _ledger(tmp_path, monkeypatch)
    room = _room(ledger, root)
    real = rr.open_secret

    def open_then_retire(doc, private):
        value = real(doc, private)
        (root / room).rmdir()
        return value

    monkeypatch.setattr(rr, "open_secret", open_then_retire)
    with pytest.raises(rr.SecretRefused) as refused:
        ledger.write_sealed_secret(room, _seal(ledger, room))
    assert (refused.value.status, refused.value.code) == (404, "sealed_secret_room_not_found")
    assert not (root / room).exists() and ledger.secrets.tracked == 0


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
