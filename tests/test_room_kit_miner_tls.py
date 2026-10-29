"""Miner hotel (ROOM_MINER=1): attested guest TLS and the per-hotel key install (AB#57).

The control plane side is polariscomputer #1588 (cathedral_hotel_reconciler.
RoomKitKeyInstaller and cathedral_hotel_offers.verify_attestation). The
request built here follows that code step by step: GET the install key over
TLS pinned to the binding's tls_spki_sha256, check its receipt-key signature,
seal the key (X25519, HKDF-SHA256 with salt = AAD and info = label + eph +
recipient, AES-256-GCM), sign canonical(request) with Ed25519, POST.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import importlib.util
import json
import os
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KIT = Path(__file__).resolve().parents[1] / "room-kit"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rr = _load("room_receipts_miner_t", KIT / "room_receipts.py")
vr = _load("verify_receipts_miner_t", KIT / "verify_receipts.py")

INTERNAL = b"guest-internal-key-" + b"i" * 24  # the API's own key: made in the guest, never sent out
CONTROL = Ed25519PrivateKey.generate()  # the control plane install key
CONTROL_B64 = base64.b64encode(CONTROL.public_key().public_bytes_raw()).decode()
CONFIG_BINDING_KEYS = {"schema", "hotel", "boot_id", "created_at", "receipt_key_ed25519_b64", "measurement", "chip_id",
                       "reported_tcb", "policy", "host_data", "kernel_cmdline", "kernel_release", "software"}


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# ---------------------------------------------------------------- fixtures

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


def _ledger(tmp_path, monkeypatch, *, miner=True, signers=(CONTROL_B64,)):
    """A sealed ledger on a fake SNP report that carries whatever REPORT_DATA the guest asks for."""
    asked: list[bytes] = []

    def report(data: bytes) -> bytes:
        asked.append(data)
        return _fake_report(data)

    monkeypatch.setattr(rr, "tsm_provider", lambda: "sev_guest")
    monkeypatch.setattr(rr, "snp_report", report)
    hotel = rr.MinerHotel("miner-box", rr.parse_install_signers(" ".join(signers))) if miner else None
    ledger = rr.Ledger("miner-box", str(tmp_path / "store"), miner=hotel)
    return ledger, asked


class Upstream:
    """The room API behind the front: records the Authorization it was given."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str, str | None]] = []
        outer = self

        class Api(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def answer(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                outer.seen.append((self.command, self.path, self.headers.get("Authorization")))
                body = b'{"ok":true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_DELETE = answer  # noqa: N815

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Api)
        Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]


def _miner_front(ledger, upstream: Upstream, tmp_path, tls_context=None):
    ctx = tls_context or ledger.miner.tls_context(str(tmp_path / "store"))
    tls = rr.TLSServer(("127.0.0.1", 0), ledger, upstream.port, 1, INTERNAL, "/nonexistent.sock", tls_context=ctx)
    Thread(target=tls.serve_forever, daemon=True).start()
    plain = rr.Server(("127.0.0.1", 0), ledger, upstream.port, 1, INTERNAL, "/nonexistent.sock", attestation_only=True)
    Thread(target=plain.serve_forever, daemon=True).start()
    return tls.server_address[1], plain.server_address[1]


class PinMismatch(Exception):
    pass


def _https(port: int, method: str, path: str, *, body: bytes | None = None, key: bytes | None = None,
           pin: str | None = None):
    """One request over TLS. With pin, nothing is sent unless the peer SPKI equals it (the control plane rule)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=ctx)
    try:
        conn.connect()
        spki = vr.spki_sha256_of_certificate(conn.sock.getpeercert(binary_form=True))
        if pin is not None and spki != pin:
            raise PinMismatch(spki)
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if key is not None:
            headers["Authorization"] = "Bearer " + key.decode()
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read(), spki
    finally:
        conn.close()


def _http(port: int, method: str, path: str, *, body: bytes | None = None, key: bytes | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Authorization": "Bearer " + key.decode()} if key is not None else {}
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    return resp.status, resp.read()


# ---------------------------------------------------------------- the #1588 control plane request

def seal_1588(plaintext: bytes, recipient_raw: bytes, binding_sha256: str) -> dict:
    """polariscomputer #1588 cathedral_hotel_reconciler.seal_hotel_key, as written there."""
    recipient = X25519PublicKey.from_public_bytes(recipient_raw)
    ephemeral = X25519PrivateKey.generate()
    raw_eph = ephemeral.public_key().public_bytes_raw()
    aad = f"hotel-key-install:{binding_sha256}".encode()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=aad,
               info=b"cathedral.hotel-key-install.v1" + raw_eph + recipient_raw).derive(ephemeral.exchange(recipient))
    nonce = os.urandom(12)
    return {"algorithm": "x25519-hkdf-sha256-aes256gcm-v1", "ephemeral_public_b64": base64.b64encode(raw_eph).decode(),
            "nonce_b64": base64.b64encode(nonce).decode(),
            "ciphertext_b64": base64.b64encode(AESGCM(key).encrypt(nonce, plaintext, aad)).decode()}


def check_install_key_1588(doc: dict, binding_sha256: str, receipt_key_b64: str) -> bytes:
    """#1588 RoomKitKeyInstaller step 1: the statement, its receipt-key signature, the recipient."""
    statement = {k: doc.get(k) for k in ("algorithm", "binding_sha256", "purpose", "x25519_public_b64")}
    assert statement["algorithm"] == "x25519-hkdf-sha256-aes256gcm-v1"
    assert statement["purpose"] == "hotel-key-install" and statement["binding_sha256"] == binding_sha256
    Ed25519PublicKey.from_public_bytes(base64.b64decode(receipt_key_b64)).verify(
        base64.b64decode(doc["signature_b64"], validate=True), canonical(statement))
    recipient = base64.b64decode(statement["x25519_public_b64"], validate=True)
    assert len(recipient) == 32
    return recipient


def request_1588(key: str, recipient: bytes, binding_sha256: str, *, hotel_id="miner-0123456789abcdef01234567",
                 issued_at=None, signer=CONTROL, **changes) -> dict:
    """#1588 RoomKitKeyInstaller step 2: the signed install request."""
    request = {"schema": "cathedral_hotel_key_install_v1", "binding_sha256": binding_sha256, "hotel_id": hotel_id,
               "key_sha256": hashlib.sha256(key.encode()).hexdigest(),
               "issued_at": int(time.time()) if issued_at is None else issued_at,
               "envelope": seal_1588(key.encode(), recipient, binding_sha256), **changes}
    request["signature_b64"] = base64.b64encode(signer.sign(canonical(request))).decode()
    return request


def _hotel_key(tag: str) -> str:
    return (tag * 43)[:43]  # secrets.token_urlsafe(32) shape: 43 of [A-Za-z0-9_-]


def _recipient(ledger) -> bytes:
    return check_install_key_1588(ledger.install_key_document(), ledger.binding_sha256,
                                  ledger.binding["receipt_key_ed25519_b64"])


# ---------------------------------------------------------------- binding and REPORT_DATA

def test_binding_names_the_tls_and_install_keys_and_report_data_commits_to_them(tmp_path, monkeypatch) -> None:
    ledger, asked = _ledger(tmp_path, monkeypatch)
    binding, miner = ledger.binding, ledger.miner
    cert = x509.load_pem_x509_certificate(miner.cert_pem)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert binding["tls_spki_sha256"] == hashlib.sha256(spki).hexdigest() == miner.tls_spki_sha256
    assert binding["hotel_key_install_x25519_b64"] == base64.b64encode(
        miner.install_private.public_key().public_bytes_raw()).decode()
    assert binding["hotel_key_install_signers_ed25519_b64"] == [CONTROL_B64]
    assert binding["hotel_key_source"] == "install"
    assert set(binding) == CONFIG_BINDING_KEYS | {"tls_spki_sha256", "hotel_key_install_x25519_b64",
                                                  "hotel_key_install_signers_ed25519_b64", "hotel_key_source"}
    # The second report is the boot report: REPORT_DATA = sha256(canonical(binding)) || 32 zero bytes.
    assert ledger.binding_sha256 == hashlib.sha256(canonical(binding)).hexdigest()
    assert asked[-1] == bytes.fromhex(ledger.binding_sha256) + bytes(32)
    att = ledger.attestation()
    out = vr.verify_attestation(att, "ab" * 48, None, str(tmp_path), None, skip_amd=True)
    assert out["binding_sha256"] == ledger.binding_sha256
    assert vr.verify_guest_tls(att, miner.tls_spki_sha256)["tls_spki_sha256"] == miner.tls_spki_sha256

    # A host that swaps in its own TLS key changes the binding: the report no longer commits to it.
    forged = json.loads(json.dumps(att))
    forged["binding"]["tls_spki_sha256"] = "5e" * 32
    forged["binding_sha256"] = hashlib.sha256(canonical(forged["binding"])).hexdigest()
    with pytest.raises(vr.Fail, match="REPORT_DATA does not commit"):
        vr.verify_attestation(forged, None, None, str(tmp_path), None, skip_amd=True)
    forged["binding_sha256"] = att["binding_sha256"]
    with pytest.raises(vr.Fail, match="binding_sha256 does not match"):
        vr.verify_attestation(forged, None, None, str(tmp_path), None, skip_amd=True)


def test_each_boot_makes_new_keys(tmp_path, monkeypatch) -> None:
    a, _ = _ledger(tmp_path / "a", monkeypatch)
    b, _ = _ledger(tmp_path / "b", monkeypatch)
    assert a.binding["tls_spki_sha256"] != b.binding["tls_spki_sha256"]
    assert a.binding["hotel_key_install_x25519_b64"] != b.binding["hotel_key_install_x25519_b64"]


def test_a_config_hotel_binding_is_unchanged(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch, miner=False)
    assert set(ledger.binding) == CONFIG_BINDING_KEYS
    assert ledger.install_key_document() is None
    att = ledger.attestation()
    assert vr.verify_guest_tls(att) is None
    with pytest.raises(vr.Fail, match="names no guest TLS key"):
        vr.verify_guest_tls(att, require=True)
    with pytest.raises(vr.Fail, match="names no guest TLS key"):
        vr.verify_guest_tls(att, "5e" * 32)


def test_miner_mode_refuses_an_unsealed_host(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(rr, "tsm_provider", lambda: None)
    with pytest.raises(RuntimeError, match="sealed guest"):
        rr.Ledger("miner-box", str(tmp_path), miner=rr.MinerHotel("miner-box", [CONTROL.public_key().public_bytes_raw()]))


@pytest.mark.parametrize("raw", ["", "   ", "not-base64!", base64.b64encode(b"x" * 31).decode(),
                                 " ".join(base64.b64encode(os.urandom(32)).decode() for _ in range(5))])
def test_install_signers_must_be_one_to_four_ed25519_keys(raw) -> None:
    with pytest.raises(ValueError):
        rr.parse_install_signers(raw)


# ---------------------------------------------------------------- TLS pinned to the bound key

def test_tls_pinned_to_the_bound_key_succeeds_and_another_key_fails(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    upstream = Upstream()
    tls_port, _ = _miner_front(ledger, upstream, tmp_path)
    status, _, body, spki = _https(tls_port, "GET", "/room/attestation", pin=ledger.binding["tls_spki_sha256"])
    assert status == 200 and spki == ledger.binding["tls_spki_sha256"]
    att = json.loads(body)
    assert att["binding_sha256"] == ledger.binding_sha256
    vr.verify_guest_tls(att, spki)

    # The host terminates TLS with a key of its own and relays the guest's genuine attestation.
    impostor_key = rr.MinerHotel("miner-box", [CONTROL.public_key().public_bytes_raw()])
    impostor_port, _ = _miner_front(ledger, upstream, tmp_path, tls_context=impostor_key.tls_context(str(tmp_path)))
    with pytest.raises(PinMismatch):
        _https(impostor_port, "GET", "/room/attestation", pin=ledger.binding["tls_spki_sha256"])
    status, _, body, spki = _https(impostor_port, "GET", "/room/attestation")
    assert status == 200 and json.loads(body) == att  # the same document, from the wrong peer
    with pytest.raises(vr.Fail, match="TLS peer is not the key the binding names"):
        vr.verify_guest_tls(json.loads(body), spki)


def test_verify_receipts_origin_mode_checks_the_peer_and_the_install_key(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    upstream = Upstream()
    tls_port, _ = _miner_front(ledger, upstream, tmp_path)
    answers, spki = vr.fetch_origin(f"https://127.0.0.1:{tls_port}", ["/room/attestation", "/room/hotel-key-install-key"])
    att, install = json.loads(answers[0][1]), json.loads(answers[1][1])
    assert spki == att["binding"]["tls_spki_sha256"]
    assert vr.verify_install_key(install, att) == att["binding"]["hotel_key_install_x25519_b64"]
    other = rr.MinerHotel("x", [CONTROL.public_key().public_bytes_raw()])
    forged = {**install, "x25519_public_b64": other.install_public_b64}
    with pytest.raises(vr.Fail, match="not signed by the binding's receipt key"):
        vr.verify_install_key(forged, att)

    cli = [sys.executable, str(KIT / "verify_receipts.py"), "--origin", f"https://127.0.0.1:{tls_port}",
           "--require-sealed", "--skip-amd", "--expected-measurement", "ab" * 48]
    proc = subprocess.run(cli, capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = json.loads(proc.stdout)
    assert out["verdict"] == "PASS" and out["attestation"]["guest_tls"]["peer_checked"] is True
    assert out["attestation"]["guest_tls"]["install_key_checked"] is True

    impostor = rr.MinerHotel("miner-box", [CONTROL.public_key().public_bytes_raw()])
    impostor_port, _ = _miner_front(ledger, upstream, tmp_path, tls_context=impostor.tls_context(str(tmp_path)))
    cli[3] = f"https://127.0.0.1:{impostor_port}"
    proc = subprocess.run(cli, capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 1 and "TLS peer is not the key the binding names" in proc.stdout


# ---------------------------------------------------------------- key install over the wire

def test_key_install_accepts_a_correct_envelope_and_the_front_takes_only_that_key(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    upstream = Upstream()
    tls_port, _ = _miner_front(ledger, upstream, tmp_path)
    pin = ledger.binding["tls_spki_sha256"]

    # Before an install nothing authenticates, and nothing reaches the API.
    for key in (None, INTERNAL, b"k" * 43):
        assert _https(tls_port, "GET", "/v1/status", key=key, pin=pin)[0] == 401
        assert _https(tls_port, "GET", "/room/health", key=key, pin=pin)[0] == 401
    assert upstream.seen == []

    status, _, body, _ = _https(tls_port, "GET", "/room/hotel-key-install-key", pin=pin)
    assert status == 200
    recipient = check_install_key_1588(json.loads(body), ledger.binding_sha256, ledger.binding["receipt_key_ed25519_b64"])
    hotel_key = _hotel_key("Ab3_")
    request = request_1588(hotel_key, recipient, ledger.binding_sha256)
    status, headers, body, _ = _https(tls_port, "POST", "/room/hotel-key", body=json.dumps(request).encode(), pin=pin)
    assert status == 200, body
    answer = json.loads(body)
    assert answer["key_sha256"] == hashlib.sha256(hotel_key.encode()).hexdigest() and answer["status"] == "installed"
    assert hotel_key.encode() not in body
    raw = headers["X-Room-Receipt"]
    receipt = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    st = receipt["statement"]
    assert st["action"] == "hotel_key_install" and st["key_sha256"] == answer["key_sha256"]
    assert st["signer_ed25519_b64"] == CONTROL_B64 and st["broker_hotel_id"] == request["hotel_id"]
    assert hotel_key not in json.dumps(receipt)
    assert vr.verify_receipts(ledger.attestation(), [receipt])["signatures_ok"] == 1

    # The installed key works; the API behind sees only the internal key.
    assert _https(tls_port, "GET", "/v1/status", key=hotel_key.encode(), pin=pin)[0] == 200
    assert upstream.seen == [("GET", "/v1/status", "Bearer " + INTERNAL.decode())]
    # The internal key is not a hotel key on the front.
    assert _https(tls_port, "GET", "/v1/status", key=INTERNAL, pin=pin)[0] == 401
    assert len(upstream.seen) == 1
    # Signed actions still get receipts under the installed key.
    status, headers, _, _ = _https(tls_port, "POST", "/v1/sandboxes", body=b'{"image":"alpine:3.20"}',
                                   key=hotel_key.encode(), pin=pin)
    assert status == 200 and "X-Room-Receipt" in headers


def test_the_plain_http_port_serves_the_attestation_only(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    upstream = Upstream()
    _, plain_port = _miner_front(ledger, upstream, tmp_path)
    status, body = _http(plain_port, "GET", "/room/attestation")
    assert status == 200 and json.loads(body)["binding_sha256"] == ledger.binding_sha256
    for method, path in (("GET", "/room/health"), ("GET", "/v1/sandboxes"), ("POST", "/v1/sandboxes"),
                         ("GET", "/room/hotel-key-install-key"), ("POST", "/room/hotel-key"), ("GET", "/room/receipts")):
        status, body = _http(plain_port, method, path, body=b"{}" if method == "POST" else None, key=b"k" * 43)
        assert status == 403 and b"https_required" in body, (method, path)
    assert upstream.seen == []


# ---------------------------------------------------------------- key install refusals

def _install(ledger, request, now=None):
    return ledger.install_hotel_key(json.loads(json.dumps(request)), now=now)


def test_install_refuses_a_wrong_signature(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    recipient = _recipient(ledger)
    forged = request_1588(_hotel_key("x"), recipient, ledger.binding_sha256, signer=Ed25519PrivateKey.generate())
    with pytest.raises(rr.InstallRefused, match="install_signature_invalid"):
        _install(ledger, forged)
    altered = request_1588(_hotel_key("x"), recipient, ledger.binding_sha256)
    altered["hotel_id"] = "miner-other"  # changed after signing
    with pytest.raises(rr.InstallRefused, match="install_signature_invalid"):
        _install(ledger, altered)
    assert ledger.miner.key is None and ledger.chain == []


def test_install_refuses_a_wrong_recipient_or_binding(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    other_boot, _ = _ledger(tmp_path / "other", monkeypatch)
    # Sealed to another guest's install key, naming this boot: the envelope does not open.
    wrong_key = request_1588(_hotel_key("x"), _recipient(other_boot), ledger.binding_sha256)
    with pytest.raises(rr.InstallRefused, match="install_envelope_does_not_open") as err:
        _install(ledger, wrong_key)
    assert err.value.status == 400
    # Made for the other boot (its binding and its key): refused before anything is opened.
    other = request_1588(_hotel_key("x"), _recipient(other_boot), other_boot.binding_sha256)
    with pytest.raises(rr.InstallRefused, match="install_wrong_binding") as err:
        _install(ledger, other)
    assert err.value.status == 409
    # Right key, sealed under another binding's AAD: does not open.
    aad_swap = request_1588(_hotel_key("x"), _recipient(ledger), ledger.binding_sha256,
                            envelope=seal_1588(_hotel_key("x").encode(), _recipient(ledger), other_boot.binding_sha256))
    with pytest.raises(rr.InstallRefused, match="install_envelope_does_not_open"):
        _install(ledger, aad_swap)
    assert ledger.miner.key is None and ledger.chain == []


def test_install_refuses_a_digest_mismatch_a_bad_key_and_bad_fields(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    recipient = _recipient(ledger)
    mismatch = request_1588(_hotel_key("x"), recipient, ledger.binding_sha256, key_sha256="00" * 32)
    with pytest.raises(rr.InstallRefused, match="install_key_digest_mismatch"):
        _install(ledger, mismatch)
    short = request_1588("too-short", recipient, ledger.binding_sha256)
    with pytest.raises(rr.InstallRefused, match="install_key_invalid"):
        _install(ledger, short)
    extra = request_1588(_hotel_key("x"), recipient, ledger.binding_sha256, note="x")
    with pytest.raises(rr.InstallRefused, match="install_fields_invalid"):
        _install(ledger, extra)
    with pytest.raises(rr.InstallRefused, match="install_fields_invalid"):
        _install(ledger, {"schema": "cathedral_hotel_key_install_v1"})
    assert ledger.miner.key is None


def test_install_refuses_replays_and_stale_requests_and_rotates(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    recipient = _recipient(ledger)
    now = int(time.time())
    first = request_1588(_hotel_key("a"), recipient, ledger.binding_sha256, issued_at=now - 10)
    second = request_1588(_hotel_key("b"), recipient, ledger.binding_sha256, issued_at=now)
    out, receipt = _install(ledger, first, now)
    assert out["status"] == "installed" and receipt is not None
    # The same request again (a lost answer, retried): no change, no new receipt.
    out, receipt = _install(ledger, first, now)
    assert out["status"] == "unchanged" and receipt is None and len(ledger.chain) == 1
    out, _ = _install(ledger, second, now)  # rotation: the newer key wins
    assert out["status"] == "installed" and ledger.miner.key == _hotel_key("b").encode()
    assert not ledger.miner.authorized(_hotel_key("a").encode()) and ledger.miner.authorized(_hotel_key("b").encode())
    with pytest.raises(rr.InstallRefused, match="install_replayed") as err:  # the older request again
        _install(ledger, first, now)
    assert err.value.status == 409 and ledger.miner.key == _hotel_key("b").encode()
    same_second = request_1588(_hotel_key("c"), recipient, ledger.binding_sha256, issued_at=now)
    with pytest.raises(rr.InstallRefused, match="install_replayed"):
        _install(ledger, same_second, now)
    stale = request_1588(_hotel_key("d"), recipient, ledger.binding_sha256, issued_at=now - 3600)
    with pytest.raises(rr.InstallRefused, match="install_not_fresh"):
        _install(ledger, stale, now)
    future = request_1588(_hotel_key("e"), recipient, ledger.binding_sha256, issued_at=now + 3600)
    with pytest.raises(rr.InstallRefused, match="install_not_fresh"):
        _install(ledger, future, now)
    assert ledger.miner.key == _hotel_key("b").encode() and len(ledger.chain) == 2


def test_install_refusals_over_https_change_nothing(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch)
    upstream = Upstream()
    tls_port, _ = _miner_front(ledger, upstream, tmp_path)
    pin = ledger.binding["tls_spki_sha256"]
    forged = request_1588(_hotel_key("x"), _recipient(ledger), ledger.binding_sha256, signer=Ed25519PrivateKey.generate())
    status, _, body, _ = _https(tls_port, "POST", "/room/hotel-key", body=json.dumps(forged).encode(), pin=pin)
    assert status == 403 and json.loads(body)["error"]["code"] == "install_signature_invalid"
    status, _, body, _ = _https(tls_port, "POST", "/room/hotel-key", body=b"not json", pin=pin)
    assert status == 400
    status, _, _, _ = _https(tls_port, "GET", "/room/hotel-key", pin=pin)
    assert status == 405
    assert _https(tls_port, "GET", "/v1/status", key=_hotel_key("x").encode(), pin=pin)[0] == 401
    assert ledger.miner.key is None and upstream.seen == []


# ---------------------------------------------------------------- config hotels unchanged

def test_a_config_hotel_front_passes_its_key_through_and_has_no_install_routes(tmp_path, monkeypatch) -> None:
    ledger, _ = _ledger(tmp_path, monkeypatch, miner=False)
    upstream = Upstream()
    server = rr.Server(("127.0.0.1", 0), ledger, upstream.port, 1, INTERNAL, "/nonexistent.sock")
    Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    status, _ = _http(port, "GET", "/v1/status", key=INTERNAL)
    assert status == 200 and upstream.seen[-1] == ("GET", "/v1/status", "Bearer " + INTERNAL.decode())
    # The install routes are not the front's on a config hotel: the request goes on as any other did.
    status, _ = _http(port, "GET", "/room/hotel-key-install-key", key=INTERNAL)
    assert upstream.seen[-1][1] == "/room/hotel-key-install-key"
    status, _ = _http(port, "GET", "/room/attestation")
    assert status == 200
