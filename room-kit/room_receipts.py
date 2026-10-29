#!/usr/bin/env python3
"""Room kit: signed receipts for a hotel.

Two modes. The mode is chosen at start from the TSM provider.

Level 1, every host (TSM provider is not sev_guest). An Ed25519 receipt key
in memory and a binding that says level "hotel". No read of
/sys/kernel/config/tsm/report, no SNP measurement, and health does not say
sealed. Schema cathedral_hotel_binding_v1 / cathedral_hotel_receipt_v1.

Sealed (TSM provider sev_guest). The same chain, plus an SNP report whose
REPORT_DATA is sha256(canonical(binding)) followed by 32 zero bytes. Schema
cathedral_sealed_hotel_binding_v1 / cathedral_sealed_hotel_receipt_v1, and
health sealed is true. That path is the sealed guest, not level 1.

Then it listens on ROOM_RECEIPTS_LISTEN and passes every request to the room
API (127.0.0.1:ROOM_API_PORT) and /room/health to the health endpoint. For each
create, exec, background process start and delete it signs one receipt. The
receipts make one chain per boot: each statement carries the sha256 of the
statement before it; the first one carries the binding's sha256.

Routes it adds:
  GET /room/attestation            binding, binding_sha256, report (base64)
  POST /room/attest                a fresh SNP report over caller REPORT_DATA (sealed only);
                                   with "sandbox_id", also that room's signed create receipt
  GET /room/receipts?after=&limit= the chain of this boot, in order
  GET /v1/sandboxes/<id>/receipts  the receipts of one room
  GET /room/escape-plant-key       sealed Escape hotels only: the guest X25519 public
                                   key, signed by the attested receipt key
  POST /room/escape-nonce          sealed Escape hotels only: plant the window nonce
                                   (never echoed; receipt signs the plant without the value)
  GET /room/hotel-key-install-key  miner hotels only: the guest X25519 install key, signed
                                   by the attested receipt key
  POST /room/hotel-key             miner hotels only: install the per-hotel API key, sealed
                                   to the install key and signed by a pinned control plane key
Response header on a signed operation:
  X-Room-Receipt: base64url(canonical(receipt))

Miner hotel (ROOM_MINER=1, sealed only). The host is not trusted with the
hotel key, so the front makes, at start and in memory, a TLS key (P-256, self-
issued certificate) and an X25519 install key, and names both in the binding
(tls_spki_sha256, hotel_key_install_x25519_b64), so the boot's REPORT_DATA
commits to them. It serves every route above over HTTPS on
ROOM_RECEIPTS_TLS_LISTEN with that key. Plain HTTP on ROOM_RECEIPTS_LISTEN
serves GET /room/attestation only. The hotel key is never read from a file:
the control plane installs it with POST /room/hotel-key, and the front
accepts a bearer only when it equals the installed key. The API behind the
front knows only a guest-internal key (ROOM_API_KEY_PATH, made at boot inside
the guest), which the front puts on each request it passes on.

Canonical JSON: sort_keys, separators (",", ":"), ensure_ascii=False, UTF-8.
Verify offline with verify_receipts.py.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

BINDING_SCHEMA = "cathedral_sealed_hotel_binding_v1"
RECEIPT_SCHEMA = "cathedral_sealed_hotel_receipt_v1"
HOTEL_BINDING_SCHEMA = "cathedral_hotel_binding_v1"
HOTEL_RECEIPT_SCHEMA = "cathedral_hotel_receipt_v1"
TSM = "/sys/kernel/config/tsm/report"
PLANT_ACTION = "escape_nonce_plant"
PLANT_ALGORITHM = "x25519-hkdf-sha256-aes256gcm-v1"
PLANT_KEY_PURPOSE = "escape-plant-key"
PLANT_HKDF_INFO = b"cathedral.escape-nonce-plant.v1"
DEFAULT_ESCAPE_NONCE_PATH = "/run/escape-room/nonce"
WINDOW_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9+/=_-]{16,512}$")
# Miner hotel key install (the control plane side is polariscomputer
# cathedral_hotel_reconciler.RoomKitKeyInstaller; keep the two in step).
INSTALL_ALGORITHM = PLANT_ALGORITHM  # the plant construction, with its own HKDF info and AAD
INSTALL_PURPOSE = "hotel-key-install"
INSTALL_SCHEMA = "cathedral_hotel_key_install_v1"
INSTALL_HKDF_INFO = b"cathedral.hotel-key-install.v1"
INSTALL_ACTION = "hotel_key_install"
INSTALL_FIELDS = frozenset({"schema", "binding_sha256", "hotel_id", "key_sha256", "issued_at", "envelope",
                            "signature_b64"})
INSTALL_MAX_BYTES = 16 * 1024
# The control plane posts a request at once; the window only bounds a request
# that was made and never delivered. Replays inside it fail the order check.
INSTALL_MAX_AGE_SECONDS = 900
INSTALL_FUTURE_SKEW_SECONDS = 300
INSTALL_MAX_SIGNERS = 4
HOTEL_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{32,256}$")  # the broker's hotel key rule, bounded
BROKER_HOTEL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
KEY_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PlantError(ValueError):
    """The plant ciphertext did not open. The message never names the nonce."""


def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# ---------------------------------------------------------------- attestation

# The sealed path's first report uses 64 zero bytes. tsm_provider() reads that
# report once; snp_report() returns it instead of asking the processor again.
_ZERO_REPORT: tuple[str, bytes] | None = None


def _read_tsm(report_data: bytes) -> tuple[str, bytes]:
    """One configfs-tsm report: provider name and outblob."""
    provider, report, _aux = _read_tsm_aux(report_data)
    return provider, report


def _read_tsm_aux(report_data: bytes, want_aux: bool = False) -> tuple[str, bytes, bytes]:
    """One configfs-tsm report: provider, outblob and (if asked) auxblob.

    auxblob is the host's certificate table (VCEK, ASK, ARK) when the host
    stored one and the kernel exposes it; otherwise it is empty.
    """
    assert len(report_data) == 64
    entry = os.path.join(TSM, "room-" + uuid.uuid4().hex[:12])
    os.mkdir(entry)
    aux = b""
    try:
        with open(os.path.join(entry, "inblob"), "wb") as f:
            f.write(report_data)
        with open(os.path.join(entry, "outblob"), "rb") as f:
            report = f.read()
        with open(os.path.join(entry, "provider")) as f:
            provider = f.read().strip()
        if want_aux:
            try:
                with open(os.path.join(entry, "auxblob"), "rb") as f:
                    aux = f.read()
            except OSError:
                aux = b""  # older kernel or no host certificates: the caller fetches from AMD KDS
    finally:
        os.rmdir(entry)
    return provider, report, aux


# GHCB certificate table GUIDs (AMD SEV-SNP firmware ABI / GHCB spec).
_CERT_GUIDS = {
    "vcek": "63da758d-e664-4564-adc5-f4b93be8accd",
    "ask": "4ab7b379-bbac-4fe4-a02f-05aef327c782",
    "ark": "c0b406a4-a803-4952-9743-3fb6014cd0ae",
}


def cert_chain(aux: bytes) -> dict | None:
    """VCEK, ASK and ARK (base64 DER) from an SNP certificate table, or None.

    The table is entries of GUID (16 bytes), offset (u32 LE) and length (u32
    LE), ended by an all-zero entry; offsets count from the table start. The
    GUID is matched in both byte orders. None unless all three are present
    and in range: a partial chain is not handed out as a chain.
    """
    names = {}
    for name, g in _CERT_GUIDS.items():
        u = uuid.UUID(g)
        names[u.bytes], names[u.bytes_le] = name, name
    found: dict[str, str] = {}
    pos = 0
    while pos + 24 <= len(aux):
        guid = aux[pos:pos + 16]
        if guid == bytes(16):
            break
        off = int.from_bytes(aux[pos + 16:pos + 20], "little")
        ln = int.from_bytes(aux[pos + 20:pos + 24], "little")
        name = names.get(guid)
        if name and ln and off + ln <= len(aux):
            found[name] = b64(aux[off:off + ln])
        pos += 24
    return found if set(found) == set(_CERT_GUIDS) else None


def tsm_provider() -> str | None:
    """The configfs-tsm provider, or None when this host has no TSM report.

    No configfs directory means level 1. A probe writes a zero REPORT_DATA
    and reads provider. sev_guest is the sealed path. Any other provider is
    level 1. A probe error is raised: a sealed guest with a broken TSM must
    not publish a hotel binding instead. The zero report is kept for
    snp_report(), so a sealed start still asks for two reports, as before.
    """
    global _ZERO_REPORT
    if not os.path.isdir(TSM):
        return None
    provider, report = _read_tsm(bytes(64))
    _ZERO_REPORT = (provider, report)
    return provider or None


def snp_report(report_data: bytes) -> bytes:
    """One SNP attestation report through configfs-tsm (Linux TSM reports)."""
    global _ZERO_REPORT
    if report_data == bytes(64) and _ZERO_REPORT is not None:
        provider, report = _ZERO_REPORT
        _ZERO_REPORT = None
    else:
        provider, report = _read_tsm(report_data)
    if provider != "sev_guest" or len(report) < 0x4A0:
        raise RuntimeError(f"unexpected TSM provider {provider!r} or report size {len(report)}")
    return report


def fresh_report(report_data: bytes) -> tuple[bytes, dict | None]:
    """A new SNP report whose REPORT_DATA is report_data, byte for byte.

    No hashing here: the caller chooses the 64 bytes and so the binding.
    Returns the report and the certificate chain when the host gave one.
    """
    provider, report, aux = _read_tsm_aux(report_data, want_aux=True)
    if provider != "sev_guest" or len(report) < 0x4A0:
        raise RuntimeError(f"unexpected TSM provider {provider!r} or report size {len(report)}")
    return report, cert_chain(aux)


def report_fields(report: bytes) -> dict:
    u64 = lambda o: int.from_bytes(report[o:o + 8], "little")  # noqa: E731
    return {
        "version": int.from_bytes(report[0:4], "little"),
        "policy": hex(u64(0x08)),
        "measurement": report[0x90:0xC0].hex(),
        "host_data": report[0xC0:0xE0].hex(),
        "reported_tcb": u64(0x180).to_bytes(8, "little").hex(),
        "chip_id": report[0x1A0:0x1E0].hex(),
    }


def read(path: str, default: str = "") -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def escape_plant_open(ledger: "Ledger") -> bool:
    """Sealed Escape hotels only. Unset or any other value fails closed."""
    return os.environ.get("ROOM_ESCAPE") == "1" and bool(getattr(ledger, "sealed", False))


def escape_nonce_path() -> str:
    return os.environ.get("ROOM_ESCAPE_NONCE_PATH") or DEFAULT_ESCAPE_NONCE_PATH


def plant_key_statement(hotel: str, x25519_public_b64: str, binding_sha256: str) -> dict:
    """Canonical fields the guest signs and the broker verifies."""
    return {
        "algorithm": PLANT_ALGORITHM,
        "binding_sha256": binding_sha256,
        "hotel": hotel,
        "purpose": PLANT_KEY_PURPOSE,
        "x25519_public_b64": x25519_public_b64,
    }


def plant_aad(hotel: str, window_id: str) -> bytes:
    return f"escape-nonce-plant:{hotel}:{window_id}".encode()


def _raw_x25519(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _wrapping_key(info: bytes, shared: bytes, aad: bytes, ephemeral: bytes, recipient: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=aad, info=info + ephemeral + recipient).derive(shared)


def _plant_wrapping_key(shared: bytes, aad: bytes, ephemeral: bytes, recipient: bytes) -> bytes:
    return _wrapping_key(PLANT_HKDF_INFO, shared, aad, ephemeral, recipient)


def _seal_envelope(plaintext: bytes, recipient: X25519PublicKey, info: bytes, aad: bytes) -> dict:
    """X25519 to the recipient, HKDF-SHA256 (salt = AAD), AES-256-GCM with the same AAD."""
    ephemeral = X25519PrivateKey.generate()
    raw_eph = _raw_x25519(ephemeral.public_key())
    raw_rec = _raw_x25519(recipient)
    key = _wrapping_key(info, ephemeral.exchange(recipient), aad, raw_eph, raw_rec)
    n = os.urandom(12)
    return {
        "algorithm": PLANT_ALGORITHM,
        "ephemeral_public_b64": b64(raw_eph),
        "nonce_b64": b64(n),
        "ciphertext_b64": b64(AESGCM(key).encrypt(n, plaintext, aad)),
    }


def _open_envelope(doc: dict, private: X25519PrivateKey, info: bytes, aad: bytes) -> bytes:
    """Open an envelope of _seal_envelope. Raises PlantError, which never names the plaintext."""
    if not isinstance(doc, dict) or doc.get("algorithm") != PLANT_ALGORITHM:
        raise PlantError("ciphertext does not open")
    try:
        raw_eph = base64.b64decode(doc["ephemeral_public_b64"], validate=True)
        aes_n = base64.b64decode(doc["nonce_b64"], validate=True)
        ct = base64.b64decode(doc["ciphertext_b64"], validate=True)
        if len(raw_eph) != 32 or len(aes_n) != 12 or not (16 <= len(ct) <= 2048):
            raise PlantError("ciphertext does not open")
        ephemeral = X25519PublicKey.from_public_bytes(raw_eph)
        # from_public_bytes accepts low-order points; a trial exchange rejects them.
        X25519PrivateKey.generate().exchange(ephemeral)
        raw_rec = _raw_x25519(private.public_key())
        key = _wrapping_key(info, private.exchange(ephemeral), aad, raw_eph, raw_rec)
        return AESGCM(key).decrypt(aes_n, ct, aad)
    except (KeyError, TypeError, ValueError, InvalidTag) as exc:
        raise PlantError("ciphertext does not open") from exc


def seal_plant_nonce(plaintext: bytes, recipient: X25519PublicKey, hotel: str, window_id: str) -> dict:
    """Seal the window nonce to the guest-held plant key. Same construction the broker uses."""
    return _seal_envelope(plaintext, recipient, PLANT_HKDF_INFO, plant_aad(hotel, window_id))


def open_plant_nonce(doc: dict, private: X25519PrivateKey, hotel: str, window_id: str) -> str:
    """Open a broker plant envelope. Raises PlantError without naming the nonce."""
    opened = _open_envelope(doc, private, PLANT_HKDF_INFO, plant_aad(hotel, window_id))
    try:
        return opened.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PlantError("ciphertext does not open") from exc


# ---------------------------------------------------------------- miner hotel: guest TLS and key install

def install_aad(binding_sha256: str) -> bytes:
    return f"hotel-key-install:{binding_sha256}".encode()


def seal_hotel_key(plaintext: bytes, recipient: X25519PublicKey, binding_sha256: str) -> dict:
    """The control plane's envelope for POST /room/hotel-key (tests and tools; the guest only opens)."""
    return _seal_envelope(plaintext, recipient, INSTALL_HKDF_INFO, install_aad(binding_sha256))


def install_key_statement(x25519_public_b64: str, binding_sha256: str) -> dict:
    """Canonical fields the guest signs with the receipt key and the control plane verifies.

    Unlike the plant statement there is no hotel field: the broker hotel id is
    chosen by the control plane at join and travels in the signed request.
    """
    return {"algorithm": INSTALL_ALGORITHM, "binding_sha256": binding_sha256, "purpose": INSTALL_PURPOSE,
            "x25519_public_b64": x25519_public_b64}


def parse_install_signers(raw: str) -> list[bytes]:
    """ROOM_HOTEL_KEY_INSTALL_SIGNERS: 1 to 4 control plane Ed25519 public keys, base64 of the raw
    32 bytes, separated by spaces. Measured with room.env. Anything else stops the front."""
    out = []
    for item in (raw or "").split():
        try:
            key = base64.b64decode(item, validate=True)
        except ValueError:
            key = b""
        if len(key) != 32 or b64(key) != item:
            raise ValueError("ROOM_HOTEL_KEY_INSTALL_SIGNERS holds a value that is not a base64 Ed25519 public key")
        Ed25519PublicKey.from_public_bytes(key)
        if key not in out:
            out.append(key)
    if not 1 <= len(out) <= INSTALL_MAX_SIGNERS:
        raise ValueError(f"ROOM_HOTEL_KEY_INSTALL_SIGNERS must name 1 to {INSTALL_MAX_SIGNERS} keys")
    return out


def spki_sha256(public_key) -> str:
    """sha256 of the DER SubjectPublicKeyInfo: what a client pins (cathedral.channel.tls_spki_binding)."""
    return sha(public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))


def make_tls_identity(hotel: str) -> tuple[bytes, bytes, str]:
    """A P-256 key and a self-issued certificate, made in this process.

    Returns (certificate PEM, key PEM, SPKI sha256). No CA vouches for it:
    the binding names the SPKI and the client pins that value.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, (hotel or "room")[:64])])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return cert.public_bytes(Encoding.PEM), key_pem, spki_sha256(key.public_key())


class InstallRefused(Exception):
    """POST /room/hotel-key refused. The code is short and never names the key."""

    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status, self.code = status, code


class MinerHotel:
    """A miner hotel's guest-held secrets: TLS key, install key, installed hotel key.

    All three exist in this process only. The TLS key and the install key are
    made at start and named in the binding (binding_fields), so the boot's SNP
    report commits to them. The hotel key arrives only through
    POST /room/hotel-key; the latest accepted install wins.
    """

    def __init__(self, hotel: str, signers: list[bytes]):
        if not signers:
            raise ValueError("a miner hotel needs at least one pinned install signer")
        self.signers = [(b64(k), Ed25519PublicKey.from_public_bytes(k)) for k in signers]
        self.cert_pem, self._key_pem, self.tls_spki_sha256 = make_tls_identity(hotel)
        self.install_private = X25519PrivateKey.generate()
        self.install_public_b64 = b64(_raw_x25519(self.install_private.public_key()))
        self.lock = threading.Lock()
        self.key: bytes | None = None
        self.key_sha256: str | None = None
        self.hotel_id: str | None = None
        self.issued_at = -1
        self.request_sha256: str | None = None

    def __repr__(self) -> str:
        return f"MinerHotel(tls_spki_sha256={self.tls_spki_sha256})"

    def binding_fields(self) -> dict:
        return {
            "tls_spki_sha256": self.tls_spki_sha256,
            "hotel_key_install_x25519_b64": self.install_public_b64,
            "hotel_key_install_signers_ed25519_b64": [name for name, _ in self.signers],
            # The hotel key never comes from fw_cfg or a host file on this guest.
            "hotel_key_source": "install",
        }

    def tls_context(self, private_dir: str) -> ssl.SSLContext:
        """Server context with the boot TLS key. load_cert_chain reads a file only,
        so the PEM is written root-only into the guest's private store, loaded and removed."""
        if self._key_pem is None:
            raise RuntimeError("the TLS key was already loaded")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        fd, path = tempfile.mkstemp(prefix=".tls.", dir=private_dir)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, self._key_pem + self.cert_pem)
            os.close(fd)
            fd = -1
            ctx.load_cert_chain(path)
        finally:
            if fd >= 0:
                os.close(fd)
            os.unlink(path)
        self._key_pem = None
        return ctx

    def authorized(self, presented: bytes) -> bool:
        key = self.key
        return key is not None and hmac.compare_digest(presented, key)

    def signer(self, signature: bytes, message: bytes) -> str | None:
        for name, public in self.signers:
            try:
                public.verify(signature, message)
                return name
            except InvalidSignature:
                continue
        return None


def write_escape_nonce(path: str, nonce: str, window_id: str) -> None:
    """Write the nonce as a root-only file. The window id sits beside it and is not secret."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    _replace_private_file(directory, os.path.join(directory, "window"), window_id.encode() + b"\n", 0o444)
    _replace_private_file(directory, path, nonce.encode() + b"\n", 0o400)


def _replace_private_file(directory: str, path: str, data: bytes, mode: int) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".plant.", dir=directory)
    try:
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(tmp, path)
        os.chmod(path, mode)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Ledger:
    """The receipt key, the binding and the chain of this boot."""

    def __init__(self, hotel: str, store: str, miner: MinerHotel | None = None):
        self.miner = miner
        if tsm_provider() == "sev_guest":
            self._init_sealed(hotel, store)
        elif miner is not None:
            # A miner hotel's TLS key means something only under an SNP report.
            raise RuntimeError("miner mode needs a sealed guest (TSM provider sev_guest)")
        else:
            self._init_hotel(hotel, store)
        # Runtime guest key. Not in the binding: adding it there would change
        # REPORT_DATA. Authenticated by an Ed25519 signature over the plant-key
        # statement using the receipt key the binding already names
        # (receipt_key_ed25519_b64). TODO Mr Spock: pin move after rebuild.
        self.plant_private = (
            X25519PrivateKey.generate() if self.sealed and os.environ.get("ROOM_ESCAPE") == "1" else None
        )

    def plant_public_b64(self) -> str | None:
        if self.plant_private is None:
            return None
        return b64(_raw_x25519(self.plant_private.public_key()))

    def plant_key_document(self) -> dict | None:
        """Public plant key signed by the attested receipt key.

        The statement binds hotel (ROOM_HOTEL_NAME, the broker hotel id),
        this boot's binding_sha256, the X25519 key, and a purpose string so
        the signature cannot be replayed onto another hotel or room.
        """
        pub = self.plant_public_b64()
        if pub is None:
            return None
        statement = plant_key_statement(self.hotel, pub, self.binding_sha256)
        return {**statement, "signature_b64": b64(self.key.sign(canonical(statement)))}

    def _init_sealed(self, hotel: str, store: str) -> None:
        """SNP binding. Same schema, report and fields as the sealed guest."""
        self.sealed = True
        self.receipt_schema = RECEIPT_SCHEMA
        self.hotel = hotel
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        # A first report (zero REPORT_DATA) gives the launch facts the binding names.
        facts = report_fields(snp_report(bytes(64)))
        self.binding = {
            "schema": BINDING_SCHEMA,
            "hotel": hotel,
            "boot_id": read("/proc/sys/kernel/random/boot_id"),
            "created_at": int(time.time()),
            "receipt_key_ed25519_b64": b64(pub),
            "measurement": facts["measurement"],
            "chip_id": facts["chip_id"],
            "reported_tcb": facts["reported_tcb"],
            "policy": facts["policy"],
            "host_data": facts["host_data"],
            "kernel_cmdline": read("/proc/cmdline"),
            "kernel_release": os.uname().release,
            "software": {
                "room_kit": read("/opt/room-kit/KIT_COMMIT", "unknown"),
                "cathedral": read("/opt/pool-room/src/COMMIT", "unknown"),
            },
        }
        if self.miner is not None:
            # TLS key, install key and pinned signers: REPORT_DATA commits to them.
            self.binding.update(self.miner.binding_fields())
        self.binding_sha256 = sha(canonical(self.binding))
        self.report = snp_report(bytes.fromhex(self.binding_sha256) + bytes(32))
        if report_fields(self.report)["measurement"] != facts["measurement"]:
            raise RuntimeError("measurement changed between the two reports")
        self._open_store(store)

    def install_key_document(self) -> dict | None:
        """Miner hotels: the install X25519 key, signed by the attested receipt key."""
        if self.miner is None:
            return None
        statement = install_key_statement(self.miner.install_public_b64, self.binding_sha256)
        return {**statement, "signature_b64": b64(self.key.sign(canonical(statement)))}

    def install_hotel_key(self, doc, now: float | None = None) -> tuple[dict, dict | None]:
        """POST /room/hotel-key. Returns (answer, receipt); raises InstallRefused.

        Accepted only when the control plane signature verifies with a pinned
        signer, the request names this boot's binding, issued_at is fresh and
        newer than the last install, and the envelope opens with this boot's
        install key to a key whose sha256 the request names. The exact request
        that installed the current key answers again with no change (a retry
        after a lost answer); any other older or equal issued_at is a replay.
        """
        miner = self.miner
        if miner is None:
            raise InstallRefused(403, "install_disabled")
        if not isinstance(doc, dict) or set(doc) != INSTALL_FIELDS or doc["schema"] != INSTALL_SCHEMA:
            raise InstallRefused(400, "install_fields_invalid")
        signature = doc["signature_b64"]
        try:
            raw_sig = base64.b64decode(signature, validate=True) if isinstance(signature, str) else b""
        except ValueError:
            raw_sig = b""
        body = {k: v for k, v in doc.items() if k != "signature_b64"}
        try:
            message = canonical(body)
        except (TypeError, ValueError):
            raise InstallRefused(400, "install_fields_invalid") from None
        signer = miner.signer(raw_sig, message) if len(raw_sig) == 64 else None
        if signer is None:
            raise InstallRefused(403, "install_signature_invalid")
        if doc["binding_sha256"] != self.binding_sha256:
            raise InstallRefused(409, "install_wrong_binding")
        hotel_id, key_sha256, issued = doc["hotel_id"], doc["key_sha256"], doc["issued_at"]
        if (not isinstance(hotel_id, str) or not BROKER_HOTEL_ID_RE.fullmatch(hotel_id)
                or not isinstance(key_sha256, str) or not KEY_SHA256_RE.fullmatch(key_sha256)
                or type(issued) is not int):
            raise InstallRefused(400, "install_fields_invalid")
        now = time.time() if now is None else now
        if not now - INSTALL_MAX_AGE_SECONDS <= issued <= now + INSTALL_FUTURE_SKEW_SECONDS:
            raise InstallRefused(409, "install_not_fresh")
        request_sha256 = sha(canonical(doc))

        def answer(status: str) -> dict:
            return {"key_sha256": key_sha256, "hotel_id": hotel_id, "issued_at": issued, "status": status}

        with miner.lock:
            if request_sha256 == miner.request_sha256:
                return answer("unchanged"), None
            if issued <= miner.issued_at:
                raise InstallRefused(409, "install_replayed")
        try:
            opened = _open_envelope(doc["envelope"], miner.install_private, INSTALL_HKDF_INFO,
                                    install_aad(self.binding_sha256))
        except PlantError:
            # Sealed to another key (another boot or guest), or altered.
            raise InstallRefused(400, "install_envelope_does_not_open") from None
        if not HOTEL_KEY_RE.fullmatch(opened.decode("latin-1")):
            raise InstallRefused(400, "install_key_invalid")
        if sha(opened) != key_sha256:
            raise InstallRefused(400, "install_key_digest_mismatch")
        with miner.lock:
            if request_sha256 == miner.request_sha256:
                return answer("unchanged"), None
            if issued <= miner.issued_at:  # a newer install landed while this one was opened
                raise InstallRefused(409, "install_replayed")
            miner.key, miner.key_sha256, miner.hotel_id = opened, key_sha256, hotel_id
            miner.issued_at, miner.request_sha256 = issued, request_sha256
        receipt = self.sign({
            "action": INSTALL_ACTION,
            "target": "POST /room/hotel-key",
            "sandbox_id": None,
            "broker_hotel_id": hotel_id,
            "key_sha256": key_sha256,
            "install_issued_at": issued,
            "install_request_sha256": request_sha256,
            "signer_ed25519_b64": signer,
            "status": 200,
        })
        return answer("installed"), receipt

    def _init_hotel(self, hotel: str, store: str) -> None:
        """Level 1: an Ed25519 hotel chain. No SNP report and no measurement."""
        self.sealed = False
        self.receipt_schema = HOTEL_RECEIPT_SCHEMA
        self.hotel = hotel
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.binding = {
            "schema": HOTEL_BINDING_SCHEMA,
            "level": "hotel",
            "hotel": hotel,
            "boot_id": read("/proc/sys/kernel/random/boot_id"),
            "created_at": int(time.time()),
            "receipt_key_ed25519_b64": b64(pub),
            "kernel_cmdline": read("/proc/cmdline"),
            "kernel_release": os.uname().release,
            "software": {
                "room_kit": read("/opt/room-kit/KIT_COMMIT", "unknown"),
                "cathedral": read("/opt/pool-room/src/COMMIT", "unknown"),
            },
        }
        self.binding_sha256 = sha(canonical(self.binding))
        self.report = b""
        self._open_store(store)

    def _open_store(self, store: str) -> None:
        self.lock = threading.Lock()
        self.attest_lock = threading.Lock()
        # Fresh-report slots keyed by guest id (X-Cathedral-Guest). A shared
        # hotel serves many guests; a per-hotel counter let one guest starve
        # the others (Spock / Escape capacity).
        self.attest_times: dict[str, list[float]] = {}
        self.chain: list[dict] = []
        self.by_room: dict[str, list[int]] = {}
        self.head = self.binding_sha256
        os.makedirs(store, mode=0o700, exist_ok=True)
        self.store = open(os.path.join(store, f"chain-{self.binding['boot_id']}.jsonl"), "ab", buffering=0)
        with open(os.path.join(store, f"attestation-{self.binding['boot_id']}.json"), "w") as f:
            json.dump(self.attestation(), f)

    def attestation(self) -> dict:
        doc = {"binding": self.binding, "binding_sha256": self.binding_sha256}
        if self.sealed:
            doc["report_b64"] = b64(self.report)
        return doc

    def attest_slot(self, guest: str, per_minute: int) -> float:
        """Take one fresh-report slot for *guest*. 0 when taken, else seconds to wait."""
        key = guest if guest else "_direct"
        now = time.monotonic()
        with self.attest_lock:
            times = self.attest_times.setdefault(key, [])
            times[:] = [t for t in times if now - t < 60]
            if len(times) >= per_minute:
                return max(0.001, 60 - (now - times[0]))
            times.append(now)
            return 0.0

    def attest(self, report_data: bytes) -> dict:
        """A fresh SNP report over the caller's 64 bytes, tied to this boot's binding."""
        report, chain = fresh_report(report_data)
        measurement = report_fields(report)["measurement"]
        if measurement != self.binding["measurement"]:
            raise RuntimeError("measurement changed since the binding")
        # Field name matches the receipt (cathedral_challenge_receipt_v1_1
        # tee.cert_chain): DER base64 for vcek/ask/ark, or null.
        return {"report_b64": b64(report), "cert_chain": chain, "binding_sha256": self.binding_sha256,
                "measurement": measurement, "generated_at": int(time.time())}

    def create_receipt(self, room: str) -> dict | None:
        """The last successful create receipt of *room* in this boot's chain, or None."""
        with self.lock:
            for i in reversed(self.by_room.get(room, [])):
                st = self.chain[i]["statement"]
                if st.get("action") == "create" and 200 <= int(st.get("status") or 0) < 300:
                    return self.chain[i]
        return None

    def sign(self, fields: dict) -> dict:
        with self.lock:
            statement = {"schema": self.receipt_schema, "binding_sha256": self.binding_sha256, "hotel": self.hotel,
                         "operation_id": str(uuid.uuid4()), "sequence": len(self.chain) + 1,
                         "previous_receipt_sha256": self.head, "issued_at": int(time.time()), **fields}
            receipt = {"statement": statement, "signature_b64": b64(self.key.sign(canonical(statement))),
                       "receipt_sha256": sha(canonical(statement))}
            self.head = receipt["receipt_sha256"]
            self.chain.append(receipt)
            room = statement.get("sandbox_id")
            if room:
                self.by_room.setdefault(room, []).append(len(self.chain) - 1)
            self.store.write(canonical(receipt) + b"\n")
            return receipt


# ---------------------------------------------------------------- proxy

ROOM = r"/v1/sandboxes/(?P<id>[^/]+)"
SIGNED = [  # (method, path pattern, action)
    ("POST", re.compile(r"^/v1/sandboxes$"), "create"),
    ("POST", re.compile("^" + ROOM + r"/exec$"), "exec"),
    ("POST", re.compile("^" + ROOM + r"/processes$"), "process_start"),
    ("DELETE", re.compile("^" + ROOM + r"$"), "delete"),
    ("PUT", re.compile("^" + ROOM + r"/network$"), "network_set"),
    ("POST", re.compile("^" + ROOM + r"/network$"), "network_set"),
    ("PATCH", re.compile("^" + ROOM + r"/network$"), "network_set"),
    ("DELETE", re.compile(r"^/v1/sandboxes$"), "bulk_delete"),
]
HEX64 = re.compile(r"[0-9a-fA-F]{128}")
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization",
       "proxy-authenticate", "content-length", "host"}


class Upstreams(threading.local):
    def conn(self, port: int) -> http.client.HTTPConnection:
        conns = self.__dict__.setdefault("conns", {})
        if port not in conns:
            conns[port] = http.client.HTTPConnection("127.0.0.1", port, timeout=1800)
        return conns[port]

    def drop(self, port: int) -> None:
        c = self.__dict__.get("conns", {}).pop(port, None)
        if c:
            c.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "room-receipts"

    def log_message(self, *args):  # no request logs
        pass

    # -- helpers
    def reply(self, status: int, body: bytes, headers: dict | None = None, ctype="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def authorized(self) -> bool:
        raw = self.headers.get("Authorization", "")
        if raw[:7].lower() != "bearer ":
            return False
        miner = getattr(self.server.ledger, "miner", None)
        if miner is not None:
            # Only the key the control plane installed; never the guest-internal API key.
            return miner.authorized(raw[7:].strip().encode())
        return hmac.compare_digest(raw[7:].strip().encode(), self.server.api_key)

    def upstream(self, port: int, body: bytes | None):
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        if getattr(self.server.ledger, "miner", None) is not None:
            # The caller's key was checked against the installed key before this
            # call. The API knows only the guest-internal key.
            headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
            headers["Authorization"] = "Bearer " + self.server.api_key.decode()
        if self.command not in ("GET", "HEAD"):
            # A write may have run before its answer was lost, so it is never
            # sent twice: a fresh connection (no stale keep-alive) and no
            # retry. A lost answer is a 502, and the receipt records it.
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=1800)
            try:
                c.request(self.command, self.path, body=body, headers=headers)
                r = c.getresponse()
                return r.status, r.getheaders(), r.read()
            except (http.client.HTTPException, OSError):
                return 502, [], b'{"error":{"code":"hotel_api_no_answer","message":"the API did not answer; the request may have run"}}'
            finally:
                c.close()
        for attempt in (1, 2):
            c = UP.conn(port)
            try:
                c.request(self.command, self.path, body=body, headers=headers)
                r = c.getresponse()
                return r.status, r.getheaders(), r.read()
            except (http.client.HTTPException, OSError):
                UP.drop(port)
                if attempt == 2:
                    raise

    # -- routes
    def handle_any(self):
        if self.server.attestation_only:
            # A miner hotel's plain HTTP port (the host's side of the tap): the
            # public attestation only. Nothing else, so no bearer and no room
            # traffic ever crosses it in the clear. The body is not read.
            if self.command == "GET" and urlsplit(self.path).path == "/room/attestation":
                return self.reply(200, canonical(self.server.ledger.attestation()))
            self.close_connection = True
            return self.reply(403, b'{"error":{"code":"https_required","message":"this port serves GET /room/attestation only; use the attested HTTPS port"}}')
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            # Only Content-Length bodies are read and signed; a chunked body
            # would be signed as empty and its bytes left on the connection.
            self.close_connection = True
            return self.reply(411, b'{"error":"length_required"}')
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else (b"" if self.command in ("POST", "PUT", "PATCH") else None)
        path = urlsplit(self.path).path
        ledger: Ledger = self.server.ledger
        if self.command == "GET" and path == "/room/attestation":
            return self.reply(200, canonical(ledger.attestation()))
        if path == "/room/attest":
            return self.handle_attest(ledger, body)
        if self.command == "GET" and path == "/room/receipts":
            if not self.authorized():
                return self.reply(401, b'{"error":"unauthorized"}')
            q = parse_qs(urlsplit(self.path).query)
            try:
                after, limit = int(q.get("after", ["0"])[0]), min(int(q.get("limit", ["1000"])[0]), 10000)
            except ValueError:
                after = limit = -1
            if after < 0 or limit < 1:
                return self.reply(400, b'{"error":"after must be >= 0 and limit >= 1"}')
            with ledger.lock:
                page = ledger.chain[after:after + limit]
                head = ledger.head
            return self.reply(200, canonical({"binding_sha256": ledger.binding_sha256, "head": head,
                                              "count": len(page), "receipts": page}))
        m = re.match("^" + ROOM + r"/receipts$", path)
        if self.command == "GET" and m:
            if not self.authorized():
                return self.reply(401, b'{"error":"unauthorized"}')
            with ledger.lock:
                page = [ledger.chain[i] for i in ledger.by_room.get(m["id"], [])]
            return self.reply(200, canonical({"sandbox_id": m["id"], "binding_sha256": ledger.binding_sha256,
                                              "receipts": page}))
        if path == "/room/health":
            # Served from the cache that health_loop fills. No upstream call,
            # no subprocess and no ledger lock in the request, so health
            # answers at once when the guest CPU is full.
            if not self.authorized():
                return self.reply(401, b'{"error":"unauthorized"}')
            with self.server.health_lock:
                status, out, at = self.server.health
            if out is None:
                return self.reply(503, b'{"error":"health_not_ready"}')
            return self.reply(status, out, {"X-Health-Age-Ms": str(int((time.time() - at) * 1000))})
        if path == "/room/escape-plant-key":
            return self.handle_escape_plant_key(ledger)
        if path == "/room/escape-nonce":
            return self.handle_escape_nonce(ledger, body)
        miner = getattr(ledger, "miner", None)
        if miner is not None:
            if path == "/room/hotel-key-install-key":
                return self.handle_install_key(ledger)
            if path == "/room/hotel-key":
                return self.handle_hotel_key(ledger, body)
            if not self.authorized():
                # The API behind accepts the internal key the front adds, so the
                # front is the gate for every call it passes on.
                return self.reply(401, b'{"error":"unauthorized"}')
        action = next((a for meth, pat, a in SIGNED if meth == self.command and pat.match(path)), None)
        if action and body:
            # A JSON escape of a lone surrogate parses, but cannot be encoded
            # when the statement is signed. Refuse it before the API runs
            # the action: an action with no receipt is the one thing this
            # front must never produce.
            try:
                canonical(json.loads(body))
            except UnicodeEncodeError:  # before ValueError: it is a subclass
                return self.reply(400, b'{"error":{"code":"invalid_request","message":"the body holds a lone surrogate escape"}}')
            except ValueError:
                pass  # not JSON: the API answers
        status, headers, out = self.upstream(self.server.api_port, body)
        extra = {}
        if action and self.authorized():
            try:
                extra["X-Room-Receipt"] = base64.urlsafe_b64encode(
                    canonical(ledger.sign(self.fields(action, path, body, status, out)))).decode()
            except Exception as exc:  # noqa: BLE001 the action ran: answer, and say the receipt is missing
                traceback.print_exc()
                extra["X-Room-Receipt-Error"] = type(exc).__name__
        ctype = next((v for k, v in headers if k.lower() == "content-type"), "application/json")
        passthrough = {k: v for k, v in headers if k.lower() not in HOP and k.lower() != "content-type"}
        return self.reply(status, out, {**passthrough, **extra}, ctype)

    def handle_attest(self, ledger: "Ledger", body: bytes | None):
        """POST /room/attest {"report_data_hex": <128 hex>}: a fresh SNP report.

        REPORT_DATA is the caller's 64 bytes verbatim. The caller must put a
        digest of what it binds there (for example sha512 of its statement);
        the hotel does not hash it again.
        """
        if self.command != "POST":
            return self.reply(405, b'{"error":"method_not_allowed"}', {"Allow": "POST"})
        if not self.authorized():
            return self.reply(401, b'{"error":"unauthorized"}')
        if not ledger.sealed:
            return self.reply(503, b'{"error":"not_sealed"}')
        try:
            doc = json.loads(body or b"")
        except ValueError:
            doc = None
        raw = doc.get("report_data_hex") if isinstance(doc, dict) else None
        if not isinstance(raw, str) or not HEX64.fullmatch(raw):
            return self.reply(400, b'{"error":"report_data_hex must be 128 hex characters (64 bytes)"}')
        room = doc.get("sandbox_id")
        if room is not None and (not isinstance(room, str) or not re.fullmatch(r"[^/\s]{1,200}", room)):
            return self.reply(400, b'{"error":"sandbox_id must be a room id"}')
        # Broker sets X-Cathedral-Guest; a direct hotel-key call has no guest
        # and shares the "_direct" bucket. Limit is per guest, not per hotel.
        guest = (self.headers.get("X-Cathedral-Guest") or "").strip()
        wait = ledger.attest_slot(guest, self.server.attest_per_minute)
        if wait:
            return self.reply(429, b'{"error":"attest_rate_limit"}', {"Retry-After": str(int(wait) + 1)})
        try:
            out = ledger.attest(bytes.fromhex(raw))
        except Exception as exc:  # noqa: BLE001 a TSM failure is the hotel's, not the caller's
            traceback.print_exc()
            return self.reply(500, canonical({"error": "attest_failed", "detail": type(exc).__name__}))
        if room is not None:
            # The room's signed create receipt (its tunables and tunables_sha256, when it
            # has them), under the receipt key of the binding this report names.
            out["room"] = {"sandbox_id": room, "create_receipt": ledger.create_receipt(room)}
        return self.reply(200, canonical(out))

    def handle_install_key(self, ledger: "Ledger"):
        """GET /room/hotel-key-install-key: the install key, signed by the attested receipt key.

        No bearer: the control plane has no key yet. It reads this over TLS
        pinned to the binding's tls_spki_sha256 and checks the signature with
        the binding's receipt key.
        """
        if self.command != "GET":
            return self.reply(405, b'{"error":"method_not_allowed"}', {"Allow": "GET"})
        return self.reply(200, canonical(ledger.install_key_document()))

    def handle_hotel_key(self, ledger: "Ledger", body: bytes | None):
        """POST /room/hotel-key: install the per-hotel API key. Never echoes it."""
        if self.command != "POST":
            return self.reply(405, b'{"error":"method_not_allowed"}', {"Allow": "POST"})
        if body is None or len(body) > INSTALL_MAX_BYTES:
            return self.reply(413, b'{"error":{"code":"install_too_large","message":"the request is too large"}}')
        try:
            doc = json.loads(body)
        except ValueError:
            doc = None
        try:
            out, receipt = ledger.install_hotel_key(doc)
        except InstallRefused as exc:
            return self.reply(exc.status, canonical({"error": {"code": exc.code, "message": exc.code.replace("_", " ")}}))
        extra = {}
        if receipt is not None:
            extra["X-Room-Receipt"] = base64.urlsafe_b64encode(canonical(receipt)).decode()
        return self.reply(200, canonical(out), extra)

    def handle_escape_plant_key(self, ledger: "Ledger"):
        """GET /room/escape-plant-key: the guest X25519 public key (Escape hotels only)."""
        if self.command != "GET":
            return self.reply(405, b'{"error":"method_not_allowed"}', {"Allow": "GET"})
        if not self.authorized():
            return self.reply(401, b'{"error":"unauthorized"}')
        doc = ledger.plant_key_document() if escape_plant_open(ledger) else None
        if doc is None:
            return self.reply(403, b'{"error":{"code":"escape_disabled","message":"this hotel does not accept an Escape nonce plant"}}')
        return self.reply(200, canonical(doc))

    def handle_escape_nonce(self, ledger: "Ledger", body: bytes | None):
        """POST /room/escape-nonce: write the window nonce. Never echo it."""
        if self.command != "POST":
            return self.reply(405, b'{"error":"method_not_allowed"}', {"Allow": "POST"})
        if not self.authorized():
            return self.reply(401, b'{"error":"unauthorized"}')
        if not escape_plant_open(ledger) or ledger.plant_private is None:
            return self.reply(403, b'{"error":{"code":"escape_disabled","message":"this hotel does not accept an Escape nonce plant"}}')
        try:
            doc = json.loads(body or b"")
        except ValueError:
            return self.reply(400, b'{"error":{"code":"invalid_request","message":"request body is not JSON"}}')
        if not isinstance(doc, dict):
            return self.reply(400, b'{"error":{"code":"invalid_request","message":"request body is not JSON"}}')
        window_id = doc.get("window_id")
        if not isinstance(window_id, str) or not WINDOW_ID_RE.fullmatch(window_id):
            return self.reply(400, b'{"error":{"code":"invalid_request","message":"window_id must be 1 to 128 of [A-Za-z0-9._:-]"}}')
        encrypted = False
        nonce = None
        if doc.get("ciphertext_b64"):
            try:
                nonce = open_plant_nonce(doc, ledger.plant_private, ledger.hotel, window_id)
                encrypted = True
            except PlantError:
                return self.reply(400, b'{"error":{"code":"invalid_request","message":"ciphertext does not open"}}')
        elif isinstance(doc.get("nonce"), str):
            if os.environ.get("ROOM_ESCAPE_ALLOW_PLAINTEXT") != "1":
                return self.reply(409, b'{"error":{"code":"plaintext_forbidden","message":"this hotel requires an encrypted plant"}}')
            nonce = doc["nonce"]
        else:
            return self.reply(400, b'{"error":{"code":"invalid_request","message":"ciphertext_b64 or nonce is required"}}')
        if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
            return self.reply(400, b'{"error":{"code":"invalid_request","message":"nonce must be 16 to 512 of [A-Za-z0-9+/=_-]"}}')
        path = escape_nonce_path()
        try:
            write_escape_nonce(path, nonce, window_id)
        except OSError:
            traceback.print_exc()
            return self.reply(500, b'{"error":{"code":"plant_failed","message":"the nonce file could not be written"}}')
        nonce_sha = sha(nonce.encode())
        nonce = None
        extra = {}
        try:
            receipt = ledger.sign({
                "action": PLANT_ACTION,
                "target": "POST /room/escape-nonce",
                "sandbox_id": None,
                "window_id": window_id,
                "nonce_sha256": nonce_sha,
                "path": path,
                "encrypted": encrypted,
                "status": 200,
            })
            extra["X-Room-Receipt"] = base64.urlsafe_b64encode(canonical(receipt)).decode()
        except Exception as exc:  # noqa: BLE001 the file is written: answer, and say the receipt is missing
            traceback.print_exc()
            extra["X-Room-Receipt-Error"] = type(exc).__name__
        return self.reply(200, canonical({
            "ok": True, "window_id": window_id, "path": path, "encrypted": encrypted,
        }), extra)

    def fields(self, action: str, path: str, body: bytes | None, status: int, out: bytes) -> dict:
        req = {}
        try:
            req = json.loads(body) if body else {}
        except ValueError:
            pass
        res = {}
        try:
            res = json.loads(out) if out else {}
        except ValueError:
            pass
        m = re.match("^" + ROOM, path)
        sandbox = m["id"] if m else (res.get("id") if isinstance(res, dict) else None)
        command = (req.get("cmd", req.get("command")) if isinstance(req, dict) else None)
        image = req.get("image") if action == "create" and isinstance(req, dict) else None
        if isinstance(image, dict):
            # The object form carries registry_auth: record the reference only.
            image = image.get("image")
        if not isinstance(image, str):
            image = None
        policy = self.network_policy(action, status, res)
        tunables = self.room_tunables(action, status, res)
        return {
            "action": action,
            "target": f"{self.command} {self.path}",
            "sandbox_id": sandbox if isinstance(sandbox, str) else None,
            "customer_request_sha256": sha(body or b""),
            "command_sha256": sha(canonical(command)) if command is not None else None,
            "image": image,
            "image_digest": self.server.image_digest(image) if image and status in (200, 201, 202) else None,
            "status": status,
            "result_sha256": sha(out),
            # Create and network switch: the egress policy the hotel applied
            # (canonical {"mode", "allow", "credentials"?}) and its sha256. The sha256 is
            # computed here from the policy, not copied from the API.
            **({"network_policy": policy, "network_policy_sha256": sha(canonical(policy))} if policy else {}),
            # Create with per-room tunables: the values the room started under, the runsc
            # runtime and its args. tunables_sha256 is computed here from the values (it is
            # the tunables document's sha256, the one the Escape challenge records), not
            # copied from the API. The receipt key is in the binding, whose sha256 is the
            # boot report's REPORT_DATA, so a sealed hotel's SNP report covers this field.
            **(tunables or {}),
        }

    @staticmethod
    def room_tunables(action: str, status: int, res) -> dict | None:
        if action != "create" or not 200 <= status < 300 or not isinstance(res, dict):
            return None
        view = res.get("tunables")
        values = view.get("values") if isinstance(view, dict) else None
        if not isinstance(values, dict) or view.get("status") != "applied":
            return None
        return {"tunables": values, "tunables_sha256": sha(canonical(values)),
                "tunables_runtime": str(view.get("runtime")),
                "tunables_runtime_args": [str(a) for a in view.get("runtime_args") or []]}

    @staticmethod
    def network_policy(action: str, status: int, res) -> dict | None:
        if action not in ("create", "network_set") or not 200 <= status < 300 or not isinstance(res, dict):
            return None
        net = res.get("network")
        policy = net.get("policy") if isinstance(net, dict) else None
        if not (isinstance(policy, dict) and isinstance(policy.get("mode"), str) and isinstance(policy.get("allow"), list)):
            return None
        out = {"mode": policy["mode"], "allow": [str(x) for x in policy["allow"]]}
        # #304: credential references (host, header name, secret name). The
        # policy never carries a secret value.
        creds = policy.get("credentials")
        if isinstance(creds, list) and creds:
            out["credentials"] = [{"host": str(c.get("host")), "header": str(c.get("header")),
                                   "secret": str(c.get("secret"))} for c in creds if isinstance(c, dict)]
        return out

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = handle_any


UP = Upstreams()



class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 1024

    def __init__(self, addr, ledger, api_port, health_port, api_key, docker_sock, attest_per_minute=30, *,
                 attestation_only=False):
        super().__init__(addr, Handler)
        self.attest_per_minute = max(1, int(attest_per_minute))
        self.ledger, self.api_port, self.health_port, self.api_key = ledger, api_port, health_port, api_key
        self.docker_sock = docker_sock
        self.attestation_only = attestation_only
        self._digests: dict[str, str | None] = {}
        self.health_lock = threading.Lock()
        self.health: tuple[int, bytes | None, float] = (503, None, 0.0)
        if not attestation_only:
            threading.Thread(target=self.health_loop, daemon=True).start()

    def health_loop(self) -> None:
        """Build the health answer once a second, off the request path."""
        up = http.client.HTTPConnection("127.0.0.1", self.health_port, timeout=30)
        auth = {"Authorization": "Bearer " + self.api_key.decode()}
        while True:
            try:
                up.request("GET", "/room/health", headers=auth)
                r = up.getresponse()
                status, out = r.status, r.read()
                if status == 200:
                    doc = json.loads(out)
                    # Sealed guests only. Level 1 must not claim an SNP binding.
                    if self.ledger.sealed:
                        doc["sealed"] = True
                    doc["receipts"] = {"binding_sha256": self.ledger.binding_sha256, "count": len(self.ledger.chain)}
                    doc["runsc_sandbox_procs"] = int(subprocess.run(
                        ["pgrep", "-cf", "[r]unsc-sandbox"], capture_output=True, text=True, timeout=20).stdout.strip() or 0)
                    doc["guest_kernel_sev"] = self.sev_log()
                    out = canonical(doc)
                with self.health_lock:
                    self.health = (status, out, time.time())
            except (http.client.HTTPException, OSError, ValueError, subprocess.SubprocessError):
                up.close()
                up = http.client.HTTPConnection("127.0.0.1", self.health_port, timeout=30)
            time.sleep(1)

    def sev_log(self) -> list[str]:
        """The guest kernel's own SEV lines (dmesg), read once."""
        if not hasattr(self, "_sev"):
            out = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
            self._sev = [ln.strip() for ln in out.splitlines() if "SEV" in ln][:12]
        return self._sev

    def image_digest(self, ref: str) -> str | None:
        if not isinstance(ref, str):
            return None
        if ref not in self._digests:
            try:
                r = subprocess.run(["docker", "-H", "unix://" + self.docker_sock, "image", "inspect", "--format",
                                    "{{.Id}}", ref], capture_output=True, text=True, timeout=30)
            except (subprocess.SubprocessError, OSError):
                return None  # a digest is a bonus; the receipt is the product
            self._digests[ref] = r.stdout.strip() or None if r.returncode == 0 else None
        return self._digests[ref]


class TLSServer(Server):
    """The miner hotel front over HTTPS with the boot TLS key the binding names.

    The handshake runs in the request's own thread, so a client that stalls
    it holds that thread only, not the accept loop.
    """

    handshake_timeout = 30

    def __init__(self, addr, *args, tls_context: ssl.SSLContext, **kwargs):
        self.tls_context = tls_context
        super().__init__(addr, *args, **kwargs)

    def finish_request(self, request, client_address):
        request.settimeout(self.handshake_timeout)
        try:
            conn = self.tls_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            conn.settimeout(None)
            self.RequestHandlerClass(conn, client_address, self)
        finally:
            conn.close()


def main() -> int:
    env = os.environ
    host, port = env["ROOM_RECEIPTS_LISTEN"].rsplit(":", 1)
    mode = env.get("ROOM_MINER") or "0"
    if mode not in ("0", "1"):
        raise SystemExit("ROOM_MINER must be 0 or 1")
    # Miner hotel: this key file holds the guest-internal API key (made at boot in the guest).
    with open(env.get("ROOM_API_KEY_PATH", "/etc/pool-room/api.key"), "rb") as f:
        api_key = f.read().strip()
    miner = None
    if mode == "1":
        miner = MinerHotel(env["ROOM_HOTEL_NAME"], parse_install_signers(env.get("ROOM_HOTEL_KEY_INSTALL_SIGNERS", "")))
    store = env.get("ROOM_RECEIPTS_DIR", "/run/room-receipts")
    ledger = Ledger(env["ROOM_HOTEL_NAME"], store, miner=miner)
    if ledger.sealed:
        print(f"room-receipts: binding {ledger.binding_sha256} measurement {ledger.binding['measurement']}", flush=True)
    else:
        print(f"room-receipts: binding {ledger.binding_sha256} level hotel", flush=True)
    args = (ledger, int(env.get("ROOM_API_PORT", "18090")), int(env.get("ROOM_HEALTH_PORT", "18091")), api_key,
            env.get("ROOM_DOCKER_SOCK", "/run/pool-room/docker.sock"), int(env.get("ROOM_ATTEST_PER_MINUTE", "30")))
    if miner is None:
        srv = Server((host, int(port)), *args)
        srv.serve_forever()
        return 0
    tls_host, tls_port = env["ROOM_RECEIPTS_TLS_LISTEN"].rsplit(":", 1)
    tls = TLSServer((tls_host, int(tls_port)), *args, tls_context=miner.tls_context(store))
    plain = Server((host, int(port)), *args, attestation_only=True)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    print(f"room-receipts: miner hotel: HTTPS {tls_host}:{tls_port} tls_spki_sha256 {miner.tls_spki_sha256}; "
          f"plain HTTP {host}:{port} serves /room/attestation only; no hotel key until POST /room/hotel-key", flush=True)
    tls.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
