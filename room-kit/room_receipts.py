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
  POST /room/escape-nonce          sealed Escape hotels only: plant the window nonce at
                                   /run/escape-room/<window_id>/nonce, one file per window
                                   (never echoed; the signed receipt and the answer carry that
                                   path, not the value)
  GET /room/hotel-key-install-key  miner hotels only: the guest X25519 install key, signed
                                   by the attested receipt key
  POST /room/hotel-key             miner hotels only: install the per-hotel API key, sealed
                                   to the install key and signed by a pinned control plane key
  POST /v1/sandboxes/<id>/sealed-secrets
                                   ROOM_SEALED_SECRETS=1 on a sealed guest only: one customer
                                   secret, sealed to the binding's sealed_secrets key,
                                   written read-only at /run/secrets/<name> in that room
                                   (never echoed; the receipt signs the envelope sha256;
                                   an exact retry answers unchanged with that receipt)
  GET /v1/sandboxes/<id>/sealed-secrets
                                   names, versions and envelope sha256 of that room's secrets
  POST /v1/sandboxes/<id>/sealed-env
                                   ROOM_SEALED_SECRETS=1 on a sealed guest only (AB#414): the
                                   room's whole env overlay, sealed to the same sealed_secrets
                                   key, merged under each later exec and process start's own env
                                   (never echoed; the receipt signs the names and the envelope
                                   sha256; an exact retry answers unchanged with that receipt)
  GET /v1/sandboxes/<id>/sealed-env
                                   names, version and envelope sha256 of that room's overlay
  POST /v1/sandboxes/<id>/sealed-exec
                                   ROOM_SEALED_EXEC=1 on a sealed guest only: one customer exec,
                                   sealed to the binding's sealed_exec key; the answer is sealed to
                                   a key the client made for it (the receipt signs sha256 of the
                                   plaintext command, as for any exec, and of both envelopes)
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

Sealed secrets (ROOM_SEALED_SECRETS=1, sealed only; AB#417). The front makes,
at start and in memory, an X25519 key and names it in the binding
(sealed_secrets.x25519_public_b64), so the boot's REPORT_DATA commits to it. A
customer who has checked the attestation seals a secret to that key with the
envelope the plant and the hotel key use (X25519, HKDF-SHA256, AES-256-GCM),
under its own HKDF info and an AAD that names this binding, the room, the
room's create receipt (its incarnation), the secret name and its version.
Only this guest can open it, and only into that incarnation of the room. The
front writes the value into the room's directory under
ROOM_SEALED_SECRETS_DIR (tmpfs, guest memory), which the room API bind-mounts
read-only at /run/secrets. A version at or below the last one accepted for
that room incarnation and name is refused, so an older envelope cannot roll a
secret back. A room's entries go with the room. Flag off: the binding is byte
for byte what it was, and the routes answer 403.

Sealed commands (ROOM_SEALED_EXEC=1, sealed only; AB#417). The same pattern
for exec, with its own per-boot X25519 key (sealed_exec.x25519_public_b64 in
the binding). The envelope holds cmd, env, stdin, cwd and user; its AAD names
the binding, the room, its incarnation, issued_at, the timeout and the key the
answer is sealed to. The front opens it, runs it through the room API inside
the guest (which keeps it out of the exec history and logs), and seals the
room API's whole answer (status, exit code, output) to the client's key. An
envelope runs once: its ephemeral key is kept while issued_at is in the
window, and one outside the window is refused. The receipt is an exec receipt
that signs sha256 of the plaintext command, as for any exec, and the sha256 of
both envelopes, which is how the client knows the answer is the guest's.

Dedicated sealed machine (one owner). The host launches the guest with the
owner's Ed25519 public key and the manifest digest in fw_cfg, and with
HOST_DATA = sha256("cathedral-dedicated-v1\\0" || manifest sha256 || owner key).
At start this front recomputes that value and compares it with HOST_DATA in
its own SNP report. A key that the report does not name stops the front: it
does not serve. A match turns on the owner gate: every room create (and image
build) must carry X-Cathedral-Owner-Timestamp and X-Cathedral-Owner-Signature,
an Ed25519 signature by the owner key over
  "cathedral-owner-<action>-v1\\n" || timestamp || "\\n" || owner_request_sha256
where owner_request_sha256 is owner_request_sha256(body) below. No key in
fw_cfg: a shared machine, no gate. The binding says which ("tenancy").

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
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse, urlsplit

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
DEFAULT_ESCAPE_NONCE_DIR = "/run/escape-room"
# Kept for 25 h: longer than a window plus the AB#677 grace. Age, not count, so a create flood cannot evict live windows.
DEFAULT_ESCAPE_NONCE_KEEP_SECONDS = 25 * 3600
WINDOW_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
# A window id becomes a directory name: no ".", "..", or hidden names.
WINDOW_DIR_RE = re.compile(r"^[A-Za-z0-9_:-][A-Za-z0-9._:-]{0,127}$")
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
# Dedicated sealed machines (one owner). fw_cfg files are host-given and not
# measured; HOST_DATA (chip-signed, fixed at launch) is what makes them count.
OWNER_FW_CFG = "/sys/firmware/qemu_fw_cfg/by_name/opt/cathedral"
DEDICATED_HOST_DATA_DOMAIN = b"cathedral-dedicated-v1\0"
OWNER_SIGNATURE_HEADER = "X-Cathedral-Owner-Signature"
OWNER_TIMESTAMP_HEADER = "X-Cathedral-Owner-Timestamp"
OWNER_MAX_SKEW_SECONDS = 300
# The one field the broker adds per request that the owner cannot know in
# advance (a random id per create request). Everything else is signed.
OWNER_UNSIGNED_LABELS = ("broker_batch",)
OWNER_TIMESTAMP_RE = re.compile(r"^[0-9]{1,12}$")
GUEST_HEADER = "X-Cathedral-Guest"
# Customer-sealed secrets (AB#417 Mode B). The client side is ctcli (cathedral-pool
# cli/sealed_secrets.py) and, later, the browser; keep all three in step.
# v2: the header names the room's incarnation (its create receipt sha256), so a
# room's state can be dropped when the room goes. v1 never shipped.
SECRETS_SCHEMA = "cathedral_sealed_secret_v2"
# One envelope construction in the guest: the plant one, with its own HKDF info and AAD.
# WebCrypto has every step (X25519, HKDF, AES-GCM), so the browser seals the same way.
SECRETS_ALGORITHM = PLANT_ALGORITHM
SECRETS_HKDF_INFO = b"cathedral.sealed-secret.v2"
SECRETS_AAD_LABEL = b"cathedral.sealed-secret.v2\n"
SECRETS_ACTION = "sealed_secret_write"
SECRETS_HEADER = ("schema", "algorithm", "binding_sha256", "sandbox_id", "room_create_receipt_sha256", "name",
                  "version")
SECRETS_ENVELOPE = ("ephemeral_public_b64", "nonce_b64", "ciphertext_b64")
SECRETS_FIELDS = frozenset(SECRETS_HEADER + SECRETS_ENVELOPE)
SECRETS_IN_ROOM = "/run/secrets"
DEFAULT_SECRETS_DIR = "/run/room-secrets"
SECRET_VALUE_MAX_BYTES = 64 * 1024
SECRETS_MAX_BYTES = 128 * 1024  # one request: base64 of the largest envelope plus the header
SECRETS_MAX_PER_ROOM = 64
# (room incarnation, name) entries of live rooms: 1,000 slots x 64 names. Entries of a
# room that is gone or made again are dropped (SealedSecrets.sweep), never replayable.
SECRETS_MAX_TRACKED = 65536
SECRETS_SWEEP_SECONDS = 1.0  # a full table sweeps at most once a second
SECRET_VERSION_MAX = 2**53 - 1  # an integer a browser can hold exactly
SECRET_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")  # a file name: no slash, no leading dot
SECRETS_ROOM_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SECRETS_ROUTE = re.compile(r"^/v1/sandboxes/(?P<id>[^/]+)/sealed-secrets$")
# AB#389: the Cathedral API names the sandbox a create is for in this label
# (the id its customer holds, a UUID) and refuses it from customers. The create
# receipt signs it, so the customer can tie that id to this room without the
# API's word. Any other value is not signed: the receipt then names no sandbox.
SANDBOX_LINK_LABEL = "cathedral_sandbox_id"
SANDBOX_LINK_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# Customer-sealed commands (AB#417, docs/SEALED_COMMANDS.md). The client side is ctcli
# (cathedral-pool cli/sealed_exec.py); keep the two in step. The same envelope as sealed
# secrets, with its own key, HKDF info and AAD, in both directions: the request is sealed
# to this boot's sealed_exec key, the answer to a key the client made for this one exec.
EXEC_SCHEMA = "cathedral_sealed_exec_v1"
EXEC_ALGORITHM = PLANT_ALGORITHM
EXEC_HKDF_INFO = b"cathedral.sealed-exec.v1"
EXEC_AAD_LABEL = b"cathedral.sealed-exec.v1\n"
EXEC_RESPONSE_SCHEMA = "cathedral_sealed_exec_response_v1"
EXEC_RESPONSE_HKDF_INFO = b"cathedral.sealed-exec-response.v1"
EXEC_RESPONSE_AAD_LABEL = b"cathedral.sealed-exec-response.v1\n"
EXEC_HEADER = ("schema", "algorithm", "binding_sha256", "sandbox_id", "room_create_receipt_sha256", "issued_at",
               "timeout_seconds", "response_public_b64")
EXEC_FIELDS = frozenset(EXEC_HEADER + SECRETS_ENVELOPE)
EXEC_STRING_FIELDS = ("response_public_b64",) + SECRETS_ENVELOPE  # hashed or decoded before any other check
# What the envelope opens to: the exec request the room API takes, less the timeout (in the header).
EXEC_REQUEST_KEYS = frozenset({"cmd", "env", "stdin", "cwd", "user"})
EXEC_PLAINTEXT_MAX_BYTES = 6 * 1024 * 1024  # 1 MiB of stdin and the env, with JSON escapes
EXEC_MAX_BYTES = 9 * 1024 * 1024  # one request: base64 of the largest envelope plus the header
# A sealed exec's answer exists only in the front's one reply (it is kept out of the room API's
# log), so the front must be able to wait for it: at most 1,800 s, and the front waits that plus
# EXEC_ANSWER_MARGIN_SECONDS (the room API adds 15 s for docker exec past the command's limit).
EXEC_TIMEOUT_MAX = 1800
EXEC_ANSWER_MARGIN_SECONDS = 120
# The room API's own limit on a plain exec (cathedral/sandbox_api.py EXEC_MAX_TIMEOUT_SECONDS). The front
# waits for a plain exec's answer up to the command's timeout, so it must not stop waiting before the
# API does: a flat 1800 s wait answered 502 for any command running past 30 minutes (AB#696).
EXEC_API_MAX_SECONDS = 14400


def plain_exec_wait(body: bytes | None) -> float:
    """How long the front waits for the room API's answer to a plain exec: its timeout plus the margin."""
    try:
        timeout = json.loads(body or b"").get("timeout_seconds")
    except (ValueError, RecursionError, AttributeError):
        timeout = None
    if type(timeout) is not int or not 1 <= timeout <= EXEC_API_MAX_SECONDS:
        # The API refuses a timeout it cannot use at once, and one it takes has no other bound than its maximum.
        timeout = EXEC_API_MAX_SECONDS
    return timeout + EXEC_ANSWER_MARGIN_SECONDS
# Replay: each accepted envelope's ephemeral key is kept until its issued_at leaves the window,
# and an envelope outside the window is refused, so a kept key is never needed after that.
EXEC_MAX_AGE_SECONDS = 120
EXEC_FUTURE_SKEW_SECONDS = 30
EXEC_MAX_PER_ROOM = 4096  # accepted in one window by one room incarnation (about 27 a second)
EXEC_MAX_TRACKED = 131072  # across rooms
EXEC_ROUTE = re.compile(r"^/v1/sandboxes/(?P<id>[^/]+)/sealed-exec$")
# The room API's route for an exec this front opened: it runs as /exec does and keeps the
# command and its output out of the exec history and the container log, which GET .../logs
# serves to the relay. An API without the route answers 404 and runs nothing (fail closed).
# Only this front calls it: a caller's request that names it in any spelling is refused.
EXEC_API_TAIL = "exec-sealed"
EXEC_API_ROUTE = re.compile(r"^/v1/sandboxes/[^/]+/exec-sealed$")  # the room API's own pattern

# Customer-sealed env overlay (AB#414, docs/SEALED_SECRETS.md). The room's env after
# create: one envelope holds the whole overlay ({"env": {name: value}}, {} clears it),
# sealed to this boot's sealed_secrets key under its own HKDF info and AAD, so it is on
# whenever sealed secrets are and the binding does not change. The front opens it and
# puts it on the room API over loopback; every later exec and process start in the room
# runs with it under its own env. The receipt signs the names and the envelope sha256,
# never a digest of a value (values are often guessable), as for a sealed secret.
ENV_SCHEMA = "cathedral_sealed_env_v1"
ENV_ALGORITHM = PLANT_ALGORITHM
ENV_HKDF_INFO = b"cathedral.sealed-env.v1"
ENV_AAD_LABEL = b"cathedral.sealed-env.v1\n"
ENV_ACTION = "sealed_env_set"
ENV_HEADER = ("schema", "algorithm", "binding_sha256", "sandbox_id", "room_create_receipt_sha256", "version")
ENV_FIELDS = frozenset(ENV_HEADER + SECRETS_ENVELOPE)
# The rules of the room API (cathedral/sandbox_api.py env_overlay_problem); keep the two in step.
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
ENV_MAX_NAMES = 64
ENV_MAX_BYTES_SET = 64 * 1024  # names and values, UTF-8
ENV_RESERVED = ("PATH",)
ENV_RESERVED_PREFIXES = ("LD_",)
ENV_PLAINTEXT_MAX_BYTES = 6 * ENV_MAX_BYTES_SET + 1024  # the overlay as JSON, every byte escaped at worst
ENV_MAX_BYTES = 4 * ENV_PLAINTEXT_MAX_BYTES // 3 + 4096  # one request: base64 of the envelope plus the header
ENV_MAX_TRACKED = 65536  # rooms with an overlay on this boot
ENV_APPLY_STRIPES = 64  # one write at a time per room; rooms share a stripe, never a wait past the timeout
ENV_APPLY_TIMEOUT_SECONDS = 30  # the room API sets a dict in memory: a slow answer is a broken API
ENV_ROUTE = re.compile(r"^/v1/sandboxes/(?P<id>[^/]+)/sealed-env$")
# The room API's route for an overlay this front opened. Only this front calls it: a caller's
# request that names it in any spelling is refused, as for exec-sealed.
ENV_API_TAIL = "env-sealed"
ENV_API_ROUTE = re.compile(r"^/v1/sandboxes/[^/]+/env-sealed$")
INTERNAL_API_ROUTES = (EXEC_API_ROUTE, ENV_API_ROUTE)


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


# ---------------------------------------------------------------- dedicated owner

class OwnerBindingError(RuntimeError):
    """fw_cfg names an owner that HOST_DATA does not. The front must not serve."""


def dedicated_host_data(manifest_sha256: bytes, owner_key: bytes) -> bytes:
    """HOST_DATA of a dedicated machine (launch-guest.sh computes the same)."""
    return hashlib.sha256(DEDICATED_HOST_DATA_DOMAIN + manifest_sha256 + owner_key).digest()


def _fw_cfg(name: str) -> bytes | None:
    try:
        with open(os.path.join(OWNER_FW_CFG, name, "raw"), "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def owner_tenancy(host_data_hex: str) -> tuple[bytes, bytes] | None:
    """(owner key, manifest sha256) on a dedicated machine; None on a shared one.

    No owner key in fw_cfg: shared. A key that this report's HOST_DATA does
    not commit to raises OwnerBindingError: the host gave the guest an owner
    the chip did not sign, and serving would claim an owner nobody can check.
    """
    key = _fw_cfg("owner-pubkey")
    if key is None:
        return None
    if len(key) != 32:
        raise OwnerBindingError(f"fw_cfg owner-pubkey is {len(key)} bytes, expected a 32-byte raw Ed25519 public key")
    try:
        Ed25519PublicKey.from_public_bytes(key)
    except ValueError as exc:
        raise OwnerBindingError("fw_cfg owner-pubkey is not an Ed25519 public key") from exc
    manifest = _fw_cfg("manifest-sha256")
    if manifest is None or len(manifest) != 32:
        raise OwnerBindingError("fw_cfg has an owner key but no 32-byte manifest-sha256")
    if not hmac.compare_digest(dedicated_host_data(manifest, key), bytes.fromhex(host_data_hex)):
        raise OwnerBindingError("HOST_DATA in the SNP report does not commit to the fw_cfg owner key")
    return key, manifest


def _whole_numbers(doc):
    """2.0 -> 2, recursively. The broker (Go) re-encodes every JSON number as a float64."""
    if isinstance(doc, float) and doc.is_integer():
        return int(doc)
    if isinstance(doc, dict):
        return {k: _whole_numbers(v) for k, v in doc.items()}
    if isinstance(doc, list):
        return [_whole_numbers(v) for v in doc]
    return doc


def owner_request_sha256(body: bytes) -> str:
    """The digest an owner signs: canonical JSON of the request body as the
    hotel receives it, without the broker's per-request batch label.

    The broker changes a create before the hotel sees it (placement fields
    and count removed, a default network, the broker_guest and broker_batch
    labels); owner_sign.py makes the same changes, so both sides hash the
    same document. Only broker_batch, a random id per request, is left out
    here; "count" and every other field count. Raises ValueError when the
    body is not a JSON object.
    """
    return sha(canonical(_whole_numbers(_signed_document(body))))


def _signed_document(body: bytes) -> dict:
    doc = json.loads(body)
    if not isinstance(doc, dict):
        raise ValueError("the request body is not a JSON object")
    labels = doc.get("labels")
    if isinstance(labels, dict):
        for k in OWNER_UNSIGNED_LABELS:
            labels.pop(k, None)
    return doc


def owner_message(action: str, timestamp: str, request_sha256: str) -> bytes:
    return f"cathedral-owner-{action}-v1\n{timestamp}\n{request_sha256}".encode()


def check_owner_signature(owner_key: bytes, action: str, headers, body: bytes | None,
                          now: float) -> tuple[str | None, str, dict]:
    """(error code or None, message, receipt fields) for one gated request."""
    sig_b64 = (headers.get(OWNER_SIGNATURE_HEADER) or "").strip()
    ts = (headers.get(OWNER_TIMESTAMP_HEADER) or "").strip()
    if not sig_b64 or not ts:
        return ("owner_signature_required",
                f"this is a dedicated machine: a {action} needs {OWNER_TIMESTAMP_HEADER} and "
                f"{OWNER_SIGNATURE_HEADER} signed by the owner key in the attestation", {})
    if not OWNER_TIMESTAMP_RE.fullmatch(ts):
        return "owner_signature_invalid", "the owner timestamp is not unix seconds", {}
    if abs(now - int(ts)) > OWNER_MAX_SKEW_SECONDS:
        return "owner_signature_invalid", f"the owner timestamp is more than {OWNER_MAX_SKEW_SECONDS} s from the hotel clock", {}
    try:
        sig = base64.b64decode(sig_b64, validate=True)
        doc = _signed_document(body or b"")
        digest = sha(canonical(_whole_numbers(doc)))
    except (ValueError, RecursionError):  # binascii.Error, JSONDecodeError and UnicodeDecodeError are ValueErrors
        return "owner_signature_invalid", "the owner signature or the request body does not parse", {}
    try:
        Ed25519PublicKey.from_public_bytes(owner_key).verify(sig, owner_message(action, ts, digest))
    except InvalidSignature:
        return "owner_signature_invalid", "the owner signature does not verify over this request", {}
    if action == "create":
        # The API takes a room's guest (whose workspaces and secrets it gets)
        # from X-Cathedral-Guest before the signed broker_guest label. The
        # broker sends no such header on a create; any copy must equal the label.
        labels = doc.get("labels") if isinstance(doc.get("labels"), dict) else {}
        all_values = headers.get_all(GUEST_HEADER) if hasattr(headers, "get_all") else [headers.get(GUEST_HEADER)]
        if any(v and v != labels.get("broker_guest") for v in all_values or []):
            return "owner_signature_invalid", "X-Cathedral-Guest differs from the signed broker_guest label", {}
    return None, "", {"owner_request_sha256": digest, "owner_timestamp": int(ts), "owner_signature_b64": b64(sig)}


def escape_plant_open(ledger: "Ledger") -> bool:
    """Sealed Escape hotels only. Unset or any other value fails closed."""
    return os.environ.get("ROOM_ESCAPE") == "1" and bool(getattr(ledger, "sealed", False))


def escape_nonce_dir() -> str:
    return os.environ.get("ROOM_ESCAPE_NONCE_DIR") or DEFAULT_ESCAPE_NONCE_DIR


def escape_nonce_path(window_id: str) -> str:
    """One secret file per window, so a second plant cannot overwrite the first."""
    return os.path.join(escape_nonce_dir(), window_id, "nonce")


def escape_nonce_keep_seconds() -> float:
    try:
        return float(os.environ.get("ROOM_ESCAPE_NONCE_KEEP_SECONDS") or DEFAULT_ESCAPE_NONCE_KEEP_SECONDS)
    except ValueError:
        return float(DEFAULT_ESCAPE_NONCE_KEEP_SECONDS)


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


def _open_envelope(doc: dict, private: X25519PrivateKey, info: bytes, aad: bytes,
                   max_ciphertext: int = 2048) -> bytes:
    """Open an envelope of _seal_envelope. Raises PlantError, which never names the plaintext."""
    if not isinstance(doc, dict) or doc.get("algorithm") != PLANT_ALGORITHM:
        raise PlantError("ciphertext does not open")
    try:
        raw_eph = base64.b64decode(doc["ephemeral_public_b64"], validate=True)
        aes_n = base64.b64decode(doc["nonce_b64"], validate=True)
        ct = base64.b64decode(doc["ciphertext_b64"], validate=True)
        if len(raw_eph) != 32 or len(aes_n) != 12 or not (16 <= len(ct) <= max_ciphertext):
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


# ---------------------------------------------------------------- sealed secrets (AB#417)

class SecretRefused(Exception):
    """A sealed secret write refused. The code is short and never names the value."""

    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status, self.code = status, code


def sealed_secrets_wanted() -> bool:
    """ROOM_SEALED_SECRETS=1. Unset or any other value: off."""
    return os.environ.get("ROOM_SEALED_SECRETS") == "1"


def secret_header(binding_sha256: str, sandbox_id: str, room_create_receipt_sha256: str, name: str,
                  version: int) -> dict:
    """The fields of an envelope that its AAD authenticates (all but the three envelope values).

    room_create_receipt_sha256 is the receipt_sha256 of the room's create
    receipt in this boot's chain: it names this incarnation of the room, so an
    envelope never opens into a room made again under the same id.
    """
    return {"schema": SECRETS_SCHEMA, "algorithm": SECRETS_ALGORITHM, "binding_sha256": binding_sha256,
            "sandbox_id": sandbox_id, "room_create_receipt_sha256": room_create_receipt_sha256, "name": name,
            "version": version}


def secret_aad(header: dict) -> bytes:
    """A label and canonical(header): HKDF salt and AES-GCM AAD. Any change to a header field fails the open."""
    return SECRETS_AAD_LABEL + canonical(header)


def seal_secret(value: bytes, recipient: X25519PublicKey, *, binding_sha256: str, sandbox_id: str,
                room_create_receipt_sha256: str, name: str, version: int) -> dict:
    """The customer's envelope (ctcli, tests). The guest only opens."""
    header = secret_header(binding_sha256, sandbox_id, room_create_receipt_sha256, name, version)
    return {**header, **_seal_envelope(value, recipient, SECRETS_HKDF_INFO, secret_aad(header))}


def open_secret(doc: dict, private: X25519PrivateKey) -> bytes:
    """Open an envelope of seal_secret. Raises SecretRefused, which never names the value."""
    header = {k: doc[k] for k in SECRETS_HEADER}
    try:
        # The tag is 16 bytes: an empty value is a 16-byte ciphertext.
        return _open_envelope(doc, private, SECRETS_HKDF_INFO, secret_aad(header),
                              max_ciphertext=SECRET_VALUE_MAX_BYTES + 16)
    except PlantError:
        raise SecretRefused(400, "sealed_secret_does_not_open") from None


class AcceptedSecret:
    """What this boot accepted for one name in one room incarnation."""

    __slots__ = ("version", "envelope_sha256", "ephemeral_public_b64", "receipt")

    def __init__(self, version: int, envelope_sha256: str, ephemeral_public_b64: str, receipt: dict | None):
        self.version, self.envelope_sha256 = version, envelope_sha256
        self.ephemeral_public_b64, self.receipt = ephemeral_public_b64, receipt


class SealedSecrets:
    """The per-boot secrets key and what this boot accepted. Memory only.

    The private key never leaves this process. The binding names the public
    key (binding_fields), so the boot's SNP report commits to it. rooms maps a
    room id to (incarnation, {name: AcceptedSecret}). The incarnation is the
    receipt_sha256 of the room's create receipt, and every envelope names it
    in its AAD. A room's entries go when a delete of it passes this front
    (retire), when it is made again (a new create receipt), or when its
    directory is gone (sweep). None of that lets an old envelope replay: it
    names an incarnation the front no longer accepts.
    """

    def __init__(self, root: str):
        self.root = root
        self.private = X25519PrivateKey.generate()
        self.public_b64 = b64(_raw_x25519(self.private.public_key()))
        self.lock = threading.Lock()
        self.rooms: dict[str, tuple[str, dict[str, AcceptedSecret]]] = {}
        self.tracked = 0  # entries across rooms; at most SECRETS_MAX_TRACKED
        self.swept_at = float("-inf")

    def accepted(self, room: str, incarnation: str) -> dict[str, AcceptedSecret]:
        """The room's entries for *incarnation* (empty for another one). Caller holds the lock."""
        held = self.rooms.get(room)
        return held[1] if held is not None and held[0] == incarnation else {}

    def record(self, room: str, incarnation: str, name: str, entry: AcceptedSecret) -> None:
        """Keep entry; the entries of an earlier incarnation of the room go. Caller holds the lock."""
        held = self.rooms.get(room)
        if held is None or held[0] != incarnation:
            self.forget(room)
            held = self.rooms[room] = (incarnation, {})
        if name not in held[1]:
            self.tracked += 1
        held[1][name] = entry

    def forget(self, room: str) -> None:
        """Drop the room's entries. Caller holds the lock."""
        held = self.rooms.pop(room, None)
        if held is not None:
            self.tracked -= len(held[1])

    def retire(self, room: str) -> None:
        """A delete of the room passed this front: drop its entries and anything a racing write left.

        The API dropped the directory before it answered the delete, but a
        write that renamed into it meanwhile makes that rmtree fail
        (ENOTEMPTY). Writes hold this lock until their file is in place and
        the room's incarnation is gone before this runs, so after it no file
        of the room is left and no write can make one.
        """
        if not SECRETS_ROOM_RE.fullmatch(room):
            return  # never a path outside the root: "..", "." and anything with a slash do not match
        with self.lock:
            self.forget(room)
            shutil.rmtree(os.path.join(self.root, room), ignore_errors=True)

    def sweep(self, incarnation_of, now: float) -> None:
        """Drop each room that is gone or made again. At most once a SECRETS_SWEEP_SECONDS. Caller holds the lock.

        A directory is made only by a create, which signs a new create
        receipt, so a room whose directory is gone takes no write under its
        old incarnation again.
        """
        if now - self.swept_at < SECRETS_SWEEP_SECONDS:
            return
        self.swept_at = now
        for room, (incarnation, _) in list(self.rooms.items()):
            if incarnation_of(room) != incarnation or not _is_dir(os.path.join(self.root, room)):
                self.forget(room)

    def __repr__(self) -> str:
        return f"SealedSecrets(x25519_public_b64={self.public_b64})"

    def binding_fields(self) -> dict:
        return {"sealed_secrets": {"schema": SECRETS_SCHEMA, "algorithm": SECRETS_ALGORITHM,
                                   "x25519_public_b64": self.public_b64, "path": SECRETS_IN_ROOM}}

    def room_dir(self, room: str) -> int:
        """A directory fd for the room's secrets, or SecretRefused 404.

        The room API makes ROOM_SEALED_SECRETS_DIR/<room> at create and mounts
        it read-only at /run/secrets; no directory means no such room on this
        boot (or one made before the API had the mount). A link is refused.
        """
        try:
            return os.open(os.path.join(self.root, room), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise SecretRefused(404, "sealed_secret_room_not_found") from None

    def listing(self, room: str, incarnation: str | None) -> list[dict]:
        with self.lock:
            items = sorted(self.accepted(room, incarnation).items()) if incarnation else []
        return [{"name": name, "version": e.version, "envelope_sha256": e.envelope_sha256,
                 "path": f"{SECRETS_IN_ROOM}/{name}"} for name, e in items]


def _is_dir(path: str) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def _secret_file_present(dir_fd: int, name: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def _secret_file_count(dir_fd: int) -> int:
    """Secrets in the room directory, whatever incarnation wrote them (temp names start with a dot)."""
    return sum(1 for entry in os.listdir(dir_fd) if not entry.startswith("."))


def _write_secret_file(dir_fd: int, name: str, value: bytes) -> None:
    """Write name in the room directory as a whole new file (temp, then rename), mode 0444.

    0444 because the room's own user may not be root; only this room mounts
    the directory. The temp name starts with a dot, which no secret name can.
    """
    tmp = f".tmp-{uuid.uuid4().hex}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    try:
        view = memoryview(value)
        while view:
            view = view[os.write(fd, view):]
        os.fchmod(fd, 0o444)
        os.close(fd)
        fd = -1
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------- sealed env overlay (AB#414)

class EnvRefused(Exception):
    """A sealed env write refused. The code is short and never names a value."""

    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status, self.code = status, code


def env_header(binding_sha256: str, sandbox_id: str, room_create_receipt_sha256: str, version: int) -> dict:
    """The fields of an env envelope that its AAD authenticates (all but the three envelope values)."""
    return {"schema": ENV_SCHEMA, "algorithm": ENV_ALGORITHM, "binding_sha256": binding_sha256,
            "sandbox_id": sandbox_id, "room_create_receipt_sha256": room_create_receipt_sha256, "version": version}


def env_aad(header: dict) -> bytes:
    return ENV_AAD_LABEL + canonical(header)


def seal_env(env: dict, recipient: X25519PublicKey, *, binding_sha256: str, sandbox_id: str,
             room_create_receipt_sha256: str, version: int) -> dict:
    """The customer's envelope (ctcli, tests): the whole overlay. The guest only opens."""
    header = env_header(binding_sha256, sandbox_id, room_create_receipt_sha256, version)
    return {**header, **_seal_envelope(canonical({"env": env}), recipient, ENV_HKDF_INFO, env_aad(header))}


def open_env(doc: dict, private: X25519PrivateKey) -> bytes:
    """Open an envelope of seal_env. Raises EnvRefused, which never names a value."""
    header = {k: doc[k] for k in ENV_HEADER}
    try:
        return _open_envelope(doc, private, ENV_HKDF_INFO, env_aad(header),
                              max_ciphertext=ENV_PLAINTEXT_MAX_BYTES + 16)
    except PlantError:
        raise EnvRefused(400, "sealed_env_does_not_open") from None


def env_overlay_problem(env) -> str | None:
    """None when *env* is an overlay the room API takes. The answer never names a value."""
    if not isinstance(env, dict) or len(env) > ENV_MAX_NAMES:
        return "shape"
    size = 0
    for name, value in env.items():
        if not isinstance(name, str) or not ENV_NAME_RE.fullmatch(name):
            return "name"
        if name in ENV_RESERVED or name.startswith(ENV_RESERVED_PREFIXES):
            return "reserved"
        if not isinstance(value, str) or not _utf8(value) or "\0" in value:
            # A lone surrogate escape parses as JSON and cannot be sent on; NUL cannot be in an env.
            return "value"
        size += len(name) + len(value.encode("utf-8"))
    return "size" if size > ENV_MAX_BYTES_SET else None


class AcceptedEnv:
    """The overlay this boot put on one room incarnation: names and digests, never values."""

    __slots__ = ("version", "envelope_sha256", "ephemeral_public_b64", "names", "receipt")

    def __init__(self, version: int, envelope_sha256: str, ephemeral_public_b64: str, names: list[str],
                 receipt: dict | None):
        self.version, self.envelope_sha256, self.ephemeral_public_b64 = version, envelope_sha256, ephemeral_public_b64
        self.names, self.receipt = names, receipt


class SealedEnv:
    """What this boot accepted for each room's env overlay. Memory only; the key is the sealed secrets key.

    rooms maps a room id to (incarnation, AcceptedEnv). lock guards rooms. A
    write holds its room's stripe for the whole check, apply, sign and record,
    so two writes to one room never cross, and the clear of a room made again
    (reconcile) never lands between a write's apply and its record.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.rooms: dict[str, tuple[str, AcceptedEnv]] = {}
        self.stripes = [threading.Lock() for _ in range(ENV_APPLY_STRIPES)]
        self.swept_at = float("-inf")

    def stripe(self, room: str) -> threading.Lock:
        return self.stripes[int(sha(room.encode())[:8], 16) % ENV_APPLY_STRIPES]

    def held(self, room: str, incarnation: str) -> AcceptedEnv | None:
        """The room's entry for *incarnation*, else None. Caller holds the lock."""
        entry = self.rooms.get(room)
        return entry[1] if entry is not None and entry[0] == incarnation else None

    def forget(self, room: str) -> None:
        """Caller holds the lock."""
        self.rooms.pop(room, None)

    def retire(self, room: str) -> None:
        """A delete of the room passed this front; the room API dropped the overlay with the room."""
        with self.lock:
            self.forget(room)

    def sweep(self, incarnation_of, room_present, now: float) -> None:
        """Drop rooms that are gone (deleted, or reaped past this front). At most once a second. Caller holds the lock.

        A room made again under the same id keeps its entry until reconcile
        clears its overlay on the room API: dropping it here would leave the
        old overlay in force with nothing to say so.
        """
        if now - self.swept_at < SECRETS_SWEEP_SECONDS:
            return
        self.swept_at = now
        for room in list(self.rooms):
            if incarnation_of(room) is None or not room_present(room):
                self.forget(room)

    def stale(self, incarnation_of) -> list[str]:
        """Rooms whose overlay names an incarnation that is no longer the room's own."""
        with self.lock:
            return [room for room, (incarnation, _) in self.rooms.items() if incarnation_of(room) != incarnation]

    def listing(self, room: str, incarnation: str | None) -> dict:
        with self.lock:
            entry = self.held(room, incarnation) if incarnation else None
            if entry is None:
                return {"version": None, "envelope_sha256": None, "names": []}
            return {"version": entry.version, "envelope_sha256": entry.envelope_sha256, "names": list(entry.names)}


# ---------------------------------------------------------------- sealed commands (AB#417)

class ExecRefused(Exception):
    """A sealed exec refused before it ran. The code is short and never names the command."""

    def __init__(self, status: int, code: str, extra: dict | None = None):
        super().__init__(code)
        self.status, self.code, self.extra = status, code, extra or {}


def sealed_exec_wanted() -> bool:
    """ROOM_SEALED_EXEC=1. Unset or any other value: off."""
    return os.environ.get("ROOM_SEALED_EXEC") == "1"


def exec_header(binding_sha256: str, sandbox_id: str, room_create_receipt_sha256: str, issued_at: int,
                timeout_seconds: int, response_public_b64: str) -> dict:
    """The fields of a sealed exec that its AAD authenticates (all but the three envelope values).

    Relays read them (the timeout sizes their own waits) and cannot change
    them: any change fails the open.
    """
    return {"schema": EXEC_SCHEMA, "algorithm": EXEC_ALGORITHM, "binding_sha256": binding_sha256,
            "sandbox_id": sandbox_id, "room_create_receipt_sha256": room_create_receipt_sha256,
            "issued_at": issued_at, "timeout_seconds": timeout_seconds, "response_public_b64": response_public_b64}


def exec_aad(header: dict) -> bytes:
    return EXEC_AAD_LABEL + canonical(header)


def exec_response_header(header: dict, request_sha256: str) -> dict:
    """What the answer's AAD names: this boot, this room incarnation, this exact request and its answer key."""
    return {"schema": EXEC_RESPONSE_SCHEMA, "algorithm": EXEC_ALGORITHM, "binding_sha256": header["binding_sha256"],
            "sandbox_id": header["sandbox_id"], "room_create_receipt_sha256": header["room_create_receipt_sha256"],
            "request_sha256": request_sha256, "response_public_b64": header["response_public_b64"]}


def exec_response_aad(header: dict, request_sha256: str) -> bytes:
    return EXEC_RESPONSE_AAD_LABEL + canonical(exec_response_header(header, request_sha256))


def seal_exec_request(request: dict, recipient: X25519PublicKey, *, binding_sha256: str, sandbox_id: str,
                      room_create_receipt_sha256: str, issued_at: int, timeout_seconds: int,
                      response_public_b64: str) -> dict:
    """The customer's sealed exec (ctcli, tests). The guest only opens."""
    header = exec_header(binding_sha256, sandbox_id, room_create_receipt_sha256, issued_at, timeout_seconds,
                         response_public_b64)
    return {**header, **_seal_envelope(canonical(request), recipient, EXEC_HKDF_INFO, exec_aad(header))}


def open_exec_request(doc: dict, private: X25519PrivateKey) -> bytes:
    """Open a sealed exec. Raises ExecRefused, which never names the command."""
    header = {k: doc[k] for k in EXEC_HEADER}
    try:
        return _open_envelope(doc, private, EXEC_HKDF_INFO, exec_aad(header),
                              max_ciphertext=EXEC_PLAINTEXT_MAX_BYTES + 16)
    except PlantError:
        raise ExecRefused(400, "sealed_exec_does_not_open") from None


def seal_exec_response(plaintext: bytes, header: dict, request_sha256: str) -> dict:
    """The answer, sealed to the key the request names: only the client that made the request opens it."""
    recipient = X25519PublicKey.from_public_bytes(base64.b64decode(header["response_public_b64"], validate=True))
    sealed = _seal_envelope(plaintext, recipient, EXEC_RESPONSE_HKDF_INFO, exec_response_aad(header, request_sha256))
    return {"schema": EXEC_RESPONSE_SCHEMA, "request_sha256": request_sha256, **sealed}


def open_exec_response(doc: dict, response_private: X25519PrivateKey, request_doc: dict) -> bytes:
    """Open an answer of seal_exec_response (ctcli, tests). Raises PlantError."""
    header = {k: request_doc[k] for k in EXEC_HEADER}
    request_sha256 = sha(canonical(request_doc))
    if not isinstance(doc, dict) or doc.get("schema") != EXEC_RESPONSE_SCHEMA \
            or doc.get("request_sha256") != request_sha256:
        raise PlantError("ciphertext does not open")
    return _open_envelope(doc, response_private, EXEC_RESPONSE_HKDF_INFO, exec_response_aad(header, request_sha256),
                          max_ciphertext=1 << 31)


def _canonical_b64(value) -> bytes | None:
    """The bytes of a base64 string written the one way b64encode writes them, else None.

    A 32-byte key has 2 spare bits in its last character, so four strings decode to one key.
    """
    try:
        raw = base64.b64decode(value, validate=True)
    except (TypeError, ValueError):
        return None
    return raw if b64(raw) == value else None


def _replay_key(ephemeral_b64: str) -> str:
    """The replay table's name for an envelope: its ephemeral key's bytes, base64 as b64encode writes them."""
    raw = _canonical_b64(ephemeral_b64)
    if raw is None:
        raw = base64.b64decode(ephemeral_b64, validate=True)
    return b64(raw)


def _usable_x25519(raw_b64) -> bool:
    """32 bytes of base64 that make a shared key (low-order points do not)."""
    try:
        raw = base64.b64decode(raw_b64, validate=True)
        if len(raw) != 32 or b64(raw) != raw_b64:
            return False
        X25519PrivateKey.generate().exchange(X25519PublicKey.from_public_bytes(raw))
        return True
    except (TypeError, ValueError):
        return False


def _utf8(value) -> bool:
    """A string that encodes as UTF-8: a lone surrogate escape parses as JSON and does not."""
    try:
        value.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def _exec_request_problem(request) -> str | None:
    """None when the opened request has the room API's exec shape (the API checks the values).

    Every string must encode as UTF-8, or the front could not hash the command or send the
    request on after recording the envelope as run.
    """
    if not isinstance(request, dict) or "cmd" not in request or not set(request) <= EXEC_REQUEST_KEYS:
        return "fields"
    cmd = request["cmd"]
    if isinstance(cmd, str):
        if not cmd.strip():
            return "cmd"
    elif not (isinstance(cmd, list) and cmd and all(isinstance(p, str) and p for p in cmd)):
        return "cmd"
    env = request.get("env")
    if env is not None and not (isinstance(env, dict) and all(isinstance(k, str) and isinstance(v, str)
                                                              for k, v in env.items())):
        return "env"
    for key in ("stdin", "cwd", "user"):
        if request.get(key) is not None and not isinstance(request[key], str):
            return key
    # The types are checked above: every value here is a string or None.
    strings = [cmd] if isinstance(cmd, str) else list(cmd)
    strings += [request[k] for k in ("stdin", "cwd", "user") if request.get(k) is not None]
    strings += [x for kv in (env or {}).items() for x in kv]
    if not all(_utf8(x) for x in strings):
        return "encoding"
    return None


class SealedExec:
    """The per-boot sealed exec key and the ephemeral keys this boot ran. Memory only.

    rooms maps a room id to (incarnation, {ephemeral_public_b64: issued_at}).
    An envelope's ephemeral key is its identity: it is in the ECDH and the HKDF
    info, so a relay cannot change it without breaking the open. A room's
    entries go when a delete of it passes this front, when it is made again,
    or when its issued_at leaves the window; none of that lets an envelope run
    twice, because the window and the incarnation refuse it first.
    """

    def __init__(self):
        self.private = X25519PrivateKey.generate()
        self.public_b64 = b64(_raw_x25519(self.private.public_key()))
        self.lock = threading.Lock()
        self.rooms: dict[str, tuple[str, dict[str, int]]] = {}
        self.tracked = 0
        self.swept_at = float("-inf")
        self.latest = float("-inf")  # the highest time this boot has used

    def __repr__(self) -> str:
        return f"SealedExec(x25519_public_b64={self.public_b64})"

    def clock(self, now: float) -> float:
        """now, never below a time already used: a host that steps the guest clock back after
        an envelope's entry was dropped must not make that envelope fresh again."""
        with self.lock:
            self.latest = max(self.latest, now)
            return self.latest

    def binding_fields(self) -> dict:
        return {"sealed_exec": {"schema": EXEC_SCHEMA, "algorithm": EXEC_ALGORITHM,
                                "x25519_public_b64": self.public_b64}}

    def _prune(self, room: str, now: float) -> dict[str, int]:
        """The room's live entries; those whose issued_at left the window go. Caller holds the lock."""
        _, seen = self.rooms[room]
        stale = [eph for eph, at in seen.items() if at < now - EXEC_MAX_AGE_SECONDS]
        for eph in stale:
            del seen[eph]
        self.tracked -= len(stale)
        return seen

    def forget(self, room: str) -> None:
        """Drop the room's entries. Caller holds the lock."""
        held = self.rooms.pop(room, None)
        if held is not None:
            self.tracked -= len(held[1])

    def ran(self, room: str, incarnation: str, ephemeral: str) -> bool:
        """True when this envelope already ran in the room's incarnation. Caller holds the lock."""
        held = self.rooms.get(room)
        return held is not None and held[0] == incarnation and _replay_key(ephemeral) in held[1]

    def admit(self, room: str, incarnation: str, ephemeral: str, issued_at: int, now: float, incarnation_of) -> None:
        """Record the envelope as run, or raise ExecRefused. Caller holds the lock."""
        ephemeral = _replay_key(ephemeral)
        held = self.rooms.get(room)
        if held is None or held[0] != incarnation:
            self.forget(room)
            self.rooms[room] = (incarnation, {})
        seen = self._prune(room, now)
        if ephemeral in seen:
            raise ExecRefused(409, "sealed_exec_replayed")
        if len(seen) >= EXEC_MAX_PER_ROOM:
            raise ExecRefused(429, "sealed_exec_room_busy", {"retry_after_s": EXEC_MAX_AGE_SECONDS})
        if self.tracked >= EXEC_MAX_TRACKED:
            self.sweep(incarnation_of, now)
            if self.tracked >= EXEC_MAX_TRACKED:
                raise ExecRefused(503, "sealed_exec_full", {"retry_after_s": EXEC_MAX_AGE_SECONDS})
        seen[ephemeral] = issued_at
        self.tracked += 1

    def retire(self, room: str) -> None:
        """A delete of the room passed this front."""
        with self.lock:
            self.forget(room)

    def sweep(self, incarnation_of, now: float) -> None:
        """Drop rooms that are gone or made again, and entries out of the window. At most once a second."""
        if now - self.swept_at < SECRETS_SWEEP_SECONDS:
            return
        self.swept_at = now
        for room, (incarnation, _) in list(self.rooms.items()):
            if incarnation_of(room) != incarnation:
                self.forget(room)
            else:
                self._prune(room, now)


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


def write_escape_nonce(base_dir: str, window_id: str, nonce: str) -> str:
    """Write <base>/<window_id>/nonce (0400 root) and return its path. Touches no other window."""
    if not WINDOW_DIR_RE.fullmatch(window_id):
        raise OSError("window id is not a safe directory name")
    if os.path.islink(base_dir):
        raise OSError("nonce base directory is a symlink")
    os.makedirs(base_dir, mode=0o700, exist_ok=True)
    os.chmod(base_dir, 0o700)
    window_dir = os.path.join(base_dir, window_id)
    if os.path.islink(window_dir):
        raise OSError("window directory is a symlink")
    os.makedirs(window_dir, mode=0o700, exist_ok=True)
    os.chmod(window_dir, 0o700)
    path = os.path.join(window_dir, "nonce")
    if os.path.islink(path):
        raise OSError("nonce file is a symlink")
    _replace_private_file(window_dir, path, nonce.encode() + b"\n", 0o400)
    return path


def prune_escape_windows(base_dir: str, keep_window_id: str, now: float | None = None) -> None:
    """Remove window directories older than the keep time. Never raises: a plant must not fail on it.

    An ended room's file stays until this age, so the AB#677 grace needs no extra rule.
    Refuses a symlinked or non-directory base so prune cannot delete outside the nonce directory.
    """
    try:
        base_st = os.lstat(base_dir)
        if stat.S_ISLNK(base_st.st_mode) or not stat.S_ISDIR(base_st.st_mode):
            return
        cutoff = (time.time() if now is None else now) - escape_nonce_keep_seconds()
        for name in os.listdir(base_dir):
            if name == keep_window_id or not WINDOW_DIR_RE.fullmatch(name):
                continue
            entry = os.path.join(base_dir, name)
            try:
                st = os.lstat(entry)
                if not stat.S_ISDIR(st.st_mode) or st.st_mtime >= cutoff:
                    continue
                shutil.rmtree(entry)
            except OSError:
                continue
    except OSError:
        pass


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

    def __init__(self, hotel: str, store: str, miner: MinerHotel | None = None,
                 secrets: SealedSecrets | None = None, sealed_exec: SealedExec | None = None):
        self.miner = miner
        # A secrets or sealed exec key means something only under an SNP report: level 1 drops both below.
        self.secrets = secrets
        self.sealed_exec = sealed_exec
        # The env overlay (AB#414) opens with the secrets key: on with sealed secrets, off without.
        self.sealed_env = SealedEnv() if secrets is not None else None
        # Raw Ed25519 owner key on a dedicated sealed machine, else None (no gate).
        self.owner_key: bytes | None = None
        if tsm_provider() == "sev_guest":
            self._init_sealed(hotel, store)
        elif miner is not None:
            # A miner hotel's TLS key means something only under an SNP report.
            raise RuntimeError("miner mode needs a sealed guest (TSM provider sev_guest)")
        else:
            self.secrets = None
            self.sealed_exec = None
            self.sealed_env = None
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
        # Before any key or binding exists: a dedicated machine whose fw_cfg
        # owner HOST_DATA does not name raises here and never serves.
        owner = owner_tenancy(facts["host_data"])
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
            "tenancy": "shared",
        }
        if self.miner is not None:
            # TLS key, install key and pinned signers: REPORT_DATA commits to them.
            self.binding.update(self.miner.binding_fields())
        if self.secrets is not None:
            # One added key, only with the flag on: a binding without it is unchanged,
            # and verifiers hash the binding whole, so they check this one as before.
            self.binding.update(self.secrets.binding_fields())
        if self.sealed_exec is not None:
            # The same rule for the sealed exec key: one added key, only with its flag on.
            self.binding.update(self.sealed_exec.binding_fields())
        if owner is not None:
            # Enough to recompute HOST_DATA from published fields:
            # sha256(domain || manifest_sha256 || owner key) == host_data.
            self.owner_key, manifest = owner
            self.binding.update({"tenancy": "dedicated", "owner_ed25519_b64": b64(self.owner_key),
                                 "manifest_sha256": manifest.hex()})
        self.binding_sha256 = sha(canonical(self.binding))
        self.report = snp_report(bytes.fromhex(self.binding_sha256) + bytes(32))
        second = report_fields(self.report)
        if second["measurement"] != facts["measurement"]:
            raise RuntimeError("measurement changed between the two reports")
        if second["host_data"] != facts["host_data"]:
            raise RuntimeError("HOST_DATA changed between the two reports")
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

    def write_sealed_secret(self, room: str, doc) -> tuple[dict, dict | None]:
        """POST /v1/sandboxes/<room>/sealed-secrets. Returns (answer, receipt); raises SecretRefused.

        Checked in this order: the fields, this boot's binding, the room in
        the path, the name and version, the room's incarnation (its create
        receipt in this boot's chain, with no delete after it), the room's
        directory, the version against the last one accepted (the exact
        request that wrote the current value answers again with no change and
        the receipt of that write), a fresh ephemeral key, then the envelope
        opens with this boot's key. The receipt signs the envelope sha256 and
        never a digest of the value: secrets are often guessable.
        """
        secrets = self.secrets
        if secrets is None:
            raise SecretRefused(403, "sealed_secrets_disabled")
        if not isinstance(doc, dict) or set(doc) != SECRETS_FIELDS:
            raise SecretRefused(400, "sealed_secret_fields_invalid")
        if not all(isinstance(doc[k], str) and doc[k].isascii() for k in SECRETS_ENVELOPE):
            # Base64 is ASCII. A lone surrogate escape parses as JSON but cannot be hashed below;
            # every other string field must equal an ASCII value or match an ASCII pattern.
            raise SecretRefused(400, "sealed_secret_fields_invalid")
        if doc["schema"] != SECRETS_SCHEMA or doc["algorithm"] != SECRETS_ALGORITHM:
            raise SecretRefused(400, "sealed_secret_algorithm_unsupported")
        if doc["binding_sha256"] != self.binding_sha256:
            # Sealed for another boot or guest: the client fetches the attestation again and reseals.
            raise SecretRefused(409, "sealed_secret_wrong_binding")
        if doc["sandbox_id"] != room or not SECRETS_ROOM_RE.fullmatch(room):
            raise SecretRefused(400, "sealed_secret_wrong_room")
        name, version, incarnation = doc["name"], doc["version"], doc["room_create_receipt_sha256"]
        if not isinstance(name, str) or not SECRET_NAME_RE.fullmatch(name):
            raise SecretRefused(400, "sealed_secret_name_invalid")
        if type(version) is not int or not 1 <= version <= SECRET_VERSION_MAX:
            raise SecretRefused(400, "sealed_secret_version_invalid")
        if not isinstance(incarnation, str) or not KEY_SHA256_RE.fullmatch(incarnation):
            raise SecretRefused(400, "sealed_secret_incarnation_invalid")

        def check_incarnation() -> None:
            current = self.room_incarnation(room)
            if current is None:
                # No create receipt for the room in this boot's chain, or a delete after it.
                raise SecretRefused(404, "sealed_secret_room_not_found")
            if current != incarnation:
                # Sealed for an earlier room under this id: read its create receipt again and reseal.
                raise SecretRefused(409, "sealed_secret_wrong_incarnation")

        check_incarnation()
        envelope_sha256 = sha(canonical(doc))
        path = f"{SECRETS_IN_ROOM}/{name}"

        def answer(status: str) -> dict:
            return {"sandbox_id": room, "room_create_receipt_sha256": incarnation, "name": name, "version": version,
                    "envelope_sha256": envelope_sha256, "path": path, "status": status}

        def check_order() -> AcceptedSecret | None:
            """The entry when this exact request already wrote the value now in place. Caller holds the lock."""
            check_incarnation()  # deleted or made again while this request waited
            accepted = secrets.accepted(room, incarnation)
            held = accepted.get(name)
            if held is not None:
                if (held.version, held.envelope_sha256) == (version, envelope_sha256) \
                        and _secret_file_present(dir_fd, name):
                    return held
                if version <= held.version:
                    raise SecretRefused(409, "sealed_secret_replayed")
            if any(e.ephemeral_public_b64 == doc["ephemeral_public_b64"] for e in accepted.values()):
                # Every seal makes a new ephemeral key. A reused one is a broken client
                # (a constant key in its code opens every envelope it made): refuse it.
                raise SecretRefused(400, "sealed_secret_ephemeral_reused")
            if held is None:
                if not _secret_file_present(dir_fd, name) and _secret_file_count(dir_fd) >= SECRETS_MAX_PER_ROOM:
                    raise SecretRefused(409, "sealed_secrets_room_full")
                if secrets.tracked >= SECRETS_MAX_TRACKED:
                    secrets.sweep(self.room_incarnation, time.monotonic())
                    if secrets.tracked >= SECRETS_MAX_TRACKED:
                        raise SecretRefused(503, "sealed_secrets_full")
            return None

        dir_fd = secrets.room_dir(room)
        try:
            with secrets.lock:
                held = check_order()
                if held is not None:
                    return answer("unchanged"), held.receipt
            value = open_secret(doc, secrets.private)
            with secrets.lock:
                # A newer write, a delete or a re-create may have landed while this one opened.
                held = check_order()
                if held is not None:
                    return answer("unchanged"), held.receipt
                try:
                    _write_secret_file(dir_fd, name, value)
                except FileNotFoundError:
                    # The directory was removed (the room is going): nothing was written.
                    raise SecretRefused(404, "sealed_secret_room_not_found") from None
                except OSError:
                    traceback.print_exc()
                    raise SecretRefused(500, "sealed_secret_write_failed") from None
                finally:
                    value = None
                # Signed under the lock, so an exact retry finds this write's receipt with its entry.
                try:
                    receipt = self.sign({
                        "action": SECRETS_ACTION,
                        "target": f"POST /v1/sandboxes/{room}/sealed-secrets",
                        "sandbox_id": room,
                        "room_create_receipt_sha256": incarnation,
                        "secret_name": name,
                        "secret_version": version,
                        "envelope_sha256": envelope_sha256,
                        "path": path,
                        "status": 200,
                    })
                except Exception:  # noqa: BLE001 the file is written: answer, and say the receipt is missing
                    traceback.print_exc()
                    receipt = None
                secrets.record(room, incarnation, name,
                               AcceptedSecret(version, envelope_sha256, doc["ephemeral_public_b64"], receipt))
        finally:
            os.close(dir_fd)
        return answer("written"), receipt

    def write_sealed_env(self, room: str, doc, apply) -> tuple[dict, dict | None]:
        """POST /v1/sandboxes/<room>/sealed-env. Returns (answer, receipt); raises EnvRefused.

        apply(env) puts the overlay on the room API and returns (status, error
        code or None). Checked in this order: the fields, this boot's binding,
        the room, the version and incarnation formats, the room's current
        incarnation, the version against the last one accepted (the exact
        request that set the current overlay answers again with no change and
        its receipt), a fresh ephemeral key, then the envelope opens with this
        boot's secrets key to an overlay the room API takes. Nothing is
        recorded unless the room API took it, so a client retries the same
        envelope after any failure; the overlay is replaced whole, so a retry
        of one that did land changes nothing.
        """
        box, secrets = self.sealed_env, self.secrets
        if box is None or secrets is None:
            raise EnvRefused(403, "sealed_env_disabled")
        if not isinstance(doc, dict) or set(doc) != ENV_FIELDS:
            raise EnvRefused(400, "sealed_env_fields_invalid")
        if not all(isinstance(doc[k], str) and doc[k].isascii() and _canonical_b64(doc[k]) is not None
                   for k in SECRETS_ENVELOPE):
            # Base64 written one way only: one envelope has one sha256 and one ephemeral key.
            raise EnvRefused(400, "sealed_env_fields_invalid")
        if doc["schema"] != ENV_SCHEMA or doc["algorithm"] != ENV_ALGORITHM:
            raise EnvRefused(400, "sealed_env_algorithm_unsupported")
        if doc["binding_sha256"] != self.binding_sha256:
            raise EnvRefused(409, "sealed_env_wrong_binding")
        if doc["sandbox_id"] != room or not SECRETS_ROOM_RE.fullmatch(room):
            raise EnvRefused(400, "sealed_env_wrong_room")
        version, incarnation = doc["version"], doc["room_create_receipt_sha256"]
        if type(version) is not int or not 1 <= version <= SECRET_VERSION_MAX:
            raise EnvRefused(400, "sealed_env_version_invalid")
        if not isinstance(incarnation, str) or not KEY_SHA256_RE.fullmatch(incarnation):
            raise EnvRefused(400, "sealed_env_incarnation_invalid")

        def check_incarnation() -> None:
            current = self.room_incarnation(room)
            if current is None:
                raise EnvRefused(404, "sealed_env_room_not_found")
            if current != incarnation:
                raise EnvRefused(409, "sealed_env_wrong_incarnation")

        check_incarnation()
        envelope_sha256 = sha(canonical(doc))

        def answer(status: str, names: list[str]) -> dict:
            return {"sandbox_id": room, "room_create_receipt_sha256": incarnation, "version": version,
                    "envelope_sha256": envelope_sha256, "names": names, "status": status}

        def applied(env: dict) -> None:
            status, code = apply(env)
            if 200 <= status < 300:
                return
            if status == 501 or (status == 404 and code == "route_not_found"):
                # A room API from before AB#414 has no route: nothing was set.
                raise EnvRefused(501, "sealed_env_unsupported")
            if status == 404:
                raise EnvRefused(404, "sealed_env_room_not_found")
            if status == 409:
                raise EnvRefused(409, "sealed_env_room_not_ready")
            raise EnvRefused(502, "sealed_env_apply_failed")

        with box.stripe(room):
            with box.lock:
                check_incarnation()
                held = box.held(room, incarnation)
                if held is not None:
                    if (held.version, held.envelope_sha256) == (version, envelope_sha256):
                        return answer("unchanged", list(held.names)), held.receipt
                    if version <= held.version:
                        raise EnvRefused(409, "sealed_env_replayed")
                    if held.ephemeral_public_b64 == doc["ephemeral_public_b64"]:
                        raise EnvRefused(400, "sealed_env_ephemeral_reused")
                elif room not in box.rooms and len(box.rooms) >= ENV_MAX_TRACKED:
                    box.sweep(self.room_incarnation, lambda r: _is_dir(os.path.join(secrets.root, r)),
                              time.monotonic())
                    if len(box.rooms) >= ENV_MAX_TRACKED:
                        raise EnvRefused(503, "sealed_env_full")
            opened = open_env(doc, secrets.private)
            try:
                request = json.loads(opened)
            except (ValueError, RecursionError):
                request = None
            opened = None
            env = request.get("env") if isinstance(request, dict) and set(request) == {"env"} else None
            request = None
            if env_overlay_problem(env) is not None:
                raise EnvRefused(400, "sealed_env_request_invalid")
            names = sorted(env)
            try:
                applied(env)
            finally:
                env = None
            with box.lock:
                refusal = None
                try:
                    check_incarnation()  # deleted or made again while the API set it
                except EnvRefused as exc:
                    refusal = exc
                if refusal is None:
                    # Signed under the lock, so an exact retry finds this write's receipt with its entry.
                    try:
                        receipt = self.sign({
                            "action": ENV_ACTION,
                            "target": f"POST /v1/sandboxes/{room}/sealed-env",
                            "sandbox_id": room,
                            "room_create_receipt_sha256": incarnation,
                            "env_version": version,
                            "env_names": names,
                            "envelope_sha256": envelope_sha256,
                            "status": 200,
                        })
                    except Exception:  # noqa: BLE001 the overlay is set: answer, and say the receipt is missing
                        traceback.print_exc()
                        receipt = None
                    box.rooms[room] = (incarnation, AcceptedEnv(version, envelope_sha256,
                                                                doc["ephemeral_public_b64"], names, receipt))
            if refusal is not None:
                # The overlay may now sit on a room made again under this id: take it off (still
                # under the room's stripe, so no newer write to that room lands in between).
                try:
                    apply({})
                except Exception:  # noqa: BLE001 the refusal is the answer either way
                    traceback.print_exc()
                raise refusal
        return answer("set", names), receipt

    def reconcile_sealed_env(self, apply_for) -> None:
        """After a create: clear the overlay of each room whose incarnation moved under it.

        A create answered again for the same Idempotency-Key signs a new
        create receipt for a room the API kept, overlay and all. The front's
        entry names the old incarnation, so it must not stay in force unseen.
        apply_for(room) returns the apply of sealed-env for that room.
        """
        box = self.sealed_env
        if box is None:
            return
        for room in box.stale(self.room_incarnation):
            with box.stripe(room):
                with box.lock:
                    entry = box.rooms.get(room)
                    current = self.room_incarnation(room)
                    if entry is None or current == entry[0]:
                        continue
                    box.forget(room)
                if current is None:
                    continue  # deleted: the API dropped the overlay with the room
                try:
                    status, _code = apply_for(room)({})
                except Exception:  # noqa: BLE001 log and go on: the next room still needs its clear
                    traceback.print_exc()
                    continue
                if not 200 <= status < 300 and status != 404:
                    print(f"room-receipts: sealed env clear of {room} answered {status}", file=sys.stderr, flush=True)

    def open_sealed_exec(self, room: str, doc, now: float | None = None) -> tuple[dict, dict]:
        """POST /v1/sandboxes/<room>/sealed-exec, up to the run. Returns (header, request); raises ExecRefused.

        Checked in this order: the fields, this boot's binding, the room in
        the path, the incarnation, timeout and issued_at formats, freshness,
        the answer key, the room's current incarnation, a replay, then the
        envelope opens with this boot's key and its request has the room
        API's exec shape. Then, under the lock, the envelope is recorded as
        run: a second copy (a replay, or two racing) is refused.
        """
        box = self.sealed_exec
        if box is None:
            raise ExecRefused(403, "sealed_exec_disabled")
        if not isinstance(doc, dict) or set(doc) != EXEC_FIELDS:
            raise ExecRefused(400, "sealed_exec_fields_invalid")
        if not all(isinstance(doc[k], str) and doc[k].isascii() for k in EXEC_STRING_FIELDS):
            # Base64 is ASCII; a lone surrogate escape would parse and then fail the hash below.
            raise ExecRefused(400, "sealed_exec_fields_invalid")
        if any(_canonical_b64(doc[k]) is None for k in SECRETS_ENVELOPE):
            # One spelling per value: a relay must not make one envelope look like another
            # (the ephemeral key names the envelope in the replay table).
            raise ExecRefused(400, "sealed_exec_fields_invalid")
        if doc["schema"] != EXEC_SCHEMA or doc["algorithm"] != EXEC_ALGORITHM:
            raise ExecRefused(400, "sealed_exec_algorithm_unsupported")
        if doc["binding_sha256"] != self.binding_sha256:
            # Sealed for another boot or guest: the client fetches the evidence again and reseals.
            raise ExecRefused(409, "sealed_exec_wrong_binding")
        if doc["sandbox_id"] != room or not SECRETS_ROOM_RE.fullmatch(room):
            raise ExecRefused(400, "sealed_exec_wrong_room")
        incarnation, timeout, issued = doc["room_create_receipt_sha256"], doc["timeout_seconds"], doc["issued_at"]
        if not isinstance(incarnation, str) or not KEY_SHA256_RE.fullmatch(incarnation):
            raise ExecRefused(400, "sealed_exec_incarnation_invalid")
        if type(timeout) is not int or timeout < 1:
            raise ExecRefused(400, "sealed_exec_timeout_invalid")
        if timeout > EXEC_TIMEOUT_MAX:
            raise ExecRefused(400, "sealed_exec_timeout_too_long")
        if type(issued) is not int or not 0 <= issued <= SECRET_VERSION_MAX:
            raise ExecRefused(400, "sealed_exec_issued_at_invalid")
        now = box.clock(time.time() if now is None else now)
        if not now - EXEC_MAX_AGE_SECONDS <= issued <= now + EXEC_FUTURE_SKEW_SECONDS:
            # The guest's clock is not secret, and naming it lets the client see its own skew.
            raise ExecRefused(409, "sealed_exec_not_fresh", {"guest_time": int(now)})
        if not _usable_x25519(doc["response_public_b64"]):
            raise ExecRefused(400, "sealed_exec_response_key_invalid")
        ephemeral = doc["ephemeral_public_b64"]

        def check_incarnation() -> None:
            current = self.room_incarnation(room)
            if current is None:
                raise ExecRefused(404, "sealed_exec_room_not_found")
            if current != incarnation:
                raise ExecRefused(409, "sealed_exec_wrong_incarnation")

        check_incarnation()
        with box.lock:
            if box.ran(room, incarnation, ephemeral):
                raise ExecRefused(409, "sealed_exec_replayed")
        opened = open_exec_request(doc, box.private)
        try:
            request = json.loads(opened)
        except (ValueError, RecursionError):  # RecursionError: nesting past the parser's depth
            request = None
        opened = None
        if _exec_request_problem(request) is not None:
            raise ExecRefused(400, "sealed_exec_request_invalid")
        with box.lock:
            check_incarnation()  # deleted or made again while this one opened
            box.admit(room, incarnation, ephemeral, issued, now, self.room_incarnation)
        return {k: doc[k] for k in EXEC_HEADER}, request

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
        # Room id -> receipt_sha256 of its last successful create receipt, until a
        # successful delete of the room is signed (sealed secrets bind to it).
        self.incarnations: dict[str, str] = {}
        # Serial rooms (all guarded by self.lock). in_flight counts the authorized requests between enter and
        # leave; busy is the per-room token (taken without waiting, so nothing queues and nothing can deadlock),
        # always a subset of the in_flight keys; serial holds the rooms whose create was signed serial; broken the
        # rooms that lost or never signed an action. Marks go when a 2xx delete is signed.
        self.in_flight: dict[str, int] = {}
        self.busy: set[str] = set()
        self.serial: set[str] = set()
        self.broken: set[str] = set()
        # The flag of a serial create needs that nothing ran in the room before the create was signed. The
        # in-flight count sees a request still running; touched sees one that finished without a receipt (an
        # unsigned write, or a request the API refused): a non-read request for an id with no create receipt is
        # recorded at enter and again at leave when a create is pending at that moment, so any request whose
        # life overlapped the time between a create being sent and its receipt being signed is in it.
        # creates_in_flight counts the creates forwarded and not yet signed; when it returns to zero touched is
        # cleared, since a request that ended before any create was pending cannot have run in a room whose
        # create was not yet sent. overflow withholds every flag while touched is full.
        self.creates_in_flight = 0
        self.touched: set[str] = set()
        self.overflow = False
        # A bulk delete by label names no room, so it cannot be matched to a pending create. One that is in
        # flight at any moment while a create is pending withholds every flag (it sets overflow, at both ends).
        self.bulk_in_flight = 0
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

    def room_incarnation(self, room: str) -> str | None:
        """receipt_sha256 of the room's last successful create receipt, or None once a delete of it is signed."""
        with self.lock:
            return self.incarnations.get(room)

    def enter(self, room: str, kind: str) -> tuple[Turn | None, tuple[int, str, str] | None]:
        """Admit one authorized request for *room*: (turn, None), or (None, (status, code, message)).

        One locked step checks the room's marks, takes the token when the room needs one and counts the
        request. A busy room is refused at once, never waited on.
        """
        with self.lock:
            token = False
            if room in self.broken:
                if kind != "delete":
                    return None, (409, "room_broken", "this room lost an answer; only a delete is accepted")
                token = True
            elif room in self.serial:
                if kind in ("signed", "delete"):
                    token = True
                elif kind != "read":
                    return None, (409, "room_serial_unsigned", "a serial room accepts signed requests and reads only")
            if token and room in self.busy:
                return None, (409, "room_busy", "this room is running another request")
            nonread = kind not in ("read", "record_read")
            if nonread:
                self._touch(room)
            if token:
                self.busy.add(room)
            self.in_flight[room] = self.in_flight.get(room, 0) + 1
            return Turn(room, token, len(self.by_room.get(room, [])), room in self.serial, nonread), None

    def _touch(self, room: str) -> None:
        """Remember a non-read request for an id with no create receipt while a create is pending. Caller holds self.lock."""
        if not self.creates_in_flight or room in self.by_room or room in self.touched:
            return
        if len(self.touched) >= TOUCHED_CAP:
            self.overflow = True  # a further id has to be remembered and does not fit
        else:
            self.touched.add(room)

    def begin_create(self) -> None:
        with self.lock:
            self.creates_in_flight += 1
            if self.bulk_in_flight:
                self.overflow = True

    def begin_bulk(self) -> None:
        with self.lock:
            self.bulk_in_flight += 1
            if self.creates_in_flight:
                self.overflow = True

    def end_bulk(self) -> None:
        with self.lock:
            self.bulk_in_flight = max(0, self.bulk_in_flight - 1)
            if self.creates_in_flight:
                self.overflow = True

    def end_create(self) -> None:
        with self.lock:
            self.creates_in_flight = max(0, self.creates_in_flight - 1)
            if not self.creates_in_flight:
                self.touched.clear()
                self.overflow = False

    def leave(self, turn: Turn) -> None:
        """End a turn: break a serial room that lost an answer or left an action unsigned, free the token, lower the count."""
        with self.lock:
            room = turn.room
            if turn.nonread:
                self._touch(room)  # it may have run while a create was pending, though it entered before
            if turn.token and room in self.serial:
                signed = len(self.by_room.get(room, [])) > turn.receipts_before
                if turn.lost or (turn.called and not signed):
                    self.broken.add(room)
            if turn.token:
                self.busy.discard(room)
            left = self.in_flight.get(room, 0) - 1
            if left > 0:
                self.in_flight[room] = left
            else:
                self.in_flight.pop(room, None)

    def sign(self, fields: dict, create: dict | None = None) -> dict:
        with self.lock:
            return self._sign_locked(fields, create)

    def _sign_locked(self, fields: dict, create: dict | None = None) -> dict:
        """Sign and append one receipt. The caller holds self.lock.

        *create* is what the create request asked for. A 2xx create that asked for a serial room is signed
        serial only as the room's receipt 1 with no request in flight for it, so no request ran in the room
        before the flag.
        """
        statement = {"schema": self.receipt_schema, "binding_sha256": self.binding_sha256, "hotel": self.hotel,
                     "operation_id": str(uuid.uuid4()), "sequence": len(self.chain) + 1,
                     "previous_receipt_sha256": self.head, "issued_at": int(time.time()), **fields}
        named = fields.get("sandbox_id")
        if isinstance(named, str) and named:
            # A room's own count and link, taken after **fields so no statement field can set them. A
            # list that holds every number from 1 shows that no receipt of that room is missing from it.
            earlier = self.by_room.get(named, [])
            statement["room_sequence"] = len(earlier) + 1
            statement["room_previous_receipt_sha256"] = self.chain[earlier[-1]]["receipt_sha256"] if earlier else None
        status = statement.get("status")
        ok = isinstance(status, int) and 200 <= status < 300
        if create and ok and statement.get("action") == "create" and isinstance(named, str) and named:
            if create.get("serial") and not self.in_flight.get(named) and named not in self.by_room \
                    and named not in self.touched and not self.overflow:
                statement["serial"] = True
        receipt = {"statement": statement, "signature_b64": b64(self.key.sign(canonical(statement))),
                   "receipt_sha256": sha(canonical(statement))}
        self.head = receipt["receipt_sha256"]
        self.chain.append(receipt)
        room = statement.get("sandbox_id")
        if room:
            self.by_room.setdefault(room, []).append(len(self.chain) - 1)
            action = statement.get("action")
            if ok:
                # The same rule as create_receipt(): the last successful create names the room.
                if action == "create":
                    self.incarnations[room] = receipt["receipt_sha256"]
                    if statement.get("serial"):
                        self.serial.add(room)
                elif action == "delete":
                    self.incarnations.pop(room, None)
                    self.serial.discard(room)
                    self.broken.discard(room)
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
    ("PUT", re.compile("^" + ROOM + r"/files$"), "file_put"),
    ("GET", re.compile("^" + ROOM + r"/files$"), "file_get"),
    # AB#385 slice 2. Heartbeat, lifetime and PATCH /v1/sandboxes/{id} (also a heartbeat) stay
    # unsigned: the broker sends them as keepalives, and each receipt stays on the chain.
    ("PUT", re.compile("^" + ROOM + r"/tar$"), "tar_put"),
    ("GET", re.compile("^" + ROOM + r"/tar$"), "tar_get"),
    ("DELETE", re.compile("^" + ROOM + r"/processes/[^/]+$"), "process_stop"),
    ("POST", re.compile("^" + ROOM + r"/snapshot$"), "snapshot"),
    ("POST", re.compile("^" + ROOM + r"/freeze$"), "freeze"),
    ("POST", re.compile("^" + ROOM + r"/thaw$"), "thaw"),
    ("POST", re.compile("^" + ROOM + r"/expose$"), "expose"),
]
# Archive bodies are never JSON. Not parsing them keeps a large plain tar from
# being decoded into a str on every pass.
OPAQUE_BODY = {"tar_put", "tar_get"}
# Dedicated machine: the requests that start code need the owner signature.
# A build runs Dockerfile steps in the guest, and the broker sends builds to
# every hotel, so it is gated like a create.
OWNER_GATED = [  # (method, path pattern, action in the signed message)
    ("POST", re.compile(r"^/v1/sandboxes$"), "create"),
    ("POST", re.compile(r"^/v1/images/build$"), "build"),
]
# Serial rooms. A create that carries SERIAL_LABEL = "1" makes a room that runs one signed request at a
# time, so the order of its receipts is the order things ran. The labels are ours: the API refuses them
# from customers.
SERIAL_LABEL = "cathedral_serial"
POOL_LABEL = "cathedral_pool"
ROOM_PATH = re.compile(r"^/v1/sandboxes/(?P<id>[^/]+)(?:/|$)")
# What a serial room lets through unsigned: requests that read the room and change nothing. A route on no
# list here is refused, so a route added later is closed until it is listed. A terminal's output is not a
# read: reading it clears its buffer.
READS = [  # (method, path pattern)
    ("GET", re.compile("^" + ROOM + r"$")),
    ("POST", re.compile("^" + ROOM + r"/wait$")),
    ("GET", re.compile("^" + ROOM + r"/logs$")),
    ("GET", re.compile("^" + ROOM + r"/stat$")),
    ("GET", re.compile("^" + ROOM + r"/tar$")),
    ("GET", re.compile("^" + ROOM + r"/desktop$")),
    ("GET", re.compile("^" + ROOM + r"/terminals$")),
    ("GET", re.compile("^" + ROOM + r"/processes/[^/]+/logs$")),
    ("GET", re.compile("^" + ROOM + r"/sealed-secrets$")),
    ("GET", re.compile("^" + ROOM + r"/sealed-env$")),
    ("GET", re.compile("^" + ROOM + r"/entries$")),
]
# Room ids the front forwarded a non-read request for while it held no create receipt for them and a create
# was in flight (see Ledger.touched). Past this many, no create is flagged until the creates end.
TOUCHED_CAP = 4096
HEX64 = re.compile(r"[0-9a-fA-F]{128}")
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization",
       "proxy-authenticate", "content-length", "host"}


def room_of(path: str) -> str | None:
    """The room id a request path names, or None for a path with no room.

    *path* must be the API's path form (``urlparse(...).path``), which drops a
    ``;params`` suffix. ``urlsplit`` keeps that suffix in the path and would
    make ``sbx_1;alias`` look like another room (AB#384).
    """
    m = ROOM_PATH.match(path)
    return m["id"] if m else None


def route_kind(method: str, path: str) -> str:
    """How the gate sees a request that names a room: delete, signed (a row of SIGNED), read or other."""
    if method == "DELETE" and re.match("^" + ROOM + "$", path):
        return "delete"
    if any(meth == method and pat.match(path) for meth, pat, _action in SIGNED):
        return "signed"
    if any(meth == method and pat.match(path) for meth, pat in READS):
        return "read"
    return "other"


def api_request_path(raw_target: str) -> tuple[str, str]:
    """Path and query as the room API sees them (urlparse drops ``;params``).

    Returns ``(path, forward)`` where *forward* is path plus ``?query`` when
    present — the spelling passed to the upstream API.
    """
    parsed = urlparse(raw_target)
    path = parsed.path
    forward = path + (f"?{parsed.query}" if parsed.query else "")
    return path, forward


class Turn:
    """One authorized request between Ledger.enter and Ledger.leave."""

    __slots__ = ("room", "token", "receipts_before", "serial", "nonread", "called", "lost")

    def __init__(self, room: str, token: bool, receipts_before: int, serial: bool = False,
                 nonread: bool = False) -> None:
        self.room, self.token, self.receipts_before, self.serial = room, token, receipts_before, serial
        self.nonread = nonread  # not a read: it may change the room
        self.called = False  # a request went to the API
        self.lost = False  # the API gave no answer


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

    turn: Turn | None = None
    create_open = False  # a create was forwarded and its receipt is not yet signed
    bulk_open = False  # a bulk delete was forwarded and has not been answered

    def handle_one_request(self):
        self.turn = None
        self.create_open = False
        self.bulk_open = False
        try:
            super().handle_one_request()
        finally:
            self.release_turn()

    def release_turn(self) -> None:
        """Give back the request's count and token, and its place among the creates in flight. Safe to call twice."""
        turn, self.turn = self.turn, None
        if turn is not None:
            self.server.ledger.leave(turn)
        if self.create_open:
            self.create_open = False
            self.server.ledger.end_create()
        if self.bulk_open:
            self.bulk_open = False
            self.server.ledger.end_bulk()

    # -- helpers
    def reply(self, status: int, body: bytes, headers: dict | None = None, ctype="application/json"):
        # The turn ends after the receipt is signed and before the answer is written, so a caller that
        # sends its next request on seeing this answer finds the room free.
        self.release_turn()
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

    def upstream(self, port: int, body: bytes | None, *, method: str | None = None, path: str | None = None,
                 extra: dict | None = None, timeout: float = 1800):
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        if extra:
            headers = {k: v for k, v in headers.items() if k.lower() not in {e.lower() for e in extra}}
            headers.update(extra)
        if getattr(self.server.ledger, "miner", None) is not None:
            # The caller's key was checked against the installed key before this
            # call. The API knows only the guest-internal key.
            headers = {k: v for k, v in headers.items() if k.lower() != "authorization"}
            headers["Authorization"] = "Bearer " + self.server.api_key.decode()
        method, path = method or self.command, path or self.path
        if self.turn is not None:
            self.turn.called = True
        if method not in ("GET", "HEAD") or (self.turn is not None and self.turn.serial):
            # A write may have run before its answer was lost, so it is never
            # sent twice: a fresh connection (no stale keep-alive) and no
            # retry. A lost answer is a 502, and the receipt records it. On a serial room every
            # request is sent once, so one receipt stands for exactly one request at the API.
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
            try:
                c.request(method, path, body=body, headers=headers)
                r = c.getresponse()
                return r.status, r.getheaders(), r.read()
            except (http.client.HTTPException, OSError):
                if self.turn is not None:
                    self.turn.lost = True
                return 502, [], b'{"error":{"code":"hotel_api_no_answer","message":"the API did not answer; the request may have run"}}'
            finally:
                c.close()
        for attempt in (1, 2):
            c = UP.conn(port)
            try:
                c.request(method, path, body=body, headers=headers)
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
        # Same path form as cathedral/sandbox_server.dispatch (urlparse): a
        # ";alias" suffix must not bypass the serial gate or mis-name a receipt.
        path, forward_path = api_request_path(self.path)
        ledger: Ledger = self.server.ledger
        if self.command == "GET" and path == "/room/attestation":
            return self.reply(200, canonical(ledger.attestation()))
        if path == "/room/attest":
            return self.handle_attest(ledger, body)
        if self.command == "GET" and path == "/room/receipts":
            if not self.authorized():
                return self.reply(401, b'{"error":"unauthorized"}')
            q = parse_qs(urlparse(self.path).query)
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
            # count and room_head are read with the page, so a reader can hold the list against them.
            return self.reply(200, canonical({"sandbox_id": m["id"], "binding_sha256": ledger.binding_sha256,
                                              "count": len(page),
                                              "room_head": page[-1]["receipt_sha256"] if page else None,
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
        room = room_of(path)
        if room and self.authorized():
            # Callers without the key are not counted: they never hold a token, and the API refuses them.
            self.turn, refusal = ledger.enter(room, route_kind(self.command, path))
            if refusal is not None:
                status, code, message = refusal
                return self.reply(status, canonical({"error": {"code": code, "message": message}}))
        m = SECRETS_ROUTE.match(path)
        if m:
            # Never passed to the API: the envelope stops here, opened or refused.
            return self.handle_sealed_secrets(ledger, m["id"], body)
        m = EXEC_ROUTE.match(path)
        if m:
            # Opened here; only the plaintext exec goes on, inside the guest, to the room API.
            return self.handle_sealed_exec(ledger, m["id"], body)
        m = ENV_ROUTE.match(path)
        if m:
            # Opened here; only the opened overlay goes on, inside the guest, to the room API.
            return self.handle_sealed_env(ledger, m["id"], body)
        if any(route.match(p) for route in INTERNAL_API_ROUTES for p in (path, unquote(path))):
            # The room API's sealed exec route runs an exec that leaves no history or log, and
            # its env-sealed route sets a room's env from an envelope this front opened; neither
            # is a signed route here: no caller may reach them. Matched as the API matches
            # them (urlparse drops a ";params" suffix, then the raw path), and decoded too; any
            # other path, flag on or off, passes as before.
            return self.reply(404, b'{"error":{"code":"route_not_found","message":"no such route"}}')
        # Matched on the path the API routes on (urlparse drops a ";params" suffix), so no
        # spelling of a signed route reaches the API unsigned.
        path = api_path
        action = next((a for meth, pat, a in SIGNED if meth == self.command and pat.match(path)), None)
        if action and body and action not in OPAQUE_BODY:
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
        refusal, owner_fields = self.owner_gate(ledger, body)
        if refusal is None and action == "create" and self.asks_for_other_than_one_room(body):
            # One create, one room, so each room's list holds its own create. Refused unsent and unsigned,
            # as the surrogate refusal above is.
            return self.reply(400, b'{"error":{"code":"create_count_refused","message":"a create makes one room"}}')
        create_ask = None
        if refusal is None and action == "create":
            problem, create_ask = self.reserved_label_check(body)
            if problem is not None:
                return self.reply(400, canonical({"error": {"code": problem[0], "message": problem[1]}}))
        if refusal is not None:
            status, headers, out = 403, [], refusal
        else:
            if action == "create" and self.authorized():
                ledger.begin_create()
                self.create_open = True
            elif action == "bulk_delete" and self.authorized():
                ledger.begin_bulk()
                self.bulk_open = True
            # Forward the canonical path (no ";params") so gate, receipt and API agree.
            status, headers, out = self.upstream(
                self.server.api_port, body, path=forward_path,
                **({"timeout": plain_exec_wait(body)} if action == "exec" else {}))
        extra = {}
        if action and self.authorized():
            try:
                extra["X-Room-Receipt"] = base64.urlsafe_b64encode(canonical(ledger.sign(
                    {**self.fields(action, path, body, status, out, target_path=forward_path), **owner_fields},
                    **({"create": create_ask} if create_ask else {})))).decode()
            except Exception as exc:  # noqa: BLE001 the action ran: answer, and say the receipt is missing
                traceback.print_exc()
                extra["X-Room-Receipt-Error"] = type(exc).__name__
            if action == "create" and 200 <= status < 300 and ledger.sealed_env is not None:
                # A create answered again for a room the API kept moves its incarnation: an
                # overlay set under the old one comes off before the room is used again.
                ledger.reconcile_sealed_env(self.env_apply)
            deleted = re.match("^" + ROOM + "$", path) if action == "delete" and 200 <= status < 300 else None
            if deleted and ledger.secrets is not None:
                # After the receipt, which ends the room's incarnation: no write lands from here on.
                ledger.secrets.retire(deleted["id"])
            if deleted and ledger.sealed_exec is not None:
                ledger.sealed_exec.retire(deleted["id"])
            if deleted and ledger.sealed_env is not None:
                ledger.sealed_env.retire(deleted["id"])
        ctype = next((v for k, v in headers if k.lower() == "content-type"), "application/json")
        passthrough = {k: v for k, v in headers if k.lower() not in HOP and k.lower() != "content-type"}
        return self.reply(status, out, {**passthrough, **extra}, ctype)

    def reserved_label_check(self, body: bytes | None) -> tuple[tuple[str, str] | None, dict | None]:
        """(refusal, ask) for a create. The ask says what the create requested, for the signing step.

        The serial label must be the string "1", alone (not with the pool label). A serial create always
        makes a new room, so it carries no Idempotency-Key.
        """
        try:
            doc = json.loads(body or b"")
        except (ValueError, RecursionError):
            return None, None
        labels = doc.get("labels") if isinstance(doc, dict) else None
        if not isinstance(labels, dict) or SERIAL_LABEL not in labels:
            return None, None
        if labels[SERIAL_LABEL] != "1" or type(labels[SERIAL_LABEL]) is not str or POOL_LABEL in labels:
            return ("reserved_label_invalid", f"{SERIAL_LABEL} must be the string 1 and not set with {POOL_LABEL}"), None
        if self.headers.get_all("Idempotency-Key") is not None:
            return ("idempotency_key_refused", "a serial room is made without an Idempotency-Key"), None
        return None, {"serial": True}

    @staticmethod
    def asks_for_other_than_one_room(body: bytes | None) -> bool:
        try:
            doc = json.loads(body or b"")
        except (ValueError, RecursionError):
            return False  # not JSON: the API answers
        return isinstance(doc, dict) and "count" in doc and not (type(doc["count"]) is int and doc["count"] == 1)

    def owner_gate(self, ledger: "Ledger", body: bytes | None) -> tuple[bytes | None, dict]:
        """Dedicated machine: (403 body, {}) for a gated request without a
        valid owner signature, else (None, owner fields for a create receipt).

        The path is parsed as the API parses it (urlparse, which drops a
        ";params" suffix), so no spelling reaches the API's create route
        without passing here.
        """
        if ledger.owner_key is None:
            return None, {}
        api_path = urlparse(self.path).path
        action = next((a for meth, pat, a in OWNER_GATED if meth == self.command and pat.match(api_path)), None)
        if action is None:
            return None, {}
        code, msg, fields = check_owner_signature(ledger.owner_key, action, self.headers, body, time.time())
        if code:
            return canonical({"error": {"code": code, "message": msg}}), {}
        return None, (fields if action == "create" else {})

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

    def handle_sealed_secrets(self, ledger: "Ledger", room: str, body: bytes | None):
        """POST: write one customer-sealed secret. GET: names and versions. Never echoes a value."""
        if self.command not in ("GET", "POST"):
            return self.reply(405, b'{"error":"method_not_allowed"}', {"Allow": "GET, POST"})
        if not self.authorized():
            return self.reply(401, b'{"error":"unauthorized"}')
        if ledger.secrets is None:
            return self.reply(403, b'{"error":{"code":"sealed_secrets_disabled","message":"this hotel does not accept sealed secrets"}}')
        if not SECRETS_ROOM_RE.fullmatch(room):
            return self.reply(400, b'{"error":{"code":"sealed_secret_wrong_room","message":"not a room id"}}')
        if self.command == "GET":
            incarnation = ledger.room_incarnation(room)
            return self.reply(200, canonical({"sandbox_id": room, "binding_sha256": ledger.binding_sha256,
                                              "room_create_receipt_sha256": incarnation,
                                              "secrets": ledger.secrets.listing(room, incarnation)}))
        if body is None or len(body) > SECRETS_MAX_BYTES:
            return self.reply(413, b'{"error":{"code":"sealed_secret_too_large","message":"the request is too large"}}')
        try:
            doc = json.loads(body)
        except ValueError:
            doc = None
        try:
            out, receipt = ledger.write_sealed_secret(room, doc)
        except SecretRefused as exc:
            return self.reply(exc.status, canonical({"error": {"code": exc.code, "message": exc.code.replace("_", " ")}}))
        extra = {}
        if receipt is not None:
            # written: this write's receipt. unchanged: the receipt of the write that put this envelope in place.
            extra["X-Room-Receipt"] = base64.urlsafe_b64encode(canonical(receipt)).decode()
        else:
            extra["X-Room-Receipt-Error"] = "sign_failed"
        return self.reply(200, canonical(out), extra)

    def env_apply(self, room: str):
        """The apply of a sealed env write: PUT the opened overlay on the room API over loopback.

        Returns (status, error code or None). The API's answer is never passed to
        the caller: its messages could name what it was sent.
        """
        def apply(env: dict) -> tuple[int, str | None]:
            status, _headers, out = self.upstream(
                self.server.api_port, canonical({"env": env}), method="PUT",
                path=f"/v1/sandboxes/{room}/{ENV_API_TAIL}", extra={"Content-Type": "application/json"},
                timeout=ENV_APPLY_TIMEOUT_SECONDS)
            try:
                code = json.loads(out)["error"]["code"]
            except (ValueError, TypeError, KeyError, RecursionError):
                code = None
            return status, code if isinstance(code, str) else None
        return apply

    def handle_sealed_env(self, ledger: "Ledger", room: str, body: bytes | None):
        """POST: set a room's env overlay from one customer-sealed envelope. GET: names and version. Never a value."""
        if self.command not in ("GET", "POST"):
            return self.reply(405, b'{"error":"method_not_allowed"}', {"Allow": "GET, POST"})
        if not self.authorized():
            return self.reply(401, b'{"error":"unauthorized"}')
        if ledger.sealed_env is None:
            return self.reply(403, b'{"error":{"code":"sealed_env_disabled","message":"this hotel does not accept a sealed env"}}')
        if not SECRETS_ROOM_RE.fullmatch(room):
            return self.reply(400, b'{"error":{"code":"sealed_env_wrong_room","message":"not a room id"}}')
        if self.command == "GET":
            incarnation = ledger.room_incarnation(room)
            return self.reply(200, canonical({"sandbox_id": room, "binding_sha256": ledger.binding_sha256,
                                              "room_create_receipt_sha256": incarnation,
                                              **ledger.sealed_env.listing(room, incarnation)}))
        if body is None or len(body) > ENV_MAX_BYTES:
            return self.reply(413, b'{"error":{"code":"sealed_env_too_large","message":"the request is too large"}}')
        try:
            doc = json.loads(body)
        except (ValueError, RecursionError):  # RecursionError: nesting past the parser's depth
            doc = None
        try:
            out, receipt = ledger.write_sealed_env(room, doc, self.env_apply(room))
        except EnvRefused as exc:
            return self.reply(exc.status, canonical({"error": {"code": exc.code, "message": exc.code.replace("_", " ")}}))
        extra = {}
        if receipt is not None:
            # set: this write's receipt. unchanged: the receipt of the write that set this overlay.
            extra["X-Room-Receipt"] = base64.urlsafe_b64encode(canonical(receipt)).decode()
        else:
            extra["X-Room-Receipt-Error"] = "sign_failed"
        return self.reply(200, canonical(out), extra)

    def handle_sealed_exec(self, ledger: "Ledger", room: str, body: bytes | None):
        """POST: open one customer-sealed exec, run it in the room, seal the room API's answer back.

        The answer is 200 whenever the exec ran, whatever the room API said:
        its status, exit code and output are all inside the sealed answer.
        Only a room that died under the command is said in the clear
        (room_alive, oom_killed), because the API stops billing on it.
        """
        if self.command != "POST":
            return self.reply(405, b'{"error":"method_not_allowed"}', {"Allow": "POST"})
        if not self.authorized():
            return self.reply(401, b'{"error":"unauthorized"}')
        if ledger.sealed_exec is None:
            return self.reply(403, b'{"error":{"code":"sealed_exec_disabled","message":"this hotel does not accept sealed commands"}}')
        if not SECRETS_ROOM_RE.fullmatch(room):
            return self.reply(400, b'{"error":{"code":"sealed_exec_wrong_room","message":"not a room id"}}')
        if body is None or len(body) > EXEC_MAX_BYTES:
            return self.reply(413, b'{"error":{"code":"sealed_exec_too_large","message":"the request is too large"}}')
        try:
            doc = json.loads(body)
        except (ValueError, RecursionError):  # RecursionError: nesting past the parser's depth
            doc = None
        try:
            header, request = ledger.open_sealed_exec(room, doc)
        except ExecRefused as exc:
            return self.reply(exc.status, canonical({"error": {"code": exc.code, "message": exc.code.replace("_", " "),
                                                               **exc.extra}}),
                              {"Retry-After": str(exc.extra["retry_after_s"])} if "retry_after_s" in exc.extra else None)
        request_sha256 = sha(canonical(doc))
        command_sha256 = sha(canonical(request["cmd"]))
        inner = canonical({"cmd": request["cmd"], "env": request.get("env") or {}, "stdin": request.get("stdin"),
                           "cwd": request.get("cwd"), "user": request.get("user"),
                           "timeout_seconds": header["timeout_seconds"]})
        request = None
        status, _headers, out = self.upstream(
            self.server.api_port, inner, method="POST", path=f"/v1/sandboxes/{room}/{EXEC_API_TAIL}",
            extra={"Content-Type": "application/json"},
            timeout=header["timeout_seconds"] + EXEC_ANSWER_MARGIN_SECONDS)
        inner = None
        try:
            answer = json.loads(out) if out else None
        except ValueError:
            answer = None
        plain = {"status": status, "answer": answer}
        if answer is None and out:
            plain["answer_b64"] = b64(out)
        sealed = seal_exec_response(canonical(plain), header, request_sha256)
        plain = out = None
        fate = {}
        if status == 200 and isinstance(answer, dict) and answer.get("room_alive") is False:
            # The API ends a dead room's billing on these two (cathedral_broker_sealed.room_fate).
            fate = {"room_alive": False, "oom_killed": answer.get("oom_killed") is True}
        answer = None
        reply = canonical({"sealed_response": sealed, **fate})
        extra = {}
        try:
            receipt = ledger.sign({
                "action": "exec",
                "target": f"{self.command} {api_request_path(self.path)[1]}",
                "sandbox_id": room,
                "customer_request_sha256": sha(body),
                # As for every exec: sha256 of the command the room ran, here the opened one.
                "command_sha256": command_sha256,
                "image": None,
                "image_digest": None,
                # The front's answer. The room API's own status is inside the sealed answer.
                "status": 200,
                "result_sha256": sha(reply),
                "sealed": True,
                "room_create_receipt_sha256": header["room_create_receipt_sha256"],
                "sealed_request_sha256": request_sha256,
                "sealed_response_sha256": sha(canonical(sealed)),
            })
            extra["X-Room-Receipt"] = base64.urlsafe_b64encode(canonical(receipt)).decode()
        except Exception as exc:  # noqa: BLE001 the command ran: answer, and say the receipt is missing
            traceback.print_exc()
            extra["X-Room-Receipt-Error"] = type(exc).__name__
        return self.reply(200, reply, extra)

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
        if not isinstance(window_id, str) or not WINDOW_ID_RE.fullmatch(window_id) or not WINDOW_DIR_RE.fullmatch(window_id):
            return self.reply(400, b'{"error":{"code":"invalid_request","message":"window_id must be 1 to 128 of [A-Za-z0-9._:-], not starting with a dot"}}')
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
        base_dir = escape_nonce_dir()
        # Reject a symlinked or non-directory base before prune: listdir/rmtree would otherwise
        # follow the link and delete matching directories in an outside target.
        try:
            if os.path.lexists(base_dir):
                base_st = os.lstat(base_dir)
                if stat.S_ISLNK(base_st.st_mode) or not stat.S_ISDIR(base_st.st_mode):
                    return self.reply(500, b'{"error":{"code":"plant_failed","message":"the nonce file could not be written"}}')
        except OSError:
            return self.reply(500, b'{"error":{"code":"plant_failed","message":"the nonce file could not be written"}}')
        prune_escape_windows(base_dir, window_id)
        try:
            path = write_escape_nonce(base_dir, window_id, nonce)
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

    def fields(self, action: str, path: str, body: bytes | None, status: int, out: bytes,
               *, target_path: str | None = None) -> dict:
        req = {}
        try:
            req = json.loads(body) if body and action not in OPAQUE_BODY else {}
        except ValueError:
            pass
        res = {}
        try:
            # tar_get answers an archive on success and a JSON error otherwise.
            res = json.loads(out) if out and not (action in OPAQUE_BODY and 200 <= status < 300) else {}
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
        link = self.sandbox_link(action, req)
        start_command = None
        start_command_sha256 = None
        if action == "create" and isinstance(res, dict) and 200 <= status < 300:
            raw_start = res.get("start_command")
            if isinstance(raw_start, list) and all(isinstance(part, str) for part in raw_start):
                start_command = raw_start
                start_command_sha256 = sha(canonical(start_command))
        receipt_path = target_path if target_path is not None else path
        return {
            "action": action,
            # *receipt_path* is path plus query (urlparse drops ``;params``); never the raw client target.
            "target": f"{self.command} {receipt_path}",
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
            # Create: the Cathedral sandbox id the request's labels name (AB#389). Read from
            # the request as this guest received it, so customer_request_sha256 covers it too.
            **({"cathedral_sandbox_id": link} if link else {}),
            **({"start_command": start_command, "start_command_sha256": start_command_sha256}
               if action == "create" else {}),
        }

    @staticmethod
    def sandbox_link(action: str, req) -> str | None:
        """The Cathedral sandbox id a create's labels name, when it is a lower-case UUID."""
        if action != "create" or not isinstance(req, dict) or not isinstance(req.get("labels"), dict):
            return None
        value = req["labels"].get(SANDBOX_LINK_LABEL)
        return value if isinstance(value, str) and SANDBOX_LINK_RE.fullmatch(value) else None

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
    secrets = SealedSecrets(env.get("ROOM_SEALED_SECRETS_DIR") or DEFAULT_SECRETS_DIR) if sealed_secrets_wanted() else None
    sealed_exec = SealedExec() if sealed_exec_wanted() else None
    try:
        ledger = Ledger(env["ROOM_HOTEL_NAME"], store, miner=miner, secrets=secrets, sealed_exec=sealed_exec)
    except OwnerBindingError as exc:
        # Fail closed: nothing listens, so the broker sees the hotel down.
        # The console is the guest serial port, the one log the host operator can read.
        msg = f"room-receipts: REFUSING TO SERVE (dedicated owner check): {exc}"
        print(msg, file=sys.stderr, flush=True)
        try:
            with open("/dev/console", "w") as console:
                console.write(msg + "\n")
        except OSError:
            pass
        return 2
    if ledger.sealed:
        print(f"room-receipts: binding {ledger.binding_sha256} measurement {ledger.binding['measurement']} "
              f"tenancy {ledger.binding['tenancy']}", flush=True)
        if ledger.secrets is not None:
            print(f"room-receipts: sealed secrets on: key {ledger.secrets.public_b64} in the binding; "
                  f"room directories under {ledger.secrets.root}", flush=True)
        if ledger.sealed_exec is not None:
            print(f"room-receipts: sealed commands on: key {ledger.sealed_exec.public_b64} in the binding", flush=True)
    elif secrets is not None or sealed_exec is not None:
        print("room-receipts: ROOM_SEALED_SECRETS=1 and ROOM_SEALED_EXEC=1 are ignored: level 1 has no SNP report "
              "to bind the key", flush=True)
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
