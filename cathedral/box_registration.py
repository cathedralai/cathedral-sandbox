"""Register a miner's Cathedral runtime box with the SN94 prober.

A miner turns a server into a Cathedral runtime box with the runtime's
``install-runtime-host.sh --direct-ip``, which writes ``host-values.env`` (its
front door, certificate pin, measured capacity and templates) and the box's
keys. With ``--probe-template NAME`` it also makes a probe key and records the
template it is scoped to. This module turns those into one registration
document:

- signed with the miner's hotkey (sr25519), so the box is tied to the hotkey
  that will be paid for it;
- naming the probe template and carrying the box's probe key sealed to the
  prober's X25519 key, so only the prober can open it. The sealing binds the
  digest of the rest of the registration, and the signature covers the sealed
  key, so a key cannot be lifted onto another registration.

The probe key is not the team key. The box's front door lets it create only
short, offline sandboxes from the probe template, look up and delete its own,
and hold at most 8 at once; it cannot see or touch any other sandbox. The team
key never leaves the box's operator. Runtime team keys carry the ``e2b_``
prefix (the runtime's ``packages/auth/pkg/auth/consts.go``, ``PrefixAPIKey``)
and a probe key is exactly 64 hex characters, so the format check at seal and
at open tells the two apart.

A leaked probe key lets its holder register the box under another hotkey,
which the first-claim rule below refuses while the owner's claim holds, and
keep the 8-sandbox cap full so the prober's challenge cannot start. The
runbook gives the rotation: delete the key on the box, rerun the installer
with ``--probe-template``, register again. Rotating ends every claim made with
the old key, the owner's too until the new registration passes a probe; while
a squatter's claim holds, the owner's new registration is refused as another
hotkey's until the prober sees the squatter's probe fail, so the owner retries
after the next probe round.

Capacity. The prober's challenge runs in one probe sandbox, so the prober
probes, and pays, the box at the probe template's shape
(``VerifiedRegistration.probe_capacity``) and never more. ``capacity`` is the
host as the installer measured it; it bounds the templates, and host vCPUs or
memory outside the probe template earn nothing. A miner makes the probe
template its largest shape, ideally the whole box. docs/CAPACITY.md (#217)
sizes the challenge from claimed vCPUs and memory, so the prober must size it
with ``spec_for`` from ``probe_capacity``, never from ``capacity``.

The prober verifies the registration, probes the box through its front door,
and only then admits it (docs/MINER_BOX_RUNBOOK.md).

One box, one hotkey. The certificate pin and IP are public, so a registration
proves only that its signer holds the key it seals. ``box_id`` is per hotkey;
``box_key`` (``box_key_for``) depends only on the certificate pin, so it is the
same under every hotkey, but only for one certificate: the installer keeps the
certificate across reruns while at least 48 hours of its 7-day life remain,
and renews it after that, which changes ``box_key``. ``verify_registration``
checks one document; the prober's endpoint then applies the first-claim rule
keyed on the control IP, the identity that survives a renewal: the first
claim for an IP whose key opens and passes a probe wins, and a later claim for
the same IP (or the same ``box_key``) under another hotkey is refused, never
zeroing the first claimant. The same hotkey registering again, including with
a renewed certificate, keeps the claim. A claim lapses when its registration
expires unrenewed or its key stops passing the probe. Moving a box to another
hotkey means letting the old hotkey's claim lapse, then registering under the
new one. Binding the box to its hotkey
from the box side (the installer records the miner hotkey and the ingress
serves it over the pinned TLS, so the prober checks box to hotkey too) is a
follow-up in the runtime repo; until then whoever holds the key and registers
first holds the box.

Neither the IP nor the certificate stops one box being registered twice: a
TLS-terminating proxy on a second public IP, with its own certificate and
forwarding to the box, gives a new IP and a new ``box_key`` but seals the same
key. So the prober also dedupes on the opened key (``opened_key_digest``): a
claim for another IP whose key matches a held claim's is refused, under any
hotkey, the same hotkey included. And because one box might still answer under
more than one claim, the prober must challenge all admitted boxes
concurrently in each round, so two claims backed by one box share its CPU and
memory and cannot both pass.

Replay. A registration has no nonce, so anyone who saw a still-valid one can
resubmit it. And anyone can sign a document with a box's public front door and
certificate pin under their own hotkey, sealing a key they made up, with
``issued_at`` up to 5 minutes ahead (the allowed skew): it verifies and its key
opens; only the probe fails. So the endpoint orders registrations by
``issued_at`` per (control IP, hotkey), never per IP alone (``replay_order``),
and counts a registration only after its key opens and it passes a probe; a
counted registration then refuses an older one in its scope, or a different
one with the same order, so a superseded registration cannot displace its
successor, and a document that fails the probe never enters the order. The
order is the signed ``issued_at`` itself, never the arrival time, so a replayed
copy always ranks where the original did and cannot displace a document signed
after it. (A miner whose clock runs ahead can outrank their own later renewal
until real time passes the early ``issued_at``; keep the clock synchronised.)
Conflicts
between hotkeys are left to the first-claim rule: a document under another
hotkey never refuses the owner's renewal, whatever its ``issued_at``. The
document names no network: the prober keeps one X25519 key per network, so a
registration replayed to another network's prober verifies there but its key
does not open, and it is refused.

Run ``python -m cathedral.box_registration --help`` on the machine that ran the
installer and holds the miner hotkey.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cathedral.validator_access import (
    ValidatorAccessError,
    bittensor_account_id,
    load_sr25519_verifier,
)

# v2: the sealed key is the box's scoped probe key (`sealed_probe_key`) and the
# body names the probe template (`probe_template_id`). v1 sealed the runtime
# team key; it is refused, so no v1 document is ever read with this field set.
SCHEMA = "cathedral_box_registration_v2"
SEAL_ALGORITHM = "x25519-hkdf-sha256-chacha20poly1305"
SEAL_INFO = b"cathedral.box-registration.probe-key.v1"
ISSUED_AT_SKEW = timedelta(minutes=5)
BOX_KINDS = ("tee", "bare_metal")
MAX_VALIDITY = timedelta(days=7)
MAX_HOST_VALUES_BYTES = 64 * 1024
# The installer's probe key is 64 hex characters and a newline.
MAX_PROBE_KEY_FILE_BYTES = 128
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TIME = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
_TEMPLATE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_TEMPLATE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_REVISION = re.compile(r"[0-9a-f]{40}")
_HOST_KEY = re.compile(r"CATHEDRAL_[A-Z0-9_]+")
# 6to4 relay anycast (RFC 7526): global by ipaddress, but shared by many hosts.
_ANYCAST_6TO4 = ipaddress.IPv4Network("192.88.99.0/24")
_BODY_KEYS = frozenset(
    {
        "schema",
        "netuid",
        "miner_hotkey",
        "box_id",
        "kind",
        "front_door",
        "capacity",
        "templates",
        "runtime_revision",
        "issued_at",
        "expires_at",
        "probe_template_id",
        "sealed_probe_key",
    }
)


class RegistrationError(ValueError):
    """A registration, its host values or its sealed key is malformed or false."""


@dataclass(frozen=True)
class VerifiedRegistration:
    box_id: str
    box_key: str
    miner_hotkey: str
    netuid: int
    kind: str
    control_url: str
    guest_url: str
    cert_sha256: str
    vcpus: int
    memory_gib: int
    templates: tuple[dict[str, Any], ...]
    runtime_revision: str
    issued_at: datetime
    expires_at: datetime
    probe_template_id: str
    probe_capacity: Mapping[str, int]  # the probe template's cpu and memory_gib
    sealed_probe_key: Mapping[str, str]
    digest: bytes


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: object, name: str) -> datetime:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise RegistrationError(f"{name} must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:  # an impossible date, such as February 30 or year 0
        raise RegistrationError(f"{name} is not a real date") from exc


def _front_door(control: object, guest: object) -> tuple[str, str]:
    """Exactly what the installer's direct mode writes: ``https://<IP>`` and
    ``https://<IP>:8443``, one public IPv4 address. A DNS name, a private,
    loopback or metadata address, another port or any other spelling is refused,
    so a registration cannot point the prober anywhere but a public box. A
    multicast, reserved or anycast address is refused too: ``is_global`` alone
    admits multicast and 6to4 anycast. (Every reserved IPv4 address is already
    non-global in Python 3.12; ``is_reserved`` keeps that true whatever
    ``is_global`` becomes.)"""

    if not isinstance(control, str) or not control.startswith("https://"):
        raise RegistrationError("control_url must be https://<public IPv4>")
    host = control[len("https://") :]
    try:
        address = ipaddress.IPv4Address(host)
    except ValueError as exc:
        raise RegistrationError("control_url must be https://<public IPv4>") from exc
    if (
        str(address) != host
        or not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address in _ANYCAST_6TO4
    ):
        raise RegistrationError("control_url must name one public IPv4 address")
    if guest != f"https://{host}:8443":
        raise RegistrationError("guest_url must be https://<the same IPv4>:8443")
    return control, guest


def parse_host_values(text: str) -> dict[str, str]:
    """Read the installer's literal KEY=VALUE file. Never sourced: a repeated
    key, a malformed line or an oversize file is refused."""

    if len(text.encode()) > MAX_HOST_VALUES_BYTES:
        raise RegistrationError("host values file is too large")
    values: dict[str, str] = {}
    if "\r" in text:
        raise RegistrationError("host values must use plain newlines")
    for number, line in enumerate(text.split("\n"), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or _HOST_KEY.fullmatch(key) is None:
            raise RegistrationError(f"host values line {number} is not KEY=VALUE")
        if key in values:
            raise RegistrationError(f"host values repeat {key}")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
            raise RegistrationError(f"host values line {number} holds a control character")
        values[key] = value
    return values


def box_id_for(cert_sha256: str, miner_hotkey: str) -> str:
    """Stable per certificate and hotkey: a renewed certificate is a new box_id."""
    digest = hashlib.sha256(f"{cert_sha256}\x00{miner_hotkey}".encode()).hexdigest()
    return f"box-{digest[:32]}"


def box_key_for(cert_sha256: str) -> str:
    """The same under every hotkey, but only for one certificate: it changes
    when the installer renews the certificate (weekly). One of the prober's
    dedupe keys, beside the control IP and ``opened_key_digest``; none of them
    alone stops a box being registered twice (see the module docstring)."""
    return f"boxkey-{hashlib.sha256(cert_sha256.encode()).hexdigest()[:32]}"


def opened_key_digest(key: bytes) -> str:
    """The prober's dedupe key for an opened key: a domain-separated SHA-256,
    so the prober can compare keys across claims without keeping them. Two
    claims with the same digest are backed by one box, whatever their IPs and
    certificates (see the module docstring)."""
    if not isinstance(key, bytes):
        raise RegistrationError("the opened key must be bytes")
    return hashlib.sha256(b"cathedral.box-registration.opened-key.v1\x00" + key).hexdigest()


def replay_order(registration: VerifiedRegistration) -> tuple[tuple[str, str], datetime]:
    """Where and how the endpoint orders a registration against replays: the
    scope is (control IP, hotkey), never the IP alone, and the order is the
    signed ``issued_at``. It never depends on when a copy arrives, so a replayed
    document ranks exactly where the original did. The endpoint records the
    order only once the registration's key opens and passes a probe, and then
    refuses an older one in the same scope, or a different one with the same
    order (see the module docstring)."""
    if not isinstance(registration, VerifiedRegistration):
        raise RegistrationError("verify the registration before ordering it")
    control_ip = registration.control_url[len("https://") :]
    return (control_ip, registration.miner_hotkey), registration.issued_at


def _templates(value: object) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except (ValueError, RecursionError) as exc:  # JSONDecodeError is a ValueError
        raise RegistrationError("templates are not JSON") from exc
    if not isinstance(parsed, list) or not 1 <= len(parsed) <= 32:
        raise RegistrationError("templates must be a list of 1 to 32 shapes")
    out = []
    for item in parsed:
        if not isinstance(item, dict):
            raise RegistrationError("each template must be an object")
        name, cpu, memory = item.get("name"), item.get("cpu"), item.get("memory_gib")
        if not isinstance(name, str) or _TEMPLATE_NAME.fullmatch(name) is None:
            raise RegistrationError("template name is malformed")
        for label, number in (("cpu", cpu), ("memory_gib", memory)):
            if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 4096:
                raise RegistrationError(f"template {label} must be from 1 to 4096")
        shape = {"name": name, "cpu": cpu, "memory_gib": memory}
        for key in ("template_id", "build_id"):
            if key in item:
                if not isinstance(item[key], str) or _TEMPLATE_ID.fullmatch(item[key]) is None:
                    raise RegistrationError(f"template {key} is malformed")
                shape[key] = item[key]
        out.append(shape)
    return out


def _positive(value: object, name: str) -> int:
    # isdigit() alone admits digits such as "²" that int() refuses.
    if isinstance(value, str) and value.isascii() and value.isdigit() and value == str(int(value)):
        value = int(value)
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 1 << 20:
        raise RegistrationError(f"{name} must be a positive integer")
    return value


def build_body(
    host_values: Mapping[str, str],
    *,
    netuid: int,
    miner_hotkey: str,
    kind: str,
    now: datetime,
    valid_for: timedelta = timedelta(days=1),
) -> dict[str, Any]:
    """The registration body from host values, without its sealed probe key."""

    def need(key: str) -> str:
        if key not in host_values or not host_values[key]:
            raise RegistrationError(f"host values lack {key}")
        return host_values[key]

    if not host_values.get("CATHEDRAL_PROBE_TEMPLATE_ID"):
        raise RegistrationError(
            "host values lack CATHEDRAL_PROBE_TEMPLATE_ID: rerun the installer with --probe-template"
        )
    cert = need("CATHEDRAL_TLS_CERT_SHA256")
    if _HEX64.fullmatch(cert) is None:
        raise RegistrationError("CATHEDRAL_TLS_CERT_SHA256 must be 64 lowercase hex characters")
    body = {
        "schema": SCHEMA,
        "netuid": netuid,
        "miner_hotkey": miner_hotkey,
        "box_id": box_id_for(cert, miner_hotkey),
        "kind": kind,
        "front_door": {
            "control_url": need("CATHEDRAL_E2B_API_URL"),
            "guest_url": need("CATHEDRAL_E2B_SANDBOX_URL"),
            "cert_sha256": cert,
        },
        "capacity": {
            "vcpus": _positive(need("CATHEDRAL_CAPACITY_VCPU"), "CATHEDRAL_CAPACITY_VCPU"),
            "memory_gib": _positive(
                need("CATHEDRAL_CAPACITY_MEMORY_GIB"), "CATHEDRAL_CAPACITY_MEMORY_GIB"
            ),
        },
        "templates": _templates(need("CATHEDRAL_TEMPLATES_JSON")),
        "runtime_revision": need("CATHEDRAL_RUNTIME_GIT_REVISION"),
        "probe_template_id": host_values["CATHEDRAL_PROBE_TEMPLATE_ID"],
        "issued_at": _iso(now),
        "expires_at": _iso(now + valid_for),
    }
    _check_unsealed(body)
    return body


def _unsealed_digest(body: Mapping[str, Any]) -> bytes:
    unsealed = {key: value for key, value in body.items() if key != "sealed_probe_key"}
    return hashlib.sha256(b"cathedral.box-registration.v1\x00" + canonical_bytes(unsealed)).digest()


def _raw(key: X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _seal_key(shared: bytes, aad: bytes, ephemeral: bytes, recipient: bytes) -> bytes:
    # As in HPKE, the derivation binds both public keys, not only the secret.
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=aad, info=SEAL_INFO + ephemeral + recipient
    ).derive(shared)


def seal_probe_key(
    probe_key: bytes, prober_public_key: X25519PublicKey, body: Mapping[str, Any]
) -> dict[str, str]:
    """Seal the box's probe key to the prober, bound to this registration."""

    # Exactly what the installer writes. A team key starts with "e2b_", so one
    # passed by mistake is refused.
    if not isinstance(probe_key, bytes) or _HEX64.fullmatch(probe_key.decode("latin-1")) is None:
        raise RegistrationError(
            "probe key must be the installer's cathedral-runtime-LABEL.probe-key (64 hex characters)"
        )
    ephemeral = X25519PrivateKey.generate()
    aad = _unsealed_digest(body)
    raw_public = _raw(ephemeral.public_key())
    key = _seal_key(ephemeral.exchange(prober_public_key), aad, raw_public, _raw(prober_public_key))
    nonce = os.urandom(12)
    return {
        "algorithm": SEAL_ALGORITHM,
        "ephemeral_public_b64": base64.b64encode(raw_public).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(
            ChaCha20Poly1305(key).encrypt(nonce, probe_key, aad)
        ).decode(),
    }


def open_probe_key(
    registration: VerifiedRegistration, prober_private_key: X25519PrivateKey
) -> bytes:
    """The prober's side: recover the probe key from a registration it has
    verified, or raise when the key was sealed to someone else or lifted from
    another registration."""

    if not isinstance(registration, VerifiedRegistration):
        raise RegistrationError("verify the registration before opening its key")
    sealed, aad = registration.sealed_probe_key, registration.digest
    try:
        raw_ephemeral = base64.b64decode(sealed["ephemeral_public_b64"], validate=True)
        ephemeral = X25519PublicKey.from_public_bytes(raw_ephemeral)
        nonce = base64.b64decode(sealed["nonce_b64"], validate=True)
        ciphertext = base64.b64decode(sealed["ciphertext_b64"], validate=True)
        key = _seal_key(
            prober_private_key.exchange(ephemeral),
            aad,
            raw_ephemeral,
            _raw(prober_private_key.public_key()),
        )
        opened = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise RegistrationError("the sealed probe key does not open for this prober") from exc
    # A registration built without this module could seal the team key
    # instead; a team key starts with "e2b_", so it is never 64 hex.
    if _HEX64.fullmatch(opened.decode("latin-1")) is None:
        raise RegistrationError("the sealed key is not a probe key")
    return opened


def sign_registration(body: Mapping[str, Any], signer: Callable[[bytes], bytes]) -> dict[str, Any]:
    """The miner's side: sign the complete body (sealed key included) with the hotkey."""

    if "signature" in body:
        raise RegistrationError("body already carries a signature")
    _check_sealed(body)
    signature = signer(canonical_bytes(body))
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise RegistrationError("the hotkey signer must return a 64-byte sr25519 signature")
    return {
        **body,
        "signature": {"algorithm": "sr25519", "value_b64": base64.b64encode(signature).decode()},
    }


def verify_registration(
    signed: Mapping[str, Any],
    *,
    netuid: int,
    now: datetime,
    verifier: Callable[[bytes, bytes, bytes], bool] | None = None,
) -> VerifiedRegistration:
    """The prober's side: shape, audience, validity window and hotkey signature."""

    if not isinstance(signed, Mapping) or "signature" not in signed:
        raise RegistrationError("registration is not a signed object")
    body = {key: value for key, value in signed.items() if key != "signature"}
    parsed = _check_sealed(body)
    signature = signed["signature"]
    if (
        not isinstance(signature, Mapping)
        or set(signature) != {"algorithm", "value_b64"}
        or signature["algorithm"] != "sr25519"
    ):
        raise RegistrationError("registration signature must be an sr25519 object")
    try:
        raw = base64.b64decode(signature["value_b64"], validate=True)
        public_key = bittensor_account_id(body["miner_hotkey"])
    except (binascii.Error, TypeError, ValueError, ValidatorAccessError) as exc:
        raise RegistrationError("registration signature or hotkey is malformed") from exc
    verify = verifier or load_sr25519_verifier()
    if len(raw) != 64 or not verify(raw, canonical_bytes(body), public_key):
        raise RegistrationError("registration signature does not verify")
    if parsed.netuid != netuid:
        raise RegistrationError("registration is for another netuid")
    # Compared as differences, so dates near year 1 or 9999 cannot overflow.
    if now - parsed.issued_at < -ISSUED_AT_SKEW or now >= parsed.expires_at:
        raise RegistrationError("registration is not currently valid")
    return parsed


def _check_unsealed(body: Mapping[str, Any]) -> None:
    if set(body) != _BODY_KEYS - {"sealed_probe_key"}:
        raise RegistrationError("registration body has the wrong fields")
    _fields(body)


def _check_sealed(body: Mapping[str, Any]) -> VerifiedRegistration:
    if set(body) != _BODY_KEYS:
        raise RegistrationError("registration body has the wrong fields")
    sealed = body["sealed_probe_key"]
    if (
        not isinstance(sealed, Mapping)
        or set(sealed) != {"algorithm", "ephemeral_public_b64", "nonce_b64", "ciphertext_b64"}
        or sealed["algorithm"] != SEAL_ALGORITHM
        or any(not isinstance(value, str) for value in sealed.values())
    ):
        raise RegistrationError("sealed_probe_key is malformed")
    return _fields(body)


def _fields(body: Mapping[str, Any]) -> VerifiedRegistration:
    if body["schema"] != SCHEMA:
        raise RegistrationError("registration schema is unsupported")
    netuid = body["netuid"]
    if not isinstance(netuid, int) or isinstance(netuid, bool) or not 0 <= netuid <= 65535:
        raise RegistrationError("netuid must be an integer from 0 to 65535")
    hotkey = body["miner_hotkey"]
    try:
        bittensor_account_id(hotkey)
    except ValidatorAccessError as exc:
        raise RegistrationError("miner_hotkey is not a Bittensor SS58 address") from exc
    front = body["front_door"]
    if not isinstance(front, Mapping) or set(front) != {"control_url", "guest_url", "cert_sha256"}:
        raise RegistrationError("front_door must have control_url, guest_url and cert_sha256")
    control, guest = _front_door(front["control_url"], front["guest_url"])
    cert = front["cert_sha256"]
    if not isinstance(cert, str) or _HEX64.fullmatch(cert) is None:
        raise RegistrationError("cert_sha256 must be 64 lowercase hex characters")
    if body["box_id"] != box_id_for(cert, hotkey):
        raise RegistrationError("box_id does not match the certificate and hotkey")
    if body["kind"] not in BOX_KINDS:
        raise RegistrationError("kind must be tee or bare_metal")
    capacity = body["capacity"]
    if not isinstance(capacity, Mapping) or set(capacity) != {"vcpus", "memory_gib"}:
        raise RegistrationError("capacity must have vcpus and memory_gib")
    vcpus = capacity["vcpus"]
    memory = capacity["memory_gib"]
    for label, value in (("vcpus", vcpus), ("memory_gib", memory)):
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 1 << 20:
            raise RegistrationError(f"capacity {label} must be a positive integer")
    templates = _templates(body["templates"])
    if templates != body["templates"]:
        raise RegistrationError("templates must be in canonical form")
    if any(t["cpu"] > vcpus or t["memory_gib"] > memory for t in templates):
        raise RegistrationError("a template is larger than the box")
    probe_template = body["probe_template_id"]
    if not isinstance(probe_template, str) or _TEMPLATE_ID.fullmatch(probe_template) is None:
        raise RegistrationError("probe_template_id is malformed")
    probe_shapes = [t for t in templates if t.get("template_id") == probe_template]
    if not probe_shapes:
        raise RegistrationError("probe_template_id is not one of the box's templates")
    if len(probe_shapes) > 1:
        raise RegistrationError("probe_template_id names more than one template")
    # The one shape the prober can prove, and so pay: its challenge runs in one
    # probe sandbox.
    probe_capacity = {
        "cpu": probe_shapes[0]["cpu"],
        "memory_gib": probe_shapes[0]["memory_gib"],
    }
    revision = body["runtime_revision"]
    if not isinstance(revision, str) or _REVISION.fullmatch(revision) is None:
        raise RegistrationError("runtime_revision must be a 40-hex git revision")
    issued = _parse_time(body["issued_at"], "issued_at")
    expires = _parse_time(body["expires_at"], "expires_at")
    if not (issued < expires and expires - issued <= MAX_VALIDITY):
        raise RegistrationError("registration validity must be positive and at most 7 days")
    return VerifiedRegistration(
        box_id=body["box_id"],
        box_key=box_key_for(cert),
        miner_hotkey=hotkey,
        netuid=netuid,
        kind=body["kind"],
        control_url=control,
        guest_url=guest,
        cert_sha256=cert,
        vcpus=vcpus,
        memory_gib=memory,
        templates=tuple(templates),
        runtime_revision=revision,
        issued_at=issued,
        expires_at=expires,
        probe_template_id=probe_template,
        probe_capacity=probe_capacity,
        sealed_probe_key=dict(body.get("sealed_probe_key") or {}),
        digest=_unsealed_digest(body),
    )


def register(
    *,
    host_values_text: str,
    probe_key: bytes,
    prober_public_key: X25519PublicKey,
    netuid: int,
    kind: str,
    keypair: Any,
    now: datetime,
    valid_for: timedelta = timedelta(days=1),
) -> dict[str, Any]:
    """Host values + probe key + hotkey → one signed, sealed registration."""

    body = build_body(
        parse_host_values(host_values_text),
        netuid=netuid,
        miner_hotkey=keypair.ss58_address,
        kind=kind,
        now=now,
        valid_for=valid_for,
    )
    body["sealed_probe_key"] = seal_probe_key(probe_key, prober_public_key, body)
    return sign_registration(body, keypair.sign)


def _read_file(path: str, name: str, limit: int, *, private: bool = False) -> bytes:
    """Read a bounded file. A ``private`` (key) file that the group or others
    can read still works, but draws a warning on stderr."""

    with open(path, "rb") as handle:
        mode = os.fstat(handle.fileno()).st_mode
        data = handle.read(limit + 1)
    if not 1 <= len(data) <= limit:
        raise RegistrationError(f"{name} is empty or too large")
    if private and mode & 0o077:
        print(
            f"warning: {name} file {path} is readable by group or others "
            f"(mode {mode & 0o777:o}); chmod 600 it",
            file=sys.stderr,
        )
    return data


def main(
    argv: list[str] | None = None, *, keypair_factory: Callable[..., Any] | None = None
) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m cathedral.box_registration",
        description="Write a signed registration for this Cathedral runtime box.",
    )
    parser.add_argument(
        "--host-values", required=True, help="the installer's cathedral-runtime-LABEL.values"
    )
    parser.add_argument(
        "--probe-key-file", required=True, help="the installer's cathedral-runtime-LABEL.probe-key"
    )
    parser.add_argument(
        "--prober-key", required=True, help="the SN94 prober's X25519 public key, 64 hex characters"
    )
    parser.add_argument("--netuid", required=True, type=int)
    parser.add_argument("--kind", required=True, choices=BOX_KINDS)
    parser.add_argument("--wallet-name", required=True)
    parser.add_argument("--hotkey-name", required=True)
    parser.add_argument("--wallet-path", default=None)
    parser.add_argument("--valid-hours", type=int, default=24)
    options = parser.parse_args(argv)
    try:
        if not 1 <= options.valid_hours <= 7 * 24:
            raise RegistrationError("--valid-hours must be from 1 to 168")
        if _HEX64.fullmatch(options.prober_key) is None:
            raise RegistrationError("--prober-key must be 64 lowercase hex characters")
        prober = X25519PublicKey.from_public_bytes(bytes.fromhex(options.prober_key))
        if keypair_factory is None:
            from cathedral.cli import _wallet_hotkey_keypair  # noqa: PLC0415

            keypair_factory = _wallet_hotkey_keypair
        keypair = keypair_factory(options.wallet_name, options.hotkey_name, options.wallet_path)
        registration = register(
            host_values_text=_read_file(
                options.host_values, "host values", MAX_HOST_VALUES_BYTES
            ).decode(),
            probe_key=_read_file(
                options.probe_key_file, "probe key", MAX_PROBE_KEY_FILE_BYTES, private=True
            ).strip(),
            prober_public_key=prober,
            netuid=options.netuid,
            kind=options.kind,
            keypair=keypair,
            now=datetime.now(UTC).replace(microsecond=0),
            valid_for=timedelta(hours=options.valid_hours),
        )
    except (RegistrationError, OSError, UnicodeDecodeError) as exc:
        print(f"box registration refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(registration, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
