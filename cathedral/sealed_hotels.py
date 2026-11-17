"""cathedral_sealed_hotels_v1: the signed per-hotel sealed guest measurement list.

AB#382 work package 1. Contract: docs/specs/ab382-signed-hotel-measurements.md;
format reference: docs/SEALED_HOTELS_V1.md.

The envelope reuses the policy registry convention (cathedral/policy_registry.py):
Ed25519 over canonical JSON of the document without ``signature`` (sorted keys,
ASCII escapes, no insignificant whitespace). Duplicate JSON keys, unknown
fields, floats and non-finite numbers are refused before canonicalization.
Unlike the registry, the published bytes must themselves be the canonical
JSON of the whole document (signature included), so "SHA-256 of the exact
signed envelope bytes" (decision 4) has exactly one value per release.

Owner keys are pinned outside the envelope (a pin file or the caller), each
with a closed ``not_before`` / ``not_after`` window. A ``key_id`` in the
envelope only selects among pinned keys; it grants no trust by itself.

No admission path consumes this yet (work packages 3 to 5).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if TYPE_CHECKING:
    from cathedral.signer import Signer

SCHEMA = "cathedral_sealed_hotels_v1"
PINS_SCHEMA = "cathedral_sealed_hotels_pins_v1"
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_PIN_FILE_BYTES = 64 * 1024
MAX_HOTELS = 256
MAX_MEASUREMENTS_PER_HOTEL = 16
MAX_RELEASE = 2**63 - 1
MAX_POLICY_AGE = timedelta(hours=24)  # decision 2
MAX_FUTURE_SKEW = timedelta(minutes=5)

_TOP_LEVEL_KEYS = frozenset(
    {"schema", "release", "generated_at", "valid_from", "valid_until", "key_id", "hotels", "signature"}
)
_HOTEL_KEYS = frozenset({"chip_id", "measurements"})
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_PIN_FILE_KEYS = frozenset({"schema", "keys"})
_PIN_KEYS = frozenset({"algorithm", "public_key_hex", "not_before", "not_after"})
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_CHIP_ID_RE = re.compile(r"^[0-9a-f]{128}$")
_MEASUREMENT_RE = re.compile(r"^[0-9a-f]{96}$")
_PUBLIC_KEY_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class SealedHotelsError(ValueError):
    """A sealed hotel envelope or pin file failed a schema, signature, time or rollback check."""


# ---------------------------------------------------------------- JSON helpers


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SealedHotelsError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _refuse_float(_value: str) -> object:
    raise SealedHotelsError("floating-point JSON is not canonical")


def _refuse_constant(_value: str) -> object:
    raise SealedHotelsError("non-finite JSON is not canonical")


def strict_json(data: bytes, *, limit: int, what: str) -> dict[str, object]:
    """Parse UTF-8 JSON, refusing duplicate keys, floats, constants and non-objects."""
    if not isinstance(data, (bytes, bytearray)):
        raise SealedHotelsError(f"{what} must be bytes")
    if len(data) > limit:
        raise SealedHotelsError(f"{what} exceeds {limit} bytes")
    try:
        parsed = json.loads(
            bytes(data).decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_refuse_float,
            parse_constant=_refuse_constant,
        )
    except SealedHotelsError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise SealedHotelsError(f"{what} is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise SealedHotelsError(f"{what} must be a JSON object")
    return parsed


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise SealedHotelsError("document contains a non-canonical value") from exc


def canonical_signed_bytes(document: Mapping[str, object]) -> bytes:
    """The Ed25519 signature input: canonical JSON of the document without ``signature``."""
    unsigned = dict(document)
    unsigned.pop("signature", None)
    return canonical_json(unsigned)


def envelope_digest(envelope_bytes: bytes) -> str:
    return "sha256:" + hashlib.sha256(envelope_bytes).hexdigest()


def format_time(when: datetime) -> str:
    if when.tzinfo is None or when.utcoffset() != timedelta(0):
        raise SealedHotelsError("times must be UTC")
    return when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: object, name: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise SealedHotelsError(f"{name} must be canonical UTC time YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise SealedHotelsError(f"{name} must be canonical UTC time") from exc


def _utc(when: datetime | None, name: str) -> datetime:
    if when is None:
        return datetime.now(UTC)
    if when.tzinfo is None or when.utcoffset() != timedelta(0):
        raise SealedHotelsError(f"{name} must be UTC")
    return when


# -------------------------------------------------------------------- key pins


@dataclass(frozen=True)
class KeyPin:
    key_id: str
    public_key: bytes
    not_before: datetime
    not_after: datetime

    @property
    def fingerprint(self) -> str:
        """SHA-256 of the 32 raw public key bytes, lowercase hex."""
        return hashlib.sha256(self.public_key).hexdigest()

    def contains(self, when: datetime) -> bool:
        return self.not_before <= when <= self.not_after


def parse_pins(data: bytes) -> Mapping[str, KeyPin]:
    """Parse a ``cathedral_sealed_hotels_pins_v1`` pin file. Every window must be closed."""
    document = strict_json(data, limit=MAX_PIN_FILE_BYTES, what="pin file")
    if frozenset(document) != _PIN_FILE_KEYS:
        raise SealedHotelsError("pin file has missing or unknown fields")
    if document["schema"] != PINS_SCHEMA:
        raise SealedHotelsError("pin file schema is unsupported")
    keys = document["keys"]
    if not isinstance(keys, dict) or not keys or len(keys) > 64:
        raise SealedHotelsError("pin file keys must be a non-empty object")
    pins: dict[str, KeyPin] = {}
    seen_public: set[bytes] = set()
    for key_id, raw in keys.items():
        if _ID_RE.fullmatch(key_id) is None:
            raise SealedHotelsError(f"pin key id {key_id!r} is malformed")
        if not isinstance(raw, dict) or frozenset(raw) != _PIN_KEYS:
            raise SealedHotelsError(f"pin {key_id!r} has missing or unknown fields")
        if raw["algorithm"] != "ed25519":
            raise SealedHotelsError(f"pin {key_id!r} algorithm is unsupported")
        public_hex = raw["public_key_hex"]
        if not isinstance(public_hex, str) or _PUBLIC_KEY_RE.fullmatch(public_hex) is None:
            raise SealedHotelsError(f"pin {key_id!r} public_key_hex must be 64 lowercase hex")
        public = bytes.fromhex(public_hex)
        try:
            Ed25519PublicKey.from_public_bytes(public)
        except ValueError as exc:
            raise SealedHotelsError(f"pin {key_id!r} is not an Ed25519 public key") from exc
        if public in seen_public:
            raise SealedHotelsError("one public key is pinned under two key ids")
        seen_public.add(public)
        if raw["not_after"] is None:
            raise SealedHotelsError(f"pin {key_id!r} has an open not_after; every pin window is closed")
        not_before = parse_time(raw["not_before"], f"pin {key_id!r} not_before")
        not_after = parse_time(raw["not_after"], f"pin {key_id!r} not_after")
        if not not_before < not_after:
            raise SealedHotelsError(f"pin {key_id!r} window is empty or inverted")
        pins[key_id] = KeyPin(key_id, public, not_before, not_after)
    return MappingProxyType(pins)


# -------------------------------------------------------------- the envelope


@dataclass(frozen=True)
class HotelEntry:
    chip_id: str
    measurements: tuple[str, ...]


@dataclass(frozen=True)
class SealedHotelsRelease:
    release: int
    generated_at: datetime
    valid_from: datetime
    valid_until: datetime
    key_id: str
    key_fingerprint: str
    hotels: Mapping[str, HotelEntry]
    digest: str
    envelope_bytes: bytes

    def approves(self, hotel_id: str, chip_id: str, measurement: str) -> bool:
        """True only if the enrolled hotel's signed entry names this full chip ID and measurement."""
        entry = self.hotels.get(hotel_id)
        return entry is not None and entry.chip_id == chip_id and measurement in entry.measurements


def _hotels(raw: object) -> Mapping[str, HotelEntry]:
    if not isinstance(raw, dict) or not raw:
        raise SealedHotelsError("hotels must be a non-empty object keyed by enrolled hotel ID")
    if len(raw) > MAX_HOTELS:
        raise SealedHotelsError("too many hotels")
    hotels: dict[str, HotelEntry] = {}
    for hotel_id, entry in raw.items():
        if _ID_RE.fullmatch(hotel_id) is None:
            raise SealedHotelsError(f"hotel ID {hotel_id!r} is malformed")
        if not isinstance(entry, dict) or frozenset(entry) != _HOTEL_KEYS:
            raise SealedHotelsError(f"hotel {hotel_id!r} has missing or unknown fields")
        chip_id = entry["chip_id"]
        if not isinstance(chip_id, str) or _CHIP_ID_RE.fullmatch(chip_id) is None:
            raise SealedHotelsError(
                f"hotel {hotel_id!r} chip_id must be the full 64-byte SNP CHIP_ID as 128 lowercase hex"
            )
        if chip_id == "0" * 128:
            raise SealedHotelsError(f"hotel {hotel_id!r} chip_id is all zero")
        measurements = entry["measurements"]
        if not isinstance(measurements, list) or not measurements:
            raise SealedHotelsError(f"hotel {hotel_id!r} measurements must be a non-empty list")
        if len(measurements) > MAX_MEASUREMENTS_PER_HOTEL:
            raise SealedHotelsError(f"hotel {hotel_id!r} has too many measurements")
        for measurement in measurements:
            if not isinstance(measurement, str) or _MEASUREMENT_RE.fullmatch(measurement) is None:
                raise SealedHotelsError(
                    f"hotel {hotel_id!r} measurement must be 96 lowercase hex (SNP MEASUREMENT)"
                )
        if len(set(measurements)) != len(measurements):
            raise SealedHotelsError(f"hotel {hotel_id!r} lists a measurement twice")
        hotels[hotel_id] = HotelEntry(chip_id, tuple(measurements))
    return MappingProxyType(hotels)


def _release_number(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= MAX_RELEASE:
        raise SealedHotelsError("release must be a positive integer")
    return value


def verify_envelope(
    envelope_bytes: bytes,
    pins: Mapping[str, KeyPin],
    *,
    now: datetime | None = None,
    historical_at: datetime | None = None,
) -> SealedHotelsRelease:
    """Verify exact envelope bytes against pinned keys.

    ``now`` (default: wall clock) is the verification time. ``historical_at``
    checks an archived release at a past admission time instead: the pin window
    and the release validity must contain it and it must be within 24 hours of
    ``generated_at``, while ``now`` still bounds how far in the future
    ``generated_at`` may be.
    """
    wall_clock = _utc(now, "now")
    check_time = _utc(historical_at, "historical_at") if historical_at is not None else wall_clock
    document = strict_json(envelope_bytes, limit=MAX_ENVELOPE_BYTES, what="envelope")
    if frozenset(document) != _TOP_LEVEL_KEYS:
        missing = sorted(_TOP_LEVEL_KEYS - frozenset(document))
        unknown = sorted(frozenset(document) - _TOP_LEVEL_KEYS)
        raise SealedHotelsError(f"envelope fields wrong (missing {missing}, unknown {unknown})")
    if document["schema"] != SCHEMA:
        raise SealedHotelsError("envelope schema is unsupported")
    if canonical_json(document) != bytes(envelope_bytes):
        raise SealedHotelsError("envelope bytes are not canonical JSON")
    release = _release_number(document["release"])
    key_id = document["key_id"]
    if not isinstance(key_id, str) or _ID_RE.fullmatch(key_id) is None:
        raise SealedHotelsError("key_id is malformed")
    pin = pins.get(key_id)
    if not isinstance(pin, KeyPin):
        raise SealedHotelsError(f"key {key_id!r} is not pinned")
    signature = document["signature"]
    if not isinstance(signature, dict) or frozenset(signature) != _SIGNATURE_KEYS:
        raise SealedHotelsError("signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise SealedHotelsError("signature algorithm is unsupported")
    try:
        signature_bytes = base64.b64decode(signature["value_base64"], validate=True)
    except (TypeError, binascii.Error, ValueError) as exc:
        raise SealedHotelsError("signature is not canonical base64") from exc
    if (
        len(signature_bytes) != 64
        or base64.b64encode(signature_bytes).decode("ascii") != signature["value_base64"]
    ):
        raise SealedHotelsError("signature must be 64 bytes in canonical base64")
    try:
        Ed25519PublicKey.from_public_bytes(pin.public_key).verify(
            signature_bytes, canonical_signed_bytes(document)
        )
    except (InvalidSignature, ValueError) as exc:
        raise SealedHotelsError("signature verification failed") from exc

    generated_at = parse_time(document["generated_at"], "generated_at")
    valid_from = parse_time(document["valid_from"], "valid_from")
    valid_until = parse_time(document["valid_until"], "valid_until")
    if not valid_from < valid_until:
        raise SealedHotelsError("validity window is empty or inverted")
    if generated_at >= valid_until:
        raise SealedHotelsError("generated_at must precede valid_until")
    if generated_at > wall_clock + MAX_FUTURE_SKEW:
        raise SealedHotelsError("generated_at is in the future")
    if not pin.contains(generated_at):
        raise SealedHotelsError(f"key {key_id!r} pin window does not contain generated_at")
    if not pin.contains(check_time):
        raise SealedHotelsError(f"key {key_id!r} pin window does not contain the verification time")
    if check_time < valid_from:
        raise SealedHotelsError("release is not yet valid (valid_from is in the future)")
    if check_time > valid_until:
        raise SealedHotelsError("release has expired (past valid_until)")
    if check_time - generated_at > MAX_POLICY_AGE:
        raise SealedHotelsError("release is older than the 24 hour maximum policy age")
    hotels = _hotels(document["hotels"])
    return SealedHotelsRelease(
        release=release,
        generated_at=generated_at,
        valid_from=valid_from,
        valid_until=valid_until,
        key_id=key_id,
        key_fingerprint=pin.fingerprint,
        hotels=hotels,
        digest=envelope_digest(bytes(envelope_bytes)),
        envelope_bytes=bytes(envelope_bytes),
    )


def check_successor(previous: tuple[int, str] | None, candidate: SealedHotelsRelease) -> bool:
    """Rollback rule against a recorded high-water ``(release, digest)``.

    Returns True when ``candidate`` is newer, False when it is the same release
    (same digest, nothing to do). Refuses a lower release and a same-number
    release with another digest.
    """
    if previous is None:
        return True
    previous_release, previous_digest = previous
    _release_number(previous_release)
    if not isinstance(previous_digest, str) or _DIGEST_RE.fullmatch(previous_digest) is None:
        raise SealedHotelsError("recorded digest is malformed")
    if candidate.release < previous_release:
        raise SealedHotelsError(
            f"rollback refused: release {candidate.release} is below recorded {previous_release}"
        )
    if candidate.release == previous_release:
        if candidate.digest != previous_digest:
            raise SealedHotelsError(
                f"equivocation refused: release {candidate.release} has another digest"
            )
        return False
    return True


# -------------------------------------------------------------------- signing


def build_unsigned(
    *,
    release: int,
    generated_at: datetime,
    valid_from: datetime,
    valid_until: datetime,
    key_id: str,
    hotels: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    """An unsigned document; measurements are sorted so equal sets sign the same bytes."""
    document: dict[str, object] = {
        "schema": SCHEMA,
        "release": _release_number(release),
        "generated_at": format_time(generated_at),
        "valid_from": format_time(valid_from),
        "valid_until": format_time(valid_until),
        "key_id": key_id,
        "hotels": {},
    }
    for hotel_id, entry in hotels.items():
        if not isinstance(entry, Mapping) or not isinstance(entry.get("measurements"), list):
            raise SealedHotelsError(f"hotel {hotel_id!r} entry must have a measurements list")
        document["hotels"][hotel_id] = {  # type: ignore[index]
            "chip_id": entry.get("chip_id"),
            "measurements": list(entry["measurements"]),
        }
    _hotels(document["hotels"])  # validates before sorting
    for entry in document["hotels"].values():  # type: ignore[union-attr]
        entry["measurements"].sort()
    return document


def sign_envelope(unsigned_document: Mapping[str, object], signer: "Signer") -> bytes:
    """Sign with any cathedral.signer backend; returns the exact canonical envelope bytes."""
    if "signature" in unsigned_document:
        raise SealedHotelsError("unsigned document must not contain signature")
    if unsigned_document.get("key_id") != signer.key_id:
        raise SealedHotelsError("document key_id does not match the signer's key_id")
    document = dict(unsigned_document)
    signature = signer.sign(canonical_signed_bytes(document))
    document["signature"] = {
        "algorithm": "ed25519",
        "value_base64": base64.b64encode(signature).decode("ascii"),
    }
    return canonical_json(document)


__all__ = [
    "HotelEntry",
    "KeyPin",
    "MAX_POLICY_AGE",
    "PINS_SCHEMA",
    "SCHEMA",
    "SealedHotelsError",
    "SealedHotelsRelease",
    "build_unsigned",
    "canonical_json",
    "canonical_signed_bytes",
    "check_successor",
    "envelope_digest",
    "parse_pins",
    "parse_time",
    "sign_envelope",
    "verify_envelope",
]
