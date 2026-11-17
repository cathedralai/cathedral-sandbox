#!/usr/bin/env python3
"""Standalone customer verifier for a cathedral_sealed_hotels_v1 release (AB#382).

Needs only Python 3.11+ and the ``cryptography`` package. It does not import
any Cathedral code and does not trust any key carried by the document: the
owner keys are pinned below (or in a pin file you pass with --pins), each with
its own not_before / not_after window. Compare the pinned fingerprint with the
one published in the cathedral-sandbox repository (docs/keys/README.md) and on
the AB#382 card; the website alone is not an independent trust root.

    curl -fsS https://cathedral.computer/approved-measurements.signed.json -o release.json
    python3 verify_sealed_hotels.py release.json

    # an archived release, checked at a historical admission time
    python3 verify_sealed_hotels.py archived.json --at 2026-11-17T18:00:00Z

    # refuse a rollback against a release you accepted before
    python3 verify_sealed_hotels.py release.json --previous-release 3 \\
        --previous-digest sha256:<64 hex>

Exit status 0 and a line starting with PASS when every check holds; otherwise
exit status 1 and a line starting with FAIL naming the first refused check.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "cathedral_sealed_hotels_v1"
PINS_SCHEMA = "cathedral_sealed_hotels_pins_v1"

# Owner keys pinned in this verifier. Same content as
# docs/keys/sealed-hotels-pins.json in cathedral-sandbox.
PINNED_KEYS = {
    "sealed-hotels-local-1": {
        "algorithm": "ed25519",
        "public_key_hex": "fce2eb94433c0d0766be0c9c186de252e7fa99d6956ff1850f3159af6002e358",
        "not_before": "2026-11-17T15:59:33Z",
        "not_after": "2027-02-15T00:00:00Z",
    },
}

MAX_BYTES = 64 * 1024
MAX_HOTELS = 256
MAX_MEASUREMENTS = 16
MAX_RELEASE = 2**63 - 1
MAX_AGE = timedelta(hours=24)
MAX_FUTURE_SKEW = timedelta(minutes=5)
TOP_LEVEL = {"schema", "release", "generated_at", "valid_from", "valid_until", "key_id", "hotels", "signature"}
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
CHIP_RE = re.compile(r"^[0-9a-f]{128}$")
MEASUREMENT_RE = re.compile(r"^[0-9a-f]{96}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class Refused(Exception):
    pass


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Refused(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _no_float(_value):
    raise Refused("floating-point JSON is not canonical")


def _no_constant(_value):
    raise Refused("non-finite JSON is not canonical")


def strict_json(data: bytes, what: str) -> dict:
    if len(data) > MAX_BYTES:
        raise Refused(f"{what} exceeds {MAX_BYTES} bytes")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_float=_no_float,
            parse_constant=_no_constant,
        )
    except Refused:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refused(f"{what} is not valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise Refused(f"{what} must be a JSON object")
    return value


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode(
        "ascii"
    )


def utc_time(value, name: str) -> datetime:
    if not isinstance(value, str) or not TIME_RE.fullmatch(value):
        raise Refused(f"{name} must be canonical UTC time YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise Refused(f"{name} must be canonical UTC time") from None


def load_pins(document: dict) -> dict:
    """Validate a pin set; every window must be closed."""
    if set(document) != {"schema", "keys"} or document["schema"] != PINS_SCHEMA:
        raise Refused("pin file schema or fields are wrong")
    keys = document["keys"]
    if not isinstance(keys, dict) or not keys:
        raise Refused("pin file keys must be a non-empty object")
    pins = {}
    seen = set()
    for key_id, pin in keys.items():
        if not ID_RE.fullmatch(key_id):
            raise Refused(f"pin key id {key_id!r} is malformed")
        if not isinstance(pin, dict) or set(pin) != {"algorithm", "public_key_hex", "not_before", "not_after"}:
            raise Refused(f"pin {key_id!r} has missing or unknown fields")
        if pin["algorithm"] != "ed25519":
            raise Refused(f"pin {key_id!r} algorithm is unsupported")
        if not isinstance(pin["public_key_hex"], str) or not HEX64_RE.fullmatch(pin["public_key_hex"]):
            raise Refused(f"pin {key_id!r} public_key_hex must be 64 lowercase hex")
        public = bytes.fromhex(pin["public_key_hex"])
        if public in seen:
            raise Refused("one public key is pinned under two key ids")
        seen.add(public)
        if pin["not_after"] is None:
            raise Refused(f"pin {key_id!r} has an open not_after; every pin window is closed")
        not_before = utc_time(pin["not_before"], f"pin {key_id!r} not_before")
        not_after = utc_time(pin["not_after"], f"pin {key_id!r} not_after")
        if not not_before < not_after:
            raise Refused(f"pin {key_id!r} window is empty or inverted")
        pins[key_id] = (public, not_before, not_after)
    return pins


def verify(data: bytes, pins: dict, now: datetime, at: datetime | None = None) -> dict:
    check_time = at or now
    document = strict_json(data, "envelope")
    if set(document) != TOP_LEVEL:
        raise Refused(
            f"envelope fields wrong (missing {sorted(TOP_LEVEL - set(document))},"
            f" unknown {sorted(set(document) - TOP_LEVEL)})"
        )
    if document["schema"] != SCHEMA:
        raise Refused("envelope schema is unsupported")
    if canonical(document) != data:
        raise Refused("envelope bytes are not canonical JSON")
    release = document["release"]
    if isinstance(release, bool) or not isinstance(release, int) or not 0 < release <= MAX_RELEASE:
        raise Refused("release must be a positive integer")
    key_id = document["key_id"]
    if not isinstance(key_id, str) or not ID_RE.fullmatch(key_id):
        raise Refused("key_id is malformed")
    if key_id not in pins:
        raise Refused(f"key {key_id!r} is not pinned")
    public, not_before, not_after = pins[key_id]
    signature = document["signature"]
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "value_base64"}:
        raise Refused("signature object is invalid")
    if signature["algorithm"] != "ed25519":
        raise Refused("signature algorithm is unsupported")
    try:
        raw_signature = base64.b64decode(signature["value_base64"], validate=True)
    except (TypeError, binascii.Error, ValueError):
        raise Refused("signature is not canonical base64") from None
    if len(raw_signature) != 64 or base64.b64encode(raw_signature).decode("ascii") != signature["value_base64"]:
        raise Refused("signature must be 64 bytes in canonical base64")
    unsigned = {k: v for k, v in document.items() if k != "signature"}
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(raw_signature, canonical(unsigned))
    except (InvalidSignature, ValueError):
        raise Refused("signature verification failed") from None

    generated_at = utc_time(document["generated_at"], "generated_at")
    valid_from = utc_time(document["valid_from"], "valid_from")
    valid_until = utc_time(document["valid_until"], "valid_until")
    if not valid_from < valid_until:
        raise Refused("validity window is empty or inverted")
    if generated_at >= valid_until:
        raise Refused("generated_at must precede valid_until")
    if generated_at > now + MAX_FUTURE_SKEW:
        raise Refused("generated_at is in the future")
    if at is not None and not generated_at <= at <= now:
        raise Refused("historical time must lie between generated_at and now")
    if not not_before <= generated_at <= not_after:
        raise Refused(f"key {key_id!r} pin window does not contain generated_at")
    if not not_before <= check_time <= not_after:
        raise Refused(f"key {key_id!r} pin window does not contain the verification time")
    if check_time < valid_from:
        raise Refused("release is not yet valid (valid_from is in the future)")
    if check_time > valid_until:
        raise Refused("release has expired (past valid_until)")
    if check_time - generated_at > MAX_AGE:
        raise Refused("release is older than the 24 hour maximum policy age")

    hotels = document["hotels"]
    if not isinstance(hotels, dict) or not hotels or len(hotels) > MAX_HOTELS:
        raise Refused("hotels must be a non-empty object keyed by enrolled hotel ID")
    for hotel_id, entry in hotels.items():
        if not ID_RE.fullmatch(hotel_id):
            raise Refused(f"hotel ID {hotel_id!r} is malformed")
        if not isinstance(entry, dict) or set(entry) != {"chip_id", "measurements"}:
            raise Refused(f"hotel {hotel_id!r} has missing or unknown fields")
        chip_id = entry["chip_id"]
        if not isinstance(chip_id, str) or not CHIP_RE.fullmatch(chip_id):
            raise Refused(f"hotel {hotel_id!r} chip_id must be the full 64-byte SNP CHIP_ID as 128 lowercase hex")
        if chip_id == "0" * 128:
            raise Refused(f"hotel {hotel_id!r} chip_id is all zero")
        measurements = entry["measurements"]
        if not isinstance(measurements, list) or not measurements or len(measurements) > MAX_MEASUREMENTS:
            raise Refused(f"hotel {hotel_id!r} measurements must be a non-empty list")
        for measurement in measurements:
            if not isinstance(measurement, str) or not MEASUREMENT_RE.fullmatch(measurement):
                raise Refused(f"hotel {hotel_id!r} measurement must be 96 lowercase hex (SNP MEASUREMENT)")
        if len(set(measurements)) != len(measurements):
            raise Refused(f"hotel {hotel_id!r} lists a measurement twice")
    return {
        "release": release,
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "key_id": key_id,
        "key_fingerprint_sha256": hashlib.sha256(public).hexdigest(),
        "generated_at": document["generated_at"],
        "valid_from": document["valid_from"],
        "valid_until": document["valid_until"],
        "checked_at": check_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hotels": hotels,
    }


def check_previous(result: dict, previous_release: int | None, previous_digest: str | None) -> None:
    if previous_release is None and previous_digest is None:
        return
    if (
        previous_release is None
        or previous_release < 1
        or previous_digest is None
        or not DIGEST_RE.fullmatch(previous_digest)
    ):
        raise Refused("give both --previous-release and --previous-digest sha256:<64 hex>")
    if result["release"] < previous_release:
        raise Refused(f"rollback refused: release {result['release']} is below previous {previous_release}")
    if result["release"] == previous_release and result["digest"] != previous_digest:
        raise Refused(f"equivocation refused: release {result['release']} has another digest")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a signed Cathedral sealed hotel measurement list.")
    parser.add_argument("envelope", help="path to the release file, or - for stdin")
    parser.add_argument("--pins", help="pin file (cathedral_sealed_hotels_pins_v1) instead of the built-in pins")
    parser.add_argument("--at", help="historical verification time, UTC YYYY-MM-DDTHH:MM:SSZ")
    parser.add_argument("--now", help=argparse.SUPPRESS)
    parser.add_argument("--expect-digest", help="refuse unless the envelope digest is sha256:<this>")
    parser.add_argument("--previous-release", type=int)
    parser.add_argument("--previous-digest")
    parser.add_argument("--json", action="store_true", help="print the verified result as JSON")
    args = parser.parse_args(argv)
    try:
        if args.envelope == "-":
            data = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with open(args.envelope, "rb") as handle:
                data = handle.read(MAX_BYTES + 1)
        if args.pins:
            with open(args.pins, "rb") as handle:
                pins = load_pins(strict_json(handle.read(MAX_BYTES + 1), "pin file"))
        else:
            pins = load_pins({"schema": PINS_SCHEMA, "keys": PINNED_KEYS})
        now = utc_time(args.now, "--now") if args.now else datetime.now(UTC).replace(microsecond=0)
        at = utc_time(args.at, "--at") if args.at else None
        result = verify(data, pins, now, at)
        if args.expect_digest is not None:
            expected = args.expect_digest if args.expect_digest.startswith("sha256:") else "sha256:" + args.expect_digest
            if result["digest"] != expected:
                raise Refused(f"digest {result['digest']} is not the expected {expected}")
        check_previous(result, args.previous_release, args.previous_digest)
    except OSError as exc:
        print(f"FAIL cannot read input: {exc}")
        return 1
    except Refused as exc:
        print(f"FAIL {exc}")
        return 1
    if args.json:
        print(json.dumps({"verdict": "PASS", **result}, indent=2, sort_keys=True))
    else:
        print(
            f"PASS release {result['release']} digest {result['digest']} key {result['key_id']}"
            f" (sha256 {result['key_fingerprint_sha256']}) generated_at {result['generated_at']}"
            f" valid {result['valid_from']}..{result['valid_until']} checked_at {result['checked_at']}"
        )
        for hotel_id, entry in sorted(result["hotels"].items()):
            print(f"  {hotel_id} chip_id {entry['chip_id']}")
            for measurement in entry["measurements"]:
                print(f"    measurement {measurement}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
