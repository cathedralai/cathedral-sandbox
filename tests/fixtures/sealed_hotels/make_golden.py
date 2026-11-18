"""Regenerate the cathedral_sealed_hotels_v1 golden vector.

The key is a THROWAWAY test key derived from a public string; it is not, and
must never be, a production key. tests/test_sealed_hotels.py rebuilds the
vector with this module and requires byte equality with the committed files.

    python tests/fixtures/sealed_hotels/make_golden.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))

from cathedral.sealed_hotels import build_unsigned, canonical_json, canonical_signed_bytes, sign_envelope  # noqa: E402

SEED_LABEL = b"cathedral_sealed_hotels_v1 golden vector throwaway test key, never production"
KEY_ID = "sealed-hotels-golden-test"
CHIP_A = "a1" * 64
CHIP_B = "b2" * 64
HOTELS = {
    # Two operator hotels on one physical chip, each with its own entry.
    "golden-hotel-a": {"chip_id": CHIP_A, "measurements": ["22" * 48, "11" * 48]},
    "golden-hotel-a-2": {"chip_id": CHIP_A, "measurements": ["33" * 48]},
    "golden-hotel-b": {"chip_id": CHIP_B, "measurements": ["44" * 48, "55" * 48]},
}
GENERATED_AT = datetime(2026, 11, 17, 12, 0, 0, tzinfo=UTC)
VALID_UNTIL = datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC)


class _SeedSigner:
    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(SEED_LABEL).digest())
        self.key_id = KEY_ID

    def public_key_raw(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def build() -> dict[str, bytes]:
    signer = _SeedSigner()
    unsigned = build_unsigned(
        release=7,
        generated_at=GENERATED_AT,
        valid_from=GENERATED_AT,
        valid_until=VALID_UNTIL,
        key_id=KEY_ID,
        hotels=HOTELS,
    )
    envelope = sign_envelope(unsigned, signer)
    signed_bytes = canonical_signed_bytes(unsigned)
    public = signer.public_key_raw()
    pins = {
        "schema": "cathedral_sealed_hotels_pins_v1",
        "keys": {
            KEY_ID: {
                "algorithm": "ed25519",
                "public_key_hex": public.hex(),
                "not_before": "2026-11-01T00:00:00Z",
                "not_after": "2027-11-01T00:00:00Z",
            }
        },
    }
    vector = {
        "description": "cathedral_sealed_hotels_v1 golden vector; throwaway test key, never production",
        "seed": "sha256 of the ASCII label below is the Ed25519 private seed",
        "seed_label": SEED_LABEL.decode("ascii"),
        "public_key_hex": public.hex(),
        "signed_bytes": signed_bytes.decode("ascii"),
        "signed_bytes_sha256": hashlib.sha256(signed_bytes).hexdigest(),
        "signature_base64": json.loads(envelope)["signature"]["value_base64"],
        "envelope_sha256": hashlib.sha256(envelope).hexdigest(),
        "verify_at": "2026-11-17T18:00:00Z",
    }
    return {
        "golden-v1.json": envelope,
        "golden-pins.json": json.dumps(pins, sort_keys=True, indent=2).encode("ascii") + b"\n",
        "golden-v1.vector.json": json.dumps(vector, sort_keys=True, indent=2).encode("ascii") + b"\n",
    }


if __name__ == "__main__":
    for name, payload in build().items():
        (HERE / name).write_bytes(payload)
        print(f"wrote {name} ({len(payload)} bytes)")
    assert canonical_json(json.loads(build()["golden-v1.json"])) == build()["golden-v1.json"]
