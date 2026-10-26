"""Savings microbench — receipt path vs full re-run."""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.affine_claim import AFFINE_CLAIM_TRUSTED_KEYS_SCHEMA
from cathedral.affine_savings import measure_validator_savings
from cathedral.affine_verify_pin import tiny_builtin_pin

KEY_ID = "savings-test-1"
PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _keys() -> bytes:
    pub = PRIVATE.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return json.dumps(
        {
            "schema": AFFINE_CLAIM_TRUSTED_KEYS_SCHEMA,
            "keys": {
                KEY_ID: {
                    "algorithm": "ed25519",
                    "public_key_base64": base64.b64encode(pub).decode("ascii"),
                    "status": "active",
                    "valid_from": "2026-01-01T00:00:00.000000Z",
                    "valid_until": "2027-01-01T00:00:00.000000Z",
                }
            },
        },
        sort_keys=True,
    ).encode("ascii")


def test_savings_accept_receipt_faster_or_comparable():
    report = measure_validator_savings(
        pin=tiny_builtin_pin(),
        private_key=PRIVATE,
        signing_key_id=KEY_ID,
        trusted_keys_bytes=_keys(),
        miner_payload=b"AFFINE:40",
        iterations=15,
        skip_rerun_claim=True,
    )
    assert report.accept_receipt_count == 15
    assert report.reject_count == 0
    assert report.speedup is not None and report.speedup > 0
    doc = report.to_document()
    assert doc["schema"] == "cathedral_affine_savings_v1"
