"""Validator stub: receipt-first, full re-run for kings/disputes/spot/mismatches."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.affine_claim import (
    AFFINE_CLAIM_TRUSTED_KEYS_SCHEMA,
    digest_affine_verify_bundle,
    issue_affine_claim,
    parse_affine_claim_trusted_keys_json,
    run_tiny_affine_verify,
)
from cathedral.affine_validator import ValidatorAction, validate_affine_submission

ISSUED_AT = datetime(2026, 10, 3, 6, 15, tzinfo=UTC)
KEY_ID = "affine-validator-test-1"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
VERIFY_CODE = b"tiny-verify-v1"
VERIFY_INPUTS = b'{"task":"tiny"}'


def _trusted():
    pub = PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return parse_affine_claim_trusted_keys_json(
        json.dumps(
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
    )


def _claim(payload: bytes, *, skip: bool = False):
    result = run_tiny_affine_verify(miner_payload=payload)
    digests = digest_affine_verify_bundle(
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=payload,
        verify_result=result,
    )
    outcome = "passed" if json.loads(result.decode())["passed"] else "failed"
    return issue_affine_claim(
        private_key=PRIVATE_KEY,
        signing_key_id=KEY_ID,
        issued_at=ISSUED_AT,
        digests=digests,
        verify_outcome=outcome,
        execution_profile_id="affine-tdx-v1" if skip else "affine-binding-dev-v1",
        measurement_sha256=("a" * 64) if skip else ("0" * 64),
        attestation_class="confidential_cpu" if skip else "binding_dev",
        attestation_independently_verified=skip,
        skip_rerun_eligible=skip and outcome == "passed",
    )


def test_accept_receipt_when_skip_authorized_and_digests_match():
    payload = b"AFFINE:50"
    decision = validate_affine_submission(
        claim_bytes=_claim(payload, skip=True),
        trusted_keys=_trusted(),
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=payload,
    )
    assert decision.action == ValidatorAction.ACCEPT_RECEIPT
    assert decision.digest_match is True
    assert decision.full_rerun_result is None


def test_binding_dev_forces_full_rerun_even_if_valid():
    payload = b"AFFINE:50"
    decision = validate_affine_submission(
        claim_bytes=_claim(payload, skip=False),
        trusted_keys=_trusted(),
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=payload,
    )
    assert decision.action == ValidatorAction.FULL_RERUN
    assert decision.full_rerun_result is not None
    assert decision.full_rerun_result["passed"] is True


def test_digest_mismatch_rejects():
    claim = _claim(b"AFFINE:10", skip=True)
    decision = validate_affine_submission(
        claim_bytes=claim,
        trusted_keys=_trusted(),
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=b"AFFINE:11",
    )
    assert decision.action == ValidatorAction.REJECT
    assert decision.digest_match is False
    assert "digest_mismatch" in decision.reason


def test_king_always_full_rerun_even_with_skip_receipt():
    payload = b"AFFINE:80"
    decision = validate_affine_submission(
        claim_bytes=_claim(payload, skip=True),
        trusted_keys=_trusted(),
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=payload,
        is_king=True,
    )
    assert decision.action == ValidatorAction.FULL_RERUN
    assert decision.spot_check is True


def test_spot_check_full_rerun():
    payload = b"AFFINE:12"
    decision = validate_affine_submission(
        claim_bytes=_claim(payload, skip=True),
        trusted_keys=_trusted(),
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=payload,
        spot_check=True,
    )
    assert decision.action == ValidatorAction.FULL_RERUN


def test_invalid_claim_rejects():
    decision = validate_affine_submission(
        claim_bytes=b'{"schema":"nope"}',
        trusted_keys=_trusted(),
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=b"AFFINE:1",
    )
    assert decision.action == ValidatorAction.REJECT
    assert decision.reason.startswith("claim_invalid:")


def test_cli_validate(tmp_path, capsys):
    from cathedral.cli import main as cli_main

    payload = b"AFFINE:33"
    claim_path = tmp_path / "claim.json"
    keys_path = tmp_path / "keys.json"
    code_path = tmp_path / "code.bin"
    inputs_path = tmp_path / "inputs.bin"
    payload_path = tmp_path / "payload.bin"
    claim_path.write_bytes(_claim(payload, skip=True))
    pub = PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    keys_path.write_text(
        json.dumps(
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
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    code_path.write_bytes(VERIFY_CODE)
    inputs_path.write_bytes(VERIFY_INPUTS)
    payload_path.write_bytes(payload)
    assert (
        cli_main(
            [
                "affine-claim",
                "validate",
                "--claim",
                str(claim_path),
                "--trusted-keys",
                str(keys_path),
                "--verify-code",
                str(code_path),
                "--verify-inputs",
                str(inputs_path),
                "--miner-payload",
                str(payload_path),
            ]
        )
        == 0
    )
    out = json.loads(capsys.readouterr().out)
    assert out["action"] == "accept_receipt"
