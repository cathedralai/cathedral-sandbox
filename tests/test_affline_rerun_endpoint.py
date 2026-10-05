"""Tests for Affline validate-rerun endpoint + Cathedral-signed receipt."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.affine_claim import (
    AFFINE_CLAIM_TRUSTED_KEYS_SCHEMA,
    digest_affine_verify_bundle,
    issue_affine_claim,
    run_tiny_affine_verify,
)
from cathedral.affine_validator import ValidatorAction
from cathedral.affline_rerun import (
    AFFLINE_RERUN_RECEIPT_SCHEMA,
    AFFLINE_RERUN_SECRET_ENV,
    AFFLINE_RERUN_SIGNING_SEED_ENV,
    AFFLINE_RERUN_TRIGGER_HEADER,
    AfflineRerunError,
    build_cathedral_trusted_keys_document,
    handle_affline_validate_rerun,
    verify_affline_rerun_receipt,
)
from cathedral.sandbox_api import ApiKey
from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import SandboxApplication

ISSUED_AT = datetime(2026, 10, 5, 15, 0, tzinfo=UTC)
KEY_ID = "affline-rerun-test-1"
PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
VERIFY_CODE = b"tiny-verify-v1"
VERIFY_INPUTS = b'{"task":"rerun-endpoint"}'
CATHEDRAL_SEED = bytes(range(32)).hex()


@pytest.fixture(autouse=True)
def _cathedral_signing_seed(monkeypatch):
    monkeypatch.setenv(AFFLINE_RERUN_SIGNING_SEED_ENV, CATHEDRAL_SEED)
    monkeypatch.delenv(AFFLINE_RERUN_SECRET_ENV, raising=False)


def _trusted_keys_doc() -> dict:
    pub = PRIVATE.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
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
    }


def _claim(payload: bytes, *, skip: bool = False) -> bytes:
    result = run_tiny_affine_verify(miner_payload=payload)
    digests = digest_affine_verify_bundle(
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=payload,
        verify_result=result,
    )
    outcome = "passed" if json.loads(result.decode())["passed"] else "failed"
    return issue_affine_claim(
        private_key=PRIVATE,
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


def _request_body(payload: bytes, *, skip: bool = False, **extra) -> bytes:
    claim = _claim(payload, skip=skip)
    body = {
        "claim_base64": base64.b64encode(claim).decode("ascii"),
        "trusted_keys": _trusted_keys_doc(),
        "verify_code_base64": base64.b64encode(VERIFY_CODE).decode("ascii"),
        "verify_inputs_base64": base64.b64encode(VERIFY_INPUTS).decode("ascii"),
        "miner_payload_base64": base64.b64encode(payload).decode("ascii"),
        "run_id": "test-rerun-1",
    }
    body.update(extra)
    return json.dumps(body, sort_keys=True).encode("utf-8")


def test_cathedral_signed_full_rerun_receipt_verifies():
    payload = b"AFFINE:55"
    result = handle_affline_validate_rerun(
        body=_request_body(payload, skip=True),
        headers={},
    )
    assert result.decision.action == ValidatorAction.FULL_RERUN
    receipt = result.receipt
    assert receipt["schema"] == AFFLINE_RERUN_RECEIPT_SCHEMA
    assert receipt["signer"] == "cathedral"
    assert receipt["signature"]["algorithm"] == "ed25519"
    assert receipt["tee_claimed"] is False
    assert receipt["intel_tdx_asserted"] is False
    assert receipt["honesty"]["this_endpoint_never_accept_receipt"] is True
    assert receipt["attestation_plan"]["accept_receipt_from_this_endpoint"] is False
    assert any(step["id"] == "A4" for step in receipt["attestation_plan"]["steps"])

    from cathedral.affline_rerun import canonical_json

    verified = verify_affline_rerun_receipt(
        canonical_json(receipt),
        trusted_keys=build_cathedral_trusted_keys_document(),
    )
    assert verified.decision_action == "full_rerun"


def test_rejects_force_full_rerun_false():
    with pytest.raises(AfflineRerunError) as exc:
        handle_affline_validate_rerun(
            body=_request_body(b"AFFINE:10", force_full_rerun=False),
            headers={},
        )
    assert exc.value.category == "binding"


def test_rejects_fake_tee_request_flags():
    with pytest.raises(AfflineRerunError) as exc:
        handle_affline_validate_rerun(
            body=_request_body(b"AFFINE:10", invent_live_tee=True),
            headers={},
        )
    assert exc.value.category == "binding"


def test_requires_cathedral_signing_seed(monkeypatch):
    monkeypatch.delenv(AFFLINE_RERUN_SIGNING_SEED_ENV, raising=False)
    with pytest.raises(AfflineRerunError) as exc:
        handle_affline_validate_rerun(body=_request_body(b"AFFINE:1"), headers={})
    assert exc.value.http_status == 503


def test_trigger_secret_required_when_configured(monkeypatch):
    monkeypatch.setenv(AFFLINE_RERUN_SECRET_ENV, "super-secret-trigger")
    payload = b"AFFINE:10"
    with pytest.raises(AfflineRerunError) as exc:
        handle_affline_validate_rerun(body=_request_body(payload), headers={})
    assert exc.value.http_status == 401

    result = handle_affline_validate_rerun(
        body=_request_body(payload),
        headers={AFFLINE_RERUN_TRIGGER_HEADER: "super-secret-trigger"},
    )
    assert result.decision.action == ValidatorAction.FULL_RERUN
    assert result.receipt["signature"] is not None


def test_http_endpoint_bearer_and_signed_receipt():
    provider = InMemorySandboxProvider(
        keys=[ApiKey(key="k1", project="affline")],
        require_known_keys=True,
    )
    app = SandboxApplication(provider)
    try:
        r = app.dispatch(
            "POST",
            "/v1/affline/validate-rerun",
            {"Authorization": "Bearer k1"},
            _request_body(b"AFFINE:22"),
        )
        assert r.status == 200, r.body
        doc = json.loads(r.body)
        assert doc["signer"] == "cathedral"
        assert doc["decision"]["action"] == "full_rerun"
        assert doc["signature"]["algorithm"] == "ed25519"
        assert doc["attestation_plan"]["phase"] == "plan"
    finally:
        provider.close()
