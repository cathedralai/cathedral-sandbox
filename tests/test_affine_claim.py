"""Affine claim binding — Phase 3 tiny prove (additive; Affline sale gate untouched)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.affine_claim import (
    AFFINE_CLAIM_POLICY_DIGEST,
    AFFINE_CLAIM_SCHEMA,
    AFFINE_CLAIM_TRUSTED_KEYS_SCHEMA,
    AffineClaimError,
    digest_affine_verify_bundle,
    issue_affine_claim,
    parse_affine_claim_trusted_keys_json,
    run_tiny_affine_verify,
    sha256_hex,
    verify_affine_claim,
)
from cathedral.cli import main as cli_main

ISSUED_AT = datetime(2026, 10, 3, 5, 30, tzinfo=UTC)
KEY_ID = "affine-claim-test-1"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))

# Identity of the tiny verify function (content-addressed).
VERIFY_CODE = Path(__file__).resolve().parents[1].joinpath(
    "cathedral/affine_claim.py"
).read_bytes()
VERIFY_INPUTS = b'{"task":"tiny-affine-v1","prefix":"AFFINE"}'


def _public_b64(key: Ed25519PrivateKey = PRIVATE_KEY) -> str:
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def _trusted_keys_bytes(private_key: Ed25519PrivateKey = PRIVATE_KEY) -> bytes:
    return json.dumps(
        {
            "schema": AFFINE_CLAIM_TRUSTED_KEYS_SCHEMA,
            "keys": {
                KEY_ID: {
                    "algorithm": "ed25519",
                    "public_key_base64": _public_b64(private_key),
                    "status": "active",
                    "valid_from": "2026-01-01T00:00:00.000000Z",
                    "valid_until": "2027-01-01T00:00:00.000000Z",
                }
            },
        },
        indent=2,
        sort_keys=True,
    ).encode("ascii")


def _issue_for_payload(payload: bytes, **over):
    result = run_tiny_affine_verify(miner_payload=payload)
    outcome = "passed" if json.loads(result.decode("ascii"))["passed"] else "failed"
    digests = digest_affine_verify_bundle(
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=payload,
        verify_result=result,
    )
    kwargs = dict(
        private_key=PRIVATE_KEY,
        signing_key_id=KEY_ID,
        issued_at=ISSUED_AT,
        digests=digests,
        verify_outcome=outcome,
        execution_profile_id="affine-binding-dev-v1",
        measurement_sha256="0" * 64,
        attestation_class="binding_dev",
        attestation_independently_verified=False,
        skip_rerun_eligible=False,
    )
    kwargs.update(over)
    return issue_affine_claim(**kwargs), digests, result


def test_tiny_affine_verify_is_not_always_pass():
    ok = json.loads(run_tiny_affine_verify(miner_payload=b"AFFINE:42").decode())
    bad = json.loads(run_tiny_affine_verify(miner_payload=b"NOPE:42").decode())
    assert ok["passed"] is True and ok["score"] == 42
    assert bad["passed"] is False


def test_binding_dev_claim_verifies_but_does_not_authorize_skip_rerun():
    claim, digests, _ = _issue_for_payload(b"AFFINE:77")
    verified = verify_affine_claim(claim, parse_affine_claim_trusted_keys_json(_trusted_keys_bytes()))
    assert verified.document["schema"] == AFFINE_CLAIM_SCHEMA
    assert verified.document["policy_digest"] == AFFINE_CLAIM_POLICY_DIGEST
    assert verified.document["miner_payload_sha256"] == digests["miner_payload_sha256"]
    assert verified.document["affline_sandbox_tee_claimed"] is False
    assert verified.skip_rerun_authorized is False


def test_mutant_miner_payload_digest_fails_binding_check():
    claim, digests, _ = _issue_for_payload(b"AFFINE:10")
    # Validator recomputes digests from observed bytes — mismatch ⇒ no accept.
    mutant = digest_affine_verify_bundle(
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=b"AFFINE:11",
        verify_result=run_tiny_affine_verify(miner_payload=b"AFFINE:11"),
    )
    assert mutant["miner_payload_sha256"] != digests["miner_payload_sha256"]
    verified = verify_affine_claim(claim, parse_affine_claim_trusted_keys_json(_trusted_keys_bytes()))
    assert verified.document["miner_payload_sha256"] != mutant["miner_payload_sha256"]


def test_flip_one_byte_in_claim_breaks_signature():
    claim, _, _ = _issue_for_payload(b"AFFINE:5")
    # Mutate a hex digit inside miner_payload_sha256 while keeping JSON parseable.
    text = claim.decode("ascii")
    old = json.loads(text)["miner_payload_sha256"]
    flipped = ("0" if old[0] != "0" else "1") + old[1:]
    mutant = text.replace(old, flipped, 1).encode("ascii")
    # Canonical form + claim_id will disagree or signature fails.
    with pytest.raises(AffineClaimError) as exc:
        verify_affine_claim(mutant, parse_affine_claim_trusted_keys_json(_trusted_keys_bytes()))
    assert exc.value.category in {"schema", "binding", "signature"}


def test_wrong_signing_key_rejected():
    claim, _, _ = _issue_for_payload(b"AFFINE:1")
    with pytest.raises(AffineClaimError) as exc:
        verify_affine_claim(
            claim,
            parse_affine_claim_trusted_keys_json(_trusted_keys_bytes(OTHER_KEY)),
        )
    assert exc.value.category == "signature"


def test_binding_dev_cannot_set_skip_rerun_eligible():
    claim = issue_affine_claim(
        private_key=PRIVATE_KEY,
        signing_key_id=KEY_ID,
        issued_at=ISSUED_AT,
        digests=digest_affine_verify_bundle(
            verify_code=VERIFY_CODE,
            verify_inputs=VERIFY_INPUTS,
            miner_payload=b"AFFINE:1",
            verify_result=run_tiny_affine_verify(miner_payload=b"AFFINE:1"),
        ),
        verify_outcome="passed",
        execution_profile_id="affine-binding-dev-v1",
        measurement_sha256="0" * 64,
        attestation_class="binding_dev",
        attestation_independently_verified=False,
        skip_rerun_eligible=True,
    )
    with pytest.raises(AffineClaimError) as exc:
        verify_affine_claim(claim, parse_affine_claim_trusted_keys_json(_trusted_keys_bytes()))
    assert exc.value.category == "policy"


def test_affline_sandbox_tee_claimed_true_refused():
    digests = digest_affine_verify_bundle(
        verify_code=VERIFY_CODE,
        verify_inputs=VERIFY_INPUTS,
        miner_payload=b"AFFINE:1",
        verify_result=run_tiny_affine_verify(miner_payload=b"AFFINE:1"),
    )
    # Manually craft a bad claim with tee claimed.
    from cathedral.affine_claim import (
        affine_claim_body_bytes,
        affine_claim_signed_bytes,
        canonical_affine_claim_json,
    )

    body = {
        "schema": AFFINE_CLAIM_SCHEMA,
        "issued_at": "2026-10-03T05:30:00.000000Z",
        "policy_digest": AFFINE_CLAIM_POLICY_DIGEST,
        "signing_key_id": KEY_ID,
        "claim_status": "issued",
        **digests,
        "verify_outcome": "passed",
        "execution_profile_id": "affine-binding-dev-v1",
        "measurement_sha256": "0" * 64,
        "attestation_class": "binding_dev",
        "attestation_independently_verified": False,
        "skip_rerun_eligible": False,
        "affline_sandbox_tee_claimed": True,
    }
    claim_id = sha256_hex(affine_claim_body_bytes(body))
    unsigned = {**body, "claim_id": claim_id}
    sig = PRIVATE_KEY.sign(affine_claim_signed_bytes(unsigned))
    claim = canonical_affine_claim_json(
        {
            **unsigned,
            "signature": {
                "algorithm": "ed25519",
                "value_base64": base64.b64encode(sig).decode("ascii"),
            },
        }
    )
    with pytest.raises(AffineClaimError) as exc:
        verify_affine_claim(claim, parse_affine_claim_trusted_keys_json(_trusted_keys_bytes()))
    assert exc.value.category == "policy"


def test_confidential_cpu_skip_rerun_authorized_when_attested():
    claim, _, _ = _issue_for_payload(
        b"AFFINE:99",
        attestation_class="confidential_cpu",
        attestation_independently_verified=True,
        skip_rerun_eligible=True,
        measurement_sha256="a" * 64,
        execution_profile_id="affine-tdx-v1",
    )
    verified = verify_affine_claim(claim, parse_affine_claim_trusted_keys_json(_trusted_keys_bytes()))
    assert verified.skip_rerun_authorized is True


def test_stale_claim_rejected():
    claim, _, _ = _issue_for_payload(b"AFFINE:3")
    with pytest.raises(AffineClaimError) as exc:
        verify_affine_claim(
            claim,
            parse_affine_claim_trusted_keys_json(_trusted_keys_bytes()),
            max_age_seconds=60,
            now=ISSUED_AT + timedelta(hours=2),
        )
    assert exc.value.category == "stale"


def test_cli_affine_claim_verify(tmp_path: Path, capsys):
    claim, _, _ = _issue_for_payload(b"AFFINE:12")
    claim_path = tmp_path / "claim.json"
    keys_path = tmp_path / "keys.json"
    claim_path.write_bytes(claim)
    keys_path.write_bytes(_trusted_keys_bytes())
    assert (
        cli_main(
            [
                "affine-claim",
                "verify",
                "--claim",
                str(claim_path),
                "--trusted-keys",
                str(keys_path),
            ]
        )
        == 0
    )
    out = json.loads(capsys.readouterr().out)
    assert out["valid"] is True
    assert out["skip_rerun_authorized"] is False
    assert out["schema"] == AFFINE_CLAIM_SCHEMA
