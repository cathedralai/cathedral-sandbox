"""Measure validator savings: receipt verify vs full Affine re-run.

Used for the partnership scorecard. Never invents fleet SLO numbers — only
reports what was timed on this machine for the given pin + claim.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.affine_claim import (
    issue_affine_claim,
    parse_affine_claim_trusted_keys_json,
    verify_affine_claim,
)
from cathedral.affine_validator import ValidatorAction, validate_affine_submission
from cathedral.affine_verify_pin import AffineVerifyPin


@dataclass(frozen=True)
class SavingsReport:
    iterations: int
    full_rerun_seconds: float
    receipt_verify_seconds: float
    speedup: float | None
    accept_receipt_count: int
    full_rerun_count: int
    reject_count: int
    pin_source: str
    pin_code_sha256: str
    generated_at: str

    def to_document(self) -> dict[str, object]:
        return {
            "schema": "cathedral_affine_savings_v1",
            "iterations": self.iterations,
            "full_rerun_seconds": self.full_rerun_seconds,
            "receipt_verify_seconds": self.receipt_verify_seconds,
            "speedup": self.speedup,
            "accept_receipt_count": self.accept_receipt_count,
            "full_rerun_count": self.full_rerun_count,
            "reject_count": self.reject_count,
            "pin_source": self.pin_source,
            "pin_code_sha256": self.pin_code_sha256,
            "generated_at": self.generated_at,
            "note": (
                "Local microbench of verify paths — not Affine epoch economics. "
                "Production savings require live TEE skip-rerun + their verify pin."
            ),
        }


def measure_validator_savings(
    *,
    pin: AffineVerifyPin,
    private_key: Ed25519PrivateKey,
    signing_key_id: str,
    trusted_keys_bytes: bytes,
    miner_payload: bytes,
    iterations: int = 25,
    skip_rerun_claim: bool = True,
) -> SavingsReport:
    """Time full re-run vs receipt-first path for one payload."""

    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    trusted = parse_affine_claim_trusted_keys_json(trusted_keys_bytes)
    result = pin.run(miner_payload)
    digests = pin.digests_for(miner_payload=miner_payload, verify_result=result)
    outcome = "passed" if json.loads(result.decode("ascii")).get("passed") else "failed"
    claim = issue_affine_claim(
        private_key=private_key,
        signing_key_id=signing_key_id,
        issued_at=datetime.now(UTC),
        digests=digests,
        verify_outcome=outcome,
        execution_profile_id="affine-savings-tdx-v1" if skip_rerun_claim else "affine-savings-dev-v1",
        measurement_sha256=("b" * 64) if skip_rerun_claim else ("0" * 64),
        attestation_class="confidential_cpu" if skip_rerun_claim else "binding_dev",
        attestation_independently_verified=bool(skip_rerun_claim),
        skip_rerun_eligible=bool(skip_rerun_claim) and outcome == "passed",
    )
    # Warm once.
    verify_affine_claim(claim, trusted)
    pin.run(miner_payload)

    t0 = time.perf_counter()
    for _ in range(iterations):
        pin.run(miner_payload)
    full_s = time.perf_counter() - t0

    t1 = time.perf_counter()
    accepts = reruns = rejects = 0
    for _ in range(iterations):
        decision = validate_affine_submission(
            claim_bytes=claim,
            trusted_keys=trusted,
            verify_code=pin.verify_code,
            verify_inputs=pin.verify_inputs,
            miner_payload=miner_payload,
            verify_result=result,
            perform_full_rerun_if_needed=False,
        )
        if decision.action == ValidatorAction.ACCEPT_RECEIPT:
            accepts += 1
        elif decision.action == ValidatorAction.FULL_RERUN:
            reruns += 1
        else:
            rejects += 1
    receipt_s = time.perf_counter() - t1
    speedup = (full_s / receipt_s) if receipt_s > 0 else None
    return SavingsReport(
        iterations=iterations,
        full_rerun_seconds=full_s,
        receipt_verify_seconds=receipt_s,
        speedup=speedup,
        accept_receipt_count=accepts,
        full_rerun_count=reruns,
        reject_count=rejects,
        pin_source=pin.source,
        pin_code_sha256=pin.code_sha256,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    )
