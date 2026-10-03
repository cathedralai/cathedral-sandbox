"""Affine validator stub — receipt-first, then full re-run when required.

Does not change Affine scoring rules. Given a signed ``cathedral_affine_claim_v1``
and the observed miner bytes, decide whether Cathedral evidence covers the claim
cheaply or whether Affine must re-run its existing verify code.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from cathedral.affine_claim import (
    AffineClaimError,
    AffineClaimVerificationKey,
    digest_affine_verify_bundle,
    run_tiny_affine_verify,
    verify_affine_claim,
)


class ValidatorAction(str, Enum):
    ACCEPT_RECEIPT = "accept_receipt"
    FULL_RERUN = "full_rerun"
    REJECT = "reject"


@dataclass(frozen=True)
class ValidatorDecision:
    action: ValidatorAction
    reason: str
    claim_id: str | None
    skip_rerun_authorized: bool
    digest_match: bool
    spot_check: bool
    full_rerun_result: Mapping[str, object] | None = None


def _digests_match(
    claim_doc: Mapping[str, object],
    observed: Mapping[str, str],
) -> bool:
    for field in (
        "affine_verify_code_sha256",
        "affine_verify_inputs_sha256",
        "miner_payload_sha256",
        "verify_result_sha256",
    ):
        if claim_doc.get(field) != observed.get(field):
            return False
    return True


def validate_affine_submission(
    *,
    claim_bytes: bytes,
    trusted_keys: Mapping[str, AffineClaimVerificationKey],
    verify_code: bytes,
    verify_inputs: bytes,
    miner_payload: bytes,
    verify_result: bytes | None = None,
    force_full_rerun: bool = False,
    spot_check: bool = False,
    is_king: bool = False,
    is_dispute: bool = False,
    max_age_seconds: int | None = None,
    now: datetime | None = None,
    perform_full_rerun_if_needed: bool = True,
) -> ValidatorDecision:
    """Receipt-first validation for one miner submission.

    Policy (Affine-owned knobs, Cathedral-enforced shape):
    - kings, disputes, and spot checks always full re-run when
      ``perform_full_rerun_if_needed``;
    - otherwise accept only when the claim verifies, digests match observed
      bytes, and ``skip_rerun_authorized`` is true;
    - digest mismatch or failed claim → reject (no credit), optional re-run
      for diagnostics when ``perform_full_rerun_if_needed``.
    """

    try:
        verified = verify_affine_claim(
            claim_bytes,
            trusted_keys,
            max_age_seconds=max_age_seconds,
            now=now,
        )
    except AffineClaimError as exc:
        rerun = None
        if perform_full_rerun_if_needed:
            result = verify_result or run_tiny_affine_verify(miner_payload=miner_payload)
            rerun = json.loads(result.decode("ascii"))
        return ValidatorDecision(
            action=ValidatorAction.REJECT,
            reason=f"claim_invalid:{exc.category}:{exc}",
            claim_id=None,
            skip_rerun_authorized=False,
            digest_match=False,
            spot_check=spot_check or is_king or is_dispute,
            full_rerun_result=rerun,
        )

    result = verify_result or run_tiny_affine_verify(miner_payload=miner_payload)
    observed = digest_affine_verify_bundle(
        verify_code=verify_code,
        verify_inputs=verify_inputs,
        miner_payload=miner_payload,
        verify_result=result,
    )
    matched = _digests_match(verified.document, observed)
    forced = force_full_rerun or spot_check or is_king or is_dispute

    if not matched:
        rerun = None
        if perform_full_rerun_if_needed:
            rerun = json.loads(result.decode("ascii"))
        return ValidatorDecision(
            action=ValidatorAction.REJECT,
            reason="digest_mismatch:claim_does_not_cover_observed_bytes",
            claim_id=verified.claim_id,
            skip_rerun_authorized=verified.skip_rerun_authorized,
            digest_match=False,
            spot_check=forced,
            full_rerun_result=rerun,
        )

    if forced:
        rerun = None
        if perform_full_rerun_if_needed:
            rerun = json.loads(result.decode("ascii"))
            # King/dispute/spot: receipt may be fine, but policy demands re-run.
            if rerun.get("passed") is not True:
                return ValidatorDecision(
                    action=ValidatorAction.REJECT,
                    reason="full_rerun_failed_under_policy",
                    claim_id=verified.claim_id,
                    skip_rerun_authorized=verified.skip_rerun_authorized,
                    digest_match=True,
                    spot_check=True,
                    full_rerun_result=rerun,
                )
        return ValidatorDecision(
            action=ValidatorAction.FULL_RERUN,
            reason="policy_requires_full_rerun",
            claim_id=verified.claim_id,
            skip_rerun_authorized=verified.skip_rerun_authorized,
            digest_match=True,
            spot_check=True,
            full_rerun_result=rerun,
        )

    if verified.skip_rerun_authorized and verified.document["verify_outcome"] == "passed":
        return ValidatorDecision(
            action=ValidatorAction.ACCEPT_RECEIPT,
            reason="receipt_covers_claim",
            claim_id=verified.claim_id,
            skip_rerun_authorized=True,
            digest_match=True,
            spot_check=False,
            full_rerun_result=None,
        )

    # Valid binding_dev or non-skip claim: evidence is informative but cheap path closed.
    rerun = None
    if perform_full_rerun_if_needed:
        rerun = json.loads(result.decode("ascii"))
        if rerun.get("passed") is True:
            return ValidatorDecision(
                action=ValidatorAction.FULL_RERUN,
                reason="receipt_valid_but_skip_rerun_not_authorized",
                claim_id=verified.claim_id,
                skip_rerun_authorized=False,
                digest_match=True,
                spot_check=False,
                full_rerun_result=rerun,
            )
        return ValidatorDecision(
            action=ValidatorAction.REJECT,
            reason="full_rerun_failed",
            claim_id=verified.claim_id,
            skip_rerun_authorized=False,
            digest_match=True,
            spot_check=False,
            full_rerun_result=rerun,
        )

    return ValidatorDecision(
        action=ValidatorAction.FULL_RERUN,
        reason="receipt_valid_but_skip_rerun_not_authorized",
        claim_id=verified.claim_id,
        skip_rerun_authorized=False,
        digest_match=True,
        spot_check=False,
        full_rerun_result=None,
    )


def decision_to_json(decision: ValidatorDecision) -> dict[str, object]:
    return {
        "action": decision.action.value,
        "reason": decision.reason,
        "claim_id": decision.claim_id,
        "skip_rerun_authorized": decision.skip_rerun_authorized,
        "digest_match": decision.digest_match,
        "spot_check": decision.spot_check,
        "full_rerun_result": decision.full_rerun_result,
    }
