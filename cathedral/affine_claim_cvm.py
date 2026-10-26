"""Issue Affine claims from a CVM attestation path — never from Affline sandboxes.

Fail-closed rules:
- Affline ``/v1/sandboxes`` is not an issuance source.
- ``tee=reference`` may only mint ``binding_dev`` (no skip-rerun).
- ``confidential_cpu`` + ``skip_rerun_eligible`` require a live ``tdx``/``snp``
  CVM whose hardware evidence re-verifies at issue time.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral.affine_claim import (
    AffineClaimError,
    digest_affine_verify_bundle,
    issue_affine_claim,
    run_tiny_affine_verify,
    sha256_hex,
)
from cathedral.cvm_lifecycle import AttestationEvidence, CvmInstance


def _measurement_digest(measurement: str) -> str:
    if len(measurement) == 64 and all(c in "0123456789abcdef" for c in measurement):
        return measurement
    return sha256_hex(measurement.encode("utf-8"))


def issue_affine_claim_from_cvm(
    *,
    cvm: CvmInstance,
    private_key: Ed25519PrivateKey,
    signing_key_id: str,
    verify_code: bytes,
    verify_inputs: bytes,
    miner_payload: bytes,
    verify_result: bytes | None = None,
    issued_at: datetime | None = None,
    allow_reference: bool = True,
) -> bytes:
    """Run (or accept) Affine verify bytes and bind them to CVM attestation.

    If ``verify_result`` is omitted, :func:`run_tiny_affine_verify` is used so CI
    has a real (non-always-pass) check. Production callers should pass the
    canonical result bytes from Affine's own verify artifact and set
    ``allow_reference=False`` so only hardware-attested CVMs issue claims.
    """

    if cvm.state != "running":
        raise AffineClaimError(
            "status",
            f"CVM must be running to issue an affine claim (state={cvm.state})",
        )
    if cvm.evidence is None:
        raise AffineClaimError("policy", "CVM has no attestation evidence")
    if cvm.labels.get("customer") == "affline":
        raise AffineClaimError(
            "policy",
            "Affline sandboxes cannot issue affine claims; use the CVM product path",
        )

    evidence = cvm.evidence
    result = verify_result if verify_result is not None else run_tiny_affine_verify(
        miner_payload=miner_payload
    )
    try:
        import json

        outcome_doc = json.loads(result.decode("ascii"))
        verify_outcome = "passed" if outcome_doc.get("passed") is True else "failed"
    except Exception as exc:
        raise AffineClaimError("schema", "verify_result must be canonical JSON") from exc

    digests = digest_affine_verify_bundle(
        verify_code=verify_code,
        verify_inputs=verify_inputs,
        miner_payload=miner_payload,
        verify_result=result,
    )

    tee = evidence.tee
    if tee == "reference":
        if not allow_reference:
            raise AffineClaimError(
                "policy",
                "reference CVM cannot issue claims when allow_reference=false",
            )
        return issue_affine_claim(
            private_key=private_key,
            signing_key_id=signing_key_id,
            issued_at=issued_at or datetime.now(UTC),
            digests=digests,
            verify_outcome=verify_outcome,
            execution_profile_id="affine-cvm-reference-v1",
            measurement_sha256=_measurement_digest(evidence.measurement),
            attestation_class="binding_dev",
            attestation_independently_verified=False,
            skip_rerun_eligible=False,
        )

    if tee not in ("tdx", "snp"):
        raise AffineClaimError("policy", f"unsupported CVM tee {tee!r}")

    # Re-verify hardware at issue time — do not trust a stale running bit alone.
    from cathedral.cvm_attest import verify_hardware_evidence

    reason = verify_hardware_evidence(evidence)
    if reason is not None:
        raise AffineClaimError(
            "policy",
            f"CVM hardware evidence not admitted at issue time: {reason}",
        )

    skip = verify_outcome == "passed"
    return issue_affine_claim(
        private_key=private_key,
        signing_key_id=signing_key_id,
        issued_at=issued_at or datetime.now(UTC),
        digests=digests,
        verify_outcome=verify_outcome,
        execution_profile_id=f"affine-cvm-{tee}-v1",
        measurement_sha256=_measurement_digest(evidence.measurement),
        attestation_class="confidential_cpu",
        attestation_independently_verified=True,
        skip_rerun_eligible=skip,
    )


def evidence_from_document(document: Mapping[str, object]) -> AttestationEvidence:
    """Parse a CVM evidence JSON object (fail-closed on missing fields)."""

    required = ("quote_b64", "measurement", "nonce", "issued_at", "tee")
    missing = [key for key in required if key not in document]
    if missing:
        raise AffineClaimError("schema", f"CVM evidence missing fields: {missing}")
    issued_at = document["issued_at"]
    if isinstance(issued_at, bool) or not isinstance(issued_at, (int, float)):
        raise AffineClaimError("schema", "issued_at must be a unix timestamp")
    return AttestationEvidence(
        quote_b64=str(document["quote_b64"]),
        measurement=str(document["measurement"]),
        nonce=str(document["nonce"]),
        issued_at=float(issued_at),
        tee=str(document["tee"]),
        gpu_bound=bool(document.get("gpu_bound", False)),
    )


def cvm_instance_from_running_document(document: Mapping[str, object]) -> CvmInstance:
    """Rebuild a minimal running CvmInstance from a status/evidence document."""

    if document.get("state") != "running":
        raise AffineClaimError("status", "CVM document state must be running")
    evidence_doc = document.get("evidence")
    if not isinstance(evidence_doc, dict):
        raise AffineClaimError("schema", "CVM document must include evidence")
    labels = document.get("labels")
    if labels is not None and not isinstance(labels, dict):
        raise AffineClaimError("schema", "labels must be an object")
    inst = CvmInstance(
        id=str(document.get("id") or "cvm_external"),
        state="running",
        nonce=str(evidence_doc.get("nonce") or ""),
        evidence=evidence_from_document(evidence_doc),
        labels={str(k): str(v) for k, v in dict(labels or {}).items()},
        last_attest_at=float(document["last_attest_at"])
        if isinstance(document.get("last_attest_at"), (int, float))
        else None,
    )
    return inst


def bind_quote_to_claim_material(
    *,
    nonce: str,
    digests: Mapping[str, str],
) -> str:
    """Deterministic binding material for operators logging quote↔claim linkage."""

    material = "|".join(
        [
            f"nonce={nonce}",
            f"code={digests['affine_verify_code_sha256']}",
            f"inputs={digests['affine_verify_inputs_sha256']}",
            f"payload={digests['miner_payload_sha256']}",
            f"result={digests['verify_result_sha256']}",
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
