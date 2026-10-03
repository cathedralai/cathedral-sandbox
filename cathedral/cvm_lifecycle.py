"""Confidential CVM reference lifecycle (Product C) — not Affline `/v1/sandboxes`.

Fail-closed attestation admission for a persistent CVM object. Live hardware quotes
are opt-in; the reference path uses explicit stub evidence so CI never fabricates TEE.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Mapping


CVM_STATES = frozenset({"pending", "attesting", "running", "rejected", "stopped", "deleted"})
CVM_CUSTOMER_LABEL = "cvm"


@dataclass(frozen=True)
class AttestationEvidence:
    """C4 evidence schema — quote bytes + measurement + challenge binding."""

    quote_b64: str
    measurement: str
    nonce: str
    issued_at: float
    tee: str = "reference"  # reference | tdx | snp
    gpu_bound: bool = False

    def to_document(self) -> dict[str, Any]:
        return {
            "quote_b64": self.quote_b64,
            "measurement": self.measurement,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "tee": self.tee,
            "gpu_bound": self.gpu_bound,
        }


@dataclass
class CvmInstance:
    id: str
    state: str = "pending"
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    evidence: AttestationEvidence | None = None
    labels: dict[str, str] = field(default_factory=lambda: {"customer": CVM_CUSTOMER_LABEL})
    last_attest_at: float | None = None
    reject_reason: str | None = None

    def to_document(self) -> dict[str, Any]:
        # Honest: reference evidence is never hardware attestation.
        kind = None
        if self.evidence is not None:
            kind = "reference" if self.evidence.tee == "reference" else self.evidence.tee
        hardware = (
            self.state == "running"
            and self.evidence is not None
            and self.evidence.tee in ("tdx", "snp")
        )
        return {
            "id": self.id,
            "state": self.state,
            "nonce": self.nonce,
            "labels": dict(self.labels),
            "evidence": self.evidence.to_document() if self.evidence else None,
            "last_attest_at": self.last_attest_at,
            "reject_reason": self.reject_reason,
            "attestation": hardware,
            "attestation_kind": kind,
        }


class CvmLifecycle:
    """In-process CVM control plane for unit/reference tests (C3)."""

    def __init__(self, *, max_evidence_age_seconds: float = 300.0) -> None:
        self._instances: dict[str, CvmInstance] = {}
        self._seen_nonces: set[str] = set()
        self._max_evidence_age_seconds = max_evidence_age_seconds
        self._seq = 0

    def create(self, *, labels: Mapping[str, str] | None = None) -> CvmInstance:
        self._seq += 1
        cid = f"cvm_{self._seq:04d}_{secrets.token_hex(4)}"
        inst = CvmInstance(id=cid)
        if labels:
            inst.labels.update(dict(labels))
        inst.labels.setdefault("customer", CVM_CUSTOMER_LABEL)
        self._instances[cid] = inst
        return inst

    def get(self, cvm_id: str) -> CvmInstance:
        inst = self._instances.get(cvm_id)
        if inst is None or inst.state == "deleted":
            raise KeyError(cvm_id)
        return inst

    def begin_attest(self, cvm_id: str) -> CvmInstance:
        inst = self.get(cvm_id)
        if inst.state not in ("pending", "running"):
            raise ValueError(f"cannot attest from state {inst.state}")
        inst.state = "attesting"
        inst.nonce = secrets.token_hex(16)
        return inst

    def submit_evidence(self, cvm_id: str, evidence: AttestationEvidence) -> CvmInstance:
        """Fail-closed admit: wrong nonce, replay, stale, or empty quote → rejected."""
        inst = self.get(cvm_id)
        if inst.state != "attesting":
            raise ValueError(f"submit_evidence requires attesting, got {inst.state}")
        reason = self._validate(inst, evidence)
        if reason is not None:
            inst.state = "rejected"
            inst.reject_reason = reason
            inst.evidence = evidence
            return inst
        self._seen_nonces.add(evidence.nonce)
        inst.evidence = evidence
        inst.last_attest_at = time.time()
        inst.state = "running"
        inst.reject_reason = None
        return inst

    def _validate(self, inst: CvmInstance, evidence: AttestationEvidence) -> str | None:
        if not evidence.quote_b64 or not evidence.measurement:
            return "missing_quote_or_measurement"
        if evidence.nonce != inst.nonce:
            return "nonce_mismatch"
        if evidence.nonce in self._seen_nonces:
            return "nonce_replay"
        age = time.time() - evidence.issued_at
        if age < 0 or age > self._max_evidence_age_seconds:
            return "stale_or_future_evidence"
        if evidence.tee == "reference":
            if not evidence.quote_b64.startswith("ref."):
                return "invalid_reference_quote"
            return None
        # Hardware TEEs: require vendor verifier (see cathedral.cvm_attest).
        from cathedral.cvm_attest import verify_hardware_evidence

        return verify_hardware_evidence(evidence)

    @staticmethod
    def mint_reference_evidence(nonce: str, *, measurement: str = "m_ref_v1") -> AttestationEvidence:
        """Dev/CI only — never a hardware quote. Prefix `ref.` marks honesty."""
        material = f"{nonce}:{measurement}".encode()
        digest = hashlib.sha256(material).hexdigest()
        return AttestationEvidence(
            quote_b64=f"ref.{digest}",
            measurement=measurement,
            nonce=nonce,
            issued_at=time.time(),
            tee="reference",
            gpu_bound=False,
        )

    def stop(self, cvm_id: str) -> CvmInstance:
        inst = self.get(cvm_id)
        if inst.state not in ("running", "rejected", "attesting"):
            raise ValueError(f"cannot stop from {inst.state}")
        inst.state = "stopped"
        return inst

    def delete(self, cvm_id: str) -> None:
        inst = self._instances.get(cvm_id)
        if inst is None:
            return
        inst.state = "deleted"

    def status_report(self) -> dict[str, Any]:
        """C7: CVM attestation flag stays on this report — not Affline /v1/status."""
        live = [i for i in self._instances.values() if i.state == "running"]
        hardware = [
            i
            for i in live
            if i.evidence is not None and i.evidence.tee in ("tdx", "snp")
        ]
        reference = [
            i
            for i in live
            if i.evidence is not None and i.evidence.tee == "reference"
        ]
        return {
            "product": "cvm",
            "attestation": len(hardware) > 0,
            "attestation_kind": (
                "hardware" if hardware else ("reference" if reference else None)
            ),
            "running": len(live),
            "note": "Affline /v1/status must not inherit this attestation bit; reference ≠ TEE",
        }


__all__ = [
    "AttestationEvidence",
    "CVM_CUSTOMER_LABEL",
    "CVM_STATES",
    "CvmInstance",
    "CvmLifecycle",
]
