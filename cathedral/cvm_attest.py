"""Hardware quote gate for Confidential CVM — wraps Cathedral TDX/SNP verifiers.

Never admits tdx/snp without a configured vendor verifier. Reference evidence stays
on the separate `ref.` path in :mod:`cathedral.cvm_lifecycle`.
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cathedral.cvm_lifecycle import AttestationEvidence


def cvm_report_data(nonce: str) -> bytes:
    """64-byte REPORT_DATA binding for CVM challenges (nonce → digest, zero-padded)."""
    digest = hashlib.sha256(f"cathedral.cvm.nonce.v1:{nonce}".encode("utf-8")).digest()
    return digest + b"\x00" * (64 - len(digest))


def verify_hardware_evidence(evidence: AttestationEvidence) -> str | None:
    """Return a reject reason, or ``None`` when the quote is admitted."""
    tee = evidence.tee
    if tee == "tdx":
        return _verify_tdx(evidence)
    if tee == "snp":
        return _verify_snp(evidence)
    return "unsupported_tee"


def _decode_quote(quote_b64: str) -> bytes | str:
    try:
        raw = base64.b64decode(quote_b64, validate=True)
    except Exception:
        return "invalid_quote_encoding"
    if not raw:
        return "empty_quote"
    return raw


def _verify_tdx(evidence: AttestationEvidence) -> str | None:
    if not os.environ.get("CATHEDRAL_TDX_VERIFY_CMD"):
        return "tee_verification_unavailable"
    quote = _decode_quote(evidence.quote_b64)
    if isinstance(quote, str):
        return quote
    expected = cvm_report_data(evidence.nonce)
    # Import lazy so unit tests without verifier deps stay light.
    from cathedral.verify import _run_tdx_verifier

    try:
        claims = _run_tdx_verifier(
            quote,
            production_mode=False,
            expected_report_data=expected,
        )
    except NotImplementedError:
        return "tee_verification_unavailable"
    except Exception:
        return "tdx_verifier_error"
    if not claims:
        return "tdx_verifier_rejected"
    if claims.get("intel_verified") is not True:
        return "tdx_not_intel_verified"
    measurement = (
        claims.get("measurement")
        or claims.get("mrtd")
        or claims.get("td_measurement")
    )
    if not isinstance(measurement, str) or measurement != evidence.measurement:
        return "measurement_mismatch"
    # When the verifier reports report_data, require CVM nonce binding.
    report_data = claims.get("report_data")
    if report_data is not None:
        if isinstance(report_data, str):
            try:
                if len(report_data) == 128 and all(
                    c in "0123456789abcdefABCDEF" for c in report_data
                ):
                    actual = bytes.fromhex(report_data)
                else:
                    actual = base64.b64decode(report_data)
            except Exception:
                return "tdx_report_data_unreadable"
        elif isinstance(report_data, (bytes, bytearray)):
            actual = bytes(report_data)
        else:
            return "tdx_report_data_unreadable"
        if actual != expected:
            return "nonce_report_data_mismatch"
    return None


def _verify_snp(evidence: AttestationEvidence) -> str | None:
    # snpguest must be configured; otherwise refuse (no structure-only admit).
    if not (
        os.environ.get("CATHEDRAL_SNPGUEST")
        or os.environ.get("CATHEDRAL_SNP_VERIFY_CMD")
    ):
        # Also accept PATH snpguest — verify_snp_report_data looks it up.
        import shutil

        if shutil.which("snpguest") is None:
            return "tee_verification_unavailable"
    quote = _decode_quote(evidence.quote_b64)
    if isinstance(quote, str):
        return quote
    from cathedral.common import Policy
    from cathedral.verify.snp import verify_snp_report_data

    policy = Policy(allowed_measurements=frozenset({evidence.measurement}), min_tcb=0)
    expected = cvm_report_data(evidence.nonce)
    try:
        attested = verify_snp_report_data(
            quote,
            expected,
            policy,
            raise_on_verifier_unavailable=True,
        )
    except Exception:
        return "snp_verifier_unavailable_or_error"
    if attested is None:
        return "snp_verifier_rejected"
    if not getattr(attested, "chain_verified", False):
        return "snp_chain_unverified"
    if attested.measurement != evidence.measurement:
        return "measurement_mismatch"
    return None


__all__ = ["cvm_report_data", "verify_hardware_evidence"]
