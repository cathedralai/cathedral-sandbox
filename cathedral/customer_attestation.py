"""Offline verification of a signed customer receipt and bound vendor evidence."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
from datetime import datetime
from pathlib import Path

from cathedral.common import Policy
from cathedral.customer_receipt import (
    CUSTOMER_ATTESTATION_RECEIPT_SCHEMA,
    CustomerReceiptError,
    _duplicate_safe_object,
    verify_customer_receipt,
)
from cathedral.verify.snp import (
    SnpCertificateChain,
    SnpVerifierUnavailable,
    _snp_report_is_admissible,
    _tcb_meets_minimum,
    parse_snp_report,
    snp_generation,
    verify_snp_offline,
)
from cathedral.verify.tdx_offline import TdxOfflineUnavailable, verify_tdx_offline

BUNDLE_SCHEMA = "cathedral_customer_attestation_bundle_v1"
MAX_BUNDLE_BYTES = 36 * 1024 * 1024


def read_bounded_file(path: str | Path, maximum: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= maximum:
                raise CustomerReceiptError("schema", "local input must be a bounded regular file")
            value = source.read(maximum + 1)
    except OSError as exc:
        raise CustomerReceiptError("schema", "required local input is not readable") from exc
    if not value or len(value) > maximum:
        raise CustomerReceiptError("schema", "local input size is outside the accepted range")
    return value


def _object(data: bytes, maximum: int) -> dict:
    if not isinstance(data, bytes) or not 0 < len(data) <= maximum:
        raise CustomerReceiptError("schema", "JSON input size is outside the accepted range")
    try:
        value = json.loads(data, object_pairs_hook=_duplicate_safe_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CustomerReceiptError("schema", "invalid or ambiguous JSON input") from exc
    if not isinstance(value, dict):
        raise CustomerReceiptError("schema", "JSON input must be an object")
    return value


def _decode(value: object, maximum: int, category: str = "schema") -> bytes:
    if not isinstance(value, str) or len(value) > 4 * ((maximum + 2) // 3):
        raise CustomerReceiptError(category, "encoded evidence is outside the accepted range")
    try:
        encoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CustomerReceiptError(category, "evidence must be canonical base64") from exc
    if not 0 < len(encoded) <= maximum or base64.b64encode(encoded).decode("ascii") != value:
        raise CustomerReceiptError(category, "evidence must be bounded canonical base64")
    return encoded


def parse_attestation_policy(data: bytes) -> Policy:
    """Only customer-selected local policy supplies measurements and TCB floors."""
    document = _object(data, 64 * 1024)
    if set(document) != {"allowed_measurements", "min_snp_tcb"}:
        raise CustomerReceiptError("policy", "local policy fields are invalid")
    measurements = document["allowed_measurements"]
    floor = document["min_snp_tcb"]
    if (not isinstance(measurements, list) or not 1 <= len(measurements) <= 128
            or any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in measurements)
            or type(floor) is not int or not 0 <= floor < 2**64):
        raise CustomerReceiptError("policy", "local measurement policy or SNP TCB floor is invalid")
    return Policy(allowed_measurements=frozenset(measurements), min_tcb=floor)


def verify_attestation_bundle(
    data: bytes,
    trusted_keys,
    policy: Policy,
    *,
    expected_box_id: str | None = None,
    max_age_seconds: int | None = None,
    now: datetime | None = None,
    snpguest_path: str | None = None,
    tdx_executable: str | None = None,
    tdx_implementation_digest: str | None = None,
) -> dict:
    bundle = _object(data, MAX_BUNDLE_BYTES)
    if set(bundle) != {"schema", "receipt_base64", "evidence"} or bundle["schema"] != BUNDLE_SCHEMA:
        raise CustomerReceiptError("schema", "attestation bundle schema or fields are invalid")
    receipt_bytes = _decode(bundle["receipt_base64"], 256 * 1024)
    receipt = verify_customer_receipt(receipt_bytes, trusted_keys, max_age_seconds=max_age_seconds, now=now)
    document = receipt.document
    if document["schema"] != CUSTOMER_ATTESTATION_RECEIPT_SCHEMA:
        raise CustomerReceiptError("binding", "legacy receipt has no signed hardware binding")
    binding = document["hardware_binding"]
    if expected_box_id is not None and binding["box_id"] != expected_box_id:
        raise CustomerReceiptError("binding", "signed receipt belongs to another box")
    evidence = bundle["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {"kind", "quote_base64", "collateral"}:
        raise CustomerReceiptError("schema", "hardware evidence fields are invalid")
    quote = _decode(evidence["quote_base64"], 1024 * 1024)
    if hashlib.sha256(quote).hexdigest() != binding["quote_sha256"]:
        raise CustomerReceiptError("binding", "hardware quote does not match the signed receipt")
    expected = bytes.fromhex(binding["report_data_hex"])
    if not isinstance(policy, Policy) or not policy.allowed_measurements:
        raise CustomerReceiptError("policy", "local hardware measurement policy is required")
    kind = evidence["kind"]
    collateral = evidence["collateral"]
    if kind == "sev_snp" and document["execution_class"] == "snp_cpu":
        if not isinstance(collateral, dict) or set(collateral) != {"vcek_base64", "ask_base64", "ark_base64"}:
            raise CustomerReceiptError("vendor_chain", "SNP certificate chain is incomplete")
        try:
            chain = SnpCertificateChain(**{name: _decode(collateral[name + "_base64"], 64 * 1024, "vendor_chain")
                                          for name in ("vcek", "ask", "ark")})
            parsed = parse_snp_report(quote)
        except ValueError as exc:
            if isinstance(exc, CustomerReceiptError):
                raise
            raise CustomerReceiptError("vendor_chain", "SNP report or DER chain is malformed") from exc
        if parsed.report_data != expected:
            raise CustomerReceiptError("binding", "SNP REPORT_DATA does not match the signed binding")
        if (not _snp_report_is_admissible(quote, parsed)
                or parsed.measurement not in policy.allowed_measurements
                or not _tcb_meets_minimum(parsed.tcb.reported, policy.min_tcb, snp_generation(parsed))):
            raise CustomerReceiptError("policy", "SNP report fails the unchanged admission policy")
        try:
            verdict = verify_snp_offline(quote, expected, policy, vcek_der=chain.vcek,
                                         ask_der=chain.ask, ark_der=chain.ark,
                                         snpguest_path=snpguest_path, raise_on_verifier_unavailable=True)
        except SnpVerifierUnavailable as exc:
            raise CustomerReceiptError("vendor_unavailable", "pinned SNP verifier is unavailable") from exc
        if verdict is None or verdict.chain_verified is not True:
            raise CustomerReceiptError("vendor_chain", "AMD certificate chain or report signature failed")
        measurement = verdict.measurement
        current_reason = "offline SNP replay does not establish current vendor revocation state"
    elif kind == "tdx" and document["execution_class"] == "tdx_cpu":
        encoded = _decode(collateral, 24 * 1024 * 1024, "vendor_chain")
        if not tdx_executable or not tdx_implementation_digest:
            raise CustomerReceiptError("vendor_unavailable", "local TDX executable and implementation digest are required")
        try:
            claims = verify_tdx_offline(quote, expected, encoded, executable=tdx_executable,
                                        implementation_digest=tdx_implementation_digest)
        except TdxOfflineUnavailable as exc:
            raise CustomerReceiptError("vendor_unavailable", "pinned offline TDX verifier is unavailable") from exc
        if not claims:
            raise CustomerReceiptError("vendor_chain", "Intel signature, collateral validity, revocation or TCB check failed")
        measurement = claims.get("measurement")
        if measurement not in policy.allowed_measurements:
            raise CustomerReceiptError("policy", "TDX measurement is outside local policy")
        current_reason = claims["collateral_current_reason"]
    else:
        raise CustomerReceiptError("binding", "hardware kind does not match the signed CPU receipt")
    return {
        "ok": True,
        "receipt_verified": True,
        "evidence_independently_verified": True,
        "verification_scope": "cathedral_receipt_and_vendor_hardware",
        "receipt_id": receipt.receipt_id,
        "box_id": binding["box_id"],
        "hardware_kind": kind,
        "measurement": measurement,
        "collateral_current": False,
        "collateral_current_reason": current_reason,
    }
