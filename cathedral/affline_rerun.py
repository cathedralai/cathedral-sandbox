"""Affline validate-rerun: secret-triggered full re-run + Cathedral-signed receipt.

``POST /v1/affline/validate-rerun`` (Bearer + optional shared secret) always forces
full re-run and returns a signed ``cathedral_affline_rerun_receipt_v1``.

Anti-fake (fail-closed):
- Never stamps Affline sandbox TEE / ``tee_claimed``
- Never returns ``accept_receipt`` from this endpoint
- Rejects request fields that invent live-TEE / skip authorization
- Requires Cathedral Ed25519 signature (``CATHEDRAL_AFFLINE_RERUN_SIGNING_SEED``)

Attestation plan (live TEE) stays on the separate CVM path:
``affine-claim issue-from-cvm --require-hardware`` → ``live-tee-claim-*.json``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.affine_claim import (
    AffineClaimError,
    digest_affine_verify_bundle,
    parse_affine_claim_trusted_keys_json,
    run_tiny_affine_verify,
    verify_affine_claim,
)
from cathedral.affine_validator import (
    ValidatorAction,
    ValidatorDecision,
    decision_to_json,
    validate_affine_submission,
)

UTC = timezone.utc

AFFLINE_RERUN_RECEIPT_SCHEMA = "cathedral_affline_rerun_receipt_v1"
AFFLINE_RERUN_TRUSTED_KEYS_SCHEMA = "cathedral_affline_rerun_trusted_keys_v1"
AFFLINE_RERUN_TRIGGER_HEADER = "X-Cathedral-Affline-Trigger"
AFFLINE_RERUN_SECRET_ENV = "CATHEDRAL_AFFLINE_RERUN_SECRET"
AFFLINE_RERUN_SIGNING_SEED_ENV = "CATHEDRAL_AFFLINE_RERUN_SIGNING_SEED"
AFFLINE_RERUN_SIGNING_KEY_ID_ENV = "CATHEDRAL_AFFLINE_RERUN_SIGNING_KEY_ID"
DEFAULT_SIGNING_KEY_ID = "cathedral-affline-rerun-1"
CATHEDRAL_SIGNER = "cathedral"

MAX_BODY_BYTES = 512 * 1024
MAX_BLOB_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 512 * 1024
_TIME_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")

# Request keys that invent trust — rejected if present/true.
_FORBIDDEN_REQUEST_TRUTHY = frozenset(
    {
        "tee_claimed",
        "affline_sandbox_tee_claimed",
        "invent_live_tee",
        "simulate_hardware_attestation",
        "skip_rerun_authorized",
        "accept_receipt",
        "fabricate_attestation",
    }
)

_ATTESTATION_PLAN = {
    "phase": "plan",
    "current_endpoint_role": "full_rerun_only",
    "accept_receipt_from_this_endpoint": False,
    "steps": [
        {
            "id": "A1",
            "title": "Harbor / Affline sandbox trial",
            "status": "available",
            "artifact": "cathedral_product_run_receipt_v1 (required_validator_action=full_rerun)",
            "tee": False,
        },
        {
            "id": "A2",
            "title": "Secret-triggered full re-run (this endpoint)",
            "status": "available",
            "artifact": "cathedral_affline_rerun_receipt_v1 (Cathedral-signed)",
            "tee": False,
            "notes": "Always force_full_rerun; never accept_receipt here",
        },
        {
            "id": "A3",
            "title": "CVM reference binding_dev claim",
            "status": "available",
            "artifact": "cathedral_affine_claim_v1 attestation_class=binding_dev",
            "tee": False,
            "command": "affine-claim issue-from-cvm (allow_reference)",
        },
        {
            "id": "A4",
            "title": "Live TDX/SNP hardware re-verify",
            "status": "open_gate",
            "artifact": "evidence/affine-pilot/live-tee-claim-*.json",
            "tee": True,
            "command": "affine-claim issue-from-cvm --require-hardware on CvmHost",
            "requires": ["running CVM tee=tdx|snp", "verify_hardware_evidence pass"],
        },
        {
            "id": "A5",
            "title": "Validator accept_receipt",
            "status": "blocked_until_A4",
            "artifact": "affine-claim validate → action=accept_receipt",
            "tee": True,
            "requires": [
                "confidential_cpu",
                "attestation_independently_verified=true",
                "skip_rerun_eligible=true",
                "affline_sandbox_tee_claimed=false",
            ],
        },
    ],
    "forbidden": [
        "Setting affline_sandbox_tee_claimed=true",
        "Minting confidential_cpu without hardware re-verify",
        "Returning accept_receipt from /v1/affline/validate-rerun",
        "Writing live-tee-claim-*.json from reference/macOS stubs",
    ],
}


class AfflineRerunError(ValueError):
    def __init__(self, category: str, message: str, *, http_status: int = 400) -> None:
        self.category = category
        self.http_status = http_status
        super().__init__(message)


@dataclass(frozen=True)
class AfflineRerunResult:
    receipt: dict[str, object]
    decision: ValidatorDecision
    http_status: int


@dataclass(frozen=True)
class VerifiedAfflineRerunReceipt:
    receipt_id: str
    decision_action: str
    document: Mapping[str, object]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def attestation_plan() -> dict[str, object]:
    """Public attestation roadmap (no fake live TEE)."""

    return dict(_ATTESTATION_PLAN)


def _b64_field(payload: Mapping[str, Any], key: str, *, required: bool) -> bytes | None:
    raw = payload.get(key)
    if raw is None:
        if required:
            raise AfflineRerunError("schema", f"{key} is required")
        return None
    if not isinstance(raw, str) or not raw:
        raise AfflineRerunError("schema", f"{key} must be a non-empty base64 string")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise AfflineRerunError("schema", f"{key} is not canonical base64") from exc
    if len(decoded) > MAX_BLOB_BYTES:
        raise AfflineRerunError("schema", f"{key} exceeds maximum blob size")
    return decoded


def _claim_bytes(payload: Mapping[str, Any]) -> bytes:
    if "claim_base64" in payload:
        data = _b64_field(payload, "claim_base64", required=True)
        assert data is not None
        return data
    claim = payload.get("claim")
    if isinstance(claim, dict):
        return canonical_json(claim)
    if isinstance(claim, str) and claim:
        encoded = claim.encode("utf-8")
        if len(encoded) > MAX_BLOB_BYTES:
            raise AfflineRerunError("schema", "claim exceeds maximum size")
        return encoded
    raise AfflineRerunError("schema", "claim or claim_base64 is required")


def _trusted_keys_bytes(payload: Mapping[str, Any]) -> bytes:
    if "trusted_keys_base64" in payload:
        data = _b64_field(payload, "trusted_keys_base64", required=True)
        assert data is not None
        return data
    keys = payload.get("trusted_keys")
    if isinstance(keys, dict):
        return canonical_json(keys)
    if isinstance(keys, str) and keys:
        return keys.encode("utf-8")
    raise AfflineRerunError("schema", "trusted_keys or trusted_keys_base64 is required")


def require_trigger_secret(headers: Mapping[str, str]) -> None:
    """Fail closed when ``CATHEDRAL_AFFLINE_RERUN_SECRET`` is configured."""

    expected = os.environ.get(AFFLINE_RERUN_SECRET_ENV, "").strip()
    if not expected:
        return
    provided = (
        headers.get(AFFLINE_RERUN_TRIGGER_HEADER)
        or headers.get(AFFLINE_RERUN_TRIGGER_HEADER.lower())
        or ""
    ).strip()
    if not provided or not secrets.compare_digest(provided, expected):
        raise AfflineRerunError(
            "unauthorized",
            "missing or invalid Affline rerun trigger secret",
            http_status=401,
        )


def _reject_fake_request_fields(payload: Mapping[str, Any]) -> None:
    for key in _FORBIDDEN_REQUEST_TRUTHY:
        if key not in payload:
            continue
        value = payload[key]
        if value is True or value == "true" or value == 1:
            raise AfflineRerunError(
                "binding",
                f"request must not set {key}=true (anti-fake / no invented attestation)",
            )
    # force_full_rerun=false would open a skip path on this endpoint — refuse.
    if "force_full_rerun" in payload and payload["force_full_rerun"] is False:
        raise AfflineRerunError(
            "binding",
            "this endpoint always forces full_rerun; omit force_full_rerun or set true "
            "(accept_receipt requires live TEE via issue-from-cvm --require-hardware)",
        )


def require_cathedral_signing_key() -> tuple[Ed25519PrivateKey, str]:
    """Cathedral signature is mandatory for affline rerun receipts."""

    seed_hex = os.environ.get(AFFLINE_RERUN_SIGNING_SEED_ENV, "").strip()
    if not seed_hex:
        raise AfflineRerunError(
            "key",
            f"{AFFLINE_RERUN_SIGNING_SEED_ENV} must be set to 32-byte hex "
            "(Cathedral Ed25519 seed) before issuing signed rerun receipts",
            http_status=503,
        )
    try:
        seed = bytes.fromhex(seed_hex)
    except ValueError as exc:
        raise AfflineRerunError("key", "AFFLINE rerun signing seed must be hex") from exc
    if len(seed) != 32:
        raise AfflineRerunError("key", "AFFLINE rerun signing seed must be 32 bytes")
    key_id = os.environ.get(AFFLINE_RERUN_SIGNING_KEY_ID_ENV, DEFAULT_SIGNING_KEY_ID).strip()
    if _KEY_ID_RE.fullmatch(key_id) is None:
        raise AfflineRerunError("key", "signing key id is invalid")
    return Ed25519PrivateKey.from_private_bytes(seed), key_id


def cathedral_signing_public_key_base64() -> str:
    private, _ = require_cathedral_signing_key()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public).decode("ascii")


def build_cathedral_trusted_keys_document() -> bytes:
    """Trusted-keys document for verifying Cathedral-signed rerun receipts."""

    private, key_id = require_cathedral_signing_key()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    now = datetime.now(UTC)
    doc = {
        "schema": AFFLINE_RERUN_TRUSTED_KEYS_SCHEMA,
        "keys": {
            key_id: {
                "algorithm": "ed25519",
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "status": "active",
                "valid_from": (now - timedelta(days=1)).strftime(_TIME_FMT),
                "valid_until": (now + timedelta(days=730)).strftime(_TIME_FMT),
                "signer": CATHEDRAL_SIGNER,
            }
        },
    }
    return canonical_json(doc)


def _claim_summary(claim_doc: Mapping[str, object] | None) -> dict[str, object] | None:
    if claim_doc is None:
        return None
    fields = (
        "claim_id",
        "issued_at",
        "verify_outcome",
        "execution_profile_id",
        "measurement_sha256",
        "attestation_class",
        "attestation_independently_verified",
        "skip_rerun_eligible",
        "affline_sandbox_tee_claimed",
        "affine_verify_code_sha256",
        "affine_verify_inputs_sha256",
        "miner_payload_sha256",
        "verify_result_sha256",
        "signing_key_id",
        "policy_digest",
    )
    out: dict[str, object] = {}
    for key in fields:
        if key in claim_doc:
            out[key] = claim_doc[key]
    return out


def build_affline_rerun_receipt(
    *,
    decision: ValidatorDecision,
    claim_doc: Mapping[str, object] | None,
    verify_code: bytes,
    verify_inputs: bytes,
    miner_payload: bytes,
    verify_result: bytes,
    observed_digests: Mapping[str, str],
    run_id: str,
    api_key_project: str | None = None,
    private_key: Ed25519PrivateKey | None = None,
    signing_key_id: str | None = None,
) -> dict[str, object]:
    if decision.action == ValidatorAction.ACCEPT_RECEIPT:
        raise AfflineRerunError(
            "binding",
            "affline validate-rerun receipts must not carry accept_receipt "
            "(live TEE accept stays on affine-claim validate after hardware issue)",
        )

    if private_key is None or signing_key_id is None:
        private_key, signing_key_id = require_cathedral_signing_key()

    issued_at = datetime.now(UTC).strftime(_TIME_FMT)
    triggered = (
        decision.full_rerun_result is not None or decision.action == ValidatorAction.FULL_RERUN
    )
    body: dict[str, object] = {
        "schema": AFFLINE_RERUN_RECEIPT_SCHEMA,
        "issued_at": issued_at,
        "run_id": run_id,
        "signer": CATHEDRAL_SIGNER,
        "signing_key_id": signing_key_id,
        "tee_claimed": False,
        "affline_sandbox_tee_claimed": False,
        "intel_tdx_asserted": False,
        "required_validator_action": "full_rerun",
        "force_full_rerun": True,
        "decision": decision_to_json(decision),
        "claim_summary": _claim_summary(claim_doc),
        "full_rerun": {
            "triggered": bool(triggered),
            "result": decision.full_rerun_result,
            "verify_code_sha256": sha256_hex(verify_code),
            "verify_inputs_sha256": sha256_hex(verify_inputs),
            "miner_payload_sha256": sha256_hex(miner_payload),
            "verify_result_sha256": sha256_hex(verify_result),
            "observed_digests": dict(observed_digests),
        },
        "honesty": {
            "product_run_receipt_never_skip": True,
            "this_endpoint_never_accept_receipt": True,
            "accept_receipt_requires_confidential_cpu_claim": True,
            "accept_receipt_requires_hardware_reverify": True,
            "live_tee_gate_open": True,
            "no_fabricated_attestation": True,
        },
        "attestation_plan": attestation_plan(),
    }
    if api_key_project is not None:
        body["api_key_project"] = api_key_project

    receipt_id = sha256_hex(canonical_json(body))
    unsigned = {**body, "receipt_id": receipt_id}
    signature = private_key.sign(canonical_json(unsigned))
    return {
        **unsigned,
        "signature": {
            "algorithm": "ed25519",
            "value_base64": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_affline_rerun_receipt(
    raw: bytes,
    *,
    trusted_keys: bytes,
) -> VerifiedAfflineRerunReceipt:
    if len(raw) > MAX_RECEIPT_BYTES:
        raise AfflineRerunError("schema", "receipt exceeds maximum size")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AfflineRerunError("schema", f"receipt is not UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise AfflineRerunError("schema", "receipt must be a JSON object")
    if canonical_json(document) != raw:
        raise AfflineRerunError("schema", "receipt is not canonical JSON")
    if document.get("schema") != AFFLINE_RERUN_RECEIPT_SCHEMA:
        raise AfflineRerunError("schema", "unsupported receipt schema")
    if document.get("signer") != CATHEDRAL_SIGNER:
        raise AfflineRerunError("binding", "signer must be cathedral")
    if document.get("tee_claimed") is not False:
        raise AfflineRerunError("binding", "tee_claimed must be false")
    if document.get("affline_sandbox_tee_claimed") is not False:
        raise AfflineRerunError("binding", "affline_sandbox_tee_claimed must be false")
    if document.get("intel_tdx_asserted") is not False:
        raise AfflineRerunError("binding", "intel_tdx_asserted must be false on this schema")
    if document.get("required_validator_action") != "full_rerun":
        raise AfflineRerunError("binding", "required_validator_action must be full_rerun")
    if document.get("force_full_rerun") is not True:
        raise AfflineRerunError("binding", "force_full_rerun must be true")
    decision = document.get("decision")
    if not isinstance(decision, dict) or decision.get("action") == "accept_receipt":
        raise AfflineRerunError("binding", "signed receipt must not authorize accept_receipt")

    signature = document.get("signature")
    if not isinstance(signature, dict):
        raise AfflineRerunError("signature", "signature is required")
    if signature.get("algorithm") != "ed25519":
        raise AfflineRerunError("signature", "signature algorithm is unsupported")
    try:
        sig = base64.b64decode(str(signature["value_base64"]), validate=True)
    except Exception as exc:
        raise AfflineRerunError("signature", "signature is not canonical base64") from exc
    if len(sig) != 64:
        raise AfflineRerunError("signature", "signature length is invalid")

    unsigned = {k: v for k, v in document.items() if k != "signature"}
    body_for_id = {k: v for k, v in unsigned.items() if k != "receipt_id"}
    expected_id = sha256_hex(canonical_json(body_for_id))
    if document.get("receipt_id") != expected_id:
        raise AfflineRerunError("binding", "receipt_id does not match body digest")

    keys_doc = json.loads(trusted_keys.decode("utf-8"))
    if not isinstance(keys_doc, dict) or keys_doc.get("schema") != AFFLINE_RERUN_TRUSTED_KEYS_SCHEMA:
        raise AfflineRerunError("key", "trusted keys schema is unsupported")
    keys = keys_doc.get("keys")
    if not isinstance(keys, dict):
        raise AfflineRerunError("key", "trusted keys map is invalid")
    key_id = document.get("signing_key_id")
    entry = keys.get(key_id) if isinstance(key_id, str) else None
    if not isinstance(entry, dict):
        raise AfflineRerunError("key", "signing key is not trusted")
    if entry.get("status") == "revoked":
        raise AfflineRerunError("key", "signing key is revoked")
    try:
        raw_pk = base64.b64decode(str(entry["public_key_base64"]), validate=True)
    except Exception as exc:
        raise AfflineRerunError("key", "trusted public key is invalid") from exc
    if len(raw_pk) != 32:
        raise AfflineRerunError("key", "trusted public key is invalid")
    public = Ed25519PublicKey.from_public_bytes(raw_pk)
    try:
        public.verify(sig, canonical_json(unsigned))
    except InvalidSignature as exc:
        raise AfflineRerunError("signature", "Cathedral signature is invalid") from exc

    return VerifiedAfflineRerunReceipt(
        receipt_id=str(document["receipt_id"]),
        decision_action=str(decision.get("action")),
        document=MappingProxyType(document),
    )


def handle_affline_validate_rerun(
    *,
    body: bytes,
    headers: Mapping[str, str],
    api_key_project: str | None = None,
) -> AfflineRerunResult:
    """Parse request, enforce anti-fake + secret + Cathedral signature, force full re-run."""

    if len(body) > MAX_BODY_BYTES:
        raise AfflineRerunError("schema", "request body exceeds maximum size")
    require_trigger_secret(headers)
    # Fail early if Cathedral signing is not configured.
    private_key, signing_key_id = require_cathedral_signing_key()

    try:
        payload = json.loads(body.decode("utf-8") if body else "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AfflineRerunError("schema", f"request body is not UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise AfflineRerunError("schema", "request body must be a JSON object")
    _reject_fake_request_fields(payload)

    claim_bytes = _claim_bytes(payload)
    trusted_raw = _trusted_keys_bytes(payload)
    verify_code = _b64_field(payload, "verify_code_base64", required=True)
    verify_inputs = _b64_field(payload, "verify_inputs_base64", required=True)
    miner_payload = _b64_field(payload, "miner_payload_base64", required=True)
    assert verify_code is not None and verify_inputs is not None and miner_payload is not None
    verify_result = _b64_field(payload, "verify_result_base64", required=False)

    # Endpoint always forces full re-run — never accept_receipt here.
    force_full_rerun = True
    spot_check = bool(payload.get("spot_check", False))
    is_king = bool(payload.get("is_king", False))
    is_dispute = bool(payload.get("is_dispute", False))
    max_age_seconds = payload.get("max_age_seconds")
    if max_age_seconds is not None and (
        not isinstance(max_age_seconds, int) or isinstance(max_age_seconds, bool) or max_age_seconds < 0
    ):
        raise AfflineRerunError("schema", "max_age_seconds must be a non-negative integer")
    run_id = payload.get("run_id")
    if run_id is None:
        run_id = f"affline-rerun-{sha256_hex(miner_payload)[:16]}"
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
        raise AfflineRerunError("schema", "run_id is invalid")

    try:
        trusted_keys = parse_affine_claim_trusted_keys_json(trusted_raw)
    except AffineClaimError as exc:
        raise AfflineRerunError(exc.category, str(exc)) from exc

    result_bytes = verify_result or run_tiny_affine_verify(miner_payload=miner_payload)
    observed = digest_affine_verify_bundle(
        verify_code=verify_code,
        verify_inputs=verify_inputs,
        miner_payload=miner_payload,
        verify_result=result_bytes,
    )

    claim_doc: Mapping[str, object] | None = None
    try:
        verified_claim = verify_affine_claim(
            claim_bytes,
            trusted_keys,
            max_age_seconds=max_age_seconds,
        )
        claim_doc = verified_claim.document
        if claim_doc.get("affline_sandbox_tee_claimed") is True:
            raise AfflineRerunError(
                "binding",
                "affline_sandbox_tee_claimed must be false",
            )
        # Even a confidential_cpu claim does not skip on this endpoint.
        if (
            claim_doc.get("attestation_class") == "confidential_cpu"
            and claim_doc.get("attestation_independently_verified") is True
        ):
            # Honest note only — still force full_rerun below.
            pass
    except AffineClaimError:
        claim_doc = None

    decision = validate_affine_submission(
        claim_bytes=claim_bytes,
        trusted_keys=trusted_keys,
        verify_code=verify_code,
        verify_inputs=verify_inputs,
        miner_payload=miner_payload,
        verify_result=result_bytes,
        force_full_rerun=force_full_rerun,
        spot_check=spot_check,
        is_king=is_king,
        is_dispute=is_dispute,
        max_age_seconds=max_age_seconds,
        perform_full_rerun_if_needed=True,
    )
    if decision.action == ValidatorAction.ACCEPT_RECEIPT:
        # Defense in depth: endpoint must never emit accept_receipt.
        raise AfflineRerunError(
            "binding",
            "internal policy violation: validate-rerun produced accept_receipt",
        )

    receipt = build_affline_rerun_receipt(
        decision=decision,
        claim_doc=claim_doc,
        verify_code=verify_code,
        verify_inputs=verify_inputs,
        miner_payload=miner_payload,
        verify_result=result_bytes,
        observed_digests=observed,
        run_id=run_id,
        api_key_project=api_key_project,
        private_key=private_key,
        signing_key_id=signing_key_id,
    )

    status = 200
    if decision.action == ValidatorAction.REJECT and claim_doc is None:
        status = 400
    return AfflineRerunResult(receipt=receipt, decision=decision, http_status=status)


__all__ = [
    "AFFLINE_RERUN_RECEIPT_SCHEMA",
    "AFFLINE_RERUN_SECRET_ENV",
    "AFFLINE_RERUN_SIGNING_KEY_ID_ENV",
    "AFFLINE_RERUN_SIGNING_SEED_ENV",
    "AFFLINE_RERUN_TRIGGER_HEADER",
    "AFFLINE_RERUN_TRUSTED_KEYS_SCHEMA",
    "CATHEDRAL_SIGNER",
    "AfflineRerunError",
    "AfflineRerunResult",
    "VerifiedAfflineRerunReceipt",
    "attestation_plan",
    "build_affline_rerun_receipt",
    "build_cathedral_trusted_keys_document",
    "canonical_json",
    "cathedral_signing_public_key_base64",
    "handle_affline_validate_rerun",
    "require_cathedral_signing_key",
    "require_trigger_secret",
    "sha256_hex",
    "verify_affline_rerun_receipt",
]
