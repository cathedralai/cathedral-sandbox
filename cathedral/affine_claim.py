"""Affine claim binding — signed digests over Affine's existing verify checks.

Additive contract. Does not modify Affline ``/v1/sandboxes`` semantics and does
not stamp TEE on Affline status. A verified claim proves Cathedral signed the
digest binding; ``skip_rerun_authorized`` is true only when attestation is
independently marked and the class is ``confidential_cpu``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

AFFINE_CLAIM_SCHEMA = "cathedral_affine_claim_v1"
AFFINE_CLAIM_TRUSTED_KEYS_SCHEMA = "cathedral_affine_claim_trusted_keys_v1"
AFFINE_CLAIM_POLICY_V1 = b"cathedral.affine-claim.policy.v1"
AFFINE_CLAIM_POLICY_DIGEST = "sha256:" + hashlib.sha256(AFFINE_CLAIM_POLICY_V1).hexdigest()

MAX_AFFINE_CLAIM_BYTES = 64 * 1024
MAX_AFFINE_CLAIM_TRUSTED_KEYS_BYTES = 64 * 1024
MAX_AFFINE_CLAIM_NODES = 256
MAX_AFFINE_CLAIM_DEPTH = 8
MAX_JSON_INTEGER = 2**63 - 1

_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")

_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "claim_id",
        "issued_at",
        "policy_digest",
        "signing_key_id",
        "claim_status",
        "affine_verify_code_sha256",
        "affine_verify_inputs_sha256",
        "miner_payload_sha256",
        "verify_result_sha256",
        "verify_outcome",
        "execution_profile_id",
        "measurement_sha256",
        "attestation_class",
        "attestation_independently_verified",
        "skip_rerun_eligible",
        "affline_sandbox_tee_claimed",
        "signature",
    }
)
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_TRUSTED_KEYS_TOP_LEVEL = frozenset({"schema", "keys"})
_TRUSTED_KEY_FIELDS = frozenset(
    {"algorithm", "public_key_base64", "status", "valid_from", "valid_until"}
)
_KEY_STATUSES = frozenset({"active", "retired", "revoked"})
_VERIFY_OUTCOMES = frozenset({"passed", "failed"})
_ATTESTATION_CLASSES = frozenset({"binding_dev", "confidential_cpu"})
_CLAIM_STATUSES = frozenset({"issued"})


class AffineClaimError(ValueError):
    """Stable affine-claim failure with a machine-readable category."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


@dataclass(frozen=True)
class AffineClaimVerificationKey:
    key_id: str
    public_key: bytes
    status: str
    valid_from: datetime
    valid_until: datetime

    def verifies_at(self, issued_at: datetime) -> bool:
        return self.status in {"active", "retired"} and (
            self.valid_from <= issued_at < self.valid_until
        )


@dataclass(frozen=True)
class VerifiedAffineClaim:
    claim_id: str
    claim_bytes: bytes
    claim_digest: str
    issued_at: datetime
    document: Mapping[str, object]
    skip_rerun_authorized: bool


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_affine_verify_bundle(
    *,
    verify_code: bytes,
    verify_inputs: bytes,
    miner_payload: bytes,
    verify_result: bytes,
) -> dict[str, str]:
    """Hash the exact bytes an Affine validator would re-run over."""

    return {
        "affine_verify_code_sha256": sha256_hex(verify_code),
        "affine_verify_inputs_sha256": sha256_hex(verify_inputs),
        "miner_payload_sha256": sha256_hex(miner_payload),
        "verify_result_sha256": sha256_hex(verify_result),
    }


def run_tiny_affine_verify(*, miner_payload: bytes, expected_prefix: bytes = b"AFFINE") -> bytes:
    """Tiny real check used for Phase-3 smoke — not a mock always-PASS.

    Mimics an Affine-shaped rule: payload must start with a fixed prefix and
    contain a decimal score in ``0..100``. Returns canonical result JSON bytes.
    """

    if not miner_payload.startswith(expected_prefix + b":"):
        result = {"passed": False, "reason": "prefix_mismatch", "score": 0}
    else:
        rest = miner_payload.split(b":", 1)[1]
        try:
            score = int(rest.strip())
        except ValueError:
            result = {"passed": False, "reason": "score_not_int", "score": 0}
        else:
            if 0 <= score <= 100:
                result = {"passed": True, "reason": "ok", "score": score}
            else:
                result = {"passed": False, "reason": "score_out_of_range", "score": score}
    return canonical_affine_claim_json(result)


def _duplicate_safe_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AffineClaimError("schema", f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _json_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise AffineClaimError("schema", "JSON integer is invalid") from exc
    if not -(2**63) <= parsed <= MAX_JSON_INTEGER:
        raise AffineClaimError("schema", "JSON integer exceeds the supported range")
    return parsed


def _validate_json_shape(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_AFFINE_CLAIM_NODES or depth > MAX_AFFINE_CLAIM_DEPTH:
            raise AffineClaimError("schema", "JSON structure is too complex")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 256:
                    raise AffineClaimError("schema", "JSON object key is invalid")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str):
            if len(current.encode("utf-8")) > 16 * 1024:
                raise AffineClaimError("schema", "JSON string exceeds the size limit")
        elif current is None or isinstance(current, (bool, int)):
            continue
        else:
            raise AffineClaimError("schema", "JSON contains a non-canonical value")


def _parse_json(data: bytes | str, *, maximum_bytes: int, label: str) -> dict[str, object]:
    try:
        encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise AffineClaimError("schema", f"{label} is not UTF-8 JSON") from exc
    if len(encoded) > maximum_bytes:
        raise AffineClaimError("schema", f"{label} exceeds the maximum encoded size")
    try:
        parsed = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_object,
            parse_float=lambda _value: (_ for _ in ()).throw(
                AffineClaimError("schema", "floating-point JSON is unsupported")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                AffineClaimError("schema", "non-finite JSON is unsupported")
            ),
            parse_int=_json_integer,
        )
    except AffineClaimError:
        raise
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AffineClaimError("schema", f"{label} is not UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise AffineClaimError("schema", f"{label} must be a JSON object")
    _validate_json_shape(parsed)
    return parsed


def canonical_affine_claim_json(value: Mapping[str, object] | dict[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise AffineClaimError("schema", "document contains a non-canonical value") from exc


def affine_claim_body_bytes(document: Mapping[str, object]) -> bytes:
    """Canonical body excluding ``claim_id`` and ``signature`` (id is the digest)."""

    body = {
        key: value
        for key, value in document.items()
        if key not in {"claim_id", "signature"}
    }
    return canonical_affine_claim_json(body)


def affine_claim_signed_bytes(document: Mapping[str, object]) -> bytes:
    """Canonical signature input: every field except ``signature``."""

    body = {key: value for key, value in document.items() if key != "signature"}
    return canonical_affine_claim_json(body)


def _parse_time(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise AffineClaimError("schema", f"{field} must use six-fractional-digit UTC")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _require_sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256_HEX_RE.fullmatch(value) is None:
        raise AffineClaimError("schema", f"{field} must be a lowercase sha256 hex digest")
    return value


def parse_affine_claim_trusted_keys_json(
    data: bytes | str,
) -> Mapping[str, AffineClaimVerificationKey]:
    document = _parse_json(
        data,
        maximum_bytes=MAX_AFFINE_CLAIM_TRUSTED_KEYS_BYTES,
        label="affine claim trusted keys",
    )
    if set(document) != _TRUSTED_KEYS_TOP_LEVEL:
        raise AffineClaimError("key", "trusted keys document has unexpected fields")
    if document.get("schema") != AFFINE_CLAIM_TRUSTED_KEYS_SCHEMA:
        raise AffineClaimError("key", "trusted keys schema is unsupported")
    keys = document.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise AffineClaimError("key", "trusted keys must be a non-empty object")
    parsed: dict[str, AffineClaimVerificationKey] = {}
    for key_id, row in keys.items():
        if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
            raise AffineClaimError("key", "trusted key id is invalid")
        if not isinstance(row, dict) or set(row) != _TRUSTED_KEY_FIELDS:
            raise AffineClaimError("key", f"trusted key {key_id!r} fields are invalid")
        if row.get("algorithm") != "ed25519":
            raise AffineClaimError("key", f"trusted key {key_id!r} algorithm is unsupported")
        status = row.get("status")
        if status not in _KEY_STATUSES:
            raise AffineClaimError("key", f"trusted key {key_id!r} status is invalid")
        try:
            public_key = base64.b64decode(str(row.get("public_key_base64") or ""), validate=True)
        except Exception as exc:
            raise AffineClaimError("key", f"trusted key {key_id!r} public key is invalid") from exc
        if len(public_key) != 32:
            raise AffineClaimError("key", f"trusted key {key_id!r} public key is invalid")
        parsed[key_id] = AffineClaimVerificationKey(
            key_id=key_id,
            public_key=public_key,
            status=str(status),
            valid_from=_parse_time(row.get("valid_from"), field="valid_from"),
            valid_until=_parse_time(row.get("valid_until"), field="valid_until"),
        )
    return MappingProxyType(parsed)


def parse_affine_claim_json(data: bytes | str) -> dict[str, object]:
    document = _parse_json(data, maximum_bytes=MAX_AFFINE_CLAIM_BYTES, label="affine claim")
    encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    if encoded != canonical_affine_claim_json(document):
        raise AffineClaimError("schema", "affine claim bytes are not canonical")
    if set(document) != _TOP_LEVEL_KEYS:
        raise AffineClaimError("schema", "affine claim has unexpected or missing fields")
    if document.get("schema") != AFFINE_CLAIM_SCHEMA:
        raise AffineClaimError("schema", "affine claim schema is unsupported")
    if document.get("policy_digest") != AFFINE_CLAIM_POLICY_DIGEST:
        raise AffineClaimError("policy", "affine claim policy_digest is not accepted")
    if document.get("claim_status") not in _CLAIM_STATUSES:
        raise AffineClaimError("status", "affine claim_status is invalid")
    if document.get("verify_outcome") not in _VERIFY_OUTCOMES:
        raise AffineClaimError("schema", "verify_outcome is invalid")
    if document.get("attestation_class") not in _ATTESTATION_CLASSES:
        raise AffineClaimError("schema", "attestation_class is invalid")
    if not isinstance(document.get("signing_key_id"), str) or (
        _KEY_ID_RE.fullmatch(str(document["signing_key_id"])) is None
    ):
        raise AffineClaimError("schema", "signing_key_id is invalid")
    if not isinstance(document.get("execution_profile_id"), str) or (
        _PROFILE_RE.fullmatch(str(document["execution_profile_id"])) is None
    ):
        raise AffineClaimError("schema", "execution_profile_id is invalid")
    for field in (
        "affine_verify_code_sha256",
        "affine_verify_inputs_sha256",
        "miner_payload_sha256",
        "verify_result_sha256",
        "measurement_sha256",
    ):
        _require_sha256(document.get(field), field=field)
    if not isinstance(document.get("attestation_independently_verified"), bool):
        raise AffineClaimError("schema", "attestation_independently_verified must be a boolean")
    if not isinstance(document.get("skip_rerun_eligible"), bool):
        raise AffineClaimError("schema", "skip_rerun_eligible must be a boolean")
    if document.get("affline_sandbox_tee_claimed") is not False:
        raise AffineClaimError(
            "policy",
            "affline_sandbox_tee_claimed must be false — Affline sandboxes are not TEEs",
        )
    # Fail closed: binding_dev must never authorize skip-rerun.
    if document["attestation_class"] == "binding_dev":
        if document["attestation_independently_verified"] is not False:
            raise AffineClaimError(
                "policy",
                "binding_dev claims cannot assert independent attestation",
            )
        if document["skip_rerun_eligible"] is not False:
            raise AffineClaimError(
                "policy",
                "binding_dev claims cannot be skip_rerun_eligible",
            )
    if document["attestation_class"] == "confidential_cpu":
        if document["skip_rerun_eligible"] and not document["attestation_independently_verified"]:
            raise AffineClaimError(
                "policy",
                "skip_rerun_eligible requires attestation_independently_verified",
            )
        if document["verify_outcome"] != "passed" and document["skip_rerun_eligible"]:
            raise AffineClaimError(
                "policy",
                "failed verify_outcome cannot be skip_rerun_eligible",
            )
    signature = document.get("signature")
    if not isinstance(signature, dict) or set(signature) != _SIGNATURE_KEYS:
        raise AffineClaimError("schema", "signature object is invalid")
    if signature.get("algorithm") != "ed25519":
        raise AffineClaimError("schema", "signature algorithm is unsupported")
    try:
        sig = base64.b64decode(str(signature.get("value_base64") or ""), validate=True)
    except Exception as exc:
        raise AffineClaimError("signature", "signature is not valid base64") from exc
    if len(sig) != 64:
        raise AffineClaimError("signature", "signature must be 64 bytes")
    claim_id = document.get("claim_id")
    expected_id = sha256_hex(affine_claim_body_bytes(document))
    if claim_id != expected_id:
        raise AffineClaimError("binding", "claim_id does not match the canonical body digest")
    _parse_time(document.get("issued_at"), field="issued_at")
    return document


def verify_affine_claim(
    claim_bytes: bytes | str,
    trusted_keys: Mapping[str, AffineClaimVerificationKey],
    *,
    max_age_seconds: int | None = None,
    now: datetime | None = None,
) -> VerifiedAffineClaim:
    encoded = claim_bytes if isinstance(claim_bytes, bytes) else claim_bytes.encode("utf-8")
    document = parse_affine_claim_json(encoded)
    issued_at = _parse_time(document["issued_at"], field="issued_at")
    clock = now or datetime.now(UTC)
    if max_age_seconds is not None:
        if max_age_seconds < 0:
            raise AffineClaimError("policy", "max_age_seconds must be non-negative")
        if issued_at < clock - timedelta(seconds=max_age_seconds):
            raise AffineClaimError("stale", "affine claim exceeds max_age_seconds")
    key_id = str(document["signing_key_id"])
    key = trusted_keys.get(key_id)
    if key is None:
        raise AffineClaimError("key", "signing_key_id is not trusted")
    if not key.verifies_at(issued_at):
        raise AffineClaimError("key", "signing key is not valid at issued_at")
    signature = base64.b64decode(str(document["signature"]["value_base64"]), validate=True)
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(
            signature,
            affine_claim_signed_bytes(document),
        )
    except InvalidSignature as exc:
        raise AffineClaimError("signature", "affine claim signature is invalid") from exc
    skip = bool(
        document["skip_rerun_eligible"]
        and document["attestation_class"] == "confidential_cpu"
        and document["attestation_independently_verified"] is True
        and document["verify_outcome"] == "passed"
        and document["affline_sandbox_tee_claimed"] is False
    )
    return VerifiedAffineClaim(
        claim_id=str(document["claim_id"]),
        claim_bytes=encoded,
        claim_digest="sha256:" + sha256_hex(encoded),
        issued_at=issued_at,
        document=MappingProxyType(document),
        skip_rerun_authorized=skip,
    )


def issue_affine_claim(
    *,
    private_key: Ed25519PrivateKey,
    signing_key_id: str,
    issued_at: datetime,
    digests: Mapping[str, str],
    verify_outcome: str,
    execution_profile_id: str,
    measurement_sha256: str,
    attestation_class: str = "binding_dev",
    attestation_independently_verified: bool = False,
    skip_rerun_eligible: bool = False,
    policy_digest: str = AFFINE_CLAIM_POLICY_DIGEST,
) -> bytes:
    """Issue a canonical signed affine claim (test / pilot helper)."""

    if verify_outcome not in _VERIFY_OUTCOMES:
        raise AffineClaimError("schema", "verify_outcome is invalid")
    if attestation_class not in _ATTESTATION_CLASSES:
        raise AffineClaimError("schema", "attestation_class is invalid")
    if issued_at.tzinfo is None:
        raise AffineClaimError("schema", "issued_at must be timezone-aware UTC")
    issued_text = issued_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    body: dict[str, object] = {
        "schema": AFFINE_CLAIM_SCHEMA,
        "issued_at": issued_text,
        "policy_digest": policy_digest,
        "signing_key_id": signing_key_id,
        "claim_status": "issued",
        "affine_verify_code_sha256": digests["affine_verify_code_sha256"],
        "affine_verify_inputs_sha256": digests["affine_verify_inputs_sha256"],
        "miner_payload_sha256": digests["miner_payload_sha256"],
        "verify_result_sha256": digests["verify_result_sha256"],
        "verify_outcome": verify_outcome,
        "execution_profile_id": execution_profile_id,
        "measurement_sha256": measurement_sha256,
        "attestation_class": attestation_class,
        "attestation_independently_verified": attestation_independently_verified,
        "skip_rerun_eligible": skip_rerun_eligible,
        "affline_sandbox_tee_claimed": False,
    }
    claim_id = sha256_hex(affine_claim_body_bytes(body))
    unsigned = {**body, "claim_id": claim_id}
    signature = private_key.sign(affine_claim_signed_bytes(unsigned))
    signed = {
        **unsigned,
        "signature": {
            "algorithm": "ed25519",
            "value_base64": base64.b64encode(signature).decode("ascii"),
        },
    }
    return canonical_affine_claim_json(signed)
