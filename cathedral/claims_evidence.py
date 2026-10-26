"""Claims (SN111) evidence pack — signed binding over Claims' canonical unit.

The Claims canonical unit is ``agent_output.json`` (ARA / agent_v1) plus its
``source_payload`` digests — not a Cathedral sandbox. This module issues and
verifies ``cathedral_claims_evidence_v1``: a Cathedral-signed envelope that
binds job identity, input digests, execution policy digests and output digests.

It does not set SN111 weights, hold validator wallets, or claim that a service
signature is independent hardware attestation. ``assurance_level`` is explicit:

- ``service_signed``: Cathedral Ed25519 over the pack (pilot / audit mode).
- ``confidential_cpu``: reserved for a later native SNP/TDX bind; issue path
  today only emits ``service_signed``.

Designed so Claims can later call verify offline without Cathedral holding keys.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CLAIMS_EVIDENCE_SCHEMA = "cathedral_claims_evidence_v1"
CLAIMS_EVIDENCE_TRUSTED_KEYS_SCHEMA = "cathedral_claims_evidence_trusted_keys_v1"
CLAIMS_EVIDENCE_POLICY_V1 = b"cathedral.claims-evidence.policy.v1"
CLAIMS_EVIDENCE_POLICY_DIGEST = (
    "sha256:" + hashlib.sha256(CLAIMS_EVIDENCE_POLICY_V1).hexdigest()
)
CLAIMS_MANIFEST_SCHEMA = "cathedral_claims_job_manifest_v1"

MAX_CLAIMS_EVIDENCE_BYTES = 128 * 1024
MAX_CLAIMS_TRUSTED_KEYS_BYTES = 64 * 1024
# Observed Claims artifacts can exceed the evidence envelope. Pretty-printed
# agent_output / source_payload for a long paper may be multi-MiB; PDFs larger.
MAX_CLAIMS_OBSERVED_JSON_BYTES = 8 * 1024 * 1024
MAX_CLAIMS_OBSERVED_PDF_BYTES = 96 * 1024 * 1024
# Allow small forward skew so verify hosts slightly behind the issuer still pass.
CLAIMS_EVIDENCE_CLOCK_SKEW_SECONDS = 300
MAX_CLAIMS_NODES = 512
MAX_CLAIMS_DEPTH = 10
MAX_JSON_INTEGER = 2**63 - 1

_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")

_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "evidence_id",
        "issued_at",
        "policy_digest",
        "signing_key_id",
        "evidence_status",
        "assurance_level",
        "terminal_status",
        "netuid",
        "batch_id",
        "assignment_id",
        "operation_id",
        "attempt_id",
        "paper_id",
        "miner_hotkey",
        "stage_id",
        "manifest_sha256",
        "source_pdf_sha256",
        "source_payload_sha256",
        "agent_output_sha256",
        "image_digest_sha256",
        "workload_commit_sha256",
        "execution_policy_sha256",
        "reuse_authorized_until",
        "signature",
    }
)
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_TRUSTED_KEYS_TOP_LEVEL = frozenset({"schema", "keys"})
_TRUSTED_KEY_FIELDS = frozenset(
    {"algorithm", "public_key_base64", "status", "valid_from", "valid_until"}
)
_KEY_STATUSES = frozenset({"active", "retired", "revoked"})
_EVIDENCE_STATUSES = frozenset({"issued"})
_ASSURANCE_LEVELS = frozenset({"service_signed", "confidential_cpu"})
_TERMINAL_STATUSES = frozenset({"succeeded", "failed", "cancelled"})


class ClaimsEvidenceError(ValueError):
    """Stable Claims-evidence failure with a machine-readable category."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


@dataclass(frozen=True)
class ClaimsEvidenceVerificationKey:
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
class VerifiedClaimsEvidence:
    evidence_id: str
    evidence_bytes: bytes
    evidence_digest: str
    issued_at: datetime
    document: Mapping[str, object]
    accepted: bool
    reject_reasons: tuple[str, ...]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def claims_json_sha256(value: object) -> str:
    """Digest exactly as Claims computes artifact_hash and source_payload_hash.

    Claims hashes the parsed JSON object, not file bytes: sorted keys, compact
    separators, ensure_ascii=False, UTF-8 (neurons/miner.py _json_hash and
    neurons/validator.py _stable_hash at Claims 41573a4).
    """

    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    ).hexdigest()


def claims_json_bytes_sha256(data: bytes, *, label: str) -> str:
    """Parse a Claims JSON document and return its Claims-canonical digest."""

    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ClaimsEvidenceError("schema", f"{label} is not UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ClaimsEvidenceError("schema", f"{label} must be a JSON object")
    return claims_json_sha256(value)


def _duplicate_safe_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ClaimsEvidenceError("schema", f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _json_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ClaimsEvidenceError("schema", "JSON integer is invalid") from exc
    if not -(2**63) <= parsed <= MAX_JSON_INTEGER:
        raise ClaimsEvidenceError("schema", "JSON integer exceeds the supported range")
    return parsed


def _validate_json_shape(value: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_CLAIMS_NODES or depth > MAX_CLAIMS_DEPTH:
            raise ClaimsEvidenceError("schema", "JSON structure is too complex")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 256:
                    raise ClaimsEvidenceError("schema", "JSON object key is invalid")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, str):
            if len(current.encode("utf-8")) > 16 * 1024:
                raise ClaimsEvidenceError("schema", "JSON string exceeds the size limit")
        elif current is None or isinstance(current, (bool, int)):
            continue
        else:
            raise ClaimsEvidenceError("schema", "JSON contains a non-canonical value")


def _parse_json(data: bytes | str, *, maximum_bytes: int, label: str) -> dict[str, object]:
    try:
        encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise ClaimsEvidenceError("schema", f"{label} is not UTF-8 JSON") from exc
    if len(encoded) > maximum_bytes:
        raise ClaimsEvidenceError("schema", f"{label} exceeds the maximum encoded size")
    try:
        parsed = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_object,
            parse_float=lambda _value: (_ for _ in ()).throw(
                ClaimsEvidenceError("schema", "floating-point JSON is unsupported")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ClaimsEvidenceError("schema", "non-finite JSON is unsupported")
            ),
            parse_int=_json_integer,
        )
    except ClaimsEvidenceError:
        raise
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ClaimsEvidenceError("schema", f"{label} is not UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ClaimsEvidenceError("schema", f"{label} must be a JSON object")
    _validate_json_shape(parsed)
    return parsed


def canonical_claims_json(value: Mapping[str, object] | dict[str, object]) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ClaimsEvidenceError("schema", "document contains a non-canonical value") from exc


def claims_evidence_body_bytes(document: Mapping[str, object]) -> bytes:
    body = {
        key: value
        for key, value in document.items()
        if key not in {"evidence_id", "signature"}
    }
    return canonical_claims_json(body)


def claims_evidence_signed_bytes(document: Mapping[str, object]) -> bytes:
    body = {key: value for key, value in document.items() if key != "signature"}
    return canonical_claims_json(body)


def _parse_time(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise ClaimsEvidenceError("schema", f"{field} must use six-fractional-digit UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ClaimsEvidenceError("schema", f"{field} is not a valid UTC time") from exc


def _require_sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256_HEX_RE.fullmatch(value) is None:
        raise ClaimsEvidenceError("schema", f"{field} must be a lowercase sha256 hex digest")
    return value


def _require_id(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise ClaimsEvidenceError("schema", f"{field} is invalid")
    return value


def _utc_stamp(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ClaimsEvidenceError("schema", "timestamps must be timezone-aware UTC")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def build_claims_manifest(
    *,
    netuid: int,
    batch_id: str,
    assignment_id: str,
    operation_id: str,
    attempt_id: str,
    paper_id: str,
    miner_hotkey: str,
    stage_id: str,
    source_pdf_sha256: str,
    source_payload_sha256: str,
    image_digest_sha256: str,
    workload_commit_sha256: str,
    execution_policy_sha256: str,
    agent_output_sha256: str | None = None,
) -> dict[str, object]:
    """Claims job identity + digests (the submit body, without signature)."""

    if not isinstance(netuid, int) or netuid < 0 or netuid > 65535:
        raise ClaimsEvidenceError("schema", "netuid must be an integer in 0..65535")
    manifest: dict[str, object] = {
        "schema": CLAIMS_MANIFEST_SCHEMA,
        "netuid": netuid,
        "batch_id": _require_id(batch_id, field="batch_id"),
        "assignment_id": _require_id(assignment_id, field="assignment_id"),
        "operation_id": _require_id(operation_id, field="operation_id"),
        "attempt_id": _require_id(attempt_id, field="attempt_id"),
        "paper_id": _require_id(paper_id, field="paper_id"),
        "miner_hotkey": _require_id(miner_hotkey, field="miner_hotkey"),
        "stage_id": _require_id(stage_id, field="stage_id"),
        "source_pdf_sha256": _require_sha256(source_pdf_sha256, field="source_pdf_sha256"),
        "source_payload_sha256": _require_sha256(
            source_payload_sha256, field="source_payload_sha256"
        ),
        "image_digest_sha256": _require_sha256(image_digest_sha256, field="image_digest_sha256"),
        "workload_commit_sha256": _require_sha256(
            workload_commit_sha256, field="workload_commit_sha256"
        ),
        "execution_policy_sha256": _require_sha256(
            execution_policy_sha256, field="execution_policy_sha256"
        ),
    }
    if agent_output_sha256 is not None:
        manifest["agent_output_sha256"] = _require_sha256(
            agent_output_sha256, field="agent_output_sha256"
        )
    return manifest


_MANIFEST_STRING_FIELDS = (
    "batch_id",
    "assignment_id",
    "operation_id",
    "attempt_id",
    "paper_id",
    "miner_hotkey",
    "stage_id",
    "source_pdf_sha256",
    "source_payload_sha256",
    "image_digest_sha256",
    "workload_commit_sha256",
    "execution_policy_sha256",
)
_MANIFEST_REQUIRED_KEYS = frozenset({"schema", "netuid", *_MANIFEST_STRING_FIELDS})
_MANIFEST_ALLOWED_KEYS = _MANIFEST_REQUIRED_KEYS | {"agent_output_sha256"}


def _freeze_manifest(manifest: Mapping[str, object]) -> tuple[dict[str, object], str | None]:
    """Strictly validate a job manifest; return it without agent_output_sha256 plus that digest."""

    if not isinstance(manifest, Mapping):
        raise ClaimsEvidenceError("schema", "claims manifest must be a JSON object")
    keys = set(manifest)
    if not _MANIFEST_REQUIRED_KEYS <= keys or not keys <= _MANIFEST_ALLOWED_KEYS:
        raise ClaimsEvidenceError("schema", "claims manifest has unexpected or missing fields")
    if manifest["schema"] != CLAIMS_MANIFEST_SCHEMA:
        raise ClaimsEvidenceError("schema", "claims manifest schema is unsupported")
    netuid = manifest["netuid"]
    if isinstance(netuid, bool) or not isinstance(netuid, int):
        raise ClaimsEvidenceError("schema", "netuid must be an integer in 0..65535")
    for field in _MANIFEST_STRING_FIELDS:
        if not isinstance(manifest[field], str):
            raise ClaimsEvidenceError("schema", f"{field} is invalid")
    agent_output_sha256 = manifest.get("agent_output_sha256")
    if agent_output_sha256 is not None:
        agent_output_sha256 = _require_sha256(agent_output_sha256, field="agent_output_sha256")
    frozen = build_claims_manifest(
        netuid=netuid,
        **{field: str(manifest[field]) for field in _MANIFEST_STRING_FIELDS},
    )
    return frozen, agent_output_sha256


def digest_claims_artifacts(
    *,
    source_pdf: bytes,
    source_payload: bytes,
    agent_output: bytes,
    image_digest_ref: bytes,
    workload_commit_ref: bytes,
    execution_policy: bytes,
) -> dict[str, str]:
    """Digest the inputs the way Claims does.

    The PDF is hashed as raw bytes (Claims ``source_sha256``). ``source_payload``
    and ``agent_output`` are hashed as Claims-canonical JSON so the digests equal
    Claims ``source_payload_hash`` and ``artifact_hash``.
    """

    return {
        "source_pdf_sha256": sha256_hex(source_pdf),
        "source_payload_sha256": claims_json_bytes_sha256(source_payload, label="source_payload"),
        "agent_output_sha256": claims_json_bytes_sha256(agent_output, label="agent_output"),
        "image_digest_sha256": sha256_hex(image_digest_ref),
        "workload_commit_sha256": sha256_hex(workload_commit_ref),
        "execution_policy_sha256": sha256_hex(execution_policy),
    }


def write_claims_pack(
    pack_dir: Path,
    *,
    manifest: Mapping[str, object],
    evidence_bytes: bytes,
    source_pdf: bytes | None = None,
    source_payload: bytes | None = None,
    agent_output: bytes | None = None,
) -> Path:
    """Write a hand-off directory Claims can inspect offline."""

    pack_dir = Path(pack_dir)
    outputs = pack_dir / "outputs"
    evidence = pack_dir / "evidence"
    outputs.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    (pack_dir / "manifest.json").write_bytes(canonical_claims_json(dict(manifest)))
    (evidence / "cathedral-claims-evidence.json").write_bytes(evidence_bytes)
    if source_pdf is not None:
        (outputs / "paper.pdf").write_bytes(source_pdf)
    if source_payload is not None:
        (outputs / "source_payload.json").write_bytes(source_payload)
    if agent_output is not None:
        (outputs / "agent_output.json").write_bytes(agent_output)
    return pack_dir


def parse_claims_evidence_trusted_keys_json(
    data: bytes | str,
) -> Mapping[str, ClaimsEvidenceVerificationKey]:
    document = _parse_json(
        data,
        maximum_bytes=MAX_CLAIMS_TRUSTED_KEYS_BYTES,
        label="claims evidence trusted keys",
    )
    if set(document) != _TRUSTED_KEYS_TOP_LEVEL:
        raise ClaimsEvidenceError("key", "trusted keys document has unexpected fields")
    if document.get("schema") != CLAIMS_EVIDENCE_TRUSTED_KEYS_SCHEMA:
        raise ClaimsEvidenceError("key", "trusted keys schema is unsupported")
    keys = document.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise ClaimsEvidenceError("key", "trusted keys must be a non-empty object")
    parsed: dict[str, ClaimsEvidenceVerificationKey] = {}
    for key_id, row in keys.items():
        if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
            raise ClaimsEvidenceError("key", "trusted key id is invalid")
        if not isinstance(row, dict) or set(row) != _TRUSTED_KEY_FIELDS:
            raise ClaimsEvidenceError("key", f"trusted key {key_id!r} fields are invalid")
        if row.get("algorithm") != "ed25519":
            raise ClaimsEvidenceError("key", f"trusted key {key_id!r} algorithm is unsupported")
        status = row.get("status")
        if status not in _KEY_STATUSES:
            raise ClaimsEvidenceError("key", f"trusted key {key_id!r} status is invalid")
        try:
            public_key = base64.b64decode(str(row.get("public_key_base64") or ""), validate=True)
        except Exception as exc:
            raise ClaimsEvidenceError(
                "key", f"trusted key {key_id!r} public key is invalid"
            ) from exc
        if len(public_key) != 32:
            raise ClaimsEvidenceError("key", f"trusted key {key_id!r} public key is invalid")
        parsed[key_id] = ClaimsEvidenceVerificationKey(
            key_id=key_id,
            public_key=public_key,
            status=str(status),
            valid_from=_parse_time(row.get("valid_from"), field="valid_from"),
            valid_until=_parse_time(row.get("valid_until"), field="valid_until"),
        )
    return MappingProxyType(parsed)


def parse_claims_evidence_json(data: bytes | str) -> dict[str, object]:
    document = _parse_json(data, maximum_bytes=MAX_CLAIMS_EVIDENCE_BYTES, label="claims evidence")
    encoded = data if isinstance(data, bytes) else data.encode("utf-8")
    if encoded != canonical_claims_json(document):
        raise ClaimsEvidenceError("schema", "claims evidence bytes are not canonical")
    if set(document) != _TOP_LEVEL_KEYS:
        raise ClaimsEvidenceError("schema", "claims evidence has unexpected or missing fields")
    if document.get("schema") != CLAIMS_EVIDENCE_SCHEMA:
        raise ClaimsEvidenceError("schema", "claims evidence schema is unsupported")
    if document.get("policy_digest") != CLAIMS_EVIDENCE_POLICY_DIGEST:
        raise ClaimsEvidenceError("policy", "claims evidence policy_digest is not accepted")
    if document.get("evidence_status") not in _EVIDENCE_STATUSES:
        raise ClaimsEvidenceError("status", "evidence_status is invalid")
    if document.get("assurance_level") not in _ASSURANCE_LEVELS:
        raise ClaimsEvidenceError("schema", "assurance_level is invalid")
    if document.get("terminal_status") not in _TERMINAL_STATUSES:
        raise ClaimsEvidenceError("schema", "terminal_status is invalid")
    if document.get("assurance_level") == "confidential_cpu":
        raise ClaimsEvidenceError(
            "policy",
            "confidential_cpu assurance is not issued by this module yet; "
            "use service_signed for the pilot",
        )
    if not isinstance(document.get("signing_key_id"), str) or (
        _KEY_ID_RE.fullmatch(str(document["signing_key_id"])) is None
    ):
        raise ClaimsEvidenceError("schema", "signing_key_id is invalid")
    if not isinstance(document.get("netuid"), int):
        raise ClaimsEvidenceError("schema", "netuid must be an integer")
    for field in (
        "batch_id",
        "assignment_id",
        "operation_id",
        "attempt_id",
        "paper_id",
        "miner_hotkey",
        "stage_id",
    ):
        _require_id(document.get(field), field=field)
    for field in (
        "manifest_sha256",
        "source_pdf_sha256",
        "source_payload_sha256",
        "agent_output_sha256",
        "image_digest_sha256",
        "workload_commit_sha256",
        "execution_policy_sha256",
    ):
        _require_sha256(document.get(field), field=field)
    _parse_time(document.get("issued_at"), field="issued_at")
    _parse_time(document.get("reuse_authorized_until"), field="reuse_authorized_until")
    signature = document.get("signature")
    if not isinstance(signature, dict) or set(signature) != _SIGNATURE_KEYS:
        raise ClaimsEvidenceError("schema", "signature object is invalid")
    if signature.get("algorithm") != "ed25519":
        raise ClaimsEvidenceError("schema", "signature algorithm is unsupported")
    try:
        sig = base64.b64decode(str(signature.get("value_base64") or ""), validate=True)
    except Exception as exc:
        raise ClaimsEvidenceError("signature", "signature is not valid base64") from exc
    if len(sig) != 64:
        raise ClaimsEvidenceError("signature", "signature must be 64 bytes")
    if base64.b64encode(sig).decode("ascii") != signature.get("value_base64"):
        # Reject non-canonical encodings so one signature has one evidence digest.
        raise ClaimsEvidenceError("signature", "signature base64 is not canonical")
    expected_id = sha256_hex(claims_evidence_body_bytes(document))
    if document.get("evidence_id") != expected_id:
        raise ClaimsEvidenceError("binding", "evidence_id does not match the canonical body digest")
    return document


def issue_claims_evidence(
    *,
    private_key: Ed25519PrivateKey,
    signing_key_id: str,
    issued_at: datetime,
    manifest: Mapping[str, object],
    agent_output_sha256: str,
    terminal_status: str = "succeeded",
    assurance_level: str = "service_signed",
    reuse_authorized_until: datetime | None = None,
) -> bytes:
    """Sign a Claims evidence envelope bound to *manifest* and output digest."""

    if assurance_level != "service_signed":
        raise ClaimsEvidenceError(
            "policy",
            "only assurance_level=service_signed may be issued today",
        )
    if terminal_status not in _TERMINAL_STATUSES:
        raise ClaimsEvidenceError("schema", "terminal_status is invalid")
    if not isinstance(signing_key_id, str) or _KEY_ID_RE.fullmatch(signing_key_id) is None:
        raise ClaimsEvidenceError("schema", "signing_key_id is invalid")
    frozen, manifest_agent_output_sha256 = _freeze_manifest(manifest)
    _require_sha256(agent_output_sha256, field="agent_output_sha256")
    if (
        manifest_agent_output_sha256 is not None
        and manifest_agent_output_sha256 != agent_output_sha256
    ):
        raise ClaimsEvidenceError(
            "binding", "agent_output_sha256 does not match the manifest agent_output_sha256"
        )
    manifest_sha = sha256_hex(canonical_claims_json(frozen))
    until = reuse_authorized_until or (issued_at + timedelta(days=14))
    unsigned: dict[str, object] = {
        "schema": CLAIMS_EVIDENCE_SCHEMA,
        "issued_at": _utc_stamp(issued_at),
        "policy_digest": CLAIMS_EVIDENCE_POLICY_DIGEST,
        "signing_key_id": signing_key_id,
        "evidence_status": "issued",
        "assurance_level": assurance_level,
        "terminal_status": terminal_status,
        "netuid": frozen["netuid"],
        "batch_id": frozen["batch_id"],
        "assignment_id": frozen["assignment_id"],
        "operation_id": frozen["operation_id"],
        "attempt_id": frozen["attempt_id"],
        "paper_id": frozen["paper_id"],
        "miner_hotkey": frozen["miner_hotkey"],
        "stage_id": frozen["stage_id"],
        "manifest_sha256": manifest_sha,
        "source_pdf_sha256": frozen["source_pdf_sha256"],
        "source_payload_sha256": frozen["source_payload_sha256"],
        "agent_output_sha256": _require_sha256(agent_output_sha256, field="agent_output_sha256"),
        "image_digest_sha256": frozen["image_digest_sha256"],
        "workload_commit_sha256": frozen["workload_commit_sha256"],
        "execution_policy_sha256": frozen["execution_policy_sha256"],
        "reuse_authorized_until": _utc_stamp(until),
    }
    evidence_id = sha256_hex(claims_evidence_body_bytes(unsigned))
    to_sign = {**unsigned, "evidence_id": evidence_id}
    signature = private_key.sign(claims_evidence_signed_bytes(to_sign))
    document = {
        **to_sign,
        "signature": {
            "algorithm": "ed25519",
            "value_base64": base64.b64encode(signature).decode("ascii"),
        },
    }
    return canonical_claims_json(document)


def verify_claims_evidence(
    evidence_bytes: bytes | str,
    trusted_keys: Mapping[str, ClaimsEvidenceVerificationKey],
    *,
    expected_manifest: Mapping[str, object] | None = None,
    observed_agent_output: bytes | None = None,
    observed_source_pdf: bytes | None = None,
    observed_source_payload: bytes | None = None,
    max_age_seconds: int | None = None,
    now: datetime | None = None,
) -> VerifiedClaimsEvidence:
    """Verify signature and optional exact digest matches against observed bytes."""

    encoded = evidence_bytes if isinstance(evidence_bytes, bytes) else evidence_bytes.encode("utf-8")
    document = parse_claims_evidence_json(encoded)
    issued_at = _parse_time(document["issued_at"], field="issued_at")
    reuse_until = _parse_time(document["reuse_authorized_until"], field="reuse_authorized_until")
    key_id = str(document["signing_key_id"])
    key = trusted_keys.get(key_id)
    if key is None:
        raise ClaimsEvidenceError("key", f"signing_key_id {key_id!r} is not trusted")
    if not key.verifies_at(issued_at):
        raise ClaimsEvidenceError("key", f"signing_key_id {key_id!r} is not valid at issued_at")
    signature = base64.b64decode(str(document["signature"]["value_base64"]), validate=True)  # type: ignore[index]
    try:
        Ed25519PublicKey.from_public_bytes(key.public_key).verify(
            signature, claims_evidence_signed_bytes(document)
        )
    except InvalidSignature as exc:
        raise ClaimsEvidenceError("signature", "claims evidence signature is invalid") from exc

    clock = now or datetime.now(UTC)
    if issued_at > clock + timedelta(seconds=CLAIMS_EVIDENCE_CLOCK_SKEW_SECONDS):
        raise ClaimsEvidenceError(
            "freshness",
            "claims evidence issued_at is beyond allowed clock skew",
        )
    if max_age_seconds is not None:
        if max_age_seconds < 0:
            raise ClaimsEvidenceError("policy", "max_age_seconds must be non-negative")
        if clock - issued_at > timedelta(seconds=max_age_seconds):
            raise ClaimsEvidenceError("freshness", "claims evidence is older than max_age_seconds")

    reasons: list[str] = []
    if clock >= reuse_until:
        reasons.append("reuse_window_expired")

    if expected_manifest is not None:
        frozen, expected_agent_output_sha256 = _freeze_manifest(expected_manifest)
        if (
            expected_agent_output_sha256 is not None
            and document["agent_output_sha256"] != expected_agent_output_sha256
        ):
            reasons.append("agent_output_sha256_mismatch")
        expected_manifest_sha = sha256_hex(canonical_claims_json(frozen))
        if document["manifest_sha256"] != expected_manifest_sha:
            reasons.append("manifest_digest_mismatch")
        for field in (
            "batch_id",
            "assignment_id",
            "operation_id",
            "attempt_id",
            "paper_id",
            "miner_hotkey",
            "stage_id",
            "source_pdf_sha256",
            "source_payload_sha256",
            "image_digest_sha256",
            "workload_commit_sha256",
            "execution_policy_sha256",
        ):
            if document[field] != frozen[field]:
                reasons.append(f"{field}_mismatch")
        if document["netuid"] != frozen["netuid"]:
            reasons.append("netuid_mismatch")

    if observed_agent_output is not None:
        observed = claims_json_bytes_sha256(observed_agent_output, label="agent_output")
        if observed != document["agent_output_sha256"]:
            reasons.append("agent_output_digest_mismatch")
    if observed_source_pdf is not None:
        if sha256_hex(observed_source_pdf) != document["source_pdf_sha256"]:
            reasons.append("source_pdf_digest_mismatch")
    if observed_source_payload is not None:
        observed = claims_json_bytes_sha256(observed_source_payload, label="source_payload")
        if observed != document["source_payload_sha256"]:
            reasons.append("source_payload_digest_mismatch")

    if document["terminal_status"] != "succeeded":
        reasons.append("terminal_status_not_succeeded")

    accepted = not reasons
    return VerifiedClaimsEvidence(
        evidence_id=str(document["evidence_id"]),
        evidence_bytes=encoded,
        evidence_digest=sha256_hex(encoded),
        issued_at=issued_at,
        document=MappingProxyType(document),
        accepted=accepted,
        reject_reasons=tuple(reasons),
    )


def tiny_claims_agent_output(*, paper_id: str, claim_statement: str) -> bytes:
    """Minimal ARA-shaped agent_output.json for unit tests (not a real miner)."""

    doc: dict[str, Any] = {
        "ara_version": "1",
        "paper": {
            "paper_id": paper_id,
            "title": "fixture-paper",
            "authors": ["fixture"],
            "year": 2013,
            "venue": "fixture",
            "doi": "",
            "domain": "fixture",
            "keywords": [],
            "abstract": "fixture",
            "claims_summary": [claim_statement],
        },
        "logic": {
            "problem_observations": [],
            "gaps": [],
            "key_insight": claim_statement,
            "assumptions": [],
            "claims": [
                {
                    "claim_id": "C01",
                    "statement": claim_statement,
                    "conditions": "fixture",
                    "status": "supported",
                    "falsification_criteria": "fixture",
                    "proof": [],
                    "evidence_ids": ["EV01"],
                    "dependencies": [],
                    "sources": [],
                    "metadata": {},
                }
            ],
            "concepts": [],
            "experiments": [],
        },
        "evidence": {"records": [{"evidence_id": "EV01", "summary": "fixture"}], "ledger_notes": []},
        "trace": {
            "node_id": "T01",
            "node_type": "root",
            "support_level": "direct",
            "summary": claim_statement,
            "source_refs": [],
            "evidence": [],
            "children": [],
        },
        "src": {"environment": [], "artifacts": []},
        "metadata": {
            "pipeline_name": "cathedral-claims-fixture",
            "output_schema": "agent_v1",
            "runtime": "fixture",
            "source_bounded": True,
        },
    }
    return canonical_claims_json(doc)
