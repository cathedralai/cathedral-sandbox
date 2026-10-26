"""Host-trusted product run receipts for Affline / Ditto / Reliquary / Agent / CVM-reference.

These are **not** ``cathedral_customer_receipt_v1`` (sealed TDX one-shots) and
**not** ``cathedral_box_receipt_v1`` (sealed console). They prove Cathedral signed
an operational run record with ``tee_claimed=false``.

``execution`` + ``evidence`` are shaped to the fields each product's validators
or qualify clients actually inspect (Harbor digests, Ditto deny-all + expect flag,
Reliquary health/load keys, Agent freeze/thaw, CVM AttestationEvidence). This
schema never authorizes Affline skip-rerun; that requires ``cathedral_affine_claim_v1``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

UTC = timezone.utc

PRODUCT_RUN_RECEIPT_SCHEMA = "cathedral_product_run_receipt_v1"
PRODUCT_RUN_RECEIPT_TRUSTED_KEYS_SCHEMA = "cathedral_product_run_receipt_trusted_keys_v1"
PRODUCT_RUN_RECEIPT_POLICY_V1 = b"cathedral.product-run-receipt.policy.v2"
PRODUCT_RUN_RECEIPT_POLICY_DIGEST = (
    "sha256:" + hashlib.sha256(PRODUCT_RUN_RECEIPT_POLICY_V1).hexdigest()
)

MAX_RECEIPT_BYTES = 128 * 1024
MAX_TRUSTED_KEYS_BYTES = 64 * 1024
MAX_NODES = 640
MAX_DEPTH = 12
MAX_JSON_INTEGER = 2**63 - 1
MAX_NOTE_BYTES = 512
MAX_LIST_LEN = 32
TERMINAL_DIM_MAX = 1000  # matches cathedral.agent_interactive.TERMINAL_DIM_MAX
TICKET_TTL_MAX = 300

_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_KEY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
_IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,255}$")
_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_LOAD_ROW_RE = re.compile(r"^(\d+)_of_(\d+)$")

PRODUCTS = frozenset({"affline", "ditto", "reliquary", "agent", "cvm"})
SURFACES = frozenset({"v1_sandboxes", "v1_workers", "cvm_lifecycle", "offline_pack"})
OUTCOMES = frozenset({"succeeded", "failed"})
ATTESTATION_CLASSES = frozenset({"none"})
TRUST_CLASSES = frozenset({"host_trusted"})

PRODUCT_KINDS = {
    "affline": "harbor_sandbox_trial",
    "ditto": "ditto_harness_slot",
    "reliquary": "reliquary_workers",
    "agent": "agent_ide_session",
    "cvm": "cvm_lifecycle",
}
PRODUCT_SURFACES = {
    "affline": frozenset({"v1_sandboxes"}),
    "ditto": frozenset({"v1_sandboxes"}),
    "reliquary": frozenset({"v1_workers", "offline_pack"}),
    "agent": frozenset({"v1_sandboxes"}),
    "cvm": frozenset({"cvm_lifecycle"}),
}

_AFFINE_DIGEST_FIELDS = (
    "affine_verify_code_sha256",
    "affine_verify_inputs_sha256",
    "miner_payload_sha256",
    "verify_result_sha256",
)

_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "receipt_id",
        "issued_at",
        "policy_digest",
        "signing_key_id",
        "receipt_status",
        "product",
        "surface",
        "tee_claimed",
        "attestation_class",
        "run_id",
        "request_sha256",
        "result_sha256",
        "outcome",
        "note",
        "execution",
        "evidence",
        "signature",
    }
)
_SIGNATURE_KEYS = frozenset({"algorithm", "value_base64"})
_TRUSTED_KEYS_TOP_LEVEL = frozenset({"schema", "keys"})
_TRUSTED_KEY_FIELDS = frozenset(
    {"algorithm", "public_key_base64", "status", "valid_from", "valid_until"}
)
_KEY_STATUSES = frozenset({"active", "retired", "revoked"})
_NETWORK_MODES = frozenset({"none", "allowlist", "public"})
_SANDBOX_BACKENDS = frozenset({"runsc", "docker", "kata", "reference"})
_SANDBOX_PLATFORMS = frozenset({"kvm", "systrap", "reference"})
_CVM_STATES = frozenset(
    {"pending", "attesting", "running", "rejected", "stopped", "deleted"}
)
_TEE_KINDS = frozenset({"reference", "tdx", "snp"})
_AGENT_STATES = frozenset({"creating", "running", "frozen", "stopped", "deleted"})
_VERIFY_OUTCOMES = frozenset({"passed", "failed", "not_applicable"})
_EXPECTS_ISOLATION = frozenset({"0", "1"})


class ProductRunReceiptError(ValueError):
    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


@dataclass(frozen=True)
class VerifiedProductRunReceipt:
    receipt_id: str
    product: str
    surface: str
    outcome: str
    tee_claimed: bool
    document: Mapping[str, object]
    validator_view: Mapping[str, object]


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


def _parse_object(raw: bytes, *, label: str, maximum_bytes: int) -> dict[str, object]:
    if len(raw) > maximum_bytes:
        raise ProductRunReceiptError("schema", f"{label} exceeds the maximum encoded size")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProductRunReceiptError("schema", f"{label} is not UTF-8 JSON") from exc

    def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in pairs:
            if key in out:
                raise ProductRunReceiptError("schema", f"duplicate JSON key {key!r}")
            out[key] = value
        return out

    try:
        parsed = json.loads(text, object_pairs_hook=_object_pairs, parse_int=_parse_int)
    except ProductRunReceiptError:
        raise
    except json.JSONDecodeError as exc:
        raise ProductRunReceiptError("schema", f"{label} is not UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise ProductRunReceiptError("schema", f"{label} must be a JSON object")
    _check_complexity(parsed, nodes=0, depth=0)
    if canonical_json(parsed) != raw:
        raise ProductRunReceiptError("schema", f"{label} is not canonical JSON")
    return parsed


def _parse_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise ProductRunReceiptError("schema", "JSON integer is invalid") from exc
    if number < -MAX_JSON_INTEGER or number > MAX_JSON_INTEGER:
        raise ProductRunReceiptError("schema", "JSON integer exceeds the supported range")
    return number


def _check_complexity(value: object, *, nodes: int, depth: int) -> int:
    nodes += 1
    if nodes > MAX_NODES or depth > MAX_DEPTH:
        raise ProductRunReceiptError("schema", "JSON structure is too complex")
    if isinstance(value, dict):
        for child in value.values():
            nodes = _check_complexity(child, nodes=nodes, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_LIST_LEN:
            raise ProductRunReceiptError("schema", "JSON list is too long")
        for child in value:
            nodes = _check_complexity(child, nodes=nodes, depth=depth + 1)
    elif isinstance(value, float):
        raise ProductRunReceiptError("schema", "floating-point JSON is unsupported")
    return nodes


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or _TIME_RE.fullmatch(value) is None:
        raise ProductRunReceiptError("schema", f"{label} must be canonical UTC time")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ProductRunReceiptError("schema", f"{label} must be canonical UTC time") from exc
    return parsed


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_HEX_RE.fullmatch(value) is None:
        raise ProductRunReceiptError("schema", f"{label} must be 64 lowercase hex chars")
    return value


def _require_sha256_prefixed(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_DIGEST_RE.fullmatch(value) is None:
        raise ProductRunReceiptError("schema", f"{label} must be sha256:<64 hex>")
    return value


def _require_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise ProductRunReceiptError("schema", f"{label} is invalid")
    return value


def _require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ProductRunReceiptError("schema", f"{label} must be a boolean")
    return value


def _require_str(value: object, label: str, *, max_len: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ProductRunReceiptError("schema", f"{label} is invalid")
    return value


def _require_nonneg_int(value: object, label: str, *, maximum: int = 10_000_000) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > maximum:
        raise ProductRunReceiptError("schema", f"{label} must be a non-negative integer")
    return value


def _require_object(value: object, label: str, *, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProductRunReceiptError("schema", f"{label} fields are invalid")
    return value


def _require_object_subset(
    value: object, label: str, *, required: frozenset[str], optional: frozenset[str]
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProductRunReceiptError("schema", f"{label} must be an object")
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        raise ProductRunReceiptError("schema", f"{label} fields are invalid")
    return value


def _require_network(value: object, label: str) -> dict[str, object]:
    network = _require_object_subset(
        value, label, required=frozenset({"mode", "allow"}), optional=frozenset()
    )
    mode = network["mode"]
    if mode not in _NETWORK_MODES:
        raise ProductRunReceiptError("schema", f"{label}.mode is unsupported")
    allow = network["allow"]
    if not isinstance(allow, list) or len(allow) > MAX_LIST_LEN:
        raise ProductRunReceiptError("schema", f"{label}.allow is invalid")
    for item in allow:
        if not isinstance(item, str) or len(item) > 128:
            raise ProductRunReceiptError("schema", f"{label}.allow entry is invalid")
    if mode == "none" and allow:
        raise ProductRunReceiptError("binding", f"{label}.allow must be empty when mode=none")
    return network


def _require_resources(value: object, label: str) -> dict[str, object]:
    resources = _require_object(
        value, label, keys=frozenset({"vcpu", "memory_gib", "disk_gib"})
    )
    _require_nonneg_int(resources["vcpu"], f"{label}.vcpu", maximum=256)
    _require_nonneg_int(resources["memory_gib"], f"{label}.memory_gib", maximum=2048)
    _require_nonneg_int(resources["disk_gib"], f"{label}.disk_gib", maximum=10_000)
    return resources


def _require_labels(value: object, label: str, *, customer: str) -> dict[str, object]:
    if not isinstance(value, dict) or not value or len(value) > 16:
        raise ProductRunReceiptError("schema", f"{label} is invalid")
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ProductRunReceiptError("schema", f"{label} entries must be strings")
        if len(key) > 64 or len(item) > 128:
            raise ProductRunReceiptError("schema", f"{label} entry is too long")
    if value.get("customer") != customer:
        raise ProductRunReceiptError("binding", f"{label}.customer must be {customer!r}")
    return value


def _require_exec_probe(value: object, label: str) -> dict[str, object]:
    probe = _require_object(
        value,
        label,
        keys=frozenset(
            {
                "cmd_sha256",
                "exit_code",
                "stdout_sha256",
                "stderr_sha256",
                "duration_ms",
                "timed_out",
            }
        ),
    )
    _require_digest(probe["cmd_sha256"], f"{label}.cmd_sha256")
    _require_digest(probe["stdout_sha256"], f"{label}.stdout_sha256")
    _require_digest(probe["stderr_sha256"], f"{label}.stderr_sha256")
    exit_code = probe["exit_code"]
    if not isinstance(exit_code, int) or isinstance(exit_code, bool) or exit_code < -1 or exit_code > 255:
        raise ProductRunReceiptError("schema", f"{label}.exit_code is invalid")
    _require_nonneg_int(probe["duration_ms"], f"{label}.duration_ms", maximum=86_400_000)
    _require_bool(probe["timed_out"], f"{label}.timed_out")
    return probe


def _validate_affline_execution(execution: dict[str, object]) -> None:
    required = frozenset(
        {
            "kind",
            "sandbox_id",
            "image",
            "image_digest",
            "resources",
            "network",
            "labels",
            "ttl_seconds",
            "create_request_sha256",
            "exec",
            "adapter",
            "verify_outcome",
        }
    )
    optional = frozenset(
        {
            "task_id",
            "dataset",
            "agent_name",
            *_AFFINE_DIGEST_FIELDS,
        }
    )
    _require_object_subset(execution, "execution", required=required, optional=optional)
    if execution["kind"] != PRODUCT_KINDS["affline"]:
        raise ProductRunReceiptError("binding", "affline execution.kind mismatch")
    _require_id(execution["sandbox_id"], "execution.sandbox_id")
    image = execution["image"]
    if not isinstance(image, str) or _IMAGE_RE.fullmatch(image) is None:
        raise ProductRunReceiptError("schema", "execution.image is invalid")
    if execution["image_digest"] is not None:
        _require_sha256_prefixed(execution["image_digest"], "execution.image_digest")
    _require_resources(execution["resources"], "execution.resources")
    _require_network(execution["network"], "execution.network")
    _require_labels(execution["labels"], "execution.labels", customer="affline")
    _require_nonneg_int(execution["ttl_seconds"], "execution.ttl_seconds", maximum=86_400)
    _require_digest(execution["create_request_sha256"], "execution.create_request_sha256")
    _require_exec_probe(execution["exec"], "execution.exec")
    _require_str(execution["adapter"], "execution.adapter", max_len=64)
    if execution["verify_outcome"] not in _VERIFY_OUTCOMES:
        raise ProductRunReceiptError("schema", "execution.verify_outcome is unsupported")
    for digest_field in _AFFINE_DIGEST_FIELDS:
        if digest_field in execution:
            _require_digest(execution[digest_field], f"execution.{digest_field}")
    for optional_str in ("task_id", "dataset", "agent_name"):
        if optional_str in execution:
            _require_str(execution[optional_str], f"execution.{optional_str}", max_len=128)


def _validate_ditto_execution(execution: dict[str, object]) -> None:
    required = frozenset(
        {
            "kind",
            "sandbox_id",
            "image",
            "image_digest",
            "resources",
            "network",
            "labels",
            "ttl_seconds",
            "create_request_sha256",
            "quota",
            "score_probe",
            "entrypoint",
        }
    )
    _require_object_subset(execution, "execution", required=required, optional=frozenset())
    if execution["kind"] != PRODUCT_KINDS["ditto"]:
        raise ProductRunReceiptError("binding", "ditto execution.kind mismatch")
    _require_id(execution["sandbox_id"], "execution.sandbox_id")
    image = execution["image"]
    if not isinstance(image, str) or _IMAGE_RE.fullmatch(image) is None:
        raise ProductRunReceiptError("schema", "execution.image is invalid")
    if execution["image_digest"] is not None:
        _require_sha256_prefixed(execution["image_digest"], "execution.image_digest")
    _require_resources(execution["resources"], "execution.resources")
    network = _require_network(execution["network"], "execution.network")
    if network["mode"] != "none":
        raise ProductRunReceiptError("binding", "ditto execution.network.mode must be none")
    _require_labels(execution["labels"], "execution.labels", customer="ditto")
    _require_nonneg_int(execution["ttl_seconds"], "execution.ttl_seconds", maximum=3600)
    _require_digest(execution["create_request_sha256"], "execution.create_request_sha256")
    entrypoint = execution["entrypoint"]
    if not isinstance(entrypoint, list) or not entrypoint or len(entrypoint) > 16:
        raise ProductRunReceiptError("schema", "execution.entrypoint is invalid")
    for item in entrypoint:
        if not isinstance(item, str) or not item or len(item) > 128:
            raise ProductRunReceiptError("schema", "execution.entrypoint entry is invalid")
    quota = _require_object(
        execution["quota"],
        "execution.quota",
        keys=frozenset(
            {
                "max_running",
                "rejected_429",
                "retry_after_seconds",
                "cap_trial_exercised",
            }
        ),
    )
    max_running = _require_nonneg_int(quota["max_running"], "execution.quota.max_running", maximum=64)
    if max_running < 2 or max_running > 8:
        raise ProductRunReceiptError("binding", "ditto max_running must be in 2..8")
    _require_bool(quota["rejected_429"], "execution.quota.rejected_429")
    _require_nonneg_int(
        quota["retry_after_seconds"], "execution.quota.retry_after_seconds", maximum=3600
    )
    _require_bool(quota["cap_trial_exercised"], "execution.quota.cap_trial_exercised")
    if quota["rejected_429"] is True and quota["retry_after_seconds"] <= 0:
        raise ProductRunReceiptError("binding", "ditto 429 trials require retry_after_seconds > 0")
    probe = _require_object(
        execution["score_probe"],
        "execution.score_probe",
        keys=frozenset(
            {
                "cmd_sha256",
                "exit_code",
                "result_sha256",
                "stdout_sha256",
                "stderr_sha256",
                "duration_ms",
                "timed_out",
            }
        ),
    )
    _require_digest(probe["cmd_sha256"], "execution.score_probe.cmd_sha256")
    exit_code = probe["exit_code"]
    if not isinstance(exit_code, int) or isinstance(exit_code, bool) or exit_code < -1 or exit_code > 255:
        raise ProductRunReceiptError("schema", "execution.score_probe.exit_code is invalid")
    _require_digest(probe["result_sha256"], "execution.score_probe.result_sha256")
    _require_digest(probe["stdout_sha256"], "execution.score_probe.stdout_sha256")
    _require_digest(probe["stderr_sha256"], "execution.score_probe.stderr_sha256")
    _require_nonneg_int(probe["duration_ms"], "execution.score_probe.duration_ms", maximum=86_400_000)
    _require_bool(probe["timed_out"], "execution.score_probe.timed_out")


def _validate_reliquary_execution(execution: dict[str, object], *, surface: str) -> None:
    required = frozenset(
        {
            "kind",
            "allocation_id",
            "image_id",
            "source_revision",
            "batch_deadline_seconds",
            "health",
            "load",
            "health_sha256",
            "summary_sha256",
        }
    )
    optional = frozenset({"script_sha256"})
    _require_object_subset(execution, "execution", required=required, optional=optional)
    if execution["kind"] != PRODUCT_KINDS["reliquary"]:
        raise ProductRunReceiptError("binding", "reliquary execution.kind mismatch")
    allocation_id = _require_id(execution["allocation_id"], "execution.allocation_id")
    _require_sha256_prefixed(execution["image_id"], "execution.image_id")
    _require_str(execution["source_revision"], "execution.source_revision", max_len=64)
    deadline = _require_nonneg_int(
        execution["batch_deadline_seconds"], "execution.batch_deadline_seconds", maximum=600
    )
    if deadline == 0 or deadline > 120:
        raise ProductRunReceiptError("binding", "reliquary batch_deadline_seconds must be 1..120")

    health = _require_object(
        execution["health"],
        "execution.health",
        keys=frozenset(
            {
                "status",
                "protocol_version",
                "executor_id",
                "runtime_id",
                "sandbox_backend",
                "sandbox_platform",
                "pool",
                "api",
            }
        ),
    )
    if health["status"] != "ok":
        raise ProductRunReceiptError("binding", "reliquary health.status must be ok")
    if _require_nonneg_int(health["protocol_version"], "execution.health.protocol_version", maximum=32) != 2:
        raise ProductRunReceiptError("binding", "reliquary protocol_version must be 2")
    if health["executor_id"] != allocation_id:
        raise ProductRunReceiptError("binding", "reliquary executor_id must equal allocation_id")
    runtime_id = _require_str(health["runtime_id"], "execution.health.runtime_id", max_len=128)
    if health["sandbox_backend"] != "runsc":
        raise ProductRunReceiptError("binding", "reliquary sandbox_backend must be runsc")
    platform = health["sandbox_platform"]
    if platform not in _SANDBOX_PLATFORMS:
        raise ProductRunReceiptError("schema", "execution.health.sandbox_platform is unsupported")
    if surface == "offline_pack":
        if platform not in {"kvm", "systrap", "reference"}:
            raise ProductRunReceiptError("binding", "offline_pack platform unsupported")
    elif platform not in {"kvm", "systrap"}:
        raise ProductRunReceiptError(
            "binding",
            "live v1_workers qualify requires sandbox_platform kvm|systrap",
        )
    pool = _require_object(
        health["pool"],
        "execution.health.pool",
        keys=frozenset(
            {
                "pool_size",
                "workers_alive",
                "retire_worker_after_batch",
                "worker_reap_failures_total",
                "container_delete_failures_total",
            }
        ),
    )
    for key in ("pool_size", "workers_alive"):
        if _require_nonneg_int(pool[key], f"execution.health.pool.{key}", maximum=10_000) != 50:
            raise ProductRunReceiptError("binding", "reliquary trial requires pool counters == 50")
    if _require_bool(pool["retire_worker_after_batch"], "execution.health.pool.retire_worker_after_batch") is not True:
        raise ProductRunReceiptError("binding", "retire_worker_after_batch must be true")
    for key in ("worker_reap_failures_total", "container_delete_failures_total"):
        if _require_nonneg_int(pool[key], f"execution.health.pool.{key}", maximum=10_000) != 0:
            raise ProductRunReceiptError("binding", f"{key} must be 0")
    api = _require_object(health["api"], "execution.health.api", keys=frozenset({"max_inflight"}))
    if _require_nonneg_int(api["max_inflight"], "execution.health.api.max_inflight", maximum=10_000) != 50:
        raise ProductRunReceiptError("binding", "reliquary api.max_inflight must be 50")

    load = _require_object(
        execution["load"],
        "execution.load",
        keys=frozenset(
            {
                "row",
                "requests",
                "successful",
                "parallel",
                "runtime_id",
                "latency_ms",
                "failures",
                "max_p95_ms",
            }
        ),
    )
    row = _require_str(load["row"], "execution.load.row", max_len=32)
    requests = _require_nonneg_int(load["requests"], "execution.load.requests")
    successful = _require_nonneg_int(load["successful"], "execution.load.successful")
    parallel = _require_nonneg_int(load["parallel"], "execution.load.parallel", maximum=10_000)
    if successful > requests:
        raise ProductRunReceiptError("binding", "load.successful cannot exceed requests")
    if load["runtime_id"] != runtime_id:
        raise ProductRunReceiptError("binding", "load.runtime_id must match health.runtime_id")
    match = _LOAD_ROW_RE.fullmatch(row)
    if match is not None and int(match.group(1)) != parallel:
        raise ProductRunReceiptError(
            "binding",
            f"load.row {row!r} requires parallel={match.group(1)} (got {parallel})",
        )
    latency = _require_object(
        load["latency_ms"],
        "execution.load.latency_ms",
        keys=frozenset({"p50", "p95", "p99", "max"}),
    )
    for key in ("p50", "p95", "p99", "max"):
        _require_nonneg_int(latency[key], f"execution.load.latency_ms.{key}", maximum=86_400_000)
    max_p95 = _require_nonneg_int(load["max_p95_ms"], "execution.load.max_p95_ms", maximum=10_000)
    if max_p95 > 1000:
        raise ProductRunReceiptError("binding", "reliquary max_p95_ms must be <= 1000")
    if latency["p95"] > max_p95:
        raise ProductRunReceiptError("binding", "load p95 exceeds max_p95_ms acceptance threshold")
    failures = load["failures"]
    if not isinstance(failures, list) or len(failures) > MAX_LIST_LEN:
        raise ProductRunReceiptError("schema", "execution.load.failures is invalid")
    for item in failures:
        if not isinstance(item, str) or len(item) > 128:
            raise ProductRunReceiptError("schema", "execution.load.failures entry is invalid")
    if failures:
        raise ProductRunReceiptError("binding", "reliquary load.failures must be empty for qualify")

    expected_health_digest = sha256_hex(canonical_json(health))
    if execution["health_sha256"] != expected_health_digest:
        raise ProductRunReceiptError("binding", "health_sha256 does not match execution.health")
    _require_digest(execution["summary_sha256"], "execution.summary_sha256")
    if "script_sha256" in execution:
        _require_digest(execution["script_sha256"], "execution.script_sha256")


def _validate_agent_execution(execution: dict[str, object]) -> None:
    required = frozenset(
        {
            "kind",
            "sandbox_id",
            "image",
            "network",
            "labels",
            "create_request_sha256",
            "lifecycle",
            "terminals",
            "access_tickets",
            "template_uid",
        }
    )
    _require_object_subset(execution, "execution", required=required, optional=frozenset())
    if execution["kind"] != PRODUCT_KINDS["agent"]:
        raise ProductRunReceiptError("binding", "agent execution.kind mismatch")
    _require_id(execution["sandbox_id"], "execution.sandbox_id")
    image = execution["image"]
    if not isinstance(image, str) or _IMAGE_RE.fullmatch(image) is None:
        raise ProductRunReceiptError("schema", "execution.image is invalid")
    network = _require_network(execution["network"], "execution.network")
    if network["mode"] != "public":
        raise ProductRunReceiptError("binding", "agent execution.network.mode must be public")
    _require_labels(execution["labels"], "execution.labels", customer="agent")
    _require_digest(execution["create_request_sha256"], "execution.create_request_sha256")
    lifecycle = execution["lifecycle"]
    if not isinstance(lifecycle, list) or len(lifecycle) < 2 or len(lifecycle) > MAX_LIST_LEN:
        raise ProductRunReceiptError("schema", "execution.lifecycle is invalid")
    prev_at: datetime | None = None
    for entry in lifecycle:
        item = _require_object(entry, "execution.lifecycle[]", keys=frozenset({"state", "at"}))
        if item["state"] not in _AGENT_STATES:
            raise ProductRunReceiptError("schema", "execution.lifecycle state is unsupported")
        at = _timestamp(item["at"], "execution.lifecycle[].at")
        if prev_at is not None and at <= prev_at:
            raise ProductRunReceiptError(
                "binding",
                "agent lifecycle timestamps must be strictly increasing (freeze/thaw wall-clock)",
            )
        prev_at = at
    terminals = execution["terminals"]
    if not isinstance(terminals, list) or len(terminals) > MAX_LIST_LEN:
        raise ProductRunReceiptError("schema", "execution.terminals is invalid")
    for entry in terminals:
        term = _require_object(
            entry,
            "execution.terminals[]",
            keys=frozenset(
                {
                    "id",
                    "cols",
                    "rows",
                    "exited",
                    "exit_code",
                    "output_sha256",
                    "started_at",
                    "connected",
                }
            ),
        )
        _require_id(term["id"], "execution.terminals[].id")
        cols = _require_nonneg_int(term["cols"], "execution.terminals[].cols", maximum=TERMINAL_DIM_MAX)
        rows = _require_nonneg_int(term["rows"], "execution.terminals[].rows", maximum=TERMINAL_DIM_MAX)
        if cols < 1 or rows < 1:
            raise ProductRunReceiptError("schema", "terminal cols/rows must be >= 1")
        _require_bool(term["exited"], "execution.terminals[].exited")
        _require_bool(term["connected"], "execution.terminals[].connected")
        _timestamp(term["started_at"], "execution.terminals[].started_at")
        exit_code = term["exit_code"]
        if exit_code is not None:
            if (
                not isinstance(exit_code, int)
                or isinstance(exit_code, bool)
                or exit_code < -1
                or exit_code > 255
            ):
                raise ProductRunReceiptError("schema", "execution.terminals[].exit_code is invalid")
        _require_digest(term["output_sha256"], "execution.terminals[].output_sha256")
    tickets = execution["access_tickets"]
    if not isinstance(tickets, list) or len(tickets) > MAX_LIST_LEN:
        raise ProductRunReceiptError("schema", "execution.access_tickets is invalid")
    for entry in tickets:
        ticket = _require_object(
            entry,
            "execution.access_tickets[]",
            keys=frozenset({"ttl_seconds", "issued_at", "consumed"}),
        )
        ttl = _require_nonneg_int(
            ticket["ttl_seconds"], "execution.access_tickets[].ttl_seconds", maximum=TICKET_TTL_MAX
        )
        if ttl < 1:
            raise ProductRunReceiptError("binding", "access ticket ttl_seconds must be 1..300")
        _timestamp(ticket["issued_at"], "execution.access_tickets[].issued_at")
        _require_bool(ticket["consumed"], "execution.access_tickets[].consumed")
    if execution["template_uid"] is not None:
        _require_id(execution["template_uid"], "execution.template_uid")


def _validate_cvm_execution(execution: dict[str, object]) -> None:
    required = frozenset(
        {
            "kind",
            "cvm_id",
            "state",
            "nonce",
            "labels",
            "attestation_evidence",
            "evidence_sha256",
            "tee_kind",
            "last_attest_at",
            "attestation_hardware",
            "lifecycle",
        }
    )
    optional = frozenset({"gpu_bound", "reject_reason"})
    _require_object_subset(execution, "execution", required=required, optional=optional)
    if execution["kind"] != PRODUCT_KINDS["cvm"]:
        raise ProductRunReceiptError("binding", "cvm execution.kind mismatch")
    _require_id(execution["cvm_id"], "execution.cvm_id")
    state = execution["state"]
    if state not in _CVM_STATES:
        raise ProductRunReceiptError("schema", "execution.state is unsupported")
    nonce = _require_str(execution["nonce"], "execution.nonce", max_len=128)
    _require_labels(execution["labels"], "execution.labels", customer="cvm")
    evidence = _require_object(
        execution["attestation_evidence"],
        "execution.attestation_evidence",
        keys=frozenset(
            {"quote_b64", "measurement", "nonce", "issued_at_unix", "tee", "gpu_bound"}
        ),
    )
    quote = _require_str(evidence["quote_b64"], "execution.attestation_evidence.quote_b64", max_len=8192)
    measurement = _require_str(
        evidence["measurement"], "execution.attestation_evidence.measurement", max_len=256
    )
    if evidence["nonce"] != nonce:
        raise ProductRunReceiptError("binding", "attestation_evidence.nonce must match execution.nonce")
    issued_at = _require_nonneg_int(
        evidence["issued_at_unix"], "execution.attestation_evidence.issued_at_unix", maximum=10**12
    )
    if evidence["tee"] not in _TEE_KINDS:
        raise ProductRunReceiptError("schema", "attestation_evidence.tee is unsupported")
    _require_bool(evidence["gpu_bound"], "execution.attestation_evidence.gpu_bound")
    expected = sha256_hex(canonical_json(evidence))
    if execution["evidence_sha256"] != expected:
        raise ProductRunReceiptError(
            "binding", "evidence_sha256 must digest attestation_evidence document"
        )
    if execution["tee_kind"] != "reference" or evidence["tee"] != "reference":
        raise ProductRunReceiptError(
            "binding",
            "product run receipts only record tee_kind=reference; live tdx/snp belongs on sealed/affine artifacts",
        )
    if not quote.startswith("ref."):
        raise ProductRunReceiptError("binding", "reference quote_b64 must start with 'ref.'")
    if not measurement:
        raise ProductRunReceiptError("schema", "measurement is required")
    last_attest = _require_nonneg_int(execution["last_attest_at"], "execution.last_attest_at", maximum=10**12)
    if state == "running":
        if last_attest <= 0 or issued_at <= 0:
            raise ProductRunReceiptError(
                "binding",
                "running CVM receipts require last_attest_at and evidence.issued_at_unix > 0",
            )
    if _require_bool(execution["attestation_hardware"], "execution.attestation_hardware") is True:
        raise ProductRunReceiptError(
            "binding",
            "product run receipts must set attestation_hardware=false; use affine claims / customer receipts for live TDX",
        )
    lifecycle = execution["lifecycle"]
    if not isinstance(lifecycle, list) or not lifecycle or len(lifecycle) > MAX_LIST_LEN:
        raise ProductRunReceiptError("schema", "execution.lifecycle is invalid")
    prev_at: datetime | None = None
    for entry in lifecycle:
        item = _require_object(entry, "execution.lifecycle[]", keys=frozenset({"state", "at"}))
        if item["state"] not in _CVM_STATES:
            raise ProductRunReceiptError("schema", "execution.lifecycle state is unsupported")
        at = _timestamp(item["at"], "execution.lifecycle[].at")
        if prev_at is not None and at <= prev_at:
            raise ProductRunReceiptError("binding", "cvm lifecycle timestamps must be strictly increasing")
        prev_at = at
    if "gpu_bound" in execution:
        _require_bool(execution["gpu_bound"], "execution.gpu_bound")
    if "reject_reason" in execution and execution["reject_reason"] is not None:
        _require_str(execution["reject_reason"], "execution.reject_reason", max_len=256)


def validate_execution(product: str, surface: str, execution: object) -> dict[str, object]:
    if not isinstance(execution, dict):
        raise ProductRunReceiptError("schema", "execution must be an object")
    if product == "affline":
        _validate_affline_execution(execution)
    elif product == "ditto":
        _validate_ditto_execution(execution)
    elif product == "reliquary":
        _validate_reliquary_execution(execution, surface=surface)
    elif product == "agent":
        _validate_agent_execution(execution)
    elif product == "cvm":
        _validate_cvm_execution(execution)
    else:
        raise ProductRunReceiptError("schema", "product is unsupported")
    return execution


def validate_evidence(product: str, evidence: object) -> dict[str, object]:
    if not isinstance(evidence, dict):
        raise ProductRunReceiptError("schema", "evidence must be an object")
    common_required = frozenset(
        {
            "trust",
            "validation_purpose",
            "skip_rerun_authorized",
            "affline_sandbox_tee_claimed",
            "related_schemas",
        }
    )
    if product == "affline":
        required = common_required | frozenset(
            {
                "affine_claim_id",
                "affine_claim_sha256",
                "claim_attestation_class",
                "execution_profile_id",
                "required_validator_action",
            }
        )
        optional: frozenset[str] = frozenset()
    elif product == "ditto":
        required = common_required | frozenset({"tier", "expects_isolation"})
        optional = frozenset()
    elif product == "reliquary":
        required = common_required | frozenset(
            {"tier", "runtime_digest_is_host_tee", "admission_enabled_at_issue"}
        )
        optional = frozenset()
    elif product == "agent":
        required = common_required | frozenset({"tier", "sealed_customer_receipt"})
        optional = frozenset()
    elif product == "cvm":
        required = common_required | frozenset({"tier", "hardware_reverified_at_issue"})
        optional = frozenset()
    else:
        raise ProductRunReceiptError("schema", "product is unsupported")

    _require_object_subset(evidence, "evidence", required=required, optional=optional)
    if evidence["trust"] not in TRUST_CLASSES:
        raise ProductRunReceiptError("binding", "evidence.trust must be host_trusted")
    _require_str(evidence["validation_purpose"], "evidence.validation_purpose", max_len=256)
    if _require_bool(evidence["skip_rerun_authorized"], "evidence.skip_rerun_authorized") is True:
        raise ProductRunReceiptError(
            "binding",
            "product run receipts must set skip_rerun_authorized=false; use cathedral_affine_claim_v1",
        )
    if (
        _require_bool(evidence["affline_sandbox_tee_claimed"], "evidence.affline_sandbox_tee_claimed")
        is True
    ):
        raise ProductRunReceiptError("binding", "affline_sandbox_tee_claimed must be false")
    related = evidence["related_schemas"]
    if not isinstance(related, list) or len(related) > MAX_LIST_LEN:
        raise ProductRunReceiptError("schema", "evidence.related_schemas is invalid")
    for item in related:
        if not isinstance(item, str) or len(item) > 128:
            raise ProductRunReceiptError("schema", "evidence.related_schemas entry is invalid")

    if product == "affline":
        if evidence["affine_claim_id"] is not None:
            _require_id(evidence["affine_claim_id"], "evidence.affine_claim_id")
        if evidence["affine_claim_sha256"] is not None:
            _require_digest(evidence["affine_claim_sha256"], "evidence.affine_claim_sha256")
        claim_class = evidence["claim_attestation_class"]
        if claim_class not in {"none", "binding_dev", "confidential_cpu"}:
            raise ProductRunReceiptError("schema", "evidence.claim_attestation_class is unsupported")
        if evidence["execution_profile_id"] is not None:
            _require_str(evidence["execution_profile_id"], "evidence.execution_profile_id", max_len=128)
        # Product-run receipts never authorize skip; validators must full_rerun.
        if evidence["required_validator_action"] != "full_rerun":
            raise ProductRunReceiptError(
                "binding",
                "affline product receipts must set required_validator_action=full_rerun "
                "(accept_receipt only via cathedral_affine_claim_v1 + confidential_cpu)",
            )
        claim_linked = evidence["affine_claim_id"] is not None
        if claim_linked != (evidence["affine_claim_sha256"] is not None):
            raise ProductRunReceiptError(
                "binding", "affine_claim_id and affine_claim_sha256 must both be set or both null"
            )
        if claim_linked and "cathedral_affine_claim_v1" not in related:
            raise ProductRunReceiptError(
                "binding", "linked Affine claim requires related_schemas to include cathedral_affine_claim_v1"
            )
        if not claim_linked and related:
            raise ProductRunReceiptError(
                "binding",
                "do not advertise related_schemas without a linked claim artifact",
            )
    elif product == "ditto":
        tier = _require_str(evidence["tier"], "evidence.tier", max_len=64)
        expects = evidence["expects_isolation"]
        if expects not in _EXPECTS_ISOLATION:
            raise ProductRunReceiptError(
                "schema",
                "expects_isolation must be '0' or '1' (CATHEDRAL_EXPECTS_ISOLATION)",
            )
        if tier == "ditto-ready" and expects != "1":
            raise ProductRunReceiptError(
                "binding", "tier=ditto-ready requires expects_isolation='1'"
            )
    elif product == "reliquary":
        tier = _require_str(evidence["tier"], "evidence.tier", max_len=64)
        if _require_bool(evidence["runtime_digest_is_host_tee"], "evidence.runtime_digest_is_host_tee"):
            raise ProductRunReceiptError("binding", "runtime_digest_is_host_tee must be false")
        _require_bool(evidence["admission_enabled_at_issue"], "evidence.admission_enabled_at_issue")
        if tier == "reliquary-workers-qualified" and "qualified" not in tier:
            pass  # kept for clarity; platform check happens in bind
    elif product == "agent":
        _require_str(evidence["tier"], "evidence.tier", max_len=64)
        if _require_bool(evidence["sealed_customer_receipt"], "evidence.sealed_customer_receipt"):
            raise ProductRunReceiptError("binding", "sealed_customer_receipt must be false here")
    elif product == "cvm":
        _require_str(evidence["tier"], "evidence.tier", max_len=64)
        if _require_bool(
            evidence["hardware_reverified_at_issue"], "evidence.hardware_reverified_at_issue"
        ):
            raise ProductRunReceiptError(
                "binding",
                "hardware_reverified_at_issue must be false on product run receipts",
            )
    return evidence


def bind_execution_evidence(
    product: str, surface: str, execution: dict[str, object], evidence: dict[str, object]
) -> None:
    """Cross-field rules matching what validators would reject as misleading."""

    if product == "affline":
        has_digests = any(field in execution for field in _AFFINE_DIGEST_FIELDS)
        outcome = execution["verify_outcome"]
        claim_linked = evidence["affine_claim_id"] is not None
        if has_digests or outcome in {"passed", "failed"}:
            if not claim_linked:
                raise ProductRunReceiptError(
                    "binding",
                    "Affine digests/verify_outcome require linked cathedral_affine_claim_v1 "
                    "(affine_claim_id + affine_claim_sha256); Harbor-only runs use "
                    "verify_outcome=not_applicable with digests omitted",
                )
            missing = [field for field in _AFFINE_DIGEST_FIELDS if field not in execution]
            if missing:
                raise ProductRunReceiptError(
                    "binding",
                    "linked Affine claim requires full digest quartet: " + ",".join(missing),
                )
            if evidence["claim_attestation_class"] == "none":
                raise ProductRunReceiptError(
                    "binding",
                    "linked claim must set claim_attestation_class to binding_dev or confidential_cpu",
                )
        else:
            if claim_linked:
                raise ProductRunReceiptError(
                    "binding",
                    "linked Affine claim requires digest quartet and verify_outcome passed|failed",
                )
            if outcome != "not_applicable":
                raise ProductRunReceiptError(
                    "binding",
                    "Harbor-only Affline receipts must use verify_outcome=not_applicable",
                )
    elif product == "reliquary":
        platform = execution["health"]["sandbox_platform"]
        tier = evidence["tier"]
        if tier == "reliquary-workers-qualified" and platform not in {"kvm", "systrap"}:
            raise ProductRunReceiptError(
                "binding",
                "tier=reliquary-workers-qualified requires health.sandbox_platform kvm|systrap",
            )
        if surface == "offline_pack" and tier == "reliquary-workers-qualified":
            raise ProductRunReceiptError(
                "binding",
                "qualified Reliquary receipts must use surface=v1_workers, not offline_pack",
            )
    elif product == "ditto":
        if evidence["tier"] == "ditto-ready" and execution["score_probe"]["exit_code"] != 0:
            raise ProductRunReceiptError(
                "binding", "ditto-ready requires score_probe.exit_code == 0"
            )


def build_validator_view(
    *,
    product: str,
    surface: str,
    outcome: str,
    run_id: str,
    execution: Mapping[str, object],
    evidence: Mapping[str, object],
) -> dict[str, object]:
    """Compact fields subnet validators typically need for partial verification."""

    base: dict[str, object] = {
        "product": product,
        "surface": surface,
        "run_id": run_id,
        "outcome": outcome,
        "kind": execution.get("kind"),
        "trust": evidence.get("trust"),
        "skip_rerun_authorized": False,
        "tee_claimed": False,
        "validation_purpose": evidence.get("validation_purpose"),
    }
    if product == "affline":
        exec_probe = execution.get("exec")
        base.update(
            {
                "sandbox_id": execution.get("sandbox_id"),
                "image": execution.get("image"),
                "image_digest": execution.get("image_digest"),
                "network_mode": (execution.get("network") or {}).get("mode")
                if isinstance(execution.get("network"), dict)
                else None,
                "create_request_sha256": execution.get("create_request_sha256"),
                "exec_exit_code": exec_probe.get("exit_code")
                if isinstance(exec_probe, dict)
                else None,
                "exec_stdout_sha256": exec_probe.get("stdout_sha256")
                if isinstance(exec_probe, dict)
                else None,
                "exec_stderr_sha256": exec_probe.get("stderr_sha256")
                if isinstance(exec_probe, dict)
                else None,
                "affine_claim_id": evidence.get("affine_claim_id"),
                "affine_claim_sha256": evidence.get("affine_claim_sha256"),
                "affine_verify_code_sha256": execution.get("affine_verify_code_sha256"),
                "affine_verify_inputs_sha256": execution.get("affine_verify_inputs_sha256"),
                "miner_payload_sha256": execution.get("miner_payload_sha256"),
                "verify_result_sha256": execution.get("verify_result_sha256"),
                "verify_outcome": execution.get("verify_outcome"),
                "claim_attestation_class": evidence.get("claim_attestation_class"),
                "required_validator_action": "full_rerun",
                "related_claim_schema": "cathedral_affine_claim_v1"
                if evidence.get("affine_claim_id")
                else None,
            }
        )
    elif product == "ditto":
        probe = execution.get("score_probe")
        quota = execution.get("quota")
        base.update(
            {
                "sandbox_id": execution.get("sandbox_id"),
                "image": execution.get("image"),
                "network_mode": "none",
                "ttl_seconds": execution.get("ttl_seconds"),
                "entrypoint": execution.get("entrypoint"),
                "max_running": quota.get("max_running") if isinstance(quota, dict) else None,
                "cap_trial_exercised": quota.get("cap_trial_exercised")
                if isinstance(quota, dict)
                else None,
                "rejected_429": quota.get("rejected_429") if isinstance(quota, dict) else None,
                "score_cmd_sha256": probe.get("cmd_sha256") if isinstance(probe, dict) else None,
                "score_exit_code": probe.get("exit_code") if isinstance(probe, dict) else None,
                "score_result_sha256": probe.get("result_sha256")
                if isinstance(probe, dict)
                else None,
                "tier": evidence.get("tier"),
                "expects_isolation": evidence.get("expects_isolation"),
            }
        )
    elif product == "reliquary":
        health = execution.get("health") if isinstance(execution.get("health"), dict) else {}
        pool = health.get("pool") if isinstance(health.get("pool"), dict) else {}
        api = health.get("api") if isinstance(health.get("api"), dict) else {}
        load = execution.get("load") if isinstance(execution.get("load"), dict) else {}
        base.update(
            {
                "allocation_id": execution.get("allocation_id"),
                "executor_id": health.get("executor_id"),
                "runtime_id": health.get("runtime_id"),
                "image_id": execution.get("image_id"),
                "source_revision": execution.get("source_revision"),
                "sandbox_backend": health.get("sandbox_backend"),
                "sandbox_platform": health.get("sandbox_platform"),
                "protocol_version": health.get("protocol_version"),
                "status": health.get("status"),
                "pool_size": pool.get("pool_size"),
                "workers_alive": pool.get("workers_alive"),
                "max_inflight": api.get("max_inflight"),
                "retire_worker_after_batch": pool.get("retire_worker_after_batch"),
                "worker_reap_failures_total": pool.get("worker_reap_failures_total"),
                "container_delete_failures_total": pool.get("container_delete_failures_total"),
                "load_row": load.get("row"),
                "load_parallel": load.get("parallel"),
                "load_successful": load.get("successful"),
                "load_max_p95_ms": load.get("max_p95_ms"),
                "health_sha256": execution.get("health_sha256"),
                "summary_sha256": execution.get("summary_sha256"),
                "script_sha256": execution.get("script_sha256"),
                "runtime_digest_is_host_tee": False,
            }
        )
    elif product == "agent":
        base.update(
            {
                "sandbox_id": execution.get("sandbox_id"),
                "network_mode": "public",
                "lifecycle": execution.get("lifecycle"),
                "terminals": execution.get("terminals"),
                "access_tickets": execution.get("access_tickets"),
                "template_uid": execution.get("template_uid"),
                "tier": evidence.get("tier"),
            }
        )
    elif product == "cvm":
        evidence_doc = execution.get("attestation_evidence")
        base.update(
            {
                "cvm_id": execution.get("cvm_id"),
                "state": execution.get("state"),
                "tee_kind": "reference",
                "nonce": execution.get("nonce"),
                "evidence_sha256": execution.get("evidence_sha256"),
                "measurement": evidence_doc.get("measurement")
                if isinstance(evidence_doc, dict)
                else None,
                "quote_b64_prefix": "ref.",
                "last_attest_at": execution.get("last_attest_at"),
                "attestation_hardware": False,
                "lifecycle": execution.get("lifecycle"),
                "labels": execution.get("labels"),
                "tier": evidence.get("tier"),
            }
        )
    return base


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def build_affline_execution(
    *,
    sandbox_id: str,
    image: str,
    create_request_sha256: str,
    exec_cmd_sha256: str,
    exec_stdout_sha256: str,
    exec_stderr_sha256: str,
    exec_exit_code: int = 0,
    exec_duration_ms: int = 0,
    timed_out: bool = False,
    image_digest: str | None = None,
    network_mode: str = "none",
    ttl_seconds: int = 600,
    vcpu: int = 2,
    memory_gib: int = 4,
    disk_gib: int = 20,
    adapter: str = "harbor_cathedral",
    labels: Mapping[str, str] | None = None,
    task_id: str | None = None,
    dataset: str | None = None,
    agent_name: str | None = None,
    affine_verify_code_sha256: str | None = None,
    affine_verify_inputs_sha256: str | None = None,
    miner_payload_sha256: str | None = None,
    verify_result_sha256: str | None = None,
    verify_outcome: str = "not_applicable",
) -> dict[str, object]:
    out: dict[str, object] = {
        "kind": PRODUCT_KINDS["affline"],
        "sandbox_id": sandbox_id,
        "image": image,
        "image_digest": image_digest,
        "resources": {"vcpu": vcpu, "memory_gib": memory_gib, "disk_gib": disk_gib},
        "network": {"mode": network_mode, "allow": []},
        "labels": dict(labels or {"customer": "affline", "adapter": adapter}),
        "ttl_seconds": ttl_seconds,
        "create_request_sha256": create_request_sha256,
        "exec": {
            "cmd_sha256": exec_cmd_sha256,
            "exit_code": exec_exit_code,
            "stdout_sha256": exec_stdout_sha256,
            "stderr_sha256": exec_stderr_sha256,
            "duration_ms": exec_duration_ms,
            "timed_out": timed_out,
        },
        "adapter": adapter,
        "verify_outcome": verify_outcome,
    }
    if task_id is not None:
        out["task_id"] = task_id
    if dataset is not None:
        out["dataset"] = dataset
    if agent_name is not None:
        out["agent_name"] = agent_name
    for key, value in (
        ("affine_verify_code_sha256", affine_verify_code_sha256),
        ("affine_verify_inputs_sha256", affine_verify_inputs_sha256),
        ("miner_payload_sha256", miner_payload_sha256),
        ("verify_result_sha256", verify_result_sha256),
    ):
        if value is not None:
            out[key] = value
    return out


def build_affline_evidence(
    *,
    validation_purpose: str = (
        "Partial Harbor trial verify: match create/exec digests and exit_code. "
        "Validators must full_rerun; accept_receipt only via cathedral_affine_claim_v1 "
        "with confidential_cpu + independent hardware re-verify"
    ),
    affine_claim_id: str | None = None,
    affine_claim_sha256: str | None = None,
    claim_attestation_class: str = "none",
    execution_profile_id: str | None = None,
) -> dict[str, object]:
    related: list[str] = []
    if affine_claim_id is not None:
        related = ["cathedral_affine_claim_v1"]
    return {
        "trust": "host_trusted",
        "validation_purpose": validation_purpose,
        "skip_rerun_authorized": False,
        "required_validator_action": "full_rerun",
        "affline_sandbox_tee_claimed": False,
        "related_schemas": related,
        "affine_claim_id": affine_claim_id,
        "affine_claim_sha256": affine_claim_sha256,
        "claim_attestation_class": claim_attestation_class,
        "execution_profile_id": execution_profile_id,
    }


def build_ditto_execution(
    *,
    sandbox_id: str,
    image: str,
    create_request_sha256: str,
    score_cmd_sha256: str,
    score_result_sha256: str,
    score_stdout_sha256: str,
    score_stderr_sha256: str,
    score_exit_code: int = 0,
    score_duration_ms: int = 0,
    timed_out: bool = False,
    image_digest: str | None = None,
    ttl_seconds: int = 600,
    max_running: int = 8,
    rejected_429: bool = False,
    retry_after_seconds: int = 0,
    cap_trial_exercised: bool = False,
    vcpu: int = 1,
    memory_gib: int = 2,
    disk_gib: int = 10,
    entrypoint: Sequence[str] | None = None,
    labels: Mapping[str, str] | None = None,
) -> dict[str, object]:
    return {
        "kind": PRODUCT_KINDS["ditto"],
        "sandbox_id": sandbox_id,
        "image": image,
        "image_digest": image_digest,
        "resources": {"vcpu": vcpu, "memory_gib": memory_gib, "disk_gib": disk_gib},
        "network": {"mode": "none", "allow": []},
        "labels": dict(labels or {"customer": "ditto", "job": "ditto-harness"}),
        "ttl_seconds": ttl_seconds,
        "create_request_sha256": create_request_sha256,
        "entrypoint": list(entrypoint or ["sleep", "infinity"]),
        "quota": {
            "max_running": max_running,
            "rejected_429": rejected_429,
            "retry_after_seconds": retry_after_seconds,
            "cap_trial_exercised": cap_trial_exercised,
        },
        "score_probe": {
            "cmd_sha256": score_cmd_sha256,
            "exit_code": score_exit_code,
            "result_sha256": score_result_sha256,
            "stdout_sha256": score_stdout_sha256,
            "stderr_sha256": score_stderr_sha256,
            "duration_ms": score_duration_ms,
            "timed_out": timed_out,
        },
    }


def build_ditto_evidence(
    *,
    tier: str = "ditto-reference",
    expects_isolation: str = "0",
    validation_purpose: str = (
        "Partial harness verify: network.mode=none, create digest, score_probe "
        "cmd/exit/result digests, max_running 2..8, expects_isolation flag"
    ),
) -> dict[str, object]:
    return {
        "trust": "host_trusted",
        "validation_purpose": validation_purpose,
        "skip_rerun_authorized": False,
        "affline_sandbox_tee_claimed": False,
        "related_schemas": [],
        "tier": tier,
        "expects_isolation": expects_isolation,
    }


def build_reliquary_health(
    *,
    allocation_id: str,
    runtime_id: str,
    sandbox_platform: str,
    sandbox_backend: str = "runsc",
) -> dict[str, object]:
    return {
        "status": "ok",
        "protocol_version": 2,
        "executor_id": allocation_id,
        "runtime_id": runtime_id,
        "sandbox_backend": sandbox_backend,
        "sandbox_platform": sandbox_platform,
        "pool": {
            "pool_size": 50,
            "workers_alive": 50,
            "retire_worker_after_batch": True,
            "worker_reap_failures_total": 0,
            "container_delete_failures_total": 0,
        },
        "api": {"max_inflight": 50},
    }


def build_reliquary_execution(
    *,
    allocation_id: str,
    runtime_id: str,
    image_id: str,
    source_revision: str,
    summary_sha256: str,
    sandbox_platform: str = "reference",
    batch_deadline_seconds: int = 120,
    load_row: str = "32_of_50",
    requests: int = 3000,
    successful: int = 3000,
    parallel: int | None = None,
    latency_ms: Mapping[str, int] | None = None,
    failures: list[str] | None = None,
    max_p95_ms: int = 1000,
    script_sha256: str | None = None,
) -> dict[str, object]:
    if parallel is None:
        match = _LOAD_ROW_RE.fullmatch(load_row)
        parallel = int(match.group(1)) if match else 50
    health = build_reliquary_health(
        allocation_id=allocation_id,
        runtime_id=runtime_id,
        sandbox_platform=sandbox_platform,
    )
    lat = dict(latency_ms or {"p50": 400, "p95": 600, "p99": 800, "max": 1200})
    out: dict[str, object] = {
        "kind": PRODUCT_KINDS["reliquary"],
        "allocation_id": allocation_id,
        "image_id": image_id,
        "source_revision": source_revision,
        "batch_deadline_seconds": batch_deadline_seconds,
        "health": health,
        "load": {
            "row": load_row,
            "requests": requests,
            "successful": successful,
            "parallel": parallel,
            "runtime_id": runtime_id,
            "latency_ms": {
                "p50": int(lat["p50"]),
                "p95": int(lat["p95"]),
                "p99": int(lat["p99"]),
                "max": int(lat["max"]),
            },
            "failures": list(failures or []),
            "max_p95_ms": max_p95_ms,
        },
        "health_sha256": sha256_hex(canonical_json(health)),
        "summary_sha256": summary_sha256,
    }
    if script_sha256 is not None:
        out["script_sha256"] = script_sha256
    return out


def build_reliquary_evidence(
    *,
    tier: str = "reliquary-workers-offline",
    admission_enabled_at_issue: bool = True,
    validation_purpose: str | None = None,
) -> dict[str, object]:
    if validation_purpose is None:
        if tier == "reliquary-workers-qualified":
            validation_purpose = (
                "Partial Workers qualify verify against qualify-client.validate_health/"
                "validate_load keys (pool 50, api.max_inflight 50, cleanup 0, load row parallel)"
            )
        else:
            validation_purpose = (
                "Offline Workers pack evidence with qualify-shaped health/load fields; "
                "platform may be reference — not a live kvm/systrap qualify pass"
            )
    return {
        "trust": "host_trusted",
        "validation_purpose": validation_purpose,
        "skip_rerun_authorized": False,
        "affline_sandbox_tee_claimed": False,
        "related_schemas": [],
        "tier": tier,
        "runtime_digest_is_host_tee": False,
        "admission_enabled_at_issue": admission_enabled_at_issue,
    }


def build_agent_execution(
    *,
    sandbox_id: str,
    image: str,
    create_request_sha256: str,
    lifecycle: list[Mapping[str, str]],
    terminals: list[Mapping[str, object]] | None = None,
    access_tickets: list[Mapping[str, object]] | None = None,
    template_uid: str | None = None,
    labels: Mapping[str, str] | None = None,
) -> dict[str, object]:
    return {
        "kind": PRODUCT_KINDS["agent"],
        "sandbox_id": sandbox_id,
        "image": image,
        "network": {"mode": "public", "allow": []},
        "labels": dict(labels or {"customer": "agent", "job": "agent-ide"}),
        "create_request_sha256": create_request_sha256,
        "lifecycle": [dict(item) for item in lifecycle],
        "terminals": [dict(item) for item in (terminals or [])],
        "access_tickets": [dict(item) for item in (access_tickets or [])],
        "template_uid": template_uid,
    }


def build_agent_evidence(
    *,
    tier: str = "agent-reference",
    validation_purpose: str = (
        "Partial Agent IDE verify: public network, strictly-increasing freeze/thaw "
        "timestamps, terminal dims/exit/output digests, access ticket TTL 1..300"
    ),
) -> dict[str, object]:
    return {
        "trust": "host_trusted",
        "validation_purpose": validation_purpose,
        "skip_rerun_authorized": False,
        "affline_sandbox_tee_claimed": False,
        "related_schemas": [],
        "tier": tier,
        "sealed_customer_receipt": False,
    }


def build_cvm_attestation_evidence(
    *,
    nonce: str,
    measurement: str = "m_ref_v1",
    issued_at_unix: int,
    gpu_bound: bool = False,
) -> dict[str, object]:
    material = f"{nonce}:{measurement}".encode()
    digest = hashlib.sha256(material).hexdigest()
    return {
        "quote_b64": f"ref.{digest}",
        "measurement": measurement,
        "nonce": nonce,
        "issued_at_unix": issued_at_unix,
        "tee": "reference",
        "gpu_bound": gpu_bound,
    }


def build_cvm_execution(
    *,
    cvm_id: str,
    state: str,
    nonce: str,
    lifecycle: list[Mapping[str, str]],
    issued_at_unix: int,
    last_attest_at: int | None = None,
    measurement: str = "m_ref_v1",
    gpu_bound: bool = False,
    labels: Mapping[str, str] | None = None,
    reject_reason: str | None = None,
) -> dict[str, object]:
    evidence = build_cvm_attestation_evidence(
        nonce=nonce,
        measurement=measurement,
        issued_at_unix=issued_at_unix,
        gpu_bound=gpu_bound,
    )
    out: dict[str, object] = {
        "kind": PRODUCT_KINDS["cvm"],
        "cvm_id": cvm_id,
        "state": state,
        "nonce": nonce,
        "labels": dict(labels or {"customer": "cvm"}),
        "attestation_evidence": evidence,
        "evidence_sha256": sha256_hex(canonical_json(evidence)),
        "tee_kind": "reference",
        "last_attest_at": last_attest_at if last_attest_at is not None else issued_at_unix,
        "attestation_hardware": False,
        "lifecycle": [dict(item) for item in lifecycle],
        "gpu_bound": gpu_bound,
    }
    if reject_reason is not None:
        out["reject_reason"] = reject_reason
    return out


def build_cvm_evidence(
    *,
    tier: str = "cvm-reference",
    validation_purpose: str = (
        "Partial CVM-reference lifecycle verify: AttestationEvidence document "
        "(quote_b64/measurement/nonce/issued_at_unix/tee) + state machine; "
        "live TDX/SNP uses hardware attest + customer/affine receipts"
    ),
) -> dict[str, object]:
    return {
        "trust": "host_trusted",
        "validation_purpose": validation_purpose,
        "skip_rerun_authorized": False,
        "affline_sandbox_tee_claimed": False,
        "related_schemas": [],
        "tier": tier,
        "hardware_reverified_at_issue": False,
    }


def _load_trusted_keys(raw: bytes) -> dict[str, Mapping[str, object]]:
    document = _parse_object(raw, label="trusted keys", maximum_bytes=MAX_TRUSTED_KEYS_BYTES)
    if set(document) != _TRUSTED_KEYS_TOP_LEVEL:
        raise ProductRunReceiptError("key", "trusted keys document has unexpected fields")
    if document["schema"] != PRODUCT_RUN_RECEIPT_TRUSTED_KEYS_SCHEMA:
        raise ProductRunReceiptError("key", "trusted keys schema is unsupported")
    keys = document["keys"]
    if not isinstance(keys, dict) or not keys:
        raise ProductRunReceiptError("key", "trusted keys map is empty")
    out: dict[str, Mapping[str, object]] = {}
    for key_id, entry in keys.items():
        if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
            raise ProductRunReceiptError("key", "trusted key id is invalid")
        if not isinstance(entry, dict) or set(entry) != _TRUSTED_KEY_FIELDS:
            raise ProductRunReceiptError("key", f"trusted key {key_id!r} fields are invalid")
        if entry.get("algorithm") != "ed25519":
            raise ProductRunReceiptError("key", f"trusted key {key_id!r} algorithm is unsupported")
        if entry.get("status") not in _KEY_STATUSES:
            raise ProductRunReceiptError("key", f"trusted key {key_id!r} status is unsupported")
        _timestamp(entry["valid_from"], "valid_from")
        _timestamp(entry["valid_until"], "valid_until")
        pk = entry["public_key_base64"]
        if not isinstance(pk, str):
            raise ProductRunReceiptError("key", f"trusted key {key_id!r} public key is invalid")
        try:
            raw_pk = base64.b64decode(pk, validate=True)
        except Exception as exc:
            raise ProductRunReceiptError("key", f"trusted key {key_id!r} public key is invalid") from exc
        if len(raw_pk) != 32:
            raise ProductRunReceiptError("key", f"trusted key {key_id!r} public key is invalid")
        out[key_id] = MappingProxyType(entry)
    return out


def _public_key_for(
    key_id: str,
    trusted: Mapping[str, Mapping[str, object]],
    *,
    issued_at: datetime,
) -> Ed25519PublicKey:
    entry = trusted.get(key_id)
    if entry is None:
        raise ProductRunReceiptError("key", f"signing key {key_id!r} is not trusted")
    if entry["status"] == "revoked":
        raise ProductRunReceiptError("key", f"signing key {key_id!r} is revoked")
    valid_from = _timestamp(entry["valid_from"], "valid_from")
    valid_until = _timestamp(entry["valid_until"], "valid_until")
    if issued_at < valid_from or issued_at >= valid_until:
        raise ProductRunReceiptError("key", f"signing key {key_id!r} is outside its validity window")
    raw_pk = base64.b64decode(str(entry["public_key_base64"]), validate=True)
    return Ed25519PublicKey.from_public_bytes(raw_pk)


def issue_product_run_receipt(
    *,
    product: str,
    surface: str,
    run_id: str,
    request_bytes: bytes,
    result_bytes: bytes,
    outcome: str,
    private_key: Ed25519PrivateKey,
    signing_key_id: str,
    execution: Mapping[str, Any],
    evidence: Mapping[str, Any],
    note: str = "",
    issued_at: datetime | None = None,
) -> bytes:
    if product not in PRODUCTS:
        raise ProductRunReceiptError("schema", "product is unsupported")
    if surface not in SURFACES:
        raise ProductRunReceiptError("schema", "surface is unsupported")
    if surface not in PRODUCT_SURFACES[product]:
        raise ProductRunReceiptError("binding", f"{product} does not use surface {surface}")
    if outcome not in OUTCOMES:
        raise ProductRunReceiptError("schema", "outcome is unsupported")
    if not isinstance(note, str) or len(note.encode("utf-8")) > MAX_NOTE_BYTES:
        raise ProductRunReceiptError("schema", "note is invalid")
    if _KEY_ID_RE.fullmatch(signing_key_id) is None:
        raise ProductRunReceiptError("schema", "signing_key_id is invalid")
    execution_obj = validate_execution(product, surface, dict(execution))
    evidence_obj = validate_evidence(product, dict(evidence))
    bind_execution_evidence(product, surface, execution_obj, evidence_obj)
    when = issued_at or datetime.now(UTC)
    if when.tzinfo is None:
        raise ProductRunReceiptError("schema", "issued_at must be timezone-aware UTC")
    issued_text = when.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    body: dict[str, object] = {
        "schema": PRODUCT_RUN_RECEIPT_SCHEMA,
        "issued_at": issued_text,
        "policy_digest": PRODUCT_RUN_RECEIPT_POLICY_DIGEST,
        "signing_key_id": signing_key_id,
        "receipt_status": "ready",
        "product": product,
        "surface": surface,
        "tee_claimed": False,
        "attestation_class": "none",
        "run_id": run_id,
        "request_sha256": sha256_hex(request_bytes),
        "result_sha256": sha256_hex(result_bytes),
        "outcome": outcome,
        "note": note,
        "execution": execution_obj,
        "evidence": evidence_obj,
    }
    _require_id(run_id, "run_id")
    receipt_id = sha256_hex(canonical_json(body))
    unsigned = {**body, "receipt_id": receipt_id}
    signature = private_key.sign(canonical_json(unsigned))
    signed = {
        **unsigned,
        "signature": {
            "algorithm": "ed25519",
            "value_base64": base64.b64encode(signature).decode("ascii"),
        },
    }
    return canonical_json(signed)


def verify_product_run_receipt(
    raw: bytes,
    *,
    trusted_keys: bytes,
    max_age_seconds: int | None = None,
) -> VerifiedProductRunReceipt:
    document = _parse_object(raw, label="product run receipt", maximum_bytes=MAX_RECEIPT_BYTES)
    if set(document) != _TOP_LEVEL_KEYS:
        raise ProductRunReceiptError("schema", "product run receipt has unexpected or missing fields")
    if document["schema"] != PRODUCT_RUN_RECEIPT_SCHEMA:
        raise ProductRunReceiptError("schema", "product run receipt schema is unsupported")
    if document["policy_digest"] != PRODUCT_RUN_RECEIPT_POLICY_DIGEST:
        raise ProductRunReceiptError("policy", "product run receipt policy digest is unsupported")
    if document["receipt_status"] != "ready":
        raise ProductRunReceiptError("status", "product run receipt status is not ready")
    product = document["product"]
    surface = document["surface"]
    outcome = document["outcome"]
    if product not in PRODUCTS or surface not in SURFACES or outcome not in OUTCOMES:
        raise ProductRunReceiptError("schema", "product/surface/outcome is unsupported")
    if not isinstance(product, str) or not isinstance(surface, str) or not isinstance(outcome, str):
        raise ProductRunReceiptError("schema", "product/surface/outcome is unsupported")
    if surface not in PRODUCT_SURFACES[product]:
        raise ProductRunReceiptError("binding", f"{product} does not use surface {surface}")
    if _require_bool(document["tee_claimed"], "tee_claimed") is not False:
        raise ProductRunReceiptError(
            "binding",
            "product run receipts must set tee_claimed=false (use sealed customer receipts for TDX)",
        )
    if document["attestation_class"] not in ATTESTATION_CLASSES:
        raise ProductRunReceiptError("binding", "attestation_class must be none for product run receipts")
    _require_id(document["run_id"], "run_id")
    _require_digest(document["request_sha256"], "request_sha256")
    _require_digest(document["result_sha256"], "result_sha256")
    _require_id(document["receipt_id"], "receipt_id")
    note = document["note"]
    if not isinstance(note, str) or len(note.encode("utf-8")) > MAX_NOTE_BYTES:
        raise ProductRunReceiptError("schema", "note is invalid")
    execution = validate_execution(product, surface, document["execution"])
    evidence = validate_evidence(product, document["evidence"])
    bind_execution_evidence(product, surface, execution, evidence)
    issued_at = _timestamp(document["issued_at"], "issued_at")
    if max_age_seconds is not None:
        age = (datetime.now(UTC) - issued_at).total_seconds()
        if age > max_age_seconds or age < -60:
            raise ProductRunReceiptError("stale", "product run receipt is outside the allowed age")

    signature = document["signature"]
    if not isinstance(signature, dict) or set(signature) != _SIGNATURE_KEYS:
        raise ProductRunReceiptError("signature", "signature object is invalid")
    if signature.get("algorithm") != "ed25519":
        raise ProductRunReceiptError("signature", "signature algorithm is unsupported")
    try:
        sig = base64.b64decode(str(signature["value_base64"]), validate=True)
    except Exception as exc:
        raise ProductRunReceiptError("signature", "signature is not canonical base64") from exc
    if len(sig) != 64:
        raise ProductRunReceiptError("signature", "signature length is invalid")

    unsigned = {k: v for k, v in document.items() if k != "signature"}
    body_for_id = {k: v for k, v in unsigned.items() if k != "receipt_id"}
    expected_id = sha256_hex(canonical_json(body_for_id))
    if document["receipt_id"] != expected_id:
        raise ProductRunReceiptError("binding", "receipt_id does not match body digest")

    trusted = _load_trusted_keys(trusted_keys)
    public_key = _public_key_for(
        str(document["signing_key_id"]),
        trusted,
        issued_at=issued_at,
    )
    try:
        public_key.verify(sig, canonical_json(unsigned))
    except InvalidSignature as exc:
        raise ProductRunReceiptError("signature", "product run receipt signature is invalid") from exc

    view = build_validator_view(
        product=product,
        surface=surface,
        outcome=outcome,
        run_id=str(document["run_id"]),
        execution=execution,
        evidence=evidence,
    )
    return VerifiedProductRunReceipt(
        receipt_id=str(document["receipt_id"]),
        product=product,
        surface=surface,
        outcome=outcome,
        tee_claimed=False,
        document=MappingProxyType(document),
        validator_view=MappingProxyType(view),
    )


__all__ = [
    "PRODUCT_KINDS",
    "PRODUCT_RUN_RECEIPT_POLICY_DIGEST",
    "PRODUCT_RUN_RECEIPT_SCHEMA",
    "PRODUCT_RUN_RECEIPT_TRUSTED_KEYS_SCHEMA",
    "ProductRunReceiptError",
    "VerifiedProductRunReceipt",
    "bind_execution_evidence",
    "build_affline_evidence",
    "build_affline_execution",
    "build_agent_evidence",
    "build_agent_execution",
    "build_cvm_attestation_evidence",
    "build_cvm_evidence",
    "build_cvm_execution",
    "build_ditto_evidence",
    "build_ditto_execution",
    "build_reliquary_evidence",
    "build_reliquary_execution",
    "build_reliquary_health",
    "build_validator_view",
    "canonical_json",
    "issue_product_run_receipt",
    "sha256_hex",
    "validate_evidence",
    "validate_execution",
    "verify_product_run_receipt",
]
