"""Cathedral compute sandbox API request contracts.

This module turns the customer-facing sandbox API shape (cathedral-audit's
requirements document ``requirements.txt`` §§3.1-3.12) into typed, validated,
provider-neutral records the Cathedral control plane can admit and dispatch.

It is deliberately separate from :mod:`cathedral.workload`.  ``workload.py``
holds the hardened confidential-compute admission boundary whose
:class:`~cathedral.workload.ImageReference` *requires* an immutable digest and
rejects mutable tags, credentials and IP-literal registries.  The sandbox
create payload uses a mutable ``image: "…:latest"`` field, so the mutable-ref
grammar lives here and is resolved to a digest before it ever reaches that
boundary.  Nothing here provisions capacity or runs a container; the hosted
``cathedral.computer`` runtime does.  These are the contracts and the
quota/TTL/fork/idempotency decision functions those calls validate against.

Cathedral configuration is read from the same environment variables the
operator tooling and the audit facade already use (``CATHEDRAL_API_URL``,
``CATHEDRAL_KEY_QUOTAS``), so a single ``source env.sh`` configures both paths.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Mapping, Sequence

# ---------------------------------------------------------------- cathedral variables
CATHEDRAL_API_URL = os.environ.get("CATHEDRAL_API_URL", "https://cathedral.computer").rstrip("/")
CATHEDRAL_REGISTRY = os.environ.get("CATHEDRAL_REGISTRY", "registry.cathedral.computer")
# The API base the sandbox surface is served under, mirroring the audit facade.
SANDBOX_API_BASE = f"{CATHEDRAL_API_URL}/v1"


def _configured_key_quotas() -> Mapping[str, int]:
    """Per-key ``max_running`` sub-quotas from ``CATHEDRAL_KEY_QUOTAS`` / ``FACADE_KEY_QUOTAS``.

    Format is ``key:limit,key:limit``.  Read live so a caller can re-import or
    call :func:`key_quota_for` after mutating the environment.
    """
    raw = os.environ.get("CATHEDRAL_KEY_QUOTAS") or os.environ.get("FACADE_KEY_QUOTAS", "")
    quotas: dict[str, int] = {}
    for pair in filter(None, (part.strip() for part in raw.split(","))):
        if ":" in pair:
            key, _, value = pair.partition(":")
            try:
                quotas[key.strip()] = int(value.strip())
            except ValueError:
                continue
    return quotas


def key_quota_for(api_key: str, default: int | None = None) -> int | None:
    """The ``max_running`` cap configured for one API key, or ``default``."""
    return _configured_key_quotas().get(api_key, default)


# ---------------------------------------------------------------- §3.6 resource classes
VCPU_MIN, VCPU_MAX = 1, 16
MEMORY_GIB_MIN, MEMORY_GIB_MAX = 1, 64
DISK_GIB_MIN, DISK_GIB_MAX = 5, 100

# §3.4 lifecycle: default 1 h, max ≥ 48 h; auto-GC within 5 min of expiry.
TTL_DEFAULT_SECONDS = 3600
TTL_MAX_SECONDS = 48 * 3600
GC_GRACE_SECONDS = 300

# §3.5 fork: N ≤ 16 copy-on-write siblings, each running ≤ 15 s after the call.
FORK_MAX_COUNT = 16
FORK_SLO_SECONDS = 15

# §3.5 snapshots: retention is set by us (a TTL), and the service guarantees a
# snapshot store of at least 1,000 per project (Daytona caps at 30).
SNAPSHOT_TTL_DEFAULT_SECONDS = 7 * 24 * 3600
SNAPSHOT_TTL_MAX_SECONDS = 30 * 24 * 3600
MIN_SNAPSHOTS = 1000

# §3.8 project minimums (sustained / 2 h burst).
MIN_RUNNING_SANDBOXES = 500
MIN_VCPU = 1_000
MIN_MEMORY_GIB = 3_000
BURST_RUNNING_SANDBOXES = 1_000
BURST_VCPU = 2_000
BURST_MEMORY_GIB = 6_000
MIN_CREATES_PER_MINUTE = 100

# §3.12 idempotency-key grammar (Harbor's own pattern: 8-128 of A-Za-z0-9._:-).
_IDEMPOTENCY_KEY_RE = re.compile(r"[A-Za-z0-9._:-]{8,128}")
_LABEL_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,62}")
_LABEL_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,63}")
# A docker reference path: optional registry, repository, and a :tag or @digest suffix.
_IMAGE_REF_RE = re.compile(
    r"^(?:(?P<registry>[a-z0-9._-]+(?::[0-9]+)?)/)?(?P<repository>[a-z0-9._/-]+?)"
    r"(?::(?P<tag>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})|@(?P<digest>sha256:[0-9a-f]{64}))$"
)
# Agent IDE published templates (G6): sbt-<slug>-<hex>
_TEMPLATE_UID_RE = re.compile(r"^sbt-[a-z0-9][a-z0-9-]{0,48}$")


class SandboxContractError(ValueError):
    """A request violated the Cathedral sandbox contract, with a stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise SandboxContractError(code, message)


# ---------------------------------------------------------------- §3.1 sources
@dataclass(frozen=True)
class ImageSource:
    """An OCI image reference.  Accepts a mutable ``:tag`` or a pinned
    ``@sha256`` digest, optionally with private-registry credentials.

    The resolved digest (when only a tag is given) is filled in later by the
    registry mirror; admission records the request, not the pull.
    """

    image: str
    registry_auth: Mapping[str, str] | None = None
    resolved_digest: str | None = None

    def __post_init__(self) -> None:
        if _TEMPLATE_UID_RE.fullmatch(self.image):
            # Agent IDE template UID — resolved by the provider to a concrete image.
            return
        match = _IMAGE_REF_RE.match(self.image)
        _require(match is not None, "invalid_image_reference", f"image reference is invalid: {self.image!r}")
        assert match is not None
        if match.group("registry") is not None:
            _require("://" not in self.image, "invalid_image_reference", "image reference must not carry a scheme")
        _require(
            self.resolved_digest is None or re.fullmatch(r"sha256:[0-9a-f]{64}", self.resolved_digest) is not None,
            "invalid_digest",
            "resolved_digest must be a canonical sha256 digest",
        )
        if self.registry_auth is not None:
            _require(
                isinstance(self.registry_auth, Mapping)
                and set(self.registry_auth) == {"username", "password"}
                and all(isinstance(v, str) and v for v in self.registry_auth.values()),
                "invalid_registry_auth",
                "registry_auth needs non-empty username and password",
            )

    @property
    def tag(self) -> str | None:
        match = _IMAGE_REF_RE.match(self.image)
        return match.group("tag") if match and match.group("tag") else None

    @property
    def digest(self) -> str | None:
        match = _IMAGE_REF_RE.match(self.image)
        return match.group("digest") if match and match.group("digest") else self.resolved_digest

    def to_document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "image": self.image,
                **({"resolved_digest": self.resolved_digest} if self.resolved_digest else {}),
                **({"registry_auth": True} if self.registry_auth else {}),
            }
        )


@dataclass(frozen=True)
class BuildSpec:
    """Create from a Dockerfile plus build context, cached by content hash (§3.1b)."""

    dockerfile: str
    context_tar_url: str | None = None
    context_multipart: bool = False

    def __post_init__(self) -> None:
        _require(bool(self.dockerfile.strip()), "invalid_build", "dockerfile must not be empty")
        _require(
            (self.context_tar_url is not None) or self.context_multipart,
            "invalid_build",
            "a build needs context_tar_url or a multipart context",
        )

    @property
    def content_hash(self) -> str:
        """Stable build key: identical dockerfile+context is a cache no-op (§3.9)."""
        digest = hashlib.sha256()
        digest.update(self.dockerfile.encode("utf-8"))
        digest.update(b"\0")
        digest.update((self.context_tar_url or "multipart").encode("utf-8"))
        return "sha256:" + digest.hexdigest()

    def to_document(self) -> Mapping[str, object]:
        return MappingProxyType({"content_hash": self.content_hash, "dockerfile_bytes": len(self.dockerfile)})


# ---------------------------------------------------------------- §3.6 / §3.7 fields
@dataclass(frozen=True)
class Resources:
    """Numeric per-sandbox resources; Cathedral bills the request, not a fixed class."""

    vcpu: int = 1
    memory_gib: int = 4
    disk_gib: int = 10
    gpu: int | None = None

    def __post_init__(self) -> None:
        for name, value, lo, hi in (
            ("vcpu", self.vcpu, VCPU_MIN, VCPU_MAX),
            ("memory_gib", self.memory_gib, MEMORY_GIB_MIN, MEMORY_GIB_MAX),
            ("disk_gib", self.disk_gib, DISK_GIB_MIN, DISK_GIB_MAX),
        ):
            _require(
                isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi,
                "invalid_resources",
                f"{name} must be an integer between {lo} and {hi}",
            )
        if self.gpu is not None:
            _require(
                isinstance(self.gpu, int) and not isinstance(self.gpu, bool) and self.gpu >= 0,
                "invalid_resources",
                "gpu must be a non-negative integer",
            )


NETWORK_MODES = frozenset({"public", "none", "allowlist"})


@dataclass(frozen=True)
class NetworkSpec:
    """Egress policy at create and, for allowlist, the reachable set (§3.7)."""

    mode: str = "public"
    allow: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require(self.mode in NETWORK_MODES, "invalid_network_mode", "mode must be public, none, or allowlist")
        _require(len(self.allow) <= 256, "invalid_network_allowlist", "allowlist must be bounded to 256 entries")
        for entry in self.allow:
            _require(
                isinstance(entry, str) and 1 <= len(entry) <= 255,
                "invalid_network_allowlist",
                "allowlist entries must be non-empty strings",
            )
        if self.mode == "allowlist":
            _require(bool(self.allow), "invalid_network_allowlist", "allowlist mode requires at least one entry")


# ---------------------------------------------------------------- §3.1 / §3.4 / §3.5 create
def _validated_labels(labels: Mapping[str, str]) -> Mapping[str, str]:
    for key, value in labels.items():
        _require(
            isinstance(key, str) and _LABEL_KEY_RE.fullmatch(key) is not None,
            "invalid_label",
            f"label key is invalid: {key!r}",
        )
        _require(
            isinstance(value, str) and (value == "" or _LABEL_VALUE_RE.fullmatch(value) is not None),
            "invalid_label",
            f"label value is invalid: {value!r}",
        )
    return dict(labels)


@dataclass(frozen=True)
class CreateSandboxRequest:
    """One endpoint, three sources (§3.1): image, build, or snapshot.

    Exactly one source is set.  ``snapshot_id`` plus ``count`` is the fork path
    (§3.5); ``count`` is 1 for a single create.  ``ttl_seconds`` drives the
    lifecycle/GC contract (§3.4).
    """

    resources: Resources = field(default_factory=Resources)
    network: NetworkSpec = field(default_factory=NetworkSpec)
    env: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)
    ttl_seconds: int = TTL_DEFAULT_SECONDS
    entrypoint: tuple[str, ...] = ("sleep", "infinity")
    user: str | None = None
    workdir: str | None = None
    image: ImageSource | None = None
    build: BuildSpec | None = None
    snapshot_id: str | None = None
    count: int = 1
    # §3.10/§3.11: the verifier runtime drives idle reclamation and create pacing.
    idle_timeout_seconds: int | None = None

    def __post_init__(self) -> None:
        sources = [self.image is not None, self.build is not None, self.snapshot_id is not None]
        _require(sum(sources) == 1, "invalid_source", "exactly one of image, build, or snapshot_id is required")
        if self.snapshot_id is not None:
            _require(bool(self.snapshot_id.strip()), "invalid_snapshot_id", "snapshot_id must not be blank")
        _require(1 <= self.count <= FORK_MAX_COUNT, "invalid_count", f"count must be between 1 and {FORK_MAX_COUNT}")
        _require(
            isinstance(self.ttl_seconds, int)
            and not isinstance(self.ttl_seconds, bool)
            and 1 <= self.ttl_seconds <= TTL_MAX_SECONDS,
            "invalid_ttl",
            f"ttl_seconds must be between 1 and {TTL_MAX_SECONDS}",
        )
        if self.idle_timeout_seconds is not None:
            _require(
                isinstance(self.idle_timeout_seconds, int)
                and not isinstance(self.idle_timeout_seconds, bool)
                and 1 <= self.idle_timeout_seconds <= TTL_MAX_SECONDS,
                "invalid_idle_timeout",
                f"idle_timeout_seconds must be between 1 and {TTL_MAX_SECONDS}",
            )
        _require(
            isinstance(self.env, Mapping)
            and all(isinstance(k, str) and isinstance(v, str) for k, v in self.env.items()),
            "invalid_env",
            "env must map string keys to string values",
        )
        object.__setattr__(self, "labels", _validated_labels(self.labels))
        if self.entrypoint == () or not all(isinstance(part, str) for part in self.entrypoint):
            raise SandboxContractError("invalid_entrypoint", "entrypoint must be a non-empty argv list")

    @property
    def is_fork(self) -> bool:
        return self.snapshot_id is not None and self.count > 1

    @property
    def total_vcpu(self) -> int:
        return self.resources.vcpu * self.count

    @property
    def total_memory_gib(self) -> int:
        return self.resources.memory_gib * self.count

    def to_document(self) -> Mapping[str, object]:
        source: Mapping[str, object]
        if self.image is not None:
            source = {"image": self.image.to_document()}
        elif self.build is not None:
            source = {"build": self.build.to_document()}
        else:
            source = {"snapshot_id": self.snapshot_id, "count": self.count}
        return MappingProxyType(
            {
                **source,
                "resources": {
                    "vcpu": self.resources.vcpu,
                    "memory_gib": self.resources.memory_gib,
                    "disk_gib": self.resources.disk_gib,
                    **({"gpu": self.resources.gpu} if self.resources.gpu is not None else {}),
                },
                "network": {"mode": self.network.mode, "allow": list(self.network.allow)},
                "ttl_seconds": self.ttl_seconds,
                "idle_timeout_seconds": self.idle_timeout_seconds,
                "labels": dict(self.labels),
                "env_keys": sorted(self.env),  # §3.17: names only, never secret values
                "entrypoint": list(self.entrypoint),
            }
        )


# ---------------------------------------------------------------- §3.5 snapshot / fork
@dataclass(frozen=True)
class SnapshotRecord:
    """A saved filesystem image that new sandboxes can fork from (§3.5).

    §3.5/§3.17: a snapshot is addressable by an optional human ``name`` (Harbor forks
    with ``CreateSandboxFromSnapshotParams(snapshot=name)``) and carries ``labels`` so
    it participates in the "every object has labels, every list filters by label" rule.
    """

    snapshot_id: str
    size_bytes: int
    ttl_seconds: int = SNAPSHOT_TTL_DEFAULT_SECONDS
    created_at: datetime | None = None
    name: str | None = None
    labels: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require(bool(self.snapshot_id.strip()), "invalid_snapshot_id", "snapshot_id must not be blank")
        _require(
            isinstance(self.size_bytes, int) and not isinstance(self.size_bytes, bool) and self.size_bytes >= 0,
            "invalid_snapshot",
            "size_bytes must be a non-negative integer",
        )
        _require(self.ttl_seconds >= 1, "invalid_snapshot", "snapshot ttl_seconds must be positive")


@dataclass(frozen=True)
class ForkPlan:
    """Validation that a snapshot can fan out to ``count`` siblings within SLO."""

    snapshot_id: str
    count: int

    def __post_init__(self) -> None:
        _require(bool(self.snapshot_id.strip()), "invalid_snapshot_id", "snapshot_id must not be blank")
        _require(1 <= self.count <= FORK_MAX_COUNT, "invalid_count", f"count must be between 1 and {FORK_MAX_COUNT}")


# ---------------------------------------------------------------- §3.8 quota + 429
@dataclass(frozen=True)
class QuotaLimits:
    running_sandboxes: int
    vcpu: int
    memory_gib: int

    def __post_init__(self) -> None:
        for name, value in (
            ("running_sandboxes", self.running_sandboxes),
            ("vcpu", self.vcpu),
            ("memory_gib", self.memory_gib),
        ):
            _require(
                isinstance(value, int) and not isinstance(value, bool) and value >= 0,
                "invalid_quota",
                f"{name} must be a non-negative integer",
            )


@dataclass(frozen=True)
class QuotaUsage:
    running_sandboxes: int = 0
    vcpu: int = 0
    memory_gib: int = 0

    def within(self, limits: QuotaLimits) -> bool:
        return (
            self.running_sandboxes <= limits.running_sandboxes
            and self.vcpu <= limits.vcpu
            and self.memory_gib <= limits.memory_gib
        )


@dataclass(frozen=True)
class QuotaDecision:
    admitted: bool
    http_status: int
    retry_after_seconds: int | None
    reason: str | None = None

    @property
    def is_rate_limited(self) -> bool:
        return not self.admitted and self.http_status == 429


def evaluate_quota(
    request: CreateSandboxRequest,
    *,
    limits: QuotaLimits,
    usage: QuotaUsage,
    api_key: str | None = None,
    key_max_running: int | None = None,
    key_usage: QuotaUsage | None = None,
) -> QuotaDecision:
    """§3.8: a full quota is a synchronous 429 with Retry-After, never a start-timeout.

    Per-key caps prefer ``CATHEDRAL_KEY_QUOTAS``; when unset, ``key_max_running`` from
    the key store (``CATHEDRAL_SANDBOX_KEYS`` third field / ``ApiKey.max_running``) applies.
    Key subquota is measured against ``key_usage`` (resident sandboxes owned by the key),
    not the project-wide usage, so one tenant cannot exhaust another's subquota math.
    """
    projected = QuotaUsage(
        running_sandboxes=usage.running_sandboxes + request.count,
        vcpu=usage.vcpu + request.total_vcpu,
        memory_gib=usage.memory_gib + request.total_memory_gib,
    )
    if not projected.within(limits):
        return QuotaDecision(admitted=False, http_status=429, retry_after_seconds=1, reason="project_quota_exhausted")
    if api_key is not None:
        max_running = key_quota_for(api_key)
        if max_running is None:
            max_running = key_max_running
        owned = key_usage if key_usage is not None else usage
        if max_running is not None and owned.running_sandboxes + request.count > max_running:
            return QuotaDecision(admitted=False, http_status=429, retry_after_seconds=1, reason="key_subquota_exhausted")
    return QuotaDecision(admitted=True, http_status=202, retry_after_seconds=None)


# ---------------------------------------------------------------- §3.4 lifecycle / TTL / GC
def is_collectable(now: datetime, *, deadline_at: datetime, last_heartbeat_at: datetime | None) -> bool:
    """§3.4: past TTL, or a job that stopped heartbeating, is collected within the grace window."""
    if now >= deadline_at:
        return True
    if last_heartbeat_at is not None:
        # A dead driver stops heartbeating; its sandboxes are collected at TTL even
        # if the deadline was pushed forward by earlier heartbeats.
        return now - last_heartbeat_at > timedelta(seconds=TTL_MAX_SECONDS)
    return False


def gc_deadline(expires_at: datetime) -> datetime:
    """The sandbox must be gone by ``expires_at`` plus the ≤ 5 min GC grace."""
    return expires_at + timedelta(seconds=GC_GRACE_SECONDS)


# ---------------------------------------------------------------- §3.12 idempotency / operations
def validate_idempotency_key(key: str) -> str:
    _require(
        isinstance(key, str) and _IDEMPOTENCY_KEY_RE.fullmatch(key) is not None,
        "invalid_idempotency_key",
        "Idempotency-Key must be 8-128 of A-Za-z0-9._:-",
    )
    return key


def operation_id() -> str:
    return "op_" + hashlib.sha256(os.urandom(16)).hexdigest()[:16]


def idempotency_digest(prefix: str, *parts: Sequence[object] | object) -> str:
    """A stable Idempotency-Key derived from request content (same body -> same key)."""
    import json

    digest = hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode("utf-8"))
    return validate_idempotency_key(f"{prefix}-{digest.hexdigest()[:40]}")


# ---------------------------------------------------------------- §3.2 exec / processes
EXEC_MAX_TIMEOUT_SECONDS = 3600
# §3.2: output must be streamed or capped at a stated size >= 10 MiB with a truncated flag.
STDOUT_MIN_CAP_BYTES = 10 * 1024 * 1024
STDOUT_CAP_BYTES = 16 * 1024 * 1024
PROCESS_LOG_RETENTION_HOURS = 24


def _validated_env(env: Mapping[str, object]) -> dict[str, str]:
    _require(
        isinstance(env, Mapping) and all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()),
        "invalid_env",
        "env must map string keys to string values",
    )
    return dict(env)


def _validated_abs_path(path: str, code: str = "invalid_path") -> str:
    _require(
        isinstance(path, str) and path.startswith("/") and ".." not in path.split("/"),
        code,
        f"path must be absolute and free of '..' traversal: {path!r}",
    )
    return path


@dataclass(frozen=True)
class ExecRequest:
    """§3.2: one endpoint accepts a shell string OR an argv list.

    ``timeout_seconds`` is enforced by the provider, not by wrapping ``timeout`` in
    the shell; on expiry the process group is killed, ``timed_out`` is true and the
    sandbox stays alive.  ``cmd`` is normalised so callers never branch on the form.
    """

    cmd: str | Sequence[str]
    cwd: str | None = None
    env: Mapping[str, str] = field(default_factory=dict)
    user: str | None = None
    timeout_seconds: int | None = None
    stdin: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.cmd, str):
            _require(bool(self.cmd.strip()), "invalid_exec", "shell cmd must not be empty")
        else:
            _require(
                isinstance(self.cmd, Sequence)
                and len(self.cmd) > 0
                and all(isinstance(part, str) and part for part in self.cmd),
                "invalid_exec",
                "argv form must be a non-empty list of non-empty strings",
            )
        if self.cwd is not None:
            _validated_abs_path(self.cwd, "invalid_cwd")
        _validated_env(self.env)
        if self.timeout_seconds is not None:
            _require(
                isinstance(self.timeout_seconds, int)
                and not isinstance(self.timeout_seconds, bool)
                and 1 <= self.timeout_seconds <= EXEC_MAX_TIMEOUT_SECONDS,
                "invalid_timeout",
                f"timeout_seconds must be between 1 and {EXEC_MAX_TIMEOUT_SECONDS}",
            )

    @property
    def is_shell(self) -> bool:
        return isinstance(self.cmd, str)

    @property
    def argv(self) -> tuple[str, ...]:
        """The concrete argv to run: ``bash -c`` for a shell string, else as given."""
        return ("bash", "-c", self.cmd) if isinstance(self.cmd, str) else tuple(self.cmd)


@dataclass(frozen=True)
class ExecResult:
    """§3.2 exec response. ``truncated`` is set when output exceeded the stated cap."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool
    truncated: bool = False

    def to_document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "exit_code": self.exit_code,
                "stdout": self.stdout,
                "stderr": self.stderr,
                "duration_ms": self.duration_ms,
                "timed_out": self.timed_out,
                "truncated": self.truncated,
            }
        )


@dataclass(frozen=True)
class ProcessHandle:
    """§3.2 background process. It must outlive the exec call that started it."""

    process_id: str
    argv: tuple[str, ...]
    running: bool = True


@dataclass(frozen=True)
class ExecRecord:
    """§3.13 one entry in a sandbox's exec history (command, exit code, duration)."""

    command: str
    exit_code: int
    duration_ms: int
    at: datetime

    def to_document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "command": self.command,
                "exit_code": self.exit_code,
                "duration_ms": self.duration_ms,
                "at": self.at.isoformat(),
            }
        )


# ---------------------------------------------------------------- §3.3 files / tar / stat
@dataclass(frozen=True)
class FilePut:
    """§3.3 PUT file: body is bytes, parent dirs are created, optional mode."""

    path: str
    mode: int | None = None

    def __post_init__(self) -> None:
        _validated_abs_path(self.path)
        if self.mode is not None:
            _require(0 <= self.mode <= 0o7777, "invalid_mode", "mode must be an octal permission")


@dataclass(frozen=True)
class FileGet:
    """§3.3 GET file. ``max_bytes`` past the cap is a 413; Range is a closed interval."""

    path: str
    max_bytes: int | None = None
    range_start: int | None = None
    range_end: int | None = None

    def __post_init__(self) -> None:
        _validated_abs_path(self.path)
        if self.max_bytes is not None:
            _require(
                isinstance(self.max_bytes, int) and not isinstance(self.max_bytes, bool) and self.max_bytes >= 0,
                "invalid_max_bytes",
                "max_bytes must be a non-negative integer",
            )
        if self.range_start is not None:
            _require(self.range_start >= 0, "invalid_range", "range start must be non-negative")
            if self.range_end is not None:
                _require(self.range_end >= self.range_start, "invalid_range", "range end must be >= start")


@dataclass(frozen=True)
class TarPut:
    """§3.3 upload a .tar.gz extracted in place, preserving modes and symlinks."""

    path: str

    def __post_init__(self) -> None:
        _validated_abs_path(self.path)


@dataclass(frozen=True)
class TarGet:
    """§3.3 pack and stream a directory, optionally excluding/including members.

    ``include`` (when non-empty) restricts the packed set to those top-level names --
    the server side of Harbor's ``download_dir_filtered(include=, exclude=, protect=)``.
    ``exclude`` always wins over ``include``.
    """

    path: str
    exclude: tuple[str, ...] = ()
    include: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validated_abs_path(self.path)


@dataclass(frozen=True)
class StatResult:
    is_dir: bool
    is_file: bool
    size: int
    mode: int

    def to_document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {"is_dir": self.is_dir, "is_file": self.is_file, "size": self.size, "mode": self.mode}
        )


# ---------------------------------------------------------------- §3.7 network patch / expose
@dataclass(frozen=True)
class NetworkPatch:
    """§3.7 runtime network-policy change (dynamic_network_policy between phases)."""

    mode: str
    allow: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require(self.mode in NETWORK_MODES, "invalid_network_mode", "mode must be public, none, or allowlist")
        _require(len(self.allow) <= 256, "invalid_network_allowlist", "allowlist must be bounded to 256 entries")
        if self.mode == "allowlist":
            _require(bool(self.allow), "invalid_network_allowlist", "allowlist mode requires at least one entry")


PORT_MIN, PORT_MAX = 1, 65535


@dataclass(frozen=True)
class ExposeRequest:
    port: int

    def __post_init__(self) -> None:
        _require(
            isinstance(self.port, int) and not isinstance(self.port, bool) and PORT_MIN <= self.port <= PORT_MAX,
            "invalid_port",
            f"port must be between {PORT_MIN} and {PORT_MAX}",
        )


@dataclass(frozen=True)
class ExposeResult:
    port: int
    url: str

    def to_document(self) -> Mapping[str, object]:
        return MappingProxyType({"port": self.port, "url": self.url})


# ---------------------------------------------------------------- §3.9 images
@dataclass(frozen=True)
class PrefetchRequest:
    """§3.9 warm a list of image references before a job (bounded; dedup preserved)."""

    images: tuple[str, ...]

    def __post_init__(self) -> None:
        _require(len(self.images) <= 1000, "invalid_prefetch", "prefetch list is bounded to 1000 images")
        for ref in self.images:
            _require(_IMAGE_REF_RE.match(ref) is not None, "invalid_image_reference", f"image ref is invalid: {ref!r}")


@dataclass(frozen=True)
class ImageStatus:
    ref: str
    cached: bool
    size_bytes: int
    digest: str | None = None

    def to_document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {"ref": self.ref, "cached": self.cached, "size_bytes": self.size_bytes, "digest": self.digest}
        )


# ---------------------------------------------------------------- §3.13 observability
@dataclass(frozen=True)
class Metrics:
    """§3.13 per-sandbox resource counters surfaced in GET /v1/sandboxes/{id}."""

    cpu_seconds: float = 0.0
    memory_peak_bytes: int = 0
    disk_bytes: int = 0
    network_bytes: int = 0
    started_at: datetime | None = None
    deleted_at: datetime | None = None

    def to_document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "cpu_seconds": self.cpu_seconds,
                "memory_peak_bytes": self.memory_peak_bytes,
                "disk_bytes": self.disk_bytes,
                "network_bytes": self.network_bytes,
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
            }
        )


@dataclass(frozen=True)
class StatusReport:
    """§3.13 create latency + error rate surfaced at GET /v1/status.

    §3.18 requires the operator to *state which* region (US or EU) the fleet runs in,
    so a declared ``region`` is carried here when the operator configures one
    (``CATHEDRAL_SANDBOX_REGION``).  It is ``None`` when undeclared -- we surface the
    region the operator actually set rather than asserting one we cannot honour.

    The customer checklist also needs an honest statement of the *runtime*:
    whether creates are kernel-isolated (Kata) and whether DinD is available.
    Those fields default to the reference-provider truth (memory, no isolation).
    """

    status: str
    create_latency_p50_ms: int
    error_rate: float
    region: str | None = None
    runtime: str = "memory"
    kernel_isolation: bool = False
    dind: bool = False
    disk_enforced: bool = False

    def to_document(self) -> Mapping[str, object]:
        return MappingProxyType(
            {
                "status": self.status,
                "create_latency_p50_ms": self.create_latency_p50_ms,
                "error_rate": self.error_rate,
                "region": self.region,
                "runtime": self.runtime,
                "kernel_isolation": self.kernel_isolation,
                "dind": self.dind,
                "disk_enforced": self.disk_enforced,
                # Honest: allowlist mode maps to network=none until an egress proxy exists.
                "network_allowlist_enforced": False,
            }
        )


# ---------------------------------------------------------------- §3.14 auth
@dataclass(frozen=True)
class ApiKey:
    """§3.4/§3.14: a project key with an individual max_running; revocation blocks new
    calls but deletes nothing."""

    key: str
    project: str
    max_running: int | None = None
    revoked: bool = False

    def __post_init__(self) -> None:
        _require(bool(self.key.strip()), "invalid_key", "api key must not be blank")
        _require(bool(self.project.strip()), "invalid_project", "project must not be blank")
        if self.max_running is not None:
            _require(
                isinstance(self.max_running, int) and not isinstance(self.max_running, bool) and self.max_running >= 0,
                "invalid_key_quota",
                "max_running must be a non-negative integer",
            )


# ---------------------------------------------------------------- §3.16 pricing
# Reference points from the requirements: Daytona ~= $0.116 per hour for a
# 1 vCPU / 4 GiB / 10 GiB sandbox; Modal quotes ~= 40% below that; our target is at or
# below Modal.  These are illustrative list rates for the metering model, not a
# commercial contract — the hosted runtime is what invoices.
DAYTONA_REFERENCE_USD_PER_HOUR = 0.116
MODAL_TARGET_DISCOUNT = 0.40
# Cathedral default rates chosen so 1 vCPU + 4 GiB lands at Modal's ~= 60% of Daytona:
#   1 * RATE_VCPU_HOUR + 4 * RATE_GIB_HOUR  ==  DAYTONA_REFERENCE * (1 - MODAL_TARGET_DISCOUNT)
RATE_VCPU_HOUR = 0.0100
RATE_GIB_HOUR = 0.0149
RATE_SNAPSHOT_GIB_MONTH = 0.08  # per GiB held for a 30-day month
DISK_INCLUDED_GIB = 10.0  # §3.16: disk over the included amount is billed
HOURS_PER_MONTH = 24 * 30


@dataclass(frozen=True)
class Pricing:
    """§3.16 rate card: per vCPU-hour, per GiB-hour, snapshot GiB-month.

    Metered by the second from running to deleted, no per-sandbox minimum, no idle
    charge for stopped sandboxes, no charge for image pulls.
    """

    vcpu_hour_usd: float = RATE_VCPU_HOUR
    gib_hour_usd: float = RATE_GIB_HOUR
    snapshot_gib_month_usd: float = RATE_SNAPSHOT_GIB_MONTH

    def __post_init__(self) -> None:
        for name in ("vcpu_hour_usd", "gib_hour_usd", "snapshot_gib_month_usd"):
            value = getattr(self, name)
            _require(
                isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0,
                "invalid_pricing",
                f"{name} must be a non-negative number",
            )

    def cost_usd(
        self,
        *,
        vcpu_hours: float = 0.0,
        gib_hours: float = 0.0,
        snapshot_gib_months: float = 0.0,
    ) -> float:
        total = (
            vcpu_hours * self.vcpu_hour_usd
            + gib_hours * self.gib_hour_usd
            + snapshot_gib_months * self.snapshot_gib_month_usd
        )
        return round(total, 6)

    def reference_comparisons(self) -> Mapping[str, object]:
        """Show the Cathedral 1 vCPU / 4 GiB hourly rate against the Daytona/Modal refs."""
        cathedral = self.cost_usd(vcpu_hours=1.0, gib_hours=4.0)
        modal = DAYTONA_REFERENCE_USD_PER_HOUR * (1 - MODAL_TARGET_DISCOUNT)
        return MappingProxyType(
            {
                "cathedral_usd_per_hour": round(cathedral, 6),
                "daytona_reference_usd_per_hour": DAYTONA_REFERENCE_USD_PER_HOUR,
                "modal_reference_usd_per_hour": round(modal, 6),
                "at_or_below_modal": cathedral <= modal + 1e-9,
            }
        )


def snapshot_gib_months(size_bytes: int, retention_seconds: float) -> float:
    """§3.16: a snapshot is billed per GiB held per (30-day) month."""
    gib = max(size_bytes, 0) / (1024 ** 3)
    months = max(retention_seconds, 0.0) / (HOURS_PER_MONTH * 3600)
    return gib * months


# ---------------------------------------------------------------- §3.18 data handling
# §3.13/§3.18: logs (container stdout/stderr + exec history) are retained 24 h after
# the sandbox is deleted, then dropped.  PROCESS_LOG_RETENTION_HOURS is the window.


def parse_byte_range(header: str | None, length: int) -> tuple[int, int] | None:
    """Parse an HTTP ``Range: bytes=a-b`` header into a closed interval for ``length``.

    Returns ``None`` when the header is absent or malformed-but-tolerable (a missing
    end means "to EOF").  Raises ``SandboxContractError`` on an unsatisfiable range.
    """
    if not header:
        return None
    match = re.fullmatch(r"bytes=(\d+)-(\d*)", header.strip())
    _require(match is not None, "invalid_range", f"unsupported Range header: {header!r}")
    assert match is not None
    start = int(match.group(1))
    end = int(match.group(2)) if match.group(2) else length - 1
    if start > end or start >= max(length, 1):
        raise SandboxContractError("range_not_satisfiable", f"range {header!r} is not satisfiable for {length} bytes")
    return start, min(end, length - 1)


__all__ = [
    "ApiKey",
    "BuildSpec",
    "CATHEDRAL_API_URL",
    "CATHEDRAL_REGISTRY",
    "CreateSandboxRequest",
    "DAYTONA_REFERENCE_USD_PER_HOUR",
    "DISK_INCLUDED_GIB",
    "ExecRecord",
    "ExecRequest",
    "ExecResult",
    "ExposeRequest",
    "ExposeResult",
    "FORK_MAX_COUNT",
    "FORK_SLO_SECONDS",
    "MIN_SNAPSHOTS",
    "SNAPSHOT_TTL_DEFAULT_SECONDS",
    "ForkPlan",
    "FileGet",
    "FilePut",
    "HOURS_PER_MONTH",
    "ImageSource",
    "ImageStatus",
    "Metrics",
    "MODAL_TARGET_DISCOUNT",
    "NETWORK_MODES",
    "NetworkPatch",
    "NetworkSpec",
    "PORT_MAX",
    "PORT_MIN",
    "PrefetchRequest",
    "Pricing",
    "ProcessHandle",
    "QuotaDecision",
    "QuotaLimits",
    "QuotaUsage",
    "RATE_GIB_HOUR",
    "RATE_SNAPSHOT_GIB_MONTH",
    "RATE_VCPU_HOUR",
    "Resources",
    "SANDBOX_API_BASE",
    "STDOUT_MIN_CAP_BYTES",
    "SnapshotRecord",
    "SandboxContractError",
    "StatResult",
    "StatusReport",
    "TarGet",
    "TarPut",
    "evaluate_quota",
    "gc_deadline",
    "idempotency_digest",
    "is_collectable",
    "key_quota_for",
    "operation_id",
    "parse_byte_range",
    "snapshot_gib_months",
    "validate_idempotency_key",
]
