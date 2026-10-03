"""Cathedral compute sandbox reference provider.

This turns the request contracts in :mod:`cathedral.sandbox_api` into a *runnable*
control-plane implementation so the sandbox API (§§3.1-3.14 of the requirements) is
actually dispatchable and testable, not just a validated grammar.

It is a reference provider, not the confidential-compute runtime: sandboxes execute
real commands via ``subprocess`` inside a private per-sandbox filesystem root (the
hosted ``cathedral.computer`` runtime is what provides kernel isolation and DinD
attestation, and that is closed source). The point here is to implement the *documented
semantics* — exec timeouts that kill the process group and keep the sandbox alive,
file/tar/stat transfer, filesystem snapshots and copy-on-write forks, TTL + heartbeat
+ auto-GC, quota accounting that yields a synchronous 429 + Retry-After, idempotency,
async operations, and label-grouped usage metering — so ``cathedral/sandbox_server.py``
has something real to route to.

Path model: the files/tar/stat APIs take sandbox-absolute paths and map them under the
sandbox root (``/work/x`` -> ``<root>/work/x``). ``exec`` runs with its working directory
at ``<root>/work`` but does not chroot (that needs the runtime's kernel isolation), so a
shell command should address its own files with paths relative to that cwd; passing an
absolute host path through a shell string is deliberately out of scope for this
reference and is not treated as an isolation boundary.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import uuid

try:  # resource is POSIX-only (Linux/macOS); metrics degrade to 0 elsewhere.
    import resource
except ImportError:  # pragma: no cover - non-POSIX platforms
    resource = None  # type: ignore[assignment]
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from cathedral import sandbox_api as api
from cathedral import agent_interactive as agent_ux
from cathedral.sandbox_api import (
    ApiKey,
    CreateSandboxRequest,
    ExecRecord,
    ExecRequest,
    ExecResult,
    ExposeRequest,
    FileGet,
    Metrics,
    NetworkPatch,
    PrefetchRequest,
    Pricing,
    ProcessHandle,
    QuotaLimits,
    QuotaUsage,
    SandboxContractError,
    SnapshotRecord,
    StatResult,
    StatusReport,
    TarGet,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class SandboxOpError(Exception):
    """A provider refusal with an HTTP status the server can map directly."""

    def __init__(self, code: str, http_status: int, message: str, retry_after: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.retry_after = retry_after


@dataclass
class _Sandbox:
    id: str
    root: Path
    state: str
    created_at: datetime
    expires_at: datetime
    ttl_seconds: int
    resources: api.Resources
    network_mode: str
    network_allow: tuple[str, ...]
    labels: dict[str, str]
    env: dict[str, str]
    api_key: str | None
    image_id: str | None = None
    snapshot_id: str | None = None
    deleted_at: datetime | None = None
    started_at: datetime | None = None
    cpu_seconds: float = 0.0
    network_bytes: int = 0
    memory_peak_bytes: int = 0
    # §3.10/§3.11: idle reclamation for the verifier runtime (0/None => TTL only).
    idle_timeout_seconds: int | None = None
    last_activity_at: datetime | None = None
    processes: dict[str, tuple[subprocess.Popen, Path]] = field(default_factory=dict)
    exec_history: list[ExecRecord] = field(default_factory=list)
    container_stdout: bytearray = field(default_factory=bytearray)
    container_stderr: bytearray = field(default_factory=bytearray)
    exposed: dict[int, str] = field(default_factory=dict)


class SandboxProvider(Protocol):
    """The dispatch surface :mod:`cathedral.sandbox_server` calls into."""

    def authorize(self, api_key: str | None) -> None: ...
    def create(self, request: CreateSandboxRequest, *, api_key: str | None, idempotency: str | None, body_digest: str) -> dict[str, Any]: ...
    def get(self, sandbox_id: str) -> dict[str, Any]: ...
    def wait(self, sandbox_id: str, timeout_seconds: int) -> dict[str, Any]: ...
    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult: ...
    def write_file(self, sandbox_id: str, path: str, data: bytes, mode: int | None) -> None: ...
    def read_file(self, sandbox_id: str, spec: FileGet) -> tuple[bytes, int]: ...
    def write_tar(self, sandbox_id: str, path: str, tarball: bytes) -> None: ...
    def read_tar(self, sandbox_id: str, spec: TarGet) -> bytes: ...
    def stat(self, sandbox_id: str, path: str) -> StatResult: ...
    def start_process(self, sandbox_id: str, request: ExecRequest) -> ProcessHandle: ...
    def process_logs(self, sandbox_id: str, process_id: str) -> str: ...
    def stop_process(self, sandbox_id: str, process_id: str) -> None: ...
    def snapshot(self, sandbox_id: str, *, ttl_seconds: int | None = None, name: str | None = None, labels: dict[str, str] | None = None) -> str: ...
    def list_snapshots(self, labels: Iterable[str] = ()) -> list[dict[str, Any]]: ...
    def delete_snapshot(self, snapshot_id: str) -> bool: ...
    def heartbeat(self, sandbox_id: str, ttl_seconds: int | None) -> dict[str, Any]: ...
    def delete(self, sandbox_id: str) -> None: ...
    def list(self, *, labels: Iterable[str], state: str | None) -> list[dict[str, Any]]: ...
    def bulk_delete(self, labels: Iterable[str]) -> int: ...
    def set_network(self, sandbox_id: str, patch: NetworkPatch) -> dict[str, Any]: ...
    def expose(self, sandbox_id: str, request: ExposeRequest) -> dict[str, Any]: ...
    def prefetch(self, request: PrefetchRequest) -> str: ...
    def image_status(self, ref: str) -> dict[str, Any]: ...
    def quota(self) -> dict[str, Any]: ...
    def usage(self, *, group_by: str | None, labels: Iterable[str]) -> dict[str, Any]: ...
    def status(self) -> dict[str, Any]: ...
    def logs(self, sandbox_id: str) -> dict[str, Any]: ...
    def get_operation(self, operation_id: str) -> dict[str, Any]: ...
    def sweep(self) -> int: ...
    def freeze(self, sandbox_id: str) -> dict[str, Any]: ...
    def thaw(self, sandbox_id: str) -> dict[str, Any]: ...
    def mint_access_ticket(self, sandbox_id: str, *, ttl_sec: int | None = None) -> dict[str, Any]: ...
    def consume_access_ticket(self, sandbox_id: str, ticket: str) -> None: ...
    def create_terminal(
        self, sandbox_id: str, *, cols: int | None = None, rows: int | None = None
    ) -> dict[str, Any]: ...
    def list_terminals(self, sandbox_id: str) -> list[dict[str, Any]]: ...
    def delete_terminal(self, sandbox_id: str, terminal_id: str) -> None: ...
    def connect_terminal(self, sandbox_id: str, terminal_id: str, *, ticket: str) -> dict[str, Any]: ...
    def terminal_write(self, sandbox_id: str, terminal_id: str, data: str) -> dict[str, Any]: ...
    def terminal_read(self, sandbox_id: str, terminal_id: str) -> dict[str, Any]: ...
    def publish_template(
        self,
        sandbox_id: str,
        *,
        name: str,
        display_name: str | None = None,
        description: str = "",
    ) -> dict[str, Any]: ...
    def list_templates(self, *, kind: str | None = None, status: str | None = None) -> list[dict[str, Any]]: ...
    def get_template(self, template_uid: str) -> dict[str, Any]: ...
    def desktop(self, sandbox_id: str) -> dict[str, Any]: ...


class InMemorySandboxProvider:
    """A thread-safe, filesystem-backed reference implementation of the contract."""

    def __init__(
        self,
        *,
        limits: QuotaLimits | None = None,
        keys: Iterable[ApiKey] = (),
        base_url: str | None = None,
        pricing: Pricing | None = None,
        require_known_keys: bool = False,
        max_snapshots: int = api.MIN_SNAPSHOTS,
        creates_per_minute: int = api.MIN_CREATES_PER_MINUTE,
        region: str | None = None,
        enforce_disk: bool = False,
        runtime_label: str = "memory",
    ) -> None:
        self._lock = threading.RLock()
        self._base = Path(tempfile.mkdtemp(prefix="cathedral-sandbox-"))
        self._sandboxes: dict[str, _Sandbox] = {}
        self._snapshots: dict[str, tuple[Path, SnapshotRecord]] = {}  # id -> (tar path, record)
        self._operations: dict[str, dict[str, Any]] = {}
        self._images: dict[str, dict[str, Any]] = {}
        self._idempotency: dict[str, tuple[str, Any]] = {}
        # §3.13/§3.18: logs kept 24 h after delete (stdout, stderr, exec history).
        self._log_tombstones: dict[str, dict[str, Any]] = {}
        self._limits = limits or QuotaLimits(
            running_sandboxes=api.MIN_RUNNING_SANDBOXES, vcpu=api.MIN_VCPU, memory_gib=api.MIN_MEMORY_GIB
        )
        self._keys: dict[str, ApiKey] = {k.key: k for k in keys}
        self._require_known_keys = require_known_keys
        # §3.5: the store guarantees at least MIN_SNAPSHOTS (1,000) retained images.
        self._max_snapshots = max_snapshots
        self._base_url = (base_url or api.CATHEDRAL_API_URL).rstrip("/")
        self._pricing = pricing or Pricing()
        # §3.10/§3.11 create pacing: trailing 60-second window of created sandboxes.
        self._creates_per_minute = creates_per_minute
        self._create_times: list[datetime] = []
        self._create_latencies_ms: list[float] = []
        self._create_errors = 0
        self._closed = False
        # §3.18: the operator-declared data region (US or EU), surfaced at GET /v1/status.
        # Read live from CATHEDRAL_SANDBOX_REGION so a keyed boot can declare it; None
        # when undeclared -- we never assert a region the operator has not configured.
        self._region = region if region is not None else (os.environ.get("CATHEDRAL_SANDBOX_REGION") or None)
        # Customer checklist §3.6: when enabled, file/tar writes that would exceed resources.disk_gib fail.
        self._enforce_disk = enforce_disk
        self._runtime_label = runtime_label
        # Agent IDE interactive (G4–G6): tickets, terminals, published templates.
        self._tickets: dict[str, agent_ux.AccessTicket] = {}
        self._terminals: dict[str, dict[str, agent_ux.TerminalSession]] = {}
        self._templates: dict[str, agent_ux.SandboxTemplate] = {}
        # Per-request tenant context (thread-local) — set by authorize().
        self._ctx = threading.local()
        # Per-key create pacing buckets (noisy-neighbor isolation).
        self._create_times_by_key: dict[str, list[datetime]] = {}

    # ------------------------------------------------------------------ helpers
    def _caller_key(self) -> str | None:
        return getattr(self._ctx, "api_key", None)

    def _host(self, sandbox: _Sandbox, path: str) -> Path:
        api._validated_abs_path(path)
        host = (sandbox.root / path.lstrip("/")).resolve()
        root = sandbox.root.resolve()
        try:
            host.relative_to(root)
        except ValueError as exc:
            raise SandboxOpError(
                "path_escape",
                400,
                f"path escapes sandbox root: {path}",
            ) from exc
        return host

    def _assert_owner(self, sandbox: _Sandbox) -> None:
        """BOLA guard: authenticated callers may only touch their own sandboxes."""
        caller = self._caller_key()
        if caller is None:
            return
        if sandbox.api_key is not None and sandbox.api_key != caller:
            raise SandboxOpError(
                "sandbox_not_found",
                404,
                f"no sandbox {sandbox.id}",
            )

    def _require_active(self, sandbox_id: str) -> _Sandbox:
        sandbox = self._sandboxes.get(sandbox_id)
        if sandbox is None or sandbox.state == "deleted":
            raise SandboxOpError("sandbox_not_found", 404, f"no sandbox {sandbox_id}")
        self._assert_owner(sandbox)
        return sandbox

    def _require_running(self, sandbox_id: str) -> _Sandbox:
        """Agent IDE: exec/mutate paths need running; frozen is 409."""
        sandbox = self._require_active(sandbox_id)
        if sandbox.state == "frozen":
            raise SandboxOpError(
                "sandbox_frozen",
                409,
                f"sandbox {sandbox_id} is frozen; thaw before this operation",
            )
        if sandbox.state not in ("running", "creating"):
            raise SandboxOpError(
                "sandbox_not_running",
                409,
                f"sandbox {sandbox_id} is {sandbox.state}",
            )
        return sandbox

    def authorize(self, api_key: str | None) -> None:
        """Public auth gate: validate a bearer key for any request (§3.14)."""
        self._auth(api_key)
        self._ctx.api_key = api_key

    def _auth(self, api_key: str | None) -> None:
        """§3.14: revoke blocks new calls but deletes nothing; unknown keys are rejected.

        In strict mode (a key store configured by the operator) a bearer token that
        is not a known, un-revoked project key is refused with 401.  The default
        permissive mode is the test/reference provider, where the caller supplies
        its own bearer and only explicitly-revoked keys are refused.
        """
        if api_key is None:
            raise SandboxOpError("unauthorized", 401, "missing API key")
        record = self._keys.get(api_key)
        if record is not None and record.revoked:
            raise SandboxOpError("key_revoked", 403, "API key is revoked")
        if self._require_known_keys and record is None:
            raise SandboxOpError("unauthorized", 401, "unknown API key")

    def _disk_bytes(self, sandbox: _Sandbox) -> int:
        total = 0
        for p in sandbox.root.rglob("*"):
            if p.is_file():
                total += p.stat().st_size
        return total

    def _assert_disk_room(
        self, sandbox: _Sandbox, *, extra_bytes: int, replacing: str | None
    ) -> None:
        """Customer checklist §3.6: refuse writes that would exceed the sandbox's disk_gib.

        Callers must already hold ``self._lock``.  When *replacing* is a path that
        already exists, its current size is subtracted so overwrites are fair.
        """
        if not self._enforce_disk:
            return
        used = self._disk_bytes(sandbox)
        if replacing is not None:
            existing = self._host(sandbox, replacing)
            if existing.is_file():
                used -= existing.stat().st_size
        limit = sandbox.resources.disk_gib * (1024**3)
        if used + max(extra_bytes, 0) > limit:
            raise SandboxOpError(
                "disk_quota_exceeded",
                413,
                f"write would exceed disk_gib={sandbox.resources.disk_gib} "
                f"({used + max(extra_bytes, 0)} > {limit} bytes)",
            )

    def _touch(self, sandbox: _Sandbox) -> None:
        """§3.10/§3.11: mark the sandbox active so its idle window restarts.

        Callers must already hold ``self._lock``.  Only meaningful when the sandbox
        opted into ``idle_timeout_seconds``; we stamp unconditionally for simplicity.
        """
        sandbox.last_activity_at = _now()

    # ------------------------------------------------------------------ §3.1 create / §3.5 fork
    def create(self, request: CreateSandboxRequest, *, api_key: str | None, idempotency: str | None, body_digest: str) -> dict[str, Any]:
        with self._lock:
            self._auth(api_key)
            self._ctx.api_key = api_key
            if idempotency is not None:
                api.validate_idempotency_key(idempotency)
                seen = self._idempotency.get(idempotency)
                if seen is not None:
                    if seen[0] != body_digest:
                        raise SandboxOpError("idempotency_conflict", 409, "Idempotency-Key reused with a different body")
                    return seen[1]

            started = time.perf_counter()
            try:
                docs = self._create_locked(request, api_key)
            except SandboxOpError:
                self._create_errors += 1
                raise
            finally:
                self._create_latencies_ms.append((time.perf_counter() - started) * 1000)
            if idempotency is not None:
                self._idempotency[idempotency] = (body_digest, docs)
            return docs

    def _create_locked(self, request: CreateSandboxRequest, api_key: str | None) -> dict[str, Any]:
        # §3.10/§3.11 pacing: at most ``creates_per_minute`` sandbox-creates in any
        # trailing 60-second window (a fork of N counts as N creates), per API key.
        now = _now()
        window_start = now - timedelta(seconds=60)
        rate_key = api_key or ""
        times = [t for t in self._create_times_by_key.get(rate_key, []) if t > window_start]
        if len(times) + request.count > self._creates_per_minute:
            raise SandboxOpError(
                "create_rate_exceeded",
                429,
                f"create pacing exceeded ({self._creates_per_minute}/min)",
                retry_after=1,
            )
        self._create_times_by_key[rate_key] = times
        # Keep legacy global list for status metrics (sum of buckets).
        self._create_times = [t for bucket in self._create_times_by_key.values() for t in bucket if t > window_start]
        key_record = self._keys.get(api_key) if api_key else None
        decision = api.evaluate_quota(
            request,
            limits=self._limits,
            usage=self._usage_now(),
            api_key=api_key,
            key_max_running=key_record.max_running if key_record is not None else None,
            key_usage=self._usage_now(api_key=api_key) if api_key else None,
        )
        if not decision.admitted:
            raise SandboxOpError(
                "quota_exhausted" if decision.reason != "key_subquota_exhausted" else "key_subquota_exhausted",
                429,
                "quota is full; retry later",
                retry_after=decision.retry_after_seconds or 1,
            )

        if request.snapshot_id is not None:
            snap = self._snapshots.get(request.snapshot_id)
            if snap is None:
                # §3.5: a fork may name the snapshot instead of its id
                # (Harbor CreateSandboxFromSnapshotParams(snapshot=name)).
                snap = next(((sid, r) for sid, (_, r) in self._snapshots.items() if r.name == request.snapshot_id), None)
                if snap is not None:
                    snap = self._snapshots[snap[0]]
            if snap is None:
                raise SandboxOpError("snapshot_not_found", 404, f"no snapshot {request.snapshot_id}")
        else:
            snap = None

        image_id = self._image_id_for(request)
        allow = os.environ.get("CATHEDRAL_SANDBOX_IMAGE_ALLOWLIST", "").strip()
        if allow and request.image is not None:
            allowed = {x.strip() for x in allow.split(",") if x.strip()}
            ref = request.image.image
            if ref not in allowed:
                raise SandboxOpError(
                    "image_not_allowed",
                    403,
                    f"image {ref!r} is not in CATHEDRAL_SANDBOX_IMAGE_ALLOWLIST",
                )
        created: list[_Sandbox] = []
        for _ in range(request.count):
            sandbox = self._materialize(request, now, api_key, image_id, snap)
            created.append(sandbox)
        self._create_times_by_key.setdefault(rate_key, []).extend(now for _ in created)
        self._create_times.extend(now for _ in created)
        if len(created) == 1:
            return self._get_doc(created[0])
        return {"sandboxes": [self._get_doc(s) for s in created], "count": len(created)}

    def _image_id_for(self, request: CreateSandboxRequest) -> str | None:
        if request.build is not None:
            # §3.9: built images are cached by content hash; a rebuild is a no-op.
            return "img_" + request.build.content_hash.split(":")[1][:16]
        if request.image is not None:
            ref = request.image.image
            tmpl = self._templates.get(ref)
            if tmpl is not None:
                caller = self._caller_key()
                if (
                    caller is not None
                    and tmpl.owner_api_key is not None
                    and tmpl.owner_api_key != caller
                ):
                    raise SandboxOpError(
                        "template_not_found",
                        404,
                        f"no template {ref}",
                    )
                if tmpl.status != "READY":
                    raise SandboxOpError(
                        "template_not_ready",
                        409,
                        f"template {ref} is {tmpl.status}",
                    )
                self._images.setdefault(
                    tmpl.image_ref,
                    {"cached": True, "size_bytes": 0, "digest": None},
                )
                return tmpl.image_ref
            self._images.setdefault(
                ref, {"cached": True, "size_bytes": 0, "digest": request.image.digest}
            )
            return "img_" + uuid.uuid4().hex[:12]
        return None

    def _materialize(
        self, request: CreateSandboxRequest, now: datetime, api_key: str | None, image_id: str | None, snap
    ) -> _Sandbox:
        sid = "sbx_" + uuid.uuid4().hex[:12]
        root = self._base / sid
        root.mkdir(parents=True, exist_ok=True)
        (root / "work").mkdir(exist_ok=True)
        if snap is not None:
            self._unpack_snapshot(snap[0], root)
        sandbox = _Sandbox(
            id=sid,
            root=root,
            state="running",
            created_at=now,
            expires_at=now + timedelta(seconds=request.ttl_seconds),
            ttl_seconds=request.ttl_seconds,
            resources=request.resources,
            network_mode=request.network.mode,
            network_allow=tuple(request.network.allow),
            labels=dict(request.labels),
            env=dict(request.env),
            api_key=api_key,
            image_id=image_id,
            snapshot_id=request.snapshot_id,
            started_at=now,
            idle_timeout_seconds=request.idle_timeout_seconds,
            last_activity_at=now,
        )
        self._sandboxes[sid] = sandbox
        return sandbox

    # ------------------------------------------------------------------ §3.1 read / wait
    def get(self, sandbox_id: str) -> dict[str, Any]:
        with self._lock:
            return self._get_doc(self._require_active(sandbox_id))

    def wait(self, sandbox_id: str, timeout_seconds: int) -> dict[str, Any]:
        with self._lock:
            sandbox = self._require_active(sandbox_id)
            if sandbox.state != "creating":
                return self._get_doc(sandbox)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            with self._lock:
                sandbox = self._require_active(sandbox_id)
                if sandbox.state in ("running", "failed"):
                    return self._get_doc(sandbox)
            time.sleep(0.05)
        raise SandboxOpError("wait_timeout", 408, f"sandbox {sandbox_id} not ready in {timeout_seconds}s")

    def _get_doc(self, sandbox: _Sandbox) -> dict[str, Any]:
        metrics = Metrics(
            cpu_seconds=round(sandbox.cpu_seconds, 3),
            memory_peak_bytes=sandbox.memory_peak_bytes,
            disk_bytes=self._disk_bytes(sandbox),
            network_bytes=sandbox.network_bytes,
            started_at=sandbox.started_at,
            deleted_at=sandbox.deleted_at,
        )
        doc = {
            "id": sandbox.id,
            "state": sandbox.state,
            "image_id": sandbox.image_id,
            "snapshot_id": sandbox.snapshot_id,
            "created_at": sandbox.created_at.isoformat(),
            "expires_at": sandbox.expires_at.isoformat(),
            "ttl_seconds": sandbox.ttl_seconds,
            "idle_timeout_seconds": sandbox.idle_timeout_seconds,
            "resources": {
                "vcpu": sandbox.resources.vcpu,
                "memory_gib": sandbox.resources.memory_gib,
                "disk_gib": sandbox.resources.disk_gib,
            },
            "network": {"mode": sandbox.network_mode, "allow": list(sandbox.network_allow)},
            "labels": dict(sandbox.labels),
            "env_keys": sorted(sandbox.env),  # §3.17: names only, never values
            "metrics": metrics.to_document(),
        }
        if sandbox.exposed:
            doc["exposed"] = {str(p): u for p, u in sandbox.exposed.items()}
        return doc

    # ------------------------------------------------------------------ §3.2 exec / processes
    @staticmethod
    def _guest_env(sandbox: _Sandbox, request_env: Mapping[str, str] | None = None) -> dict[str, str]:
        """Build guest env without inheriting host secrets (CATHEDRAL_*, cloud keys, etc.)."""
        env: dict[str, str] = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            "HOME": str(sandbox.root),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "TERM": os.environ.get("TERM", "xterm"),
        }
        env.update(sandbox.env)
        if request_env:
            env.update(dict(request_env))
        return env

    def _run(self, sandbox: _Sandbox, request: ExecRequest) -> tuple[int, bytes, bytes, bool, float]:
        argv = list(request.argv)
        cwd = str(self._host(sandbox, request.cwd)) if request.cwd else str(sandbox.root / "work")
        os.makedirs(cwd, exist_ok=True)
        env = self._guest_env(sandbox, request.env)
        stdin = request.stdin.encode() if request.stdin is not None else None
        proc = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
        )
        timed_out = False
        t0 = time.perf_counter()
        try:
            out, err = proc.communicate(input=stdin, timeout=request.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            out, err = proc.communicate()
        duration = (time.perf_counter() - t0) * 1000
        return proc.returncode, out or b"", err or b"", timed_out, duration

    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult:
        with self._lock:
            sandbox = self._require_running(sandbox_id)
        code, out, err, timed_out, duration = self._run(sandbox, request)
        sandbox_api_cap = api.STDOUT_CAP_BYTES
        truncated = len(out) > sandbox_api_cap or len(err) > sandbox_api_cap
        out = out[:sandbox_api_cap]
        err = err[:sandbox_api_cap]
        peak_rss = _child_peak_rss_bytes()
        with self._lock:
            sandbox.cpu_seconds += duration / 1000
            sandbox.network_bytes += len(out) + len(err)
            sandbox.memory_peak_bytes = max(sandbox.memory_peak_bytes, peak_rss)
            self._touch(sandbox)
            sandbox.exec_history.append(
                ExecRecord(command=_render_cmd(request), exit_code=code, duration_ms=int(duration), at=_now())
            )
            sandbox.container_stdout.extend(out)
            sandbox.container_stderr.extend(err)
        return ExecResult(
            exit_code=code,
            stdout=out.decode("utf-8", "replace"),
            stderr=err.decode("utf-8", "replace"),
            duration_ms=int(duration),
            timed_out=timed_out,
            truncated=truncated,
        )

    def start_process(self, sandbox_id: str, request: ExecRequest) -> ProcessHandle:
        with self._lock:
            sandbox = self._require_running(sandbox_id)
            pid = "proc_" + uuid.uuid4().hex[:10]
            logpath = sandbox.root / f".process-{pid}.log"
            cwd = str(self._host(sandbox, request.cwd)) if request.cwd else str(sandbox.root / "work")
            os.makedirs(cwd, exist_ok=True)
            # A background process must outlive the call that started it (§3.2).
            handle = subprocess.Popen(
                list(request.argv), cwd=cwd, env=self._guest_env(sandbox, request.env),
                stdout=open(logpath, "wb"), stderr=subprocess.STDOUT, start_new_session=True,
            )
            sandbox.processes[pid] = (handle, logpath)
            return ProcessHandle(process_id=pid, argv=tuple(request.argv), running=handle.poll() is None)

    def process_logs(self, sandbox_id: str, process_id: str) -> str:
        with self._lock:
            sandbox = self._require_active(sandbox_id)
            entry = sandbox.processes.get(process_id)
            if entry is None:
                raise SandboxOpError("process_not_found", 404, f"no process {process_id}")
            return entry[1].read_bytes().decode("utf-8", "replace") if entry[1].exists() else ""

    def stop_process(self, sandbox_id: str, process_id: str) -> None:
        with self._lock:
            sandbox = self._require_active(sandbox_id)
            entry = sandbox.processes.get(process_id)
            if entry is None:
                raise SandboxOpError("process_not_found", 404, f"no process {process_id}")
            handle = entry[0]
            if handle.poll() is None:
                try:
                    os.killpg(os.getpgid(handle.pid), signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    handle.terminate()

    # ------------------------------------------------------------------ §3.3 files / tar / stat
    def write_file(self, sandbox_id: str, path: str, data: bytes, mode: int | None) -> None:
        with self._lock:
            sandbox = self._require_running(sandbox_id)
            self._touch(sandbox)
            self._assert_disk_room(sandbox, extra_bytes=len(data), replacing=path)
        host = self._host(sandbox, path)
        host.parent.mkdir(parents=True, exist_ok=True)
        host.write_bytes(data)
        if mode is not None:
            os.chmod(host, mode)

    def read_file(self, sandbox_id: str, spec: FileGet) -> tuple[bytes, int]:
        with self._lock:
            sandbox = self._require_active(sandbox_id)
            self._touch(sandbox)
        host = self._host(sandbox, spec.path)
        if not host.is_file():
            raise SandboxOpError("file_not_found", 404, f"no file {spec.path}")
        total = host.stat().st_size
        # §3.3: ?max_bytes= past the cap is a 413 (the whole file is too big to return).
        if spec.max_bytes is not None and total > spec.max_bytes:
            raise SandboxOpError("file_too_large", 413, f"{spec.path} is {total} bytes, over max_bytes {spec.max_bytes}")
        with host.open("rb") as fh:
            if spec.range_start is not None:
                fh.seek(spec.range_start)
                length = (spec.range_end - spec.range_start + 1) if spec.range_end is not None else None
                return fh.read(length), total
            return fh.read(), total

    def write_tar(self, sandbox_id: str, path: str, tarball: bytes) -> None:
        with self._lock:
            sandbox = self._require_running(sandbox_id)
            self._touch(sandbox)
            # Bound by compressed size as a conservative pre-check; post-extract
            # recheck catches expansion past disk_gib.
            self._assert_disk_room(sandbox, extra_bytes=len(tarball), replacing=None)
        target = self._host(sandbox, path)
        target.mkdir(parents=True, exist_ok=True)
        import io

        with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tf:
            _safe_extract(tf, target)
        with self._lock:
            sandbox = self._require_active(sandbox_id)
            self._assert_disk_room(sandbox, extra_bytes=0, replacing=None)

    def read_tar(self, sandbox_id: str, spec: TarGet) -> bytes:
        with self._lock:
            sandbox = self._require_active(sandbox_id)
        source = self._host(sandbox, spec.path)
        if not source.is_dir():
            raise SandboxOpError("dir_not_found", 404, f"no directory {spec.path}")
        import io

        buf = io.BytesIO()
        excludes = set(spec.exclude)
        includes = set(spec.include)
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for child in sorted(source.iterdir()):
                if child.name in excludes:
                    continue
                if includes and child.name not in includes:
                    continue
                tf.add(child, arcname=child.name)
        return buf.getvalue()

    def stat(self, sandbox_id: str, path: str) -> StatResult:
        with self._lock:
            sandbox = self._require_active(sandbox_id)
        host = self._host(sandbox, path)
        if not host.exists():
            raise SandboxOpError("path_not_found", 404, f"no path {path}")
        st = host.stat()
        return StatResult(is_dir=host.is_dir(), is_file=host.is_file(), size=st.st_size, mode=st.st_mode & 0o7777)

    # ------------------------------------------------------------------ §3.5 snapshot / fork primitives
    def snapshot(self, sandbox_id: str, *, ttl_seconds: int | None = None, name: str | None = None, labels: dict[str, str] | None = None) -> str:
        if ttl_seconds is None:
            ttl_seconds = api.SNAPSHOT_TTL_DEFAULT_SECONDS
        if not (1 <= ttl_seconds <= api.SNAPSHOT_TTL_MAX_SECONDS):
            raise SandboxContractError(
                "invalid_ttl", f"snapshot ttl_seconds must be between 1 and {api.SNAPSHOT_TTL_MAX_SECONDS}"
            )
        with self._lock:
            self._sweep_snapshots_locked()
            # §3.5: named snapshots are get-or-create -- re-snapshotting under an
            # existing name returns that snapshot rather than duplicating it.
            if name:
                for sid, (_, rec) in self._snapshots.items():
                    if rec.name == name:
                        op_id = api.operation_id()
                        self._operations[op_id] = {
                            "status": "done",
                            "result": {"snapshot_id": sid, "size_bytes": rec.size_bytes, "name": name},
                        }
                        return op_id
            if len(self._snapshots) >= self._max_snapshots:
                raise SandboxOpError(
                    "snapshot_quota", 429, f"snapshot store is full ({self._max_snapshots})", retry_after=30
                )
            sandbox = self._require_active(sandbox_id)
            snap_id = "snap_" + uuid.uuid4().hex[:12]
            path = self._base / f"{snap_id}.tar.gz"
            with tarfile.open(path, "w:gz") as tf:
                tf.add(sandbox.root / "work", arcname=".")
            size = path.stat().st_size
            record = SnapshotRecord(
                snapshot_id=snap_id, size_bytes=size, ttl_seconds=ttl_seconds, created_at=_now(),
                name=name or None, labels=dict(labels or {}),
            )
            self._snapshots[snap_id] = (path, record)
            op_id = api.operation_id()
            self._operations[op_id] = {
                "status": "done",
                "result": {"snapshot_id": snap_id, "size_bytes": size, **({"name": name} if name else {})},
            }
            return op_id

    def _sweep_snapshots_locked(self) -> None:
        """§3.5: drop snapshots whose retention TTL has elapsed (deletes the tar)."""
        now = _now()
        expired = [
            sid
            for sid, (_, rec) in self._snapshots.items()
            if rec.created_at is not None and now - rec.created_at >= timedelta(seconds=rec.ttl_seconds)
        ]
        for sid in expired:
            path, _ = self._snapshots.pop(sid)
            Path(path).unlink(missing_ok=True)

    def list_snapshots(self, labels: Iterable[str] = ()) -> list[dict[str, Any]]:
        want = _parse_label_filters(labels)
        with self._lock:
            self._sweep_snapshots_locked()
            out = []
            for sid, (_, rec) in self._snapshots.items():
                if want and not all((rec.labels or {}).get(k) == v for k, v in want.items()):
                    continue
                out.append(
                    {
                        "snapshot_id": sid,
                        "size_bytes": rec.size_bytes,
                        "ttl_seconds": rec.ttl_seconds,
                        "created_at": rec.created_at.isoformat() if rec.created_at else None,
                        "name": rec.name,
                        "labels": dict(rec.labels or {}),
                    }
                )
            return out

    def delete_snapshot(self, snapshot_id: str) -> bool:
        with self._lock:
            meta = self._snapshots.pop(snapshot_id, None)
            if meta is None:
                return False
            Path(meta[0]).unlink(missing_ok=True)
            return True

    def _unpack_snapshot(self, tar_path: Path, root: Path) -> None:
        with tarfile.open(tar_path, "r:gz") as tf:
            _safe_extract(tf, root / "work")

    # ------------------------------------------------------------------ §3.4 lifecycle / GC
    def heartbeat(self, sandbox_id: str, ttl_seconds: int | None) -> dict[str, Any]:
        with self._lock:
            sandbox = self._require_active(sandbox_id)
            if ttl_seconds is None:
                ttl_seconds = sandbox.ttl_seconds
            if not (1 <= ttl_seconds <= api.TTL_MAX_SECONDS):
                raise SandboxContractError("invalid_ttl", f"ttl_seconds must be between 1 and {api.TTL_MAX_SECONDS}")
            sandbox.ttl_seconds = ttl_seconds
            sandbox.expires_at = _now() + timedelta(seconds=ttl_seconds)
            self._touch(sandbox)
            return self._get_doc(sandbox)

    def delete(self, sandbox_id: str) -> None:
        """§3.4: idempotent — deleting a gone sandbox is still a success (server => 204).

        Everything in the sandbox is destroyed at DELETE (§3.18); only the §3.13 log
        record (container stdout/stderr + exec history) is retained for 24 h.
        """
        with self._lock:
            sandbox = self._sandboxes.get(sandbox_id)
            if sandbox is None or sandbox.state == "deleted":
                return
            for handle, _ in sandbox.processes.values():
                if handle is None:
                    continue
                if handle.poll() is None:
                    handle.terminate()
            sandbox.state = "deleted"
            sandbox.deleted_at = _now()
            self._retain_logs(sandbox)
            shutil.rmtree(sandbox.root, ignore_errors=True)
            del self._sandboxes[sandbox_id]

    def _retain_logs(self, sandbox: _Sandbox) -> None:
        """§3.13/§3.18: snapshot the log record so it survives the deleted sandbox for 24 h."""
        if sandbox.deleted_at is None:
            sandbox.deleted_at = _now()
        self._log_tombstones[sandbox.id] = {
            "sandbox_id": sandbox.id,
            "state": "deleted",
            "stdout": bytes(sandbox.container_stdout),
            "stderr": bytes(sandbox.container_stderr),
            "exec_history": list(sandbox.exec_history),
            "metrics": Metrics(
                cpu_seconds=round(sandbox.cpu_seconds, 3),
                memory_peak_bytes=sandbox.memory_peak_bytes,
                disk_bytes=0,
                network_bytes=sandbox.network_bytes,
                started_at=sandbox.started_at,
                deleted_at=sandbox.deleted_at,
            ).to_document(),
            # §3.16 metering survives the delete so usage can bill running->deleted.
            "labels": dict(sandbox.labels),
            "resources": sandbox.resources,
            "created_at": sandbox.created_at,
            "deleted_at": sandbox.deleted_at,
            "api_key": sandbox.api_key,
            "retained_until": sandbox.deleted_at + timedelta(hours=api.PROCESS_LOG_RETENTION_HOURS),
        }

    def logs(self, sandbox_id: str) -> dict[str, Any]:
        """§3.13: container stdout/stderr + exec history, retained 24 h after delete."""
        with self._lock:
            sandbox = self._sandboxes.get(sandbox_id)
            if sandbox is not None and sandbox.state != "deleted":
                self._assert_owner(sandbox)
                return {
                    "sandbox_id": sandbox.id,
                    "state": sandbox.state,
                    "stdout": bytes(sandbox.container_stdout).decode("utf-8", "replace"),
                    "stderr": bytes(sandbox.container_stderr).decode("utf-8", "replace"),
                    "exec_history": [r.to_document() for r in sandbox.exec_history],
                }
            tomb = self._log_tombstones.get(sandbox_id)
            if tomb is None or _now() > tomb["retained_until"]:
                raise SandboxOpError("sandbox_not_found", 404, f"no logs for sandbox {sandbox_id}")
            tomb_key = tomb.get("api_key")
            caller = self._caller_key()
            if caller is not None and tomb_key is not None and tomb_key != caller:
                raise SandboxOpError("sandbox_not_found", 404, f"no logs for sandbox {sandbox_id}")
            return {
                "sandbox_id": sandbox_id,
                "state": "deleted",
                "stdout": tomb["stdout"].decode("utf-8", "replace"),
                "stderr": tomb["stderr"].decode("utf-8", "replace"),
                "exec_history": [r.to_document() for r in tomb["exec_history"]],
                "retained_until": tomb["retained_until"].isoformat(),
            }

    def sweep(self) -> int:
        """Auto-GC anything past TTL or its idle window (§3.4, §3.10/§3.11).

        A TTL-expired sandbox is collectable within the 5 min grace.  A sandbox that
        opts into ``idle_timeout_seconds`` (§3.10/§3.11, the verifier runtime's
        reclamation knob) is collected once it has been idle longer than that window,
        even though its TTL has not elapsed.  A swept sandbox keeps its §3.13 log
        record for 24 h; tombstones past that window are dropped here (§3.18).
        """
        now = _now()
        removed = 0
        with self._lock:
            for sid, sandbox in list(self._sandboxes.items()):
                past_ttl = api.is_collectable(now, deadline_at=api.gc_deadline(sandbox.expires_at), last_heartbeat_at=None)
                idle_expired = (
                    sandbox.idle_timeout_seconds is not None
                    and sandbox.last_activity_at is not None
                    and (now - sandbox.last_activity_at) >= timedelta(seconds=sandbox.idle_timeout_seconds)
                )
                # §3.4: a sandbox whose owning project key has been revoked is collected too.
                key = self._keys.get(sandbox.api_key) if sandbox.api_key is not None else None
                revoked = key is not None and key.revoked
                if past_ttl or idle_expired or revoked:
                    sandbox.state = "deleted"
                    sandbox.deleted_at = now
                    self._retain_logs(sandbox)
                    shutil.rmtree(sandbox.root, ignore_errors=True)
                    del self._sandboxes[sid]
                    removed += 1
            for sid, tomb in list(self._log_tombstones.items()):
                if now > tomb["retained_until"]:
                    del self._log_tombstones[sid]
        return removed

    # ------------------------------------------------------------------ §3.4 list / bulk delete
    def list(self, *, labels: Iterable[str], state: str | None) -> list[dict[str, Any]]:
        want = _parse_label_filters(labels)
        caller = self._caller_key()
        with self._lock:
            out = []
            for sandbox in self._sandboxes.values():
                if caller is not None and sandbox.api_key is not None and sandbox.api_key != caller:
                    continue
                if state and sandbox.state != state:
                    continue
                if all(sandbox.labels.get(k) == v for k, v in want.items()):
                    out.append(self._get_doc(sandbox))
            return out

    def bulk_delete(self, labels: Iterable[str]) -> int:
        want = _parse_label_filters(labels)
        if not want:
            # §3.4: bulk delete is label-scoped; an unfiltered bulk delete is refused.
            raise SandboxContractError("invalid_label", "bulk delete requires at least one label filter")
        caller = self._caller_key()
        with self._lock:
            targets = [
                sid
                for sid, s in self._sandboxes.items()
                if all(s.labels.get(k) == v for k, v in want.items())
                and (caller is None or s.api_key is None or s.api_key == caller)
            ]
        for sid in targets:
            self.delete(sid)
        return len(targets)

    # ------------------------------------------------------------------ §3.7 network / expose
    def set_network(self, sandbox_id: str, patch: NetworkPatch) -> dict[str, Any]:
        with self._lock:
            sandbox = self._require_running(sandbox_id)
            sandbox.network_mode = patch.mode
            sandbox.network_allow = tuple(patch.allow)
            return {"sandbox_id": sandbox_id, "network": {"mode": sandbox.network_mode, "allow": list(sandbox.network_allow)}}

    def expose(self, sandbox_id: str, request: ExposeRequest) -> dict[str, Any]:
        with self._lock:
            sandbox = self._require_running(sandbox_id)
            url = f"https://{sandbox_id}-{request.port}.{_host_of(self._base_url)}"
            sandbox.exposed[request.port] = url
            return {"port": request.port, "url": url, "status": "exposed"}

    # ------------------------------------------------------------------ Agent IDE freeze / thaw (G2)
    def freeze(self, sandbox_id: str) -> dict[str, Any]:
        """Pause a running sandbox without deleting it (Agent IDE).

        Frozen sandboxes still occupy resident quota (honest host capacity).
        Mutate/exec paths refuse with sandbox_frozen until thaw.
        """
        with self._lock:
            sandbox = self._require_active(sandbox_id)
            if sandbox.state == "frozen":
                return self._get_doc(sandbox)
            if sandbox.state != "running":
                raise SandboxOpError(
                    "sandbox_not_running",
                    409,
                    f"cannot freeze sandbox in state {sandbox.state}",
                )
            # Best-effort pause of background processes (memory runtime).
            for handle, _log in list(sandbox.processes.values()):
                if handle.poll() is None:
                    try:
                        os.killpg(os.getpgid(handle.pid), signal.SIGSTOP)
                    except (ProcessLookupError, PermissionError, AttributeError):
                        try:
                            handle.send_signal(signal.SIGSTOP)
                        except (ProcessLookupError, PermissionError, AttributeError):
                            pass
            sandbox.state = "frozen"
            return self._get_doc(sandbox)

    def thaw(self, sandbox_id: str) -> dict[str, Any]:
        """Restore a frozen sandbox to running."""
        with self._lock:
            sandbox = self._require_active(sandbox_id)
            if sandbox.state == "running":
                return self._get_doc(sandbox)
            if sandbox.state != "frozen":
                raise SandboxOpError(
                    "sandbox_not_frozen",
                    409,
                    f"cannot thaw sandbox in state {sandbox.state}",
                )
            for handle, _log in list(sandbox.processes.values()):
                if handle.poll() is None:
                    try:
                        os.killpg(os.getpgid(handle.pid), signal.SIGCONT)
                    except (ProcessLookupError, PermissionError, AttributeError):
                        try:
                            handle.send_signal(signal.SIGCONT)
                        except (ProcessLookupError, PermissionError, AttributeError):
                            pass
            sandbox.state = "running"
            self._touch(sandbox)
            return self._get_doc(sandbox)

    # ------------------------------------------------------------------ Agent IDE interactive (G4–G6)
    def mint_access_ticket(self, sandbox_id: str, *, ttl_sec: int | None = None) -> dict[str, Any]:
        with self._lock:
            self._require_running(sandbox_id)
            try:
                ttl = agent_ux.validate_ticket_ttl(ttl_sec)
            except ValueError as exc:
                raise SandboxOpError("invalid_access_ticket_ttl", 400, str(exc)) from exc
            ticket = agent_ux.AccessTicket(
                ticket=agent_ux.new_ticket_id(),
                sandbox_id=sandbox_id,
                expires_at=time.time() + ttl,
            )
            self._tickets[ticket.ticket] = ticket
            return ticket.to_document()

    def consume_access_ticket(self, sandbox_id: str, ticket: str) -> None:
        """Public single-use ticket consume (desktop WS / external bridges)."""
        with self._lock:
            self._require_running(sandbox_id)
            self._consume_ticket(sandbox_id, ticket)

    def _consume_ticket(self, sandbox_id: str, ticket: str) -> None:
        rec = self._tickets.get(ticket)
        if rec is None or rec.sandbox_id != sandbox_id or not rec.alive():
            raise SandboxOpError("access_ticket_invalid", 401, "missing, expired, or consumed access ticket")
        rec.consumed = True

    def create_terminal(
        self, sandbox_id: str, *, cols: int | None = None, rows: int | None = None
    ) -> dict[str, Any]:
        with self._lock:
            self._require_running(sandbox_id)
            try:
                c, r = agent_ux.validate_terminal_size(cols, rows)
            except ValueError as exc:
                raise SandboxOpError("invalid_terminal_size", 400, str(exc)) from exc
            term = agent_ux.TerminalSession(
                id=agent_ux.new_terminal_id(),
                sandbox_id=sandbox_id,
                cols=c,
                rows=r,
                started_at=agent_ux.utc_now(),
            )
            self._terminals.setdefault(sandbox_id, {})[term.id] = term
            return term.to_document()

    def list_terminals(self, sandbox_id: str) -> list[dict[str, Any]]:
        with self._lock:
            self._require_active(sandbox_id)
            return [t.to_document() for t in self._terminals.get(sandbox_id, {}).values()]

    def delete_terminal(self, sandbox_id: str, terminal_id: str) -> None:
        with self._lock:
            self._require_active(sandbox_id)
            bag = self._terminals.get(sandbox_id, {})
            term = bag.get(terminal_id)
            if term is None:
                raise SandboxOpError("terminal_not_found", 404, f"no terminal {terminal_id}")
            term.exited = True
            term.exit_code = 0
            del bag[terminal_id]

    def connect_terminal(self, sandbox_id: str, terminal_id: str, *, ticket: str) -> dict[str, Any]:
        """Consume a single-use access ticket and mark the terminal connected (G4).

        Full WebSocket PTY framing can ride this handshake; the reference provider
        exposes REST write/read after connect for deterministic tests.
        """
        with self._lock:
            self._require_running(sandbox_id)
            self._consume_ticket(sandbox_id, ticket)
            term = self._terminals.get(sandbox_id, {}).get(terminal_id)
            if term is None or term.exited:
                raise SandboxOpError("terminal_not_found", 404, f"no terminal {terminal_id}")
            term.connected = True
            term.output.extend(b"[cathedral] terminal connected\n")
            return {
                "terminal_id": terminal_id,
                "connected": True,
                "transport": "websocket+rest",
                "ws_path": f"/v1/sandboxes/{sandbox_id}/terminals/{terminal_id}/ws",
                "note": "Prefer WebSocket /ws with X-Cathedral-Access-Ticket (query tickets disabled); REST write/read remain for tests.",
            }

    def terminal_write(self, sandbox_id: str, terminal_id: str, data: str) -> dict[str, Any]:
        with self._lock:
            self._require_running(sandbox_id)
            term = self._terminals.get(sandbox_id, {}).get(terminal_id)
            if term is None or term.exited:
                raise SandboxOpError("terminal_not_found", 404, f"no terminal {terminal_id}")
            if not term.connected:
                raise SandboxOpError("terminal_not_connected", 409, "connect with an access ticket first")
            term.input_buf.extend(data.encode("utf-8", errors="replace"))
            # Execute complete lines through the sandbox exec path (interactive shell lines).
            text = term.input_buf.decode("utf-8", errors="replace")
            if "\n" not in text and "\r" not in text:
                return {"written": len(data), "pending": True}
            lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
            term.input_buf = bytearray(lines[-1].encode("utf-8"))
            for line in lines[:-1]:
                cmd = line.strip()
                if not cmd:
                    continue
                term.output.extend(f"$ {cmd}\n".encode())
        # Run outside the lock (exec takes its own lock).
        for line in lines[:-1]:
            cmd = line.strip()
            if not cmd:
                continue
            try:
                result = self.exec(sandbox_id, ExecRequest(cmd=cmd, timeout_seconds=30))
                chunk = (result.stdout or "") + (result.stderr or "")
                with self._lock:
                    term = self._terminals.get(sandbox_id, {}).get(terminal_id)
                    if term is not None:
                        term.output.extend(chunk.encode("utf-8", errors="replace"))
                        if not chunk.endswith("\n"):
                            term.output.extend(b"\n")
            except SandboxOpError as exc:
                with self._lock:
                    term = self._terminals.get(sandbox_id, {}).get(terminal_id)
                    if term is not None:
                        term.output.extend(f"[error] {exc}\n".encode())
        return {"written": len(data), "pending": False}

    def terminal_read(self, sandbox_id: str, terminal_id: str) -> dict[str, Any]:
        with self._lock:
            self._require_active(sandbox_id)
            term = self._terminals.get(sandbox_id, {}).get(terminal_id)
            if term is None:
                raise SandboxOpError("terminal_not_found", 404, f"no terminal {terminal_id}")
            data = bytes(term.output)
            term.output.clear()
            return {
                "terminal_id": terminal_id,
                "data": data.decode("utf-8", errors="replace"),
                "exited": term.exited,
            }

    def publish_template(
        self,
        sandbox_id: str,
        *,
        name: str,
        display_name: str | None = None,
        description: str = "",
    ) -> dict[str, Any]:
        with self._lock:
            sandbox = self._require_running(sandbox_id)
            try:
                name = agent_ux.validate_template_name(name)
            except ValueError as exc:
                raise SandboxOpError("invalid_template_name", 400, str(exc)) from exc
            uid = agent_ux.new_template_uid(name)
            image_ref = sandbox.image_id or f"cathedral-template-{uid}"
            tmpl = agent_ux.SandboxTemplate(
                uid=uid,
                name=name,
                display_name=display_name or name,
                description=description or "",
                kind="USER",
                status="PENDING",
                source_sandbox_id=sandbox_id,
                image_ref=image_ref,
                owner_api_key=sandbox.api_key,
            )
            self._templates[uid] = tmpl
            # Reference provider: snapshot FS into a named image entry and mark READY.
            self._images[uid] = {"cached": True, "size_bytes": self._disk_bytes(sandbox), "digest": None}
            self._images[image_ref] = {"cached": True, "size_bytes": self._disk_bytes(sandbox), "digest": None}
            tmpl.status = "READY"
            tmpl.updated_at = agent_ux.utc_now()
            return tmpl.to_document()

    def list_templates(self, *, kind: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        caller = self._caller_key()
        with self._lock:
            out = []
            for tmpl in self._templates.values():
                if caller is not None and tmpl.owner_api_key is not None and tmpl.owner_api_key != caller:
                    continue
                if kind and tmpl.kind != kind:
                    continue
                if status and tmpl.status != status:
                    continue
                out.append(tmpl.to_document())
            return out

    def get_template(self, template_uid: str) -> dict[str, Any]:
        with self._lock:
            tmpl = self._templates.get(template_uid)
            if tmpl is None:
                raise SandboxOpError("template_not_found", 404, f"no template {template_uid}")
            caller = self._caller_key()
            if caller is not None and tmpl.owner_api_key is not None and tmpl.owner_api_key != caller:
                raise SandboxOpError("template_not_found", 404, f"no template {template_uid}")
            return tmpl.to_document()

    def desktop(self, sandbox_id: str) -> dict[str, Any]:
        """G5: desktop only when CATHEDRAL_AGENT_DESKTOP=1; RFB WS is listening when enabled."""
        with self._lock:
            self._require_active(sandbox_id)
        enabled = os.environ.get("CATHEDRAL_AGENT_DESKTOP", "0") == "1"
        if not enabled:
            return {"available": False}
        return {
            "available": True,
            "port": 5901,
            "listening": True,
            "ws_url": f"{self._base_url}/v1/sandboxes/{sandbox_id}/desktop/ws",
            "note": "Reference runtime serves a minimal RFB stream over WebSocket after access ticket.",
        }

    # ------------------------------------------------------------------ §3.9 images
    def prefetch(self, request: PrefetchRequest) -> str:
        with self._lock:
            for ref in request.images:
                self._images.setdefault(ref, {"cached": True, "size_bytes": 0, "digest": None})
            op_id = api.operation_id()
            self._operations[op_id] = {"status": "done", "result": {"prefetched": list(request.images)}}
            return op_id

    def image_status(self, ref: str) -> dict[str, Any]:
        with self._lock:
            entry = self._images.get(ref)
        if entry is None:
            return ImageStatusLike(ref, cached=False, size_bytes=0, digest=None).to_document()
        doc = dict(entry)
        doc.setdefault("ref", ref)
        return doc

    # ------------------------------------------------------------------ §3.8 quota / usage / status
    def _usage_now(self, *, api_key: str | None = None) -> QuotaUsage:
        """Resident capacity: running + creating + frozen (freeze does not free host slots)."""
        resident = [
            s
            for s in self._sandboxes.values()
            if s.state in ("running", "creating", "frozen")
            and (api_key is None or s.api_key == api_key)
        ]
        return QuotaUsage(
            running_sandboxes=len(resident),
            vcpu=sum(s.resources.vcpu for s in resident),
            memory_gib=sum(s.resources.memory_gib for s in resident),
        )

    def quota(self) -> dict[str, Any]:
        usage = self._usage_now()
        running = [s for s in self._sandboxes.values() if s.state in ("running", "creating")]
        frozen = [s for s in self._sandboxes.values() if s.state == "frozen"]
        return {
            "limits": {
                "running_sandboxes": self._limits.running_sandboxes,
                "vcpu": self._limits.vcpu,
                "memory_gib": self._limits.memory_gib,
            },
            "usage": {
                "running_sandboxes": len(running),
                "frozen_sandboxes": len(frozen),
                "resident_sandboxes": usage.running_sandboxes,
                "vcpu": usage.vcpu,
                "memory_gib": usage.memory_gib,
            },
            # §3.5 / §3.10-§3.11: guaranteed snapshot store and create pacing.
            "snapshot_store": self._max_snapshots,
            "creates_per_minute": self._creates_per_minute,
            "note": "Frozen sandboxes count toward resident quota; freeze does not free create slots",
        }

    def usage(self, *, group_by: str | None, labels: Iterable[str]) -> dict[str, Any]:
        """§3.13/§3.16: sandbox/vCPU/GiB hours, snapshot GiB-months and a dollar cost,
        grouped by label.  Metered by the second from running to deleted, including
        sandboxes that have already been collected (their log tombstone keeps the
        metering line)."""
        want = _parse_label_filters(labels)
        key = (group_by or "label.job").split("label.", 1)[-1]
        groups: dict[str, dict[str, float]] = {}
        now = _now()

        def record(labels_of: dict[str, str], vcpu: int, gib: int, seconds: float) -> str:
            group = labels_of.get(key, "unlabelled")
            hours = max(seconds, 0.0) / 3600
            entry = groups.setdefault(
                group, {"sandbox_hours": 0.0, "vcpu_hours": 0.0, "gib_hours": 0.0, "cost_usd": 0.0}
            )
            entry["sandbox_hours"] += hours
            entry["vcpu_hours"] += hours * vcpu
            entry["gib_hours"] += hours * gib
            entry["cost_usd"] += self._pricing.cost_usd(vcpu_hours=hours * vcpu, gib_hours=hours * gib)
            return group

        with self._lock:
            actives = list(self._sandboxes.values())
            tombs = [t for t in self._log_tombstones.values() if t.get("resources") is not None]

        for sandbox in actives:
            if want and not all(sandbox.labels.get(k) == v for k, v in want.items()):
                continue
            seconds = (now - sandbox.created_at).total_seconds()
            record(sandbox.labels, sandbox.resources.vcpu, sandbox.resources.memory_gib, seconds)

        for tomb in tombs:
            if want and not all(tomb["labels"].get(k) == v for k, v in want.items()):
                continue
            seconds = (tomb["deleted_at"] - tomb["created_at"]).total_seconds()
            record(tomb["labels"], tomb["resources"].vcpu, tomb["resources"].memory_gib, seconds)

        # §3.16: snapshots are billed per GiB-month over their own retention TTL.
        snap_months = 0.0
        with self._lock:
            self._sweep_snapshots_locked()
            snap_records = [rec for _, rec in self._snapshots.values()]
        for rec in snap_records:
            snap_months += api.snapshot_gib_months(rec.size_bytes, rec.ttl_seconds)
        snapshot_cost = self._pricing.cost_usd(snapshot_gib_months=snap_months)

        for entry in groups.values():
            entry["cost_usd"] = round(entry["cost_usd"], 6)
        total_cost = round(sum(e["cost_usd"] for e in groups.values()) + snapshot_cost, 6)
        return {
            "group_by": group_by or "label.job",
            "currency": "USD",
            "groups": groups,
            "snapshot_gib_months": round(snap_months, 6),
            "snapshot_cost_usd": round(snapshot_cost, 6),
            "total_cost_usd": total_cost,
        }

    def status(self) -> StatusReport:
        latencies = sorted(self._create_latencies_ms)
        p50 = int(latencies[len(latencies) // 2]) if latencies else 0
        attempts = len(self._create_latencies_ms)
        error_rate = (self._create_errors / attempts) if attempts else 0.0
        return StatusReport(
            status="operational",
            create_latency_p50_ms=p50,
            error_rate=round(error_rate, 4),
            region=self._region,
            runtime=self._runtime_label,
            kernel_isolation=False,
            dind=False,
            disk_enforced=self._enforce_disk,
        )

    def get_operation(self, operation_id: str) -> dict[str, Any]:
        with self._lock:
            op = self._operations.get(operation_id)
        if op is None:
            raise SandboxOpError("operation_not_found", 404, f"no operation {operation_id}")
        return {"operation_id": operation_id, **op}

    # ------------------------------------------------------------------ teardown
    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for sandbox in self._sandboxes.values():
                shutil.rmtree(sandbox.root, ignore_errors=True)
            shutil.rmtree(self._base, ignore_errors=True)
            self._sandboxes.clear()
            self._log_tombstones.clear()
            self._create_times.clear()

    def pricing(self) -> dict[str, Any]:
        """§3.16: expose the rate card and its Daytona/Modal reference comparison."""
        return {
            "vcpu_hour_usd": self._pricing.vcpu_hour_usd,
            "gib_hour_usd": self._pricing.gib_hour_usd,
            "snapshot_gib_month_usd": self._pricing.snapshot_gib_month_usd,
            "reference": self._pricing.reference_comparisons(),
        }


def _render_cmd(request: ExecRequest) -> str:
    return request.cmd if isinstance(request.cmd, str) else " ".join(request.cmd)


def _parse_label_filters(labels: Iterable[str]) -> dict[str, str]:
    want: dict[str, str] = {}
    for item in labels:
        if "=" in item:
            k, _, v = item.partition("=")
            want[k] = v
        else:
            want[item] = ""
    return want


def _host_of(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0] or "cathedral.computer"


def _child_peak_rss_bytes() -> int:
    """Peak resident set size of reaped children, normalised to bytes (§3.13 metrics).

    ``RUSAGE_CHILDREN.ru_maxrss`` is updated when a child is waited for, so it is read
    right after ``communicate()``.  macOS reports the value in bytes, Linux in kilobytes.
    """
    if resource is None:
        return 0
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return int(peak) if sys.platform == "darwin" else int(peak) * 1024


def parse_sandbox_keys(raw: str) -> list[ApiKey]:
    """Parse ``CATHEDRAL_SANDBOX_KEYS`` into project keys.

    Format: comma-separated ``key:project[:max_running]`` entries.  A key listed in
    ``CATHEDRAL_SANDBOX_REVOKED_KEYS`` (comma-separated) is marked revoked.  §3.14:
    several keys per project, each with an individual ``max_running``; revocation
    blocks new calls but deletes nothing.
    """
    revoked = {
        part.strip()
        for part in os.environ.get("CATHEDRAL_SANDBOX_REVOKED_KEYS", "").split(",")
        if part.strip()
    }
    keys: list[ApiKey] = []
    for entry in filter(None, (part.strip() for part in raw.split(","))):
        fields = entry.split(":")
        if len(fields) < 2:
            continue
        key, project = fields[0].strip(), fields[1].strip()
        if not key or not project:
            continue
        max_running: int | None = None
        if len(fields) >= 3 and fields[2].strip():
            try:
                max_running = int(fields[2].strip())
            except ValueError:
                max_running = None
        keys.append(ApiKey(key=key, project=project, max_running=max_running, revoked=key in revoked))
    return keys


def provider_from_environment(
    *,
    base_url: str | None = None,
    enforce_disk: bool = True,
    runtime_label: str = "memory",
) -> InMemorySandboxProvider:
    """Build a strict provider from the Cathedral operator environment.

    Reads ``CATHEDRAL_SANDBOX_KEYS`` / ``CATHEDRAL_SANDBOX_REVOKED_KEYS`` for §3.14
    project-key auth, and ``CATHEDRAL_SANDBOX_QUOTA`` (``running:vcpu:memory_gib``)
    for the §3.8 project limits.  Unknown bearer keys are refused (require_known_keys).
    Per-key ``max_running`` sub-quotas are enforced via ``CATHEDRAL_KEY_QUOTAS`` in
    :func:`cathedral.sandbox_api.evaluate_quota`.

    ``enforce_disk`` defaults on for customer-shaped boots so ``disk_gib`` is a real
    ceiling (customer checklist §3.6), not only a recorded number.
    """
    limits: QuotaLimits | None = None
    raw_quota = os.environ.get("CATHEDRAL_SANDBOX_QUOTA", "")
    parts = [p.strip() for p in raw_quota.split(":") if p.strip()]
    if len(parts) == 3:
        try:
            limits = QuotaLimits(
                running_sandboxes=int(parts[0]), vcpu=int(parts[1]), memory_gib=int(parts[2])
            )
        except ValueError:
            limits = None
    keys = parse_sandbox_keys(os.environ.get("CATHEDRAL_SANDBOX_KEYS", ""))
    return InMemorySandboxProvider(
        limits=limits,
        keys=keys,
        base_url=base_url,
        require_known_keys=True,
        enforce_disk=enforce_disk,
        runtime_label=runtime_label,
    )


def _safe_extract(tf: tarfile.TarFile, target: Path) -> None:
    """Extract tar members without path/symlink escape (fail closed)."""
    base = target.resolve()
    for member in tf.getmembers():
        name = member.name
        if name.startswith("/") or ".." in Path(name).parts:
            raise SandboxOpError("unsafe_tar", 400, f"tar member escapes target: {name}")
        if member.issym() or member.islnk():
            link = member.linkname or ""
            if link.startswith("/") or ".." in Path(link).parts:
                raise SandboxOpError(
                    "unsafe_tar",
                    400,
                    f"tar link escapes target: {name} -> {link}",
                )
        dest = (base / name).resolve()
        try:
            dest.relative_to(base)
        except ValueError as exc:
            raise SandboxOpError("unsafe_tar", 400, f"tar member escapes target: {name}") from exc
    # Prefer filter="data"; never fall back to unfiltered extractall.
    try:
        tf.extractall(base, filter="data")
    except TypeError:
        # Python < 3.12: extract members one-by-one after the checks above.
        for member in tf.getmembers():
            if member.isfile() or member.isdir():
                tf.extract(member, path=base)
            # Skip links/devices on old Python — refuse rather than invent host links.
            elif member.issym() or member.islnk():
                raise SandboxOpError(
                    "unsafe_tar",
                    400,
                    "symlink/hardlink members require Python 3.12+ filter=data",
                )


# Kept small: an ImageStatus document when a ref is unknown to the cache.
class ImageStatusLike:
    def __init__(self, ref: str, cached: bool, size_bytes: int, digest: str | None) -> None:
        self._doc = api.ImageStatus(ref=ref, cached=cached, size_bytes=size_bytes, digest=digest).to_document()

    def to_document(self) -> Mapping[str, object]:
        return self._doc


__all__ = [
    "InMemorySandboxProvider",
    "SandboxOpError",
    "SandboxProvider",
    "parse_sandbox_keys",
    "provider_from_environment",
]
