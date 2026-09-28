"""Sandbox executors for the TEE box: the protocol, a fake, and a runsc backend.

The service validates every caller value before it reaches an executor.
``RunscExecutor`` still builds only argv lists (never a shell on the host),
bounds every argument and every captured output, and is used only when an
operator configures it.
"""

from __future__ import annotations

import io
import json
import re
import secrets
import subprocess
import tarfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Protocol

from cathedral.tee_box.egress import EgressPolicy

MAX_OUTPUT_BYTES = 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_ARG_BYTES = 64 * 1024
# Background exec records, running or finished, are bounded per sandbox and
# per box. Each record holds at most MAX_OUTPUT_BYTES per stream, so the box
# retains at most MAX_RETAINED_OUTPUT_BYTES of exec output in total. Finished
# records are evicted once their result has been read and a short retention
# has passed (a caller that lost an answer may ask again), after a longer
# retention if never read, and oldest first when a cap is reached.
MAX_JOBS_PER_BOX = 32
MAX_JOBS_PER_SANDBOX = 16
MAX_RETAINED_OUTPUT_BYTES = MAX_JOBS_PER_BOX * 2 * MAX_OUTPUT_BYTES
DELIVERED_RETENTION_SECONDS = 60.0
FINISHED_RETENTION_SECONDS = 600.0
SANDBOX_PREFIX = "cathsbx-"
BOX_LABEL = "org.cathedral.tee-box.box"
SANDBOX_LABEL = "org.cathedral.tee-box.sandbox"
# How long a container name from a create that timed out stays pending
# cleanup: the daemon may still create it after the CLI was killed.
PENDING_CLEANUP_GRACE_SECONDS = 300.0
_BOX_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
DEFAULT_DNS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
DEFAULT_PIDS_PER_SANDBOX = 4096
DEFAULT_RUNTIME_PATH = "/usr/local/bin/runsc"
# Each customer exec records its in-sandbox pid here, so a timeout or a stop
# can kill the process tree inside the sandbox, not only the docker client.
EXEC_PID_PREFIX = "/tmp/.cathedral-exec-"
KILL_TIMEOUT_SECONDS = 30.0
# Storage drivers that honour ``docker run --storage-opt size=``. overlay2
# does so only on xfs mounted with project quotas (pquota).
QUOTA_DRIVERS = frozenset({"btrfs", "zfs", "devicemapper"})
# After an egress lapse, running internet sandboxes are removed on their own
# threads, at most this many at once, each docker call bounded by this
# timeout (a removal makes at most four calls).
LAPSE_REMOVAL_WORKERS = 4
LAPSE_REMOVAL_CALL_TIMEOUT_SECONDS = 15.0


class ExecutorError(Exception):
    """The executor could not do what was asked."""


class ExecutorRefused(ExecutorError):
    """The executor refuses this request on this box (for example, no egress control)."""


class NetworkLapsed(ExecutorError):
    """The sandbox ran while the egress rules lapsed and is being removed."""


class NotFound(ExecutorError):
    """The sandbox, exec, image or path does not exist."""


class TooLarge(ExecutorError):
    """The file or archive is larger than the transfer cap."""


@dataclass(frozen=True)
class Shape:
    vcpus: int
    memory_mib: int
    disk_mib: int

    def fits_within(self, other: "Shape") -> bool:
        return (
            self.vcpus <= other.vcpus
            and self.memory_mib <= other.memory_mib
            and self.disk_mib <= other.disk_mib
        )

    def plus(self, other: "Shape") -> "Shape":
        return Shape(
            self.vcpus + other.vcpus,
            self.memory_mib + other.memory_mib,
            self.disk_mib + other.disk_mib,
        )

    def view(self) -> dict[str, int]:
        return {"vcpus": self.vcpus, "memory_mib": self.memory_mib, "disk_mib": self.disk_mib}


@dataclass(frozen=True)
class ImageInfo:
    digest: str
    reference: str

    def view(self) -> dict[str, object]:
        return {
            "id": self.digest,
            "digest": self.digest,
            "reference": self.reference,
            "state": "ready",
        }


@dataclass(frozen=True)
class SandboxSpec:
    sandbox_id: str
    owner: str
    image: ImageInfo
    shape: Shape
    network: str
    expires_at: float
    env: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SandboxInfo:
    spec: SandboxSpec
    created_at: float
    state: str = "running"

    @property
    def sandbox_id(self) -> str:
        return self.spec.sandbox_id


@dataclass(frozen=True)
class ExecRequest:
    argv: tuple[str, ...]
    timeout_seconds: int
    env: Mapping[str, str] = field(default_factory=dict)
    user: str | None = None
    cwd: str | None = None


@dataclass(frozen=True)
class ExecResult:
    exit_code: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(frozen=True)
class ExecStatus:
    exec_id: str
    state: str  # running, exited, timed_out or killed
    result: ExecResult | None = None


@dataclass(frozen=True)
class FileStat:
    is_dir: bool
    is_file: bool
    size: int
    mode: int


class Executor(Protocol):
    """Sandbox lifecycle on one box. Callers own ids, owners and expiries."""

    @property
    def network_modes(self) -> tuple[str, ...]: ...
    def import_image(self, digest: str, reference: str) -> ImageInfo: ...
    def get_image(self, digest: str) -> ImageInfo | None: ...
    def create(self, spec: SandboxSpec) -> SandboxInfo: ...
    def get(self, sandbox_id: str) -> SandboxInfo | None: ...
    def list(self) -> tuple[SandboxInfo, ...]: ...
    def set_expiry(self, sandbox_id: str, expires_at: float) -> SandboxInfo: ...
    def delete(self, sandbox_id: str) -> bool: ...
    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult: ...
    def start_exec(self, sandbox_id: str, request: ExecRequest) -> str: ...
    def poll_exec(self, sandbox_id: str, exec_id: str, wait_seconds: float) -> ExecStatus: ...
    def stop_exec(self, sandbox_id: str, exec_id: str) -> ExecStatus: ...
    def write_file(self, sandbox_id: str, path: str, data: bytes, mode: int) -> None: ...
    def read_file(self, sandbox_id: str, path: str) -> bytes: ...
    def stat(self, sandbox_id: str, path: str) -> FileStat | None: ...
    def put_tar(self, sandbox_id: str, path: str, data: bytes) -> None: ...
    def get_tar(self, sandbox_id: str, path: str, excludes: Sequence[str]) -> bytes: ...
    def sweep(self) -> int:
        """Remove sandboxes the table does not track; return how many remain."""
        ...


class EgressControl(Protocol):
    """What ``RunscExecutor`` needs from an egress enforcer (``tee_box.enforce``)."""

    @property
    def active(self) -> bool: ...
    @property
    def lapses(self) -> int: ...
    @property
    def quarantined(self) -> bool: ...
    def quarantine(self) -> bool: ...
    def lift_quarantine(self) -> bool: ...
    def verify(self) -> bool: ...
    def attach(self, container: str) -> object: ...
    def is_enforced(self, container: str) -> bool: ...
    def detach(self, container: str) -> bool: ...
    def maintain(self, on_lapse: Callable[[], object] | None = None) -> None: ...
    def status(self) -> dict[str, object]: ...


class _Table:
    """Sandbox and image bookkeeping shared by both executors."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._sandboxes: dict[str, SandboxInfo] = {}
        self._images: dict[str, ImageInfo] = {}

    def get_image(self, digest: str) -> ImageInfo | None:
        with self._lock:
            return self._images.get(digest)

    def get(self, sandbox_id: str) -> SandboxInfo | None:
        with self._lock:
            return self._sandboxes.get(sandbox_id)

    def list(self) -> tuple[SandboxInfo, ...]:
        with self._lock:
            return tuple(self._sandboxes.values())

    def set_expiry(self, sandbox_id: str, expires_at: float) -> SandboxInfo:
        with self._lock:
            info = self._sandboxes.get(sandbox_id)
            if info is None:
                raise NotFound
            info = replace(info, spec=replace(info.spec, expires_at=expires_at))
            self._sandboxes[sandbox_id] = info
            return info

    def _require(self, sandbox_id: str) -> SandboxInfo:
        info = self.get(sandbox_id)
        if info is None:
            raise NotFound
        return info

    def _record(self, spec: SandboxSpec) -> SandboxInfo:
        info = SandboxInfo(spec=spec, created_at=self._clock())
        with self._lock:
            self._sandboxes[spec.sandbox_id] = info
        return info

    def _forget(self, sandbox_id: str) -> bool:
        with self._lock:
            return self._sandboxes.pop(sandbox_id, None) is not None


class FakeExecutor(_Table):
    """In-memory executor for tests. Files live in a dict; execs are scripted.

    ``exec_handler(sandbox_id, request)`` returns the result of every exec.
    Background execs stay ``running`` until ``finish`` or ``stop_exec``.
    """

    def __init__(
        self,
        *,
        exec_handler: Callable[[str, ExecRequest], ExecResult] | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(clock)
        self.exec_handler = exec_handler or (lambda _sid, _req: ExecResult(0, b"ok\n"))
        self.files: dict[str, dict[str, tuple[bytes, int]]] = {}
        self.execs: dict[tuple[str, str], ExecStatus] = {}
        self.requests: list[tuple[str, ExecRequest]] = []
        self.deleted: list[str] = []
        # Test levers: a delete that fails, and containers the table forgot.
        self.delete_fails = False
        self.orphans: set[str] = set()
        self.orphans_stuck = False
        self.sweep_fails = False

    @property
    def network_modes(self) -> tuple[str, ...]:
        return ("internet", "deny_all")

    def import_image(self, digest: str, reference: str) -> ImageInfo:
        image = ImageInfo(digest, reference)
        with self._lock:
            self._images[digest] = image
        return image

    def create(self, spec: SandboxSpec) -> SandboxInfo:
        if self.get_image(spec.image.digest) is None:
            raise NotFound
        self.files[spec.sandbox_id] = {}
        return self._record(spec)

    def delete(self, sandbox_id: str) -> bool:
        if self.delete_fails and self.get(sandbox_id) is not None:
            raise ExecutorError("sandbox delete failed")
        self.files.pop(sandbox_id, None)
        removed = self._forget(sandbox_id)
        if removed:
            self.deleted.append(sandbox_id)
        return removed

    def sweep(self) -> int:
        if self.sweep_fails:
            raise ExecutorError("container listing failed")
        if not self.delete_fails and not self.orphans_stuck:
            self.orphans.clear()
        return len(self.orphans)

    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult:
        self._require(sandbox_id)
        self.requests.append((sandbox_id, request))
        return self.exec_handler(sandbox_id, request)

    def start_exec(self, sandbox_id: str, request: ExecRequest) -> str:
        self._require(sandbox_id)
        self.requests.append((sandbox_id, request))
        exec_id = "exec-" + secrets.token_hex(8)
        self.execs[(sandbox_id, exec_id)] = ExecStatus(exec_id, "running")
        return exec_id

    def finish(self, sandbox_id: str, exec_id: str, result: ExecResult) -> None:
        state = "timed_out" if result.timed_out else "exited"
        self.execs[(sandbox_id, exec_id)] = ExecStatus(exec_id, state, result)

    def poll_exec(self, sandbox_id: str, exec_id: str, wait_seconds: float) -> ExecStatus:
        self._require(sandbox_id)
        status = self.execs.get((sandbox_id, exec_id))
        if status is None:
            raise NotFound
        return status

    def stop_exec(self, sandbox_id: str, exec_id: str) -> ExecStatus:
        status = self.poll_exec(sandbox_id, exec_id, 0)
        if status.state == "running":
            status = ExecStatus(exec_id, "killed", ExecResult(None))
            self.execs[(sandbox_id, exec_id)] = status
        return status

    def write_file(self, sandbox_id: str, path: str, data: bytes, mode: int) -> None:
        self._require(sandbox_id)
        self.files[sandbox_id][path] = (bytes(data), mode)

    def read_file(self, sandbox_id: str, path: str) -> bytes:
        self._require(sandbox_id)
        entry = self.files[sandbox_id].get(path)
        if entry is None:
            raise NotFound
        return entry[0]

    def _is_dir(self, sandbox_id: str, path: str) -> bool:
        prefix = path.rstrip("/") + "/"
        return path == "/" or any(name.startswith(prefix) for name in self.files[sandbox_id])

    def stat(self, sandbox_id: str, path: str) -> FileStat | None:
        self._require(sandbox_id)
        entry = self.files[sandbox_id].get(path)
        if entry is not None:
            return FileStat(False, True, len(entry[0]), entry[1])
        if self._is_dir(sandbox_id, path):
            return FileStat(True, False, 0, 0o755)
        return None

    def put_tar(self, sandbox_id: str, path: str, data: bytes) -> None:
        self._require(sandbox_id)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                name = member.name.lstrip("./")
                if not name or ".." in name.split("/"):
                    raise ExecutorError("unsafe archive member")
                extracted = archive.extractfile(member)
                assert extracted is not None
                target = path.rstrip("/") + "/" + name
                self.files[sandbox_id][target] = (extracted.read(), member.mode & 0o7777)

    def get_tar(self, sandbox_id: str, path: str, excludes: Sequence[str]) -> bytes:
        self._require(sandbox_id)
        if not self._is_dir(sandbox_id, path):
            raise NotFound
        prefix = path.rstrip("/") + "/"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, (content, mode) in sorted(self.files[sandbox_id].items()):
                relative = name[len(prefix) :] if name.startswith(prefix) else None
                if relative is None or any(pattern in relative for pattern in excludes):
                    continue
                member = tarfile.TarInfo(relative)
                member.size = len(content)
                member.mode = mode
                archive.addfile(member, io.BytesIO(content))
        return buffer.getvalue()


def _check_argv(argv: Sequence[str]) -> list[str]:
    checked = list(argv)
    if not checked or any(
        not isinstance(item, str) or "\x00" in item or len(item.encode()) > MAX_ARG_BYTES
        for item in checked
    ):
        raise ExecutorError("argument is invalid")
    return checked


def _drain(stream, sink: bytearray, cap: int, flags: list[bool], index: int) -> None:  # noqa: ANN001
    while True:
        chunk = stream.read(65536)
        if not chunk:
            return
        room = cap - len(sink)
        if room > 0:
            sink.extend(chunk[:room])
        if len(chunk) > max(room, 0):
            flags[index] = True


def _feed(stream, data: bytes) -> None:  # noqa: ANN001
    try:
        stream.write(data)
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except (OSError, ValueError):
            pass


class _Job:
    """One running subprocess whose output is captured up to a cap."""

    def __init__(self, argv: list[str], cap: int, stdin: bytes | None) -> None:
        self.process = subprocess.Popen(  # noqa: S603 - argv list, no shell
            argv,
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.truncated = [False, False]
        self.killed = False
        self.timed_out = False
        self._readers = [
            threading.Thread(
                target=_drain,
                args=(self.process.stdout, self.stdout, cap, self.truncated, 0),
                daemon=True,
            ),
            threading.Thread(
                target=_drain,
                args=(self.process.stderr, self.stderr, cap, self.truncated, 1),
                daemon=True,
            ),
        ]
        if stdin is not None:
            # The upload is written from its own thread, so a target that
            # never reads (a FIFO, say) cannot hold the caller past the
            # transfer timeout: wait() times out and kill() breaks the pipe.
            self._readers.append(
                threading.Thread(target=_feed, args=(self.process.stdin, stdin), daemon=True)
            )
        for reader in self._readers:
            reader.start()

    def wait(self, timeout: float | None) -> bool:
        try:
            self.process.wait(timeout)
        except subprocess.TimeoutExpired:
            return False
        for reader in self._readers:
            reader.join(5)
        return True

    def kill(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(5)
        for reader in self._readers:
            reader.join(5)

    def result(self) -> ExecResult:
        return ExecResult(
            exit_code=None if self.timed_out or self.killed else self.process.returncode,
            stdout=bytes(self.stdout),
            stderr=bytes(self.stderr),
            timed_out=self.timed_out,
            stdout_truncated=self.truncated[0],
            stderr_truncated=self.truncated[1],
        )


@dataclass
class _JobRecord:
    """A background exec slot: reserved (no job yet), running, or finished."""

    job: _Job | None = None
    finished_at: float | None = None
    delivered_at: float | None = None
    pid_file: str | None = None

    def running(self) -> bool:
        return self.job is None or self.job.process.poll() is None

    def output_bytes(self) -> int:
        if self.job is None:
            return 0
        return len(self.job.stdout) + len(self.job.stderr)


# In-sandbox helper scripts. Paths and modes arrive as positional arguments
# ("$1", "$2"), never interpolated into the script text.
_WRITE_SCRIPT = (
    '{ test ! -e "$1" || test -f "$1"; } || exit 4; '
    'mkdir -p -- "$(dirname -- "$1")" && cat > "$1" && chmod "$2" "$1"'
)
_READ_SCRIPT = 'test -f "$1" || exit 3; exec cat -- "$1"'
_STAT_SCRIPT = 'test -e "$1" || exit 3; exec stat -c "%F|%s|%a" -- "$1"'
_PUT_TAR_SCRIPT = 'mkdir -p -- "$1" && exec tar --no-same-owner -xzf - -C "$1"'
_GET_TAR_SCRIPT = 'd="$1"; shift; test -d "$d" || exit 3; cd -- "$d" && exec tar -czf - "$@" .'
# Customer execs: record the shell's pid, then exec the command in place, so
# the recorded pid is the command's. A pid file that cannot be written does
# not stop the command.
_EXEC_WRAPPER = '{ echo "$$" > "$1"; } 2>/dev/null; shift; exec "$@"'
# Kill one exec's process tree inside the sandbox, as root. Every process
# found is stopped first so it cannot fork away; the walk repeats until no
# new descendant appears, then the whole set is killed. Pure POSIX sh, so it
# needs nothing beyond what the other helpers use.
_KILL_SCRIPT = (
    'f="$1"; test -f "$f" || exit 3; read -r root < "$f" || exit 3; '
    'case "$root" in ""|*[!0-9]*) exit 3;; esac; '
    'kill -s STOP "$root" 2>/dev/null; all=" $root "; new=1; '
    'while [ "$new" = 1 ]; do new=0; '
    'for d in /proc/[0-9]*; do p="${d#/proc/}"; '
    'case "$all" in *" $p "*) continue;; esac; '
    'pp=$(while read -r k v; do if [ "$k" = PPid: ]; then echo "$v"; break; fi; '
    'done 2>/dev/null < "$d/status"); '
    'case "$all" in *" $pp "*) kill -s STOP "$p" 2>/dev/null; all="$all$p "; new=1;; esac; '
    "done; done; "
    'kill -s KILL -- "-$root" 2>/dev/null; kill -s KILL $all 2>/dev/null; '
    'rm -f -- "$f"; exit 0'
)


class RunscExecutor(_Table):
    """Drive sandboxes through ``docker --runtime=runsc`` (gVisor, systrap).

    The Docker daemon registers the runtime with ``--platform=systrap``; see
    ``daemon_runtime_config``. Every sandbox is one container that sleeps
    until deleted, and every exec, file and archive call runs inside it,
    because gVisor's in-sandbox overlay hides writes from the host.

    ``internet`` sandboxes need live egress control: the nft ruleset from
    ``EgressPolicy.render_nft`` and a per-sandbox bandwidth cap. ``internet``
    is offered only while an ``egress_enforcer`` (``tee_box.enforce``)
    reports its table active, and a new ``internet`` sandbox is kept only
    once the enforcer reports its cap verified. Otherwise only ``deny_all``
    runs.

    With ``storage_quota`` (the default) each container gets
    ``--storage-opt size=<disk_mib>m``. The storage driver must support it
    (``storage_quota_support``); an operator who cannot must opt out.

    A customer exec records its in-sandbox pid. A timeout or a stop kills
    that process tree inside the sandbox, then the docker client.

    Every container carries the box label and its sandbox id, and has a
    deterministic name, before ``docker run`` starts. A create that fails or
    times out is removed by name, and stays pending cleanup while the daemon
    might still start it. ``sweep`` removes every box-labelled container the
    table does not track, so nothing outlives a hand-over or a restart.
    """

    def __init__(
        self,
        egress: EgressPolicy,
        *,
        docker: str = "/usr/bin/docker",
        runtime: str = "runsc",
        runtime_path: str = DEFAULT_RUNTIME_PATH,
        dns: Sequence[str] = DEFAULT_DNS,
        pids_per_sandbox: int = DEFAULT_PIDS_PER_SANDBOX,
        egress_enforcer: EgressControl | None = None,
        storage_quota: bool = True,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        clock: Callable[[], float] = time.time,
        pull_timeout: float = 1800.0,
        control_timeout: float = 120.0,
        kill_timeout: float = KILL_TIMEOUT_SECONDS,
        box_id: str = "default",
    ) -> None:
        super().__init__(clock)
        if not isinstance(egress, EgressPolicy):
            raise ValueError("RunscExecutor requires an EgressPolicy")
        if not isinstance(box_id, str) or _BOX_ID_RE.fullmatch(box_id) is None:
            raise ValueError("box id must be a short lowercase identifier")
        for name in (docker, runtime, runtime_path, *dns):
            _check_argv([name])
        if not runtime_path.startswith("/"):
            raise ValueError("the runtime path must be absolute")
        self.egress = egress
        self.docker = docker
        self.runtime = runtime
        self.runtime_path = runtime_path
        self.dns = tuple(dns)
        self.pids_per_sandbox = pids_per_sandbox
        self.egress_enforcer = egress_enforcer
        self.storage_quota = bool(storage_quota)
        self._runner = runner
        self._kill_timeout = kill_timeout
        self._pull_timeout = pull_timeout
        self._control_timeout = control_timeout
        self.box_id = box_id
        self._job_factory: Callable[[list[str], int, bytes | None], _Job] = _Job
        self._jobs: dict[tuple[str, str], _JobRecord] = {}
        self._creating: set[str] = set()
        # Container name -> time before which it stays pending even if absent.
        self._pending_cleanup: dict[str, float] = {}
        # Egress lapses already acted on, and internet sandboxes still to end
        # because the rules lapsed while they ran.
        self._seen_lapses = 0 if egress_enforcer is None else egress_enforcer.lapses
        self._lapse_cut: set[str] = set()
        self._lapse_inflight: dict[str, threading.Thread] = {}
        self._lapse_slots = threading.BoundedSemaphore(LAPSE_REMOVAL_WORKERS)
        self._lapse_call_timeout = LAPSE_REMOVAL_CALL_TIMEOUT_SECONDS
        self._ended_on_lapse = 0

    @property
    def network_modes(self) -> tuple[str, ...]:
        enforcer = self.egress_enforcer
        if enforcer is not None and enforcer.active:
            return ("internet", "deny_all")
        return ("deny_all",)

    def egress_status(self) -> dict[str, object]:
        if self.egress_enforcer is None:
            return {"enforced": False, "error": "no egress enforcer is configured"}
        status = dict(self.egress_enforcer.status())
        with self._lock:
            pending = len(self._lapse_cut)
            status["ended_on_lapse"] = self._ended_on_lapse
        status["lapse_removals_pending"] = pending
        if pending:
            status["error"] = (
                f"{pending} internet sandbox(es) could not be removed after the egress rules lapsed"
            )
        return status

    # -- argv construction (pure, unit-tested) ---------------------------

    @staticmethod
    def container_name(sandbox_id: str) -> str:
        return SANDBOX_PREFIX + sandbox_id

    def daemon_runtime_config(self) -> dict[str, object]:
        """The ``/etc/docker/daemon.json`` runtimes entry this backend expects."""

        return {
            "runtimes": {
                self.runtime: {
                    "path": self.runtime_path,
                    "runtimeArgs": ["--platform=systrap", "--network=sandbox"],
                }
            }
        }

    def pull_argv(self, image: ImageInfo) -> list[str]:
        return _check_argv([self.docker, "pull", "--quiet", f"{image.reference}@{image.digest}"])

    def create_argv(self, spec: SandboxSpec) -> list[str]:
        shape = spec.shape
        argv = [
            self.docker,
            "run",
            "--detach",
            f"--runtime={self.runtime}",
            "--name",
            self.container_name(spec.sandbox_id),
            "--label",
            f"{BOX_LABEL}={self.box_id}",
            "--label",
            f"{SANDBOX_LABEL}={spec.sandbox_id}",
            "--cpus",
            str(shape.vcpus),
            "--memory",
            f"{shape.memory_mib}m",
            "--memory-swap",
            f"{shape.memory_mib}m",
            "--pids-limit",
            str(self.pids_per_sandbox),
            "--security-opt",
            "no-new-privileges",
        ]
        if self.storage_quota:
            argv += ["--storage-opt", f"size={shape.disk_mib}m"]
        argv += [*self.egress.docker_network_args(spec.network)]
        if spec.network == "internet":
            for server in self.dns:
                argv += ["--dns", server]
        for key, value in sorted(spec.env.items()):
            argv += ["--env", f"{key}={value}"]
        argv += [
            "--entrypoint",
            "sleep",
            f"{spec.image.reference}@{spec.image.digest}",
            "infinity",
        ]
        return _check_argv(argv)

    def exec_argv(
        self,
        sandbox_id: str,
        request: ExecRequest,
        *,
        interactive: bool = False,
    ) -> list[str]:
        argv = [self.docker, "exec"]
        if interactive:
            argv.append("--interactive")
        for key, value in sorted(request.env.items()):
            argv += ["--env", f"{key}={value}"]
        if request.user is not None:
            argv += ["--user", request.user]
        if request.cwd is not None:
            argv += ["--workdir", request.cwd]
        argv.append(self.container_name(sandbox_id))
        argv += list(request.argv)
        return _check_argv(argv)

    @staticmethod
    def exec_pid_file() -> str:
        return EXEC_PID_PREFIX + secrets.token_hex(16) + ".pid"

    def tracked_exec_argv(self, sandbox_id: str, request: ExecRequest, pid_file: str) -> list[str]:
        """``exec_argv`` for a customer command that records its pid in ``pid_file``."""

        wrapped = replace(
            request,
            argv=("/bin/sh", "-c", _EXEC_WRAPPER, "cathedral-exec", pid_file, *request.argv),
        )
        return self.exec_argv(sandbox_id, wrapped)

    def kill_exec_argv(self, sandbox_id: str, pid_file: str) -> list[str]:
        return self._script(sandbox_id, _KILL_SCRIPT, pid_file, root=True)

    def info_argv(self) -> list[str]:
        return _check_argv(
            [self.docker, "info", "--format", "{{json .Driver}} {{json .DriverStatus}}"]
        )

    def runtimes_argv(self) -> list[str]:
        return _check_argv([self.docker, "info", "--format", "{{json .Runtimes}}"])

    def delete_argv(self, sandbox_id: str) -> list[str]:
        return self.remove_argv(self.container_name(sandbox_id))

    def remove_argv(self, name: str) -> list[str]:
        return _check_argv([self.docker, "rm", "--force", name])

    def kill_argv(self, name: str) -> list[str]:
        return _check_argv([self.docker, "kill", "--signal", "KILL", name])

    def inspect_argv(self, name: str) -> list[str]:
        return _check_argv([self.docker, "container", "inspect", "--format", "{{.Id}}", name])

    def list_argv(self) -> list[str]:
        return _check_argv(
            [
                self.docker,
                "ps",
                "--all",
                "--filter",
                f"label={BOX_LABEL}={self.box_id}",
                "--format",
                "{{.Names}}",
            ]
        )

    def _script(
        self, sandbox_id: str, script: str, *args: str, stdin: bool = False, root: bool = False
    ) -> list[str]:
        request = ExecRequest(
            ("/bin/sh", "-c", script, "cathedral-sandbox", *args),
            timeout_seconds=1,
            user="0" if root else None,
        )
        return self.exec_argv(sandbox_id, request, interactive=stdin)

    # -- running ---------------------------------------------------------

    def _run(
        self,
        argv: list[str],
        *,
        timeout: float,
        stdin: bytes | None = None,
        cap: int = MAX_OUTPUT_BYTES,
    ) -> ExecResult:
        job = _Job(argv, cap, stdin)
        if not job.wait(timeout):
            job.timed_out = True
            job.kill()
        return job.result()

    def _control(self, argv: list[str], timeout: float) -> subprocess.CompletedProcess:
        try:
            return self._runner(
                argv, capture_output=True, timeout=timeout, check=False, shell=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ExecutorError("container runtime call failed") from exc

    def runtime_check(self) -> tuple[bool, str]:
        """Whether the daemon registers ``runtime`` at ``runtime_path`` with systrap."""

        try:
            result = self._control(self.runtimes_argv(), self._control_timeout)
        except ExecutorError:
            return False, "docker info failed"
        if result.returncode != 0:
            return False, "docker info failed"
        try:
            runtimes = json.loads(result.stdout or b"")
            entry = runtimes.get(self.runtime)
        except (AttributeError, UnicodeDecodeError, ValueError):
            return False, "docker info output is invalid"
        if not isinstance(entry, dict):
            return False, f"the docker daemon has no {self.runtime} runtime"
        if entry.get("path") != self.runtime_path:
            return False, f"the {self.runtime} runtime is not {self.runtime_path}"
        if "--platform=systrap" not in (entry.get("runtimeArgs") or []):
            return False, f"the {self.runtime} runtime does not use --platform=systrap"
        return True, f"{self.runtime} at {self.runtime_path} with systrap"

    def storage_quota_support(self) -> tuple[bool, str]:
        """Whether the daemon's storage driver honours ``--storage-opt size=``.

        overlay2 needs an xfs backing filesystem, and docker then also needs
        the pquota mount option, which it checks only when a container starts:
        a create on xfs without pquota fails rather than running unbounded.
        """

        try:
            result = self._control(self.info_argv(), self._control_timeout)
        except ExecutorError:
            return False, "docker info failed"
        if result.returncode != 0:
            return False, "docker info failed"
        try:
            driver_text, _, status_text = (result.stdout or b"").decode().strip().partition(" ")
            driver = json.loads(driver_text)
            status = dict(json.loads(status_text) or [])
        except (UnicodeDecodeError, ValueError, TypeError):
            return False, "docker info output is invalid"
        if driver in QUOTA_DRIVERS:
            return True, f"storage driver {driver}"
        if driver == "overlay2" and status.get("Backing Filesystem") == "xfs":
            return True, "overlay2 on xfs (needs the pquota mount option)"
        return False, f"storage driver {driver!s:.64} does not support per-container size"

    def import_image(self, digest: str, reference: str) -> ImageInfo:
        image = ImageInfo(digest, reference)
        if self._control(self.pull_argv(image), self._pull_timeout).returncode != 0:
            raise ExecutorError("image pull failed")
        with self._lock:
            self._images[digest] = image
        return image

    def _exists(self, name: str, timeout: float | None = None) -> bool:
        """False only when the daemon says the container does not exist."""

        try:
            result = self._control(self.inspect_argv(name), timeout or self._control_timeout)
        except ExecutorError:
            return True
        return result.returncode == 0 or b"No such" not in (result.stderr or b"")

    def _remove(self, name: str, timeout: float | None = None) -> bool:
        """Force-remove ``name``; true once it is confirmed gone.

        At most four docker calls, each bounded by ``timeout`` (default: the
        control timeout).
        """

        for argv in (self.remove_argv(name), self.kill_argv(name), self.remove_argv(name)):
            try:
                result = self._control(argv, timeout or self._control_timeout)
            except ExecutorError:
                continue
            if argv[1] == "rm" and result.returncode == 0:
                return True
        return not self._exists(name, timeout)

    def _abandon(self, name: str, *, timed_out: bool) -> bool:
        """Remove a container whose create failed; keep it pending if unsure."""

        removed = self._remove(name)
        if timed_out or not removed:
            grace = PENDING_CLEANUP_GRACE_SECONDS if timed_out else 0.0
            with self._lock:
                self._pending_cleanup[name] = self._clock() + grace
        return removed

    def create(self, spec: SandboxSpec) -> SandboxInfo:
        enforcer = self.egress_enforcer
        lapses = None if enforcer is None else enforcer.lapses
        if spec.network == "internet" and (enforcer is None or not enforcer.verify()):
            self.end_lapsed_sandboxes()
            raise ExecutorRefused("internet egress is not enforced on this box")
        if self.get_image(spec.image.digest) is None:
            raise NotFound
        name = self.container_name(spec.sandbox_id)
        argv = self.create_argv(spec)
        with self._lock:
            self._creating.add(spec.sandbox_id)
        try:
            try:
                started = self._control(argv, self._control_timeout).returncode == 0
                timed_out = False
            except ExecutorError:
                started, timed_out = False, True
            if not started:
                self._abandon(name, timed_out=timed_out)
                raise ExecutorError("sandbox start failed")
            if spec.network == "internet":
                assert enforcer is not None
                try:
                    enforcer.attach(name)
                    enforced = enforcer.is_enforced(name)
                except Exception:
                    enforced = False
                if not enforced:
                    # The cap goes only once the container is gone; a container
                    # left pending is removed, then detached, by the sweep.
                    if self._abandon(name, timed_out=False):
                        self._detach(name)
                    # attach's own read-back may have found a lapse.
                    self.end_lapsed_sandboxes()
                    raise ExecutorError("egress enforcement failed")
            info = self._record(spec)
            if spec.network == "internet" and enforcer is not None and enforcer.lapses != lapses:
                # The rules lapsed while this sandbox started: end it too.
                with self._lock:
                    self._lapse_cut.add(spec.sandbox_id)
                self.end_lapsed_sandboxes()
                raise ExecutorError("egress enforcement failed")
            return info
        finally:
            with self._lock:
                self._creating.discard(spec.sandbox_id)

    def delete(self, sandbox_id: str) -> bool:
        return self._delete(sandbox_id, None)

    def _delete(self, sandbox_id: str, timeout: float | None) -> bool:
        with self._lock:
            keys = [key for key in self._jobs if key[0] == sandbox_id]
            stale = [self._jobs.pop(key) for key in keys]
        for record in stale:
            if record.job is not None:
                record.job.killed = True
                record.job.kill()
        if self.get(sandbox_id) is None:
            return False
        name = self.container_name(sandbox_id)
        # The cap stays until the container is confirmed gone: a failed
        # remove leaves a running sandbox that must stay capped.
        if not self._remove(name, timeout):
            raise ExecutorError("sandbox delete failed")
        self._detach(name)
        with self._lock:
            self._lapse_cut.discard(sandbox_id)
        return self._forget(sandbox_id)

    def check_egress(self) -> int:
        """Re-check the egress table and end lapsed sandboxes (the egress thread).

        Runs apart from the docker-bound reaper, so the nft read-back is never
        queued behind slow deletes. Returns how many lapse removals remain.
        """

        enforcer = self.egress_enforcer
        if enforcer is None:
            return 0
        # A lapse may already be recorded (a create's attach or verify found
        # it): mark and cut those sandboxes before any re-apply waits on docker.
        self.end_lapsed_sandboxes()
        try:
            enforcer.maintain(on_lapse=self.end_lapsed_sandboxes)
        except Exception:
            pass
        return self.end_lapsed_sandboxes()

    def end_lapsed_sandboxes(self, *, wait: bool = False) -> int:
        """End every ``internet`` sandbox that ran while the egress rules lapsed.

        When the enforcer reports a new lapse (its table failed a read-back),
        every ``internet`` sandbox running at that moment is removed, as a
        delete would, rather than disconnected: removal does not depend on how
        runsc treats a vanished interface. Re-applying the table does not bring
        them back. Until its removal succeeds, every call on such a sandbox is
        refused (``NetworkLapsed``).

        While any is waiting, the enforcer's quarantine table drops all
        traffic on the sandbox bridge (one nft call, no docker), so a lapsed
        sandbox loses its network before its container is removed; the
        quarantine is lifted once none is left, and ``internet`` creates are
        refused until then.

        Removals run on their own threads, at most ``LAPSE_REMOVAL_WORKERS``
        at once, each docker call bounded by the lapse call timeout, so one
        slow removal does not hold up the others or the caller. A failed
        removal is retried on the next call. Returns how many are still
        waiting; ``wait`` joins this call's removals first (tests).
        """

        enforcer = self.egress_enforcer
        if enforcer is None:
            return 0
        started: list[threading.Thread] = []
        joined: list[threading.Thread] = []
        with self._lock:
            lapses = enforcer.lapses
            if lapses != self._seen_lapses:
                self._seen_lapses = lapses
                self._lapse_cut.update(
                    sid for sid, info in self._sandboxes.items() if info.spec.network == "internet"
                )
            waiting = bool(self._lapse_cut or self._lapse_inflight)
        # Cut the bridge off while any lapsed sandbox still runs (re-applied
        # each call, in case it was flushed too), and lift the cut once none is
        # left.
        try:
            if waiting:
                enforcer.quarantine()
            elif enforcer.quarantined:
                enforcer.lift_quarantine()
        except Exception:
            pass
        with self._lock:
            for sandbox_id in sorted(self._lapse_cut):
                thread = self._lapse_inflight.get(sandbox_id)
                if thread is None:
                    thread = threading.Thread(
                        target=self._end_lapsed_one, args=(sandbox_id,), daemon=True
                    )
                    self._lapse_inflight[sandbox_id] = thread
                    started.append(thread)
                joined.append(thread)
        for thread in started:
            thread.start()
        if wait:
            for thread in joined:
                thread.join(4 * self._lapse_call_timeout + 5)
        with self._lock:
            return len(self._lapse_cut)

    def _end_lapsed_one(self, sandbox_id: str) -> None:
        ended = None
        with self._lapse_slots:
            try:
                ended = self._delete(sandbox_id, self._lapse_call_timeout)
            except ExecutorError:
                pass
            except Exception:
                pass
        with self._lock:
            self._lapse_inflight.pop(sandbox_id, None)
            if ended is not None:
                self._lapse_cut.discard(sandbox_id)
                self._ended_on_lapse += int(ended)

    def _require(self, sandbox_id: str) -> SandboxInfo:
        info = super()._require(sandbox_id)
        with self._lock:
            lapsed = sandbox_id in self._lapse_cut
        if lapsed:
            raise NetworkLapsed("the sandbox ran while egress rules lapsed and is being removed")
        return info

    def set_expiry(self, sandbox_id: str, expires_at: float) -> SandboxInfo:
        self._require(sandbox_id)
        return super().set_expiry(sandbox_id, expires_at)

    def _detach(self, name: str) -> None:
        """Drop the sandbox's tc cap, once its container is gone."""

        if self.egress_enforcer is not None:
            try:
                self.egress_enforcer.detach(name)
            except Exception:
                pass

    def sweep(self) -> int:
        """Remove box-labelled containers the table does not track.

        Returns how many untracked containers may still exist: ones whose
        removal failed, and names from a timed-out create still in their
        grace window. Raises ``ExecutorError`` if the daemon cannot list.
        """

        result = self._control(self.list_argv(), self._control_timeout)
        if result.returncode != 0:
            raise ExecutorError("container listing failed")
        listed = {
            line.strip()
            for line in (result.stdout or b"").decode("utf-8", "replace").splitlines()
            if _CONTAINER_NAME_RE.fullmatch(line.strip())
        }
        with self._lock:
            keep = {self.container_name(sid) for sid in (*self._sandboxes, *self._creating)}
            pending = dict(self._pending_cleanup)
        remaining = 0
        now = self._clock()
        for name in sorted((listed | set(pending)) - keep):
            gone = self._remove(name) if name in listed else not self._exists(name)
            if gone:
                self._detach(name)
            if gone and now >= pending.get(name, 0.0):
                with self._lock:
                    self._pending_cleanup.pop(name, None)
            else:
                remaining += 1
        return remaining

    def _kill_in_sandbox(self, sandbox_id: str, pid_file: str | None) -> bool:
        """Kill an exec's process tree inside the sandbox; true when the kill ran."""

        if pid_file is None:
            return False
        try:
            argv = self.kill_exec_argv(sandbox_id, pid_file)
            return self._control(argv, self._kill_timeout).returncode == 0
        except ExecutorError:
            return False

    def _end(self, job: _Job, sandbox_id: str, pid_file: str | None) -> None:
        """Kill inside the sandbox first, so the client can exit with its output."""

        self._kill_in_sandbox(sandbox_id, pid_file)
        job.wait(2)
        job.kill()

    def _start_job(self, argv: list[str]) -> _Job:
        try:
            return self._job_factory(argv, MAX_OUTPUT_BYTES, None)
        except OSError as exc:
            raise ExecutorError("exec start failed") from exc

    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult:
        self._require(sandbox_id)
        pid_file = self.exec_pid_file()
        job = self._start_job(self.tracked_exec_argv(sandbox_id, request, pid_file))
        if not job.wait(request.timeout_seconds):
            job.timed_out = True
            self._end(job, sandbox_id, pid_file)
        return job.result()

    def _prune_jobs_locked(self, now: float) -> None:
        for key, record in list(self._jobs.items()):
            if record.running():
                continue
            if record.finished_at is None:
                record.finished_at = now
            read = record.delivered_at
            if (read is not None and now - read >= DELIVERED_RETENTION_SECONDS) or (
                now - record.finished_at >= FINISHED_RETENTION_SECONDS
            ):
                del self._jobs[key]

    def _make_room_locked(self, sandbox_id: str, now: float) -> None:
        """Evict finished records, oldest read ones first, until both caps allow one more."""

        self._prune_jobs_locked(now)
        for scope, cap in ((sandbox_id, MAX_JOBS_PER_SANDBOX), (None, MAX_JOBS_PER_BOX)):
            while True:
                keys = [key for key in self._jobs if scope is None or key[0] == scope]
                if len(keys) < cap:
                    break
                finished = [key for key in keys if not self._jobs[key].running()]
                if not finished:
                    raise ExecutorRefused("too many background execs")
                oldest = min(
                    finished,
                    key=lambda key: (
                        self._jobs[key].delivered_at is None,
                        self._jobs[key].finished_at or now,
                    ),
                )
                del self._jobs[oldest]

    def retained_output_bytes(self) -> int:
        with self._lock:
            return sum(record.output_bytes() for record in self._jobs.values())

    def start_exec(self, sandbox_id: str, request: ExecRequest) -> str:
        self._require(sandbox_id)
        pid_file = self.exec_pid_file()
        argv = self.tracked_exec_argv(sandbox_id, request, pid_file)
        exec_id = "exec-" + secrets.token_hex(8)
        key = (sandbox_id, exec_id)
        record = _JobRecord(pid_file=pid_file)
        # The cap check and the slot reservation are one atomic step.
        with self._lock:
            self._make_room_locked(sandbox_id, self._clock())
            self._jobs[key] = record
        try:
            job = self._start_job(argv)
        except ExecutorError:
            with self._lock:
                self._jobs.pop(key, None)
            raise
        with self._lock:
            record.job = job
            orphaned = self._jobs.get(key) is not record
        if orphaned:  # the sandbox was deleted while the exec started
            job.killed = True
            job.kill()
            raise NotFound
        deadline = self._clock() + request.timeout_seconds

        def watchdog() -> None:
            if not job.wait(max(0.0, deadline - self._clock())):
                job.timed_out = True
                self._end(job, sandbox_id, pid_file)
            with self._lock:
                if record.finished_at is None:
                    record.finished_at = self._clock()

        threading.Thread(target=watchdog, daemon=True).start()
        return exec_id

    def _status(self, exec_id: str, record: "_JobRecord") -> ExecStatus:
        job = record.job
        if job is None or job.process.poll() is None:
            return ExecStatus(exec_id, "running")
        state = "killed" if job.killed else "timed_out" if job.timed_out else "exited"
        with self._lock:
            now = self._clock()
            if record.finished_at is None:
                record.finished_at = now
            if record.delivered_at is None:
                record.delivered_at = now
        return ExecStatus(exec_id, state, job.result())

    def _record_for(self, sandbox_id: str, exec_id: str) -> "_JobRecord":
        self._require(sandbox_id)
        with self._lock:
            self._prune_jobs_locked(self._clock())
            record = self._jobs.get((sandbox_id, exec_id))
        if record is None:
            raise NotFound
        return record

    def poll_exec(self, sandbox_id: str, exec_id: str, wait_seconds: float) -> ExecStatus:
        record = self._record_for(sandbox_id, exec_id)
        if wait_seconds > 0 and record.job is not None:
            record.job.wait(wait_seconds)
        return self._status(exec_id, record)

    def stop_exec(self, sandbox_id: str, exec_id: str) -> ExecStatus:
        record = self._record_for(sandbox_id, exec_id)
        job = record.job
        if job is not None and job.process.poll() is None:
            job.killed = True
            self._end(job, sandbox_id, record.pid_file)
        return self._status(exec_id, record)

    def write_file(self, sandbox_id: str, path: str, data: bytes, mode: int) -> None:
        self._require(sandbox_id)
        argv = self._script(
            sandbox_id, _WRITE_SCRIPT, path, format(mode, "o"), stdin=True, root=True
        )
        result = self._run(argv, timeout=self._control_timeout, stdin=data)
        if result.exit_code == 4:
            raise ExecutorRefused("the target exists and is not a regular file")
        if result.exit_code != 0:
            raise ExecutorError("file write failed")

    def read_file(self, sandbox_id: str, path: str) -> bytes:
        self._require(sandbox_id)
        result = self._run(
            self._script(sandbox_id, _READ_SCRIPT, path, root=True),
            timeout=self._control_timeout,
            cap=MAX_FILE_BYTES,
        )
        return self._transfer(result)

    def stat(self, sandbox_id: str, path: str) -> FileStat | None:
        self._require(sandbox_id)
        result = self._run(
            self._script(sandbox_id, _STAT_SCRIPT, path, root=True),
            timeout=self._control_timeout,
            cap=4096,
        )
        if result.exit_code == 3:
            return None
        if result.exit_code != 0:
            raise ExecutorError("stat failed")
        try:
            kind, size, mode = result.stdout.decode().strip().split("|")
            return FileStat(
                kind == "directory", kind.startswith("regular"), int(size), int(mode, 8)
            )
        except ValueError as exc:
            raise ExecutorError("stat output is invalid") from exc

    def put_tar(self, sandbox_id: str, path: str, data: bytes) -> None:
        self._require(sandbox_id)
        argv = self._script(sandbox_id, _PUT_TAR_SCRIPT, path, stdin=True, root=True)
        if self._run(argv, timeout=self._control_timeout, stdin=data).exit_code != 0:
            raise ExecutorError("tar_extract_failed")

    def get_tar(self, sandbox_id: str, path: str, excludes: Sequence[str]) -> bytes:
        self._require(sandbox_id)
        options = [f"--exclude={pattern}" for pattern in excludes]
        result = self._run(
            self._script(sandbox_id, _GET_TAR_SCRIPT, path, *options, root=True),
            timeout=self._control_timeout,
            cap=MAX_FILE_BYTES,
        )
        return self._transfer(result)

    @staticmethod
    def _transfer(result: ExecResult) -> bytes:
        if result.exit_code == 3:
            raise NotFound
        if result.stdout_truncated:
            raise TooLarge
        if result.exit_code != 0:
            raise ExecutorError("transfer failed")
        return result.stdout
