"""Sandbox executors for the TEE box: the protocol, a fake, and a runsc backend.

The service validates every caller value before it reaches an executor.
``RunscExecutor`` still builds only argv lists (never a shell on the host),
bounds every argument and every captured output, and is used only when an
operator configures it.
"""

from __future__ import annotations

import io
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
MAX_BACKGROUND_EXECS = 64
SANDBOX_PREFIX = "cathsbx-"
DEFAULT_DNS: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
DEFAULT_PIDS_PER_SANDBOX = 4096


class ExecutorError(Exception):
    """The executor could not do what was asked."""


class ExecutorRefused(ExecutorError):
    """The executor refuses this request on this box (for example, no egress control)."""


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
        self.files.pop(sandbox_id, None)
        removed = self._forget(sandbox_id)
        if removed:
            self.deleted.append(sandbox_id)
        return removed

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
        for reader in self._readers:
            reader.start()
        if stdin is not None:
            try:
                assert self.process.stdin is not None
                self.process.stdin.write(stdin)
            except OSError:
                pass
            finally:
                try:
                    self.process.stdin.close()
                except OSError:
                    pass

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


# In-sandbox helper scripts. Paths and modes arrive as positional arguments
# ("$1", "$2"), never interpolated into the script text.
_WRITE_SCRIPT = 'mkdir -p -- "$(dirname -- "$1")" && cat > "$1" && chmod "$2" "$1"'
_READ_SCRIPT = 'test -f "$1" || exit 3; exec cat -- "$1"'
_STAT_SCRIPT = 'test -e "$1" || exit 3; exec stat -c "%F|%s|%a" -- "$1"'
_PUT_TAR_SCRIPT = 'mkdir -p -- "$1" && exec tar --no-same-owner -xzf - -C "$1"'
_GET_TAR_SCRIPT = 'd="$1"; shift; test -d "$d" || exit 3; cd -- "$d" && exec tar -czf - "$@" .'


class RunscExecutor(_Table):
    """Drive sandboxes through ``docker --runtime=runsc`` (gVisor, systrap).

    The Docker daemon registers the runtime with ``--platform=systrap``; see
    ``daemon_runtime_config``. Every sandbox is one container that sleeps
    until deleted, and every exec, file and archive call runs inside it,
    because gVisor's in-sandbox overlay hides writes from the host.

    ``internet`` sandboxes need live egress control: the nft ruleset from
    ``EgressPolicy.render_nft`` and a per-sandbox bandwidth cap. Until an
    ``egress_enforcer`` is supplied that applies both for a new container,
    ``internet`` is refused and only ``deny_all`` runs.
    """

    def __init__(
        self,
        egress: EgressPolicy,
        *,
        docker: str = "/usr/bin/docker",
        runtime: str = "runsc",
        dns: Sequence[str] = DEFAULT_DNS,
        pids_per_sandbox: int = DEFAULT_PIDS_PER_SANDBOX,
        egress_enforcer: Callable[[str, EgressPolicy], None] | None = None,
        runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        clock: Callable[[], float] = time.time,
        pull_timeout: float = 1800.0,
        control_timeout: float = 120.0,
    ) -> None:
        super().__init__(clock)
        if not isinstance(egress, EgressPolicy):
            raise ValueError("RunscExecutor requires an EgressPolicy")
        for name in (docker, runtime, *dns):
            _check_argv([name])
        self.egress = egress
        self.docker = docker
        self.runtime = runtime
        self.dns = tuple(dns)
        self.pids_per_sandbox = pids_per_sandbox
        self.egress_enforcer = egress_enforcer
        self._runner = runner
        self._pull_timeout = pull_timeout
        self._control_timeout = control_timeout
        self._jobs: dict[tuple[str, str], _Job] = {}

    @property
    def network_modes(self) -> tuple[str, ...]:
        return ("internet", "deny_all") if self.egress_enforcer is not None else ("deny_all",)

    # -- argv construction (pure, unit-tested) ---------------------------

    @staticmethod
    def container_name(sandbox_id: str) -> str:
        return SANDBOX_PREFIX + sandbox_id

    def daemon_runtime_config(self) -> dict[str, object]:
        """The ``/etc/docker/daemon.json`` runtimes entry this backend expects."""

        return {
            "runtimes": {
                self.runtime: {
                    "path": "/usr/local/bin/runsc",
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
            f"org.cathedral.tee-box.sandbox={spec.sandbox_id}",
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
            *self.egress.docker_network_args(spec.network),
        ]
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

    def delete_argv(self, sandbox_id: str) -> list[str]:
        return _check_argv([self.docker, "rm", "--force", self.container_name(sandbox_id)])

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

    def import_image(self, digest: str, reference: str) -> ImageInfo:
        image = ImageInfo(digest, reference)
        if self._control(self.pull_argv(image), self._pull_timeout).returncode != 0:
            raise ExecutorError("image pull failed")
        with self._lock:
            self._images[digest] = image
        return image

    def create(self, spec: SandboxSpec) -> SandboxInfo:
        if spec.network == "internet" and self.egress_enforcer is None:
            raise ExecutorRefused("internet egress is not enforced on this box yet")
        if self.get_image(spec.image.digest) is None:
            raise NotFound
        if self._control(self.create_argv(spec), self._control_timeout).returncode != 0:
            raise ExecutorError("sandbox start failed")
        if spec.network == "internet":
            assert self.egress_enforcer is not None
            try:
                self.egress_enforcer(self.container_name(spec.sandbox_id), self.egress)
            except Exception as exc:
                self._control(self.delete_argv(spec.sandbox_id), self._control_timeout)
                raise ExecutorError("egress enforcement failed") from exc
        return self._record(spec)

    def delete(self, sandbox_id: str) -> bool:
        with self._lock:
            jobs = [key for key in self._jobs if key[0] == sandbox_id]
            stale = [self._jobs.pop(key) for key in jobs]
        for job in stale:
            job.killed = True
            job.kill()
        if self.get(sandbox_id) is None:
            return False
        result = self._control(self.delete_argv(sandbox_id), self._control_timeout)
        if result.returncode != 0:
            raise ExecutorError("sandbox delete failed")
        return self._forget(sandbox_id)

    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult:
        self._require(sandbox_id)
        # TODO(T6b): a timed-out docker exec client is killed, but the process
        # inside gVisor runs on until the sandbox is deleted. Use runsc exec
        # with a pid file and runsc kill instead.
        return self._run(self.exec_argv(sandbox_id, request), timeout=request.timeout_seconds)

    def start_exec(self, sandbox_id: str, request: ExecRequest) -> str:
        self._require(sandbox_id)
        with self._lock:
            running = sum(1 for job in self._jobs.values() if job.process.poll() is None)
            if running >= MAX_BACKGROUND_EXECS:
                raise ExecutorRefused("too many background execs")
        exec_id = "exec-" + secrets.token_hex(8)
        job = _Job(self.exec_argv(sandbox_id, request), MAX_OUTPUT_BYTES, None)
        deadline = self._clock() + request.timeout_seconds

        def watchdog() -> None:
            if not job.wait(max(0.0, deadline - self._clock())):
                job.timed_out = True
                job.kill()

        threading.Thread(target=watchdog, daemon=True).start()
        with self._lock:
            self._jobs[(sandbox_id, exec_id)] = job
        return exec_id

    def _status(self, exec_id: str, job: _Job) -> ExecStatus:
        if job.process.poll() is None:
            return ExecStatus(exec_id, "running")
        state = "killed" if job.killed else "timed_out" if job.timed_out else "exited"
        return ExecStatus(exec_id, state, job.result())

    def poll_exec(self, sandbox_id: str, exec_id: str, wait_seconds: float) -> ExecStatus:
        with self._lock:
            job = self._jobs.get((sandbox_id, exec_id))
        if job is None:
            raise NotFound
        if wait_seconds > 0:
            job.wait(wait_seconds)
        return self._status(exec_id, job)

    def stop_exec(self, sandbox_id: str, exec_id: str) -> ExecStatus:
        with self._lock:
            job = self._jobs.get((sandbox_id, exec_id))
        if job is None:
            raise NotFound
        if job.process.poll() is None:
            job.killed = True
            job.kill()
        return self._status(exec_id, job)

    def write_file(self, sandbox_id: str, path: str, data: bytes, mode: int) -> None:
        self._require(sandbox_id)
        argv = self._script(
            sandbox_id, _WRITE_SCRIPT, path, format(mode, "o"), stdin=True, root=True
        )
        if self._run(argv, timeout=self._control_timeout, stdin=data).exit_code != 0:
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
