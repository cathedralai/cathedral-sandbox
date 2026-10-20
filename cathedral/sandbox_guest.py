"""Linux guest sandboxes for customer Sandbox / Image / DinD definitions.

The customer checklist defines a sandbox as an isolated Linux container or
micro-VM with its own filesystem, network and process tree, started from an OCI
image (or Dockerfile), with optional Docker-in-Docker for compose tasks.

This module talks to a real Docker daemon only. There is no fake client, no stub
guest, and no path that pretends Kata or DinD when they are absent.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from cathedral.sandbox_api import (
    CreateSandboxRequest,
    ExecRecord,
    ExecRequest,
    ExecResult,
    FileGet,
    NetworkPatch,
    PrefetchRequest,
    ProcessHandle,
    SandboxContractError,
    StatusReport,
    TarGet,
)
from cathedral.sandbox_provider import (
    InMemorySandboxProvider,
    SandboxOpError,
    _parse_label_filters,
    _render_cmd,
    provider_from_environment,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def docker_cli_available() -> bool:
    return shutil.which("docker") is not None


def docker_daemon_ready(*, timeout_seconds: float = 2.0) -> bool:
    if not docker_cli_available():
        return False
    try:
        completed = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0 and bool(completed.stdout.strip())


# Docker labels on every guest container. The reconcile pass uses them to find
# containers that have no live sandbox record.
LABEL_OWNER = "cathedral.sandbox.owner"
LABEL_SANDBOX_ID = "cathedral.sandbox.id"


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(int(raw), minimum)
    except ValueError:
        return default


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return max(float(raw), minimum)
    except ValueError:
        return default


DIND_DOCKERD_ARGS_DEFAULT = (
    "--host=unix:///var/run/docker.sock",
    "--default-address-pool",
    "base=172.28.0.0/16,size=24",
)


@dataclass(frozen=True)
class DindConfig:
    """Operator settings for Docker-in-Docker guests.

    CATHEDRAL_DIND_RUNTIME: OCI runtime for DinD guests (for example
    runsc-netraw, a runsc entry with --net-raw). Not used with Kata.
    CATHEDRAL_DIND_DOCKERD_ARGS: inner dockerd arguments (shell words). They
    replace the default arguments.
    CATHEDRAL_DIND_ENV: extra guest environment as shell words of KEY=VALUE.
    """

    runtime: str | None = None
    dockerd_args: tuple[str, ...] = DIND_DOCKERD_ARGS_DEFAULT
    env: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_env(cls) -> "DindConfig":
        raw_args = os.environ.get("CATHEDRAL_DIND_DOCKERD_ARGS", "").strip()
        env: list[tuple[str, str]] = []
        for word in shlex.split(os.environ.get("CATHEDRAL_DIND_ENV", "")):
            key, sep, value = word.partition("=")
            if not sep or not key:
                raise ValueError(f"CATHEDRAL_DIND_ENV entry is not KEY=VALUE: {word!r}")
            env.append((key, value))
        return cls(
            runtime=os.environ.get("CATHEDRAL_DIND_RUNTIME", "").strip() or None,
            dockerd_args=tuple(shlex.split(raw_args)) if raw_args else DIND_DOCKERD_ARGS_DEFAULT,
            env=tuple(env),
        )


def runtime_has_kernel_isolation(runtime: str) -> bool:
    """True for OCI runtimes that put a separate kernel under the guest.

    runsc (gVisor) runs a user-space kernel; Kata runs a micro-VM. runc shares
    the host kernel.
    """
    name = runtime.strip().lower()
    return name.startswith("runsc") or "kata" in name


def is_dind_image(image: str) -> bool:
    """True when the image is a Docker-in-Docker base used for compose tasks."""
    lowered = image.lower()
    return "docker:" in lowered and "dind" in lowered


@dataclass
class GuestRecord:
    sandbox_id: str
    container_id: str
    image: str
    dind: bool
    work_mount: Path
    network_mode: str = "public"
    guest_processes: dict[str, Path] = field(default_factory=dict)


class DockerClient:
    """Real docker CLI only — every call hits the local daemon."""

    def __init__(self, *, kata_runtime: str | None = None) -> None:
        self.kata_runtime = kata_runtime or os.environ.get("CATHEDRAL_KATA_RUNTIME", "kata-runtime")
        # Optional OCI runtime for non-Kata guests (for example runsc). Empty means
        # the daemon default runtime.
        self.guest_runtime = os.environ.get("CATHEDRAL_DOCKER_RUNTIME", "").strip() or None
        self.dind = DindConfig.from_env()

    def default_runtime(self) -> str:
        """The daemon's default OCI runtime name, or "" when unknown."""
        try:
            result = self.run(["docker", "info", "--format", "{{.DefaultRuntime}}"], timeout=15.0)
        except SandboxOpError:
            return ""
        return result.stdout.strip() if result.returncode == 0 else ""

    def run(
        self,
        argv: list[str],
        *,
        timeout: float | None = 120.0,
        input_bytes: bytes | None = None,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        merged = None if env is None else {**os.environ, **dict(env)}
        try:
            return subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=(None if input_bytes is None else input_bytes.decode("utf-8", "replace")),
                check=False,
                env=merged,
            )
        except FileNotFoundError as exc:
            raise SandboxOpError(
                "runtime_unavailable",
                503,
                "docker CLI not found on PATH",
                retry_after=30,
            ) from exc
        except OSError as exc:
            raise SandboxOpError(
                "runtime_unavailable",
                503,
                f"docker could not be executed: {exc}",
                retry_after=30,
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise SandboxOpError(
                "docker_timeout", 504, f"docker timed out: {' '.join(argv[:4])}"
            ) from exc

    def info_ok(self) -> bool:
        try:
            result = self.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                timeout=15.0,
            )
        except SandboxOpError:
            return False
        return result.returncode == 0 and bool(result.stdout.strip())

    def pull(self, image: str, *, registry_auth: Mapping[str, str] | None = None) -> None:
        env: dict[str, str] | None = None
        config_dir: Path | None = None
        if registry_auth is not None:
            config_dir = Path(tempfile.mkdtemp(prefix="cathedral-docker-auth-"))
            config_dir.joinpath("config.json").write_text(
                json.dumps(
                    {
                        "auths": {
                            _registry_host(image): {
                                "username": registry_auth["username"],
                                "password": registry_auth["password"],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            env = {"DOCKER_CONFIG": str(config_dir)}
        try:
            result = self.run(["docker", "pull", image], timeout=600.0, env=env)
            if result.returncode != 0:
                raise SandboxOpError(
                    "image_pull_failed",
                    502,
                    f"docker pull failed for {image}: {result.stderr.strip()[:300]}",
                )
        finally:
            if config_dir is not None:
                shutil.rmtree(config_dir, ignore_errors=True)

    def ensure_image(
        self,
        image: str,
        *,
        registry_auth: Mapping[str, str] | None = None,
        refresh: bool = False,
        mirror: str | None = None,
    ) -> bool:
        """Make *image* present locally. Return True when a pull ran.

        Skip the pull when the image is already present, unless *refresh* is set.
        With *mirror* set, a Docker Hub image is pulled from the mirror first and
        tagged with its original name; on mirror failure the pull goes direct.
        """
        if not refresh and self.image_exists(image):
            return False
        mirrored = mirror_ref(mirror, image) if mirror and registry_auth is None else None
        if mirrored is not None:
            try:
                self.pull(mirrored)
                tagged = self.run(["docker", "tag", mirrored, image], timeout=30.0)
                if tagged.returncode == 0:
                    return True
            except SandboxOpError:
                pass
        self.pull(image, registry_auth=registry_auth)
        return True

    def image_inspect(self, image: str) -> dict[str, Any]:
        result = self.run(
            ["docker", "image", "inspect", "--format", "{{json .}}", image],
            timeout=30.0,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        try:
            return json.loads(result.stdout.strip().splitlines()[-1])
        except json.JSONDecodeError:
            return {}

    def build(self, *, tag: str, context_dir: Path, dockerfile_name: str = "Dockerfile") -> None:
        result = self.run(
            ["docker", "build", "-t", tag, "-f", str(context_dir / dockerfile_name), str(context_dir)],
            timeout=900.0,
        )
        if result.returncode != 0:
            raise SandboxOpError(
                "image_build_failed",
                502,
                f"docker build failed: {result.stderr.strip()[:400]}",
            )

    def image_exists(self, tag: str) -> bool:
        result = self.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", tag],
            timeout=15.0,
        )
        return result.returncode == 0 and bool(result.stdout.strip())

    def create_and_start(
        self,
        *,
        image: str,
        name: str,
        work_dir: Path,
        vcpu: int,
        memory_gib: int,
        disk_gib: int,
        network_mode: str,
        env: Mapping[str, str],
        dind: bool,
        use_kata: bool,
        entrypoint: tuple[str, ...] | None,
        workdir: str | None,
        user: str | None,
        labels: Mapping[str, str] | None = None,
    ) -> str:
        work_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            "docker",
            "run",
            "-d",
            "--name",
            name,
        ]
        for key, value in (labels or {}).items():
            argv.extend(["--label", f"{key}={value}"])
        argv += [
            "--cpus",
            str(vcpu),
            "--memory",
            f"{memory_gib}g",
            "-v",
            f"{work_dir.resolve()}:/work",
            "-w",
            workdir or "/work",
        ]
        if user:
            argv.extend(["--user", user])
        if use_kata:
            argv.extend(["--runtime", self.kata_runtime])
        elif dind and self.dind.runtime:
            argv.extend(["--runtime", self.dind.runtime])
        elif self.guest_runtime:
            argv.extend(["--runtime", self.guest_runtime])
        if dind:
            if os.environ.get("CATHEDRAL_ALLOW_PRIVILEGED_DIND") != "1":
                raise SandboxOpError(
                    "privileged_dind_disabled",
                    403,
                    "DinD requires CATHEDRAL_ALLOW_PRIVILEGED_DIND=1 "
                    "(privileged guests are host-risk on plain Docker; prefer Kata)",
                )
            argv.append("--privileged")
            argv.extend(["-e", "DOCKER_TLS_CERTDIR="])
            for key, value in self.dind.env:
                argv.extend(["-e", f"{key}={value}"])
        # Prefer storage quota when the local driver accepts it (overlay2+xfs usually).
        storage_opt = ["--storage-opt", f"size={disk_gib}G"] if disk_gib > 0 and not use_kata else []
        argv.extend(storage_opt)
        # allowlist fails closed to none until an egress proxy lands (honest).
        if network_mode in {"none", "allowlist"}:
            argv.extend(["--network", "none"])
        for key, value in env.items():
            argv.extend(["-e", f"{key}={value}"])
        if dind:
            argv.extend([image, "dockerd-entrypoint.sh", "dockerd", *self.dind.dockerd_args])
        elif entrypoint:
            argv.append(image)
            argv.extend(list(entrypoint))
        else:
            argv.extend([image, "sleep", "infinity"])
        result = self._run_guest(argv, name)
        if result.returncode != 0 and storage_opt:
            # Driver may reject size=; retry without it (API disk still enforced on /work).
            # A failed docker run can leave a created container with this name.
            # Remove it first, or the retry fails on a name conflict.
            self.remove_confirmed(name, timeout=60.0)
            stripped = []
            skip_next = False
            for part in argv:
                if skip_next:
                    skip_next = False
                    continue
                if part == "--storage-opt":
                    skip_next = True
                    continue
                stripped.append(part)
            result = self._run_guest(stripped, name)
        if result.returncode != 0:
            self.remove_confirmed(name, timeout=60.0)
            raise SandboxOpError(
                "guest_start_failed",
                502,
                f"docker run failed: {result.stderr.strip()[:400]}",
            )
        container_id = result.stdout.strip().splitlines()[-1].strip()
        if not container_id:
            raise SandboxOpError("guest_start_failed", 502, "docker run returned empty container id")
        return container_id

    def _run_guest(self, argv: list[str], name: str) -> subprocess.CompletedProcess[str]:
        """docker run; on a CLI timeout, remove the container it may have left."""
        try:
            return self.run(argv, timeout=180.0)
        except SandboxOpError as exc:
            if exc.code == "docker_timeout":
                self.remove_confirmed(name, timeout=60.0)
            raise

    def set_network(self, container_id: str, mode: str) -> None:
        """Apply egress mode on a live container. allowlist fails closed to none."""
        want_none = mode in {"none", "allowlist"}
        networks = self.run(
            ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", container_id],
            timeout=15.0,
        )
        attached: list[str] = []
        if networks.returncode == 0 and networks.stdout.strip():
            try:
                attached = list(json.loads(networks.stdout.strip()).keys())
            except json.JSONDecodeError:
                attached = []
        if want_none:
            for net in attached:
                if net != "none":
                    self.run(["docker", "network", "disconnect", "-f", net, container_id], timeout=30.0)
            return
        # public: ensure bridge (or first non-none network)
        if "bridge" not in attached and "none" in attached:
            self.run(["docker", "network", "disconnect", "-f", "none", container_id], timeout=30.0)
        if "bridge" not in attached:
            connect = self.run(["docker", "network", "connect", "bridge", container_id], timeout=30.0)
            if connect.returncode != 0:
                raise SandboxOpError(
                    "network_change_failed",
                    502,
                    f"failed to attach bridge: {connect.stderr.strip()[:300]}",
                )

    def exec(
        self,
        container_id: str,
        argv: list[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
        timeout_seconds: int,
        stdin: str | None,
        detach: bool = False,
        user: str | None = None,
    ) -> tuple[int, str, str, bool]:
        cmd = ["docker", "exec"]
        if detach:
            cmd.append("-d")
        else:
            cmd.append("-i")
        if user:
            cmd.extend(["-u", user])
        if cwd:
            cmd.extend(["-w", cwd])
        for key, value in env.items():
            cmd.extend(["-e", f"{key}={value}"])
        cmd.append(container_id)
        cmd.extend(argv)
        try:
            result = self.run(
                cmd,
                timeout=float(timeout_seconds),
                input_bytes=(stdin.encode() if stdin is not None else None),
            )
        except SandboxOpError as exc:
            if exc.code == "docker_timeout":
                # Kill only the timed-out docker-exec client process (already dead via
                # subprocess timeout). Never docker-kill the whole sandbox — the
                # checklist requires the sandbox to stay alive after a timed-out exec (§3.2).
                return 137, "", "exec timed out", True
            raise
        return result.returncode, result.stdout, result.stderr, False

    def remove(self, container_id: str) -> None:
        """Best-effort removal. The result is not checked; use remove_confirmed for GC."""
        self.run(["docker", "rm", "-f", container_id], timeout=60.0)

    def remove_confirmed(self, container_ref: str, *, timeout: float = 60.0) -> bool:
        """Remove a container. Return True only when it is gone.

        A timeout or a daemon error returns False, so the caller can retry.
        "No such container" counts as gone.
        """
        try:
            result = self.run(["docker", "rm", "-f", container_ref], timeout=timeout)
        except SandboxOpError:
            return False
        if result.returncode == 0:
            return True
        return "no such container" in (result.stderr or "").lower()

    def list_labeled(self, owner: str) -> list[tuple[str, str]]:
        """Return (container_id, sandbox_id) for all containers with our owner label.

        Raises SandboxOpError when the daemon cannot list. The caller must not
        treat a failed list as "no containers".
        """
        result = self.run(
            [
                "docker",
                "ps",
                "-a",
                "--no-trunc",
                "--filter",
                f"label={LABEL_OWNER}={owner}",
                "--format",
                "{{.ID}} {{.Label \"" + LABEL_SANDBOX_ID + "\"}}",
            ],
            timeout=60.0,
        )
        if result.returncode != 0:
            raise SandboxOpError(
                "docker_list_failed",
                502,
                f"docker ps failed: {(result.stderr or '').strip()[:200]}",
            )
        out: list[tuple[str, str]] = []
        for line in (result.stdout or "").splitlines():
            parts = line.strip().split(" ", 1)
            if parts and parts[0]:
                out.append((parts[0], parts[1].strip() if len(parts) > 1 else ""))
        return out

    def pause(self, container_id: str) -> None:
        result = self.run(["docker", "pause", container_id], timeout=30.0)
        if result.returncode != 0:
            raise SandboxOpError(
                "guest_pause_failed",
                502,
                f"docker pause failed: {(result.stderr or result.stdout or '')[:200]}",
            )

    def unpause(self, container_id: str) -> None:
        result = self.run(["docker", "unpause", container_id], timeout=30.0)
        if result.returncode != 0:
            raise SandboxOpError(
                "guest_unpause_failed",
                502,
                f"docker unpause failed: {(result.stderr or result.stdout or '')[:200]}",
            )

    def commit(self, container_id: str, image_name: str) -> str:
        result = self.run(["docker", "commit", container_id, image_name], timeout=300.0)
        if result.returncode != 0:
            raise SandboxOpError(
                "snapshot_failed",
                502,
                f"docker commit failed: {result.stderr.strip()[:300]}",
            )
        inspect = self.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image_name],
            timeout=30.0,
        )
        return (inspect.stdout.strip() if inspect.returncode == 0 else image_name) or image_name

    def wait_dind_ready(self, container_id: str, *, timeout_seconds: float = 90.0) -> None:
        deadline = time.monotonic() + timeout_seconds
        last_err = ""
        while time.monotonic() < deadline:
            code, out, err, _ = self.exec(
                container_id,
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                cwd=None,
                env={},
                timeout_seconds=15,
                stdin=None,
            )
            if code == 0 and out.strip():
                return
            last_err = (err or out or "dockerd not ready").strip()[:200]
            time.sleep(1.0)
        raise SandboxOpError(
            "dind_not_ready",
            503,
            f"dockerd inside guest did not become ready: {last_err}",
            retry_after=30,
        )


def mirror_ref(mirror: str, image: str) -> str | None:
    """Return the mirror reference for a Docker Hub *image*, else None.

    "alpine:3.20" -> "<mirror>/library/alpine:3.20". Images on another
    registry and digest references are not mirrored.
    """
    mirror = mirror.strip().rstrip("/")
    if not mirror or "@" in image:
        return None
    name = image
    for prefix in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    else:
        first = name.split("/", 1)[0]
        if "/" in name and ("." in first or ":" in first or first == "localhost"):
            return None
    if "/" not in name:
        name = "library/" + name
    return f"{mirror}/{name}"


def _registry_host(image: str) -> str:
    first = image.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first
    return "https://index.docker.io/v1/"


def _fetch_context_tar(url: str) -> bytes:
    """Fetch a build context. Fail closed against file:// and link-local/private SSRF."""
    from urllib.parse import urlparse
    import ipaddress
    import socket

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme == "file" or url.startswith("file:"):
        raise SandboxOpError(
            "build_context_forbidden",
            400,
            "file:// build contexts are not allowed",
        )
    if scheme not in ("http", "https"):
        raise SandboxOpError(
            "build_context_forbidden",
            400,
            f"unsupported build context scheme: {scheme or '<none>'}",
        )
    host = parsed.hostname or ""
    if not host:
        raise SandboxOpError("build_context_forbidden", 400, "build context URL missing host")
    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SandboxOpError(
            "build_context_fetch_failed",
            502,
            f"failed to resolve build context host: {exc}",
        ) from exc
    for info in addrs:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise SandboxOpError(
                "build_context_forbidden",
                400,
                "build context URL resolves to a non-public address",
            )
    try:
        with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 — gated above
            return resp.read()
    except (urllib.error.URLError, OSError) as exc:
        raise SandboxOpError(
            "build_context_fetch_failed",
            502,
            f"failed to fetch build context: {exc}",
        ) from exc


class DockerGuestProvider:
    """SandboxProvider that runs each sandbox as a real Linux Docker (or Kata) guest."""

    def __init__(
        self,
        *,
        use_kata: bool = False,
        default_image: str = "alpine:3.20",
        inner: InMemorySandboxProvider | None = None,
    ) -> None:
        self._client = DockerClient()
        self._use_kata = use_kata
        self._default_image = default_image
        self._guests: dict[str, GuestRecord] = {}
        self._snapshot_images: dict[str, str] = {}
        self._built_images: dict[str, str] = {}  # content_hash -> tag
        # GC state. A sandbox id in _doomed has a "deleting" record and a container
        # that is not yet confirmed gone. Only one drain runs at a time.
        self._owner = os.environ.get("CATHEDRAL_SANDBOX_OWNER", "").strip() or "default"
        self._doomed: dict[str, str] = {}  # sandbox_id -> container_id
        self._doomed_attempts: dict[str, int] = {}
        self._doomed_lock = threading.Lock()
        self._drain_lock = threading.Lock()
        self._gc_parallelism = _env_int("CATHEDRAL_SANDBOX_GC_PARALLELISM", 8, minimum=1)
        self._rm_timeout = _env_float("CATHEDRAL_SANDBOX_RM_TIMEOUT", 60.0, minimum=0.1)
        self._reconcile_interval = _env_float("CATHEDRAL_SANDBOX_RECONCILE_SECONDS", 60.0)
        self._last_reconcile: float | None = None
        # Image pulls. "missing" (default) pulls only when the image is not local;
        # "always" restores the old pull-on-every-create behaviour.
        self._pull_policy = (os.environ.get("CATHEDRAL_SANDBOX_PULL_POLICY", "").strip().lower() or "missing")
        self._registry_mirror = os.environ.get("CATHEDRAL_SANDBOX_REGISTRY_MIRROR", "").strip() or None
        # Images pulled with registry credentials. A create of one of these always
        # pulls, so the registry still checks the caller's credentials.
        self._auth_pulled: set[str] = set()
        if not self._client.info_ok():
            raise SandboxOpError(
                "runtime_unavailable",
                503,
                "docker daemon is not available; start Docker or use --runtime memory",
                retry_after=30,
            )
        if use_kata:
            probe = self._client.run(
                ["docker", "info", "--format", "{{json .Runtimes}}"],
                timeout=5.0,
            )
            runtime_name = self._client.kata_runtime
            if probe.returncode != 0 or runtime_name not in (probe.stdout or ""):
                if not shutil.which(runtime_name) and "kata" not in (probe.stdout or "").lower():
                    raise SandboxOpError(
                        "runtime_unavailable",
                        503,
                        f"kata runtime {runtime_name!r} is not registered with this Docker daemon",
                        retry_after=60,
                    )
        runtime_label = "kata" if use_kata else "docker"
        # The OCI runtime under each guest decides kernel isolation for /v1/status.
        self._oci_runtime = (
            self._client.kata_runtime
            if use_kata
            else (self._client.guest_runtime or self._client.default_runtime())
        )
        if inner is not None:
            self._inner = inner
        elif os.environ.get("CATHEDRAL_SANDBOX_KEYS", "").strip():
            self._inner = provider_from_environment(
                enforce_disk=True,
                runtime_label=runtime_label,
            )
        else:
            self._inner = InMemorySandboxProvider(
                enforce_disk=True,
                runtime_label=runtime_label,
            )
        self._capabilities_dind = False

    @property
    def capabilities_dind(self) -> bool:
        return self._capabilities_dind or any(g.dind for g in self._guests.values())

    def authorize(self, api_key: str | None) -> None:
        self._inner.authorize(api_key)

    def _build_image(self, request: CreateSandboxRequest) -> str:
        assert request.build is not None
        content_hash = request.build.content_hash
        cached = self._built_images.get(content_hash)
        if cached and self._client.image_exists(cached):
            return cached
        short = content_hash.split(":")[-1][:16]
        tag = f"cathedral-build-{short}:latest"
        if self._client.image_exists(tag):
            self._built_images[content_hash] = tag
            return tag
        work = Path(tempfile.mkdtemp(prefix="cathedral-build-"))
        try:
            if request.build.context_tar_url:
                raw = _fetch_context_tar(request.build.context_tar_url)
                import io
                import tarfile

                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as tf:
                    try:
                        tf.extractall(work, filter="data")
                    except TypeError:
                        tf.extractall(work)
            (work / "Dockerfile").write_text(request.build.dockerfile, encoding="utf-8")
            self._client.build(tag=tag, context_dir=work)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        self._built_images[content_hash] = tag
        return tag

    def _image_for(self, request: CreateSandboxRequest) -> str:
        if request.image is not None:
            return request.image.image
        if request.snapshot_id is not None:
            snap = self._snapshot_images.get(request.snapshot_id)
            if snap:
                return snap
            return self._default_image
        if request.build is not None:
            return self._build_image(request)
        return self._default_image

    def create(
        self,
        request: CreateSandboxRequest,
        *,
        api_key: str | None,
        idempotency: str | None,
        body_digest: str,
    ) -> dict[str, Any]:
        docs = self._inner.create(
            request, api_key=api_key, idempotency=idempotency, body_digest=body_digest
        )
        batch = docs["sandboxes"] if "sandboxes" in docs else [docs]
        started: list[dict[str, Any]] = []
        try:
            for doc in batch:
                existing = self._guests.get(doc["id"])
                if existing is not None:
                    started.append(self._enrich_doc(doc, existing))
                else:
                    started.append(self._start_guest(doc, request))
        except Exception:
            # One failed guest fails the whole create. Release every record and
            # guest of this batch, so no ghost holds quota, and forget the
            # Idempotency-Key so a retry creates again.
            for doc in batch:
                self.delete(doc["id"])
            if idempotency is not None:
                with self._inner._lock:  # noqa: SLF001
                    seen = self._inner._idempotency.get(idempotency)  # noqa: SLF001
                    if seen is not None and seen[1] is docs:
                        del self._inner._idempotency[idempotency]  # noqa: SLF001
            raise
        if "sandboxes" in docs:
            return {"sandboxes": started, "count": len(started)}
        return started[0]

    def _enrich_doc(self, doc: dict[str, Any], guest: GuestRecord) -> dict[str, Any]:
        enriched = dict(doc)
        enriched["runtime"] = "kata" if self._use_kata else "docker"
        enriched["guest"] = {
            "container_id": guest.container_id,
            "image": guest.image,
            "dind": guest.dind,
            "network_mode": guest.network_mode,
            "network_enforced": guest.network_mode != "allowlist",
            "allowlist_fail_closed": guest.network_mode == "allowlist",
        }
        return enriched

    def _ensure_image(
        self, image: str, *, registry_auth: Mapping[str, str] | None = None, refresh: bool = False
    ) -> None:
        if registry_auth is not None or image in self._auth_pulled or self._pull_policy == "always":
            refresh = True
        self._client.ensure_image(
            image,
            registry_auth=registry_auth,
            refresh=refresh,
            mirror=self._registry_mirror,
        )
        if registry_auth is not None:
            self._auth_pulled.add(image)

    def _start_guest(self, doc: dict[str, Any], request: CreateSandboxRequest) -> dict[str, Any]:
        """Start the guest for one record. The caller releases the record on failure."""
        sandbox_id = doc["id"]
        image = self._image_for(request)
        if request.snapshot_id and request.snapshot_id in self._snapshot_images:
            image = self._snapshot_images[request.snapshot_id]
        elif request.image is not None:
            self._ensure_image(image, registry_auth=request.image.registry_auth)
            inspected = self._client.image_inspect(image)
            self._inner._images[image] = {  # noqa: SLF001
                "ref": image,
                "cached": True,
                "size_bytes": int(inspected.get("Size") or 0),
                "digest": (inspected.get("RepoDigests") or [None])[0],
            }
        elif request.build is not None:
            self._inner._images[image] = {  # noqa: SLF001
                "ref": image,
                "cached": True,
                "size_bytes": 0,
                "digest": request.build.content_hash,
            }
        dind = is_dind_image(image)
        work = Path(self._inner._sandboxes[sandbox_id].root) / "work"  # noqa: SLF001
        name = f"cathedral-{sandbox_id}"
        entrypoint = None if dind else (tuple(request.entrypoint) if request.entrypoint else ("sleep", "infinity"))
        container_id = self._client.create_and_start(
            image=image,
            name=name,
            work_dir=work,
            vcpu=request.resources.vcpu,
            memory_gib=request.resources.memory_gib,
            disk_gib=request.resources.disk_gib,
            network_mode=request.network.mode,
            env=request.env,
            dind=dind,
            use_kata=self._use_kata,
            entrypoint=entrypoint,
            workdir=request.workdir,
            user=request.user,
            labels={LABEL_OWNER: self._owner, LABEL_SANDBOX_ID: sandbox_id},
        )
        if not self._inner.has_record(sandbox_id):
            # GC or DELETE removed the record while the guest started. Do not
            # register an orphan; the reconcile pass retries if this rm fails.
            self._client.remove_confirmed(container_id, timeout=self._rm_timeout)
            raise SandboxOpError("sandbox_not_found", 404, f"no sandbox {sandbox_id}")
        self._guests[sandbox_id] = GuestRecord(
            sandbox_id=sandbox_id,
            container_id=container_id,
            image=image,
            dind=dind,
            work_mount=work,
            network_mode=request.network.mode,
        )
        if dind:
            self._capabilities_dind = True
            self._client.wait_dind_ready(container_id)
        # Guest start can take longer than a short idle_timeout; refresh activity
        # so idle GC does not reap a sandbox mid-create.
        with self._inner._lock:  # noqa: SLF001
            if sandbox_id in self._inner._sandboxes:  # noqa: SLF001
                self._inner._touch(self._inner._sandboxes[sandbox_id])  # noqa: SLF001
        return self._enrich_doc(doc, self._guests[sandbox_id])

    def exec(self, sandbox_id: str, request: ExecRequest) -> ExecResult:
        guest = self._guests.get(sandbox_id)
        if guest is None:
            return self._inner.exec(sandbox_id, request)
        cwd = request.cwd or "/work"
        argv = list(request.argv)
        # Portable shell: ExecRequest maps string cmds to bash -c; many customer images
        # (alpine, slim) only ship sh. Prefer sh when bash is not the guest's shell.
        if argv and argv[0] == "bash":
            argv[0] = "sh"
        timeout_seconds = request.timeout_seconds or 60
        # Enforce timeout inside the guest so the container stays alive (§3.2).
        # Try GNU timeout first, then BusyBox ``timeout -t``.
        candidates = [
            ["timeout", str(timeout_seconds), *argv],
            ["timeout", "-t", str(timeout_seconds), *argv],
            argv,
        ]
        t0 = time.perf_counter()
        code, out, err, timed_out = 1, "", "", False
        for wrapped in candidates:
            code, out, err, timed_out = self._client.exec(
                guest.container_id,
                wrapped,
                cwd=cwd,
                env={**dict(request.env)},
                timeout_seconds=timeout_seconds + 15 if wrapped is not argv else timeout_seconds,
                stdin=request.stdin,
                user=request.user,
            )
            # 127 = command not found (no timeout binary) — try next form.
            if wrapped is argv or code != 127:
                break
        # GNU timeout → 124; BusyBox/KILL → 137/143; client-side timeout flag.
        if code in {124, 137, 143} or timed_out:
            timed_out = True
        duration_ms = int((time.perf_counter() - t0) * 1000)
        with self._inner._lock:  # noqa: SLF001
            sandbox = self._inner._require_active(sandbox_id)  # noqa: SLF001
            sandbox.exec_history.append(
                ExecRecord(
                    command=_render_cmd(request),
                    exit_code=code,
                    duration_ms=duration_ms,
                    at=_now(),
                )
            )
            sandbox.container_stdout.extend(out.encode("utf-8", "replace"))
            sandbox.container_stderr.extend(err.encode("utf-8", "replace"))
            self._inner._touch(sandbox)  # noqa: SLF001
        cap = 16 * 1024 * 1024
        truncated = len(out.encode()) > cap or len(err.encode()) > cap
        return ExecResult(
            exit_code=code,
            stdout=out[:cap],
            stderr=err[:cap],
            duration_ms=duration_ms,
            timed_out=timed_out,
            truncated=truncated,
        )

    def start_process(self, sandbox_id: str, request: ExecRequest) -> ProcessHandle:
        guest = self._guests.get(sandbox_id)
        if guest is None:
            return self._inner.start_process(sandbox_id, request)
        pid = "proc_" + uuid.uuid4().hex[:10]
        log_guest = f"/work/.process-{pid}.log"
        log_host = guest.work_mount / f".process-{pid}.log"
        # Background inside the guest so it outlives the HTTP call (§3.2).
        quoted = " ".join(shlex_quote(part) for part in request.argv)
        starter = ["sh", "-c", f"({quoted}) > {log_guest} 2>&1"]
        code, _, err, _ = self._client.exec(
            guest.container_id,
            starter,
            cwd=request.cwd or "/work",
            env={**dict(request.env)},
            timeout_seconds=30,
            stdin=None,
            detach=True,
            user=request.user,
        )
        if code != 0:
            raise SandboxOpError(
                "process_start_failed",
                502,
                f"failed to start background process: {err.strip()[:300]}",
            )
        guest.guest_processes[pid] = log_host
        with self._inner._lock:  # noqa: SLF001
            sandbox = self._inner._require_active(sandbox_id)  # noqa: SLF001
            sandbox.processes[pid] = (None, log_host)  # type: ignore[arg-type]
        return ProcessHandle(process_id=pid, argv=tuple(request.argv), running=True)

    def process_logs(self, sandbox_id: str, process_id: str) -> str:
        guest = self._guests.get(sandbox_id)
        if guest is None or process_id not in guest.guest_processes:
            return self._inner.process_logs(sandbox_id, process_id)
        path = guest.guest_processes[process_id]
        return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""

    def stop_process(self, sandbox_id: str, process_id: str) -> None:
        guest = self._guests.get(sandbox_id)
        if guest is None or process_id not in guest.guest_processes:
            return self._inner.stop_process(sandbox_id, process_id)
        # Best-effort: kill matching process tree by log redirect is hard; use pkill on argv marker.
        self._client.exec(
            guest.container_id,
            ["sh", "-c", f"pkill -f '.process-{process_id}.log' || true"],
            cwd=None,
            env={},
            timeout_seconds=15,
            stdin=None,
        )

    def write_file(self, sandbox_id: str, path: str, data: bytes, mode: int | None) -> None:
        self._inner.write_file(sandbox_id, path, data, mode)

    def read_file(self, sandbox_id: str, spec: FileGet) -> tuple[bytes, int]:
        return self._inner.read_file(sandbox_id, spec)

    def write_tar(self, sandbox_id: str, path: str, tarball: bytes) -> None:
        self._inner.write_tar(sandbox_id, path, tarball)

    def read_tar(self, sandbox_id: str, spec: TarGet) -> bytes:
        return self._inner.read_tar(sandbox_id, spec)

    def snapshot(
        self,
        sandbox_id: str,
        *,
        ttl_seconds: int | None = None,
        name: str | None = None,
        labels: dict[str, str] | None = None,
    ) -> str:
        op_id = self._inner.snapshot(
            sandbox_id, ttl_seconds=ttl_seconds, name=name, labels=labels
        )
        snap_id = self._inner.get_operation(op_id)["result"]["snapshot_id"]
        guest = self._guests.get(sandbox_id)
        if guest is not None:
            image_name = f"cathedral-snap-{snap_id}:latest"
            self._client.commit(guest.container_id, image_name)
            self._snapshot_images[snap_id] = image_name
        return op_id

    def set_network(self, sandbox_id: str, patch: NetworkPatch) -> dict[str, Any]:
        doc = self._inner.set_network(sandbox_id, patch)
        guest = self._guests.get(sandbox_id)
        if guest is not None:
            self._client.set_network(guest.container_id, patch.mode)
            guest.network_mode = patch.mode
            doc["network"]["enforced"] = patch.mode != "allowlist"
            doc["network"]["allowlist_fail_closed"] = patch.mode == "allowlist"
        return doc

    def freeze(self, sandbox_id: str) -> dict[str, Any]:
        guest = self._guests.get(sandbox_id)
        if guest is not None:
            self._client.pause(guest.container_id)
        return self._inner.freeze(sandbox_id)

    def thaw(self, sandbox_id: str) -> dict[str, Any]:
        guest = self._guests.get(sandbox_id)
        doc = self._inner.thaw(sandbox_id)
        if guest is not None:
            self._client.unpause(guest.container_id)
        return doc

    def delete(self, sandbox_id: str) -> None:
        """DELETE is idempotent (204). The record only goes when the container is gone.

        When the container removal fails, the sandbox stays "deleting": hidden
        from the API, still counted in quota. The next sweep retries it.
        """
        guest = self._guests.get(sandbox_id)
        if guest is None:
            self._inner.delete(sandbox_id)
            return
        for process_id in list(guest.guest_processes):
            try:
                self.stop_process(sandbox_id, process_id)
            except SandboxOpError:
                pass
        if self._retire(sandbox_id):
            self._remove_queued([sandbox_id])

    def bulk_delete(self, labels: Iterable[str]) -> int:
        # Must use this.delete so containers are removed (inner.bulk_delete would leak).
        want = _parse_label_filters(labels)
        if not want:
            raise SandboxContractError("invalid_label", "bulk delete requires at least one label filter")
        caller = self._inner._caller_key()  # noqa: SLF001
        with self._inner._lock:  # noqa: SLF001
            targets = [
                sid
                for sid, s in self._inner._sandboxes.items()  # noqa: SLF001
                if s.state != "deleting"
                and all(s.labels.get(k) == v for k, v in want.items())
                and (caller is None or s.api_key is None or s.api_key == caller)
            ]
        retired = [sid for sid in targets if self._retire(sid)]
        self._remove_queued(retired)
        return len(targets)

    # ------------------------------------------------------------------ GC
    def _retire(self, sandbox_id: str) -> bool:
        """Move a sandbox to "deleting" and queue its container for removal.

        Return False when another caller already retired it. A record with no
        container is dropped at once.
        """
        if not self._inner.begin_delete(sandbox_id):
            return False
        guest = self._guests.pop(sandbox_id, None)
        if guest is None:
            self._inner.finish_delete(sandbox_id)
            return True
        with self._doomed_lock:
            self._doomed[sandbox_id] = guest.container_id
        return True

    def _confirm_removed(self, sandbox_id: str) -> None:
        with self._doomed_lock:
            self._doomed.pop(sandbox_id, None)
            self._doomed_attempts.pop(sandbox_id, None)
        self._inner.finish_delete(sandbox_id)

    def _remove_queued(self, sandbox_ids: list[str]) -> None:
        """Try once, in parallel, to remove the queued containers of *sandbox_ids*.

        Failures stay queued for the next sweep.
        """
        with self._doomed_lock:
            batch = [(sid, self._doomed[sid]) for sid in sandbox_ids if sid in self._doomed]
        for (sid, _), gone in zip(batch, self._remove_many([cid for _, cid in batch])):
            if gone:
                self._confirm_removed(sid)

    def mark_expired(self) -> int:
        """Move every collectable sandbox to "deleting". Fast; runs no docker command."""
        marked = 0
        for sid in self._inner.collectable_ids():
            if self._retire(sid):
                marked += 1
        return marked

    def _remove_many(self, refs: list[str]) -> list[bool]:
        """Remove containers in bounded parallel batches. Return one result per ref."""
        if not refs:
            return []
        workers = min(self._gc_parallelism, len(refs))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="cathedral-gc") as pool:
            return list(
                pool.map(lambda ref: self._client.remove_confirmed(ref, timeout=self._rm_timeout), refs)
            )

    def _drain_locked(self) -> int:
        """Try once to remove each queued container. Caller holds _drain_lock."""
        attempted: set[str] = set()
        confirmed = 0
        while True:
            with self._doomed_lock:
                batch = [(sid, cid) for sid, cid in self._doomed.items() if sid not in attempted]
            if not batch:
                return confirmed
            attempted.update(sid for sid, _ in batch)
            results = self._remove_many([cid for _, cid in batch])
            for (sid, cid), gone in zip(batch, results):
                if gone:
                    self._confirm_removed(sid)
                    confirmed += 1
                else:
                    with self._doomed_lock:
                        attempts = self._doomed_attempts.get(sid, 0) + 1
                        self._doomed_attempts[sid] = attempts
                    print(
                        f"cathedral-sandbox gc: container {cid[:12]} of {sid} not removed "
                        f"(attempt {attempts}); will retry",
                        file=sys.stderr,
                        flush=True,
                    )

    def _reconcile_locked(self) -> int:
        """Remove containers with our owner label that have no sandbox record.

        Caller holds _drain_lock. A record is created before its container, so
        a container whose sandbox id has no record is an orphan.
        """
        try:
            labeled = self._client.list_labeled(self._owner)
        except SandboxOpError as exc:
            print(f"cathedral-sandbox gc: reconcile skipped: {exc}", file=sys.stderr, flush=True)
            return 0
        with self._doomed_lock:
            queued = set(self._doomed)
        orphans = [
            cid
            for cid, sid in labeled
            if sid not in queued and not (sid and self._inner.has_record(sid))
        ]
        return sum(1 for gone in self._remove_many(orphans) if gone)

    def sweep(self) -> int:
        """GC expired guests. Return the number of sandboxes collected by this call.

        1. Mark expired records "deleting" (hidden from the API, still in quota).
        2. Remove queued containers in parallel batches. Drop each record only
           after its container is confirmed gone. Failures stay queued.
        3. At most every CATHEDRAL_SANDBOX_RECONCILE_SECONDS, remove labeled
           containers that have no record.
        Only one call runs steps 2 and 3 at a time. A concurrent call returns
        after step 1.
        """
        marked = self.mark_expired()
        if self._drain_lock.acquire(blocking=False):
            try:
                self._drain_locked()
                now = time.monotonic()
                if self._last_reconcile is None or now - self._last_reconcile >= self._reconcile_interval:
                    self._last_reconcile = now
                    self._reconcile_locked()
            finally:
                self._drain_lock.release()
        # Drops expired log tombstones. Live expired records are already "deleting".
        self._inner.sweep()
        return marked

    def pending_removals(self) -> dict[str, str]:
        """Sandbox id -> container id for containers not yet confirmed gone."""
        with self._doomed_lock:
            return dict(self._doomed)

    def status(self) -> StatusReport:
        report = self._inner.status()
        return StatusReport(
            status=report.status,
            create_latency_p50_ms=report.create_latency_p50_ms,
            error_rate=report.error_rate,
            region=report.region,
            runtime="kata" if self._use_kata else "docker",
            kernel_isolation=self._use_kata or runtime_has_kernel_isolation(self._oci_runtime),
            dind=self.capabilities_dind,
            disk_enforced=True,
        )

    def prefetch(self, request: PrefetchRequest) -> str:
        for image in request.images:
            # Prefetch is the explicit refresh path: it always pulls.
            self._ensure_image(image, refresh=True)
            inspected = self._client.image_inspect(image)
            self._inner._images[image] = {  # noqa: SLF001
                "ref": image,
                "cached": True,
                "size_bytes": int(inspected.get("Size") or 0),
                "digest": (inspected.get("RepoDigests") or [None])[0],
            }
        return self._inner.prefetch(request)

    def image_status(self, ref: str) -> dict[str, Any]:
        entry = self._inner.image_status(ref)
        if entry.get("cached") and "ref" not in entry:
            entry = {"ref": ref, **entry}
        if not entry.get("cached") and self._client.image_exists(ref):
            inspected = self._client.image_inspect(ref)
            entry = {
                "ref": ref,
                "cached": True,
                "size_bytes": int(inspected.get("Size") or 0),
                "digest": (inspected.get("RepoDigests") or [None])[0],
            }
            self._inner._images[ref] = entry  # noqa: SLF001
        return entry

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def close(self) -> None:
        refs = [g.container_id for g in self._guests.values()]
        with self._doomed_lock:
            refs.extend(self._doomed.values())
            self._doomed.clear()
        self._remove_many(refs)
        self._guests.clear()
        self._inner.close()


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


__all__ = [
    "DIND_DOCKERD_ARGS_DEFAULT",
    "DindConfig",
    "DockerClient",
    "DockerGuestProvider",
    "GuestRecord",
    "docker_cli_available",
    "docker_daemon_ready",
    "is_dind_image",
]
