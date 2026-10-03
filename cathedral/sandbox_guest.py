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
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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
    gc_deadline,
    is_collectable,
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
    ) -> str:
        work_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            "docker",
            "run",
            "-d",
            "--name",
            name,
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
        # Prefer storage quota when the local driver accepts it (overlay2+xfs usually).
        storage_opt = ["--storage-opt", f"size={disk_gib}G"] if disk_gib > 0 and not use_kata else []
        argv.extend(storage_opt)
        # allowlist fails closed to none until an egress proxy lands (honest).
        if network_mode in {"none", "allowlist"}:
            argv.extend(["--network", "none"])
        for key, value in env.items():
            argv.extend(["-e", f"{key}={value}"])
        if dind:
            argv.extend(
                [
                    image,
                    "dockerd-entrypoint.sh",
                    "dockerd",
                    "--host=unix:///var/run/docker.sock",
                    "--default-address-pool",
                    "base=172.28.0.0/16,size=24",
                ]
            )
        elif entrypoint:
            argv.append(image)
            argv.extend(list(entrypoint))
        else:
            argv.extend([image, "sleep", "infinity"])
        result = self.run(argv, timeout=180.0)
        if result.returncode != 0 and storage_opt:
            # Driver may reject size=; retry without it (API disk still enforced on /work).
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
            result = self.run(stripped, timeout=180.0)
        if result.returncode != 0:
            raise SandboxOpError(
                "guest_start_failed",
                502,
                f"docker run failed: {result.stderr.strip()[:400]}",
            )
        container_id = result.stdout.strip().splitlines()[-1].strip()
        if not container_id:
            raise SandboxOpError("guest_start_failed", 502, "docker run returned empty container id")
        return container_id

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
        self.run(["docker", "rm", "-f", container_id], timeout=60.0)

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
        if "sandboxes" in docs:
            started = []
            for doc in docs["sandboxes"]:
                existing = self._guests.get(doc["id"])
                if existing is not None:
                    started.append(self._enrich_doc(doc, existing))
                else:
                    started.append(self._start_guest(doc, request))
            return {"sandboxes": started, "count": len(started)}
        existing = self._guests.get(docs["id"])
        if existing is not None:
            return self._enrich_doc(docs, existing)
        return self._start_guest(docs, request)

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

    def _start_guest(self, doc: dict[str, Any], request: CreateSandboxRequest) -> dict[str, Any]:
        sandbox_id = doc["id"]
        image = self._image_for(request)
        if request.snapshot_id and request.snapshot_id in self._snapshot_images:
            image = self._snapshot_images[request.snapshot_id]
        elif request.image is not None:
            auth = request.image.registry_auth
            self._client.pull(image, registry_auth=auth)
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
        try:
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
            )
        except SandboxOpError:
            self._inner.delete(sandbox_id)
            raise
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
            try:
                self._client.wait_dind_ready(container_id)
            except SandboxOpError:
                self._client.remove(container_id)
                self._guests.pop(sandbox_id, None)
                self._inner.delete(sandbox_id)
                raise
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
        guest = self._guests.get(sandbox_id)
        if guest is not None:
            for process_id in list(guest.guest_processes):
                try:
                    self.stop_process(sandbox_id, process_id)
                except SandboxOpError:
                    pass
            self._guests.pop(sandbox_id, None)
            self._client.remove(guest.container_id)
        self._inner.delete(sandbox_id)

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
                if all(s.labels.get(k) == v for k, v in want.items())
                and (caller is None or s.api_key is None or s.api_key == caller)
            ]
        for sid in targets:
            self.delete(sid)
        return len(targets)

    def sweep(self) -> int:
        """GC expired guests and remove their Docker containers."""
        now = _now()
        to_remove: list[str] = []
        with self._inner._lock:  # noqa: SLF001
            for sid, sandbox in list(self._inner._sandboxes.items()):  # noqa: SLF001
                past_ttl = is_collectable(
                    now, deadline_at=gc_deadline(sandbox.expires_at), last_heartbeat_at=None
                )
                idle_expired = (
                    sandbox.idle_timeout_seconds is not None
                    and sandbox.last_activity_at is not None
                    and (now - sandbox.last_activity_at)
                    >= timedelta(seconds=sandbox.idle_timeout_seconds)
                )
                key = (
                    self._inner._keys.get(sandbox.api_key)  # noqa: SLF001
                    if sandbox.api_key is not None
                    else None
                )
                revoked = key is not None and key.revoked
                if past_ttl or idle_expired or revoked:
                    to_remove.append(sid)
        for sid in to_remove:
            guest = self._guests.pop(sid, None)
            if guest is not None:
                try:
                    self._client.remove(guest.container_id)
                except SandboxOpError:
                    pass
        return self._inner.sweep()

    def status(self) -> StatusReport:
        report = self._inner.status()
        return StatusReport(
            status=report.status,
            create_latency_p50_ms=report.create_latency_p50_ms,
            error_rate=report.error_rate,
            region=report.region,
            runtime="kata" if self._use_kata else "docker",
            kernel_isolation=self._use_kata,
            dind=self.capabilities_dind,
            disk_enforced=True,
        )

    def prefetch(self, request: PrefetchRequest) -> str:
        for image in request.images:
            self._client.pull(image)
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
        for guest in list(self._guests.values()):
            try:
                self._client.remove(guest.container_id)
            except SandboxOpError:
                pass
        self._guests.clear()
        self._inner.close()


def shlex_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


__all__ = [
    "DockerClient",
    "DockerGuestProvider",
    "GuestRecord",
    "docker_cli_available",
    "docker_daemon_ready",
    "is_dind_image",
]
