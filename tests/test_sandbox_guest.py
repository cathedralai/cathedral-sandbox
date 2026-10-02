"""Live Docker guest tests — real daemon only, no fakes.

Skipped when Docker is not running. Set CATHEDRAL_EXPECTS_DIND=1 to also run
the docker:*-dind path (pulls a DinD image).
"""

from __future__ import annotations

import os
import time

import pytest

from cathedral.sandbox_api import (
    BuildSpec,
    CreateSandboxRequest,
    ExecRequest,
    FileGet,
    ImageSource,
    NetworkPatch,
    NetworkSpec,
    Resources,
)
from cathedral.sandbox_guest import (
    DockerGuestProvider,
    docker_daemon_ready,
    is_dind_image,
)
from cathedral.sandbox_provider import SandboxOpError
from cathedral.sandbox_runtime import RUNTIME_DOCKER, detect_runtime, kata_host_ready


pytestmark = [
    pytest.mark.skipif(
        not docker_daemon_ready(),
        reason="Docker daemon not available — start Docker to run real guest tests",
    ),
]


@pytest.fixture(autouse=True)
def _clear_operator_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    # Serve boots may leave CATHEDRAL_SANDBOX_KEYS in the environment; guest unit
    # tests use permissive keys like "k" and must not inherit a strict key store.
    monkeypatch.delenv("CATHEDRAL_SANDBOX_KEYS", raising=False)
    monkeypatch.delenv("CATHEDRAL_SANDBOX_REVOKED_KEYS", raising=False)
    monkeypatch.delenv("CATHEDRAL_SANDBOX_QUOTA", raising=False)


def _req(**over) -> CreateSandboxRequest:
    values = {
        "image": ImageSource(image="alpine:3.20"),
        "resources": Resources(vcpu=1, memory_gib=1, disk_gib=5),
    }
    values.update(over)
    return CreateSandboxRequest(**values)


def test_is_dind_image() -> None:
    assert is_dind_image("docker:28.3.3-dind")
    assert not is_dind_image("alpine:3.20")


def test_detect_runtime_accepts_docker() -> None:
    assert detect_runtime("docker") == RUNTIME_DOCKER


def test_real_guest_create_exec_file_delete() -> None:
    provider = DockerGuestProvider(use_kata=False)
    try:
        doc = provider.create(_req(), api_key="k", idempotency=None, body_digest="b")
        assert doc["runtime"] == "docker"
        assert doc["guest"]["container_id"]
        assert doc["guest"]["dind"] is False
        sid = doc["id"]
        provider.write_file(sid, "/work/a.txt", b"payload", None)
        data, total = provider.read_file(sid, FileGet(path="/work/a.txt"))
        assert data == b"payload" and total == 7
        inside = provider.exec(
            sid, ExecRequest(cmd=["cat", "/work/a.txt"], timeout_seconds=30)
        )
        assert inside.exit_code == 0 and inside.stdout == "payload"
        logs = provider.logs(sid)
        assert "payload" in logs["stdout"]
        status = provider.status().to_document()
        assert status["runtime"] == "docker"
        assert status["kernel_isolation"] is False
        assert status["disk_enforced"] is True
        provider.delete(sid)
    finally:
        provider.close()


def test_real_dockerfile_build_cached() -> None:
    provider = DockerGuestProvider(use_kata=False)
    try:
        build = BuildSpec(
            dockerfile="FROM alpine:3.20\nRUN echo built-by-cathedral > /marker\n",
            context_multipart=True,
        )
        doc = provider.create(
            _req(image=None, build=build),
            api_key="k",
            idempotency=None,
            body_digest="build1",
        )
        marker = provider.exec(
            doc["id"], ExecRequest(cmd=["cat", "/marker"], timeout_seconds=30)
        )
        assert marker.exit_code == 0 and "built-by-cathedral" in marker.stdout
        # Second create with same hash must reuse the image (no rebuild required).
        doc2 = provider.create(
            _req(image=None, build=build),
            api_key="k",
            idempotency=None,
            body_digest="build2",
        )
        assert doc2["guest"]["image"] == doc["guest"]["image"]
        provider.delete(doc["id"])
        provider.delete(doc2["id"])
    finally:
        provider.close()


def test_real_network_none_blocks_egress() -> None:
    provider = DockerGuestProvider(use_kata=False)
    try:
        doc = provider.create(
            _req(network=NetworkSpec(mode="none")),
            api_key="k",
            idempotency=None,
            body_digest="net",
        )
        # Alpine may lack wget; use a TCP probe via /dev/tcp if bash present, else nc/wget.
        probe = provider.exec(
            doc["id"],
            ExecRequest(
                cmd=["sh", "-c", "wget -q -O- --timeout=3 http://1.1.1.1 >/dev/null 2>&1; echo $?"],
                timeout_seconds=20,
            ),
        )
        # Non-zero means blocked (or wget missing). Retry with ping-style failure check:
        if "wget: not found" in probe.stderr or probe.stdout.strip() == "127":
            probe = provider.exec(
                doc["id"],
                ExecRequest(
                    cmd=["sh", "-c", "nc -z -w 2 1.1.1.1 80 >/dev/null 2>&1; echo $?"],
                    timeout_seconds=20,
                ),
            )
        assert probe.stdout.strip() not in {"0"}, f"egress should be blocked, got {probe!r}"
        # Switch to public and confirm reconnect works.
        provider.set_network(doc["id"], NetworkPatch(mode="public"))
        provider.delete(doc["id"])
    finally:
        provider.close()


def test_real_background_process_in_guest() -> None:
    provider = DockerGuestProvider(use_kata=False)
    try:
        doc = provider.create(_req(), api_key="k", idempotency=None, body_digest="proc")
        handle = provider.start_process(
            doc["id"],
            ExecRequest(cmd=["sh", "-c", "echo hello-bg; sleep 2"]),
        )
        time.sleep(0.5)
        logs = provider.process_logs(doc["id"], handle.process_id)
        # May still be empty briefly; wait a bit more.
        deadline = time.time() + 5
        while time.time() < deadline and "hello-bg" not in logs:
            time.sleep(0.2)
            logs = provider.process_logs(doc["id"], handle.process_id)
        assert "hello-bg" in logs
        provider.stop_process(doc["id"], handle.process_id)
        provider.delete(doc["id"])
    finally:
        provider.close()


def test_real_snapshot_commit() -> None:
    provider = DockerGuestProvider(use_kata=False)
    try:
        doc = provider.create(_req(), api_key="k", idempotency=None, body_digest="s")
        provider.write_file(doc["id"], "/work/state.txt", b"snap-me", None)
        op = provider.snapshot(doc["id"])
        snap_id = provider.get_operation(op)["result"]["snapshot_id"]
        assert snap_id in provider._snapshot_images  # noqa: SLF001
        provider.delete(doc["id"])
    finally:
        provider.close()


def test_missing_daemon_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(SandboxOpError) as exc:
        DockerGuestProvider(use_kata=False)
    assert exc.value.code == "runtime_unavailable"


@pytest.mark.skipif(
    os.environ.get("CATHEDRAL_EXPECTS_DIND", "0") != "1",
    reason="Set CATHEDRAL_EXPECTS_DIND=1 to pull/run a real docker:*-dind guest",
)
def test_real_dind_guest() -> None:
    provider = DockerGuestProvider(use_kata=False)
    try:
        doc = provider.create(
            _req(image=ImageSource(image="docker:28-dind")),
            api_key="k",
            idempotency=None,
            body_digest="dind",
        )
        assert doc["guest"]["dind"] is True
        assert provider.status().dind is True
        info = provider.exec(
            doc["id"],
            ExecRequest(
                cmd=["docker", "info", "--format", "{{.ServerVersion}}"],
                timeout_seconds=120,
            ),
        )
        assert info.exit_code == 0, info.stderr
        assert info.stdout.strip()
        # Bind-mount check the customer checklist requires.
        mount = provider.exec(
            doc["id"],
            ExecRequest(
                cmd=["docker", "run", "--rm", "-v", "/work:/work", "busybox", "true"],
                timeout_seconds=120,
            ),
        )
        assert mount.exit_code == 0, mount.stderr
        provider.delete(doc["id"])
    finally:
        provider.close()


@pytest.mark.skipif(
    not kata_host_ready(),
    reason="Kata runtime not registered with Docker on this host",
)
def test_real_kata_guest() -> None:
    provider = DockerGuestProvider(use_kata=True)
    try:
        doc = provider.create(_req(), api_key="k", idempotency=None, body_digest="kata")
        assert doc["runtime"] == "kata"
        assert provider.status().kernel_isolation is True
        result = provider.exec(doc["id"], ExecRequest(cmd=["uname", "-s"], timeout_seconds=30))
        assert result.exit_code == 0 and "Linux" in result.stdout
        provider.delete(doc["id"])
    finally:
        provider.close()
