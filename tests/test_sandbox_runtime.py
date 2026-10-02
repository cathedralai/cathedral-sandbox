"""Runtime selection — fail-closed, no stub guests."""

from __future__ import annotations

import pytest

from cathedral.sandbox_guest import docker_daemon_ready
from cathedral.sandbox_provider import InMemorySandboxProvider, SandboxOpError
from cathedral.sandbox_runtime import (
    RUNTIME_DOCKER,
    RUNTIME_KATA,
    RUNTIME_MEMORY,
    build_sandbox_provider,
    detect_runtime,
    kata_host_ready,
)


def test_detect_runtime_defaults_to_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CATHEDRAL_SANDBOX_RUNTIME", raising=False)
    assert detect_runtime(None) == RUNTIME_MEMORY


def test_detect_runtime_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        detect_runtime("firecracker")


def test_detect_runtime_accepts_docker_and_kata() -> None:
    assert detect_runtime("docker") == RUNTIME_DOCKER
    assert detect_runtime("kata") == RUNTIME_KATA


def test_disk_enforced_rejects_oversize_write() -> None:
    provider = InMemorySandboxProvider(enforce_disk=True)
    try:
        from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources

        doc = provider.create(
            CreateSandboxRequest(
                image=ImageSource(image="alpine:3.20"),
                resources=Resources(vcpu=1, memory_gib=2, disk_gib=5),
            ),
            api_key="k",
            idempotency=None,
            body_digest="d",
        )
        assert provider.status().disk_enforced is True
        provider.write_file(doc["id"], "/work/ok.bin", b"x" * 1024, None)
        with provider._lock:  # noqa: SLF001
            sandbox = provider._sandboxes[doc["id"]]  # noqa: SLF001
            with pytest.raises(SandboxOpError) as exc:
                provider._assert_disk_room(  # noqa: SLF001
                    sandbox, extra_bytes=6 * (1024**3), replacing=None
                )
            assert exc.value.code == "disk_quota_exceeded"
    finally:
        provider.close()


def test_status_reports_memory_runtime() -> None:
    provider = InMemorySandboxProvider(enforce_disk=True, runtime_label=RUNTIME_MEMORY)
    try:
        report = provider.status().to_document()
        assert report["runtime"] == "memory"
        assert report["kernel_isolation"] is False
        assert report["dind"] is False
        assert report["disk_enforced"] is True
    finally:
        provider.close()


def test_build_memory_dev_provider() -> None:
    provider = build_sandbox_provider(allow_insecure_dev=True)
    try:
        assert provider.status().runtime == RUNTIME_MEMORY
    finally:
        provider.close()


def test_build_docker_fails_closed_without_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    if docker_daemon_ready():
        pytest.skip("Docker is up; cannot assert fail-closed here")
    with pytest.raises(SandboxOpError) as exc:
        build_sandbox_provider(runtime=RUNTIME_DOCKER, allow_insecure_dev=False)
    assert exc.value.code == "runtime_unavailable"


def test_build_kata_fails_closed_without_kata(monkeypatch: pytest.MonkeyPatch) -> None:
    if kata_host_ready():
        pytest.skip("Kata is available; cannot assert fail-closed here")
    with pytest.raises(SandboxOpError) as exc:
        build_sandbox_provider(runtime=RUNTIME_KATA, allow_insecure_dev=False)
    assert exc.value.code == "runtime_unavailable"


def test_build_with_fleet_refuses_oversized_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_FLEET", "n1:2:4:8:20")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_QUOTA", "500:1000:3000")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_KEYS", "k:demo:2")
    with pytest.raises(SandboxOpError) as exc:
        build_sandbox_provider(runtime=RUNTIME_MEMORY, allow_insecure_dev=False)
    assert exc.value.code == "fleet_capacity_insufficient"
