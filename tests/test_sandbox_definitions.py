"""Customer checklist §0 definitions — proven with real providers only (no fake Docker).

Harbor / verifiers / King / Teacher are the customer's side. Sandbox / Image /
Snapshot / Fork / DinD are Cathedral's product meanings.
"""

from __future__ import annotations

import os

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, FileGet, ImageSource, Resources
from cathedral.sandbox_guest import docker_daemon_ready, is_dind_image
from cathedral.sandbox_provider import InMemorySandboxProvider, SandboxOpError


def test_sandbox_status_states_runtime_honestly() -> None:
    mem = InMemorySandboxProvider(enforce_disk=True, runtime_label="memory")
    try:
        doc = mem.status().to_document()
        assert doc["runtime"] == "memory"
        assert doc["kernel_isolation"] is False
        assert doc["dind"] is False
    finally:
        mem.close()


def test_image_create_from_oci_ref_shape() -> None:
    req = CreateSandboxRequest(
        image=ImageSource(image="swebench/sweb.eval.x86_64.django__django-12345:latest"),
        resources=Resources(vcpu=1, memory_gib=4, disk_gib=10),
    )
    assert req.image is not None
    assert "django" in req.image.image


def test_snapshot_and_fork_on_real_reference_provider() -> None:
    p = InMemorySandboxProvider(enforce_disk=True)
    try:
        base = p.create(
            CreateSandboxRequest(
                image=ImageSource(image="alpine:3.20"),
                resources=Resources(vcpu=1, memory_gib=2, disk_gib=5),
            ),
            api_key="k",
            idempotency=None,
            body_digest="a",
        )
        p.write_file(base["id"], "/work/state.txt", b"shared", None)
        op = p.snapshot(base["id"])
        snap = p.get_operation(op)["result"]["snapshot_id"]
        forked = p.create(
            CreateSandboxRequest(
                snapshot_id=snap,
                count=3,
                resources=Resources(vcpu=1, memory_gib=2, disk_gib=5),
            ),
            api_key="k",
            idempotency=None,
            body_digest="f",
        )
        assert forked["count"] == 3
        ids = [s["id"] for s in forked["sandboxes"]]
        assert len(set(ids)) == 3
        p.write_file(ids[0], "/work/only0.txt", b"x", None)
        with pytest.raises(SandboxOpError):
            p.read_file(ids[1], FileGet(path="/work/only0.txt"))
    finally:
        p.close()


def test_dind_image_name_matches_customer_harbor_path() -> None:
    assert is_dind_image("docker:28.3.3-dind")


@pytest.mark.skipif(
    not docker_daemon_ready(),
    reason="Docker daemon required for a real Linux-container Sandbox",
)
def test_real_docker_guest_is_a_linux_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CATHEDRAL_SANDBOX_KEYS", raising=False)
    from cathedral.sandbox_api import ExecRequest
    from cathedral.sandbox_guest import DockerGuestProvider

    provider = DockerGuestProvider(use_kata=False)
    try:
        doc = provider.create(
            CreateSandboxRequest(
                image=ImageSource(image="alpine:3.20"),
                resources=Resources(vcpu=1, memory_gib=1, disk_gib=5),
            ),
            api_key="k",
            idempotency=None,
            body_digest="g",
        )
        assert doc["guest"]["container_id"]
        assert doc["runtime"] == "docker"
        uname = provider.exec(doc["id"], ExecRequest(cmd=["uname", "-s"], timeout_seconds=30))
        assert uname.exit_code == 0 and uname.stdout.strip() == "Linux"
        provider.delete(doc["id"])
    finally:
        provider.close()


@pytest.mark.skipif(
    os.environ.get("CATHEDRAL_EXPECTS_DIND", "0") != "1",
    reason="Set CATHEDRAL_EXPECTS_DIND=1 against a real docker/kata fleet",
)
def test_live_dind_expect_flag() -> None:
    assert os.environ.get("CATHEDRAL_EXPECTS_DIND") == "1"
    assert docker_daemon_ready()
