"""DockerGuestProvider GC against a fake docker CLI (no daemon needed).

Covers defect 9 from the 2026-10-20 pool qualification run: GC dropped the API
record but left the container running.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import LABEL_OWNER, LABEL_SANDBOX_ID, DockerGuestProvider
from cathedral.sandbox_provider import SandboxOpError
from tests.fake_docker_cli import FakeDocker, install


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RM_TIMEOUT", "1")
    return docker


def _req(**over) -> CreateSandboxRequest:
    values = {
        "image": ImageSource(image="alpine:3.20"),
        "resources": Resources(vcpu=1, memory_gib=1, disk_gib=5),
    }
    values.update(over)
    return CreateSandboxRequest(**values)


def _expire(provider: DockerGuestProvider, *ids: str) -> None:
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    with provider._inner._lock:  # noqa: SLF001
        for sid in ids:
            provider._inner._sandboxes[sid].expires_at = past  # noqa: SLF001


def _create(provider: DockerGuestProvider, n: int) -> list[str]:
    return [provider.create(_req(), api_key="k", idempotency=None, body_digest=str(i))["id"] for i in range(n)]


def _resident(provider: DockerGuestProvider) -> int:
    return provider.quota()["usage"]["resident_sandboxes"]


def test_guest_containers_carry_owner_and_sandbox_labels(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        (sid,) = _create(provider, 1)
        (container,) = fake.containers.values()
        assert container["labels"] == {LABEL_OWNER: "default", LABEL_SANDBOX_ID: sid}
    finally:
        provider.close()


def test_one_sweep_removes_many_expired_containers(fake: FakeDocker, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_GC_PARALLELISM", "8")
    provider = DockerGuestProvider()
    try:
        ids = _create(provider, 40)
        keep = _create(provider, 2)
        _expire(provider, *ids)
        fake.set(rm_delay=0.05)

        assert provider.sweep() == 40

        remaining = {c["labels"][LABEL_SANDBOX_ID] for c in fake.containers.values()}
        assert remaining == set(keep)
        assert provider.pending_removals() == {}
        assert _resident(provider) == 2
        state = fake.state
        assert 1 < state["rm_max_active"] <= 8  # parallel, but bounded
        for sid in ids:
            with pytest.raises(SandboxOpError) as err:
                provider.get(sid)
            assert err.value.http_status == 404
    finally:
        provider.close()


def test_rm_timeout_keeps_quota_then_retry_removes(fake: FakeDocker, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RM_TIMEOUT", "0.5")
    provider = DockerGuestProvider()
    try:
        (sid,) = _create(provider, 1)
        (cid,) = fake.containers
        fake.set(rm_hang={cid: 1})  # first docker rm hangs past the timeout
        _expire(provider, sid)

        provider.sweep()

        # The API treats it as gone, but the container still runs and still holds quota.
        with pytest.raises(SandboxOpError):
            provider.get(sid)
        assert provider.list(labels=[], state=None) == []
        assert cid in fake.containers
        assert provider.pending_removals() == {sid: cid}
        assert _resident(provider) == 1
        assert provider.quota()["usage"]["deleting_sandboxes"] == 1

        provider.sweep()

        assert fake.containers == {}
        assert provider.pending_removals() == {}
        assert _resident(provider) == 0
    finally:
        provider.close()


def test_rm_daemon_error_is_not_swallowed(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        (sid,) = _create(provider, 1)
        (cid,) = fake.containers
        fake.set(rm_fail={cid: 2})
        _expire(provider, sid)
        provider.sweep()
        provider.sweep()
        assert cid in fake.containers and _resident(provider) == 1
        provider.sweep()
        assert fake.containers == {} and _resident(provider) == 0
    finally:
        provider.close()


def test_two_concurrent_sweeps_remove_each_container_once(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        ids = _create(provider, 20)
        _expire(provider, *ids)
        fake.set(rm_delay=0.2)
        barrier = threading.Barrier(2)
        counts: list[int] = []

        def run() -> None:
            barrier.wait()
            counts.append(provider.sweep())

        threads = [threading.Thread(target=run) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert sum(counts) == 20  # each record is collected by exactly one sweep
        assert fake.containers == {}
        rm_calls = fake.calls_of("rm", "-f")
        assert len(rm_calls) == 20  # no container removed twice
        assert _resident(provider) == 0
    finally:
        provider.close()


def test_delete_with_failed_rm_keeps_quota_until_sweep(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        (sid,) = _create(provider, 1)
        (cid,) = fake.containers
        fake.set(rm_fail={cid: 1})
        provider.delete(sid)  # still idempotent: no error
        provider.delete(sid)
        assert _resident(provider) == 1 and cid in fake.containers
        provider.sweep()
        assert _resident(provider) == 0 and fake.containers == {}
    finally:
        provider.close()


def test_reconcile_removes_only_our_orphans(fake: FakeDocker, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_OWNER", "room-a")
    fake.add_container("a" * 64, name="cathedral-sbx_lost", labels={LABEL_OWNER: "room-a", LABEL_SANDBOX_ID: "sbx_lost"})
    fake.add_container("b" * 64, name="other-room", labels={LABEL_OWNER: "room-b", LABEL_SANDBOX_ID: "sbx_x"})
    fake.add_container("c" * 64, name="toby-pilot", labels={})
    provider = DockerGuestProvider()
    try:
        (sid,) = _create(provider, 1)
        provider.sweep()
        names = sorted(c["name"] for c in fake.containers.values())
        assert names == sorted([f"cathedral-{sid}", "other-room", "toby-pilot"])
    finally:
        provider.close()


def test_bulk_delete_removes_containers(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        for i in range(5):
            provider.create(_req(labels={"job": "a"}), api_key="k", idempotency=None, body_digest=str(i))
        assert provider.bulk_delete(["job=a"]) == 5
        assert fake.containers == {} and _resident(provider) == 0
    finally:
        provider.close()


def test_idempotent_replay_of_deleted_sandbox_starts_no_container(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        doc = provider.create(_req(), api_key="k", idempotency="replay-key-01", body_digest="b")
        provider.delete(doc["id"])
        with pytest.raises(SandboxOpError) as err:
            provider.create(_req(), api_key="k", idempotency="replay-key-01", body_digest="b")
        assert err.value.http_status == 404
        assert fake.containers == {}
        assert _resident(provider) == 0
    finally:
        provider.close()
