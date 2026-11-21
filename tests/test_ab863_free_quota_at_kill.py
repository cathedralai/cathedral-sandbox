"""AB#863: a deleted room leaves hotel quota when it is killed, not when docker rm ends.

Delete kills the container first. Once docker says it is not running, the
record moves to "stopped_deleting": hidden like "deleting", not counted in
resident quota nor in deleting_sandboxes, counted in removing_sandboxes and
removing_disk_gib. The record itself stays until docker rm confirms (AB#815).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import SandboxOpError
from tests.fake_docker_cli import FakeDocker, install


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RM_TIMEOUT", "2")
    return docker


def _create(provider: DockerGuestProvider, n: int, *, disk: int = 5, labels=None) -> list[str]:
    out = []
    for i in range(n):
        req = CreateSandboxRequest(
            image=ImageSource(image="alpine:3.20"),
            resources=Resources(vcpu=1, memory_gib=1, disk_gib=disk),
            labels=labels or {},
        )
        out.append(provider.create(req, api_key="k", idempotency=None, body_digest=f"{disk}-{i}")["id"])
    return out


def _usage(provider: DockerGuestProvider) -> dict:
    return provider.quota()["usage"]


def test_killed_room_leaves_quota_before_rm_and_keeps_its_record(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        (sid,) = _create(provider, 1, disk=25)
        (cid,) = fake.containers
        fake.set(rm_hang={cid: 1})  # the first docker rm outlives its timeout
        provider.delete(sid)

        usage = _usage(provider)
        assert usage["resident_sandboxes"] == 0
        assert usage["vcpu"] == 0 and usage["memory_gib"] == 0
        assert usage["deleting_sandboxes"] == 0
        assert usage["removing_sandboxes"] == 1
        assert usage["removing_disk_gib"] == 15  # the disk above the 10 GiB default
        # The record and the container stay until rm confirms (AB#815).
        assert provider.has_record(sid)
        assert cid in fake.containers
        assert provider.pending_removals() == {sid: cid}
        assert provider.list(labels=[], state=None) == []
        with pytest.raises(SandboxOpError) as err:
            provider.get(sid)
        assert (err.value.code, err.value.http_status) == ("sandbox_deleting", 409)

        provider.sweep()

        usage = _usage(provider)
        assert usage["removing_sandboxes"] == 0 and usage["removing_disk_gib"] == 0
        assert not provider.has_record(sid) and fake.containers == {}
    finally:
        provider.close()


def test_reconcile_and_a_second_retire_never_drop_a_stopped_room(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        (sid,) = _create(provider, 1)
        (cid,) = fake.containers
        fake.set(rm_hang={cid: 1})
        provider.delete(sid)
        assert _usage(provider)["removing_sandboxes"] == 1
        # A second retire (GC, bulk delete) must not finish_delete while the container exists.
        assert provider._inner.begin_delete(sid) is False  # noqa: SLF001
        assert provider._retire(sid) is False  # noqa: SLF001
        assert provider.bulk_delete(["job=none"]) == 0
        with provider._drain_lock:  # noqa: SLF001
            provider._reconcile_locked()  # noqa: SLF001
        assert provider.has_record(sid) and cid in fake.containers
    finally:
        provider.close()


def test_bulk_delete_skips_rooms_already_stopped(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        ids = _create(provider, 2, labels={"job": "a"})
        first = provider._guests[ids[0]].container_id  # noqa: SLF001
        fake.set(rm_hang={first: 1})
        provider.delete(ids[0])
        assert provider.bulk_delete(["job=a"]) == 1  # only the live room
    finally:
        provider.close()


def test_failed_kill_stays_deleting_and_counted(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        (sid,) = _create(provider, 1)
        (cid,) = fake.containers
        fake.set(kill_fail={cid: 1}, rm_hang={cid: 1})
        provider.delete(sid)

        usage = _usage(provider)
        assert usage["resident_sandboxes"] == 1
        assert usage["deleting_sandboxes"] == 1
        assert usage["removing_sandboxes"] == 0

        provider.sweep()  # the drain retries it like any deleting room
        assert not provider.has_record(sid) and fake.containers == {}
        assert _usage(provider)["resident_sandboxes"] == 0
    finally:
        provider.close()


def test_stopped_rooms_beyond_the_slot_count_count_again(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    # Two slots: at most two killed rooms leave quota.
    provider._inner._limits = replace(provider._inner._limits, running_sandboxes=2)  # noqa: SLF001
    try:
        ids = _create(provider, 2)
        cids = [provider._guests[s].container_id for s in ids]  # noqa: SLF001
        fake.set(rm_hang={c: 1 for c in cids})
        for sid in ids:
            provider.delete(sid)
        usage = _usage(provider)
        assert usage["removing_sandboxes"] == 2
        assert usage["resident_sandboxes"] == 0
        # Two more rooms fit now; their removal hangs too, past the cap of 2.
        more = _create(provider, 2)
        more_cids = [provider._guests[s].container_id for s in more]  # noqa: SLF001
        fake.set(rm_hang={c: 1 for c in cids + more_cids})
        for sid in more:
            provider.delete(sid)
        usage = _usage(provider)
        assert usage["removing_sandboxes"] == 2
        assert usage["deleting_sandboxes"] == 2
        assert usage["resident_sandboxes"] == 2
    finally:
        provider.close()


def test_stopped_room_is_not_billed_twice(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        (sid,) = _create(provider, 1, labels={"job": "x"})
        (cid,) = fake.containers
        with provider._inner._lock:  # noqa: SLF001
            rec = provider._inner._sandboxes[sid]  # noqa: SLF001
            rec.created_at = rec.created_at - timedelta(hours=1)
        fake.set(rm_hang={cid: 1})
        provider.delete(sid)
        assert _usage(provider)["removing_sandboxes"] == 1
        hours = provider.usage(group_by="label.job", labels=[])["groups"]["x"]["sandbox_hours"]
        # One metering line, the tombstone: about 1 h, not 2 h.
        assert 0.9 < hours < 1.5
    finally:
        provider.close()
