"""A room whose container ends by itself reads failed on GET, wait and list (AB#920).

The Docker guest reads every room's engine state from one ``docker ps -a``,
at most once per CATHEDRAL_SANDBOX_LIVENESS_SECONDS. A running or frozen room
whose container is exited, dead or gone is reported ``failed`` with
``end_reason`` (container_exited or oom_killed) until it is deleted.
"""

from __future__ import annotations

import json

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_provider import SandboxOpError
from cathedral import sandbox_guest
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

K = {"Authorization": "Bearer k"}


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RM_TIMEOUT", "1")
    # No reconcile during a test: only the liveness read may notice an end.
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RECONCILE_SECONDS", "3600")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_LIVENESS_SECONDS", "0")
    return docker


@pytest.fixture
def provider(fake):
    p = DockerGuestProvider()
    try:
        yield p
    finally:
        p.close()


def _room(provider: DockerGuestProvider, digest: str = "0") -> str:
    req = CreateSandboxRequest(
        image=ImageSource(image="alpine:3.20"), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5)
    )
    room = provider.create(req, api_key="k", idempotency=None, body_digest=digest)["id"]
    provider.wait(room, 10)
    return room


def _cid(fake: FakeDocker, room: str) -> str:
    (cid,) = [c for c, v in fake.containers.items() if v["labels"].get("cathedral.sandbox.id") == room]
    return cid


def _remove(fake: FakeDocker, cid: str) -> None:
    state = fake.state
    del state["containers"][cid]
    fake._save(state)  # noqa: SLF001


def _listed(provider: DockerGuestProvider, state: str | None = None) -> dict[str, dict]:
    return {d["id"]: d for d in provider.list(labels=[], state=state)}


def _ps_count(fake: FakeDocker) -> int:
    return len(fake.calls_of("ps"))


def test_an_exited_room_reads_failed_on_get_wait_and_list(fake, provider) -> None:
    alive, exited = _room(provider, "a"), _room(provider, "b")
    fake.set_container(_cid(fake, exited), status="exited", exit_code=1)

    got = provider.get(exited)
    assert got["state"] == "failed" and got["end_reason"] == "container_exited"
    waited = provider.wait(exited, 5)
    assert waited["state"] == "failed" and waited["end_reason"] == "container_exited"
    docs = _listed(provider)
    assert docs[exited]["state"] == "failed" and docs[exited]["end_reason"] == "container_exited"

    # The neighbour is untouched.
    assert provider.get(alive)["state"] == "running" and "end_reason" not in provider.get(alive)
    assert docs[alive]["state"] == "running"
    # The state filter follows what is reported.
    assert set(_listed(provider, "failed")) == {exited}
    assert set(_listed(provider, "running")) == {alive}


def test_an_oom_killed_room_says_so(fake, provider) -> None:
    room = _room(provider)
    fake.set_container(_cid(fake, room), status="exited", exit_code=137, oom_killed=True)

    assert provider.get(room)["state"] == "failed"
    assert provider.get(room)["end_reason"] == "oom_killed"
    assert _listed(provider)[room]["end_reason"] == "oom_killed"


def test_a_room_whose_container_is_gone_reads_failed(fake, provider) -> None:
    room = _room(provider)
    _remove(fake, _cid(fake, room))

    doc = provider.get(room)
    assert doc["state"] == "failed" and doc["end_reason"] == "container_exited"
    assert _listed(provider)[room]["state"] == "failed"
    assert provider.wait(room, 5)["state"] == "failed"


def test_a_frozen_room_stays_frozen_and_an_ended_one_stays_failed(fake, provider) -> None:
    frozen = _room(provider, "f")
    provider.freeze(frozen)
    assert fake.status_of(frozen) == "paused"
    assert provider.get(frozen)["state"] == "frozen"
    assert _listed(provider)[frozen]["state"] == "frozen"

    # A frozen room whose container is then killed has ended too.
    fake.set_container(_cid(fake, frozen), status="exited", exit_code=1)
    assert provider.get(frozen)["state"] == "failed"
    # Ended is kept: a later read that cannot see the container changes nothing.
    fake.set_container(_cid(fake, frozen), status="running")
    assert provider.get(frozen)["state"] == "failed"


def test_an_ended_room_deletes_and_is_404_after(fake, provider) -> None:
    room = _room(provider)
    fake.set_container(_cid(fake, room), status="exited", exit_code=1)
    assert provider.get(room)["state"] == "failed"

    provider.delete(room)
    provider.sweep()
    with pytest.raises(SandboxOpError) as err:
        provider.get(room)
    assert err.value.http_status == 404
    assert room not in provider._ended_rooms  # noqa: SLF001


def test_reads_inside_the_window_share_one_engine_query(fake, provider, monkeypatch) -> None:
    rooms = [_room(provider, str(i)) for i in range(5)]
    provider._liveness_max_age = 60.0  # noqa: SLF001
    provider._liveness_at = None  # noqa: SLF001
    before = _ps_count(fake)

    for _ in range(10):
        provider.get(rooms[0])
        provider.wait(rooms[1], 5)
        provider.list(labels=[], state=None)
        provider.list(labels=[], state="failed")
    # One batch for every room and every call in the window; no inspect for a live room.
    assert _ps_count(fake) - before == 1
    assert not [c for c in fake.calls_of("inspect") if ".State.Running" in " ".join(c)]

    # Inside the window the cached read answers; the next window sees the exit.
    fake.set_container(_cid(fake, rooms[2]), status="exited", exit_code=1)
    assert provider.get(rooms[2])["state"] == "running"
    provider._liveness_at -= 61.0  # noqa: SLF001
    assert provider.get(rooms[2])["state"] == "failed"
    assert _ps_count(fake) - before == 2


def test_an_unreadable_engine_keeps_the_last_states_and_is_asked_once_per_window(fake, provider, monkeypatch) -> None:
    alive, ended = _room(provider, "a"), _room(provider, "b")
    fake.set_container(_cid(fake, ended), status="exited", exit_code=1)
    assert provider.get(ended)["state"] == "failed"

    calls = []

    def broken(owner, **_kw):
        calls.append(owner)
        raise SandboxOpError("docker_list_failed", 502, "docker ps failed: daemon down")

    monkeypatch.setattr(provider._client, "list_labeled_states", broken)  # noqa: SLF001
    provider._liveness_max_age = 60.0  # noqa: SLF001
    provider._liveness_at = None  # noqa: SLF001

    docs = _listed(provider)
    assert docs[alive]["state"] == "running" and docs[ended]["state"] == "failed"
    assert provider.get(alive)["state"] == "running"
    assert provider.wait(ended, 5)["state"] == "failed"
    assert len(calls) == 1


def test_a_room_created_while_the_engine_is_read_is_not_taken_for_gone(fake, provider, monkeypatch) -> None:
    room = _room(provider)
    # The listing ran before the room's container existed, and the room was not
    # running when the read started: it must not be reported failed.
    monkeypatch.setattr(provider, "_live_rooms", lambda: {})
    monkeypatch.setattr(provider._client, "list_labeled_states", lambda owner, **_kw: [])  # noqa: SLF001
    assert provider.get(room)["state"] == "running"
    assert _listed(provider)[room]["state"] == "running"


def test_the_http_answers_say_failed(fake, provider) -> None:
    app = SandboxApplication(provider)
    alive, room = _room(provider, "a"), _room(provider, "b")
    fake.set_container(_cid(fake, room), status="exited", exit_code=1)

    got = json.loads(app.dispatch("GET", f"/v1/sandboxes/{room}", K, b"").body)
    waited = json.loads(app.dispatch("POST", f"/v1/sandboxes/{room}/wait", K, b"{\"timeout_seconds\": 5}").body)
    listed = json.loads(app.dispatch("GET", "/v1/sandboxes?state=failed", K, b"").body)["sandboxes"]
    assert (got["state"], got["end_reason"]) == ("failed", "container_exited")
    assert (waited["state"], waited["end_reason"]) == ("failed", "container_exited")
    assert [d["id"] for d in listed] == [room]
    running = json.loads(app.dispatch("GET", "/v1/sandboxes?state=running", K, b"").body)["sandboxes"]
    assert [d["id"] for d in running] == [alive]


def test_negative_control_without_the_liveness_read_the_exit_is_missed(fake, provider, monkeypatch) -> None:
    """Main's behaviour: with the read off, an exited room reads running. Proves the tests above
    detect the exit only through the liveness read."""
    monkeypatch.setattr(provider, "_refresh_liveness", lambda: None)
    room = _room(provider)
    fake.set_container(_cid(fake, room), status="exited", exit_code=1)
    assert provider.get(room)["state"] == "running"
    assert provider.wait(room, 5)["state"] == "running"
    assert _listed(provider)[room]["state"] == "running"


def test_a_slow_engine_read_does_not_block_other_callers(fake, provider, monkeypatch) -> None:
    """AB#920: one slow docker ps must not make every GET, wait and list wait on it."""
    import threading
    import time as _time

    room = _room(provider)
    started, release = threading.Event(), threading.Event()
    seen_timeouts = []

    def slow(owner, *, timeout=60.0):
        seen_timeouts.append(timeout)
        started.set()
        release.wait(10)
        return []

    monkeypatch.setattr(provider._client, "list_labeled_states", slow)  # noqa: SLF001
    provider._liveness_max_age = 60.0  # noqa: SLF001
    provider._liveness_at = None  # noqa: SLF001
    worker = threading.Thread(target=lambda: provider.get(room), daemon=True)
    worker.start()
    try:
        assert started.wait(5)
        began = _time.monotonic()
        assert provider.get(room)["state"] == "running"  # answered from the last known states
        provider.list(labels=[], state=None)
        assert _time.monotonic() - began < 1.0
    finally:
        release.set()
        worker.join(10)
    assert seen_timeouts == [sandbox_guest.LIVENESS_PS_TIMEOUT_SECONDS]
    # The window starts when the read finished: no second read straight after a slow one.
    provider.get(room)
    assert len(seen_timeouts) == 1


def test_an_ended_room_keeps_oom_killed_when_its_container_is_later_removed(fake, provider) -> None:
    room = _room(provider)
    cid = _cid(fake, room)
    fake.set_container(cid, status="exited", exit_code=137)
    provider._liveness_at = None  # noqa: SLF001
    assert provider.get(room)["state"] == "failed"
    first = provider._ended_rooms.get(room)  # noqa: SLF001
    fake.remove_container(cid) if hasattr(fake, "remove_container") else fake.containers.pop(cid, None)
    provider._liveness_at = None  # noqa: SLF001
    provider.get(room)
    assert provider._ended_rooms.get(room) == first  # noqa: SLF001
