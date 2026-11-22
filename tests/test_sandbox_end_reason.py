"""Why a room ended (AB#864, hotel side).

A room that leaves the hotel records why: deleted, ttl_expired, idle_timeout or
key_revoked. The list answer carries the rooms that ended in the last 10 min
under "ended", scoped to the caller key, and the API start time. A GET of an
ended room stays 404 but says why. A room whose container stopped stays listed
(R6) with container_state and end_reason oom_killed / container_exited.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone

import pytest

from cathedral import sandbox_provider as sp
from cathedral.sandbox_api import ApiKey, CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

K1 = {"Authorization": "Bearer k1"}
K2 = {"Authorization": "Bearer k2"}


def _create(app: SandboxApplication, headers=K1, **body) -> str:
    payload = {"image": "repo/tool:latest", "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 5}}
    payload.update(body)
    r = app.dispatch("POST", "/v1/sandboxes", headers, json.dumps(payload).encode())
    assert r.status == 202, r.body
    return json.loads(r.body)["id"]


def _list(app: SandboxApplication, headers=K1) -> dict:
    r = app.dispatch("GET", "/v1/sandboxes", headers, b"")
    assert r.status == 200, r.body
    return json.loads(r.body)


def _ended(app: SandboxApplication, headers=K1) -> dict[str, dict]:
    return {e["id"]: e for e in _list(app, headers)["ended"]}


@pytest.fixture
def provider():
    p = InMemorySandboxProvider(keys=[ApiKey(key="k1", project="p1"), ApiKey(key="k2", project="p2")])
    try:
        yield p
    finally:
        p.close()


@pytest.fixture
def app(provider) -> SandboxApplication:
    return SandboxApplication(provider)


def _as_operator(p: InMemorySandboxProvider) -> None:
    """No caller key: the operator view, which sees every key's rooms."""
    p._ctx.api_key = None  # noqa: SLF001


def _past(hours: float = 1) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)


# ------------------------------------------------------------------ GC and delete reasons
def test_gc_records_ttl_and_idle_reasons(app, provider) -> None:
    ttl_room = _create(app)
    idle_room = _create(app, idle_timeout_seconds=60)
    with provider._lock:  # noqa: SLF001
        provider._sandboxes[ttl_room].expires_at = _past()  # noqa: SLF001
        provider._sandboxes[idle_room].last_activity_at = _past()  # noqa: SLF001

    ended = _ended(app)

    assert ended[ttl_room]["end_reason"] == "ttl_expired"
    assert ended[idle_room]["end_reason"] == "idle_timeout"
    for room in (ttl_room, idle_room):
        assert datetime.fromisoformat(ended[room]["ended_at"]).tzinfo is not None
        assert set(ended[room]) == {"id", "end_reason", "ended_at"}
    assert _list(app)["sandboxes"] == []


def test_gc_of_a_revoked_key_records_key_revoked(app, provider) -> None:
    room = _create(app, headers=K2)
    provider._keys["k2"] = dataclasses.replace(provider._keys["k2"], revoked=True)  # noqa: SLF001

    assert _ended(app, K1) == {}  # k2's room is not k1's to see
    _as_operator(provider)
    assert {e["id"]: e["end_reason"] for e in provider.ended()} == {room: "key_revoked"}


def test_api_delete_records_deleted_and_get_is_404_with_the_reason(app) -> None:
    room = _create(app)
    assert app.dispatch("DELETE", f"/v1/sandboxes/{room}", K1, b"").status == 204

    assert _ended(app)[room]["end_reason"] == "deleted"
    r = app.dispatch("GET", f"/v1/sandboxes/{room}", K1, b"")
    assert r.status == 404
    err = json.loads(r.body)["error"]
    assert err["code"] == "sandbox_not_found"
    assert err["end_reason"] == "deleted" and err["ended_at"]

    # Another key learns nothing beyond "not found", as for a wrong id.
    other = json.loads(app.dispatch("GET", f"/v1/sandboxes/{room}", K2, b"").body)["error"]
    assert other["code"] == "sandbox_not_found" and "end_reason" not in other


def test_ended_is_scoped_per_key_and_ages_out(app, provider, monkeypatch) -> None:
    mine = _create(app, headers=K1)
    theirs = _create(app, headers=K2)
    for room, headers in ((mine, K1), (theirs, K2)):
        app.dispatch("DELETE", f"/v1/sandboxes/{room}", headers, b"")

    assert set(_ended(app, K1)) == {mine}
    assert set(_ended(app, K2)) == {theirs}
    _as_operator(provider)
    assert {e["id"] for e in provider.ended()} == {mine, theirs}

    later = datetime.now(timezone.utc) + timedelta(minutes=10, seconds=5)
    monkeypatch.setattr(sp, "_now", lambda: later)
    assert _ended(app, K1) == {}
    r = app.dispatch("GET", f"/v1/sandboxes/{mine}", K1, b"")
    assert r.status == 404 and "end_reason" not in json.loads(r.body)["error"]


def test_list_carries_a_fixed_api_start_time(app) -> None:
    first = _list(app)["api_started_at"]
    _create(app)
    assert _list(app)["api_started_at"] == first
    started = datetime.fromisoformat(first)
    assert started.tzinfo is not None
    assert started <= datetime.now(timezone.utc)


# ------------------------------------------------------------------ docker guest
@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RM_TIMEOUT", "1")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RECONCILE_SECONDS", "0")
    return docker


def _guest_room(provider: DockerGuestProvider, digest: str = "0") -> str:
    req = CreateSandboxRequest(
        image=ImageSource(image="alpine:3.20"), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5)
    )
    return provider.create(req, api_key="k", idempotency=None, body_digest=digest)["id"]


def _cid(fake: FakeDocker, room: str) -> str:
    (cid,) = [c for c, v in fake.containers.items() if v["labels"].get("cathedral.sandbox.id") == room]
    return cid


def _docs(provider: DockerGuestProvider) -> dict[str, dict]:
    return {d["id"]: d for d in provider.list(labels=[], state=None)}


def test_a_stopped_container_is_listed_with_its_end_reason(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        alive, exited, oom = (_guest_room(provider, str(i)) for i in range(3))
        fake.set_container(_cid(fake, exited), status="exited", exit_code=1)
        fake.set_container(_cid(fake, oom), status="exited", exit_code=137, oom_killed=True)

        provider.sweep()
        docs = _docs(provider)

        # R6: a dead room is not retired; it stays listed until TTL or idle.
        assert set(docs) == {alive, exited, oom}
        assert docs[alive]["container_state"] == "running" and "end_reason" not in docs[alive]
        assert docs[exited]["container_state"] == "exited"
        assert docs[exited]["end_reason"] == "container_exited"
        assert docs[oom]["container_state"] == "exited"
        assert docs[oom]["end_reason"] == "oom_killed"
        assert provider.get(oom)["end_reason"] == "oom_killed"

        # Bounded: one inspect per dead room, none for a live one, none again.
        inspects = lambda: [c for c in fake.calls_of("inspect") if ".State.Running" in " ".join(c)]  # noqa: E731
        assert len(inspects()) == 2
        provider.sweep()
        assert len(inspects()) == 2
        assert _docs(provider)[exited]["end_reason"] == "container_exited"
    finally:
        provider.close()


def test_guest_gc_and_delete_record_their_reasons(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        expired, deleted = _guest_room(provider, "a"), _guest_room(provider, "b")
        with provider._inner._lock:  # noqa: SLF001
            provider._inner._sandboxes[expired].expires_at = _past()  # noqa: SLF001
        provider.delete(deleted)
        provider.sweep()

        _as_operator(provider._inner)  # noqa: SLF001
        assert {e["id"]: e["end_reason"] for e in provider.ended()} == {
            expired: "ttl_expired",
            deleted: "deleted",
        }
    finally:
        provider.close()
