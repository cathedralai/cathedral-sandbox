"""#704: exec on a frozen room is refused with 409 sandbox_frozen before anything reaches the engine.

Before the fix the hotel handed the exec to docker, which refused the paused container, and the route
answered 200 with exit_code 1 and the engine's "is paused" text. Clients read a 200 as a command that ran.
"""

from __future__ import annotations

import json

import pytest

from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

A = {"Authorization": "Bearer hotel-key", "X-Cathedral-Guest": "guest-a"}
ROOM = {"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    return docker


@pytest.fixture
def app(fake):
    provider = DockerGuestProvider()
    yield SandboxApplication(provider)
    provider.close()


def _call(app, method, path, body=None):
    res = app.dispatch(method, path, A, json.dumps(body).encode() if body is not None else b"")
    return res.status, json.loads(res.body) if res.body else None


def _running_room(app) -> str:
    status, doc = _call(app, "POST", "/v1/sandboxes", ROOM)
    assert status in (200, 201, 202), doc
    sid = doc["id"]
    status, doc = _call(app, "GET", f"/v1/sandboxes/{sid}")
    assert status == 200 and doc["state"] == "running", doc
    return sid


def _engine_execs(fake: FakeDocker) -> int:
    return len(fake.calls_of("exec"))


def test_exec_on_a_frozen_room_is_409_sandbox_frozen_and_reaches_no_engine(app, fake) -> None:
    sid = _running_room(app)
    # One exec while running, as in the live probe: the image probes are cached, so the next exec goes
    # straight to docker exec (the path that answered 200 exit_code 1 before #704).
    status, doc = _call(app, "POST", f"/v1/sandboxes/{sid}/exec", {"cmd": ["true"]})
    assert status == 200 and doc["exit_code"] == 0, doc
    status, doc = _call(app, "POST", f"/v1/sandboxes/{sid}/freeze", {})
    assert status == 200 and doc["state"] == "frozen", doc
    before = _engine_execs(fake)
    status, doc = _call(app, "POST", f"/v1/sandboxes/{sid}/exec", {"cmd": ["echo", "ab704"]})
    assert status == 409, doc
    assert doc["error"]["code"] == "sandbox_frozen"
    assert _engine_execs(fake) == before  # refused before docker exec, not after it failed
    # The room is left as it was: still frozen, and it runs commands again after a thaw.
    assert _call(app, "GET", f"/v1/sandboxes/{sid}")[1]["state"] == "frozen"
    status, doc = _call(app, "POST", f"/v1/sandboxes/{sid}/thaw", {})
    assert status == 200 and doc["state"] == "running", doc
    status, doc = _call(app, "POST", f"/v1/sandboxes/{sid}/exec", {"cmd": ["true"]})
    assert status == 200 and doc["exit_code"] == 0, doc


def test_exec_on_a_running_room_is_unchanged(app, fake) -> None:
    sid = _running_room(app)
    before = _engine_execs(fake)
    status, doc = _call(app, "POST", f"/v1/sandboxes/{sid}/exec", {"cmd": ["true"]})
    assert status == 200, doc
    assert doc["exit_code"] == 0 and doc["timed_out"] is False
    assert _engine_execs(fake) > before


def test_exec_on_an_unknown_room_is_still_404(app) -> None:
    status, doc = _call(app, "POST", "/v1/sandboxes/sbx_nope/exec", {"cmd": ["true"]})
    assert status == 404 and doc["error"]["code"] == "sandbox_not_found", doc
