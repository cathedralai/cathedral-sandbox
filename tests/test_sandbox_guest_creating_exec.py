"""A command on a room that has no started container is refused, never run as a host process.

DockerGuestProvider hands a room with no guest record to its inner provider, whose exec and process start run a
host subprocess. During a create the room is listed before its container exists, so a caller that
reads the list could reach that path. Exec and process start must answer 409 and run nothing.
"""

from __future__ import annotations

import threading
import uuid

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ExecRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import SandboxOpError
from tests.fake_docker_cli import FakeDocker, install

RES = Resources(vcpu=1, memory_gib=1, disk_gib=5)


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    return docker


@pytest.fixture
def provider(fake):
    p = DockerGuestProvider()
    yield p
    p.close()


@pytest.fixture
def creating_room(provider):
    """(room id, release) for a room whose create is held inside docker run."""
    gate, reached = threading.Event(), threading.Event()
    real = provider._client.create_and_start

    def held(**kw):
        reached.set()
        gate.wait(10)
        return real(**kw)

    provider._client.create_and_start = held
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES)
    worker = threading.Thread(
        target=lambda: provider.create(req, api_key="k", idempotency=None, body_digest="x"), daemon=True)
    worker.start()
    assert reached.wait(10)
    provider._inner._ctx.api_key = "k"
    (room,) = provider.list(labels=(), state=None)
    # The record is listed (as creating, or as running on some paths) before its container exists.
    assert room["state"] in ("creating", "running") and room["id"] not in provider._guests

    def release() -> None:
        gate.set()
        worker.join(10)

    yield room["id"], release
    release()


def test_exec_on_a_creating_room_is_409_and_runs_nothing_on_the_host(provider, creating_room, tmp_path) -> None:
    room, release = creating_room
    marker = tmp_path / ("host-" + uuid.uuid4().hex)
    with pytest.raises(SandboxOpError) as err:
        provider.exec(room, ExecRequest(cmd=["sh", "-c", f"touch {marker}"], timeout_seconds=5))
    assert (err.value.code, err.value.http_status) == ("sandbox_not_running", 409)
    assert not marker.exists()
    release()
    assert provider.get(room)["state"] == "running"


def test_a_process_start_on_a_creating_room_is_409_and_runs_nothing_on_the_host(provider, creating_room, tmp_path) -> None:
    room, _release = creating_room
    marker = tmp_path / ("host-" + uuid.uuid4().hex)
    with pytest.raises(SandboxOpError) as err:
        provider.start_process(room, ExecRequest(cmd=["sh", "-c", f"touch {marker}"], timeout_seconds=5))
    assert (err.value.code, err.value.http_status) == ("sandbox_not_running", 409)
    assert not marker.exists()


def test_exec_on_an_unknown_room_is_still_404(provider) -> None:
    provider._inner._ctx.api_key = "k"
    with pytest.raises(SandboxOpError) as err:
        provider.exec("sbx_nope", ExecRequest(cmd=["true"], timeout_seconds=5))
    assert (err.value.code, err.value.http_status) == ("sandbox_not_found", 404)
