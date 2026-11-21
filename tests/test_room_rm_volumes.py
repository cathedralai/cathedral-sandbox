"""Room removal also removes the room's anonymous volumes.

docker:dind declares VOLUME /var/lib/docker, so each DinD room gets an
anonymous volume on the hotel data disk. 'docker rm -f' without -v left it
behind after every delete; on c46-sealed-2 (19 Nov 2026) deleted Ditto build
rooms filled 99 of 100 GiB and new rooms failed with 'no space left on device'.
"""

from __future__ import annotations

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import ROOM_RM_FLAGS, DockerGuestProvider
from tests.fake_docker_cli import FakeDocker, install


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    docker.add_image("docker:27-dind")
    monkeypatch.setenv("CATHEDRAL_ALLOW_PRIVILEGED_DIND", "1")
    monkeypatch.setenv("CATHEDRAL_SANDBOX_RM_TIMEOUT", "1")
    return docker


def _create(provider: DockerGuestProvider, image: str, n: int = 0) -> str:
    req = CreateSandboxRequest(image=ImageSource(image=image), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5))
    return provider.create(req, api_key="k", idempotency=None, body_digest=f"{image}-{n}")["id"]


def _rm_calls(fake: FakeDocker) -> list[list[str]]:
    return fake.calls_of("rm")


def test_rm_flags_force_and_remove_anonymous_volumes() -> None:
    assert ROOM_RM_FLAGS == ("-f", "-v")


@pytest.mark.parametrize("image", ["docker:27-dind", "alpine:3.20"])
def test_delete_removes_the_container_with_its_anonymous_volumes(fake: FakeDocker, image: str) -> None:
    provider = DockerGuestProvider()
    try:
        sid = _create(provider, image)
        provider.delete(sid)
        calls = _rm_calls(fake)
        assert calls, "delete issued no docker rm"
        assert all(c[1:3] == ["-f", "-v"] for c in calls), calls
        assert fake.containers == {}
    finally:
        provider.close()


def test_best_effort_remove_also_drops_volumes(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        _create(provider, "docker:27-dind")
        (cid,) = fake.containers
        provider._client.remove(cid)  # noqa: SLF001
        (call,) = _rm_calls(fake)
        assert call == ["rm", "-f", "-v", cid]
    finally:
        provider.close()
