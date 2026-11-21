"""Pull disk floor (AB#861): a burst of pulls cannot fill the room data volume.

21 Nov 2026 const scale report item 7: docker pull had no free-space check, so
a burst of large pulls could fill the scratch the rooms write to.
"""

from __future__ import annotations

import os
import threading
from types import SimpleNamespace

import pytest

from cathedral.sandbox_api import PrefetchRequest
from cathedral.sandbox_provider import SandboxOpError
from cathedral.sandbox_guest import DockerGuestProvider, PullGate
from tests.fake_docker_cli import FakeDocker, install

GIB = 1 << 30


def vfs(free_gib: float):
    return lambda _path: SimpleNamespace(f_bavail=int(free_gib * GIB) // 4096, f_frsize=4096)


def test_pull_refused_under_the_floor() -> None:
    gate = PullGate("/data", 10, 4, statvfs=vfs(9))
    with pytest.raises(SandboxOpError) as err:
        with gate.admit("big:1"):
            pass
    assert err.value.code == "image_store_full" and err.value.http_status == 507
    assert "big:1" in str(err.value)


def test_pull_allowed_over_the_floor_and_releases_its_reservation() -> None:
    gate = PullGate("/data", 10, 4, statvfs=vfs(15))
    with gate.admit("a:1"):
        # 15 free, one pull in flight holds 4: 11 >= 10, a second pull passes.
        with gate.admit("b:1"):
            # Two in flight hold 8: 7 < 10, a third is refused.
            with pytest.raises(SandboxOpError):
                with gate.admit("c:1"):
                    pass
    with gate.admit("c:1"):  # both released
        pass


def test_parallel_pulls_cannot_all_pass_on_one_reading() -> None:
    gate = PullGate("/data", 10, 4, statvfs=vfs(19))
    started, release = threading.Barrier(9), threading.Event()
    outcome: list[str] = []

    def pull(i: int) -> None:
        try:
            with gate.admit(f"img:{i}"):
                outcome.append("ok")
                started.wait(5)
                release.wait(5)
        except SandboxOpError:
            outcome.append("refused")
            started.wait(5)

    threads = [threading.Thread(target=pull, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    started.wait(5)
    release.set()
    for t in threads:
        t.join(5)
    # 19 free: 19, 15, 11 pass; the 4th sees 7 < 10.
    assert outcome.count("ok") == 3 and outcome.count("refused") == 5


def test_floor_zero_or_no_dir_is_no_check() -> None:
    for gate in (PullGate("/data", 0, 4, statvfs=vfs(0)), PullGate(None, 10, 4, statvfs=vfs(0))):
        with gate.admit("x:1"):
            pass


def test_from_env_defaults(monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_PULL_DATA_DIR", "/srv/room-sealed")
    monkeypatch.delenv("CATHEDRAL_PULL_MIN_FREE_GIB", raising=False)
    monkeypatch.delenv("CATHEDRAL_PULL_RESERVE_GIB", raising=False)
    gate = PullGate.from_env()
    assert gate.data_dir == "/srv/room-sealed" and gate.min_free == 10 * GIB and gate.reserve == 4 * GIB
    monkeypatch.delenv("CATHEDRAL_PULL_DATA_DIR")
    assert PullGate.from_env().data_dir is None


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    monkeypatch.setenv("CATHEDRAL_PULL_DATA_DIR", str(tmp_path))
    return docker


def test_prefetch_of_a_new_image_on_a_full_volume_is_refused(fake, monkeypatch) -> None:
    monkeypatch.setattr(os, "statvfs", vfs(2))
    p = DockerGuestProvider()
    try:
        with pytest.raises(SandboxOpError) as err:
            p.prefetch(PrefetchRequest(images=("ghcr.io/acme/big:1",)))
        assert err.value.code == "image_store_full"
        assert "ghcr.io/acme/big:1" not in fake.state["images"]
    finally:
        p.close()


def test_refresh_of_a_local_image_is_not_refused(fake, monkeypatch) -> None:
    # Guest B's grant pull of an image guest A already pulled must not become a 403.
    monkeypatch.setattr(os, "statvfs", vfs(2))
    p = DockerGuestProvider()
    try:
        p.prefetch(PrefetchRequest(images=("alpine:3.20",)))
    finally:
        p.close()
