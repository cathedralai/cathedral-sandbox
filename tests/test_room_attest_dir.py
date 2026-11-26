"""The room API side of the in-room SNP report call (AB#1001, docs/IN_ROOM_REPORT_CALL.md).

On a dedicated hotel with CATHEDRAL_ROOM_ATTEST_DIR set, each room gets a fresh, empty
directory under it, bind-mounted read-only at /run/cathedral. The receipts front puts the
room's attest.sock there. The directory goes the moment the room is retired, and
reconcile drops any left by a lost room. Shared hotels never get the directory or mount.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

KEY = "hotel-key"
A = {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": "guest-a"}
ROOM = {"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    return docker


def _app(monkeypatch, root: Path | None, *, tenancy: str | None = "dedicated"):
    monkeypatch.delenv("CATHEDRAL_SEALED_SECRETS_DIR", raising=False)
    if tenancy is None:
        monkeypatch.delenv("CATHEDRAL_HOTEL_TENANCY", raising=False)
    else:
        monkeypatch.setenv("CATHEDRAL_HOTEL_TENANCY", tenancy)
    if root is None:
        monkeypatch.delenv("CATHEDRAL_ROOM_ATTEST_DIR", raising=False)
    else:
        root.mkdir(mode=0o700, exist_ok=True)
        monkeypatch.setenv("CATHEDRAL_ROOM_ATTEST_DIR", str(root))
    provider = DockerGuestProvider()
    return provider, SandboxApplication(provider)


def call(app, method, path, body=None):
    raw = b"" if body is None else json.dumps(body).encode()
    res = app.dispatch(method, path, A, raw)
    return res.status, json.loads(res.body) if res.body else None


def attest_mounts(fake) -> list[str]:
    run = [c for c in fake.calls_of("run") if "--name" in c][-1]
    mounts = [run[i + 1] for i, p in enumerate(run) if p == "--mount"]
    return [m for m in mounts if "target=/run/cathedral" in m]


def test_dedicated_room_mounts_its_own_empty_directory_read_only(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-attest"
    provider, app = _app(monkeypatch, root)
    try:
        status, doc = call(app, "POST", "/v1/sandboxes", ROOM)
        assert status == 202, doc
        room = root / doc["id"]
        assert attest_mounts(fake) == [f"type=bind,source={room.resolve()},target=/run/cathedral,readonly"]
        assert room.is_dir() and not any(room.iterdir())
        assert stat.S_IMODE(room.stat().st_mode) == 0o755
        _, other = call(app, "POST", "/v1/sandboxes", ROOM)
        assert attest_mounts(fake) == [
            f"type=bind,source={(root / other['id']).resolve()},target=/run/cathedral,readonly"]
    finally:
        provider.close()


@pytest.mark.parametrize("tenancy", [None, "shared", "Dedicated-ish"])
def test_shared_hotel_never_gets_the_directory_or_mount(fake, tmp_path, monkeypatch, tenancy) -> None:
    root = tmp_path / "room-attest"
    provider, app = _app(monkeypatch, root, tenancy=tenancy)
    try:
        status, doc = call(app, "POST", "/v1/sandboxes",
                           {**ROOM, "labels": {"cathedral.tenancy": "dedicated"}})
        assert status == 202, doc
        assert attest_mounts(fake) == []
        assert list(root.iterdir()) == []
    finally:
        provider.close()


def test_dedicated_hotel_without_the_dir_setting_mounts_nothing(fake, tmp_path, monkeypatch) -> None:
    provider, app = _app(monkeypatch, None)
    try:
        status, doc = call(app, "POST", "/v1/sandboxes", ROOM)
        assert status == 202, doc
        assert attest_mounts(fake) == []
    finally:
        provider.close()


def test_a_leftover_socket_is_removed_before_the_room_starts(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-attest"
    provider, app = _app(monkeypatch, root)
    try:
        real = provider._make_attest_dir  # noqa: SLF001

        def plant_then_make(sandbox_id: str) -> None:
            (root / sandbox_id).mkdir()
            (root / sandbox_id / "attest.sock").write_text("from an earlier room")
            real(sandbox_id)

        monkeypatch.setattr(provider, "_make_attest_dir", plant_then_make)
        status, doc = call(app, "POST", "/v1/sandboxes", ROOM)
        assert status == 202 and not any((root / doc["id"]).iterdir())
    finally:
        provider.close()


def test_delete_removes_the_directory_at_once(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-attest"
    provider, app = _app(monkeypatch, root)
    try:
        _, doc = call(app, "POST", "/v1/sandboxes", ROOM)
        room = root / doc["id"]
        (room / "attest.sock").write_text("made by the front")
        status, _ = call(app, "DELETE", f"/v1/sandboxes/{doc['id']}")
        assert status == 204
        assert not room.exists()
    finally:
        provider.close()


def test_a_failed_start_removes_the_directory(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-attest"
    provider, app = _app(monkeypatch, root)
    try:
        def boom(*_a, **_k):
            raise RuntimeError("docker run failed")

        monkeypatch.setattr(provider, "_start_guest_mounted", boom)
        with pytest.raises(RuntimeError):
            request = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"),
                                           resources=Resources(vcpu=1, memory_gib=1, disk_gib=5))
            provider._start_guest({"id": "sbx_failedstart01"}, request)  # noqa: SLF001
        assert not (root / "sbx_failedstart01").exists()
    finally:
        provider.close()


def test_reconcile_drops_the_directory_of_a_room_with_no_record(fake, tmp_path, monkeypatch) -> None:
    root = tmp_path / "room-attest"
    provider, app = _app(monkeypatch, root)
    try:
        _, doc = call(app, "POST", "/v1/sandboxes", ROOM)
        lost = root / "sbx_lostlostlost"
        lost.mkdir()
        (lost / "attest.sock").write_text("a room this API no longer knows")
        assert provider._sweep_attest_dirs() == 1  # noqa: SLF001
        assert not lost.exists()
        assert (root / doc["id"]).is_dir()
    finally:
        provider.close()
