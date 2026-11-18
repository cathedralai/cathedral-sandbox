"""Byte quota on a room's /work and on workspaces (AB#396).

Unit tests drive a recording quota object. The last test runs the real
xfs_quota on a loop-mounted xfs with prjquota and proves that a write past
the cap fails with ENOSPC; it needs root, mkfs.xfs and xfs_quota.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import SandboxOpError
from cathedral.sandbox_quota import (
    GIB,
    ROOM_IDS,
    WORKSPACE_IDS,
    QuotaUnavailable,
    XfsProjectQuota,
    mount_of,
    pick_id,
)
from cathedral.sandbox_server import SandboxApplication
from cathedral.sandbox_workspaces import owner_id
from tests.fake_docker_cli import FakeDocker, install

REPO = Path(__file__).resolve().parents[1]


class RecordingQuota:
    def __init__(self, fail: set[str] | None = None) -> None:
        self.calls: list[tuple] = []
        self.fail = fail or set()

    def _do(self, op: str, *args) -> None:
        self.calls.append((op, *args))
        if op in self.fail:
            raise QuotaUnavailable(f"{op} refused")

    def assign(self, path, project_id, limit_bytes):
        self._do("assign", Path(path), project_id, limit_bytes)

    def set_limit(self, path, project_id, limit_bytes):
        self._do("set_limit", Path(path), project_id, limit_bytes)

    def clear(self, path, project_id):
        self._do("clear", Path(path), project_id)

    def of(self, op: str) -> list[tuple]:
        return [c for c in self.calls if c[0] == op]


# ---------------------------------------------------------------- module

MOUNTINFO = """\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
40 22 7:0 / /srv/room rw,noatime shared:2 - xfs /dev/loop0 rw,inode64,prjquota
41 40 7:0 /workspaces /srv/room/workspaces rw,nosuid,nodev,noexec shared:2 - xfs /dev/loop0 rw,inode64,prjquota
42 22 7:1 / /srv/plain rw shared:3 - xfs /dev/loop1 rw,inode64,noquota
43 22 7:2 / /srv/with\\040space rw shared:4 - xfs /dev/loop2 rw,pquota
"""


@pytest.fixture
def mountinfo(tmp_path) -> str:
    path = tmp_path / "mountinfo"
    path.write_text(MOUNTINFO)
    return str(path)


def test_mount_of_takes_the_longest_xfs_prjquota_mount(mountinfo) -> None:
    assert mount_of(Path("/srv/room/work/cathedral-sandbox-x/sbx_1"), mountinfo) == "/srv/room"
    assert mount_of(Path("/srv/room/workspaces/abc/repo"), mountinfo) == "/srv/room/workspaces"
    assert mount_of(Path("/srv/with space/a"), mountinfo) == "/srv/with space"


def test_mount_of_refuses_a_volume_without_project_quota(mountinfo) -> None:
    with pytest.raises(QuotaUnavailable, match="not mounted with prjquota"):
        mount_of(Path("/srv/plain/x"), mountinfo)
    with pytest.raises(QuotaUnavailable, match="not xfs"):
        mount_of(Path("/home/x"), mountinfo)


def test_assign_runs_project_then_limit_on_the_mount(mountinfo) -> None:
    seen = []

    def runner(argv, **kwargs):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    quota = XfsProjectQuota(runner=runner, mountinfo=mountinfo)
    quota.assign(Path("/srv/room/work/b/sbx_1"), 0x40000001, 5 * GIB)
    quota.clear(Path("/srv/room/work/b"), 0x40000001)
    assert seen == [
        ["xfs_quota", "-x", "-c", f"project -s -p /srv/room/work/b/sbx_1 {0x40000001}",
         "-c", f"limit -p bhard={5 * GIB} {0x40000001}", "/srv/room"],
        ["xfs_quota", "-x", "-c", f"limit -p bhard=0 {0x40000001}", "/srv/room"],
    ]


def test_a_failed_xfs_quota_raises_without_its_output(mountinfo) -> None:
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "/srv/room/work/secret-name: Operation not permitted")

    with pytest.raises(QuotaUnavailable) as caught:
        XfsProjectQuota(runner=runner, mountinfo=mountinfo).set_limit(Path("/srv/room/x"), 7, 1)
    assert "secret-name" not in str(caught.value) and "exit 1" in str(caught.value)


def test_missing_binary_is_unavailable(mountinfo) -> None:
    quota = XfsProjectQuota(binary="/nonexistent/xfs_quota", mountinfo=mountinfo)
    with pytest.raises(QuotaUnavailable, match="did not run"):
        quota.set_limit(Path("/srv/room/x"), 7, 1)


def test_ids_are_in_their_range_and_avoid_ids_in_use() -> None:
    first = pick_id(ROOM_IDS, set(), seed="0123456789ab")
    assert first in ROOM_IDS and first == pick_id(ROOM_IDS, set(), seed="0123456789ab")
    other = pick_id(ROOM_IDS, {first}, seed="0123456789ab")
    assert other in ROOM_IDS and other != first
    assert pick_id(WORKSPACE_IDS, set()) in WORKSPACE_IDS
    # Docker's overlay2 quota counts up from small ids on the same volume.
    assert ROOM_IDS.start > 1 << 24 and WORKSPACE_IDS.start >= ROOM_IDS.stop


# ---------------------------------------------------------------- room /work

def _req(disk_gib: int = 5) -> CreateSandboxRequest:
    return CreateSandboxRequest(
        image=ImageSource(image="alpine:3.20"), resources=Resources(vcpu=1, memory_gib=1, disk_gib=disk_gib)
    )


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    return docker


def _provider(monkeypatch, quota: RecordingQuota | None) -> DockerGuestProvider:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_WORK_QUOTA", "1" if quota is not None else "0")
    provider = DockerGuestProvider()
    if quota is not None:
        assert isinstance(provider._work_quota, XfsProjectQuota)  # noqa: SLF001
        provider._work_quota = quota  # noqa: SLF001
    return provider


def test_room_dir_is_capped_at_disk_gib_before_the_room_starts(fake, monkeypatch) -> None:
    quota = RecordingQuota()
    provider = _provider(monkeypatch, quota)
    try:
        doc = provider.create(_req(5), api_key="k", idempotency=None, body_digest="a")
        room_dir = Path(provider._inner._sandboxes[doc["id"]].root)  # noqa: SLF001
        [(op, path, project, limit)] = quota.calls
        assert (op, path, limit) == ("assign", room_dir, 5 * GIB)
        assert project in ROOM_IDS
        # /work is inside the capped dir and is what the room binds.
        run = [c for c in fake.calls_of("run") if "--name" in c][-1]
        assert any(str((room_dir / "work").resolve()) in part for part in run)

        provider.delete(doc["id"])
        assert quota.of("clear") == [("clear", room_dir.parent, project)]
        assert provider._work_quota_ids == {}  # noqa: SLF001
    finally:
        provider.close()


def test_two_rooms_get_two_projects(fake, monkeypatch) -> None:
    quota = RecordingQuota()
    provider = _provider(monkeypatch, quota)
    try:
        provider.create(_req(), api_key="k", idempotency=None, body_digest="a")
        provider.create(_req(), api_key="k", idempotency=None, body_digest="b")
        ids = [c[2] for c in quota.of("assign")]
        assert len(set(ids)) == 2
    finally:
        provider.close()


def test_a_cap_that_cannot_be_set_fails_the_create_and_starts_nothing(fake, monkeypatch) -> None:
    quota = RecordingQuota(fail={"assign"})
    provider = _provider(monkeypatch, quota)
    try:
        with pytest.raises(SandboxOpError) as caught:
            provider.create(_req(), api_key="k", idempotency=None, body_digest="a")
        assert caught.value.code == "work_quota_unavailable" and caught.value.http_status == 503
        assert [c for c in fake.calls_of("run") if "--name" in c] == []
        assert provider.quota()["usage"]["resident_sandboxes"] == 0
        assert provider._work_quota_ids == {}  # noqa: SLF001
    finally:
        provider.close()


def test_quota_off_sets_no_cap(fake, monkeypatch) -> None:
    provider = _provider(monkeypatch, None)
    try:
        assert provider._work_quota is None  # noqa: SLF001
        provider.create(_req(), api_key="k", idempotency=None, body_digest="a")
    finally:
        provider.close()


# ---------------------------------------------------------------- workspaces

KEY = "hotel-key"
A = {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": "guest-a"}
ROOM = {"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}


def call(app, method, path, body=None):
    res = app.dispatch(method, path, A, b"" if body is None else json.dumps(body).encode())
    return res.status, (json.loads(res.body) if res.body else None)


@pytest.fixture
def ws_app(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_MOUNT_CHECK", "0")
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_MAX_BYTES", str(2 * GIB))
    provider = DockerGuestProvider()
    quota = RecordingQuota()
    assert isinstance(provider.workspace_store.quota, XfsProjectQuota)
    provider.workspace_store.quota = quota
    app = SandboxApplication(provider)
    yield app, quota
    provider.close()


def _ws_dir(app, name) -> Path:
    return app.provider.workspace_store._dir(owner_id(KEY, A["X-Cathedral-Guest"]), name)  # noqa: SLF001


def test_workspace_create_caps_its_data(ws_app) -> None:
    app, quota = ws_app
    status, _ = call(app, "POST", "/v1/workspaces", {"name": "repo"})
    assert status == 201
    path = _ws_dir(app, "repo")
    [(op, where, project, limit)] = quota.calls
    # data/ only: meta.json and versions/ stay outside, so a full workspace
    # can still be versioned, rolled back and listed.
    assert (op, where, limit) == ("assign", path / "data", 2 * GIB) and project in WORKSPACE_IDS
    assert json.loads((path / "meta.json").read_text())["quota_project"] == project
    assert (path / "versions").is_dir()

    status, doc = call(app, "POST", "/v1/sandboxes", {**ROOM, "workspace": "repo"})
    assert status == 202, doc
    assert quota.of("set_limit") == [("set_limit", path / "data", project, 2 * GIB)]

    call(app, "DELETE", f"/v1/sandboxes/{doc['id']}")
    status, _ = call(app, "DELETE", "/v1/workspaces/repo")
    assert status == 204
    assert quota.of("clear") == [("clear", path.parent, project)]


def test_two_workspaces_get_two_projects(ws_app) -> None:
    app, quota = ws_app
    call(app, "POST", "/v1/workspaces", {"name": "one"})
    call(app, "POST", "/v1/workspaces", {"name": "two"})
    assert len({c[2] for c in quota.of("assign")}) == 2


def test_a_workspace_whose_cap_fails_is_not_made(ws_app) -> None:
    app, quota = ws_app
    quota.fail.add("assign")
    status, doc = call(app, "POST", "/v1/workspaces", {"name": "repo"})
    assert status == 503 and doc["error"]["code"] == "workspace_quota_unavailable"
    assert not _ws_dir(app, "repo").exists()


def test_a_mount_whose_limit_fails_starts_no_room(ws_app, fake) -> None:
    app, quota = ws_app
    call(app, "POST", "/v1/workspaces", {"name": "repo"})
    quota.fail.add("set_limit")
    status, doc = call(app, "POST", "/v1/sandboxes", {**ROOM, "workspace": "repo"})
    assert status == 503 and doc["error"]["code"] == "workspace_quota_unavailable"
    assert [c for c in fake.calls_of("run") if "--name" in c] == []
    _, ws = call(app, "GET", "/v1/workspaces/repo")
    assert ws["in_use"] is False


def test_a_legacy_workspace_mounts_uncapped(ws_app) -> None:
    app, quota = ws_app
    call(app, "POST", "/v1/workspaces", {"name": "repo"})
    path = _ws_dir(app, "repo")
    meta = json.loads((path / "meta.json").read_text())
    del meta["quota_project"]
    (path / "meta.json").write_text(json.dumps(meta))
    status, _ = call(app, "POST", "/v1/sandboxes", {**ROOM, "workspace": "repo"})
    assert status == 202
    assert len(quota.of("assign")) == 1 and quota.of("set_limit") == []
    status, _ = call(app, "DELETE", "/v1/workspaces/repo")
    assert status in (204, 409)
    assert quota.of("clear") == []


def test_workspaces_are_off_when_the_volume_has_no_project_quota(fake, tmp_path, monkeypatch) -> None:
    from cathedral.sandbox_workspaces import LocalCopier, WorkspaceStore

    mount_ok = lambda path: (True, "ok")  # noqa: E731
    monkeypatch.setattr("cathedral.sandbox_workspaces.mount_options_safe", mount_ok)
    store = WorkspaceStore(tmp_path / "ws", LocalCopier(), max_bytes=GIB, quota=RecordingQuota())
    # tmp_path is not an xfs with prjquota.
    assert store.disabled_reason is not None and "CATHEDRAL_WORKSPACE_MAX_BYTES" in store.disabled_reason
    with pytest.raises(SandboxOpError) as caught:
        store.create("o", "repo")
    assert caught.value.http_status == 503


def test_api_write_that_hits_the_cap_is_413(fake, monkeypatch) -> None:
    provider = _provider(monkeypatch, None)
    try:
        doc = provider.create(_req(), api_key="k", idempotency=None, body_digest="a")

        def full(*args, **kwargs):
            raise OSError(errno.EDQUOT, "Disk quota exceeded")

        monkeypatch.setattr("cathedral.sandbox_provider._open_beneath", full)
        with pytest.raises(SandboxOpError) as caught:
            provider.write_file(doc["id"], "/work/big", b"x", None)
        assert caught.value.code == "disk_quota_exceeded" and caught.value.http_status == 413
    finally:
        provider.close()


def test_no_max_bytes_means_no_quota(fake, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_MOUNT_CHECK", "0")
    monkeypatch.delenv("CATHEDRAL_WORKSPACE_MAX_BYTES", raising=False)
    provider = DockerGuestProvider()
    try:
        assert provider.workspace_store.quota is None
    finally:
        provider.close()


# ---------------------------------------------------------------- kit

def test_kit_turns_the_quota_on_and_lets_the_api_set_it() -> None:
    unit = (REPO / "room-kit/install.sh").read_text()
    assert "AmbientCapabilities=CAP_SYS_ADMIN\nCapabilityBoundingSet=CAP_SYS_ADMIN" in unit
    profile = (REPO / "room-kit/profiles/v1.sh").read_text()
    assert "CATHEDRAL_SANDBOX_WORK_QUOTA=1" in profile
    assert "CATHEDRAL_WORKSPACE_MAX_BYTES=${ROOM_WORKSPACE_MAX_BYTES:-10737418240}" in profile
    sealed = (REPO / "room-kit/sealed/sealed-data.sh").read_text()
    assert "mount -t xfs -o nosuid,nodev,noexec,noatime,prjquota" in sealed


# ---------------------------------------------------------------- real xfs

def _tool(name: str) -> str | None:
    return shutil.which(name) or shutil.which(name, path="/usr/sbin:/sbin")


@pytest.mark.skipif(
    os.geteuid() != 0 or not _tool("mkfs.xfs") or not _tool("xfs_quota") or not Path("/dev/loop-control").exists(),
    reason="needs root, mkfs.xfs, xfs_quota and loop devices",
)
def test_real_xfs_write_past_the_cap_is_enospc(tmp_path) -> None:
    image, mnt = tmp_path / "img", tmp_path / "mnt"
    with open(image, "wb") as fh:
        fh.truncate(300 * 1024 * 1024)
    subprocess.run([_tool("mkfs.xfs"), "-q", str(image)], check=True)
    mnt.mkdir()
    mounted = subprocess.run(["mount", "-o", "loop,prjquota", str(image), str(mnt)], capture_output=True)
    if mounted.returncode != 0:
        pytest.skip("loop mount not permitted here")
    try:
        room = mnt / "work" / "sbx_1"
        (room / "work").mkdir(parents=True)
        quota = XfsProjectQuota(binary=_tool("xfs_quota"))
        project = pick_id(ROOM_IDS, set(), seed="1")
        quota.assign(room, project, 4 * 1024 * 1024)
        # A file made later, deep in /work, inherits the project.
        (room / "work" / "deep").mkdir()
        with pytest.raises(OSError) as caught:
            with open(room / "work" / "deep" / "fill", "wb") as fh:
                for _ in range(8):
                    fh.write(b"\0" * 1024 * 1024)
                    fh.flush()
                    os.fsync(fh.fileno())
        assert caught.value.errno in (errno.ENOSPC, errno.EDQUOT)
        # Outside the capped dir the volume still takes writes.
        (mnt / "other").write_bytes(b"\0" * 8 * 1024 * 1024)
        shutil.rmtree(room)
        quota.clear(mnt / "work", project)
    finally:
        subprocess.run(["umount", str(mnt)], check=False)
