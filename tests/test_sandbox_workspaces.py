"""Persistent, versioned workspaces (#305) through the hotel API.

The provider runs against the fake docker CLI. The fake runs the workspace
helper container as a copy on the host paths of its mounts.

Most tests are negative: one guest must never see, mount, version, roll back
or delete the workspace of another guest, and the answer is 404 (not 403),
so a guest cannot learn that a name exists.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cathedral.sandbox_api import SandboxContractError, WorkspaceSpec
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_server import SandboxApplication
from cathedral.sandbox_workspaces import LocalCopier, WorkspaceStore, mount_options_safe, owner_id
from tests.fake_docker_cli import FakeDocker, install

KEY = "hotel-key"
A = {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": "guest-a"}
B = {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": "guest-b"}
ROOM = {"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    docker = install(tmp_path, monkeypatch)
    docker.add_image("alpine:3.20")
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_MOUNT_CHECK", "0")
    return docker


@pytest.fixture
def app(fake):
    provider = DockerGuestProvider()
    application = SandboxApplication(provider)
    yield application
    provider.close()


def call(app, method, path, headers, body=None):
    raw = b"" if body is None else json.dumps(body).encode()
    res = app.dispatch(method, path, headers, raw)
    doc = json.loads(res.body) if res.body else None
    return res.status, doc


def err(doc) -> str:
    return doc["error"]["code"]


def room(app, headers, workspace, **extra):
    body = {**ROOM, "workspace": workspace, **extra}
    return call(app, "POST", "/v1/sandboxes", headers, body)


def data_dir(app, headers, name) -> Path:
    store = app.provider.workspace_store
    owner = owner_id(KEY, headers["X-Cathedral-Guest"])
    return store._dir(owner, name) / "data"  # noqa: SLF001


def run_mounts(fake) -> list[str]:
    run = [c for c in fake.calls_of("run") if "--name" in c][-1]
    return [run[i + 1] for i, p in enumerate(run) if p == "--mount"]


# ---------------------------------------------------------------- happy path

def test_room_mounts_its_workspace_read_write(app, fake) -> None:
    status, doc = call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    assert status == 201 and doc["name"] == "repo" and doc["versions"] == []
    status, doc = room(app, A, "repo")
    assert status == 202, doc
    assert doc["workspace"] == {"name": "repo", "path": "/workspace", "version_on_delete": False}
    source = data_dir(app, A, "repo").resolve()
    assert run_mounts(fake) == [f"type=bind,source={source},target=/workspace"]
    status, ws = call(app, "GET", "/v1/workspaces/repo", A)
    assert ws["in_use"] is True and ws["rooms"] == [doc["id"]]


def test_custom_mount_path(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    status, doc = room(app, A, {"name": "repo", "path": "/home/agent/repo"})
    assert status == 202, doc
    assert run_mounts(fake)[0].endswith(",target=/home/agent/repo")


def test_two_rooms_of_one_owner_share_the_workspace(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    _, one = room(app, A, "repo")
    first = run_mounts(fake)
    _, two = room(app, A, "repo")
    assert run_mounts(fake) == first
    _, ws = call(app, "GET", "/v1/workspaces/repo", A)
    assert ws["rooms"] == sorted([one["id"], two["id"]])


def test_room_without_workspace_mounts_none(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    status, _ = call(app, "POST", "/v1/sandboxes", A, ROOM)
    assert status == 202
    assert run_mounts(fake) == []


def test_version_and_rollback(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    data = data_dir(app, A, "repo")
    (data / "file.txt").write_text("v1")
    status, v = call(app, "POST", "/v1/workspaces/repo/versions", A, {"label": "first"})
    assert status == 201 and v["version"] == 1 and v["label"] == "first" and v["reason"] == "request"
    (data / "file.txt").write_text("v2")
    (data / "extra.txt").write_text("later")
    status, doc = call(app, "POST", "/v1/workspaces/repo/rollback", A, {"version": 1})
    assert status == 200 and doc["rolled_back_to"] == 1
    assert (data / "file.txt").read_text() == "v1"
    assert not (data / "extra.txt").exists()
    _, versions = call(app, "GET", "/v1/workspaces/repo/versions", A)
    assert [x["version"] for x in versions["versions"]] == [1]
    # Copies run in the helper container with no network.
    helper = fake.state["helpers"][-1]
    assert helper[:5] == ["run", "--rm", "--network", "none", "--label"]


def test_rollback_to_unknown_version_is_404(app) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    status, doc = call(app, "POST", "/v1/workspaces/repo/rollback", A, {"version": 7})
    assert status == 404 and err(doc) == "version_not_found"


def test_delete_of_last_room_keeps_the_workspace_and_its_files(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    _, doc = room(app, A, "repo")
    (data_dir(app, A, "repo") / "out.txt").write_text("result")
    status, _ = call(app, "DELETE", f"/v1/sandboxes/{doc['id']}", A)
    assert status == 204
    status, ws = call(app, "GET", "/v1/workspaces/repo", A)
    assert status == 200 and ws["in_use"] is False and ws["rooms"] == []
    assert (data_dir(app, A, "repo") / "out.txt").read_text() == "result"
    # A new room sees the same files.
    status, _ = room(app, A, "repo")
    assert status == 202


def test_version_on_delete(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    _, doc = room(app, A, {"name": "repo", "version_on_delete": True})
    (data_dir(app, A, "repo") / "out.txt").write_text("result")
    call(app, "DELETE", f"/v1/sandboxes/{doc['id']}", A)
    _, ws = call(app, "GET", "/v1/workspaces/repo", A)
    assert [(v["version"], v["reason"]) for v in ws["versions"]] == [(1, "room_delete")]


def test_workspace_survives_an_api_restart(fake, tmp_path) -> None:
    first = DockerGuestProvider()
    call(SandboxApplication(first), "POST", "/v1/workspaces", A, {"name": "repo"})
    first.close()
    second = DockerGuestProvider()
    try:
        status, doc = call(SandboxApplication(second), "GET", "/v1/workspaces", A)
        assert status == 200 and [w["name"] for w in doc["workspaces"]] == ["repo"]
    finally:
        second.close()


# ---------------------------------------------------------------- isolation (negative)

def test_other_guest_cannot_see_mount_version_rollback_or_delete(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    call(app, "POST", "/v1/workspaces/repo/versions", A, {})
    (data_dir(app, A, "repo") / "secret.txt").write_text("guest a data")

    status, doc = call(app, "GET", "/v1/workspaces", B)
    assert status == 200 and doc["workspaces"] == []
    for method, path, body in (
        ("GET", "/v1/workspaces/repo", None),
        ("GET", "/v1/workspaces/repo/versions", None),
        ("POST", "/v1/workspaces/repo/versions", {}),
        ("POST", "/v1/workspaces/repo/rollback", {"version": 1}),
        ("DELETE", "/v1/workspaces/repo", None),
    ):
        status, doc = call(app, method, path, B, body)
        assert (status, err(doc)) == (404, "workspace_not_found"), (method, path)

    runs_before = len(fake.calls_of("run"))
    status, doc = room(app, B, "repo")
    assert (status, err(doc)) == (404, "workspace_not_found")
    assert len(fake.calls_of("run")) == runs_before  # no container started
    assert app.provider.quota()["usage"]["resident_sandboxes"] == 0

    # A's workspace is intact.
    status, ws = call(app, "GET", "/v1/workspaces/repo", A)
    assert status == 200 and len(ws["versions"]) == 1
    assert (data_dir(app, A, "repo") / "secret.txt").read_text() == "guest a data"


def test_same_name_for_two_guests_is_two_workspaces(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    status, _ = call(app, "POST", "/v1/workspaces", B, {"name": "repo"})
    assert status == 201
    assert data_dir(app, A, "repo") != data_dir(app, B, "repo")
    room(app, B, "repo")
    mounts = run_mounts(fake)
    assert mounts == [f"type=bind,source={data_dir(app, B, 'repo').resolve()},target=/workspace"]
    assert str(data_dir(app, A, "repo").resolve()) not in json.dumps(fake.calls_of("run")[-1])


def test_other_hotel_key_with_the_same_guest_id_is_another_owner(app) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    assert owner_id("other-key", "guest-a") != owner_id(KEY, "guest-a")


def test_label_owner_is_used_when_the_header_is_absent(app, fake) -> None:
    # Through the broker a create carries the guest in the broker_guest label.
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    plain = {"Authorization": f"Bearer {KEY}"}
    status, _ = room(app, plain, "repo", labels={"broker_guest": "guest-a"})
    assert status == 202
    status, doc = room(app, plain, "repo", labels={"broker_guest": "guest-b"})
    assert (status, err(doc)) == (404, "workspace_not_found")


@pytest.mark.parametrize("name", ["..", "../repo", "a/b", "%2e%2e", "..%2Frepo", ".hidden", "Repo", "", "a" * 64, "a.b"])
def test_bad_names_fail(app, fake, name) -> None:
    status, doc = call(app, "POST", "/v1/workspaces", A, {"name": name})
    assert status == 400 and err(doc) == "invalid_workspace_name"
    status, doc = room(app, A, name) if name else (400, {"error": {"code": "invalid_workspace_name"}})
    assert status == 400 and err(doc) == "invalid_workspace_name"
    root = Path(app.provider.workspace_store.root)
    # Nothing was made outside an owner directory.
    assert all(p.parent == root for p in root.iterdir())


@pytest.mark.parametrize("path", ["%2e%2e", "..%2F..%2Fetc"])
def test_bad_names_in_the_url_fail(app, path) -> None:
    status, doc = call(app, "GET", f"/v1/workspaces/{path}", A)
    assert status == 400 and err(doc) == "invalid_workspace_name"


@pytest.mark.parametrize("target", ["/", "/proc", "/proc/1", "/dev/sda", "/work", "/etc/x", "relative", "/a/../etc", "/a//b"])
def test_bad_mount_paths_fail(target) -> None:
    with pytest.raises(SandboxContractError) as exc:
        WorkspaceSpec(name="repo", path=target)
    assert exc.value.code == "invalid_workspace_path"


def test_guest_header_with_bad_characters_fails(app) -> None:
    bad = {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": "a/../b"}
    status, doc = call(app, "GET", "/v1/workspaces", bad)
    assert status == 400 and err(doc) == "invalid_guest"


def test_delete_and_rollback_refuse_while_a_room_mounts_it(app) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    call(app, "POST", "/v1/workspaces/repo/versions", A, {})
    room(app, A, "repo")
    status, doc = call(app, "DELETE", "/v1/workspaces/repo", A)
    assert (status, err(doc)) == (409, "workspace_in_use")
    status, doc = call(app, "POST", "/v1/workspaces/repo/rollback", A, {"version": 1})
    assert (status, err(doc)) == (409, "workspace_in_use")


def test_delete_removes_files_and_versions(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    (data_dir(app, A, "repo") / "f").write_text("x")
    call(app, "POST", "/v1/workspaces/repo/versions", A, {})
    path = data_dir(app, A, "repo").parent
    status, _ = call(app, "DELETE", "/v1/workspaces/repo", A)
    assert status == 204 and not path.exists()
    status, doc = call(app, "GET", "/v1/workspaces/repo", A)
    assert (status, err(doc)) == (404, "workspace_not_found")


def test_failed_room_start_releases_the_mount(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    fake.set(run_fail_images=["alpine:3.20"])
    status, _ = room(app, A, "repo")
    assert status == 502
    _, ws = call(app, "GET", "/v1/workspaces/repo", A)
    assert ws["in_use"] is False


def test_failed_helper_copy_leaves_no_version(app, fake) -> None:
    call(app, "POST", "/v1/workspaces", A, {"name": "repo"})
    fake.set(helper_fail=True)
    status, doc = call(app, "POST", "/v1/workspaces/repo/versions", A, {})
    assert status == 502 and err(doc) == "workspace_copy_failed"
    assert "No space" not in doc["error"]["message"]  # helper output stays out of answers
    _, ws = call(app, "GET", "/v1/workspaces/repo", A)
    assert ws["versions"] == []


# ---------------------------------------------------------------- quota

def test_workspace_and_version_limits(fake, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_MAX_PER_OWNER", "2")
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_MAX_VERSIONS", "1")
    provider = DockerGuestProvider()
    app = SandboxApplication(provider)
    try:
        assert call(app, "POST", "/v1/workspaces", A, {"name": "one"})[0] == 201
        assert call(app, "POST", "/v1/workspaces", A, {"name": "two"})[0] == 201
        status, doc = call(app, "POST", "/v1/workspaces", A, {"name": "three"})
        assert (status, err(doc)) == (409, "workspace_limit")
        # The limit is per owner: guest B still has room.
        assert call(app, "POST", "/v1/workspaces", B, {"name": "three"})[0] == 201
        assert call(app, "POST", "/v1/workspaces/one/versions", A, {})[0] == 201
        status, doc = call(app, "POST", "/v1/workspaces/one/versions", A, {})
        assert (status, err(doc)) == (409, "version_limit")
        status, doc = call(app, "POST", "/v1/workspaces", A, {"name": "one"})
        assert (status, err(doc)) == (409, "workspace_exists")
    finally:
        provider.close()


# ---------------------------------------------------------------- hotel settings

def test_no_workspace_root_means_501(tmp_path, monkeypatch) -> None:
    fake = install(tmp_path, monkeypatch)
    fake.add_image("alpine:3.20")
    provider = DockerGuestProvider()
    app = SandboxApplication(provider)
    try:
        status, doc = call(app, "GET", "/v1/workspaces", A)
        assert (status, err(doc)) == (501, "workspaces_unavailable")
        status, doc = room(app, A, "repo")
        assert (status, err(doc)) == (501, "workspaces_unavailable")
        assert fake.calls_of("run") == []
    finally:
        provider.close()


def test_unsafe_mount_turns_workspaces_off(tmp_path) -> None:
    mountinfo = tmp_path / "mountinfo"
    root = tmp_path / "ws"
    root.mkdir()
    mountinfo.write_text(f"36 1 8:1 / {tmp_path} rw,relatime - xfs /dev/sda1 rw\n")
    assert mount_options_safe(root, str(mountinfo)) == (False, "the workspace root mount lacks nosuid,nodev,noexec")
    mountinfo.write_text(
        f"36 1 8:1 / {tmp_path} rw,relatime - xfs /dev/sda1 rw\n"
        f"37 36 8:1 /ws {root} rw,nosuid,nodev,noexec,relatime - xfs /dev/sda1 rw\n"
    )
    assert mount_options_safe(root, str(mountinfo)) == (True, "ok")
    store = WorkspaceStore(tmp_path / "other", LocalCopier(), check_mount=True)
    if store.disabled_reason is not None:  # the test host has no such mount
        with pytest.raises(Exception) as exc:
            store.create("o", "repo")
        assert getattr(exc.value, "code", None) == "workspaces_unavailable"


def test_local_copier_does_not_follow_symlinks(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "host-file").write_text("host")
    store = WorkspaceStore(tmp_path / "ws", LocalCopier(), check_mount=False)
    store.create("o", "repo")
    data = store._dir("o", "repo") / "data"  # noqa: SLF001
    (data / "link").symlink_to(outside)
    store.version("o", "repo")
    copied = store._dir("o", "repo") / "versions" / "1" / "link"  # noqa: SLF001
    assert copied.is_symlink()
    store.delete("o", "repo")
    assert (outside / "host-file").read_text() == "host"
