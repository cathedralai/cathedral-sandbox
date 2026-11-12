"""AB#408: list, mkdir and delete under the room's /work, with no path or link escape."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import SandboxApplication

AUTH = {"Authorization": "Bearer k1"}


@pytest.fixture
def app():
    provider = InMemorySandboxProvider()
    a = SandboxApplication(provider)
    try:
        yield a
    finally:
        provider.close()


def _create(a) -> str:
    payload = {"image": "repo/tool:latest", "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 5}}
    r = a.dispatch("POST", "/v1/sandboxes", AUTH, json.dumps(payload).encode())
    assert r.status == 202, r.body
    return json.loads(r.body)["id"]


def _root(app, sid) -> Path:
    return app.provider._sandboxes[sid].root


def _call(app, method, sid, route, path, extra=""):
    return app.dispatch(method, f"/v1/sandboxes/{sid}/{route}?path={path}{extra}", AUTH, b"")


def test_mkdir_then_list_shows_the_entries(app) -> None:
    sid = _create(app)
    assert _call(app, "POST", sid, "mkdir", "/work/a/b").status == 200
    app.dispatch("PUT", f"/v1/sandboxes/{sid}/files?path=/work/a/f.txt", AUTH, b"hello")
    r = _call(app, "GET", sid, "list", "/work/a")
    assert r.status == 200
    entries = {e["name"]: e for e in json.loads(r.body)["entries"]}
    assert entries["b"]["type"] == "dir"
    assert entries["f.txt"]["type"] == "file" and entries["f.txt"]["size"] == 5


def test_mkdir_is_idempotent(app) -> None:
    sid = _create(app)
    assert _call(app, "POST", sid, "mkdir", "/work/d").status == 200
    assert _call(app, "POST", sid, "mkdir", "/work/d").status == 200


def test_delete_file_and_empty_dir(app) -> None:
    sid = _create(app)
    app.dispatch("PUT", f"/v1/sandboxes/{sid}/files?path=/work/d/f", AUTH, b"x")
    assert _call(app, "DELETE", sid, "files", "/work/d/f").status == 200
    assert _call(app, "GET", sid, "files", "/work/d/f").status == 404
    assert _call(app, "DELETE", sid, "files", "/work/d").status == 200
    assert _call(app, "GET", sid, "list", "/work/d").status == 404


def test_delete_of_a_full_dir_needs_recursive(app) -> None:
    sid = _create(app)
    app.dispatch("PUT", f"/v1/sandboxes/{sid}/files?path=/work/d/f", AUTH, b"x")
    assert _call(app, "DELETE", sid, "files", "/work/d").status == 409
    assert _call(app, "DELETE", sid, "files", "/work/d", "&recursive=1").status == 200
    assert _call(app, "GET", sid, "list", "/work/d").status == 404


def test_delete_of_the_work_root_is_refused(app) -> None:
    sid = _create(app)
    assert _call(app, "DELETE", sid, "files", "/work", "&recursive=1").status == 400


def test_dot_dot_is_refused(app) -> None:
    sid = _create(app)
    for route, method in (("list", "GET"), ("mkdir", "POST"), ("files", "DELETE")):
        assert _call(app, method, sid, route, "/work/../etc").status == 400


def test_symlinked_dir_is_not_followed(app, tmp_path) -> None:
    sid = _create(app)
    secret = tmp_path / "outside"
    secret.mkdir()
    (secret / "key").write_text("host secret")
    work = _root(app, sid) / "work"
    work.mkdir(parents=True, exist_ok=True)
    (work / "link").symlink_to(secret)
    assert _call(app, "GET", sid, "list", "/work/link").status == 400
    assert _call(app, "POST", sid, "mkdir", "/work/link/sub").status == 400
    assert _call(app, "DELETE", sid, "files", "/work/link/key").status == 400
    assert (secret / "key").read_text() == "host secret"
    assert not (secret / "sub").exists()


def test_delete_of_a_link_removes_the_link_only(app, tmp_path) -> None:
    sid = _create(app)
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_text("k")
    work = _root(app, sid) / "work"
    work.mkdir(parents=True, exist_ok=True)
    (work / "link").symlink_to(target)
    assert _call(app, "DELETE", sid, "files", "/work/link").status == 200
    assert not (work / "link").is_symlink()
    assert (target / "keep").read_text() == "k"


def test_recursive_delete_does_not_follow_a_link_inside(app, tmp_path) -> None:
    sid = _create(app)
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_text("k")
    work = _root(app, sid) / "work"
    (work / "d").mkdir(parents=True, exist_ok=True)
    (work / "d" / "link").symlink_to(target)
    assert _call(app, "DELETE", sid, "files", "/work/d", "&recursive=1").status == 200
    assert (target / "keep").read_text() == "k"


def test_list_shows_a_link_as_a_link(app, tmp_path) -> None:
    sid = _create(app)
    work = _root(app, sid) / "work"
    work.mkdir(parents=True, exist_ok=True)
    (work / "l").symlink_to(tmp_path)
    entries = json.loads(_call(app, "GET", sid, "list", "/work").body)["entries"]
    assert [e["type"] for e in entries if e["name"] == "l"] == ["symlink"]


def test_guest_provider_confines_to_work() -> None:
    from cathedral.sandbox_guest import _in_work
    from cathedral.sandbox_provider import SandboxOpError

    for bad in ("/etc", "/workspace/x", "/workx", "/tmp/work"):
        with pytest.raises(SandboxOpError):
            _in_work(bad)


KIT = Path(__file__).resolve().parents[1] / "room-kit"
_spec = importlib.util.spec_from_file_location("room_receipts_dirops_t", KIT / "room_receipts.py")
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)


@pytest.mark.parametrize("method,path,action", [
    ("GET", "/v1/sandboxes/r1/list", "dir_list"),
    ("POST", "/v1/sandboxes/r1/mkdir", "dir_make"),
    ("DELETE", "/v1/sandboxes/r1/files", "file_delete"),
])
def test_the_front_signs_the_dir_routes(method, path, action) -> None:
    got = next((a for m, pat, a in rr.SIGNED if m == method and pat.match(path)), None)
    assert got == action
