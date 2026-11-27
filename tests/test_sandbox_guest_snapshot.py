"""DockerGuestProvider snapshot and fork against a fake docker CLI.

Defects from run 5 (2026-10-20):
1. a fork from a snapshot this host does not have started the default image;
2. a snapshot could not leave its host (no push to a registry);
3. snapshot size_bytes measured only the /work archive.
"""

from __future__ import annotations

import datetime as _dt

import hashlib
import importlib.util
import json
import os
import threading
from pathlib import Path

import pytest

from cathedral import sandbox_provider
from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import InMemorySandboxProvider, SandboxOpError
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

RES = Resources(vcpu=1, memory_gib=1, disk_gib=5)
AUTH = {"username": "robot", "password": "s3cret-token"}


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


def _source(provider) -> str:
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES)
    return provider.create(req, api_key="k", idempotency=None, body_digest="src")["id"]


def _fork(provider, ref: str, digest: str = "fork"):
    return provider.create(CreateSandboxRequest(snapshot_id=ref, resources=RES), api_key="k", idempotency=None, body_digest=digest)


def _snapshot(provider, sid: str, **kw) -> dict:
    return provider.get_operation(provider.snapshot(sid, **kw))["result"]


# ---------------------------------------------------------------- defect 1
def test_fork_of_unknown_snapshot_is_404_and_starts_nothing(fake, provider) -> None:
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, "snap_000000000000")
    assert (err.value.code, err.value.http_status) == ("snapshot_not_found", 404)
    assert fake.calls_of("run") == []
    assert provider.quota()["usage"]["resident_sandboxes"] == 0


def test_fork_by_name_uses_the_committed_image(fake, provider) -> None:
    sid = _source(provider)
    result = _snapshot(provider, sid, name="busy")
    doc = _fork(provider, "busy")
    assert doc["guest"]["image"] == f"cathedral-snap-{result['snapshot_id']}:latest"


def test_fork_of_snapshot_without_committed_image_is_409(fake, provider) -> None:
    sid = _source(provider)
    snap_id = _snapshot(provider, sid)["snapshot_id"]
    state = fake.state
    state["images"].remove(f"cathedral-snap-{snap_id}:latest")  # for example pruned by an operator
    fake._save(state)  # noqa: SLF001
    runs_before = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, snap_id)
    assert (err.value.code, err.value.http_status) == ("snapshot_corrupt", 409)  # AB#604 D5: was snapshot_image_missing
    assert len(fake.calls_of("run")) == runs_before


def test_unknown_snapshot_over_http_is_a_json_404(fake, provider) -> None:
    app = SandboxApplication(provider)
    body = json.dumps({"snapshot_id": "snap_000000000000"}).encode()
    response = app.dispatch("POST", "/v1/sandboxes", {"Authorization": "Bearer k"}, body)
    assert response.status == 404
    assert json.loads(response.body)["error"]["code"] == "snapshot_not_found"


def test_named_snapshot_is_not_committed_again(fake, provider) -> None:
    sid = _source(provider)
    _snapshot(provider, sid, name="busy")
    _snapshot(provider, sid, name="busy")
    assert len(fake.calls_of("commit")) == 1


# ---------------------------------------------------------------- defect 3
def test_snapshot_sizes_name_each_part(fake, provider) -> None:
    # Run 5: a 3.64 MB commit layer was reported as 259 bytes (the /work archive).
    image = "cathedral-snap-snap_aaaaaaaaaaaa:latest"
    fake.add_image(image)
    fake.set(image_sizes={"alpine:3.20": 100_000_000, image: 103_640_000})
    sizes = provider._snapshot_sizes("snap_aaaaaaaaaaaa", image, "alpine:3.20", 259)  # noqa: SLF001
    assert sizes["layer_size_bytes"] == 3_640_000
    assert sizes["image_size_bytes"] == 103_640_000
    assert sizes["work_archive_bytes"] == 259
    assert sizes["size_bytes"] == 3_640_259


def test_snapshot_result_and_list_carry_the_real_sizes(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    sizes = {"alpine:3.20": 100_000_000}
    real_commit = provider._client.commit  # noqa: SLF001

    def commit(container_id, image_name):
        out = real_commit(container_id, image_name)
        sizes[image_name] = 103_640_000
        fake.set(image_sizes=sizes)
        return out

    monkeypatch.setattr(provider._client, "commit", commit)  # noqa: SLF001
    result = _snapshot(provider, sid)
    assert result["layer_size_bytes"] == 3_640_000
    assert result["image_size_bytes"] == 103_640_000
    assert result["size_bytes"] == 3_640_000 + result["work_archive_bytes"]
    (listed,) = provider.list_snapshots()
    assert listed["size_bytes"] == result["size_bytes"]
    assert listed["layer_size_bytes"] == 3_640_000


# ---------------------------------------------------------------- defect 2 (hotel side)
def test_push_snapshot_tags_and_pushes_with_a_one_call_login(fake, provider) -> None:
    sid = _source(provider)
    snap_id = _snapshot(provider, sid)["snapshot_id"]
    out = provider.push_snapshot(snap_id, image="ghcr.io/acme/forks:md230", registry_auth=AUTH)
    assert out["image"] == "ghcr.io/acme/forks:md230"
    assert out["includes_work"] is False
    assert fake.calls_of("tag") == [["tag", f"cathedral-snap-{snap_id}:latest", "ghcr.io/acme/forks:md230"]]
    (pushed,) = fake.state["pushed"]
    assert pushed["auth"]["auths"]["ghcr.io"]["password"] == AUTH["password"]
    # The password is never on the docker command line.
    assert not any(AUTH["password"] in " ".join(c) for c in fake.calls)


def test_push_of_unknown_snapshot_is_404(fake, provider) -> None:
    with pytest.raises(SandboxOpError) as err:
        provider.push_snapshot("snap_000000000000", image="ghcr.io/acme/forks:x")
    assert err.value.code == "snapshot_not_found"


def test_push_route_over_http(fake, provider) -> None:
    app = SandboxApplication(provider)
    sid = _source(provider)
    snap_id = _snapshot(provider, sid)["snapshot_id"]
    body = json.dumps({"image": "ghcr.io/acme/forks:a", "registry_auth": AUTH}).encode()
    response = app.dispatch("POST", f"/v1/snapshots/{snap_id}/push", {"Authorization": "Bearer k"}, body)
    assert response.status == 200, response.body
    assert json.loads(response.body)["image"] == "ghcr.io/acme/forks:a"


def test_delete_snapshot_removes_its_image(fake, provider) -> None:
    sid = _source(provider)
    snap_id = _snapshot(provider, sid)["snapshot_id"]
    assert provider.delete_snapshot(snap_id) is True
    assert f"cathedral-snap-{snap_id}:latest" not in fake.state["images"]
    with pytest.raises(SandboxOpError):
        _fork(provider, snap_id)


# ======================================================================== AB#604 CS-1: one-moment capture
# The plan's machine capture: pause, tar /work, commit, unpause, with the tar outside the
# provider lock, one snapshot per room at a time, and two new answer fields.
KIT = Path(__file__).resolve().parents[1] / "room-kit"
_spec = importlib.util.spec_from_file_location("tunable_runtimes_snap_t", KIT / "lib" / "tunable_runtimes.py")
kit_runtimes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kit_runtimes)
GIB = 1 << 30


def _bytes_writer(fake: FakeDocker, payload: bytes = b"the tar bytes the fake produced", gate: threading.Event | None = None,
                  entered: threading.Event | None = None):
    """A stand-in for the /work archive writer: it logs a TAR marker among the docker calls."""

    def write(src: Path, dest: Path, **kw) -> None:
        fake.mark("TAR")
        if entered is not None:
            entered.set()
        if gate is not None:
            assert gate.wait(10), "test never released the tar"
        dest.write_bytes(payload)

    return write


def _engine_order(fake: FakeDocker) -> list[str]:
    return [c[0] for c in fake.calls if c[0] in ("pause", "TAR", "commit", "unpause")]


def _sid_container_status(fake: FakeDocker, sid: str) -> str | None:
    return fake.status_of(sid)


def test_capture_order_is_pause_tar_commit_unpause(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake))
    assert fake.status_of(sid) == "running"
    _snapshot(provider, sid)
    assert _engine_order(fake) == ["pause", "TAR", "commit", "unpause"]
    assert fake.status_of(sid) == "running"


def test_the_tar_is_taken_while_the_room_is_paused(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    seen = []

    def write(src, dest, **kw):
        seen.append(fake.status_of(sid))
        dest.write_bytes(b"x")

    monkeypatch.setattr(sandbox_provider, "_write_work_archive", write)
    _snapshot(provider, sid)
    assert seen == ["paused"]


def test_a_paused_room_is_not_paused_again_and_stays_paused(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    provider.freeze(sid)
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake))
    _snapshot(provider, sid)
    assert len(fake.calls_of("pause")) == 1  # the freeze, not the snapshot
    assert fake.calls_of("unpause") == []
    assert fake.status_of(sid) == "paused"
    assert _engine_order(fake) == ["pause", "TAR", "commit"]


def _hash_fails(path):
    raise RuntimeError("disk read error while hashing")


def _tar_fails(src, dest, **kw):
    dest.write_bytes(b"half")  # a partial file the code must not leave behind
    raise OSError("no space left on device")


@pytest.mark.parametrize("path", ["tar_fails", "commit_fails", "hash_fails", "exception_between"])
def test_a_running_room_runs_again_on_every_exit_path(fake, provider, monkeypatch, path) -> None:
    sid = _source(provider)
    patch = pytest.MonkeyPatch()  # a local one: undoing it must not undo the fake docker on PATH
    if path == "tar_fails":
        patch.setattr(sandbox_provider, "_write_work_archive", _tar_fails)
    elif path == "commit_fails":
        fake.set(commit_fail=True)
    elif path == "hash_fails":
        patch.setattr(sandbox_provider, "_sha256_file", _hash_fails)
    else:  # an exception no one planned for, between the pause and the unpause
        def boom(ref):
            raise RuntimeError("unexpected")
        patch.setattr(provider, "_image_id_of", boom)
    with pytest.raises(Exception):
        provider.snapshot(sid)
    assert fake.status_of(sid) == "running"
    assert len(fake.calls_of("unpause")) == len(fake.calls_of("pause")) == 1
    # No record, no committed image and no archive is left; the room takes a new snapshot at once.
    assert provider.list_snapshots() == []
    assert not [i for i in fake.state["images"] if i.startswith("cathedral-snap-")]
    assert not list(provider._inner._base.glob("snap_*"))  # noqa: SLF001
    patch.undo()
    fake.set(commit_fail=False)
    assert _snapshot(provider, sid)["snapshot_id"].startswith("snap_")


def test_a_failed_unpause_is_an_error_not_a_silent_paused_room(fake, provider) -> None:
    sid = _source(provider)
    fake.set(unpause_fail=True)
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(sid)
    assert err.value.code == "guest_unpause_failed"
    assert provider.list_snapshots() == []  # a snapshot of a room we could not release is not handed out


def test_the_tar_runs_outside_the_provider_lock(fake, provider, monkeypatch) -> None:
    sid, other = _source(provider), provider.create(
        CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES), api_key="k", idempotency=None, body_digest="o")["id"]
    gate, entered = threading.Event(), threading.Event()
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, gate=gate, entered=entered))
    worker = threading.Thread(target=lambda: provider.snapshot(sid), daemon=True)
    worker.start()
    try:
        assert entered.wait(10)
        answered = []
        reader = threading.Thread(target=lambda: answered.append(provider.get(other)["id"]), daemon=True)
        reader.start()
        reader.join(5)
        assert answered == [other], "a status read of another room waited for the slow tar"
        assert provider._inner._lock.acquire(timeout=2)  # noqa: SLF001
        provider._inner._lock.release()  # noqa: SLF001
    finally:
        gate.set()
        worker.join(10)


def test_a_second_snapshot_of_a_room_is_409_while_one_runs(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    gate, entered = threading.Event(), threading.Event()
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, gate=gate, entered=entered))
    worker = threading.Thread(target=lambda: provider.snapshot(sid), daemon=True)
    worker.start()
    try:
        assert entered.wait(10)
        with pytest.raises(SandboxOpError) as err:
            provider.snapshot(sid)
        assert (err.value.code, err.value.http_status) == ("snapshot_in_progress", 409)
        assert len(fake.calls_of("pause")) == 1  # the refused call did not touch the engine
    finally:
        gate.set()
        worker.join(10)
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake))
    assert _snapshot(provider, sid)["snapshot_id"]  # after the first ended, a new one is accepted


def test_a_snapshot_is_accepted_again_after_the_first_failed(fake, provider) -> None:
    sid = _source(provider)
    fake.set(commit_fail=True)
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    fake.set(commit_fail=False)
    assert _snapshot(provider, sid)["snapshot_id"]


def test_snapshots_of_different_rooms_run_side_by_side(fake, provider, monkeypatch) -> None:
    a = _source(provider)
    b = provider.create(CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES), api_key="k", idempotency=None, body_digest="b")["id"]
    gate, entered = threading.Event(), threading.Event()
    real = sandbox_provider._write_work_archive
    calls = []

    def write(src, dest, **kw):
        calls.append(src)
        if len(calls) == 1:
            entered.set()
            assert gate.wait(10)
        real(src, dest, **kw)

    monkeypatch.setattr(sandbox_provider, "_write_work_archive", write)
    worker = threading.Thread(target=lambda: provider.snapshot(a), daemon=True)
    worker.start()
    try:
        assert entered.wait(10)
        assert _snapshot(provider, b)["snapshot_id"]  # b finishes while a's tar is still running
    finally:
        gate.set()
        worker.join(10)


def test_the_answer_carries_the_image_id_and_the_hash_of_the_tar_bytes(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    payload = b"the tar bytes the fake produced"
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, payload))
    result = _snapshot(provider, sid)
    assert result["work_archive_sha256"] == hashlib.sha256(payload).hexdigest()
    image = f"cathedral-snap-{result['snapshot_id']}:latest"
    assert result["committed_image_id"] == provider._image_id_of(image)  # noqa: SLF001
    assert result["committed_image_id"].startswith("sha256:") and len(result["committed_image_id"]) == 71
    assert result["work_archive_bytes"] == len(payload)
    (listed,) = provider.list_snapshots()
    assert listed["work_archive_sha256"] == result["work_archive_sha256"]
    assert listed["committed_image_id"] == result["committed_image_id"]


def test_the_hash_is_of_the_stored_archive(fake, provider) -> None:
    sid = _source(provider)
    result = _snapshot(provider, sid)
    path, _ = provider._inner._snapshots[result["snapshot_id"]]  # noqa: SLF001
    assert result["work_archive_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_an_old_caller_that_reads_the_old_fields_still_works(fake, provider) -> None:
    app = SandboxApplication(provider)
    sid = _source(provider)
    response = app.dispatch("POST", f"/v1/sandboxes/{sid}/snapshot", {"Authorization": "Bearer k"}, json.dumps({"name": "old"}).encode())
    assert response.status == 202, response.body
    doc = json.loads(response.body)
    assert set(doc) >= {"operation_id", "status", "result"} and doc["status"] == "done"
    result = doc["result"]
    for field, kind in (("snapshot_id", str), ("size_bytes", int), ("layer_size_bytes", int), ("image_size_bytes", int),
                        ("work_archive_bytes", int), ("image", str), ("name", str)):
        assert isinstance(result[field], kind), field
    assert result["image"] == f"cathedral-snap-{result['snapshot_id']}:latest"
    listed = json.loads(app.dispatch("GET", "/v1/snapshots", {"Authorization": "Bearer k"}, b"").body)["snapshots"]
    assert listed[0]["snapshot_id"] == result["snapshot_id"] and listed[0]["size_bytes"] == result["size_bytes"]
    forked = _fork(provider, result["snapshot_id"])
    assert forked["guest"]["image"] == result["image"]


# ---------------------------------------------------------------- caps
def _sparse_writer(size: int):
    def write(src, dest, **kw):
        with open(dest, "wb") as fh:
            fh.truncate(size)
    return write


def test_a_snapshot_over_the_rooms_disk_is_413_before_the_commit(fake, provider, monkeypatch) -> None:
    sid = _source(provider)  # disk_gib 5
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _sparse_writer(5 * GIB + 1))
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(sid)
    assert (err.value.code, err.value.http_status) == ("snapshot_too_large", 413)
    assert fake.calls_of("commit") == []
    assert fake.status_of(sid) == "running"
    assert provider.list_snapshots() == []


def test_a_snapshot_whose_layer_pushes_it_over_the_disk_is_413_and_its_image_is_removed(fake, provider) -> None:
    sid = _source(provider)
    real_commit = provider._client.commit  # noqa: SLF001

    def commit(container_id, image_name):
        out = real_commit(container_id, image_name)
        fake.set(image_sizes={"alpine:3.20": 1_000, image_name: 1_000 + 6 * GIB})
        return out

    provider._client.commit = commit  # noqa: SLF001
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(sid)
    assert (err.value.code, err.value.http_status) == ("snapshot_too_large", 413)
    assert not [i for i in fake.state["images"] if i.startswith("cathedral-snap-")]
    assert fake.status_of(sid) == "running" and provider.list_snapshots() == []


def test_a_full_store_by_count_is_429_snapshot_store_sold_out(fake) -> None:
    p = DockerGuestProvider(inner=InMemorySandboxProvider(max_snapshots=1, enforce_disk=True))
    try:
        sid = _source(p)
        _snapshot(p, sid)
        with pytest.raises(SandboxOpError) as err:
            p.snapshot(sid)
        assert (err.value.code, err.value.http_status, err.value.retry_after) == ("snapshot_store_sold_out", 429, 30)
        assert "sold out" in str(err.value) and "unavailable" not in str(err.value)
        assert len(fake.calls_of("pause")) == 1  # the refusal came before any pause
        assert fake.status_of(sid) == "running"
    finally:
        p.close()


def test_a_full_store_by_bytes_is_429_snapshot_store_sold_out(fake, monkeypatch) -> None:
    p = DockerGuestProvider(inner=InMemorySandboxProvider(max_snapshot_bytes=100, enforce_disk=True))
    try:
        sid = _source(p)
        monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, b"a" * 60))
        _snapshot(p, sid)  # 60 stored, under the cap of 100
        with pytest.raises(SandboxOpError) as err:
            p.snapshot(sid)  # a second 60 would pass 100
        assert (err.value.code, err.value.http_status) == ("snapshot_store_sold_out", 429)
        assert fake.status_of(sid) == "running" and len(p.list_snapshots()) == 1
        assert not [i for i in fake.state["images"] if i.startswith("cathedral-snap-")][1:]
    finally:
        p.close()


def test_the_cap_errors_over_http(fake) -> None:
    p = DockerGuestProvider(inner=InMemorySandboxProvider(max_snapshots=1, enforce_disk=True))
    try:
        app = SandboxApplication(p)
        sid = _source(p)
        ok = app.dispatch("POST", f"/v1/sandboxes/{sid}/snapshot", {"Authorization": "Bearer k"}, b"{}")
        assert ok.status == 202
        full = app.dispatch("POST", f"/v1/sandboxes/{sid}/snapshot", {"Authorization": "Bearer k"}, b"{}")
        assert full.status == 429 and json.loads(full.body)["error"]["code"] == "snapshot_store_sold_out"
        assert full.headers["Retry-After"] == "30"
    finally:
        p.close()


# ---------------------------------------------------------------- overlay refusal
@pytest.mark.parametrize("tunables", [{"schema": 1}, {"schema": 1, "runsc": {"overlay2": "all:self"}}])
def test_a_room_on_an_overlay_is_refused_422_before_anything_happens(fake, monkeypatch, tunables) -> None:
    fake.set(default_runtime="runsc", runtimes=kit_runtimes.runtimes("/opt/pool-room/gvisor/runsc", "--platform=systrap --overlay2=none --net-raw"))
    p = DockerGuestProvider()
    try:
        sid = p.create(CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES, tunables=tunables),
                       api_key="k", idempotency=None, body_digest="t")["id"]
        monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake))
        with pytest.raises(SandboxOpError) as err:
            p.snapshot(sid)
        assert (err.value.code, err.value.http_status) == ("snapshot_overlay_unsupported", 422)
        assert fake.calls_of("pause") == [] and fake.calls_of("commit") == [] and "TAR" not in _engine_order(fake)
        assert fake.status_of(sid) == "running"
        # A room without tunables (the hotel default, overlay2 none) is not refused.
        plain = p.create(CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES), api_key="k", idempotency=None, body_digest="p")["id"]
        assert _snapshot(p, plain)["snapshot_id"]
    finally:
        p.close()


# ---------------------------------------------------------------- stale and terminal states
def test_a_snapshot_of_a_room_that_is_being_deleted_is_refused_and_pauses_nothing(fake, provider) -> None:
    sid = _source(provider)
    provider._inner.begin_delete(sid)  # noqa: SLF001  the record is "deleting", its container still there
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(sid)
    assert (err.value.code, err.value.http_status) == ("sandbox_deleting", 409)
    assert fake.calls_of("pause") == [] and fake.calls_of("commit") == []


def test_a_snapshot_of_an_unknown_room_is_404(fake, provider) -> None:
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot("00000000-0000-0000-0000-000000000000")
    assert err.value.http_status == 404 and fake.calls_of("pause") == []


def test_deleting_a_room_while_its_snapshot_runs_leaves_nothing_behind(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    gate, entered = threading.Event(), threading.Event()
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, gate=gate, entered=entered))
    outcome: list = []

    def run():
        try:
            outcome.append(provider.snapshot(sid))
        except SandboxOpError as exc:
            outcome.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    assert entered.wait(10)
    provider.delete(sid)  # the delete is not held up by the snapshot
    gate.set()
    worker.join(10)
    (result,) = outcome
    assert isinstance(result, SandboxOpError) and result.http_status in (404, 409, 502), result
    assert provider.list_snapshots() == []
    assert not [i for i in fake.state["images"] if i.startswith("cathedral-snap-")]
    assert not list(provider._inner._base.glob("snap_*"))  # noqa: SLF001
    assert fake.status_of(sid) is None  # the room is gone, not left paused


def test_freeze_and_thaw_are_refused_while_a_snapshot_of_the_room_runs(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    gate, entered = threading.Event(), threading.Event()
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, gate=gate, entered=entered))
    worker = threading.Thread(target=lambda: provider.snapshot(sid), daemon=True)
    worker.start()
    try:
        assert entered.wait(10)
        for call in (provider.freeze, provider.thaw):
            with pytest.raises(SandboxOpError) as err:
                call(sid)
            assert err.value.code == "snapshot_in_progress"
    finally:
        gate.set()
        worker.join(10)
    assert fake.status_of(sid) == "running"


def test_an_api_restart_mid_snapshot_does_not_leave_a_room_paused_for_ever(fake, provider, monkeypatch) -> None:
    # What the code does: records live in the API process, so a new process owns no room. Its first
    # sweep removes every labeled container without a record, paused or not, and every cathedral-snap
    # image no record names. The paused room is removed, not unpaused (all rooms are lost on an API restart).
    # The fake cannot kill a process: a second provider on the same fake engine stands in for the new one.
    sid = _source(provider)
    gate, entered = threading.Event(), threading.Event()
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, gate=gate, entered=entered))
    def old_process():
        try:
            provider.snapshot(sid)
        except SandboxOpError:
            pass  # its room is gone under it: the capture fails

    worker = threading.Thread(target=old_process, daemon=True)
    worker.start()
    try:
        assert entered.wait(10)
        assert fake.status_of(sid) == "paused"  # the old process "dies" here
        fake.add_image("cathedral-snap-snap_deadbeef0000:latest")  # an image committed by the old process
        fresh = DockerGuestProvider()
        try:
            fresh.sweep()
            assert fake.status_of(sid) is None
            assert "cathedral-snap-snap_deadbeef0000:latest" not in fake.state["images"]
        finally:
            fresh.close()
    finally:
        gate.set()
        worker.join(10)


# ======================================================================== plan section 8, D1 to D3
def _room(provider, digest: str) -> str:
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES)
    return provider.create(req, api_key="k", idempotency=None, body_digest=digest)["id"]


def _gate_first_commit(provider):
    """Hold the first docker commit (and only it) until released; record every container committed."""
    gate, entered, committed = threading.Event(), threading.Event(), []
    real = provider._client.commit  # noqa: SLF001

    def commit(container_id, image_name):
        committed.append((container_id, image_name))
        if len(committed) == 1:
            entered.set()
            assert gate.wait(10)
        return real(container_id, image_name)

    provider._client.commit = commit  # noqa: SLF001
    return gate, entered, committed


def test_two_captures_under_one_name_from_two_rooms_let_one_through(fake, provider) -> None:
    # The fault on main: both commit before the guest's image map is filled, so A's tar ends up with C's image.
    a, c = _room(provider, "a"), _room(provider, "c")
    gate, entered, committed = _gate_first_commit(provider)
    outcome: list = []
    def first():
        provider.authorize("k")  # a request thread carries its key, as the server sets it per request
        outcome.append(provider.get_operation(provider.snapshot(a, name="shared"))["result"])

    provider.authorize("k")
    worker = threading.Thread(target=first, daemon=True)
    worker.start()
    try:
        assert entered.wait(10)
        with pytest.raises(SandboxOpError) as err:
            provider.snapshot(c, name="shared")
        assert (err.value.code, err.value.http_status) == ("snapshot_in_progress", 409)
    finally:
        gate.set()
        worker.join(10)
    (result,) = outcome
    assert len(committed) == 1 and committed[0][0] == provider._guests[a].container_id  # noqa: SLF001
    assert committed[0][1] == f"cathedral-snap-{result['snapshot_id']}:latest"
    assert fake.status_of(c) == "running" and len(fake.calls_of("pause")) == 1


def test_no_record_exists_until_the_capture_is_complete_and_it_is_written_whole(fake, provider) -> None:
    a = _room(provider, "a")
    gate, entered, _ = _gate_first_commit(provider)
    outcome: list = []
    worker = threading.Thread(target=lambda: outcome.append(provider.snapshot(a, name="n")), daemon=True)
    worker.start()
    try:
        assert entered.wait(10)
        assert provider.list_snapshots() == []  # a reserved id is not a snapshot yet
        with pytest.raises(SandboxOpError) as err:
            _fork(provider, "n")
        assert err.value.code == "snapshot_not_found"
    finally:
        gate.set()
        worker.join(10)
    result = provider.get_operation(outcome[0])["result"]
    for field in ("snapshot_id", "size_bytes", "committed_image_id", "work_archive_sha256", "source_sandbox_id"):
        assert result[field], field
    assert result["source_sandbox_id"] == a
    path, record = provider._inner._snapshots[result["snapshot_id"]]  # noqa: SLF001
    assert record.size_bytes == result["size_bytes"]  # the record already holds its final size
    (listed,) = provider.list_snapshots()
    assert listed["size_bytes"] == result["size_bytes"]


def test_a_repeat_of_a_finished_capture_from_the_same_room_returns_the_stored_record(fake, provider) -> None:
    a = _room(provider, "a")
    first = _snapshot(provider, a, name="n")
    again = _snapshot(provider, a, name="n")
    assert again == first and len(fake.calls_of("commit")) == 1


def test_the_same_name_through_another_rooms_path_is_refused_not_answered_with_the_first_record(fake, provider) -> None:
    a, c = _room(provider, "a"), _room(provider, "c")
    _snapshot(provider, a, name="n")
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(c, name="n")
    assert (err.value.code, err.value.http_status) == ("snapshot_name_taken", 409)
    assert len(fake.calls_of("commit")) == 1 and fake.status_of(c) == "running" and fake.calls_of("pause") == fake.calls_of("pause")[:1]


# ---------------------------------------------------------------- D2: API writes stop for the capture
def _tiny_tar() -> bytes:
    import io
    import tarfile as tf

    buf = io.BytesIO()
    with tf.open(fileobj=buf, mode="w:gz") as t:
        info = tf.TarInfo("up.txt")
        info.size = 2
        t.addfile(info, io.BytesIO(b"ok"))
    return buf.getvalue()


def test_api_writes_to_a_room_are_409_while_its_capture_runs_and_other_rooms_are_untouched(fake, provider, monkeypatch) -> None:
    a, other = _room(provider, "a"), _room(provider, "o")
    gate, entered = threading.Event(), threading.Event()
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, gate=gate, entered=entered))
    worker = threading.Thread(target=lambda: provider.snapshot(a), daemon=True)
    worker.start()
    try:
        assert entered.wait(10)
        with pytest.raises(SandboxOpError) as err:
            provider.write_file(a, "/work/x.txt", b"1", None)
        assert (err.value.code, err.value.http_status) == ("snapshot_in_progress", 409)
        with pytest.raises(SandboxOpError) as err:
            provider.write_tar(a, "/work", _tiny_tar())
        assert err.value.code == "snapshot_in_progress"
        with pytest.raises(SandboxOpError) as err:
            provider.make_directory(a, "/work/newdir")
        assert err.value.code == "snapshot_in_progress"
        with pytest.raises(SandboxOpError) as err:
            provider.remove_entry(a, "/work/x.txt")
        assert err.value.code == "snapshot_in_progress"
        provider.write_file(other, "/work/x.txt", b"1", None)  # another room: untouched
        provider.write_tar(other, "/work", _tiny_tar())
        assert provider.make_directory(other, "/work/newdir")
    finally:
        gate.set()
        worker.join(10)
    provider.write_file(a, "/work/x.txt", b"1", None)  # after the capture, writes work again
    provider.write_tar(a, "/work", _tiny_tar())


def _slow_write(monkeypatch, gate: threading.Event, started: threading.Event) -> None:
    real = sandbox_provider._open_beneath

    def slow(root, path, flags, **kw):
        if path.endswith("slow.txt"):
            started.set()
            assert gate.wait(10)
        return real(root, path, flags, **kw)

    monkeypatch.setattr(sandbox_provider, "_open_beneath", slow)


def test_a_write_already_in_flight_finishes_before_the_tar_begins(fake, provider, monkeypatch) -> None:
    a = _room(provider, "a")
    write_gate, write_started, tar_started = threading.Event(), threading.Event(), threading.Event()
    seen: list[str] = []
    _slow_write(monkeypatch, write_gate, write_started)

    def tar(src, dest, **kw):
        tar_started.set()
        seen.append((src / "slow.txt").read_text())
        dest.write_bytes(b"t")

    monkeypatch.setattr(sandbox_provider, "_write_work_archive", tar)
    writer = threading.Thread(target=lambda: provider.write_file(a, "/work/slow.txt", b"complete", None), daemon=True)
    writer.start()
    assert write_started.wait(10)
    snap = threading.Thread(target=lambda: provider.snapshot(a), daemon=True)
    snap.start()
    try:
        assert not tar_started.wait(0.5), "the tar began while a write was still in flight"
        assert fake.calls_of("pause") == []  # the capture is still waiting for the write
    finally:
        write_gate.set()
    writer.join(10)
    snap.join(10)
    assert tar_started.is_set() and seen == ["complete"]


def test_a_write_that_outlasts_the_bound_fails_the_capture_cleanly(fake, provider, monkeypatch) -> None:
    a = _room(provider, "a")
    write_gate, write_started = threading.Event(), threading.Event()
    _slow_write(monkeypatch, write_gate, write_started)
    provider._inner._snapshot_write_wait = 0.3  # noqa: SLF001
    writer = threading.Thread(target=lambda: provider.write_file(a, "/work/slow.txt", b"late", None), daemon=True)
    writer.start()
    assert write_started.wait(10)
    try:
        with pytest.raises(SandboxOpError) as err:
            provider.snapshot(a)
        assert (err.value.code, err.value.http_status) == ("snapshot_writes_pending", 503)
        assert fake.calls_of("pause") == [] and fake.status_of(a) == "running"
        assert provider.list_snapshots() == [] and not list(provider._inner._base.glob("snap_*"))  # noqa: SLF001
    finally:
        write_gate.set()
        writer.join(10)
    assert _snapshot(provider, a)["snapshot_id"]  # the room is not stuck


# ---------------------------------------------------------------- D3: no tar-only success
def test_a_capture_that_commits_no_image_is_an_error_with_no_record_and_no_file(fake, provider) -> None:
    a = _room(provider, "a")
    provider._guests.pop(a)  # noqa: SLF001  an active record whose guest is gone
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(a)
    assert (err.value.code, err.value.http_status) == ("snapshot_image_missing", 409)
    assert provider.list_snapshots() == [] and not list(provider._inner._base.glob("snap_*"))  # noqa: SLF001
    assert fake.calls_of("pause") == [] and fake.calls_of("commit") == []


# ======================================================================== AB#604 CS-2: fork safety (plan section 8, D5 to D8)
import os
import tarfile as _tarfile
from datetime import timedelta


def _room_with_file(provider, payload: bytes | None = None, **create):
    payload = payload if payload is not None else os.urandom(4000)  # random: it does not compress, so the tar is not tiny
    req = CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), resources=RES, **create)
    sid = provider.create(req, api_key="k", idempotency=None, body_digest="src")["id"]
    provider.write_file(sid, "/work/a.txt", payload, None)
    return sid, payload


def _captured(provider, **create):
    sid, payload = _room_with_file(provider, **create)
    result = _snapshot(provider, sid)
    path, _ = provider._inner._snapshots[result["snapshot_id"]]  # noqa: SLF001
    return result, Path(path), payload


def _other_tar() -> bytes:
    import io

    buf = io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = _tarfile.TarInfo("evil.txt")
        info.size = 4
        t.addfile(info, io.BytesIO(b"evil"))
    return buf.getvalue()


def _fork_root(provider, doc) -> Path:
    return Path(provider._inner._sandboxes[doc["id"]].root) / "work"  # noqa: SLF001


def _nothing_started(fake, provider, runs_before: int) -> None:
    assert len(fake.calls_of("run")) == runs_before
    # No container, no record, no guest, no work folder (staging included) and no image tag for the new room.
    assert len(fake.containers) == 1 and len(provider._guests) == 1 and len(provider._inner._sandboxes) == 1  # noqa: SLF001
    assert [i for i in fake.state["images"] if not i.startswith("cathedral-snap-")] == ["alpine:3.20"]
    assert not list(provider._inner._base.glob("sbx_*/.incoming"))  # noqa: SLF001
    assert provider.quota()["usage"]["resident_sandboxes"] == 1  # the source room only
    assert len([p for p in provider._inner._base.iterdir() if p.name.startswith("sbx_")]) == 1  # noqa: SLF001


# ---------------------------------------------------------------- D5: one read, one digest
def test_a_good_tar_starts_the_fork_with_the_files(fake, provider) -> None:
    result, path, payload = _captured(provider)
    doc = _fork(provider, result["snapshot_id"])
    assert (_fork_root(provider, doc) / "a.txt").read_bytes() == payload


def _tamper_one_byte(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))


@pytest.mark.parametrize("tamper", [
    _tamper_one_byte,
    lambda p: p.write_bytes(p.read_bytes()[: len(p.read_bytes()) // 2]),  # truncated
    lambda p: p.write_bytes(_other_tar()),  # a valid tar of other files
], ids=["one_byte", "truncated", "other_valid_tar"])
def test_a_tar_changed_on_disk_after_the_capture_never_starts_a_room(fake, provider, tamper) -> None:
    result, path, _ = _captured(provider)
    tamper(path)
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, result["snapshot_id"])
    assert (err.value.code, err.value.http_status) == ("snapshot_corrupt", 409)
    _nothing_started(fake, provider, runs)


class _SlowReader:
    """A reader that gives 64 bytes, then lets the test act, then gives the rest."""

    def __init__(self, path: Path, between) -> None:
        self._fh = open(path, "rb", buffering=0)  # unbuffered: a read sees what is on disk now
        self._between = between
        self._reads = 0

    def read(self, n: int = -1) -> bytes:
        self._reads += 1
        if self._reads == 1:
            return self._fh.read(64)
        if self._reads == 2:
            self._between()
        return self._fh.read(n)

    def close(self) -> None:
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def test_a_tar_changed_in_place_during_the_read_never_starts_a_room(fake, provider, monkeypatch) -> None:
    result, path, _ = _captured(provider)

    def flip() -> None:
        with open(path, "r+b") as fh:
            fh.seek(300)
            original = fh.read(1)
            assert len(original) == 1
            fh.seek(300)
            # A fixed 0xff sometimes leaves this random archive byte unchanged.
            fh.write(bytes([original[0] ^ 1]))

    monkeypatch.setattr(sandbox_provider, "_open_snapshot_archive", lambda p: _SlowReader(p, flip))
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, result["snapshot_id"])
    assert err.value.code == "snapshot_corrupt"
    _nothing_started(fake, provider, runs)


def test_a_tar_swapped_by_path_during_the_read_cannot_put_other_files_in_the_fork(fake, provider, monkeypatch) -> None:
    result, path, payload = _captured(provider)

    def swap() -> None:
        other = path.with_name("swap.tmp")
        other.write_bytes(_other_tar())
        os.replace(other, path)

    monkeypatch.setattr(sandbox_provider, "_open_snapshot_archive", lambda p: _SlowReader(p, swap))
    try:
        doc = _fork(provider, result["snapshot_id"])
    except SandboxOpError as err:
        assert err.code == "snapshot_corrupt"
        return
    # If it started, it started from the bytes the digest covered: the first file, not the swapped one.
    assert (_fork_root(provider, doc) / "a.txt").read_bytes() == payload
    assert not (_fork_root(provider, doc) / "evil.txt").exists()


def test_a_fork_opens_the_stored_tar_once(fake, provider, monkeypatch) -> None:
    result, path, _ = _captured(provider)
    opened = []
    real = sandbox_provider._open_snapshot_archive
    monkeypatch.setattr(sandbox_provider, "_open_snapshot_archive", lambda p: (opened.append(p), real(p))[1])
    _fork(provider, result["snapshot_id"])
    assert opened == [path]


def test_the_fork_starts_the_records_committed_image(fake, provider) -> None:
    result, _, _ = _captured(provider)
    doc = _fork(provider, result["snapshot_id"])
    argv = next(c["argv"] for c in fake.state["containers"].values() if c["labels"].get("cathedral.sandbox.id") == doc["id"])
    assert result["committed_image_id"] in argv


def test_an_image_with_another_id_is_snapshot_corrupt(fake, provider) -> None:
    result, _, _ = _captured(provider)
    fake.set_image_id(f"cathedral-snap-{result['snapshot_id']}:latest", "sha256:" + "ab" * 32)
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, result["snapshot_id"])
    assert (err.value.code, err.value.http_status) == ("snapshot_corrupt", 409)
    _nothing_started(fake, provider, runs)


def test_a_missing_image_is_snapshot_corrupt(fake, provider) -> None:
    result, _, _ = _captured(provider)
    state = fake.state
    state["images"].remove(f"cathedral-snap-{result['snapshot_id']}:latest")
    fake._save(state)  # noqa: SLF001
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, result["snapshot_id"])
    assert err.value.code == "snapshot_corrupt"
    _nothing_started(fake, provider, runs)


# ---------------------------------------------------------------- D6: a fork checks the expiry itself
def test_a_fork_of_an_expired_snapshot_is_refused_before_the_sweep_runs(fake, provider) -> None:
    # The code's own name for a snapshot that is not usable is 404 snapshot_not_found; there is no separate "expired" error.
    result, path, _ = _captured(provider)
    snap_id = result["snapshot_id"]
    _, rec = provider._inner._snapshots[snap_id]  # noqa: SLF001
    from dataclasses import replace

    provider._inner._snapshots[snap_id] = (path, replace(rec, created_at=rec.created_at - timedelta(seconds=rec.ttl_seconds + 1)))  # noqa: SLF001
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, snap_id)
    assert (err.value.code, err.value.http_status) == ("snapshot_not_found", 404)
    assert len(fake.calls_of("run")) == runs


# ---------------------------------------------------------------- D7: only the fork call starts a snapshot image
def _create_image(provider, ref: str):
    return provider.create(CreateSandboxRequest(image=ImageSource(image=ref), resources=RES), api_key="k", idempotency=None, body_digest="plain:" + ref)


def test_a_plain_create_from_a_snapshot_image_is_refused_in_every_form(fake, provider) -> None:
    result, _, _ = _captured(provider)
    name = f"cathedral-snap-{result['snapshot_id']}:latest"
    image_id = result["committed_image_id"]
    fake.add_image("retagged:1", alias_of=name)  # another tag on the same image
    # (A bare 64-hex id is not a valid image reference: the request itself is refused as invalid_image_reference.)
    forms = [image_id, name, f"cathedral-snap-{result['snapshot_id']}:other",
             f"cathedral-snap-{result['snapshot_id']}@{image_id}", "retagged:1"]
    runs = len(fake.calls_of("run"))
    for ref in forms:
        with pytest.raises(SandboxOpError) as err:
            _create_image(provider, ref)
        assert (err.value.code, err.value.http_status) == ("snapshot_image_fork_only", 400), ref
    assert len(fake.calls_of("run")) == runs


def test_a_template_that_resolves_to_a_snapshot_image_is_refused(fake, provider) -> None:
    from cathedral import agent_interactive as ux

    result, _, _ = _captured(provider)
    provider._inner._templates["sbt-tpl:v1"] = ux.SandboxTemplate(  # noqa: SLF001
        uid="sbt-tpl:v1", name="tpl", display_name="t", description="", kind="USER", status="READY", source_sandbox_id=None,
        image_ref=f"cathedral-snap-{result['snapshot_id']}:latest")
    with pytest.raises(SandboxOpError) as err:
        _create_image(provider, "sbt-tpl:v1")
    assert err.value.code == "snapshot_image_fork_only"


def test_the_id_that_will_run_is_checked_again_after_the_early_check(fake, provider, monkeypatch) -> None:
    # A tag moved onto the snapshot's image after the first check (or a pull that took the lock's time):
    # the Id that actually runs is compared with the snapshot images once more.
    result, _, _ = _captured(provider)
    fake.add_image("late:1", alias_of=f"cathedral-snap-{result['snapshot_id']}:latest")
    monkeypatch.setattr(provider, "_names_snapshot_image", lambda *a, **k: False)
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _create_image(provider, "late:1")
    assert err.value.code == "snapshot_image_fork_only"
    assert len(fake.calls_of("run")) == runs and provider.quota()["usage"]["resident_sandboxes"] == 1


def test_the_fork_call_still_starts_a_snapshot_image_and_an_ordinary_image_is_untouched(fake, provider) -> None:
    result, _, _ = _captured(provider)
    assert _fork(provider, result["snapshot_id"])["guest"]["image"] == f"cathedral-snap-{result['snapshot_id']}:latest"
    assert _create_image(provider, "alpine:3.20")["guest"]["image"] == "alpine:3.20"


# ---------------------------------------------------------------- D8: create-time env is blanked in the fork
def _commit_changes(fake) -> list[str]:
    (argv,) = fake.calls_of("commit")
    return [argv[i + 1] for i, a in enumerate(argv) if a == "--change"]


def test_the_commit_blanks_each_create_time_variable_and_only_those(fake, provider) -> None:
    # The fake shows the docker argv only. Whether docker keeps -e values in a commit at all, and
    # whether --change ENV NAME= blanks them under runsc, is real-machine step T2. The name stays, with an empty value.
    _captured(provider, env={"API_TOKEN": "s3cret", "MODE": "x"})
    assert sorted(_commit_changes(fake)) == ["ENV API_TOKEN=", "ENV MODE="]


def test_a_room_without_create_time_env_commits_with_no_change(fake, provider) -> None:
    _captured(provider)
    assert _commit_changes(fake) == []  # a variable the image sets itself is not named, so it is not blanked


def test_the_forks_own_env_wins_and_the_first_rooms_values_are_not_passed_on(fake, provider) -> None:
    result, _, _ = _captured(provider, env={"API_TOKEN": "s3cret", "MODE": "x"})
    src_id = next(iter(provider._guests))  # noqa: SLF001
    provider._guests[src_id].env_overlay = {"SEALED": "v"}  # noqa: SLF001  a sealed overlay on the first room
    req = CreateSandboxRequest(snapshot_id=result["snapshot_id"], resources=RES, env={"API_TOKEN": "fork-own"})
    doc = provider.create(req, api_key="k", idempotency=None, body_digest="f")
    argv = next(c["argv"] for c in fake.state["containers"].values() if c["labels"].get("cathedral.sandbox.id") == doc["id"])
    passed = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
    assert "API_TOKEN=fork-own" in passed
    assert not [e for e in passed if e.startswith(("MODE=", "SEALED=")) or e == "API_TOKEN=s3cret"]
    assert provider._guests[doc["id"]].env_overlay == {}  # noqa: SLF001
    assert not any(src_id in " ".join(a) for a in [argv] if "-v" in a and f"{src_id}/secrets" in " ".join(a))


# ---------------------------------------------------------------- the sweep that retries image removal
def test_an_image_whose_removal_failed_is_retried_by_later_sweeps(fake, provider) -> None:
    result, _, _ = _captured(provider)
    snap_id, image = result["snapshot_id"], f"cathedral-snap-{result['snapshot_id']}:latest"
    fake.set(image_rm_fail_times=2)
    assert provider.delete_snapshot(snap_id) is True
    assert image in fake.state["images"] and image in provider.pending_image_removals()
    for _ in range(4):
        provider.sweep()
    assert image not in fake.state["images"] and provider.pending_image_removals() == {}


def test_an_expired_snapshots_image_is_retried_too(fake, provider) -> None:
    result, path, _ = _captured(provider)
    snap_id, image = result["snapshot_id"], f"cathedral-snap-{result['snapshot_id']}:latest"
    _, rec = provider._inner._snapshots[snap_id]  # noqa: SLF001
    from dataclasses import replace

    provider._inner._snapshots[snap_id] = (path, replace(rec, created_at=rec.created_at - timedelta(seconds=rec.ttl_seconds + 1)))  # noqa: SLF001
    fake.set(image_rm_fail_times=2)  # the sweep's first try and its retry in the same pass both fail
    provider.sweep()
    assert image in fake.state["images"] and image in provider.pending_image_removals()
    provider.sweep()
    assert image not in fake.state["images"] and provider.pending_image_removals() == {}


def test_a_snapshot_delete_that_could_not_remove_the_image_says_so_over_http(fake, provider) -> None:
    app = SandboxApplication(provider)
    result, _, _ = _captured(provider)
    fake.set(image_rm_fail_times=1)
    response = app.dispatch("DELETE", f"/v1/snapshots/{result['snapshot_id']}", {"Authorization": "Bearer k"}, b"")
    assert response.status == 200 and json.loads(response.body) == {"deleted": True, "image_removal": "pending"}
    other, _, _ = _captured(provider)  # a clean delete keeps the old answer exactly
    clean = app.dispatch("DELETE", f"/v1/snapshots/{other['snapshot_id']}", {"Authorization": "Bearer k"}, b"")
    assert json.loads(clean.body) == {"deleted": True}

# ======================================================================== CS-1 review 1 fixes
import time as _time


def _hold_first(provider, name: str):
    """Hold the first call of a docker client method (pause, unpause) after the caller was admitted."""
    gate, entered, calls = threading.Event(), threading.Event(), []
    real = getattr(provider._client, name)  # noqa: SLF001

    def wrapped(*a, **kw):
        calls.append(a)
        if len(calls) == 1:
            entered.set()
            assert gate.wait(10)
        return real(*a, **kw)

    setattr(provider._client, name, wrapped)  # noqa: SLF001
    return gate, entered


def test_a_freeze_admitted_before_the_capture_finishes_before_the_tar_and_the_room_stays_frozen(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    gate, entered = _hold_first(provider, "pause")
    tar_started = threading.Event()

    def tar(src, dest, **kw):
        tar_started.set()
        dest.write_bytes(b"t")

    monkeypatch.setattr(sandbox_provider, "_write_work_archive", tar)
    outcome: list = []
    freezer = threading.Thread(target=lambda: provider.freeze(sid), daemon=True)
    freezer.start()
    assert entered.wait(10)  # the freeze is admitted and held inside the engine call
    snap = threading.Thread(target=lambda: outcome.append(provider.snapshot(sid)), daemon=True)
    snap.start()
    try:
        assert not tar_started.wait(0.5), "the capture went ahead of a freeze that was already admitted"
    finally:
        gate.set()
    freezer.join(10)
    snap.join(10)
    assert len(outcome) == 1  # the snapshot succeeded, on a room that is frozen
    assert fake.status_of(sid) == "paused" and provider.get(sid)["state"] == "frozen"
    assert len(fake.calls_of("pause")) == 1 and fake.calls_of("unpause") == []  # no second pause, no stray unpause


def test_a_thaw_admitted_before_the_capture_finishes_before_the_tar_so_the_tar_sees_a_paused_room(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    provider.freeze(sid)
    gate, entered = _hold_first(provider, "unpause")
    seen: list = []
    tar_started = threading.Event()

    def tar(src, dest, **kw):
        tar_started.set()
        seen.append(fake.status_of(sid))
        dest.write_bytes(b"t")

    monkeypatch.setattr(sandbox_provider, "_write_work_archive", tar)
    thawer = threading.Thread(target=lambda: provider.thaw(sid), daemon=True)
    thawer.start()
    assert entered.wait(10)
    snap = threading.Thread(target=lambda: provider.snapshot(sid), daemon=True)
    snap.start()
    try:
        assert not tar_started.wait(0.5), "the capture started its tar while a thaw was in flight"
    finally:
        gate.set()
    thawer.join(10)
    snap.join(10)
    assert seen == ["paused"]  # the thaw finished first, then the capture paused the room itself
    assert fake.status_of(sid) == "running" and provider.get(sid)["state"] == "running"


# ---------------------------------------------------------------- item 2: a pause attempted is always undone
def test_a_pause_that_timed_out_but_took_effect_is_undone(fake, provider) -> None:
    sid = _source(provider)
    real = provider._client.pause  # noqa: SLF001

    def pause(cid):
        real(cid)
        raise SandboxOpError("guest_pause_failed", 502, "docker pause timed out")

    provider._client.pause = pause  # noqa: SLF001
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(sid)
    assert err.value.code == "guest_pause_failed"
    assert fake.status_of(sid) == "running" and len(fake.calls_of("unpause")) == 1
    assert provider.pending_reconciles() == {}


def test_a_pause_that_timed_out_and_did_not_take_effect_leaves_a_running_room_and_no_debt(fake, provider) -> None:
    sid = _source(provider)

    def pause(cid):
        raise SandboxOpError("guest_pause_failed", 502, "docker pause timed out")

    provider._client.pause = pause  # noqa: SLF001
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(sid)
    assert err.value.code == "guest_pause_failed"  # the unpause of a running container ("is not paused") is harmless
    assert len(fake.calls_of("unpause")) == 1 and fake.status_of(sid) == "running"
    assert provider.pending_reconciles() == {} and provider.get(sid)["state"] == "running"


def test_a_failed_unpause_is_owed_reported_truthfully_logged_and_retried_by_the_sweep(fake, provider, capsys) -> None:
    sid = _source(provider)
    fake.set(unpause_fail_times=2)  # the capture's unpause fails, and so does the sweep's first retry
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(sid)
    assert err.value.code == "guest_unpause_failed"
    assert provider.list_snapshots() == []
    assert fake.status_of(sid) == "paused"
    assert provider.get(sid)["state"] == "frozen"  # not "running" over a paused room
    assert list(provider.pending_reconciles()) == [sid]
    first = [ln for ln in capsys.readouterr().err.splitlines() if "unpause" in ln and sid in ln]
    assert len(first) == 1
    provider.sweep()  # fails again: still owed, one more line
    assert fake.status_of(sid) == "paused" and provider.get(sid)["state"] == "frozen"
    assert len([ln for ln in capsys.readouterr().err.splitlines() if "unpause" in ln and sid in ln]) == 1
    provider.sweep()  # succeeds
    assert fake.status_of(sid) == "running" and provider.get(sid)["state"] == "running"
    assert provider.pending_reconciles() == {}


def test_a_marked_room_whose_engine_cannot_be_read_fails_closed_on_get(fake, provider) -> None:
    sid = _source(provider)
    fake.set(unpause_fail_times=2)
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    assert list(provider.pending_reconciles()) == [sid]
    real = provider._client.engine_status  # noqa: SLF001

    def unreadable(cid):
        raise SandboxOpError("docker_inspect_failed", 502, "docker inspect failed")

    provider._client.engine_status = unreadable  # noqa: SLF001
    with pytest.raises(SandboxOpError) as err:
        provider.get(sid)
    assert err.value.code == "reconcile_unreadable" and err.value.http_status == 503
    provider._client.engine_status = real  # noqa: SLF001
    assert provider.get(sid)["state"] == "frozen"


def test_a_marked_room_reports_the_engine_now_not_a_stale_read(fake, provider) -> None:
    sid = _source(provider)
    fake.set(unpause_fail_times=2)
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    assert provider.get(sid)["state"] == "frozen"
    # The unpause took effect late: the engine runs the room while the mark is still owed.
    provider._client.engine_status = lambda cid: "running"  # noqa: SLF001
    assert provider.get(sid)["state"] == "running"
    # The container exited: never reported running.
    provider._client.engine_status = lambda cid: "exited"  # noqa: SLF001
    assert provider.get(sid)["state"] == "failed"


def _end_container(fake, sid: str) -> None:
    """The room's container stops on its own (the entrypoint exited, or the engine killed it)."""
    state = fake.state
    for c in state["containers"].values():
        if c["labels"].get("cathedral.sandbox.id") == sid:
            c["status"] = "exited"
    fake._save(state)  # noqa: SLF001


def test_a_marked_room_that_exits_before_the_sweep_stays_failed_after_it(fake, provider) -> None:
    sid = _source(provider)
    fake.set(unpause_fail_times=2)
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    _end_container(fake, sid)
    provider.sweep()  # the reconcile finds nothing to unpause and drops the mark
    assert provider.pending_reconciles() == {}
    assert provider.get(sid)["state"] == "failed"  # not the record's "running"
    provider.sweep()
    assert provider.get(sid)["state"] == "failed"


def _unpause_finds_it_stopped(fake, provider, sid: str) -> None:
    """The container stops between the engine read and the unpause: Docker then says "is not paused"."""
    def unpause(container_id):
        _end_container(fake, sid)
        raise SandboxOpError("docker_unpause_failed", 502, f"Error response from daemon: Container {container_id} is not paused")

    provider._client.unpause = unpause  # noqa: SLF001


def test_a_reconcile_whose_room_stops_before_the_unpause_says_failed(fake, provider) -> None:
    sid = _source(provider)
    fake.set(unpause_fail_times=2)
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    assert fake.status_of(sid) == "paused"
    _unpause_finds_it_stopped(fake, provider, sid)
    provider.sweep()
    assert provider.pending_reconciles() == {}
    assert provider.get(sid)["state"] == "failed"


def test_a_capture_whose_room_stops_before_the_unpause_says_failed(fake, provider) -> None:
    sid = _source(provider)
    _unpause_finds_it_stopped(fake, provider, sid)
    try:
        provider.snapshot(sid)
    except SandboxOpError:
        pass  # whether the capture itself is kept is not this test's business
    assert provider.get(sid)["state"] == "failed"


def test_a_thaw_of_a_room_whose_container_stopped_is_refused_and_says_failed(fake, provider) -> None:
    sid = _source(provider)
    provider.freeze(sid)
    _end_container(fake, sid)
    with pytest.raises(SandboxOpError) as err:
        provider.thaw(sid)
    assert (err.value.code, err.value.http_status) == ("sandbox_not_running", 409)
    assert provider.get(sid)["state"] == "failed"
    provider.delete(sid)
    assert sid not in provider._ended_rooms  # noqa: SLF001


def test_a_thaw_of_a_room_already_running_in_the_engine_still_succeeds(fake, provider) -> None:
    sid = _source(provider)
    provider.freeze(sid)
    provider._client.unpause(provider._guests[sid].container_id)  # noqa: SLF001  unpaused behind the record
    assert provider.thaw(sid)["state"] == "running"
    assert provider.get(sid)["state"] == "running"


def test_an_owed_unpause_is_dropped_when_the_room_is_gone(fake, provider) -> None:
    sid = _source(provider)
    fake.set(unpause_fail_times=1)
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    provider.delete(sid)
    provider.sweep()
    assert provider.pending_reconciles() == {}


def test_the_tar_has_a_deadline_and_a_byte_limit_that_the_provider_passes(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    seen: dict = {}

    def tar(src, dest, **kw):
        seen.update(kw)
        dest.write_bytes(b"t")

    monkeypatch.setattr(sandbox_provider, "_write_work_archive", tar)
    _snapshot(provider, sid)
    assert seen["max_bytes"] == 5 * GIB and seen["deadline"] > _time.monotonic()


def test_the_real_tar_stops_at_its_deadline(tmp_path) -> None:
    work = tmp_path / "w"
    work.mkdir()
    (work / "a").write_bytes(b"x" * 100)
    with pytest.raises(SandboxOpError) as err:
        sandbox_provider._write_work_archive(work, tmp_path / "t.tgz", deadline=_time.monotonic() - 1)
    assert err.value.code == "snapshot_timeout"


# ---------------------------------------------------------------- item 3: the reaper leaves a capture's image alone
def test_a_sweep_between_the_commit_and_the_record_does_not_remove_the_image(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    gate, entered = threading.Event(), threading.Event()
    real = sandbox_provider._sha256_file

    def slow_hash(path):
        entered.set()
        assert gate.wait(10)
        return real(path)

    monkeypatch.setattr(sandbox_provider, "_sha256_file", slow_hash)
    outcome: list = []
    worker = threading.Thread(target=lambda: outcome.append(provider.get_operation(provider.snapshot(sid))["result"]), daemon=True)
    worker.start()
    try:
        assert entered.wait(10)  # committed, unpaused, not yet recorded
        provider._reconcile_interval = 0  # noqa: SLF001
        provider._last_reconcile = None  # noqa: SLF001
        provider.sweep()
        assert [i for i in fake.state["images"] if i.startswith("cathedral-snap-")], "the sweep removed an image mid-capture"
        assert provider.list_snapshots() == []
    finally:
        gate.set()
        worker.join(10)
    (result,) = outcome
    assert _fork(provider, result["snapshot_id"])["guest"]["image"] == f"cathedral-snap-{result['snapshot_id']}:latest"
    assert provider._snapshot_images[result["snapshot_id"]]  # noqa: SLF001


# ---------------------------------------------------------------- item 4: cleanup holes
def test_a_commit_that_succeeded_but_failed_to_report_leaves_no_image(fake, provider) -> None:
    sid = _source(provider)
    real = provider._client.commit  # noqa: SLF001

    def commit(cid, image_name, **kw):
        real(cid, image_name, **kw)
        raise SandboxOpError("snapshot_failed", 502, "docker image inspect timed out")

    provider._client.commit = commit  # noqa: SLF001
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    assert not [i for i in fake.state["images"] if i.startswith("cathedral-snap-")]
    assert fake.status_of(sid) == "running"


def test_a_failure_while_the_record_is_inserted_leaves_no_replayable_record(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    from cathedral import sandbox_api

    real = sandbox_api.operation_id
    state = {"armed": True}

    def op_id():
        if state["armed"]:
            state["armed"] = False
            raise RuntimeError("injected failure while the record is written")
        return real()

    monkeypatch.setattr(sandbox_api, "operation_id", op_id)
    with pytest.raises(RuntimeError):
        provider.snapshot(sid, name="n")
    assert provider.list_snapshots() == [] and provider._inner._snapshot_capture == {}  # noqa: SLF001
    assert not [i for i in fake.state["images"] if i.startswith("cathedral-snap-")]
    assert not list(provider._inner._base.glob("snap_*"))  # noqa: SLF001
    again = _snapshot(provider, sid, name="n")  # the name is free and nothing stale is replayed
    assert len(fake.calls_of("commit")) == 2 and again["snapshot_id"]


# ---------------------------------------------------------------- item 5: limits before allocation
def test_the_tar_stops_at_the_cap_and_never_writes_past_it(tmp_path) -> None:
    work = tmp_path / "w"
    work.mkdir()
    (work / "big").write_bytes(os.urandom(400_000))
    dest = tmp_path / "t.tgz"
    with pytest.raises(SandboxOpError) as err:
        sandbox_provider._write_work_archive(work, dest, max_bytes=50_000)
    assert (err.value.code, err.value.http_status) == ("snapshot_too_large", 413)
    assert dest.stat().st_size <= 50_000


def test_two_concurrent_captures_that_together_exceed_the_store_are_not_both_started(fake, monkeypatch) -> None:
    p = DockerGuestProvider(inner=InMemorySandboxProvider(max_snapshot_bytes=8 * GIB, enforce_disk=True))
    try:
        a, b = _room(p, "a"), _room(p, "b")  # each room may write up to 5 GiB: 10 GiB would not fit in 8
        gate, entered = threading.Event(), threading.Event()
        limits: list = []

        def tar(src, dest, **kw):
            limits.append(kw.get("max_bytes"))
            entered.set()
            assert gate.wait(10)
            dest.write_bytes(b"t")

        monkeypatch.setattr(sandbox_provider, "_write_work_archive", tar)
        worker = threading.Thread(target=lambda: p.snapshot(a), daemon=True)
        worker.start()
        try:
            assert entered.wait(10)
            with pytest.raises(SandboxOpError) as err:
                p.snapshot(b)
            assert (err.value.code, err.value.http_status) == ("snapshot_store_sold_out", 429)
            assert fake.status_of(b) == "running" and len(fake.calls_of("pause")) == 1
        finally:
            gate.set()
            worker.join(10)
        assert limits == [5 * GIB]
        assert _snapshot(p, b)["snapshot_id"]  # the reservation went away with the first capture
    finally:
        p.close()


# ---------------------------------------------------------------- item 6: no unlink under the provider lock
def test_the_aborted_captures_tar_is_removed_outside_the_provider_lock(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _tar_fails)
    owned: list[bool] = []
    real_unlink = Path.unlink

    def unlink(self, *a, **kw):
        if self.name.startswith("snap_"):
            owned.append(provider._inner._lock._is_owned())  # noqa: SLF001
        return real_unlink(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", unlink)
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    assert owned and not any(owned)
    assert not list(provider._inner._base.glob("snap_*"))  # noqa: SLF001


# ======================================================================== main's terminal and exec code against a capture
class _StubPty:
    """Stands in for agent_pty.PtyProcess: a host process of `docker exec -it`, which lives in the room's container."""

    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.sizes: list[tuple[int, int]] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    def resize(self, cols: int, rows: int) -> None:
        self.sizes.append((cols, rows))

    def close(self) -> None:
        self.closed = True


def test_terminal_routes_do_not_touch_the_room_and_survive_a_capture(fake, provider, monkeypatch) -> None:
    # Main's terminals (line and PTY) run inside the room's container: paused with it, resumed with it.
    # None of them writes /work from the host, so none is counted in flight or refused. The session
    # records and the host-side PTY process are not touched by the pause.
    sid = _source(provider)
    stub = _StubPty()
    inner = provider._inner
    line_id = provider.create_terminal(sid)["id"]
    pty_id = inner.create_terminal(sid, mode="pty", spawn=lambda c, r, on_output, on_exit: stub)["id"]
    for tid in (line_id, pty_id):
        provider.connect_terminal(sid, tid, ticket=provider.mint_access_ticket(sid)["ticket"])
    assert stub.closed is False
    gate, entered = threading.Event(), threading.Event()
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, gate=gate, entered=entered))
    worker = threading.Thread(target=lambda: provider.snapshot(sid), daemon=True)
    worker.start()
    try:
        assert entered.wait(10)  # the room is paused, the tar is running
        done: list = []

        def during() -> None:
            provider.terminal_write(sid, pty_id, b"ls\n")
            provider.terminal_resize(sid, pty_id, 100, 30)
            provider.terminal_write(sid, line_id, "echo hi\n")
            done.append(provider.create_terminal(sid)["id"])
            done.append(len(provider.list_terminals(sid)))

        t = threading.Thread(target=during, daemon=True)
        t.start()
        t.join(10)
        assert not t.is_alive() and len(done) == 2, "a terminal call hung or failed during the capture"
    finally:
        gate.set()
        worker.join(10)
    assert stub.writes == [b"ls\n"] and stub.sizes == [(100, 30)] and stub.closed is False
    ids = {t["id"] for t in provider.list_terminals(sid)}
    assert {line_id, pty_id} <= ids  # both sessions survived, none marked exited by the pause
    assert not any(t.get("exited") for t in provider.list_terminals(sid))
    assert fake.status_of(sid) == "running"


def test_kept_exec_results_are_untouched_by_a_capture_and_are_not_in_the_tar(fake, provider, tmp_path) -> None:
    # The kept (spill) results are in the process's memory under (room, token), read through a virtual
    # /work/.cathedral-spill path: never a file under the room's /work, so never in a snapshot.
    from cathedral import exec_spill

    sid = _source(provider)
    token = "ab" * 16
    spill = exec_spill.open_spill(sid, token, 1024)
    spill.add("stdout", b"kept")
    result = _snapshot(provider, sid)
    path, _ = provider._inner._snapshots[result["snapshot_id"]]  # noqa: SLF001
    import tarfile as _tf

    with _tf.open(path) as tf:
        assert not [n for n in tf.getnames() if "cathedral-spill" in n]
    assert exec_spill.read_spill(sid, token, "stdout") == b"kept"  # still there after the capture
    exec_spill.close_spill(sid, token)


def test_a_fork_carries_no_terminals_no_pty_and_no_kept_exec_results_of_the_source(fake, provider) -> None:
    # Terminals, PTY sessions and kept (spill) exec results are keyed by room id in memory
    # (provider._terminals[room_id], exec_spill._spills[(room_id, token)]). A fork has a new id and
    # starts empty. Native exec holds and re-attach state are the broker's, keyed by its own room name.
    from cathedral import exec_spill
    from cathedral.sandbox_api import FileGet

    result, _, _ = _captured(provider)
    src = result["source_sandbox_id"]
    provider.create_terminal(src)
    token = "cd" * 16
    exec_spill.open_spill(src, token, 1024).add("stdout", b"kept")
    try:
        doc = _fork(provider, result["snapshot_id"])
        assert doc["id"] != src
        assert provider.list_terminals(doc["id"]) == []
        assert exec_spill.read_spill(doc["id"], token, "stdout") is None
        with pytest.raises(SandboxOpError) as err:
            provider.read_file(doc["id"], FileGet(path=f"/work/.cathedral-spill/{token}/stdout"))
        assert err.value.code == "file_not_found"
        assert len(provider.list_terminals(src)) == 1  # the source keeps its own
    finally:
        exec_spill.close_spill(src, token)

# ======================================================================== review 2: reconcile instead of guessing
def _fail_unpause_after_capture(fake, provider, sid) -> None:
    """Leave a room paused with a reconcile owed: the capture's unpause fails once."""
    fake.set(unpause_fail_times=1)
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    assert fake.status_of(sid) == "paused" and sid in provider.pending_reconciles()


def test_a_sweep_cannot_unpause_a_room_while_a_second_capture_tars_it(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    _fail_unpause_after_capture(fake, provider, sid)
    with provider._inner._lock:  # noqa: SLF001
        provider._reconcile_pending[sid] = None  # noqa: SLF001  a debt still marked while the next capture runs
    gate, entered = threading.Event(), threading.Event()
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, gate=gate, entered=entered))
    worker = threading.Thread(target=lambda: provider.snapshot(sid), daemon=True)
    worker.start()
    try:
        assert entered.wait(10)
        unpauses = len(fake.calls_of("unpause"))
        with provider._inner._lock:  # noqa: SLF001
            provider._reconcile_pending[sid] = None  # noqa: SLF001
        provider.sweep()  # the sweep only triggers a reconcile; admission refuses it during a capture
        assert len(fake.calls_of("unpause")) == unpauses and fake.status_of(sid) == "paused"
    finally:
        gate.set()
        worker.join(10)
    assert fake.status_of(sid) == "running"


def test_an_unpause_that_took_effect_but_timed_out_is_not_reported_frozen_and_the_next_capture_pauses(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    real = provider._client.unpause  # noqa: SLF001
    provider._client.unpause = lambda cid: (real(cid), (_ for _ in ()).throw(SandboxOpError("guest_unpause_failed", 502, "docker unpause timed out")))[0]  # noqa: SLF001
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    provider._client.unpause = real  # noqa: SLF001
    assert fake.status_of(sid) == "running" and provider.get(sid)["state"] == "running"  # read from the engine, not assumed
    seen: list = []

    def tar(src, dest, **kw):
        seen.append(fake.status_of(sid))
        dest.write_bytes(b"t")

    monkeypatch.setattr(sandbox_provider, "_write_work_archive", tar)
    _snapshot(provider, sid)
    assert seen == ["paused"]  # the capture paused it: it did not trust a stale "frozen" record
    assert provider.pending_reconciles() == {} and fake.status_of(sid) == "running"


def test_a_stale_debt_cannot_unpause_a_room_the_customer_froze(fake, provider) -> None:
    sid = _source(provider)
    _fail_unpause_after_capture(fake, provider, sid)
    provider.freeze(sid)  # the room is already paused: that is the customer's wish, not an error
    assert provider.pending_reconciles() == {} and provider.get(sid)["state"] == "frozen"
    for _ in range(3):
        provider.sweep()
    assert fake.status_of(sid) == "paused" and provider.get(sid)["state"] == "frozen"


def test_a_failed_thaw_does_not_report_running_over_a_paused_room(fake, provider) -> None:
    sid = _source(provider)
    provider.freeze(sid)
    fake.set(unpause_fail_times=1)
    with pytest.raises(SandboxOpError):
        provider.thaw(sid)
    assert fake.status_of(sid) == "paused" and provider.get(sid)["state"] == "frozen"
    provider.sweep()  # the customer's wish is still "frozen": nothing to undo
    assert fake.status_of(sid) == "paused" and provider.pending_reconciles() == {}
    provider.thaw(sid)
    assert fake.status_of(sid) == "running" and provider.get(sid)["state"] == "running"


def test_a_capture_waits_for_a_reconcile_in_flight(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    _fail_unpause_after_capture(fake, provider, sid)
    gate, entered = _hold_first(provider, "unpause")
    tar_started = threading.Event()

    def tar(src, dest, **kw):
        tar_started.set()
        dest.write_bytes(b"t")

    monkeypatch.setattr(sandbox_provider, "_write_work_archive", tar)
    reconciler = threading.Thread(target=lambda: provider._reconcile_room(sid), daemon=True)  # noqa: SLF001
    reconciler.start()
    assert entered.wait(10)
    snap = threading.Thread(target=lambda: provider.snapshot(sid), daemon=True)
    snap.start()
    try:
        assert not tar_started.wait(0.5), "a capture started while a reconcile was in flight"
    finally:
        gate.set()
    reconciler.join(10)
    snap.join(10)
    assert tar_started.is_set() and fake.status_of(sid) == "running"


def test_a_reconcile_and_a_customer_freeze_do_not_cross(fake, provider) -> None:
    sid = _source(provider)
    _fail_unpause_after_capture(fake, provider, sid)
    gate, entered = _hold_first(provider, "unpause")
    reconciler = threading.Thread(target=lambda: provider._reconcile_room(sid), daemon=True)  # noqa: SLF001
    reconciler.start()
    assert entered.wait(10)
    freezer = threading.Thread(target=lambda: provider.freeze(sid), daemon=True)
    freezer.start()
    freezer.join(0.5)
    assert freezer.is_alive(), "the freeze ran in the middle of a reconcile"
    gate.set()
    reconciler.join(10)
    freezer.join(10)
    assert fake.status_of(sid) == "paused" and provider.get(sid)["state"] == "frozen"  # the customer's freeze is last
    assert provider.pending_reconciles() == {}


def test_two_reconciles_at_once_make_one_engine_call(fake, provider) -> None:
    sid = _source(provider)
    _fail_unpause_after_capture(fake, provider, sid)
    gate, entered = _hold_first(provider, "unpause")
    before = len(fake.calls_of("unpause"))
    first = threading.Thread(target=lambda: provider._reconcile_room(sid), daemon=True)  # noqa: SLF001
    first.start()
    assert entered.wait(10)
    second = threading.Thread(target=lambda: provider._reconcile_room(sid), daemon=True)  # noqa: SLF001
    second.start()
    second.join(5)
    gate.set()
    first.join(10)
    assert len(fake.calls_of("unpause")) == before + 1 and fake.status_of(sid) == "running"


def test_a_room_deleted_while_a_reconcile_is_pending_drops_it_without_touching_the_engine(fake, provider) -> None:
    sid = _source(provider)
    _fail_unpause_after_capture(fake, provider, sid)
    provider.delete(sid)
    unpauses = len(fake.calls_of("unpause"))
    provider.sweep()
    assert provider.pending_reconciles() == {} and len(fake.calls_of("unpause")) == unpauses


# ---------------------------------------------------------------- review 2, item 2 and 3: an exec refused by a paused room
def test_a_probe_refused_by_a_paused_room_is_not_cached_as_no_timeout_tool(fake, provider) -> None:
    from cathedral.sandbox_api import ExecRequest

    sid = _source(provider)
    fake.set(exec_model=None)
    # Paused at the engine only (as a capture does), so the record is not frozen and the exec reaches the
    # probe; a customer freeze is refused before it (#704). The engine refuses any exec on a paused
    # container, as docker does.
    cid = provider._guests[sid].container_id  # noqa: SLF001
    provider._client.pause(cid)  # noqa: SLF001
    with pytest.raises(SandboxOpError) as err:
        provider.exec(sid, ExecRequest(cmd=["echo", "x"], timeout_seconds=5))
    assert err.value.code == "sandbox_paused"
    assert provider._guests[sid].timeout_form is None and provider._guests[sid].has_bash is None  # noqa: SLF001
    provider._client.unpause(cid)  # noqa: SLF001
    # After the room runs again the probe reads the image: with the fake's default exec it finds a timeout tool.
    result = provider.exec(sid, ExecRequest(cmd=["echo", "x"], timeout_seconds=5))
    assert provider._guests[sid].timeout_form in ("gnu", "busybox") and result.exit_code == 0  # noqa: SLF001


def test_a_terminal_line_written_during_a_capture_is_refused_by_the_engine_not_hung(fake, provider, monkeypatch) -> None:
    sid = _source(provider)
    tid = provider.create_terminal(sid)["id"]
    provider.connect_terminal(sid, tid, ticket=provider.mint_access_ticket(sid)["ticket"])
    gate, entered = threading.Event(), threading.Event()
    monkeypatch.setattr(sandbox_provider, "_write_work_archive", _bytes_writer(fake, gate=gate, entered=entered))
    worker = threading.Thread(target=lambda: provider.snapshot(sid), daemon=True)
    worker.start()
    try:
        assert entered.wait(10)
        answer: list = []
        t = threading.Thread(target=lambda: answer.append(provider.terminal_write(sid, tid, "echo hi\n")), daemon=True)
        t.start()
        t.join(10)
        assert answer and not t.is_alive(), "a terminal line hung during the capture"
        out = provider.terminal_read(sid, tid)
        # What really happens: the exec is refused by the paused container, and the terminal shows docker's own message.
        assert "is paused" in json.dumps(out)
    finally:
        gate.set()
        worker.join(10)


# ======================================================================== review 2: fork safety
def _count_by_name(provider, monkeypatch, name: str, first_ids, then_id):
    """The first len(first_ids) answers for *name* are the verified id; later answers are then_id (a moved tag)."""
    calls = {"n": 0}
    real_id, real_inspect = provider._image_id_of, provider._client.image_inspect  # noqa: SLF001

    def which() -> str:
        calls["n"] += 1
        return first_ids[calls["n"] - 1] if calls["n"] <= len(first_ids) else then_id

    def image_id_of(ref):
        return which() if ref == name else real_id(ref)

    def image_inspect(ref):
        if ref == name:
            doc = dict(real_inspect(ref))
            doc["Id"] = which()
            return doc
        return real_inspect(ref)

    monkeypatch.setattr(provider, "_image_id_of", image_id_of)
    monkeypatch.setattr(provider._client, "image_inspect", image_inspect)  # noqa: SLF001
    return calls


def _fork_argv(fake, doc) -> list[str]:
    return next(c["argv"] for c in fake.state["containers"].values() if c["labels"].get("cathedral.sandbox.id") == doc["id"])


@pytest.mark.parametrize("looks_at_a", [1, 2, 3, 4, 5])
def test_a_fork_never_starts_an_image_other_than_the_verified_one_when_the_tag_moves(fake, provider, monkeypatch, looks_at_a) -> None:
    result, _, _ = _captured(provider)
    name, a, b = f"cathedral-snap-{result['snapshot_id']}:latest", result["committed_image_id"], "sha256:" + "ab" * 32
    _count_by_name(provider, monkeypatch, name, [a] * looks_at_a, b)  # A for the first looks, then B for every later look at the name
    runs = len(fake.calls_of("run"))
    try:
        doc = _fork(provider, result["snapshot_id"])
    except SandboxOpError as err:
        assert err.code == "snapshot_corrupt"
        assert len(fake.calls_of("run")) == runs
        return
    argv = _fork_argv(fake, doc)
    assert a in argv and b not in argv  # started from the verified id


def test_a_tag_that_moves_after_the_one_check_does_not_change_the_image_a_fork_starts(fake, provider, monkeypatch) -> None:
    # The fork looks at the name once, to pin the verified id, and starts that id: a later move of the tag is not seen.
    result, _, _ = _captured(provider)
    name, a, b = f"cathedral-snap-{result['snapshot_id']}:latest", result["committed_image_id"], "sha256:" + "ab" * 32
    _count_by_name(provider, monkeypatch, name, [a], b)  # only the first look is A
    doc = _fork(provider, result["snapshot_id"])
    argv = _fork_argv(fake, doc)
    assert a in argv and b not in argv


def test_a_record_whose_image_id_changed_before_the_start_is_snapshot_corrupt_and_leaves_nothing(fake, provider) -> None:
    result, _, _ = _captured(provider)
    runs = len(fake.calls_of("run"))
    real_unpack = provider._inner._unpack_snapshot  # noqa: SLF001

    def unpack_then_change(*a, **kw):
        real_unpack(*a, **kw)
        provider._snapshot_meta[result["snapshot_id"]]["committed_image_id"] = "sha256:" + "cd" * 32  # noqa: SLF001

    provider._inner._unpack_snapshot = unpack_then_change  # noqa: SLF001
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, result["snapshot_id"])
    assert (err.value.code, err.value.http_status) == ("snapshot_corrupt", 409)
    _nothing_started(fake, provider, runs)


def test_a_snapshot_name_deleted_and_made_again_during_the_unpack_is_not_mixed_with_the_original_tar(fake, provider, monkeypatch) -> None:
    src, payload = _room_with_file(provider)
    first = _snapshot(provider, src, name="n")
    other = _room(provider, "other")
    real_open = sandbox_provider._open_snapshot_archive
    swapped = []

    def open_then_replace(path):
        fh = real_open(path)
        if not swapped:
            swapped.append(1)
            provider.delete_snapshot(first["snapshot_id"])
            _snapshot(provider, other, name="n")  # the same name now names another snapshot, with another image
        return fh

    monkeypatch.setattr(sandbox_provider, "_open_snapshot_archive", open_then_replace)
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, "n")
    assert err.value.code == "snapshot_corrupt"
    assert len(fake.calls_of("run")) == runs  # no container started from the replacement's image
    assert len([p for p in provider._inner._base.iterdir() if p.name.startswith("sbx_")]) == 2  # noqa: SLF001  the two source rooms only


# ---------------------------------------------------------------- D8: only a safe name goes into --change
@pytest.mark.parametrize("bad", ["A=\nUSER root\nENV PAD", "A=B", "A B", 'A"B', "A$B", "", "X" * 300, "1ABC", "A-B"],
                         ids=["newline", "equals", "space", "quote", "dollar", "empty", "long", "leading_digit", "dash"])
def test_a_variable_name_that_cannot_go_into_a_change_refuses_the_snapshot_before_anything_is_paused(fake, provider, bad) -> None:
    sid, _ = _room_with_file(provider, env={"OK_NAME": "1"})
    provider._inner._sandboxes[sid].env[bad] = "v"  # noqa: SLF001  create accepts odd keys; the commit must not
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(sid)
    assert (err.value.code, err.value.http_status) == ("snapshot_env_name_unsupported", 422)
    assert fake.calls_of("pause") == [] and fake.calls_of("commit") == [] and fake.status_of(sid) == "running"
    assert provider._inner._captures == {} and provider.list_snapshots() == []  # noqa: SLF001  nothing stays reserved


def test_a_good_name_reaches_the_engine_as_exactly_one_change_argument(fake, provider) -> None:
    sid, _ = _room_with_file(provider, env={"API_TOKEN": "s", "_x1": "y"})
    result = _snapshot(provider, sid)
    (argv,) = fake.calls_of("commit")
    cid = provider._guests[sid].container_id  # noqa: SLF001
    assert argv == ["commit", "--change", "ENV API_TOKEN=", "--change", "ENV _x1=", cid, f"cathedral-snap-{result['snapshot_id']}:latest"]


# ---------------------------------------------------------------- extraction is bounded and unlocked
def _replace_tar(provider, snap_id: str, path: Path, data: bytes) -> None:
    """Put another tar in the store and make the record say it is the captured one (the digest and size match)."""
    path.write_bytes(data)
    record = provider._inner._snapshot_capture[snap_id]["result"]  # noqa: SLF001
    record["work_archive_sha256"] = hashlib.sha256(data).hexdigest()
    record["work_archive_bytes"] = len(data)


def test_a_member_larger_than_the_capture_cap_is_refused_before_it_is_extracted(fake, provider, monkeypatch) -> None:
    result, _, _ = _captured(provider)  # a real capture
    big, path, _ = (lambda r: (r, Path(provider._inner._snapshots[r["snapshot_id"]][0]), None))(_snapshot(provider, _room_with_file(provider, payload=bytes(1 << 20))[0]))  # noqa: SLF001
    snap_id = big["snapshot_id"]
    provider._inner._snapshot_capture[snap_id]["disk_cap_bytes"] = 100_000  # noqa: SLF001  the cap the capture enforced
    extracted: list = []
    real = _tarfile.TarFile.extract

    def spy(self, member, *a, **kw):
        extracted.append(getattr(member, "name", member))
        return real(self, member, *a, **kw)

    monkeypatch.setattr(_tarfile.TarFile, "extract", spy)
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, snap_id)
    assert err.value.code == "snapshot_corrupt"
    assert not [n for n in extracted if str(n).endswith("a.txt")], "the oversized member reached extraction"
    assert not list(provider._inner._base.glob("sbx_*/.incoming"))  # noqa: SLF001


def test_a_tar_longer_than_the_record_says_is_refused(fake, provider) -> None:
    result, _, _ = _captured(provider)
    provider._inner._snapshot_capture[result["snapshot_id"]]["result"]["work_archive_bytes"] -= 10  # noqa: SLF001
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, result["snapshot_id"])
    assert err.value.code == "snapshot_corrupt"
    _nothing_started(fake, provider, runs)


@pytest.mark.parametrize("old_python", [False, True], ids=["data_filter", "no_filter_fallback"])
def test_a_device_node_in_the_tar_is_refused_on_every_python(fake, provider, monkeypatch, old_python) -> None:
    import io

    result, path, _ = _captured(provider)
    buf = io.BytesIO()
    with _tarfile.open(fileobj=buf, mode="w:gz") as t:
        dev = _tarfile.TarInfo("dev0")
        dev.type, dev.devmajor, dev.devminor = _tarfile.CHRTYPE, 1, 3
        t.addfile(dev)
    _replace_tar(provider, result["snapshot_id"], path, buf.getvalue())
    if old_python:
        real = _tarfile.TarFile.extract

        def no_filter(self, member, path=".", *a, **kw):
            if "filter" in kw:
                raise TypeError("extract() got an unexpected keyword argument 'filter'")
            return real(self, member, path, *a, **kw)

        monkeypatch.setattr(_tarfile.TarFile, "extract", no_filter)
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, result["snapshot_id"])
    assert err.value.code in ("unsafe_tar", "snapshot_corrupt")
    _nothing_started(fake, provider, runs)


def test_the_unpack_and_the_hash_run_outside_the_provider_lock(fake, provider, monkeypatch) -> None:
    result, _, _ = _captured(provider)
    other = _room(provider, "other")
    gate = threading.Event()
    owned: list[bool] = []

    def slow_open(path):
        reader = _SlowReader(path, lambda: (owned.append(provider._inner._lock._is_owned()), gate.wait(10)))  # noqa: SLF001
        return reader

    monkeypatch.setattr(sandbox_provider, "_open_snapshot_archive", slow_open)
    worker = threading.Thread(target=lambda: _fork(provider, result["snapshot_id"]), daemon=True)
    worker.start()
    try:
        deadline = _time.monotonic() + 10
        while not owned and _time.monotonic() < deadline:
            _time.sleep(0.01)
        answered: list = []
        reader = threading.Thread(target=lambda: answered.append(provider.get(other)["id"]), daemon=True)
        reader.start()
        reader.join(5)
        assert answered == [other], "another room's call waited for a fork's unpack"
        assert owned and not any(owned)
    finally:
        gate.set()
        worker.join(10)


# ---------------------------------------------------------------- order of refusals and removal timeouts
def test_an_expired_snapshot_is_not_found_even_when_its_image_is_also_missing(fake, provider) -> None:
    from dataclasses import replace

    result, path, _ = _captured(provider)
    snap_id = result["snapshot_id"]
    _, rec = provider._inner._snapshots[snap_id]  # noqa: SLF001
    provider._inner._snapshots[snap_id] = (path, replace(rec, created_at=rec.created_at - timedelta(seconds=rec.ttl_seconds + 1)))  # noqa: SLF001
    state = fake.state
    state["images"].remove(f"cathedral-snap-{snap_id}:latest")
    fake._save(state)  # noqa: SLF001
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, snap_id)
    assert (err.value.code, err.value.http_status) == ("snapshot_not_found", 404)


def test_an_image_removal_that_times_out_is_still_queued_for_the_sweep(fake, provider) -> None:
    result, _, _ = _captured(provider)
    image = f"cathedral-snap-{result['snapshot_id']}:latest"
    real = provider._client.run  # noqa: SLF001

    def run(argv, **kw):
        if argv[:3] == ["docker", "image", "rm"]:
            raise SandboxOpError("docker_timeout", 502, "docker image rm timed out")
        return real(argv, **kw)

    provider._client.run = run  # noqa: SLF001
    deleted, pending = provider.delete_snapshot_ex(result["snapshot_id"])
    provider._client.run = real  # noqa: SLF001
    assert deleted is True and pending is True and image in provider.pending_image_removals()
    provider.sweep()
    assert image not in fake.state["images"] and provider.pending_image_removals() == {}


# ---------------------------------------------------------------- AB#604 re-review: checked again after the start
def _late(provider, monkeypatch, after_start) -> None:
    """Run *after_start* right after docker run returns, as a delete or a publish racing the start would."""
    real = provider._start_container  # noqa: SLF001

    def start(*args, **kwargs):
        container_id = real(*args, **kwargs)
        after_start(kwargs)
        return container_id

    monkeypatch.setattr(provider, "_start_container", start)


def test_a_snapshot_deleted_while_the_fork_starts_is_409_and_the_started_container_is_removed(fake, provider, monkeypatch) -> None:
    result, _, _ = _captured(provider)
    snap_id = result["snapshot_id"]
    _late(provider, monkeypatch, lambda _kw: provider.delete_snapshot(snap_id))
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, snap_id)
    assert (err.value.code, err.value.http_status) == ("snapshot_corrupt", 409)
    assert len(fake.calls_of("run")) == runs + 1  # it did start, then went
    assert len(fake.containers) == 1 and len(provider._guests) == 1  # noqa: SLF001  the source room only
    assert provider.quota()["usage"]["resident_sandboxes"] == 1


def test_an_ordinary_create_whose_image_became_a_snapshot_image_while_it_started_is_refused_and_removed(fake, provider, monkeypatch) -> None:
    fake.add_image("plain:1")
    published: set[str] = set()
    real_keys = provider._snapshot_image_keys  # noqa: SLF001

    def keys():
        ids, names = real_keys()
        return ids | published, names

    monkeypatch.setattr(provider, "_snapshot_image_keys", keys)
    _late(provider, monkeypatch, lambda kw: published.add(kw["image"].removeprefix("sha256:")))
    with pytest.raises(SandboxOpError) as err:
        _create_image(provider, "plain:1")
    assert (err.value.code, err.value.http_status) == ("snapshot_image_fork_only", 400)
    assert fake.containers == {} and provider._guests == {}  # noqa: SLF001
    assert provider.quota()["usage"]["resident_sandboxes"] == 0


def test_a_fork_of_an_expired_id_never_starts_the_snapshot_named_that_id(fake, provider) -> None:
    # AB#604 review schedule, through create(): A is snapshotted and signed as A; C is snapshotted under the NAME
    # of A's id; A expires. A fork of A's id must be 404, never a room built from C.
    import dataclasses

    first, _, _ = _captured(provider)
    a = first["snapshot_id"]
    c = _snapshot(provider, _source(provider), name=a)["snapshot_id"]
    assert c != a
    path, rec = provider._inner._snapshots[a]  # noqa: SLF001
    provider._inner._snapshots[a] = (path, dataclasses.replace(rec, created_at=rec.created_at - _dt.timedelta(days=30)))  # noqa: SLF001
    runs = len(fake.calls_of("run"))
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, a)
    assert (err.value.code, err.value.http_status) == ("snapshot_not_found", 404)
    assert len(fake.calls_of("run")) == runs
    assert provider._resolve_snapshot(a) is None  # noqa: SLF001


def test_lookups_after_the_first_resolution_are_by_id_and_never_match_a_name(fake, provider) -> None:
    first, _, _ = _captured(provider)
    gone = first["snapshot_id"]
    other = _snapshot(provider, _source(provider), name=gone)  # a second snapshot whose NAME is the first one's id
    assert other["snapshot_id"] != gone
    provider.delete_snapshot(gone)
    with pytest.raises(SandboxOpError) as err:
        provider._pin_snapshot(gone)  # noqa: SLF001
    assert err.value.code == "snapshot_not_found"
    assert provider._snapshot_by_id(gone) is None  # noqa: SLF001
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, gone)  # through create(): the id-shaped reference is never read as a name
    assert err.value.code == "snapshot_not_found"


# ---------------------------------------------------------------- H9: the fork's environment as the engine builds it
def _env_of(fake, room_id: str) -> dict:
    return next(c["env"] for c in fake.state["containers"].values() if c["labels"].get("cathedral.sandbox.id") == room_id)


def test_the_fork_sees_its_own_values_and_blank_values_for_the_first_rooms_create_time_variables(fake, provider) -> None:
    result, _, _ = _captured(provider, env={"API_TOKEN": "s3cret", "MODE": "x"})
    req = CreateSandboxRequest(snapshot_id=result["snapshot_id"], resources=RES, env={"API_TOKEN": "fork-own"})
    env = _env_of(fake, provider.create(req, api_key="k", idempotency=None, body_digest="f")["id"])
    assert env["API_TOKEN"] == "fork-own" and env["MODE"] == ""
    assert "s3cret" not in env.values() and "x" not in env.values()


def test_without_the_blanking_the_engine_model_shows_the_value_leak(fake, provider, monkeypatch) -> None:
    # Control: the model above is not just reading argv. With the --change list dropped, the image keeps MODE=x.
    real = provider._client.commit  # noqa: SLF001
    monkeypatch.setattr(provider._client, "commit", lambda cid, name, blank_env=(): real(cid, name))  # noqa: SLF001
    result, _, _ = _captured(provider, env={"API_TOKEN": "s3cret", "MODE": "x"})
    env = _env_of(fake, _fork(provider, result["snapshot_id"])["id"])
    assert env["MODE"] == "x" and env["API_TOKEN"] == "s3cret"


class _FakeEgress:
    def __init__(self) -> None:
        self.forgotten: list[str] = []

    def apply(self, container_id, sandbox_id, policy, owner_key):
        return {"policy": {"mode": "deny_all", "allow": []}, "policy_sha256": "0" * 64}

    def forget(self, container_id) -> None:
        self.forgotten.append(container_id)


class _FakeNetPool:
    dns: tuple[str, ...] = ()

    def __init__(self) -> None:
        self.held: list[str] = []
        self.released: list[str | None] = []

    def ensure(self, client) -> None:
        pass

    def acquire(self) -> str:
        self.held.append("bridge")
        return "bridge"

    def release(self, network) -> None:
        self.released.append(network)


def test_a_late_refusal_forgets_the_egress_entry_and_gives_the_network_back(fake, provider, monkeypatch) -> None:
    result, _, _ = _captured(provider)
    snap_id = result["snapshot_id"]
    egress, pool = _FakeEgress(), _FakeNetPool()
    monkeypatch.setattr(provider, "_egress", egress)
    monkeypatch.setattr(provider, "_net_pool", pool)
    started: list[str] = []
    real = provider._start_container  # noqa: SLF001

    def start(*args, **kwargs):
        cid = real(*args, **kwargs)
        started.append(cid)
        provider.delete_snapshot(snap_id)
        return cid

    monkeypatch.setattr(provider, "_start_container", start)
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, snap_id)
    assert err.value.code == "snapshot_corrupt"
    assert egress.forgotten == started and len(started) == 1
    assert pool.released == ["bridge"]
    assert provider._net_pending == {}  # noqa: SLF001


# ---------------------------------------------------------------- AB#604 review of 7b07baa (Codex, Bugbot)
def test_a_deleted_snapshots_image_stays_fork_only_until_it_is_removed(fake, provider) -> None:
    # The record goes at once, but a failed `docker image rm` leaves the image: a plain create from its id
    # must still be refused, or the new room keeps the image in use and the removal never finishes.
    result, _, _ = _captured(provider)
    snap_id, image, image_id = result["snapshot_id"], f"cathedral-snap-{result['snapshot_id']}:latest", result["committed_image_id"]
    fake.set(image_rm_fail_times=1)
    assert provider.delete_snapshot_ex(snap_id) == (True, True)
    runs = len(fake.calls_of("run"))
    for ref in (image_id, image):
        with pytest.raises(SandboxOpError) as err:
            _create_image(provider, ref)
        assert err.value.code == "snapshot_image_fork_only", ref
    assert len(fake.calls_of("run")) == runs
    provider.sweep()
    assert image not in fake.state["images"] and provider.pending_image_removals() == {}
    assert provider._doomed_image_ids == {}  # noqa: SLF001


def test_an_expired_snapshots_image_stays_fork_only_until_it_is_removed(fake, provider) -> None:
    from dataclasses import replace

    result, path, _ = _captured(provider)
    snap_id, image_id = result["snapshot_id"], result["committed_image_id"]
    _, rec = provider._inner._snapshots[snap_id]  # noqa: SLF001
    provider._inner._snapshots[snap_id] = (path, replace(rec, created_at=rec.created_at - timedelta(seconds=rec.ttl_seconds + 1)))  # noqa: SLF001
    fake.set(image_rm_fail_times=2)
    provider.sweep()
    with pytest.raises(SandboxOpError) as err:
        _create_image(provider, image_id)
    assert err.value.code == "snapshot_image_fork_only"


def test_a_snapshot_archive_gone_before_the_fork_opens_it_is_409_not_500(fake, provider, monkeypatch) -> None:
    result, _, _ = _captured(provider)
    resident = provider.quota()["usage"]["resident_sandboxes"]

    def gone(path):
        raise FileNotFoundError(path)

    monkeypatch.setattr(sandbox_provider, "_open_snapshot_archive", gone)
    with pytest.raises(SandboxOpError) as err:
        _fork(provider, result["snapshot_id"])
    assert (err.value.code, err.value.http_status) == ("snapshot_corrupt", 409)
    assert provider.quota()["usage"]["resident_sandboxes"] == resident


def test_a_fork_room_is_not_idle_collected_while_it_unpacks(fake, provider, monkeypatch) -> None:
    result, _, _ = _captured(provider)
    seen: list[list[str]] = []

    def stale_then_check():
        # The unpack outlasts the idle window: every creating room looks idle for an hour.
        with provider._inner._lock:  # noqa: SLF001
            for sb in provider._inner._sandboxes.values():  # noqa: SLF001
                if sb.state == "creating":
                    sb.last_activity_at = sb.last_activity_at - timedelta(hours=1)
        seen.append(provider._inner.collectable_ids())  # noqa: SLF001

    monkeypatch.setattr(sandbox_provider, "_open_snapshot_archive", lambda p: _SlowReader(p, stale_then_check))
    req = CreateSandboxRequest(snapshot_id=result["snapshot_id"], resources=RES, idle_timeout_seconds=60)
    doc = provider.create(req, api_key="k", idempotency=None, body_digest="idle-fork")
    assert seen == [[]]
    assert doc["id"] not in provider._inner.collectable_ids()  # noqa: SLF001  its idle window starts when it runs


def test_a_fork_room_takes_no_write_or_exec_while_its_files_are_unpacked(fake, provider, monkeypatch) -> None:
    # Bugbot on 587b0b9: the room is listed as creating during the unlocked unpack; a write there would land
    # in its folder and break the unpack. Writes and runs are refused until the fork is published.
    import threading

    from cathedral.sandbox_api import ExecRequest

    result, _path, payload = _captured(provider)
    gate, reached = threading.Event(), threading.Event()
    monkeypatch.setattr(sandbox_provider, "_open_snapshot_archive",
                        lambda p: _SlowReader(p, lambda: (reached.set(), gate.wait(10))))
    out: dict = {}
    worker = threading.Thread(target=lambda: out.setdefault("doc", _fork(provider, result["snapshot_id"])), daemon=True)
    worker.start()
    assert reached.wait(10)
    provider._inner._ctx.api_key = "k"  # noqa: SLF001
    (room,) = [s for s in provider._inner._sandboxes.values() if s.unpacking]  # noqa: SLF001
    for call in (lambda: provider.write_file(room.id, "/work/planted.txt", b"x", None),
                 lambda: provider._inner.write_file(room.id, "/work/planted.txt", b"x", None),  # noqa: SLF001
                 lambda: provider._inner.exec(room.id, ExecRequest(cmd=["true"], timeout_seconds=5))):  # noqa: SLF001
        with pytest.raises(SandboxOpError) as err:
            call()
        assert (err.value.code, err.value.http_status) == ("sandbox_not_running", 409)
    gate.set()
    worker.join(10)
    doc = out["doc"]
    assert doc["id"] == room.id and doc["state"] == "running" and not room.unpacking
    assert (_fork_root(provider, doc) / "a.txt").read_bytes() == payload
    assert not (_fork_root(provider, doc) / "planted.txt").exists()


def test_a_retry_of_a_started_fork_answers_the_same_room_after_its_snapshot_expired(fake, provider) -> None:
    # Bugbot on 587b0b9: a retry with the same Idempotency-Key got 404 once the snapshot aged out, while the
    # fork it made still ran, so a caller would make a second room.
    from dataclasses import replace as _replace
    from datetime import timedelta

    result, _path, _payload = _captured(provider)
    snap = result["snapshot_id"]
    req = CreateSandboxRequest(snapshot_id=snap, resources=RES)
    first = provider.create(req, api_key="k", idempotency="fork-1", body_digest="fork")
    runs = len(fake.calls_of("run"))
    with provider._inner._lock:  # noqa: SLF001
        path, rec = provider._inner._snapshots[snap]  # noqa: SLF001
        provider._inner._snapshots[snap] = (path, _replace(rec, created_at=rec.created_at - timedelta(seconds=rec.ttl_seconds + 1)))  # noqa: SLF001
    again = provider.create(req, api_key="k", idempotency="fork-1", body_digest="fork")
    assert again["id"] == first["id"] and len(fake.calls_of("run")) == runs
    # A new key still sees the expired snapshot as gone, and another body under the same key is a conflict.
    with pytest.raises(SandboxOpError) as err:
        provider.create(req, api_key="k", idempotency="fork-2", body_digest="fork")
    assert (err.value.code, err.value.http_status) == ("snapshot_not_found", 404)
    with pytest.raises(SandboxOpError) as err:
        provider.create(req, api_key="k", idempotency="fork-1", body_digest="other")
    assert err.value.http_status in (404, 409)
