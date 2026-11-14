"""DockerGuestProvider snapshot and fork against a fake docker CLI.

Defects from run 5 (2026-10-20):
1. a fork from a snapshot this host does not have started the default image;
2. a snapshot could not leave its host (no push to a registry);
3. snapshot size_bytes measured only the /work archive.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
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
    assert (err.value.code, err.value.http_status) == ("snapshot_image_missing", 409)
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

    def write(src: Path, dest: Path) -> None:
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
        provider.write_file(other, "/work/x.txt", b"1", None)  # another room: untouched
        provider.write_tar(other, "/work", _tiny_tar())
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
    assert provider.pending_unpauses() == {}


def test_a_pause_that_timed_out_and_did_not_take_effect_leaves_a_running_room_and_no_debt(fake, provider) -> None:
    sid = _source(provider)

    def pause(cid):
        raise SandboxOpError("guest_pause_failed", 502, "docker pause timed out")

    provider._client.pause = pause  # noqa: SLF001
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(sid)
    assert err.value.code == "guest_pause_failed"  # the unpause of a running container ("is not paused") is harmless
    assert len(fake.calls_of("unpause")) == 1 and fake.status_of(sid) == "running"
    assert provider.pending_unpauses() == {} and provider.get(sid)["state"] == "running"


def test_a_failed_unpause_is_owed_reported_truthfully_logged_and_retried_by_the_sweep(fake, provider, capsys) -> None:
    sid = _source(provider)
    fake.set(unpause_fail_times=2)  # the capture's unpause fails, and so does the sweep's first retry
    with pytest.raises(SandboxOpError) as err:
        provider.snapshot(sid)
    assert err.value.code == "guest_unpause_failed"
    assert provider.list_snapshots() == []
    assert fake.status_of(sid) == "paused"
    assert provider.get(sid)["state"] == "frozen"  # not "running" over a paused room
    assert list(provider.pending_unpauses()) == [sid]
    first = [ln for ln in capsys.readouterr().err.splitlines() if "unpause" in ln and sid in ln]
    assert len(first) == 1
    provider.sweep()  # fails again: still owed, one more line
    assert fake.status_of(sid) == "paused" and provider.get(sid)["state"] == "frozen"
    assert len([ln for ln in capsys.readouterr().err.splitlines() if "unpause" in ln and sid in ln]) == 1
    provider.sweep()  # succeeds
    assert fake.status_of(sid) == "running" and provider.get(sid)["state"] == "running"
    assert provider.pending_unpauses() == {}


def test_an_owed_unpause_is_dropped_when_the_room_is_gone(fake, provider) -> None:
    sid = _source(provider)
    fake.set(unpause_fail_times=1)
    with pytest.raises(SandboxOpError):
        provider.snapshot(sid)
    provider.delete(sid)
    provider.sweep()
    assert provider.pending_unpauses() == {}


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
