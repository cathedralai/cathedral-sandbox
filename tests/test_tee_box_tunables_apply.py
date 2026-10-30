"""tunables.apply and tunables.get: POST and GET /v1/box/tunables on the TEE box."""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import replace
from pathlib import Path

import pytest
from test_tee_box_executor import DIGEST as EXEC_DIGEST
from test_tee_box_executor import _executor, _inspect_answer, _spec
from test_tee_box_service import (
    BOX_IP,
    CALLER,
    CAPACITY,
    DEFAULT_SHAPE,
    DIGEST,
    OTHER,
    _authorizer,
    _binding,
    _boot,
    _BootIds,
    _handle,
    _push_revocations,
)

from cathedral.tee_box.daemon_reload import DaemonReloader, DaemonReloadError
from cathedral.tee_box.egress import build_egress_policy
from cathedral.tee_box.executor import FakeExecutor, Shape
from cathedral.tee_box.service import TeeBoxSandboxApi
from cathedral.tee_box.tunables import default_tunables, parse_tunables

WARM_SHAPE = Shape(2, 4096, 10240)
PINNED = ["--platform=systrap", "--network=sandbox"]
KING = {"schema": 1, "pool": {"warm_size": 2}, "boot": {"create_concurrency": 4}}
CHALLENGER = {"schema": 1, "docker": {"log_driver": "none"}, "image": {"prime": "page_cache"}}


def _api(tmp_path: Path, executor=None, *, reloader=None, lease=True, source="default"):
    executor = executor or FakeExecutor()
    api = TeeBoxSandboxApi(
        executor=executor,
        authorizer=_authorizer(tmp_path, _binding()),
        egress=build_egress_policy([BOX_IP]),
        capacity=CAPACITY,
        default_shape=DEFAULT_SHAPE,
        boot=_boot(_BootIds()),
        tunables_source=source,
        daemon_reloader=reloader,
    )
    _push_revocations(api)
    if lease:
        assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 600})[0] == 200
    return api, executor


def _apply(api, document, caller=CALLER):
    raw = document if isinstance(document, bytes) else json.dumps(document).encode()
    response = api.handle("POST", "/v1/box/tunables", caller, raw)
    return response.status, json.loads(response.body)


def _create(api):
    return _handle(
        api,
        "POST",
        "/v1/sandboxes",
        body={"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 3600},
    )


# -- tunables.get --------------------------------------------------------------------------


def test_get_reports_the_start_up_tunables_without_a_lease(tmp_path: Path):
    api, _ = _api(tmp_path, lease=False, source="file")
    status, view = _handle(api, "GET", "/v1/box/tunables")
    assert status == 200
    assert view["sha256"] == default_tunables().sha256
    assert view["source"] == "file" and view["applied_at"] is None
    assert view["values"] == {"schema": 1, **default_tunables().nested()}
    assert view["daemon_reload"] is False and view["daemon_confirmed"] is True


def test_get_takes_no_query(tmp_path: Path):
    api, _ = _api(tmp_path)
    assert _handle(api, "GET", "/v1/box/tunables?x=1")[0] == 400


# -- tunables.apply ------------------------------------------------------------------------


def test_apply_returns_the_sha_of_what_the_box_now_runs(tmp_path: Path):
    api, fake = _api(tmp_path)
    status, view = _apply(api, KING)
    expected = parse_tunables(json.dumps(KING))
    assert status == 200, view
    assert view["sha256"] == expected.sha256 != default_tunables().sha256
    assert view["previous_sha256"] == default_tunables().sha256
    assert view["changed"] is True and view["reloaded"] is False
    assert view["source"] == "applied" and isinstance(view["applied_at"], int)
    assert fake.tunables == expected
    assert api._create_slots._initial_value == 4
    status, got = _handle(api, "GET", "/v1/box/tunables")
    assert got["sha256"] == expected.sha256 and got["source"] == "applied"


def test_the_sha_is_of_the_normalised_document_not_the_bytes(tmp_path: Path):
    # Defaults spelled out, other key order, whitespace: the same tunables, the same sha.
    api, _ = _api(tmp_path)
    spelled = b'{ "pool": {"warm_size": 0, "idle_seconds": 300}, "schema": 1 }'
    status, view = _apply(api, spelled)
    assert status == 200 and view["sha256"] == default_tunables().sha256
    assert view["changed"] is False


def test_reapplying_the_same_document_changes_nothing(tmp_path: Path):
    api, _ = _api(tmp_path)
    first = _apply(api, KING)[1]
    status, again = _apply(api, KING)
    assert status == 200 and again["changed"] is False
    assert again["sha256"] == first["sha256"] and again["applied_at"] == first["applied_at"]


@pytest.mark.parametrize(
    "document",
    [
        b"",
        b"not json",
        b"[]",
        {"schema": 2},
        {"schema": 1, "pool": {"warm_size": 17}},
        {"schema": 1, "pool": {"warm_size": 1.0}},
        {"schema": 1, "runsc": {"platform": "ptrace"}},
        {"schema": 1, "docker": {"privileged": True}},
        {"schema": 1, "shape": {"vcpus": 64}},
        b'{"schema": 1, "pool": {"warm_size": 1, "warm_size": 2}}',
        b'{"schema": 1, "pad": "' + b"x" * 5000 + b'"}',
    ],
)
def test_apply_validates_like_the_start_up_file(tmp_path: Path, document):
    api, fake = _api(tmp_path)
    status, view = _apply(api, document)
    assert status == 400 and view["error"].startswith("tunables refused")
    assert fake.tunables == default_tunables()


def test_apply_needs_the_lease(tmp_path: Path):
    api, fake = _api(tmp_path, lease=False)
    assert _apply(api, KING)[1]["reason"] == "lease_required"
    assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 600})[0] == 200
    assert _apply(api, KING, caller=OTHER)[1]["reason"] == "box_busy"
    assert fake.tunables == default_tunables()


def test_apply_never_touches_a_live_sandbox(tmp_path: Path):
    api, fake = _api(tmp_path)
    fake.import_image(DIGEST, "registry.example/tasks/base")
    status, room = _create(api)
    assert status == 201
    assert _apply(api, KING)[0] == 200
    assert _apply(api, CHALLENGER)[0] == 200
    assert fake.deleted == []
    assert _handle(api, "GET", f"/v1/sandboxes/{room['id']}")[0] == 200


def test_apply_is_refused_while_a_create_is_in_flight(tmp_path: Path):
    api, fake = _api(tmp_path)
    api._inflight = 1
    status, view = _apply(api, KING)
    assert status == 409 and view["reason"] == "creates_in_flight"
    assert fake.tunables == default_tunables()
    api._inflight = 0
    assert _apply(api, KING)[0] == 200


def test_fifty_alternations_are_fast_and_keep_rooms(tmp_path: Path):
    api, fake = _api(tmp_path)
    fake.import_image(DIGEST, "registry.example/tasks/base")
    assert _create(api)[0] == 201
    shas = {}
    started = time.monotonic()
    for _ in range(50):
        for name, document in (("king", KING), ("challenger", CHALLENGER)):
            status, view = _apply(api, document)
            assert status == 200 and view["changed"] is True
            shas.setdefault(name, view["sha256"])
            assert view["sha256"] == shas[name]
    assert time.monotonic() - started < 5.0
    assert len(fake.list()) == 1 and fake.deleted == []


# -- runsc flags: the daemon reload ---------------------------------------------------------


def test_a_runsc_change_without_daemon_reload_needs_a_restart(tmp_path: Path):
    api, fake = _api(tmp_path)
    status, view = _apply(api, {"schema": 1, "runsc": {"directfs": False}})
    assert status == 409 and view["reason"] == "runsc_change_needs_restart"
    assert fake.tunables == default_tunables()


class _Daemon:
    """daemon.json on disk, a dockerd that re-reads it on reload, and docker for the executor."""

    def __init__(self, path: Path, *, takes_reload: bool = True, reload_fails: bool = False):
        self.path = path
        self.takes_reload = takes_reload
        self.reload_fails = reload_fails
        self.reloads = 0
        self.calls: list[list[str]] = []
        path.write_text(
            json.dumps(
                {
                    "data-root": "/var/lib/docker",
                    "runtimes": {"runsc": {"path": "/usr/local/bin/runsc", "runtimeArgs": PINNED}},
                }
            )
        )
        self.loaded = json.loads(path.read_text())["runtimes"]

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[:3] == ["systemctl", "reload", "docker"]:
            self.reloads += 1
            if self.reload_fails:
                return subprocess.CompletedProcess(argv, 1, b"", b"")
            if self.takes_reload:
                self.loaded = json.loads(self.path.read_text())["runtimes"]
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        if argv[1] == "info":
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.loaded).encode(), b"")
        if argv[1] == "image":
            return _inspect_answer(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")


def _runsc_api(tmp_path: Path, daemon: _Daemon):
    executor = _executor(daemon, warm_shape=WARM_SHAPE, spawn=lambda work: work())
    reloader = DaemonReloader(str(daemon.path), runner=daemon, sleep=lambda _s: None)
    api, _ = _api(tmp_path, executor, reloader=reloader)
    return api, executor


def test_a_runsc_change_rewrites_the_entry_and_reloads_when_the_box_is_idle(tmp_path: Path):
    daemon = _Daemon(tmp_path / "daemon.json")
    api, executor = _runsc_api(tmp_path, daemon)
    document = {"schema": 1, "runsc": {"directfs": False, "net_channels": 2}}
    status, view = _apply(api, document)
    assert status == 200, view
    assert view["reloaded"] is True and view["daemon_confirmed"] is True
    assert view["sha256"] == parse_tunables(json.dumps(document)).sha256
    written = json.loads(daemon.path.read_text())
    assert written["data-root"] == "/var/lib/docker"  # other keys kept
    assert written["runtimes"]["runsc"]["runtimeArgs"] == [
        *PINNED,
        "--directfs=false",
        "--num-network-channels=2",
    ]
    assert daemon.reloads == 1 and executor.runtime_check()[0]
    # Back to the defaults: one more reload, the pinned two alone.
    assert _apply(api, {"schema": 1})[1]["reloaded"] is True
    assert json.loads(daemon.path.read_text())["runtimes"]["runsc"]["runtimeArgs"] == PINNED


def test_a_runsc_change_is_refused_while_any_sandbox_is_live(tmp_path: Path):
    daemon = _Daemon(tmp_path / "daemon.json")
    reloader = DaemonReloader(str(daemon.path), runner=daemon, sleep=lambda _s: None)
    api, fake = _api(tmp_path, reloader=reloader)
    fake.import_image(DIGEST, "registry.example/tasks/base")
    assert _create(api)[0] == 201
    status, view = _apply(api, {"schema": 1, "runsc": {"overlay2": "all:self"}})
    assert status == 409 and view["reason"] == "sandboxes_live"
    assert daemon.reloads == 0 and fake.tunables == default_tunables()
    # A change that leaves the runsc flags alone still applies with the room live.
    assert _apply(api, KING)[0] == 200


def test_warm_containers_go_before_a_reload(tmp_path: Path):
    daemon = _Daemon(tmp_path / "daemon.json")
    api, executor = _runsc_api(tmp_path, daemon)
    assert _apply(api, {"schema": 1, "pool": {"warm_size": 2, "refill_parallelism": 2}})[0] == 200
    executor.import_image(EXEC_DIGEST, "registry.example/tasks/base")
    executor.maintain_pool(enabled=True, room=4)
    assert executor.warm_count() == 2
    document = {"schema": 1, "pool": {"warm_size": 2}, "runsc": {"directfs": False}}
    assert _apply(api, document)[0] == 200
    assert executor.warm_count() == 0
    assert len([c for c in daemon.calls if c[1:3] == ["rm", "--force"]]) == 2


@pytest.mark.parametrize("failure", ["not_taken", "reload_fails"])
def test_a_failed_reload_restores_the_file_and_the_tunables(tmp_path: Path, failure):
    daemon = _Daemon(
        tmp_path / "daemon.json",
        takes_reload=failure != "not_taken",
        reload_fails=failure == "reload_fails",
    )
    before = daemon.path.read_bytes()
    api, executor = _runsc_api(tmp_path, daemon)
    status, view = _apply(api, {"schema": 1, "runsc": {"directfs": False}})
    assert status == 503 and view["reason"] == "daemon_reload_failed"
    assert json.loads(daemon.path.read_bytes()) == json.loads(before)
    assert executor.tunables == default_tunables()
    got = _handle(api, "GET", "/v1/box/tunables")[1]
    assert got["sha256"] == default_tunables().sha256
    # The restore itself reloaded; only a failed restore leaves the daemon unconfirmed.
    assert got["daemon_confirmed"] is (failure == "not_taken")


# -- executor: the warm pool follows the tunables -------------------------------------------


def _pooled(**pool):
    body = {"warm_size": 2, "refill_parallelism": 2, **pool}
    tunables = parse_tunables(json.dumps({"schema": 1, "pool": body}))
    daemon = _Daemon.__new__(_Daemon)
    daemon.calls, daemon.loaded = [], {}
    daemon.takes_reload, daemon.reload_fails, daemon.reloads = True, False, 0
    deferred = []
    executor = _executor(
        daemon, tunables=tunables, warm_shape=WARM_SHAPE, spawn=lambda work: deferred.append(work)
    )
    executor.import_image(EXEC_DIGEST, "registry.example/tasks/base")
    return executor, daemon, deferred


def _run(deferred):
    while deferred:
        deferred.pop(0)()


def test_new_start_arguments_empty_the_pool():
    executor, _daemon, deferred = _pooled()
    executor.maintain_pool(enabled=True, room=4)
    _run(deferred)
    assert executor.warm_count() == 2
    log_none = parse_tunables(json.dumps({"schema": 1, "docker": {"log_driver": "none"}}))
    executor.apply_tunables(replace(log_none))
    assert executor.warm_count() == 0
    assert executor.reserve_warm(replace(_spec(), env={})) == ""


def test_a_smaller_pool_keeps_the_rest():
    executor, _daemon, deferred = _pooled(warm_size=3, refill_parallelism=3)
    executor.maintain_pool(enabled=True, room=4)
    _run(deferred)
    assert executor.warm_count() == 3
    executor.apply_tunables(parse_tunables('{"schema": 1, "pool": {"warm_size": 1}}'))
    assert executor.warm_count() == 1


def test_a_warm_start_from_before_an_apply_never_joins_the_pool():
    executor, _daemon, deferred = _pooled()
    executor.maintain_pool(enabled=True, room=4)
    assert len(deferred) == 2  # started under the old tunables, not finished
    executor.apply_tunables(
        parse_tunables('{"schema": 1, "pool": {"warm_size": 2}, "docker": {"log_driver": "local"}}')
    )
    _run(deferred)
    assert executor.warm_count() == 0
    removed = [c for c in _daemon.calls if c[1:3] == ["rm", "--force"]]
    assert len(removed) == 2


# -- the daemon reloader --------------------------------------------------------------------


def test_reloader_writes_only_the_runtime_entry(tmp_path: Path):
    daemon = _Daemon(tmp_path / "daemon.json")
    reloader = DaemonReloader(str(daemon.path), runner=daemon, sleep=lambda _s: None)
    config = {"runtimes": {"runsc": {"path": "/usr/local/bin/runsc", "runtimeArgs": PINNED}}}
    reloader.sync(config, lambda: (True, "ok"))
    assert json.loads(daemon.path.read_text())["data-root"] == "/var/lib/docker"


def test_reloader_refuses_a_relative_path_and_a_broken_file(tmp_path: Path):
    with pytest.raises(ValueError):
        DaemonReloader("daemon.json")
    path = tmp_path / "daemon.json"
    path.write_text("{not json")
    with pytest.raises(DaemonReloadError):
        DaemonReloader(str(path), runner=lambda *a, **k: None).sync({"runtimes": {}}, None)
    assert path.read_text() == "{not json"


def test_reloader_creates_a_missing_file_and_removes_it_on_failure(tmp_path: Path):
    path = tmp_path / "daemon.json"
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    reloader = DaemonReloader(str(path), runner=runner, confirm_attempts=2, sleep=lambda _s: None)
    with pytest.raises(DaemonReloadError) as caught:
        reloader.sync({"runtimes": {"runsc": {}}}, lambda: (False, "mismatch"))
    assert caught.value.restored is True and not path.exists()
    assert len(calls) == 2  # the reload, then the reload of the restore


def test_a_warm_container_started_during_a_reload_never_joins_the_pool(tmp_path: Path):
    daemon = _Daemon(tmp_path / "daemon.json")
    api, executor = _runsc_api(tmp_path, daemon)
    assert _apply(api, {"schema": 1, "pool": {"warm_size": 1}})[0] == 200
    executor.import_image(EXEC_DIGEST, "registry.example/tasks/base")
    real_reload = daemon.__call__

    def reload_and_refill(argv, **kwargs):
        # The reaper's refill lands while dockerd still has the old runsc flags.
        if argv[:3] == ["systemctl", "reload", "docker"]:
            executor.maintain_pool(enabled=True, room=4)
        return real_reload(argv, **kwargs)

    api._daemon_reloader._runner = reload_and_refill  # noqa: SLF001
    document = {"schema": 1, "pool": {"warm_size": 1}, "runsc": {"directfs": False}}
    assert _apply(api, document)[1]["reloaded"] is True
    assert executor.warm_count() == 0
