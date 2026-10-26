"""Tunables file, runsc flags, priming, warm pool and bounded create concurrency."""

from __future__ import annotations

import json
import subprocess
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
from test_tee_box_executor import DIGEST as EXEC_DIGEST
from test_tee_box_executor import IMAGE, IMAGE_ID, _executor, _inspect_answer, _spec
from test_tee_box_service import (
    CALLER,
    CAPACITY,
    DEFAULT_SHAPE,
    DIGEST,
    OTHER,
    BOX_IP,
    _authorizer,
    _binding,
    _boot,
    _BootIds,
    _Clock,
    _handle,
    _push_revocations,
)

from cathedral.tee_box.egress import build_egress_policy
from cathedral.tee_box.executor import (
    BOX_LABEL,
    WARM_LABEL,
    FakeExecutor,
    Shape,
)
from cathedral.tee_box.service import MAX_SANDBOXES, TeeBoxSandboxApi
from cathedral.tee_box.tunables import (
    DEFAULTS,
    FIELDS,
    MAX_BYTES,
    PINNED,
    TunablesError,
    default_tunables,
    json_schema,
    load_tunables_file,
    parse_tunables,
)

ROOT = Path(__file__).resolve().parents[1]
WARM_SHAPE = Shape(2, 4096, 10240)


# -- the settings file ------------------------------------------------------------------


def test_no_overrides_means_every_default():
    assert dict(default_tunables().values) == DEFAULTS


@pytest.mark.parametrize(
    "text",
    [
        "",
        "[]",
        "{}",
        '{"schema": 2}',
        '{"schema": true}',
        '{"schema": 1, "mystery": {}}',
        '{"schema": 1, "pool": {"mystery": 1}}',
        '{"schema": 1, "pool": {"warm_size": 17}}',
        '{"schema": 1, "pool": {"warm_size": true}}',
        '{"schema": 1, "pool": {"warm_size": 1.0}}',
        '{"schema": 1, "pool": {"warm_size": 1, "warm_size": 2}}',
        '{"schema": 1, "runsc": {"overlay2": "root:memory"}}',
        '{"schema": 1, "runsc": {"overlay2": "all:memory"}}',
        '{"schema": 1, "runsc": {"directfs": "yes"}}',
        '{"schema": 1, "docker": {"log_driver": "syslog"}}',
        '{"schema": 1, "boot": {"create_concurrency": 17}}',
        '{"schema": 1, "boot": {"create_concurrency": 0}}',
        '{"schema": 1, "pool": {"warm_size": ' + "9" * 5000 + "}}",
        '{"schema": 1, "pool": {"warm_size": NaN}}',
    ],
)
def test_bad_files_are_refused(text):
    with pytest.raises(TunablesError):
        parse_tunables(text)


@pytest.mark.parametrize(
    "section",
    [
        '"runsc": {"platform": "ptrace"}',
        '"runsc": {"network": "host"}',
        '"runsc": {"host_uds": "all"}',
        '"docker": {"security_opt": "seccomp=unconfined"}',
        '"docker": {"privileged": true}',
        '"docker": {"cap_add": "SYS_ADMIN"}',
        '"shape": {"vcpus": 1}',
        '"network": {"mode": "internet"}',
        '"image": {"digest": "sha256:0"}',
        '"egress": {"enabled": false}',
    ],
)
def test_pinned_settings_cannot_be_named(section):
    with pytest.raises(TunablesError):
        parse_tunables('{"schema": 1, ' + section + "}")


def test_size_cap_and_unreadable_files(tmp_path: Path):
    with pytest.raises(TunablesError):
        parse_tunables(b'{"schema": 1, "pad": "' + b"x" * MAX_BYTES + b'"}')
    with pytest.raises(TunablesError):
        load_tunables_file(str(tmp_path / "missing.json"))
    path = tmp_path / "t.json"
    path.write_text('{"schema": 1, "pool": {"warm_size": 3}}')
    assert load_tunables_file(str(path)).warm_size == 3


def test_published_schema_is_the_generated_one():
    path = ROOT / "docs" / "tee_box_tunables.schema.json"
    assert json.loads(path.read_text()) == json_schema()


def test_every_pinned_item_is_listed_in_the_doc():
    text = (ROOT / "docs" / "TEE_BOX_TUNABLES.md").read_text().replace("`", "").lower()
    for item in PINNED:
        assert item.split(" (")[0].lower() in text, item
    for field in FIELDS:
        assert field.key in text


# -- runsc flags and the runtime check ---------------------------------------------------


def test_default_runtime_config_is_what_the_box_expected_before():
    config = _executor().daemon_runtime_config()
    assert config == {
        "runtimes": {
            "runsc": {
                "path": "/usr/local/bin/runsc",
                "runtimeArgs": ["--platform=systrap", "--network=sandbox"],
            }
        }
    }


def test_tunable_flags_follow_the_pinned_ones():
    t = parse_tunables(
        '{"schema": 1, "runsc": {"directfs": false, "overlay2": "all:self", "net_channels": 3}}'
    )
    args = _executor(tunables=t).daemon_runtime_config()["runtimes"]["runsc"]["runtimeArgs"]
    assert args == [
        "--platform=systrap",
        "--network=sandbox",
        "--directfs=false",
        "--overlay2=all:self",
        "--num-network-channels=3",
    ]


def _runtimes_runner(args):
    def runner(argv, **kwargs):
        entry = {"runsc": {"path": "/usr/local/bin/runsc", "runtimeArgs": args}}
        return subprocess.CompletedProcess(argv, 0, json.dumps(entry).encode(), b"")

    return runner


def test_runtime_check_needs_the_daemon_to_match_the_tunables():
    tuned = parse_tunables('{"schema": 1, "runsc": {"directfs": false}}')
    base = ["--platform=systrap", "--network=sandbox"]
    assert _executor(_runtimes_runner(base)).runtime_check()[0]
    assert not _executor(_runtimes_runner([*base, "--directfs=false"])).runtime_check()[0]
    assert _executor(_runtimes_runner([*base, "--directfs=false"]), tunables=tuned).runtime_check()[
        0
    ]
    assert not _executor(_runtimes_runner(base), tunables=tuned).runtime_check()[0]
    # A different value of the same flag is a mismatch too.
    assert not _executor(
        _runtimes_runner([*base, "--directfs=true"]), tunables=tuned
    ).runtime_check()[0]


@pytest.mark.parametrize(
    "text",
    [
        '{"schema": 1}',
        '{"schema": 1, "docker": {"log_driver": "none"}, "runsc": {"net_channels": 4}}',
        '{"schema": 1, "pool": {"warm_size": 16}, "boot": {"create_concurrency": 16}}',
    ],
)
def test_pinned_security_arguments_survive_every_tunable_set(text):
    executor = _executor(tunables=parse_tunables(text), warm_shape=WARM_SHAPE)
    for argv in (
        executor.create_argv(_spec()),
        executor.warm_argv("cathwarm-x", IMAGE, WARM_SHAPE),
    ):
        assert ["--security-opt", "no-new-privileges"] == argv[argv.index("--security-opt") :][:2]
        assert argv[argv.index("--runtime=runsc") :][0] == "--runtime=runsc"
        assert argv.count("--pull") == 1 and argv[argv.index("--pull") + 1] == "never"
        assert argv[-4:] == ["--entrypoint", "sleep", IMAGE_ID, "infinity"]
        assert "--privileged" not in argv and "--cap-add" not in argv
    warm = executor.warm_argv("cathwarm-x", IMAGE, WARM_SHAPE)
    assert ["--network", "none"] == warm[warm.index("--network") :][:2]
    assert f"{BOX_LABEL}=default" in warm and f"{WARM_LABEL}=1" in warm
    assert "--env" not in warm


def test_log_driver_is_a_run_flag_only_when_it_is_not_the_default():
    plain = _executor().create_argv(_spec())
    assert "--log-driver" not in plain
    none = _executor(tunables=parse_tunables('{"schema": 1, "docker": {"log_driver": "none"}}'))
    argv = none.create_argv(_spec())
    assert argv[argv.index("--log-driver") :][:2] == ["--log-driver", "none"]


# -- image priming -----------------------------------------------------------------------


class _Docker:
    """Records docker calls; answers the ones a warm pool and an import make."""

    def __init__(self, fail=()) -> None:
        self.calls: list[list[str]] = []
        self.fail = set(fail)
        self.lock = threading.Lock()

    def __call__(self, argv, **kwargs):
        with self.lock:
            self.calls.append(list(argv))
        verb = argv[1]
        if verb == "image":
            return _inspect_answer(argv)
        code = 1 if verb in self.fail else 0
        return subprocess.CompletedProcess(argv, code, b"", b"")

    def verbs(self, verb):
        return [c for c in self.calls if c[1] == verb]


def test_priming_reads_the_image_once_after_import_and_not_by_default():
    docker = _Docker()
    primed = _executor(
        docker, tunables=parse_tunables('{"schema": 1, "image": {"prime": "page_cache"}}')
    )
    primed.import_image(EXEC_DIGEST, "registry.example/tasks/base")
    assert docker.verbs("save") == [["docker", "save", "--output", "/dev/null", IMAGE_ID]]
    plain = _Docker()
    _executor(plain).import_image(EXEC_DIGEST, "registry.example/tasks/base")
    assert plain.verbs("save") == []


def test_a_failed_prime_does_not_fail_the_import():
    docker = _Docker(fail={"save"})
    executor = _executor(
        docker, tunables=parse_tunables('{"schema": 1, "image": {"prime": "page_cache"}}')
    )
    assert executor.import_image(EXEC_DIGEST, "registry.example/tasks/base").image_id == IMAGE_ID


# -- warm pool (RunscExecutor, synchronous spawn) -----------------------------------------


def _pooled(docker=None, clock=None, **pool):
    docker = docker or _Docker()
    body = {"warm_size": 2, "refill_parallelism": 2, "idle_seconds": 60, **pool}
    tunables = parse_tunables(json.dumps({"schema": 1, "pool": body}))
    kwargs = {} if clock is None else {"clock": clock}
    executor = _executor(
        docker, tunables=tunables, warm_shape=WARM_SHAPE, spawn=lambda work: work(), **kwargs
    )
    executor.import_image(EXEC_DIGEST, "registry.example/tasks/base")
    return executor, docker


def test_pool_fills_only_while_enabled_up_to_warm_size_and_room():
    executor, docker = _pooled()
    executor.maintain_pool(enabled=False)
    assert executor.warm_count() == 0 and docker.verbs("run") == []
    executor.maintain_pool(enabled=True, room=1)
    assert executor.warm_count() == 1
    executor.maintain_pool(enabled=True, room=5)
    assert executor.warm_count() == 2
    executor.maintain_pool(enabled=True, room=5)
    assert executor.warm_count() == 2 and len(docker.verbs("run")) == 2
    assert executor.warm_usage() == Shape(4, 8192, 20480)


def test_refill_parallelism_bounds_each_round():
    executor, docker = _pooled(warm_size=4, refill_parallelism=1)
    executor.maintain_pool(enabled=True, room=9)
    assert executor.warm_count() == 1  # one start per round
    for _ in range(3):
        executor.maintain_pool(enabled=True, room=9)
    assert executor.warm_count() == 4


def test_reserve_claims_one_and_renames_it():
    executor, docker = _pooled()
    executor.maintain_pool(enabled=True, room=5)
    spec = replace(_spec(), env={})
    warm = executor.reserve_warm(spec)
    assert warm.startswith("cathwarm-") and executor.warm_count() == 1
    info = executor.create(replace(spec, warm=warm))
    rename = docker.verbs("rename")
    assert rename == [["docker", "rename", warm, "cathsbx-" + spec.sandbox_id]]
    assert info.spec.sandbox_id == spec.sandbox_id
    assert [c for c in docker.verbs("run") if "cathsbx-" + spec.sandbox_id in c] == []
    # The executor does not refill on its own: the service does, within the room it knows.
    assert executor.warm_count() == 1
    executor.maintain_pool(enabled=True, room=1)
    assert executor.warm_count() == 2


@pytest.mark.parametrize(
    "change",
    [
        {"env": {"A": "1"}},
        {"network": "internet"},
        {"shape": Shape(1, 1024, 2048)},
    ],
)
def test_only_an_identical_start_may_take_a_warm_container(change):
    executor, _ = _pooled()
    executor.maintain_pool(enabled=True, room=5)
    assert executor.reserve_warm(replace(_spec(), **{"env": {}, **change})) == ""
    assert executor.warm_count() == 2


def test_a_warm_container_is_never_given_to_a_different_image():
    executor, _ = _pooled()
    executor.maintain_pool(enabled=True, room=5)
    other = replace(IMAGE, digest="sha256:" + "ee" * 32)
    assert executor.reserve_warm(replace(_spec(), env={}, image=other)) == ""


def test_a_failed_rename_falls_back_to_a_cold_create_and_removes_the_warm_one():
    docker = _Docker(fail={"rename"})
    executor, docker = _pooled(docker)
    executor.maintain_pool(enabled=True, room=5)
    spec = replace(_spec(), env={})
    warm = executor.reserve_warm(spec)
    executor.create(replace(spec, warm=warm))
    assert any(
        c[:2] == ["docker", "run"] and "cathsbx-" + spec.sandbox_id in c for c in docker.calls
    )
    assert ["docker", "rm", "--force", warm] in docker.calls


def test_release_puts_a_reservation_back():
    executor, _ = _pooled()
    executor.maintain_pool(enabled=True, room=5)
    spec = replace(_spec(), env={})
    warm = executor.reserve_warm(spec)
    executor.release_warm(warm, spec.image.digest)
    assert executor.warm_count() == 2 and executor.reserve_warm(spec) == warm


def test_idle_warm_containers_expire_and_are_replaced():
    clock = _Clock()
    executor, docker = _pooled(clock=clock)
    executor.maintain_pool(enabled=True, room=5)
    first = {c[c.index("--name") + 1] for c in docker.verbs("run")}
    clock.value += 61
    executor.maintain_pool(enabled=True, room=5)
    removed = {c[-1] for c in docker.verbs("rm")}
    assert first <= removed
    now = {c[c.index("--name") + 1] for c in docker.verbs("run")} - first
    assert len(now) == 2 and executor.warm_count() == 2


def test_discard_removes_everything_and_stops_refills():
    executor, docker = _pooled()
    executor.maintain_pool(enabled=True, room=5)
    executor.discard_warm()
    assert executor.warm_count() == 0 and len(docker.verbs("rm")) >= 2
    executor.maintain_pool(enabled=False)
    assert executor.reserve_warm(replace(_spec(), env={})) == ""
    runs = len(docker.verbs("run"))
    executor._refill(room=5)
    assert len(docker.verbs("run")) == runs


def test_evict_frees_the_oldest():
    executor, docker = _pooled()
    executor.maintain_pool(enabled=True, room=5)
    assert executor.evict_warm() and executor.warm_count() == 1
    assert executor.evict_warm() and not executor.evict_warm()


def test_sweep_leaves_warm_containers_alone():
    executor, docker = _pooled()
    executor.maintain_pool(enabled=True, room=5)
    names = [c[c.index("--name") + 1] for c in docker.verbs("run")]

    def runner(argv, **kwargs):
        docker.calls.append(list(argv))
        if argv[1] == "ps":
            return subprocess.CompletedProcess(argv, 0, "\n".join([*names, "stray"]).encode(), b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    executor._runner = runner
    executor.sweep()
    removed = {c[-1] for c in docker.calls if c[1] == "rm"}
    assert "stray" in removed and not removed & set(names)


def test_a_warm_start_that_finishes_after_discard_is_removed():
    started = threading.Event()
    release = threading.Event()
    docker = _Docker()
    original = docker.__call__

    def slow(argv, **kwargs):
        if argv[1] == "run":
            started.set()
            release.wait(5)
        return original(argv, **kwargs)

    tunables = parse_tunables('{"schema": 1, "pool": {"warm_size": 1}}')
    executor = _executor(
        slow,
        tunables=tunables,
        warm_shape=WARM_SHAPE,
        spawn=lambda w: threading.Thread(target=w).start(),
    )
    executor.import_image(EXEC_DIGEST, "registry.example/tasks/base")
    executor.maintain_pool(enabled=True, room=1)
    assert started.wait(5)
    executor.discard_warm()
    release.set()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and executor.warm_count():
        time.sleep(0.01)
    assert executor.warm_count() == 0
    assert executor.reserve_warm(replace(_spec(), env={})) == ""
    assert any(c[1] == "rm" for c in docker.calls)


def test_defaults_never_create_a_pool():
    docker = _Docker()
    executor = _executor(docker, warm_shape=WARM_SHAPE)
    executor.import_image(EXEC_DIGEST, "registry.example/tasks/base")
    executor.maintain_pool(enabled=True, room=9)
    assert executor.warm_count() == 0 and docker.verbs("run") == []


# -- service: bounded concurrency, reservations, hand-over --------------------------------


class _Gated(FakeExecutor):
    """create() waits on a gate and records how many run at once."""

    def __init__(self) -> None:
        super().__init__()
        self.gate = threading.Event()
        self.entered = threading.Semaphore(0)
        self.running = 0
        self.peak = 0
        self.fail_next = False
        self._m = threading.Lock()

    def create(self, spec):
        with self._m:
            self.running += 1
            self.peak = max(self.peak, self.running)
        self.entered.release()
        try:
            self.gate.wait(10)
            if self.fail_next:
                self.fail_next = False
                from cathedral.tee_box.executor import ExecutorError

                raise ExecutorError("sandbox start failed")
            return super().create(spec)
        finally:
            with self._m:
                self.running -= 1


def _service(tmp_path: Path, executor, concurrency=1, clock=None, **kw):
    kwargs = {} if clock is None else {"clock": clock}
    boot_ids = _BootIds()
    api = TeeBoxSandboxApi(
        executor=executor,
        authorizer=_authorizer(tmp_path, _binding()),
        egress=build_egress_policy([BOX_IP]),
        capacity=kw.get("capacity", CAPACITY),
        default_shape=DEFAULT_SHAPE,
        boot=_boot(boot_ids, None, clock),
        create_concurrency=concurrency,
        **kwargs,
    )
    _push_revocations(api)
    assert _handle(api, "POST", "/v1/lease", body={"ttl_seconds": 600})[0] == 200
    executor.import_image(DIGEST, "registry.example/tasks/base")
    return api


def _create_body(**extra):
    return {"image_id": DIGEST, "network": "deny_all", "lifetime_seconds": 3600, **extra}


def _fire(api, n, results):
    threads = []
    for i in range(n):

        def work(i=i):
            results[i] = _handle(api, "POST", "/v1/sandboxes", body=_create_body())

        thread = threading.Thread(target=work)
        thread.start()
        threads.append(thread)
    return threads


def test_concurrency_one_runs_creates_one_at_a_time(tmp_path: Path):
    fake = _Gated()
    api = _service(tmp_path, fake, concurrency=1)
    results: dict = {}
    threads = _fire(api, 3, results)
    assert fake.entered.acquire(timeout=5)
    time.sleep(0.2)
    assert fake.running == 1
    fake.gate.set()
    for t in threads:
        t.join(10)
    assert fake.peak == 1 and sorted(s for s, _ in results.values()) == [201, 201, 201]


def test_concurrency_n_runs_up_to_n_at_once_and_no_more(tmp_path: Path):
    fake = _Gated()
    api = _service(tmp_path, fake, concurrency=3, capacity=Shape(16, 65536, 409600))
    results: dict = {}
    threads = _fire(api, 5, results)
    for _ in range(3):
        assert fake.entered.acquire(timeout=5)
    time.sleep(0.2)
    assert fake.running == 3
    fake.gate.set()
    for t in threads:
        t.join(10)
    assert fake.peak == 3 and all(s == 201 for s, _ in results.values())
    assert len(fake.list()) == 5


def test_in_flight_creates_cannot_overcommit_capacity(tmp_path: Path):
    fake = _Gated()
    capacity = Shape(6, 12288, 30720)  # room for exactly three default sandboxes
    api = _service(tmp_path, fake, concurrency=8, capacity=capacity)
    results: dict = {}
    threads = _fire(api, 8, results)
    deadline = time.monotonic() + 5
    while len(results) < 5 and time.monotonic() < deadline:
        time.sleep(0.01)
    refused = [r for r in results.values() if r[0] == 409]
    assert len(refused) == 5 and all(r[1]["reason"] == "box_capacity_full" for r in refused)
    fake.gate.set()
    for t in threads:
        t.join(10)
    assert sorted(s for s, _ in results.values()).count(201) == 3 and len(fake.list()) == 3


def test_sandbox_count_cap_holds_with_creates_in_flight(tmp_path: Path):
    fake = _Gated()
    big = Shape(4096, 64 * 1024 * 1024, 64 * 1024 * 1024)
    api = _service(tmp_path, fake, concurrency=16, capacity=big)
    results: dict = {}
    total = MAX_SANDBOXES + 4
    threads = _fire(api, total, results)
    deadline = time.monotonic() + 20
    while len(results) < 4 and time.monotonic() < deadline:
        time.sleep(0.01)
    fake.gate.set()
    for t in threads:
        t.join(30)
    statuses = [s for s, _ in results.values()]
    assert statuses.count(201) == MAX_SANDBOXES and statuses.count(409) == 4
    assert len(fake.list()) == MAX_SANDBOXES


def test_a_failed_create_gives_its_reservation_back(tmp_path: Path):
    fake = _Gated()
    fake.gate.set()
    capacity = Shape(2, 4096, 10240)  # one sandbox
    api = _service(tmp_path, fake, capacity=capacity)
    fake.fail_next = True
    assert _handle(api, "POST", "/v1/sandboxes", body=_create_body())[0] >= 400
    assert _handle(api, "POST", "/v1/sandboxes", body=_create_body())[0] == 201
    assert _handle(api, "POST", "/v1/sandboxes", body=_create_body())[1]["reason"] == (
        "box_capacity_full"
    )


def test_a_drain_waits_for_a_create_in_flight_and_then_deletes_it(tmp_path: Path):
    clock = _Clock()
    fake = _Gated()
    api = _service(tmp_path, fake, clock=clock)
    results: dict = {}
    (creator,) = _fire(api, 1, results)
    assert fake.entered.acquire(timeout=5)
    clock.value += 601  # the lease ends while the create is still running
    drained: list[bool] = []
    drainer = threading.Thread(target=lambda: drained.append(api._drain_owner(CALLER)))
    drainer.start()
    time.sleep(0.3)
    assert drainer.is_alive() and drained == []  # waiting, not racing
    fake.gate.set()
    creator.join(10)
    drainer.join(10)
    assert drained == [True]
    assert fake.list() == ()  # the sandbox that landed during the drain was deleted


def test_a_new_create_after_the_lease_ended_is_refused(tmp_path: Path):
    clock = _Clock()
    fake = _Gated()
    fake.gate.set()
    api = _service(tmp_path, fake, clock=clock)
    clock.value += 601
    status, body = _handle(api, "POST", "/v1/sandboxes", body=_create_body())
    assert status == 409 and fake.list() == ()


@pytest.mark.parametrize("value", [0, 17, True, "2"])
def test_create_concurrency_is_validated(tmp_path: Path, value):
    with pytest.raises(ValueError):
        _service(tmp_path, FakeExecutor(), concurrency=value)


# -- service with a warm pool ---------------------------------------------------------------


class _PoolFake(FakeExecutor):
    """FakeExecutor with the warm-pool surface the service talks to."""

    def __init__(self) -> None:
        super().__init__()
        self.warm = [f"w{i}" for i in range(3)]
        self.reserved: list[str] = []
        self.released: list[str] = []
        self.evicted = 0
        self.maintained: list[tuple[bool, int]] = []
        self.discarded = 0

    def warm_count(self):
        return len(self.warm)

    def warm_usage(self):
        return Shape(*(len(self.warm) * v for v in (2, 4096, 10240)))

    def reserve_warm(self, spec):
        if (
            self.warm
            and spec.shape == DEFAULT_SHAPE
            and not spec.env
            and spec.network == "deny_all"
        ):
            name = self.warm.pop(0)
            self.reserved.append(name)
            return name
        return ""

    def release_warm(self, name, digest):
        self.released.append(name)
        self.warm.insert(0, name)

    def evict_warm(self):
        if not self.warm:
            return False
        self.warm.pop(0)
        self.evicted += 1
        return True

    def maintain_pool(self, *, enabled, room=0):
        self.maintained.append((enabled, room))

    def discard_warm(self):
        self.discarded += 1
        self.warm.clear()


def test_warm_containers_count_against_capacity_and_make_way(tmp_path: Path):
    fake = _PoolFake()
    capacity = Shape(6, 12288, 30720)  # three default sandboxes, all taken by warm ones
    api = _service(tmp_path, fake, capacity=capacity)
    fake.warm = ["w0", "w1", "w2"]  # the box-start drain emptied the pool; fill it now
    status, view = _handle(api, "POST", "/v1/sandboxes", body=_create_body())
    assert status == 201 and fake.reserved == ["w0"]
    # With env the warm ones cannot serve it; each such create evicts one for room.
    for evicted in (1, 2):
        status, _ = _handle(api, "POST", "/v1/sandboxes", body=_create_body(env={"A": "1"}))
        assert status == 201 and fake.evicted == evicted
    status, body = _handle(api, "POST", "/v1/sandboxes", body=_create_body(env={"A": "1"}))
    assert status == 409 and body["reason"] == "box_capacity_full"


def test_a_refused_create_returns_its_warm_container(tmp_path: Path):
    fake = _PoolFake()
    # One shape of capacity, all of it the warm container; a 4-vcpu create cannot fit even
    # after evicting it, so the claim path is not used, and nothing leaks.
    api = _service(tmp_path, fake, capacity=Shape(2, 4096, 10240))
    fake.warm = ["w0"]
    big = _create_body(shape={"vcpus": 4, "memory_mib": 8192, "disk_mib": 20480})
    status, body = _handle(api, "POST", "/v1/sandboxes", body=big)
    assert (status, body["reason"]) == (409, "box_capacity_full")
    assert fake.reserved == [] and fake.warm_count() == 0 and fake.evicted == 1


def test_the_pool_is_discarded_at_hand_over_and_kept_only_while_leased(tmp_path: Path):
    clock = _Clock()
    fake = _PoolFake()
    api = _service(tmp_path, fake, clock=clock)
    api.reap()
    assert fake.maintained[-1][0] is True
    clock.value += 601
    api.reap()
    assert fake.maintained[-1][0] is False
    assert fake.discarded >= 1 and fake.warm == []


def test_room_given_to_the_pool_respects_capacity_and_reservations(tmp_path: Path):
    fake = _PoolFake()
    fake.warm = []
    api = _service(tmp_path, fake, capacity=Shape(6, 12288, 30720))
    api.reap()
    assert fake.maintained[-1] == (True, 3)
    _handle(api, "POST", "/v1/sandboxes", body=_create_body())
    api.reap()
    assert fake.maintained[-1] == (True, 2)


def test_other_customer_never_sees_the_first_ones_pool(tmp_path: Path):
    clock = _Clock()
    fake = _PoolFake()
    api = _service(tmp_path, fake, clock=clock)
    clock.value += 601
    api.lease.retry_drain()
    assert fake.warm == []
    status, _ = _handle(api, "POST", "/v1/lease", OTHER, {"ttl_seconds": 60})
    assert status in (200, 409)


class _GatedRename(_Docker):
    """Holds ``docker rename`` (a warm claim) until the gate opens."""

    def __init__(self) -> None:
        super().__init__()
        self.gate = threading.Event()
        self.renaming = threading.Event()

    def __call__(self, argv, **kwargs):
        if argv[1] == "rename":
            self.renaming.set()
            self.gate.wait(10)
        return super().__call__(argv, **kwargs)


def test_a_refill_after_a_warm_claim_never_overcommits_in_flight_creates(tmp_path: Path):
    # Capacity for two default sandboxes, a pool of one. Create A claims the warm container;
    # while its rename runs, create B is admitted cold into the second slot. When A finishes,
    # the pool must not start a replacement: that would be a third container on room for two.
    docker = _GatedRename()
    tunables = parse_tunables(
        json.dumps({"schema": 1, "pool": {"warm_size": 1}, "boot": {"create_concurrency": 2}})
    )
    executor = _executor(docker, tunables=tunables, warm_shape=WARM_SHAPE, spawn=lambda w: w())
    api = _service(tmp_path, executor, concurrency=2, capacity=Shape(4, 8192, 20480))
    api.reap()
    assert executor.warm_count() == 1
    results: dict = {}

    def claim() -> None:
        results["a"] = _handle(api, "POST", "/v1/sandboxes", body=_create_body())

    first = threading.Thread(target=claim)
    first.start()
    assert docker.renaming.wait(5)
    results["b"] = _handle(api, "POST", "/v1/sandboxes", body=_create_body(env={"A": "1"}))
    docker.gate.set()
    first.join(10)
    assert results["a"][0] == 201 and results["b"][0] == 201
    assert len(executor.list()) + executor.warm_count() <= 2
    # Once a slot frees, the pool refills into it again.
    executor.delete(results["b"][1]["id"])
    api.reap()
    assert executor.warm_count() == 1
