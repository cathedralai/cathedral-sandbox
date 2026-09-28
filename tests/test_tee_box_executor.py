"""T6a egress policy rendering and the runsc backend's argv, with subprocess mocked."""

from __future__ import annotations

import ipaddress
import subprocess
import sys
import threading
import time

import pytest

from cathedral.common import is_globally_routable
from cathedral.tee_box.egress import (
    DENIED_IPV4,
    DENIED_IPV6,
    METADATA_ADDRESSES,
    EgressPolicyError,
    build_egress_policy,
)
from cathedral.tee_box import executor as executor_module
from cathedral.tee_box.executor import (
    MAX_JOBS_PER_BOX,
    MAX_JOBS_PER_SANDBOX,
    MAX_OUTPUT_BYTES,
    MAX_RETAINED_OUTPUT_BYTES,
    PENDING_CLEANUP_GRACE_SECONDS,
    ExecRequest,
    ExecResult,
    ExecutorError,
    ExecutorRefused,
    ImageInfo,
    NotFound,
    RunscExecutor,
    SandboxSpec,
    Shape,
    TooLarge,
    _check_argv,
)

BOX_IPS = ("34.120.1.2", "2600:1900:4000::7/128")
DIGEST = "sha256:" + "ab" * 32
IMAGE = ImageInfo(DIGEST, "registry.example/tasks/base")


def _policy(**kwargs):
    return build_egress_policy(BOX_IPS, **kwargs)


def _spec(network: str = "deny_all", sid: str = "sbx-" + "1" * 24) -> SandboxSpec:
    return SandboxSpec(
        sandbox_id=sid,
        owner="caller",
        image=IMAGE,
        shape=Shape(2, 4096, 10240),
        network=network,
        expires_at=0.0,
        env={"B": "2", "A": "1"},
    )


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "168.63.129.16",
        "192.0.0.192",
        "fd00:ec2::254",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.251",
        "255.255.255.255",
        "240.0.0.1",
        "198.18.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::ffff:10.0.0.1",
        "64:ff9b::a00:1",
        "2002:a00:1::1",
        "34.120.1.2",
        "2600:1900:4000::7",
    ],
)
def test_denied_destinations(address: str):
    assert _policy().denies(address)


@pytest.mark.parametrize("address", ["1.1.1.1", "8.8.8.8", "34.120.1.3", "2606:4700:4700::1111"])
def test_the_public_internet_stays_reachable(address: str):
    assert not _policy().denies(address)


def test_deny_list_names_metadata_and_the_box_itself():
    policy = _policy()
    rendered = {str(net) for net in policy.denied}
    for text in (*DENIED_IPV4, *DENIED_IPV6, *METADATA_ADDRESSES):
        assert str(ipaddress.ip_network(text)) in rendered
    assert {"169.254.169.254/32", "34.120.1.2/32", "2600:1900:4000::7/128"} <= rendered
    assert policy.box_addresses == (
        ipaddress.ip_network("34.120.1.2"),
        ipaddress.ip_network("2600:1900:4000::7"),
    )
    # Every fixed range is non-global unicast except three blocks Python's
    # ipaddress calls global, denied on purpose: Azure WireServer (answered by
    # the host alone), the retired 6to4 relay anycast block, and deprecated
    # IPv6 site-local.
    for text in (*DENIED_IPV4, *DENIED_IPV6, *METADATA_ADDRESSES):
        address = ipaddress.ip_network(text).network_address
        public = is_globally_routable(address) and not address.is_multicast
        assert public == (text in {"168.63.129.16/32", "192.88.99.0/24", "fec0::/10"}), text


def test_nft_rendering_blocks_the_ranges_and_the_box():
    rendered = _policy(bridge="sbx0").render_nft()
    assert "table inet cathedral_tee_box_egress {" in rendered
    assert '    iifname "sbx0" ip daddr @deny4 counter drop\n' in rendered
    assert '    iifname "sbx0" ip6 daddr @deny6 counter drop\n' in rendered
    # Traffic from the bridge to the box's own stack never reaches a service.
    assert "type filter hook input priority -1; policy accept;\n" in rendered
    assert '    iifname "sbx0" counter drop\n' in rendered
    for text in (
        "169.254.0.0/16",
        "100.64.0.0/10",
        "10.0.0.0/8",
        "168.63.129.16/32",
        "34.120.1.2/32",
        "fc00::/7",
        "2600:1900:4000::7/128",
        "fe80::/9",
    ):  # link-local and site-local, collapsed
        assert text in rendered
    # Interval sets refuse overlaps, so contained /32s are collapsed away.
    assert "169.254.169.254" not in rendered


def test_bandwidth_cap_renders_tc_argv():
    commands = _policy(bandwidth_mbit=250).bandwidth_commands("veth1a2b")
    assert commands == (
        (
            "tc",
            "qdisc",
            "replace",
            "dev",
            "veth1a2b",
            "root",
            "tbf",
            "rate",
            "250mbit",
            "burst",
            "312500b",
            "latency",
            "50ms",
        ),
        ("tc", "qdisc", "replace", "dev", "veth1a2b", "handle", "ffff:", "ingress"),
        (
            "tc",
            "filter",
            "replace",
            "dev",
            "veth1a2b",
            "parent",
            "ffff:",
            "matchall",
            "action",
            "police",
            "rate",
            "250mbit",
            "burst",
            "312500b",
            "drop",
        ),
    )
    assert _policy(bandwidth_mbit=1).bandwidth_commands("v")[0][10] == "32768b"
    assert _policy().describe()["bandwidth_mbit"] == 100


@pytest.mark.parametrize(
    "kwargs",
    [
        {"bandwidth_mbit": 0},
        {"bandwidth_mbit": 100_001},
        {"bandwidth_mbit": True},
        {"bridge": "br0; reboot"},
        {"bridge": "x" * 16},
    ],
)
def test_invalid_policy_inputs_are_refused(kwargs):
    with pytest.raises(EgressPolicyError):
        _policy(**kwargs)


@pytest.mark.parametrize("addresses", [[], "34.120.1.2", ["34.120.1.0/23"], ["not-an-ip"]])
def test_box_addresses_are_required_and_exact(addresses):
    with pytest.raises(EgressPolicyError):
        build_egress_policy(addresses)


def test_tc_refuses_a_hostile_interface():
    with pytest.raises(EgressPolicyError):
        _policy().bandwidth_commands("eth0 root")


class _Runner:
    def __init__(self, returncode: int = 0) -> None:
        self.calls: list[tuple[list[str], dict]] = []
        self.returncode = returncode

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, self.returncode, b"", b"")


def _executor(runner=None, **kwargs) -> RunscExecutor:
    return RunscExecutor(_policy(), docker="docker", runner=runner or _Runner(), **kwargs)


def test_create_argv_uses_runsc_limits_and_the_policy_network():
    executor = _executor()
    assert executor.create_argv(_spec()) == [
        "docker",
        "run",
        "--detach",
        "--runtime=runsc",
        "--name",
        "cathsbx-sbx-" + "1" * 24,
        "--label",
        "org.cathedral.tee-box.box=default",
        "--label",
        "org.cathedral.tee-box.sandbox=sbx-" + "1" * 24,
        "--cpus",
        "2",
        "--memory",
        "4096m",
        "--memory-swap",
        "4096m",
        "--pids-limit",
        "4096",
        "--security-opt",
        "no-new-privileges",
        "--network",
        "none",
        "--env",
        "A=1",
        "--env",
        "B=2",
        "--entrypoint",
        "sleep",
        f"registry.example/tasks/base@{DIGEST}",
        "infinity",
    ]
    internet = executor.create_argv(_spec("internet"))
    at = internet.index("--network")
    assert internet[at : at + 6] == [
        "--network",
        "cathsbx0",
        "--dns",
        "1.1.1.1",
        "--dns",
        "8.8.8.8",
    ]
    assert executor.daemon_runtime_config()["runtimes"]["runsc"]["runtimeArgs"] == [
        "--platform=systrap",
        "--network=sandbox",
    ]


def test_import_and_create_call_docker_without_a_shell():
    runner = _Runner()
    executor = _executor(runner)
    executor.import_image(DIGEST, IMAGE.reference)
    executor.create(_spec())
    (pull, pull_kwargs), (run, run_kwargs) = runner.calls
    assert pull == ["docker", "pull", "--quiet", f"registry.example/tasks/base@{DIGEST}"]
    assert run[:2] == ["docker", "run"]
    assert pull_kwargs["shell"] is False and run_kwargs["shell"] is False
    assert executor.get(_spec().sandbox_id) is not None
    executor.delete(_spec().sandbox_id)
    assert runner.calls[-1][0] == ["docker", "rm", "--force", "cathsbx-sbx-" + "1" * 24]
    assert executor.get(_spec().sandbox_id) is None


def test_failed_docker_calls_raise():
    executor = _executor(_Runner(returncode=1))
    with pytest.raises(ExecutorError):
        executor.import_image(DIGEST, IMAGE.reference)
    with pytest.raises(NotFound):
        executor.create(_spec())


def test_internet_needs_live_egress_enforcement():
    runner = _Runner()
    executor = _executor(runner)
    executor.import_image(DIGEST, IMAGE.reference)
    assert executor.network_modes == ("deny_all",)
    with pytest.raises(ExecutorRefused):
        executor.create(_spec("internet"))
    assert len(runner.calls) == 1  # only the pull

    applied = []
    enforced = _executor(runner, egress_enforcer=lambda name, policy: applied.append(name))
    enforced.import_image(DIGEST, IMAGE.reference)
    enforced.create(_spec("internet"))
    assert applied == ["cathsbx-sbx-" + "1" * 24]
    assert enforced.network_modes == ("internet", "deny_all")

    def broken(_name, _policy):
        raise RuntimeError("tc failed")

    failing = _executor(runner, egress_enforcer=broken)
    failing.import_image(DIGEST, IMAGE.reference)
    with pytest.raises(ExecutorError, match="egress"):
        failing.create(_spec("internet"))
    assert runner.calls[-1][0][:3] == ["docker", "rm", "--force"]
    assert failing.get(_spec().sandbox_id) is None


def test_exec_and_file_argv_pass_caller_values_as_arguments(monkeypatch):
    executor = _executor()
    executor.import_image(DIGEST, IMAGE.reference)
    executor.create(_spec())
    sid = _spec().sandbox_id
    request = ExecRequest(
        ("/bin/sh", "-c", "echo $HOME"),
        timeout_seconds=30,
        env={"K": "v"},
        user="1000:1000",
        cwd="/work",
    )
    assert executor.exec_argv(sid, request) == [
        "docker",
        "exec",
        "--env",
        "K=v",
        "--user",
        "1000:1000",
        "--workdir",
        "/work",
        "cathsbx-" + sid,
        "/bin/sh",
        "-c",
        "echo $HOME",
    ]
    seen = []

    def fake_run(argv, *, timeout, stdin=None, cap=0):
        seen.append((argv, stdin))
        return ExecResult(0, b"regular file|5|644\n")

    monkeypatch.setattr(executor, "_run", fake_run)
    hostile = '/tmp/"; reboot; echo "'
    executor.write_file(sid, hostile, b"hello", 0o644)
    argv, stdin = seen[-1]
    assert argv[:6] == ["docker", "exec", "--interactive", "--user", "0", "cathsbx-" + sid]
    assert argv[6:8] == ["/bin/sh", "-c"]
    assert hostile not in argv[8] and argv[9:] == ["cathedral-sandbox", hostile, "644"]
    assert stdin == b"hello"
    assert executor.stat(sid, "/x") is not None
    executor.get_tar(sid, "/data", ["*.pyc"])
    assert seen[-1][0][-3:] == ["cathedral-sandbox", "/data", "--exclude=*.pyc"]


def test_transfers_map_exit_codes(monkeypatch):
    executor = _executor()
    executor.import_image(DIGEST, IMAGE.reference)
    executor.create(_spec())
    sid = _spec().sandbox_id
    for result, error in (
        (ExecResult(3), NotFound),
        (ExecResult(0, b"x", stdout_truncated=True), TooLarge),
        (ExecResult(1), ExecutorError),
    ):
        monkeypatch.setattr(executor, "_run", lambda *a, result=result, **k: result)
        with pytest.raises(error):
            executor.read_file(sid, "/f")
    monkeypatch.setattr(executor, "_run", lambda *a, **k: ExecResult(3))
    assert executor.stat(sid, "/missing") is None


def test_argv_is_bounded():
    with pytest.raises(ExecutorError):
        _check_argv(["docker", "a\x00b"])
    with pytest.raises(ExecutorError):
        _check_argv(["x" * (64 * 1024 + 1)])
    with pytest.raises(ExecutorError):
        _check_argv([])


def test_captured_output_is_capped_and_timeouts_kill():
    executor = _executor()
    result = executor._run(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 300000)"], timeout=30, cap=1000
    )
    assert (result.exit_code, len(result.stdout), result.stdout_truncated) == (0, 1000, True)
    slow = executor._run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
    assert slow.timed_out and slow.exit_code is None


class _Docker:
    """A scripted docker CLI: containers appear on run and vanish on rm."""

    def __init__(self) -> None:
        self.containers: set[str] = set()
        self.calls: list[list[str]] = []
        self.run_mode = "ok"  # ok, timeout (the daemon starts it anyway), fail
        self.rm_failures = 0  # how many rm calls fail before one succeeds
        self.ps_fails = False

    def __call__(self, argv, **kwargs):
        assert kwargs["shell"] is False
        self.calls.append(argv)
        verb = argv[1]
        if verb == "run":
            name = argv[argv.index("--name") + 1]
            if self.run_mode == "timeout":
                self.containers.add(name)
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            if self.run_mode == "fail":
                return subprocess.CompletedProcess(argv, 125, b"", b"error")
            self.containers.add(name)
        elif verb == "rm":
            if self.rm_failures:
                self.rm_failures -= 1
                return subprocess.CompletedProcess(argv, 1, b"", b"daemon busy")
            self.containers.discard(argv[-1])
        elif verb == "container":
            if argv[-1] not in self.containers:
                return subprocess.CompletedProcess(argv, 1, b"", b"Error: No such container")
        elif verb == "ps":
            assert argv[argv.index("--filter") + 1] == "label=org.cathedral.tee-box.box=default"
            if self.ps_fails:
                return subprocess.CompletedProcess(argv, 1, b"", b"daemon down")
            listing = "".join(name + "\n" for name in sorted(self.containers))
            return subprocess.CompletedProcess(argv, 0, listing.encode(), b"")
        return subprocess.CompletedProcess(argv, 0, b"", b"")


class _Clock:
    def __init__(self) -> None:
        self.value = 1_900_000_000.0

    def __call__(self) -> float:
        return self.value


def _docker_executor():
    docker, clock = _Docker(), _Clock()
    executor = _executor(docker, clock=clock)
    executor.import_image(DIGEST, IMAGE.reference)
    return executor, docker, clock


NAME = "cathsbx-sbx-" + "1" * 24


def test_a_timed_out_create_is_removed_by_name_and_stays_pending():
    executor, docker, clock = _docker_executor()
    docker.run_mode = "timeout"
    with pytest.raises(ExecutorError):
        executor.create(_spec())
    assert executor.get(_spec().sandbox_id) is None
    assert NAME not in docker.containers
    assert ["docker", "rm", "--force", NAME] in docker.calls
    # The daemon may still start it after the CLI was killed: the name stays
    # pending, and the sweep removes it when it appears.
    assert executor.sweep() == 1
    docker.containers.add(NAME)
    assert executor.sweep() == 1 and NAME not in docker.containers
    clock.value += PENDING_CLEANUP_GRACE_SECONDS
    assert executor.sweep() == 0


def test_a_failed_create_whose_removal_fails_is_swept_later():
    executor, docker, _clock = _docker_executor()
    docker.run_mode = "fail"
    docker.containers.add(NAME)  # a half-created container
    docker.rm_failures = 2
    with pytest.raises(ExecutorError):
        executor.create(_spec())
    assert NAME in docker.containers
    docker.rm_failures = 2
    assert executor.sweep() == 1
    assert executor.sweep() == 0 and NAME not in docker.containers


def test_the_sweep_removes_only_untracked_box_containers():
    executor, docker, _clock = _docker_executor()
    executor.create(_spec())
    other = _spec(sid="sbx-" + "2" * 24)
    docker.containers |= {"cathsbx-sbx-left-by-a-restart", "cathsbx-" + other.sandbox_id}
    executor._creating.add(other.sandbox_id)  # a create in flight is not an orphan
    assert executor.sweep() == 0
    assert docker.containers == {NAME, "cathsbx-" + other.sandbox_id}
    docker.ps_fails = True
    with pytest.raises(ExecutorError):
        executor.sweep()


def test_delete_force_kills_and_confirms_the_container_is_gone():
    executor, docker, _clock = _docker_executor()
    executor.create(_spec())
    docker.rm_failures = 1
    assert executor.delete(_spec().sandbox_id)
    assert docker.calls[-2:] == [
        ["docker", "kill", "--signal", "KILL", NAME],
        ["docker", "rm", "--force", NAME],
    ]
    executor.create(_spec())
    docker.rm_failures = 2
    with pytest.raises(ExecutorError):
        executor.delete(_spec().sandbox_id)
    assert executor.get(_spec().sandbox_id) is not None
    docker.rm_failures = 2
    docker.containers.discard(NAME)  # rm failed, but the daemon says it is gone
    assert executor.delete(_spec().sandbox_id)


class _FakeProcess:
    def __init__(self, done: threading.Event) -> None:
        self._done = done

    def poll(self):
        return 0 if self._done.is_set() else None


_SHARED_OUTPUT = b"x" * MAX_OUTPUT_BYTES


class _FakeJob:
    """A background exec: finished at once, or running until killed."""

    finished = True
    start_delay = 0.0

    def __init__(self, argv, cap, stdin) -> None:
        time.sleep(self.start_delay)
        self.done = threading.Event()
        if self.finished:
            self.done.set()
        self.process = _FakeProcess(self.done)
        self.stdout = _SHARED_OUTPUT
        self.stderr = _SHARED_OUTPUT
        self.killed = self.timed_out = False

    def wait(self, timeout):
        return self.done.wait(timeout)

    def kill(self):
        self.done.set()

    def result(self):
        return ExecResult(0, b"done")


def _job_executor(job_class):
    executor, docker, clock = _docker_executor()
    executor._job_factory = job_class
    sids = []
    for digit in "123":
        spec = _spec(sid="sbx-" + digit * 24)
        executor.create(spec)
        sids.append(spec.sandbox_id)
    return executor, clock, sids


REQUEST = ExecRequest(("true",), timeout_seconds=60)


def test_a_loop_of_short_execs_keeps_retained_output_bounded():
    executor, _clock, sids = _job_executor(_FakeJob)
    for index in range(300):
        executor.start_exec(sids[index % 3], REQUEST)
        assert len(executor._jobs) <= MAX_JOBS_PER_BOX
        assert executor.retained_output_bytes() <= MAX_RETAINED_OUTPUT_BYTES
    for sid in sids:
        assert sum(1 for key in executor._jobs if key[0] == sid) <= MAX_JOBS_PER_SANDBOX
    assert MAX_RETAINED_OUTPUT_BYTES == 64 * 1024 * 1024


def test_finished_execs_are_evicted_after_their_output_is_read():
    executor, clock, sids = _job_executor(_FakeJob)
    read = executor.start_exec(sids[0], REQUEST)
    unread = executor.start_exec(sids[0], REQUEST)
    assert executor.poll_exec(sids[0], read, 0).state == "exited"
    # A caller that lost the answer may ask again inside the retention.
    assert executor.poll_exec(sids[0], read, 0).state == "exited"
    clock.value += 61
    with pytest.raises(NotFound):
        executor.poll_exec(sids[0], read, 0)
    assert executor.poll_exec(sids[0], unread, 0).state == "exited"
    clock.value += 30
    executor.poll_exec(sids[0], unread, 0)
    # An answer never read is kept for the longer retention only.
    other = executor.start_exec(sids[0], REQUEST)
    deadline = time.monotonic() + 5
    while executor._jobs[(sids[0], other)].finished_at is None and time.monotonic() < deadline:
        time.sleep(0.01)
    clock.value += 599
    executor._record_for(sids[0], other)
    clock.value += 1
    with pytest.raises(NotFound):
        executor.poll_exec(sids[0], other, 0)


class _RunningJob(_FakeJob):
    finished = False


def test_running_execs_hit_the_cap():
    executor, _clock, sids = _job_executor(_RunningJob)
    for _ in range(MAX_JOBS_PER_SANDBOX):
        executor.start_exec(sids[0], REQUEST)
    with pytest.raises(ExecutorRefused):
        executor.start_exec(sids[0], REQUEST)
    for _ in range(MAX_JOBS_PER_BOX - MAX_JOBS_PER_SANDBOX):
        executor.start_exec(sids[1], REQUEST)
    with pytest.raises(ExecutorRefused):
        executor.start_exec(sids[2], REQUEST)


class _SlowRunningJob(_RunningJob):
    start_delay = 0.02


def test_concurrent_starts_cannot_exceed_the_caps():
    executor, _clock, sids = _job_executor(_SlowRunningJob)
    results: list[str] = []
    barrier = threading.Barrier(60)

    def start(index: int) -> None:
        barrier.wait()
        try:
            executor.start_exec(sids[index % 3], REQUEST)
            results.append("ok")
        except ExecutorRefused:
            results.append("refused")

    threads = [threading.Thread(target=start, args=(index,)) for index in range(60)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert results.count("ok") == MAX_JOBS_PER_BOX == len(executor._jobs)
    for sid in sids:
        assert sum(1 for key in executor._jobs if key[0] == sid) <= MAX_JOBS_PER_SANDBOX


class _BlockingPipe:
    """A stdin whose reader never reads: write blocks until the process dies."""

    def __init__(self, dead: threading.Event) -> None:
        self._dead = dead

    def write(self, data):
        self._dead.wait()
        raise BrokenPipeError

    def read(self, _size):
        self._dead.wait()
        return b""

    def close(self):
        pass


class _StuckPopen:
    def __init__(self, argv, **kwargs) -> None:
        assert kwargs["shell"] is False
        self._dead = threading.Event()
        self.stdin = _BlockingPipe(self._dead)
        self.stdout = _BlockingPipe(self._dead)
        self.stderr = _BlockingPipe(self._dead)
        self.returncode = None

    def wait(self, timeout=None):
        if not self._dead.wait(timeout):
            raise subprocess.TimeoutExpired("docker", timeout)
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9
        self._dead.set()


def test_the_transfer_timeout_covers_the_upload(monkeypatch):
    monkeypatch.setattr(executor_module.subprocess, "Popen", _StuckPopen)
    executor = _executor()
    outcome: list[ExecResult] = []
    worker = threading.Thread(
        target=lambda: outcome.append(
            executor._run(["docker", "exec"], timeout=0.3, stdin=b"x" * (8 * 1024 * 1024))
        ),
        daemon=True,
    )
    started = time.monotonic()
    worker.start()
    worker.join(10)
    assert not worker.is_alive(), "an upload to a reader that never reads blocked the caller"
    assert outcome[0].timed_out and time.monotonic() - started < 10


def test_file_uploads_refuse_a_target_that_is_not_a_regular_file(monkeypatch):
    executor, _docker, _clock = _docker_executor()
    executor.create(_spec())
    seen = []

    def fake_run(argv, **kwargs):
        seen.append(argv)
        return ExecResult(4)

    monkeypatch.setattr(executor, "_run", fake_run)
    with pytest.raises(ExecutorRefused, match="regular file"):
        executor.write_file(_spec().sandbox_id, "/tmp/fifo", b"data", 0o644)
    script = seen[0][seen[0].index("-c") + 1]
    assert script.index('test -f "$1"') < script.index('cat > "$1"')
