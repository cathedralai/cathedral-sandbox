"""T6a egress policy rendering and the runsc backend's argv, with subprocess mocked."""

from __future__ import annotations

import ipaddress
import subprocess
import sys

import pytest

from cathedral.common import is_globally_routable
from cathedral.tee_box.egress import (
    DENIED_IPV4,
    DENIED_IPV6,
    METADATA_ADDRESSES,
    EgressPolicyError,
    build_egress_policy,
)
from cathedral.tee_box.executor import (
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
