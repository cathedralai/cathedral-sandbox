"""T6b1 egress enforcer: apply, verify, fail closed and tear down, with subprocess mocked.

The last test runs the real nft, tc, ip and nsenter inside an unprivileged
user and network namespace when the host allows one, so the read-back
parsers are checked against the tools' real output formats.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import sys
import textwrap
from dataclasses import replace
from pathlib import Path

import pytest

from cathedral.tee_box.egress import build_egress_policy
from cathedral.tee_box.executor import ExecutorError, ExecutorRefused
from cathedral.tee_box.enforce import (
    NFT_TABLE,
    EgressEnforcementError,
    EgressEnforcer,
    checked_policy,
    detect_box_addresses,
    table_matches,
)

BOX_IPS = ("34.120.1.2", "2600:1900:4000::7")
CONTAINER = "cathsbx-sbx-" + "1" * 24
SANDBOX_KEY = "/var/run/docker/netns/0123456789ab"
VETH = "veth9f8e7d6"


def _policy(**kwargs):
    return build_egress_policy(BOX_IPS, **kwargs)


def _listing(policy, *, extra_rule=None, drop_element=None) -> bytes:
    """What ``nft --json list table`` prints for the policy's table (nft 1.0.9 shape)."""

    def elements(networks):
        out = []
        for net in ipaddress.collapse_addresses(networks):
            if net == drop_element:
                continue
            if net.num_addresses == 1:
                out.append(str(net.network_address))
            else:
                out.append({"prefix": {"addr": str(net.network_address), "len": net.prefixlen}})
        return out

    base = {"family": "inet", "table": NFT_TABLE}
    iif = {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": policy.bridge}}
    counter = {"counter": {"packets": 3, "bytes": 180}}
    entries = [
        {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": NFT_TABLE, "handle": 3}},
        {
            "set": {
                **base,
                "name": "deny4",
                "type": "ipv4_addr",
                "handle": 3,
                "flags": ["interval"],
                "elem": elements(policy.denied_ipv4),
            }
        },
        {
            "set": {
                **base,
                "name": "deny6",
                "type": "ipv6_addr",
                "handle": 4,
                "flags": ["interval"],
                "elem": elements(policy.denied_ipv6),
            }
        },
        {
            "chain": {
                **base,
                "name": "forward",
                "handle": 1,
                "type": "filter",
                "hook": "forward",
                "prio": -1,
                "policy": "accept",
            }
        },
        {
            "chain": {
                **base,
                "name": "input",
                "handle": 2,
                "type": "filter",
                "hook": "input",
                "prio": -1,
                "policy": "accept",
            }
        },
    ]
    for protocol, name in (("ip", "@deny4"), ("ip6", "@deny6")):
        daddr = {"payload": {"protocol": protocol, "field": "daddr"}}
        entries.append(
            {
                "rule": {
                    **base,
                    "chain": "forward",
                    "handle": 5,
                    "expr": [
                        iif,
                        {"match": {"op": "==", "left": daddr, "right": name}},
                        counter,
                        {"drop": None},
                    ],
                }
            }
        )
    entries.append(
        {"rule": {**base, "chain": "input", "handle": 7, "expr": [iif, counter, {"drop": None}]}}
    )
    if extra_rule is not None:
        entries.append({"rule": {**base, "chain": "forward", "handle": 9, "expr": extra_rule}})
    return json.dumps({"nftables": entries}).encode()


class _Box:
    """A scripted guest: docker, nft, nsenter, ip and tc answer from state."""

    def __init__(self, policy) -> None:
        self.policy = policy
        self.calls: list[tuple[list[str], bytes | None]] = []
        self.network: dict | None = None
        self.table: bytes | None = None
        self.qdiscs: dict[str, list[dict]] = {}
        self.filters: dict[str, str] = {}
        self.fail: set[str] = set()  # verbs that exit non-zero
        self.raise_on: set[str] = set()  # verbs whose command times out
        self.tamper_after_apply = False
        self.police_rate = f"{policy.bandwidth_mbit}Mbit"

    def __call__(self, argv, **kwargs):
        assert kwargs["shell"] is False and kwargs["check"] is False
        assert 0 < kwargs["timeout"] <= 120
        assert all(isinstance(item, str) for item in argv)
        stdin = kwargs.get("input")
        self.calls.append((argv, stdin))
        tool = argv[0].rsplit("/", 1)[-1]
        verb = tool + ":" + (argv[1] if len(argv) > 1 else "")
        if verb in self.raise_on or tool in self.raise_on:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        if verb in self.fail or tool in self.fail:
            return subprocess.CompletedProcess(argv, 1, b"", b"Error: failed")
        return getattr(self, "_" + tool)(argv, stdin)

    @staticmethod
    def _done(argv, stdout=b"", code=0, stderr=b""):
        return subprocess.CompletedProcess(argv, code, stdout, stderr)

    def _docker(self, argv, stdin):
        if argv[1:3] == ["network", "inspect"]:
            if self.network is None:
                return self._done(argv, code=1, stderr=b"Error: network cathsbx0 not found")
            return self._done(argv, json.dumps(self.network).encode())
        if argv[1:3] == ["network", "create"]:
            options = dict(argv[i + 1].split("=", 1) for i, a in enumerate(argv) if a == "--opt")
            self.network = {"Name": argv[-1], "Driver": "bridge", "Options": options}
            return self._done(argv, b"f00d\n")
        if argv[1:3] == ["container", "inspect"]:
            return self._done(argv, (SANDBOX_KEY + "\n").encode())
        raise AssertionError(argv)

    def _nft(self, argv, stdin):
        if argv[1:] == ["-f", "-"]:
            text = stdin.decode()
            assert text.startswith(f"table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n")
            self.table = _listing(self.policy)
            if self.tamper_after_apply:
                self.table = _listing(self.policy, drop_element=ipaddress.ip_network("10.0.0.0/8"))
            return self._done(argv)
        if argv[1:] == ["--json", "list", "table", "inet", NFT_TABLE]:
            if self.table is None:
                return self._done(argv, code=1, stderr=b"Error: No such file or directory")
            return self._done(argv, self.table)
        raise AssertionError(argv)

    def _nsenter(self, argv, stdin):
        assert argv[1] == f"--net={SANDBOX_KEY}"
        assert argv[2].endswith("/ip") and argv[3:] == ["-o", "link", "show", "dev", "eth0"]
        return self._done(argv, b"2: eth0@if17: <BROADCAST,MULTICAST,UP> mtu 1500\\    link\n")

    def _ip(self, argv, stdin):
        assert argv[1:] == ["-o", "link", "show", "master", self.policy.bridge]
        return self._done(
            argv,
            b"16: veth0000001@if2: <BROADCAST> mtu 1500 master cathsbx0\n"
            + f"17: {VETH}@if2: <BROADCAST> mtu 1500 master cathsbx0\n".encode(),
        )

    def _tc(self, argv, stdin):
        if argv[1:3] == ["qdisc", "replace"] and "root" in argv:
            rate = int(argv[argv.index("rate") + 1].removesuffix("mbit")) * 125_000
            self.qdiscs.setdefault(argv[4], []).append(
                {"kind": "tbf", "handle": "8001:", "root": True, "options": {"rate": rate}}
            )
        elif argv[1:3] == ["qdisc", "replace"]:
            self.qdiscs.setdefault(argv[4], []).append(
                {"kind": "ingress", "handle": "ffff:", "parent": "ffff:fff1", "options": {}}
            )
        elif argv[1:3] == ["filter", "replace"]:
            self.filters[argv[4]] = (
                "filter parent ffff: protocol all pref 49152 matchall chain 0 handle 0x1\n"
                f"\taction order 1:  police 0x1 rate {self.police_rate} burst 1250000b "
                "mtu 2Kb action drop overhead 0b\n"
            )
        elif argv[1:4] == ["-json", "qdisc", "show"]:
            return self._done(argv, json.dumps(self.qdiscs.get(argv[5], [])).encode())
        elif argv[1:3] == ["filter", "show"]:
            return self._done(argv, self.filters.get(argv[4], "").encode())
        elif argv[1:3] == ["qdisc", "del"]:
            if argv[4] not in self.qdiscs:
                return self._done(
                    argv, code=1, stderr=b'Cannot find device "%s"' % argv[4].encode()
                )
            kind = "tbf" if argv[5] == "root" else "ingress"
            self.qdiscs[argv[4]] = [q for q in self.qdiscs[argv[4]] if q["kind"] != kind]
        else:
            raise AssertionError(argv)
        return self._done(argv)


class _Clock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value


def _enforcer(box=None, **kwargs):
    policy = kwargs.pop("policy", None) or _policy()
    box = box or _Box(policy)
    enforcer = EgressEnforcer(policy, runner=box, **kwargs)
    return enforcer, box


def test_apply_creates_the_bridge_network_applies_and_reads_back_the_table():
    enforcer, box = _enforcer()
    assert enforcer.active is False
    assert enforcer.status()["error"] == "egress rules not applied yet"
    assert enforcer.apply() is True
    assert enforcer.active is True
    assert enforcer.status() == {
        "enforced": True,
        "error": None,
        "bridge": "cathsbx0",
        "nft_table": f"inet {NFT_TABLE}",
        "capped_sandboxes": 0,
        "lapses": 0,
    }
    argvs = [argv for argv, _stdin in box.calls]
    assert argvs[1] == [
        "/usr/bin/docker",
        "network",
        "create",
        "--driver",
        "bridge",
        "--opt",
        "com.docker.network.bridge.name=cathsbx0",
        "--opt",
        "com.docker.network.bridge.enable_icc=false",
        "--label",
        "org.cathedral.tee-box.network=egress",
        "cathsbx0",
    ]
    assert argvs[3] == ["/usr/sbin/nft", "-f", "-"]
    assert box.calls[3][1] == enforcer.nft_ruleset()
    assert enforcer.nft_ruleset().decode().endswith(enforcer.policy.render_nft())
    assert argvs[4] == ["/usr/sbin/nft", "--json", "list", "table", "inet", NFT_TABLE]


@pytest.mark.parametrize(
    "breakage",
    [
        "nft_apply_fails",
        "nft_list_fails",
        "nft_times_out",
        "table_differs",
        "docker_down",
        "network_differs",
    ],
)
def test_a_failed_apply_or_verify_stays_inactive_and_reports(breakage):
    enforcer, box = _enforcer()
    if breakage == "nft_apply_fails":
        box.fail.add("nft:-f")
    elif breakage == "nft_list_fails":
        box.fail.add("nft:--json")
    elif breakage == "nft_times_out":
        box.raise_on.add("nft")
    elif breakage == "table_differs":
        box.tamper_after_apply = True
    elif breakage == "docker_down":
        box.fail.add("docker")
    elif breakage == "network_differs":
        box.network = {"Driver": "bridge", "Options": {"com.docker.network.bridge.name": "br-1"}}
    assert enforcer.apply() is False
    assert enforcer.active is False
    status = enforcer.status()
    assert status["enforced"] is False and status["error"]
    with pytest.raises(EgressEnforcementError):
        enforcer.attach(CONTAINER)
    assert not enforcer.is_enforced(CONTAINER)


def test_verification_that_later_fails_turns_enforcement_off():
    enforcer, box = _enforcer()
    assert enforcer.apply()
    box.table = _listing(box.policy, extra_rule=[{"accept": None}])  # someone edited the table
    assert enforcer.verify() is False
    assert enforcer.status()["error"] == "the nft table does not match the egress policy"
    with pytest.raises(EgressEnforcementError):
        enforcer.attach(CONTAINER)


def test_a_capped_sandbox_stops_counting_as_enforced_when_the_table_fails():
    enforcer, box = _enforcer()
    assert enforcer.apply()
    enforcer.attach(CONTAINER)
    assert enforcer.is_enforced(CONTAINER)
    box.fail.add("nft:--json")
    assert enforcer.verify() is False
    assert not enforcer.is_enforced(CONTAINER)


def test_maintain_retries_a_failed_apply_on_a_bounded_schedule():
    clock = _Clock()
    enforcer, box = _enforcer(clock=clock, retry_seconds=60)
    box.fail.add("nft:-f")
    assert enforcer.apply() is False
    applies = lambda: sum(1 for argv, _ in box.calls if argv[1:] == ["-f", "-"])  # noqa: E731
    enforcer.maintain()
    assert applies() == 1  # too soon
    clock.value += 60
    box.fail.clear()
    enforcer.maintain()
    assert applies() == 2 and enforcer.active
    enforcer.maintain()
    assert applies() == 2  # active: nothing to do


def test_attach_finds_the_veth_through_the_sandbox_namespace_and_verifies_tc():
    enforcer, box = _enforcer(policy=_policy(bandwidth_mbit=250))
    assert enforcer.apply()
    attached = enforcer.attach(CONTAINER)
    assert attached.veth == VETH
    assert enforcer.is_enforced(CONTAINER)
    argvs = [argv for argv, _ in box.calls]
    assert [
        "/usr/bin/docker",
        "container",
        "inspect",
        "--format",
        "{{.NetworkSettings.SandboxKey}}",
        CONTAINER,
    ] in argvs
    tc = [argv for argv in argvs if argv[0] == "/usr/sbin/tc" and argv[2] == "replace"]
    assert tc == [["/usr/sbin/tc", *command[1:]] for command in box.policy.bandwidth_commands(VETH)]
    assert enforcer.status()["capped_sandboxes"] == 1


@pytest.mark.parametrize("breakage", ["tc_fails", "rate_differs", "police_differs", "no_veth"])
def test_a_cap_that_does_not_verify_is_not_enforced(breakage):
    enforcer, box = _enforcer()
    assert enforcer.apply()
    if breakage == "tc_fails":
        box.fail.add("tc:filter")
    elif breakage == "rate_differs":
        original = box._tc

        def slow_tbf(argv, stdin):
            result = original(argv, stdin)
            for qdisc in box.qdiscs.get(VETH, []):
                if qdisc["kind"] == "tbf":
                    qdisc["options"]["rate"] = 1
            return result

        box._tc = slow_tbf
    elif breakage == "police_differs":
        box.police_rate = "1Gbit"
    elif breakage == "no_veth":
        box._ip = lambda argv, stdin: box._done(argv, b"16: veth0000001@if2: <BROADCAST>\n")
    with pytest.raises(EgressEnforcementError):
        enforcer.attach(CONTAINER)
    assert not enforcer.is_enforced(CONTAINER)


def test_detach_removes_the_sandbox_qdiscs_and_tolerates_a_missing_veth():
    enforcer, box = _enforcer()
    assert enforcer.apply()
    enforcer.attach(CONTAINER)
    assert enforcer.detach(CONTAINER) is True
    assert box.calls[-2][0] == ["/usr/sbin/tc", "qdisc", "del", "dev", VETH, "root"]
    assert box.calls[-1][0] == ["/usr/sbin/tc", "qdisc", "del", "dev", VETH, "ingress"]
    assert box.qdiscs[VETH] == []
    assert not enforcer.is_enforced(CONTAINER)
    assert enforcer.status()["capped_sandboxes"] == 0
    # A container already removed took its veth with it.
    enforcer.attach(CONTAINER)
    del box.qdiscs[VETH]
    assert enforcer.detach(CONTAINER) is True
    assert enforcer.detach("never-attached") is True


def test_hostile_sandbox_namespace_or_interface_names_are_refused():
    enforcer, box = _enforcer()
    assert enforcer.apply()
    box._docker = lambda argv, stdin: box._done(argv, b"/proc/1/ns/net\n")
    with pytest.raises(EgressEnforcementError, match="namespace"):
        enforcer.attach(CONTAINER)
    enforcer, box = _enforcer()
    assert enforcer.apply()
    box._ip = lambda argv, stdin: box._done(argv, b"17: eth0;reboot@if2: <BROADCAST>\n")
    with pytest.raises(EgressEnforcementError):
        enforcer.attach(CONTAINER)
    with pytest.raises(EgressEnforcementError):
        enforcer.attach("cathsbx-x; rm -rf /")


def test_policy_addresses_must_be_ipaddress_objects():
    policy = _policy()
    hostile = "1.2.3.4/32 }; flush ruleset; table inet x {"
    for bad in (
        replace(policy, denied=(*policy.denied, hostile)),
        replace(policy, box_addresses=(hostile,)),
        replace(policy, box_addresses=(ipaddress.ip_network("9.9.9.9/32"),)),  # not denied
        replace(policy, bridge="br0 }"),
        replace(policy, bandwidth_mbit="100mbit burst"),
    ):
        with pytest.raises(EgressEnforcementError):
            checked_policy(bad)
        with pytest.raises(EgressEnforcementError):
            EgressEnforcer(bad, runner=_Box(policy))
    assert checked_policy(policy) is policy


def test_detected_box_addresses_come_from_ipaddress_objects_only():
    listing = [
        {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},
        {
            "ifname": "eth0",
            "addr_info": [
                {"family": "inet", "local": "10.128.0.5"},
                {"family": "inet6", "local": "fe80::4001:aff:fe80:5"},
            ],
        },
    ]

    def runner(argv, **kwargs):
        assert argv == ["/usr/sbin/ip", "-json", "address", "show"] and kwargs["shell"] is False
        return subprocess.CompletedProcess(argv, 0, json.dumps(listing).encode(), b"")

    found = detect_box_addresses(runner=runner, extra=("34.120.1.2",))
    assert found == tuple(
        ipaddress.ip_address(text)
        for text in ("34.120.1.2", "127.0.0.1", "10.128.0.5", "fe80::4001:aff:fe80:5")
    )
    for hostile in ("10.0.0.1 } ; flush ruleset", "10.0.0.1\n", "cathsbx0", 7, ""):
        listing[1]["addr_info"][0]["local"] = hostile
        with pytest.raises(EgressEnforcementError):
            detect_box_addresses(runner=runner)
    with pytest.raises(EgressEnforcementError):
        detect_box_addresses(runner=runner, extra=("34.120.1.2; reboot",))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["nftables"].pop(2),  # a set is missing
        lambda d: d["nftables"][2]["set"].__setitem__("elem", d["nftables"][2]["set"]["elem"][1:]),
        lambda d: d["nftables"][4]["chain"].__setitem__("prio", 10),
        lambda d: d["nftables"][4]["chain"].__setitem__("policy", "drop"),
        lambda d: d["nftables"].append({"map": {"family": "inet", "table": NFT_TABLE}}),
        lambda d: d["nftables"][6]["rule"]["expr"].pop(3),  # no drop
        lambda d: d["nftables"][6]["rule"]["expr"][0]["match"].__setitem__("right", "eth0"),
        lambda d: d["nftables"][1]["table"].__setitem__("family", "ip"),
        lambda d: d["nftables"].__setitem__(slice(0, None), []),
    ],
)
def test_table_comparison_catches_every_difference(mutate):
    policy = _policy()
    document = json.loads(_listing(policy))
    assert table_matches(policy, json.dumps(document).encode())
    mutate(document)
    assert not table_matches(policy, json.dumps(document).encode())
    assert not table_matches(policy, b"not json")


_REAL_SCRIPT = textwrap.dedent(
    """
    import json, subprocess, sys
    sys.path.insert(0, sys.argv[1])
    from cathedral.tee_box.egress import build_egress_policy
    from cathedral.tee_box.enforce import EgressEnforcer
    sh = lambda cmd: subprocess.run(cmd, shell=True, check=True)
    sh("mount -t tmpfs none /run && mkdir -p /run/docker/netns && ip netns add sbx"
       " && touch /run/docker/netns/abc123"
       " && mount --bind /run/netns/sbx /run/docker/netns/abc123"
       " && ip link add cathsbx0 type bridge"
       " && ip link add veth9f8e7d6 type veth peer name eth0 netns sbx"
       " && ip link set veth9f8e7d6 master cathsbx0")
    policy = build_egress_policy(["34.120.1.2", "2600:1900:4000::7"], bandwidth_mbit=250)

    def runner(argv, **kwargs):
        if argv[0].endswith("docker"):
            if argv[1:3] == ["network", "inspect"]:
                network = {"Driver": "bridge", "Options": {
                    "com.docker.network.bridge.name": "cathsbx0",
                    "com.docker.network.bridge.enable_icc": "false"}}
                return subprocess.CompletedProcess(argv, 0, json.dumps(network).encode(), b"")
            return subprocess.CompletedProcess(argv, 0, b"/run/docker/netns/abc123\\n", b"")
        return subprocess.run(argv, **kwargs)

    tools = {name: sys.argv[i] for i, name in enumerate(("nft", "tc", "ip", "nsenter"), 2)}
    enforcer = EgressEnforcer(policy, runner=runner, **tools)
    out = {"applied": enforcer.apply(), "error": enforcer.status()["error"]}
    out["reapplied"] = enforcer.apply()
    attached = enforcer.attach("cathsbx-sbx-1")
    out["veth"] = attached.veth
    out["enforced"] = enforcer.is_enforced("cathsbx-sbx-1")
    out["detached"] = enforcer.detach("cathsbx-sbx-1")
    out["qdiscs_left"] = [q["kind"] for q in json.loads(subprocess.run(
        [tools["tc"], "-json", "qdisc", "show", "dev", "veth9f8e7d6"],
        capture_output=True, check=True).stdout) if q["kind"] in ("tbf", "ingress")]
    sh(tools["nft"] + " add rule inet cathedral_tee_box_egress forward accept")
    out["verify_after_tamper"] = enforcer.verify()
    print(json.dumps(out))
    """
)


def test_real_nft_tc_and_ip_in_an_unprivileged_namespace(tmp_path: Path):
    tools = [
        shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
        for name in ("nft", "tc", "ip", "nsenter", "unshare")
    ]
    if not all(tools):
        pytest.skip("nft, tc, ip, nsenter or unshare is not installed")
    probe = subprocess.run([tools[4], "-r", "-n", "-m", "true"], capture_output=True, timeout=30)
    if probe.returncode != 0:
        pytest.skip("unprivileged user and network namespaces are not available")
    script = tmp_path / "real.py"
    script.write_text(_REAL_SCRIPT)
    repo = str(Path(__file__).resolve().parent.parent)
    result = subprocess.run(
        [tools[4], "-r", "-n", "-m", sys.executable, str(script), repo, *tools[:4]],
        capture_output=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr.decode()[-2000:]
    out = json.loads(result.stdout.decode().strip().splitlines()[-1])
    assert out == {
        "applied": True,
        "error": None,
        "reapplied": True,
        "veth": "veth9f8e7d6",
        "enforced": True,
        "detached": True,
        "qdiscs_left": [],
        "verify_after_tamper": False,
    }


# -- the executor and the real enforcer together ---------------------------


def _wired(box_policy=None):
    """A RunscExecutor using a real EgressEnforcer; docker and the tools are scripted."""

    from tests.test_tee_box_executor import DIGEST, IMAGE, _Clock as _WallClock, _Docker

    policy = box_policy or _policy()
    box, docker, clock = _Box(policy), _Docker(), _Clock()
    box.order = []  # every command, docker and tools, in order

    def runner(argv, **kwargs):
        box.order.append(argv)
        tool = argv[0].rsplit("/", 1)[-1]
        if tool != "docker" or argv[1] == "network" or "{{.NetworkSettings.SandboxKey}}" in argv:
            return box(argv, **kwargs)
        return docker(argv, **kwargs)

    enforcer = EgressEnforcer(policy, runner=runner, clock=clock, retry_seconds=60)
    from cathedral.tee_box.executor import RunscExecutor

    executor = RunscExecutor(
        policy, docker="docker", runner=runner, egress_enforcer=enforcer, clock=_WallClock()
    )
    executor.import_image(DIGEST, IMAGE.reference)
    assert enforcer.apply()
    return executor, enforcer, box, docker, clock


def _internet(sid_digit: str = "1"):
    from tests.test_tee_box_executor import _spec

    return _spec("internet", sid="sbx-" + sid_digit * 24)


def _tc_deletes(box):
    return [argv for argv, _ in box.calls if argv[1:3] == ["qdisc", "del"]]


def test_a_flushed_table_cuts_off_running_internet_sandboxes_on_the_next_tick():
    executor, enforcer, box, docker, clock = _wired()
    running = _internet()
    executor.create(running)
    name = "cathsbx-" + running.sandbox_id
    assert name in docker.containers and enforcer.is_enforced(name)
    # nftables.service reload: "nft flush ruleset". The re-apply fails too.
    box.table = None
    box.fail.add("nft:-f")
    executor.sweep()
    assert executor.get(running.sandbox_id) is None
    assert name not in docker.containers
    status = executor.egress_status()
    assert status["enforced"] is False and status["error"]
    assert (status["lapses"], status["ended_on_lapse"]) == (1, 1)
    assert executor.network_modes == ("deny_all",)
    with pytest.raises(ExecutorRefused):
        executor.create(_internet("2"))
    # The cap went only after the container was gone.
    rm_at = box.order.index(["docker", "rm", "--force", name])
    tc_at = box.order.index(_tc_deletes(box)[0])
    assert rm_at < tc_at
    # The reaper's re-apply restores new creates; the ended sandbox stays gone.
    box.fail.clear()
    clock.value += 60
    executor.sweep()
    assert executor.egress_status()["enforced"] is True
    assert executor.network_modes == ("internet", "deny_all")
    executor.create(_internet("2"))
    assert executor.get(running.sandbox_id) is None
    assert name not in docker.containers


def test_a_tampered_table_ends_running_sandboxes_even_when_re_apply_succeeds():
    executor, enforcer, box, docker, _clock = _wired()
    executor.create(_internet())
    deny_all = _internet("3")
    deny_all = replace(deny_all, network="deny_all")
    executor.create(deny_all)
    box.table = _listing(box.policy, extra_rule=[{"accept": None}])
    executor.sweep()
    # Re-applied at once, but the sandbox ran unprotected for an unknown time.
    assert enforcer.active and enforcer.lapses == 1
    assert executor.get(_internet().sandbox_id) is None
    assert executor.get(deny_all.sandbox_id) is not None  # no network, untouched
    assert executor.egress_status()["ended_on_lapse"] == 1


def test_a_lapse_whose_removal_fails_keeps_the_cap_and_retries():
    executor, enforcer, box, docker, _clock = _wired()
    running = _internet()
    executor.create(running)
    name = "cathsbx-" + running.sandbox_id
    box.table = None
    box.fail.add("nft:-f")
    docker.rm_failures = 10**6
    executor.sweep()
    assert executor.get(running.sandbox_id) is not None
    status = executor.egress_status()
    assert status["lapse_removals_pending"] == 1
    assert "could not be removed" in status["error"]
    assert _tc_deletes(box) == [] and enforcer.status()["capped_sandboxes"] == 1
    docker.rm_failures = 0
    executor.sweep()
    assert executor.get(running.sandbox_id) is None and name not in docker.containers
    assert len(_tc_deletes(box)) == 2
    assert executor.egress_status()["lapse_removals_pending"] == 0


def test_a_delete_whose_remove_fails_keeps_the_bandwidth_cap():
    executor, enforcer, box, docker, _clock = _wired()
    running = _internet()
    executor.create(running)
    docker.rm_failures = 3  # rm, kill, rm all fail; the daemon still lists it
    with pytest.raises(ExecutorError):
        executor.delete(running.sandbox_id)
    assert _tc_deletes(box) == []
    assert enforcer.is_enforced("cathsbx-" + running.sandbox_id)
    assert executor.delete(running.sandbox_id)
    assert len(_tc_deletes(box)) == 2
    assert not enforcer.is_enforced("cathsbx-" + running.sandbox_id)


def test_the_sweep_detaches_an_orphan_only_once_it_is_gone():
    executor, enforcer, box, docker, _clock = _wired()
    running = _internet()
    executor.create(running)
    name = "cathsbx-" + running.sandbox_id
    executor._forget(running.sandbox_id)  # the table lost it: now an orphan
    docker.rm_failures = 10**6
    assert executor.sweep() == 1
    assert _tc_deletes(box) == [] and enforcer.status()["capped_sandboxes"] == 1
    docker.rm_failures = 0
    assert executor.sweep() == 0 and name not in docker.containers
    assert len(_tc_deletes(box)) == 2


def test_the_reaper_reads_the_table_back_every_tick():
    executor, enforcer, box, docker, _clock = _wired()
    lists = lambda: sum(1 for argv, _ in box.calls if argv[1] == "--json")  # noqa: E731
    before = lists()
    executor.sweep()
    executor.sweep()
    assert lists() == before + 2
