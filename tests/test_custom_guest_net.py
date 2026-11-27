"""custom-net.sh (spec-r9 6; test plan 14.1 "Network").

A stateful fake iptables, ip6tables, ip, sysctl and ss on PATH; the real script
under bash. Checks the rule set of up, idempotence, the clash and IPv6 refusals,
check's restore and cleanup, and that down and purge leave no tagged rule."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
NET = REPO / "ops" / "custom-guest" / "custom-net.sh"
HOTEL, LAUNCH = "chi-ur-2", "cg-0123456789ab"
TAG = f"custom-guest:{HOTEL}:{LAUNCH}"

FAKE_IPTABLES = r'''#!/usr/bin/env python3
import json, os, sys
v6 = os.path.basename(sys.argv[0]) == "ip6tables"
path = os.environ["FAKE_NET"] + (".ip6.json" if v6 else ".ip4.json")
st = json.load(open(path)) if os.path.exists(path) else {}
args = sys.argv[1:]
with open(os.environ["FAKE_NET"] + ".calls", "a") as log:
    log.write(("ip6tables " if v6 else "iptables ") + " ".join(args) + "\n")
table = "filter"
if args[:1] == ["-t"]:
    table, args = args[1], args[2:]
BUILTIN = {"filter": ["INPUT", "FORWARD", "OUTPUT"], "nat": ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"]}
t = st.setdefault(table, {c: [] for c in BUILTIN[table]})
op = args[0]
def done(rc=0):
    json.dump(st, open(path, "w"))
    sys.exit(rc)
if op == "-S":
    if len(args) > 1 and args[1] not in t:
        sys.exit(1)
    chains = [args[1]] if len(args) > 1 else list(t)
    for c in chains:
        print(f"-P {c} ACCEPT" if c in BUILTIN[table] else f"-N {c}")
    for c in chains:
        for r in t[c]:
            print(f"-A {c} {r}")
    sys.exit(0)
chain, rest = args[1], args[2:]
spec = " ".join(rest)
if op == "-N":
    if chain in t:
        done(1)
    t[chain] = []
elif op == "-F":
    if chain not in t:
        done(1)
    t[chain] = []
elif op == "-X":
    if chain not in t or t[chain]:
        done(1)
    del t[chain]
elif op == "-C":
    sys.exit(0 if chain in t and spec in t[chain] else 1)
elif op == "-A":
    if chain not in t:
        done(1)
    t[chain].append(spec)
elif op == "-I":
    pos = 1
    if rest and rest[0].isdigit():
        pos, rest = int(rest[0]), rest[1:]
    t[chain].insert(pos - 1, " ".join(rest))
elif op == "-D":
    stuck = os.environ.get("FAKE_STUCK")
    if (stuck and stuck in spec) or chain not in t or spec not in t[chain]:
        done(1)
    t[chain].remove(spec)
done(0)
'''

FAKE_IP = r'''#!/usr/bin/env python3
import json, os, sys
path = os.environ["FAKE_NET"] + ".links.json"
st = json.load(open(path)) if os.path.exists(path) else {}
a = sys.argv[1:]
rc = 0
if a[:2] == ["link", "show"]:
    rc = 0 if a[2] in st else 1
elif a[:2] == ["tuntap", "add"]:
    st[a[3]] = {"user": a[a.index("user") + 1], "group": a[a.index("group") + 1], "addrs": [], "up": False}
elif a[:2] == ["addr", "replace"]:
    st[a[4]]["addrs"] = [a[2]]
elif a[:2] == ["link", "set"] and a[3] == "up":
    conf = os.path.join(os.environ["CG_IPV6_CONF_DIR"], a[2], "disable_ipv6")
    st[a[2]]["up"] = True
    st[a[2]]["v6_off_at_up"] = os.path.exists(conf) and open(conf).read().strip() == "1"
elif a[:2] == ["link", "del"]:
    rc = 0 if st.pop(a[2], None) is not None else 1
elif a[:4] == ["-4", "-o", "addr", "show"]:
    for i, (dev, s) in enumerate(st.items()):
        for cidr in s["addrs"]:
            print(f"{i + 2}: {dev}    inet {cidr} scope global {dev}\\       valid_lft forever")
json.dump(st, open(path, "w"))
sys.exit(rc)
'''

FAKE_SYSCTL = r'''#!/bin/sh
for a; do case "$a" in -*) ;; *) kv=$a ;; esac; done
key=${kv%%=*}; val=${kv#*=}
case "$key" in
  net.ipv6.conf.*.disable_ipv6)
    [ -n "${FAKE_V6_BROKEN:-}" ] && exit 1
    dev=${key#net.ipv6.conf.}; dev=${dev%.disable_ipv6}
    mkdir -p "$CG_IPV6_CONF_DIR/$dev"; echo "$val" > "$CG_IPV6_CONF_DIR/$dev/disable_ipv6" ;;
esac
exit 0
'''

FAKE_SS = r'''#!/bin/sh
for a; do case "$a" in "sport = :"*) p=${a#sport = :} ;; esac; done
case " ${FAKE_LISTEN:-} " in *" $p "*) echo "LISTEN 0 4096 0.0.0.0:$p 0.0.0.0:*" ;; esac
exit 0
'''

FAKE_SYSTEMCTL = '#!/bin/sh\necho "${FAKE_UNIT_STATE:-inactive}"\n'


class Net:
    def __init__(self, tmp: Path, ports=((20022, 22), (20443, 443))):
        self.tmp = tmp
        self.root = tmp / "root"
        self.bin = tmp / "bin"
        self.state = tmp / "net"
        self.v6 = tmp / "v6conf"
        for d in (self.bin, self.v6, self.root / "run/lock", self.root / f"srv/sealed-hotel-{HOTEL}"):
            d.mkdir(parents=True, exist_ok=True)
        for name, text in (("iptables", FAKE_IPTABLES), ("ip6tables", FAKE_IPTABLES), ("ip", FAKE_IP),
                           ("sysctl", FAKE_SYSCTL), ("ss", FAKE_SS), ("systemctl", FAKE_SYSTEMCTL),
                           ("flock", "#!/bin/sh\nexit 0\n")):
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        (self.root / f"srv/sealed-hotel-{HOTEL}/sealed.env").write_text(f"SEALED_NAME={HOTEL}\n")
        self.write_bootstrap(ports)
        # A kit rule that is not ours: down must leave it.
        self.ipt("-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "8443", "-j", "DNAT",
                 "--to-destination", "10.215.0.2:8443")
        self.ipt("-A", "FORWARD", "-i", "snp0", "-j", "ACCEPT")

    def write_bootstrap(self, ports) -> None:
        img = self.root / f"srv/custom-guest/{HOTEL}/{LAUNCH}/images"
        img.mkdir(parents=True, exist_ok=True)
        (img / "bootstrap.json").write_text(json.dumps({
            "network": {"guest_ip": "10.217.0.2", "host_ip": "10.217.0.1", "prefix": 30},
            "ports": [{"public": p, "guest": g, "proto": "tcp"} for p, g in ports]}))

    def env(self, **extra: str) -> dict:
        return dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", CG_ROOT=str(self.root),
                    FAKE_NET=str(self.state), CG_IPV6_CONF_DIR=str(self.v6), **extra)

    def ipt(self, *args: str) -> None:
        subprocess.run([str(self.bin / "iptables"), *args], check=True, env=self.env())

    def run(self, action: str, **extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(NET), action, HOTEL, LAUNCH], capture_output=True, text=True,
                              env=self.env(**extra), timeout=60)

    def tables(self, v6: bool = False) -> dict:
        p = Path(f"{self.state}{'.ip6' if v6 else '.ip4'}.json")
        return json.loads(p.read_text()) if p.exists() else {}

    def links(self) -> dict:
        p = Path(f"{self.state}.links.json")
        return json.loads(p.read_text()) if p.exists() else {}

    def tagged(self) -> list[str]:
        out = []
        for v6 in (False, True):
            for table, chains in self.tables(v6).items():
                for chain, rules in chains.items():
                    out += [f"{table} {chain} {r}" for r in rules if TAG in r]
        return out


@pytest.fixture
def net(tmp_path):
    return Net(tmp_path)


def test_up_builds_the_section_6_rule_set(net):
    p = net.run("up")
    assert p.returncode == 0, p.stderr
    t, links = net.tables(), net.links()
    assert links["cgst0"]["user"] == f"cg-{HOTEL}" and links["cgst0"]["addrs"] == ["10.217.0.1/30"]
    assert links["cgst0"]["up"] and links["cgst0"]["v6_off_at_up"], "disable_ipv6 before link up"
    fwd = t["filter"]["CGST-CGST0-FWD"]
    assert fwd[:2] == ["-i cgst0 -s 10.217.0.2 -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT",
                       "-i cgst0 -s 10.217.0.2 -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT"]
    assert "-i cgst0 -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16,224.0.0.0/4," \
           "240.0.0.0/4 -j DROP" in fwd
    assert "-i cgst0 -p tcp --dport 25 -j DROP" in fwd
    assert fwd.index("-i cgst0 -s 10.217.0.2 -j ACCEPT") == fwd.index("-i cgst0 -j DROP") - 1
    assert "-o cgst0 -d 10.217.0.2 -p tcp --dport 22 -m conntrack --ctstate NEW -m conntrack --ctstate DNAT " \
           "--ctorigdstport 20022 -j ACCEPT" in fwd
    assert fwd[-2:] == ["-o cgst0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "-o cgst0 -j DROP"]
    assert t["filter"]["CGST-CGST0-IN"] == ["-i cgst0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                                            "-i cgst0 -j DROP"]
    assert t["filter"]["FORWARD"][0] == f"-m comment --comment {TAG} -j CGST-CGST0-FWD"
    assert t["filter"]["INPUT"][0] == f"-m comment --comment {TAG} -j CGST-CGST0-IN"
    assert t["filter"]["OUTPUT"] == [
        f"-o cgst0 -m owner --uid-owner cg-probe -m conntrack --ctstate NEW -m comment --comment {TAG} -j ACCEPT",
        f"-o cgst0 -m conntrack --ctstate NEW -m comment --comment {TAG} -j DROP"]
    dnat = [r for r in t["nat"]["PREROUTING"] if TAG in r]
    assert dnat == [f"-p tcp --dport {p} -m addrtype --dst-type LOCAL -m comment --comment {TAG} -j DNAT "
                    f"--to-destination 10.217.0.2:{g}" for p, g in ((20022, 22), (20443, 443))]
    assert not [r for r in t["nat"]["OUTPUT"] if TAG in r], "no nat OUTPUT rule: the host does not reach the guest"
    assert t["nat"]["POSTROUTING"] == [f"-s 10.217.0.2/32 ! -o cgst0 -m comment --comment {TAG} -j MASQUERADE"]
    v6 = net.tables(v6=True)["filter"]
    assert f"-i cgst0 -m comment --comment {TAG} -j DROP" in v6["INPUT"]
    assert {f"-i cgst0 -m comment --comment {TAG} -j DROP", f"-o cgst0 -m comment --comment {TAG} -j DROP"} \
        <= set(v6["FORWARD"])


def test_up_twice_is_the_same_rule_set(net):
    assert net.run("up").returncode == 0
    first = (net.tables(), net.tables(v6=True), net.links())
    assert net.run("up").returncode == 0
    assert (net.tables(), net.tables(v6=True), net.links()) == first


def test_up_drops_a_tagged_forward_an_older_run_left(net):
    assert net.run("up").returncode == 0
    net.ipt("-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "20999", "-m", "addrtype", "--dst-type", "LOCAL",
            "-m", "comment", "--comment", TAG, "-j", "DNAT", "--to-destination", "10.217.0.2:9999")
    assert net.run("up").returncode == 0
    assert not [r for r in net.tables()["nat"]["PREROUTING"] if "20999" in r]


@pytest.mark.parametrize("down", ["down", "purge"])
def test_down_and_purge_leave_no_tagged_rule_and_keep_the_kit_rules(net, down):
    assert net.run("up").returncode == 0
    p = net.run(down)
    assert p.returncode == 0, p.stderr
    assert net.tagged() == []
    t = net.tables()
    assert "CGST-CGST0-FWD" not in t["filter"] and "CGST-CGST0-IN" not in t["filter"]
    assert "cgst0" not in net.links()
    assert "-p tcp --dport 8443 -j DNAT --to-destination 10.215.0.2:8443" in t["nat"]["PREROUTING"]
    assert "-i snp0 -j ACCEPT" in t["filter"]["FORWARD"]


def test_purge_after_the_launch_folder_is_gone(net):
    assert net.run("up").returncode == 0
    (net.root / f"srv/custom-guest/{HOTEL}/{LAUNCH}/images/bootstrap.json").unlink()
    p = net.run("purge")
    assert p.returncode == 0, p.stderr
    assert net.tagged() == [] and "cgst0" not in net.links(), "the tap is found from the tagged jumps"


def test_down_fails_while_a_tagged_rule_is_left(net):
    assert net.run("up").returncode == 0
    p = net.run("down", FAKE_STUCK="MASQUERADE")
    assert p.returncode == 1 and "custom_guest_isolation_failed" in p.stderr
    assert [r for r in net.tagged() if "MASQUERADE" in r]


@pytest.mark.parametrize("case", ["kit_port", "other_dnat", "listener"])
def test_port_clash_refused_before_any_change(net, case):
    extra = {}
    if case == "kit_port":
        (net.root / f"srv/sealed-hotel-{HOTEL}/sealed.env").write_text(
            f"SEALED_NAME={HOTEL}\nSEALED_MINER_PUBLIC_PORT=20443\n")
    elif case == "other_dnat":
        net.ipt("-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "20443", "-j", "DNAT",
                "--to-destination", "10.215.0.2:443")
    else:
        extra["FAKE_LISTEN"] = "20022"
    p = net.run("up", **extra)
    assert p.returncode == 1 and "ERROR custom_guest_port_unavailable" in p.stderr, p.stderr
    assert net.tagged() == [] and "cgst0" not in net.links()


def test_link_clash_refused(net):
    links = {"eth9": {"user": "", "group": "", "addrs": ["10.217.0.5/24"], "up": True}}
    Path(f"{net.state}.links.json").write_text(json.dumps(links))
    p = net.run("up")
    assert p.returncode == 1 and "custom_guest_port_unavailable" in p.stderr
    assert net.tagged() == []


def test_ipv6_not_shut_refuses_and_leaves_nothing(net):
    p = net.run("up", FAKE_V6_BROKEN="1")
    assert p.returncode == 1 and "ERROR custom_guest_ipv6_not_shut" in p.stderr, p.stderr
    assert net.tagged() == []
    assert not net.links().get("cgst0", {}).get("up"), "the link never came up"


def test_check_restores_rules_while_the_unit_runs(net):
    assert net.run("up").returncode == 0
    want = net.tables()
    # A firewall reload flushed the nat table.
    state = net.tables()
    state["nat"] = {c: [r for r in rules if TAG not in r] for c, rules in state["nat"].items()}
    Path(f"{net.state}.ip4.json").write_text(json.dumps(state))
    p = net.run("check", FAKE_UNIT_STATE="active")
    assert p.returncode == 0, p.stderr
    assert "restoring" in p.stderr
    assert net.tables()["nat"] == want["nat"]
    assert net.run("check", FAKE_UNIT_STATE="active").stderr == "", "nothing to restore the second time"


@pytest.mark.parametrize("unit_state", ["inactive", "failed"])
def test_check_removes_leftovers_once_the_unit_stopped(net, unit_state):
    assert net.run("up").returncode == 0
    p = net.run("check", FAKE_UNIT_STATE=unit_state)
    assert p.returncode == 0, p.stderr
    assert net.tagged() == [] and "cgst0" not in net.links()
    assert net.run("check", FAKE_UNIT_STATE=unit_state).returncode == 0


def test_check_leaves_rules_alone_while_the_unit_is_activating(net):
    assert net.run("up").returncode == 0
    before = net.tables()
    assert net.run("check", FAKE_UNIT_STATE="activating").returncode == 0
    assert net.tables() == before


@pytest.mark.parametrize("bad", [{"guest_ip": "10.218.0.2"}, {"host_ip": "10.217.0.9"}, {"prefix": 24}])
def test_a_bootstrap_outside_the_link_plan_is_refused(net, bad):
    path = net.root / f"srv/custom-guest/{HOTEL}/{LAUNCH}/images/bootstrap.json"
    doc = json.loads(path.read_text())
    doc["network"].update(bad)
    path.write_text(json.dumps(doc))
    p = net.run("up")
    assert p.returncode == 1 and "custom_guest_isolation_failed" in p.stderr
    assert net.tagged() == []
