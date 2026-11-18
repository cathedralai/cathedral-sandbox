"""AB#343: a room on a sealed miner hotel sends nothing except along the path
the broker set for it.

The broker sets a room's network policy (create, or PUT .../network). The
hotel API hands it to room_egress.py, which writes it into nftables inside the
SNP guest. Named destinations go to the egress daemon on the bridge gateway
(DNS, SNI/HTTP proxy); every other packet a room sends is dropped unless the
policy opens it. The miner host only NATs the guest's link.

This test builds that packet path in network namespaces and runs the real
rules on it, then probes from rooms:

    room ns --veth--> guest ns (bridge rmbr0 / rmnet0, room-net.sh, the
                      room_egress tables through Table.put, sealed_guard from
                      build-guest.sh) --"uplink"--> host ns (host-net.sh,
                      SEALED_MINER=1) --> inet ns (public addresses) and
                      lan ns (a private network behind the miner host)

Every listener answers with its own name, so a probe tells "reached the
public host" from "redirected to the egress daemon" from "dropped" (timeout).
Each drop has a positive control: the same listener answers someone allowed.

The egress daemon itself is not started (it needs Docker); stand-in listeners
take its ports. Its name decisions are covered by tests/test_room_kit_egress.py.

Needs root, ip, nft and iptables. Skips otherwise (CI runs unprivileged).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
KIT = REPO / "room-kit"
ENV_PATH = os.environ.get("PATH", "") + ":/usr/sbin:/sbin"


def _have_tools() -> str | None:
    if os.geteuid() != 0:
        return "needs root (network namespaces, nftables)"
    for tool in ("ip", "nft", "iptables", "bash"):
        if shutil.which(tool, path=ENV_PATH) is None:
            return f"needs {tool}"
    return None


pytestmark = pytest.mark.skipif(_have_tools() is not None, reason=_have_tools() or "")


def _load_room_egress():
    spec = importlib.util.spec_from_file_location("room_egress", KIT / "room_egress.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["room_egress"] = mod
    spec.loader.exec_module(mod)
    return mod


# One helper for listeners and probes, run inside a namespace.
HELPER = textwrap.dedent(r'''
    import json, socket, sys, threading

    def listen(name, log, specs):
        socks = []
        for spec in specs:
            proto, addr, port = spec.split(":")
            kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
            s = socket.socket(socket.AF_INET, kind)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((addr, int(port)))
            if proto == "tcp":
                s.listen(64)
            socks.append((proto, s))

        def tcp(s):
            while True:
                c, peer = s.accept()
                try:
                    c.sendall(f"{name} {peer[0]}\n".encode())
                finally:
                    c.close()

        def udp(s):
            while True:
                data, peer = s.recvfrom(2048)
                with open(log, "a") as f:
                    f.write(f"{name} {peer[0]} {data.decode(errors='replace')}\n")
                s.sendto(f"{name} {peer[0]}".encode(), peer)

        for proto, s in socks:
            threading.Thread(target=tcp if proto == "tcp" else udp, args=(s,), daemon=True).start()
        print("ready", flush=True)
        sys.stdin.read()  # until the test closes stdin

    def probe(targets):
        out = {}

        def one(t):
            proto, addr, port = t["proto"], t["addr"], int(t["port"])
            try:
                if proto == "tcp":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(t.get("timeout", 1.5))
                    if t.get("src"):
                        s.bind((t["src"], 0))
                    s.connect((addr, port))
                    out[t["id"]] = s.recv(256).decode().strip() or "closed"
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(t.get("timeout", 1.5))
                    if t.get("src"):
                        s.bind((t["src"], 0))
                    s.sendto(t.get("payload", t["id"]).encode(), (addr, port))
                    out[t["id"]] = s.recv(256).decode().strip()
            except socket.timeout:
                out[t["id"]] = "timeout"
            except ConnectionRefusedError:
                out[t["id"]] = "refused"
            except OSError as exc:
                out[t["id"]] = f"error {exc.errno}"

        threads = [threading.Thread(target=one, args=(t,)) for t in targets]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        print(json.dumps(out))

    if sys.argv[1] == "listen":
        listen(sys.argv[2], sys.argv[3], sys.argv[4:])
    else:
        probe(json.loads(sys.argv[2]))
''')

# Production values (room-kit/sealed/guest-constants.sh, build-guest.sh room.env).
HOST_IP, GUEST_IP, GUEST_MAC = "10.215.0.1", "10.215.0.2", "52:54:00:5e:a1:ed"
TLS_PORT, PUBLIC_PORT, API_PORT = 18443, 9443, 18090
DNS_PORT, HTTP_PORT, PROXY_TLS_PORT = 15353, 15080, 15443
ROOM_ENV = {
    "ROOM_ID": "ab343",
    "ROOM_BRIDGE": "rmbr0",
    "ROOM_BRIDGE_CIDR": "10.213.0.1/21",
    "ROOM_NETS": "10.214.0.0/22",
    "ROOM_NET_BRIDGE_PREFIX": "rmnet",
}
# The miner host's public side and the internet behind it. None of these is in
# a range the rules drop, so a drop below is the policy, not the address.
HOST_PUBLIC, INET_LINK = "198.51.100.1", "198.51.100.2"
WEB, ALLOWED_NET_HOST, RESOLVER = "203.0.113.34", "192.0.2.4", "8.8.8.8"
LAN_HOST = "192.168.50.2"

# Rooms: name -> (bridge, ip, mac, policy or None for a port with no policy,
# mac the broker's facts report if it differs from the real one).
ROOMS = {
    "open": ("rmbr0", "10.213.0.2", "02:42:0a:d5:00:02", {"mode": "internet", "allow": []}, None),
    "deny": ("rmbr0", "10.213.0.3", "02:42:0a:d5:00:03", {"mode": "deny_all", "allow": []}, None),
    "allow": ("rmbr0", "10.213.0.4", "02:42:0a:d5:00:04",
              {"mode": "allowlist", "allow": ["pypi.org", "192.0.2.0/24"]}, None),
    "net1": ("rmnet0", "10.214.0.2", "02:42:0a:d6:00:02", {"mode": "internet", "allow": []}, None),
    "badmac": ("rmbr0", "10.213.0.5", "02:42:0a:d5:00:05", {"mode": "internet", "allow": []}, "02:42:0a:d5:00:55"),
    "unbound": ("rmbr0", "10.213.0.9", "02:42:0a:d5:00:09", None, None),
}


class Net:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.tag = "ab343" + secrets.token_hex(3)
        self.ns: list[str] = []
        self.procs: list[subprocess.Popen] = []
        self.helper = tmp / "netns_helper.py"
        self.helper.write_text(HELPER)
        self.env = dict(os.environ, PATH=ENV_PATH)

    def n(self, name: str) -> str:
        return f"{self.tag}-{name}"

    def sh(self, *argv: str, ns: str | None = None, check: bool = True, stdin: str | None = None) -> str:
        cmd = (["ip", "netns", "exec", self.n(ns)] if ns else []) + list(argv)
        r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, env=self.env, timeout=60, check=False)
        if check and r.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd)}: {r.returncode} {r.stderr.strip()}")
        return r.stdout + r.stderr

    def add_ns(self, name: str) -> None:
        self.sh("ip", "netns", "add", self.n(name))
        self.ns.append(name)
        self.sh("ip", "link", "set", "lo", "up", ns=name)
        for key in ("all", "default"):
            self.sh("sysctl", "-qw", f"net.ipv4.conf.{key}.rp_filter=0", ns=name)

    def veth(self, a: str, a_if: str, b: str, b_if: str) -> None:
        # Both ends are created inside their namespaces: no name in the root
        # namespace, so parallel runs cannot collide.
        self.sh("ip", "link", "add", a_if, "netns", self.n(a), "type", "veth", "peer", "name", b_if, "netns", self.n(b))
        self.sh("ip", "link", "set", a_if, "up", ns=a)
        self.sh("ip", "link", "set", b_if, "up", ns=b)

    def listen(self, ns: str, name: str, *specs: str) -> None:
        p = subprocess.Popen(["ip", "netns", "exec", self.n(ns), sys.executable, "-I", str(self.helper), "listen", name,
                              str(self.tmp / "udp.log"), *specs],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)
        self.procs.append(p)
        line = p.stdout.readline().strip()
        if line != "ready":
            raise RuntimeError(f"listener {name} in {ns}: {line} {p.stderr.read()}")

    def probe(self, ns: str, targets: list[dict]) -> dict[str, str]:
        out = self.sh(sys.executable, "-I", str(self.helper), "probe", json.dumps(targets), ns=ns)
        return json.loads(out.strip().splitlines()[-1])

    def udp_log(self) -> str:
        p = self.tmp / "udp.log"
        return p.read_text() if p.exists() else ""

    def close(self) -> None:
        for p in self.procs:
            try:
                p.stdin.close()
            except OSError:
                pass
            p.kill()
            p.wait(timeout=10)
            for f in (p.stdout, p.stderr):
                f.close()
        for name in reversed(self.ns):
            subprocess.run(["ip", "netns", "del", self.n(name)], capture_output=True, env=self.env, check=False)


def _sealed_guard(miner: bool) -> str:
    """Render the guest's uplink firewall from build-guest.sh, so this test
    runs the same rules the measured image installs at sysinit."""
    text = (KIT / "sealed" / "build-guest.sh").read_text()
    m = re.search(r'cat > "\$R/etc/sealed-guard\.nft" <<EOF\n(.*?)\nEOF\n', text, re.DOTALL)
    assert m, "sealed-guard.nft heredoc not found in build-guest.sh"
    input_rules = f'iifname "uplink" tcp dport {TLS_PORT} accept' if miner else ""
    script = f'SEALED_HOST_IP={HOST_IP}\nINPUT_RULES={json.dumps(input_rules)}\ncat <<EOF\n{m.group(1)}\nEOF\n'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout


@pytest.fixture(scope="module")
def net(tmp_path_factory):
    eg = _load_room_egress()
    tmp = tmp_path_factory.mktemp("ab343")
    n = Net(tmp)
    try:
        for name in ("inet", "lan", "host", "guest", *ROOMS):
            n.add_ns(name)

        # inet: the public internet, reached through the miner host.
        n.veth("host", "wan0", "inet", "eth0")
        n.sh("ip", "addr", "add", f"{HOST_PUBLIC}/24", "dev", "wan0", ns="host")
        n.sh("ip", "addr", "add", f"{INET_LINK}/24", "dev", "eth0", ns="inet")
        for a in (WEB, ALLOWED_NET_HOST, RESOLVER):
            n.sh("ip", "addr", "add", f"{a}/32", "dev", "lo", ns="inet")
        n.sh("ip", "route", "add", "default", "via", HOST_PUBLIC, ns="inet")
        n.sh("ip", "route", "add", "default", "via", INET_LINK, ns="host")

        # lan: a private network behind the miner host (its LAN, other tenants).
        n.veth("host", "lan0", "lan", "eth0")
        n.sh("ip", "addr", "add", "192.168.50.1/24", "dev", "lan0", ns="host")
        n.sh("ip", "addr", "add", f"{LAN_HOST}/24", "dev", "eth0", ns="lan")
        n.sh("ip", "route", "add", "default", "via", "192.168.50.1", ns="lan")

        # The guest link. host-net.sh makes a tap only when the link is missing,
        # so a veth with the tap's name stands in for QEMU's tap.
        n.veth("host", "sltap0", "guest", "uplink")
        n.sh("ip", "link", "set", "uplink", "address", GUEST_MAC, ns="guest")
        sealed_env = tmp / "sealed.env"
        sealed_env.write_text(f"SEALED_TAP=sltap0\nSEALED_NAME={n.tag}\nSEALED_MINER=1\n"
                              f"SEALED_MINER_TLS_PORT={TLS_PORT}\nSEALED_MINER_PUBLIC_PORT={PUBLIC_PORT}\n")
        n.host_env = sealed_env
        n.sh("bash", str(KIT / "sealed" / "host-net.sh"), "up", str(sealed_env), ns="host")
        n.sh("ip", "addr", "add", f"{GUEST_IP}/30", "dev", "uplink", ns="guest")
        n.sh("ip", "route", "add", "default", "via", HOST_IP, ns="guest")
        n.sh("nft", "-f", "-", ns="guest", stdin=_sealed_guard(miner=True))

        # Guest: room-net.sh first (the room daemon's ExecStartPre), then the
        # room network bridges dockerd would make, then the egress tables.
        (tmp / "data").mkdir()
        room_env = tmp / "room.env"
        room_env.write_text("".join(f'{k}="{v}"\n' for k, v in {**ROOM_ENV, "ROOM_DATA_DIR": str(tmp / "data")}.items()))
        n.sh("bash", str(KIT / "lib" / "room-net.sh"), "up", str(room_env), ns="guest")
        n.sh("ip", "link", "add", "rmnet0", "type", "bridge", ns="guest")
        n.sh("ip", "addr", "add", "10.214.0.1/22", "dev", "rmnet0", ns="guest")
        n.sh("ip", "link", "set", "rmnet0", "up", ns="guest")
        n.br_netfilter = os.path.exists("/proc/sys/net/bridge/bridge-nf-call-iptables")
        if n.br_netfilter:  # the guest image loads br_netfilter; follow it when the kernel has it
            n.sh("sysctl", "-qw", "net.bridge.bridge-nf-call-iptables=1", ns="guest")

        class Facts:
            def __init__(self):
                self.by_cid = {}

            def facts(self, cid):
                return self.by_cid[cid]

            def running(self):
                return set(self.by_cid)

        facts = Facts()
        rules = eg.rules_for(ROOM_ENV, (DNS_PORT, HTTP_PORT, PROXY_TLS_PORT),
                             run=lambda script: n.sh("nft", "-f", "-", ns="guest", stdin=script))
        table = eg.Table(rules, facts, None)
        eg.flush_conntrack = lambda ip: n.sh("conntrack", "-D", "-s", ip, ns="guest", check=False) \
            if shutil.which("conntrack", path=ENV_PATH) else None
        table.load()  # the daemon starts with no rooms: base tables, deny by default

        gateways = {"rmbr0": "10.213.0.1", "rmnet0": "10.214.0.1"}
        for i, (name, (bridge, ip, mac, policy, facts_mac)) in enumerate(ROOMS.items()):
            port = f"vr{i}"
            n.veth("guest", port, name, "eth0")
            n.sh("ip", "link", "set", port, "master", bridge, ns="guest")
            n.sh("ip", "link", "set", "eth0", "address", mac, ns=name)
            prefix = "21" if bridge == "rmbr0" else "22"
            n.sh("ip", "addr", "add", f"{ip}/{prefix}", "dev", "eth0", ns=name)
            n.sh("ip", "route", "add", "default", "via", gateways[bridge], ns=name)
            if policy is not None:
                cid = f"{i:02d}" + "ab343" * 3 + "0" * 7
                facts.by_cid[cid] = (ip, facts_mac or mac, port)
                # The production entry point: what the control socket PUT calls.
                table.put(cid, f"sbx-{name}", eg.Policy.parse(policy))

        # Listeners. Each answers with its name and the peer address it saw.
        n.listen("inet", "inet", *(f"tcp:{WEB}:{p}" for p in (22, 80, 443)),
                 f"tcp:{ALLOWED_NET_HOST}:22", f"tcp:{ALLOWED_NET_HOST}:443",
                 f"tcp:{RESOLVER}:53", f"tcp:{RESOLVER}:5353", f"udp:{RESOLVER}:53", f"udp:{RESOLVER}:9999")
        n.listen("lan", "lan", f"tcp:{LAN_HOST}:80")
        n.listen("host", "host", f"tcp:{HOST_IP}:2222", f"tcp:{HOST_PUBLIC}:2222")
        n.listen("guest", "guest-attested", f"tcp:{GUEST_IP}:{TLS_PORT}")
        n.listen("guest", "guest-api", f"tcp:{GUEST_IP}:{API_PORT}")
        n.listen("guest", "guest-docker", "tcp:10.213.0.1:2375")
        n.listen("guest", "egress-dns", f"udp:0.0.0.0:{DNS_PORT}", f"tcp:0.0.0.0:{DNS_PORT}")
        n.listen("guest", "egress-http", f"tcp:0.0.0.0:{HTTP_PORT}")
        n.listen("guest", "egress-tls", f"tcp:0.0.0.0:{PROXY_TLS_PORT}")
        n.listen("deny", "room-deny", "tcp:10.213.0.3:7000")
        n.table = table
        yield n
    finally:
        n.close()


def tcp(tid, addr, port, **kw):
    return {"id": tid, "proto": "tcp", "addr": addr, "port": port, **kw}


def udp(tid, addr, port, **kw):
    return {"id": tid, "proto": "udp", "addr": addr, "port": port, **kw}


def who(result: str) -> str:
    return result.split()[0]


# Private and in-guest destinations no room may reach, whatever its policy.
INSIDE = [
    tcp("host-link", HOST_IP, 2222),
    tcp("host-public", HOST_PUBLIC, 2222),
    tcp("lan", LAN_HOST, 80),
    tcp("guest-api", GUEST_IP, API_PORT),
    tcp("guest-attested", GUEST_IP, TLS_PORT),
    tcp("guest-docker", "10.213.0.1", 2375),
    tcp("room-to-room", "10.213.0.3", 7000),
]


def test_controls_every_listener_answers_someone_allowed(net):
    """Positive controls: each target dropped below is up and reachable."""
    got = net.probe("inet", [tcp(f"web{p}", WEB, p) for p in (22, 80, 443)]
                    + [tcp("net22", ALLOWED_NET_HOST, 22), tcp("dns-tcp", RESOLVER, 53), tcp("dns5353", RESOLVER, 5353),
                       udp("dns-udp", RESOLVER, 53)])
    assert all(who(v) == "inet" for v in got.values()), got
    got = net.probe("host", [tcp("lan", LAN_HOST, 80), tcp("host-link", HOST_IP, 2222),
                             tcp("guest-api", GUEST_IP, API_PORT)])
    assert {k: who(v) for k, v in got.items()} == {"lan": "lan", "host-link": "host", "guest-api": "guest-api"}, got
    got = net.probe("guest", [tcp("docker", "10.213.0.1", 2375), tcp("room", "10.213.0.3", 7000),
                              tcp("attested", GUEST_IP, TLS_PORT), tcp("host-public", HOST_PUBLIC, 2222)])
    assert {k: who(v) for k, v in got.items()} == {
        "docker": "guest-docker", "room": "room-deny", "attested": "guest-attested", "host-public": "timeout"}, got
    # (the guest itself is refused the miner host's own services: host-net.sh SEALED-*-IN)


def test_internet_room_leaves_through_the_guest_and_the_host_nat(net):
    for room in ("open", "net1"):
        got = net.probe(room, [tcp(f"web{p}", WEB, p) for p in (22, 80, 443)]
                        + [udp("dns", RESOLVER, 53), tcp("dns5353", RESOLVER, 5353)])
        # inet sees the miner host's address: room -> guest NAT -> host NAT.
        assert all(v == f"inet {HOST_PUBLIC}" for v in got.values()), (room, got)


def test_no_room_reaches_private_or_in_guest_destinations(net):
    for room in ("open", "deny", "allow", "net1"):
        # The deny room holds the room-to-room listener; it may talk to itself.
        got = net.probe(room, [t for t in INSIDE if not (room == "deny" and t["id"] == "room-to-room")])
        if room == "allow":
            # A named-allowlist room's port 80 goes to the egress proxy whatever
            # the address; the proxy connects only to public answers for an
            # allowed name, so the LAN host is still never reached.
            assert who(got.pop("lan")) == "egress-http", got
        assert all(v == "timeout" for v in got.values()), json.dumps([room, got])


def test_deny_all_room_has_no_direct_egress(net):
    got = net.probe("deny", [tcp(f"web{p}", WEB, p) for p in (22, 80, 443)]
                    + [tcp("net22", ALLOWED_NET_HOST, 22), tcp("dns5353", RESOLVER, 5353), udp("udp9999", RESOLVER, 9999)])
    assert all(v == "timeout" for v in got.values()), got
    # DNS goes to the hotel resolver (it answers REFUSED for deny_all), never upstream.
    got = net.probe("deny", [udp("dns-udp", RESOLVER, 53), tcp("dns-tcp", RESOLVER, 53)])
    assert {k: who(v) for k, v in got.items()} == {"dns-udp": "egress-dns", "dns-tcp": "egress-dns"}, got


def test_allowlist_room_named_traffic_goes_through_the_egress_proxy(net):
    got = net.probe("allow", [
        tcp("web443", WEB, 443), tcp("web80", WEB, 80), udp("dns-udp", RESOLVER, 53), tcp("dns-tcp", RESOLVER, 53),
        tcp("web22", WEB, 22), tcp("dns5353", RESOLVER, 5353), udp("udp9999", RESOLVER, 9999),
        tcp("net22", ALLOWED_NET_HOST, 22), tcp("net443", ALLOWED_NET_HOST, 443),
    ])
    assert {k: who(v) for k, v in got.items()} == {
        # A public address on 443/80 lands on the proxy, which connects only to
        # an allowed name it resolves itself; the room never reaches the address.
        "web443": "egress-tls", "web80": "egress-http",
        "dns-udp": "egress-dns", "dns-tcp": "egress-dns",
        "web22": "timeout", "dns5353": "timeout", "udp9999": "timeout",
        # An allowed CIDR is the one direct path the policy opens.
        "net22": "inet", "net443": "inet",
    }, got


def test_forged_sources_and_unbound_ports_send_nothing(net):
    # The open room's address is the one that would pass room_forward.
    net.sh("ip", "addr", "add", "10.213.0.2/32", "dev", "eth0", ns="allow")
    net.sh("ip", "addr", "add", "10.213.0.2/32", "dev", "eth0", ns="unbound")
    try:
        before = net.udp_log()
        got = {
            "allow-as-open": net.probe("allow", [udp("x", RESOLVER, 9999, src="10.213.0.2", payload="forged-allow")])["x"],
            "unbound-as-open": net.probe("unbound", [udp("x", RESOLVER, 9999, src="10.213.0.2", payload="forged-unbound")])["x"],
            "unbound-own": net.probe("unbound", [udp("x", RESOLVER, 9999, src="10.213.0.9", payload="unbound-own")])["x"],
            "unbound-dns": net.probe("unbound", [udp("x", RESOLVER, 53, src="10.213.0.9", payload="unbound-dns")])["x"],
            "badmac": net.probe("badmac", [udp("x", RESOLVER, 9999, payload="badmac")])["x"],
        }
        assert all(v == "timeout" for v in got.values()), got
        new = net.udp_log()[len(before):]
        for payload in ("forged-allow", "forged-unbound", "unbound-own", "unbound-dns", "badmac"):
            assert payload not in new, new
        # Control: the open room's own datagram arrives and is logged.
        assert who(net.probe("open", [udp("x", RESOLVER, 9999, payload="open-own")])["x"]) == "inet"
        assert "open-own" in net.udp_log()
    finally:
        net.sh("ip", "addr", "del", "10.213.0.2/32", "dev", "eth0", ns="allow", check=False)
        net.sh("ip", "addr", "del", "10.213.0.2/32", "dev", "eth0", ns="unbound", check=False)


def test_policy_switch_closes_the_direct_path(net):
    # A live switch (PUT .../network) goes through the same Table.put.
    eg = sys.modules["room_egress"]
    cid = next(c for c, f in net.table.docker.by_cid.items() if f[0] == "10.213.0.2")
    net.table.put(cid, "sbx-open", eg.Policy.parse({"mode": "deny_all", "allow": []}))
    try:
        got = net.probe("open", [tcp("web22", WEB, 22), udp("dns", RESOLVER, 53)])
        assert {k: who(v) for k, v in got.items()} == {"web22": "timeout", "dns": "egress-dns"}, got
    finally:
        net.table.put(cid, "sbx-open", eg.Policy.parse({"mode": "internet", "allow": []}))
    assert who(net.probe("open", [tcp("web22", WEB, 22)])["web22"]) == "inet"


def test_miner_host_link_admits_only_the_attested_port(net):
    # From the internet: the public port reaches the guest's attested HTTPS
    # port; nothing else on the guest answers, from the internet or the LAN.
    got = net.probe("inet", [tcp("public", HOST_PUBLIC, PUBLIC_PORT), tcp("api", GUEST_IP, API_PORT),
                             tcp("proxy", GUEST_IP, PROXY_TLS_PORT)])
    assert who(got["public"]) == "guest-attested", got
    assert {k: v for k, v in got.items() if k != "public"} == {"api": "timeout", "proxy": "timeout"}, got
    got = net.probe("lan", [tcp("api", GUEST_IP, API_PORT)])
    assert got == {"api": "timeout"}, got
    # From the guest itself: the miner LAN and the host's services are closed.
    got = net.probe("guest", [tcp("lan", LAN_HOST, 80), tcp("host-link", HOST_IP, 2222), tcp("web", WEB, 443)])
    assert {k: who(v) for k, v in got.items()} == {"lan": "timeout", "host-link": "timeout", "web": "inet"}, got
    # host-net.sh check finds every rule in place (it restores and says so otherwise).
    out = net.sh("bash", str(KIT / "sealed" / "host-net.sh"), "check", str(net.host_env), ns="host")
    assert "restoring" not in out, out
    fwd = net.sh("iptables", "-S", "SEALED-SLTAP0-FWD", ns="host")
    for private in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16"):
        assert f"-d {private} -i sltap0 -j DROP" in fwd, fwd
    assert fwd.rstrip().splitlines()[-1].endswith("-o sltap0 -j DROP"), fwd


def test_egress_drops_are_counted_by_the_room_policy(net):
    out = net.sh("nft", "list", "chain", "ip", "pool_room_egress_ab343", "room_forward", ns="guest")
    m = re.search(r"counter packets (\d+) bytes \d+ drop", out)
    assert m and int(m.group(1)) > 0, out
