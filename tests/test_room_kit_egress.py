"""Room kit egress daemon (room_egress.py): per-room policy outside the room.

The nftables runner and the docker facts are fakes. The DNS resolver and the
SNI/HTTP proxy run for real on 127.0.0.1 with a fake upstream.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import ssl
import struct
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "room-kit" / "room_egress.py"


def _load():
    spec = importlib.util.spec_from_file_location("room_egress", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["room_egress"] = mod  # dataclasses look the module up by name
    spec.loader.exec_module(mod)
    return mod


eg = _load()


class FakeDocker:
    def __init__(self):
        self.facts_by_cid = {}
        self.alive = set()

    def add(self, cid, ip, mac="02:42:0a:00:00:02", port="veth1"):
        self.facts_by_cid[cid] = (ip, mac, port)
        self.alive.add(cid)

    def facts(self, cid):
        if cid not in self.facts_by_cid:
            raise RuntimeError("not running")
        return self.facts_by_cid[cid]

    def running(self):
        return set(self.alive)


class Runner:
    def __init__(self):
        self.scripts: list[str] = []
        self.fail_next = False

    def __call__(self, script: str) -> None:
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("nft failed: No such file or directory")
        self.scripts.append(script)


@pytest.fixture
def table(tmp_path, monkeypatch):
    monkeypatch.setattr(eg, "flush_conntrack", lambda ip: None)
    runner = Runner()
    rules = eg.Rules("room-test", ["10.213.0.0/21", "10.214.0.0/22"], 15353, 15080, 15443, run=runner)
    docker = FakeDocker()
    t = eg.Table(rules, docker, str(tmp_path / "state.json"))
    t.load()
    t.runner, t.fake = runner, docker
    return t


ALLOW = {"mode": "allowlist", "allow": ["pypi.org", "*.pythonhosted.org", "1.2.3.4", "9.0.0.0/8"]}


def test_policy_parse_canonical_and_matching() -> None:
    p = eg.Policy.parse({"mode": "allowlist", "allow": ["PyPI.org.", "*.pythonhosted.org", "1.2.3.4", "9.1.2.3/8", "1.2.3.0/24"]})
    assert p.document() == {"mode": "allowlist", "allow": ["*.pythonhosted.org", "1.2.3.0/24", "1.2.3.4", "9.0.0.0/8", "pypi.org"]}
    assert p.nets == ("1.2.3.0/24", "9.0.0.0/8")  # 1.2.3.4 folds into 1.2.3.0/24: no interval overlap in nft
    assert p.allows_name("pypi.org") and p.allows_name("PYPI.ORG.")
    assert p.allows_name("pypi.org", 443) and p.allows_name("pypi.org", 80)
    assert p.allows_name("files.pythonhosted.org") and p.allows_name("a.b.pythonhosted.org")
    assert not p.allows_name("pythonhosted.org")  # a wildcard does not match its suffix
    assert not p.allows_name("github.com") and not p.allows_name("evilpypi.org")
    assert not eg.Policy.parse({"mode": "internet"}).allows_name("pypi.org")


def test_policy_honors_hostname_port() -> None:
    """example.com:443 opens TLS only; :80 is refused (Affinities / CONST)."""
    p = eg.Policy.parse({"mode": "allowlist", "allow": ["example.com:443"]})
    assert p.document()["allow"] == ["example.com:443"]
    assert p.allows_name("example.com")  # DNS
    assert p.allows_name("example.com", 443)
    assert not p.allows_name("example.com", 80)
    both = eg.Policy.parse({"mode": "allowlist", "allow": ["example.com:443", "example.com:80"]})
    assert both.document()["allow"] == ["example.com"]
    assert both.allows_name("example.com", 80) and both.allows_name("example.com", 443)


@pytest.mark.parametrize("bad", ["::1", "2001:db8::/32", "http://pypi.org", "pypi.org:8080", "*", "*.1.2.3.4", "a..b", "pypi", ""])
def test_policy_refuses_bad_entries(bad) -> None:
    with pytest.raises(ValueError):
        eg.Policy.parse({"mode": "allowlist", "allow": [bad]})


def test_policy_refuses_bad_modes() -> None:
    for doc in ({"mode": "public"}, {"mode": "allowlist", "allow": []}, {"mode": "deny_all", "allow": ["pypi.org"]}):
        with pytest.raises(ValueError):
            eg.Policy.parse(doc)


def test_base_tables_deny_by_default(table) -> None:
    base = table.runner.scripts[0]
    # Both tables are replaced in one transaction.
    assert base.startswith("table ip pool_room_egress_room_test {}\ndelete table ip pool_room_egress_room_test\n")
    assert "elements = { 10.213.0.0/21, 10.214.0.0/22 }" in base
    assert "ip saddr . ip daddr @allow return" in base
    assert "meta l4proto { tcp, udp } th dport 53 redirect to :15353" in base
    assert "ip saddr @named tcp dport 443 redirect to :15443" in base
    assert "ip saddr @named tcp dport 80 redirect to :15080" in base
    # A room address that is in no set falls through to the drop.
    fwd = base[base.index("chain room_forward"):]
    assert fwd.index("ip saddr @open return") < fwd.index("counter drop")
    # The bridge guard binds each port to its MAC and address.
    assert "iifname . ether saddr != @bound_mac drop" in base
    assert "ether type arp iifname . arp saddr ip != @bound drop" in base


def test_put_switch_and_forget(table) -> None:
    table.fake.add("c" * 64, "10.214.0.2")
    room = table.put("c" * 64, "sbx_1", eg.Policy.parse(ALLOW))
    assert room.ip == "10.214.0.2"
    add = table.runner.scripts[-1]
    assert "add element ip pool_room_egress_room_test named { 10.214.0.2 }" in add
    assert "add element ip pool_room_egress_room_test allow { 10.214.0.2 . 1.2.3.4/32, 10.214.0.2 . 9.0.0.0/8 }" in add
    assert 'add element bridge pool_room_egress_room_test bound { "veth1" . 10.214.0.2 }' in add
    assert "open" not in add
    # Live switch to internet: the old elements go and the new one comes in one transaction.
    table.put("c" * 64, "sbx_1", eg.Policy.parse({"mode": "internet"}))
    sw = table.runner.scripts[-1]
    assert sw.index("delete element ip pool_room_egress_room_test named") < sw.index("add element ip pool_room_egress_room_test open { 10.214.0.2 }")
    assert table.policy_of("10.214.0.2").mode == "internet"
    # deny_all: no element in open, named or allow.
    table.put("c" * 64, "sbx_1", eg.Policy.parse({"mode": "deny_all"}))
    deny = table.runner.scripts[-1]
    assert "delete element ip pool_room_egress_room_test open { 10.214.0.2 }" in deny
    assert not any(line.startswith("add element ip ") for line in deny.splitlines())
    assert table.forget("c" * 64)
    assert table.policy_of("10.214.0.2") is None
    assert not table.forget("c" * 64)


def test_stale_room_on_reused_address_loses_its_policy(table) -> None:
    table.fake.add("a" * 64, "10.214.0.9")
    table.put("a" * 64, "sbx_old", eg.Policy.parse({"mode": "internet"}))
    # The old container is gone without a forget; a new one gets its address.
    table.fake.alive.discard("a" * 64)
    table.fake.add("b" * 64, "10.214.0.9", port="veth2")
    table.put("b" * 64, "sbx_new", eg.Policy.parse({"mode": "deny_all"}))
    tx = table.runner.scripts[-1]
    assert "delete element ip pool_room_egress_room_test open { 10.214.0.9 }" in tx
    assert table.policy_of("10.214.0.9").mode == "deny_all"
    assert "a" * 64 not in table.by_cid


def test_reconcile_drops_gone_containers(table) -> None:
    table.fake.add("d" * 64, "10.214.0.3")
    table.put("d" * 64, "sbx_d", eg.Policy.parse({"mode": "internet"}))
    table.fake.alive.clear()
    assert table.reconcile() == 1
    assert table.policy_of("10.214.0.3") is None


def test_drift_reinstalls_from_memory(table) -> None:
    table.fake.add("e" * 64, "10.214.0.4")
    table.put("e" * 64, "sbx_e", eg.Policy.parse({"mode": "internet"}))
    table.fake.add("f" * 64, "10.214.0.5", port="veth5")
    table.runner.fail_next = True
    table.put("f" * 64, "sbx_f", eg.Policy.parse(ALLOW))
    reinstall = table.runner.scripts[-2]
    assert "delete table ip pool_room_egress_room_test" in reinstall
    assert "add element ip pool_room_egress_room_test open { 10.214.0.4 }" in reinstall
    assert "10.214.0.5" in table.runner.scripts[-1]


def test_state_survives_a_restart_but_not_for_gone_rooms(table, tmp_path) -> None:
    table.fake.add("1" * 64, "10.214.0.6")
    table.fake.add("2" * 64, "10.214.0.7", port="veth7")
    table.put("1" * 64, "sbx_1", eg.Policy.parse(ALLOW))
    table.put("2" * 64, "sbx_2", eg.Policy.parse({"mode": "internet"}))
    table.fake.alive.discard("2" * 64)
    runner = Runner()
    again = eg.Table(eg.Rules("room-test", ["10.214.0.0/22"], 15353, 15080, 15443, run=runner), table.fake,
                     str(tmp_path / "state.json"))
    again.load()
    assert again.policy_of("10.214.0.6").document() == eg.Policy.parse(ALLOW).document()
    assert again.policy_of("10.214.0.7") is None
    assert "10.214.0.7" not in runner.scripts[0]


# ---------------------------------------------------------------- DNS

def _query(name: str, qtype: int = 1, qid: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def _rcode(msg: bytes) -> int:
    return struct.unpack("!H", msg[2:4])[0] & 0xF


def test_dns_decisions(table) -> None:
    table.fake.add("1" * 64, "10.214.0.10")
    table.fake.add("2" * 64, "10.214.0.11", port="veth11")
    table.fake.add("3" * 64, "10.214.0.12", port="veth12")
    table.put("1" * 64, "s1", eg.Policy.parse(ALLOW))
    table.put("2" * 64, "s2", eg.Policy.parse({"mode": "deny_all"}))
    table.put("3" * 64, "s3", eg.Policy.parse({"mode": "internet"}))
    r = eg.Resolver(table, ["192.0.2.53"])
    assert r.decide("10.214.0.10", _query("pypi.org")) is None  # forward
    assert r.decide("10.214.0.10", _query("files.pythonhosted.org", 28)) is None
    nx = r.decide("10.214.0.10", _query("github.com"))
    assert _rcode(nx) == eg.NXDOMAIN and nx[:2] == b"\x12\x34" and nx[2] & 0x80
    assert _rcode(r.decide("10.214.0.11", _query("pypi.org"))) == eg.REFUSED
    assert _rcode(r.decide("10.214.0.99", _query("pypi.org"))) == eg.REFUSED  # unknown room
    assert r.decide("10.214.0.12", _query("github.com")) is None
    assert r.decide("10.214.0.10", b"\x00\x01") == b""  # malformed: dropped


# ---------------------------------------------------------------- proxy

def _client_hello(name: str) -> bytes:
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=name)
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    return out.read()


def test_tls_sni_from_a_real_client_hello() -> None:
    raw = _client_hello("files.pythonhosted.org")
    assert raw[0] == 22
    assert eg.tls_sni(raw[5:]) == "files.pythonhosted.org"
    assert eg.tls_sni(b"\x01\x00") is None


async def _run_proxy(table, *, tls: bool, room_ip: str, payload: bytes):
    """Start a fake upstream and the proxy on 127.0.0.1. The proxy sees the
    room address through a patched peername."""
    got = {}

    async def upstream(reader, writer):
        got["data"] = await reader.read(65536)
        writer.write(b"UPSTREAM-OK")
        await writer.drain()
        writer.close()

    up = await asyncio.start_server(upstream, "127.0.0.1", 0)
    up_port = up.sockets[0].getsockname()[1]

    async def resolve(name, port):
        got["resolved"] = name
        return ["127.0.0.1"]

    proxy = eg.Proxy(table, resolve=resolve, addr_ok=lambda a: True)

    async def handler(reader, writer):
        real = writer.get_extra_info

        def fake(key, default=None):
            return (room_ip, 1) if key == "peername" else real(key, default)

        writer.get_extra_info = fake
        # The proxy checks the policy on the room's real port (80 or 443),
        # so hand it that port and send its upstream dial to the fake server.
        await proxy.handle(reader, writer, 443 if tls else 80, tls)

    real_open = asyncio.open_connection

    async def open_upstream(host, port, *args, **kwargs):
        if host == "127.0.0.1" and port in (80, 443):
            port = up_port
        return await real_open(host, port, *args, **kwargs)

    front = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = front.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection("127.0.0.1", port)
    asyncio.open_connection = open_upstream
    try:
        w.write(payload)
        await w.drain()
        answer = await asyncio.wait_for(r.read(65536), 5)
    finally:
        asyncio.open_connection = real_open
    w.close()
    up.close()
    front.close()
    return answer, got, proxy


def test_proxy_tls_allowed_name_reaches_its_own_answer(table) -> None:
    table.fake.add("1" * 64, "10.214.0.20")
    table.put("1" * 64, "s1", eg.Policy.parse(ALLOW))
    hello = _client_hello("pypi.org")
    answer, got, _ = asyncio.run(_run_proxy(table, tls=True, room_ip="10.214.0.20", payload=hello))
    assert answer == b"UPSTREAM-OK"
    assert got["resolved"] == "pypi.org" and got["data"] == hello


def test_proxy_tls_refuses_other_names_and_other_rooms(table) -> None:
    table.fake.add("1" * 64, "10.214.0.21")
    table.fake.add("2" * 64, "10.214.0.22", port="veth22")
    table.put("1" * 64, "s1", eg.Policy.parse(ALLOW))
    table.put("2" * 64, "s2", eg.Policy.parse({"mode": "deny_all"}))
    answer, got, _ = asyncio.run(_run_proxy(table, tls=True, room_ip="10.214.0.21", payload=_client_hello("github.com")))
    assert answer == b"" and "resolved" not in got
    answer, got, _ = asyncio.run(_run_proxy(table, tls=True, room_ip="10.214.0.22", payload=_client_hello("pypi.org")))
    assert answer == b"" and "resolved" not in got


def test_proxy_http_host_header(table) -> None:
    table.fake.add("1" * 64, "10.214.0.23")
    table.put("1" * 64, "s1", eg.Policy.parse(ALLOW))
    ok = b"GET /simple/ HTTP/1.1\r\nHost: files.pythonhosted.org:80\r\n\r\n"
    answer, got, _ = asyncio.run(_run_proxy(table, tls=False, room_ip="10.214.0.23", payload=ok))
    assert answer == b"UPSTREAM-OK" and got["resolved"] == "files.pythonhosted.org"
    bad = b"GET / HTTP/1.1\r\nHost: github.com\r\n\r\n"
    answer, got, _ = asyncio.run(_run_proxy(table, tls=False, room_ip="10.214.0.23", payload=bad))
    assert answer.startswith(b"HTTP/1.1 403")


def test_switch_closes_open_proxy_connections(table) -> None:
    table.fake.add("1" * 64, "10.214.0.24")
    table.put("1" * 64, "s1", eg.Policy.parse(ALLOW))
    closed = []

    class W:
        class transport:  # noqa: N801 - mimics a StreamWriter
            @staticmethod
            def abort():
                closed.append(1)

    proxy = eg.Proxy(table)
    table.on_change = proxy.recheck
    proxy.active["10.214.0.24"] = {("pypi.org", 443, W, W)}
    table.put("1" * 64, "s1", eg.Policy.parse({"mode": "allowlist", "allow": ["pypi.org"]}))
    assert closed == []  # still allowed
    table.put("1" * 64, "s1", eg.Policy.parse({"mode": "deny_all"}))
    assert closed == [1, 1]


def test_control_socket_round_trip(table, tmp_path) -> None:
    import http.client
    import socket
    import threading

    import tempfile

    table.fake.add("ab" * 32, "10.214.0.30")
    path = tempfile.mktemp(prefix="eg", suffix=".sock", dir="/tmp")  # AF_UNIX paths are short
    srv = eg.ControlServer(path, eg.Control)
    srv.table = table
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    class Conn(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(path)

    def call(method, url, body=None):
        c = Conn("localhost")
        c.request(method, url, body=json.dumps(body).encode() if body is not None else None)
        r = c.getresponse()
        return r.status, json.loads(r.read())

    status, doc = call("PUT", "/rooms/" + "ab" * 32, {"sandbox_id": "sbx_x", "policy": ALLOW})
    assert status == 200 and doc["ip"] == "10.214.0.30"
    assert doc["policy"] == eg.Policy.parse(ALLOW).document()
    assert doc["policy_sha256"] == eg.policy_sha256(doc["policy"])
    status, doc = call("PUT", "/rooms/" + "ab" * 32, {"policy": {"mode": "allowlist", "allow": ["::1"]}})
    assert status == 400 and doc["error"]["code"] == "invalid_policy"
    status, doc = call("PUT", "/rooms/" + "cd" * 32, {"policy": {"mode": "internet"}})
    assert status == 502  # container not running
    status, doc = call("GET", "/rooms")
    assert [r["sandbox_id"] for r in doc["rooms"]] == ["sbx_x"]
    status, doc = call("DELETE", "/rooms/" + "ab" * 32)
    assert status == 200 and doc["forgotten"] is True
    srv.shutdown()
    Path(path).unlink(missing_ok=True)


def test_put_refuses_a_room_without_its_bridge_port(table) -> None:
    # Without the host-side port the room is not in @ports, so the guard that
    # binds its source IP and MAC skips it and a raw-socket room could send as
    # another room. Refuse the room instead (the API then removes the guest).
    table.fake.add("d" * 64, "10.214.0.9", port=None)
    with pytest.raises(RuntimeError):
        table.put("d" * 64, "sbx_9", eg.Policy.parse({"mode": "internet"}))
    assert table.policy_of("10.214.0.9") is None


@pytest.mark.parametrize("bad", ["169.254.169.254/32", "127.0.0.1", "10.0.0.0/8", "0.0.0.0/0"])
def test_policy_refuses_non_public_ranges(bad) -> None:
    with pytest.raises(ValueError):
        eg.Policy.parse({"mode": "allowlist", "allow": [bad]})


def test_known_bridges_drop_unbound_ports_and_ipv6() -> None:
    # A room port with no policy yet used to pass the guard ("return"): with
    # raw sockets a new room could send as a neighbour until apply() bound it.
    runner = Runner()
    rules = eg.Rules("room-test", ["10.214.0.0/22"], 15353, 15080, 15443, run=runner, bridges=["rmbr0", "rmnet0"])
    base = rules.base([])
    guard = base[base.index("chain room_guard"):]
    assert 'meta ibrname != { "rmbr0", "rmnet0" } return' in guard
    assert "iifname != @ports drop" in guard and "iifname != @ports return" not in guard
    assert guard.index("ether type ip6 drop") < guard.index("iifname . ether saddr != @bound_mac drop")
    # Without bridge names (older callers) the guard stays open to unknown ports but still drops IPv6.
    old = eg.Rules("room-test", ["10.214.0.0/22"], 15353, 15080, 15443, run=runner).base([])
    assert "iifname != @ports return" in old and "ether type ip6 drop" in old


def test_room_bridges_follow_room_net_sh_names() -> None:
    env = {"ROOM_BRIDGE": "rmbr0", "ROOM_NETS": "10.214.0.0/22 10.214.4.0/22"}
    assert eg.room_bridges(env) == ["rmbr0", "rmnet0", "rmnet1"]
    assert eg.room_bridges({"ROOM_BRIDGE": "rmbr0"}) == ["rmbr0"]


def test_proxy_admits_a_bounded_number_of_connections_per_room(table) -> None:
    proxy = eg.Proxy(table, per_room_max=2)
    assert proxy.admit("10.214.0.2") and proxy.admit("10.214.0.2")
    assert not proxy.admit("10.214.0.2")
    assert proxy.admit("10.214.0.3")  # another room is not affected
    proxy.release("10.214.0.2")
    assert proxy.admit("10.214.0.2")


def test_room_net_sh_drops_ipv6_from_room_bridges() -> None:
    text = (Path(__file__).resolve().parents[1] / "room-kit" / "lib" / "room-net.sh").read_text()
    assert 'ip6tables -I FORWARD 1 -i "$br" -j DROP' in text and 'ip6tables -I INPUT 1 -i "$br" -j DROP' in text
    assert "ip6tables $rule" in text  # and down() removes them
