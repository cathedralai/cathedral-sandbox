#!/usr/bin/env python3
"""Room kit: per-room egress policy, enforced outside the rooms.

This daemon runs as root on the hotel (on a sealed hotel: inside the SEV-SNP
guest, so the host cannot change the rules). A room cannot change it: the
rules and the resolver live in the hotel's network stack, not in the room.

Policies (one per room, by the room's bridge address):
  internet   all egress (the room-net.sh rules still drop private ranges)
  deny_all   no egress; DNS answers REFUSED
  allowlist  IPv4 addresses and CIDRs: every port, by nftables
             hostnames and *.wildcards: TCP 80 and 443 only, through the
             hotel egress proxy, which reads the TLS SNI or the HTTP Host,
             checks it against the room's list, resolves the name itself and
             connects to that answer only. DNS answers allowed names only.

Why a proxy and not only DNS plus address sets: many allowed names share
CDN addresses with names that are not allowed. An address set filled from
DNS answers would open those other names too. The proxy connects to the
address of the name the room asked for, so a room cannot reach a name that
is not on its list, even when it uses an allowed address.

Deny by default: a room address that has no policy here has no egress. The
sandbox API (unprivileged) sends each room's policy over the control socket
after the room starts, and on every live switch. Each change is one nftables
transaction. On a switch, open proxy connections that the new policy does not
allow are closed, and conntrack entries of the room are deleted.

Each room is also bound to its bridge port: frames from the port must carry
the room's MAC and address (bridge table), so a room with raw sockets
(runsc --net-raw) cannot take another room's address and its policy.

Control socket (HTTP over a Unix socket, group of the API user):
  PUT    /rooms/<container_id>  {"sandbox_id": str, "policy": {"mode", "allow"}}
  DELETE /rooms/<container_id>
  GET    /rooms                  the table
  GET    /health
Settings come from the resolved room.env (ROOM_ID, ROOM_BRIDGE_CIDR, ROOM_NETS,
ROOM_DNS, ROOM_RUN) and these optional environment variables:
  ROOM_EGRESS_SOCKET (default /run/pool-room-egress/control.sock)
  ROOM_EGRESS_GROUP  (default poolroom)
  ROOM_EGRESS_DNS_PORT, ROOM_EGRESS_HTTP_PORT, ROOM_EGRESS_TLS_PORT
  (default 15353, 15080, 15443)
"""
from __future__ import annotations

import asyncio
import grp
import hashlib
import ipaddress
import json
import os
import re
import shlex
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, UnixStreamServer
from typing import Callable

IP_FREEBIND = 15
DNS_PORT_DEFAULT, HTTP_PORT_DEFAULT, TLS_PORT_DEFAULT = 15353, 15080, 15443
MAX_ALLOW = 256
HOST_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


# ---------------------------------------------------------------- policy

def canonical(doc) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def policy_sha256(policy: dict) -> str:
    return hashlib.sha256(canonical(policy)).hexdigest()


def classify(entry: str) -> tuple[str, str]:
    """("cidr", "1.2.3.0/24") | ("host", "pypi.org") | ("wild", "example.com").

    Same rules as cathedral.sandbox_api.normalize_allow_entry; the daemon
    checks again because it is the enforcement point. Optional ``:80`` / ``:443``
    on a hostname is accepted and stripped (proxy only offers those ports).
    """
    if not isinstance(entry, str) or not entry or len(entry) > 255:
        raise ValueError(f"bad allowlist entry {entry!r}")
    value = entry.strip().lower().rstrip(".")
    if value.count(":") == 1 and "/" not in value and not value.startswith("["):
        host_part, port_part = value.rsplit(":", 1)
        if port_part.isdigit():
            port = int(port_part)
            if not 1 <= port <= 65535:
                raise ValueError(f"bad allowlist entry {entry!r}")
            try:
                ipaddress.ip_address(host_part)
            except ValueError:
                if port not in (80, 443):
                    raise ValueError(
                        f"named hosts only allow TCP 80 and 443: {entry!r}"
                    ) from None
                value = host_part
            else:
                raise ValueError(
                    f"use a bare IPv4/CIDR (all ports) or a hostname:80|:443: {entry!r}"
                )
    try:
        # "1.2.3.4" stays an address, "1.2.3.4/8" becomes "1.0.0.0/8".
        net = ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value)
    except ValueError:
        net = None
    if net is not None:
        if net.version != 4:
            raise ValueError(f"IPv6 is not supported: {entry!r}")
        return "cidr", str(net)
    if ":" in value or "/" in value:
        raise ValueError(f"bad allowlist entry {entry!r}")
    wild = value.startswith("*.")
    name = value[2:] if wild else value
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(HOST_LABEL.match(x) for x in labels) or labels[-1].isdigit():
        raise ValueError(f"bad allowlist entry {entry!r}")
    return ("wild", name) if wild else ("host", name)


@dataclass(frozen=True)
class Policy:
    mode: str
    allow: tuple[str, ...] = ()
    hosts: frozenset = frozenset()
    wilds: tuple[str, ...] = ()
    nets: tuple[str, ...] = ()

    @classmethod
    def parse(cls, doc: dict) -> "Policy":
        mode = doc.get("mode")
        allow = doc.get("allow") or []
        if mode not in ("internet", "deny_all", "allowlist"):
            raise ValueError(f"mode must be internet, deny_all or allowlist, not {mode!r}")
        if not isinstance(allow, list) or len(allow) > MAX_ALLOW:
            raise ValueError("allow must be a list of at most 256 entries")
        if mode != "allowlist":
            if allow:
                raise ValueError(f"mode {mode} takes no allow entries")
            return cls(mode=mode)
        if not allow:
            raise ValueError("allowlist mode needs at least one entry")
        hosts, wilds, nets = set(), set(), set()
        for entry in allow:
            kind, value = classify(entry)
            {"host": hosts, "wild": wilds, "cidr": nets}[kind].add(value)
        canon = sorted(hosts | {"*." + w for w in wilds} | nets)
        collapsed = tuple(str(n) for n in ipaddress.collapse_addresses(ipaddress.ip_network(x) for x in nets))
        return cls(mode=mode, allow=tuple(canon), hosts=frozenset(hosts), wilds=tuple(sorted(wilds)), nets=collapsed)

    def document(self) -> dict:
        return {"mode": self.mode, "allow": list(self.allow)}

    @property
    def named(self) -> bool:
        return bool(self.hosts or self.wilds)

    def allows_name(self, name: str) -> bool:
        if self.mode != "allowlist":
            return False
        name = name.strip().lower().rstrip(".")
        if name in self.hosts:
            return True
        return any(name.endswith("." + w) for w in self.wilds)


@dataclass
class Room:
    container_id: str
    sandbox_id: str
    ip: str
    mac: str
    port: str | None
    policy: Policy
    applied_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------- nftables

def nft_name(room_id: str) -> str:
    return "pool_room_egress_" + re.sub(r"[^A-Za-z0-9]", "_", room_id)


class Rules:
    """The nftables tables of this hotel. All changes go through apply()."""

    def __init__(self, room_id: str, room_nets: list[str], dns_port: int, http_port: int, tls_port: int,
                 run: Callable[[str], None] | None = None):
        self.table = nft_name(room_id)
        self.room_nets = room_nets
        self.ports = (dns_port, http_port, tls_port)
        self.run = run or self._nft

    @staticmethod
    def _nft(script: str) -> None:
        r = subprocess.run(["nft", "-f", "-"], input=script, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise RuntimeError(f"nft failed: {r.stderr.strip()[:500]}")

    def base(self, rooms: list[Room]) -> str:
        """Replace both tables in one transaction, with the elements of *rooms*."""
        dns, http, tls = self.ports
        t = self.table
        nets = ", ".join(self.room_nets)
        lines = [
            f"table ip {t} {{}}", f"delete table ip {t}",
            f"table bridge {t} {{}}", f"delete table bridge {t}",
            f"table ip {t} {{",
            f"  set rooms {{ type ipv4_addr; flags interval; elements = {{ {nets} }} }}",
            "  set open { type ipv4_addr; }",
            "  set named { type ipv4_addr; }",
            "  set allow { type ipv4_addr . ipv4_addr; flags interval; }",
            "  chain room_prerouting {",
            "    type nat hook prerouting priority dstnat - 5; policy accept;",
            "    ip saddr != @rooms return",
            "    ip saddr @open return",
            "    ip saddr . ip daddr @allow return",
            f"    meta l4proto {{ tcp, udp }} th dport 53 redirect to :{dns}",
            f"    ip saddr @named tcp dport 443 redirect to :{tls}",
            f"    ip saddr @named tcp dport 80 redirect to :{http}",
            "  }",
            "  chain room_forward {",
            "    type filter hook forward priority filter - 5; policy accept;",
            "    ip saddr != @rooms return",
            "    ip saddr @open return",
            "    ip saddr . ip daddr @allow return",
            "    counter drop",
            "  }",
            "}",
            f"table bridge {t} {{",
            "  set ports { type ifname; }",
            "  set bound { type ifname . ipv4_addr; }",
            "  set bound_mac { type ifname . ether_addr; }",
            "  chain room_guard {",
            "    type filter hook prerouting priority -300; policy accept;",
            "    iifname != @ports return",
            "    iifname . ether saddr != @bound_mac drop",
            "    ether type ip iifname . ip saddr != @bound drop",
            "    ether type arp iifname . arp saddr ip != @bound drop",
            "  }",
            "}",
        ]
        for room in rooms:
            lines += self.elements("add", room)
        return "\n".join(lines) + "\n"

    def elements(self, verb: str, room: Room) -> list[str]:
        t, ip, p = self.table, room.ip, room.policy
        out: list[str] = []
        if p.mode == "internet":
            out.append(f"{verb} element ip {t} open {{ {ip} }}")
        if p.mode == "allowlist":
            if p.named:
                out.append(f"{verb} element ip {t} named {{ {ip} }}")
            if p.nets:
                out.append(f"{verb} element ip {t} allow {{ " + ", ".join(f"{ip} . {n}" for n in p.nets) + " }")
        if room.port:
            port = json.dumps(room.port)
            out.append(f"{verb} element bridge {t} ports {{ {port} }}")
            out.append(f"{verb} element bridge {t} bound {{ {port} . {ip} }}")
            out.append(f"{verb} element bridge {t} bound_mac {{ {port} . {room.mac} }}")
        return out

    def install(self, rooms: list[Room]) -> None:
        self.run(self.base(rooms))

    def change(self, old: Room | None, new: Room | None) -> None:
        lines = (self.elements("delete", old) if old else []) + (self.elements("add", new) if new else [])
        if lines:
            self.run("\n".join(lines) + "\n")


# ---------------------------------------------------------------- docker facts

def sh(argv: list[str], timeout: float = 30) -> str:
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"{shlex.join(argv[:4])}: {r.stderr.strip()[:300]}")
    return r.stdout


class Docker:
    def __init__(self, sock: str):
        self.base = ["docker", "-H", "unix://" + sock]

    def facts(self, container_id: str) -> tuple[str, str, str | None]:
        """(ip, mac, host-side port name) of a running container with one network."""
        fmt = ("{{.State.Running}} {{.NetworkSettings.SandboxKey}}"
               "{{range .NetworkSettings.Networks}} {{.IPAddress}} {{.MacAddress}}{{end}}")
        parts = sh(self.base + ["inspect", "--format", fmt, container_id]).split()
        if len(parts) < 4 or parts[0] != "true" or not parts[2]:
            raise RuntimeError(f"container {container_id[:12]} is not running with one network")
        netns, ip, mac = parts[1], parts[2], parts[3]
        ipaddress.IPv4Address(ip)
        port = None
        try:
            link = sh(["nsenter", "--net=" + netns, "ip", "-o", "link", "show", "eth0"])
            m = re.search(r"eth0@if(\d+):", link)
            if m:
                for line in sh(["ip", "-o", "link", "show"]).splitlines():
                    if line.startswith(m.group(1) + ":"):
                        port = line.split(":")[1].strip().split("@")[0]
                        break
        except (RuntimeError, subprocess.SubprocessError, OSError):
            port = None
        return ip, mac, port

    def running(self) -> set[str]:
        return set(sh(self.base + ["ps", "-q", "--no-trunc"]).split())


# ---------------------------------------------------------------- state

class Table:
    """Rooms by address and by container. One lock for every change."""

    def __init__(self, rules: Rules, docker: Docker, state_path: str | None, on_change=None):
        self.rules, self.docker, self.state_path = rules, docker, state_path
        self.lock = threading.Lock()
        self.by_ip: dict[str, Room] = {}
        self.by_cid: dict[str, Room] = {}
        self.on_change = on_change or (lambda room: None)

    def load(self) -> None:
        rooms: list[Room] = []
        if self.state_path and os.path.exists(self.state_path):
            try:
                with open(self.state_path) as f:
                    for d in json.load(f):
                        rooms.append(Room(d["container_id"], d["sandbox_id"], d["ip"], d["mac"], d.get("port"),
                                          Policy.parse(d["policy"]), d.get("applied_at", time.time())))
            except (OSError, ValueError, KeyError) as exc:
                print(f"room-egress: state not loaded: {exc}", file=sys.stderr, flush=True)
                rooms = []
        if rooms:
            # After a room daemon restart the old rooms are gone; their
            # addresses must not carry a policy to new rooms.
            try:
                running = self.docker.running()
                rooms = [r for r in rooms if r.container_id in running]
            except (RuntimeError, subprocess.SubprocessError, OSError):
                rooms = []
        with self.lock:
            self.rules.install(rooms)
            self.by_ip = {r.ip: r for r in rooms}
            self.by_cid = {r.container_id: r for r in rooms}

    def save(self) -> None:
        if not self.state_path:
            return
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump([{"container_id": r.container_id, "sandbox_id": r.sandbox_id, "ip": r.ip, "mac": r.mac,
                        "port": r.port, "policy": r.policy.document(), "applied_at": r.applied_at}
                       for r in self.by_cid.values()], f)
        os.replace(tmp, self.state_path)

    def put(self, container_id: str, sandbox_id: str, policy: Policy) -> Room:
        ip, mac, port = self.docker.facts(container_id)
        if not port:
            # Without the host-side port the room is not in @ports, so the
            # guard that binds its source IP and MAC would skip it and a
            # raw-socket room could send as another room. Fail closed: the
            # API removes a guest whose policy cannot be applied.
            raise RuntimeError(f"container {container_id[:12]}: bridge port not found, room not admitted")
        with self.lock:
            old = self.by_cid.get(container_id)
            stale = self.by_ip.get(ip)
            new = Room(container_id, sandbox_id, ip, mac, port, policy)
            # A stale room on the same address (container gone, not yet
            # reaped) loses its elements in the same transaction.
            dropped = [r for r in (old, stale) if r is not None]
            lines: list[str] = []
            seen = set()
            for r in dropped:
                if id(r) not in seen:
                    seen.add(id(r))
                    lines += self.rules.elements("delete", r)
            lines += self.rules.elements("add", new)
            for r in dropped:
                self.by_cid.pop(r.container_id, None)
                self.by_ip.pop(r.ip, None)
            self._run(lines)
            self.by_cid[container_id] = new
            self.by_ip[ip] = new
            self.save()
        self.on_change(new)
        flush_conntrack(ip)
        return new

    def forget(self, container_id: str) -> bool:
        with self.lock:
            room = self.by_cid.pop(container_id, None)
            if room is None:
                return False
            self.by_ip.pop(room.ip, None)
            self._run(self.rules.elements("delete", room))
            self.save()
        self.on_change(Room(room.container_id, room.sandbox_id, room.ip, room.mac, room.port, Policy("deny_all")))
        flush_conntrack(room.ip)
        return True

    def _run(self, lines: list[str]) -> None:
        """Run one element transaction. If the kernel table drifted from this
        table (an element is missing), install the whole table again from
        memory, which is the source of truth. Caller holds the lock."""
        if not lines:
            return
        try:
            self.rules.run("\n".join(lines) + "\n")
        except RuntimeError as exc:
            print(f"room-egress: element change failed, reinstalling the table: {exc}", file=sys.stderr, flush=True)
            raise_again = [r for r in lines if r.startswith("add ")]
            self.rules.install(list(self.by_cid.values()))
            if raise_again:
                # The new room is not in by_cid yet: add it now.
                self.rules.run("\n".join(raise_again) + "\n")

    def policy_of(self, ip: str) -> Policy | None:
        room = self.by_ip.get(ip)
        return room.policy if room else None

    def reconcile(self) -> int:
        """Drop rooms whose container no longer runs."""
        running = self.docker.running()
        gone = [cid for cid in list(self.by_cid) if cid not in running]
        for cid in gone:
            self.forget(cid)
        return len(gone)


def flush_conntrack(ip: str) -> None:
    """Delete the room's conntrack entries, so a flow that started under the
    old policy (for example a DNS socket to a public resolver) cannot go on
    under the new one. Best effort: needs the conntrack tool."""
    for flag in ("-s", "-d"):
        try:
            subprocess.run(["conntrack", "-D", flag, ip], capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return


# ---------------------------------------------------------------- DNS

def dns_question(msg: bytes) -> tuple[str, int, int]:
    """(qname, qtype, end offset of the question) of a query."""
    if len(msg) < 12 or struct.unpack("!H", msg[4:6])[0] != 1:
        raise ValueError("one question expected")
    labels, i = [], 12
    while True:
        n = msg[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0:
            raise ValueError("compressed question")
        labels.append(msg[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
        if i > 270:
            raise ValueError("name too long")
    qtype = struct.unpack("!H", msg[i:i + 2])[0]
    return ".".join(labels).lower(), qtype, i + 4


def dns_reply(query: bytes, end: int, rcode: int) -> bytes:
    """A reply with no answer: the query id, the question, and *rcode*."""
    qid, flags = struct.unpack("!HH", query[:4])
    flags = 0x8000 | (flags & 0x7900) | 0x0080 | rcode  # QR, opcode+RD kept, RA
    return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + query[12:end]


NXDOMAIN, REFUSED, SERVFAIL = 3, 5, 2


class Resolver:
    def __init__(self, table: Table, upstream: list[str]):
        self.table, self.upstream = table, upstream

    def decide(self, ip: str, query: bytes) -> bytes | None:
        """A local answer, b"" to drop a malformed query, or None to forward it upstream."""
        try:
            name, _qtype, end = dns_question(query)
        except (ValueError, IndexError, struct.error):
            return b""
        policy = self.table.policy_of(ip)
        if policy is None or policy.mode == "deny_all":
            return dns_reply(query, end, REFUSED)
        if policy.mode == "internet" or policy.allows_name(name):
            return None
        return dns_reply(query, end, NXDOMAIN)

    async def forward(self, query: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        for server in self.upstream:
            fut: asyncio.Future = loop.create_future()

            class Once(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if not fut.done():
                        fut.set_result(data)

                def error_received(self, exc):
                    if not fut.done():
                        fut.set_exception(exc)

            transport, _ = await loop.create_datagram_endpoint(Once, remote_addr=(server, 53))
            try:
                transport.sendto(query)
                return await asyncio.wait_for(fut, 3.0)
            except (asyncio.TimeoutError, OSError):
                continue
            finally:
                transport.close()
        _, _, end = dns_question(query)
        return dns_reply(query, end, SERVFAIL)

    async def answer(self, ip: str, query: bytes) -> bytes:
        local = self.decide(ip, query)
        if local == b"":
            return b""
        return local if local is not None else await self.forward(query)


class DNSUDP(asyncio.DatagramProtocol):
    def __init__(self, resolver: Resolver):
        self.resolver = resolver

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        async def go():
            out = await self.resolver.answer(addr[0], data)
            if out:
                self.transport.sendto(out, addr)
        asyncio.ensure_future(go())


async def dns_tcp(resolver: Resolver, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    ip = writer.get_extra_info("peername")[0]
    try:
        while True:
            head = await asyncio.wait_for(reader.readexactly(2), 30)
            query = await reader.readexactly(struct.unpack("!H", head)[0])
            out = await resolver.answer(ip, query)
            if not out:
                break
            writer.write(struct.pack("!H", len(out)) + out)
            await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        writer.close()


# ---------------------------------------------------------------- proxy

def tls_sni(hello: bytes) -> str | None:
    """The server name from a TLS ClientHello handshake message, or None."""
    try:
        if hello[0] != 1:
            return None
        i = 4 + 2 + 32
        i += 1 + hello[i]
        i += 2 + struct.unpack("!H", hello[i:i + 2])[0]
        i += 1 + hello[i]
        end = i + 2 + struct.unpack("!H", hello[i:i + 2])[0]
        i += 2
        while i + 4 <= end:
            etype, elen = struct.unpack("!HH", hello[i:i + 4])
            i += 4
            if etype == 0:
                j = i + 2
                while j + 3 <= i + elen:
                    ntype, nlen = hello[j], struct.unpack("!H", hello[j + 1:j + 3])[0]
                    if ntype == 0:
                        return hello[j + 3:j + 3 + nlen].decode("ascii").lower()
                    j += 3 + nlen
                return None
            i += elen
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None


async def read_client_hello(reader: asyncio.StreamReader) -> tuple[bytes, bytes]:
    """(raw bytes read, handshake message). Reads TLS records until the whole
    ClientHello is in hand (it may span records)."""
    raw, hs = b"", b""
    while True:
        head = await reader.readexactly(5)
        if head[0] != 22:
            raise ValueError("not a TLS handshake")
        body = await reader.readexactly(struct.unpack("!H", head[3:5])[0])
        raw += head + body
        hs += body
        if len(hs) >= 4:
            need = 4 + int.from_bytes(hs[1:4], "big")
            if need > 65536:
                raise ValueError("ClientHello too large")
            if len(hs) >= need:
                return raw, hs[:need]


async def read_http_head(reader: asyncio.StreamReader) -> tuple[bytes, str | None]:
    raw = await reader.readuntil(b"\r\n\r\n")
    if len(raw) > 32768:
        raise ValueError("header too large")
    host = None
    for line in raw.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"host":
            host = v.strip().decode("ascii", "replace").lower()
            if host.startswith("["):
                return raw, None
            host = host.rsplit(":", 1)[0] if ":" in host else host
            break
    return raw, host


def public_ipv4(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return ip.version == 4 and ip.is_global


async def resolve_ipv4(name: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(name, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
    return [i[4][0] for i in infos]


class Proxy:
    def __init__(self, table: Table, resolve=resolve_ipv4, addr_ok=public_ipv4):
        self.table = table
        self.resolve, self.addr_ok = resolve, addr_ok
        self.lock = threading.Lock()
        self.active: dict[str, set] = {}  # room ip -> {(name, writer, upstream writer)}

    def recheck(self, room: Room) -> None:
        """After a policy change, close this room's connections the new policy does not allow."""
        with self.lock:
            conns = list(self.active.get(room.ip, ()))
        for item in conns:
            name, w1, w2 = item
            if not room.policy.allows_name(name):
                for w in (w1, w2):
                    try:
                        w.transport.abort()
                    except Exception:  # noqa: BLE001 - closing is best effort
                        pass

    async def handle(self, reader, writer, port: int, tls: bool):
        ip = writer.get_extra_info("peername")[0]
        up_w = None
        try:
            if tls:
                first, hello = await asyncio.wait_for(read_client_hello(reader), 15)
                name = tls_sni(hello)
            else:
                first, name = await asyncio.wait_for(read_http_head(reader), 15)
            policy = self.table.policy_of(ip)
            if not name or policy is None or not policy.allows_name(name):
                if not tls:
                    writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            # Connect to the address of the name the room asked for, never to
            # the address the room used. No private or local answers.
            addrs = [a for a in await self.resolve(name, port) if self.addr_ok(a)]
            if not addrs:
                return
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(addrs[0], port), 15)
            item = (name, writer, up_w)
            with self.lock:
                self.active.setdefault(ip, set()).add(item)
            try:
                # A switch between the policy read and the registration above
                # is caught here.
                if not (self.table.policy_of(ip) or Policy("deny_all")).allows_name(name):
                    return
                up_w.write(first)
                await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))
            finally:
                with self.lock:
                    self.active.get(ip, set()).discard(item)
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError):
            pass
        finally:
            for w in (writer, up_w):
                if w is not None:
                    try:
                        w.close()
                    except Exception:  # noqa: BLE001
                        pass


async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (OSError, asyncio.CancelledError):
        pass
    finally:
        try:
            dst.write_eof()
        except (OSError, RuntimeError):
            pass


# ---------------------------------------------------------------- control socket

class Control(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "room-egress"

    def log_message(self, *args):
        pass

    def address_string(self):
        return "control"

    def reply(self, status: int, doc) -> None:
        body = canonical(doc)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        table: Table = self.server.table
        if self.path == "/health":
            return self.reply(200, {"status": "ok", "rooms": len(table.by_cid)})
        if self.path == "/rooms":
            with table.lock:
                rooms = [{"container_id": r.container_id, "sandbox_id": r.sandbox_id, "ip": r.ip, "port": r.port,
                          "policy": r.policy.document(), "policy_sha256": policy_sha256(r.policy.document()),
                          "applied_at": r.applied_at} for r in table.by_cid.values()]
            return self.reply(200, {"rooms": rooms})
        return self.reply(404, {"error": {"code": "not_found", "message": self.path}})

    def do_PUT(self):
        m = re.fullmatch(r"/rooms/([0-9a-f]{12,64})", self.path)
        if not m:
            return self.reply(404, {"error": {"code": "not_found", "message": self.path}})
        try:
            doc = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            policy = Policy.parse(doc.get("policy") or {})
        except (ValueError, AttributeError) as exc:
            return self.reply(400, {"error": {"code": "invalid_policy", "message": str(exc)}})
        try:
            room = self.server.table.put(m.group(1), str(doc.get("sandbox_id") or ""), policy)
        except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as exc:
            return self.reply(502, {"error": {"code": "apply_failed", "message": str(exc)[:400]}})
        pdoc = room.policy.document()
        return self.reply(200, {"container_id": room.container_id, "ip": room.ip, "port_bound": room.port is not None,
                                "policy": pdoc, "policy_sha256": policy_sha256(pdoc),
                                "applied_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(room.applied_at))})

    def do_DELETE(self):
        m = re.fullmatch(r"/rooms/([0-9a-f]{12,64})", self.path)
        if not m:
            return self.reply(404, {"error": {"code": "not_found", "message": self.path}})
        try:
            found = self.server.table.forget(m.group(1))
        except (RuntimeError, OSError) as exc:
            return self.reply(502, {"error": {"code": "apply_failed", "message": str(exc)[:400]}})
        return self.reply(200, {"forgotten": found})


class ControlServer(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True


# ---------------------------------------------------------------- main

def read_env(path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    with open(path) as f:
        for line in f:
            k, sep, v = line.strip().partition("=")
            if sep and re.fullmatch(r"[A-Z_][A-Z0-9_]*", k):
                out[k] = v.strip().strip('"')
    return out


def room_networks(env: dict[str, str]) -> list[tuple[str, str]]:
    """(network CIDR, gateway address) of the main bridge and every room network."""
    main = ipaddress.ip_interface(env["ROOM_BRIDGE_CIDR"])
    out = [(str(main.network), str(main.ip))]
    for cidr in env.get("ROOM_NETS", "").split():
        net = ipaddress.ip_network(cidr, strict=False)
        out.append((str(net), str(net.network_address + 1)))
    return out


def bound_socket(kind: int, addr: str, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, kind)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_IP, IP_FREEBIND, 1)  # the bridge may not exist yet
    s.bind((addr, port))
    s.setblocking(False)
    return s


async def serve(table: Table, proxy: Proxy, resolver: Resolver, gateways: list[str], ports: tuple[int, int, int]):
    loop = asyncio.get_running_loop()
    dns_port, http_port, tls_port = ports
    for gw in gateways:
        await loop.create_datagram_endpoint(lambda: DNSUDP(resolver), sock=bound_socket(socket.SOCK_DGRAM, gw, dns_port))
        for port, handler in ((dns_port, lambda r, w: dns_tcp(resolver, r, w)),
                              (http_port, lambda r, w: proxy.handle(r, w, 80, False)),
                              (tls_port, lambda r, w: proxy.handle(r, w, 443, True))):
            s = bound_socket(socket.SOCK_STREAM, gw, port)
            s.listen(1024)
            await asyncio.start_server(handler, sock=s, limit=65536)
    while True:
        await asyncio.sleep(15)
        try:
            await loop.run_in_executor(None, table.reconcile)
        except Exception as exc:  # noqa: BLE001 - keep serving; log and retry next tick
            print(f"room-egress: reconcile failed: {exc}", file=sys.stderr, flush=True)


def main() -> int:
    env = read_env(os.environ.get("ROOM_ENV", "/etc/pool-room/room.env"))
    ports = (int(os.environ.get("ROOM_EGRESS_DNS_PORT", DNS_PORT_DEFAULT)),
             int(os.environ.get("ROOM_EGRESS_HTTP_PORT", HTTP_PORT_DEFAULT)),
             int(os.environ.get("ROOM_EGRESS_TLS_PORT", TLS_PORT_DEFAULT)))
    nets = room_networks(env)
    sock_path = os.environ.get("ROOM_EGRESS_SOCKET", "/run/pool-room-egress/control.sock")
    run_dir = os.path.dirname(sock_path)
    os.makedirs(run_dir, mode=0o750, exist_ok=True)
    rules = Rules(env["ROOM_ID"], [n for n, _ in nets], *ports)
    docker = Docker(os.environ.get("ROOM_DOCKER_SOCK", "/run/pool-room/docker.sock"))
    proxy_box: list[Proxy] = []
    table = Table(rules, docker, os.path.join(run_dir, "state.json"),
                  on_change=lambda room: proxy_box and proxy_box[0].recheck(room))
    table.load()
    proxy = Proxy(table)
    proxy_box.append(proxy)
    resolver = Resolver(table, env.get("ROOM_DNS", "1.1.1.1").split())
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    ctl = ControlServer(sock_path, Control)
    ctl.table = table
    group = os.environ.get("ROOM_EGRESS_GROUP", "poolroom")
    try:
        os.chown(sock_path, 0, grp.getgrnam(group).gr_gid)
        os.chown(run_dir, 0, grp.getgrnam(group).gr_gid)
    except KeyError:
        pass
    os.chmod(sock_path, 0o660)
    threading.Thread(target=ctl.serve_forever, daemon=True).start()
    print(f"room-egress: table {rules.table}, {len(table.by_cid)} rooms, networks {[n for n, _ in nets]}", flush=True)
    asyncio.run(serve(table, proxy, resolver, [gw for _, gw in nets], ports))
    return 0


if __name__ == "__main__":
    sys.exit(main())
