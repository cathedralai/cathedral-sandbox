"""Review round 6 (reader P): room egress daemon fixes of PR #312 that existed
only as helpers. The daemon's own wiring and the proxy's connection path are
driven here, not read. Each test failed on 22e7824."""
from __future__ import annotations

import asyncio

from tests.test_room_kit_egress import FakeDocker, Runner, eg


# ---------------------------------------------------------------- O8a: main wires the bridges

def test_the_daemon_rules_come_from_room_env_with_every_bridge() -> None:
    # The guard that drops frames from a port with no policy yet exists only
    # when the bridges are known. main() built Rules on one untested line;
    # the env it reads must yield that guard for the main bridge and every
    # room network bridge.
    env = {"ROOM_ID": "room-test", "ROOM_BRIDGE": "rmbr0", "ROOM_BRIDGE_CIDR": "10.213.0.1/21",
           "ROOM_NETS": "10.214.0.0/22 10.214.4.0/22"}
    rules = eg.rules_for(env, (15353, 15080, 15443), run=Runner())
    assert rules.room_nets == ["10.213.0.0/21", "10.214.0.0/22", "10.214.4.0/22"]
    base = rules.base([])
    guard = base[base.index("chain room_guard"):]
    assert 'meta ibrname != { "rmbr0", "rmnet0", "rmnet1" } return' in guard
    assert "iifname != @ports drop" in guard and "iifname != @ports return" not in guard


# ---------------------------------------------------------------- O8b: handle() enforces the cap

class _Reader:
    """A room connection: readuntil waits for *gate* when one is given."""

    def __init__(self, data: bytes, gate: asyncio.Event | None = None):
        self.data, self.gate = data, gate

    async def readuntil(self, sep: bytes) -> bytes:
        if self.gate is not None:
            await self.gate.wait()
        return self.data


class _Writer:
    def __init__(self, ip: str):
        self.ip, self.writes, self.closed = ip, [], False

    def get_extra_info(self, key, default=None):
        return (self.ip, 40000) if key == "peername" else default

    def write(self, data: bytes) -> None:
        self.writes.append(bytes(data))

    def close(self) -> None:
        self.closed = True


def test_proxy_handle_answers_429_past_the_per_room_cap_and_frees_the_slot(tmp_path, monkeypatch) -> None:
    # admit() and release() existed as helpers only. handle() is the path a
    # room's connection takes: it must take a slot before it reads and give
    # the slot back when it ends, or the cap never holds.
    monkeypatch.setattr(eg, "flush_conntrack", lambda ip: None)
    table = eg.Table(eg.Rules("room-test", ["10.214.0.0/22"], 15353, 15080, 15443, run=Runner()), FakeDocker(),
                     str(tmp_path / "state.json"))
    table.load()
    proxy = eg.Proxy(table)
    proxy.per_room_max = 1
    ip = "10.214.0.2"
    head = b"GET / HTTP/1.1\r\nHost: pypi.org\r\n\r\n"

    async def scenario():
        gate = asyncio.Event()
        first_w, second_w = _Writer(ip), _Writer(ip)
        first = asyncio.ensure_future(proxy.handle(_Reader(head, gate), first_w, 80, False))
        for _ in range(5):
            await asyncio.sleep(0)  # the first connection is now inside its read
        await proxy.handle(_Reader(head), second_w, 80, False)
        gate.set()
        await first
        return first_w, second_w

    first_w, second_w = asyncio.run(scenario())
    answers = [w.writes[0][:12] for w in (first_w, second_w) if w.writes]
    assert answers.count(b"HTTP/1.1 429") == 1, answers
    assert second_w.writes[0].startswith(b"HTTP/1.1 429") and second_w.closed
    assert first_w.writes[0].startswith(b"HTTP/1.1 403")  # no policy for this room: refused, not capped
    assert getattr(proxy, "pending", {}).get(ip, 0) == 0
