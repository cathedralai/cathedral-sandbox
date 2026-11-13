"""Unit tests for the Escape slot supervisor (AB#683). Fake guest, fake systemctl, no QEMU."""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC
from pathlib import Path

import pytest

TOOL_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "escape_slots" / "supervise_escape_slot.py"
)
_SPEC = importlib.util.spec_from_file_location("supervise_escape_slot", TOOL_PATH)
es = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
sys.modules[_SPEC.name] = es  # dataclasses look the module up by name
_SPEC.loader.exec_module(es)

MEASUREMENT = "ab" * 48


class FakeGuest:
    """Answers the three GET routes the supervisor reads, like room_receipts.py does."""

    def __init__(self) -> None:
        self.boot = 0
        self.up = True
        self.status = 200
        self.chain = 0
        self.rooms: list = []
        self.measurement = MEASUREMENT
        self.paths: list = []

    @property
    def binding(self) -> str:
        return f"{self.boot:064x}"

    def relaunch(self) -> None:
        self.boot += 1
        self.chain = 0
        self.rooms = []

    def fetch(self, path: str):
        self.paths.append(path)
        if not self.up:
            return None, None
        if self.status != 200:
            return self.status, None
        if path == "/room/receipts?limit=1":
            page = [{"statement": {"sequence": 1}}] if self.chain else []
            return 200, {"binding_sha256": self.binding, "head": "x", "count": len(page),
                         "receipts": page}
        if path == "/v1/sandboxes":
            return 200, {"sandboxes": list(self.rooms)}
        if path == "/room/attestation":
            return 200, {"binding": {"measurement": self.measurement},
                         "binding_sha256": self.binding}
        raise AssertionError(f"unexpected path {path}")


class FakeSystemctl:
    def __init__(self, guest: FakeGuest, scratch: Path) -> None:
        self.guest = guest
        self.scratch = scratch
        self.calls: list = []
        self.order: list = []
        self.active = "active"
        self.pid = 4242
        self.stop_works = True
        self.start_code = 0

    def __call__(self, args: list):
        self.calls.append(list(args))
        verb = args[0]
        if verb == "show":
            return 0, f"ActiveState={self.active}\nMainPID={self.pid}\n"
        self.order.append((verb, self.scratch.exists()))
        if verb == "stop" and self.stop_works:
            # systemctl stop leaves a failed unit failed until reset-failed
            self.active = "failed" if self.active == "failed" else "inactive"
            self.pid = 0
        elif verb == "start" and self.start_code == 0:
            self.active, self.pid = "active", 5000 + len(self.calls)
            self.guest.relaunch()
            self.scratch.write_bytes(b"")  # launch-guest.sh truncates a new one
        elif verb == "reset-failed":
            self.active = "inactive"
        return (self.start_code if verb == "start" else 0), ""

    def mutating(self) -> list:
        return [c[0] for c in self.calls if c[0] != "show"]


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def make_slot(tmp_path: Path, **extra) -> Path:
    sealed_dir = tmp_path / "slot"
    (sealed_dir / "run").mkdir(parents=True)
    (sealed_dir / "images" / "current").mkdir(parents=True)
    (sealed_dir / "images" / "current" / "expected-measurement").write_text(MEASUREMENT + "\n")
    (sealed_dir / "scratch.raw").write_bytes(b"old attempt")
    key = tmp_path / "hotel.key"
    key.write_text("k" * 32 + "\n")
    values = {"SEALED_NAME": "esc-slot-1", "SEALED_DIR": str(sealed_dir),
              "SEALED_API_KEY_FILE": str(key), "SEALED_DATA_GIB": "0", "SEALED_MINER": "0",
              "SEALED_TAP": "snp1", **extra}
    env = tmp_path / "sealed.env"
    env.write_text("# slot\n" + "".join(f"{k}={v}\n" for k, v in values.items()))
    return env


@pytest.fixture()
def rig(tmp_path: Path):
    env = make_slot(tmp_path)
    guest = FakeGuest()
    scratch = tmp_path / "slot" / "scratch.raw"
    systemctl = FakeSystemctl(guest, scratch)
    clock = Clock()
    lines: list = []
    sup = es.SlotSupervisor(sealed_env=env, fetch=guest.fetch, systemctl=systemctl,
                            clock=clock, out=lines.append)
    return sup, guest, systemctl, clock, lines


def poll(sup, clock, times=1, seconds=5.0):
    for _ in range(times):
        sup.step()
        clock.now += seconds


def transitions(lines):
    return [json.loads(x) for x in lines if x.startswith("{")]


def test_empty_chain_stays_fresh_and_is_never_restarted(rig):
    sup, _guest, systemctl, clock, lines = rig
    poll(sup, clock, times=500)
    assert sup.launch.state == "fresh"
    assert systemctl.mutating() == []
    fresh = [t for t in transitions(lines) if t.get("state") == "fresh"]
    assert fresh and fresh[0]["boot_seconds"] == 0.0


def test_used_guest_is_retired_stop_delete_start_in_order(rig, tmp_path):
    sup, guest, systemctl, clock, lines = rig
    (tmp_path / "slot" / "run" / "serial.log").write_text("[sealed-hotel] boot\n")
    poll(sup, clock)
    guest.chain, guest.rooms = 1, [{"id": "r1"}]
    poll(sup, clock, times=3)
    assert sup.launch.state == "in_use"
    assert systemctl.mutating() == []
    guest.rooms = []
    poll(sup, clock)
    assert systemctl.mutating() == []  # one empty poll is not enough
    poll(sup, clock)
    # stop while the old scratch exists, start after it was deleted
    assert systemctl.order == [("stop", True), ("start", False)]
    assert sup.launch.state == "booting"
    assert sup.launch.binding_sha256 is None
    assert (tmp_path / "slot" / "run" / "serial.prev.log").is_file()
    poll(sup, clock)
    assert sup.launch.state == "fresh"
    retire = [t for t in transitions(lines) if t.get("state") == "retiring"]
    assert retire[0]["reason"] == "attempt_ended"


def test_one_empty_poll_then_room_again_does_not_retire(rig):
    sup, guest, systemctl, clock, _ = rig
    poll(sup, clock)
    guest.chain, guest.rooms = 1, [{"id": "r1"}]
    poll(sup, clock)
    guest.rooms = []
    poll(sup, clock)
    guest.rooms = [{"id": "r1"}]
    poll(sup, clock, times=10)
    assert systemctl.mutating() == []
    assert sup.launch.state == "in_use"


def test_room_without_receipt_still_counts_as_used(rig):
    sup, guest, _systemctl, clock, _ = rig
    poll(sup, clock)
    guest.rooms = [{"id": "r1"}]
    poll(sup, clock)
    assert sup.launch.state == "in_use"


def test_room_that_never_ends_is_retired_after_its_expiry_and_gc_grace(rig):
    sup, guest, systemctl, clock, _ = rig
    poll(sup, clock)
    from datetime import datetime
    expiry = clock.now + 1800
    stamp = datetime.fromtimestamp(expiry, UTC).isoformat()
    guest.chain, guest.rooms = 1, [{"id": "r1", "expires_at": stamp}]
    poll(sup, clock)
    clock.now = expiry + es.ROOM_GC_GRACE_SECONDS  # within grace + margin
    poll(sup, clock)
    assert systemctl.mutating() == []
    clock.now = expiry + es.ROOM_GC_GRACE_SECONDS + es.ROOM_EXPIRY_MARGIN_SECONDS + 1
    poll(sup, clock)
    assert systemctl.mutating() == ["stop", "start"]


def test_heartbeat_moves_the_expiry_and_keeps_the_attempt(rig):
    sup, guest, systemctl, clock, _ = rig
    from datetime import datetime

    def iso(t):
        return datetime.fromtimestamp(t, UTC).isoformat()

    poll(sup, clock)
    guest.chain, guest.rooms = 1, [{"id": "r1", "expires_at": iso(clock.now + 600)}]
    poll(sup, clock)
    for _ in range(6):  # heartbeat every 10 min pushes expiry 10 min ahead
        clock.now += 600
        guest.rooms = [{"id": "r1", "expires_at": iso(clock.now + 600)}]
        poll(sup, clock)
    assert systemctl.mutating() == []


def test_hard_cap_retires_a_room_with_no_readable_expiry(rig):
    sup, guest, systemctl, clock, _ = rig
    poll(sup, clock)
    guest.chain, guest.rooms = 1, [{"id": "r1"}]
    poll(sup, clock)
    clock.now += 4 * 3600 + 1
    poll(sup, clock)
    assert systemctl.mutating() == ["stop", "start"]


def test_guest_that_never_answers_is_retired_and_three_failures_alert(rig):
    sup, guest, systemctl, clock, lines = rig
    guest.up = False
    systemctl.start_code = 0
    for _ in range(3):
        clock.now += 15 * 60 + 1
        sup.step()
        guest.up = False  # the relaunch does not answer either
    alerts = [x for x in lines if x.startswith("[OPERATOR-ALERT]")]
    assert any("boot_failing" in a for a in alerts)
    assert sup.hold_until > clock.now
    # Held: the third retire stopped the guest and dropped the scratch, but
    # did not start a new launch.
    assert systemctl.mutating()[-1] == "stop"
    assert sup.launch.state == "retiring"
    clock.now = sup.hold_until
    sup.step()
    assert systemctl.mutating()[-1] == "start"


def test_booting_guest_within_timeout_is_left_alone(rig):
    sup, guest, systemctl, clock, _ = rig
    guest.up = False
    poll(sup, clock, times=100)  # 500 s
    assert systemctl.mutating() == []
    assert sup.launch.state == "booting"


def test_fresh_guest_past_max_idle_age_is_retired(rig):
    sup, _guest, systemctl, clock, lines = rig
    poll(sup, clock)
    clock.now += 6 * 3600 + 1
    poll(sup, clock)
    assert systemctl.mutating() == ["stop", "start"]
    assert next(t for t in transitions(lines) if t.get("state") == "retiring")["reason"] == \
        "fresh_max_age"


def test_binding_change_marks_used_and_retires(rig):
    sup, guest, systemctl, clock, _ = rig
    poll(sup, clock)
    assert sup.launch.state == "fresh"
    guest.boot += 1  # receipts front restarted in the guest: empty chain, new binding
    poll(sup, clock)
    assert systemctl.mutating() == ["stop", "start"]


def test_transient_failure_keeps_in_use(rig):
    sup, guest, systemctl, clock, _ = rig
    poll(sup, clock)
    guest.chain, guest.rooms = 1, [{"id": "r1"}]
    poll(sup, clock)
    guest.up = False
    poll(sup, clock, times=200)  # 1000 s of failures, past nothing
    guest.up = True
    poll(sup, clock)
    assert sup.launch.state == "in_use"
    assert systemctl.mutating() == []


@pytest.mark.parametrize("status", [401, 403])
def test_refused_key_alerts_and_never_retires(rig, status):
    sup, guest, systemctl, clock, lines = rig
    guest.status = status
    for _ in range(3):
        clock.now += 20 * 60
        sup.step()
    assert systemctl.mutating() == []
    alerts = [x for x in lines if x.startswith("[OPERATOR-ALERT]")]
    assert len(alerts) == 1 and "guest_refused_key" in alerts[0]


def test_only_get_requests_reach_the_guest(rig):
    sup, guest, _systemctl, clock, _ = rig
    poll(sup, clock)
    guest.chain, guest.rooms = 1, [{"id": "r1"}]
    poll(sup, clock)
    guest.rooms = []
    poll(sup, clock, times=3)
    assert set(guest.paths) <= {"/room/receipts?limit=1", "/v1/sandboxes", "/room/attestation"}


def test_http_fetcher_sends_only_get_with_bearer(tmp_path, monkeypatch):
    key = tmp_path / "k"
    key.write_text(" secret \n")
    seen = []

    class Answer:
        status = 200

        def read(self):
            return b'{"ok": true}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(request, timeout):
        seen.append((request.get_method(), request.full_url, request.get_header("Authorization")))
        return Answer()

    monkeypatch.setattr(es.urllib.request, "urlopen", fake_urlopen)
    fetch = es.http_fetcher("http://10.215.0.2:18090/", key)
    assert fetch("/v1/sandboxes") == (200, {"ok": True})
    assert seen == [("GET", "http://10.215.0.2:18090/v1/sandboxes", "Bearer secret")]


def test_stop_that_leaves_the_unit_running_keeps_scratch(rig, tmp_path):
    sup, guest, systemctl, clock, _lines = rig
    poll(sup, clock)
    guest.chain, guest.rooms = 1, []
    systemctl.stop_works = False
    poll(sup, clock, times=2)
    assert (tmp_path / "slot" / "scratch.raw").read_bytes() == b"old attempt"
    assert "start" not in systemctl.mutating()
    assert sup.launch.state == "retiring"
    systemctl.stop_works = True
    poll(sup, clock)
    assert systemctl.mutating()[-1] == "start"


def test_failed_unit_is_reset_and_relaunched(rig):
    sup, _guest, systemctl, clock, _ = rig
    poll(sup, clock)
    systemctl.active, systemctl.pid = "failed", 0  # QEMU died
    poll(sup, clock)
    assert systemctl.mutating() == ["stop", "reset-failed", "start"]
    assert sup.launch.state == "booting"


def test_measurement_mismatch_alerts(rig):
    sup, guest, _systemctl, clock, lines = rig
    guest.measurement = "cd" * 48
    poll(sup, clock)
    assert any("measurement_mismatch" in x for x in lines)


def test_live_gate_blocks_mutating_systemctl(monkeypatch):
    monkeypatch.delenv(es.LIVE_ENV, raising=False)
    with pytest.raises(SystemExit, match=es.LIVE_ENV):
        es.live_systemctl(["stop", "room-sealed-esc-slot-1.service"])


@pytest.mark.parametrize(
    "extra, message",
    [({"SEALED_DATA_GIB": "10"}, "SEALED_DATA_GIB"),
     ({"SEALED_MINER": "1"}, "SEALED_MINER"),
     ({"SEALED_NAME": "Bad_Name"}, "SEALED_NAME"),
     ({"SEALED_TAP": "$TAP"}, "plain value")],
)
def test_slot_config_refusals(tmp_path, extra, message):
    with pytest.raises(SystemExit, match=message):
        es.load_slot(make_slot(tmp_path, **extra))


def test_data_volume_file_is_refused(tmp_path):
    env = make_slot(tmp_path)
    (tmp_path / "slot" / "data.raw").write_bytes(b"")
    with pytest.raises(SystemExit, match="data.raw"):
        es.load_slot(env)


def test_config_is_rechecked_before_every_launch(rig, tmp_path):
    sup, guest, systemctl, clock, _ = rig
    poll(sup, clock)
    guest.chain = 1
    env = tmp_path / "sealed.env"
    env.write_text(env.read_text().replace("SEALED_DATA_GIB=0", "SEALED_DATA_GIB=5"))
    with pytest.raises(SystemExit, match="SEALED_DATA_GIB"):
        poll(sup, clock, times=3)
    assert "start" not in systemctl.mutating()
