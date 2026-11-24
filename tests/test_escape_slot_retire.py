"""AB#683 fresh slot host side: the broker retire channel on the net-check unit and
the #496 supervisor that stops, scrubs and relaunches. Fake guest, fake systemctl,
fake broker; no QEMU, no network."""
from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

import pytest

from test_escape_slot_supervise import Clock, FakeGuest, FakeSystemctl, es, make_slot

ROOT = Path(__file__).resolve().parents[1]
WRITE_UNITS = ROOT / "scripts" / "escape_slots" / "write-escape-units.sh"


def report_id(boot: int) -> str:
    return f"{boot + 1:064x}"  # REPORT_ID is never all zeros


class AttestingGuest(FakeGuest):
    """FakeGuest whose attestation carries an SNP report with a per-launch REPORT_ID."""

    def fetch(self, path: str):
        status, doc = super().fetch(path)
        if path == "/room/attestation" and status == 200:
            report = bytearray(0x4A0)
            report[0x140:0x160] = bytes.fromhex(report_id(self.boot))
            doc["report_b64"] = base64.b64encode(bytes(report)).decode()
        return status, doc


class FakeBroker:
    """The broker's escape-retire route as escape_destroy.go answers it."""

    def __init__(self, slot: str) -> None:
        self.slot = slot
        self.retire: dict = {}
        self.confirmed: list = []
        self.calls: list = []
        self.up = True

    def __call__(self, method: str, path: str, body):
        self.calls.append((method, path))
        if not self.up:
            return None, None
        assert path == f"/v1/broker/hotels/{self.slot}/escape-retire"
        if method == "GET":
            items = [{"report_id": r, "binding_sha256": b} for r, b in self.retire.items()]
            return 200, {"schema": es.RETIRE_REQUEST_SCHEMA, "slot": self.slot, "retire": items}
        doc = json.loads(body)
        assert set(doc) == {"schema", "slot", "report_id", "binding_sha256", "state"}
        if self.retire.get(doc["report_id"]) != doc["binding_sha256"] or doc["state"] != "stopped":
            return 409, None
        self.confirmed.append(doc["report_id"])
        del self.retire[doc["report_id"]]
        return 200, dict(doc)


@pytest.fixture()
def slot_rig(tmp_path: Path):
    env = make_slot(tmp_path)
    guest = AttestingGuest()
    scratch = tmp_path / "slot" / "scratch.raw"
    systemctl = FakeSystemctl(guest, scratch)
    clock = Clock()
    lines: list = []
    sup = es.SlotSupervisor(sealed_env=env, fetch=guest.fetch, systemctl=systemctl, clock=clock,
                            out=lines.append)
    broker = FakeBroker(sup.slot.name)
    return sup, guest, systemctl, clock, broker, lines


def channel(sup, broker, wait=0.0):
    ticks = iter(range(10_000))
    return es.retire_channel(sup.slot, broker, wait_seconds=wait, poll_seconds=1.0,
                             clock=lambda: float(next(ticks)), sleep=lambda _s: None, out=lambda _l: None)


def stopped_file(sup, report):
    return sup.slot.retire_dir / f"{report}.stopped"


def test_supervisor_learns_the_launch_report_id(slot_rig):
    sup, guest, _s, clock, _b, _l = slot_rig
    sup.step()
    assert sup.launch.report_id == report_id(guest.boot)


def test_broker_destroy_stops_scrubs_and_relaunches_on_a_new_report_id(slot_rig, tmp_path):
    sup, guest, systemctl, clock, broker, _ = slot_rig
    sup.step()
    guest.chain, guest.rooms = 1, [{"id": "r1"}]  # an attempt is running
    sup.step()
    original = (report_id(guest.boot), guest.binding)
    broker.retire[original[0]] = original[1]
    assert channel(sup, broker) == 0  # nothing stopped yet: no confirm, broker stays pending
    assert broker.confirmed == []
    assert (sup.slot.retire_dir / f"{original[0]}.request").is_file()
    sup.step()
    # Stopped while the old scratch existed, started only after it was deleted.
    assert systemctl.order == [("stop", True), ("start", False)]
    record = json.loads(stopped_file(sup, original[0]).read_text())
    assert record["binding_sha256"] == original[1] and record["reason"] == "broker_destroy"
    assert channel(sup, broker) == 1
    assert broker.confirmed == [original[0]] and broker.retire == {}
    assert not (sup.slot.retire_dir / f"{original[0]}.request").exists()
    sup.step()
    assert sup.launch.report_id == report_id(guest.boot) != original[0]


def test_a_stop_that_fails_is_never_reported_stopped(slot_rig):
    sup, guest, systemctl, _c, broker, _ = slot_rig
    sup.step()
    broker.retire[report_id(guest.boot)] = guest.binding
    systemctl.stop_works = False
    channel(sup, broker)
    sup.step()
    assert not stopped_file(sup, report_id(guest.boot)).exists()
    assert channel(sup, broker) == 0 and broker.confirmed == []
    assert sup.slot.scratch.exists()  # kept: the guest may still run


def test_a_launch_that_is_not_running_is_confirmed_without_touching_the_unit(slot_rig):
    sup, guest, systemctl, _c, broker, lines = slot_rig
    sup.step()
    old = "f" * 64  # e.g. the supervisor's own attempt_ended retire ran first
    broker.retire[old] = "e" * 64
    channel(sup, broker)
    sup.step()
    assert systemctl.mutating() == []
    assert json.loads(stopped_file(sup, old).read_text())["reason"] == "not_running"
    assert channel(sup, broker) == 1 and broker.confirmed == [old]


def test_an_unknown_running_launch_waits_instead_of_guessing(slot_rig):
    sup, guest, systemctl, _c, broker, _ = slot_rig
    guest.up = False  # booting: no answer yet, unit active
    broker.retire["f" * 64] = "e" * 64
    channel(sup, broker)
    sup.step()
    assert not stopped_file(sup, "f" * 64).exists()
    assert systemctl.mutating() == []


def test_a_unit_that_restarted_on_its_own_is_never_confirmed_not_running(slot_rig):
    """Restart=on-failure: the unit runs a launch the supervisor has not seen. A destroy of
    that launch must not be confirmed as not running (Codex P1 on #724)."""
    sup, guest, systemctl, _c, broker, _ = slot_rig
    sup.step()
    tracked = sup.launch.report_id
    guest.relaunch()  # systemd restarted the unit; the supervisor still tracks the old launch
    new = report_id(guest.boot)
    assert new != tracked
    broker.retire[new] = guest.binding
    channel(sup, broker)
    sup.serve_retire_requests()
    assert not stopped_file(sup, new).exists()
    assert channel(sup, broker) == 0 and broker.confirmed == []


def test_the_supervisors_own_retire_also_leaves_a_stopped_record(slot_rig):
    sup, guest, _s, clock, broker, _ = slot_rig
    sup.step()
    first = (report_id(guest.boot), guest.binding)
    guest.chain, guest.rooms = 1, [{"id": "r1"}]
    sup.step()
    guest.rooms = []
    sup.step()
    sup.step()  # two empty polls: attempt_ended, the #496 backstop
    assert json.loads(stopped_file(sup, first[0]).read_text())["reason"] == "attempt_ended"
    broker.retire[first[0]] = first[1]  # the API's destroy arrives afterwards
    assert channel(sup, broker) == 1


def test_channel_refuses_a_foreign_or_broken_answer(slot_rig):
    sup, _g, _s, _c, broker, _ = slot_rig
    broker.up = False
    assert channel(sup, broker) == 0
    bad = lambda method, path, body: (200, {"schema": es.RETIRE_REQUEST_SCHEMA, "slot": "other", "retire": []})  # noqa: E731
    assert es.retire_channel(sup.slot, bad, wait_seconds=0, out=lambda _l: None) == 0
    junk = lambda method, path, body: (200, {"schema": es.RETIRE_REQUEST_SCHEMA, "slot": sup.slot.name,  # noqa: E731
                                             "retire": [{"report_id": "../x", "binding_sha256": "b" * 64}]})
    assert es.retire_channel(sup.slot, junk, wait_seconds=0, out=lambda _l: None) == 0
    assert list(sup.slot.retire_dir.glob("*.request")) == []


def test_channel_waits_for_the_supervisor_then_confirms(slot_rig):
    sup, guest, _s, _c, broker, _ = slot_rig
    sup.step()
    report = report_id(guest.boot)
    broker.retire[report] = guest.binding
    steps = iter([None, None, "go"])

    def sleep(_s):
        if next(steps, None) == "go":
            sup.step()  # the supervisor polls while the channel waits

    ticks = iter(range(10_000))
    confirmed = es.retire_channel(sup.slot, broker, wait_seconds=100, poll_seconds=1.0,
                                  clock=lambda: float(next(ticks)), sleep=sleep, out=lambda _l: None)
    assert confirmed == 1 and broker.confirmed == [report]


def test_channel_needs_the_slot_opt_in_and_an_https_broker(tmp_path):
    env = make_slot(tmp_path)
    with pytest.raises(SystemExit, match="SEALED_ESCAPE_SLOT"):
        es.broker_url_of(env)
    for n, (url, ok) in enumerate([("http://broker.example", False), ("https://broker.example/v1", False),
                                   ("https://u@broker.example", False), ("https://broker.example:8443", True)]):
        env = make_slot(tmp_path / str(n), SEALED_ESCAPE_SLOT="1", SEALED_BROKER_URL=url)
        if ok:
            assert es.broker_url_of(env) == url
        else:
            with pytest.raises(SystemExit, match="https"):
                es.broker_url_of(env)


def _write_units(tmp_path: Path, **extra) -> subprocess.CompletedProcess:
    values = {"SEALED_NAME": "chi-test", "SEALED_DIR": "/srv/sealed-test", "SEALED_ESCAPE_SLOT": "1",
              "SEALED_BROKER_URL": "https://broker.example", **extra}
    env = tmp_path / "sealed.env"
    env.write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    return subprocess.run(["bash", str(WRITE_UNITS), str(env)], capture_output=True, text=True,
                          env={"ROOM_DESTDIR": str(tmp_path / "root"), "PATH": "/usr/bin:/bin"})


def test_write_escape_units_extends_the_net_check_unit_and_wires_the_supervisor(tmp_path):
    proc = _write_units(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "no start" in proc.stdout
    etc = tmp_path / "root" / "etc" / "systemd" / "system"
    dropin = (etc / "room-sealed-chi-test-net.service.d" / "50-escape-retire.conf").read_text()
    tool = "/srv/sealed-test/escape-slot/supervise_escape_slot.py"
    assert (f"ExecStartPre=-/usr/bin/python3 -I {tool} --sealed-env /srv/sealed-test/sealed.env --retire-channel"
            in dropin)
    assert "ExecStart=" not in dropin.replace("ExecStartPre=", "")  # the link check itself is untouched
    unit = (etc / "room-sealed-chi-test-escape.service").read_text()
    assert f"ExecStart=/usr/bin/python3 -I {tool} --sealed-env /srv/sealed-test/sealed.env" in unit
    assert "Environment=CATHEDRAL_ESCAPE_SLOT_LIVE_OK=yes" in unit and "Restart=always" in unit
    assert "After=room-sealed-chi-test.service" in unit
    installed = tmp_path / "root" / "srv" / "sealed-test" / "escape-slot" / "supervise_escape_slot.py"
    assert installed.read_bytes() == (ROOT / "scripts" / "escape_slots" / "supervise_escape_slot.py").read_bytes()
    # No new listener: nothing in the units opens a port.
    assert "ListenStream" not in unit + dropin and ".socket" not in unit + dropin


@pytest.mark.parametrize("extra, message", [
    ({"SEALED_ESCAPE_SLOT": "0"}, "SEALED_ESCAPE_SLOT=1"),
    ({"SEALED_BROKER_URL": "http://broker.example"}, "https origin"),
    ({"SEALED_BROKER_URL": "https://broker.example/v1"}, "https origin"),
    ({"SEALED_DATA_GIB": "4"}, "SEALED_DATA_GIB"),
    ({"SEALED_MINER": "1"}, "SEALED_MINER"),
])
def test_write_escape_units_refuses_a_slot_it_cannot_retire_safely(tmp_path, extra, message):
    proc = _write_units(tmp_path, **extra)
    assert proc.returncode != 0 and message in proc.stderr
    assert not (tmp_path / "root" / "etc").exists()


def test_write_escape_units_never_starts_or_stops_anything():
    text = WRITE_UNITS.read_text()
    for verb in ("restart", "start", "stop", "enable", "kill", "disable"):
        assert f"systemctl {verb}" not in text
