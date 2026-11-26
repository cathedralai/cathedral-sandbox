"""AB#992 work package 1: the host execution history (docs/VM_EXECUTION_HISTORY.md H1 to H9).

Most tests run vm_ctl in process so a crash can be simulated by raising inside a patched step and
retrying. Fake systemctl and friends as in test_ab991_vm_runtime.py; clocks are patched."""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from test_ab991_vm_runtime import (FAKE_IPTABLES, FAKE_LOCALDS, FAKE_LOG, FAKE_QEMU_IMG, FAKE_SYSTEMCTL, KEY,
                                   KIT)

BOOT_A, BOOT_B = "boot-a", "boot-b"
T0 = 1_800_000_000_000_000  # microseconds


class Clock:
    """Patched wall, monotonic, boot id and sync state, so every line is exact."""

    def __init__(self):
        self.wall, self.mono, self.boot, self.synced, self.maxerror = T0, 5_000_000_000, BOOT_A, True, 1000
        self.bootns = 7_000_000_000  # CLOCK_BOOTTIME: mono plus suspended time

    def advance(self, seconds: float):
        self.wall += int(seconds * 1_000_000)
        self.mono += int(seconds * 1_000_000_000)
        self.bootns += int(seconds * 1_000_000_000)


@pytest.fixture
def vm(tmp_path, monkeypatch):
    fake = tmp_path / "bin"
    fake.mkdir()
    for n, text in {"systemctl": FAKE_SYSTEMCTL, "qemu-img": FAKE_QEMU_IMG, "cloud-localds": FAKE_LOCALDS,
                    "ip": FAKE_LOG, "iptables": FAKE_IPTABLES, "ip6tables": FAKE_IPTABLES, "sysctl": FAKE_LOG,
                    "flock": FAKE_LOG, "ss": FAKE_LOG}.items():
        (fake / n).write_text(text)
        (fake / n).chmod(0o755)
    image = tmp_path / "base.img"
    image.write_bytes(b"not really an image")
    (tmp_path / "id.pub").write_text(KEY + "\n")
    for k, v in {"PATH": f"{fake}:{os.environ['PATH']}", "VM_ROOT": str(tmp_path / "vms"),
                 "SYSTEMD_UNIT_DIR": str(tmp_path / "units"), "FAKE_STATE": str(tmp_path / "systemd.json"),
                 "VM_STOP_WAIT": "1", "VM_LOCK_DIR": str(tmp_path / "lock")}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(sys, "dont_write_bytecode", True)  # no __pycache__ in the kit directory
    spec = importlib.util.spec_from_file_location("vm_ctl_under_test", KIT / "vm_ctl.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    clock = Clock()
    monkeypatch.setattr(mod, "wall_us", lambda: clock.wall)
    monkeypatch.setattr(mod, "mono_ns", lambda: clock.mono)
    monkeypatch.setattr(mod, "boot_id", lambda: clock.boot)
    monkeypatch.setattr(mod, "boot_ns", lambda: clock.bootns)
    monkeypatch.setattr(mod, "kernel_clock", lambda: (clock.synced, clock.maxerror))

    class H:
        m, clk, root = mod, clock, tmp_path / "vms"
        paid = int(time.time()) + 36000

        def run(self, fn, *args):
            """(exit code, answer) the way main() would print it."""
            try:
                return 0, fn(list(args))
            except mod.Refusal as e:
                return e.code, {"error": e.error}

        def create(self, name="vm1", port="22001"):
            return self.run(lambda a: mod.cmd_create(a, None), name, "--vcpus", "1", "--mem-gib", "1",
                            "--disk-gib", "8", "--ssh-key-file", str(tmp_path / "id.pub"), "--ssh-port", port,
                            "--image", str(image))

        def auth(self, g, name="vm1", paid=None):
            return self.run(mod.cmd_authorize, name, str(paid or self.paid), str(g))

        def start(self, name="vm1", *extra):
            return self.run(mod.cmd_start, name, *extra)

        def stop(self, name="vm1"):
            return self.run(mod.cmd_stop, name)

        def cancel(self, g, name="vm1"):
            return self.run(mod.cmd_cancel, name, str(g))

        def history(self, g, name="vm1"):
            return self.run(mod.cmd_history, name, str(g))

        def check_paid(self, name="vm1"):
            return self.run(mod.cmd_check_paid, name)

        def lines(self, name="vm1"):
            return [json.loads(x) for x in (self.root / ".history" / f"{name}.jsonl").read_text().splitlines()]

        def hfile(self, name="vm1"):
            return self.root / ".history" / f"{name}.jsonl"

        def authjson(self, name="vm1"):
            return json.loads((self.root / name / "authorization.json").read_text())

        def systemd(self):
            return json.loads((tmp_path / "systemd.json").read_text())

        def legacy_vm(self, generation=0):
            """A VM made by the code before AB#992: no history file, authorization as it was."""
            assert self.create()[0] == 0
            self.hfile().unlink()
            (self.root / ".history").rmdir()
            a = {"generation": generation, "paid_through": self.paid if generation else 0, "closed_generation": 0}
            (self.root / "vm1" / "authorization.json").write_text(json.dumps(a))

    return H()


def lower(close_wall_us: int, elapsed_us: int, start_wall_us: int = T0, maxerror_us: int = 1000) -> int:
    """The r4.1 same-boot lower bound, written out independently of the code under test."""
    widened = -(-elapsed_us * 10_000 // 9_995)  # elapsed / 0.9995, rounded up
    return min(close_wall_us - maxerror_us - widened, start_wall_us - maxerror_us)


def crash_on(monkeypatch, mod, attr, when):
    """Make mod.<attr> raise once when when(*args) is true, then work again."""
    real = getattr(mod, attr)
    state = {"hit": False}

    def boom(*a, **k):
        if not state["hit"] and when(*a, **k):
            state["hit"] = True
            raise RuntimeError("simulated crash")
        return real(*a, **k)

    monkeypatch.setattr(mod, attr, boom)
    return state


# ---- H1, H7: file, coverage boundary, names ------------------------------------------

def test_create_writes_tracked_from_one_and_mode_0600(vm):
    assert vm.create()[0] == 0
    assert vm.lines() == [{"event": "tracked_from", "generation": 1}]
    assert oct(vm.hfile().stat().st_mode & 0o777) == "0o600"
    assert not (vm.root / "vm1" / "history").exists()  # outside the VM directory


def test_each_append_fsyncs_the_file_then_the_history_directory(vm, monkeypatch):
    vm.create()
    synced = []
    real = os.fsync

    def spy(fd):
        synced.append("dir" if os.path.isdir(f"/dev/fd/{fd}") else "file")
        real(fd)

    monkeypatch.setattr(vm.m.os, "fsync", spy)
    vm.m.history_append("vm1", {"event": "start", "generation": 9, **vm.m.stamp()})
    assert synced == ["file", "dir"]


def test_rollout_running_generation_is_never_tracked(vm):
    vm.legacy_vm(generation=1)
    assert vm.start()[0] == 0  # first touch after the upgrade
    assert vm.lines() == [{"event": "tracked_from", "generation": 2}]  # no start line for G=1
    assert vm.check_paid()[0] == 0  # the generation open at upgrade is not gated
    vm.clk.advance(60)
    assert vm.stop()[0] == 0
    assert vm.history(1) == (3, {"error": "history_unknown"})
    assert vm.start()[1]["error"] == "generation_closed"  # a retried start of G stays unknown
    assert vm.history(1) == (3, {"error": "history_unknown"})
    assert all(e["event"] == "tracked_from" for e in vm.lines())
    # The next generation is tracked from its first line.
    assert vm.auth(2)[0] == 0 and vm.start()[0] == 0
    vm.clk.advance(30)
    vm.stop()
    code, h = vm.history(2)
    assert code == 0 and h["tracked_from"] == 2 and h["started_at"] is not None


def test_a_vm_with_no_history_file_answers_unknown(vm):
    vm.legacy_vm(generation=1)
    assert vm.history(1) == (3, {"error": "history_unknown"})


def test_delete_keeps_history_and_the_name_is_not_reused(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(120)
    code, _ = vm.run(vm.m.cmd_delete, "vm1", "--confirm", "vm1")
    assert code == 0 and not (vm.root / "vm1").exists()
    code, h = vm.history(1)
    assert code == 0 and h["close_reason"] == "deleted" and h["started_at"] is not None
    code, out = vm.create()
    assert code == 5 and out["error"] == "exists"
    assert vm.history(1)[0] == 0


# ---- H2: start line before launch, check-paid gate -------------------------------------

def test_start_line_is_durable_before_enable_and_start(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    seen = []
    real = vm.m.systemctl

    def spy(*args, **kw):
        if args[0] in ("enable", "start"):
            seen.append((args[0], [e["event"] for e in vm.lines()]))
        return real(*args, **kw)

    monkeypatch.setattr(vm.m, "systemctl", spy)
    assert vm.start()[0] == 0
    assert seen and all(ev == ["tracked_from", "start"] for _, ev in seen), seen


def test_start_line_survives_a_failed_launch_and_is_not_duplicated(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    state = crash_on(monkeypatch, vm.m, "systemctl", lambda *a, **k: a[0] == "start")
    with pytest.raises(RuntimeError):
        vm.start()
    assert [e["event"] for e in vm.lines()] == ["tracked_from", "start"]
    first = vm.lines()[1]
    vm.clk.advance(5)
    assert state["hit"] and vm.start()[0] == 0
    assert vm.lines()[1] == first and len(vm.lines()) == 2  # a retry keeps the first start time


def test_check_paid_refuses_a_reboot_relaunch_with_no_start_line(vm):
    vm.create()
    vm.auth(1)
    # The enabled unit relaunches after a host reboot without cmd_start; nothing wrote a start line.
    code, out = vm.check_paid()
    assert code == 3 and out["error"] == "start_not_recorded"
    assert vm.start()[0] == 0
    assert vm.check_paid()[0] == 0


def test_the_unit_still_gates_launch_on_check_paid(vm):
    vm.create()
    assert "check-paid vm1" in (vm.root.parent / "units" / "cathedral-vm-vm1.service").read_text()


# ---- H3: authorize over an open generation -------------------------------------------

def test_authorize_over_a_started_generation_is_refused(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    code, out = vm.auth(2)
    assert code == 3 and out["error"] == "generation_open"
    assert vm.authjson()["generation"] == 1


def test_authorize_over_an_unstarted_generation_closes_it_as_never_started(vm):
    vm.create()
    vm.auth(1)
    vm.clk.advance(10)
    assert vm.auth(2)[0] == 0
    assert vm.authjson()["closed_generation"] == 1
    code, h = vm.history(1)
    assert code == 0 and h["started_at"] is None and h["close_reason"] == "superseded"
    assert h["stopped_at"] == (T0 + 10_000_000) // 1_000_000
    assert vm.history(2) == (3, {"error": "history_open"})


# ---- H4 and the close-line authority -------------------------------------------------------

def test_crash_after_the_close_line_before_authorization_or_stop_json(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(100)
    state = crash_on(monkeypatch, vm.m, "write_atomic", lambda p, *a, **k: Path(p).name == "authorization.json")
    with pytest.raises(RuntimeError):
        vm.stop()
    assert state["hit"] and vm.lines()[-1]["event"] == "close"
    assert vm.authjson()["closed_generation"] == 0 and not (vm.root / "vm1" / "stop.json").exists()
    close = vm.lines()[-1]
    # Time moves on: the retry must still report the first stop.
    vm.clk.advance(500)
    code, out = vm.stop()
    assert code == 0 and out["stopped_at"] == close["stopped_at"]
    assert json.loads((vm.root / "vm1" / "stop.json").read_text())["stopped_at"] == close["stopped_at"]
    code, h = vm.history(1)
    assert code == 0 and h["stopped_at"] == close["stopped_at"] and len([e for e in vm.lines() if e["event"] == "close"]) == 1


def test_a_durable_close_line_blocks_start_and_check_paid_before_authorization_catches_up(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(100)
    crash_on(monkeypatch, vm.m, "write_atomic", lambda p, *a, **k: Path(p).name == "authorization.json")
    with pytest.raises(RuntimeError):
        vm.stop()
    assert vm.authjson()["closed_generation"] == 0  # authorization.json missed the close
    code, out = vm.check_paid()  # read only: reads the close line
    assert code == 3 and out["error"] == "generation_closed"
    code, out = vm.start()
    assert code == 3 and out["error"] == "generation_closed"
    assert vm.authjson()["closed_generation"] == 1  # recovered from history, rewritten first


def test_authorize_and_cancel_recover_closure_from_the_close_line(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(100)
    crash_on(monkeypatch, vm.m, "write_atomic", lambda p, *a, **k: Path(p).name == "authorization.json")
    with pytest.raises(RuntimeError):
        vm.stop()
    code, out = vm.auth(1)  # a top-up of the closed run
    assert code == 3 and out["error"] == "generation_closed"
    assert vm.cancel(1)[1]["close_reason"] == "requested"  # returns the existing close


def test_enforce_stop_reuses_the_close_line(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    vm.start()
    a = vm.authjson()
    a["paid_through"] = int(time.time()) - 5
    (vm.root / "vm1" / "authorization.json").write_text(json.dumps(a))
    vm.clk.advance(50)
    out = vm.m.cmd_enforce([])
    assert out["stopped"][0]["generation"] == 1
    code, h = vm.history(1)
    assert code == 0 and h["close_reason"] == "paid_through" and h["stopped_at"] == out["stopped"][0]["stopped_at"]


def test_ordinary_start_and_stop_retries_keep_the_first_times(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    first_start = vm.lines()[1]
    vm.clk.advance(10)
    assert vm.start()[0] == 0
    assert vm.lines()[1] == first_start
    vm.clk.advance(100)
    first = vm.stop()[1]
    vm.clk.advance(1000)
    again = vm.stop()[1]
    assert again["stopped_at"] == first["stopped_at"]
    assert vm.history(1)[1]["started_at"] == vm.history(1)[1]["started_at"]
    assert [e["event"] for e in vm.lines()] == ["tracked_from", "start", "close"]


# ---- H5: cancel ------------------------------------------------------------------------

def test_cancel_of_an_undelivered_generation_fences_it_and_is_idempotent(vm):
    vm.create()
    vm.clk.advance(1)
    code, rec = vm.cancel(1)
    assert code == 0 and rec["close_reason"] == "cancelled" and rec["generation"] == 1
    assert vm.authjson()["closed_generation"] == 1
    vm.clk.advance(500)
    assert vm.cancel(1) == (0, rec)  # the same record
    assert vm.auth(1)[1]["error"] == "generation_closed"  # the late authorize is fenced out
    assert vm.auth(2)[0] == 0
    code, h = vm.history(1)
    assert code == 0 and h["started_at"] is None and h["close_reason"] == "cancelled"


def test_cancel_of_an_authorized_unstarted_generation(vm):
    vm.create()
    vm.auth(1)
    code, rec = vm.cancel(1)
    assert code == 0 and rec["close_reason"] == "cancelled"
    assert vm.start()[1]["error"] == "generation_closed"
    assert vm.history(1)[1]["started_at"] is None


def test_cancel_of_a_started_generation_stops_it_and_keeps_the_start(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(90)
    code, rec = vm.cancel(1)
    assert code == 0 and rec["close_reason"] == "cancelled"
    assert not vm.systemd()["cathedral-vm-vm1.service"]["active"]
    code, h = vm.history(1)
    assert code == 0 and h["started_at"] == vm.m.iso_us(lower(T0 + 90_000_000, 90_000_000))
    assert h["started_at"] <= vm.m.iso_us(T0)  # never later than the real start
    assert vm.cancel(1) == (0, rec)


def test_cancel_after_a_failed_launch_closes_with_a_conservative_started_at(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    crash_on(monkeypatch, vm.m, "systemctl", lambda *a, **k: a[0] == "start")
    with pytest.raises(RuntimeError):
        vm.start()  # start line written, launch failed
    vm.clk.advance(40)
    code, rec = vm.cancel(1)
    assert code == 0 and rec["close_reason"] == "cancelled"
    code, h = vm.history(1)
    assert code == 0 and h["started_at"] == vm.m.iso_us(lower(T0 + 40_000_000, 40_000_000))
    assert h["stopped_at"] == (T0 + 40_000_000) // 1_000_000


def test_cancel_then_start_and_start_then_cancel(vm):
    vm.create()
    vm.auth(1)
    assert vm.cancel(1)[0] == 0
    assert vm.start()[1]["error"] == "generation_closed"  # never launched
    assert not vm.systemd().get("cathedral-vm-vm1.service", {}).get("active")
    assert vm.history(1)[1]["started_at"] is None
    vm.auth(2)
    vm.start()
    vm.clk.advance(7)
    assert vm.cancel(2)[0] == 0  # a start line exists: it closes, it does not claim "never started"
    assert vm.history(2)[1]["started_at"] == vm.m.iso_us(lower(T0 + 7_000_000, 7_000_000))


def test_cancel_above_a_started_generation_is_refused(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    code, out = vm.cancel(2)
    assert code == 3 and out["error"] == "generation_open"
    assert vm.authjson()["closed_generation"] == 0


def test_cancel_above_an_unstarted_generation_closes_both(vm):
    vm.create()
    vm.auth(1)
    assert vm.cancel(2)[0] == 0
    assert vm.history(1)[1]["close_reason"] == "superseded"
    assert vm.history(2)[1]["close_reason"] == "cancelled"
    assert vm.authjson()["closed_generation"] == 2


# ---- H6: torn lines ------------------------------------------------------------------------

def test_a_torn_final_line_is_ignored_by_readers_and_cut_by_the_next_writer(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(5)
    vm.stop()
    with open(vm.hfile(), "ab") as f:
        f.write(b'{"event":"start","generation":2,"wal')
    assert vm.history(1)[0] == 0  # reader ignores the tail
    assert vm.history(2) == (3, {"error": "history_open"})
    vm.auth(2)
    vm.start()
    raw = vm.hfile().read_bytes()
    assert raw.endswith(b"\n") and b'"generation":2,"wal' not in raw
    assert [e["event"] for e in vm.lines()] == ["tracked_from", "start", "close", "start"]


def test_a_malformed_middle_line_makes_the_file_unknown(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(5)
    vm.stop()
    lines = vm.hfile().read_text().splitlines()
    lines[1] = "{not json"
    vm.hfile().write_text("\n".join(lines) + "\n")
    assert vm.history(1) == (3, {"error": "history_unknown"})


def test_a_missing_or_invalid_first_line_means_no_coverage(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(5)
    vm.stop()
    lines = vm.hfile().read_text().splitlines()[1:]
    vm.hfile().write_text("\n".join(lines) + "\n")
    assert vm.history(1) == (3, {"error": "history_unknown"})


# ---- H8, H9: time and the answer ----------------------------------------------------------

def test_same_boot_derivation_is_exact_and_anchored_on_the_close_wall_time(vm):
    vm.create()
    vm.auth(1)
    vm.clk.advance(3)
    vm.start()
    # The wall clock stepped (NTP) during the run; the monotonic duration does not care.
    vm.clk.advance(600)
    vm.clk.wall += 2_000_000
    vm.stop()
    close = vm.lines()[-1]
    code, h = vm.history(1)
    start = vm.lines()[1]
    expected = lower(close["wall_us"], 600_000_000, start["wall_us"])
    assert code == 0 and h["started_at"] == vm.m.iso_us(expected)
    # The close wall time stepped 2 s ahead, so the start line's own wall time less its error wins.
    assert expected == start["wall_us"] - 1000
    assert h["started_at_error_us"] == close["wall_us"] - 600_000_000 - expected == 2_001_000
    assert h["started_at"].endswith("Z") and "." in h["started_at"]
    assert set(h) == {"generation", "closed", "started_at", "started_at_error_us", "stopped_at", "tracked_from",
                      "close_reason", "history"}
    assert h["history"] == "v2" and h["closed"] is True and h["tracked_from"] == 1
    assert isinstance(h["stopped_at"], int) and h["stopped_at"] == close["wall_us"] // 1_000_000


def test_cross_boot_uses_the_start_wall_time_only_when_both_lines_are_synced(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(3600)
    vm.clk.boot = BOOT_B  # a host reboot during the run
    vm.clk.mono = 1_000_000_000
    vm.stop()
    code, h = vm.history(1)
    assert h["started_at"] == vm.m.iso_us(T0 - 1000) and h["started_at_error_us"] == 1000
    # Same file, but the start line was written with an unsynced clock.
    lines = vm.lines()
    lines[1]["synced"] = False
    vm.hfile().write_text("".join(json.dumps(e) + "\n" for e in lines))
    assert vm.history(1) == (3, {"error": "history_unknown"})


@pytest.mark.parametrize("fast_us", [0, 1000, -1000])
@pytest.mark.parametrize("slew", [1.0, 1.0005, 0.9995])
def test_a_wall_clock_off_by_up_to_maxerror_never_yields_a_start_after_the_real_one(vm, fast_us, slew):
    """Real start is T0. The wall clock reads real time plus fast_us at the close (|fast_us| <= maxerror),
    and the kernel clocks run slew times real elapsed time, within 500 ppm."""
    vm.create()
    vm.auth(1)
    vm.start()
    real_elapsed_us = 3_600_000_000
    vm.clk.wall = T0 + real_elapsed_us + fast_us
    vm.clk.mono += int(real_elapsed_us * slew * 1000)
    vm.clk.bootns += int(real_elapsed_us * slew * 1000)
    vm.stop()
    code, h = vm.history(1)
    started_us = int(vm.m.datetime.datetime.strptime(h["started_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
                     .replace(tzinfo=vm.m.datetime.timezone.utc).timestamp() * 1_000_000)
    assert code == 0 and started_us <= T0, (started_us - T0)
    assert h["started_at_error_us"] > 0


def started_us_of(vm, h):
    return int(vm.m.datetime.datetime.strptime(h["started_at"], "%Y-%m-%dT%H:%M:%S.%fZ")
               .replace(tzinfo=vm.m.datetime.timezone.utc).timestamp() * 1_000_000)


def test_a_suspend_gap_is_counted_through_clock_boottime(vm):
    """CLOCK_MONOTONIC stops while the host is suspended; the wall clock and CLOCK_BOOTTIME do not."""
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(100)
    vm.clk.wall += 3_600_000_000  # one hour asleep
    vm.clk.bootns += 3_600_000_000_000
    vm.stop()
    code, h = vm.history(1)
    assert code == 0 and started_us_of(vm, h) <= T0, started_us_of(vm, h) - T0
    # The bound counts the hour asleep: elapsed 3700 s, not the 100 s of CLOCK_MONOTONIC.
    close = vm.lines()[-1]
    assert started_us_of(vm, h) == lower(close["wall_us"], 3_700_000_000) < T0 - 1000
    # What the old monotonic-based rule would have said is an hour too late.
    close, start = vm.lines()[-1], vm.lines()[1]
    assert close["wall_us"] - (close["mono_ns"] - start["mono_ns"]) // 1000 > T0 + 3_000_000_000


def test_a_clock_running_500_ppm_slow_over_a_day_still_gives_a_lower_bound(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    day_us = 86_400_000_000
    slow_ns = day_us * 1000 * 9995 // 10_000  # 0.9995 of real time
    vm.clk.wall = T0 + day_us
    vm.clk.mono += slow_ns
    vm.clk.bootns += slow_ns
    vm.stop()
    code, h = vm.history(1)
    assert code == 0 and started_us_of(vm, h) <= T0 - 1000 + 1, started_us_of(vm, h) - T0


@pytest.mark.parametrize("bad", [None, "missing", 1_000_001, -1])
def test_a_missing_or_oversized_maxerror_is_unknown(vm, bad):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(60)
    vm.stop()
    lines = vm.lines()
    for e in lines[1:]:
        if bad == "missing":
            e.pop("maxerror_us")
        else:
            e["maxerror_us"] = bad
    vm.hfile().write_text("".join(json.dumps(e) + "\n" for e in lines))
    assert vm.history(1) == (3, {"error": "history_unknown"})


def test_a_maxerror_of_exactly_one_second_is_accepted(vm):
    vm.create()
    vm.auth(1)
    vm.clk.maxerror = 1_000_000
    vm.start()
    vm.clk.advance(60)
    vm.stop()
    code, h = vm.history(1)
    assert code == 0 and h["started_at_error_us"] == 1_030_016  # 1 s clock error + 60 s / 0.9995 less 60 s


def test_the_adjtimex_reader_fails_closed_off_linux_and_never_raises(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("vm_ctl_clock", KIT / "vm_ctl.py")
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    synced, err = mod.kernel_clock()
    assert isinstance(synced, bool) and (err is None or isinstance(err, int))
    if not sys.platform.startswith("linux"):
        assert (synced, err) == (False, None)
    monkeypatch.setattr(mod.sys, "platform", "darwin")
    assert mod.kernel_clock() == (False, None)


def test_an_unsynced_line_is_unknown_in_the_same_boot_branch_too(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(10)
    vm.clk.synced = False
    vm.stop()
    assert vm.history(1) == (3, {"error": "history_unknown"})


def test_a_never_started_close_needs_no_clock_sync(vm):
    vm.create()
    vm.clk.synced = False
    vm.cancel(1)
    assert vm.history(1)[1]["started_at"] is None


def test_started_at_is_never_later_than_stopped_at(vm):
    vm.create()
    vm.auth(1)
    vm.clk.wall = T0 + 900_000  # 0.9 s into the second
    vm.start()
    vm.clk.advance(0.05)
    vm.stop()
    code, h = vm.history(1)
    assert code == 0
    assert h["started_at"] <= vm.m.iso_us(h["stopped_at"] * 1_000_000)
    # Cross boot with a start later than the close is not believable.
    lines = vm.lines()
    lines[1]["boot_id"] = BOOT_B
    lines[1]["wall_us"] = lines[2]["wall_us"] + 5000  # still later after its 1000 us error
    vm.hfile().write_text("".join(json.dumps(e) + "\n" for e in lines))
    assert vm.history(1) == (3, {"error": "history_unknown"})


def test_history_open_while_open_and_unknown_below_tracked_from(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    assert vm.history(1) == (3, {"error": "history_open"})
    assert vm.history(7) == (3, {"error": "history_open"})
    lines = vm.lines()
    lines[0]["generation"] = 3  # tracked from 3: G=1 is below it
    vm.hfile().write_text("".join(json.dumps(e) + "\n" for e in lines))
    assert vm.history(1) == (3, {"error": "history_unknown"})


def test_history_works_through_the_cli_and_the_broker_forced_command(vm, tmp_path, monkeypatch):
    import subprocess

    vm.create()
    vm.auth(1)
    vm.cancel(1)
    env = dict(os.environ)
    p = subprocess.run([str(KIT / "vm-ctl.sh"), "history", "vm1", "1"], capture_output=True, text=True, env=env)
    assert p.returncode == 0 and json.loads(p.stdout)["close_reason"] == "cancelled"
    env["SSH_ORIGINAL_COMMAND"] = "cancel vm1 1"
    p = subprocess.run([str(KIT / "vm-ctl.sh"), "--from-broker"], capture_output=True, text=True, env=env)
    assert p.returncode == 0 and json.loads(p.stdout)["generation"] == 1
    env["SSH_ORIGINAL_COMMAND"] = "history vm1 9"
    p = subprocess.run([str(KIT / "vm-ctl.sh"), "--from-broker"], capture_output=True, text=True, env=env)
    assert p.returncode == 3 and json.loads(p.stdout)["error"] == "history_open"


def test_the_cutoff_stops_the_unit_even_when_history_io_fails(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    vm.start()
    a = vm.authjson()
    a["paid_through"] = int(time.time()) - 5
    (vm.root / "vm1" / "authorization.json").write_text(json.dumps(a))
    monkeypatch.setattr(vm.m, "read_history", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    out = vm.m.cmd_enforce([])
    assert not vm.systemd()["cathedral-vm-vm1.service"]["active"]
    assert not vm.systemd()["cathedral-vm-vm1.service"]["enabled"]
    assert out["errors"][0]["name"] == "vm1"  # the history failure is reported after the stop


def test_stop_and_delete_also_stop_before_touching_history(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    vm.start()
    monkeypatch.setattr(vm.m, "read_history", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        vm.stop()
    assert not vm.systemd()["cathedral-vm-vm1.service"]["active"]


# ---- Review fixes (Astra impl r1) -------------------------------------------------------------

def test_a_retry_fsyncs_the_journal_before_it_launches_on_a_line_it_did_not_sync(vm, monkeypatch):
    """Finding 1: a start line written but never fsynced must not be trusted by a retry's launch."""
    vm.create()
    vm.auth(1)
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: None)  # the start line is written, never fsynced
    crash_on(monkeypatch, vm.m, "systemctl", lambda *a, **k: a[0] == "start")
    with pytest.raises(RuntimeError):
        vm.start()
    events = []
    monkeypatch.setattr(os, "fsync", lambda fd: (events.append("fsync"), real_fsync(fd))[1])
    real_systemctl = vm.m.systemctl
    monkeypatch.setattr(vm.m, "systemctl", lambda *a, **k: (events.append("systemctl " + a[0]),
                                                           real_systemctl(*a, **k))[1])
    assert vm.start()[0] == 0
    assert "fsync" in events and events.index("fsync") < events.index("systemctl enable"), events


@pytest.mark.parametrize("reader", ["check_paid", "history"])
def test_every_reader_fsyncs_the_journal_before_it_answers(vm, monkeypatch, reader):
    vm.create()
    vm.auth(1)
    vm.start()
    if reader == "history":
        vm.clk.advance(5)
        vm.stop()
    events = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (events.append("fsync"), real_fsync(fd))[1])
    getattr(vm, reader)(*([] if reader == "check_paid" else [1]))
    assert events.count("fsync") >= 2  # the file and the directory


def test_create_holds_the_vm_lock_and_initialises_history_before_publishing_vm_env(vm, monkeypatch):
    """Finding 2: no command can append to a journal that create is still starting."""
    seen = {}
    real = vm.m.history_append

    def spy(name, record):
        d = vm.root / name
        seen["env_published"] = (d / "vm.env").exists()
        fd = os.open(d / ".lock", os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            seen["lock_held"] = False
        except BlockingIOError:
            seen["lock_held"] = True
        finally:
            os.close(fd)
        return real(name, record)

    monkeypatch.setattr(vm.m, "history_append", spy)
    assert vm.create()[0] == 0
    assert seen == {"env_published": False, "lock_held": True}
    assert (vm.root / "vm1" / "vm.env").exists()


def test_a_failed_create_does_not_burn_the_name(vm, monkeypatch):
    crash_on(monkeypatch, vm.m, "write_unit", lambda *a, **k: True)
    with pytest.raises(RuntimeError):
        vm.create()
    assert not vm.hfile().exists() and not (vm.root / "vm1").exists()
    assert vm.create()[0] == 0


def test_history_append_waits_for_the_journal_lock_and_never_cuts_a_complete_line(vm):
    vm.create()
    vm.auth(1)
    vm.start()
    before = vm.hfile().read_bytes()
    fd = os.open(vm.hfile(), os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)  # another writer is mid-append
    done = threading.Event()

    def writer():
        vm.m.history_append("vm1", {"event": "start", "generation": 9, **vm.m.stamp()})
        done.set()

    t = threading.Thread(target=writer)
    t.start()
    assert not done.wait(0.5)  # blocked on the journal lock
    os.close(fd)
    t.join(5)
    assert done.is_set() and vm.hfile().read_bytes().startswith(before)


def test_the_journal_dir_cannot_collide_with_a_vm_named_history(vm):
    """Finding 3: journals live in <root>/.history; a VM called history is an ordinary VM."""
    assert vm.m.history_dir() == vm.root / ".history"
    for bad in (".history", ".x"):
        with pytest.raises(vm.m.Refusal):
            vm.m.check_name(bad)
    assert vm.create()[0] == 0
    code, _ = vm.create("history", port="22002")
    assert code == 0 and (vm.root / "history" / "vm.env").exists()
    assert (vm.root / ".history" / "vm1.jsonl").exists() and (vm.root / ".history" / "history.jsonl").exists()
    vm.auth(1, "history")
    vm.start("history")
    vm.clk.advance(30)
    assert vm.run(vm.m.cmd_delete, "history", "--confirm", "history")[0] == 0
    assert not (vm.root / "history").exists()
    assert vm.lines("vm1") == [{"event": "tracked_from", "generation": 1}]  # the other journal is untouched
    assert vm.history(1, "history")[0] == 0  # and its own survives the delete
    assert vm.create("history", port="22002")[1]["error"] == "exists"  # the name is not reused
    assert vm.history(1, "history")[0] == 0 and (vm.root / ".history" / "vm1.jsonl").exists()


def test_authorize_over_a_running_legacy_generation_is_refused(vm):
    """Finding 4: G1 runs untracked at the upgrade; G2 must not certify it never started."""
    vm.legacy_vm(generation=1)
    assert vm.start()[0] == 0
    code, out = vm.auth(2)
    assert code == 3 and out["error"] == "generation_open"
    assert vm.authjson()["generation"] == 1
    assert vm.cancel(3)[1]["error"] == "generation_open"  # a fence above it is no way around that
    assert vm.stop()[0] == 0
    assert vm.auth(2)[0] == 0  # down: the inactive untracked generation is replaced
    assert vm.history(1) == (3, {"error": "history_unknown"})  # and stays unknown


def test_stop_always_stops_the_unit_and_verifies_it_inactive(vm, monkeypatch):
    """Finding 5: the unit looks inactive but a queued start job is pending."""
    vm.create()
    vm.auth(1)
    vm.start()
    calls, state = [], {"stopped": False}
    real_systemctl = vm.m.systemctl

    def spy(*a, **k):
        calls.append(a[0])
        if a[0] == "stop":
            state["stopped"] = True
        return real_systemctl(*a, **k)

    monkeypatch.setattr(vm.m, "systemctl", spy)
    monkeypatch.setattr(vm.m, "unit_active", lambda n: False if not state["stopped"] else state.get("late", False))
    assert vm.stop()[0] == 0
    assert "disable" in calls and "stop" in calls
    # The start job was not cancelled: the unit comes up after the stop. No close line, stop_failed.
    vm2 = state
    vm2["stopped"] = False
    vm2["late"] = True
    code, out = vm.stop()
    assert code == 1 and out["error"] == "stop_failed"


def test_stop_failed_writes_no_close_line(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    vm.start()
    monkeypatch.setattr(vm.m, "unit_active", lambda n: True)
    monkeypatch.setattr(vm.m, "qmp", lambda *a, **k: False)
    code, out = vm.stop()
    assert code == 1 and out["error"] == "stop_failed"
    assert [e["event"] for e in vm.lines()] == ["tracked_from", "start"]


def test_check_paid_fails_closed_on_a_corrupt_journal(vm):
    """Finding 6."""
    vm.create()
    vm.auth(1)
    vm.start()
    lines = vm.hfile().read_text().splitlines()
    vm.hfile().write_text(lines[0] + "\n{not json\n" + lines[1] + "\n")
    code, out = vm.check_paid()
    assert code == 3 and out["error"] == "history_corrupt"
    assert vm.start()[1]["error"] == "history_corrupt"
    # A parsable close line for the current generation refuses first, whatever else is wrong.
    close = {"event": "close", "generation": 1, "stopped_at": 1, "reason": "requested", "wall_us": 1,
             "boot_id": None, "mono_ns": 1, "boot_ns": 1, "synced": True, "maxerror_us": 1}
    vm.hfile().write_text(lines[0] + "\n{not json\n" + json.dumps(close) + "\n")
    code, out = vm.check_paid()
    assert code == 3 and out["error"] == "generation_closed"
    # No journal at all is a VM from before the upgrade: not corrupt, not gated.
    vm.hfile().unlink()
    assert vm.check_paid()[0] == 0


def test_cancel_retry_rewrites_stop_json_from_the_close_line(vm, monkeypatch):
    """Finding 9: a crash after the close and authorization left stop.json stale or missing."""
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(30)
    crash_on(monkeypatch, vm.m, "write_atomic", lambda p, *a, **k: Path(p).name == "stop.json")
    with pytest.raises(RuntimeError):
        vm.cancel(1)
    assert not (vm.root / "vm1" / "stop.json").exists()
    vm.clk.advance(500)
    code, rec = vm.cancel(1)
    close = [e for e in vm.lines() if e["event"] == "close"][0]
    stop = json.loads((vm.root / "vm1" / "stop.json").read_text())
    assert code == 0 and rec["stopped_at"] == close["stopped_at"] == stop["stopped_at"]
    assert stop["reason"] == "cancelled" and vm.authjson()["closed_generation"] == 1


def test_no_em_dashes_in_the_history_work():
    for f in (KIT / "vm_ctl.py", KIT / "README.md", Path(__file__)):
        assert chr(0x2014) not in f.read_text(), f


# ---- Review fixes (Astra impl r2) -------------------------------------------------------------

def test_a_reader_never_trusts_a_close_appended_after_its_snapshot(vm, monkeypatch):
    """r1 #1: an unlocked reader that fsyncs before reading can see a later, unsynced close."""
    vm.create()
    vm.auth(1)
    vm.start()
    vm.clk.advance(5)
    vm.stop()
    raw = vm.hfile().read_bytes()
    lines = raw.splitlines(keepends=True)
    assert json.loads(lines[-1])["event"] == "close"
    vm.hfile().write_bytes(b"".join(lines[:-1]))
    real_fsync, fired = os.fsync, []

    def append_then_sync(fd):
        if not fired:  # a writer lands its close between the reader's snapshot and its fsync
            fired.append(1)
            with open(vm.hfile(), "ab") as f:
                f.write(lines[-1])
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", append_then_sync)
    h = vm.m.read_history("vm1")
    assert fired and not [e for e in h["events"] if e["event"] == "close"]


def test_enforce_stops_every_expired_vm_before_any_history_io(vm, monkeypatch):
    """r1 #8: the serial prerequisite scan must not touch history before a cutoff starts."""
    vm.create()
    vm.auth(1)
    vm.start()
    a = vm.authjson()
    a["paid_through"] = int(time.time()) - 5
    (vm.root / "vm1" / "authorization.json").write_text(json.dumps(a))
    events = []
    real_systemctl, real_begin = vm.m.systemctl, vm.m.begin_best_effort
    monkeypatch.setattr(vm.m, "systemctl", lambda *a, **k: (events.append("systemctl " + a[0]),
                                                           real_systemctl(*a, **k))[1])
    monkeypatch.setattr(vm.m, "begin_best_effort", lambda *a: (events.append("history"), real_begin(*a))[1])
    out = vm.m.cmd_enforce([])
    assert out["stopped"] and "history" in events  # history is still attempted, after
    assert events.index("systemctl stop") < events.index("history"), events


def test_delete_retry_after_the_unit_was_removed_but_the_directory_was_not(vm, monkeypatch):
    """r2 SHOULD 3: stop and disable fail on a missing unit, so cleanup must treat it as stopped."""
    vm.create()
    vm.auth(1)
    vm.start()
    crash_on(monkeypatch, vm.m.shutil, "rmtree", lambda *a, **k: True)
    with pytest.raises(RuntimeError):
        vm.run(vm.m.cmd_delete, "vm1", "--confirm", "vm1")
    assert not (vm.root.parent / "units" / "cathedral-vm-vm1.service").exists()
    real, calls = vm.m.systemctl, []

    def missing_unit(*a, **k):
        calls.append(a[0])
        if a[0] == "show":
            out = "inactive\n" if "--value" in a else "LoadState=not-found\nActiveState=inactive\n"
            return subprocess.CompletedProcess(a, 0, out, "")
        if a[0] in ("stop", "disable") and a[-1].startswith("cathedral-vm-vm1"):
            raise vm.m.Refusal("command_failed", f"systemctl {a[0]}: Unit not loaded", 1)
        return real(*a, **k)

    monkeypatch.setattr(vm.m, "systemctl", missing_unit)
    assert vm.run(vm.m.cmd_delete, "vm1", "--confirm", "vm1")[0] == 0
    assert not (vm.root / "vm1").exists()


def test_a_unit_that_exists_still_gets_the_unconditional_stop(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    calls, real = [], vm.m.systemctl
    monkeypatch.setattr(vm.m, "systemctl", lambda *a, **k: (calls.append(a[0]), real(*a, **k))[1])
    assert vm.stop()[0] == 0  # never started: the unit file exists
    assert "disable" in calls and "stop" in calls


# ---- Review fixes (Chaser HOLD at 9ae381e): stalled history must not hold the cutoff ----------

def run_pass(vm, limit=5.0):
    """One enforce pass in a thread: a pass that hangs on history I/O fails the test instead of the run."""
    box = {}
    t = threading.Thread(target=lambda: box.update(out=vm.m.cmd_enforce([])), daemon=True)
    t.start()
    t.join(limit)
    return None if t.is_alive() else box["out"]


def fake_wall(vm, monkeypatch):
    """A controlled time.time() for the paid_through checks, with the rest of time untouched."""
    import types
    state = {"now": int(time.time())}
    shim = types.SimpleNamespace(**{k: getattr(time, k) for k in dir(time) if not k.startswith("_")})
    shim.time = lambda: state["now"]
    monkeypatch.setattr(vm.m, "time", shim)
    return state


def test_a_stalled_history_read_in_the_sweep_does_not_hold_the_next_cutoff_pass(vm, monkeypatch):
    """Reviewer counterexample: funded at scan time, expires while the sweep is stuck on a history read."""
    vm.create()
    vm.auth(1)
    vm.start()
    wall = fake_wall(vm, monkeypatch)
    a = vm.authjson()
    a["paid_through"] = wall["now"] + 10
    (vm.root / "vm1" / "authorization.json").write_text(json.dumps(a))
    release = threading.Event()
    real = vm.m.read_history
    monkeypatch.setattr(vm.m, "HISTORY_BUDGET", 0.3, raising=False)
    monkeypatch.setattr(vm.m, "read_history", lambda *a, **k: (release.wait(30), real(*a, **k))[1])
    try:
        first = run_pass(vm)
        assert first is not None, "the first pass never returned: history I/O holds the cutoff service"
        assert vm.systemd()["cathedral-vm-vm1.service"]["active"]  # not expired yet
        wall["now"] += 61
        vm.clk.advance(61)
        second = run_pass(vm)
        assert second is not None, "the second pass never returned"
        assert [s["name"] for s in second["stopped"]] == ["vm1"]
        assert not vm.systemd()["cathedral-vm-vm1.service"]["active"]
    finally:
        release.set()


def test_a_stalled_close_write_in_the_stop_path_neither_holds_the_pass_nor_the_next_one(vm, monkeypatch):
    vm.create()
    vm.auth(1)
    vm.start()
    a = vm.authjson()
    a["paid_through"] = int(time.time()) - 5
    (vm.root / "vm1" / "authorization.json").write_text(json.dumps(a))
    release = threading.Event()
    real = vm.m.history_append
    monkeypatch.setattr(vm.m, "HISTORY_BUDGET", 0.3, raising=False)
    monkeypatch.setattr(vm.m, "history_append",
                        lambda name, rec: (release.wait(30), real(name, rec))[1] if rec["event"] == "close"
                        else real(name, rec))
    try:
        first = run_pass(vm)
        assert first is not None, "the pass never returned: the stop thread joined a stalled close write"
        assert not vm.systemd()["cathedral-vm-vm1.service"]["active"]
        assert [s["name"] for s in first["stopped"]] == ["vm1"]
        assert [e["error"] for e in first["errors"]] == ["history_stalled"]  # the close is still pending
        assert run_pass(vm) is not None  # and a later pass is not held either
    finally:
        release.set()
    # Once the journal answers again the close lands exactly once and history reads clean.
    time.sleep(0.3)
    assert len([e for e in vm.lines() if e["event"] == "close"]) == 1
    assert vm.m.read_history("vm1")["corrupt"] is False


def test_the_enforce_service_has_a_start_timeout_so_a_wedged_pass_cannot_block_the_timer(vm, monkeypatch):
    Path(os.environ["SYSTEMD_UNIT_DIR"]).mkdir(parents=True, exist_ok=True)
    vm.m.ensure_enforce_timer()
    text = (Path(os.environ["SYSTEMD_UNIT_DIR"]) / "cathedral-vm-enforce.service").read_text()
    assert "Type=oneshot" in text and "TimeoutStartSec=" in text
