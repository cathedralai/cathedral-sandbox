"""The operator machine's sweeper units (Q5): reconcile every minute, the folder wipe every 15 min."""
from __future__ import annotations

import configparser
import shutil
import subprocess
from pathlib import Path

import pytest

UNITS = Path(__file__).resolve().parents[1] / "ops" / "custom-guest" / "systemd"
RUNBOOK = Path(__file__).resolve().parents[1] / "ops" / "custom-guest" / "OPERATOR.md"


def unit(name: str) -> configparser.ConfigParser:
    c = configparser.ConfigParser(strict=False, interpolation=None)
    c.optionxform = str
    c.read_string((UNITS / name).read_text())
    return c


@pytest.mark.parametrize("what,calendar", [("reconcile", "*-*-* *:*:00"), ("wipe", "*-*-* *:00/15:00")])
def test_each_timer_runs_its_sweep_pass(what, calendar):
    timer = unit(f"cathedral-custom-guest-{what}@.timer")
    assert timer["Timer"]["OnCalendar"] == calendar
    assert timer["Install"]["WantedBy"] == "timers.target"
    svc = unit(f"cathedral-custom-guest-{what}@.service")["Service"]
    assert svc["Type"] == "oneshot" and svc["User"] == "cathedral-cg"
    assert svc["ExecStart"].endswith(f"/ops/custom-guest/custom-guest.sh sweep --hotel %i --what {what}")
    assert svc["EnvironmentFile"] == "/etc/cathedral/custom-guest-operator.env"
    assert svc["Environment"] == "CG_HOME=/var/lib/cathedral-custom-guest"
    assert svc["SuccessExitStatus"] == "2"  # alerts raised is not a failed run
    if shutil.which("systemd-analyze"):
        r = subprocess.run(["systemd-analyze", "calendar", calendar], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


def test_the_wipe_service_outlasts_the_host_phases_deadline():
    svc = unit("cathedral-custom-guest-wipe@.service")["Service"]
    assert svc["TimeoutStartSec"] == "35min"  # custom_guest_host.py PHASES["wipe"] is 1800 s


def test_the_runbook_installs_the_units_it_names_and_gates_a_launch_on_them():
    text = RUNBOOK.read_text()
    for name in sorted(p.name for p in UNITS.iterdir()):
        assert name.split("@")[0] in text
    assert "systemctl enable --now cathedral-custom-guest-reconcile@<hotel>.timer" in text
    assert "no customer launch begins on a hotel until" in text
