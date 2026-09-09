"""Checks for the two defects the live TDX run exposed."""
from __future__ import annotations
import json
from datetime import datetime, timedelta, timezone
import pytest
from cathedral import miner_update_cli as cli


def test_a_container_that_just_started_is_not_yet_running(monkeypatch):
    """A crash-looping container is up for a moment at a time.

    Sampling one of those moments and calling it healthy is exactly how the
    live run committed an update to a miner that could not start.
    """

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    calls = {"n": 0}

    def fake_run(argv, timeout=300):
        calls["n"] += 1
        class R: pass
        r = R(); r.returncode = 0
        r.stdout = "active" if argv[0] == "systemctl" else f"true {now} img@sha256:x"
        r.stderr = ""
        return r

    monkeypatch.setattr(cli, "run", fake_run)
    monkeypatch.setattr(cli, "SETTLE_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(cli, "SETTLE_POLL_SECONDS", 0)
    from cathedral.miner_products import SN39_AUDIT_MINER
    assert cli.running_image(SN39_AUDIT_MINER) is None


def test_a_container_up_past_the_dwell_is_running(monkeypatch):
    started = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat().replace("+00:00", "Z")

    def fake_run(argv, timeout=300):
        class R: pass
        r = R(); r.returncode = 0
        r.stdout = "active" if argv[0] == "systemctl" else f"true {started} img@sha256:x"
        r.stderr = ""
        return r

    monkeypatch.setattr(cli, "run", fake_run)
    from cathedral.miner_products import SN39_AUDIT_MINER
    assert cli.running_image(SN39_AUDIT_MINER) == "img@sha256:x"


def test_an_activating_unit_is_not_running(monkeypatch):
    """systemd reports activating while restarting a failing service."""

    started = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat().replace("+00:00", "Z")

    def fake_run(argv, timeout=300):
        class R: pass
        r = R(); r.returncode = 0
        r.stdout = "activating" if argv[0] == "systemctl" else f"true {started} img@sha256:x"
        r.stderr = ""
        return r

    monkeypatch.setattr(cli, "run", fake_run)
    monkeypatch.setattr(cli, "SETTLE_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(cli, "SETTLE_POLL_SECONDS", 0)
    from cathedral.miner_products import SN39_AUDIT_MINER
    assert cli.running_image(SN39_AUDIT_MINER) is None


def test_docker_nanosecond_timestamps_parse(monkeypatch):
    started = "2026-09-09T09:00:00.123456789Z"
    assert cli._uptime_seconds(started) > 0


def test_an_unparseable_start_time_fails_safe():
    assert cli._uptime_seconds("not-a-time") == 0.0


def test_restart_is_refused_near_snapshot_expiry(tmp_path, monkeypatch):
    """The live failure: a restart re-reads a snapshot that has lapsed."""

    path = tmp_path / "va.json"
    soon = (datetime.now(timezone.utc) + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    path.write_text(json.dumps({"expires_at": soon}))
    monkeypatch.setattr(cli, "VALIDATOR_ACCESS_PATH", path)
    assert cli.safe_to_activate() is False


def test_restart_is_allowed_with_margin(tmp_path, monkeypatch):
    path = tmp_path / "va.json"
    later = (datetime.now(timezone.utc) + timedelta(seconds=3600)).isoformat().replace("+00:00", "Z")
    path.write_text(json.dumps({"expires_at": later}))
    monkeypatch.setattr(cli, "VALIDATOR_ACCESS_PATH", path)
    assert cli.safe_to_activate() is True


def test_an_unreadable_snapshot_is_unsafe(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "VALIDATOR_ACCESS_PATH", tmp_path / "missing.json")
    assert cli.safe_to_activate() is False
