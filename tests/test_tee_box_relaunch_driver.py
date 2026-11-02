"""Operator relaunch driver over DryRunHooks."""

from __future__ import annotations

from cathedral.tee_box.relaunch import RelaunchPhase
from cathedral.tee_box.relaunch_driver import DryRunHooks, run_relaunch_cycle


def test_dry_run_cycle_reaches_ready():
    hooks = DryRunHooks()
    result = run_relaunch_cycle("box-1", hooks, prior_boot_id="boot-dry-0")
    assert result.ok
    assert result.state.phase is RelaunchPhase.READY
    assert hooks.reboots == ["box-1"]
    assert result.state.boot_id == "boot-dry-1"
    assert "complete_admit" in result.steps


def test_dry_run_fails_when_boot_id_unchanged():
    hooks = DryRunHooks(boot_id="same", next_boot_id="same")
    # After reboot hook sets boot_id = next_boot_id ("same") — collide with prior.
    result = run_relaunch_cycle("box-1", hooks, prior_boot_id="same")
    assert not result.ok
    assert result.state.phase is RelaunchPhase.FAILED
    assert "fresh_boot_id_must_differ" in (result.state.failure_reason or "")
