"""Paths where the miner updater went quiet or disagreed with its docs (review round 6).

Run with the worktree venv:
    .venv/bin/python -m pytest -q -p no:cacheprovider tests/probe_sn94_updater_silence.py

Each probe asserts the behaviour the docs promise or the trust-set code already
has. A failing probe is the finding.
"""

from __future__ import annotations

from pathlib import Path

from cathedral.miner_updater import (
    EXIT_ALERT,
    EXIT_REFUSED,
    UNVERIFIED_ALERT_AFTER,
    describe_status,
)
from tests.miner_update_support import Harness

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "deploy/miner-update/install-miner-update.sh"


def test_a_dead_miner_is_paged_even_when_the_updater_state_is_unreadable(tmp_path):
    """An unreadable trust.json alerts at once (TrustSetUnavailable). An
    unreadable state.json should not be quieter: `_locked` returns the
    read_state refusal before `_after_check`, so the unverified counter, the
    miner health check and the alert path never run, and the unit sees exit 10
    (SuccessExitStatus) forever.
    """

    h = Harness(tmp_path)
    h.release(sequence=5)
    committed = h.commit()
    assert committed.action == "current", committed.reason

    # Control: with readable state, a check that finds the miner down pages.
    h.running[h.profile.container] = None
    control = h.check()
    assert control.action == "unhealthy" and control.exit_status == EXIT_ALERT and control.alert

    # The state file is now unreadable (disk damage, a stray edit, a bad write
    # by another tool). The miner is still down.
    h.paths.state_file.write_bytes(b"{this is not json")
    outcomes = [h.check() for _ in range(UNVERIFIED_ALERT_AFTER + 1)]
    assert all(o.exit_status == EXIT_REFUSED and not o.alert for o in outcomes) or any(
        o.alert for o in outcomes
    )
    assert any(o.alert for o in outcomes), (
        "seven checks with the miner down and state.json unreadable: every one exited 10 "
        f"(unit success) and none paged; first reason: {outcomes[0].reason!r}"
    )


def test_status_still_answers_when_the_updater_state_is_unreadable(tmp_path):
    """`cathedral-miner-update status` is the operator's view. It should say
    the state is unreadable rather than refuse outright, as it does for an
    unreadable pin or trust set."""

    h = Harness(tmp_path)
    h.paths.state_file.write_bytes(b"{this is not json")
    try:
        report = describe_status(h.paths, h.config, expected_uid=h.host().expected_uid)
    except Exception as exc:  # noqa: BLE001 - the probe reports what happened
        raise AssertionError(f"status refuses outright: {type(exc).__name__}: {exc}") from exc
    assert "state" in report


def test_minimum_sequence_is_a_floor_the_installer_describes_as_one(tmp_path):
    """The code treats --minimum-sequence as a floor that must be exceeded. The
    installer used to call it "the lowest sequence this host may accept", so
    an operator who passed the current sequence got refusals for a week."""

    text = INSTALLER.read_text()
    assert "lowest channel sequence this host may accept" not in text
    assert "only channel records with a" in text and "higher sequence" in text
    h = Harness(tmp_path, minimum_sequence=5)
    h.release(sequence=5)
    assert h.check().action != "activated"  # at the floor: refused, as documented now
    h.release(sequence=6)
    assert h.check().action == "activated"
