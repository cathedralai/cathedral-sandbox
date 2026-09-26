"""Miner updater state machine checks.

docker and systemd are faked (``tests/miner_update_support.Harness``); every
file effect is real under a temporary root. Kept from #197: the floor is
burned before an attempt, the ``may_have_run`` latch, health means the running
container reports the released image, the lock, pause and status. Added: the
schema-based rollback rule on a live-like miner (F2), the snapshot re-check
before the swap (F3), ``reset-failed`` before a rollback start (F4), atomic
launcher delivery (F5), failed-release memory (F11), deferral alerting (F1),
pin, and ``resolve``.
"""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from cathedral.miner_bundle import link_target
from cathedral.miner_update_cli import MINIMUM_ACCESS_REMAINING_SECONDS, safe_to_activate
from cathedral.miner_updater import (
    DEFERRAL_ALERT_AFTER,
    EXIT_ALERT,
    EXIT_HALTED,
    EXIT_REFUSED,
    LEGACY,
    STAGE_MAY_HAVE_RUN,
    STAGE_PREPARED,
    describe_status,
    resolve,
    write_state,
)
from cathedral.validator_access import ValidatorAccessState
from tests.miner_update_support import DAY, NOW, OTHER_NETUID, Harness


@pytest.fixture()
def h(tmp_path) -> Harness:
    return Harness(tmp_path)


def activation_dir(h: Harness):
    return h.paths.miner_dir / str(h.active())


# --- adoption ----------------------------------------------------------------------------


def test_a_new_signed_digest_is_adopted(h):
    h.release(sequence=5)
    outcome = h.check()
    assert outcome.action == "activated", outcome.reason
    assert h.running_image() == h.new_image
    assert h.active().startswith("releases/")
    env = (activation_dir(h) / "release.env").read_text()
    assert f"{h.profile.image_variable}={h.new_image}\n" in env
    assert f"CATHEDRAL_NETUID={h.config.netuid}\n" in env
    assert f"CATHEDRAL_NETWORK={h.config.network}\n" in env
    assert h.systemctl_calls == [
        ("daemon-reload",),
        ("reset-failed", h.config.miner_unit),
        ("restart", h.config.miner_unit),
    ]
    current = h.state()["miner"]["current"]
    assert current["image"] == h.new_image and current["sequence"] == 5
    assert h.state()["last_check"]["action"] == "activated"


def test_the_timer_path_adopts_a_release_with_the_real_gate(h):
    """F1: the unattended path uses the real snapshot gate and activates.

    ``tests/test_miner_update_unit.py`` runs this same check inside an
    emulation of the unit's mount sandbox.
    """

    h.paths.snapshot.parent.mkdir(parents=True)
    later = datetime.now(timezone.utc) + timedelta(seconds=MINIMUM_ACCESS_REMAINING_SECONDS + 600)
    h.paths.snapshot.write_text(json.dumps({"expires_at": later.isoformat().replace("+00:00", "Z")}))
    h.release(sequence=5)
    outcome = h.check(safe_to_activate=lambda: safe_to_activate(h.paths.snapshot))
    assert outcome.action == "activated", outcome.reason


def test_running_the_same_release_twice_is_a_no_op(h):
    h.release(sequence=5)
    h.check()
    outcome = h.check()
    assert outcome.action == "current"
    assert h.restarts() == 1


def test_a_fresh_signature_of_the_same_release_does_not_restart(h):
    """Weekly re-signing for freshness bumps the sequence but changes nothing."""

    h.release(sequence=5)
    h.check()
    h.release(sequence=6)
    outcome = h.check()
    assert outcome.action == "current"
    assert h.restarts() == 1
    assert h.state()["miner"]["current"]["sequence"] == 6


def test_the_operator_env_file_is_never_rewritten(h, tmp_path):
    """The pin moves through release.env; the operator's file is not the updater's."""

    h.release(sequence=5)
    h.check()
    assert not list(h.paths.root.glob("etc/cathedral/*.env"))


# --- refusals that change nothing --------------------------------------------------------


def _refused_and_untouched(h: Harness, outcome) -> None:
    assert outcome.action == "refused", outcome.reason
    assert outcome.exit_status == EXIT_REFUSED
    assert h.restarts() == 0
    assert h.active() == LEGACY
    assert h.running_image() == h.old_image
    assert h.state()["last_refusal"]["action"] == "refused"


def test_an_unsigned_record_is_refused(h):
    record = json.loads(h.release(sequence=5))
    del record["signature"]
    h.metadata = json.dumps(record).encode()
    _refused_and_untouched(h, h.check())
    assert h.state()["floors"] == {}


def test_a_record_signed_by_an_untrusted_key_is_refused(h):
    from tests.miner_update_support import OTHER_KEY

    h.release(sequence=5, key=OTHER_KEY, key_id="stable-1")
    _refused_and_untouched(h, h.check())


@pytest.mark.parametrize(
    "timing",
    [
        {"issued": NOW - 8 * DAY, "lifetime": 7 * DAY},
        {"issued": NOW + 301, "lifetime": 7 * DAY},
        {"issued": NOW - 60, "lifetime": 15 * DAY},
    ],
    ids=["expired", "not-yet-valid", "over-lifetime"],
)
def test_stale_or_premature_records_are_refused(h, timing):
    h.release(sequence=5, **timing)
    _refused_and_untouched(h, h.check())


def test_a_rolled_back_sequence_is_refused(h):
    h.release(sequence=5)
    h.check()
    h.release(sequence=4, image=h.image("3"))
    outcome = h.check()
    assert outcome.action == "refused" and "rolls back" in outcome.reason
    assert h.running_image() == h.new_image


def test_equivocation_at_the_same_sequence_is_refused(h):
    h.release(sequence=5)
    h.check()
    h.release(sequence=5, image=h.image("3"))
    outcome = h.check()
    assert "equivocates" in outcome.reason


def test_a_record_for_another_netuid_is_refused(h):
    h.release(sequence=5, netuid=OTHER_NETUID)
    _refused_and_untouched(h, h.check())


def test_the_bootstrap_floor_refuses_old_records(tmp_path):
    h = Harness(tmp_path, minimum_sequence=5)
    h.release(sequence=5)
    _refused_and_untouched(h, h.check())
    h.release(sequence=6)
    assert h.check().action == "activated"


def test_a_failed_preparation_burns_its_sequence_and_changes_nothing(h):
    h.prepare_raises = True
    h.release(sequence=5)
    outcome = h.check()
    _refused_and_untouched(h, outcome)
    assert h.state()["floors"]["stable"]["sequence"] == 5
    assert h.state()["miner"]["stage"] is None
    h.release(sequence=5, image=h.image("3"))
    assert "equivocates" in h.check().reason


# --- deferral (F1 reporting, F3) -----------------------------------------------------------


def test_an_unsafe_moment_defers_without_restarting(h):
    h.safe = [False]
    h.release(sequence=5)
    outcome = h.check()
    assert outcome.action == "deferred" and outcome.exit_status == 0
    assert h.restarts() == 0 and h.prepared == []
    assert h.state()["consecutive_deferrals"] == 1


def test_repeated_deferral_raises_an_alert(h):
    h.safe = [False]
    h.release(sequence=5)
    for _ in range(DEFERRAL_ALERT_AFTER - 1):
        assert h.check().exit_status == 0
    outcome = h.check()
    assert outcome.exit_status == EXIT_ALERT and outcome.alert
    assert h.state()["consecutive_deferrals"] == DEFERRAL_ALERT_AFTER
    h.safe = [True]
    assert h.check().action == "activated"
    assert h.state()["consecutive_deferrals"] == 0


def test_the_snapshot_is_checked_again_after_the_pull(h):
    """F3: a slow pull can use up the margin checked before it."""

    h.safe = [True, False]
    h.release(sequence=5)
    outcome = h.check()
    assert outcome.action == "deferred"
    assert "during the pull" in outcome.reason
    assert h.prepared == [h.new_image]
    assert h.restarts() == 0 and h.active() == LEGACY
    assert h.state()["miner"]["stage"] is None


# --- pause and pin --------------------------------------------------------------------------


def test_pause_stops_everything(h):
    h.paths.pause_file.write_text("maintenance\n")
    h.release(sequence=5)
    outcome = h.check()
    assert outcome.action == "paused"
    assert h.fetches == 0 and h.restarts() == 0


def test_a_paused_miner_does_not_contend_for_the_lock(h):
    h.paths.pause_file.write_text("")
    h.paths.state_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(h.paths.lock_file, os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        assert h.check().action == "paused"
    finally:
        os.close(fd)


def test_a_pin_holds_the_miner_at_its_version(h):
    h.release(sequence=5, version="2026.09.01")
    h.check()
    h.paths.pin_file.write_text("2026.09.01\n")
    h.release(sequence=6, image=h.image("3"), version="2026.09.20")
    outcome = h.check()
    assert outcome.action == "held"
    assert h.running_image() == h.new_image
    assert h.state()["floors"]["stable"]["sequence"] == 6
    h.paths.pin_file.unlink()
    h.release(sequence=7, image=h.image("3"), version="2026.09.20")
    assert h.check().action == "activated"


def test_an_unreadable_pin_refuses_rather_than_guesses(h):
    h.paths.pin_file.write_text("not a version at all\n")
    h.release(sequence=5)
    assert h.check().action == "refused"


def test_a_second_concurrent_check_is_refused(h):
    h.release(sequence=5)
    h.paths.state_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(h.paths.lock_file, os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        outcome = h.check()
    finally:
        os.close(fd)
    assert outcome.action == "refused" and "already running" in outcome.reason
    assert h.restarts() == 0


# --- rollback (F2, F4, F11) -------------------------------------------------------------------


def _activate_first(h: Harness) -> None:
    h.release(sequence=5)
    assert h.check().action == "activated"


def test_a_schema_compatible_failure_rolls_back_and_is_remembered(h):
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad)
    outcome = h.check()
    assert outcome.action == "rolled_back", outcome.reason
    assert outcome.exit_status == EXIT_REFUSED
    assert h.running_image() == h.new_image
    assert h.state()["failed"]["sequence"] == 6
    restarts = h.restarts()
    again = h.check()
    assert again.action == "refused" and "already failed" in again.reason
    assert h.restarts() == restarts, "a failed release is not retried every hour (F11)"


def test_rollback_works_on_a_live_miner_that_writes_its_database(h):
    """F2: the old image writes its replay database during the attempt.

    #197 fingerprinted this directory and halted whenever it changed, which on
    a live miner is almost every time (review probe B). The schema rule does
    not look at it, so the host rolls back and keeps serving.
    """

    _activate_first(h)
    state_dir = h.paths.root / "var/lib/cathedral/validator-access"
    state_dir.mkdir(parents=True, mode=0o700)
    store = ValidatorAccessState(str(state_dir / "validator-access.sqlite"))
    now = datetime.now(timezone.utc)
    served = []

    def validator_probe() -> None:
        nonce = os.urandom(16).hex()
        assert store.check_and_record_request(
            "5" + "A" * 47, nonce, now=now, expires_at=now + timedelta(minutes=5)
        )
        served.append(nonce)

    before = (state_dir / "validator-access.sqlite").read_bytes()
    h.on_prepare = validator_probe
    h.on_restart = lambda image: validator_probe() if image == h.new_image else None
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad)
    outcome = h.check()
    assert (state_dir / "validator-access.sqlite").read_bytes() != before
    assert len(served) == 2
    assert outcome.action == "rolled_back", outcome.reason
    assert h.running_image() == h.new_image
    assert h.state()["miner"]["stage"] is None
    with sqlite3.connect(state_dir / "validator-access.sqlite") as connection:
        assert connection.execute("SELECT COUNT(*) FROM validator_request_replays").fetchone()[0] == 2


def test_a_launcher_only_change_rolls_back_to_the_legacy_launcher(h):
    """Same image, new launcher: the previous image trivially reads its own state.

    This is also the rollout's first step: sign the image hosts already run, so
    every host moves from its own launcher to the managed one with a rollback
    that is always allowed.
    """

    h.managed_fails = True
    h.release(sequence=5, image=h.old_image)
    outcome = h.check()
    assert outcome.action == "rolled_back", outcome.reason
    assert "image is unchanged" in outcome.reason
    assert h.active() == LEGACY
    assert h.running_image() == h.old_image


def test_a_schema_bump_that_fails_halts_for_an_operator(h):
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad, state_schema=2)
    outcome = h.check()
    assert outcome.action == "halted" and outcome.exit_status == EXIT_HALTED
    assert "state schema 2" in outcome.reason
    assert h.state()["miner"]["stage"] == STAGE_MAY_HAVE_RUN
    again = h.check()
    assert again.action == "halted"
    status = describe_status(h.paths, h.config)
    assert status["needs_operator"] is True


def test_a_first_activation_with_an_unknown_previous_schema_halts(h):
    """From the legacy launcher with a different image, the old schema is unknown."""

    bad = h.new_image
    h.broken_images.add(bad)
    h.release(sequence=5)
    assert h.check().action == "halted"


def test_resolve_restore_previous_puts_the_previous_release_back(h):
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad, state_schema=2)
    h.check()
    outcome = resolve(h.host(), "restore-previous")
    assert outcome.action == "resolved", outcome.reason
    assert h.running_image() == h.new_image
    assert h.state()["miner"]["stage"] is None
    assert h.state()["failed"]["sequence"] == 6


def test_resolve_accept_release_commits_a_running_release(h):
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad, state_schema=2)
    h.check()
    h.broken_images.discard(bad)
    h.running[h.profile.container] = bad  # the operator fixed and started it
    outcome = resolve(h.host(), "accept-release")
    assert outcome.action == "resolved", outcome.reason
    assert h.state()["miner"]["current"]["image"] == bad


def test_resolve_retry_clears_failure_memory(h):
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad)
    h.check()
    resolve(h.host(), "retry")
    h.broken_images.discard(bad)
    assert h.check().action == "activated"


def test_reset_failed_runs_before_the_rollback_start(h):
    """F4: a crash-looping release can trip the start limit, refusing the rollback start."""

    _activate_first(h)
    h.systemctl_calls.clear()
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad)
    h.check()
    unit = h.config.miner_unit
    assert h.systemctl_calls[-3:] == [("daemon-reload",), ("reset-failed", unit), ("restart", unit)]


def test_a_rollback_whose_restart_fails_halts(h):
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)

    def fail_after_first(image):
        h.restart_raises = True

    h.on_restart = fail_after_first
    h.release(sequence=6, image=bad)
    outcome = h.check()
    assert outcome.action == "halted"
    assert "may be running nothing" in outcome.reason


def test_a_rollback_that_does_not_bring_the_old_image_back_halts(h):
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.update({bad, h.new_image})
    h.release(sequence=6, image=bad)
    outcome = h.check()
    assert outcome.action == "halted" and "did not come back" in outcome.reason


# --- atomic launcher delivery (F5) ---------------------------------------------------------------


def test_a_launcher_update_is_applied_atomically(h):
    _activate_first(h)
    first = h.active()
    old_launcher = (activation_dir(h) / "launcher").read_bytes()
    h.release(sequence=6, image=h.image("3"), bundle={"launcher_suffix": b"# launcher v2\n"})
    assert h.check().action == "activated"
    second = h.active()
    assert second != first
    new_dir = activation_dir(h)
    assert (new_dir / "launcher").read_bytes() == old_launcher + b"# launcher v2\n"
    assert h.image("3") in (new_dir / "release.env").read_text()
    # One symlink selects launcher, pin and unit drop-in together.
    assert h.paths.miner_current.is_symlink()
    for name in ("launcher", "release.env", "unit.conf"):
        assert (h.paths.miner_current / name).resolve().parent == new_dir.resolve()
    # The previous activation is untouched, so a rollback is one rename back.
    assert (h.paths.miner_dir / first / "launcher").read_bytes() == old_launcher
    assert os.stat(new_dir / "launcher").st_mode & 0o777 == 0o555


def test_a_crash_after_the_flip_is_resolved_on_the_next_run(h):
    """The latch survives a crash between the flip and the health check."""

    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))

    def die(image):
        raise KeyboardInterrupt("power lost")

    h.on_restart = die
    with pytest.raises(KeyboardInterrupt):
        h.check()
    assert h.state()["miner"]["stage"] == STAGE_MAY_HAVE_RUN
    h.on_restart = None
    outcome = h.check()
    assert outcome.action == "current", outcome.reason
    assert h.state()["miner"]["current"]["image"] == h.image("3")


def test_a_tampered_activation_directory_is_refused(h):
    _activate_first(h)
    first = activation_dir(h)
    h.release(sequence=6, image=h.image("3"))
    assert h.check().action == "activated"
    launcher = first / "launcher"
    os.chmod(launcher, 0o755)
    launcher.write_bytes(b"#!/bin/sh\necho tampered\n")
    os.chmod(launcher, 0o555)
    h.release(sequence=7)  # the first release's image and bundle again
    outcome = h.check()
    assert outcome.action == "refused" and "modified" in outcome.reason
    assert h.running_image() == h.image("3")


# --- reconcile -----------------------------------------------------------------------------------


def _write_stage(h: Harness, stage, pending) -> None:
    state = h.state()
    state["miner"]["stage"] = stage
    state["miner"]["pending"] = pending
    write_state(h.paths.state_file, state)


def test_a_prepared_stage_is_cleared_and_retried(h):
    _write_stage(h, STAGE_PREPARED, {"release": {}})
    h.release(sequence=5)
    assert h.check().action == "activated"


def test_an_interrupted_activation_without_a_pending_record_halts(h):
    _write_stage(h, STAGE_MAY_HAVE_RUN, None)
    h.release(sequence=5)
    assert h.check().action == "halted"


def test_an_interrupted_activation_before_the_flip_is_cleared(h):
    _activate_first(h)
    active = h.active()
    _write_stage(
        h,
        STAGE_MAY_HAVE_RUN,
        {
            "release": {"image": h.image("3"), "state_schema": 1},
            "target": "releases/" + "0" * 64,
            "container": h.profile.container,
            "previous_target": active,
            "previous_container": h.profile.container,
            "previous_image": h.new_image,
            "previous_state_schema": 1,
        },
    )
    assert h.check().action == "current"
    assert h.state()["miner"]["stage"] is None


def test_an_interrupted_activation_with_nothing_running_halts(h):
    _activate_first(h)
    active = h.active()
    h.running[h.profile.container] = None
    _write_stage(
        h,
        STAGE_MAY_HAVE_RUN,
        {
            "release": {"image": h.image("3"), "state_schema": 1},
            "target": "releases/" + "0" * 64,
            "container": h.profile.container,
            "previous_target": active,
            "previous_container": h.profile.container,
            "previous_image": h.new_image,
            "previous_state_schema": 1,
        },
    )
    assert h.check().action == "halted"


# --- status ----------------------------------------------------------------------------------------


def test_status_shows_the_release_the_last_check_and_the_last_refusal(h):
    _activate_first(h)
    h.release(sequence=4, image=h.image("3"))
    h.check()
    h.paths.pause_file.write_text("")
    h.paths.pin_file.write_text("2026.09.26\n")
    status = describe_status(h.paths, h.config)
    assert status["miner"]["current_release"]["image"] == h.new_image
    assert status["miner"]["active"] == h.active()
    assert status["last_check"]["action"] == "refused"
    assert "rolls back" in status["last_refusal"]["reason"]
    assert status["paused"] is True
    assert status["pinned_version"] == "2026.09.26"
    assert status["updater"]["current"] == f"releases/{h.tree_a}"
    assert status["config"]["netuid"] == h.config.netuid
    assert status["needs_operator"] is False


def test_status_works_with_no_state_yet(h):
    status = describe_status(h.paths, None)
    assert status["miner"]["current_release"] is None
    assert status["last_check"] is None
    assert link_target(h.paths.miner_current) == LEGACY
