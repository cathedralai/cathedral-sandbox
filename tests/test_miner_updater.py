"""Miner updater state machine checks.

docker and systemd are faked (``tests/miner_update_support.Harness``); every
file effect is real under a temporary root. Kept from #197: the floor is
burned before an attempt, the ``may_have_run`` latch, the lock, pause and
status. Added: the schema-based rollback rule on a live-like miner (F2), the
snapshot re-check before the swap (F3), ``reset-failed`` before every start
(F4), atomic launcher delivery (F5), and every probe of the activation review
(P1 to P8): probation, the flip time, retrying the previous release, the
registry-independent launcher, schema labels, operator stops, ``resolve --abandon``.
"""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from cathedral.miner_update_cli import MINIMUM_ACCESS_REMAINING_SECONDS, safe_to_activate
from cathedral.miner_updater import (
    DEFERRAL_ALERT_AFTER,
    PROBATION_MINIMUM_SECONDS,
    UNVERIFIED_ALERT_AFTER,
    EXIT_ALERT,
    EXIT_HALTED,
    EXIT_REFUSED,
    LEGACY,
    STAGE_MAY_HAVE_RUN,
    STAGE_PREPARED,
    STAGE_PROBATION,
    MinerUpdateError,
    describe_status,
    pin_document,
    resolve,
    write_state,
)
from cathedral.validator_access import ValidatorAccessState
from tests.miner_update_support import DAY, NETUID, NOW, OTHER_KEY, OTHER_NETUID, Harness


@pytest.fixture()
def h(tmp_path) -> Harness:
    return Harness(tmp_path)


def activation_dir(h: Harness):
    return h.paths.miner_dir / str(h.active())


def stage(h: Harness):
    return h.state()["miner"]["stage"]


def _activate_first(h: Harness) -> None:
    h.release(sequence=5)
    assert h.commit().action == "current"


# --- adoption ----------------------------------------------------------------------------


def test_a_new_signed_digest_is_adopted_and_committed_after_probation(h):
    h.release(sequence=5)
    outcome = h.check()
    assert outcome.action == "activated", outcome.reason
    assert outcome.verified is True
    assert stage(h) == STAGE_PROBATION
    assert h.running_image() == h.new_image
    env = (activation_dir(h) / "release.env").read_text()
    assert f"{h.profile.image_variable}={h.new_image}\n" in env
    assert f"CATHEDRAL_NETUID={h.config.netuid}\n" in env
    assert f"CATHEDRAL_NETWORK={h.config.network}\n" in env
    assert h.systemctl_calls == [
        ("daemon-reload",),
        ("reset-failed", h.config.miner_unit),
        ("restart", h.config.miner_unit),
    ]
    h.now += 3600
    confirmed = h.check()
    assert confirmed.action == "current", confirmed.reason
    current = h.state()["miner"]["current"]
    assert current["image"] == h.new_image and current["schema_verified"] is True
    assert stage(h) is None


def test_the_timer_path_adopts_a_release_with_the_real_gate(h):
    """F1: the unattended path uses the real snapshot gate and activates.

    ``tests/test_miner_update_unit.py`` runs this same check inside an
    emulation of the unit's mount sandbox.
    """

    now = datetime.now(timezone.utc)
    h.paths.snapshot.parent.mkdir(parents=True)
    h.paths.snapshot.write_text(
        json.dumps(
            {
                "generated_at": now.isoformat().replace("+00:00", "Z"),
                "expires_at": (now + timedelta(seconds=900)).isoformat().replace("+00:00", "Z"),
            }
        )
    )
    h.release(sequence=5)
    outcome = h.check(safe_to_activate=lambda: safe_to_activate(h.paths.snapshot))
    assert outcome.action == "activated", outcome.reason


def test_running_the_same_release_twice_is_a_no_op(h):
    _activate_first(h)
    restarts = h.restarts()
    assert h.check().action == "current"
    assert h.restarts() == restarts


def test_a_fresh_signature_of_the_same_release_does_not_restart(h):
    """Weekly re-signing for freshness bumps the sequence but changes nothing."""

    _activate_first(h)
    restarts = h.restarts()
    h.release(sequence=6)
    assert h.check().action == "current"
    assert h.restarts() == restarts
    assert h.state()["miner"]["current"]["sequence"] == 6


def test_the_operator_env_file_is_never_rewritten(h):
    _activate_first(h)
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
    outcome = h.check()
    _refused_and_untouched(h, outcome)
    assert outcome.verified is False
    assert h.state()["floors"] == {}


def test_a_record_signed_by_an_untrusted_key_is_refused(h):
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


def test_hostile_channel_bytes_are_a_refusal_not_a_crash(h):
    """Trust review P0-1: an integer past Python's digit limit crashed the updater."""

    h.metadata = b"[" + b"1" * 5000 + b"]"
    outcome = h.check()
    _refused_and_untouched(h, outcome)
    assert outcome.verified is False


def test_a_fetch_that_raises_anything_is_a_refusal(h):
    import http.client

    def truncated():
        raise http.client.IncompleteRead(b"par", 10)

    outcome = h.check(fetch_metadata=truncated)
    _refused_and_untouched(h, outcome)


def test_an_unexpected_exception_in_the_updater_is_a_documented_fault(h):
    h.release(sequence=5)

    def broken_gate():
        raise KeyError("a bug")

    outcome = h.check(safe_to_activate=broken_gate)
    assert outcome.action == "fault" and outcome.exit_status == 13


def test_a_rolled_back_sequence_is_refused(h):
    _activate_first(h)
    h.release(sequence=4, image=h.image("3"))
    outcome = h.check()
    assert outcome.action == "refused" and "rolls back" in outcome.reason
    assert h.running_image() == h.new_image


def test_equivocation_at_the_same_sequence_is_refused(h):
    _activate_first(h)
    h.release(sequence=5, image=h.image("3"))
    assert "equivocates" in h.check().reason


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
    _refused_and_untouched(h, h.check())
    assert h.state()["floors"]["stable"]["sequence"] == 5
    assert stage(h) is None
    h.release(sequence=5, image=h.image("3"))
    assert "equivocates" in h.check().reason


# --- deferral and the gate (F1 reporting, F3, #211) -----------------------------------------


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
    h.safe = [True]
    assert h.check().action == "activated"
    assert h.state()["consecutive_deferrals"] == 0


def test_a_refusal_does_not_reset_the_deferral_count(h):
    """Documented: a channel blip must not hide a gate that never opens."""

    h.safe = [False]
    h.release(sequence=5)
    h.check()
    good = h.metadata
    h.metadata = b"not json"
    h.check()
    h.metadata = good
    h.check()
    assert h.state()["consecutive_deferrals"] == 2


def test_a_gate_that_can_never_pass_alerts_at_once(h):
    """Activation review P2: a snapshot shorter than the margin plus refresh."""

    now = datetime.now(timezone.utc)
    h.paths.snapshot.parent.mkdir(parents=True)
    h.paths.snapshot.write_text(
        json.dumps(
            {
                "generated_at": now.isoformat().replace("+00:00", "Z"),
                "expires_at": (now + timedelta(seconds=600)).isoformat().replace("+00:00", "Z"),
            }
        )
    )
    h.release(sequence=5)
    outcome = h.check(safe_to_activate=lambda: safe_to_activate(h.paths.snapshot))
    assert outcome.action == "deferred" and outcome.exit_status == EXIT_ALERT
    assert "lengthen the snapshot lifetime" in outcome.reason
    assert MINIMUM_ACCESS_REMAINING_SECONDS < 900


def test_the_snapshot_is_checked_again_after_the_pull(h):
    """F3: a slow pull can use up the margin checked before it."""

    h.safe = [True, False]
    h.release(sequence=5)
    outcome = h.check()
    assert outcome.action == "deferred" and "during the pull" in outcome.reason
    assert h.prepared == [h.new_image]
    assert h.restarts() == 0 and h.active() == LEGACY
    assert stage(h) is None


def test_a_miner_its_operator_stopped_is_not_started(h):
    """Activation review P8."""

    h.operator_stopped = True
    h.running[h.profile.container] = None
    h.release(sequence=5)
    outcome = h.check()
    assert outcome.action == "deferred" and "never starts a stopped miner" in outcome.reason
    # An inactive miner on a host that is not paused pages (activation re-review P1).
    assert outcome.exit_status == EXIT_ALERT
    assert h.restarts() == 0
    assert h.running_image() is None


# --- nothing fails silently (activation re-review P2) --------------------------------------


def test_a_dead_miner_after_a_rollback_alerts_although_the_check_only_refuses(h):
    """Probe A9: the channel still offers the failed release; the refusal is quiet,
    the dead miner is not."""

    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad)
    assert h.check().action == "rolled_back"
    h.running[h.profile.container] = None
    h.now += 86400
    h.release(sequence=7, image=bad)
    outcome = h.check()
    assert outcome.action == "unhealthy" and outcome.exit_status == EXIT_ALERT
    assert "already failed" in outcome.reason


def test_a_dead_miner_on_a_pinned_host_alerts(h):
    _activate_first(h)
    h.paths.pin_file.write_bytes(pin_document(h.state()["miner"]["current"]))
    h.release(sequence=6, image=h.image("5"))
    assert h.check().action == "held"
    h.running[h.profile.container] = None
    h.now += 3600
    outcome = h.check()
    assert outcome.action == "unhealthy" and outcome.exit_status == EXIT_ALERT and "held" in outcome.reason


def test_a_restart_on_a_quiet_host_alerts_once(h):
    _activate_first(h)
    h.paths.pin_file.write_bytes(pin_document(h.state()["miner"]["current"]))
    h.release(sequence=6, image=h.image("5"))
    assert h.check().action == "held"
    h.nrestarts += 1
    assert h.check().action == "unhealthy"
    assert h.check().action == "held"


def test_an_expired_channel_alerts_after_six_checks(h):
    """Probe A11: the signer stopped re-signing. Refusals succeed, but not forever."""

    _activate_first(h)
    h.now += 30 * DAY
    statuses = []
    for _ in range(UNVERIFIED_ALERT_AFTER):
        h.now += 3600
        statuses.append(h.check().exit_status)
    assert statuses[:-1] == [EXIT_REFUSED] * (UNVERIFIED_ALERT_AFTER - 1)
    assert statuses[-1] == EXIT_ALERT
    assert h.state()["consecutive_unverified"] == UNVERIFIED_ALERT_AFTER
    h.release(sequence=6)
    assert h.check().verified is True
    assert h.state()["consecutive_unverified"] == 0


def test_a_withheld_channel_alerts_after_six_checks(h):
    _activate_first(h)

    def withheld():
        raise MinerUpdateError("the server answered 404")

    outcomes = [h.check(fetch_metadata=withheld) for _ in range(UNVERIFIED_ALERT_AFTER)]
    assert outcomes[-1].exit_status == EXIT_ALERT and "no verified channel record" in outcomes[-1].reason


def test_a_lost_or_corrupt_trust_set_alerts_at_once(h):
    _activate_first(h)
    h.paths.trust_file.write_text("{}")
    h.release(sequence=6)
    outcome = h.check()
    assert outcome.exit_status == EXIT_ALERT and "--repair-trust-set" in outcome.reason
    h.paths.trust_file.unlink()
    assert h.check().exit_status == EXIT_ALERT


def test_a_trust_write_interrupted_between_its_two_files_is_finished_forward(h, monkeypatch):
    """Trust re-review P3: the backup is written first, so a crash leaves it
    ahead, never behind, and the next check completes the write."""

    from cathedral import miner_updater
    from cathedral.miner_release import rotate_trust
    from cathedral.miner_updater import load_trust_state, trust_backup_path, write_trust_state
    from tests.miner_update_support import DEFAULT_TRUST, trust_root_bytes

    uid = os.getuid()
    old = load_trust_state(h.paths.trust_file, expected_uid=uid)
    retired = {"canary-1": DEFAULT_TRUST["canary-1"], "stable-2": (OTHER_KEY, ["stable"])}
    new = rotate_trust(old, trust_root_bytes(retired), signing_key_id="stable-2", channel="stable")
    real = miner_updater._atomic_write

    def crash_on_the_live_file(path, body, *, mode):
        if path == h.paths.trust_file:
            raise KeyboardInterrupt("power lost")
        real(path, body, mode=mode)

    monkeypatch.setattr(miner_updater, "_atomic_write", crash_on_the_live_file)
    with pytest.raises(KeyboardInterrupt):
        write_trust_state(h.paths.trust_file, new)
    monkeypatch.setattr(miner_updater, "_atomic_write", real)
    assert load_trust_state(trust_backup_path(h.paths.trust_file), expected_uid=uid).generation == 2
    assert load_trust_state(h.paths.trust_file, expected_uid=uid).generation == 1
    h.release(sequence=5, key=OTHER_KEY, key_id="stable-2", bundle={"trust": retired})
    h.check()
    assert load_trust_state(h.paths.trust_file, expected_uid=uid).generation == 2
    assert load_trust_state(trust_backup_path(h.paths.trust_file), expected_uid=uid).generation == 2
    assert h.state()["trust_generation"] == 2


def test_every_check_keeps_a_current_backup_of_the_trust_set(h):
    from cathedral.miner_updater import load_trust_state, trust_backup_path

    backup = trust_backup_path(h.paths.trust_file)
    backup.unlink()
    h.release(sequence=5)
    h.check()
    assert load_trust_state(backup, expected_uid=os.getuid()).as_document() == load_trust_state(
        h.paths.trust_file, expected_uid=os.getuid()
    ).as_document()


# --- pause and pin --------------------------------------------------------------------------


def test_pause_stops_everything(h):
    h.paths.pause_file.write_text("maintenance\n")
    h.release(sequence=5)
    assert h.check().action == "paused"
    assert h.fetches == 0 and h.restarts() == 0


def test_a_paused_miner_does_not_contend_for_the_lock(h):
    h.paths.pause_file.write_text("")
    fd = os.open(h.paths.lock_file, os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        assert h.check().action == "paused"
    finally:
        os.close(fd)


def test_a_pin_holds_the_release_by_content_not_by_version(h):
    """Trust review P2: a same-version re-sign with other content is still held."""

    h.release(sequence=5, version="2026.09.01")
    h.commit()
    h.paths.pin_file.write_bytes(pin_document(h.state()["miner"]["current"]))
    h.release(sequence=6, image=h.image("3"), version="2026.09.01")
    outcome = h.check()
    assert outcome.action == "held"
    assert h.running_image() == h.new_image
    assert h.state()["floors"]["stable"]["sequence"] == 6
    h.release(sequence=7, version="2026.09.01")
    assert h.check().action == "current"
    h.paths.pin_file.unlink()
    h.release(sequence=8, image=h.image("3"), version="2026.09.20")
    assert h.check().action == "activated"


def test_an_unreadable_pin_refuses_rather_than_guesses(h):
    h.paths.pin_file.write_text("not a pin\n")
    h.release(sequence=5)
    assert h.check().action == "refused"


def test_a_second_concurrent_check_is_refused(h):
    h.release(sequence=5)
    fd = os.open(h.paths.lock_file, os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        outcome = h.check()
    finally:
        os.close(fd)
    assert outcome.action == "refused" and "already running" in outcome.reason
    assert h.restarts() == 0


# --- probation (activation review P0) --------------------------------------------------------


def test_a_release_that_dies_during_the_second_look_is_rolled_back(h):
    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))

    def crash():
        if h.running_image() == h.image("3"):
            h.running[h.profile.container] = None

    h.after_sleep = crash
    outcome = h.check()
    assert outcome.action == "rolled_back", outcome.reason
    assert h.running_image() == h.new_image


def test_a_release_that_restarts_during_the_second_look_is_rolled_back(h):
    """Up at both looks is not enough: it must be the same container, with no restart."""

    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))

    def restart():
        if h.running_image() == h.image("3"):
            h.nrestarts += 1
            h.started[h.profile.container] = float(h.now)

    h.after_sleep = restart
    outcome = h.check()
    assert outcome.action == "rolled_back", outcome.reason
    assert "second look" in outcome.reason


def test_a_release_that_dies_before_the_next_check_is_rolled_back_not_committed(h):
    """P1: a crash after the 20 s dwell used to be committed and reported current."""

    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))
    assert h.check().action == "activated"
    h.nrestarts += 3  # crash-looped since
    h.now += 3600
    outcome = h.check()
    assert outcome.action == "rolled_back", outcome.reason
    assert h.state()["miner"]["current"]["image"] == h.new_image
    assert h.running_image() == h.new_image


def test_a_new_container_during_probation_restarts_probation_once(h):
    """Activation re-review P2 (probes A1, A1b): one restart, a docker daemon
    restart say, restarts probation; a second one fails the release."""

    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))
    assert h.check().action == "activated"
    h.started[h.profile.container] += 1800
    h.nrestarts += 1
    h.now += 3600
    outcome = h.check()
    assert outcome.action == "probation" and "restarted once" in outcome.reason
    assert stage(h) == STAGE_PROBATION and h.state()["failed"] is None
    h.started[h.profile.container] += 1800
    h.now += 3600
    outcome = h.check()
    assert outcome.action == "rolled_back", outcome.reason
    assert h.state()["miner"]["current"]["image"] == h.new_image


def test_a_restarted_schema_bump_is_not_halted(h):
    """Probe A1b: the same restart during a schema-bump probation must not halt."""

    _activate_first(h)
    h.release(sequence=6, image=h.image("3"), state_schema=2)
    assert h.check().action == "activated"
    h.started[h.profile.container] += 900
    h.nrestarts += 1
    h.now += 3600
    assert h.check().action == "probation"
    h.now += 3600
    assert h.check().action == "current"
    assert h.state()["miner"]["current"]["image"] == h.image("3")


def test_probation_commits_only_after_its_minimum_age(h):
    """Probe A12: a second `check` right after the first cannot commit."""

    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))
    assert h.check().action == "activated"
    h.now += 5
    outcome = h.check()
    assert outcome.action == "probation" and stage(h) == STAGE_PROBATION
    assert h.state()["miner"]["current"]["image"] == h.new_image
    h.now += PROBATION_MINIMUM_SECONDS
    assert h.check().action == "current"
    assert h.state()["miner"]["current"]["image"] == h.image("3")


def test_an_inactive_miner_during_probation_alerts_and_is_not_rolled_back(h):
    """Probe A10: a clean exit, or a stop without `pause`, pages at once."""

    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))
    assert h.check().action == "activated"
    h.running[h.profile.container] = None
    h.operator_stopped = True
    restarts = h.restarts()
    h.now += 3600
    outcome = h.check()
    assert outcome.action == "unhealthy" and outcome.exit_status == EXIT_ALERT
    assert "without `pause`" in outcome.reason
    assert stage(h) == STAGE_PROBATION and h.restarts() == restarts


def test_an_inactive_committed_miner_alerts(h):
    """Probe A10b: `current` with an inactive unit is not success."""

    _activate_first(h)
    h.running[h.profile.container] = None
    h.operator_stopped = True
    h.now += 3600
    outcome = h.check()
    assert outcome.action == "unhealthy" and outcome.exit_status == EXIT_ALERT
    assert "without `pause`" in outcome.reason


def test_a_committed_release_running_another_image_alerts(h):
    _activate_first(h)
    h.running[h.profile.container] = h.image("9")  # started by hand, outside the updater
    outcome = h.check()
    assert outcome.action == "unhealthy" and h.image("9") in outcome.reason


def test_a_paused_host_does_not_alert_on_a_stopped_miner(h):
    _activate_first(h)
    h.running[h.profile.container] = None
    h.operator_stopped = True
    h.paths.pause_file.write_text("maintenance\n")
    outcome = h.check()
    assert outcome.action == "paused" and outcome.exit_status == 0


def test_a_committed_release_that_later_dies_alerts(h):
    """P1: the `current` shortcut checks the miner and alerts when it is down."""

    _activate_first(h)
    h.running[h.profile.container] = None
    h.release(sequence=6)
    outcome = h.check()
    assert outcome.action == "unhealthy" and outcome.exit_status == EXIT_ALERT


def test_restarts_since_the_last_check_alert_once(h):
    _activate_first(h)
    h.nrestarts += 2
    outcome = h.check()
    assert outcome.action == "unhealthy" and "restarted 2 times" in outcome.reason
    assert h.check().action == "current"


def test_a_reboot_during_probation_restarts_probation(h):
    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))
    h.check()
    h.boot = "boot-2"
    h.started[h.profile.container] += 5000
    outcome = h.check()
    assert outcome.action == "probation" and "rebooted" in outcome.reason
    assert stage(h) == STAGE_PROBATION
    h.now += 3600
    assert h.check().action == "current"


# --- rollback (F2, F4, F11) and failure memory ----------------------------------------------


def test_a_schema_compatible_failure_rolls_back_and_is_remembered(h):
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad)
    outcome = h.check()
    assert outcome.action == "rolled_back", outcome.reason
    assert outcome.exit_status == EXIT_REFUSED
    assert h.running_image() == h.new_image
    restarts = h.restarts()
    again = h.check()
    assert again.action == "refused" and "already failed" in again.reason
    assert h.restarts() == restarts, "a failed release is not retried every hour (F11)"


def test_failure_memory_holds_across_a_re_signature(h):
    """Activation review P3: failure memory is keyed by content."""

    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad)
    h.check()
    h.release(sequence=7, image=bad)
    outcome = h.check()
    assert outcome.action == "refused" and "already failed" in outcome.reason


def test_rollback_works_on_a_live_miner_that_writes_its_database(h):
    """F2: the old image writes its replay database during the attempt."""

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
    with sqlite3.connect(state_dir / "validator-access.sqlite") as connection:
        assert connection.execute("SELECT COUNT(*) FROM validator_request_replays").fetchone()[0] == 2


def test_a_launcher_only_change_rolls_back_to_the_legacy_launcher(h):
    h.managed_fails = True
    h.labels[h.old_image] = None  # the image already running needs no label to be taken over
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
    assert stage(h) == STAGE_MAY_HAVE_RUN
    assert h.check().action == "halted"
    assert describe_status(h.paths, h.config, expected_uid=os.getuid())["needs_operator"] is True


def test_a_first_activation_with_an_unverified_previous_schema_halts(h):
    h.broken_images.add(h.new_image)
    h.release(sequence=5)
    assert h.check().action == "halted"


def test_reset_failed_runs_before_the_rollback_start(h):
    _activate_first(h)
    h.systemctl_calls.clear()
    h.broken_images.add(h.image("3"))
    h.release(sequence=6, image=h.image("3"))
    h.check()
    unit = h.config.miner_unit
    assert h.systemctl_calls[-3:] == [("daemon-reload",), ("reset-failed", unit), ("restart", unit)]


def test_a_rollback_whose_restarts_fail_halts(h):
    _activate_first(h)
    h.broken_images.add(h.image("3"))
    h.on_restart = lambda image: setattr(h, "restart_raises", True)
    h.release(sequence=6, image=h.image("3"))
    outcome = h.check()
    assert outcome.action == "halted" and "two starts" in outcome.reason


def test_the_previous_release_gets_a_second_start(h):
    """P1-4: one failed start of the previous release no longer strands the host."""

    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    attempts = {"previous": 0}

    def flaky(image):
        if image == h.new_image:
            attempts["previous"] += 1
            if attempts["previous"] == 1:
                h.running[h.profile.container] = None

    h.on_restart = flaky
    h.release(sequence=6, image=bad)
    assert h.check().action == "rolled_back"
    assert attempts["previous"] == 2


def test_a_registry_outage_after_the_pull_does_not_block_the_rollback(h):
    """P7: the managed launcher starts from the local digest, so GHCR is not needed."""

    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.on_prepare = lambda: None
    h.release(sequence=6, image=bad)

    def registry_drops(image):
        h.registry_up = False

    h.on_restart = registry_drops
    outcome = h.check()
    assert outcome.action == "rolled_back", outcome.reason
    assert h.running_image() == h.new_image


def test_the_launchers_start_from_a_local_verified_digest():
    from cathedral.miner_products import PRODUCTS, find_launcher
    from tests.miner_update_support import REPO_ROOT

    for product in PRODUCTS.values():
        text = find_launcher(REPO_ROOT, product).read_text()
        guard = text.index("if ! docker image inspect")
        pull = text.index("docker pull --platform linux/amd64")
        close = text.index("\nfi\n", pull)
        assert guard < pull < close
        assert text.count("docker pull") == 1
        assert '"${IMAGE_PREFIX}${image_digest}"' in text[guard:pull]


# --- the flip time (activation review P2, P3, P4) ------------------------------------------------


def _die_after_flip(h: Harness) -> None:
    real = h._systemctl

    def die(arguments):
        raise KeyboardInterrupt("killed after the flip")

    h._systemctl = die
    with pytest.raises(KeyboardInterrupt):
        h.check()
    h._systemctl = real
    assert stage(h) == STAGE_MAY_HAVE_RUN


def test_a_launcher_that_never_ran_is_started_before_it_is_judged(h):
    """P2: same image, crash between the flip and the restart."""

    h.labels[h.old_image] = None
    h.release(sequence=5, image=h.old_image, bundle={"launcher_suffix": b"# broken v2\n"})
    _die_after_flip(h)
    h.managed_fails = True
    before = h.restarts()
    outcome = h.check()
    assert h.restarts() > before, "the new launcher is started, not assumed"
    assert outcome.action == "rolled_back", outcome.reason
    assert h.active() == LEGACY


def test_a_failed_daemon_reload_is_never_reported_activated(h):
    """P3: the old container runs the same image, but nothing restarted."""

    h.labels[h.old_image] = None
    h.release(sequence=5, image=h.old_image, bundle={"launcher_suffix": b"# v2\n"})
    real = h._systemctl

    def reload_fails(arguments):
        if arguments[0] == "daemon-reload":
            h.systemctl_calls.append(tuple(arguments))
            raise MinerUpdateError("systemctl daemon-reload timed out")
        real(arguments)

    h._systemctl = reload_fails
    outcome = h.check()
    assert outcome.action != "activated"
    assert h.state()["miner"]["current"] is None


def test_a_restart_that_did_not_take_effect_is_retried_before_judging(h):
    """P2/P4: an old container, whatever its image, means the release has not run yet."""

    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))
    before = h.restarts()
    real = h._systemctl
    ignored = {"restarts": 0}

    def first_restart_is_lost(arguments):
        if arguments[0] == "restart" and ignored["restarts"] == 0:
            ignored["restarts"] += 1
            h.systemctl_calls.append(tuple(arguments))
            return  # systemctl said yes, but the old container keeps running
        real(arguments)

    h._systemctl = first_restart_is_lost
    outcome = h.check()
    assert outcome.action == "activated", outcome.reason
    assert h.running_image() == h.image("3")
    assert h.restarts() - before == 2
    assert h.state()["failed"] is None


def test_the_old_container_never_passes_for_a_same_image_release(h):
    """P2: when no restart takes effect, the old container runs the same image,
    and it still is not the release."""

    h.labels[h.old_image] = None
    h.release(sequence=5, image=h.old_image, bundle={"launcher_suffix": b"# v2\n"})
    real = h._systemctl

    def restarts_do_nothing(arguments):
        if arguments[0] == "restart":
            h.systemctl_calls.append(tuple(arguments))
            return
        real(arguments)

    h._systemctl = restarts_do_nothing
    outcome = h.check()
    assert outcome.action == "rolled_back", outcome.reason
    assert h.state()["miner"]["stage"] is None and h.active() == LEGACY


def test_a_restart_error_is_never_ignored_even_when_the_release_runs(h):
    """P2: `systemctl restart` reported a failure; what then runs is not trusted."""

    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))
    real = h._systemctl
    calls = {"restart": 0}

    def first_restart_errors_after_it_ran(arguments):
        real(arguments)
        if arguments[0] == "restart":
            calls["restart"] += 1
            if calls["restart"] == 1:
                raise MinerUpdateError("systemctl restart timed out")

    h._systemctl = first_restart_errors_after_it_ran
    outcome = h.check()
    assert outcome.action == "rolled_back" and "restart failed" in outcome.reason, outcome.reason
    assert h.running_image() == h.new_image


def test_a_crash_after_the_flip_starts_the_release_instead_of_failing_it(h):
    """P4: the next check starts the release rather than remembering it as failed."""

    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))
    _die_after_flip(h)
    outcome = h.check()
    assert outcome.action == "activated", outcome.reason
    assert h.state()["failed"] is None
    assert h.running_image() == h.image("3")


# --- state schema (activation review P2, P5) ---------------------------------------------------


def test_a_label_that_differs_from_the_record_is_refused(h):
    h.labels[h.new_image] = 3
    h.release(sequence=5, state_schema=2)
    outcome = h.check()
    assert outcome.action == "refused" and "label is 3" in outcome.reason
    assert h.restarts() == 0


def test_an_unlabelled_image_is_taken_over_only_if_it_already_runs(h):
    h.labels[h.new_image] = None
    h.release(sequence=5)
    outcome = h.check()
    assert outcome.action == "refused" and "no org.cathedral.state-schema label" in outcome.reason


def test_a_schema_decrease_is_refused(h):
    """P5."""

    h.release(sequence=5, state_schema=2)
    h.commit()
    h.release(sequence=6, image=h.image("3"), state_schema=1)
    outcome = h.check()
    assert outcome.action == "refused" and "schemas never go down" in outcome.reason
    assert h.running_image() == h.new_image


def test_a_schema_decrease_with_the_same_image_is_allowed(h):
    """Only a different image can write another format; a launcher-only change may relabel."""

    h.release(sequence=5, state_schema=2)
    h.commit()
    h.labels[h.new_image] = 2
    h.release(sequence=6, state_schema=2, bundle={"launcher_suffix": b"# v2\n"})
    assert h.commit().action == "current"


def test_the_miner_images_carry_the_durable_state_schema_label():
    from cathedral.validator_access import DURABLE_STATE_SCHEMA
    from tests.miner_update_support import REPO_ROOT

    dockerfiles = sorted(REPO_ROOT.glob("Dockerfile.*-miner"))
    assert len(dockerfiles) == 2
    for dockerfile in dockerfiles:
        assert f'LABEL org.cathedral.state-schema="{DURABLE_STATE_SCHEMA}"' in dockerfile.read_text()


# The durable-state tables of schema 2, as (declared type, required). Required
# means NOT NULL with no default: every writer must fill it. An image of schema
# 2 writes exactly these columns. So state that newer code creates stays
# writable by every schema-2 image while no pinned table or column is dropped
# or changed and every new column is optional. A nullable column added by a
# migration (for example #212's clock high-water) keeps schema 2. Anything else
# raises DURABLE_STATE_SCHEMA and the Dockerfile labels, and so does any change
# in what a column means, which no structural test can see.
_SCHEMA_2_TABLES = {
    "validator_request_clock_high_water": {
        "singleton": ("INTEGER", False),
        "observed_at_epoch": ("INTEGER", True),
    },
    "validator_request_replays": {
        "validator_hotkey": ("TEXT", True),
        "nonce_hex": ("TEXT", True),
        "expires_at_epoch": ("INTEGER", True),
    },
    "validator_snapshot_high_water": {
        "network": ("TEXT", True),
        "netuid": ("INTEGER", True),
        "block": ("INTEGER", True),
        "block_hash": ("TEXT", True),
        "snapshot_digest": ("TEXT", True),
        "authorization_digest": ("TEXT", True),
    },
}


def _durable_state(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    ValidatorAccessState(str(directory / "validator-access.sqlite"))
    return directory / "validator-access.sqlite"


def test_state_this_code_creates_stays_writable_by_every_schema_2_image(tmp_path):
    from cathedral.validator_access import DURABLE_STATE_SCHEMA

    with sqlite3.connect(_durable_state(tmp_path)) as connection:
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        actual = {
            table: {
                name: (declared, bool(notnull) and default is None)
                for _cid, name, declared, notnull, default, _pk in connection.execute(
                    f"PRAGMA table_info({table})"
                )
            }
            for table in tables
        }
    assert DURABLE_STATE_SCHEMA == 2
    assert set(actual) == set(_SCHEMA_2_TABLES), "a table was added or dropped: decide the schema number"
    for table, pinned in _SCHEMA_2_TABLES.items():
        for column, spec in pinned.items():
            assert actual[table].get(column) == spec, f"{table}.{column} changed: raise the schema"
        added = [name for name, (_, required) in actual[table].items() if name not in pinned and required]
        assert added == [], f"{table} gained required columns {added}: raise the schema"


def test_schema_1_code_cannot_write_state_created_since_179(tmp_path):
    """Why "existing images are schema 1" was false: #179 made a column NOT NULL
    in the tables it creates, and code from before #179 does not fill it."""

    with sqlite3.connect(_durable_state(tmp_path)) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="NOT NULL"):
            # The insert the code before #179 (8ad7f6e) ran.
            connection.execute(
                "INSERT INTO validator_snapshot_high_water "
                "(network, netuid, block, block_hash, snapshot_digest) VALUES (?, ?, ?, ?, ?)",
                ("testnet", NETUID, 1, "0x" + "0" * 64, "0" * 64),
            )


# --- halts and resolve (activation review P1-3, P6) ----------------------------------------------


def _halt_on_schema_bump(h: Harness) -> None:
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad, state_schema=2)
    assert h.check().action == "halted"


def test_abandon_lets_a_newer_release_recover_a_halted_host(h):
    """P6: neither image runs, restore and accept both refuse; abandon then N+1 works."""

    _halt_on_schema_bump(h)
    h.broken_images.add(h.new_image)
    assert resolve(h.host(), "restore-previous").action == "halted"
    assert resolve(h.host(), "accept-release").action == "refused"
    outcome = resolve(h.host(), "abandon")
    assert outcome.action == "resolved", outcome.reason
    assert stage(h) is None
    h.release(sequence=7, image=h.image("4"), state_schema=2)
    assert h.commit().action == "current"
    assert h.running_image() == h.image("4")


def test_a_halted_host_still_takes_a_newer_updater(h):
    """P1-3: a halt blocks activation, not the channel."""

    _halt_on_schema_bump(h)
    before = h.updater_current()
    h.release(sequence=7, image=h.image("3"), state_schema=2, bundle={"launcher_suffix": b"# fix\n"})
    h.check()
    assert h.updater_current() != before


def test_abandon_remembers_the_release_as_failed(h):
    """Kills the re-review's surviving mutant: a re-signed copy of an abandoned
    release is not tried again."""

    _halt_on_schema_bump(h)
    resolve(h.host(), "abandon")
    assert h.state()["failed"]["image"] == h.image("3")
    h.release(sequence=7, image=h.image("3"), state_schema=2)
    outcome = h.check()
    assert "already failed" in outcome.reason and "abandoned" in outcome.reason


def test_abandon_does_not_lower_the_schema_floor(h):
    """Probe A4: the abandoned release may have migrated the state."""

    h.release(sequence=5, state_schema=2)
    h.commit()
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad, state_schema=3)
    assert h.check().action == "halted"
    assert h.state()["schema_high_water"] == {"schema": 3, "image": bad}
    resolve(h.host(), "abandon")
    h.release(sequence=7, image=h.image("4"), state_schema=2)
    outcome = h.check()
    assert "schemas never go down" in outcome.reason
    # Nothing runs since the abandon, so the refusal pages too (probe A5).
    assert outcome.action == "unhealthy" and outcome.exit_status == EXIT_ALERT
    h.release(sequence=8, image=h.image("4"), state_schema=3)
    assert h.commit().action == "current"


def test_resolve_restore_previous_puts_the_previous_release_back(h):
    _halt_on_schema_bump(h)
    outcome = resolve(h.host(), "restore-previous")
    assert outcome.action == "resolved", outcome.reason
    assert h.running_image() == h.new_image
    assert stage(h) is None
    assert h.state()["failed"]["sequence"] == 6


def test_resolve_accept_release_requires_the_release_to_run(h):
    """Kills the reviewer's surviving mutant that skipped the running check."""

    _halt_on_schema_bump(h)
    outcome = resolve(h.host(), "accept-release")
    assert outcome.action == "refused" and "not running" in outcome.reason
    assert stage(h) == STAGE_MAY_HAVE_RUN
    # The previous image running is not the release running.
    h.running[h.profile.container] = h.new_image
    outcome = resolve(h.host(), "accept-release")
    assert outcome.action == "refused" and "not running" in outcome.reason
    assert stage(h) == STAGE_MAY_HAVE_RUN


def test_resolve_accept_release_selects_the_release_and_reloads_units(h):
    """Kills the reviewer's surviving mutant that did not flip miner/current."""

    _halt_on_schema_bump(h)
    pending = h.state()["miner"]["pending"]
    from cathedral.miner_bundle import atomic_symlink

    atomic_symlink(h.paths.miner_current, pending["previous_target"])
    h.broken_images.discard(h.image("3"))
    h.running[h.profile.container] = h.image("3")  # the operator fixed and started it
    h.systemctl_calls.clear()
    outcome = resolve(h.host(), "accept-release")
    assert outcome.action == "resolved", outcome.reason
    assert h.active() == pending["target"]
    assert ("daemon-reload",) in h.systemctl_calls
    assert h.state()["miner"]["current"]["image"] == h.image("3")


def test_resolve_retry_clears_failure_memory(h):
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.release(sequence=6, image=bad)
    h.check()
    resolve(h.host(), "retry")
    h.broken_images.discard(bad)
    assert h.check().action == "activated"


# --- atomic launcher delivery (F5) ---------------------------------------------------------------


def test_a_launcher_update_is_applied_atomically(h):
    _activate_first(h)
    first = h.active()
    old_launcher = (activation_dir(h) / "launcher").read_bytes()
    h.release(sequence=6, image=h.image("3"), bundle={"launcher_suffix": b"# launcher v2\n"})
    assert h.commit().action == "current"
    second = h.active()
    assert second != first
    new_dir = activation_dir(h)
    assert (new_dir / "launcher").read_bytes() == old_launcher + b"# launcher v2\n"
    assert h.image("3") in (new_dir / "release.env").read_text()
    assert h.paths.miner_current.is_symlink()
    for name in ("launcher", "release.env", "unit.conf"):
        assert (h.paths.miner_current / name).resolve().parent == new_dir.resolve()
    assert (h.paths.miner_dir / first / "launcher").read_bytes() == old_launcher
    assert os.stat(new_dir / "launcher").st_mode & 0o777 == 0o555


def test_a_tampered_activation_directory_is_refused(h):
    _activate_first(h)
    first = activation_dir(h)
    h.release(sequence=6, image=h.image("3"))
    h.commit()
    launcher = first / "launcher"
    os.chmod(launcher, 0o755)
    launcher.write_bytes(b"#!/bin/sh\necho tampered\n")
    os.chmod(launcher, 0o555)
    h.release(sequence=7)
    outcome = h.check()
    assert outcome.action == "refused" and "modified" in outcome.reason
    assert h.running_image() == h.image("3")


# --- reconcile -----------------------------------------------------------------------------------


def _write_stage(h: Harness, value, pending) -> None:
    state = h.state()
    state["miner"]["stage"] = value
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


def _pending_before_flip(h: Harness) -> dict:
    return {
        "release": {"image": h.image("3"), "state_schema": 1, "tree_sha256": "0" * 64},
        "target": "releases/" + "0" * 64,
        "container": h.profile.container,
        "previous_target": h.active(),
        "previous_container": h.profile.container,
        "previous_image": h.new_image,
        "previous_state_schema": 1,
        "schema_verified": True,
        "flip_unix": h.now,
        "probation": None,
    }


def test_an_interrupted_activation_before_the_flip_is_cleared(h):
    _activate_first(h)
    _write_stage(h, STAGE_MAY_HAVE_RUN, _pending_before_flip(h))
    assert h.check().action == "current"
    assert stage(h) is None


def test_the_previous_release_is_started_again_before_a_halt(h):
    """P1-4 / P7: reconcile retries the known-good previous release."""

    _activate_first(h)
    h.running[h.profile.container] = None
    _write_stage(h, STAGE_MAY_HAVE_RUN, _pending_before_flip(h))
    outcome = h.check()
    assert outcome.action == "current", outcome.reason
    assert h.running_image() == h.new_image


def test_a_rollback_that_halted_and_later_completes_remembers_the_release(h):
    _activate_first(h)
    bad = h.image("3")
    h.broken_images.add(bad)
    h.broken_images.add(h.new_image)  # the previous release does not come back at first
    h.release(sequence=6, image=bad)
    assert h.check().action == "halted"
    h.broken_images.discard(h.new_image)
    assert h.check().action == "refused"  # recovered, and the failed release is not retried
    assert h.running_image() == h.new_image and stage(h) is None
    assert h.state()["failed"]["image"] == bad


def test_abandon_clears_a_stage_with_no_pending_record(h):
    """P1-3: every halt has an exit."""

    _write_stage(h, STAGE_MAY_HAVE_RUN, None)
    h.release(sequence=5)
    assert h.check().action == "halted"
    assert resolve(h.host(), "abandon").action == "resolved"
    assert h.check().action == "activated"


def test_a_probation_whose_selection_changed_halts(h):
    _activate_first(h)
    h.release(sequence=6, image=h.image("3"))
    assert h.check().action == "activated"
    from cathedral.miner_bundle import atomic_symlink

    atomic_symlink(h.paths.miner_current, LEGACY)
    h.now += 3600
    outcome = h.check()
    assert outcome.action == "halted" and "changed during probation" in outcome.reason


def test_an_interrupted_activation_that_cannot_restart_halts(h):
    _activate_first(h)
    h.running[h.profile.container] = None
    h.broken_images.add(h.new_image)
    _write_stage(h, STAGE_MAY_HAVE_RUN, _pending_before_flip(h))
    assert h.check().action == "halted"


# --- status ----------------------------------------------------------------------------------------


def test_status_shows_the_release_the_last_check_and_the_last_refusal(h):
    _activate_first(h)
    h.release(sequence=4, image=h.image("3"))
    h.check()
    h.paths.pause_file.write_text("")
    h.paths.pin_file.write_bytes(pin_document(h.state()["miner"]["current"]))
    status = describe_status(h.paths, h.config, expected_uid=os.getuid())
    assert status["miner"]["current_release"]["image"] == h.new_image
    assert status["miner"]["active"] == h.active()
    assert status["last_check"]["action"] == "refused"
    assert "rolls back" in status["last_refusal"]["reason"]
    assert status["paused"] is True
    assert status["pinned"]["image"] == h.new_image
    assert status["updater"]["current"] == f"releases/{h.tree_a}"
    assert status["trust"]["generation"] == 1
    assert status["config"]["netuid"] == h.config.netuid
    assert status["needs_operator"] is False


def test_status_works_with_no_state_yet(h):
    status = describe_status(h.paths, None, expected_uid=os.getuid())
    assert status["miner"]["current_release"] is None
    assert status["last_check"] is None
