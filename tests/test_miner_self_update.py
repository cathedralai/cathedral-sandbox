"""Self-update, the host trust set, and the fallback between updaters.

Review finding F5: the first updater a host installed was permanent. Now each
release ships the updater, and a check installs it first. The trust review
then found two ways that went wrong, and these tests hold the fixes:

- P0-1: the fallback ran the previous updater against its own bundled keys,
  so a key revoked by a rotation became trusted again, and the untrusted
  channel could force that fallback by crashing the current updater. The
  trust set now lives in host state and only moves forward, channel bytes can
  no longer crash an updater, and the bootstrap leaves no stale fallback.
- P0-2: a buggy-but-signed updater that refused everything was kept forever.
  Now a new updater stays current only if its first run verified the channel,
  and the previous updater takes over after two failures that it did not share.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from cathedral import miner_update_cli as cli
from cathedral.miner_bundle import atomic_symlink, install_directory, link_target
from cathedral.miner_release import MinerReleaseError, initial_trust_state, rotate_trust
from cathedral.miner_updater import (
    EXIT_ALERT,
    EXIT_FAULT,
    EXIT_HALTED,
    EXIT_REFUSED,
    STRIKES_TO_DEMOTE,
    MinerUpdateError,
    fallback_to_previous,
    load_trust_state,
    update_once,
    write_state,
)
from tests.miner_update_support import (
    DEFAULT_TRUST,
    OTHER_KEY,
    REPO_ROOT,
    STABLE_KEY,
    Harness,
    build_tree,
    trust_root_bytes,
)

SHIM = REPO_ROOT / "deploy" / "miner-update" / "cathedral-miner-update"
V2 = {"launcher_suffix": b"# launcher v2\n"}
V3 = {"launcher_suffix": b"# launcher v3\n"}
ROTATED = {**DEFAULT_TRUST, "stable-2": (OTHER_KEY, ["stable"])}
RETIRED = {"canary-1": DEFAULT_TRUST["canary-1"], "stable-2": (OTHER_KEY, ["stable"])}


@pytest.fixture()
def h(tmp_path) -> Harness:
    return Harness(tmp_path)


def _tree_of(record: bytes) -> str:
    return json.loads(record)["release"]["bundle"]["tree_sha256"]


def _broken_fetch_for(h: Harness, bad_tree: str):
    """A host factory whose updater `bad_tree` has a fetch regression."""

    def host_for(tree: str, **overrides):
        host = h.host(running_tree=tree, **overrides)
        if tree == bad_tree:

            def broken():
                raise MinerUpdateError("the download failed: a regression in this updater")

            host.fetch_metadata = broken
        return host

    def handoff(release_dir, fd):
        child = host_for(release_dir.name)
        child.handoff_depth = 1
        child.lock_fd = fd
        outcome = update_once(child)
        return outcome.exit_status, outcome.as_dict()

    return host_for, handoff


# --- adoption --------------------------------------------------------------------------------


def test_a_new_updater_is_adopted_first_and_applies_the_release(h):
    h.release(sequence=5, bundle=V2)
    outcome = h.check()
    assert outcome.action == "activated", outcome.reason
    assert outcome.verified is True and "took over" in outcome.reason
    assert h.updater_current() != h.tree_a
    assert link_target(h.paths.updater_previous) == f"releases/{h.tree_a}"
    assert h.running_image() == h.new_image
    assert h.state()["last_check"]["action"] == "activated"


def test_an_unsigned_record_never_reaches_the_bundle(h):
    record = json.loads(h.release(sequence=5, bundle=V2))
    record["signature"]["value_base64"] = record["signature"]["value_base64"][::-1]
    h.metadata = json.dumps(record).encode()
    before = set(os.listdir(h.paths.updater_releases))
    assert h.check().action == "refused"
    assert h.updater_current() == h.tree_a
    assert set(os.listdir(h.paths.updater_releases)) == before


def test_a_bundle_that_does_not_match_its_digest_is_refused(h):
    h.release(sequence=5, bundle=V2)
    (digest,) = h.bundles
    original = h.bundles[digest]
    h.bundles[digest] = original[:100] + bytes([original[100] ^ 1]) + original[101:]
    outcome = h.check()
    assert outcome.action == "refused" and "archive digest" in outcome.reason
    assert h.updater_current() == h.tree_a


def test_a_probe_that_does_not_confirm_the_release_is_refused(h):
    """Kills the surviving mutant that skipped the probe's confirmation."""

    h.release(sequence=5, bundle=V2)
    outcome = h.check(
        probe_updater=lambda release_dir, record: {"probe": "ok", "signed_sha256": "0" * 64}
    )
    assert outcome.action == "refused" and "did not confirm" in outcome.reason
    assert h.updater_current() == h.tree_a


def test_a_probe_reporting_another_state_schema_is_refused(h):
    """Trust review P2: a state-schema bump must not strand the fallback."""

    record = h.release(sequence=5, bundle=V2)

    def probe(release_dir, saved):
        document = h._probe(release_dir, saved)
        return dict(document, state_schema="cathedral_miner_update_state_v2")

    outcome = h.check(probe_updater=probe)
    assert outcome.action == "refused" and "state_schema" in outcome.reason
    assert "strike 1" in outcome.reason
    assert h.updater_current() == h.tree_a
    # A failed probe is a strike, not a verdict (P1-1); the second one retires the tree.
    assert "no longer uses" in h.check(probe_updater=probe).reason
    assert _tree_of(record) in h.state()["failed_updaters"]
    assert "already failed" in h.check(probe_updater=probe).reason


def test_one_probe_timeout_does_not_blacklist_a_good_updater(h):
    """Trust review P1-1: a transient probe failure must not retire a good tree."""

    good = _tree_of(h.release(sequence=5, bundle=V2))

    def slow(release_dir, saved):
        raise MinerUpdateError("the probe did not complete: timed out")

    assert "strike 1" in h.check(probe_updater=slow).reason
    assert good not in h.state()["failed_updaters"]
    outcome = h.check()
    assert outcome.action == "activated", outcome.reason
    assert h.updater_current() == good
    assert not h.state()["updater_strikes"]


def test_a_second_self_update_inside_a_handoff_waits_for_the_next_run(h):
    h.release(sequence=5, bundle=V2)
    host = h.host()
    host.handoff_depth = 1
    outcome = update_once(host)
    assert outcome.action == "refused" and "next check" in outcome.reason


# --- the host trust set (trust review P0-1) ----------------------------------------------------


def test_rotation_moves_the_host_trust_set_forward(h):
    h.release(sequence=5, bundle={"trust": ROTATED, **V2})
    assert h.commit().action == "current"
    trust = load_trust_state(h.paths.trust_file, expected_uid=os.getuid())
    assert trust.generation == 2 and set(trust.keys) == {"canary-1", "stable-1", "stable-2"}
    h.release(sequence=6, image=h.image("3"), key=OTHER_KEY, key_id="stable-2", bundle={"trust": RETIRED, **V3})
    assert h.commit().action == "current"
    trust = load_trust_state(h.paths.trust_file, expected_uid=os.getuid())
    assert trust.generation == 3 and "stable-1" not in trust.keys
    assert [entry["key_id"] for entry in trust.revoked.values()] == ["stable-1"]


def test_a_revoked_key_is_refused_even_by_the_previous_updater(h):
    """The reviewer's scenario: crash the current updater, then serve a revoked-key record."""

    h.release(sequence=5, bundle={"trust": ROTATED, **V2})
    h.commit()
    h.release(sequence=6, image=h.image("3"), key=OTHER_KEY, key_id="stable-2", bundle={"trust": RETIRED, **V3})
    h.commit()
    current = h.updater_current()
    previous = link_target(h.paths.updater_previous).split("/")[-1]
    evil = h.release(
        sequence=7,
        image=h.image("4"),
        key=STABLE_KEY,
        key_id="stable-1",
        bundle={"trust": ROTATED, "launcher_suffix": b"# evil\n"},
    )
    refused = h.check()
    assert refused.action == "refused" and refused.verified is False
    # The previous updater judges the same revoked-key record, against the host trust set.
    judged = fallback_to_previous(h.host(running_tree=previous), refused.exit_status)
    assert "not trusted" in judged.reason and "the current updater stays" in judged.reason
    # 1. The channel serves a body that used to crash the updater. Now it is a refusal.
    h.metadata = b"[" + b"1" * 5000 + b"]"
    crashed = update_once(h.host())
    assert crashed.action == "refused" and crashed.exit_status == EXIT_REFUSED
    # 2. The reviewer's scenario: the current updater dies before it fetches
    #    anything, and the channel then serves the revoked-key record to the
    #    previous updater, which fetches for itself. It is still refused.
    h.now += 3600
    h.metadata = evil
    outcome = fallback_to_previous(h.host(running_tree=previous), EXIT_FAULT)
    assert outcome.action == "refused" and "not trusted" in outcome.reason
    assert outcome.exit_status == EXIT_FAULT
    assert h.updater_current() == current
    assert h.running_image() == h.image("3")
    assert not h.state()["updater_strikes"]


def test_a_bundle_cannot_re_add_a_revoked_key(h):
    h.release(sequence=5, bundle={"trust": ROTATED, **V2})
    h.commit()
    h.release(sequence=6, image=h.image("3"), key=OTHER_KEY, key_id="stable-2", bundle={"trust": RETIRED, **V3})
    h.commit()
    h.release(
        sequence=7,
        image=h.image("4"),
        key=OTHER_KEY,
        key_id="stable-2",
        bundle={"trust": ROTATED, "launcher_suffix": b"# re-add\n"},
    )
    re_add = _tree_of(h.metadata)
    outcome = h.check()
    assert outcome.action == "refused" and "revoked key" in outcome.reason
    assert "stable-1" not in load_trust_state(h.paths.trust_file, expected_uid=os.getuid()).keys
    # The root is part of that tree, so the tree is retired, not probed again.
    assert re_add in h.state()["failed_updaters"]
    assert "updater in this release already failed" in h.check().reason


def test_a_rotation_that_would_lock_the_host_out_is_refused(h):
    lockout = {"canary-1": DEFAULT_TRUST["canary-1"], "other-1": (OTHER_KEY, ["stable"])}
    h.release(sequence=5, bundle={"trust": lockout, **V2})
    outcome = h.check()
    assert outcome.action == "refused" and "would not trust the key that signed it" in outcome.reason
    assert load_trust_state(h.paths.trust_file, expected_uid=os.getuid()).generation == 1
    assert h.updater_current() == h.tree_a


def test_rotation_rules_in_isolation():
    state = initial_trust_state(trust_root_bytes())
    same = rotate_trust(state, trust_root_bytes())
    assert same is state
    moved = rotate_trust(state, trust_root_bytes(RETIRED), signing_key_id="stable-2", channel="stable")
    assert moved.generation == 2 and len(moved.revoked) == 1
    with pytest.raises(MinerReleaseError, match="revoked"):
        rotate_trust(moved, trust_root_bytes())


def test_a_pinned_host_still_takes_trust_rotations(h):
    """Trust review P2."""

    from cathedral.miner_updater import pin_document

    h.release(sequence=5)
    h.commit()
    h.paths.pin_file.write_bytes(pin_document(h.state()["miner"]["current"]))
    h.release(sequence=6, image=h.image("3"), bundle={"trust": RETIRED, **V2}, key=STABLE_KEY, key_id="stable-1")
    # The signer's key is dropped by this root, so it is refused; use a rotation that keeps it.
    h.release(sequence=7, image=h.image("3"), bundle={"trust": ROTATED, **V2})
    assert h.check().action == "held"
    assert "stable-2" in load_trust_state(h.paths.trust_file, expected_uid=os.getuid()).keys
    # The generation a later repair may not go below is recorded at once.
    assert h.state()["trust_generation"] == 2
    assert h.updater_current() == h.tree_a


# --- the first run must prove a verified check (trust review P0-2) -----------------------------


def test_a_fetch_regression_in_a_new_updater_is_caught_and_recovered(h):
    """The reviewer's P0-2 scenario, and recovery once a fixed release is published."""

    bad = _tree_of(h.release(sequence=5, bundle={"launcher_suffix": b"# v2 with a fetch regression\n"}))
    host_for, handoff = _broken_fetch_for(h, bad)
    for _ in range(STRIKES_TO_DEMOTE + 1):
        refused = update_once(host_for(h.tree_a, handoff=handoff))
        assert refused.action == "refused" and "did not prove a verified check" in refused.reason
        assert h.updater_current() == h.tree_a
    # It is never kept. It is not retired either: a fetch that fails looks the
    # same as an outage, so it cannot blame a tree (trust re-review P2).
    assert "no strike" in refused.reason
    assert bad not in h.state()["failed_updaters"] and not h.state()["updater_strikes"]
    # The signer publishes a fixed updater. The host takes it without hands.
    fixed = _tree_of(h.release(sequence=6, bundle={"launcher_suffix": b"# v3 fixes the fetch\n"}))
    outcome = update_once(host_for(h.tree_a, handoff=handoff))
    assert outcome.action == "activated", outcome.reason
    assert h.updater_current() == fixed


def test_a_regression_that_appears_later_is_recovered_by_the_fallback(h):
    good = _tree_of(h.release(sequence=5, bundle=V2))
    assert h.commit().action == "current"
    assert h.updater_current() == good
    host_for, _ = _broken_fetch_for(h, good)
    for strike in range(1, STRIKES_TO_DEMOTE + 1):
        refused = update_once(host_for(good))
        assert refused.action == "refused" and refused.verified is False
        judged = fallback_to_previous(host_for(h.tree_a), refused.exit_status)
        if strike < STRIKES_TO_DEMOTE:
            assert judged.exit_status == EXIT_REFUSED and f"strike {strike}" in judged.reason
            assert h.updater_current() == good
    assert judged.action == "demoted" and judged.exit_status == EXIT_ALERT
    assert h.updater_current() == h.tree_a
    assert link_target(h.paths.updater_previous) is None
    # Only its fetch failed, so the tree is switched away from but not retired.
    assert good not in h.state()["failed_updaters"] and "not retired" in judged.reason
    fixed = _tree_of(h.release(sequence=6, bundle=V3))
    assert update_once(h.host()).action == "activated"
    assert h.updater_current() == fixed


def test_an_updater_that_verifies_but_cannot_self_update_is_replaced(h):
    """Trust re-review P1: it verifies every check, so its refusals were final.
    Now the fallback probes the tree it could not install, and when that tree
    is sound the strike goes to the current updater instead."""

    good = _tree_of(h.release(sequence=5, bundle=V2))
    h.commit()
    assert h.updater_current() == good

    def stuck(tree: str):
        # This updater's handoff never works: every self-update fails.
        return h.host(running_tree=tree, handoff=lambda release_dir, fd: (1, None))

    fixed = _tree_of(h.release(sequence=6, bundle=V3))  # the signer publishes a newer updater
    for strike in range(1, STRIKES_TO_DEMOTE + 1):
        h.now += 3600
        refused = update_once(stuck(good))
        assert refused.action == "refused" and refused.verified is True, refused.reason
        assert refused.updater_offered == fixed and refused.updater_blame == "ambiguous"
        judged = fallback_to_previous(h.host(running_tree=h.tree_a), refused.exit_status)
        if strike < STRIKES_TO_DEMOTE:
            assert f"strike {strike}" in judged.reason and "probe accepts" in judged.reason
            assert h.state()["updater_strikes"].get(fixed) is None, "the new tree's strike is taken back"
    assert judged.action == "demoted" and h.updater_current() == h.tree_a
    assert fixed not in h.state()["failed_updaters"]
    # The previous updater installs the newer one itself.
    h.now += 3600
    outcome = update_once(h.host())
    assert outcome.action == "activated", outcome.reason
    assert h.updater_current() == fixed


def test_a_new_tree_that_fails_for_both_updaters_is_not_blamed_on_the_current_one(h):
    good = _tree_of(h.release(sequence=5, bundle=V2))
    h.commit()
    broken = _tree_of(h.release(sequence=6, bundle={"replace_modules": {"miner_updater.py": b"not python\n"}}))

    def real_probe(release_dir, record):
        return cli.probe_updater(h.paths, release_dir, record)

    _real_clock(h)
    h.release(sequence=7, bundle={"replace_modules": {"miner_updater.py": b"not python\n"}})
    refused = update_once(h.host(probe_updater=real_probe))
    assert refused.updater_offered == broken and "probe" in refused.reason
    judged = fallback_to_previous(h.host(running_tree=h.tree_a, probe_updater=real_probe), refused.exit_status)
    assert "fails for this updater too" in judged.reason
    assert good not in h.state()["updater_strikes"]
    assert h.updater_current() == good


def test_a_new_tree_that_reports_its_own_failure_is_not_judged_again(h):
    """The brick scenario seen from the fallback: the new tree ran and said it
    could not verify, so the fault is its own and the refusal stands."""

    good = _tree_of(h.release(sequence=5, bundle=V2))
    h.commit()
    bad = _tree_of(h.release(sequence=6, bundle=V3))
    host_for, handoff = _broken_fetch_for(h, bad)
    refused = update_once(host_for(good, handoff=handoff))
    assert refused.updater_offered == bad and refused.updater_blame == "new"
    judged = fallback_to_previous(h.host(running_tree=h.tree_a), refused.exit_status)
    assert "its refusal stands" in judged.reason
    assert good not in h.state()["updater_strikes"]


def test_a_channel_that_shows_each_updater_other_bytes_demotes_nothing(h):
    """Trust re-review P2, the reviewer's split-serving PoC: garbage to the
    current updater, the good record to the fallback. The fallback now judges
    the bytes the current updater saw."""

    good_record = h.release(sequence=5, bundle=V2)
    assert h.check().action == "activated"
    current = h.updater_current()
    for _ in range(STRIKES_TO_DEMOTE + 1):
        h.now += 3600
        h.metadata = b"not json"  # served to the current updater
        refused = update_once(h.host(running_tree=current))
        h.metadata = good_record  # served to the fallback
        judged = fallback_to_previous(h.host(running_tree=h.tree_a), refused.exit_status)
        assert "cannot verify what the current updater saw" in judged.reason
    assert h.updater_current() == current
    assert not h.state()["updater_strikes"] and not h.state()["failed_updaters"]


def test_a_channel_that_resets_only_the_current_updaters_fetch_retires_nothing(h):
    """Trust re-review P2, the reviewer's reset-first-request PoC. Fetch
    failures may switch updaters, but never retire or blame the good tree, and
    the previous updater installs it again once the channel lets it through."""

    good_record = h.release(sequence=5, bundle=V2)
    assert h.check().action == "activated"
    good = h.updater_current()
    for _ in range(STRIKES_TO_DEMOTE):
        h.now += 3600
        host = h.host(running_tree=good)

        def reset():
            raise MinerUpdateError("the download failed: connection reset")

        host.fetch_metadata = reset
        refused = update_once(host)
        h.metadata = good_record
        judged = fallback_to_previous(h.host(running_tree=h.tree_a), refused.exit_status)
    assert judged.action == "demoted" and "not retired" in judged.reason
    assert h.updater_current() == h.tree_a
    assert good not in h.state()["failed_updaters"] and not h.state()["updater_strikes"]
    assert h.state()["failed"] is None
    h.now += 3600
    outcome = h.check()
    assert "took over" in outcome.reason, outcome.reason
    assert h.updater_current() == good


def test_the_saved_record_must_be_the_bytes_the_current_updater_fetched(h):
    """Kills the surviving mutant that skipped the saved record's hash."""

    good_record = h.release(sequence=5, bundle=V2)
    assert h.check().action == "activated"
    current = h.updater_current()
    h.now += 3600
    h.metadata = b"not json"
    refused = update_once(h.host(running_tree=current))
    h.paths.fetched_record.write_bytes(good_record)  # changed after it was fetched
    judged = fallback_to_previous(h.host(running_tree=h.tree_a), refused.exit_status)
    assert "changed since" in judged.reason
    assert not h.state()["updater_strikes"]


def test_a_stalled_update_is_judged_only_for_the_tree_the_record_names(h):
    """Kills the surviving mutant that skipped binding the record's tree to the
    tree the current updater said it could not install."""

    good = _tree_of(h.release(sequence=5, bundle=V2))
    h.commit()
    _tree_of(h.release(sequence=6, bundle=V3))
    h.now += 3600
    refused = update_once(h.host(running_tree=good, handoff=lambda release_dir, fd: (1, None)))
    assert refused.updater_blame == "ambiguous"
    state = h.state()
    state["last_check"]["updater_offered"] = "e" * 64  # a tree the record does not name
    write_state(h.paths.state_file, state)
    judged = fallback_to_previous(h.host(running_tree=h.tree_a), refused.exit_status)
    assert "names another updater" in judged.reason
    assert good not in h.state()["updater_strikes"]


def test_the_fallback_passes_the_current_status_through_when_it_cannot_run(h):
    """Trust re-review P3: a fault must still page when the fallback refuses
    its own preconditions."""

    good = _tree_of(h.release(sequence=5, bundle=V2))
    h.commit()
    # previous == current
    same = fallback_to_previous(h.host(running_tree=good), EXIT_FAULT)
    assert same.exit_status == EXIT_FAULT and "is the current updater" in same.reason
    # the lock is busy
    import fcntl

    fd = os.open(h.paths.lock_file, os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        busy = fallback_to_previous(h.host(running_tree=h.tree_a), 1)
    finally:
        os.close(fd)
    assert busy.exit_status == EXIT_FAULT and "already running" in busy.reason
    # the state is unreadable
    h.paths.state_file.write_text("not json")
    unreadable = fallback_to_previous(h.host(running_tree=h.tree_a), EXIT_FAULT)
    assert unreadable.exit_status == EXIT_FAULT


def test_the_fallback_command_passes_the_status_through_when_it_cannot_start(monkeypatch, tmp_path):
    monkeypatch.setenv(cli.ROOT_ENV, str(tmp_path))  # no config here, so it refuses at once
    assert cli.main(["fallback", "--current-status", "13"]) == EXIT_FAULT
    assert cli.main(["fallback", "--current-status", "1"]) == EXIT_FAULT
    assert cli.main(["fallback", "--current-status", "10"]) == EXIT_REFUSED


def test_a_first_run_crash_is_reverted_with_a_strike(h):
    h.release(sequence=5, bundle=V2)
    outcome = h.check(handoff=lambda release_dir, fd: (1, None))
    assert outcome.action == "refused" and "strike 1" in outcome.reason
    assert h.updater_current() == h.tree_a
    assert link_target(h.paths.updater_previous) is None
    assert h.active() == "legacy"


def test_a_first_run_that_faults_after_verifying_is_not_kept(h):
    h.release(sequence=5, bundle=V2)
    outcome = h.check(
        handoff=lambda release_dir, fd: (EXIT_FAULT, {"action": "fault", "verified": True, "reason": "a bug"})
    )
    assert outcome.action == "refused" and "strike 1" in outcome.reason
    assert h.updater_current() == h.tree_a


def test_reverting_a_new_updater_keeps_the_fallback_the_host_had(h):
    good = _tree_of(h.release(sequence=5, bundle=V2))
    h.commit()
    assert link_target(h.paths.updater_previous) == f"releases/{h.tree_a}"
    h.release(sequence=6, bundle=V3)
    outcome = h.check(handoff=lambda release_dir, fd: (1, None))
    assert "strike 1" in outcome.reason
    assert h.updater_current() == good
    assert link_target(h.paths.updater_previous) == f"releases/{h.tree_a}"


def test_a_halt_keeps_paging_while_the_channel_is_down(h):
    """A refusal later in the check must not turn exit 11 into a quiet exit 10."""

    h.release(sequence=5)
    h.commit()
    h.broken_images.add(h.image("3"))
    h.release(sequence=6, image=h.image("3"), state_schema=2)
    assert h.check().action == "halted"

    def down():
        raise MinerUpdateError("the download failed: outage")

    outcome = h.check(fetch_metadata=down)
    assert outcome.action == "halted" and outcome.exit_status == EXIT_HALTED
    assert "outage" in outcome.reason


def test_a_first_run_during_a_channel_outage_is_reverted_without_a_strike(h):
    record = h.release(sequence=5, bundle=V2)
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] > 1:
            raise MinerUpdateError("the download failed: outage")
        return record

    def child_in_the_outage(release_dir, fd):
        child = h.host(running_tree=release_dir.name, fetch_metadata=flaky)
        child.handoff_depth = 1
        child.lock_fd = fd
        result = update_once(child)
        return result.exit_status, result.as_dict()

    outcome = h.check(fetch_metadata=flaky, handoff=child_in_the_outage)
    assert "no strike" in outcome.reason
    assert not h.state()["updater_strikes"]
    assert not h.state()["failed_updaters"]


def test_an_induced_failure_the_previous_updater_shares_blames_nothing(h):
    """Trust review P1-1: channel garbage must not retire a good updater."""

    good = _tree_of(h.release(sequence=5, bundle=V2))
    h.commit()
    h.metadata = b"[" + b"1" * 5000 + b"]"
    refused = update_once(h.host())
    judged = fallback_to_previous(h.host(running_tree=h.tree_a), refused.exit_status)
    assert "cannot verify what the current updater saw either" in judged.reason
    assert h.updater_current() == good
    assert not h.state()["updater_strikes"] and not h.state()["failed_updaters"]


def _verified_refusal(h: Harness) -> str:
    """A verified refusal, recorded; then the channel serves a good record again."""

    valid = h.release(sequence=5, bundle=V2)
    h.commit()
    h.release(sequence=4, bundle=V2)  # a rollback: refused after a verified fetch
    refused = update_once(h.host())
    assert refused.exit_status == EXIT_REFUSED and refused.verified is True
    h.metadata = valid
    return _tree_of(valid)


def test_a_verified_refusal_is_not_second_guessed(h):
    _verified_refusal(h)
    judged = fallback_to_previous(h.host(running_tree=h.tree_a), EXIT_REFUSED)
    assert "its refusal stands" in judged.reason
    assert not h.state()["updater_strikes"]


def test_a_stale_verified_record_does_not_excuse_a_new_failure(h):
    """The fallback trusts `verified` only from the run the shim just saw."""

    good = _verified_refusal(h)
    h.now += 3600
    # An hour later the current updater crashes before it records anything.
    judged = fallback_to_previous(h.host(running_tree=h.tree_a), EXIT_REFUSED)
    assert "stands" not in judged.reason and "strike 1" in judged.reason
    assert good in h.state()["updater_strikes"]


def test_a_record_of_another_exit_status_does_not_excuse_a_refusal(h):
    good = _tree_of(h.release(sequence=5, bundle=V2))
    h.commit()
    assert h.state()["last_check"]["exit_status"] == 0 and h.state()["last_check"]["verified"]
    # The shim saw 10, but the record says 0: it is not this run's record.
    judged = fallback_to_previous(h.host(running_tree=h.tree_a), EXIT_REFUSED)
    assert "stands" not in judged.reason and "strike 1" in judged.reason
    assert good in h.state()["updater_strikes"]


def test_a_stage_a_newer_updater_wrote_stops_activation_but_not_the_fallback(h):
    """Trust review P2: newer state must never make an older updater refuse it."""

    from cathedral.miner_updater import resolve

    good = _tree_of(h.release(sequence=5, bundle=V2))
    h.commit()
    state = h.state()
    state["miner"]["stage"] = "a_stage_from_the_future"
    state["a_field_from_the_future"] = {"kept": True}
    write_state(h.paths.state_file, state)
    host_for, _ = _broken_fetch_for(h, good)
    refused = update_once(host_for(good))
    judged = fallback_to_previous(host_for(h.tree_a), refused.exit_status)
    assert "strike 1" in judged.reason, judged.reason
    # The older updater, as current, halts activation but still verifies.
    halted = update_once(h.host(running_tree=h.tree_a))
    assert halted.action == "halted" and halted.verified is True
    assert "a_stage_from_the_future" in halted.reason
    assert h.state()["a_field_from_the_future"] == {"kept": True}
    assert resolve(h.host(), "abandon").action == "resolved"
    assert h.state()["miner"]["stage"] is None


# --- real processes ----------------------------------------------------------------------------


def _real_clock(h: Harness) -> Harness:
    """Child processes read the real clock, so records must be fresh by it."""

    h.now = int(time.time())
    return h


def test_the_real_probe_accepts_a_sound_updater(h):
    _real_clock(h)
    h.release(sequence=5, bundle=V2)
    outcome = h.check(probe_updater=lambda release_dir, record: cli.probe_updater(h.paths, release_dir, record))
    assert outcome.action == "activated", outcome.reason


def test_the_real_probe_refuses_a_broken_updater_and_the_old_one_keeps_working(h):
    _real_clock(h)
    h.release(sequence=5, bundle={"replace_modules": {"miner_updater.py": b"this is not python\n"}})
    outcome = h.check(probe_updater=lambda release_dir, record: cli.probe_updater(h.paths, release_dir, record))
    assert outcome.action == "refused" and "probe exited" in outcome.reason
    assert h.updater_current() == h.tree_a
    h.release(sequence=6)
    assert h.check().action == "activated"


def test_the_real_handoff_passes_the_lock_and_an_unverified_first_run_is_not_kept(h):
    _real_clock(h)
    h.release(sequence=5, bundle=V2)
    seen = {}

    def handoff(release_dir, fd):
        status, document = cli.handoff(h.paths, release_dir, fd, 0)
        seen["status"], seen["document"] = status, document
        return status, document

    outcome = h.check(
        probe_updater=lambda release_dir, record: cli.probe_updater(h.paths, release_dir, record),
        handoff=handoff,
    )
    assert seen["status"] == EXIT_REFUSED
    assert "download failed" in seen["document"]["reason"]
    assert "already running" not in seen["document"]["reason"]
    assert seen["document"]["verified"] is False
    # The child could not reach the channel (a closed local port) while this
    # updater could. The new tree is not kept, and since a failed fetch looks
    # like an outage, it gets no strike.
    assert outcome.action == "refused" and "no strike" in outcome.reason
    assert h.updater_current() == h.tree_a


def test_the_probe_and_handoff_run_from_the_release_directory(h, monkeypatch):
    """Kills the surviving mutant that dropped the probe's cwd=."""

    calls = []

    def fake_run(argv, **kwargs):
        calls.append(kwargs)

        class Result:
            returncode = 0
            stdout = '{"probe": "ok"}'
            stderr = ""

        return Result()

    class FakePopen:
        def __init__(self, argv, **kwargs):
            calls.append(kwargs)
            self.returncode = 0
            self.pid = -1

        def communicate(self, timeout=None):
            calls[-1]["timeout"] = timeout
            return '{"action": "current"}', None

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setattr(cli.subprocess, "Popen", FakePopen)
    release = h.paths.updater_releases / h.tree_a
    cli.probe_updater(h.paths, release, Path("/nonexistent"))
    cli.handoff(h.paths, release, 0, 0)
    assert [call["cwd"] for call in calls] == [release / "updater", release / "updater"]
    assert all(call["env"]["PYTHONSAFEPATH"] == "1" for call in calls)
    assert calls[1]["timeout"] == cli.HANDOFF_TIMEOUT_SECONDS
    assert calls[1]["start_new_session"] is True


def test_a_first_run_that_hangs_is_killed_with_everything_it_started(h, monkeypatch, tmp_path):
    """Trust review P0-2: the handoff has a timeout, and it ends the child's whole group."""

    release = tmp_path / "hanging-release"
    package = release / "updater" / "cathedral"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    marker = tmp_path / "grandchild.pid"
    (package / "miner_update_cli.py").write_text(
        "import pathlib, subprocess, time\n"
        "child = subprocess.Popen(['sleep', '300'])\n"
        f"pathlib.Path({str(marker)!r}).write_text(str(child.pid))\n"
        "time.sleep(300)\n"
    )
    monkeypatch.setattr(cli, "HANDOFF_TIMEOUT_SECONDS", 3)
    started = time.monotonic()
    status, document = cli.handoff(h.paths, release, 0, 0)
    assert status == 124 and "timed out" in document["error"]
    assert time.monotonic() - started < 60
    pid = int(marker.read_text())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            # Gone, including when it is reaped between opening the file and
            # reading it, which the kernel reports as ESRCH.
            break
        if state == "Z":
            break
        time.sleep(0.1)
    else:
        pytest.fail("the first run's own child outlived the timeout")


def _shim_copy(h: Harness, tmp_path: Path, *, extra_env: str = "") -> Path:
    """The shim reads nothing from the environment, so tests run a relocated copy."""

    text = SHIM.read_text()
    text = text.replace("INSTALL=/usr/local/lib/cathedral-miner-update", f"INSTALL={h.paths.install_root}")
    text = text.replace("PYTHON=/usr/bin/python3", f"PYTHON={sys.executable}")
    text = text.replace(
        "LANG=C.UTF-8 PYTHONSAFEPATH=1",
        f"LANG=C.UTF-8 PYTHONSAFEPATH=1 CATHEDRAL_MINER_UPDATE_ROOT={h.paths.root} {extra_env}".rstrip(),
    )
    # A miner that is up, as systemctl and docker would report it, so the
    # health check that closes every check sees a running miner.
    fake = tmp_path / "fake-bin"
    fake.mkdir(exist_ok=True)
    (fake / "systemctl").write_text(
        "#!/bin/sh\ncase \"$*\" in\n  *--value*) echo active ;;\n"
        "  show*) printf 'ActiveState=active\\nNRestarts=0\\n' ;;\nesac\nexit 0\n"
    )
    (fake / "docker").write_text("#!/bin/sh\necho 'true 2020-01-01T00:00:00Z legacy@sha256:0'\n")
    for tool in ("systemctl", "docker"):
        os.chmod(fake / tool, 0o755)
    text = text.replace("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f"PATH={fake}:/usr/sbin:/usr/bin:/sbin:/bin")
    copy = tmp_path / "shim"
    copy.write_text(text)
    return copy


@contextlib.contextmanager
def _local_channel(tmp_path: Path, body: Callable[[], bytes]):
    """An https channel on 127.0.0.1 with a throwaway certificate. It contacts no other host."""

    import datetime
    import http.server
    import ipaddress
    import ssl
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "channel-cert.pem"
    key_file = tmp_path / "channel-key.pem"
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            payload = body()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}/miner/stable.json", cert_file
    finally:
        server.shutdown()
        server.server_close()


def test_the_real_shim_demotes_a_crashing_updater_the_previous_one_can_stand_in_for(h, tmp_path):
    """Trust review P0-2 end to end: shim, fallback, strikes and demotion, over a real fetch."""

    _real_clock(h)
    h.release(sequence=5)
    crashing = tmp_path / "crashing-tree"
    tree_b = build_tree(crashing, replace_modules={"miner_update_cli.py": b"raise RuntimeError('broken')\n"})
    install_directory(crashing, tree_sha256=tree_b, releases=h.paths.updater_releases)
    atomic_symlink(h.paths.updater_previous, f"releases/{h.tree_a}")
    atomic_symlink(h.paths.updater_current, f"releases/{tree_b}")
    with _local_channel(tmp_path, lambda: h.metadata) as (url, cert):
        config = json.loads(h.paths.config_file.read_text())
        config["channel_url"] = url
        h.paths.config_file.write_text(json.dumps(config))
        shim = _shim_copy(h, tmp_path, extra_env=f"SSL_CERT_FILE={cert}")

        def run():
            return subprocess.run(
                ["sh", str(shim), "check"], env={"PATH": os.environ["PATH"]}, capture_output=True, text=True, timeout=120
            )

        first = run()
        assert first.returncode == EXIT_FAULT, first.stdout + first.stderr[-2000:]
        assert "strike 1" in first.stdout
        assert h.updater_current() == tree_b
        second = run()
        assert second.returncode == EXIT_ALERT, second.stdout + second.stderr[-2000:]
        assert json.loads(second.stdout.strip().splitlines()[-1])["action"] == "demoted"
    assert h.updater_current() == h.tree_a
    assert link_target(h.paths.updater_previous) is None
    assert tree_b in h.state()["failed_updaters"]


def test_the_shim_reads_no_settings_from_the_environment():
    import re

    text = SHIM.read_text()
    # No ${NAME:-default} or ${NAME-default} expansions, apart from the argument $1.
    assert re.search(r"\$\{(?!1:-)[A-Za-z_][A-Za-z0-9_]*:?-", text) is None
    assert "CATHEDRAL_MINER_UPDATE_ROOT" not in text
    assert 'PYTHON=/usr/bin/python3' in text
    assert 'READLINK=/usr/bin/readlink' in text and 'ENV=/usr/bin/env' in text
    for line in text.splitlines():
        stripped = line.strip()
        assert not stripped.startswith(("readlink ", "env ")), line


def test_the_shim_asks_the_previous_updater_and_nothing_changes_when_it_cannot_verify(h, tmp_path):
    """A crashing current updater, and a channel nobody can reach: no strike, no switch."""

    _real_clock(h)
    crashing = tmp_path / "crashing-tree"
    tree_b = build_tree(crashing, replace_modules={"miner_update_cli.py": b"raise RuntimeError('broken')\n"})
    install_directory(crashing, tree_sha256=tree_b, releases=h.paths.updater_releases)
    atomic_symlink(h.paths.updater_previous, f"releases/{h.tree_a}")
    atomic_symlink(h.paths.updater_current, f"releases/{tree_b}")
    assert tree_b != h.tree_a
    result = subprocess.run(
        ["sh", str(_shim_copy(h, tmp_path)), "check"],
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        timeout=120,
    )
    document = json.loads(result.stdout.strip().splitlines()[-1])
    assert "cannot verify what the current updater saw either" in document["reason"], result.stderr[-2000:]
    assert result.returncode == EXIT_FAULT
    assert h.updater_current() == tree_b
    assert not h.state()["updater_strikes"]
    assert h.state()["last_fallback"]["current_status"] == 1


def test_the_shim_passes_a_refusal_through_when_nobody_can_verify(h, tmp_path):
    _real_clock(h)
    other = tmp_path / "other-tree"
    tree_b = build_tree(other, launcher_suffix=b"# b\n")
    install_directory(other, tree_sha256=tree_b, releases=h.paths.updater_releases)
    atomic_symlink(h.paths.updater_previous, f"releases/{h.tree_a}")
    atomic_symlink(h.paths.updater_current, f"releases/{tree_b}")
    result = subprocess.run(
        ["sh", str(_shim_copy(h, tmp_path)), "check"],
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == EXIT_REFUSED, result.stderr[-2000:]
    assert h.updater_current() == tree_b
    assert link_target(h.paths.updater_previous) == f"releases/{h.tree_a}"
    # The shim asked the previous updater, which could not verify the channel either.
    assert h.state()["last_fallback"]["current_status"] == EXIT_REFUSED


def test_the_shim_reports_status_without_the_channel(h, tmp_path):
    result = subprocess.run(
        ["sh", str(_shim_copy(h, tmp_path)), "status"],
        env={"PATH": os.environ["PATH"]},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    status = json.loads(result.stdout)
    assert status["updater"]["current"] == f"releases/{h.tree_a}"
    assert status["trust"]["generation"] == 1


def test_the_bundle_updater_imports_nothing_outside_the_bundle(tmp_path):
    tree = tmp_path / "tree"
    build_tree(tree)
    script = (
        "import sys; sys.path.insert(0, sys.argv[1]); import cathedral.miner_update_cli; "
        "print(sorted(m for m in sys.modules if m.startswith('cathedral')))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tree / "updater")], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr
    loaded = set(json.loads(result.stdout.replace("'", '"')))
    assert loaded == {
        "cathedral",
        "cathedral.miner_bundle",
        "cathedral.miner_products",
        "cathedral.miner_release",
        "cathedral.miner_update_cli",
        "cathedral.miner_updater",
    }
