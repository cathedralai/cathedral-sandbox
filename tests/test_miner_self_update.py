"""The updater updates itself through the channel, and cannot strand itself doing so.

Review finding F5: the first updater a host installed was permanent, so every
defect in it (F1 included) needed hands on every host. Now each release ships
the updater's code, and a check installs it first. Three guards keep a bad
updater from stranding a host: the pre-flip probe, the first-run handoff, and
the frozen shim's fallback. The in-process tests drive the state machine; the
subprocess tests run the real CLI and the real shell shim.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from cathedral import miner_update_cli as cli
from cathedral.miner_bundle import atomic_symlink, install_directory, link_target
from cathedral.miner_updater import EXIT_REFUSED, update_once
from tests.miner_update_support import (
    DEFAULT_TRUST,
    OTHER_KEY,
    REPO_ROOT,
    STABLE_KEY,
    Harness,
    build_tree,
)

SHIM = REPO_ROOT / "deploy" / "miner-update" / "cathedral-miner-update"
NEW_LAUNCHER = {"launcher_suffix": b"# launcher v2\n"}


@pytest.fixture()
def h(tmp_path) -> Harness:
    return Harness(tmp_path)


def _releases(h: Harness) -> set[str]:
    return {path.name for path in h.paths.updater_releases.iterdir()}


# --- in process ------------------------------------------------------------------------


def test_a_new_updater_is_adopted_first_and_applies_the_release(h):
    h.release(sequence=5, bundle=NEW_LAUNCHER)
    outcome = h.check()
    assert outcome.action == "activated", outcome.reason
    assert "took over" in outcome.reason
    new_tree = h.updater_current()
    assert new_tree != h.tree_a
    assert link_target(h.paths.updater_previous) == f"releases/{h.tree_a}"
    assert h.running_image() == h.new_image
    # The child recorded its own outcome; the parent did not overwrite it.
    assert h.state()["last_check"]["action"] == "activated"


def test_an_unsigned_record_never_reaches_the_bundle(h):
    record = json.loads(h.release(sequence=5, bundle=NEW_LAUNCHER))
    record["signature"]["value_base64"] = record["signature"]["value_base64"][::-1]
    h.metadata = json.dumps(record).encode()
    before = _releases(h)
    outcome = h.check()
    assert outcome.action == "refused"
    assert h.updater_current() == h.tree_a
    assert _releases(h) == before
    # The old updater still works.
    h.release(sequence=5)
    assert h.check().action == "activated"


def test_a_bundle_that_does_not_match_its_digest_is_refused(h):
    h.release(sequence=5, bundle=NEW_LAUNCHER)
    (digest,) = h.bundles
    original = h.bundles[digest]
    h.bundles[digest] = original[:100] + bytes([original[100] ^ 1]) + original[101:]
    outcome = h.check()
    assert outcome.action == "refused" and "archive digest" in outcome.reason
    assert h.updater_current() == h.tree_a


def test_a_bundle_whose_trust_root_would_lock_the_host_out_fails_its_probe(h):
    """A new trust root that drops the key which signed it would strand the host."""

    lockout = {"canary-1": DEFAULT_TRUST["canary-1"], "other-1": (OTHER_KEY, ["stable"])}
    h.release(sequence=5, bundle={"trust": lockout, **NEW_LAUNCHER})
    outcome = h.check()
    assert outcome.action == "refused" and "probe" in outcome.reason
    assert h.updater_current() == h.tree_a
    assert h.state()["failed"]["updater_tree"] is not None
    assert h.check().action == "refused"  # remembered, not retried hourly
    # A newer release with a sound bundle is still accepted by the old updater.
    h.release(sequence=6, bundle={"launcher_suffix": b"# launcher v3\n"})
    assert h.check().action == "activated"


def test_a_new_updater_that_crashes_on_its_first_run_is_reverted(h):
    h.release(sequence=5, bundle=NEW_LAUNCHER)
    outcome = h.check(handoff=lambda release_dir, fd: (1, None))
    assert outcome.action == "refused" and "crashed" in outcome.reason
    assert h.updater_current() == h.tree_a
    assert link_target(h.paths.updater_previous) is None
    assert h.state()["failed"]["updater_tree"] is not None
    assert h.active() == "legacy"


def test_a_second_self_update_inside_a_handoff_waits_for_the_next_run(h):
    h.release(sequence=5, bundle=NEW_LAUNCHER)
    host = h.host()
    host.handoff_depth = 1
    outcome = update_once(host)
    assert outcome.action == "refused" and "next check" in outcome.reason


def test_key_rotation_arrives_through_the_channel(h):
    """A bundle can add a key; the next record signed by it is then trusted."""

    rotated = {**DEFAULT_TRUST, "stable-2": (OTHER_KEY, ["stable"])}
    h.release(sequence=5, bundle={"trust": rotated, **NEW_LAUNCHER})
    assert h.check().action == "activated"
    h.release(
        sequence=6,
        image=h.image("3"),
        key=OTHER_KEY,
        key_id="stable-2",
        bundle={"trust": rotated, **NEW_LAUNCHER},
    )
    assert h.check().action == "activated"
    # And a key the rotated root no longer lists is refused.
    retired = {"canary-1": DEFAULT_TRUST["canary-1"], "stable-2": (OTHER_KEY, ["stable"])}
    h.release(
        sequence=7,
        image=h.image("4"),
        key=OTHER_KEY,
        key_id="stable-2",
        bundle={"trust": retired, **NEW_LAUNCHER},
    )
    assert h.check().action == "activated"
    h.release(sequence=8, image=h.image("5"), key=STABLE_KEY, key_id="stable-1", bundle={"trust": retired, **NEW_LAUNCHER})
    assert h.check().action == "refused"


# --- real processes ----------------------------------------------------------------------


def _real_clock(h: Harness) -> Harness:
    """Child processes read the real clock, so records must be fresh by it."""

    h.now = int(time.time())
    return h


def _root_env(h: Harness) -> dict[str, str]:
    return {
        "PATH": os.environ["PATH"],
        "CATHEDRAL_MINER_UPDATE_ROOT": str(h.paths.root),
        "CATHEDRAL_MINER_UPDATE_PYTHON": sys.executable,
    }


def test_the_real_probe_accepts_a_sound_updater(h):
    _real_clock(h)
    h.release(sequence=5, bundle=NEW_LAUNCHER)
    outcome = h.check(
        probe_updater=lambda release_dir, record: cli.probe_updater(h.paths, release_dir, record)
    )
    assert outcome.action == "activated", outcome.reason


def test_the_real_probe_refuses_a_broken_updater_and_the_old_one_keeps_working(h):
    _real_clock(h)
    broken = {"replace_modules": {"miner_updater.py": b"this is not python\n"}}
    h.release(sequence=5, bundle=broken)
    outcome = h.check(
        probe_updater=lambda release_dir, record: cli.probe_updater(h.paths, release_dir, record)
    )
    assert outcome.action == "refused" and "probe exited" in outcome.reason
    assert h.updater_current() == h.tree_a
    h.release(sequence=6)
    assert h.check().action == "activated"


def test_the_real_handoff_passes_the_lock_to_the_new_updater(h):
    """The child runs a full check holding the parent's lock.

    The child cannot reach the channel (a closed local port), so it refuses
    with a documented status. What matters: it did not report lock contention,
    and a documented refusal keeps the new updater current.
    """
    _real_clock(h)

    h.release(sequence=5, bundle=NEW_LAUNCHER)
    outcome = h.check(
        probe_updater=lambda release_dir, record: cli.probe_updater(h.paths, release_dir, record),
        handoff=lambda release_dir, fd: cli.handoff(h.paths, release_dir, fd, 0),
    )
    assert outcome.exit_status == EXIT_REFUSED
    assert "took over" in outcome.reason
    assert "download failed" in outcome.reason
    assert "already running" not in outcome.reason
    assert h.updater_current() != h.tree_a


def test_the_shim_hands_over_to_the_previous_updater_when_the_current_one_crashes(h, tmp_path):
    crashing = tmp_path / "crashing-tree"
    tree_b = build_tree(
        crashing,
        replace_modules={"miner_update_cli.py": b"raise RuntimeError('a broken updater')\n"},
    )
    install_directory(crashing, tree_sha256=tree_b, releases=h.paths.updater_releases)
    atomic_symlink(h.paths.updater_previous, f"releases/{h.tree_a}")
    atomic_symlink(h.paths.updater_current, f"releases/{tree_b}")

    result = subprocess.run(
        ["sh", str(SHIM), "check"], env=_root_env(h), capture_output=True, text=True, timeout=120
    )
    assert "previous updater takes over" in result.stderr
    assert result.returncode == EXIT_REFUSED, result.stderr[-2000:]
    assert h.updater_current() == h.tree_a
    assert link_target(h.paths.updater_previous) is None
    assert h.state()["failed"]["updater_tree"] == tree_b


def test_the_shim_does_not_fall_back_on_a_documented_refusal(h):
    atomic_symlink(h.paths.updater_previous, f"releases/{h.tree_a}")
    result = subprocess.run(
        ["sh", str(SHIM), "check"], env=_root_env(h), capture_output=True, text=True, timeout=120
    )
    assert result.returncode == EXIT_REFUSED
    assert "takes over" not in result.stderr
    document = json.loads(result.stdout.strip().splitlines()[-1])
    assert document["action"] == "refused" and "download failed" in document["reason"]
    assert link_target(h.paths.updater_previous) == f"releases/{h.tree_a}"


def test_the_shim_reports_status_without_the_channel(h):
    result = subprocess.run(
        ["sh", str(SHIM), "status"], env=_root_env(h), capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stderr
    status = json.loads(result.stdout)
    assert status["updater"]["current"] == f"releases/{h.tree_a}"
    assert status["config"]["miner_unit"] == h.config.miner_unit


def test_the_bundle_updater_imports_nothing_outside_the_bundle(tmp_path):
    """The updater runs from the bundle alone, on the host's Python and cryptography."""

    tree = tmp_path / "tree"
    build_tree(tree)
    script = (
        "import sys; sys.path.insert(0, sys.argv[1]); import cathedral.miner_update_cli; "
        "print(sorted(m for m in sys.modules if m.startswith('cathedral')))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tree / "updater")],
        capture_output=True,
        text=True,
        timeout=60,
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
    for module in loaded - {"cathedral"}:
        path = tree / "updater" / Path(*module.split(".")).with_suffix(".py")
        assert path.is_file()
