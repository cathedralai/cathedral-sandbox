"""The shipped systemd units, checked against what the updater actually does.

Review finding F1: #197's unit set ``InaccessiblePaths=-/etc/cathedral/validator-access``
while the safe-restart gate reads the snapshot inside it, so every unattended
check deferred and nothing reported it. The fakes-only tests could not see
that. These tests parse the real unit, and one runs a real check inside an
emulation of the unit's mount sandbox, with #197's mask as the negative control.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath

import pytest

from cathedral import miner_update_cli as cli
from cathedral.miner_updater import HostPaths
from tests.miner_update_support import REPO_ROOT, Harness

DEPLOY = REPO_ROOT / "deploy" / "miner-update"
SERVICE = DEPLOY / "cathedral-miner-update.service"
TIMER = DEPLOY / "cathedral-miner-update.timer"
DROPIN = DEPLOY / "miner-unit.conf"
REVIEWED_MASK = "-/etc/cathedral/validator-access"  # what #197 shipped


def directives(text: str) -> dict[str, list[str]]:
    """systemd-style: repeated keys accumulate, continuation lines join."""

    result: dict[str, list[str]] = {}
    logical = text.replace("\\\n", " ")
    for line in logical.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        key, _, value = line.partition("=")
        result.setdefault(key.strip(), []).append(value.strip())
    return result


def listed(values: list[str]) -> list[str]:
    return [item for value in values for item in value.split()]


def _under(path: PurePosixPath, entries: list[str]) -> bool:
    for entry in entries:
        base = PurePosixPath(entry.lstrip("-+"))
        if path == base or base in path.parents:
            return True
    return False


def _host_paths() -> dict[str, PurePosixPath]:
    """Every path HostPaths exposes, as absolute host paths."""

    paths = HostPaths()
    found = {}
    for name in dir(HostPaths):
        if isinstance(getattr(HostPaths, name), property):
            found[name] = PurePosixPath(str(getattr(paths, name)))
    return found


# Written only by the bootstrap or by an operator command, never by `check`.
NOT_WRITTEN_BY_CHECK = {"config_dir", "config_file", "pause_file", "pin_file", "systemd_dir", "operator_command", "snapshot"}


def test_every_path_the_updater_reads_is_visible_in_the_unit():
    unit = directives(SERVICE.read_text())
    hidden = listed(unit.get("InaccessiblePaths", [])) + listed(unit.get("TemporaryFileSystem", []))
    for name, path in _host_paths().items():
        assert not _under(path, hidden), f"the unit hides {name} ({path})"
    assert not _under(PurePosixPath(str(HostPaths().snapshot)), hidden)


def test_every_path_check_writes_is_writable_in_the_unit():
    unit = directives(SERVICE.read_text())
    assert unit["ProtectSystem"] == ["strict"]
    writable = listed(unit.get("ReadWritePaths", []))
    for name, path in _host_paths().items():
        if name in NOT_WRITTEN_BY_CHECK:
            continue
        assert _under(path, writable), f"check writes {name} ({path}) but the unit makes it read-only"


def test_the_unit_keeps_the_trust_root_and_config_read_only():
    """F17: the updater cannot rewrite its own config, and its keys live in immutable trees."""

    unit = directives(SERVICE.read_text())
    writable = listed(unit.get("ReadWritePaths", []))
    assert not _under(PurePosixPath(str(HostPaths().config_file)), writable)
    assert "/etc/cathedral" not in writable


def test_the_unit_hides_the_miners_own_database():
    unit = directives(SERVICE.read_text())
    assert "-/var/lib/cathedral/validator-access" in listed(unit["InaccessiblePaths"])


def test_the_unit_runs_the_frozen_shim():
    unit = directives(SERVICE.read_text())
    assert unit["ExecStart"] == [f"{HostPaths().shim} check"]
    assert unit["Type"] == ["oneshot"]
    assert unit["ConditionPathExists"] == [str(HostPaths().config_file)]


def test_the_unit_timeout_covers_the_worst_case():
    """F15: systemd must never kill a check between two durable steps."""

    unit = directives(SERVICE.read_text())
    (timeout,) = unit["TimeoutStartSec"]
    assert timeout.endswith("s")
    assert int(timeout[:-1]) >= cli.worst_case_seconds() + cli.SYSTEMD_MARGIN_SECONDS


def test_the_timer_triggers_the_service():
    timer = directives(TIMER.read_text())
    assert timer["Unit"] == [SERVICE.name]
    assert timer["OnUnitActiveSec"] == ["1h"]


def test_the_miner_dropin_selects_the_active_release():
    dropin = directives(DROPIN.read_text())
    current = HostPaths().miner_current
    assert dropin["ExecStart"] == ["", str(current / "launcher")]
    assert dropin["EnvironmentFile"] == [str(current / "release.env")]


# --- the sandbox, emulated ----------------------------------------------------------------

_CHILD = r"""
import json, sys, time
from pathlib import Path
from cathedral.miner_bundle import TREE_TRUST_ROOT, link_target
from cathedral.miner_release import load_trust_root
from cathedral.miner_update_cli import safe_to_activate
from cathedral.miner_updater import HostPaths, LEGACY, MinerUpdaterHost, load_config, read_activation_profile, update_once
import os

root, record = Path(sys.argv[1]), Path(sys.argv[2])
paths = HostPaths(root=root)
tree = str(link_target(paths.updater_current)).split("/")[-1]
running = {}

def systemctl(arguments):
    if arguments[0] == "restart":
        target = link_target(paths.miner_current)
        profile = read_activation_profile(paths, target)
        running[profile["container"]] = profile.get("image")

readonly_etc = True
try:
    (root / "etc" / "cathedral" / "probe-write").write_text("x")
    readonly_etc = False
except OSError:
    pass

host = MinerUpdaterHost(
    config=load_config(paths.config_file, expected_uid=os.getuid()),
    paths=paths,
    trusted_keys=load_trust_root((paths.updater_releases / tree / TREE_TRUST_ROOT).read_bytes()),
    running_tree=tree,
    fetch_metadata=lambda: record.read_bytes(),
    fetch_bundle=lambda bundle: b"",
    probe_updater=lambda release, saved: {},
    handoff=lambda release, fd: (1, None),
    prepare_image=lambda release, profile: None,
    systemctl=systemctl,
    current_image=lambda container: running.get(container, "legacy-image"),
    settled_image=lambda container: running.get(container),
    safe_to_activate=lambda: safe_to_activate(paths.snapshot),
    now_unix=lambda: int(time.time()),
    expected_uid=os.getuid(),
)
gate = safe_to_activate(paths.snapshot)
outcome = update_once(host)
print(json.dumps({"gate": gate, "readonly_etc": readonly_etc, "outcome": outcome.as_dict()}))
"""


def _mounts_for(unit_text: str, root: Path) -> list[str]:
    """Shell commands that apply the unit's mount sandbox under ``root``."""

    unit = directives(unit_text)
    commands = []
    if unit.get("ProtectSystem") == ["strict"]:
        commands += [f"mount --bind {root} {root}", f"mount -o remount,bind,ro {root}"]
    for entry in listed(unit.get("ReadWritePaths", [])):
        target = root / entry.lstrip("-").lstrip("/")
        if target.exists():
            commands += [f"mount --bind {target} {target}", f"mount -o remount,bind,rw {target}"]
    for entry in listed(unit.get("InaccessiblePaths", [])):
        target = root / entry.lstrip("-").lstrip("/")
        if target.is_dir():
            # systemd mounts an empty, mode-000 directory here.
            commands.append(f"mount -t tmpfs -o mode=000,size=4k tmpfs {target}")
        elif target.exists():
            commands.append(f"mount --bind /dev/null {target}")
        elif not entry.startswith("-"):
            raise AssertionError(f"required inaccessible path is missing: {entry}")
    return commands


def _can_emulate() -> bool:
    if os.geteuid() != 0 or shutil.which("unshare") is None:
        return False
    probe = subprocess.run(["unshare", "-m", "true"], capture_output=True)
    return probe.returncode == 0


def _run_sandboxed(tmp_path: Path, unit_text: str) -> dict:
    h = Harness(tmp_path)
    h.now = int(time.time())
    record = h.release(sequence=5)
    (tmp_path / "record.json").write_bytes(record)
    snapshot = h.paths.snapshot
    snapshot.parent.mkdir(parents=True)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    snapshot.write_text(json.dumps({"expires_at": expires.isoformat().replace("+00:00", "Z")}))
    miner_db = h.paths.root / "var/lib/cathedral/validator-access"
    miner_db.mkdir(parents=True)
    (miner_db / "validator-access.sqlite").write_bytes(b"live")
    h.paths.state_dir.mkdir(parents=True, exist_ok=True)
    (tmp_path / "child.py").write_text(_CHILD)

    script = " && ".join(
        _mounts_for(unit_text, h.paths.root)
        + [f"exec {sys.executable} {tmp_path / 'child.py'} {h.paths.root} {tmp_path / 'record.json'}"]
    )
    result = subprocess.run(
        ["unshare", "-m", "sh", "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
    )
    assert result.returncode == 0, result.stderr[-3000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.skipif(not _can_emulate(), reason="needs root and a mount namespace")
def test_a_check_under_the_units_sandbox_activates_a_release(tmp_path):
    """F1, end to end: the gate sees the snapshot and the release activates."""

    report = _run_sandboxed(tmp_path, SERVICE.read_text())
    assert report["readonly_etc"] is True, "the emulation did not apply ProtectSystem=strict"
    assert report["gate"] is True
    assert report["outcome"]["action"] == "activated", report["outcome"]["reason"]


@pytest.mark.skipif(not _can_emulate(), reason="needs root and a mount namespace")
def test_the_reviewed_mask_would_defer_every_check(tmp_path):
    """Negative control: the emulation reproduces F1 with #197's line."""

    text = SERVICE.read_text().replace(
        "InaccessiblePaths=-/var/lib/cathedral/validator-access",
        f"InaccessiblePaths=-/var/lib/cathedral/validator-access {REVIEWED_MASK}",
    )
    report = _run_sandboxed(tmp_path, text)
    assert report["gate"] is False
    assert report["outcome"]["action"] == "deferred"


# --- systemd's own verifier ---------------------------------------------------------------


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze is not installed")
def test_systemd_analyze_accepts_the_units(tmp_path):
    units = tmp_path / "units"
    units.mkdir()
    for source in (SERVICE, TIMER):
        shutil.copy(source, units / source.name)
    result = subprocess.run(
        ["systemd-analyze", "verify", "--man=no", str(units / SERVICE.name), str(units / TIMER.name)],
        capture_output=True,
        text=True,
        env={**os.environ, "SYSTEMD_UNIT_PATH": f"{units}:"},
        timeout=60,
    )
    complaints = [line for line in (result.stdout + result.stderr).splitlines() if line.strip()]
    # The shim is installed by the bootstrap, so on a build machine it is absent.
    unexpected = [line for line in complaints if str(HostPaths().shim) not in line]
    assert unexpected == [], complaints


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze is not installed")
def test_systemd_follows_the_dropin_symlink_to_the_active_release(tmp_path):
    """The miner drop-in is a symlink to miner/current/unit.conf; flipping it switches ExecStart."""

    units = tmp_path / "units"
    (units / "demo-miner.service.d").mkdir(parents=True)
    (units / "demo-miner.service").write_text("[Service]\nType=simple\nExecStart=/bin/true\n")
    release = tmp_path / "release"
    release.mkdir()
    (release / "unit.conf").write_text(
        DROPIN.read_text().replace(str(HostPaths().miner_current), str(tmp_path / "current"))
    )
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "unit.conf").write_text("")
    os.symlink(release, tmp_path / "current")
    os.symlink(tmp_path / "current" / "unit.conf", units / "demo-miner.service.d" / "50-cathedral-miner-update.conf")

    def verify() -> str:
        result = subprocess.run(
            ["systemd-analyze", "verify", "--man=no", str(units / "demo-miner.service")],
            capture_output=True,
            text=True,
            env={**os.environ, "SYSTEMD_UNIT_PATH": f"{units}:"},
            timeout=60,
        )
        return result.stdout + result.stderr

    assert str(tmp_path / "current" / "launcher") in verify()
    os.unlink(tmp_path / "current")
    os.symlink(legacy, tmp_path / "current")
    assert "launcher" not in verify()
