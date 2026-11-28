"""The generated VM unit under a real systemd (live VM proof, 28 Nov, systemd 259.5).

The unit has TemporaryFileSystem=/srv:ro and binds back only what QEMU needs. A `+` hook runs with full privileges
but still inside that mount namespace, so the unit's check-paid found no authorization.json, read the default
generation 0 and refused every start as generation_closed. The fake systemctl of tests/test_ab991_vm_runtime.py never
runs a unit, so none of that showed. This test installs the unit text vm_ctl.py generates, runs the real
`vm-ctl.sh check-paid` and `powerdown` in it, with stubs in place of QEMU, the gates and the link, and checks what
each step can see. It needs root and a systemd: it runs in .github/workflows/vm-unit.yml with VM_SYSTEMD_TESTS=1
and is skipped elsewhere. The job runs on ubuntu-24.04 (systemd 255) and ubuntu-26.04 (259, the proof host's).
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "room-kit" / "vm"
# The kit is copied out of the checkout: the runner's home is not traversable by the VM user, and ProtectHome=yes.
KIT = Path("/opt/cathedral-vm-unit-test/vm")
VM_ROOT = Path("/srv/cathedral-vm-unit-test")
NAME = "vm-0a1b2c3d4e5f"
USER = "cvm-ut"
BUNDLE = "ab" * 32
UNIT = f"cathedral-vm-{NAME}.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT
LOCKS = ("cathedral-vm-ut.lock", "cathedral-vm-ut-net.up", "cathedral-vm-ut-net.down", "cathedral-vm-ut-gates")

pytestmark = pytest.mark.skipif(
    os.environ.get("VM_SYSTEMD_TESTS") != "1" or os.geteuid() != 0 or shutil.which("systemctl") is None,
    reason="needs root, systemd and VM_SYSTEMD_TESTS=1")


def sh(*argv, check=True, **kw):
    return subprocess.run(list(argv), capture_output=True, text=True, check=check, **kw)


def systemd_version() -> int:
    return int(re.search(r"systemd (\d+)", sh("systemctl", "--version").stdout).group(1))


# What each stub does to the file system is what the real step does, and nothing else. The gates read vm.env and the
# bundle manifest; vm-net.sh sources vm.env and takes its lock under /run/lock.
GATES = r'''#!/bin/sh
set -eu
[ "$1" = check ] || exit 2
grep -q "^VM_NAME='$2'$" "$VM_ROOT/$2/vm.env"
test -r "$VM_ROOT/bundles/__BUNDLE__/manifest.json"
echo ok > /run/lock/cathedral-vm-ut-gates
'''
NET = r'''#!/bin/sh
set -eu
. "$2"
mkdir -p /run/lock
exec 9>/run/lock/cathedral-vm-ut.lock
flock -n 9
echo "$VM_NAME" > "/run/lock/cathedral-vm-ut-net.$1"
'''
LAUNCH = r'''#!/usr/bin/env python3
# Stands in for QEMU: records what the VM's own process can see, then powers off (exit 0, the unit stays down).
import json, os, sys
d = sys.argv[1]
def can_write(path):
    try:
        with open(path, "ab"):
            return True
    except OSError:
        return False
seen = []
for root, dirs, files in os.walk("/srv"):
    rel = os.path.relpath(root, "/srv")
    if rel != ".":
        seen.append(rel)
        seen.extend(os.path.join(rel, f) for f in files)
with open(os.path.join(d, "run", "guest-view.json"), "w") as f:
    json.dump({"srv": sorted(seen), "authorization_visible": os.path.exists(os.path.join(d, "authorization.json")),
               "root_writable": can_write(os.path.join(d, "root.raw")), "user": os.getuid()}, f)
'''


def load_ctl():
    spec = importlib.util.spec_from_file_location("vm_ctl_unit", KIT / "vm_ctl.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def vm(monkeypatch):
    monkeypatch.setenv("VM_ROOT", str(VM_ROOT))
    monkeypatch.delenv("SYSTEMD_UNIT_DIR", raising=False)
    shutil.rmtree(KIT, ignore_errors=True)
    shutil.copytree(SRC, KIT, ignore=shutil.ignore_patterns("__pycache__"))
    for name, body in {"vm-gates.sh": GATES, "vm-net.sh": NET, "launch-vm.py": LAUNCH}.items():
        (KIT / name).write_text(body.replace("__BUNDLE__", BUNDLE))
        (KIT / name).chmod(0o755)
    sh("chmod", "-R", "a+rX", str(KIT.parent))
    mod = load_ctl()
    sh("groupadd", "-r", mod.SEV_GROUP, check=False)
    sh("groupadd", "-r", "kvm", check=False)
    sh("useradd", "-r", "-M", "-s", "/usr/sbin/nologin", USER, check=False)
    d = VM_ROOT / NAME
    (VM_ROOT / "bundles" / BUNDLE).mkdir(parents=True, exist_ok=True)
    (VM_ROOT / "bundles" / BUNDLE / "manifest.json").write_text("{}\n")
    (d / "run").mkdir(parents=True, exist_ok=True)
    # Like a real host: every VM directory is root's, mode 0700; the disks and run/ are the VM user's.
    sh("chmod", "700", str(d))
    for f in ("root.raw", "mailbox.raw"):
        (d / f).write_bytes(b"")
    (d / "vm-identity.json").write_text("{}\n")
    sh("chown", f"{USER}:{USER}", str(d / "root.raw"), str(d / "mailbox.raw"), str(d / "run"))
    env = {"VM_NAME": NAME, "VM_USER": USER, "VM_BUNDLE": BUNDLE, "VM_MEM_GIB": "1", "VM_VCPUS": "1"}
    mod.write_env(d, env)
    # A paid, started generation 1, as `vm-ctl start` leaves it just before `systemctl start`.
    mod.write_atomic(d / "authorization.json",
                     json.dumps({"generation": 1, "paid_through": int(time.time()) + 3600, "closed_generation": 0}) + "\n")
    mod.write_atomic(d / "launch.json", json.dumps({"bundle": BUNDLE, "bundle_selection_revision": 0}) + "\n")
    mod.history_append(NAME, {"event": "tracked_from", "generation": 1})
    mod.history_append(NAME, {"event": "start", "generation": 1, **mod.stamp()})
    # What `vm-ctl stop` leaves before it stops the unit: ExecStop's powerdown must see it and not ask again.
    mod.powerdown_marker(d).write_text("")
    text = mod.unit_text(NAME, d, env)
    # The only change to the generated text: the /dev/kvm wait. The runner may have no /dev/kvm, and the unit would
    # wait 120 s for it. Every other line is exactly what a host gets.
    lines = text.splitlines()
    wait = [i for i, ln in enumerate(lines) if "no /dev/kvm after 120 s" in ln]
    assert len(wait) == 1
    lines[wait[0]] = f"ExecStartPre=+{mod.HOST_NS} /bin/true"
    UNIT_PATH.write_text("\n".join(lines) + "\n")
    sh("systemctl", "daemon-reload")
    yield {"mod": mod, "d": d}
    sh("systemctl", "stop", UNIT, check=False)
    sh("systemctl", "reset-failed", UNIT, check=False)
    UNIT_PATH.unlink(missing_ok=True)
    sh("systemctl", "daemon-reload", check=False)
    shutil.rmtree(VM_ROOT, ignore_errors=True)
    shutil.rmtree(KIT.parent, ignore_errors=True)
    for f in LOCKS:
        Path("/run/lock", f).unlink(missing_ok=True)


def state_of(unit: str) -> str:
    return sh("systemctl", "is-active", unit, check=False).stdout.strip()


def wait_for(cond, seconds: float = 90) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.5)
    return cond()


def log_of(unit: str, since: float) -> str:
    """The unit's journal since `since` (a Unix time), so an earlier test's run of the same unit is not read."""
    return sh("journalctl", "-u", unit, "--since", f"@{int(since)}", "--no-pager", "-o", "cat", check=False).stdout


def logged(unit: str, since: float, text: str, seconds: float = 30) -> bool:
    return wait_for(lambda: text in log_of(unit, since), seconds)


def test_the_generated_unit_passes_check_paid_runs_its_hooks_on_the_host_and_hides_srv_from_the_vm(vm):
    print(f"systemd {systemd_version()} on the runner (the proof host that failed ran 259)")
    since = time.time() - 1
    result = sh("systemctl", "start", UNIT, check=False)
    wait_for(lambda: state_of(UNIT) in ("inactive", "failed"))
    d = vm["d"]
    detail = f"start rc={result.returncode} {result.stderr}\n{log_of(UNIT, since)}"
    # 1. The real check-paid (a + hook) read authorization.json, launch.json and the history journal and passed:
    #    the VM process ran at all.
    assert (d / "run" / "guest-view.json").exists(), detail
    assert logged(UNIT, since, '"paid": true'), detail
    # 2. The gates and vm-net.sh up and down ran, and took their lock under /run/lock.
    assert Path("/run/lock/cathedral-vm-ut-gates").read_text().strip() == "ok", detail
    assert Path("/run/lock/cathedral-vm-ut-net.up").read_text().strip() == NAME, detail
    assert Path("/run/lock/cathedral-vm-ut-net.down").read_text().strip() == NAME, detail
    # 3. The real powerdown (ExecStop +) saw the marker `vm-ctl stop` leaves in the VM directory.
    assert logged(UNIT, since, "vm-ctl stop already asked and waited"), detail
    assert state_of(UNIT) == "inactive", detail
    # 4. The VM process still sees only its own bundle and files, no billing state, and it is the VM user.
    view = json.loads((d / "run" / "guest-view.json").read_text())
    top = VM_ROOT.name
    assert set(view["srv"]) == {top, f"{top}/bundles", f"{top}/bundles/{BUNDLE}", f"{top}/bundles/{BUNDLE}/manifest.json",
                                f"{top}/{NAME}", f"{top}/{NAME}/vm.env", f"{top}/{NAME}/vm-identity.json",
                                f"{top}/{NAME}/root.raw", f"{top}/{NAME}/mailbox.raw", f"{top}/{NAME}/run"}, view
    assert view["authorization_visible"] is False and view["root_writable"] is True, view
    assert view["user"] != 0, view


def test_every_plus_hook_of_the_unit_is_wrapped_and_the_vm_line_is_not(vm):
    text = UNIT_PATH.read_text()
    plus = [ln for ln in text.splitlines() if re.match(r"Exec(StartPre|Stop|StopPost)=\+", ln)]
    assert len(plus) == 8
    for ln in plus:
        assert vm["mod"].HOST_NS in ln, ln
    assert "nsenter" not in next(ln for ln in text.splitlines() if ln.startswith("ExecStart="))


def test_the_unwrapped_unit_refuses_every_start_as_generation_closed(vm):
    """The control: the unit without the host-namespace wrapper (main before this change) must fail, on every
    systemd version, for the reason the live proof saw. That proves the old unit breaks and that the passing test
    above can fail."""
    UNIT_PATH.write_text(UNIT_PATH.read_text().replace(vm["mod"].HOST_NS + " ", ""))
    sh("systemctl", "daemon-reload")
    since = time.time() - 1
    sh("systemctl", "start", UNIT, check=False)
    # Restart=on-failure keeps it in auto-restart, so wait for the refusal in the journal, not for an end state.
    seen = logged(UNIT, since, "generation_closed", 60)
    print(f"systemd {systemd_version()}: the unit WITHOUT the host namespace: {state_of(UNIT)}; "
          f"a refusal here is the bug this change fixes\n{log_of(UNIT, since)}")
    assert seen, log_of(UNIT, since)
    assert not (vm["d"] / "run" / "guest-view.json").exists()
