"""The generated custom guest unit under a real systemd (rehearsal B, run 3, 27 Nov).

The unit has TemporaryFileSystem=/srv:ro and ProtectSystem=strict. From systemd 259 a `+` hook runs with full
privileges but still inside that mount namespace, so check-start found an empty /srv (no host journal), exited
could not write the journal (EROFS) and custom-net.sh could not take its lock under /run/lock. The fake systemctl
of the other tests never ran a unit, so none of that showed. This test installs the unit text the module
generates, with stub scripts in place of QEMU and the real hooks, starts it with systemctl and checks what a
hook can see and write. It needs root and a systemd: it runs in .github/workflows/custom-guest-unit.yml with
CG_SYSTEMD_TESTS=1 and is skipped elsewhere. The runner's systemd version is printed; where it is older than
259 the old behaviour does not reproduce, but the generated unit must pass on every version.
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
OPS = REPO / "ops" / "custom-guest"
HOTEL, LAUNCH = "ut-ci", "cg-0a1b2c3d4e5f"
USER = f"cg-{HOTEL}"
UNIT = f"custom-guest-{LAUNCH}.service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT

pytestmark = pytest.mark.skipif(
    os.environ.get("CG_SYSTEMD_TESTS") != "1" or os.geteuid() != 0 or shutil.which("systemctl") is None,
    reason="needs root, systemd and CG_SYSTEMD_TESTS=1")


def sh(*argv, check=True, **kw):
    return subprocess.run(list(argv), capture_output=True, text=True, check=check, **kw)


def systemd_version() -> int:
    return int(re.search(r"systemd (\d+)", sh("systemctl", "--version").stdout).group(1))


def load_host():
    os.environ.pop("CG_ROOT", None)
    sys.path.insert(0, str(OPS))
    spec = importlib.util.spec_from_file_location("cg_host_unit", OPS / "custom_guest_host.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# What each stub does is what the real hook does to the file system, and nothing else: read the journal under
# /srv, append to it, take a lock under /run/lock, read the images. They fail loudly where the real ones would.
CHECK_START = r'''#!/bin/sh
set -eu
J=/srv/custom-guest/__HOTEL__/host-journal.jsonl
[ -s "$J" ] || { echo "check-start: no host journal at $J: /srv is hidden from this hook" >&2; exit 1; }
tail -n 1 "$J" | grep -q '"event": "boot".*"state": "intent"' || { echo "check-start: latest entry is not a boot intent" >&2; exit 1; }
echo '{"event": "token_used"}' >> "$J"
'''
EXITED = r'''#!/bin/sh
set -eu
J=/srv/custom-guest/__HOTEL__/host-journal.jsonl
echo "{\"event\": \"exit\", \"exit_status\": \"${EXIT_STATUS:-}\", \"service_result\": \"${SERVICE_RESULT:-}\"}" >> "$J"
'''
NET_UP = r'''#!/bin/sh
set -eu
[ "$1" = up ] || exit 2
D=/srv/custom-guest/__HOTEL__/__LAUNCH__
test -r "$D/images/bootstrap.json"
mkdir -p /run/lock
exec 9>/run/lock/custom-guest-ut.lock
flock -n 9
echo locked > /run/lock/custom-guest-ut.done
'''
LAUNCH_STUB = r'''#!/usr/bin/env python3
# Stands in for QEMU: records what the guest process can see.
import os, sys
d = sys.argv[1]
def can_write(path):
    try:
        with open(path, "ab"):
            return True
    except OSError:
        return False
seen = sorted(os.listdir("/srv")) if os.path.isdir("/srv") else None
with open(os.path.join(d, "run", "stub-ran"), "w") as f:
    f.write("ran\n")
with open(os.path.join(d, "run", "guest-view.json"), "w") as f:
    import json
    json.dump({"srv": seen, "journal_visible": os.path.exists("/srv/custom-guest/__HOTEL__/host-journal.jsonl"),
               "images_writable": can_write(os.path.join(d, "images", "x")), "disks_writable": can_write(os.path.join(d, "disks", "x")),
               "user": os.getuid()}, f)
'''


@pytest.fixture
def host():
    mod = load_host()
    base = Path(f"/srv/custom-guest/{HOTEL}")
    d = base / LAUNCH
    lib = Path(mod.LIBDIR)
    sh("groupadd", "-r", "cg-sev", check=False)
    sh("groupadd", "-r", "kvm", check=False)
    sh("useradd", "-r", "-M", "-s", "/usr/sbin/nologin", USER, check=False)
    for sub in ("images", "disks", "run"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    # Like a real host: the hotel folder is traversable, the journal is root-only.
    sh("chmod", "711", "/srv/custom-guest", str(base), str(d))
    (d / "images" / "bootstrap.json").write_text("{}")
    sh("chmod", "755", str(d / "images"))
    sh("chown", "-R", f"{USER}:{USER}", str(d / "disks"), str(d / "run"))
    lib.mkdir(parents=True, exist_ok=True)
    stubs = {"custom-guest-host.sh": None, "custom-net.sh": NET_UP, "launch-custom-guest.py": LAUNCH_STUB}
    host_script = '#!/bin/sh\ncase "$1" in\n  check-start) exec /bin/sh __LIB__/check-start.sh ;;\n  exited) exec /bin/sh __LIB__/exited.sh ;;\n  *) exit 2 ;;\nesac\n'
    for name, body in {**stubs, "custom-guest-host.sh": host_script, "check-start.sh": CHECK_START, "exited.sh": EXITED}.items():
        text = body.replace("__HOTEL__", HOTEL).replace("__LAUNCH__", LAUNCH).replace("__LIB__", str(lib))
        (lib / name).write_text(text)
        (lib / name).chmod(0o755)
    journal = base / "host-journal.jsonl"
    journal.write_text(json.dumps({"event": "boot", "state": "intent", "launch_id": LAUNCH, "generation": 1, "token": "t"}) + "\n")
    journal.chmod(0o600)
    ctx = mod.Ctx("boot", HOTEL, LAUNCH, {}, {})
    text = mod.unit_text(ctx, 4)
    # The only change to the generated text: the /dev/kvm wait. The runner may have no /dev/kvm, and the
    # unit would wait 120 s for it. Every other line is exactly what a host gets.
    lines = text.splitlines()
    wait = [i for i, ln in enumerate(lines) if "no /dev/kvm after 120 s" in ln]
    assert len(wait) == 1
    lines[wait[0]] = f"ExecStartPre=+{mod.HOST_NS} /bin/true"
    UNIT_PATH.write_text("\n".join(lines) + "\n")
    sh("systemctl", "daemon-reload")
    yield {"mod": mod, "d": d, "journal": journal, "base": base}
    sh("systemctl", "stop", UNIT, check=False)
    sh("systemctl", "reset-failed", UNIT, check=False)
    UNIT_PATH.unlink(missing_ok=True)
    sh("systemctl", "daemon-reload", check=False)
    shutil.rmtree(base, ignore_errors=True)
    shutil.rmtree(lib, ignore_errors=True)
    for f in ("custom-guest-ut.lock", "custom-guest-ut.done"):
        Path("/run/lock", f).unlink(missing_ok=True)


def wait_inactive(unit: str, seconds: float = 60) -> str:
    end = time.time() + seconds
    while time.time() < end:
        state = sh("systemctl", "is-active", unit, check=False).stdout.strip()
        if state in ("inactive", "failed"):
            return state
        time.sleep(0.5)
    return sh("systemctl", "is-active", unit, check=False).stdout.strip()


def log_of(unit: str) -> str:
    return sh("journalctl", "-u", unit, "--no-pager", "-o", "cat", check=False).stdout


def test_the_generated_unit_starts_runs_its_hooks_on_the_host_and_hides_srv_from_the_guest(host):
    version = systemd_version()
    print(f"systemd {version} on the runner (the rehearsal host that failed ran 259)")
    result = sh("systemctl", "start", UNIT, check=False)
    state = wait_inactive(UNIT)
    detail = f"start rc={result.returncode} {result.stderr}\n{log_of(UNIT)}"
    d, journal = host["d"], host["journal"]

    # 1. check-start (a + hook) read the real host journal and passed: the unit ran at all.
    assert (d / "run" / "stub-ran").read_text() == "ran\n", detail
    entries = [json.loads(line) for line in journal.read_text().splitlines()]
    events = [e["event"] for e in entries]
    assert "token_used" in events, f"check-start did not write to the real journal\n{detail}"
    # 2. custom-net.sh (a + hook) read images/bootstrap.json and took its lock under /run/lock.
    assert Path("/run/lock/custom-guest-ut.done").read_text().strip() == "locked", detail
    # 3. exited (ExecStopPost +) appended to the real journal after the stub ended.
    assert events[-1] == "exit", f"exited did not write the journal: {events}\n{detail}"
    assert state == "inactive", f"{state}\n{detail}"
    # 4. The guest process still sees only its own folders: an empty /srv apart from nothing, no host journal,
    #    images read-only, disks writable, and it is the unprivileged user.
    view = json.loads((d / "run" / "guest-view.json").read_text())
    assert view["srv"] == [], view
    assert view["journal_visible"] is False, view
    assert view["images_writable"] is False and view["disks_writable"] is True, view
    assert view["user"] != 0, view


def test_every_plus_hook_of_the_unit_is_wrapped_and_the_guest_line_is_not(host):
    text = UNIT_PATH.read_text()
    hook_ns = host["mod"].HOST_NS
    plus = [ln for ln in text.splitlines() if re.match(r"Exec(StartPre|StopPost)=\+", ln)]
    assert len(plus) == 6
    for ln in plus:
        assert hook_ns in ln, ln
    assert "nsenter" not in next(ln for ln in text.splitlines() if ln.startswith("ExecStart="))


def test_report_whether_the_unwrapped_unit_fails_on_this_systemd(host):
    """Not an assertion about the fix: on systemd 259 the old unit failed check-start, on older ones it
    passed. Printed so a CI log shows which side of the change this runner is on."""
    unwrapped = UNIT_PATH.read_text().replace(host["mod"].HOST_NS + " ", "")
    UNIT_PATH.write_text(unwrapped)
    sh("systemctl", "daemon-reload")
    sh("systemctl", "start", UNIT, check=False)
    state = wait_inactive(UNIT)
    print(f"systemd {systemd_version()}: the unit WITHOUT the host namespace ended {state}; "
          f"a failure here is the bug this change fixes")
