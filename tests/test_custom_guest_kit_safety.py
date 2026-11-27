"""AB#999 PR 2 kit safety: the host lock, the kit unit guard and the custom guest hold marker.

Spec r9 5.3 (one host lock, an explicit owner, a timeout, no nesting), 5.10 (kit guard and marker)
and the 14.1 "Lock" and "Guard" cases. Everything runs the real scripts with real flock and real
files; only systemctl and id are faked. The roll call graph and the roll exclusion cases live in
tests/test_ab453_roll.py next to its fake ssh, curl and host tree.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"
SEALED = KIT / "sealed"
LIB = SEALED / "host-lock.sh"
LAUNCH = "cg-0123456789ab"
OTHER = "cg-ba9876543210"

pytestmark = pytest.mark.skipif(shutil.which("flock") is None or not Path("/proc/self/status").exists(),
                                reason="needs util-linux flock and /proc (Linux), as on the hosts")

# The kit unit as main wrote it before this change, for /srv/sealed-hotel-9 (nc-sealed-9).
UNIT_BEFORE = """[Unit]
Description=Sealed hotel nc-sealed-9 (AMD SEV-SNP guest with the room kit)
After=network-online.target systemd-modules-load.service
Wants=network-online.target
# At most 5 starts in 15 min, then the unit stays failed for a person to look at.
StartLimitIntervalSec=900
StartLimitBurst=5
[Service]
Type=simple
ExecStartPre=-/sbin/modprobe -q kvm_amd
ExecStartPre=/bin/sh -c 'for i in $$(seq 1 120); do [ -c /dev/kvm ] && exit 0; sleep 1; done; echo "no /dev/kvm after 120 s" >&2; exit 1'
ExecStartPre=/srv/sealed-hotel-9/host-net.sh up /srv/sealed-hotel-9/sealed.env
ExecStart=/srv/sealed-hotel-9/launch-guest.sh /srv/sealed-hotel-9/sealed.env
ExecStopPost=/srv/sealed-hotel-9/host-net.sh down /srv/sealed-hotel-9/sealed.env
KillSignal=SIGTERM
TimeoutStopSec=60
# The /dev/kvm wait alone may take 120 s; the default 90 s start timeout would cut it short.
TimeoutStartSec=180
Restart=on-failure
RestartSec=15
LimitMEMLOCK=infinity
[Install]
WantedBy=multi-user.target
"""
GUARD_COMMENT = "# Custom guest hold guard (spec r9 5.10): no start while the hold marker says held; none without it."
GUARD = ("ExecStartPre=/bin/sh -c '[ ! -e {d}/custom-guest.hold ] || "
         "grep -q \"[{{,] *.state. *: *.kit_start.\" {d}/custom-guest.hold'")

FAKE_SYSTEMCTL = """#!/bin/bash
echo "systemctl $* record=$(cat "$CATHEDRAL_SNP_LOCK_DIR/cathedral-snp-host.owner" 2>/dev/null || echo none)" >> "$FAKE_LOG"
exit 0
"""
FAKE_ID = '#!/bin/bash\ncase "${1:-}" in -u) echo 0 ;; *) exit 0 ;; esac\n'
FLOCK_WRAPPER = '#!/bin/bash\necho "flock $*" >> "$FAKE_LOG"\nexec {real} "$@"\n'


class Box:
    """A lock dir, a fake PATH (systemctl, id, a logging flock) and a kit copy."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.lock = tmp / "run-lock"
        self.log = tmp / "calls.log"
        self.log.write_text("")
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for name, body in (("systemctl", FAKE_SYSTEMCTL), ("id", FAKE_ID),
                           ("flock", FLOCK_WRAPPER.format(real=shutil.which("flock")))):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.kit = tmp / "kit"
        shutil.copytree(SEALED, self.kit / "sealed", ignore=shutil.ignore_patterns("sealed.env", "__pycache__"))
        shutil.copy2(KIT / "install.sh", self.kit / "install.sh")
        self.root = tmp / "root"
        self.sealed_dir = tmp / "srv" / "sealed-hotel-9"
        self.sealed_dir.mkdir(parents=True)
        self.env_file = tmp / "sealed.env"
        self.env_file.write_text(f"SEALED_NAME=sealed-9\nSEALED_DIR={self.sealed_dir}\n")

    def env(self, **extra: str) -> dict[str, str]:
        e = {k: v for k, v in os.environ.items() if not k.startswith("CATHEDRAL_SNP_LOCK")}
        e.update({"PATH": f"{self.bin}:{e.get('PATH', '/usr/bin:/bin')}", "CATHEDRAL_SNP_LOCK_DIR": str(self.lock),
                  "ROOM_DESTDIR": str(self.root), "FAKE_LOG": str(self.log)})
        e.update(extra)
        return e

    def sh(self, script: str, timeout: float = 30, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", "-c", f"source {shlex.quote(str(LIB))}\n{script}"], env=self.env(**extra),
                              capture_output=True, text=True, timeout=timeout)

    def holder(self, phase: str = "hold-stop", launch: str = LAUNCH, entry: str = "custom-guest",
               then: str = "sleep 60") -> subprocess.Popen[str]:
        """A top-level holder (a custom guest phase) that prints its owner, then runs *then*."""
        p = subprocess.Popen(["bash", "-c", f"source {shlex.quote(str(LIB))}\n"
                              f"snp_lock_take {entry} {phase} sealed-9 {launch} 900 || exit 9\n"
                              f'echo "ready $CATHEDRAL_SNP_LOCK_OWNER"\n{then}'],
                             env=self.env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             start_new_session=True)
        line = p.stdout.readline()
        assert line.startswith("ready "), (line, p.stderr.read() if p.poll() is not None else "")
        p.owner = line.split()[1]
        return p

    def flocks(self) -> list[str]:
        return [x for x in self.log.read_text().splitlines() if x.startswith("flock ")]

    def unit(self) -> Path:
        return self.root / "etc" / "systemd" / "system" / "room-sealed-sealed-9.service"

    def marker(self, state: str = "held", launch: str = LAUNCH, raw: str | None = None) -> None:
        text = raw if raw is not None else json.dumps({"launch_id": launch, "state": state}) + "\n"
        (self.sealed_dir / "custom-guest.hold").write_text(text)

    def write_units(self, *, env_file: Path | None = None, **extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", str(self.kit / "sealed" / "write-units.sh"), str(env_file or self.env_file)],
                              env=self.env(**extra), capture_output=True, text=True, timeout=30)


def stop(p: subprocess.Popen[str]) -> None:
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    p.wait(timeout=10)


@pytest.fixture
def box(tmp_path: Path) -> Box:
    return Box(tmp_path)


# ---------------------------------------------------------------- the lock (5.3)

def test_a_top_level_entry_writes_the_owner_record_and_removes_it_at_release(box: Box) -> None:
    r = box.sh('snp_lock_take roll host_install hotel-x - 3600 || exit 9\n'
               'echo "pid=$$ fd=$CATHEDRAL_SNP_LOCK_FD owner=$CATHEDRAL_SNP_LOCK_OWNER"\n'
               'cat "$SNP_LOCK_RECORD"\nsnp_lock_release\n[ -e "$SNP_LOCK_RECORD" ] && echo kept || echo removed')
    assert r.returncode == 0, r.stderr
    head, record, tail = r.stdout.splitlines()
    facts = dict(kv.split("=", 1) for kv in head.split())
    rec = json.loads(record)
    assert set(rec) == {"owner", "phase", "hotel", "launch_id", "pid", "started_at", "deadline_at"}
    assert rec["owner"] == facts["owner"] and facts["fd"] == "9"
    assert rec["pid"] == int(facts["pid"]) and rec["phase"] == "host_install" and rec["hotel"] == "hotel-x"
    assert rec["launch_id"] is None
    t0 = time.strptime(rec["started_at"], "%Y-%m-%dT%H:%M:%SZ")
    t1 = time.strptime(rec["deadline_at"], "%Y-%m-%dT%H:%M:%SZ")
    assert time.mktime(t1) - time.mktime(t0) == 3600
    assert tail == "removed"


def test_the_default_wait_is_60_seconds(box: Box) -> None:
    e = box.env()
    e.pop("CATHEDRAL_SNP_LOCK_WAIT", None)
    r = subprocess.run(["bash", "-c", f"source {LIB}; echo $SNP_LOCK_WAIT $SNP_LOCK_FILE"], env=e, capture_output=True, text=True)
    assert r.stdout.split()[0] == "60"
    e.pop("CATHEDRAL_SNP_LOCK_DIR")
    e.pop("ROOM_DESTDIR")
    r = subprocess.run(["bash", "-c", f"source {LIB}; echo $SNP_LOCK_FILE $SNP_LOCK_RECORD"], env=e, capture_output=True, text=True)
    assert r.stdout.split() == ["/run/lock/cathedral-snp-host.lock", "/run/lock/cathedral-snp-host.owner"]


def test_a_second_top_level_entry_waits_then_refuses_with_the_owner_record(box: Box) -> None:
    p = box.holder()
    try:
        t = time.monotonic()
        r = box.sh("snp_lock_take roll host_install sealed-9 - 3600", CATHEDRAL_SNP_LOCK_WAIT="2")
        waited = time.monotonic() - t
    finally:
        stop(p)
    assert r.returncode == 1
    assert "custom_guest_lifecycle_busy" in r.stderr and "waited 2s" in r.stderr
    assert p.owner in r.stderr and '"phase": "hold-stop"' in r.stderr and LAUNCH in r.stderr
    assert waited >= 1.9


def test_the_lock_is_free_again_once_the_holder_ends(box: Box) -> None:
    p = box.holder(then="exit 0")
    p.wait(timeout=10)
    r = box.sh("snp_lock_take roll host_install sealed-9 - 3600 && echo got", CATHEDRAL_SNP_LOCK_WAIT="0")
    assert r.returncode == 0 and "got" in r.stdout, r.stderr


def test_a_holder_killed_at_its_deadline_frees_the_lock_even_with_a_child_on_fd_9(box: Box) -> None:
    # timeout signals the whole process group, so a child that inherited fd 9 dies too.
    t = time.monotonic()
    r = subprocess.run(["timeout", "--kill-after=1s", "2", "bash", "-c",
                        f"source {LIB}; snp_lock_take roll host_install sealed-9 - 2 || exit 9; sleep 60 & sleep 60"],
                       env=box.env(), capture_output=True, text=True, timeout=30)
    assert r.returncode in (124, 137) and time.monotonic() - t < 10
    r = box.sh("snp_lock_take roll host_install sealed-9 - 3600 && echo got", CATHEDRAL_SNP_LOCK_WAIT="5")
    assert r.returncode == 0 and "got" in r.stdout, r.stderr


def test_control_killing_only_the_holder_leaves_the_lock_with_its_child(box: Box) -> None:
    # Why the deadline kills the group: the open file description lives while any fd 9 does.
    p = box.holder(then="sleep 60 & echo $! ; wait")
    child = int(p.stdout.readline())
    try:
        os.kill(p.pid, signal.SIGKILL)
        p.wait(timeout=10)
        r = box.sh("snp_lock_take roll host_install sealed-9 - 3600", CATHEDRAL_SNP_LOCK_WAIT="0")
        assert r.returncode == 1 and "custom_guest_lifecycle_busy" in r.stderr
    finally:
        os.kill(child, signal.SIGKILL)
    time.sleep(0.2)
    r = box.sh("snp_lock_take roll host_install sealed-9 - 3600 && echo got", CATHEDRAL_SNP_LOCK_WAIT="5")
    assert "got" in r.stdout, r.stderr


def test_a_non_blocking_take_skips_at_once_while_a_phase_holds_the_lock(box: Box) -> None:
    # The custom timer's tick (spec 5.3, 6) takes the lock with flock -n.
    p = box.holder()
    try:
        t = time.monotonic()
        r = box.sh("snp_lock_take custom-guest timer sealed-9 cg-0123456789ab -", CATHEDRAL_SNP_LOCK_WAIT="0")
        assert r.returncode == 1 and time.monotonic() - t < 1.5
        assert "flock -n 9" in box.flocks()
    finally:
        stop(p)


def test_a_helper_under_a_holder_checks_the_inherited_lock_and_never_calls_flock(box: Box) -> None:
    r = box.sh(f"snp_lock_take custom-guest return-kit sealed-9 {LAUNCH} 5400 || exit 9\n"
               f"bash -c 'source {LIB}; snp_lock_take write-units write-units sealed-9 - - && "
               "echo \"helper $SNP_LOCK_PHASE $SNP_LOCK_LAUNCH mine=$SNP_LOCK_MINE\"'")
    assert r.returncode == 0, r.stderr
    assert f"helper return-kit {LAUNCH} mine=0" in r.stdout
    assert len(box.flocks()) == 1, box.flocks()  # the holder's only


def _forged(box: Box, how: str) -> subprocess.CompletedProcess[str]:
    helper = f"source {LIB}; snp_lock_take write-units write-units sealed-9 - - && echo ACTED"
    lock = box.lock / "cathedral-snp-host.lock"
    if how == "fd9-devnull":
        return box.sh(f"exec 9>/dev/null; bash -c {shlex.quote(helper)}",
                      CATHEDRAL_SNP_LOCK_FD="9", CATHEDRAL_SNP_LOCK_OWNER="roll:sealed-9:1:1")
    if how == "fd9-closed":
        return box.sh(f"exec 9>&-; bash -c {shlex.quote(helper)}",
                      CATHEDRAL_SNP_LOCK_FD="9", CATHEDRAL_SNP_LOCK_OWNER="roll:sealed-9:1:1")
    if how == "fd8":
        return box.sh(f"snp_lock_take roll host_install sealed-9 - 60 || exit 9\nexec 8>&9\n"
                      f"CATHEDRAL_SNP_LOCK_FD=8 bash -c {shlex.quote(helper)}")
    if how == "owner-only":
        return box.sh(f"snp_lock_take roll host_install sealed-9 - 60 || exit 9\n"
                      f"env -u CATHEDRAL_SNP_LOCK_FD bash -c {shlex.quote(helper)}")
    if how == "wrong-owner":
        return box.sh(f"snp_lock_take roll host_install sealed-9 - 60 || exit 9\n"
                      f"CATHEDRAL_SNP_LOCK_OWNER=roll:sealed-9:2:2 bash -c {shlex.quote(helper)}")
    if how == "not-an-ancestor":
        # A real holder elsewhere; this process opens the same lock file and claims its owner.
        p = box.holder()
        try:
            return box.sh(f"exec 9>>{shlex.quote(str(lock))}; bash -c {shlex.quote(helper)}",
                          CATHEDRAL_SNP_LOCK_FD="9", CATHEDRAL_SNP_LOCK_OWNER=p.owner)
        finally:
            stop(p)
    raise AssertionError(how)


@pytest.mark.parametrize("how,why", [
    ("fd9-devnull", "fd 9 is not"), ("fd9-closed", "fd 9 is not"), ("fd8", "must be 9"),
    ("owner-only", "must be 9"), ("wrong-owner", "owner record names"), ("not-an-ancestor", "nor an ancestor"),
])
def test_a_forged_inherited_lock_refuses_and_never_acquires_instead(box: Box, how: str, why: str) -> None:
    box.lock.mkdir(parents=True, exist_ok=True)
    (box.lock / "cathedral-snp-host.lock").touch()
    before = len(box.flocks())
    r = _forged(box, how)
    assert "ACTED" not in r.stdout, (how, r.stdout, r.stderr)
    assert why in r.stderr, (how, r.stderr)
    helper_flocks = len(box.flocks()) - before - (1 if how in ("fd8", "owner-only", "wrong-owner", "not-an-ancestor") else 0)
    assert helper_flocks == 0, box.flocks()


# ---------------------------------------------------------------- the kit unit guard (5.10)

def test_without_a_marker_the_unit_differs_from_main_by_the_guard_line_only(box: Box) -> None:
    env_file = box.tmp / "nine.env"
    env_file.write_text("SEALED_NAME=nc-sealed-9\nSEALED_DIR=/srv/sealed-hotel-9\n")
    r = box.write_units(env_file=env_file)
    assert r.returncode == 0, r.stderr
    after = (box.root / "etc/systemd/system/room-sealed-nc-sealed-9.service").read_text()
    expected = UNIT_BEFORE.replace("Type=simple\n", "Type=simple\n" + GUARD_COMMENT + "\n"
                                   + GUARD.format(d="/srv/sealed-hotel-9") + "\n")
    assert after == expected


def _guard_argv(box: Box) -> list[str]:
    r = box.write_units()
    assert r.returncode == 0, r.stderr
    pre = [ln.split("=", 1)[1] for ln in box.unit().read_text().splitlines() if ln.startswith("ExecStartPre=")]
    guard = pre[0]
    # systemd expands $ and %, and unescapes backslashes, in command lines. With none of them in the
    # line, its word splitting is plain quote removal, which shlex does the same way.
    assert not any(c in guard for c in "$%\\"), guard
    argv = shlex.split(guard)
    assert argv[:2] == ["/bin/sh", "-c"] and len(argv) == 3
    return argv


@pytest.mark.parametrize("raw,starts", [
    (None, True),
    (json.dumps({"launch_id": LAUNCH, "state": "held"}) + "\n", False),
    (json.dumps({"launch_id": LAUNCH, "state": "kit_start"}) + "\n", True),
    (json.dumps({"launch_id": LAUNCH, "state": "kit_start"}, separators=(",", ":")), True),
    (json.dumps({"state": "kit_start", "launch_id": LAUNCH}), True),
    (json.dumps({"launch_id": LAUNCH, "state": "kit_start", "disk_verified": {"at": "2026-11-27T10:00:00Z", "sha256": "ab" * 32}}), True),
    (json.dumps({"launch_id": LAUNCH, "prev_state": "kit_start", "state": "held"}), False),
    (json.dumps({"launch_id": LAUNCH, "state": "kit_start"}, indent=2), False),  # not one line: fails closed
    ("", False),
    ("not json", False),
])
def test_the_guard_refuses_a_start_only_while_the_marker_says_held(box: Box, raw: str | None, starts: bool) -> None:
    argv = _guard_argv(box)
    if raw is not None:
        box.marker(raw=raw)
    r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    assert (r.returncode == 0) is starts, (raw, r.returncode, r.stderr)


def test_the_guard_never_waits_on_the_host_lock(box: Box) -> None:
    # A phase holds the lock while its systemctl start waits on this ExecStartPre (spec 5.3).
    argv = _guard_argv(box)
    box.marker("kit_start")
    p = box.holder(phase="return-kit")
    try:
        t = time.monotonic()
        r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        assert r.returncode == 0 and time.monotonic() - t < 2
    finally:
        stop(p)
    assert "lock" not in argv[2] and "flock" not in argv[2]


# ---------------------------------------------------------------- write-units.sh

def test_write_units_run_directly_takes_the_lock_and_frees_it(box: Box) -> None:
    r = box.write_units()
    assert r.returncode == 0, r.stderr
    assert box.flocks() == ["flock -w 60 9"]
    assert not (box.lock / "cathedral-snp-host.owner").exists()
    r = box.sh("snp_lock_take roll host_install sealed-9 - 60 && echo got", CATHEDRAL_SNP_LOCK_WAIT="0")
    assert "got" in r.stdout


@pytest.mark.parametrize("state", ["held", "kit_start", "unreadable"])
def test_write_units_refuses_while_a_custom_guest_holds_the_hotel(box: Box, state: str) -> None:
    box.unit().parent.mkdir(parents=True)
    box.unit().write_text("UNIT BEFORE\n")
    box.marker(raw="{" if state == "unreadable" else None, state=state)
    r = box.write_units()
    assert r.returncode == 1
    assert "custom_guest_held" in r.stderr and f"state={state}" in r.stderr
    assert box.unit().read_text() == "UNIT BEFORE\n"
    assert not (box.unit().parent / "room-sealed-sealed-9-net.service").exists()


@pytest.mark.parametrize("phase,launch,ok", [
    ("return-kit", LAUNCH, True), ("return-kit", OTHER, False), ("hold-stop", LAUNCH, False),
])
def test_write_units_under_a_holder_runs_only_for_that_launchs_return_phase(box: Box, phase: str, launch: str, ok: bool) -> None:
    box.marker("held")
    r = box.sh(f"snp_lock_take custom-guest {phase} sealed-9 {launch} 5400 || exit 9\n"
               f"bash {shlex.quote(str(box.kit / 'sealed' / 'write-units.sh'))} {shlex.quote(str(box.env_file))}")
    assert (r.returncode == 0) is ok, r.stderr
    assert box.unit().exists() is ok
    assert len(box.flocks()) == 1  # the holder's; write-units.sh inherits it
    if ok:
        assert GUARD.format(d=box.sealed_dir) in box.unit().read_text()


def test_write_units_waits_then_refuses_while_another_step_holds_the_lock(box: Box) -> None:
    p = box.holder()
    try:
        r = box.write_units(CATHEDRAL_SNP_LOCK_WAIT="1")
    finally:
        stop(p)
    assert r.returncode == 1 and "custom_guest_lifecycle_busy" in r.stderr and p.owner in r.stderr
    assert not box.unit().exists()


@pytest.mark.parametrize("sealed_dir", ["/srv/a b", "/srv/x'y", "srv/relative", "/srv/%h", "/srv/$x"])
def test_write_units_refuses_a_sealed_dir_the_guard_cannot_carry(box: Box, sealed_dir: str) -> None:
    env_file = box.tmp / "odd.env"
    env_file.write_text(f"SEALED_NAME=sealed-9\nSEALED_DIR={shlex.quote(sealed_dir)}\n")
    r = box.write_units(env_file=env_file)
    assert r.returncode == 1 and "SEALED_DIR must be an absolute path" in r.stderr
    assert not box.unit().exists() and box.flocks() == []


# ---------------------------------------------------------------- install-sealed.sh

def _install_sealed_slice(box: Box) -> None:
    """install-sealed.sh with the parts that need an SNP host (assess, packages, build, start) cut.

    Kept verbatim: the head, the host lock block and section 4 (units, which runs write-units.sh).
    """
    text = (SEALED / "install-sealed.sh").read_text()
    head = text[:text.index("# ---------------------------------------------------------------- 1. assess")]
    lock = text[text.index("# >>> host lock"):text.index("# <<< host lock")]
    unit = text[text.index("# ---------------------------------------------------------------- 4. unit"):
                text.index("# ---------------------------------------------------------------- 5. start and check")]
    path = box.kit / "sealed" / "install-sealed.sh"
    path.write_text(head + lock + unit + 'log "slice done"\n')
    path.chmod(0o755)


def test_install_sealed_takes_the_lock_before_its_first_host_change() -> None:
    text = (SEALED / "install-sealed.sh").read_text()
    lock = text.index("# >>> host lock")
    assert text.index("source \"$KIT/sealed/host-lock.sh\"") < text.index("# ---------------------------------------------------------------- 1. assess")
    assert lock < text.index('"$KIT/sealed/host-net.sh" clash') < text.index('mkdir -p "$SEALED_DIR/images"')
    block = text[lock:text.index("# <<< host lock")]
    assert "snp_lock_take install-sealed" in block and "snp_hold_marker" in block
    assert "trap 'data_volume_restore_on_exit; snp_lock_release' EXIT" in text


def test_install_sealed_run_directly_takes_the_lock_and_write_units_inherits_it(box: Box) -> None:
    _install_sealed_slice(box)
    r = subprocess.run(["bash", str(box.kit / "install.sh"), "--sealed", str(box.env_file)], env=box.env(),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-3000:]
    assert "slice done" in r.stdout and "units written for sealed-9" in r.stdout
    assert box.flocks() == ["flock -w 60 9"], box.flocks()  # install-sealed.sh's; write-units.sh inherits
    enable = [x for x in box.log.read_text().splitlines() if x.startswith("systemctl enable")]
    assert enable and '"phase": "install-sealed"' in enable[0]
    assert GUARD.format(d=box.sealed_dir) in box.unit().read_text()
    assert not (box.lock / "cathedral-snp-host.owner").exists()


@pytest.mark.parametrize("state", ["held", "kit_start"])
def test_install_sealed_refuses_while_a_custom_guest_holds_the_hotel(box: Box, state: str) -> None:
    _install_sealed_slice(box)
    box.marker(state)
    r = subprocess.run(["bash", str(box.kit / "install.sh"), "--sealed", str(box.env_file)], env=box.env(),
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 1
    assert f"custom_guest_held: launch={LAUNCH} state={state}" in r.stderr
    assert not box.unit().exists() and not (box.sealed_dir / "launch-guest.sh").exists()
    assert not [x for x in box.log.read_text().splitlines() if x.startswith("systemctl")]


def test_install_sealed_refuses_even_under_the_return_phase_of_that_launch(box: Box) -> None:
    # 11.6: the return starts the kit itself and never runs install-sealed.sh.
    _install_sealed_slice(box)
    box.marker("held")
    r = box.sh(f"snp_lock_take custom-guest return-kit sealed-9 {LAUNCH} 5400 || exit 9\n"
               f"bash {shlex.quote(str(box.kit / 'install.sh'))} --sealed {shlex.quote(str(box.env_file))}")
    assert r.returncode == 1 and "custom_guest_held" in r.stderr
    assert not box.unit().exists()
