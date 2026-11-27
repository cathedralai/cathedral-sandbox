#!/usr/bin/env python3
"""Host phases of one custom SNP guest launch (spec-r9 5.1 to 5.12, 6, 11).

  custom-guest-host.sh <phase> --hotel H --launch-id L [phase options] < input.json

The operator's custom-guest.sh runs each phase over SSH; no broker or API
credential reaches this host. A phase prints one last line `RESULT <json>` and
exits 0, or 1 with {"ok": false, "error_code", "detail"}.

Lock (5.3). Every phase below marked LOCK is a top-level entry: it runs under
`timeout --kill-after=30s <deadline>`, takes the one host lock
/run/lock/cathedral-snp-host.lock on fd 9 with flock(2) (the lock flock(1)
takes; 60 s wait, else custom_guest_lifecycle_busy with the owner record),
writes the owner record, exports CATHEDRAL_SNP_LOCK_FD=9 and
CATHEDRAL_SNP_LOCK_OWNER, and hands fd 9 down to the one helper it runs under
the lock (write-units.sh at R6). The unit hooks check-start and exited, the
boot recorder and facts never take the lock: systemd runs the hooks while a
phase that holds it waits on systemctl. The timer's tick takes it with a
non-blocking try and skips while a phase holds it.

Verify before act (5.4). Each sub-step journals its intent to the host
journal, observes live state, acts only when ready, and observes again. A
rerun after a crash or a kill at the deadline finds what is done by
observation.

Nothing here runs unless an operator starts a phase, and every phase refuses
unless /etc/cathedral/custom-guest.allow lists the hotel.
"""
from __future__ import annotations

import base64
import errno
import fcntl
import glob
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.environ.get("CG_ROOT", "")
PROC = os.environ.get("CG_PROC", "/proc")
LIBDIR = ROOT + "/usr/local/lib/cathedral-custom-guest"
KIT_DIR = os.environ.get("CG_KIT_DIR") or os.path.normpath(os.path.join(HERE, "..", "..", "room-kit"))
BOOT_ID_FILE = os.environ.get("CG_BOOT_ID_FILE", "/proc/sys/kernel/random/boot_id")
LOCK_WAIT = float(os.environ.get("CG_LOCK_WAIT", "60"))
DISK_RESERVE_GIB = int(os.environ.get("CG_DISK_RESERVE_GIB", "100"))
PROBE_TIMEOUT = float(os.environ.get("CG_PROBE_TIMEOUT", "300"))
STOP_WAIT = float(os.environ.get("CG_STOP_WAIT", "60"))
KIT_ATTEST_WAIT = float(os.environ.get("CG_KIT_ATTEST_WAIT", "900"))
POLL = float(os.environ.get("CG_POLL", "5"))
SNP_MEASURE_VERSION = "0.0.12"
# snp_qemu.py is a link to room-kit/vm/snp_qemu.py, the SNP argv shared with the VM launcher;
# install_tools copies its content, so LIBDIR holds a plain file.
TOOLS = ("custom-guest-host.sh", "custom_guest_host.py", "custom-net.sh", "launch-custom-guest.py",
         "sev_status.py", "custom_guest_stage.py", "snp_qemu.py")
KIT_DISKS = ("data.raw", "data.raw.prev", "scratch.raw")
GUARD_TEXT = "custom-guest.hold"  # the 5.10 guard line write-units.sh writes (PR 2)
GIB = 1 << 30

# phase: (lock mode, deadline seconds). Deadlines from 5.3; intake, measure, verify-disks and the
# finish steps are not listed there and take the bounds noted.
PHASES = {
    "inbox": ("lock", 300), "intake": ("lock", 7200), "measure": ("lock", 1800), "discard": ("lock", 600),
    "hold-stop": ("lock", 900), "unhold": ("lock", 300), "hold-baseline": ("lock", 5400),
    "boot": ("lock", 600), "verify-disks": ("lock", 5400), "stop": ("lock", 300),
    "return-kit": ("lock", 5400), "return-finish": ("lock", 1800), "tick": ("try", 300),
    "check-start": ("none", 0), "exited": ("none", 0), "boot-record": ("none", 0), "facts": ("none", 0),
}


class Halt(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


# ---------------------------------------------------------------- paths and small helpers

def p(path: str) -> str:
    return ROOT + path


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def canonical(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def boot_id() -> str:
    try:
        return open(BOOT_ID_FILE).read().strip()
    except OSError:
        return "unknown"


class Ctx:
    def __init__(self, phase: str, hotel: str, launch: str, opts: dict, data: dict):
        self.phase, self.hotel, self.launch, self.opts, self.data = phase, hotel, launch, opts, data
        self.base = p(f"/srv/custom-guest/{hotel}")
        self.d = f"{self.base}/{launch}"
        self.images = f"{self.d}/images"
        self.sealed = p(f"/srv/sealed-hotel-{hotel}")
        self.marker = f"{self.sealed}/custom-guest.hold"
        self.journal = f"{self.base}/host-journal.jsonl"
        self.kit_unit = f"room-sealed-{hotel}.service"
        self.kit_net_timer = f"room-sealed-{hotel}-net.timer"
        self.unit = f"custom-guest-{launch}.service"
        self.timer = f"custom-guest-{hotel}.timer"
        self.timer_service = f"custom-guest-{hotel}.service"
        self.boot_record = "custom-guest-boot-record.service"
        self.user = f"cg-{hotel}"
        self.unit_dir = p("/etc/systemd/system")

    # ---------------- host journal (root 0600, append-only, fsynced)
    def log(self, event: str, **fields) -> dict:
        os.makedirs(self.base, mode=0o711, exist_ok=True)
        entry = {"at": now_iso(), "t": time.time(), "boot_id": boot_id(), "launch_id": self.launch,
                 "event": event, **fields}
        line = (json.dumps(entry, sort_keys=True) + "\n").encode()
        fd = os.open(self.journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        return entry

    def entries(self, event: str | None = None, launch_only: bool = True) -> list[dict]:
        out = []
        try:
            with open(self.journal) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if launch_only and e.get("launch_id") != self.launch:
                        continue
                    if event is None or e.get("event") == event:
                        out.append(e)
        except FileNotFoundError:
            pass
        return out

    def last(self, event: str, **match) -> dict | None:
        for e in reversed(self.entries(event)):
            if all(e.get(k) == v for k, v in match.items()):
                return e
        return None

    # ---------------- sealed.env (KEY=VALUE lines only, never sourced)
    def kit_env(self) -> dict:
        env = {}
        try:
            for line in open(f"{self.sealed}/sealed.env"):
                m = re.fullmatch(r"([A-Z_][A-Z0-9_]*)=(.*)", line.strip())
                if m:
                    env[m.group(1)] = m.group(2).strip().strip('"').strip("'")
        except OSError:
            pass
        return env


def run(argv: list[str], timeout: float = 120, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, **kw)


def fault(where: str) -> None:
    """Test hook: CG_FAULT=host:<phase>:<sub> kills this process right after that act."""
    if os.environ.get("CG_FAULT") == where:
        os._exit(137)


def sub(ctx: Ctx, name: str, observe, act=None) -> None:
    """One verify-before-act sub-step (5.4). observe() returns True (done), False (ready) or raises Halt."""
    ctx.log("sub", phase=ctx.phase, sub=name, state="intent")
    try:
        if observe():
            ctx.log("sub", phase=ctx.phase, sub=name, state="done")
            return
        if act is None:
            raise Halt("custom_guest_journal_behind", f"{name}: not done and has no act")
        act()
        fault(f"host:{ctx.phase}:{name}")
        if not observe():
            raise Halt("custom_guest_hold_failed", f"{name}: the postcondition did not hold after the act")
    except Halt as e:
        ctx.log("sub", phase=ctx.phase, sub=name, state="failed", error_code=e.code, detail=e.detail[:300])
        raise
    ctx.log("sub", phase=ctx.phase, sub=name, state="done")


# ---------------------------------------------------------------- systemd

def show(unit: str, *props: str) -> dict:
    r = run(["systemctl", "show", *[a for pr in props for a in ("-p", pr)], "--timestamp=unix", unit])
    out = {}
    for line in r.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def active(unit: str) -> bool:
    return show(unit, "ActiveState").get("ActiveState") == "active"


def state(unit: str) -> str:
    return show(unit, "ActiveState").get("ActiveState", "unknown")


def enabled(unit: str) -> bool:
    return run(["systemctl", "is-enabled", unit]).stdout.strip() == "enabled"


def systemctl(*args: str, timeout: float = 300) -> None:
    r = run(["systemctl", *args], timeout=timeout)
    if r.returncode != 0:
        raise Halt("custom_guest_kit_failed", f"systemctl {' '.join(args)}: {r.stderr.strip()[:200]}")


def unit_files(pattern: str) -> list[str]:
    names = set()
    for d in ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/system"):
        for path in glob.glob(p(d) + "/" + pattern):
            names.add(os.path.basename(path))
    return sorted(names)


def write_if_changed(path: str, text: str, mode: int = 0o644) -> bool:
    try:
        if open(path).read() == text:
            return False
    except OSError:
        pass
    tmp = path + ".part"
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


# ---------------------------------------------------------------- processes

def qemu_processes() -> list[dict]:
    """QEMU by executable path in /proc/*/exe, never by cmdline text (5.1)."""
    out = []
    for d in glob.glob(f"{PROC}/[0-9]*"):
        try:
            exe = os.readlink(f"{d}/exe")
        except OSError:
            continue
        if not os.path.basename(exe).startswith("qemu-system"):
            continue
        unit = ""
        try:
            for line in open(f"{d}/cgroup"):
                m = re.search(r"/([^/\s]+\.service)(/|$)", line.strip())
                if m:
                    unit = m.group(1)
        except OSError:
            pass
        out.append({"pid": int(os.path.basename(d)), "exe": exe, "unit": unit})
    return sorted(out, key=lambda q: q["pid"])


def kit_absent(ctx: Ctx) -> bool:
    return not active(ctx.kit_unit) and state(ctx.kit_unit) in ("inactive", "failed") \
        and not [q for q in qemu_processes() if q["unit"] == ctx.kit_unit]


# ---------------------------------------------------------------- allow file and modes

def allow_lines() -> list[list[str]]:
    path = p("/etc/cathedral/custom-guest.allow")
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return []
    if st.st_mode & 0o022 or st.st_uid not in (0, os.getuid()):
        raise Halt("custom_guest_hold_unsupported", f"{path} must be owned by root and not group or world writable")
    out = []
    for line in open(path):
        words = line.split("#", 1)[0].split()
        if words:
            out.append(words)
    return out


def shared_mode(hotel: str) -> bool:
    return ["shared_host_rehearsal", hotel] in allow_lines()


def allowed(hotel: str) -> bool:
    lines = allow_lines()
    return [hotel] in lines or ["hotel", hotel] in lines or ["shared_host_rehearsal", hotel] in lines


# ---------------------------------------------------------------- SEV status

def sev_read() -> dict:
    cmd = os.environ.get("CG_SEV_STATUS")
    argv = cmd.split() if cmd else [sys.executable, "-I", os.path.join(HERE, "sev_status.py"), "read"]
    r = run(argv, timeout=30)
    if r.returncode != 0:
        raise Halt("custom_guest_sev_platform_changed", f"SEV status unreadable: {r.stderr.strip()[:200]}")
    return json.loads(r.stdout)


def sev_differences(baseline: dict, now: dict) -> list[str]:
    fields = {"snp": ("api_major", "api_minor", "build_id", "mask_chip_id", "mask_chip_key", "vlek_en",
                      "current_tcb", "reported_tcb"),
              "sev": ("api_major", "api_minor", "build", "owner", "config_flags")}
    out = []
    for part, names in fields.items():
        for n in names:
            a, b = (baseline.get(part) or {}).get(n), (now.get(part) or {}).get(n)
            if a != b:
                out.append(f"{part}.{n}: {a} -> {b}")
    return out


def sev_baseline(ctx: Ctx) -> dict | None:
    e = ctx.last("sev_baseline")
    return e["status"] if e else None


# ---------------------------------------------------------------- kit disks (5.11)

def sparse_sha256(path: str) -> str:
    """sha256 over the data extents (offset, length, bytes) and the size; holes are skipped.

    A hole and written zeros differ, which can only make a check fail closed.
    """
    h = hashlib.sha256(b"cathedral-sparse-sha256/v1\0")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        size = os.fstat(fd).st_size
        h.update(size.to_bytes(8, "little"))
        off = 0
        seek_data, seek_hole = getattr(os, "SEEK_DATA", None), getattr(os, "SEEK_HOLE", None)
        while off < size:
            if seek_data is not None:
                try:
                    start = os.lseek(fd, off, seek_data)
                    end = os.lseek(fd, start, seek_hole)
                except OSError as e:
                    if e.errno == errno.ENXIO:
                        break
                    start, end = off, size
            else:
                start, end = off, size
            h.update(start.to_bytes(8, "little") + (end - start).to_bytes(8, "little"))
            os.lseek(fd, start, os.SEEK_SET)
            left = end - start
            while left:
                chunk = os.read(fd, min(left, 8 << 20))
                if not chunk:
                    break
                h.update(chunk)
                left -= len(chunk)
            off = end
    finally:
        os.close(fd)
    return h.hexdigest()


def luks_launch_id(path: str) -> str | None:
    if not shutil.which("cryptsetup"):
        return None
    r = run(["cryptsetup", "token", "export", "--token-id", "0", path], timeout=60)
    try:
        t = json.loads(r.stdout)
        return t.get("slots", {}).get("0", {}).get("launch_id") if t.get("type") == "cathedral-sealed-data" else None
    except ValueError:
        return None


META = ("size", "inode", "mode", "uid", "gid", "mtime_ns", "ctime_ns")


def fingerprint(ctx: Ctx, full: bool) -> dict:
    out = {}
    for name in KIT_DISKS:
        path = f"{ctx.sealed}/{name}"
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue
        meta = {"size": st.st_size, "inode": st.st_ino, "mode": st.st_mode, "uid": st.st_uid, "gid": st.st_gid,
                "mtime_ns": st.st_mtime_ns, "ctime_ns": st.st_ctime_ns}
        if full:
            if not stat.S_ISREG(st.st_mode):
                raise Halt("custom_guest_kit_data_changed", f"{name} is not a regular file")
            meta["sha256"] = sparse_sha256(path)
            if name == "data.raw":
                meta["luks_launch_id"] = luks_launch_id(path)
        out[name] = meta
    return out


def fingerprint_sha256(fp: dict) -> str:
    return hashlib.sha256(canonical(fp)).hexdigest()


def disk_differences(base: dict, now: dict, meta_only: bool) -> list[str]:
    out = []
    for name in sorted(set(base) | set(now)):
        a, b = base.get(name), now.get(name)
        if a is None or b is None:
            out.append(f"{name}: {'appeared' if a is None else 'gone'}")
            continue
        for k in (META if meta_only else sorted(set(a) | set(b))):
            if a.get(k) != b.get(k):
                out.append(f"{name}.{k}")
    return out


def baseline_fingerprint(ctx: Ctx) -> dict:
    e = ctx.last("fingerprint")
    if not e:
        raise Halt("custom_guest_journal_behind", "no disk fingerprint in the host journal")
    return e["fingerprint"]


# ---------------------------------------------------------------- 5.1 eligibility

def marker_doc(ctx: Ctx, path: str | None = None) -> dict | None:
    try:
        return json.load(open(path or ctx.marker))
    except FileNotFoundError:
        return None
    except ValueError:
        return {"launch_id": "?", "state": "?"}


def eligibility(ctx: Ctx, when: str) -> dict:
    """Refuse a host that is not this hotel's alone (5.1), or in the rehearsal mode not as recorded (5.12)."""
    shared = shared_mode(ctx.hotel)
    dirs = sorted(os.path.basename(d) for d in glob.glob(p("/srv/sealed-hotel-*"))
                  if os.path.isdir(d) and not os.path.islink(d))
    kit_units = [u for u in unit_files("room-sealed-*.service") if not u.endswith("-net.service")]
    vm_units = unit_files("cathedral-vm-*.service")
    other_custom = [u for u in unit_files("custom-guest-cg-*.service") if u != ctx.unit]
    if unit_files("hotel-offer*"):
        raise Halt("custom_guest_miner_hotel", "the host has a hotel-offer-refresh unit")
    if ctx.hotel.startswith("miner-"):
        raise Halt("custom_guest_miner_hotel", "the hotel id is a miner hotel id")
    for m in glob.glob(p("/srv/sealed-hotel-*/custom-guest.hold")):
        doc = marker_doc(ctx, m)
        if doc and doc.get("launch_id") != ctx.launch:
            raise Halt("custom_guest_previous_launch_on_host", f"{m} names launch {doc.get('launch_id')}")
    for d in glob.glob(p("/srv/custom-guest/*/cg-*")):
        if os.path.isdir(d) and os.path.basename(d) != ctx.launch:
            raise Halt("custom_guest_previous_launch_on_host", f"launch folder {d} is still on the host")
    for d in glob.glob(p("/srv/custom-guest/*/inbox/cg-*")) + glob.glob(p("/srv/custom-guest/*/staging/cg-*")):
        if os.path.basename(d) != ctx.launch:
            raise Halt("custom_guest_previous_launch_on_host", f"{d} of another launch is still on the host")
    if other_custom:
        raise Halt("custom_guest_previous_launch_on_host", f"other custom guest units: {other_custom}")
    if vm_units:
        raise Halt("custom_guest_host_not_exclusive", f"VM units on the host: {vm_units}")
    ours = {ctx.kit_unit, ctx.unit}
    qemus = qemu_processes()
    if not shared:
        if dirs != [f"sealed-hotel-{ctx.hotel}"]:
            raise Halt("custom_guest_host_not_single_hotel", f"sealed hotel folders: {dirs}")
        if kit_units != [ctx.kit_unit]:
            raise Halt("custom_guest_host_not_single_hotel", f"kit units: {kit_units}")
        stray = [q for q in qemus if q["unit"] not in ours]
        if stray:
            raise Halt("custom_guest_host_not_exclusive", f"QEMU outside this hotel: {stray}")
        inventory = None
    else:
        inv = ctx.last("shared_inventory")
        current = {"units": sorted(set(kit_units) - {ctx.kit_unit}),
                   "qemu": sorted({(q["unit"], q["exe"]) for q in qemus if q["unit"] not in ours})}
        current["qemu"] = [list(x) for x in current["qemu"]]
        if inv is None:
            if when != "intake":
                raise Halt("custom_guest_host_not_exclusive", "no shared-host inventory recorded at intake")
            env = ctx.kit_env()
            inv = ctx.log("shared_inventory", units=current["units"], qemu=current["qemu"],
                          kit_vcpus=int(env.get("SEALED_VCPUS", "0") or 0),
                          kit_mem_gib=int(env.get("SEALED_MEM_GIB", "0") or 0))
        if current["units"] != inv["units"]:
            raise Halt("custom_guest_host_not_single_hotel",
                       f"other kit units {current['units']} differ from intake {inv['units']}")
        if current["qemu"] != inv["qemu"] or any(q["unit"] not in inv["units"] for q in qemus if q["unit"] not in ours):
            raise Halt("custom_guest_host_not_exclusive",
                       f"QEMU outside the recorded kit units: {current['qemu']} vs {inv['qemu']}")
        inventory = inv
    if when == "boot":
        if [q for q in qemus if q["unit"] == ctx.kit_unit] or (not shared and qemus):
            raise Halt("custom_guest_host_not_exclusive", f"QEMU is running: {qemus}")
        if active(ctx.kit_unit) or enabled(ctx.kit_unit):
            raise Halt("custom_guest_host_not_exclusive", "the kit unit is not inactive and disabled")
        base = sev_baseline(ctx)
        count = sev_read()["snp"]["guest_count"]
        want = base["snp"]["guest_count"] if shared and base else 0
        if count != want:
            raise Halt("custom_guest_host_not_exclusive", f"SNP guest_count {count}, want {want}")
    return {"shared": shared, "inventory": inventory}


# ---------------------------------------------------------------- users, tools, files

def ensure_user(name: str, groups: str = "") -> None:
    if run(["getent", "passwd", name]).returncode == 0:
        return
    argv = ["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
            "--shell", "/usr/sbin/nologin"]
    if groups:
        argv += ["--groups", groups]
    r = run(argv + [name])
    if r.returncode != 0:
        raise Halt("custom_guest_hold_failed", f"useradd {name}: {r.stderr.strip()[:200]}")


def ensure_group(name: str) -> None:
    if run(["getent", "group", name]).returncode != 0:
        r = run(["groupadd", "--system", name])
        if r.returncode != 0:
            raise Halt("custom_guest_hold_failed", f"groupadd {name}: {r.stderr.strip()[:200]}")


def chown(owner: str, *paths: str, recursive: bool = False) -> None:
    r = run(["chown", *(["-R"] if recursive else []), "--no-dereference", owner, *paths])
    if r.returncode != 0:
        raise Halt("custom_guest_hold_failed", f"chown {owner}: {r.stderr.strip()[:200]}")


def install_tools() -> None:
    # The unit's + hooks run through nsenter (HOST_NS). Without it every start would fail in ExecStartPre, after a
    # boot intent and a token were written: refuse before any of that, on a real host (a test root has no /usr/bin).
    if not ROOT and not os.access(NSENTER, os.X_OK):
        raise Halt("custom_guest_hold_failed", f"{NSENTER} is missing: the guest unit's host hooks need it (util-linux)")
    os.makedirs(LIBDIR, mode=0o755, exist_ok=True)
    for name in TOOLS:
        src, dst = os.path.join(HERE, name), os.path.join(LIBDIR, name)
        if os.path.realpath(src) == os.path.realpath(dst):
            continue
        data = open(src, "rb").read()
        try:
            if open(dst, "rb").read() == data:
                continue
        except OSError:
            pass
        with open(dst + ".part", "wb") as f:
            f.write(data)
        os.chmod(dst + ".part", 0o755)
        os.replace(dst + ".part", dst)


def copy_hashed(src: str, dst: str) -> tuple[str, int]:
    """Copy a regular file without following links, hashing what is written."""
    fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        raise Halt("custom_guest_digest_mismatch", f"{os.path.basename(src)} is not a plain regular file")
    h, n = hashlib.sha256(), 0
    with os.fdopen(fd, "rb") as fin, open(dst, "xb") as fout:
        while True:
            chunk = fin.read(8 << 20)
            if not chunk:
                break
            h.update(chunk)
            fout.write(chunk)
            n += len(chunk)
        fout.flush()
        os.fsync(fout.fileno())
    return h.hexdigest(), n


def sha256_path(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_atomic(path: str, data: bytes, mode: int) -> None:
    tmp = path + ".part"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    dfd = os.open(os.path.dirname(path), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def write_marker(ctx: Ctx, doc: dict) -> None:
    # json.dumps keeps '"state": "kit_start"', which the kit unit guard greps for (5.10).
    write_atomic(ctx.marker, (json.dumps(doc, sort_keys=True) + "\n").encode(), 0o644)


def load_doc(path: str) -> tuple[dict, bytes]:
    raw = open(path, "rb").read()
    doc = json.loads(raw)
    if canonical(doc) != raw:
        raise Halt("custom_guest_digest_mismatch", f"{os.path.basename(path)} is not canonical")
    return doc, raw


# ---------------------------------------------------------------- QMP and probes

QMP_CLIENT = """
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(float(sys.argv[2]))
s.connect(sys.argv[1])
f = s.makefile("rwb")
def reply():
    while True:
        line = f.readline()
        if not line:
            raise OSError("QMP closed")
        msg = json.loads(line)
        if "return" in msg or "error" in msg:
            return msg
json.loads(f.readline())
out = []
for cmd in [{"execute": "qmp_capabilities"}] + json.loads(sys.argv[3]):
    f.write(json.dumps(cmd).encode() + b"\\n")
    f.flush()
    out.append(reply())
print(json.dumps(out[1:]))
"""


def qmp(ctx: Ctx, *commands: dict, timeout: float = 10) -> list[dict]:
    """QMP as the guest's own user. D/run is writable by QEMU, so a root connect could follow a planted
    symlink to another socket (the kit's QMP, systemd's); as cg-<hotel> it reaches only what QEMU could."""
    r = run(["runuser", "-u", ctx.user, "--", sys.executable, "-I", "-c", QMP_CLIENT, f"{ctx.d}/run/qmp.sock",
             str(timeout), json.dumps(list(commands))], timeout=timeout + 10)
    if r.returncode != 0:
        raise OSError(f"QMP: {r.stderr.strip()[-200:]}")
    try:
        out = json.loads(r.stdout)
    except ValueError as e:
        raise OSError(f"QMP answer: {e}")
    if not isinstance(out, list):
        raise OSError("QMP answer is not a list")
    return out


def root_write(directory: str, name: str, data: bytes) -> str:
    """Write a file as root only inside a folder this process owns, never through a link (5.8)."""
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass
    st = os.lstat(directory)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise OSError(f"{directory} is not a private folder of this user")
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    finally:
        os.close(dfd)
    return os.path.join(directory, name)


def save_ring(ctx: Ctx) -> str | None:
    """The serial tail, kept in D/log (root-only; the unit binds only D/images, D/disks and D/run)."""
    try:
        r = qmp(ctx, {"execute": "ringbuf-read", "arguments": {"device": "serial0", "size": 1 << 20,
                                                                "format": "utf8"}})[0]
        text = r.get("return", "")
    except (OSError, ValueError, IndexError, AttributeError):
        return None
    try:
        return root_write(f"{ctx.d}/log", "serial-tail.txt", (text if isinstance(text, str) else "").encode())
    except OSError:
        return None


def probe_banner(ctx: Ctx, addr: str, port: int) -> bool:
    """As cg-probe, the one uid the host OUTPUT rules let into the guest (6)."""
    code = ("import socket,sys\n"
            "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=5)\n"
            "b=s.recv(256)\nsys.exit(0 if b.startswith(b'SSH-2.0-') else 1)\n")
    r = run(["runuser", "-u", "cg-probe", "--", sys.executable, "-I", "-c", code, addr, str(port)], timeout=20)
    return r.returncode == 0


def guest_net(ctx: Ctx) -> dict:
    return load_doc(f"{ctx.images}/bootstrap.json")[0]["network"]


def custom_qemu(ctx: Ctx) -> list[dict]:
    return [q for q in qemu_processes() if q["unit"] == ctx.unit]


# A KVM guest_memfd, which backs an SNP guest's private memory, reads back from /proc/<pid>/fd as this exact
# name and stats as a regular file with one link, so neither name nor link count separates it from a host file
# (surveyed on the kit's SNP QEMU: three of them, 640 GiB, 4 MiB and 128 KiB). What does: its mount id (fdinfo
# mnt_id) belongs to an internal kernel mount that no path reaches, so it is in no line of /proc/<pid>/mountinfo,
# while a real file's mount id is. It is kernel memory, not a host file. An fd is skipped only with BOTH the exact
# name and an unlisted mount id; if either read fails it is treated as an offender. The stat is a test seam so the
# fake /proc can say what stat would.
KVM_GMEM_TARGET = "/[kvm-gmem] (deleted)"
FD_STAT = os.stat


def fd_mount_id(pid: int, fd: str) -> str | None:
    """The mnt_id of /proc/<pid>/fdinfo/<fd>, or None when it cannot be read."""
    try:
        with open(f"{PROC}/{pid}/fdinfo/{os.path.basename(fd)}") as f:
            for line in f.read(4096).splitlines():
                key, _, value = line.partition(":")
                if key == "mnt_id" and value.strip().isdigit():
                    return value.strip()
    except (OSError, ValueError):
        pass
    return None


def mount_ids(pid: int) -> set[str] | None:
    """Every mount id in /proc/<pid>/mountinfo (the first field of each line), or None when it cannot be read."""
    try:
        with open(f"{PROC}/{pid}/mountinfo") as f:
            ids = {line.split(" ", 1)[0] for line in f.read(1 << 20).splitlines() if line}
    except (OSError, ValueError):
        return None
    return ids if ids and all(i.isdigit() for i in ids) else None


def is_guest_memfd(pid: int, fd: str, target: str, mounts: set[str] | None) -> bool:
    """True only for the exact guest_memfd name whose mount id is in no mountinfo line. Fails closed."""
    if target != KVM_GMEM_TARGET or mounts is None:
        return False
    mnt = fd_mount_id(pid, fd)
    return mnt is not None and mnt not in mounts


def single_line(text: str, limit: int = 300) -> str:
    """One line of printable ASCII, whitespace collapsed, at most `limit` characters (never empty). Same rule as
    custom_guest.one_line in the operator tool, which is not installed on the host."""
    flat = "".join(c if " " <= c <= "~" else " " for c in str(text))
    return " ".join(flat.split())[:limit].rstrip() or "no detail given"


def verify_isolation(ctx: Ctx) -> None:
    """Only allowlisted block nodes, and every regular file QEMU holds open is under D (5.11)."""
    try:
        blocks = qmp(ctx, {"execute": "query-block"})[0].get("return", [])
    except (OSError, ValueError) as e:
        raise Halt("custom_guest_isolation_failed", f"QMP query-block: {e}")
    manifest = load_doc(f"{ctx.images}/manifest.json")[0]
    want = {"root"} | ({"data"} if manifest.get("data_disk_gib") else set())
    got = {b.get("device") for b in blocks}
    if got != want:
        raise Halt("custom_guest_isolation_failed", f"block devices {sorted(map(str, got))}, want {sorted(want)}")
    for b in blocks:
        f = (b.get("inserted") or {}).get("file", "")
        if not os.path.normpath(f).startswith(ctx.d + os.sep):
            raise Halt("custom_guest_isolation_failed", f"block file {f} is outside the launch folder")
        if b.get("device") == "root" and not (b.get("inserted") or {}).get("ro"):
            raise Halt("custom_guest_isolation_failed", "the root drive is not read-only")
    offenders: list[str] = []
    for q in custom_qemu(ctx):
        mounts = mount_ids(q["pid"])
        for fd in sorted(glob.glob(f"{PROC}/{q['pid']}/fd/*"), key=lambda f: (len(f), f)):  # fd order, 9 before 10
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if not target.startswith("/") or target.startswith(("/memfd:", "/dev/")):
                continue
            try:
                st = FD_STAT(fd)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if is_guest_memfd(q["pid"], fd, target, mounts):
                continue  # SNP private guest memory: kernel memory, not a host file
            if not os.path.normpath(target).startswith(ctx.d + os.sep) and target not in offenders:
                offenders.append(target)
    if offenders:
        # Every offender at once, so one run shows all of them. The detail is one bounded line: a file name can
        # hold a newline, and the API refuses a multi-line detail.
        shown = ", ".join(offenders)
        raise Halt("custom_guest_isolation_failed", single_line(f"QEMU holds open, outside the launch folder: {shown}"))


# ---------------------------------------------------------------- unit text (5.8)

# Every `+` hook of the custom unit runs in the host's mount namespace. systemd runs a `+` command with
# full privileges, but on systemd 259 still inside the unit's own mount namespace, and this unit's namespace
# has TemporaryFileSystem=/srv:ro (so the guest user sees no other hotel or launch). Seen from there, check-start
# finds an empty /srv and no host journal, and exited cannot append to it (EROFS). Those two are the real
# breakage (rehearsal B, run 3, 27 Nov). A plain `+` hook can still write /run/lock and use netlink on 259
# (probed with the full lockdown), so custom-net.sh and the /dev/kvm wait, modprobe and rm lines are wrapped for
# consistency, one rule for every host hook, not because they failed.
# `nsenter --mount=/proc/1/ns/mnt` puts only the hook, never the guest process, in PID 1's mount namespace
# (probed on systemd 259 with the unit's sandbox: the wrapped hook saw /srv, the main process did not).
# Chosen over binding the hooks' files into the unit (they would then be visible to the guest user, and the list
# would grow with every hook) and over separate helper units (more moving parts for the same effect). The
# guest's ExecStart is unchanged: it still sees images (ro), disks and run.
NSENTER = "/usr/bin/nsenter"
HOST_NS = f"{NSENTER} --mount=/proc/1/ns/mnt --"

def unit_text(ctx: Ctx, mem_gib: int) -> str:
    d, lib, h, l = ctx.d, LIBDIR, ctx.hotel, ctx.launch
    return f"""[Unit]
Description=Custom SNP guest {l} on hotel {h} (owner launch; never enabled, never restarted)
After=network-online.target
[Service]
Type=simple
User=cg-{h}
Group=cg-{h}
SupplementaryGroups=kvm cg-sev
ExecStartPre=+{HOST_NS} {lib}/custom-guest-host.sh check-start --hotel {h} --launch-id {l}
ExecStartPre=+-{HOST_NS} /sbin/modprobe -q kvm_amd
ExecStartPre=+{HOST_NS} /bin/sh -c 'for i in $$(seq 1 120); do [ -c /dev/kvm ] && exit 0; sleep 1; done; echo "no /dev/kvm after 120 s" >&2; exit 1'
ExecStartPre=+{HOST_NS} {lib}/custom-net.sh up {h} {l}
ExecStartPre=+{HOST_NS} /bin/rm -f {d}/run/qmp.sock
ExecStart=/usr/bin/python3 -I {lib}/launch-custom-guest.py {d}
ExecStopPost=+{HOST_NS} {lib}/custom-guest-host.sh exited --hotel {h} --launch-id {l}
Restart=no
KillSignal=SIGTERM
TimeoutStartSec=180
TimeoutStopSec=90
DevicePolicy=closed
DeviceAllow=/dev/kvm rw
DeviceAllow=/dev/sev rw
DeviceAllow=/dev/vhost-net rw
DeviceAllow=/dev/net/tun rw
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
TemporaryFileSystem=/srv:ro
BindReadOnlyPaths={d}/images
BindPaths={d}/disks {d}/run
MemoryMax={mem_gib + 16}G
MemorySwapMax=0
TasksMax=512
LimitNOFILE=4096
LimitCORE=0
LimitMEMLOCK=infinity
NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX
"""


def timer_texts(ctx: Ctx) -> dict[str, str]:
    lib, h, l = LIBDIR, ctx.hotel, ctx.launch
    return {
        ctx.timer_service: f"""[Unit]
Description=Custom guest {l} on {h}: link check, SEV compare, kit disk metadata (starts nothing)
[Service]
Type=oneshot
ExecStart={lib}/custom-guest-host.sh tick --hotel {h} --launch-id {l}
""",
        ctx.timer: f"""[Unit]
Description=Custom guest {l} on {h}: every minute while held
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
""",
        ctx.boot_record: f"""[Unit]
Description=Custom guest {l} on {h}: record each host boot in the host journal
[Service]
Type=oneshot
ExecStart={lib}/custom-guest-host.sh boot-record --hotel {h} --launch-id {l}
[Install]
WantedBy=multi-user.target
""",
    }


# ---------------------------------------------------------------- phases

def ph_facts(ctx: Ctx) -> dict:
    """Read only, no lock: what the operator observes (H5, H6, H9, reconcile)."""
    kit = show(ctx.kit_unit, "ActiveState", "InvocationID", "ActiveEnterTimestamp")
    enter = kit.get("ActiveEnterTimestamp", "")
    custom = show(ctx.unit, "ActiveState", "InvocationID") if os.path.exists(f"{ctx.unit_dir}/{ctx.unit}") else None
    return {"ok": True, "kit_unit": {"state": kit.get("ActiveState"), "invocation_id": kit.get("InvocationID"),
                                     "active_enter": int(enter[1:]) if enter.startswith("@") and enter[1:].isdigit() else None,
                                     "enabled": enabled(ctx.kit_unit)},
            "kit_absent": kit_absent(ctx), "kit_net_timer": {"active": active(ctx.kit_net_timer),
                                                             "enabled": enabled(ctx.kit_net_timer)},
            "custom_unit": custom, "marker": marker_doc(ctx), "launch_dir": os.path.isdir(ctx.d),
            "inbox_dir": os.path.isdir(f"{ctx.base}/inbox/{ctx.launch}"),
            "staging_dir": os.path.isdir(f"{ctx.base}/staging/{ctx.launch}"),
            "journal": [e for e in ctx.entries() if e.get("event") != "sub"], "boot_id": boot_id(),
            "allowed": allowed(ctx.hotel)}


def ph_inbox(ctx: Ctx) -> dict:
    eligibility(ctx, "intake")
    if os.path.isdir(ctx.images):
        raise Halt("custom_guest_previous_launch_on_host", "this launch already has images")
    inbox = f"{ctx.base}/inbox/{ctx.launch}"
    for d in (ctx.base, f"{ctx.base}/inbox", f"{ctx.base}/staging"):
        os.makedirs(d, mode=0o711, exist_ok=True)
        os.chmod(d, 0o711)
    os.makedirs(inbox, mode=0o700, exist_ok=True)
    return {"ok": True, "inbox": inbox}


def stage_argv(ctx: Ctx, inbox: str, staging: str) -> list[str]:
    """The exact validator line of spec 5.5."""
    return ["systemd-run", "--wait", "--pipe", "--uid=cg-stage", "--gid=cg-stage",
            "-p", "PrivateNetwork=yes", "-p", "ProtectSystem=strict", "-p", "ProtectHome=yes", "-p", "PrivateTmp=yes",
            "-p", "NoNewPrivileges=yes", "-p", "CapabilityBoundingSet=", "-p", "MemoryMax=4G", "-p", "TasksMax=16",
            "-p", "LimitCORE=0", "-p", "RuntimeMaxSec=3600", "-p", f"ReadOnlyPaths={inbox}",
            "-p", f"ReadWritePaths={staging}",
            "python3", "-I", f"{LIBDIR}/custom_guest_stage.py", "--inbox", inbox, "--staging", staging]


def gate(ctx: Ctx, req: dict, shared: bool) -> None:
    """4.1 intake gate and 5.12: the Cathedral test image, or (not on a shared host) Toby's go."""
    test = ctx.data.get("test_image") or {}
    is_test = bool(test) and req["kernel"]["sha256"] == test.get("kernel_sha256") \
        and req["initrd"]["sha256"] == test.get("initrd_sha256") and req["root_disk"]["sha256"] == test.get("root_sha256")
    if shared and not is_test:
        raise Halt("custom_guest_shared_host_needs_test_image", "the rehearsal mode runs only the Cathedral test image")
    if not is_test and not ctx.data.get("toby_go"):
        raise Halt("custom_guest_toby_go_required", "a customer image needs Toby's written go (--toby-go)")


def images_complete(ctx: Ctx, req: dict) -> bool:
    want = {"vmlinuz": req["kernel"]["sha256"], "initrd": req["initrd"]["sha256"],
            "root.raw": req["root_disk"]["sha256"], "cmdline": hashlib.sha256(req["cmdline"].encode()).hexdigest()}
    done = ctx.last("intake_done")
    if not done:
        return False
    return all(os.path.isfile(f"{ctx.images}/{n}") and done["files"].get(n, {}).get("sha256") == sha
               for n, sha in want.items())


def ph_intake(ctx: Ctx) -> dict:
    req = ctx.data["request"]
    elig = eligibility(ctx, "intake")
    gate(ctx, req, elig["shared"])
    if elig["shared"]:
        inv = elig["inventory"]
        if req["vcpus"] > inv["kit_vcpus"] or req["mem_gib"] > inv["kit_mem_gib"]:
            raise Halt("custom_guest_resources_exceeded", "the rehearsal guest may not exceed the kit guest's size")
    inbox, staging = f"{ctx.base}/inbox/{ctx.launch}", f"{ctx.base}/staging/{ctx.launch}"
    if images_complete(ctx, req):
        for d in (inbox, staging):
            if os.path.isdir(d):
                shutil.rmtree(d)
        done = ctx.last("intake_done")
        return {"ok": True, "report": done["report"], "files": done["files"]}
    free = shutil.disk_usage(ctx.base).free
    need = req["root_disk"]["bytes"] + req.get("data_disk_gib", 0) * GIB + DISK_RESERVE_GIB * GIB
    if free < need:
        raise Halt("custom_guest_host_disk_low", f"free {free // GIB} GiB, need {need // GIB} GiB")
    ensure_group("cg-sev")
    ensure_user("cg-stage")
    ensure_user("cg-probe")
    ensure_user(ctx.user)
    install_tools()
    for name in ("vmlinuz", "initrd", "root.raw"):
        st = os.lstat(f"{inbox}/{name}")
        if not stat.S_ISREG(st.st_mode):
            raise Halt("custom_guest_request_invalid", f"inbox {name} is not a regular file")
    for name, doc in (("request.json", req), ("inputs.json", ctx.data.get("inputs") or {})):
        write_atomic(f"{inbox}/{name}", json.dumps(doc, sort_keys=True).encode(), 0o400)
    if os.path.isdir(staging):
        shutil.rmtree(staging)
    os.makedirs(staging, mode=0o700)
    chown("cg-stage:cg-stage", inbox, recursive=True)
    chown("cg-stage:cg-stage", staging)
    for name in os.listdir(inbox):
        os.chmod(f"{inbox}/{name}", 0o400)
    os.chmod(inbox, 0o700)
    ctx.log("sub", phase="intake", sub="validator", state="intent")
    r = run(stage_argv(ctx, inbox, staging), timeout=3700)
    try:
        fd = os.open(f"{staging}/report.json", os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as f:
            report = json.loads(f.read(1 << 20))
    except (OSError, ValueError):
        raise Halt("custom_guest_request_invalid", f"the validator left no report: {r.stderr.strip()[:200]}")
    if not report.get("ok") or r.returncode != 0:
        ctx.log("sub", phase="intake", sub="validator", state="failed", error_code=report.get("error_code"))
        raise Halt(report.get("error_code") or "custom_guest_request_invalid", str(report.get("detail", ""))[:300])
    ctx.log("sub", phase="intake", sub="validator", state="done")
    # Finish: root copies into images and re-hashes every byte against the request and the verdict.
    if os.path.isdir(ctx.images):
        shutil.rmtree(ctx.images)
    os.makedirs(ctx.d, mode=0o755, exist_ok=True)
    os.makedirs(ctx.images, mode=0o750)
    files = {}
    want = {"vmlinuz": req["kernel"]["sha256"], "initrd": req["initrd"]["sha256"], "root.raw": req["root_disk"]["sha256"]}
    for name, sha in want.items():
        got, n = copy_hashed(f"{inbox}/{name}", f"{ctx.images}/{name}")
        if got != sha or got != report["files"][name]["sha256"]:
            raise Halt("custom_guest_digest_mismatch", f"{name} changed after the validator read it")
        files[name] = {"sha256": got, "bytes": n}
    got, n = copy_hashed(f"{staging}/cmdline", f"{ctx.images}/cmdline")
    if open(f"{ctx.images}/cmdline", "rb").read() != req["cmdline"].encode():
        raise Halt("custom_guest_cmdline_invalid", "the staged cmdline differs from the request")
    files["cmdline"] = {"sha256": got, "bytes": n}
    for name in files:
        os.chmod(f"{ctx.images}/{name}", 0o440)
    chown(f"root:{ctx.user}", ctx.images, *[f"{ctx.images}/{n}" for n in files])
    os.chmod(ctx.images, 0o550)
    ctx.log("intake_done", files=files, report={k: report[k] for k in ("kernel", "cmdline")})
    fault("host:intake:finish")
    shutil.rmtree(inbox)
    shutil.rmtree(staging)
    return {"ok": True, "files": files, "report": {k: report[k] for k in ("kernel", "cmdline")}}


def qemu_version() -> str:
    r = run([os.environ.get("CG_QEMU", "/usr/bin/qemu-system-x86_64"), "--version"])
    m = re.search(r"version ([0-9]+\.[0-9]+\.[0-9]+)", r.stdout)
    if not m:
        raise Halt("custom_guest_host_changed", "cannot read the QEMU version")
    return m.group(1)


def ovmf_source(ctx: Ctx) -> str:
    return ROOT + ctx.kit_env().get("SEALED_OVMF", "/usr/share/ovmf/OVMF.amdsev.fd")


def snp_measure(ctx: Ctx) -> str:
    venv = f"{ctx.sealed}/venv/bin"
    r = run([f"{venv}/python", "-I", "-c",
             "import importlib.metadata as m; print(m.version('sev-snp-measure'))"])
    if r.stdout.strip() != SNP_MEASURE_VERSION:
        raise Halt("custom_guest_host_changed", f"sev-snp-measure {r.stdout.strip() or '?'}, want {SNP_MEASURE_VERSION}")
    return f"{venv}/sev-snp-measure"


def free_link(ctx: Ctx) -> int:
    used = set(re.findall(r"10\.217\.([0-9]{1,3})\.", run(["ip", "-4", "-o", "addr", "show"]).stdout))
    for n in range(256):
        if str(n) not in used and run(["ip", "link", "show", f"cgst{n}"]).returncode != 0:
            return n
    raise Halt("custom_guest_port_unavailable", "no free 10.217.<n>.0/30 link")


def ph_measure(ctx: Ctx) -> dict:
    req = ctx.data["request"]
    if not images_complete(ctx, req):
        raise Halt("custom_guest_journal_behind", "intake is not complete")
    os.chmod(ctx.images, 0o750)
    ovmf = f"{ctx.images}/OVMF.amdsev.fd"
    if not os.path.exists(ovmf):
        sha, _ = copy_hashed(ovmf_source(ctx), ovmf)
        os.chmod(ovmf, 0o440)
        chown(f"root:{ctx.user}", ovmf)
    if sha256_path(ovmf) != ctx.data["ovmf_sha256"]:
        os.remove(ovmf)
        raise Halt("custom_guest_host_changed", "the host's OVMF.amdsev.fd is not the published one")
    files = ctx.last("intake_done")["files"]
    names = ("OVMF.amdsev.fd", "vmlinuz", "initrd", "cmdline", "root.raw")
    sizes = {n: (os.path.getsize(f"{ctx.images}/{n}") if n == "OVMF.amdsev.fd" else files[n]["bytes"]) for n in names}
    shas = {n: (sha256_path(ovmf) if n == "OVMF.amdsev.fd" else files[n]["sha256"]) for n in names}
    rep = ctx.last("intake_done")["report"]["cmdline"]
    manifest = {"version": 1, "schema": "cathedral.custom_guest.manifest/v1", "kind": "custom_guest",
                "sha256": shas, "bytes": sizes, "cmdline": req["cmdline"], "root_verity": rep["root_verity"],
                "root_data_bytes": rep["root_data_bytes"], "vcpus": req["vcpus"], "cpu_model": req["cpu_model"],
                "mem_gib": req["mem_gib"], "data_disk_gib": req.get("data_disk_gib", 0), "policy": "0x30000",
                "qemu_version": qemu_version(), "sev_snp_measure": SNP_MEASURE_VERSION,
                "reference_initrd": req["initrd"]["reference"]}
    m_raw = canonical(manifest)
    existing = None
    if os.path.exists(f"{ctx.images}/bootstrap.json"):
        existing = load_doc(f"{ctx.images}/bootstrap.json")[0]
    n = int(existing["network"]["guest_ip"].split(".")[2]) if existing else free_link(ctx)
    hexid = ctx.launch[3:]
    bootstrap = {"version": 1, "schema": "cathedral.custom_guest.bootstrap/v1", "launch_id": ctx.launch,
                 "hotel": ctx.hotel, "owner_scope": ctx.data["owner_scope"],
                 "owner_ed25519_b64": req["owner_ed25519_b64"], "manifest_sha256": hashlib.sha256(m_raw).hexdigest(),
                 "ssh_public_key": " ".join(req["ssh_public_key"].split()[:2]),
                 "launch_nonce_hex": req["launch_nonce_hex"],
                 "ports": [{"guest": x["guest"], "proto": "tcp", "public": x["public"]} for x in req["ports"]],
                 "network": {"guest_ip": f"10.217.{n}.2", "host_ip": f"10.217.{n}.1", "prefix": 30,
                             "guest_mac": f"52:54:00:c7:{hexid[0:2]}:{hexid[2:4]}",
                             "public_host": ctx.data["public_host"]}}
    b_raw = canonical(bootstrap)
    for name, raw in (("manifest.json", m_raw), ("bootstrap.json", b_raw)):
        path = f"{ctx.images}/{name}"
        if not os.path.exists(path) or open(path, "rb").read() != raw:
            write_atomic(path, raw, 0o440)
            chown(f"root:{ctx.user}", path)
    tool = snp_measure(ctx)
    r = run([tool, "--mode", "snp", "--vcpus", str(req["vcpus"]), "--vcpu-type", req["cpu_model"],
             "--ovmf", ovmf, "--kernel", f"{ctx.images}/vmlinuz", "--initrd", f"{ctx.images}/initrd",
             "--append", req["cmdline"]], timeout=600)
    measurement = r.stdout.strip().splitlines()[-1] if r.returncode == 0 and r.stdout.strip() else ""
    if not re.fullmatch(r"[0-9a-f]{96}", measurement):
        raise Halt("custom_guest_not_snp_bootable", f"sev-snp-measure failed: {r.stderr.strip()[:200]}")
    os.chmod(ctx.images, 0o550)
    owner = base64.b64decode(req["owner_ed25519_b64"])
    hd = hashlib.sha256(b"cathedral-dedicated-v2\0" + hashlib.sha256(m_raw).digest() + owner
                        + hashlib.sha256(b_raw).digest()).hexdigest()
    out = {"ok": True, "manifest": manifest, "manifest_sha256": hashlib.sha256(m_raw).hexdigest(),
           "bootstrap": bootstrap, "bootstrap_sha256": hashlib.sha256(b_raw).hexdigest(), "host_data_hex": hd,
           "expected_measurement": measurement, "cmdline_hex": req["cmdline"].encode().hex(),
           "ovmf_sha256": shas["OVMF.amdsev.fd"], "qemu_version": manifest["qemu_version"],
           "sev_snp_measure_version": SNP_MEASURE_VERSION}
    ctx.log("measured", **{k: out[k] for k in ("manifest_sha256", "bootstrap_sha256", "host_data_hex",
                                                 "expected_measurement")})
    return out


def ph_discard(ctx: Ctx) -> dict:
    """Cancel before any hold: delete the staged files of this launch only."""
    if (marker_doc(ctx) or {}).get("launch_id") == ctx.launch:
        raise Halt("custom_guest_hold_failed", "this launch holds the hotel; return it, do not discard")
    for d in (f"{ctx.base}/inbox/{ctx.launch}", f"{ctx.base}/staging/{ctx.launch}", ctx.d):
        if os.path.isdir(d):
            shutil.rmtree(d)
    ctx.log("discarded")
    return {"ok": True}


def kit_attestation(ctx: Ctx) -> dict | None:
    env = ctx.kit_env()
    ip = env.get("SEALED_GUEST_IP", "10.215.0.2")
    r = run(["curl", "-fsS", "-m", "10", f"http://{ip}:18090/room/attestation"], timeout=20)
    if r.returncode != 0:
        return None
    try:
        doc = json.loads(r.stdout)
        return doc if isinstance(doc.get("binding"), dict) else None
    except ValueError:
        return None


def kit_unit_has_guard(ctx: Ctx) -> bool:
    try:
        return GUARD_TEXT in open(f"{ctx.unit_dir}/{ctx.kit_unit}").read()
    except OSError:
        return False


def ph_hold_stop(ctx: Ctx) -> dict:
    part = ctx.opts.get("part")
    intent = ctx.last("kit_stop")
    if part == "a":
        # H6a: only while the kit unit is active.
        if not active(ctx.kit_unit):
            if intent and kit_absent(ctx):
                return {"ok": True, "next": "b", "kit_attestation_before": (ctx.last("kit_attestation_before") or {}).get("attestation")}
            raise Halt("custom_guest_kit_failed", "the kit is not active and this launch never stopped it")
        eligibility(ctx, "hold")
        if not kit_unit_has_guard(ctx):
            raise Halt("custom_guest_hold_unsupported", "the kit unit lacks the 5.10 guard (deploy PR 2's write-units.sh)")
        if ctx.kit_env().get("SEALED_MINER") != "1":
            raise Halt("custom_guest_hotel_not_guest_tls", "the kit is not in guest-TLS mode (SEALED_MINER=1)")
        inv = show(ctx.kit_unit, "InvocationID").get("InvocationID", "")

        def att_done() -> bool:
            e = ctx.last("kit_attestation_before")
            return bool(e and e.get("invocation_id") == inv)

        def att_act() -> None:
            att = kit_attestation(ctx)
            if not att:
                raise Halt("custom_guest_kit_failed", "no attestation from the running kit over the host link")
            ctx.log("kit_attestation_before", invocation_id=inv, attestation=att)

        sub(ctx, "kit_attestation", att_done, att_act)
        sub(ctx, "marker", lambda: (marker_doc(ctx) or {}).get("launch_id") == ctx.launch
            and marker_doc(ctx).get("state") == "held",
            lambda: write_marker(ctx, {"launch_id": ctx.launch, "state": "held"}))
        sub(ctx, "kit_stop_intent", lambda: ctx.last("kit_stop") is not None, lambda: ctx.log("kit_stop", state="intent"))
        sub(ctx, "kit_stop", lambda: kit_absent(ctx), lambda: systemctl("stop", ctx.kit_unit, timeout=600))
        att = ctx.last("kit_attestation_before")
        return {"ok": True, "next": "b", "kit_attestation_before": att["attestation"]}
    if part != "b":
        raise Halt("custom_guest_hold_failed", "hold-stop needs --part a or b")
    # H6b: never reads a room list; a stopped kit cannot answer one.
    if not intent:
        raise Halt("custom_guest_kit_failed", "no kit_stop intent for this launch: H6b does not run")
    if not kit_absent(ctx):
        raise Halt("custom_guest_kit_failed", "the kit is not absent: run H6a with a live read")
    sub(ctx, "marker_b", lambda: (marker_doc(ctx) or {}).get("launch_id") == ctx.launch,
        lambda: write_marker(ctx, {"launch_id": ctx.launch, "state": "held"}))
    sub(ctx, "kit_disable", lambda: not enabled(ctx.kit_unit), lambda: systemctl("disable", ctx.kit_unit))
    sub(ctx, "kit_net_timer", lambda: not active(ctx.kit_net_timer) and not enabled(ctx.kit_net_timer),
        lambda: systemctl("disable", "--now", ctx.kit_net_timer))

    def still_absent() -> bool:
        if not kit_absent(ctx):
            raise Halt("custom_guest_kit_failed", "the kit came back while the hold stopped it")
        return True

    sub(ctx, "kit_absent", still_absent)
    if not ctx.last("kit_stopped"):
        ctx.log("kit_stopped")
    att = ctx.last("kit_attestation_before")
    return {"ok": True, "kit_attestation_before": att["attestation"] if att else None}


def ph_unhold(ctx: Ctx) -> dict:
    """Abort step 1: only while the kit never stopped (11.2)."""
    if not active(ctx.kit_unit):
        if ctx.last("kit_stop"):
            raise Halt("custom_guest_hold_failed", "the kit stopped for this launch: no abort, only forward")
        raise Halt("custom_guest_kit_failed", "the kit is not active; Toby decides")
    doc = marker_doc(ctx)
    if doc and doc.get("launch_id") != ctx.launch:
        raise Halt("custom_guest_previous_launch_on_host", "the marker names another launch")
    sub(ctx, "marker_removed", lambda: marker_doc(ctx) is None, lambda: os.remove(ctx.marker))
    ctx.log("unheld")
    return {"ok": True}


def kit_link_gone(ctx: Ctx) -> bool:
    env = ctx.kit_env()
    tag = f"sealed-hotel:{ctx.hotel}"
    for table in ("filter", "nat"):
        r = run(["iptables", "-t", table, "-S"])
        if r.returncode != 0 or re.search(rf'--comment "?{re.escape(tag)}"?( |$)', r.stdout, re.M):
            return False
    host_ip = env.get("SEALED_HOST_IP", "10.215.0.1")
    if f" {host_ip}/30 " in " " + run(["ip", "-4", "-o", "addr", "show"]).stdout.replace("\n", " ") + " ":
        return False
    tap = env.get("SEALED_TAP", "snp0")
    return run(["ip", "link", "show", tap]).returncode != 0


def ph_hold_baseline(ctx: Ctx) -> dict:
    """H8: prove the kit's link is gone, then the SEV baseline and the disk fingerprint, then the timer."""
    if not ctx.last("kit_stopped") or not kit_absent(ctx) or (marker_doc(ctx) or {}).get("launch_id") != ctx.launch:
        raise Halt("custom_guest_journal_behind", "H6b is not complete")
    sub(ctx, "kit_link_gone", lambda: kit_link_gone(ctx),
        lambda: run([f"{ctx.sealed}/host-net.sh", "down", f"{ctx.sealed}/sealed.env"], timeout=60))
    sub(ctx, "sev_baseline", lambda: sev_baseline(ctx) is not None,
        lambda: ctx.log("sev_baseline", status=sev_read()))
    dev = p("/dev/sev")

    def dev_record() -> None:
        st = os.stat(dev)
        ctx.log("dev_sev_before", uid=st.st_uid, gid=st.st_gid, mode=stat.S_IMODE(st.st_mode))

    sub(ctx, "dev_sev_before", lambda: ctx.last("dev_sev_before") is not None, dev_record)
    def fp_act() -> None:
        fp = fingerprint(ctx, full=True)
        ctx.log("fingerprint", fingerprint=fp, sha256=fingerprint_sha256(fp))

    sub(ctx, "fingerprint", lambda: ctx.last("fingerprint") is not None, fp_act)
    texts = timer_texts(ctx)

    def timers_done() -> bool:
        return all(os.path.exists(f"{ctx.unit_dir}/{n}") and open(f"{ctx.unit_dir}/{n}").read() == t
                   for n, t in texts.items()) and active(ctx.timer) and enabled(ctx.timer) and enabled(ctx.boot_record)

    def timers_act() -> None:
        install_tools()
        for n, t in texts.items():
            write_if_changed(f"{ctx.unit_dir}/{n}", t)
        systemctl("daemon-reload")
        systemctl("enable", "--now", ctx.timer)
        systemctl("enable", ctx.boot_record)

    sub(ctx, "custom_timer", timers_done, timers_act)
    if not ctx.last("baselined"):
        ctx.log("baselined", fingerprint_sha256=ctx.last("fingerprint")["sha256"])
    return {"ok": True, "sev_baseline": sev_baseline(ctx), "fingerprint_sha256": ctx.last("fingerprint")["sha256"]}


def host_checks_before_boot(ctx: Ctx) -> dict:
    manifest, m_raw = load_doc(f"{ctx.images}/manifest.json")
    bootstrap, b_raw = load_doc(f"{ctx.images}/bootstrap.json")
    if hashlib.sha256(m_raw).hexdigest() != ctx.data.get("manifest_sha256") \
            or hashlib.sha256(b_raw).hexdigest() != ctx.data.get("bootstrap_sha256"):
        raise Halt("custom_guest_host_changed", "the launch documents differ from the record")
    for name in ("OVMF.amdsev.fd", "vmlinuz", "initrd", "cmdline"):
        if sha256_path(f"{ctx.images}/{name}") != manifest["sha256"][name]:
            raise Halt("custom_guest_host_changed", f"images/{name} differs from the manifest")
    if sha256_path(ovmf_source(ctx)) != manifest["sha256"]["OVMF.amdsev.fd"] or qemu_version() != manifest["qemu_version"]:
        raise Halt("custom_guest_host_changed", "the host's OVMF or QEMU differs from the manifest")
    base = sev_baseline(ctx)
    diff = sev_differences(base, sev_read()) if base else ["no baseline"]
    if diff:
        raise Halt("custom_guest_sev_platform_changed", "; ".join(diff))
    eligibility(ctx, "boot")
    return manifest


def ph_boot(ctx: Ctx) -> dict:
    gen = int(ctx.data["generation"])
    if not ctx.last("baselined") or (marker_doc(ctx) or {}).get("state") != "held":
        raise Halt("custom_guest_journal_behind", "the hold is not baselined")
    used = ctx.last("token_used")
    if active(ctx.unit):
        if used and used.get("generation") == gen:
            if any(e.get("generation") == gen for e in ctx.entries("booted")):
                return {"ok": True, "already": True, "generation": gen}
            # A run that died between the start and "booted": finish the checks, never skip them.
            return finish_boot(ctx, gen)
        raise Halt("custom_guest_host_not_exclusive", "the custom guest runs another generation")
    if any(e.get("generation") == gen for e in ctx.entries("token_used")):
        # Nothing restarts a guest (11.4): a new start is an owner relaunch with a new generation.
        raise Halt("custom_guest_boot_failed", f"generation {gen} already started once; relaunch allocates a new one")
    manifest = host_checks_before_boot(ctx)
    sig = base64.b64decode(ctx.data["bootstrap_signature_b64"], validate=True)
    if len(sig) != 64:
        raise Halt("custom_guest_signature_invalid", "the bootstrap signature must be 64 bytes")

    def sig_done() -> bool:
        path = f"{ctx.images}/bootstrap.sig"
        if not os.path.exists(path):
            return False
        if open(path, "rb").read() != sig:
            raise Halt("custom_guest_bootstrap_mismatch", "images/bootstrap.sig differs from the record")
        return True

    def sig_act() -> None:
        os.chmod(ctx.images, 0o750)
        write_atomic(f"{ctx.images}/bootstrap.sig", sig, 0o440)
        chown(f"root:{ctx.user}", f"{ctx.images}/bootstrap.sig")
        os.chmod(ctx.images, 0o550)

    sub(ctx, "signature", sig_done, sig_act)
    dev = p("/dev/sev")

    def dev_done() -> bool:
        e = ctx.last("dev_sev_set")
        return stat.S_IMODE(os.stat(dev).st_mode) == 0o660 and bool(e) and e.get("boot_id") == boot_id()

    def dev_act() -> None:
        # The custom QEMU runs unprivileged; the kit's QEMU runs as root and is down while held.
        chown("root:cg-sev", dev)
        os.chmod(dev, 0o660)
        ctx.log("dev_sev_set")

    sub(ctx, "dev_sev", dev_done, dev_act)

    def dirs_done() -> bool:
        ok = all(os.path.isdir(f"{ctx.d}/{x}") for x in ("disks", "run"))
        if manifest.get("data_disk_gib"):
            ok = ok and os.path.isfile(f"{ctx.d}/disks/data.raw")
        return ok

    def dirs_act() -> None:
        for x in ("disks", "run"):
            os.makedirs(f"{ctx.d}/{x}", mode=0o700, exist_ok=True)
            chown(f"{ctx.user}:{ctx.user}", f"{ctx.d}/{x}")
        if manifest.get("data_disk_gib") and not os.path.exists(f"{ctx.d}/disks/data.raw"):
            fd = os.open(f"{ctx.d}/disks/data.raw", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.ftruncate(fd, manifest["data_disk_gib"] * GIB)
            os.close(fd)
            chown(f"{ctx.user}:{ctx.user}", f"{ctx.d}/disks/data.raw")

    sub(ctx, "launch_dirs", dirs_done, dirs_act)
    text = unit_text(ctx, manifest["mem_gib"])

    def unit_act() -> None:
        install_tools()
        write_if_changed(f"{ctx.unit_dir}/{ctx.unit}", text)
        systemctl("daemon-reload")

    sub(ctx, "unit", lambda: os.path.exists(f"{ctx.unit_dir}/{ctx.unit}")
        and open(f"{ctx.unit_dir}/{ctx.unit}").read() == text, unit_act)
    r = run([os.path.join(HERE, "custom-net.sh"), "up", ctx.hotel, ctx.launch], timeout=120)
    if r.returncode != 0:
        m = re.search(r"ERROR (custom_guest_[a-z_]+)", r.stderr)
        run([os.path.join(HERE, "custom-net.sh"), "down", ctx.hotel, ctx.launch], timeout=120)
        raise Halt(m.group(1) if m else "custom_guest_isolation_failed", r.stderr.strip()[-300:])
    # The start token is the latest journal entry when systemctl start runs check-start.
    token = secrets.token_hex(16)
    ctx.log("boot", state="intent", generation=gen, token=token)
    fault("host:boot:intent")
    r = run(["systemctl", "start", ctx.unit], timeout=240)
    if r.returncode != 0 or not active(ctx.unit):
        raise Halt("custom_guest_boot_failed", f"the unit did not start: {r.stderr.strip()[:200]}")
    fault("host:boot:started")
    return finish_boot(ctx, gen)


def finish_boot(ctx: Ctx, gen: int) -> dict:
    """After the start: the SSH banner, the isolation checks, then "booted". Any failure stops the unit."""
    net = guest_net(ctx)
    addr = os.environ.get("CG_PROBE_ADDR", f"{net['guest_ip']}:22")
    host, port = addr.rsplit(":", 1)
    deadline = time.time() + PROBE_TIMEOUT
    while time.time() < deadline and active(ctx.unit):
        if probe_banner(ctx, host, int(port)):
            break
        time.sleep(min(POLL, 5))
    else:
        tail = save_ring(ctx)
        run(["systemctl", "stop", ctx.unit], timeout=120)
        ctx.log("boot_failed", generation=gen, serial_tail=tail)
        raise Halt("custom_guest_boot_failed", f"no SSH banner within {int(PROBE_TIMEOUT)} s; serial tail {tail}")
    try:
        verify_isolation(ctx)
    except Halt:
        save_ring(ctx)
        run(["systemctl", "stop", ctx.unit], timeout=120)
        ctx.log("isolation_failed", generation=gen)
        raise
    # The unit run and (via log) the host boot this entry is about: the operator matches both against the live
    # unit before it records running, so an entry from before a host reboot proves nothing (11.3).
    ctx.log("booted", generation=gen, invocation_id=show(ctx.unit, "InvocationID").get("InvocationID"))
    return {"ok": True, "generation": gen, "qemu": custom_qemu(ctx)}


def ph_verify_disks(ctx: Ctx) -> dict:
    """The full kit disk content check after a boot (5.11); a difference stops the guest."""
    base = baseline_fingerprint(ctx)
    now = fingerprint(ctx, full=True)
    diff = disk_differences(base, now, meta_only=False)
    if diff:
        ctx.log("kit_data_changed", diff=diff, context=ctx.opts.get("context", "boot"))
        if active(ctx.unit):
            save_ring(ctx)
            run(["systemctl", "stop", ctx.unit], timeout=120)
        raise Halt("custom_guest_kit_data_changed", ", ".join(diff)[:300])
    e = ctx.log("disk_verified", context=ctx.opts.get("context", "boot"), fingerprint_sha256=fingerprint_sha256(base))
    return {"ok": True, "at": e["at"]}


def net_gone(ctx: Ctx) -> bool:
    tag = f"custom-guest:{ctx.hotel}:{ctx.launch}"
    for tool, table in (("iptables", "filter"), ("iptables", "nat"), ("ip6tables", "filter")):
        r = run([tool, "-t", table, "-S"])
        if r.returncode == 0 and re.search(rf'--comment "?{re.escape(tag)}"?( |$)', r.stdout, re.M):
            return False
    try:
        n = guest_net(ctx)["guest_ip"].split(".")[2]
        return run(["ip", "link", "show", f"cgst{n}"]).returncode != 0
    except (OSError, ValueError, KeyError, Halt):
        return True


def net_down(ctx: Ctx) -> None:
    r = run([os.path.join(HERE, "custom-net.sh"), "down", ctx.hotel, ctx.launch], timeout=120)
    if r.returncode != 0:
        raise Halt("custom_guest_stop_failed", r.stderr.strip()[-300:])


def ph_stop(ctx: Ctx) -> dict:
    if active(ctx.unit):
        save_ring(ctx)
        try:
            qmp(ctx, {"execute": "system_powerdown"})
        except (OSError, ValueError):
            pass
        deadline = time.time() + STOP_WAIT
        while time.time() < deadline and active(ctx.unit):
            time.sleep(min(POLL, 2))
    sub(ctx, "unit_stop", lambda: not active(ctx.unit), lambda: systemctl("stop", ctx.unit, timeout=120))
    sub(ctx, "net_down", lambda: net_gone(ctx), lambda: net_down(ctx))
    return {"ok": True}


def ph_return_kit(ctx: Ctx) -> dict:
    """R1 to R10 (11.6). From R7 on, R1 to R7 observe done from the marker alone, and no kit disk is read."""
    doc = marker_doc(ctx) or {}
    if doc.get("launch_id") != ctx.launch:
        raise Halt("custom_guest_journal_behind", "no marker for this launch: the hold never reached H6")
    if not ctx.last("baselined"):
        raise Halt("custom_guest_journal_behind", "the hold is not baselined: finish H6 to H9 first")
    boundary = doc.get("state") == "kit_start" and isinstance(doc.get("disk_verified"), dict)
    if not boundary:
        sub(ctx, "R1", lambda: not active(ctx.unit) and not custom_qemu(ctx),
            lambda: systemctl("stop", ctx.unit, timeout=120))

        def r2_act() -> None:
            r = run([os.path.join(HERE, "custom-net.sh"), "purge", ctx.hotel, ctx.launch], timeout=120)
            if r.returncode != 0:
                raise Halt("custom_guest_stop_failed", r.stderr.strip()[-300:])

        sub(ctx, "R2", lambda: net_gone(ctx), r2_act)

        def r3() -> bool:
            diff = sev_differences(sev_baseline(ctx), sev_read())
            if diff:
                ctx.log("reboot_required", diff=diff)
                raise Halt("custom_guest_sev_platform_changed", "reboot_required: " + "; ".join(diff))
            return True

        sub(ctx, "R3", r3)
        dev = p("/dev/sev")
        dev_before = ctx.last("dev_sev_before") or {}

        def r4_done() -> bool:
            st = os.stat(dev)
            return not active(ctx.timer) and not enabled(ctx.timer) and not enabled(ctx.boot_record) \
                and not active(ctx.timer_service) \
                and (not dev_before or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) ==
                     (dev_before["uid"], dev_before["gid"], dev_before["mode"]))

        def r4_act() -> None:
            run(["systemctl", "disable", "--now", ctx.timer])
            run(["systemctl", "disable", "--now", ctx.boot_record])
            run(["systemctl", "stop", ctx.timer_service])
            if dev_before:
                chown(f"{dev_before['uid']}:{dev_before['gid']}", dev)
                os.chmod(dev, dev_before["mode"])

        sub(ctx, "R4", r4_done, r4_act)
        r4_at = ctx.last("sub", phase="return-kit", sub="R4", state="done")["t"]

        def r5_done() -> bool:
            e = ctx.last("disk_verified", context="R5")
            return bool(e and e["t"] >= r4_at and e["fingerprint_sha256"] == ctx.last("fingerprint")["sha256"])

        def r5_act() -> None:
            ctx.opts["context"] = "R5"
            ph_verify_disks(ctx)

        sub(ctx, "R5", r5_done, r5_act)

        def r6_done() -> bool:
            return kit_unit_has_guard(ctx) and enabled(ctx.kit_net_timer)

        def r6_act() -> None:
            wu = os.path.join(KIT_DIR, "sealed", "write-units.sh")
            env = dict(os.environ, CATHEDRAL_SNP_LOCK_FD="9")
            r = subprocess.run([wu, f"{ctx.sealed}/sealed.env"], capture_output=True, text=True, timeout=120,
                               env=env, pass_fds=(9,))
            if r.returncode != 0:
                raise Halt("custom_guest_kit_failed", f"write-units.sh: {r.stderr.strip()[-300:]}")
            systemctl("enable", "--now", ctx.kit_net_timer)

        sub(ctx, "R6", r6_done, r6_act)
        verified = ctx.last("disk_verified", context="R5")

        def r7_act() -> None:
            write_marker(ctx, {"launch_id": ctx.launch, "state": "kit_start",
                               "disk_verified": {"at": verified["at"], "fingerprint_sha256": verified["fingerprint_sha256"]}})
            ctx.log("predisk_verified", at=verified["at"], fingerprint_sha256=verified["fingerprint_sha256"])

        sub(ctx, "R7", lambda: (marker_doc(ctx) or {}).get("state") == "kit_start", r7_act)
    # R8: start the kit only if it is inactive; never a restart.
    sub(ctx, "R8", lambda: active(ctx.kit_unit), lambda: systemctl("start", ctx.kit_unit, timeout=600))
    expected = open(f"{ctx.sealed}/images/current/expected-measurement").read().strip()
    before = (ctx.last("kit_attestation_before") or {}).get("attestation") or {}
    want_hd = (before.get("binding") or {}).get("host_data")

    def r9_done() -> bool:
        inv = show(ctx.kit_unit, "InvocationID").get("InvocationID")
        e = ctx.last("kit_boot")
        return bool(e and inv and e["invocation_id"] == inv and e["measurement"] == expected
                    and e["host_data"] == want_hd)

    def r9_act() -> None:
        inv = show(ctx.kit_unit, "InvocationID", "ActiveEnterTimestamp")
        deadline = time.time() + KIT_ATTEST_WAIT
        att = None
        while time.time() < deadline and active(ctx.kit_unit):
            att = kit_attestation(ctx)
            if att:
                break
            time.sleep(POLL)
        if not att:
            raise Halt("custom_guest_return_measurement_differs", "no kit attestation after the start")
        b = att["binding"]
        enter = inv.get("ActiveEnterTimestamp", "")
        ctx.log("kit_boot", invocation_id=inv.get("InvocationID"), binding_boot_id=b.get("boot_id"),
                measurement=b.get("measurement"), host_data=b.get("host_data"),
                active_enter=int(enter[1:]) if enter.startswith("@") and enter[1:].isdigit() else None)
        if b.get("measurement") != expected or b.get("host_data") != want_hd:
            run(["systemctl", "disable", "--now", ctx.kit_unit], timeout=300)
            raise Halt("custom_guest_return_measurement_differs",
                       f"kit measurement {b.get('measurement')} host_data {b.get('host_data')}")

    sub(ctx, "R9", r9_done, r9_act)
    sub(ctx, "R10", lambda: enabled(ctx.kit_unit), lambda: systemctl("enable", ctx.kit_unit))
    e = ctx.last("kit_boot")
    return {"ok": True, "kit_boot": {k: e.get(k) for k in ("invocation_id", "binding_boot_id", "measurement",
                                                            "host_data", "at", "active_enter")},
            "disk_verified": (marker_doc(ctx) or {}).get("disk_verified")}


def ph_return_finish(ctx: Ctx) -> dict:
    """R15: after the terminal commit only."""
    if ctx.data.get("record_state") != "returned":
        raise Halt("custom_guest_journal_behind", "R15 runs only after the record is returned")
    doc = marker_doc(ctx)
    if doc and doc.get("launch_id") != ctx.launch:
        raise Halt("custom_guest_previous_launch_on_host", "the marker names another launch")
    if doc and doc.get("state") != "kit_start":
        raise Halt("custom_guest_journal_behind", "the marker never reached the R7 boundary")
    sub(ctx, "marker_removed", lambda: marker_doc(ctx) is None, lambda: os.remove(ctx.marker))
    sub(ctx, "launch_wiped", lambda: not os.path.exists(ctx.d), lambda: shutil.rmtree(ctx.d))
    names = [ctx.unit, ctx.timer, ctx.timer_service, ctx.boot_record]

    def units_act() -> None:
        for n in names:
            run(["systemctl", "disable", "--now", n])
            try:
                os.remove(f"{ctx.unit_dir}/{n}")
            except FileNotFoundError:
                pass
        systemctl("daemon-reload")

    sub(ctx, "units_removed", lambda: not any(os.path.exists(f"{ctx.unit_dir}/{n}") for n in names), units_act)
    if not ctx.last("return_finished"):
        ctx.log("return_finished")
    return {"ok": True}


def ph_tick(ctx: Ctx) -> dict:
    """Custom timer, every minute: link check, SEV compare, kit disk metadata. Starts nothing."""
    alerts = []
    r = run([os.path.join(HERE, "custom-net.sh"), "check", ctx.hotel, ctx.launch], timeout=120)
    if r.returncode != 0:
        alerts.append("link: " + r.stderr.strip()[-200:])
    base = sev_baseline(ctx)
    if base:
        diff = sev_differences(base, sev_read())
        if diff:
            alerts.append("sev")
            ctx.log("sev_platform_changed", diff=diff)
            if active(ctx.unit):
                save_ring(ctx)
                run(["systemctl", "stop", ctx.unit], timeout=120)
    if ctx.last("fingerprint"):
        diff = disk_differences(baseline_fingerprint(ctx), fingerprint(ctx, full=False), meta_only=True)
        if diff:
            alerts.append("disk")
            ctx.log("kit_data_changed", diff=diff, context="tick")
            if active(ctx.unit):
                save_ring(ctx)
                run(["systemctl", "stop", ctx.unit], timeout=120)
    return {"ok": not alerts, "alerts": alerts}


def ph_check_start(ctx: Ctx) -> dict:
    """ExecStartPre of the custom unit: a fresh boot token and the 5.1 boot checks, or no start."""
    entries = ctx.entries(launch_only=False)
    latest = entries[-1] if entries else {}
    if latest.get("launch_id") != ctx.launch or latest.get("event") != "boot" or latest.get("state") != "intent":
        raise Halt("custom_guest_boot_failed", "the latest host journal entry is not a boot intent for this launch")
    if (marker_doc(ctx) or {}).get("state") != "held":
        raise Halt("custom_guest_boot_failed", "the hotel is not held for this launch")
    eligibility(ctx, "boot")
    ctx.log("token_used", token=latest["token"], generation=latest["generation"])
    return {"ok": True}


def ph_exited(ctx: Ctx) -> dict:
    boot = ctx.last("boot")
    ctx.log("exit", generation=boot.get("generation") if boot else None,
            exit_code=os.environ.get("EXIT_CODE", ""), exit_status=os.environ.get("EXIT_STATUS", ""),
            service_result=os.environ.get("SERVICE_RESULT", ""))
    r = run([os.path.join(HERE, "custom-net.sh"), "down", ctx.hotel, ctx.launch], timeout=120)
    return {"ok": r.returncode == 0}


def ph_boot_record(ctx: Ctx) -> dict:
    ctx.log("host_boot")
    return {"ok": True}


FUNCS = {"facts": ph_facts, "inbox": ph_inbox, "intake": ph_intake, "measure": ph_measure, "discard": ph_discard,
         "hold-stop": ph_hold_stop, "unhold": ph_unhold, "hold-baseline": ph_hold_baseline, "boot": ph_boot,
         "verify-disks": ph_verify_disks, "stop": ph_stop, "return-kit": ph_return_kit,
         "return-finish": ph_return_finish, "tick": ph_tick, "check-start": ph_check_start, "exited": ph_exited,
         "boot-record": ph_boot_record}


# ---------------------------------------------------------------- lock (5.3) and entry

def take_lock(ctx: Ctx, mode: str, deadline: int) -> str | None:
    """flock(2) on fd 9 of the host lock, the owner record, the exported owner. None: tick skipped."""
    if os.environ.get("CATHEDRAL_SNP_LOCK_FD"):
        raise Halt("custom_guest_lifecycle_busy", "a host phase is a top-level entry; it never nests under a lock")
    lock, owner_path = p("/run/lock/cathedral-snp-host.lock"), p("/run/lock/cathedral-snp-host.owner")
    os.makedirs(os.path.dirname(lock), exist_ok=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o644)
    if fd != 9:
        os.dup2(fd, 9)
        os.close(fd)
    os.set_inheritable(9, True)
    end = time.time() + (0 if mode == "try" else LOCK_WAIT)
    while True:
        try:
            fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.time() >= end:
                if mode == "try":
                    return None
                try:
                    holder = open(owner_path).read().strip()
                except OSError:
                    holder = "(no owner record)"
                raise Halt("custom_guest_lifecycle_busy", f"the host lock is held: {holder}")
            time.sleep(0.2)
    owner = f"custom-guest:{ctx.phase}:{ctx.launch}:{os.getpid()}"
    rec = {"owner": owner, "phase": ctx.phase, "hotel": ctx.hotel, "launch_id": ctx.launch, "pid": os.getpid(),
           "started_at": now_iso(), "deadline_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + deadline))}
    write_atomic(owner_path, (json.dumps(rec, sort_keys=True) + "\n").encode(), 0o644)
    os.environ["CATHEDRAL_SNP_LOCK_FD"] = "9"
    os.environ["CATHEDRAL_SNP_LOCK_OWNER"] = owner
    return owner_path


def parse(argv: list[str]) -> tuple[str, dict]:
    if not argv or argv[0] not in PHASES:
        raise SystemExit(f"usage: custom-guest-host.sh <{'|'.join(PHASES)}> --hotel H --launch-id L")
    phase, opts, i = argv[0], {}, 1
    while i < len(argv):
        if not argv[i].startswith("--") or i + 1 >= len(argv):
            raise SystemExit(f"bad argument {argv[i]}")
        opts[argv[i][2:].replace("-", "_")] = argv[i + 1]
        i += 2
    return phase, opts


def main(argv: list[str]) -> int:
    phase, opts = parse(argv)
    hotel, launch = opts.pop("hotel", ""), opts.pop("launch_id", "")
    result: dict
    owner_path = None
    try:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,58}", hotel) or not re.fullmatch(r"cg-[0-9a-f]{12}", launch):
            raise Halt("custom_guest_request_invalid", "bad --hotel or --launch-id")
        mode, deadline = PHASES[phase]
        if mode != "none" and os.environ.get("CG_DEADLINE") != phase:
            # Run the holder under its deadline; a kill frees the lock with the process (5.3).
            env = dict(os.environ, CG_DEADLINE=phase)
            os.execvpe("timeout", ["timeout", "--kill-after=30s", f"{deadline}s", sys.executable, "-I",
                                   os.path.realpath(__file__), *argv], env)
        if phase not in ("check-start", "exited", "boot-record") and not allowed(hotel):
            raise Halt("custom_guest_hold_unsupported", "/etc/cathedral/custom-guest.allow does not list this hotel")
        data = {}
        if phase in STDIN_PHASES:
            raw = sys.stdin.read(1 << 20)
            data = json.loads(raw) if raw.strip() else {}
        ctx = Ctx(phase, hotel, launch, opts, data)
        if mode != "none":
            owner_path = take_lock(ctx, mode, deadline)
            if owner_path is None:
                print("RESULT " + json.dumps({"ok": True, "skipped": "the host lock is held"}))
                return 0
        result = FUNCS[phase](ctx)
    except Halt as e:
        result = {"ok": False, "error_code": e.code, "detail": e.detail}
    finally:
        if owner_path:
            try:
                os.remove(owner_path)  # just before the release, which is this process's exit
            except OSError:
                pass
    print("RESULT " + json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1


STDIN_PHASES = ("intake", "measure", "boot", "return-finish")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
