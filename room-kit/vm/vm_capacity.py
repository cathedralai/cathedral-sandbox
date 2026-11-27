#!/usr/bin/env python3
"""Host admission ledger for customer VMs and sealed hotel kits (AB#999, VM spec r2 section 9).

One SNP host shares its memory, disks, SNP ASIDs and threads between the sealed hotel kits
(room-sealed-<name>.service) and the customer VMs (room-kit/vm). This module counts both and
answers whether one more VM may be created or started. vm_ctl.py calls it for create and start;
install-sealed.sh calls `vm_capacity.py assess-kit <sealed.env>` in its assess step.

What it counts:
- Kits: every room-sealed-<name>.service unit file in the systemd unit directory, enabled or not,
  except the -net check units, and the env file named on its ExecStart line
  (`<SEALED_DIR>/launch-guest.sh <SEALED_DIR>/sealed.env`, write-units.sh). No directory glob:
  SEALED_DIR is configurable. A -net check unit is skipped only when it is exactly what
  write-units.sh writes (oneshot, `host-net.sh check <env>`); any other unit is a kit and must
  parse. Plus the kits being installed, from /var/lib/cathedral-snp/kits/<name>.json. The union
  is taken by kit name, each size the larger of the two.
- Kit records: install-sealed.sh's assess step records the larger of the running build and the
  replacement before its build. The record shrinks to the new size only after the new guest is
  verified running (commit-kit), so a roll that fails or is refused after the env copy never
  releases the running guest's room. A data-volume reset is reserved before data.raw is moved
  aside (assess-kit --data-reset): data.raw.prev keeps its blocks while a fresh data.raw grows.
- VMs: every $VM_ROOT/<name>/vm.env, in any state (the broker's rule).
- A kit unit, env file or record that cannot be read refuses every VM create and start
  (resource kit_unaccounted): the ledger never guesses a size.

Rules (spec section 9 table), on create (commit) and start (live):
- memory: create, kits + VMs + the new VM, each plus GUEST_OVERHEAD_MIB, plus the 32 GiB reserve
  (install-sealed.sh) <= MemTotal. Start, MemAvailable >= mem + overhead + reserve.
- disk, per file system (by device): avail minus the remaining growth of every sparse file on it
  (logical size minus allocated: VM disks, kit scratch.raw and data.raw) minus the new VM's full
  size >= the reserve. Start: the same without the new VM.
- SNP ASIDs: create, one per kit (running or not, so a stopped kit can always restart) plus one
  per VM plus one <= misc.capacity sev_es. Start, max(misc.current sev_es, running kits and VMs
  that run or are enabled) + the stopped kits + 1 <= capacity.
- vCPU: create only, kits + VMs + the new VM <= threads - 4 (ratio 1.0).

The capacity lock (/run/lock/cathedral-snp-capacity.lock) is held only for check-and-record: by
VM create (until vm.env is written), VM start (until the unit is enabled) and install-sealed.sh's
assess step (until the kit record is written). stop, enforce, cancel and delete never take it, so
the credit cutoff never waits on it. It is not the dedicated host lifecycle lock.

Off by default: admission runs only while the VM host switch /etc/cathedral/snp-vm-host.json
exists (VM spec r2 section 12). Without it vm_ctl.py and install-sealed.sh behave as before.
The custom-guest refusal (a dedicated custom-guest host never takes a VM) always runs on create.

VM_CAPACITY_ROOT (default /) prefixes the host paths above, for tests.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

GIB = 1 << 30
MIB = 1 << 20
KIB_PER_GIB = 1 << 20
KIB_PER_MIB = 1 << 10
MEM_RESERVE_GIB = 32  # the kit's margin, install-sealed.sh assess step
HOST_THREADS = 4  # vCPU rule: threads minus 4, ratio 1.0 (VM spec r2 Q7)
# Per-guest memory beyond the guest's own (QEMU, page tables, the SNP metadata). The spec leaves the
# figure to rehearsal A2; this default errs toward refusing until it is measured.
GUEST_OVERHEAD_MIB = int(os.environ.get("VM_GUEST_OVERHEAD_MIB", "1024"))
# Disk reserve on a file system that holds no kit (a kit's SEALED_MIN_HOST_FREE_GIB applies on its own).
VM_MIN_HOST_FREE_GIB = int(os.environ.get("VM_MIN_HOST_FREE_GIB", "64"))
LOCK_WAIT = float(os.environ.get("VM_CAPACITY_LOCK_WAIT", "60"))

# Resource names of a refusal. The broker passes only these on (broker/vms.go).
RESOURCES = ("memory", "disk", "asid", "vcpu", "kit_unaccounted", "vm_unaccounted", "custom_guest_host")

SWITCH = "etc/cathedral/snp-vm-host.json"
LOCK = "run/lock/cathedral-snp-capacity.lock"
KIT_RECORDS = "var/lib/cathedral-snp/kits"
CUSTOM_GUEST_ALLOW = "etc/cathedral/custom-guest.allow"
CUSTOM_GUEST_ROOT = "srv/custom-guest"
RECORD_SCHEMA = "cathedral.snp.kit-reservation/v1"

KIT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,58}$")  # install-sealed.sh SEALED_NAME rule
VM_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")  # vm_ctl.py NAME_RE
ACTIVE_STATES = ("active", "activating", "reloading", "deactivating")


class CapacityRefusal(Exception):
    def __init__(self, resource: str, detail: str):
        super().__init__(f"{resource}: {detail}")
        self.resource, self.detail = resource, detail


class CapacityBusy(Exception):
    pass


# ---- paths ----------------------------------------------------------------------

def host_root() -> Path:
    return Path(os.environ.get("VM_CAPACITY_ROOT", "/"))


def hp(rel: str) -> Path:
    return host_root() / rel


def unit_dir() -> Path:
    return Path(os.environ.get("SYSTEMD_UNIT_DIR", "/etc/systemd/system"))


def vm_root() -> Path:
    return Path(os.environ.get("VM_ROOT", "/srv/cathedral-vms"))


def enforced() -> bool:
    """The VM host switch: without it no admission runs and nothing changes for the kits."""
    return hp(SWITCH).exists()


@contextlib.contextmanager
def capacity_lock(wait: float | None = None):
    path = hp(LOCK)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    deadline = time.monotonic() + (LOCK_WAIT if wait is None else wait)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise CapacityBusy(f"{path} is held by another create, start or kit install") from None
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)  # drops the flock


# ---- env files ---------------------------------------------------------------------

ASSIGN_RE = re.compile(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)")
PLAIN_RE = re.compile(r"[A-Za-z0-9_./:@%+,=-]*")


def shell_value(raw: str) -> str | None:
    """The literal value of one assignment, or None when only a shell could read it."""
    if len(raw) >= 2 and raw[0] == raw[-1] == "'" and "'" not in raw[1:-1]:
        return raw[1:-1]
    if len(raw) >= 2 and raw[0] == raw[-1] == '"' and not re.search(r'[$`\\"]', raw[1:-1]):
        return raw[1:-1]
    if PLAIN_RE.fullmatch(raw):
        return raw
    return None


def parse_env(text: str) -> dict[str, str | None]:
    """KEY=value lines as sealed.env and vm.env hold them. A line that is not blank, a comment or an
    assignment could set anything when the file is sourced, so it makes the whole file unreadable."""
    env: dict[str, str | None] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = ASSIGN_RE.fullmatch(line)
        if not m:
            raise ValueError("a line is not KEY=value")
        env[m.group(1)] = shell_value(m.group(2))
    return env


def env_int(env: dict, key: str, default: int | None = None) -> int | None:
    """A decimal integer; unset or empty gives the default (None: required)."""
    if key not in env or env[key] == "":
        if default is None:
            raise ValueError(f"{key} is not set")
        return default
    v = env[key]
    if v is None or not re.fullmatch(r"[0-9]{1,7}", v):
        raise ValueError(f"{key} is not a decimal integer")
    return int(v)


# ---- kits ----------------------------------------------------------------------------

@dataclass
class Kit:
    name: str
    source: str  # unit, record, or both
    env: str
    dirs: list[str]
    vcpus: int
    mem_gib: int
    scratch_gib: int
    data_gib: int
    min_free_gib: int  # SEALED_MIN_HOST_FREE_GIB, -1 when the env does not set it
    unit: str | None = None
    active: bool = False
    # [st_dev, st_ino] of the data.raw a pending reset will set aside: while data.raw is still that
    # file, it counts as a fresh disk at full size (its blocks stay allocated as data.raw.prev).
    reset_file: list[int] | None = None


def kit_from_env(name: str | None, env_path: str, source: str) -> Kit:
    if not env_path.startswith("/"):
        raise ValueError("the env path is not absolute")
    env = parse_env(Path(env_path).read_text())
    seal_name = env.get("SEALED_NAME")
    if name is None:
        name = seal_name
    elif seal_name not in (None, "", name):
        raise ValueError(f"SEALED_NAME {seal_name!r} is not the unit's name")
    if not name or not KIT_NAME_RE.fullmatch(name):
        raise ValueError("SEALED_NAME is missing or invalid")
    sealed_dir = env.get("SEALED_DIR")
    if not sealed_dir or not sealed_dir.startswith("/"):
        raise ValueError("SEALED_DIR is not an absolute literal path")
    return Kit(name=name, source=source, env=env_path, dirs=[sealed_dir],
               vcpus=env_int(env, "SEALED_VCPUS"), mem_gib=env_int(env, "SEALED_MEM_GIB"),
               scratch_gib=env_int(env, "SEALED_SCRATCH_GIB"), data_gib=env_int(env, "SEALED_DATA_GIB", 0),
               min_free_gib=env_int(env, "SEALED_MIN_HOST_FREE_GIB", -1))


def exec_start(text: str) -> list[str]:
    lines = [m.group(1).strip() for m in re.finditer(r"^\s*ExecStart\s*=(.*)$", text, re.M)]
    lines = [l for l in lines if l]
    if len(lines) != 1:
        raise ValueError(f"{len(lines)} ExecStart lines, need exactly one")
    return lines[0].lstrip("@-:+!").split()


def runs_launcher(argv: list[str]) -> bool:
    return bool(argv) and argv[0].rsplit("/", 1)[-1] == "launch-guest.sh"


def is_net_helper(name: str, text: str) -> bool:
    """Exactly the -net check unit write-units.sh writes: room-sealed-<X>-net.service, oneshot,
    one ExecStart `<dir>/host-net.sh check <env>`. A damaged unit with that name is not one."""
    if not name.endswith("-net.service") or not re.search(r"^\s*Type\s*=\s*oneshot\s*$", text, re.M):
        return False
    try:
        argv = exec_start(text)
    except ValueError:
        return False
    return (len(argv) == 3 and argv[0].startswith("/") and argv[0].rsplit("/", 1)[-1] == "host-net.sh"
            and argv[1] == "check" and argv[2].startswith("/"))


def kit_units() -> tuple[list[Kit], list[dict]]:
    kits, bad = [], []
    if not unit_dir().is_dir():
        return kits, bad
    for path in sorted(unit_dir().glob("room-sealed-*.service")):
        name = path.name[len("room-sealed-"):-len(".service")]
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError) as e:
            bad.append({"unit": path.name, "name": name, "detail": f"unit file unreadable: {type(e).__name__}"})
            continue
        # Skipped only when it is exactly a -net check unit. A kit whose own name ends in -net has
        # the same file name pattern, and a damaged unit of either kind is a kit that must parse.
        if is_net_helper(path.name, text):
            continue
        try:
            argv = exec_start(text)
            if not runs_launcher(argv) or len(argv) != 2:
                raise ValueError("ExecStart is not '<SEALED_DIR>/launch-guest.sh <env file>'")
            if not KIT_NAME_RE.fullmatch(name):
                raise ValueError("the unit name is not a kit name")
            kit = kit_from_env(name, argv[1], "unit")
        except (OSError, UnicodeDecodeError, ValueError) as e:
            detail = str(e) if isinstance(e, ValueError) else f"env file unreadable: {type(e).__name__}"
            bad.append({"unit": path.name, "name": name, "detail": detail})
            continue
        kit.unit = path.name
        kits.append(kit)
    return kits, bad


def kit_records() -> tuple[list[Kit], list[dict]]:
    kits, bad = [], []
    d = hp(KIT_RECORDS)
    if not d.is_dir():
        return kits, bad
    for path in sorted(d.glob("*.json")):
        name = path.stem
        try:
            rec = json.loads(path.read_text())
            ints = ("vcpus", "mem_gib", "scratch_gib", "data_gib")
            dirs = rec.get("sealed_dirs") if isinstance(rec, dict) else None
            reset = rec.get("data_reset_file") if isinstance(rec, dict) else None
            if (not isinstance(rec, dict) or rec.get("schema") != RECORD_SCHEMA or rec.get("name") != name
                    or not KIT_NAME_RE.fullmatch(name)
                    or not all(isinstance(rec.get(k), int) and not isinstance(rec.get(k), bool) and rec[k] >= 0
                               for k in ints)
                    or not isinstance(dirs, list) or not dirs
                    or not all(isinstance(d, str) and d.startswith("/") for d in dirs)
                    or not (reset is None or (isinstance(reset, list) and len(reset) == 2
                                              and all(isinstance(x, int) for x in reset)))
                    or not (rec.get("min_host_free_gib") is None or isinstance(rec["min_host_free_gib"], int))):
                raise ValueError("not a kit reservation record")
        except (OSError, UnicodeDecodeError, ValueError) as e:
            bad.append({"record": str(path), "name": name, "detail": str(e) if isinstance(e, ValueError)
                        else f"record unreadable: {type(e).__name__}"})
            continue
        kits.append(Kit(name=name, source="record", env=str(rec.get("env", "")), dirs=sorted(set(dirs)),
                        vcpus=rec["vcpus"], mem_gib=rec["mem_gib"], scratch_gib=rec["scratch_gib"],
                        data_gib=rec["data_gib"],
                        min_free_gib=-1 if rec.get("min_host_free_gib") is None else rec["min_host_free_gib"],
                        reset_file=reset))
    return kits, bad


def merge_kit(into: Kit, other: Kit) -> None:
    """Union by name: a roll's record may be larger or smaller than the installed env; take the larger."""
    if into.source != other.source:
        into.source = "unit+record"
    into.vcpus, into.mem_gib = max(into.vcpus, other.vcpus), max(into.mem_gib, other.mem_gib)
    into.scratch_gib, into.data_gib = max(into.scratch_gib, other.scratch_gib), max(into.data_gib, other.data_gib)
    into.min_free_gib = max(into.min_free_gib, other.min_free_gib)
    into.dirs = sorted(set(into.dirs) | set(other.dirs))
    into.unit = into.unit or other.unit
    into.reset_file = into.reset_file or other.reset_file


# ---- VMs -------------------------------------------------------------------------------

@dataclass
class VM:
    name: str
    vcpus: int
    mem_gib: int
    disk_gib: int
    dir: str
    active: bool = False
    enabled: bool = False
    state_known: bool = False

    @property
    def disk(self) -> Path:
        d = Path(self.dir)
        # root.raw is the v2 disk (VM spec r2 7.1); disk.qcow2 the v1 overlay it replaces.
        return d / "root.raw" if (d / "root.raw").exists() or not (d / "disk.qcow2").exists() else d / "disk.qcow2"


def vm_list() -> tuple[list[VM], list[dict]]:
    vms, bad = [], []
    if not vm_root().is_dir():
        return vms, bad
    for d in sorted(vm_root().iterdir()):
        if not VM_NAME_RE.fullmatch(d.name) or d.is_symlink() or not (d / "vm.env").is_file():
            continue
        try:
            env = parse_env((d / "vm.env").read_text())
            vms.append(VM(name=d.name, vcpus=env_int(env, "VM_VCPUS"), mem_gib=env_int(env, "VM_MEM_GIB"),
                          disk_gib=env_int(env, "VM_DISK_GIB"), dir=str(d)))
        except (OSError, UnicodeDecodeError, ValueError) as e:
            bad.append({"vm": d.name, "detail": str(e) if isinstance(e, ValueError) else type(e).__name__})
    return vms, bad


# ---- systemd -----------------------------------------------------------------------------

def unit_state(unit: str) -> tuple[bool, bool] | None:
    """(active, enabled), or None when systemd did not answer."""
    try:
        p = subprocess.run(["systemctl", "show", "-p", "ActiveState", "-p", "UnitFileState", unit],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    props = dict(l.split("=", 1) for l in p.stdout.splitlines() if "=" in l)
    if p.returncode != 0 or "ActiveState" not in props:
        return None
    return props["ActiveState"] in ACTIVE_STATES, props.get("UnitFileState", "").startswith(("enabled", "linked"))


# ---- host figures ---------------------------------------------------------------------------

@dataclass
class Host:
    mem_total_kib: int | None
    mem_available_kib: int | None
    threads: int | None
    asid_capacity: int
    asid_current: int | None


def read_text(rel: str) -> str | None:
    try:
        return hp(rel).read_text()
    except (OSError, UnicodeDecodeError):
        return None


def misc_value(text: str | None, key: str) -> int | None:
    """One key of a cgroup misc flat-keyed file (scripts/snp_host_check.py parse_misc_capacity)."""
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == key and parts[1].isdigit():
            return int(parts[1])
    return None


def host_facts() -> Host:
    mem = {}
    for line in (read_text("proc/meminfo") or "").splitlines():
        m = re.fullmatch(r"(\w+):\s+([0-9]+) kB", line.strip())
        if m:
            mem[m.group(1)] = int(m.group(2))
    cpuinfo = read_text("proc/cpuinfo")
    threads = len(re.findall(r"^processor\s*:", cpuinfo, re.M)) if cpuinfo else None
    # SNP guests draw from the SEV-ES ASID range (scripts/snp_host_check.py).
    capacity = misc_value(read_text("sys/fs/cgroup/misc.capacity"), "sev_es")
    return Host(mem_total_kib=mem.get("MemTotal"), mem_available_kib=mem.get("MemAvailable"),
                threads=threads or None, asid_capacity=capacity or 0,
                asid_current=misc_value(read_text("sys/fs/cgroup/misc.current"), "sev_es"))


# ---- disk ---------------------------------------------------------------------------------------

def existing(path: Path) -> Path:
    p = path
    while not p.exists() and p.parent != p:
        p = p.parent
    return p


def device_of(path: Path) -> int:
    """The file system a path is (or will be) on: its own device, or its nearest existing parent's."""
    return os.stat(existing(path)).st_dev


def fs_avail(path: Path) -> int:
    """Bytes available to an unprivileged writer, as `df --output=avail` (install-sealed.sh)."""
    st = os.statvfs(existing(path))
    return st.f_bavail * st.f_frsize


def file_facts(path: Path) -> tuple[int, int, int, int] | None:
    """(size, allocated bytes, st_dev, st_ino), or None when the file does not exist."""
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    return st.st_size, st.st_blocks * 512, st.st_dev, st.st_ino


def growth(path: Path, logical: int) -> int:
    """Remaining growth of a sparse file: its full size less what is allocated now."""
    facts = file_facts(path)
    if facts is None:
        return logical
    return max(0, max(logical, facts[0]) - facts[1])


@dataclass
class Sparse:
    path: Path
    logical: int
    owner: str
    fresh: bool = False  # replaced by a new empty file before it is written: grows by its full size

    def remaining(self) -> int:
        return self.logical if self.fresh else growth(self.path, self.logical)


# ---- the ledger ----------------------------------------------------------------------------------

@dataclass
class Ledger:
    kits: list[Kit]
    unaccounted: list[dict]
    vms: list[VM]
    vm_unaccounted: list[dict]
    host: Host
    overhead_kib: int = field(default_factory=lambda: GUEST_OVERHEAD_MIB * KIB_PER_MIB)

    def sparse_files(self) -> list[Sparse]:
        files = []
        for k in self.kits:
            for d in k.dirs:
                files.append(Sparse(Path(d) / "scratch.raw", k.scratch_gib * GIB, f"kit:{k.name}"))
                data = Path(d) / "data.raw"
                facts = file_facts(data)
                if k.data_gib or facts is not None:
                    # A reset pending on this very file keeps its blocks (as data.raw.prev) and adds
                    # a fresh volume at full size.
                    fresh = (k.reset_file is not None and facts is not None
                             and [facts[2], facts[3]] == list(k.reset_file))
                    files.append(Sparse(data, k.data_gib * GIB, f"kit:{k.name}", fresh=fresh))
                prev = Path(d) / "data.raw.prev"
                if file_facts(prev) is not None:
                    # Set aside by a reset roll: kept until the operator removes it, and restored
                    # as data.raw when the roll is not confirmed, so its own growth stays reserved.
                    files.append(Sparse(prev, 0, f"kit:{k.name}"))
        for v in self.vms:
            files.append(Sparse(v.disk, v.disk_gib * GIB, f"vm:{v.name}"))
        return files

    def reserve_bytes(self, dev: int) -> int:
        """A file system's disk reserve: the largest SEALED_MIN_HOST_FREE_GIB of a kit on it, and the
        VM floor."""
        gib = VM_MIN_HOST_FREE_GIB
        for k in self.kits:
            if k.min_free_gib > gib and any(device_of(Path(d)) == dev for d in k.dirs):
                gib = k.min_free_gib
        return gib * GIB

    def fs_left(self, path: Path, extra: int = 0) -> tuple[int, int, int, int]:
        """(left, avail, growth, reserve) in bytes for the file system of path, less extra bytes."""
        dev = device_of(path)
        grow = sum(f.remaining() for f in self.sparse_files() if device_of(f.path) == dev)
        avail, reserve = fs_avail(path), self.reserve_bytes(dev)
        return avail - grow - extra - reserve, avail, grow, reserve

    def mem_commit_kib(self) -> int:
        kits = sum(k.mem_gib * KIB_PER_GIB + self.overhead_kib for k in self.kits)
        vms = sum(v.mem_gib * KIB_PER_GIB + self.overhead_kib for v in self.vms)
        return kits + vms + MEM_RESERVE_GIB * KIB_PER_GIB

    def refuse_unaccounted(self, skip_kit: str | None = None) -> None:
        bad = [b for b in self.unaccounted if b.get("name") != skip_kit]
        if bad:
            first = bad[0]
            raise CapacityRefusal("kit_unaccounted", f"{first.get('unit') or first.get('record')}: {first['detail']}")
        if self.vm_unaccounted:
            first = self.vm_unaccounted[0]
            raise CapacityRefusal("vm_unaccounted", f"VM {first['vm']}: {first['detail']}")


def snapshot(states: bool = False) -> Ledger:
    unit_kits, bad = kit_units()
    record_kits, bad_records = kit_records()
    merged: dict[str, Kit] = {}
    for k in unit_kits + record_kits:
        if k.name in merged:
            merge_kit(merged[k.name], k)
        else:
            merged[k.name] = k
    vms, bad_vms = vm_list()
    led = Ledger(kits=list(merged.values()), unaccounted=bad + bad_records, vms=vms, vm_unaccounted=bad_vms,
                 host=host_facts())
    if states:
        for k in led.kits:
            # Unknown counts as stopped: a stopped kit keeps its ASID reserved, the larger count.
            st = unit_state(k.unit) if k.unit else None
            k.active = bool(st and st[0])
        for v in led.vms:
            # Unknown counts as live for the others: it may hold memory and an ASID.
            st = unit_state(f"cathedral-vm-{v.name}.service")
            v.state_known = st is not None
            v.active, v.enabled = (True, True) if st is None else st
    return led


def gib(kib_or_bytes: int, unit: int) -> str:
    return f"{kib_or_bytes / unit:.1f} GiB"


def check_create(vcpus: int, mem_gib: int, disk_gib: int, vm_dir: Path) -> None:
    """Commit rules for one new VM. Raises CapacityRefusal. Caller holds the capacity lock."""
    led = snapshot()
    led.refuse_unaccounted()
    h = led.host
    need = led.mem_commit_kib() + mem_gib * KIB_PER_GIB + led.overhead_kib
    if h.mem_total_kib is None:
        raise CapacityRefusal("memory", "MemTotal unreadable")
    if need > h.mem_total_kib:
        raise CapacityRefusal("memory", f"kits, VMs, overhead and reserve with this VM need {gib(need, KIB_PER_GIB)}"
                                        f" of MemTotal {gib(h.mem_total_kib, KIB_PER_GIB)}")
    left, avail, grow, reserve = led.fs_left(vm_dir, disk_gib * GIB)
    if left < 0:
        raise CapacityRefusal("disk", f"avail {gib(avail, GIB)} less sparse growth {gib(grow, GIB)} less"
                                      f" {disk_gib} GiB is under the {gib(reserve, GIB)} reserve")
    asids = len(led.kits) + len(led.vms) + 1
    if asids > h.asid_capacity:
        raise CapacityRefusal("asid", f"{len(led.kits)} kit(s) and {len(led.vms) + 1} VM(s) need {asids}"
                                      f" SNP ASIDs, misc.capacity sev_es is {h.asid_capacity}")
    if h.threads is None:
        raise CapacityRefusal("vcpu", "/proc/cpuinfo unreadable")
    cpus = sum(k.vcpus for k in led.kits) + sum(v.vcpus for v in led.vms) + vcpus
    if cpus > h.threads - HOST_THREADS:
        raise CapacityRefusal("vcpu", f"kits and VMs with this VM need {cpus} vCPUs, the limit is"
                                      f" {h.threads} threads less {HOST_THREADS}")


def check_start(name: str) -> None:
    """Live rules for starting VM `name`. Raises CapacityRefusal. Caller holds the capacity lock."""
    led = snapshot(states=True)
    me = next((v for v in led.vms if v.name == name), None)
    if me is None:
        raise CapacityRefusal("vm_unaccounted", f"VM {name} is not in the ledger")
    if me.state_known and me.active:
        return  # a repeated start of a running VM: it already holds what it needs
    led.refuse_unaccounted()
    h = led.host
    need = me.mem_gib * KIB_PER_GIB + led.overhead_kib + MEM_RESERVE_GIB * KIB_PER_GIB
    if h.mem_available_kib is None:
        raise CapacityRefusal("memory", "MemAvailable unreadable")
    if h.mem_available_kib < need:
        raise CapacityRefusal("memory", f"MemAvailable {gib(h.mem_available_kib, KIB_PER_GIB)} is under"
                                        f" {gib(need, KIB_PER_GIB)} (guest, overhead and reserve)")
    left, avail, grow, reserve = led.fs_left(me.disk)
    if left < 0:
        raise CapacityRefusal("disk", f"avail {gib(avail, GIB)} less sparse growth {gib(grow, GIB)} is under"
                                      f" the {gib(reserve, GIB)} reserve")
    if h.asid_current is None:
        raise CapacityRefusal("asid", "misc.current sev_es unreadable")
    running = sum(k.active for k in led.kits) + sum(v.active or v.enabled for v in led.vms if v is not me)
    stopped_kits = sum(not k.active for k in led.kits)
    used = max(h.asid_current, running) + stopped_kits + 1
    if used > h.asid_capacity:
        raise CapacityRefusal("asid", f"{max(h.asid_current, running)} in use, {stopped_kits} kept for stopped kits,"
                                      f" plus this VM is {used} of {h.asid_capacity} SNP ASIDs")


# ---- custom-guest hosts (dedicated spec r9 5.1, 5.2) ---------------------------------------------

def custom_guest_reasons() -> list[str]:
    """A dedicated custom-guest host never takes a VM: an allow file, a hold marker or a launch folder."""
    reasons = []
    if hp(CUSTOM_GUEST_ALLOW).exists() or hp(CUSTOM_GUEST_ALLOW).is_symlink():
        reasons.append(f"{CUSTOM_GUEST_ALLOW} exists")
    dirs = {Path(d) for k in kit_units()[0] + kit_records()[0] for d in k.dirs}
    dirs |= set(hp("srv").glob("sealed-hotel-*"))  # the dedicated spec's SEALED_DIR layout
    for d in sorted(dirs):
        if (d / "custom-guest.hold").exists():
            reasons.append(f"hold marker {d / 'custom-guest.hold'}")
    for pattern in ("*/cg-*", "*/inbox/cg-*", "*/staging/cg-*"):
        for p in sorted(hp(CUSTOM_GUEST_ROOT).glob(pattern)):
            if p.is_dir():
                reasons.append(f"launch folder {p}")
    return reasons


def refuse_custom_guest_host() -> None:
    reasons = custom_guest_reasons()
    if reasons:
        raise CapacityRefusal("custom_guest_host", "; ".join(reasons))


# ---- install-sealed.sh assess step ----------------------------------------------------------------

def write_atomic(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def kit_record(kit: Kit) -> dict:
    return {"schema": RECORD_SCHEMA, "name": kit.name, "env": kit.env, "sealed_dirs": list(kit.dirs),
            "vcpus": kit.vcpus, "mem_gib": kit.mem_gib, "scratch_gib": kit.scratch_gib, "data_gib": kit.data_gib,
            "min_host_free_gib": None if kit.min_free_gib < 0 else kit.min_free_gib,
            "data_reset_file": kit.reset_file, "recorded_at": int(time.time())}


def assess_kit(env_path: str, data_reset: bool = False) -> dict:
    """The kit's disk and memory checks with every VM and every other kit counted, then its record.

    Under the capacity lock, so a VM create cannot take the room between this check and the unit
    that install-sealed.sh writes after the 10 to 20 minute build. The record is the larger of the
    replacement, the installed env and any earlier record: the running guest keeps its size until
    commit_kit sees the new one verified, so a roll that stops after the env copy (a refused or
    failed restart) never releases it.

    data_reset: install-sealed.sh is about to move data.raw aside as data.raw.prev and start an
    empty one. Both are reserved from here: the current file stays allocated, the new one grows to
    its full size."""
    new = kit_from_env(None, os.path.abspath(env_path), "record")
    with capacity_lock():
        led = snapshot()
        led.refuse_unaccounted(skip_kit=new.name)
        check = Kit(**{**new.__dict__, "dirs": list(new.dirs)})
        for k in led.kits:
            if k.name == new.name:
                merge_kit(check, k)  # the installed env and the earlier record, already merged by name
        check.source = "record"
        if data_reset:
            facts = file_facts(Path(new.dirs[0]) / "data.raw")
            if facts is not None:
                check.reset_file = [facts[2], facts[3]]
        led.kits = [k for k in led.kits if k.name != new.name] + [check]
        h = led.host
        if h.mem_total_kib is None:
            raise CapacityRefusal("memory", "MemTotal unreadable")
        if led.mem_commit_kib() > h.mem_total_kib:
            raise CapacityRefusal("memory", f"kits, VMs, overhead and reserve need {gib(led.mem_commit_kib(), KIB_PER_GIB)}"
                                            f" of MemTotal {gib(h.mem_total_kib, KIB_PER_GIB)}")
        for d in check.dirs:
            left, avail, grow, reserve = led.fs_left(Path(d))
            if left < 0:
                raise CapacityRefusal("disk", f"{d}: avail {gib(avail, GIB)} less the growth of every kit and VM"
                                              f" disk {gib(grow, GIB)} is under the {gib(reserve, GIB)} reserve")
        write_atomic(hp(KIT_RECORDS) / f"{new.name}.json", json.dumps(kit_record(check), sort_keys=True) + "\n")
    return {"kit": new.name, "recorded": True, "vms": len(led.vms), "kits": len(led.kits)}


def commit_kit(env_path: str) -> dict:
    """After install-sealed.sh verified the new guest running (its measurement matched): the record
    becomes exactly the installed env, so a smaller roll gives its room back. data.raw.prev, if the
    roll reset the data volume, is counted from the file until the operator removes it."""
    kit = kit_from_env(None, os.path.abspath(env_path), "record")
    with capacity_lock():
        write_atomic(hp(KIT_RECORDS) / f"{kit.name}.json", json.dumps(kit_record(kit), sort_keys=True) + "\n")
    return {"kit": kit.name, "committed": True}


# ---- the capacity read ------------------------------------------------------------------------------

def mib(n_bytes: int) -> int:
    return n_bytes // MIB


def report(broker: dict[str, int] | None = None) -> dict:
    """Everything the ledger sees, the VM share left after the kits, and the broker config check."""
    led = snapshot(states=True)
    h = led.host
    kits_mem = sum(k.mem_gib * KIB_PER_GIB + led.overhead_kib for k in led.kits)
    kits_cpu = sum(k.vcpus for k in led.kits)
    by_dev: dict[int, list[Sparse]] = {}
    for f in led.sparse_files():
        by_dev.setdefault(device_of(f.path), []).append(f)
    vm_dev = device_of(vm_root())
    by_dev.setdefault(vm_dev, [])
    filesystems = []
    vm_disk_share = None
    for dev, files in sorted(by_dev.items()):
        probe = files[0].path if files else vm_root()
        avail, reserve = fs_avail(probe), led.reserve_bytes(dev)
        grow = sum(f.remaining() for f in files)
        filesystems.append({"device": dev, "avail_mib": mib(avail), "growth_mib": mib(grow),
                            "reserve_mib": mib(reserve), "left_mib": mib(avail - grow - reserve),
                            "files": [{"path": str(f.path), "owner": f.owner,
                                       "growth_mib": mib(f.remaining())} for f in files]})
        if dev == vm_dev:
            # All VM disks together, at full size, as the broker counts them: what is free now, less the
            # kits' growth and the reserve, plus what the VMs already hold.
            vm_held = sum(v.disk_gib * GIB - growth(v.disk, v.disk_gib * GIB) for v in led.vms
                          if device_of(v.disk) == dev)
            kit_grow = sum(f.remaining() for f in files if f.owner.startswith("kit:"))
            vm_disk_share = (avail - kit_grow - reserve + vm_held) // GIB
    share = {
        "vcpus": None if h.threads is None else h.threads - HOST_THREADS - kits_cpu,
        "mem_gib": None if h.mem_total_kib is None
        else (h.mem_total_kib - MEM_RESERVE_GIB * KIB_PER_GIB - kits_mem) // KIB_PER_GIB,
        "asids": h.asid_capacity - len(led.kits),
        "disk_gib": vm_disk_share,
    }
    out = {
        "enforced": enforced(),
        "host": {"mem_total_mib": None if h.mem_total_kib is None else h.mem_total_kib // KIB_PER_MIB,
                 "mem_available_mib": None if h.mem_available_kib is None else h.mem_available_kib // KIB_PER_MIB,
                 "threads": h.threads, "asid_capacity": h.asid_capacity, "asid_current": h.asid_current},
        "rules": {"mem_reserve_gib": MEM_RESERVE_GIB, "guest_overhead_mib": GUEST_OVERHEAD_MIB,
                  "host_threads": HOST_THREADS, "vm_min_host_free_gib": VM_MIN_HOST_FREE_GIB},
        "kits": [{"name": k.name, "source": k.source, "unit": k.unit, "env": k.env, "dirs": k.dirs,
                  "vcpus": k.vcpus, "mem_gib": k.mem_gib, "scratch_gib": k.scratch_gib, "data_gib": k.data_gib,
                  "active": k.active} for k in led.kits],
        "unaccounted": led.unaccounted + led.vm_unaccounted,
        "vms": [{"name": v.name, "vcpus": v.vcpus, "mem_gib": v.mem_gib, "disk_gib": v.disk_gib,
                 "active": v.active, "enabled": v.enabled} for v in led.vms],
        "commit": {"mem_mib": led.mem_commit_kib() // KIB_PER_MIB,
                   "vcpus": kits_cpu + sum(v.vcpus for v in led.vms),
                   "asids": len(led.kits) + len(led.vms)},
        "filesystems": filesystems,
        "vm_share": share,
        "custom_guest_host": custom_guest_reasons(),
    }
    if broker:
        over = []
        if "max_vcpus" in broker and (share["vcpus"] is None or broker["max_vcpus"] > share["vcpus"]):
            over.append("max_vcpus")
        if "max_mem_gib" in broker:
            # Each VM adds the overhead too; at most one VM per ASID and per vCPU.
            most_vms = max(0, min(share["asids"], broker.get("max_vcpus", share["asids"])))
            need = broker["max_mem_gib"] + -(-most_vms * GUEST_OVERHEAD_MIB // 1024)
            if share["mem_gib"] is None or need > share["mem_gib"]:
                over.append("max_mem_gib")
        if "max_disk_gib" in broker and (share["disk_gib"] is None or broker["max_disk_gib"] > share["disk_gib"]):
            over.append("max_disk_gib")
        out["broker_check"] = {"ok": not over, "over": over, "config": broker}
    return out


def main(argv: list[str]) -> int:
    cmd, args = (argv[0], argv[1:]) if argv else ("", [])
    reset = cmd == "assess-kit" and args[:1] == ["--data-reset"]
    if reset:
        args = args[1:]
    if cmd not in ("assess-kit", "commit-kit") or len(args) != 1:
        print("usage: vm_capacity.py assess-kit [--data-reset] <sealed.env> | commit-kit <sealed.env>"
              "   (the read is vm-ctl.sh capacity)", file=sys.stderr)
        return 2
    try:
        res = assess_kit(args[0], data_reset=reset) if cmd == "assess-kit" else commit_kit(args[0])
    except CapacityRefusal as e:
        print(f"sealed: VM host ledger: not enough {e.resource}: {e.detail}", file=sys.stderr)
        return 1
    except CapacityBusy as e:
        print(f"sealed: VM host ledger busy: {e}", file=sys.stderr)
        return 1
    except (OSError, UnicodeDecodeError, ValueError) as e:
        print(f"sealed: VM host ledger: cannot read {args[0]}: {e}", file=sys.stderr)
        return 1
    if cmd == "commit-kit":
        print(f"[sealed] VM host ledger: {res['kit']} recorded at its installed size")
    else:
        what = "with a fresh data volume next to data.raw.prev" if reset else f"with {res['vms']} VM(s) and {res['kits']} kit(s)"
        print(f"[sealed] VM host ledger: room for {res['kit']} {what}; recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
