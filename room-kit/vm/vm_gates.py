#!/usr/bin/env python3
"""Pre-launch gates and the host change gate for sealed customer VMs (AB#999, VM runtime spec r2 8.3).

  vm-gates.sh check <name>          every gate for VM <name>: exit 0, or the refusing gate's code
  vm-gates.sh enforce               the enforce tick: SEV status against the baseline
  vm-gates.sh status                print the SEV status and its digest (read only), to verify
  vm-gates.sh baseline --expect <digest> [--replace]
                                    record the verified status as the baseline (operator)
  vm-gates.sh host-build            print this host's build (read only), for the verified list

Every command prints one JSON line on stdout. A refusal also prints one line,
"vm-gates: <error>: <reason>", on stderr, which the unit's journal keeps.

`check` runs as root in two places: in `vm-ctl.sh start` before the run's start line (#765), so a
refused start leaves no start line and bills nothing, and as the unit's `ExecStartPre=+`, so a host
boot, a crash restart and a guest reboot (a relaunch, spec 8.1) pass the same gates. The gates run
in this order and the first refusal ends the check (exit code, error):

  10 vm_invalid             no such VM, or its vm.env has no valid VM_NAME, VM_BUNDLE or VM_VCPUS
  11 vm_host_not_enabled    the host file is missing, unsafe or invalid: this host runs no sealed VM
  12 vm_bundle_not_enabled  the VM's bundle is not in the host file's `bundles`
  14 vm_host_changed        this host's QEMU binary (sha256) and kernel release, with the VM's vCPU
                            count, are not a verified build of the bundle, and the VM is no canary
  15 sev_baseline_missing   no SEV baseline, or it is unsafe or invalid
  16 sev_status_unreadable  /dev/sev did not answer the status commands
  17 sev_platform_changed   the SEV status differs from the baseline now, or did earlier in this boot
  18 sev_state_unavailable  this boot's SEV state cannot be held or kept (lock busy, /run unsafe or
                            not writable), or the boot is not armed: a change was seen and its
                            record was lost, so only a reboot or an accept ends it
  13 vm_bundle_mismatch     manifest.json is not the bundle id, or a bundle file is missing or differs
                            from the size or sha256 the manifest names (read last: it is the slow one)
   1 internal error, 2 usage. Every failure refuses: no gate has a fallback.

`enforce` (spec 5, D 5.9 extended) runs on the enforce tick. It compares only the SEV status and never
starts or stops a unit: a change refuses new starts, and running VMs are left alone, because stopping
every customer on the host would be the bigger harm. Exit 0 when equal, or "off" when the host file is
absent; else 15 to 18 as above.

SEV state per boot (in /run, a tmpfs, so a reboot clears it). The first compare of a boot creates the
armed token and the boot record; a boot is armed once. A change renames the token to the changed
marker, or else unlinks it; neither needs free space, so a full disk cannot lose the change. The
detail is then written over the marker and, when the boot id is known, to a durable copy in /var/lib.
A start passes only while the token exists, no marker and no durable copy for this boot exists, and
the status equals the baseline; a boot record without a token refuses (18). So a status that flips
back still refuses, until a host reboot with a status equal to the baseline (the D 5.9 recovery) or
the operator's explicit accept, `baseline --replace --expect <digest>`. That records the status only if
its digest is the one the operator verified (`status`), clears this boot's change and arms the boot
again. Baseline reads, compares, state writes and the replace all run under one flock.

Files (VM_GATES_ROOT prefixes the host paths, for tests; VM_ROOT as vm_ctl.py):
  /etc/cathedral/snp-vm-host.json              host file: `bundles` (read by the launcher too),
                                               `verified` and `canary_vms` (read only here)
  /var/lib/cathedral-snp/vm-sev-baseline.json  `sev_status.py read` output; `sev_status.py compare`
                                               reads the same file
  /run/cathedral-snp/vm-sev-armed              the armed token of this boot
  /run/cathedral-snp/vm-sev-boot               the boot record: this boot was armed once
  /run/cathedral-snp/vm-sev-changed.json       the changed marker: boot_id, time and differences
  /var/lib/cathedral-snp/vm-sev-changed.json   its durable copy, written only with a known boot id
  /run/lock/cathedral-vm-sev.lock              the SEV state lock
  $VM_ROOT/<name>/vm.env, $VM_ROOT/bundles/<id>/manifest.json and the files it names

These gates do not protect a guest from a host that lies: the launch measurement, the init's identity
check and dm-verity do. The gates refuse early, with a reason and before anything is billed, and keep
a changed host from starting VMs that were verified on another build.
"""
from __future__ import annotations

import contextlib
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

KIT = Path(__file__).resolve().parent
# The D 5.9 SEV status tool of the dedicated custom guest (#780). One reader and one compare
# serve both products; this file adds no field list of its own.
SEV_TOOL = KIT.parent.parent / "ops" / "custom-guest" / "sev_status.py"

HOST_FILE = "etc/cathedral/snp-vm-host.json"
BASELINE = "var/lib/cathedral-snp/vm-sev-baseline.json"
SEV_STATE = "run/cathedral-snp"
ARMED = SEV_STATE + "/vm-sev-armed"
BOOTED = SEV_STATE + "/vm-sev-boot"
CHANGED = SEV_STATE + "/vm-sev-changed.json"
DURABLE_CHANGED = "var/lib/cathedral-snp/vm-sev-changed.json"
SEV_LOCK = "run/lock/cathedral-vm-sev.lock"
SEV_LOCK_WAIT = 30.0
BOOT_ID = "proc/sys/kernel/random/boot_id"
OSRELEASE = "proc/sys/kernel/osrelease"
SEV_DEVICE = "dev/sev"
# The binary the launcher runs (snp_qemu.QEMU). Its sha256 pins its version, so `check` never
# runs a QEMU binary as root to ask for one.
QEMU = "usr/bin/qemu-system-x86_64"

EXIT = {
    "vm_invalid": 10,
    "vm_host_not_enabled": 11,
    "vm_bundle_not_enabled": 12,
    "vm_bundle_mismatch": 13,
    "vm_host_changed": 14,
    "sev_baseline_missing": 15,
    "sev_status_unreadable": 16,
    "sev_platform_changed": 17,
    "sev_state_unavailable": 18,
}
EXIT_INTERNAL, EXIT_USAGE = 1, 2

NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")  # vm_ctl.py NAME_RE
HEX64_RE = re.compile(r"[0-9a-f]{64}")
ENV_LINE_RE = re.compile(r"([A-Z][A-Z0-9_]*)='([^']*)'")  # what vm_ctl.py create writes
BUNDLE_FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
VERSION_RE = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
RELEASE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}")
BUILD_FIELDS = frozenset({"qemu_sha256", "qemu_version", "kernel_release", "vcpus"})
VCPUS_MAX = 64  # vm_ctl.py create and the broker
DOC_MAX = 65536


class GateRefusal(Exception):
    def __init__(self, error: str, detail: str):
        self.error, self.code = error, EXIT[error]
        self.detail = " ".join(str(detail).split())[:400]  # one line, for the journal
        super().__init__(f"{error}: {self.detail}")


class UsageError(Exception):
    def __init__(self, error: str, detail: str):
        super().__init__(detail)
        self.error, self.detail = error, detail


def host_root() -> Path:
    return Path(os.environ.get("VM_GATES_ROOT", "/"))


def hp(rel: str) -> Path:
    return host_root() / rel


def vm_root() -> Path:
    return Path(os.environ.get("VM_ROOT", "/srv/cathedral-vms"))


# ---- files ---------------------------------------------------------------------------------

def read_protected(path: Path, error: str, dir_fd: int | None = None) -> bytes:
    """A regular file, never a link, owned by root and writable by no group or other. A non-root
    writer (a QEMU escape as cvm-<slot>, spec Q10) must not edit what a gate compares against."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except FileNotFoundError:
        raise GateRefusal(error, f"{path} is missing") from None
    except OSError as e:
        raise GateRefusal(error, f"{path}: cannot open ({e.strerror})") from None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid not in (0, os.getuid()) or st.st_mode & 0o022:
            raise GateRefusal(error, f"{path} must be a regular file owned by root, not group or world writable")
        raw = f.read(DOC_MAX + 1)
    if len(raw) > DOC_MAX:
        raise GateRefusal(error, f"{path} is over {DOC_MAX} bytes")
    return raw


def load_object(path: Path, error: str) -> dict:
    raw = read_protected(path, error)
    try:
        doc = json.loads(raw)
    except ValueError:
        raise GateRefusal(error, f"{path} is not JSON") from None
    if not isinstance(doc, dict):
        raise GateRefusal(error, f"{path} is not a JSON object")
    return doc


def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
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


def boot_id() -> str:
    try:
        return hp(BOOT_ID).read_text().strip() or "unknown"
    except OSError:
        return "unknown"


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- gate: the VM -------------------------------------------------------------------------

def vm_of(name: str) -> dict:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise GateRefusal("vm_invalid", "name must match ^[a-z0-9][a-z0-9-]{0,40}$")
    d = vm_root() / name
    if d.is_symlink() or not d.is_dir():
        raise GateRefusal("vm_invalid", f"no VM {name}")
    text = read_protected(d / "vm.env", "vm_invalid").decode("ascii", "replace")
    env = {}
    for line in text.splitlines():
        m = ENV_LINE_RE.fullmatch(line)
        if m:
            env[m.group(1)] = m.group(2)
    if env.get("VM_NAME") != name:
        raise GateRefusal("vm_invalid", f"{d / 'vm.env'} does not name VM {name}")
    bundle = env.get("VM_BUNDLE", "")
    if not HEX64_RE.fullmatch(bundle):
        raise GateRefusal("vm_invalid", f"VM {name} names no sealed bundle (VM_BUNDLE)")
    vcpus = env.get("VM_VCPUS", "")
    if not re.fullmatch(r"[1-9][0-9]?", vcpus) or int(vcpus) > VCPUS_MAX:
        raise GateRefusal("vm_invalid", f"VM {name}: VM_VCPUS must be 1..{VCPUS_MAX}")
    return {"name": name, "bundle": bundle, "vcpus": int(vcpus)}


# ---- gate: the host file ---------------------------------------------------------------------

def valid_build(entry: object) -> bool:
    if not isinstance(entry, dict) or set(entry) != BUILD_FIELDS:
        return False
    vcpus = entry["vcpus"]
    return (isinstance(entry["qemu_sha256"], str) and bool(HEX64_RE.fullmatch(entry["qemu_sha256"]))
            and isinstance(entry["qemu_version"], str) and bool(VERSION_RE.fullmatch(entry["qemu_version"]))
            and isinstance(entry["kernel_release"], str) and bool(RELEASE_RE.fullmatch(entry["kernel_release"]))
            and isinstance(vcpus, list) and bool(vcpus)
            and all(type(n) is int and 1 <= n <= VCPUS_MAX for n in vcpus))


def host_config() -> dict:
    """The host switch (spec 12): absent means every launch refuses. Any part this file cannot
    read refuses the whole host, never only the part."""
    path = hp(HOST_FILE)
    doc = load_object(path, "vm_host_not_enabled")
    bundles = doc.get("bundles")
    if not isinstance(bundles, list) or not all(isinstance(b, str) and HEX64_RE.fullmatch(b) for b in bundles):
        raise GateRefusal("vm_host_not_enabled", f"{path}: bundles must be a list of bundle ids")
    verified = doc.get("verified", {})
    if not isinstance(verified, dict) or not all(
            isinstance(k, str) and HEX64_RE.fullmatch(k) and isinstance(v, list) and all(valid_build(e) for e in v)
            for k, v in verified.items()):
        raise GateRefusal("vm_host_not_enabled",
                          f"{path}: verified must map a bundle id to a list of"
                          f" {{qemu_sha256, qemu_version, kernel_release, vcpus}} builds")
    canary = doc.get("canary_vms", [])
    if not isinstance(canary, list) or not all(isinstance(n, str) and NAME_RE.fullmatch(n) for n in canary):
        raise GateRefusal("vm_host_not_enabled", f"{path}: canary_vms must be a list of VM names")
    return {"bundles": set(bundles), "verified": verified, "canary_vms": set(canary)}


# ---- gate: the host change gate --------------------------------------------------------------

def sha256_stream(f) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    for block in iter(lambda: f.read(1 << 20), b""):
        h.update(block)
        n += len(block)
    return h.hexdigest(), n


def kernel_release() -> str:
    try:
        release = hp(OSRELEASE).read_text().strip()
    except OSError:
        raise GateRefusal("vm_host_changed", "cannot read the kernel release") from None
    if not RELEASE_RE.fullmatch(release):
        raise GateRefusal("vm_host_changed", "the kernel release is not a release name")
    return release


def qemu_sha256() -> str:
    try:
        with open(hp(QEMU), "rb") as f:  # follows a link, as exec does
            return sha256_stream(f)[0]
    except OSError:
        raise GateRefusal("vm_host_changed", f"cannot read {hp(QEMU)}") from None


def host_build_gate(cfg: dict, vm: dict) -> str:
    """Spec 8.3: a host build enters a bundle's verified list only after a canary VM of that bundle
    and vCPU count booted on it and its report matched expected_measurement. A canary VM, listed in
    canary_vms, is the one start allowed on a build that is not verified yet."""
    sha, release = qemu_sha256(), kernel_release()
    for entry in cfg["verified"].get(vm["bundle"], []):
        if entry["qemu_sha256"] == sha and entry["kernel_release"] == release and vm["vcpus"] in entry["vcpus"]:
            return "verified"
    if vm["name"] in cfg["canary_vms"]:
        return "canary"
    raise GateRefusal("vm_host_changed",
                      f"QEMU sha256 {sha[:16]} on kernel {release} with {vm['vcpus']} vCPUs is not a verified"
                      f" build of bundle {vm['bundle'][:16]}")


# ---- gate: SEV status against its baseline ---------------------------------------------------

_sev_tool = None


def sev_tool():
    """ops/custom-guest/sev_status.py, loaded by path: vm-gates.sh runs python3 -I."""
    global _sev_tool
    if _sev_tool is None:
        if not SEV_TOOL.is_file():
            raise GateRefusal("sev_status_unreadable", f"{SEV_TOOL} is missing")
        spec = importlib.util.spec_from_file_location("sev_status", SEV_TOOL)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _sev_tool = mod
    return _sev_tool


def read_sev() -> dict:
    try:
        return sev_tool().read_status(str(hp(SEV_DEVICE)))
    except (OSError, ValueError) as e:
        raise GateRefusal("sev_status_unreadable", str(e)) from None


def sev_baseline() -> dict:
    path = hp(BASELINE)
    doc = load_object(path, "sev_baseline_missing")
    for part, fields in sev_tool().COMPARED.items():
        if not isinstance(doc.get(part), dict) or any(f not in doc[part] for f in fields):
            raise GateRefusal("sev_baseline_missing", f"{path} lacks {part} fields: not `sev_status.py read` output")
    return doc


@contextlib.contextmanager
def sev_lock():
    """One lock for every baseline read, compare, state write and replace."""
    path = hp(SEV_LOCK)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as e:
        raise GateRefusal("sev_state_unavailable", f"{path}: cannot open ({e.strerror})") from None
    try:
        deadline = time.monotonic() + SEV_LOCK_WAIT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise GateRefusal("sev_state_unavailable", f"{path} is held by another compare") from None
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)  # drops the flock


def state_dir() -> Path:
    """/run/cathedral-snp: root only, so no other user can arm a boot or remove its marker."""
    d = hp(SEV_STATE)
    try:
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        st = os.lstat(d)
    except OSError as e:
        raise GateRefusal("sev_state_unavailable", f"{d}: {e.strerror}") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in (0, os.getuid()) or st.st_mode & 0o077:
        raise GateRefusal("sev_state_unavailable", f"{d} must be a directory owned by root, mode 0700")
    return d


def describe(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as f:
            doc = json.loads(f.read(DOC_MAX))
        return f"at {doc.get('at', 'unknown')}: {'; '.join(map(str, doc.get('diff') or ['(no detail)']))}"
    except (OSError, ValueError, AttributeError):
        return f"({path} unreadable)"


def seen_change() -> str | None:
    """The change this boot already saw, or None. Any marker counts, readable or not: /run is cleared
    by a reboot. The durable copy counts only when it names this boot, so it never outlives it."""
    marker = hp(CHANGED)
    if marker.exists() or marker.is_symlink():
        return describe(marker)
    me = boot_id()
    durable = hp(DURABLE_CHANGED)
    if me != "unknown" and (durable.exists() or durable.is_symlink()):
        try:
            doc = load_object(durable, "sev_platform_changed")
        except GateRefusal:
            return f"({durable} unreadable)"
        if doc.get("boot_id") == me:
            return describe(durable)
    return None


def present(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def armed() -> bool:
    try:
        return stat.S_ISREG(os.lstat(hp(ARMED)).st_mode)
    except OSError:
        return False


def create_once(path: Path) -> None:
    """Create a root-only record if it is missing. Its existence is what counts, not its bytes."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except FileExistsError:
        return
    try:
        os.write(fd, json.dumps({"boot_id": boot_id(), "at": now_iso()}).encode() + b"\n")
    except OSError:
        pass
    finally:
        os.close(fd)


def arm_boot() -> None:
    """The first compare of a boot: the armed token, then the boot record. A boot is armed once.
    After that only the operator's accept re-arms it, so a token that a change took away never
    comes back by itself, and a missing token with a boot record refuses (18)."""
    state_dir()
    try:
        create_once(hp(ARMED))
        create_once(hp(BOOTED))
    except OSError as e:
        raise GateRefusal("sev_state_unavailable", f"cannot arm this boot: {e.strerror}") from None


def revoke(diff: list[str]) -> str:
    """Keep the change for the rest of this boot. The token is renamed to the marker, or else
    unlinked; neither needs free space, so a full disk or a full /run cannot lose the change. Then
    the boot record (so a missing token refuses), the detail and the durable copy."""
    record = json.dumps({"boot_id": boot_id(), "at": now_iso(), "diff": diff}, sort_keys=True).encode() + b"\n"
    notes = []
    try:
        os.rename(hp(ARMED), hp(CHANGED))
    except FileNotFoundError:
        pass  # this boot was not armed: its first compare could not arm it
    except OSError as e:
        notes.append(f"rename: {e.strerror}")
        try:
            os.unlink(hp(ARMED))
        except FileNotFoundError:
            pass
        except OSError as e2:
            notes.append(f"unlink: {e2.strerror}")
    try:
        state_dir()
        create_once(hp(BOOTED))  # an empty file: it needs an inode, no data blocks
    except OSError as e:
        notes.append(f"boot record: {e.strerror}")
    except GateRefusal as e:
        notes.append(f"boot record: {e.detail}")
    try:
        write_atomic(hp(CHANGED), record)
    except OSError as e:
        notes.append(f"marker: {e.strerror}")
    if boot_id() != "unknown":  # never a durable record that no later boot can tell apart
        try:
            write_atomic(hp(DURABLE_CHANGED), record)
        except OSError as e:
            notes.append(f"durable copy: {e.strerror}")
    kept = seen_change() is not None or (not armed() and present(hp(BOOTED)))
    return "" if kept else f" (not kept for this boot: {'; '.join(notes)})"


def sev_gate() -> None:
    with sev_lock():
        base = sev_baseline()
        seen = seen_change()
        if seen:
            raise GateRefusal("sev_platform_changed",
                              f"changed earlier in this boot {seen}; new starts stay refused until a host"
                              " reboot with a baseline match, or `vm-gates.sh baseline --replace --expect`")
        arm_error = None
        if not present(hp(BOOTED)):
            try:
                arm_boot()
            except GateRefusal as e:
                arm_error = e  # still compare: a change must be seen and alerted
        diff = sev_tool().differences(base, read_sev())
        if diff:
            raise GateRefusal("sev_platform_changed", "; ".join(diff) + revoke(diff))
        if arm_error:
            raise arm_error
        if not armed():
            raise GateRefusal("sev_state_unavailable",
                              "this boot is not armed: a SEV change was seen and its record was lost, or"
                              " the token was removed; reboot the host, or accept the status with"
                              " `vm-gates.sh baseline --replace --expect`")


def accept_change() -> None:
    """The operator accepts the verified status: clears this boot's change and arms the boot again.
    Caller holds the SEV lock and has written the new baseline."""
    state_dir()
    for path in (hp(CHANGED), hp(DURABLE_CHANGED)):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            raise GateRefusal("sev_state_unavailable", f"cannot clear {path}: {e.strerror}") from None
    try:
        create_once(hp(ARMED))
        create_once(hp(BOOTED))
    except OSError as e:
        raise GateRefusal("sev_state_unavailable", f"cannot arm this boot: {e.strerror}") from None


def status_digest(status: dict) -> str:
    """sha256 of the compared fields only (canonical JSON). Guest count and state move as guests start
    and stop, so the digest an operator verified stays the same while VMs run."""
    picked = {part: {f: (status.get(part) or {}).get(f) for f in fields}
              for part, fields in sev_tool().COMPARED.items()}
    return hashlib.sha256(json.dumps(picked, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---- gate: bundle digests ------------------------------------------------------------------

def bundle_gate(vm: dict) -> None:
    """Every file the manifest names has its size and sha256, and the manifest is the bundle id the
    VM names (the id the host file enabled). Read through one directory descriptor, no links."""
    bundle = vm["bundle"]
    d = vm_root() / "bundles" / bundle
    try:
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise GateRefusal("vm_bundle_mismatch", f"bundle {bundle[:16]} is missing at {d}") from None
    try:
        raw = read_protected(Path("manifest.json"), "vm_bundle_mismatch", dir_fd=dfd)
        if hashlib.sha256(raw).hexdigest() != bundle:
            raise GateRefusal("vm_bundle_mismatch", f"{d}/manifest.json is not bundle {bundle[:16]}")
        try:
            doc = json.loads(raw)
        except ValueError:
            raise GateRefusal("vm_bundle_mismatch", f"{d}/manifest.json is not JSON") from None
        sha = doc.get("sha256") if isinstance(doc, dict) else None
        size = doc.get("bytes") if isinstance(doc, dict) else None
        if not isinstance(sha, dict) or not isinstance(size, dict) or not sha or set(sha) != set(size):
            raise GateRefusal("vm_bundle_mismatch", f"{d}/manifest.json names no file digests")
        for name in sorted(sha):
            if (not BUNDLE_FILE_RE.fullmatch(name) or name == "manifest.json" or not isinstance(sha[name], str)
                    or not HEX64_RE.fullmatch(sha[name]) or type(size[name]) is not int or size[name] < 0):
                raise GateRefusal("vm_bundle_mismatch", f"{d}/manifest.json: bad entry {name[:64]!r}")
            file_gate(dfd, d, name, sha[name], size[name])
    finally:
        os.close(dfd)


def file_gate(dfd: int, d: Path, name: str, want_sha: str, want_size: int) -> None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
    except OSError as e:
        raise GateRefusal("vm_bundle_mismatch", f"{d}/{name}: cannot open ({e.strerror})") from None
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise GateRefusal("vm_bundle_mismatch", f"{d}/{name} is not a regular file")
        if st.st_size != want_size:
            raise GateRefusal("vm_bundle_mismatch", f"{d}/{name} is {st.st_size} bytes, the manifest says {want_size}")
        digest, n = sha256_stream(f)
    if (digest, n) != (want_sha, want_size):
        raise GateRefusal("vm_bundle_mismatch", f"{d}/{name} differs from its sha256 in the manifest")


# ---- commands ------------------------------------------------------------------------------

def check(name: str) -> dict:
    """The entry point VM3 calls (cmd_start, ExecStartPre). Raises GateRefusal."""
    vm = vm_of(name)
    cfg = host_config()
    if vm["bundle"] not in cfg["bundles"]:
        raise GateRefusal("vm_bundle_not_enabled", f"bundle {vm['bundle'][:16]} is not enabled on this host")
    build = host_build_gate(cfg, vm)
    sev_gate()
    bundle_gate(vm)
    return {"ok": True, "name": name, "bundle": vm["bundle"], "host_build": build}


def enforce() -> dict:
    """The enforce tick. Reads the SEV status and the baseline; starts and stops nothing."""
    if not hp(HOST_FILE).exists() and not hp(HOST_FILE).is_symlink():
        return {"ok": True, "sev": "off"}
    sev_gate()
    return {"ok": True, "sev": "equal"}


def show_status() -> dict:
    """Operator, read only: the status to verify before a baseline, and the digest to pass as --expect."""
    status = read_sev()
    doc = {"ok": True, "status": status, "digest": status_digest(status)}
    try:
        base = sev_baseline()
        doc["baseline_digest"] = status_digest(base)
        doc["differences"] = sev_tool().differences(base, status)
    except GateRefusal as e:
        doc["baseline"] = e.error
    return doc


def take_baseline(replace: bool, expect: str) -> dict:
    """Operator: record the verified SEV status as the baseline (D 5.9 `baselined`). This is the explicit
    accept: it also clears a change this boot saw and arms the boot again. It accepts only the status
    the operator verified: `expect` is the digest `vm-gates.sh status` printed for it, and the status is
    read again under the lock, so a change in between is refused, never accepted."""
    path = hp(BASELINE)
    with sev_lock():
        if present(path) and not replace:
            raise UsageError("baseline_exists", f"{path} exists; pass --replace after verifying the platform")
        status = read_sev()
        now = status_digest(status)
        if now != expect:
            raise GateRefusal("sev_platform_changed",
                              f"the status now (digest {now[:16]}) is not the one verified ({expect[:16]}):"
                              " read it again with `vm-gates.sh status` and verify it")
        write_atomic(path, json.dumps(status, sort_keys=True).encode() + b"\n")  # mode 0600 (mkstemp)
        accept_change()
    return {"ok": True, "baseline": str(path), "digest": now, "status": status}


def baseline_args(rest: list[str]) -> tuple[bool, str]:
    replace, expect, i = False, None, 0
    while i < len(rest):
        if rest[i] == "--replace" and not replace:
            replace, i = True, i + 1
        elif rest[i] == "--expect" and expect is None and i + 1 < len(rest) and HEX64_RE.fullmatch(rest[i + 1]):
            expect, i = rest[i + 1], i + 2
        else:
            raise UsageError("usage", USAGE)
    if expect is None:
        raise UsageError("usage", "baseline needs --expect <digest>, from `vm-gates.sh status` for the status you verified")
    return replace, expect


def host_build_info() -> dict:
    """Operator, read only: this host's build, for a verified entry once a canary passed. Runs
    `qemu-system-x86_64 --version`; `check` never does."""
    sha = qemu_sha256()
    r = subprocess.run([str(hp(QEMU)), "--version"], capture_output=True, text=True, timeout=30)
    m = re.search(r"version ([0-9]+\.[0-9]+\.[0-9]+)", r.stdout)
    if r.returncode != 0 or not m:
        raise GateRefusal("vm_host_changed", "cannot read the QEMU version")
    return {"qemu_sha256": sha, "qemu_version": m.group(1), "kernel_release": kernel_release()}


USAGE = "usage: vm-gates.sh check <name> | enforce | status | baseline --expect <digest> [--replace] | host-build"


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 2 and argv[0] == "check":
            doc = check(argv[1])
        elif argv == ["enforce"]:
            doc = enforce()
        elif argv == ["status"]:
            doc = show_status()
        elif argv[:1] == ["baseline"]:
            doc = take_baseline(*baseline_args(argv[1:]))
        elif argv == ["host-build"]:
            doc = host_build_info()
        else:
            raise UsageError("usage", USAGE)
    except GateRefusal as e:
        print(json.dumps({"ok": False, "error": e.error, "detail": e.detail}, sort_keys=True))
        print(f"vm-gates: {e.error}: {e.detail}", file=sys.stderr)
        return e.code
    except UsageError as e:
        print(json.dumps({"ok": False, "error": e.error, "detail": e.detail}, sort_keys=True))
        print(f"vm-gates: {e.error}: {e.detail}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as e:  # a bug refuses too, with one line
        detail = " ".join(f"{type(e).__name__}: {e}".split())[:400]
        print(json.dumps({"ok": False, "error": "internal", "detail": detail}, sort_keys=True))
        print(f"vm-gates: internal: {detail}", file=sys.stderr)
        return EXIT_INTERNAL
    print(json.dumps(doc, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
