#!/usr/bin/env python3
"""Host runtime for long-lived customer VMs (AB#991). Run through vm-ctl.sh.

One VM is one directory $VM_ROOT/<name>/ (vm.env, vm-identity.json, launch.json,
root.raw, mailbox.raw, authorization.json, stop.json, run/), one system user
cvm-<slot> and one systemd unit cathedral-vm-<name>.service that runs the SEV-SNP
guest as that user (launch-vm.py; VM runtime spec r2 6.3, 7.1, 8.1, 8.2).
Every command prints one JSON line on stdout; a refusal prints {"error": ...} and exits nonzero:
  2 invalid request, 3 authorization refused, 4 unpaid, 5 no such VM or exists,
  10 to 18 a pre-launch gate (start; vm_gates.EXIT), 19 stale bundle selection and 20 bundle
  incompatible (rebundle), 1 anything else. A refusal may add "reason", a token naming the check.

Rebundle (spec r3 7.5 step 1) moves a stopped VM to another bundle, fenced by its closed
generation and its bundle_selection_revision, idempotent by op_id.

Credit cutoff (polariscomputer#2290 rules 3, 5, 6) is enforced here, on the host,
so it holds with the API and the broker down:
- authorize is idempotent and monotonic: a lower generation is refused, the same
  generation may only keep or raise paid_through, a higher one replaces.
- start, and the unit's ExecStartPre, refuse when now >= paid_through.
- stop closes the run: its generation can never start again, so a resume needs
  a fresh generation and an old authorization cannot revive the VM.
- enforce (a timer, every 30 s) stops any running VM past paid_through. Disks
  are kept; only delete --confirm <name> removes one.

Execution history (AB#992, docs/VM_EXECUTION_HISTORY.md H1 to H9): <root>/.history/<name>.jsonl
is an append-only record, outside the VM directory, that delete never removes. A start
line is durable before a run launches and a close line is durable before the run's
authorization and stop evidence are written, so billing settlement can read one exact
start time, or proof that a run never started, from `history <name> <generation>`.
"""
from __future__ import annotations

import contextlib
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

KIT = Path(__file__).resolve().parent
# -I keeps the script's directory off sys.path; vm_measure.py beside this file is the kit's.
sys.path.insert(0, str(KIT))
import vm_measure  # noqa: E402

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
# Entries of $VM_ROOT that are not VMs: no VM may take their name.
RESERVED_NAMES = (".history", "bundles")
# Must equal the broker's vmKeyTypes (broker/vms.go); both test files pin the same set.
# The sk-* security-key types are accepted by the guest sshd (OpenSSH 9.6 on the pinned Ubuntu 24.04).
KEY_TYPES = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
NET = ipaddress.IPv4Network("10.216.0.0/16")
SLOTS = NET.num_addresses // 4
COMMANDS = ("create", "authorize", "start", "stop", "reboot", "delete", "status", "list", "enforce",
            "cancel", "history", "rebundle")
STOP_WAIT = int(os.environ.get("VM_STOP_WAIT", "60"))
MAILBOX_BYTES = 1 << 20
# Rebundle (spec r3 7.5 step 1): the applied op_ids a VM remembers, with their results.
SELECTION_OPS_MAX = 64
BUNDLE_ID_RE = re.compile(r"[0-9a-f]{64}")
EXIT_STALE_SELECTION, EXIT_BUNDLE_INCOMPATIBLE = 19, 20  # 17 and 18 are the gates' (vm_gates.EXIT)
OP_ID_RE = re.compile(r"[0-9a-f]{32}")  # 128 random bits from the caller
# MemoryMax headroom over guest memory: the dedicated unit's figure (D 5.8) until rehearsal A2
# measures the SNP QEMU overhead. A cap, not a reservation: admission (VM4) counts its own.
MEM_OVERHEAD_GIB = 16
SEV_GROUP = "cvm-sev"
# Fields of launch.json (vm_measure.launch_values at create) that status returns.
LAUNCH_STATUS = ("vm_id", "bundle", "identity_sha256", "expected_measurement", "host_data", "cpu_family",
                 "cpu_model", "cpu_signature", "policy")
# Credit cutoff: a short grace, and every expired VM at once, so one guest that ignores
# the powerdown cannot keep the next one running past its paid_through.
CUTOFF_WAIT = int(os.environ.get("VM_CUTOFF_WAIT", "15"))
# History is best effort inside enforce: one VM's history I/O gets this long (a pass-wide window for
# the sweep), then it is abandoned so a stalled disk cannot hold the oneshot service or a VM lock.
HISTORY_BUDGET = float(os.environ.get("VM_HISTORY_BUDGET", "5"))
HISTORY_SWEEP_BUDGET = float(os.environ.get("VM_HISTORY_SWEEP_BUDGET", "15"))


class Refusal(Exception):
    def __init__(self, error: str, detail: str = "", code: int = 2, reason: str = ""):
        super().__init__(detail or error)
        self.error, self.detail, self.code, self.reason = error, detail, code, reason


def root() -> Path:
    return Path(os.environ.get("VM_ROOT", "/srv/cathedral-vms"))


def unit_dir() -> Path:
    return Path(os.environ.get("SYSTEMD_UNIT_DIR", "/etc/systemd/system"))


def udev_rules_dir() -> Path:
    return Path(os.environ.get("VM_UDEV_RULES_DIR", "/etc/udev/rules.d"))


def host_config_path() -> Path:
    # launch-vm.py reads the same file at its fixed path (HOST_CONFIG); only tests move it.
    return Path(os.environ.get("VM_HOST_CONFIG", "/etc/cathedral/snp-vm-host.json"))


def host_config() -> dict:
    """The host's sealed VM switch: absent, every create (and every launch) refuses.

    {"version": 1, "cpu_family": "genoa"|"turin", "bundles": [<bundle id>, ...],
     "default_bundle": <one of bundles>, "sev_snp_measure": <absolute path, optional>}"""
    path = host_config_path()
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        raise Refusal("snp_vm_host_disabled", f"{path} is missing: this host runs no sealed VM", 1) from None
    except (OSError, ValueError):
        raise Refusal("snp_vm_host_config", f"{path} is not readable JSON", 1) from None
    bundles = doc.get("bundles") if isinstance(doc, dict) else None
    tool = doc.get("sev_snp_measure") if isinstance(doc, dict) else None
    if not (isinstance(doc, dict) and doc.get("version") == 1 and doc.get("cpu_family") in vm_measure.CPU_MODELS
            and isinstance(bundles, list) and bundles
            and all(isinstance(b, str) and re.fullmatch(r"[0-9a-f]{64}", b) for b in bundles)
            and doc.get("default_bundle") in bundles
            and (tool is None or (isinstance(tool, str) and tool.startswith("/")))):
        raise Refusal("snp_vm_host_config", f"{path}: version, cpu_family, bundles or default_bundle is wrong", 1)
    return doc


def vm_user(slot: int) -> str:
    return f"cvm-{slot}"


def unit_name(name: str) -> str:
    return f"cathedral-vm-{name}.service"


def out(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, sort_keys=True) + "\n")


def check_name(name: str) -> str:
    if name in RESERVED_NAMES or not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise Refusal("invalid_name", "name must match ^[a-z0-9][a-z0-9-]{0,40}$")
    return name


def check_int(value: str, what: str, lo: int, hi: int) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,16}", value):
        raise Refusal("invalid_" + what, f"{what} must be a decimal integer")
    n = int(value)
    if not lo <= n <= hi:
        raise Refusal("invalid_" + what, f"{what} must be in {lo}..{hi}")
    return n


def check_key(text: str) -> str:
    """One OpenSSH public key line. Returns 'type base64' (the comment is dropped)."""
    import base64
    import binascii

    lines = [line for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
    if len(lines) != 1 or len(text) > 16384:
        raise Refusal("invalid_ssh_key", "the key file must hold exactly one public key line")
    parts = lines[0].strip().split()
    if len(parts) < 2 or parts[0] not in KEY_TYPES or not re.fullmatch(r"[A-Za-z0-9+/]+={0,3}", parts[1]):
        raise Refusal("invalid_ssh_key", "not an ssh-ed25519, ecdsa-sha2-nistp*, sk-* or ssh-rsa public key")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        raise Refusal("invalid_ssh_key", "the key is not valid base64") from None
    n = int.from_bytes(blob[:4], "big") if len(blob) >= 4 else -1
    if n <= 0 or blob[4:4 + n] != parts[0].encode():
        raise Refusal("invalid_ssh_key", "the key blob does not match its type")
    return f"{parts[0]} {parts[1]}"


# ---- files -------------------------------------------------------------------

def write_atomic(path: Path, data: str, mode: int = 0o600) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
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


def read_json(path: Path, default: dict) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return dict(default)


def read_env(path: Path) -> dict:
    env = {}
    for line in path.read_text().splitlines():
        m = re.fullmatch(r"([A-Z][A-Z0-9_]*)='([^']*)'", line)
        if m:
            env[m.group(1)] = m.group(2)
    return env


class Lock:
    def __init__(self, path: Path, wait: float = 120):
        self.path, self.wait = path, wait

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.wait
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() > deadline:
                    os.close(self.fd)
                    raise Refusal("busy", f"{self.path} is held by another command", 1)
                time.sleep(0.2)

    def __exit__(self, *exc):
        os.close(self.fd)


def global_lock() -> Lock:
    root().mkdir(parents=True, exist_ok=True, mode=0o700)
    return Lock(root() / ".lock")


def vm_dir(name: str) -> Path:
    d = root() / check_name(name)
    if d.is_symlink() or not (d / "vm.env").is_file():
        raise Refusal("not_found", f"no VM named {name}", 5)
    return d


def all_vms() -> list[str]:
    if not root().is_dir():
        return []
    return sorted(p.name for p in root().iterdir()
                  if NAME_RE.fullmatch(p.name) and not p.is_symlink() and (p / "vm.env").is_file())


# ---- systemd and QMP -------------------------------------------------------------

def run(*cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise Refusal("command_failed", f"{' '.join(cmd[:3])}: {(p.stderr or p.stdout).strip()[-400:]}", 1)
    return p


def systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run("systemctl", *args, check=check)


def unit_active(name: str) -> bool:
    state = systemctl("show", "-p", "ActiveState", "--value", unit_name(name), check=False).stdout.strip()
    return state in ("active", "activating", "reloading", "deactivating")


def unit_absent(name: str) -> bool:
    """True only when the unit file is gone and systemd positively reports it not loaded and inactive."""
    if (unit_dir() / unit_name(name)).exists():
        return False
    p = systemctl("show", "-p", "LoadState", "-p", "ActiveState", unit_name(name), check=False)
    props = dict(l.split("=", 1) for l in p.stdout.splitlines() if "=" in l)
    return p.returncode == 0 and props.get("LoadState") == "not-found" and props.get("ActiveState") == "inactive"


def qmp_exchange(sock_path: str, command: str, timeout: float) -> bool:
    """qmp_capabilities, then one command, on one QMP socket. True when both returned."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(sock_path)
            f = s.makefile("rwb")
            f.readline()  # greeting
            for cmd in ("qmp_capabilities", command):
                f.write(json.dumps({"execute": cmd}).encode() + b"\n")
                f.flush()
                while True:
                    reply = json.loads(f.readline() or b"{}")
                    if "event" not in reply:
                        break
                if "return" not in reply:
                    return False
            return True
    except (OSError, ValueError):
        return False


QMP_COMMANDS = ("system_powerdown",)


def qmp(name: str, command: str, timeout: float = 5) -> bool:
    """Send one QMP command; False when QEMU is not there to take it.

    run/ belongs to the VM's QEMU user, who can replace qmp.sock with a link to any path at
    any time, so no check made by root before connect() holds (Astra #789 P1). The connect
    therefore runs as that user: a child process starts in run/ (root resolves only the
    root-owned path down to it), drops to the VM user with no supplementary groups, and
    connects to "qmp.sock" relative to it. Whatever the link names, it is followed with the
    VM user's rights, which reach no other VM (every VM directory is root's, mode 0700).
    The lstat check below only fails fast; it is not what makes this safe."""
    d = root() / name
    run_dir = d / "run"
    try:
        st = os.lstat(run_dir / "qmp.sock")
        if not stat.S_ISSOCK(st.st_mode):
            return False
        user = read_env(d / "vm.env").get("VM_USER")
    except OSError:
        return False
    if user is None:
        # A VM from before AB#999 VM3: QEMU ran as root and run/ is root's.
        return qmp_exchange(str(run_dir / "qmp.sock"), command, timeout)
    try:
        import pwd
        pw = pwd.getpwnam(user)
    except KeyError:
        return False
    drop = {"user": pw.pw_uid, "group": pw.pw_gid, "extra_groups": []} if os.geteuid() == 0 else {}
    try:
        p = subprocess.run([sys.executable, "-I", str(KIT / "vm_ctl.py"), "qmp-as-vm-user", command, str(timeout)],
                           cwd=str(run_dir), capture_output=True, timeout=timeout + 10, env={"PATH": "/usr/bin:/bin"},
                           **drop)
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0


def cmd_qmp_as_vm_user(args: list[str]) -> dict:
    """Internal (never from the broker): the child of qmp(), already the VM user, cwd run/."""
    if len(args) != 2 or args[0] not in QMP_COMMANDS:
        raise Refusal("usage", "qmp-as-vm-user <command> <timeout>")
    if os.geteuid() == 0:
        raise Refusal("usage", "qmp-as-vm-user runs only as a VM user, never as root")
    if not qmp_exchange("qmp.sock", args[0], float(args[1])):
        raise Refusal("qmp_failed", "QEMU did not take the command", 1)
    return {"sent": args[0]}


# ---- authorization -------------------------------------------------------------

def auth_of(d: Path) -> dict:
    return read_json(d / "authorization.json", {"generation": 0, "paid_through": 0, "closed_generation": 0})


def paid_refusal(a: dict, now: int) -> Refusal | None:
    if a["generation"] <= a.get("closed_generation", 0):
        return Refusal("generation_closed", "this run was stopped; authorize a new generation to start again", 3)
    if now >= a["paid_through"]:
        return Refusal("unpaid", f"paid_through {a['paid_through']} is not after now {now}", 4)
    return None


# ---- pre-launch gates (spec r2 8.3, #788) ---------------------------------------------

GATE_WAIT = 90  # gate 13 reads every bundle file; the broker gives start 2 min in all


def gates_command() -> str:
    # VM_GATES stands in for the entry in tests, as PATH does for systemctl.
    return os.environ.get("VM_GATES") or str(KIT / "vm-gates.sh")


def gate_refusal(name: str) -> Refusal | None:
    """`vm-gates.sh check <name>`: None when every gate passes, else the start refusal.

    A gate's error and exit code (10 to 18, vm_gates.EXIT) pass through unchanged, so
    sev_platform_changed is exit 17 and sev_state_unavailable exit 18. The broker answers every
    exit but 3 and 4 with 502 vm_host_refused and keeps the VM stopped. Anything else (1
    internal, 2 usage, a crash, a timeout, an answer that does not match its code) refuses as
    gates_failed, exit 1: no gate result fails open."""
    import vm_gates
    try:
        p = subprocess.run([gates_command(), "check", name], capture_output=True, text=True,
                           timeout=GATE_WAIT)
    except subprocess.TimeoutExpired:
        return Refusal("gates_failed", f"the pre-launch gates did not answer in {GATE_WAIT} s", 1)
    except OSError as e:
        return Refusal("gates_failed", f"the pre-launch gates did not run: {type(e).__name__}", 1)
    if p.returncode == 0:
        return None
    try:
        doc = json.loads(p.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        doc = None
    doc = doc if isinstance(doc, dict) else {}
    error, code = doc.get("error"), p.returncode
    if code in vm_gates.EXIT.values() and vm_gates.EXIT.get(error) == code:
        return Refusal(error, " ".join(str(doc.get("detail", "")).split())[:400], code)
    return Refusal("gates_failed", f"the pre-launch gates refused (exit {code})", 1)


# ---- execution history (AB#992) -------------------------------------------------------

HISTORY_DIR_NAME = ".history"  # a leading dot can never match NAME_RE, so no VM name can collide


def history_dir() -> Path:
    return root() / HISTORY_DIR_NAME


def history_path(name: str) -> Path:
    return history_dir() / f"{check_name(name)}.jsonl"


def wall_us() -> int:
    return time.time_ns() // 1000


def mono_ns() -> int:
    return time.monotonic_ns()


def boot_ns() -> int | None:
    """CLOCK_BOOTTIME: like CLOCK_MONOTONIC but it keeps counting through suspend."""
    try:
        return time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        return None


def boot_id() -> str | None:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip() or None
    except OSError:
        return None


MAX_CLOCK_ERROR_US = 1_000_000


def kernel_clock() -> tuple[bool, int | None]:
    """(synced, maxerror_us) from adjtimex(2) with modes=0 (read only).

    synced means the kernel returned no TIME_ERROR and STA_UNSYNC is clear; maxerror_us is
    struct timex .maxerror, the kernel's bound on the wall clock error. Any doubt (not Linux x86_64
    layout, call failed) is (False, None): such a line can only make history_unknown."""
    try:
        import ctypes

        if ctypes.sizeof(ctypes.c_long) != 8 or not sys.platform.startswith("linux"):
            return False, None

        class Timex(ctypes.Structure):
            _fields_ = [("modes", ctypes.c_uint), ("offset", ctypes.c_long), ("freq", ctypes.c_long),
                        ("maxerror", ctypes.c_long), ("esterror", ctypes.c_long), ("status", ctypes.c_int),
                        ("constant", ctypes.c_long), ("precision", ctypes.c_long), ("tolerance", ctypes.c_long),
                        ("time_sec", ctypes.c_long), ("time_usec", ctypes.c_long), ("tick", ctypes.c_long),
                        ("ppsfreq", ctypes.c_long), ("jitter", ctypes.c_long), ("shift", ctypes.c_int),
                        ("stabil", ctypes.c_long), ("jitcnt", ctypes.c_long), ("calcnt", ctypes.c_long),
                        ("errcnt", ctypes.c_long), ("stbcnt", ctypes.c_long), ("tai", ctypes.c_int),
                        ("pad", ctypes.c_int * 11), ("spare", ctypes.c_char * 256)]

        libc = ctypes.CDLL(None, use_errno=True)
        tx = Timex()  # modes 0: read only
        state = libc.adjtimex(ctypes.byref(tx))
        if not 0 <= state <= 5:
            return False, None
        # TIME_ERROR (5) is what the kernel returns while STA_UNSYNC (0x40) is set.
        return state < 5 and not tx.status & 0x40, int(tx.maxerror)
    except Exception:
        return False, None


def stamp() -> dict:
    synced, maxerror_us = kernel_clock()
    return {"wall_us": wall_us(), "boot_id": boot_id(), "mono_ns": mono_ns(), "boot_ns": boot_ns(),
            "synced": bool(synced),
            "maxerror_us": maxerror_us}


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _valid_event(e: dict) -> bool:
    kind = e.get("event")
    if kind == "tracked_from":
        return _is_int(e.get("generation")) and e["generation"] >= 1
    if kind not in ("start", "close") or not _is_int(e.get("generation")) or e["generation"] < 1:
        return False
    if not (_is_int(e.get("wall_us")) and _is_int(e.get("mono_ns")) and isinstance(e.get("synced"), bool)
            and (e.get("boot_id") is None or isinstance(e["boot_id"], str))
            and (e.get("maxerror_us") is None or _is_int(e["maxerror_us"]))
            and (e.get("boot_ns") is None or _is_int(e["boot_ns"]))):
        return False
    return kind == "start" or (_is_int(e.get("stopped_at")) and isinstance(e.get("reason"), str))


def read_synced(name: str) -> bytes | None:
    """Read the journal, then fsync that same descriptor and the directory: what comes back is durable.

    Sync must follow the read. A reader outside the journal lock could otherwise fsync, then read a
    close appended just after, and trust a line a power loss would still drop. None: no file."""
    try:
        fd = os.open(history_path(name), os.O_RDONLY)
    except FileNotFoundError:
        return None
    try:
        with os.fdopen(os.dup(fd), "rb") as f:
            data = f.read()
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(history_dir(), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return data


def read_history(name: str, durable: bool = True) -> dict:
    """The history file as readers see it (H6).

    {"events": parsed lines, "valid_len": bytes up to the last newline, "exists": bool,
     "corrupt": bool, "tracked_from": int | None}. An unterminated final line is ignored.
    Corrupt means a complete line that is malformed, or a shape no writer produces (a second
    first line, a duplicate start or close, a start after its close): the whole file is unknown.
    durable: read a snapshot, then fsync it, so no decision rests on a line a power loss could drop."""
    try:
        data = read_synced(name) if durable else history_path(name).read_bytes()
    except FileNotFoundError:
        data = None
    if data is None:
        return {"events": [], "valid_len": 0, "exists": False, "corrupt": False, "tracked_from": None}
    return parse_history(data)


def parse_history(data: bytes) -> dict:
    valid_len = data.rfind(b"\n") + 1
    events, corrupt, seen = [], False, set()
    for raw in data[:valid_len].splitlines():
        try:
            e = json.loads(raw)
        except ValueError:
            corrupt = True
            continue
        if not isinstance(e, dict) or not _valid_event(e):
            corrupt = True
            continue
        key = (e["event"], 0 if e["event"] == "tracked_from" else e["generation"])
        if key in seen or (not events and e["event"] != "tracked_from") or \
                (e["event"] == "start" and ("close", e["generation"]) in seen):
            corrupt = True
        seen.add(key)
        events.append(e)
    first = events[0] if events and events[0]["event"] == "tracked_from" else None
    if valid_len and not first:
        corrupt = True
    return {"events": events, "valid_len": valid_len, "exists": True, "corrupt": corrupt,
            "tracked_from": first["generation"] if first else None}


def event_of(h: dict, kind: str, generation: int) -> dict | None:
    for e in h["events"]:
        if e["event"] == kind and e["generation"] == generation:
            return e
    return None


class HistoryStalled(OSError):
    """History I/O did not answer within the enforce budget; the caller moves on."""


_hist = threading.local()
_stalled: set[str] = set()  # VMs with an abandoned journal call still in flight in this process


@contextlib.contextmanager
def history_budget(seconds: float):
    _hist.seconds, _hist.deadline = seconds, None
    try:
        yield
    finally:
        _hist.seconds = _hist.deadline = None


def hio(name: str, fn, *args):
    """Run one journal call; inside a history_budget, give up on it when the budget is spent.

    Only pure journal I/O goes through here (read, append). State changes stay on the caller's
    thread under the VM lock, so an abandoned call can finish later without racing an authorize.
    One abandoned call per VM per process: a second would race it into a duplicate line."""
    seconds = getattr(_hist, "seconds", None)
    if seconds is None:
        return fn(*args)
    if getattr(_hist, "deadline", None) is None:
        _hist.deadline = time.monotonic() + seconds  # starts at the first history call, after the stop
    remaining = _hist.deadline - time.monotonic()
    if name in _stalled or remaining <= 0:
        raise HistoryStalled(f"history for {name} is stalled")
    box: dict = {}

    def work():
        try:
            box["v"] = fn(*args)
        except BaseException as e:
            box["e"] = e

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(remaining)
    if t.is_alive():
        _stalled.add(name)
        raise HistoryStalled(f"history for {name} did not answer in {seconds:g}s")
    if "e" in box:
        raise box["e"]
    return box["v"]


def recorded_event(h: dict, record: dict) -> dict | None:
    """The journal event that makes appending `record` unnecessary or wrong, if any.

    One tracked_from per file, one start and one close per generation, and no start after the
    close of its generation. A writer that was abandoned on a timeout and finishes late, or a
    second process doing the same step, finds the event already there and appends nothing."""
    kind, g = record["event"], record.get("generation")
    if kind == "tracked_from":
        return next((e for e in h["events"] if e["event"] == "tracked_from"), None)
    close = event_of(h, "close", g)
    if kind == "close":
        return close
    return event_of(h, "start", g) or close


def history_append(name: str, record: dict) -> dict:
    """H1: append one line (a torn tail is cut first), then fsync the file and the journal dir.

    Returns the event now in the journal for this step: `record`, or the equivalent event that was
    already there. The decision to append is made under the journal's flock, from the bytes read
    under it, so it is atomic with every other writer in any process, and a late completion of an
    abandoned append is a no-op. A line found here is fsynced before it is returned."""
    hdir = history_dir()
    hdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(history_path(name), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        size = os.fstat(fd).st_size
        data = os.pread(fd, size, 0) if size else b""
        parsed = parse_history(data)
        existing = recorded_event(parsed, record)
        if existing is None:
            if parsed["valid_len"] != len(data):
                os.ftruncate(fd, parsed["valid_len"])  # only the unterminated tail: nothing depended on it
            os.lseek(fd, parsed["valid_len"], os.SEEK_SET)
            line = (json.dumps(record, sort_keys=True) + "\n").encode()
            while line:
                line = line[os.write(fd, line):]
        os.fsync(fd)
    finally:
        os.close(fd)  # drops the flock
    dfd = os.open(hdir, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return existing if existing is not None else record


def ensure_tracked(name: str, d: Path) -> None:
    """H1: the first command to touch a VM after the upgrade writes tracked_from."""
    h = hio(name, read_history, name)
    if h["events"] or (h["exists"] and h["corrupt"]):
        return
    hio(name, history_append, name, {"event": "tracked_from", "generation": auth_of(d)["generation"] + 1})


def recover_closure(name: str, d: Path) -> dict:
    """A durable close line is authoritative: raise closed_generation to it before deciding anything."""
    a, h = auth_of(d), hio(name, read_history, name)
    closed = max((e["generation"] for e in h["events"] if e["event"] == "close"), default=0)
    if closed > a.get("closed_generation", 0):
        a["closed_generation"] = closed
        write_atomic(d / "authorization.json", json.dumps(a, sort_keys=True) + "\n")
    return a


def finish_pending_close(name: str, d: Path) -> None:
    """Write the close a stalled cutoff could not (see fence_pending_close), with the stop-time stamp.

    The marker survives the death of the process that abandoned the append, so the next command or
    enforce tick closes the generation. history_append is idempotent, so a late abandoned writer
    that lands first or after is harmless."""
    marker = d / "pending-close.json"
    p = read_json(marker, {})
    if not p:
        return
    g = p["generation"]
    h = hio(name, read_history, name)
    if is_tracked(h, g) and not event_of(h, "close", g):
        hio(name, history_append, name, {"event": "close", "generation": g, "reason": p["reason"],
                                         "stopped_at": p["wall_us"] // 1_000_000,
                                         **{k: p.get(k) for k in ("wall_us", "boot_id", "mono_ns", "boot_ns",
                                                                  "synced", "maxerror_us")}})
    marker.unlink(missing_ok=True)


def fence_pending_close(name: str, d: Path, reason: str) -> dict:
    """The stop is done but the journal did not answer: fence the generation durably, without any
    history I/O, on the lock-holding thread. closed_generation stops authorize and start from
    reviving it; the marker makes the next command or tick write the close."""
    a = auth_of(d)
    marker = {"generation": a["generation"], "reason": reason, **stamp()}
    write_atomic(d / "pending-close.json", json.dumps(marker, sort_keys=True) + "\n")
    a["closed_generation"] = max(a.get("closed_generation", 0), a["generation"])
    write_atomic(d / "authorization.json", json.dumps(a, sort_keys=True) + "\n")
    return marker


def begin(name: str, d: Path) -> None:
    """First thing under the VM lock in every command that decides something."""
    ensure_tracked(name, d)
    finish_pending_close(name, d)
    recover_closure(name, d)


def close_record(name: str, close: dict) -> dict:
    return {"name": name, "generation": close["generation"], "closed": True,
            "stopped_at": close["stopped_at"], "close_reason": close["reason"]}


def append_close(name: str, generation: int, reason: str) -> dict:
    now = stamp()
    line = {"event": "close", "generation": generation, "stopped_at": now["wall_us"] // 1_000_000,
            "reason": reason, **now}
    return history_append(name, line)  # the close already there wins over this one


def is_tracked(h: dict, generation: int) -> bool:
    return h["tracked_from"] is not None and not h["corrupt"] and generation >= h["tracked_from"]


def refuse_if_running(name: str, generation: int) -> None:
    """A newer generation may only replace a run whose unit is down, tracked or not: otherwise the
    old run keeps executing while its history says it never started."""
    if unit_active(name):
        raise Refusal("generation_open", f"generation {generation} is still running: stop it first", 3)


def close_open_generation(name: str, d: Path, a: dict, reason: str) -> None:
    """H3: close the authorized generation as never started, or refuse when it has a start line.

    Only for a tracked, open generation; one opened before the upgrade is replaced as before."""
    g = a["generation"]
    if g < 1 or g <= a.get("closed_generation", 0):
        return
    h = read_history(name)
    if not is_tracked(h, g):
        return
    if event_of(h, "start", g):
        raise Refusal("generation_open", f"generation {g} was started: stop it before moving on", 3)
    if not event_of(h, "close", g):
        append_close(name, g, reason)
    a["closed_generation"] = g
    write_atomic(d / "authorization.json", json.dumps(a, sort_keys=True) + "\n")


# ---- status ---------------------------------------------------------------------

def status_of(name: str) -> dict:
    d = vm_dir(name)
    env, a = read_env(d / "vm.env"), auth_of(d)
    launch = read_json(d / "launch.json", {})
    if unit_active(name):
        state = "running"
    else:
        state = "stopped" if (d / "started").exists() else "created"
    return {
        "name": name, "state": state, "generation": a["generation"], "paid_through": a["paid_through"],
        # True once this generation was stopped or cancelled: it can never run again.
        # The broker settles a "starting" record it lost the answer for from this.
        "closed": a["generation"] <= a.get("closed_generation", 0) and a["generation"] > 0,
        "ssh_port": int(env["VM_SSH_PORT"]), "guest_ip": env["VM_GUEST_IP"], "vcpus": int(env["VM_VCPUS"]),
        "mem_gib": int(env["VM_MEM_GIB"]), "disk_gib": int(env["VM_DISK_GIB"]),
        # Sealed VM launch values (spec r2 6.3): the customer recomputes expected_measurement from
        # the published bundle and their identity document; the broker passes these through.
        **{k: launch[k] for k in LAUNCH_STATUS if k in launch},
        **({"disks": {"root": (d / "root.raw").is_file(), "mailbox": (d / "mailbox.raw").is_file()},
            # The caller passes it back as rebundle --expect-revision (spec r3 7.5 step 1).
            "bundle_selection_revision": launch.get("bundle_selection_revision", 0)}
           if launch else {}),
    }


# ---- create ---------------------------------------------------------------------

def host_taken() -> tuple[set[str], list[ipaddress.IPv4Network]]:
    links = run("ip", "-o", "link", "show", check=False).stdout
    names = {m.group(1) for m in re.finditer(r"^\d+:\s+([^:@\s]+)", links, re.M)}
    addrs = run("ip", "-4", "-o", "addr", "show", check=False).stdout
    nets = [ipaddress.IPv4Interface(m.group(1)).network for m in re.finditer(r"\binet\s+(\S+)", addrs)]
    return names, nets


def allocate(port: int) -> int:
    used_slots = set()
    for other in all_vms():
        env = read_env(root() / other / "vm.env")
        if int(env["VM_SSH_PORT"]) == port:
            raise Refusal("port_in_use", f"ssh port {port} is used by VM {other}", 5)
        used_slots.add(int(env["VM_SLOT"]))
    # A host service already listening there would be shadowed by the forward.
    listening = run("ss", "-Hltn", f"sport = :{port}", check=False).stdout
    if listening.strip():
        raise Refusal("port_in_use", f"ssh port {port} is already listened on by this host", 5)
    links, nets = host_taken()
    for slot in range(SLOTS):
        net = ipaddress.IPv4Network((int(NET.network_address) + 4 * slot, 30))
        if slot in used_slots or f"cvm{slot}" in links or any(net.overlaps(n) for n in nets):
            continue
        return slot
    raise Refusal("no_free_link", "no free /30 in 10.216.0.0/16", 1)


# ---- the VM user, its disks and its unit (spec r2 7.1, 8.2) ----------------------------

def ensure_user(user: str) -> None:
    """One system user per VM. A user left by a delete cut before userdel owns no file: reused."""
    if run("getent", "passwd", user, check=False).returncode == 0:
        return
    run("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
        "--shell", "/usr/sbin/nologin", user)


SEV_RULE = f'KERNEL=="sev", GROUP="{SEV_GROUP}", MODE="0660"\n'


def ensure_sev_access() -> None:
    """QEMU opens /dev/sev unprivileged: rw for the cvm-sev group (the dedicated cg-sev pattern).

    Root keeps its access, so the hotel kits' QEMU (root) is not affected."""
    if run("getent", "group", SEV_GROUP, check=False).returncode != 0:
        run("groupadd", "--system", SEV_GROUP)
    rule = udev_rules_dir() / "60-cathedral-vm-sev.rules"
    try:
        if rule.read_text() == SEV_RULE:
            return
    except FileNotFoundError:
        pass
    udev_rules_dir().mkdir(parents=True, exist_ok=True)
    write_atomic(rule, SEV_RULE, 0o644)
    run("udevadm", "control", "--reload", check=False)
    run("udevadm", "trigger", "--action=change", "--sysname-match=sev", check=False)


def make_sparse(path: Path, size: int) -> None:
    """A new all-zero sparse file: the guest formats only a disk it reads as all zero (7.2)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.ftruncate(fd, size)
        os.fsync(fd)
    finally:
        os.close(fd)


def bundle_dir(bundle: str) -> Path:
    return root() / "bundles" / bundle


def unit_mounts(d: Path, env: dict) -> tuple[list[str], list[str], list[str]]:
    """(TemporaryFileSystem, BindReadOnlyPaths, BindPaths) of the VM unit.

    /srv is hidden, and VM_ROOT too when it is elsewhere, so one VM's QEMU sees no other VM and
    no kit. What launch-vm.py reads comes back read only: the kit code, the bundle, vm.env and
    the identity (Astra r2 P1 #2: without the last two the launcher cannot build its argv).
    What QEMU writes comes back read-write: the root and mailbox disks and run/ (QMP sockets)."""
    hidden = ["/srv:ro"]
    r = root().resolve()
    if r != Path("/srv") and Path("/srv") not in r.parents:
        hidden.append(f"{r}:ro")
    read_only = [str(KIT), str(bundle_dir(env["VM_BUNDLE"])), str(d / "vm.env"), str(d / "vm-identity.json")]
    read_write = [str(d / "root.raw"), str(d / "mailbox.raw"), str(d / "run")]
    return hidden, read_only, read_write


def unit_text(name: str, d: Path, env: dict) -> str:
    ctl, net, launch, gates = KIT / "vm-ctl.sh", KIT / "vm-net.sh", KIT / "launch-vm.py", KIT / "vm-gates.sh"
    vm_env, user = d / "vm.env", env["VM_USER"]
    hidden, read_only, read_write = unit_mounts(d, env)
    tmpfs = "".join(f"TemporaryFileSystem={h}\n" for h in hidden)
    mem = int(env["VM_MEM_GIB"]) + MEM_OVERHEAD_GIB
    # The dedicated unit (D 5.8) as the VM's own user, never root and no -runas. The '+' steps
    # run as root outside the sandbox: KVM, the credit check, the pre-launch gates (8.3, so a
    # host boot, a crash restart and a guest reboot pass them too), the link with a tap the VM
    # user owns, stale QMP sockets. Restart: a guest reset exits 75 and relaunches in the same
    # generation (check-paid needs its start line and no close line, so no new charge); a
    # poweroff exits 0 and stays down; a refused launch exits 78 and stays down.
    return f"""[Unit]
Description=Cathedral sealed customer VM {name}
After=network-online.target systemd-modules-load.service
Wants=network-online.target
StartLimitIntervalSec=900
StartLimitBurst=5
[Service]
Type=simple
User={user}
Group={user}
SupplementaryGroups=kvm {SEV_GROUP}
Environment=VM_ROOT={root()}
ExecStartPre=+-/sbin/modprobe -q kvm_amd
ExecStartPre=+/bin/sh -c 'for i in $$(seq 1 120); do [ -c /dev/kvm ] && exit 0; sleep 1; done; echo "no /dev/kvm after 120 s" >&2; exit 1'
ExecStartPre=+{ctl} check-paid {name}
ExecStartPre=+{gates} check {name}
ExecStartPre=+{net} up {vm_env}
ExecStartPre=+/bin/rm -f {d}/run/qmp.sock {d}/run/events.sock
ExecStart=/usr/bin/python3 -I {launch} {d}
ExecStop=+{ctl} powerdown {name}
ExecStopPost=+{net} down {vm_env}
KillSignal=SIGTERM
TimeoutStopSec=90
TimeoutStartSec=180
Restart=on-failure
RestartSec=15
RestartForceExitStatus=75
RestartPreventExitStatus=78
DevicePolicy=closed
DeviceAllow=/dev/kvm rw
DeviceAllow=/dev/sev rw
DeviceAllow=/dev/vhost-net rw
DeviceAllow=/dev/net/tun rw
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
{tmpfs}BindReadOnlyPaths={' '.join(read_only)}
BindPaths={' '.join(read_write)}
MemoryMax={mem}G
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
[Install]
WantedBy=multi-user.target
"""


def write_unit(name: str, d: Path, env: dict) -> None:
    unit_dir().mkdir(parents=True, exist_ok=True)
    write_atomic(unit_dir() / unit_name(name), unit_text(name, d, env), 0o644)


def write_env(d: Path, env: dict) -> None:
    write_atomic(d / "vm.env", "".join(f"{k}='{v}'\n" for k, v in env.items()), 0o644)


def unit_binds_bundle(name: str, bundle: str) -> bool:
    try:
        text = (unit_dir() / unit_name(name)).read_text()
    except FileNotFoundError:
        return False
    want = str(bundle_dir(bundle))
    return any(line.startswith("BindReadOnlyPaths=") and want in line.split("=", 1)[1].split()
               for line in text.splitlines())


def synced_revision(d: Path) -> int:
    """The bundle_selection_revision whose vm.env, unit file and daemon-reload are all done.
    No file: revision 0, which needs nothing (create writes all three)."""
    return read_json(d / "selection-synced.json", {"revision": 0})["revision"]


def selection_synced(name: str, d: Path) -> bool:
    launch = read_json(d / "launch.json", {})
    bundle = launch.get("bundle")
    if not bundle:
        return True  # a VM from before AB#999 VM3: no sealed bundle
    return (synced_revision(d) == launch.get("bundle_selection_revision", 0)
            and read_env(d / "vm.env").get("VM_BUNDLE") == bundle and unit_binds_bundle(name, bundle))


def sync_selection(name: str, d: Path) -> None:
    """launch.json is the commit point of the VM's bundle: rebundle changes it in one rename.
    vm.env's VM_BUNDLE (read by launch-vm.py and the start gates), the unit's bundle bind and
    systemd's copy of the unit follow it, in that order, and selection-synced.json records the
    revision once all three are done. A rebundle cut anywhere after its commit leaves them
    behind; this finishes them. Under the VM lock: on every rebundle, and in start before any
    gate or launch reads VM_BUNDLE. The marker, not the unit file, says whether systemd reloaded:
    a cut between the unit write and daemon-reload leaves a right file and a stale systemd."""
    if selection_synced(name, d):
        return
    launch = read_json(d / "launch.json", {})
    env = read_env(d / "vm.env")
    if env.get("VM_BUNDLE") != launch["bundle"]:
        env["VM_BUNDLE"] = launch["bundle"]
        write_env(d, env)
    write_unit(name, d, env)
    systemctl("daemon-reload")
    write_atomic(d / "selection-synced.json",
                 json.dumps({"revision": launch.get("bundle_selection_revision", 0)}) + "\n")


def ensure_enforce_timer() -> None:
    svc, timer = unit_dir() / "cathedral-vm-enforce.service", unit_dir() / "cathedral-vm-enforce.timer"
    write_atomic(svc, f"""[Unit]
Description=Cathedral customer VMs: stop any VM past paid_through, compare the SEV status
[Service]
Type=oneshot
Environment=VM_ROOT={root()}
# A oneshot has no start timeout by default and a timer never starts a second copy of a running
# service: a wedged pass would end every later credit cutoff. The pass bounds its own history I/O.
TimeoutStartSec=180
ExecStart={KIT / 'vm-ctl.sh'} enforce
# The SEV status against its baseline (8.3, D 5.9): a change refuses new starts and leaves running
# VMs alone; its journal line is the alert. '-': the credit cutoff above never depends on it.
ExecStart=-{KIT / 'vm-gates.sh'} enforce
""", 0o644)
    write_atomic(timer, """[Unit]
Description=Cathedral customer VMs: credit cutoff every 30 s
[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=1s
[Install]
WantedBy=timers.target
""", 0o644)
    systemctl("daemon-reload")
    systemctl("enable", "--now", "cathedral-vm-enforce.timer")


def cmd_create(args: list[str], key_text: str | None) -> dict:
    opts = parse_opts(args, {"--vcpus", "--mem-gib", "--disk-gib", "--ssh-key-file", "--ssh-port", "--bundle"}, 1)
    name = check_name(opts["_"][0])
    for req in ("--vcpus", "--mem-gib", "--disk-gib", "--ssh-port"):
        if req not in opts:
            raise Refusal("missing_option", f"create needs {req}")
    vcpus = check_int(opts["--vcpus"], "vcpus", 1, vm_measure.VCPUS_MAX)
    mem = check_int(opts["--mem-gib"], "mem_gib", 1, 512)
    disk = check_int(opts["--disk-gib"], "disk_gib", 4, 4096)
    port = check_int(opts["--ssh-port"], "ssh_port", 1024, 65535)
    if key_text is None:
        if "--ssh-key-file" not in opts:
            raise Refusal("missing_option", "create needs --ssh-key-file")
        try:
            key_text = Path(opts["--ssh-key-file"]).read_text()
        except (OSError, UnicodeDecodeError):
            raise Refusal("invalid_ssh_key", "cannot read --ssh-key-file") from None
    key = check_key(key_text)
    cfg = host_config()
    bundle = opts.get("--bundle", cfg["default_bundle"])
    if bundle not in cfg["bundles"]:
        raise Refusal("bundle_not_enabled", f"bundle {bundle[:64]} is not enabled on this host", 1)
    try:
        manifest, raw = vm_measure.read_manifest(bundle_dir(bundle))
    except vm_measure.Refusal as e:
        raise Refusal("no_bundle", f"bundle {bundle}: {e}", 1) from None
    if hashlib.sha256(raw).hexdigest() != bundle:
        raise Refusal("no_bundle", f"bundle {bundle}: the manifest is not the one its directory names", 1)
    # The broker names a VM by its id (vms.go vmIDRE), which the identity carries; an operator
    # name gets a fresh id.
    vm_id = name if vm_measure.VM_ID_RE.fullmatch(name) else "vm-" + secrets.token_hex(6)
    # The identity and its launch values first: nothing is written and no lock is held while
    # sev-snp-measure runs. The salt comes from the CSPRNG (vm_measure.identity_document).
    try:
        identity = vm_measure.identity_document(vm_id, key, manifest["base_root_verity"],
                                                manifest["base_root_data_bytes"])
        launch = vm_measure.launch_values(bundle_dir(bundle), identity, vcpus, cfg["cpu_family"],
                                          cfg.get("sev_snp_measure"))
    except vm_measure.Refusal as e:
        raise Refusal("launch_values", str(e), 1) from None
    launch["vm_id"] = vm_id
    with global_lock():
        d = root() / name
        if d.exists() or d.is_symlink():
            raise Refusal("exists", f"VM {name} exists", 5)
        if history_path(name).exists():
            raise Refusal("exists", f"name {name} was used before: its history is kept, pick a new name", 5)
        slot = allocate(port)
        base = int(NET.network_address) + 4 * slot
        user = vm_user(slot)
        env = {
            "VM_NAME": name, "VM_DIR": str(d), "VM_VCPUS": str(vcpus), "VM_MEM_GIB": str(mem),
            "VM_DISK_GIB": str(disk), "VM_SSH_PORT": str(port), "VM_SLOT": str(slot), "VM_TAP": f"cvm{slot}",
            "VM_HOST_IP": str(ipaddress.IPv4Address(base + 1)), "VM_GUEST_IP": str(ipaddress.IPv4Address(base + 2)),
            "VM_MAC": "52:54:00:d8:%02x:%02x" % (slot >> 8, slot & 0xFF),
            "VM_USER": user, "VM_ID": vm_id, "VM_BUNDLE": bundle, "VM_CREATED_AT": str(int(time.time())),
        }
        d.mkdir(mode=0o700)
        # The VM lock is held from before anything is published until create is done, and the
        # journal is initialised before vm.env makes the VM visible: no command can append to a
        # journal that create is still starting.
        with Lock(d / ".lock"):
            try:
                (d / "run").mkdir(mode=0o700)
                write_atomic(d / "vm-identity.json", identity.decode("ascii"), 0o644)
                write_atomic(d / "launch.json", json.dumps(launch, sort_keys=True) + "\n", 0o644)
                make_sparse(d / "root.raw", disk << 30)
                make_sparse(d / "mailbox.raw", MAILBOX_BYTES)
                ensure_sev_access()
                ensure_user(user)
                # QEMU writes only these; everything else in the VM directory stays root's.
                run("chown", "--no-dereference", f"{user}:{user}",
                    str(d / "root.raw"), str(d / "mailbox.raw"), str(d / "run"))
                write_atomic(d / "authorization.json",
                             json.dumps({"generation": 0, "paid_through": 0, "closed_generation": 0}) + "\n")
                history_append(name, {"event": "tracked_from", "generation": 1})
                write_atomic(d / "vm.env", "".join(f"{k}='{v}'\n" for k, v in env.items()), 0o644)
                write_unit(name, d, env)
                ensure_enforce_timer()
            except BaseException:
                h = read_history(name, durable=False)
                if [e["event"] for e in h["events"]] == ["tracked_from"]:
                    history_path(name).unlink(missing_ok=True)  # nothing ran: do not burn the name
                shutil.rmtree(d, ignore_errors=True)
                (unit_dir() / unit_name(name)).unlink(missing_ok=True)
                run("userdel", user, check=False)
                raise
    return status_of(name)


# ---- authorize, start, stop, reboot ------------------------------------------

def cmd_authorize(args: list[str]) -> dict:
    opts = parse_opts(args, set(), 3)
    name = check_name(opts["_"][0])
    paid = check_int(opts["_"][1], "paid_through", 0, 2**40)
    gen = check_int(opts["_"][2], "generation", 1, 2**53)
    d = vm_dir(name)
    with Lock(d / ".lock"):
        begin(name, d)
        a = auth_of(d)
        if gen < a["generation"]:
            raise Refusal("stale_generation", f"generation {gen} is older than {a['generation']}", 3)
        if gen <= a.get("closed_generation", 0):
            raise Refusal("generation_closed", f"generation {gen} was stopped and cannot run again", 3)
        if gen == a["generation"] and paid < a["paid_through"]:
            raise Refusal("paid_through_lower", f"paid_through {paid} is below {a['paid_through']}", 3)
        if gen > a["generation"]:
            refuse_if_running(name, a["generation"])
            close_open_generation(name, d, a, "superseded")
        changed = (gen, paid) != (a["generation"], a["paid_through"])
        if changed:
            a.update(generation=gen, paid_through=paid, authorized_at=int(time.time()))
            write_atomic(d / "authorization.json", json.dumps(a, sort_keys=True) + "\n")
    return {"name": name, "generation": gen, "paid_through": paid, "changed": changed}


def cmd_check_paid(args: list[str]) -> dict:
    name = check_name(parse_opts(args, set(), 1)["_"][0])
    d = vm_dir(name)
    a = auth_of(d)
    refusal = paid_refusal(a, int(time.time()))
    if refusal:
        raise refusal
    if not selection_synced(name, d):
        # A rebundle was cut after its commit: vm-ctl start (or the rebundle retry) syncs first.
        raise Refusal("selection_unsynced", "vm.env names another bundle than launch.json: use vm-ctl start", 3)
    # H2: no launch of a tracked generation without a durable start line, and none after a durable
    # close line (it is authoritative even when authorization.json missed it), and none from a
    # corrupt journal. Read only. No journal at all is a VM from before the upgrade: not gated.
    h = read_history(name)
    g = a["generation"]
    if event_of(h, "close", g):  # any parsable close line, even in a file that is corrupt elsewhere
        raise Refusal("generation_closed", "this run has a close line; authorize a new generation", 3)
    if h["corrupt"]:
        sys.stderr.write(f"history: {name}: corrupt journal, launch of generation {g} refused\n")
        raise Refusal("history_corrupt", f"the history journal of {name} is corrupt: no launch", 3)
    if is_tracked(h, g):
        if not event_of(h, "start", g):
            raise Refusal("start_not_recorded", f"generation {g} has no start line: use vm-ctl start", 3)
    return {"name": name, "paid": True}


def check_generation(opts: dict, a: dict) -> None:
    """--generation N fences a call to one run: a delayed call from an older run
    (at-least-once billing delivery) must not stop, start or reset the new one."""
    want = opts.get("--generation")
    if want is None:
        return
    if not re.fullmatch(r"[1-9][0-9]{0,17}", want):
        raise Refusal("invalid_generation", "generation must be a positive integer")
    if int(want) != a["generation"]:
        raise Refusal("stale_generation", f"generation {want} is not the current run ({a['generation']})", 3)


def cmd_start(args: list[str]) -> dict:
    opts = parse_opts(args, {"--generation"}, 1)
    name = check_name(opts["_"][0])
    d = vm_dir(name)
    with Lock(d / ".lock"):
        begin(name, d)
        sync_selection(name, d)  # before any gate or launch reads VM_BUNDLE (rebundle cut)
        check_generation(opts, auth_of(d))
        refusal = paid_refusal(auth_of(d), int(time.time())) or gate_refusal(name)
        if refusal:
            raise refusal  # a gate refusal leaves no start line, so nothing is billed (8.3)
        # H2: the start line is durable before anything can launch the run.
        g = auth_of(d)["generation"]
        h = read_history(name)
        if h["corrupt"]:
            raise Refusal("history_corrupt", f"the history journal of {name} is corrupt: no launch", 3)
        if is_tracked(h, g) and not event_of(h, "start", g):
            history_append(name, {"event": "start", "generation": g, **stamp()})
        (d / "started").touch()
        # Enabled while it should run, so it comes back after a host reboot.
        systemctl("enable", "-q", unit_name(name))
        systemctl("reset-failed", unit_name(name), check=False)
        systemctl("start", unit_name(name))
    return status_of(name)


def wait_inactive(name: str, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not unit_active(name):
            return True
        time.sleep(1)
    return not unit_active(name)


def stop_locked(name: str, d: Path, reason: str, wait: float | None = None) -> dict:
    # The physical stop comes first and never depends on history I/O (the credit cutoff). It always
    # runs disable and stop, even for a unit that looks inactive: a start job queued by a reboot
    # relaunch can still be pending, and `systemctl stop` cancels it.
    was_running = unit_active(name)
    # A delete that removed the unit and reloaded systemd, then crashed before removing the VM
    # directory, leaves nothing to disable or stop; both fail on a missing unit. Only a positively
    # verified absent, inactive unit gets this: any other unit still takes the unconditional stop.
    unit_gone = not was_running and unit_absent(name)
    # Disable first: whatever happens next, a host reboot must not bring it back.
    if not unit_gone:
        systemctl("disable", "-q", unit_name(name))
    graceful = False
    marker = powerdown_marker(d)
    if was_running:
        # The unit's ExecStop would ask again and wait again; this marker says it was asked.
        marker.touch()
    try:
        if was_running:
            graceful = qmp(name, "system_powerdown") and wait_inactive(name, STOP_WAIT if wait is None else wait)
        if not unit_gone:
            systemctl("stop", unit_name(name))
    finally:
        marker.unlink(missing_ok=True)
    if unit_active(name):
        raise Refusal("stop_failed", f"{unit_name(name)} is still active", 1)
    # Only now history: it may raise, with the VM already stopped.
    try:
        begin(name, d)
        a = auth_of(d)
        previous = read_json(d / "stop.json", {})
        g = a["generation"]
        h = hio(name, read_history, name)
        close = None
        if is_tracked(h, g):
            # H4: the close line is the one record of this stop. Reuse it, or write it first and make
            # it durable; authorization.json and stop.json are then rebuilt from it on every retry.
            close = event_of(h, "close", g) or hio(name, append_close, name, g, reason)
    except HistoryStalled:
        # Enforce only: the unit is down and the journal is not answering. Leave the close to the
        # next stop, cancel, delete or authorize (each runs stop_locked or recover_closure again).
        a = auth_of(d)
        fence = fence_pending_close(name, d, reason)
        return {"name": name, "stopped_at": fence["wall_us"] // 1_000_000, "generation": a["generation"],
                "paid_through": a["paid_through"], "reason": reason, "was_running": was_running,
                "graceful": graceful, "state": "stopped", "history_pending": True}
    if close is not None:
        stopped_at, reason = close["stopped_at"], close["reason"]
    elif not was_running and previous.get("generation") == g:
        # Opened before the upgrade (no history): the same run, stopped before: repeat the same evidence.
        stopped_at, reason = previous["stopped_at"], previous.get("reason", reason)
    else:
        stopped_at = int(time.time())
    # Close the run: this generation (and any older) can never start again.
    a["closed_generation"] = max(a.get("closed_generation", 0), g)
    write_atomic(d / "authorization.json", json.dumps(a, sort_keys=True) + "\n")
    evidence = {"name": name, "stopped_at": stopped_at, "generation": g,
                "paid_through": a["paid_through"], "reason": reason,
                "was_running": was_running, "graceful": graceful}
    write_atomic(d / "stop.json", json.dumps(evidence, sort_keys=True) + "\n")
    return {**evidence, "state": "stopped"}


def cmd_stop(args: list[str]) -> dict:
    opts = parse_opts(args, {"--generation"}, 1)
    name = check_name(opts["_"][0])
    d = vm_dir(name)
    with Lock(d / ".lock"):
        check_generation(opts, auth_of(d))
        return stop_locked(name, d, "requested")


def powerdown_marker(d: Path) -> Path:
    # In the root-owned VM directory, not in run/, which the VM's QEMU user can write.
    return d / "powerdown-sent"


def cmd_powerdown(args: list[str]) -> dict:
    """ExecStop of the unit (host shutdown, systemctl stop): ask the guest to power off first."""
    name = check_name(parse_opts(args, set(), 1)["_"][0])
    if powerdown_marker(root() / name).exists():
        return {"name": name, "powerdown_sent": False, "detail": "vm-ctl stop already asked and waited"}
    sent = qmp(name, "system_powerdown")
    pid = os.environ.get("MAINPID", "")
    deadline = time.monotonic() + STOP_WAIT
    while sent and pid.isdigit() and time.monotonic() < deadline and Path(f"/proc/{pid}").exists():
        time.sleep(1)
    return {"name": name, "powerdown_sent": sent}


def reboot_marker(d: Path) -> Path:
    return d / "reboot-pending.json"


def cmd_reboot(args: list[str]) -> dict:
    """A fenced relaunch in the same generation (spec r2 8.1): an SNP guest cannot be reset in
    the same QEMU. Ask the guest to power off, wait up to STOP_WAIT, then restart the unit. The
    generation keeps its start line and has no close line, so check-paid lets the relaunch
    through, no history line is added and nothing is charged again.

    reboot-pending.json names the generation before the powerdown and goes only after the
    restart is queued: a reboot cut between the two (Astra #789 P2) leaves the VM down with
    the marker, and a retry for that same paid, open generation relaunches it instead of
    answering not_running. stop, and any newer generation, make the marker inert."""
    opts = parse_opts(args, {"--generation"}, 1)
    name = check_name(opts["_"][0])
    d = vm_dir(name)
    with Lock(d / ".lock"):
        begin(name, d)
        a = auth_of(d)
        check_generation(opts, a)
        g = a["generation"]
        pending = reboot_marker(d)
        resume = read_json(pending, {}).get("generation") == g
        running = unit_active(name)
        if not running and not resume:
            pending.unlink(missing_ok=True)
            raise Refusal("not_running", f"VM {name} is not running", 5)
        # The relaunch passes the gates in ExecStartPre; ask first, so a host that would refuse
        # it leaves the running VM alone instead of powering it down (8.3).
        refusal = paid_refusal(a, int(time.time())) or gate_refusal(name)
        if refusal:
            raise refusal
        write_atomic(pending, json.dumps({"generation": g, "at": int(time.time())}) + "\n")
        marker = powerdown_marker(d)
        marker.touch()  # the unit's ExecStop would ask and wait again
        graceful = False
        try:
            if running:
                graceful = qmp(name, "system_powerdown") and wait_inactive(name, STOP_WAIT)
            systemctl("reset-failed", unit_name(name), check=False)
            systemctl("restart", unit_name(name))
        finally:
            marker.unlink(missing_ok=True)
        pending.unlink(missing_ok=True)
    return {"name": name, "rebooted_at": int(time.time()), "state": "running", "generation": g,
            "graceful": graceful, "resumed": resume and not running}


# ---- rebundle (spec r3 7.5 step 1) ----------------------------------------------------------

def incompatible(reason: str, detail: str) -> Refusal:
    return Refusal("bundle_incompatible", detail, EXIT_BUNDLE_INCOMPATIBLE, reason)


def selection_values(name: str, d: Path, launch: dict, bundle: str) -> dict:
    """Check 4 of spec r3 7.5 step 1, then the launch values of this VM's identity on B2. B2 must
    pass what create checks (enabled, its manifest is its id) and what start's gates check (a
    verified build of B2 for this host and the VM's vCPUs, or the VM is a canary: the vm_gates
    helpers themselves), and carry the identity's base root, which never changes. Any failure is
    bundle_incompatible (exit 20) with the check as its reason; nothing is written."""
    import vm_gates
    cfg = host_config()
    if bundle not in cfg["bundles"]:
        raise incompatible("bundle_not_enabled", f"bundle {bundle} is not enabled on this host")
    try:
        manifest, raw = vm_measure.read_manifest(bundle_dir(bundle))
    except vm_measure.Refusal as e:
        raise incompatible("no_bundle", f"bundle {bundle}: {e}") from None
    if hashlib.sha256(raw).hexdigest() != bundle:
        raise incompatible("no_bundle", f"bundle {bundle}: the manifest is not the one its directory names")
    env = read_env(d / "vm.env")
    vcpus = int(env["VM_VCPUS"])
    try:
        vm_gates.host_build_gate(vm_gates.host_config(), {"name": name, "bundle": bundle, "vcpus": vcpus})
    except vm_gates.GateRefusal as e:
        raise incompatible("no_verified_build", f"{e.error}: {e.detail}") from None
    try:
        with open(d / "vm-identity.json", "rb") as f:
            identity_raw = f.read(vm_measure.DOC_MAX + 1)
        identity = vm_measure.parse_identity(identity_raw)
    except (OSError, vm_measure.Refusal) as e:
        raise Refusal("launch_values", f"vm-identity.json: {e}", 1) from None
    if (identity["base_root_verity"], identity["base_root_data_bytes"]) != \
            (manifest["base_root_verity"], manifest["base_root_data_bytes"]):
        raise incompatible("base_root_differs", f"bundle {bundle} has another base root than this VM's identity")
    try:
        values = vm_measure.launch_values(bundle_dir(bundle), identity_raw, vcpus,
                                          cfg["cpu_family"], cfg.get("sev_snp_measure"))
    except vm_measure.Refusal as e:
        raise Refusal("launch_values", str(e), 1) from None
    values["vm_id"] = launch.get("vm_id", identity["vm_id"])
    return values


def cmd_rebundle(args: list[str]) -> dict:
    """Spec r3 7.5 step 1: select bundle B2 for a stopped VM (a restore is the same command back).

    Under the VM lock, in this order: (1) an op_id in selection_ops with the same generation,
    expect_revision and to returns its stored result and writes nothing; the same op_id with any
    other field is stale_selection (reason op_id_reused). (2) G must be the current generation,
    closed (or 0 for a VM never authorized), with the unit stopped: else stale_generation, exit 3.
    (3) expect_revision must equal bundle_selection_revision: else stale_selection, exit 19.
    (4) selection_values: else bundle_incompatible, exit 20. Then launch.json is written once (the
    commit point) with B2, its measurement, the revision + 1 and the op; vm.env and the unit
    follow (sync_selection), as start does again before its gates."""
    want = ("--generation", "--expect-revision", "--op-id", "--to")
    opts = parse_opts(args, set(want), 1)
    name = check_name(opts["_"][0])
    for req in want:
        if req not in opts:
            raise Refusal("missing_option", f"rebundle needs {req}")
    gen = check_int(opts["--generation"], "generation", 0, 2**53)
    expect = check_int(opts["--expect-revision"], "expect_revision", 0, 2**53)
    dst, op_id = opts["--to"], opts["--op-id"]
    if not BUNDLE_ID_RE.fullmatch(dst):
        raise Refusal("invalid_bundle", "--to is a bundle id (64 lowercase hex)")
    if not OP_ID_RE.fullmatch(op_id):
        raise Refusal("invalid_op_id", "--op-id is 32 lowercase hex (128 random bits)")
    d = vm_dir(name)
    with Lock(d / ".lock"):
        begin(name, d)
        launch = read_json(d / "launch.json", {})
        if not launch.get("bundle"):
            raise Refusal("not_sealed", f"VM {name} has no sealed launch record", 1)
        for op in launch.get("selection_ops", []):
            if op["op_id"] == op_id:
                if (op["generation"], op["expect_revision"], op["to"]) != (gen, expect, dst):
                    raise Refusal("stale_selection", "this op_id was applied to another request",
                                  EXIT_STALE_SELECTION, "op_id_reused")
                sync_selection(name, d)  # derived files only: a retry after a cut finishes them
                return {"name": name, "op_id": op_id, **op["result"]}
        a = auth_of(d)
        if gen != a["generation"]:
            raise Refusal("stale_generation", f"generation {gen} is not the current one ({a['generation']})", 3,
                          "not_current")
        if gen > a.get("closed_generation", 0):
            raise Refusal("stale_generation", f"generation {gen} is open: stop or cancel it first", 3,
                          "generation_open")
        if unit_active(name):
            raise Refusal("stale_generation", f"{unit_name(name)} is active", 3, "unit_active")
        revision = launch.get("bundle_selection_revision", 0)
        if expect != revision:
            raise Refusal("stale_selection", f"expect_revision {expect} is not the revision ({revision})",
                          EXIT_STALE_SELECTION, "revision_changed")
        values = selection_values(name, d, launch, dst)
        result = {"bundle": dst, "expected_measurement": values["expected_measurement"],
                  "bundle_selection_revision": revision + 1}
        ops = launch.get("selection_ops", []) + [
            {"op_id": op_id, "generation": gen, "expect_revision": expect, "to": dst, "result": result}]
        committed = {**launch, **values, "bundle_selection_revision": revision + 1,
                     "selection_ops": ops[-SELECTION_OPS_MAX:]}
        write_atomic(d / "launch.json", json.dumps(committed, sort_keys=True) + "\n", 0o644)
        sync_selection(name, d)
    return {"name": name, "op_id": op_id, **result}


# ---- delete, status, list, enforce ---------------------------------------------

def close_unreached_generation(name: str, d: Path) -> None:
    """Delete removes the VM directory, and with it any way to cancel: close the next generation as
    never started too, so a generation whose authorize never arrived is not history_open forever."""
    h = read_history(name)
    nxt = auth_of(d)["generation"] + 1
    if is_tracked(h, nxt) and not event_of(h, "close", nxt):
        append_close(name, nxt, "deleted")


def cmd_delete(args: list[str]) -> dict:
    opts = parse_opts(args, {"--confirm"}, 1)
    name = check_name(opts["_"][0])
    if opts.get("--confirm") != name:
        raise Refusal("confirm_required", f"delete needs --confirm {name}")
    with global_lock():
        gone = root() / name
        if not gone.exists() and not gone.is_symlink():
            # Idempotent: the broker repeats a delete whose answer was lost, or clears a
            # create that never reached the host. Nothing to stop or remove.
            return {"name": name, "deleted": True, "existed": False}
        d = vm_dir(name)
        with Lock(d / ".lock"):
            stop_locked(name, d, "deleted")
            close_unreached_generation(name, d)
            run(str(KIT / "vm-net.sh"), "down", str(d / "vm.env"), check=False)
            (unit_dir() / unit_name(name)).unlink(missing_ok=True)
            systemctl("daemon-reload", check=False)
            if d.resolve().parent != root().resolve():
                raise Refusal("unsafe_path", f"{d} is not inside {root()}", 1)
            user = read_env(d / "vm.env").get("VM_USER")
            shutil.rmtree(d)
            if user:
                # After the files it owned are gone; a delete cut before this leaves a user that
                # owns nothing, and the next create of that slot reuses it.
                run("userdel", user, check=False)
        if not all_vms():
            systemctl("disable", "--now", "cathedral-vm-enforce.timer", check=False)
            for f in ("cathedral-vm-enforce.timer", "cathedral-vm-enforce.service"):
                (unit_dir() / f).unlink(missing_ok=True)
            systemctl("daemon-reload", check=False)
    return {"name": name, "deleted": True}


def cmd_cancel(args: list[str]) -> dict:
    """H5: close generation G in any state. Above the authorized generation it is fenced; the
    authorized one is stopped (a never-started one just closes). A repeat returns the same record."""
    opts = parse_opts(args, set(), 2)
    name = check_name(opts["_"][0])
    g = check_int(opts["_"][1], "generation", 1, 2**53)
    d = vm_dir(name)
    with Lock(d / ".lock"):
        begin(name, d)
        a = auth_of(d)
        done = event_of(read_history(name), "close", g)
        if done and g == a["generation"]:
            # A retry of the current generation: rewrite closed_generation and stop.json from the
            # close line (a crash may have left them stale), through the same path as stop.
            stop_locked(name, d, "cancelled")
            return close_record(name, done)
        if done:
            return close_record(name, done)
        if g < a["generation"]:
            raise Refusal("stale_generation", f"generation {g} is older than {a['generation']}", 3)
        if g == a["generation"]:
            ev = stop_locked(name, d, "cancelled")
            done = event_of(read_history(name), "close", g)
            if done:
                return close_record(name, done)
            return {"name": name, "generation": g, "closed": True, "stopped_at": ev["stopped_at"],
                    "close_reason": ev["reason"]}
        # G was never authorized here. An open, unstarted lower generation is closed first, as
        # authorize does; a started one must be stopped first.
        refuse_if_running(name, a["generation"])
        close_open_generation(name, d, a, "superseded")
        if not is_tracked(read_history(name), g):
            raise Refusal("history_unknown", f"generation {g} is not tracked", 3)
        done = append_close(name, g, "cancelled")
        a = auth_of(d)
        a["closed_generation"] = max(a.get("closed_generation", 0), g)
        write_atomic(d / "authorization.json", json.dumps(a, sort_keys=True) + "\n")
        return close_record(name, done)


def clock_error(line: dict) -> int:
    """maxerror_us of a line whose clock is trusted, else history_unknown."""
    err = line.get("maxerror_us")
    if not line["synced"] or err is None or not 0 <= err <= MAX_CLOCK_ERROR_US:
        raise Refusal("history_unknown", f"the {line['event']} line has no trusted clock bound", 3)
    return err


def lower_bound_start(start: dict, close: dict) -> tuple[int, int]:
    """H8: (started_at in microseconds, total error subtracted), a lower bound on the real start.

    Same boot: elapsed CLOCK_BOOTTIME (it counts suspend), widened for a clock that runs 500 ppm
    slow (divide by 0.9995), anchored on the close wall time less its clock error, and never later
    than the start line's own wall time less its error. Different boots: the start line's wall
    time less its clock error."""
    if start["boot_id"] is not None and start["boot_id"] == close["boot_id"]:
        if start.get("boot_ns") is None or close.get("boot_ns") is None:
            raise Refusal("history_unknown", "no boot-time clock on the lines", 3)
        delta_ns = close["boot_ns"] - start["boot_ns"]
        if delta_ns < 0:
            raise Refusal("history_unknown", "boot clock went backwards", 3)
        start_err, close_err = clock_error(start), clock_error(close)
        elapsed = -(-delta_ns // 1000)
        widened = -(-elapsed * 10_000 // 9_995)
        started_us = min(close["wall_us"] - close_err - widened, start["wall_us"] - start_err)
        return started_us, close["wall_us"] - elapsed - started_us
    if start["boot_id"] is None or close["boot_id"] is None:
        raise Refusal("history_unknown", "boot id unavailable", 3)
    err = clock_error(start)
    started_us = start["wall_us"] - err
    if close["synced"] and started_us > close["wall_us"]:
        raise Refusal("history_unknown", "start is later than stop", 3)
    return started_us, err


def iso_us(us: int) -> str:
    t = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=us)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def cmd_history(args: list[str]) -> dict:
    """H8, H9: read only, no lock, works after delete."""
    opts = parse_opts(args, set(), 2)
    name = check_name(opts["_"][0])
    g = check_int(opts["_"][1], "generation", 1, 2**53)
    h = read_history(name)
    n = h["tracked_from"]
    if not h["exists"] or h["corrupt"] or n is None or g < n:
        raise Refusal("history_unknown", f"no trustworthy history for generation {g}", 3)
    close = event_of(h, "close", g)
    if close is None:
        raise Refusal("history_open", f"generation {g} is not closed", 3)
    start = event_of(h, "start", g)
    started_at, error_us = None, None
    if start is not None:
        started_us, error_us = lower_bound_start(start, close)
        # stopped_at is the close time floored to seconds: never report a start after it.
        started_us = min(started_us, close["stopped_at"] * 1_000_000)
        started_at = iso_us(started_us)
    return {"generation": g, "closed": True, "started_at": started_at, "started_at_error_us": error_us,
            "stopped_at": close["stopped_at"], "tracked_from": n, "close_reason": close["reason"], "history": "v2"}


def cmd_status(args: list[str]) -> dict:
    return status_of(check_name(parse_opts(args, set(), 1)["_"][0]))


def cmd_list(args: list[str]) -> dict:
    parse_opts(args, set(), 0)
    return {"vms": [status_of(n) for n in all_vms()]}


def begin_best_effort(name: str, d: Path) -> None:
    """The credit cutoff must never depend on history I/O: a failure here is logged, not raised."""
    try:
        begin(name, d)
    except Exception as e:
        sys.stderr.write(f"history: {name}: {type(e).__name__}: {e}\n")


def cmd_enforce(args: list[str]) -> dict:
    parse_opts(args, set(), 0)
    stopped, errors, names = [], [], all_vms()

    def cut(name: str) -> None:
        d = root() / name
        try:
            with Lock(d / ".lock", wait=20):
                # No history I/O before the stop: stop_locked does the physical cutoff first.
                # Re-check under the lock: an authorize may have landed since the scan.
                if unit_active(name) and paid_refusal(auth_of(d), int(time.time())):
                    with history_budget(HISTORY_BUDGET):
                        ev = stop_locked(name, d, "paid_through", CUTOFF_WAIT)
                    stopped.append({"name": name, "stopped_at": ev["stopped_at"], "generation": ev["generation"]})
                    if ev.get("history_pending"):
                        errors.append({"name": name, "error": "history_stalled", "detail": "stopped; close pending"})
        except Refusal as e:
            errors.append({"name": name, "error": e.error, "detail": e.detail})
        except Exception as e:  # one VM's failure must not hide or skip the others
            errors.append({"name": name, "error": "internal", "detail": type(e).__name__})

    expired = []
    for name in names:
        d = root() / name
        try:
            with Lock(d / ".lock", wait=20):
                if not unit_active(name):
                    # A failed "down" (or a crash) can leave the public SSH forward of a
                    # stopped VM behind, holding the port. Only for a VM that is stopped on
                    # purpose: unit down AND disabled. An enabled unit may be about to start
                    # (host boot, Restart=) and its ExecStartPre "up" must not race this.
                    # vm-ctl start enables it under the VM lock held here. "purge" removes
                    # only the tagged nat rules, under the same host lock as "up".
                    show = systemctl("show", "-p", "ActiveState", "-p", "UnitFileState", unit_name(name),
                                     check=False).stdout
                    props = dict(l.split("=", 1) for l in show.splitlines() if "=" in l)
                    if props.get("ActiveState") in ("inactive", "failed") and props.get("UnitFileState") == "disabled":
                        run(str(KIT / "vm-net.sh"), "purge", str(d / "vm.env"), check=False)
                    continue
                if paid_refusal(auth_of(d), int(time.time())):
                    expired.append(name)
                else:
                    # A firewall reload may have taken the link rules: put them back.
                    run(str(KIT / "vm-net.sh"), "check", str(d / "vm.env"), check=False)
        except Refusal as e:
            errors.append({"name": name, "error": e.error, "detail": e.detail})
        except Exception as e:
            errors.append({"name": name, "error": "internal", "detail": type(e).__name__})
    # All expired VMs are cut together: the slowest guest bounds the delay, not the sum.
    threads = [threading.Thread(target=cut, args=(n,)) for n in expired]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # History after every stop, inside a pass-wide window: a stalled journal must neither delay a
    # cutoff nor keep this service running into the next timer tick (systemd would not start one).
    sweep_end = time.monotonic() + HISTORY_SWEEP_BUDGET
    for name in names:
        if name in _stalled or time.monotonic() >= sweep_end:
            continue
        d = root() / name
        try:
            with Lock(d / ".lock", wait=5), history_budget(HISTORY_BUDGET):
                begin_best_effort(name, d)
        except Exception as e:
            sys.stderr.write(f"history: {name}: {type(e).__name__}: {e}\n")
    result = {"checked": len(names), "stopped": stopped, "at": int(time.time())}
    if errors:
        result["errors"] = errors
    return result


# ---- argument parsing --------------------------------------------------------------

def parse_opts(args: list[str], allowed: set[str], positional: int) -> dict:
    opts: dict = {"_": []}
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("--"):
            if a not in allowed or a in opts or i + 1 >= len(args):
                raise Refusal("invalid_option", f"unexpected option {a[:40]}")
            opts[a] = args[i + 1]
            i += 2
        else:
            opts["_"].append(a)
            i += 1
    if len(opts["_"]) != positional:
        raise Refusal("usage", f"expected {positional} argument(s)")
    return opts


BROKER_SAFE = re.compile(r"[A-Za-z0-9 ._-]{1,512}")


def from_broker() -> tuple[list[str], str | None]:
    """authorized_keys forced command: SSH_ORIGINAL_COMMAND split on spaces, never a shell."""
    raw = os.environ.get("SSH_ORIGINAL_COMMAND")
    if raw is None:
        raise Refusal("usage", "--from-broker needs SSH_ORIGINAL_COMMAND")
    if not BROKER_SAFE.fullmatch(raw):
        raise Refusal("invalid_command", "only letters, digits, space, '.', '_' and '-' are allowed")
    args = raw.split()
    if args and args[0] == "vm-ctl.sh":
        args = args[1:]
    if not args or args[0] not in COMMANDS:
        raise Refusal("invalid_command", "unknown subcommand")
    if args[0] == "create":
        if "--ssh-key-file" in args or "--image" in args:
            raise Refusal("invalid_option", "from the broker the key comes on stdin and the image is the pinned one")
        return args, sys.stdin.read(16385)
    return args, None


def main(argv: list[str]) -> int:
    try:
        key_text = None
        if argv[:1] == ["--from-broker"]:
            if len(argv) != 1:
                raise Refusal("usage", "--from-broker takes no arguments")
            argv, key_text = from_broker()
        if not argv:
            raise Refusal("usage", "usage: vm-ctl.sh " + "|".join(COMMANDS) + " ...")
        cmd, rest = argv[0], argv[1:]
        handlers = {
            "authorize": cmd_authorize, "start": cmd_start, "stop": cmd_stop, "reboot": cmd_reboot,
            "delete": cmd_delete, "status": cmd_status, "list": cmd_list, "enforce": cmd_enforce,
            "check-paid": cmd_check_paid, "powerdown": cmd_powerdown, "cancel": cmd_cancel,
            "history": cmd_history, "qmp-as-vm-user": cmd_qmp_as_vm_user, "rebundle": cmd_rebundle,
        }
        if cmd == "create":
            out(cmd_create(rest, key_text))
        elif cmd in handlers:
            out(handlers[cmd](rest))
        else:
            raise Refusal("unknown_command", "unknown subcommand")
        return 0
    except Refusal as e:
        out({"error": e.error, "detail": e.detail, **({"reason": e.reason} if e.reason else {})})
        return e.code
    except Exception as e:  # one JSON line, even on a bug
        out({"error": "internal", "detail": f"{type(e).__name__}: {e}"[:400]})
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
