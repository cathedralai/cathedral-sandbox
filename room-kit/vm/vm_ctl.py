#!/usr/bin/env python3
"""Host runtime for long-lived customer VMs (AB#991). Run through vm-ctl.sh.

One VM is one directory $VM_ROOT/<name>/ (vm.env, disk.qcow2, seed.iso,
authorization.json, stop.json, run/) and one systemd unit
cathedral-vm-<name>.service that runs QEMU/KVM. Every command prints one JSON
line on stdout; a refusal prints {"error": ...} and exits nonzero:
  2 invalid request, 3 authorization refused, 4 unpaid, 5 no such VM or exists, or
  {"error": "host_capacity", "resource": ...} from create and start (vm_capacity.py), 1 anything else.

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
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

KIT = Path(__file__).resolve().parent


def capacity():
    """vm_capacity.py, loaded on first use. Only create, start and capacity load it, so stop and
    enforce (the credit cutoff) never depend on it. Loaded by path: vm-ctl.sh runs python3 -I,
    which keeps this directory off sys.path."""
    mod = sys.modules.get("vm_capacity")
    if mod is None:
        spec = importlib.util.spec_from_file_location("vm_capacity", KIT / "vm_capacity.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod  # dataclasses look the module up while the class is made
        spec.loader.exec_module(mod)
    return mod
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
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
            "cancel", "history")
STOP_WAIT = int(os.environ.get("VM_STOP_WAIT", "60"))
# Credit cutoff: a short grace, and every expired VM at once, so one guest that ignores
# the powerdown cannot keep the next one running past its paid_through.
CUTOFF_WAIT = int(os.environ.get("VM_CUTOFF_WAIT", "15"))
# History is best effort inside enforce: one VM's history I/O gets this long (a pass-wide window for
# the sweep), then it is abandoned so a stalled disk cannot hold the oneshot service or a VM lock.
HISTORY_BUDGET = float(os.environ.get("VM_HISTORY_BUDGET", "5"))
HISTORY_SWEEP_BUDGET = float(os.environ.get("VM_HISTORY_SWEEP_BUDGET", "15"))


class Refusal(Exception):
    def __init__(self, error: str, detail: str = "", code: int = 2, **extra):
        super().__init__(detail or error)
        self.error, self.detail, self.code, self.extra = error, detail, code, extra


def root() -> Path:
    return Path(os.environ.get("VM_ROOT", "/srv/cathedral-vms"))


def unit_dir() -> Path:
    return Path(os.environ.get("SYSTEMD_UNIT_DIR", "/etc/systemd/system"))


def unit_name(name: str) -> str:
    return f"cathedral-vm-{name}.service"


def out(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, sort_keys=True) + "\n")


def check_name(name: str) -> str:
    if name == ".history" or not isinstance(name, str) or not NAME_RE.fullmatch(name):
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


# ---- host admission (AB#999 VM spec r2 section 9, vm_capacity.py) ---------------------

def admit(check, *args) -> None:
    try:
        check(*args)
    except capacity().CapacityRefusal as e:
        raise Refusal("host_capacity", e.detail, 5, resource=e.resource) from None


def hold_capacity_lock(stack: contextlib.ExitStack) -> None:
    """The host capacity lock until the stack closes. Only create and start take it, never stop,
    enforce, cancel or delete, so the credit cutoff never waits on it."""
    try:
        stack.enter_context(capacity().capacity_lock())
    except capacity().CapacityBusy as e:
        raise Refusal("busy", str(e), 1) from None


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


def qmp(name: str, command: str, timeout: float = 5) -> bool:
    """Send one QMP command; False when QEMU is not there to take it."""
    path = root() / name / "run" / "qmp.sock"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(str(path))
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


# ---- authorization -------------------------------------------------------------

def auth_of(d: Path) -> dict:
    return read_json(d / "authorization.json", {"generation": 0, "paid_through": 0, "closed_generation": 0})


def paid_refusal(a: dict, now: int) -> Refusal | None:
    if a["generation"] <= a.get("closed_generation", 0):
        return Refusal("generation_closed", "this run was stopped; authorize a new generation to start again", 3)
    if now >= a["paid_through"]:
        return Refusal("unpaid", f"paid_through {a['paid_through']} is not after now {now}", 4)
    return None


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
    }


# ---- create ---------------------------------------------------------------------

def image_lock() -> dict:
    vals = {}
    for line in (KIT / "images.lock").read_text().splitlines():
        m = re.fullmatch(r"(IMAGE_[A-Z0-9]+)=(\S+)", line.strip())
        if m:
            vals[m.group(1)] = m.group(2)
    return vals


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


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


def make_seed(d: Path, name: str, key: str, env: dict) -> None:
    seed = d / "seed"
    seed.mkdir(mode=0o700)
    # JSON is YAML: every value is quoted by json.dumps, so a key cannot add keys.
    user_data = "#cloud-config\n" + json.dumps({
        "disable_root": True,
        "ssh_pwauth": False,
        "users": [{
            "name": "cathedral", "shell": "/bin/bash", "lock_passwd": True,
            "sudo": "ALL=(ALL) NOPASSWD:ALL", "groups": ["sudo"], "ssh_authorized_keys": [key],
        }],
    }, indent=1) + "\n"
    meta = json.dumps({"instance-id": f"cvm-{name}-{secrets.token_hex(6)}", "local-hostname": name}) + "\n"
    dns = os.environ.get("VM_DNS", "1.1.1.1 8.8.8.8").split()
    network = json.dumps({"version": 2, "ethernets": {"eth0": {
        "match": {"macaddress": env["VM_MAC"]}, "set-name": "eth0",
        "addresses": [env["VM_GUEST_IP"] + "/30"],
        "routes": [{"to": "default", "via": env["VM_HOST_IP"]}],
        "nameservers": {"addresses": dns},
    }}}) + "\n"
    for fname, text in (("user-data", user_data), ("meta-data", meta), ("network-config", network)):
        (seed / fname).write_text(text)
    iso = str(d / "seed.iso")
    if shutil.which("cloud-localds"):
        run("cloud-localds", "-N", str(seed / "network-config"), iso, str(seed / "user-data"), str(seed / "meta-data"))
    else:
        tool = shutil.which("genisoimage") or shutil.which("mkisofs")
        if not tool:
            raise Refusal("missing_tool", "need cloud-localds, genisoimage or mkisofs", 1)
        run(tool, "-quiet", "-output", iso, "-volid", "cidata", "-joliet", "-rock",
            str(seed / "user-data"), str(seed / "meta-data"), str(seed / "network-config"))


def write_unit(name: str, d: Path) -> None:
    ctl, net, launch = KIT / "vm-ctl.sh", KIT / "vm-net.sh", KIT / "launch-vm.sh"
    env = d / "vm.env"
    # Same shape as the sealed hotel unit (room-kit/sealed/write-units.sh): load
    # KVM, wait for /dev/kvm (late after a host reboot), restart on failure, at
    # most 5 starts in 15 min. Plus the credit check before every start, so a host
    # reboot or a crash restart never runs past paid_through.
    text = f"""[Unit]
Description=Cathedral customer VM {name}
After=network-online.target systemd-modules-load.service
Wants=network-online.target
StartLimitIntervalSec=900
StartLimitBurst=5
[Service]
Type=simple
Environment=VM_ROOT={root()}
ExecStartPre=-/sbin/modprobe -q kvm_amd
ExecStartPre=-/sbin/modprobe -q kvm_intel
ExecStartPre=/bin/sh -c 'for i in $$(seq 1 120); do [ -c /dev/kvm ] && exit 0; sleep 1; done; echo "no /dev/kvm after 120 s" >&2; exit 1'
ExecStartPre={ctl} check-paid {name}
ExecStartPre={net} up {env}
ExecStart={launch} {env}
ExecStop={ctl} powerdown {name}
ExecStopPost={net} down {env}
KillSignal=SIGTERM
TimeoutStopSec=90
TimeoutStartSec=180
Restart=on-failure
RestartSec=15
[Install]
WantedBy=multi-user.target
"""
    unit_dir().mkdir(parents=True, exist_ok=True)
    write_atomic(unit_dir() / unit_name(name), text, 0o644)


def ensure_enforce_timer() -> None:
    svc, timer = unit_dir() / "cathedral-vm-enforce.service", unit_dir() / "cathedral-vm-enforce.timer"
    write_atomic(svc, f"""[Unit]
Description=Cathedral customer VMs: stop any VM past paid_through
[Service]
Type=oneshot
Environment=VM_ROOT={root()}
# A oneshot has no start timeout by default and a timer never starts a second copy of a running
# service: a wedged pass would end every later credit cutoff. The pass bounds its own history I/O.
TimeoutStartSec=180
ExecStart={KIT / 'vm-ctl.sh'} enforce
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
    opts = parse_opts(args, {"--vcpus", "--mem-gib", "--disk-gib", "--ssh-key-file", "--ssh-port", "--image"}, 1)
    name = check_name(opts["_"][0])
    for req in ("--vcpus", "--mem-gib", "--disk-gib", "--ssh-port"):
        if req not in opts:
            raise Refusal("missing_option", f"create needs {req}")
    vcpus = check_int(opts["--vcpus"], "vcpus", 1, 64)
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
    lock = image_lock()
    if "--image" in opts:
        image = Path(opts["--image"]).resolve()
        pinned = None
    else:
        image = Path(os.environ.get("VM_BASE_IMAGE", root() / "images" / lock["IMAGE_FILE"]))
        pinned = lock["IMAGE_SHA256"]
    if not image.is_file():
        raise Refusal("no_image", f"base image {image} is missing (run fetch-image.sh)", 1)
    with global_lock(), contextlib.ExitStack() as admission:
        d = root() / name
        if d.exists() or d.is_symlink():
            raise Refusal("exists", f"VM {name} exists", 5)
        if history_path(name).exists():
            raise Refusal("exists", f"name {name} was used before: its history is kept, pick a new name", 5)
        slot = allocate(port)
        digest = sha256_file(image)
        if pinned and digest != pinned:
            raise Refusal("image_mismatch", f"{image} sha256 {digest} is not the pinned {pinned}", 1)
        admit(capacity().refuse_custom_guest_host)
        if capacity().enforced():
            # Check and record under one hold: vm.env, written below, is this VM's line in the
            # ledger. The lock is released when create returns.
            hold_capacity_lock(admission)
            admit(capacity().check_create, vcpus, mem, disk, d)
        base = int(NET.network_address) + 4 * slot
        env = {
            "VM_NAME": name, "VM_DIR": str(d), "VM_VCPUS": str(vcpus), "VM_MEM_GIB": str(mem),
            "VM_DISK_GIB": str(disk), "VM_SSH_PORT": str(port), "VM_SLOT": str(slot), "VM_TAP": f"cvm{slot}",
            "VM_HOST_IP": str(ipaddress.IPv4Address(base + 1)), "VM_GUEST_IP": str(ipaddress.IPv4Address(base + 2)),
            "VM_MAC": "52:54:00:d8:%02x:%02x" % (slot >> 8, slot & 0xFF),
            "VM_BASE_IMAGE": str(image), "VM_BASE_SHA256": digest, "VM_CREATED_AT": str(int(time.time())),
        }
        d.mkdir(mode=0o700)
        # The VM lock is held from before anything is published until create is done, and the
        # journal is initialised before vm.env makes the VM visible: no command can append to a
        # journal that create is still starting.
        with Lock(d / ".lock"):
            try:
                (d / "run").mkdir(mode=0o700)
                make_seed(d, name, key, env)
                run("qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(image),
                    str(d / "disk.qcow2"), f"{disk}G")
                write_atomic(d / "authorization.json",
                             json.dumps({"generation": 0, "paid_through": 0, "closed_generation": 0}) + "\n")
                history_append(name, {"event": "tracked_from", "generation": 1})
                write_atomic(d / "vm.env", "".join(f"{k}='{v}'\n" for k, v in env.items()), 0o644)
                write_unit(name, d)
                ensure_enforce_timer()
            except BaseException:
                h = read_history(name, durable=False)
                if [e["event"] for e in h["events"]] == ["tracked_from"]:
                    history_path(name).unlink(missing_ok=True)  # nothing ran: do not burn the name
                shutil.rmtree(d, ignore_errors=True)
                (unit_dir() / unit_name(name)).unlink(missing_ok=True)
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
    with Lock(d / ".lock"), contextlib.ExitStack() as admission:
        begin(name, d)
        check_generation(opts, auth_of(d))
        refusal = paid_refusal(auth_of(d), int(time.time()))
        if refusal:
            raise refusal
        # H2: the start line is durable before anything can launch the run.
        g = auth_of(d)["generation"]
        h = read_history(name)
        if h["corrupt"]:
            raise Refusal("history_corrupt", f"the history journal of {name} is corrupt: no launch", 3)
        if capacity().enforced():
            # Before the start line, so a refused start leaves no line and bills nothing.
            hold_capacity_lock(admission)
            admit(capacity().check_start, name)
        if is_tracked(h, g) and not event_of(h, "start", g):
            history_append(name, {"event": "start", "generation": g, **stamp()})
        (d / "started").touch()
        # Enabled while it should run, so it comes back after a host reboot.
        systemctl("enable", "-q", unit_name(name))
        # The enabled unit is this start's record in the ledger: the next start counts it.
        admission.close()
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
    marker = d / "run" / "powerdown-sent"
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


def cmd_powerdown(args: list[str]) -> dict:
    """ExecStop of the unit (host shutdown, systemctl stop): ask the guest to power off first."""
    name = check_name(parse_opts(args, set(), 1)["_"][0])
    if (root() / name / "run" / "powerdown-sent").exists():
        return {"name": name, "powerdown_sent": False, "detail": "vm-ctl stop already asked and waited"}
    sent = qmp(name, "system_powerdown")
    pid = os.environ.get("MAINPID", "")
    deadline = time.monotonic() + STOP_WAIT
    while sent and pid.isdigit() and time.monotonic() < deadline and Path(f"/proc/{pid}").exists():
        time.sleep(1)
    return {"name": name, "powerdown_sent": sent}


def cmd_reboot(args: list[str]) -> dict:
    opts = parse_opts(args, {"--generation"}, 1)
    name = check_name(opts["_"][0])
    d = vm_dir(name)
    with Lock(d / ".lock"):
        begin(name, d)
        check_generation(opts, auth_of(d))
        if not unit_active(name):
            raise Refusal("not_running", f"VM {name} is not running", 5)
        if not qmp(name, "system_reset"):
            raise Refusal("qmp_failed", "QEMU did not take system_reset", 1)
    return {"name": name, "rebooted_at": int(time.time()), "state": "running"}


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
            shutil.rmtree(d)
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


CAPACITY_FLAGS = {"--broker-max-vcpus": "max_vcpus", "--broker-max-mem-gib": "max_mem_gib",
                  "--broker-max-disk-gib": "max_disk_gib"}


def cmd_capacity(args: list[str]) -> dict:
    """Read only, no lock: the host ledger. Given the broker's maxima for this host, it also checks
    that they stay within the VM share left after the kits (spec section 9, an operator rule)."""
    opts = parse_opts(args, set(CAPACITY_FLAGS), 0)
    broker = {key: check_int(opts[flag], key, 0, 2**31) for flag, key in CAPACITY_FLAGS.items() if flag in opts}
    return capacity().report(broker or None)


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
            "history": cmd_history,
        }
        if cmd == "create":
            out(cmd_create(rest, key_text))
        elif cmd == "capacity":
            doc = cmd_capacity(rest)
            out(doc)
            return 0 if doc.get("broker_check", {}).get("ok", True) else 1
        elif cmd in handlers:
            out(handlers[cmd](rest))
        else:
            raise Refusal("unknown_command", "unknown subcommand")
        return 0
    except Refusal as e:
        out({"error": e.error, "detail": e.detail, **e.extra})
        return e.code
    except Exception as e:  # one JSON line, even on a bug
        out({"error": "internal", "detail": f"{type(e).__name__}: {e}"[:400]})
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
