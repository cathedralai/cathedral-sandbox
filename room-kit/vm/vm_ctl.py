#!/usr/bin/env python3
"""Host runtime for long-lived customer VMs (AB#991). Run through vm-ctl.sh.

One VM is one directory $VM_ROOT/<name>/ (vm.env, disk.qcow2, seed.iso,
authorization.json, stop.json, run/) and one systemd unit
cathedral-vm-<name>.service that runs QEMU/KVM. Every command prints one JSON
line on stdout; a refusal prints {"error": ...} and exits nonzero:
  2 invalid request, 3 authorization refused, 4 unpaid, 5 no such VM or exists,
  1 anything else.

Credit cutoff (polariscomputer#2290 rules 3, 5, 6) is enforced here, on the host,
so it holds with the API and the broker down:
- authorize is idempotent and monotonic: a lower generation is refused, the same
  generation may only keep or raise paid_through, a higher one replaces.
- start, and the unit's ExecStartPre, refuse when now >= paid_through.
- stop closes the run: its generation can never start again, so a resume needs
  a fresh generation and an old authorization cannot revive the VM.
- enforce (a timer, every 30 s) stops any running VM past paid_through. Disks
  are kept; only delete --confirm <name> removes one.
"""
from __future__ import annotations

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
import sys
import tempfile
import threading
import time
from pathlib import Path

KIT = Path(__file__).resolve().parent
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa")
NET = ipaddress.IPv4Network("10.216.0.0/16")
SLOTS = NET.num_addresses // 4
COMMANDS = ("create", "authorize", "start", "stop", "reboot", "delete", "status", "list", "enforce")
STOP_WAIT = int(os.environ.get("VM_STOP_WAIT", "60"))
# Credit cutoff: a short grace, and every expired VM at once, so one guest that ignores
# the powerdown cannot keep the next one running past its paid_through.
CUTOFF_WAIT = int(os.environ.get("VM_CUTOFF_WAIT", "15"))


class Refusal(Exception):
    def __init__(self, error: str, detail: str = "", code: int = 2):
        super().__init__(detail or error)
        self.error, self.detail, self.code = error, detail, code


def root() -> Path:
    return Path(os.environ.get("VM_ROOT", "/srv/cathedral-vms"))


def unit_dir() -> Path:
    return Path(os.environ.get("SYSTEMD_UNIT_DIR", "/etc/systemd/system"))


def unit_name(name: str) -> str:
    return f"cathedral-vm-{name}.service"


def out(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, sort_keys=True) + "\n")


def check_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
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
        raise Refusal("invalid_ssh_key", "not an ssh-ed25519, ecdsa-sha2-nistp* or ssh-rsa public key")
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
    with global_lock():
        d = root() / name
        if d.exists() or d.is_symlink():
            raise Refusal("exists", f"VM {name} exists", 5)
        slot = allocate(port)
        digest = sha256_file(image)
        if pinned and digest != pinned:
            raise Refusal("image_mismatch", f"{image} sha256 {digest} is not the pinned {pinned}", 1)
        base = int(NET.network_address) + 4 * slot
        env = {
            "VM_NAME": name, "VM_DIR": str(d), "VM_VCPUS": str(vcpus), "VM_MEM_GIB": str(mem),
            "VM_DISK_GIB": str(disk), "VM_SSH_PORT": str(port), "VM_SLOT": str(slot), "VM_TAP": f"cvm{slot}",
            "VM_HOST_IP": str(ipaddress.IPv4Address(base + 1)), "VM_GUEST_IP": str(ipaddress.IPv4Address(base + 2)),
            "VM_MAC": "52:54:00:d8:%02x:%02x" % (slot >> 8, slot & 0xFF),
            "VM_BASE_IMAGE": str(image), "VM_BASE_SHA256": digest, "VM_CREATED_AT": str(int(time.time())),
        }
        d.mkdir(mode=0o700)
        try:
            (d / "run").mkdir(mode=0o700)
            make_seed(d, name, key, env)
            run("qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(image),
                str(d / "disk.qcow2"), f"{disk}G")
            write_atomic(d / "authorization.json",
                         json.dumps({"generation": 0, "paid_through": 0, "closed_generation": 0}) + "\n")
            write_atomic(d / "vm.env", "".join(f"{k}='{v}'\n" for k, v in env.items()), 0o644)
            write_unit(name, d)
            ensure_enforce_timer()
        except BaseException:
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
        a = auth_of(d)
        if gen < a["generation"]:
            raise Refusal("stale_generation", f"generation {gen} is older than {a['generation']}", 3)
        if gen <= a.get("closed_generation", 0):
            raise Refusal("generation_closed", f"generation {gen} was stopped and cannot run again", 3)
        if gen == a["generation"] and paid < a["paid_through"]:
            raise Refusal("paid_through_lower", f"paid_through {paid} is below {a['paid_through']}", 3)
        changed = (gen, paid) != (a["generation"], a["paid_through"])
        if changed:
            a.update(generation=gen, paid_through=paid, authorized_at=int(time.time()))
            write_atomic(d / "authorization.json", json.dumps(a, sort_keys=True) + "\n")
    return {"name": name, "generation": gen, "paid_through": paid, "changed": changed}


def cmd_check_paid(args: list[str]) -> dict:
    name = check_name(parse_opts(args, set(), 1)["_"][0])
    refusal = paid_refusal(auth_of(vm_dir(name)), int(time.time()))
    if refusal:
        raise refusal
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
        check_generation(opts, auth_of(d))
        refusal = paid_refusal(auth_of(d), int(time.time()))
        if refusal:
            raise refusal
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
    a = auth_of(d)
    previous = read_json(d / "stop.json", {})
    was_running = unit_active(name)
    # Disable first: whatever happens next, a host reboot must not bring it back.
    systemctl("disable", "-q", unit_name(name))
    graceful = False
    if was_running:
        # The unit's ExecStop would ask again and wait again; this marker says it was asked.
        marker = d / "run" / "powerdown-sent"
        marker.touch()
        try:
            graceful = qmp(name, "system_powerdown") and wait_inactive(name, STOP_WAIT if wait is None else wait)
            systemctl("stop", unit_name(name))
        finally:
            marker.unlink(missing_ok=True)
        if unit_active(name):
            raise Refusal("stop_failed", f"{unit_name(name)} is still active", 1)
    if not was_running and previous.get("generation") == a["generation"]:
        # The same run, stopped before: repeat the same evidence.
        stopped_at, reason = previous["stopped_at"], previous.get("reason", reason)
    else:
        stopped_at = int(time.time())
    # Close the run: this generation (and any older) can never start again.
    a["closed_generation"] = max(a.get("closed_generation", 0), a["generation"])
    write_atomic(d / "authorization.json", json.dumps(a, sort_keys=True) + "\n")
    evidence = {"name": name, "stopped_at": stopped_at, "generation": a["generation"],
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
        check_generation(opts, auth_of(d))
        if not unit_active(name):
            raise Refusal("not_running", f"VM {name} is not running", 5)
        if not qmp(name, "system_reset"):
            raise Refusal("qmp_failed", "QEMU did not take system_reset", 1)
    return {"name": name, "rebooted_at": int(time.time()), "state": "running"}


# ---- delete, status, list, enforce ---------------------------------------------

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


def cmd_status(args: list[str]) -> dict:
    return status_of(check_name(parse_opts(args, set(), 1)["_"][0]))


def cmd_list(args: list[str]) -> dict:
    parse_opts(args, set(), 0)
    return {"vms": [status_of(n) for n in all_vms()]}


def cmd_enforce(args: list[str]) -> dict:
    parse_opts(args, set(), 0)
    stopped, errors, names = [], [], all_vms()

    def cut(name: str) -> None:
        d = root() / name
        try:
            with Lock(d / ".lock", wait=20):
                # Re-check under the lock: an authorize may have landed since the scan.
                if unit_active(name) and paid_refusal(auth_of(d), int(time.time())):
                    ev = stop_locked(name, d, "paid_through", CUTOFF_WAIT)
                    stopped.append({"name": name, "stopped_at": ev["stopped_at"], "generation": ev["generation"]})
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
            "check-paid": cmd_check_paid, "powerdown": cmd_powerdown,
        }
        if cmd == "create":
            out(cmd_create(rest, key_text))
        elif cmd in handlers:
            out(handlers[cmd](rest))
        else:
            raise Refusal("unknown_command", "unknown subcommand")
        return 0
    except Refusal as e:
        out({"error": e.error, "detail": e.detail})
        return e.code
    except Exception as e:  # one JSON line, even on a bug
        out({"error": "internal", "detail": f"{type(e).__name__}: {e}"[:400]})
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
