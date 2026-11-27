"""Shared fakes for the custom guest host tests: a host root in tmp (CG_ROOT), a fake /proc
(CG_PROC), and fake systemctl, iptables, ip and friends on PATH. No root, no KVM."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CG = REPO / "ops" / "custom-guest"
HOST = CG / "custom-guest-host.sh"
HOTEL = "chi-ur-2"
LAUNCH = "cg-0123456789ab"

# State: {unit: {active, enabled, invocation, enter}}. A start of a kit unit runs its guard line
# (the 5.10 ExecStartPre of PR 2) and a start of a custom unit runs its "+" check-start hook,
# the way systemd would; a stop of a custom unit runs its ExecStopPost hook.
FAKE_SYSTEMCTL = r'''#!/usr/bin/env python3
import json, os, re, subprocess, sys, time, uuid
path = os.environ["FAKE_STATE"]
state = json.load(open(path)) if os.path.exists(path) else {}
argv = sys.argv[1:]
with open(path + ".log", "a") as log:
    log.write(" ".join(argv) + "\n")
flags = {a for a in argv if a.startswith("--")}
args = [a for a in argv if not a.startswith("--")]
props = []
if "-p" in args:
    rest = []
    i = 0
    while i < len(args):
        if args[i] == "-p":
            props.append(args[i + 1]); i += 2
        else:
            rest.append(args[i]); i += 1
    args = rest
verb, units = args[0], args[1:]
root = os.environ.get("CG_ROOT", "")
proc = os.environ.get("CG_PROC", "/proc")
def u(name):
    return state.setdefault(name, {"active": False, "enabled": False, "invocation": "", "enter": 0})
def unit_text(name):
    for d in ("/etc/systemd/system",):
        try:
            return open(root + d + "/" + name).read()
        except OSError:
            pass
    return ""
def spawn_qemu(name):
    pid = 100000 + len(os.listdir(proc)) if os.path.isdir(proc) else 100000
    d = os.path.join(proc, str(pid)); os.makedirs(d, exist_ok=True)
    os.symlink("/usr/bin/qemu-system-x86_64", d + "/exe")
    open(d + "/cgroup", "w").write(f"0::/system.slice/{name}\n")
    u(name)["pid"] = pid
def kill_qemu(name):
    pid = u(name).pop("pid", None)
    if pid:
        d = os.path.join(proc, str(pid))
        for f in os.listdir(d):
            os.remove(os.path.join(d, f))
        os.rmdir(d)
rc = 0
if verb == "show":
    name = units[0]; s = u(name)
    vals = {"ActiveState": "active" if s["active"] else s.get("result", "inactive"), "InvocationID": s["invocation"],
            "ActiveEnterTimestamp": f"@{s['enter']}" if s["enter"] else "", "UnitFileState": "enabled" if s["enabled"] else "disabled",
            "MainPID": str(s.get("pid", 0))}
    for p in props:
        print(f"{p}={vals.get(p, '')}")
elif verb == "is-enabled":
    print("enabled" if u(units[0])["enabled"] else "disabled"); rc = 0 if u(units[0])["enabled"] else 1
elif verb == "is-active":
    rc = 0 if u(units[0])["active"] else 3
elif verb == "daemon-reload":
    pass
elif verb == "start":
    for name in units:
        s = u(name)
        if s["active"]:
            continue
        text = unit_text(name)
        for line in text.splitlines():
            if line.startswith("ExecStartPre=") and "custom-guest.hold" in line:
                cmd = line.split("=", 1)[1]
                if subprocess.run(["/bin/sh", "-c", cmd.split("-c ", 1)[1].strip("'")]).returncode != 0:
                    rc = 1
            if line.startswith("ExecStartPre=+") and "check-start" in line:
                if subprocess.run(line.split("=", 1)[1][1:].split()).returncode != 0:
                    rc = 1
        if rc:
            s["result"] = "failed"; continue
        s["active"] = True; s["invocation"] = uuid.uuid4().hex; s["enter"] = int(time.time()); s.pop("result", None)
        if name.startswith(("room-sealed-", "custom-guest-cg-")) and not name.endswith(("-net.timer", "-net.service")):
            spawn_qemu(name)
        if name.startswith("room-sealed-") and os.environ.get("FAKE_KIT_WRITES"):
            sealed = root + "/srv/sealed-hotel-" + name[len("room-sealed-"):-len(".service")]
            for disk in ("scratch.raw", "data.raw"):
                with open(f"{sealed}/{disk}", "r+b") as f:
                    f.write(os.urandom(64))
elif verb in ("stop", "enable", "disable"):
    for name in units:
        s = u(name)
        if verb == "enable":
            s["enabled"] = True
        if verb == "disable":
            s["enabled"] = False
        if (verb == "stop" or ("--now" in flags and verb == "disable")) and s["active"]:
            s["active"] = False; kill_qemu(name)
            for line in unit_text(name).splitlines():
                if line.startswith("ExecStopPost=+") and "exited" in line:
                    subprocess.run(line.split("=", 1)[1][1:].split(), env={**os.environ, "SERVICE_RESULT": "success", "EXIT_STATUS": "0"})
        if "--now" in flags and verb == "enable" and not s["active"]:
            s["active"] = True; s["invocation"] = uuid.uuid4().hex; s["enter"] = int(time.time())
json.dump(state, open(path, "w"))
sys.exit(rc)
'''

FAKE_LOG = '#!/bin/sh\necho "$(basename "$0") $*" >> "$FAKE_STATE.tools"\n'
FAKE_OK = FAKE_LOG + "exit 0\n"
FAKE_FAIL = FAKE_LOG + "exit 1\n"
FAKE_CURL = FAKE_LOG + 'cat "$FAKE_STATE.attestation.json" 2>/dev/null || exit 22\n'
FAKE_RUNUSER = FAKE_LOG + 'shift 3\nexec "$@"\n'
FAKE_SEV = '#!/bin/sh\ncat "$FAKE_STATE.sev.json"\n'
FAKE_TIMEOUT = '#!/bin/sh\nwhile [ "${1#-}" != "$1" ]; do shift; done\nshift\nexec "$@"\n'


def sev_doc(mask_chip_id=0, guests=0) -> dict:
    return {"snp": {"api_major": 1, "api_minor": 58, "build_id": 10, "mask_chip_id": mask_chip_id, "mask_chip_key": 0,
                    "vlek_en": 0, "current_tcb": "0103030800000076", "reported_tcb": "0103030800000076",
                    "guest_count": guests, "state": 1},
            "sev": {"api_major": 1, "api_minor": 58, "build": 10, "owner": 1, "config_flags": 256, "state": 2,
                    "guest_count": guests}}


class Host:
    def __init__(self, tmp: Path, shared: bool = False):
        self.tmp = tmp
        self.root = tmp / "root"
        self.proc = tmp / "proc"
        self.bin = tmp / "bin"
        self.state = tmp / "systemd.json"
        for d in (self.root / "etc/cathedral", self.root / "etc/systemd/system", self.root / "run/lock",
                  self.root / "dev", self.proc, self.bin):
            d.mkdir(parents=True, exist_ok=True)
        fakes = {"systemctl": FAKE_SYSTEMCTL, "iptables": FAKE_FAIL, "ip6tables": FAKE_FAIL, "ip": FAKE_FAIL,
                 "sysctl": FAKE_OK, "flock": FAKE_OK, "ss": FAKE_OK, "chown": FAKE_OK, "getent": FAKE_OK,
                 "useradd": FAKE_OK, "groupadd": FAKE_OK, "curl": FAKE_CURL, "runuser": FAKE_RUNUSER,
                 "cg-sev-status": FAKE_SEV, "timeout": FAKE_TIMEOUT}
        for name, text in fakes.items():
            (self.bin / name).write_text(text)
            (self.bin / name).chmod(0o755)
        (self.root / "dev/sev").write_text("")
        (self.root / "dev/sev").chmod(0o600)
        self.set_sev(sev_doc())
        self.allow(shared=shared)
        self.sealed = self.add_hotel(HOTEL)
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", CG_ROOT=str(self.root),
                        CG_PROC=str(self.proc), FAKE_STATE=str(self.state), CG_SEV_STATUS=str(self.bin / "cg-sev-status"),
                        CG_BOOT_ID_FILE=str(tmp / "boot_id"), CG_LOCK_WAIT="2", CG_DISK_RESERVE_GIB="0", CG_POLL="0.05")
        (tmp / "boot_id").write_text("boot-1\n")
        for k in ("CATHEDRAL_SNP_LOCK_FD", "CATHEDRAL_SNP_LOCK_OWNER", "CG_DEADLINE", "CG_FAULT"):
            self.env.pop(k, None)

    def allow(self, shared: bool = False, hotel: str = HOTEL) -> None:
        line = f"shared_host_rehearsal {hotel}\n" if shared else f"{hotel}\n"
        (self.root / "etc/cathedral/custom-guest.allow").write_text(line)
        (self.root / "etc/cathedral/custom-guest.allow").chmod(0o644)

    def set_sev(self, doc: dict) -> None:
        Path(str(self.state) + ".sev.json").write_text(json.dumps(doc))

    def add_hotel(self, name: str, guard: bool = True, running: bool = True) -> Path:
        sealed = self.root / f"srv/sealed-hotel-{name}"
        (sealed / "images" / "b1").mkdir(parents=True, exist_ok=True)
        cur = sealed / "images" / "current"
        if not cur.exists():
            os.symlink("b1", cur)
        (sealed / "images/b1/expected-measurement").write_text("ab" * 48 + "\n")
        (sealed / "sealed.env").write_text(f"SEALED_NAME={name}\nSEALED_DIR={sealed}\nSEALED_MINER=1\n"
                                           "SEALED_VCPUS=56\nSEALED_MEM_GIB=640\nSEALED_TAP=snp0\n")
        for disk, size in (("scratch.raw", 1 << 20), ("data.raw", 1 << 20)):
            with open(sealed / disk, "wb") as f:
                f.write(os.urandom(4096))
                f.truncate(size)
        guard_line = (f"ExecStartPre=/bin/sh -c 'm={sealed}/custom-guest.hold; [ ! -e \"$m\" ] || "
                      "grep -q \"\\\"state\\\": *\\\"kit_start\\\"\" \"$m\"'\n") if guard else ""
        (self.root / f"etc/systemd/system/room-sealed-{name}.service").write_text(
            "[Service]\n" + guard_line + f"ExecStart={sealed}/launch-guest.sh {sealed}/sealed.env\n")
        (self.root / f"etc/systemd/system/room-sealed-{name}-net.service").write_text("[Service]\n")
        if running:
            self.systemctl("enable", f"room-sealed-{name}.service")
            self.systemctl("start", f"room-sealed-{name}.service")
        return sealed

    def systemctl(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([str(self.bin / "systemctl"), *args], capture_output=True, text=True,
                              env=getattr(self, "env", dict(os.environ, FAKE_STATE=str(self.state),
                                                            CG_ROOT=str(self.root), CG_PROC=str(self.proc))))

    def systemd(self) -> dict:
        return json.loads(self.state.read_text()) if self.state.exists() else {}

    def add_qemu(self, pid: int, unit: str) -> None:
        d = self.proc / str(pid)
        d.mkdir()
        os.symlink("/usr/bin/qemu-system-x86_64", d / "exe")
        (d / "cgroup").write_text(f"0::/system.slice/{unit}\n")

    def phase(self, phase: str, data: dict | None = None, extra: dict | None = None, **opts: str) -> tuple[int, dict]:
        argv = ["bash", str(HOST), phase, "--hotel", HOTEL, "--launch-id", LAUNCH]
        for k, v in opts.items():
            argv += [f"--{k.replace('_', '-')}", v]
        p = subprocess.run(argv, input=json.dumps(data or {}), capture_output=True, text=True,
                           env={**self.env, **(extra or {})}, timeout=120)
        lines = [ln for ln in p.stdout.splitlines() if ln.startswith("RESULT ")]
        assert lines, (p.stdout, p.stderr)
        return p.returncode, json.loads(lines[-1][7:])

    def journal(self) -> list[dict]:
        path = self.root / f"srv/custom-guest/{HOTEL}/host-journal.jsonl"
        if not path.exists():
            return []
        return [json.loads(x) for x in path.read_text().splitlines()]


def load_host_module(env: dict):
    """Import custom_guest_host.py with a test root (its paths are read at import)."""
    import importlib.util
    old = dict(os.environ)
    os.environ.update({k: v for k, v in env.items() if k.startswith(("CG_", "FAKE_"))})
    try:
        spec = importlib.util.spec_from_file_location("custom_guest_host_t", CG / "custom_guest_host.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        os.environ.clear()
        os.environ.update(old)
    return mod


__all__ = ["Host", "HOTEL", "LAUNCH", "REPO", "CG", "sev_doc", "load_host_module", "sys"]
