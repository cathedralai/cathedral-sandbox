#!/usr/bin/env python3
"""Run one sealed customer VM in the foreground (AB#999, VM runtime spec r2 8.1).

ExecStart of cathedral-vm-<name>.service, run as cvm-<slot> with no capabilities:

  python3 -I launch-vm.py <VM dir>          run QEMU, then exit 0, 75 or 1 (below)
  python3 -I launch-vm.py <VM dir> --print  print the argv as JSON, start nothing

Every value comes from root-owned files: <VM dir>/vm.env, <VM dir>/vm-identity.json, the
bundle manifest under $VM_ROOT/bundles/<id>/ and the host file HOST_CONFIG, never from the
environment. QEMU gets an argv list built by snp_qemu.snp_argv, the function the custom
guest launcher uses too: no shell runs, and there is no argv without the SNP object.
The measured cmdline and HOST_DATA are recomputed here from the identity document by
vm_measure.py, so a host-edited copy of them cannot reach QEMU.

Every launch refuses (exit 78, and the unit does not restart) unless HOST_CONFIG exists and
lists the VM's bundle: a host without it runs no VM, as the stub before this file did.
The vCPU model is always snp_qemu.VM_CPU_MODEL (EPYC-v4), with no flag or key to change it.

-no-reboot: a guest reset ends QEMU. QEMU starts paused (-S); the launcher stays its parent,
negotiates a second QMP socket, sends cont, and reads SHUTDOWN events there: a reset
exits 75 (the unit's RestartForceExitStatus, so the VM relaunches in the same generation),
a poweroff exits 0 (the unit stays down), anything else exits 1 (Restart=on-failure).
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

# -I keeps the script's directory off sys.path; the two modules beside this file are the kit's.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import snp_qemu  # noqa: E402
import vm_measure  # noqa: E402

HOST_CONFIG = "/etc/cathedral/snp-vm-host.json"
FW_CFG_NAMES = ("opt/cathedral/vm-identity.json", "opt/cathedral/link")
DRIVE_IDS = ("root", "base", "mailbox")
EXIT_POWEROFF, EXIT_RELAUNCH, EXIT_FAILED, EXIT_REFUSED = 0, 75, 1, 78
# QEMU ShutdownCause names. With -no-reboot every reset request ends QEMU with one of these.
RELAUNCH_REASONS = frozenset({"guest-reset", "host-qmp-system-reset"})
POWEROFF_REASONS = frozenset({"guest-shutdown", "host-qmp-quit", "host-signal", "host-ui"})
EVENTS_CONNECT_WAIT = 60.0
NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")
VM_NET = ipaddress.IPv4Network("10.216.0.0/16")
DOC_MAX = 16384


class LaunchError(Exception):
    pass


def read_env(path: str) -> dict:
    """vm.env as vm_ctl.py writes it: KEY='value' lines, nothing else is read."""
    env = {}
    with open(path, encoding="ascii") as f:
        for line in f.read(DOC_MAX + 1).splitlines():
            m = re.fullmatch(r"([A-Z][A-Z0-9_]*)='([^']*)'", line)
            if m:
                env[m.group(1)] = m.group(2)
    return env


def enabled_bundles(path: str) -> set[str]:
    try:
        with open(path, "rb") as f:
            doc = json.loads(f.read(DOC_MAX + 1))
    except FileNotFoundError:
        raise LaunchError(f"{path} is missing: this host runs no sealed VM") from None
    except ValueError:
        raise LaunchError(f"{path} is not JSON") from None
    bundles = doc.get("bundles") if isinstance(doc, dict) else None
    if not isinstance(bundles, list) or not all(isinstance(b, str) and re.fullmatch(r"[0-9a-f]{64}", b)
                                                for b in bundles):
        raise LaunchError(f"{path}: bundles must be a list of bundle ids")
    return set(bundles)


def vm_values(d: str, env: dict) -> dict:
    """The checked vm.env values the argv uses."""
    name = env.get("VM_NAME", "")
    if not NAME_RE.fullmatch(name) or os.path.realpath(env.get("VM_DIR", "")) != os.path.realpath(d) \
            or os.path.basename(d) != name:
        raise LaunchError("vm.env does not describe this VM directory")
    vcpus, mem = env.get("VM_VCPUS", ""), env.get("VM_MEM_GIB", "")
    if not (re.fullmatch(r"[1-9][0-9]{0,2}", vcpus) and int(vcpus) <= vm_measure.VCPUS_MAX
            and re.fullmatch(r"[1-9][0-9]{0,2}", mem) and int(mem) <= 512):
        raise LaunchError("VM_VCPUS or VM_MEM_GIB out of range")
    slot = env.get("VM_SLOT", "")
    if not re.fullmatch(r"[0-9]{1,5}", slot) or int(slot) >= VM_NET.num_addresses // 4:
        raise LaunchError("bad VM_SLOT")
    base = int(VM_NET.network_address) + 4 * int(slot)
    host_ip, guest_ip = str(ipaddress.IPv4Address(base + 1)), str(ipaddress.IPv4Address(base + 2))
    if env.get("VM_TAP") != f"cvm{slot}" or env.get("VM_HOST_IP") != host_ip or env.get("VM_GUEST_IP") != guest_ip:
        raise LaunchError("VM_TAP, VM_HOST_IP or VM_GUEST_IP is not the link of VM_SLOT")
    if not re.fullmatch(r"52:54:00:d8(:[0-9a-f]{2}){2}", env.get("VM_MAC", "")):
        raise LaunchError("bad VM_MAC")
    bundle = env.get("VM_BUNDLE", "")
    if not re.fullmatch(r"[0-9a-f]{64}", bundle):
        raise LaunchError("bad VM_BUNDLE")
    return {"name": name, "vcpus": int(vcpus), "mem_gib": int(mem), "tap": env["VM_TAP"], "mac": env["VM_MAC"],
            "host_ip": host_ip, "guest_ip": guest_ip, "bundle": bundle}


def paths_of(d: str, bundle: str) -> dict:
    """Every file the argv names. cathedral-vm-<name>.service must expose each of them."""
    b = os.path.join(os.path.dirname(d), "bundles", bundle)
    return {"bundle": b, "identity": os.path.join(d, "vm-identity.json"), "root": os.path.join(d, "root.raw"),
            "mailbox": os.path.join(d, "mailbox.raw"), "base": os.path.join(b, "base-root.raw"),
            "qmp": os.path.join(d, "run", "qmp.sock"), "events": os.path.join(d, "run", "events.sock")}


def build_argv(d: str) -> list[str]:
    v = vm_values(d, read_env(os.path.join(d, "vm.env")))
    if v["bundle"] not in enabled_bundles(HOST_CONFIG):
        raise LaunchError(f"bundle {v['bundle'][:12]} is not enabled on this host")
    p = paths_of(d, v["bundle"])
    manifest, manifest_raw = vm_measure.read_manifest(Path(p["bundle"]))
    if hashlib.sha256(manifest_raw).hexdigest() != v["bundle"]:
        raise LaunchError("the bundle manifest is not the one its directory names")
    if manifest["cpu_model"] != snp_qemu.VM_CPU_MODEL:
        raise LaunchError(f"the bundle was measured for {manifest['cpu_model']}, not {snp_qemu.VM_CPU_MODEL}")
    with open(p["identity"], "rb") as f:
        identity_raw = f.read(DOC_MAX + 1)
    identity = vm_measure.parse_identity(identity_raw)
    if (identity["base_root_verity"], identity["base_root_data_bytes"]) != \
            (manifest["base_root_verity"], manifest["base_root_data_bytes"]):
        raise LaunchError("the identity names another base root than the bundle")
    line = vm_measure.cmdline(manifest["cmdline_template"], hashlib.sha256(identity_raw).hexdigest())
    hd = base64.b64encode(vm_measure.host_data(identity_raw)).decode()

    def disk(drive_id: str, path: str, readonly: bool) -> list[str]:
        ro = "readonly=on," if readonly else ""
        return ["-drive", f"if=none,id={drive_id},format=raw,{ro}file={path},cache=none,aio=io_uring",
                "-device", f"virtio-blk-pci,drive={drive_id},serial=cathedral-{drive_id},disable-legacy=on,"
                           "iommu_platform=true"]

    devices = disk("root", p["root"], False) + disk("base", p["base"], True) + disk("mailbox", p["mailbox"], False)
    devices += ["-netdev", f"tap,id=net0,ifname={v['tap']},script=no,downscript=no,vhost=on",
                "-device", f"virtio-net-pci,netdev=net0,mac={v['mac']},disable-legacy=on,iommu_platform=true,"
                           "romfile="]
    # The link in the kit's format (launch-guest.sh): "<host ip> <guest ip>", one argv element.
    devices += ["-fw_cfg", f"name={FW_CFG_NAMES[0]},file={p['identity']}",
                "-fw_cfg", f"name={FW_CFG_NAMES[1]},string={v['host_ip']} {v['guest_ip']}"]
    argv = snp_qemu.sealed_vm_argv(
        name=f"cathedral-vm-{v['name']}", vcpus=v["vcpus"], mem_gib=v["mem_gib"],
        host_data_b64=hd, ovmf=os.path.join(p["bundle"], "OVMF.amdsev.fd"),
        kernel=os.path.join(p["bundle"], "vmlinuz"), initrd=os.path.join(p["bundle"], "initrd.cpio.zst"),
        cmdline=line, devices=devices, qmp_sockets=[p["qmp"], p["events"]])
    check_argv(argv, d, v["bundle"])
    return argv


def check_argv(argv: list[str], d: str, bundle: str) -> None:
    """The shared SNP property, plus this launcher's own: three drives, two fw_cfg names, one tap."""
    snp_qemu.check_snp_argv(argv)
    if snp_qemu.values_of(argv, "-cpu") != [snp_qemu.VM_CPU_MODEL]:
        raise LaunchError(f"a sealed VM runs only the {snp_qemu.VM_CPU_MODEL} vCPU model")
    if argv.count("-S") != 1:
        raise LaunchError("QEMU must start paused: the launcher lets the guest run after it listens for events")
    p = paths_of(d, bundle)
    fw = [x.split(",", 1)[0] for x in snp_qemu.values_of(argv, "-fw_cfg")]
    if fw != [f"name={n}" for n in FW_CFG_NAMES]:
        raise LaunchError("exactly the two fw_cfg names")
    want = {"root": (p["root"], False), "base": (p["base"], True), "mailbox": (p["mailbox"], False)}
    seen = []
    for drive in snp_qemu.values_of(argv, "-drive"):
        fields = dict(f.split("=", 1) for f in drive.split(",") if "=" in f)
        did = fields.get("id")
        if did not in want or did in seen or fields.get("file") != want[did][0] \
                or (fields.get("readonly") == "on") != want[did][1] or fields.get("format") != "raw":
            raise LaunchError("a drive other than root (rw), base (read only) and mailbox (rw)")
        seen.append(did)
    if seen != list(DRIVE_IDS):
        raise LaunchError("the root, base and mailbox drives, in that order")
    nets = snp_qemu.values_of(argv, "-netdev")
    if len(nets) != 1 or not nets[0].startswith("tap,id=net0,ifname=cvm"):
        raise LaunchError("one tap netdev")


# ---- run -------------------------------------------------------------------------------

def exit_code(qemu_rc: int, reason: str | None) -> int:
    """The unit's exit code for one QEMU run: 75 relaunches, 0 stays down, 1 is a failure.

    A clean QEMU exit with no SHUTDOWN event seen counts as a poweroff (Astra #789 P2
    fallback): staying down is the safe side, and the watcher's own failures exit 1 in run()."""
    if reason in RELAUNCH_REASONS:
        return EXIT_RELAUNCH
    if qemu_rc == 0 and (reason is None or reason in POWEROFF_REASONS):
        return EXIT_POWEROFF
    return EXIT_FAILED


def _reply(f, box: dict) -> dict:
    """The next command reply on a QMP stream, recording any SHUTDOWN event read before it."""
    while True:
        raw = f.readline()
        if not raw:
            raise OSError("QMP closed")
        msg = json.loads(raw)
        if not isinstance(msg, dict):
            continue
        if "event" in msg:
            if msg.get("event") == "SHUTDOWN" and isinstance(msg.get("data"), dict):
                box["reason"] = msg["data"].get("reason")
            continue
        return msg


def watch_shutdown(path: str, proc: subprocess.Popen, box: dict) -> None:
    """Negotiate the events socket, then let the guest run (cont), then record the reason of
    the last SHUTDOWN event. QEMU starts paused (-S) and sends no event before negotiation, so
    a guest can power off only after this watcher listens (Astra #789 P2). If the socket
    cannot be reached or cont fails, QEMU is ended and the run counts as a failure."""
    deadline = time.monotonic() + EVENTS_CONNECT_WAIT
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        while True:
            try:
                s.connect(path)
                break
            except OSError:
                if proc.poll() is not None:
                    return
                if time.monotonic() > deadline:
                    box["error"] = "events socket unreachable"
                    proc.terminate()
                    return
                time.sleep(0.05)
        f = s.makefile("rwb")
        f.readline()  # greeting
        for command in ("qmp_capabilities", "cont"):
            f.write(json.dumps({"execute": command}).encode() + b"\n")
            f.flush()
            if "return" not in _reply(f, box):
                box["error"] = f"QMP {command} refused"
                proc.terminate()
                return
        box["running"] = True
        while True:
            _reply(f, box)  # only events follow; returns at EOF by raising
    except (OSError, ValueError) as e:
        if not box.get("running") and proc.poll() is None:
            box["error"] = f"events socket: {type(e).__name__}"
            proc.terminate()
        return
    finally:
        s.close()


def run(argv: list[str], events: str) -> int:
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, close_fds=True)
    # systemd stops the unit with SIGTERM to the whole cgroup; pass it on and wait for QEMU's own end.
    previous = {sig: signal.signal(sig, lambda signum, _frame: proc.send_signal(signum))
                for sig in (signal.SIGTERM, signal.SIGINT)}
    box: dict = {}
    watcher = threading.Thread(target=watch_shutdown, args=(events, proc, box), daemon=True)
    watcher.start()
    try:
        rc = proc.wait()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    watcher.join(5)
    code = EXIT_FAILED if box.get("error") else exit_code(rc, box.get("reason"))
    print(f"launch-vm: qemu exit {rc}, shutdown reason {box.get('reason') or 'none seen'}"
          f"{', ' + box['error'] if box.get('error') else ''}, exit {code}", file=sys.stderr)
    return code


def main(args: list[str]) -> int:
    if not args or len(args) > 2 or (len(args) == 2 and args[1] != "--print"):
        print("usage: launch-vm.py <VM dir> [--print]", file=sys.stderr)
        return 2
    d = os.path.realpath(args[0])
    try:
        argv = build_argv(d)
        if len(args) == 1 and os.geteuid() == 0:
            raise LaunchError("QEMU runs as the VM's own user, never as root")
    except (LaunchError, snp_qemu.SnpArgvError, vm_measure.Refusal, OSError, ValueError, KeyError) as e:
        print(f"launch-vm: refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    if len(args) == 2:
        print(json.dumps(argv))
        return 0
    return run(argv, os.path.join(d, "run", "events.sock"))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
