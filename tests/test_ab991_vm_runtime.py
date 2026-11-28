"""AB#991, AB#999: host runtime for sealed customer VMs (room-kit/vm). No KVM, no root:
fake systemctl, ip, iptables, user tools and sev-snp-measure on PATH, VM_ROOT in tmp,
a vector bundle and the host switch file (tests/vm_host_support.py)."""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

import vm_host_support

KIT = Path(__file__).resolve().parents[1] / "room-kit" / "vm"
CTL = KIT / "vm-ctl.sh"
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHoDtpqWFYgHInGUaI+YzF7+kVPelQqOMZroOCQpu3bE user@laptop"

FAKE_SYSTEMCTL = r'''#!/usr/bin/env python3
import json, os, sys
path = os.environ["FAKE_STATE"]
state = json.load(open(path)) if os.path.exists(path) else {}
args = [a for a in sys.argv[1:] if a not in ("-q", "--now", "--value")]
with open(path + ".log", "a") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
verb = args[0]
unit = args[-1]
u = state.setdefault(unit, {"active": False, "enabled": False})
if verb == "start": u["active"] = True
elif verb == "stop": u["active"] = False
elif verb == "enable":
    u["enabled"] = True
    if "--now" in sys.argv: u["active"] = True
elif verb == "disable":
    u["enabled"] = False
    if "--now" in sys.argv: u["active"] = False
elif verb == "show":
    act = "active" if u["active"] else "inactive"
    if "--value" in sys.argv: print(act)
    else: print(f"ActiveState={act}\nUnitFileState={'enabled' if u['enabled'] else 'disabled'}")
json.dump(state, open(path, "w"))
'''
FAKE_LOG = '#!/bin/sh\necho "$(basename "$0") $*" >> "$FAKE_STATE.tools"\n'
FAKE_QEMU_IMG = FAKE_LOG + 'eval "f=\\${$(($#-1))}"\n: > "$f"\n'
# -C (check) finds nothing, so "up" adds every rule.
FAKE_IPTABLES = FAKE_LOG + 'case " $* " in *" -C "*) exit 1;; esac\n'
FAKE_LOCALDS = FAKE_LOG + ': > "$3"\n'


@pytest.fixture
def host(tmp_path, monkeypatch):
    fake = tmp_path / "bin"
    fake.mkdir()
    for name, text in {"systemctl": FAKE_SYSTEMCTL, "qemu-img": FAKE_QEMU_IMG, "cloud-localds": FAKE_LOCALDS,
                       "ip": FAKE_LOG, "iptables": FAKE_IPTABLES, "ip6tables": FAKE_IPTABLES, "sysctl": FAKE_LOG,
                       "flock": FAKE_LOG, "ss": FAKE_LOG}.items():
        (fake / name).write_text(text)
        (fake / name).chmod(0o755)
    sealed = vm_host_support.sealed_host(tmp_path, fake)
    (tmp_path / "id.pub").write_text(KEY + "\n")
    env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", VM_ROOT=str(tmp_path / "vms"),
               SYSTEMD_UNIT_DIR=str(tmp_path / "units"), FAKE_STATE=str(tmp_path / "systemd.json"),
               VM_STOP_WAIT="1", VM_LOCK_DIR=str(tmp_path / "lock"),
               VM_IPV6_CONF_DIR=str(tmp_path / "ipv6conf"), **sealed)
    env.pop("SSH_ORIGINAL_COMMAND", None)

    class Host:
        root = tmp_path / "vms"
        units = tmp_path / "units"
        bundle = sealed["VM_TEST_BUNDLE"]
        config = Path(sealed["VM_HOST_CONFIG"])
        environ = env

        def ctl(self, *args, stdin="", extra=None):
            p = subprocess.run([str(CTL), *args], capture_output=True, text=True, input=stdin,
                               env={**env, **(extra or {})}, timeout=60)
            lines = p.stdout.strip().splitlines()
            assert len(lines) == 1, (p.stdout, p.stderr)
            return p.returncode, json.loads(lines[0])

        def create(self, name="vm1", port="22001", key=None, **opts):
            args = ["create", name, "--vcpus", "1", "--mem-gib", "1", "--disk-gib", "8",
                    "--ssh-key-file", str(key or tmp_path / "id.pub"), "--ssh-port", port]
            return self.ctl(*args)

        def systemd(self):
            return json.loads((tmp_path / "systemd.json").read_text())

        def run_net(self, action, name="vm1"):
            return subprocess.run([str(KIT / "vm-net.sh"), action, str(self.root / name / "vm.env")],
                                  capture_output=True, text=True, env=env, timeout=30)

        tools = tmp_path / "systemd.json.tools"
        bin = fake
        ipv6 = tmp_path / "ipv6conf"

    return Host()


def test_create_writes_identity_disks_user_unit_and_does_not_start(host):
    code, vm = host.create()
    assert code == 0, vm
    assert vm["state"] == "created" and vm["ssh_port"] == 22001 and vm["guest_ip"] == "10.216.0.2"
    assert (vm["vcpus"], vm["mem_gib"], vm["disk_gib"], vm["generation"], vm["paid_through"]) == (1, 1, 8, 0, 0)
    d = host.root / "vm1"
    for f in ("vm.env", "vm-identity.json", "launch.json", "root.raw", "mailbox.raw", "authorization.json"):
        assert (d / f).exists(), f
    for gone in ("disk.qcow2", "seed.iso", "seed"):
        assert not (d / gone).exists(), gone
    # The identity (spec r2 6.3): canonical, immutable, the customer's key without its comment.
    raw = (d / "vm-identity.json").read_bytes()
    ident = json.loads(raw)
    assert ident["ssh_public_key"] == " ".join(KEY.split()[:2]) and ident["schema"] == "cathedral.vm.identity/v1"
    assert len(ident["salt_hex"]) == 32 and ident["vm_id"].startswith("vm-")
    import hashlib
    assert vm["identity_sha256"] == hashlib.sha256(raw).hexdigest()
    assert vm["bundle"] == host.bundle and vm["expected_measurement"] == vm_host_support.MEASUREMENT
    assert len(vm["host_data"]) == 64 and vm["policy"] == "0x30000" and vm["vm_id"] == ident["vm_id"]
    assert vm["disks"] == {"root": True, "mailbox": True}
    # Sparse all-zero disks of the asked size: the guest formats only a disk that reads as zero.
    root_raw = (d / "root.raw").stat()
    assert root_raw.st_size == 8 << 30 and root_raw.st_blocks * 512 < 1 << 20
    assert (d / "mailbox.raw").stat().st_size == 1 << 20
    env = dict(line.split("=", 1) for line in (d / "vm.env").read_text().splitlines())
    assert env["VM_USER"] == "'cvm-0'" and env["VM_BUNDLE"] == f"'{host.bundle}'"
    tools = host.tools.read_text()
    assert "useradd --system --user-group --no-create-home" in tools and tools.count("cvm-0") >= 2
    assert f"chown --no-dereference cvm-0:cvm-0 {d}/root.raw {d}/mailbox.raw {d}/run" in tools
    assert "groupadd --system cvm-sev" in tools
    unit = (host.units / "cathedral-vm-vm1.service").read_text()
    assert "check-paid vm1" in unit and "Restart=on-failure" in unit and "StartLimitBurst" in unit
    assert "vm-net.sh up" in unit and "ExecStopPost=" in unit and "WantedBy=multi-user.target" in unit
    assert "OnUnitActiveSec=30s" in (host.units / "cathedral-vm-enforce.timer").read_text()
    state = host.systemd()
    assert not state.get("cathedral-vm-vm1.service", {}).get("active")
    # A second VM gets the next /30, its own tap and its own user.
    code, vm2 = host.create("vm2", port="22002")
    assert code == 0 and vm2["guest_ip"] == "10.216.0.6"
    assert "User=cvm-1" in (host.units / "cathedral-vm-vm2.service").read_text()
    assert vm2["identity_sha256"] != vm["identity_sha256"]  # own salt, own measurement
    code, listed = host.ctl("list")
    assert [v["name"] for v in listed["vms"]] == ["vm1", "vm2"]


def test_create_refuses_without_the_host_switch_or_an_enabled_bundle(host):
    config = json.loads(host.config.read_text())
    host.config.unlink()
    code, out = host.create()
    assert code == 1 and out["error"] == "snp_vm_host_disabled"
    assert not (host.root / "vm1").exists()
    host.config.write_text(json.dumps(config))
    code, out = host.ctl("create", "vm1", "--vcpus", "1", "--mem-gib", "1", "--disk-gib", "8", "--ssh-port",
                         "22001", "--ssh-key-file", str(host.root.parent / "id.pub"), "--bundle", "0" * 64)
    assert code == 1 and out["error"] == "bundle_not_enabled"
    host.config.write_text(json.dumps({**config, "cpu_family": "turin"}))
    code, out = host.create()
    assert code == 1 and out["error"] == "launch_values"  # the bundle is built for another family
    assert not (host.root / "vm1").exists() and not (host.root / ".history" / "vm1.jsonl").exists()


def test_a_broker_vm_id_is_the_identity_vm_id(host):
    code, vm = host.create("vm-0123456789ab")
    assert code == 0, vm
    assert vm["vm_id"] == "vm-0123456789ab"
    assert json.loads((host.root / "vm-0123456789ab" / "vm-identity.json").read_text())["vm_id"] == vm["vm_id"]


def test_bundles_is_not_a_vm_name(host):
    code, out = host.create("bundles")
    assert code == 2 and out["error"] == "invalid_name"


@pytest.mark.parametrize("name", ["", "-a", "A", "a_b", "a" * 42, "a;b", "../x"])
def test_create_refuses_bad_names(host, name):
    code, out = host.create(name)
    assert code == 2 and out["error"] == "invalid_name"


@pytest.mark.parametrize("port", ["22", "1023", "65536", "0", "abc", "-1"])
def test_create_refuses_bad_ports(host, port):
    code, out = host.create(port=port)
    assert code == 2 and out["error"] == "invalid_ssh_port"


def test_create_refuses_a_port_another_vm_uses_and_an_existing_name(host):
    assert host.create()[0] == 0
    code, out = host.create("vm2", port="22001")
    assert code == 5 and out["error"] == "port_in_use"
    code, out = host.create("vm1", port="22009")
    assert code == 5 and out["error"] == "exists"


@pytest.mark.parametrize("text", [
    "",
    "not a key",
    KEY + "\n" + KEY,  # two keys
    "ssh-dss AAAAB3NzaC1kc3MAAACBAP== x",
    "ssh-ed25519 AAAAB3NzaC1yc2EAAAADAQABAAABAQ== x",  # an RSA blob under an ed25519 type
    "ssh-ed25519 !!notbase64",
    'command="sh" ' + KEY,  # options are not a key line
])
def test_create_refuses_bad_keys(host, tmp_path, text):
    f = tmp_path / "bad.pub"
    f.write_text(text)
    code, out = host.create(key=f)
    assert code == 2 and out["error"] == "invalid_ssh_key"
    assert not (host.root / "vm1").exists()


def _sk_key(typ):
    import base64
    blob = len(typ).to_bytes(4, "big") + typ.encode() + b"\x00" * 8
    return typ + " " + base64.b64encode(blob).decode() + " user@laptop"


@pytest.mark.parametrize("typ", ["sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"])
def test_create_accepts_security_key_types(host, tmp_path, typ):
    f = tmp_path / "sk.pub"
    f.write_text(_sk_key(typ) + "\n")
    code, out = host.create(key=f)
    assert code == 0, out
    assert (host.root / "vm1").exists()


def test_key_types_equal_the_broker_set():
    """Drift guard: the host KEY_TYPES must equal broker vmKeyTypes (broker/vms.go)."""
    import importlib.util
    import re
    spec = importlib.util.spec_from_file_location("vm_ctl", KIT / "vm_ctl.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    src = (KIT.parents[1] / "broker" / "vms.go").read_text()
    block = re.search(r"var vmKeyTypes = map\[string\]bool\{(.*?)\n\}", src, re.S).group(1)
    broker = set(re.findall(r'"([^"]+)":\s+true', block))
    assert broker and set(mod.KEY_TYPES) == broker


def test_authorize_is_idempotent_and_monotonic(host):
    host.create()
    now = int(time.time())
    code, out = host.ctl("authorize", "vm1", str(now + 3600), "1")
    assert code == 0 and out["changed"] is True
    code, out = host.ctl("authorize", "vm1", str(now + 3600), "1")
    assert code == 0 and out["changed"] is False  # same call again: no change
    code, out = host.ctl("authorize", "vm1", str(now + 60), "1")
    assert code == 3 and out["error"] == "paid_through_lower"
    assert host.ctl("authorize", "vm1", str(now + 7200), "1")[0] == 0
    # A higher generation replaces, even with a lower paid_through.
    code, out = host.ctl("authorize", "vm1", str(now + 10), "2")
    assert code == 0 and out == {"name": "vm1", "generation": 2, "paid_through": now + 10, "changed": True}
    code, out = host.ctl("authorize", "vm1", str(now + 99999), "1")
    assert code == 3 and out["error"] == "stale_generation"
    a = json.loads((host.root / "vm1" / "authorization.json").read_text())
    assert (a["generation"], a["paid_through"]) == (2, now + 10)
    assert host.ctl("authorize", "vm1", "x", "3")[1]["error"] == "invalid_paid_through"
    assert host.ctl("authorize", "vm1", "1", "0")[1]["error"] == "invalid_generation"
    assert host.ctl("authorize", "nope", "1", "1")[0] == 5


def test_start_is_refused_when_unpaid_and_runs_when_paid(host):
    host.create()
    code, out = host.ctl("start", "vm1")
    assert code == 3 and out["error"] == "generation_closed"  # never authorized: generation 0
    host.ctl("authorize", "vm1", str(int(time.time()) - 1), "1")
    code, out = host.ctl("start", "vm1")
    assert code == 4 and out["error"] == "unpaid"
    assert host.ctl("check-paid", "vm1")[0] == 4  # the unit's ExecStartPre refuses too
    assert not host.systemd().get("cathedral-vm-vm1.service", {}).get("active")
    host.ctl("authorize", "vm1", str(int(time.time()) + 3600), "2")
    code, out = host.ctl("start", "vm1")
    assert code == 0 and out["state"] == "running"
    u = host.systemd()["cathedral-vm-vm1.service"]
    assert u["active"] and u["enabled"]
    assert host.ctl("check-paid", "vm1")[0] == 0


# The unit's root steps run through this (vm_ctl.HOST_NS); pinned here so a change to it is seen.
HOST_NS = "/usr/bin/nsenter --mount=/proc/1/ns/mnt --"

# Runs vm_ctl.py with an audit hook that writes every path the process opens, one per line.
RECORD_OPENS = r"""
import runpy, sys
log = open(sys.argv[1], "a", buffering=1)
def hook(event, args):
    if event == "open" and isinstance(args[0], (str, bytes)):
        log.write(args[0].decode() if isinstance(args[0], bytes) else args[0])
        log.write("\n")
sys.addaudithook(hook)
sys.argv = sys.argv[2:]
runpy.run_path(sys.argv[0], run_name="__main__")
"""


def unit_entries(unit: str, key: str) -> list[str]:
    return [e for ln in unit.splitlines() if ln.startswith(key + "=") for e in ln.split("=", 1)[1].split()]


def hook_sees(unit: str, marker: str, path: str) -> bool:
    """Whether the Exec line of `unit` that contains `marker` can open `path`. A step that runs through HOST_NS is
    in the host's mount namespace and sees every path. Any other step, `+` or not, is in the unit's namespace
    (systemd 255 and 259): it sees a path only when no TemporaryFileSystem hides it or a bind gives it back."""
    (line,) = [ln for ln in unit.splitlines() if ln.startswith("Exec") and marker in ln]
    if line.split("=", 1)[1].lstrip("+-@:!").startswith(HOST_NS + " "):
        return True
    real = os.path.realpath(path)

    def under(base: str) -> bool:
        b = os.path.realpath(base)
        return real == b or real.startswith(b.rstrip("/") + "/")

    hidden = any(under(e.split(":", 1)[0]) for e in unit_entries(unit, "TemporaryFileSystem"))
    bound = any(under(e) for e in unit_entries(unit, "BindReadOnlyPaths") + unit_entries(unit, "BindPaths"))
    return not hidden or bound


def test_check_paid_in_the_unit_can_read_every_file_it_reads(host, tmp_path):
    """Live VM proof, 28 Nov (systemd 259.5): the unit's `+` check-paid ran inside the unit's mount namespace, found
    no authorization.json under the hidden VM_ROOT, read the default generation 0 and refused every start as
    generation_closed, while the same command as plain root passed. Record every file check-paid opens for a paid,
    started VM, then check each one against the rendered unit."""
    host.create()
    host.ctl("authorize", "vm1", str(int(time.time()) + 3600), "1")
    assert host.ctl("start", "vm1")[0] == 0
    log = tmp_path / "opens.txt"
    p = subprocess.run([sys.executable, "-I", "-c", RECORD_OPENS, str(log), str(KIT / "vm_ctl.py"), "check-paid", "vm1"],
                       capture_output=True, text=True, env=host.environ, timeout=60)
    assert p.returncode == 0 and json.loads(p.stdout)["paid"] is True, (p.stdout, p.stderr)
    opened = sorted({os.path.realpath(x) for x in log.read_text().splitlines() if os.path.isabs(x)})
    d = host.root / "vm1"
    # The recorder works: it saw the files the decision rests on.
    for want in (d / "authorization.json", d / "launch.json", d / "vm.env", host.root / ".history" / "vm1.jsonl"):
        assert os.path.realpath(want) in opened, (want, opened)
    unit = (host.units / "cathedral-vm-vm1.service").read_text()
    assert [f for f in opened if not hook_sees(unit, " check-paid vm1", f)] == []
    # The control: the same unit without the wrapper hides the files that made the live start fail, so the
    # assertion above can fail, and binding only authorization.json would not have been enough.
    bare = unit.replace(HOST_NS + " ", "")
    unseen = {f for f in opened if not hook_sees(bare, " check-paid vm1", f)}
    assert {os.path.realpath(d / "authorization.json"), os.path.realpath(d / "launch.json"),
            os.path.realpath(host.root / ".history" / "vm1.jsonl")} <= unseen, unseen


def test_every_root_step_of_the_unit_runs_in_the_host_namespace_and_qemu_does_not(host):
    host.create()
    unit = (host.units / "cathedral-vm-vm1.service").read_text()
    plus = [ln for ln in unit.splitlines() if re.match(r"Exec\w+=[-@:!]*\+", ln)]
    # modprobe, the /dev/kvm wait, check-paid, the gates, net up, rm, ExecStop powerdown, ExecStopPost net down.
    assert len(plus) == 8, plus
    for ln in plus:
        assert ln.split("=", 1)[1].lstrip("+-@:!").startswith(HOST_NS + " "), ln
    (start,) = [ln for ln in unit.splitlines() if ln.startswith("ExecStart=")]
    assert "nsenter" not in start and not start.startswith("ExecStart=+"), start


def test_stop_keeps_the_disk_closes_the_generation_and_is_idempotent(host):
    host.create()
    host.ctl("authorize", "vm1", str(int(time.time()) + 3600), "1")
    host.ctl("start", "vm1")
    code, out = host.ctl("stop", "vm1")
    assert code == 0 and out["state"] == "stopped" and out["was_running"] and out["generation"] == 1
    assert abs(out["stopped_at"] - time.time()) < 30
    u = host.systemd()["cathedral-vm-vm1.service"]
    assert not u["active"] and not u["enabled"]
    assert (host.root / "vm1" / "root.raw").exists()
    again = host.ctl("stop", "vm1")[1]
    assert again["stopped_at"] == out["stopped_at"] and not again["was_running"]
    # A top-up of the stopped run cannot revive it; a fresh generation can.
    code, out = host.ctl("authorize", "vm1", str(int(time.time()) + 7200), "1")
    assert code == 3 and out["error"] == "generation_closed"
    assert host.ctl("start", "vm1")[1]["error"] == "generation_closed"
    host.ctl("authorize", "vm1", str(int(time.time()) + 7200), "2")
    assert host.ctl("start", "vm1")[1]["state"] == "running"
    assert host.ctl("status", "vm1")[1]["state"] == "running"


def test_enforce_stops_expired_vms_and_keeps_their_disks(host):
    host.create()
    host.create("vm2", port="22002")
    for name in ("vm1", "vm2"):
        host.ctl("authorize", name, str(int(time.time()) + 3600), "1")
        host.ctl("start", name)
    # vm1's paid window ends while it runs (a higher generation over a started run is refused,
    # AB#992, so the window is moved the way an expiry would).
    auth = host.root / "vm1" / "authorization.json"
    a = json.loads(auth.read_text())
    a["paid_through"] = int(time.time()) - 5
    auth.write_text(json.dumps(a))
    code, out = host.ctl("enforce")
    assert code == 0 and [s["name"] for s in out["stopped"]] == ["vm1"] and out["checked"] == 2
    assert host.ctl("status", "vm1")[1]["state"] == "stopped"
    assert host.ctl("status", "vm2")[1]["state"] == "running"
    assert (host.root / "vm1" / "root.raw").exists()
    assert json.loads((host.root / "vm1" / "stop.json").read_text())["reason"] == "paid_through"
    assert not host.systemd()["cathedral-vm-vm1.service"]["enabled"]  # not back after a host reboot
    assert host.ctl("enforce")[1]["stopped"] == []


def test_delete_needs_confirm_with_the_name(host):
    host.create()
    code, out = host.ctl("delete", "vm1")
    assert code == 2 and out["error"] == "confirm_required"
    code, out = host.ctl("delete", "vm1", "--confirm", "vm2")
    assert code == 2 and out["error"] == "confirm_required"
    assert (host.root / "vm1" / "root.raw").exists()
    code, out = host.ctl("delete", "vm1", "--confirm", "vm1")
    assert code == 0 and out == {"name": "vm1", "deleted": True}
    assert "userdel cvm-0" in host.tools.read_text()  # the VM user goes with the VM
    assert not (host.root / "vm1").exists() and not (host.units / "cathedral-vm-vm1.service").exists()
    assert not (host.units / "cathedral-vm-enforce.timer").exists()  # last VM gone
    # A repeated delete (lost answer) or one for a create that never reached the host succeeds.
    code, out = host.ctl("delete", "vm1", "--confirm", "vm1")
    assert code == 0 and out == {"name": "vm1", "deleted": True, "existed": False}


def test_reboot_needs_a_running_vm(host):
    host.create()
    code, out = host.ctl("reboot", "vm1")
    assert code == 5 and out["error"] == "not_running"


def test_reboot_is_a_fenced_relaunch_in_the_same_generation(host):
    """Spec r2 8.1: powerdown, wait, restart the unit; no new history line, no new generation."""
    host.create()
    now = int(time.time())
    host.ctl("authorize", "vm1", str(now + 600), "1")
    assert host.ctl("start", "vm1", "--generation", "1")[0] == 0
    hist = (host.root / ".history" / "vm1.jsonl").read_text()
    (host.root.parent / "systemd.json.log").write_text("")
    code, out = host.ctl("reboot", "vm1", "--generation", "1")
    assert code == 0 and out["state"] == "running" and out["generation"] == 1, out
    log = (host.root.parent / "systemd.json.log").read_text().splitlines()
    assert log[-1] == "restart cathedral-vm-vm1.service" and "disable -q cathedral-vm-vm1.service" not in log
    assert (host.root / ".history" / "vm1.jsonl").read_text() == hist
    assert not (host.root / "vm1" / "powerdown-sent").exists()
    assert host.ctl("check-paid", "vm1")[0] == 0  # the relaunch passes the unit's gate
    a = json.loads((host.root / "vm1" / "authorization.json").read_text())
    assert (a["generation"], a["closed_generation"]) == (1, 0)
    # Past paid_through a reboot is refused: enforce stops it instead.
    a["paid_through"] = now - 1
    (host.root / "vm1" / "authorization.json").write_text(json.dumps(a))
    code, out = host.ctl("reboot", "vm1", "--generation", "1")
    assert code == 4 and out["error"] == "unpaid"


# The fake systemctl, plus "restart": it fails once (and leaves the unit down, as after the
# guest's powerdown) while a .fail-restart flag exists, and starts the unit otherwise.
FLAKY_RESTART = FAKE_SYSTEMCTL.replace(
    'if verb == "start": u["active"] = True',
    'if verb == "restart" and os.path.exists(path + ".fail-restart"):\n'
    '    os.unlink(path + ".fail-restart"); u["active"] = False; json.dump(state, open(path, "w")); sys.exit(1)\n'
    'if verb in ("start", "restart"): u["active"] = True')


def test_an_interrupted_reboot_relaunches_on_retry(host):
    """Astra #789 P2: powerdown done, restart never queued. The retry for the same paid, open
    generation relaunches instead of answering not_running; nothing else can revive it."""
    assert FLAKY_RESTART != FAKE_SYSTEMCTL
    (host.bin / "systemctl").write_text(FLAKY_RESTART)
    host.create()
    now = int(time.time())
    host.ctl("authorize", "vm1", str(now + 600), "1")
    assert host.ctl("start", "vm1", "--generation", "1")[0] == 0
    hist = (host.root / ".history" / "vm1.jsonl").read_text()
    (host.root.parent / "systemd.json.fail-restart").write_text("")
    code, out = host.ctl("reboot", "vm1", "--generation", "1")
    assert code == 1 and out["error"] == "command_failed", out
    assert host.ctl("status", "vm1")[1]["state"] == "stopped"
    assert json.loads((host.root / "vm1" / "reboot-pending.json").read_text())["generation"] == 1
    code, out = host.ctl("reboot", "vm1", "--generation", "1")
    assert code == 0 and out["state"] == "running" and out["resumed"] is True, out
    assert host.ctl("status", "vm1")[1]["state"] == "running"
    assert not (host.root / "vm1" / "reboot-pending.json").exists()
    assert (host.root / ".history" / "vm1.jsonl").read_text() == hist  # same run, no new line
    # A marker cannot revive a stopped run, nor one of an older generation.
    (host.root.parent / "systemd.json.fail-restart").write_text("")
    assert host.ctl("reboot", "vm1", "--generation", "1")[0] == 1
    assert host.ctl("stop", "vm1", "--generation", "1")[0] == 0
    code, out = host.ctl("reboot", "vm1", "--generation", "1")
    assert code == 3 and out["error"] == "generation_closed", out
    host.ctl("authorize", "vm1", str(now + 600), "2")
    code, out = host.ctl("reboot", "vm1", "--generation", "2")
    assert code == 5 and out["error"] == "not_running"
    assert not (host.root / "vm1" / "reboot-pending.json").exists()
    assert host.ctl("status", "vm1")[1]["state"] == "stopped"


@pytest.mark.parametrize("command", [
    "status vm1; rm -rf /",
    "status $(id)",
    "status `id`",
    "status vm1 | cat",
    "status vm1 && id",
    "status 'vm1'",
    "shell vm1",
    "check-paid vm1",
    "powerdown vm1",
    "create vm2 --vcpus 1 --mem-gib 1 --disk-gib 8 --ssh-port 22002 --ssh-key-file /etc/passwd",
    "create vm2 --vcpus 1 --mem-gib 1 --disk-gib 8 --ssh-port 22002 --image /etc/shadow",
    "create vm2 --vcpus 1 --mem-gib 1 --disk-gib 8 --ssh-port 22002 --bundle " + "0" * 64,
    "status ../vm1",
    "",
])
def test_from_broker_refuses_injection_and_unknown_commands(host, command):
    host.create()
    code, out = host.ctl("--from-broker", extra={"SSH_ORIGINAL_COMMAND": command})
    assert code != 0 and "error" in out


def test_from_broker_runs_known_commands_and_takes_the_key_on_stdin(host):
    host.create()
    code, out = host.ctl("--from-broker", extra={"SSH_ORIGINAL_COMMAND": "status vm1"})
    assert code == 0 and out["name"] == "vm1"
    cmd = "create vm2 --vcpus 1 --mem-gib 1 --disk-gib 8 --ssh-port 22002"
    code, out = host.ctl("--from-broker", stdin="", extra={"SSH_ORIGINAL_COMMAND": cmd})
    assert code == 2 and out["error"] == "invalid_ssh_key"
    code, out = host.ctl("--from-broker", stdin=KEY + "\n", extra={"SSH_ORIGINAL_COMMAND": cmd})
    assert code == 0 and out["name"] == "vm2" and out["bundle"] == host.bundle, out
    ident = json.loads((host.root / "vm2" / "vm-identity.json").read_text())
    assert ident["ssh_public_key"] == " ".join(KEY.split()[:2])


def test_vm_net_up_blocks_private_ranges_and_forwards_only_ssh(host):
    host.create()
    (host.ipv6 / "cvm0").mkdir(parents=True)  # the fake sysctl writes nothing; the real one sets this
    (host.ipv6 / "cvm0" / "disable_ipv6").write_text("1\n")
    p = host.run_net("up")
    assert p.returncode == 0, p.stderr
    log = host.tools.read_text()
    assert "-d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" in log
    assert "-A CVM-CVM0-IN -i cvm0 -j DROP" in log
    assert "--dport 22001 -m addrtype --dst-type LOCAL -m comment --comment cathedral-vm:vm1 -j DNAT --to-destination 10.216.0.2:22" in log
    assert "-I FORWARD 1 -m comment --comment cathedral-vm:vm1 -j CVM-CVM0-FWD" in log
    assert "-t nat -A OUTPUT" in log and "-t nat -A PREROUTING" in log and "MASQUERADE" in log
    assert "ctorigdstport 22001" in log  # only connections through this VM's own forward
    assert "-I INPUT 1 -i cvm0 -m comment --comment cathedral-vm:vm1 -j DROP" in log  # IPv6 backstop
    assert "ip tuntap add dev cvm0 mode tap user cvm-0 group cvm-0" in log  # QEMU is not root
    assert "net.ipv6.conf.cvm0.disable_ipv6=1" in log
    assert host.run_net("down").returncode == 0
    assert "link del cvm0" in host.tools.read_text()


def _launch_code() -> str:
    """The launcher and the shared SNP argv module without comments and docstrings."""
    out = []
    for name in ("launch-vm.py", "snp_qemu.py"):
        tree = ast.parse((KIT / name).read_text())
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if isinstance(body, list) and body and isinstance(body[0], ast.Expr) \
                    and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                body[0] = ast.Pass()
        out.append(ast.unparse(tree))
    return "\n".join(out)


def test_the_stub_launcher_is_gone():
    """VM3 replaces the exit-78 stub of #775 with launch-vm.py (tests/test_vm_launcher.py)."""
    assert not (KIT / "launch-vm.sh").exists()
    assert not (KIT / "images.lock").exists() and not (KIT / "fetch-image.sh").exists()


def test_launch_has_no_plain_mode_switch():
    code = _launch_code().upper()
    for name in ("PLAIN", "UNSEALED", "ALLOW", "INSECURE", "NO_SNP", "SKIP_SNP", "DISABLE_SNP"):
        assert name not in code, name
    # Every shipped file in the kit: no env name that reads as a plain-mode switch.
    for f in KIT.iterdir():
        if f.suffix in (".sh", ".py", ".example"):
            text = f.read_text().upper()
            assert "ALLOW_UNSEALED" not in text and "VM_PLAIN" not in text, f.name


def test_no_em_dashes_in_the_kit():
    for f in KIT.iterdir():
        # Importing vm_ctl in tests leaves a __pycache__ directory in the kit.
        if not f.is_file():
            continue
        assert "—" not in f.read_text(), f


def test_generation_fences_stop_start_and_reboot(host):
    # At-least-once billing delivery: a delayed call from an older run must not touch the new one.
    host.create()
    now = int(time.time())
    assert host.ctl("authorize", "vm1", str(now + 600), "1")[0] == 0
    assert host.ctl("start", "vm1", "--generation", "1")[0] == 0
    assert host.ctl("stop", "vm1", "--generation", "1")[0] == 0
    assert host.ctl("authorize", "vm1", str(now + 60), "2")[0] == 0  # shorter window, new run: accepted
    code, out = host.ctl("start", "vm1", "--generation", "1")
    assert code == 3 and out["error"] == "stale_generation"
    assert host.ctl("status", "vm1")[1]["closed"] is False
    assert host.ctl("start", "vm1", "--generation", "2")[0] == 0
    code, out = host.ctl("stop", "vm1", "--generation", "1")
    assert code == 3 and out["error"] == "stale_generation"
    assert host.ctl("status", "vm1")[1]["state"] == "running"
    code, out = host.ctl("--from-broker", extra={"SSH_ORIGINAL_COMMAND": "stop vm1 --generation 1"})
    assert code == 3 and out["error"] == "stale_generation"
    assert host.ctl("reboot", "vm1", "--generation", "1")[1]["error"] == "stale_generation"
    code, out = host.ctl("stop", "vm1", "--generation", "x1")
    assert code == 2 and out["error"] == "invalid_generation"
    assert host.ctl("status", "vm1")[1]["state"] == "running"
    assert host.ctl("stop", "vm1", "--generation", "2")[0] == 0


def test_stop_cancels_an_authorized_run_that_never_started(host):
    # Billing cancel between authorize and start: terminal evidence, and the run can never start.
    host.create()
    now = int(time.time())
    assert host.ctl("authorize", "vm1", str(now + 600), "1")[0] == 0
    code, out = host.ctl("stop", "vm1", "--generation", "1")
    assert code == 0 and out["was_running"] is False and out["generation"] == 1 and out["stopped_at"] >= now
    assert host.ctl("status", "vm1")[1]["closed"] is True
    again = host.ctl("stop", "vm1", "--generation", "1")[1]
    assert again["stopped_at"] == out["stopped_at"]  # same receipt on a repeat
    code, out = host.ctl("start", "vm1", "--generation", "1")
    assert code == 3
    assert host.ctl("status", "vm1")[1]["state"] != "running"
    assert host.ctl("authorize", "vm1", str(now + 600), "2")[0] == 0
    assert host.ctl("status", "vm1")[1]["closed"] is False
    assert host.ctl("start", "vm1", "--generation", "2")[0] == 0


def test_ipv6_shut_needs_one_of_disable_ipv6_or_ip6tables(host):
    host.create()
    # ip6tables refuses every change (no ip6 tables module), disable_ipv6 took: the VM still starts.
    (host.bin / "ip6tables").write_text('#!/bin/sh\nexit 1\n')
    (host.ipv6 / "cvm0").mkdir(parents=True)
    (host.ipv6 / "cvm0" / "disable_ipv6").write_text("1\n")
    p = host.run_net("up")
    assert p.returncode == 0, p.stderr
    assert host.run_net("down").returncode == 0
    # Neither layer holds: refuse to bring the link up.
    (host.ipv6 / "cvm0" / "disable_ipv6").write_text("0\n")
    p = host.run_net("up")
    assert p.returncode != 0 and "could not shut IPv6" in p.stderr


def test_enforce_purges_a_stopped_vms_leftover_forward_only_when_disabled(host):
    host.create()
    host.tools.write_text("")
    assert host.ctl("enforce")[0] == 0
    # Created, never started: disabled and inactive, so the purge runs (nat only, no tap or chain change).
    log = host.tools.read_text()
    assert "iptables -t nat -S" in log and "ip link del" not in log and "-D FORWARD" not in log
    # Enabled but not active (host boot before systemd started it, or Restart= pending): hands off.
    st = host.systemd(); st["cathedral-vm-vm1.service"]["enabled"] = True
    (host.root.parent / "systemd.json").write_text(json.dumps(st))
    host.tools.write_text("")
    assert host.ctl("enforce")[0] == 0
    assert "iptables" not in host.tools.read_text()


# ---- pre-launch gates wiring (spec r2 8.3, #788) ----------------------------------------

GATE_ERRORS = {10: "vm_invalid", 11: "vm_host_not_enabled", 12: "vm_bundle_not_enabled",
               13: "vm_bundle_mismatch", 14: "vm_host_changed", 15: "sev_baseline_missing",
               16: "sev_status_unreadable", 17: "sev_platform_changed", 18: "sev_state_unavailable"}


def _gates(host, code, doc):
    (host.root.parent / "systemd.json.gates").write_text(f"{code}\n{json.dumps(doc)}\n")


def _gate_calls(host):
    tools = host.root.parent / "systemd.json.tools"
    return [ln for ln in (tools.read_text().splitlines() if tools.exists() else []) if ln.startswith("vm-gates ")]


def test_the_gate_codes_are_the_gates_own():
    import importlib.util
    spec = importlib.util.spec_from_file_location("vm_gates_codes", KIT / "vm_gates.py")
    gates = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gates)
    assert {v: k for k, v in gates.EXIT.items()} == GATE_ERRORS


@pytest.mark.parametrize("code", sorted(GATE_ERRORS))
def test_start_refused_by_each_gate_leaves_no_start_line(host, code):
    """A gate refusal passes through with its own error and exit code (17 sev_platform_changed,
    18 sev_state_unavailable): no start line, nothing billed, the unit never started."""
    host.create()
    host.ctl("authorize", "vm1", str(int(time.time()) + 600), "1")
    _gates(host, code, {"ok": False, "error": GATE_ERRORS[code], "detail": "the  reason\nhere"})
    rc, out = host.ctl("start", "vm1", "--generation", "1")
    assert (rc, out["error"], out["detail"]) == (code, GATE_ERRORS[code], "the reason here"), out
    assert _gate_calls(host) == ["vm-gates check vm1"]
    assert host.ctl("status", "vm1")[1]["state"] == "created"
    hist = host.root / ".history" / "vm1.jsonl"
    assert not hist.exists() or '"start"' not in hist.read_text()
    assert not (host.root / "vm1" / "started").exists()


@pytest.mark.parametrize("code,doc", [
    (1, {"ok": False, "error": "internal", "detail": "x"}), (2, {"ok": False, "error": "usage", "detail": "x"}),
    (17, {"ok": False, "error": "vm_invalid", "detail": "x"}),   # an error that is not its code's
    (17, "not json"), (3, {"ok": False, "error": "stale_generation"}), (4, {"error": "unpaid"}),
])
def test_any_other_gate_answer_refuses_as_gates_failed(host, code, doc):
    """Never a pass, and never an exit the broker reads as stale (3) or unpaid (4)."""
    host.create()
    host.ctl("authorize", "vm1", str(int(time.time()) + 600), "1")
    _gates(host, code, doc)
    rc, out = host.ctl("start", "vm1", "--generation", "1")
    assert (rc, out["error"]) == (1, "gates_failed"), out
    assert host.ctl("status", "vm1")[1]["state"] == "created"


def _start_refused_gates_failed(host, extra):
    host.create()
    host.ctl("authorize", "vm1", str(int(time.time()) + 600), "1")
    rc, out = host.ctl("start", "vm1", "--generation", "1", extra=extra)
    assert (rc, out["error"]) == (1, "gates_failed"), out
    assert host.ctl("status", "vm1")[1]["state"] == "created"
    hist = host.root / ".history" / "vm1.jsonl"
    assert not hist.exists() or '"start"' not in hist.read_text()
    assert not (host.root / "vm1" / "started").exists()


def test_a_gates_script_that_hangs_refuses_as_gates_failed(host):
    """A timeout never passes. The wait is shortened so the test is fast."""
    hang = host.root.parent / "hang-gates"
    hang.write_text("#!/bin/sh\nexec sleep 30\n")
    hang.chmod(0o755)
    _start_refused_gates_failed(host, {"VM_GATES": str(hang), "VM_GATE_WAIT": "1"})


@pytest.mark.parametrize("mode", ["missing", "not_executable"])
def test_a_gates_script_that_cannot_run_refuses_as_gates_failed(host, mode):
    path = host.root.parent / "absent-gates"
    if mode == "not_executable":
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o644)
    _start_refused_gates_failed(host, {"VM_GATES": str(path)})


@pytest.mark.parametrize("bad", ["abc", "0", "-5", "nan", "inf"])
def test_a_bad_gate_wait_falls_back_and_breaks_nothing(host, bad):
    host.create()
    host.ctl("authorize", "vm1", str(int(time.time()) + 600), "1")
    assert host.ctl("enforce", extra={"VM_GATE_WAIT": bad})[0] == 0
    rc, out = host.ctl("start", "vm1", "--generation", "1", extra={"VM_GATE_WAIT": bad})
    assert rc == 0 and out["state"] == "running", out


def test_start_runs_when_the_gates_pass_after_the_paid_check(host):
    host.create()
    rc, out = host.ctl("start", "vm1", "--generation", "1")
    assert out["error"] in ("stale_generation", "generation_closed", "unpaid") and _gate_calls(host) == []
    host.ctl("authorize", "vm1", str(int(time.time()) + 600), "1")
    rc, out = host.ctl("start", "vm1", "--generation", "1")
    assert rc == 0 and out["state"] == "running", out
    assert _gate_calls(host) == ["vm-gates check vm1"]
    assert '"start"' in (host.root / ".history" / "vm1.jsonl").read_text()


def test_a_reboot_the_gates_refuse_leaves_the_vm_running(host):
    host.create()
    host.ctl("authorize", "vm1", str(int(time.time()) + 600), "1")
    assert host.ctl("start", "vm1", "--generation", "1")[0] == 0
    _gates(host, 17, {"ok": False, "error": "sev_platform_changed", "detail": "x"})
    rc, out = host.ctl("reboot", "vm1", "--generation", "1")
    assert (rc, out["error"]) == (17, "sev_platform_changed"), out
    assert host.ctl("status", "vm1")[1]["state"] == "running"
    assert not (host.root / "vm1" / "reboot-pending.json").exists()


def test_the_enforce_service_compares_the_sev_status_after_the_credit_cutoff(host):
    host.create()
    lines = [ln for ln in (host.units / "cathedral-vm-enforce.service").read_text().splitlines()
             if ln.startswith("ExecStart=")]
    assert lines == [f"ExecStart={KIT.resolve()}/vm-ctl.sh enforce", f"ExecStart=-{KIT.resolve()}/vm-gates.sh enforce"]
