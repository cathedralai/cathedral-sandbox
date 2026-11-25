"""AB#991: host runtime for long-lived customer VMs (room-kit/vm). No KVM, no root:
fake systemctl, qemu-img, cloud-localds, ip and iptables on PATH, VM_ROOT in tmp."""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

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
elif verb == "show": print("active" if u["active"] else "inactive")
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
                       "ip": FAKE_LOG, "iptables": FAKE_IPTABLES, "sysctl": FAKE_LOG, "flock": FAKE_LOG}.items():
        (fake / name).write_text(text)
        (fake / name).chmod(0o755)
    image = tmp_path / "base.img"
    image.write_bytes(b"not really an image")
    (tmp_path / "id.pub").write_text(KEY + "\n")
    env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", VM_ROOT=str(tmp_path / "vms"),
               SYSTEMD_UNIT_DIR=str(tmp_path / "units"), FAKE_STATE=str(tmp_path / "systemd.json"),
               VM_STOP_WAIT="1", VM_LOCK_DIR=str(tmp_path / "lock"))
    env.pop("SSH_ORIGINAL_COMMAND", None)

    class Host:
        root = tmp_path / "vms"
        units = tmp_path / "units"

        def ctl(self, *args, stdin="", extra=None):
            p = subprocess.run([str(CTL), *args], capture_output=True, text=True, input=stdin,
                               env={**env, **(extra or {})}, timeout=60)
            lines = p.stdout.strip().splitlines()
            assert len(lines) == 1, (p.stdout, p.stderr)
            return p.returncode, json.loads(lines[0])

        def create(self, name="vm1", port="22001", key=None, **opts):
            args = ["create", name, "--vcpus", "1", "--mem-gib", "1", "--disk-gib", "8",
                    "--ssh-key-file", str(key or tmp_path / "id.pub"), "--ssh-port", port, "--image", str(image)]
            return self.ctl(*args)

        def systemd(self):
            return json.loads((tmp_path / "systemd.json").read_text())

        def run_net(self, action, name="vm1"):
            return subprocess.run([str(KIT / "vm-net.sh"), action, str(self.root / name / "vm.env")],
                                  capture_output=True, text=True, env=env, timeout=30)

        tools = tmp_path / "systemd.json.tools"

    return Host()


def test_create_writes_disk_seed_env_unit_and_does_not_start(host):
    code, vm = host.create()
    assert code == 0, vm
    assert vm["state"] == "created" and vm["ssh_port"] == 22001 and vm["guest_ip"] == "10.216.0.2"
    assert (vm["vcpus"], vm["mem_gib"], vm["disk_gib"], vm["generation"], vm["paid_through"]) == (1, 1, 8, 0, 0)
    d = host.root / "vm1"
    for f in ("vm.env", "disk.qcow2", "seed.iso", "authorization.json"):
        assert (d / f).exists(), f
    user_data = (d / "seed" / "user-data").read_text()
    cfg = json.loads(user_data.split("\n", 1)[1])
    assert cfg["disable_root"] is True and cfg["ssh_pwauth"] is False
    assert cfg["users"][0]["name"] == "cathedral" and cfg["users"][0]["sudo"] == "ALL=(ALL) NOPASSWD:ALL"
    assert cfg["users"][0]["ssh_authorized_keys"] == [" ".join(KEY.split()[:2])]
    net = json.loads((d / "seed" / "network-config").read_text())
    assert net["ethernets"]["eth0"]["addresses"] == ["10.216.0.2/30"]
    unit = (host.units / "cathedral-vm-vm1.service").read_text()
    assert "check-paid vm1" in unit and "Restart=on-failure" in unit and "StartLimitBurst" in unit
    assert "vm-net.sh up" in unit and "ExecStopPost=" in unit and "WantedBy=multi-user.target" in unit
    assert "OnUnitActiveSec=30s" in (host.units / "cathedral-vm-enforce.timer").read_text()
    assert "-b " in host.tools.read_text() and "8G" in host.tools.read_text()
    state = host.systemd()
    assert not state.get("cathedral-vm-vm1.service", {}).get("active")
    # A second VM gets the next /30 and its own tap.
    code, vm2 = host.create("vm2", port="22002")
    assert code == 0 and vm2["guest_ip"] == "10.216.0.6"
    code, listed = host.ctl("list")
    assert [v["name"] for v in listed["vms"]] == ["vm1", "vm2"]


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


def test_stop_keeps_the_disk_closes_the_generation_and_is_idempotent(host):
    host.create()
    host.ctl("authorize", "vm1", str(int(time.time()) + 3600), "1")
    host.ctl("start", "vm1")
    code, out = host.ctl("stop", "vm1")
    assert code == 0 and out["state"] == "stopped" and out["was_running"] and out["generation"] == 1
    assert abs(out["stopped_at"] - time.time()) < 30
    u = host.systemd()["cathedral-vm-vm1.service"]
    assert not u["active"] and not u["enabled"]
    assert (host.root / "vm1" / "disk.qcow2").exists()
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
    # The broker installs a new generation whose window already ended.
    host.ctl("authorize", "vm1", str(int(time.time()) - 5), "2")
    code, out = host.ctl("enforce")
    assert code == 0 and [s["name"] for s in out["stopped"]] == ["vm1"] and out["checked"] == 2
    assert host.ctl("status", "vm1")[1]["state"] == "stopped"
    assert host.ctl("status", "vm2")[1]["state"] == "running"
    assert (host.root / "vm1" / "disk.qcow2").exists()
    assert json.loads((host.root / "vm1" / "stop.json").read_text())["reason"] == "paid_through"
    assert not host.systemd()["cathedral-vm-vm1.service"]["enabled"]  # not back after a host reboot
    assert host.ctl("enforce")[1]["stopped"] == []


def test_delete_needs_confirm_with_the_name(host):
    host.create()
    code, out = host.ctl("delete", "vm1")
    assert code == 2 and out["error"] == "confirm_required"
    code, out = host.ctl("delete", "vm1", "--confirm", "vm2")
    assert code == 2 and out["error"] == "confirm_required"
    assert (host.root / "vm1" / "disk.qcow2").exists()
    code, out = host.ctl("delete", "vm1", "--confirm", "vm1")
    assert code == 0 and out == {"name": "vm1", "deleted": True}
    assert not (host.root / "vm1").exists() and not (host.units / "cathedral-vm-vm1.service").exists()
    assert not (host.units / "cathedral-vm-enforce.timer").exists()  # last VM gone
    # A repeated delete (lost answer) or one for a create that never reached the host succeeds.
    code, out = host.ctl("delete", "vm1", "--confirm", "vm1")
    assert code == 0 and out == {"name": "vm1", "deleted": True, "existed": False}


def test_reboot_needs_a_running_vm(host):
    host.create()
    code, out = host.ctl("reboot", "vm1")
    assert code == 5 and out["error"] == "not_running"


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
    image = str(host.root.parent / "base.img")
    code, out = host.ctl("--from-broker", stdin=KEY + "\n",
                         extra={"SSH_ORIGINAL_COMMAND": cmd, "VM_BASE_IMAGE": image})
    # The pinned digest is checked even when the image path comes from the host env.
    assert code == 1 and out["error"] == "image_mismatch"
    code, out = host.ctl("--from-broker", stdin="", extra={"SSH_ORIGINAL_COMMAND": cmd})
    assert code == 2 and out["error"] == "invalid_ssh_key"


def test_vm_net_up_blocks_private_ranges_and_forwards_only_ssh(host):
    host.create()
    p = host.run_net("up")
    assert p.returncode == 0, p.stderr
    log = host.tools.read_text()
    assert "-d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" in log
    assert "-A CVM-CVM0-IN -i cvm0 -j DROP" in log
    assert "--dport 22001 -m addrtype --dst-type LOCAL -m comment --comment cathedral-vm:vm1 -j DNAT --to-destination 10.216.0.2:22" in log
    assert "-I FORWARD 1 -m comment --comment cathedral-vm:vm1 -j CVM-CVM0-FWD" in log
    assert "-t nat -A OUTPUT" in log and "-t nat -A PREROUTING" in log and "MASQUERADE" in log
    assert host.run_net("down").returncode == 0
    assert "link del cvm0" in host.tools.read_text()


def test_launch_keeps_the_process_on_guest_reboot():
    text = (KIT / "launch-vm.sh").read_text()
    assert "-no-reboot" not in text.replace("No -no-reboot", "")
    for flag in ("-enable-kvm", "-cpu host", "q35", "cache=none", "virtio-blk-pci", "virtio-net-pci",
                 "-qmp", "-display none", "seed.iso"):
        assert flag in text, flag


def test_image_is_pinned():
    lock = (KIT / "images.lock").read_text()
    assert "IMAGE_URL=https://cloud-images.ubuntu.com/releases/noble/release-" in lock
    sha = [line.split("=", 1)[1] for line in lock.splitlines() if line.startswith("IMAGE_SHA256=")]
    assert len(sha) == 1 and len(sha[0]) == 64


def test_no_em_dashes_in_the_kit():
    for f in KIT.iterdir():
        assert "—" not in f.read_text(), f
