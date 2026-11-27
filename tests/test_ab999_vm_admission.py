"""AB#999 VM spec r2 section 9: the host admission ledger (room-kit/vm/vm_capacity.py), its
wiring into vm-ctl.sh create and start, and install-sealed.sh's assess step.

No KVM, no root: fake /proc/meminfo, /proc/cpuinfo and cgroup misc files under VM_CAPACITY_ROOT,
real kit unit files from write-units.sh (ROOM_DESTDIR), real sparse files, fake systemctl,
qemu-img and network tools on PATH. File system free space and devices are faked in the unit
tests; the end-to-end tests use the real tmp file system with a zero reserve."""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
KIT = REPO / "room-kit" / "vm"
SEALED = REPO / "room-kit" / "sealed"
CTL = KIT / "vm-ctl.sh"
GIB = 1 << 30
MIB = 1 << 20
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
FAKE_IPTABLES = FAKE_LOG + 'case " $* " in *" -C "*) exit 1;; esac\n'
FAKE_LOCALDS = FAKE_LOG + ': > "$3"\n'
# install-sealed.sh's kit install lock (-n FD, -u FD) is real: the lock belongs to the open file,
# which the calling shell keeps. Other forms (vm-net.sh's -w) only log, as before.
FAKE_FLOCK = FAKE_LOG + """case "$1" in -n|-u) exec python3 -I -c '
import fcntl, sys
op = fcntl.LOCK_UN if sys.argv[1] == "-u" else fcntl.LOCK_EX | fcntl.LOCK_NB
try:
    fcntl.flock(int(sys.argv[2]), op)
except BlockingIOError:
    sys.exit(1)
' "$1" "$2";; esac
"""


def load_capacity():
    spec = importlib.util.spec_from_file_location("vm_capacity_under_test", KIT / "vm_capacity.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses look the module up while the class is made
    spec.loader.exec_module(mod)
    return mod


def write_fakes(bin_dir: Path) -> None:
    bin_dir.mkdir(exist_ok=True)
    for name, text in {"systemctl": FAKE_SYSTEMCTL, "qemu-img": FAKE_QEMU_IMG, "cloud-localds": FAKE_LOCALDS,
                       "ip": FAKE_LOG, "iptables": FAKE_IPTABLES, "ip6tables": FAKE_IPTABLES, "sysctl": FAKE_LOG,
                       "flock": FAKE_FLOCK, "ss": FAKE_LOG}.items():
        (bin_dir / name).write_text(text)
        (bin_dir / name).chmod(0o755)


class Host:
    """One fake SNP host: host files, kit units written by the real write-units.sh, VM dirs."""

    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.root = tmp / "host"  # VM_CAPACITY_ROOT
        self.destdir = tmp / "dest"  # write-units.sh ROOM_DESTDIR
        self.units = self.destdir / "etc" / "systemd" / "system"
        self.vms = tmp / "vms"
        self.state = tmp / "systemd.json"
        for d in (self.root, self.units, self.vms):
            d.mkdir(parents=True, exist_ok=True)
        write_fakes(tmp / "bin")
        self.env = {**os.environ, "PATH": f"{tmp / 'bin'}:{os.environ['PATH']}", "FAKE_STATE": str(self.state),
                    "VM_CAPACITY_ROOT": str(self.root), "SYSTEMD_UNIT_DIR": str(self.units),
                    "VM_ROOT": str(self.vms), "VM_GUEST_OVERHEAD_MIB": "1024", "VM_MIN_HOST_FREE_GIB": "0",
                    "VM_STOP_WAIT": "1", "VM_LOCK_DIR": str(tmp / "lock"), "VM_IPV6_CONF_DIR": str(tmp / "ipv6")}
        self.env.pop("SSH_ORIGINAL_COMMAND", None)
        self.facts()

    def facts(self, mem_total_gib=512, mem_avail_gib=None, threads=64, asids=16, current=0):
        p = self.root / "proc"
        p.mkdir(exist_ok=True)
        avail = mem_total_gib if mem_avail_gib is None else mem_avail_gib
        (p / "meminfo").write_text(f"MemTotal:       {mem_total_gib * 1048576} kB\nMemFree:        1 kB\n"
                                   f"MemAvailable:   {avail * 1048576} kB\n")
        (p / "cpuinfo").write_text("".join(f"processor\t: {i}\nmodel name\t: x\n\n" for i in range(threads)))
        cg = self.root / "sys" / "fs" / "cgroup"
        cg.mkdir(parents=True, exist_ok=True)
        (cg / "misc.capacity").write_text(f"sev 0\nsev_es {asids}\n")
        if current is None:
            (cg / "misc.current").unlink(missing_ok=True)
        else:
            (cg / "misc.current").write_text(f"sev 0\nsev_es {current}\n")

    def switch_on(self):
        (self.root / "etc" / "cathedral").mkdir(parents=True, exist_ok=True)
        (self.root / "etc" / "cathedral" / "snp-vm-host.json").write_text('{"bundles": []}\n')

    def set_unit(self, unit: str, active: bool, enabled: bool | None = None):
        state = json.loads(self.state.read_text()) if self.state.exists() else {}
        state[unit] = {"active": active, "enabled": active if enabled is None else enabled}
        self.state.write_text(json.dumps(state))

    def kit_env(self, name, sealed_dir=None, vcpus=8, mem=64, scratch=100, data=0, min_free=0, extra=""):
        sealed_dir = Path(sealed_dir or self.tmp / "srv" / f"sealed-hotel-{name}")
        sealed_dir.mkdir(parents=True, exist_ok=True)
        env = sealed_dir / "sealed.env"
        env.write_text(f"# test kit\nSEALED_NAME={name}\nSEALED_DIR={sealed_dir}\nSEALED_VCPUS={vcpus}\n"
                       f"SEALED_MEM_GIB={mem}\nSEALED_SCRATCH_GIB={scratch}\nSEALED_MIN_HOST_FREE_GIB={min_free}\n"
                       f"SEALED_DATA_GIB={data}\nSEALED_ROOM_NETS=\"10.214.0.0/22 10.214.4.0/22\"\n{extra}")
        return env

    def kit(self, name, active=False, **kw):
        """A kit as install-sealed.sh leaves it: sealed.env in SEALED_DIR and the units write-units.sh writes."""
        env = self.kit_env(name, **kw)
        p = subprocess.run(["bash", str(SEALED / "write-units.sh"), str(env)], capture_output=True, text=True,
                           env={**os.environ, "ROOM_DESTDIR": str(self.destdir)}, timeout=30)
        assert p.returncode == 0, p.stderr
        self.set_unit(f"room-sealed-{name}.service", active)
        return env

    def vm(self, name, vcpus=2, mem=4, disk=20, alloc_mib=None, active=False, enabled=None):
        """A VM directory as vm_ctl.py create writes it (vm.env), optionally with a sparse root.raw."""
        d = self.vms / name
        d.mkdir(parents=True)
        (d / "vm.env").write_text("".join(f"{k}='{v}'\n" for k, v in {
            "VM_NAME": name, "VM_DIR": d, "VM_VCPUS": vcpus, "VM_MEM_GIB": mem, "VM_DISK_GIB": disk,
            "VM_SSH_PORT": 22000 + len(list(self.vms.iterdir())), "VM_SLOT": 0}.items()))
        if alloc_mib is not None:
            sparse(d / "root.raw", disk * GIB, alloc_mib)
        self.set_unit(f"cathedral-vm-{name}.service", active, enabled)
        return d

    def record(self, name, install_id="0123456789abcdef", **fields):
        d = self.root / "var" / "lib" / "cathedral-snp" / "kits"
        d.mkdir(parents=True, exist_ok=True)
        rec = {"schema": "cathedral.snp.kit-reservation/v1", "name": name, "install_id": install_id,
               "env": f"/x/{name}/sealed.env",
               "sealed_dirs": [str(self.tmp / "srv" / f"sealed-hotel-{name}")], "vcpus": 8, "mem_gib": 64,
               "scratch_gib": 100, "data_gib": 0, "min_host_free_gib": 0, "data_reset_file": None,
               "data_reset_gib": None, "recorded_at": 1, **fields}
        (d / f"{name}.{install_id}.json").write_text(json.dumps(rec))
        return d / f"{name}.{install_id}.json"

    def records(self, name):
        """The open install records of a kit, oldest name first."""
        d = self.root / "var" / "lib" / "cathedral-snp" / "kits"
        return [json.loads(f.read_text()) for f in sorted(d.glob(f"{name}.*.json"))]

    def ctl(self, *args, extra=None, stdin=""):
        p = subprocess.run([str(CTL), *args], capture_output=True, text=True, input=stdin,
                           env={**self.env, **(extra or {})}, timeout=60)
        lines = p.stdout.strip().splitlines()
        assert len(lines) == 1, (p.stdout, p.stderr)
        return p.returncode, json.loads(lines[0])

    def create(self, name="vm1", port="22001", mem="1", vcpus="1", disk="4", extra=None):
        (self.tmp / "id.pub").write_text(KEY + "\n")
        image = self.tmp / "base.img"
        image.write_bytes(b"not really an image")
        return self.ctl("create", name, "--vcpus", vcpus, "--mem-gib", mem, "--disk-gib", disk,
                        "--ssh-key-file", str(self.tmp / "id.pub"), "--ssh-port", port, "--image", str(image),
                        extra=extra)

    def lock_path(self) -> Path:
        return self.root / "run" / "lock" / "cathedral-snp-capacity.lock"


def sparse(path: Path, logical: int, alloc_mib: int) -> None:
    with open(path, "wb") as f:
        f.truncate(logical)
        f.seek(0)
        for _ in range(alloc_mib):
            f.write(b"\x01" * MIB)
        f.flush()
        os.fsync(f.fileno())


@pytest.fixture
def host(tmp_path):
    return Host(tmp_path)


@pytest.fixture
def cap(host, monkeypatch):
    """The module in this process, pointed at the fake host, with a fake df (avail per device)."""
    for k in ("PATH", "FAKE_STATE", "VM_CAPACITY_ROOT", "SYSTEMD_UNIT_DIR", "VM_ROOT"):
        monkeypatch.setenv(k, host.env[k])
    mod = load_capacity()
    monkeypatch.setattr(mod, "GUEST_OVERHEAD_MIB", 1024)
    monkeypatch.setattr(mod, "VM_MIN_HOST_FREE_GIB", 0)
    mod.avail = {}  # device -> bytes; the default device gets 10 TiB
    real_device = mod.device_of
    mod.fs_mounts = {}  # path prefix -> fake device, for tests with two file systems

    def device_of(path):
        for prefix, dev in sorted(mod.fs_mounts.items(), key=lambda kv: -len(kv[0])):
            if str(path).startswith(prefix):
                return dev
        return real_device(path)

    monkeypatch.setattr(mod, "device_of", device_of)
    monkeypatch.setattr(mod, "fs_avail", lambda path: mod.avail.get(mod.device_of(path), 10 * 1024 * GIB))
    mod.fake_files = {}  # str(path) -> (size, allocated, st_dev, st_ino), or None for "gone"
    real_facts = mod.file_facts
    monkeypatch.setattr(mod, "file_facts",
                        lambda path: mod.fake_files[str(path)] if str(path) in mod.fake_files else real_facts(path))
    return mod


def refused(cap, fn, *args):
    with pytest.raises(cap.CapacityRefusal) as e:
        fn(*args)
    return e.value.resource


# ---------------------------------------------------------------- kit inventory


def test_kit_inventory_reads_unit_files_not_net_units_and_any_sealed_dir(host, cap):
    host.kit("alpha", vcpus=8, mem=64, scratch=100)  # the default SEALED_DIR layout
    host.kit("beta", sealed_dir=host.tmp / "data" / "elsewhere", vcpus=4, mem=32, scratch=50, data=20)
    host.kit("gamma-net", vcpus=2, mem=8, scratch=10)  # a kit whose own name ends in -net
    names = sorted(p.name for p in host.units.glob("room-sealed-*.service"))
    assert "room-sealed-alpha-net.service" in names and "room-sealed-gamma-net-net.service" in names
    kits, bad = cap.kit_units()
    assert bad == []
    got = {k.name: (k.vcpus, k.mem_gib, k.scratch_gib, k.data_gib, k.dirs) for k in kits}
    assert got == {
        "alpha": (8, 64, 100, 0, [str(host.tmp / "srv" / "sealed-hotel-alpha")]),
        "beta": (4, 32, 50, 20, [str(host.tmp / "data" / "elsewhere")]),
        "gamma-net": (2, 8, 10, 0, [str(host.tmp / "srv" / "sealed-hotel-gamma-net")]),
    }
    # Enabled or not: a disabled, stopped kit is counted the same.
    host.set_unit("room-sealed-alpha.service", active=False, enabled=False)
    assert {k.name for k in cap.snapshot(states=True).kits} == {"alpha", "beta", "gamma-net"}


def test_install_record_is_counted_and_merged_with_the_unit_by_name(host, cap):
    host.kit("alpha", mem=64, scratch=100)
    host.record("alpha", mem_gib=96, scratch_gib=80)  # a roll in flight: more memory, less scratch
    host.record("delta", mem_gib=16, vcpus=2)  # a new kit, no unit yet
    led = cap.snapshot()
    kits = {k.name: k for k in led.kits}
    assert set(kits) == {"alpha", "delta"}
    assert (kits["alpha"].source, kits["alpha"].mem_gib, kits["alpha"].scratch_gib) == ("unit+record", 96, 100)
    assert (kits["delta"].source, kits["delta"].mem_gib, kits["delta"].vcpus) == ("record", 16, 2)


@pytest.mark.parametrize("breakage", [
    "env_missing", "env_shell_line", "env_expansion", "mem_not_integer", "name_mismatch",
    "two_execstart", "execstart_not_launcher", "record_garbage", "record_without_install_id", "unit_masked",
])
def test_an_unreadable_kit_refuses_every_create_and_start(host, cap, breakage):
    env = host.kit("alpha")
    host.vm("vm1")
    unit = host.units / "room-sealed-alpha.service"
    if breakage == "env_missing":
        env.unlink()
    elif breakage == "env_shell_line":
        env.write_text(env.read_text() + "source /etc/other.env\n")
    elif breakage == "env_expansion":
        env.write_text(env.read_text().replace("SEALED_MEM_GIB=64", "SEALED_MEM_GIB=$((32*2))"))
    elif breakage == "mem_not_integer":
        env.write_text(env.read_text().replace("SEALED_MEM_GIB=64", "SEALED_MEM_GIB=lots"))
    elif breakage == "name_mismatch":
        env.write_text(env.read_text().replace("SEALED_NAME=alpha", "SEALED_NAME=other"))
    elif breakage == "two_execstart":
        unit.write_text(unit.read_text().replace("ExecStopPost=", "ExecStart=/bin/true\nExecStopPost="))
    elif breakage == "execstart_not_launcher":
        unit.write_text(unit.read_text().replace("launch-guest.sh", "start-something.sh"))
    elif breakage == "record_garbage":
        host.record("delta").write_text("{not json")
    elif breakage == "record_without_install_id":
        host.record("delta").rename(host.root / "var/lib/cathedral-snp/kits/delta.json")
    elif breakage == "unit_masked":
        unit.unlink()
        unit.symlink_to("/dev/null")
    assert refused(cap, cap.check_create, 1, 1, 4, host.vms / "vm2") == "kit_unaccounted"
    assert refused(cap, cap.check_start, "vm1") == "kit_unaccounted"


def test_a_damaged_kit_unit_whose_name_ends_in_net_is_unaccounted(host, cap):
    """Review P2: kit alpha-net's unit, truncated during a rewrite, while its guest runs."""
    host.kit("alpha-net", active=True)
    unit = host.units / "room-sealed-alpha-net.service"
    unit.write_text(unit.read_text()[:120])  # cut before ExecStart
    host.vm("vm1")
    assert refused(cap, cap.check_create, 1, 1, 4, host.vms / "vm2") == "kit_unaccounted"
    assert refused(cap, cap.check_start, "vm1") == "kit_unaccounted"
    # Its intact -net check unit is still recognized and skipped.
    assert [b["unit"] for b in cap.snapshot().unaccounted] == ["room-sealed-alpha-net.service"]


@pytest.mark.parametrize("damage", ["truncated", "not_oneshot", "other_command"])
def test_only_an_exact_net_check_unit_is_skipped(host, cap, damage):
    host.kit("alpha")
    net = host.units / "room-sealed-alpha-net.service"
    text = net.read_text()
    assert cap.is_net_helper(net.name, text)
    if damage == "truncated":
        net.write_text(text[:60])
    elif damage == "not_oneshot":
        net.write_text(text.replace("Type=oneshot", "Type=simple"))
    else:
        net.write_text(text.replace("host-net.sh check", "host-net.sh up"))
    assert [b["unit"] for b in cap.snapshot().unaccounted] == ["room-sealed-alpha-net.service"]
    assert refused(cap, cap.check_create, 1, 1, 4, host.vms / "vm1") == "kit_unaccounted"


def test_a_vm_env_that_does_not_parse_refuses_create(host, cap):
    d = host.vm("vm1")
    (d / "vm.env").write_text("VM_VCPUS='2'\nVM_MEM_GIB='x'\nVM_DISK_GIB='20'\n")
    assert refused(cap, cap.check_create, 1, 1, 4, host.vms / "vm2") == "vm_unaccounted"


# ---------------------------------------------------------------- memory


def test_memory_commit_counts_kits_vms_overhead_and_the_reserve(host, cap):
    # 2 kits (64 + 32) + 2 VMs (4 + 4), each plus 1 GiB, plus the 32 GiB reserve = 140 GiB.
    host.kit("alpha", mem=64)
    host.kit("beta", mem=32, active=False)  # stopped: still committed
    host.vm("vm1", mem=4)
    host.vm("vm2", mem=4)
    host.facts(mem_total_gib=140 + 9)  # room for a new 8 GiB VM (plus 1 GiB overhead), exactly
    cap.check_create(1, 8, 4, host.vms / "vm3")
    assert refused(cap, cap.check_create, 1, 9, 4, host.vms / "vm3") == "memory"


def test_memory_live_start_uses_mem_available(host, cap):
    host.vm("vm1", mem=8)
    host.facts(mem_total_gib=512, mem_avail_gib=8 + 1 + 32)
    cap.check_start("vm1")
    host.facts(mem_total_gib=512, mem_avail_gib=8 + 1 + 31)
    assert refused(cap, cap.check_start, "vm1") == "memory"


def test_a_repeated_start_of_a_running_vm_is_not_checked_again(host, cap):
    host.vm("vm1", mem=8, active=True)
    host.facts(mem_total_gib=512, mem_avail_gib=1, current=16)  # full: the running VM is part of it
    cap.check_start("vm1")


# ---------------------------------------------------------------- disk


def test_sparse_growth_is_logical_size_less_allocated(host, cap):
    f = host.tmp / "s.raw"
    sparse(f, 2 * GIB, 64)
    st = os.stat(f)
    assert cap.growth(f, 2 * GIB) == 2 * GIB - st.st_blocks * 512
    assert cap.growth(f, 2 * GIB) <= 2 * GIB - 60 * MIB
    assert cap.growth(host.tmp / "missing.raw", 5 * GIB) == 5 * GIB
    # A file bigger than its configured size still grows to its own size.
    assert cap.growth(f, 1 * GIB) == 2 * GIB - st.st_blocks * 512


def test_disk_refuses_a_vm_whose_full_size_does_not_fit_after_every_sparse_growth(host, cap):
    # One file system holding a kit (scratch 100 GiB, 64 MiB written; data 20 GiB) and a VM (20 GiB,
    # 64 MiB written). Unrelated files are already out of df avail.
    host.kit("alpha", scratch=100, data=20, min_free=0)
    sparse(host.tmp / "srv" / "sealed-hotel-alpha" / "scratch.raw", 100 * GIB, 64)
    host.vm("vm1", disk=20, alloc_mib=64)
    dev = cap.device_of(host.vms)
    grow = sum(cap.growth(f.path, f.logical) for f in cap.snapshot().sparse_files())
    assert 140 * GIB - 200 * MIB < grow < 140 * GIB
    cap.avail[dev] = grow + 40 * GIB
    cap.check_create(1, 1, 40, host.vms / "vm2")
    assert refused(cap, cap.check_create, 1, 1, 41, host.vms / "vm2") == "disk"
    # The kit's own SEALED_MIN_HOST_FREE_GIB is the reserve on its file system.
    host.kit_env("alpha", scratch=100, data=20, min_free=10)
    assert refused(cap, cap.check_create, 1, 1, 31, host.vms / "vm2") == "disk"
    cap.check_create(1, 1, 30, host.vms / "vm2")


def test_disk_is_counted_per_file_system(host, cap):
    # The kit's scratch is on another file system than the VMs: its growth does not count for them.
    host.kit("alpha", sealed_dir=host.tmp / "fs2" / "kit", scratch=1000, min_free=0)
    cap.fs_mounts[str(host.tmp / "fs2")] = 2
    cap.fs_mounts[str(host.vms)] = 1
    cap.avail.update({1: 50 * GIB, 2: 10 * GIB})
    cap.check_create(1, 1, 50, host.vms / "vm1")
    assert refused(cap, cap.check_create, 1, 1, 51, host.vms / "vm1") == "disk"
    # A start checks the VM's own file system, without adding its full size again.
    host.vm("vm1", disk=50)
    cap.check_start("vm1")
    cap.avail[1] = 50 * GIB - 1
    assert refused(cap, cap.check_start, "vm1") == "disk"


# ---------------------------------------------------------------- SNP ASIDs and vCPUs


def test_sixteen_asid_host_takes_kits_plus_vms_up_to_sixteen(host, cap):
    # A Genoa host that reports 16 SEV-ES ASIDs (spec section 9, known limit): three kits, one of
    # them stopped, keep three, so 13 VMs fit and the 14th is refused.
    host.facts(mem_total_gib=4096, threads=384, asids=16, current=2)
    host.kit("alpha", mem=8, active=True)
    host.kit("beta", mem=8, active=True)
    host.kit("gamma", mem=8, active=False)
    for i in range(12):
        host.vm(f"vm{i}", mem=1, vcpus=1)
    cap.check_create(1, 1, 4, host.vms / "vm12")
    host.vm("vm12", mem=1, vcpus=1)
    assert refused(cap, cap.check_create, 1, 1, 4, host.vms / "vm13") == "asid"
    # Live: 2 running kits in misc.current, the stopped kit keeps one, 13 stopped VMs keep none.
    cap.check_start("vm0")
    host.facts(mem_total_gib=4096, threads=384, asids=16, current=14)
    cap.check_start("vm0")  # 14 in use + 1 kept for gamma + this VM = 16
    host.facts(mem_total_gib=4096, threads=384, asids=16, current=15)
    assert refused(cap, cap.check_start, "vm0") == "asid"


def test_live_asids_count_stopped_kits_and_vms_mid_start(host, cap):
    host.facts(asids=16, current=2)
    host.kit("alpha", active=True)
    host.kit("beta", active=True)
    host.kit("gamma", active=False)  # keeps its ASID while stopped
    for i in range(12):
        host.vm(f"vm{i}", mem=1, vcpus=1, active=False, enabled=i < 11)  # 11 started, QEMU not yet counted
    host.vm("vm12", mem=1, vcpus=1)
    # max(misc.current 2, 2 kits + 11 enabled VMs) + 1 stopped kit + this VM = 15 <= 16.
    cap.check_start("vm12")
    host.set_unit("cathedral-vm-vm11.service", active=False, enabled=True)
    host.vm("vm13", mem=1, vcpus=1)
    # 2 + 12 + 1 + 1 = 16: still fits; one more enabled VM does not.
    cap.check_start("vm13")
    host.set_unit("cathedral-vm-vm12.service", active=True)
    assert refused(cap, cap.check_start, "vm13") == "asid"
    # misc.current is the floor even when the units look idle (another guest on the chip).
    host.facts(asids=16, current=15)
    for i in range(13):
        host.set_unit(f"cathedral-vm-vm{i}.service", active=False, enabled=False)
    assert refused(cap, cap.check_start, "vm13") == "asid"
    host.facts(asids=16, current=14)
    cap.check_start("vm13")
    host.facts(asids=16, current=None)
    assert refused(cap, cap.check_start, "vm13") == "asid"


def test_vcpus_are_threads_less_four(host, cap):
    host.facts(threads=32)
    host.kit("alpha", vcpus=16)
    host.vm("vm1", vcpus=8)
    cap.check_create(4, 1, 4, host.vms / "vm2")
    assert refused(cap, cap.check_create, 5, 1, 4, host.vms / "vm2") == "vcpu"


def test_unreadable_host_figures_refuse(host, cap):
    (host.root / "proc" / "meminfo").unlink()
    assert refused(cap, cap.check_create, 1, 1, 4, host.vms / "vm1") == "memory"
    host.facts()
    (host.root / "sys" / "fs" / "cgroup" / "misc.capacity").unlink()
    assert refused(cap, cap.check_create, 1, 1, 4, host.vms / "vm1") == "asid"
    host.facts()
    (host.root / "proc" / "cpuinfo").unlink()
    assert refused(cap, cap.check_create, 1, 1, 4, host.vms / "vm1") == "vcpu"


# ---------------------------------------------------------------- custom-guest hosts


@pytest.mark.parametrize("marker", ["allow", "hold_in_kit_dir", "hold_in_layout_dir", "launch", "inbox", "staging"])
def test_a_custom_guest_host_refuses_vm_create(host, cap, marker):
    host.kit("alpha", sealed_dir=host.tmp / "kits" / "alpha")
    cap.refuse_custom_guest_host()  # a plain kit host is fine
    if marker == "allow":
        (host.root / "etc" / "cathedral").mkdir(parents=True)
        (host.root / "etc" / "cathedral" / "custom-guest.allow").write_text("hotel-x\n")
    elif marker == "hold_in_kit_dir":
        (host.tmp / "kits" / "alpha" / "custom-guest.hold").write_text('{"launch_id": "cg-0123456789ab"}')
    elif marker == "hold_in_layout_dir":
        d = host.root / "srv" / "sealed-hotel-other"
        d.mkdir(parents=True)
        (d / "custom-guest.hold").write_text('{"launch_id": "cg-0123456789ab"}')
    else:
        sub = {"launch": "", "inbox": "inbox", "staging": "staging"}[marker]
        (host.root / "srv" / "custom-guest" / "hotel-x" / sub / "cg-0123456789ab").mkdir(parents=True)
    assert refused(cap, cap.refuse_custom_guest_host) == "custom_guest_host"


def test_a_returned_launch_journal_alone_is_not_a_custom_guest_host(host, cap):
    d = host.root / "srv" / "custom-guest" / "hotel-x"
    d.mkdir(parents=True)
    (d / "host-journal.jsonl").write_text("{}\n")
    (host.root / "srv" / "sealed-hotel-x-owner.pub").write_bytes(b"\0" * 32)  # a file, not a kit dir
    cap.refuse_custom_guest_host()


# ---------------------------------------------------------------- install-sealed.sh assess step


def test_assess_kit_counts_vms_and_records_the_kit(host, cap):
    host.facts(mem_total_gib=32 + 65 + 9 * 2)
    host.vm("vm1", mem=8)
    env = host.kit_env("alpha", mem=64, scratch=100)
    out = cap.assess_kit(str(env))
    [rec] = host.records("alpha")
    assert out["recorded"] and (rec["mem_gib"], rec["scratch_gib"], rec["sealed_dirs"]) == (64, 100, [str(env.parent)])
    assert rec["install_id"] == out["install_id"]
    # With a second VM there, a rerun of the same kit still fits exactly (its records count once, at
    # the larger); a larger roll does not, and its refusal writes no record.
    host.vm("vm2", mem=8)
    cap.assess_kit(str(env))
    env2 = host.kit_env("alpha", mem=72)
    assert refused(cap, cap.assess_kit, str(env2)) == "memory"
    assert [r["mem_gib"] for r in host.records("alpha")] == [64, 64]


def test_assess_kit_counts_vm_disk_growth_on_its_file_system(host, cap):
    host.vm("vm1", disk=500)
    env = host.kit_env("alpha", scratch=100, min_free=0)
    cap.avail[cap.device_of(env.parent)] = 600 * GIB
    cap.assess_kit(str(env))
    cap.avail[cap.device_of(env.parent)] = 600 * GIB - 1
    assert refused(cap, cap.assess_kit, str(env)) == "disk"


def test_a_shrinking_roll_keeps_the_running_size_until_the_new_guest_is_verified(host, cap):
    """Review P1: a 194 GiB host, a running 128 GiB kit and a 32 GiB VM, full with overhead and
    reserve. A roll to 64 GiB copies its env before the restart; if the restart is refused or
    crashes, the 128 GiB guest still runs, so no 32 GiB VM may be admitted (227 GiB committed)."""
    host.facts(mem_total_gib=32 + 129 + 33)
    installed = host.kit("alpha", mem=128, active=True)
    host.vm("vm1", mem=32)
    assert refused(cap, cap.check_create, 1, 32, 4, host.vms / "vm2") == "memory"
    # The operator's new env (install-sealed.sh $ENV_FILE), same SEALED_DIR, 64 GiB.
    new_env = host.tmp / "operator" / "alpha.env"
    new_env.parent.mkdir()
    new_env.write_text(installed.read_text().replace("SEALED_MEM_GIB=128", "SEALED_MEM_GIB=64"))
    a = cap.assess_kit(str(new_env))["install_id"]
    assert [r["mem_gib"] for r in host.records("alpha")] == [128]
    # Step 4 copies the smaller env, then the restart is refused (rooms remain) or crashes.
    shutil.copy(new_env, installed)
    assert [k.mem_gib for k in cap.kit_units()[0]] == [64]
    assert refused(cap, cap.check_create, 1, 32, 4, host.vms / "vm2") == "memory"
    # This install's re-assess (the data reset step) keeps the larger size: the unit env is 64 now.
    assert cap.assess_kit(str(new_env), install_id=a)["install_id"] == a
    assert [r["mem_gib"] for r in host.records("alpha")] == [128]
    assert refused(cap, cap.check_create, 1, 32, 4, host.vms / "vm2") == "memory"
    # The new guest is verified running at 64 GiB (install-sealed.sh commit-kit): the room comes back.
    assert cap.commit_kit(str(installed), a)["committed"]
    assert host.records("alpha") == []
    cap.check_create(1, 32, 4, host.vms / "vm2")


def test_a_confirmed_install_drops_the_record_a_failed_install_left(host, cap):
    """Review r3 P2: install A rolls a 128 GiB kit to 64 GiB, copies its env and is refused for
    live rooms: the 128 GiB guest still runs, so A's record stays. A later confirmed install B of
    the kit (one at a time: the install lock) restarts the guest from the current sealed.env, so
    its commit drops every open record and the room comes back."""
    host.facts(mem_total_gib=32 + 129 + 33)
    installed = host.kit("alpha", mem=128, active=True)
    host.vm("vm1", mem=32)
    ops = host.tmp / "operator"
    ops.mkdir()
    env_64 = ops / "a.env"
    env_64.write_text(installed.read_text().replace("SEALED_MEM_GIB=128", "SEALED_MEM_GIB=64"))

    def no_room():
        assert refused(cap, cap.check_create, 1, 32, 4, host.vms / "vm2") == "memory"

    a = cap.assess_kit(str(env_64))["install_id"]
    shutil.copy(env_64, installed)  # A copies its env, then its restart is refused
    no_room()
    assert [r["install_id"] for r in host.records("alpha")] == [a]
    assert cap.report()["kits"][0]["open_installs"] == [a]
    b = cap.assess_kit(str(env_64))["install_id"]
    no_room()
    res = cap.commit_kit(str(installed), b)  # B's guest verified at 64 GiB from sealed.env
    assert sorted(res["dropped"]) == sorted([a, b]) and host.records("alpha") == []
    assert cap.report()["kits"][0]["open_installs"] == []
    cap.check_create(1, 32, 4, host.vms / "vm2")


def test_a_commit_of_an_unknown_install_is_refused(host, cap):
    env = host.kit("alpha", mem=64)
    a = cap.assess_kit(str(env))["install_id"]
    with pytest.raises(ValueError, match="no open record"):
        cap.commit_kit(str(env), "fedcba9876543210")
    assert [r["install_id"] for r in host.records("alpha")] == [a]
    p = subprocess.run([sys.executable, "-I", str(KIT / "vm_capacity.py"), "commit-kit", "--install-id",
                        "fedcba9876543210", str(env)], capture_output=True, text=True, env=host.env, timeout=60)
    assert p.returncode == 1 and "no open record" in p.stderr and "committed" not in p.stderr
    p = subprocess.run([sys.executable, "-I", str(KIT / "vm_capacity.py"), "commit-kit", "--install-id", a, str(env)],
                       capture_output=True, text=True, env=host.env, timeout=60)
    assert p.returncode == 0 and "committed" in p.stderr and host.records("alpha") == []


def test_commit_kit_runs_only_after_the_measurement_matched():
    text = (SEALED / "install-sealed.sh").read_text()
    match = text[text.index('if [ "$GOT" = "$EXPECTED" ]'):text.index("MEASUREMENT DIFFERS")]
    assert 'vm_capacity.py" commit-kit --install-id "$VM_LEDGER_ID" "$SEALED_DIR/sealed.env"' in match
    assert 'if [ -n "${VM_LEDGER_ID:-}" ]; then' in match
    assert match.index('systemctl enable -q "$UNIT"') < match.index("commit-kit")
    assert text.count("commit-kit") == 1  # never on the refused, failed or mismatched paths
    # A failed commit keeps the records; it never fails a verified install.
    block = match[match.index("commit-kit"):]
    assert "&& VM_LEDGER_COMMITTED=1" in block[:300] and "|| log " in block[:300] and "|| exit" not in block[:300]
    # Every exit runs the ledger's exit step (log the open record, unlock), after the volume restore.
    assert "trap 'data_volume_restore_on_exit; vm_ledger_on_exit' EXIT" in text


def reset_host(host, cap, avail_gib, data_gib, allocated_gib, new_data_gib, vm_growth_gib=100):
    """A kit with a data volume, a VM disk with vm_growth_gib to grow, and avail_gib free.
    Returns (env of the replacement, fake file paths, device)."""
    env = host.kit("alpha", scratch=0, data=data_gib, min_free=64, active=True)
    d = env.parent
    dev = os.stat(d).st_dev
    data, prev = str(d / "data.raw"), str(d / "data.raw.prev")
    cap.fake_files[data] = (data_gib * GIB, allocated_gib * GIB, dev, 7)
    host.vm("vm1", disk=vm_growth_gib)
    cap.avail[cap.device_of(d)] = avail_gib * GIB
    ops = host.tmp / "operator"
    ops.mkdir()
    new_env = ops / "alpha.env"
    new_env.write_text(env.read_text().replace(f"SEALED_DATA_GIB={data_gib}", f"SEALED_DATA_GIB={new_data_gib}"))
    return env, new_env, data, prev, dev


def left_gib(cap, env):
    return cap.snapshot().fs_left(env.parent)[0] / GIB


def test_a_data_volume_reset_reserves_the_fresh_volume_next_to_data_raw_prev(host, cap):
    """Review r1 P1 numbers: 164 GiB avail, a fully allocated 100 GiB data.raw, 100 GiB of VM growth
    and a 64 GiB reserve pass exactly. A reset to a fresh 100 GiB volume is 100 GiB over."""
    env, new_env, data, prev, dev = reset_host(host, cap, 164, 100, 100, 100)
    a = cap.assess_kit(str(new_env))["install_id"]
    assert left_gib(cap, env) == 0
    shutil.copy(new_env, env)
    # The reset step asks first, before anything moves, and is refused at 164 GiB.
    assert refused(cap, cap.assess_kit, str(new_env), True, a) == "disk"
    assert [r["data_reset_file"] for r in host.records("alpha")] == [None]
    # With 100 GiB more it is reserved: before the move, after it, and once the fresh volume exists.
    cap.avail[cap.device_of(env.parent)] = 264 * GIB
    cap.assess_kit(str(new_env), True, a)
    assert [(r["data_reset_file"], r["data_reset_gib"]) for r in host.records("alpha")] == [([dev, 7], 100)]
    for step in ("assessed", "moved", "fresh volume", "committed"):
        if step == "moved":
            cap.fake_files.update({data: None, prev: (100 * GIB, 100 * GIB, dev, 7)})
        elif step == "fresh volume":
            cap.fake_files[data] = (100 * GIB, 0, dev, 8)
        elif step == "committed":
            cap.commit_kit(str(env), a)
        assert left_gib(cap, env) == 0, step
        assert refused(cap, cap.check_create, 1, 1, 1, host.vms / "vm2") == "disk", step


def test_a_shrinking_data_reset_charges_the_replacement_its_own_size(host, cap):
    """Review r2 P2: a fully allocated 100 GiB volume reset to 20 GiB, 184 GiB avail, 100 GiB of
    VM growth, 64 GiB reserve: fits exactly, at every step."""
    env, new_env, data, prev, dev = reset_host(host, cap, 184, 100, 100, 20)
    a = cap.assess_kit(str(new_env))["install_id"]
    shutil.copy(new_env, env)
    cap.assess_kit(str(new_env), True, a)
    assert left_gib(cap, env) == 0
    cap.fake_files.update({data: None, prev: (100 * GIB, 100 * GIB, dev, 7)})
    assert left_gib(cap, env) == 0
    cap.fake_files[data] = (20 * GIB, 0, dev, 8)
    assert left_gib(cap, env) == 0
    # A retry of the reset (same install) fits too.
    cap.fake_files.update({data: (100 * GIB, 100 * GIB, dev, 7), prev: None})
    cap.assess_kit(str(new_env), True, a)
    cap.fake_files.update({data: (20 * GIB, 0, dev, 8), prev: (100 * GIB, 100 * GIB, dev, 7)})
    cap.commit_kit(str(env), a)
    assert left_gib(cap, env) == 0
    assert refused(cap, cap.check_create, 1, 1, 1, host.vms / "vm2") == "disk"


def test_a_sparse_backup_counts_only_its_blocks(host, cap):
    """Review r2 P2: a 100 GiB volume with 10 GiB allocated, reset to 100 GiB, 274 GiB avail, 100 GiB
    of VM growth, 64 GiB reserve: 10 GiB left at every step; data.raw.prev cannot grow."""
    env, new_env, data, prev, dev = reset_host(host, cap, 274, 100, 10, 100)
    a = cap.assess_kit(str(new_env))["install_id"]
    shutil.copy(new_env, env)
    cap.assess_kit(str(new_env), True, a)
    assert left_gib(cap, env) == 10
    cap.fake_files.update({data: None, prev: (100 * GIB, 10 * GIB, dev, 7)})
    assert left_gib(cap, env) == 10
    cap.fake_files[data] = (100 * GIB, 0, dev, 8)
    assert left_gib(cap, env) == 10
    cap.commit_kit(str(env), a)
    assert left_gib(cap, env) == 10
    cap.check_create(1, 1, 10 - 1, host.vms / "vm2")  # fits: the backup's 90 GiB is not growth


def test_a_reset_that_is_not_confirmed_keeps_the_restored_volume_reserved(host, cap):
    """The EXIT trap moves data.raw.prev back over the fresh volume: the record stays (the install
    failed) and the restored volume keeps the larger of its own growth and the replacement."""
    env, new_env, data, prev, dev = reset_host(host, cap, 300, 100, 10, 20)
    a = cap.assess_kit(str(new_env))["install_id"]
    shutil.copy(new_env, env)
    cap.assess_kit(str(new_env), True, a)
    cap.fake_files.update({data: None, prev: (100 * GIB, 10 * GIB, dev, 7)})
    cap.fake_files.update({data: (100 * GIB, 10 * GIB, dev, 7), prev: None})  # restored
    assert left_gib(cap, env) == 300 - 90 - 100 - 64


def test_the_reset_branch_asks_the_ledger_before_it_moves_the_volume():
    text = (SEALED / "install-sealed.sh").read_text()
    branch = text[text.index("    reset)"):text.index("    keep)")]
    ask = branch.index('assess-kit --install-id "$VM_LEDGER_ID" --data-reset "$ENV_FILE"')
    assert ask < branch.index('rm -f "$SEALED_DIR/data-on-new-build"')
    assert ask < branch.index('mv -f "$SEALED_DIR/data.raw" "$SEALED_DIR/data.raw.prev"')
    assert ask < branch.index("DATA_RESET=1")  # so the EXIT trap does not stop the running guest


def test_assess_kit_refuses_while_another_kit_is_unaccounted_but_not_for_its_own(host, cap):
    host.kit("alpha")
    env_b = host.kit("beta")
    env_b.unlink()
    assert refused(cap, cap.assess_kit, str(host.kit_env("alpha"))) == "kit_unaccounted"
    # Reinstalling the broken kit itself, from a new env, is how it gets fixed.
    cap.assess_kit(str(host.kit_env("beta", sealed_dir=host.tmp / "srv" / "beta-new")))
    assert [b["name"] for b in cap.snapshot().unaccounted] == ["beta"]


def _assess_block() -> str:
    text = (SEALED / "install-sealed.sh").read_text()
    start = text.index("# Customer VMs on this host")
    return text[start:text.index("\nfi\n", start) + 4]


def run_assess_slice(host: Host, env_file: Path, tail: str = ""):
    script = host.tmp / "assess-slice.sh"
    script.write_text("#!/bin/bash\nset -euo pipefail\n"
                      f"KIT={shlex.quote(str(REPO / 'room-kit'))}\nENV_FILE={shlex.quote(str(env_file))}\n"
                      "SEALED_NAME=$(sed -n 's/^SEALED_NAME=//p' \"$ENV_FILE\")\n"
                      + _assess_block() + 'echo "ledger id ${VM_LEDGER_ID}"\n' + tail + 'echo "slice passed"\n')
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, env=host.env, timeout=60)


def test_install_sealed_runs_the_ledger_after_its_own_checks_and_before_the_build():
    text = (SEALED / "install-sealed.sh").read_text()
    block = text.index("# Customer VMs on this host")
    assert text.index("only ${MEM_FREE_GIB} GiB RAM available") < block
    assert block < text.index("# ---------------------------------------------------------------- 2. host packages")
    assert block < text.index('"$KIT/sealed/build-guest.sh" "$ENV_FILE"')
    block = _assess_block()
    assert 'VM_LEDGER_ID=$(python3 -I "$KIT/vm/vm_capacity.py" assess-kit "$ENV_FILE") || exit 1' in block
    assert block.index("flock -n 8") < block.index("assess-kit")  # one install of a kit at a time


def test_install_sealed_assess_does_nothing_without_the_vm_host_switch(host):
    env = host.kit_env("alpha")
    host.vm("vm1", mem=100000)  # would refuse every kit if counted
    p = run_assess_slice(host, env)
    assert p.returncode == 0 and "slice passed" in p.stdout and "ledger id \n" in p.stdout, p.stderr
    assert "ledger" not in p.stderr
    assert not (host.root / "var").exists() and not (host.root / "run").exists()


def test_install_sealed_assess_records_the_kit_or_refuses_with_the_switch_on(host):
    host.switch_on()
    host.facts(mem_total_gib=32 + 65 + 5)
    host.vm("vm1", mem=4)
    env = host.kit_env("alpha", mem=64, scratch=1)
    p = run_assess_slice(host, env)
    assert p.returncode == 0 and "slice passed" in p.stdout and "recorded" in p.stderr, p.stderr
    [rec] = host.records("alpha")
    assert (rec["name"], rec["env"], rec["mem_gib"]) == ("alpha", str(env), 64)
    assert f"ledger id {rec['install_id']}" in p.stdout  # kept for this install's commit
    # One more VM: no room for the kit, the install stops before the build.
    host.vm("vm2", mem=4)
    p = run_assess_slice(host, env)
    assert p.returncode == 1 and "slice passed" not in p.stdout
    assert "VM host ledger: not enough memory" in p.stderr
    # Disk on the real file system: a VM whose remaining growth exceeds what is free.
    host.facts(mem_total_gib=4096)
    host.vm("vm3", mem=1, disk=9_999_999)
    p = run_assess_slice(host, env)
    assert p.returncode == 1 and "not enough disk" in p.stderr


def kit_lock(host, name="alpha"):
    return host.root / "run" / "lock" / f"cathedral-kit-{name}.install.lock"


def lock_is_free(path: Path) -> bool:
    with open(path, "a") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(f, fcntl.LOCK_UN)
        return True


def test_a_second_install_of_a_kit_stops_at_once(host):
    """Review r3 P1: installs K and I of one kit at once. I holds the kit's install lock (from its
    assess to its exit); K stops at once, before its assess, with no record and no wait."""
    host.switch_on()
    env = host.kit_env("alpha", mem=64, scratch=1)
    lock = kit_lock(host)
    lock.parent.mkdir(parents=True)
    with open(lock, "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        t0 = time.monotonic()
        p = run_assess_slice(host, env)
        assert time.monotonic() - t0 < 30
        assert p.returncode == 1 and "another install of alpha is running" in p.stderr, p.stderr
        assert host.records("alpha") == [] and "slice passed" not in p.stdout
    # Once I has exited, K runs; another kit is never blocked by it.
    other = host.kit_env("beta", mem=8, scratch=1)
    with open(lock, "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        assert run_assess_slice(host, other).returncode == 0
    p = run_assess_slice(host, env)
    assert p.returncode == 0 and len(host.records("alpha")) == 1, p.stderr


@pytest.mark.parametrize("path", ["passes", "refused", "fails_later"])
def test_the_kit_install_lock_is_held_to_the_exit_and_released_on_every_path(host, path):
    host.switch_on()
    host.facts(mem_total_gib=32 + 65 + (1 if path == "refused" else 5))
    host.vm("vm1", mem=4)
    env = host.kit_env("alpha", mem=64, scratch=1)
    pid = host.tmp / "child.pid"
    # A process the install started that outlives it, holding the descriptor: the exit step unlocks.
    tail = (f'sleep 30 >/dev/null 2>&1 & echo $! > {shlex.quote(str(pid))}\n'
            'python3 -I -c "import fcntl,sys; f=open(sys.argv[1],\'a\'); fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB)"'
            ' "$KIT_INSTALL_LOCK" 2>/dev/null && echo "lock free during install" || echo "lock held during install"\n')
    if path == "fails_later":
        tail += "false\n"
    p = run_assess_slice(host, env, tail)
    try:
        if path == "refused":
            assert p.returncode == 1 and "not enough memory" in p.stderr and host.records("alpha") == []
            assert "was not confirmed" not in p.stderr
        else:
            assert "lock held during install" in p.stdout, p.stdout + p.stderr
            [rec] = host.records("alpha")
            assert p.returncode == (0 if path == "passes" else 1)
            # No commit on either path: the record stays, and the exit step names it.
            assert f"install {rec['install_id']} of alpha was not confirmed; its record stays" in p.stderr
        assert lock_is_free(kit_lock(host))
    finally:
        if pid.exists():
            subprocess.run(["kill", pid.read_text().strip()], capture_output=True)


# ---------------------------------------------------------------- vm-ctl.sh wiring


def test_without_the_switch_create_and_start_are_unchanged(host):
    (host.root / "proc" / "meminfo").unlink()  # admission would refuse: it is not asked
    code, vm = host.create()
    assert code == 0, vm
    now = int(time.time())
    assert host.ctl("authorize", "vm1", str(now + 600), "1")[0] == 0
    code, vm = host.ctl("start", "vm1", "--generation", "1")
    assert code == 0 and vm["state"] == "running", vm
    assert not host.lock_path().exists()


def test_create_refusal_is_exit_5_host_capacity_and_leaves_nothing(host):
    host.switch_on()
    host.facts(mem_total_gib=33)  # 32 reserve + a 1 GiB VM + 1 GiB overhead does not fit
    code, out = host.create()
    assert code == 5 and out["error"] == "host_capacity" and out["resource"] == "memory", out
    assert not (host.vms / "vm1").exists()
    assert not (host.vms / ".history" / "vm1.jsonl").exists()
    assert not (host.units / "cathedral-vm-vm1.service").exists()
    host.facts(mem_total_gib=34)
    code, vm = host.create()
    assert code == 0, vm


def test_create_refuses_on_a_custom_guest_host_with_the_switch_off(host):
    d = host.root / "srv" / "custom-guest" / "hotel-x" / "cg-0123456789ab"
    d.mkdir(parents=True)
    code, out = host.create()
    assert code == 5 and (out["error"], out["resource"]) == ("host_capacity", "custom_guest_host"), out
    assert not (host.vms / "vm1").exists()


def test_create_refuses_while_a_kit_is_unaccounted(host):
    host.switch_on()
    env = host.kit("alpha")
    env.unlink()
    code, out = host.create()
    assert code == 5 and out["resource"] == "kit_unaccounted" and "room-sealed-alpha.service" in out["detail"], out


def test_start_refusal_writes_no_start_line_and_leaves_the_unit_disabled(host):
    host.switch_on()
    assert host.create()[0] == 0
    now = int(time.time())
    assert host.ctl("authorize", "vm1", str(now + 600), "1")[0] == 0
    host.facts(mem_total_gib=512, mem_avail_gib=33)
    code, out = host.ctl("start", "vm1", "--generation", "1")
    assert code == 5 and (out["error"], out["resource"]) == ("host_capacity", "memory"), out
    lines = [json.loads(l) for l in (host.vms / ".history" / "vm1.jsonl").read_text().splitlines()]
    assert [e["event"] for e in lines] == ["tracked_from"]
    state = json.loads(host.state.read_text())["cathedral-vm-vm1.service"]
    assert not state["enabled"] and not state["active"]
    host.facts(mem_total_gib=512, mem_avail_gib=34)
    code, vm = host.ctl("start", "vm1", "--generation", "1")
    assert code == 0 and vm["state"] == "running", vm
    lines = [json.loads(l) for l in (host.vms / ".history" / "vm1.jsonl").read_text().splitlines()]
    assert [e["event"] for e in lines] == ["tracked_from", "start"]


def test_two_creates_race_for_the_last_room_and_one_wins(host):
    host.switch_on()
    host.facts(mem_total_gib=35)  # one 1 GiB VM with its overhead fits, two do not
    results = {}

    def go(name, port):
        results[name] = host.create(name, port=port)

    threads = [threading.Thread(target=go, args=(f"vm{i}", str(22001 + i))) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    codes = sorted(code for code, _ in results.values())
    assert codes == [0, 5], results
    assert [out["resource"] for code, out in results.values() if code == 5] == ["memory"]


def test_create_waits_for_a_kit_assess_and_counts_its_record(host):
    """Check-and-record: a kit install holding the lock records its kit before a create can check."""
    host.switch_on()
    host.facts(mem_total_gib=32 + 2 + 9)
    host.lock_path().parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(host.lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    result = {}
    t = threading.Thread(target=lambda: result.update(r=host.create(extra={"VM_CAPACITY_LOCK_WAIT": "20"})))
    t.start()
    time.sleep(1.0)
    assert t.is_alive(), "create did not wait for the capacity lock"
    host.record("alpha", mem_gib=9, scratch_gib=0)  # 9 GiB + 1 GiB overhead takes the room
    os.close(fd)
    t.join()
    code, out = result["r"]
    assert code == 5 and out["resource"] == "memory", out


def test_only_create_and_start_take_the_capacity_lock(host):
    host.switch_on()
    assert host.create("vm1")[0] == 0
    assert host.create("vm2", port="22002")[0] == 0
    now = int(time.time())
    for name in ("vm1", "vm2"):
        assert host.ctl("authorize", name, str(now + 600), "1")[0] == 0
    assert host.ctl("start", "vm1", "--generation", "1")[0] == 0
    fd = os.open(host.lock_path(), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        quick = {"VM_CAPACITY_LOCK_WAIT": "0.3"}
        # The positive control: create and start do wait on it, and give up.
        code, out = host.create("vm3", port="22003", extra=quick)
        assert code == 1 and out["error"] == "busy", out
        code, out = host.ctl("start", "vm2", "--generation", "1", extra=quick)
        assert code == 1 and out["error"] == "busy", out
        # The credit cutoff and the other commands never take it.
        assert host.ctl("authorize", "vm1", str(now + 600), "1", extra=quick)[0] == 0
        code, out = host.ctl("enforce", extra=quick)
        assert code == 0 and "errors" not in out, out
        code, out = host.ctl("stop", "vm1", "--generation", "1", extra=quick)
        assert code == 0 and out["state"] == "stopped", out
        code, out = host.ctl("cancel", "vm2", "1", extra=quick)
        assert code == 0 and out["closed"], out
        code, out = host.ctl("delete", "vm2", "--confirm", "vm2", extra=quick)
        assert code == 0 and out["deleted"], out
        code, out = host.ctl("capacity", extra=quick)
        assert code == 0 and [v["name"] for v in out["vms"]] == ["vm1"], out
    finally:
        os.close(fd)


def test_capacity_read_reports_the_ledger_and_checks_the_broker_maxima(host):
    host.facts(mem_total_gib=256, threads=64, asids=16, current=1)
    host.kit("alpha", vcpus=16, mem=128, scratch=1, active=True)
    host.vm("vm1", vcpus=2, mem=4, disk=4)
    code, out = host.ctl("capacity")
    assert code == 0, out
    assert out["enforced"] is False
    assert [k["name"] for k in out["kits"]] == ["alpha"] and out["kits"][0]["active"] is True
    assert out["host"]["asid_capacity"] == 16 and out["host"]["asid_current"] == 1
    # VM share: 64 - 4 - 16 vCPUs; 256 - 32 - (128 + 1) GiB; 16 - 1 ASIDs.
    assert (out["vm_share"]["vcpus"], out["vm_share"]["mem_gib"], out["vm_share"]["asids"]) == (44, 95, 15)
    assert out["commit"]["asids"] == 2 and out["unaccounted"] == []
    code, ok = host.ctl("capacity", "--broker-max-vcpus", "44", "--broker-max-mem-gib", "80")
    assert code == 0 and ok["broker_check"] == {"ok": True, "over": [], "config": {"max_vcpus": 44, "max_mem_gib": 80}}
    # 80 GiB of VM memory plus up to 15 VMs' overhead does not fit in 95 GiB; 45 vCPUs do not either.
    code, bad = host.ctl("capacity", "--broker-max-vcpus", "45", "--broker-max-mem-gib", "81")
    assert code == 1 and bad["broker_check"]["over"] == ["max_vcpus", "max_mem_gib"], bad
    code, bad = host.ctl("capacity", "--broker-max-disk-gib", str(1 << 30))
    assert code == 1 and bad["broker_check"]["over"] == ["max_disk_gib"], bad


def test_capacity_is_not_a_broker_command(host):
    code, out = host.ctl("--from-broker", extra={"SSH_ORIGINAL_COMMAND": "capacity"})
    assert code == 2 and out["error"] == "invalid_command"


def test_the_credit_cutoff_never_loads_the_ledger(host):
    """stop and enforce must work even when vm_capacity.py cannot load: only create, start and
    capacity import it."""
    kit = host.tmp / "kit-copy" / "vm"
    shutil.copytree(KIT, kit)
    ctl = kit / "vm-ctl.sh"

    def run(*args):
        p = subprocess.run([str(ctl), *args], capture_output=True, text=True, env=host.env, timeout=60)
        return p.returncode, json.loads(p.stdout.strip().splitlines()[-1])

    (host.tmp / "id.pub").write_text(KEY + "\n")
    (host.tmp / "base.img").write_bytes(b"x")
    assert run("create", "vm1", "--vcpus", "1", "--mem-gib", "1", "--disk-gib", "4", "--ssh-key-file",
               str(host.tmp / "id.pub"), "--ssh-port", "22001", "--image", str(host.tmp / "base.img"))[0] == 0
    now = int(time.time())
    assert run("authorize", "vm1", str(now + 600), "1")[0] == 0
    assert run("start", "vm1", "--generation", "1")[0] == 0
    (kit / "vm_capacity.py").write_text("raise ImportError('broken on purpose')\n")
    code, out = run("enforce")
    assert code == 0 and "errors" not in out, out
    code, out = run("stop", "vm1", "--generation", "1")
    assert code == 0 and out["state"] == "stopped", out
    code, out = run("create", "vm2", "--vcpus", "1", "--mem-gib", "1", "--disk-gib", "4", "--ssh-key-file",
                    str(host.tmp / "id.pub"), "--ssh-port", "22002", "--image", str(host.tmp / "base.img"))
    assert code == 1 and "broken on purpose" in out["detail"], out
