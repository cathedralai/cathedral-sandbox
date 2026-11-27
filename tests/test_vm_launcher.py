"""AB#999 VM3: the sealed VM launcher and its unit (VM runtime spec r2 8.1, 8.2; 13.1 T1, T4).

- T1: the argv property over every launcher input: the SNP object, the confidential machine,
  kernel-hashes=on and policy 0x30000 are always there, and no env name, vm.env key or flag
  removes them; exactly two fw_cfg names; the drive allowlist; no -smbios.
- One SNP argv function: both launchers build through snp_qemu.snp_argv.
- Exit mapping: a guest reset exits 75 (relaunch), a poweroff 0, anything else 1, a refusal 78.
- Astra r2 P1 #2: the rendered unit exposes every path the launcher reads or names in the
  argv, read only, and read-write exactly the files QEMU writes; nothing of another VM.
"""
from __future__ import annotations

import base64
import builtins
import hashlib
import importlib.util
import itertools
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import vm_host_support
from test_ab991_vm_runtime import host  # noqa: F401  (the fixture)

REPO = Path(__file__).resolve().parents[1]
KIT = REPO / "room-kit" / "vm"
LAUNCHER = KIT / "launch-vm.py"
CUSTOM_LAUNCHER = REPO / "ops" / "custom-guest" / "launch-custom-guest.py"
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHoDtpqWFYgHInGUaI+YzF7+kVPelQqOMZroOCQpu3bE"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(mod)
    return mod


L = _load("launch_vm_under_test", LAUNCHER)
SNP = L.snp_qemu
VM = L.vm_measure


@pytest.fixture
def site(tmp_path, monkeypatch):
    """A VM root with a genoa and a turin bundle and a host switch file naming both."""
    vm_root = tmp_path / "srv" / "cathedral-vms"
    bundles = {f: vm_host_support.install_bundle(vm_root, f) for f in ("genoa", "turin")}
    config = tmp_path / "snp-vm-host.json"
    config.write_text(json.dumps({"version": 1, "bundles": sorted(bundles.values())}))
    monkeypatch.setattr(L, "HOST_CONFIG", str(config))

    class Site:
        root, cfg = vm_root, config
        bundle = bundles

        def vm(self, name="vm1", family="genoa", vcpus=2, mem=4, slot=0, extra_env=None):
            d = vm_root / name
            (d / "run").mkdir(parents=True)
            manifest = json.loads((vm_root / "bundles" / bundles[family] / "manifest.json").read_bytes())
            ident = VM.identity_document("vm-0123456789ab", KEY, manifest["base_root_verity"],
                                         manifest["base_root_data_bytes"], salt_hex="0f" * 16)
            (d / "vm-identity.json").write_bytes(ident)
            for f in ("root.raw", "mailbox.raw"):
                (d / f).write_bytes(b"")
            base = (10 << 24) | (216 << 16) | 4 * slot
            ip = lambda n: ".".join(str((n >> s) & 255) for s in (24, 16, 8, 0))  # noqa: E731
            env = {"VM_NAME": name, "VM_DIR": str(d), "VM_VCPUS": str(vcpus), "VM_MEM_GIB": str(mem),
                   "VM_DISK_GIB": "8", "VM_SSH_PORT": "22001", "VM_SLOT": str(slot), "VM_TAP": f"cvm{slot}",
                   "VM_HOST_IP": ip(base + 1), "VM_GUEST_IP": ip(base + 2),
                   "VM_MAC": "52:54:00:d8:%02x:%02x" % (slot >> 8, slot & 0xFF), "VM_USER": f"cvm-{slot}",
                   "VM_ID": "vm-0123456789ab", "VM_BUNDLE": bundles[family], **(extra_env or {})}
            (d / "vm.env").write_text("".join(f"{k}='{v}'\n" for k, v in env.items()))
            return d

    return Site()


@pytest.fixture
def short_dir():
    """AF_UNIX paths are capped near 104 bytes: sockets live in a short directory."""
    import shutil
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="vm3", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def opt(argv: list[str], name: str) -> list[str]:
    return SNP.values_of(argv, name)


def assert_snp(argv: list[str]) -> None:
    snp = [o for o in opt(argv, "-object") if o.startswith("sev-snp-guest,")]
    assert len(snp) == 1
    fields = snp[0].split(",")
    assert "policy=0x30000" in fields and "kernel-hashes=on" in fields
    assert opt(argv, "-machine") == ["q35,confidential-guest-support=sev0,memory-backend=ram1"]
    assert "-no-reboot" in argv and "-smbios" not in argv and "-runas" not in argv


# ---- T1: golden argv and the property --------------------------------------------------

def test_golden_argv(site):
    d = site.vm()
    b = site.root / "bundles" / site.bundle["genoa"]
    ident = (d / "vm-identity.json").read_bytes()
    hd = base64.b64encode(hashlib.sha256(b"cathedral-vm-v1\0" + hashlib.sha256(ident).digest()).digest()).decode()
    line = VM.CMDLINE_TEMPLATE_V1.replace("{identity_sha256}", hashlib.sha256(ident).hexdigest())
    assert L.build_argv(str(d)) == [
        "/usr/bin/qemu-system-x86_64", "-no-user-config", "-nodefaults", "-no-reboot", "-S", "-name", "cathedral-vm-vm1",
        "-enable-kvm", "-cpu", "EPYC-v4", "-smp", "2", "-m", "4G",
        "-machine", "q35,confidential-guest-support=sev0,memory-backend=ram1",
        "-object", "memory-backend-memfd,id=ram1,size=4G,share=true,prealloc=false",
        "-object", f"sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,host-data={hd}",
        "-bios", f"{b}/OVMF.amdsev.fd", "-kernel", f"{b}/vmlinuz", "-initrd", f"{b}/initrd.cpio.zst",
        "-append", line,
        "-drive", f"if=none,id=root,format=raw,file={d}/root.raw,cache=none,aio=io_uring",
        "-device", "virtio-blk-pci,drive=root,serial=cathedral-root,disable-legacy=on,iommu_platform=true",
        "-drive", f"if=none,id=base,format=raw,readonly=on,file={b}/base-root.raw,cache=none,aio=io_uring",
        "-device", "virtio-blk-pci,drive=base,serial=cathedral-base,disable-legacy=on,iommu_platform=true",
        "-drive", f"if=none,id=mailbox,format=raw,file={d}/mailbox.raw,cache=none,aio=io_uring",
        "-device", "virtio-blk-pci,drive=mailbox,serial=cathedral-mailbox,disable-legacy=on,iommu_platform=true",
        "-netdev", "tap,id=net0,ifname=cvm0,script=no,downscript=no,vhost=on",
        "-device", "virtio-net-pci,netdev=net0,mac=52:54:00:d8:00:00,disable-legacy=on,iommu_platform=true,romfile=",
        "-fw_cfg", f"name=opt/cathedral/vm-identity.json,file={d}/vm-identity.json",
        "-fw_cfg", "name=opt/cathedral/link,string=10.216.0.1 10.216.0.2",
        "-qmp", f"unix:{d}/run/qmp.sock,server=on,wait=off",
        "-qmp", f"unix:{d}/run/events.sock,server=on,wait=off",
        "-display", "none", "-vga", "none", "-monitor", "none",
        "-chardev", "ringbuf,id=serial0,size=1M", "-serial", "chardev:serial0",
        "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]


# A vm.env key, an env name or an argument that reads as a way out of SNP.
HOSTILE_ENV = {"VM_PLAIN": "1", "VM_SNP": "0", "VM_SEALED": "0", "VM_MACHINE": "pc", "VM_POLICY": "0x0",
               "VM_CPU_MODEL": "EPYC-Genoa-v1", "CPU_MODEL": "host", "VM_CPU": "host",
               "VM_KERNEL_HASHES": "off", "QEMU": "/bin/true", "VM_SMBIOS": "type=11,value=x",
               "VM_EXTRA_ARGS": "-machine pc"}


def test_property_every_argv_keeps_the_snp_object(site, monkeypatch):
    families, vcpus, mems, slots = ("genoa", "turin"), (1, 2, 64), (1, 4, 512), (0, 1, 16383)
    for n, (family, cpus, mem, slot) in enumerate(itertools.product(families, vcpus, mems, slots)):
        d = site.vm(f"vm{n}", family, cpus, mem, slot)
        plain = L.build_argv(str(d))
        assert_snp(plain)
        # Toby 12:19Z: EPYC-v4 is the one vCPU model, on Genoa and Turin hosts alike.
        assert opt(plain, "-cpu") == ["EPYC-v4"] and opt(plain, "-smp") == [str(cpus)]
        assert [f.split(",", 1)[0] for f in opt(plain, "-fw_cfg")] == [
            "name=opt/cathedral/vm-identity.json", "name=opt/cathedral/link"]
        # The same VM with hostile vm.env keys and process env: byte for byte the same argv.
        with (d / "vm.env").open("a") as f:
            f.write("".join(f"{k}='{v}'\n" for k, v in HOSTILE_ENV.items()))
        with monkeypatch.context() as m:
            for k, v in HOSTILE_ENV.items():
                m.setenv(k, v)
            assert L.build_argv(str(d)) == plain


@pytest.mark.parametrize("args", [["--plain"], ["--print", "--plain"], ["--no-snp"], ["--machine", "pc"]])
def test_no_flag_changes_the_argv(site, args):
    d = site.vm()
    assert L.main([str(d), *args]) == 2  # usage: the only flag is --print


@pytest.mark.parametrize("mutate", [
    lambda a: [x for i, x in enumerate(a) if not (x.startswith("sev-snp-guest,") or
                                                  (x == "-object" and a[i + 1].startswith("sev-snp-guest,")))],
    lambda a: [x.replace("policy=0x30000", "policy=0x10000") for x in a],
    lambda a: [x.replace("kernel-hashes=on", "kernel-hashes=off") for x in a],
    lambda a: [x.replace("confidential-guest-support=sev0,", "") for x in a],
    lambda a: [x for x in a if x != "-no-reboot"],
    lambda a: [x for x in a if x != "-S"],
    lambda a: a + ["-smbios", "type=11,value=io.systemd.credential:x=y"],
    lambda a: a + ["-runas", "root"],
    lambda a: a + ["-fw_cfg", "name=opt/io.systemd.credentials/x,string=y"],
    lambda a: a + ["-drive", "if=none,id=kit,format=raw,file=/srv/sealed-hotel/data.raw"],
    lambda a: [x.replace("readonly=on,", "") for x in a],
    lambda a: a + ["-object", "sev-guest,id=sev1,policy=0x1"],
    lambda a: [x.replace(",iommu_platform=true", "") for x in a],
    lambda a: a + ["-netdev", "user,id=net1"],
    lambda a: [x.replace("EPYC-v4", "EPYC-Genoa-v1") for x in a],
    lambda a: [x.replace("EPYC-v4", "host") for x in a],
])
def test_check_argv_refuses_every_mutation(site, mutate):
    d = site.vm()
    argv = L.build_argv(str(d))
    L.check_argv(argv, str(d), site.bundle["genoa"])
    with pytest.raises((L.LaunchError, SNP.SnpArgvError)):
        L.check_argv(mutate(list(argv)), str(d), site.bundle["genoa"])


def test_the_vm_cpu_model_is_epyc_v4_and_not_a_parameter():
    assert SNP.VM_CPU_MODEL == VM.CPU_MODEL == "EPYC-v4"  # launch and expected measurement agree
    assert set(VM.CPU_MODELS.values()) == {"EPYC-v4"}
    with pytest.raises(SNP.SnpArgvError):
        SNP.sealed_vm_argv(cpu_model="EPYC-Genoa-v1", name="x", vcpus=1, mem_gib=1, host_data_b64="A" * 43 + "=",
                           ovmf="o", kernel="k", initrd="i", cmdline="c", devices=[], qmp_sockets=[])
    src = LAUNCHER.read_text()
    assert "EPYC-" not in src.replace("(EPYC-v4)", "") and "cpu_model=" not in src


def test_both_launchers_build_through_one_snp_function():
    assert "snp_qemu.sealed_vm_argv(" in LAUNCHER.read_text()
    assert "snp_qemu.snp_argv(" in CUSTOM_LAUNCHER.read_text()
    for path in (LAUNCHER, CUSTOM_LAUNCHER):
        src = path.read_text()
        assert "snp_qemu.check_snp_argv(" in src, path.name
        assert '"sev-snp-guest' not in src and "'sev-snp-guest" not in src, path.name  # no SNP object of its own
    # The custom guest reaches the same file through a link, and installs it beside its launcher.
    assert (REPO / "ops" / "custom-guest" / "snp_qemu.py").resolve() == (KIT / "snp_qemu.py").resolve()
    assert '"snp_qemu.py")' in (REPO / "ops" / "custom-guest" / "custom_guest_host.py").read_text()


# ---- refusals: off by default ------------------------------------------------------------

def test_every_launch_refuses_without_the_host_switch(site, capsys):
    d = site.vm()
    site.cfg.unlink()
    assert L.main([str(d), "--print"]) == 78
    assert "this host runs no sealed VM" in capsys.readouterr().err
    site.cfg.write_text(json.dumps({"version": 1, "bundles": [site.bundle["turin"]]}))
    assert L.main([str(d), "--print"]) == 78
    assert "not enabled on this host" in capsys.readouterr().err


@pytest.mark.parametrize("what", ["vm_dir", "tap", "identity", "manifest", "bundle_name", "vcpus"])
def test_refuses_inconsistent_launch_inputs(site, capsys, what):
    d = site.vm()
    env = (d / "vm.env").read_text()
    b = site.root / "bundles" / site.bundle["genoa"]
    if what == "vm_dir":
        (d / "vm.env").write_text(env.replace(f"VM_DIR='{d}'", f"VM_DIR='{d.parent / 'vm2'}'"))
    elif what == "tap":
        (d / "vm.env").write_text(env.replace("VM_TAP='cvm0'", "VM_TAP='cvm1'"))
    elif what == "identity":
        (d / "vm-identity.json").write_bytes((d / "vm-identity.json").read_bytes().replace(b'"version":1', b'"version": 1'))
    elif what == "manifest":
        (b / "manifest.json").write_bytes((b / "manifest.json").read_bytes().replace(b'"label":"', b'"label":"x'))
    elif what == "bundle_name":
        # An enabled id whose directory holds another manifest.
        import shutil
        shutil.copytree(b, site.root / "bundles" / ("e" * 64))
        site.cfg.write_text(json.dumps({"version": 1, "bundles": [site.bundle["genoa"], "e" * 64]}))
        (d / "vm.env").write_text(env.replace(site.bundle["genoa"], "e" * 64))
    elif what == "vcpus":
        (d / "vm.env").write_text(env.replace("VM_VCPUS='2'", "VM_VCPUS='65'"))
    assert L.main([str(d), "--print"]) == 78, what
    assert "refused" in capsys.readouterr().err


def test_the_launcher_never_runs_qemu_as_root(site, monkeypatch, capsys):
    d = site.vm()
    monkeypatch.setattr(L.os, "geteuid", lambda: 0)
    monkeypatch.setattr(L, "run", lambda *a: pytest.fail("QEMU started as root"))
    assert L.main([str(d)]) == 78
    assert "never as root" in capsys.readouterr().err


# ---- T4: exit mapping -------------------------------------------------------------------

@pytest.mark.parametrize("rc,reason,code", [
    (0, "guest-reset", 75), (0, "host-qmp-system-reset", 75), (0, "guest-shutdown", 0), (0, "host-signal", 0),
    (0, "host-qmp-quit", 0), (0, None, 0), (0, "guest-panic", 1), (1, "guest-shutdown", 1), (-9, None, 1),
])
def test_exit_code(rc, reason, code):
    assert L.exit_code(rc, reason) == code


# A QEMU started with -S: the guest runs (and can power off or reset) only after cont.
FAKE_QEMU = textwrap.dedent('''
    import json, socket, sys, time
    path, mode, rc, log = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    if mode == "no-socket":
        time.sleep(30)
        sys.exit(0)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    s.listen(1)
    c, _ = s.accept()
    f = c.makefile("rwb")
    f.write(b'{"QMP": {"version": {}, "capabilities": []}}\\n'); f.flush()
    got = []
    for _ in range(2):
        got.append(json.loads(f.readline())["execute"])
        open(log, "w").write(json.dumps(got))
        if got[-1] == "cont" and mode == "refuse-cont":
            f.write(b'{"error": {"class": "GenericError", "desc": "no"}}\\n'); f.flush()
            time.sleep(30)  # paused until the launcher ends it
            sys.exit(0)
        if got[-1] == "cont":
            f.write(b'{"event": "RESUME", "data": {}}\\n')  # an event before the reply, as QEMU may send
        f.write(b'{"return": {}}\\n'); f.flush()
    if mode != "none":  # the guest ran, then powered off or reset
        f.write(json.dumps({"event": "SHUTDOWN", "data": {"guest": True, "reason": mode}}).encode() + b"\\n")
        f.flush()
    sys.exit(rc)
''')


@pytest.mark.parametrize("mode,rc,code", [("guest-reset", 0, 75), ("guest-shutdown", 0, 0), ("none", 0, 0),
                                          ("guest-shutdown", 1, 1), ("refuse-cont", 0, 1), ("no-socket", 0, 1)])
def test_run_lets_the_guest_run_only_after_it_listens(tmp_path, short_dir, monkeypatch, mode, rc, code):
    """Astra #789 P2: QEMU starts paused and the launcher sends cont only after qmp_capabilities,
    so no SHUTDOWN can be lost; no socket or a refused cont ends QEMU as a failure."""
    import time
    monkeypatch.setattr(L, "EVENTS_CONNECT_WAIT", 1.0)
    script, log = tmp_path / "fake_qemu.py", tmp_path / "qmp.log"
    script.write_text(FAKE_QEMU)
    sock = short_dir / "ev.sock"
    t0 = time.monotonic()
    assert L.run([sys.executable, str(script), str(sock), mode, str(rc), str(log)], str(sock)) == code
    assert time.monotonic() - t0 < 20  # a paused QEMU is ended, not waited on
    if mode != "no-socket":
        assert json.loads(log.read_text()) == ["qmp_capabilities", "cont"]


def test_start_paused_changes_no_measured_input():
    """-S is not a launch measurement input: every measured option is the same with and without it."""
    kw = dict(name="x", cpu_model="EPYC-v4", vcpus=2, mem_gib=4, host_data_b64="A" * 43 + "=", ovmf="/b/o",
              kernel="/b/k", initrd="/b/i", cmdline="console=ttyS0", devices=[], qmp_sockets=["/r/q"])
    plain, paused = SNP.snp_argv(**kw), SNP.snp_argv(**kw, start_paused=True)
    assert [x for x in paused if x != "-S"] == plain and paused.count("-S") == 1
    for flag in ("-object", "-machine", "-cpu", "-smp", "-m", "-bios", "-kernel", "-initrd", "-append"):
        assert opt(paused, flag) == opt(plain, flag), flag
    with pytest.raises(SNP.SnpArgvError):
        SNP.sealed_vm_argv(**{k: v for k, v in kw.items() if k != "cpu_model"}, start_paused=False)


# ---- Astra r2 P1 #2: the unit exposes what the launcher reads ----------------------------------

def unit_props(text: str) -> dict[str, list[str]]:
    props: dict[str, list[str]] = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith(("[", "#")):
            k, v = line.split("=", 1)
            props.setdefault(k, []).append(v)
    return props


def under(path: str, roots: list[str]) -> bool:
    p = os.path.normpath(path)
    return any(p == r or p.startswith(r.rstrip("/") + "/") for r in map(os.path.normpath, roots))


def launcher_reads(monkeypatch, d: Path) -> tuple[list[str], set[str]]:
    """(argv, every path the launcher opened) for one in-process --print."""
    seen: set[str] = set()
    real_open, real_os_open = builtins.open, os.open

    def spy_open(file, *a, **k):
        if isinstance(file, (str, os.PathLike)):
            seen.add(os.path.realpath(file))
        return real_open(file, *a, **k)

    def spy_os_open(path, *a, **k):
        seen.add(os.path.realpath(path))
        return real_os_open(path, *a, **k)

    builtins.open, os.open = spy_open, spy_os_open
    try:
        argv = L.build_argv(str(d))
    finally:
        builtins.open, os.open = real_open, real_os_open
    return argv, seen


def argv_paths(argv: list[str]) -> tuple[set[str], set[str]]:
    """(paths QEMU reads, paths QEMU writes) named in the argv."""
    reads, writes = set(), set()
    for flag in ("-bios", "-kernel", "-initrd"):
        reads |= set(opt(argv, flag))
    for spec in opt(argv, "-drive") + opt(argv, "-fw_cfg"):
        fields = dict(f.split("=", 1) for f in spec.split(",") if "=" in f)
        if "file" in fields:
            (reads if fields.get("readonly") == "on" or "name" in fields else writes).add(fields["file"])
    for q in opt(argv, "-qmp"):
        writes.add(q.split(",", 1)[0].removeprefix("unix:"))
    return reads, writes


def test_the_unit_exposes_every_path_the_launcher_reads(host, monkeypatch):  # noqa: F811
    assert host.create()[0] == 0
    assert host.create("vm2", port="22002")[0] == 0
    d = Path(os.path.realpath(host.root / "vm1"))
    props = unit_props((host.units / "cathedral-vm-vm1.service").read_text())
    ro = [os.path.realpath(x) for x in " ".join(props["BindReadOnlyPaths"]).split()]
    rw = [os.path.realpath(x) for x in " ".join(props["BindPaths"]).split()]
    hidden = [h.rsplit(":", 1)[0] for h in props["TemporaryFileSystem"]]
    assert "/srv" in hidden and under(str(d), hidden)  # VM_ROOT is hidden here (tmp is not under /srv)
    monkeypatch.setattr(L, "HOST_CONFIG", str(host.config))
    config = json.loads(host.config.read_text())
    host.config.write_text(json.dumps({"version": 1, "bundles": config["bundles"]}))
    argv, opened = launcher_reads(monkeypatch, host.root / "vm1")
    assert {f"{d}/vm.env", f"{d}/vm-identity.json"} <= opened  # the P1 #2 inputs are read
    reads, writes = argv_paths(argv)
    # The launcher's own code: ExecStart names it, python3 -I imports the two modules beside it.
    code = {str(LAUNCHER.resolve()), str((KIT / "snp_qemu.py").resolve()), str((KIT / "vm_measure.py").resolve())}
    exposed = ro + rw
    for path in sorted((opened | code) - {os.path.realpath(host.config)}):
        assert under(path, exposed), f"the launcher reads {path}, which the unit hides"
    for path in sorted(writes):
        assert under(os.path.realpath(path), rw), f"QEMU writes {path}, which the unit does not bind read-write"
    for path in sorted(reads):
        assert under(os.path.realpath(path), exposed), f"QEMU reads {path}, which the unit hides"
    assert set(rw) == {f"{d}/root.raw", f"{d}/mailbox.raw", f"{d}/run"}
    # Nothing of another VM, and the VM directory itself (authorization, history) is not exposed.
    vm2 = os.path.realpath(host.root / "vm2")
    assert not any(under(p, [vm2]) for p in exposed)
    assert str(d) not in exposed and not any(p.endswith(("authorization.json", "launch.json")) for p in exposed)
    # ExecStart is the launcher on this VM's directory, as the VM's own user.
    assert props["ExecStart"] == [f"/usr/bin/python3 -I {KIT / 'launch-vm.py'} {host.root / 'vm1'}"]
    assert props["User"] == ["cvm-0"] and props["Group"] == ["cvm-0"]


def test_unit_confinement_and_restart_policy(host):  # noqa: F811
    assert host.create()[0] == 0
    text = (host.units / "cathedral-vm-vm1.service").read_text()
    props = unit_props(text)
    assert props["SupplementaryGroups"] == ["kvm cvm-sev"]
    assert props["Restart"] == ["on-failure"] and props["RestartForceExitStatus"] == ["75"]
    assert props["RestartPreventExitStatus"] == ["78"]
    assert props["StartLimitBurst"] == ["5"] and props["StartLimitIntervalSec"] == ["900"]
    assert props["MemoryMax"] == ["17G"] and props["MemorySwapMax"] == ["0"] and props["LimitMEMLOCK"] == ["infinity"]
    assert props["RestrictAddressFamilies"] == ["AF_UNIX"] and props["CapabilityBoundingSet"] == [""]
    assert props["NoNewPrivileges"] == ["yes"] and props["ProtectSystem"] == ["strict"]
    assert props["DevicePolicy"] == ["closed"]
    assert set(props["DeviceAllow"]) == {"/dev/kvm rw", "/dev/sev rw", "/dev/vhost-net rw", "/dev/net/tun rw"}
    # Root steps run outside the sandbox with '+'; QEMU never does.
    pre = props["ExecStartPre"]
    assert all(p.startswith("+") for p in pre) and len(pre) == 6
    assert any("check-paid vm1" in p for p in pre) and any("vm-net.sh up" in p for p in pre)
    # The pre-launch gates (8.3, #788): after the credit check, before the link comes up.
    gates = [i for i, p in enumerate(pre) if p == f"+{KIT.resolve()}/vm-gates.sh check vm1"]
    paid = [i for i, p in enumerate(pre) if "check-paid vm1" in p]
    up = [i for i, p in enumerate(pre) if "vm-net.sh up" in p]
    assert len(gates) == 1 and paid[0] < gates[0] < up[0], pre
    assert any("modprobe -q kvm_amd" in p for p in pre) and any("/dev/kvm" in p for p in pre)
    assert props["ExecStopPost"][0].startswith("+") and "vm-net.sh down" in props["ExecStopPost"][0]
    assert props["ExecStop"][0].startswith("+") and not props["ExecStart"][0].startswith("+")
    assert "-runas" not in text


def _qmp_server(path: Path, got: list):
    import socket
    import threading
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(1)
    srv.settimeout(5)

    def one():
        try:
            c, _ = srv.accept()
        except OSError:
            return
        f = c.makefile("rwb")
        f.write(b'{"QMP": {}}\n')
        f.flush()
        for _ in range(2):
            got.append(json.loads(f.readline())["execute"])
            f.write(b'{"return": {}}\n')
            f.flush()
        c.close()
    threading.Thread(target=one, daemon=True).start()
    return srv


def test_the_qmp_helper_connects_as_the_vm_user_from_run(short_dir, monkeypatch):
    """Astra #789 P1: root's QMP connect runs in a child that starts in run/, drops to the VM
    user with no supplementary groups, and connects to qmp.sock relative to run/."""
    import pwd
    me = pwd.getpwuid(os.getuid())
    run_dir = short_dir / "vm1" / "run"
    run_dir.mkdir(parents=True)
    (short_dir / "vm1" / "vm.env").write_text(f"VM_NAME='vm1'\nVM_USER='{me.pw_name}'\n")
    monkeypatch.setenv("VM_ROOT", str(short_dir))
    mod = _load("vm_ctl_qmp_test", KIT / "vm_ctl.py")
    other, got = short_dir / "o.sock", []
    srv = _qmp_server(other, got)
    sock = run_dir / "qmp.sock"
    os.symlink(other, sock)
    assert mod.qmp("vm1", "system_powerdown", timeout=1) is False and got == []  # fails fast on a link
    srv.close()
    sock.unlink()
    got = []
    srv = _qmp_server(sock, got)
    assert mod.qmp("vm1", "system_powerdown", timeout=3) is True and got == ["qmp_capabilities", "system_powerdown"]
    srv.close()
    # As root, the child gets exactly the VM user's uid and gid, no groups, and cwd run/.
    seen = {}

    def spy(argv, **kw):
        seen.update(kw, argv=argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    monkeypatch.setattr(mod.subprocess, "run", spy)
    assert mod.qmp("vm1", "system_powerdown") is True
    assert (seen["user"], seen["group"], seen["extra_groups"]) == (me.pw_uid, me.pw_gid, [])
    assert seen["cwd"] == str(run_dir) and seen["argv"][-3:] == ["qmp-as-vm-user", "system_powerdown", "5"]
    assert "qmp-as-vm-user" not in mod.COMMANDS  # never reachable from the broker
    with pytest.raises(mod.Refusal):  # and never run as root itself
        mod.cmd_qmp_as_vm_user(["system_powerdown", "1"])
    with pytest.raises(mod.Refusal):
        mod.cmd_qmp_as_vm_user(["quit", "1"])


ROOT_SWAP = textwrap.dedent('''
    import importlib.util, json, os, pwd, shutil, socket, stat, sys, threading
    kit, base = sys.argv[1], sys.argv[2]
    nobody = pwd.getpwnam("nobody")
    try:
        victim = os.path.join(base, "victim")
        os.mkdir(victim, 0o700)  # another VM's directory: root's, 0700
        hits = []
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(os.path.join(victim, "qmp.sock"))
        srv.listen(4)
        srv.settimeout(3)

        def accept():
            try:
                while True:
                    c, _ = srv.accept()
                    hits.append(1)
                    c.close()
            except OSError:
                pass
        threading.Thread(target=accept, daemon=True).start()
        # The kit in a world-readable place, so the dropped child can run it.
        kit_copy = os.path.join(base, "kit")
        os.mkdir(kit_copy, 0o755)
        for f in ("vm_ctl.py", "vm_measure.py", "vm_mailbox.py"):
            shutil.copy(os.path.join(kit, f), kit_copy)
        vms = os.path.join(base, "vms")

        def vm(name):
            d = os.path.join(vms, name)
            os.makedirs(os.path.join(d, "run"))
            os.chmod(d, 0o700)
            os.chown(os.path.join(d, "run"), nobody.pw_uid, nobody.pw_gid)
            with open(os.path.join(d, "vm.env"), "w") as f:
                f.write(f"VM_NAME='{name}'\\nVM_USER='nobody'\\n")
            return d
        d = vm("vm1")
        # Positive control: vm2's own socket, served by "its QEMU" (owned by nobody), is reached.
        d2 = vm("vm2")
        own = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        own.bind(os.path.join(d2, "run", "qmp.sock"))
        os.chown(os.path.join(d2, "run", "qmp.sock"), nobody.pw_uid, nobody.pw_gid)
        own.listen(1)
        own.settimeout(5)

        def serve_own():
            c, _ = own.accept()
            f = c.makefile("rwb")
            f.write(b'{"QMP": {}}\\n'); f.flush()
            for _ in range(2):
                f.readline()
                f.write(b'{"return": {}}\\n'); f.flush()
            c.close()
        threading.Thread(target=serve_own, daemon=True).start()
        # The swap after root's check: qmp.sock is a link to the victim, yet lstat says socket.
        os.symlink(os.path.join(victim, "qmp.sock"), os.path.join(d, "run", "qmp.sock"))
        os.environ["VM_ROOT"] = vms
        spec = importlib.util.spec_from_file_location("vm_ctl_root", os.path.join(kit_copy, "vm_ctl.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        real_lstat = os.lstat
        fake = os.stat_result((stat.S_IFSOCK | 0o755,) + tuple(real_lstat(victim))[1:])
        mod.os.lstat = lambda p, *a, **k: fake if str(p).endswith("qmp.sock") else real_lstat(p, *a, **k)
        own_ok = mod.qmp("vm2", "system_powerdown", timeout=3)
        ok = mod.qmp("vm1", "system_powerdown", timeout=2)
        print(json.dumps({"own": own_ok, "qmp": ok, "victim_hits": len(hits)}))
    finally:
        shutil.rmtree(base, ignore_errors=True)
''')


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs Linux and passwordless sudo")
def test_a_swapped_qmp_link_cannot_reach_another_vm_as_root(tmp_path):
    """Astra #789 P1, the review's deterministic swap, run as root: the link passes root's
    check, and the connect, made as the VM user, still cannot reach the victim's socket."""
    import shutil
    import tempfile
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        if os.environ.get("CI"):
            pytest.fail("CI must run this as root (sudo -n)")
        pytest.skip("no passwordless sudo")
    base = tempfile.mkdtemp(prefix="vq", dir="/tmp")
    os.chmod(base, 0o755)
    script = tmp_path / "swap.py"
    script.write_text(ROOT_SWAP)
    try:  # the base interpreter, so the dropped child can run it too (not a venv under $HOME)
        p = subprocess.run(["sudo", "-n", os.path.realpath(sys.executable), "-I", "-B", str(script), str(KIT), base],
                           capture_output=True, text=True, timeout=60)
    finally:
        shutil.rmtree(base, ignore_errors=True)  # the script removes what root made
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout.strip().splitlines()[-1]) == {"own": True, "qmp": False, "victim_hits": 0}
