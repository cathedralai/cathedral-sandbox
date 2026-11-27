"""Custom SNP guest launcher (spec-r9 5.7, 8.5; test plan 14.1 "Launcher").

Golden argv for root only and root plus data, the SNP property, exactly three
fw_cfg names, no -smbios, the cmdline as one argv element, and the HOST_DATA
function shared with room-kit/sealed/launch-guest.sh (v2)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LAUNCHER = REPO / "ops" / "custom-guest" / "launch-custom-guest.py"
OWNER = bytes(range(32))
CMDLINE = ("console=ttyS0 cathedral.owner=" + base64.urlsafe_b64encode(OWNER).rstrip(b"=").decode()
           + " cathedral.root_verity=" + "ab" * 32 + " cathedral.root_data_bytes=4096 systemd.import_credentials=no")


def canonical(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def make_launch(tmp_path: Path, data_disk_gib: int = 0, cmdline: str = CMDLINE) -> Path:
    d = tmp_path / "srv" / "custom-guest" / "chi-ur-2" / "cg-0123456789ab"
    img = d / "images"
    img.mkdir(parents=True)
    for name in ("vmlinuz", "initrd", "root.raw", "OVMF.amdsev.fd"):
        (img / name).write_bytes(name.encode())
    (img / "cmdline").write_bytes(cmdline.encode())
    manifest = {"version": 1, "schema": "cathedral.custom_guest.manifest/v1", "kind": "custom_guest",
                "sha256": {}, "bytes": {}, "cmdline": CMDLINE, "root_verity": "ab" * 32, "root_data_bytes": 4096,
                "vcpus": 4, "cpu_model": "EPYC-Genoa-v1", "mem_gib": 24, "data_disk_gib": data_disk_gib,
                "policy": "0x30000", "qemu_version": "10.2.1", "sev_snp_measure": "0.0.12", "reference_initrd": "1"}
    m_raw = canonical(manifest)
    bootstrap = {"version": 1, "schema": "cathedral.custom_guest.bootstrap/v1", "launch_id": "cg-0123456789ab",
                 "hotel": "chi-ur-2", "owner_scope": "user:x", "owner_ed25519_b64": base64.b64encode(OWNER).decode(),
                 "manifest_sha256": hashlib.sha256(m_raw).hexdigest(), "ssh_public_key": "ssh-ed25519 AAAA",
                 "launch_nonce_hex": "00" * 32, "ports": [{"guest": 22, "proto": "tcp", "public": 20022}],
                 "network": {"guest_ip": "10.217.0.2", "host_ip": "10.217.0.1", "prefix": 30,
                             "guest_mac": "52:54:00:c7:01:23", "public_host": "84.32.63.93"}}
    (img / "manifest.json").write_bytes(m_raw)
    (img / "bootstrap.json").write_bytes(canonical(bootstrap))
    (img / "bootstrap.sig").write_bytes(b"\0" * 64)
    return d


def argv_of(d: Path) -> tuple[int, list[str] | str]:
    p = subprocess.run([sys.executable, "-I", str(LAUNCHER), str(d), "--print"], capture_output=True, text=True)
    return p.returncode, (json.loads(p.stdout) if p.returncode == 0 else p.stderr)


def host_data_b64(d: Path) -> str:
    img = d / "images"
    m, b = (img / "manifest.json").read_bytes(), (img / "bootstrap.json").read_bytes()
    return base64.b64encode(hashlib.sha256(b"cathedral-dedicated-v2\0" + hashlib.sha256(m).digest() + OWNER
                                           + hashlib.sha256(b).digest()).digest()).decode()


def golden(d: Path, data: bool) -> list[str]:
    d = Path(os.path.realpath(d))
    img = d / "images"
    out = ["/usr/bin/qemu-system-x86_64", "-no-user-config", "-nodefaults", "-no-reboot",
           "-name", "custom-guest-cg-0123456789ab", "-enable-kvm", "-cpu", "EPYC-Genoa-v1", "-smp", "4", "-m", "24G",
           "-machine", "q35,confidential-guest-support=sev0,memory-backend=ram1",
           "-object", "memory-backend-memfd,id=ram1,size=24G,share=true,prealloc=false",
           "-object", "sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,"
                      f"host-data={host_data_b64(d)}",
           "-bios", f"{img}/OVMF.amdsev.fd", "-kernel", f"{img}/vmlinuz", "-initrd", f"{img}/initrd",
           "-append", CMDLINE,
           "-drive", f"if=none,id=root,format=raw,readonly=on,file={img}/root.raw,cache=none,aio=io_uring",
           "-device", "virtio-blk-pci,drive=root,serial=custom-root,disable-legacy=on,iommu_platform=true"]
    if data:
        out += ["-drive", f"if=none,id=data,format=raw,file={d}/disks/data.raw,cache=none,aio=io_uring",
                "-device", "virtio-blk-pci,drive=data,serial=custom-data,disable-legacy=on,iommu_platform=true"]
    out += ["-netdev", "tap,id=net0,ifname=cgst0,script=no,downscript=no,vhost=on",
            "-device", "virtio-net-pci,netdev=net0,mac=52:54:00:c7:01:23,disable-legacy=on,iommu_platform=true,romfile=",
            "-fw_cfg", f"name=opt/cathedral/manifest.json,file={img}/manifest.json",
            "-fw_cfg", f"name=opt/cathedral/bootstrap.json,file={img}/bootstrap.json",
            "-fw_cfg", f"name=opt/cathedral/bootstrap.sig,file={img}/bootstrap.sig",
            "-qmp", f"unix:{d}/run/qmp.sock,server=on,wait=off",
            "-display", "none", "-vga", "none", "-monitor", "none",
            "-chardev", "ringbuf,id=serial0,size=1M", "-serial", "chardev:serial0",
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]
    return out


@pytest.mark.parametrize("data_gib", [0, 8])
def test_golden_argv(tmp_path, data_gib):
    d = make_launch(tmp_path, data_disk_gib=data_gib)
    rc, argv = argv_of(d)
    assert rc == 0, argv
    assert argv == golden(d, data=bool(data_gib))


def test_snp_object_three_fw_cfg_no_smbios_one_cmdline_element(tmp_path):
    d = make_launch(tmp_path)
    rc, argv = argv_of(d)
    assert rc == 0
    snp = [argv[i + 1] for i, a in enumerate(argv) if a == "-object" and argv[i + 1].startswith("sev-snp-guest,")]
    assert len(snp) == 1 and "policy=0x30000" in snp[0] and "kernel-hashes=on" in snp[0]
    assert [argv[i + 1].split(",")[0] for i, a in enumerate(argv) if a == "-fw_cfg"] == [
        "name=opt/cathedral/manifest.json", "name=opt/cathedral/bootstrap.json", "name=opt/cathedral/bootstrap.sig"]
    assert "-smbios" not in argv
    i = argv.index("-append")
    assert argv[i + 1] == CMDLINE and argv.count("-append") == 1


def test_host_data_matches_the_kit_v2_function(tmp_path):
    """Shared vector with room-kit/sealed/launch-guest.sh (LAUNCH_PRINT_HOST_DATA=1, v2)."""
    d = make_launch(tmp_path)
    img = d / "images"
    key = tmp_path / "owner.pub"
    key.write_bytes(OWNER)
    sealed = tmp_path / "sealed"
    (sealed / "images").mkdir(parents=True)
    os.symlink(img, sealed / "images" / "current")
    env = sealed / "sealed.env"
    env.write_text(f"SEALED_NAME=chi-ur-2\nSEALED_DIR={sealed}\nSEALED_OWNER_PUBKEY_FILE={key}\n"
                   f"SEALED_BOOTSTRAP_SHA256={hashlib.sha256((img / 'bootstrap.json').read_bytes()).hexdigest()}\n")
    p = subprocess.run(["bash", str(REPO / "room-kit" / "sealed" / "launch-guest.sh"), str(env)],
                       capture_output=True, text=True, env={**os.environ, "LAUNCH_PRINT_HOST_DATA": "1"})
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == host_data_b64(d)


@pytest.mark.parametrize("mutate,why", [
    (lambda d: (d / "images" / "cmdline").write_bytes((CMDLINE + " quiet").encode()), "cmdline"),
    (lambda d: (d / "images" / "manifest.json").write_bytes(
        (d / "images" / "manifest.json").read_bytes().replace(b'"vcpus":4', b'"vcpus": 4')), "canonical"),
    (lambda d: (d / "images" / "bootstrap.sig").unlink(), "bootstrap.sig"),
])
def test_refuses_inconsistent_launch_files(tmp_path, mutate, why):
    d = make_launch(tmp_path)
    mutate(d)
    rc, err = argv_of(d)
    assert rc == 1 and "refused" in err, (why, err)


def test_property_no_argv_without_the_snp_object(tmp_path):
    sys.path.insert(0, str(LAUNCHER.parent))
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("launch_custom_guest", LAUNCHER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    d = make_launch(tmp_path)
    argv = mod.build_argv(os.path.realpath(d))
    for i, a in enumerate(argv):
        if a == "-object" and argv[i + 1].startswith("sev-snp-guest,"):
            broken = argv[:i] + argv[i + 2:]
            with pytest.raises(mod.LaunchError):
                mod.check_argv(broken, os.path.realpath(d))
    with pytest.raises(mod.LaunchError):
        mod.check_argv(argv + ["-smbios", "type=11,value=x"], os.path.realpath(d))
    with pytest.raises(mod.LaunchError):
        mod.check_argv(argv + ["-fw_cfg", "name=opt/io.systemd.credentials/x,string=y"], os.path.realpath(d))
    with pytest.raises(mod.LaunchError):
        mod.check_argv(argv + ["-drive", "if=none,id=kit,file=/srv/sealed-hotel-chi-ur-2/data.raw"],
                       os.path.realpath(d))
