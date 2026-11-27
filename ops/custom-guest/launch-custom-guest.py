#!/usr/bin/env python3
"""Start one custom SNP guest in the foreground (spec-r9 5.7).

ExecStart of custom-guest-<launch_id>.service, run as cg-<hotel> with no
capabilities:

  python3 -I launch-custom-guest.py <D>          exec QEMU
  python3 -I launch-custom-guest.py <D> --print  print the argv as JSON, start nothing

D is /srv/custom-guest/<hotel>/<launch_id>. Every value comes from the
root-owned files in D/images (manifest.json, bootstrap.json, cmdline), never
from the environment, and QEMU gets an argv list: no shell runs, and the
cmdline is one argv element with the exact bytes of images/cmdline, which must
equal manifest.cmdline. The SNP object, policy, firmware and direct boot are
those of room-kit/sealed/launch-guest.sh; HOST_DATA is its v2 function.
Exactly three fw_cfg names, no -smbios, no drive outside D.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys

# -I keeps the script's directory off sys.path. snp_qemu.py is installed beside this file
# (TOOLS in custom_guest_host.py); in the repository it is a link to room-kit/vm/snp_qemu.py.
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import snp_qemu  # noqa: E402

QEMU = snp_qemu.QEMU
POLICY = snp_qemu.POLICY
HOST_DATA_DOMAIN = b"cathedral-dedicated-v2\0"
CPU_MODELS = snp_qemu.CPU_MODELS
FW_CFG_NAMES = ("opt/cathedral/manifest.json", "opt/cathedral/bootstrap.json", "opt/cathedral/bootstrap.sig")


class LaunchError(Exception):
    pass


def canonical(doc: dict) -> bytes:
    """Spec 8.1 canonical bytes (cathedral_owner_signed.py:53-54)."""
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def read_canonical(path: str) -> tuple[dict, bytes]:
    raw = open(path, "rb").read()
    doc = json.loads(raw)
    if not isinstance(doc, dict) or canonical(doc) != raw:
        raise LaunchError(f"{os.path.basename(path)} is not in canonical form")
    if doc.get("version") != 1:
        raise LaunchError(f"{os.path.basename(path)} version must be 1")
    return doc, raw


def host_data(manifest_raw: bytes, owner_key: bytes, bootstrap_raw: bytes) -> bytes:
    """sha256("cathedral-dedicated-v2\\0" || sha256(manifest) || owner key || sha256(bootstrap)) (8.5)."""
    if len(owner_key) != 32:
        raise LaunchError("the owner key must be 32 bytes")
    return hashlib.sha256(HOST_DATA_DOMAIN + hashlib.sha256(manifest_raw).digest() + owner_key
                          + hashlib.sha256(bootstrap_raw).digest()).digest()


def build_argv(d: str) -> list[str]:
    img = os.path.join(d, "images")
    manifest, manifest_raw = read_canonical(os.path.join(img, "manifest.json"))
    bootstrap, bootstrap_raw = read_canonical(os.path.join(img, "bootstrap.json"))
    if manifest.get("schema") != "cathedral.custom_guest.manifest/v1" \
            or bootstrap.get("schema") != "cathedral.custom_guest.bootstrap/v1":
        raise LaunchError("unexpected document schema")
    if bootstrap.get("manifest_sha256") != hashlib.sha256(manifest_raw).hexdigest():
        raise LaunchError("bootstrap.manifest_sha256 does not name this manifest")
    cmdline = open(os.path.join(img, "cmdline"), "rb").read()
    if cmdline != str(manifest.get("cmdline", "")).encode() or b"\n" in cmdline:
        raise LaunchError("images/cmdline differs from manifest.cmdline")
    if not os.path.isfile(os.path.join(img, "bootstrap.sig")):
        raise LaunchError("images/bootstrap.sig is missing")
    vcpus, mem, model = manifest.get("vcpus"), manifest.get("mem_gib"), manifest.get("cpu_model")
    data_gib = manifest.get("data_disk_gib", 0)
    if not (isinstance(vcpus, int) and 1 <= vcpus <= 56 and isinstance(mem, int) and 4 <= mem <= 640
            and model in CPU_MODELS and isinstance(data_gib, int) and 0 <= data_gib <= 400):
        raise LaunchError("manifest resources are out of range")
    if manifest.get("policy") != POLICY:
        raise LaunchError("manifest policy must be 0x30000")
    net = bootstrap.get("network") or {}
    m = re.fullmatch(r"10\.217\.([0-9]{1,3})\.2", str(net.get("guest_ip", "")))
    if not m or int(m.group(1)) > 255 or net.get("host_ip") != f"10.217.{m.group(1)}.1" or net.get("prefix") != 30:
        raise LaunchError("bootstrap network is not a 10.217.<n>.0/30 link")
    mac = str(net.get("guest_mac", ""))
    if not re.fullmatch(r"52:54:00:c7(:[0-9a-f]{2}){2}", mac):
        raise LaunchError("bootstrap guest_mac must be 52:54:00:c7:xx:xx")
    tap = f"cgst{int(m.group(1))}"
    owner = base64.b64decode(str(bootstrap.get("owner_ed25519_b64", "")), validate=True)
    hd = base64.b64encode(host_data(manifest_raw, owner, bootstrap_raw)).decode()

    devices = ["-drive", f"if=none,id=root,format=raw,readonly=on,file={os.path.join(img, 'root.raw')},"
                         "cache=none,aio=io_uring",
               "-device", "virtio-blk-pci,drive=root,serial=custom-root,disable-legacy=on,iommu_platform=true"]
    if data_gib:
        devices += ["-drive", f"if=none,id=data,format=raw,file={os.path.join(d, 'disks', 'data.raw')},"
                              "cache=none,aio=io_uring",
                    "-device", "virtio-blk-pci,drive=data,serial=custom-data,disable-legacy=on,iommu_platform=true"]
    devices += ["-netdev", f"tap,id=net0,ifname={tap},script=no,downscript=no,vhost=on",
                "-device", f"virtio-net-pci,netdev=net0,mac={mac},disable-legacy=on,iommu_platform=true,romfile="]
    for name in FW_CFG_NAMES:
        devices += ["-fw_cfg", f"name={name},file={os.path.join(img, os.path.basename(name))}"]
    try:
        argv = snp_qemu.snp_argv(
            name=f"custom-guest-{bootstrap['launch_id']}", cpu_model=model, vcpus=vcpus, mem_gib=mem,
            host_data_b64=hd, ovmf=os.path.join(img, "OVMF.amdsev.fd"), kernel=os.path.join(img, "vmlinuz"),
            initrd=os.path.join(img, "initrd"), cmdline=cmdline.decode("ascii"), devices=devices,
            qmp_sockets=[os.path.join(d, "run", "qmp.sock")])
    except snp_qemu.SnpArgvError as e:
        raise LaunchError(str(e)) from None
    check_argv(argv, d)
    return argv


def check_argv(argv: list[str], d: str) -> None:
    """Property checks every launch must pass: the shared SNP property, and nothing extra."""
    try:
        snp_qemu.check_snp_argv(argv)
    except snp_qemu.SnpArgvError as e:
        raise LaunchError(str(e)) from None
    fw = [argv[i + 1].split(",", 1)[0] for i, a in enumerate(argv[:-1]) if a == "-fw_cfg"]
    if fw != [f"name={n}" for n in FW_CFG_NAMES]:
        raise LaunchError("exactly the three fw_cfg names")
    if argv.count("-append") != 1:
        raise LaunchError("one -append")
    for i, a in enumerate(argv[:-1]):
        if a == "-drive":
            f = re.search(r"(?:^|,)file=([^,]+)", argv[i + 1])
            if not f or not os.path.normpath(f.group(1)).startswith(os.path.normpath(d) + os.sep):
                raise LaunchError("a drive outside the launch directory")


def main(argv: list[str]) -> int:
    if not argv or len(argv) > 2 or (len(argv) == 2 and argv[1] != "--print"):
        print("usage: launch-custom-guest.py <launch dir> [--print]", file=sys.stderr)
        return 2
    d = os.path.realpath(argv[0])
    try:
        args = build_argv(d)
    except (LaunchError, OSError, ValueError, KeyError) as e:
        print(f"launch-custom-guest: refused: {e}", file=sys.stderr)
        return 1
    if len(argv) == 2:
        print(json.dumps(args))
        return 0
    os.execv(QEMU, args)
    return 1  # not reached


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
