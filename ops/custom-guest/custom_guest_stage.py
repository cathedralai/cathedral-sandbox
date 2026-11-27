#!/usr/bin/env python3
"""Intake validator for one custom SNP guest launch (spec-r9 5.5, 4.4).

Run by the host phase `intake` as the unprivileged user cg-stage, with no
network, inside the systemd-run line of spec 5.5:

  python3 -I custom_guest_stage.py --inbox <inbox/L> --staging <staging/L>

It reads only the inbox (request.json, inputs.json, vmlinuz, initrd, root.raw)
and writes only the staging directory: `cmdline` (the exact measured bytes) and
`report.json` (the verdict with every digest it checked). It never trusts a
file name or size it did not check itself. Root later copies the inbox files
into the launch images and re-hashes every byte it copies against this report
and the request (custom_guest_host.py), so a file changed after this check is
refused there.

Self-contained on purpose: `python3 -I` puts neither this directory nor user
site-packages on sys.path, so a planted module cannot run here.

Exit 0 with report {"ok": true, ...}; exit 1 with {"ok": false, "error_code"}.
"""
from __future__ import annotations

import argparse
import base64
import bz2
import gzip
import hashlib
import json
import lzma
import os
import re
import shutil
import stat
import subprocess
import sys
import zlib

MIB = 1 << 20
GIB = 1 << 30
KERNEL_MAX = 64 * MIB
ROOT_MAX = 200 * GIB
CMDLINE_MAX = 2033  # OVMF prepends "initrd=initrd " (14 bytes); the kernel keeps 2047 (spec 4.4)
OVMF_PREFIX_LEN = 14
REQUEST_SCHEMA = "cathedral.custom_guest.request/v1"
REQUEST_FIELDS = {"schema", "kernel", "initrd", "root_disk", "cmdline", "data_disk_gib", "vcpus", "mem_gib",
                  "cpu_model", "owner_ed25519_b64", "ssh_public_key", "launch_nonce_hex", "ports"}
CPU_MODELS = {"EPYC-Genoa-v1", "EPYC-v4"}
HEX64 = re.compile(r"[0-9a-f]{64}")

# Kernel config (spec 5.5). Built in, every one of these.
REQUIRED_Y = ("AMD_MEM_ENCRYPT", "SEV_GUEST", "TSM_REPORTS", "VIRTIO_PCI", "VIRTIO_BLK", "VIRTIO_NET",
              "BLK_DEV_DM", "DM_VERITY", "DM_CRYPT", "DM_INTEGRITY", "BLK_DEV_INITRD", "RD_ZSTD", "EFI_STUB")
ROOT_FS_ONE_OF = ("SQUASHFS", "EXT4_FS")
# Must be unset: a built-in cmdline or an embedded bootconfig adds kernel
# parameters outside the 4.4 check.
FORBIDDEN_SET = ("CMDLINE_BOOL", "BOOT_CONFIG_EMBED", "BOOT_CONFIG_FORCE")


class Refused(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------- cmdline (4.4 allowlist)

def _b64url_32(value: str) -> bytes | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, base64.binascii.Error):
        return None
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != value:
        return None
    return raw


def check_cmdline(cmdline: str, owner_key: bytes, root_bytes: int) -> dict:
    """Return the parsed required tokens, or raise custom_guest_cmdline_invalid.

    Every byte 0x20..0x7E, 1..2033 bytes, single spaces, no leading or trailing
    space, every token at most once, only allowlisted tokens.
    """
    def bad(why: str) -> Refused:
        return Refused("custom_guest_cmdline_invalid", why)

    raw = cmdline.encode("utf-8", "surrogateescape") if isinstance(cmdline, str) else b""
    if not isinstance(cmdline, str) or not 1 <= len(raw) <= CMDLINE_MAX:
        raise bad(f"cmdline must be 1 to {CMDLINE_MAX} bytes")
    if any(b < 0x20 or b > 0x7E for b in raw):
        raise bad("cmdline bytes must be 0x20 to 0x7E")
    if cmdline != cmdline.strip(" ") or "  " in cmdline:
        raise bad("single spaces between tokens, none leading or trailing")
    seen: set[str] = set()
    out: dict = {}
    for token in cmdline.split(" "):
        key = token.split("=", 1)[0] if "=" in token else token
        if key in seen:
            raise bad(f"token {key} appears more than once")
        seen.add(key)
        value = token.split("=", 1)[1] if "=" in token else None
        if key == "cathedral.owner" and value is not None:
            key_bytes = _b64url_32(value)
            if key_bytes is None or key_bytes != owner_key:
                raise bad("cathedral.owner must be the 43-character base64url form of owner_ed25519_b64")
            out["owner"] = value
        elif key == "cathedral.root_verity" and value is not None:
            if not HEX64.fullmatch(value):
                raise bad("cathedral.root_verity must be 64 lowercase hex")
            out["root_verity"] = value
        elif key == "cathedral.root_data_bytes" and value is not None:
            if not re.fullmatch(r"[1-9][0-9]{0,15}", value):
                raise bad("cathedral.root_data_bytes must be a decimal byte count")
            n = int(value)
            if n % 4096 or n >= root_bytes:
                raise bad("cathedral.root_data_bytes must be a multiple of 4096 and less than root_disk.bytes")
            out["root_data_bytes"] = n
        elif token == "systemd.import_credentials=no":
            out["import_credentials_off"] = True
        elif token in ("console=ttyS0", "console=ttyS0,115200", "quiet"):
            pass
        elif key == "loglevel" and value is not None and re.fullmatch(r"[0-7]", value):
            pass
        elif key == "panic" and value is not None and re.fullmatch(r"-1|0|[1-9][0-9]{0,3}", value) \
                and int(value) <= 3600:
            pass
        elif key == "cathedral.note" and value is not None and all(0x21 <= ord(c) <= 0x7E for c in value):
            pass
        else:
            # rdinit=, init=, noinitrd, initrd=, root=, ro, rw, every other systemd.* token,
            # the cloud-init tokens and anything unknown.
            raise bad(f"token {token[:64]!r} is not on the allowlist")
    for need in ("owner", "root_verity", "root_data_bytes", "import_credentials_off"):
        if need not in out:
            name = {"owner": "cathedral.owner", "root_verity": "cathedral.root_verity",
                    "root_data_bytes": "cathedral.root_data_bytes",
                    "import_credentials_off": "systemd.import_credentials=no"}[need]
            raise bad(f"{name} is required")
    return out


# ---------------------------------------------------------------- kernel (bzImage, IKCONFIG)

def _u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 2], "little")


def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "little")


def check_bzimage(data: bytes) -> dict:
    """x86_64 bzImage with an EFI stub, boot protocol >= 2.12, XLF_KERNEL_64, cmdline_size >= 2047.

    cmdline_size is the longest command line without the terminating zero
    (Documentation/arch/x86/boot.rst); a stock x86 kernel sets it to
    COMMAND_LINE_SIZE - 1 = 2047 (arch/x86/boot/header.S). Spec 5.5 writes
    ">= 2048", which no stock kernel meets; 2047 is the spec's own 4.4 figure.
    """
    def bad(why: str) -> Refused:
        return Refused("custom_guest_not_snp_bootable", why)

    if len(data) < 0x260 or data[:2] != b"MZ":
        raise bad("not a PE image (no MZ header)")
    pe = _u32(data, 0x3C)
    if pe + 4 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise bad("no PE header: the kernel has no EFI stub")
    if data[0x202:0x206] != b"HdrS":
        raise bad("no Linux boot header (HdrS at 0x202)")
    version = _u16(data, 0x206)
    if version < 0x020C:
        raise bad(f"boot protocol {version >> 8}.{version & 0xff} is older than 2.12")
    if not _u16(data, 0x236) & 0x1:
        raise bad("XLF_KERNEL_64 is not set")
    cmdline_size = _u32(data, 0x238)
    if cmdline_size < 2047:
        raise bad(f"cmdline_size {cmdline_size} is below 2047")
    setup_sects = data[0x1F1] or 4
    pm_start = (setup_sects + 1) * 512
    payload_off, payload_len = _u32(data, 0x248), _u32(data, 0x24C)
    start = pm_start + payload_off
    if payload_len == 0 or start + payload_len > len(data):
        raise bad("the compressed payload lies outside the file")
    return {"protocol": f"{version >> 8}.{version & 0xff}", "cmdline_size": cmdline_size,
            "payload": data[start:start + payload_len]}


def _run_decompressor(argv: list[str], payload: bytes) -> bytes:
    exe = shutil.which(argv[0])
    if not exe:
        raise Refused("custom_guest_kernel_config_refused", f"{argv[0]} is not installed to read this payload")
    for body in (payload, payload[:-4]):  # the kernel build appends a 4-byte size to some payloads
        p = subprocess.run([exe, *argv[1:]], input=body, capture_output=True, timeout=300)
        if p.returncode == 0 and p.stdout:
            return p.stdout
    raise Refused("custom_guest_kernel_config_refused", f"{argv[0]} could not decompress the kernel payload")


def decompress_payload(payload: bytes) -> bytes:
    """The vmlinux inside a bzImage, for the compressions the kernel build offers."""
    try:
        if payload[:2] == b"\x1f\x8b":
            d = zlib.decompressobj(wbits=31)
            return d.decompress(payload)
        if payload[:6] == b"\xfd7zXZ\x00":
            return lzma.LZMADecompressor(format=lzma.FORMAT_XZ).decompress(payload)
        if payload[:3] == b"\x5d\x00\x00":
            return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(payload)
        if payload[:3] == b"BZh":
            return bz2.BZ2Decompressor().decompress(payload)
    except (OSError, EOFError, lzma.LZMAError, zlib.error, ValueError) as e:
        raise Refused("custom_guest_kernel_config_refused", f"could not decompress the kernel payload: {e}")
    if payload[:4] == b"\x28\xb5\x2f\xfd":
        return _run_decompressor(["zstd", "-dcq"], payload)
    if payload[:4] == b"\x02\x21\x4c\x18":
        return _run_decompressor(["lz4", "-dcq"], payload)
    raise Refused("custom_guest_kernel_config_refused", "unknown kernel payload compression")


def extract_ikconfig(vmlinux: bytes) -> str:
    """The .config the kernel carries (CONFIG_IKCONFIG): gzip between IKCFG_ST and IKCFG_ED.

    The same search as the kernel's scripts/extract-ikconfig, done here so the
    reader is pinned by this repository's commit.
    """
    start = vmlinux.find(b"IKCFG_ST")
    if start < 0:
        raise Refused("custom_guest_kernel_config_refused", "no IKCONFIG in the kernel (CONFIG_IKCONFIG=y is required)")
    end = vmlinux.find(b"IKCFG_ED", start + 8)
    if end < 0:
        raise Refused("custom_guest_kernel_config_refused", "IKCONFIG has no end marker")
    try:
        return gzip.decompress(vmlinux[start + 8:end]).decode("utf-8", "replace")
    except (OSError, EOFError, zlib.error) as e:
        raise Refused("custom_guest_kernel_config_refused", f"IKCONFIG does not decompress: {e}")


def parse_config(text: str) -> dict[str, str]:
    cfg: dict[str, str] = {}
    for line in text.splitlines():
        m = re.fullmatch(r"CONFIG_([A-Za-z0-9_]+)=(.*)", line.strip())
        if m:
            cfg[m.group(1)] = m.group(2)
    return cfg


def check_kernel_config(cfg: dict[str, str]) -> None:
    def bad(why: str) -> Refused:
        return Refused("custom_guest_kernel_config_refused", why)

    if cfg.get("IKCONFIG") != "y":
        raise bad("CONFIG_IKCONFIG=y is required")
    for name in FORBIDDEN_SET:
        if name in cfg:
            raise bad(f"CONFIG_{name} must not be set")
    if cfg.get("INITRAMFS_SOURCE") != '""':
        raise bad('CONFIG_INITRAMFS_SOURCE must be "" (no built-in initramfs)')
    missing = [n for n in REQUIRED_Y if cfg.get(n) != "y"]
    if missing:
        raise bad("not built in: " + ", ".join(f"CONFIG_{n}" for n in missing))
    if not any(cfg.get(n) == "y" for n in ROOT_FS_ONE_OF):
        raise bad("CONFIG_SQUASHFS or CONFIG_EXT4_FS must be built in")


# ---------------------------------------------------------------- files

def open_regular(path: str) -> tuple[int, os.stat_result]:
    """Open a regular file without following a link; refuse anything else."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise Refused("custom_guest_request_invalid", f"{os.path.basename(path)} is not a regular file")
    return fd, st


def sha256_file(path: str, limit: int) -> tuple[str, int]:
    fd, st = open_regular(path)
    if st.st_size > limit:
        os.close(fd)
        raise Refused("custom_guest_image_too_large", f"{os.path.basename(path)} is larger than {limit} bytes")
    h = hashlib.sha256()
    n = 0
    with os.fdopen(fd, "rb") as f:
        while True:
            chunk = f.read(4 * MIB)
            if not chunk:
                break
            n += len(chunk)
            h.update(chunk)
    return h.hexdigest(), n


def read_small(path: str, limit: int) -> bytes:
    fd, st = open_regular(path)
    with os.fdopen(fd, "rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise Refused("custom_guest_image_too_large", f"{os.path.basename(path)} is larger than {limit} bytes")
    return data


# ---------------------------------------------------------------- request

def check_request(req: object) -> dict:
    def bad(code: str, why: str) -> Refused:
        return Refused(code, why)

    if not isinstance(req, dict) or req.get("schema") != REQUEST_SCHEMA or set(req) - REQUEST_FIELDS \
            or "hotel" in req:
        raise bad("custom_guest_request_invalid", "schema, fields or a hotel field")
    for name, limit in (("kernel", KERNEL_MAX), ("root_disk", ROOT_MAX)):
        part = req.get(name)
        code = "custom_guest_image_digest_required" if name == "kernel" else "custom_guest_root_required"
        if not isinstance(part, dict) or not HEX64.fullmatch(str(part.get("sha256", ""))) \
                or not isinstance(part.get("bytes"), int) or isinstance(part.get("bytes"), bool):
            raise bad(code, f"{name} needs sha256 and bytes")
        if not 0 < part["bytes"] <= limit:
            raise bad("custom_guest_image_too_large", f"{name} is larger than {limit} bytes")
    initrd = req.get("initrd")
    if not isinstance(initrd, dict) or not HEX64.fullmatch(str(initrd.get("sha256", ""))) \
            or not isinstance(initrd.get("reference"), str):
        raise bad("custom_guest_not_reference_initrd", "initrd needs reference and sha256")
    for field, lo, hi in (("data_disk_gib", 0, 400), ("vcpus", 1, 56), ("mem_gib", 4, 640)):
        v = req.get(field, 0 if field == "data_disk_gib" else None)
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise bad("custom_guest_resources_exceeded", f"{field} must be {lo} to {hi}")
    if req.get("cpu_model") not in CPU_MODELS:
        raise bad("custom_guest_cpu_model_unsupported", "cpu_model must be EPYC-Genoa-v1 or EPYC-v4")
    try:
        owner = base64.b64decode(str(req.get("owner_ed25519_b64", "")), validate=True)
    except (ValueError, base64.binascii.Error):
        owner = b""
    if len(owner) != 32:
        raise bad("custom_guest_owner_key_invalid", "owner_ed25519_b64 must hold 32 bytes")
    if not HEX64.fullmatch(str(req.get("launch_nonce_hex", ""))):
        raise bad("custom_guest_nonce_invalid", "launch_nonce_hex must be 64 lowercase hex")
    ports = req.get("ports")
    if not isinstance(ports, list) or not 1 <= len(ports) <= 8:
        raise bad("custom_guest_port_invalid", "1 to 8 port pairs")
    publics = set()
    for i, p in enumerate(ports):
        if not isinstance(p, dict) or set(p) != {"public", "guest"} \
                or not all(isinstance(p[k], int) and not isinstance(p[k], bool) for k in p):
            raise bad("custom_guest_port_invalid", "each port is {public, guest}")
        if not 20000 <= p["public"] <= 29999 or not 1 <= p["guest"] <= 65535 or p["public"] in publics:
            raise bad("custom_guest_port_invalid", "public ports 20000 to 29999, unique")
        if (i == 0) != (p["guest"] == 22):
            raise bad("custom_guest_ssh_port_required", "ports[0].guest must be 22 and no other pair may use 22")
        publics.add(p["public"])
    return {"owner_key": owner}


# ---------------------------------------------------------------- root (dm-verity)

def check_verity(root: str, data_bytes: int, root_hash: str) -> None:
    exe = shutil.which("veritysetup")
    if not exe:
        raise Refused("custom_guest_root_not_verity", "veritysetup is not installed")
    argv = [exe, "verify", root, root, root_hash, f"--hash-offset={data_bytes}",
            f"--data-blocks={data_bytes // 4096}", "--data-block-size=4096"]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=3000)
    if p.returncode != 0:
        raise Refused("custom_guest_root_not_verity",
                      "veritysetup verify failed: " + (p.stderr.strip() or p.stdout.strip())[:300])


# ---------------------------------------------------------------- main

def validate(inbox: str, staging: str) -> dict:
    try:
        req = json.loads(read_small(os.path.join(inbox, "request.json"), 16 * 1024))
        inputs = json.loads(read_small(os.path.join(inbox, "inputs.json"), 64 * 1024))
    except (ValueError, OSError) as e:
        raise Refused("custom_guest_request_invalid", f"request.json or inputs.json: {e}")
    facts = check_request(req)
    report: dict = {"ok": True, "files": {}}

    # Kernel: size, digest, format, config.
    k_path = os.path.join(inbox, "vmlinuz")
    k_sha, k_len = sha256_file(k_path, KERNEL_MAX)
    if k_len != req["kernel"]["bytes"]:
        raise Refused("custom_guest_size_mismatch", "vmlinuz size differs from the request")
    if k_sha != req["kernel"]["sha256"]:
        raise Refused("custom_guest_digest_mismatch", "vmlinuz sha256 differs from the request")
    kernel = read_small(k_path, KERNEL_MAX)
    if hashlib.sha256(kernel).hexdigest() != k_sha:
        raise Refused("custom_guest_digest_mismatch", "vmlinuz changed while it was read")
    boot = check_bzimage(kernel)
    check_kernel_config(parse_config(extract_ikconfig(decompress_payload(boot["payload"]))))
    report["kernel"] = {"protocol": boot["protocol"], "cmdline_size": boot["cmdline_size"]}
    report["files"]["vmlinuz"] = {"sha256": k_sha, "bytes": k_len}

    # Initrd: byte for byte a published reference initrd.
    published = (inputs.get("reference_initrds") or {}) if isinstance(inputs, dict) else {}
    want = published.get(req["initrd"]["reference"])
    if want is None or want != req["initrd"]["sha256"]:
        raise Refused("custom_guest_not_reference_initrd", "the request names no published reference initrd")
    i_sha, i_len = sha256_file(os.path.join(inbox, "initrd"), KERNEL_MAX)
    if i_sha != want:
        raise Refused("custom_guest_not_reference_initrd", "initrd differs from the published reference initrd")
    report["files"]["initrd"] = {"sha256": i_sha, "bytes": i_len}

    # Cmdline: the allowlist again, and the kernel's own limit.
    root_bytes = req["root_disk"]["bytes"]
    parsed = check_cmdline(req["cmdline"], facts["owner_key"], root_bytes)
    line = req["cmdline"].encode()
    if OVMF_PREFIX_LEN + len(line) > boot["cmdline_size"]:  # cmdline_size excludes the NUL
        raise Refused("custom_guest_cmdline_invalid", "the cmdline does not fit the kernel's cmdline_size")
    report["cmdline"] = parsed

    # Root: size, digest, dm-verity against the hash in the measured cmdline.
    r_path = os.path.join(inbox, "root.raw")
    r_sha, r_len = sha256_file(r_path, ROOT_MAX)
    if r_len != root_bytes:
        raise Refused("custom_guest_size_mismatch", "root.raw size differs from the request")
    if r_sha != req["root_disk"]["sha256"]:
        raise Refused("custom_guest_digest_mismatch", "root.raw sha256 differs from the request")
    check_verity(r_path, parsed["root_data_bytes"], parsed["root_verity"])
    report["files"]["root.raw"] = {"sha256": r_sha, "bytes": r_len}

    # Output: the exact cmdline bytes (no newline) and the verdict.
    with open(os.path.join(staging, "cmdline"), "xb") as f:
        f.write(line)
    report["files"]["cmdline"] = {"sha256": hashlib.sha256(line).hexdigest(), "bytes": len(line)}
    return report


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--inbox", required=True)
    ap.add_argument("--staging", required=True)
    a = ap.parse_args(argv)
    try:
        report = validate(a.inbox, a.staging)
        rc = 0
    except Refused as e:
        report, rc = {"ok": False, "error_code": e.code, "detail": e.detail}, 1
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        report, rc = {"ok": False, "error_code": "custom_guest_request_invalid", "detail": str(e)[:300]}, 1
    out = os.path.join(a.staging, "report.json")
    tmp = out + ".part"
    with open(tmp, "w") as f:
        json.dump(report, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out)
    print(json.dumps(report, sort_keys=True))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
