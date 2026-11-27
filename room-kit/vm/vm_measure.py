#!/usr/bin/env python3
"""Launch values of one sealed customer VM (AB#999, VM runtime v2 spec r2 6.1 to 6.3).

From a bundle manifest and the VM's parameters this computes:

- the identity document (vm-identity.json) and its sha256;
- the exact measured kernel cmdline, which names that identity (cathedral.vm=);
- HOST_DATA: sha256(b"cathedral-vm-v1\\0" || sha256(vm-identity.json));
- the expected SNP launch measurement for a vCPU count and CPU family, computed
  by the pinned sev-snp-measure 0.0.12 over the bundle's OVMF, kernel and initrd
  and the per-VM cmdline, with the argv of install-sealed.sh:88-90.

It also writes and checks the bundle manifest (build-bundle.sh calls it).

Commands (one JSON object on stdout; a refusal prints {"error": ...} and exits 2):

  vm_measure.py identity --bundle DIR --vm-id vm-<12 hex> --ssh-key-file F --out FILE [--salt-hex H]
  vm_measure.py launch --bundle DIR --identity FILE --vcpus N --cpu-family genoa|turin [--tool PATH]
  vm_measure.py bundle-manifest --dir DIR --label L --cpu-family F ... (see --help)
  vm_measure.py check-bundle DIR

Standard library only, so the host (create, status) and the customer's verifier
(PR VM2) can run the same code. sev-snp-measure is the one outside tool
(requirements/vm-measure.txt). Nothing here launches a VM or reads a VM disk.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# ---- constants ----------------------------------------------------------------

IDENTITY_SCHEMA = "cathedral.vm.identity/v1"
BUNDLE_SCHEMA = "cathedral.vm.bundle/v1"
# Own domain (spec r2 6.3, Q3): a VM report never reads as a dedicated owner launch,
# whose domains are cathedral-dedicated-v1\0 and -v2\0 (room_receipts.py:257-261).
HOST_DATA_DOMAIN = b"cathedral-vm-v1\0"

IDENTITY_FIELDS = frozenset({"version", "schema", "vm_id", "salt_hex", "ssh_public_key",
                             "base_root_verity", "base_root_data_bytes"})
# Measured inputs: hashed into the launch measurement by OVMF (kernel-hashes=on).
MEASURED_FILES = ("OVMF.amdsev.fd", "vmlinuz", "initrd.cpio.zst")
# Every file a bundle holds. base-root.raw is bound by its verity root hash in the
# identity, which the measured cmdline names; the two locks record what was installed.
BUNDLE_FILES = MEASURED_FILES + ("base-root.raw", "base-root.packages.lock", "kernel.packages.lock")
BUNDLE_FIELDS = frozenset({"version", "schema", "label", "sha256", "bytes", "cmdline_template",
                           "cpu_family", "cpu_model", "policy", "qemu_version", "sev_snp_measure",
                           "kernel_release", "initrd_version", "base_root_verity",
                           "base_root_data_bytes", "snapshot", "ovmf_source"})

IDENTITY_PLACEHOLDER = "{identity_sha256}"
# The measured cmdline, fixed per bundle (spec r2 6.3). Every token is here on purpose:
# - systemd.import_credentials=no: no host-set fw_cfg or SMBIOS credential is imported
#   (build-guest.sh:538-542);
# - systemd.getty_auto=0 stops systemd-getty-generator from adding a getty on the kernel
#   console or any virtualizer console the host attaches (hvc0 and friends);
# - the getty masks cover the statically enabled getty@tty1, logind's autovt@ on a VGA
#   the host adds, serial-getty@ on an extra serial port, and console-getty;
# - the recovery shells are masked: emergency.service and rescue.service run sulogin on
#   the console, which the host reads and writes. After switch_root the host can make a
#   required mount fail and reach emergency.target, where a customer-set root password
#   would get a prompt and an empty one a shell. Masked, that boot stays down instead.
#   debug-shell.service is a root shell on tty9 with no password;
# - qemu-guest-agent is masked, so a host-added guest-agent channel gets no answer even
#   if the customer installs the agent.
# Masking a template unit masks every instance. Test T9 (live) proves no prompt and no
# agent answer on an extra serial, VGA and virtio-serial device, and no prompt or shell
# after a required-mount failure with a locked, a password-protected and an empty root.
CMDLINE_TEMPLATE_V1 = (
    "console=ttyS0 loglevel=4 panic=-1 systemd.import_credentials=no"
    " systemd.getty_auto=0"
    " systemd.mask=getty@.service systemd.mask=serial-getty@.service"
    " systemd.mask=autovt@.service systemd.mask=console-getty.service"
    " systemd.mask=emergency.service systemd.mask=rescue.service"
    " systemd.mask=debug-shell.service"
    " systemd.mask=qemu-guest-agent.service"
    " cathedral.vm=" + IDENTITY_PLACEHOLDER
)
# OVMF puts "initrd=initrd " in front of the measured bytes in /proc/cmdline, and the
# kernel keeps 2047 bytes (spec D 9, custom_guest_protocol.py cmdline cap).
CMDLINE_MAX = 2033

# The QEMU -cpu model per host CPU family. Only the model's CPUID signature (family,
# model, stepping: the EDX reset value in every VMSA) is in the launch measurement. Its
# feature set is not (the CPUID page is outside the digest), so models that share a
# signature measure the same: EPYC-v1 and EPYC-v4 give one digest. The measurement
# therefore proves the signature below, not the model name; checking the CPU features
# in the guest before any key is released is the VM init's job (PR VM1b).
# Decision (Toby, 27 Nov 12:19Z): every sealed VM runs EPYC-v4 until the measurement tool
# supports Turin. It is the model the kit runs on our Turin host, whose expected value
# matched its live report; sev-snp-measure 0.0.12 knows no Turin model name. So EPYC-v4
# is the only model a manifest may name, on either family. The family stays in the
# manifest because the verifier (VM2) picks the AMD chain and TCB floor by it.
CPU_MODEL = "EPYC-v4"
CPU_MODELS = {"genoa": CPU_MODEL, "turin": CPU_MODEL}
# The measured signature of each model, family:model:stepping in hex (sev-snp-measure
# vcpu_types.py). It is the guest vCPU signature in every VMSA, not the chip CPUID a
# report carries (a Turin report says 1a:02:01 whatever the guest model).
CPU_SIGNATURES = {"EPYC-v4": "17:01:02"}
POLICY = "0x30000"
SEV_SNP_MEASURE_VERSION = "0.0.12"
# Same bounds as vm_ctl.py create (--vcpus 1..64) and the broker (vmMaxVCPUs).
VCPUS_MAX = 64
MEASURE_TIMEOUT = 600

# Must equal vm_ctl.KEY_TYPES and the broker's vmKeyTypes; a test pins the set.
KEY_TYPES = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
VM_ID_RE = re.compile(r"vm-[0-9a-f]{12}")  # broker/vms.go vmIDRE
HEX32_RE = re.compile(r"[0-9a-f]{32}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
HEX96_RE = re.compile(r"[0-9a-f]{96}")
LABEL_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")
VERSION_RE = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
# packages_lock.py KERNEL_PACKAGE: the release part of linux-image-<release>.
KERNEL_RELEASE_RE = re.compile(r"\d+\.\d+\.\d+-\d+-[a-z0-9]+")
INITRD_VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SNAPSHOT_RE = re.compile(r"\d{8}T\d{6}Z")  # packages_lock.py SNAPSHOT_ID
DOC_MAX = 16384
FILE_MAX = 64 * 1024 ** 3


class Refusal(ValueError):
    """An input this module will not accept. The message names the field."""


def need(condition: object, message: str) -> None:
    if not condition:
        raise Refusal(message)


# ---- canonical documents (spec D 8.1) -------------------------------------------

def _check_value(value: object) -> None:
    if type(value) is str:
        need(all(0x20 <= ord(c) <= 0x7E for c in value), "strings must be printable ASCII")
    elif type(value) is int:
        pass
    elif type(value) is dict:
        for key, item in value.items():
            need(type(key) is str, "object keys must be strings")
            _check_value(key)
            _check_value(item)
    else:
        raise Refusal("only integers, strings and objects are allowed")


def canonical(doc: dict) -> bytes:
    """D 8.1 canonical bytes (cathedral_owner_signed.py:53-54, custom_guest_protocol.canonical)."""
    need(type(doc) is dict, "a document is a JSON object")
    _check_value(doc)
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("ascii")


def parse_document(raw: bytes, label: str) -> dict:
    need(type(raw) is bytes and 0 < len(raw) <= DOC_MAX, f"{label}: must be 1 to {DOC_MAX} bytes")
    try:
        doc = json.loads(raw.decode("ascii"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Refusal(f"{label}: not ASCII JSON") from exc
    need(type(doc) is dict and canonical(doc) == raw, f"{label}: not canonical JSON")
    return doc


def _fields(doc: dict, expected: frozenset, label: str) -> None:
    need(set(doc) == expected, f"{label}: missing or unknown field")


def _int(value: object, lo: int, hi: int, label: str) -> int:
    need(type(value) is int and lo <= value <= hi, f"{label}: integer out of range")
    return value


def _match(pattern: re.Pattern, value: object, label: str) -> str:
    need(type(value) is str and pattern.fullmatch(value) is not None, f"{label}: invalid")
    return value


def _verity_fields(doc: dict, label: str) -> None:
    _match(HEX64_RE, doc["base_root_verity"], f"{label} base_root_verity")
    n = _int(doc["base_root_data_bytes"], 4096, FILE_MAX, f"{label} base_root_data_bytes")
    need(n % 4096 == 0, f"{label} base_root_data_bytes: must be a multiple of 4096")


# ---- SSH key -------------------------------------------------------------------

def ssh_public_key(text: str) -> str:
    """One OpenSSH public key line, as vm_ctl.check_key: returns 'type base64', comment dropped."""
    need(type(text) is str and len(text) <= DOC_MAX, "ssh key: too long")
    lines = [line for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
    need(len(lines) == 1, "ssh key: exactly one public key line")
    parts = lines[0].strip().split()
    need(len(parts) >= 2 and parts[0] in KEY_TYPES, "ssh key: unsupported type")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refusal("ssh key: not base64") from exc
    need(base64.b64encode(blob).decode() == parts[1], "ssh key: noncanonical base64")
    n = int.from_bytes(blob[:4], "big") if len(blob) >= 4 else -1
    need(n > 0 and blob[4:4 + n] == parts[0].encode() and len(blob) > 4 + n,
         "ssh key: the blob does not match its type")
    return f"{parts[0]} {parts[1]}"


# ---- identity (spec r2 6.3) ----------------------------------------------------

def identity_document(vm_id: str, ssh_key: str, base_root_verity: str, base_root_data_bytes: int,
                      salt_hex: str | None = None) -> bytes:
    """vm-identity.json bytes. The host's create writes them once; they never change."""
    doc = {"version": 1, "schema": IDENTITY_SCHEMA, "vm_id": vm_id,
           "salt_hex": secrets.token_hex(16) if salt_hex is None else salt_hex,
           "ssh_public_key": ssh_public_key(ssh_key),
           "base_root_verity": base_root_verity, "base_root_data_bytes": base_root_data_bytes}
    raw = canonical(doc)
    parse_identity(raw)
    return raw


def parse_identity(raw: bytes) -> dict:
    doc = parse_document(raw, "identity")
    _fields(doc, IDENTITY_FIELDS, "identity")
    need(type(doc["version"]) is int and doc["version"] == 1 and doc["schema"] == IDENTITY_SCHEMA,
         "identity: unsupported version or schema")
    _match(VM_ID_RE, doc["vm_id"], "identity vm_id")
    _match(HEX32_RE, doc["salt_hex"], "identity salt_hex")
    need(type(doc["ssh_public_key"]) is str and ssh_public_key(doc["ssh_public_key"]) == doc["ssh_public_key"],
         "identity ssh_public_key: must be 'type base64' with no comment")
    _verity_fields(doc, "identity")
    return doc


def identity_sha256(raw: bytes) -> str:
    parse_identity(raw)
    return hashlib.sha256(raw).hexdigest()


# ---- cmdline and HOST_DATA (spec r2 6.3) ----------------------------------------

def _check_template(template: str) -> None:
    # A bundle carries its template so the customer sees it, but only the reviewed
    # v1 bytes are accepted: another template is a code change, not a manifest edit.
    need(template == CMDLINE_TEMPLATE_V1, "cmdline_template: not the v1 template")


def cmdline(template: str, identity_hex: str) -> str:
    """The exact measured cmdline bytes (no trailing newline, no NUL)."""
    _check_template(template)
    _match(HEX64_RE, identity_hex, "identity sha256")
    line = template.replace(IDENTITY_PLACEHOLDER, identity_hex)
    need(len(line) <= CMDLINE_MAX, "cmdline: too long")
    return line


def identity_from_cmdline(line: str, template: str = CMDLINE_TEMPLATE_V1) -> str:
    """The identity sha256 a measured cmdline names; refuses any other byte."""
    _check_template(template)
    head = template[:-len(IDENTITY_PLACEHOLDER)]
    need(type(line) is str and line.startswith(head) and len(line) == len(head) + 64,
         "cmdline: not the v1 cmdline")
    identity_hex = _match(HEX64_RE, line[len(head):], "cmdline cathedral.vm")
    need(cmdline(template, identity_hex) == line, "cmdline: not the v1 cmdline")
    return identity_hex


def host_data(identity_raw: bytes) -> bytes:
    """32 raw bytes. QEMU takes them as base64 (host-data=), a report shows them as hex."""
    parse_identity(identity_raw)
    return hashlib.sha256(HOST_DATA_DOMAIN + hashlib.sha256(identity_raw).digest()).digest()


# ---- bundle manifest (spec r2 6.1) ----------------------------------------------

def parse_manifest(raw: bytes) -> dict:
    doc = parse_document(raw, "manifest")
    _fields(doc, BUNDLE_FIELDS, "manifest")
    need(type(doc["version"]) is int and doc["version"] == 1 and doc["schema"] == BUNDLE_SCHEMA,
         "manifest: unsupported version or schema")
    _match(LABEL_RE, doc["label"], "manifest label")
    for key in ("sha256", "bytes"):
        need(type(doc[key]) is dict and set(doc[key]) == set(BUNDLE_FILES), f"manifest {key}: wrong file set")
    for name in BUNDLE_FILES:
        _match(HEX64_RE, doc["sha256"][name], f"manifest sha256 {name}")
        _int(doc["bytes"][name], 1, FILE_MAX, f"manifest bytes {name}")
    _check_template(doc["cmdline_template"])
    need(doc["cpu_family"] in CPU_MODELS, "manifest cpu_family: genoa or turin")
    need(doc["cpu_model"] == CPU_MODEL, "manifest cpu_model: must be EPYC-v4 (the one accepted model)")
    need(doc["policy"] == POLICY, "manifest policy: must be 0x30000")
    need(doc["sev_snp_measure"] == SEV_SNP_MEASURE_VERSION, "manifest sev_snp_measure: must be 0.0.12")
    _match(VERSION_RE, doc["qemu_version"], "manifest qemu_version")
    _match(KERNEL_RELEASE_RE, doc["kernel_release"], "manifest kernel_release")
    _match(INITRD_VERSION_RE, doc["initrd_version"], "manifest initrd_version")
    _match(SNAPSHOT_RE, doc["snapshot"], "manifest snapshot")
    need(type(doc["ovmf_source"]) is str and 1 <= len(doc["ovmf_source"]) <= 128, "manifest ovmf_source: invalid")
    _verity_fields(doc, "manifest")
    # The verity tree sits after the data area in the same file (hash offset = data bytes).
    need(doc["base_root_data_bytes"] < doc["bytes"]["base-root.raw"],
         "manifest base_root_data_bytes: must leave room for the verity tree")
    return doc


def bundle_id(manifest_raw: bytes) -> str:
    """A bundle is digest-addressed by its manifest bytes ($VM_ROOT/bundles/<id>/)."""
    parse_manifest(manifest_raw)
    return hashlib.sha256(manifest_raw).hexdigest()


def _open_regular(path: Path) -> int:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise Refusal(f"{path.name}: not a regular file")
    return fd


def file_digest(path: Path, copy_to: Path | None = None) -> tuple[str, int]:
    """sha256 and size of a regular file (never a link), optionally copied while read."""
    try:
        fd = _open_regular(path)
    except OSError as exc:
        raise Refusal(f"{path.name}: cannot open") from exc
    h, n = hashlib.sha256(), 0
    with os.fdopen(fd, "rb") as src, (open(copy_to, "xb") if copy_to else open(os.devnull, "wb")) as dst:
        for block in iter(lambda: src.read(1 << 20), b""):
            h.update(block)
            dst.write(block)
            n += len(block)
    return h.hexdigest(), n


def read_manifest(bundle: Path) -> tuple[dict, bytes]:
    try:
        fd = _open_regular(bundle / "manifest.json")
    except OSError as exc:
        raise Refusal("manifest.json: cannot open") from exc
    with os.fdopen(fd, "rb") as f:
        raw = f.read(DOC_MAX + 1)
    return parse_manifest(raw), raw


def check_bundle(bundle: Path) -> dict:
    """Every bundle file has the size and sha256 its manifest names."""
    manifest, raw = read_manifest(bundle)
    for name in BUNDLE_FILES:
        digest, size = file_digest(bundle / name)
        need(digest == manifest["sha256"][name] and size == manifest["bytes"][name],
             f"{name}: differs from the manifest")
    return {"bundle": hashlib.sha256(raw).hexdigest(), "label": manifest["label"]}


def write_manifest(bundle: Path, **fields: object) -> str:
    """manifest.json over the finished files in bundle/. Refuses to replace one."""
    sha, size = {}, {}
    for name in BUNDLE_FILES:
        sha[name], size[name] = file_digest(bundle / name)
    doc = {"version": 1, "schema": BUNDLE_SCHEMA, "sha256": sha, "bytes": size,
           "cmdline_template": CMDLINE_TEMPLATE_V1, "policy": POLICY,
           "sev_snp_measure": SEV_SNP_MEASURE_VERSION, **fields}
    doc.setdefault("cpu_model", CPU_MODEL)
    raw = canonical(doc)
    parse_manifest(raw)
    with open(bundle / "manifest.json", "xb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    return hashlib.sha256(raw).hexdigest()


# ---- expected measurement (spec r2 6.3, D 9) ------------------------------------

def default_tool() -> str:
    beside = Path(sys.executable).with_name("sev-snp-measure")
    if beside.is_file():
        return str(beside)
    return shutil.which("sev-snp-measure") or "sev-snp-measure"


def _run(argv: list[str], cwd: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=MEASURE_TIMEOUT, cwd=cwd,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refusal(f"sev-snp-measure did not run: {type(exc).__name__}") from exc


def check_tool(tool: str) -> None:
    r = _run([tool, "--version"], cwd="/")
    need(r.returncode == 0 and r.stdout.strip() == f"sev-snp-measure {SEV_SNP_MEASURE_VERSION}",
         f"sev-snp-measure {SEV_SNP_MEASURE_VERSION} is required")


def measure_argv(tool: str, vcpus: int, cpu_model: str, ovmf: str, kernel: str, initrd: str,
                 line: str) -> list[str]:
    """The argv of install-sealed.sh:88-90 and spec r2 6.3. The cmdline is one element."""
    return [tool, "--mode", "snp", "--vcpus", str(vcpus), "--vcpu-type", cpu_model,
            "--ovmf", ovmf, "--kernel", kernel, "--initrd", initrd, "--append", line]


def expected_measurement(bundle: Path, manifest: dict, line: str, vcpus: int, tool: str) -> str:
    """96 hex. Measures private copies whose digests matched, so a file swapped after
    the check cannot be the one measured."""
    _int(vcpus, 1, VCPUS_MAX, "vcpus")
    check_tool(tool)
    with tempfile.TemporaryDirectory(prefix="vm-measure-") as tmp:
        copies = {}
        for name in MEASURED_FILES:
            copies[name] = Path(tmp) / name
            digest, size = file_digest(bundle / name, copy_to=copies[name])
            need(digest == manifest["sha256"][name] and size == manifest["bytes"][name],
                 f"{name}: differs from the manifest")
        r = _run(measure_argv(tool, vcpus, manifest["cpu_model"], str(copies["OVMF.amdsev.fd"]),
                              str(copies["vmlinuz"]), str(copies["initrd.cpio.zst"]), line), cwd=tmp)
    out = r.stdout.strip()
    need(r.returncode == 0 and HEX96_RE.fullmatch(out) is not None,
         f"sev-snp-measure failed: {r.stderr.strip()[:200]}")
    return out


def launch_values(bundle: Path, identity_raw: bytes, vcpus: int, cpu_family: str,
                  tool: str | None = None) -> dict:
    """What create computes and status returns (spec r2 6.3), the broker passes through."""
    manifest, raw = read_manifest(bundle)
    need(cpu_family in CPU_MODELS, "cpu_family: genoa or turin")
    need(manifest["cpu_family"] == cpu_family, "cpu_family: the bundle is built for another CPU family")
    _int(vcpus, 1, VCPUS_MAX, "vcpus")
    identity_hex = identity_sha256(identity_raw)
    line = cmdline(manifest["cmdline_template"], identity_hex)
    hd = host_data(identity_raw)
    return {"bundle": hashlib.sha256(raw).hexdigest(), "identity_sha256": identity_hex, "cmdline": line,
            "host_data": hd.hex(), "host_data_b64": base64.b64encode(hd).decode(),
            "vcpus": vcpus, "cpu_family": cpu_family, "cpu_model": manifest["cpu_model"],
            "cpu_signature": CPU_SIGNATURES[manifest["cpu_model"]],
            "policy": POLICY, "sev_snp_measure": SEV_SNP_MEASURE_VERSION,
            "expected_measurement": expected_measurement(bundle, manifest, line, vcpus, tool or default_tool())}


# ---- command line ---------------------------------------------------------------

def _read_small(path: str, limit: int = DOC_MAX) -> bytes:
    with open(path, "rb") as f:
        raw = f.read(limit + 1)
    need(len(raw) <= limit, f"{Path(path).name}: too large")
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("identity", help="write vm-identity.json for a new VM")
    p.add_argument("--bundle", required=True)
    p.add_argument("--vm-id", required=True)
    p.add_argument("--ssh-key-file", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--salt-hex", help="tests and vectors only; create uses the CSPRNG")
    p = sub.add_parser("launch", help="identity sha256, cmdline, HOST_DATA and expected measurement")
    p.add_argument("--bundle", required=True)
    p.add_argument("--identity", required=True)
    p.add_argument("--vcpus", required=True, type=int)
    p.add_argument("--cpu-family", required=True, choices=sorted(CPU_MODELS))
    p.add_argument("--tool", help="sev-snp-measure path (default: beside this Python, then PATH)")
    p = sub.add_parser("bundle-manifest", help="write manifest.json over a finished bundle directory")
    p.add_argument("--dir", required=True)
    for flag in ("--label", "--qemu-version", "--kernel-release", "--initrd-version", "--snapshot",
                 "--base-root-verity", "--ovmf-source"):
        p.add_argument(flag, required=True)
    p.add_argument("--cpu-family", required=True, choices=sorted(CPU_MODELS))
    p.add_argument("--base-root-data-bytes", required=True, type=int)
    p = sub.add_parser("check-bundle", help="check every bundle file against its manifest")
    p.add_argument("dir")
    args = parser.parse_args(argv)
    try:
        if args.command == "identity":
            manifest, _ = read_manifest(Path(args.bundle))
            raw = identity_document(args.vm_id, _read_small(args.ssh_key_file).decode("ascii", "replace"),
                                    manifest["base_root_verity"], manifest["base_root_data_bytes"],
                                    salt_hex=args.salt_hex)
            with open(args.out, "xb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            result = {"identity_sha256": hashlib.sha256(raw).hexdigest(), "vm_id": args.vm_id}
        elif args.command == "launch":
            result = launch_values(Path(args.bundle), _read_small(args.identity), args.vcpus,
                                   args.cpu_family, args.tool)
        elif args.command == "bundle-manifest":
            result = {"bundle": write_manifest(
                Path(args.dir), label=args.label, cpu_family=args.cpu_family, qemu_version=args.qemu_version,
                kernel_release=args.kernel_release, initrd_version=args.initrd_version, snapshot=args.snapshot,
                base_root_verity=args.base_root_verity, base_root_data_bytes=args.base_root_data_bytes,
                ovmf_source=args.ovmf_source)}
        else:
            result = check_bundle(Path(args.dir))
    except (Refusal, OSError) as exc:
        print(json.dumps({"error": "refused", "detail": str(exc) or type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
