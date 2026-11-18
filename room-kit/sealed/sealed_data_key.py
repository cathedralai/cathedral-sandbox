#!/usr/bin/python3
"""Key of the sealed data volume, made inside the SNP guest.

Runs INSIDE the sealed guest, before the room kit is installed, with the
system python3 and the standard library only.

The AMD secure processor derives a key for this guest (MSG_KEY_REQ through
the SNP_GET_DERIVED_KEY ioctl on /dev/sev-guest). The chip mixes in:

- its own chip-unique root key (VCEK root): another machine cannot make it;
- GUEST_POLICY and MEASUREMENT (GUEST_FIELD_SELECT bits 0 and 3): another
  build, or this build with a debug policy, cannot make it.

FAMILY_ID and IMAGE_ID are not mixed in: they come from an ID block that the
host signs with a key of its own choosing, so a host could launch its own
image with the same IDs and get the same key. TCB_VERSION is not mixed in, so
a host firmware update does not change the key (see docs/SEALED_DATA_VOLUME.md).

This script then mixes in HOST_DATA from the guest's own attestation report
(HKDF-SHA256). The chip has no field select bit for HOST_DATA; the guest reads
it from a report the chip signs, so the host cannot change it after launch.
On a dedicated machine HOST_DATA names the owner, so a relaunch that names
another owner gets another key.

Usage:
  sealed_data_key.py key    32 raw key bytes on stdout, for cryptsetup --key-file -
  sealed_data_key.py info   JSON on stdout: field select, measurement, policy,
                            HOST_DATA and key_id (an HKDF label of the key, not the key)

Nothing else is printed, and the key never goes to a log. sealed-data.sh keeps
it in a 0600 file on /run (tmpfs, so guest memory) for the seconds cryptsetup
needs it, then removes it.
"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import hmac
import json
import os
import sys
import uuid

SEV_GUEST = "/dev/sev-guest"
TSM = "/sys/kernel/config/tsm/report"

# GUEST_FIELD_SELECT (SEV-SNP firmware ABI, MSG_KEY_REQ).
FIELD_POLICY = 1 << 0
FIELD_IMAGE_ID = 1 << 1
FIELD_FAMILY_ID = 1 << 2
FIELD_MEASUREMENT = 1 << 3
FIELD_GUEST_SVN = 1 << 4
FIELD_TCB_VERSION = 1 << 5
FIELD_SELECT = FIELD_POLICY | FIELD_MEASUREMENT
ROOT_KEY_VCEK = 0
VMPL = 0

SALT = b"cathedral-sealed-data-v1"


# linux/sev-guest.h
class _GuestRequest(ctypes.Structure):
    _fields_ = [
        ("msg_version", ctypes.c_uint8),
        ("req_data", ctypes.c_uint64),
        ("resp_data", ctypes.c_uint64),
        ("exitinfo2", ctypes.c_uint64),
    ]


class _DerivedKeyRequest(ctypes.Structure):
    _fields_ = [
        ("root_key_select", ctypes.c_uint32),
        ("rsvd", ctypes.c_uint32),
        ("guest_field_select", ctypes.c_uint64),
        ("vmpl", ctypes.c_uint32),
        ("guest_svn", ctypes.c_uint32),
        ("tcb_version", ctypes.c_uint64),
    ]


def _iowr(nr: int, size: int) -> int:
    # _IOWR('S', nr, size): direction read|write (3) << 30, size << 16, type << 8, nr
    return (3 << 30) | (size << 16) | (ord("S") << 8) | nr


SNP_GET_DERIVED_KEY = _iowr(0x1, ctypes.sizeof(_GuestRequest))
DERIVED_KEY_RESPONSE_BYTES = 64  # struct snp_derived_key_resp: MSG_KEY_RSP

# Attestation report offsets (SEV-SNP firmware ABI, ATTESTATION_REPORT).
REPORT_POLICY = slice(0x08, 0x10)
REPORT_MEASUREMENT = slice(0x90, 0xC0)
REPORT_HOST_DATA = slice(0xC0, 0xE0)
REPORT_BYTES = 0x4A0


class SealedKeyError(RuntimeError):
    """The secure processor did not give a key or a report."""


def derived_key(path: str = SEV_GUEST, ioctl=fcntl.ioctl, field_select: int = FIELD_SELECT) -> bytes:
    """32 bytes from MSG_KEY_REQ: VCEK root, GUEST_FIELD_SELECT, VMPL 0."""
    req = _DerivedKeyRequest(root_key_select=ROOT_KEY_VCEK, guest_field_select=field_select, vmpl=VMPL)
    resp = ctypes.create_string_buffer(DERIVED_KEY_RESPONSE_BYTES)
    guest = _GuestRequest(msg_version=1, req_data=ctypes.addressof(req), resp_data=ctypes.addressof(resp))
    try:
        fd = os.open(path, os.O_RDWR)
    except OSError as exc:
        raise SealedKeyError(f"cannot open {path}: {exc.strerror}") from None
    try:
        ioctl(fd, SNP_GET_DERIVED_KEY, guest, True)
    except OSError as exc:
        raise SealedKeyError(
            f"SNP_GET_DERIVED_KEY failed: {exc.strerror}; firmware error {guest.exitinfo2 & 0xFFFFFFFF:#x}, "
            f"VMM error {guest.exitinfo2 >> 32:#x}"
        ) from None
    finally:
        os.close(fd)
    raw = resp.raw
    status = int.from_bytes(raw[0:4], "little")
    if status != 0:
        raise SealedKeyError(f"MSG_KEY_RSP status {status:#x}")
    key = raw[32:64]
    ctypes.memset(resp, 0, len(resp))
    if key == bytes(32):
        raise SealedKeyError("MSG_KEY_RSP gave an all-zero key")
    return key


def tsm_report(report_data: bytes = bytes(64), root: str = TSM) -> bytes:
    """One attestation report through configfs-tsm (as room_receipts.py reads it)."""
    entry = os.path.join(root, "sealed-data-" + uuid.uuid4().hex[:12])
    try:
        os.mkdir(entry)
    except OSError as exc:
        raise SealedKeyError(f"cannot make a report entry in {root}: {exc.strerror}") from None
    try:
        with open(os.path.join(entry, "inblob"), "wb") as f:
            f.write(report_data)
        with open(os.path.join(entry, "outblob"), "rb") as f:
            report = f.read()
    finally:
        os.rmdir(entry)
    if len(report) < REPORT_BYTES:
        raise SealedKeyError(f"report has {len(report)} bytes, want {REPORT_BYTES}")
    return report


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _context(field_select: int, host_data: bytes) -> bytes:
    return field_select.to_bytes(8, "little") + host_data


def volume_key(chip_key: bytes, field_select: int, host_data: bytes) -> bytes:
    """The LUKS2 passphrase: 32 bytes."""
    return hkdf(chip_key, SALT, b"luks2-passphrase\0" + _context(field_select, host_data), 32)


def key_id(chip_key: bytes, field_select: int, host_data: bytes) -> str:
    """A public label of the key: equal labels mean equal keys, and it reveals nothing of the key."""
    return hkdf(chip_key, SALT, b"key-id\0" + _context(field_select, host_data), 8).hex()


def material(path: str = SEV_GUEST, tsm_root: str = TSM, ioctl=fcntl.ioctl) -> tuple[bytes, dict]:
    report = tsm_report(root=tsm_root)
    chip_key = derived_key(path, ioctl, FIELD_SELECT)
    host_data = report[REPORT_HOST_DATA]
    info = {
        "schema": "cathedral_sealed_data_key_v1",
        "root_key": "vcek",
        "guest_field_select": FIELD_SELECT,
        "vmpl": VMPL,
        "policy": f"{int.from_bytes(report[REPORT_POLICY], 'little'):#x}",
        "measurement": report[REPORT_MEASUREMENT].hex(),
        "host_data": host_data.hex(),
        "key_id": key_id(chip_key, FIELD_SELECT, host_data),
    }
    key = volume_key(chip_key, FIELD_SELECT, host_data)
    return key, info


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("key", "info"):
        print("usage: sealed_data_key.py key|info", file=sys.stderr)
        return 2
    try:
        key, info = material()
    except SealedKeyError as exc:
        print(f"sealed_data_key: {exc}", file=sys.stderr)
        return 1
    if argv[1] == "key":
        sys.stdout.buffer.write(key)
        sys.stdout.buffer.flush()
    else:
        print(json.dumps(info, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
