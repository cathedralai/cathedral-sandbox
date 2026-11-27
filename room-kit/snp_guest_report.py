#!/usr/bin/env python3
"""Collect an unverified SNP report directly inside a Linux SNP VM (AB#1004).

Linux UAPI: include/uapi/linux/sev-guest.h, SNP_GET_REPORT.
Firmware response: MSG_REPORT_RSP, 32-byte header followed by the report.
No socket, configfs, network, permission change or emulation fallback.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import fcntl
import json
import os
import re
import stat
import sys

DEVICE = "/dev/sev-guest"
REPORT_BYTES = 1184
RESPONSE_BYTES = 4000


class ReportError(RuntimeError):
    pass


class GuestRequest(ctypes.Structure):
    _fields_ = [("msg_version", ctypes.c_uint8), ("req_data", ctypes.c_uint64),
                ("resp_data", ctypes.c_uint64), ("exitinfo2", ctypes.c_uint64)]


class ReportRequest(ctypes.Structure):
    _fields_ = [("user_data", ctypes.c_uint8 * 64), ("vmpl", ctypes.c_uint32),
                ("reserved", ctypes.c_uint8 * 28)]


SNP_GET_REPORT = (3 << 30) | (ctypes.sizeof(GuestRequest) << 16) | (ord("S") << 8)


def collect(report_data: bytes, device: str = DEVICE, *, ioctl=None) -> dict:
    """Return collected bytes, not a cryptographic verdict. Requires VMPL 0."""
    if len(report_data) != 64:
        raise ReportError("REPORT_DATA must be exactly 64 bytes")
    if sys.byteorder != "little" or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(GuestRequest) != 32:
        raise ReportError("requires the 64-bit little-endian Linux SNP guest ABI")
    request = ReportRequest()
    request.user_data[:] = report_data
    request.vmpl = 0
    response = ctypes.create_string_buffer(RESPONSE_BYTES)
    command = GuestRequest(msg_version=1, req_data=ctypes.addressof(request),
                           resp_data=ctypes.addressof(response))
    try:
        fd = os.open(device, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise ReportError(f"cannot open SNP guest device: {exc.strerror}") from None
    try:
        if not stat.S_ISCHR(os.fstat(fd).st_mode):
            raise ReportError("SNP guest device must be a character device")
        try:
            (ioctl or fcntl.ioctl)(fd, SNP_GET_REPORT, command, True)
        except OSError as exc:
            raise ReportError(f"SNP_GET_REPORT failed: {exc.strerror}; "
                              f"firmware={command.exitinfo2 & 0xffffffff:#x}, "
                              f"VMM={command.exitinfo2 >> 32:#x}") from None
    finally:
        os.close(fd)
    if command.exitinfo2:
        raise ReportError(f"SNP_GET_REPORT returned firmware/VMM error {command.exitinfo2:#x}")
    raw = response.raw
    status = int.from_bytes(raw[:4], "little")
    size = int.from_bytes(raw[4:8], "little")
    if status:
        raise ReportError(f"MSG_REPORT_RSP status {status:#x}")
    if size != REPORT_BYTES:
        raise ReportError(f"MSG_REPORT_RSP report size {size}, expected {REPORT_BYTES}")
    report = raw[32:32 + size]
    if report[0x50:0x90] != report_data:
        raise ReportError("collected REPORT_DATA differs from the requested challenge")
    if int.from_bytes(report[0x30:0x34], "little") != 0:
        raise ReportError("collected report is not VMPL 0")
    return {"schema": "cathedral.snp.guest-report/v1", "verification": "not_checked",
            "source": "SNP_GET_REPORT", "report_b64": base64.b64encode(report).decode(),
            "cert_chain": None}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-data-hex", required=True, help="64 verifier-chosen bytes, 128 hex characters")
    parser.add_argument("--device", default=DEVICE, help="SNP guest character device (default /dev/sev-guest)")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-fA-F]{128}", args.report_data_hex):
        parser.error("--report-data-hex must be exactly 128 hex characters")
    try:
        result = collect(bytes.fromhex(args.report_data_hex), args.device)
    except (ReportError, OSError) as exc:
        print(json.dumps({"error": "report_collection_failed", "message": str(exc)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
