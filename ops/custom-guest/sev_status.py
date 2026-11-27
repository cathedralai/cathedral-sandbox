#!/usr/bin/env python3
"""Read the AMD SEV and SEV-SNP platform status from /dev/sev (spec-r9 5.9).

  sev_status.py read                 print {"snp": {...}, "sev": {...}} as JSON
  sev_status.py compare <base.json>  exit 0 when the compared fields equal the
                                     baseline, 3 when any differs (printed), 1 on error

Root runs it at `baselined`, and the custom timer, the boot phase and the
return phase compare against that baseline. A change means a platform command
reached the chip through a writable /dev/sev (SNP_SET_CONFIG, SNP_COMMIT), so
the guest stops (`sev_platform_changed`).

Only status commands are issued, on a read-only descriptor: SEV_PLATFORM_STATUS
and SNP_PLATFORM_STATUS need no write access (linux drivers/crypto/ccp/sev-dev.c
checks `writable` only for the commands that change the platform). The structs
are those of include/uapi/linux/psp-sev.h.
"""
from __future__ import annotations

import ctypes
import fcntl
import json
import os
import struct
import sys

SEV_DEVICE = "/dev/sev"
# enum sev_cmd (uapi psp-sev.h)
SEV_PLATFORM_STATUS = 1
SNP_PLATFORM_STATUS = 9


# struct sev_issue_cmd { __u32 cmd; __u64 data; __u32 error; } __packed: 16 bytes.
ISSUE_CMD = struct.Struct("<IQI")


def _iowr(type_char: str, nr: int, size: int) -> int:
    return (3 << 30) | (size << 16) | (ord(type_char) << 8) | nr


SEV_ISSUE_CMD = _iowr("S", 0, ISSUE_CMD.size)  # 0xC0105300

# Fields that must not change during a hold. guest_count and state follow the
# guests that run, so they are reported, not compared.
COMPARED = {
    "snp": ("api_major", "api_minor", "build_id", "mask_chip_id", "mask_chip_key", "vlek_en",
            "current_tcb", "reported_tcb"),
    "sev": ("api_major", "api_minor", "build", "owner", "config_flags"),
}


def parse_snp(raw: bytes) -> dict:
    """struct sev_user_data_snp_status (packed, 32 bytes)."""
    if len(raw) < 32:
        raise ValueError("short SNP status")
    word = int.from_bytes(raw[8:12], "little")
    return {
        "api_major": raw[0], "api_minor": raw[1], "state": raw[2], "is_rmp_initialized": raw[3] & 1,
        "build_id": int.from_bytes(raw[4:8], "little"),
        "mask_chip_id": word & 1, "mask_chip_key": (word >> 1) & 1, "vlek_en": (word >> 2) & 1,
        "feature_info": (word >> 3) & 1, "rapl_dis": (word >> 4) & 1,
        "ciphertext_hiding_cap": (word >> 5) & 1, "ciphertext_hiding_en": (word >> 6) & 1,
        "guest_count": int.from_bytes(raw[12:16], "little"),
        "current_tcb": raw[16:24].hex(), "reported_tcb": raw[24:32].hex(),
    }


def parse_sev(raw: bytes) -> dict:
    """struct sev_user_data_status (packed, 12 bytes)."""
    if len(raw) < 12:
        raise ValueError("short SEV status")
    flags = int.from_bytes(raw[3:7], "little")
    return {"api_major": raw[0], "api_minor": raw[1], "state": raw[2], "owner": flags & 1,
            "config_flags": flags & ~1, "build": raw[7], "guest_count": int.from_bytes(raw[8:12], "little")}


def _issue(fd: int, cmd: int, size: int) -> bytes:
    # The kernel copies the SNP status out of a page it allocates, so give it a page.
    buf = ctypes.create_string_buffer(max(size, 4096))
    req = bytearray(ISSUE_CMD.pack(cmd, ctypes.addressof(buf), 0))
    try:
        fcntl.ioctl(fd, SEV_ISSUE_CMD, req, True)
    except OSError as e:
        raise OSError(f"SEV command {cmd} failed: {e} (firmware error {ISSUE_CMD.unpack(req)[2]})") from e
    return buf.raw[:size]


def read_status(device: str = SEV_DEVICE) -> dict:
    fd = os.open(device, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return {"snp": parse_snp(_issue(fd, SNP_PLATFORM_STATUS, 32)),
                "sev": parse_sev(_issue(fd, SEV_PLATFORM_STATUS, 12))}
    finally:
        os.close(fd)


def differences(baseline: dict, now: dict) -> list[str]:
    out = []
    for part, fields in COMPARED.items():
        for f in fields:
            a = (baseline.get(part) or {}).get(f, "<missing>")
            b = (now.get(part) or {}).get(f, "<missing>")
            if a != b:
                out.append(f"{part}.{f}: {a} -> {b}")
    return out


def main(argv: list[str]) -> int:
    device = os.environ.get("CG_SEV_DEVICE", SEV_DEVICE)
    if argv[:1] == ["read"] and len(argv) == 1:
        try:
            print(json.dumps(read_status(device), sort_keys=True))
        except (OSError, ValueError) as e:
            print(f"sev_status: {e}", file=sys.stderr)
            return 1
        return 0
    if argv[:1] == ["compare"] and len(argv) == 2:
        try:
            base = json.load(open(argv[1]))
            diff = differences(base, read_status(device))
        except (OSError, ValueError) as e:
            print(f"sev_status: {e}", file=sys.stderr)
            return 1
        for d in diff:
            print(d)
        return 3 if diff else 0
    print("usage: sev_status.py read | compare <baseline.json>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
