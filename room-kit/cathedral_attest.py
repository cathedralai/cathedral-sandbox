#!/usr/bin/env python3
"""Root-only custom guest report endpoint; install as /usr/bin/cathedral-attest."""
import argparse
import base64
import json
import os
import re
import stat
import sys

import custom_guest_protocol as protocol
import snp_guest_report

HOST_KEY = "/run/cathedral/ssh_host_ed25519_key.pub"


def public_blob(path=HOST_KEY):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        protocol.need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
                      "host public key must be a root-owned regular file without group/other write")
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    protocol.need(len(raw) <= 4096, "host public key too large")
    parts = raw.strip().split()
    protocol.need(len(parts) in (2, 3) and parts[0] == b"ssh-ed25519", "host public key invalid")
    return protocol.host_key_blob(base64.b64decode(parts[1], validate=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("challenge_hex")
    args = parser.parse_args()
    try:
        protocol.need(os.geteuid() == 0, "root is required")
        protocol.need(re.fullmatch(r"[0-9a-f]{64}", args.challenge_hex) is not None,
                      "challenge must be 32 bytes of lowercase hex")
        data = protocol.report_data(bytes.fromhex(args.challenge_hex), public_blob())
        answer = snp_guest_report.collect(data)
        print(json.dumps(answer))
        return 0
    except (OSError, ValueError, snp_guest_report.ReportError) as exc:
        print(json.dumps({"error": "custom_guest_report_failed", "reason": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
