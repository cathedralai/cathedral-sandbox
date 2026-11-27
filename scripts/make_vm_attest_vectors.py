#!/usr/bin/env python3
"""Make tests/fixtures/vm_attest_report_data_v1.json (AB#999, VM runtime spec r3 6.4): REPORT_DATA
for the in-guest cathedral-attest, computed by room-kit/vm/verify_vm.py's own report_data() so the
Go tool (internal/vmattest) is pinned to what the verifier expects, in the other language.

  make_vm_attest_vectors.py            write the fixture
  make_vm_attest_vectors.py --check    exit 1 if the file on disk differs
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "room-kit" / "vm"))
import verify_vm  # noqa: E402

FIXTURE = REPO / "tests" / "fixtures" / "vm_attest_report_data_v1.json"


def build() -> dict:
    cases = []
    for name in ("one", "two", "three"):
        seed = hashlib.sha256(b"cathedral-vm-attest-vector/" + name.encode()).digest()
        blob = verify_vm.ED25519_BLOB_PREFIX + seed
        challenge = hashlib.sha256(b"challenge/" + name.encode()).digest()
        cases.append({
            "challenge_hex": challenge.hex(),
            "host_key_line": "ssh-ed25519 " + base64.b64encode(blob).decode() + " root@vm-" + name,
            "host_key_blob_hex": blob.hex(),
            "report_data_hex": verify_vm.report_data(challenge, blob).hex(),
        })
    return {"spec": "VM runtime spec r3 6.4", "domain": "cathedral-vm-report/v1\\0",
            "formula": "sha512(domain || challenge[32] || sha256(host_key_blob))", "cases": cases}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    if args.check:
        return 0 if FIXTURE.read_text() == text else 1
    FIXTURE.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
