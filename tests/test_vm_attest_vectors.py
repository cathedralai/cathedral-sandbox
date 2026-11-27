"""AB#999 VM1b: the guest attest vectors are what verify_vm.report_data computes."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "room-kit" / "vm"))
import verify_vm  # noqa: E402

GEN = REPO / "scripts" / "make_vm_attest_vectors.py"
FIXTURE = REPO / "tests" / "fixtures" / "vm_attest_report_data_v1.json"


def test_fixture_is_what_the_generator_makes():
    assert subprocess.run([sys.executable, str(GEN), "--check"]).returncode == 0


def test_every_case_equals_verify_vm_report_data():
    for case in json.loads(FIXTURE.read_text())["cases"]:
        blob = bytes.fromhex(case["host_key_blob_hex"])
        assert verify_vm.report_data(bytes.fromhex(case["challenge_hex"]), blob).hex() == case["report_data_hex"]
        assert verify_vm.GUEST_ATTEST == "/run/cathedral/bin/cathedral-attest"
