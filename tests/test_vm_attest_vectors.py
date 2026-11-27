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


def test_the_go_recovery_show_line_parses_in_verify_vm():
    raw = (REPO / "tests" / "fixtures" / "vm_recovery_show_v1.txt").read_bytes()
    doc = json.loads(raw)
    expected = {"vm_id": doc["vm_id"], "identity_sha256": doc["identity_sha256"]}
    assert verify_vm.parse_recovery(raw.rstrip(b"\n"), expected, doc["chip_id"]) == doc["recovery_key_b64"]
    assert set(doc) == verify_vm.RECOVERY_FIELDS
    # The run of the Go tool prints exactly this line, newline included; the verifier gets it stripped or not.
    assert verify_vm.parse_recovery(raw, expected, doc["chip_id"]) == doc["recovery_key_b64"]
