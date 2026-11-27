"""End-to-end acceptance for a dedicated custom guest (draft for spec r9 section 16).

Runs only against a real launched guest. It is skipped unless UR_REHEARSAL_HOST is set, so
CI and laptops never touch hardware. Every value comes from the operator's environment and
the owner's retained files; nothing is read from the API or the report itself.

  UR_REHEARSAL_HOST, UR_REHEARSAL_PORT (default 20022), UR_REHEARSAL_IDENTITY,
  UR_REHEARSAL_DIR (holds manifest.json, bootstrap.json, bootstrap.sig, owner.pub),
  UR_EXPECTED_MEASUREMENT, UR_EXPECTED_CHIP_ID, UR_EXPECTED_CPUID, UR_ARK_SHA256,
  UR_RESTART_RESULT (verify_custom_guest.py JSON taken after the hold and return),
  UR_PRESERVED_BEFORE, UR_PRESERVED_AFTER (sha256sum listings of the kept disks),
  UR_MIN_TCB (one floor per generation, separated by spaces, each in the verifier's form,
  for example "turin:fmc=1,bl=1,tee=1,snp=1,ucode=1").
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NEEDED = ("UR_REHEARSAL_HOST", "UR_REHEARSAL_IDENTITY", "UR_REHEARSAL_DIR", "UR_EXPECTED_MEASUREMENT",
          "UR_EXPECTED_CHIP_ID", "UR_EXPECTED_CPUID", "UR_ARK_SHA256", "UR_MIN_TCB",
          "UR_RESTART_RESULT", "UR_PRESERVED_BEFORE", "UR_PRESERVED_AFTER")

pytestmark = pytest.mark.skipif(not os.environ.get("UR_REHEARSAL_HOST"), reason="needs a launched dedicated guest")


def test_rehearsal_a_passes_against_live_guest(tmp_path):
    missing = [name for name in NEEDED if not os.environ.get(name)]
    assert not missing, f"set {', '.join(missing)}"
    env, docs = os.environ, Path(os.environ["UR_REHEARSAL_DIR"])
    argv = [sys.executable, str(ROOT / "room-kit" / "ur_rehearsal_check.py"),
            "--host", env["UR_REHEARSAL_HOST"], "--port", env.get("UR_REHEARSAL_PORT", "20022"),
            "--identity", env["UR_REHEARSAL_IDENTITY"],
            "--manifest", str(docs / "manifest.json"), "--bootstrap", str(docs / "bootstrap.json"),
            "--bootstrap-signature", str(docs / "bootstrap.sig"), "--owner-public-key", str(docs / "owner.pub"),
            "--expected-measurement", env["UR_EXPECTED_MEASUREMENT"], "--expected-chip-id", env["UR_EXPECTED_CHIP_ID"],
            "--expected-cpuid", env["UR_EXPECTED_CPUID"], "--ark-sha256", env["UR_ARK_SHA256"],
            "--known-hosts-out", str(tmp_path / "known_hosts"),
            "--restart-result", env["UR_RESTART_RESULT"],
            "--preserved-before", env["UR_PRESERVED_BEFORE"], "--preserved-after", env["UR_PRESERVED_AFTER"]]
    # Commas separate components inside one floor; only whitespace separates floors.
    for floor in env["UR_MIN_TCB"].split():
        argv += ["--min-tcb", floor]
    done = subprocess.run(argv, capture_output=True, timeout=300, check=False)
    result = json.loads(done.stdout)
    by_name = {c["name"]: c for c in result["checks"]}
    assert result["verdict"] == "PASS" and done.returncode == 0, json.dumps(result, indent=1)
    assert by_name["guest_report"]["detail"]["ssh_channel_binding"] == "verified"
    # A pinned key is written only after every check passed.
    assert (tmp_path / "known_hosts").read_bytes().count(b"\n") == 1
