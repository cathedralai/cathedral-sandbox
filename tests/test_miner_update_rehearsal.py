"""The scratch-host rehearsal of Rollout step 3 (AB#349) must itself pass."""

from __future__ import annotations

import json
import subprocess
import sys

from tests.miner_update_support import REPO_ROOT

SCRIPT = REPO_ROOT / "deploy" / "miner-update" / "rehearse_miner_update.py"


def _run(evidence_dir):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--evidence-dir", str(evidence_dir)],
        capture_output=True, text=True, timeout=300,
    )


def test_the_rehearsal_captures_step_3_and_refuses_both_negative_controls(tmp_path):
    result = _run(tmp_path / "evidence")
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    report = json.loads((tmp_path / "evidence" / "evidence.json").read_text())
    assert report["passed"] and report["scratch"]
    assert report["serving_before"]["active"] == "legacy"
    assert report["serving_after"]["version"] == "rehearsal-1"
    assert set(report["key_fingerprints"]) == {"rehearsal-canary", "rehearsal-stable"}
    controls = report["negative_controls"]
    assert controls["bad_signature"]["action"] == "refused"
    assert controls["rollback"]["action"] == "refused"
    # The throwaway keys are gone and no trust root was written outside the scratch root.
    assert not any(path.suffix == ".pem" for path in (tmp_path / "evidence").rglob("*"))


def test_the_rehearsal_never_overwrites_evidence(tmp_path):
    assert _run(tmp_path / "evidence").returncode == 0
    again = _run(tmp_path / "evidence")
    assert again.returncode != 0 and "never overwrite" in (again.stdout + again.stderr)
