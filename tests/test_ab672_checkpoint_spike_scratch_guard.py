"""Run the checkpoint spike scratch guard regression in CI (AB#672)."""

import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "checkpoint_spike" / "test_scratch_guard.sh"


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_checkpoint_spike_scratch_guard_runs_to_completion():
    result = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    # The last line only prints if every assertion above it ran.
    assert result.stdout.strip().splitlines()[-1] == "ok scratch guard"
