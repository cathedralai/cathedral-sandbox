"""AB#447: sealed guests get EPYC-Genoa-v1 (AVX-512) from one variable.

The measured vCPU type (sev-snp-measure --vcpu-type), the QEMU -cpu model and the
manifest cpu_model must all come from SEALED_CPU_MODEL, so they cannot drift.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SEALED = Path(__file__).resolve().parents[1] / "room-kit" / "sealed"
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash")


def _resolved_model(env_lines: str) -> str:
    """Source a sealed.env, then the image constants, as every sealed script does."""
    script = f'set -euo pipefail\n{env_lines}\nsource "{SEALED}/guest-constants.sh"\nprintf %s "$SEALED_CPU_MODEL"'
    proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=30,
                          env={"PATH": "/usr/bin:/bin"})
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_default_is_genoa_when_sealed_env_sets_nothing() -> None:
    assert _resolved_model("") == "EPYC-Genoa-v1"


def test_example_env_is_genoa() -> None:
    assert _resolved_model(f'source "{SEALED}/sealed.env.example"') == "EPYC-Genoa-v1"


def test_baseline_override_to_epyc_v4_works() -> None:
    assert _resolved_model("SEALED_CPU_MODEL=EPYC-v4") == "EPYC-v4"


def test_no_script_hardcodes_a_cpu_model() -> None:
    for name in ("build-guest.sh", "install-sealed.sh", "launch-guest.sh"):
        text = (SEALED / name).read_text()
        assert not re.search(r"EPYC-", text), f"{name} hardcodes a CPU model"


def test_qemu_cpu_measurement_and_manifest_use_the_same_variable() -> None:
    launch = (SEALED / "launch-guest.sh").read_text()
    install = (SEALED / "install-sealed.sh").read_text()
    build = (SEALED / "build-guest.sh").read_text()
    assert '-cpu "$SEALED_CPU_MODEL"' in launch
    assert '--vcpu-type "$SEALED_CPU_MODEL"' in install
    assert re.search(r'python3 - "\$OUT" "\$SEALED_VCPUS" "\$SEALED_CPU_MODEL"', build)
    # Each script must read the constants after sealed.env, where the default lives.
    for text in (launch, install, build):
        assert text.index("guest-constants.sh") > text.index('source "$')
