"""AB#383 / AB#968: the measured kernel command line turns systemd credential import off.

systemd imports credentials from QEMU fw_cfg and SMBIOS unless told not to. The host
sets both and neither is measured, so a credential such as systemd.extra-unit.* would
run host code as root in the guest with the measurement unchanged. The build puts
systemd.import_credentials=no on the measured command line for every build.

These tests run the cmdline slice of build-guest.sh; the active injection test needs an
SNP host and is an ops step (AB#968 spec section 7).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

BUILD = Path(__file__).resolve().parents[1] / "room-kit" / "sealed" / "build-guest.sh"
WORD = "systemd.import_credentials=no"
BASH = shutil.which("bash")


def _cmdline(debug: str) -> str:
    text = BUILD.read_text()
    cmd = text[text.index("CMDLINE="):text.index("printf '%s' \"$CMDLINE\"")]
    proc = subprocess.run([BASH, "-c", 'set -euo pipefail\nDEBUG=$1\n' + cmd + 'printf "%s" "$CMDLINE"', "_", debug],
                          capture_output=True, text=True, timeout=30, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_build_script_names_the_switch_once_on_the_cmdline() -> None:
    text = BUILD.read_text()
    assigned = [line for line in text.splitlines() if line.startswith("CMDLINE=")]
    assert len(assigned) == 1, "one measured cmdline assignment"
    assert WORD in assigned[0].split()


@pytest.mark.skipif(BASH is None, reason="needs bash")
@pytest.mark.parametrize("debug", ["0", "1"])
def test_every_build_turns_credential_import_off(debug: str) -> None:
    words = _cmdline(debug).split()
    assert WORD in words, "debug and production builds both refuse host credentials"
    # No later word turns it back on: systemd takes the last value of a repeated option.
    assert [w for w in words if w.startswith("systemd.import_credentials=")] == [WORD]
    assert not any(w.startswith(("systemd.set_credential", "systemd.extra-unit")) for w in words)
    assert f"cathedral.debug={debug}" in words


@pytest.mark.skipif(BASH is None, reason="needs bash")
def test_the_rest_of_the_cmdline_is_unchanged() -> None:
    # Verifiers match the debug word by str.split(); the other words stay as they were.
    assert _cmdline("0") == ("console=ttyS0 loglevel=7 systemd.show_status=error panic=-1 rdinit=/init "
                             "systemd.import_credentials=no cathedral.debug=0")
