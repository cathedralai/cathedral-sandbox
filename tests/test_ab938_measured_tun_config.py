"""AB#938: the measured build carries an explicit opt-in, never request labels."""
from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILD = (ROOT / "room-kit/sealed/build-guest.sh").read_text()


def measured_config(**values):
    block = BUILD.split("# >>> dedicated TUN", 1)[1].split("# <<< dedicated TUN", 1)[0]
    block = block.split("\n", 1)[1]
    env = {k: v for k, v in os.environ.items() if not k.startswith("SEALED_")}
    return subprocess.run(["bash", "-eu", "-c", block + '\nprintf "%s" "$DEDICATED_ENV"'],
                          env={**env, **values}, text=True, capture_output=True, timeout=10)


@pytest.mark.parametrize("values", [{}, {"SEALED_HOTEL_TENANCY": "shared", "SEALED_ROOM_ALLOW_TUN": "0"}])
def test_default_adds_no_measured_settings(values):
    result = measured_config(**values)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("tun", ["0", "1"])
def test_dedicated_writes_only_validated_literals(tun):
    result = measured_config(SEALED_HOTEL_TENANCY="dedicated", SEALED_ROOM_ALLOW_TUN=tun)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"CATHEDRAL_HOTEL_TENANCY=dedicated\nROOM_ALLOW_TUN={tun}"


@pytest.mark.parametrize("values", [
    {"SEALED_ROOM_ALLOW_TUN": "1"},
    {"SEALED_HOTEL_TENANCY": "Dedicated"},
    {"SEALED_HOTEL_TENANCY": "dedicated\nROOM_RECEIPTS=0"},
    {"SEALED_HOTEL_TENANCY": "dedicated", "SEALED_ROOM_ALLOW_TUN": "yes"},
    {"SEALED_OWNER_GATE": "open"},
    {"SEALED_HOTEL_TENANCY": "shared", "SEALED_OWNER_GATE": "open"},
    {"SEALED_HOTEL_TENANCY": "dedicated", "SEALED_OWNER_GATE": "Open"},
    {"SEALED_HOTEL_TENANCY": "dedicated", "SEALED_OWNER_GATE": "open\nROOM_RECEIPTS=0"},
])
def test_invalid_or_shared_tun_stops_before_build(values):
    result = measured_config(**values)
    assert result.returncode != 0
    assert "SEALED_" in result.stderr
    assert result.stdout == ""


def test_settings_are_appended_to_measured_room_env_and_tun_module_is_opt_in(tmp_path):
    # Execute the actual builder writes without package installation/image build.
    room_write = next(line for line in BUILD.splitlines() if line.startswith('[ -z "$DEDICATED_ENV" ]'))
    module_write = next(line for line in BUILD.splitlines() if line.startswith('[ "$ALLOW_TUN" != 1 ]'))
    for tun in ("0", "1"):
        root = tmp_path / tun
        (root / "opt/room-kit").mkdir(parents=True)
        (root / "etc/modules-load.d").mkdir(parents=True)
        room = root / "opt/room-kit/room.env"
        modules = root / "etc/modules-load.d/sealed.conf"
        room.write_text("existing\n")
        modules.write_text("existing\n")
        config = measured_config(SEALED_HOTEL_TENANCY="dedicated", SEALED_ROOM_ALLOW_TUN=tun)
        subprocess.run(["bash", "-eu", "-c", f"R={shlex.quote(str(root))}\nALLOW_TUN={tun}\n"
                        f"DEDICATED_ENV={shlex.quote(config.stdout)}\n{room_write}\n{module_write}"], check=True)
        assert room.read_text() == "existing\n\n" + config.stdout + "\n"
        assert modules.read_text() == "existing\n" + ("tun\n" if tun == "1" else "")


# AB#962: the owner gate is a measured build input. required (or unset) is today's build byte for byte.
@pytest.mark.parametrize("tun", ["0", "1"])
def test_required_owner_gate_adds_nothing(tun):
    base = measured_config(SEALED_HOTEL_TENANCY="dedicated", SEALED_ROOM_ALLOW_TUN=tun)
    required = measured_config(SEALED_HOTEL_TENANCY="dedicated", SEALED_ROOM_ALLOW_TUN=tun, SEALED_OWNER_GATE="required")
    assert base.returncode == required.returncode == 0
    assert required.stdout == base.stdout == f"CATHEDRAL_HOTEL_TENANCY=dedicated\nROOM_ALLOW_TUN={tun}"
    assert measured_config(SEALED_OWNER_GATE="required").stdout == ""


@pytest.mark.parametrize("tun", ["0", "1"])
def test_open_owner_gate_is_written_into_the_measured_config(tun):
    result = measured_config(SEALED_HOTEL_TENANCY="dedicated", SEALED_ROOM_ALLOW_TUN=tun, SEALED_OWNER_GATE="open")
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"CATHEDRAL_HOTEL_TENANCY=dedicated\nROOM_ALLOW_TUN={tun}\nCATHEDRAL_OWNER_GATE=open"


def _runsc_flags(tenancy: str) -> str:
    start = BUILD.index('if [ "$TENANCY" = dedicated ]; then\n  # --host-uds')
    block = BUILD[start:BUILD.index("\nfi\n", start) + 4]
    result = subprocess.run(["bash", "-eu", "-c", f'TENANCY={tenancy}\n{block}\nprintf "%s" "$ROOM_RUNSC_FLAGS"'],
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_dedicated_runsc_flags_open_host_uds_only():
    # The report socket (AB#1001) needs host UDS; no room opens a host character device.
    assert _runsc_flags("dedicated") == "--platform=systrap --overlay2=none --net-raw --host-uds=open"


def test_shared_runsc_flags_are_unchanged():
    assert _runsc_flags("shared") == "--platform=systrap --overlay2=none --net-raw"


def test_in_room_attest_line_is_dedicated_only_and_outside_the_measured_block():
    assert '[ "$TENANCY" != dedicated ] || echo "ROOM_IN_ROOM_ATTEST=1" >>' in BUILD
    assert "ROOM_IN_ROOM_ATTEST" not in measured_config(SEALED_HOTEL_TENANCY="dedicated").stdout
