"""2 vCPU rooms without halving the room cap (AB#857).

The hotel quota's vCPU part was slots x shape vCPU, so on a sealed hotel with
1,000 one-vCPU slots a 2 vCPU room stopped at 500. Sealed hotels now take the
overcommitted CPU pool as the vCPU quota.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
SIZE = REPO / "room-kit" / "size.py"
GIB = 1 << 30


def _machine(threads: int, ram_gib: int) -> dict:
    # A sealed hotel guest sizes itself: the guest is the whole machine.
    return {
        "cpu": {"threads": threads},
        "memory": {"total_bytes": ram_gib * GIB, "hugepages_reserved_bytes": 0},
        "root_fs": {"mount": "/", "total_bytes": 4000 * GIB, "used_bytes": 10 * GIB},
        "data_dir": {"mount": "/"},
        "workloads": {"host_docker": {}, "vms": {}},
    }


def _size(tmp_path: Path, *extra: str, threads: int = 96, ram_gib: int = 384) -> subprocess.CompletedProcess[str]:
    p = tmp_path / "machine.json"
    p.write_text(json.dumps(_machine(threads, ram_gib)))
    # The sealed guest's sizing inputs (room-kit/sealed/build-guest.sh).
    return subprocess.run([sys.executable, str(SIZE), str(p), "--vcpu", "1", "--mem-gib", "4", "--disk-gib", "10",
                           "--cpu-overcommit", "16", "--mem-overcommit", "20", "--disk-overcommit", "1000",
                           "--reserve-ram-pct", "12", "--reserve-threads", "2", "--disk-max-fill-pct", "80",
                           "--max-slots", "1000", *extra], capture_output=True, text=True)


def _quota(tmp_path: Path, *extra: str, **machine) -> str:
    out = _size(tmp_path, *extra, **machine)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)["quota"]


def test_default_quota_is_unchanged(tmp_path: Path) -> None:
    assert _quota(tmp_path) == "1000:1000:4000"
    assert _quota(tmp_path, "--quota-vcpu", "slots") == "1000:1000:4000"


def test_pool_quota_lets_2_vcpu_rooms_use_the_overcommitted_pool(tmp_path: Path) -> None:
    # nc-sealed: (96 - 2) x 16 = 1,504 vCPU; 752 rooms of 2 vCPU instead of 500.
    assert _quota(tmp_path, "--quota-vcpu", "pool") == "1000:1504:4000"
    # chi-sealed: (144 - 2) x 16 = 2,272 vCPU; 1,000 rooms of 2 vCPU fit.
    assert _quota(tmp_path, "--quota-vcpu", "pool", threads=144, ram_gib=576) == "1000:2272:4000"


def test_pool_quota_is_never_below_one_vcpu_per_slot(tmp_path: Path) -> None:
    # A small box whose slots are capped by CPU: the pool equals slots x vCPU, not less.
    out = _size(tmp_path, "--quota-vcpu", "pool", threads=4, ram_gib=16)
    doc = json.loads(out.stdout)
    running, vcpu, _ = doc["quota"].split(":")
    assert int(vcpu) >= int(running) and doc["quota_vcpu_source"] == "pool"


def test_an_operator_number_sets_it_but_not_below_the_slots(tmp_path: Path) -> None:
    assert _quota(tmp_path, "--quota-vcpu", "2000") == "1000:2000:4000"
    assert _quota(tmp_path, "--quota-vcpu", "10") == "1000:1000:4000"


@pytest.mark.parametrize("bad", ["", "lots", "-5", "1.5"])
def test_a_bad_value_stops_the_install(tmp_path: Path, bad: str) -> None:
    assert _size(tmp_path, "--quota-vcpu", bad).returncode != 0


def test_install_passes_room_quota_vcpu_and_keeps_it_in_room_env() -> None:
    text = (REPO / "room-kit" / "install.sh").read_text()
    keys = text.split('ROOM_KEYS="', 1)[1].split('"', 1)[0].split()
    assert "ROOM_QUOTA_VCPU" in keys
    start = text.index("size_room() {")
    size_call = text[start:text.index("\n}\n", start)]
    assert '--quota-vcpu "${ROOM_QUOTA_VCPU:-slots}"' in size_call


def test_sealed_guests_size_their_vcpu_quota_from_the_pool(tmp_path: Path) -> None:
    text = (REPO / "room-kit" / "sealed" / "build-guest.sh").read_text()
    env = text[text.index('cat > "$R/opt/room-kit/room.env" <<EOF'):text.index("# Units: no logins")]
    root = tmp_path / "root"
    (root / "opt" / "room-kit").mkdir(parents=True)
    script = tmp_path / "slice.sh"
    script.write_text("set -eo pipefail\n" + env)  # unset build vars read as empty
    values = {"R": str(root), "SEALED_GUEST_IP": "10.215.0.2", "SEALED_DNS": "1.1.1.1",
              "SEALED_ROOM_MAX_SLOTS": "1000", "SEALED_ROOM_NETS": "10.214.0.0/22"}
    proc = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", **values})
    assert proc.returncode == 0, proc.stderr
    lines = (root / "opt" / "room-kit" / "room.env").read_text().splitlines()
    assert "ROOM_QUOTA_VCPU=pool" in lines


def _sealed_room_env(tmp_path: Path, **extra: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Run the quota check and the room.env heredoc of build-guest.sh with sealed.env values."""
    text = (REPO / "room-kit" / "sealed" / "build-guest.sh").read_text()
    check = text[text.index("# Hotel vCPU quota (AB#857)"):text.index("esac\n", text.index("# Hotel vCPU quota (AB#857)")) + 5]
    env = text[text.index('cat > "$R/opt/room-kit/room.env" <<EOF'):text.index("# Units: no logins")]
    root = tmp_path / "root"
    (root / "opt" / "room-kit").mkdir(parents=True)
    script = tmp_path / "slice.sh"
    script.write_text("set -eo pipefail\n" + check + env)
    values = {"R": str(root), "SEALED_GUEST_IP": "10.215.0.2", "SEALED_DNS": "1.1.1.1",
              "SEALED_ROOM_MAX_SLOTS": "1200", "SEALED_ROOM_NETS": "10.214.0.0/22 10.214.4.0/22", **extra}
    proc = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", **values})
    out = root / "opt" / "room-kit" / "room.env"
    return proc, out.read_text().splitlines() if out.exists() else []


def test_sealed_env_can_set_a_vcpu_quota_for_2_vcpu_rooms_at_every_slot(tmp_path: Path) -> None:
    proc, lines = _sealed_room_env(tmp_path, SEALED_ROOM_QUOTA_VCPU="2400")
    assert proc.returncode == 0, proc.stderr
    assert "ROOM_QUOTA_VCPU=2400" in lines
    # size.py takes it: 1,200 slots x 2 vCPU on a 144-thread host whose pool is 2,272.
    assert _quota(tmp_path, "--max-slots", "1200", "--quota-vcpu", "2400", threads=144, ram_gib=1152) == "1200:2400:4800"


def test_sealed_env_without_a_quota_keeps_the_pool(tmp_path: Path) -> None:
    proc, lines = _sealed_room_env(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "ROOM_QUOTA_VCPU=pool" in lines


@pytest.mark.parametrize("bad", ["0", "02400", "2.5", "lots", "-1", "pool slots"])
def test_a_bad_sealed_quota_stops_the_build(tmp_path: Path, bad: str) -> None:
    proc, lines = _sealed_room_env(tmp_path, SEALED_ROOM_QUOTA_VCPU=bad)
    assert proc.returncode != 0
    assert "SEALED_ROOM_QUOTA_VCPU" in proc.stderr
    assert lines == []
