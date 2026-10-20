"""Room kit network plan (#291): room networks from the host size."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "room-kit" / "lib" / "net_plan.py"
CAPACITY = SCRIPT.with_name("net_capacity.py")


def _load():
    spec = importlib.util.spec_from_file_location("net_plan", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


net_plan = _load()


def test_small_host_needs_no_room_network() -> None:
    assert net_plan.plan(900, 1023, 1000, "10.214.0.0/16", []) == ([], None)
    assert net_plan.plan(1023, 1023, 1000, "10.214.0.0/16", []) == ([], None)


def test_one_network_for_each_thousand_rooms() -> None:
    nets, warning = net_plan.plan(4000, 1023, 1000, "10.214.0.0/16", [])
    assert warning is None
    assert nets == ["10.214.0.0/22", "10.214.4.0/22", "10.214.8.0/22", "10.214.12.0/22"]
    nets, _ = net_plan.plan(4001, 1023, 1000, "10.214.0.0/16", [])
    assert len(nets) == 5


def test_routed_cidrs_are_skipped() -> None:
    nets, _ = net_plan.plan(2500, 1023, 1000, "10.214.0.0/16", ["10.214.4.0/24", "10.214.0.1/22"])
    assert nets == ["10.214.8.0/22", "10.214.12.0/22", "10.214.16.0/22"]


def test_block_holds_the_network_size() -> None:
    assert net_plan.block_prefix(1000) == 22
    assert net_plan.block_prefix(1023) == 21
    nets, _ = net_plan.plan(3000, 1023, 1023, "10.214.0.0/16", [])
    assert all(n.endswith("/21") for n in nets)


def test_small_pool_gives_what_fits_and_a_warning() -> None:
    nets, warning = net_plan.plan(4000, 1023, 1000, "10.214.0.0/21", [])
    assert nets == ["10.214.0.0/22", "10.214.4.0/22"]
    assert warning and "4 wanted" in warning


def test_plan_capacity_matches_the_rooms() -> None:
    # The CIDRs from the plan give net_capacity.py at least the planned rooms.
    nets, _ = net_plan.plan(4000, 1023, 1000, "10.214.0.0/16", [])
    out = subprocess.run(
        [sys.executable, str(CAPACITY), "10.213.0.1/22", "1023", "1000", *nets],
        capture_output=True, text=True, check=True,
    )
    assert int(out.stdout) >= 4000


def test_cli_prints_one_line() -> None:
    out = subprocess.run(
        [sys.executable, str(SCRIPT), "2100", "1023", "1000", "10.214.0.0/16", "10.214.0.0/22"],
        capture_output=True, text=True, check=True,
    )
    assert out.stdout.strip() == "10.214.4.0/22 10.214.8.0/22 10.214.12.0/22"


def test_pool_smaller_than_one_network_fails() -> None:
    with pytest.raises(ValueError):
        net_plan.plan(4000, 1023, 1000, "10.214.0.0/24", [])
