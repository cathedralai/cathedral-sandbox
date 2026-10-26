"""Room kit sizing with a sealed hotel guest on the same host."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

SIZE = Path(__file__).resolve().parents[1] / "room-kit" / "size.py"
GIB = 1 << 30


def machine(vms: dict | None = None, docker_cpu=80.0, docker_mem_gib=320) -> dict:
    return {
        "cpu": {"threads": 192},
        "memory": {"total_bytes": 752 * GIB, "hugepages_reserved_bytes": 0},
        "root_fs": {"mount": "/", "total_bytes": 3500 * GIB, "used_bytes": 1500 * GIB},
        "data_dir": {"mount": "/"},
        "workloads": {
            "host_docker": {"cpu_limit_sum": docker_cpu, "mem_limit_sum_bytes": docker_mem_gib * GIB,
                            "unlimited_cpu": 0, "unlimited_mem": 0, "running": 80},
            "vms": vms or {"count": 0, "vcpus_sum": 0, "mem_sum_bytes": 0, "items": []},
        },
    }


def size(tmp_path: Path, m: dict, *extra: str) -> dict:
    p = tmp_path / "machine.json"
    p.write_text(json.dumps(m))
    out = subprocess.run([sys.executable, str(SIZE), str(p), "--vcpu", "1", "--mem-gib", "4", "--disk-gib", "10",
                          "--reserve-ram-pct", "12", "--reserve-threads", "2", *extra],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


SEALED = {"count": 1, "vcpus_sum": 96, "mem_sum_bytes": 384 * GIB, "items": [],
          "sealed_hotel_count": 1, "sealed_hotel_vcpus_sum": 96, "sealed_hotel_mem_sum_bytes": 384 * GIB}


def test_overcommit_one_is_unchanged(tmp_path):
    # At overcommit 1.0 other workloads still come off the physical pool.
    d = size(tmp_path, machine())
    assert d["slots_by_resource"]["cpu"] == 192 - 2 - 80
    assert d["slots_by_resource"]["memory"] == int((752 * 0.88 - 320) // 4)


def test_sealed_guest_is_a_reserve_not_a_zero(tmp_path):
    over = ("--cpu-overcommit", "16", "--mem-overcommit", "20", "--disk-overcommit", "1000", "--max-slots", "1400")
    d = size(tmp_path, machine(SEALED), *over)
    assert d["sealed_hotel_reserve"] == {"vcpu": 96, "ram_gib": 384.0, "guests": 1}
    assert d["slots_by_resource"]["cpu"] == (192 - 2 - 96) * 16 - 80
    assert d["slots_by_resource"]["memory"] == int(((752 * 0.88 - 384) * 20 - 320) // 4)
    assert 0 < d["slots"] <= 1400


def test_unsealed_vm_is_still_a_commitment(tmp_path):
    vm = {"count": 1, "vcpus_sum": 96, "mem_sum_bytes": 384 * GIB, "items": []}
    d = size(tmp_path, machine(vm))
    assert d["slots_by_resource"]["memory"] == 0
    assert d["sealed_hotel_reserve"]["guests"] == 0
