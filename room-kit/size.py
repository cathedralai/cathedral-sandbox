#!/usr/bin/env python3
"""Room kit: size. Compute sandbox slots for one shape from machine.json.

Usage: size.py machine.json [--vcpu 1] [--mem-gib 4] [--disk-gib 10]
       [--cpu-overcommit 1.0] [--mem-overcommit 1.0] [--disk-overcommit 1.0]
       [--reserve-ram-pct 12]
       [--reserve-threads 2] [--disk-max-fill-pct 70] [--room-disk-bytes N]
       [--max-slots N] [--out size.json]

Rules:
* Existing workloads are subtracted at their committed limits (Docker
  --cpus/--memory, VM -smp/-m). A container with no limit is charged at its
  live memory and 1 thread.
* The room's own Docker daemon is not subtracted (those are our slots).
* Disk: the room may grow the host filesystem to disk-max-fill-pct, no more.
  If the room has its own data volume (room-disk-bytes), the smaller wins.
* Overcommit multiplies the pool. Use 1.0 until real per-sandbox use is
  measured. The per-sandbox disk size is a ceiling (xfs project quota), and
  blocks are allocated only when written, so disk overcommit is safe to raise
  while real fill is watched.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

GIB = 1 << 30


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("machine")
    ap.add_argument("--vcpu", type=float, default=1)
    ap.add_argument("--mem-gib", type=float, default=4)
    ap.add_argument("--disk-gib", type=float, default=10)
    ap.add_argument("--cpu-overcommit", type=float, default=1.0)
    ap.add_argument("--mem-overcommit", type=float, default=1.0)
    ap.add_argument("--disk-overcommit", type=float, default=1.0)
    ap.add_argument("--reserve-ram-pct", type=float, default=12)
    ap.add_argument("--reserve-threads", type=int, default=2)
    ap.add_argument("--disk-max-fill-pct", type=float, default=70)
    ap.add_argument("--room-disk-bytes", type=int, default=0)
    ap.add_argument("--max-slots", type=int, default=0)
    ap.add_argument("--bridge-addresses", type=int, default=0, help="usable guest IPs on the room bridge")
    ap.add_argument("--out", default="-")
    a = ap.parse_args()
    m = json.loads(Path(a.machine).read_text())

    threads = m["cpu"]["threads"]
    ram = m["memory"]["total_bytes"]
    hd = m["workloads"].get("host_docker") or {}
    vms = m["workloads"].get("vms") or {}
    used_cpu = (hd.get("cpu_limit_sum") or 0) + (hd.get("unlimited_cpu") or 0) + (vms.get("vcpus_sum") or 0)
    used_ram = (hd.get("mem_limit_sum_bytes") or 0) + (vms.get("mem_sum_bytes") or 0)
    used_ram += m["memory"].get("hugepages_reserved_bytes", 0)
    if hd.get("unlimited_mem"):
        used_ram += hd.get("mem_usage_sum_bytes") or 0

    cpu_pool = max(threads - a.reserve_threads - used_cpu, 0)
    ram_pool = max(ram * (1 - a.reserve_ram_pct / 100.0) - used_ram, 0)
    fs = m["root_fs"] if m["data_dir"].get("mount") == m["root_fs"].get("mount") else m["data_dir"]
    disk_pool = max(fs["total_bytes"] * a.disk_max_fill_pct / 100.0 - fs["used_bytes"], 0)
    if a.room_disk_bytes:
        disk_pool = min(disk_pool, a.room_disk_bytes * 0.95)

    by = {
        "cpu": math.floor(cpu_pool * a.cpu_overcommit / a.vcpu),
        "memory": math.floor(ram_pool * a.mem_overcommit / (a.mem_gib * GIB)),
        "disk": math.floor(disk_pool * a.disk_overcommit / (a.disk_gib * GIB)),
    }
    if a.max_slots:
        by["operator_cap"] = a.max_slots
    if a.bridge_addresses:
        by["bridge_ips"] = a.bridge_addresses
    limiting = min(by, key=by.get)
    slots = by[limiting]
    out = {
        "shape": {"vcpu": a.vcpu, "mem_gib": a.mem_gib, "disk_gib": a.disk_gib},
        "inputs": {k: getattr(a, k) for k in ["cpu_overcommit", "mem_overcommit", "disk_overcommit", "reserve_ram_pct", "reserve_threads", "disk_max_fill_pct", "room_disk_bytes", "max_slots"]},
        "host": {"threads": threads, "ram_gib": round(ram / GIB, 1)},
        "already_used": {"vcpu": round(used_cpu, 2), "ram_gib": round(used_ram / GIB, 1),
                         "host_containers": hd.get("running", 0), "vms": vms.get("count", 0)},
        "pool": {"vcpu": round(cpu_pool, 2), "ram_gib": round(ram_pool / GIB, 1), "disk_gib": round(disk_pool / GIB, 1)},
        "slots_by_resource": by,
        "slots": slots,
        "limiting": limiting,
        # CATHEDRAL_SANDBOX_QUOTA format is running:vcpu:memory_gib.
        "quota": f"{slots}:{math.floor(slots * a.vcpu)}:{math.floor(slots * a.mem_gib)}",
    }
    text = json.dumps(out, indent=2, sort_keys=True)
    if a.out == "-":
        print(text)
    else:
        Path(a.out).write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
