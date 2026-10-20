#!/usr/bin/env python3
"""Room kit: assess. Read-only. Describe this machine and write machine.json.

Usage: assess.py [--data-dir PATH] [--room-socket PATH] [--out FILE]

It reads /proc, /sys, mounts, the host Docker daemon (if any), VM processes and
listening ports. It changes nothing.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path


def sh(argv: list[str], timeout: float = 60.0) -> tuple[int, str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def read(path: str) -> str:
    try:
        return Path(path).read_text()
    except OSError:
        return ""


def meminfo() -> dict[str, int]:
    out: dict[str, int] = {}
    for line in read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        parts = v.split()
        if parts:
            out[k] = int(parts[0]) * 1024
    return out


def cpu() -> dict:
    model = ""
    flags: set[str] = set()
    for line in read("/proc/cpuinfo").splitlines():
        if line.startswith("model name") and not model:
            model = line.split(":", 1)[1].strip()
        if line.startswith("flags") and not flags:
            flags = set(line.split(":", 1)[1].split())
    return {"model": model, "threads": os.cpu_count() or 0, "flags_subset": sorted(flags & {"sev", "sev_es", "sev_snp", "tdx_guest", "hypervisor", "vmx", "svm"})}


def tee() -> dict:
    p = lambda f: read(f).strip()
    return {
        "kvm": os.path.exists("/dev/kvm"),
        "sev_snp_host": p("/sys/module/kvm_amd/parameters/sev_snp") in {"Y", "1"},
        "tdx_host": p("/sys/module/kvm_intel/parameters/tdx") in {"Y", "1"},
        "sev_snp_guest": os.path.exists("/dev/sev-guest"),
        "tdx_guest": os.path.exists("/dev/tdx_guest"),
        "is_vm_guest": "hypervisor" in read("/proc/cpuinfo"),
    }


def mount_of(path: str) -> dict:
    p = Path(path)
    while not p.exists() and p != p.parent:
        p = p.parent
    rc, out = sh(["findmnt", "-n", "-J", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS", "-T", str(p)])
    info: dict = {"path": path, "probe_path": str(p)}
    if rc == 0 and out.strip():
        fs = json.loads(out)["filesystems"][0]
        opts = fs.get("options", "")
        info.update({
            "mount": fs.get("target"), "source": fs.get("source"), "fstype": fs.get("fstype"),
            "options": opts,
            "xfs_pquota": fs.get("fstype") == "xfs" and bool(re.search(r"(prjquota|pquota|pqnoenforce)", opts)),
            "nodev": "nodev" in opts.split(","),
        })
    st = shutil.disk_usage(str(p))
    info.update({"total_bytes": st.total, "used_bytes": st.used, "free_bytes": st.free,
                 "used_pct": round(100.0 * st.used / st.total, 1) if st.total else None})
    return info


def docker_workloads(host: str | None) -> dict:
    """Committed and live resources of containers on one Docker daemon."""
    base = ["docker"] + (["-H", host] if host else [])
    rc, out = sh(base + ["ps", "-q"], timeout=30)
    if rc != 0:
        return {"daemon": host or "default", "reachable": False}
    ids = out.split()
    res = {"daemon": host or "default", "reachable": True, "running": len(ids),
           "cpu_limit_sum": 0.0, "mem_limit_sum_bytes": 0, "unlimited_cpu": 0, "unlimited_mem": 0,
           "mem_usage_sum_bytes": 0, "runtimes": {}}
    for i in range(0, len(ids), 50):
        rc, out = sh(base + ["inspect", "--format", "{{json .HostConfig}}"] + ids[i:i + 50], timeout=60)
        for line in out.splitlines():
            hc = json.loads(line)
            nano = hc.get("NanoCpus") or 0
            quota, period = hc.get("CpuQuota") or 0, hc.get("CpuPeriod") or 0
            cpus = nano / 1e9 if nano else (quota / period if quota and period else 0)
            if cpus:
                res["cpu_limit_sum"] += cpus
            else:
                res["unlimited_cpu"] += 1
            mem = hc.get("Memory") or 0
            if mem:
                res["mem_limit_sum_bytes"] += mem
            else:
                res["unlimited_mem"] += 1
            rt = hc.get("Runtime") or "runc"
            res["runtimes"][rt] = res["runtimes"].get(rt, 0) + 1
    # Live memory from the cgroup tree (cheaper than docker stats on many containers).
    for cid in ids:
        for cg in Path("/sys/fs/cgroup/system.slice").glob(f"docker-{cid}*.scope"):
            try:
                res["mem_usage_sum_bytes"] += int((cg / "memory.current").read_text())
            except (OSError, ValueError):
                pass
    res["cpu_limit_sum"] = round(res["cpu_limit_sum"], 2)
    return res


def vms() -> dict:
    rc, out = sh(["ps", "-eo", "rss=,args="])
    found = []
    for line in out.splitlines():
        if re.search(r"qemu-system|firecracker|cloud-hypervisor", line):
            rss, _, args = line.strip().partition(" ")
            smp = re.search(r"-smp\s+(?:cpus=)?(\d+)", args)
            mem = re.search(r"-m\s+(?:size=)?(\d+)([MGmg]?)", args)
            mem_b = 0
            if mem:
                n, unit = int(mem.group(1)), mem.group(2).upper()
                mem_b = n * (1 << 30) if unit == "G" else n * (1 << 20)
            name = re.search(r"-name\s+(?:guest=)?([^\s,]+)", args)
            found.append({"vcpus": int(smp.group(1)) if smp else 1, "mem_bytes": mem_b, "rss_bytes": int(rss) * 1024,
                          "cmd": args.split()[0], "name": name.group(1) if name else None,
                          # A sealed hotel guest (room kit --sealed) names itself sealed-<hotel>.
                          "sealed_hotel": bool(name and name.group(1).startswith("sealed-"))})
    sealed = [v for v in found if v["sealed_hotel"]]
    return {"count": len(found), "vcpus_sum": sum(v["vcpus"] for v in found),
            "mem_sum_bytes": sum(v["mem_bytes"] for v in found), "items": found,
            "sealed_hotel_count": len(sealed), "sealed_hotel_vcpus_sum": sum(v["vcpus"] for v in sealed),
            "sealed_hotel_mem_sum_bytes": sum(v["mem_bytes"] for v in sealed)}


def ports() -> list[dict]:
    rc, out = sh(["ss", "-H", "-ltn"])
    seen = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            addr = parts[3]
            host, _, port = addr.rpartition(":")
            seen.append({"addr": host, "port": int(port)})
    return sorted({(p["addr"], p["port"]): p for p in seen}.values(), key=lambda p: p["port"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="/srv")
    ap.add_argument("--room-socket", default="")
    ap.add_argument("--out", default="-")
    a = ap.parse_args()
    mi = meminfo()
    machine = {
        "assessed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hostname": socket.gethostname(),
        "os": dict(re.findall(r'^(PRETTY_NAME|VERSION_ID)="?([^"\n]*)"?', read("/etc/os-release"), re.M)),
        "kernel": platform.release(),
        "cpu": cpu(),
        "memory": {"total_bytes": mi.get("MemTotal", 0), "available_bytes": mi.get("MemAvailable", 0),
                   # Reserved hugepages (e.g. Firecracker hosts) are not available to sandboxes.
                   "hugepages_reserved_bytes": mi.get("HugePages_Total", 0) // 1024 * mi.get("Hugepagesize", 0),
                   "used_pct": round(100 * (1 - mi.get("MemAvailable", 0) / max(mi.get("MemTotal", 1), 1)), 1)},
        "cgroup_v2": os.path.exists("/sys/fs/cgroup/cgroup.controllers"),
        "tee": tee(),
        "data_dir": mount_of(a.data_dir),
        "root_fs": mount_of("/"),
        "workloads": {
            "host_docker": docker_workloads(None) if shutil.which("docker") else {"reachable": False},
            "room_docker": docker_workloads(f"unix://{a.room_socket}") if a.room_socket and os.path.exists(a.room_socket) else None,
            "vms": vms(),
        },
        "listening_ports": ports(),
        "tools": {t: bool(shutil.which(t)) for t in ["docker", "dockerd", "containerd", "mkfs.xfs", "losetup", "iptables", "ufw"]},
    }
    text = json.dumps(machine, indent=2, sort_keys=True)
    if a.out == "-":
        print(text)
    else:
        Path(a.out).write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
