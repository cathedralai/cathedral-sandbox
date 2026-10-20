#!/usr/bin/env python3
"""Room kit: health. One read-only endpoint the front desk polls.

GET /room/health (Bearer = the room API key) returns:
room id, API profile, runtime, kernel isolation proof, machine summary,
slots, sandboxes running, free slots, live host memory and disk use.

The server binds 127.0.0.1 only. Caddy exposes it on 443 at /room/health.
`room_health.py --once` prints the same JSON and exits (a CLI health command).
"""
from __future__ import annotations

import hmac
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ETC = Path(os.environ.get("ROOM_ETC", "/etc/pool-room"))
SOCK = os.environ["ROOM_DOCKER_SOCK"]
DOCKER = ["docker", "-H", f"unix://{SOCK}"]
PROBE_IMAGE = os.environ.get("ROOM_PROBE_IMAGE", "alpine:3.20")
_probe: dict = {}
_lock = threading.Lock()
# Live numbers sampled in the background, so a busy room daemon never makes
# the health call slow: host CPU busy % (1 s window), load, room containers.
_live: dict = {"cpu_pct": None, "containers": None, "containers_at": None}


def run(argv: list[str], timeout: float = 60) -> tuple[int, str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def isolation_probe() -> dict:
    """Start one throwaway guest and compare its kernel with the host kernel."""
    rc, info = run(DOCKER + ["info", "--format", "{{.DefaultRuntime}}"])
    rc2, guest = run(DOCKER + ["run", "--rm", "--network", "none", PROBE_IMAGE, "uname", "-r"], timeout=120)
    rc3, dmesg = run(DOCKER + ["run", "--rm", "--network", "none", PROBE_IMAGE, "dmesg"], timeout=120)
    host = os.uname().release
    gvisor = rc3 == 0 and "gVisor" in dmesg
    return {
        "default_runtime": info if rc == 0 else None,
        "guest_kernel": guest if rc2 == 0 else None,
        "host_kernel": host,
        "guest_dmesg_says_gvisor": gvisor,
        "kernel_isolation": bool(rc2 == 0 and guest and guest != host and gvisor),
        "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def refresh_probe_loop() -> None:
    while True:
        result = isolation_probe()
        with _lock:
            _probe.clear()
            _probe.update(result)
        time.sleep(600)


def _cpu_times() -> tuple[int, int]:
    f = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
    idle = f[3] + (f[4] if len(f) > 4 else 0)
    return sum(f), idle


def cpu_loop() -> None:
    prev = _cpu_times()
    while True:
        time.sleep(1)
        cur = _cpu_times()
        total, idle = cur[0] - prev[0], cur[1] - prev[1]
        prev = cur
        if total > 0:
            with _lock:
                _live["cpu_pct"] = round(100.0 * (total - idle) / total, 1)


def containers_loop() -> None:
    while True:
        rc, out = run(DOCKER + ["ps", "-q"], timeout=30)
        with _lock:
            _live["containers"] = len(out.split()) if rc == 0 else None
            _live["containers_at"] = time.time()
        time.sleep(2)


def meminfo() -> dict[str, int]:
    out = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        k, _, v = line.partition(":")
        out[k] = int(v.split()[0]) * 1024
    return out


def document() -> dict:
    env = dict(line.split("=", 1) for line in (ETC / "room.env").read_text().splitlines()
               if "=" in line and not line.lstrip().startswith("#"))
    env = {k: v.strip().strip('"') for k, v in env.items()}
    machine = json.loads((ETC / "machine.json").read_text())
    size = json.loads((ETC / "size.json").read_text())
    with _lock:
        live = dict(_live)
    if live["containers_at"] is None:
        rc, out = run(DOCKER + ["ps", "-q"])
        live["containers"] = len(out.split()) if rc == 0 else None
    running = live["containers"]
    mi = meminfo()
    data_dir = env.get("ROOM_DATA_DIR", "/")
    du = shutil.disk_usage(data_dir)
    root = shutil.disk_usage("/")
    with _lock:
        probe = dict(_probe)
    return {
        "room_id": env.get("ROOM_ID"),
        "customer": env.get("ROOM_CUSTOMER"),
        "api_profile": env.get("API_PROFILE"),
        "hostname": env.get("ROOM_HOSTNAME"),
        "runtime": "runsc" if probe.get("default_runtime") == "runsc" else probe.get("default_runtime"),
        "kernel_isolation": probe.get("kernel_isolation"),
        "isolation_probe": probe,
        "machine": {
            "cpu_model": machine["cpu"]["model"], "threads": machine["cpu"]["threads"],
            "ram_gib": round(machine["memory"]["total_bytes"] / 2**30, 1),
            "kernel": machine["kernel"], "os": machine["os"].get("PRETTY_NAME"),
            "tee": machine["tee"], "assessed_at": machine["assessed_at"],
            "other_workloads": size["already_used"],
        },
        "shape": size["shape"],
        "slots": size["slots"],
        "limiting": size["limiting"],
        "slots_by_resource": size["slots_by_resource"],
        "sandboxes_running": running,
        "free_slots": None if running is None else max(size["slots"] - running, 0),
        "live": {
            "host_mem_used_pct": round(100 * (1 - mi["MemAvailable"] / mi["MemTotal"]), 1),
            "host_mem_used_gib": round((mi["MemTotal"] - mi["MemAvailable"]) / 2**30, 1),
            "host_cpu_pct": live["cpu_pct"],
            "load1": round(os.getloadavg()[0], 1),
            "room_data_used_pct": round(100 * du.used / du.total, 1),
            "host_root_used_pct": round(100 * root.used / root.total, 1),
        },
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def load_key() -> str:
    raw = Path(os.environ.get("ROOM_KEY_FILE", str(ETC / "api.key"))).read_text().strip()
    return raw


class Handler(BaseHTTPRequestHandler):
    key = ""

    def log_message(self, fmt, *args):  # no request logging (no secrets in logs)
        return

    def do_GET(self):
        if self.path.split("?")[0] != "/room/health":
            return self._send(404, {"error": {"code": "not_found"}})
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        if not hmac.compare_digest(token.encode(), self.key.encode()):
            return self._send(401, {"error": {"code": "unauthorized"}})
        self._send(200, document())

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    if "--once" in sys.argv:
        _probe.update(isolation_probe())
        print(json.dumps(document(), indent=2, sort_keys=True))
        return 0
    Handler.key = load_key()
    threading.Thread(target=refresh_probe_loop, daemon=True).start()
    threading.Thread(target=cpu_loop, daemon=True).start()
    threading.Thread(target=containers_loop, daemon=True).start()
    port = int(os.environ.get("ROOM_HEALTH_PORT", "18091"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
