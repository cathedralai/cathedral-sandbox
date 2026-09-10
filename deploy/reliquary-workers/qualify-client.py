#!/usr/bin/env python3
"""Run the pinned customer load and attack checks through its local adapter.

This records client-path evidence. It never promotes an allocation or reports
the remaining host, overload, reset and real-grader checks as passed.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

REVISION = "0be0cda0c9a73dc3f08e3af2a07dda9407635aa7"
REMAINING = [
    "host_exclusivity_and_cpu_ram_inventory", "observed_50_slot_occupancy",
    "bounded_overload_at_64_callers", "reset_and_leftovers_under_saturation",
    "network_and_metadata_denial_below_python_policy", "memory_and_output_limits",
    "maximum_batch_deadline", "disconnect_restart_and_replica_fenced_drain",
    "real_grader_shadow_accounting_and_customer_corpus",
]


def validate_health(data: dict, allocation_id: str, runtime_id: str) -> None:
    pool, api = data["pool"], data["api"]
    if (data.get("status") != "ok" or data.get("protocol_version") != 2
            or data.get("executor_id") != allocation_id or data.get("runtime_id") != runtime_id
            or data.get("sandbox_backend") != "runsc"
            or data.get("sandbox_platform") not in ("kvm", "systrap")
            or pool.get("retire_worker_after_batch") is not True):
        raise ValueError("executor identity or isolation configuration mismatch")
    for value in (pool.get("pool_size"), pool.get("workers_alive"), api.get("max_inflight")):
        if type(value) is not int or value != 50:
            raise ValueError("the trial requires 50 configured healthy slots")
    for name in ("worker_reap_failures_total", "container_delete_failures_total"):
        value = pool.get(name)
        if type(value) is not int or value != 0:
            raise ValueError("cleanup counters must be present and zero")


def validate_load(data: dict, count: int, parallel: int, runtime_id: str, maximum: float) -> None:
    for key, expected in (("requests", count), ("successful", count), ("parallel", parallel)):
        if type(data.get(key)) is not int or data[key] != expected:
            raise ValueError("load report has incomplete request accounting")
    if data.get("failures") != [] or data.get("runtime_id") != runtime_id:
        raise ValueError("load report failed or changed runtime")
    for key in ("p50", "p95", "p99", "max"):
        value = data["latency_ms"][key]
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError("invalid measured latency")
    if data["latency_ms"]["p95"] > maximum:
        raise ValueError("p95 exceeded the acceptance threshold")


def run_case(command: list[str], source: Path, output: Path, name: str, timeout: int) -> tuple[dict, dict]:
    started = time.monotonic()
    with (output / f"{name}.stdout").open("w") as stdout, (output / f"{name}.stderr").open("w") as stderr:
        try:
            result = subprocess.run(command, cwd=source, stdout=stdout, stderr=stderr,
                                    env={**os.environ, "PYTHONPATH": str(source)},
                                    timeout=timeout, check=False)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
    record = {"check": name, "returncode": code, "elapsed_seconds": time.monotonic() - started,
              "status": "PASS" if code == 0 else "FAIL"}
    try:
        # Upstream emits a single JSON report after any diagnostic output.
        lines = (output / f"{name}.stdout").read_text().strip().splitlines()
        data = json.loads(lines[-1])
        if not isinstance(data, dict):
            raise ValueError("report is not an object")
    except (ValueError, IndexError):
        data = {}
        record["status"] = "FAIL"
        record["reason"] = "missing_or_invalid_report"
    return record, data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New private evidence directory")
    parser.add_argument("--allocation-id", required=True)
    parser.add_argument("--runtime-id", required=True)
    parser.add_argument("--requests", type=int, default=3000)
    parser.add_argument("--soak-requests", type=int, default=10000)
    parser.add_argument("--max-p95-ms", type=float, default=1000)
    parser.add_argument("--confirm-dedicated-host", action="store_true")
    args = parser.parse_args()
    if not args.confirm_dedicated_host:
        parser.error("confirm this adapter is assigned only to the disposable dedicated trial host")
    if not 3000 <= args.requests <= 20000 or not 10000 <= args.soak_requests <= 100000:
        parser.error("use at least 3000 load requests and 10000 soak requests within the bounded limits")
    if not math.isfinite(args.max_p95_ms) or not 0 < args.max_p95_ms <= 1000:
        parser.error("p95 must be at most the customer's 1000 ms threshold")
    endpoint = os.environ.get("RELIQUARY_GRADER_EXECUTOR_URL", "")
    url = urlsplit(endpoint)
    try:
        loopback = ipaddress.ip_address(url.hostname or "").is_loopback
        port = url.port
    except ValueError:
        loopback, port = False, None
    if (url.scheme != "https" or not loopback or not port or url.username or url.password
            or url.path not in ("", "/") or url.query or url.fragment):
        parser.error("source the separate adapter environment with its HTTPS loopback origin")
    source = args.source.resolve()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True)
    if revision != REVISION or dirty:
        parser.error("source must be the clean pinned Reliquary revision")
    scripts = {name: source / "scripts" / f"{name}_cpu_executor.py" for name in ("load_test", "attack_test")}
    hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in scripts.items()}
    tls_args = []
    credentials = {}
    for flag, suffix in (("--ca", "CA"), ("--cert", "CERT"), ("--key", "KEY")):
        path = Path(os.environ.get(f"RELIQUARY_GRADER_EXECUTOR_{suffix}", ""))
        if not path.is_absolute() or not path.is_file():
            parser.error("adapter certificate paths must be existing absolute paths")
        tls_args.extend((flag, str(path)))
        credentials[suffix] = str(path)
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {"source_revision": revision, "script_sha256": hashes, "allocation_id": args.allocation_id,
              "runtime_id": args.runtime_id, "client_checks": [], "client_path": "NOT_RUN",
              "trial_delivery": "NOT_PROVEN", "remaining": REMAINING}

    def save():
        (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")

    save()
    try:
        import httpx
        tls = ssl.create_default_context(cafile=credentials["CA"])
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(credentials["CERT"], credentials["KEY"])
        with httpx.Client(verify=tls, trust_env=False, follow_redirects=False, timeout=10) as client:
            response = client.get(endpoint.rstrip("/") + "/v1/health")
            response.raise_for_status()
            health = response.json()
        validate_health(health, args.allocation_id, args.runtime_id)
        (args.output / "health-before.json").write_text(json.dumps(health, indent=2) + "\n")
        for name, count, parallel in (("load-32", args.requests, 32), ("load-50", args.requests, 50),
                                     ("soak-50", args.soak_requests, 50)):
            command = [sys.executable, str(scripts["load_test"]), endpoint, *tls_args,
                       "--requests", str(count), "--parallel", str(parallel), "--max-p95-ms", str(args.max_p95_ms)]
            record, data = run_case(command, source, args.output, name, max(300, math.ceil(count * 10 / parallel)))
            try:
                validate_load(data, count, parallel, args.runtime_id, args.max_p95_ms)
            except (ValueError, KeyError, TypeError):
                record["status"] = "FAIL"
                record["reason"] = "load_acceptance_failed"
            record["report"] = data
            report["client_checks"].append(record)
            save()
            if record["status"] != "PASS":
                raise ValueError("load acceptance failed; stop before further host stress")
        command = [sys.executable, str(scripts["attack_test"]), endpoint, *tls_args, "--confirm-dedicated-host"]
        record, data = run_case(command, source, args.output, "attack-corpus", 180)
        record["report"] = data
        report["client_checks"].append(record)
        if data.get("status") != "passed":
            record["status"] = "FAIL"
        else:
            try:
                validate_health(data["health"], args.allocation_id, args.runtime_id)
            except (ValueError, KeyError, TypeError):
                record["status"] = "FAIL"
                record["reason"] = "post_attack_health_failed"
        report["client_path"] = "PASS" if record["status"] == "PASS" else "FAIL"
    except Exception as exc:
        report["client_path"] = "FAIL"
        report["failure_type"] = type(exc).__name__
    finally:
        save()
    print(args.output / "summary.json")
    return 0 if report["client_path"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
