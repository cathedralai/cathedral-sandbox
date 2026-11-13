#!/usr/bin/env python3
"""Pinned restic against a Hippius S3 bucket, timed, one JSON result (AB#394).

Run it once from each hotel region. It answers the measurable half of the
Hippius due diligence in docs/HIPPIUS_DUE_DILIGENCE.md: latency, throughput,
restic compatibility and deletion through restic.

Steps, each timed, in order; the first failure skips the rest:
  init       restic init on a fresh per-run prefix <bucket>/ab394-<uuid>
  backup     back up --size-mib of random data; MiB/s from the summary line
  latency    --latency-runs x `restic --no-cache cat config`; median and p95
  check      restic check --read-data (every pack downloaded and verified)
  restore    restore the snapshot and compare sha256 with the source
  delete     forget --prune every snapshot; raw-data bytes before and after
Cleanup (the delete step) still runs when a step after init fails.

Credentials reach restic only through the environment, never argv or output.
restic leaves `config`, `keys/` and empty dirs under the prefix after prune;
remove the prefix by hand after the run.

Usage:
  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... RESTIC_PASSWORD=... \
  hippius_restic_bench.py --bucket <bucket> --hotel-region <label> --out result.json \
      [--endpoint https://s3.hippius.com] [--size-mib 256] [--latency-runs 10] [--connections 5]
Env: RESTIC (default restic).
Exit: 0 every step ok, 1 a step failed (partial JSON still written), 2 bad usage or
restic is not the pinned version.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

PINNED_RESTIC = "0.19.1"
DEFAULT_ENDPOINT = "https://s3.hippius.com"
# Hippius S3 serves path-style only, region "decentralized".
HIPPIUS_REGION = "decentralized"
REQUIRED_ENV = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "RESTIC_PASSWORD")
STEPS = ("init", "backup", "latency", "check", "restore", "delete")
CHUNK = 4 * 1024 * 1024
MIB = 1024 * 1024


class StepFailed(Exception):
    pass


def restic_version(restic: list[str]) -> str | None:
    try:
        out = subprocess.run(restic + ["version", "--json"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout.strip().splitlines()[-1]).get("version")
    except (ValueError, IndexError, AttributeError):
        return None


def write_random(path: Path, size_mib: int) -> str:
    digest = hashlib.sha256()
    with path.open("wb") as f:
        left = size_mib * MIB
        while left:
            block = os.urandom(min(CHUNK, left))
            digest.update(block)
            f.write(block)
            left -= len(block)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))]


class Bench:
    def __init__(self, args: argparse.Namespace, restic: list[str], work: Path):
        self.args = args
        self.work = work
        self.prefix = f"ab394-{uuid.uuid4().hex[:12]}"
        repo = f"s3:{args.endpoint.rstrip('/')}/{args.bucket}/{self.prefix}"
        self.base = restic + [
            "-r", repo,
            "-o", "s3.bucket-lookup=path",
            "-o", f"s3.region={HIPPIUS_REGION}",
            "-o", f"s3.connections={args.connections}",
            "--cache-dir", str(work / "cache"),
        ]
        self.snapshots: list[str] = []

    def restic(self, *cmd: str, cwd: Path | None = None, no_cache: bool = False) -> str:
        argv = self.base + (["--no-cache"] if no_cache else []) + list(cmd)
        out = subprocess.run(argv, capture_output=True, text=True, cwd=cwd)
        if out.returncode != 0:
            # restic's stderr carries no credentials; keep the tail for the result.
            raise StepFailed(f"restic {cmd[0]} exit {out.returncode}: {out.stderr.strip()[-400:]}")
        return out.stdout

    def raw_bytes(self) -> int:
        doc = json.loads(self.restic("stats", "--mode", "raw-data", "--json").strip().splitlines()[-1])
        return int(doc.get("total_size", 0))

    def step_init(self) -> dict:
        self.restic("init")
        return {}

    def step_backup(self) -> dict:
        src = self.work / "src"
        src.mkdir()
        self.source_sha = write_random(src / "data.bin", self.args.size_mib)
        started = time.monotonic()
        stdout = self.restic("backup", "--json", "data.bin", cwd=src)
        seconds = time.monotonic() - started
        summary = None
        for line in stdout.splitlines():
            try:
                doc = json.loads(line)
            except ValueError:
                continue
            if doc.get("message_type") == "summary":
                summary = doc
        if not summary or not summary.get("snapshot_id"):
            raise StepFailed("backup printed no summary line with a snapshot_id")
        self.snapshots.append(summary["snapshot_id"])
        processed = int(summary.get("total_bytes_processed", 0))
        return {
            "snapshot_id": summary["snapshot_id"],
            "bytes_processed": processed,
            "data_added": summary.get("data_added"),
            "mib_s": round(processed / MIB / seconds, 2) if seconds > 0 else None,
        }

    def step_latency(self) -> dict:
        samples = []
        for _ in range(self.args.latency_runs):
            started = time.monotonic()
            self.restic("cat", "config", no_cache=True)
            samples.append(time.monotonic() - started)
        return {
            "runs": len(samples),
            "median_ms": round(statistics.median(samples) * 1000, 1),
            "p95_ms": round(p95(samples) * 1000, 1),
        }

    def step_check(self) -> dict:
        self.restic("check", "--read-data")
        return {}

    def step_restore(self) -> dict:
        target = self.work / "restore"
        started = time.monotonic()
        self.restic("restore", self.snapshots[-1], "--target", str(target))
        seconds = time.monotonic() - started
        restored = target / "data.bin"
        match = restored.is_file() and sha256_file(restored) == self.source_sha
        if not match:
            raise StepFailed("restored data.bin does not match the source sha256")
        return {"sha256_match": True, "mib_s": round(self.args.size_mib / seconds, 2) if seconds > 0 else None}

    def step_delete(self) -> dict:
        before = self.raw_bytes()
        if self.snapshots:
            self.restic("forget", "--prune", *self.snapshots)
        after = self.raw_bytes()
        return {"raw_bytes_before": before, "raw_bytes_after": after}


def run(args: argparse.Namespace, restic: list[str], work: Path) -> tuple[dict, int]:
    bench = Bench(args, restic, work)
    result = {
        "card": "AB#394",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "restic_version": PINNED_RESTIC,
        "endpoint": args.endpoint,
        "bucket": args.bucket,
        "prefix": bench.prefix,
        "hotel_region": args.hotel_region,
        "size_mib": args.size_mib,
        "s3_connections": args.connections,
        "steps": {},
    }
    failed = False
    for name in STEPS:
        # Cleanup runs even after a failure, as long as the repo exists.
        if failed and not (name == "delete" and result["steps"].get("init", {}).get("ok")):
            result["steps"][name] = {"ok": False, "skipped": True}
            continue
        started = time.monotonic()
        try:
            detail = getattr(bench, f"step_{name}")()
            result["steps"][name] = {"ok": True, "seconds": round(time.monotonic() - started, 3), **detail}
        except (StepFailed, ValueError, OSError) as exc:
            result["steps"][name] = {"ok": False, "seconds": round(time.monotonic() - started, 3), "error": str(exc)}
            failed = True
    return result, 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--hotel-region", required=True, help="neutral label, e.g. region-a")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--size-mib", type=int, default=256)
    parser.add_argument("--latency-runs", type=int, default=10)
    parser.add_argument("--connections", type=int, default=5)
    args = parser.parse_args(argv)
    if args.size_mib < 1 or args.latency_runs < 1 or args.connections < 1:
        print("--size-mib, --latency-runs and --connections must be at least 1", file=sys.stderr)
        return 2
    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        print(f"missing env: {', '.join(missing)}", file=sys.stderr)
        return 2
    restic = os.environ.get("RESTIC", "restic").split()
    version = restic_version(restic)
    if version != PINNED_RESTIC:
        print(f"restic {version or 'not found'} is not the pinned {PINNED_RESTIC}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="ab394-") as tmp:
        result, code = run(args, restic, Path(tmp))
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({name: step.get("ok") for name, step in result["steps"].items()}))
    return code


if __name__ == "__main__":
    sys.exit(main())
