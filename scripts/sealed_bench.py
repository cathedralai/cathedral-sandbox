#!/usr/bin/env python3
"""One sealed benchmark run, one receipt chain (AB#444, slice 1).

Creates ONE sealed sandbox through the customer API, runs a fixed prompt set
inside it with the image's own `lfm3-ask` (which prints a `lfm3-timing` line),
fetches the sandbox evidence bundle, deletes the sandbox, and writes a JSON
result.

How the result is bound to a signed receipt: Cathedral's exec receipt carries
stdout_sha256 of the exact stdout bytes, and the room's guest signs the
command_sha256. This script saves each run's stdout byte for byte, finds the
Cathedral receipt whose stdout_sha256 matches, and records its number. Anyone
can then check a run with:

    ctcli receipt verify --bundle <bundle> --stdout <n>=<run stdout file>

The numbers are only as good as that check: a run with no matching receipt is
written with "receipt_n": null and the script exits 3.

Not in this slice: time to first token (needs an in-image harness, so a
re-seal), image digest / model sha256 inside a signed statement, a signed
summary of the whole run. See ab444-plan.md.

Usage:
  CATHEDRAL_API_KEY=... sealed_bench.py --image ghcr.io/cathedralai/room-lfm3-omni-2b@sha256:<64 hex> \
      --template sealed-2x4 --prompts bench/prompts.json --out-dir out/ [--runs 3]
Env: CATHEDRAL_API_URL (default https://cathedral.computer), CTCLI (default ctcli).
Exit: 0 all runs bound to a receipt, 1 failure, 2 bad usage, 3 ran but a run has no matching receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

HARNESS_VERSION = "sealed-bench-1"
DIGEST_IMAGE = re.compile(r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
TIMING = re.compile(r"^lfm3-timing (.*)$", re.M)
EXEC_TIMEOUT_SECONDS = 45  # the API cuts a longer foreground exec off
EXEC_ACTIONS = {"sandbox.exec", "exec"}


class BenchError(Exception):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Api:
    def __init__(self, base: str, key: str, timeout: int = 120):
        self.base, self.key, self.timeout = base.rstrip("/"), key, timeout

    def call(self, method: str, path: str, body: dict | None = None, idem: str | None = None, timeout: int | None = None):
        headers = {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"}
        if idem:
            headers["Idempotency-Key"] = idem
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise BenchError(f"{method} {path} failed: HTTP {exc.code}") from exc
        except OSError as exc:
            raise BenchError(f"{method} {path} failed: {exc}") from exc
        return json.loads(raw) if raw else {}


def parse_timing(stdout: str) -> dict:
    """The `lfm3-timing k=v ...` line lfm3-ask prints last. Numbers become numbers."""
    found = TIMING.findall(stdout)
    if not found:
        raise BenchError("no lfm3-timing line in the output")
    fields = {}
    for pair in found[-1].split():
        name, _, value = pair.partition("=")
        try:
            fields[name] = float(value) if "." in value else int(value)
        except ValueError:
            fields[name] = value
    for needed in ("prompt_tok_s", "gen_tok_s", "wall_ms"):
        if not isinstance(fields.get(needed), (int, float)):
            raise BenchError(f"lfm3-timing has no usable {needed}")
    return fields


def find_receipt_n(bundle: dict, stdout_bytes: bytes) -> int | None:
    want = sha256_hex(stdout_bytes)
    receipts = (bundle.get("cathedral_receipts") or {}).get("receipts") or []
    for doc in receipts:
        if isinstance(doc, dict) and doc.get("action") in EXEC_ACTIONS and doc.get("stdout_sha256") == want \
                and isinstance(doc.get("n"), int):
            return doc["n"]
    return None


def run(args, api: Api, ctcli: list[str]) -> tuple[dict, int]:
    prompts_bytes = Path(args.prompts).read_bytes()
    prompts = json.loads(prompts_bytes)
    if not isinstance(prompts, list) or not prompts or not all(isinstance(p, str) and p for p in prompts):
        raise BenchError("--prompts must be a JSON array of non-empty strings")
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:12]
    result = {
        "schema": "cathedral_sealed_bench_v1", "harness_version": HARNESS_VERSION, "run_id": run_id,
        "image": args.image, "template": args.template,
        "prompt_set_sha256": sha256_hex(prompts_bytes), "max_tokens": args.max_tokens,
        "sandbox_id": None, "runs": [], "bundle_path": None, "deleted": False, "error": None,
    }
    sandbox_id = None
    try:
        created = api.call("POST", "/v1/sandboxes", {
            "image": args.image, "template": args.template, "required_hardware": "amd_sev_snp",
            "network": "deny_all", "lifetime_seconds": args.lifetime_seconds,
            "max_spend_usd": args.max_spend_usd, "labels": {"bench": "ab444", "run": run_id},
        }, idem=f"bench-create-{run_id}")
        sandbox_id = created.get("id")
        if not isinstance(sandbox_id, str):
            raise BenchError("create returned no sandbox id")
        result["sandbox_id"] = sandbox_id
        deadline = time.monotonic() + args.ready_timeout
        state = created.get("state")
        while state != "running":
            if state in ("failed", "deleted", "deleting") or time.monotonic() > deadline:
                raise BenchError(f"sandbox did not reach running (state {state})")
            time.sleep(args.poll_seconds)
            state = api.call("GET", f"/v1/sandboxes/{sandbox_id}").get("state")
        result["create_to_running_s"] = round(time.monotonic() - (deadline - args.ready_timeout), 3)

        stdouts: list[bytes] = []
        for rep in range(args.runs):
            for index, prompt in enumerate(prompts):
                command = ["lfm3-ask", prompt]
                started = time.monotonic()
                answer = api.call("POST", f"/v1/sandboxes/{sandbox_id}/exec", {
                    "command": command, "timeout_seconds": EXEC_TIMEOUT_SECONDS,
                    "env": {"LFM3_MAX_TOKENS": str(args.max_tokens)},
                }, idem=f"bench-exec-{run_id}-{rep}-{index}", timeout=EXEC_TIMEOUT_SECONDS + 30)
                if answer.get("exit_code") != 0 or not isinstance(answer.get("stdout"), str):
                    raise BenchError(f"exec {rep}/{index} failed (exit {answer.get('exit_code')})")
                raw = answer["stdout"].encode()
                path = out_dir / f"{run_id}-run{rep}-{index}.stdout"
                path.write_bytes(raw)
                stdouts.append(raw)
                timing = parse_timing(answer["stdout"])
                result["runs"].append({
                    "rep": rep, "prompt_index": index, "wall_s": round(time.monotonic() - started, 3),
                    "prompt_tok_s": timing["prompt_tok_s"], "decode_tok_s": timing["gen_tok_s"],
                    "model_wall_ms": timing["wall_ms"], "load_ms": timing.get("load_ms"),
                    "threads": timing.get("threads"), "stdout_file": str(path),
                    "stdout_sha256": sha256_hex(raw), "command_sha256": sha256_hex(
                        json.dumps(command, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()),
                    "room_receipt_id": answer.get("room_receipt_id"), "receipt_n": None,
                })

        # The bundle is fetched before delete: a deleted room's evidence is not guaranteed.
        bundle_path = out_dir / f"{run_id}-bundle.json"
        done = subprocess.run([*ctcli, "sandbox", "evidence", sandbox_id, "-o", str(bundle_path), "--force"],
                              capture_output=True, text=True, timeout=300)
        if done.returncode != 0:
            raise BenchError("ctcli sandbox evidence failed: " + (done.stderr or "").strip()[:200])
        result["bundle_path"] = str(bundle_path)
        bundle = json.loads(bundle_path.read_text())
        for entry, raw in zip(result["runs"], stdouts):
            entry["receipt_n"] = find_receipt_n(bundle, raw)
    except BenchError as exc:
        result["error"] = str(exc)
    finally:
        if sandbox_id:
            try:
                api.call("DELETE", f"/v1/sandboxes/{sandbox_id}", idem=f"bench-delete-{run_id}")
                result["deleted"] = True
            except BenchError as exc:
                result["error"] = (result["error"] + "; " if result["error"] else "") + str(exc)
    unbound = any(r["receipt_n"] is None for r in result["runs"])
    code = 1 if result["error"] or not result["runs"] else 3 if unbound else 0
    (out_dir / f"{run_id}-result.json").write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
    return result, code


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--image", required=True, help="room image pinned by digest (name@sha256:...)")
    p.add_argument("--template", default="sealed-2x4")
    p.add_argument("--prompts", required=True, help="JSON array of prompt strings")
    p.add_argument("--out-dir", required=True)
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--max-tokens", type=int, default=256)
    p.add_argument("--lifetime-seconds", type=int, default=900)
    p.add_argument("--max-spend-usd", default="0.50")
    p.add_argument("--ready-timeout", type=int, default=300)
    p.add_argument("--poll-seconds", type=float, default=3.0)
    args = p.parse_args(argv)
    if not DIGEST_IMAGE.match(args.image) or args.runs < 1:
        print("--image must be name@sha256:<64 hex> (never a tag) and --runs at least 1", file=sys.stderr)
        return 2
    key = os.environ.get("CATHEDRAL_API_KEY")
    if not key:
        print("set CATHEDRAL_API_KEY", file=sys.stderr)
        return 2
    api = Api(os.environ.get("CATHEDRAL_API_URL", "https://cathedral.computer"), key)
    try:
        result, code = run(args, api, os.environ.get("CTCLI", "ctcli").split())
    except BenchError as exc:
        print(f"sealed_bench: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"result": str(Path(args.out_dir) / f"{result['run_id']}-result.json"),
                      "bundle": result["bundle_path"], "sandbox_id": result["sandbox_id"],
                      "deleted": result["deleted"], "error": result["error"]}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
