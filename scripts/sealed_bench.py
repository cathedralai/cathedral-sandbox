#!/usr/bin/env python3
"""One sealed benchmark run, one receipt chain (AB#444, slice 1).

Creates ONE sealed sandbox through the customer API, runs a fixed prompt set
inside it with the image's own `lfm3-ask` (which prints a `lfm3-timing` line),
fetches the sandbox evidence bundle, deletes the sandbox, and writes a JSON
result.

How the result is bound to a signed receipt: Cathedral's exec receipt carries
stdout_sha256 of the exact stdout bytes, and the room's guest signs the
command_sha256. This script saves each run's stdout byte for byte, finds the
Cathedral receipt whose stdout_sha256 matches, and records its number. Each receipt
is used for at most one run, and must carry the same command hash as the run.
Before exit 0 the script itself runs the offline check:

    ctcli receipt verify --bundle <bundle> --json --require-outputs \
        --cathedral-key <hex> --expected-measurement <96 hex> --stdout <n>=<file> ...

and requires PASS. The Cathedral key (or a trusted keys file) and the guest
measurement are required flags: with no pins there is nothing to verify against,
so the script refuses to start (exit 2) rather than report unverified numbers.
A run with no matching receipt is written with "receipt_n": null (exit 3). A
verify verdict other than PASS is an error (exit 1) and the result says why.

Not in this slice: time to first token (needs an in-image harness, so a
re-seal), image digest / model sha256 inside a signed statement, a signed
summary of the whole run. See ab444-plan.md.

Usage:
  CATHEDRAL_API_KEY=... sealed_bench.py --image ghcr.io/cathedralai/room-lfm3-omni-2b@sha256:<64 hex> \
      --template sealed-2x4 --prompts bench/prompts.json --out-dir out/ [--runs 3] \
      --cathedral-key <hex> --expected-measurement <96 hex>
Env: CATHEDRAL_API_URL (default https://cathedral.computer), CTCLI (default ctcli).
Exit: 0 all runs bound to a receipt and the offline verify PASSed, 1 failure, 2 bad usage,
3 ran but a run has no matching receipt.
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
EXEC_ACTIONS = {"sandbox.exec", "sandbox.exec.finish", "exec"}
USER_AGENT = "cathedral-sealed-bench/1.0"


class BenchError(Exception):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Api:
    def __init__(self, base: str, key: str, timeout: int = 120):
        self.base, self.key, self.timeout = base.rstrip("/"), key, timeout

    def call(self, method: str, path: str, body: dict | None = None, idem: str | None = None, timeout: int | None = None):
        # The public edge refuses urllib's default User-Agent.
        headers = {"Authorization": f"Bearer {self.key}", "Content-Type": "application/json",
                   "User-Agent": USER_AGENT}
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


def command_sha256(command: list[str]) -> str:
    return sha256_hex(json.dumps(command, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def find_receipt_n(bundle: dict, stdout_bytes: bytes, command_hash: str, used: set[int]) -> int | None:
    """The lowest unused exec receipt with this stdout hash AND this command hash.

    A finish receipt has no command of its own: it takes it from its start receipt (exec_id).
    A receipt with no command hash never matches, and a receipt number is returned once,
    so two identical outputs map to two different receipts.
    """
    want = sha256_hex(stdout_bytes)
    receipts = [d for d in ((bundle.get("cathedral_receipts") or {}).get("receipts") or []) if isinstance(d, dict)]
    starts = {d.get("exec_id"): d for d in receipts if d.get("action") == "sandbox.exec.start"}
    for doc in sorted((d for d in receipts if isinstance(d.get("n"), int)), key=lambda d: d["n"]):
        if doc.get("action") not in EXEC_ACTIONS or doc.get("stdout_sha256") != want or doc["n"] in used:
            continue
        source = starts.get(doc.get("exec_id")) if doc.get("action") == "sandbox.exec.finish" else doc
        if source and source.get("command_sha256") == command_hash:
            return doc["n"]
    return None


def verify_offline(ctcli: list[str], args, bundle_path: Path, sandbox_id: str, bound: list[tuple[int, str]]) -> dict:
    """Run `ctcli receipt verify` on the bundle with the pins. Returns the verdict and exit code."""
    argv = [*ctcli, "receipt", "verify", "--bundle", str(bundle_path), "--json", "--require-outputs",
            "--sandbox", sandbox_id, "--expected-measurement", args.expected_measurement]
    argv += ["--cathedral-key", args.cathedral_key] if args.cathedral_key else ["--trusted-keys-file", args.trusted_keys_file]
    for n, path in bound:
        argv += ["--stdout", f"{n}={path}"]
    done = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    try:
        verdict = json.loads(done.stdout).get("verdict")
    except (ValueError, AttributeError):
        verdict = None
    return {"verdict": verdict, "exit_code": done.returncode}


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
        "verification": None,
    }
    sandbox_id = None
    try:
        create_started = time.monotonic()  # before the POST: provisioning time counts
        created = api.call("POST", "/v1/sandboxes", {
            "image": args.image, "template": args.template, "required_hardware": "amd_sev_snp",
            "network": "deny_all", "lifetime_seconds": args.lifetime_seconds,
            "max_spend_usd": args.max_spend_usd, "labels": {"bench": "ab444", "run": run_id},
        }, idem=f"bench-create-{run_id}")
        sandbox_id = created.get("id")
        if not isinstance(sandbox_id, str):
            raise BenchError("create returned no sandbox id")
        result["sandbox_id"] = sandbox_id
        deadline = create_started + args.ready_timeout
        state = created.get("state")
        while state != "running":
            if state in ("failed", "deleted", "deleting") or time.monotonic() > deadline:
                raise BenchError(f"sandbox did not reach running (state {state})")
            time.sleep(args.poll_seconds)
            state = api.call("GET", f"/v1/sandboxes/{sandbox_id}").get("state")
        result["create_to_running_s"] = round(time.monotonic() - create_started, 3)

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
                    "stdout_sha256": sha256_hex(raw), "command_sha256": command_sha256(command),
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
        used: set[int] = set()
        for entry, raw in zip(result["runs"], stdouts):
            entry["receipt_n"] = find_receipt_n(bundle, raw, entry["command_sha256"], used)
            if entry["receipt_n"] is not None:
                used.add(entry["receipt_n"])
        if all(e["receipt_n"] is not None for e in result["runs"]):
            bound = [(e["receipt_n"], e["stdout_file"]) for e in result["runs"]]
            result["verification"] = verify_offline(ctcli, args, bundle_path, sandbox_id, bound)
            if result["verification"]["verdict"] != "PASS" or result["verification"]["exit_code"] != 0:
                raise BenchError("ctcli receipt verify did not PASS (verdict %s, exit %s); the numbers are unverified"
                                 % (result["verification"]["verdict"], result["verification"]["exit_code"]))
    except (BenchError, subprocess.TimeoutExpired, OSError) as exc:
        # A timeout or a missing ctcli must not skip the result file: the room is deleted below.
        result["error"] = str(exc) if isinstance(exc, BenchError) else f"{type(exc).__name__}: {exc}"
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
    p.add_argument("--cathedral-key", help="Cathedral receipt public key (hex), pinned for the offline verify")
    p.add_argument("--trusted-keys-file", help="Local trusted keys file, alternative to --cathedral-key")
    p.add_argument("--expected-measurement", help="Guest measurement (96 hex) the offline verify must see")
    p.add_argument("--poll-seconds", type=float, default=3.0)
    args = p.parse_args(argv)
    if not DIGEST_IMAGE.match(args.image) or args.runs < 1:
        print("--image must be name@sha256:<64 hex> (never a tag) and --runs at least 1", file=sys.stderr)
        return 2
    if not (args.cathedral_key or args.trusted_keys_file) or not args.expected_measurement:
        print("--expected-measurement and one of --cathedral-key / --trusted-keys-file are required: "
              "the result is only signed evidence after an offline PASS", file=sys.stderr)
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
