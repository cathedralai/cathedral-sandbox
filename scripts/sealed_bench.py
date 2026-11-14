#!/usr/bin/env python3
"""One sealed benchmark run, one receipt chain (AB#444).

Creates ONE sealed sandbox through the customer API, runs a fixed prompt set
inside it with the image's own `lfm3-bench` (one exec per prompt; it prints a
`lfm3-bench {json}` line with time to first token, prompt and decode tokens/s,
the model file's sha256 hashed in the room and the prompt-set hash), fetches
the sandbox evidence bundle, deletes the sandbox, and writes a JSON result.
`--harness lfm3-ask` runs images published before lfm3-bench (no time to first
token, no model hash).

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

What binds what, with lfm3-bench:
- harness version, prompt set, index, max tokens: the argv, whose
  command_sha256 the guest signs.
- time to first token, rates, model sha256, prompt_set_sha256: the stdout
  line, whose sha256 Cathedral's exec receipt carries. The script checks the
  in-room prompt_set_sha256 equals its own and that every run names one model.
- image digest: the guest-signed create receipt in the bundle must name an
  image with the same @sha256 as --image, or the result is unbound (exit 3).
  Its image_digest (the docker image Id the guest saw) is recorded as is.
prompt_set_sha256 is the sha256 of the compact JSON of the prompt list
(json.dumps(prompts, separators=(",", ":"), ensure_ascii=False)), the bytes
sent to lfm3-bench, so it does not depend on how the prompts file is formatted.

Not here: a signed summary of the whole run, and the live run itself.

Usage:
  CATHEDRAL_API_KEY=... sealed_bench.py --image ghcr.io/cathedralai/room-lfm3-omni-2b@sha256:<64 hex> \
      --template sealed-2x4 --prompts bench/prompts.json --out-dir out/ [--runs 3] \
      --cathedral-key <hex> --expected-measurement <96 hex>
Env: CATHEDRAL_API_URL (default https://cathedral.computer), CTCLI (default ctcli).
Exit: 0 all runs bound to a receipt, the image bound to the guest create receipt and the
offline verify PASSed, 1 failure, 2 bad usage, 3 ran but a run has no matching receipt or
the image is not bound.
"""
from __future__ import annotations

import argparse
import base64
import binascii
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

HARNESS_VERSION = "sealed-bench-2"
ROOM_HARNESS = "lfm3-bench-1"  # the in-room lfm3-bench this script expects
DIGEST_IMAGE = re.compile(r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
TIMING = re.compile(r"^lfm3-timing (.*)$", re.M)
BENCH_LINE = re.compile(r"^lfm3-bench (\{.*\})$", re.M)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_PROMPT_SET_BYTES = 100_000  # one argv string; Linux caps a single argument at 128 KiB
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


def parse_bench(stdout: str, prompt_set_sha256: str, index: int) -> dict:
    """The `lfm3-bench {json}` line lfm3-bench prints last, checked against what was asked."""
    found = BENCH_LINE.findall(stdout)
    if not found:
        raise BenchError("no lfm3-bench line in the output")
    try:
        line = json.loads(found[-1])
    except ValueError as exc:
        raise BenchError("the lfm3-bench line is not JSON") from exc
    if not isinstance(line, dict):
        raise BenchError("the lfm3-bench line is not an object")
    if line.get("harness") != ROOM_HARNESS:
        raise BenchError(f"lfm3-bench harness {line.get('harness')!r}, expected {ROOM_HARNESS}")
    for needed in ("ttft_ms", "prompt_tok_s", "decode_tok_s", "wall_ms"):
        if not isinstance(line.get(needed), (int, float)) or isinstance(line.get(needed), bool):
            raise BenchError(f"lfm3-bench has no usable {needed}")
    if not isinstance(line.get("model_sha256"), str) or not HEX64.match(line["model_sha256"]):
        raise BenchError("lfm3-bench has no model_sha256")
    if line.get("prompt_set_sha256") != prompt_set_sha256:
        raise BenchError("lfm3-bench hashed a different prompt set")
    if line.get("prompt_index") != index:
        raise BenchError(f"lfm3-bench answered prompt {line.get('prompt_index')}, asked {index}")
    return line


def guest_create_statements(bundle: dict, sandbox_id: str) -> list[dict]:
    """The successful create statements in the bundle's guest receipts for this sandbox.

    Each guest receipt is base64url of {statement, signature_b64, receipt_sha256}; ctcli receipt
    verify checks the signatures. A statement that names a Cathedral sandbox id must name this one.
    """
    found = []
    for entry in (bundle.get("guest_receipts") or {}).get("receipts") or []:
        header = entry.get("hotel_receipt_b64") if isinstance(entry, dict) else None
        if not isinstance(header, str) or not header:
            continue
        try:
            receipt = json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
        except (ValueError, binascii.Error):
            continue
        st = receipt.get("statement") if isinstance(receipt, dict) else None
        if not isinstance(st, dict) or st.get("action") != "create":
            continue
        if not isinstance(st.get("status"), int) or not 200 <= st["status"] < 300:
            continue
        if st.get("cathedral_sandbox_id") not in (None, sandbox_id):
            continue
        found.append(st)
    return found


def image_binding(bundle: dict, sandbox_id: str, image: str) -> dict:
    """Whether the guest-signed create receipt names --image's manifest digest."""
    want = image.rsplit("@", 1)[1]
    creates = guest_create_statements(bundle, sandbox_id)
    bound = bool(creates) and all(isinstance(st.get("image"), str) and st["image"].endswith("@" + want)
                                  for st in creates)
    last = creates[-1] if creates else {}
    return {"image_bound": bound, "guest_image": last.get("image"), "guest_image_digest": last.get("image_digest"),
            "guest_create_receipts": len(creates)}


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
    try:
        prompts = json.loads(Path(args.prompts).read_bytes())
    except (OSError, ValueError) as exc:
        raise BenchError(f"cannot read --prompts: {exc}") from exc
    if not isinstance(prompts, list) or not prompts or not all(isinstance(p, str) and p for p in prompts):
        raise BenchError("--prompts must be a JSON array of non-empty strings")
    prompt_set = json.dumps(prompts, separators=(",", ":"), ensure_ascii=False)
    if len(prompt_set.encode()) > MAX_PROMPT_SET_BYTES:
        raise BenchError(f"the prompt set is over {MAX_PROMPT_SET_BYTES} bytes as one argument")
    prompt_set_sha256 = sha256_hex(prompt_set.encode())
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:12]
    result = {
        "schema": "cathedral_sealed_bench_v2", "harness_version": HARNESS_VERSION, "run_id": run_id,
        "room_harness": ROOM_HARNESS if args.harness == "lfm3-bench" else "lfm3-ask",
        "image": args.image, "template": args.template,
        "prompt_set_sha256": prompt_set_sha256, "max_tokens": args.max_tokens,
        "sandbox_id": None, "runs": [], "bundle_path": None, "deleted": False, "error": None,
        "verification": None, "model_sha256": None, "image_bound": False,
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
                if args.harness == "lfm3-bench":
                    command = ["lfm3-bench", "--max-tokens", str(args.max_tokens), "--index", str(index), prompt_set]
                    body = {"command": command, "timeout_seconds": EXEC_TIMEOUT_SECONDS}
                else:
                    command = ["lfm3-ask", prompt]
                    body = {"command": command, "timeout_seconds": EXEC_TIMEOUT_SECONDS,
                            "env": {"LFM3_MAX_TOKENS": str(args.max_tokens)}}
                started = time.monotonic()
                answer = api.call("POST", f"/v1/sandboxes/{sandbox_id}/exec", body,
                                  idem=f"bench-exec-{run_id}-{rep}-{index}", timeout=EXEC_TIMEOUT_SECONDS + 30)
                if answer.get("exit_code") != 0 or not isinstance(answer.get("stdout"), str):
                    raise BenchError(f"exec {rep}/{index} failed (exit {answer.get('exit_code')})")
                raw = answer["stdout"].encode()
                path = out_dir / f"{run_id}-run{rep}-{index}.stdout"
                path.write_bytes(raw)
                stdouts.append(raw)
                entry = {"rep": rep, "prompt_index": index, "wall_s": round(time.monotonic() - started, 3),
                         "stdout_file": str(path), "stdout_sha256": sha256_hex(raw),
                         "command_sha256": command_sha256(command),
                         "room_receipt_id": answer.get("room_receipt_id"), "receipt_n": None}
                if args.harness == "lfm3-bench":
                    line = parse_bench(answer["stdout"], prompt_set_sha256, index)
                    if result["model_sha256"] not in (None, line["model_sha256"]):
                        raise BenchError("runs in one room reported different model sha256")
                    result["model_sha256"] = line["model_sha256"]
                    entry.update({
                        "ttft_ms": line["ttft_ms"], "prompt_tok_s": line["prompt_tok_s"],
                        "decode_tok_s": line["decode_tok_s"], "model_wall_ms": line["wall_ms"],
                        "prompt_ms": line.get("prompt_ms"), "prompt_n": line.get("prompt_n"),
                        "decode_n": line.get("decode_n"), "load_ms": line.get("load_ms"),
                        "threads": line.get("threads"), "model_sha256": line["model_sha256"],
                        "mmproj_sha256": line.get("mmproj_sha256"),
                    })
                else:
                    timing = parse_timing(answer["stdout"])
                    entry.update({
                        "ttft_ms": None, "prompt_tok_s": timing["prompt_tok_s"], "decode_tok_s": timing["gen_tok_s"],
                        "model_wall_ms": timing["wall_ms"], "load_ms": timing.get("load_ms"),
                        "threads": timing.get("threads"),
                    })
                result["runs"].append(entry)

        # The bundle is fetched before delete: a deleted room's evidence is not guaranteed.
        bundle_path = out_dir / f"{run_id}-bundle.json"
        done = subprocess.run([*ctcli, "sandbox", "evidence", sandbox_id, "-o", str(bundle_path), "--force"],
                              capture_output=True, text=True, timeout=300)
        if done.returncode != 0:
            raise BenchError("ctcli sandbox evidence failed: " + (done.stderr or "").strip()[:200])
        result["bundle_path"] = str(bundle_path)
        bundle = json.loads(bundle_path.read_text())
        result.update(image_binding(bundle, sandbox_id, args.image))
        used: set[int] = set()
        for entry, raw in zip(result["runs"], stdouts):
            entry["receipt_n"] = find_receipt_n(bundle, raw, entry["command_sha256"], used)
            if entry["receipt_n"] is not None:
                used.add(entry["receipt_n"])
        if result["image_bound"] and all(e["receipt_n"] is not None for e in result["runs"]):
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
    unbound = any(r["receipt_n"] is None for r in result["runs"]) or not result["image_bound"]
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
    p.add_argument("--harness", choices=("lfm3-bench", "lfm3-ask"), default="lfm3-bench",
                   help="in-room tool: lfm3-bench (TTFT, model sha256) or lfm3-ask for older images")
    p.add_argument("--lifetime-seconds", type=int, default=900)
    p.add_argument("--max-spend-usd", default="0.50")
    p.add_argument("--ready-timeout", type=int, default=300)
    p.add_argument("--cathedral-key", help="Cathedral receipt public key (hex), pinned for the offline verify")
    p.add_argument("--trusted-keys-file", help="Local trusted keys file, alternative to --cathedral-key")
    p.add_argument("--expected-measurement", help="Guest measurement (96 hex) the offline verify must see")
    p.add_argument("--poll-seconds", type=float, default=3.0)
    args = p.parse_args(argv)
    if not DIGEST_IMAGE.match(args.image) or args.runs < 1 or args.max_tokens < 1:
        print("--image must be name@sha256:<64 hex> (never a tag), --runs and --max-tokens at least 1",
              file=sys.stderr)
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
