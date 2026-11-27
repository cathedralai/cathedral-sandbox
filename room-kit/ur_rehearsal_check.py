#!/usr/bin/env python3
"""Rehearsal A checker for a dedicated custom SNP guest (draft for spec r9 section 14.2).

Runs the owner-side checks in order and prints one JSON checklist.
  PASS        every check passed, including the restart and disk evidence.
  INCOMPLETE  nothing failed, but restart or disk evidence was not given (exit 2).
  FAIL        any check failed (exit 1).
Only PASS exits 0, so a rehearsal without its evidence never reads as a pass.

Checks:
  1. launch_documents: the owner's retained manifest, bootstrap and signature agree and
     give HOST_DATA (custom_guest_protocol.validate_launch). The SSH endpoint given here
     must be the owner-signed public host and first port.
  2. guest_report: one fresh SSH connection returns an SNP report bound to the accepted
     host key and a fresh challenge, with the expected measurement, HOST_DATA, chip, CPU
     and TCB floor (verify_custom_guest.py, run as a subprocess).
  3. restart_same_launch (--pre-hold-result, --restart-result): verify_custom_guest.py JSON
     taken before the hold and after the return. Both must be one line, PASS, SSH-bound and
     for this launch_id. The after result's host key must be the live report's (check 2),
     and the before result's must differ: the guest makes a new RAM host key every boot,
     so a changed key is what shows the restart happened.
  4. preserved_work (--preserved-before, --preserved-after): sha256sum listings of the kept
     disks, two different files. Each starts with a header line
       # cathedral.preserved/v1 launch_id=<launch_id> taken=<UTC YYYY-MM-DDTHH:MM:SSZ>
     naming this launch; the before listing must be taken earlier. Both must list the same
     disks with the same digests (spec r9 section 14.2 A5).

It never creates, stops or changes a guest.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

KIT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, KIT)
import custom_guest_protocol as protocol  # noqa: E402

SCHEMA = "cathedral.ur_rehearsal_check/v1-draft"
# Same caps as verify_custom_guest.py, so both tools accept the same files.
DOC_LIMIT = 16384
EVIDENCE_LIMIT = 1 << 20
SHA256SUM_LINE = re.compile(r"([0-9a-f]{64})  (\S(?:.*\S)?)")
LISTING_HEADER = re.compile(r"# cathedral\.preserved/v1 launch_id=(cg-[0-9a-f]{12}) taken=(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)")


def read_limit(path, limit):
    with open(path, "rb") as stream:
        raw = stream.read(limit + 1)
    protocol.need(len(raw) <= limit, f"{os.path.basename(path)} too large")
    return raw


def check(name, fn):
    try:
        return {"name": name, "status": "pass", "detail": fn()}
    except Exception as exc:  # noqa: BLE001  # any failure is a FAIL line, never a crash
        return {"name": name, "status": "fail", "detail": str(exc) or type(exc).__name__}


def launch_documents(manifest_raw, bootstrap_raw, signature, owner_key, host, port):
    _, launch, host_data = protocol.validate_launch(manifest_raw, bootstrap_raw, signature, owner_key)
    protocol.need(host == launch["network"]["public_host"] and port == launch["ports"][0]["public"],
                  "SSH endpoint differs from owner-signed bootstrap")
    return {"launch_id": launch["launch_id"], "hotel": launch["hotel"], "host_data": host_data}


def guest_report(argv, runner=subprocess.run):
    done = runner(argv, capture_output=True, timeout=180, check=False)
    lines = [line for line in done.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    protocol.need(lines, "verifier printed nothing")
    result = json.loads(lines[-1])
    protocol.need(isinstance(result, dict), "verifier output is not an object")
    protocol.need(done.returncode == 0 and result.get("verdict") == "PASS",
                  "guest report not verified: " + str(result.get("reason", result.get("verdict"))))
    return {key: result.get(key) for key in ("verdict", "launch_id", "ssh_channel_binding", "ssh_host_key")}


def evidence(name, given, flags, fn):
    if not given:
        return {"name": name, "status": "not_checked", "detail": f"no evidence: pass {flags}"}
    return check(name, fn)


def verifier_result(raw, launch_id, label):
    protocol.need(launch_id, f"launch documents failed, so the {label} result cannot be matched")
    lines = [line for line in raw.decode("utf-8", "replace").splitlines() if line.strip()]
    protocol.need(len(lines) == 1, f"{label} result must be exactly one JSON line")
    result = json.loads(lines[0])
    protocol.need(isinstance(result, dict) and result.get("verdict") == "PASS", f"{label} result is not PASS")
    protocol.need(result.get("launch_id") == launch_id, f"{label} result names another launch")
    protocol.need(result.get("ssh_channel_binding") == "verified", f"{label} result is not SSH-bound")
    key = result.get("ssh_host_key")
    protocol.need(isinstance(key, str) and key.startswith("ssh-ed25519 "), f"{label} result has no host key")
    return key


def restart_same_launch(before_raw, after_raw, launch_id, live_key):
    protocol.need(live_key, "no live guest report to compare the restart with")
    before = verifier_result(before_raw, launch_id, "pre-hold")
    after = verifier_result(after_raw, launch_id, "restart")
    protocol.need(after == live_key, "restart result is from another boot than the live report")
    protocol.need(before != after, "host key did not change, so no restart is shown")
    return {"launch_id": launch_id}


def sha256sum_listing(raw, label, launch_id):
    lines = [line for line in raw.decode("ascii").splitlines() if line.strip()]
    protocol.need(lines, f"{label}: empty listing")
    header = LISTING_HEADER.fullmatch(lines[0])
    protocol.need(header, f"{label}: missing cathedral.preserved/v1 header")
    protocol.need(header.group(1) == launch_id, f"{label}: listing names another launch")
    entries = {}
    for line in lines[1:]:
        match = SHA256SUM_LINE.fullmatch(line)
        protocol.need(match, f"{label}: not a sha256sum line")
        protocol.need(match.group(2) not in entries, f"{label}: disk listed twice")
        entries[match.group(2)] = match.group(1)
    protocol.need(entries, f"{label}: no disks listed")
    return header.group(2), entries


def preserved_work(before_path, after_path, launch_id):
    protocol.need(launch_id, "launch documents failed, so the listings cannot be matched")
    protocol.need(not os.path.samefile(before_path, after_path), "before and after are the same file")
    taken_before, before = sha256sum_listing(read_limit(before_path, EVIDENCE_LIMIT), "before", launch_id)
    taken_after, after = sha256sum_listing(read_limit(after_path, EVIDENCE_LIMIT), "after", launch_id)
    # Fixed-width UTC ISO times compare correctly as strings.
    protocol.need(taken_before < taken_after, "the before listing is not older than the after listing")
    protocol.need(set(before) == set(after), "the kept disks before and after differ")
    changed = sorted(name for name in before if before[name] != after[name])
    protocol.need(not changed, "changed during the hold: " + ", ".join(changed))
    return {"disks": len(before)}


def verifier_argv(args):
    argv = [sys.executable, os.path.join(KIT, "verify_custom_guest.py"),
            "--host", args.host, "--port", str(args.port), "--identity", args.identity,
            "--manifest", args.manifest, "--bootstrap", args.bootstrap,
            "--bootstrap-signature", args.bootstrap_signature, "--owner-public-key", args.owner_public_key,
            "--expected-measurement", args.expected_measurement, "--expected-chip-id", args.expected_chip_id,
            "--expected-cpuid", args.expected_cpuid, "--ark-sha256", args.ark_sha256,
            "--known-hosts-out", args.known_hosts_out]
    for floor in args.min_tcb:
        argv += ["--min-tcb", floor]
    if args.ark_crl:
        argv += ["--ark-crl", args.ark_crl]
    return argv


def run(args, runner=subprocess.run):
    checks = [check("launch_documents", lambda: launch_documents(
        read_limit(args.manifest, DOC_LIMIT), read_limit(args.bootstrap, DOC_LIMIT),
        read_limit(args.bootstrap_signature, 64), read_limit(args.owner_public_key, 32),
        args.host, args.port))]
    launch = checks[0]
    if launch["status"] != "pass":
        checks.append({"name": "guest_report", "status": "fail", "detail": "not run: launch documents failed"})
    else:
        report = check("guest_report", lambda: guest_report(verifier_argv(args), runner))
        if report["status"] == "pass" and report["detail"].get("launch_id") != launch["detail"]["launch_id"]:
            report = {"name": "guest_report", "status": "fail", "detail": "report names another launch"}
        checks.append(report)
    launch_id = launch["detail"].get("launch_id") if launch["status"] == "pass" else None
    live_key = checks[1]["detail"].get("ssh_host_key") if checks[1]["status"] == "pass" else None
    checks.append(evidence("restart_same_launch", args.pre_hold_result and args.restart_result,
                           "--pre-hold-result and --restart-result",
                           lambda: restart_same_launch(read_limit(args.pre_hold_result, EVIDENCE_LIMIT),
                                                       read_limit(args.restart_result, EVIDENCE_LIMIT), launch_id, live_key)))
    checks.append(evidence("preserved_work", args.preserved_before and args.preserved_after,
                           "--preserved-before and --preserved-after",
                           lambda: preserved_work(args.preserved_before, args.preserved_after, launch_id)))
    statuses = {c["status"] for c in checks}
    verdict = "FAIL" if "fail" in statuses else "INCOMPLETE" if "not_checked" in statuses else "PASS"
    return {"schema": SCHEMA, "verdict": verdict, "checks": checks}


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("host", "identity", "manifest", "bootstrap", "bootstrap-signature", "owner-public-key",
                 "expected-measurement", "expected-chip-id", "expected-cpuid", "ark-sha256", "known-hosts-out"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--port", type=int, default=20022)
    p.add_argument("--min-tcb", action="append", required=True)
    p.add_argument("--ark-crl")
    p.add_argument("--pre-hold-result", help="verify_custom_guest.py JSON output taken before the hold")
    p.add_argument("--restart-result", help="verify_custom_guest.py JSON output taken after the hold and return")
    p.add_argument("--preserved-before", help="headed sha256sum listing of the kept disks before the hold")
    p.add_argument("--preserved-after", help="headed sha256sum listing of the kept disks after the return")
    return p


def main(argv=None):
    result = run(parser().parse_args(argv))
    print(json.dumps(result, indent=1))
    return {"PASS": 0, "FAIL": 1}.get(result["verdict"], 2)


if __name__ == "__main__":
    sys.exit(main())
