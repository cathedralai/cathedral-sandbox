#!/usr/bin/env python3
"""Fail-closed boot check for the dedicated custom guest image (image acceptance, no SNP).

Boots the built kernel and initrd under plain QEMU (TCG, no SEV-SNP) with the manifest's
measured cmdline, reads the serial console, and checks that our PID1 runs and fails closed:

  PASS   the console shows `cathedral-init: <expected stage>: ...`, no other cathedral-init
         stage, no kernel panic, and QEMU exits by itself (the guest powered off) in time.
  FAIL   anything else: a hang past --timeout, a panic, PID1 never reached, another stage,
         or QEMU still running.

Without a chip, `launch documents` (firmware attributes plus a native SNP report) can never
succeed, so that is the default expected stage. An image built without its digest pins must
stop earlier, at `pins` (--expect-stage pins). This proves the image boots to our PID1 and
refuses to continue without SNP. It is not SNP acceptance; that is the chip rehearsal.

One JSON line on stdout. Exit 0 PASS, 1 FAIL, 2 ERROR (inputs or QEMU missing).
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Boot stage names in cathedral-init's order (cmd/cathedral-init: fail(stage, err)).
STAGES = ("pins", "kernel views", "launch documents", "memory", "verified root", "exec")
STAGE_LINE = re.compile(r"cathedral-init: (pins|kernel views|launch documents|memory|verified root|exec): ")
PANIC_LINE = re.compile(r"cathedral-init: panic in boot stage|Kernel panic|end Kernel panic")
LOG_LIMIT = 1 << 20


def evaluate(console: str, exited: bool, timed_out: bool, expect_stage: str) -> dict:
    """The verdict for one boot, from its console text and how QEMU ended."""
    stages = STAGE_LINE.findall(console)
    checks = {
        "pid1_reached": bool(stages) or "cathedral-init:" in console,
        "expected_stage": stages == [expect_stage],
        "no_panic": PANIC_LINE.search(console) is None,
        "powered_off": exited and not timed_out,
    }
    if timed_out:
        reason = "QEMU still running at the time limit (the guest did not power off)"
    elif not checks["no_panic"]:
        reason = "panic during boot"
    elif not checks["pid1_reached"]:
        reason = "the console never showed cathedral-init"
    elif not stages:
        reason = "cathedral-init printed no stage failure"
    elif stages != [expect_stage]:
        reason = f"stopped at {stages}, expected only {expect_stage!r}"
    elif not exited:
        reason = "QEMU did not exit"
    else:
        reason = None
    verdict = "PASS" if all(checks.values()) else "FAIL"
    return {"verdict": verdict, "checks": checks, "stages_seen": stages, "reason": reason}


def manifest_cmdline(path: Path) -> str:
    doc = json.loads(path.read_text())
    line = doc.get("cmdline")
    if not isinstance(line, str) or not line:
        raise ValueError("manifest has no cmdline")
    return line


def qemu_argv(qemu: str, kernel: Path, initrd: Path, cmdline: str, memory_mib: int) -> list[str]:
    # -no-reboot turns the guest's poweroff (and any reboot) into QEMU exiting. -cpu max: TCG's
    # default qemu64 lacks features an EPYC-built kernel may need before it reaches PID1.
    return [qemu, "-nographic", "-no-reboot", "-nodefaults", "-cpu", "max", "-serial", "stdio", "-m", str(memory_mib),
            "-kernel", str(kernel), "-initrd", str(initrd), "-append", cmdline]


def boot(argv: list[str], timeout: float, runner=subprocess.run) -> tuple[str, bool, bool, int | None]:
    """Console text, whether QEMU exited, whether it hit the time limit, and its return code."""
    try:
        done = runner(argv, capture_output=True, timeout=timeout, check=False)
        out = (done.stdout or b"")[:LOG_LIMIT] + (done.stderr or b"")[:LOG_LIMIT]
        return out.decode("utf-8", "replace"), True, False, done.returncode
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"")[:LOG_LIMIT] + (exc.stderr or b"")[:LOG_LIMIT]
        return out.decode("utf-8", "replace"), False, True, None


def main(argv: list[str] | None = None, runner=subprocess.run) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--kernel", type=Path, required=True)
    p.add_argument("--initrd", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True, help="the image manifest; its cmdline is used exactly")
    p.add_argument("--expect-stage", default="launch documents", choices=STAGES)
    p.add_argument("--qemu", default="qemu-system-x86_64")
    p.add_argument("--memory-mib", type=int, default=1024)
    p.add_argument("--timeout", type=float, default=180)
    p.add_argument("--console-out", type=Path, help="also save the console log here")
    args = p.parse_args(argv)
    try:
        for path in (args.kernel, args.initrd, args.manifest):
            if not path.is_file():
                raise ValueError(f"{path} not found")
        if shutil.which(args.qemu) is None and not Path(args.qemu).is_file():
            raise ValueError(f"{args.qemu} not found")
        cmdline = manifest_cmdline(args.manifest)
        # Only the serial port is read: without a ttyS0 console every boot would read as a FAIL.
        if not any(t == "console=ttyS0" or t.startswith("console=ttyS0,") for t in cmdline.split()):
            raise ValueError("manifest cmdline sends no console to ttyS0, so this check cannot read the boot")
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"verdict": "ERROR", "reason": str(exc)}))
        return 2
    console, exited, timed_out, qemu_rc = boot(qemu_argv(args.qemu, args.kernel, args.initrd, cmdline, args.memory_mib),
                                      args.timeout, runner)
    if args.console_out:
        args.console_out.write_text(console)
    result = evaluate(console, exited, timed_out, args.expect_stage)
    # A QEMU argument or startup error otherwise reads as "never showed cathedral-init".
    result.update(schema="cathedral.custom_guest_boot_check/v1", expect_stage=args.expect_stage, snp=False,
                  qemu_returncode=qemu_rc)
    print(json.dumps(result))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
