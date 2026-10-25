#!/usr/bin/env python3
"""Host supervisor for #1469 warm customer guest (seed-box step 8).

Never invents QEMU argv, image digests, hostfwd, or policy pins. The operator
supplies a reviewed start script (absolute path + sha256). This process only:

1. Waits for ``guest.pid`` to exit (lease end or unadmitted MAX_WAIT exit).
2. Rotates the run directory and optionally installs a pre-wiped spare
   ``scratch.raw`` so the next boot can skip the in-guest wipe when the host
   prepared it offline.
3. Re-invokes the pinned start script once with ``CATHEDRAL_CUSTOMER_RUN_DIR``.

Live execute requires ``CATHEDRAL_SEEDBOX_LIVE_OK=yes`` (Contabo: wait until
Ditto seal end 2026-10-23 unless Fred frees the slot).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SCHEMA = "cathedral_snp_seedbox_supervise_v1"


def die(message: str) -> None:
    raise SystemExit(f"refusing seed-box supervise: {message}")


def require_live_ok() -> None:
    if os.environ.get("CATHEDRAL_SEEDBOX_LIVE_OK") != "yes":
        die(
            "set CATHEDRAL_SEEDBOX_LIVE_OK=yes only after owner authorization "
            "(Contabo: do not touch sealed Ditto guest before 2026-10-23)"
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_start_script(path: Path, expected_sha256: str) -> Path:
    if not path.is_absolute() or any(c in str(path) for c in (",", "\n", "\r", "\0")):
        die("start script path must be absolute and free of separators")
    if any(p.is_symlink() for p in (path, *path.parents)):
        die("start script path must not involve symlinks")
    if not path.is_file():
        die(f"start script missing: {path}")
    if not HEX64.fullmatch(expected_sha256):
        die("start script sha256 must be 64 lowercase hex")
    got = sha256_file(path)
    if got != expected_sha256:
        die(f"start script sha256 mismatch got={got} want={expected_sha256}")
    mode = path.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        die("start script must not be group/other-writable")
    return path


def require_owner_only_dir(path: Path, *, must_be_empty: bool = False) -> Path:
    if not path.is_absolute() or any(c in str(path) for c in (",", "\n", "\r", "\0")):
        die("directory path invalid")
    if any(p.is_symlink() for p in (path, *path.parents)):
        die("directory path must not involve symlinks")
    if not path.is_dir():
        die(f"directory missing: {path}")
    info = path.stat()
    if info.st_uid != os.geteuid():
        die(f"directory must be owned by current uid: {path}")
    if info.st_mode & 0o077:
        die(f"directory must be mode 0700 (no group/other bits): {path}")
    if must_be_empty and any(path.iterdir()):
        die(f"directory must be empty: {path}")
    return path


def read_guest_pid(run_dir: Path) -> int:
    require_owner_only_dir(run_dir)
    pid_path = run_dir / "guest.pid"
    if pid_path.is_symlink() or not pid_path.is_file():
        die(f"guest.pid missing under {run_dir}")
    raw = pid_path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[1-9][0-9]{0,9}", raw):
        die("guest.pid is not a positive integer")
    return int(raw)


def pid_alive(pid: int) -> bool:
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_for_guest_exit(run_dir: Path, *, poll_seconds: float = 2.0) -> int:
    pid = read_guest_pid(run_dir)
    while pid_alive(pid):
        time.sleep(max(0.2, poll_seconds))
    return pid


def next_run_dir(run_base: Path, stamp: str | None = None) -> Path:
    require_owner_only_dir(run_base)
    label = stamp or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    candidate = run_base / f"customer-run-{label}"
    if candidate.exists():
        die(f"next run dir already exists: {candidate}")
    candidate.mkdir(mode=0o700)
    return require_owner_only_dir(candidate, must_be_empty=True)


def install_spare_scratch(run_dir: Path, spare_scratch: Path | None) -> dict:
    """Move a pre-wiped spare scratch.raw into the new run dir when provided."""
    if spare_scratch is None:
        return {"spare_installed": False}
    if not spare_scratch.is_absolute() or spare_scratch.is_symlink():
        die("spare scratch must be an absolute non-symlink path")
    if spare_scratch.name != "scratch.raw":
        die("spare scratch file must be named scratch.raw")
    if not spare_scratch.is_file():
        die(f"spare scratch missing: {spare_scratch}")
    dest = run_dir / "scratch.raw"
    if dest.exists():
        die(f"run dir already has scratch.raw: {dest}")
    os.rename(spare_scratch, dest)
    os.chmod(dest, 0o600)
    return {
        "spare_installed": True,
        "scratch": str(dest),
        "bytes": dest.stat().st_size,
    }


def archive_finished_run(run_dir: Path, archive_root: Path) -> Path:
    require_owner_only_dir(run_dir)
    require_owner_only_dir(archive_root)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    dest = archive_root / f"finished-{run_dir.name}-{stamp}"
    if dest.exists():
        die(f"archive path exists: {dest}")
    shutil.move(str(run_dir), str(dest))
    return dest


def prepare_next(
    *,
    run_base: Path,
    spare_scratch: Path | None = None,
    stamp: str | None = None,
) -> dict:
    run_dir = next_run_dir(run_base, stamp=stamp)
    spare = install_spare_scratch(run_dir, spare_scratch)
    document = {
        "schema": SCHEMA,
        "action": "prepare_next",
        "run_dir": str(run_dir),
        **spare,
    }
    return document


def invoke_start_script(script: Path, run_dir: Path, extra_env: dict | None = None) -> int:
    require_live_ok()
    require_owner_only_dir(run_dir)
    env = os.environ.copy()
    env["CATHEDRAL_CUSTOMER_RUN_DIR"] = str(run_dir)
    env["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    if extra_env:
        env.update(extra_env)
    completed = subprocess.run(
        [str(script)],
        check=False,
        env=env,
        cwd=str(run_dir),
    )
    return int(completed.returncode)


def supervise_loop(
    *,
    run_base: Path,
    start_script: Path,
    start_sha256: str,
    current_run: Path,
    spare_scratch: Path | None,
    archive_root: Path,
    poll_seconds: float,
    max_cycles: int,
) -> None:
    script = verify_start_script(start_script, start_sha256)
    require_owner_only_dir(run_base)
    require_owner_only_dir(archive_root)
    run_dir = require_owner_only_dir(current_run)
    cycles = 0
    while max_cycles <= 0 or cycles < max_cycles:
        exited_pid = wait_for_guest_exit(run_dir, poll_seconds=poll_seconds)
        archived = archive_finished_run(run_dir, archive_root)
        prepared = prepare_next(run_base=run_base, spare_scratch=spare_scratch)
        print(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "action": "cycle",
                    "exited_pid": exited_pid,
                    "archived": str(archived),
                    **prepared,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        code = invoke_start_script(script, Path(prepared["run_dir"]))
        if code != 0:
            die(f"start script exited {code}")
        # After start, guest.pid must appear under the new run dir.
        deadline = time.monotonic() + 120
        new_run = Path(prepared["run_dir"])
        while time.monotonic() < deadline:
            if (new_run / "guest.pid").is_file():
                break
            time.sleep(1)
        else:
            die(f"start script did not write guest.pid under {new_run}")
        run_dir = new_run
        spare_scratch = None  # one-shot spare; operator replenishes offline
        cycles += 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare-next", help="create empty next run dir; optional spare scratch")
    prepare.add_argument("--run-base", required=True, type=Path)
    prepare.add_argument("--spare-scratch", type=Path, default=None)
    prepare.add_argument("--stamp", default=None)

    watch = sub.add_parser("watch-once", help="wait for guest.pid exit; print exited pid")
    watch.add_argument("--run-dir", required=True, type=Path)
    watch.add_argument("--poll-seconds", type=float, default=2.0)

    supervise = sub.add_parser(
        "supervise",
        help="wait for exit → archive → prepare-next → pinned start script (live gated)",
    )
    supervise.add_argument("--run-base", required=True, type=Path)
    supervise.add_argument("--current-run", required=True, type=Path)
    supervise.add_argument("--archive-root", required=True, type=Path)
    supervise.add_argument("--start-script", required=True, type=Path)
    supervise.add_argument("--start-script-sha256", required=True)
    supervise.add_argument("--spare-scratch", type=Path, default=None)
    supervise.add_argument("--poll-seconds", type=float, default=2.0)
    supervise.add_argument(
        "--max-cycles",
        type=int,
        default=0,
        help="0 = unlimited; use 1 for a single relaunch proof",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "prepare-next":
        document = prepare_next(
            run_base=args.run_base,
            spare_scratch=args.spare_scratch,
            stamp=args.stamp,
        )
        print(json.dumps(document, sort_keys=True))
        return 0
    if args.command == "watch-once":
        pid = wait_for_guest_exit(args.run_dir, poll_seconds=args.poll_seconds)
        print(json.dumps({"schema": SCHEMA, "action": "watch_once", "exited_pid": pid}))
        return 0
    if args.command == "supervise":
        supervise_loop(
            run_base=args.run_base,
            start_script=args.start_script,
            start_sha256=args.start_script_sha256,
            current_run=args.current_run,
            spare_scratch=args.spare_scratch,
            archive_root=args.archive_root,
            poll_seconds=args.poll_seconds,
            max_cycles=args.max_cycles,
        )
        return 0
    die(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
