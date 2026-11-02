#!/usr/bin/env python3
"""Dry-run the tee-box relaunch driver (no VMM, no reboot).

Usage:
  PYTHONPATH=/opt/cathedral/sandbox python3 scripts/tee_box_snp_e2e/relaunch_dry_run.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def main() -> int:
    if sys.version_info < (3, 10):
        print("relaunch_dry_run needs Python >= 3.10 (tee_box package)", file=sys.stderr)
        return 2
    from cathedral.tee_box.relaunch_driver import DryRunHooks, run_relaunch_cycle

    hooks = DryRunHooks()
    result = run_relaunch_cycle("tee-box-snp-e2e", hooks, prior_boot_id="boot-dry-0")
    print(
        json.dumps(
            {
                "ok": result.ok,
                "phase": result.state.phase.value,
                "steps": result.steps,
                "reboots": hooks.reboots,
                "state": result.state.as_dict(),
            },
            indent=2,
        )
    )
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
