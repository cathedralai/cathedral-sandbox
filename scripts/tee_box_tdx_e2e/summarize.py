#!/usr/bin/env python3
"""Write the plain-text results summary for one collected TEE box run.

usage: summarize.py RESULTS_DIR [BASELINE_DIR]

RESULTS_DIR holds what run.sh collected (harness-*.json, *-tests.log,
*.fails, *.fails.rerun, setup-*.log). BASELINE_DIR holds the same suites'
*.fails from a local run, so failures that also fail locally are told apart
from failures that only happen on the box.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

GROUPS = {
    "a": "storage (plain ext4 refused, LUKS2 integrity accepted, state on tmpfs) + measured root",
    "b": "auth: revocation list gating (none -> 409, fresh opens, stale -> 409)",
    "c": "lease, import by digest, create under runsc, exec, delete",
    "d": "RTMR3: zero before, RTMR3_CONSUMED after, quote + admit(require_fresh_boot)",
    "e": "egress: metadata / VPC gateway / box denied, 1.1.1.1 reachable",
    "f": "one customer per boot (B relaunch_required, A leases again)",
    "g": "wrong scope and revoked delegation refused",
}


def lines_of(path: Path) -> list[str]:
    try:
        return [line for line in path.read_text().splitlines() if line.strip()]
    except OSError:
        return []


def main() -> int:
    dest = Path(sys.argv[1])
    baseline = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    out: list[str] = []
    out.append(f"TEE box end-to-end results: {dest.name}")
    for name in ("sandbox", "validator"):
        log = dest / f"{name}-tests.log"
        head = lines_of(log)[:1]
        if head:
            out.append(f"  {name}: {head[0]}")
    rows_by_group: dict[str, list[dict]] = {}
    harness_rows: list[str] = []
    for phase in ("pre-luks", "main"):
        path = dest / f"harness-{phase}.json"
        try:
            report = json.loads(path.read_text())
        except (OSError, ValueError):
            harness_rows.append(f"[{phase}] no report ({path.name} missing or unreadable)")
            rows_by_group.setdefault("a" if phase == "pre-luks" else "?", []).append(
                {"status": "FAIL", "id": phase, "name": "no report"}
            )
            continue
        harness_rows.append(f"[{phase}] {report.get('counts')}")
        for row in report["rows"]:
            detail = row["detail"]
            if len(detail) > 300:
                detail = detail[:300] + "..."
            harness_rows.append(
                f"  {row['status']:<4} {row['id']:<6} {row['name']}"
                + (f"\n         {detail}" if detail and row["status"] != "INFO" else "")
            )
            group = row["id"].split(".")[0]
            if group in GROUPS or row["status"] == "FAIL":
                rows_by_group.setdefault(group if group in GROUPS else "?", []).append(row)
    out.append("")
    out.append("== Required checks ==")
    for group, title in GROUPS.items():
        rows = rows_by_group.get(group, [])
        statuses = {row["status"] for row in rows}
        verdict = (
            "FAIL"
            if "FAIL" in statuses
            else "PASS"
            if "PASS" in statuses
            else "SKIP"
            if rows
            else "MISSING"
        )
        failed = [row["id"] for row in rows if row["status"] == "FAIL"]
        out.append(
            f"  {verdict:<7} {group}. {title}"
            + (f"  (failed: {', '.join(failed)})" if failed else "")
        )
    for row in rows_by_group.get("?", []):
        out.append(f"  FAIL    {row['id']}: {row['name']}")
    out.append("")
    out.append("== Test suites ==")
    for name in ("sandbox", "validator"):
        log = lines_of(dest / f"{name}-tests.log")
        if not log:
            out.append(f"  {name}: not run")
            continue
        summary = next(
            (
                line
                for line in reversed(log)
                if re.search(r"\d+ (passed|failed)", line) and " in " in line
            ),
            "no pytest summary",
        )
        exit_line = next((line for line in reversed(log) if line.startswith("EXIT ")), "")
        fails = set(lines_of(dest / f"{name}.fails"))
        rerun = set(lines_of(dest / f"{name}.fails.rerun")) if fails else set()
        base: set[str] = set()
        if baseline is not None:
            base = set(lines_of(baseline / f"{name}.fails.rerun")) | set(
                lines_of(baseline / f"{name}.fails")
            )
        out.append(f"  {name}: {summary.strip('= ')}  [{exit_line}]")
        out.append(
            f"    failing ids: {len(fails)}; still failing after a sequential re-run: {len(rerun)}; "
            f"flaky (passed on re-run): {len(fails - rerun)}"
        )
        if baseline is not None:
            new = sorted(rerun - base)
            out.append(
                f"    also failing in the local baseline: {len(rerun & base)}; "
                f"box-only failures: {len(new)}"
            )
            for item in new[:40]:
                out.append(f"      NEW  {item}")
            fixed = sorted(base - fails)
            if fixed:
                out.append(f"    failing locally but passing on the box: {len(fixed)}")
        for item in sorted(fails - rerun)[:20]:
            out.append(f"      FLAKY {item}")
    out.append("")
    out.append("== Harness detail ==")
    out.extend(harness_rows)
    out.append("")
    out.append("== Setup ==")
    for name in ("setup-prepare.log", "setup-luks.log", "setup-status.txt"):
        for line in lines_of(dest / name):
            if (
                line.startswith(
                    (
                        "[setup",
                        "  table:",
                        "  type",
                        "  cipher",
                        "  integrity",
                        "runsc",
                        "docker",
                        "state",
                        "swaps",
                        "ERROR",
                    )
                )
                or "ERROR" in line
            ):
                out.append(f"  {line}")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
