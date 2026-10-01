"""Run the conformance checks and write one JSON report.

    CATHEDRAL_API_KEY=cat_sk_... cathedral-conformance --report report.json

Exit status: 0 when every mvp check passes (every check with --strict),
1 otherwise, 2 for a usage error. Everything the run created is deleted at the
end, including after a crash, and swept again by the run's label.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone

from cathedral.conformance.api import Api
from cathedral.conformance.checks import CHECKS, Check, Config, Context, Result

# Checks that change shared state run last: fork deletes the primary sandbox,
# and quota.full_429 fills the quota.
RUN_LAST = ("snapshot.fork", "quota.full_429")


def ordered(checks: list[Check], only: set[str] | None) -> list[Check]:
    picked = [c for c in checks if not only or c.id in only]
    return [c for c in picked if c.id not in RUN_LAST] + [
        c for name in RUN_LAST for c in picked if c.id == name
    ]


def run(api: Api, config: Config, only: set[str] | None = None, strict: bool = False,
        log=lambda line: None) -> dict:
    ctx = Context(api, config)
    results: list[Result] = []
    started = datetime.now(timezone.utc)
    try:
        for check in ordered(CHECKS, only):
            if check.needs_primary and ctx.primary is None:
                why = ctx.primary_failure or "create.first did not run"
                result = Result(check.id, check.title, check.spec, check.tier, "skip", check.threshold,
                                detail=f"no running sandbox: {why}")
            else:
                began = time.monotonic()
                try:
                    status, measured, detail = check.run(ctx)
                except Exception as exc:  # a check bug or an unexpected answer is a fail, with the reason
                    status, measured, detail = "fail", {}, f"{type(exc).__name__}: {exc}"
                measured.setdefault("check_s", round(time.monotonic() - began, 1))
                result = Result(check.id, check.title, check.spec, check.tier, status, check.threshold,
                                measured, detail)
            results.append(result)
            log(f"{result.status.upper():4}  {result.id:20} {json.dumps(result.measured)[:160]}")
    finally:
        cleanup = ctx.cleanup()
    gating = [r for r in results if strict or r.tier == "mvp"]
    return {
        "suite": "cathedral-conformance",
        "version": 1,
        "spec": "Affine sandbox API requirements, 2026-09-22",
        "run_id": config.run_id,
        "api_url": api.base_url,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "strict": strict,
        "passed": all(r.status == "pass" for r in gating),
        "counts": {s: sum(1 for r in results if r.status == s) for s in ("pass", "fail", "skip")},
        "config": asdict(config),
        "results": [asdict(r) for r in results],
        "cleanup": cleanup,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cathedral-conformance", description=__doc__.split("\n\n")[0])
    parser.add_argument("--api-url", default=os.environ.get("CATHEDRAL_API_URL", "https://cathedral.computer"))
    parser.add_argument("--team", default=os.environ.get("CATHEDRAL_TEAM"))
    parser.add_argument("--report", help="write the JSON report here (default: stdout)")
    parser.add_argument("--only", help="comma-separated check ids")
    parser.add_argument("--list", action="store_true", help="list checks and exit")
    parser.add_argument("--strict", action="store_true", help="later-tier checks also gate the result")
    parser.add_argument("--image", default=Config.image)
    parser.add_argument("--template")
    parser.add_argument("--samples", type=int, default=Config.samples)
    parser.add_argument("--exec-samples", type=int, default=Config.exec_samples)
    parser.add_argument("--fork-count", type=int, default=Config.fork_count)
    parser.add_argument("--burst", type=int, default=Config.burst,
                        help="concurrent creates for create.burst_tti (ComputeSDK runs 100)")
    parser.add_argument("--max-fill", type=int, default=Config.max_fill,
                        help="most sandboxes quota.full_429 may create to reach the limit")
    parser.add_argument("--max-spend-usd", default=Config.max_spend_usd, help="per-sandbox spend cap")
    args = parser.parse_args(argv)

    if args.list:
        for c in ordered(CHECKS, None):
            print(f"{c.id:20} {c.tier:5} {c.spec:14} {c.threshold}")
        return 0
    key = os.environ.get("CATHEDRAL_API_KEY")
    if not key:
        print("CATHEDRAL_API_KEY is required (a key with the sandboxes:control scope).", file=sys.stderr)
        return 2
    only = set(args.only.split(",")) if args.only else None
    unknown = (only or set()) - {c.id for c in CHECKS}
    if unknown:
        print(f"unknown check ids: {sorted(unknown)}", file=sys.stderr)
        return 2
    config = Config(image=args.image, template=args.template, samples=args.samples,
                    exec_samples=args.exec_samples, fork_count=args.fork_count, burst=args.burst,
                    max_fill=args.max_fill, max_spend_usd=args.max_spend_usd)
    report = run(Api(args.api_url, key, team=args.team), config, only, args.strict,
                 log=lambda line: print(line, file=sys.stderr))
    text = json.dumps(report, indent=2)
    if args.report:
        with open(args.report, "w") as handle:
            handle.write(text + "\n")
    else:
        print(text)
    print(f"{'PASS' if report['passed'] else 'FAIL'} {report['counts']} run {config.run_id}", file=sys.stderr)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
