"""Sealed bench / SDK adapter contracts (Eng-owned scaffolds).

Mirrors cathedral-site ``src/lib/adapters``: ComputeSDK, Sandbox Bench, Frontier
Harness, Harbor Index. Status stays ``coming-soon`` until published evidence.
Does not invent digests, TTI marketing numbers, or flip prod flags.
"""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Any

COMPUTESDK_PROVIDER_ID = "cathedral-sealed"
SANDBOX_BENCH_ADAPTER_ID = "cathedral-sealed"
FRONTIER_HARNESS_ID = "cathedral-frontier"
HARBOR_INDEX_ADAPTER_ID = "cathedral-harbor-index"
COMING_SOON = "coming-soon"
HARBOR_TB_SCHEMA = "cathedral_harbor_terminal_bench_v1"
HARBOR_TB_DATASET = "terminal-bench@2.0"
HARBOR_TB_COMMIT = "69671fbaac6d67a7ef0dfec016cc38a64ef7a77c"
# Pinned in cathedral-harbor terminal_bench.py at HARBOR_TB_COMMIT.
HARBOR_TB_TASKS = frozenset((
    "adaptive-rejection-sampler", "bn-fit-modify", "break-filter-js-from-html",
    "build-cython-ext", "build-pmars", "build-pov-ray", "caffe-cifar-10",
    "cancel-async-tasks", "chess-best-move", "circuit-fibsqrt",
    "cobol-modernization", "code-from-image", "compile-compcert",
    "configure-git-webserver", "constraints-scheduling", "count-dataset-tokens",
    "crack-7z-hash", "custom-memory-heap-crash", "db-wal-recovery",
    "distribution-search", "dna-assembly",
))
_UNSIGNED_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,18})?\Z")


def _unsigned_decimal(value: Any) -> bool:
    return isinstance(value, str) and _UNSIGNED_DECIMAL.fullmatch(value) is not None


def _measured_harbor_report(summary: Any) -> bool:
    """Validate the exported summary shape; receipt verification stays with Harbor."""
    if not isinstance(summary, dict) or any((
        summary.get("schema") != HARBOR_TB_SCHEMA,
        summary.get("dataset") != HARBOR_TB_DATASET,
        summary.get("commit") != HARBOR_TB_COMMIT,
        summary.get("task_count") != len(HARBOR_TB_TASKS),
        summary.get("verdict") != "measured",
        summary.get("measured") is not True,
    )):
        return False
    trials, totals, failures = summary.get("trials"), summary.get("totals"), summary.get("failures")
    if not isinstance(trials, list) or len(trials) != len(HARBOR_TB_TASKS):
        return False
    if not isinstance(totals, dict) or not isinstance(failures, list):
        return False
    if any(not isinstance(trial, dict) for trial in trials):
        return False
    names = [trial.get("task") for trial in trials]
    if any(not isinstance(name, str) for name in names) or set(names) != HARBOR_TB_TASKS:
        return False
    expected_failures = []
    for trial in trials:
        exit_code = trial.get("exit_code")
        duration = trial.get("command_duration_ms")
        if any((
            trial.get("cost_estimated") is not False,
            not _unsigned_decimal(trial.get("cost_usd")),
            not _unsigned_decimal(trial.get("running_seconds")),
            trial.get("chain_ok") is not True,
            not isinstance(trial.get("chain_failures"), list),
            trial.get("chain_failures") != [],
            trial.get("exec_state") != "exited",
            trial.get("failure") is not None,
            trial.get("hardware") != "amd_sev_snp",
            type(exit_code) is not int or abs(exit_code) > (1 << 53) - 1,
            type(duration) is not int or duration < 0,
        )):
            return False
        if exit_code != 0:
            expected_failures.append({
                "task": trial["task"], "code": "command_exit", "detail": str(exit_code),
            })
    if failures != expected_failures:
        return False
    if totals.get("source") != "GET /v1/usage?group_by=sandbox_id":
        return False
    if not _unsigned_decimal(totals.get("cost_usd")):
        return False
    if not _unsigned_decimal(totals.get("running_seconds")):
        return False
    return (
        sum((Decimal(trial["cost_usd"]) for trial in trials), Decimal(0))
        == Decimal(totals["cost_usd"])
        and sum((Decimal(trial["running_seconds"]) for trial in trials), Decimal(0))
        == Decimal(totals["running_seconds"])
    )


def computesdk_provider_contract() -> dict[str, Any]:
    return {
        "id": COMPUTESDK_PROVIDER_ID,
        "status": COMING_SOON,
        "methods": [
            "create_sandbox",
            "wait_running",
            "run_command",
            "burst_time_to_interactive",
            "destroy",
        ],
        "evidence_path": "/proof/computesdk/summary.json",
        "docs": "https://cathedral.computer/docs/products/computesdk/",
    }


def sandbox_bench_contract() -> dict[str, Any]:
    return {
        "id": SANDBOX_BENCH_ADAPTER_ID,
        "status": COMING_SOON,
        "methods": ["create", "exec", "teardown", "evidence"],
        "evidence_path": "/proof/sandbox-bench/summary.json",
        "docs": "https://cathedral.computer/docs/products/sandbox-bench/",
    }


def frontier_harness_contract() -> dict[str, Any]:
    return {
        "id": FRONTIER_HARNESS_ID,
        "status": COMING_SOON,
        "methods": ["run_trial", "run_suite"],
        "evidence_path": "/proof/frontier-harness/summary.json",
        "docs": "https://cathedral.computer/docs/products/frontier-harness/",
    }


def harbor_index_contract() -> dict[str, Any]:
    return {
        "id": HARBOR_INDEX_ADAPTER_ID,
        "status": COMING_SOON,
        "methods": ["harbor_index_from_terminal_bench_summary"],
        "docs": "https://cathedral.computer/docs/products/terminal-bench/",
    }


def adapter_contracts() -> list[dict[str, Any]]:
    return [
        computesdk_provider_contract(),
        sandbox_bench_contract(),
        frontier_harness_contract(),
        harbor_index_contract(),
    ]


def harbor_index_from_terminal_bench_summary(summary: dict[str, Any] | None) -> dict[str, Any]:
    measured = _measured_harbor_report(summary)
    trials = summary["trials"] if measured else []
    failures = summary["failures"] if measured else []
    totals = summary["totals"] if measured else None
    return {
        "adapter": HARBOR_INDEX_ADAPTER_ID,
        "status": "ready" if measured else COMING_SOON,
        "dataset": HARBOR_TB_DATASET,
        "provider": "cathedral-sealed",
        "hardware": "amd_sev_snp",
        "measured": measured,
        "task_count": len(trials),
        "cost_usd": totals["cost_usd"] if measured else None,
        "running_seconds": totals["running_seconds"] if measured else None,
        "failures": failures,
        "source": totals["source"] if measured else None,
    }
