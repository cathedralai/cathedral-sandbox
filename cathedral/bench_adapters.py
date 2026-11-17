"""Sealed bench / SDK adapter contracts (Eng-owned scaffolds).

Mirrors cathedral-site ``src/lib/adapters``: ComputeSDK, Sandbox Bench, Frontier
Harness, Harbor Index. Status stays ``coming-soon`` until published evidence.
Does not invent digests, TTI marketing numbers, or flip prod flags.
"""

from __future__ import annotations

from typing import Any

COMPUTESDK_PROVIDER_ID = "cathedral-sealed"
SANDBOX_BENCH_ADAPTER_ID = "cathedral-sealed"
FRONTIER_HARNESS_ID = "cathedral-frontier"
HARBOR_INDEX_ADAPTER_ID = "cathedral-harbor-index"
COMING_SOON = "coming-soon"


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
    measured = bool(summary and summary.get("measured") is True and summary.get("totals"))
    trials = summary.get("trials") if isinstance(summary, dict) else None
    failures = summary.get("failures") if isinstance(summary, dict) else None
    totals = summary.get("totals") if isinstance(summary, dict) else None
    return {
        "adapter": HARBOR_INDEX_ADAPTER_ID,
        "status": "ready" if measured else COMING_SOON,
        "dataset": (summary or {}).get("dataset", "terminal-bench@2.0") if summary else "terminal-bench@2.0",
        "provider": "cathedral-sealed",
        "hardware": "amd_sev_snp",
        "measured": measured,
        "task_count": len(trials) if isinstance(trials, list) else 0,
        "cost_usd": totals.get("cost_usd") if measured and isinstance(totals, dict) else None,
        "running_seconds": totals.get("running_seconds") if measured and isinstance(totals, dict) else None,
        "failures": failures if isinstance(failures, list) else [],
        "source": totals.get("source") if measured and isinstance(totals, dict) else None,
    }
