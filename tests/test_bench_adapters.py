from copy import deepcopy

from cathedral.bench_adapters import (
    HARBOR_TB_COMMIT,
    HARBOR_TB_DATASET,
    HARBOR_TB_SCHEMA,
    HARBOR_TB_TASKS,
    adapter_contracts,
    computesdk_provider_contract,
    frontier_harness_contract,
    harbor_index_from_terminal_bench_summary,
    sandbox_bench_contract,
)


def test_adapter_contracts_are_coming_soon():
    contracts = adapter_contracts()
    assert len(contracts) == 4
    for row in contracts:
        assert row["status"] == "coming-soon"
        assert row["id"]
        assert row["methods"]


def test_individual_contracts():
    assert computesdk_provider_contract()["id"] == "cathedral-sealed"
    assert sandbox_bench_contract()["id"] == "cathedral-sealed"
    assert frontier_harness_contract()["id"] == "cathedral-frontier"


def test_harbor_index_honest_without_summary():
    mapped = harbor_index_from_terminal_bench_summary(None)
    assert mapped["measured"] is False
    assert mapped["cost_usd"] is None
    assert mapped["status"] == "coming-soon"


def measured_summary():
    trials = [{
        "task": task,
        "sandbox_id": f"sbx_{task}",
        "cost_estimated": False,
        "cost_usd": "0.01",
        "running_seconds": "3.5",
        "chain_ok": True,
        "chain_failures": [],
        "exec_state": "exited",
        "exit_code": 1 if task == "dna-assembly" else 0,
        "failure": None,
        "hardware": "amd_sev_snp",
        "command_duration_ms": 3500,
    } for task in sorted(HARBOR_TB_TASKS)]
    return {
        "schema": HARBOR_TB_SCHEMA,
        "dataset": HARBOR_TB_DATASET,
        "commit": HARBOR_TB_COMMIT,
        "task_count": len(trials),
        "verdict": "measured",
        "measured": True,
        "totals": {
            "cost_usd": "0.21",
            "running_seconds": "73.5",
            "source": "GET /v1/usage?group_by=sandbox_id",
        },
        "failures": [{"task": "dna-assembly", "code": "command_exit", "detail": "1"}],
        "trials": trials,
    }


def test_harbor_index_valid_measured_report():
    mapped = harbor_index_from_terminal_bench_summary(measured_summary())
    assert mapped["measured"] is True
    assert mapped["status"] == "ready"
    assert mapped["task_count"] == 21
    assert mapped["cost_usd"] == "0.21"
    assert mapped["failures"] == [{"task": "dna-assembly", "code": "command_exit", "detail": "1"}]


def test_harbor_index_rejects_incomplete_or_contradictory_reports():
    variants = []
    variants.append({"measured": True, "totals": {"cost_usd": "1"}})
    missing_failure = measured_summary()
    missing_failure["failures"] = []
    variants.append(missing_failure)
    wrong_total = measured_summary()
    wrong_total["totals"]["cost_usd"] = "999"
    variants.append(wrong_total)
    missing_chain = measured_summary()
    missing_chain["trials"][0]["chain_failures"] = [{"code": "missing"}]
    variants.append(missing_chain)
    duplicate_task = measured_summary()
    duplicate_task["trials"][0]["task"] = duplicate_task["trials"][1]["task"]
    variants.append(duplicate_task)
    wrong_commit = measured_summary()
    wrong_commit["commit"] = "unverified"
    variants.append(wrong_commit)
    missing_exit = measured_summary()
    missing_exit["trials"][0].pop("exit_code")
    variants.append(missing_exit)
    malformed_task = measured_summary()
    malformed_task["trials"][0]["task"] = []
    variants.append(malformed_task)
    duplicate_sandbox = measured_summary()
    duplicate_sandbox["trials"][0]["sandbox_id"] = duplicate_sandbox["trials"][1]["sandbox_id"]
    variants.append(duplicate_sandbox)
    missing_sandbox = measured_summary()
    missing_sandbox["trials"][0].pop("sandbox_id")
    variants.append(missing_sandbox)
    for variant in variants:
        mapped = harbor_index_from_terminal_bench_summary(deepcopy(variant))
        assert mapped["measured"] is False
        assert mapped["status"] == "coming-soon"
        assert mapped["task_count"] == 0
        assert mapped["cost_usd"] is None
        assert mapped["failures"] == []
