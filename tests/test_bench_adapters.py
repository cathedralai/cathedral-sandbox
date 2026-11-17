from cathedral.bench_adapters import (
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
