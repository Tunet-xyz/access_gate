from __future__ import annotations

from tools.authorization_benchmark import (
    BenchmarkBudgets,
    BenchmarkConfig,
    enforce_budgets,
    run_benchmarks,
)


def test_assurance_benchmark_produces_enforceable_metrics() -> None:
    metrics = run_benchmarks(
        BenchmarkConfig(
            collection_items=100,
            indexed_policies=100,
            decisions=10,
            repeats=1,
        )
    )

    assert set(metrics) == {
        "collection_seconds",
        "engine_build_seconds",
        "indexed_decisions_seconds",
        "peak_memory_mib",
    }
    assert enforce_budgets(
        metrics,
        BenchmarkBudgets(10.0, 10.0, 10.0, 256.0),
    ) == []


def test_assurance_benchmark_reports_budget_failures() -> None:
    metrics = {
        "collection_seconds": 1.0,
        "engine_build_seconds": 1.0,
        "indexed_decisions_seconds": 1.0,
        "peak_memory_mib": 1.0,
    }

    assert len(enforce_budgets(metrics, BenchmarkBudgets(0.0, 0.0, 0.0, 0.0))) == 4
