from __future__ import annotations

from types import MappingProxyType

import pytest

from access_gate import abac
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


def test_assurance_benchmark_times_a_matching_comparison_at_the_size_limit() -> None:
    config = BenchmarkConfig(
        collection_items=abac.MAX_COLLECTION_ITEMS,
        indexed_policies=10,
        decisions=1,
        repeats=1,
    )
    assert run_benchmarks(config)["collection_seconds"] > 0

    with pytest.raises(ValueError, match="collection size limit"):
        run_benchmarks(
            BenchmarkConfig(
                collection_items=abac.MAX_COLLECTION_ITEMS + 1,
                indexed_policies=10,
                decisions=1,
                repeats=1,
            )
        )


def test_assurance_benchmark_rejects_a_comparison_that_does_not_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Policies share the operator table built at import, so replace that table.
    operators = dict(abac._BUILTIN_OPERATORS, intersects=lambda left, right: False)
    monkeypatch.setattr(abac, "_BUILTIN_OPERATORS", MappingProxyType(operators))

    with pytest.raises(RuntimeError, match="expected an allow from 'collection'"):
        run_benchmarks(
            BenchmarkConfig(collection_items=100, indexed_policies=10, decisions=1, repeats=1)
        )
