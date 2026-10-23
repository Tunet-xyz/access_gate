"""Repeatable performance and resource budgets for security-critical paths."""

from __future__ import annotations

import argparse
import json
import time
import tracemalloc
from dataclasses import asdict, dataclass

from access_gate import (
    AttributePolicy,
    AuthorizationEngine,
    AuthorizationRequest,
    ContextAttribute,
    Decision,
    FunctionPolicy,
    Subject,
)
from access_gate.abac import MAX_COLLECTION_ITEMS


@dataclass(frozen=True)
class BenchmarkConfig:
    collection_items: int = 10_000
    indexed_policies: int = 10_000
    decisions: int = 1_000
    repeats: int = 5


@dataclass(frozen=True)
class BenchmarkBudgets:
    collection_seconds: float = 0.5
    engine_build_seconds: float = 5.0
    indexed_decisions_seconds: float = 1.0
    peak_memory_mib: float = 128.0


def _best_seconds(operation: object, repeats: int) -> float:
    if not callable(operation):
        raise TypeError("operation must be callable.")
    samples: list[float] = []
    for _ in range(repeats):
        started = time.perf_counter()
        operation()
        samples.append(time.perf_counter() - started)
    return min(samples)


def _require_allow(decision: Decision | None, policy: str) -> None:
    if decision is None or not decision.allowed or decision.policy != policy:
        raise RuntimeError(f"benchmark expected an allow from {policy!r}, got {decision!r}.")


def run_benchmarks(config: BenchmarkConfig | None = None) -> dict[str, float]:
    """Measure bounded collection matching and action-indexed evaluation."""

    config = config or BenchmarkConfig()
    if min(
        config.collection_items,
        config.indexed_policies,
        config.decisions,
        config.repeats,
    ) <= 0:
        raise ValueError("benchmark sizes and repeats must be positive.")
    if config.collection_items > MAX_COLLECTION_ITEMS:
        raise ValueError("collection_items must not exceed the ABAC collection size limit.")

    # Both operands hold exactly collection_items values and share one, so the
    # timed comparison runs to completion instead of stopping at a bound check.
    values = list(range(config.collection_items))
    overlap = list(range(config.collection_items - 1, config.collection_items * 2 - 1))
    request = AuthorizationRequest(
        Subject("benchmark-subject"),
        "records.read",
        context={"left": values, "right": overlap},
    )
    collection_policy = AttributePolicy(
        ContextAttribute("left").intersects(ContextAttribute("right")),
        name="collection",
    )
    _require_allow(collection_policy.evaluate(request), "collection")
    collection_seconds = _best_seconds(
        lambda: collection_policy.evaluate(request),
        config.repeats,
    )

    tracemalloc.start()
    build_started = time.perf_counter()
    policies = [
        FunctionPolicy(
            f"irrelevant-{index}",
            lambda value: Decision.deny("Must not run."),
            actions={f"other.action.{index}"},
        )
        for index in range(config.indexed_policies)
    ]
    policies.append(
        FunctionPolicy(
            "target",
            lambda value: Decision.allow("Allowed.", policy="target"),
            actions={"records.read"},
        )
    )
    engine = AuthorizationEngine(policies)
    engine_build_seconds = time.perf_counter() - build_started
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    decision_request = AuthorizationRequest(Subject("benchmark-subject"), "records.read")
    _require_allow(engine.decide(decision_request), "target")
    indexed_decisions_seconds = _best_seconds(
        lambda: [engine.decide(decision_request) for _ in range(config.decisions)],
        config.repeats,
    )
    return {
        "collection_seconds": collection_seconds,
        "engine_build_seconds": engine_build_seconds,
        "indexed_decisions_seconds": indexed_decisions_seconds,
        "peak_memory_mib": peak_bytes / (1024 * 1024),
    }


def enforce_budgets(
    metrics: dict[str, float],
    budgets: BenchmarkBudgets | None = None,
) -> list[str]:
    budgets = budgets or BenchmarkBudgets()
    failures: list[str] = []
    for name, budget in asdict(budgets).items():
        actual = metrics[name]
        if actual > budget:
            failures.append(f"{name}={actual:.6f} exceeded budget={budget:.6f}")
    return failures


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enforce", action="store_true", help="fail when a budget is exceeded")
    args = parser.parse_args()
    config = BenchmarkConfig()
    budgets = BenchmarkBudgets()
    metrics = run_benchmarks(config)
    result = {
        "schema_version": "access_gate.performance.v1",
        "config": asdict(config),
        "budgets": asdict(budgets),
        "metrics": metrics,
        "failures": enforce_budgets(metrics, budgets),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.enforce and result["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
