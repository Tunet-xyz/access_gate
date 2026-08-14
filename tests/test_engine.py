from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pytest

from access_gate import (
    AuthorizationDenied,
    AuthorizationEngine,
    AuthorizationRequest,
    Decision,
    Effect,
    ErrorMode,
    FunctionPolicy,
    Subject,
)


def request() -> AuthorizationRequest:
    return AuthorizationRequest(Subject("user-1"), "records.read")


def test_no_matching_policy_is_denied() -> None:
    decision = AuthorizationEngine([]).decide(request())

    assert decision.effect is Effect.DENY
    assert decision.policy == "access_gate.default_deny"


def test_policy_names_must_be_unique_and_valid() -> None:
    first = FunctionPolicy("duplicate", lambda value: None)
    second = FunctionPolicy("duplicate", lambda value: None)

    with pytest.raises(ValueError, match="unique"):
        AuthorizationEngine([first, second])

    class Nameless:
        def evaluate(self, value: AuthorizationRequest) -> None:
            del value

    with pytest.raises(TypeError, match="non-empty string name"):
        AuthorizationEngine([Nameless()])  # type: ignore[list-item]


def test_policy_set_identifier_is_engine_owned_and_audited() -> None:
    policy = FunctionPolicy(
        "allow",
        lambda value: Decision.allow(
            "Allowed.",
            metadata={"policy_set_id": "spoofed"},
        ),
    )
    recorder = Recorder([])
    engine = AuthorizationEngine(
        [policy],
        policy_set_id="sha256:0123456789abcdef",
        audit_sink=recorder,
    )

    decision = engine.decide(request())

    assert decision.metadata["policy_set_id"] == "sha256:0123456789abcdef"
    assert engine.policy_set_id == "sha256:0123456789abcdef"
    assert recorder.values == [(request(), decision)]


@pytest.mark.parametrize("value", ["", "unsafe value", "x" * 257])
def test_policy_set_identifier_is_validated(value: str) -> None:
    with pytest.raises(ValueError, match="policy_set_id"):
        AuthorizationEngine([], policy_set_id=value)


def test_explicit_allow_grants_access() -> None:
    policy = FunctionPolicy(
        "allow_read",
        lambda value: Decision.allow("Readable.", policy="allow_read"),
    )

    decision = AuthorizationEngine([policy]).decide(request())

    assert decision.allowed
    assert decision.policy == "allow_read"


def test_deny_overrides_allow_regardless_of_order() -> None:
    allow = FunctionPolicy("allow", lambda value: Decision.allow("Allowed.", policy="allow"))
    deny = FunctionPolicy("deny", lambda value: Decision.deny("Denied.", policy="deny"))

    first = AuthorizationEngine([allow, deny]).decide(request())
    second = AuthorizationEngine([deny, allow]).decide(request())

    assert not first.allowed
    assert not second.allowed
    assert first.policy == second.policy == "deny"


def test_policy_failure_denies_without_leaking_exception_text() -> None:
    def explode(value: AuthorizationRequest) -> Decision | None:
        raise RuntimeError("database password should never enter the reason")

    decision = AuthorizationEngine([FunctionPolicy("broken", explode)]).decide(request())

    assert not decision.allowed
    assert decision.policy == "broken"
    assert decision.metadata == {"error_type": "RuntimeError"}
    assert "password" not in decision.reason


def test_policy_failure_can_be_raised_for_host_level_handling() -> None:
    def explode(value: AuthorizationRequest) -> Decision | None:
        raise RuntimeError("boom")

    engine = AuthorizationEngine(
        [FunctionPolicy("broken", explode)],
        policy_error_mode=ErrorMode.RAISE,
    )

    with pytest.raises(RuntimeError, match="boom"):
        engine.decide(request())


def test_invalid_policy_result_fails_closed() -> None:
    policy = FunctionPolicy("invalid", lambda value: "allow")  # type: ignore[arg-type]

    decision = AuthorizationEngine([policy]).decide(request())

    assert not decision.allowed
    assert decision.policy == "invalid"
    assert decision.metadata == {"error_type": "TypeError"}


def test_invalid_error_mode_configuration_is_rejected() -> None:
    with pytest.raises(TypeError, match="ErrorMode"):
        AuthorizationEngine([], policy_error_mode="deny")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="cannot ignore"):
        AuthorizationEngine([], strategy_error_mode=ErrorMode.IGNORE)


class BrokenStrategy:
    def combine(
        self,
        value: AuthorizationRequest,
        decisions: Sequence[Decision],
    ) -> Decision:
        raise RuntimeError("sensitive strategy detail")


def test_strategy_failure_denies_with_redacted_metadata() -> None:
    decision = AuthorizationEngine([], strategy=BrokenStrategy()).decide(request())

    assert not decision.allowed
    assert decision.policy == "access_gate.strategy"
    assert decision.metadata == {"error_type": "RuntimeError"}
    assert "sensitive" not in decision.reason


def test_strategy_failure_can_be_raised() -> None:
    engine = AuthorizationEngine(
        [],
        strategy=BrokenStrategy(),
        strategy_error_mode=ErrorMode.RAISE,
    )

    with pytest.raises(RuntimeError, match="sensitive strategy detail"):
        engine.decide(request())


class InvalidStrategy:
    def combine(
        self,
        value: AuthorizationRequest,
        decisions: Sequence[Decision],
    ) -> Decision:
        return "allow"  # type: ignore[return-value]


def test_invalid_strategy_result_fails_closed() -> None:
    decision = AuthorizationEngine([], strategy=InvalidStrategy()).decide(request())

    assert not decision.allowed
    assert decision.metadata == {"error_type": "TypeError"}


def test_ignore_modes_are_explicit_and_audit_raise_is_supported() -> None:
    broken = FunctionPolicy("broken", lambda value: 1 / 0)
    allow = FunctionPolicy("allow", lambda value: Decision.allow("Allowed."))
    ignored_policy_error = AuthorizationEngine(
        [broken, allow],
        policy_error_mode=ErrorMode.IGNORE,
    ).decide(request())
    ignored_audit_error = AuthorizationEngine(
        [allow],
        audit_sink=BrokenAuditSink(),
        audit_error_mode=ErrorMode.IGNORE,
    ).decide(request())

    assert ignored_policy_error.allowed
    assert ignored_audit_error.allowed
    with pytest.raises(OSError, match="unavailable"):
        AuthorizationEngine(
            [allow],
            audit_sink=BrokenAuditSink(),
            audit_error_mode=ErrorMode.RAISE,
        ).decide(request())


def test_remaining_error_mode_types_are_validated() -> None:
    with pytest.raises(TypeError, match="strategy_error_mode"):
        AuthorizationEngine([], strategy_error_mode="deny")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="audit_error_mode"):
        AuthorizationEngine([], audit_error_mode="deny")  # type: ignore[arg-type]


def test_async_policy_result_is_closed_and_denied() -> None:
    async def async_policy(value: AuthorizationRequest) -> Decision:
        return Decision.allow("Allowed.")

    policy = FunctionPolicy("async", async_policy)  # type: ignore[arg-type]

    decision = AuthorizationEngine([policy]).decide(request())

    assert not decision.allowed
    assert decision.policy == "async"
    assert decision.metadata == {"error_type": "TypeError"}


class AsyncStrategy:
    def combine(
        self,
        value: AuthorizationRequest,
        decisions: Sequence[Decision],
    ) -> Decision:
        async def result() -> Decision:
            return Decision.allow("Allowed.")

        return result()  # type: ignore[return-value]


def test_async_strategy_result_is_closed_and_denied() -> None:
    decision = AuthorizationEngine([], strategy=AsyncStrategy()).decide(request())

    assert not decision.allowed
    assert decision.policy == "access_gate.strategy"


class InvalidAuditSink:
    def record(self, value: AuthorizationRequest, decision: Decision) -> None:
        return "recorded"  # type: ignore[return-value]


class AsyncAuditSink:
    async def record(self, value: AuthorizationRequest, decision: Decision) -> None:
        return None


@pytest.mark.parametrize("sink", [InvalidAuditSink(), AsyncAuditSink()])
def test_invalid_or_async_audit_sink_results_deny(sink: object) -> None:
    allow = FunctionPolicy("allow", lambda value: Decision.allow("Allowed."))

    decision = AuthorizationEngine([allow], audit_sink=sink).decide(request())  # type: ignore[arg-type]

    assert not decision.allowed
    assert decision.policy == "access_gate.audit"
    assert decision.metadata == {"error_type": "TypeError"}


def test_action_targeted_policies_are_indexed_without_reordering() -> None:
    called: list[str] = []

    def policy(name: str, *, actions: set[str] | None = None) -> FunctionPolicy:
        def evaluate(value: AuthorizationRequest) -> Decision | None:
            called.append(name)
            return Decision.allow("Allowed.", policy=name) if name == "target" else None

        return FunctionPolicy(name, evaluate, actions=actions)

    engine = AuthorizationEngine(
        [
            policy("global-first"),
            policy("other", actions={"other.read"}),
            policy("target", actions={"records.read"}),
            policy("global-last"),
        ]
    )

    decision = engine.decide(request())

    assert decision.allowed
    assert called == ["global-first", "target", "global-last"]


def test_decide_many_preserves_order_and_audits_each_request() -> None:
    recorder = Recorder([])
    engine = AuthorizationEngine(
        [
            FunctionPolicy(
                "read",
                lambda value: Decision.allow("Allowed.", policy=value.action),
                actions=frozenset({"records.read"}),
            )
        ],
        audit_sink=recorder,
    )
    requests = (
        request(),
        AuthorizationRequest(Subject("user-1"), "records.write"),
    )

    decisions = engine.decide_many(requests)

    assert decisions[0].allowed
    assert not decisions[1].allowed
    assert [recorded_request for recorded_request, _ in recorder.values] == list(requests)


@dataclass
class Recorder:
    values: list[tuple[AuthorizationRequest, Decision]]

    def record(self, value: AuthorizationRequest, decision: Decision) -> None:
        self.values.append((value, decision))


def test_final_decision_is_audited() -> None:
    recorder = Recorder([])
    engine = AuthorizationEngine(
        [FunctionPolicy("allow", lambda value: Decision.allow("Allowed."))],
        audit_sink=recorder,
    )

    decision = engine.decide(request())

    assert recorder.values == [(request(), decision)]


class BrokenAuditSink:
    def record(self, value: AuthorizationRequest, decision: Decision) -> None:
        raise OSError("unavailable")


def test_audit_failure_denies_by_default() -> None:
    engine = AuthorizationEngine(
        [FunctionPolicy("allow", lambda value: Decision.allow("Allowed."))],
        audit_sink=BrokenAuditSink(),
    )

    decision = engine.decide(request())

    assert not decision.allowed
    assert decision.policy == "access_gate.audit"
    assert decision.metadata == {"error_type": "OSError"}


def test_enforce_raises_with_the_decision() -> None:
    engine = AuthorizationEngine([])

    with pytest.raises(AuthorizationDenied) as caught:
        engine.enforce(request())

    assert caught.value.decision.policy == "access_gate.default_deny"
