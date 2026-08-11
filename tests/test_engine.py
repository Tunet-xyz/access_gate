from __future__ import annotations

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
