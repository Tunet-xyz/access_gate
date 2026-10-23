from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

django = pytest.importorskip("django")
from django.core.exceptions import PermissionDenied  # noqa: E402
from django.http import Http404  # noqa: E402

from access_gate import (  # noqa: E402
    AuthenticatedPolicy,
    AuthorizationEngine,
    AuthorizationRequest,
    Decision,
    Effect,
    ErrorMode,
    Resource,
    RolePolicy,
    Subject,
)
from access_gate.adapters.django import DjangoAuthorizer  # noqa: E402


class _Sink:
    def __init__(self) -> None:
        self.records: list[tuple[AuthorizationRequest, Decision]] = []

    def record(self, request: AuthorizationRequest, decision: Decision) -> None:
        self.records.append((request, decision))


def _request() -> Any:
    user = SimpleNamespace(pk=7, is_authenticated=True, access_gate_roles=("manager",))
    return SimpleNamespace(user=user, method="POST", path="/incidents/1")


def _authorizer(sink: _Sink, **options: Any) -> DjangoAuthorizer:
    return DjangoAuthorizer(
        AuthorizationEngine([RolePolicy({"manager"})], audit_sink=sink, policy_set_id="set-1"),
        denial_handler=lambda request, decision: ("denied", decision),
        **options,
    )


def _boom(*args: object, **kwargs: object) -> Any:
    raise ConnectionError("scope service unavailable")


def _view(request: Any, *args: object, **kwargs: object) -> str:
    raise AssertionError("the view must not run")


def test_resolver_errors_propagate_unaudited_by_default() -> None:
    sink = _Sink()
    view = _authorizer(sink).require("incident.read", resource_resolver=_boom)(_view)

    with pytest.raises(ConnectionError):
        view(_request())
    assert sink.records == []


@pytest.mark.parametrize(
    ("options", "stage", "error_type", "subject_identifier"),
    [
        ({"subject_resolver": _boom}, "subject_resolver", "ConnectionError", ""),
        (
            {"subject_resolver": lambda request: Subject("7", roles={""})},  # type: ignore[arg-type]
            "subject_resolver",
            "TypeError",
            "",
        ),
        ({"context_resolver": _boom}, "context_resolver", "ConnectionError", "7"),
        (
            {"action_attributes_resolver": _boom},
            "action_attributes_resolver",
            "ConnectionError",
            "7",
        ),
        ({"context_resolver": lambda request: {1: "x"}}, "authorization_request", "TypeError", "7"),
    ],
)
def test_deny_mode_audits_each_resolver_stage(
    options: dict[str, Any], stage: str, error_type: str, subject_identifier: str
) -> None:
    sink = _Sink()
    view = _authorizer(sink, resolver_error_mode=ErrorMode.DENY, **options).require(
        "incident.read"
    )(_view)

    outcome, decision = view(_request())

    assert outcome == "denied"
    assert not decision.allowed
    assert decision.policy == "access_gate.resolver"
    assert dict(decision.metadata) == {
        "resolver": stage,
        "error_type": error_type,
        "policy_set_id": "set-1",
    }
    [(audited_request, audited_decision)] = sink.records
    assert audited_decision == decision
    assert audited_request.action == "incident.read"
    assert audited_request.subject.identifier == subject_identifier
    assert dict(audited_request.context) == {"method": "POST", "path": "/incidents/1"}


def test_deny_mode_covers_the_resource_resolver_and_keeps_order() -> None:
    sink = _Sink()
    calls: list[str] = []

    def resource(request: Any, incident_id: str) -> Resource:
        calls.append("resource")
        return Resource("incident", incident_id)

    def subject(request: Any) -> Subject:
        calls.append("subject")
        return Subject("7", roles={"manager"})

    def context(request: Any) -> dict[str, object]:
        calls.append("context")
        raise ConnectionError("unavailable")

    authorizer = _authorizer(
        sink,
        resolver_error_mode=ErrorMode.DENY,
        subject_resolver=subject,
        context_resolver=context,
    )
    outcome, decision = authorizer.require("incident.read", resource_resolver=resource)(_view)(
        _request(), "INC-1"
    )

    assert calls == ["resource", "subject", "context"]
    assert decision.metadata["resolver"] == "context_resolver"
    [(audited_request, _)] = sink.records
    assert audited_request.resource == Resource("incident", "INC-1")
    assert audited_request.subject.identifier == "7"

    sink.records.clear()
    failing = _authorizer(sink, resolver_error_mode=ErrorMode.DENY)
    outcome, decision = failing.require("incident.read", resource_resolver=_boom)(_view)(_request())
    assert decision.metadata["resolver"] == "resource_resolver"
    [(audited_request, _)] = sink.records
    assert audited_request.resource is None
    assert not audited_request.subject.authenticated


@pytest.mark.parametrize("error", [Http404("missing"), PermissionDenied("no")])
def test_deny_mode_lets_django_responses_propagate(error: Exception) -> None:
    sink = _Sink()

    def resource(request: Any) -> Resource:
        raise error

    view = _authorizer(sink, resolver_error_mode=ErrorMode.DENY).require(
        "incident.read", resource_resolver=resource
    )(_view)

    with pytest.raises(type(error)):
        view(_request())
    assert sink.records == []


def test_deny_mode_applies_to_async_views() -> None:
    sink = _Sink()

    async def resource(request: Any) -> Resource:
        raise ConnectionError("unavailable")

    async def deny(request: Any, decision: Decision) -> Decision:
        return decision

    authorizer = DjangoAuthorizer(
        AuthorizationEngine([RolePolicy({"manager"})], audit_sink=sink),
        denial_handler=deny,
        resolver_error_mode=ErrorMode.DENY,
    )

    @authorizer.require("incident.read", resource_resolver=resource)
    async def view(request: Any) -> str:
        raise AssertionError("the view must not run")

    decision = asyncio.run(view(_request()))
    assert decision.policy == "access_gate.resolver"
    assert decision.metadata["resolver"] == "resource_resolver"
    assert len(sink.records) == 1


def test_resolver_error_mode_is_validated() -> None:
    engine = AuthorizationEngine([RolePolicy({"manager"})])
    with pytest.raises(ValueError, match="cannot ignore"):
        DjangoAuthorizer(engine, resolver_error_mode=ErrorMode.IGNORE)
    with pytest.raises(TypeError, match="ErrorMode"):
        DjangoAuthorizer(engine, resolver_error_mode="deny")  # type: ignore[arg-type]


def test_check_returns_an_audited_decision_with_the_configured_resolvers() -> None:
    sink = _Sink()
    authorizer = DjangoAuthorizer(
        AuthorizationEngine([AuthenticatedPolicy(actions={"incident.update"})], audit_sink=sink)
    )

    allowed = authorizer.check(_request(), "incident.update", resource=Resource("incident", "1"))
    anonymous = _request()
    anonymous.user = SimpleNamespace(pk=None, is_authenticated=False)
    denied = asyncio.run(authorizer.acheck(anonymous, "incident.update"))

    assert allowed.allowed and not denied.allowed
    assert [(request.resource, request.context["method"]) for request, _ in sink.records] == [
        (Resource("incident", "1"), "POST"),
        (None, "POST"),
    ]


def test_check_honours_the_resolver_error_mode() -> None:
    sink = _Sink()
    raising = _authorizer(sink, subject_resolver=_boom)
    denying = _authorizer(sink, subject_resolver=_boom, resolver_error_mode=ErrorMode.DENY)

    with pytest.raises(ConnectionError):
        raising.check(_request(), "incident.read")
    decision = denying.check(_request(), "incident.read", resource=Resource("incident", "1"))

    assert decision.policy == "access_gate.resolver"
    [(audited_request, _)] = sink.records
    assert audited_request.resource == Resource("incident", "1")


def test_record_denial_audits_like_a_final_decision() -> None:
    class BrokenSink:
        def record(self, request: AuthorizationRequest, decision: Decision) -> None:
            raise RuntimeError("audit store unavailable")

    request = AuthorizationRequest(Subject("", authenticated=False), "incident.read")
    denial = Decision.deny("Unresolved.", policy="access_gate.resolver")

    recorded = AuthorizationEngine([], policy_set_id="set-1").record_denial(request, denial)
    broken = AuthorizationEngine([], audit_sink=BrokenSink()).record_denial(request, denial)

    assert recorded.metadata["policy_set_id"] == "set-1"
    assert broken.policy == "access_gate.audit"
    with pytest.raises(ValueError, match="deny"):
        AuthorizationEngine([]).record_denial(request, Decision.allow("Allowed."))

    class LooksDenied(Decision):
        __slots__ = ()

        @property
        def allowed(self) -> bool:
            return False

    with pytest.raises(ValueError, match="deny"):
        AuthorizationEngine([], policy_set_id="set-1").record_denial(
            request, LooksDenied(Effect.ALLOW, "Allowed.")
        )
    with pytest.raises(TypeError):
        AuthorizationEngine([]).record_denial(request, None)  # type: ignore[arg-type]
