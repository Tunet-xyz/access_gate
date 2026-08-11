"""The framework-neutral authorization engine."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import Enum

from .exceptions import AuthorizationDenied
from .protocols import AuditSink, DecisionStrategy, Policy
from .strategies import DenyOverrides
from .types import AuthorizationRequest, Decision, Resource, Subject


class ErrorMode(str, Enum):
    """How extension failures are handled."""

    DENY = "deny"
    RAISE = "raise"
    IGNORE = "ignore"


class AuthorizationEngine:
    """Evaluate policies with secure defaults and explicit extension points."""

    def __init__(
        self,
        policies: Iterable[Policy],
        *,
        strategy: DecisionStrategy | None = None,
        audit_sink: AuditSink | None = None,
        policy_error_mode: ErrorMode = ErrorMode.DENY,
        audit_error_mode: ErrorMode = ErrorMode.DENY,
    ) -> None:
        self._policies = tuple(policies)
        self._strategy = strategy or DenyOverrides()
        self._audit_sink = audit_sink
        self._policy_error_mode = policy_error_mode
        self._audit_error_mode = audit_error_mode

    @property
    def policies(self) -> tuple[Policy, ...]:
        return self._policies

    def decide(self, request: AuthorizationRequest) -> Decision:
        decisions: list[Decision] = []
        for policy in self._policies:
            try:
                decision = policy.evaluate(request)
            except Exception as error:
                if self._policy_error_mode is ErrorMode.RAISE:
                    raise
                if self._policy_error_mode is ErrorMode.DENY:
                    decisions.append(
                        Decision.deny(
                            "A policy failed during evaluation.",
                            policy=getattr(policy, "name", type(policy).__name__),
                            metadata={"error_type": type(error).__name__},
                        )
                    )
                continue
            if decision is not None:
                decisions.append(decision)

        final = self._strategy.combine(request, decisions)
        return self._record(request, final)

    def authorize(
        self,
        subject: Subject,
        action: str,
        resource: Resource | None = None,
        *,
        context: Mapping[str, object] | None = None,
    ) -> Decision:
        """Convenience API for callers that do not need to construct a request."""

        return self.decide(
            AuthorizationRequest(
                subject=subject,
                action=action,
                resource=resource,
                context=context or {},
            )
        )

    def enforce(self, request: AuthorizationRequest) -> Decision:
        """Return an allowed decision or raise :class:`AuthorizationDenied`."""

        decision = self.decide(request)
        if not decision.allowed:
            raise AuthorizationDenied(decision)
        return decision

    def _record(self, request: AuthorizationRequest, decision: Decision) -> Decision:
        if self._audit_sink is None:
            return decision
        try:
            self._audit_sink.record(request, decision)
        except Exception as error:
            if self._audit_error_mode is ErrorMode.RAISE:
                raise
            if self._audit_error_mode is ErrorMode.DENY:
                return Decision.deny(
                    "The authorization decision could not be audited.",
                    policy="access_gate.audit",
                    metadata={"error_type": type(error).__name__},
                )
        return decision
