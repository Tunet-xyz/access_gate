"""The framework-neutral authorization engine."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from enum import Enum
from inspect import isawaitable
from typing import cast

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
        strategy_error_mode: ErrorMode = ErrorMode.DENY,
        audit_error_mode: ErrorMode = ErrorMode.DENY,
        policy_set_id: str | None = None,
    ) -> None:
        if not isinstance(policy_error_mode, ErrorMode):
            raise TypeError("policy_error_mode must be an ErrorMode value.")
        if not isinstance(strategy_error_mode, ErrorMode):
            raise TypeError("strategy_error_mode must be an ErrorMode value.")
        if strategy_error_mode is ErrorMode.IGNORE:
            raise ValueError("strategy_error_mode cannot ignore a missing final decision.")
        if not isinstance(audit_error_mode, ErrorMode):
            raise TypeError("audit_error_mode must be an ErrorMode value.")
        if policy_set_id is not None and (
            not isinstance(policy_set_id, str)
            or len(policy_set_id) > 256
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]*", policy_set_id) is None
        ):
            raise ValueError(
                "policy_set_id must be a bounded identifier containing safe characters."
            )
        self._policies = tuple(policies)
        policy_names: list[str] = []
        for policy in self._policies:
            name = getattr(policy, "name", None)
            if not isinstance(name, str) or not name:
                raise TypeError("Every policy must have a non-empty string name.")
            policy_names.append(name)
        if len(set(policy_names)) != len(policy_names):
            raise ValueError("Policy names must be unique within an authorization engine.")
        global_policies: list[tuple[int, Policy]] = []
        policies_by_action: dict[str, list[tuple[int, Policy]]] = {}
        for index, policy in enumerate(self._policies):
            actions = getattr(policy, "actions", None)
            if isinstance(actions, frozenset) and actions and all(
                isinstance(action, str) and action for action in actions
            ):
                for action in actions:
                    policies_by_action.setdefault(action, []).append((index, policy))
            else:
                global_policies.append((index, policy))
        self._global_policies = tuple(global_policies)
        self._policies_by_action = {
            action: tuple(indexed) for action, indexed in policies_by_action.items()
        }
        self._strategy = strategy or DenyOverrides()
        self._audit_sink = audit_sink
        self._policy_error_mode = policy_error_mode
        self._strategy_error_mode = strategy_error_mode
        self._audit_error_mode = audit_error_mode
        self._policy_set_id = policy_set_id

    @property
    def policies(self) -> tuple[Policy, ...]:
        return self._policies

    @property
    def policy_set_id(self) -> str | None:
        return self._policy_set_id

    def decide(self, request: AuthorizationRequest) -> Decision:
        decisions: list[Decision] = []
        for policy in self._policies_for_action(request.action):
            try:
                decision = policy.evaluate(request)
                if decision is not None and not isinstance(decision, Decision):
                    self._close_awaitable(decision)
                    raise TypeError("A policy returned an invalid decision value.")
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

        try:
            final = self._strategy.combine(request, decisions)
            if not isinstance(final, Decision):
                self._close_awaitable(final)
                raise TypeError("The decision strategy returned an invalid value.")
        except Exception as error:
            if self._strategy_error_mode is ErrorMode.RAISE:
                raise
            final = Decision.deny(
                "The decision strategy failed.",
                policy="access_gate.strategy",
                metadata={"error_type": type(error).__name__},
            )
        return self._record(request, self._annotate(final))

    def decide_many(self, requests: Iterable[AuthorizationRequest]) -> tuple[Decision, ...]:
        """Evaluate a batch while preserving request order and audit behavior."""

        return tuple(self.decide(request) for request in requests)

    def authorize(
        self,
        subject: Subject,
        action: str,
        resource: Resource | None = None,
        *,
        context: Mapping[str, object] | None = None,
        action_attributes: Mapping[str, object] | None = None,
    ) -> Decision:
        """Convenience API for callers that do not need to construct a request."""

        return self.decide(
            AuthorizationRequest(
                subject=subject,
                action=action,
                resource=resource,
                context=context or {},
                action_attributes=action_attributes or {},
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
            audit_record = cast(
                Callable[[AuthorizationRequest, Decision], object],
                self._audit_sink.record,
            )
            audit_result = audit_record(request, decision)
            if audit_result is not None:
                self._close_awaitable(audit_result)
                raise TypeError("The audit sink returned an invalid value.")
        except Exception as error:
            if self._audit_error_mode is ErrorMode.RAISE:
                raise
            if self._audit_error_mode is ErrorMode.DENY:
                return self._annotate(
                    Decision.deny(
                        "The authorization decision could not be audited.",
                        policy="access_gate.audit",
                        metadata={"error_type": type(error).__name__},
                    )
                )
        return decision

    def _annotate(self, decision: Decision) -> Decision:
        if self._policy_set_id is None:
            return decision
        metadata = dict(decision.metadata)
        metadata["policy_set_id"] = self._policy_set_id
        return Decision(decision.effect, decision.reason, decision.policy, metadata)

    @staticmethod
    def _close_awaitable(value: object) -> None:
        if not isawaitable(value):
            return
        close = getattr(value, "close", None)
        if callable(close):
            close()

    def _policies_for_action(self, action: str) -> tuple[Policy, ...]:
        targeted = self._policies_by_action.get(action, ())
        if not targeted:
            return tuple(policy for _, policy in self._global_policies)
        selected: list[Policy] = []
        global_index = 0
        targeted_index = 0
        while global_index < len(self._global_policies) and targeted_index < len(targeted):
            global_item = self._global_policies[global_index]
            targeted_item = targeted[targeted_index]
            if global_item[0] < targeted_item[0]:
                selected.append(global_item[1])
                global_index += 1
            else:
                selected.append(targeted_item[1])
                targeted_index += 1
        selected.extend(policy for _, policy in self._global_policies[global_index:])
        selected.extend(policy for _, policy in targeted[targeted_index:])
        return tuple(selected)
