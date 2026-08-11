"""Framework-neutral authorization value objects."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum


class Effect(str, Enum):
    """The outcome of an authorization decision."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class Subject:
    """The actor attempting an action.

    Applications decide which claims become roles and attributes. AccessGate
    deliberately does not depend on a particular user, token, or ORM model.
    """

    identifier: str
    authenticated: bool = True
    roles: frozenset[str] = field(default_factory=frozenset)
    attributes: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Resource:
    """A protected object or collection."""

    kind: str
    identifier: str | None = None
    attributes: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """The complete input to policy evaluation."""

    subject: Subject
    action: str
    resource: Resource | None = None
    context: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Decision:
    """A final or intermediate policy decision."""

    effect: Effect
    reason: str
    policy: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    @classmethod
    def allow(
        cls,
        reason: str,
        *,
        policy: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> Decision:
        return cls(Effect.ALLOW, reason, policy, metadata or {})

    @classmethod
    def deny(
        cls,
        reason: str,
        *,
        policy: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> Decision:
        return cls(Effect.DENY, reason, policy, metadata or {})
