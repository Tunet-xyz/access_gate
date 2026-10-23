"""Extension interfaces for application-specific authorization behaviour."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, TypeVar

from .types import AuthorizationRequest, Decision, Resource, Subject

SubjectSource = TypeVar("SubjectSource", contravariant=True)
ResourceSource = TypeVar("ResourceSource", contravariant=True)


class Policy(Protocol):
    """Evaluate one authorization concern.

    Returning ``None`` means that the policy abstains. Returning a decision
    means that the policy explicitly allows or denies the request.
    """

    # A read-only member, so frozen dataclasses and properties conform as well
    # as plain attributes.
    @property
    def name(self) -> str: ...

    def evaluate(self, request: AuthorizationRequest) -> Decision | None: ...


class DecisionStrategy(Protocol):
    """Combine individual policy results into one final decision."""

    def combine(
        self,
        request: AuthorizationRequest,
        decisions: Sequence[Decision],
    ) -> Decision: ...


class AuditSink(Protocol):
    """Receive every final authorization decision."""

    def record(self, request: AuthorizationRequest, decision: Decision) -> None: ...


class SubjectResolver(Protocol[SubjectSource]):
    """Convert an application identity into an AccessGate subject."""

    def resolve_subject(self, source: SubjectSource) -> Subject: ...


class ResourceResolver(Protocol[ResourceSource]):
    """Convert an application object into an AccessGate resource."""

    def resolve_resource(self, source: ResourceSource) -> Resource: ...
