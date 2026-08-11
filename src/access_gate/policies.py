"""Small, composable policies for common authorization models."""

from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from enum import Enum

from .types import AuthorizationRequest, Decision


class MissEffect(str, Enum):
    """What a granting policy should do when its condition does not match."""

    DENY = "deny"
    ABSTAIN = "abstain"


def _targets(action: str, actions: frozenset[str] | None) -> bool:
    return actions is None or action in actions


@dataclass(frozen=True, slots=True)
class FunctionPolicy:
    """Adapt an application callable to the Policy protocol."""

    name: str
    evaluator: Callable[[AuthorizationRequest], Decision | None]

    def evaluate(self, request: AuthorizationRequest) -> Decision | None:
        return self.evaluator(request)


@dataclass(frozen=True, slots=True)
class RolePolicy:
    """Allow subjects possessing any or all required roles."""

    required_roles: frozenset[str]
    actions: frozenset[str] | None = None
    require_all: bool = False
    on_miss: MissEffect = MissEffect.DENY
    name: str = "role"

    def __init__(
        self,
        required_roles: Collection[str],
        *,
        actions: Collection[str] | None = None,
        require_all: bool = False,
        on_miss: MissEffect = MissEffect.DENY,
        name: str = "role",
    ) -> None:
        object.__setattr__(self, "required_roles", frozenset(required_roles))
        object.__setattr__(self, "actions", None if actions is None else frozenset(actions))
        object.__setattr__(self, "require_all", require_all)
        object.__setattr__(self, "on_miss", on_miss)
        object.__setattr__(self, "name", name)

    def evaluate(self, request: AuthorizationRequest) -> Decision | None:
        if not _targets(request.action, self.actions):
            return None
        roles = request.subject.roles
        matches = (
            self.required_roles <= roles
            if self.require_all
            else bool(self.required_roles & roles)
        )
        if matches:
            return Decision.allow("The subject has a required role.", policy=self.name)
        if self.on_miss is MissEffect.ABSTAIN:
            return None
        return Decision.deny("The subject lacks a required role.", policy=self.name)


@dataclass(frozen=True, slots=True)
class OwnerPolicy:
    """Allow when a resource owner attribute equals the subject identifier."""

    actions: frozenset[str] | None = None
    owner_attribute: str = "owner_id"
    on_miss: MissEffect = MissEffect.DENY
    name: str = "owner"

    def __init__(
        self,
        *,
        actions: Collection[str] | None = None,
        owner_attribute: str = "owner_id",
        on_miss: MissEffect = MissEffect.DENY,
        name: str = "owner",
    ) -> None:
        object.__setattr__(self, "actions", None if actions is None else frozenset(actions))
        object.__setattr__(self, "owner_attribute", owner_attribute)
        object.__setattr__(self, "on_miss", on_miss)
        object.__setattr__(self, "name", name)

    def evaluate(self, request: AuthorizationRequest) -> Decision | None:
        if not _targets(request.action, self.actions):
            return None
        owner_id = None
        if request.resource is not None:
            owner_id = request.resource.attributes.get(self.owner_attribute)
        if owner_id is not None and str(owner_id) == request.subject.identifier:
            return Decision.allow("The subject owns the resource.", policy=self.name)
        if self.on_miss is MissEffect.ABSTAIN:
            return None
        return Decision.deny("The subject does not own the resource.", policy=self.name)


@dataclass(frozen=True, slots=True)
class TenantBoundaryPolicy:
    """Deny cross-tenant access without granting same-tenant access by itself."""

    actions: frozenset[str] | None = None
    subject_attribute: str = "tenant_id"
    resource_attribute: str = "tenant_id"
    name: str = "tenant_boundary"

    def __init__(
        self,
        *,
        actions: Collection[str] | None = None,
        subject_attribute: str = "tenant_id",
        resource_attribute: str = "tenant_id",
        name: str = "tenant_boundary",
    ) -> None:
        object.__setattr__(self, "actions", None if actions is None else frozenset(actions))
        object.__setattr__(self, "subject_attribute", subject_attribute)
        object.__setattr__(self, "resource_attribute", resource_attribute)
        object.__setattr__(self, "name", name)

    def evaluate(self, request: AuthorizationRequest) -> Decision | None:
        if not _targets(request.action, self.actions):
            return None
        subject_tenant = request.subject.attributes.get(self.subject_attribute)
        resource_tenant = None
        if request.resource is not None:
            resource_tenant = request.resource.attributes.get(self.resource_attribute)
        if subject_tenant is None or resource_tenant is None:
            return Decision.deny("Tenant scope is missing.", policy=self.name)
        if str(subject_tenant) != str(resource_tenant):
            return Decision.deny("Cross-tenant access is forbidden.", policy=self.name)
        return None


@dataclass(frozen=True, slots=True)
class AuthenticatedPolicy:
    """Allow authenticated subjects for selected actions."""

    actions: frozenset[str] | None = field(default=None)
    name: str = "authenticated"

    def __init__(
        self,
        *,
        actions: Collection[str] | None = None,
        name: str = "authenticated",
    ) -> None:
        object.__setattr__(self, "actions", None if actions is None else frozenset(actions))
        object.__setattr__(self, "name", name)

    def evaluate(self, request: AuthorizationRequest) -> Decision | None:
        if not _targets(request.action, self.actions):
            return None
        if request.subject.authenticated:
            return Decision.allow("The subject is authenticated.", policy=self.name)
        return Decision.deny("Authentication is required.", policy=self.name)
