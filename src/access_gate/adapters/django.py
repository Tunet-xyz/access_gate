"""Django integration for AccessGate."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import wraps
from typing import TypeVar, cast

from django.core.exceptions import PermissionDenied
from django.http import HttpRequest

from ..engine import AuthorizationEngine
from ..types import AuthorizationRequest, Decision, Resource, Subject

View = TypeVar("View", bound=Callable[..., object])
SubjectResolverFunction = Callable[[HttpRequest], Subject]
ResourceResolverFunction = Callable[..., Resource | None]
ContextResolverFunction = Callable[[HttpRequest], Mapping[str, object]]
DenialHandler = Callable[[HttpRequest, Decision], object]


def default_subject_resolver(request: HttpRequest) -> Subject:
    """Resolve Django's user without assuming a project-specific user model.

    Applications can expose ``access_gate_roles`` and
    ``access_gate_attributes`` on their user object, or replace this resolver.
    """

    user = getattr(request, "user", None)
    authenticated = bool(user is not None and getattr(user, "is_authenticated", False))
    identifier_value = getattr(user, "pk", None)
    if identifier_value is None:
        identifier_value = getattr(user, "id", None)
    roles_value = getattr(user, "access_gate_roles", ())
    attributes_value = getattr(user, "access_gate_attributes", {})
    if isinstance(roles_value, str):
        roles_value = (roles_value,)
    if not isinstance(attributes_value, Mapping):
        attributes_value = {}
    return Subject(
        identifier="" if identifier_value is None else str(identifier_value),
        authenticated=authenticated,
        roles=frozenset(str(role) for role in roles_value),
        attributes=dict(attributes_value),
    )


def default_context_resolver(request: HttpRequest) -> Mapping[str, object]:
    return {
        "method": getattr(request, "method", ""),
        "path": getattr(request, "path", ""),
    }


def raise_permission_denied(request: HttpRequest, decision: Decision) -> object:
    del request
    raise PermissionDenied(decision.reason)


@dataclass(slots=True)
class DjangoAuthorizer:
    """Create authorization decorators from a configured engine and resolvers."""

    engine: AuthorizationEngine
    subject_resolver: SubjectResolverFunction = default_subject_resolver
    context_resolver: ContextResolverFunction = default_context_resolver
    denial_handler: DenialHandler = raise_permission_denied

    def require(
        self,
        action: str,
        *,
        resource_resolver: ResourceResolverFunction | None = None,
    ) -> Callable[[View], View]:
        """Decorate a Django view with an authorization requirement."""

        def decorator(view: View) -> View:
            @wraps(view)
            def wrapped(request: HttpRequest, *args: object, **kwargs: object) -> object:
                resource = None
                if resource_resolver is not None:
                    resource = resource_resolver(request, *args, **kwargs)
                authorization_request = AuthorizationRequest(
                    subject=self.subject_resolver(request),
                    action=action,
                    resource=resource,
                    context=self.context_resolver(request),
                )
                decision = self.engine.decide(authorization_request)
                if not decision.allowed:
                    return self.denial_handler(request, decision)
                return view(request, *args, **kwargs)

            return cast(View, wrapped)

        return decorator
