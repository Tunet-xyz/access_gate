"""Django integration for AccessGate."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from functools import wraps
from inspect import isawaitable
from typing import TypeVar, cast

from asgiref.sync import iscoroutinefunction
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest

from ..engine import AuthorizationEngine
from ..types import AuthorizationRequest, Decision, Resource, Subject

View = TypeVar("View", bound=Callable[..., object])
Resolved = TypeVar("Resolved")
SubjectResolverFunction = Callable[[HttpRequest], Subject | Awaitable[Subject]]
ResourceResolverFunction = Callable[..., Resource | None | Awaitable[Resource | None]]
ContextResolverFunction = Callable[
    [HttpRequest],
    Mapping[str, object] | Awaitable[Mapping[str, object]],
]
ActionAttributesResolverFunction = Callable[
    [HttpRequest, str],
    Mapping[str, object] | Awaitable[Mapping[str, object]],
]
DenialHandler = Callable[[HttpRequest, Decision], object | Awaitable[object]]


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


def default_action_attributes_resolver(
    request: HttpRequest,
    action: str,
) -> Mapping[str, object]:
    del request, action
    return {}


def raise_permission_denied(request: HttpRequest, decision: Decision) -> object:
    del request
    raise PermissionDenied(decision.reason)


def _sync_value(value: Resolved | Awaitable[Resolved], *, resolver: str) -> Resolved:
    if isawaitable(value):
        close = getattr(value, "close", None)
        if callable(close):
            close()
        raise TypeError(f"{resolver} returned an awaitable for a synchronous Django view.")
    return value


async def _async_value(value: Resolved | Awaitable[Resolved]) -> Resolved:
    if isawaitable(value):
        return await value
    return value


@dataclass(slots=True)
class DjangoAuthorizer:
    """Create authorization decorators from a configured engine and resolvers."""

    engine: AuthorizationEngine
    subject_resolver: SubjectResolverFunction = default_subject_resolver
    context_resolver: ContextResolverFunction = default_context_resolver
    action_attributes_resolver: ActionAttributesResolverFunction = (
        default_action_attributes_resolver
    )
    denial_handler: DenialHandler = raise_permission_denied

    def require(
        self,
        action: str,
        *,
        resource_resolver: ResourceResolverFunction | None = None,
    ) -> Callable[[View], View]:
        """Decorate a Django view with an authorization requirement."""

        def decorator(view: View) -> View:
            if iscoroutinefunction(view):

                @wraps(view)
                async def async_wrapped(
                    request: HttpRequest,
                    *args: object,
                    **kwargs: object,
                ) -> object:
                    resource = None
                    if resource_resolver is not None:
                        resource = await _async_value(resource_resolver(request, *args, **kwargs))
                    authorization_request = AuthorizationRequest(
                        subject=await _async_value(self.subject_resolver(request)),
                        action=action,
                        resource=resource,
                        context=await _async_value(self.context_resolver(request)),
                        action_attributes=await _async_value(
                            self.action_attributes_resolver(request, action)
                        ),
                    )
                    decision = self.engine.decide(authorization_request)
                    if not decision.allowed:
                        return await _async_value(self.denial_handler(request, decision))
                    async_view = cast(Callable[..., Awaitable[object]], view)
                    return await async_view(request, *args, **kwargs)

                return cast(View, async_wrapped)

            @wraps(view)
            def wrapped(request: HttpRequest, *args: object, **kwargs: object) -> object:
                resource = None
                if resource_resolver is not None:
                    resource = _sync_value(
                        resource_resolver(request, *args, **kwargs),
                        resolver="resource_resolver",
                    )
                authorization_request = AuthorizationRequest(
                    subject=_sync_value(
                        self.subject_resolver(request),
                        resolver="subject_resolver",
                    ),
                    action=action,
                    resource=resource,
                    context=_sync_value(
                        self.context_resolver(request),
                        resolver="context_resolver",
                    ),
                    action_attributes=_sync_value(
                        self.action_attributes_resolver(request, action),
                        resolver="action_attributes_resolver",
                    ),
                )
                decision = self.engine.decide(authorization_request)
                if not decision.allowed:
                    return _sync_value(
                        self.denial_handler(request, decision),
                        resolver="denial_handler",
                    )
                return view(request, *args, **kwargs)

            return cast(View, wrapped)

        return decorator
