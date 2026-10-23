"""Django integration for AccessGate."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from functools import partial, wraps
from inspect import isawaitable
from typing import TypeVar, cast

from asgiref.sync import iscoroutinefunction, sync_to_async
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest

from ..engine import AuthorizationEngine, ErrorMode
from ..types import AuthorizationRequest, Decision, Resource, Subject

_SESSION_ASSURANCE_CONTEXT_KEY = "session_assurance"
_RESOLVER_POLICY = "access_gate.resolver"
# Deliberate Django responses raised by a resolver are not resolver failures.
_DJANGO_RESPONSES = (Http404, PermissionDenied)

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
_BoundResourceResolver = Callable[[], Resource | None | Awaitable[Resource | None]]
DenialHandler = Callable[[HttpRequest, Decision], object | Awaitable[object]]


def default_subject_resolver(request: HttpRequest) -> Subject:
    """Resolve Django's user without assuming a project-specific user model.

    Applications can expose ``access_gate_roles`` and
    ``access_gate_attributes`` on their user object, or replace this resolver.
    """

    user = getattr(request, "user", None)
    # Only a real ``True`` authenticates: a legacy ``is_authenticated()`` method
    # or another truthy stand-in must not.
    authenticated = user is not None and getattr(user, "is_authenticated", False) is True
    identifier_value = getattr(user, "pk", None)
    if identifier_value is None:
        identifier_value = getattr(user, "id", None)
    roles_value = getattr(user, "access_gate_roles", ())
    attributes_value = getattr(user, "access_gate_attributes", {})
    if roles_value is None:
        roles_value = ()
    if isinstance(roles_value, str):
        roles_value = (roles_value,)
    if not isinstance(attributes_value, Mapping):
        attributes_value = {}
    return Subject(
        identifier="" if identifier_value is None else str(identifier_value),
        authenticated=authenticated,
        roles=frozenset(
            text for text in (str(role) for role in roles_value if role is not None) if text
        ),
        attributes=dict(attributes_value),
    )


def default_context_resolver(request: HttpRequest) -> Mapping[str, object]:
    context: dict[str, object] = {
        "method": getattr(request, "method", ""),
        "path": getattr(request, "path", ""),
    }
    assurance = getattr(request, "session_assurance", None)
    serializer = getattr(assurance, "to_authorization_context", None)
    if callable(serializer):
        try:
            serialized = serializer()
            if isinstance(serialized, Mapping):
                context[_SESSION_ASSURANCE_CONTEXT_KEY] = dict(serialized)
            else:
                context[_SESSION_ASSURANCE_CONTEXT_KEY] = {"schema": "invalid"}
        except Exception:
            context[_SESSION_ASSURANCE_CONTEXT_KEY] = {"schema": "invalid"}
    return context


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
    """Create authorization decorators from a configured engine and resolvers.

    ``resolver_error_mode`` controls exceptions raised while resolving the
    resource, subject, context, or action attributes, or while building the
    authorization request. ``RAISE`` (the default) propagates them. ``DENY``
    turns them into a denial from the ``access_gate.resolver`` policy that is
    audited by the engine and passed to ``denial_handler``. Django's ``Http404``
    and ``PermissionDenied`` always propagate.

    In async views the engine, and so every policy and audit sink, runs through
    ``sync_to_async`` because they may use the ORM. ``async_engine_in_thread=False``
    runs it on the event loop instead, for non-blocking pure-Python policies.
    """

    engine: AuthorizationEngine
    subject_resolver: SubjectResolverFunction = default_subject_resolver
    context_resolver: ContextResolverFunction = default_context_resolver
    action_attributes_resolver: ActionAttributesResolverFunction = (
        default_action_attributes_resolver
    )
    denial_handler: DenialHandler = raise_permission_denied
    resolver_error_mode: ErrorMode = ErrorMode.RAISE
    async_engine_in_thread: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.resolver_error_mode, ErrorMode):
            raise TypeError("resolver_error_mode must be an ErrorMode value.")
        if self.resolver_error_mode is ErrorMode.IGNORE:
            raise ValueError("resolver_error_mode cannot ignore unresolved authorization inputs.")
        if not isinstance(self.async_engine_in_thread, bool):
            raise TypeError("async_engine_in_thread must be a bool.")

    def check(
        self,
        request: HttpRequest,
        action: str,
        *,
        resource: Resource | None = None,
    ) -> Decision:
        """Return the audited decision for an action inside a synchronous view."""

        return self._decide(request, action, None if resource is None else lambda: resource)

    async def acheck(
        self,
        request: HttpRequest,
        action: str,
        *,
        resource: Resource | None = None,
    ) -> Decision:
        """Return the audited decision for an action inside an asynchronous view."""

        return await self._adecide(request, action, None if resource is None else lambda: resource)

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
                    decision = await self._adecide(
                        request,
                        action,
                        None
                        if resource_resolver is None
                        else partial(resource_resolver, request, *args, **kwargs),
                    )
                    if not decision.allowed:
                        return await _async_value(self.denial_handler(request, decision))
                    async_view = cast(Callable[..., Awaitable[object]], view)
                    return await async_view(request, *args, **kwargs)

                return cast(View, async_wrapped)

            @wraps(view)
            def wrapped(request: HttpRequest, *args: object, **kwargs: object) -> object:
                decision = self._decide(
                    request,
                    action,
                    None
                    if resource_resolver is None
                    else partial(resource_resolver, request, *args, **kwargs),
                )
                if not decision.allowed:
                    return _sync_value(
                        self.denial_handler(request, decision),
                        resolver="denial_handler",
                    )
                return view(request, *args, **kwargs)

            return cast(View, wrapped)

        return decorator

    def _decide(
        self,
        request: HttpRequest,
        action: str,
        resource_resolver: _BoundResourceResolver | None,
    ) -> Decision:
        stage = "resource_resolver"
        resource: Resource | None = None
        subject: Subject | None = None
        try:
            if resource_resolver is not None:
                resource = _sync_value(resource_resolver(), resolver=stage)
            stage = "subject_resolver"
            subject = _sync_value(self.subject_resolver(request), resolver=stage)
            stage = "context_resolver"
            context = _sync_value(self.context_resolver(request), resolver=stage)
            stage = "action_attributes_resolver"
            action_attributes = _sync_value(
                self.action_attributes_resolver(request, action),
                resolver=stage,
            )
            stage = "authorization_request"
            authorization_request = AuthorizationRequest(
                subject=subject,
                action=action,
                resource=resource,
                context=context,
                action_attributes=action_attributes,
            )
        except _DJANGO_RESPONSES:
            raise
        except Exception as error:
            if self.resolver_error_mode is ErrorMode.RAISE:
                raise
            return self._unresolved(request, action, stage, error, subject, resource)
        return self.engine.decide(authorization_request)

    async def _adecide(
        self,
        request: HttpRequest,
        action: str,
        resource_resolver: _BoundResourceResolver | None,
    ) -> Decision:
        stage = "resource_resolver"
        resource: Resource | None = None
        subject: Subject | None = None
        try:
            if resource_resolver is not None:
                resource = await _async_value(resource_resolver())
            stage = "subject_resolver"
            subject_resolver = self.subject_resolver
            if subject_resolver is default_subject_resolver:
                # request.user is loaded lazily from the session and database.
                subject_resolver = sync_to_async(default_subject_resolver)
            subject = await _async_value(subject_resolver(request))
            stage = "context_resolver"
            context = await _async_value(self.context_resolver(request))
            stage = "action_attributes_resolver"
            action_attributes = await _async_value(self.action_attributes_resolver(request, action))
            stage = "authorization_request"
            authorization_request = AuthorizationRequest(
                subject=subject,
                action=action,
                resource=resource,
                context=context,
                action_attributes=action_attributes,
            )
        except _DJANGO_RESPONSES:
            raise
        except Exception as error:
            if self.resolver_error_mode is ErrorMode.RAISE:
                raise
            return await self._run_engine(
                partial(self._unresolved, request, action, stage, error, subject, resource)
            )
        return await self._run_engine(partial(self.engine.decide, authorization_request))

    async def _run_engine(self, call: Callable[[], Decision]) -> Decision:
        # Policies and audit sinks are synchronous and may use the ORM.
        if self.async_engine_in_thread:
            return await sync_to_async(call)()
        return call()

    def _unresolved(
        self,
        request: HttpRequest,
        action: str,
        stage: str,
        error: Exception,
        subject: object,
        resource: object,
    ) -> Decision:
        # Audit what is known: inputs resolved before the failure are kept, an
        # unresolved subject is anonymous, and the context is method and path.
        fallback = AuthorizationRequest(
            subject=(subject if isinstance(subject, Subject) else Subject("", authenticated=False)),
            action=action,
            resource=resource if isinstance(resource, Resource) else None,
            context={
                "method": str(getattr(request, "method", "") or ""),
                "path": str(getattr(request, "path", "") or ""),
            },
        )
        return self.engine.record_denial(
            fallback,
            Decision.deny(
                "The authorization inputs could not be resolved.",
                policy=_RESOLVER_POLICY,
                metadata={"resolver": stage, "error_type": type(error).__name__},
            ),
        )
