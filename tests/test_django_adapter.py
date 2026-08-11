from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

django = pytest.importorskip("django")
from django.core.exceptions import PermissionDenied  # noqa: E402

from access_gate import (  # noqa: E402
    ActionAttribute,
    AttributePolicy,
    AuthorizationEngine,
    Resource,
    RolePolicy,
)
from access_gate.adapters.django import DjangoAuthorizer  # noqa: E402


def django_request(*, roles: tuple[str, ...]) -> Any:
    user = SimpleNamespace(
        pk=7,
        is_authenticated=True,
        access_gate_roles=roles,
        access_gate_attributes={"tenant_id": "acme"},
    )
    return SimpleNamespace(user=user, method="GET", path="/incidents/1")


def test_django_decorator_calls_allowed_view() -> None:
    authorizer = DjangoAuthorizer(AuthorizationEngine([RolePolicy({"manager"})]))

    @authorizer.require("incident.read")
    def view(request: Any) -> str:
        return "ok"

    assert view(django_request(roles=("manager",))) == "ok"


def test_django_decorator_raises_normal_permission_denied() -> None:
    authorizer = DjangoAuthorizer(AuthorizationEngine([RolePolicy({"manager"})]))

    @authorizer.require("incident.read")
    def view(request: Any) -> str:
        return "should not run"

    with pytest.raises(PermissionDenied):
        view(django_request(roles=("viewer",)))


def test_django_resource_resolver_receives_view_arguments() -> None:
    seen: list[str] = []

    def resolve(request: Any, incident_id: str) -> Resource:
        seen.append(incident_id)
        return Resource("incident", incident_id, {"tenant_id": "acme"})

    authorizer = DjangoAuthorizer(AuthorizationEngine([RolePolicy({"manager"})]))

    @authorizer.require("incident.read", resource_resolver=resolve)
    def view(request: Any, incident_id: str) -> str:
        return incident_id

    assert view(django_request(roles=("manager",)), "INC-1") == "INC-1"
    assert seen == ["INC-1"]


def test_django_resolver_treats_a_string_role_as_one_exact_role() -> None:
    request = django_request(roles=("placeholder",))
    request.user.access_gate_roles = "manager"
    authorizer = DjangoAuthorizer(AuthorizationEngine([RolePolicy({"manager"})]))

    @authorizer.require("incident.read")
    def view(request: Any) -> str:
        return "ok"

    assert view(request) == "ok"


def test_django_adapter_can_resolve_action_attributes_for_abac() -> None:
    authorizer = DjangoAuthorizer(
        AuthorizationEngine([AttributePolicy(ActionAttribute("risk").less_than(3))]),
        action_attributes_resolver=lambda request, action: {"risk": 2},
    )

    @authorizer.require("incident.read")
    def view(request: Any) -> str:
        return "ok"

    assert view(django_request(roles=())) == "ok"
