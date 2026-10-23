"""Type-checked by tests/test_typing.py: built-in policies must satisfy ``Policy``."""

from __future__ import annotations

from access_gate import (
    AttributePolicy,
    AuthenticatedPolicy,
    AuthorizationEngine,
    AuthorizationRequest,
    Decision,
    FunctionPolicy,
    OwnerPolicy,
    Policy,
    RolePolicy,
    SessionAssurancePolicy,
    SubjectAttribute,
    TenantBoundaryPolicy,
)


def abstain(request: AuthorizationRequest) -> Decision | None:
    return None


class ClassAttributePolicy:
    name = "class-attribute"

    def evaluate(self, request: AuthorizationRequest) -> Decision | None:
        return None


policies: list[Policy] = [
    AuthenticatedPolicy(actions={"records.read"}),
    SessionAssurancePolicy(actions={"records.read"}),
    AttributePolicy(SubjectAttribute("tenant").equals("acme"), actions={"records.read"}),
    RolePolicy({"reader"}, actions={"records.read"}),
    OwnerPolicy(actions={"records.read"}),
    TenantBoundaryPolicy(actions={"records.read"}),
    FunctionPolicy("function", abstain, actions={"records.read"}),
    ClassAttributePolicy(),
]
engine = AuthorizationEngine(policies)
inline_engine = AuthorizationEngine([RolePolicy({"admin"}, actions={"users.list"})])
