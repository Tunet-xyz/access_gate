from __future__ import annotations

from access_gate import (
    AuthenticatedPolicy,
    AuthorizationEngine,
    MissEffect,
    OwnerPolicy,
    Resource,
    RolePolicy,
    Subject,
    TenantBoundaryPolicy,
)


def test_role_names_are_matched_exactly() -> None:
    engine = AuthorizationEngine([RolePolicy({"admin"})])

    decision = engine.authorize(Subject("1", roles=frozenset({"administrator"})), "read")

    assert not decision.allowed


def test_role_policy_can_require_all_roles() -> None:
    policy = RolePolicy({"reviewer", "publisher"}, require_all=True)

    denied = AuthorizationEngine([policy]).authorize(
        Subject("1", roles=frozenset({"reviewer"})),
        "publish",
    )
    allowed = AuthorizationEngine([policy]).authorize(
        Subject("1", roles=frozenset({"reviewer", "publisher"})),
        "publish",
    )

    assert not denied.allowed
    assert allowed.allowed


def test_untargeted_action_abstains_and_remains_default_denied() -> None:
    engine = AuthorizationEngine([RolePolicy({"admin"}, actions={"users.read"})])

    decision = engine.authorize(
        Subject("1", roles=frozenset({"admin"})),
        "users.delete",
    )

    assert not decision.allowed
    assert decision.policy == "access_gate.default_deny"


def test_role_miss_can_abstain_for_alternative_grants() -> None:
    role = RolePolicy({"admin"}, on_miss=MissEffect.ABSTAIN)
    owner = OwnerPolicy()
    engine = AuthorizationEngine([role, owner])

    decision = engine.authorize(
        Subject("user-7"),
        "record.update",
        Resource("record", "7", {"owner_id": "user-7"}),
    )

    assert decision.allowed
    assert decision.policy == "owner"


def test_tenant_match_needs_a_separate_grant() -> None:
    boundary = TenantBoundaryPolicy()
    subject = Subject("1", attributes={"tenant_id": "a"})
    resource = Resource("record", "1", {"tenant_id": "a"})

    decision = AuthorizationEngine([boundary]).authorize(subject, "read", resource)

    assert not decision.allowed
    assert decision.policy == "access_gate.default_deny"


def test_tenant_mismatch_overrides_a_role_grant() -> None:
    engine = AuthorizationEngine([TenantBoundaryPolicy(), RolePolicy({"reader"})])
    subject = Subject("1", roles=frozenset({"reader"}), attributes={"tenant_id": "a"})
    resource = Resource("record", "1", {"tenant_id": "b"})

    decision = engine.authorize(subject, "read", resource)

    assert not decision.allowed
    assert decision.policy == "tenant_boundary"


def test_missing_tenant_scope_denies() -> None:
    engine = AuthorizationEngine([TenantBoundaryPolicy(), RolePolicy({"reader"})])
    subject = Subject("1", roles=frozenset({"reader"}))

    decision = engine.authorize(subject, "read", Resource("record", "1"))

    assert not decision.allowed
    assert decision.reason == "Tenant scope is missing."


def test_authenticated_policy_denies_anonymous_subject() -> None:
    engine = AuthorizationEngine([AuthenticatedPolicy()])

    decision = engine.authorize(Subject("", authenticated=False), "profile.read")

    assert not decision.allowed
