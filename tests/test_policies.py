from __future__ import annotations

import pytest

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


def test_role_policy_rejects_empty_or_malformed_configuration() -> None:
    with pytest.raises(ValueError, match="at least one"):
        RolePolicy([], require_all=True)
    with pytest.raises(TypeError, match="collection"):
        RolePolicy("admin")
    with pytest.raises(TypeError, match="non-empty strings"):
        RolePolicy({"admin", ""})
    with pytest.raises(ValueError, match="at least one"):
        RolePolicy({"admin"}, actions=[])
    with pytest.raises(TypeError, match="collection"):
        RolePolicy({"admin"}, actions="read")
    with pytest.raises(TypeError, match="policy name"):
        RolePolicy({"admin"}, name="")
    with pytest.raises(TypeError, match="boolean"):
        RolePolicy({"admin"}, require_all="yes")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="MissEffect"):
        RolePolicy({"admin"}, on_miss="deny")  # type: ignore[arg-type]


def test_relationship_policy_configuration_is_validated() -> None:
    with pytest.raises(TypeError, match="owner_attribute"):
        OwnerPolicy(owner_attribute="")
    with pytest.raises(TypeError, match="subject_attribute"):
        TenantBoundaryPolicy(subject_attribute="")
    with pytest.raises(TypeError, match="resource_attribute"):
        TenantBoundaryPolicy(resource_attribute="")
    with pytest.raises(TypeError, match="MissEffect"):
        OwnerPolicy(on_miss="deny")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="maximum item count"):
        RolePolicy({f"role-{index}" for index in range(4_097)})


def test_owner_policy_requires_authenticated_exact_string_identity() -> None:
    engine = AuthorizationEngine([OwnerPolicy()])

    anonymous = engine.authorize(
        Subject("", authenticated=False),
        "record.read",
        Resource("record", attributes={"owner_id": ""}),
    )
    wrong_type = engine.authorize(
        Subject("7"),
        "record.read",
        Resource("record", attributes={"owner_id": 7}),
    )

    assert not anonymous.allowed
    assert not wrong_type.allowed


def test_tenant_boundary_rejects_cross_type_identifiers() -> None:
    engine = AuthorizationEngine([TenantBoundaryPolicy(), RolePolicy({"reader"})])

    decision = engine.authorize(
        Subject("1", roles={"reader"}, attributes={"tenant_id": "7"}),
        "record.read",
        Resource("record", attributes={"tenant_id": 7}),
    )

    assert not decision.allowed
    assert decision.policy == "tenant_boundary"
    assert decision.reason == "Tenant scope is invalid."

    empty = engine.authorize(
        Subject("1", roles={"reader"}, attributes={"tenant_id": ""}),
        "record.read",
        Resource("record", attributes={"tenant_id": ""}),
    )
    assert not empty.allowed
    assert empty.reason == "Tenant scope is invalid."


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
