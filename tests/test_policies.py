from __future__ import annotations

import pytest

from access_gate import (
    AuthenticatedPolicy,
    AuthorizationEngine,
    AuthorizationRequest,
    MissEffect,
    OwnerPolicy,
    Resource,
    RolePolicy,
    SessionAssurancePolicy,
    Subject,
    TenantBoundaryPolicy,
)


def _session_context(now: float = 100.0, **overrides: object) -> dict[str, object]:
    evidence: dict[str, object] = {
        "schema": "session-armor.assurance/v1",
        "status": "trusted",
        "reason": "validated",
        "subject_identifier": "1",
        "session_identifier": "session-token",
        "established_at": 1.0,
        "verified_at": now,
        "last_activity_at": now,
        "binding_factors": ["ip", "user_agent"],
        "claims_bound": True,
    }
    evidence.update(overrides)
    return {"session_assurance": evidence}


def test_session_assurance_policy_abstains_for_fresh_matching_evidence() -> None:
    policy = SessionAssurancePolicy(clock=lambda: 100.0)
    request = AuthorizationRequest(Subject("1"), "read", context=_session_context())
    assert policy.evaluate(request) is None


@pytest.mark.parametrize(
    ("context", "failure"),
    [
        ({}, "missing"),
        (_session_context(schema="invented"), "unsupported_schema"),
        (_session_context(status="unverified"), "untrusted"),
        (_session_context(subject_identifier="2"), "subject_mismatch"),
        (_session_context(session_identifier=""), "missing_session_identifier"),
        (_session_context(session_identifier="x" * 513), "missing_session_identifier"),
        (_session_context(established_at=None), "invalid_verification_time"),
        (_session_context(verified_at="now"), "invalid_verification_time"),
        (
            _session_context(
                established_at=0.0,
                last_activity_at=0.0,
                verified_at=0.0,
            ),
            "stale_verification",
        ),
        (_session_context(verified_at=200.0), "future_verification"),
        (_session_context(established_at=106.0), "invalid_session_timeline"),
        (_session_context(last_activity_at=106.0), "invalid_session_timeline"),
        (_session_context(binding_factors=[]), "binding_required"),
        (_session_context(binding_factors=["ip", "ip"]), "binding_required"),
        (_session_context(binding_factors=["x" * 65]), "binding_required"),
        (_session_context(claims_bound=False), "claim_binding_required"),
    ],
)
def test_session_assurance_policy_denies_malformed_or_untrusted_evidence(
    context: dict[str, object], failure: str
) -> None:
    policy = SessionAssurancePolicy(clock=lambda: 100.0)
    request = AuthorizationRequest(Subject("1"), "read", context=context)
    decision = policy.evaluate(request)
    assert decision is not None
    assert not decision.allowed
    assert decision.metadata["assurance_failure"] == failure


def test_session_assurance_policy_denies_an_unauthenticated_subject() -> None:
    policy = SessionAssurancePolicy(clock=lambda: 100.0)
    request = AuthorizationRequest(
        Subject("1", authenticated=False), "read", context=_session_context()
    )
    decision = policy.evaluate(request)
    assert decision is not None
    assert decision.metadata["assurance_failure"] == "unauthenticated_subject"


def test_session_assurance_policy_cannot_grant_by_itself() -> None:
    engine = AuthorizationEngine([SessionAssurancePolicy(clock=lambda: 100.0)])
    decision = engine.authorize(Subject("1"), "read", context=_session_context())
    assert not decision.allowed


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
