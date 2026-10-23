"""A minimal hybrid RBAC, ABAC, and tenant-boundary configuration."""

from access_gate import (
    AllOf,
    AttributePolicy,
    AuthorizationEngine,
    ContextAttribute,
    MissEffect,
    Resource,
    ResourceAttribute,
    RolePolicy,
    Subject,
    SubjectAttribute,
    TenantBoundaryPolicy,
)

engine = AuthorizationEngine(
    [
        # A boundary: same-tenant access is necessary but never sufficient.
        TenantBoundaryPolicy(actions={"incident.read"}),
        # One valid grant path.
        RolePolicy(
            {"incident_manager"},
            actions={"incident.read"},
            on_miss=MissEffect.ABSTAIN,
        ),
        # An alternative grant path based on attributes. Missing facts (no
        # device context, an unassigned incident) only mean this path does not
        # apply; abstaining cannot grant, so the other grants still decide.
        AttributePolicy(
            AllOf(
                SubjectAttribute("team").equals(ResourceAttribute("assigned_team")),
                ContextAttribute("device.trusted").equals(True),
            ),
            actions={"incident.read"},
            on_no_match=MissEffect.ABSTAIN,
            on_indeterminate=MissEffect.ABSTAIN,
            name="assigned_team_on_trusted_device",
        ),
    ]
)

decision = engine.authorize(
    Subject(
        "user-42",
        attributes={"tenant_id": "acme", "team": "response"},
    ),
    "incident.read",
    Resource(
        "incident",
        "INC-123",
        {"tenant_id": "acme", "assigned_team": "response"},
    ),
    context={"device": {"trusted": True}},
)

assert decision.allowed

manager_without_device_context = engine.authorize(
    Subject(
        "user-7",
        roles=frozenset({"incident_manager"}),
        attributes={"tenant_id": "acme"},
    ),
    "incident.read",
    Resource("incident", "INC-124", {"tenant_id": "acme"}),
)

assert manager_without_device_context.allowed
