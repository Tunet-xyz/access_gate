from __future__ import annotations

import runpy
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from pathlib import Path

import pytest

from access_gate import (
    ActionAttribute,
    AllOf,
    AnyOf,
    AttributePolicy,
    AttributeRef,
    AttributeSource,
    AuthorizationEngine,
    AuthorizationRequest,
    ConditionState,
    ContextAttribute,
    Effect,
    MissEffect,
    Not,
    OperatorRegistry,
    PolicySchemaError,
    Resource,
    ResourceAttribute,
    RolePolicy,
    Subject,
    SubjectAttribute,
    attribute_policy_from_dict,
    dumps_policy,
    load_policy_schema,
    loads_policy,
)


def abac_request(
    *,
    subject_attributes: dict[str, object] | None = None,
    resource_attributes: dict[str, object] | None = None,
    action_attributes: dict[str, object] | None = None,
    context: dict[str, object] | None = None,
) -> AuthorizationRequest:
    return AuthorizationRequest(
        subject=Subject(
            "user-1",
            roles=frozenset({"reviewer"}),
            attributes=subject_attributes or {},
        ),
        action="document.read",
        resource=Resource("document", "doc-1", resource_attributes or {}),
        context=context or {},
        action_attributes=action_attributes or {},
    )


def evaluate(condition: object, request: AuthorizationRequest) -> ConditionState:
    return condition.evaluate(request, OperatorRegistry()).state  # type: ignore[attr-defined]


def test_all_abac_namespaces_can_participate_in_one_policy() -> None:
    policy = AttributePolicy(
        AllOf(
            SubjectAttribute("department").equals(ResourceAttribute("department")),
            SubjectAttribute("clearance").greater_than_or_equal(
                ResourceAttribute("classification")
            ),
            ActionAttribute("risk").less_than_or_equal(3),
            ContextAttribute("device.trusted").equals(True),
            AttributeRef(AttributeSource.SUBJECT, "authenticated").equals(True),
            AttributeRef(AttributeSource.RESOURCE, "kind").equals("document"),
            AttributeRef(AttributeSource.ACTION, "name").equals("document.read"),
        ),
        actions={"document.read"},
        name="document_attributes",
    )
    request = abac_request(
        subject_attributes={"department": "safety", "clearance": 4},
        resource_attributes={"department": "safety", "classification": 3},
        action_attributes={"risk": 2},
        context={"device": {"trusted": True}},
    )

    decision = AuthorizationEngine([policy]).decide(request)

    assert decision.allowed
    assert decision.policy == "document_attributes"


@pytest.mark.parametrize(
    ("operator", "left", "right", "expected"),
    [
        ("eq", "uk", "uk", ConditionState.MATCH),
        ("neq", "uk", "us", ConditionState.MATCH),
        ("in", "uk", ["uk", "ie"], ConditionState.MATCH),
        ("not_in", "fr", ["uk", "ie"], ConditionState.MATCH),
        ("contains", ["read", "write"], "write", ConditionState.MATCH),
        ("not_contains", ["read"], "write", ConditionState.MATCH),
        ("intersects", ["a", "b"], ["b", "c"], ConditionState.MATCH),
        ("subset_of", ["a"], ["a", "b"], ConditionState.MATCH),
        ("superset_of", ["a", "b"], ["a"], ConditionState.MATCH),
        ("gt", 4, 3, ConditionState.MATCH),
        ("gt", 3, 3, ConditionState.NO_MATCH),
        ("gte", 4, 4.0, ConditionState.MATCH),
        ("lt", 2, 3, ConditionState.MATCH),
        ("lt", 3, 3, ConditionState.NO_MATCH),
        ("lte", 3, 3, ConditionState.MATCH),
        ("eq", True, 1, ConditionState.NO_MATCH),
        ("contains", "administrator", "admin", ConditionState.INDETERMINATE),
        ("in", "admin", "administrator", ConditionState.INDETERMINATE),
        ("not_contains", "administrator", "admin", ConditionState.INDETERMINATE),
        ("not_in", "admin", "administrator", ConditionState.INDETERMINATE),
        ("gt", "4", "3", ConditionState.INDETERMINATE),
    ],
)
def test_builtin_operators_have_safe_exact_semantics(
    operator: str,
    left: object,
    right: object,
    expected: ConditionState,
) -> None:
    condition = ContextAttribute("left").compare(operator, ContextAttribute("right"))

    result = condition.evaluate(
        abac_request(context={"left": left, "right": right}),
        OperatorRegistry(),
    )

    assert result.state is expected


@pytest.mark.parametrize("value", [Decimal("50000"), "50000", None, True, float("nan")])
def test_unorderable_or_nan_operands_cannot_slip_past_a_boundary(value: object) -> None:
    limit = AttributePolicy(
        ContextAttribute("amount").greater_than(10_000),
        match_effect=Effect.DENY,
        name="amount_limit",
    )
    below_limit = AttributePolicy(Not(ContextAttribute("amount").greater_than(10_000)))
    request = abac_request(context={"amount": value})

    assert evaluate(ContextAttribute("amount").greater_than(10_000), request) is (
        ConditionState.INDETERMINATE
    )
    assert not AuthorizationEngine([limit, RolePolicy({"reviewer"})]).decide(request).allowed
    assert not AuthorizationEngine([below_limit]).decide(request).allowed


@pytest.mark.parametrize("nan", [float("nan"), Decimal("NaN"), complex("nan")])
def test_nan_is_never_equal_or_unequal(nan: object) -> None:
    request = abac_request(context={"left": nan, "right": 1})

    for condition in (
        ContextAttribute("left").equals(ContextAttribute("right")),
        ContextAttribute("left").not_equals(ContextAttribute("right")),
        ContextAttribute("left").is_not_in([1, 2]),
    ):
        assert evaluate(condition, request) is ConditionState.INDETERMINATE


class _Role(str, Enum):
    ADMIN = "admin"


@pytest.mark.parametrize(
    ("operator", "left", "right", "expected"),
    [
        ("eq", [True], [1], ConditionState.NO_MATCH),
        ("eq", {"admin": True}, {"admin": 1}, ConditionState.NO_MATCH),
        ("eq", {"flags": {True: "on"}}, {"flags": {1: "on"}}, ConditionState.NO_MATCH),
        ("eq", {"n": [1, {"mfa": True}]}, {"n": [1.0, {"mfa": True}]}, ConditionState.MATCH),
        ("in", [True], [[1], [2]], ConditionState.NO_MATCH),
        ("subset_of", [[True]], [[1]], ConditionState.NO_MATCH),
        ("eq", _Role.ADMIN, "admin", ConditionState.NO_MATCH),
        ("in", _Role.ADMIN, ["admin"], ConditionState.NO_MATCH),
        ("intersects", [_Role.ADMIN], ["admin"], ConditionState.NO_MATCH),
        ("intersects", [_Role.ADMIN, ["x"]], ["admin"], ConditionState.NO_MATCH),
        ("intersects", [_Role.ADMIN], [_Role.ADMIN], ConditionState.MATCH),
    ],
)
def test_exact_equality_applies_inside_containers_and_to_every_operator(
    operator: str,
    left: object,
    right: object,
    expected: ConditionState,
) -> None:
    condition = ContextAttribute("left").compare(operator, ContextAttribute("right"))

    assert evaluate(condition, abac_request(context={"left": left, "right": right})) is expected


def test_missing_operand_is_indeterminate_and_denied() -> None:
    condition = SubjectAttribute("clearance").greater_than_or_equal(3)
    policy = AttributePolicy(condition)

    decision = AuthorizationEngine([policy]).decide(abac_request())

    assert not decision.allowed
    assert decision.metadata["condition_state"] == "indeterminate"
    assert "clearance" not in decision.reason


def test_not_does_not_turn_missing_data_into_a_match() -> None:
    condition = Not(SubjectAttribute("suspended").equals(True))

    state = evaluate(condition, abac_request())

    assert state is ConditionState.INDETERMINATE


def test_exists_and_not_exists_are_explicit_missing_value_checks() -> None:
    present = SubjectAttribute("department").exists()
    missing = SubjectAttribute("suspended").does_not_exist()
    request = abac_request(subject_attributes={"department": "safety"})

    assert evaluate(present, request) is ConditionState.MATCH
    assert evaluate(missing, request) is ConditionState.MATCH


def test_none_is_an_explicit_literal_not_an_omitted_operand() -> None:
    condition = ContextAttribute("optional").equals(None)

    assert evaluate(condition, abac_request(context={"optional": None})) is ConditionState.MATCH
    assert evaluate(condition, abac_request()) is ConditionState.INDETERMINATE


def test_two_null_attributes_never_establish_a_relationship() -> None:
    same_tenant = SubjectAttribute("tenant").equals(ResourceAttribute("tenant"))
    other_tenant = SubjectAttribute("tenant").not_equals(ResourceAttribute("tenant"))
    unscoped = abac_request(
        subject_attributes={"tenant": None},
        resource_attributes={"tenant": None},
    )

    result = same_tenant.evaluate(unscoped, OperatorRegistry())
    assert result.state is ConditionState.INDETERMINATE
    assert result.metadata["issue"] == "null_operands"
    assert evaluate(other_tenant, unscoped) is ConditionState.INDETERMINATE
    assert not AuthorizationEngine([AttributePolicy(same_tenant)]).decide(unscoped).allowed
    boundary = AttributePolicy(other_tenant, match_effect=Effect.DENY, name="tenant_boundary")
    assert not AuthorizationEngine([boundary, RolePolicy({"reviewer"})]).decide(unscoped).allowed

    scoped = abac_request(subject_attributes={"tenant": "a"}, resource_attributes={"tenant": None})
    assert evaluate(same_tenant, scoped) is ConditionState.NO_MATCH
    assert evaluate(other_tenant, scoped) is ConditionState.MATCH


def test_all_of_no_match_wins_over_an_indeterminate_child() -> None:
    condition = AllOf(
        SubjectAttribute("missing").equals(True),
        SubjectAttribute("department").equals("legal"),
    )
    request = abac_request(subject_attributes={"department": "safety"})

    assert evaluate(condition, request) is ConditionState.NO_MATCH


def test_any_of_match_wins_over_an_indeterminate_child() -> None:
    condition = AnyOf(
        SubjectAttribute("missing").equals(True),
        SubjectAttribute("department").equals("safety"),
    )
    request = abac_request(subject_attributes={"department": "safety"})

    assert evaluate(condition, request) is ConditionState.MATCH


def test_combinators_reject_empty_condition_sets() -> None:
    with pytest.raises(ValueError, match="at least one"):
        AllOf()
    with pytest.raises(ValueError, match="at least one"):
        AnyOf()


def test_deny_attribute_policy_abstains_when_boundary_does_not_match() -> None:
    blocked_country = AttributePolicy(
        ContextAttribute("country").equals("blocked"),
        match_effect=Effect.DENY,
        name="blocked_country",
    )
    role = RolePolicy({"reviewer"})

    allowed = AuthorizationEngine([blocked_country, role]).decide(
        abac_request(context={"country": "uk"})
    )
    denied = AuthorizationEngine([blocked_country, role]).decide(
        abac_request(context={"country": "blocked"})
    )

    assert allowed.allowed
    assert not denied.allowed
    assert denied.policy == "blocked_country"


def test_grant_policy_can_abstain_for_mixed_rbac_abac_grants() -> None:
    role = RolePolicy({"admin"}, on_miss=MissEffect.ABSTAIN)
    department = AttributePolicy(
        SubjectAttribute("department").equals("safety"),
        on_no_match=MissEffect.ABSTAIN,
        name="safety_department",
    )
    request = abac_request(subject_attributes={"department": "safety"})

    decision = AuthorizationEngine([role, department]).decide(request)

    assert decision.allowed
    assert decision.policy == "safety_department"


def test_hybrid_example_does_not_let_missing_facts_veto_the_role_grant() -> None:
    example = Path(__file__).resolve().parents[1] / "examples" / "hybrid_authorization.py"
    engine = runpy.run_path(str(example))["engine"]
    manager = Subject(
        "manager-1",
        roles=frozenset({"incident_manager"}),
        attributes={"tenant_id": "acme"},
    )
    member = Subject("member-1", attributes={"tenant_id": "acme", "team": "response"})
    assigned = Resource("incident", "INC-1", {"tenant_id": "acme", "assigned_team": "response"})

    assert engine.authorize(manager, "incident.read", assigned).allowed
    assert not engine.authorize(member, "incident.read", assigned).allowed
    other_tenant = Resource("incident", "INC-2", {"tenant_id": "other"})
    assert not engine.authorize(manager, "incident.read", other_tenant).allowed


def test_action_targeting_is_exact() -> None:
    policy = AttributePolicy(
        SubjectAttribute("department").equals("safety"),
        actions={"document.read"},
    )
    request = abac_request(subject_attributes={"department": "safety"})
    other_request = AuthorizationRequest(
        request.subject,
        "document.reader",
        request.resource,
        request.context,
        request.action_attributes,
    )

    decision = AuthorizationEngine([policy]).decide(other_request)

    assert not decision.allowed
    assert decision.policy == "access_gate.default_deny"
    assert policy.evaluate(other_request) is None


def test_engine_convenience_api_accepts_action_attributes() -> None:
    engine = AuthorizationEngine([AttributePolicy(ActionAttribute("risk").less_than(3))])

    decision = engine.authorize(
        Subject("user-1"),
        "document.read",
        Resource("document"),
        action_attributes={"risk": 2},
    )

    assert decision.allowed


def test_custom_operator_registry_is_policy_local() -> None:
    registry = OperatorRegistry()
    registry.register(
        "same_prefix",
        lambda left, right: isinstance(left, str)
        and isinstance(right, str)
        and left.split("-")[0] == right.split("-")[0],
    )
    condition = SubjectAttribute("cost_center").compare(
        "same_prefix", ResourceAttribute("cost_center")
    )
    policy = AttributePolicy(condition, operators=registry)
    registry.register("always", lambda left, right: True)

    decision = AuthorizationEngine([policy]).decide(
        abac_request(
            subject_attributes={"cost_center": "safety-01"},
            resource_attributes={"cost_center": "safety-99"},
        )
    )

    assert decision.allowed
    assert "always" not in policy.operators.names


def test_custom_operator_exception_is_indeterminate_and_redacted() -> None:
    registry = OperatorRegistry({"broken": lambda left, right: 1 / 0})
    policy = AttributePolicy(
        SubjectAttribute("department").compare("broken", "safety"),
        operators=registry,
    )

    decision = AuthorizationEngine([policy]).decide(
        abac_request(subject_attributes={"department": "secret-value"})
    )

    assert not decision.allowed
    assert decision.metadata["evaluation"]["issue"] == "operator_error"  # type: ignore[index]
    assert "secret-value" not in str(decision.metadata)


@pytest.mark.parametrize("result", [1, "true", object()])
def test_custom_operator_must_return_an_actual_boolean(result: object) -> None:
    registry = OperatorRegistry({"invalid": lambda left, right: result})  # type: ignore[dict-item]
    policy = AttributePolicy(
        SubjectAttribute("department").compare("invalid", "safety"),
        operators=registry,
    )

    decision = AuthorizationEngine([policy]).decide(
        abac_request(subject_attributes={"department": "safety"})
    )

    assert not decision.allowed
    assert decision.metadata["evaluation"]["issue"] == "operator_error"  # type: ignore[index]


def test_async_custom_operator_is_closed_and_fails_closed() -> None:
    async def async_operator(left: object, right: object) -> bool:
        return True

    registry = OperatorRegistry({"async_operator": async_operator})  # type: ignore[dict-item]
    policy = AttributePolicy(
        SubjectAttribute("department").compare("async_operator", "safety"),
        operators=registry,
    )

    decision = AuthorizationEngine([policy]).decide(
        abac_request(subject_attributes={"department": "safety"})
    )

    assert not decision.allowed
    assert decision.metadata["condition_state"] == "indeterminate"


def test_registry_rejects_unsafe_or_reserved_operator_names() -> None:
    registry = OperatorRegistry()

    with pytest.raises(ValueError):
        registry.register("unsafe-name", lambda left, right: True)
    with pytest.raises(ValueError):
        registry.register("exists", lambda left, right: True)
    with pytest.raises(ValueError):
        registry.register("eq", lambda left, right: True)


def test_policy_round_trip_preserves_semantics() -> None:
    original = AttributePolicy(
        AllOf(
            SubjectAttribute("department").equals(ResourceAttribute("department")),
            ContextAttribute("device.trusted").equals(True),
        ),
        actions={"document.read"},
        name="department_document",
    )

    restored = loads_policy(dumps_policy(original))
    decision = AuthorizationEngine([restored]).decide(
        abac_request(
            subject_attributes={"department": "safety"},
            resource_attributes={"department": "safety"},
            context={"device": {"trusted": True}},
        )
    )

    assert restored.to_dict() == original.to_dict()
    assert decision.allowed


def test_packaged_policy_schema_has_the_public_version() -> None:
    schema = load_policy_schema()

    assert schema["title"] == "AccessGate ABAC Policy v1"
    assert schema["properties"]["schema_version"]["const"] == "access_gate.policy.v1"  # type: ignore[index]


def test_custom_operator_policy_can_be_deserialized_with_its_registry() -> None:
    registry = OperatorRegistry({"same": lambda left, right: left == right})
    document = {
        "schema_version": "access_gate.policy.v1",
        "type": "attribute_policy",
        "name": "custom",
        "actions": None,
        "match_effect": "allow",
        "on_no_match": "deny",
        "on_indeterminate": "deny",
        "condition": {
            "type": "comparison",
            "operator": "same",
            "left": {"source": "subject", "path": "attributes.department"},
            "right": {"value": "safety"},
        },
    }

    policy = attribute_policy_from_dict(document, operators=registry)

    assert AuthorizationEngine([policy]).decide(
        abac_request(subject_attributes={"department": "safety"})
    ).allowed


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"schema_version": "wrong", "type": "attribute_policy"},
        {
            "schema_version": "access_gate.policy.v1",
            "type": "attribute_policy",
            "name": "bad",
            "actions": [1],
            "match_effect": "allow",
            "on_no_match": "deny",
            "on_indeterminate": "deny",
            "condition": {
                "type": "comparison",
                "operator": "eq",
                "left": {"source": "subject", "path": "attributes.department"},
                "right": {"value": "safety"},
            },
        },
        {
            "schema_version": "access_gate.policy.v1",
            "type": "attribute_policy",
            "name": "bad",
            "actions": None,
            "match_effect": "allow",
            "on_no_match": "deny",
            "on_indeterminate": "deny",
            "condition": {
                "type": "comparison",
                "operator": "unknown",
                "left": {"source": "context", "path": "value"},
                "right": {"value": 1},
            },
        },
    ],
)
def test_invalid_policy_documents_are_rejected(document: dict[str, object]) -> None:
    with pytest.raises(PolicySchemaError):
        attribute_policy_from_dict(document)


def test_invalid_json_and_non_serializable_literals_are_rejected() -> None:
    with pytest.raises(PolicySchemaError, match="valid JSON"):
        loads_policy("{")

    policy = AttributePolicy(ContextAttribute("value").equals(object()))
    with pytest.raises(PolicySchemaError, match="not JSON serializable"):
        dumps_policy(policy)


def test_serialized_policies_reject_unknown_fields_and_duplicate_actions() -> None:
    policy = AttributePolicy(ContextAttribute("trusted").equals(True), name="trusted")
    document = policy.to_dict()
    document["unexpected"] = True

    with pytest.raises(PolicySchemaError, match="unknown fields"):
        attribute_policy_from_dict(document)

    duplicate_actions = policy.to_dict()
    duplicate_actions["actions"] = ["read", "read"]
    with pytest.raises(PolicySchemaError, match="duplicates"):
        attribute_policy_from_dict(duplicate_actions)


@dataclass(frozen=True)
class CustomOperand:
    value: object

    def resolve(self, request: AuthorizationRequest) -> object:
        del request
        return self.value

    def to_dict(self) -> dict[str, object]:
        return {"value": self.value}

    @property
    def label(self) -> str:
        return "custom"


def test_custom_operand_protocol_is_supported() -> None:
    condition = SubjectAttribute("department").equals(CustomOperand("safety"))

    assert evaluate(
        condition,
        abac_request(subject_attributes={"department": "safety"}),
    ) is ConditionState.MATCH
