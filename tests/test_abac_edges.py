from __future__ import annotations

import json
from enum import Enum

import pytest

from access_gate import (
    AllOf,
    AnyOf,
    AttributePolicy,
    AttributeRef,
    AttributeSource,
    AuthorizationEngine,
    AuthorizationRequest,
    Comparison,
    ConditionResult,
    ConditionState,
    ContextAttribute,
    Literal,
    MissEffect,
    Not,
    OperatorRegistry,
    PolicySchemaError,
    Resource,
    Subject,
    SubjectAttribute,
    attribute_policy_from_dict,
    condition_from_dict,
    dumps_policy,
    loads_policy,
)


def request(
    *,
    subject_attributes: dict[str, object] | None = None,
    context: dict[str, object] | None = None,
    resource: Resource | None = None,
) -> AuthorizationRequest:
    return AuthorizationRequest(
        Subject("user-1", attributes=subject_attributes or {}),
        "read",
        Resource("record") if resource is None else resource,
        context or {},
    )


def state(condition: object, value: AuthorizationRequest) -> ConditionState:
    return condition.evaluate(value, OperatorRegistry()).state  # type: ignore[attr-defined]


def complete_document() -> dict[str, object]:
    return AttributePolicy(ContextAttribute("trusted").equals(True), name="trusted").to_dict()


def test_condition_result_matched_property_is_exact() -> None:
    assert ConditionResult(ConditionState.MATCH, "yes").matched
    assert not ConditionResult(ConditionState.NO_MATCH, "no").matched


def test_a_condition_result_state_outside_condition_state_cannot_grant() -> None:
    class ForeignState(Enum):
        NO = "no"

    class ForeignCondition:
        def evaluate(
            self,
            request: AuthorizationRequest,
            operators: OperatorRegistry,
        ) -> ConditionResult:
            return ConditionResult(ForeignState.NO, "custom")  # type: ignore[arg-type]

        def to_dict(self) -> dict[str, object]:
            return {"type": "custom"}

    for condition in (ForeignCondition(), Not(ForeignCondition()), AllOf(ForeignCondition())):
        decision = AuthorizationEngine([AttributePolicy(condition, name="custom")]).decide(
            request()
        )
        assert not decision.allowed
        assert decision.metadata["error_type"] == "TypeError"
    with pytest.raises(TypeError, match="ConditionState"):
        ConditionResult("match", "plain string")  # type: ignore[arg-type]


def test_attribute_reference_rejects_empty_path_segments() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        ContextAttribute("")
    with pytest.raises(ValueError, match="non-empty"):
        ContextAttribute("device..trusted")


def test_missing_resource_makes_a_resource_reference_indeterminate() -> None:
    value = request()
    value = AuthorizationRequest(value.subject, value.action, None)
    condition = AttributeRef(AttributeSource.RESOURCE, "kind").equals("record")

    assert state(condition, value) is ConditionState.INDETERMINATE


def test_literal_and_attribute_reference_serialization_are_stable() -> None:
    literal = Literal({"a": 1})
    reference = AttributeRef(AttributeSource.SUBJECT, "id")

    assert literal.resolve(request()) == {"a": 1}
    assert literal.to_dict() == {"value": {"a": 1}}
    assert literal.label == "literal"
    assert reference.to_dict() == {"source": "subject", "path": "id"}
    assert reference.label == "subject.id"


def test_every_attribute_convenience_method_builds_the_expected_operator() -> None:
    attribute = ContextAttribute("value")
    conditions = [
        attribute.not_equals(1),
        attribute.is_in([1]),
        attribute.is_not_in([2]),
        attribute.contains(1),
        attribute.does_not_contain(2),
        attribute.intersects([1]),
        attribute.subset_of([1]),
        attribute.superset_of([1]),
        attribute.greater_than(0),
        attribute.greater_than_or_equal(1),
        attribute.less_than(2),
        attribute.less_than_or_equal(1),
    ]

    assert [condition.operator for condition in conditions] == [
        "neq",
        "in",
        "not_in",
        "contains",
        "not_contains",
        "intersects",
        "subset_of",
        "superset_of",
        "gt",
        "gte",
        "lt",
        "lte",
    ]


def test_mapping_membership_is_exact_and_non_collections_are_indeterminate() -> None:
    value = request(context={"mapping": {"tenant": 1}, "number": 7})

    assert state(ContextAttribute("mapping").contains("tenant"), value) is ConditionState.MATCH
    assert state(ContextAttribute("number").intersects([7]), value) is ConditionState.INDETERMINATE
    assert state(ContextAttribute("number").subset_of([7]), value) is ConditionState.INDETERMINATE


def test_comparison_constructor_rejects_invalid_shapes() -> None:
    left = ContextAttribute("value")

    with pytest.raises(ValueError, match="lowercase"):
        Comparison(left, "Not-Safe", Literal(1))
    with pytest.raises(ValueError, match="requires"):
        Comparison(left, "eq")
    with pytest.raises(ValueError, match="does not accept"):
        Comparison(left, "exists", Literal(True))


def test_missing_right_operand_and_unknown_operator_are_indeterminate() -> None:
    value = request(context={"left": 1})
    missing_right = ContextAttribute("left").equals(ContextAttribute("missing"))
    unknown = ContextAttribute("left").compare("custom", 1)

    assert state(missing_right, value) is ConditionState.INDETERMINATE
    assert state(unknown, value) is ConditionState.INDETERMINATE


def test_operator_registry_can_replace_explicitly_and_rejects_non_callables() -> None:
    registry = OperatorRegistry()
    registry.register("eq", lambda left, right: False, replace=True)

    assert not registry.evaluate("eq", 1, 1)
    with pytest.raises(TypeError, match="callable"):
        registry.register("bad", 1)  # type: ignore[arg-type]
    with pytest.raises(KeyError, match="Unknown ABAC operator"):
        OperatorRegistry(include_builtins=False).evaluate("missing", 1, 1)


def test_policy_operator_registry_is_frozen_after_construction() -> None:
    policy = AttributePolicy(ContextAttribute("value").equals("trusted"))

    assert policy.operators.frozen
    with pytest.raises(TypeError, match="frozen"):
        policy.operators.register("eq", lambda left, right: True, replace=True)


def test_policy_document_is_redacted_from_decisions_by_default() -> None:
    safe = AttributePolicy(ContextAttribute("token").equals("classified-policy-value"))
    diagnostic = AttributePolicy(
        ContextAttribute("token").equals("classified-policy-value"),
        name="diagnostic",
        include_policy_document_in_metadata=True,
    )

    safe_decision = safe.evaluate(request(context={"token": "wrong"}))
    diagnostic_decision = diagnostic.evaluate(request(context={"token": "wrong"}))

    assert safe_decision is not None
    assert "classified-policy-value" not in str(safe_decision.metadata)
    assert diagnostic_decision is not None
    assert "classified-policy-value" in str(diagnostic_decision.metadata)


def test_combinator_remaining_states_and_serialization() -> None:
    value = request(context={"truth": True, "false": False})
    indeterminate_all = AllOf(
        ContextAttribute("truth").equals(True),
        ContextAttribute("missing").equals(True),
    )
    no_match_any = AnyOf(
        ContextAttribute("false").equals(True),
        ContextAttribute("truth").equals(False),
    )
    negated_match = Not(ContextAttribute("truth").equals(True))
    negated_no_match = Not(ContextAttribute("false").equals(True))

    assert state(indeterminate_all, value) is ConditionState.INDETERMINATE
    assert state(no_match_any, value) is ConditionState.NO_MATCH
    assert state(negated_match, value) is ConditionState.NO_MATCH
    assert state(negated_no_match, value) is ConditionState.MATCH
    assert indeterminate_all.to_dict()["type"] == "all_of"
    assert no_match_any.to_dict()["type"] == "any_of"
    assert negated_match.to_dict()["type"] == "not"


def test_combinators_short_circuit_after_a_decisive_result() -> None:
    class MustNotRun:
        def evaluate(self, request: AuthorizationRequest, operators: OperatorRegistry) -> None:
            raise AssertionError("condition should have been short-circuited")

        def to_dict(self) -> dict[str, object]:
            return {"type": "comparison"}

    value = request(context={"truth": True})
    all_of = AllOf(ContextAttribute("truth").equals(False), MustNotRun())  # type: ignore[arg-type]
    any_of = AnyOf(ContextAttribute("truth").equals(True), MustNotRun())  # type: ignore[arg-type]

    assert state(all_of, value) is ConditionState.NO_MATCH
    assert state(any_of, value) is ConditionState.MATCH


def test_large_primitive_collection_comparison_remains_exact() -> None:
    value = request(context={"left": list(range(2_000)), "right": list(range(2_000, 4_000))})

    assert state(ContextAttribute("left").intersects(ContextAttribute("right")), value) is (
        ConditionState.NO_MATCH
    )


def test_complex_collection_comparison_budget_fails_closed() -> None:
    left = [{"value": index} for index in range(317)]
    right = [{"value": index} for index in range(317, 634)]
    value = request(context={"left": left, "right": right})

    assert state(ContextAttribute("left").intersects(ContextAttribute("right")), value) is (
        ConditionState.INDETERMINATE
    )


def test_policy_can_explicitly_abstain_on_indeterminate() -> None:
    policy = AttributePolicy(
        SubjectAttribute("missing").equals(True),
        on_indeterminate=MissEffect.ABSTAIN,
    )

    assert policy.evaluate(request()) is None
    assert not AuthorizationEngine([policy]).decide(request()).allowed


def test_policy_no_match_denial_contains_no_resolved_values() -> None:
    policy = AttributePolicy(SubjectAttribute("department").equals("secret-target"))

    decision = policy.evaluate(request(subject_attributes={"department": "secret-source"}))

    assert decision is not None
    assert not decision.allowed
    assert "secret" not in decision.reason
    assert "secret-source" not in str(decision.metadata)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda value: value.update({"type": "other"}), "type must"),
        (lambda value: value.update({"actions": "read"}), "actions must"),
        (lambda value: value.update({"match_effect": "maybe"}), "unsupported"),
        (lambda value: value.update({"name": ""}), "non-empty"),
        (lambda value: value.update({"condition": []}), "must be an object"),
    ],
)
def test_more_invalid_policy_shapes_are_rejected(mutator: object, message: str) -> None:
    document = complete_document()
    mutator(document)  # type: ignore[operator]

    with pytest.raises(PolicySchemaError, match=message):
        attribute_policy_from_dict(document)


@pytest.mark.parametrize(
    "condition",
    [
        {"type": "unknown"},
        {"type": "all_of", "conditions": "wrong"},
        {"type": "all_of", "conditions": []},
        {"type": "not", "condition": []},
        {
            "type": "comparison",
            "operator": "eq",
            "left": {"source": "missing", "path": "value"},
            "right": {"value": 1},
        },
        {
            "type": "comparison",
            "operator": "eq",
            "left": {"source": "context", "path": "bad..path"},
            "right": {"value": 1},
        },
        {
            "type": "comparison",
            "operator": "eq",
            "left": {"value": 1, "extra": True},
            "right": {"value": 1},
        },
        {
            "type": "comparison",
            "operator": "eq",
            "left": {"source": "context", "value": 1},
            "right": {"value": 1},
        },
    ],
)
def test_invalid_condition_documents_are_rejected(condition: dict[str, object]) -> None:
    with pytest.raises(PolicySchemaError):
        condition_from_dict(condition)


def test_loads_policy_rejects_non_object_json() -> None:
    with pytest.raises(PolicySchemaError, match="must be an object"):
        loads_policy("[]")


def test_loads_policy_rejects_duplicate_json_keys() -> None:
    with pytest.raises(PolicySchemaError, match="valid JSON"):
        loads_policy('{"schema_version":"access_gate.policy.v1","schema_version":"other"}')


def test_all_serialized_policy_entry_points_enforce_complexity_limits() -> None:
    condition: dict[str, object] = {
        "type": "comparison",
        "operator": "eq",
        "left": {"value": 1},
        "right": {"value": 1},
    }
    for _ in range(65):
        condition = {"type": "not", "condition": condition}

    with pytest.raises(PolicySchemaError, match="nesting depth"):
        condition_from_dict(condition)

    document = complete_document()
    document["actions"] = []
    with pytest.raises(PolicySchemaError, match="at least one"):
        attribute_policy_from_dict(document)

    document["actions"] = [f"action-{index}" for index in range(4_097)]
    with pytest.raises(PolicySchemaError, match="maximum item count"):
        attribute_policy_from_dict(document)


@pytest.mark.parametrize("group", ["all_of", "any_of", "not"])
def test_documented_condition_depth_is_accepted_and_the_next_level_rejected(group: str) -> None:
    literal: object = 1
    for _ in range(64):
        literal = [literal]

    def nested(levels: int) -> dict[str, object]:
        condition: dict[str, object] = {
            "type": "comparison",
            "operator": "eq",
            "left": {"source": "context", "path": "value"},
            "right": {"value": literal},
        }
        for _ in range(levels - 1):
            condition = (
                {"type": "not", "condition": condition}
                if group == "not"
                else {"type": group, "conditions": [condition]}
            )
        return condition

    document = complete_document()
    document["condition"] = nested(64)
    attribute_policy_from_dict(document)
    AttributePolicy(condition_from_dict(nested(64)))

    document["condition"] = nested(65)
    with pytest.raises(PolicySchemaError, match="nesting depth"):
        attribute_policy_from_dict(document)


def test_serialized_policies_enforce_size_and_node_limits() -> None:
    document = complete_document()
    with pytest.raises(PolicySchemaError, match="size limit"):
        loads_policy(json.dumps(document) + " " * 1_000_000)

    leaf = complete_document()["condition"]
    document["condition"] = {"type": "any_of", "conditions": [leaf] * 4_096}
    with pytest.raises(PolicySchemaError, match="maximum node count"):
        attribute_policy_from_dict(document)

    condition = complete_document()["condition"]
    assert isinstance(condition, dict)
    condition["right"] = {"value": [[0] * 10_000 for _ in range(11)]}
    document["condition"] = condition
    with pytest.raises(PolicySchemaError, match="literal value exceeds the maximum node count"):
        attribute_policy_from_dict(document)


def test_serialized_literals_require_bounded_finite_json_data() -> None:
    document = complete_document()
    condition = document["condition"]
    assert isinstance(condition, dict)
    condition["right"] = {"value": float("nan")}

    with pytest.raises(PolicySchemaError, match="finite"):
        attribute_policy_from_dict(document)
    with pytest.raises(PolicySchemaError, match="valid JSON"):
        loads_policy(json.dumps(document))

    condition["right"] = {"value": ("tuple",)}
    with pytest.raises(PolicySchemaError, match="JSON-compatible"):
        attribute_policy_from_dict(document)

    shared: list[object] = [1]
    condition["right"] = {"value": [shared, shared]}
    with pytest.raises(PolicySchemaError, match="shared or cyclic"):
        attribute_policy_from_dict(document)


def test_literal_built_from_a_live_view_is_snapshotted() -> None:
    allowed = {"uk": None}
    condition = ContextAttribute("country").is_in(allowed.keys())

    allowed["ru"] = None

    assert state(condition, request(context={"country": "ru"})) is ConditionState.NO_MATCH


def test_non_json_dsl_collection_literal_is_not_silently_changed() -> None:
    policy = AttributePolicy(ContextAttribute("scopes").equals({"read"}))

    with pytest.raises(PolicySchemaError, match="not JSON serializable"):
        dumps_policy(policy)


@pytest.mark.parametrize("condition_type", [["comparison"], {"type": "comparison"}])
def test_unhashable_condition_types_are_schema_errors(condition_type: object) -> None:
    condition = {
        "type": "not",
        "condition": {
            "type": condition_type,
            "operator": "eq",
            "left": {"source": "context", "path": "value"},
            "right": {"value": 1},
        },
    }
    document = complete_document()
    document["condition"] = condition

    with pytest.raises(PolicySchemaError, match="condition.type must be a non-empty string"):
        condition_from_dict(condition)
    with pytest.raises(PolicySchemaError, match="condition.type must be a non-empty string"):
        loads_policy(json.dumps(document))


def test_policy_documents_must_state_actions_and_omit_unused_operands() -> None:
    document = complete_document()
    del document["actions"]

    with pytest.raises(PolicySchemaError, match="actions is required"):
        attribute_policy_from_dict(document)
    with pytest.raises(PolicySchemaError, match="condition.right"):
        condition_from_dict(
            {
                "type": "comparison",
                "operator": "exists",
                "left": {"source": "context", "path": "device"},
                "right": None,
            }
        )
    assert attribute_policy_from_dict({**document, "actions": None}).actions is None
