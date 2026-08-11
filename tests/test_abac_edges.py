from __future__ import annotations

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


def test_mapping_membership_is_exact_and_non_collections_do_not_intersect() -> None:
    value = request(context={"mapping": {"tenant": 1}, "number": 7})

    assert state(ContextAttribute("mapping").contains("tenant"), value) is ConditionState.MATCH
    assert state(ContextAttribute("number").intersects([7]), value) is ConditionState.NO_MATCH
    assert state(ContextAttribute("number").subset_of([7]), value) is ConditionState.NO_MATCH


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
