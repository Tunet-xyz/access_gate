from __future__ import annotations

import json

from hypothesis import given, settings
from hypothesis import strategies as st
from reference_authorization_model import deny_overrides, exact_contains, exact_equal

from access_gate import (
    AttributePolicy,
    AuthorizationEngine,
    AuthorizationRequest,
    ContextAttribute,
    Decision,
    Effect,
    FunctionPolicy,
    Not,
    Resource,
    Subject,
    dumps_policy,
    loads_policy,
    policy_fingerprint,
)
from access_gate.strategies import DenyOverrides

JSON_SCALAR = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text()
)
JSON_VALUE = st.recursive(
    JSON_SCALAR,
    lambda children: st.lists(children, max_size=8)
    | st.dictionaries(st.text(max_size=20), children, max_size=8),
    max_leaves=25,
)


@settings(max_examples=200, deadline=None)
@given(JSON_VALUE)
def test_authorization_values_are_immutable_json_round_trips(value: object) -> None:
    attributes = {"value": value}
    request = AuthorizationRequest(
        Subject("subject-1", attributes=attributes),
        "resource.read",
        Resource("record", "record-1", attributes),
        context=attributes,
        action_attributes=attributes,
    )
    snapshot = request.to_dict()

    attributes["value"] = "mutated"

    assert request.to_dict() == snapshot
    json.dumps(snapshot, allow_nan=False)


@settings(max_examples=200, deadline=None)
@given(JSON_SCALAR, JSON_SCALAR)
def test_exact_equality_matches_independent_reference(left: object, right: object) -> None:
    condition = ContextAttribute("left").equals(ContextAttribute("right"))
    request = AuthorizationRequest(
        Subject("subject-1"),
        "compare",
        context={"left": left, "right": right},
    )

    result = condition.evaluate(request, AttributePolicy(condition).operators)

    if left is None and right is None:
        assert result.state.value == "indeterminate"
    else:
        assert (result.state.value == "match") is exact_equal(left, right)


def _retyped(value: object, mode: str) -> object:
    if isinstance(value, bool):
        return int(value) if mode == "bool_as_int" else value
    if isinstance(value, int) and mode == "int_as_float" and abs(value) <= 2**53:
        return float(value)
    if isinstance(value, list):
        return [_retyped(item, mode) for item in value]
    if isinstance(value, dict):
        return {key: _retyped(item, mode) for key, item in value.items()}
    return value


@settings(max_examples=200, deadline=None)
@given(JSON_VALUE, st.sampled_from(["same", "bool_as_int", "int_as_float"]))
def test_nested_equality_matches_independent_reference(value: object, mode: str) -> None:
    other = _retyped(value, mode)
    condition = ContextAttribute("left").equals(ContextAttribute("right"))
    request = AuthorizationRequest(
        Subject("subject-1"),
        "compare",
        context={"left": value, "right": other},
    )

    result = condition.evaluate(request, AttributePolicy(condition).operators)

    if value is None:
        assert result.state.value == "indeterminate"
    else:
        assert (result.state.value == "match") is exact_equal(value, other)


@settings(max_examples=200, deadline=None)
@given(st.lists(JSON_SCALAR, max_size=30), JSON_SCALAR)
def test_collection_membership_matches_independent_reference(
    values: list[object],
    member: object,
) -> None:
    condition = ContextAttribute("member").is_in(ContextAttribute("values"))
    request = AuthorizationRequest(
        Subject("subject-1"),
        "compare",
        context={"member": member, "values": values},
    )

    result = condition.evaluate(request, AttributePolicy(condition).operators)

    assert (result.state.value == "match") is exact_contains(values, member)


@settings(max_examples=150, deadline=None)
@given(
    st.lists(st.sampled_from(["allow", "deny", "abstain"]), max_size=30),
)
def test_deny_overrides_matches_independent_truth_table(effects: list[str]) -> None:
    decisions = [
        Decision(Effect(effect), f"{effect} decision", policy=f"policy-{index}")
        for index, effect in enumerate(effects)
        if effect != "abstain"
    ]
    request = AuthorizationRequest(Subject("subject-1"), "read")

    actual = DenyOverrides().combine(request, decisions)

    assert actual.effect.value == deny_overrides(effects)


@settings(max_examples=150, deadline=None)
@given(JSON_SCALAR, JSON_SCALAR, st.text(min_size=1, max_size=30))
def test_policy_round_trip_preserves_identity_and_decision(
    configured: object,
    supplied: object,
    name_suffix: str,
) -> None:
    safe_suffix = name_suffix.encode("unicode_escape").hex()[:40] or "00"
    original = AttributePolicy(
        ContextAttribute("value").equals(configured),
        name=f"property_{safe_suffix}",
    )
    restored = loads_policy(dumps_policy(original, indent=None))
    request = AuthorizationRequest(Subject("subject-1"), "read", context={"value": supplied})

    assert restored.to_dict() == original.to_dict()
    assert policy_fingerprint(restored) == policy_fingerprint(original)
    assert restored.evaluate(request) == original.evaluate(request)


@settings(max_examples=100, deadline=None)
@given(st.sampled_from(["in", "not_in"]), st.one_of(st.none(), st.integers(), st.text()))
def test_malformed_collection_operands_never_grant(operator: str, malformed: object) -> None:
    policy = AttributePolicy(ContextAttribute("role").compare(operator, malformed))
    request = AuthorizationRequest(
        Subject("subject-1"),
        "read",
        context={"role": "admin"},
    )

    assert not AuthorizationEngine([policy]).decide(request).allowed


@settings(max_examples=100, deadline=None)
@given(st.text(min_size=1), st.text(min_size=1))
def test_missing_data_under_negation_never_grants(attribute: str, action: str) -> None:
    safe_attribute = attribute.replace(".", "_")
    policy = AttributePolicy(Not(ContextAttribute(safe_attribute).equals(True)))

    decision = AuthorizationEngine([policy]).decide(
        AuthorizationRequest(Subject("subject-1"), action)
    )

    assert not decision.allowed


@settings(max_examples=100, deadline=None)
@given(st.text(min_size=1))
def test_no_applicable_grant_is_always_denied(action: str) -> None:
    policy = FunctionPolicy(
        "different_action",
        lambda request: Decision.allow("Allowed."),
        actions={"reserved.action"},
    )

    decision = AuthorizationEngine([policy]).decide(
        AuthorizationRequest(Subject("subject-1"), action)
    )

    assert action == "reserved.action" or not decision.allowed
