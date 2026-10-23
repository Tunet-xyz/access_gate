from __future__ import annotations

import enum
import math
from dataclasses import dataclass
from types import MappingProxyType

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from access_gate import (
    AttributePolicy,
    AuthorizationRequest,
    ContextAttribute,
    Literal,
    Subject,
    SubjectAttribute,
    abac,
)
from access_gate.abac import AttributeRef, Operand, OperatorRegistry, _operand


class _Text(str):
    pass


class _Number(int):
    pass


class _TextEnum(str, enum.Enum):
    A = "a"


class _NumberEnum(enum.IntEnum):
    ONE = 1


class _Ref(AttributeRef):
    pass


@dataclass(frozen=True)
class _DuckOperand:
    value: object = "duck"

    def resolve(self, request: AuthorizationRequest) -> object:
        return self.value

    def to_dict(self) -> dict[str, object]:
        return {"value": self.value}

    @property
    def label(self) -> str:
        return "duck"


def _reference_operand(value: object) -> Operand:
    """The 0.3.0a1 implementation, kept as the equivalence oracle."""

    if isinstance(value, Operand):
        return value
    return Literal(value)


SCALARS = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats()
    | st.text(max_size=8)
    | st.binary(max_size=4)
    | st.text(max_size=4).map(_Text)
    | st.integers().map(_Number)
    | st.sampled_from([_TextEnum.A, _NumberEnum.ONE, math.nan])
)
OPERANDS = (
    SCALARS
    | st.lists(SCALARS, max_size=3)
    | st.lists(SCALARS, max_size=3).map(tuple)
    | st.dictionaries(st.text(max_size=3), SCALARS, max_size=3)
    | st.frozensets(st.text(max_size=3), max_size=3)
    | st.sampled_from(
        [
            SubjectAttribute("tenant"),
            ContextAttribute("method"),
            _Ref(abac.AttributeSource.SUBJECT, "attributes.tenant"),
            Literal("x"),
            Literal(["x", 1]),
            _DuckOperand(),
        ]
    )
)


@settings(max_examples=1000, deadline=None)
@given(OPERANDS)
def test_operand_matches_the_reference_conversion(value: object) -> None:
    expected = _reference_operand(value)
    actual = _operand(value)
    if expected is value:
        assert actual is value
    else:
        assert type(actual) is Literal and type(expected) is Literal
        assert actual.to_dict() == expected.to_dict() or (
            isinstance(value, float) and math.isnan(value) and actual.value is value
        )
        assert type(actual.value) is type(expected.value)


def test_operand_fast_paths_skip_the_runtime_protocol_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protocol_meta = type(Operand)
    calls: list[object] = []
    original = protocol_meta.__instancecheck__

    def counting(cls: type, instance: object) -> bool:
        calls.append(instance)
        return original(cls, instance)

    reference = SubjectAttribute("tenant")
    literal = Literal("acme")
    monkeypatch.setattr(protocol_meta, "__instancecheck__", counting)
    converted = [_operand(value) for value in ("acme", 1, 1.5, None, b"x")]
    same = [_operand(reference), _operand(literal)]
    subclassed = [_operand(value) for value in (True, _Text("acme"))]
    monkeypatch.undo()

    assert [operand.value for operand in converted] == ["acme", 1, 1.5, None, b"x"]
    assert same[0] is reference and same[1] is literal
    assert all(isinstance(operand, Literal) for operand in subclassed)
    assert calls == [True, _Text("acme")]


def test_default_policy_registry_is_built_without_revalidating_builtins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registrations: list[str] = []
    original = OperatorRegistry.register

    def counting(self: OperatorRegistry, name: str, *args: object, **kwargs: object) -> None:
        registrations.append(name)
        original(self, name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(OperatorRegistry, "register", counting)
    AttributePolicy(SubjectAttribute("tenant").equals("acme"))
    custom = OperatorRegistry({"same": lambda left, right: left == right})
    AttributePolicy(SubjectAttribute("tenant").equals("acme"), operators=custom)

    assert registrations == ["same", *abac._builtins(), "same"]


SAMPLE_OPERANDS = [
    None,
    True,
    1,
    2.5,
    math.nan,
    "a",
    "",
    ("a", "b"),
    frozenset({"a"}),
    MappingProxyType({"a": 1}),
    object(),
]


def test_default_policy_registry_is_equivalent_to_a_frozen_builtin_copy() -> None:
    first = AttributePolicy(SubjectAttribute("tenant").equals("acme"), name="first")
    second = AttributePolicy(SubjectAttribute("tenant").equals("acme"), name="second")
    reference = OperatorRegistry().copy(frozen=True)

    assert first.operators is not second.operators
    assert first.operators._operators is not second.operators._operators
    for registry in (first.operators, second.operators):
        assert type(registry) is OperatorRegistry
        assert registry.frozen
        assert registry.names == reference.names
        assert list(registry._operators) == list(reference._operators)
        with pytest.raises(TypeError, match="frozen"):
            registry.register("custom", lambda left, right: True)
        for name in reference._operators:
            for left in SAMPLE_OPERANDS:
                for right in SAMPLE_OPERANDS:
                    assert _evaluate(registry, name, left, right) == _evaluate(
                        reference, name, left, right
                    )


def test_custom_policy_registry_is_still_copied_and_frozen() -> None:
    custom = OperatorRegistry({"same": lambda left, right: left == right})
    policy = AttributePolicy(SubjectAttribute("tenant").compare("same", "acme"), operators=custom)
    custom.register("later", lambda left, right: True)
    request = AuthorizationRequest(Subject("subject-1", attributes={"tenant": "acme"}), "read")

    assert policy.operators is not custom
    assert policy.operators.frozen and not custom.frozen
    decision = policy.evaluate(request)
    assert not policy.operators.contains("later")
    assert decision is not None and decision.allowed


def _evaluate(registry: OperatorRegistry, name: str, left: object, right: object) -> object:
    try:
        return registry.evaluate(name, left, right)
    except Exception as error:  # noqa: BLE001 - the error itself is compared
        return (type(error), str(error))
