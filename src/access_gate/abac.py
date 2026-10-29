"""Safe, declarative attribute-based access control primitives."""

from __future__ import annotations

import json
import re
from cmath import isnan as _complex_isnan
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from importlib.resources import files
from inspect import isawaitable
from math import isfinite, isnan
from types import MappingProxyType
from typing import Protocol, cast, runtime_checkable

from .policies import MissEffect
from .types import AuthorizationRequest, Decision, Effect, _freeze_value

POLICY_SCHEMA_VERSION = "access_gate.policy.v1"
_OPERATOR_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
MAX_POLICY_DOCUMENT_CHARS = 1_000_000
MAX_POLICY_CONDITION_DEPTH = 64
MAX_POLICY_CONDITION_NODES = 4_096
MAX_POLICY_LITERAL_NODES = 100_000
MAX_COLLECTION_ITEMS = 10_000
MAX_FALLBACK_COMPARISONS = 100_000
# A serialized condition nests two containers per all_of/any_of level, then an
# operand object and a literal of up to MAX_POLICY_CONDITION_DEPTH levels.
_MAX_CONDITION_DOCUMENT_DEPTH = (
    2 * (MAX_POLICY_CONDITION_DEPTH - 1) + 2 + MAX_POLICY_CONDITION_DEPTH
)


class PolicySchemaError(ValueError):
    """Raised when a serialized policy is malformed or unsupported."""


def _thaw_policy_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_policy_value(child) for key, child in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw_policy_value(child) for child in value]
    if isinstance(value, frozenset | set):
        return value
    return value


class AttributeSource(str, Enum):
    """A namespace from which an ABAC operand is resolved."""

    SUBJECT = "subject"
    RESOURCE = "resource"
    ACTION = "action"
    CONTEXT = "context"


class ConditionState(str, Enum):
    """Tri-state condition outcome used to preserve fail-closed semantics."""

    MATCH = "match"
    NO_MATCH = "no_match"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class ConditionResult:
    """A condition outcome that never contains resolved attribute values."""

    state: ConditionState
    reason: str
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Policies and combinators branch on identity with these states, so any
        # other value would fall through to their match path.
        if not isinstance(self.state, ConditionState):
            raise TypeError("ConditionResult.state must be a ConditionState value.")

    @property
    def matched(self) -> bool:
        return self.state is ConditionState.MATCH


class _Missing:
    __slots__ = ()


MISSING = _Missing()
_UNSET_OPERAND = object()
ResolvedValue = object | _Missing
OperatorFunction = Callable[[object, object], bool]


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _reject_nan(value: object) -> None:
    if isinstance(value, float):
        if isnan(value):
            raise ValueError("NaN is not a comparable authorization value.")
    elif isinstance(value, Decimal | complex) and (
        value.is_nan() if isinstance(value, Decimal) else _complex_isnan(value)
    ):
        # A Decimal NaN (DecimalField, Decimal("nan") from input) or a complex
        # NaN compares unequal to everything, just like a float NaN.
        raise ValueError("NaN is not a comparable authorization value.")


def _equal(left: object, right: object, budget: _ComparisonBudget | None = None) -> bool:
    _reject_nan(left)
    _reject_nan(right)
    if _is_number(left) and _is_number(right):
        return bool(left == right)
    if type(left) is not type(right):
        return False
    if not isinstance(left, tuple | list | Mapping | frozenset | set):
        return bool(left == right)
    if budget is None:
        budget = _ComparisonBudget()
    # Containers keep the same type-aware semantics as top-level values
    # (``[True]`` never equals ``[1]``). A hashable container's exact key
    # encodes exactly that, and is computed once per operator call.
    if isinstance(left, tuple | frozenset):
        left_key = _exact_key(left, budget)
        if left_key is not _UNHASHABLE:
            right_key = _exact_key(right, budget)
            if right_key is not _UNHASHABLE:
                return left_key == right_key
    if isinstance(left, tuple | list):
        items = cast(Sequence[object], right)
        return len(left) == len(items) and all(
            _equal(a, b, budget) for a, b in zip(left, items, strict=True)
        )
    if isinstance(left, Mapping):
        mapping = cast(Mapping[object, object], right)
        return _same_members(left, mapping, budget) and all(
            _equal(value, mapping[key], budget) for key, value in left.items()
        )
    return _same_members(left, cast(Collection[object], right), budget)


def _collection(value: object) -> Collection[object] | Mapping[object, object] | None:
    if isinstance(value, str | bytes | bytearray):
        return None
    if isinstance(value, Mapping):
        return cast(Mapping[object, object], value)
    if isinstance(value, Collection):
        return cast(Collection[object], value)
    return None


def _required_collection(
    value: object,
    *,
    operand: str,
) -> Collection[object] | Mapping[object, object]:
    values = _collection(value)
    if values is None:
        raise TypeError(f"{operand} operand must be a non-string collection.")
    if len(values) > MAX_COLLECTION_ITEMS:
        raise ValueError(f"{operand} operand exceeds the collection size limit.")
    return values


_UNHASHABLE = object()


class _ComparisonBudget:
    """Cost accounting shared by every nested comparison of one operator call.

    Hashable container keys are memoized by identity (holding the container, so
    its id cannot be reused), and every member-by-member fallback draws on one
    budget, so nested values cannot multiply the per-level limit.
    """

    __slots__ = ("keys", "remaining")

    def __init__(self) -> None:
        self.keys: dict[int, tuple[object, object]] = {}
        self.remaining = MAX_FALLBACK_COMPARISONS

    def charge(self, comparisons: int) -> None:
        self.remaining -= comparisons
        if self.remaining < 0:
            raise ValueError("Collection comparison exceeds the safe comparison limit.")


def _exact_key(value: object, budget: _ComparisonBudget | None = None) -> object:
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int | float):
        if isinstance(value, float) and isnan(value):
            return _UNHASHABLE
        return ("number", value)
    if isinstance(value, str | bytes):
        # Keyed by exact type, so a str subclass such as a StrEnum member matches
        # a plain string here exactly when ``_equal`` would.
        return (type(value), value)
    if value is None:
        return ("none", None)
    if isinstance(value, tuple | frozenset):
        if budget is None:
            budget = _ComparisonBudget()
        cached = budget.keys.get(id(value))
        if cached is not None and cached[0] is value:
            return cached[1]
        key = _container_key(value, budget)
        budget.keys[id(value)] = (value, key)
        return key
    if isinstance(value, Mapping | list | set):
        # Unhashable containers keep the capped member-by-member comparison.
        return _UNHASHABLE
    try:
        _reject_nan(value)
        hash(value)
    except (TypeError, ValueError):
        # Unhashable values and NaNs are compared member by member, where
        # ``_equal`` rejects a NaN.
        return _UNHASHABLE
    # Other hashable values (UUID, date, Enum, Decimal) compare by exact type
    # and ``==``, as ``_equal`` does.
    return (type(value), value)


def _container_key(
    value: tuple[object, ...] | frozenset[object], budget: _ComparisonBudget
) -> object:
    keys: list[object] = []
    for item in value:
        key = _exact_key(item, budget)
        if key is _UNHASHABLE:
            return _UNHASHABLE
        keys.append(key)
    return (type(value), tuple(keys) if isinstance(value, tuple) else frozenset(keys))


def _exact_key_set(
    values: Collection[object] | Mapping[object, object],
    budget: _ComparisonBudget | None = None,
) -> set[object] | None:
    keys: set[object] = set()
    for value in values:
        key = _exact_key(value, budget)
        if key is _UNHASHABLE:
            return None
        keys.add(key)
    return keys


def _same_members(
    left: Collection[object] | Mapping[object, object],
    right: Collection[object] | Mapping[object, object],
    budget: _ComparisonBudget,
) -> bool:
    if len(left) != len(right):
        return False
    left_keys = _exact_key_set(left, budget)
    right_keys = _exact_key_set(right, budget)
    if left_keys is not None and right_keys is not None:
        return left_keys == right_keys
    # One budget covers every nested fallback of the operator call.
    budget.charge(len(left) * len(right))
    return all(any(_equal(item, other, budget) for other in right) for item in left)


def _contains(container: object, member: object) -> bool:
    values = _required_collection(container, operand="collection")
    budget = _ComparisonBudget()
    return any(_equal(candidate, member, budget) for candidate in values)


def _intersects(left: object, right: object) -> bool:
    left_values = _required_collection(left, operand="left")
    right_values = _required_collection(right, operand="right")
    budget = _ComparisonBudget()
    left_keys = _exact_key_set(left_values, budget)
    right_keys = _exact_key_set(right_values, budget)
    if left_keys is not None and right_keys is not None:
        return not left_keys.isdisjoint(right_keys)
    budget.charge(len(left_values) * len(right_values))
    return any(_equal(a, b, budget) for a in left_values for b in right_values)


def _subset_of(left: object, right: object) -> bool:
    left_values = _required_collection(left, operand="left")
    right_values = _required_collection(right, operand="right")
    budget = _ComparisonBudget()
    left_keys = _exact_key_set(left_values, budget)
    right_keys = _exact_key_set(right_values, budget)
    if left_keys is not None and right_keys is not None:
        return left_keys <= right_keys
    budget.charge(len(left_values) * len(right_values))
    return all(
        any(_equal(item, candidate, budget) for candidate in right_values) for item in left_values
    )


def _ordered(left: object, right: object, operation: str) -> bool:
    if not (_is_number(left) and _is_number(right)):
        raise TypeError("Ordered comparisons require int or float operands.")
    _reject_nan(left)
    _reject_nan(right)
    left_number = cast(float, left)
    right_number = cast(float, right)
    if operation == "gt":
        return left_number > right_number
    if operation == "gte":
        return left_number >= right_number
    if operation == "lt":
        return left_number < right_number
    return left_number <= right_number


def _builtins() -> dict[str, OperatorFunction]:
    return {
        "eq": _equal,
        "neq": lambda left, right: not _equal(left, right),
        "in": lambda left, right: _contains(right, left),
        "not_in": lambda left, right: not _contains(right, left),
        "contains": _contains,
        "not_contains": lambda left, right: not _contains(left, right),
        "intersects": _intersects,
        "subset_of": _subset_of,
        "superset_of": lambda left, right: _subset_of(right, left),
        "gt": lambda left, right: _ordered(left, right, "gt"),
        "gte": lambda left, right: _ordered(left, right, "gte"),
        "lt": lambda left, right: _ordered(left, right, "lt"),
        "lte": lambda left, right: _ordered(left, right, "lte"),
    }


class OperatorRegistry:
    """A named collection of comparison callables.

    Registries are copied into each policy, so application customization cannot
    mutate a process-wide global operator table.
    """

    def __init__(
        self,
        operators: Mapping[str, OperatorFunction] | None = None,
        *,
        include_builtins: bool = True,
        frozen: bool = False,
    ) -> None:
        self._frozen = False
        self._operators = _builtins() if include_builtins else {}
        if operators is not None:
            for name, evaluator in operators.items():
                self.register(name, evaluator, replace=True)
        self._frozen = frozen

    def register(
        self,
        name: str,
        evaluator: OperatorFunction,
        *,
        replace: bool = False,
    ) -> None:
        if self._frozen:
            raise TypeError("A frozen operator registry cannot be modified.")
        if not _OPERATOR_NAME.fullmatch(name):
            raise ValueError("Operator names must use lowercase letters, digits, and underscores.")
        if name in {"exists", "not_exists"}:
            raise ValueError(f"{name!r} is reserved by the condition evaluator.")
        if name in self._operators and not replace:
            raise ValueError(f"Operator {name!r} is already registered.")
        if not callable(evaluator):
            raise TypeError("Operator evaluators must be callable.")
        self._operators[name] = evaluator

    def contains(self, name: str) -> bool:
        return name in {"exists", "not_exists"} or name in self._operators

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(sorted((*self._operators, "exists", "not_exists")))

    @property
    def frozen(self) -> bool:
        return self._frozen

    def evaluate(self, name: str, left: object, right: object) -> bool:
        try:
            evaluator = self._operators[name]
        except KeyError as error:
            raise KeyError(f"Unknown ABAC operator: {name}") from error
        result = evaluator(left, right)
        if isawaitable(result):
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise TypeError("ABAC operators must be synchronous.")
        if not isinstance(result, bool):
            raise TypeError("ABAC operators must return a boolean.")
        return result

    def copy(self, *, frozen: bool = False) -> OperatorRegistry:
        return OperatorRegistry(self._operators, include_builtins=False, frozen=frozen)


_BUILTIN_OPERATORS: Mapping[str, OperatorFunction] = MappingProxyType(_builtins())


def _frozen_builtin_registry() -> OperatorRegistry:
    """Return ``OperatorRegistry().copy(frozen=True)`` without re-validating.

    The built-in names are constants that already satisfy ``register()``; each
    policy still receives its own frozen registry.
    """

    registry = OperatorRegistry(include_builtins=False)
    registry._operators.update(_BUILTIN_OPERATORS)
    registry._frozen = True
    return registry


@runtime_checkable
class Operand(Protocol):
    def resolve(self, request: AuthorizationRequest) -> ResolvedValue: ...

    def to_dict(self) -> dict[str, object]: ...

    @property
    def label(self) -> str: ...


@dataclass(frozen=True, slots=True)
class Literal:
    """A literal condition operand."""

    value: object

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value",
            _freeze_value(self.value, field_name="literal.value"),
        )

    def resolve(self, request: AuthorizationRequest) -> ResolvedValue:
        del request
        return self.value

    def to_dict(self) -> dict[str, object]:
        return {"value": _thaw_policy_value(self.value)}

    @property
    def label(self) -> str:
        return "literal"


@dataclass(frozen=True, slots=True)
class AttributeRef:
    """A mapping-only attribute reference; object attribute access is never used."""

    source: AttributeSource
    path: str

    def __post_init__(self) -> None:
        if not self.path or any(not part for part in self.path.split(".")):
            raise ValueError("Attribute paths must contain non-empty dot-separated segments.")

    @property
    def label(self) -> str:
        return f"{self.source.value}.{self.path}"

    def to_dict(self) -> dict[str, object]:
        return {"source": self.source.value, "path": self.path}

    def resolve(self, request: AuthorizationRequest) -> ResolvedValue:
        root: object
        if self.source is AttributeSource.SUBJECT:
            root = {
                "id": request.subject.identifier,
                "authenticated": request.subject.authenticated,
                "roles": request.subject.roles,
                "attributes": request.subject.attributes,
            }
        elif self.source is AttributeSource.RESOURCE:
            if request.resource is None:
                return MISSING
            root = {
                "id": request.resource.identifier,
                "kind": request.resource.kind,
                "attributes": request.resource.attributes,
            }
        elif self.source is AttributeSource.ACTION:
            root = {"name": request.action, "attributes": request.action_attributes}
        else:
            root = request.context

        current: object = root
        for segment in self.path.split("."):
            if not isinstance(current, Mapping) or segment not in current:
                return MISSING
            current = cast(Mapping[str, object], current)[segment]
        return current

    def compare(self, operator: str, other: Operand | object = _UNSET_OPERAND) -> Comparison:
        right = None if other is _UNSET_OPERAND else _operand(other)
        return Comparison(self, operator, right)

    def equals(self, other: Operand | object) -> Comparison:
        return self.compare("eq", other)

    def not_equals(self, other: Operand | object) -> Comparison:
        return self.compare("neq", other)

    def is_in(self, other: Operand | object) -> Comparison:
        return self.compare("in", other)

    def is_not_in(self, other: Operand | object) -> Comparison:
        return self.compare("not_in", other)

    def contains(self, other: Operand | object) -> Comparison:
        return self.compare("contains", other)

    def does_not_contain(self, other: Operand | object) -> Comparison:
        return self.compare("not_contains", other)

    def intersects(self, other: Operand | object) -> Comparison:
        return self.compare("intersects", other)

    def subset_of(self, other: Operand | object) -> Comparison:
        return self.compare("subset_of", other)

    def superset_of(self, other: Operand | object) -> Comparison:
        return self.compare("superset_of", other)

    def greater_than(self, other: Operand | object) -> Comparison:
        return self.compare("gt", other)

    def greater_than_or_equal(self, other: Operand | object) -> Comparison:
        return self.compare("gte", other)

    def less_than(self, other: Operand | object) -> Comparison:
        return self.compare("lt", other)

    def less_than_or_equal(self, other: Operand | object) -> Comparison:
        return self.compare("lte", other)

    def exists(self) -> Comparison:
        return self.compare("exists")

    def does_not_exist(self) -> Comparison:
        return self.compare("not_exists")


def SubjectAttribute(path: str) -> AttributeRef:
    return AttributeRef(AttributeSource.SUBJECT, f"attributes.{path}")


def ResourceAttribute(path: str) -> AttributeRef:
    return AttributeRef(AttributeSource.RESOURCE, f"attributes.{path}")


def ActionAttribute(path: str) -> AttributeRef:
    return AttributeRef(AttributeSource.ACTION, f"attributes.{path}")


def ContextAttribute(path: str) -> AttributeRef:
    return AttributeRef(AttributeSource.CONTEXT, path)


class Condition(Protocol):
    def evaluate(
        self,
        request: AuthorizationRequest,
        operators: OperatorRegistry,
    ) -> ConditionResult: ...

    def to_dict(self) -> dict[str, object]: ...


# Exact built-in scalars never satisfy the Operand protocol. Subclasses, bool
# included, are not listed and keep the runtime protocol check.
_SCALAR_LITERAL_TYPES = frozenset({str, int, float, bytes, type(None)})


def _operand(value: Operand | object) -> Operand:
    # Skip the runtime protocol check, which inspects every protocol member, for
    # the two built-in operand classes and for exact scalar literals.
    value_type = type(value)
    if value_type is AttributeRef or value_type is Literal:
        return cast(Operand, value)
    if value_type in _SCALAR_LITERAL_TYPES:
        return Literal(value)
    if isinstance(value, Operand):
        return value
    return Literal(value)


def _result(
    state: ConditionState,
    reason: str,
    **metadata: object,
) -> ConditionResult:
    return ConditionResult(state, reason, MappingProxyType(metadata))


@dataclass(frozen=True, slots=True)
class Comparison:
    """Compare two operands using a named, registry-controlled operator."""

    left: Operand
    operator: str
    right: Operand | None = None

    def __post_init__(self) -> None:
        if not _OPERATOR_NAME.fullmatch(self.operator):
            raise ValueError("Operator names must use lowercase letters, digits, and underscores.")
        if self.operator not in {"exists", "not_exists"} and self.right is None:
            raise ValueError(f"Operator {self.operator!r} requires a right operand.")
        if self.operator in {"exists", "not_exists"} and self.right is not None:
            raise ValueError(f"Operator {self.operator!r} does not accept a right operand.")

    def evaluate(
        self,
        request: AuthorizationRequest,
        operators: OperatorRegistry,
    ) -> ConditionResult:
        left_value = self.left.resolve(request)
        metadata = {"operator": self.operator, "left": self.left.label}
        if self.right is not None:
            metadata["right"] = self.right.label

        if self.operator == "exists":
            state = ConditionState.NO_MATCH if left_value is MISSING else ConditionState.MATCH
            return _result(state, "Attribute existence was evaluated.", **metadata)
        if self.operator == "not_exists":
            state = ConditionState.MATCH if left_value is MISSING else ConditionState.NO_MATCH
            return _result(state, "Attribute absence was evaluated.", **metadata)
        if left_value is MISSING:
            return _result(
                ConditionState.INDETERMINATE,
                "A required left attribute is missing.",
                issue="missing_left_operand",
                **metadata,
            )

        if self.right is None:  # Defensive against corrupted/deserialized objects.
            return _result(
                ConditionState.INDETERMINATE,
                "The condition is missing a required operand.",
                issue="missing_configured_operand",
                **metadata,
            )
        right_value = self.right.resolve(request)
        if right_value is MISSING:
            return _result(
                ConditionState.INDETERMINATE,
                "A required right attribute is missing.",
                issue="missing_right_operand",
                **metadata,
            )
        if (
            left_value is None
            and right_value is None
            and not isinstance(self.left, Literal)
            and not isinstance(self.right, Literal)
        ):
            # Two absent facts never establish a relationship; compare with an
            # explicit null literal when null is the intended value.
            return _result(
                ConditionState.INDETERMINATE,
                "Both compared attributes are null.",
                issue="null_operands",
                **metadata,
            )
        if not operators.contains(self.operator):
            return _result(
                ConditionState.INDETERMINATE,
                "The condition references an unknown operator.",
                issue="unknown_operator",
                **metadata,
            )
        try:
            matched = operators.evaluate(self.operator, left_value, right_value)
        except Exception as error:
            return _result(
                ConditionState.INDETERMINATE,
                "The condition operator failed.",
                issue="operator_error",
                error_type=type(error).__name__,
                **metadata,
            )
        state = ConditionState.MATCH if matched else ConditionState.NO_MATCH
        return _result(state, "Attribute comparison was evaluated.", **metadata)

    def to_dict(self) -> dict[str, object]:
        document: dict[str, object] = {
            "type": "comparison",
            "operator": self.operator,
            "left": self.left.to_dict(),
        }
        if self.right is not None:
            document["right"] = self.right.to_dict()
        return document


@dataclass(frozen=True, slots=True, init=False)
class AllOf:
    conditions: tuple[Condition, ...]

    def __init__(self, *conditions: Condition) -> None:
        if not conditions:
            raise ValueError("AllOf requires at least one condition.")
        object.__setattr__(self, "conditions", tuple(conditions))

    def evaluate(
        self,
        request: AuthorizationRequest,
        operators: OperatorRegistry,
    ) -> ConditionResult:
        states: list[str] = []
        indeterminate = False
        for condition in self.conditions:
            result = condition.evaluate(request, operators)
            states.append(result.state.value)
            if result.state is ConditionState.NO_MATCH:
                return _result(
                    ConditionState.NO_MATCH,
                    "At least one required condition did not match.",
                    children=tuple(states),
                )
            if result.state is ConditionState.INDETERMINATE:
                indeterminate = True
        if indeterminate:
            return _result(
                ConditionState.INDETERMINATE,
                "A required condition was indeterminate.",
                children=tuple(states),
            )
        return _result(
            ConditionState.MATCH,
            "All required conditions matched.",
            children=tuple(states),
        )

    def to_dict(self) -> dict[str, object]:
        return {"type": "all_of", "conditions": [item.to_dict() for item in self.conditions]}


@dataclass(frozen=True, slots=True, init=False)
class AnyOf:
    conditions: tuple[Condition, ...]

    def __init__(self, *conditions: Condition) -> None:
        if not conditions:
            raise ValueError("AnyOf requires at least one condition.")
        object.__setattr__(self, "conditions", tuple(conditions))

    def evaluate(
        self,
        request: AuthorizationRequest,
        operators: OperatorRegistry,
    ) -> ConditionResult:
        states: list[str] = []
        indeterminate = False
        for condition in self.conditions:
            result = condition.evaluate(request, operators)
            states.append(result.state.value)
            if result.state is ConditionState.MATCH:
                return _result(
                    ConditionState.MATCH,
                    "At least one condition matched.",
                    children=tuple(states),
                )
            if result.state is ConditionState.INDETERMINATE:
                indeterminate = True
        if indeterminate:
            return _result(
                ConditionState.INDETERMINATE,
                "An alternative condition was indeterminate.",
                children=tuple(states),
            )
        return _result(
            ConditionState.NO_MATCH,
            "No alternative condition matched.",
            children=tuple(states),
        )

    def to_dict(self) -> dict[str, object]:
        return {"type": "any_of", "conditions": [item.to_dict() for item in self.conditions]}


@dataclass(frozen=True, slots=True)
class Not:
    condition: Condition

    def evaluate(
        self,
        request: AuthorizationRequest,
        operators: OperatorRegistry,
    ) -> ConditionResult:
        child = self.condition.evaluate(request, operators)
        if child.state is ConditionState.INDETERMINATE:
            return _result(
                ConditionState.INDETERMINATE,
                "A negated condition was indeterminate.",
                child=child.state.value,
            )
        state = (
            ConditionState.NO_MATCH
            if child.state is ConditionState.MATCH
            else ConditionState.MATCH
        )
        return _result(state, "A condition result was negated.", child=child.state.value)

    def to_dict(self) -> dict[str, object]:
        return {"type": "not", "condition": self.condition.to_dict()}


@dataclass(frozen=True, slots=True, init=False)
class AttributePolicy:
    """A declarative ABAC policy with explicit no-match and error behaviour."""

    condition: Condition
    actions: frozenset[str] | None
    match_effect: Effect
    on_no_match: MissEffect
    on_indeterminate: MissEffect
    name: str
    operators: OperatorRegistry
    include_policy_document_in_metadata: bool
    _condition_document: Mapping[str, object]

    def __init__(
        self,
        condition: Condition,
        *,
        actions: Collection[str] | None = None,
        match_effect: Effect = Effect.ALLOW,
        on_no_match: MissEffect | None = None,
        on_indeterminate: MissEffect = MissEffect.DENY,
        name: str = "attribute",
        operators: OperatorRegistry | None = None,
        include_policy_document_in_metadata: bool = False,
    ) -> None:
        if on_no_match is None:
            on_no_match = MissEffect.DENY if match_effect is Effect.ALLOW else MissEffect.ABSTAIN
        if not isinstance(match_effect, Effect):
            raise TypeError("match_effect must be an Effect value.")
        if not isinstance(on_no_match, MissEffect):
            raise TypeError("on_no_match must be a MissEffect value.")
        if not isinstance(on_indeterminate, MissEffect):
            raise TypeError("on_indeterminate must be a MissEffect value.")
        if not isinstance(name, str) or not name:
            raise TypeError("policy name must be a non-empty string.")
        if not isinstance(include_policy_document_in_metadata, bool):
            raise TypeError("include_policy_document_in_metadata must be a boolean.")
        if isinstance(actions, str):
            raise TypeError("actions must be a collection of names, not a string.")
        normalized_actions = None if actions is None else frozenset(actions)
        if normalized_actions is not None:
            if not normalized_actions:
                raise ValueError("actions must contain at least one action when provided.")
            if len(normalized_actions) > MAX_POLICY_CONDITION_NODES:
                raise ValueError("actions exceeds the maximum item count.")
            if not all(isinstance(action, str) and action for action in normalized_actions):
                raise TypeError("actions must contain only non-empty strings.")
        try:
            condition_document = condition.to_dict()
        except RecursionError as error:
            raise PolicySchemaError("condition exceeds the maximum nesting depth.") from error
        if not isinstance(condition_document, Mapping):
            raise TypeError("condition.to_dict() must return a mapping.")
        _validate_condition_complexity(condition_document)
        frozen_document = _freeze_value(
            condition_document,
            field_name="condition document",
            max_depth=_MAX_CONDITION_DOCUMENT_DEPTH,
        )
        if not isinstance(frozen_document, Mapping):
            raise TypeError("condition.to_dict() must return a mapping.")
        object.__setattr__(self, "condition", condition)
        object.__setattr__(self, "actions", normalized_actions)
        object.__setattr__(self, "match_effect", match_effect)
        object.__setattr__(self, "on_no_match", on_no_match)
        object.__setattr__(self, "on_indeterminate", on_indeterminate)
        object.__setattr__(self, "name", name)
        object.__setattr__(
            self,
            "operators",
            operators.copy(frozen=True) if operators else _frozen_builtin_registry(),
        )
        object.__setattr__(
            self,
            "include_policy_document_in_metadata",
            include_policy_document_in_metadata,
        )
        object.__setattr__(self, "_condition_document", frozen_document)

    def evaluate(self, request: AuthorizationRequest) -> Decision | None:
        if self.actions is not None and request.action not in self.actions:
            return None
        result = self.condition.evaluate(request, self.operators)
        if isawaitable(result):
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise TypeError("ABAC conditions must be synchronous.")
        if not isinstance(result, ConditionResult):
            raise TypeError("ABAC conditions must return a ConditionResult.")
        metadata: dict[str, object] = {
            "condition_state": result.state.value,
            "evaluation": dict(result.metadata),
        }
        if self.include_policy_document_in_metadata:
            metadata["condition"] = self._condition_document
        if result.state is ConditionState.INDETERMINATE:
            if self.on_indeterminate is MissEffect.ABSTAIN:
                return None
            return Decision.deny(
                "The attribute condition could not be safely evaluated.",
                policy=self.name,
                metadata=metadata,
            )
        if result.state is ConditionState.NO_MATCH:
            if self.on_no_match is MissEffect.ABSTAIN:
                return None
            return Decision.deny(
                "The attribute condition did not match.",
                policy=self.name,
                metadata=metadata,
            )
        if self.match_effect is Effect.DENY:
            return Decision.deny(
                "The attribute condition matched a deny rule.",
                policy=self.name,
                metadata=metadata,
            )
        return Decision.allow(
            "The attribute condition matched.",
            policy=self.name,
            metadata=metadata,
        )

    def to_dict(self) -> dict[str, object]:
        condition = _thaw_policy_value(self._condition_document)
        if not isinstance(condition, dict):  # pragma: no cover - constructor invariant
            raise TypeError("The cached condition document is invalid.")
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "type": "attribute_policy",
            "name": self.name,
            "actions": None if self.actions is None else sorted(self.actions),
            "match_effect": self.match_effect.value,
            "on_no_match": self.on_no_match.value,
            "on_indeterminate": self.on_indeterminate.value,
            "condition": condition,
        }

    @classmethod
    def from_dict(
        cls,
        document: Mapping[str, object],
        *,
        operators: OperatorRegistry | None = None,
    ) -> AttributePolicy:
        return attribute_policy_from_dict(document, operators=operators)


def _mapping(value: object, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise PolicySchemaError(f"{field_name} must be an object with string keys.")
    return cast(Mapping[str, object], value)


def _string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicySchemaError(f"{field_name} must be a non-empty string.")
    return value


def _check_keys(
    document: Mapping[str, object],
    *,
    allowed: Collection[str],
    field_name: str,
) -> None:
    extras = sorted(set(document) - set(allowed))
    if extras:
        raise PolicySchemaError(f"{field_name} contains unknown fields: {', '.join(extras)}")


def _validate_condition_complexity(condition: Mapping[str, object]) -> None:
    stack: list[tuple[object, int]] = [(condition, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_POLICY_CONDITION_NODES:
            raise PolicySchemaError("condition exceeds the maximum node count.")
        if depth > MAX_POLICY_CONDITION_DEPTH:
            raise PolicySchemaError("condition exceeds the maximum nesting depth.")
        if not isinstance(current, Mapping):
            continue
        condition_type = current.get("type")
        if not isinstance(condition_type, str):
            continue
        if condition_type == "not":
            stack.append((current.get("condition"), depth + 1))
        elif condition_type in {"all_of", "any_of"}:
            children = current.get("conditions")
            if isinstance(children, Sequence) and not isinstance(children, str | bytes):
                stack.extend((child, depth + 1) for child in children)


def _validate_serialized_literal(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    seen: set[int] = set()
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_POLICY_LITERAL_NODES:
            raise PolicySchemaError("literal value exceeds the maximum node count.")
        if depth > MAX_POLICY_CONDITION_DEPTH:
            raise PolicySchemaError("literal value exceeds the maximum nesting depth.")
        if current is None or isinstance(current, str | bool | int):
            continue
        if isinstance(current, float):
            if not isfinite(current):
                raise PolicySchemaError("literal numbers must be finite.")
            continue
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                raise PolicySchemaError(
                    "literal values must not contain shared or cyclic containers."
                )
            seen.add(identity)
            if not all(isinstance(key, str) for key in current):
                raise PolicySchemaError("literal object keys must be strings.")
            stack.extend((child, depth + 1) for child in current.values())
            continue
        if isinstance(current, list):
            identity = id(current)
            if identity in seen:
                raise PolicySchemaError(
                    "literal values must not contain shared or cyclic containers."
                )
            seen.add(identity)
            stack.extend((child, depth + 1) for child in current)
            continue
        raise PolicySchemaError("literal values must contain only JSON-compatible data.")


def _validate_lossless_literals(document: object) -> None:
    """Reject literals that a JSON round trip would load as different values.

    Built-in operators compare exact types, so a ``str`` subclass such as an enum
    member decides differently once it is reloaded as ``str``, and JSON turns
    non-string object keys into strings.
    """

    stack: list[object] = [document]
    while stack:
        current = stack.pop()
        if isinstance(current, list):
            stack.extend(current)
            continue
        if not isinstance(current, dict):
            continue
        if set(current) != {"value"}:
            stack.extend(current.values())
            continue
        values: list[object] = [current["value"]]
        while values:
            item = values.pop()
            if isinstance(item, dict):
                # Keys are compared by exact type too, so a str subclass key would
                # reload as a plain str key that decides differently.
                if not all(type(key) is str for key in item):
                    raise PolicySchemaError("literal object keys must be plain str values.")
                values.extend(item.values())
            elif isinstance(item, list):
                values.extend(item)
            elif isinstance(item, str) and type(item) is not str:
                raise PolicySchemaError("literal strings must be plain str values.")


def operand_from_dict(document: Mapping[str, object]) -> Operand:
    has_source = "source" in document
    has_value = "value" in document
    if has_source == has_value:
        raise PolicySchemaError("An operand must contain exactly one of source or value.")
    if has_value:
        _check_keys(document, allowed={"value"}, field_name="operand")
        value = document["value"]
        _validate_serialized_literal(value)
        try:
            return Literal(value)
        except (TypeError, ValueError) as error:
            raise PolicySchemaError("literal value could not be safely normalized.") from error
    _check_keys(document, allowed={"source", "path"}, field_name="operand")
    try:
        source = AttributeSource(_string(document.get("source"), "operand.source"))
    except ValueError as error:
        raise PolicySchemaError("operand.source is not supported.") from error
    path = _string(document.get("path"), "operand.path")
    try:
        return AttributeRef(source, path)
    except ValueError as error:
        raise PolicySchemaError(str(error)) from error


def condition_from_dict(document: Mapping[str, object]) -> Condition:
    _validate_condition_complexity(document)
    return _condition_from_dict(document)


def _condition_from_dict(document: Mapping[str, object]) -> Condition:
    condition_type = _string(document.get("type"), "condition.type")
    if condition_type == "comparison":
        _check_keys(
            document,
            allowed={"type", "operator", "left", "right"},
            field_name="comparison condition",
        )
        left = operand_from_dict(_mapping(document.get("left"), "condition.left"))
        operator = _string(document.get("operator"), "condition.operator")
        right = (
            None
            if "right" not in document
            else operand_from_dict(_mapping(document["right"], "condition.right"))
        )
        try:
            return Comparison(left, operator, right)
        except ValueError as error:
            raise PolicySchemaError(str(error)) from error
    if condition_type in {"all_of", "any_of"}:
        _check_keys(
            document,
            allowed={"type", "conditions"},
            field_name=f"{condition_type} condition",
        )
        raw_conditions = document.get("conditions")
        if not isinstance(raw_conditions, Sequence) or isinstance(raw_conditions, str | bytes):
            raise PolicySchemaError("condition.conditions must be an array.")
        children = tuple(
            _condition_from_dict(_mapping(item, "condition.conditions[]"))
            for item in raw_conditions
        )
        try:
            return AllOf(*children) if condition_type == "all_of" else AnyOf(*children)
        except ValueError as error:
            raise PolicySchemaError(str(error)) from error
    if condition_type == "not":
        _check_keys(
            document,
            allowed={"type", "condition"},
            field_name="not condition",
        )
        return Not(_condition_from_dict(_mapping(document.get("condition"), "condition.condition")))
    raise PolicySchemaError(f"Unsupported condition type: {condition_type}")


def _condition_operators(condition: Condition) -> tuple[str, ...]:
    if isinstance(condition, Comparison):
        return (condition.operator,)
    if isinstance(condition, AllOf | AnyOf):
        return tuple(name for child in condition.conditions for name in _condition_operators(child))
    if isinstance(condition, Not):
        return _condition_operators(condition.condition)
    return ()


def attribute_policy_from_dict(
    document: Mapping[str, object],
    *,
    operators: OperatorRegistry | None = None,
) -> AttributePolicy:
    _check_keys(
        document,
        allowed={
            "schema_version",
            "type",
            "name",
            "actions",
            "match_effect",
            "on_no_match",
            "on_indeterminate",
            "condition",
        },
        field_name="policy",
    )
    if document.get("schema_version") != POLICY_SCHEMA_VERSION:
        raise PolicySchemaError(f"schema_version must be {POLICY_SCHEMA_VERSION!r}.")
    if document.get("type") != "attribute_policy":
        raise PolicySchemaError("type must be 'attribute_policy'.")
    registry = operators or OperatorRegistry()
    condition_document = _mapping(document.get("condition"), "condition")
    condition = condition_from_dict(condition_document)
    unknown = sorted(
        name for name in _condition_operators(condition) if not registry.contains(name)
    )
    if unknown:
        raise PolicySchemaError(f"Unknown operators: {', '.join(unknown)}")

    if "actions" not in document:
        raise PolicySchemaError("actions is required; use null to target every action.")
    raw_actions = document["actions"]
    actions: Collection[str] | None
    if raw_actions is None:
        actions = None
    elif isinstance(raw_actions, Sequence) and not isinstance(raw_actions, str | bytes):
        if not raw_actions:
            raise PolicySchemaError("actions must contain at least one action when provided.")
        if len(raw_actions) > MAX_POLICY_CONDITION_NODES:
            raise PolicySchemaError("actions exceeds the maximum item count.")
        if not all(isinstance(action, str) and action for action in raw_actions):
            raise PolicySchemaError("actions must contain only non-empty strings.")
        actions = cast(Sequence[str], raw_actions)
        if len(set(actions)) != len(actions):
            raise PolicySchemaError("actions must not contain duplicates.")
    else:
        raise PolicySchemaError("actions must be null or an array of strings.")
    try:
        match_effect = Effect(_string(document.get("match_effect"), "match_effect"))
        on_no_match = MissEffect(_string(document.get("on_no_match"), "on_no_match"))
        on_indeterminate = MissEffect(
            _string(document.get("on_indeterminate"), "on_indeterminate")
        )
    except ValueError as error:
        raise PolicySchemaError("A policy effect value is unsupported.") from error
    try:
        return AttributePolicy(
            condition,
            actions=actions,
            match_effect=match_effect,
            on_no_match=on_no_match,
            on_indeterminate=on_indeterminate,
            name=_string(document.get("name"), "name"),
            operators=registry,
        )
    except PolicySchemaError:
        raise
    except (TypeError, ValueError) as error:
        raise PolicySchemaError("The policy could not be safely normalized.") from error


def dumps_policy(policy: AttributePolicy, *, indent: int | None = 2) -> str:
    try:
        document = policy.to_dict()
        _validate_lossless_literals(document)
        return json.dumps(document, ensure_ascii=False, indent=indent, sort_keys=True)
    except (TypeError, ValueError) as error:
        raise PolicySchemaError(
            "The policy contains a value that is not JSON serializable."
        ) from error


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Unsupported JSON constant: {value}")


def _reject_duplicate_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON object key: {key}")
        value[key] = item
    return value


def loads_policy(document: str, *, operators: OperatorRegistry | None = None) -> AttributePolicy:
    if not isinstance(document, str):
        raise TypeError("policy document must be a string.")
    if len(document) > MAX_POLICY_DOCUMENT_CHARS:
        raise PolicySchemaError("The policy document exceeds the size limit.")
    try:
        value = json.loads(
            document,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_json_object,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise PolicySchemaError("The policy document is not valid JSON.") from error
    return attribute_policy_from_dict(_mapping(value, "policy"), operators=operators)


def load_policy_schema() -> dict[str, object]:
    """Load a fresh copy of the packaged ABAC policy JSON Schema."""

    schema_text = files("access_gate").joinpath("schema/abac-policy-v1.json").read_text(
        encoding="utf-8"
    )
    return dict(_mapping(json.loads(schema_text), "policy schema"))
