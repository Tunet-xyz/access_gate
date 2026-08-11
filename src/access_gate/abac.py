"""Safe, declarative attribute-based access control primitives."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from importlib.resources import files
from types import MappingProxyType
from typing import Protocol, cast, runtime_checkable

from .policies import MissEffect
from .types import AuthorizationRequest, Decision, Effect

POLICY_SCHEMA_VERSION = "access_gate.policy.v1"
_OPERATOR_NAME = re.compile(r"^[a-z][a-z0-9_]*$")


class PolicySchemaError(ValueError):
    """Raised when a serialized policy is malformed or unsupported."""


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

    @property
    def matched(self) -> bool:
        return self.state is ConditionState.MATCH


class _Missing:
    __slots__ = ()


MISSING = _Missing()
ResolvedValue = object | _Missing
OperatorFunction = Callable[[object, object], bool]


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _equal(left: object, right: object) -> bool:
    if _is_number(left) and _is_number(right):
        return bool(left == right)
    if type(left) is not type(right):
        return False
    return bool(left == right)


def _collection(value: object) -> Collection[object] | Mapping[object, object] | None:
    if isinstance(value, (str, bytes, bytearray)):
        return None
    if isinstance(value, Mapping):
        return cast(Mapping[object, object], value)
    if isinstance(value, Collection):
        return cast(Collection[object], value)
    return None


def _contains(container: object, member: object) -> bool:
    values = _collection(container)
    if values is None:
        return False
    return any(_equal(candidate, member) for candidate in values)


def _intersects(left: object, right: object) -> bool:
    left_values = _collection(left)
    right_values = _collection(right)
    if left_values is None or right_values is None:
        return False
    return any(_equal(a, b) for a in left_values for b in right_values)


def _subset_of(left: object, right: object) -> bool:
    left_values = _collection(left)
    right_values = _collection(right)
    if left_values is None or right_values is None:
        return False
    return all(any(_equal(item, candidate) for candidate in right_values) for item in left_values)


def _ordered(left: object, right: object, operation: str) -> bool:
    if not (_is_number(left) and _is_number(right)):
        return False
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
    ) -> None:
        self._operators = _builtins() if include_builtins else {}
        if operators is not None:
            for name, evaluator in operators.items():
                self.register(name, evaluator, replace=True)

    def register(
        self,
        name: str,
        evaluator: OperatorFunction,
        *,
        replace: bool = False,
    ) -> None:
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

    def evaluate(self, name: str, left: object, right: object) -> bool:
        try:
            evaluator = self._operators[name]
        except KeyError as error:
            raise KeyError(f"Unknown ABAC operator: {name}") from error
        return bool(evaluator(left, right))

    def copy(self) -> OperatorRegistry:
        return OperatorRegistry(self._operators, include_builtins=False)


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

    def resolve(self, request: AuthorizationRequest) -> ResolvedValue:
        del request
        return self.value

    def to_dict(self) -> dict[str, object]:
        return {"value": self.value}

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

    def compare(self, operator: str, other: Operand | object | None = None) -> Comparison:
        right = None if other is None else _operand(other)
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


def _operand(value: Operand | object) -> Operand:
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

        assert self.right is not None
        right_value = self.right.resolve(request)
        if right_value is MISSING:
            return _result(
                ConditionState.INDETERMINATE,
                "A required right attribute is missing.",
                issue="missing_right_operand",
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
        results = tuple(condition.evaluate(request, operators) for condition in self.conditions)
        states = tuple(result.state.value for result in results)
        if any(result.state is ConditionState.NO_MATCH for result in results):
            return _result(
                ConditionState.NO_MATCH,
                "At least one required condition did not match.",
                children=states,
            )
        if any(result.state is ConditionState.INDETERMINATE for result in results):
            return _result(
                ConditionState.INDETERMINATE,
                "A required condition was indeterminate.",
                children=states,
            )
        return _result(ConditionState.MATCH, "All required conditions matched.", children=states)

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
        results = tuple(condition.evaluate(request, operators) for condition in self.conditions)
        states = tuple(result.state.value for result in results)
        if any(result.state is ConditionState.MATCH for result in results):
            return _result(ConditionState.MATCH, "At least one condition matched.", children=states)
        if any(result.state is ConditionState.INDETERMINATE for result in results):
            return _result(
                ConditionState.INDETERMINATE,
                "An alternative condition was indeterminate.",
                children=states,
            )
        return _result(
            ConditionState.NO_MATCH,
            "No alternative condition matched.",
            children=states,
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
    ) -> None:
        if on_no_match is None:
            on_no_match = MissEffect.DENY if match_effect is Effect.ALLOW else MissEffect.ABSTAIN
        object.__setattr__(self, "condition", condition)
        object.__setattr__(self, "actions", None if actions is None else frozenset(actions))
        object.__setattr__(self, "match_effect", match_effect)
        object.__setattr__(self, "on_no_match", on_no_match)
        object.__setattr__(self, "on_indeterminate", on_indeterminate)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "operators", (operators or OperatorRegistry()).copy())

    def evaluate(self, request: AuthorizationRequest) -> Decision | None:
        if self.actions is not None and request.action not in self.actions:
            return None
        result = self.condition.evaluate(request, self.operators)
        metadata = {
            "condition_state": result.state.value,
            "condition": self.condition.to_dict(),
            "evaluation": dict(result.metadata),
        }
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
        return {
            "schema_version": POLICY_SCHEMA_VERSION,
            "type": "attribute_policy",
            "name": self.name,
            "actions": None if self.actions is None else sorted(self.actions),
            "match_effect": self.match_effect.value,
            "on_no_match": self.on_no_match.value,
            "on_indeterminate": self.on_indeterminate.value,
            "condition": self.condition.to_dict(),
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


def operand_from_dict(document: Mapping[str, object]) -> Operand:
    has_source = "source" in document
    has_value = "value" in document
    if has_source == has_value:
        raise PolicySchemaError("An operand must contain exactly one of source or value.")
    if has_value:
        _check_keys(document, allowed={"value"}, field_name="operand")
        return Literal(document["value"])
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
    condition_type = _string(document.get("type"), "condition.type")
    if condition_type == "comparison":
        _check_keys(
            document,
            allowed={"type", "operator", "left", "right"},
            field_name="comparison condition",
        )
        left = operand_from_dict(_mapping(document.get("left"), "condition.left"))
        operator = _string(document.get("operator"), "condition.operator")
        right_value = document.get("right")
        right = (
            None
            if right_value is None
            else operand_from_dict(_mapping(right_value, "condition.right"))
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
        if not isinstance(raw_conditions, Sequence) or isinstance(raw_conditions, (str, bytes)):
            raise PolicySchemaError("condition.conditions must be an array.")
        children = tuple(
            condition_from_dict(_mapping(item, "condition.conditions[]")) for item in raw_conditions
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
        return Not(condition_from_dict(_mapping(document.get("condition"), "condition.condition")))
    raise PolicySchemaError(f"Unsupported condition type: {condition_type}")


def _condition_operators(condition: Condition) -> tuple[str, ...]:
    if isinstance(condition, Comparison):
        return (condition.operator,)
    if isinstance(condition, (AllOf, AnyOf)):
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
    condition = condition_from_dict(_mapping(document.get("condition"), "condition"))
    unknown = sorted(
        name for name in _condition_operators(condition) if not registry.contains(name)
    )
    if unknown:
        raise PolicySchemaError(f"Unknown operators: {', '.join(unknown)}")

    raw_actions = document.get("actions")
    actions: Collection[str] | None
    if raw_actions is None:
        actions = None
    elif isinstance(raw_actions, Sequence) and not isinstance(raw_actions, (str, bytes)):
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
    return AttributePolicy(
        condition,
        actions=actions,
        match_effect=match_effect,
        on_no_match=on_no_match,
        on_indeterminate=on_indeterminate,
        name=_string(document.get("name"), "name"),
        operators=registry,
    )


def dumps_policy(policy: AttributePolicy, *, indent: int | None = 2) -> str:
    try:
        return json.dumps(policy.to_dict(), ensure_ascii=False, indent=indent, sort_keys=True)
    except (TypeError, ValueError) as error:
        raise PolicySchemaError(
            "The policy contains a value that is not JSON serializable."
        ) from error


def loads_policy(document: str, *, operators: OperatorRegistry | None = None) -> AttributePolicy:
    try:
        value = json.loads(document)
    except json.JSONDecodeError as error:
        raise PolicySchemaError("The policy document is not valid JSON.") from error
    return attribute_policy_from_dict(_mapping(value, "policy"), operators=operators)


def load_policy_schema() -> dict[str, object]:
    """Load a fresh copy of the packaged ABAC policy JSON Schema."""

    schema_text = files("access_gate").joinpath("schema/abac-policy-v1.json").read_text(
        encoding="utf-8"
    )
    return dict(_mapping(json.loads(schema_text), "policy schema"))
