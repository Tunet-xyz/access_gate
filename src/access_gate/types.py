"""Framework-neutral authorization value objects."""

from __future__ import annotations

from collections.abc import (
    ItemsView,
    Iterator,
    KeysView,
    Mapping,
    MutableSequence,
    MutableSet,
    ValuesView,
)
from dataclasses import dataclass, field
from enum import Enum
from typing import cast

_MAX_VALUE_DEPTH = 64
_MAX_VALUE_ITEMS = 100_000
_MAX_SUBJECT_ROLES = 10_000
# Exact built-in immutable scalars. Subclasses (bool, str enums, custom ints) are
# not listed and keep the general isinstance path below.
_IMMUTABLE_SCALAR_TYPES = frozenset({str, int, float, bytes, type(None)})


class _FrozenMapping(Mapping[object, object]):
    """An internally owned immutable mapping that can be safely reused."""

    __slots__ = ("__values",)

    def __init__(self, values: dict[object, object]) -> None:
        self.__values = values

    def __getitem__(self, key: object) -> object:
        return self.__values[key]

    def __iter__(self) -> Iterator[object]:
        return iter(self.__values)

    def __len__(self) -> int:
        return len(self.__values)

    def __repr__(self) -> str:
        return f"_FrozenMapping({self.__values!r})"


def _freeze_value(
    value: object,
    *,
    field_name: str,
    depth: int = 0,
    seen: set[int] | None = None,
    item_count: list[int] | None = None,
    max_depth: int = _MAX_VALUE_DEPTH,
) -> object:
    """Create a bounded immutable snapshot of authorization input data."""

    if depth > max_depth:
        raise ValueError(f"{field_name} exceeds the maximum nesting depth.")
    value_type = type(value)
    # Exact scalars match none of the container branches below; returning them
    # first skips the comparatively slow ABC isinstance checks on every leaf.
    if value_type in _IMMUTABLE_SCALAR_TYPES:
        return value
    if seen is None:
        seen = set()
    if item_count is None:
        item_count = [0]

    if value_type is not dict and isinstance(value, _FrozenMapping):
        return value

    if isinstance(value, dict) or isinstance(value, Mapping):
        identity = id(value)
        if identity in seen:
            raise ValueError(f"{field_name} must not contain reference cycles.")
        seen.add(identity)
        try:
            frozen: dict[object, object] = {}
            for key, child in value.items():
                item_count[0] += 1
                if item_count[0] > _MAX_VALUE_ITEMS:
                    raise ValueError(f"{field_name} contains too many values.")
                frozen[key] = _freeze_value(
                    child,
                    field_name=field_name,
                    depth=depth + 1,
                    seen=seen,
                    item_count=item_count,
                    max_depth=max_depth,
                )
            return _FrozenMapping(frozen)
        finally:
            seen.remove(identity)

    if isinstance(value, list | tuple):
        identity = id(value)
        if identity in seen:
            raise ValueError(f"{field_name} must not contain reference cycles.")
        seen.add(identity)
        try:
            frozen_items: list[object] = []
            for child in value:
                item_count[0] += 1
                if item_count[0] > _MAX_VALUE_ITEMS:
                    raise ValueError(f"{field_name} contains too many values.")
                frozen_items.append(
                    _freeze_value(
                        child,
                        field_name=field_name,
                        depth=depth + 1,
                        seen=seen,
                        item_count=item_count,
                        max_depth=max_depth,
                    )
                )
            return tuple(frozen_items)
        finally:
            seen.remove(identity)

    if isinstance(value, set | frozenset):
        identity = id(value)
        if identity in seen:
            raise ValueError(f"{field_name} must not contain reference cycles.")
        seen.add(identity)
        try:
            frozen_items = []
            for child in value:
                item_count[0] += 1
                if item_count[0] > _MAX_VALUE_ITEMS:
                    raise ValueError(f"{field_name} contains too many values.")
                frozen_items.append(
                    _freeze_value(
                        child,
                        field_name=field_name,
                        depth=depth + 1,
                        seen=seen,
                        item_count=item_count,
                        max_depth=max_depth,
                    )
                )
            return frozenset(frozen_items)
        finally:
            seen.remove(identity)

    if isinstance(value, bytearray | memoryview):
        return bytes(value)

    if isinstance(value, MutableSequence | MutableSet | KeysView | ItemsView | ValuesView):
        # Other mutable or live containers (deque, UserList, array, dictionary
        # views) are copied first, so later caller mutation cannot reach the
        # snapshot through them.
        identity = id(value)
        if identity in seen:
            raise ValueError(f"{field_name} must not contain reference cycles.")
        if len(value) > _MAX_VALUE_ITEMS - item_count[0]:
            raise ValueError(f"{field_name} contains too many values.")
        seen.add(identity)
        try:
            copied = set(value) if isinstance(value, KeysView | MutableSet) else list(value)
            return _freeze_value(
                copied,
                field_name=field_name,
                depth=depth,
                seen=seen,
                item_count=item_count,
                max_depth=max_depth,
            )
        finally:
            seen.remove(identity)

    return value


def _freeze_mapping(value: Mapping[str, object], *, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be a mapping.")
    if not all(isinstance(key, str) for key in value):
        raise TypeError(f"{field_name} keys must be strings.")
    frozen = _freeze_value(value, field_name=field_name)
    if not isinstance(frozen, Mapping):  # pragma: no cover - guarded above
        raise TypeError(f"{field_name} could not be snapshotted as a mapping.")
    return cast(Mapping[str, object], frozen)


def _thaw_value(value: object) -> object:
    """Convert immutable snapshots back into JSON-friendly containers."""

    if isinstance(value, Mapping):
        return {key: _thaw_value(child) for key, child in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw_value(child) for child in value]
    if isinstance(value, frozenset | set):
        return [_thaw_value(child) for child in value]
    return value


class Effect(str, Enum):
    """The outcome of an authorization decision."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class Subject:
    """The actor attempting an action.

    Applications decide which claims become roles and attributes. AccessGate
    deliberately does not depend on a particular user, token, or ORM model.
    """

    identifier: str
    authenticated: bool = True
    roles: frozenset[str] = field(default_factory=frozenset)
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.identifier, str):
            raise TypeError("subject.identifier must be a string.")
        if not isinstance(self.authenticated, bool):
            raise TypeError("subject.authenticated must be a boolean.")
        if self.authenticated and not self.identifier:
            raise ValueError("an authenticated subject must have a non-empty identifier.")
        if isinstance(self.roles, str):
            raise TypeError("subject.roles must be a collection of role names, not a string.")
        roles = frozenset(self.roles)
        if len(roles) > _MAX_SUBJECT_ROLES:
            raise ValueError("subject.roles exceeds the maximum item count.")
        if not all(isinstance(role, str) and role for role in roles):
            raise TypeError("subject.roles must contain only non-empty strings.")
        object.__setattr__(self, "roles", roles)
        object.__setattr__(
            self,
            "attributes",
            _freeze_mapping(self.attributes, field_name="subject.attributes"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "identifier": self.identifier,
            "authenticated": self.authenticated,
            "roles": sorted(self.roles),
            "attributes": _thaw_value(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class Resource:
    """A protected object or collection."""

    kind: str
    identifier: str | None = None
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind:
            raise TypeError("resource.kind must be a non-empty string.")
        if self.identifier is not None and not isinstance(self.identifier, str):
            raise TypeError("resource.identifier must be a string or None.")
        object.__setattr__(
            self,
            "attributes",
            _freeze_mapping(self.attributes, field_name="resource.attributes"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "attributes": _thaw_value(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """The complete input to policy evaluation."""

    subject: Subject
    action: str
    resource: Resource | None = None
    context: Mapping[str, object] = field(default_factory=dict)
    action_attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.subject, Subject):
            raise TypeError("authorization subject must be a Subject.")
        if self.resource is not None and not isinstance(self.resource, Resource):
            raise TypeError("authorization resource must be a Resource or None.")
        if not isinstance(self.action, str) or not self.action:
            raise TypeError("authorization action must be a non-empty string.")
        object.__setattr__(self, "context", _freeze_mapping(self.context, field_name="context"))
        object.__setattr__(
            self,
            "action_attributes",
            _freeze_mapping(self.action_attributes, field_name="action_attributes"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "subject": self.subject.to_dict(),
            "action": self.action,
            "resource": None if self.resource is None else self.resource.to_dict(),
            "context": _thaw_value(self.context),
            "action_attributes": _thaw_value(self.action_attributes),
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """A final or intermediate policy decision."""

    effect: Effect
    reason: str
    policy: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.effect, Effect):
            raise TypeError("decision.effect must be an Effect value.")
        if not isinstance(self.reason, str) or not self.reason:
            raise TypeError("decision.reason must be a non-empty string.")
        if self.policy is not None and not isinstance(self.policy, str):
            raise TypeError("decision.policy must be a string or None.")
        object.__setattr__(
            self,
            "metadata",
            _freeze_mapping(self.metadata, field_name="decision.metadata"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "effect": self.effect.value,
            "reason": self.reason,
            "policy": self.policy,
            "metadata": _thaw_value(self.metadata),
        }

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    @classmethod
    def allow(
        cls,
        reason: str,
        *,
        policy: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> Decision:
        return cls(Effect.ALLOW, reason, policy, metadata or {})

    @classmethod
    def deny(
        cls,
        reason: str,
        *,
        policy: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> Decision:
        return cls(Effect.DENY, reason, policy, metadata or {})
