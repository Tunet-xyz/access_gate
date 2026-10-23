from __future__ import annotations

import abc
import enum
import math
from collections import OrderedDict, defaultdict, namedtuple
from collections.abc import (
    ItemsView,
    Iterator,
    KeysView,
    Mapping,
    MutableSequence,
    MutableSet,
    ValuesView,
)
from decimal import Decimal
from types import MappingProxyType
from uuid import UUID

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from access_gate.types import _MAX_VALUE_DEPTH, _MAX_VALUE_ITEMS, _freeze_value, _FrozenMapping


def _reference_freeze_value(
    value: object,
    *,
    field_name: str,
    depth: int = 0,
    seen: set[int] | None = None,
    item_count: list[int] | None = None,
) -> object:
    """The slow path (0.3.0a1 plus mutable-container snapshots): the equivalence oracle."""

    if depth > _MAX_VALUE_DEPTH:
        raise ValueError(f"{field_name} exceeds the maximum nesting depth.")
    if seen is None:
        seen = set()
    if item_count is None:
        item_count = [0]
    if isinstance(value, _FrozenMapping):
        return value
    if isinstance(value, Mapping):
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
                frozen[key] = _reference_freeze_value(
                    child, field_name=field_name, depth=depth + 1, seen=seen, item_count=item_count
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
                    _reference_freeze_value(
                        child,
                        field_name=field_name,
                        depth=depth + 1,
                        seen=seen,
                        item_count=item_count,
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
                    _reference_freeze_value(
                        child,
                        field_name=field_name,
                        depth=depth + 1,
                        seen=seen,
                        item_count=item_count,
                    )
                )
            return frozenset(frozen_items)
        finally:
            seen.remove(identity)
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, MutableSequence | MutableSet | KeysView | ItemsView | ValuesView):
        identity = id(value)
        if identity in seen:
            raise ValueError(f"{field_name} must not contain reference cycles.")
        if len(value) > _MAX_VALUE_ITEMS - item_count[0]:
            raise ValueError(f"{field_name} contains too many values.")
        seen.add(identity)
        try:
            copied = set(value) if isinstance(value, KeysView | MutableSet) else list(value)
            return _reference_freeze_value(
                copied, field_name=field_name, depth=depth, seen=seen, item_count=item_count
            )
        finally:
            seen.remove(identity)
    return value


class _Text(str):
    pass


class _Number(int):
    pass


class _Ratio(float):
    pass


class _TextEnum(str, enum.Enum):
    A = "a"


class _NumberEnum(enum.IntEnum):
    ONE = 1


class _Flag(enum.Flag):
    READ = 1


class _Dict(dict):  # type: ignore[type-arg]
    pass


class _List(list):  # type: ignore[type-arg]
    pass


class _CustomMapping(Mapping[str, object]):
    def __init__(self, values: dict[str, object]) -> None:
        self._values = values

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


class _TextMapping(str, Mapping[str, object]):  # type: ignore[misc]
    """A str subclass that is also a Mapping: only exact str may skip the checks."""


class _FrozenChild(_FrozenMapping):
    __slots__ = ()


_Pair = namedtuple("_Pair", "left right")
_SHARED_NAN = math.nan
_SHARED_OBJECT = object()

LEAVES = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats()
    | st.just(_SHARED_NAN)
    | st.text(max_size=8)
    | st.binary(max_size=4)
    | st.text(max_size=4).map(_Text)
    | st.integers().map(_Number)
    | st.floats(allow_nan=False).map(_Ratio)
    | st.sampled_from([_TextEnum.A, _NumberEnum.ONE, _Flag.READ, _TextMapping("ab")])
    | st.sampled_from([Decimal("1.5"), UUID(int=7), _SHARED_OBJECT, bytearray(b"x"), 1j])
)
HASHABLE_LEAVES = (
    st.none() | st.booleans() | st.integers() | st.text(max_size=4) | st.just(_TextEnum.A)
)


def _containers(children: st.SearchStrategy[object]) -> st.SearchStrategy[object]:
    keys = st.text(max_size=4) | st.integers() | st.just(_TextEnum.A)
    mappings = st.dictionaries(keys, children, max_size=4)
    return (
        mappings
        | mappings.map(_Dict)
        | mappings.map(OrderedDict)
        | mappings.map(lambda value: defaultdict(list, value))
        | mappings.map(MappingProxyType)
        | st.dictionaries(st.text(max_size=4), children, max_size=4).map(_CustomMapping)
        | mappings.map(lambda value: _FrozenMapping(dict(value)))
        | mappings.map(lambda value: _FrozenChild(dict(value)))
        | st.lists(children, max_size=4)
        | st.lists(children, max_size=4).map(tuple)
        | st.lists(children, max_size=4).map(_List)
        | st.tuples(children, children).map(lambda pair: _Pair(*pair))
        | st.frozensets(HASHABLE_LEAVES, max_size=4)
        | st.sets(HASHABLE_LEAVES, max_size=4)
    )


VALUES = st.recursive(LEAVES, _containers, max_leaves=30)


def _same(left: object, right: object) -> bool:
    """Identical snapshot shape: same types everywhere, same leaf objects."""

    if type(left) is not type(right):
        return False
    if isinstance(left, _FrozenMapping) and isinstance(right, _FrozenMapping):
        return list(left) == list(right) and all(_same(left[key], right[key]) for key in left)
    if type(left) is tuple:
        assert isinstance(right, tuple)
        return len(left) == len(right) and all(map(_same, left, right))
    if type(left) is frozenset or type(left) is bytes:
        # bytes may be a fresh copy of a bytearray; equal bytes are the same snapshot.
        return left == right
    return left is right


def _outcome(function: object, value: object) -> tuple[str, object]:
    try:
        return "value", function(value, field_name="value")  # type: ignore[operator]
    except Exception as error:  # noqa: BLE001 - the error itself is compared
        return "error", (type(error), str(error))


def _assert_equivalent(value: object) -> None:
    expected = _outcome(_reference_freeze_value, value)
    actual = _outcome(_freeze_value, value)
    assert expected[0] == actual[0]
    if expected[0] == "error":
        assert expected == actual
    else:
        assert _same(expected[1], actual[1])


@settings(max_examples=1500, deadline=None)
@given(VALUES)
def test_freeze_value_matches_the_reference_snapshot(value: object) -> None:
    _assert_equivalent(value)


@pytest.mark.parametrize("depth", [_MAX_VALUE_DEPTH - 1, _MAX_VALUE_DEPTH, _MAX_VALUE_DEPTH + 1])
@pytest.mark.parametrize("leaf", ["text", 1, 1.5, True, None, b"x", _Text("t"), _TextEnum.A])
@pytest.mark.parametrize("wrap", [lambda child: {"k": child}, lambda child: [child]])
def test_depth_limit_still_applies_to_scalar_leaves(depth: int, leaf: object, wrap: object) -> None:
    value = leaf
    for _ in range(depth):
        value = wrap(value)  # type: ignore[operator]
    _assert_equivalent(value)


def test_cycles_and_item_limits_still_raise() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    looped: list[object] = []
    looped.append(looped)
    for value in (cyclic, looped, ["x"] * (_MAX_VALUE_ITEMS + 1), {"k": ["x"] * _MAX_VALUE_ITEMS}):
        _assert_equivalent(value)


def test_exact_scalars_and_dicts_skip_abc_instance_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[type] = []
    original = abc.ABCMeta.__instancecheck__

    def counting(cls: abc.ABCMeta, instance: object) -> bool:
        calls.append(cls)
        return original(cls, instance)

    value = {"text": "x", "number": 1, "ratio": 1.5, "missing": None, "raw": b"x"}
    monkeypatch.setattr(abc.ABCMeta, "__instancecheck__", counting)
    frozen = _freeze_value(value, field_name="value")
    monkeypatch.undo()

    assert calls == []
    assert dict(frozen) == value  # type: ignore[call-overload]

    # bool is an int subclass and, like other subclasses, keeps the general path.
    monkeypatch.setattr(abc.ABCMeta, "__instancecheck__", counting)
    flag = _freeze_value(True, field_name="value")
    monkeypatch.undo()

    assert flag is True and calls
