"""Small independent model used only for differential security tests."""

from __future__ import annotations

from collections.abc import Sequence


def deny_overrides(effects: Sequence[str]) -> str:
    """Reference truth table independent of AccessGate strategy code."""

    if "deny" in effects:
        return "deny"
    if "allow" in effects:
        return "allow"
    return "deny"


def exact_equal(left: object, right: object) -> bool:
    """Reference equality: booleans are not numbers; numeric types interoperate."""

    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, int | float) and isinstance(right, int | float):
        return left == right
    return type(left) is type(right) and left == right


def exact_contains(container: Sequence[object], member: object) -> bool:
    return any(exact_equal(candidate, member) for candidate in container)
