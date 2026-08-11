"""AccessGate exceptions."""

from __future__ import annotations

from .types import Decision


class AuthorizationDenied(PermissionError):
    """Raised when enforcement receives a denied decision."""

    def __init__(self, decision: Decision) -> None:
        self.decision = decision
        super().__init__(decision.reason)
