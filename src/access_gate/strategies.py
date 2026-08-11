"""Built-in policy decision strategies."""

from __future__ import annotations

from collections.abc import Sequence

from .types import AuthorizationRequest, Decision, Effect


class DenyOverrides:
    """Deny on any explicit denial; otherwise allow on any explicit allowance."""

    def combine(
        self,
        request: AuthorizationRequest,
        decisions: Sequence[Decision],
    ) -> Decision:
        del request
        for decision in decisions:
            if decision.effect is Effect.DENY:
                return decision
        for decision in decisions:
            if decision.effect is Effect.ALLOW:
                return decision
        return Decision.deny(
            "No policy allowed the request.",
            policy="access_gate.default_deny",
        )
