"""AccessGate: composable, default-deny authorization for Python."""

from .engine import AuthorizationEngine, ErrorMode
from .exceptions import AuthorizationDenied
from .policies import (
    AuthenticatedPolicy,
    FunctionPolicy,
    MissEffect,
    OwnerPolicy,
    RolePolicy,
    TenantBoundaryPolicy,
)
from .protocols import (
    AuditSink,
    DecisionStrategy,
    Policy,
    ResourceResolver,
    SubjectResolver,
)
from .strategies import DenyOverrides
from .types import AuthorizationRequest, Decision, Effect, Resource, Subject

__all__ = [
    "AuditSink",
    "AuthenticatedPolicy",
    "AuthorizationDenied",
    "AuthorizationEngine",
    "AuthorizationRequest",
    "Decision",
    "DecisionStrategy",
    "DenyOverrides",
    "Effect",
    "ErrorMode",
    "FunctionPolicy",
    "MissEffect",
    "OwnerPolicy",
    "Policy",
    "Resource",
    "ResourceResolver",
    "RolePolicy",
    "Subject",
    "SubjectResolver",
    "TenantBoundaryPolicy",
]

__version__ = "0.1.0a1"
