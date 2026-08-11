# AccessGate

Composable, default-deny RBAC, ABAC, and relationship-aware authorization for
Python applications.

AccessGate answers one question: **may this subject perform this action on
this resource in this context?** It provides a small framework-neutral kernel,
secure decision defaults, and extension interfaces for application-specific
identity, policy, audit, and framework integration.

It is complementary to authentication and session-security packages such as
SessionArmor. Those establish who the caller is and whether the session can be
trusted; AccessGate decides what that caller is allowed to do.

> **Status:** early alpha. The core concepts are implemented, but the public API
> may evolve before 1.0.

## Design guarantees

- **Default deny:** abstention never grants access.
- **Deny overrides:** any explicit denial wins over grants by default.
- **Fail closed:** policy and audit failures deny access by default.
- **Exact matching:** built-in role, action, owner, and tenant comparisons never
  use substring matching.
- **Safe ABAC:** missing attributes and operator failures are indeterminate,
  cannot be negated into access, and deny by default.
- **No expression evaluation:** declarative policies use registered operators
  and mapping-only attribute traversal—never Python `eval` or object traversal.
- **Framework-neutral core:** no runtime dependencies and no ORM, token, or user
  model assumptions.
- **Custom from day one:** policies, decision strategies, identity/resource
  resolvers, audit sinks, and framework adapters are public extension points.

## Installation

```bash
pip install AccessGate
```

For the optional Django adapter:

```bash
pip install "AccessGate[django]"
```

## Quick start

```python
from access_gate import (
    AuthorizationEngine,
    Resource,
    RolePolicy,
    Subject,
    TenantBoundaryPolicy,
)

engine = AuthorizationEngine(
    [
        TenantBoundaryPolicy(actions={"incident.read"}),
        RolePolicy({"incident_manager"}, actions={"incident.read"}),
    ]
)

decision = engine.authorize(
    Subject(
        "user-42",
        roles=frozenset({"incident_manager"}),
        attributes={"tenant_id": "acme"},
    ),
    "incident.read",
    Resource("incident", "INC-123", {"tenant_id": "acme"}),
)

assert decision.allowed
```

Tenant boundaries deliberately do not grant access. They abstain when the
tenant matches and deny when it is missing or different; another policy must
positively allow the action.

## Attribute-based access control

ABAC policies can compare subject, resource, action, and context attributes:

```python
from access_gate import (
    ActionAttribute,
    AllOf,
    AttributePolicy,
    ContextAttribute,
    ResourceAttribute,
    SubjectAttribute,
)

document_access = AttributePolicy(
    AllOf(
        SubjectAttribute("department").equals(ResourceAttribute("department")),
        SubjectAttribute("clearance").greater_than_or_equal(
            ResourceAttribute("classification")
        ),
        ActionAttribute("risk").less_than_or_equal(3),
        ContextAttribute("device.trusted").equals(True),
    ),
    actions={"document.read"},
    name="document_access",
)
```

Conditions support `AllOf`, `AnyOf`, and `Not`, multi-valued attributes, exact
membership and set relations, numeric comparisons, and explicit existence
checks. `Not` preserves indeterminate outcomes, so a missing attribute never
becomes a grant merely because a condition was negated.

Policies serialize to the versioned `access_gate.policy.v1` format:

```python
from access_gate import dumps_policy, loads_policy

document = dumps_policy(document_access)
restored = loads_policy(document)
```

See [`docs/abac.md`](docs/abac.md) for the full data model, operator semantics,
customization rules, JSON format, and rollout guidance.

## Application-defined policies

Implement the `Policy` protocol directly or wrap a function:

```python
from access_gate import Decision, FunctionPolicy

def published_incidents(request):
    resource = request.resource
    if resource and resource.attributes.get("published") is True:
        return Decision.allow("The incident is public.", policy="published")
    return None

policy = FunctionPolicy("published", published_incidents)
```

A policy returns an allow/deny `Decision`, or `None` to abstain. Custom decision
strategies can replace deny-overrides where a domain needs different semantics.

For mixed RBAC/ABAC grants, configure alternative grant policies to abstain on
a miss. Explicit boundary denials still override every grant.

## Django adapter

```python
from access_gate import AuthorizationEngine, RolePolicy
from access_gate.adapters.django import DjangoAuthorizer

authorizer = DjangoAuthorizer(
    AuthorizationEngine([RolePolicy({"admin"}, actions={"users.list"})])
)

@authorizer.require("users.list")
def user_list(request):
    ...
```

The default Django subject resolver only reads `pk`, `is_authenticated`,
`access_gate_roles`, and `access_gate_attributes`. Real applications should
normally provide a resolver that validates and maps their exact identity claims.
The adapter also accepts custom context and action-attribute resolvers for ABAC.

## MCP server

AccessGate includes a dependency-free stdio MCP server:

```bash
accessgate-mcp
```

From a source checkout, run `python mcp/server.py`. The server exposes package
capabilities, authorization-model guidance, the ABAC JSON Schema, exact built-in
operator discovery, and read-only policy validation. It does not authenticate
users, evaluate production identity data, or change application policy.

## Project boundary

AccessGate does not authenticate users, validate JWTs, secure sessions, query
application permissions, or decide how tenants and resources are represented.
Those are application and adapter responsibilities. See
[`docs/architecture.md`](docs/architecture.md) and
[`docs/customization.md`](docs/customization.md). AccessGate provides its own
policy format but does not claim wire compatibility with XACML, Cedar, Rego, or
other policy languages.

## Development

```bash
python -m pip install -e ".[dev]"
ruff check src tests
mypy src/access_gate
pytest --cov=access_gate --cov-report=term-missing
```

## License

MIT (c) Tunet Ltd.
