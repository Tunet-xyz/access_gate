# AccessGate

Composable, default-deny RBAC, ABAC, and relationship-aware authorization for
Python applications.

Part of the [Tunet](https://www.tunet.xyz/engineering/) open-source libraries, alongside [GeoCanon](https://github.com/Tunet-xyz/geo_canon), [SessionArmor](https://github.com/Tunet-xyz/session_armor), and [SwapLayer](https://github.com/Tunet-xyz/swap_layer).

AccessGate answers one question: **may this subject perform this action on
this resource in this context?** It provides a small framework-neutral kernel,
secure decision defaults, and extension interfaces for application-specific
identity, policy, audit, and framework integration.

It is complementary to authentication and session-security packages such as
SessionArmor. Those establish who the caller is and whether the session can be
trusted; AccessGate decides what that caller is allowed to do.

With SessionArmor, the integration is explicit and deny-only:
`SessionAssurancePolicy` denies a request that lacks fresh, subject-bound session
evidence and otherwise abstains, so another policy still makes the grant:

```python
from access_gate import AuthorizationEngine, RolePolicy, SessionAssurancePolicy

engine = AuthorizationEngine([
    SessionAssurancePolicy(actions={"records.read"}),
    RolePolicy({"records_reader"}, actions={"records.read"}),
])
```

The default Django adapter carries SessionArmor's versioned
`request.session_assurance` evidence into authorization context without a hard
package dependency. Missing, stale, malformed, future-dated, unbound, or
subject-mismatched evidence denies; valid evidence never grants by itself.

## Version 1.0

The documented authorization engine, request/decision types, built-in policies,
ABAC policy format, extension protocols, explicit Django adapter, and
`accessgate-mcp` entry point form the stable 1.x API. The core supports Python
3.10–3.13 with no runtime dependencies. Install `[django]` for Django 4.2–6.x
(`Django<7`), using a framework version still receiving upstream security updates.

The `access_gate.policy.v1` format and SessionArmor assurance v1 bridge are
unchanged. Two alphas reached PyPI before 1.0.0, 0.2.0a1 and 0.3.0a1 (0.3.0a2
was prepared but never published). If you used either alpha, read the 0.3.0a2
and 1.0.0 changelog entries first: ABAC comparisons and the Django adapter now
deny some input the alphas accepted.
Future compatibility changes follow [VERSIONING.md](https://github.com/Tunet-xyz/access_gate/blob/main/VERSIONING.md).

Version 1.0 defines API stability. The package has not received an independent
security audit or government/NATO accreditation. The assurance documentation
records the limits of mutation, fuzz, and deployment evidence.

## Design guarantees

- **Default deny:** abstention never grants access.
- **Deny overrides:** any explicit denial wins over grants by default.
- **Fail closed:** policy and audit failures deny access by default.
- **Exact matching:** built-in role, action, owner, and tenant comparisons never
  use substring matching.
- **Safe ABAC:** missing attributes, two attributes that are both null, NaN
  operands, non-numeric operands to ordered comparisons, non-collection operands
  to collection operators, and operator failures are indeterminate, cannot be
  negated into access, and deny by default. Equality and membership are
  type-aware, so a value of another type is a definite non-match that `neq`,
  `not_in` and `Not` turn into a match.
- **Immutable inputs:** request attributes, literal values, and decision metadata
  are recursively snapshotted before evaluation or audit.
- **Bounded evaluation:** serialized policies, condition trees, MCP messages, and
  collection workloads have explicit denial-of-service limits.
- **Verifiable policy identity:** canonical fingerprints, ordered policy-set
  fingerprints, externally verified signed envelopes, and engine-owned policy
  deployment identifiers support change control without embedding key custody.
- **No expression evaluation:** declarative policies use registered operators
  and mapping-only attribute traversal—never Python `eval` or object traversal.
- **Framework-neutral core:** no runtime dependencies and no ORM, token, or user
  model assumptions.
- **Custom from day one:** policies, decision strategies, identity/resource
  resolvers, audit sinks, and framework adapters are public extension points.

`Subject`, `Resource`, `AuthorizationRequest`, and `Decision` expose `to_dict()`
for JSON-friendly snapshots of their otherwise immutable data.

## Installation

```bash
pip install AccessGate
```

For the optional Django adapter:

```bash
pip install "AccessGate[django]"
```

The package root remains framework-neutral. Django integration is imported
explicitly from the adapter namespace:

```python
from access_gate.adapters.django import DjangoAuthorizer
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

For controlled deployments, identify the exact ordered policy set and pass that
identifier into the engine so every final and audited decision is attributable:

```python
from access_gate import AuthorizationEngine, policy_set_fingerprint

policy_set_id = policy_set_fingerprint([document_access])
engine = AuthorizationEngine([document_access], policy_set_id=policy_set_id)
```

`dumps_signed_policy()` and `loads_signed_policy()` accept application-supplied
signer/verifier protocols. AccessGate deliberately does not choose algorithms,
store keys, or implement a trust store. See
[`docs/POLICY_FORMAT.md`](https://github.com/Tunet-xyz/access_gate/blob/main/docs/POLICY_FORMAT.md).

See [`docs/abac.md`](https://github.com/Tunet-xyz/access_gate/blob/main/docs/abac.md) for the full data model, operator semantics,
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
Policies exposing a validated `frozenset` in an `actions` attribute are indexed
by the engine and skipped for unrelated actions. `FunctionPolicy` supports this
directly through its `actions` argument. Use `decide_many()` for ordered batch
evaluation; every request still receives its own decision and audit event.

For mixed RBAC/ABAC grants, configure alternative grant policies to abstain on
a miss (`on_no_match`) and, unless missing facts should veto every other grant,
on an indeterminate result (`on_indeterminate`). Explicit boundary denials still
override every grant.

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

The default Django subject resolver only reads `pk` (falling back to `id`), `is_authenticated`,
`access_gate_roles`, and `access_gate_attributes`. Real applications should
normally provide a resolver that validates and maps their exact identity claims.
With SessionArmor, the subject identifier must equal the evidence's subject
identifier, which SessionArmor takes from `user.sub` before `pk`; for a user
model with `sub`, resolve the subject from `sub` (or align SessionArmor's
`get_subject_identifier()`), otherwise every request is denied with
`subject_mismatch`.
The adapter also accepts custom context and action-attribute resolvers for ABAC.
Synchronous and asynchronous Django views are supported. Async views may use
awaitable subject, resource, context, action-attribute, and denial resolvers.
In an async view the default subject resolver and the engine (every policy and
the audit sink) run in a worker thread through `sync_to_async`, so ORM-backed
policies and sinks work; pass `async_engine_in_thread=False` to keep a
non-blocking engine on the event loop.
`default_context_resolver()` provides `method`, `path`, and, when the request
carries SessionArmor evidence, `session_assurance`.

`authorizer.check(request, action, resource=...)`, or `acheck()` in an async
view, returns the audited decision for an object- or action-level check made
inside a view with the same resolvers. Test `decision.allowed`; a `Decision`
object is truthy even when it denies:

```python
resource = Resource("incident", str(incident.pk))
decision = authorizer.check(request, "incident.update", resource=resource)
if not decision.allowed:
    raise PermissionDenied
```

Resolver exceptions propagate by default. With
`resolver_error_mode=ErrorMode.DENY`, a failure to resolve the inputs or build
the request becomes an audited denial from the `access_gate.resolver` policy.
`require()` passes that denial to the denial handler; `check()` and `acheck()`
return it and never call the denial handler. `Http404` and `PermissionDenied`
still propagate. Outside the adapter,
`AuthorizationEngine.record_denial(request, decision)` sends a denial reached
without policy evaluation through the same audit path.

## MCP server

AccessGate includes a dependency-free stdio MCP server:

```bash
accessgate-mcp
```

From a source checkout, run `python mcp/server.py`. The server exposes package
capabilities, authorization-model guidance, the ABAC JSON Schema, exact built-in
operator discovery, and read-only policy validation. It does not authenticate
users, evaluate production identity data, or change application policy.
It runs locally under the caller's control, makes no network connections, and
needs no credentials or account.

## Project boundary

AccessGate does not authenticate users, validate JWTs, secure sessions, query
application permissions, or decide how tenants and resources are represented.
Those are application and adapter responsibilities. See
[`docs/architecture.md`](https://github.com/Tunet-xyz/access_gate/blob/main/docs/architecture.md) and
[`docs/customization.md`](https://github.com/Tunet-xyz/access_gate/blob/main/docs/customization.md). AccessGate provides its own
policy format but does not claim wire compatibility with XACML, Cedar, Rego, or
other policy languages.

## Development

```bash
python -m pip install -e ".[dev]"
ruff check src tests fuzz tools
mypy src/access_gate
pytest --cov=access_gate --cov-report=term-missing
python -m tools.authorization_benchmark --enforce
```

Security reviewers should begin with the
[`threat model`](https://github.com/Tunet-xyz/access_gate/blob/main/docs/THREAT_MODEL.md),
[`assurance case`](https://github.com/Tunet-xyz/access_gate/blob/main/docs/SECURITY_ASSURANCE.md), and
[`audit scope`](https://github.com/Tunet-xyz/access_gate/blob/main/docs/AUDIT_SCOPE.md).

## Contributing and releases

See [CONTRIBUTING.md](https://github.com/Tunet-xyz/access_gate/blob/main/CONTRIBUTING.md) for the owner-reviewed contribution process and [VERSIONING.md](https://github.com/Tunet-xyz/access_gate/blob/main/VERSIONING.md) for the shared SemVer and release policy. Report vulnerabilities privately as described in [SECURITY.md](https://github.com/Tunet-xyz/access_gate/blob/main/SECURITY.md). CI workflows run only when the maintainer starts them, so include your local test results in pull requests.

## License

MIT (c) Tunet Ltd. See [LICENSE](https://github.com/Tunet-xyz/access_gate/blob/main/LICENSE).
