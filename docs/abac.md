# Attribute-Based Access Control

AccessGate ABAC evaluates a condition tree over four namespaces:

| Namespace | Canonical contents | Convenience factory |
| --- | --- | --- |
| Subject | `id`, `authenticated`, `roles`, `attributes` | `SubjectAttribute(path)` |
| Resource | `id`, `kind`, `attributes` | `ResourceAttribute(path)` |
| Action | `name`, `attributes` | `ActionAttribute(path)` |
| Context | Application-provided environment mapping | `ContextAttribute(path)` |

Convenience factories select the application-defined `attributes` mapping.
Use `AttributeRef` for canonical fields such as `subject.authenticated`,
`resource.kind`, or `action.name`.

Attribute paths traverse mappings only. AccessGate never calls `getattr`,
properties, descriptors, or arbitrary expressions while resolving a path.

## Condition outcomes

Every condition returns one of three states:

- `match`: the condition is positively satisfied.
- `no_match`: the condition was evaluated and is false.
- `indeterminate`: required data is missing or evaluation could not be completed
  safely.

An `AttributePolicy` denies indeterminate results by default. `Not` leaves an
indeterminate result indeterminate; it never turns missing data or an operator
failure into a match.

`AllOf` returns `no_match` if any child is a definite no-match, otherwise
indeterminate if any child is indeterminate. `AnyOf` returns `match` if any child
matches, otherwise indeterminate if any child is indeterminate.

## Built-in operators

| Operator | Meaning |
| --- | --- |
| `eq`, `neq` | Type-aware equality or inequality, also inside lists, mappings and sets; numeric int/float values interoperate, booleans remain distinct, and a `str` subclass such as a string enum member never equals a plain string. |
| `in`, `not_in` | Exact membership of the left scalar in the right collection. |
| `contains`, `not_contains` | Exact membership of the right scalar in the left collection. |
| `intersects` | At least one exact value appears in both collections. |
| `subset_of`, `superset_of` | Exact collection inclusion. |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison of int and float values; any other operand type is indeterminate. |
| `exists`, `not_exists` | Explicit presence or absence checks. |

Strings are not treated as collections. Passing a string or scalar where a
collection is required produces an indeterminate result rather than a substring
match or a negated grant. Likewise a boolean, string, `None`, `Decimal` or
date operand to an ordered comparison is indeterminate, and so is any built-in
comparison involving a NaN (`float`, `Decimal` or `complex`). Register an
explicitly named custom operator if a domain requires different semantics.

Collection operands are limited to 10,000 items. Primitive intersections and
subset checks use exact, type-aware set keys. Comparisons involving complex,
unhashable values retain exact semantics but are capped at 100,000 candidate
pairs; exceeding the limit is indeterminate and therefore denies by default.

## Grant and boundary policies

An allow policy grants on a match and denies a no-match by default:

```python
policy = AttributePolicy(
    SubjectAttribute("clearance").greater_than_or_equal(
        ResourceAttribute("classification")
    ),
    actions={"document.read"},
)
```

Set `on_no_match=MissEffect.ABSTAIN` when another independent grant is valid.
That alone still denies an indeterminate result, so a request that lacks the
policy's facts (for example, no device context) is denied even when another
grant applies. Also set `on_indeterminate=MissEffect.ABSTAIN` when missing facts
should only mean that this grant path does not apply. An allow policy that
abstains cannot grant, so this never creates access; keep the default when an
evaluation failure must block every other grant.

A deny boundary denies on a match and abstains on a no-match by default:

```python
blocked_country = AttributePolicy(
    ContextAttribute("country").equals("blocked"),
    match_effect=Effect.DENY,
    name="blocked_country",
)
```

The engine's default deny-overrides strategy means a matching boundary wins over
RBAC, ABAC, ownership, or other grants.

## Custom operators

Operators are local to a registry and are copied into the policy:

```python
registry = OperatorRegistry()
registry.register("same_prefix", same_prefix)

policy = AttributePolicy(
    SubjectAttribute("cost_center").compare(
        "same_prefix", ResourceAttribute("cost_center")
    ),
    operators=registry,
)
```

Names must use lowercase letters, digits, and underscores. `exists` and
`not_exists` are reserved. Do not use custom operators for I/O, authentication,
token verification, database queries, or mutable application state. Resolve and
validate those facts before authorization.

The copied registry is frozen when attached to a policy. Build and test the
registry before policy construction; attempts to replace operators afterward
raise `TypeError`.

## Serialized policy format

`AttributePolicy.to_dict()` emits a complete `access_gate.policy.v1` document.
`dumps_policy()` and `loads_policy()` provide JSON round-tripping. The strict
parser rejects unknown fields, duplicate actions, invalid condition shapes, and
operators absent from the supplied registry.

The JSON Schema is packaged at `schema/abac-policy-v1.json` and available from
`load_policy_schema()` and the AccessGate MCP server.

Policy JSON is limited to 1,000,000 characters, 64 nested condition or literal
levels, 4,096 condition nodes/actions, and 100,000 literal nodes. Deployments
should apply a smaller transport limit when their policy domain permits it.

Custom operators remain code and are not embedded in a policy document. A host
must explicitly supply the required registry when loading such a policy.

Policy decisions omit the configured condition document from metadata by
default, because literal operands may contain sensitive configuration. Set
`include_policy_document_in_metadata=True` only for a controlled diagnostic
environment whose audit sink, retention, and access controls are appropriate.
Structural evaluation metadata remains available without supplied values.

`equals(None)` and other comparisons with `None` use an explicit JSON null
literal. Omitting the operand is distinct and is valid only for operators whose
shape permits it. A comparison whose two attribute operands both resolve to
`None` is indeterminate, so an absent claim and an empty resource field never
establish a relationship.

## Attribute provenance

Treat each attribute as a security input:

1. Verify identity and tokens before constructing a `Subject`.
2. Obtain resource attributes from an authoritative, tenant-scoped source.
3. Define action attributes in trusted application configuration.
4. Derive context attributes through a reviewed adapter; do not trust forwarded
   headers without a validated proxy boundary.
5. Normalize identifiers and types once at the resolver boundary.
6. Avoid placing raw secrets or personal data in decision reasons or metadata.

## Rollout

Before enforcement, run representative decisions in shadow mode and compare
AccessGate outcomes with the existing authorization path. Exercise missing and
malformed attributes, cross-tenant resources, exact action names, custom
operator failures, and audit-sink failures. Monitor denial reasons by policy
identifier, retain a rollback path, then enable enforcement incrementally.
