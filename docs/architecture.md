# Architecture

AccessGate separates authorization into five replaceable parts:

1. **Resolvers** map verified application identities and objects into `Subject`,
   `Resource`, action-attribute, and context value mappings.
2. **Policies** independently evaluate a subject/action/resource/context tuple.
3. **A decision strategy** combines explicit policy results.
4. **The engine** applies failure behaviour and produces the final decision.
5. **An audit sink** records that final decision.

The core imports no web framework, ORM, token library, or Safety AZ code.
Framework adapters depend inward on the core; the core never depends outward on
an adapter.

## Evaluation sequence

```text
application input
      |
      v
subject/resource/action/context resolvers
      |
      v
AuthorizationRequest
      |
      +-- policy A -- allow / deny / abstain
      +-- policy B -- allow / deny / abstain
      +-- policy N -- allow / deny / abstain
      |
      v
decision strategy (default: deny overrides)
      |
      v
audit sink
      |
      v
Decision
```

With the default configuration, a policy exception becomes an explicit denial,
no matching policy becomes a denial, and an audit failure replaces the result
with a denial. `ErrorMode.RAISE` is available when the host application owns
exception-to-denial handling. `ErrorMode.IGNORE` is explicit and should be used
only when the associated extension is genuinely non-security-critical.

Decision-strategy exceptions also deny by default. They may be raised to the
host with `strategy_error_mode=ErrorMode.RAISE`; ignoring a missing final
decision is intentionally unsupported.

Authorization mappings are recursively snapshotted into immutable containers.
This prevents caller mutation, policy mutation, or an audit sink from changing
the facts associated with an in-flight or retained decision.
Use each value object's `to_dict()` method when an audit or transport integration
needs ordinary JSON-serializable lists and dictionaries.

## Stable domain vocabulary

- **Subject:** the actor, including exact roles and application-defined claims.
- **Action:** a namespaced string such as `incident.read` or `user.invite`.
- **Resource:** the protected object or collection and its policy attributes.
- **Context:** request-time facts such as method, path, source, or assurance level.
- **Decision:** allow or deny, with a safe reason, policy identifier, and metadata.

Applications should keep sensitive values out of decision reasons and metadata
because audit sinks may persist them.

## Authorization models

RBAC is represented by exact `RolePolicy` rules. ABAC uses an
`AttributePolicy` condition tree over subject, resource, action, and context
namespaces. `OwnerPolicy` and `TenantBoundaryPolicy` cover common relationship
and scope boundaries. All of them implement the same `Policy` protocol and are
combined by the same decision strategy.

At engine construction, policies with immutable action targets are indexed.
Evaluation merges matching targeted policies with global policies in original
configuration order, so deny-overrides and deterministic first-decision details
remain stable without scanning unrelated action-specific rules.

ABAC conditions evaluate to `match`, `no_match`, or `indeterminate`. Missing
attributes, unknown operators, and operator exceptions are indeterminate. A
negation preserves indeterminate rather than converting it to a match.
