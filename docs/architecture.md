# Architecture

AccessGate separates authorization into five replaceable parts:

1. **Resolvers** map application identities and objects into `Subject` and
   `Resource` value objects.
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
      │
      ▼
subject/resource resolvers
      │
      ▼
AuthorizationRequest
      │
      ├── policy A ── allow / deny / abstain
      ├── policy B ── allow / deny / abstain
      └── policy N ── allow / deny / abstain
      │
      ▼
decision strategy (default: deny overrides)
      │
      ▼
audit sink
      │
      ▼
Decision
```

With the default configuration, a policy exception becomes an explicit denial,
no matching policy becomes a denial, and an audit failure replaces the result
with a denial. `ErrorMode.RAISE` is available when the host application owns
exception-to-denial handling. `ErrorMode.IGNORE` is explicit and should be used
only when the associated extension is genuinely non-security-critical.

## Stable domain vocabulary

- **Subject:** the actor, including exact roles and application-defined claims.
- **Action:** a namespaced string such as `incident.read` or `user.invite`.
- **Resource:** the protected object or collection and its policy attributes.
- **Context:** request-time facts such as method, path, source, or assurance level.
- **Decision:** allow or deny, with a safe reason, policy identifier, and metadata.

Applications should keep sensitive values out of decision reasons and metadata
because audit sinks may persist them.
