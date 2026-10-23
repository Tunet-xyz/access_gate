# Customization

AccessGate customization is protocol-based. An application can replace one
part without subclassing or forking the engine.

## Identity and resource mapping

Implement `SubjectResolver` and `ResourceResolver` at the application boundary.
Resolvers should validate claim types, normalize identifiers once, and reject
ambiguous or missing security-critical scope. Never place token verification in
a policy; verification must happen before a `Subject` is created.
Built-in ownership and tenant policies require non-empty string identifiers;
they never coerce integers, booleans, or other malformed values into a match.

## Policies

Implement the `Policy` protocol:

```python
class BusinessHoursPolicy:
    name = "business_hours"

    def evaluate(self, request):
        hour = request.context.get("hour")
        if isinstance(hour, int) and 8 <= hour < 18:
            return None
        return Decision.deny("Access is outside the permitted window.", policy=self.name)
```

Boundary policies should deny violations and abstain on success. Grant policies
should allow a positive match and either deny or abstain on a miss, according to
whether another grant is valid for the same action.

Custom policies may expose `actions: frozenset[str] | None`. A non-empty,
validated frozenset opts the policy into engine action indexing; `None` or an
unrecognized shape remains a global policy. The policy must still abstain when
called directly with an unrelated action. `FunctionPolicy(actions=...)` handles
both behaviors automatically.

Declarative policies can use `AttributePolicy`. Custom operands implement the
`Operand` protocol; custom operators are registered on an `OperatorRegistry`
instance supplied to a policy. The policy copies that registry, preventing
later application mutation from changing an already-configured policy. The
policy-owned copy is frozen as well; operator registration is a configuration
phase operation, not a runtime hot-reload mechanism.

Custom operators must be deterministic, side-effect free, quick to evaluate,
and return a boolean. Exceptions become redacted indeterminate outcomes. Do not
perform network or database access inside an operator; resolve those attributes
before calling the engine.

## Decision strategies

Implement `DecisionStrategy.combine(request, decisions)` to change composition.
The strategy must always return a final `Decision`; there is no final abstain.
The engine treats an allow returned when no policy allowed the request as a
strategy failure, so permit-unless-deny style strategies are not supported.
The built-in `DenyOverrides` is recommended for most application authorization.

## Audit sinks

Implement `AuditSink.record(request, decision)`. The default audit error mode is
`DENY`, so a sink failure fails closed. Configure `RAISE` if your integration
layer converts the exception to a denial and records the operational failure.

## Framework adapters

Adapters should be thin: obtain already-authenticated identity, resolve domain
objects, call the engine once, and translate denial into the framework's normal
403 mechanism. Business policy belongs in policies, not decorators or middleware.
An adapter that cannot build an authorization request can still audit its
denial with `AuthorizationEngine.record_denial()`.

The Django adapter preserves both synchronous and asynchronous view behavior.
Resolvers and denial handlers used by an async view may return awaitables. A
synchronous view rejects an awaitable resolver result instead of leaking a
coroutine or silently bypassing enforcement. In an async view, the default
subject resolver and the engine (policies and audit sinks) run through
`asgiref.sync.sync_to_async`, so they may use the ORM. When every policy and
audit sink is non-blocking pure Python, `async_engine_in_thread=False` runs the
engine on the event loop and saves that thread hop. Synchronous resolvers or
denial handlers you supply run on the event loop; make them async if they
perform I/O.

## Serialized policies

`AttributePolicy.to_dict()`, `dumps_policy()`, `loads_policy()`, and
`attribute_policy_from_dict()` use the versioned `access_gate.policy.v1` format.
The parser rejects unknown fields, duplicate actions, invalid effect values,
empty condition groups, unsafe operator names, and unregistered operators.

The packaged schema is available through `load_policy_schema()`, the
`opensource://access_gate/policy-schema` MCP resource, and the MCP
`get_policy_schema` tool.
