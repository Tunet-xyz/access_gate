# Customization

AccessGate customization is protocol-based. An application can replace one
part without subclassing or forking the engine.

## Identity and resource mapping

Implement `SubjectResolver` and `ResourceResolver` at the application boundary.
Resolvers should validate claim types, normalize identifiers once, and reject
ambiguous or missing security-critical scope. Never place token verification in
a policy; verification must happen before a `Subject` is created.

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

## Decision strategies

Implement `DecisionStrategy.combine(request, decisions)` to change composition.
The strategy must always return a final `Decision`; there is no final abstain.
The built-in `DenyOverrides` is recommended for most application authorization.

## Audit sinks

Implement `AuditSink.record(request, decision)`. The default audit error mode is
`DENY`, so a sink failure fails closed. Configure `RAISE` if your integration
layer converts the exception to a denial and records the operational failure.

## Framework adapters

Adapters should be thin: obtain already-authenticated identity, resolve domain
objects, call the engine once, and translate denial into the framework's normal
403 mechanism. Business policy belongs in policies, not decorators or middleware.
