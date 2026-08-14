# Policy format and migration

`access_gate.policy.v1` is the only executable serialized policy version in this
release. Parsing is exact: unknown fields, unknown operators, duplicate actions,
wrong types, unsupported versions, excess size/depth/nodes, and ambiguous
condition shapes are rejected. There is no implicit migration or best-effort
interpretation.

Canonical policy bytes use UTF-8 JSON with sorted object keys, compact
separators, Unicode preserved, and non-finite numbers rejected. The identifier
`access_gate.canonical-json.v1` describes this package-specific representation;
it is not a claim of RFC 8785 compatibility. Policy-set fingerprints include
configured order because order can affect diagnostic selection.

Signed envelopes protect the envelope version, canonicalization identifier,
key identifier, declared algorithm, and complete policy. AccessGate owns no keys
and chooses no algorithm. A caller-supplied synchronous verifier must validate
the declared algorithm and key against an allowlisted trust store; returning
anything except exact `True` rejects the policy. Apply freshness, activation,
revocation, and rollback rules outside the envelope.

Future formats require a new schema identifier, threat-model update, schema and
golden fixtures, explicit one-way migration code, negative tests, and a release
note. A v1 parser must never silently accept a future version.

The golden v1 fixture under `tests/fixtures/policies/v1` has fingerprint
`sha256:38e6408b17ee1e83c6b14f44593678e46264f4133ccaac116b5ced51ce3d87a7`.
