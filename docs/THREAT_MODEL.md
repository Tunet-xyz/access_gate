# Threat model

This threat model covers the framework-neutral AccessGate package at a specific
source revision. It is not a system accreditation and must be combined with the
host application's identity, data, deployment, and operational threat models.

## Security objective

Given immutable subject, action, resource, action-attribute, and context inputs,
AccessGate must grant only when a configured policy produces a valid allow and
the configured decision strategy accepts it. Missing facts, malformed policies,
extension failures, abstention, and ambiguous results must not create access.

## Assets and trust boundaries

- Protected assets are authorization decisions, policy documents, policy-set
  identity, and audit records.
- Identity providers, JWT/session verification, databases, proxy headers,
  signing keys, and deployment configuration are outside the package boundary.
- Resolver output crosses from the host application into AccessGate and is
  trusted only after application validation.
- Custom policies, operators, strategies, resolvers, signers, verifiers, and
  audit sinks are executable trusted extensions.
- Serialized and MCP policy input is untrusted. Signed-policy trust is supplied
  by the caller's verifier and external key store.

## Adversaries and abuse cases

| Threat | Package control | Residual responsibility |
| --- | --- | --- |
| Missing, malformed, or type-confused attributes produce a grant | Tri-state ABAC, indeterminate-preserving negation, default deny, property tests | Resolver schemas and authoritative attribute provenance |
| Cross-tenant or relationship bypass | Exact matching, explicit deny boundaries, deny-overrides | Every protected path must configure and invoke its boundary policy |
| Policy tampering or stale policy deployment | Canonical fingerprints, signed envelopes, engine-owned `policy_set_id` | Trusted key management, rollback prevention, approval and distribution |
| Policy or audit extension raises or returns an invalid value | Fail-closed error modes and result validation | Do not select permissive modes for security-critical extensions |
| Policy literals or supplied values leak through diagnostics | Safe reasons, immutable metadata, policy-document redaction by default | Audit access control, retention, and application-provided reason hygiene |
| Resource exhaustion through policy JSON or collections | Document, depth, node, action, message, collection and comparison bounds | Transport limits, process limits, rate limiting and capacity planning |
| Arbitrary code execution through policy expressions | Declarative operators, mapping-only traversal, no `eval` | Custom operators remain trusted code and require review |
| Supply-chain substitution | Pinned CI actions, locked hashed build tools, reproducible artifacts, checksums, SBOM and PyPI (PEP 740) attestations | Protected branches/environments, trusted maintainers, tag policy and consumer verification |

## Required invariants

1. No applicable allow is a deny.
2. Any explicit deny overrides an allow under the default strategy.
3. Missing or indeterminate facts cannot become an allow through negation.
4. Input and decision snapshots cannot change after construction.
5. A signed policy is parsed into an executable policy only after every
   protected field and signature has been verified.
6. A release is not published unless tests, reproducibility, metadata checks,
   provenance generation, and the protected PyPI environment succeed.

## Explicitly out of scope

Authentication, cryptographic algorithm selection, private-key custody, token
validation, revocation services, distributed policy synchronization, database
row filtering, network security, and deployment accreditation are not provided.
AccessGate deliberately accepts signer/verifier protocols instead of embedding
a key-management or cryptography policy.

## Review triggers

Review this model for every new policy/operator, serialization version, trust
boundary, framework adapter, error mode, authorization input, cryptographic
integration, or release path. Record newly accepted residual risks before merge.
