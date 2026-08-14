# Audit scope

An assessment must name an immutable Git commit and the exact wheel and sdist
SHA-256 digests. Findings against a moving branch or an unverified local build
are not release evidence.

## In scope

- `src/access_gate`: core values, policies, ABAC, strategies, engine, adapters,
  integrity envelope, schemas, and MCP implementation.
- Public exports and optional Django behavior.
- Parser and resource-exhaustion boundaries.
- Tests, fuzz targets, benchmarks, type/lint/security configuration.
- Build, dependency, publishing, SBOM, checksum, and attestation workflows.

## Out of scope unless separately commissioned

- Host applications and their resolver implementations.
- Identity providers, token/session verification, databases, cloud controls,
  networks, signing-key infrastructure and organizational processes.
- Custom extensions supplied by a consumer.
- Claims about classified deployment or an accrediting authority's acceptance.

## Review entry points

Start with `THREAT_MODEL.md`, `architecture.md`, `SECURITY_ASSURANCE.md`,
`SECURE_DEVELOPMENT.md`, and `POLICY_FORMAT.md`; then trace all public exports,
decision creation, error paths, serialization boundaries, and release jobs.
Treat examples as non-normative. Record tool versions and distinguish automated
findings from manual design conclusions.
