# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Native async Django view support, including awaitable adapter resolvers and
  denial handlers.
- Bounded policy documents, condition depth, condition count, MCP messages, and
  collection evaluation workloads.
- Fail-closed decision-strategy error handling with an explicit
  `strategy_error_mode`.

### Changed

- Authorization inputs, literal values, and decision metadata are recursively
  snapshotted into immutable containers.
- Operator registries attached to policies are frozen against later mutation.
- Collection operators now classify invalid operand shapes as indeterminate.
- Primitive collection intersection and subset checks use linear-time set
  comparisons, and decisive condition branches short-circuit safely.
- Policies declaring immutable action targets are indexed by action while
  preserving configured evaluation order; `decide_many()` provides ordered
  batch evaluation with per-request auditing.
- GitHub Actions are commit-pinned, vulnerability auditing is blocking, and
  package building is isolated from the PyPI publishing identity.

### Security

- Empty role requirements and malformed policy names/actions are rejected at
  construction time.
- Invalid policy results, invalid error-mode configuration, and strategy
  exceptions can no longer create ambiguous authorization behavior.
- Invalid or oversized JSON-RPC messages no longer terminate the MCP server.

## [0.2.0a1] - 2026-08-11

### Added

- First-class ABAC across subject, resource, action, and context namespaces.
- Tri-state conditions with fail-closed missing-data and operator-error handling.
- Exact equality, membership, set-relation, numeric, and existence operators.
- Nested `AllOf`, `AnyOf`, and indeterminate-preserving `Not` conditions.
- Policy-local custom operator registries and custom operand protocol support.
- Versioned `access_gate.policy.v1` serialization and packaged JSON Schema.
- Strict serialized-policy parsing with unknown-field and duplicate-action rejection.
- Django action-attribute resolver support.
- Dependency-free MCP server with resources, prompts, operator discovery, schema
  discovery, and real read-only policy validation.

### Changed

- Package version advanced to `0.2.0a1`.

## [0.1.0a1] - 2026-08-11

### Added

- Framework-neutral subject, resource, request, and decision value objects.
- Default-deny, deny-overrides authorization engine.
- Configurable fail-closed policy and audit error handling.
- Policy, decision strategy, resolver, and audit sink extension protocols.
- Built-in authentication, role, ownership, and tenant-boundary policies.
- Optional Django view decorator adapter with replaceable resolvers and denial handler.
- Test, security, and trusted-publishing workflows.
