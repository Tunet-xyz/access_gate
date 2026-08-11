# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
