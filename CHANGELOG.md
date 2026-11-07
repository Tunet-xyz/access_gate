# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- README: the upgrade note names the two alphas published to PyPI, the Django
  subject resolver's `id` fallback and the CI lint scope are documented, and the
  MCP and contribution notes are written for outside readers.

## [1.0.0] - 2026-11-05

### Changed

- Stabilized the documented engine, policy, ABAC v1, immutable decision, extension
  protocol, Django adapter, and local MCP APIs from 0.3.0a2.
- Adopted the shared SemVer, owner-review, manual-workflow, and immutable-release
  policy, with matching Claude and Codex instructions.
- Aligned package, runtime, and MCP versions while preserving serialized schema
  versions; bounded the Django extra below the next unsupported major release.
- Declared packaged MIT license files and a PEP 639-capable build backend.
- Made reproducible-build tooling work on Windows as well as POSIX hosts and
  generated a cross-platform build dependency lock for Python 3.10+.

### Security

- Updated the pinned setuptools build tool to 84.2.1 to address
  GHSA-xmj3-9gf7-h52w in the previous Windows build toolchain.

### Documentation

- Documented the stable public contract, alpha migration boundary, supported
  integration ranges, local MCP access boundary, and assurance limitations.

## [0.3.0a2] - 2026-10-29 (not published to PyPI; included in 1.0.0)

### Security

- A comparison whose two attribute operands both resolve to `None` is now
  indeterminate (`issue: null_operands`) instead of matching, so an absent claim
  and an empty resource field never satisfy a relationship grant or slip past a
  `neq` deny boundary. Compare against an explicit `None` literal when null is
  intended.
- `gt`/`gte`/`lt`/`lte` with a non-int/float operand (string, `None`, boolean,
  `Decimal`, date), and any built-in comparison involving a float, `Decimal` or
  complex NaN, are now indeterminate instead of no-match, so deny boundaries and
  negated grants fail closed.
- `loads_policy` and `AttributePolicy.from_dict` reject documents that omit
  `actions` (use `null` to target every action) and comparisons with an explicit
  `"right": null`, matching the packaged policy JSON Schema.
- Policy fingerprints, signed envelopes and `dumps_policy` refuse literals that
  JSON would retype (str subclasses such as enum members, as values or mapping
  keys, and non-string mapping keys). Such a policy used to share its
  fingerprint with a reloaded policy that decides differently.
- `default_subject_resolver` authenticates only when `user.is_authenticated is
  True`; a legacy `is_authenticated()` method or another truthy value no longer
  authenticates. `access_gate_roles=None` means no roles, and `None` or empty
  role entries are dropped.
- The engine treats an allow returned by a decision strategy when no policy
  allowed the request as a strategy failure (deny, or raise under
  `strategy_error_mode=RAISE`).
- `ConditionResult` rejects a state that is not a `ConditionState`, so a custom
  condition returning a foreign state denies instead of falling through to a
  grant.

### Added

- `DjangoAuthorizer(resolver_error_mode=ErrorMode.DENY)` turns resolver and
  request-construction failures into an audited `access_gate.resolver` denial
  passed to the denial handler. The default `RAISE` is unchanged, and `Http404`
  and `PermissionDenied` still propagate.
- `DjangoAuthorizer.check()` and `acheck()` return an audited decision for checks
  inside a view (test `decision.allowed`; they never call the denial handler);
  `AuthorizationEngine.record_denial()` audits a denial reached without policy
  evaluation.

### Changed

- `eq`/`neq` and the collection operators (`in`, `contains`, `intersects`,
  `subset_of`, `superset_of` and their negations) apply type-aware equality
  inside lists, mappings and sets (`[True]` no longer equals `[1]` or is `in`
  `[[1]]`), and `intersects`/`subset_of`/`superset_of` no longer treat a `str`
  subclass such as a `StrEnum` member as a plain string.
- Exact, type-aware comparison keys also cover UUIDs, dates, enum members and
  tuples and frozensets of hashable values. Sets and mapping keys of them compare
  in linear time, and `intersects`/`subset_of`/`superset_of` over them are no
  longer indeterminate when the two sizes multiply to more than 100,000. The
  100,000-pair fallback limit for unhashable values now covers nested
  comparisons in total.
- Deques, `UserList`, `array`, dictionary views, other mutable sequences and
  sets, `bytearray` and `memoryview` in request attributes, policy literals and
  decision metadata are copied into tuples, frozensets and bytes, so later
  caller mutation cannot change a decision or its audit record.
- Subject, request and policy construction is faster: exact built-in scalars
  skip the container checks, and policies without custom operators share a
  pre-validated built-in operator table. Decisions are unchanged.
- Release workflows stay manually dispatched but refuse refs other than `main`
  or `v<version>`, run lint, type checks and tests first, normalize sdist file
  modes, and publish the verified build; tag dispatches attach release evidence.
- The authorization benchmark times an in-bounds matching collection comparison
  and checks that every benchmarked decision allows; mutation testing copies
  `tools/`, `fuzz/` and `mcp/` so runs complete.
- The hybrid example sets `on_indeterminate=MissEffect.ABSTAIN` on alternative
  grant policies so missing facts no longer veto an independent grant.
- The README states that `Subject.identifier` must equal SessionArmor's evidence
  subject, which SessionArmor takes from `sub` before `pk`.
- Release and assurance docs reference PyPI PEP 740 attestations instead of the
  removed GitHub artifact attestations, and the SECURITY.md support table lists
  0.3.x.

### Fixed

- Async Django views work under ASGI: the default subject resolver and the
  engine (policies and audit sinks) run through `sync_to_async`.
  `DjangoAuthorizer(async_engine_in_thread=False)` keeps the engine on the event
  loop for non-blocking policies.
- Policies nested to the documented 64 condition levels, with literals up to 64
  levels deep inside them, are accepted; `all_of`/`any_of` nesting used to be
  rejected from 33 levels with a generic error.
- A non-string `condition.type` raises `PolicySchemaError` instead of leaking
  `TypeError`, and unencodable policy text (lone surrogates) raises
  `PolicyIntegrityError` instead of a raw `UnicodeEncodeError` or a misleading
  signer/verifier failure.
- `Policy.name` is a read-only protocol property, so the built-in policies
  satisfy `Policy` under mypy.
- The MCP server writes ASCII-only JSON, reads stdin as UTF-8 under any locale,
  answers unserializable responses with -32603 and invalid UTF-8 with -32700
  instead of exiting, omits `outputSchema` when a tool defines none, answers
  `ping`, rejects a `null` request id, and never echoes an invalid id.
- Fuzz harnesses exercise the MCP write path and report any parser exception
  other than `PolicySchemaError`.

## [0.3.0a1] - 2026-08-17

### Added

- Exported `SessionAssurancePolicy` as a supported public boundary policy for
  fresh, subject-bound SessionArmor evidence, with compatibility tests for the
  duck-typed Django context bridge.
- Deterministic policy and ordered policy-set fingerprints, externally supplied
  signed-policy verification, and engine-owned policy-set decision identifiers.
- Property/differential tests, parser fuzz targets, scheduled mutation testing,
  authorization performance budgets, and golden policy-format fixtures.

### Changed

- Package version advanced to `0.3.0a1` for the coordinated session-assurance
  integration contract.
- Threat model, assurance case, immutable audit scope, secure-development,
  strict policy migration, and evidence-preserving release procedures.
- Reproducible release verification, hash-locked build tools, SPDX artifact SBOM,
  checksums, GitHub artifact attestations, and OpenSSF Scorecard analysis.
- Native async Django view support, including awaitable adapter resolvers and
  denial handlers.
- Bounded policy documents, condition depth, condition count, MCP messages, and
  collection evaluation workloads.
- Fail-closed decision-strategy error handling with an explicit
  `strategy_error_mode`.
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

- Policy literals are excluded from decision metadata by default; diagnostic
  inclusion is an explicit opt-in.
- Signed envelopes reject tampering, unknown fields, unsupported versions,
  non-canonical signatures, invalid verifier returns, and verifier failures.
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

## [0.1.0a1] - 2026-08-11 (not published to PyPI)

### Added

- Framework-neutral subject, resource, request, and decision value objects.
- Default-deny, deny-overrides authorization engine.
- Configurable fail-closed policy and audit error handling.
- Policy, decision strategy, resolver, and audit sink extension protocols.
- Built-in authentication, role, ownership, and tenant-boundary policies.
- Optional Django view decorator adapter with replaceable resolvers and denial handler.
- Test, security, and trusted-publishing workflows.
