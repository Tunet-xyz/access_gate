# AccessGate secure development

AccessGate applies the intent of the NIST Secure Software Development Framework
(SSDF) to a small security library.

## Practices

- **Prepare:** maintain the threat model, ownership boundaries, disclosure
  process, protected CI permissions, and documented release criteria.
- **Protect:** require least-privilege workflows, commit-pinned actions, hashed
  release tooling, trusted publishing, protected environments, and reviewed
  changes on `main`.
- **Produce:** specify authorization invariants, use strict typing and linting,
  test negative/error paths, property-test independent models, fuzz untrusted
  parsers, mutation-test the suite, and enforce resource/performance budgets.
- **Respond:** triage privately, contain critical issues rapidly, revoke or
  rotate affected trust, issue patched releases and advisories, and capture
  lessons in tests and the threat model.

## Security-sensitive changes

Every security-relevant change must identify the affected assets and trust
boundaries, include negative tests, and consider compatibility and migration.
No generated or AI-assisted change is exempt from human review and the same
checks. Do not weaken a bound, error mode, audit behavior, signature check, or
release gate solely to preserve compatibility.

Review these areas with particular care: decision strategies and error
modes, ABAC operators, negation, and limits, serialized-policy parsing,
policy fingerprints and signed envelopes, the Django adapter's resolvers and
denial handling, and the MCP server's validation path.

## Repository controls

These GitHub settings were in place on 2026-11-10:

- `main` accepts pushes only from the owner and rejects force pushes and
  deletion. Other changes need a pull request approved by the code owner, with
  stale approvals dismissed and conversations resolved.
- Release tags (`v*`) can be created only by repository administrators, and no
  one can move or delete them.
- The `pypi` environment accepts only `main` and `v*` tags, requires the
  owner's approval, and does not let administrators bypass it. PyPI uploads use
  Trusted Publishing with short-lived OIDC credentials.
- Every workflow is manual (`workflow_dispatch`) and runs only when the owner
  starts it, with actions pinned to full commit SHAs and read-only default
  permissions. Pull requests, issues, and comments cannot start a workflow.
  GitHub's Dependabot jobs run weekly on their own and only open pull requests.
- Workflows can use only the actions on the repository's allowlist, each at one
  commit SHA. Before merging a Dependabot pull request that moves an action to a
  new SHA, the owner adds the new SHA to the allowlist, together with any action
  the new version itself uses.
- Secret scanning with push protection, private vulnerability reporting, and
  Dependabot alerts, security updates, and weekly version updates are on.

Known gaps: the project has one maintainer, so no second person reviews the
owner's changes, and the owner can push to `main` directly. No status checks
are required, because CI runs only when the owner starts it, and commits are
not required to be signed. Export these settings with each audit.
