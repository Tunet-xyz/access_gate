# Secure development lifecycle

The project applies the intent of NIST SSDF to a small security library:

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

Every security-relevant change must identify affected assets/trust boundaries,
include negative tests, and consider compatibility and policy migration. No
generated or AI-assisted change is exempt from human review and the same checks.
Do not weaken a bound, error mode, audit behavior, signature check, or release
gate solely to preserve compatibility.

Repository settings are not encoded by source files. Administrators must require
review by at least one independent maintainer, dismissal of stale approvals,
conversation resolution, signed commits or protected signed tags where policy
requires them, passing required checks, restricted force-push/deletion, and
approval for the `pypi` environment. Export those settings for each audit.
