# Security policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Security fixes ship as new 1.0.x releases on
[PyPI](https://pypi.org/project/AccessGate/). The pre-1.0 alphas on PyPI
(0.2.0a1 and 0.3.0a1) are not supported; upgrade to 1.0.x.

## Reporting a vulnerability

Do not report a suspected vulnerability in a public issue, pull request, or
discussion. Report it privately in either of these ways:

- On GitHub, open the repository's **Security** tab and choose
  **Report a vulnerability**
  ([direct link](https://github.com/Tunet-xyz/access_gate/security/advisories/new)).
- Email **alex@tunet.xyz**.

Include a description, the affected versions, reproduction steps, the potential
impact, and any suggested mitigation. Use synthetic examples; do not send
credentials, personal data, or production samples.

## Response targets

We aim to acknowledge reports within 48 hours and provide an initial assessment
within five business days. Targets begin when severity is confirmed:

| Severity | Containment/mitigation target | Fix target |
| --- | --- | --- |
| Critical | 24 hours | 7 days |
| High | 3 business days | 14 days |
| Moderate | 10 business days | 30 days |
| Low | 30 days | 90 days |

These are maximum targets, not a promise to delay urgent fixes. If a complete
fix needs longer, we will prioritize a safe mitigation, coordinate disclosure,
and communicate a revised timeline privately. Please allow a reasonable period
for remediation before public disclosure. We will request a CVE and publish a
GitHub security advisory when impact warrants it.

## Scope

### In scope

- Any path that incorrectly converts abstention or an error into access.
- Deny-overrides or tenant-boundary bypasses.
- Inexact role, action, subject, resource, owner, or tenant matching.
- Information disclosure through decision reasons or metadata.
- Framework adapter behavior that bypasses or misrepresents a denial.
- Missing attributes, unknown operators, or operator failures that become grants.
- Negation or condition-composition behavior that converts indeterminate input
  into a match.
- Unsafe attribute traversal, arbitrary expression evaluation, or implicit
  substring matching in built-in ABAC operators.
- Serialized-policy validation that accepts unsupported versions, operators, or
  ambiguous condition shapes.
- MCP validation or diagnostic output that exposes supplied attribute values.

### Out of scope

- Authentication, credential storage, session integrity, and token
  verification, unless AccessGate claims to perform the affected operation.
- Vulnerabilities in host frameworks such as Django; report them to that
  project.
- Resolvers, policies, signers, and audit sinks supplied by an application,
  unless the flaw comes from AccessGate's documented contract.

## Secure use

- AccessGate decides what an identified caller may do. Authenticate users and
  protect sessions separately, for example with SessionArmor, whose evidence
  `SessionAssurancePolicy` can require.
- Provide resolvers that validate and map your exact identity claims. The
  default Django resolver reads only `pk` (or `id`), `is_authenticated`,
  `access_gate_roles`, and `access_gate_attributes`.
- Keep the default fail-closed error modes, and test the deny, missing-data,
  malformed-input, and extension-failure paths of your own policies.
- Identify deployed policy sets with `policy_set_fingerprint()`, and verify
  signed policy envelopes with keys your application manages.

The [threat model](docs/THREAT_MODEL.md),
[security assurance case](docs/SECURITY_ASSURANCE.md),
[audit scope](docs/AUDIT_SCOPE.md), and
[secure development](docs/SECURE_DEVELOPMENT.md) documents describe the design
assumptions, evidence, and residual risks in more detail.

## Releases and advisories

Security fixes are released from a reviewed commit on `main` through the
owner-approved trusted-publishing workflow described in
[docs/RELEASE.md](docs/RELEASE.md). Workflows run only when the owner starts
them, and PyPI uploads use short-lived OIDC credentials from a protected
environment. Stable API changes follow [VERSIONING.md](VERSIONING.md); a
security fix may intentionally reject previously accepted ambiguous input, with
the compatibility and migration impact explained in the release notes. Pin and
verify release artifacts, watch this repository's security advisories, test
your integration, and upgrade supported versions promptly.
