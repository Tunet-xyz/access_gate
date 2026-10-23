# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.3.x alpha | Yes |
| < 0.3 | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Email
**alex@tunet.xyz** with a description, reproduction steps, potential impact,
and any suggested mitigation.

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
for remediation before public disclosure. We will request a CVE and publish an
advisory when impact warrants it.

## In scope

- Any path that incorrectly converts abstention or an error into access.
- Deny-overrides or tenant-boundary bypasses.
- Inexact role, action, subject, resource, owner, or tenant matching.
- Information disclosure through decision reasons or metadata.
- Framework adapter behaviour that bypasses or misrepresents a denial.
- Missing attributes, unknown operators, or operator failures that become grants.
- Negation or condition-composition behaviour that converts indeterminate input
  into a match.
- Unsafe attribute traversal, arbitrary expression evaluation, or implicit
  substring matching in built-in ABAC operators.
- Serialized-policy validation that accepts unsupported versions, operators, or
  ambiguous condition shapes.
- MCP validation or diagnostic output that exposes supplied attribute values.

Authentication, credential storage, session integrity, token verification, and
vulnerabilities in host frameworks are outside AccessGate's implementation
boundary unless the package claims to perform the affected operation.

## Release and support expectations

Security fixes are released from a reviewed commit through the trusted-publishing
workflow. Consumers should pin and verify release artifacts, subscribe to
security advisories, test authorization integration, and upgrade supported
versions promptly. Alpha releases may contain incompatible API changes; a
security fix may intentionally reject previously accepted ambiguous input.
