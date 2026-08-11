# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x alpha | Yes |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Email
**alex@tunet.xyz** with a description, reproduction steps, potential impact,
and any suggested mitigation.

We aim to acknowledge reports within 48 hours, provide an initial assessment
within five business days, and release fixes for critical issues within 30 days.

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
