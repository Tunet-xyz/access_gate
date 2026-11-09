# AccessGate documentation

Start with the [README](../README.md) for installation, a quick start, and the
Django adapter. These documents go further.

## Guides

| Guide | Contents |
| --- | --- |
| [Architecture](architecture.md) | Evaluation sequence, domain vocabulary, and supported authorization models |
| [Attribute-based access control](abac.md) | Condition outcomes, operators, grant and boundary policies, custom operators, and rollout |
| [Customization](customization.md) | Identity and resource mapping, policies, decision strategies, audit sinks, and adapters |
| [Policy format](policy-format.md) | The `access_gate.policy.v1` format, signed envelopes, and migration |
| [MCP server](../mcp/README.md) | The local stdio server: methods, tools, limits, and boundaries |

## Security

| Document | Contents |
| --- | --- |
| [Security policy](../SECURITY.md) | Supported versions, private vulnerability reporting, and response targets |
| [Threat model](THREAT_MODEL.md) | Assets, trust boundaries, threats, controls, and residual risks |
| [Security assurance](SECURITY_ASSURANCE.md) | The evidence behind each security claim, and what it does not establish |
| [Audit scope](AUDIT_SCOPE.md) | What a package security review covers and where to start |
| [Secure development](SECURE_DEVELOPMENT.md) | How changes are designed, tested, reviewed, and released |

## Releases and contributing

| Document | Contents |
| --- | --- |
| [Changelog](../CHANGELOG.md) | Changes in each version, and which versions reached PyPI |
| [Versioning policy](../VERSIONING.md) | SemVer and release rules shared by the Tunet libraries |
| [Release procedure](RELEASE.md) | Verification, build, and owner-approved publication |
| [Contributing](../CONTRIBUTING.md) | How to report issues and propose changes |
| [Code of conduct](../CODE_OF_CONDUCT.md) | Expected behavior in project spaces |

## Links

- [PyPI](https://pypi.org/project/AccessGate/)
- [GitHub](https://github.com/Tunet-xyz/access_gate)
- [Tunet open-source libraries](https://www.tunet.xyz/engineering/)
