# Security assurance case

This document links security claims to repository evidence. Passing evidence
increases confidence; it does not constitute NATO, government, regulatory, or
independent security certification.

| Claim | Implementation | Automated evidence |
| --- | --- | --- |
| Default deny and deny-overrides | `engine.py`, `strategies.py` | engine, strategy, differential property tests |
| Invalid or failing extensions cannot grant by default | engine result/error validation | adversarial engine and edge tests |
| Missing data and negation fail closed | tri-state conditions in `abac.py` | ABAC edge and Hypothesis tests |
| Matching is exact and type-aware | built-in ABAC operators and core policies | model-based equality/membership properties |
| Inputs and metadata are immutable snapshots | `types.py`, ABAC literal freezing | immutability and round-trip properties |
| Untrusted policy input is bounded and strict | ABAC parser/schema, signed envelope parser | parser boundary, tampering, property and fuzz suites |
| Policy deployments can be identified and verified | `integrity.py`, engine `policy_set_id` | fingerprint, envelope tamper, duplicate-name tests |
| Runtime cost has explicit regression limits | indexed policies and bounded collections | `authorization_benchmark --enforce` |
| Release bytes are traceable | locked build tools, reproducibility, SPDX, checksums, PyPI (PEP 740) attestations | publish workflow and release-tool tests |

## Evidence commands

Run from a clean checkout of the revision being assessed:

```bash
python -m pip install -e ".[dev,assurance]"
ruff check src tests fuzz tools
mypy src/access_gate
bandit -r src/access_gate
pip-audit --strict --skip-editable
pytest --cov=access_gate --cov-branch --cov-report=term-missing
python -m tools.authorization_benchmark --enforce
python -m tools.verify_reproducible_build
```

Manually dispatched workflows additionally run native fuzz targets, mutation
testing, CodeQL, and OpenSSF Scorecard; nothing runs on a schedule, so record
which of them ran for the assessed commit. Preserve workflow URLs, logs, commit
SHA, runner image, dependency resolution, benchmark JSON, mutation results,
release checksums, SBOM, and PyPI provenance as the assessment evidence bundle.

Mutation results are review input, not passing evidence yet. `mutmut` 3 does
not mutate decorated classes, so every `@dataclass` policy, ABAC condition node,
request/decision type and `DjangoAuthorizer` is outside its scope; their
behavior is pinned by targeted negative tests instead. For the remaining
functions the run still reports untriaged surviving mutants, so
`tools.check_mutation_results` fails until they are killed or reviewed.

## Manual evidence still required

- Independent architecture, code, abuse-case, and cryptographic integration review.
- Repository branch protection, two-person review, environment protection and
  maintainer-access evidence from GitHub settings.
- Key generation, custody, rotation, compromise and rollback procedures.
- Host application authorization coverage and end-to-end negative tests.
- Incident exercises, vulnerability response records, penetration testing, and
  any authority-specific accreditation artifacts.
