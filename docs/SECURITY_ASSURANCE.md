# AccessGate security assurance case

This document links AccessGate's security claims to repository evidence.
Passing evidence increases confidence; it is not an independent audit or a
NATO, government, or regulatory certification.

## Claims and evidence

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
python -m pip freeze --exclude-editable > /tmp/accessgate-deps.txt
pip-audit --strict --disable-pip --no-deps -r /tmp/accessgate-deps.txt
pytest --cov=access_gate --cov-branch --cov-report=term-missing
python -m tools.authorization_benchmark --enforce
python -m tools.verify_reproducible_build
```

## Workflow evidence

The GitHub workflows are manual: only the owner starts them, and none runs on
a schedule (Dependabot checks dependencies weekly). Record which of them ran
for the assessed commit.

| Workflow | What it runs |
| --- | --- |
| `tests.yaml` | Ruff, mypy, and pytest with coverage on Python 3.10–3.13, the benchmark, and the Django adapter tests on Django 4.2 in the `minimum-dependencies` job |
| `security.yaml` | Bandit and a strict dependency audit |
| `assurance.yaml` | Property, integrity, release, and benchmark suites, the reproducible-build check, and mutation testing |
| `fuzz.yaml` | Native fuzzing of the policy-JSON and MCP-JSON parsers |
| `codeql.yaml` | CodeQL with the security-extended queries |
| `scorecard.yaml` | OpenSSF Scorecard |
| `publish.yaml` | Verification, a reproducible build with SBOM and checksums, and PyPI publication with PEP 740 attestations |

Keep the workflow URLs and logs, commit SHA, runner image, dependency
resolution, release checksums, SBOM, and PyPI provenance as the evidence
bundle. The benchmark and mutation results appear only in the job logs, so
save them from there.

Mutation results are review input, not passing evidence yet. `mutmut` 3 does
not mutate decorated classes, so every `@dataclass` policy, ABAC condition node,
request/decision type and `DjangoAuthorizer` is outside its scope; their
behavior is pinned by targeted negative tests instead. For the remaining
functions the run still reports surviving mutants. `tools.check_mutation_results`
fails on any mutant that is not killed unless `tools/reviewed-survivors.toml`
records it with a matching status and diff digest and the reason it is
acceptable. The list starts empty, so the job fails until every survivor is
killed or reviewed, and a changed function or mutation needs a fresh review.

## Manual evidence still required

- Independent architecture, code, abuse-case, and cryptographic integration review.
- Repository branch protection, two-person review, environment protection and
  maintainer-access evidence from GitHub settings.
- Key generation, custody, rotation, compromise and rollback procedures.
- Host application authorization coverage and end-to-end negative tests.
- Incident exercises, vulnerability response records, penetration testing, and
  any authority-specific accreditation artifacts.
