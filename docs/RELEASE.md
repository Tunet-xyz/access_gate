# Release procedure

Follow the shared [versioning policy](../VERSIONING.md). The GitHub Actions
workflows are manual-only: only the owner (`@bezu-1`) starts, reruns, or
re-enables them, and only the owner approves the protected `pypi` environment.
Agents run the equivalent checks locally and never dispatch, rerun, re-enable,
or approve a workflow. Pull requests, issues, comments, and mentions never
start one.

## 1. Prepare

1. Confirm one release identity: `version` in `pyproject.toml`,
   `access_gate.__version__`, `server.version` in both copies of the MCP
   contract (`mcp/agent-contract.json` and
   `src/access_gate/mcp/agent-contract.json`), the dated `CHANGELOG.md` entry,
   and the supported-versions table in `SECURITY.md`.
2. Review the compatibility impact, migration notes, documentation, the [threat
   model](THREAT_MODEL.md) and [audit scope](AUDIT_SCOPE.md), open
   vulnerability reports, and any policy-format migration.

## 2. Verify

Run the evidence commands from a clean checkout of the release commit (the
[security assurance case](SECURITY_ASSURANCE.md#evidence-commands) adds the
dependency audit):

```bash
python -m pip install -e ".[dev,assurance]"
ruff check src tests fuzz tools
mypy src/access_gate
bandit -r src/access_gate
pytest --cov=access_gate --cov-branch --cov-report=term-missing
python -m tools.authorization_benchmark --enforce
python -m tools.verify_reproducible_build
```

The owner runs the manual test, security, assurance, fuzz, CodeQL, and
Scorecard workflows on the release commit. The mutation job fails while any
mutant survives; record the reviewed survivors as accepted residual risk.
Record any check you could not run.

## 3. Build

```bash
python -m pip install --require-hashes -r requirements/build.txt
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
python -m build --no-isolation
python -m twine check dist/*
```

The publish workflow repeats this with `python -m
tools.verify_reproducible_build`, which builds twice and rejects differing
artifacts, then validates the metadata and writes a validated SPDX SBOM and
`SHA256SUMS`. Smoke-test the exact wheel in a clean environment.

## 4. Publish

1. Commit and push the verified source under the owner's authorization, then
   create an annotated `v<version>` tag on that exact commit. Only repository
   administrators can create `v*` tags, and nobody can move or delete one.
2. The owner starts `publish.yaml` from `main` or that tag; it stops on any
   other ref, including a tag that does not match the package version. Dispatch
   from the tag for a release. The workflow verifies the source and builds the
   evidence above. On a tag run it attaches the wheel, sdist, SBOM, and
   checksums to the GitHub Release, which must already exist or the upload
   fails and blocks publication; a run from `main` attaches nothing.
3. The upload job runs in the `pypi` environment, which only `main` and `v*`
   tags may use and which needs the owner's approval; administrators cannot
   bypass it, and agents cannot give that approval. PyPI Trusted Publishing
   gives the job a short-lived OIDC token, so no long-lived PyPI token exists.
   The trusted publisher must name `Tunet-xyz/access_gate`, `publish.yaml`, and
   the `pypi` environment; otherwise a workflow edited on another branch could
   publish.

Do not publish when a check was skipped without a recorded reason, evidence is
missing, the checkout is dirty, the tag and version disagree, or a security
finding is unresolved. A rerun must start from the same commit or from a new,
reviewed release candidate.

## 5. After publication

Verify the PyPI files against `SHA256SUMS` and their PEP 740 provenance with
`pypi-attestations verify pypi --repository
https://github.com/Tunet-xyz/access_gate pypi:<file name>`. Archive the commit,
workflow URLs and logs, artifacts, checksums, SBOM, PyPI provenance, approvals,
tool reports, and accepted residual risks. A prepared or tagged version is not
a release until it is on PyPI.

Then update anything that described the publication as pending, such as the
changelog heading or the README's release status.

Never put PyPI credentials, agent tokens, or production policies and identity
data in release artifacts or workflow logs. Never move a release tag, overwrite
PyPI files, or reuse a published version; fix a bad release with a new version.
