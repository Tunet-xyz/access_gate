# Release procedure

1. Select an immutable reviewed commit on protected `main`; confirm the
   manually dispatched test, security, assurance, CodeQL, fuzz, mutation, and
   Scorecard runs for that commit.
2. Confirm the version and changelog, audit scope, threat model, compatibility
   impact, vulnerability status, and policy-format migration notes.
3. Run the evidence commands in `SECURITY_ASSURANCE.md` from a clean checkout.
4. Create the release through an approved, protected process. The publish
   workflow installs hash-locked build tools, builds twice, rejects differing
   artifacts, normalizes the sdist, validates metadata, and creates an SPDX SBOM
   and checksums. The PyPI upload step publishes PEP 740 attestations for the
   wheel and sdist; no GitHub artifact attestations are generated.
5. Only the environment-protected trusted-publishing job may upload the wheel
   and sdist to PyPI. Long-lived PyPI API tokens are not part of this process.
   The PyPI trusted publisher must name the `pypi` environment, and that
   environment must allow only `main` and `v*` tags; otherwise a workflow edited
   on another branch can publish.
6. Verify the PyPI files against `SHA256SUMS` and verify their PyPI provenance
   with `pypi-attestations verify pypi --repository
   https://github.com/Tunet-xyz/access_gate pypi:<file name>`.
7. Archive the commit, workflow URLs/logs, exact artifacts, checksums, SBOM,
   PyPI provenance, approvals, tool reports, and any accepted residual risks.

Do not publish when a check is bypassed, evidence is missing, the checkout is
dirty, the release tag/version disagree, an unresolved security finding exists,
or the required independent approval is absent. A rerun must start from the same
immutable commit or create a new reviewed release candidate.
