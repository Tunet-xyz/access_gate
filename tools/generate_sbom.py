"""Generate a deterministic SPDX 2.3 SBOM for AccessGate release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha1(path: Path) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_revision(root: Path) -> str:
    configured = os.environ.get("GITHUB_SHA")
    if configured:
        return configured
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _created_at() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    timestamp = int(epoch) if epoch is not None else 0
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_sbom(root: Path, dist: Path) -> dict[str, object]:
    """Describe the package and exact wheel/sdist bytes without resolving optional extras."""

    root = root.resolve()
    dist = dist.resolve()
    with (root / "pyproject.toml").open("rb") as handle:
        project = cast(dict[str, object], tomllib.load(handle)["project"])
    name = str(project["name"])
    version = str(project["version"])
    revision = _source_revision(root)
    artifacts = sorted(path for path in dist.iterdir() if path.suffix in {".whl", ".gz"})
    if not artifacts:
        raise ValueError("No wheel or source distribution artifacts were found.")

    files: list[dict[str, object]] = []
    file_sha1_values: list[str] = []
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-AccessGate",
        }
    ]
    for index, artifact in enumerate(artifacts, start=1):
        file_id = f"SPDXRef-Artifact-{index}"
        sha1 = _sha1(artifact)
        file_sha1_values.append(sha1)
        files.append(
            {
                "SPDXID": file_id,
                "fileName": artifact.name,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": _sha256(artifact)},
                    {"algorithm": "SHA1", "checksumValue": sha1},
                ],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-AccessGate",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-{version}",
        "documentNamespace": (
            f"https://github.com/Tunet-xyz/access_gate/sbom/{version}/{revision}"
        ),
        "creationInfo": {
            "created": _created_at(),
            "creators": ["Tool: access-gate-sbom/1"],
            "licenseListVersion": "3.27",
        },
        "documentDescribes": ["SPDXRef-Package-AccessGate"],
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-AccessGate",
                "name": name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "packageVerificationCode": {
                    "packageVerificationCodeValue": hashlib.sha1(
                        "".join(sorted(file_sha1_values)).encode("ascii"),
                        usedforsecurity=False,
                    ).hexdigest()
                },
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "licenseInfoFromFiles": ["NOASSERTION"],
                "copyrightText": "NOASSERTION",
                "supplier": "Organization: Tunet Ltd",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{name.lower()}@{version}",
                    },
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": "vcs",
                        "referenceLocator": (
                            "git+https://github.com/Tunet-xyz/access_gate@" + revision
                        ),
                    },
                ],
            }
        ],
        "files": files,
        "relationships": relationships,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, default=Path("dist/accessgate.spdx.json"))
    args = parser.parse_args()
    sbom = generate_sbom(args.root, args.dist)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(args.output)


if __name__ == "__main__":
    main()
