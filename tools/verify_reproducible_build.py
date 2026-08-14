"""Build twice from the same revision and compare artifact digests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from tools.normalize_sdist import normalize_sdist


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_date_epoch(root: Path) -> str:
    configured = os.environ.get("SOURCE_DATE_EPOCH")
    if configured:
        return configured
    result = subprocess.run(
        ["git", "show", "-s", "--format=%ct", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def verify_reproducible_build(root: Path) -> dict[str, object]:
    root = root.resolve()
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = _source_date_epoch(root)
    builds: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="access-gate-repro-") as temporary:
        temporary_root = Path(temporary)
        for index in range(2):
            output = temporary_root / f"build-{index + 1}"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "build",
                    "--no-isolation",
                    "--outdir",
                    str(output),
                ],
                cwd=root,
                check=True,
                env=environment,
                capture_output=True,
                text=True,
            )
            for sdist in output.glob("*.tar.gz"):
                normalize_sdist(sdist, int(environment["SOURCE_DATE_EPOCH"]))
            builds.append({path.name: _sha256(path) for path in sorted(output.iterdir())})
    return {
        "schema_version": "access_gate.reproducible-build.v1",
        "source_date_epoch": environment["SOURCE_DATE_EPOCH"],
        "reproducible": builds[0] == builds[1],
        "first": builds[0],
        "second": builds[1],
    }


def main() -> None:
    result = verify_reproducible_build(Path.cwd())
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["reproducible"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
