"""Build twice from the same revision and compare artifact digests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
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


def verify_reproducible_build(root: Path, outdir: Path | None = None) -> dict[str, object]:
    """Build twice; when ``outdir`` is given, copy the first verified build there."""

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
                # Wheel file modes follow the build process umask; pin it so the
                # runner's or a developer's setting cannot change release bytes.
                umask=0o022 if os.name == "posix" else -1,
            )
            for sdist in output.glob("*.tar.gz"):
                normalize_sdist(sdist, int(environment["SOURCE_DATE_EPOCH"]))
            builds.append({path.name: _sha256(path) for path in sorted(output.iterdir())})
        if outdir is not None and builds[0] == builds[1]:
            outdir.mkdir(parents=True, exist_ok=True)
            for path in sorted((temporary_root / "build-1").iterdir()):
                shutil.copy2(path, outdir / path.name)
    return {
        "schema_version": "access_gate.reproducible-build.v1",
        "source_date_epoch": environment["SOURCE_DATE_EPOCH"],
        "reproducible": builds[0] == builds[1],
        "first": builds[0],
        "second": builds[1],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--outdir",
        type=Path,
        help="copy the verified first build here so the released bytes are the verified bytes",
    )
    args = parser.parse_args()
    result = verify_reproducible_build(Path.cwd(), args.outdir)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["reproducible"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
