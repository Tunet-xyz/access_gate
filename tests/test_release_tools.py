from __future__ import annotations

import hashlib
import io
import os
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

import access_gate
from tools import verify_reproducible_build as reproducible
from tools.generate_sbom import generate_sbom
from tools.normalize_sdist import normalize_sdist

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib


def test_spdx_sbom_binds_exact_release_artifacts(
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    wheel = tmp_path / "accessgate-0.3.0a1-py3-none-any.whl"
    sdist = tmp_path / "accessgate-0.3.0a1.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)  # type: ignore[attr-defined]
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")  # type: ignore[attr-defined]

    sbom = generate_sbom(Path.cwd(), tmp_path)

    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["documentDescribes"] == ["SPDXRef-Package-AccessGate"]
    files = sbom["files"]
    assert isinstance(files, list)
    observed = {
        item["fileName"]: item["checksums"][0]["checksumValue"]  # type: ignore[index]
        for item in files
    }
    assert observed == {
        wheel.name: hashlib.sha256(b"wheel").hexdigest(),
        sdist.name: hashlib.sha256(b"sdist").hexdigest(),
    }


def _write_sdist(path: Path, *, mtime: int, mode: int = 0o644) -> None:
    payload = b"content"
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo("package/file.txt")
        member.size = len(payload)
        member.mode = mode
        member.mtime = mtime
        member.uid = mtime
        member.gid = mtime
        member.uname = "builder"
        member.gname = "builder"
        archive.addfile(member, io.BytesIO(payload))


def test_sdist_normalization_removes_archive_metadata_variance(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _write_sdist(first, mtime=100)
    _write_sdist(second, mtime=200)

    normalize_sdist(first, 1_700_000_000)
    normalize_sdist(second, 1_700_000_000)

    assert first.read_bytes() == second.read_bytes()


def test_sdist_normalization_removes_builder_umask(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _write_sdist(first, mtime=100, mode=0o644)
    _write_sdist(second, mtime=100, mode=0o664)

    normalize_sdist(first, 1_700_000_000)
    normalize_sdist(second, 1_700_000_000)

    assert first.read_bytes() == second.read_bytes()


def test_reproducible_build_pins_umask_and_releases_the_verified_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_build(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["umask"] == (0o022 if os.name == "posix" else -1)
        output = Path(command[command.index("--outdir") + 1])
        output.mkdir(parents=True)
        (output / "accessgate-0-py3-none-any.whl").write_bytes(b"wheel")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    monkeypatch.setattr(reproducible.subprocess, "run", fake_build)
    release = tmp_path / "packages"

    result = reproducible.verify_reproducible_build(tmp_path, release)

    assert result["reproducible"] is True
    assert result["first"] == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in release.iterdir()
    }


def test_mutation_testing_copies_every_directory_the_suite_needs() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with pyproject.open("rb") as handle:
        mutmut = tomllib.load(handle)["tool"]["mutmut"]

    assert {"tools/", "fuzz/", "mcp/"} <= set(mutmut.get("also_copy", ()))


def test_security_policy_lists_the_current_release_line() -> None:
    security = (Path(__file__).resolve().parents[1] / "SECURITY.md").read_text()
    release_line = ".".join(access_gate.__version__.split(".")[:2])

    supported_row = rf"^\| {re.escape(release_line)}\.x .*\| :white_check_mark: \|$"
    assert re.search(supported_row, security, re.M)
