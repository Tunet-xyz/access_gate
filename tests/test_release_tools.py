from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

from tools.generate_sbom import generate_sbom
from tools.normalize_sdist import normalize_sdist


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


def _write_sdist(path: Path, *, mtime: int) -> None:
    payload = b"content"
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo("package/file.txt")
        member.size = len(payload)
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
