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
from tools import check_mutation_results as mutation
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


# What mutmut 3.7.0 prints for `mutmut show <name>`; the path separator follows the OS.
_SHOW = """# access_gate.abac.x_ActionAttribute__mutmut_1: survived
--- src/access_gate/abac.py
+++ src/access_gate/abac.py
@@ -1,2 +1,2 @@
 def ActionAttribute(path: str) -> AttributeRef:
-    return AttributeRef(AttributeSource.ACTION, f"attributes.{path}")
+    return AttributeRef(None, f"attributes.{path}")
"""
_REASON = "Equivalent mutant: reviewed and no input can tell it apart."


def _survivors_file(tmp_path: Path, *entries: dict[str, str]) -> Path:
    path = tmp_path / "reviewed-survivors.toml"
    tables = [
        "[[survivor]]\n" + "".join(f"{key} = {value!r}\n" for key, value in entry.items())
        for entry in entries
    ]
    path.write_text("\n".join(tables), encoding="utf-8")
    return path


def _entry(mutant: str = "access_gate.abac.x_ActionAttribute__mutmut_1", **changes: str) -> dict:
    entry = {
        "mutant": mutant,
        "status": "survived",
        "diff_sha256": mutation.diff_fingerprint(_SHOW),
        "reason": _REASON,
    }
    entry.update(changes)
    return entry


def test_mutation_results_parse_every_listed_status() -> None:
    output = (
        "    access_gate.abac.x_ActionAttribute__mutmut_1: survived\n"
        "\n"
        "    access_gate.engine.xǁAuthorizationEngineǁdecide__mutmut_3: no tests\n"
        "    access_gate.types.x__freeze__mutmut_2: check was interrupted by user\n"
    )

    assert mutation.parse_results(output) == {
        "access_gate.abac.x_ActionAttribute__mutmut_1": "survived",
        "access_gate.engine.xǁAuthorizationEngineǁdecide__mutmut_3": "no tests",
        "access_gate.types.x__freeze__mutmut_2": "check was interrupted by user",
    }
    for line in ("Generating mutants", "    name with spaces: survived", "    : survived"):
        with pytest.raises(ValueError, match="Unrecognised"):
            mutation.parse_results(line)


def test_mutation_fingerprint_names_the_mutation_on_every_platform() -> None:
    windows = _SHOW.replace("src/access_gate/abac.py", r"src\access_gate\abac.py")
    other_status = _SHOW.replace(": survived", ": timeout")
    changed = _SHOW.replace("AttributeRef(None,", "AttributeRef(AttributeSource.SUBJECT,")

    digest = mutation.diff_fingerprint(_SHOW)

    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert mutation.diff_fingerprint(windows) == digest
    assert mutation.diff_fingerprint(other_status) == digest
    assert mutation.diff_fingerprint(changed) != digest
    with pytest.raises(ValueError, match="no diff"):
        mutation.diff_fingerprint("# access_gate.abac.x_f__mutmut_1: survived\n")


def test_only_a_matching_reviewed_entry_accepts_a_mutant(tmp_path: Path) -> None:
    reviewed = mutation.load_reviewed(
        _survivors_file(
            tmp_path,
            _entry(),
            _entry("access_gate.abac.x_retyped__mutmut_1", status="timeout"),
            _entry("access_gate.abac.x_rediffed__mutmut_1", diff_sha256="0" * 64),
            _entry("access_gate.abac.x_killed_now__mutmut_1"),
        )
    )
    results = {
        "access_gate.abac.x_ActionAttribute__mutmut_1": "survived",
        "access_gate.abac.x_retyped__mutmut_1": "survived",
        "access_gate.abac.x_rediffed__mutmut_1": "survived",
        "access_gate.abac.x_unlisted__mutmut_1": "no tests",
    }

    report = mutation.review(results, reviewed, lambda name: _SHOW)

    assert not report.passed
    assert [entry.mutant for entry in report.accepted] == [
        "access_gate.abac.x_ActionAttribute__mutmut_1"
    ]
    assert report.unreviewed == (
        "access_gate.abac.x_rediffed__mutmut_1: survived (diff changed since review)",
        "access_gate.abac.x_retyped__mutmut_1: survived (reviewed as timeout)",
        "access_gate.abac.x_unlisted__mutmut_1: no tests (not reviewed)",
    )
    assert report.stale == ("access_gate.abac.x_killed_now__mutmut_1",)
    assert mutation.review({}, reviewed, lambda name: _SHOW).passed


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ([_entry(reason="")], "needs a reason"),
        ([_entry(reason="Looks fine.")], "needs a reason"),
        ([_entry(diff_sha256="ABC")], "SHA-256"),
        ([_entry(diff_sha256="A" * 64)], "SHA-256"),
        ([_entry(status="not checked")], "no reviewable status"),
        ([_entry(status="check was interrupted by user")], "no reviewable status"),
        ([_entry(mutant="two words")], "mutant name"),
        ([_entry(), _entry()], "repeats"),
        ([{**_entry(), "approved": "yes"}], "exactly"),
        ([{key: value for key, value in _entry().items() if key != "reason"}], "exactly"),
    ],
)
def test_reviewed_survivor_entries_are_validated(
    tmp_path: Path,
    entries: list[dict[str, str]],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        mutation.load_reviewed(_survivors_file(tmp_path, *entries))


def test_reviewed_survivors_file_rejects_other_tables(tmp_path: Path) -> None:
    path = tmp_path / "reviewed-survivors.toml"
    path.write_text('[survivors]\nmutant = "x"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="unknown tables"):
        mutation.load_reviewed(path)


def test_the_committed_reviewed_survivors_are_valid() -> None:
    reviewed = mutation.load_reviewed()

    assert all(name.startswith("access_gate.") for name in reviewed)


def _fake_mutmut(
    monkeypatch: pytest.MonkeyPatch,
    results: str,
    *,
    returncode: int = 0,
) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        stdout = results if command[1] == "results" else _SHOW
        return subprocess.CompletedProcess(command, returncode, stdout, "")

    monkeypatch.setattr(mutation.subprocess, "run", run)
    return calls


def test_mutation_check_passes_reviewed_survivors_and_blocks_the_rest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(mutation, "REVIEWED_SURVIVORS", _survivors_file(tmp_path, _entry()))
    listed = "    access_gate.abac.x_ActionAttribute__mutmut_1: survived\n"

    calls = _fake_mutmut(monkeypatch, listed)
    mutation.main([])
    assert _REASON in capsys.readouterr().out
    assert calls == [
        ["mutmut", "results"],
        ["mutmut", "show", "access_gate.abac.x_ActionAttribute__mutmut_1"],
    ]

    _fake_mutmut(monkeypatch, listed + "    access_gate.abac.x_other__mutmut_2: survived\n")
    with pytest.raises(SystemExit, match="Mutation assurance failed"):
        mutation.main([])
    assert "x_other__mutmut_2: survived (not reviewed)" in capsys.readouterr().out

    _fake_mutmut(monkeypatch, "", returncode=1)
    with pytest.raises(SystemExit, match="exit code 1"):
        mutation.main([])


def test_mutation_check_prints_an_entry_the_allow_list_accepts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _fake_mutmut(monkeypatch, "    access_gate.abac.x_ActionAttribute__mutmut_1: survived\n")

    mutation.main(["--entry", "access_gate.abac.x_ActionAttribute__mutmut_1"])
    printed = capsys.readouterr().out
    path = tmp_path / "reviewed-survivors.toml"
    path.write_text(printed.replace('reason = ""', f'reason = "{_REASON}"'), encoding="utf-8")

    assert tomllib.loads(path.read_text(encoding="utf-8"))["survivor"][0]["status"] == "survived"
    assert mutation.load_reviewed(path)["access_gate.abac.x_ActionAttribute__mutmut_1"] == (
        mutation.ReviewedSurvivor(
            "access_gate.abac.x_ActionAttribute__mutmut_1",
            "survived",
            mutation.diff_fingerprint(_SHOW),
            _REASON,
        )
    )
    with pytest.raises(SystemExit, match="not a non-killed mutant"):
        mutation.main(["--entry", "access_gate.abac.x_missing__mutmut_9"])


def test_security_policy_lists_the_current_release_line() -> None:
    security = (Path(__file__).resolve().parents[1] / "SECURITY.md").read_text()
    release_line = ".".join(access_gate.__version__.split(".")[:2])

    supported_row = rf"^\| {re.escape(release_line)}\.x .*\| :white_check_mark: \|$"
    assert re.search(supported_row, security, re.M)
