from __future__ import annotations

import os
from pathlib import Path

import pytest

mypy_api = pytest.importorskip("mypy.api")

ROOT = Path(__file__).resolve().parents[1]


def test_built_in_policies_type_check_as_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MYPYPATH", str(ROOT / "src"))
    stdout, stderr, status = mypy_api.run(
        [
            "--config-file",
            str(ROOT / "pyproject.toml"),
            "--no-incremental",
            "--cache-dir",
            os.devnull,
            str(ROOT / "tests" / "typecheck" / "policy_protocol.py"),
            str(ROOT / "tools" / "authorization_benchmark.py"),
        ]
    )
    assert status == 0, stdout + stderr
