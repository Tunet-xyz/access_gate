"""Fail CI when mutmut reports a non-killed mutant."""

from __future__ import annotations

import subprocess


def main() -> None:
    result = subprocess.run(
        ["mutmut", "results"],
        check=False,
        capture_output=True,
        text=True,
    )
    output = result.stdout + result.stderr
    print(output, end="")
    # Mutmut 3 suppresses killed mutants by default. Any result text therefore
    # represents a survivor, timeout, skipped/no-test mutant, crash, or another
    # non-killed state and must block the assurance gate.
    if result.returncode != 0 or output.strip():
        raise SystemExit("Mutation assurance failed: non-killed mutants require review.")


if __name__ == "__main__":
    main()
