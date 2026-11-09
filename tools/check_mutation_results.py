"""Fail the mutation job unless every non-killed mutant is a reviewed survivor.

``tools/reviewed-survivors.toml`` lists the non-killed mutants the owner has
reviewed and accepted, each with the reason it is acceptable (typically an
equivalent mutant) and the SHA-256 of its diff. The digest pins an entry to the
reviewed mutation: when the function or the mutation changes, the entry stops
matching and the mutant needs a fresh review.

Print a new entry for review with ``python -m tools.check_mutation_results
--entry <mutant name>``; the owner adds it once the reason is written.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

REVIEWED_SURVIVORS = Path(__file__).with_name("reviewed-survivors.toml")
# A mutant that was never run, or whose run was interrupted, has no outcome to
# review, so no entry can accept it.
_UNREVIEWABLE_STATUSES = frozenset({"not checked", "check was interrupted by user"})
_ENTRY_KEYS = frozenset({"mutant", "status", "diff_sha256", "reason"})
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ReviewedSurvivor:
    mutant: str
    status: str
    diff_sha256: str
    reason: str


def parse_results(output: str) -> dict[str, str]:
    """Map each mutant listed by ``mutmut results`` to its status.

    Mutmut 3 lists only non-killed mutants, one ``    <name>: <status>`` line
    each. Any other line is refused rather than skipped.
    """

    results: dict[str, str] = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        name, separator, status = line.strip().rpartition(": ")
        if not separator or not name or " " in name or not status:
            raise ValueError(f"Unrecognised mutmut results line: {line!r}")
        results[name] = status
    return results


def diff_fingerprint(show_output: str) -> str:
    """Hash the diff ``mutmut show`` prints, from its first hunk on.

    The status line and the ``---``/``+++`` path headers before the first hunk
    are left out, so the digest names the mutation itself on every platform.
    Hunk line numbers count from the start of the mutated function, so edits
    elsewhere in the module keep it stable.
    """

    lines = show_output.splitlines()
    start = next((index for index, line in enumerate(lines) if line.startswith("@@")), None)
    if start is None:
        raise ValueError("mutmut show printed no diff.")
    diff = "\n".join(line.rstrip() for line in lines[start:]).strip("\n")
    return hashlib.sha256(diff.encode("utf-8")).hexdigest()


def load_reviewed(path: Path = REVIEWED_SURVIVORS) -> dict[str, ReviewedSurvivor]:
    """Load and validate the reviewed survivors, keyed by mutant name."""

    with path.open("rb") as handle:
        document = tomllib.load(handle)
    unknown = set(document) - {"survivor"}
    if unknown:
        raise ValueError(f"{path.name} has unknown tables: {', '.join(sorted(unknown))}")
    entries = document.get("survivor", [])
    if not isinstance(entries, list):
        raise ValueError(f"{path.name} must list survivors as [[survivor]] tables.")
    reviewed: dict[str, ReviewedSurvivor] = {}
    for index, entry in enumerate(entries, start=1):
        label = f"{path.name} survivor {index}"
        if not isinstance(entry, Mapping) or set(entry) != _ENTRY_KEYS:
            raise ValueError(f"{label} must have exactly: {', '.join(sorted(_ENTRY_KEYS))}")
        if not all(isinstance(entry[key], str) for key in _ENTRY_KEYS):
            raise ValueError(f"{label} values must be strings.")
        survivor = ReviewedSurvivor(
            mutant=entry["mutant"].strip(),
            status=entry["status"].strip(),
            diff_sha256=entry["diff_sha256"].strip(),
            reason=" ".join(entry["reason"].split()),
        )
        if not survivor.mutant or " " in survivor.mutant:
            raise ValueError(f"{label} needs a mutant name as mutmut prints it.")
        if not survivor.status or survivor.status in _UNREVIEWABLE_STATUSES:
            raise ValueError(f"{label} has no reviewable status: {survivor.status!r}")
        if _DIGEST.match(survivor.diff_sha256) is None:
            raise ValueError(f"{label} needs a lowercase SHA-256 diff_sha256.")
        if len(survivor.reason) < 20:
            raise ValueError(f"{label} needs a reason explaining why it is acceptable.")
        if survivor.mutant in reviewed:
            raise ValueError(f"{label} repeats {survivor.mutant}.")
        reviewed[survivor.mutant] = survivor
    return reviewed


@dataclass(frozen=True)
class Report:
    accepted: tuple[ReviewedSurvivor, ...]
    unreviewed: tuple[str, ...]
    stale: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.unreviewed


def review(
    results: Mapping[str, str],
    reviewed: Mapping[str, ReviewedSurvivor],
    show: Callable[[str], str],
) -> Report:
    """Accept a non-killed mutant only when an entry matches its status and diff."""

    accepted: list[ReviewedSurvivor] = []
    unreviewed: list[str] = []
    for mutant, status in sorted(results.items()):
        entry = reviewed.get(mutant)
        if entry is None:
            unreviewed.append(f"{mutant}: {status} (not reviewed)")
        elif entry.status != status:
            unreviewed.append(f"{mutant}: {status} (reviewed as {entry.status})")
        elif diff_fingerprint(show(mutant)) != entry.diff_sha256:
            unreviewed.append(f"{mutant}: {status} (diff changed since review)")
        else:
            accepted.append(entry)
    stale = tuple(sorted(set(reviewed) - set(results)))
    return Report(tuple(accepted), tuple(unreviewed), stale)


def _mutmut(*arguments: str) -> str:
    result = subprocess.run(
        ["mutmut", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"mutmut {' '.join(arguments)} failed with exit code {result.returncode}:\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout


def _entry(mutant: str) -> str:
    results = parse_results(_mutmut("results"))
    if mutant not in results:
        raise SystemExit(f"{mutant} is not a non-killed mutant in the last run.")
    return "\n".join(
        [
            "[[survivor]]",
            f'mutant = "{mutant}"',
            f'status = "{results[mutant]}"',
            f'diff_sha256 = "{diff_fingerprint(_mutmut("show", mutant))}"',
            'reason = ""',
        ]
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--entry",
        metavar="MUTANT",
        help="print a reviewed-survivors entry for MUTANT instead of checking",
    )
    args = parser.parse_args(argv)
    if args.entry:
        print(_entry(args.entry))
        return

    reviewed = load_reviewed(REVIEWED_SURVIVORS)
    report = review(parse_results(_mutmut("results")), reviewed, lambda name: _mutmut("show", name))
    for entry in report.accepted:
        print(f"Reviewed survivor {entry.mutant} ({entry.status}): {entry.reason}")
    for mutant in report.stale:
        print(f"Note: reviewed survivor {mutant} no longer survives; remove its entry.")
    for line in report.unreviewed:
        print(f"Unreviewed mutant {line}")
    if not report.passed:
        raise SystemExit(
            "Mutation assurance failed: review the mutants above, then kill them with a "
            "test or record them in tools/reviewed-survivors.toml with a reason."
        )


if __name__ == "__main__":
    main()
