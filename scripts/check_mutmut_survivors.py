#!/usr/bin/env python3
"""Fail a mutmut run that left an unaccepted mutant undetected.

``mutmut run`` (3.8.0, pinned in uv.lock) exits 0 however many mutants
survive: it only exits non-zero when the stats or clean run itself
fails. Without this check the nightly mutation workflow is green no
matter what it finds. This script reads the full status listing and
fails on any of:

- a mutant that went undetected (survived, had no covering tests, or
  ended in a status this script does not recognize, so a mutmut
  upgrade that adds one fails closed) and is not in the allowlist;
- an allowlist entry that is no longer undetected, so the list cannot
  quietly accumulate entries for mutants a later test kills, or whose
  number shifted because the function's source changed (mutant numbers
  are positional, so an edit to an allowlisted function usually
  renumbers its mutants and the entry has to be re-triaged anyway);
- a file in pyproject.toml's ``[tool.mutmut] only_mutate`` with no
  checked mutant at all, so a run that silently checked nothing cannot
  pass.

Usage, from the repository root after a ``mutmut run``::

    uv run --frozen mutmut results --all true > mutmut-results.txt
    python3 scripts/check_mutmut_survivors.py mutmut-results.txt

The allowlist (``scripts/mutmut_survivors.txt`` by default) holds one
mutant name per line; ``#`` starts a comment. Every entry needs a
comment saying why that mutant is equivalent or out of reach: the file
is the triage record, not a mute button.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ALLOWLIST = ROOT / "scripts" / "mutmut_survivors.txt"
DEFAULT_PYPROJECT = ROOT / "pyproject.toml"

#: A test failed or hung, or the mutant crashed the interpreter or was
#: rejected by the type checker: in every case the change was noticed.
DETECTED = frozenset({"killed", "timeout", "segfault", "caught by type check"})
#: Outside this run's filters, or skipped by mutmut itself.
UNCHECKED = frozenset({"not checked", "skipped"})

_LINE = re.compile(r"^\s*(?P<name>\S+): (?P<status>.+?)\s*$")


def parse_results(lines: Iterable[str]) -> dict[str, str]:
    """Map each mutant name to its status in ``mutmut results`` output."""
    statuses: dict[str, str] = {}
    for line in lines:
        match = _LINE.match(line)
        if match:
            statuses[match["name"]] = match["status"]
    return statuses


def parse_allowlist(lines: Iterable[str]) -> set[str]:
    """The mutant names in an allowlist, ignoring comments and blanks."""
    names: set[str] = set()
    for line in lines:
        entry = line.split("#", 1)[0].strip()
        if entry:
            names.add(entry)
    return names


def mutated_modules(pyproject: str) -> list[str]:
    """Dotted module names of the files ``only_mutate`` scopes to."""
    paths = tomllib.loads(pyproject)["tool"]["mutmut"]["only_mutate"]
    modules = []
    for path in paths:
        relative = Path(path).relative_to("src").with_suffix("")
        modules.append(".".join(relative.parts))
    return modules


def check(
    statuses: dict[str, str], allowlist: set[str], modules: list[str]
) -> list[str]:
    """Every reason the run should fail; empty when it passes."""
    if not statuses:
        return ["no mutant statuses found -- was `mutmut results` empty?"]

    undetected = {
        name
        for name, status in statuses.items()
        if status not in DETECTED and status not in UNCHECKED
    }
    problems = [
        f"undetected mutant: {name} ({statuses[name]})"
        for name in sorted(undetected - allowlist)
    ]
    problems += [
        f"allowlisted mutant is no longer undetected: {name} "
        f"({statuses.get(name, 'absent from this run')}) -- remove or "
        f"re-triage its entry"
        for name in sorted(allowlist - undetected)
    ]
    for module in modules:
        checked = any(
            name.startswith(f"{module}.") and status not in UNCHECKED
            for name, status in statuses.items()
        )
        if not checked:
            problems.append(
                f"no mutant of {module} was checked -- the run's filters "
                f"no longer reach a file only_mutate lists"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "results", type=Path, help="`mutmut results --all true` output"
    )
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--pyproject", type=Path, default=DEFAULT_PYPROJECT)
    args = parser.parse_args(argv)

    statuses = parse_results(
        args.results.read_text(encoding="utf-8").splitlines()
    )
    allowlist = parse_allowlist(
        args.allowlist.read_text(encoding="utf-8").splitlines()
    )
    modules = mutated_modules(args.pyproject.read_text(encoding="utf-8"))
    problems = check(statuses, allowlist, modules)

    checked = sum(status not in UNCHECKED for status in statuses.values())
    print(
        f"{checked} mutants checked, {len(allowlist)} accepted survivors "
        f"allowlisted"
    )
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
