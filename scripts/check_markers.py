#!/usr/bin/env python3
"""Fail on any work-marker word in the repository's tracked text.

    python3 scripts/check_markers.py [--root PATH]

The four marker words are the ones :data:`WORDS` spells. Work still to
do is filed as an issue, or not done, so every marker in the tree is a
finding, whatever follows it.

Where a marker is matched:

- Everywhere, the four words in capitals as whole words.
- In a Python file's ``#`` comment tokens, and in the comment text of a
  shell, YAML, TOML, ``.cfg`` or ``.flake8`` file (a line that starts
  with ``#``, or what follows `` #`` on a line), also in any case and
  with a plural ``s`` or an ``_suffix``.
- In Markdown, prose only: the text of inline code spans is not
  scanned, and matching stays case-sensitive.

The scan covers the files ``git ls-files`` lists under the repository
root, minus files that hold a NUL byte (binary files) and the paths in
:data:`EXCLUDED_FILES` and :data:`EXCLUDED_DIRS`. Other files are read
as UTF-8 with undecodable bytes kept as surrogate escapes, so a Latin-1
file is still scanned.

Exit status: 0 when nothing is found, 1 on findings, 2 on a usage
error. The check runs offline.

Standard library only, so the runner's own ``python3`` runs it.
"""

from __future__ import annotations

import argparse
import io
import re
import subprocess
import sys
import tokenize
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

#: The marker words, built by concatenation so this file holds none.
WORDS = ("TO" + "DO", "FIX" + "ME", "X" + "XX", "HA" + "CK")
_ALTERNATION = "|".join(WORDS)
#: The words in capitals as whole words: the match everywhere.
PLAIN = re.compile(rf"\b({_ALTERNATION})\b")
#: Any case, with an ``s`` or ``_suffix``: the match in comments.
IN_COMMENT = re.compile(rf"(?i)\b({_ALTERNATION})(?:s|_\w*)?\b")
#: An inline Markdown code span: a backtick run, its text, and the same
#: run closing it, on one line.
CODE_SPAN = re.compile(r"(`+)(.+?)\1")
#: The surrogate escapes ``errors="surrogateescape"`` decodes bytes to.
SURROGATE = re.compile("[\udc80-\udcff]")

#: Suffixes of the files whose ``#`` comment text is matched with
#: :data:`IN_COMMENT`, besides Python's comment tokens.
COMMENT_SUFFIXES = (".sh", ".yml", ".yaml", ".toml", ".cfg", ".flake8")

#: Repository-relative files the scan skips: the CHANGELOG names the
#: markers where it records the rule.
EXCLUDED_FILES = frozenset({"CHANGELOG.md"})
#: Repository-relative directories, with their trailing slash, whose
#: files the scan skips.
EXCLUDED_DIRS: tuple[str, ...] = ()

EXIT_FINDINGS = 1


@dataclass(frozen=True)
class Finding:
    """One marker, at a 1-based line and column."""

    path: str
    line: int
    column: int
    word: str

    def __str__(self) -> str:
        return (
            f"{self.path}:{self.line}:{self.column}: {self.word} marker; "
            "file an issue for the work instead"
        )


def is_excluded(path: str) -> bool:
    """Whether the scan skips the repository-relative ``path``."""
    return path in EXCLUDED_FILES or (
        bool(EXCLUDED_DIRS) and path.startswith(EXCLUDED_DIRS)
    )


def read_text(path: Path) -> str | None:
    """The file's text, or ``None`` for a file holding a NUL byte."""
    data = path.read_bytes()
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="surrogateescape")


def blank_code_spans(line: str) -> str:
    """``line`` with each inline code span's text replaced by spaces.

    Columns are unchanged, so a finding's position stays exact.
    """
    return CODE_SPAN.sub(lambda m: " " * len(m.group(0)), line)


def python_comment_spans(text: str) -> list[tuple[int, int]] | None:
    """Each ``#`` comment's (1-based line, 0-based start column).

    ``None`` when ``text`` does not tokenize as Python.
    """
    spans: list[tuple[int, int]] = []
    # tokenize cannot encode surrogate escapes; one "?" each keeps every
    # column where it was.
    readline = io.StringIO(SURROGATE.sub("?", text)).readline
    try:
        for token in tokenize.generate_tokens(readline):
            if token.type == tokenize.COMMENT:
                spans.append(token.start)
    except (tokenize.TokenError, SyntaxError):
        return None
    return spans


def line_comment_start(line: str) -> int | None:
    """Where a ``#`` comment starts on a shell/YAML/TOML/cfg line."""
    if line.lstrip().startswith("#"):
        return line.index("#")
    found = line.find(" #")
    return None if found < 0 else found + 1


def comment_starts(path: str, text: str) -> dict[int, int]:
    """Each line's comment start column, for the file types that have one.

    A Python file that does not tokenize falls back to its lines that
    start with ``#``.
    """
    lines = text.splitlines()
    if path.endswith(".py"):
        spans = python_comment_spans(text)
        if spans is not None:
            return dict(spans)
        return {
            row: line.index("#")
            for row, line in enumerate(lines, start=1)
            if line.lstrip().startswith("#")
        }
    if path.endswith(COMMENT_SUFFIXES):
        starts = {
            row: line_comment_start(line)
            for row, line in enumerate(lines, start=1)
        }
        return {row: col for row, col in starts.items() if col is not None}
    return {}


def scan_text(path: str, text: str) -> list[Finding]:
    """Find every marker in ``text``, the content of the file ``path``.

    :param path: the repository-relative path, which selects the
        Markdown and comment handling and labels the findings
    :param text: the file's content
    """
    comments = comment_starts(path, text)
    findings: list[Finding] = []
    for row, raw in enumerate(text.splitlines(), start=1):
        line = blank_code_spans(raw) if path.endswith(".md") else raw
        found = {m.start(): m.group(1) for m in PLAIN.finditer(line)}
        start = comments.get(row)
        if start is not None:
            for match in IN_COMMENT.finditer(line, start):
                found.setdefault(match.start(), match.group(1))
        findings += [
            Finding(path, row, column + 1, word)
            for column, word in sorted(found.items())
        ]
    return findings


def tracked_files(root: Path) -> list[str]:
    """The repository-relative paths ``git ls-files`` lists under ``root``.

    :raises subprocess.CalledProcessError: if git fails
    """
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [p for p in result.stdout.decode("utf-8").split("\0") if p]


def scan_tree(root: Path, paths: Iterable[str]) -> list[Finding]:
    """Scan each of ``paths``, relative to ``root``, that is not excluded.

    A listed path that is not a regular file (a deleted file, a
    submodule, a symlink) is skipped.
    """
    findings: list[Finding] = []
    for path in paths:
        full = root / path
        if is_excluded(path) or full.is_symlink() or not full.is_file():
            continue
        text = read_text(full)
        if text is not None:
            findings += scan_text(path, text)
    return findings


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Fail on any work-marker word in tracked text."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: the current directory)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the check and return the exit status.

    :param argv: the arguments, or ``None`` for ``sys.argv[1:]``
    """
    args = parse_args(argv)
    root: Path = args.root
    findings = scan_tree(root, tracked_files(root))
    for finding in findings:
        print(finding)
    if findings:
        print(
            f"check_markers: {len(findings)} finding(s); open work is "
            "filed as an issue, not marked in the tree",
            file=sys.stderr,
        )
        return EXIT_FINDINGS
    print("check_markers: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
