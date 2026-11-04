"""Tests that no tracked Python file names an unknown encoding where
CodeQL's Python extractor looks for one.

The extractor (``encoding_from_source`` in
``semmle/python/parser/tokenizer.py``) matches ``ENCODING_RE`` below
against the raw bytes of a file's first and second lines, whether or
not the match sits in a comment, and takes the captured name as the
file's source encoding.
"""

import codecs
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

ENCODING_RE = re.compile(rb".*coding[:=]\s*([-\w.]+).*")


def unknown_encodings(lines: list[bytes]) -> list[tuple[int, str]]:
    """The 1-based line number and name of each match in ``lines``
    whose captured name is not a codec ``codecs.lookup`` knows."""
    found = []
    for number, line in enumerate(lines, start=1):
        match = ENCODING_RE.match(line)
        if match is None:
            continue
        name = match.group(1).decode("ascii")
        try:
            codecs.lookup(name)
        except LookupError:
            found.append((number, name))
    return found


def first_two_lines(path: Path) -> list[bytes]:
    """The first two lines of ``path``, as raw bytes."""
    with path.open("rb") as handle:
        return [handle.readline(), handle.readline()]


def tracked_python_files() -> list[str]:
    """The repository-relative ``*.py`` paths ``git ls-files`` lists."""
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [p for p in result.stdout.decode("utf-8").split("\0") if p]


class TestUnknownEncodings:
    @pytest.mark.parametrize(
        ("lines", "expected"),
        [
            ([b'"""decoding: fields"""\n'], [(1, "fields")]),
            ([b"\n", b'"""GRE decoding: the header"""\n'], [(2, "the")]),
            ([b"# -*- coding: utf-8 -*-\n"], []),
            ([b"#!/usr/bin/env python3\n", b"# coding=latin-1\n"], []),
            ([b'"""decoding the"""\n'], []),
            ([b"", b""], []),
        ],
    )
    def test_matches(
        self, lines: list[bytes], expected: list[tuple[int, str]]
    ) -> None:
        assert unknown_encodings(lines) == expected

    def test_reads_only_the_first_two_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "a.py"
        path.write_bytes(b"x = 1\ny = 2\n# coding: nonsense\n")
        assert unknown_encodings(first_two_lines(path)) == []


def test_no_tracked_python_file_names_an_unknown_encoding() -> None:
    """No tracked Python file names an unknown encoding where CodeQL's
    Python extractor looks for one."""
    paths = tracked_python_files()
    # Guards against passing vacuously on an empty listing.
    assert "tests/test_encoding_cookies.py" in paths
    failures = [
        f"{path}:{number}: {name!r}"
        for path in paths
        if (ROOT / path).is_file() and not (ROOT / path).is_symlink()
        for number, name in unknown_encodings(first_two_lines(ROOT / path))
    ]
    assert not failures, (
        "these lines match CodeQL's encoding pattern with a name that "
        "is not a codec, so its extractor skips the file; reword them: "
        f"{failures}"
    )
