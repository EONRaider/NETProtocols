#!/usr/bin/env python3
"""Fail on a TODO, FIXME, XXX or HACK marker that is not an issue-tracked TODO.

    python3 scripts/check_todos.py [--closing-issues N [N ...]]
                                   [--closing-issues-from-event PATH]
                                   [--check-open] [--repo OWNER/NAME]

The only accepted marker is ``TODO(#N): <text>``, with ``N`` a positive
issue number and ``<text>`` non-empty. Every other occurrence of the
words TODO, FIXME, XXX or HACK, matched case-sensitively as whole words,
is a finding: a bare marker, a TODO without an issue number, a TODO
with an empty text. In a Python file an accepted TODO must sit in a
``#`` comment; one inside a string or docstring is a finding.

The scan covers the files ``git ls-files`` lists under the repository
root, minus:

- files that are not UTF-8 text, or hold a NUL byte (binary files);
- every path under ``tests/fixtures/`` (captured and generated data);
- ``CHANGELOG.md``, this script, and ``tests/test_check_todos.py``,
  which name the markers as data rather than use them as markers.

In Markdown files, text inside inline code spans (```TODO```) is not
scanned.

Three modes, combinable:

- By default the scan runs offline and fails on any finding.
- ``--closing-issues N [N ...]`` also fails on an accepted
  ``TODO(#N)`` whose issue is in the list: issues a pull request
  closes. ``--closing-issues-from-event PATH`` reads that list from a
  GitHub Actions event payload (``$GITHUB_EVENT_PATH``): the GitHub
  closing keywords (close, closes, closed, fix, fixes, fixed, resolve,
  resolves, resolved; any case, optionally followed by a colon) each
  directly followed by ``#N`` in ``pull_request.body``. A payload with
  no pull request contributes no issues.
- ``--check-open`` queries the GitHub REST API
  (``GET /repos/{owner}/{repo}/issues/{N}``) once per issue the accepted
  TODOs name, and fails on an issue that is closed, does not exist, or
  is a pull request. It authenticates with ``$GITHUB_TOKEN`` when that
  is set, and reads the repository from ``--repo`` or
  ``$GITHUB_REPOSITORY``.

Exit status: 0 when nothing is found, 1 on findings, 2 on a usage
error, and 3 when ``--check-open`` cannot get an answer from the API (a
network error, a rate limit, a server error, an unreadable response).
An API failure never counts as a pass.

Standard library only, so the runner's own ``python3`` runs it.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tokenize
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The marker words, matched case-sensitively as whole words.
MARKER = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")
#: The accepted form, matched at a marker's position.
ALLOWED = re.compile(r"TODO\(#([1-9][0-9]*)\): +(\S.*)?")
#: A GitHub closing keyword directly followed by a same-repository
#: issue reference, as GitHub itself reads a pull request body.
CLOSING = re.compile(
    r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?):?\s+#([1-9][0-9]*)\b",
    re.IGNORECASE,
)
#: An inline Markdown code span: a backtick run, its text, and the same
#: run closing it, on one line.
CODE_SPAN = re.compile(r"(`+)(.+?)\1")

#: Repository-relative files the scan skips.
EXCLUDED_FILES = frozenset(
    {
        "CHANGELOG.md",
        "scripts/check_todos.py",
        "tests/test_check_todos.py",
    }
)
#: Repository-relative directories, with their trailing slash, whose
#: files the scan skips.
EXCLUDED_DIRS = ("tests/fixtures/",)

API_ROOT = "https://api.github.com"
#: Seconds one API request may take before it counts as a failure.
API_TIMEOUT = 30

EXIT_FINDINGS = 1
EXIT_API_FAILURE = 3


@dataclass(frozen=True)
class Finding:
    """One marker that fails the check, at a 1-based line and column."""

    path: str
    line: int
    column: int
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.column}: {self.message}"


@dataclass(frozen=True)
class Todo:
    """One accepted ``TODO(#N): text`` marker and the issue it names."""

    path: str
    line: int
    column: int
    issue: int


class ApiError(Exception):
    """The GitHub API gave no usable answer about an issue."""


def is_excluded(path: str) -> bool:
    """Whether the scan skips the repository-relative ``path``."""
    return path in EXCLUDED_FILES or path.startswith(EXCLUDED_DIRS)


def read_text(path: Path) -> str | None:
    """The file's text, or ``None`` for a binary or non-UTF-8 file."""
    data = path.read_bytes()
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def blank_code_spans(line: str) -> str:
    """``line`` with each inline code span's text replaced by spaces.

    Columns are unchanged, so a finding's position stays exact.
    """
    return CODE_SPAN.sub(lambda m: " " * len(m.group(0)), line)


def python_comment_spans(text: str) -> list[tuple[int, int, int]] | None:
    """Each ``#`` comment's (line, start column, end column), 0-based
    columns, or ``None`` when ``text`` does not tokenize as Python.
    """
    spans: list[tuple[int, int, int]] = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.COMMENT:
                (row, start), (_, end) = token.start, token.end
                spans.append((row, start, end))
    except (tokenize.TokenError, SyntaxError):
        return None
    return spans


def scan_text(path: str, text: str) -> tuple[list[Finding], list[Todo]]:
    """Find every marker in ``text``, the content of the file ``path``.

    :param path: the repository-relative path, which selects the
        Markdown and Python handling and labels the results
    :param text: the file's content
    :returns: the findings, and the accepted TODOs
    """
    findings: list[Finding] = []
    todos: list[Todo] = []
    comments = python_comment_spans(text) if path.endswith(".py") else None
    for row, raw in enumerate(text.splitlines(), start=1):
        line = blank_code_spans(raw) if path.endswith(".md") else raw
        for match in MARKER.finditer(line):
            column = match.start() + 1
            allowed = ALLOWED.match(line, match.start())
            if allowed is None or allowed.group(2) is None:
                findings.append(
                    Finding(path, row, column, _describe(match.group(1)))
                )
                continue
            if comments is not None and not any(
                r == row and s <= match.start() < e for r, s, e in comments
            ):
                findings.append(
                    Finding(
                        path,
                        row,
                        column,
                        "TODO(#N) must be a # comment, not part of a "
                        "string or docstring",
                    )
                )
                continue
            todos.append(Todo(path, row, column, int(allowed.group(1))))
    return findings, todos


def _describe(word: str) -> str:
    """The finding message for a marker ``word`` not in the accepted form."""
    if word == "TODO":
        return "TODO not in the form TODO(#N): <text>"
    return f"{word} is banned; write TODO(#N): <text> for an open issue"


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


def scan_tree(
    root: Path, paths: Iterable[str]
) -> tuple[list[Finding], list[Todo]]:
    """Scan each of ``paths``, relative to ``root``, that is not excluded.

    A listed path that is not a regular file (a deleted file, a
    submodule, a symlink) is skipped.

    :param root: the repository root
    :param paths: repository-relative paths
    :returns: the findings, and the accepted TODOs
    """
    findings: list[Finding] = []
    todos: list[Todo] = []
    for path in paths:
        full = root / path
        if is_excluded(path) or full.is_symlink() or not full.is_file():
            continue
        text = read_text(full)
        if text is None:
            continue
        found, accepted = scan_text(path, text)
        findings += found
        todos += accepted
    return findings, todos


def closing_issues(body: str) -> set[int]:
    """The issue numbers a pull request body closes with a keyword."""
    return {int(number) for number in CLOSING.findall(body)}


def closing_issues_from_event(event_path: Path) -> set[int]:
    """The issues closed by the pull request in a GitHub event payload.

    A payload with no ``pull_request``, or one with a null body, closes
    nothing.

    :raises OSError: if the payload cannot be read
    :raises ValueError: if the payload is not JSON
    """
    event: Any = json.loads(event_path.read_text(encoding="utf-8"))
    pull_request = (
        event.get("pull_request") if isinstance(event, dict) else None
    )
    if not isinstance(pull_request, dict):
        return set()
    body = pull_request.get("body")
    return closing_issues(body) if isinstance(body, str) else set()


def closing_findings(todos: Iterable[Todo], closing: set[int]) -> list[Finding]:
    """A finding for each accepted TODO naming an issue in ``closing``."""
    return [
        Finding(
            todo.path,
            todo.line,
            todo.column,
            f"TODO(#{todo.issue}) names an issue this pull request closes; "
            f"finish the work or drop the TODO",
        )
        for todo in todos
        if todo.issue in closing
    ]


#: Fetches a URL with the given headers and returns the HTTP status and
#: body; raises :class:`urllib.error.URLError` (or its HTTPError
#: subclass) or :class:`OSError` on failure.
Fetch = Callable[[str, dict[str, str]], tuple[int, bytes]]


def urllib_fetch(url: str, headers: dict[str, str]) -> tuple[int, bytes]:
    """GET ``url`` with ``headers`` through :mod:`urllib.request`.

    :raises urllib.error.HTTPError: for a status of 400 or more
    :raises urllib.error.URLError: if the request fails
    :raises OSError: if the connection fails or times out
    """
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=API_TIMEOUT) as response:
        status: int = response.status
        body: bytes = response.read()
    return status, body


def issue_problem(
    repo: str, issue: int, token: str | None, fetch: Fetch = urllib_fetch
) -> str | None:
    """What makes ``issue`` unfit for a TODO, or ``None`` if it is open.

    :param repo: ``owner/name``
    :param issue: the issue number
    :param token: a GitHub token, or ``None`` to query anonymously
    :param fetch: the HTTP GET to use
    :raises ApiError: if the API gives no usable answer
    """
    url = f"{API_ROOT}/repos/{repo}/issues/{issue}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "netprotocols-check-todos",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        status, body = fetch(url, headers)
    except urllib.error.HTTPError as error:
        if error.code in (404, 410):
            return f"issue #{issue} does not exist in {repo}"
        raise ApiError(f"GET {url} returned HTTP {error.code}") from error
    except (urllib.error.URLError, OSError) as error:
        raise ApiError(f"GET {url} failed: {error}") from error
    if status != 200:
        raise ApiError(f"GET {url} returned HTTP {status}")
    try:
        data: Any = json.loads(body)
    except ValueError as error:
        raise ApiError(f"GET {url} returned a body that is not JSON") from error
    if not isinstance(data, dict) or "state" not in data:
        raise ApiError(f"GET {url} returned no issue state")
    if data.get("pull_request") is not None:
        return f"#{issue} is a pull request, not an issue"
    if data["state"] != "open":
        return f"issue #{issue} is {data['state']}"
    return None


def open_findings(
    todos: Sequence[Todo],
    repo: str,
    token: str | None,
    fetch: Fetch = urllib_fetch,
) -> list[Finding]:
    """A finding for each accepted TODO whose issue is not an open issue.

    Each issue is queried once, however many TODOs name it.

    :param todos: the accepted TODOs
    :param repo: ``owner/name``
    :param token: a GitHub token, or ``None`` to query anonymously
    :param fetch: the HTTP GET to use
    :raises ApiError: if the API gives no usable answer for any issue
    """
    problems = {
        issue: issue_problem(repo, issue, token, fetch)
        for issue in sorted({todo.issue for todo in todos})
    }
    return [
        Finding(todo.path, todo.line, todo.column, problem)
        for todo in todos
        if (problem := problems[todo.issue]) is not None
    ]


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Fail on TODO/FIXME/XXX/HACK markers that are not "
        "TODO(#N): <text>."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: the current directory)",
    )
    parser.add_argument(
        "--closing-issues",
        type=int,
        nargs="+",
        default=[],
        metavar="N",
        help="fail on a TODO(#N) for any of these issues",
    )
    parser.add_argument(
        "--closing-issues-from-event",
        type=Path,
        metavar="PATH",
        help="also take the issues the pull request in this GitHub event "
        "payload closes",
    )
    parser.add_argument(
        "--check-open",
        action="store_true",
        help="fail on a TODO(#N) whose issue is closed, missing or a "
        "pull request (queries the GitHub API)",
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY"),
        help="owner/name for --check-open (default: $GITHUB_REPOSITORY)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None, fetch: Fetch = urllib_fetch) -> int:
    """Run the check and return the exit status.

    :param argv: the arguments, or ``None`` for ``sys.argv[1:]``
    :param fetch: the HTTP GET ``--check-open`` uses
    """
    args = parse_args(argv)
    if args.check_open and not args.repo:
        print(
            "check_todos: --check-open needs --repo or $GITHUB_REPOSITORY",
            file=sys.stderr,
        )
        return 2
    root: Path = args.root
    findings, todos = scan_tree(root, tracked_files(root))

    closing = set(args.closing_issues)
    if args.closing_issues_from_event is not None:
        closing |= closing_issues_from_event(args.closing_issues_from_event)
        print(
            "check_todos: the pull request closes "
            + (", ".join(f"#{n}" for n in sorted(closing)) or "no issues")
        )
    findings += closing_findings(todos, closing)

    if args.check_open:
        token = os.environ.get("GITHUB_TOKEN") or None
        try:
            findings += open_findings(todos, args.repo, token, fetch)
        except ApiError as error:
            for finding in findings:
                print(finding)
            print(
                f"check_todos: GitHub API failure, so the TODO issues could "
                f"not be checked: {error}",
                file=sys.stderr,
            )
            return EXIT_API_FAILURE

    findings.sort(key=lambda f: (f.path, f.line, f.column))
    for finding in findings:
        print(finding)
    if findings:
        print(
            f"check_todos: {len(findings)} finding(s); the only accepted "
            f"marker is TODO(#N): <text> naming an open issue",
            file=sys.stderr,
        )
        return EXIT_FINDINGS
    print(f"check_todos: OK ({len(todos)} TODO(#N) marker(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
