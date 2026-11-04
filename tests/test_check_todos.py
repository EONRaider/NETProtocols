"""Tests for scripts/check_todos.py, the TODO marker check."""

import importlib.util
import io
import json
import subprocess
import sys
import urllib.error
from email.message import Message
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_todos.py"


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_todos", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves the module's string annotations through
    # sys.modules, so the module is registered before it runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


check_todos = _load_checker()


def scan(path: str, text: str) -> tuple[list[str], list[int]]:
    """The finding messages and accepted issue numbers for one file."""
    findings, todos = check_todos.scan_text(path, text)
    return [f.message for f in findings], [t.issue for t in todos]


class TestForms:
    @pytest.mark.parametrize(
        "line",
        [
            "# TODO(#235): reject trailing bytes",
            "x = 1  # TODO(#7): name the constant",
            "#   TODO(#12):   several spaces",
        ],
    )
    def test_the_accepted_form_passes_in_a_python_comment(
        self, line: str
    ) -> None:
        messages, issues = scan("src/a.py", line + "\n")
        assert messages == []
        assert len(issues) == 1

    @pytest.mark.parametrize(
        ("path", "line"),
        [
            ("a.sh", "# TODO(#235): quote the glob"),
            ("a.yml", "  # TODO(#235): pin the action"),
            ("a.toml", "# TODO(#235): drop the ignore"),
        ],
    )
    def test_the_accepted_form_passes_in_other_files(
        self, path: str, line: str
    ) -> None:
        assert scan(path, line + "\n") == ([], [235])

    @pytest.mark.parametrize(
        "line",
        [
            "# TODO",
            "# TODO: tidy up",
            "# TODO tidy up",
            "# TODO(#12)",
            "# TODO(#12):",
            "# TODO(#12):   ",
            "# TODO(#12):no space",
            "# TODO(#12) missing colon",
            "# TODO (#12): space before the parenthesis",
            "# TODO(12): no hash",
            "# TODO(#0): issue zero",
            "# TODO(alice): a name",
            "# FIXME: broken",
            "# FIXME(#12): even with an issue",
            "# XXX",
            "# HACK(#12): even with an issue",
        ],
    )
    def test_banned_forms_fail(self, line: str) -> None:
        messages, issues = scan("src/a.py", line + "\n")
        assert len(messages) == 1, messages
        assert issues == []

    def test_every_marker_on_a_line_is_reported(self) -> None:
        messages, issues = scan("a.sh", "# TODO(#3): a XXX b FIXME\n")
        assert len(messages) == 2
        assert issues == [3]

    @pytest.mark.parametrize(
        "line",
        [
            "# todo: lowercase is ordinary prose",
            "# TODOs are tracked in issues",
            "# HACKER, XXXL, FIXMES",
            "value = 0xXXX",
            "# MY_TODO_LIST",
        ],
    )
    def test_only_whole_uppercase_words_are_markers(self, line: str) -> None:
        assert scan("a.py", line + "\n") == ([], [])

    def test_a_python_todo_in_a_docstring_fails(self) -> None:
        text = 'def f():\n    """TODO(#235): not here."""\n'
        messages, issues = scan("src/a.py", text)
        assert messages == [
            "TODO(#N) must be a # comment, not part of a string or docstring"
        ]
        assert issues == []

    def test_a_python_todo_in_a_string_fails(self) -> None:
        messages, _ = scan("a.py", 'x = "TODO(#235): not here"\n')
        assert len(messages) == 1

    def test_a_python_file_that_does_not_tokenize_is_still_scanned(
        self,
    ) -> None:
        text = 'x = """unterminated\n# TODO(#5): ok\n# FIXME\n'
        messages, issues = scan("a.py", text)
        assert len(messages) == 1
        assert issues == [5]

    def test_findings_carry_line_and_column(self) -> None:
        findings, _ = check_todos.scan_text("a.sh", "ok\n  # XXX\n")
        assert [str(f) for f in findings] == [
            "a.sh:2:5: XXX is banned; write TODO(#N): <text> for an open issue"
        ]


class TestMarkdown:
    def test_markers_in_inline_code_spans_are_not_scanned(self) -> None:
        text = "A bare `TODO`, ``FIXME`` or `TODO(#123): ...` is data.\n"
        assert scan("CONTRIBUTING.md", text) == ([], [])

    def test_markers_in_markdown_prose_are_scanned(self) -> None:
        messages, issues = scan("README.md", "TODO: write this\n")
        assert len(messages) == 1
        assert issues == []

    def test_code_spans_count_only_in_markdown(self) -> None:
        messages, _ = scan("a.py", "# `FIXME`\n")
        assert len(messages) == 1


class TestExclusions:
    """The exclusions are exactly these; a new one has to change this."""

    def test_the_excluded_files(self) -> None:
        assert {
            "CHANGELOG.md",
            "scripts/check_todos.py",
            "tests/test_check_todos.py",
        } == check_todos.EXCLUDED_FILES

    def test_the_excluded_directories(self) -> None:
        assert check_todos.EXCLUDED_DIRS == ("tests/fixtures/",)

    @pytest.mark.parametrize(
        ("path", "excluded"),
        [
            ("CHANGELOG.md", True),
            ("docs/CHANGELOG.md", False),
            ("CONTRIBUTING.md", False),
            ("tests/fixtures/x.pcap", True),
            ("tests/fixtures/codeql/python.sarif", True),
            ("tests/fixtures_more/x.txt", False),
            ("tests/test_flow.py", False),
            ("scripts/check_todos.py", True),
        ],
    )
    def test_is_excluded(self, path: str, excluded: bool) -> None:
        assert check_todos.is_excluded(path) is excluded


def git_repo(tmp_path: Path, files: dict[str, bytes]) -> Path:
    """A git repository at ``tmp_path`` with ``files`` added."""
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    for name, data in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    return tmp_path


class TestTree:
    def test_only_tracked_unexcluded_text_files_are_scanned(
        self, tmp_path: Path
    ) -> None:
        root = git_repo(
            tmp_path,
            {
                "src/a.py": b"# TODO(#4): ok\n# FIXME\n",
                "CHANGELOG.md": b"- removed a FIXME\n",
                "tests/fixtures/data.txt": b"XXX\n",
                "tests/fixtures/x.bin": b"\0HACK\n",
                "blob.bin": b"\0\1HACK\n",
                "latin1.txt": "HACK \xe9\n".encode("latin-1"),
            },
        )
        (root / "untracked.py").write_text("# FIXME\n")
        paths = check_todos.tracked_files(root)
        assert "untracked.py" not in paths
        findings, todos = check_todos.scan_tree(root, paths)
        assert [(f.path, f.line) for f in findings] == [("src/a.py", 2)]
        assert [t.issue for t in todos] == [4]

    def test_a_listed_path_that_is_gone_is_skipped(
        self, tmp_path: Path
    ) -> None:
        root = git_repo(tmp_path, {"a.sh": b"# HACK\n"})
        (root / "a.sh").unlink()
        assert check_todos.scan_tree(root, ["a.sh"]) == ([], [])

    def test_main_fails_on_a_finding(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = git_repo(tmp_path, {"a.sh": b"# HACK\n"})
        assert check_todos.main(["--root", str(root)]) == 1
        assert "a.sh:1:3: HACK is banned" in capsys.readouterr().out

    def test_main_passes_a_clean_tree(self, tmp_path: Path) -> None:
        root = git_repo(tmp_path, {"a.sh": b"# TODO(#235): later\n"})
        assert check_todos.main(["--root", str(root)]) == 0

    def test_the_repository_itself_passes(self) -> None:
        assert check_todos.main(["--root", str(ROOT)]) == 0


class TestClosingKeywords:
    @pytest.mark.parametrize(
        ("body", "issues"),
        [
            ("Fixes #12, closes #34", {12, 34}),
            ("fixes #12\nresolves #5", {12, 5}),
            ("CLOSE #1 Close #2 closed #3", {1, 2, 3}),
            ("fix #1 fixed #2 Fixes #3", {1, 2, 3}),
            ("resolve #1 Resolved #2 RESOLVES #3", {1, 2, 3}),
            ("Closes: #9", {9}),
            ("#12 without a keyword", set()),
            ("Refs #12, see #34", set()),
            ("Fixes #12, #34", {12}),
            ("prefixes #12 and unfixed #13", set()),
            ("fixes#12", set()),
            ("", set()),
        ],
    )
    def test_closing_issues(self, body: str, issues: set[int]) -> None:
        assert check_todos.closing_issues(body) == issues

    def test_reads_the_pull_request_body_from_the_event(
        self, tmp_path: Path
    ) -> None:
        event = tmp_path / "event.json"
        event.write_text(
            json.dumps({"pull_request": {"body": "Fixes #12; `rm -rf /`"}})
        )
        assert check_todos.closing_issues_from_event(event) == {12}

    @pytest.mark.parametrize(
        "payload",
        [
            {"ref": "refs/heads/master"},
            {"schedule": "0 7 * * 3"},
            {"pull_request": {"body": None}},
            [],
        ],
    )
    def test_an_event_without_a_body_closes_nothing(
        self, tmp_path: Path, payload: object
    ) -> None:
        event = tmp_path / "event.json"
        event.write_text(json.dumps(payload))
        assert check_todos.closing_issues_from_event(event) == set()

    def test_a_todo_for_a_closed_issue_fails(self, tmp_path: Path) -> None:
        root = git_repo(tmp_path, {"a.sh": b"# TODO(#12): x\n# TODO(#13): y\n"})
        event = tmp_path / "event.json"
        event.write_text(json.dumps({"pull_request": {"body": "Fixes #12"}}))
        assert (
            check_todos.main(
                ["--root", str(root), "--closing-issues-from-event", str(event)]
            )
            == 1
        )
        assert (
            check_todos.main(["--root", str(root), "--closing-issues", "13"])
            == 1
        )
        assert (
            check_todos.main(["--root", str(root), "--closing-issues", "14"])
            == 0
        )


def fake_fetch(
    responses: dict[int, object],
) -> tuple[list[tuple[str, dict[str, str]]], object]:
    """A fetch that answers each issue from ``responses``.

    A value is the issue JSON (a dict), an HTTP status to raise as an
    HTTPError (an int), or an exception to raise.
    """
    calls: list[tuple[str, dict[str, str]]] = []

    def fetch(url: str, headers: dict[str, str]) -> tuple[int, bytes]:
        calls.append((url, headers))
        answer = responses[int(url.rsplit("/", 1)[1])]
        if isinstance(answer, int):
            raise urllib.error.HTTPError(
                url, answer, "error", Message(), io.BytesIO(b"")
            )
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, tuple):
            return answer
        return 200, json.dumps(answer).encode()

    return calls, fetch


OPEN = {"number": 1, "state": "open"}
CLOSED = {"number": 1, "state": "closed"}
PULL = {"number": 1, "state": "open", "pull_request": {"url": "..."}}


class TestIssueState:
    def test_an_open_issue_passes(self) -> None:
        calls, fetch = fake_fetch({7: OPEN})
        assert check_todos.issue_problem("o/r", 7, "tok", fetch) is None
        url, headers = calls[0]
        assert url == "https://api.github.com/repos/o/r/issues/7"
        assert headers["Authorization"] == "Bearer tok"

    def test_no_token_queries_anonymously(self) -> None:
        calls, fetch = fake_fetch({7: OPEN})
        check_todos.issue_problem("o/r", 7, None, fetch)
        assert "Authorization" not in calls[0][1]

    @pytest.mark.parametrize(
        ("answer", "problem"),
        [
            (CLOSED, "issue #7 is closed"),
            (PULL, "#7 is a pull request, not an issue"),
            ({**PULL, "state": "closed"}, "#7 is a pull request, not an issue"),
            (404, "issue #7 does not exist in o/r"),
            (410, "issue #7 does not exist in o/r"),
        ],
    )
    def test_unfit_issues(self, answer: object, problem: str) -> None:
        _, fetch = fake_fetch({7: answer})
        assert check_todos.issue_problem("o/r", 7, None, fetch) == problem

    @pytest.mark.parametrize(
        "answer",
        [
            403,
            500,
            502,
            urllib.error.URLError("no route"),
            TimeoutError("timed out"),
            (200, b"not json"),
            (200, b"[]"),
            (200, b"{}"),
            (204, b""),
        ],
    )
    def test_api_failures_raise(self, answer: object) -> None:
        _, fetch = fake_fetch({7: answer})
        with pytest.raises(check_todos.ApiError):
            check_todos.issue_problem("o/r", 7, None, fetch)

    def test_each_issue_is_queried_once(self) -> None:
        todos = [
            check_todos.Todo("a.py", 1, 3, 7),
            check_todos.Todo("b.py", 2, 3, 7),
            check_todos.Todo("b.py", 3, 3, 8),
        ]
        calls, fetch = fake_fetch({7: CLOSED, 8: OPEN})
        findings = check_todos.open_findings(todos, "o/r", None, fetch)
        assert len(calls) == 2
        assert [(f.path, f.line) for f in findings] == [
            ("a.py", 1),
            ("b.py", 2),
        ]


class TestCheckOpen:
    def run(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        answer: object,
        *args: str,
    ) -> int:
        root = git_repo(tmp_path, {"a.sh": b"# TODO(#7): later\n"})
        monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
        monkeypatch.setenv("GITHUB_TOKEN", "tok")
        _, fetch = fake_fetch({7: answer})
        result: int = check_todos.main(
            ["--root", str(root), "--check-open", *args], fetch
        )
        return result

    def test_open_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert self.run(tmp_path, monkeypatch, OPEN) == 0

    @pytest.mark.parametrize("answer", [CLOSED, PULL, 404])
    def test_unfit_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        answer: object,
    ) -> None:
        assert self.run(tmp_path, monkeypatch, answer) == 1
        assert capsys.readouterr().out.startswith("a.sh:1:3: ")

    def test_an_api_failure_fails_and_says_so(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        error = urllib.error.URLError("unreachable")
        assert self.run(tmp_path, monkeypatch, error) == 3
        assert "GitHub API failure" in capsys.readouterr().err

    def test_the_repo_flag_overrides_the_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = git_repo(tmp_path, {"a.sh": b"# TODO(#7): later\n"})
        monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
        calls, fetch = fake_fetch({7: OPEN})
        check_todos.main(
            ["--root", str(root), "--check-open", "--repo", "x/y"], fetch
        )
        assert calls[0][0].endswith("/repos/x/y/issues/7")

    def test_no_repository_is_a_usage_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _, fetch = fake_fetch({})
        assert (
            check_todos.main(["--root", str(tmp_path), "--check-open"], fetch)
            == 2
        )

    def test_without_check_open_nothing_is_fetched(
        self, tmp_path: Path
    ) -> None:
        root = git_repo(tmp_path, {"a.sh": b"# TODO(#7): later\n"})
        calls, fetch = fake_fetch({})
        assert check_todos.main(["--root", str(root)], fetch) == 0
        assert calls == []
