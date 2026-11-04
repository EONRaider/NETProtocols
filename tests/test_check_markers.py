"""Tests for scripts/check_markers.py, the work-marker ban."""

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_markers.py"

# The marker words, built by concatenation so this file holds none.
T, F, X, H = "TO" + "DO", "FIX" + "ME", "X" + "XX", "HA" + "CK"


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_markers", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves the module's string annotations through
    # sys.modules, so the module is registered before it runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


check_markers = _load_checker()


def words(path: str, text: str) -> list[str]:
    """The marker words found in one file, in order."""
    return [f.word for f in check_markers.scan_text(path, text)]


class TestEveryMarkerFails:
    @pytest.mark.parametrize(
        "line",
        [
            f"# {T}(#235): reject trailing bytes",
            f"x = 1  # {T}: name the constant",
            f"# {T}",
            f"# {F}: broken",
            f"# {X}",
            f"# {H}(#12): even with an issue",
        ],
    )
    def test_in_a_python_comment(self, line: str) -> None:
        assert len(words("src/a.py", line + "\n")) == 1

    @pytest.mark.parametrize(
        ("path", "line"),
        [
            ("a.sh", f"# {T}(#235): quote the glob"),
            ("a.yml", f"  # {T}(#235): pin the action"),
            ("a.toml", f"# {F}"),
            ("a.cfg", f"# {H}"),
            (".flake8", f"# {X}"),
            ("a.txt", f"{T}: anything"),
        ],
    )
    def test_in_other_files(self, path: str, line: str) -> None:
        assert len(words(path, line + "\n")) == 1

    def test_in_a_python_docstring_or_string(self) -> None:
        text = f'def f():\n    """{T}: not here."""\nx = "{F}"\n'
        assert words("src/a.py", text) == [T, F]

    def test_every_marker_on_a_line_is_reported(self) -> None:
        assert words("a.sh", f"# {T}: a {X} b {F}\n") == [T, X, F]

    def test_findings_carry_line_and_column(self) -> None:
        findings = check_markers.scan_text("a.sh", f"ok\n  # {X}\n")
        assert [str(f) for f in findings] == [
            f"a.sh:2:5: {X} marker; file an issue for the work instead"
        ]


class TestCommentMatching:
    @pytest.mark.parametrize(
        ("path", "line"),
        [
            ("a.py", f"# {T.lower()}: lowercase"),
            ("a.py", f"# {T}s are tracked in issues"),
            ("a.py", f"x = 1  # {H.capitalize()}"),
            ("a.py", f"# {F.lower()}_later"),
            ("a.sh", f"# {X.lower()}"),
            ("a.yml", f"key: value  # {T.lower()}s"),
            ("a.toml", f"# {H.lower()}"),
            ("a.cfg", f"# {F.capitalize()}"),
            (".flake8", f"# {T.lower()}"),
        ],
    )
    def test_any_case_and_suffixes_in_comments(
        self, path: str, line: str
    ) -> None:
        assert len(words(path, line + "\n")) == 1

    @pytest.mark.parametrize(
        ("path", "line"),
        [
            ("a.py", f'x = "{T.lower()}"'),
            ("a.py", f"value = 0x{X}"),
            ("a.py", f"# MY_{T}_LIST"),
            ("a.py", f"# {H}ER, {X}L"),
            ("a.sh", f"WORK=$(mktemp -d /tmp/x.{X}{X})"),
            ("a.yml", f"key: {T.lower()}"),
            ("README.md", f"a {T.lower()} list"),
            ("README.md", f"{T}s"),
            ("a.txt", f"{T.lower()}"),
        ],
    )
    def test_outside_comments_only_whole_capital_words(
        self, path: str, line: str
    ) -> None:
        assert words(path, line + "\n") == []

    def test_a_python_file_that_does_not_tokenize_is_still_scanned(
        self,
    ) -> None:
        text = f'x = """unterminated\n# {T.lower()}\n# {F}\n'
        assert words("a.py", text) == [T.lower(), F]


class TestMarkdown:
    def test_markers_in_inline_code_spans_are_not_scanned(self) -> None:
        text = f"A bare `{T}`, ``{F}`` or `{T}(#123): ...` is data.\n"
        assert words("CONTRIBUTING.md", text) == []

    def test_markers_in_markdown_prose_are_scanned(self) -> None:
        assert words("README.md", f"{T}: write this\n") == [T]

    def test_code_spans_count_only_in_markdown(self) -> None:
        assert words("a.py", f"# `{F}`\n") == [F]


class TestExclusions:
    """The exclusions are exactly these; a new one has to change this."""

    def test_the_excluded_files(self) -> None:
        assert {"CHANGELOG.md"} == check_markers.EXCLUDED_FILES

    def test_the_excluded_directories(self) -> None:
        assert check_markers.EXCLUDED_DIRS == ()

    @pytest.mark.parametrize(
        ("path", "excluded"),
        [
            ("CHANGELOG.md", True),
            ("docs/CHANGELOG.md", False),
            ("CONTRIBUTING.md", False),
            ("tests/fixtures/MANIFEST.md", False),
            ("tests/fixtures/codeql/python.sarif", False),
            ("scripts/check_markers.py", False),
            ("tests/test_check_markers.py", False),
        ],
    )
    def test_is_excluded(self, path: str, excluded: bool) -> None:
        assert check_markers.is_excluded(path) is excluded


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
                "src/a.py": f"x = 1\n# {F}\n".encode(),
                "CHANGELOG.md": f"- removed a {F}\n".encode(),
                "tests/fixtures/data.txt": f"{X}\n".encode(),
                "blob.bin": f"\0\1{H}\n".encode(),
            },
        )
        (root / "untracked.py").write_text(f"# {F}\n")
        paths = check_markers.tracked_files(root)
        assert "untracked.py" not in paths
        findings = check_markers.scan_tree(root, paths)
        assert [(f.path, f.line) for f in findings] == [
            ("src/a.py", 2),
            ("tests/fixtures/data.txt", 1),
        ]

    def test_a_latin1_file_is_scanned(self, tmp_path: Path) -> None:
        root = git_repo(
            tmp_path, {"latin1.py": f"# caf\xe9 {H}\n".encode("latin-1")}
        )
        findings = check_markers.scan_tree(root, ["latin1.py"])
        assert [(f.path, f.word) for f in findings] == [("latin1.py", H)]

    def test_a_listed_path_that_is_gone_is_skipped(
        self, tmp_path: Path
    ) -> None:
        root = git_repo(tmp_path, {"a.sh": f"# {H}\n".encode()})
        (root / "a.sh").unlink()
        assert check_markers.scan_tree(root, ["a.sh"]) == []

    def test_main_fails_on_a_finding(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        root = git_repo(tmp_path, {"a.sh": f"# {H}\n".encode()})
        assert check_markers.main(["--root", str(root)]) == 1
        assert f"a.sh:1:3: {H} marker" in capsys.readouterr().out

    def test_main_passes_a_clean_tree(self, tmp_path: Path) -> None:
        root = git_repo(tmp_path, {"a.sh": b"# all done\n"})
        assert check_markers.main(["--root", str(root)]) == 0

    def test_the_repository_itself_passes(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert check_markers.main(["--root", str(ROOT)]) == 0, (
            capsys.readouterr().out
        )

    def test_the_command_line_runs_offline(self, tmp_path: Path) -> None:
        root = git_repo(tmp_path, {"a.sh": b"# all done\n"})
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert "check_markers: OK" in result.stdout
