"""Tests for scripts/benchmark_ab.py and scripts/benchmark_base.sh.

The comparison is run on small stand-in ``netprotocols`` packages
written to temporary directories, and on a copy of this checkout's own
``src``. Each worker process reports where its ``netprotocols`` came
from, which is how the tests check that neither tree, nor the package
installed in this environment, leaks into the other.
"""

import importlib.util
import json
import math
import shutil
import struct
import subprocess
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "benchmark_ab.py"
BASE_SCRIPT = ROOT / "scripts" / "benchmark_base.sh"
GIT = ("git", "-c", "user.name=test", "-c", "user.email=test@example.com")


@pytest.fixture(scope="module")
def ab() -> ModuleType:
    spec = importlib.util.spec_from_file_location("benchmark_ab", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_pcap(path: Path, frames: list[bytes]) -> None:
    records = b"".join(
        struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
        for frame in frames
    )
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    path.write_bytes(header + records)


def write_library(tree: Path, body: str, version: str = "0.0.test") -> Path:
    """Write a stand-in ``netprotocols`` package; return its ``src``."""
    package = tree / "src" / "netprotocols"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        f"__version__ = {version!r}\n" + textwrap.dedent(body)
    )
    (package / "extra.py").write_text("VALUE = 1\n")
    return tree / "src"


#: Raises on frames whose first byte is in ``REJECT``.
REJECTING = """
from netprotocols import extra

REJECT = {reject}


def decode_frame(frame):
    if frame[0] in REJECT:
        raise ValueError("rejected")
    return len(frame)
"""


@pytest.fixture
def fixtures(tmp_path: Path) -> Path:
    directory = tmp_path / "fixtures"
    directory.mkdir()
    write_pcap(directory / "a.pcap", [bytes([0x00, 1]), bytes([0xEE, 2])])
    write_pcap(
        directory / "b.pcap",
        [bytes([0xDD, 3]), bytes([0xEE, 4]), bytes([0x01, 5])],
    )
    return directory


def git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        [*GIT, "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def make_repository(path: Path, body: str) -> Path:
    """A repository whose one commit holds a library and stale scripts."""
    write_library(path, body)
    scripts = path / "scripts"
    scripts.mkdir()
    (scripts / "benchmark.py").write_text("raise SystemExit(3)\n")
    (scripts / "_benchmark_ab_worker.py").write_text("raise SystemExit(4)\n")
    git(path.parent, "init", "-q", str(path))
    git(path, "add", ".")
    git(path, "commit", "-q", "-m", "base")
    return path


class TestIsolation:
    def test_the_worker_imports_only_the_tree_it_is_given(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        src = write_library(tmp_path / "tree", REJECTING.format(reject="()"))
        found = ab.run_worker(src, fixtures, "probe")
        assert found["file"] == str(src.resolve() / "netprotocols/__init__.py")
        assert found["version"] == "0.0.test"
        assert found["outside"] == []
        assert found["site"] is False
        assert found["bytecode_written"] is False
        assert not list(src.rglob("__pycache__"))

    def test_each_tree_reports_its_own_package(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        base = write_library(tmp_path / "base", REJECTING.format(reject="()"))
        head = write_library(tmp_path / "head", REJECTING.format(reject="()"))
        result = ab.compare(base, head, fixtures, 2, 1, 1)
        files = {name: p["file"] for name, p in result["probes"].items()}
        assert Path(files["base"]).is_relative_to(base.resolve())
        assert Path(files["head"]).is_relative_to(head.resolve())

    def test_a_copy_of_this_checkout_loads_from_the_copy(
        self, ab: ModuleType, tmp_path: Path
    ) -> None:
        copied = ab.copy_tree(ROOT / "src", tmp_path)
        assert not list(copied.rglob("__pycache__"))
        assert not list(copied.rglob("*.pyc"))
        found = ab.run_worker(copied, ROOT / "tests" / "fixtures", "probe")
        assert Path(found["file"]).is_relative_to(copied.resolve())
        assert found["outside"] == []
        assert found["frames"] > 0

    def test_a_module_from_outside_the_tree_is_refused(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "planted.py").write_text("X = 1\n")
        body = f"""
        import sys
        sys.path.insert(0, {str(elsewhere)!r})
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "netprotocols.planted", {str(elsewhere / "planted.py")!r}
        )
        planted = importlib.util.module_from_spec(spec)
        sys.modules["netprotocols.planted"] = planted
        spec.loader.exec_module(planted)

        def decode_frame(frame):
            return frame
        """
        base = write_library(tmp_path / "base", body)
        head = write_library(tmp_path / "head", REJECTING.format(reject="()"))
        with pytest.raises(ab.ComparisonError, match=r"netprotocols\.planted"):
            ab.compare(base, head, fixtures, 1, 1, 1)

    def test_a_module_imported_during_decode_is_scanned_too(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "lazy.py").write_text("X = 1\n")
        body = f"""
        import sys


        def decode_frame(frame):
            if "netprotocols.lazy" not in sys.modules:
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "netprotocols.lazy", {str(elsewhere / "lazy.py")!r}
                )
                lazy = importlib.util.module_from_spec(spec)
                sys.modules["netprotocols.lazy"] = lazy
                spec.loader.exec_module(lazy)
            return frame
        """
        src = write_library(tmp_path / "tree", body)
        assert ab.run_worker(src, fixtures, "probe")["outside"] == [
            "netprotocols.lazy"
        ]
        timed = ab.run_worker(
            src, fixtures, "time", "--repetitions", "1", "--trials", "1"
        )
        assert timed["outside"] == ["netprotocols.lazy"]
        with pytest.raises(ab.ComparisonError, match=r"netprotocols\.lazy"):
            ab.check_timed("base", timed, 5)

    def test_what_the_library_prints_is_not_read_as_the_result(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        noisy = REJECTING.format(reject="()").replace(
            "    return len(frame)", '    print("{{")\n    return len(frame)'
        )
        base = write_library(tmp_path / "base", 'print("not json")\n' + noisy)
        head = write_library(tmp_path / "head", REJECTING.format(reject="()"))
        result = ab.compare(base, head, fixtures, 2, 1, 1)
        assert len(result["pairs"]) == 2

    def test_a_worker_that_writes_no_result_is_an_error(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        base = write_library(tmp_path / "base", "import os\nos._exit(0)\n")
        with pytest.raises(ab.ComparisonError, match="left no result"):
            ab.run_worker(base, fixtures, "probe")


class TestFrames:
    def test_frames_either_tree_raises_on_are_skipped_for_both(
        self,
        ab: ModuleType,
        tmp_path: Path,
        fixtures: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        base = write_library(
            tmp_path / "base", REJECTING.format(reject="{0xEE}")
        )
        head = write_library(
            tmp_path / "head", REJECTING.format(reject="{0xEE, 0xDD}")
        )
        result = ab.compare(base, head, fixtures, 2, 1, 1)
        assert result["frames"] == 5
        assert result["base_raises"] == [1, 3]
        assert result["head_raises"] == [1, 2, 3]
        assert result["skipped"] == [1, 2, 3]
        assert (
            "3 skipped for both trees: 2 the base raises on, 3 the head "
            "raises on"
        ) in capsys.readouterr().out
        timed = ab.run_worker(
            head,
            fixtures,
            "time",
            "--repetitions",
            "1",
            "--trials",
            "1",
            "--skip",
            "1,2,3",
        )
        assert timed["frames"] == 2
        assert timed["rejected"] == 0
        ab.check_timed("head", timed, 2)

    def test_a_timed_run_that_disagrees_with_the_probes_is_an_error(
        self, ab: ModuleType
    ) -> None:
        good = {"outside": [], "frames": 2, "rejected": 0, "seconds": 1.0}
        ab.check_timed("head", good, 2)
        for bad in ({**good, "frames": 3}, {**good, "rejected": 1}):
            with pytest.raises(ab.ComparisonError, match="probes predict"):
                ab.check_timed("head", bad, 2)

    def test_a_head_that_raises_on_every_frame_is_an_error(
        self,
        ab: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        copied = tmp_path / "copy"
        shutil.copytree(
            ROOT / "src",
            copied,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        init = copied / "netprotocols" / "__init__.py"
        init.write_text(
            init.read_text()
            + "\n\ndef decode_frame(*a, **k):\n    raise ValueError\n"
        )
        status = ab.main(
            [
                "--base-src",
                str(ROOT / "src"),
                "--head-src",
                str(copied),
                "--pairs",
                "2",
                "--repetitions",
                "1",
                "--trials",
                "1",
            ]
        )
        assert status == 2
        assert "decodes in both trees" in capsys.readouterr().err

    def test_a_base_that_decodes_nothing_is_an_error(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        base = write_library(
            tmp_path / "base", REJECTING.format(reject="range(256)")
        )
        head = write_library(tmp_path / "head", REJECTING.format(reject="()"))
        with pytest.raises(ab.ComparisonError, match="decodes in both"):
            ab.compare(base, head, fixtures, 1, 1, 1)

    def test_a_base_without_decode_frame_is_an_error(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        base = write_library(tmp_path / "base", "")
        head = write_library(tmp_path / "head", REJECTING.format(reject="()"))
        with pytest.raises(ab.ComparisonError, match="worker failed"):
            ab.compare(base, head, fixtures, 1, 1, 1)


class TestBaseRevision:
    def test_only_src_is_taken_from_the_base(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        repository = make_repository(
            tmp_path / "repo", REJECTING.format(reject="()")
        )
        destination = tmp_path / "export"
        destination.mkdir()
        src = ab.export_tree(repository, "HEAD", destination)
        assert sorted(p.name for p in destination.iterdir()) == ["src"]
        head = write_library(tmp_path / "head", REJECTING.format(reject="()"))
        result = ab.compare(src, head, fixtures, 1, 1, 1)
        assert len(result["pairs"]) == 1

    def test_a_revision_missing_from_a_shallow_clone_is_an_error(
        self, ab: ModuleType, tmp_path: Path
    ) -> None:
        repository = make_repository(
            tmp_path / "repo", REJECTING.format(reject="()")
        )
        (repository / "src" / "netprotocols" / "extra.py").write_text("V=2\n")
        git(repository, "commit", "-q", "-am", "second")
        shallow = tmp_path / "shallow"
        git(
            tmp_path,
            "clone",
            "-q",
            "--depth",
            "1",
            repository.as_uri(),
            str(shallow),
        )
        with pytest.raises(ab.ComparisonError, match="fetch-depth"):
            ab.export_tree(shallow, "HEAD^1", tmp_path)
        assert ab.export_tree(repository, "HEAD^1", tmp_path).is_dir()

    def test_a_revision_without_src_is_an_error(
        self, ab: ModuleType, tmp_path: Path
    ) -> None:
        repository = tmp_path / "repo"
        repository.mkdir()
        (repository / "README").write_text("no src\n")
        git(tmp_path, "init", "-q", str(repository))
        git(repository, "add", ".")
        git(repository, "commit", "-q", "-m", "only a readme")
        with pytest.raises(ab.ComparisonError, match="cannot export src"):
            ab.export_tree(repository, "HEAD", tmp_path)

    def test_an_unsafe_link_in_the_base_exits_2(
        self,
        ab: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        repository = make_repository(
            tmp_path / "repo", REJECTING.format(reject="()")
        )
        (repository / "src" / "netprotocols" / "evil").symlink_to("/etc/passwd")
        git(repository, "add", ".")
        git(repository, "commit", "-q", "-m", "link")
        with pytest.raises(ab.ComparisonError, match="cannot extract"):
            ab.export_tree(repository, "HEAD", tmp_path)
        status = ab.main(["--repository", str(repository), "--base", "HEAD"])
        assert status == 2
        assert "cannot extract" in capsys.readouterr().err


class TestCopy:
    def test_links_inside_the_tree_are_kept_as_links(
        self, ab: ModuleType, tmp_path: Path
    ) -> None:
        src = write_library(tmp_path / "tree", REJECTING.format(reject="()"))
        (src / "netprotocols" / "alias.py").symlink_to("extra.py")
        copied = ab.copy_tree(src, tmp_path)
        assert (copied / "netprotocols" / "alias.py").is_symlink()
        assert str((copied / "netprotocols" / "alias.py").readlink()) == (
            "extra.py"
        )

    @pytest.mark.parametrize("target", ["/etc/passwd", "../../outside.py"])
    def test_links_the_archive_filter_refuses_are_refused(
        self, ab: ModuleType, tmp_path: Path, target: str
    ) -> None:
        src = write_library(tmp_path / "tree", REJECTING.format(reject="()"))
        (src / "netprotocols" / "evil.py").symlink_to(target)
        out = tmp_path / "out"
        out.mkdir()
        with pytest.raises(ab.ComparisonError, match="links to"):
            ab.copy_tree(src, out)

    def test_a_failed_copy_is_a_comparison_error(
        self, ab: ModuleType, tmp_path: Path
    ) -> None:
        src = write_library(tmp_path / "tree", REJECTING.format(reject="()"))
        out = tmp_path / "out"
        out.mkdir()
        ab.copy_tree(src, out)
        with pytest.raises(ab.ComparisonError, match="cannot copy"):
            ab.copy_tree(src, out)


class TestVerdict:
    def test_summary_of_one_ratio(self, ab: ModuleType) -> None:
        summary = ab.summarize([1.25])
        assert summary == {
            "median": 1.25,
            "min": 1.25,
            "max": 1.25,
            "spread": 0.0,
            "q1": 1.25,
            "q3": 1.25,
        }

    def test_summary_of_several_ratios(self, ab: ModuleType) -> None:
        summary = ab.summarize([1.0, 0.9, 1.3, 1.1, 1.2])
        assert summary["median"] == 1.1
        assert summary["q1"] == 1.0
        assert summary["q3"] == 1.2
        assert summary["spread"] == pytest.approx(0.4)

    @pytest.mark.parametrize(
        ("median", "status"), [(1.049, 0), (1.05, 0), (1.051, 1), (0.5, 0)]
    )
    def test_fails_only_above_the_threshold(
        self, ab: ModuleType, median: float, status: int
    ) -> None:
        summary = ab.summarize([median])
        assert ab.verdict(summary, 5.0) == status

    @pytest.mark.parametrize(("median", "status"), [(1.05, 0), (1.051, 1)])
    def test_the_default_threshold_is_5_percent(
        self,
        ab: ModuleType,
        fixtures: Path,
        monkeypatch: pytest.MonkeyPatch,
        median: float,
        status: int,
    ) -> None:
        def fixed(*args: object) -> dict[str, object]:
            return {"summary": ab.summarize([median])}

        monkeypatch.setattr(ab, "compare", fixed)
        argv = ["--base-src", str(ROOT / "src"), "--fixtures", str(fixtures)]
        assert ab.main(argv) == status

    def test_a_tree_against_itself_passes_and_writes_json(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        src = write_library(tmp_path / "tree", REJECTING.format(reject="()"))
        output = tmp_path / "out.json"
        status = ab.main(
            [
                "--base-src",
                str(src),
                "--head-src",
                str(src),
                "--fixtures",
                str(fixtures),
                "--pairs",
                "4",
                "--repetitions",
                "200",
                "--trials",
                "3",
                "--threshold",
                "1000",
                "--json",
                str(output),
            ]
        )
        assert status == 0
        written = json.loads(output.read_text())
        assert len(written["pairs"]) == 4
        assert {pair["first"] for pair in written["pairs"]} == {
            "base",
            "head",
        }
        assert written["threshold"] == 1000

    def test_a_slowed_head_fails(
        self, ab: ModuleType, tmp_path: Path, fixtures: Path
    ) -> None:
        base = write_library(tmp_path / "base", REJECTING.format(reject="()"))
        slowed = REJECTING.format(reject="()").replace(
            "    return len(frame)",
            "    import time\n    time.sleep(0.002)\n    return len(frame)",
        )
        head = write_library(tmp_path / "head", slowed)
        status = ab.main(
            [
                "--base-src",
                str(base),
                "--head-src",
                str(head),
                "--fixtures",
                str(fixtures),
                "--pairs",
                "2",
                "--repetitions",
                "2",
                "--trials",
                "1",
            ]
        )
        assert status == 1

    def test_main_reports_a_missing_revision(
        self,
        ab: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        repository = make_repository(
            tmp_path / "repo", REJECTING.format(reject="()")
        )
        status = ab.main(
            [
                "--repository",
                str(repository),
                "--base",
                "no-such-revision",
            ]
        )
        assert status == 2
        assert "fetch-depth" in capsys.readouterr().err

    @pytest.mark.parametrize("option", ["--repetitions", "--trials"])
    @pytest.mark.parametrize("value", ["0", "-1"])
    def test_main_rejects_fewer_than_one_repetition_or_trial(
        self,
        ab: ModuleType,
        fixtures: Path,
        monkeypatch: pytest.MonkeyPatch,
        option: str,
        value: str,
    ) -> None:
        def unreachable(*args: object) -> None:
            raise AssertionError("compare ran")

        monkeypatch.setattr(ab, "compare", unreachable)
        argv = ["--base-src", str(ROOT / "src"), "--fixtures", str(fixtures)]
        with pytest.raises(SystemExit) as exited:
            ab.main([*argv, option, value])
        assert exited.value.code == 2

    @pytest.mark.parametrize("value", ["nan", "inf", "-inf"])
    def test_main_rejects_a_non_finite_threshold(
        self,
        ab: ModuleType,
        fixtures: Path,
        monkeypatch: pytest.MonkeyPatch,
        value: str,
    ) -> None:
        def unreachable(*args: object) -> None:
            raise AssertionError("compare ran")

        monkeypatch.setattr(ab, "compare", unreachable)
        argv = ["--base-src", str(ROOT / "src"), "--fixtures", str(fixtures)]
        with pytest.raises(SystemExit) as exited:
            ab.main([*argv, f"--threshold={value}"])
        assert exited.value.code == 2

    @pytest.mark.parametrize("median", [math.nan, math.inf])
    def test_a_non_finite_median_exits_2(
        self,
        ab: ModuleType,
        fixtures: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        median: float,
    ) -> None:
        with pytest.raises(ab.ComparisonError, match="median ratio is"):
            ab.verdict(ab.summarize([median]), 5.0)

        def fixed(*args: object) -> dict[str, object]:
            return {"summary": ab.summarize([median])}

        monkeypatch.setattr(ab, "compare", fixed)
        argv = ["--base-src", str(ROOT / "src"), "--fixtures", str(fixtures)]
        assert ab.main(argv) == 2
        assert "median ratio is" in capsys.readouterr().err

    @pytest.mark.parametrize("seconds", [math.inf, math.nan, 0.0])
    def test_a_time_that_is_not_positive_and_finite_is_an_error(
        self,
        ab: ModuleType,
        fixtures: Path,
        monkeypatch: pytest.MonkeyPatch,
        seconds: float,
    ) -> None:
        probe = {
            "file": "x",
            "version": "0",
            "frames": 5,
            "raises": [],
            "outside": [],
            "site": False,
            "bytecode_written": False,
        }
        timed = {"seconds": seconds, "frames": 5, "rejected": 0, "outside": []}

        def worker(
            src: Path, fixtures: Path, mode: str, *options: str
        ) -> dict[str, object]:
            return dict(probe if mode == "probe" else timed)

        monkeypatch.setattr(ab, "run_worker", worker)
        with pytest.raises(ab.ComparisonError, match="positive finite"):
            ab.compare(Path("b"), Path("h"), fixtures, 2, 1, 1)

    @pytest.mark.parametrize("seconds", ["1.0", None, True, [1.0]])
    def test_a_time_that_is_not_a_number_exits_2(
        self,
        ab: ModuleType,
        fixtures: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        seconds: object,
    ) -> None:
        probe = {
            "file": "x",
            "version": "0",
            "frames": 5,
            "raises": [],
            "outside": [],
            "site": False,
            "bytecode_written": False,
        }
        timed = {"seconds": seconds, "frames": 5, "rejected": 0, "outside": []}

        def worker(
            src: Path, fixtures: Path, mode: str, *options: str
        ) -> dict[str, object]:
            return dict(probe if mode == "probe" else timed)

        monkeypatch.setattr(ab, "run_worker", worker)
        argv = ["--base-src", str(ROOT / "src"), "--fixtures", str(fixtures)]
        assert ab.main([*argv, "--pairs", "2"]) == 2
        assert "positive finite" in capsys.readouterr().err

    def test_a_timed_run_without_a_time_is_an_error(
        self, ab: ModuleType
    ) -> None:
        timed = {"outside": [], "frames": 2, "rejected": 0}
        with pytest.raises(ab.ComparisonError, match="positive finite"):
            ab.check_timed("head", timed, 2)

    @pytest.mark.parametrize("pairs", ["0", "1", "3", "15"])
    def test_main_rejects_an_odd_or_zero_pair_count(
        self, ab: ModuleType, pairs: str
    ) -> None:
        with pytest.raises(SystemExit):
            ab.main(["--base", "HEAD", "--pairs", pairs])

    def test_the_default_pair_count_is_16(
        self,
        ab: ModuleType,
        fixtures: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        seen: list[int] = []

        def record(*args: object) -> None:
            seen.append(int(str(args[3])))
            raise ab.ComparisonError("recorded")

        monkeypatch.setattr(ab, "compare", record)
        status = ab.main(
            ["--base-src", str(ROOT / "src"), "--fixtures", str(fixtures)]
        )
        assert status == 2
        assert seen == [16]

    @pytest.mark.parametrize("kind", ["missing", "empty"])
    def test_main_reports_missing_or_empty_fixtures(
        self,
        ab: ModuleType,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        kind: str,
    ) -> None:
        fixtures = tmp_path / "fixtures"
        if kind == "empty":
            fixtures.mkdir()
        status = ab.main(
            ["--base-src", str(ROOT / "src"), "--fixtures", str(fixtures)]
        )
        assert status == 2
        err = capsys.readouterr().err
        assert (
            "no fixtures directory" if kind == "missing" else "no *.pcap"
        ) in err

    def test_copy_tree_refuses_a_directory_without_the_package(
        self, ab: ModuleType, tmp_path: Path
    ) -> None:
        with pytest.raises(ab.ComparisonError, match="no netprotocols"):
            ab.copy_tree(tmp_path, tmp_path / "out")


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
class TestBaseScript:
    @pytest.fixture
    def history(self, tmp_path: Path) -> Path:
        """master: m1 - m2 - m3; a branch from m1: b1; a clone of it."""
        upstream = tmp_path / "upstream"
        upstream.mkdir()
        git(tmp_path, "init", "-q", "-b", "master", str(upstream))
        for name in ("m1", "m2", "m3"):
            (upstream / name).write_text(name)
            git(upstream, "add", name)
            git(upstream, "commit", "-q", "-m", name)
        git(upstream, "checkout", "-q", "-b", "feature", "HEAD~2")
        (upstream / "b1").write_text("b1")
        git(upstream, "add", "b1")
        git(upstream, "commit", "-q", "-m", "b1")
        git(upstream, "checkout", "-q", "master")
        clone = tmp_path / "clone"
        git(tmp_path, "clone", "-q", upstream.as_uri(), str(clone))
        return clone

    def run(self, clone: Path, **env: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(BASE_SCRIPT)],
            cwd=clone,
            env={"PATH": "/usr/bin:/bin", "HOME": str(clone), **env},
            capture_output=True,
            text=True,
        )

    def test_a_pull_request_compares_against_the_merge_base(
        self, history: Path
    ) -> None:
        git(history, "checkout", "-q", "origin/feature")
        result = self.run(history, EVENT="pull_request", BASE_REF="master")
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == git(history, "rev-parse", "HEAD^1")
        assert result.stdout.strip() != git(
            history, "rev-parse", "origin/master"
        )

    def test_a_push_compares_against_the_commit_before_it(
        self, history: Path
    ) -> None:
        before = git(history, "rev-parse", "HEAD~2")
        result = self.run(history, EVENT="push", BEFORE=before)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == before
        assert before != git(history, "rev-parse", "HEAD^1")

    def test_a_before_equal_to_head_falls_back_to_the_parent(
        self, history: Path
    ) -> None:
        head = git(history, "rev-parse", "HEAD")
        result = self.run(history, EVENT="push", BEFORE=head)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == git(history, "rev-parse", "HEAD^1")

    @pytest.mark.parametrize("before", ["", "0" * 40])
    def test_a_push_with_no_before_falls_back_to_the_parent(
        self, history: Path, before: str
    ) -> None:
        result = self.run(history, EVENT="push", BEFORE=before)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == git(history, "rev-parse", "HEAD^1")

    def test_a_before_that_is_not_an_ancestor_falls_back_to_the_parent(
        self, history: Path
    ) -> None:
        feature = git(history, "rev-parse", "origin/feature")
        result = self.run(history, EVENT="push", BEFORE=feature)
        assert result.stdout.strip() == git(history, "rev-parse", "HEAD^1")

    def test_a_shallow_clone_without_the_parent_fails(
        self, history: Path, tmp_path: Path
    ) -> None:
        shallow = tmp_path / "shallow"
        git(
            tmp_path,
            "clone",
            "-q",
            "--depth",
            "1",
            (tmp_path / "upstream").as_uri(),
            str(shallow),
        )
        result = self.run(shallow, EVENT="push", BEFORE="")
        assert result.returncode != 0
        assert result.stdout.strip() == ""
