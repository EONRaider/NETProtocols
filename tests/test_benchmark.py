"""Tests for scripts/benchmark.py's workload selection.

``--fixture`` and ``--same-depth`` pick the frames the benchmark times.
The tests replace the timing functions with recorders, so they check
which frames reach the timer without timing anything, and replace
dpkt's layer chain with a stand-in, so they run without dpkt.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from netprotocols import ProtocolError

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
FIXTURES = ROOT / "tests" / "fixtures"


def _load_benchmark() -> ModuleType:
    saved = list(sys.path)
    try:
        spec = importlib.util.spec_from_file_location(
            "benchmark", SCRIPTS / "benchmark.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path[:] = saved


benchmark = _load_benchmark()

OSPF = benchmark.read_pcap(FIXTURES / "ospf.pcap")
BGP = benchmark.read_pcap(FIXTURES / "bgp.pcap")
CORPUS_SIZE = sum(
    len(benchmark.read_pcap(path)) for path in FIXTURES.glob("*.pcap")
)


@pytest.fixture
def timed(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[bytes]]:
    """Replace the timing functions; record the frames each is given."""
    seen: dict[str, list[bytes]] = {}

    def measure(
        frames: list[bytes], repetitions: int, trials: int
    ) -> dict[str, Any]:
        seen["measure"] = list(frames)
        return {
            "frames_per_sec": 1.0,
            "frames": len(frames),
            "repetitions": repetitions,
            "trials": trials,
        }

    def compare(
        frames: list[bytes], repetitions: int, trials: int
    ) -> list[str]:
        seen["compare"] = list(frames)
        return []

    monkeypatch.setattr(benchmark, "measure", measure)
    monkeypatch.setattr(benchmark, "compare", compare)
    return seen


def _chains(
    table: dict[bytes, tuple[list[str] | Exception, list[str] | Exception]],
) -> tuple[Any, Any]:
    """Stand-in chain functions that answer from ``table``."""

    def answer(result: list[str] | Exception) -> list[str]:
        if isinstance(result, Exception):
            raise result
        return result

    return (
        lambda frame: answer(table[frame][0]),
        lambda frame: answer(table[frame][1]),
    )


#: Each stand-in capture's frames, keyed by its file name.
CAPTURES = {"b.pcap": [b"b1", b"b2"], "a.pcap": [b"a1"], "c.pcap": [b"c1"]}


class TestSelectFrames:
    def test_no_names_selects_every_capture_in_name_order(self) -> None:
        assert benchmark.select_frames(CAPTURES, []) == [
            b"a1",
            b"b1",
            b"b2",
            b"c1",
        ]

    def test_names_match_with_or_without_the_extension(self) -> None:
        assert benchmark.select_frames(CAPTURES, ["c", "b.pcap"]) == [
            b"b1",
            b"b2",
            b"c1",
        ]

    def test_an_unknown_name_raises_and_lists_the_captures(self) -> None:
        with pytest.raises(ValueError) as caught:
            benchmark.select_frames(CAPTURES, ["a", "nope"])
        assert str(caught.value) == (
            "unknown fixture nope.pcap; choose from: a.pcap, b.pcap, c.pcap"
        )


class TestSameDepthFrames:
    def test_selects_only_frames_of_equal_depth(self) -> None:
        ours, theirs = _chains(
            {
                b"equal": (["Ethernet", "IPv4"], ["Ethernet", "IP"]),
                b"opaque": (
                    ["Ethernet", "IPv4", "UDP"],
                    ["Ethernet", "IP", "UDP", "<8 raw bytes>"],
                ),
                b"deeper": (["Ethernet", "IPv4", "UDP"], ["Ethernet", "IP"]),
                b"shallower": (["Ethernet"], ["Ethernet", "IP"]),
                b"ours rejects": (ProtocolError("bad"), ["Ethernet"]),
                b"theirs rejects": (["Ethernet"], ValueError("bad")),
            }
        )
        frames = [
            b"deeper",
            b"equal",
            b"ours rejects",
            b"opaque",
            b"theirs rejects",
            b"shallower",
        ]
        assert benchmark.same_depth_frames(frames, ours, theirs) == [
            b"equal",
            b"opaque",
        ]

    def test_a_missing_library_raises(self) -> None:
        ours, theirs = _chains(
            {b"frame": (["Ethernet"], ImportError("no dpkt"))}
        )
        with pytest.raises(ImportError):
            benchmark.same_depth_frames([b"frame"], ours, theirs)


class TestMain:
    def test_fixture_times_exactly_that_capture(
        self, timed: dict[str, list[bytes]]
    ) -> None:
        assert benchmark.main(["--fixture", "ospf.pcap"]) == 0
        assert timed["measure"] == OSPF
        assert "compare" not in timed

    def test_fixtures_combine(self, timed: dict[str, list[bytes]]) -> None:
        assert benchmark.main(["--fixture", "ospf", "--fixture", "bgp"]) == 0
        assert timed["measure"] == BGP + OSPF

    def test_an_unknown_fixture_is_a_usage_error(
        self,
        timed: dict[str, list[bytes]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        with pytest.raises(SystemExit) as caught:
            benchmark.main(["--fixture", "nope"])
        assert caught.value.code == 2
        error = capsys.readouterr().err
        assert "unknown fixture nope.pcap; choose from: " in error
        assert "ospf.pcap" in error
        assert timed == {}

    def test_same_depth_times_only_equal_depth_frames_and_compares(
        self,
        timed: dict[str, list[bytes]],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        keep = set(OSPF)

        def dpkt_chain(frame: bytes) -> list[str]:
            ours: list[str] = benchmark._netprotocols_chain(frame)
            return ours if frame in keep else [*ours, "Extra"]

        monkeypatch.setattr(benchmark, "_dpkt_chain", dpkt_chain)
        assert benchmark.main(["--same-depth"]) == 0
        assert timed["measure"] == OSPF
        assert timed["compare"] == OSPF
        out = capsys.readouterr().out
        assert f"selected {len(OSPF)} of {CORPUS_SIZE} corpus frames" in out
        assert "scapy's depth is not checked" in out

    def test_same_depth_without_dpkt_is_a_usage_error(
        self,
        timed: dict[str, list[bytes]],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        def dpkt_chain(frame: bytes) -> list[str]:
            raise ImportError("no dpkt")

        monkeypatch.setattr(benchmark, "_dpkt_chain", dpkt_chain)
        with pytest.raises(SystemExit) as caught:
            benchmark.main(["--same-depth", "--fixture", "ospf"])
        assert caught.value.code == 2
        assert "--same-depth needs dpkt" in capsys.readouterr().err
        assert timed == {}

    def test_an_empty_selection_times_nothing(
        self,
        timed: dict[str, list[bytes]],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            benchmark, "_dpkt_chain", lambda frame: ["A", "B", "C", "D", "E"]
        )
        assert benchmark.main(["--same-depth", "--fixture", "lldp"]) == 1
        assert timed == {}

    def test_json_records_the_selection(
        self,
        timed: dict[str, list[bytes]],
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        keep = set(OSPF[:5])

        def dpkt_chain(frame: bytes) -> list[str]:
            ours: list[str] = benchmark._netprotocols_chain(frame)
            return ours if frame in keep else [*ours, "Extra"]

        monkeypatch.setattr(benchmark, "_dpkt_chain", dpkt_chain)
        output = tmp_path / "result.json"
        arguments = ["--fixture", "ospf", "--fixture", "bgp.pcap"]
        assert benchmark.main([*arguments, "--json", str(output)]) == 0
        assert json.loads(output.read_text())["selection"] == {
            "fixtures": ["bgp.pcap", "ospf.pcap"],
            "same_depth": False,
            "frames_selected": len(BGP) + len(OSPF),
            "frames_total": CORPUS_SIZE,
        }
        arguments.append("--same-depth")
        assert benchmark.main([*arguments, "--json", str(output)]) == 0
        assert json.loads(output.read_text())["selection"] == {
            "fixtures": ["bgp.pcap", "ospf.pcap"],
            "same_depth": True,
            "frames_selected": sum(frame in keep for frame in BGP + OSPF),
            "frames_total": CORPUS_SIZE,
        }

    def test_no_selection_records_the_whole_corpus(
        self, timed: dict[str, list[bytes]], tmp_path: Path
    ) -> None:
        output = tmp_path / "result.json"
        assert benchmark.main(["--json", str(output)]) == 0
        assert len(timed["measure"]) == CORPUS_SIZE
        assert json.loads(output.read_text())["selection"] == {
            "fixtures": [],
            "same_depth": False,
            "frames_selected": CORPUS_SIZE,
            "frames_total": CORPUS_SIZE,
        }
