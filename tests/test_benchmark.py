"""Tests for scripts/benchmark.py's workload selection and depth report.

``--fixture`` and ``--same-depth`` pick the frames the benchmark times.
The tests replace the timing functions with recorders, so they check
which frames reach the timer without timing anything, and replace
dpkt's layer chain and its import check with stand-ins, so they run
without dpkt.
"""

import importlib.util
import json
import sys
from importlib.machinery import ModuleSpec
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
        frames: list[bytes],
        repetitions: int,
        trials: int,
        same_protocols: bool = False,
    ) -> list[str]:
        seen["compare"] = list(frames)
        seen["same_protocols"] = [b"yes"] if same_protocols else []
        return []

    monkeypatch.setattr(benchmark, "measure", measure)
    monkeypatch.setattr(benchmark, "compare", compare)
    monkeypatch.setattr(benchmark, "has_dpkt", lambda: True)
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

    def test_the_extension_matches_in_any_letter_case(self) -> None:
        assert benchmark.select_frames(CAPTURES, ["c.PCAP", "a.Pcap"]) == [
            b"a1",
            b"c1",
        ]

    def test_an_unknown_name_raises_and_lists_the_captures(self) -> None:
        with pytest.raises(ValueError) as caught:
            benchmark.select_frames(CAPTURES, ["a", "nope"])
        assert str(caught.value) == (
            "unknown fixture nope.pcap; choose from: a.pcap, b.pcap, c.pcap"
        )


#: netprotocols' and dpkt's chains for frames on which they decode the
#: same protocols, one for each folded name and each renamed protocol.
SAME_WORK = {
    "VLAN and Echo": (
        ["Ethernet", "VLAN", "VLAN", "IPv4", "ICMPv4"],
        ["Ethernet", "IP", "ICMP", "Echo", "<56 raw bytes>"],
    ),
    "MPLS": (
        ["Ethernet", "MPLS", "IPv6", "UDP"],
        ["Ethernet", "IP6", "UDP", "<8 raw bytes>"],
    ),
    "SNAP": (["Ethernet", "LLC", "SNAP", "ARP"], ["Ethernet", "LLC", "ARP"]),
    "IPv6Fragment": (
        ["Ethernet", "IPv6", "IPv6Fragment", "ICMPv6"],
        ["Ethernet", "IP6", "ICMP6", "Echo", "<56 raw bytes>"],
    ),
    "IPv6HopByHopOptions": (
        ["Ethernet", "IPv6", "IPv6HopByHopOptions", "ICMPv6"],
        ["Ethernet", "IP6", "ICMP6", "<24 raw bytes>"],
    ),
    "TimeExceed": (
        ["Ethernet", "IPv4", "ICMPv4"],
        ["Ethernet", "IP", "ICMP", "TimeExceed", "<4 raw bytes>"],
    ),
    "Unreach": (
        ["Ethernet", "IPv4", "ICMPv4"],
        ["Ethernet", "IP", "ICMP", "Unreach", "<4 raw bytes>"],
    ),
    "str": (["Ethernet", "IPv4", "VRRP"], ["Ethernet", "IP", "VRRP", "str"]),
}

#: Chains on which the two decode different protocols.
DIFFERENT_WORK = {
    "netprotocols further": (
        ["Ethernet", "IPv4", "UDP", "DHCP"],
        ["Ethernet", "IP", "UDP", "<300 raw bytes>"],
    ),
    "dpkt decodes the quoted packet": (
        ["Ethernet", "IPv4", "ICMPv4"],
        ["Ethernet", "IP", "ICMP", "TimeExceed", "IP", "ICMP", "Echo"],
    ),
    "dpkt decodes an MPLS pseudowire": (
        ["Ethernet", "MPLS"],
        ["Ethernet", "Ethernet", "IP", "ICMP", "Echo", "<56 raw bytes>"],
    ),
    "the inner protocol differs": (
        ["Ethernet", "LLC"],
        ["Ethernet", "IPX", "<14 raw bytes>"],
    ),
    "a folded name in the other library's chain": (
        ["Ethernet", "IPv4", "ICMPv4", "Echo"],
        ["Ethernet", "IP", "ICMP", "Echo"],
    ),
}


class TestSameWork:
    @pytest.mark.parametrize("chains", SAME_WORK.values(), ids=SAME_WORK)
    def test_folded_chains_that_match(
        self, chains: tuple[list[str], list[str]]
    ) -> None:
        assert benchmark.same_work(*chains)

    @pytest.mark.parametrize(
        "chains", DIFFERENT_WORK.values(), ids=DIFFERENT_WORK
    )
    def test_folded_chains_that_differ(
        self, chains: tuple[list[str], list[str]]
    ) -> None:
        assert not benchmark.same_work(*chains)

    def test_every_folded_name_has_a_case(self) -> None:
        theirs = {name for _, chain in SAME_WORK.values() for name in chain}
        ours = {name for chain, _ in SAME_WORK.values() for name in chain}
        assert ours >= benchmark.NETPROTOCOLS_FOLDED
        assert theirs >= benchmark.DPKT_FOLDED

    def test_folded_chain_uses_common_names(self) -> None:
        assert benchmark.folded_chain(
            ["Ethernet", "IP6", "ICMP6", "Echo", "<8 raw bytes>"],
            benchmark.DPKT_FOLDED,
        ) == ["Ethernet", "ip6", "icmp6"]


class TestSameWorkFrames:
    def test_selects_only_frames_of_the_same_protocols(self) -> None:
        ours, theirs = _chains(
            {
                b"equal": (["Ethernet", "IPv4"], ["Ethernet", "IP"]),
                b"folded": (
                    ["Ethernet", "VLAN", "IPv4", "UDP"],
                    ["Ethernet", "IP", "UDP", "<8 raw bytes>"],
                ),
                b"deeper": (["Ethernet", "IPv4", "UDP"], ["Ethernet", "IP"]),
                b"shallower": (["Ethernet"], ["Ethernet", "IP"]),
                b"other": (["Ethernet", "LLC"], ["Ethernet", "IPX"]),
                b"ours rejects": (ProtocolError("bad"), ["Ethernet"]),
                b"theirs rejects": (["Ethernet"], ValueError("bad")),
            }
        )
        frames = [
            b"deeper",
            b"equal",
            b"ours rejects",
            b"other",
            b"folded",
            b"theirs rejects",
            b"shallower",
        ]
        assert benchmark.same_work_frames(frames, ours, theirs) == [
            b"equal",
            b"folded",
        ]

    def test_a_missing_library_raises(self) -> None:
        ours, theirs = _chains(
            {b"frame": (["Ethernet"], ImportError("no dpkt"))}
        )
        with pytest.raises(ImportError):
            benchmark.same_work_frames([b"frame"], ours, theirs)


class TestDepthReport:
    def test_counts_deeper_and_same_by_raw_layer_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        table = {
            b"equal": (["Ethernet", "IPv4"], ["Ethernet", "IP"]),
            b"deeper": (
                ["Ethernet", "IPv4", "UDP", "DHCP"],
                ["Ethernet", "IP", "UDP", "<300 raw bytes>"],
            ),
            b"folded deeper": (
                ["Ethernet", "VLAN", "IPv4"],
                ["Ethernet", "IP"],
            ),
            b"theirs deeper": (
                ["Ethernet", "IPv4", "VRRP"],
                ["Ethernet", "IP", "VRRP", "str"],
            ),
            b"ours rejects": (ProtocolError("bad"), ["Ethernet"]),
            b"theirs rejects": (["Ethernet"], ValueError("bad")),
        }
        ours, theirs = _chains(table)
        monkeypatch.setattr(benchmark, "_netprotocols_chain", ours)
        monkeypatch.setattr(benchmark, "_dpkt_chain", theirs)
        assert benchmark.depth_report(list(table)) == [
            "",
            "Decode depth on the same frames:",
            "",
            "  netprotocols decodes further on 2 frames",
            "  both stop at the same layer on 2 frames",
            "",
            "  A frame where they differ:",
            "    netprotocols: Ethernet -> IPv4 -> UDP -> DHCP\n"
            "    dpkt:         Ethernet -> IP -> UDP -> <300 raw bytes>",
        ]

    def test_without_dpkt_it_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ours, theirs = _chains({b"frame": (["Ethernet"], ImportError("no"))})
        monkeypatch.setattr(benchmark, "_netprotocols_chain", ours)
        monkeypatch.setattr(benchmark, "_dpkt_chain", theirs)
        assert benchmark.depth_report([b"frame"])[-1] == (
            "  dpkt not installed - skipped"
        )


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

    def test_same_depth_times_only_same_work_frames_and_compares(
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
        assert timed["same_protocols"]
        out = capsys.readouterr().out
        assert f"Selected {len(OSPF)} of {CORPUS_SIZE} corpus frames:" in out
        assert f"— {len(OSPF)} of {CORPUS_SIZE} corpus frames, " in out
        assert "(scapy's are not checked)" in out

    def test_compare_alone_prints_the_full_corpus_caveats(
        self,
        timed: dict[str, list[bytes]],
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        assert benchmark.main(["--compare"]) == 0
        assert not timed["same_protocols"]
        out = capsys.readouterr().out
        assert f"— {CORPUS_SIZE} corpus frames, " in out
        assert "Selected" not in out

    @pytest.mark.parametrize(
        "arguments", [["--fixture", "ospf"], ["--fixture", "tcp_https"]]
    )
    def test_same_depth_without_dpkt_is_a_usage_error(
        self,
        arguments: list[str],
        timed: dict[str, list[bytes]],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        def rejects(frame: bytes) -> list[str]:
            raise ProtocolError("bad")

        monkeypatch.setattr(benchmark, "has_dpkt", lambda: False)
        monkeypatch.setattr(benchmark, "_netprotocols_chain", rejects)
        with pytest.raises(SystemExit) as caught:
            benchmark.main(["--same-depth", *arguments])
        assert caught.value.code == 2
        assert "--same-depth needs dpkt" in capsys.readouterr().err
        assert timed == {}

    def test_an_empty_selection_prints_it_and_times_nothing(
        self,
        timed: dict[str, list[bytes]],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setattr(
            benchmark, "_dpkt_chain", lambda frame: ["A", "B", "C", "D", "E"]
        )
        assert benchmark.main(["--same-depth", "--fixture", "lldp"]) == 1
        assert timed == {}
        captured = capsys.readouterr()
        assert captured.out.splitlines() == [
            f"Selected 0 of {CORPUS_SIZE} corpus frames:",
            "  6 frames in lldp.pcap",
            "  0 of 6 decoded to the same protocols by netprotocols and"
            " dpkt (scapy's are not checked)",
        ]
        assert captured.err == "No frames selected\n"

    def test_the_fixture_extension_matches_in_any_letter_case(
        self, timed: dict[str, list[bytes]]
    ) -> None:
        assert benchmark.main(["--fixture", "ospf.PCAP"]) == 0
        assert timed["measure"] == OSPF

    def test_the_selection_restricts_the_depth_report(
        self,
        timed: dict[str, list[bytes]],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        keep = set(OSPF[:5])

        def dpkt_chain(frame: bytes) -> list[str]:
            ours: list[str] = benchmark._netprotocols_chain(frame)
            return ours if frame in keep else [*ours[:-1], "Other"]

        monkeypatch.setattr(benchmark, "_dpkt_chain", dpkt_chain)
        assert benchmark.main(["--depth", "--fixture", "ospf"]) == 0
        out = capsys.readouterr().out
        assert f"same layer on {len(OSPF)} frames" in out
        assert benchmark.main(["--depth", "--same-depth"]) == 0
        out = capsys.readouterr().out
        assert "further on 0 frames" in out
        assert "same layer on 5 frames" in out


class TestHasDpkt:
    def test_false_when_dpkt_cannot_be_imported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "dpkt", None)
        assert not benchmark.has_dpkt()

    def test_true_when_dpkt_can_be_imported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = ModuleType("dpkt")
        module.__spec__ = ModuleSpec("dpkt", None)
        monkeypatch.setitem(sys.modules, "dpkt", module)
        assert benchmark.has_dpkt()

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
