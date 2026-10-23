"""Tests for scripts/extract_http_streams.py.

The extractor turns tests/fixtures/http/http.pcap into the byte streams
the HTTP tests and the Atheris harness read, so a stream it got wrong
would test the codec against bytes that were never on the wire. It must
therefore refuse, not guess, whenever the capture is not one it can
reassemble exactly; each refusal gets a test here, next to the run over
the committed capture.
"""

import importlib.util
import struct
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
CAPTURE = ROOT / "tests" / "fixtures" / "http" / "http.pcap"


def _load_extractor() -> ModuleType:
    # The script imports its sibling _pcap.py the way it does when run.
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(
            "extract_http_streams", SCRIPTS / "extract_http_streams.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # @dataclass looks its class's module up in sys.modules.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(SCRIPTS))


extractor = _load_extractor()

CLIENT = bytes([10, 0, 0, 2])
SERVER = bytes([10, 0, 0, 1])
SYN, ACK = 0x02, 0x10


def frame(
    seq: int,
    payload: bytes = b"",
    *,
    flags: int = ACK,
    to_server: bool = True,
    sport: int = 40000,
    ethertype: int = 0x0800,
    proto: int = 6,
    fragment: int = 0,
) -> bytes:
    """An Ethernet/IPv4/TCP frame, checksums zeroed (the extractor
    never reads them)."""
    src, dst = (CLIENT, SERVER) if to_server else (SERVER, CLIENT)
    ports = (sport, 80) if to_server else (80, sport)
    tcp = struct.pack("!HHIIBBHHH", *ports, seq, 0, 5 << 4, flags, 0, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, total, 0, fragment, 64, proto, 0, src, dst
    )
    return b"\x00" * 12 + struct.pack("!H", ethertype) + ip + tcp + payload


class TestExtract:
    def test_streams_are_ordered_by_sequence_number(self) -> None:
        frames = [
            frame(100, flags=SYN),
            frame(500, flags=SYN, to_server=False),
            frame(105, b"world"),  # arrives first, belongs second
            frame(101, b"hell"),
            frame(101, b"hell"),  # a retransmission is fine
            frame(501, b"reply", to_server=False),
        ]
        assert extractor.extract(frames, 80) == [(b"hellworld", b"reply")]

    def test_an_overlap_with_the_same_bytes_is_fine(self) -> None:
        frames = [frame(0, flags=SYN), frame(1, b"abcd"), frame(3, b"cdef")]
        frames.append(frame(9, flags=SYN, to_server=False))
        assert extractor.extract(frames, 80) == [(b"abcdef", b"")]

    def test_the_sequence_space_wraps(self) -> None:
        frames = [
            frame(0xFFFFFFFE, flags=SYN),
            frame(0xFFFFFFFF, b"ab"),
            frame(1, b"cd"),
            frame(7, flags=SYN, to_server=False),
        ]
        assert extractor.extract(frames, 80) == [(b"abcd", b"")]

    def test_connections_keep_the_order_they_opened_in(self) -> None:
        frames = []
        for port in (40002, 40001):
            frames += [
                frame(0, flags=SYN, sport=port),
                frame(0, flags=SYN, sport=port, to_server=False),
                frame(1, str(port).encode(), sport=port),
            ]
        assert extractor.extract(frames, 80) == [
            (b"40002", b""),
            (b"40001", b""),
        ]

    def test_other_ports_are_ignored(self) -> None:
        frames = [frame(0, b"x", flags=SYN, sport=40000)]
        assert extractor.extract(frames, 443) == []

    @pytest.mark.parametrize(
        "frames,message",
        [
            (
                [frame(0, flags=SYN), frame(5, b"late")],
                "gap before seq 5",
            ),
            (
                [frame(0, flags=SYN), frame(1, b"abc"), frame(2, b"xc")],
                "overlap at seq 2 differs",
            ),
            (
                [frame(0, flags=SYN), frame(1, b"abc"), frame(1, b"abd")],
                "retransmitted differently",
            ),
            ([frame(1, b"no syn")], "no SYN"),
        ],
        ids=["gap", "overlap", "retransmit", "no-syn"],
    )
    def test_refuses_a_stream_it_cannot_rebuild_exactly(
        self, frames: list[bytes], message: str
    ) -> None:
        frames.append(frame(0, flags=SYN, to_server=False))
        with pytest.raises(ValueError, match=message):
            extractor.extract(frames, 80)

    @pytest.mark.parametrize(
        "bad,message",
        [
            (frame(0, ethertype=0x86DD), "is not IPv4"),
            (frame(0, proto=17), "is not TCP"),
            (frame(0, fragment=0x2000), "fragments"),
        ],
        ids=["ipv6", "udp", "fragment"],
    )
    def test_refuses_frames_it_does_not_parse(
        self, bad: bytes, message: str
    ) -> None:
        with pytest.raises(ValueError, match=message):
            extractor.extract([bad], 80)


class TestMain:
    def test_the_committed_capture_extracts_to_the_committed_streams(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert extractor.main([str(CAPTURE), str(tmp_path)]) == 0
        written = sorted(path.name for path in tmp_path.iterdir())
        committed = CAPTURE.parent
        assert written == sorted(
            path.name for path in committed.iterdir() if path.suffix != ".pcap"
        )
        for name in written:
            assert (tmp_path / name).read_bytes() == (
                committed / name
            ).read_bytes()
        assert "07: 139 request bytes, 599 response bytes" in (
            capsys.readouterr().out
        )

    def test_no_connection_is_an_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert extractor.main([str(CAPTURE), str(tmp_path), "--port", "1"]) == 1
        assert "no TCP connection to port 1" in capsys.readouterr().err
