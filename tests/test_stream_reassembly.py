"""Tests for netprotocols.reassembly's StreamReassembler.

Every frame the helpers below build is **crafted**: IPv4 and IPv6 TCP
segments written byte by byte, with checksums computed unless a test
breaks one on purpose, to reach the rules of the design note's section
4 that real stacks do not exercise on demand. The real captures are
``tests/fixtures/http/http.pcap``, ``tests/fixtures/tls/tls_session.pcap``
and ``tests/fixtures/reassembly/http_stream.pcap`` (see
``tests/fixtures/MANIFEST.md``).
"""

from __future__ import annotations

import hashlib
import ipaddress
import itertools
import struct
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import netprotocols
from conftest import FIXTURES
from netprotocols import HTTP, IPv4, IPv6, TruncatedHeaderError, decode_frame
from netprotocols.checksum import internet_checksum
from netprotocols.flow import FlowKey
from netprotocols.packet import Packet
from netprotocols.pcap import read_pcap
from netprotocols.reassembly import (
    FLOW_OVERHEAD,
    PIECE_OVERHEAD,
    SECOND,
    Anomaly,
    AnomalyKind,
    Bound,
    ChecksumMode,
    Direction,
    EndReason,
    Evicted,
    Expired,
    Gap,
    GapReason,
    LateData,
    OutOfOrder,
    Overlap,
    OverlapPolicy,
    Retransmission,
    Span,
    StreamBounds,
    StreamData,
    StreamEnd,
    StreamEvent,
    StreamReassembler,
    Timeout,
    Usage,
)

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from _pcap import read_pcap as read_frames
from extract_http_streams import extract

# --- crafted frames ---------------------------------------------------

A = "192.0.2.1"
B = "192.0.2.2"
A6 = "2001:db8::1"
B6 = "2001:db8::2"
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
#: The key of every crafted IPv4 connection: A:40000 is addr_a.
KEY = FlowKey(A, B, 40000, 80, 6)


def packed(address: str) -> bytes:
    return ipaddress.ip_address(address).packed


def pseudo_sum(src: str, dst: str, length: int) -> int:
    """The folded pseudo-header sum a stack leaves for its NIC."""
    if ":" in src:
        header = packed(src) + packed(dst) + struct.pack("!I3xB", length, 6)
    else:
        header = packed(src) + packed(dst) + struct.pack("!xBH", 6, length)
    return ~internet_checksum(header) & 0xFFFF


def tcp_header(
    seq: int,
    ack: int,
    flags: int,
    *,
    sport: int,
    dport: int,
    window: int = 65535,
    options: bytes = b"",
) -> bytes:
    offset = 5 + len(options) // 4
    return (
        struct.pack(
            "!HHIIHHHH",
            sport,
            dport,
            seq % 2**32,
            ack % 2**32,
            (offset << 12) | flags,
            window,
            0,
            0,
        )
        + options
    )


def segment(
    seq: int,
    ack: int = 0,
    flags: int = ACK,
    data: bytes = b"",
    *,
    src: str = A,
    dst: str = B,
    sport: int = 40000,
    dport: int = 80,
    window: int = 65535,
    options: bytes = b"",
    ttl: int = 64,
    checksum: int | None = None,
    ip_checksum: int | None = None,
    total: int | None = None,
    cut: int = 0,
) -> bytes:
    """A crafted IPv4 TCP segment; ``checksum`` overrides the TCP one,
    ``total`` the Total Length, and ``cut`` drops captured bytes."""
    tcp = tcp_header(
        seq,
        ack,
        flags,
        sport=sport,
        dport=dport,
        window=window,
        options=options,
    )
    length = len(tcp) + len(data)
    if checksum is None:
        checksum = internet_checksum(
            packed(src)
            + packed(dst)
            + struct.pack("!xBH", 6, length)
            + tcp
            + data
        )
    tcp = tcp[:16] + struct.pack("!H", checksum) + tcp[18:]
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + length if total is None else total,
        1,
        0x4000,
        ttl,
        6,
        0,
        packed(src),
        packed(dst),
    )
    if ip_checksum is None:
        ip_checksum = internet_checksum(header)
    header = header[:10] + struct.pack("!H", ip_checksum) + header[12:]
    frame = header + tcp + data
    return frame[: len(frame) - cut]


def segment6(
    seq: int,
    ack: int = 0,
    flags: int = ACK,
    data: bytes = b"",
    *,
    src: str = A6,
    dst: str = B6,
    sport: int = 40000,
    dport: int = 80,
    payload_length: int | None = None,
    checksum: int | None = None,
) -> bytes:
    """A crafted IPv6 TCP segment."""
    tcp = tcp_header(seq, ack, flags, sport=sport, dport=dport)
    length = len(tcp) + len(data)
    if checksum is None:
        checksum = internet_checksum(
            packed(src)
            + packed(dst)
            + struct.pack("!I3xB", length, 6)
            + tcp
            + data
        )
    tcp = tcp[:16] + struct.pack("!H", checksum) + tcp[18:]
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        length if payload_length is None else payload_length,
        6,
        64,
        packed(src),
        packed(dst),
    )
    return header + tcp + data


def packet_of(frame: bytes) -> Packet:
    start = IPv6 if frame[0] >> 4 == 6 else IPv4
    return decode_frame(frame, start=start, lax=True)


def only[T](events: Iterable[object], kind: type[T]) -> list[T]:
    return [event for event in events if isinstance(event, kind)]


def kinds(events: Iterable[object]) -> list[AnomalyKind]:
    return [event.kind for event in only(events, Anomaly)]


def tiles(spans: tuple[Span, ...], start: int, end: int) -> bool:
    cursor = start
    for span in spans:
        if span.start != cursor:
            return False
        cursor = span.end
    return cursor == end


class Talk:
    """A crafted connection between A:40000 (side a) and B:80 (side b).

    ``a()`` and ``b()`` send a segment at a stream offset of their
    direction, which maps to ``isn + 1 + offset``; ``ack`` is an offset
    of the other direction. Each frame gets the next ref and, unless
    given, a timestamp one second after the previous one.
    """

    def __init__(
        self,
        reassembler: StreamReassembler | None = None,
        *,
        isn_a: int = 1000,
        isn_b: int = 9000,
        **kwargs: object,
    ) -> None:
        self.r = reassembler or StreamReassembler(**kwargs)  # type: ignore[arg-type]
        self.isn = {0: isn_a, 1: isn_b}
        self.ref = 0
        self.ts = 0
        self.events: list[StreamEvent] = []

    def send(
        self, frame: bytes, ts: int | None = None
    ) -> tuple[StreamEvent, ...]:
        self.ts = self.ts + SECOND if ts is None else ts
        events = self.r.feed(
            packet_of(frame), frame, timestamp=self.ts, ref=self.ref
        )
        self.ref += 1
        self.events += events
        return events

    def seg(
        self,
        side: int,
        offset: int,
        data: bytes = b"",
        flags: int = ACK,
        ack: int | None = None,
        ts: int | None = None,
        **kwargs: object,
    ) -> tuple[StreamEvent, ...]:
        src, dst, sport, dport = (
            (A, B, 40000, 80) if side == 0 else (B, A, 80, 40000)
        )
        ackno = 0 if ack is None else self.isn[1 - side] + 1 + ack
        frame = segment(
            self.isn[side] + 1 + offset,
            ackno,
            flags,
            data,
            src=src,
            dst=dst,
            sport=sport,
            dport=dport,
            **kwargs,  # type: ignore[arg-type]
        )
        return self.send(frame, ts)

    def a(
        self, offset: int, data: bytes = b"", **kwargs: object
    ) -> tuple[StreamEvent, ...]:
        return self.seg(0, offset, data, **kwargs)  # type: ignore[arg-type]

    def b(
        self, offset: int, data: bytes = b"", **kwargs: object
    ) -> tuple[StreamEvent, ...]:
        return self.seg(1, offset, data, **kwargs)  # type: ignore[arg-type]

    def syn(self, side: int = 0, **kwargs: object) -> tuple[StreamEvent, ...]:
        flags = SYN if side == 0 else SYN | ACK
        ack = None if side == 0 else 0
        return self.seg(side, -1, flags=flags, ack=ack, **kwargs)  # type: ignore[arg-type]

    def handshake(self, **kwargs: object) -> None:
        self.syn(0, **kwargs)
        self.syn(1, **kwargs)
        self.a(0, ack=0)

    def stream(self, side: int) -> bytes:
        direction = Direction.A_TO_B if side == 0 else Direction.B_TO_A
        return b"".join(
            event.data
            for event in only(self.events, StreamData)
            if event.direction is direction
        )


# --- API --------------------------------------------------------------


class TestStreamAPI:
    def test_names_are_in_all_and_not_reexported(self) -> None:
        import netprotocols.reassembly as module

        for name in (
            "StreamReassembler",
            "StreamBounds",
            "StreamData",
            "StreamEnd",
            "StreamEvent",
            "OutOfOrder",
            "Gap",
            "GapReason",
            "LateData",
            "EndReason",
        ):
            assert name in module.__all__
            assert not hasattr(netprotocols, name)
        assert GapReason.ACKED.value == "acked"
        for kind in ("RST_RECEIVED", "SYN_AFTER_RST", "ACK_BEYOND_DATA"):
            assert hasattr(AnomalyKind, kind)

    def test_defaults(self) -> None:
        bounds = StreamBounds()
        assert bounds.max_flow_bytes == 4 * 1024 * 1024
        assert bounds.max_total_bytes == 128 * 1024 * 1024
        assert bounds.max_flows == 65_536
        assert bounds.retain_bytes == 64 * 1024
        assert bounds.idle_timeout_new == 60 * SECOND
        assert bounds.idle_timeout_established == 3_600 * SECOND
        assert bounds.idle_timeout_closed == 120 * SECOND
        assert bounds.age_timeout is None
        assert bounds.ack_gap_grace == SECOND

    @pytest.mark.parametrize(
        "changes",
        [
            {"max_flow_bytes": 0},
            {"max_total_bytes": -1},
            {"max_flows": True},
            {"retain_bytes": 1.5},
            {"ack_gap_grace": None},
            {"idle_timeout_new": 0},
            {"idle_timeout_established": "1"},
            {"idle_timeout_closed": -5},
            {"age_timeout": 0},
        ],
    )
    def test_invalid_bounds(self, changes: dict[str, object]) -> None:
        with pytest.raises(ValueError):
            StreamBounds(**changes)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"policy": OverlapPolicy.BSD},
            {"policy": "first"},
            {"targets": {"10.0.0.0/8": OverlapPolicy.LINUX}},
            {"targets": {"10.0.0.0/8": "last"}},
            {"targets": {"not a network": OverlapPolicy.LAST}},
            {"targets": {7: OverlapPolicy.LAST}},
            {"checksums": "drop"},
            {"local": "10.0.0.1"},
            {"local": ["10.0.0.0/33"]},
        ],
    )
    def test_constructor_rejects(self, kwargs: dict[str, object]) -> None:
        with pytest.raises(ValueError):
            StreamReassembler(**kwargs)  # type: ignore[arg-type]

    def test_constructor_rejects_bounds_of_another_type(self) -> None:
        from netprotocols.reassembly import FragmentBounds

        with pytest.raises(TypeError):
            StreamReassembler(bounds=FragmentBounds())  # type: ignore[arg-type]

    def test_feed_rejects_wrong_types(self) -> None:
        reassembler = StreamReassembler()
        frame = segment(1)
        packet = packet_of(frame)
        with pytest.raises(TypeError):
            reassembler.feed(frame, frame, timestamp=1)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            reassembler.feed(packet, "x", timestamp=1)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            reassembler.feed(packet, frame, timestamp=1.0)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            reassembler.feed(packet, frame, timestamp=1, ref="1")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            reassembler.feed(packet, frame, timestamp=-1)
        with pytest.raises(ValueError):
            reassembler.feed(packet, frame[:30], timestamp=1)
        with pytest.raises(ValueError):
            reassembler.advance(-1)
        with pytest.raises(TypeError):
            reassembler.advance(True)

    def test_events_are_frozen_slotted_and_keyword_only(self) -> None:
        talk = Talk()
        talk.syn()
        (data,) = talk.a(0, b"hello", ack=None)
        assert isinstance(data, StreamData)
        with pytest.raises(FrozenInstanceError):
            data.offset = 1  # type: ignore[misc]
        assert not hasattr(data, "__dict__")
        with pytest.raises(TypeError):
            StreamData(KEY, None, (), None, 0, 0, 0, b"")  # type: ignore[misc]
        assert data.refs == (1,)

    def test_a_packet_without_tcp_returns_only_expiries(self) -> None:
        reassembler = StreamReassembler(
            bounds=StreamBounds(idle_timeout_new=10)
        )
        frame = segment(1, flags=SYN)
        reassembler.feed(packet_of(frame), frame, timestamp=1)
        udp = bytes.fromhex("450000200001000040110000c0000201c0000202")
        udp += bytes.fromhex("0035003500080000") + b"abcd"
        events = reassembler.feed(packet_of(udp), udp, timestamp=100)
        assert [type(event) for event in events] == [StreamEnd, Expired]
        assert reassembler.feed(packet_of(udp), udp, timestamp=200) == ()

    def test_a_tcp_layer_inside_a_fragment_is_not_taken(self) -> None:
        first = bytearray(segment(1, data=b"x" * 16))
        first[6:8] = b"\x20\x00"
        first[10:12] = b"\x00\x00"
        first[10:12] = internet_checksum(bytes(first[:20])).to_bytes(2, "big")
        reassembler = StreamReassembler()
        frame = bytes(first)
        assert reassembler.feed(packet_of(frame), frame, timestamp=1) == ()
        assert reassembler.usage == Usage(0, 0)

    def test_ref_defaults_to_the_count_of_frames_fed(self) -> None:
        reassembler = StreamReassembler()
        frames = [segment(1001, flags=SYN), segment(1002, data=b"ab")]
        events = [
            reassembler.feed(packet_of(frame), frame, timestamp=1)
            for frame in frames
        ]
        assert events[1][0].completing_ref == 1

    def test_bytearray_and_memoryview_frames(self) -> None:
        for wrap in (bytearray, memoryview):
            reassembler = StreamReassembler()
            frame = segment(7, data=b"abc")
            (anomaly, data) = reassembler.feed(
                packet_of(frame), wrap(frame), timestamp=1
            )
            assert anomaly.kind is AnomalyKind.MIDSTREAM
            assert data.data == b"abc"

    def test_ipv6_segments_reassemble(self) -> None:
        reassembler = StreamReassembler()
        frames = [segment6(10, flags=SYN), segment6(11, data=b"six")]
        events = [
            event
            for index, frame in enumerate(frames)
            for event in reassembler.feed(
                packet_of(frame), frame, timestamp=index + 1
            )
        ]
        (data,) = only(events, StreamData)
        assert data.data == b"six"
        assert data.flow == FlowKey(A6, B6, 40000, 80, 6)


# --- 4.1 to 4.3: flows, offsets, wraparound ----------------------------


class TestOffsets:
    def test_direction_is_relative_to_the_key(self) -> None:
        talk = Talk()
        talk.handshake()
        (forward,) = talk.a(0, b"GET", ack=0)
        (backward,) = talk.b(0, b"200", ack=3)
        assert forward.direction is Direction.A_TO_B
        assert backward.direction is Direction.B_TO_A
        assert forward.flow == backward.flow == KEY

    def test_offset_zero_is_the_byte_after_the_isn(self) -> None:
        talk = Talk()
        talk.syn()
        (data,) = talk.a(0, b"first")
        assert data.offset == 0
        assert data.spans == (Span(1, 0, 5, 2 * SECOND, 64),)
        (data,) = talk.a(5, b"second")
        assert data.offset == 5
        assert data.completing_ref == 2

    def test_self_connected(self) -> None:
        reassembler = StreamReassembler()
        frame = segment(5, flags=SYN, src=A, dst=A, sport=7, dport=7)
        events = reassembler.feed(packet_of(frame), frame, timestamp=1)
        assert kinds(events) == [AnomalyKind.SELF_CONNECTED]
        assert events[0].direction is Direction.A_TO_B

    def test_midstream_pickup(self) -> None:
        talk = Talk()
        events = talk.a(100, b"middle")
        assert kinds(events) == [AnomalyKind.MIDSTREAM]
        (data,) = only(events, StreamData)
        assert data.offset == 0
        events = talk.a(106, b"more")
        assert only(events, StreamData)[0].offset == 6
        assert not kinds(events)

    def test_data_before_stream_start_is_dropped(self) -> None:
        talk = Talk()
        talk.a(100, b"middle")
        events = talk.a(90, b"0123456789ab")
        assert kinds(events) == [AnomalyKind.BEFORE_STREAM_START]
        assert (events[0].start, events[0].end) == (-10, 2)
        assert not only(events, StreamData)

    def test_a_bare_fin_picks_up_mid_stream(self) -> None:
        talk = Talk()
        events = talk.a(50, flags=FIN | ACK)
        assert kinds(events) == [AnomalyKind.MIDSTREAM]
        assert only(events, StreamEnd)[0].offset == 0

    @pytest.mark.parametrize("isn", [2**32 - 1, 2**32 - 3, 2**32 - 10])
    def test_a_sequence_wrap_inside_a_stream(self, isn: int) -> None:
        talk = Talk(isn_a=isn)
        talk.syn()
        talk.a(4, b"efgh")
        events = talk.a(0, b"abcd")
        (data,) = only(events, StreamData)
        assert (data.offset, data.data) == (0, b"abcdefgh")
        talk.a(8, b"ijklmnop")
        talk.a(12, b"mnop")
        assert talk.stream(0) == b"abcdefghijklmnop"

    def test_a_retransmission_across_the_wrap(self) -> None:
        talk = Talk(isn_a=2**32 - 3)
        talk.syn()
        talk.a(0, b"abcdef")
        (repeat,) = talk.a(0, b"abcdef")
        assert isinstance(repeat, Retransmission)
        assert (repeat.start, repeat.end, repeat.verified) == (0, 6, True)


# --- 4.4: control flags ---------------------------------------------


class TestFlags:
    def test_data_on_syn(self) -> None:
        talk = Talk()
        events = talk.seg(0, -1, b"fast open", flags=SYN)
        assert kinds(events) == [AnomalyKind.SYN_DATA]
        (data,) = only(events, StreamData)
        assert (data.offset, data.data) == (0, b"fast open")

    def test_a_duplicate_syn_is_a_retransmission(self) -> None:
        talk = Talk()
        talk.syn()
        (repeat,) = talk.syn()
        assert isinstance(repeat, Retransmission)
        assert (repeat.start, repeat.end, repeat.verified) == (0, 0, True)
        assert repeat.completing_ref == 1

    def test_a_new_isn_before_data_replaces_it(self) -> None:
        talk = Talk()
        talk.syn()
        talk.a(10, b"held")
        talk.isn[0] = 1004
        events = talk.syn()
        assert kinds(events) == [AnomalyKind.ISN_CHANGED]
        (data,) = only(talk.a(0, b"abcdef"), StreamData)
        assert data.data == b"abcdefheld"

    def test_a_new_isn_drops_held_bytes_before_offset_zero(self) -> None:
        talk = Talk()
        talk.syn()
        talk.a(10, b"held")
        talk.isn[0] = 1020
        events = talk.syn()
        assert kinds(events) == [
            AnomalyKind.BEFORE_STREAM_START,
            AnomalyKind.ISN_CHANGED,
        ]
        assert (events[0].start, events[0].end) == (-10, -6)
        assert talk.r.usage.bytes == FLOW_OVERHEAD + PIECE_OVERHEAD

    def test_a_new_isn_moves_the_recorded_offsets(self) -> None:
        talk = Talk(bounds=StreamBounds(ack_gap_grace=100 * SECOND))
        talk.handshake()
        talk.b(0, ack=30)
        talk.a(10, b"held", flags=ACK | FIN)
        talk.isn[0] = 990
        talk.syn()
        (data,) = only(talk.a(0, b"x" * 20), StreamData)
        assert data.data == b"x" * 20 + b"held"
        assert only(talk.events, StreamEnd)[0].offset == 24
        talk.isn[0] = 1100
        assert kinds(talk.syn()) == [AnomalyKind.ISN_CHANGED]

    def test_a_new_isn_after_data_is_ignored(self) -> None:
        talk = Talk()
        talk.syn()
        talk.a(0, b"abc")
        talk.isn[0] = 5555
        events = talk.seg(0, -1, b"zzz", flags=SYN)
        assert kinds(events) == [AnomalyKind.ISN_CHANGED]
        talk.isn[0] = 1000
        (data,) = talk.a(3, b"def")
        assert data.data == b"def"

    def test_data_without_ack_is_dropped(self) -> None:
        talk = Talk()
        talk.syn()
        events = talk.a(0, b"abc", flags=PSH)
        assert kinds(events) == [AnomalyKind.DATA_WITHOUT_ACK]
        assert talk.a(0, b"abc") != ()

    def test_fin_ends_the_direction_when_reached(self) -> None:
        talk = Talk()
        talk.syn()
        assert not only(talk.a(4, b"tail", flags=FIN | ACK), StreamEnd)
        events = talk.a(0, b"head")
        assert [type(event) for event in events] == [StreamData, StreamEnd]
        end = events[1]
        assert (end.offset, end.reason, end.completing_ref) == (
            8,
            EndReason.FIN,
            2,
        )
        assert end.spans == (Span(1, 8, 8, 2 * SECOND, 64),)

    def test_data_after_fin_is_dropped(self) -> None:
        talk = Talk()
        talk.syn()
        talk.a(0, b"abcd", flags=FIN | ACK)
        events = talk.a(2, b"cdEF")
        assert kinds(events) == [AnomalyKind.DATA_AFTER_FIN]
        (anomaly,) = only(events, Anomaly)
        assert (anomaly.start, anomaly.end) == (4, 6)
        (repeat,) = only(events, Retransmission)
        assert (repeat.start, repeat.end) == (2, 4)
        events = talk.a(4, b"EF")
        assert kinds(events) == [AnomalyKind.DATA_AFTER_FIN]

    def test_a_later_fin_elsewhere_is_inconsistent(self) -> None:
        talk = Talk()
        talk.syn()
        talk.a(8, flags=FIN | ACK)
        events = talk.a(6, flags=FIN | ACK)
        assert kinds(events) == [AnomalyKind.INCONSISTENT_FIN]
        assert talk.a(8, flags=FIN | ACK) == ()

    def test_a_fin_before_received_data_is_inconsistent(self) -> None:
        talk = Talk()
        talk.syn()
        talk.a(10, b"later")
        events = talk.a(0, b"ab", flags=FIN | ACK)
        assert AnomalyKind.INCONSISTENT_FIN in kinds(events)
        talk.a(2, b"cdefghij")
        assert talk.stream(0) == b"abcdefghijlater"

    def test_rst_with_data(self) -> None:
        talk = Talk()
        talk.syn()
        events = talk.a(0, b"reason", flags=RST)
        assert kinds(events) == [
            AnomalyKind.RST_WITH_DATA,
            AnomalyKind.RST_RECEIVED,
        ]
        assert not only(events, StreamData)

    def test_an_rst_without_ack_is_processed(self) -> None:
        talk = Talk()
        talk.syn()
        events = talk.a(0, flags=RST)
        assert kinds(events) == [AnomalyKind.RST_RECEIVED]
        assert events[0].completing_ref == 1

    def test_an_rst_for_no_connection_keeps_no_state(self) -> None:
        talk = Talk()
        events = talk.a(0, b"x", flags=RST | ACK)
        assert kinds(events) == [
            AnomalyKind.RST_WITH_DATA,
            AnomalyKind.RST_RECEIVED,
        ]
        assert talk.r.usage == Usage(0, 0)

    def test_urgent_is_reported_once_per_direction(self) -> None:
        talk = Talk()
        talk.syn()
        assert kinds(talk.a(0, b"!", flags=URG | ACK)) == [AnomalyKind.URGENT]
        assert kinds(talk.a(1, b"!", flags=URG | ACK)) == []
        assert talk.stream(0) == b"!!"

    def test_hop_limit_changes_are_reported(self) -> None:
        talk = Talk()
        talk.syn(ttl=1)
        assert kinds(talk.a(0, b"a", ttl=64)) == [AnomalyKind.HOP_LIMIT_CHANGED]
        assert kinds(talk.a(1, b"b", ttl=64)) == []
        events = talk.a(2, b"c", ttl=3)
        assert kinds(events) == [AnomalyKind.HOP_LIMIT_CHANGED]
        assert only(events, StreamData)[0].spans[0].hop_limit == 3


# --- 4.4: decision 12, option (b): an RST makes the end pending --------


def rst_talk(held: bool = False, **bounds: object) -> Talk:
    """A connection with 4 bytes each way delivered, with ``held`` 4
    bytes of b at 10-14 past a hole, then an RST from a at t = 10 s,
    ref 5 (6 with ``held``); the closed timeout is 120 s by default."""
    talk = Talk(bounds=StreamBounds(**bounds))  # type: ignore[arg-type]
    talk.handshake()
    talk.a(0, b"ping", ack=0)
    talk.b(0, b"pong", ack=4)
    if held:
        talk.b(10, b"held", ack=4)
    talk.a(4, flags=RST | ACK, ack=4, ts=10 * SECOND)
    return talk


class TestReset:
    def test_the_rst_is_reported_at_once_and_ends_nothing(self) -> None:
        talk = rst_talk()
        (anomaly,) = talk.events[-1:]
        assert isinstance(anomaly, Anomaly)
        assert anomaly.kind is AnomalyKind.RST_RECEIVED
        assert anomaly.completing_ref == 5
        assert (anomaly.start, anomaly.end) == (4, 4)
        assert not only(talk.events, StreamEnd)

    @pytest.mark.parametrize("through", ["feed", "advance"])
    def test_confirmed_at_the_closed_timeout(self, through: str) -> None:
        talk = rst_talk()
        deadline = 130 * SECOND
        assert talk.r.advance(deadline - 1) == ()
        if through == "feed":
            other = segment(1, flags=SYN, sport=1234)
            events = talk.r.feed(
                packet_of(other), other, timestamp=deadline, ref=99
            )
        else:
            events = talk.r.advance(deadline)
        ends = only(events, StreamEnd)
        assert [(end.direction, end.offset, end.reason) for end in ends] == [
            (Direction.A_TO_B, 4, EndReason.RST),
            (Direction.B_TO_A, 4, EndReason.RST),
        ]
        assert all(
            event.completing_ref is None
            for event in events
            if event.flow == KEY
        )
        assert not only(events, Expired)
        assert talk.r.usage.flows == (1 if through == "feed" else 0)

    def test_after_confirmation_a_segment_starts_a_new_connection(self) -> None:
        talk = rst_talk()
        talk.r.advance(200 * SECOND)
        events = talk.a(4, b"late", ts=201 * SECOND)
        assert kinds(events) == [AnomalyKind.MIDSTREAM]
        assert only(events, StreamData)[0].offset == 0

    def test_held_data_is_flushed_at_confirmation(self) -> None:
        talk = rst_talk(held=True)
        events = talk.r.advance(130 * SECOND)
        assert [type(event) for event in events] == [
            StreamEnd,
            Gap,
            StreamData,
            StreamEnd,
        ]
        gap = events[1]
        assert (gap.start, gap.end, gap.reason) == (4, 10, GapReason.FLUSH)
        assert events[3].offset == 14

    def test_retransmissions_across_the_rst_do_not_move_it(self) -> None:
        talk = rst_talk()
        events = talk.a(0, b"ping", ack=4, ts=100 * SECOND)
        assert isinstance(events[0], Retransmission)
        talk.b(4, ack=4, ts=110 * SECOND)
        assert only(talk.r.advance(130 * SECOND), StreamEnd)

    def test_a_differing_retransmission_across_it_is_an_overlap(self) -> None:
        talk = rst_talk()
        (overlap,) = talk.b(0, b"pang", ack=4, ts=11 * SECOND)
        assert isinstance(overlap, Overlap)
        assert (overlap.kept, overlap.other) == (b"o", b"a")
        assert (overlap.start, overlap.end) == (1, 2)

    @pytest.mark.parametrize("side", [0, 1])
    def test_data_after_it_cancels_it_in_order(self, side: int) -> None:
        talk = rst_talk()
        events = talk.seg(side, 4, b"more", ack=4, ts=11 * SECOND)
        assert kinds(events) == [AnomalyKind.DATA_AFTER_RST]
        (data,) = only(events, StreamData)
        assert (data.offset, data.data) == (4, b"more")
        assert talk.r.advance(200 * SECOND) == ()
        assert not only(talk.events, StreamEnd)
        events = talk.seg(side, 8, b"again", ack=4, ts=201 * SECOND)
        assert kinds(events) == []

    @pytest.mark.parametrize("side", [0, 1])
    def test_data_after_it_cancels_it_out_of_order(self, side: int) -> None:
        talk = rst_talk()
        events = talk.seg(side, 10, b"far", ack=4, ts=11 * SECOND)
        assert kinds(events) == [AnomalyKind.DATA_AFTER_RST]
        assert only(events, OutOfOrder)
        assert talk.r.advance(200 * SECOND) == ()
        other = talk.seg(1 - side, 4, b"next", ack=4, ts=201 * SECOND)
        assert kinds(other) == [AnomalyKind.DATA_AFTER_RST]

    def test_the_cancelled_connection_takes_the_established_timeout(
        self,
    ) -> None:
        talk = rst_talk()
        talk.a(4, b"more", ack=4, ts=11 * SECOND)
        assert talk.r.advance(11 * SECOND + 3600 * SECOND - 1) == ()
        events = talk.r.advance(11 * SECOND + 3600 * SECOND)
        assert only(events, Expired)[0].timeout is Timeout.IDLE

    def test_another_rst_starts_a_new_pending_end(self) -> None:
        talk = rst_talk()
        talk.a(4, b"more", ack=4, ts=11 * SECOND)
        talk.b(4, flags=RST, ts=20 * SECOND)
        assert talk.r.advance(140 * SECOND - 1) == ()
        assert only(talk.r.advance(140 * SECOND), StreamEnd)

    def test_a_repeated_rst_does_not_move_it(self) -> None:
        talk = rst_talk()
        talk.a(4, flags=RST, ts=100 * SECOND)
        assert only(talk.r.advance(130 * SECOND), StreamEnd)

    def test_a_syn_with_a_new_isn_confirms_it_at_once(self) -> None:
        talk = rst_talk(held=True)
        talk.isn[0] = 77
        events = talk.syn(ts=12 * SECOND)
        ref = talk.ref - 1
        assert [type(event) for event in events] == [
            StreamEnd,
            Gap,
            StreamData,
            StreamEnd,
            Anomaly,
        ]
        assert all(event.completing_ref == ref for event in events)
        assert [end.reason for end in only(events, StreamEnd)] == [
            EndReason.RST,
            EndReason.RST,
        ]
        assert events[-1].kind is AnomalyKind.SYN_AFTER_RST
        (data,) = only(talk.a(0, b"new"), StreamData)
        assert data.offset == 0
        assert talk.r.usage.flows == 1

    def test_a_syn_with_the_old_isn_changes_nothing(self) -> None:
        talk = rst_talk()
        (repeat,) = talk.syn(ts=12 * SECOND)
        assert isinstance(repeat, Retransmission)
        assert only(talk.r.advance(130 * SECOND), StreamEnd)

    def test_any_syn_ends_a_mid_stream_direction(self) -> None:
        talk = Talk()
        talk.a(0, b"mid", ack=0)
        talk.b(0, b"way", ack=3)
        talk.a(3, flags=RST)
        events = talk.syn()
        assert kinds(events)[-1] is AnomalyKind.SYN_AFTER_RST
        assert len(only(events, StreamEnd)) == 2

    def test_close_confirms_it(self) -> None:
        talk = rst_talk()
        events = talk.r.close()
        assert [end.reason for end in only(events, StreamEnd)] == [
            EndReason.RST,
            EndReason.RST,
        ]
        assert not only(events, Expired)
        assert talk.r.usage == Usage(0, 0)

    def test_without_a_closed_timeout_only_close_confirms_it(self) -> None:
        talk = rst_talk(idle_timeout_closed=None)
        assert talk.r.advance(10**15) == ()
        assert only(talk.r.close(), StreamEnd)


# --- 4.5 and 4.6: overlaps, retransmissions, windows ------------------


def gap_talk(policy: OverlapPolicy) -> Talk:
    """A SYN from a, then 4 bytes held past a hole at 0-4."""
    talk = Talk(policy=policy)
    talk.syn()
    talk.a(4, b"held")
    return talk


class TestOverlaps:
    @pytest.mark.parametrize(
        "policy, delivered",
        [(OverlapPolicy.FIRST, b"0123held"), (OverlapPolicy.LAST, b"0123HELD")],
    )
    def test_differing_bytes_held_past_a_hole(
        self, policy: OverlapPolicy, delivered: bytes
    ) -> None:
        talk = gap_talk(policy)
        events = talk.a(4, b"HELD")
        (overlap,) = only(events, Overlap)
        assert bool(only(events, OutOfOrder)) is (policy is OverlapPolicy.LAST)
        assert overlap.policy is policy
        assert (overlap.start, overlap.end) == (4, 8)
        assert overlap.completing_ref == 2
        assert overlap.contrary is False
        assert overlap.resolved is True
        held_span = Span(1, 4, 8, 2 * SECOND, 64)
        new_span = Span(2, 4, 8, 3 * SECOND, 64)
        if policy is OverlapPolicy.FIRST:
            assert (overlap.kept, overlap.other) == (b"held", b"HELD")
            assert overlap.kept_spans == (held_span,)
            assert overlap.other_spans == (new_span,)
        else:
            assert (overlap.kept, overlap.other) == (b"HELD", b"held")
            assert overlap.kept_spans == (new_span,)
            assert overlap.other_spans == (held_span,)
        assert overlap.spans == (held_span, new_span)
        talk.a(0, b"0123")
        assert talk.stream(0) == delivered

    @pytest.mark.parametrize(
        "policy", [OverlapPolicy.FIRST, OverlapPolicy.LAST]
    )
    def test_differing_bytes_after_delivery(
        self, policy: OverlapPolicy
    ) -> None:
        talk = Talk(policy=policy)
        talk.syn()
        talk.a(0, b"abcdef")
        (overlap,) = talk.a(2, b"cXeY")
        assert isinstance(overlap, Overlap)
        assert (overlap.start, overlap.end) == (3, 6)
        assert (overlap.kept, overlap.other) == (b"def", b"XeY")
        assert overlap.kept_spans == (Span(1, 3, 6, 2 * SECOND, 64),)
        assert overlap.other_spans == (Span(2, 3, 6, 3 * SECOND, 64),)
        assert overlap.contrary is (policy is OverlapPolicy.LAST)
        assert talk.stream(0) == b"abcdef"

    def test_one_overlap_spans_delivered_and_held_bytes(self) -> None:
        talk = Talk(policy=OverlapPolicy.LAST)
        talk.syn()
        talk.a(0, b"ab")
        talk.a(4, b"ef")
        events = talk.a(0, b"XbcdEF")
        (overlap,) = only(events, Overlap)
        assert (overlap.start, overlap.end) == (0, 6)
        assert overlap.kept == b"abcdEF"
        assert overlap.other == b"XbcdEF"[:0] + b"Xbcdef"
        assert overlap.contrary is True
        assert talk.stream(0) == b"abcdEF"
        assert tiles(overlap.kept_spans, 0, 6)
        assert tiles(overlap.other_spans, 0, 6)

    def test_identical_bytes_are_a_verified_retransmission(self) -> None:
        talk = gap_talk(OverlapPolicy.FIRST)
        (held, repeat) = talk.a(2, b"23he")
        assert isinstance(repeat, Retransmission)
        assert isinstance(held, OutOfOrder)
        assert (held.start, held.end, held.expected) == (2, 6, 0)
        assert (repeat.start, repeat.end, repeat.verified) == (4, 6, True)
        assert repeat.spans == (
            Span(1, 4, 6, 2 * SECOND, 64),
            Span(2, 4, 6, 3 * SECOND, 64),
        )

    def test_a_repeat_older_than_the_retained_bytes_is_unverified(
        self,
    ) -> None:
        talk = Talk(bounds=StreamBounds(retain_bytes=4))
        talk.syn()
        talk.a(0, b"abcdefgh")
        (repeat,) = talk.a(0, b"XXcdefgh")
        assert isinstance(repeat, Retransmission)
        assert (repeat.start, repeat.end, repeat.verified) == (0, 8, False)
        (unverified, overlap) = talk.a(0, b"XXXXXXgZ")
        assert isinstance(overlap, Overlap)
        assert (overlap.start, overlap.end) == (4, 8)
        assert (overlap.kept, overlap.other) == (b"efgh", b"XXgZ")
        assert (unverified.start, unverified.end) == (0, 4)
        assert unverified.verified is False

    def test_retention_is_anchored_on_the_acknowledgement(self) -> None:
        talk = Talk(bounds=StreamBounds(retain_bytes=4))
        talk.handshake()
        talk.b(0, ack=2)
        talk.a(0, b"abcdefghijkl")
        (overlap,) = talk.a(0, b"Xbcd")
        assert isinstance(overlap, Overlap)
        assert (overlap.kept, overlap.other) == (b"a", b"X")
        talk.b(0, ack=12)
        (repeat,) = talk.a(8, b"ijkl")
        assert repeat.verified is True
        (repeat,) = talk.a(0, b"abcd")
        assert repeat.verified is False

    def test_an_ack_beyond_the_delivered_end_retains_no_less(self) -> None:
        talk = Talk(bounds=StreamBounds(retain_bytes=4))
        talk.handshake()
        talk.a(0, b"abcdefgh")
        talk.b(0, ack=10**6)
        (repeat,) = talk.a(4, b"efgh")
        assert repeat.verified is True

    def test_one_overlap_per_frame_however_many_pieces(self) -> None:
        talk = gap_talk(OverlapPolicy.FIRST)
        talk.a(10, b"aa")
        talk.a(14, b"bb")
        events = talk.a(4, b"X" * 12)
        assert len(only(events, Overlap)) == 1
        overlap = only(events, Overlap)[0]
        assert (overlap.start, overlap.end) == (4, 16)
        assert overlap.kept == b"heldXXaaXXbb"

    def test_targets_choose_the_policy_by_receiver(self) -> None:
        talk = Talk(
            targets={"192.0.2.0/24": OverlapPolicy.FIRST, B: OverlapPolicy.LAST}
        )
        talk.syn()
        talk.syn(1)
        talk.a(4, b"held")
        talk.b(4, b"held", ack=0)
        assert only(talk.a(4, b"HELD"), Overlap)[0].policy is OverlapPolicy.LAST
        assert (
            only(talk.b(4, b"HELD", ack=0), Overlap)[0].policy
            is OverlapPolicy.FIRST
        )

    def test_out_of_window_data_is_reported_and_stored(self) -> None:
        talk = Talk()
        talk.syn(options=bytes([3, 3, 2, 1]))
        talk.syn(1, options=bytes([3, 3, 1, 1]), window=1)
        talk.b(0, ack=0, window=10)
        events = talk.a(0, b"x" * 50, ack=0)
        assert kinds(events) == [AnomalyKind.OUT_OF_WINDOW]
        (anomaly,) = only(events, Anomaly)
        assert (anomaly.start, anomaly.end) == (20, 50)
        assert talk.stream(0) == b"x" * 50

    def test_the_window_of_a_syn_is_not_scaled(self) -> None:
        talk = Talk()
        talk.syn(options=bytes([3, 3, 2, 1]))
        talk.syn(1, options=bytes([3, 3, 1, 1]), window=10)
        events = talk.a(0, b"x" * 11, ack=0)
        assert kinds(events) == [AnomalyKind.OUT_OF_WINDOW]

    def test_no_window_scale_without_both_options(self) -> None:
        talk = Talk()
        talk.syn()
        talk.syn(1, options=bytes([3, 3, 4, 1]), window=1)
        talk.b(0, ack=0, window=10)
        assert kinds(talk.a(0, b"x" * 11, ack=0)) == [AnomalyKind.OUT_OF_WINDOW]

    def test_no_window_check_without_both_syns(self) -> None:
        talk = Talk()
        talk.syn()
        talk.b(0, ack=0, window=1)
        assert kinds(talk.a(0, b"x" * 50, ack=0)) == []

    @pytest.mark.parametrize(
        "options",
        [
            b"",
            bytes([1, 1, 1, 1]),
            bytes([0, 3, 3, 9]),
            bytes([2, 1, 0, 0]),
            bytes([8, 9, 1, 1]),
            bytes([3, 4, 2, 1]),
            bytes([2, 4, 5, 6, 3, 3, 30, 0]),
        ],
    )
    def test_window_scale_options_never_raise(self, options: bytes) -> None:
        talk = Talk()
        talk.syn(options=options)
        talk.syn(1, options=bytes([3, 3, 14, 1]))
        talk.b(0, ack=0, window=1)
        talk.a(0, b"x" * 7000, ack=0)


# --- 4.7: delivering byte runs, ACK-based gaps -------------------------


class TestDelivery:
    def test_one_run_per_feed_with_what_it_unblocks(self) -> None:
        talk = Talk()
        talk.syn()
        (held,) = talk.a(6, b"gh")
        assert isinstance(held, OutOfOrder)
        assert (held.start, held.end, held.expected) == (6, 8, 0)
        talk.a(3, b"def")
        (data,) = talk.a(0, b"abc")
        assert (data.offset, data.data) == (0, b"abcdefgh")
        assert data.refs == (1, 2, 3)
        assert tiles(data.spans, 0, 8)
        assert data.completing_ref == 3
        assert talk.r.usage.bytes > FLOW_OVERHEAD

    def test_a_truncated_segment_in_order_is_a_gap_at_once(self) -> None:
        talk = Talk()
        talk.syn()
        events = talk.a(0, b"abcdefgh", cut=3)
        assert [type(event) for event in events] == [StreamData, Anomaly, Gap]
        assert events[0].data == b"abcde"
        assert events[1].kind is AnomalyKind.TRUNCATED
        gap = events[2]
        assert (gap.start, gap.end, gap.reason) == (5, 8, GapReason.TRUNCATED)
        assert gap.completing_ref == 1
        (data,) = talk.a(8, b"ij")
        assert data.offset == 8

    def test_a_truncated_segment_held_is_a_gap_when_reached(self) -> None:
        talk = Talk()
        talk.syn()
        talk.a(4, b"efgh", cut=2)
        events = talk.a(0, b"abcd")
        assert [type(event) for event in events] == [StreamData, Gap]
        assert events[0].data == b"abcdef"
        assert (events[1].start, events[1].end) == (6, 8)

    def test_a_retransmission_fills_a_held_truncation(self) -> None:
        talk = Talk()
        talk.syn()
        talk.a(4, b"efgh", cut=2)
        (repeat, _) = talk.a(4, b"efgh")
        assert isinstance(repeat, Retransmission)
        assert (repeat.start, repeat.end, repeat.verified) == (4, 8, False)
        (data,) = talk.a(0, b"abcd")
        assert data.data == b"abcdefgh"

    def test_a_segment_cut_to_its_header_still_occupies_its_range(
        self,
    ) -> None:
        talk = Talk()
        talk.syn()
        talk.a(4, b"efgh", cut=4)
        events = talk.a(2, b"cdEFGH", cut=4)
        repeat = only(events, Retransmission)[0]
        assert (repeat.start, repeat.end, repeat.verified) == (4, 8, False)
        events = talk.a(0, b"ab")
        assert [type(event) for event in events] == [StreamData, Gap]
        assert events[1].end == 8

    def test_an_acknowledged_hole_waits_for_the_grace(self) -> None:
        talk = Talk()
        talk.handshake()
        talk.a(4, b"held", ack=0, ts=10 * SECOND)
        talk.b(0, ack=8, ts=10 * SECOND + 1)
        assert talk.b(0, ack=8, ts=11 * SECOND) == ()
        events = talk.b(0, ack=8, ts=11 * SECOND + 1)
        assert [type(event) for event in events] == [Gap, StreamData]
        gap, data = events
        assert (gap.start, gap.end, gap.reason) == (0, 4, GapReason.ACKED)
        assert (data.offset, data.data) == (4, b"held")
        assert gap.completing_ref == data.completing_ref == talk.ref - 1
        assert gap.direction is data.direction is Direction.A_TO_B

    def test_data_beyond_the_hole_confirms_it(self) -> None:
        talk = Talk()
        talk.handshake()
        talk.a(4, b"held", ack=0, ts=10 * SECOND)
        talk.b(0, ack=8, ts=10 * SECOND)
        events = talk.a(10, b"more", ack=0, ts=12 * SECOND)
        gaps = only(events, Gap)
        assert [(gap.start, gap.end) for gap in gaps] == [(0, 4)]
        (data,) = only(events, StreamData)
        assert data.data == b"held"
        assert only(events, OutOfOrder)

    def test_data_that_fills_the_hole_in_the_grace_cancels_it(self) -> None:
        talk = Talk()
        talk.handshake()
        talk.a(4, b"held", ack=0, ts=10 * SECOND)
        talk.b(0, ack=8, ts=10 * SECOND)
        (data,) = talk.a(0, b"fill", ack=0, ts=10 * SECOND + 5)
        assert data.data == b"fillheld"
        assert talk.b(0, ack=8, ts=20 * SECOND) == ()
        assert not only(talk.events, Gap)

    def test_the_gap_is_capped_at_the_highest_offset_received(self) -> None:
        talk = Talk()
        talk.handshake()
        talk.a(4, b"held", ack=0, ts=10 * SECOND)
        talk.b(0, ack=100, ts=10 * SECOND)
        events = talk.b(0, ack=100, ts=12 * SECOND)
        anomaly = only(events, Anomaly)[0]
        assert anomaly.kind is AnomalyKind.ACK_BEYOND_DATA
        assert (anomaly.start, anomaly.end) == (8, 100)
        assert anomaly.direction is Direction.A_TO_B
        assert [(gap.start, gap.end) for gap in only(events, Gap)] == [(0, 4)]
        events = talk.a(20, b"far", ack=0, ts=13 * SECOND)
        assert kinds(events) == []
        assert [(gap.start, gap.end) for gap in only(events, Gap)] == [(8, 20)]
        assert only(events, StreamData)[0].data == b"far"

    def test_every_acknowledged_hole_becomes_a_gap(self) -> None:
        talk = Talk()
        talk.handshake()
        talk.a(4, b"bb", ack=0, ts=10 * SECOND)
        talk.a(10, b"dd", ack=0, ts=10 * SECOND)
        talk.b(0, ack=12, ts=10 * SECOND)
        events = talk.b(0, ack=12, ts=12 * SECOND)
        assert [type(event) for event in events] == [Gap, StreamData] * 2
        assert [(e.start, e.end) for e in only(events, Gap)] == [
            (0, 4),
            (6, 10),
        ]

    def test_late_bytes_for_an_acked_gap(self) -> None:
        talk = Talk()
        talk.handshake()
        talk.a(4, b"held", ack=0, ts=10 * SECOND)
        talk.b(0, ack=8, ts=10 * SECOND)
        talk.b(0, ack=8, ts=12 * SECOND)
        events = talk.a(0, b"late", ack=0, ts=13 * SECOND)
        (late,) = events
        assert isinstance(late, LateData)
        assert (late.offset, late.data) == (0, b"late")
        assert late.spans == (Span(talk.ref - 1, 0, 4, 13 * SECOND, 64),)
        assert late.completing_ref == talk.ref - 1
        (repeat,) = talk.a(0, b"late", ack=0, ts=14 * SECOND)
        assert isinstance(repeat, Retransmission)
        assert repeat.verified is True
        (overlap,) = talk.a(2, b"TE", ack=0, ts=15 * SECOND)
        assert isinstance(overlap, Overlap)

    def test_late_bytes_for_part_of_an_acked_gap(self) -> None:
        talk = Talk()
        talk.handshake()
        talk.a(8, b"held", ack=0, ts=10 * SECOND)
        talk.b(0, ack=12, ts=10 * SECOND)
        talk.b(0, ack=12, ts=12 * SECOND)
        (late,) = talk.a(2, b"cd", ack=0, ts=13 * SECOND)
        assert (late.offset, late.data) == (2, b"cd")
        events = talk.a(0, b"abcdefgh", ack=0, ts=14 * SECOND)
        assert [(e.offset, e.data) for e in only(events, LateData)] == [
            (0, b"ab"),
            (4, b"efgh"),
        ]
        (repeat,) = only(events, Retransmission)
        assert (repeat.start, repeat.end, repeat.verified) == (2, 4, True)

    def test_bytes_for_other_gaps_are_unverified_repeats(self) -> None:
        talk = Talk()
        talk.syn()
        talk.a(0, b"abcdefgh", cut=4)
        (repeat,) = talk.a(4, b"efgh")
        assert isinstance(repeat, Retransmission)
        assert repeat.verified is False

    def test_no_ack_gap_without_a_capture_clock(self) -> None:
        talk = Talk()
        talk.handshake(ts=0)
        talk.a(4, b"held", ack=0, ts=0)
        talk.b(0, ack=8, ts=0)
        assert talk.b(0, ack=8, ts=0) == ()


# --- 5.1: checksums -------------------------------------------------


class TestChecksums:
    @pytest.mark.parametrize("mode", list(ChecksumMode))
    def test_a_bad_tcp_checksum(self, mode: ChecksumMode) -> None:
        talk = Talk(checksums=mode)
        talk.syn()
        events = talk.a(0, b"abc", checksum=0x1234)
        assert kinds(events) == [AnomalyKind.BAD_CHECKSUM]
        assert bool(only(events, StreamData)) is (mode is ChecksumMode.KEEP)

    @pytest.mark.parametrize("mode", list(ChecksumMode))
    def test_a_bad_ipv4_header_checksum(self, mode: ChecksumMode) -> None:
        talk = Talk(checksums=mode)
        talk.syn()
        events = talk.a(0, b"abc", ip_checksum=0x1234)
        assert kinds(events) == [AnomalyKind.BAD_CHECKSUM]
        assert bool(only(events, StreamData)) is (mode is ChecksumMode.KEEP)

    @pytest.mark.parametrize("length", [True, False])
    def test_an_offloaded_direction_under_auto(self, length: bool) -> None:
        talk = Talk()
        talk.syn()
        pattern = pseudo_sum(A, B, 20 + 3 if length else 0)
        events = talk.a(0, b"abc", checksum=pattern)
        assert kinds(events) == [
            AnomalyKind.BAD_CHECKSUM,
            AnomalyKind.CHECKSUM_OFFLOAD,
        ]
        assert only(events, StreamData)[0].data == b"abc"

    def test_the_offload_pattern_from_a_local_source(self) -> None:
        talk = Talk(local=["192.0.2.0/30"])
        talk.syn()
        pattern = pseudo_sum(A, B, 23)
        assert only(talk.a(0, b"abc", checksum=pattern), StreamData)
        talk = Talk(local=["198.51.100.0/24"])
        talk.syn()
        events = talk.a(0, b"abc", checksum=pattern)
        assert kinds(events) == [AnomalyKind.BAD_CHECKSUM]
        assert not only(events, StreamData)

    @pytest.mark.parametrize("mode", list(ChecksumMode))
    def test_a_zero_ipv4_header_checksum_from_windows(
        self, mode: ChecksumMode
    ) -> None:
        talk = Talk(checksums=mode)
        talk.syn()
        events = talk.a(0, b"abc", ip_checksum=0)
        assert bool(only(events, StreamData)) is (mode is not ChecksumMode.DROP)

    @pytest.mark.parametrize("mode", list(ChecksumMode))
    def test_a_zero_ip_length_is_unverified(self, mode: ChecksumMode) -> None:
        talk = Talk(checksums=mode)
        talk.syn()
        good = talk.a(0, b"abc", total=0)
        assert kinds(good)[0] is AnomalyKind.UNVERIFIED_CHECKSUM
        assert bool(only(good, StreamData)) is (mode is ChecksumMode.KEEP)
        talk = Talk(checksums=mode)
        talk.syn()
        pattern = pseudo_sum(A, B, 20 + 3)
        events = talk.a(0, b"def", total=0, checksum=pattern)
        assert bool(only(events, StreamData)) is (mode is not ChecksumMode.DROP)

    def test_a_zero_ipv6_payload_length_with_the_lso_pattern(self) -> None:
        reassembler = StreamReassembler()
        frames = [
            segment6(10, flags=SYN),
            segment6(
                11,
                data=b"tso",
                payload_length=0,
                checksum=pseudo_sum(A6, B6, 0),
            ),
        ]
        events = [
            event
            for index, frame in enumerate(frames)
            for event in reassembler.feed(
                packet_of(frame), frame, timestamp=index + 1
            )
        ]
        assert kinds(events) == [
            AnomalyKind.UNVERIFIED_CHECKSUM,
            AnomalyKind.CHECKSUM_OFFLOAD,
        ]
        assert only(events, StreamData)[0].data == b"tso"

    @pytest.mark.parametrize("mode", list(ChecksumMode))
    def test_a_truncated_segment_is_used_under_every_mode(
        self, mode: ChecksumMode
    ) -> None:
        talk = Talk(checksums=mode)
        talk.syn()
        events = talk.a(0, b"abcdef", cut=2, checksum=0x1111)
        assert only(events, StreamData)[0].data == b"abcd"
        assert AnomalyKind.BAD_CHECKSUM not in kinds(events)


# --- 2.3 and 7.3: bounds, eviction, expiry ----------------------------

#: Charges, as the reassembler counts them: a connection with one
#: direction, a held chunk of n bytes, a retained run of n bytes from
#: one frame.
ONE_SIDE = FLOW_OVERHEAD + PIECE_OVERHEAD


def held_charge(size: int) -> int:
    return PIECE_OVERHEAD + size


def run_charge(size: int, frames: int = 1) -> int:
    from netprotocols.reassembly import _SPAN_OVERHEAD

    return PIECE_OVERHEAD + size + (size >> 3) + _SPAN_OVERHEAD * frames


def syn_from(
    port: int, reassembler: StreamReassembler, ts: int, ref: int
) -> tuple[StreamEvent, ...]:
    frame = segment(port * 100, flags=SYN, sport=port)
    return reassembler.feed(packet_of(frame), frame, timestamp=ts, ref=ref)


class TestBounds:
    def test_charges_are_what_is_held(self) -> None:
        talk = Talk()
        talk.syn()
        assert talk.r.usage == Usage(1, ONE_SIDE)
        talk.a(0, b"abcd")
        talk.a(10, b"heldheld")
        assert talk.r.usage.bytes == ONE_SIDE + run_charge(4) + held_charge(8)
        talk.syn(1)
        assert talk.r.usage.bytes == (
            ONE_SIDE + PIECE_OVERHEAD + run_charge(4) + held_charge(8)
        )

    @pytest.mark.parametrize("over", [0, 1])
    def test_max_flow_bytes_trims_retained_bytes_first(self, over: int) -> None:
        cap = ONE_SIDE + run_charge(4) + held_charge(8) - over
        talk = Talk(bounds=StreamBounds(max_flow_bytes=cap))
        talk.syn()
        talk.a(0, b"abcd")
        events = talk.a(10, b"heldheld")
        assert [type(event) for event in events] == [OutOfOrder]
        assert talk.r.usage.bytes == cap
        (repeat,) = talk.a(0, b"a")
        assert repeat.verified is (over == 0)

    def test_max_flow_bytes_forces_the_lowest_hole_out(self) -> None:
        cap = ONE_SIDE + held_charge(8) - 1
        talk = Talk(bounds=StreamBounds(max_flow_bytes=cap))
        talk.syn()
        talk.a(0, b"abcd")
        events = talk.a(10, b"heldheld")
        assert [type(event) for event in events] == [
            Gap,
            OutOfOrder,
            StreamData,
        ]
        gap, _, data = events
        assert (gap.start, gap.end, gap.reason) == (4, 10, GapReason.CAP)
        assert (data.offset, data.data) == (10, b"heldheld")
        assert gap.completing_ref == data.completing_ref == 2
        assert talk.r.usage.bytes <= cap
        assert talk.r.usage.flows == 1

    def test_a_connection_that_cannot_fit_is_evicted(self) -> None:
        talk = Talk(bounds=StreamBounds(max_flow_bytes=ONE_SIDE - 1))
        events = talk.syn()
        assert [type(event) for event in events] == [StreamEnd, Evicted]
        end, evicted = events
        assert end.reason is EndReason.EVICTED
        assert evicted.bound is Bound.MAX_FLOW_BYTES
        assert evicted.completing_ref == end.completing_ref == 0
        assert talk.r.usage == Usage(0, 0)

    @pytest.mark.parametrize("over", [0, 1])
    def test_max_flows(self, over: int) -> None:
        reassembler = StreamReassembler(bounds=StreamBounds(max_flows=2))
        syn_from(1, reassembler, 1, 0)
        syn_from(2, reassembler, 2, 1)
        if not over:
            assert reassembler.usage.flows == 2
            return
        events = syn_from(3, reassembler, 3, 2)
        assert [type(event) for event in events] == [StreamEnd, Evicted]
        assert all(event.completing_ref is None for event in events)
        assert events[1].flow.port_a == 1
        assert events[1].bound is Bound.MAX_FLOWS
        assert reassembler.usage.flows == 2

    def test_half_open_connections_go_first(self) -> None:
        reassembler = StreamReassembler(bounds=StreamBounds(max_flows=2))
        talk = Talk(reassembler)
        talk.handshake()
        talk.a(0, b"q", ack=0)
        talk.b(0, b"r", ack=1)
        syn_from(2, reassembler, 100 * SECOND, 50)
        talk.a(1, b"s", ack=1, ts=101 * SECOND)
        events = syn_from(3, reassembler, 102 * SECOND, 51)
        (evicted,) = only(events, Evicted)
        assert evicted.flow.port_a == 2
        assert evicted.completing_ref is None
        assert reassembler.usage.flows == 2

    def test_a_half_open_connection_can_be_its_own_victim(self) -> None:
        reassembler = StreamReassembler(bounds=StreamBounds(max_flows=1))
        talk = Talk(reassembler)
        talk.a(0, b"q", ack=0)
        talk.b(0, b"r", ack=1)
        events = syn_from(4, reassembler, 103 * SECOND, 52)
        assert [type(event) for event in events] == [StreamEnd, Evicted]
        assert all(event.completing_ref == 52 for event in events)
        assert events[1].flow.port_a == 4
        assert reassembler.usage.flows == 1

    def test_the_least_recently_active_established_one_goes_last(
        self,
    ) -> None:
        reassembler = StreamReassembler(bounds=StreamBounds(max_flows=1))
        talk = Talk(reassembler)
        talk.a(0, b"q", ack=0)
        talk.b(0, b"r", ack=1)
        frame = segment(5, 0, ACK, b"x", sport=40001)
        events = reassembler.feed(packet_of(frame), frame, timestamp=10**12)
        assert [type(event) for event in events] == [
            Anomaly,
            StreamData,
            StreamEnd,
            Evicted,
        ]
        assert only(events, Evicted)[0].flow.port_a == 40001

    def test_with_no_half_open_one_the_least_recently_active_goes(
        self,
    ) -> None:
        both = FLOW_OVERHEAD + 2 * PIECE_OVERHEAD + 2 * run_charge(1)
        bounds = StreamBounds(max_total_bytes=2 * both + held_charge(1))
        reassembler = StreamReassembler(bounds=bounds)
        for port in (40001, 40002):
            for frame in (
                segment(5, 50, ACK, b"q", sport=port),
                segment(50, 6, ACK, b"r", src=B, dst=A, sport=80, dport=port),
            ):
                reassembler.feed(packet_of(frame), frame, timestamp=1)
        assert reassembler.usage == Usage(2, 2 * both)
        frame = segment(9, 51, ACK, b"ss", sport=40001)
        events = reassembler.feed(packet_of(frame), frame, timestamp=2)
        (evicted,) = only(events, Evicted)
        assert evicted.flow.port_a == 40002
        assert evicted.bound is Bound.MAX_TOTAL_BYTES
        assert evicted.completing_ref is None

    @pytest.mark.parametrize("over", [0, 1])
    def test_max_total_bytes(self, over: int) -> None:
        cap = 2 * ONE_SIDE - over
        reassembler = StreamReassembler(
            bounds=StreamBounds(max_total_bytes=cap)
        )
        syn_from(1, reassembler, 1, 0)
        events = syn_from(2, reassembler, 2, 1)
        if not over:
            assert events == ()
            assert reassembler.usage == Usage(2, cap)
            return
        (end, evicted) = events
        assert evicted.bound is Bound.MAX_TOTAL_BYTES
        assert evicted.flow.port_a == 1
        assert end.completing_ref is evicted.completing_ref is None
        assert reassembler.usage == Usage(1, ONE_SIDE)

    def test_an_eviction_another_frame_triggers_carries_no_ref(self) -> None:
        reassembler = StreamReassembler(bounds=StreamBounds(max_flows=1))
        talk = Talk(reassembler)
        talk.syn()
        talk.a(4, b"held")
        talk.a(0, b"ab")
        events = syn_from(7, reassembler, 10 * SECOND, 9)
        assert [type(event) for event in events] == [
            Gap,
            StreamData,
            StreamEnd,
            Evicted,
        ]
        assert all(event.completing_ref is None for event in events)
        assert events[0].reason is GapReason.FLUSH
        assert events[3].held_bytes == 4
        assert events[3].missing == ()

    def test_an_expiry_another_frame_triggers_carries_no_ref(self) -> None:
        talk = Talk(bounds=StreamBounds(idle_timeout_new=5 * SECOND))
        talk.syn()
        talk.a(4, b"held")
        events = syn_from(7, talk.r, 100 * SECOND, 9)
        assert [type(event) for event in events] == [
            Gap,
            StreamData,
            StreamEnd,
            Expired,
        ]
        assert all(event.completing_ref is None for event in events)
        assert events[3].timeout is Timeout.IDLE
        assert events[2].reason is EndReason.IDLE

    @pytest.mark.parametrize("through", ["feed", "advance"])
    @pytest.mark.parametrize(
        "kind, deadline",
        [("new", 60), ("established", 3600), ("closed", 120), ("age", 30)],
    )
    def test_timeouts(self, through: str, kind: str, deadline: int) -> None:
        bounds = StreamBounds(
            age_timeout=30 * SECOND if kind == "age" else None
        )
        talk = Talk(bounds=bounds)
        talk.syn(ts=SECOND)
        if kind in ("established", "closed"):
            talk.a(0, b"q", ts=SECOND)
            talk.b(0, b"r", ack=1, ts=SECOND)
        if kind == "closed":
            talk.a(1, flags=FIN | ACK, ack=1, ts=SECOND)
            talk.b(1, flags=FIN | ACK, ack=2, ts=SECOND)
        due = SECOND + deadline * SECOND

        def at(time: int) -> tuple[StreamEvent, ...]:
            if through == "advance":
                return talk.r.advance(time)
            return syn_from(9, talk.r, time, 99)

        assert not only(at(due - 1), Expired)
        (expired,) = only(at(due), Expired)
        assert expired.timeout is (
            Timeout.AGE if kind == "age" else Timeout.IDLE
        )
        assert expired.completing_ref is None

    def test_an_earlier_timestamp_moves_nothing(self) -> None:
        talk = Talk(bounds=StreamBounds(idle_timeout_new=10 * SECOND))
        talk.syn(ts=100 * SECOND)
        talk.a(0, b"old", ts=50 * SECOND)
        assert talk.r.advance(109 * SECOND) == ()
        (end, expired) = talk.r.advance(110 * SECOND)
        assert end.offset == 3
        assert expired.last_timestamp == 100 * SECOND
        talk.a(3, b"new", ts=60 * SECOND)
        assert talk.r.usage.flows == 1

    def test_timestamp_zero_never_moves_the_clock(self) -> None:
        talk = Talk(bounds=StreamBounds(idle_timeout_new=1))
        talk.syn(ts=0)
        assert talk.a(0, b"x", ts=0)
        assert talk.r.advance(0) == ()
        assert talk.r.usage.flows == 1

    def test_expiries_come_in_deadline_order(self) -> None:
        reassembler = StreamReassembler(
            bounds=StreamBounds(
                idle_timeout_new=10, idle_timeout_established=20
            )
        )
        syn_from(1, reassembler, 5, 0)
        syn_from(2, reassembler, 1, 1)
        syn_from(3, reassembler, 3, 2)
        events = reassembler.advance(100)
        assert [event.flow.port_a for event in only(events, Expired)] == [
            2,
            3,
            1,
        ]

    def test_a_later_deadline_is_found_when_the_entry_is_popped(self) -> None:
        reassembler = StreamReassembler(
            bounds=StreamBounds(idle_timeout_new=10)
        )
        syn_from(1, reassembler, 1, 0)
        syn_from(1, reassembler, 8, 1)
        assert reassembler.advance(15) == ()
        assert only(reassembler.advance(18), Expired)

    def test_close_flushes_everything(self) -> None:
        talk = Talk(bounds=StreamBounds(age_timeout=30 * SECOND))
        talk.syn()
        talk.a(4, b"held", flags=FIN | ACK)
        frame = segment(5, 0, ACK, b"x", sport=40001)
        talk.send(frame)
        events = talk.r.close()
        assert [type(event) for event in events] == [
            Gap,
            StreamData,
            StreamEnd,
            Expired,
            StreamEnd,
            Expired,
        ]
        assert events[2].reason is EndReason.FIN
        assert events[4].reason is EndReason.CLOSE
        assert events[3].timeout is Timeout.AGE
        assert talk.r.usage == Usage(0, 0)
        assert talk.r.close() == ()

    def test_a_syn_after_both_fins_starts_a_new_connection(self) -> None:
        talk = Talk()
        talk.handshake()
        talk.a(0, b"bye", flags=FIN | ACK, ack=0)
        talk.b(0, flags=FIN | ACK, ack=4)
        talk.isn[0] = 50000
        events = talk.syn()
        assert events == ()
        (data,) = talk.a(0, b"again")
        assert data.offset == 0

    def test_the_same_capture_twice_gives_equal_events(self) -> None:
        def run() -> list[StreamEvent]:
            reassembler = StreamReassembler()
            events: list[StreamEvent] = []
            for index, frame in enumerate(capture_frames(HTTP_STREAM)):
                events += reassembler.feed(
                    packet_of_frame(frame.data),
                    frame.data,
                    timestamp=frame.timestamp,
                    ref=index,
                )
            return events + list(reassembler.close())

        assert run() == run()

    def test_repr_is_the_same_under_two_hash_seeds(self) -> None:
        program = (
            "import sys; sys.path.insert(0, 'tests');"
            "from test_stream_reassembly import *;"
            "r = StreamReassembler(bounds=StreamBounds(max_flows=3));"
            "print(repr([e for i, f in enumerate(capture_frames(TLS_SESSION))"
            " for e in r.feed(packet_of_frame(f.data), f.data,"
            " timestamp=f.timestamp, ref=i)] + list(r.close())))"
        )
        outputs = {
            subprocess.run(
                [sys.executable, "-c", program],
                capture_output=True,
                check=True,
                env={"PYTHONHASHSEED": seed, "PATH": ""},
                cwd=Path(__file__).parent.parent,
            ).stdout
            for seed in ("1", "2")
        }
        assert len(outputs) == 1


# --- real captures ----------------------------------------------------

HTTP_STREAM = FIXTURES / "reassembly" / "http_stream.pcap"
TLS_SESSION = FIXTURES / "tls" / "tls_session.pcap"
HTTP_PCAP = FIXTURES / "http" / "http.pcap"

#: tshark 4.2.2's ``-z follow,tcp,raw`` of each connection, recorded when
#: the captures were taken: per tshark stream, the client's and the
#: server's byte count and SHA-256 (tests/fixtures/MANIFEST.md).
TSHARK_FOLLOWED = {
    HTTP_PCAP: [
        (
            (
                76,
                "2122a14255996ee9f560d8284edda8c3cb01d91311c1879ad905eff4ccf0429e",
            ),
            (
                201,
                "5e726116c46f7d1fbf21d313269c57ec1fa3516ab1fb7b6c6b6b709a7e41bc18",
            ),
        ),
        (
            (
                77,
                "016c3936be796016b33f86b7c67b4fe6d70bda34675a01dafc27302c6ff5ff60",
            ),
            (
                159,
                "a7a1abc9cacaf16d69149fa533f66ba66351d3e305d5d3b6381a2704b4b1d8fb",
            ),
        ),
        (
            (
                97,
                "dd50659548ad08a893426ce5b65ea8aed4678aae187755a6a6b7776f123b4774",
            ),
            (
                108,
                "2a0a4c29775f38707e5eab8aa42ce6f6b0e4c8d8d58f22f923c3e83083acb135",
            ),
        ),
        (
            (
                162,
                "07d207bc4d526b8e5f989c7b17a952456cd8588af791d2917c057eb71906d259",
            ),
            (
                168,
                "cb12a79542e388700c77015f64b6f27595e1fb67dc1e319a8b558ee51deb0575",
            ),
        ),
        (
            (
                78,
                "79ae8980d000ddc19366fb7f74cd77080bcb2f8c5fc1d34d5f6bd7631852b4c9",
            ),
            (
                239,
                "b2998352b98981174e53c1d26b7d20b3954fc2209efa4921662470b86073901f",
            ),
        ),
        (
            (
                78,
                "f5cc0f0836d44cd5ecbaec38528d57abf49dffaffaaffa5b54fd69a01a1606ab",
            ),
            (
                502,
                "40bec54f685f43ee53e287f8dea5f883a8a49654a0db01456f9109e4c25402f9",
            ),
        ),
        (
            (
                139,
                "b45fd8563b5eac99cef55e67b57311c3d45f13705d956088589660da753ac7e3",
            ),
            (
                599,
                "a7e231e2eb846081a0b6af46d7206a72325a78cb2904094655bf156ebbe392e0",
            ),
        ),
    ],
    TLS_SESSION: [
        (
            (
                1738,
                "fb72c279b00ae632e9b332cd2c6f227ca86fdd300d31b97f8254d34c3593ba50",
            ),
            (
                795,
                "ad40c7ac2bba37de4f8fca883e884cceb7da36ac5ac81981c3b1f5f1ddcc0975",
            ),
        ),
        (
            (
                3041,
                "873330184d5ef932dfaa3594fde52f60081d6f6b6b42e60008f52b9218be06fe",
            ),
            (
                1393,
                "dd2f99b348fe7dfd7f47c9298e8b48f128ed5ccaa2c385f495f181d7763df2c3",
            ),
        ),
        (
            (
                720,
                "526296f63f4d315470afe239f6a6daf5de572381e2806e9a4a36c19e9fae0c04",
            ),
            (
                1189,
                "7ad0850e2d5a543b891409bd22e21ef3105b164385890ef5b6abb052f385209f",
            ),
        ),
        (
            (
                577,
                "de0c3750656ad53f600d53501ded887725d2baf17f2e7bc16367180bafc22972",
            ),
            (
                1227,
                "bd90237d37bb66c0321338bf4254273bbbaaaf7f66dbe6e543c5b557b0f74c75",
            ),
        ),
        (
            (
                478,
                "89836f78c40ebd6c1faaafc97266c50303cea052aafbe3ac3f49c05828a96df4",
            ),
            (
                1188,
                "e05bbd4225cb2b1e042dabdd7521b298bb4817c6c657607651d6414187534724",
            ),
        ),
        (
            (
                455,
                "7741547277c1390d3b9080c4535bf4939123cbe874727581b8f11788093651e8",
            ),
            (
                960,
                "6a52aeb7b86755511f599ce772d35f1e3269b97741aab6a256d350a3a905b6d0",
            ),
        ),
    ],
    HTTP_STREAM: [
        (
            (
                154,
                "e7f6b8bfe7d60bb64b4809541dd15bb3a74993c340aa2651fa5f0eb3677752d8",
            ),
            (
                220406,
                "35d4e16ff8250a9962013009366c5741b662601ae656d81c79ba7a6dd226fee7",
            ),
        ),
        (
            (
                40,
                "bff3b97d9768251fd39579471bb08c34a4c0efde6d9557c20f45cbe2e5a49680",
            ),
            (
                190,
                "459db198db5e2b2498e8a8e77c40f6da486640c16c570707084d63c31417c635",
            ),
        ),
    ],
}

#: The frame (0-based) in which tshark 4.2.2's HTTP dissector completes
#: each message of http_stream.pcap, per connection, in stream order:
#: requests and responses alternate.
TSHARK_HTTP_FRAMES = [[3, 477, 515, 578], [586, 590]]


def capture_frames(path: Path) -> list:  # type: ignore[type-arg]
    return list(read_pcap(path.read_bytes()))


def packet_of_frame(frame: bytes) -> Packet:
    return decode_frame(frame, lax=True)


def reassemble(path: Path) -> tuple[list[StreamEvent], list[FlowKey]]:
    """Every event of a capture fed in order, and its connections in the
    order their first StreamData came."""
    reassembler = StreamReassembler()
    events: list[StreamEvent] = []
    for index, frame in enumerate(capture_frames(path)):
        events += reassembler.feed(
            packet_of_frame(frame.data),
            frame.data,
            timestamp=frame.timestamp,
            ref=index,
        )
    events += reassembler.close()
    assert reassembler.usage == Usage(0, 0)
    order: list[FlowKey] = []
    for event in only(events, StreamData):
        if event.flow not in order:
            order.append(typing_cast_flow(event.flow))
    return events, order


def typing_cast_flow(flow: object) -> FlowKey:
    assert isinstance(flow, FlowKey)
    return flow


def directions(
    events: list[StreamEvent], flow: FlowKey, server_port: int
) -> tuple[list[StreamData], list[StreamData]]:
    """The client's and the server's runs of one connection."""
    client = (
        Direction.A_TO_B if flow.port_b == server_port else Direction.B_TO_A
    )
    runs = [event for event in only(events, StreamData) if event.flow == flow]
    return (
        [run for run in runs if run.direction is client],
        [run for run in runs if run.direction is not client],
    )


def joined(runs: list[StreamData]) -> bytes:
    cursor = 0
    for run in runs:
        assert run.offset == cursor
        assert tiles(run.spans, run.offset, run.offset + len(run.data))
        cursor += len(run.data)
    return b"".join(run.data for run in runs)


class TestRealCaptures:
    @pytest.mark.parametrize(
        "path, port", [(HTTP_PCAP, 80), (TLS_SESSION, 443), (HTTP_STREAM, 80)]
    )
    def test_streams_match_the_extractor_and_tshark(
        self, path: Path, port: int
    ) -> None:
        events, order = reassemble(path)
        extracted = extract(read_frames(path), port)
        assert len(order) == len(extracted) == len(TSHARK_FOLLOWED[path])
        for flow, (request, response), followed in zip(
            order, extracted, TSHARK_FOLLOWED[path], strict=True
        ):
            client, server = directions(events, flow, port)
            for runs, want, (size, digest) in (
                (client, request, followed[0]),
                (server, response, followed[1]),
            ):
                data = joined(runs)
                assert data == want
                assert (len(data), hashlib.sha256(data).hexdigest()) == (
                    size,
                    digest,
                )
        assert not only(events, Overlap)
        assert not only(events, Gap)

    def test_http_files_are_the_extractors(self) -> None:
        events, order = reassemble(HTTP_PCAP)
        for number, flow in enumerate(order, start=1):
            client, server = directions(events, flow, 80)
            folder = FIXTURES / "http"
            assert (
                joined(client)
                == (folder / f"{number:02d}.request").read_bytes()
            )
            assert (
                joined(server)
                == (folder / f"{number:02d}.response").read_bytes()
            )

    def test_tls_server_names_read_through_the_runs(self) -> None:
        from netprotocols import TLS

        events, order = reassemble(TLS_SESSION)
        names = []
        for flow in order:
            client, _ = directions(events, flow, 443)
            names.append(TLS.decode(joined(client)).server_name)
        streams = extract(read_frames(TLS_SESSION), 443)
        assert names == [
            TLS.decode(client).server_name for client, _ in streams
        ]
        assert names.count(None) == 1
        first, _ = directions(events, order[0], 443)
        assert [run.refs for run in first[:2]] == [(3,), (4,)]
        last = TLS.decode(joined(first)).header_len - 1
        (holder,) = [
            run
            for run in first
            if run.offset <= last < run.offset + len(run.data)
        ]
        assert holder.completing_ref == 4

    def test_http_messages_decode_from_the_runs(self) -> None:
        events, order = reassemble(HTTP_STREAM)
        assert len(order) == 2
        for flow, frames in zip(order, TSHARK_HTTP_FRAMES, strict=True):
            client, server = directions(events, flow, 80)
            requests = messages(client, closed=False)
            methods = [message.method for message, _ in requests]
            responses = messages(server, closed=True, methods=methods)
            completing = []
            for (_, request), (_, response) in zip(
                requests, responses, strict=True
            ):
                completing += [request, response]
            assert completing == frames
        ends = [(end.flow, end.reason) for end in only(events, StreamEnd)]
        assert ends.count((order[0], EndReason.FIN)) == 2
        assert ends.count((order[1], EndReason.RST)) == 2
        (reset,) = [
            event
            for event in only(events, Anomaly)
            if event.kind is AnomalyKind.RST_RECEIVED
        ]
        assert reset.completing_ref == 592

    def test_the_big_body_is_the_one_served(self) -> None:
        events, order = reassemble(HTTP_STREAM)
        _, server = directions(events, order[0], 80)
        response = HTTP.decode(joined(server), request_method="GET")
        assert response.content == bytes(
            (index * 7 + index // 251) % 256 for index in range(200_000)
        )
        assert len(server) > 300


def messages(
    runs: list[StreamData],
    *,
    closed: bool,
    methods: list[str] | None = None,
) -> list[tuple[HTTP, int | None]]:
    """Each message of a direction, decoded from its runs as the design
    note's section 4.8 does, with its completing frame: the
    completing_ref of the run that holds its last byte."""
    buffer = bytearray()
    offset = 0
    found: list[tuple[HTTP, int | None]] = []
    queue = list(methods or [])
    for run in runs:
        buffer += run.data
        while buffer:
            method = queue[0] if queue else None
            try:
                message = HTTP.decode(
                    bytes(buffer),
                    request_method=method,
                    closed=closed and run is runs[-1],
                )
            except TruncatedHeaderError:
                break
            if queue:
                queue.pop(0)
            last = offset + message.header_len - 1
            holder = next(
                each
                for each in runs
                if each.offset <= last < each.offset + len(each.data)
            )
            found.append((message, holder.completing_ref))
            del buffer[: message.header_len]
            offset += message.header_len
    return found


# --- 7.5: properties ---------------------------------------------------


@st.composite
def cut_stream(
    draw: st.DrawFn,
) -> tuple[int, bytes, list[tuple[int, bytes]]]:
    """An ISN (wraps included), a payload, and its segments: cut at
    random points, with consistent retransmissions, shuffled."""
    isn = draw(
        st.one_of(
            st.integers(0, 2**32 - 1), st.integers(2**32 - 3000, 2**32 - 1)
        )
    )
    payload = draw(st.binary(min_size=1, max_size=3000))
    points = sorted(
        draw(st.sets(st.integers(1, len(payload) - 1), max_size=30))
        if len(payload) > 1
        else set()
    )
    bounds = [0, *points, len(payload)]
    pieces = [
        (start, payload[start:end]) for start, end in itertools.pairwise(bounds)
    ]
    extra = draw(
        st.lists(
            st.tuples(st.integers(0, len(payload) - 1), st.integers(1, 400)),
            max_size=8,
        )
    )
    pieces += [(start, payload[start : start + size]) for start, size in extra]
    order = draw(st.permutations(range(len(pieces))))
    return isn, payload, [pieces[index] for index in order]


def feed_pieces(
    reassembler: StreamReassembler,
    isn: int,
    pieces: list[tuple[int, bytes]],
) -> list[StreamEvent]:
    events: list[StreamEvent] = []
    frames = [segment(isn, flags=SYN)] + [
        segment(isn + 1 + start, data=data) for start, data in pieces
    ]
    for index, frame in enumerate(frames):
        events += reassembler.feed(
            packet_of(frame), frame, timestamp=index + 1, ref=index
        )
        usage = reassembler.usage
        bounds = reassembler._bounds
        assert usage.flows <= bounds.max_flows
        assert usage.bytes <= bounds.max_total_bytes
    return events


def reference(pieces: list[tuple[int, bytes]], last: bool) -> bytes:
    """The bytes delivered under ``first`` or ``last``: each byte takes
    the earliest or the latest version among those that arrived while it
    was not yet delivered, and delivery runs as far as bytes are
    contiguous."""
    value: dict[int, int] = {}
    delivered = 0
    for start, data in pieces:
        for index, byte in enumerate(data, start):
            if index >= delivered and (last or index not in value):
                value[index] = byte
        while delivered in value:
            delivered += 1
    return bytes(value[index] for index in range(delivered))


class TestProperties:
    @given(cut_stream())
    def test_consistent_segments_reassemble_to_the_payload(
        self, drawn: tuple[int, bytes, list[tuple[int, bytes]]]
    ) -> None:
        isn, payload, pieces = drawn
        reassembler = StreamReassembler()
        events = feed_pieces(reassembler, isn, pieces)
        runs = only(events, StreamData)
        assert joined(runs) == payload
        assert not only(events, Overlap)
        assert not only(events, Gap)
        reassembler.close()
        assert reassembler.usage == Usage(0, 0)

    @given(
        cut_stream(),
        st.lists(
            st.tuples(
                st.integers(0, 2999), st.binary(min_size=1, max_size=300)
            ),
            min_size=1,
            max_size=6,
        ),
        st.sampled_from([OverlapPolicy.FIRST, OverlapPolicy.LAST]),
        st.randoms(use_true_random=False),
    )
    def test_differing_duplicates_follow_the_reference_model(
        self,
        drawn: tuple[int, bytes, list[tuple[int, bytes]]],
        noise: list[tuple[int, bytes]],
        policy: OverlapPolicy,
        rng: object,
    ) -> None:
        isn, payload, pieces = drawn
        differing = []
        for start, data in noise:
            first = start % len(payload)
            versions = bytes(
                payload[index % len(payload)] ^ 0xFF
                for index in range(first, first + len(data))
            )
            differing.append((first, versions))
        mixed = pieces + differing
        rng.shuffle(mixed)  # type: ignore[attr-defined]
        reassembler = StreamReassembler(policy=policy)
        events = feed_pieces(reassembler, isn, mixed)
        delivered = joined(only(events, StreamData))
        assert delivered == reference(mixed, policy is OverlapPolicy.LAST)
        assert only(events, Overlap)

    @given(
        cut_stream(),
        st.builds(
            StreamBounds,
            max_flow_bytes=st.integers(1, 20_000),
            max_total_bytes=st.integers(1, 20_000),
            max_flows=st.integers(1, 3),
            retain_bytes=st.integers(1, 5_000),
        ),
    )
    def test_usage_never_exceeds_the_bounds(
        self,
        drawn: tuple[int, bytes, list[tuple[int, bytes]]],
        bounds: StreamBounds,
    ) -> None:
        isn, _, pieces = drawn
        reassembler = StreamReassembler(bounds=bounds)
        feed_pieces(reassembler, isn, pieces)
        other = segment(7, flags=SYN, sport=1)
        reassembler.feed(packet_of(other), other, timestamp=10**6)
        assert reassembler.usage.flows <= bounds.max_flows
        assert reassembler.usage.bytes <= bounds.max_total_bytes
        reassembler.close()
        assert reassembler.usage == Usage(0, 0)


class TestEdges:
    def test_a_tcp_layer_inside_an_ipv6_fragment_is_not_taken(self) -> None:
        inner = segment6(10, flags=SYN)
        tcp = inner[40:]
        frame = (
            struct.pack(
                "!IHBB16s16s",
                6 << 28,
                8 + len(tcp),
                44,
                64,
                packed(A6),
                packed(B6),
            )
            + struct.pack("!BBHI", 6, 0, 1, 77)
            + tcp
        )
        reassembler = StreamReassembler()
        assert reassembler.feed(packet_of(frame), frame, timestamp=1) == ()
        assert reassembler.usage == Usage(0, 0)

    def test_stale_deadlines_are_compacted_and_skipped(self) -> None:
        reassembler = StreamReassembler(bounds=StreamBounds(max_flows=1))
        for port in range(1, 300):
            syn_from(port, reassembler, port, port)
        assert len(reassembler._deadlines) <= 2 + 64
        events = reassembler.advance(10**15)
        assert len(only(events, Expired)) == 1

    def test_an_acked_gap_older_than_the_retained_bytes_is_forgotten(
        self,
    ) -> None:
        talk = Talk(bounds=StreamBounds(retain_bytes=4))
        talk.handshake()
        talk.a(4, b"held", ack=0, ts=10 * SECOND)
        talk.b(0, ack=8, ts=10 * SECOND)
        talk.b(0, ack=8, ts=12 * SECOND)
        talk.a(8, b"later!", ack=0, ts=13 * SECOND)
        talk.b(0, ack=14, ts=14 * SECOND)
        assert talk.r.usage.bytes == (
            FLOW_OVERHEAD + 2 * PIECE_OVERHEAD + run_charge(4)
        )
        (repeat,) = talk.a(0, b"late", ack=0, ts=15 * SECOND)
        assert isinstance(repeat, Retransmission)
        assert repeat.verified is False

    def test_a_flush_skips_to_a_known_fin(self) -> None:
        talk = Talk()
        talk.syn()
        talk.a(10, flags=FIN | ACK)
        events = talk.r.close()
        assert [type(event) for event in events] == [Gap, StreamEnd, Expired]
        gap, end, _ = events
        assert (gap.start, gap.end, gap.reason) == (0, 10, GapReason.FLUSH)
        assert (end.offset, end.reason) == (10, EndReason.FIN)

    def test_the_state_an_rst_adds_is_held_to_the_caps(self) -> None:
        talk = Talk(bounds=StreamBounds(max_total_bytes=ONE_SIDE))
        talk.syn()
        events = talk.a(0, flags=RST)
        assert [type(event) for event in events] == [
            Anomaly,
            StreamEnd,
            Evicted,
        ]
        assert events[2].bound is Bound.MAX_TOTAL_BYTES
        assert events[2].completing_ref == 1
        assert talk.r.usage == Usage(0, 0)
