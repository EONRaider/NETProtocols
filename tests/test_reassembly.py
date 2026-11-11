"""Tests for netprotocols.reassembly: IPv4 and IPv6 fragment reassembly.

Every frame this module builds is **crafted**: the helpers below write
IPv4 and IPv6 fragments byte by byte, so each rule can be driven on its
own, and the overlap vectors are the fragment pattern of Suricata's
``DefragSturgesNovak*`` unit tests (src/defrag.c), with the reassembled
bytes those tests expect for each policy. The real captures are
tests/fixtures/ipv4_fragments.pcap, ipv6_fragments.pcap and the
captures in tests/fixtures/reassembly/ (see MANIFEST.md); the values
compared against them were taken from tshark 4.2.2 when they were
captured, and are recorded here, so no test runs tshark.
"""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import itertools
import random
import struct
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import netprotocols
from conftest import FIXTURES
from netprotocols import (
    UDP,
    ICMPv4,
    IPv4,
    IPv6,
    IPv6HopByHopOptions,
    Packet,
    decode_frame,
)
from netprotocols.checksum import internet_checksum
from netprotocols.pcap import read_pcap
from netprotocols.reassembly import (
    FLOW_OVERHEAD,
    NO_TIMEOUT,
    PIECE_OVERHEAD,
    SECOND,
    Anomaly,
    AnomalyKind,
    Bound,
    ChecksumMode,
    Datagram,
    Direction,
    Evicted,
    Expired,
    FragmentBounds,
    FragmentEvent,
    FragmentKey,
    FragmentReassembler,
    FragmentTarget,
    Overlap,
    OverlapPolicy,
    Retransmission,
    Span,
    Timeout,
    Usage,
)

ROOT = Path(__file__).resolve().parent.parent
REASSEMBLY = FIXTURES / "reassembly"
SRC4, DST4 = "192.0.2.1", "192.0.2.2"
SRC6, DST6 = "2001:db8::1", "2001:db8::2"


# --- crafted frames ---------------------------------------------------


def v4(
    identification: int,
    offset: int,
    data: bytes,
    *,
    more: bool = True,
    ttl: int = 64,
    protocol: int = 17,
    src: str = SRC4,
    dst: str = DST4,
    flags: int = 0,
    options: bytes = b"",
    checksum: int | None = None,
    total_length: int | None = None,
) -> bytes:
    """A crafted IPv4 fragment; ``offset`` in bytes, a multiple of 8."""
    ihl = 5 + len(options) // 4
    header = (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x40 | ihl,
            0,
            ihl * 4 + len(data) if total_length is None else total_length,
            identification,
            ((flags | (1 if more else 0)) << 13) | offset // 8,
            ttl,
            protocol,
            0,
            ipaddress.IPv4Address(src).packed,
            ipaddress.IPv4Address(dst).packed,
        )
        + options
    )
    value = internet_checksum(header) if checksum is None else checksum
    return header[:10] + struct.pack("!H", value) + header[12:] + data


def v6(
    identification: int,
    offset: int,
    data: bytes,
    *,
    more: bool = True,
    hop_limit: int = 64,
    next_header: int = 17,
    src: str = SRC6,
    dst: str = DST6,
    extensions: bytes = b"",
    first: int = 44,
    payload_length: int | None = None,
) -> bytes:
    """A crafted IPv6 fragment; ``extensions`` precede the Fragment
    header, ``first`` names the header after the IPv6 header."""
    fragment = struct.pack(
        "!BBHI", next_header, 0, offset | (1 if more else 0), identification
    )
    payload = extensions + fragment + data
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload) if payload_length is None else payload_length,
        first,
        hop_limit,
        ipaddress.IPv6Address(src).packed,
        ipaddress.IPv6Address(dst).packed,
    )
    return header + payload


def ethernet(frame: bytes, *, padding: bytes = b"") -> bytes:
    """A crafted Ethernet II frame around an IP packet."""
    ethertype = b"\x08\x00" if frame[0] >> 4 == 4 else b"\x86\xdd"
    return b"\x02" * 6 + b"\x04" * 6 + ethertype + frame + padding


def packet_of(frame: bytes) -> Packet:
    """Decode a frame that starts at its Ethernet or IP header."""
    if frame[12:14] in (b"\x08\x00", b"\x86\xdd") and frame[0] >> 4 not in (
        4,
        6,
    ):
        return decode_frame(frame, lax=True)
    return decode_frame(
        frame, start=IPv4 if frame[0] >> 4 == 4 else IPv6, lax=True
    )


def feed(
    reassembler: FragmentReassembler,
    frame: bytes,
    *,
    ts: int = 1,
    ref: int | None = None,
) -> tuple[FragmentEvent, ...]:
    return reassembler.feed(packet_of(frame), frame, timestamp=ts, ref=ref)


def feed_all(
    reassembler: FragmentReassembler, frames: Iterable[bytes], *, ts: int = 1
) -> list[FragmentEvent]:
    events: list[FragmentEvent] = []
    for index, frame in enumerate(frames):
        events += feed(reassembler, frame, ts=ts + index, ref=index)
    return events


def only[T](events: Iterable[object], kind: type[T]) -> list[T]:
    return [event for event in events if isinstance(event, kind)]


def payload(event: Datagram) -> bytes:
    return event.data[event.payload_offset :]


def tiles(spans: tuple[Span, ...], length: int) -> bool:
    cursor = 0
    for span in spans:
        if span.start != cursor:
            return False
        cursor = span.end
    return cursor == length


def udp_datagram(size: int, *, seed: int = 0) -> bytes:
    data = random.Random(seed).randbytes(size)
    return struct.pack("!HHHH", 4000, 4001, 8 + size, 0) + data


def cut4(
    message: bytes, pieces: Iterable[tuple[int, int]], identification: int = 1
) -> list[bytes]:
    """Crafted IPv4 fragments of ``message``, cut at (offset, end)."""
    last = len(message)
    return [
        v4(identification, start, message[start:end], more=end != last)
        for start, end in pieces
    ]


def cut6(
    message: bytes, pieces: Iterable[tuple[int, int]], identification: int = 1
) -> list[bytes]:
    """Crafted IPv6 fragments of ``message``, cut at (offset, end)."""
    last = len(message)
    return [
        v6(identification, start, message[start:end], more=end != last)
        for start, end in pieces
    ]


# The fragment pattern of Suricata's DefragSturgesNovak* tests: offset,
# fill letter and length; Q, the last, at 176.
STURGES_NOVAK = [
    (0, "A", 24),
    (32, "B", 16),
    (48, "C", 24),
    (80, "D", 8),
    (104, "E", 16),
    (120, "F", 24),
    (144, "G", 16),
    (160, "H", 16),
    (176, "I", 8),
    (8, "J", 32),
    (48, "K", 24),
    (72, "L", 24),
    (96, "M", 24),
    (128, "N", 8),
    (152, "O", 8),
    (160, "P", 8),
    (176, "Q", 16),
]

# The 192 bytes each of Suricata's tests expects, one letter per 8
# bytes (DefragSturgesNovakBsdTest and the others).
STURGES_NOVAK_EXPECTED = {
    OverlapPolicy.BSD: "AAAJJBCCCLLLMMMFFFGGHHIQ",
    OverlapPolicy.LINUX: "AAAJJBKKKLLLMMMFFFGGPHQQ",
    OverlapPolicy.WINDOWS: "AAAJBBCCCLLLMEEFFFGGHHIQ",
    OverlapPolicy.SOLARIS: "AAAJBBCCCLLLMMMFFFGGHHIQ",
    OverlapPolicy.FIRST: "AAAJBBCCCLDLMEEFFFGGHHIQ",
    OverlapPolicy.LAST: "AJJJJBKKKLLLMMMFNFGOPHQQ",
}


def sturges_novak(version: int, identification: int = 1) -> list[bytes]:
    build = v4 if version == 4 else v6
    return [
        build(
            identification, offset, letter.encode() * length, more=letter != "Q"
        )
        for offset, letter, length in STURGES_NOVAK
    ]


# --- API -------------------------------------------------------------


class TestAPI:
    def test_policy_values_are_frag3_names(self) -> None:
        assert [policy.value for policy in OverlapPolicy] == [
            "first",
            "last",
            "bsd",
            "linux",
            "windows",
            "solaris",
            "discard",
            "linux-discard",
        ]

    def test_enums_have_string_values(self) -> None:
        for enum_type in (
            OverlapPolicy,
            Direction,
            Bound,
            Timeout,
            AnomalyKind,
            ChecksumMode,
        ):
            assert all(isinstance(member.value, str) for member in enum_type)
        assert {mode.value for mode in ChecksumMode} == {"drop", "keep", "auto"}
        assert AnomalyKind("checksum_offload") is AnomalyKind.CHECKSUM_OFFLOAD

    def test_defaults(self) -> None:
        bounds = FragmentBounds()
        assert bounds.max_flow_bytes is None
        assert bounds.max_total_bytes == 32 * 1024 * 1024
        assert bounds.max_flows == 16_384
        assert bounds.max_fragments == 128
        assert bounds.idle_timeout is None
        assert bounds.age_timeout == 60 * SECOND
        assert SECOND == 1_000_000_000
        assert FragmentTarget() == FragmentTarget(
            policy=None, age_timeout=None, idle_timeout=None
        )

    @pytest.mark.parametrize(
        "changes",
        [
            {"max_total_bytes": 0},
            {"max_flows": -1},
            {"max_fragments": True},
            {"max_flow_bytes": 0},
            {"age_timeout": 0},
            {"idle_timeout": 1.5},
            {"max_flows": "1"},
        ],
    )
    def test_invalid_bounds(self, changes: dict[str, object]) -> None:
        with pytest.raises(ValueError):
            FragmentBounds(**changes)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "changes",
        [
            {"policy": "first"},
            {"age_timeout": -5},
            {"idle_timeout": 0},
            {"idle_timeout": "never"},
        ],
    )
    def test_invalid_target(self, changes: dict[str, object]) -> None:
        with pytest.raises(ValueError):
            FragmentTarget(**changes)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"policy": "first"},
            {"checksums": "auto"},
            {"targets": {"10.0.0.0/33": OverlapPolicy.BSD}},
            {"targets": {"not a network": OverlapPolicy.BSD}},
            {"targets": {"10.0.0.0/8": "bsd"}},
            {"targets": {10: OverlapPolicy.BSD}},
            {"local": ["300.1.1.1"]},
            {"local": [None]},
            {"local": "10.0.0.0/8"},
        ],
    )
    def test_constructor_rejects(self, kwargs: dict[str, object]) -> None:
        with pytest.raises(ValueError):
            FragmentReassembler(**kwargs)  # type: ignore[arg-type]

    def test_constructor_rejects_bounds_of_another_type(self) -> None:
        with pytest.raises(TypeError):
            FragmentReassembler(bounds={"max_flows": 1})  # type: ignore[arg-type]

    def test_feed_rejects_wrong_types(self) -> None:
        reassembler = FragmentReassembler()
        frame = v4(1, 0, b"x" * 8)
        packet = packet_of(frame)
        with pytest.raises(TypeError):
            reassembler.feed(frame, frame, timestamp=1)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            reassembler.feed(packet, "frame", timestamp=1)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            reassembler.feed(packet, frame, timestamp=1.0)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            reassembler.feed(packet, frame, timestamp=True)
        with pytest.raises(TypeError):
            reassembler.feed(packet, frame, timestamp=1, ref="0")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            reassembler.advance(None)  # type: ignore[arg-type]
        assert reassembler.usage == Usage(0, 0)

    def test_negative_timestamps_are_rejected(self) -> None:
        reassembler = FragmentReassembler()
        frame = v4(1, 0, b"x" * 8)
        with pytest.raises(ValueError, match="negative"):
            reassembler.feed(packet_of(frame), frame, timestamp=-1)
        with pytest.raises(ValueError, match="negative"):
            reassembler.advance(-5)
        assert reassembler.usage == Usage(0, 0)

    def test_feed_rejects_a_frame_shorter_than_its_packet(self) -> None:
        frame = ethernet(v4(1, 0, b"x" * 8), padding=b"\x00" * 30)
        packet = decode_frame(frame)
        with pytest.raises(ValueError, match="fewer than"):
            FragmentReassembler().feed(packet, frame[:-1], timestamp=1)

    def test_bytearray_and_memoryview_frames(self) -> None:
        reassembler = FragmentReassembler()
        message = udp_datagram(24)
        first, last = cut4(message, [(0, 16), (16, 32)])
        reassembler.feed(packet_of(first), bytearray(first), timestamp=1)
        (datagram,) = reassembler.feed(
            packet_of(last), memoryview(last), timestamp=2
        )
        assert isinstance(datagram, Datagram)
        assert payload(datagram) == message

    def test_events_are_frozen_slotted_and_keyword_only(self) -> None:
        span = Span(0, 0, 8, 1, 64)
        key = FragmentKey(4, SRC4, DST4, 17, 1)
        fields = {
            "flow": key,
            "direction": None,
            "spans": (span,),
            "completing_ref": 0,
            "first_timestamp": 1,
            "last_timestamp": 1,
        }
        event = Retransmission(**fields, start=0, end=8, verified=True)
        assert not hasattr(event, "__dict__")
        with pytest.raises(dataclasses.FrozenInstanceError):
            event.start = 1  # type: ignore[misc]
        with pytest.raises(TypeError):
            Retransmission(key, None, (span,), 0, 1, 1, 0, 8, True)  # type: ignore[misc]
        anomaly = Anomaly(**fields, kind=AnomalyKind.TRUNCATED, start=0, end=8)
        assert anomaly != Anomaly(
            **fields, kind=AnomalyKind.OVERSIZE, start=0, end=8
        )
        assert event.refs == (0,)

    def test_refs_are_sorted_and_distinct(self) -> None:
        spans = (
            Span(5, 0, 8, 1, 64),
            Span(2, 8, 16, 1, 64),
            Span(5, 16, 24, 1, 64),
        )
        expired = Expired(
            flow=FragmentKey(6, SRC6, DST6, None, 1),
            direction=None,
            spans=spans,
            completing_ref=None,
            first_timestamp=1,
            last_timestamp=1,
            timeout=Timeout.AGE,
            held_bytes=24,
            missing=((24, None),),
        )
        assert expired.refs == (2, 5)


# --- 3.2: which fragments are taken ----------------------------------


class TestWhichFragments:
    def test_an_unfragmented_packet_returns_nothing(self) -> None:
        reassembler = FragmentReassembler()
        frame = v4(1, 0, udp_datagram(8), more=False)
        assert feed(reassembler, frame) == ()
        assert reassembler.usage == Usage(0, 0)

    def test_a_packet_without_ip_returns_nothing(self) -> None:
        frame = b"\xff" * 6 + b"\x02" * 6 + b"\x08\x06" + b"\x00" * 28
        assert (
            FragmentReassembler().feed(
                decode_frame(frame, lax=True), frame, timestamp=1
            )
            == ()
        )

    def test_an_atomic_fragment_is_processed_in_isolation(self) -> None:
        """RFC 6946 §4: offset 0 and M 0 is never combined with a train
        of the same identification, and returns nothing."""
        reassembler = FragmentReassembler()
        message = udp_datagram(40)
        first, last = cut6(message, [(0, 24), (24, 48)], identification=9)
        atomic = v6(9, 0, udp_datagram(16), more=False)
        assert feed(reassembler, first, ref=0) == ()
        assert feed(reassembler, atomic, ref=1) == ()
        (datagram,) = feed(reassembler, last, ref=2)
        assert isinstance(datagram, Datagram)
        assert payload(datagram) == message
        assert datagram.refs == (0, 2)

    def test_the_outermost_fragmented_header_is_taken(self) -> None:
        """An IP-in-IP datagram whose outer header is a fragment."""
        inner = v4(77, 0, udp_datagram(24), more=False, src="198.51.100.1")
        outer = [
            v4(5, 0, inner[:24], protocol=4),
            v4(5, 24, inner[24:], protocol=4, more=False),
        ]
        reassembler = FragmentReassembler()
        events = feed_all(reassembler, outer)
        (datagram,) = only(events, Datagram)
        assert datagram.flow == FragmentKey(4, SRC4, DST4, 4, 5)
        assert payload(datagram) == inner
        assert feed(reassembler, inner) == ()

    def test_data_ends_at_the_declared_length_not_the_padding(self) -> None:
        message = udp_datagram(16)
        first, last = cut4(message, [(0, 8), (8, 24)])
        frames = [
            ethernet(first, padding=b"\xaa" * 26),
            ethernet(last, padding=b"\xbb" * 18),
        ]
        reassembler = FragmentReassembler()
        events = feed_all(reassembler, frames)
        (datagram,) = only(events, Datagram)
        assert payload(datagram) == message

    def test_an_inner_ipv6_fragment_behind_an_unfragmented_outer_one(
        self,
    ) -> None:
        """IPv6 in IPv6: the outer header is not a fragment, the inner
        one is, and its key is the inner datagram's."""
        message = udp_datagram(40)
        reassembler = FragmentReassembler()
        events = []
        for index, inner in enumerate(cut6(message, [(0, 24), (24, 48)])):
            outer = v6(0, 0, b"", src="2001:db8::a", dst="2001:db8::b")[:40]
            outer = (
                outer[:4] + struct.pack("!HBB", len(inner), 41, 64) + outer[8:]
            )
            frame = outer + inner
            events += feed(reassembler, frame, ref=index)
        (datagram,) = events
        assert isinstance(datagram, Datagram)
        assert datagram.flow == FragmentKey(6, SRC6, DST6, None, 1)
        assert payload(datagram) == message

    def test_ref_defaults_to_the_count_of_frames_fed(self) -> None:
        message = udp_datagram(16)
        first, last = cut4(message, [(0, 8), (8, 24)])
        reassembler = FragmentReassembler()
        reassembler.feed(packet_of(first), first, timestamp=1)
        unrelated = v4(2, 0, udp_datagram(8), more=False)
        reassembler.feed(packet_of(unrelated), unrelated, timestamp=2)
        (datagram,) = reassembler.feed(packet_of(last), last, timestamp=3)
        assert isinstance(datagram, Datagram)
        assert datagram.refs == (0, 2)
        assert datagram.completing_ref == 2

    def test_a_walk_stopped_early_is_processed(self) -> None:
        """A first fragment of UDP to port 53 stops a strict walk at the
        DNS header the fragment cuts; the lax walk's packet is fed."""
        message = struct.pack("!HHHH", 4000, 53, 40, 0) + b"\x00" * 32
        frames = cut4(message, [(0, 16), (16, 40)])
        packet = decode_frame(frames[0], start=IPv4, lax=True)
        assert packet.stopped_by is not None
        reassembler = FragmentReassembler()
        reassembler.feed(packet, frames[0], timestamp=1)
        (datagram,) = feed(reassembler, frames[1], ts=2)
        assert isinstance(datagram, Datagram)
        assert payload(datagram) == message


# --- 3.3 and 3.4: overlaps --------------------------------------------


class TestOverlaps:
    @pytest.mark.parametrize("policy", list(STURGES_NOVAK_EXPECTED))
    def test_sturges_novak_vectors(self, policy: OverlapPolicy) -> None:
        reassembler = FragmentReassembler(policy=policy)
        events = feed_all(reassembler, sturges_novak(4))
        (datagram,) = only(events, Datagram)
        assert payload(datagram)[::8].decode() == STURGES_NOVAK_EXPECTED[policy]
        assert len(payload(datagram)) == 192
        assert datagram.completing_ref == 16
        assert tiles(datagram.spans, 192)
        overlaps = only(events, Overlap)
        assert overlaps
        for overlap in overlaps:
            assert overlap.resolved
            assert overlap.policy is policy
            assert overlap.kept != overlap.other
            assert (
                len(overlap.kept)
                == len(overlap.other)
                == overlap.end - overlap.start
            )
            assert tiles_range(overlap.kept_spans, overlap.start, overlap.end)
            assert tiles_range(overlap.other_spans, overlap.start, overlap.end)
            assert overlap.completing_ref in overlap.refs
        assert reassembler.usage == Usage(0, 0)

    def test_overlap_event_contents_under_first(self) -> None:
        """J (8-40) against A (0-24) and B (32-48): every differing byte
        is in 8-40, A and B keep theirs and J fills 24-32."""
        reassembler = FragmentReassembler()
        events = feed_all(reassembler, sturges_novak(4)[:10])
        (overlap,) = only(events, Overlap)
        assert (overlap.start, overlap.end) == (8, 40)
        assert overlap.kept == b"A" * 16 + b"J" * 8 + b"B" * 8
        assert overlap.other == b"J" * 32
        assert overlap.completing_ref == 9
        assert overlap.kept_spans == (
            Span(0, 8, 24, 1, 64),
            Span(9, 24, 32, 10, 64),
            Span(1, 32, 40, 2, 64),
        )
        assert overlap.other_spans == (
            Span(9, 8, 24, 10, 64),
            Span(9, 24, 32, 10, 64),
            Span(9, 32, 40, 10, 64),
        )
        assert overlap.refs == (0, 1, 9)
        assert (overlap.first_timestamp, overlap.last_timestamp) == (1, 10)
        assert overlap.direction is None
        assert not overlap.contrary

    @pytest.mark.parametrize(
        "policy", [OverlapPolicy.DISCARD, OverlapPolicy.LINUX_DISCARD]
    )
    def test_discarding_policies_discard_the_pattern(
        self, policy: OverlapPolicy
    ) -> None:
        reassembler = FragmentReassembler(policy=policy)
        events = feed_all(reassembler, sturges_novak(4))
        assert not only(events, Datagram)
        overlap = only(events, Overlap)[0]
        assert not overlap.resolved
        assert overlap.policy is policy
        assert overlap.completing_ref == 9
        assert overlap.refs == tuple(range(10))
        assert (overlap.start, overlap.end) == (8, 40)

    def test_ipv6_overlap_discards_and_a_later_train_reassembles(self) -> None:
        """RFC 5722 §4 with erratum 3089: the overlapping datagram goes,
        the key keeps no state, and a clean train under the same key
        reassembles as a new datagram."""
        reassembler = FragmentReassembler(policy=OverlapPolicy.LAST)
        frames = sturges_novak(6, identification=0x12345678)[:10]
        events = feed_all(reassembler, frames)
        (overlap,) = only(events, Overlap)
        assert not overlap.resolved
        assert overlap.policy is OverlapPolicy.DISCARD
        assert overlap.kept == b"A" * 16 + b"J" * 8 + b"B" * 8
        assert overlap.other == b"J" * 32
        assert overlap.refs == tuple(range(10))
        assert events[-1] is overlap
        assert reassembler.usage == Usage(0, 0)
        message = udp_datagram(184)
        clean = cut6(message, [(0, 64), (64, 128), (128, 192)], 0x12345678)
        later = feed_all(reassembler, clean, ts=100)
        (datagram,) = later
        assert isinstance(datagram, Datagram)
        assert payload(datagram) == message
        assert datagram.flow == overlap.flow

    def test_ipv6_overlap_with_equal_bytes_discards(self) -> None:
        message = udp_datagram(56)
        frames = cut6(message, [(0, 24), (16, 40), (40, 64)])
        events = feed_all(FragmentReassembler(), frames)
        (overlap,) = only(events, Overlap)
        assert not overlap.resolved
        assert overlap.kept == overlap.other == message[16:24]
        assert not only(events, Datagram)

    @pytest.mark.parametrize("version", [4, 6])
    def test_an_exact_duplicate_is_a_retransmission(self, version: int) -> None:
        message = udp_datagram(40)
        cut = cut4 if version == 4 else cut6
        frames = cut(message, [(0, 24), (0, 24), (24, 48)])
        events = feed_all(FragmentReassembler(), frames)
        assert [type(event) for event in events] == [Retransmission, Datagram]
        retransmission = events[0]
        assert isinstance(retransmission, Retransmission)
        assert (retransmission.start, retransmission.end) == (0, 24)
        assert retransmission.verified
        assert retransmission.refs == (0, 1)
        assert payload(only(events, Datagram)[0]) == message

    def test_a_partial_overlap_with_equal_bytes_is_a_retransmission(
        self,
    ) -> None:
        message = udp_datagram(56)
        frames = cut4(message, [(0, 24), (16, 40), (40, 64)])
        events = feed_all(FragmentReassembler(), frames)
        assert [type(event) for event in events] == [Retransmission, Datagram]
        assert (events[0].start, events[0].end) == (16, 24)  # type: ignore[union-attr]
        (datagram,) = only(events, Datagram)
        assert payload(datagram) == message
        assert datagram.spans == (
            Span(0, 0, 24, 1, 64),
            Span(1, 24, 40, 2, 64),
            Span(2, 40, 64, 3, 64),
        )

    @pytest.mark.parametrize("policy", list(OverlapPolicy))
    def test_differing_bytes_always_produce_an_overlap(
        self, policy: OverlapPolicy
    ) -> None:
        message = udp_datagram(56)
        changed = message[:8] + b"\xee" * 16 + message[24:]
        frames = [
            *cut4(message, [(0, 32)]),
            v4(1, 8, changed[8:24]),
            *cut4(message, [(32, 64)]),
        ]
        events = feed_all(FragmentReassembler(policy=policy), frames)
        (overlap,) = only(events, Overlap)
        assert (overlap.start, overlap.end) == (8, 24)
        assert {overlap.kept, overlap.other} == {message[8:24], b"\xee" * 16}

    def test_discard_policy_keeps_an_exact_duplicate(self) -> None:
        message = udp_datagram(40)
        frames = cut4(message, [(0, 24), (0, 24), (24, 48)])
        events = feed_all(
            FragmentReassembler(policy=OverlapPolicy.DISCARD), frames
        )
        assert [type(event) for event in events] == [Retransmission, Datagram]

    def test_discard_policy_discards_a_same_range_with_other_bytes(
        self,
    ) -> None:
        message = udp_datagram(40)
        frames = [
            *cut4(message, [(0, 24)]),
            v4(1, 0, b"\x01" * 24),
            *cut4(message, [(24, 48)]),
        ]
        events = feed_all(
            FragmentReassembler(policy=OverlapPolicy.DISCARD), frames
        )
        (overlap,) = only(events, Overlap)
        assert not overlap.resolved
        assert overlap.kept == message[:24]
        assert not only(events, Datagram)

    def test_linux_discard_keeps_a_contained_fragment_out(self) -> None:
        """A fragment inside a run of held fragments is dropped and the
        held bytes kept, with an Overlap when its bytes differ."""
        message = udp_datagram(56)
        changed = message[:16] + b"\xee" * 8 + message[24:]
        frames = [
            *cut4(message, [(0, 24), (24, 48)]),
            v4(1, 8, changed[8:24]),
            *cut4(message, [(48, 64)]),
        ]
        reassembler = FragmentReassembler(policy=OverlapPolicy.LINUX_DISCARD)
        events = feed_all(reassembler, frames)
        (overlap,) = only(events, Overlap)
        assert overlap.resolved
        assert (overlap.start, overlap.end) == (16, 24)
        assert overlap.kept == message[16:24]
        (datagram,) = only(events, Datagram)
        assert payload(datagram) == message

    def test_linux_discard_contained_with_equal_bytes(self) -> None:
        message = udp_datagram(56)
        frames = cut4(message, [(0, 24), (24, 48), (8, 40), (48, 64)])
        events = feed_all(
            FragmentReassembler(policy=OverlapPolicy.LINUX_DISCARD), frames
        )
        assert [type(event) for event in events] == [Retransmission, Datagram]

    def test_linux_discard_runs_follow_arrival_order(self) -> None:
        """Linux extends a run only for a fragment appended past the
        last one: a fragment inserted before it starts a run of its own,
        so one spanning both runs is an overlap, not a duplicate."""
        message = udp_datagram(56)
        reassembler = FragmentReassembler(policy=OverlapPolicy.LINUX_DISCARD)
        frames = cut4(message, [(24, 48), (0, 24), (16, 32)])
        events = feed_all(reassembler, frames)
        (overlap,) = only(events, Overlap)
        assert not overlap.resolved
        appended = FragmentReassembler(policy=OverlapPolicy.LINUX_DISCARD)
        frames = cut4(message, [(0, 24), (24, 48), (16, 32), (48, 64)])
        assert [type(event) for event in feed_all(appended, frames)] == [
            Retransmission,
            Datagram,
        ]

    def test_linux_discard_contained_in_a_run_without_held_bytes(self) -> None:
        """A run counts the fragment's declared length even where the
        snap length cut its bytes."""
        message = udp_datagram(56)
        first = v4(1, 0, message[:24])
        cut = v4(1, 24, message[24:48])[:30]
        events = feed_all(
            FragmentReassembler(policy=OverlapPolicy.LINUX_DISCARD),
            [first, cut, v4(1, 40, message[40:48])],
        )
        assert [type(event) for event in events] == [Anomaly]
        assert events[0].kind is AnomalyKind.TRUNCATED  # type: ignore[union-attr]

    def test_linux_discard_overlap_with_a_runs_uncaptured_bytes(self) -> None:
        """A run counts its fragment's declared length, so a fragment
        that overlaps only the bytes the snap length cut still discards
        the datagram."""
        reassembler = FragmentReassembler(policy=OverlapPolicy.LINUX_DISCARD)
        truncated = v4(1, 0, b"a" * 48)[: 20 + 8]
        assert kinds(feed(reassembler, truncated, ref=0)) == [
            AnomalyKind.TRUNCATED
        ]
        (overlap,) = feed(reassembler, v4(1, 16, b"b" * 40), ref=1)
        assert isinstance(overlap, Overlap)
        assert not overlap.resolved
        assert (overlap.start, overlap.end) == (16, 48)
        assert overlap.kept == overlap.other == b"b" * 32
        assert overlap.refs == (0, 1)
        assert reassembler.usage == Usage(0, 0)

    def test_a_fragment_cut_to_nothing_inside_a_held_one(self) -> None:
        """No zero-width Retransmission: only the truncation is
        reported."""
        reassembler = FragmentReassembler()
        feed(reassembler, v4(1, 0, b"a" * 48))
        events = feed(reassembler, v4(1, 16, b"c" * 16)[:20])
        assert kinds(events) == [AnomalyKind.TRUNCATED]
        assert len(events) == 1

    def test_targets_choose_the_policy_by_longest_prefix(self) -> None:
        reassembler = FragmentReassembler(
            policy=OverlapPolicy.FIRST,
            targets={
                "192.0.2.0/24": OverlapPolicy.BSD,
                "192.0.2.2": FragmentTarget(policy=OverlapPolicy.LAST),
                "192.0.0.0/16": OverlapPolicy.WINDOWS,
                "2001:db8::/32": OverlapPolicy.LAST,
            },
        )
        events = feed_all(reassembler, sturges_novak(4))
        (datagram,) = only(events, Datagram)
        assert (
            payload(datagram)[::8].decode()
            == STURGES_NOVAK_EXPECTED[OverlapPolicy.LAST]
        )
        other = FragmentReassembler(
            targets={
                "192.0.2.0/24": OverlapPolicy.SOLARIS,
                "10.0.0.0/8": OverlapPolicy.LAST,
            }
        )
        frames = [
            v4(
                1,
                offset,
                letter.encode() * length,
                more=letter != "Q",
                dst="192.0.2.9",
            )
            for offset, letter, length in STURGES_NOVAK
        ]
        (datagram,) = only(feed_all(other, frames), Datagram)
        assert (
            payload(datagram)[::8].decode()
            == STURGES_NOVAK_EXPECTED[OverlapPolicy.SOLARIS]
        )
        unmatched = FragmentReassembler(
            targets={"10.0.0.0/8": OverlapPolicy.LAST}
        )
        (datagram,) = only(feed_all(unmatched, sturges_novak(4)), Datagram)
        assert (
            payload(datagram)[::8].decode()
            == STURGES_NOVAK_EXPECTED[OverlapPolicy.FIRST]
        )

    def test_an_arriving_fragment_inside_a_held_one_it_replaces(self) -> None:
        """Under last, a fragment inside a held one splits it in three."""
        reassembler = FragmentReassembler(policy=OverlapPolicy.LAST)
        frames = [
            v4(1, 0, b"A" * 32),
            v4(1, 8, b"B" * 8),
            v4(1, 32, b"C" * 8, more=False),
        ]
        (overlap, datagram) = feed_all(reassembler, frames)
        assert isinstance(datagram, Datagram)
        assert payload(datagram) == b"A" * 8 + b"B" * 8 + b"A" * 16 + b"C" * 8
        assert [
            (span.ref, span.start, span.end) for span in datagram.spans
        ] == [
            (0, 0, 8),
            (1, 8, 16),
            (0, 16, 32),
            (2, 32, 40),
        ]
        assert datagram.header_ref == 0
        assert isinstance(overlap, Overlap)

    def test_one_overlap_per_frame_however_many_pieces(self) -> None:
        reassembler = FragmentReassembler(policy=OverlapPolicy.LAST)
        frames = [v4(1, 8 * index, b"a" * 8) for index in range(0, 20, 2)]
        frames.append(v4(1, 0, b"b" * 160))
        events = feed_all(reassembler, frames)
        (overlap,) = only(events, Overlap)
        assert (overlap.start, overlap.end) == (0, 152)
        assert overlap.kept == b"b" * 152
        assert len(overlap.other_spans) == 19


def tiles_range(spans: tuple[Span, ...], start: int, end: int) -> bool:
    cursor = start
    for span in spans:
        if span.start != cursor:
            return False
        cursor = span.end
    return cursor == end


# --- 3.5: rules -------------------------------------------------------


def kinds(events: Iterable[FragmentEvent]) -> list[AnomalyKind]:
    return [event.kind for event in events if isinstance(event, Anomaly)]


class TestRules:
    def test_oversize_ipv4_discards_the_datagram(self) -> None:
        reassembler = FragmentReassembler()
        frames = [v4(1, 0, b"a" * 16), v4(1, 65_512, b"b" * 8)]
        events = feed_all(reassembler, frames)
        (anomaly,) = events
        assert isinstance(anomaly, Anomaly)
        assert anomaly.kind is AnomalyKind.OVERSIZE
        assert (anomaly.start, anomaly.end) == (65_512, 65_520)
        assert anomaly.refs == (0, 1)
        assert reassembler.usage == Usage(0, 0)

    def test_oversize_counts_the_first_fragments_ipv4_header(self) -> None:
        """A later fragment with a short header is judged by the header
        the rebuilt datagram takes, the first fragment's 60 bytes."""
        options = b"\x01" * 40
        reassembler = FragmentReassembler()
        assert feed(reassembler, v4(7, 0, b"x" * 8, options=options)) == ()
        events = feed(reassembler, v4(7, 8, b"y" * 65_504, more=False), ref=1)
        (anomaly,) = events
        assert isinstance(anomaly, Anomaly)
        assert anomaly.kind is AnomalyKind.OVERSIZE
        assert anomaly.refs == (0, 1)
        assert reassembler.usage == Usage(0, 0)

    def test_oversize_counts_the_first_fragments_ipv6_headers(self) -> None:
        hop_by_hop = bytes([44, 31, 1, 252]) + bytes(252)
        reassembler = FragmentReassembler()
        first = v6(7, 0, udp_datagram(0), extensions=hop_by_hop, first=0)
        assert feed(reassembler, first) == ()
        events = feed(reassembler, v6(7, 8, b"y" * 65_520, more=False))
        assert kinds(events) == [AnomalyKind.OVERSIZE]
        assert reassembler.usage.flows == 1

    @pytest.mark.parametrize("version", [4, 6])
    def test_oversize_found_when_the_first_fragment_comes_last(
        self, version: int
    ) -> None:
        """Until the first fragment arrives its header is unknown, so a
        datagram it would push past 65,535 bytes is discarded when it
        completes."""
        reassembler = FragmentReassembler()
        if version == 4:
            frames = [
                v4(7, 8, b"y" * 65_496, more=False),
                v4(7, 0, b"x" * 8, options=b"\x01" * 40),
            ]
        else:
            hop_by_hop = bytes([44, 31, 1, 252]) + bytes(252)
            frames = [
                v6(7, 8, b"y" * 65_400, more=False),
                v6(7, 0, udp_datagram(0), extensions=hop_by_hop, first=0),
            ]
        events = feed_all(reassembler, frames)
        (anomaly,) = events
        assert isinstance(anomaly, Anomaly)
        assert anomaly.kind is AnomalyKind.OVERSIZE
        assert anomaly.completing_ref == 1
        assert anomaly.refs == (0, 1)
        assert reassembler.usage == Usage(0, 0)

    def test_the_largest_ipv4_datagram_is_not_oversize(self) -> None:
        reassembler = FragmentReassembler()
        message = bytes(65_515)
        pieces = [
            (start, min(start + 1480, 65_515))
            for start in range(0, 65_515, 1480)
        ]
        events = feed_all(reassembler, cut4(message, pieces))
        (datagram,) = events
        assert isinstance(datagram, Datagram)
        assert len(datagram.data) == 65_535

    def test_oversize_ipv6_drops_the_fragment_only(self) -> None:
        reassembler = FragmentReassembler()
        message = udp_datagram(24)
        frames = [
            *cut6(message, [(0, 16)]),
            v6(1, 65_528, b"x" * 8),
            *cut6(message, [(16, 32)]),
        ]
        events = feed_all(reassembler, frames)
        assert kinds(events) == [AnomalyKind.OVERSIZE]
        assert only(events, Anomaly)[0].refs == (1,)
        (datagram,) = only(events, Datagram)
        assert payload(datagram) == message

    def test_misaligned_ipv6_drops_the_fragment(self) -> None:
        message = udp_datagram(24)
        frames = [
            *cut6(message, [(0, 16)]),
            v6(1, 16, b"x" * 12),
            *cut6(message, [(16, 32)]),
        ]
        events = feed_all(FragmentReassembler(), frames)
        assert kinds(events) == [AnomalyKind.MISALIGNED]
        assert payload(only(events, Datagram)[0]) == message

    def test_misaligned_ipv4_is_cut_to_eight_and_kept(self) -> None:
        message = udp_datagram(24)
        frames = [v4(1, 0, message[:16] + b"zzzz"), *cut4(message, [(16, 32)])]
        events = feed_all(FragmentReassembler(), frames)
        assert kinds(events) == [AnomalyKind.MISALIGNED]
        assert (events[0].start, events[0].end) == (0, 20)  # type: ignore[union-attr]
        (datagram,) = only(events, Datagram)
        assert payload(datagram) == message
        assert datagram.spans[0] == Span(0, 0, 16, 1, 64)

    def test_misaligned_ipv4_with_nothing_left_discards_the_datagram(
        self,
    ) -> None:
        reassembler = FragmentReassembler()
        frames = [v4(1, 0, b"a" * 16), v4(1, 16, b"bbb")]
        events = feed_all(reassembler, frames)
        (anomaly,) = events
        assert isinstance(anomaly, Anomaly)
        assert anomaly.kind is AnomalyKind.MISALIGNED
        assert anomaly.refs == (0, 1)
        assert reassembler.usage == Usage(0, 0)

    @pytest.mark.parametrize(
        "frames",
        [
            # Two last fragments that disagree.
            [
                v4(1, 0, b"a" * 16),
                v4(1, 24, b"b" * 8, more=False),
                v4(1, 32, b"c" * 8, more=False),
            ],
            # Data past a known end.
            [v4(1, 16, b"b" * 8, more=False), v4(1, 16, b"b" * 16)],
            # A last fragment ending before held data.
            [v4(1, 32, b"c" * 8), v4(1, 16, b"b" * 8, more=False)],
        ],
    )
    def test_inconsistent_end_discards_the_datagram(
        self, frames: list[bytes]
    ) -> None:
        reassembler = FragmentReassembler()
        events = feed_all(reassembler, frames)
        assert kinds(events) == [AnomalyKind.INCONSISTENT_END]
        assert events[-1].refs == tuple(range(len(frames)))
        assert reassembler.usage == Usage(0, 0)

    def test_empty_ipv4_fragment_drops_the_fragment(self) -> None:
        message = udp_datagram(24)
        frames = [
            *cut4(message, [(0, 16)]),
            v4(1, 16, b""),
            *cut4(message, [(16, 32)]),
        ]
        events = feed_all(FragmentReassembler(), frames)
        assert kinds(events) == [AnomalyKind.EMPTY_FRAGMENT]
        assert events[0].refs == (1,)
        assert payload(only(events, Datagram)[0]) == message

    def test_empty_fragment_discards_under_linux_discard(self) -> None:
        reassembler = FragmentReassembler(policy=OverlapPolicy.LINUX_DISCARD)
        frames = [v4(1, 0, b"a" * 16), v4(1, 16, b"")]
        events = feed_all(reassembler, frames)
        assert kinds(events) == [AnomalyKind.EMPTY_FRAGMENT]
        assert events[0].refs == (0, 1)
        assert reassembler.usage == Usage(0, 0)

    def test_empty_ipv6_fragment_discards_the_datagram(self) -> None:
        reassembler = FragmentReassembler()
        frames = [v6(1, 0, udp_datagram(8)), v6(1, 16, b"")]
        events = feed_all(reassembler, frames)
        assert kinds(events) == [AnomalyKind.EMPTY_FRAGMENT]
        assert events[0].refs == (0, 1)
        assert reassembler.usage == Usage(0, 0)

    def test_empty_first_fragment_of_a_datagram(self) -> None:
        reassembler = FragmentReassembler()
        assert kinds(feed(reassembler, v6(1, 8, b""))) == [
            AnomalyKind.EMPTY_FRAGMENT
        ]
        assert reassembler.usage == Usage(0, 0)

    @pytest.mark.parametrize(
        ("next_header", "data", "complete"),
        [
            (6, bytes(16), False),
            (6, bytes(24), True),
            (17, bytes(8), True),
            (58, bytes(8), True),
            (59, b"", True),
            (60, bytes([6, 0]) + bytes(6) + bytes(16), False),
            (60, bytes([17, 0]) + bytes(6) + bytes(8), True),
            (51, bytes([17, 1]) + bytes(10) + bytes(8), True),
            (51, bytes([17, 3]) + bytes(10) + bytes(8), False),
            (60, bytes([60, 0]) + bytes(6), False),
            (44, bytes([17, 0]) + bytes(6) + bytes(8), True),
            (0, bytes([17]), False),
            (50, bytes(8), True),
        ],
    )
    def test_incomplete_header_chain(
        self, next_header: int, data: bytes, complete: bool
    ) -> None:
        """RFC 7112 §5: a first fragment must hold the header chain."""
        data = data + bytes(-len(data) % 8) if data else bytes(8)
        if next_header == 59:
            data = bytes(8)
        frame = v6(1, 0, data, next_header=next_header)
        reassembler = FragmentReassembler()
        events = feed(reassembler, frame)
        if complete:
            assert events == ()
            assert reassembler.usage.flows == 1
        else:
            assert kinds(events) == [AnomalyKind.INCOMPLETE_HEADER_CHAIN]
            assert reassembler.usage.flows == 0

    def test_a_truncated_first_fragment_is_not_judged_by_its_chain(
        self,
    ) -> None:
        frame = v6(1, 0, bytes(24), next_header=6)[: 40 + 8 + 8]
        events = feed(FragmentReassembler(), frame)
        assert kinds(events) == [AnomalyKind.TRUNCATED]

    @pytest.mark.parametrize(
        ("protocol", "length", "tiny"),
        [(6, 16, True), (6, 24, False), (17, 8, False), (1, 8, False)],
    )
    def test_tiny_fragment_is_reported(
        self, protocol: int, length: int, tiny: bool
    ) -> None:
        """RFC 1858 §3: reported, and the datagram still reassembles."""
        message = bytes(range(length + 16))
        frames = [
            v4(1, 0, message[:length], protocol=protocol),
            v4(1, length, message[length:], more=False, protocol=protocol),
        ]
        events = feed_all(FragmentReassembler(), frames)
        assert kinds(events) == ([AnomalyKind.TINY_FRAGMENT] if tiny else [])
        assert payload(only(events, Datagram)[0]) == message

    def test_tiny_udp_fragment(self) -> None:
        """A UDP first fragment under 8 bytes with MF set is misaligned
        too, and reported as tiny before it is discarded."""
        events = feed(FragmentReassembler(), v4(1, 0, b"abcd"))
        assert kinds(events) == [
            AnomalyKind.TINY_FRAGMENT,
            AnomalyKind.MISALIGNED,
        ]

    def test_tcp_offset_one_is_reported_and_resolved_by_policy(self) -> None:
        """RFC 1858 §4, RFC 3128: the fragment at offset 1 rewrites the
        TCP flags under last, and is reported under every policy."""
        segment = bytes(range(40))
        frames = [
            v4(1, 0, segment[:24], protocol=6),
            v4(1, 8, b"\xff" * 16, protocol=6),
            v4(1, 24, segment[24:], more=False, protocol=6),
        ]
        for policy in (OverlapPolicy.FIRST, OverlapPolicy.LAST):
            events = feed_all(FragmentReassembler(policy=policy), frames)
            assert AnomalyKind.TCP_OFFSET_ONE in kinds(events)
            assert only(events, Overlap)
            data = payload(only(events, Datagram)[0])
            assert (data[8:24] == b"\xff" * 16) is (
                policy is OverlapPolicy.LAST
            )

    def test_truncated_fragment_leaves_a_hole(self) -> None:
        message = udp_datagram(24)
        first, last = cut4(message, [(0, 16), (16, 32)])
        reassembler = FragmentReassembler()
        events = feed_all(reassembler, [first, last[:-4]])
        assert kinds(events) == [AnomalyKind.TRUNCATED]
        assert (events[0].start, events[0].end) == (28, 32)  # type: ignore[union-attr]
        (expired,) = reassembler.close()
        assert isinstance(expired, Expired)
        assert expired.missing == ((28, 32),)
        assert expired.held_bytes == 28

    def test_a_fragment_cut_to_nothing_holds_no_span(self) -> None:
        reassembler = FragmentReassembler()
        frame = v4(1, 16, b"x" * 16)[:20]
        assert kinds(feed(reassembler, frame, ts=7)) == [AnomalyKind.TRUNCATED]
        assert reassembler.usage.flows == 1
        (expired,) = reassembler.close()
        assert isinstance(expired, Expired)
        assert expired.spans == ()
        assert (expired.first_timestamp, expired.last_timestamp) == (7, 7)
        assert expired.held_bytes == 0
        assert expired.missing == ((0, None),)

    def test_a_retransmission_fills_a_truncation_hole(self) -> None:
        message = udp_datagram(24)
        first, last = cut4(message, [(0, 16), (16, 32)])
        events = feed_all(FragmentReassembler(), [first, last[:-4], last])
        assert isinstance(events[-1], Datagram)
        assert payload(events[-1]) == message

    @pytest.mark.parametrize("mode", list(ChecksumMode))
    def test_bad_checksum(self, mode: ChecksumMode) -> None:
        message = udp_datagram(24)
        first = v4(1, 0, message[:16], checksum=0x1234)
        last = cut4(message, [(16, 32)])[0]
        events = feed_all(FragmentReassembler(checksums=mode), [first, last])
        assert kinds(events) == [AnomalyKind.BAD_CHECKSUM]
        assert bool(only(events, Datagram)) is (mode is ChecksumMode.KEEP)

    @pytest.mark.parametrize(
        ("mode", "local", "used"),
        [
            (ChecksumMode.AUTO, None, True),
            (ChecksumMode.AUTO, ["192.0.2.0/24"], True),
            (ChecksumMode.AUTO, ["198.51.100.0/24", "2001:db8::/32"], False),
            (ChecksumMode.DROP, None, False),
            (ChecksumMode.KEEP, ["198.51.100.0/24"], True),
        ],
    )
    def test_offloaded_header_checksum(
        self, mode: ChecksumMode, local: list[str] | None, used: bool
    ) -> None:
        """A zero IPv4 header checksum, which Windows leaves for its NIC
        to fill, under each mode and ``local``."""
        message = udp_datagram(24)
        first = v4(1, 0, message[:16], checksum=0)
        last = cut4(message, [(16, 32)])[0]
        events = feed_all(
            FragmentReassembler(checksums=mode, local=local), [first, last]
        )
        offload = (
            [AnomalyKind.CHECKSUM_OFFLOAD]
            if mode is ChecksumMode.AUTO and used
            else []
        )
        assert kinds(events) == [AnomalyKind.BAD_CHECKSUM, *offload]
        assert bool(only(events, Datagram)) is used

    @pytest.mark.parametrize("mode", list(ChecksumMode))
    def test_a_zero_length_header_is_unverified(
        self, mode: ChecksumMode
    ) -> None:
        message = udp_datagram(24)
        first = v4(1, 0, message[:16], total_length=0)
        last = cut4(message, [(16, 32)])[0]
        events = feed_all(FragmentReassembler(checksums=mode), [first, last])
        assert kinds(events) == [AnomalyKind.UNVERIFIED_CHECKSUM]
        assert bool(only(events, Datagram)) is (mode is ChecksumMode.KEEP)

    def test_a_zero_ipv6_payload_length_is_unverified(self) -> None:
        frame = v6(1, 0, udp_datagram(8), payload_length=0)
        events = feed(FragmentReassembler(checksums=ChecksumMode.KEEP), frame)
        assert kinds(events) == [AnomalyKind.UNVERIFIED_CHECKSUM]

    def test_hop_limit_changed(self) -> None:
        message = udp_datagram(24)
        (first,) = cut4(message, [(0, 16)])
        last = v4(1, 16, message[16:], more=False, ttl=3)
        events = feed_all(FragmentReassembler(), [first, last])
        assert kinds(events) == [AnomalyKind.HOP_LIMIT_CHANGED]
        (datagram,) = only(events, Datagram)
        assert [span.hop_limit for span in datagram.spans] == [64, 3]

    def test_next_header_changed(self) -> None:
        message = udp_datagram(24)
        frames = [
            v6(1, 0, message[:16]),
            v6(1, 16, message[16:], more=False, next_header=6),
        ]
        events = feed_all(FragmentReassembler(), frames)
        assert kinds(events) == [AnomalyKind.NEXT_HEADER_CHANGED]
        (datagram,) = only(events, Datagram)
        assert (
            decode_frame(datagram.data, start=IPv6).layers[0].next_header == 17
        )  # type: ignore[attr-defined]

    def test_anomalies_come_in_offset_order_before_the_datagram(self) -> None:
        message = bytes(range(16))
        frames = [
            v4(1, 8, message[8:], more=False, protocol=6, ttl=9),
            v4(1, 0, message[:8], protocol=6, checksum=0x1111, ttl=8),
        ]
        events = feed_all(
            FragmentReassembler(checksums=ChecksumMode.KEEP), frames
        )
        assert kinds(events) == [
            AnomalyKind.TCP_OFFSET_ONE,
            AnomalyKind.BAD_CHECKSUM,
            AnomalyKind.TINY_FRAGMENT,
            AnomalyKind.HOP_LIMIT_CHANGED,
        ]
        assert isinstance(events[-1], Datagram)


# --- 3.6: the reassembled datagram -------------------------------------


class TestReassembledDatagram:
    def test_ipv4_header_is_rewritten(self) -> None:
        message = udp_datagram(40)
        options = b"\x94\x04\x00\x00"  # Router Alert
        frames = [
            v4(0x4242, 0, message[:24], flags=0b110, options=options, ttl=33),
            v4(0x4242, 24, message[24:], more=False, flags=0b010, ttl=33),
        ]
        reassembler = FragmentReassembler()
        events = feed_all(reassembler, list(reversed(frames)))
        (datagram,) = events
        assert isinstance(datagram, Datagram)
        assert datagram.version == 4
        assert datagram.header_ref == 1
        assert datagram.completing_ref == 1
        assert datagram.payload_offset == 24
        header = IPv4.decode(datagram.data)
        assert bytes(header) == datagram.data[: datagram.payload_offset]
        assert header.total_length == 24 + 48
        assert header.flags == 0b110
        assert header.fragment_offset == 0
        assert header.options == options
        assert header.ttl == 33
        assert header.identification == 0x4242
        assert internet_checksum(datagram.data[:24]) == 0
        packet = decode_frame(datagram.data, start=IPv4)
        assert isinstance(packet.layers[1], UDP)
        assert packet.layers[1].length == 48

    def test_ipv6_per_fragment_headers_are_kept(self) -> None:
        """RFC 8200 §4.5: the Per-Fragment headers, the last one's Next
        Header set to the Fragment header's, the Fragment header gone
        and Payload Length recomputed."""
        hop_by_hop = bytes([44, 0, 1, 4, 0, 0, 0, 0])
        message = udp_datagram(40)
        frames = [
            v6(7, 0, message[:24], extensions=hop_by_hop, first=0),
            v6(7, 24, message[24:], more=False, extensions=hop_by_hop, first=0),
        ]
        (datagram,) = feed_all(FragmentReassembler(), frames)
        assert isinstance(datagram, Datagram)
        assert datagram.version == 6
        assert datagram.payload_offset == 48
        assert datagram.flow == FragmentKey(6, SRC6, DST6, None, 7)
        packet = decode_frame(datagram.data, start=IPv6)
        ip, hop, udp = packet.layers
        assert isinstance(ip, IPv6) and isinstance(hop, IPv6HopByHopOptions)
        assert isinstance(udp, UDP)
        assert ip.payload_length == 8 + 48
        assert ip.next_header == 0
        assert hop.next_header == 17
        assert ip.header_len + hop.header_len == datagram.payload_offset
        assert payload(datagram) == message

    def test_ipv6_without_extension_headers(self) -> None:
        message = udp_datagram(40)
        (datagram,) = feed_all(
            FragmentReassembler(), cut6(message, [(0, 24), (24, 48)])
        )
        assert isinstance(datagram, Datagram)
        ip = IPv6.decode(datagram.data)
        assert (ip.next_header, ip.payload_length) == (17, 48)
        assert datagram.payload_offset == 40

    def test_routing_header_receiver_selects_the_target(self) -> None:
        """Behind a Routing header with segments left, the receiver is
        the route's final destination (RFC 8200 §8.1)."""
        final = "2001:db8:ffff::9"
        routing = (
            bytes([44, 2, 0, 1, 0, 0, 0, 0])
            + ipaddress.IPv6Address(final).packed
        )
        frame = v6(3, 0, udp_datagram(8), extensions=routing, first=43)
        reassembler = FragmentReassembler(
            targets={"2001:db8:ffff::/48": FragmentTarget(age_timeout=5)}
        )
        assert feed(reassembler, frame, ts=10) == ()
        (expired,) = reassembler.advance(15)
        assert isinstance(expired, Expired)
        assert expired.timeout is Timeout.AGE

    def test_slow_ipv4_reassembly_is_reported(self) -> None:
        message = udp_datagram(24)
        first, last = cut4(message, [(0, 16), (16, 32)])
        reassembler = FragmentReassembler()
        feed(reassembler, first, ts=SECOND)
        events = feed(reassembler, last, ts=31 * SECOND + 1)
        assert kinds(events) == [AnomalyKind.SLOW_REASSEMBLY]
        assert (events[0].start, events[0].end) == (0, 32)  # type: ignore[union-attr]
        assert isinstance(events[1], Datagram)

    def test_slow_reassembly_needs_more_than_thirty_seconds(self) -> None:
        message = udp_datagram(24)
        first, last = cut4(message, [(0, 16), (16, 32)])
        reassembler = FragmentReassembler()
        feed(reassembler, first, ts=SECOND)
        assert kinds(feed(reassembler, last, ts=31 * SECOND)) == []

    def test_no_slow_reassembly_under_a_target_age_timeout_or_for_ipv6(
        self,
    ) -> None:
        message = udp_datagram(24)
        targeted = FragmentReassembler(
            targets={DST4: FragmentTarget(age_timeout=50 * SECOND)}
        )
        first, last = cut4(message, [(0, 16), (16, 32)])
        feed(targeted, first, ts=SECOND)
        assert kinds(feed(targeted, last, ts=45 * SECOND)) == []
        plain = FragmentReassembler()
        first6, last6 = cut6(message, [(0, 16), (16, 32)])
        feed(plain, first6, ts=SECOND)
        assert kinds(feed(plain, last6, ts=45 * SECOND)) == []


# --- real captures ----------------------------------------------------


def run_capture(
    path: Path, reassembler: FragmentReassembler
) -> tuple[list[FragmentEvent], list[FragmentEvent]]:
    events: list[FragmentEvent] = []
    for index, captured in enumerate(read_pcap(path.read_bytes())):
        packet = decode_frame(captured.data, lax=True)
        events += reassembler.feed(
            packet, captured.data, timestamp=captured.timestamp, ref=index
        )
    return events, list(reassembler.close())


#: tshark 4.2.2's ip.reassembled_in / ipv6.reassembled.in frame (as a
#: 0-based index) and the length and SHA-256 of ip.reassembled.data /
#: ipv6.reassembled.data, recorded at capture time.
TSHARK_REASSEMBLED = {
    FIXTURES / "ipv4_fragments.pcap": [
        (
            2,
            2008,
            "c61040ad53c70b00a7f1f37313eacde8f7075a7ec39f9f2e12d21d4186a67a79",
        ),
        (
            4,
            2008,
            "5348a27bc5ed2b9e69e001e4f09e9982719a6d33635e2334128618fadc84b930",
        ),
    ],
    FIXTURES / "ipv6_fragments.pcap": [
        (
            2,
            2008,
            "d5feb99217ecd3043510819ca5ff4d5fc07cc1509b6fe71c2d3913e68a7a81c2",
        ),
        (
            4,
            2008,
            "912f881b4e870384e72e3224ec334f9a09de22cdb7b3cc1401e009f7ade54588",
        ),
    ],
    REASSEMBLY / "ipv4_udp_fragments.pcap": [
        (
            2,
            4008,
            "211d8f4711612d37be1c8bcf7de51adfac56fd9a50d416d53652cc680d318203",
        ),
        (
            4,
            2598,
            "b4ffa55cf60fbbd918b86f07472aeaab8fe0d0f4fdb09ed1e8b1e64eaa329c2c",
        ),
        (
            6,
            2598,
            "35e803d4fa4fd2c19a4bf96314487902e71dbcec40fd96b524c089bfb478fec5",
        ),
    ],
}


class TestRealCaptures:
    @pytest.mark.parametrize(
        "path", list(TSHARK_REASSEMBLED), ids=lambda path: path.name
    )
    def test_reassembles_to_tsharks_data(self, path: Path) -> None:
        events, _ = run_capture(path, FragmentReassembler())
        datagrams = only(events, Datagram)
        assert [
            (
                datagram.completing_ref,
                len(payload(datagram)),
                hashlib.sha256(payload(datagram)).hexdigest(),
            )
            for datagram in datagrams
        ] == TSHARK_REASSEMBLED[path]
        assert len(datagrams) == len(events)
        for datagram in datagrams:
            assert tiles(datagram.spans, len(payload(datagram)))
            start = IPv4 if datagram.version == 4 else IPv6
            whole = decode_frame(datagram.data, start=start)
            assert whole.consumed >= datagram.payload_offset

    @pytest.mark.parametrize(
        "name", ["ipv4_fragments.pcap", "ipv6_fragments.pcap"]
    )
    def test_orphan_last_fragment_expires_on_close(self, name: str) -> None:
        """Each holds two whole datagrams and the last fragment of a
        third, whose first fragment the capture missed."""
        _, closed = run_capture(FIXTURES / name, FragmentReassembler())
        (expired,) = closed
        assert isinstance(expired, Expired)
        assert expired.refs == (0,)
        assert expired.completing_ref is None
        assert expired.missing == (
            ((0, 1480),) if name.startswith("ipv4") else ((0, 1368),)
        )

    def test_udp_datagram_is_the_one_sent(self) -> None:
        events, _ = run_capture(
            REASSEMBLY / "ipv4_udp_fragments.pcap", FragmentReassembler()
        )
        first = only(events, Datagram)[0]
        whole = decode_frame(first.data, start=IPv4)
        assert whole.layers[1] == UDP(
            src_port=4000,
            dst_port=4001,
            length=4008,
            checksum=whole.layers[1].checksum,  # type: ignore[attr-defined]
        )
        sent = bytes(range(256)) * 15 + bytes(range(160))
        assert payload(first)[8:] == sent
        assert netprotocols.checksum.verify(
            whole.layers[1],
            ip=whole.layers[0],
            payload=sent,  # type: ignore[arg-type]
        )

    def test_linux_overlaps_match_the_kernel(self) -> None:
        """The running kernel replied to exactly the trains it
        reassembled, and its reply echoes the bytes it kept: under
        linux-discard the reassembler completes the same datagrams with
        the same bytes, and discards the rest."""
        path = REASSEMBLY / "linux_overlaps.pcap"
        replies: dict[int, bytes] = {}
        for captured in read_pcap(path.read_bytes()):
            packet = decode_frame(captured.data, lax=True)
            icmp = packet.get(ICMPv4)
            if isinstance(icmp, ICMPv4) and icmp.type == 0:
                assert icmp.identifier is not None
                replies[icmp.identifier] = icmp.body
        events, closed = run_capture(
            path, FragmentReassembler(policy=OverlapPolicy.LINUX_DISCARD)
        )
        completed = {}
        for datagram in only(events, Datagram):
            request = ICMPv4.decode(payload(datagram))
            assert request.identifier is not None
            completed[request.identifier] = request.body
        assert completed == replies
        assert set(replies) == {0x4F02, 0x4F03, 0x4F05}
        overlaps = only(events, Overlap)
        assert [(o.flow.identification, o.resolved) for o in overlaps] == [  # type: ignore[union-attr]
            (0x7901, False),
            (0x7902, False),
            (0x7903, True),
            (0x7904, False),
        ]
        assert [o.completing_ref for o in overlaps] == [9, 26, 33, 37]
        contained = overlaps[2]
        assert contained.kept_spans == (
            Span(31, 16, 24, contained.kept_spans[0].timestamp, 64),
        )
        assert contained.other == b"\xee" * 8
        assert {event.flow.identification for event in closed} == {
            0x7901,
            0x7904,
        }  # type: ignore[union-attr]

    @pytest.mark.parametrize("policy", list(OverlapPolicy))
    def test_linux_overlaps_overlap_under_every_policy(
        self, policy: OverlapPolicy
    ) -> None:
        """tshark 4.2.2 flags ip.fragment.overlap.conflict in trains
        0x7901, 0x7902 and 0x7903: each yields an Overlap whose bytes
        differ, under every policy."""
        events, _ = run_capture(
            REASSEMBLY / "linux_overlaps.pcap",
            FragmentReassembler(policy=policy),
        )
        differing = {
            overlap.flow.identification  # type: ignore[union-attr]
            for overlap in only(events, Overlap)
            if overlap.kept != overlap.other
        }
        assert differing == {0x7901, 0x7902, 0x7903}


# --- flushes ------------------------------------------------------------


class TestFlushes:
    def test_expiry_another_datagram_triggers_carries_no_ref(self) -> None:
        reassembler = FragmentReassembler()
        feed(reassembler, v4(1, 0, b"a" * 8), ts=SECOND, ref=0)
        events = feed(reassembler, v4(2, 0, b"b" * 8), ts=61 * SECOND, ref=1)
        (expired,) = events
        assert isinstance(expired, Expired)
        assert expired.flow.identification == 1  # type: ignore[union-attr]
        assert expired.completing_ref is None
        assert expired.timeout is Timeout.AGE
        assert expired.refs == (0,)

    def test_eviction_another_datagram_triggers_carries_no_ref(self) -> None:
        reassembler = FragmentReassembler(bounds=FragmentBounds(max_flows=1))
        feed(reassembler, v4(1, 0, b"a" * 8), ref=0)
        events = feed(reassembler, v4(2, 0, b"b" * 8), ref=1)
        (evicted,) = events
        assert isinstance(evicted, Evicted)
        assert evicted.bound is Bound.MAX_FLOWS
        assert evicted.completing_ref is None
        assert evicted.missing == ((8, None),)

    def test_eviction_by_its_own_fragment_carries_its_ref(self) -> None:
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(max_fragments=1)
        )
        feed(reassembler, v4(1, 0, b"a" * 8), ref=0)
        (evicted,) = feed(reassembler, v4(1, 16, b"b" * 8), ref=1)
        assert isinstance(evicted, Evicted)
        assert evicted.bound is Bound.MAX_FRAGMENTS
        assert evicted.completing_ref == 1
        assert evicted.refs == (0, 1)
        assert evicted.held_bytes == 8
        assert evicted.missing == ((8, 16), (24, None))

    def test_close_reports_every_datagram_and_empties(self) -> None:
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(age_timeout=None, idle_timeout=None)
        )
        feed(reassembler, v4(1, 0, b"a" * 8), ts=5, ref=0)
        feed(reassembler, v4(2, 8, b"b" * 8, more=False), ts=3, ref=1)
        closed = reassembler.close()
        assert [event.refs for event in closed] == [(0,), (1,)]
        assert all(
            isinstance(event, Expired) and event.timeout is Timeout.AGE
            for event in closed
        )
        assert closed[1].missing == ((0, 8),)  # type: ignore[union-attr]
        assert all(event.completing_ref is None for event in closed)
        assert reassembler.usage == Usage(0, 0)
        assert reassembler.close() == ()

    def test_close_reports_the_nearest_timeout(self) -> None:
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(idle_timeout=2 * SECOND)
        )
        feed(reassembler, v4(1, 0, b"a" * 8), ts=SECOND)
        feed(reassembler, v4(2, 0, b"b" * 8), ts=SECOND // 2)
        (first, second) = reassembler.close()
        assert isinstance(first, Expired) and isinstance(second, Expired)
        assert first.timeout is second.timeout is Timeout.IDLE
        assert first.flow.identification == 2  # type: ignore[union-attr]


# --- 7.3: deterministic bounds --------------------------------------


def charge(data_bytes: int, pieces: int, header: int = 20) -> int:
    return FLOW_OVERHEAD + pieces * PIECE_OVERHEAD + data_bytes + header


class TestBounds:
    def test_default_max_flow_bytes_holds_a_maximal_datagram(self) -> None:
        reassembler = FragmentReassembler()
        message = bytes(65_515)
        pieces = [
            (start, min(start + 552, 65_515)) for start in range(0, 65_515, 552)
        ]
        assert len(pieces) == 119
        events = feed_all(reassembler, cut4(message, pieces))
        assert [type(event) for event in events] == [Datagram]

    @pytest.mark.parametrize("over", [0, 1])
    def test_max_flow_bytes(self, over: int) -> None:
        limit = charge(16, 2)
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(max_flow_bytes=limit - over)
        )
        events = feed_all(
            reassembler, [v4(1, 0, b"a" * 8), v4(1, 16, b"b" * 8)]
        )
        if over:
            (evicted,) = events
            assert isinstance(evicted, Evicted)
            assert evicted.bound is Bound.MAX_FLOW_BYTES
            assert evicted.completing_ref == 1
            assert reassembler.usage == Usage(0, 0)
        else:
            assert events == []
            assert reassembler.usage == Usage(1, limit)

    def test_a_piece_larger_than_max_flow_bytes_is_evicted_at_once(
        self,
    ) -> None:
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(max_flow_bytes=100)
        )
        (evicted,) = feed(reassembler, v4(1, 0, b"a" * 8), ref=0)
        assert isinstance(evicted, Evicted)
        assert evicted.bound is Bound.MAX_FLOW_BYTES
        assert evicted.held_bytes == 0
        assert evicted.refs == (0,)
        assert reassembler.usage == Usage(0, 0)

    @pytest.mark.parametrize("over", [0, 1])
    def test_max_fragments(self, over: int) -> None:
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(max_fragments=3)
        )
        frames = [v4(1, 16 * index, b"x" * 8) for index in range(3 + over)]
        events = feed_all(reassembler, frames)
        if over:
            (evicted,) = events
            assert isinstance(evicted, Evicted)
            assert evicted.bound is Bound.MAX_FRAGMENTS
        else:
            assert events == []
            assert reassembler.usage.flows == 1

    @pytest.mark.parametrize("over", [0, 1])
    def test_max_flows_evicts_the_oldest(self, over: int) -> None:
        reassembler = FragmentReassembler(bounds=FragmentBounds(max_flows=3))
        frames = [
            v4(identification, 0, b"x" * 8)
            for identification in range(3 + over)
        ]
        events = []
        for index, frame in enumerate(frames):
            events += feed(reassembler, frame, ts=10 - index, ref=index)
        assert reassembler.usage.flows == 3
        if over:
            (evicted,) = events
            assert isinstance(evicted, Evicted)
            assert evicted.bound is Bound.MAX_FLOWS
            assert evicted.flow.identification == 3  # type: ignore[union-attr]
            assert evicted.completing_ref == 3
        else:
            assert events == []

    def test_eviction_ties_go_by_feed_order(self) -> None:
        reassembler = FragmentReassembler(bounds=FragmentBounds(max_flows=2))
        for identification in range(3):
            events = feed(reassembler, v4(identification, 0, b"x" * 8), ts=7)
        (evicted,) = events
        assert evicted.flow.identification == 0  # type: ignore[union-attr]

    @pytest.mark.parametrize("over", [0, 1])
    def test_max_total_bytes(self, over: int) -> None:
        one = charge(8, 1)
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(max_total_bytes=3 * one - over)
        )
        events = []
        for identification in range(3):
            events += feed(
                reassembler,
                v4(identification, 0, b"x" * 8),
                ts=identification + 1,
            )
        if over:
            (evicted,) = events
            assert isinstance(evicted, Evicted)
            assert evicted.bound is Bound.MAX_TOTAL_BYTES
            assert evicted.completing_ref is None
            assert evicted.flow.identification == 0  # type: ignore[union-attr]
            assert reassembler.usage == Usage(2, 2 * one)
        else:
            assert events == []
            assert reassembler.usage == Usage(3, 3 * one)

    def test_the_oldest_goes_even_when_it_is_the_growing_one(self) -> None:
        """Decision 3: the datagram whose first fragment came first is
        evicted, the arriving fragment's own included, with its ref."""
        one = charge(8, 1)
        bounds = FragmentBounds(max_total_bytes=2 * one + 8 + PIECE_OVERHEAD)
        reassembler = FragmentReassembler(bounds=bounds)
        feed(reassembler, v4(1, 0, b"x" * 8), ts=1, ref=0)
        feed(reassembler, v4(2, 0, b"y" * 8), ts=2, ref=1)
        (evicted,) = feed(reassembler, v4(1, 16, b"z" * 16), ts=3, ref=2)
        assert isinstance(evicted, Evicted)
        assert evicted.bound is Bound.MAX_TOTAL_BYTES
        assert evicted.flow.identification == 1  # type: ignore[union-attr]
        assert evicted.completing_ref == 2
        assert evicted.refs == (0, 2)
        assert reassembler.usage == Usage(1, one)

    def test_a_growing_datagram_evicts_an_older_one(self) -> None:
        one = charge(8, 1)
        bounds = FragmentBounds(max_total_bytes=2 * one + 8 + PIECE_OVERHEAD)
        reassembler = FragmentReassembler(bounds=bounds)
        feed(reassembler, v4(1, 0, b"x" * 8), ts=1)
        feed(reassembler, v4(2, 0, b"y" * 8), ts=2)
        (evicted,) = feed(reassembler, v4(2, 16, b"z" * 16), ts=3)
        assert isinstance(evicted, Evicted)
        assert evicted.flow.identification == 1  # type: ignore[union-attr]
        assert evicted.completing_ref is None
        assert reassembler.usage.flows == 1

    def test_a_new_datagram_older_than_every_held_one_is_evicted(self) -> None:
        reassembler = FragmentReassembler(bounds=FragmentBounds(max_flows=2))
        feed(reassembler, v4(1, 0, b"x" * 8), ts=10)
        feed(reassembler, v4(2, 0, b"x" * 8), ts=11)
        (evicted,) = feed(reassembler, v4(3, 0, b"x" * 8), ts=5, ref=7)
        assert isinstance(evicted, Evicted)
        assert evicted.bound is Bound.MAX_FLOWS
        assert evicted.flow.identification == 3  # type: ignore[union-attr]
        assert evicted.completing_ref == 7
        assert reassembler.usage.flows == 2

    def test_a_fragment_over_max_total_bytes_alone_flushes_nothing_else(
        self,
    ) -> None:
        """A datagram that cannot fit under the byte cap on its own is
        evicted at once, and the others stay."""
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(max_total_bytes=5000)
        )
        feed(reassembler, v4(1, 0, b"x" * 8), ts=1)
        feed(reassembler, v4(2, 0, b"x" * 8), ts=2)
        (evicted,) = feed(reassembler, v4(3, 0, b"x" * 4000), ts=3, ref=2)
        assert isinstance(evicted, Evicted)
        assert evicted.bound is Bound.MAX_TOTAL_BYTES
        assert evicted.flow.identification == 3  # type: ignore[union-attr]
        assert evicted.completing_ref == 2
        assert reassembler.usage.flows == 2

    def test_a_datagram_alone_over_max_total_bytes_is_evicted(self) -> None:
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(max_total_bytes=charge(8, 1))
        )
        feed(reassembler, v4(1, 0, b"x" * 8), ref=0)
        (evicted,) = feed(reassembler, v4(1, 16, b"y" * 8), ref=1)
        assert isinstance(evicted, Evicted)
        assert evicted.bound is Bound.MAX_TOTAL_BYTES
        assert evicted.completing_ref == 1
        assert reassembler.usage == Usage(0, 0)

    @pytest.mark.parametrize("through", ["feed", "advance"])
    @pytest.mark.parametrize("timeout", [Timeout.AGE, Timeout.IDLE])
    def test_timeout_deadline(self, through: str, timeout: Timeout) -> None:
        bounds = (
            FragmentBounds(age_timeout=100)
            if timeout is Timeout.AGE
            else FragmentBounds(age_timeout=None, idle_timeout=100)
        )
        reassembler = FragmentReassembler(bounds=bounds)
        feed(reassembler, v4(1, 0, b"a" * 8), ts=1000)
        feed(reassembler, v4(1, 16, b"b" * 8), ts=1050)
        deadline = 1100 if timeout is Timeout.AGE else 1150

        def step(ts: int) -> tuple[FragmentEvent, ...]:
            if through == "advance":
                return reassembler.advance(ts)
            return feed(
                reassembler, v4(9, 0, b"c" * 8, src="198.51.100.7"), ts=ts
            )

        assert only(step(deadline - 1), Expired) == []
        (expired,) = only(step(deadline), Expired)
        assert expired.timeout is timeout
        assert expired.flow.identification == 1  # type: ignore[union-attr]

    def test_an_earlier_timestamp_does_not_move_the_clock(self) -> None:
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(age_timeout=None, idle_timeout=100)
        )
        feed(reassembler, v4(1, 0, b"a" * 8), ts=1000)
        assert reassembler.advance(1099) == ()
        feed(reassembler, v4(1, 16, b"b" * 8), ts=500)
        (expired,) = reassembler.advance(1100)
        assert isinstance(expired, Expired)
        assert expired.spans[1].timestamp == 500
        assert (expired.first_timestamp, expired.last_timestamp) == (500, 1000)

    def test_a_late_frame_does_not_revive_an_expired_datagram(self) -> None:
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(age_timeout=100)
        )
        feed(reassembler, v4(1, 0, b"a" * 8), ts=1000)
        assert len(reassembler.advance(1100)) == 1
        events = feed(reassembler, v4(1, 8, b"b" * 8, more=False), ts=1001)
        assert events == ()
        assert reassembler.usage.flows == 1
        (expired,) = reassembler.advance(1101)
        assert expired.refs == (1,)

    def test_timestamp_zero_never_moves_the_clock(self) -> None:
        reassembler = FragmentReassembler(bounds=FragmentBounds(age_timeout=1))
        for identification in range(5):
            assert (
                feed(reassembler, v4(identification, 0, b"a" * 8), ts=0) == ()
            )
        assert reassembler.advance(0) == ()
        assert reassembler.usage.flows == 5

    def test_per_target_timeouts(self) -> None:
        reassembler = FragmentReassembler(
            targets={
                "192.0.2.0/24": FragmentTarget(
                    age_timeout=30 * SECOND, idle_timeout=10 * SECOND
                )
            }
        )
        feed(reassembler, v4(1, 0, b"a" * 8), ts=SECOND)
        feed(reassembler, v4(2, 0, b"b" * 8, dst="198.51.100.1"), ts=SECOND)
        (expired,) = reassembler.advance(11 * SECOND)
        assert expired.timeout is Timeout.IDLE  # type: ignore[union-attr]
        assert expired.flow.dst == DST4
        (expired,) = reassembler.advance(61 * SECOND)
        assert expired.flow.dst == "198.51.100.1"

    def test_no_timeout_turns_a_global_timeout_off_for_a_target(self) -> None:
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(idle_timeout=10, age_timeout=100),
            targets={
                DST4: FragmentTarget(idle_timeout=NO_TIMEOUT),
                "198.51.100.1": FragmentTarget(
                    age_timeout=NO_TIMEOUT, idle_timeout=NO_TIMEOUT
                ),
            },
        )
        feed(reassembler, v4(1, 0, b"a" * 8), ts=1000)
        feed(reassembler, v4(2, 0, b"a" * 8, dst="198.51.100.1"), ts=1000)
        assert reassembler.advance(1099) == ()
        (expired,) = reassembler.advance(1100)
        assert expired.timeout is Timeout.AGE  # type: ignore[union-attr]
        assert expired.flow.dst == DST4
        assert reassembler.advance(10**15) == ()
        assert reassembler.usage.flows == 1

    def test_a_frame_that_is_no_fragment_still_expires(self) -> None:
        """Every feed moves the clock: a frame the reassembler does not
        apply to returns the expiries it causes and nothing else."""
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(age_timeout=100)
        )
        feed(reassembler, v4(1, 0, b"a" * 8), ts=1000, ref=0)
        whole = v4(2, 0, udp_datagram(8), more=False)
        assert feed(reassembler, whole, ts=1099, ref=1) == ()
        (expired,) = feed(reassembler, whole, ts=1100, ref=2)
        assert isinstance(expired, Expired)
        assert expired.completing_ref is None
        assert expired.refs == (0,)
        arp = b"\xff" * 6 + b"\x02" * 6 + b"\x08\x06" + b"\x00" * 28
        feed(reassembler, v4(3, 0, b"a" * 8), ts=1200)
        (expired,) = reassembler.feed(
            decode_frame(arp, lax=True), arp, timestamp=1300
        )
        assert isinstance(expired, Expired)
        assert reassembler.usage == Usage(0, 0)

    def test_expiry_in_deadline_order(self) -> None:
        reassembler = FragmentReassembler(bounds=FragmentBounds(age_timeout=10))
        feed(reassembler, v4(1, 0, b"a" * 8), ts=5)
        feed(reassembler, v4(2, 0, b"a" * 8), ts=3)
        feed(reassembler, v4(3, 0, b"a" * 8), ts=3)
        events = reassembler.advance(100)
        assert [event.flow.identification for event in events] == [2, 3, 1]  # type: ignore[union-attr]

    def test_idle_deadline_moves_with_activity(self) -> None:
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(age_timeout=None, idle_timeout=10)
        )
        for index in range(50):
            feed(reassembler, v4(1, 16 * index, b"a" * 8), ts=100 + 5 * index)
        assert reassembler.advance(100 + 5 * 49 + 9) == ()
        assert len(reassembler.advance(100 + 5 * 49 + 10)) == 1

    def test_stale_heap_entries_are_dropped(self) -> None:
        """Evicted and expired datagrams leave entries behind in the
        deadline and age orders, which are rebuilt once most are stale."""
        reassembler = FragmentReassembler(
            bounds=FragmentBounds(max_flows=2, idle_timeout=10**12)
        )
        feed(reassembler, v4(65_535, 0, b"x" * 8), ts=1)
        for index in range(500):
            frame = v4(index, 0, b"x" * 8)
            feed(reassembler, frame, ts=index + 1, ref=index)
            feed(reassembler, v4(index, 8, b"y" * 8, more=False), ts=index + 1)
        for index in range(500):
            feed(reassembler, v4(index, 0, b"x" * 8), ts=600 + index)
        assert reassembler.usage.flows == 2
        heaps = (reassembler._deadlines, reassembler._ages)
        assert all(len(heap) <= 2 * 2 + 64 + 1 for heap in heaps)

    def test_same_capture_twice_gives_equal_events(self) -> None:
        def replay() -> list[FragmentEvent]:
            reassembler = FragmentReassembler(policy=OverlapPolicy.BSD)
            events, closed = run_capture(
                REASSEMBLY / "linux_overlaps.pcap", reassembler
            )
            return events + closed

        assert replay() == replay()

    def test_repr_is_the_same_under_two_hash_seeds(self) -> None:
        script = (
            "import sys\n"
            "sys.path.insert(0, 'tests')\n"
            "from test_reassembly import run_capture, REASSEMBLY, FIXTURES\n"
            "from netprotocols.reassembly import (\n"
            "    FragmentBounds, FragmentReassembler)\n"
            "out = []\n"
            "for name in (REASSEMBLY / 'linux_overlaps.pcap',\n"
            "             FIXTURES / 'ipv6_fragments.pcap'):\n"
            "    bounds = FragmentBounds(max_flows=1)\n"
            "    events, closed = run_capture(\n"
            "        name, FragmentReassembler(bounds=bounds))\n"
            "    out += events + closed\n"
            "print(repr(out))\n"
        )
        outputs = {
            subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                check=True,
                cwd=ROOT,
                env={"PYTHONHASHSEED": seed, "PATH": ""},
            ).stdout
            for seed in ("1", "2")
        }
        (output,) = outputs
        assert "Evicted" in output and "Datagram" in output


# --- 7.5: properties -------------------------------------------------


@st.composite
def fragmented(draw: st.DrawFn) -> tuple[int, bytes, list[tuple[int, int]]]:
    """A payload of up to 65,000 bytes, its cuts on 8-byte boundaries,
    exact duplicates added and the order shuffled."""
    version = draw(st.sampled_from([4, 6]))
    size = draw(st.integers(9, 65_000))
    message = random.Random(draw(st.integers(0, 2**32))).randbytes(size)
    cuts = sorted(
        draw(st.sets(st.integers(1, (size - 1) // 8), min_size=1, max_size=63))
    )
    bounds = [0, *(cut * 8 for cut in cuts), size]
    pieces = list(itertools.pairwise(bounds))
    duplicates = draw(st.lists(st.sampled_from(pieces), max_size=8))
    order = draw(st.permutations(pieces + duplicates))
    return version, message, order


class TestProperties:
    @given(
        st.sampled_from([4, 6]),
        st.integers(0, 40),
        st.integers(65_300, 65_535),
        st.integers(2, 6),
        st.booleans(),
        st.randoms(use_true_random=False),
    )
    def test_large_first_header_small_later_ones_never_raise(
        self,
        version: int,
        extra_words: int,
        total: int,
        pieces: int,
        first_last: bool,
        rng: random.Random,
    ) -> None:
        """A first fragment with the largest header and later ones with
        the smallest, the datagram near 65,535 bytes, in any order: no
        exception, and a Datagram only when it fits, else OVERSIZE."""
        if version == 4:
            extra = 20 + extra_words * 1
            extra -= extra % 4
            options = b"\x01" * (extra - 20)
            size = max(16, total - extra)
            size -= size % 8
            cuts = (
                sorted(rng.sample(range(1, size // 8), pieces - 1))
                if pieces > 1
                else []
            )
            bounds = [0, *(cut * 8 for cut in cuts), size]
            frames = [
                v4(
                    9,
                    a,
                    bytes(b - a),
                    more=b != size,
                    options=options if a == 0 else b"",
                )
                for a, b in itertools.pairwise(bounds)
            ]
        else:
            extra = 8 * (extra_words + 1)
            hop_by_hop = bytes([44, extra // 8 - 1]) + bytes(extra - 2)
            size = max(16, total - extra + rng.randrange(0, 64))
            size -= size % 8
            cuts = (
                sorted(rng.sample(range(1, size // 8), pieces - 1))
                if pieces > 1
                else []
            )
            bounds = [0, *(cut * 8 for cut in cuts), size]
            frames = [
                v6(
                    9,
                    a,
                    bytes(b - a),
                    more=b != size,
                    extensions=hop_by_hop if a == 0 else b"",
                    first=0 if a == 0 else 44,
                )
                for a, b in itertools.pairwise(bounds)
            ]
        if first_last:
            frames = frames[1:] + frames[:1]
        else:
            rng.shuffle(frames)
        reassembler = FragmentReassembler()
        events = feed_all(reassembler, frames)
        datagrams = only(events, Datagram)
        fits = extra + size <= 65_535
        if fits:
            (datagram,) = datagrams
            length = len(datagram.data) - (40 if version == 6 else 0)
            assert length == extra + size
        else:
            assert not datagrams
            assert AnomalyKind.OVERSIZE in kinds(events)
        reassembler.close()

    @given(fragmented())
    def test_any_cut_reassembles_to_the_payload(
        self, case: tuple[int, bytes, list[tuple[int, int]]]
    ) -> None:
        version, message, order = case
        cut = cut4 if version == 4 else cut6
        frames = cut(message, order)
        complete = max(order.index(piece) for piece in set(order))
        reassembler = FragmentReassembler()
        events = feed_all(reassembler, frames[: complete + 1])
        datagrams = only(events, Datagram)
        assert len(datagrams) == 1
        assert events[-1] is datagrams[0]
        assert datagrams[0].completing_ref == complete
        assert payload(datagrams[0]) == message
        assert tiles(datagrams[0].spans, len(message))
        assert all(
            isinstance(event, (Datagram, Retransmission)) for event in events
        )
        assert reassembler.usage == Usage(0, 0)

    @given(
        st.lists(
            st.tuples(
                st.integers(0, 15),
                st.integers(1, 4),
                st.binary(min_size=1, max_size=1),
            ),
            min_size=1,
            max_size=24,
        ),
        st.sampled_from([OverlapPolicy.FIRST, OverlapPolicy.LAST]),
    )
    def test_first_and_last_match_a_byte_model(
        self,
        fragments: list[tuple[int, int, bytes]],
        policy: OverlapPolicy,
    ) -> None:
        """Differing duplicates: under first each byte keeps its earliest
        version, under last its latest, and every arrival whose bytes
        differ from held ones yields an Overlap."""
        reassembler = FragmentReassembler(policy=policy)
        feed(reassembler, v4(1, 160, b"\x00" * 8, more=False), ref=0)
        model: dict[int, int] = {}
        overlaps = 0
        for index, (block, blocks, fill) in enumerate(fragments, start=1):
            start = block * 8
            data = fill * (8 * blocks)
            differ = any(
                model.get(position, data[0]) != data[0]
                for position in range(start, start + len(data))
            )
            for position in range(start, start + len(data)):
                if position not in model or policy is OverlapPolicy.LAST:
                    model[position] = data[0]
            events = feed(reassembler, v4(1, start, data), ts=index, ref=index)
            assert len(only(events, Overlap)) == int(differ)
            overlaps += differ
            assert not only(events, Datagram)
        holes = [block for block in range(20) if block * 8 not in model]
        events = []
        for block in holes:
            events += feed(reassembler, v4(1, block * 8, b"\xaa" * 8), ts=99)
            for position in range(block * 8, block * 8 + 8):
                model[position] = 0xAA
        (datagram,) = only(events, Datagram)
        assert payload(datagram)[:160] == bytes(model[p] for p in range(160))
        assert not only(events, Overlap)
        assert reassembler.usage == Usage(0, 0)

    @given(
        st.integers(1, 8),
        st.integers(1, 6000),
        st.integers(1, 6),
        st.integers(500, 4000),
        st.lists(
            st.tuples(
                st.integers(0, 6),
                st.integers(0, 40),
                st.integers(1, 6),
                st.booleans(),
            ),
            max_size=60,
        ),
    )
    def test_usage_never_exceeds_the_bounds(
        self,
        max_flows: int,
        max_total_bytes: int,
        max_fragments: int,
        max_flow_bytes: int,
        fragments: list[tuple[int, int, int, bool]],
    ) -> None:
        bounds = FragmentBounds(
            max_flows=max_flows,
            max_total_bytes=max_total_bytes,
            max_fragments=max_fragments,
            max_flow_bytes=max_flow_bytes,
        )
        reassembler = FragmentReassembler(bounds=bounds)
        for index, (identification, block, blocks, more) in enumerate(
            fragments
        ):
            frame = v4(
                identification,
                block * 8,
                bytes([index]) * (8 * blocks),
                more=more,
            )
            feed(reassembler, frame, ts=index + 1, ref=index)
            usage = reassembler.usage
            assert usage.flows <= max_flows
            assert usage.bytes <= max_total_bytes
        reassembler.close()
        assert reassembler.usage == Usage(0, 0)
