"""Memory bounds of netprotocols.reassembly's StreamReassembler.

Every frame here is **crafted**: IPv4 and IPv6 TCP segments built byte
by byte, so that a flood of them exercises the caps. The tests hold the
reassembler's charged bytes (:data:`~netprotocols.reassembly.FLOW_OVERHEAD`
per connection, :data:`~netprotocols.reassembly.PIECE_OVERHEAD` per
direction and per held chunk, and the per-frame charge of a retained
run) to what CPython actually allocates, measured with
``allocation_peak``. Timestamps are nanoseconds since the epoch, as a
capture's are, so each is a full-size ``int``.
"""

from __future__ import annotations

import gc
import ipaddress
import struct
import tracemalloc
from collections.abc import Callable

import pytest

from conftest import allocation_peak
from netprotocols import IPv4, IPv6, decode_frame
from netprotocols.checksum import internet_checksum
from netprotocols.reassembly import (
    _SPAN_OVERHEAD,
    FLOW_OVERHEAD,
    PIECE_OVERHEAD,
    Bound,
    Evicted,
    StreamBounds,
    StreamEnd,
    StreamReassembler,
)

MIB = 1024 * 1024

#: A capture timestamp: 2026-11-11 in nanoseconds.
EPOCH = 1_794_355_200 * 1_000_000_000

SYN, ACK, FIN = 0x02, 0x10, 0x01


def ipv4_segment(
    src: int,
    dst: int,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    data: bytes = b"",
) -> bytes:
    """A crafted IPv4 TCP segment between 10.x addresses."""
    source = struct.pack("!I", 0x0A000000 + src)
    destination = struct.pack("!I", 0x0A000000 + dst)
    tcp = struct.pack(
        "!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 65535, 0, 0
    )
    pseudo = source + destination + struct.pack("!xBH", 6, 20 + len(data))
    checksum = internet_checksum(pseudo + tcp + data)
    tcp = tcp[:16] + struct.pack("!H", checksum) + tcp[18:]
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40 + len(data),
        1,
        0x4000,
        64,
        6,
        0,
        source,
        destination,
    )
    header = (
        header[:10] + struct.pack("!H", internet_checksum(header)) + header[12:]
    )
    return header + tcp + data


def ipv6_segment(
    src: int,
    dst: int,
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    data: bytes = b"",
) -> bytes:
    """A crafted IPv6 TCP segment between long 2001:db8 addresses."""
    base = ipaddress.IPv6Address("2001:db8:aaaa:bbbb:cccc:dddd:eeee:0")
    source = (base + src).packed
    destination = (base + dst).packed
    tcp = struct.pack(
        "!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 65535, 0, 0
    )
    pseudo = source + destination + struct.pack("!I3xB", 20 + len(data), 6)
    checksum = internet_checksum(pseudo + tcp + data)
    tcp = tcp[:16] + struct.pack("!H", checksum) + tcp[18:]
    header = struct.pack(
        "!IHBB16s16s", 6 << 28, 20 + len(data), 6, 64, source, destination
    )
    return header + tcp + data


Build = Callable[[int, int, int, int, int, int, int, bytes], bytes]


def feed(
    reassembler: StreamReassembler, build: Build, *fields: object, at: int
) -> tuple[object, ...]:
    frame = build(*fields)  # type: ignore[arg-type]
    start = IPv4 if build is ipv4_segment else IPv6
    return reassembler.feed(
        decode_frame(frame, start=start), frame, timestamp=EPOCH + at
    )


def test_syn_flood_stays_within_the_caps() -> None:
    """200,000 SYNs from distinct source ports into a reassembler capped
    at 1,024 connections and 1 MiB: the byte cap binds first, every SYN
    past it evicts the oldest half-open connection, and the peak
    allocation, the reassembler's state and one feed's transients, stays
    under 1.5 MiB."""
    bounds = StreamBounds(max_flows=1_024, max_total_bytes=MIB)
    reassembler = StreamReassembler(bounds=bounds)
    held = MIB // (FLOW_OVERHEAD + PIECE_OVERHEAD)
    evicted = 0
    gc.collect()
    with allocation_peak() as peak:
        for index in range(200_000):
            frame = ipv4_segment(
                index >> 16, 0xFFFF, 1024 + index % 60_000, 80, index, 0, SYN
            )
            packet = decode_frame(frame, start=IPv4, lax=True)
            for event in reassembler.feed(
                packet, frame, timestamp=EPOCH + index, ref=index
            ):
                assert event.completing_ref is None
                if isinstance(event, Evicted):
                    assert event.bound is Bound.MAX_TOTAL_BYTES
                    evicted += 1
                else:
                    assert isinstance(event, StreamEnd)
            usage = reassembler.usage
            assert usage.flows <= bounds.max_flows
            assert usage.bytes <= bounds.max_total_bytes
    assert reassembler.usage.flows == held
    assert evicted == 200_000 - held
    assert peak.peak <= 1.5 * MIB


def connection(
    reassembler: StreamReassembler, build: Build, index: int, both: bool
) -> None:
    """One connection under its own key: a SYN or, with ``both``, a
    handshake whose SYNs carry window state, and a FIN each way."""
    client, server = index + 1, 0xFFFF
    feed(reassembler, build, client, server, 1000, 80, 7, 0, SYN, b"", at=index)
    if not both:
        return
    steps = [
        (server, client, 80, 1000, 70, 8, SYN | ACK),
        (client, server, 1000, 80, 8, 71, ACK | FIN),
        (server, client, 80, 1000, 71, 9, ACK | FIN),
    ]
    for src, dst, sport, dport, seq, ack, flags in steps:
        feed(
            reassembler,
            build,
            src,
            dst,
            sport,
            dport,
            seq,
            ack,
            flags,
            b"",
            at=index,
        )


@pytest.mark.parametrize("build", [ipv4_segment, ipv6_segment])
@pytest.mark.parametrize("both", [False, True])
def test_connections_cost_no_more_than_they_are_charged(
    build: Build, both: bool
) -> None:
    """n connections: the traced growth divided by n never exceeds what
    the reassembler charges for one, FLOW_OVERHEAD and PIECE_OVERHEAD per
    direction."""
    count = 3_000
    bounds = StreamBounds(max_flows=10**7, max_total_bytes=10**12)
    reassembler = StreamReassembler(bounds=bounds)
    connection(reassembler, build, -1, both)
    charge = FLOW_OVERHEAD + PIECE_OVERHEAD * (2 if both else 1)
    gc.collect()
    with allocation_peak():
        before, _ = tracemalloc.get_traced_memory()
        for index in range(count):
            connection(reassembler, build, index, both)
        gc.collect()
        after, _ = tracemalloc.get_traced_memory()
    assert (after - before) / count <= charge
    assert reassembler.usage.bytes == (count + 1) * charge


@pytest.mark.parametrize("build", [ipv4_segment, ipv6_segment])
def test_held_chunks_and_retained_frames_cost_no_more(build: Build) -> None:
    """n one-byte segments held past a hole, then n delivered and
    retained: each costs no more than PIECE_OVERHEAD plus its byte, and
    the per-frame charge of a retained run plus its byte, and the traced
    growth never exceeds the growth of what is charged."""
    count = 3_000
    bounds = StreamBounds(
        max_flows=10,
        max_total_bytes=10**12,
        max_flow_bytes=10**12,
        retain_bytes=10**9,
    )
    held = StreamReassembler(bounds=bounds)
    kept = StreamReassembler(bounds=bounds)
    for reassembler in (held, kept):
        feed(reassembler, build, 1, 2, 1000, 80, 7, 0, SYN, b"", at=0)
        feed(reassembler, build, 1, 2, 1000, 80, 8, 0, ACK, b"x", at=0)
    charged = (held.usage.bytes, kept.usage.bytes)
    gc.collect()
    with allocation_peak():
        before, _ = tracemalloc.get_traced_memory()
        for index in range(count):
            feed(
                held,
                build,
                1,
                2,
                1000,
                80,
                10 + 2 * index,
                0,
                ACK,
                b"y",
                at=index,
            )
        gc.collect()
        middle, _ = tracemalloc.get_traced_memory()
        for index in range(count):
            feed(kept, build, 1, 2, 1000, 80, 9 + index, 0, ACK, b"z", at=index)
        gc.collect()
        after, _ = tracemalloc.get_traced_memory()
    assert (middle - before) / count <= PIECE_OVERHEAD + 1
    assert (after - middle) / count <= _SPAN_OVERHEAD + 1
    assert middle - before <= held.usage.bytes - charged[0]
    assert after - middle <= kept.usage.bytes - charged[1]
