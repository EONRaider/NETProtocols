"""Memory bounds of netprotocols.reassembly's FragmentReassembler.

Every frame here is **crafted**: single-fragment IPv4 and IPv6
datagrams built byte by byte, each under its own key, so that a flood
of them exercises the caps. The tests hold the reassembler's charged
bytes (:data:`~netprotocols.reassembly.FLOW_OVERHEAD`,
:data:`~netprotocols.reassembly.PIECE_OVERHEAD`) to what CPython
actually allocates, measured with ``allocation_peak``.
"""

from __future__ import annotations

import gc
import ipaddress
import struct
import tracemalloc

import pytest

from conftest import allocation_peak
from netprotocols import IPv4, IPv6, decode_frame
from netprotocols.checksum import internet_checksum
from netprotocols.reassembly import (
    FLOW_OVERHEAD,
    PIECE_OVERHEAD,
    Bound,
    Evicted,
    FragmentBounds,
    FragmentReassembler,
    OverlapPolicy,
)

MIB = 1024 * 1024


def ipv4_fragment(index: int, offset: int = 0) -> bytes:
    """A crafted IPv4 first fragment of 8 bytes, keyed by ``index``."""
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28,
        index & 0xFFFF,
        0x2000 | offset // 8,
        64,
        17,
        0,
        struct.pack("!I", 0x0A000000 + (index >> 16)),
        bytes([10, 9, 79, 1]),
    )
    checksum = struct.pack("!H", internet_checksum(header))
    return header[:10] + checksum + header[12:] + bytes(8)


def ipv6_fragment(index: int, offset: int = 0) -> bytes:
    """A crafted IPv6 first fragment of 8 bytes, keyed by ``index``."""
    source = ipaddress.IPv6Address("2001:db8:aaaa:bbbb:cccc:dddd::") + (
        index >> 16
    )
    return (
        struct.pack(
            "!IHBB16s16s",
            6 << 28,
            16,
            44,
            64,
            source.packed,
            ipaddress.IPv6Address("2001:db8::1").packed,
        )
        + struct.pack("!BBHI", 17, 0, offset | 1, index)
        + bytes(8)
    )


def test_fragment_flood_stays_within_the_caps() -> None:
    """200,000 single-fragment datagrams, each under its own key, into
    a reassembler capped at 1,024 datagrams and 1 MiB: the byte cap
    binds, every datagram past it evicts the oldest one, and the peak
    allocation, the reassembler's state and one feed's transients,
    stays under 1.5 MiB."""
    bounds = FragmentBounds(max_flows=1_024, max_total_bytes=MIB)
    reassembler = FragmentReassembler(bounds=bounds)
    per_datagram = FLOW_OVERHEAD + PIECE_OVERHEAD + 8 + 20
    held = MIB // per_datagram
    evicted = 0
    gc.collect()
    with allocation_peak() as peak:
        for index in range(200_000):
            frame = ipv4_fragment(index)
            packet = decode_frame(frame, start=IPv4)
            for event in reassembler.feed(
                packet, frame, timestamp=index + 1, ref=index
            ):
                assert isinstance(event, Evicted)
                assert event.bound is Bound.MAX_TOTAL_BYTES
                assert event.completing_ref is None
                evicted += 1
            usage = reassembler.usage
            assert usage.flows <= bounds.max_flows
            assert usage.bytes <= bounds.max_total_bytes
    assert reassembler.usage.flows == held
    assert evicted == 200_000 - held
    assert peak.peak <= 1.5 * MIB


@pytest.mark.parametrize("build", [ipv4_fragment, ipv6_fragment])
@pytest.mark.parametrize(
    "policy", [OverlapPolicy.FIRST, OverlapPolicy.LINUX_DISCARD]
)
def test_overheads_cover_what_is_allocated(build, policy) -> None:  # type: ignore[no-untyped-def]
    """n datagrams, then n pieces of one datagram: the traced growth
    divided by n never exceeds what the reassembler charges for one,
    so the accounting never undercounts."""
    count = 3_000
    bounds = FragmentBounds(
        max_flows=10**7, max_total_bytes=10**12, max_fragments=10**6
    )
    start = IPv4 if build is ipv4_fragment else IPv6
    header = 20 if build is ipv4_fragment else 41
    datagrams = FragmentReassembler(bounds=bounds, policy=policy)
    pieces = FragmentReassembler(bounds=bounds, policy=policy)
    first = build(7)
    pieces.feed(decode_frame(first, start=start), first, timestamp=1)
    gc.collect()
    with allocation_peak():
        before, _ = tracemalloc.get_traced_memory()
        for index in range(count):
            frame = build(index)
            datagrams.feed(
                decode_frame(frame, start=start), frame, timestamp=index + 1
            )
        gc.collect()
        middle, _ = tracemalloc.get_traced_memory()
        for index in range(count):
            frame = build(7, offset=16 * (index + 1))
            pieces.feed(
                decode_frame(frame, start=start), frame, timestamp=index + 2
            )
        gc.collect()
        after, _ = tracemalloc.get_traced_memory()
    per_datagram = (middle - before) / count
    per_piece = (after - middle) / count
    assert per_piece <= PIECE_OVERHEAD + 8
    assert per_datagram - (PIECE_OVERHEAD + 8 + header) <= FLOW_OVERHEAD
    assert datagrams.usage.bytes == count * (
        FLOW_OVERHEAD + PIECE_OVERHEAD + 8 + header
    )
