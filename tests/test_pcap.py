"""Tests for netprotocols.pcap: classic pcap and pcapng capture reading.

Classic-pcap coverage reuses the real fixture corpus (tests/fixtures/),
matching this repository's real-capture-only ethos for that directory.
pcapng coverage cannot: the corpus holds no pcapng captures, and the
exotic ``if_tsresol`` cases in particular (nanosecond and non-default
resolutions) essentially never occur in real traffic, which is
overwhelmingly the tcpdump/Wireshark default (microseconds, or classic
pcap). This file therefore hand-builds pcapng byte sequences instead —
a deliberate, flagged exception to tests/fixtures/MANIFEST.md's
real-capture rule, kept as small Python builders rather than binary
fixture files so every byte is reviewable in the diff.
"""

from __future__ import annotations

import struct

import pytest

from conftest import FIXTURES
from netprotocols import (
    CapturedFrame,
    MalformedCaptureError,
    read_captures,
    read_pcap,
    read_pcapng,
)


def _reference_read_pcap(data: bytes) -> list[bytes]:
    """Minimal classic-pcap reader, independent of
    :mod:`netprotocols.pcap` (the module under test) — mirrors the
    same "standalone, so a shared bug can't cancel itself out"
    philosophy as scripts/benchmark.py and scripts/check_fixtures.py.
    This is what tests/conftest.py's own private reader used to be
    before #100; it lives here now, scoped to this one cross-check,
    rather than as a general-purpose test helper other files reach
    for (that's netprotocols.pcap.read_pcap's job now)."""
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        raise ValueError("not a pcap")
    frames = []
    cursor = 24
    while cursor + 16 <= len(data):
        (incl_len,) = struct.unpack_from(f"{endian}I", data, cursor + 8)
        cursor += 16
        frames.append(data[cursor : cursor + incl_len])
        cursor += incl_len
    return frames


# -- pcapng builders (little- and big-endian) --
#
# Deliberately independent of netprotocols.pcap's own implementation:
# these pack blocks by hand from the wire format
# (draft-ietf-opsawg-pcapng-03), so a bug shared between builder and
# reader can't cancel itself out the way reusing the library under
# test to build its own fixtures would risk.

_SHB_MAGIC_LE = b"\x4d\x3c\x2b\x1a"
_SHB_MAGIC_BE = b"\x1a\x2b\x3c\x4d"


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def _block(fmt: str, block_type: bytes, body: bytes) -> bytes:
    total_len = 8 + len(body) + 4
    return (
        block_type
        + struct.pack(f"{fmt}I", total_len)
        + body
        + struct.pack(f"{fmt}I", total_len)
    )


def shb(fmt: str = "<") -> bytes:
    magic = _SHB_MAGIC_LE if fmt == "<" else _SHB_MAGIC_BE
    body = magic + struct.pack(f"{fmt}HH", 1, 0) + struct.pack(f"{fmt}q", -1)
    return _block(fmt, b"\x0a\x0d\x0d\x0a", body)


def idb(fmt: str = "<", tsresol: int | None = None, linktype: int = 1) -> bytes:
    opts = b""
    if tsresol is not None:
        opts += (
            struct.pack(f"{fmt}HH", 9, 1) + bytes([tsresol]) + b"\x00\x00\x00"
        )
    opts += struct.pack(f"{fmt}HH", 0, 0)  # opt_endofopt
    body = struct.pack(f"{fmt}HHI", linktype, 0, 65535) + opts
    return _block(fmt, struct.pack(f"{fmt}I", 1), body)


def epb(interface_id: int, ts: int, data: bytes, fmt: str = "<") -> bytes:
    body = struct.pack(
        f"{fmt}IIIII",
        interface_id,
        ts >> 32,
        ts & 0xFFFFFFFF,
        len(data),
        len(data),
    ) + _pad4(data)
    return _block(fmt, struct.pack(f"{fmt}I", 6), body)


def spb(original_len: int, data: bytes, fmt: str = "<") -> bytes:
    body = struct.pack(f"{fmt}I", original_len) + _pad4(data)
    return _block(fmt, struct.pack(f"{fmt}I", 3), body)


def unknown_block(fmt: str = "<") -> bytes:
    """An Interface Statistics Block (type 5) — a real pcapng block
    type this library does not read, used to prove it is skipped
    wholesale rather than misread as something else."""
    body = struct.pack(f"{fmt}I", 0) + struct.pack(f"{fmt}IL", 0, 0)
    return _block(fmt, struct.pack(f"{fmt}I", 5), body)


class TestReadPcapAgainstTheRealCorpus:
    """Cross-checked against this file's own independent classic-pcap
    reader (see :func:`_reference_read_pcap`) — real corpus frames,
    both readers, must agree byte-for-byte."""

    @pytest.mark.parametrize(
        "path", sorted(FIXTURES.glob("*.pcap")), ids=lambda p: p.name
    )
    def test_matches_the_reference_reader(self, path):
        reference = _reference_read_pcap(path.read_bytes())
        frames = list(read_pcap(path.read_bytes()))
        assert len(frames) == len(reference)
        assert [frame.data for frame in frames] == reference

    def test_timestamps_are_nanoseconds_since_the_epoch_and_increase(self):
        path = sorted(FIXTURES.glob("*.pcap"))[0]
        frames = list(read_pcap(path.read_bytes()))
        assert all(isinstance(frame.timestamp, int) for frame in frames)
        # Real capture, taken in one sitting: not strictly monotonic
        # across pcap's own two-field (sec, frac) granularity in
        # principle, but every frame's timestamp is a real 2020s+ Unix
        # nanosecond value, not a raw microsecond/word miscount.
        assert all(
            frame.timestamp > 1_700_000_000_000_000_000 for frame in frames
        )

    def test_read_captures_auto_detects_classic_pcap(self):
        path = sorted(FIXTURES.glob("*.pcap"))[0]
        data = path.read_bytes()
        assert list(read_captures(data)) == list(read_pcap(data))

    def test_accepts_a_memoryview(self):
        path = sorted(FIXTURES.glob("*.pcap"))[0]
        data = path.read_bytes()
        assert list(read_pcap(memoryview(data))) == list(read_pcap(data))


class TestReadPcapMalformedInput:
    def test_too_short_for_a_magic_number_raises(self):
        with pytest.raises(MalformedCaptureError):
            list(read_pcap(b"\x00\x00"))

    def test_unrecognized_magic_raises(self):
        with pytest.raises(MalformedCaptureError):
            list(read_pcap(b"NOTAPCAP" + b"\x00" * 16))

    def test_truncated_global_header_raises(self):
        with pytest.raises(MalformedCaptureError):
            list(read_pcap(b"\xa1\xb2\xc3\xd4" + b"\x00" * 10))

    def test_truncated_record_header_raises(self):
        # A valid global header followed by a record header cut short.
        data = b"\xa1\xb2\xc3\xd4" + b"\x00" * 20 + b"\x00" * 8
        with pytest.raises(MalformedCaptureError):
            list(read_pcap(data))

    def test_declared_length_past_the_buffer_raises(self):
        global_header = b"\xa1\xb2\xc3\xd4" + b"\x00" * 20
        record_header = struct.pack("<IIII", 0, 0, 100, 100)  # incl_len=100
        data = (
            global_header + record_header + b"\x01\x02"
        )  # only 2 bytes follow
        with pytest.raises(MalformedCaptureError):
            list(read_pcap(data))


class TestReadPcapng:
    def test_default_tsresol_is_microseconds(self):
        buffer = shb() + idb() + epb(0, 1000, b"\xaa\xbb\xcc")
        (frame,) = list(read_pcapng(buffer))
        assert frame == CapturedFrame(timestamp=1_000_000, data=b"\xaa\xbb\xcc")

    def test_explicit_nanosecond_tsresol(self):
        buffer = shb() + idb(tsresol=9) + epb(0, 123_456_789, b"\x01\x02")
        (frame,) = list(read_pcapng(buffer))
        assert frame.timestamp == 123_456_789

    def test_binary_tsresol(self):
        # if_tsresol = 0x80 | 20 -> resolution 2**-20 s; a raw count of
        # exactly 2**20 units is exactly one second.
        buffer = shb() + idb(tsresol=0x80 | 20) + epb(0, 1 << 20, b"\x03")
        (frame,) = list(read_pcapng(buffer))
        assert frame.timestamp == 1_000_000_000

    def test_simple_packet_block_has_no_timestamp(self):
        buffer = shb() + idb() + spb(3, b"\xde\xad\xbe")
        (frame,) = list(read_pcapng(buffer))
        assert frame == CapturedFrame(timestamp=0, data=b"\xde\xad\xbe")

    def test_simple_packet_block_trims_to_original_length(self):
        # 4-byte-aligned padding could otherwise leak into the data.
        buffer = shb() + idb() + spb(1, b"\x99\x00\x00\x00")
        (frame,) = list(read_pcapng(buffer))
        assert frame.data == b"\x99"

    def test_big_endian_section(self):
        buffer = shb(fmt=">") + idb(fmt=">") + epb(0, 2000, b"\xee", fmt=">")
        (frame,) = list(read_pcapng(buffer))
        assert frame == CapturedFrame(timestamp=2_000_000, data=b"\xee")

    def test_unknown_block_type_is_skipped(self):
        buffer = shb() + idb() + unknown_block() + epb(0, 500, b"\x05")
        frames = list(read_pcapng(buffer))
        assert [f.data for f in frames] == [b"\x05"]

    def test_multiple_sections_reset_endianness_and_interfaces(self):
        buffer = (
            shb()
            + idb(tsresol=9)
            + epb(0, 7, b"\x07")
            + shb(fmt=">")
            + idb(fmt=">")
            + epb(0, 3000, b"\x08", fmt=">")
        )
        frames = list(read_pcapng(buffer))
        assert frames == [
            CapturedFrame(timestamp=7, data=b"\x07"),
            CapturedFrame(timestamp=3_000_000, data=b"\x08"),
        ]

    def test_multiple_interfaces_keep_independent_resolutions(self):
        buffer = (
            shb()
            + idb(tsresol=9)  # interface 0: nanoseconds
            + idb(tsresol=0)  # interface 1: seconds
            + epb(0, 5, b"\x01")
            + epb(1, 5, b"\x02")
        )
        frames = list(read_pcapng(buffer))
        assert frames[0].timestamp == 5
        assert frames[1].timestamp == 5_000_000_000

    def test_read_captures_auto_detects_pcapng(self):
        buffer = shb() + idb() + epb(0, 1, b"\x01")
        assert list(read_captures(buffer)) == list(read_pcapng(buffer))

    def test_idb_skips_over_an_unrelated_option_before_if_tsresol(self):
        # if_name (code 2), "eth0" (4 bytes, needing no padding), ahead
        # of if_tsresol — exercises walking past an option this reader
        # does not care about, not just recognizing the one it does.
        opts = (
            struct.pack("<HH", 2, 4)
            + b"eth0"
            + struct.pack("<HH", 9, 1)
            + bytes([9])
            + b"\x00\x00\x00"
            + struct.pack("<HH", 0, 0)
        )
        body = struct.pack("<HHI", 1, 0, 65535) + opts
        buffer = (
            shb()
            + _block("<", struct.pack("<I", 1), body)
            + epb(0, 42, b"\x01")
        )
        (frame,) = list(read_pcapng(buffer))
        assert frame.timestamp == 42  # nanosecond resolution applied


class TestReadPcapngMalformedInput:
    def test_missing_section_header_block_raises(self):
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(b"not a pcapng capture at all!"))

    def test_block_before_any_shb_raises_via_read_captures(self):
        # read_captures' own magic-byte check rejects this before
        # dispatching to read_pcapng at all — the buffer never even
        # starts with a Section Header Block.
        with pytest.raises(MalformedCaptureError):
            list(read_captures(idb()))

    def test_unrecognized_magic_raises(self):
        with pytest.raises(MalformedCaptureError):
            list(read_captures(b"\xff\xff\xff\xff" + b"\x00" * 20))

    def test_too_short_for_any_magic_raises(self):
        with pytest.raises(MalformedCaptureError):
            list(read_captures(b"\x01"))

    def test_truncated_byte_order_magic_raises(self):
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(b"\x0a\x0d\x0d\x0a\x0c\x00\x00\x00\x1a\x2b"))

    def test_unrecognized_byte_order_magic_raises(self):
        body = b"\xff\xff\xff\xff" + b"\x00" * 12
        buffer = _block("<", b"\x0a\x0d\x0d\x0a", body)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(buffer))

    def test_block_length_below_minimum_raises(self):
        buffer = shb() + struct.pack("<III", 1, 8, 8)  # block_len=8 < 12
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(buffer))

    def test_block_length_not_a_multiple_of_4_raises(self):
        buffer = shb() + struct.pack("<III", 1, 13, 13)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(buffer))

    def test_block_length_past_the_buffer_raises(self):
        buffer = shb() + struct.pack("<III", 1, 1000, 1000)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(buffer))

    def test_mismatched_trailing_length_raises(self):
        buffer = (
            shb()
            + struct.pack("<I", 1)
            + struct.pack("<I", 16)
            + b"\x00" * 8
            + struct.pack("<I", 20)
        )
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(buffer))

    def test_epb_referencing_an_unknown_interface_raises(self):
        buffer = shb() + epb(0, 1, b"\x01")  # no IDB at all
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(buffer))

    def test_block_header_runs_past_the_buffer_raises(self):
        buffer = shb() + b"\x00" * 4  # a dangling partial block header
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(buffer))

    def test_epb_too_short_raises(self):
        # A well-formed, self-consistent 20-byte block (all length
        # fields agree, fully present in the buffer) — too short for
        # EPB's own 32-byte minimum, distinct from the generic
        # "declares more bytes than the buffer holds" case above.
        buffer = shb() + idb() + _block("<", struct.pack("<I", 6), b"\x00" * 8)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(buffer))

    def test_epb_declared_captured_length_past_the_block_raises(self):
        body = struct.pack("<IIIII", 0, 0, 0, 1000, 1000) + b"\x00" * 4
        buffer = shb() + idb() + _block("<", struct.pack("<I", 6), body)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(buffer))

    def test_spb_too_short_raises(self):
        buffer = shb() + idb() + struct.pack("<III", 3, 12, 12)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(buffer))
