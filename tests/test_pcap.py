"""Tests for netprotocols.pcap: classic pcap and pcapng capture reading.

Classic-pcap coverage reuses the real fixture corpus (tests/fixtures/),
matching this repository's real-capture-only ethos for that directory.
pcapng coverage mostly cannot: the corpus holds one pcapng capture,
tests/fixtures/pcapng/interfaces.pcapng, and the exotic ``if_tsresol``
cases in particular (nanosecond and non-default resolutions)
essentially never occur in real traffic, which is overwhelmingly the
tcpdump/Wireshark default (microseconds, or classic pcap). This file
hand-builds pcapng byte sequences instead — a flagged exception to
tests/fixtures/MANIFEST.md's real-capture rule, as small Python
builders, so every byte is readable in the source. The
``read_packets`` tests read the real two-interface capture and derive
their other inputs from it: the ``if_name`` edge cases edit its option
bytes only, the memoryview tests edit its bytes in a bytearray, and the
section-reset tests reorder its blocks or append hand-built ones, each
edit labelled where it is made.

Each reader test runs on every input kind the ``capture`` fixture
builds from the same bytes, buffers and streams alike. The stream tests
cut the real captures short in files on disk, and the memory tests read
crafted captures of about 8 MiB, labelled where they are built.
"""

from __future__ import annotations

import io
import mmap
import struct
from collections.abc import Callable

import pytest

from conftest import FIXTURES, allocation_peak
from netprotocols import (
    CapturedFrame,
    CapturedPacket,
    MalformedCaptureError,
    read_captures,
    read_packets,
    read_pcap,
    read_pcapng,
)
from netprotocols.pcap import _READ_CHUNK


def _reference_read_pcap(data: bytes) -> list[bytes]:
    """Minimal classic-pcap reader, independent of
    :mod:`netprotocols.pcap` (the module under test) — mirrors the
    same "standalone, so a shared bug can't cancel itself out"
    philosophy as scripts/benchmark.py and scripts/check_fixtures.py.
    Scoped to this one cross-check; other tests read captures with
    netprotocols.pcap.read_pcap."""
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


# -- capture inputs --
#
# Every reader takes a buffer or a binary stream. The ``capture``
# fixture runs each reader test once per input kind, each built from
# the same bytes: the bytes themselves, a memoryview over a bytearray
# copy, an io.BytesIO, a stream with nothing but ``read``, and one that
# also returns at most 7 bytes per ``read`` call, as a pipe may.


class ReadOnlyStream:
    """A binary stream with only ``read``: no ``seek``, ``tell``,
    ``readinto`` or buffer protocol, so a reader that needs any of them
    fails on it.

    :param data: The stream's bytes.
    :param most: The most bytes one ``read`` call returns, or ``None``
        for as many as asked.
    """

    def __init__(self, data: bytes, most: int | None = None) -> None:
        self._stream = io.BytesIO(data)
        self._most = most
        self.sizes: list[int] = []

    def read(self, size: int, /) -> bytes:
        self.sizes.append(size)
        if self._most is not None:
            size = min(size, self._most)
        return self._stream.read(size)

    @property
    def consumed(self) -> int:
        """How many bytes ``read`` has returned so far."""
        return self._stream.tell()


Capture = bytes | memoryview | io.BytesIO | ReadOnlyStream

CAPTURE_KINDS: dict[str, Callable[[bytes], Capture]] = {
    "bytes": bytes,
    "memoryview": lambda data: memoryview(bytearray(data)),
    "BytesIO": io.BytesIO,
    "read-only stream": ReadOnlyStream,
    "short-read stream": lambda data: ReadOnlyStream(data, most=7),
}


@pytest.fixture(params=list(CAPTURE_KINDS.values()), ids=list(CAPTURE_KINDS))
def capture(request: pytest.FixtureRequest) -> Callable[[bytes], Capture]:
    """Build a reader's input of one kind from a capture's bytes."""
    return request.param


# -- pcapng builders (little- and big-endian) --
#
# Independent of netprotocols.pcap's own implementation: these pack
# blocks by hand from the wire format (draft-ietf-opsawg-pcapng-03), so
# a bug in the reader cannot cancel itself out in the fixtures it
# reads.

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
    def test_matches_the_reference_reader(self, capture, path):
        reference = _reference_read_pcap(path.read_bytes())
        frames = list(read_pcap(capture(path.read_bytes())))
        assert len(frames) == len(reference)
        assert [frame.data for frame in frames] == reference

    def test_timestamps_are_nanoseconds_since_the_epoch_and_increase(
        self, capture
    ):
        path = sorted(FIXTURES.glob("*.pcap"))[0]
        frames = list(read_pcap(capture(path.read_bytes())))
        assert all(isinstance(frame.timestamp, int) for frame in frames)
        # Real capture, taken in one sitting: not strictly monotonic
        # across pcap's own two-field (sec, frac) granularity in
        # principle, but every frame's timestamp is a real 2020s+ Unix
        # nanosecond value, not a raw microsecond/word miscount.
        assert all(
            frame.timestamp > 1_700_000_000_000_000_000 for frame in frames
        )

    def test_read_captures_auto_detects_classic_pcap(self, capture):
        path = sorted(FIXTURES.glob("*.pcap"))[0]
        data = path.read_bytes()
        assert list(read_captures(capture(data))) == list(
            read_pcap(capture(data))
        )

    def test_accepts_a_memoryview(self):
        path = sorted(FIXTURES.glob("*.pcap"))[0]
        data = path.read_bytes()
        assert list(read_pcap(memoryview(data))) == list(read_pcap(data))


class TestReadPcapMalformedInput:
    def test_too_short_for_a_magic_number_raises(self, capture):
        with pytest.raises(MalformedCaptureError):
            list(read_pcap(capture(b"\x00\x00")))

    def test_unrecognized_magic_raises(self, capture):
        with pytest.raises(MalformedCaptureError):
            list(read_pcap(capture(b"NOTAPCAP" + b"\x00" * 16)))

    def test_truncated_global_header_raises(self, capture):
        with pytest.raises(MalformedCaptureError):
            list(read_pcap(capture(b"\xa1\xb2\xc3\xd4" + b"\x00" * 10)))

    def test_truncated_record_header_raises(self, capture):
        # A valid global header followed by a record header cut short.
        data = b"\xa1\xb2\xc3\xd4" + b"\x00" * 20 + b"\x00" * 8
        with pytest.raises(MalformedCaptureError):
            list(read_pcap(capture(data)))

    def test_declared_length_past_the_buffer_raises(self, capture):
        global_header = b"\xa1\xb2\xc3\xd4" + b"\x00" * 20
        record_header = struct.pack("<IIII", 0, 0, 100, 100)  # incl_len=100
        data = (
            global_header + record_header + b"\x01\x02"
        )  # only 2 bytes follow
        with pytest.raises(MalformedCaptureError):
            list(read_pcap(capture(data)))


class TestReadPcapng:
    def test_default_tsresol_is_microseconds(self, capture):
        buffer = shb() + idb() + epb(0, 1000, b"\xaa\xbb\xcc")
        (frame,) = list(read_pcapng(capture(buffer)))
        assert frame == CapturedFrame(timestamp=1_000_000, data=b"\xaa\xbb\xcc")

    def test_explicit_nanosecond_tsresol(self, capture):
        buffer = shb() + idb(tsresol=9) + epb(0, 123_456_789, b"\x01\x02")
        (frame,) = list(read_pcapng(capture(buffer)))
        assert frame.timestamp == 123_456_789

    def test_binary_tsresol(self, capture):
        # if_tsresol = 0x80 | 20 -> resolution 2**-20 s; a raw count of
        # exactly 2**20 units is exactly one second.
        buffer = shb() + idb(tsresol=0x80 | 20) + epb(0, 1 << 20, b"\x03")
        (frame,) = list(read_pcapng(capture(buffer)))
        assert frame.timestamp == 1_000_000_000

    def test_simple_packet_block_has_no_timestamp(self, capture):
        buffer = shb() + idb() + spb(3, b"\xde\xad\xbe")
        (frame,) = list(read_pcapng(capture(buffer)))
        assert frame == CapturedFrame(timestamp=0, data=b"\xde\xad\xbe")

    def test_simple_packet_block_trims_to_original_length(self, capture):
        # 4-byte-aligned padding could otherwise leak into the data.
        buffer = shb() + idb() + spb(1, b"\x99\x00\x00\x00")
        (frame,) = list(read_pcapng(capture(buffer)))
        assert frame.data == b"\x99"

    def test_big_endian_section(self, capture):
        buffer = shb(fmt=">") + idb(fmt=">") + epb(0, 2000, b"\xee", fmt=">")
        (frame,) = list(read_pcapng(capture(buffer)))
        assert frame == CapturedFrame(timestamp=2_000_000, data=b"\xee")

    def test_unknown_block_type_is_skipped(self, capture):
        buffer = shb() + idb() + unknown_block() + epb(0, 500, b"\x05")
        frames = list(read_pcapng(capture(buffer)))
        assert [f.data for f in frames] == [b"\x05"]

    def test_multiple_sections_reset_endianness_and_interfaces(self, capture):
        buffer = (
            shb()
            + idb(tsresol=9)
            + epb(0, 7, b"\x07")
            + shb(fmt=">")
            + idb(fmt=">")
            + epb(0, 3000, b"\x08", fmt=">")
        )
        frames = list(read_pcapng(capture(buffer)))
        assert frames == [
            CapturedFrame(timestamp=7, data=b"\x07"),
            CapturedFrame(timestamp=3_000_000, data=b"\x08"),
        ]

    def test_multiple_interfaces_keep_independent_resolutions(self, capture):
        buffer = (
            shb()
            + idb(tsresol=9)  # interface 0: nanoseconds
            + idb(tsresol=0)  # interface 1: seconds
            + epb(0, 5, b"\x01")
            + epb(1, 5, b"\x02")
        )
        frames = list(read_pcapng(capture(buffer)))
        assert frames[0].timestamp == 5
        assert frames[1].timestamp == 5_000_000_000

    def test_read_captures_auto_detects_pcapng(self, capture):
        buffer = shb() + idb() + epb(0, 1, b"\x01")
        assert list(read_captures(capture(buffer))) == list(
            read_pcapng(capture(buffer))
        )

    def test_idb_skips_over_an_unrelated_option_before_if_tsresol(
        self, capture
    ):
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
        (frame,) = list(read_pcapng(capture(buffer)))
        assert frame.timestamp == 42  # nanosecond resolution applied

    def test_the_first_if_tsresol_wins(self, capture):
        # Two if_tsresol options: nanoseconds, then seconds.
        opts = (
            struct.pack("<HH", 9, 1)
            + bytes([9])
            + b"\x00\x00\x00"
            + struct.pack("<HH", 9, 1)
            + bytes([0])
            + b"\x00\x00\x00"
            + struct.pack("<HH", 0, 0)
        )
        body = struct.pack("<HHI", 1, 0, 65535) + opts
        buffer = (
            shb()
            + _block("<", struct.pack("<I", 1), body)
            + epb(0, 42, b"\x01")
        )
        (frame,) = list(read_pcapng(capture(buffer)))
        assert frame.timestamp == 42


class TestReadPcapngMalformedInput:
    def test_missing_section_header_block_raises(self, capture):
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(b"not a pcapng capture at all!")))

    def test_block_before_any_shb_raises_via_read_captures(self, capture):
        # read_captures' own magic-byte check rejects this before
        # dispatching to read_pcapng at all — the buffer never even
        # starts with a Section Header Block.
        with pytest.raises(MalformedCaptureError):
            list(read_captures(capture(idb())))

    def test_unrecognized_magic_raises(self, capture):
        with pytest.raises(MalformedCaptureError):
            list(read_captures(capture(b"\xff\xff\xff\xff" + b"\x00" * 20)))

    def test_too_short_for_any_magic_raises(self, capture):
        with pytest.raises(MalformedCaptureError):
            list(read_captures(capture(b"\x01")))

    def test_truncated_byte_order_magic_raises(self, capture):
        with pytest.raises(MalformedCaptureError):
            list(
                read_pcapng(
                    capture(b"\x0a\x0d\x0d\x0a\x0c\x00\x00\x00\x1a\x2b")
                )
            )

    def test_unrecognized_byte_order_magic_raises(self, capture):
        body = b"\xff\xff\xff\xff" + b"\x00" * 12
        buffer = _block("<", b"\x0a\x0d\x0d\x0a", body)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(buffer)))

    def test_block_length_below_minimum_raises(self, capture):
        buffer = shb() + struct.pack("<III", 1, 8, 8)  # block_len=8 < 12
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(buffer)))

    def test_block_length_not_a_multiple_of_4_raises(self, capture):
        buffer = shb() + struct.pack("<III", 1, 13, 13)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(buffer)))

    def test_block_length_past_the_buffer_raises(self, capture):
        buffer = shb() + struct.pack("<III", 1, 1000, 1000)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(buffer)))

    def test_mismatched_trailing_length_raises(self, capture):
        buffer = (
            shb()
            + struct.pack("<I", 1)
            + struct.pack("<I", 16)
            + b"\x00" * 8
            + struct.pack("<I", 20)
        )
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(buffer)))

    def test_epb_referencing_an_unknown_interface_raises(self, capture):
        buffer = shb() + epb(0, 1, b"\x01")  # no IDB at all
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(buffer)))

    def test_block_header_runs_past_the_buffer_raises(self, capture):
        buffer = shb() + b"\x00" * 4  # a dangling partial block header
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(buffer)))

    def test_epb_too_short_raises(self, capture):
        # A well-formed, self-consistent 20-byte block (all length
        # fields agree, fully present in the buffer) — too short for
        # EPB's own 32-byte minimum, distinct from the generic
        # "declares more bytes than the buffer holds" case above.
        buffer = shb() + idb() + _block("<", struct.pack("<I", 6), b"\x00" * 8)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(buffer)))

    def test_epb_declared_captured_length_past_the_block_raises(self, capture):
        body = struct.pack("<IIIII", 0, 0, 0, 1000, 1000) + b"\x00" * 4
        buffer = shb() + idb() + _block("<", struct.pack("<I", 6), body)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(buffer)))

    def test_spb_too_short_raises(self, capture):
        buffer = shb() + idb() + struct.pack("<III", 3, 12, 12)
        with pytest.raises(MalformedCaptureError):
            list(read_pcapng(capture(buffer)))


# -- read_packets --
#
# tests/fixtures/pcapng/interfaces.pcapng (see its MANIFEST entry):
# one section, interface 0 "lo" and interface 1 "npifa0", eight
# Enhanced Packet Blocks with interface IDs 0, 0, 1, 1, 0, 0, 1, 1.

INTERFACES_PCAPNG = (FIXTURES / "pcapng" / "interfaces.pcapng").read_bytes()

#: Block offsets in INTERFACES_PCAPNG: the Section Header Block, the two
#: Interface Description Blocks, the eight Enhanced Packet Blocks, and
#: the two Interface Statistics Blocks after them.
_SHB = slice(0, 188)
_IDB_LO = slice(188, 280)
_IDB_VETH = slice(280, 364)
_EPBS = slice(364, 1420)

#: The first options of each Interface Description Block: lo's
#: if_name ("lo") then if_description ("Loopback"), npifa0's if_name.
_LO_IF_NAME = 204
_LO_IF_DESCRIPTION = 212
_VETH_IF_NAME = 296

#: lo's last option, if_os; the zero padding after its value, then
#: opt_endofopt; and lo's options end, where the padding and
#: opt_endofopt end.
_LO_IF_OS = 244
_LO_IF_OS_PADDING = 269
_LO_OPTIONS_END = 276

_LO_FRAMES = (0, 1, 4, 5)
_VETH_FRAMES = (2, 3, 6, 7)


def _edit_options(offset: int, new: bytes) -> bytes:
    """INTERFACES_PCAPNG with the option bytes at ``offset`` replaced.

    Only Interface Description Block option bytes are edited; every
    block length stays as captured.
    """
    assert _IDB_LO.start + 16 <= offset < _IDB_VETH.stop - 4
    return (
        INTERFACES_PCAPNG[:offset]
        + new
        + INTERFACES_PCAPNG[offset + len(new) :]
    )


def _names(
    buffer: bytes, capture: Callable[[bytes], Capture]
) -> list[str | None]:
    return [packet.interface_name for packet in read_packets(capture(buffer))]


class TestReadPacketsAgainstTheRealCapture:
    def test_the_capture_holds_the_option_bytes_these_tests_edit(self):
        data = INTERFACES_PCAPNG
        assert data[_LO_IF_NAME : _LO_IF_NAME + 8] == b"\x02\x00\x02\x00lo\0\0"
        assert (
            data[_LO_IF_DESCRIPTION : _LO_IF_DESCRIPTION + 12]
            == b"\x03\x00\x08\x00Loopback"
        )
        assert data[_VETH_IF_NAME : _VETH_IF_NAME + 12] == (
            b"\x02\x00\x06\x00npifa0\0\0"
        )
        assert _IDB_LO.stop - 4 == _LO_OPTIONS_END
        assert data[_LO_IF_OS:_LO_OPTIONS_END] == (
            b"\x0c\x00\x15\x00Linux 6.18.44-fc-v378" + b"\0" * 7
        )
        assert _LO_IF_OS_PADDING == _LO_IF_OS + 4 + 21

    def test_each_frame_names_its_interface(self, capture):
        packets = list(read_packets(capture(INTERFACES_PCAPNG)))
        assert [p.interface_id for p in packets] == [0, 0, 1, 1, 0, 0, 1, 1]
        assert [p.interface_name for p in packets] == [
            "lo",
            "lo",
            "npifa0",
            "npifa0",
            "lo",
            "lo",
            "npifa0",
            "npifa0",
        ]

    def test_the_names_match_the_traffic_each_interface_carried(self, capture):
        # Ethernet, then an option-free IPv4 header: source and
        # destination at frame bytes 26-29 and 30-33.
        loopback = bytes([127, 0, 0, 1])
        veth = {bytes([10, 9, 72, 1]), bytes([10, 9, 72, 2])}
        for packet in read_packets(capture(INTERFACES_PCAPNG)):
            addresses = {packet.data[26:30], packet.data[30:34]}
            if packet.interface_name == "lo":
                assert addresses == {loopback}
            else:
                assert packet.interface_name == "npifa0"
                assert addresses == veth

    def test_timestamps_and_data_are_read_pcapngs(self, capture):
        packets = list(read_packets(capture(INTERFACES_PCAPNG)))
        frames = list(read_pcapng(capture(INTERFACES_PCAPNG)))
        assert [(p.timestamp, p.data) for p in packets] == frames
        assert list(read_captures(capture(INTERFACES_PCAPNG))) == frames

    def test_yields_captured_packets(self, capture):
        packet = next(read_packets(capture(INTERFACES_PCAPNG)))
        assert type(packet) is CapturedPacket
        timestamp, data, interface_id, interface_name = packet
        assert timestamp > 1_700_000_000_000_000_000
        assert (interface_id, interface_name) == (0, "lo")
        assert type(data) is bytes

    def test_a_memoryview_is_copied_when_iteration_starts(self):
        # Edit, made between the call and the first next(): lo's if_name
        # value "lo" becomes "LO" in the bytearray the memoryview is over.
        mutable = bytearray(INTERFACES_PCAPNG)
        packets = read_packets(memoryview(mutable))
        mutable[_LO_IF_NAME + 4 : _LO_IF_NAME + 6] = b"LO"
        assert next(packets).interface_name == "LO"

    def test_a_memoryview_is_not_reread_after_iteration_starts(self):
        # Edit, made after the first next(): npifa0's if_name value
        # becomes "NPIFA0" in the bytearray the memoryview is over.
        mutable = bytearray(INTERFACES_PCAPNG)
        packets = read_packets(memoryview(mutable))
        assert next(packets).interface_name == "lo"
        mutable[_VETH_IF_NAME + 4 : _VETH_IF_NAME + 10] = b"NPIFA0"
        assert [p.interface_name for p in packets] == [
            "lo",
            "npifa0",
            "npifa0",
            "lo",
            "lo",
            "npifa0",
            "npifa0",
        ]

    def test_accepts_a_memoryview(self):
        assert list(read_packets(memoryview(INTERFACES_PCAPNG))) == list(
            read_packets(INTERFACES_PCAPNG)
        )

    def test_interfaces_reset_at_each_section_header_block(self, capture):
        # A second section, built from the capture's own blocks: its
        # Section Header Block, then its two Interface Description
        # Blocks in the other order, then its eight Enhanced Packet
        # Blocks. In that section interface 0 is npifa0.
        data = INTERFACES_PCAPNG
        second = data[_SHB] + data[_IDB_VETH] + data[_IDB_LO] + data[_EPBS]
        packets = list(read_packets(capture(data + second)))
        assert len(packets) == 16
        assert [p.interface_id for p in packets[8:]] == [0, 0, 1, 1] * 2
        assert [p.interface_name for p in packets[8:]] == [
            "npifa0",
            "npifa0",
            "lo",
            "lo",
        ] * 2

    def test_reset_section_without_if_name_reads_none(self, capture):
        # A second section whose only Interface Description Block is
        # the hand-built one, with no if_name: the first section's
        # names are not carried into it.
        buffer = INTERFACES_PCAPNG + shb() + idb() + epb(0, 1, b"\x01")
        assert next(read_packets(capture(buffer))).interface_name == "lo"
        assert list(read_packets(capture(buffer)))[-1][2:] == (0, None)


class TestReadPacketsIfNameOptions:
    """Inputs are the real capture with its option bytes edited.

    Each edit is labelled where it is made. The one exception, a
    hand-built capture, says so in its name.
    """

    def test_no_if_name_reads_none(self, capture):
        # Edit: lo's if_name option code 2 becomes 1, opt_comment.
        buffer = _edit_options(_LO_IF_NAME, b"\x01\x00")
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == [None] * 4
        assert [names[i] for i in _VETH_FRAMES] == ["npifa0"] * 4

    def test_a_hand_built_idb_without_if_name_reads_none(self, capture):
        buffer = shb() + idb() + epb(0, 1000, b"\xaa")
        assert list(read_packets(capture(buffer))) == [
            CapturedPacket(1_000_000, b"\xaa", 0, None)
        ]

    def test_the_first_if_name_wins(self, capture):
        # Edit: lo's if_description ("Loopback") option code 3 becomes
        # 2, so lo has if_name "lo" then if_name "Loopback".
        buffer = _edit_options(_LO_IF_DESCRIPTION, b"\x02\x00")
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == ["lo"] * 4

    def test_a_later_if_name_is_read_when_the_first_is_gone(self, capture):
        # Edits: lo's if_name becomes opt_comment (code 1) and its
        # if_description becomes if_name (code 2).
        buffer = _edit_options(_LO_IF_NAME, b"\x01\x00")
        buffer = buffer[:_LO_IF_DESCRIPTION] + b"\x02\x00" + buffer[214:]
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == ["Loopback"] * 4

    def test_an_empty_if_name_reads_none(self, capture):
        # Edit: lo's 8-byte if_name option ("lo", padded) becomes an
        # empty if_name and an empty opt_comment.
        buffer = _edit_options(
            _LO_IF_NAME, b"\x02\x00\x00\x00" + b"\x01\x00\x00\x00"
        )
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == [None] * 4
        assert [names[i] for i in _VETH_FRAMES] == ["npifa0"] * 4

    def test_an_empty_if_name_is_passed_over_for_a_later_one(self, capture):
        # Edits: as above, and lo's if_description becomes if_name.
        buffer = _edit_options(
            _LO_IF_NAME,
            b"\x02\x00\x00\x00" + b"\x01\x00\x00\x00" + b"\x02\x00",
        )
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == ["Loopback"] * 4

    def test_an_if_name_is_cut_at_the_end_of_the_options(self, capture):
        # Edits: lo's if_name becomes opt_comment (code 1); its if_os
        # becomes an if_name of length 0x400, past the block; and the
        # zero padding and opt_endofopt after the if_os value, up to
        # the end of the options, become "!".
        buffer = _edit_options(_LO_IF_NAME, b"\x01\x00")
        buffer = (
            buffer[:_LO_IF_OS]
            + b"\x02\x00\x00\x04"
            + buffer[_LO_IF_OS + 4 : _LO_IF_OS_PADDING]
            + b"!" * (_LO_OPTIONS_END - _LO_IF_OS_PADDING)
            + buffer[_LO_OPTIONS_END:]
        )
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == [
            "Linux 6.18.44-fc-v378!!!!!!!"
        ] * 4

    def test_an_if_name_ends_at_its_first_zero_byte(self, capture):
        # Edit: lo's if_name length 2 becomes 4, so its value is
        # "lo" and the two zero padding bytes after it.
        buffer = _edit_options(_LO_IF_NAME + 2, b"\x04\x00")
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == ["lo"] * 4

    def test_bytes_after_an_if_names_zero_byte_are_ignored(self, capture):
        # Edits: lo's if_name length 2 becomes 4, and its last value
        # byte, a zero padding byte, becomes ff, not UTF-8.
        buffer = _edit_options(_LO_IF_NAME + 2, b"\x04\x00")
        buffer = buffer[: _LO_IF_NAME + 7] + b"\xff" + buffer[_LO_IF_NAME + 8 :]
        assert buffer[_LO_IF_NAME + 4 : _LO_IF_NAME + 8] == b"lo\x00\xff"
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == ["lo"] * 4

    def test_an_if_name_of_only_zero_bytes_reads_none(self, capture):
        # Edit: lo's if_name value "lo" becomes two zero bytes.
        buffer = _edit_options(_LO_IF_NAME + 4, b"\x00\x00")
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == [None] * 4
        assert [names[i] for i in _VETH_FRAMES] == ["npifa0"] * 4

    def test_an_if_name_of_only_zero_bytes_is_passed_over(self, capture):
        # Edits: lo's if_name value "lo" becomes two zero bytes, and
        # its if_description becomes if_name (code 2).
        buffer = _edit_options(_LO_IF_NAME + 4, b"\x00\x00")
        buffer = buffer[:_LO_IF_DESCRIPTION] + b"\x02\x00" + buffer[214:]
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == ["Loopback"] * 4

    def test_an_if_name_whose_value_starts_at_the_options_end_reads_none(
        self,
        capture,
    ):
        # Edits: lo's if_name becomes opt_comment (code 1), and its
        # opt_endofopt, the last 4 option bytes, becomes an if_name
        # header of length 1, so the value would start at the end of
        # the options.
        buffer = _edit_options(_LO_IF_NAME, b"\x01\x00")
        buffer = (
            buffer[: _LO_OPTIONS_END - 4]
            + b"\x02\x00\x01\x00"
            + buffer[_LO_OPTIONS_END:]
        )
        names = _names(buffer, capture)
        assert [names[i] for i in _LO_FRAMES] == [None] * 4
        assert [names[i] for i in _VETH_FRAMES] == ["npifa0"] * 4

    def test_a_non_utf8_if_name_raises_at_the_first_frame_naming_it(
        self, capture
    ):
        # Edit: npifa0's if_name bytes "np" become ff fe, not UTF-8.
        buffer = _edit_options(_VETH_IF_NAME + 4, b"\xff\xfe")
        packets = read_packets(capture(buffer))
        assert [next(packets).interface_name for _ in range(2)] == [
            "lo",
            "lo",
        ]
        with pytest.raises(MalformedCaptureError) as excinfo:
            next(packets)
        assert excinfo.value.field == "if_name"
        assert excinfo.value.offset == _VETH_IF_NAME + 4
        assert excinfo.value.actual == "fffe69666130"

    def test_a_non_utf8_if_name_offset_points_at_the_bad_byte(self, capture):
        # Edit: the second byte of lo's if_name, "o", becomes ff.
        buffer = _edit_options(_LO_IF_NAME + 5, b"\xff")
        with pytest.raises(MalformedCaptureError) as excinfo:
            list(read_packets(capture(buffer)))
        assert excinfo.value.offset == _LO_IF_NAME + 5

    def test_a_non_utf8_if_name_leaves_read_pcapng_unchanged(self, capture):
        buffer = _edit_options(_VETH_IF_NAME + 4, b"\xff\xfe")
        assert list(read_pcapng(capture(buffer))) == list(
            read_pcapng(capture(INTERFACES_PCAPNG))
        )
        assert list(read_captures(capture(buffer))) == list(
            read_captures(capture(INTERFACES_PCAPNG))
        )


class TestReadPacketsWithoutAnInterface:
    def test_classic_pcap_gives_none_for_both(self, capture):
        path = sorted(FIXTURES.glob("*.pcap"))[0]
        data = path.read_bytes()
        packets = list(read_packets(capture(data)))
        assert packets
        assert all(p[2:] == (None, None) for p in packets)
        assert [p[:2] for p in packets] == list(read_pcap(capture(data)))

    def test_simple_packet_block_gives_none_for_both(self, capture):
        buffer = shb() + idb() + spb(3, b"\xde\xad\xbe")
        assert list(read_packets(capture(buffer))) == [
            CapturedPacket(0, b"\xde\xad\xbe", None, None)
        ]

    def test_simple_packet_block_after_an_enhanced_one(self, capture):
        buffer = shb() + idb() + epb(0, 1, b"\x01") + spb(1, b"\x02")
        assert [p[2:] for p in read_packets(capture(buffer))] == [
            (0, None),
            (None, None),
        ]


class TestReadPacketsMalformedInput:
    def test_too_short_for_any_magic_raises_on_the_call(self, capture):
        with pytest.raises(MalformedCaptureError):
            read_packets(capture(b"\x01"))

    def test_unrecognized_magic_raises_on_the_call(self, capture):
        with pytest.raises(MalformedCaptureError):
            read_packets(capture(b"\xff\xff\xff\xff" + b"\x00" * 20))

    def test_pcapng_errors_come_during_iteration(self, capture):
        packets = read_packets(capture(shb() + epb(0, 1, b"\x01")))  # no IDB
        with pytest.raises(MalformedCaptureError):
            next(packets)

    def test_classic_pcap_errors_come_during_iteration(self, capture):
        packets = read_packets(capture(b"\xa1\xb2\xc3\xd4" + b"\x00" * 10))
        with pytest.raises(MalformedCaptureError):
            next(packets)


# -- streams --

READERS = {
    "read_pcap": read_pcap,
    "read_pcapng": read_pcapng,
    "read_captures": read_captures,
    "read_packets": read_packets,
}

ARP_EXCHANGE_PCAP = (FIXTURES / "arp_exchange.pcap").read_bytes()


def _outcome(reader: Callable[[Capture], object], source: Capture) -> tuple:
    """What a reader gives for one input: every item it yields, then
    whether and where it raised, with the error's every attribute."""
    items: list[tuple] = []
    stage = "call"
    try:
        frames = reader(source)
        stage = "iteration"
        for item in frames:  # type: ignore[attr-defined]
            items.append(tuple(item))
    except MalformedCaptureError as e:
        return (
            items,
            stage,
            str(e),
            e.field,
            e.offset,
            e.expected,
            e.actual,
        )
    return items, None


def _assert_every_kind_agrees(data: bytes) -> None:
    for name, reader in READERS.items():
        expected = _outcome(reader, data)
        for kind, build in CAPTURE_KINDS.items():
            assert _outcome(reader, build(data)) == expected, (name, kind)


def _crafted_sections() -> bytes:
    """Crafted: two sections, little- then big-endian, with an unknown
    block, Enhanced and Simple Packet Blocks, and an EPB whose frame
    needs padding."""
    return (
        shb()
        + idb(tsresol=9)
        + epb(0, 7, b"\x07" * 5)
        + unknown_block()
        + spb(3, b"\xde\xad\xbe")
        + shb(fmt=">")
        + idb(fmt=">")
        + epb(0, 3000, b"\x08" * 9, fmt=">")
        + spb(5, b"abcde", fmt=">")
    )


class TestEveryInputKindAgrees:
    """Each reader gives every input kind built from the same bytes the
    same frames and the same error, attribute for attribute."""

    @pytest.mark.parametrize(
        "path",
        sorted(FIXTURES.rglob("*.pcap")) + sorted(FIXTURES.rglob("*.pcapng")),
        ids=lambda p: str(p.relative_to(FIXTURES)),
    )
    def test_on_every_fixture(self, path):
        _assert_every_kind_agrees(path.read_bytes())

    @pytest.mark.parametrize(
        "data",
        [INTERFACES_PCAPNG, ARP_EXCHANGE_PCAP, _crafted_sections()],
        ids=["interfaces.pcapng", "arp_exchange.pcap", "crafted sections"],
    )
    def test_on_every_truncation(self, data):
        for cut in range(len(data) + 1):
            _assert_every_kind_agrees(data[:cut])

    @pytest.mark.parametrize(
        "data",
        [
            # Crafted: an Enhanced Packet Block too short for its
            # fixed fields, then a Simple Packet Block too short for
            # its own, each a block whose lengths agree.
            shb() + idb() + _block("<", struct.pack("<I", 6), b"\x00" * 8),
            shb() + idb() + struct.pack("<III", 3, 12, 12),
            # Crafted: a block and a record declaring 4 GiB.
            shb() + struct.pack("<III", 1, 0xFFFFFFFC, 0xFFFFFFFC),
            ARP_EXCHANGE_PCAP[:24] + struct.pack("<IIII", 0, 0, 0xFFFFFFFF, 0),
            # Edit: npifa0's if_name bytes "np" become ff fe.
            _edit_options(_VETH_IF_NAME + 4, b"\xff\xfe"),
        ],
        ids=[
            "short EPB",
            "short SPB",
            "4 GiB block",
            "4 GiB record",
            "if_name",
        ],
    )
    def test_on_malformed_blocks(self, data):
        _assert_every_kind_agrees(data)


def _first_record_lengths(data: bytes) -> list[int]:
    """Each classic-pcap record's incl_len, read with ``struct``."""
    lengths = []
    cursor = 24
    while cursor < len(data):
        (incl_len,) = struct.unpack_from("<I", data, cursor + 8)
        lengths.append(incl_len)
        cursor += 16 + incl_len
    return lengths


class TestTruncatedFiles:
    """A capture file that ends early raises when iteration reaches the
    cut, with the field, offset, expected and actual values a buffer
    of the same bytes gives, and the frames before the cut stay valid.

    Each file is a real capture written to disk and cut short.
    """

    @pytest.fixture
    def cut_file(self, tmp_path):
        opened = []

        def cut(data: bytes, size: int) -> io.BufferedReader:
            path = tmp_path / "capture"
            path.write_bytes(data[:size])
            stream = path.open("rb")
            opened.append(stream)
            return stream

        yield cut
        for stream in opened:
            stream.close()

    def _assert_raises_after(
        self, reader, source, frames, field, offset, expected, actual
    ):
        items = reader(source)
        for frame in frames:
            assert tuple(next(items))[:2] == frame
        with pytest.raises(MalformedCaptureError) as excinfo:
            next(items)
        error = excinfo.value
        assert (error.field, error.offset, error.expected, error.actual) == (
            field,
            offset,
            expected,
            actual,
        )

    def test_inside_a_record_header(self, cut_file, capture):
        first = _first_record_lengths(ARP_EXCHANGE_PCAP)[0]
        record = 24 + 16 + first
        frames = list(read_pcap(ARP_EXCHANGE_PCAP))[:1]
        for source in (
            cut_file(ARP_EXCHANGE_PCAP, record + 9),
            capture(ARP_EXCHANGE_PCAP[: record + 9]),
        ):
            self._assert_raises_after(
                read_pcap, source, frames, "record header", record, 16, 9
            )

    def test_inside_a_record_body(self, cut_file, capture):
        first, second = _first_record_lengths(ARP_EXCHANGE_PCAP)[:2]
        record = 24 + 16 + first
        frames = list(read_pcap(ARP_EXCHANGE_PCAP))[:1]
        for reader in (read_pcap, read_captures, read_packets):
            for source in (
                cut_file(ARP_EXCHANGE_PCAP, record + 16 + 5),
                capture(ARP_EXCHANGE_PCAP[: record + 16 + 5]),
            ):
                self._assert_raises_after(
                    reader, source, frames, "incl_len", record, second, 5
                )

    def test_inside_the_global_header(self, cut_file, capture):
        for source in (
            cut_file(ARP_EXCHANGE_PCAP, 10),
            capture(ARP_EXCHANGE_PCAP[:10]),
        ):
            self._assert_raises_after(
                read_pcap, source, [], "global header", 0, 24, 10
            )

    def _epb(self) -> tuple[int, int, list[tuple[int, bytes]]]:
        """The first Enhanced Packet Block's offset and length, and the
        frames before the second."""
        start = _EPBS.start
        (length,) = struct.unpack_from("<I", INTERFACES_PCAPNG, start + 4)
        return start, length, list(read_pcapng(INTERFACES_PCAPNG))[:1]

    @pytest.mark.parametrize("reader", [read_pcapng, read_packets])
    def test_inside_a_block_header(self, cut_file, capture, reader):
        start, length, frames = self._epb()
        second = start + length
        for source in (
            cut_file(INTERFACES_PCAPNG, second + 5),
            capture(INTERFACES_PCAPNG[: second + 5]),
        ):
            self._assert_raises_after(
                reader, source, frames, "block header", second, 8, 5
            )

    @pytest.mark.parametrize("reader", [read_pcapng, read_packets])
    def test_inside_a_block_body(self, cut_file, capture, reader):
        start, length, _ = self._epb()
        for source in (
            cut_file(INTERFACES_PCAPNG, start + 40),
            capture(INTERFACES_PCAPNG[: start + 40]),
        ):
            self._assert_raises_after(
                reader, source, [], "block total length", start + 4, length, 40
            )

    @pytest.mark.parametrize("reader", [read_pcapng, read_packets])
    def test_inside_a_block_trailer(self, cut_file, capture, reader):
        start, length, _ = self._epb()
        size = start + length - 2
        for source in (
            cut_file(INTERFACES_PCAPNG, size),
            capture(INTERFACES_PCAPNG[:size]),
        ):
            self._assert_raises_after(
                reader,
                source,
                [],
                "block total length",
                start + 4,
                length,
                length - 2,
            )

    def test_inside_interface_description_options(self, cut_file, capture):
        size = _LO_IF_DESCRIPTION + 3
        for source in (
            cut_file(INTERFACES_PCAPNG, size),
            capture(INTERFACES_PCAPNG[:size]),
        ):
            self._assert_raises_after(
                read_pcapng,
                source,
                [],
                "block total length",
                _IDB_LO.start + 4,
                _IDB_LO.stop - _IDB_LO.start,
                size - _IDB_LO.start,
            )

    def test_inside_a_section_header_blocks_magic(self, cut_file, capture):
        for source in (
            cut_file(INTERFACES_PCAPNG, 10),
            capture(INTERFACES_PCAPNG[:10]),
        ):
            self._assert_raises_after(
                read_pcapng, source, [], "byte-order magic", 0, 12, 10
            )


class _BytearrayStream:
    """A stream whose ``read`` returns a ``bytearray``."""

    def __init__(self, data: bytes) -> None:
        self._stream = io.BytesIO(data)

    def read(self, size: int, /) -> bytearray:
        return bytearray(self._stream.read(size))


class TestReadingAStream:
    def test_read_pcap_and_read_pcapng_read_nothing_on_the_call(self):
        for reader, data in (
            (read_pcap, ARP_EXCHANGE_PCAP),
            (read_pcapng, INTERFACES_PCAPNG),
        ):
            stream = ReadOnlyStream(data)
            frames = reader(stream)
            assert stream.consumed == 0
            assert list(frames) == list(reader(data))

    @pytest.mark.parametrize("reader", [read_captures, read_packets])
    @pytest.mark.parametrize(
        "data", [ARP_EXCHANGE_PCAP, INTERFACES_PCAPNG], ids=["pcap", "pcapng"]
    )
    def test_detection_reads_the_magic_number_on_the_call(self, reader, data):
        stream = ReadOnlyStream(data)
        frames = reader(stream)
        assert stream.consumed == 4
        assert list(frames) == list(reader(data))

    def test_reading_starts_at_the_streams_position(self):
        # Edit: 100 bytes of zeros before the real capture, read past
        # with seek before the stream is handed over.
        stream = io.BytesIO(b"\x00" * 100 + INTERFACES_PCAPNG)
        stream.seek(100)
        assert list(read_packets(stream)) == list(
            read_packets(INTERFACES_PCAPNG)
        )

    def test_error_offsets_count_from_the_streams_position(self):
        # Edit: as above, and the capture cut inside its first EPB.
        stream = io.BytesIO(
            b"\x00" * 100 + INTERFACES_PCAPNG[: _EPBS.start + 40]
        )
        stream.seek(100)
        with pytest.raises(MalformedCaptureError) as excinfo:
            list(read_pcapng(stream))
        assert excinfo.value.offset == _EPBS.start + 4

    def test_the_stream_is_left_open(self):
        stream = io.BytesIO(INTERFACES_PCAPNG)
        list(read_pcapng(stream))
        assert not stream.closed
        assert stream.read() == b""

    @pytest.mark.parametrize(
        "data", [ARP_EXCHANGE_PCAP, INTERFACES_PCAPNG], ids=["pcap", "pcapng"]
    )
    def test_frame_data_is_bytes_when_read_returns_a_bytearray(self, data):
        frames = list(read_captures(_BytearrayStream(data)))
        assert frames == list(read_captures(data))
        assert all(type(frame.data) is bytes for frame in frames)

    @pytest.mark.parametrize(
        "data",
        [
            # Crafted: a block declaring 4 GiB, then 64 bytes.
            shb()
            + struct.pack("<III", 1, 0xFFFFFFFC, 0xFFFFFFFC)
            + b"\x00" * 64,
            # Edit: the real capture's first record declares 4 GiB.
            ARP_EXCHANGE_PCAP[:32]
            + struct.pack("<I", 0xFFFFFFFF)
            + ARP_EXCHANGE_PCAP[36:],
        ],
        ids=["pcapng", "pcap"],
    )
    def test_a_declared_length_past_the_stream_allocates_what_it_holds(
        self, data
    ):
        stream = ReadOnlyStream(data)
        with (
            allocation_peak() as allocated,
            pytest.raises(MalformedCaptureError) as excinfo,
        ):
            list(read_captures(stream))
        assert excinfo.value.actual < len(data)
        assert max(stream.sizes) <= _READ_CHUNK
        assert allocated.peak < 64 * 1024

    @pytest.mark.parametrize(
        "data",
        [
            # Crafted: a block declaring 4 GiB, then 64 bytes.
            shb()
            + struct.pack("<III", 1, 0xFFFFFFFC, 0xFFFFFFFC)
            + b"\x00" * 64,
            # Edit: the real capture's first record declares 4 GiB.
            ARP_EXCHANGE_PCAP[:32]
            + struct.pack("<I", 0xFFFFFFFF)
            + ARP_EXCHANGE_PCAP[36:],
        ],
        ids=["pcapng", "pcap"],
    )
    def test_a_declared_length_past_a_file_allocates_at_most_one_read(
        self, tmp_path, data
    ):
        path = tmp_path / "capture"
        path.write_bytes(data)
        with (
            path.open("rb") as file,
            allocation_peak() as allocated,
            pytest.raises(MalformedCaptureError),
        ):
            list(read_captures(file))
        assert allocated.peak < 2 * _READ_CHUNK

    def test_a_long_stream_that_is_not_pcapng_is_counted(self):
        # Crafted: 3 MiB of zeros, longer than one read.
        data = bytes(3 * _READ_CHUNK)
        with pytest.raises(MalformedCaptureError) as excinfo:
            list(read_pcapng(ReadOnlyStream(data)))
        assert str(excinfo.value) == (
            "not a pcapng capture: does not start with a Section Header "
            f"Block (buffer holds {len(data)} bytes, magic 00000000)"
        )

    def test_an_mmap_is_read_as_a_buffer(self, tmp_path):
        path = tmp_path / "capture.pcapng"
        path.write_bytes(INTERFACES_PCAPNG)
        with (
            path.open("rb") as file,
            mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as mapped,
        ):
            mapped.seek(len(INTERFACES_PCAPNG))
            assert list(read_packets(mapped)) == list(
                read_packets(INTERFACES_PCAPNG)
            )


def _crafted_large_capture(pcapng: bool) -> tuple[bytes, int]:
    """Crafted: about 8 MiB of frames up to 65,535 bytes each, as a
    classic pcap or as one pcapng section, and its longest record or
    block."""
    frames = [
        bytes([index % 251]) * (64 + index * 977 % 65_472)
        for index in range(256)
    ]
    if not pcapng:
        records = [
            struct.pack("<IIII", index, 0, len(frame), len(frame)) + frame
            for index, frame in enumerate(frames)
        ]
        return b"\xd4\xc3\xb2\xa1" + bytes(20) + b"".join(records), max(
            map(len, records)
        )
    blocks = [epb(0, index, frame) for index, frame in enumerate(frames)]
    return shb() + idb() + b"".join(blocks), max(map(len, blocks))


class TestStreamMemory:
    """Reading a stream holds about one record or block at a time.

    The captures are crafted (see :func:`_crafted_large_capture`).
    """

    @pytest.mark.parametrize("pcapng", [False, True], ids=["pcap", "pcapng"])
    @pytest.mark.parametrize("kind", ["BytesIO", "file"])
    def test_peak_is_a_small_multiple_of_the_longest_block(
        self, tmp_path, pcapng, kind
    ):
        data, longest = _crafted_large_capture(pcapng)
        path = tmp_path / "capture"
        path.write_bytes(data)
        with path.open("rb") as file:
            stream = io.BytesIO(data) if kind == "BytesIO" else file
            count = 0
            with allocation_peak() as allocated:
                for _ in read_packets(stream):
                    count += 1
        assert count == 256
        assert len(data) > 8_000_000
        assert allocated.peak < 4 * longest

    def test_a_memoryview_is_copied_whole(self):
        data, _ = _crafted_large_capture(False)
        view = memoryview(data)
        with allocation_peak() as allocated:
            for _ in read_packets(view):
                pass
        assert allocated.peak >= len(data)
