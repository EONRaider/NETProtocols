"""Read classic pcap and pcapng captures from bytes, not filenames.

``read_captures`` auto-detects the format from its magic bytes and
yields :class:`CapturedFrame` — a timestamp normalized to nanoseconds
since the Unix epoch, and the frame's raw bytes, ready for
:func:`~netprotocols.decode_frame`. ``read_pcap``/``read_pcapng`` read
one known format.

Each reader copies its input once (``bytes(buffer)``) and slices every
frame from that copy, so ``CapturedFrame.data`` is always plain
``bytes``, whether the input was ``bytes`` or a ``memoryview``. The
copy is taken when iteration starts, not on the call: a ``memoryview``
over a ``bytearray`` that is mutated between the call and the first
``next()`` is read as mutated.

``read_captures`` checks the magic number on the call itself: a buffer
too short to hold one, or one matching neither format, raises
immediately. ``read_pcap`` and ``read_pcapng`` are generators: they
check the magic number and the header after it, and read each record
or block, only as iteration reaches it. A malformed record or block
raises at that point, the frames already yielded stay valid, and the
frames are never collected into a list.

Supported pcapng block types are exactly the ones frames can come
from: Section Header (SHB), Interface Description (IDB, read only for
its ``if_tsresol`` option), Enhanced Packet (EPB), and Simple Packet
(SPB). Every other block type is skipped wholesale — Interface
Statistics, Name Resolution, Decryption Secrets, and any vendor-
specific block carry nothing :class:`CapturedFrame` can represent.

No ``lax`` mode: a corrupt or truncated capture raises
:class:`~netprotocols.MalformedCaptureError` rather than silently
skipping the bad part.
"""

from __future__ import annotations

from collections.abc import Iterator
from struct import Struct
from typing import Literal, NamedTuple

from netprotocols.utils.exceptions import MalformedCaptureError

__all__ = ["CapturedFrame", "read_captures", "read_pcap", "read_pcapng"]

#: Byte order, spelled the way ``int.from_bytes``/``struct.Struct``
#: want it — both formats fix their byte order per capture (pcap) or
#: per section (pcapng), decided once from a magic number.
_Endian = Literal["little", "big"]


class CapturedFrame(NamedTuple):
    """One captured frame.

    A :class:`typing.NamedTuple`, like :class:`~netprotocols.FlowKey`:
    a value read from a capture, with no ``decode()`` or ``__bytes__``
    of its own.

    :param timestamp: Nanoseconds since the Unix epoch, normalized from
        whatever resolution the source recorded — classic pcap's
        microseconds or nanoseconds (from its magic number), or
        pcapng's per-interface ``if_tsresol``-scaled Enhanced Packet
        Block timestamp. A pcapng Simple Packet Block carries no
        timestamp at all (the block format has none): its frames
        report ``0`` here, not a guess.
    :param data: The captured bytes, from the first byte of the
        captured frame. Shorter than the original frame on the wire
        when the capture's snapshot length truncated it; pass it to
        :func:`~netprotocols.decode_frame` as any other possibly
        truncated buffer. Always plain ``bytes``, whether the source
        buffer was ``bytes`` or a ``memoryview`` (see the module
        docstring).
    """

    timestamp: int
    data: bytes


# -- classic pcap (https://www.tcpdump.org/manpages/pcap-savefile.5.html) --

#: Magic numbers: {byte-order, timestamp resolution} x {big, little}.
_PCAP_MAGIC_US_BE = b"\xa1\xb2\xc3\xd4"
_PCAP_MAGIC_US_LE = b"\xd4\xc3\xb2\xa1"
_PCAP_MAGIC_NS_BE = b"\xa1\xb2\x3c\x4d"
_PCAP_MAGIC_NS_LE = b"\x4d\x3c\xb2\xa1"

#: Global header, after the 4-byte magic already used to pick an
#: endianness: version major/minor, thiszone, sigfigs, snaplen,
#: network (linktype). None of these six fields affect frame
#: extraction, but the header must still be sized past correctly.
_PCAP_GLOBAL_REST_SIZE = 20
_PCAP_GLOBAL_HEADER_SIZE = 4 + _PCAP_GLOBAL_REST_SIZE

#: Per-record header: ts_sec, ts_frac (usec or nsec, by magic),
#: incl_len (captured length), orig_len (original on-wire length,
#: unused — CapturedFrame reports what was actually captured).
_PCAP_RECORD_HEADER_SIZE = 16


def read_pcap(buffer: bytes | memoryview) -> Iterator[CapturedFrame]:
    """Read a classic-pcap capture.

    A generator: the magic number and global header are checked, and
    each record read, only as iteration reaches them (see the module
    docstring).

    :param buffer: The whole capture, starting at its magic number.
    :raises MalformedCaptureError: if the buffer is too short for the
        4-byte magic number; the magic number is not a classic-pcap one;
        the buffer is too short for the 24-byte global header; a
        16-byte record header runs past the buffer; or a record's
        ``incl_len`` runs past the buffer.
    """
    data = bytes(buffer)
    if len(data) < 4:
        raise MalformedCaptureError(
            f"buffer holds {len(data)} bytes, too short for a pcap "
            "magic number",
            field="magic",
            offset=0,
            expected=4,
            actual=len(data),
        )
    magic = data[:4]
    if magic in (_PCAP_MAGIC_US_BE, _PCAP_MAGIC_NS_BE):
        endian = ">"
    elif magic in (_PCAP_MAGIC_US_LE, _PCAP_MAGIC_NS_LE):
        endian = "<"
    else:
        raise MalformedCaptureError(
            f"not a classic pcap: magic bytes {magic.hex()}",
            field="magic",
            offset=0,
            expected="a1b2c3d4/a1b23c4d in either byte order",
            actual=magic.hex(),
        )
    if len(data) < _PCAP_GLOBAL_HEADER_SIZE:
        raise MalformedCaptureError(
            f"classic pcap global header needs {_PCAP_GLOBAL_HEADER_SIZE} "
            f"bytes, buffer holds {len(data)}",
            field="global header",
            offset=0,
            expected=_PCAP_GLOBAL_HEADER_SIZE,
            actual=len(data),
        )
    yield from _read_pcap_records(
        data, magic in (_PCAP_MAGIC_NS_BE, _PCAP_MAGIC_NS_LE), endian
    )


def _read_pcap_records(
    data: bytes, nanosecond_resolution: bool, endian: str
) -> Iterator[CapturedFrame]:
    record_struct = Struct(f"{endian}IIII")
    cursor = _PCAP_GLOBAL_HEADER_SIZE
    while cursor < len(data):
        if cursor + _PCAP_RECORD_HEADER_SIZE > len(data):
            raise MalformedCaptureError(
                "classic pcap record header runs past the end of the buffer",
                field="record header",
                offset=cursor,
                expected=_PCAP_RECORD_HEADER_SIZE,
                actual=len(data) - cursor,
            )
        ts_sec, ts_frac, incl_len, _orig_len = record_struct.unpack_from(
            data, cursor
        )
        cursor += _PCAP_RECORD_HEADER_SIZE
        if cursor + incl_len > len(data):
            raise MalformedCaptureError(
                "classic pcap record declares more captured bytes than "
                "the buffer holds",
                field="incl_len",
                offset=cursor - _PCAP_RECORD_HEADER_SIZE,
                expected=incl_len,
                actual=len(data) - cursor,
            )
        timestamp = ts_sec * 1_000_000_000 + (
            ts_frac if nanosecond_resolution else ts_frac * 1_000
        )
        yield CapturedFrame(
            timestamp=timestamp, data=data[cursor : cursor + incl_len]
        )
        cursor += incl_len


# -- pcapng --
# https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-03.html

#: Section Header Block's own type field. Its byte pattern (0a 0d 0d
#: 0a) is a palindrome, so it reads identically as big- or little-
#: endian — the one block type identifiable before an endianness is
#: known, which is exactly what makes it usable as a section boundary.
_SHB_TYPE = b"\x0a\x0d\x0d\x0a"
_SHB_MAGIC_BE = 0x1A2B3C4D

_IDB_TYPE = 0x00000001
_EPB_TYPE = 0x00000006
_SPB_TYPE = 0x00000003

#: Interface Description Block option carrying the timestamp
#: resolution of that interface's Enhanced Packet Blocks.
_OPT_IF_TSRESOL = 9
_OPT_END_OF_OPT = 0

#: if_tsresol default when an Interface Description Block omits the
#: option: microseconds, matching classic pcap's usual resolution.
_DEFAULT_TSRESOL = 6


def read_pcapng(buffer: bytes | memoryview) -> Iterator[CapturedFrame]:
    """Read a pcapng capture.

    A generator: the first Section Header Block is checked, and each
    block read, only as iteration reaches it. The module docstring
    lists the block types read.

    A buffer may hold multiple concatenated sections (each starting
    with its own Section Header Block); each section's byte order and
    interface list are independent of any that came before it, exactly
    as the format specifies.

    :param buffer: The whole capture, starting at its first Section
        Header Block.
    :raises MalformedCaptureError: if the buffer does not start with a
        Section Header Block's type; an 8-byte block header runs past
        the buffer; a Section Header Block is too short for its
        byte-order magic, or that magic is unrecognized; a block's total
        length is below 12 or not a multiple of 4, runs past the buffer,
        or disagrees with its trailing copy; an Enhanced Packet Block is
        shorter than 32 bytes, declares more captured bytes than it
        holds, or references an interface no Interface Description Block
        in its section has declared yet; or a Simple Packet Block is
        shorter than 16 bytes.
    """
    data = bytes(buffer)
    if len(data) < 4 or data[:4] != _SHB_TYPE:
        raise MalformedCaptureError(
            "not a pcapng capture: does not start with a Section Header "
            f"Block (buffer holds {len(data)} bytes"
            + (f", magic {data[:4].hex()}" if len(data) >= 4 else "")
            + ")",
            field="block type",
            offset=0,
            expected=_SHB_TYPE.hex(),
            actual=data[:4].hex() if len(data) >= 4 else data.hex(),
        )
    yield from _read_pcapng_blocks(data)


def _read_pcapng_blocks(data: bytes) -> Iterator[CapturedFrame]:
    # read_pcapng checks that data starts with a Section Header Block
    # before calling this, so the loop's first iteration always takes
    # the `raw_type == _SHB_TYPE` branch and sets `endian` before
    # anything else reads it. The assert below states that invariant
    # for mypy; it never fails.
    endian: _Endian | None = None
    tsresol_by_interface: list[int] = []
    cursor = 0
    while cursor < len(data):
        if cursor + 8 > len(data):
            raise MalformedCaptureError(
                "pcapng block header runs past the end of the buffer",
                field="block header",
                offset=cursor,
                expected=8,
                actual=len(data) - cursor,
            )
        raw_type = data[cursor : cursor + 4]
        if raw_type == _SHB_TYPE:
            endian = _detect_shb_endian(data, cursor)
            tsresol_by_interface = []
            block_type: bytes | int = _SHB_TYPE
        else:
            assert endian is not None
            block_type = int.from_bytes(raw_type, endian)

        block_len = int.from_bytes(data[cursor + 4 : cursor + 8], endian)
        if block_len < 12 or block_len % 4:
            raise MalformedCaptureError(
                "pcapng block length must be at least 12 and a multiple "
                f"of 4, got {block_len}",
                field="block total length",
                offset=cursor + 4,
                expected="a multiple of 4, >= 12",
                actual=block_len,
            )
        if cursor + block_len > len(data):
            raise MalformedCaptureError(
                "pcapng block declares more bytes than the buffer holds",
                field="block total length",
                offset=cursor + 4,
                expected=block_len,
                actual=len(data) - cursor,
            )
        trailing_len = int.from_bytes(
            data[cursor + block_len - 4 : cursor + block_len], endian
        )
        if trailing_len != block_len:
            raise MalformedCaptureError(
                "pcapng block's trailing length disagrees with its "
                f"leading length ({trailing_len} != {block_len})",
                field="block total length",
                offset=cursor + block_len - 4,
                expected=block_len,
                actual=trailing_len,
            )

        if block_type == _IDB_TYPE:
            tsresol_by_interface.append(
                _idb_tsresol(data, cursor, block_len, endian)
            )
        elif block_type == _EPB_TYPE:
            yield _epb_frame(
                data, cursor, block_len, endian, tsresol_by_interface
            )
        elif block_type == _SPB_TYPE:
            yield _spb_frame(data, cursor, block_len, endian)
        # Every other block type (Interface Statistics, Name
        # Resolution, Decryption Secrets, Custom, ...) is skipped
        # wholesale — see the module docstring.

        cursor += block_len


def _detect_shb_endian(data: bytes, block_start: int) -> _Endian:
    if block_start + 12 > len(data):
        raise MalformedCaptureError(
            "pcapng Section Header Block is too short for its byte-order magic",
            field="byte-order magic",
            offset=block_start,
            expected=12,
            actual=len(data) - block_start,
        )
    magic_bytes = data[block_start + 8 : block_start + 12]
    if int.from_bytes(magic_bytes, "big") == _SHB_MAGIC_BE:
        return "big"
    if int.from_bytes(magic_bytes, "little") == _SHB_MAGIC_BE:
        return "little"
    raise MalformedCaptureError(
        "pcapng Section Header Block has an unrecognized byte-order "
        f"magic: {magic_bytes.hex()}",
        field="byte-order magic",
        offset=block_start + 8,
        expected="1a2b3c4d in either byte order",
        actual=magic_bytes.hex(),
    )


def _idb_tsresol(
    data: bytes, block_start: int, block_len: int, endian: _Endian
) -> int:
    """Return the raw ``if_tsresol`` byte of an Interface Description Block.

    It is read from the block's options list; the format default is
    returned if the option is absent (draft-ietf-opsawg-pcapng §4.2).
    """
    # Block Type(4) + Block Total Length(4) + LinkType(2) + Reserved(2)
    # + SnapLen(4) = 16 bytes of fixed fields before any options.
    cursor = block_start + 16
    options_end = block_start + block_len - 4
    while cursor + 4 <= options_end:
        code = int.from_bytes(data[cursor : cursor + 2], endian)
        length = int.from_bytes(data[cursor + 2 : cursor + 4], endian)
        if code == _OPT_END_OF_OPT:
            break
        value_start = cursor + 4
        if code == _OPT_IF_TSRESOL and length >= 1:
            return data[value_start]
        cursor = value_start + length + (-length % 4)
    return _DEFAULT_TSRESOL


def _timestamp_ns(raw: int, if_tsresol: int) -> int:
    """Convert an ``if_tsresol``-scaled integer timestamp to nanoseconds.

    High bit set: resolution is a negative power of 2 (the low 7 bits
    are the exponent); clear: a negative power of 10
    (draft-ietf-opsawg-pcapng §4.2).
    Integer floor division truncates any resolution finer than a
    nanosecond; no float arithmetic is involved.
    """
    if if_tsresol & 0x80:
        return (raw * 1_000_000_000) // (1 << (if_tsresol & 0x7F))
    # int(...): int**int is typed as returning Any (it can yield float
    # for a negative exponent) — if_tsresol is always >= 0 here.
    return (raw * 1_000_000_000) // int(10**if_tsresol)


def _epb_frame(
    data: bytes,
    block_start: int,
    block_len: int,
    endian: _Endian,
    tsresol_by_interface: list[int],
) -> CapturedFrame:
    # Block Type(4) + Block Total Length(4) + Interface ID(4) +
    # Timestamp High(4) + Timestamp Low(4) + Captured Packet Length(4)
    # + Original Packet Length(4) = 28 bytes of fixed fields, plus the
    # repeated Block Total Length(4) at the very end.
    if block_len < 32:
        raise MalformedCaptureError(
            "pcapng Enhanced Packet Block is too short for its fixed "
            f"fields ({block_len} < 32)",
            field="Enhanced Packet Block",
            offset=block_start,
            expected=32,
            actual=block_len,
        )
    body = block_start + 8
    interface_id = int.from_bytes(data[body : body + 4], endian)
    ts_high = int.from_bytes(data[body + 4 : body + 8], endian)
    ts_low = int.from_bytes(data[body + 8 : body + 12], endian)
    captured_len = int.from_bytes(data[body + 12 : body + 16], endian)
    packet_start = body + 20
    available = block_start + block_len - 4 - packet_start
    if captured_len > available:
        raise MalformedCaptureError(
            "pcapng Enhanced Packet Block declares more captured bytes "
            "than its block holds",
            field="captured packet length",
            offset=body + 12,
            expected=captured_len,
            actual=available,
        )
    if interface_id >= len(tsresol_by_interface):
        raise MalformedCaptureError(
            f"pcapng Enhanced Packet Block references interface "
            f"{interface_id}, but only {len(tsresol_by_interface)} "
            "Interface Description Block(s) precede it in this section",
            field="interface id",
            offset=body,
            expected=f"< {len(tsresol_by_interface)}",
            actual=interface_id,
        )
    tsresol = tsresol_by_interface[interface_id]
    timestamp = _timestamp_ns((ts_high << 32) | ts_low, tsresol)
    return CapturedFrame(
        timestamp=timestamp,
        data=data[packet_start : packet_start + captured_len],
    )


def _spb_frame(
    data: bytes, block_start: int, block_len: int, endian: _Endian
) -> CapturedFrame:
    # Simple Packet Block carries no timestamp and no interface
    # reference at all (draft-ietf-opsawg-pcapng §4.4), so
    # CapturedFrame.timestamp is 0 for these, documented on the class.
    if block_len < 16:
        raise MalformedCaptureError(
            "pcapng Simple Packet Block is too short for its fixed "
            f"fields ({block_len} < 16)",
            field="Simple Packet Block",
            offset=block_start,
            expected=16,
            actual=block_len,
        )
    original_len = int.from_bytes(
        data[block_start + 8 : block_start + 12], endian
    )
    packet_start = block_start + 12
    # The stored packet may be shorter than Original Packet Length (the
    # interface's snaplen truncated it) and the region between it and
    # the trailing length can include up to 3 padding bytes — trust
    # only whichever of the two is smaller.
    available = block_start + block_len - 4 - packet_start
    captured_len = min(original_len, available)
    return CapturedFrame(
        timestamp=0, data=data[packet_start : packet_start + captured_len]
    )


def read_captures(buffer: bytes | memoryview) -> Iterator[CapturedFrame]:
    """Read a capture, detecting classic pcap or pcapng by its magic bytes.

    :func:`read_pcap` and :func:`read_pcapng` read a known format
    without this detection.

    :param buffer: The whole capture, starting at its magic number.
    :raises MalformedCaptureError: if the buffer is too short to hold a
        magic number, or its magic bytes match neither format. These
        two are raised on the call itself; every other error, raised by
        :func:`read_pcap` or :func:`read_pcapng`, comes during
        iteration (see the module docstring).
    """
    if len(buffer) < 4:
        raise MalformedCaptureError(
            f"buffer holds {len(buffer)} bytes, too short for a capture "
            "magic number",
            field="magic",
            offset=0,
            expected=4,
            actual=len(buffer),
        )
    magic = bytes(buffer[:4])
    if magic in (
        _PCAP_MAGIC_US_BE,
        _PCAP_MAGIC_US_LE,
        _PCAP_MAGIC_NS_BE,
        _PCAP_MAGIC_NS_LE,
    ):
        return read_pcap(buffer)
    if magic == _SHB_TYPE:
        return read_pcapng(buffer)
    raise MalformedCaptureError(
        f"unrecognized capture format: magic bytes {magic.hex()}",
        field="magic",
        offset=0,
        expected="a classic pcap or pcapng magic number",
        actual=magic.hex(),
    )
