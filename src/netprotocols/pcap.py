"""Read classic pcap and pcapng captures from bytes, not filenames.

``read_captures`` auto-detects the format from its magic bytes and
yields :class:`CapturedFrame` — a timestamp normalized to nanoseconds
since the Unix epoch, and the frame's raw bytes, ready for
:func:`~netprotocols.decode_frame`. ``read_pcap``/``read_pcapng`` read
one known format. ``read_packets`` detects the format as
``read_captures`` does and yields :class:`CapturedPacket`, which adds
the pcapng interface a frame was captured on.

Each reader copies its input once (``bytes(buffer)``) and slices every
frame from that copy, so ``CapturedFrame.data`` is always plain
``bytes``, whether the input was ``bytes`` or a ``memoryview``. The
copy is taken when iteration starts, not on the call: a ``memoryview``
over a ``bytearray`` that is mutated between the call and the first
``next()`` is read as mutated.

``read_captures`` and ``read_packets`` check the magic number on the
call itself: a buffer too short to hold one, or one matching neither
format, raises immediately. ``read_pcap`` and ``read_pcapng`` are
generators: they check the magic number and the header after it, and
read each record or block, only as iteration reaches it. A malformed
record or block raises at that point, the frames already yielded stay
valid, and the frames are never collected into a list.

Supported pcapng block types are exactly the ones frames can come
from: Section Header (SHB), Interface Description (IDB, read only for
its ``if_tsresol`` and ``if_name`` options), Enhanced Packet (EPB),
and Simple Packet (SPB). Every other block type is skipped wholesale
— Interface Statistics, Name Resolution, Decryption Secrets, and any
vendor-specific block carry nothing :class:`CapturedFrame` can
represent.

No ``lax`` mode: a corrupt or truncated capture raises
:class:`~netprotocols.MalformedCaptureError` rather than silently
skipping the bad part.
"""

from __future__ import annotations

from collections.abc import Iterator
from struct import Struct
from typing import Literal, NamedTuple

from netprotocols.utils.exceptions import MalformedCaptureError

__all__ = [
    "CapturedFrame",
    "CapturedPacket",
    "read_captures",
    "read_packets",
    "read_pcap",
    "read_pcapng",
]

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


class CapturedPacket(NamedTuple):
    """One captured frame and the interface it was captured on.

    Yielded by :func:`read_packets`. The first two fields are
    :class:`CapturedFrame`'s.

    :param timestamp: As :class:`CapturedFrame`'s ``timestamp``.
    :param data: As :class:`CapturedFrame`'s ``data``.
    :param interface_id: The Interface ID of the pcapng Enhanced Packet
        Block the frame came from: the index, within its section, of
        the Interface Description Block that describes the interface.
        ``None`` for a frame from a pcapng Simple Packet Block, which
        records no interface, and for a classic-pcap record.
    :param interface_name: That Interface Description Block's
        ``if_name`` option, up to its first zero byte, decoded as
        UTF-8, or ``None`` when the block has no ``if_name`` or an
        empty one. When the block holds more than one non-empty
        ``if_name``, the first is used. ``None`` whenever
        ``interface_id`` is ``None``.
    """

    timestamp: int
    data: bytes
    interface_id: int | None
    interface_name: str | None


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

#: Interface Description Block options: the interface's name, and the
#: timestamp resolution of its Enhanced Packet Blocks.
_OPT_IF_NAME = 2
_OPT_IF_TSRESOL = 9
_OPT_END_OF_OPT = 0

#: if_tsresol default when an Interface Description Block omits the
#: option: microseconds, matching classic pcap's usual resolution.
_DEFAULT_TSRESOL = 6


class _Interface(NamedTuple):
    """What a section's Interface Description Block declares.

    :param interface_id: The block's index within its section, the
        Interface ID an Enhanced Packet Block names it by.
    :param tsresol: The raw ``if_tsresol`` byte.
    :param name: The first non-empty ``if_name`` value, up to its
        first zero byte, undecoded, or ``None``.
    :param name_offset: The buffer offset of ``name``'s first byte, or
        of the block when ``name`` is ``None``.
    """

    interface_id: int
    tsresol: int
    name: bytes | None
    name_offset: int


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
    yield from _read_pcapng_blocks(_pcapng_data(buffer), [None])


def _pcapng_data(buffer: bytes | memoryview) -> bytes:
    """Return a copy of a pcapng capture, checked to start with an SHB.

    :param buffer: The whole capture, starting at its first Section
        Header Block.
    :raises MalformedCaptureError: if the buffer does not start with a
        Section Header Block's type.
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
    return data


def _read_pcapng_blocks(
    data: bytes, interface_cell: list[_Interface | None]
) -> Iterator[CapturedFrame]:
    """Walk a pcapng capture's blocks, yielding each frame.

    :param data: The whole capture, starting at its first Section
        Header Block.
    :param interface_cell: A one-item list. Before each frame is
        yielded, its item is set to the :class:`_Interface` the frame's
        Enhanced Packet Block names, or to ``None`` for a Simple Packet
        Block.
    :raises MalformedCaptureError: as :func:`read_pcapng` lists,
        except for a missing first Section Header Block.
    """
    # Every caller passes data that _pcapng_data has checked starts
    # with a Section Header Block, so the loop's first iteration always
    # takes the `raw_type == _SHB_TYPE` branch and sets `endian` before
    # anything else reads it. The assert below states that invariant
    # for mypy; it never fails.
    endian: _Endian | None = None
    interfaces: list[_Interface] = []
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
            interfaces = []
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
            interfaces.append(
                _idb_interface(data, cursor, block_len, endian, len(interfaces))
            )
        elif block_type == _EPB_TYPE:
            yield _epb_frame(
                data, cursor, block_len, endian, interfaces, interface_cell
            )
        elif block_type == _SPB_TYPE:
            interface_cell[0] = None
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


def _idb_interface(
    data: bytes, block_start: int, block_len: int, endian: _Endian, index: int
) -> _Interface:
    """Return what an Interface Description Block declares.

    The first ``if_tsresol`` and the first non-empty ``if_name`` are
    read from the block's options list; an ``if_tsresol`` of length 0
    is ignored. The format default resolution is used when no
    ``if_tsresol`` is present (draft-ietf-opsawg-pcapng §4.2). An
    ``if_name`` value is cut at the end of the options list and then
    at its first zero byte; one with no bytes left is ignored.
    """
    # Block Type(4) + Block Total Length(4) + LinkType(2) + Reserved(2)
    # + SnapLen(4) = 16 bytes of fixed fields before any options.
    cursor = block_start + 16
    options_end = block_start + block_len - 4
    tsresol: int | None = None
    name: bytes | None = None
    name_offset = block_start
    while cursor + 4 <= options_end:
        code = int.from_bytes(data[cursor : cursor + 2], endian)
        length = int.from_bytes(data[cursor + 2 : cursor + 4], endian)
        if code == _OPT_END_OF_OPT:
            break
        value_start = cursor + 4
        if code == _OPT_IF_TSRESOL and length >= 1 and tsresol is None:
            tsresol = data[value_start]
        elif code == _OPT_IF_NAME and name is None:
            value = data[value_start : min(value_start + length, options_end)]
            value = value.split(b"\x00", 1)[0]
            if value:
                name = value
                name_offset = value_start
        cursor = value_start + length + (-length % 4)
    return _Interface(
        interface_id=index,
        tsresol=_DEFAULT_TSRESOL if tsresol is None else tsresol,
        name=name,
        name_offset=name_offset,
    )


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
    interfaces: list[_Interface],
    interface_cell: list[_Interface | None],
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
    if interface_id >= len(interfaces):
        raise MalformedCaptureError(
            f"pcapng Enhanced Packet Block references interface "
            f"{interface_id}, but only {len(interfaces)} "
            "Interface Description Block(s) precede it in this section",
            field="interface id",
            offset=body,
            expected=f"< {len(interfaces)}",
            actual=interface_id,
        )
    interface = interfaces[interface_id]
    interface_cell[0] = interface
    timestamp = _timestamp_ns((ts_high << 32) | ts_low, interface.tsresol)
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


def _is_pcapng(buffer: bytes | memoryview) -> bool:
    """Return whether ``buffer``'s magic number is pcapng's.

    :param buffer: The whole capture, starting at its magic number.
    :raises MalformedCaptureError: if the buffer is too short to hold a
        magic number, or its magic bytes match neither format.
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
        return False
    if magic == _SHB_TYPE:
        return True
    raise MalformedCaptureError(
        f"unrecognized capture format: magic bytes {magic.hex()}",
        field="magic",
        offset=0,
        expected="a classic pcap or pcapng magic number",
        actual=magic.hex(),
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
    if _is_pcapng(buffer):
        return read_pcapng(buffer)
    return read_pcap(buffer)


def read_packets(buffer: bytes | memoryview) -> Iterator[CapturedPacket]:
    """Read a capture with the interface each frame was captured on.

    The format is detected as :func:`read_captures` detects it, and the
    frames, timestamps and errors are the ones :func:`read_captures`
    gives, with one more error: a pcapng Enhanced Packet Block that
    references an interface whose ``if_name``, up to its first zero
    byte, is not valid UTF-8.

    :param buffer: The whole capture, starting at its magic number.
    :raises MalformedCaptureError: if the buffer is too short to hold a
        magic number, or its magic bytes match neither format, both on
        the call itself; and during iteration, for every error
        :func:`read_pcap` or :func:`read_pcapng` raises, or if an
        Enhanced Packet Block references an Interface Description Block
        whose ``if_name``, up to its first zero byte, is not valid
        UTF-8.
    """
    if _is_pcapng(buffer):
        return _read_pcapng_packets(buffer)
    return _read_pcap_packets(buffer)


def _read_pcap_packets(
    buffer: bytes | memoryview,
) -> Iterator[CapturedPacket]:
    """Read a classic pcap capture as :class:`CapturedPacket`.

    :param buffer: The whole capture, starting at its magic number.
    :raises MalformedCaptureError: as :func:`read_pcap` raises.
    """
    for timestamp, data in read_pcap(buffer):
        yield CapturedPacket(timestamp, data, None, None)


def _read_pcapng_packets(
    buffer: bytes | memoryview,
) -> Iterator[CapturedPacket]:
    """Read a pcapng capture as :class:`CapturedPacket`.

    :param buffer: The whole capture, starting at its first Section
        Header Block.
    :raises MalformedCaptureError: as :func:`read_pcapng` raises, or if
        an Enhanced Packet Block references an Interface Description
        Block whose ``if_name`` is not valid UTF-8.
    """
    interface_cell: list[_Interface | None] = [None]
    for timestamp, data in _read_pcapng_blocks(
        _pcapng_data(buffer), interface_cell
    ):
        interface = interface_cell[0]
        if interface is None:
            yield CapturedPacket(timestamp, data, None, None)
        else:
            yield CapturedPacket(
                timestamp,
                data,
                interface.interface_id,
                _interface_name(interface),
            )


def _interface_name(interface: _Interface) -> str | None:
    """Return an interface's ``if_name`` decoded as UTF-8, or ``None``.

    :param interface: The interface an Enhanced Packet Block names.
    :raises MalformedCaptureError: if the name is not valid UTF-8.
    """
    if interface.name is None:
        return None
    try:
        return interface.name.decode("utf-8")
    except UnicodeDecodeError as e:
        raise MalformedCaptureError(
            f"pcapng interface {interface.interface_id}'s if_name is not valid "
            f"UTF-8: {interface.name.hex()}",
            field="if_name",
            offset=interface.name_offset + e.start,
            expected="UTF-8",
            actual=interface.name.hex(),
        ) from e
