"""SCTP packet: the common header and its chunks (RFC 9260).

An SCTP packet is a 12-byte common header (§3.1) followed by one or more
chunks (§3.2), each a type byte, a flags byte, a 16-bit length counting
those four header bytes and the value, then the value itself, padded
with zero bytes to a multiple of 4. The padding is not counted in the
length.

SCTP has no length field of its own: like ICMP and IGMP, the packet is
the whole IP payload, and the chain walk does not trim a frame to the
IP header's declared length. Unlike them, SCTP cannot simply keep that
whole buffer: an Ethernet sender pads a frame to its 60-byte minimum,
normally with zero bytes, so every IP datagram under 46 bytes arrives
with a trailer (COOKIE ACK, SHUTDOWN, SHUTDOWN ACK, SHUTDOWN COMPLETE,
a bare ABORT), and the CRC32c checksum
(:func:`netprotocols.checksum.crc32c`) changes when zero bytes are
appended, where the internet checksum ICMPv4 and IGMP use does not.
``decode`` therefore walks the chunk headers to find where the packet
ends, and stops at a remainder made only of zero bytes that starts
where a chunk would, since that can never begin a chunk (a chunk
length below 4 is invalid), so the checksum covers exactly the
packet's bytes.

Past the 12-byte common header, ``decode`` never raises. A remainder
the walk cannot parse — a chunk cut short by a snap length, an IP
fragment or an ICMP error's quote, a length below 4, a nonzero trailer
such as an Ethernet FCS — is kept in ``chunks`` verbatim, so the ports,
verification tag and checksum still decode, and
:func:`~netprotocols.checksum.verify` returns ``False``, since the CRC
covers bytes the sender did not send or misses bytes it did. That is
the reliable signal: :attr:`SCTP.parsed_chunks` raises only when the
remainder does not walk, and a trailer that happens to (an FCS whose
bytes read as a chunk header) parses as a phantom chunk.

One sender bug the walk cannot see past: a final chunk sent without
its padding (RFC 9260 §3.2 requires it), followed by Ethernet's zero
bytes, takes up to three of those zeros as its padding, so the decoded
packet is longer than the one sent and does not verify.

The chunks are kept as raw ``bytes``, padding and all, so
``bytes(SCTP.decode(x)) == x[:header_len]`` holds by construction, even
for the nonzero padding a receiver must ignore (§3.2) and for a
remainder that does not parse. The :attr:`SCTP.parsed_chunks` accessor
splits them into :class:`SCTPChunk` objects on demand and never
re-encodes.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, hex_str
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["SCTP", "SCTPChunk"]

#: A chunk's type, flags and length (RFC 9260 §3.2).
_CHUNK_HEADER = Struct("!BBH")

#: The largest value a chunk can carry: its 16-bit length counts the
#: 4-byte chunk header too.
_MAX_VALUE_LEN = 0xFFFF - _CHUNK_HEADER.size

#: Chunk types this library names: RFC 9260 §3.2 (0-14), then the
#: extensions in common use (RFC 4895 AUTH, RFC 8260 I-DATA and
#: I-FORWARD-TSN, RFC 5061 ASCONF and ASCONF-ACK, RFC 6525 RE-CONFIG,
#: RFC 4820 PAD, RFC 3758 FORWARD-TSN). Unknown types fall back to
#: their numeric value.
_CHUNK_TYPE_NAMES: dict[int, str] = {
    0: "DATA",
    1: "INIT",
    2: "INIT ACK",
    3: "SACK",
    4: "HEARTBEAT",
    5: "HEARTBEAT ACK",
    6: "ABORT",
    7: "SHUTDOWN",
    8: "SHUTDOWN ACK",
    9: "ERROR",
    10: "COOKIE ECHO",
    11: "COOKIE ACK",
    12: "ECNE",
    13: "CWR",
    14: "SHUTDOWN COMPLETE",
    15: "AUTH",
    64: "I-DATA",
    128: "ASCONF-ACK",
    130: "RE-CONFIG",
    132: "PAD",
    192: "FORWARD-TSN",
    193: "ASCONF",
    194: "I-FORWARD-TSN",
}

#: The flag bits a chunk type defines, most significant first, as the
#: RFC draws them. DATA (RFC 9260 §3.3.1; the I bit is RFC 7053) and
#: I-DATA (RFC 8260 §2.1) carry I(mmediate), U(nordered), B(eginning
#: fragment) and E(nding fragment); ABORT (§3.3.7) and SHUTDOWN
#: COMPLETE (§3.3.13) carry T, set when the sender reflected the
#: verification tag it received, which is its own tag, instead of
#: filling in the tag its peer expects.
_DATA_FLAGS = ((0x08, "I"), (0x04, "U"), (0x02, "B"), (0x01, "E"))
_T_FLAG = ((0x01, "T"),)
_CHUNK_FLAG_NAMES: dict[int, tuple[tuple[int, str], ...]] = {
    0: _DATA_FLAGS,
    6: _T_FLAG,
    14: _T_FLAG,
    64: _DATA_FLAGS,
}


@dataclass(frozen=True, slots=True)
class SCTPChunk:
    """One SCTP chunk (RFC 9260 §3.2).

    :param type: Chunk type, ``0``-``255`` — ``0`` DATA, ``1`` INIT,
        ``2`` INIT ACK, ``3`` SACK, ``4`` HEARTBEAT, ``6`` ABORT, ``7``
        SHUTDOWN, ``10`` COOKIE ECHO, ``11`` COOKIE ACK, ... (see
        :attr:`type_name`). The two high bits say what a receiver does
        with a type it does not recognize (:attr:`unrecognized_action`).
    :param flags: Chunk flags, ``0``-``255``; their meaning depends on
        the type (see :attr:`flags_str`).
    :param value: The chunk value, kept raw, without its padding: a
        DATA chunk's TSN, stream fields, payload protocol identifier and
        user data; an INIT's fixed fields and parameters; and so on.
        At most 65531 bytes, since :attr:`length` is a 16-bit field.

    ``bytes(chunk)`` is the on-wire chunk, padded with zero bytes to a
    multiple of 4, so ``SCTP(..., chunks=b"".join(map(bytes, chunks)))``
    builds a packet from a list of them.
    """

    type: int
    flags: int = 0
    value: bytes = b""

    def __post_init__(self) -> None:
        for name, number in (("type", self.type), ("flags", self.flags)):
            if not 0 <= number <= 0xFF:
                raise InvalidFieldError(
                    f"SCTP chunk {name} must be within 0-255, got {number}",
                    protocol=type(self),
                    field=name,
                    expected="0-255",
                    actual=number,
                )
        if len(self.value) > _MAX_VALUE_LEN:
            raise InvalidFieldError(
                f"SCTP chunk value must be at most {_MAX_VALUE_LEN} bytes, "
                f"got {len(self.value)}",
                protocol=type(self),
                field="value",
                expected=f"<={_MAX_VALUE_LEN}",
                actual=len(self.value),
            )

    def __bytes__(self) -> bytes:
        return (
            _CHUNK_HEADER.pack(self.type, self.flags, self.length)
            + self.value
            + bytes(-self.length % 4)
        )

    @property
    def length(self) -> int:
        """The chunk length field: the 4-byte chunk header plus the
        value, not counting the padding (RFC 9260 §3.2)."""
        return _CHUNK_HEADER.size + len(self.value)

    @property
    def type_name(self) -> str:
        """Display name of the chunk type, e.g. ``"INIT ACK"``; falls
        back to ``"unknown (n)"`` for types this library does not
        name."""
        return _CHUNK_TYPE_NAMES.get(self.type, f"unknown ({self.type})")

    @property
    def flags_str(self) -> str:
        """Space-separated names of the flags set on the chunk, for the
        types that define any: ``"B E"`` for an unfragmented DATA chunk,
        ``"T"`` for an ABORT that carries the sender's own tag. Empty for
        other types; bits this library does not name are left out (read
        :attr:`flags` for them)."""
        return " ".join(
            name
            for bit, name in _CHUNK_FLAG_NAMES.get(self.type, ())
            if self.flags & bit
        )

    @property
    def unrecognized_action(self) -> int:
        """What a receiver does with a chunk type it does not recognize
        — the two high bits of the type (RFC 9260 §3.2): ``0`` stop
        processing the packet, discarding this chunk and every chunk
        after it (the chunks before it were already processed), ``1``
        the same and report the chunk in an ERROR chunk, ``2`` skip the
        chunk and continue, ``3`` skip it, continue, and report it."""
        return self.type >> 6


def _walk_chunks(
    raw: bytes | memoryview, start: int, protocol: type
) -> Iterator[tuple[int, int, int, int, int]]:
    """Walk the chunks in ``raw`` from ``start``, yielding ``(offset,
    type, flags, value_end, end)`` for each: ``raw[offset + 4 :
    value_end]`` is its value and ``end`` is where the next chunk
    starts, padding skipped.

    The walk ends at the end of ``raw``, or early at a remainder made
    only of zero bytes, which is link-layer padding rather than a chunk
    (a chunk length below 4 is invalid). A final chunk whose padding the
    buffer cuts short ends at the end of ``raw``. Offsets in raised
    errors are relative to ``raw``.

    :raises TruncatedHeaderError: if fewer than 4 bytes (not all zero)
        remain for a chunk header, or a chunk's length runs past
        ``raw``.
    :raises InvalidFieldError: if a chunk's length is below 4.

    Bounded: every chunk advances the walk by at least 4 bytes, so it
    never hangs or over-reads whatever ``raw`` holds. The zero-tail scan
    reads through a view, so a long trailer is not copied to be checked.
    """
    size = len(raw)
    cursor = start
    while cursor < size:
        if size - cursor < _CHUNK_HEADER.size:
            if not any(memoryview(raw)[cursor:]):
                return
            raise TruncatedHeaderError(
                f"SCTP chunk header needs {_CHUNK_HEADER.size} bytes, "
                f"{size - cursor} remain",
                protocol=protocol,
                field="chunks",
                offset=cursor,
                expected=_CHUNK_HEADER.size,
                actual=size - cursor,
            )
        type_, flags, length = _CHUNK_HEADER.unpack_from(raw, cursor)
        if length < _CHUNK_HEADER.size:
            # Checked only on the way out, so the scan runs once.
            if not any(memoryview(raw)[cursor:]):
                return
            raise InvalidFieldError(
                f"SCTP chunk length must be at least {_CHUNK_HEADER.size}, "
                f"got {length}",
                protocol=protocol,
                field="chunks",
                offset=cursor,
                expected=f">={_CHUNK_HEADER.size}",
                actual=length,
            )
        value_end = cursor + length
        if value_end > size:
            raise TruncatedHeaderError(
                f"SCTP chunk declares {length} bytes, {size - cursor} remain",
                protocol=protocol,
                field="chunks",
                offset=cursor,
                expected=length,
                actual=size - cursor,
            )
        end = min(value_end + (-length % 4), size)
        yield cursor, type_, flags, value_end, end
        cursor = end


@dataclass(frozen=True, slots=True)
class SCTP(Protocol):
    """An SCTP packet: the common header (RFC 9260 §3.1) and its chunks.

    :param src_port: Source port.
    :param dst_port: Destination port.
    :param verification_tag: Verification tag: the receiver's initiate
        tag, ``0`` on a packet carrying an INIT, or the sender's own tag
        on an ABORT or SHUTDOWN COMPLETE with the T flag set.
    :param checksum: The CRC32c checksum field, read as a big-endian
        integer from its four wire bytes and carried verbatim; compute
        and verify it with :mod:`netprotocols.checksum`.
    :param chunks: The chunks as raw bytes, each chunk's padding
        included. Parsed on demand via :attr:`parsed_chunks`.
    """

    src_port: int
    dst_port: int
    verification_tag: int
    checksum: int
    chunks: bytes = b""

    _struct: ClassVar[Struct] = Struct("!HHII")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the common header and the chunks after it.

        The chunk headers are walked to find where the packet ends; a
        run of zero bytes where the next chunk would start is left
        undecoded as link-layer padding. A remainder the walk cannot
        parse is kept in :attr:`chunks` as is, so past the common header
        this never raises (see the module docstring).

        :raises TruncatedHeaderError: if ``data`` is shorter than the
            12-byte common header.
        """
        src_port, dst_port, verification_tag, checksum = cls._unpack_fixed(data)
        end = cls._struct.size
        try:
            for *_, chunk_end in _walk_chunks(data, end, cls):
                end = chunk_end
        except (TruncatedHeaderError, InvalidFieldError):
            # Unwalkable: keep the rest verbatim, for parsed_chunks to
            # report and verify() to reject.
            end = len(data)
        return cls(
            src_port=src_port,
            dst_port=dst_port,
            verification_tag=verification_tag,
            checksum=checksum,
            chunks=bytes(data[cls._struct.size : end]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(
                self.src_port,
                self.dst_port,
                self.verification_tag,
                self.checksum,
            )
            + self.chunks
        )

    @property
    def header_len(self) -> int:
        # The chunks are the whole packet: SCTP is terminal here.
        return self._struct.size + len(self.chunks)

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x3a93ccd7"``."""
        return hex_str(self.checksum, 10)

    @property
    def verification_tag_hex_str(self) -> str:
        """The verification tag as a hexadecimal string, e.g.
        ``"0x7324d044"``."""
        return hex_str(self.verification_tag, 10)

    @property
    def parsed_chunks(self) -> tuple[SCTPChunk, ...]:
        """The chunks as a tuple of :class:`SCTPChunk`, in wire order,
        parsed on demand (RFC 9260 §3.2); their padding is dropped. A
        trailing run of zero bytes is padding and yields no chunk.

        Raises when :attr:`chunks` does not walk: on a decoded instance,
        that is a remainder :meth:`decode` kept verbatim because it
        could not parse it (a packet cut short, a nonzero trailer).
        Errors name ``field="chunks"`` with an ``offset`` relative to
        :attr:`chunks`.

        :raises TruncatedHeaderError: if :attr:`chunks` ends inside a
            chunk header or a chunk's declared length.
        :raises InvalidFieldError: if a chunk's length is below 4.
        """
        raw = self.chunks
        return tuple(
            SCTPChunk(
                type_, flags, raw[offset + _CHUNK_HEADER.size : value_end]
            )
            for offset, type_, flags, value_end, _ in _walk_chunks(
                raw, 0, type(self)
            )
        )
