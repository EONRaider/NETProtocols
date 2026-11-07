"""SCTP packet: the common header and its chunks (RFC 9260).

An SCTP packet is a 12-byte common header (§3.1) followed by one or more
chunks (§3.2), each a type byte, a flags byte, a 16-bit length counting
those four header bytes and the value, then the value itself, padded
with zero bytes to a multiple of 4. The padding is not counted in the
length.

SCTP has no length field of its own: like ICMP and IGMP, the packet is
the whole IP payload. In a :func:`~netprotocols.decode_frame` walk the
IP header's declared length ends the buffer ``decode`` receives, so an
Ethernet sender's padding and a captured FCS are the packet's
:attr:`~netprotocols.Packet.trailer`, and the CRC32c checksum
(:func:`netprotocols.checksum.crc32c`) covers exactly the packet's
bytes.

Decoded on its own, as ``SCTP.decode(raw)``, or in a walk that no IP
length bounds (an IPv4 Total Length or IPv6 Payload Length of 0), the
buffer can run past the packet. An Ethernet sender pads a frame to its
60-byte minimum, normally with zero bytes, so every IP datagram under
46 bytes arrives with a trailer (COOKIE ACK, SHUTDOWN, SHUTDOWN ACK,
SHUTDOWN COMPLETE, a bare ABORT), and the CRC32c changes when zero bytes
are appended, where the internet checksum ICMPv4 and IGMP use does not.
For that buffer ``decode`` walks the chunk headers to find where the
packet ends, and stops at a remainder made only of zero bytes that
starts where a chunk would, since that can never begin a chunk (a chunk
length below 4 is invalid).

Past the 12-byte common header, ``decode`` never raises. A remainder
the walk cannot parse — a chunk cut short by a snap length, an IP
fragment or an ICMP error's quote, a length below 4, and, in a buffer
no IP length bounds, a nonzero trailer such as an Ethernet FCS — is
kept in ``chunks`` verbatim, so the ports, verification tag and
checksum still decode, and :func:`~netprotocols.checksum.verify`
returns ``False``, since the CRC covers bytes the sender did not send
or misses bytes it did. That is the reliable signal:
:attr:`SCTP.parsed_chunks` raises only when the remainder does not
walk, and a trailer that happens to (an FCS whose bytes read as a chunk
header) parses as a phantom chunk.

One sender bug the zero-byte scan cannot see past, in a buffer no IP
length bounds: a final chunk sent without its padding (RFC 9260 §3.2
requires it), followed by Ethernet's zero bytes, takes up to three of
those zeros as its padding, so the decoded packet is longer than the
one sent and does not verify.

The chunks are kept as raw ``bytes``, padding and all, so
``bytes(SCTP.decode(x)) == x[:header_len]`` holds by construction, even
for the nonzero padding a receiver must ignore (§3.2) and for a
remainder that does not parse. The :attr:`SCTP.parsed_chunks` accessor
splits them into :class:`SCTPChunk` objects on demand and never
re-encodes. The typed accessors of :class:`SCTPChunk` read the fields
of DATA, INIT, INIT ACK, SACK and I-DATA chunks, and the parameters of
INIT and INIT ACK as :class:`SCTPParameter` objects.

A :func:`~netprotocols.decode_frame` walk ends at SCTP, whose
:meth:`~netprotocols._base.Protocol.next_protocol` answers ``None``.
One packet can carry several DATA chunks, each with its own Payload
Protocol Identifier, and a user message can span several chunks.
:meth:`SCTPChunk.decode_user_data` decodes the user data of one
unfragmented DATA or I-DATA chunk through the ``sctp.ppid`` dispatch
table, and reassembling a fragmented message is the caller's.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, NoReturn, Self, cast

from netprotocols._base import Protocol, hex_str
from netprotocols._tlv import walk_kind_length_value
from netprotocols.registry import DEFAULT, TABLE_SCTP_PPID, Registry
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["SCTP", "SCTPChunk", "SCTPParameter"]

#: A chunk's type, flags and length (RFC 9260 §3.2).
_CHUNK_HEADER = Struct("!BBH")

#: The largest value a chunk can carry: its 16-bit length counts the
#: 4-byte chunk header too.
_MAX_VALUE_LEN = 0xFFFF - _CHUNK_HEADER.size

#: A parameter's type and length (RFC 9260 §3.2.1).
_PARAMETER_HEADER = Struct("!HH")

#: The largest value a parameter can carry: its 16-bit length counts the
#: 4-byte parameter header too.
_MAX_PARAMETER_VALUE_LEN = 0xFFFF - _PARAMETER_HEADER.size

#: The chunk types the typed accessors read (RFC 9260 §3.3.1-3.3.4,
#: RFC 8260 §2.1).
_DATA = 0
_INIT = 1
_INIT_ACK = 2
_SACK = 3
_I_DATA = 64

#: The I, U, B and E flag bits of DATA and I-DATA chunks.
_I_BIT = 0x08
_U_BIT = 0x04
_B_BIT = 0x02
_E_BIT = 0x01

#: The fixed fields before the parameters of an INIT or INIT ACK, and
#: before the Gap Ack Blocks of a SACK.
_INIT_FIXED_LEN = 16
_SACK_FIXED_LEN = 12

#: Where the user data starts in a DATA and in an I-DATA chunk's value.
_DATA_USER_DATA = 12
_I_DATA_USER_DATA = 16

#: The user data's start by chunk type, for the types that carry it.
_USER_DATA_START: dict[int, int] = {
    _DATA: _DATA_USER_DATA,
    _I_DATA: _I_DATA_USER_DATA,
}

#: The State Cookie parameter type (RFC 9260 §3.3.3.1.1).
_STATE_COOKIE = 7

#: The flat ``sctp.ppid`` table of the default registry, bound once at
#: import. Registering a decoder mutates this dict in place, so the
#: reference stays live (see :mod:`netprotocols.registry`).
_PPID_CLASSES: dict[int, type[Protocol]] = DEFAULT.table(TABLE_SCTP_PPID)

#: Parameter types this library names: RFC 9260 §3.3.2.1 and §3.3.3.1,
#: then the extensions an INIT or INIT ACK commonly carries (RFC 4895
#: Random, Chunk List and Requested HMAC Algorithm, RFC 4820 Padding,
#: RFC 5061 Supported Extensions and Adaptation Layer Indication, RFC
#: 3758 Forward-TSN-Supported, RFC 9653 Zero Checksum Acceptable).
#: Unknown types read ``"unknown (n)"``.
_PARAMETER_TYPE_NAMES: dict[int, str] = {
    5: "IPv4 Address",
    6: "IPv6 Address",
    7: "State Cookie",
    8: "Unrecognized Parameter",
    9: "Cookie Preservative",
    11: "Host Name Address",
    12: "Supported Address Types",
    0x8000: "ECN Capable",
    0x8001: "Zero Checksum Acceptable",
    0x8002: "Random",
    0x8003: "Chunk List",
    0x8004: "Requested HMAC Algorithm",
    0x8005: "Padding",
    0x8008: "Supported Extensions",
    0xC000: "Forward-TSN-Supported",
    0xC006: "Adaptation Layer Indication",
}

#: Chunk types this library names: RFC 9260 §3.2 (0-14), then the
#: extensions in common use (RFC 4895 AUTH, RFC 8260 I-DATA and
#: I-FORWARD-TSN, RFC 5061 ASCONF and ASCONF-ACK, RFC 6525 RE-CONFIG,
#: RFC 4820 PAD, RFC 3758 FORWARD-TSN). Unknown types read
#: ``"unknown (n)"``.
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
class SCTPParameter:
    """One optional or variable-length parameter (RFC 9260 §3.2.1).

    INIT and INIT ACK chunks carry them after their fixed fields
    (:attr:`SCTPChunk.parameters`).

    :param type: Parameter type, ``0``-``65535`` — ``5`` IPv4 Address,
        ``6`` IPv6 Address, ``7`` State Cookie, ``9`` Cookie
        Preservative, ``12`` Supported Address Types, ... (see
        :attr:`type_name`).
    :param value: The parameter value, kept raw, without its padding.
        At most 65531 bytes, since :attr:`length` is a 16-bit field.

    ``bytes(parameter)`` is the on-wire parameter, padded with zero
    bytes to a multiple of 4.
    """

    type: int
    value: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.type <= 0xFFFF:
            raise InvalidFieldError(
                f"SCTP parameter type must be within 0-65535, got {self.type}",
                protocol=type(self),
                field="type",
                expected="0-65535",
                actual=self.type,
            )
        if len(self.value) > _MAX_PARAMETER_VALUE_LEN:
            raise InvalidFieldError(
                "SCTP parameter value must be at most "
                f"{_MAX_PARAMETER_VALUE_LEN} bytes, got {len(self.value)}",
                protocol=type(self),
                field="value",
                expected=f"<={_MAX_PARAMETER_VALUE_LEN}",
                actual=len(self.value),
            )

    def __bytes__(self) -> bytes:
        return (
            _PARAMETER_HEADER.pack(self.type, self.length)
            + self.value
            + bytes(-self.length % 4)
        )

    @property
    def length(self) -> int:
        """The parameter length field (RFC 9260 §3.2.1).

        It counts the 4-byte parameter header and the value, not the
        padding.
        """
        return _PARAMETER_HEADER.size + len(self.value)

    @property
    def type_name(self) -> str:
        """Display name of the parameter type, e.g. ``"State Cookie"``.

        ``"unknown (n)"`` for types this library does not name (degrades,
        never raises).
        """
        return _PARAMETER_TYPE_NAMES.get(self.type, f"unknown ({self.type})")


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

    Typed accessors read the fields of DATA (RFC 9260 §3.3.1), INIT
    (§3.3.2), INIT ACK (§3.3.3), SACK (§3.3.4) and I-DATA (RFC 8260
    §2.1) chunks out of :attr:`value`. Each one is ``None`` for a
    chunk of a type that has no such field, and for a value too short
    to hold it, so a field before the cut still reads from a value cut
    short. Each one but :attr:`parameters` never raises;
    :attr:`parameters` raises when the parameters after the fixed
    fields do not walk. Fields shared by several types (``tsn``,
    ``stream_id``, ``ppid``, ``user_data``, ``a_rwnd``) read each
    type's own layout.
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
        """The chunk length field (RFC 9260 §3.2).

        It counts the 4-byte chunk header and the value, not the padding.
        """
        return _CHUNK_HEADER.size + len(self.value)

    @property
    def type_name(self) -> str:
        """Display name of the chunk type, e.g. ``"INIT ACK"``.

        ``"unknown (n)"`` for types this library does not name (degrades,
        never raises).
        """
        return _CHUNK_TYPE_NAMES.get(self.type, f"unknown ({self.type})")

    @property
    def flags_str(self) -> str:
        """Space-separated names of the flags set on the chunk.

        ``"B E"`` for an unfragmented DATA chunk, ``"T"`` for an ABORT
        that carries the sender's own tag. Empty for types that define no
        flags; bits this library does not name are left out (read
        :attr:`flags` for them).
        """
        return " ".join(
            name
            for bit, name in _CHUNK_FLAG_NAMES.get(self.type, ())
            if self.flags & bit
        )

    @property
    def unrecognized_action(self) -> int:
        """What a receiver does with a chunk type it does not recognize.

        These are the two high bits of the type (RFC 9260 §3.2): ``0`` stop
        processing the packet, discarding this chunk and every chunk
        after it (the chunks before it were already processed), ``1``
        the same and report the chunk in an ERROR chunk, ``2`` skip the
        chunk and continue, ``3`` skip it, continue, and report it.
        """
        return self.type >> 6

    def _uint(
        self, types: tuple[int, ...], offset: int, size: int
    ) -> int | None:
        """Read a big-endian unsigned field of the value.

        :param types: The chunk types that carry the field.
        :param offset: Where the field starts in :attr:`value`.
        :param size: The field's width in bytes.
        :returns: The field, or ``None`` when :attr:`type` is not one of
            ``types`` or :attr:`value` ends before the field does.
        """
        if self.type not in types or len(self.value) < offset + size:
            return None
        return int.from_bytes(self.value[offset : offset + size])

    def _flag(self, bit: int) -> bool | None:
        """Read a DATA or I-DATA flag bit.

        :param bit: The bit's mask in :attr:`flags`.
        :returns: Whether it is set, or ``None`` for any other chunk type.
        """
        if self.type not in (_DATA, _I_DATA):
            return None
        return bool(self.flags & bit)

    @property
    def immediate(self) -> bool | None:
        """The I bit of a DATA (RFC 7053 §3) or I-DATA chunk.

        Set, it asks the receiver to send its SACK without delay.
        ``None`` for other chunk types (degrades, never raises).
        """
        return self._flag(_I_BIT)

    @property
    def unordered(self) -> bool | None:
        """The U bit of a DATA or I-DATA chunk: an unordered message.

        ``None`` for other chunk types (degrades, never raises).
        """
        return self._flag(_U_BIT)

    @property
    def beginning_fragment(self) -> bool | None:
        """The B bit of a DATA or I-DATA chunk: a message's first piece.

        Both B and E set mark an unfragmented message. ``None`` for
        other chunk types (degrades, never raises).
        """
        return self._flag(_B_BIT)

    @property
    def ending_fragment(self) -> bool | None:
        """The E bit of a DATA or I-DATA chunk: a message's last piece.

        ``None`` for other chunk types (degrades, never raises).
        """
        return self._flag(_E_BIT)

    @property
    def tsn(self) -> int | None:
        """The TSN of a DATA or I-DATA chunk.

        ``None`` for other chunk types and a value shorter than 4 bytes
        (degrades, never raises).
        """
        return self._uint((_DATA, _I_DATA), 0, 4)

    @property
    def stream_id(self) -> int | None:
        """The Stream Identifier of a DATA or I-DATA chunk.

        ``None`` for other chunk types and a value shorter than 6 bytes
        (degrades, never raises).
        """
        return self._uint((_DATA, _I_DATA), 4, 2)

    @property
    def stream_sequence_number(self) -> int | None:
        """The Stream Sequence Number of a DATA chunk.

        A receiver ignores it when the U bit is set. ``None`` for other
        chunk types, I-DATA included, and a value shorter than 8 bytes
        (degrades, never raises).
        """
        return self._uint((_DATA,), 6, 2)

    @property
    def message_id(self) -> int | None:
        """The Message Identifier (MID) of an I-DATA chunk.

        Every fragment of one user message carries the same MID.
        ``None`` for other chunk types and a value shorter than 12 bytes
        (degrades, never raises).
        """
        return self._uint((_I_DATA,), 8, 4)

    @property
    def ppid(self) -> int | None:
        """The Payload Protocol Identifier of a DATA or I-DATA chunk.

        It names the upper-layer protocol of the user data, from IANA's
        SCTP Payload Protocol Identifiers registry, read big-endian. An
        I-DATA chunk carries it only in a message's first fragment, its
        B bit set, in the place of the Fragment Sequence Number. ``None``
        for other chunk types, an I-DATA chunk with B clear, and a value
        shorter than 12 bytes (DATA) or 16 bytes (I-DATA) (degrades,
        never raises).
        """
        if self.type == _I_DATA:
            if not self.flags & _B_BIT:
                return None
            return self._uint((_I_DATA,), 12, 4)
        return self._uint((_DATA,), 8, 4)

    @property
    def fragment_sequence_number(self) -> int | None:
        """The Fragment Sequence Number (FSN) of an I-DATA chunk.

        It numbers the fragments of one message from 0. A chunk with
        the B bit clear carries it in its fifth word; a first fragment,
        B set, holds the PPID there instead, and its FSN is 0 (RFC 8260
        §2.1). ``None`` for other chunk types and a value shorter than
        16 bytes (degrades, never raises).
        """
        if self.type == _I_DATA and self.flags & _B_BIT:
            return 0 if len(self.value) >= _I_DATA_USER_DATA else None
        return self._uint((_I_DATA,), 12, 4)

    @property
    def user_data(self) -> bytes | None:
        """The user data of a DATA or I-DATA chunk, without its padding.

        A fragment's user data is that piece of the message only.
        ``None`` for other chunk types and a value shorter than the
        12-byte (DATA) or 16-byte (I-DATA) fields before the user data
        (degrades, never raises).
        """
        start = _USER_DATA_START.get(self.type)
        if start is None or len(self.value) < start:
            return None
        return self.value[start:]

    def decode_user_data(
        self, registry: Registry | None = None
    ) -> Protocol | None:
        """Decode an unfragmented message's user data by its PPID.

        The decoder is the class the ``sctp.ppid`` table holds for
        :attr:`ppid`. This library registers none there, so the table is
        empty until a caller registers one. Only a DATA or I-DATA chunk
        with both the B and E bits set carries a whole user message;
        reassembling a fragmented one is the caller's.
        :class:`~netprotocols.SCTP` names no successor layer in a
        :func:`~netprotocols.decode_frame` walk, and the walk never reads
        the ``sctp.ppid`` table, ``decode_as`` included. A caller that
        wants lax behaviour catches :class:`~netprotocols.ProtocolError`.

        :param registry: The registry whose ``sctp.ppid`` table is read;
            :data:`~netprotocols.registry.DEFAULT` when ``None``.
        :returns: The decoded user data, or ``None`` for a chunk of
            another type, a fragment, a value too short for the user
            data, and a PPID the table holds no class for or withholds
            (:data:`~netprotocols.registry.WITHHELD`).
        :raises ProtocolError: if the registered decoder rejects the user
            data, as its ``decode()`` documents.
        """
        if not (self.beginning_fragment and self.ending_fragment):
            return None
        ppid, user_data = self.ppid, self.user_data
        if ppid is None or user_data is None:
            return None
        table = (
            _PPID_CLASSES
            if registry is None
            else registry.table(TABLE_SCTP_PPID)
        )
        decoder = table.get(ppid)
        return None if decoder is None else decoder.decode(user_data)

    @property
    def initiate_tag(self) -> int | None:
        """The Initiate Tag of an INIT or INIT ACK chunk.

        The receiver of the chunk puts it in the verification tag of
        every packet it sends in the association. ``None`` for other
        chunk types and a value shorter than 4 bytes (degrades, never
        raises).
        """
        return self._uint((_INIT, _INIT_ACK), 0, 4)

    @property
    def a_rwnd(self) -> int | None:
        """The Advertised Receiver Window Credit, in bytes.

        An INIT, INIT ACK or SACK chunk carries it. ``None`` for other
        chunk types and a value shorter than 8 bytes (degrades, never
        raises).
        """
        return self._uint((_INIT, _INIT_ACK, _SACK), 4, 4)

    @property
    def outbound_streams(self) -> int | None:
        """The Number of Outbound Streams of an INIT or INIT ACK chunk.

        ``None`` for other chunk types and a value shorter than 10 bytes
        (degrades, never raises).
        """
        return self._uint((_INIT, _INIT_ACK), 8, 2)

    @property
    def inbound_streams(self) -> int | None:
        """The Number of Inbound Streams of an INIT or INIT ACK chunk.

        ``None`` for other chunk types and a value shorter than 12 bytes
        (degrades, never raises).
        """
        return self._uint((_INIT, _INIT_ACK), 10, 2)

    @property
    def initial_tsn(self) -> int | None:
        """The Initial TSN of an INIT or INIT ACK chunk.

        ``None`` for other chunk types and a value shorter than 16 bytes
        (degrades, never raises).
        """
        return self._uint((_INIT, _INIT_ACK), 12, 4)

    @property
    def parameters(self) -> tuple[SCTPParameter, ...] | None:
        """The parameters after an INIT or INIT ACK's fixed fields.

        They come in wire order, each value without its padding
        (RFC 9260 §3.2.1). ``()`` for a value of exactly the 16 fixed
        bytes. ``None`` for other chunk types and a value shorter than
        16 bytes. Padding the value ends before completing, after the
        last parameter, is accepted.

        :raises InvalidFieldError: if the parameters do not walk: a
            parameter length below 4, a length past the value, or 1-3
            bytes left over for a parameter header (``field``
            ``"value"``, ``offset`` relative to :attr:`value`; bounded,
            so it never hangs or over-reads).
        """
        if self.type not in (_INIT, _INIT_ACK):
            return None
        if len(self.value) < _INIT_FIXED_LEN:
            return None
        raw = self.value[_INIT_FIXED_LEN:]
        try:
            return tuple(
                SCTPParameter(type_, value)
                for type_, value in walk_kind_length_value(
                    raw,
                    lone_byte_kinds=frozenset(),
                    terminator_kind=None,
                    min_option_length=None,
                    length_includes_header=True,
                    protocol=SCTPChunk,
                    field="value",
                    width=2,
                    align=4,
                )
            )
        except InvalidFieldError as error:
            _raise_parameter_error(raw, cast(int, error.offset))

    @property
    def state_cookie(self) -> bytes | None:
        """The Cookie of an INIT ACK chunk's State Cookie parameter.

        The first State Cookie parameter's value (RFC 9260
        §3.3.3.1.1), which the peer echoes back in its COOKIE ECHO.
        ``None`` for other chunk types, INIT included, for parameters
        that do not walk (where :attr:`parameters` raises), and for an
        INIT ACK without a State Cookie (degrades, never raises).
        """
        if self.type != _INIT_ACK:
            return None
        try:
            parameters = self.parameters or ()
        except InvalidFieldError:
            return None
        for parameter in parameters:
            if parameter.type == _STATE_COOKIE:
                return parameter.value
        return None

    @property
    def cumulative_tsn_ack(self) -> int | None:
        """The Cumulative TSN Ack of a SACK chunk.

        ``None`` for other chunk types and a value shorter than 4 bytes
        (degrades, never raises).
        """
        return self._uint((_SACK,), 0, 4)

    @property
    def num_gap_ack_blocks(self) -> int | None:
        """The Number of Gap Ack Blocks a SACK chunk declares.

        ``None`` for other chunk types and a value shorter than 10 bytes
        (degrades, never raises).
        """
        return self._uint((_SACK,), 8, 2)

    @property
    def num_duplicate_tsns(self) -> int | None:
        """The Number of Duplicate TSNs a SACK chunk declares.

        ``None`` for other chunk types and a value shorter than 12 bytes
        (degrades, never raises).
        """
        return self._uint((_SACK,), 10, 2)

    @property
    def gap_ack_blocks(self) -> tuple[tuple[int, int], ...] | None:
        """The Gap Ack Blocks of a SACK chunk, as ``(start, end)`` pairs.

        Each is a pair of offsets from :attr:`cumulative_tsn_ack`: the
        block acknowledges the TSNs from ``cumulative_tsn_ack + start``
        to ``cumulative_tsn_ack + end``, both included. There are
        :attr:`num_gap_ack_blocks` of them. ``None`` for other chunk
        types, and for a value too short for the 12 fixed bytes and every
        block the count declares, never a partial list (degrades, never
        raises). Bytes after the declared blocks and duplicate TSNs are
        ignored.
        """
        count = self.num_gap_ack_blocks
        if count is None or len(self.value) < _SACK_FIXED_LEN + 4 * count:
            return None
        value = self.value
        return tuple(
            (
                int.from_bytes(value[at : at + 2]),
                int.from_bytes(value[at + 2 : at + 4]),
            )
            for at in range(_SACK_FIXED_LEN, _SACK_FIXED_LEN + 4 * count, 4)
        )

    @property
    def duplicate_tsns(self) -> tuple[int, ...] | None:
        """The Duplicate TSNs of a SACK chunk, in wire order.

        There are :attr:`num_duplicate_tsns` of them, after the Gap Ack
        Blocks. ``None`` for other chunk types, and for a value too short
        for the 12 fixed bytes, every declared block and every declared
        duplicate TSN, never a partial list (degrades, never raises).
        """
        blocks, count = self.num_gap_ack_blocks, self.num_duplicate_tsns
        if blocks is None or count is None:
            return None
        start = _SACK_FIXED_LEN + 4 * blocks
        if len(self.value) < start + 4 * count:
            return None
        value = self.value
        return tuple(
            int.from_bytes(value[at : at + 4])
            for at in range(start, start + 4 * count, 4)
        )


def _raise_parameter_error(raw: bytes, offset: int) -> NoReturn:
    """Raise the error for the parameter at ``offset`` that does not walk.

    The error names ``field="value"`` with an ``offset`` relative to
    :attr:`SCTPChunk.value`.

    :param raw: The parameters, the INIT or INIT ACK value after its 16
        fixed bytes.
    :param offset: Where in ``raw`` the parameter that does not walk
        starts.
    :raises InvalidFieldError: on every call, naming the failure: fewer
        than 4 bytes left for the parameter header, a parameter length
        below 4, or otherwise a parameter length past the end of ``raw``.
    """
    left = len(raw) - offset
    at = _INIT_FIXED_LEN + offset
    if left < _PARAMETER_HEADER.size:
        raise InvalidFieldError(
            f"SCTP parameter header needs {_PARAMETER_HEADER.size} bytes, "
            f"{left} remain",
            protocol=SCTPChunk,
            field="value",
            offset=at,
            expected=_PARAMETER_HEADER.size,
            actual=left,
        ) from None
    _, length = _PARAMETER_HEADER.unpack_from(raw, offset)
    if length < _PARAMETER_HEADER.size:
        raise InvalidFieldError(
            "SCTP parameter length must be at least "
            f"{_PARAMETER_HEADER.size}, got {length}",
            protocol=SCTPChunk,
            field="value",
            offset=at,
            expected=f">={_PARAMETER_HEADER.size}",
            actual=length,
        ) from None
    raise InvalidFieldError(
        f"SCTP parameter declares {length} bytes, {left} remain",
        protocol=SCTPChunk,
        field="value",
        offset=at,
        expected=length,
        actual=left,
    ) from None


def _walk_chunks(
    raw: bytes | memoryview, start: int, protocol: type
) -> Iterator[tuple[int, int, int, int, int]]:
    """Walk the chunks in ``raw`` from ``start``.

    Yields ``(offset, type, flags, value_end, end)`` for each chunk:
    ``raw[offset + 4 : value_end]`` is its value and ``end`` is where the
    next chunk starts, padding skipped.

    The walk ends at the end of ``raw``, or early at a remainder made
    only of zero bytes, which is link-layer padding rather than a chunk
    (a chunk length below 4 is invalid). A final chunk whose padding the
    buffer cuts short ends at the end of ``raw``. Offsets in raised
    errors are relative to ``raw``.

    Bounded: every chunk advances the walk by at least 4 bytes, so it
    never hangs or over-reads whatever ``raw`` holds. The zero-tail scan
    reads through a view, so a long trailer is not copied to be checked.

    :param raw: The chunk bytes to walk.
    :param start: Offset in ``raw`` of the first chunk.
    :param protocol: The class named as ``protocol`` in raised errors.
    :raises TruncatedHeaderError: if fewer than 4 bytes (not all zero)
        remain for a chunk header, or a chunk's length runs past
        ``raw``.
    :raises InvalidFieldError: if a chunk's length is below 4.
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
            # The zero-tail scan runs on two paths only: fewer than 4
            # bytes remain for a chunk header, or a chunk's length is
            # below 4. A walk of valid chunks never scans.
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

        :param data: The buffer, starting at the common header.
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
        """The whole message: the 12-byte common header and the chunks."""
        return self._struct.size + len(self.chunks)

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x3a93ccd7"``."""
        return hex_str(self.checksum, 10)

    @property
    def verification_tag_hex_str(self) -> str:
        """The verification tag as a hex string, e.g. ``"0x7324d044"``."""
        return hex_str(self.verification_tag, 10)

    @property
    def parsed_chunks(self) -> tuple[SCTPChunk, ...]:
        """The chunks as :class:`SCTPChunk` objects, in wire order.

        Parsed on demand (RFC 9260 §3.2); their padding is dropped. A
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
