"""PIM — Protocol Independent Multicast, Sparse Mode (RFC 7761).

PIM rides directly on IPv4 or IPv6 as IP protocol 103 and never chains
onward in a frame walk. Every message starts with the same 4-byte header
(RFC 7761 §4.9): a version nibble (always 2), a type nibble, a reserved
byte (RFC 9436's Flag Bits) and the checksum. :class:`PIM` models that
header as fields and keeps the rest of the message raw in ``body``, the
shape :class:`IGMP` uses; :attr:`PIM.message` dispatches on ``type`` to
a parser that reads ``body`` into a typed message:

* ``0`` Hello: :class:`PIMHello`, its option TLVs (§4.9.2) walked by the
  shared :func:`~netprotocols._tlv.walk_kind_length_value`;
* ``1`` Register: :class:`PIMRegister`, the B and N bits and the
  encapsulated data packet (§4.9.3);
* ``2`` Register-Stop: :class:`PIMRegisterStop` (§4.9.4);
* ``3`` Join/Prune: :class:`PIMJoinPrune` (§4.9.5), and ``6`` Graft and
  ``7`` Graft-Ack, which PIM-DM sends in the same format (RFC 3973
  §4.7.6-4.7.7);
* ``5`` Assert: :class:`PIMAssert` (§4.9.6).

Bootstrap (``4``), Candidate-RP-Advertisement (``8``), State Refresh
(``9``) and any other type decode with their ``body`` kept raw, and
:attr:`PIM.message` is ``None`` for them.

Addresses in the messages are Encoded-Unicast, Encoded-Group or
Encoded-Source addresses (§4.9.1), each naming its own address family
and encoding, so their width comes from the message, not from the IP
header carrying it. Native IPv4 (family ``1``) and IPv6 (family ``2``)
encodings are decoded. Any other family, or an encoding type no RFC
defines, cannot be sized, and the parser raises
:class:`InvalidFieldError` there. RFC 5384's type 1 Encoded-Source could
be sized — its join attributes are TLVs (``F``, ``E``, a 6-bit type, a
length byte, the value) ending at the one with the E bit set (§3.4.1) —
but is not supported, and the parser raises there too.

PIM has no length field of its own: like ICMP, IGMP and SCTP, the
message is the whole IP payload, and the chain walk does not trim a
frame to the IP header's declared length, so an Ethernet sender's zero
padding or a captured FCS can follow the message in the buffer
``decode`` receives. ``decode`` therefore bounds the message by its own
structure, using the same parser :attr:`PIM.message` does:

* A message whose parser knows where it ends (Register-Stop, Join/Prune,
  Graft, Graft-Ack, Assert) ends there; whatever follows is left
  undecoded, for :attr:`~netprotocols.Packet.consumed` to report.
* A Hello's options run to the end of the message, so its end is found
  by walking them: a remainder made only of zero bytes where the next
  option would start is padding and is left undecoded. Option type 0 is
  reserved, so a conforming sender never ends a Hello with an all-zero
  option. A nonzero trailer cannot be told from an option: one that
  walks (an FCS whose third and fourth bytes are zero reads as an empty
  option) is kept as a phantom option, and one that does not makes the
  remainder unwalkable (below).
* A Register's data packet, and the other types' bodies, run to the end
  of the buffer and are kept whole. A Register's checksum in the form
  §4.9.3 specifies (and FRR sends) covers only its first 8 bytes, so a
  trailer cannot break it; in the whole-message form a receiver also
  accepts, a trailer counts like any other kept byte (below).

When the parser cannot read the body (a message cut short by a snap
length, an unknown address family, a count or length that runs past
the buffer, a nonzero trailer after a Hello that does not walk), the
whole remainder is kept in ``body`` verbatim and :attr:`PIM.message`
raises. Past the 4-byte header ``decode`` never raises. The checksum
(:mod:`netprotocols.checksum`) is the signal for what the structure
cannot see, but only as far as the internet checksum sees. Over IPv4
there is no pseudo-header, so bytes kept in ``body`` or cut from it
change the checksum only by their share of the one's-complement sum,
and bytes whose share is zero are invisible: zero bytes, but also a
nonzero trailer such as ``ff ff 00 00`` after a Hello (kept as a
phantom option) or ``12 34 ed cb`` (an unwalkable remainder, so
:attr:`PIM.message` raises), both of which still verify. A trailer or
cut whose share is not zero fails. Over IPv6 the pseudo-header's length
counts the kept bytes too. A Register's checksum in its 8-byte form
says nothing about the data packet: a trailer in it, or a cut through
it, still verifies.

``bytes(PIM.decode(x)) == x[:header_len]`` holds by construction: the
header fields are packed back and ``body`` is carried verbatim. Every
typed message, option and encoded address has a ``bytes()`` of its own,
so ``PIM(type=3, body=bytes(join_prune))`` builds a message from them.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import (
    Protocol,
    bytes_to_ipv4,
    bytes_to_ipv6,
    hex_str,
    ipv4_to_bytes,
    ipv6_to_bytes,
)
from netprotocols._tlv import walk_kind_length_value
from netprotocols.layer3.ip import IPv4, IPv6
from netprotocols.packet import Packet
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    ProtocolError,
    TruncatedHeaderError,
)
from netprotocols.walk import decode_frame

__all__ = [
    "PIM",
    "PIMAssert",
    "PIMEncodedGroup",
    "PIMEncodedSource",
    "PIMEncodedUnicast",
    "PIMGroupSet",
    "PIMHello",
    "PIMHelloOption",
    "PIMJoinPrune",
    "PIMLANPruneDelay",
    "PIMRegister",
    "PIMRegisterStop",
]

#: The only PIM version carried in IP protocol 103 (RFC 7761 §4.9):
#: PIMv1 rode inside IGMP instead.
_VERSION = 2

#: Address widths by PIM address family (RFC 7761 §4.9.1; IANA Address
#: Family Numbers): 1 IPv4, 2 IPv6, both in native encoding (type 0).
_ADDRESS_LENGTHS = {1: 4, 2: 16}
_NATIVE_ENCODING = 0

#: Hello option types named by RFC 7761 §4.9.2 and the IANA registry's
#: other RFC-defined entries (RFC 3973 §4.7.5, RFC 5015 §3.7.4, RFC 5384
#: §3.4.2).
_OPTION_TYPE_NAMES: dict[int, str] = {
    1: "Holdtime",
    2: "LAN Prune Delay",
    18: "Deprecated",
    19: "DR Priority",
    20: "Generation ID",
    21: "State Refresh Capable",
    22: "Bidirectional Capable",
    24: "Address List",
    26: "Join Attribute",
}

_HOLDTIME, _LAN_PRUNE_DELAY, _DR_PRIORITY = 1, 2, 19
_GENERATION_ID, _ADDRESS_LIST = 20, 24

_UINT16 = Struct("!H")
_UINT32 = Struct("!I")
_OPTION_HEADER = Struct("!HH")
_JOIN_PRUNE_FIXED = Struct("!BBH")
_SOURCE_COUNTS = Struct("!HH")
_ASSERT_METRICS = Struct("!II")


def _check_range(
    owner: type, name: str, value: int, maximum: int, field: str | None = None
) -> None:
    """Raise unless ``0 <= value <= maximum``.

    :param name: What ``value`` is, for the message.
    :param field: The attribute at fault, when it is not ``name`` (a
        count or length derived from it).
    """
    if not 0 <= value <= maximum:
        raise InvalidFieldError(
            f"{owner.__name__} {name} must be within 0-{maximum}, got {value}",
            protocol=owner,
            field=name if field is None else field,
            expected=f"0-{maximum}",
            actual=value,
        )


def _pack_address(
    owner: type, family: int, encoding: int, address: str
) -> bytes:
    """Pack an encoded address's address, checked against its family.

    The family, the encoding and the address string are validated
    against each other.

    :raises InvalidFieldError: if the family is not IPv4 (1) or IPv6
        (2), the encoding is not native (0), or ``address`` is not an
        address of that family.
    """
    if family not in _ADDRESS_LENGTHS:
        raise InvalidFieldError(
            f"{owner.__name__} family must be 1 (IPv4) or 2 (IPv6), "
            f"got {family}",
            protocol=owner,
            field="family",
            expected="1 or 2",
            actual=family,
        )
    if encoding != _NATIVE_ENCODING:
        raise InvalidFieldError(
            f"{owner.__name__} encoding must be 0 (native), got {encoding}",
            protocol=owner,
            field="encoding",
            expected=_NATIVE_ENCODING,
            actual=encoding,
        )
    try:
        if family == 1:
            return ipv4_to_bytes(address)
        return ipv6_to_bytes(address)
    except OSError as e:
        raise InvalidFieldError(
            f"{owner.__name__} address {address!r} is not an "
            f"{'IPv4' if family == 1 else 'IPv6'} address",
            protocol=owner,
            field="address",
            actual=address,
        ) from e


@dataclass(frozen=True, slots=True)
class PIMEncodedUnicast:
    """An Encoded-Unicast address (RFC 7761 §4.9.1).

    :param family: PIM address family — ``1`` IPv4, ``2`` IPv6.
    :param encoding: Encoding type; only the native encoding, ``0``, is
        supported.
    :param address: The address, dotted-decimal or IPv6 text form.

    :raises InvalidFieldError: if the family, the encoding or the
        address is not one of the above.
    """

    family: int
    encoding: int
    address: str

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring)."""
        _pack_address(type(self), self.family, self.encoding, self.address)

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return bytes((self.family, self.encoding)) + _pack_address(
            type(self), self.family, self.encoding, self.address
        )


@dataclass(frozen=True, slots=True)
class PIMEncodedGroup:
    """An Encoded-Group address, a group or range (RFC 7761 §4.9.1).

    :param family: PIM address family — ``1`` IPv4, ``2`` IPv6.
    :param encoding: Encoding type; only the native encoding, ``0``, is
        supported.
    :param flags: The byte holding the B bit (``0x80``, bidirectional
        PIM), the reserved bits and the Z bit (``0x01``, admin scope
        zone), carried whole so reserved bits round-trip; see
        :attr:`bidirectional` and :attr:`admin_scope`.
    :param mask_len: The group range's mask length in bits; the address
        length (32 or 128) for a single group.
    :param address: The group address, dotted-decimal or IPv6 text form.

    :raises InvalidFieldError: if the family, the encoding or the
        address is not one of the above, or ``flags`` or ``mask_len`` is
        not a byte.
    """

    family: int
    encoding: int
    flags: int
    mask_len: int
    address: str

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring)."""
        _check_range(type(self), "flags", self.flags, 0xFF)
        _check_range(type(self), "mask_len", self.mask_len, 0xFF)
        _pack_address(type(self), self.family, self.encoding, self.address)

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return bytes(
            (self.family, self.encoding, self.flags, self.mask_len)
        ) + _pack_address(type(self), self.family, self.encoding, self.address)

    @property
    def bidirectional(self) -> bool:
        """Report the B bit: the range uses Bidirectional PIM (RFC 5015).

        It is zero for PIM-SM.
        """
        return bool(self.flags & 0x80)

    @property
    def admin_scope(self) -> bool:
        """Report the Z bit: the range is an admin scope zone (BSR only)."""
        return bool(self.flags & 0x01)


@dataclass(frozen=True, slots=True)
class PIMEncodedSource:
    """An Encoded-Source address (RFC 7761 §4.9.1).

    Join/Prune lists its joined and pruned sources in this form.

    :param family: PIM address family — ``1`` IPv4, ``2`` IPv6.
    :param encoding: Encoding type; only the native encoding, ``0``, is
        supported (RFC 5384's type 1, with join attributes, is not).
    :param flags: The byte holding the reserved bits and the S
        (``0x04``, sparse), W (``0x02``, wildcard) and R (``0x01``, RP
        tree) bits, carried whole so reserved bits round-trip; see
        :attr:`sparse`, :attr:`wildcard` and :attr:`rpt`.
    :param mask_len: The source's mask length in bits, the address
        length (32 or 128) by RFC 7761.
    :param address: The source address — for a (*,G) entry, the RP's —
        dotted-decimal or IPv6 text form.

    :raises InvalidFieldError: if the family, the encoding or the
        address is not one of the above, or ``flags`` or ``mask_len`` is
        not a byte.
    """

    family: int
    encoding: int
    flags: int
    mask_len: int
    address: str

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring)."""
        _check_range(type(self), "flags", self.flags, 0xFF)
        _check_range(type(self), "mask_len", self.mask_len, 0xFF)
        _pack_address(type(self), self.family, self.encoding, self.address)

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return bytes(
            (self.family, self.encoding, self.flags, self.mask_len)
        ) + _pack_address(type(self), self.family, self.encoding, self.address)

    @property
    def sparse(self) -> bool:
        """Report the S bit, set for PIM-SM (kept for PIMv1 compatibility)."""
        return bool(self.flags & 0x04)

    @property
    def wildcard(self) -> bool:
        """Report the W (WC) bit: the entry is a (*,G) entry for the RP."""
        return bool(self.flags & 0x02)

    @property
    def rpt(self) -> bool:
        """Report the R (RPT) bit: the entry applies to the RP tree."""
        return bool(self.flags & 0x01)


def _read_encoded(
    body: bytes, cursor: int, fixed: int
) -> tuple[int, int, bytes, str, int]:
    """Read the encoded address at ``body[cursor:]``.

    Its address follows ``fixed`` bytes of fixed fields, the family and
    encoding bytes first: 2 for Encoded-Unicast, 4 for Encoded-Group and
    Encoded-Source.

    :returns: ``(family, encoding, the fixed bytes after those two, the
        address string, where the address ends)``.
    :raises TruncatedHeaderError: if the address runs past ``body``.
    :raises InvalidFieldError: if the family or encoding is not native
        IPv4 or IPv6: one this library cannot size, or RFC 5384's join
        attribute encoding, which it does not support.
    """
    if cursor + fixed > len(body):
        raise TruncatedHeaderError(
            f"PIM encoded address needs {fixed} bytes before its address, "
            f"{len(body) - cursor} remain",
            protocol=PIM,
            field="body",
            offset=cursor,
            expected=fixed,
            actual=len(body) - cursor,
        )
    family, encoding = body[cursor], body[cursor + 1]
    width = _ADDRESS_LENGTHS.get(family)
    if width is None or encoding != _NATIVE_ENCODING:
        raise InvalidFieldError(
            f"PIM encoded address has family {family} and encoding "
            f"{encoding}; only native IPv4 (1, 0) and IPv6 (2, 0) are "
            f"supported",
            protocol=PIM,
            field="body",
            offset=cursor,
        )
    end = cursor + fixed + width
    if end > len(body):
        raise TruncatedHeaderError(
            f"PIM encoded address needs {fixed + width} bytes, "
            f"{len(body) - cursor} remain",
            protocol=PIM,
            field="body",
            offset=cursor,
            expected=fixed + width,
            actual=len(body) - cursor,
        )
    raw = body[cursor + fixed : end]
    address = bytes_to_ipv4(raw) if family == 1 else bytes_to_ipv6(raw)
    return family, encoding, body[cursor + 2 : cursor + fixed], address, end


def _read_unicast(body: bytes, cursor: int) -> tuple[PIMEncodedUnicast, int]:
    family, encoding, _, address, end = _read_encoded(body, cursor, 2)
    return PIMEncodedUnicast(family, encoding, address), end


def _read_group(body: bytes, cursor: int) -> tuple[PIMEncodedGroup, int]:
    family, encoding, fixed, address, end = _read_encoded(body, cursor, 4)
    return PIMEncodedGroup(family, encoding, fixed[0], fixed[1], address), end


def _read_source(body: bytes, cursor: int) -> tuple[PIMEncodedSource, int]:
    family, encoding, fixed, address, end = _read_encoded(body, cursor, 4)
    return PIMEncodedSource(family, encoding, fixed[0], fixed[1], address), end


def _need(body: bytes, cursor: int, size: int, what: str) -> None:
    """Raise unless ``size`` bytes remain in ``body`` at ``cursor``."""
    if cursor + size > len(body):
        raise TruncatedHeaderError(
            f"PIM {what} needs {size} bytes, {len(body) - cursor} remain",
            protocol=PIM,
            field="body",
            offset=cursor,
            expected=size,
            actual=len(body) - cursor,
        )


@dataclass(frozen=True, slots=True)
class PIMHelloOption:
    """One Hello option TLV (RFC 7761 §4.9.2).

    :param type: Option type, ``0``-``65535`` — ``1`` Holdtime, ``2``
        LAN Prune Delay, ``19`` DR Priority, ``20`` Generation ID,
        ``24`` Address List, ... (see :attr:`type_name`).
    :param value: The option value, kept raw; at most 65535 bytes.
        :class:`PIMHello` reads the RFC 7761 options' values.

    ``bytes(option)`` is the on-wire option: type, length, value.
    """

    type: int
    value: bytes = b""

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring)."""
        _check_range(type(self), "type", self.type, 0xFFFF)
        _check_range(
            type(self), "value length", len(self.value), 0xFFFF, "value"
        )

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return _OPTION_HEADER.pack(self.type, len(self.value)) + self.value

    @property
    def type_name(self) -> str:
        """Name the option type, e.g. ``"Generation ID"``.

        Types this library does not name read ``"unknown (n)"``.
        """
        return _OPTION_TYPE_NAMES.get(self.type, f"unknown ({self.type})")


@dataclass(frozen=True, slots=True)
class PIMLANPruneDelay:
    """The LAN Prune Delay Hello option's value (RFC 7761 §4.9.2).

    :param t: The T bit: the sender can disable Join suppression.
    :param propagation_delay: Propagation_Delay, in milliseconds (15
        bits).
    :param override_interval: Override_Interval, in milliseconds.
    """

    t: bool
    propagation_delay: int
    override_interval: int


@dataclass(frozen=True, slots=True)
class PIMHello:
    """A Hello message's options (RFC 7761 §4.9.2), in wire order.

    The properties read the options RFC 7761 defines from the first
    option of each type; each is ``None`` when the Hello does not carry
    it, and raises :class:`InvalidFieldError` when its value has the
    wrong length for its type. Unknown options are kept in
    :attr:`options` (a receiver ignores them, §4.9.2).

    :param options: The options.
    """

    options: tuple[PIMHelloOption, ...] = ()

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return b"".join(bytes(option) for option in self.options)

    def option(self, option_type: int) -> PIMHelloOption | None:
        """Return the first option of type ``option_type``, or ``None``."""
        return next((o for o in self.options if o.type == option_type), None)

    def _value(self, option_type: int, size: int | None) -> bytes | None:
        option = self.option(option_type)
        if option is None:
            return None
        if size is not None and len(option.value) != size:
            raise InvalidFieldError(
                f"PIM Hello {option.type_name} option must be {size} bytes, "
                f"got {len(option.value)}",
                protocol=PIM,
                field="body",
                expected=size,
                actual=len(option.value),
            )
        return option.value

    @property
    def holdtime(self) -> int | None:
        """Read Holdtime (option 1), in seconds.

        ``0`` says the sender is going away; ``0xffff``, never time it
        out.
        """
        value = self._value(_HOLDTIME, 2)
        return None if value is None else int.from_bytes(value)

    @property
    def lan_prune_delay(self) -> PIMLANPruneDelay | None:
        """Read LAN Prune Delay (option 2)."""
        value = self._value(_LAN_PRUNE_DELAY, 4)
        if value is None:
            return None
        delay, override = struct.unpack("!HH", value)
        return PIMLANPruneDelay(bool(delay >> 15), delay & 0x7FFF, override)

    @property
    def dr_priority(self) -> int | None:
        """Read DR Priority (option 19), a 32-bit unsigned number."""
        value = self._value(_DR_PRIORITY, 4)
        return None if value is None else int.from_bytes(value)

    @property
    def generation_id(self) -> int | None:
        """Read Generation ID (option 20).

        It is a random 32-bit value per interface, regenerated when PIM
        restarts on it.
        """
        value = self._value(_GENERATION_ID, 4)
        return None if value is None else int.from_bytes(value)

    @property
    def address_list(self) -> tuple[PIMEncodedUnicast, ...] | None:
        """Read Address List (option 24): the sender's secondary addresses.

        :raises ProtocolError: if an address does not decode or the
            last one runs past the option; the error's ``offset`` is
            relative to the option's value.
        """
        value = self._value(_ADDRESS_LIST, None)
        if value is None:
            return None
        addresses = []
        cursor = 0
        while cursor < len(value):
            address, cursor = _read_unicast(value, cursor)
            addresses.append(address)
        return tuple(addresses)


def _parse_hello(body: bytes) -> tuple[PIMHello, int]:
    """Walk a Hello's options to find where the message ends.

    A remainder of zero bytes where an option would start ends the
    message there (see the module docstring). Where the zero tail starts
    is found once, up front: testing the remainder at every option
    instead would rescan it for each empty type-0 option, quadratic in
    a Hello made of them.
    """
    options: list[PIMHelloOption] = []
    end = 0
    zero_tail = len(bytes(body).rstrip(b"\x00"))
    try:
        for option_type, value in walk_kind_length_value(
            body,
            lone_byte_kinds=frozenset(),
            terminator_kind=None,
            min_option_length=None,
            length_includes_header=False,
            protocol=PIM,
            field="body",
            width=2,
        ):
            if option_type == 0 and end >= zero_tail:
                break
            options.append(PIMHelloOption(option_type, value))
            end += _OPTION_HEADER.size + len(value)
    except InvalidFieldError:
        if end < zero_tail:
            raise
    return PIMHello(tuple(options)), end


@dataclass(frozen=True, slots=True)
class PIMRegister:
    """A Register message (RFC 7761 §4.9.3).

    It is a data packet the source's DR encapsulates to the RP.

    :param border: The B bit, deprecated: sent as 0, ignored on receipt.
    :param null_register: The N bit: a Null-Register, probing the RP;
        its packet is then a dummy IP header naming the source and
        group.
    :param reserved: Reserved2, the remaining 30 bits, carried verbatim.
    :param packet: The encapsulated packet, from its IP header, kept
        raw; :attr:`encapsulated` decodes it.
    """

    border: bool = False
    null_register: bool = False
    reserved: int = 0
    packet: bytes = b""

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring)."""
        _check_range(type(self), "reserved", self.reserved, 0x3FFFFFFF)

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        word = self.border << 31 | self.null_register << 30 | self.reserved
        return _UINT32.pack(word) + self.packet

    @property
    def encapsulated(self) -> Packet:
        """Decode :attr:`packet` as far as it goes.

        The walk is :func:`~netprotocols.decode_frame` in lax mode, from
        :class:`~netprotocols.IPv6` when its version nibble is 6 and
        from :class:`~netprotocols.IPv4` otherwise. A Null-Register's
        dummy IPv4 header names PIM but carries no PIM message, and its
        dummy IPv6 header is followed by a dummy PIM header of version 0
        (RFC 7761 §4.9.3), so either walk stops there with
        ``stopped_by`` set; so does any packet cut short.
        """
        start = IPv6 if self.packet[:1] and self.packet[0] >> 4 == 6 else IPv4
        return decode_frame(self.packet, lax=True, start=start)


def _parse_register(body: bytes) -> tuple[PIMRegister, int]:
    _need(body, 0, 4, "Register header")
    (word,) = _UINT32.unpack_from(body)
    register = PIMRegister(
        border=bool(word >> 31),
        null_register=bool(word >> 30 & 1),
        reserved=word & 0x3FFFFFFF,
        packet=body[4:],
    )
    return register, len(body)


@dataclass(frozen=True, slots=True)
class PIMRegisterStop:
    """A Register-Stop message (RFC 7761 §4.9.4).

    The RP sends it to the DR that sent a Register.

    :param group: The group of the Register's data packet.
    :param source: Its source; an all-zero address means any source.
    """

    group: PIMEncodedGroup
    source: PIMEncodedUnicast

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return bytes(self.group) + bytes(self.source)


def _parse_register_stop(body: bytes) -> tuple[PIMRegisterStop, int]:
    group, cursor = _read_group(body, 0)
    source, cursor = _read_unicast(body, cursor)
    return PIMRegisterStop(group, source), cursor


@dataclass(frozen=True, slots=True)
class PIMGroupSet:
    """One group set of a Join/Prune message (RFC 7761 §4.9.5).

    It holds a group and the sources joined and pruned for it.

    :param group: The multicast group, or range of groups.
    :param joined: Joined sources, at most 65535.
    :param pruned: Pruned sources, at most 65535.
    """

    group: PIMEncodedGroup
    joined: tuple[PIMEncodedSource, ...] = ()
    pruned: tuple[PIMEncodedSource, ...] = ()

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring)."""
        _check_range(
            type(self), "joined count", len(self.joined), 0xFFFF, "joined"
        )
        _check_range(
            type(self), "pruned count", len(self.pruned), 0xFFFF, "pruned"
        )

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return (
            bytes(self.group)
            + _SOURCE_COUNTS.pack(len(self.joined), len(self.pruned))
            + b"".join(bytes(source) for source in self.joined + self.pruned)
        )


@dataclass(frozen=True, slots=True)
class PIMJoinPrune:
    """A Join/Prune message (RFC 7761 §4.9.5).

    It is also the format of PIM-DM's Graft and Graft-Ack (RFC 3973
    §4.7.6-4.7.7).

    :param upstream_neighbor: The upstream neighbor the message is for.
    :param holdtime: How long, in seconds, the receiver keeps the state.
    :param groups: The group sets, at most 255.
    :param reserved: The reserved byte before the group count, carried
        verbatim.
    """

    upstream_neighbor: PIMEncodedUnicast
    holdtime: int
    groups: tuple[PIMGroupSet, ...] = ()
    reserved: int = 0

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring)."""
        _check_range(type(self), "holdtime", self.holdtime, 0xFFFF)
        _check_range(
            type(self), "group count", len(self.groups), 0xFF, "groups"
        )
        _check_range(type(self), "reserved", self.reserved, 0xFF)

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return (
            bytes(self.upstream_neighbor)
            + _JOIN_PRUNE_FIXED.pack(
                self.reserved, len(self.groups), self.holdtime
            )
            + b"".join(bytes(group) for group in self.groups)
        )


def _read_sources(
    body: bytes, cursor: int, count: int
) -> tuple[tuple[PIMEncodedSource, ...], int]:
    sources = []
    for _ in range(count):
        source, cursor = _read_source(body, cursor)
        sources.append(source)
    return tuple(sources), cursor


def _parse_join_prune(body: bytes) -> tuple[PIMJoinPrune, int]:
    upstream, cursor = _read_unicast(body, 0)
    _need(body, cursor, _JOIN_PRUNE_FIXED.size, "Join/Prune header")
    reserved, num_groups, holdtime = _JOIN_PRUNE_FIXED.unpack_from(body, cursor)
    cursor += _JOIN_PRUNE_FIXED.size
    groups = []
    for _ in range(num_groups):
        group, cursor = _read_group(body, cursor)
        _need(body, cursor, _SOURCE_COUNTS.size, "group set source counts")
        num_joined, num_pruned = _SOURCE_COUNTS.unpack_from(body, cursor)
        joined, cursor = _read_sources(
            body, cursor + _SOURCE_COUNTS.size, num_joined
        )
        pruned, cursor = _read_sources(body, cursor, num_pruned)
        groups.append(PIMGroupSet(group, joined, pruned))
    return PIMJoinPrune(upstream, holdtime, tuple(groups), reserved), cursor


@dataclass(frozen=True, slots=True)
class PIMAssert:
    """An Assert message (RFC 7761 §4.9.6).

    It resolves which router forwards onto a link.

    :param group: The group under contention.
    :param source: The source; zero for an Assert(*,G).
    :param rpt: The RPT bit: set for Assert(*,G), clear for
        Assert(S,G).
    :param metric_preference: The unicast routing protocol's preference
        for the route (31 bits).
    :param metric: The route's metric (32 bits).
    """

    group: PIMEncodedGroup
    source: PIMEncodedUnicast
    rpt: bool
    metric_preference: int
    metric: int

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring)."""
        _check_range(
            type(self), "metric_preference", self.metric_preference, 0x7FFFFFFF
        )
        _check_range(type(self), "metric", self.metric, 0xFFFFFFFF)

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return (
            bytes(self.group)
            + bytes(self.source)
            + _ASSERT_METRICS.pack(
                self.rpt << 31 | self.metric_preference, self.metric
            )
        )


def _parse_assert(body: bytes) -> tuple[PIMAssert, int]:
    group, cursor = _read_group(body, 0)
    source, cursor = _read_unicast(body, cursor)
    _need(body, cursor, _ASSERT_METRICS.size, "Assert metrics")
    preference, metric = _ASSERT_METRICS.unpack_from(body, cursor)
    message = PIMAssert(
        group, source, bool(preference >> 31), preference & 0x7FFFFFFF, metric
    )
    return message, cursor + _ASSERT_METRICS.size


#: A typed PIM message, as :attr:`PIM.message` returns it.
PIMMessage = PIMHello | PIMRegister | PIMRegisterStop | PIMJoinPrune | PIMAssert

#: The message-type dispatch table: each parser reads a message body and
#: returns the typed message and where in the body it ends.
_PARSERS: dict[int, Callable[[bytes], tuple[PIMMessage, int]]] = {
    0: _parse_hello,
    1: _parse_register,
    2: _parse_register_stop,
    3: _parse_join_prune,
    5: _parse_assert,
    6: _parse_join_prune,
    7: _parse_join_prune,
}


@dataclass(frozen=True, slots=True)
class PIM(Protocol):
    """A PIM message: the common header (RFC 7761 §4.9) and its body.

    :param version: PIM version; always ``2`` (RFC 7761 §4.9: PIMv1 was
        carried in IGMP, not IP protocol 103), and the default.
    :param type: Message type, ``0``-``15`` — ``0`` Hello, ``1``
        Register, ``2`` Register-Stop, ``3`` Join/Prune, ``4``
        Bootstrap, ``5`` Assert, ... (see :attr:`type_name`).
    :param reserved: Reserved byte: zero on send, ignored on receipt,
        carried verbatim. RFC 9436 (updating RFC 7761) names it Flag
        Bits and lets each type define its own: Bootstrap's No-Forward
        bit, Assert's Packed and Aggregated bits, Register-Stop's
        Packing Capability bit; none of them is decoded here.
    :param checksum: The internet checksum over the message — over the
        first 8 bytes only for a Register — with the IPv6 pseudo-header
        over IPv6, carried verbatim; compute and verify it with
        :mod:`netprotocols.checksum`.
    :param body: Everything after the 4-byte header, kept raw; parsed
        on demand by :attr:`message`.

    :raises InvalidFieldError: if ``version`` is not 2 or another field
        is out of its range.
    """

    version: int = _VERSION
    type: int = 0
    reserved: int = 0
    checksum: int = 0
    body: bytes = b""

    _struct: ClassVar[Struct] = Struct("!BBH")

    type_names: ClassVar[dict[int, str]] = {
        0: "Hello",
        1: "Register",
        2: "Register-Stop",
        3: "Join/Prune",
        4: "Bootstrap",
        5: "Assert",
        6: "Graft",
        7: "Graft-Ack",
        8: "Candidate-RP-Advertisement",
        9: "State Refresh",
        10: "DF Election",
        11: "ECMP Redirect",
        12: "PIM Flooding Mechanism",
    }

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring)."""
        if self.version != _VERSION:
            raise InvalidFieldError(
                f"PIM version must be {_VERSION}, got {self.version}",
                protocol=type(self),
                field="version",
                expected=_VERSION,
                actual=self.version,
            )
        _check_range(type(self), "type", self.type, 0x0F)
        _check_range(type(self), "reserved", self.reserved, 0xFF)
        _check_range(type(self), "checksum", self.checksum, 0xFFFF)

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the common header and the message body after it.

        The body is bounded by the message's own structure where it has
        one (see the module docstring); a body its parser cannot read is
        kept whole, so past the header this never raises.

        :raises TruncatedHeaderError: if ``data`` is shorter than the
            4-byte header.
        :raises InvalidFieldError: if the version is not 2.
        """
        version_type, reserved, checksum = cls._unpack_fixed(data)
        version, type_ = version_type >> 4, version_type & 0x0F
        if version != _VERSION:
            raise InvalidFieldError(
                f"PIM version must be {_VERSION}, got {version}",
                protocol=cls,
                field="version",
                offset=0,
                expected=_VERSION,
                actual=version,
            )
        body = bytes(data[cls._struct.size :])
        return cls(
            version=version,
            type=type_,
            reserved=reserved,
            checksum=checksum,
            body=body[: _message_end(type_, body)],
        )

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return (
            self._struct.pack(
                self.version << 4 | self.type, self.reserved, self.checksum
            )
            + self.body
        )

    @property
    def header_len(self) -> int:
        """Count the header and the body: PIM is terminal."""
        return self._struct.size + len(self.body)

    @property
    def type_name(self) -> str:
        """Name the message type, e.g. ``"Join/Prune"``.

        Types this library does not name read ``"unknown (n)"``.
        """
        return self.type_names.get(self.type, f"unknown ({self.type})")

    @property
    def checksum_hex_str(self) -> str:
        """Render the checksum in hexadecimal, e.g. ``"0xb4be"``."""
        return hex_str(self.checksum, 6)

    @property
    def message(self) -> PIMMessage | None:
        """Parse the body by message type.

        It is a :class:`PIMHello`, :class:`PIMRegister`,
        :class:`PIMRegisterStop`,
        :class:`PIMJoinPrune` (Join/Prune, Graft, Graft-Ack) or
        :class:`PIMAssert`; ``None`` for the types kept raw (Bootstrap,
        Candidate-RP-Advertisement, State Refresh, unknown types).

        Bytes past the end of the message's own structure are ignored, as
        is a Hello's zero tail. Errors name ``field="body"`` with an
        ``offset`` relative to :attr:`body`.

        :raises ProtocolError: if the body does not parse — on a decoded
            instance, only when :meth:`decode` kept it whole for that
            reason: a :class:`TruncatedHeaderError` for a message cut
            short, an :class:`InvalidFieldError` for an address family
            or encoding this library does not support, or a Hello option
            that runs past the message.
        """
        parser = _PARSERS.get(self.type)
        if parser is None:
            return None
        message, _ = parser(self.body)
        return message


def _message_end(type_: int, body: bytes) -> int:
    """Find where in ``body`` the message of type ``type_`` ends.

    That is what its parser reads, or all of ``body`` when it has no
    parser or the parser cannot read it.
    """
    parser = _PARSERS.get(type_)
    if parser is None:
        return len(body)
    try:
        _, end = parser(body)
    except ProtocolError:
        return len(body)
    return end
