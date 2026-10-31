"""STUN — Session Traversal Utilities for NAT (RFC 8489, RFC 5389).

STUN lets a host behind a NAT learn the address and port its traffic
leaves the NAT with, and is the request/response layer TURN and ICE
build on. It runs over UDP and TCP port 3478. RFC 5389 defined the
message format this module decodes, and RFC 8489 obsoletes it without
changing a bit of the header or the attribute framing; both are cited
where they say the same thing, and the differences are named where
they matter. Every message starts with a 20-byte header (RFC 8489 §5,
RFC 5389 §6)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0 0|     STUN Message Type     |         Message Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Magic Cookie                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Transaction ID (96 bits)                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

followed by Message Length bytes of attributes. One :class:`STUN`
instance is one message: the header decoded into fields, the
attributes kept raw, padding included, so ``bytes(STUN.decode(x)) ==
x[:header_len]`` holds by construction. :attr:`STUN.length` is
``len(attributes)``, not a field, so the two cannot disagree.

The message type
----------------
The 14-bit Message Type holds two values, a class and a method,
interleaved: the class's two bits sit at positions 4 and 8 of the
type, among the method's twelve (RFC 8489 §5, Figure 3)::

    0                 1
    2  3  4 5 6 7 8 9 0 1 2 3 4 5
   +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
   |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
   |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
   +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

It is kept as the one field it is on the wire, :attr:`STUN.
message_type`, and split only by accessors: :attr:`STUN.message_class`
(``0`` Request, ``1`` Indication, ``2`` Success Response, ``3`` Error
Response) and :attr:`STUN.method` (``1`` Binding, and TURN's methods),
with :attr:`STUN.message_type_name` naming the pair, e.g. ``"Binding
Success Response"`` for ``0x0101``. The two bits above it must be zero,
which tells STUN apart from the other protocols multiplexed on its
port, such as TURN's ChannelData (RFC 8656 §12.4) and RTP (RFC 7983).

The magic cookie and RFC 3489
-----------------------------
The Magic Cookie is always ``0x2112A442`` (:attr:`STUN.MAGIC_COOKIE`).
RFC 3489, the first STUN, had a 128-bit transaction ID there instead;
RFC 5389 §6 carved the cookie out of it so that a receiver can tell the
revised protocol from the classic one, and RFC 5389 §12, which RFC
8489 §11 keeps, describes how a server still answers a classic client.
:meth:`STUN.decode` verifies the cookie and rejects a message without
it (:class:`~netprotocols.InvalidFieldError`, ``field``
``"magic_cookie"``): an RFC 3489 message, whose random transaction ID
carries the cookie once in 2**32, is not decoded, and neither is
anything else on the port that merely has two zero bits on top.
``tests/fixtures/stun/stun_rfc3489.pcap`` holds a classic exchange,
which the tests walk to that rejection.

Attributes and padding
----------------------
Each attribute is a 2-byte type, a 2-byte length counting only the
value, and the value, padded to a multiple of 4 bytes; the padding is
not counted in the length, so the Message Length, which counts it, is
a multiple of 4 too (RFC 8489 §14, RFC 5389 §15). :meth:`STUN.decode`
requires that, and :attr:`STUN.parsed_attributes` walks the list with
the shared :func:`~netprotocols._tlv.walk_kind_length_value`, aligned
to 4 bytes, into :class:`STUNAttribute` objects without their padding.
What the padding holds differs between the two RFCs: RFC 5389 §15 lets
it be any value, and RFC 8489 §14 says to send zeros and ignore them on
receipt. Either way it is kept, verbatim, in :attr:`STUN.attributes`,
so a message padded with spaces, as RFC 5769's IPv4 test vector is,
re-encodes exactly. Types below ``0x8000`` are comprehension-required,
the rest comprehension-optional (:attr:`STUNAttribute.
comprehension_required`).

Addresses, and the XOR
----------------------
MAPPED-ADDRESS (``0x0001``) carries a family (``1`` IPv4, ``2`` IPv6),
a port and an address in the clear. XOR-MAPPED-ADDRESS (``0x0020``)
carries them obscured, so that a NAT rewriting addresses it finds in
payloads cannot corrupt them (RFC 8489 §14.2, RFC 5389 §15.2): the port
is XORed with the cookie's top 16 bits, an IPv4 address with the
cookie, and an IPv6 address with the cookie followed by the 12-byte
transaction ID. The un-XOR is an accessor, :attr:`STUN.
xor_mapped_address`, like the library's other display helpers, so the
wire bytes stay untouched in :attr:`STUN.attributes`; it needs the
message's cookie and transaction ID, which is why it lives on
:class:`STUN` rather than on the attribute. :meth:`STUN.xor_address`
reads any attribute in that encoding, such as TURN's XOR-PEER-ADDRESS
and XOR-RELAYED-ADDRESS, and :attr:`STUNAttribute.address` any in the
clear one, such as RFC 5780's RESPONSE-ORIGIN and OTHER-ADDRESS.

Integrity and the fingerprint
-----------------------------
MESSAGE-INTEGRITY (``0x0008``) is an HMAC-SHA1 over the message up to
it, keyed by a credential (RFC 8489 §14.5, RFC 5389 §15.4), and RFC
8489 §14.6 adds MESSAGE-INTEGRITY-SHA256 (``0x001C``). Without the key
neither can be checked, so :attr:`STUN.message_integrity` returns the
raw 20 bytes and nothing verifies them, as with IPsec's ICVs, OSPF's
digests and RIP's: ``scripts/check_fixtures.py`` verifies the corpus's
with its published test credentials instead. FINGERPRINT (``0x8028``)
needs no key: it is the CRC-32 of the message up to it, XORed with
``0x5354554E`` (:attr:`STUN.FINGERPRINT_XOR`; RFC 8489 §14.7, RFC 5389
§15.5), and it must be the last attribute. :attr:`STUN.fingerprint`
returns it, and :func:`netprotocols.checksum.compute` and
:func:`~netprotocols.checksum.verify` compute and check it, like a
checksum, which it is.

Over TCP
--------
STUN over TCP has no framing of its own: messages follow one another
in the byte stream, each bounded by its Message Length (RFC 8489
§6.2.2, RFC 5389 §7.2.2). So, as with BGP, a segment can hold several,
and :meth:`STUN.decode` records whether the bytes after its message
begin another one, a whole 8 bytes of header with the cookie in place;
:meth:`STUN.next_protocol` then names :class:`STUN` again, and the
walk decodes the next message as its own layer. Fewer than 8 bytes, or
bytes that do not begin like a message, end the walk there, with the
rest of the segment undecoded. A message the segment cuts short raises
:class:`~netprotocols.TruncatedHeaderError`, as it does over UDP when a
snap length cuts the datagram. Reassembling a stream is the caller's,
as it is for BGP and HTTP. TURN's ChannelData messages, which share a
TCP connection with STUN, end the walk at their first byte.

Each message being a layer, a segment of many is a deep chain, as it is
for BGP: Ethernet, IPv4 and TCP are three layers, and the walk's
default ``max_depth`` of :data:`~netprotocols.MAX_DEPTH` (32) leaves
room for 29 messages. A message can be a bare 20-byte header, so a
1448-byte segment can hold 72, and a strict walk of it raises
:class:`~netprotocols.MaxDepthExceededError` on valid traffic while a
lax one stops with ``packet.stopped_by`` set. A larger ``max_depth``,
or a second walk with ``decode_frame(frame[packet.consumed:],
start=STUN)``, decodes the rest, as :mod:`netprotocols.layer7.bgp`
describes. The corpus's TCP segments carry 2 messages each.

Decoding a guess
----------------
STUN is reached through ``udp.port`` and ``tcp.port`` 3478, best-effort
like every port entry, and :meth:`STUN.decode` checks everything the
header lets it check: two zero bits on top, the 32-bit cookie and a
Message Length that is a multiple of 4. Random bytes pass once in
2**36. It does not walk the attributes: a message whose header is
sound decodes, and :attr:`STUN.parsed_attributes` raises
:class:`~netprotocols.InvalidFieldError` on a malformed list, with an
``offset`` into :attr:`STUN.attributes`. The other accessors never
raise: they read the attributes up to the first malformed one, and
answer ``None`` for an attribute that is absent, or whose value is too
short or of an unknown family.

Not decoded: STUN over TLS and DTLS (port 5349), the RFC 6544 framing
ICE-TCP puts in front of each message, TURN's ChannelData, and the
attribute values not named above, which stay raw in
:class:`STUNAttribute`.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from struct import Struct
from typing import TYPE_CHECKING, ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv4, bytes_to_ipv6
from netprotocols._tlv import walk_kind_length_value
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

if TYPE_CHECKING:
    from netprotocols.registry import Registry

__all__ = ["STUN", "STUNAddress", "STUNAttribute"]

#: The Magic Cookie (RFC 8489 §5, RFC 5389 §6).
_MAGIC_COOKIE = 0x2112A442
_COOKIE_BYTES = _MAGIC_COOKIE.to_bytes(4, "big")

#: What FINGERPRINT's CRC-32 is XORed with (RFC 8489 §14.7).
_FINGERPRINT_XOR = 0x5354554E

_HEADER_LEN = 20

#: The attribute types the accessors read (IANA "STUN Attributes").
_MAPPED_ADDRESS = 0x0001
_MESSAGE_INTEGRITY = 0x0008
_ERROR_CODE = 0x0009
_UNKNOWN_ATTRIBUTES = 0x000A
_XOR_MAPPED_ADDRESS = 0x0020
_SOFTWARE = 0x8022
_FINGERPRINT = 0x8028

#: Attribute names: IANA's "STUN Attributes" registry, for RFC 8489
#: (and RFC 5389), RFC 3489's reserved ones, RFC 5780 (NAT behaviour
#: discovery), RFC 8656 (TURN), RFC 6062 (TURN over TCP) and RFC 8445
#: (ICE).
_ATTRIBUTE_NAMES: dict[int, str] = {
    _MAPPED_ADDRESS: "MAPPED-ADDRESS",
    0x0002: "RESPONSE-ADDRESS",
    0x0003: "CHANGE-REQUEST",
    0x0004: "SOURCE-ADDRESS",
    0x0005: "CHANGED-ADDRESS",
    0x0006: "USERNAME",
    0x0007: "PASSWORD",
    _MESSAGE_INTEGRITY: "MESSAGE-INTEGRITY",
    _ERROR_CODE: "ERROR-CODE",
    _UNKNOWN_ATTRIBUTES: "UNKNOWN-ATTRIBUTES",
    0x000B: "REFLECTED-FROM",
    0x000C: "CHANNEL-NUMBER",
    0x000D: "LIFETIME",
    0x0012: "XOR-PEER-ADDRESS",
    0x0013: "DATA",
    0x0014: "REALM",
    0x0015: "NONCE",
    0x0016: "XOR-RELAYED-ADDRESS",
    0x0017: "REQUESTED-ADDRESS-FAMILY",
    0x0018: "EVEN-PORT",
    0x0019: "REQUESTED-TRANSPORT",
    0x001A: "DONT-FRAGMENT",
    0x001C: "MESSAGE-INTEGRITY-SHA256",
    0x001D: "PASSWORD-ALGORITHM",
    0x001E: "USERHASH",
    _XOR_MAPPED_ADDRESS: "XOR-MAPPED-ADDRESS",
    0x0022: "RESERVATION-TOKEN",
    0x0024: "PRIORITY",
    0x0025: "USE-CANDIDATE",
    0x0026: "PADDING",
    0x0027: "RESPONSE-PORT",
    0x002A: "CONNECTION-ID",
    0x8000: "ADDITIONAL-ADDRESS-FAMILY",
    0x8001: "ADDRESS-ERROR-CODE",
    0x8002: "PASSWORD-ALGORITHMS",
    0x8003: "ALTERNATE-DOMAIN",
    0x8004: "ICMP",
    _SOFTWARE: "SOFTWARE",
    0x8023: "ALTERNATE-SERVER",
    0x8027: "CACHE-TIMEOUT",
    _FINGERPRINT: "FINGERPRINT",
    0x8029: "ICE-CONTROLLED",
    0x802A: "ICE-CONTROLLING",
    0x802B: "RESPONSE-ORIGIN",
    0x802C: "OTHER-ADDRESS",
}

#: Methods: IANA's "STUN Methods" registry (RFC 8489 Binding; RFC 8656
#: TURN; RFC 6062 TURN over TCP). 0x002 was RFC 3489's Shared Secret
#: and is reserved since RFC 5389.
_METHOD_NAMES: dict[int, str] = {
    0x001: "Binding",
    0x003: "Allocate",
    0x004: "Refresh",
    0x006: "Send",
    0x007: "Data",
    0x008: "CreatePermission",
    0x009: "ChannelBind",
    0x00A: "Connect",
    0x00B: "ConnectionBind",
    0x00C: "ConnectionAttempt",
}

#: The four classes (RFC 8489 §5).
_CLASS_NAMES = ("Request", "Indication", "Success Response", "Error Response")

#: Address families in an address attribute (RFC 8489 §14.1), with
#: each one's address length.
_FAMILIES: dict[int, tuple[str, int]] = {1: ("IPv4", 4), 2: ("IPv6", 16)}


def _check_width(owner: type, name: str, value: int, bits: int) -> None:
    """Raise :class:`InvalidFieldError` unless ``value`` fits ``bits``."""
    top = (1 << bits) - 1
    if not 0 <= value <= top:
        raise InvalidFieldError(
            f"{owner.__name__} {name} must be within 0-{top:#x}, got {value}",
            protocol=owner,
            field=name,
            expected=f"0-{top:#x}",
            actual=value,
        )


def _check_length(owner: type, name: str, value: bytes) -> None:
    """Raise :class:`InvalidFieldError` unless ``value`` fits a 16-bit
    length field."""
    if len(value) > 0xFFFF:
        raise InvalidFieldError(
            f"{owner.__name__} {name} must be at most 65535 bytes, "
            f"got {len(value)}",
            protocol=owner,
            field=name,
            expected="<=65535",
            actual=len(value),
        )


def _text(value: bytes) -> str:
    """Read a text attribute's value: UTF-8 (RFC 8489 §14.8, §14.14),
    any undecodable byte replaced, and trailing NUL bytes dropped.

    Those NULs are padding some senders count into the value: coturn
    4.6.1 pads its error reason phrases that way, and the SOFTWARE it
    sends an RFC 3489 client.
    """
    return value.rstrip(b"\x00").decode("utf-8", "replace")


@dataclass(frozen=True, slots=True)
class STUNAddress:
    """An address and port from an address attribute, in the clear.

    :param family: ``1`` IPv4 or ``2`` IPv6 (RFC 8489 §14.1).
    :param port: The port.
    :param address: The address, dotted-decimal or RFC 5952 text.
    """

    family: int
    port: int
    address: str

    @property
    def family_name(self) -> str:
        """Name the family: ``"IPv4"`` or ``"IPv6"``.

        Falls back to ``"unknown (n)"`` for a family built here that no
        address attribute carries.
        """
        known = _FAMILIES.get(self.family)
        return f"unknown ({self.family})" if known is None else known[0]


def _parse_address(value: bytes, mask: bytes) -> STUNAddress | None:
    """Read an address attribute's value, XORing it with ``mask``.

    The value is a reserved byte, the family, the port and the address
    (RFC 8489 §14.1). ``mask`` is XORed over the port's 2 bytes and the
    address's 4 or 16, and is all zero for an address in the clear.
    ``None`` for a value of an unknown family, or the wrong length for
    its own.
    """
    known = _FAMILIES.get(value[1]) if len(value) > 1 else None
    if known is None or len(value) != 4 + known[1]:
        return None
    clear = bytes(a ^ b for a, b in zip(value[2:], mask, strict=False))
    render = bytes_to_ipv4 if value[1] == 1 else bytes_to_ipv6
    return STUNAddress(value[1], int.from_bytes(clear[:2]), render(clear[2:]))


@dataclass(frozen=True, slots=True)
class STUNAttribute:
    """One attribute (RFC 8489 §14), its value without padding.

    :param type: The attribute type; see :attr:`type_name`.
    :param value: The value, as long as its Length says.

    ``bytes(attribute)`` is the on-wire attribute, padded with zeros to
    a multiple of 4 bytes as RFC 8489 §14 sends it, so ``STUN(...,
    attributes=b"".join(map(bytes, attributes)))`` builds a message.
    """

    type: int
    value: bytes = b""

    def __post_init__(self) -> None:
        """Check the type's width and the value's length."""
        _check_width(type(self), "type", self.type, 16)
        _check_length(type(self), "value", self.value)

    def __bytes__(self) -> bytes:
        """Serialize the attribute, its value padded to 4 bytes."""
        return (
            self.type.to_bytes(2, "big")
            + len(self.value).to_bytes(2, "big")
            + self.value
            + bytes(-len(self.value) % 4)
        )

    @property
    def type_name(self) -> str:
        """Name the type, e.g. ``"XOR-MAPPED-ADDRESS"``.

        Falls back to ``"unknown (0x7ff0)"`` for a type not named here.
        """
        return _ATTRIBUTE_NAMES.get(self.type, f"unknown ({self.type:#06x})")

    @property
    def comprehension_required(self) -> bool:
        """Whether a receiver must understand this type to process the
        message: types ``0x0000``-``0x7FFF`` (RFC 8489 §14)."""
        return self.type < 0x8000

    @property
    def address(self) -> STUNAddress | None:
        """Read the value as an address in the clear (RFC 8489 §14.1).

        That is MAPPED-ADDRESS's encoding, which ALTERNATE-SERVER,
        RFC 5780's RESPONSE-ORIGIN and OTHER-ADDRESS, and RFC 3489's
        SOURCE-ADDRESS and CHANGED-ADDRESS share. ``None`` for a value
        that is not one: an unknown family, or a length other than 8
        for IPv4 or 20 for IPv6.
        """
        return _parse_address(self.value, bytes(18))


@dataclass(frozen=True, slots=True)
class STUN(Protocol):
    """One STUN message (RFC 8489 §5, RFC 5389 §6).

    Construction checks that each field fits; it does not check the
    Magic Cookie or that the attributes are a multiple of 4 bytes,
    which :meth:`decode` rejects, so a test of another stack can build a
    message it would refuse.

    :param message_type: The 14-bit Message Type, class and method
        interleaved (see the module docstring and
        :attr:`message_type_name`).
    :param magic_cookie: ``0x2112A442`` (:attr:`MAGIC_COOKIE`).
    :param transaction_id: The 12-byte Transaction ID.
    :param attributes: The attributes, kept raw with their padding;
        parsed by :attr:`parsed_attributes` and the accessors.
    """

    message_type: int
    magic_cookie: int = _MAGIC_COOKIE
    transaction_id: bytes = bytes(12)
    attributes: bytes = b""
    #: Whether the bytes after this message, in the buffer it was
    #: decoded from, begin another message, as they can over TCP;
    #: decode context, not a wire field, so it is neither compared nor
    #: hashed (see the module docstring's *Over TCP*).
    _followed: bool = field(
        default=False, init=False, repr=False, compare=False
    )

    MAGIC_COOKIE: ClassVar[int] = _MAGIC_COOKIE
    FINGERPRINT_XOR: ClassVar[int] = _FINGERPRINT_XOR

    MAPPED_ADDRESS: ClassVar[int] = _MAPPED_ADDRESS
    MESSAGE_INTEGRITY: ClassVar[int] = _MESSAGE_INTEGRITY
    ERROR_CODE: ClassVar[int] = _ERROR_CODE
    UNKNOWN_ATTRIBUTES: ClassVar[int] = _UNKNOWN_ATTRIBUTES
    XOR_MAPPED_ADDRESS: ClassVar[int] = _XOR_MAPPED_ADDRESS
    SOFTWARE: ClassVar[int] = _SOFTWARE
    FINGERPRINT: ClassVar[int] = _FINGERPRINT

    _struct: ClassVar[Struct] = Struct("!HHI12s")

    def __post_init__(self) -> None:
        """Check each field fits its width.

        :raises InvalidFieldError: a field does not.
        """
        _check_width(type(self), "message_type", self.message_type, 14)
        _check_width(type(self), "magic_cookie", self.magic_cookie, 32)
        _check_length(type(self), "attributes", self.attributes)
        if len(self.transaction_id) != 12:
            raise InvalidFieldError(
                f"STUN transaction_id must be 12 bytes, "
                f"got {len(self.transaction_id)}",
                protocol=type(self),
                field="transaction_id",
                expected=12,
                actual=len(self.transaction_id),
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the message at the start of ``data``.

        :raises TruncatedHeaderError: ``data`` is shorter than the
            20-byte header, or than the Message Length says
            (``field`` ``"length"``).
        :raises InvalidFieldError: the two bits above the Message Type
            are not zero (``field`` ``"message_type"``), the Magic
            Cookie is not ``0x2112A442`` (``"magic_cookie"``), or the
            Message Length is not a multiple of 4 (``"length"``).
        """
        message_type, length, cookie, transaction_id = cls._unpack_fixed(data)
        _check_header(cls, message_type, length, cookie)
        end = _HEADER_LEN + length
        if end > len(data):
            raise TruncatedHeaderError(
                f"STUN message of {end} bytes, buffer holds {len(data)}",
                protocol=cls,
                field="length",
                offset=2,
                expected=end,
                actual=len(data),
            )
        message = cls(
            message_type=message_type,
            magic_cookie=cookie,
            transaction_id=transaction_id,
            attributes=bytes(data[_HEADER_LEN:end]),
        )
        rest = bytes(data[end : end + 8])
        if len(rest) == 8 and rest[0] < 0x40 and rest[4:] == _COOKIE_BYTES:
            object.__setattr__(message, "_followed", True)
        return message

    def __bytes__(self) -> bytes:
        """Serialize the header and the raw attributes."""
        return (
            self._struct.pack(
                self.message_type,
                len(self.attributes),
                self.magic_cookie,
                self.transaction_id,
            )
            + self.attributes
        )

    @property
    def header_len(self) -> int:
        """The whole message: the 20-byte header and the attributes."""
        return _HEADER_LEN + len(self.attributes)

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """Name the next message in the same buffer, if one begins there.

        :class:`STUN` when the 8 bytes after this message began like a
        message, the cookie in place, when it was decoded; ``None``
        otherwise, and for a message built rather than decoded. The
        answer is always this class, so ``registry`` has nothing to
        select.
        """
        return STUN if self._followed else None

    @property
    def length(self) -> int:
        """The Message Length: the attributes' bytes, padding included."""
        return len(self.attributes)

    @property
    def message_class(self) -> int:
        """The class, from bits 4 and 8 of the type (RFC 8489 §5).

        ``0`` Request, ``1`` Indication, ``2`` Success Response, ``3``
        Error Response.
        """
        kind = self.message_type
        return (kind >> 7 & 0b10) | (kind >> 4 & 0b01)

    @property
    def method(self) -> int:
        """The 12-bit method, from the type's other bits (RFC 8489 §5).

        ``1`` is Binding; TURN adds the others (see :attr:`method_name`).
        """
        kind = self.message_type
        return (kind & 0x000F) | (kind >> 1 & 0x0070) | (kind >> 2 & 0x0F80)

    @property
    def class_name(self) -> str:
        """Name the class, e.g. ``"Success Response"``."""
        return _CLASS_NAMES[self.message_class]

    @property
    def method_name(self) -> str:
        """Name the method, e.g. ``"Binding"``.

        Falls back to ``"unknown (0x5)"`` for a method not named here.
        """
        return _METHOD_NAMES.get(self.method, f"unknown ({self.method:#x})")

    @property
    def message_type_name(self) -> str:
        """Name the method and class, e.g. ``"Binding Request"``."""
        return f"{self.method_name} {self.class_name}"

    def _walk(self) -> Iterator[STUNAttribute]:
        for kind, value in walk_kind_length_value(
            self.attributes,
            lone_byte_kinds=frozenset(),
            terminator_kind=None,
            min_option_length=None,
            length_includes_header=False,
            protocol=type(self),
            field="attributes",
            width=2,
            align=4,
        ):
            yield STUNAttribute(kind, value)

    @property
    def parsed_attributes(self) -> tuple[STUNAttribute, ...]:
        """Parse every attribute, in wire order, on demand.

        :raises InvalidFieldError: an attribute header or value runs
            past :attr:`attributes` (``field`` ``"attributes"``,
            ``offset`` into them).
        """
        return tuple(self._walk())

    @property
    def _readable(self) -> tuple[tuple[STUNAttribute, ...], bool]:
        """Return the attributes up to the first malformed one, and
        whether the walk reached the end without one."""
        found: list[STUNAttribute] = []
        try:
            found.extend(self._walk())
        except InvalidFieldError:
            return tuple(found), False
        return tuple(found), True

    def attribute(self, kind: int) -> STUNAttribute | None:
        """Return the first attribute of type ``kind``, or ``None``.

        A receiver processes only the first of duplicate attributes
        (RFC 8489 §14). Never raises: a malformed list is read up to
        the first attribute that does not fit.
        """
        for attribute in self._readable[0]:
            if attribute.type == kind:
                return attribute
        return None

    def xor_address(self, attribute: STUNAttribute) -> STUNAddress | None:
        """Un-XOR an address in XOR-MAPPED-ADDRESS's encoding.

        The port is XORed with the Magic Cookie's top 16 bits, an IPv4
        address with the cookie, and an IPv6 address with the cookie
        and the Transaction ID (RFC 8489 §14.2, RFC 5389 §15.2), all
        this message's. That encoding is also TURN's XOR-PEER-ADDRESS
        and XOR-RELAYED-ADDRESS (RFC 8656 §18). ``None`` for a value of
        an unknown family or the wrong length.
        """
        mask = self.magic_cookie.to_bytes(4, "big") + self.transaction_id
        return _parse_address(attribute.value, mask[:2] + mask)

    @property
    def mapped_address(self) -> STUNAddress | None:
        """MAPPED-ADDRESS (RFC 8489 §14.1), or ``None``."""
        found = self.attribute(_MAPPED_ADDRESS)
        return None if found is None else found.address

    @property
    def xor_mapped_address(self) -> STUNAddress | None:
        """XOR-MAPPED-ADDRESS, un-XORed (RFC 8489 §14.2), or ``None``.

        The address and port the server saw the request come from; see
        :meth:`xor_address`.
        """
        found = self.attribute(_XOR_MAPPED_ADDRESS)
        return None if found is None else self.xor_address(found)

    @property
    def software(self) -> str | None:
        """SOFTWARE (RFC 8489 §14.14), as text, or ``None``.

        See :func:`_text` for how the bytes are read.
        """
        found = self.attribute(_SOFTWARE)
        return None if found is None else _text(found.value)

    @property
    def _error(self) -> STUNAttribute | None:
        found = self.attribute(_ERROR_CODE)
        return found if found is not None and len(found.value) >= 4 else None

    @property
    def error_code(self) -> int | None:
        """ERROR-CODE's code, ``300``-``699`` (RFC 8489 §14.8).

        That is the Class times 100 plus the Number. ``None`` without
        the attribute, with one shorter than 4 bytes, or with one whose
        Class is not 3-6 or whose Number is above 99, which RFC 8489
        §14.8 rules out and which would otherwise read as a code of
        0-955, or as another, valid code (Class 3, Number 150 as 450).
        :attr:`error_reason` reads the reason phrase all the same.
        """
        found = self._error
        if found is None:
            return None
        klass, number = found.value[2] & 0x07, found.value[3]
        if not 3 <= klass <= 6 or number > 99:
            return None
        return klass * 100 + number

    @property
    def error_reason(self) -> str | None:
        """ERROR-CODE's reason phrase, as text, or ``None``.

        See :func:`_text` for how the bytes are read.
        """
        found = self._error
        return None if found is None else _text(found.value[4:])

    @property
    def unknown_attributes(self) -> tuple[int, ...] | None:
        """UNKNOWN-ATTRIBUTES' types (RFC 8489 §14.13), or ``None``.

        A trailing odd byte is not a type, and is left out.
        """
        found = self.attribute(_UNKNOWN_ATTRIBUTES)
        if found is None:
            return None
        value = found.value
        return tuple(
            int.from_bytes(value[i : i + 2])
            for i in range(0, len(value) - 1, 2)
        )

    @property
    def message_integrity(self) -> bytes | None:
        """MESSAGE-INTEGRITY's HMAC-SHA1, raw and unverified, or ``None``.

        Verifying it needs the credential's key (RFC 8489 §14.5); see the
        module docstring.
        """
        found = self.attribute(_MESSAGE_INTEGRITY)
        return None if found is None else found.value

    @property
    def fingerprint(self) -> int | None:
        """FINGERPRINT's value (RFC 8489 §14.7), or ``None``.

        Only a FINGERPRINT that is the last attribute, of 4 bytes, in a
        list that walks to its end, counts; one anywhere else is not
        a fingerprint RFC 8489 §14.7 defines, and
        :func:`~netprotocols.checksum.verify` fails it.
        """
        found, whole = self._readable
        if not whole or not found:
            return None
        last = found[-1]
        if last.type != _FINGERPRINT or len(last.value) != 4:
            return None
        return int.from_bytes(last.value)


def _check_header(
    cls: type[STUN], message_type: int, length: int, cookie: int
) -> None:
    """Raise :class:`InvalidFieldError` for a header no STUN message
    has: a nonzero top two bits, another cookie, or a Message Length
    that is not a multiple of 4."""
    if message_type >> 14:
        raise InvalidFieldError(
            f"STUN message type {message_type:#06x} does not start with "
            f"two zero bits",
            protocol=cls,
            field="message_type",
            offset=0,
            expected="0x0000-0x3fff",
            actual=message_type,
        )
    if cookie != _MAGIC_COOKIE:
        raise InvalidFieldError(
            f"STUN magic cookie must be {_MAGIC_COOKIE:#010x}, got "
            f"{cookie:#010x} (an RFC 3489 message has none)",
            protocol=cls,
            field="magic_cookie",
            offset=4,
            expected=_MAGIC_COOKIE,
            actual=cookie,
        )
    if length % 4:
        raise InvalidFieldError(
            f"STUN message length {length} is not a multiple of 4",
            protocol=cls,
            field="length",
            offset=2,
            expected="a multiple of 4",
            actual=length,
        )
