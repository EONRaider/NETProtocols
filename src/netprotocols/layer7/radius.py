"""RADIUS — Remote Authentication Dial In User Service (RFC 2865).

RADIUS carries authentication and authorization (RFC 2865) and
accounting (RFC 2866) between a network access server (NAS), its client,
and a RADIUS server, in UDP datagrams to port 1812 (authentication) and
1813 (accounting). A packet is a 20-byte header and a list of attributes
(RFC 2865 §3)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                         Authenticator                         |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

The Code names the packet (Access-Request, Access-Accept, ...; see
:attr:`RADIUS.code_name`), the Identifier pairs a request with its
reply, and the Length counts the whole packet, header included. Each
attribute is a Type byte, a Length byte that counts the two header bytes
too, and Length - 2 bytes of Value (§5), with no nesting and no
terminator: the attributes run to the end the packet's Length gives.
:attr:`RADIUS.parsed_attributes` walks them with the TLV walker TCP,
IPv4, IPv6 and PIM share, :func:`~netprotocols._tlv.walk_kind_length_value`.

Decoding
--------

:meth:`RADIUS.decode` reads the header, holds the Length against the
buffer and keeps the attributes as raw ``bytes``, so ``bytes(RADIUS.
decode(x)) == x[:header_len]`` holds by construction, as for
:class:`~netprotocols.BGP`. The Length decides the packet's extent:
below 20 it cannot hold the header and raises
:class:`~netprotocols.InvalidFieldError`; past the end of the buffer it
raises :class:`~netprotocols.TruncatedHeaderError`, for RFC 2865 §3 says
a packet shorter than its Length is discarded. Bytes past the Length
are padding to be ignored (§3), and an Ethernet FCS a capture kept is
too; both are left undecoded, past ``packet.consumed``. RFC 2865's
upper bound of 4096 is not enforced: RFC 7930 §2 lets RADIUS over TCP
and TLS carry packets up to 65535 bytes, and a decoder reading one
through ``decode_as`` has no reason to refuse it.

The attributes are not validated on decode. An attribute whose Length
is below 2 or runs past the packet raises
:class:`~netprotocols.InvalidFieldError` from
:attr:`RADIUS.parsed_attributes` and the accessors built on it, never
from :meth:`RADIUS.decode`, so the header of a packet with a broken
attribute list still decodes, as :class:`~netprotocols.TCP` does for
its options.

Attributes
----------

Every attribute is a :class:`RADIUSAttribute` of its type and its raw
``data``; :attr:`RADIUSAttribute.type_name` names the types of RFC 2865
§5, RFC 2866 §5 and RFC 3579 §3. :attr:`RADIUSAttribute.value` decodes
the commonest: User-Name (1) as text, NAS-IP-Address (4) and
Framed-IP-Address (8) as :class:`~ipaddress.IPv4Address`, NAS-Port (5)
as an integer. User-Password (2) and Vendor-Specific (26) are named and
kept raw: the first is obfuscated with the shared secret, the second
holds a vendor's own attributes, not decoded here. Every other type is
kept raw, with ``value`` ``None``.

Out of scope
------------

Everything that needs the shared secret between client and server: the
Request Authenticator of an Accounting-Request (RFC 2866 §3) and the
Response Authenticator of every reply (RFC 2865 §3), which are MD5
hashes keyed with it; the Message-Authenticator attribute (RFC 3579
§3.2), an HMAC-MD5 under it; and the hiding of User-Password (RFC 2865
§5.2) and Tunnel-Password (RFC 2868). The Authenticator and those
attributes are kept as the raw bytes they are. ``tests/test_radius.py``
verifies every one in the corpus with its published test secret, and
``scripts/check_fixtures.py`` those a frame holds alone, each
independently of this module.

Dynamic Authorization (RFC 5176: Disconnect and CoA, on UDP 3799)
shares the packet format and decodes with this class, its codes named,
but its port is not registered; ``decode_as={"udp.port": {3799:
RADIUS}}`` reads it. Neither are the legacy 1645 and 1646, which
predate IANA's assignment and a few servers still use.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import IPv4Address
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv4
from netprotocols._tlv import walk_kind_length_value
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["RADIUS", "RADIUSAttribute"]

#: The header's length, and the shortest packet (RFC 2865 §3).
_HEADER_LEN = 20

#: The most data one attribute holds: its Length byte counts the 2-byte
#: header, so 255 - 2.
_MAX_DATA = 253

#: Packet codes (IANA "RADIUS Packet Type Codes"): RFC 2865 §3 for 1-5
#: and 11-13 (12 and 13 experimental there; RFC 5997 defines
#: Status-Server), RFC 5176 for Disconnect and CoA, 40-45.
_CODE_NAMES: dict[int, str] = {
    1: "Access-Request",
    2: "Access-Accept",
    3: "Access-Reject",
    4: "Accounting-Request",
    5: "Accounting-Response",
    11: "Access-Challenge",
    12: "Status-Server",
    13: "Status-Client",
    40: "Disconnect-Request",
    41: "Disconnect-ACK",
    42: "Disconnect-NAK",
    43: "CoA-Request",
    44: "CoA-ACK",
    45: "CoA-NAK",
    255: "Reserved",
}

#: Attribute types (IANA "RADIUS Attribute Types"): RFC 2865 §5 for
#: 1-39 and 60-63, RFC 2866 §5 for the accounting attributes 40-51, RFC
#: 3579 §3 for 79 and 80.
_TYPE_NAMES: dict[int, str] = {
    1: "User-Name",
    2: "User-Password",
    3: "CHAP-Password",
    4: "NAS-IP-Address",
    5: "NAS-Port",
    6: "Service-Type",
    7: "Framed-Protocol",
    8: "Framed-IP-Address",
    9: "Framed-IP-Netmask",
    10: "Framed-Routing",
    11: "Filter-Id",
    12: "Framed-MTU",
    13: "Framed-Compression",
    14: "Login-IP-Host",
    15: "Login-Service",
    16: "Login-TCP-Port",
    18: "Reply-Message",
    19: "Callback-Number",
    20: "Callback-Id",
    22: "Framed-Route",
    23: "Framed-IPX-Network",
    24: "State",
    25: "Class",
    26: "Vendor-Specific",
    27: "Session-Timeout",
    28: "Idle-Timeout",
    29: "Termination-Action",
    30: "Called-Station-Id",
    31: "Calling-Station-Id",
    32: "NAS-Identifier",
    33: "Proxy-State",
    34: "Login-LAT-Service",
    35: "Login-LAT-Node",
    36: "Login-LAT-Group",
    37: "Framed-AppleTalk-Link",
    38: "Framed-AppleTalk-Network",
    39: "Framed-AppleTalk-Zone",
    40: "Acct-Status-Type",
    41: "Acct-Delay-Time",
    42: "Acct-Input-Octets",
    43: "Acct-Output-Octets",
    44: "Acct-Session-Id",
    45: "Acct-Authentic",
    46: "Acct-Session-Time",
    47: "Acct-Input-Packets",
    48: "Acct-Output-Packets",
    49: "Acct-Terminate-Cause",
    50: "Acct-Multi-Session-Id",
    51: "Acct-Link-Count",
    60: "CHAP-Challenge",
    61: "NAS-Port-Type",
    62: "Port-Limit",
    63: "Login-LAT-Port",
    79: "EAP-Message",
    80: "Message-Authenticator",
}

#: The attribute types :attr:`RADIUSAttribute.value` decodes.
_USER_NAME = 1
_USER_PASSWORD = 2
_NAS_IP_ADDRESS = 4
_NAS_PORT = 5
_FRAMED_IP_ADDRESS = 8
_VENDOR_SPECIFIC = 26


def _text(data: bytes) -> str:
    """Read a ``text`` value: UTF-8 (RFC 2865 §5), never raising."""
    return data.decode("utf-8", "replace")


def _raw(data: bytes) -> bytes:
    """Keep a value that cannot be read without more than it holds."""
    return data


def _address(data: bytes) -> IPv4Address | None:
    """Read an ``address`` value, 4 bytes (RFC 2865 §5)."""
    return IPv4Address(bytes_to_ipv4(data)) if len(data) == 4 else None


def _integer(data: bytes) -> int | None:
    """Read an ``integer`` value, 4 bytes, unsigned (RFC 2865 §5)."""
    return int.from_bytes(data, "big") if len(data) == 4 else None


#: What :attr:`RADIUSAttribute.value` gives for the types it decodes.
_Value = str | int | IPv4Address | bytes | None

#: How :attr:`RADIUSAttribute.value` reads each type it decodes.
_READERS: dict[int, Callable[[bytes], _Value]] = {
    _USER_NAME: _text,
    _USER_PASSWORD: _raw,
    _NAS_IP_ADDRESS: _address,
    _NAS_PORT: _integer,
    _FRAMED_IP_ADDRESS: _address,
    _VENDOR_SPECIFIC: _raw,
}


def _check_width(owner: type, name: str, value: int, bits: int) -> None:
    """Raise :class:`InvalidFieldError` unless ``value`` fits ``bits``."""
    top = (1 << bits) - 1
    if not 0 <= value <= top:
        raise InvalidFieldError(
            f"{owner.__name__} {name} must be within 0-{top}, got {value}",
            protocol=owner,
            field=name,
            expected=f"0-{top}",
            actual=value,
        )


@dataclass(frozen=True, slots=True)
class RADIUSAttribute:
    """One attribute (RFC 2865 §5): its Type and its Value, raw.

    :param type: Attribute type, ``0``-``255`` — ``1`` User-Name, ``2``
        User-Password, ``4`` NAS-IP-Address, ``5`` NAS-Port, ``8``
        Framed-IP-Address, ``26`` Vendor-Specific, ... (see
        :attr:`type_name`).
    :param data: The Value, kept raw: at most 253 bytes, the Length
        byte counting the 2-byte header too.
    :raises InvalidFieldError: ``type`` does not fit a byte, or ``data``
        is longer than 253 bytes.

    ``bytes(attribute)`` is the on-wire attribute, so ``RADIUS(...,
    attributes=b"".join(map(bytes, attributes)))`` builds a packet.
    """

    type: int
    data: bytes = b""

    def __post_init__(self) -> None:
        """Check the type's width and the data's length."""
        _check_width(type(self), "type", self.type, 8)
        if len(self.data) > _MAX_DATA:
            raise InvalidFieldError(
                f"RADIUSAttribute data must be at most {_MAX_DATA} bytes, "
                f"got {len(self.data)}",
                protocol=type(self),
                field="data",
                expected=f"<={_MAX_DATA}",
                actual=len(self.data),
            )

    def __bytes__(self) -> bytes:
        """Serialize the attribute: Type, Length, then the data."""
        return bytes([self.type, 2 + len(self.data)]) + self.data

    @property
    def type_name(self) -> str:
        """Name the attribute type, e.g. ``"User-Name"``.

        Falls back to ``"unknown (n)"`` for a type not named here.
        """
        return _TYPE_NAMES.get(self.type, f"unknown ({self.type})")

    @property
    def value(self) -> _Value:
        """The decoded value, for the types this library reads.

        A ``str`` for User-Name (1), UTF-8 with undecodable bytes
        replaced; an :class:`~ipaddress.IPv4Address` for NAS-IP-Address
        (4) and Framed-IP-Address (8); an ``int`` for NAS-Port (5); the
        raw ``bytes`` for User-Password (2), hidden with the shared
        secret (RFC 2865 §5.2), and Vendor-Specific (26), a vendor's own
        attributes. ``None`` for every other type, and for an address or
        integer whose data is not 4 bytes: read :attr:`data` instead.
        Never raises.
        """
        reader = _READERS.get(self.type)
        return None if reader is None else reader(self.data)


@dataclass(frozen=True, slots=True)
class RADIUS(Protocol):
    """A RADIUS packet (RFC 2865 §3): the header and its attributes.

    Construction checks that each header field fits and that
    :attr:`length` agrees with :attr:`attributes`, so a packet built
    here is one :meth:`decode` reads back as it was.

    :param code: Packet type — :attr:`ACCESS_REQUEST` (1),
        :attr:`ACCESS_ACCEPT` (2), :attr:`ACCESS_REJECT` (3),
        :attr:`ACCOUNTING_REQUEST` (4), :attr:`ACCOUNTING_RESPONSE` (5),
        :attr:`ACCESS_CHALLENGE` (11), :attr:`STATUS_SERVER` (12), ...
        (see :attr:`code_name`).
    :param identifier: Pairs a reply with its request, and a
        retransmission with the original.
    :param length: The whole packet's length in bytes, header included:
        ``20 + len(attributes)``.
    :param authenticator: The 16-byte Authenticator, kept raw: random in
        an Access-Request or a Status-Server, an MD5 hash keyed with
        the shared secret in an Accounting-Request (RFC 2866 §3) and in
        every reply (RFC 2865 §3), which this library does not verify.
    :param attributes: The attribute list, kept raw; read via
        :attr:`parsed_attributes`.
    """

    code: int
    identifier: int
    length: int
    authenticator: bytes = bytes(16)
    attributes: bytes = b""

    ACCESS_REQUEST: ClassVar[int] = 1
    ACCESS_ACCEPT: ClassVar[int] = 2
    ACCESS_REJECT: ClassVar[int] = 3
    ACCOUNTING_REQUEST: ClassVar[int] = 4
    ACCOUNTING_RESPONSE: ClassVar[int] = 5
    ACCESS_CHALLENGE: ClassVar[int] = 11
    STATUS_SERVER: ClassVar[int] = 12

    _struct: ClassVar[Struct] = Struct("!BBH16s")

    def __post_init__(self) -> None:
        """Check each header field fits and the Length matches.

        :raises InvalidFieldError: a field does not.
        """
        _check_width(type(self), "code", self.code, 8)
        _check_width(type(self), "identifier", self.identifier, 8)
        if len(self.authenticator) != 16:
            raise InvalidFieldError(
                f"RADIUS authenticator must be 16 bytes, "
                f"got {len(self.authenticator)}",
                protocol=type(self),
                field="authenticator",
                expected=16,
                actual=len(self.authenticator),
            )
        expected = _HEADER_LEN + len(self.attributes)
        if self.length != expected or self.length > 0xFFFF:
            raise InvalidFieldError(
                f"RADIUS length {self.length} disagrees with "
                f"{len(self.attributes)} bytes of attributes",
                protocol=type(self),
                field="length",
                expected=expected,
                actual=self.length,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the packet at the start of ``data``.

        :raises TruncatedHeaderError: ``data`` is shorter than the
            20-byte header, or than the packet's Length (``field``
            ``"length"``).
        :raises InvalidFieldError: the Length is below 20 (``field``
            ``"length"``, ``offset`` ``2``).
        """
        code, identifier, length, authenticator = cls._unpack_fixed(data)
        if length < _HEADER_LEN:
            raise InvalidFieldError(
                f"RADIUS length must be at least {_HEADER_LEN}, got {length}",
                protocol=cls,
                field="length",
                offset=2,
                expected=f">={_HEADER_LEN}",
                actual=length,
            )
        if length > len(data):
            raise TruncatedHeaderError(
                f"RADIUS packet of {length} bytes, buffer holds {len(data)}",
                protocol=cls,
                field="length",
                offset=0,
                expected=length,
                actual=len(data),
            )
        return cls(
            code=code,
            identifier=identifier,
            length=length,
            authenticator=bytes(authenticator),
            attributes=bytes(data[_HEADER_LEN:length]),
        )

    def __bytes__(self) -> bytes:
        """Serialize the header and the raw attributes."""
        return (
            self._struct.pack(
                self.code, self.identifier, self.length, self.authenticator
            )
            + self.attributes
        )

    @property
    def header_len(self) -> int:
        """The whole packet: the 20-byte header and the attributes.

        RADIUS is terminal; bytes past it are padding (RFC 2865 §3).
        """
        return _HEADER_LEN + len(self.attributes)

    @property
    def code_name(self) -> str:
        """Name the packet type, e.g. ``"Access-Request"``.

        Falls back to ``"unknown (n)"`` for a code not named here.
        """
        return _CODE_NAMES.get(self.code, f"unknown ({self.code})")

    @property
    def parsed_attributes(self) -> tuple[RADIUSAttribute, ...]:
        """The attributes as :class:`RADIUSAttribute`, in wire order.

        Parsed on demand; a type may repeat (RFC 2865 §5), and every
        occurrence is kept. Empty for a packet with no attributes.

        :raises InvalidFieldError: an attribute's Length is below 2, or
            runs past the packet (``field`` ``"attributes"``, ``offset``
            relative to the first attribute; bounded, so it never hangs
            or over-reads).
        """
        return tuple(
            RADIUSAttribute(kind, data)
            for kind, data in walk_kind_length_value(
                self.attributes,
                lone_byte_kinds=frozenset(),
                terminator_kind=None,
                min_option_length=None,
                length_includes_header=True,
                protocol=type(self),
                field="attributes",
            )
        )

    def _first_value(self, kind: int) -> _Value:
        """The :attr:`RADIUSAttribute.value` of the first ``kind``."""
        for attribute in self.parsed_attributes:
            if attribute.type == kind:
                return attribute.value
        return None

    @property
    def user_name(self) -> str | None:
        """The first User-Name (1), as text; ``None`` if there is none.

        :raises InvalidFieldError: the attributes are malformed (see
            :attr:`parsed_attributes`).
        """
        value = self._first_value(_USER_NAME)
        return value if isinstance(value, str) else None

    @property
    def nas_ip_address(self) -> IPv4Address | None:
        """The first NAS-IP-Address (4); ``None`` if absent or not 4 bytes.

        :raises InvalidFieldError: the attributes are malformed (see
            :attr:`parsed_attributes`).
        """
        value = self._first_value(_NAS_IP_ADDRESS)
        return value if isinstance(value, IPv4Address) else None

    @property
    def nas_port(self) -> int | None:
        """The first NAS-Port (5); ``None`` if absent or not 4 bytes.

        :raises InvalidFieldError: the attributes are malformed (see
            :attr:`parsed_attributes`).
        """
        value = self._first_value(_NAS_PORT)
        return value if isinstance(value, int) else None

    @property
    def framed_ip_address(self) -> IPv4Address | None:
        """The first Framed-IP-Address (8); ``None`` if absent or not 4
        bytes.

        :raises InvalidFieldError: the attributes are malformed (see
            :attr:`parsed_attributes`).
        """
        value = self._first_value(_FRAMED_IP_ADDRESS)
        return value if isinstance(value, IPv4Address) else None
