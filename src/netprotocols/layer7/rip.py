"""RIP — the Routing Information Protocol, versions 1 and 2.

RIP (RFC 1058 for version 1, RFC 2453 for version 2) is a
distance-vector routing protocol carried in UDP datagrams to and from
port 520. A message is a 4-byte header followed by a list of 20-byte
entries filling the rest of the datagram, up to 25 of them (RFC 2453
§3.6; the layout is §4's)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------+---------------+-------------------------------+
   |  command (1)  |  version (1)  |       must be zero (2)        |
   +---------------+---------------+-------------------------------+
   | Address Family Identifier (2) |        Route Tag (2)          |
   +-------------------------------+-------------------------------+
   |                         IP Address (4)                        |
   +---------------------------------------------------------------+
   |                         Subnet Mask (4)                       |
   +---------------------------------------------------------------+
   |                         Next Hop (4)                          |
   +---------------------------------------------------------------+
   |                         Metric (4)                            |
   +---------------------------------------------------------------+

RIPv1 sends the Route Tag, Subnet Mask and Next Hop as zero ("must be
zero", RFC 1058 §3.1) rather than leaving them out, so both versions
share one entry layout and only the interpretation differs. Bytes 2-3
of the header are must-be-zero in RFC 1058 and RFC 2453 (§4 calls them
"unused"); RFC 1388, the first RIPv2 specification, used them as a
Routing Domain, and RFC 4822's figures still draw that name. They are
kept as :attr:`RIP.reserved`, verbatim.

Authentication (RFC 2453 §4.1, RFC 4822) takes the place of the first
entry: Address Family Identifier ``0xFFFF``, then an Authentication
Type and 16 bytes whose meaning depends on it. Type 2 is a plain-text
password. Type 3, Cryptographic Hash Function (RFC 4822), carries the
RIPv2 Packet Length, a Key ID, an Auth Data Len and a sequence number
there, and appends an authentication trailer after the last entry: the
4 bytes ``0xFFFF 0x0001``, then the digest. :class:`RIPAuthentication`
models that entry, so it is never read as a route.

The datagram as a whole
-----------------------

RIP has no length field of its own: its entries fill the rest of the
UDP datagram, and the chain walk does not trim a frame to the UDP
header's declared length. So, like ICMPv4 and IGMP, a RIP message keeps
the whole buffer after its header as :attr:`RIP.body`, verbatim, and
past the 4-byte header :meth:`RIP.decode` never raises: ``bytes(RIP.
decode(x)) == x`` holds for every buffer decode accepts. The accessors
then split that body without raising:

- :attr:`RIP.entries` reads every whole 20-byte entry, up to the
  authentication trailer when the message has one.
- :attr:`RIP.authentication_trailer` is the RFC 4822 trailer: the bytes
  from the offset the RIPv2 Packet Length field gives to the end of the
  body, when they start with the trailer's ``0xFFFF 0x0001`` (or as
  much of it as a cut capture kept); otherwise the body is read as
  entries, so a wrong Packet Length cannot hide routes as a trailer.
  It is not sized by Auth Data Len, which senders fill in two
  ways: the digest's own length, as RFC 4822 says, or that plus the
  trailer's 4-byte header. BIRD 2.14 does each: the corpus's keyed-MD5
  messages declare 20 for a 16-byte digest, its HMAC-SHA-256 ones 32
  for a 32-byte digest. FRR's ripd has a switch between two keyed-MD5
  lengths for the same reason (``auth-length rfc|old-ripd``).
- :attr:`RIP.remainder` is what is left after the last whole entry
  when the message has no trailer: fewer than 20 bytes, which cannot be
  an entry.

A remainder has two sources a decoder cannot tell apart without the
UDP length: an entry cut short by a capture's snap length, and bytes
after the datagram, such as a 4-byte Ethernet FCS a capture kept. Both
stay in the body, reported by :attr:`RIP.remainder` (or, after a
trailer, counted into :attr:`RIP.authentication_trailer`), and neither
fails the decode. Ethernet's zero padding only reaches a message with
no entries at all: the shortest one with an entry, 24 bytes behind
UDP's 8 and IPv4's 20, already fills Ethernet's 46-byte minimum
payload.

Decoding a guess
----------------

RIP is reached through ``udp.port``, which is best-effort (see
:mod:`netprotocols.registry`), and any 4 bytes would make a header and
any 20 an entry. :meth:`RIP.decode` therefore rejects the two header
values no RIP message carries: a version other than 1 or 2, and command
0. IANA lists command 0 as invalid and versions 3-254 as unassigned;
version 0 messages are to be ignored (RFC 1058 §3.4). RFC 1058 §3.4
also asks a receiver to process a version above 1 as if it were 1,
for a future revision that never came: RIPng, the IPv6 successor,
runs on its own port, 521 (RFC 2080), and is not decoded here. Two
bytes then decide, and of their 65,536 values 510 pass, so a random
datagram on port 520 is rejected 99.2% of the time.

Nothing else is checked. The commands past Request and Response (RFC
1058's obsolete TraceOn and TraceOff, Sun's reserved 5, RFC 1582's
triggered and RFC 2091's update messages) decode, with their body
framed as entries all the same. A RIPv1 message whose must-be-zero
fields are not zero, which RFC 1058 §3.4 tells a receiver to ignore,
decodes too, its fields carried verbatim, so a capture of a stack that
sends one can be read.

Construction checks only that each header field fits its width, so a
header with a version decode rejects builds, and
``RIP.decode(bytes(message))`` raises for it, which ARCHITECTURE.md's
round-trip guarantee allows: it covers canonical headers, which that
one is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv4, ipv4_to_bytes
from netprotocols.utils.exceptions import InvalidFieldError
from netprotocols.utils.ipv4 import validate_ipv4_addr

__all__ = ["RIP", "RIPAuthentication", "RIPEntry"]

#: One entry, route or authentication: AFI, route tag (or authentication
#: type), then 16 bytes.
_ENTRY = Struct("!HH4s4s4sI")
_ENTRY_LEN = _ENTRY.size

#: The Address Family Identifier that marks an authentication entry
#: (RFC 2453 §4.1).
_AFI_AUTHENTICATION = 0xFFFF

#: The authentication type whose entry carries the RIPv2 Packet Length
#: and is followed by an authentication trailer (RFC 4822 §2.1).
_AUTH_CRYPTOGRAPHIC = 3
_CRYPTOGRAPHIC_FIELDS = Struct("!HBBI8x")

#: How an authentication trailer starts: AFI 0xFFFF, then type 1,
#: Authentication Trailer (RFC 4822 §2.1).
_TRAILER_HEADER = b"\xff\xff\x00\x01"

#: RIP commands (IANA "RIP Commands"; RFC 1058 §3.1 for 1-5, RFC 1582
#: for 6-8, RFC 2091 for 9-11).
_COMMAND_NAMES: dict[int, str] = {
    1: "Request",
    2: "Response",
    3: "TraceOn",
    4: "TraceOff",
    5: "Reserved",
    6: "Triggered Request",
    7: "Triggered Response",
    8: "Triggered Acknowledgement",
    9: "Update Request",
    10: "Update Response",
    11: "Update Acknowledge",
}

#: Address Family Identifiers (IANA "RIP Address Family Identifiers").
#: AFI 0 asks for the whole table when it is a Request's only entry,
#: with metric 16 (RFC 2453 §3.9.1).
_AFI_NAMES: dict[int, str] = {
    0: "Unspecified",
    2: "IP",
    _AFI_AUTHENTICATION: "Authentication",
}

#: Authentication types (IANA "RIP Authentication Type"). Type 1 names
#: the trailer RFC 4822 appends, not an entry.
_AUTH_TYPE_NAMES: dict[int, str] = {
    0: "none",
    1: "Authentication Trailer",
    2: "Plain-text password",
    3: "Cryptographic Hash Function",
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
class RIPEntry:
    """One route entry (RFC 2453 §4; RFC 1058 §3.1 for RIPv1).

    In a RIPv1 message the route tag, subnet mask and next hop must be
    zero; they are carried verbatim either way.

    :param afi: Address Family Identifier: ``2`` IP, or ``0`` in a
        Request for the whole table (see :attr:`afi_name`).
    :param route_tag: Route tag (RIPv2): an attribute a route keeps as
        it is readvertised, such as the AS it was learnt from.
    :param address: The destination, dotted-decimal.
    :param subnet_mask: The destination's mask (RIPv2), dotted-decimal;
        ``"0.0.0.0"`` when none is included.
    :param next_hop: Where to forward to (RIPv2), dotted-decimal;
        ``"0.0.0.0"`` means the sender itself.
    :param metric: Hop count, ``1``-``15``, or ``16`` for unreachable
        (infinity); carried as the 32-bit field it is on the wire.
    :raises InvalidIPv4AddressError: an address is not dotted-decimal.
    :raises InvalidFieldError: ``afi``, ``route_tag`` or ``metric`` does
        not fit its field.

    ``bytes(entry)`` is the 20-byte on-wire entry, so ``RIP(...,
    body=b"".join(map(bytes, entries)))`` builds a message.
    """

    afi: int
    route_tag: int
    address: str
    subnet_mask: str
    next_hop: str
    metric: int

    def __post_init__(self) -> None:
        """Check each field's width and each address's form."""
        _check_width(type(self), "afi", self.afi, 16)
        _check_width(type(self), "route_tag", self.route_tag, 16)
        _check_width(type(self), "metric", self.metric, 32)
        for name in ("address", "subnet_mask", "next_hop"):
            validate_ipv4_addr(
                getattr(self, name), protocol=type(self), field=name
            )

    def __bytes__(self) -> bytes:
        """Serialize the entry to its 20 on-wire bytes."""
        return _ENTRY.pack(
            self.afi,
            self.route_tag,
            ipv4_to_bytes(self.address),
            ipv4_to_bytes(self.subnet_mask),
            ipv4_to_bytes(self.next_hop),
            self.metric,
        )

    @property
    def afi_name(self) -> str:
        """Name the address family, e.g. ``"IP"``.

        Falls back to ``"unknown (n)"`` for a family not named here.
        """
        return _AFI_NAMES.get(self.afi, f"unknown ({self.afi})")


@dataclass(frozen=True, slots=True)
class RIPAuthentication:
    """The authentication entry of a RIPv2 message (RFC 2453 §4.1).

    It takes the first entry's place, with Address Family Identifier
    ``0xFFFF``; the AFI is implied here, and ``bytes(auth)`` writes it.

    :param auth_type: Authentication type: ``2`` plain-text password,
        ``3`` Cryptographic Hash Function (RFC 4822); see
        :attr:`auth_type_name`.
    :param data: The 16 bytes after the type, kept raw: the password,
        NUL-padded on the right, for type 2; the RIPv2 Packet Length,
        Key ID, Auth Data Len, sequence number and 8 zero bytes for type
        3, read by :attr:`packet_length`, :attr:`key_id`,
        :attr:`auth_data_len` and :attr:`sequence_number`.
    """

    auth_type: int
    data: bytes = bytes(16)

    def __post_init__(self) -> None:
        """Check the type's width and the data's length."""
        _check_width(type(self), "auth_type", self.auth_type, 16)
        if len(self.data) != 16:
            raise InvalidFieldError(
                f"RIPAuthentication data must be 16 bytes, "
                f"got {len(self.data)}",
                protocol=type(self),
                field="data",
                expected=16,
                actual=len(self.data),
            )

    def __bytes__(self) -> bytes:
        """Serialize the entry to its 20 on-wire bytes, AFI included."""
        return (
            _AFI_AUTHENTICATION.to_bytes(2, "big")
            + self.auth_type.to_bytes(2, "big")
            + self.data
        )

    @property
    def afi(self) -> int:
        """The Address Family Identifier, always ``0xFFFF``."""
        return _AFI_AUTHENTICATION

    @property
    def auth_type_name(self) -> str:
        """Name the authentication type, e.g. ``"Plain-text password"``.

        Falls back to ``"unknown (n)"`` for a type not named here.
        """
        return _AUTH_TYPE_NAMES.get(
            self.auth_type, f"unknown ({self.auth_type})"
        )

    @property
    def password(self) -> bytes | None:
        """Return a type 2 entry's plain-text password, unpadded.

        The NUL padding on the right (RFC 2453 §4.1) is stripped.
        ``None`` for other types.
        """
        if self.auth_type != 2:
            return None
        return self.data.rstrip(b"\x00")

    @property
    def _cryptographic(self) -> tuple[int, int, int, int] | None:
        if self.auth_type != _AUTH_CRYPTOGRAPHIC:
            return None
        packet_length, key_id, auth_data_len, sequence = (
            _CRYPTOGRAPHIC_FIELDS.unpack(self.data)
        )
        return packet_length, key_id, auth_data_len, sequence

    @property
    def packet_length(self) -> int | None:
        """Return a type 3 entry's RIPv2 Packet Length (RFC 4822 §2.1).

        It is the offset from the start of the RIP header to the
        authentication trailer. ``None`` for other types.
        """
        fields = self._cryptographic
        return None if fields is None else fields[0]

    @property
    def key_id(self) -> int | None:
        """Return a type 3 entry's Key ID; ``None`` for other types.

        It names the security association whose key made the digest.
        """
        fields = self._cryptographic
        return None if fields is None else fields[1]

    @property
    def auth_data_len(self) -> int | None:
        """Return a type 3 entry's Auth Data Len; ``None`` otherwise.

        RFC 4822 makes it the digest's length, but some senders count
        the trailer's 4-byte header too (see the module docstring), so
        it does not reliably size :attr:`RIP.authentication_trailer`.
        """
        fields = self._cryptographic
        return None if fields is None else fields[2]

    @property
    def sequence_number(self) -> int | None:
        """Return a type 3 entry's sequence number; ``None`` otherwise.

        RFC 4822 makes it non-decreasing per sender and Key ID.
        """
        fields = self._cryptographic
        return None if fields is None else fields[3]


def _parse_entry(raw: bytes, offset: int) -> RIPEntry | RIPAuthentication:
    """Parse the entry at ``offset`` in ``raw``, which holds 20 bytes."""
    afi, tag, address, mask, next_hop, metric = _ENTRY.unpack_from(raw, offset)
    if afi == _AFI_AUTHENTICATION:
        return RIPAuthentication(tag, raw[offset + 4 : offset + _ENTRY_LEN])
    return RIPEntry(
        afi,
        tag,
        bytes_to_ipv4(address),
        bytes_to_ipv4(mask),
        bytes_to_ipv4(next_hop),
        metric,
    )


@dataclass(frozen=True, slots=True)
class RIP(Protocol):
    """A RIP message: the header (RFC 2453 §4) and its entries.

    Construction accepts any value that fits each header field;
    :meth:`decode` is stricter and rejects a version other than 1 or 2
    and command 0 (see the module docstring).

    :param command: ``1`` Request, ``2`` Response; ``3``-``11`` are
        obsolete or extensions (see :attr:`command_name`).
    :param version: ``1`` (RFC 1058) or ``2`` (RFC 2453).
    :param reserved: Header bytes 2-3, must be zero (RFC 1388's Routing
        Domain), carried verbatim.
    :param body: Everything after the header, kept raw: the entries,
        an authentication trailer, and any remainder, read by
        :attr:`entries`, :attr:`authentication_trailer` and
        :attr:`remainder`.
    """

    command: int
    version: int
    reserved: int = 0
    body: bytes = b""

    _struct: ClassVar[Struct] = Struct("!BBH")

    def __post_init__(self) -> None:
        """Check each header field's width."""
        _check_width(type(self), "command", self.command, 8)
        _check_width(type(self), "version", self.version, 8)
        _check_width(type(self), "reserved", self.reserved, 16)

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the header and keep the rest of ``data`` as the body.

        :raises TruncatedHeaderError: ``data`` is shorter than 4 bytes.
        :raises InvalidFieldError: the version is not 1 or 2 (``field``
            ``"version"``, ``offset`` ``1``), or the command is 0
            (``field`` ``"command"``, ``offset`` ``0``).
        """
        command, version, reserved = cls._unpack_fixed(data)
        if version not in (1, 2):
            # Checked here and not in __post_init__, as VXLAN's I flag
            # is: a decoded message without one is most likely not RIP.
            raise InvalidFieldError(
                f"RIP version must be 1 or 2, got {version}",
                protocol=cls,
                field="version",
                offset=1,
                expected="1 or 2",
                actual=version,
            )
        if command == 0:
            raise InvalidFieldError(
                "RIP command 0 is invalid",
                protocol=cls,
                field="command",
                offset=0,
                expected="1-255",
                actual=command,
            )
        return cls(
            command=command,
            version=version,
            reserved=reserved,
            body=bytes(data[cls._struct.size :]),
        )

    def __bytes__(self) -> bytes:
        """Serialize the header and the body, verbatim."""
        return (
            self._struct.pack(self.command, self.version, self.reserved)
            + self.body
        )

    @property
    def header_len(self) -> int:
        """Return the header's 4 bytes plus the whole body.

        The body is the rest of the datagram: RIP is terminal.
        """
        return self._struct.size + len(self.body)

    @property
    def command_name(self) -> str:
        """Name the command, e.g. ``"Response"``.

        Falls back to ``"unknown (n)"`` for a command not named here.
        """
        return _COMMAND_NAMES.get(self.command, f"unknown ({self.command})")

    @property
    def _trailer_offset(self) -> int | None:
        """Return where the RFC 4822 trailer starts in :attr:`body`.

        ``None`` unless the first entry is a type 3 authentication entry
        whose RIPv2 Packet Length is usable: past that entry, at an
        entry boundary, within the body, and at bytes that begin the
        trailer's ``0xFFFF 0x0001``, or as much of it as the body holds.
        """
        body = self.body
        if len(body) < _ENTRY_LEN or body[:4] != b"\xff\xff\x00\x03":
            return None
        offset = int.from_bytes(body[4:6], "big") - self._struct.size
        if offset < _ENTRY_LEN or offset % _ENTRY_LEN or offset > len(body):
            return None
        if not _TRAILER_HEADER.startswith(body[offset : offset + 4]):
            return None
        return offset

    @property
    def _entries_end(self) -> int:
        """Return where the last whole entry ends in :attr:`body`."""
        offset = self._trailer_offset
        if offset is not None:
            return offset
        return len(self.body) - len(self.body) % _ENTRY_LEN

    @property
    def entries(self) -> tuple[RIPEntry | RIPAuthentication, ...]:
        """Parse every whole entry, in wire order, on demand.

        An entry with Address Family Identifier ``0xFFFF`` is a
        :class:`RIPAuthentication`, wherever it stands (RFC 2453 §4.1
        puts it first), and every other one a :class:`RIPEntry`. The
        entries end at the authentication trailer, when there is one,
        or at the last 20 bytes the body holds whole. Never raises.
        """
        body = self.body
        return tuple(
            _parse_entry(body, offset)
            for offset in range(0, self._entries_end, _ENTRY_LEN)
        )

    @property
    def routes(self) -> tuple[RIPEntry, ...]:
        """Return :attr:`entries` without the authentication entries."""
        return tuple(
            entry for entry in self.entries if isinstance(entry, RIPEntry)
        )

    @property
    def authentication(self) -> RIPAuthentication | None:
        """Return the first entry if it authenticates (RFC 2453 §4.1).

        ``None`` when the first entry is a route, or there is none.
        """
        body = self.body
        if len(body) < _ENTRY_LEN or body[:2] != b"\xff\xff":
            return None
        return RIPAuthentication(
            int.from_bytes(body[2:4], "big"), body[4:_ENTRY_LEN]
        )

    @property
    def authentication_trailer(self) -> bytes | None:
        """Return the RFC 4822 authentication trailer, raw.

        That is ``0xFFFF 0x0001`` and the digest, from the offset the
        first entry's RIPv2 Packet Length gives to the end of the body.

        ``None`` when there is none to find: no type 3 authentication
        entry, or a Packet Length that is not past it, at an entry
        boundary and within the body (a message cut before its trailer,
        for one), or that points at bytes other than the trailer's
        ``0xFFFF 0x0001`` (a route, for one). Bytes after the datagram,
        such as an Ethernet FCS, run on into it (see the module
        docstring).
        """
        offset = self._trailer_offset
        return None if offset is None else self.body[offset:]

    @property
    def remainder(self) -> bytes:
        """Return what follows the last whole entry, short of an entry.

        That is an entry cut short, or bytes after the datagram, such as
        an Ethernet FCS (see the module docstring). Empty for a message
        that ends on an entry boundary, and for one with a trailer.
        """
        if self._trailer_offset is not None:
            return b""
        return self.body[self._entries_end :]
