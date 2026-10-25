"""OSPF — Open Shortest Path First, version 2 (RFC 2328).

OSPF is the link-state interior gateway protocol, IP protocol 89. Every
packet starts with the same 24-byte header (RFC 2328 §A.3.1): Version,
Type, Packet Length, Router ID, Area ID, Checksum, Instance ID, AuType
and the 64-bit Authentication field. RFC 6549 §2 (which updates RFC
2328) split the original 16-bit AuType into an 8-bit Instance ID and
an 8-bit AuType "without any change in meaning", so a packet of the
base instance (Instance ID ``0``) reads the same either way. The Type
names one of five messages, whose body follows the header:

* ``1`` Hello (§A.3.2): :attr:`OSPF.hello`
* ``2`` Database Description (§A.3.3): :attr:`OSPF.database_description`
* ``3`` Link State Request (§A.3.4): :attr:`OSPF.ls_requests`
* ``4`` Link State Update (§A.3.5): :attr:`OSPF.lsas`
* ``5`` Link State Acknowledgment (§A.3.6):
  :attr:`OSPF.ls_acknowledgments`

The body is kept as raw ``bytes`` and each accessor parses it on demand
into frozen records (:class:`OSPFHello`, :class:`OSPFDatabaseDescription`,
:class:`OSPFLSRequest`, :class:`OSPFLSAHeader`, :class:`OSPFLSA`),
returning ``None`` for the other message types. ``decode`` and the
constructor check that the body has its message's framing -- a Hello's
20 fixed bytes and whole 4-byte neighbors, a Database Description's 8
fixed bytes and whole 20-byte LSA headers, whole 12-byte requests, whole
LSA headers in an acknowledgment, and an update's LSA count and LSA
lengths walking the body exactly -- so no accessor ever raises. A body
of another type is kept as it is. The cost is that a malformed body of
a known type fails the whole layer: ``decode`` raises, so a strict walk
raises and a lax one stops after IPv4.

Those framing errors are raised by ``decode``, so although they name
``field="body"``, their ``offset`` is relative to the ``decode`` buffer,
as every decode-time error's is (``24`` is the body's first byte), which
is what lets :func:`~netprotocols.decode_frame` rebase it onto the
frame; the same errors raised by the constructor have no offset.

This module decodes OSPF version 2 over IPv4 only. OSPFv3 (RFC 5340),
which IPv6 carries under the same protocol number, changes the header
and every message, so :meth:`OSPF.decode` rejects any version but 2,
and protocol 89 is withheld from the IPv6 dispatch table: an IPv6
packet carrying OSPFv3 ends its walk at the IPv6 header, as it did
before this module existed, instead of failing to decode as OSPFv2.

**LSA bodies are not decoded.** A Link State Update's LSAs decode as a
20-byte LSA header (§A.4.1) and a raw ``body`` -- the Router, Network,
Summary, AS-external (and NSSA, opaque, ...) contents that the LS Type
selects. Decoding those bodies is follow-up work. The LS Checksum, a
Fletcher checksum over the whole LSA but its LS Age, is computed and
verified by
:func:`netprotocols.checksum.lsa_checksum` and
:func:`~netprotocols.checksum.verify_lsa`.

**Where the packet ends.** Packet Length bounds the packet: the header
and body are exactly that many bytes. Under cryptographic
authentication (AuType 2, RFC 2328 §D.4.3) the message digest follows,
outside Packet Length; its size is the Auth Data Len byte of the
Authentication field, and it is kept in :attr:`OSPF.auth_trailer`.
AuType 3, cryptographic authentication with extended sequence numbers
(RFC 7474), is laid out the same way: the 64-bit sequence number and
then the digest follow the packet (RFC 7474 §3), and Auth Data Len
counts both (§2), so they are its ``auth_trailer``. So ``header_len`` is
Packet Length plus the trailer, and ``bytes(OSPF.decode(x)) ==
x[:header_len]``. Nothing after that is consumed. The chain walk does
not trim a frame to the IP header's length, so what may follow is an
Ethernet frame's padding or FCS, or an RFC 5613 Link-Local Signaling
block, which a router appends to a Hello or Database Description when
it sets the L bit (``0x10``) in Options. All three are left undecoded,
after the OSPF layer: ``decode_frame`` ends the walk at OSPF, and
``frame[packet.consumed:]`` holds them. An LLS block is not part of the
packet the checksum covers, so leaving it out keeps
:func:`~netprotocols.checksum.verify` independent of it.

``bytes(OSPF.decode(x)) == x[:header_len]`` holds by construction: the
header fields are packed back and the body and authentication
trailer are carried verbatim.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import (
    Protocol,
    bytes_to_ipv4,
    hex_str,
    ipv4_to_bytes,
)
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = [
    "OSPF",
    "OSPFLSA",
    "OSPFDatabaseDescription",
    "OSPFHello",
    "OSPFLSAHeader",
    "OSPFLSRequest",
]

#: The only OSPF version this module decodes (RFC 2328 §A.3.1).
_VERSION = 2

#: Cryptographic authentication with extended sequence numbers (RFC
#: 7474 §3), whose trailer opens with a 64-bit sequence number.
_AU_TYPE_EXTENDED = 3
_EXTENDED_SEQUENCE_SIZE = 8

_HELLO_TYPE = 1
_DATABASE_DESCRIPTION_TYPE = 2
_LS_REQUEST_TYPE = 3
_LS_UPDATE_TYPE = 4
_LS_ACKNOWLEDGMENT_TYPE = 5

#: Network Mask, HelloInterval, Options, Rtr Pri, RouterDeadInterval,
#: Designated Router, Backup Designated Router (RFC 2328 §A.3.2).
_HELLO = Struct("!4sHBBI4s4s")
#: Interface MTU, Options, the I/M/MS flags byte, DD sequence number
#: (RFC 2328 §A.3.3).
_DATABASE_DESCRIPTION = Struct("!HBBI")
#: LS type, Link State ID, Advertising Router (RFC 2328 §A.3.4).
_LS_REQUEST = Struct("!I4s4s")
#: LS age, Options, LS type, Link State ID, Advertising Router, LS
#: sequence number, LS checksum, length (RFC 2328 §A.4.1).
_LSA_HEADER = Struct("!HBB4s4sIHH")
#: A Link State Update's "# LSAs" (RFC 2328 §A.3.5).
_LSA_COUNT = Struct("!I")
#: An LSA header's length field, the last two of its 20 bytes.
_LSA_LENGTH = Struct("!H")
_LSA_LENGTH_OFFSET = 18
_NEIGHBOR_SIZE = 4

#: Each fixed-shape message's body: its fixed part, the size of each of
#: the entries that follow it, and what an entry is.
_FRAMING: dict[int, tuple[int, int, str]] = {
    _HELLO_TYPE: (_HELLO.size, _NEIGHBOR_SIZE, "neighbor"),
    _DATABASE_DESCRIPTION_TYPE: (
        _DATABASE_DESCRIPTION.size,
        _LSA_HEADER.size,
        "LSA header",
    ),
    _LS_REQUEST_TYPE: (0, _LS_REQUEST.size, "request"),
    _LS_ACKNOWLEDGMENT_TYPE: (0, _LSA_HEADER.size, "LSA header"),
}

#: The Options field's bits (RFC 2328 §A.2), most significant first:
#: DN (RFC 4576), O (opaque LSAs, RFC 5250), DC (demand circuits, RFC
#: 1793), L (Link-Local Signaling, RFC 5613; RFC 2328's EA), N/P (NSSA,
#: RFC 3101), MC (MOSPF, RFC 1584), E (external routing) and MT
#: (multi-topology, RFC 4915; RFC 1583's TOS bit).
_OPTION_NAMES = (
    (0x80, "DN"),
    (0x40, "O"),
    (0x20, "DC"),
    (0x10, "L"),
    (0x08, "N/P"),
    (0x04, "MC"),
    (0x02, "E"),
    (0x01, "MT"),
)

#: The Database Description flags (RFC 2328 §A.3.3): Init, More,
#: Master/Slave.
_DD_FLAG_NAMES = ((0x04, "I"), (0x02, "M"), (0x01, "MS"))

#: LS types (RFC 2328 §A.4.1, RFC 1584 for 6, RFC 3101 for 7, RFC 5250
#: for the opaque 9-11).
_LS_TYPE_NAMES: dict[int, str] = {
    1: "Router-LSA",
    2: "Network-LSA",
    3: "Summary-LSA (IP network)",
    4: "Summary-LSA (ASBR)",
    5: "AS-external-LSA",
    6: "Group-membership-LSA",
    7: "NSSA-LSA",
    9: "Opaque-LSA (link-local)",
    10: "Opaque-LSA (area-local)",
    11: "Opaque-LSA (AS-wide)",
}


def _bit_names(value: int, names: tuple[tuple[int, str], ...]) -> str:
    return " ".join(name for bit, name in names if value & bit)


def _ls_type_name(ls_type: int) -> str:
    return _LS_TYPE_NAMES.get(ls_type, f"unknown ({ls_type})")


@dataclass(frozen=True, slots=True)
class OSPFLSAHeader:
    """The 20-byte header every LSA starts with (RFC 2328 §A.4.1).

    It describes an LSA in a Link State Update, and stands for one in a
    Database Description and a Link State Acknowledgment, which carry
    the header alone.

    :param ls_age: Seconds since the LSA was originated; ``3600``
        (MaxAge) flushes it. The top bit is RFC 1793's DoNotAge.
    :param options: The optional capabilities the LSA's originator
        supports (see :attr:`options_str`).
    :param ls_type: The LSA's type, ``1`` Router-LSA to ``5``
        AS-external-LSA, and so on (see :attr:`ls_type_name`).
    :param link_state_id: The Link State ID, dotted-decimal; what it
        identifies depends on the LS type.
    :param advertising_router: The originating router's Router ID.
    :param ls_sequence_number: The sequence number as its 32 wire bits,
        unsigned: ``0x80000001`` is RFC 2328's InitialSequenceNumber
        (the field is a signed integer, ``-0x7fffffff``).
    :param ls_checksum: The Fletcher checksum of the whole LSA but LS
        age, carried verbatim (see
        :func:`netprotocols.checksum.lsa_checksum`).
    :param length: The LSA's length in bytes, this header included.
    """

    ls_age: int
    options: int
    ls_type: int
    link_state_id: str
    advertising_router: str
    ls_sequence_number: int
    ls_checksum: int
    length: int

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return _LSA_HEADER.pack(
            self.ls_age,
            self.options,
            self.ls_type,
            ipv4_to_bytes(self.link_state_id),
            ipv4_to_bytes(self.advertising_router),
            self.ls_sequence_number,
            self.ls_checksum,
            self.length,
        )

    @classmethod
    def _parse(cls, data: bytes, offset: int) -> OSPFLSAHeader:
        """Parse the LSA header at ``data[offset:]``, which must hold one."""
        (
            ls_age,
            options,
            ls_type,
            link_state_id,
            advertising_router,
            ls_sequence_number,
            ls_checksum,
            length,
        ) = _LSA_HEADER.unpack_from(data, offset)
        return cls(
            ls_age=ls_age,
            options=options,
            ls_type=ls_type,
            link_state_id=bytes_to_ipv4(link_state_id),
            advertising_router=bytes_to_ipv4(advertising_router),
            ls_sequence_number=ls_sequence_number,
            ls_checksum=ls_checksum,
            length=length,
        )

    @property
    def ls_type_name(self) -> str:
        """Display name of the LS type, e.g. ``"Network-LSA"``.

        Falls back to ``"unknown (n)"``.
        """
        return _ls_type_name(self.ls_type)

    @property
    def options_str(self) -> str:
        """Space-separated names of the Options bits set, e.g. ``"E"``.

        See :attr:`OSPFHello.options_str`.
        """
        return _bit_names(self.options, _OPTION_NAMES)

    @property
    def ls_checksum_hex_str(self) -> str:
        """The LS checksum as a hexadecimal string, e.g. ``"0x6a15"``."""
        return hex_str(self.ls_checksum, 6)

    @property
    def ls_sequence_number_hex_str(self) -> str:
        """The LS sequence number as a hexadecimal string.

        E.g. ``"0x80000001"``, the form routers print it in.
        """
        return hex_str(self.ls_sequence_number, 10)


@dataclass(frozen=True, slots=True)
class OSPFLSA:
    """One LSA from a Link State Update: its header and its body.

    :param header: The 20-byte LSA header (RFC 2328 §A.4.1).
    :param body: Everything after the header, ``header.length - 20``
        bytes, kept raw: this library does not decode the LS types'
        contents yet (§A.4.2-§A.4.5).

    :raises InvalidFieldError: if ``body`` is not ``header.length - 20``
        bytes.
    """

    header: OSPFLSAHeader
    body: bytes = b""

    def __post_init__(self) -> None:
        """Check that the fields agree with each other (see the class)."""
        expected = self.header.length - _LSA_HEADER.size
        if len(self.body) != expected:
            raise InvalidFieldError(
                f"OSPF LSA header declares {self.header.length} bytes, "
                f"so a {expected}-byte body, got {len(self.body)}",
                protocol=type(self),
                field="body",
                expected=expected,
                actual=len(self.body),
            )

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return bytes(self.header) + self.body


@dataclass(frozen=True, slots=True)
class OSPFLSRequest:
    """One entry of a Link State Request (RFC 2328 §A.3.4).

    It names the LSA it asks for.

    :param ls_type: The requested LSA's LS type, a 32-bit field here
        (see :attr:`ls_type_name`).
    :param link_state_id: Its Link State ID, dotted-decimal.
    :param advertising_router: Its originating router's Router ID.
    """

    ls_type: int
    link_state_id: str
    advertising_router: str

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return _LS_REQUEST.pack(
            self.ls_type,
            ipv4_to_bytes(self.link_state_id),
            ipv4_to_bytes(self.advertising_router),
        )

    @property
    def ls_type_name(self) -> str:
        """Display name of the LS type, e.g. ``"Router-LSA"``."""
        return _ls_type_name(self.ls_type)


@dataclass(frozen=True, slots=True)
class OSPFHello:
    """The body of a Hello packet (RFC 2328 §A.3.2).

    :param network_mask: The sending interface's network mask,
        dotted-decimal.
    :param hello_interval: Seconds between this router's Hellos.
    :param options: The optional capabilities the router supports (see
        :attr:`options_str`).
    :param router_priority: The router's priority in the Designated
        Router election; ``0`` makes it ineligible.
    :param router_dead_interval: Seconds of silence before a neighbor is
        declared down.
    :param designated_router: The sender's view of the network's
        Designated Router, by interface address; ``0.0.0.0`` for none.
    :param backup_designated_router: The same for the Backup Designated
        Router.
    :param neighbors: The Router IDs of every router the sender has
        heard a Hello from in the last RouterDeadInterval.
    """

    network_mask: str
    hello_interval: int
    options: int
    router_priority: int
    router_dead_interval: int
    designated_router: str
    backup_designated_router: str
    neighbors: tuple[str, ...] = ()

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return _HELLO.pack(
            ipv4_to_bytes(self.network_mask),
            self.hello_interval,
            self.options,
            self.router_priority,
            self.router_dead_interval,
            ipv4_to_bytes(self.designated_router),
            ipv4_to_bytes(self.backup_designated_router),
        ) + b"".join(ipv4_to_bytes(neighbor) for neighbor in self.neighbors)

    @property
    def options_str(self) -> str:
        """Space-separated names of the Options bits set (RFC 2328 §A.2).

        Most significant first: ``DN``, ``O``, ``DC``, ``L`` (RFC 5613
        Link-Local Signaling), ``N/P``, ``MC``, ``E``, ``MT``. ``"E"``
        for a router in an area that floods external routes; empty
        when none is set.
        """
        return _bit_names(self.options, _OPTION_NAMES)


@dataclass(frozen=True, slots=True)
class OSPFDatabaseDescription:
    """The body of a Database Description packet (RFC 2328 §A.3.3).

    :param interface_mtu: The largest IP datagram the sending interface
        can send unfragmented.
    :param options: The optional capabilities the router supports (see
        :attr:`options_str`).
    :param flags: The I (Init, ``0x04``), M (More, ``0x02``) and MS
        (Master, ``0x01``) bits (see :attr:`flags_str`); the other five
        are carried verbatim.
    :param dd_sequence_number: The exchange's sequence number.
    :param lsa_headers: The headers of the LSAs this packet describes.
    """

    interface_mtu: int
    options: int
    flags: int
    dd_sequence_number: int
    lsa_headers: tuple[OSPFLSAHeader, ...] = ()

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return _DATABASE_DESCRIPTION.pack(
            self.interface_mtu,
            self.options,
            self.flags,
            self.dd_sequence_number,
        ) + b"".join(bytes(header) for header in self.lsa_headers)

    @property
    def options_str(self) -> str:
        """Space-separated names of the Options bits set.

        See :attr:`OSPFHello.options_str`.
        """
        return _bit_names(self.options, _OPTION_NAMES)

    @property
    def flags_str(self) -> str:
        """Space-separated names of the I, M and MS flags set.

        ``"I M MS"`` on the first packet of an exchange, ``"MS"`` on a
        later one from the master, empty on the slave's last.
        """
        return _bit_names(self.flags, _DD_FLAG_NAMES)


@dataclass(frozen=True, slots=True)
class OSPF(Protocol):
    """An OSPFv2 packet (RFC 2328 §A.3).

    The 24-byte header, then the message body after it.

    :param version: The OSPF version; only ``2`` decodes or constructs.
    :param type: The message type: ``1`` Hello, ``2`` Database
        Description, ``3`` Link State Request, ``4`` Link State Update,
        ``5`` Link State Acknowledgment (see :attr:`type_name`). Any
        other value constructs and decodes, its body kept as is.
    :param packet_length: The packet's length in bytes, header included
        and any authentication trailer excluded: ``24 + len(body)``.
    :param router_id: The sending router's Router ID, dotted-decimal.
    :param area_id: The area the packet belongs to; ``0.0.0.0`` is the
        backbone.
    :param checksum: The internet checksum of the whole packet but the
        Authentication field (RFC 2328 §D.4.1), carried verbatim; ``0``
        under cryptographic authentication, which does not compute it.
        Compute and verify it with :mod:`netprotocols.checksum`.
    :param instance_id: The OSPFv2 instance the packet belongs to (RFC
        6549 §2), header byte 14: ``0`` is the base IPv4 unicast
        instance, and the only one before RFC 6549.
    :param au_type: The authentication type (RFC 2328 Appendix D),
        header byte 15: ``0`` none, ``1`` simple password, ``2``
        cryptographic, ``3`` cryptographic with extended sequence
        numbers (RFC 7474) (see :attr:`au_type_name`).
    :param authentication: The 64-bit Authentication field, raw: zero
        or anything under AuType 0, the password under AuType 1, under
        AuType 2 a reserved zero word, the Key ID, Auth Data Len and
        the cryptographic sequence number, and under AuType 3 three
        zero bytes, Auth Data Len and a 32-bit Key ID (RFC 7474 §3)
        (see :attr:`key_id`, :attr:`auth_data_len` and
        :attr:`crypto_sequence_number`).
    :param body: The message after the header, ``packet_length - 24``
        bytes, kept raw and parsed by the accessor for its type. It must
        have that message's framing (see the module docstring).
    :param auth_trailer: Under AuType 2, the message digest that follows
        the packet, and under AuType 3 the 64-bit sequence number and
        the digest: exactly :attr:`auth_data_len` bytes either way;
        empty under any other AuType.

    :raises InvalidFieldError: if ``version`` is not 2, ``packet_length``
        disagrees with ``body``, ``authentication`` is not 8 bytes,
        ``auth_trailer`` is not the size the AuType gives it, or a known
        message type's body does not have its framing.
    """

    version: int
    type: int
    packet_length: int
    router_id: str
    area_id: str
    checksum: int
    instance_id: int
    au_type: int
    authentication: bytes
    body: bytes = b""
    auth_trailer: bytes = b""

    _struct: ClassVar[Struct] = Struct("!BBH4s4sHBB8s")

    #: The cryptographic authentication types, whose trailer follows the
    #: packet and whose packet checksum is not computed: ``2`` (RFC 2328
    #: §D.4.3) and ``3``, which changes the sequence number and the
    #: Authentication field's layout (RFC 7474 §2, §3) and starts Apad,
    #: the value the Authentication Trailer holds while the digest is
    #: computed (RFC 5709 §3.3), with the IP source address (RFC 7474
    #: §5).
    CRYPTOGRAPHIC_AU_TYPES: ClassVar[frozenset[int]] = frozenset({2, 3})

    type_names: ClassVar[dict[int, str]] = {
        _HELLO_TYPE: "Hello",
        _DATABASE_DESCRIPTION_TYPE: "Database Description",
        _LS_REQUEST_TYPE: "Link State Request",
        _LS_UPDATE_TYPE: "Link State Update",
        _LS_ACKNOWLEDGMENT_TYPE: "Link State Acknowledgment",
    }

    au_type_names: ClassVar[dict[int, str]] = {
        0: "Null",
        1: "Simple Password",
        2: "Cryptographic",
        3: "Cryptographic with Extended Sequence Numbers",
    }

    def __post_init__(self) -> None:
        """Check that the fields agree with each other (see the class)."""
        self._check_version(self.version, offset=None)
        size = self._struct.size
        if self.packet_length != size + len(self.body):
            raise InvalidFieldError(
                f"OSPF packet_length {self.packet_length} disagrees with a "
                f"{len(self.body)}-byte body (expected "
                f"{size + len(self.body)})",
                protocol=type(self),
                field="packet_length",
                expected=size + len(self.body),
                actual=self.packet_length,
            )
        if len(self.authentication) != 8:
            raise InvalidFieldError(
                f"OSPF authentication must be 8 bytes, got "
                f"{len(self.authentication)}",
                protocol=type(self),
                field="authentication",
                expected=8,
                actual=len(self.authentication),
            )
        trailer = self._trailer_len(self.au_type, self.authentication)
        if len(self.auth_trailer) != trailer:
            raise InvalidFieldError(
                f"OSPF AuType {self.au_type} takes a {trailer}-byte "
                f"auth_trailer, got {len(self.auth_trailer)}",
                protocol=type(self),
                field="auth_trailer",
                expected=trailer,
                actual=len(self.auth_trailer),
            )
        self._check_body(self.type, self.body, base=None)

    @classmethod
    def _check_version(cls, version: int, *, offset: int | None) -> None:
        """Reject any version but 2.

        :raises InvalidFieldError: ``offset`` is passed through -- ``0``
            from :meth:`decode`, ``None`` from construction.
        """
        if version != _VERSION:
            raise InvalidFieldError(
                f"OSPF version {version} is not decoded: only OSPFv2 (RFC "
                f"2328) is; OSPFv3 (RFC 5340, version 3) is not",
                protocol=cls,
                offset=offset,
                field="version",
                expected=_VERSION,
                actual=version,
            )

    @classmethod
    def _trailer_len(cls, au_type: int, authentication: bytes) -> int:
        """Return the size of the trailer after the packet.

        That is the Auth Data Len byte under cryptographic
        authentication, and nothing otherwise.
        """
        if au_type in cls.CRYPTOGRAPHIC_AU_TYPES:
            return authentication[3]
        return 0

    @classmethod
    def _check_body(cls, type_: int, body: bytes, *, base: int | None) -> None:
        """Check that ``body`` has message ``type_``'s framing.

        :param base: Where ``body`` starts in the :meth:`decode` buffer,
            added to each error's offset; ``None`` from construction,
            which leaves the offset ``None``.
        :raises InvalidFieldError: with ``field="body"``.
        """
        if type_ == _LS_UPDATE_TYPE:
            for _ in _walk_lsas(body, cls, base):
                pass
            return
        framing = _FRAMING.get(type_)
        if framing is None:
            return
        fixed, entry, what = framing
        excess = (len(body) - fixed) % entry
        if len(body) >= fixed and not excess:
            return
        position = 0 if len(body) < fixed else len(body) - excess
        raise InvalidFieldError(
            f"OSPF {cls.type_names[type_]} body is {len(body)} bytes, not "
            f"{fixed} plus whole {entry}-byte {what}s",
            protocol=cls,
            offset=None if base is None else base + position,
            field="body",
            expected=f"{fixed} + n*{entry}",
            actual=len(body),
        )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the header, the body and any authentication trailer.

        Packet Length bounds the body; under cryptographic
        authentication the trailer follows, Auth Data Len bytes: the
        digest, after the 64-bit sequence number under AuType 3.

        :raises TruncatedHeaderError: if ``data`` is shorter than the
            24-byte header, than Packet Length, or than Packet Length
            plus the authentication trailer.
        :raises InvalidFieldError: if the version is not 2, Packet
            Length is below 24, or the body does not have its message
            type's framing.
        """
        (
            version,
            type_,
            packet_length,
            router_id,
            area_id,
            checksum,
            instance_id,
            au_type,
            authentication,
        ) = cls._unpack_fixed(data)
        cls._check_version(version, offset=0)
        size = cls._struct.size
        if packet_length < size:
            raise InvalidFieldError(
                f"OSPF packet_length must be at least {size}, got "
                f"{packet_length}",
                protocol=cls,
                offset=0,
                field="packet_length",
                expected=f">={size}",
                actual=packet_length,
            )
        if packet_length > len(data):
            raise TruncatedHeaderError(
                f"OSPF declares {packet_length} bytes, buffer holds "
                f"{len(data)}",
                protocol=cls,
                offset=0,
                field="packet_length",
                expected=packet_length,
                actual=len(data),
            )
        end = packet_length + cls._trailer_len(au_type, authentication)
        if end > len(data):
            raise TruncatedHeaderError(
                f"OSPF AuType {au_type} authentication trailer ends at "
                f"byte {end}, buffer holds {len(data)}",
                protocol=cls,
                offset=packet_length,
                field="auth_trailer",
                expected=end,
                actual=len(data),
            )
        body = bytes(data[size:packet_length])
        cls._check_body(type_, body, base=size)
        return cls(
            version=version,
            type=type_,
            packet_length=packet_length,
            router_id=bytes_to_ipv4(router_id),
            area_id=bytes_to_ipv4(area_id),
            checksum=checksum,
            instance_id=instance_id,
            au_type=au_type,
            authentication=authentication,
            body=body,
            auth_trailer=bytes(data[packet_length:end]),
        )

    def __bytes__(self) -> bytes:
        """Serialize this packet to its exact on-wire form."""
        return (
            self._struct.pack(
                self.version,
                self.type,
                self.packet_length,
                ipv4_to_bytes(self.router_id),
                ipv4_to_bytes(self.area_id),
                self.checksum,
                self.instance_id,
                self.au_type,
                self.authentication,
            )
            + self.body
            + self.auth_trailer
        )

    @property
    def header_len(self) -> int:
        """Packet Length plus the authentication trailer, if any."""
        # The whole packet, and the trailer after it: OSPF is terminal.
        return self.packet_length + len(self.auth_trailer)

    @property
    def type_name(self) -> str:
        """Display name of the message type, e.g. ``"Hello"``.

        Falls back to ``"unknown (n)"``.
        """
        return self.type_names.get(self.type, f"unknown ({self.type})")

    @property
    def au_type_name(self) -> str:
        """Display name of the authentication type, e.g. ``"Null"``.

        Falls back to ``"unknown (n)"``.
        """
        return self.au_type_names.get(self.au_type, f"unknown ({self.au_type})")

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0xd0a3"``."""
        return hex_str(self.checksum, 6)

    @property
    def _cryptographic(self) -> bool:
        return self.au_type in self.CRYPTOGRAPHIC_AU_TYPES

    @property
    def key_id(self) -> int | None:
        """The Key ID of the key that made the digest.

        The 8-bit Key ID under AuType 2 (RFC 2328 §D.3), the 32-bit one
        in the Authentication field's last four bytes under AuType 3
        (RFC 7474 §3). ``None`` under any other AuType.
        """
        if self.au_type == _AU_TYPE_EXTENDED:
            return int.from_bytes(self.authentication[4:], "big")
        return self.authentication[2] if self._cryptographic else None

    @property
    def auth_data_len(self) -> int | None:
        """The trailer's length in bytes, ``16`` for keyed MD5.

        Under AuType 3 it counts the 8-byte sequence number as well as
        the digest (RFC 7474 §2). ``None`` unless the AuType is 2 or 3.
        """
        return self.authentication[3] if self._cryptographic else None

    @property
    def crypto_sequence_number(self) -> int | None:
        """The cryptographic sequence number, which guards against replay.

        Under AuType 2 it is the Authentication field's last 32 bits,
        which never decrease (RFC 2328 §D.3). Under AuType 3 it is the
        64 bits that open the trailer (RFC 7474 §3), boot count then a
        packet counter that strictly increases (§2), or ``None`` if the
        trailer is shorter than that. ``None`` under any other AuType.
        """
        if self.au_type == _AU_TYPE_EXTENDED:
            if len(self.auth_trailer) < _EXTENDED_SEQUENCE_SIZE:
                return None
            sequence = self.auth_trailer[:_EXTENDED_SEQUENCE_SIZE]
            return int.from_bytes(sequence, "big")
        if not self._cryptographic:
            return None
        return int.from_bytes(self.authentication[4:], "big")

    @property
    def hello(self) -> OSPFHello | None:
        """The Hello message (type 1), parsed; ``None`` for other types."""
        if self.type != _HELLO_TYPE:
            return None
        body = self.body
        mask, interval, options, priority, dead, dr, bdr = _HELLO.unpack_from(
            body
        )
        return OSPFHello(
            network_mask=bytes_to_ipv4(mask),
            hello_interval=interval,
            options=options,
            router_priority=priority,
            router_dead_interval=dead,
            designated_router=bytes_to_ipv4(dr),
            backup_designated_router=bytes_to_ipv4(bdr),
            neighbors=tuple(
                bytes_to_ipv4(body[at : at + _NEIGHBOR_SIZE])
                for at in range(_HELLO.size, len(body), _NEIGHBOR_SIZE)
            ),
        )

    @property
    def database_description(self) -> OSPFDatabaseDescription | None:
        """The Database Description message (type 2), parsed.

        Its LSA headers are included. ``None`` for other types.
        """
        if self.type != _DATABASE_DESCRIPTION_TYPE:
            return None
        mtu, options, flags, sequence = _DATABASE_DESCRIPTION.unpack_from(
            self.body
        )
        return OSPFDatabaseDescription(
            interface_mtu=mtu,
            options=options,
            flags=flags,
            dd_sequence_number=sequence,
            lsa_headers=self._lsa_headers(_DATABASE_DESCRIPTION.size),
        )

    @property
    def ls_requests(self) -> tuple[OSPFLSRequest, ...] | None:
        """The entries of a Link State Request (type 3), in wire order.

        ``None`` for other types.
        """
        if self.type != _LS_REQUEST_TYPE:
            return None
        return tuple(
            OSPFLSRequest(
                ls_type=ls_type,
                link_state_id=bytes_to_ipv4(link_state_id),
                advertising_router=bytes_to_ipv4(router),
            )
            for ls_type, link_state_id, router in _LS_REQUEST.iter_unpack(
                self.body
            )
        )

    @property
    def lsas(self) -> tuple[OSPFLSA, ...] | None:
        """The LSAs of a Link State Update (type 4), in wire order.

        Each is a parsed header and a raw body. ``None`` for other
        types.
        """
        if self.type != _LS_UPDATE_TYPE:
            return None
        body = self.body
        return tuple(
            OSPFLSA(
                header=OSPFLSAHeader._parse(body, start),
                body=body[start + _LSA_HEADER.size : end],
            )
            for start, end in _walk_lsas(body, type(self), None)
        )

    @property
    def ls_acknowledgments(self) -> tuple[OSPFLSAHeader, ...] | None:
        """The LSA headers a Link State Acknowledgment (type 5) carries.

        ``None`` for other types.
        """
        if self.type != _LS_ACKNOWLEDGMENT_TYPE:
            return None
        return self._lsa_headers(0)

    def _lsa_headers(self, start: int) -> tuple[OSPFLSAHeader, ...]:
        body = self.body
        return tuple(
            OSPFLSAHeader._parse(body, offset)
            for offset in range(start, len(body), _LSA_HEADER.size)
        )


def _walk_lsas(
    body: bytes, protocol: type[OSPF], base: int | None
) -> Iterator[tuple[int, int]]:
    """Walk a Link State Update's body, yielding each LSA's bounds.

    Each ``(start, end)`` pair gives ``body[start:end]``, the LSA with
    its header.

    The body must hold exactly the number of LSAs its count gives, each
    at least a header long, and nothing after the last.

    :param base: Added to each error's offset (relative to ``body``);
        ``None`` leaves the offset ``None``.
    :raises InvalidFieldError: with ``field="body"``.

    Bounded: every LSA advances the walk by at least 20 bytes, so a
    hostile count can neither hang nor over-read.
    """
    size = len(body)
    if size < _LSA_COUNT.size:
        raise InvalidFieldError(
            f"OSPF Link State Update body is {size} bytes, too short for "
            f"its {_LSA_COUNT.size}-byte LSA count",
            protocol=protocol,
            offset=base,
            field="body",
            expected=f">={_LSA_COUNT.size}",
            actual=size,
        )
    (count,) = _LSA_COUNT.unpack_from(body)
    cursor = _LSA_COUNT.size
    for index in range(count):
        remaining = size - cursor
        if remaining < _LSA_HEADER.size:
            raise InvalidFieldError(
                f"OSPF Link State Update declares {count} LSAs, but LSA "
                f"{index + 1} has {remaining} bytes for its "
                f"{_LSA_HEADER.size}-byte header",
                protocol=protocol,
                offset=None if base is None else base + cursor,
                field="body",
                expected=_LSA_HEADER.size,
                actual=remaining,
            )
        (length,) = _LSA_LENGTH.unpack_from(body, cursor + _LSA_LENGTH_OFFSET)
        if not _LSA_HEADER.size <= length <= remaining:
            raise InvalidFieldError(
                f"OSPF LSA {index + 1} declares {length} bytes; it needs "
                f"at least {_LSA_HEADER.size} and {remaining} remain",
                protocol=protocol,
                offset=None if base is None else base + cursor,
                field="body",
                expected=f"{_LSA_HEADER.size}-{remaining}",
                actual=length,
            )
        yield cursor, cursor + length
        cursor += length
    if cursor != size:
        raise InvalidFieldError(
            f"OSPF Link State Update carries {size - cursor} bytes after "
            f"its {count} LSAs",
            protocol=protocol,
            offset=None if base is None else base + cursor,
            field="body",
            expected=cursor,
            actual=size,
        )
