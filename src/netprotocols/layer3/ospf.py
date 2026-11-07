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
lengths walking the body exactly, each LSA's body with its LS type's
framing (see below) -- so no accessor ever raises. A body
of another type is kept as it is. A malformed body of a known type
fails the whole layer: ``decode`` raises, so a strict walk
raises and a lax one stops after IPv4.

Those framing errors are raised by ``decode``, so although they name
``field="body"``, their ``offset`` is relative to the ``decode`` buffer,
as every decode-time error's is (``24`` is the body's first byte), which
is what lets :func:`~netprotocols.decode_frame` rebase it onto the
frame; the same errors raised by the constructor have no offset.

This module decodes OSPF version 2 over IPv4 only. OSPFv3 (RFC 5340),
which IPv6 carries under the same protocol number, changes the header
and every message, so :meth:`OSPF.decode` rejects any version but 2,
and protocol 89 is absent from the IPv6 dispatch table: an IPv6
packet carrying OSPFv3 ends its walk at the IPv6 header instead of
failing to decode as OSPFv2.

**LSA bodies.** A Link State Update's LSAs decode as a 20-byte LSA
header (§A.4.1) and a raw ``body``, the contents the LS type selects.
:class:`OSPFLSA` parses the body on demand for six LS types, each into a
frozen record:

* ``1`` Router-LSA (§A.4.2): :attr:`OSPFLSA.router`, an
  :class:`OSPFRouterLSA` of :class:`OSPFRouterLink` and
  :class:`OSPFRouterLinkTOS`
* ``2`` Network-LSA (§A.4.3): :attr:`OSPFLSA.network`, an
  :class:`OSPFNetworkLSA`
* ``3`` and ``4`` Summary-LSAs (§A.4.4): :attr:`OSPFLSA.summary`, an
  :class:`OSPFSummaryLSA` of :class:`OSPFSummaryTOS`
* ``5`` AS-external-LSA (§A.4.5) and ``7`` NSSA-LSA (RFC 3101 §2.3),
  which has its layout: :attr:`OSPFLSA.external`, an
  :class:`OSPFExternalLSA` of :class:`OSPFExternalMetric`

Each accessor returns ``None`` for the other LS types, whose bodies
(opaque LSAs, RFC 5250, among them) are kept raw and not checked. The
constructor checks that a body of those six types has its framing -- a
Router-LSA's "# links" and each link's "# TOS" walking the body
exactly, the other types' fixed part and whole entries -- so no
accessor ever raises, and every record re-encodes to the body it came
from. A body without its framing fails the LSA, and with it the update
it is in: ``decode`` raises, as for any malformed body of a known
message type, with the offset of the first byte that breaks it.

The LS Checksum, a Fletcher checksum over the whole LSA but its LS
Age, is computed and verified by
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
x[:header_len]``. Nothing after that is consumed. What may follow,
inside the IP datagram, is an RFC 5613 Link-Local Signaling block,
which a router appends to a Hello or Database Description when it sets
the L bit (``0x10``) in Options. It is left undecoded, after the OSPF
layer: ``decode_frame`` ends the walk at OSPF, and
``frame[packet.consumed : len(frame) - len(packet.trailer)]`` holds it.
An Ethernet frame's padding or FCS, past the IP header's declared
length, is the packet's :attr:`~netprotocols.Packet.trailer`. An LLS
block is not part of the packet the checksum covers, and
:func:`~netprotocols.checksum.verify` does not read it.

``bytes(OSPF.decode(x)) == x[:header_len]`` holds by construction: the
header fields are packed back and the body and authentication
trailer are carried verbatim.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, NoReturn, Self

from netprotocols._base import (
    Protocol,
    bytes_to_ipv4,
    hex_str,
    ipv4_to_bytes,
    slot_setters,
)
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = [
    "OSPF",
    "OSPFLSA",
    "OSPFDatabaseDescription",
    "OSPFExternalLSA",
    "OSPFExternalMetric",
    "OSPFHello",
    "OSPFLSAHeader",
    "OSPFLSRequest",
    "OSPFNetworkLSA",
    "OSPFRouterLSA",
    "OSPFRouterLink",
    "OSPFRouterLinkTOS",
    "OSPFSummaryLSA",
    "OSPFSummaryTOS",
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


#: The LS types whose bodies decode (RFC 2328 §A.4.2-§A.4.5, RFC 3101
#: §2.3 for the NSSA-LSA, which has the AS-external-LSA's layout).
_ROUTER_LSA = 1
_NETWORK_LSA = 2
_SUMMARY_LSAS = frozenset({3, 4})
_EXTERNAL_LSAS = frozenset({5, 7})

#: A Router-LSA's flags byte, a reserved byte and its "# links" (RFC
#: 2328 §A.4.2).
_ROUTER_FIXED = Struct("!BBH")
#: A router link: Link ID, Link Data, Type, "# TOS" and its metric
#: (RFC 2328 §A.4.2).
_ROUTER_LINK = Struct("!4s4sBBH")
_ROUTER_LINK_TOS_COUNT_OFFSET = 9
#: A router link's TOS entry: TOS, a reserved byte, TOS metric.
_ROUTER_TOS = Struct("!BBH")
#: A Network Mask, a Network-LSA's attached router, or a byte and a
#: 24-bit metric: a Summary-LSA's TOS entry, or an AS-external-LSA's
#: E bit, TOS and metric.
_WORD = Struct("!I")
#: The Forwarding Address and External Route Tag after an
#: AS-external-LSA's E bit, TOS and metric (RFC 2328 §A.4.5).
_EXTERNAL_TAIL = Struct("!4sI")
_METRIC_MASK = 0xFFFFFF
_EXTERNAL_ENTRY_SIZE = _WORD.size + _EXTERNAL_TAIL.size

#: The bodies made of a fixed part and whole fixed-size entries: the
#: fixed part's size, each entry's size, and what the entries are. A
#: Summary-LSA's fixed part is the Network Mask and the TOS 0 metric;
#: an AS-external-LSA's, the Network Mask and the TOS 0 entry.
_LSA_FRAMING: dict[int, tuple[int, int, str]] = {
    _NETWORK_LSA: (_WORD.size, _WORD.size, "attached routers"),
    3: (2 * _WORD.size, _WORD.size, "TOS entries"),
    4: (2 * _WORD.size, _WORD.size, "TOS entries"),
    5: (_WORD.size + _EXTERNAL_ENTRY_SIZE, _EXTERNAL_ENTRY_SIZE, "TOS entries"),
    7: (_WORD.size + _EXTERNAL_ENTRY_SIZE, _EXTERNAL_ENTRY_SIZE, "TOS entries"),
}

#: A Router-LSA's flags (RFC 2328 §A.4.2), most significant first: Nt
#: (NSSA border router translating Type-7 LSAs unconditionally, RFC 3101
#: Appendix B and §3.1), W (wildcard multicast receiver, RFC 1584), V
#: (virtual link endpoint), E (AS boundary router) and B (area border
#: router).
_ROUTER_FLAG_NAMES = (
    (0x10, "Nt"),
    (0x08, "W"),
    (0x04, "V"),
    (0x02, "E"),
    (0x01, "B"),
)
_V_BIT = 0x04
_E_BIT = 0x02
_B_BIT = 0x01
#: An AS-external-LSA entry's E bit, the top bit of its TOS byte.
_EXTERNAL_E_BIT = 0x80
#: An AS-external-LSA entry's TOS, the 7 bits after its E bit.
_EXTERNAL_TOS_MASK = 0x7F

#: Router link types (RFC 2328 §A.4.2).
_ROUTER_LINK_TYPE_NAMES: dict[int, str] = {
    1: "Point-to-point",
    2: "Transit",
    3: "Stub",
    4: "Virtual link",
}


def _bit_names(value: int, names: tuple[tuple[int, str], ...]) -> str:
    """Return the space-separated names of the bits set in ``value``."""
    return " ".join(name for bit, name in names if value & bit)


def _ls_type_name(ls_type: int) -> str:
    """Return the display name of an LS type, or ``"unknown (n)"``."""
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

        ``"unknown (n)"`` for a value this library does not name
        (degrades, never raises).
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
class OSPFRouterLinkTOS:
    """A TOS-specific metric of a router link (RFC 2328 §A.4.2).

    :param tos: The IP Type of Service the metric is for, in RFC 2328
        §12.3's encoding.
    :param metric: The 16-bit cost of the link for that TOS.
    :param reserved: The byte between the two, zero on send, carried
        verbatim.
    """

    tos: int
    metric: int
    reserved: int = 0

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return _ROUTER_TOS.pack(self.tos, self.reserved, self.metric)


@dataclass(frozen=True, slots=True)
class OSPFRouterLink:
    """One link of a Router-LSA (RFC 2328 §A.4.2).

    :param link_id: The Link ID, dotted-decimal: the neighbor's Router
        ID on a point-to-point or virtual link, the Designated Router's
        interface address on a transit network, the network number on
        a stub network.
    :param link_data: The Link Data, dotted-decimal: the router's own
        interface address, or a stub network's mask (an unnumbered
        point-to-point link's MIB-II ifIndex, as an address).
    :param type: The link type, ``1`` point-to-point, ``2`` transit,
        ``3`` stub, ``4`` virtual link (see :attr:`type_name`).
    :param metric: The 16-bit cost of the link for TOS 0.
    :param tos: The link's TOS-specific metrics, in wire order; their
        number is the link's "# TOS".
    """

    link_id: str
    link_data: str
    type: int
    metric: int
    tos: tuple[OSPFRouterLinkTOS, ...] = ()

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return _ROUTER_LINK.pack(
            ipv4_to_bytes(self.link_id),
            ipv4_to_bytes(self.link_data),
            self.type,
            len(self.tos),
            self.metric,
        ) + b"".join(bytes(entry) for entry in self.tos)

    @property
    def tos_count(self) -> int:
        """The link's "# TOS": how many TOS-specific metrics it lists."""
        return len(self.tos)

    @property
    def type_name(self) -> str:
        """Display name of the link type, e.g. ``"Transit"``.

        ``"unknown (n)"`` for a value this library does not name
        (degrades, never raises).
        """
        return _ROUTER_LINK_TYPE_NAMES.get(self.type, f"unknown ({self.type})")


@dataclass(frozen=True, slots=True)
class OSPFRouterLSA:
    """The body of a Router-LSA, LS type 1 (RFC 2328 §A.4.2).

    :param flags: The flags byte: B (``0x01``, area border router), E
        (``0x02``, AS boundary router) and V (``0x04``, virtual link
        endpoint), RFC 1584's W (``0x08``, wildcard multicast
        receiver) and RFC 3101's Nt (``0x10``, an NSSA border router
        translating Type-7 LSAs unconditionally, Appendix B and §3.1);
        the other bits are carried verbatim (see
        :attr:`flags_str`).
    :param links: The router's links in the area, in wire order; their
        number is the LSA's "# links".
    :param reserved: The byte after the flags, zero on send, carried
        verbatim.
    """

    flags: int
    links: tuple[OSPFRouterLink, ...] = ()
    reserved: int = 0

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return _ROUTER_FIXED.pack(
            self.flags, self.reserved, len(self.links)
        ) + b"".join(bytes(link) for link in self.links)

    @property
    def link_count(self) -> int:
        """The LSA's "# links": how many links it describes."""
        return len(self.links)

    @property
    def v(self) -> bool:
        """Whether the V bit is set: the router ends a virtual link."""
        return bool(self.flags & _V_BIT)

    @property
    def e(self) -> bool:
        """Whether the E bit is set: the router is an AS boundary router."""
        return bool(self.flags & _E_BIT)

    @property
    def b(self) -> bool:
        """Whether the B bit is set: the router is an area border router."""
        return bool(self.flags & _B_BIT)

    @property
    def flags_str(self) -> str:
        """Space-separated names of the flags set, e.g. ``"E B"``.

        Most significant first: ``Nt``, ``W``, ``V``, ``E``, ``B``;
        empty when none is set.
        """
        return _bit_names(self.flags, _ROUTER_FLAG_NAMES)


@dataclass(frozen=True, slots=True)
class OSPFNetworkLSA:
    """The body of a Network-LSA, LS type 2 (RFC 2328 §A.4.3).

    :param network_mask: The network's mask, dotted-decimal.
    :param attached_routers: The Router IDs of the routers fully
        adjacent to the Designated Router, the Designated Router's own
        included, in wire order.
    """

    network_mask: str
    attached_routers: tuple[str, ...] = ()

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return ipv4_to_bytes(self.network_mask) + b"".join(
            ipv4_to_bytes(router) for router in self.attached_routers
        )


@dataclass(frozen=True, slots=True)
class OSPFSummaryTOS:
    """A TOS-specific metric of a Summary-LSA (RFC 2328 §A.4.4).

    :param tos: The IP Type of Service the metric is for, in RFC 2328
        §12.3's encoding.
    :param metric: The 24-bit cost of the route for that TOS.
    """

    tos: int
    metric: int

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return bytes([self.tos]) + self.metric.to_bytes(3, "big")


@dataclass(frozen=True, slots=True)
class OSPFSummaryLSA:
    """The body of a Summary-LSA, LS type 3 or 4 (RFC 2328 §A.4.4).

    A type 3 describes a route to a network outside the area, which
    the Link State ID names; a type 4 describes a route to an AS
    boundary router, whose Router ID the Link State ID is.

    :param network_mask: The destination network's mask,
        dotted-decimal; ``0.0.0.0`` in a type 4, where it has no
        meaning.
    :param metric: The 24-bit cost of the route for TOS 0.
    :param tos: The route's TOS-specific metrics, in wire order.
    :param reserved: The byte before the metric, zero on send, carried
        verbatim.
    """

    network_mask: str
    metric: int
    tos: tuple[OSPFSummaryTOS, ...] = ()
    reserved: int = 0

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        base = OSPFSummaryTOS(self.reserved, self.metric)
        return ipv4_to_bytes(self.network_mask) + b"".join(
            bytes(entry) for entry in (base, *self.tos)
        )


@dataclass(frozen=True, slots=True)
class OSPFExternalMetric:
    """One TOS entry of an AS-external-LSA or NSSA-LSA (RFC 2328 §A.4.5).

    :param e_bit: The E bit: ``True`` for a Type 2 external metric,
        larger than any link state path, ``False`` for a Type 1 metric,
        comparable to the link state metric.
    :param tos: The IP Type of Service the entry is for, the 7 bits
        after the E bit, in RFC 2328 §12.3's encoding; ``0`` in the
        first entry.
    :param metric: The 24-bit cost of the route for that TOS.
    :param forwarding_address: Where traffic for the destination is
        forwarded, dotted-decimal; ``0.0.0.0`` for the LSA's
        originator.
    :param external_route_tag: A 32-bit tag OSPF itself does not use.
    """

    e_bit: bool
    tos: int
    metric: int
    forwarding_address: str
    external_route_tag: int

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form.

        :raises ValueError: if ``tos`` is not in ``range(0, 128)``, the
            7 bits after the E bit.
        """
        if not 0 <= self.tos <= _EXTERNAL_TOS_MASK:
            raise ValueError(
                "an AS-external-LSA TOS must be in range(0, 128), "
                f"got {self.tos}"
            )
        first = (_EXTERNAL_E_BIT if self.e_bit else 0) | self.tos
        return (
            bytes([first])
            + self.metric.to_bytes(3, "big")
            + _EXTERNAL_TAIL.pack(
                ipv4_to_bytes(self.forwarding_address),
                self.external_route_tag,
            )
        )


@dataclass(frozen=True, slots=True)
class OSPFExternalLSA:
    """The body of an AS-external-LSA or an NSSA-LSA.

    An AS-external-LSA is LS type 5 (RFC 2328 §A.4.5); an NSSA-LSA, LS
    type 7, has the same layout (RFC 3101 §2.3). Either describes a
    route to a destination outside the AS, which the Link State ID
    names.

    :param network_mask: The destination's mask, dotted-decimal.
    :param metrics: One entry per TOS, in wire order, the TOS 0 entry
        first.
    """

    network_mask: str
    metrics: tuple[OSPFExternalMetric, ...]

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form.

        :raises ValueError: if a metric's ``tos`` is not in
            ``range(0, 128)``.
        """
        return ipv4_to_bytes(self.network_mask) + b"".join(
            bytes(entry) for entry in self.metrics
        )


@dataclass(frozen=True, slots=True)
class OSPFLSA:
    """One LSA from a Link State Update: its header and its body.

    The body is kept raw; :attr:`router`, :attr:`network`,
    :attr:`summary` and :attr:`external` parse it on demand for the LS
    types they decode, 1 to 5 and 7, and answer ``None`` for any other.
    The constructor checks that the body of one of those types has its
    framing, so none of them ever raises.

    :param header: The 20-byte LSA header (RFC 2328 §A.4.1).
    :param body: Everything after the header, ``header.length - 20``
        bytes, kept raw. A body of LS type 1 to 5 or 7 must have that
        type's framing: a Router-LSA's 4 fixed bytes and exactly its
        "# links" whole links, each with its "# TOS" whole TOS entries;
        a Network-LSA's mask and whole attached routers; a
        Summary-LSA's mask, metric and whole TOS entries; an
        AS-external-LSA's or NSSA-LSA's mask, TOS 0 entry and whole TOS
        entries.

    :raises InvalidFieldError: if ``body`` is not ``header.length - 20``
        bytes, or a body of LS type 1 to 5 or 7 does not have its
        framing.
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
        _check_lsa_body(self.header.ls_type, self.body, type(self), None)

    def __bytes__(self) -> bytes:
        """Serialize this record to its exact on-wire form."""
        return bytes(self.header) + self.body

    @property
    def router(self) -> OSPFRouterLSA | None:
        """The Router-LSA body (LS type 1), parsed.

        ``None`` for other LS types.
        """
        if self.header.ls_type != _ROUTER_LSA:
            return None
        body = self.body
        flags, reserved, count = _ROUTER_FIXED.unpack_from(body)
        links = []
        cursor = _ROUTER_FIXED.size
        for _ in range(count):
            link_id, link_data, type_, tos_count, metric = (
                _ROUTER_LINK.unpack_from(body, cursor)
            )
            cursor += _ROUTER_LINK.size
            end = cursor + tos_count * _ROUTER_TOS.size
            tos = tuple(
                OSPFRouterLinkTOS(tos=tos, metric=tos_metric, reserved=byte)
                for tos, byte, tos_metric in _ROUTER_TOS.iter_unpack(
                    body[cursor:end]
                )
            )
            cursor = end
            links.append(
                OSPFRouterLink(
                    link_id=bytes_to_ipv4(link_id),
                    link_data=bytes_to_ipv4(link_data),
                    type=type_,
                    metric=metric,
                    tos=tos,
                )
            )
        return OSPFRouterLSA(flags=flags, links=tuple(links), reserved=reserved)

    @property
    def network(self) -> OSPFNetworkLSA | None:
        """The Network-LSA body (LS type 2), parsed.

        ``None`` for other LS types.
        """
        if self.header.ls_type != _NETWORK_LSA:
            return None
        body = self.body
        mask, *routers = (
            bytes_to_ipv4(body[at : at + _WORD.size])
            for at in range(0, len(body), _WORD.size)
        )
        return OSPFNetworkLSA(
            network_mask=mask, attached_routers=tuple(routers)
        )

    @property
    def summary(self) -> OSPFSummaryLSA | None:
        """The Summary-LSA body (LS type 3 or 4), parsed.

        ``None`` for other LS types.
        """
        if self.header.ls_type not in _SUMMARY_LSAS:
            return None
        body = self.body
        base, *tos = (
            OSPFSummaryTOS(tos=word >> 24, metric=word & _METRIC_MASK)
            for (word,) in _WORD.iter_unpack(body[_WORD.size :])
        )
        return OSPFSummaryLSA(
            network_mask=bytes_to_ipv4(body[: _WORD.size]),
            metric=base.metric,
            tos=tuple(tos),
            reserved=base.tos,
        )

    @property
    def external(self) -> OSPFExternalLSA | None:
        """The AS-external-LSA or NSSA-LSA body (LS type 5 or 7), parsed.

        ``None`` for other LS types.
        """
        if self.header.ls_type not in _EXTERNAL_LSAS:
            return None
        body = self.body
        metrics = []
        for cursor in range(_WORD.size, len(body), _EXTERNAL_ENTRY_SIZE):
            (word,) = _WORD.unpack_from(body, cursor)
            forwarding_address, tag = _EXTERNAL_TAIL.unpack_from(
                body, cursor + _WORD.size
            )
            metrics.append(
                OSPFExternalMetric(
                    e_bit=bool(word >> 24 & _EXTERNAL_E_BIT),
                    tos=word >> 24 & _EXTERNAL_TOS_MASK,
                    metric=word & _METRIC_MASK,
                    forwarding_address=bytes_to_ipv4(forwarding_address),
                    external_route_tag=tag,
                )
            )
        return OSPFExternalLSA(
            network_mask=bytes_to_ipv4(body[: _WORD.size]),
            metrics=tuple(metrics),
        )


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
        """Display name of the LS type, e.g. ``"Router-LSA"``.

        ``"unknown (n)"`` for a value this library does not name
        (degrades, never raises).
        """
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
    :param au_type: The authentication type (RFC 2328 §D),
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

        :param version: The version to check.
        :param offset: The offset a raised error carries: ``0`` from
            :meth:`decode`, ``None`` from construction.
        :raises InvalidFieldError: if ``version`` is not 2.
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

        :param type_: The message type, whose framing ``body`` must have.
        :param body: The message body after the 24-byte header.
        :param base: Where ``body`` starts in the :meth:`decode` buffer,
            added to each error's offset; ``None`` from construction,
            which leaves the offset ``None``.
        :raises InvalidFieldError: if ``body`` does not have the
            framing, with ``field="body"``.
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

        :param data: The buffer, starting at the Version byte.
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
        # Every check __post_init__ runs holds here, so the instance is
        # built directly, without it (see "Decode-path construction" in
        # _base.py): the version and the body's framing are checked
        # above, the body is packet_length - 24 bytes, the
        # Authentication field is the struct's 8 bytes, and the trailer
        # is sliced to the length the AuType gives after the buffer is
        # confirmed to hold it.
        (
            set_version,
            set_type,
            set_packet_length,
            set_router_id,
            set_area_id,
            set_checksum,
            set_instance_id,
            set_au_type,
            set_authentication,
            set_body,
            set_auth_trailer,
        ) = _OSPF_SETTERS
        header = object.__new__(cls)
        set_version(header, version)
        set_type(header, type_)
        set_packet_length(header, packet_length)
        set_router_id(header, bytes_to_ipv4(router_id))
        set_area_id(header, bytes_to_ipv4(area_id))
        set_checksum(header, checksum)
        set_instance_id(header, instance_id)
        set_au_type(header, au_type)
        set_authentication(header, authentication)
        set_body(header, body)
        set_auth_trailer(header, bytes(data[packet_length:end]))
        return header

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
        """The whole message: Packet Length plus the authentication trailer.

        The trailer is empty when the packet has none. OSPF is terminal.
        """
        return self.packet_length + len(self.auth_trailer)

    @property
    def type_name(self) -> str:
        """Display name of the message type, e.g. ``"Hello"``.

        ``"unknown (n)"`` for a value this library does not name
        (degrades, never raises).
        """
        return self.type_names.get(self.type, f"unknown ({self.type})")

    @property
    def au_type_name(self) -> str:
        """Display name of the authentication type, e.g. ``"Null"``.

        ``"unknown (n)"`` for a value this library does not name
        (degrades, never raises).
        """
        return self.au_type_names.get(self.au_type, f"unknown ({self.au_type})")

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0xd0a3"``."""
        return hex_str(self.checksum, 6)

    @property
    def _cryptographic(self) -> bool:
        """Whether the AuType is 2 or 3, cryptographic authentication."""
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

        Each is a parsed header and a raw body, which :class:`OSPFLSA`
        parses on demand. ``None`` for other types.
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
        """Parse the LSA headers that fill :attr:`body` from ``start``."""
        body = self.body
        return tuple(
            OSPFLSAHeader._parse(body, offset)
            for offset in range(start, len(body), _LSA_HEADER.size)
        )


#: The slot setters :meth:`OSPF.decode` builds its instance with.
_OSPF_SETTERS = slot_setters(
    OSPF,
    "version",
    "type",
    "packet_length",
    "router_id",
    "area_id",
    "checksum",
    "instance_id",
    "au_type",
    "authentication",
    "body",
    "auth_trailer",
)


def _walk_lsas(
    body: bytes, protocol: type[OSPF], base: int | None
) -> Iterator[tuple[int, int]]:
    """Walk a Link State Update's body, yielding each LSA's bounds.

    Each ``(start, end)`` pair gives ``body[start:end]``, the LSA with
    its header.

    The body must hold exactly the number of LSAs its count gives, each
    at least a header long, and nothing after the last.

    :param body: The Link State Update's body.
    :param protocol: The class to attach to a raised error.
    :param base: Added to each error's offset (relative to ``body``);
        ``None`` leaves the offset ``None``.
    :raises InvalidFieldError: if the body does not hold exactly the
        LSAs its count gives, or an LSA's body does not have its LS
        type's framing (see :class:`OSPFLSA`), with ``field="body"``.

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
        body_start = cursor + _LSA_HEADER.size
        _check_lsa_body(
            body[cursor + 3],
            body[body_start : cursor + length],
            protocol,
            None if base is None else base + body_start,
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


def _check_lsa_body(
    ls_type: int, body: bytes, protocol: type, base: int | None
) -> None:
    """Check that an LSA's body has its LS type's framing.

    A Router-LSA's "# links" and each link's "# TOS" must walk the body
    exactly; the other decoded types' bodies are a fixed part and whole
    entries (see :class:`OSPFLSA`). Any other LS type's body is not
    checked.

    :param ls_type: The LSA's LS type.
    :param body: The LSA's body, after its 20-byte header.
    :param protocol: The class to attach to a raised error.
    :param base: Added to each error's offset (relative to ``body``);
        ``None`` leaves the offset ``None``.
    :raises InvalidFieldError: if ``body`` does not have the framing,
        with ``field="body"``.
    """
    if ls_type == _ROUTER_LSA:
        _check_router_body(body, protocol, base)
        return
    framing = _LSA_FRAMING.get(ls_type)
    if framing is None:
        return
    fixed, entry, what = framing
    excess = (len(body) - fixed) % entry
    if len(body) >= fixed and not excess:
        return
    position = 0 if len(body) < fixed else len(body) - excess
    raise InvalidFieldError(
        f"OSPF {_ls_type_name(ls_type)} body is {len(body)} bytes, not "
        f"{fixed} plus whole {entry}-byte {what}",
        protocol=protocol,
        offset=None if base is None else base + position,
        field="body",
        expected=f"{fixed} + n*{entry}",
        actual=len(body),
    )


def _check_router_body(body: bytes, protocol: type, base: int | None) -> None:
    """Check that a Router-LSA's links walk its body exactly.

    Bounded: every link advances the walk by at least 12 bytes, so a
    hostile "# links" can neither hang nor over-read.

    :param body: The Router-LSA's body, after its 20-byte header.
    :param protocol: The class to attach to a raised error.
    :param base: Added to each error's offset (relative to ``body``);
        ``None`` leaves the offset ``None``.
    :raises InvalidFieldError: if the body is shorter than its 4 fixed
        bytes, a link or its TOS entries run past it, or bytes follow
        the last link, with ``field="body"``.
    """
    size = len(body)

    def fail(message: str, position: int, expected: object) -> NoReturn:
        raise InvalidFieldError(
            f"OSPF Router-LSA {message}",
            protocol=protocol,
            offset=None if base is None else base + position,
            field="body",
            expected=expected,
            actual=size,
        )

    if size < _ROUTER_FIXED.size:
        fail(
            f"body is {size} bytes, too short for its "
            f"{_ROUTER_FIXED.size} fixed bytes",
            0,
            f">={_ROUTER_FIXED.size}",
        )
    _, _, count = _ROUTER_FIXED.unpack_from(body)
    cursor = _ROUTER_FIXED.size
    for index in range(count):
        if size - cursor < _ROUTER_LINK.size:
            fail(
                f"declares {count} links, but link {index + 1} has "
                f"{size - cursor} bytes for its {_ROUTER_LINK.size} fixed "
                f"bytes",
                cursor,
                f">={cursor + _ROUTER_LINK.size}",
            )
        tos_count = body[cursor + _ROUTER_LINK_TOS_COUNT_OFFSET]
        end = cursor + _ROUTER_LINK.size + tos_count * _ROUTER_TOS.size
        if end > size:
            fail(
                f"link {index + 1} declares {tos_count} TOS entries, so "
                f"it ends at byte {end}, past the {size}-byte body",
                cursor,
                f">={end}",
            )
        cursor = end
    if cursor != size:
        fail(
            f"carries {size - cursor} bytes after its {count} links",
            cursor,
            cursor,
        )
