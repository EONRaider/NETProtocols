"""Composition of protocol headers into a serializable packet."""

from __future__ import annotations

from dataclasses import MISSING, fields, replace
from typing import TYPE_CHECKING, Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    ProtocolError,
)

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

    from netprotocols.flow import FlowKey
    from netprotocols.layer3.ip import IPv4, IPv6
    from netprotocols.layer3.ipv6_ext import IPv6Routing

__all__ = ["Packet"]


def _refilled[P: DataclassInstance](layer: P, **changes: object) -> P:
    """Rebuild ``layer`` with ``changes``, keeping its decode context.

    :func:`dataclasses.replace` resets every field outside
    ``__init__`` to its default, so the decode context some layers keep
    there (``STUN``'s and ``BGP``'s record that another message follows
    in the segment, ``MPLS``'s and ``LLC``'s view of their payload; see
    :mod:`netprotocols._base`) would be lost, and a rebuilt STUN message
    would end the walk. Filling a checksum changes no byte that context
    was read from, so it is carried across. A field outside
    ``__init__`` with no default is derived in ``__post_init__`` from
    the others, and is left to it.
    """
    rebuilt = replace(layer, **changes)
    for spec in fields(layer):
        if not spec.init and spec.default is not MISSING:
            object.__setattr__(rebuilt, spec.name, getattr(layer, spec.name))
    return rebuilt


def _enclosing_ip(
    layers: tuple[Protocol, ...], index: int
) -> tuple[IPv4 | IPv6 | None, IPv6Routing | None]:
    """Find the IP header and Routing header enclosing ``layers[index]``.

    That is the IP header nearest before it and the last
    :class:`~netprotocols.IPv6Routing` between the two with
    ``segments_left`` above 0, or ``None`` if there is none.

    RFC 8200 §4.1 says each extension header "should occur at most
    once", so a stack with several Routing headers is unusual; a
    receiver processes them in order and skips one with no segments
    left (RFC 8200 §4.4 for unrecognized types, and each type's own
    processing rules: RFC 2460 §4.4, RFC 6554 §4.2, RFC 8754 §4.3),
    so the route ends at the last one that has some. A Routing header
    before the nearest IP header (an outer tunnel's) is not between.
    """
    from netprotocols.layer3.ip import IPv4, IPv6
    from netprotocols.layer3.ipv6_ext import IPv6Routing

    routing: IPv6Routing | None = None
    for layer in reversed(layers[:index]):
        if isinstance(layer, (IPv4, IPv6)):
            return layer, routing
        if (
            routing is None
            and isinstance(layer, IPv6Routing)
            and layer.segments_left > 0
        ):
            routing = layer
    return None, None


def _ip_checksum_extent(
    layers: tuple[Protocol, ...], index: int, minimum: int
) -> int | None:
    """Return the declared bytes from a layer's start to its IP datagram's end.

    The datagram is the nearest IPv4 or IPv6 header before
    ``layers[index]``, and every header between the two counts in the
    offset. Return ``None`` when no IP header encloses the layer,
    IPv6's payload length is zero, or the declared end falls short of
    ``minimum``.

    :param layers: The packet's headers, outermost first.
    :param index: The position of the layer whose checksum input is
        bounded.
    :param minimum: The bytes that layer requires at its start.
    """
    from netprotocols.layer3.ip import IPv4, IPv6

    offset = 0
    for header in reversed(layers[:index]):
        offset += header.header_len
        if isinstance(header, IPv4):
            extent = header.total_length - offset
        elif isinstance(header, IPv6):
            if header.payload_length == 0:
                return None
            extent = header.header_len + header.payload_length - offset
        else:
            continue
        return extent if extent >= minimum else None
    return None


class Packet:
    """An ordered stack of protocol headers, outermost first.

    >>> from netprotocols import TCP, decode_frame
    >>> frame = bytes.fromhex(
    ...     "00005e005302" "00005e005301" "0800"
    ...     "45000028" "00014000" "4006b6cb" "c0000201" "c0000202"
    ...     "c0000050" "00000000" "00000000" "5002ffff" "6b8e0000"
    ... )
    >>> ethernet_header, ipv4_header, tcp_header = decode_frame(frame)
    >>> packet = Packet(ethernet_header, ipv4_header, tcp_header)
    >>> packet[TCP].dst_port
    80
    >>> bytes(packet) == frame  # ready to be sent through a raw socket
    True

    Indexing takes either an ``int`` (position on the wire) or a
    protocol class (first layer of that type): ``packet[0]`` is the
    outermost header, ``packet[TCP]`` is the first ``TCP`` layer —
    raising ``KeyError`` if there isn't one, where :meth:`get` returns
    ``None`` instead. A ``Packet`` is hashable and usable as a dict key
    or set member, consistent with ``__eq__``, which compares the
    layers, :attr:`stopped_by` and :attr:`trailer`.

    ``bytes(packet)`` is the layers alone. A frame
    :func:`~netprotocols.decode_frame` walked is those bytes, then what
    the last layer carries that no decoder read, then the
    :attr:`trailer`::

        undecoded = frame[packet.consumed : len(frame) - len(packet.trailer)]
        assert frame == bytes(packet) + undecoded + packet.trailer

    The constructor takes the headers, outermost first, then two
    keyword-only arguments: ``stopped_by``, the error that ended a lax
    walk, and ``trailer``, the frame's bytes past its declared end, any
    bytes-like object, stored as ``bytes``. It raises
    :class:`~netprotocols.InvalidFieldError` for a layer that is not a
    :class:`~netprotocols._base.Protocol` instance, and for a
    ``trailer`` that is not bytes-like (``field="trailer"``).
    """

    __slots__ = ("layers", "stopped_by", "trailer")

    def __init__(
        self,
        *layers: Protocol,
        stopped_by: ProtocolError | None = None,
        trailer: bytes | bytearray | memoryview = b"",
    ) -> None:
        for layer in layers:
            if not isinstance(layer, Protocol):
                raise InvalidFieldError(
                    f"Cannot build packet: {layer!r} is not a Protocol",
                    protocol=type(layer),
                    expected=Protocol,
                    actual=type(layer),
                )
        if not isinstance(trailer, (bytes, bytearray, memoryview)):
            raise InvalidFieldError(
                f"Cannot build packet: trailer {trailer!r} is not bytes-like",
                protocol=type(trailer),
                field="trailer",
                expected=bytes,
                actual=type(trailer),
            )
        self.layers: tuple[Protocol, ...] = layers
        #: Why the chain walk stopped early, or ``None`` when it ran to
        #: a clean end. Only :func:`~netprotocols.decode_frame` in lax
        #: mode ever sets this; a packet you built yourself has nothing
        #: to report.
        self.stopped_by: ProtocolError | None = stopped_by
        #: The frame's bytes past the end its declared length gives:
        #: an Ethernet or VLAN 802.3 Length, whichever ends first among
        #: the headers the walk decoded. Ethernet's padding of a short
        #: frame and a captured FCS land here. Empty
        #: when no declared end falls short of the frame. Never part of
        #: ``bytes(packet)``, of a layer, or of :attr:`consumed`.
        self.trailer: bytes = bytes(trailer)

    @classmethod
    def _from_decoded(
        cls,
        layers: list[Protocol],
        stopped_by: ProtocolError | None,
        trailer: bytes,
    ) -> Self:
        """Build a packet from headers that ``decode_frame`` decoded.

        This skips ``__init__``'s per-layer ``isinstance`` check.
        Precondition: every item of ``layers`` is a
        :class:`~netprotocols._base.Protocol` instance, which holds for
        :func:`~netprotocols.decode_frame`, the only caller, since it
        passes only what its ``decode()`` calls returned. It builds the
        instance with ``object.__new__``, as :mod:`netprotocols._base`
        does for Ethernet/ARP/IPv4 field construction.

        :param layers: The decoded headers, outermost first.
        :param stopped_by: The error that ended the walk, or ``None``.
        :param trailer: The frame's bytes past the walk's bound, as
            ``bytes``.
        """
        packet = object.__new__(cls)
        packet.layers = tuple(layers)
        packet.stopped_by = stopped_by
        packet.trailer = trailer
        return packet

    def __bytes__(self) -> bytes:
        return b"".join(bytes(layer) for layer in self.layers)

    def __repr__(self) -> str:
        text = f"{self.__class__.__name__}{self.layers!r}"
        if self.stopped_by is not None:
            text += f" stopped_by={self.stopped_by!r}"
        if self.trailer:
            text += f" trailer={self.trailer!r}"
        return text

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Packet):
            return NotImplemented
        return (
            self.layers == other.layers
            and type(self.stopped_by) is type(other.stopped_by)
            and str(self.stopped_by) == str(other.stopped_by)
            and self.trailer == other.trailer
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.layers,
                type(self.stopped_by),
                str(self.stopped_by),
                self.trailer,
            )
        )

    def __getitem__(self, key: int | type[Protocol]) -> Protocol:
        """Return the layer at a position, or the first of a type.

        ``packet[0]`` indexes by position; ``packet[TCP]`` returns the
        first layer of that type in wire order.

        :param key: A position on the wire, or a protocol class.
        :raises IndexError: if ``key`` is a position outside the layers.
        :raises KeyError: if ``key`` is a type that matches no layer
            (dict-like convention: ``[key]`` raises, :meth:`get` returns
            ``None``).
        """
        if isinstance(key, int):
            return self.layers[key]
        for layer in self.layers:
            if isinstance(layer, key):
                return layer
        raise KeyError(key)

    def get(self, layer_type: type[Protocol]) -> Protocol | None:
        """Return the first layer of ``layer_type`` in wire order.

        ``None`` if the packet has none (see ``__getitem__`` for
        the raising form).

        :param layer_type: The protocol class to look for.
        """
        for layer in self.layers:
            if isinstance(layer, layer_type):
                return layer
        return None

    def __len__(self) -> int:
        return len(self.layers)

    def flow_key(self) -> FlowKey | None:
        """Return the canonical flow key of this packet's conversation.

        This walks :attr:`layers` for the first TCP/UDP/SCTP layer and
        the IPv4/IPv6 header nearest before it, and returns
        :func:`~netprotocols.flow.flow_key` of the two, a
        :class:`~netprotocols.flow.FlowKey`.

        Nearest, not first: a tunnel (IP-in-IP, GRE, IPsec tunnel mode)
        stacks an outer IP header whose addresses are the tunnel's
        endpoints, not the conversation's. Layers between that IP header
        and the transport (IPv6 extension headers, AH) are skipped and
        do not change the key's protocol number, which is the
        transport's own. The last IPv6 Routing header between them with
        segments left is passed on, so the key's destination is the
        route's final destination (see
        :func:`~netprotocols.flow.flow_key`).
        VXLAN is different: its outer UDP datagram is the first
        transport layer, so the key is the tunnel's own underlay flow
        (the endpoints' addresses, the source port hashed from the inner
        flow, and the tunnel's port); the inner conversation's key is
        :func:`~netprotocols.flow.flow_key` of the inner transport and
        the IP header before it.

        ``None`` if either layer is missing — a packet with no
        transport layer, or a bare TCP/UDP/SCTP header built without an
        IP header before it — and ``None`` for a transport layer with no
        ports to key on (ICMP; see :func:`~netprotocols.flow.flow_key`).
        """
        from netprotocols.flow import _TRANSPORTS
        from netprotocols.flow import flow_key as _flow_key

        for index, layer in enumerate(self.layers):
            if isinstance(layer, _TRANSPORTS):
                ip, routing = _enclosing_ip(self.layers, index)
                if ip is None:
                    return None
                return _flow_key(layer, ip=ip, routing=routing)
        return None

    @property
    def consumed(self) -> int:
        """Total bytes these headers occupy on the wire.

        After :func:`~netprotocols.decode_frame`, this is the offset at
        which the walk stopped — so ``frame[packet.consumed:]`` is
        whatever the chain did not decode, :attr:`trailer` included, and
        ``frame[packet.consumed : len(frame) - len(packet.trailer)]`` is
        the same without the trailer.
        """
        return sum(layer.header_len for layer in self.layers)

    def with_checksums(self, payload: bytes = b"") -> Self:
        """Return a copy of this packet with its checksum fields recomputed.

        The recomputed fields are TCP's, UDP's, SCTP's, ICMPv4's,
        ICMPv6's, IGMP's, VRRP's and PIM's checksums, the IPv4 header
        checksum, CDP's checksum, GRE's checksum when its Checksum field
        is present (its reserved word, key and sequence number are
        kept), and OSPF's checksum unless the packet uses cryptographic
        authentication. The LS checksums of the LSAs an OSPF packet
        carries are carried over unchanged.

        IGMP's and GRE's checksum inputs end at the declared end of the
        nearest enclosing IPv4 or IPv6 datagram, so Ethernet padding and
        a captured FCS stay out of them; those bytes are kept in the
        returned packet. An IPv6 payload length of zero, or a declared
        end before the layer's required bytes, leaves the input
        unbounded.

        Layers are processed innermost-first so each transport checksum
        covers the final bytes of everything that follows it; ``payload``
        is whatever comes after the last layer on the wire up to the
        :attr:`trailer`, which for a packet
        :func:`~netprotocols.decode_frame` returned is
        ``frame[packet.consumed : len(frame) - len(packet.trailer)]``.
        No checksum covers the trailer, and the returned packet carries
        it unchanged. Instances
        are frozen, so layers are rebuilt with
        :func:`dataclasses.replace`, and the decode context a layer
        records outside its ``__init__`` fields, such as whether another
        STUN message follows it in a TCP segment, is copied across.
        A STUN message's FINGERPRINT attribute is recomputed when it
        has one, last; its MESSAGE-INTEGRITY, which needs a key, is
        left as it is.
        """
        from netprotocols.checksum import compute
        from netprotocols.layer2.cdp import CDP
        from netprotocols.layer3.gre import GRE
        from netprotocols.layer3.icmp import ICMPv4, ICMPv6
        from netprotocols.layer3.igmp import IGMP
        from netprotocols.layer3.ip import IPv4
        from netprotocols.layer3.ospf import OSPF
        from netprotocols.layer3.pim import PIM
        from netprotocols.layer3.vrrp import VRRP
        from netprotocols.layer4.sctp import SCTP
        from netprotocols.layer4.tcp import TCP
        from netprotocols.layer4.udp import UDP
        from netprotocols.layer7.stun import STUN

        rebuilt: list[Protocol] = []
        trailing = payload
        for index in range(len(self.layers) - 1, -1, -1):
            layer = self.layers[index]
            if isinstance(layer, (TCP, UDP, SCTP, ICMPv6, ICMPv4, VRRP, PIM)):
                enclosing, routing = _enclosing_ip(self.layers, index)
                layer = _refilled(
                    layer,
                    checksum=compute(
                        layer, ip=enclosing, routing=routing, payload=trailing
                    ),
                )
            elif isinstance(layer, GRE) and layer.checksum is not None:
                extent = _ip_checksum_extent(
                    self.layers, index, layer.header_len
                )
                covered = (
                    trailing
                    if extent is None
                    else trailing[: extent - layer.header_len]
                )
                checksum = compute(layer, payload=covered).to_bytes(2, "big")
                layer = _refilled(layer, fields=checksum + layer.fields[2:])
            elif isinstance(layer, IGMP):
                fixed = layer.header_len - len(layer.body)
                extent = _ip_checksum_extent(self.layers, index, fixed)
                message = layer
                if extent is not None and extent < layer.header_len:
                    message = _refilled(
                        layer, body=layer.body[: extent - fixed]
                    )
                layer = _refilled(layer, checksum=compute(message))
            elif isinstance(layer, (IPv4, CDP)) or (
                isinstance(layer, OSPF)
                and layer.au_type not in OSPF.CRYPTOGRAPHIC_AU_TYPES
            ):
                layer = _refilled(layer, checksum=compute(layer))
            elif isinstance(layer, STUN) and layer.fingerprint is not None:
                # FINGERPRINT is the last 4 bytes of the attributes.
                fingerprint = compute(layer).to_bytes(4, "big")
                layer = _refilled(
                    layer, attributes=layer.attributes[:-4] + fingerprint
                )
            rebuilt.append(layer)
            trailing = bytes(layer) + trailing
        return type(self)(
            *reversed(rebuilt),
            stopped_by=self.stopped_by,
            trailer=self.trailer,
        )
