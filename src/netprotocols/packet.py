"""Composition of protocol headers into a serializable packet."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    ProtocolError,
)

if TYPE_CHECKING:
    from netprotocols.flow import FlowKey
    from netprotocols.layer3.ip import IPv4, IPv6
    from netprotocols.layer3.ipv6_ext import IPv6Routing

__all__ = ["Packet"]


def _enclosing_ip(
    layers: tuple[Protocol, ...], index: int
) -> tuple[IPv4 | IPv6 | None, IPv6Routing | None]:
    """Find the IP header and Routing header enclosing ``layers[index]``.

    That is the IP header nearest before it and the last
    :class:`~netprotocols.IPv6Routing` between the two with
    ``segments_left`` above 0, or ``None`` if there is none.

    RFC 8200 §4.1 says each extension header "should occur at most
    once", so a stack with several Routing headers is unusual; a
    receiver processes them in order (§4.4) and skips one with no
    segments left, so the route ends at the last one that has some. A
    Routing header before the nearest IP header (an outer tunnel's) is
    not between.
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


class Packet:
    """An ordered stack of protocol headers, outermost first.

    >>> packet = Packet(ethernet_header, ipv4_header, tcp_header)
    >>> bytes(packet)  # ready to be sent through a raw socket

    Indexing takes either an ``int`` (position on the wire) or a
    protocol class (first layer of that type): ``packet[0]`` is the
    outermost header, ``packet[TCP]`` is the first ``TCP`` layer —
    raising ``KeyError`` if there isn't one, where :meth:`get` returns
    ``None`` instead. A ``Packet`` is hashable and usable as a dict key
    or set member, consistent with :meth:`__eq__`.
    """

    __slots__ = ("layers", "stopped_by")

    def __init__(
        self, *layers: Protocol, stopped_by: ProtocolError | None = None
    ) -> None:
        for layer in layers:
            if not isinstance(layer, Protocol):
                raise InvalidFieldError(
                    f"Cannot build packet: {layer!r} is not a Protocol",
                    protocol=type(layer),
                    expected=Protocol,
                    actual=type(layer),
                )
        self.layers: tuple[Protocol, ...] = layers
        #: Why the chain walk stopped early, or ``None`` when it ran to
        #: a clean end. Only :func:`~netprotocols.decode_frame` in lax
        #: mode ever sets this; a packet you built yourself has nothing
        #: to report.
        self.stopped_by: ProtocolError | None = stopped_by

    @classmethod
    def _from_decoded(
        cls, layers: list[Protocol], stopped_by: ProtocolError | None
    ) -> Self:
        """Build a packet from headers :func:`~netprotocols.decode_frame`
        just decoded, skipping :meth:`__init__`'s per-layer
        ``isinstance`` check.

        Internal only — the public constructor takes arbitrary
        caller-supplied arguments and has to validate them, but
        ``decode_frame`` calls this with a list built exclusively from
        this module's own ``protocol.decode()`` calls, so the
        invariant ``__init__`` checks already holds. Skipping it
        matters: profiling showed that check alone, run through
        :class:`~netprotocols._base.Protocol`'s ABC machinery, as
        ~7-8% of ``decode_frame``'s total time. Same
        ``object.__new__`` shortcut :mod:`netprotocols._base` uses for
        Ethernet/ARP/IPv4 field construction, documented there.
        """
        packet = object.__new__(cls)
        packet.layers = tuple(layers)
        packet.stopped_by = stopped_by
        return packet

    def __bytes__(self) -> bytes:
        return b"".join(bytes(layer) for layer in self.layers)

    def __repr__(self) -> str:
        name = self.__class__.__name__
        if self.stopped_by is None:
            return f"{name}{self.layers!r}"
        return f"{name}{self.layers!r} stopped_by={self.stopped_by!r}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Packet):
            return NotImplemented
        return (
            self.layers == other.layers
            and type(self.stopped_by) is type(other.stopped_by)
            and str(self.stopped_by) == str(other.stopped_by)
        )

    def __hash__(self) -> int:
        return hash((self.layers, type(self.stopped_by), str(self.stopped_by)))

    def __getitem__(self, key: int | type[Protocol]) -> Protocol:
        """``packet[0]`` indexes by position; ``packet[TCP]`` returns the
        first layer of that type in wire order.

        :raises KeyError: a type key matches no layer (dict-like
            convention: ``[key]`` raises, :meth:`get` returns ``None``).
        """
        if isinstance(key, int):
            return self.layers[key]
        for layer in self.layers:
            if isinstance(layer, key):
                return layer
        raise KeyError(key)

    def get(self, layer_type: type[Protocol]) -> Protocol | None:
        """The first layer of ``layer_type`` in wire order, or ``None``
        if the packet has none (see :meth:`__getitem__` for the
        raising form)."""
        for layer in self.layers:
            if isinstance(layer, layer_type):
                return layer
        return None

    def __len__(self) -> int:
        return len(self.layers)

    def flow_key(self) -> FlowKey | None:
        """The canonical :class:`~netprotocols.flow.FlowKey` for this
        packet's conversation, found by walking :attr:`layers` for the
        first TCP/UDP/SCTP layer and the IPv4/IPv6 header nearest
        before it, and delegating to :func:`~netprotocols.flow.flow_key`.

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
        whatever the chain did not decode.
        """
        return sum(layer.header_len for layer in self.layers)

    def with_checksums(self, payload: bytes = b"") -> Self:
        """A copy of this packet with every checksum field computed.

        Layers are processed innermost-first so each transport checksum
        covers the final bytes of everything that follows it; ``payload``
        is whatever comes after the last layer on the wire. Instances
        are frozen, so layers are rebuilt via :func:`dataclasses.replace`.
        """
        from netprotocols.checksum import compute
        from netprotocols.layer2.cdp import CDP
        from netprotocols.layer3.icmp import ICMPv4, ICMPv6
        from netprotocols.layer3.ip import IPv4
        from netprotocols.layer3.ospf import OSPF
        from netprotocols.layer3.pim import PIM
        from netprotocols.layer3.vrrp import VRRP
        from netprotocols.layer4.sctp import SCTP
        from netprotocols.layer4.tcp import TCP
        from netprotocols.layer4.udp import UDP

        rebuilt: list[Protocol] = []
        trailing = payload
        for index in range(len(self.layers) - 1, -1, -1):
            layer = self.layers[index]
            if isinstance(layer, (TCP, UDP, SCTP, ICMPv6, ICMPv4, VRRP, PIM)):
                enclosing, routing = _enclosing_ip(self.layers, index)
                layer = replace(
                    layer,
                    checksum=compute(
                        layer, ip=enclosing, routing=routing, payload=trailing
                    ),
                )
            elif isinstance(layer, (IPv4, CDP)) or (
                isinstance(layer, OSPF)
                and layer.au_type not in OSPF.CRYPTOGRAPHIC_AU_TYPES
            ):
                layer = replace(layer, checksum=compute(layer))
            rebuilt.append(layer)
            trailing = bytes(layer) + trailing
        return type(self)(*reversed(rebuilt), stopped_by=self.stopped_by)
