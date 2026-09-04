"""Composition of protocol headers into a serializable packet."""

from __future__ import annotations

from dataclasses import replace
from typing import Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    ProtocolError,
)

__all__ = ["Packet"]


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
        from netprotocols.layer3.icmp import ICMPv4, ICMPv6
        from netprotocols.layer3.ip import IPv4, IPv6
        from netprotocols.layer4.tcp import TCP
        from netprotocols.layer4.udp import UDP

        rebuilt: list[Protocol] = []
        trailing = payload
        for index in range(len(self.layers) - 1, -1, -1):
            layer = self.layers[index]
            if isinstance(layer, (TCP, UDP, ICMPv6, ICMPv4)):
                enclosing = next(
                    (
                        candidate
                        for candidate in reversed(self.layers[:index])
                        if isinstance(candidate, (IPv4, IPv6))
                    ),
                    None,
                )
                layer = replace(
                    layer,
                    checksum=compute(layer, ip=enclosing, payload=trailing),
                )
            elif isinstance(layer, IPv4):
                layer = replace(layer, checksum=compute(layer))
            rebuilt.append(layer)
            trailing = bytes(layer) + trailing
        return type(self)(*reversed(rebuilt), stopped_by=self.stopped_by)
