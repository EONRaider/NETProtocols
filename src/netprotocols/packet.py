"""Composition of protocol headers into a serializable packet."""

from __future__ import annotations

from dataclasses import replace
from typing import Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["Packet"]


class Packet:
    """An ordered stack of protocol headers, outermost first.

    >>> packet = Packet(ethernet_header, ipv4_header, tcp_header)
    >>> bytes(packet)  # ready to be sent through a raw socket
    """

    __slots__ = ("layers",)

    def __init__(self, *layers: Protocol) -> None:
        for layer in layers:
            if not isinstance(layer, Protocol):
                raise InvalidFieldError(
                    f"Cannot build packet: {layer!r} is not a Protocol"
                )
        self.layers: tuple[Protocol, ...] = layers

    def __bytes__(self) -> bytes:
        return b"".join(bytes(layer) for layer in self.layers)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}{self.layers!r}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Packet):
            return NotImplemented
        return self.layers == other.layers

    def __getitem__(self, index: int) -> Protocol:
        return self.layers[index]

    def __len__(self) -> int:
        return len(self.layers)

    @property
    def payload(self) -> bytes:
        """The serialized form of all layers, outermost first."""
        return bytes(self)

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
        return type(self)(*reversed(rebuilt))
