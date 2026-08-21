"""Composition of protocol headers into a serializable packet."""

from __future__ import annotations

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
