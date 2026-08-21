"""Ethernet II frame header (IEEE 802.3)."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_mac, mac_to_bytes
from netprotocols._enums import EtherType
from netprotocols.utils.mac import validate_mac_addr

__all__ = ["Ethernet"]


@dataclass(frozen=True, slots=True)
class Ethernet(Protocol):
    """An Ethernet II header.

    :param dst: Destination hardware address, e.g. ``"ff:ff:ff:ff:ff:ff"``.
    :param src: Source hardware address.
    :param ethertype: EtherType of the encapsulated protocol, e.g.
        ``0x0800`` for IPv4 (see :class:`~netprotocols.EtherType`).
    """

    dst: str
    src: str
    ethertype: int

    _struct: ClassVar[Struct] = Struct("!6s6sH")

    def __post_init__(self) -> None:
        validate_mac_addr(self.dst)
        validate_mac_addr(self.src)

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        dst, src, ethertype = cls._unpack_fixed(data)
        return cls(
            dst=bytes_to_mac(dst), src=bytes_to_mac(src), ethertype=ethertype
        )

    def __bytes__(self) -> bytes:
        return self._struct.pack(
            mac_to_bytes(self.dst), mac_to_bytes(self.src), self.ethertype
        )

    def next_protocol(self) -> type[Protocol] | None:
        from netprotocols.layer2.arp import ARP
        from netprotocols.layer3.ip import IPv4, IPv6

        mapping: dict[int, type[Protocol]] = {
            EtherType.ARP: ARP,
            EtherType.IPV4: IPv4,
            EtherType.IPV6: IPv6,
        }
        return mapping.get(self.ethertype)

    @property
    def ethertype_name(self) -> str:
        """Display name of the EtherType, e.g. ``"IPv4"``; falls back to
        the hexadecimal value for types unknown to this library."""
        try:
            return EtherType(self.ethertype).display_name
        except ValueError:
            return f"{self.ethertype:#06x}"
