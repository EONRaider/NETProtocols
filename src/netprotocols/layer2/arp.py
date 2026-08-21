"""ARP packet header (RFC 826)."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import (
    Protocol,
    bytes_to_ipv4,
    bytes_to_mac,
    ipv4_to_bytes,
    mac_to_bytes,
)
from netprotocols._enums import ARPOperation, EtherType
from netprotocols.utils.ipv4 import validate_ipv4_addr
from netprotocols.utils.mac import validate_mac_addr

__all__ = ["ARP"]


@dataclass(frozen=True, slots=True)
class ARP(Protocol):
    """An ARP packet for IPv4-over-Ethernet (the only binding this
    library implements: 6-byte hardware, 4-byte protocol addresses).

    :param htype: Hardware type; ``1`` for Ethernet.
    :param ptype: Protocol type as an EtherType; ``0x0800`` for IPv4.
    :param hlen: Hardware address length in bytes; ``6`` for Ethernet.
    :param plen: Protocol address length in bytes; ``4`` for IPv4.
    :param oper: Operation code; ``1`` request, ``2`` reply (see
        :class:`~netprotocols.ARPOperation`).
    :param sha: Sender hardware address, e.g. ``"00:c0:ca:a8:19:74"``.
    :param spa: Sender protocol address, e.g. ``"192.168.1.96"``.
    :param tha: Target hardware address.
    :param tpa: Target protocol address.
    """

    htype: int
    ptype: int
    hlen: int
    plen: int
    oper: int
    sha: str
    spa: str
    tha: str
    tpa: str

    _struct: ClassVar[Struct] = Struct("!HHBBH6s4s6s4s")

    def __post_init__(self) -> None:
        validate_mac_addr(self.sha)
        validate_mac_addr(self.tha)
        validate_ipv4_addr(self.spa)
        validate_ipv4_addr(self.tpa)

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        htype, ptype, hlen, plen, oper, sha, spa, tha, tpa = cls._unpack_fixed(
            data
        )
        return cls(
            htype=htype,
            ptype=ptype,
            hlen=hlen,
            plen=plen,
            oper=oper,
            sha=bytes_to_mac(sha),
            spa=bytes_to_ipv4(spa),
            tha=bytes_to_mac(tha),
            tpa=bytes_to_ipv4(tpa),
        )

    def __bytes__(self) -> bytes:
        return self._struct.pack(
            self.htype,
            self.ptype,
            self.hlen,
            self.plen,
            self.oper,
            mac_to_bytes(self.sha),
            ipv4_to_bytes(self.spa),
            mac_to_bytes(self.tha),
            ipv4_to_bytes(self.tpa),
        )

    @property
    def oper_name(self) -> str:
        """Display name of the operation: ``"request"`` or ``"reply"``."""
        try:
            return ARPOperation(self.oper).display_name
        except ValueError:
            return f"unknown ({self.oper})"

    @property
    def ptype_name(self) -> str:
        """Display name of the protocol type, e.g. ``"IPv4"``."""
        try:
            return EtherType(self.ptype).display_name
        except ValueError:
            return f"{self.ptype:#06x}"

    @property
    def ptype_hex_str(self) -> str:
        """The protocol type as a hexadecimal string, e.g. ``"0x0800"``."""
        return f"{self.ptype:#06x}"
