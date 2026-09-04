"""ARP packet header (RFC 826)."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import (
    Protocol,
    bytes_to_ipv4,
    bytes_to_mac,
    ipv4_to_bytes,
    mac_to_bytes,
)
from netprotocols._enums import ARPHardwareType, ARPOperation, EtherType
from netprotocols.utils.ipv4 import validate_ipv4_addr
from netprotocols.utils.mac import validate_mac_addr

__all__ = ["ARP"]


@dataclass(frozen=True, slots=True)
class ARP(Protocol):
    """An ARP packet for IPv4-over-Ethernet (the only binding this
    library implements: 6-byte hardware, 4-byte protocol addresses).

    :param htype: Hardware type; ``1`` for Ethernet (see
        :class:`~netprotocols.ARPHardwareType`).
    :param ptype: Protocol type as an EtherType; ``0x0800`` for IPv4
        (see :class:`~netprotocols.EtherType`).
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
        validate_mac_addr(self.sha, protocol=type(self), field="sha")
        validate_mac_addr(self.tha, protocol=type(self), field="tha")
        validate_ipv4_addr(self.spa, protocol=type(self), field="spa")
        validate_ipv4_addr(self.tpa, protocol=type(self), field="tpa")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        htype, ptype, hlen, plen, oper, sha, spa, tha, tpa = cls._unpack_fixed(
            data
        )
        # The addresses below are generated here, from raw bytes, by
        # bytes_to_mac()/bytes_to_ipv4() — they cannot fail the
        # validators the constructor runs, so this builds the instance
        # directly instead (see "Decode-path construction" in _base.py).
        header = object.__new__(cls)
        set_field = object.__setattr__
        set_field(header, "htype", htype)
        set_field(header, "ptype", ptype)
        set_field(header, "hlen", hlen)
        set_field(header, "plen", plen)
        set_field(header, "oper", oper)
        set_field(header, "sha", bytes_to_mac(sha))
        set_field(header, "spa", bytes_to_ipv4(spa))
        set_field(header, "tha", bytes_to_mac(tha))
        set_field(header, "tpa", bytes_to_ipv4(tpa))
        return header

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
    def oper_enum(self) -> ARPOperation | None:
        """The operation code as an :class:`~netprotocols.ARPOperation`,
        or ``None`` for a value this library does not enumerate;
        :attr:`oper` stays the canonical ``int`` (see :attr:`oper_name`
        for the display form)."""
        try:
            return ARPOperation(self.oper)
        except ValueError:
            return None

    @property
    def ptype_name(self) -> str:
        """Display name of the protocol type, e.g. ``"IPv4"``."""
        try:
            return EtherType(self.ptype).display_name
        except ValueError:
            return f"{self.ptype:#06x}"

    @property
    def ptype_enum(self) -> EtherType | None:
        """The protocol type as an :class:`~netprotocols.EtherType` (see
        :attr:`~netprotocols.Ethernet.ethertype_enum`); ``None`` for a
        value this library does not enumerate."""
        try:
            return EtherType(self.ptype)
        except ValueError:
            return None

    @property
    def ptype_hex_str(self) -> str:
        """The protocol type as a hexadecimal string, e.g. ``"0x0800"``."""
        return f"{self.ptype:#06x}"

    @property
    def htype_name(self) -> str:
        """Display name of the hardware type, e.g. ``"Ethernet"``; falls
        back to the numeric value for types this library does not
        name."""
        try:
            return ARPHardwareType(self.htype).display_name
        except ValueError:
            return f"unknown ({self.htype})"

    @property
    def htype_enum(self) -> ARPHardwareType | None:
        """The hardware type as an
        :class:`~netprotocols.ARPHardwareType`, or ``None`` for a value
        this library does not enumerate; :attr:`htype` stays the
        canonical ``int`` (see :attr:`htype_name` for the display
        form)."""
        try:
            return ARPHardwareType(self.htype)
        except ValueError:
            return None

    @property
    def spa_address(self) -> IPv4Address:
        """The sender protocol address as a stdlib
        :class:`~ipaddress.IPv4Address`, for comparison, subnet
        membership, and arithmetic; :attr:`spa` stays the canonical
        string form."""
        return IPv4Address(self.spa)

    @property
    def tpa_address(self) -> IPv4Address:
        """The target protocol address as a stdlib
        :class:`~ipaddress.IPv4Address` (see :attr:`spa_address`)."""
        return IPv4Address(self.tpa)
