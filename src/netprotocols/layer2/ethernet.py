"""Ethernet II frame header (IEEE 802.3)."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_mac, mac_to_bytes
from netprotocols._enums import EtherType
from netprotocols.utils.mac import validate_mac_addr

__all__ = ["Ethernet"]

#: EtherType values that mark a VLAN tag shim rather than a payload.
_VLAN_TAG_ETHERTYPES = frozenset(
    {EtherType.VLAN_TAG, EtherType.VLAN_TAG_QINQ, EtherType.VLAN_TAG_9100}
)


#: Payload dispatch table, populated on first use. The imports it needs
#: must stay deferred to keep the layer modules acyclic (see
#: ARCHITECTURE.md), so the table is built once on the first call rather
#: than at import time — every later call is a plain dict lookup.
_ETHERTYPE_CLASSES: dict[int, type[Protocol]] = {}


def _build_ethertype_classes() -> None:
    """Populate :data:`_ETHERTYPE_CLASSES` (called once, on first use)."""
    from netprotocols.layer2.arp import ARP
    from netprotocols.layer2.vlan import VLAN
    from netprotocols.layer3.ip import IPv4, IPv6

    _ETHERTYPE_CLASSES.update(
        {
            EtherType.ARP: ARP,
            EtherType.IPV4: IPv4,
            EtherType.IPV6: IPv6,
            # A tag type dispatches to VLAN, whose own next_protocol
            # calls back here with the inner EtherType — so stacked tags
            # (QinQ) decode as one VLAN layer per tag.
            **dict.fromkeys(_VLAN_TAG_ETHERTYPES, VLAN),
        }
    )


def _ethertype_class(ethertype: int) -> type[Protocol] | None:
    """The class that decodes the payload of an Ethernet/VLAN header.

    VLAN tag types dispatch to :class:`~netprotocols.VLAN`, whose own
    ``next_protocol`` calls back here with the inner EtherType — so
    stacked tags (QinQ) decode as one VLAN layer per tag.
    """
    if not _ETHERTYPE_CLASSES:
        _build_ethertype_classes()
    return _ETHERTYPE_CLASSES.get(ethertype)


def _ethertype_name(ethertype: int) -> str:
    """Display name of an EtherType, e.g. ``"IPv4"``; falls back to the
    hexadecimal value for types unknown to this library."""
    try:
        return EtherType(ethertype).display_name
    except ValueError:
        return f"{ethertype:#06x}"


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
        # The addresses below are generated here, from raw bytes, by
        # bytes_to_mac()/bytes_to_ipv4() — they cannot fail the
        # validators the constructor runs, so this builds the instance
        # directly instead (see "Decode-path construction" in _base.py).
        header = object.__new__(cls)
        set_field = object.__setattr__
        set_field(header, "dst", bytes_to_mac(dst))
        set_field(header, "src", bytes_to_mac(src))
        set_field(header, "ethertype", ethertype)
        return header

    def __bytes__(self) -> bytes:
        return self._struct.pack(
            mac_to_bytes(self.dst), mac_to_bytes(self.src), self.ethertype
        )

    def next_protocol(self) -> type[Protocol] | None:
        return _ethertype_class(self.ethertype)

    @property
    def ethertype_name(self) -> str:
        """Display name of the EtherType, e.g. ``"IPv4"``; falls back to
        the hexadecimal value for types unknown to this library."""
        return _ethertype_name(self.ethertype)
