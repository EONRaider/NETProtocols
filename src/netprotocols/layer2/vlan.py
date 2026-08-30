"""IEEE 802.1Q VLAN tag header (802.1Q-2018 §9.6, 802.1ad for QinQ).

A VLAN tag is a 4-byte shim between the Ethernet header and the
encapsulated frame: a 2-byte Tag Control Information field (PCP + DEI +
VID) followed by the 2-byte EtherType of the tagged payload. Tags
chain: a QinQ (0x88A8) or legacy double-tagged (0x9100) frame carries
an inner tag whose EtherType is again a tag type, so
``next_protocol`` dispatches recursively and the chain walker sees one
``VLAN`` layer per tag.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol

__all__ = ["VLAN"]


@dataclass(frozen=True, slots=True)
class VLAN(Protocol):
    """One 802.1Q / 802.1ad VLAN tag.

    :param tci: Tag Control Information — PCP (3 bits), DEI (1 bit)
        and VID (12 bits) — carried as the raw 16-bit field.
    :param ethertype: EtherType of the payload that follows this tag.
    """

    tci: int
    ethertype: int

    _struct: ClassVar[Struct] = Struct("!HH")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        tci, ethertype = cls._unpack_fixed(data)
        return cls(tci=tci, ethertype=ethertype)

    def __bytes__(self) -> bytes:
        return self._struct.pack(self.tci, self.ethertype)

    def next_protocol(self) -> type[Protocol] | None:
        from netprotocols.layer2.ethernet import _ethertype_class

        return _ethertype_class(self.ethertype)

    @property
    def pcp(self) -> int:
        """Priority code point (802.1p), 0-7."""
        return self.tci >> 13

    @property
    def dei(self) -> int:
        """Drop eligible indicator, 0-1."""
        return (self.tci >> 12) & 1

    @property
    def vid(self) -> int:
        """VLAN identifier, 0-4094 (0 = priority tag, 0xFFF = wildcard)."""
        return self.tci & 0xFFF

    @property
    def ethertype_name(self) -> str:
        """Display name of the tagged payload's EtherType, e.g. ``"IPv4"``."""
        from netprotocols.layer2.ethernet import _ethertype_name

        return _ethertype_name(self.ethertype)
