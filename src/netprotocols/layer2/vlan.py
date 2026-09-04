"""IEEE 802.1Q VLAN tag header (802.1Q-2018 §9.6, 802.1ad for QinQ).

A VLAN tag is a 4-byte shim between the Ethernet header and the
encapsulated frame: a 2-byte Tag Control Information field (PCP + DEI +
VID) followed by the 2-byte EtherType of the tagged payload. Tags
chain: a QinQ (0x88A8) or legacy double-tagged (0x9100) frame carries
an inner tag whose EtherType is again a tag type, so
``next_protocol`` dispatches recursively and the chain walker sees one
``VLAN`` layer per tag.

Following the house pattern (``IPv6`` stores ``version`` /
``traffic_class`` / ``flow_label``, not the raw first word), the TCI
bitfields are materialized as dataclass fields — ``pcp``, ``dei``,
``vid`` — so serialization surfaces the semantic parts instead of an
opaque integer. The packed 16-bit view remains available as the
``tci`` property.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols._enums import EtherType
from netprotocols.layer2.ethernet import _ethertype_class, _ethertype_name
from netprotocols.registry import Registry
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["VLAN"]


@dataclass(frozen=True, slots=True)
class VLAN(Protocol):
    """One 802.1Q / 802.1ad VLAN tag.

    :param pcp: Priority code point (802.1p), ``0``-``7``.
    :param dei: Drop eligible indicator, ``0`` or ``1``.
    :param vid: VLAN identifier, ``0``-``4095`` (``0`` = priority tag,
        ``0xFFF`` = wildcard).
    :param ethertype: EtherType of the payload that follows this tag
        (see :class:`~netprotocols.EtherType`).
    """

    pcp: int
    dei: int
    vid: int
    ethertype: int

    _struct: ClassVar[Struct] = Struct("!HH")

    def __post_init__(self) -> None:
        if not 0 <= self.pcp <= 7:
            raise InvalidFieldError(
                f"VLAN PCP must be within 0-7, got {self.pcp}",
                protocol=type(self),
                field="pcp",
                expected="0-7",
                actual=self.pcp,
            )
        if self.dei not in (0, 1):
            raise InvalidFieldError(
                f"VLAN DEI must be 0 or 1, got {self.dei}",
                protocol=type(self),
                field="dei",
                expected="0 or 1",
                actual=self.dei,
            )
        if not 0 <= self.vid <= 0xFFF:
            raise InvalidFieldError(
                f"VLAN VID must be within 0-4095, got {self.vid}",
                protocol=type(self),
                field="vid",
                expected="0-4095",
                actual=self.vid,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        tci, ethertype = cls._unpack_fixed(data)
        return cls(
            pcp=tci >> 13,
            dei=(tci >> 12) & 1,
            vid=tci & 0xFFF,
            ethertype=ethertype,
        )

    def __bytes__(self) -> bytes:
        return self._struct.pack(self.tci, self.ethertype)

    @property
    def tci(self) -> int:
        """The raw Tag Control Information word (PCP | DEI | VID)."""
        return (self.pcp << 13) | (self.dei << 12) | self.vid

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        return _ethertype_class(self.ethertype, registry)

    @property
    def ethertype_name(self) -> str:
        """Display name of the tagged payload's EtherType, e.g. ``"IPv4"``."""
        return _ethertype_name(self.ethertype)

    @property
    def ethertype_enum(self) -> EtherType | None:
        """The tagged payload's EtherType as an
        :class:`~netprotocols.EtherType` (see
        :attr:`~netprotocols.Ethernet.ethertype_enum`); ``None`` for a
        value this library does not enumerate."""
        try:
            return EtherType(self.ethertype)
        except ValueError:
            return None
