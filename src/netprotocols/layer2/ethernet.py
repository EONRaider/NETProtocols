"""Ethernet II frame header (IEEE 802.3)."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_mac, mac_to_bytes
from netprotocols._enums import EtherType
from netprotocols.registry import DEFAULT, TABLE_ETHERTYPE, Registry
from netprotocols.utils.mac import validate_mac_addr

__all__ = ["Ethernet"]

#: The flat ``ethertype`` dispatch table of the default registry, bound
#: once at import. Registering a decoder mutates this dict in place
#: rather than replacing it, so the reference stays live and a lookup
#: stays a bare ``dict.get`` — see :mod:`netprotocols.registry`.
_ETHERTYPE_CLASSES: dict[int, type[Protocol]] = DEFAULT.table(TABLE_ETHERTYPE)


def _ethertype_class(
    ethertype: int, registry: Registry | None = None
) -> type[Protocol] | None:
    """The class that decodes the payload of an Ethernet/VLAN header.

    VLAN tag types dispatch to :class:`~netprotocols.VLAN`, whose own
    ``next_protocol`` calls back here with the inner EtherType — so
    stacked tags (QinQ) decode as one VLAN layer per tag.

    ``registry`` overrides the process-wide tables; omitting it keeps
    the lookup a single ``dict.get`` on the hot path.
    """
    if registry is None:
        return _ETHERTYPE_CLASSES.get(ethertype)
    return registry.get(TABLE_ETHERTYPE, ethertype)


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
        validate_mac_addr(self.dst, protocol=type(self), field="dst")
        validate_mac_addr(self.src, protocol=type(self), field="src")

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

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        return _ethertype_class(self.ethertype, registry)

    @property
    def ethertype_name(self) -> str:
        """Display name of the EtherType, e.g. ``"IPv4"``; falls back to
        the hexadecimal value for types unknown to this library."""
        return _ethertype_name(self.ethertype)

    @property
    def ethertype_enum(self) -> EtherType | None:
        """The EtherType as an :class:`~netprotocols.EtherType`, or
        ``None`` for a value this library does not enumerate;
        :attr:`ethertype` stays the canonical ``int`` and round-trips
        regardless (see :attr:`ethertype_name` for the display form)."""
        try:
            return EtherType(self.ethertype)
        except ValueError:
            return None
