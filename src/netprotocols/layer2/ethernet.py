"""Ethernet frame header (IEEE 802.3): Ethernet II and 802.3 framing.

Bytes 12-13 are a type or a length (IEEE 802.3 Clause 3.2.6), and
:attr:`Ethernet.ethertype` holds them raw either way. A value of 0x0600
or more is an EtherType and dispatches through the ``ethertype`` table;
one of 1500 or less is the length of an 802.2 LLC PDU, and
:meth:`Ethernet.next_protocol` answers :class:`~netprotocols.LLC`; the
undefined 1501-1535 end the walk. See :mod:`netprotocols.layer2.llc`,
which also describes how :func:`~netprotocols.decode_frame` keeps the
padding after an LLC PDU out of the layers it decodes.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_mac, mac_to_bytes
from netprotocols._enums import EtherType
from netprotocols.layer2.llc import LLC
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


#: The type/length boundaries of IEEE 802.3 Clause 3.2.6: a value up to
#: ``_MAX_LENGTH`` is a length, one from ``_MIN_ETHERTYPE`` a type.
_MAX_LENGTH = 1500
_MIN_ETHERTYPE = 0x0600


def _type_or_length_class(
    value: int, registry: Registry | None = None
) -> type[Protocol] | None:
    """Return the class that decodes what follows a Length/Type field.

    An EtherType (0x0600 or more) dispatches as
    :func:`_ethertype_class` does; a length (1500 or less) is followed
    by an 802.2 LLC header, so it answers :class:`~netprotocols.LLC`,
    named directly as no table is consulted; the undefined values
    between answer ``None``. Ethernet and VLAN read the field this way.
    GRE's Protocol Type and a SNAP PID are EtherTypes only, and go to
    :func:`_ethertype_class` (or its table) instead.
    """
    if value >= _MIN_ETHERTYPE:
        if registry is None:
            return _ETHERTYPE_CLASSES.get(value)
        return registry.get(TABLE_ETHERTYPE, value)
    return LLC if value <= _MAX_LENGTH else None


def _length(value: int) -> int | None:
    """Return the 802.3 Length in a Length/Type field, or ``None``.

    ``None`` when the field holds an EtherType or an undefined value.
    """
    return value if value <= _MAX_LENGTH else None


def _ethertype_name(ethertype: int) -> str:
    """Display name of an EtherType, e.g. ``"IPv4"``; falls back to the
    hexadecimal value for types unknown to this library."""
    try:
        return EtherType(ethertype).display_name
    except ValueError:
        return f"{ethertype:#06x}"


def _ethertype_enum(ethertype: int) -> EtherType | None:
    """The ``EtherType`` member for a numeric value, or ``None`` if it
    isn't one this library recognizes."""
    try:
        return EtherType(ethertype)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class Ethernet(Protocol):
    """An Ethernet II or IEEE 802.3 header.

    :param dst: Destination hardware address, e.g. ``"ff:ff:ff:ff:ff:ff"``.
    :param src: Source hardware address.
    :param ethertype: The raw Length/Type field: the EtherType of the
        encapsulated protocol, e.g. ``0x0800`` for IPv4 (see
        :class:`~netprotocols.EtherType`), or, at 1500 or less, the
        802.3 length of the LLC PDU that follows (see :attr:`length`).
    """

    dst: str
    src: str
    ethertype: int

    _struct: ClassVar[Struct] = Struct("!6s6sH")

    #: An 802.3 Length bounds what follows (see :meth:`_payload_extent`).
    _BOUNDS_PAYLOAD: ClassVar[bool] = True

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
        """Return the class for the payload, by type or by length.

        The ``ethertype`` table's entry for an EtherType,
        :class:`~netprotocols.LLC` after an 802.3 Length, and ``None``
        for the undefined 1501-1535.
        """
        return _type_or_length_class(self.ethertype, registry)

    @property
    def is_length(self) -> bool:
        """Whether :attr:`ethertype` holds an 802.3 Length.

        That is, 1500 or less, rather than an EtherType or an undefined
        value.
        """
        return self.ethertype <= _MAX_LENGTH

    @property
    def length(self) -> int | None:
        """The 802.3 Length, or ``None`` when :attr:`ethertype` is not one.

        How many bytes after this header belong to the LLC PDU. The
        bytes after those are padding or a trailer such as an FCS;
        :func:`~netprotocols.decode_frame` ends the next layers' buffer
        there, and a direct caller can slice ``frame[14 : 14 + length]``.
        """
        return _length(self.ethertype)

    def _payload_extent(self) -> int | None:
        """Return the 802.3 Length, which bounds the LLC PDU after it."""
        return _length(self.ethertype)

    @property
    def ethertype_name(self) -> str:
        """Display name of the EtherType, e.g. ``"IPv4"``; falls back to
        the hexadecimal value for types unknown to this library, and
        for an 802.3 Length."""
        return _ethertype_name(self.ethertype)

    @property
    def ethertype_enum(self) -> EtherType | None:
        """The EtherType as an :class:`~netprotocols.EtherType`, or
        ``None`` for a value this library does not enumerate;
        :attr:`ethertype` stays the canonical ``int`` and round-trips
        regardless (see :attr:`ethertype_name` for the display form)."""
        return _ethertype_enum(self.ethertype)
