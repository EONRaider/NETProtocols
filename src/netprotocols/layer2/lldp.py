"""LLDP — the Link Layer Discovery Protocol (IEEE 802.1AB).

An LLDP agent multicasts an LLDPDU on each port, directly behind an
Ethernet header with EtherType ``0x88CC``, to tell its neighbours who it
is: the chassis, the port, and for how many seconds to believe it. The
LLDPDU never encapsulates anything, so the layer is terminal.

An LLDPDU is nothing but a run of TLVs (802.1AB §8). Each starts with a
16-bit header word, read big-endian, packing a 7-bit Type above a 9-bit
Length; Length bytes of value follow. :class:`LLDP` keeps every TLV, in
wire order, as an :class:`LLDPTLV`. The first three must be Chassis ID
(type 1), Port ID (type 2) and Time To Live (type 3); the typed
accessors :attr:`LLDP.chassis_id`, :attr:`LLDP.port_id` and
:attr:`LLDP.ttl` read those three positions. Every other TLV — Port
Description, System Name, System Description, System Capabilities,
Management Address, organizationally specific (type 127), a reserved
type — keeps its value raw, with :attr:`LLDPTLV.type_name` naming the
standard ones.

Where an LLDPDU ends
--------------------
There is no length for the whole LLDPDU, and Ethernet's zero padding or
a captured FCS can follow it in the buffer :meth:`LLDP.decode` is handed
(the walk does not trim a frame). An LLDPDU's own End of LLDPDU TLV
(type 0, length 0) marks its end, and is what bounds it here:

* ``decode`` walks the TLVs from the start of the buffer and stops after
  the first End of LLDPDU TLV, which it keeps as the last element of
  :attr:`LLDP.tlvs`. Whatever follows it — padding, an FCS, anything —
  is left undecoded (decode contract rule 3). Every LLDPDU lldpd 1.0.18
  sends ends this way.
* Wireshark's dissector notes that 802.1AB-2016 made the End TLV
  optional, and walks an LLDPDU without one to the end of the frame.
  So does ``decode``: when the last TLV ends exactly at the end of the
  buffer, the LLDPDU is everything walked, End or not. (lldpd 1.0.18's
  receiver, ``lldp_decode``, still requires the End TLV and discards
  an LLDPDU without one.) A snap length that happens to cut the capture
  at a TLV boundary looks just the same, and decodes the same way.
* Without an End TLV, nothing marks where the LLDPDU stops and a
  trailer starts, so the walk reads a trailer as TLVs, its first two
  bytes as a TLV header. A single byte left raises as a cut header,
  below. A header whose Length runs past the buffer raises as such a
  TLV, below. Otherwise a header of Type 0 (a first byte of ``00`` or
  ``01``) is an End TLV: with Length 0 — two or more bytes of zero
  padding — ``decode`` keeps it as the LLDPDU's last TLV (2 bytes of
  the padding become part of the message, and the rest is left
  undecoded), and with any other Length it raises as an End TLV with
  a Length, below. A header of any other Type reads as a TLV that the
  sender never sent, and the walk goes on after it.

``decode`` checks framing, and nothing more: a TLV header cut short (a
single byte left), or a TLV whose Length runs past the buffer, raises
:class:`~netprotocols.TruncatedHeaderError` (``field="tlvs"``, the
offset of the TLV's header), as any header that lies about its length
does; an End of LLDPDU TLV with a nonzero Length raises
:class:`~netprotocols.InvalidFieldError` there, as lldpd's receiver
rejects one. An empty buffer, or one of a single byte, holds no TLV
header and raises :class:`~netprotocols.TruncatedHeaderError` as any
buffer too short for a header's fixed part does (offset 0, no
``field``).

The mandatory order is not framing, and ``decode`` does not enforce it:
lldpd's receiver discards an LLDPDU whose first three TLVs are not
Chassis ID, Port ID and Time To Live, in that order (it rejects each of
them found at another position, and an LLDPDU missing one), but a
decoder of captured traffic should still show one. The accessors report it
instead: each reads its own position only and is ``None`` when the TLV
there is of another type or too short (or, for the two IDs, too long)
to hold its value, so none of them raises. A Chassis ID or Port ID TLV
later in the LLDPDU, a duplicate that lldpd rejects and Wireshark
flags, is kept in :attr:`LLDP.tlvs` like any other TLV. Dispatch is by
EtherType, which says outright what follows, so there is no wrong guess
for ``decode`` to guard against as there is for a port.

The walk is local to this module rather than
:func:`~netprotocols._tlv.walk_kind_length_value`, the TLV walker TCP,
IPv4, IPv6 and PIM share. LLDP's Type and Length are bitfields of one
16-bit word, not two fields of a byte width that walker could be told;
its End of LLDPDU is a whole TLV whose Length must be checked, not a
lone terminator byte; and ``decode`` must know where the walk stopped,
to bound :attr:`LLDP.header_len`, and must raise
:class:`~netprotocols.TruncatedHeaderError` with an offset into its own
buffer for a lying Length, where that walker yields no offsets and
raises :class:`~netprotocols.InvalidFieldError`. Extending it for all of
that would change a function in the mutation-tested scope that four
other callers rely on, for a walk of a dozen lines.

``bytes(LLDP.decode(x)) == x[:header_len]`` holds by construction: each
TLV is packed back from its type and its value, carried verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["LLDP", "LLDPTLV", "LLDPChassisID", "LLDPPortID"]

#: A TLV's header word: Type in the high 7 bits, Length in the low 9.
_TLV_HEADER = Struct("!H")
_MAX_TYPE = 0x7F
_MAX_LENGTH = 0x1FF

#: The TLV types the accessors and the walk know by number.
_END_OF_LLDPDU = 0
_CHASSIS_ID = 1
_PORT_ID = 2
_TIME_TO_LIVE = 3

#: The longest Chassis ID or Port ID: 1 to 255 bytes after the subtype
#: byte, so a TLV value of 2 to 256 bytes, the bounds lldpd 1.0.18's
#: receiver (``lldp_decode``, src/daemon/protocols/lldp.c) checks.
_MAX_ID_LENGTH = 255

# The display names below are Wireshark's, copied verbatim from
# epan/dissectors/packet-lldp.c (tables ``tlv_types``,
# ``chassis_id_subtypes`` and ``port_id_subtypes``) at commit
# 31bf085794733ece0436365ad3e0bbcc2292fc9a, fetched 2026-10-25. The
# subtype numbers agree with the IEEE 802.1 Working Group's LLDP MIBs,
# fetched the same day from ieee802.org/1/files/public/MIBs/:
# LldpChassisIdSubtype and LldpPortIdSubtype in LLDP-MIB-200505060000Z
# (802.1AB-2005), and their LldpV2 versions in LLDP-V2-TC-MIB-200906080000Z
# (802.1AB-2009), which enumerate 1-7 identically. Types 9-126 and
# subtypes 8-255 are reserved, and named "unknown (n)".

#: TLV type names.
_TLV_TYPE_NAMES: dict[int, str] = {
    0: "End of LLDPDU",
    1: "Chassis Id",
    2: "Port Id",
    3: "Time to Live",
    4: "Port Description",
    5: "System Name",
    6: "System Description",
    7: "System Capabilities",
    8: "Management Address",
    127: "Organization Specific",
}

#: Chassis ID subtype names.
_CHASSIS_ID_SUBTYPE_NAMES: dict[int, str] = {
    0: "Reserved",
    1: "Chassis component",
    2: "Interface alias",
    3: "Port component",
    4: "MAC address",
    5: "Network address",
    6: "Interface name",
    7: "Locally assigned",
}

#: Port ID subtype names.
_PORT_ID_SUBTYPE_NAMES: dict[int, str] = {
    0: "Reserved",
    1: "Interface alias",
    2: "Port component",
    3: "MAC address",
    4: "Network address",
    5: "Interface name",
    6: "Agent circuit Id",
    7: "Locally assigned",
}


def _check_range(
    owner: type, field: str, value: int, low: int, high: int
) -> None:
    """Reject ``value`` outside ``low``-``high``.

    :raises InvalidFieldError: naming ``owner`` and ``field``.
    """
    if not low <= value <= high:
        raise InvalidFieldError(
            f"{owner.__name__} {field} must be within {low}-{high}, got "
            f"{value}",
            protocol=owner,
            field=field,
            expected=f"{low}-{high}",
            actual=value,
        )


@dataclass(frozen=True, slots=True)
class LLDPTLV:
    """One TLV of an LLDPDU (IEEE 802.1AB §8), its value kept raw.

    :param type: TLV type, ``0``-``127`` (see :attr:`type_name`).
    :param value: The TLV's information string, at most 511 bytes; the
        Length the header carries is its length.

    ``bytes(tlv)`` is the on-wire TLV: the header word, then the value.
    """

    type: int
    value: bytes = b""

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring).

        :raises InvalidFieldError: a type that overflows its 7 bits, or
            a value too long for the 9-bit Length.
        """
        _check_range(type(self), "type", self.type, 0, _MAX_TYPE)
        _check_range(type(self), "value", len(self.value), 0, _MAX_LENGTH)

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return _TLV_HEADER.pack((self.type << 9) | len(self.value)) + self.value

    @property
    def length(self) -> int:
        """Return the TLV's Length: the bytes of value, not the header."""
        return len(self.value)

    @property
    def type_name(self) -> str:
        """Name the TLV type, e.g. ``"System Name"``.

        Reserved types read ``"unknown (n)"``.
        """
        return _TLV_TYPE_NAMES.get(self.type, f"unknown ({self.type})")


@dataclass(frozen=True, slots=True)
class _LLDPIdentifier:
    """The shape a Chassis ID and a Port ID TLV share (802.1AB §8).

    A subtype byte saying what kind of identifier follows, then 1 to 255
    bytes of identifier, kept raw.
    """

    subtype: int
    id: bytes

    #: The TLV type that carries this identifier.
    _TLV_TYPE: ClassVar[int]
    #: Display names of this identifier's subtypes.
    _SUBTYPE_NAMES: ClassVar[dict[int, str]]

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring).

        :raises InvalidFieldError: a subtype that overflows its byte, or
            an identifier that is empty or longer than 255 bytes.
        """
        _check_range(type(self), "subtype", self.subtype, 0, 0xFF)
        _check_range(type(self), "id", len(self.id), 1, _MAX_ID_LENGTH)

    @classmethod
    def _from_tlv(cls, tlv: LLDPTLV) -> Self | None:
        """Read the identifier ``tlv`` carries.

        :returns: ``None`` when ``tlv`` is of another type, or its value
            is too short or too long to hold a subtype and an identifier
            of 1 to 255 bytes.
        """
        value = tlv.value
        if tlv.type != cls._TLV_TYPE or not 2 <= len(value) <= 256:
            return None
        return cls(subtype=value[0], id=value[1:])

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire TLV, as :attr:`tlv` does."""
        return bytes(self.tlv)

    @property
    def tlv(self) -> LLDPTLV:
        """Return the TLV carrying this identifier."""
        return LLDPTLV(self._TLV_TYPE, bytes((self.subtype,)) + self.id)

    @property
    def subtype_name(self) -> str:
        """Name the subtype, e.g. ``"MAC address"``.

        Reserved subtypes read ``"unknown (n)"``.
        """
        return self._SUBTYPE_NAMES.get(
            self.subtype, f"unknown ({self.subtype})"
        )


@dataclass(frozen=True, slots=True)
class LLDPChassisID(_LLDPIdentifier):
    """A Chassis ID TLV's value (IEEE 802.1AB §8).

    :param subtype: What the identifier is: ``4``
        a MAC address, ``5`` a network address, ``6`` an interface
        name, ``7`` locally assigned, ... (see :attr:`subtype_name`).
    :param id: The chassis identifier, 1 to 255 bytes, kept raw.

    ``bytes(chassis_id)`` is the whole Chassis ID TLV, header included.
    """

    _TLV_TYPE: ClassVar[int] = _CHASSIS_ID
    _SUBTYPE_NAMES: ClassVar[dict[int, str]] = _CHASSIS_ID_SUBTYPE_NAMES


@dataclass(frozen=True, slots=True)
class LLDPPortID(_LLDPIdentifier):
    """A Port ID TLV's value (IEEE 802.1AB §8).

    :param subtype: What the identifier is: ``3``
        a MAC address, ``5`` an interface name, ``7`` locally assigned,
        ... (see :attr:`subtype_name`).
    :param id: The port identifier, 1 to 255 bytes, kept raw.

    ``bytes(port_id)`` is the whole Port ID TLV, header included.
    """

    _TLV_TYPE: ClassVar[int] = _PORT_ID
    _SUBTYPE_NAMES: ClassVar[dict[int, str]] = _PORT_ID_SUBTYPE_NAMES


@dataclass(frozen=True, slots=True)
class LLDP(Protocol):
    """An LLDPDU (IEEE 802.1AB §8), as the TLVs it is made of.

    :param tlvs: Every TLV, in wire order, through the End of LLDPDU
        TLV when there is one (see the module docstring). At least one;
        an End of LLDPDU TLV (type ``0``) may only come last, and with
        an empty value, since it ends the LLDPDU.
    """

    tlvs: tuple[LLDPTLV, ...]

    #: One TLV header word: the least any LLDPDU holds.
    _struct: ClassVar[Struct] = _TLV_HEADER

    def __post_init__(self) -> None:
        """Validate the TLVs as :meth:`decode` would read them back.

        :raises InvalidFieldError: no TLVs, one that is not an
            :class:`LLDPTLV`, an End of LLDPDU TLV before the last, or
            one with a value.
        """
        if not self.tlvs:
            raise InvalidFieldError(
                "LLDP needs at least one TLV",
                protocol=type(self),
                field="tlvs",
                expected=">=1",
                actual=0,
            )
        for index, tlv in enumerate(self.tlvs):
            if not isinstance(tlv, LLDPTLV):
                raise InvalidFieldError(
                    f"LLDP tlvs must all be LLDPTLV; found "
                    f"{type(tlv).__name__} at index {index}",
                    protocol=type(self),
                    field="tlvs",
                    expected="LLDPTLV",
                    actual=type(tlv).__name__,
                )
            if tlv.type != _END_OF_LLDPDU:
                continue
            if index != len(self.tlvs) - 1 or tlv.value:
                raise InvalidFieldError(
                    "LLDP End of LLDPDU TLV must be the last TLV, with "
                    f"an empty value; found at index {index} with "
                    f"{len(tlv.value)} bytes",
                    protocol=type(self),
                    field="tlvs",
                    expected="last, empty",
                    actual=index,
                )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the LLDPDU at the start of ``data``; see the module.

        :raises TruncatedHeaderError: ``data`` is shorter than one TLV
            header, 2 bytes (no ``field``, as for any fixed header); or
            a later TLV's header, or any TLV's value, runs past it
            (``field="tlvs"``, the offset of that TLV).
        :raises InvalidFieldError: an End of LLDPDU TLV has a nonzero
            Length (``field="tlvs"``).
        """
        cls._unpack_fixed(data)
        size = len(data)
        tlvs: list[LLDPTLV] = []
        cursor = 0
        while cursor < size:
            tlv, cursor = _read_tlv(cls, data, cursor)
            tlvs.append(tlv)
            if tlv.type == _END_OF_LLDPDU:
                break
        return cls(tlvs=tuple(tlvs))

    def __bytes__(self) -> bytes:
        """Serialize every TLV back to its on-wire form."""
        return b"".join(bytes(tlv) for tlv in self.tlvs)

    @property
    def header_len(self) -> int:
        """Return the length of the LLDPDU: every TLV, End included."""
        return sum(2 + len(tlv.value) for tlv in self.tlvs)

    def _at(self, index: int) -> LLDPTLV | None:
        """Return the TLV at ``index``, or ``None`` past the last."""
        return self.tlvs[index] if index < len(self.tlvs) else None

    @property
    def chassis_id(self) -> LLDPChassisID | None:
        """Return the Chassis ID, read from the first TLV.

        ``None`` when the first TLV is not a Chassis ID TLV, or its
        value cannot hold a subtype and an identifier of 1 to 255 bytes.
        """
        return LLDPChassisID._from_tlv(self.tlvs[0])

    @property
    def port_id(self) -> LLDPPortID | None:
        """Return the Port ID, read from the second TLV.

        ``None`` when there is none, it is not a Port ID TLV, or its
        value cannot hold a subtype and an identifier of 1 to 255 bytes.
        """
        tlv = self._at(1)
        return None if tlv is None else LLDPPortID._from_tlv(tlv)

    @property
    def ttl(self) -> int | None:
        """Return the Time To Live, in seconds, read from the third TLV.

        ``0`` marks a shutdown LLDPDU (802.1AB-2016 §9.1.2, as
        Wireshark's dissector cites it): forget this sender's
        information now (see :attr:`is_shutdown`). ``None`` when there
        is no third TLV, it is not a Time To Live TLV, or its value is
        shorter than 2 bytes. Bytes past the first two are ignored, as
        lldpd's receiver ignores them; they stay in the TLV's value.
        """
        tlv = self._at(2)
        if tlv is None or tlv.type != _TIME_TO_LIVE or len(tlv.value) < 2:
            return None
        return int.from_bytes(tlv.value[:2])

    @property
    def is_shutdown(self) -> bool:
        """Report whether this is a shutdown LLDPDU: :attr:`ttl` is ``0``.

        lldpd sends one when it stops, and before it changes its chassis
        or port ID, so that its neighbours drop what the old ID told
        them.
        """
        return self.ttl == 0

    @property
    def has_mandatory_tlvs(self) -> bool:
        """Report whether the LLDPDU opens as 802.1AB requires.

        That is, whether :attr:`chassis_id`, :attr:`port_id` and
        :attr:`ttl` are all present: in the first three positions, a
        Chassis ID and a Port ID TLV of 2 to 256 bytes each, then a
        Time To Live TLV of 2 bytes or more. Nothing else is checked:
        any subtype passes, the reserved ones (``0`` and ``8``-``255``)
        included, as do bytes past a TTL's first two and a later
        duplicate of any of the three.
        """
        return (
            self.chassis_id is not None
            and self.port_id is not None
            and self.ttl is not None
        )

    def tlv(self, tlv_type: int) -> LLDPTLV | None:
        """Return the first TLV of type ``tlv_type``, or ``None``."""
        return next((t for t in self.tlvs if t.type == tlv_type), None)


def _read_tlv(
    cls: type[LLDP], data: bytes | memoryview, cursor: int
) -> tuple[LLDPTLV, int]:
    """Read the TLV whose header starts at ``cursor``.

    :returns: The TLV, and the offset just past it.
    :raises TruncatedHeaderError: the header or the value runs past
        ``data``.
    :raises InvalidFieldError: an End of LLDPDU TLV with a nonzero
        Length.
    """
    size = len(data)
    if cursor + 2 > size:
        raise TruncatedHeaderError(
            f"LLDP TLV header at offset {cursor} needs 2 bytes, buffer "
            f"holds {size - cursor}",
            protocol=cls,
            field="tlvs",
            offset=cursor,
            expected=cursor + 2,
            actual=size,
        )
    (word,) = _TLV_HEADER.unpack_from(data, cursor)
    tlv_type, length = word >> 9, word & _MAX_LENGTH
    end = cursor + 2 + length
    if end > size:
        raise TruncatedHeaderError(
            f"LLDP TLV at offset {cursor} declares {length} bytes of "
            f"value, buffer holds {size - cursor - 2}",
            protocol=cls,
            field="tlvs",
            offset=cursor,
            expected=end,
            actual=size,
        )
    if tlv_type == _END_OF_LLDPDU and length:
        raise InvalidFieldError(
            f"LLDP End of LLDPDU TLV at offset {cursor} must have Length "
            f"0, got {length}",
            protocol=cls,
            field="tlvs",
            offset=cursor,
            expected=0,
            actual=length,
        )
    return LLDPTLV(tlv_type, bytes(data[cursor + 2 : end])), end
