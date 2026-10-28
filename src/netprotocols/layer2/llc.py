"""IEEE 802.2 LLC and SNAP headers, after an IEEE 802.3 Length.

Bytes 12-13 of an Ethernet header are a type or a length (IEEE 802.3
Clause 3.2.6). A value of 0x0600 or more is an EtherType, which is how
:class:`~netprotocols.Ethernet` has always read it. A value of 1500 or
less is the length of the MAC client data that follows, which begins
with an IEEE 802.2 Logical Link Control header; :meth:`Ethernet.next_protocol
<netprotocols.Ethernet.next_protocol>` answers :class:`LLC` for it, and
:class:`~netprotocols.VLAN` does the same for the 2 bytes after a tag.
Values 1501-1535 are undefined, and the walk ends there.

LLC
---
An LLC header is a DSAP octet, an SSAP octet and a Control field
(ISO/IEC 8802-2 §5)::

    +--------+--------+-----------------+
    |  DSAP  |  SSAP  | Control (1 or 2) |
    +--------+--------+-----------------+

The two low bits of the first Control octet give the PDU's format and
the field's width: ``11`` is an Unnumbered (U-format) PDU and a 1-octet
field, ``01`` a Supervisory (S-format) and ``x0`` an Information
(I-format) PDU, each with a 2-octet field. :attr:`LLC.control` holds
the field with its first octet as the integer's low byte, the order
802.2 numbers its bits in, so the format bits are the integer's two
low bits and a U-format Control is never wider than a byte. A
2-octet Control of ``0x00 0x03`` is therefore ``0x0300``, an I-format
PDU, and never collides with the UI Control ``0x03``.

A frame carries an upper-layer PDU only in an I-format PDU or an
Unnumbered Information one (UI, ``0x03``, either value of the P/F bit),
so :meth:`LLC.next_protocol` dispatches only those, through the
``llc.dsap`` table keyed on the whole DSAP octet, individual/group bit
included. The other formats (S-format, and U-format commands such as
XID and TEST) end the walk at the LLC layer.

DSAP 0x42
---------
SAP 0x42 carries more than Spanning Tree BPDUs: GARP's PDUs, such as
GVRP's, go there too, with Protocol Identifier 0x0001 where a BPDU has
0x0000 (Wireshark's ``packet-gvrp.c``, ``GARP_DEFAULT_PROTOCOL_ID``),
and the IEEE 802.1 draft that :mod:`netprotocols.layer2.stp` cites
says PDUs with other Protocol Identifiers "may be processed according
to the rules of those protocols" (P802.1aq/D1.5++ §14.5 NOTE 1). So
:meth:`LLC.decode`, for a DSAP 0x42 PDU it would dispatch, looks at the
two octets after the Control field, where the PDU starts: when both
are there and are not 0x0000, :meth:`LLC.next_protocol` answers
``None`` and the walk ends at the LLC layer, as it does at a DSAP with
no ``llc.dsap`` entry. When they are 0x0000, or fewer than two octets
follow (in a walk the 802.3 Length bounds the buffer, so padding and an
FCS are not read as them unless the Length overstates the PDU), the PDU
dispatches, and a
short one reaches :class:`~netprotocols.STP` to raise its truncation.
The check applies whatever class ``llc.dsap`` holds at 0x42, a
registered one of the caller's own included, so a GARP decoder is not
reached from the walk: decode the PDU after the LLC header directly.
It is decode context
(see *Decode context in next_protocol* in :mod:`netprotocols._base`):
kept on the instance outside its comparison and hash, so equal headers
compare equal wherever they were found. A header built with the
constructor, or copied with :func:`dataclasses.replace`, has seen no
bytes and dispatches as before; :func:`copy.copy`, :func:`copy.deepcopy`
and :mod:`pickle` keep what :meth:`LLC.decode` recorded. :meth:`STP.decode
<netprotocols.STP.decode>` called directly still rejects a Protocol
Identifier other than 0.

SNAP
----
DSAP and SSAP 0xAA are the Subnetwork Access Protocol's SAP (IEEE Std
802, which the IEEE's LSAP listing cites for 0xAA, and RFC 1042): a
5-byte :class:`SNAP` header, a 3-byte OUI and a 2-byte protocol
identifier (PID), follows the LLC header. The default registry puts
:class:`SNAP` at DSAP 0xAA in ``llc.dsap``, and
:meth:`LLC.next_protocol` reaches that entry only for a frame whose
SSAP is 0xAA too and whose Control is UI. That is this library's
choice, not a rule that other Controls carry no SNAP header: it decodes
a SNAP header only after a UI PDU, the format RFC 1042 sends IP and
ARP in ("standard 802.2 LLC Type 1 Unnumbered Information format,
control code 3"). Wireshark's ``packet-llc.c`` (master, read
2026-10-25) reads a SNAP header after any AA/AA PDU whatever its
Control, and HP's NIC-teaming heartbeats, its comments say, are SNAP
in TEST frames; here such a frame ends the walk at the LLC layer, its
SNAP header undecoded.

The PID means what the OUI's owner assigns it to (RFC 9542 §3: "zz-zz
is a protocol number, under that OUI, assigned by the OUI owner"), so
:meth:`SNAP.next_protocol` reads it in one of two tables:

- OUI 00-00-00 (RFC 1042, which RFC 9542 §3 describes as putting "an
  arbitrary EtherType" after "an all-zeros OUI") and OUI 00-00-F8 (the
  IEEE 802.1H bridge-tunnel encapsulation, whose PID is also an
  EtherType: Linux's ``net/wireless/util.c``, read 2026-10-25, defines
  ``bridge_tunnel_header`` as ``aa aa 03 00 00 f8`` "for EtherTypes
  ETH_P_AARP and ETH_P_IPX") make the PID an EtherType, looked up in
  the ``ethertype`` table whatever its value. A PID below 0x0600 is
  never read as an 802.3 Length: the default registry holds nothing
  there, so the walk ends, but a class registered there is reached, as
  it is from a GRE Protocol Type (see "Key ranges" in
  :mod:`netprotocols.registry`).
- Any other OUI makes the PID that organisation's own number, looked
  up in the ``llc.snap`` table under ``(oui << 16) | pid``. Cisco's CDP
  is OUI 00-00-0C PID 0x2000, which is not EtherType 0x2000.

Issue #188 recommended reading every PID in the ``ethertype`` table.
That is right for the two OUIs above only, and this module departs
from it for the rest: read there, a protocol under another OUI would
dispatch to whatever holds the EtherType of the same number.

Novell "raw 802.3"
------------------
Novell NetWare's original framing puts an IPX packet straight after
the 802.3 Length, with no LLC header. An IPX header starts with a
checksum that is always 0xFFFF, so its first two bytes read as DSAP
0xFF (the global DSAP) and SSAP 0xFF. Such a frame decodes as an
:class:`LLC` layer of 3 or 4 bytes that round-trips exactly,
:attr:`LLC.is_raw_ipx` is ``True``, and :meth:`LLC.next_protocol`
answers ``None``, whatever ``llc.dsap`` holds for 0xFF. The layer's
other fields and accessors are then meaningless: ``control`` and
``control_format`` read the IPX length's bytes (a 30-byte packet,
``0x00 0x1E``, reads as the I-format Control ``0x1E00``), so
``header_len`` covers the checksum and one or both length bytes, and
the SAP names, :attr:`LLC.dsap_enum`, :attr:`LLC.is_group` and
:attr:`LLC.is_response` describe the checksum's 0xFF 0xFF. Wireshark makes
the same call, from the same two bytes; a real LLC PDU from SSAP 0xFF
(a response from SAP 0xFE) to the global DSAP is not distinguishable
from it.

The 802.3 Length and the bytes after the PDU
--------------------------------------------
Neither header has a length of its own: the PDU ends where the 802.3
Length before it says, and a frame shorter than Ethernet's 60-byte
minimum carries zero padding after it, and a capture can carry the
4-byte FCS. :func:`~netprotocols.decode_frame` therefore ends every
layer's buffer after an :class:`~netprotocols.Ethernet` or
:class:`~netprotocols.VLAN` header with a Length at the end of the PDU
that Length gives (``Ethernet.length``), so padding and an FCS stay
outside every layer and ``packet.consumed`` stops short of them. It is
the one enclosing length the walk honours; IPv4's, IPv6's and UDP's
are not (#235). A Length larger than the bytes captured bounds nothing
and the layers decode what is there, as for a snap-length cut; a
Length smaller than the LLC header leaves :meth:`LLC.decode` too few
bytes, so the walk raises :class:`~netprotocols.TruncatedHeaderError`
(or, lax, stops with it on ``stopped_by``).

:meth:`LLC.decode` and :meth:`SNAP.decode` called directly have no
Length to go by: like any decoder they read their header from the
start of the buffer and leave the rest, padding included, to whoever
called them, who can bound it with ``frame[14 : 14 + eth.length]``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, hex_str
from netprotocols._enums import LLCSAP
from netprotocols.registry import (
    DEFAULT,
    TABLE_ETHERTYPE,
    TABLE_LLC_DSAP,
    TABLE_LLC_SNAP,
    Registry,
)
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["LLC", "SNAP"]

#: The flat dispatch tables of the default registry, bound once at
#: import and mutated in place by registration (see
#: :mod:`netprotocols.registry`). The ``ethertype`` table is bound here
#: rather than imported from :mod:`netprotocols.layer2.ethernet`, which
#: imports this module.
_DSAP_CLASSES: dict[int, type[Protocol]] = DEFAULT.table(TABLE_LLC_DSAP)
_SNAP_CLASSES: dict[int, type[Protocol]] = DEFAULT.table(TABLE_LLC_SNAP)
_ETHERTYPE_CLASSES: dict[int, type[Protocol]] = DEFAULT.table(TABLE_ETHERTYPE)

#: The Unnumbered Information Control octet (ISO/IEC 8802-2 §5) and
#: the P/F bit a UI PDU may carry either way.
_UI = 0x03
_PF_BIT = 0x10

#: The two OUIs under which a SNAP PID is an EtherType: RFC 1042's
#: all-zeros OUI, and IEEE 802.1H's bridge-tunnel OUI 00-00-F8.
_ETHERTYPE_OUIS = frozenset({0x000000, 0x0000F8})


def _check_octet(value: int, protocol: type[Protocol], field: str) -> None:
    """Refuse a value that does not fit in one octet.

    :raises InvalidFieldError: ``value`` is outside 0-255.
    """
    if not 0 <= value <= 0xFF:
        raise InvalidFieldError(
            f"{protocol.__name__} {field} must be within 0-255, got {value}",
            protocol=protocol,
            field=field,
            expected="0-255",
            actual=value,
        )


def _names_other_protocol(data: bytes | memoryview, offset: int) -> bool:
    """Whether a Protocol Identifier other than STP's starts at ``offset``.

    ``True`` when the two octets there are present and not ``0x0000``;
    ``False`` when they are zero, or when fewer than two remain, so
    that STP still reports the truncation.
    """
    return len(data) >= offset + 2 and (data[offset] | data[offset + 1]) != 0


def _sap_name(sap: int) -> str:
    """Display name of an LSAP, e.g. ``"SNAP"``, or its hex value."""
    try:
        return LLCSAP(sap).display_name
    except ValueError:
        return hex_str(sap, 4)


@dataclass(frozen=True, slots=True)
class LLC(Protocol):
    """An IEEE 802.2 LLC header (ISO/IEC 8802-2 §5).

    :param dsap: Destination service access point; its low bit is the
        individual/group bit (see :class:`~netprotocols.LLCSAP`).
    :param ssap: Source service access point; its low bit is the
        command/response bit.
    :param control: The Control field, its first octet in the low byte:
        one octet for a U-format PDU (two low bits ``11``), two for an
        I- or S-format PDU (see the module docstring).
    """

    dsap: int
    ssap: int
    control: int
    #: Whether :meth:`decode` found a Protocol Identifier other than
    #: STP's 0x0000 after a dispatching DSAP 0x42 PDU's Control (see
    #: :meth:`next_protocol`); decode context, not a wire field, so it is
    #: neither compared nor hashed. :func:`copy.copy`,
    #: :func:`copy.deepcopy` and :mod:`pickle` keep it;
    #: :func:`dataclasses.replace` builds a new header, which has it unset.
    _other_protocol_id: bool = field(
        default=False, init=False, repr=False, compare=False
    )

    #: DSAP, SSAP and the first Control octet; an I- or S-format PDU
    #: adds a second Control octet after them.
    _struct: ClassVar[Struct] = Struct("!BBB")

    def __post_init__(self) -> None:
        """Check that each field fits its octets.

        :raises InvalidFieldError: the DSAP or SSAP is outside 0-255, or
            the Control is negative or wider than its format allows (one
            octet when its two low bits are ``11``, else two).
        """
        _check_octet(self.dsap, type(self), "dsap")
        _check_octet(self.ssap, type(self), "ssap")
        limit = 0xFF if self.control & 0x03 == 0x03 else 0xFFFF
        if not 0 <= self.control <= limit:
            raise InvalidFieldError(
                f"LLC control must be within 0-{limit:#x} for its format, "
                f"got {self.control:#x}",
                protocol=type(self),
                field="control",
                expected=f"0-{limit:#x}",
                actual=self.control,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the LLC header at the start of ``data``.

        :raises TruncatedHeaderError: ``data`` is shorter than 3 bytes,
            or than 4 for an I- or S-format PDU.
        """
        dsap, ssap, control = cls._unpack_fixed(data)
        if control & 0x03 != 0x03:
            if len(data) < 4:
                raise TruncatedHeaderError(
                    f"LLC I- or S-format header needs 4 bytes, buffer "
                    f"holds {len(data)}",
                    protocol=cls,
                    field="control",
                    offset=2,
                    expected=4,
                    actual=len(data),
                )
            control |= data[3] << 8
        llc = cls(dsap=dsap, ssap=ssap, control=control)
        if (
            dsap == LLCSAP.SPANNING_TREE
            and llc._dispatches
            and _names_other_protocol(data, llc.header_len)
        ):
            object.__setattr__(llc, "_other_protocol_id", True)
        return llc

    def __bytes__(self) -> bytes:
        """Serialize the header, the Control's first octet first."""
        head = self._struct.pack(self.dsap, self.ssap, self.control & 0xFF)
        if self.control & 0x03 == 0x03:
            return head
        return head + bytes((self.control >> 8,))

    @property
    def header_len(self) -> int:
        """3 bytes for a U-format PDU, 4 for an I- or S-format one."""
        return 3 if self.control & 0x03 == 0x03 else 4

    @property
    def control_format(self) -> str:
        """The PDU's format: ``"I"``, ``"S"`` or ``"U"``."""
        if self.control & 0x01 == 0:
            return "I"
        return "U" if self.control & 0x02 else "S"

    @property
    def is_group(self) -> bool:
        """Whether the DSAP is a group address (its low bit set)."""
        return bool(self.dsap & 0x01)

    @property
    def is_response(self) -> bool:
        """Whether the SSAP marks a response (its low bit set)."""
        return bool(self.ssap & 0x01)

    @property
    def is_raw_ipx(self) -> bool:
        """Whether this is Novell "raw 802.3", not an LLC header.

        DSAP and SSAP 0xFF are then an IPX checksum, and the Control
        the IPX length's high byte or both its bytes, so every other
        field and accessor of this layer is meaningless for such a
        frame (see the module docstring).
        """
        return self.dsap == 0xFF and self.ssap == 0xFF

    @property
    def dsap_name(self) -> str:
        """Display name of the DSAP, e.g. ``"Bridge Spanning Tree"``.

        Falls back to the hexadecimal value for an unlisted one.
        """
        return _sap_name(self.dsap)

    @property
    def ssap_name(self) -> str:
        """Display name of the SSAP, its command/response bit cleared."""
        return _sap_name(self.ssap & 0xFE)

    @property
    def dsap_enum(self) -> LLCSAP | None:
        """The DSAP as an :class:`~netprotocols.LLCSAP`, or ``None``.

        ``None`` for a value the IEEE does not list as assigned.
        """
        try:
            return LLCSAP(self.dsap)
        except ValueError:
            return None

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """Return the class registered in ``llc.dsap`` for the DSAP.

        ``None`` for a PDU that carries no upper-layer data (anything
        but I-format and UI), for Novell raw 802.3, for DSAP 0xAA
        unless the SSAP is 0xAA and the Control UI, the one PDU after
        which this library decodes a SNAP header, and for DSAP 0x42
        when :meth:`decode` found two octets after the Control that
        are not 0x0000, a Protocol Identifier other than the spanning
        tree's, such as GARP's (see the module docstring).
        """
        if not self._dispatches or self._other_protocol_id:
            return None
        if registry is None:
            return _DSAP_CLASSES.get(self.dsap)
        return registry.get(TABLE_LLC_DSAP, self.dsap)

    @property
    def _dispatches(self) -> bool:
        """Whether the PDU carries data an ``llc.dsap`` entry decodes."""
        unnumbered_information = self.control & ~_PF_BIT == _UI
        if self.dsap == LLCSAP.SNAP:
            return unnumbered_information and self.ssap == LLCSAP.SNAP
        if self.is_raw_ipx:
            return False
        return unnumbered_information or self.control & 0x01 == 0


@dataclass(frozen=True, slots=True)
class SNAP(Protocol):
    """A Subnetwork Access Protocol header (IEEE Std 802, RFC 1042).

    :param oui: Organizationally unique identifier, 24 bits:
        ``0x000000`` for RFC 1042, ``0x0000F8`` for IEEE 802.1H.
    :param pid: Protocol identifier under that OUI: an EtherType for the
        two OUIs above, the organisation's own number for any other.
    """

    oui: int
    pid: int

    _struct: ClassVar[Struct] = Struct("!BHH")

    def __post_init__(self) -> None:
        """Check that the OUI fits 24 bits and the PID 16.

        :raises InvalidFieldError: either is out of range.
        """
        if not 0 <= self.oui <= 0xFFFFFF:
            raise InvalidFieldError(
                f"SNAP OUI must be within 0-0xffffff, got {self.oui}",
                protocol=type(self),
                field="oui",
                expected="0-0xffffff",
                actual=self.oui,
            )
        if not 0 <= self.pid <= 0xFFFF:
            raise InvalidFieldError(
                f"SNAP PID must be within 0-0xffff, got {self.pid}",
                protocol=type(self),
                field="pid",
                expected="0-0xffff",
                actual=self.pid,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the SNAP header at the start of ``data``.

        :raises TruncatedHeaderError: ``data`` is shorter than 5 bytes.
        """
        oui_high, oui_low, pid = cls._unpack_fixed(data)
        return cls(oui=oui_high << 16 | oui_low, pid=pid)

    def __bytes__(self) -> bytes:
        """Serialize the OUI and the PID."""
        return self._struct.pack(self.oui >> 16, self.oui & 0xFFFF, self.pid)

    @property
    def carries_ethertype(self) -> bool:
        """Whether the PID is an EtherType: OUI 00-00-00 or 00-00-F8."""
        return self.oui in _ETHERTYPE_OUIS

    @property
    def snap_key(self) -> int:
        """This header's key in the ``llc.snap`` table.

        That is ``(oui << 16) | pid``.
        """
        return self.oui << 16 | self.pid

    @property
    def oui_str(self) -> str:
        """The OUI in IEEE's hyphenated form, e.g. ``"00-00-0c"``."""
        return self.oui.to_bytes(3, "big").hex("-")

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """Return the class for the PID, from the table its OUI selects.

        From ``ethertype`` when :attr:`carries_ethertype`, else from
        ``llc.snap`` under :attr:`snap_key`.
        """
        if self.carries_ethertype:
            if registry is None:
                return _ETHERTYPE_CLASSES.get(self.pid)
            return registry.get(TABLE_ETHERTYPE, self.pid)
        if registry is None:
            return _SNAP_CLASSES.get(self.snap_key)
        return registry.get(TABLE_LLC_SNAP, self.snap_key)
