"""Spanning Tree BPDUs (IEEE 802.1D, 802.1w): STP and RSTP.

Bridges running the Spanning Tree Protocol exchange Bridge Protocol
Data Units in 802.2 LLC UI frames to DSAP and SSAP 0x42 (the Bridge
Spanning Tree SAP), sent to the group address 01-80-C2-00-00-00. The
default registry puts :class:`STP` at DSAP 0x42 in the ``llc.dsap``
table, and :class:`STP` is terminal: a BPDU encapsulates nothing.

A walk reaches :class:`STP` from a UI or I-format PDU to DSAP 0x42
whose first two octets are 0x0000, STP's Protocol Identifier, or that
holds fewer than two octets. GARP's PDUs, such as GVRP's, share the
SAP with Protocol Identifier 0x0001, so :class:`~netprotocols.LLC` ends the
walk at a PDU whose two octets are anything but 0x0000, whatever class
``llc.dsap`` holds at 0x42 (see "DSAP 0x42" in
:mod:`netprotocols.layer2.llc`).

Every BPDU starts with a Protocol Identifier (two octets, always 0 for
the spanning tree family), a Protocol Version Identifier and a BPDU
Type; the type alone decides the rest (IEEE 802.1D-2004 §9.3):

=========  =======================================  ======  =========
BPDU Type  BPDU                                     Octets  Version
=========  =======================================  ======  =========
``0x00``   Configuration BPDU (802.1D §9.3.1)       35      0
``0x80``   Topology Change Notification (§9.3.2)    4       0
``0x02``   RST BPDU (802.1w, 802.1D-2004 §9.3.3)    36      2 (3: MST)
=========  =======================================  ======  =========

A Configuration BPDU and an RST BPDU carry the same 31 octets after
the type: Flags, Root Identifier, Root Path Cost, Bridge Identifier,
Port Identifier, and four timers (Message Age, Max Age, Hello Time and
Forward Delay, each in units of 1/256 s). An RST BPDU adds one octet,
the Version 1 Length, transmitted as 0. A TCN is the 4-octet common
prefix alone: it decodes as the short form of the same class, with
every field the type does not carry ``None``. One class decodes all
three, branching on the type as :class:`~netprotocols.ICMPv4` branches
on its own, and the layout is keyed on the type alone: the version is
carried verbatim, so a type 0x02 BPDU of version 0 or 1, which the
validation of received BPDUs would discard (§14.5 h) of the draft
cited below), still decodes as an RST BPDU.

Flags
-----
The Flags octet has two bits in a Configuration BPDU, Topology Change
(bit 1, ``0x01``) and Topology Change Acknowledgment (bit 8, ``0x80``).
An RST BPDU keeps Topology Change and adds Proposal (``0x02``), the
two-bit Port Role (``0x0C``), Learning (``0x10``), Forwarding (``0x20``)
and Agreement (``0x40``), and leaves bit 8 unused. Each type's unused
bits "shall be transmitted as 0 and ignored on receipt", so a flag
accessor answers ``None`` in a type that does not define its bit, as
:class:`~netprotocols.VRRP`'s per-version accessors do, and the raw
octet stays in :attr:`STP.flags`. The Port Role encodes 1 as Alternate
or Backup, 2 as Root and 3 as Designated; 0 is Unknown here, the name
IEEE 802.1D-2004 gave it, which 802.1Q replaced with Master (the
draft's §14.2.9 NOTE).

The bit positions, the role values and the field layout are from the
BPDU encoding text of the IEEE 802.1 working group's public document
``aq-seaman-merged-bpdu-encoding-0509.pdf``, "P802.1aq/D1.5++suggested
changes, May 16, 2009": an unapproved draft whose Clause 14 merges
802.1D Clause 9 with 802.1Q-2005 Clause 14 (fetched from ieee802.org
2026-10-25), called "the draft" here. They agree with Wireshark's
``epan/dissectors/packet-bpdu.c`` (master, fetched 2026-10-25), whose
names for the BPDU types, the protocol versions and port roles 1-3
this module uses; Wireshark's ``role_vals`` names no role 0. The
draft's §14.4 o) labels octets 34 and 35 Max Age, a slip for the
Forward Delay they carry: the draft's own Figure 14-1 lists "Forward
Delay 34-35" (and Max Age at 30-31), Wireshark reads Forward Delay there
(``BPDU_FORWARD_DELAY``, offset 33 from the Protocol Identifier), and
Linux's ``br_send_config_bpdu()`` in ``net/bridge/br_stp_bpdu.c``
(read 2026-10-28) writes it there, ``br_set_ticks(buf+33,
bpdu->forward_delay)``.

Bridge and Port Identifiers
---------------------------
A Bridge Identifier is two priority octets and the bridge's 6-octet
MAC address. 802.1D-1998 made all 16 bits a settable priority;
802.1t, folded into 802.1D-2004, keeps the four high bits as the
settable priority, in steps of 4096, and makes the other twelve a
system ID extension (the MSTID under MSTP, 0 for the CIST). Bridges
of both kinds are on the wire, so the two octets are a field of their
own (:attr:`STP.root_priority`, :attr:`STP.bridge_priority`) and the
802.1t split is read through accessors, as Wireshark reads it:
:attr:`STP.root_priority_component` (``& 0xF000``) and
:attr:`STP.root_system_id_extension` (``& 0x0FFF``). A Port Identifier
is likewise a four-bit priority and a twelve-bit Port Number; its
priority reads back, through :attr:`STP.port_priority`, in the 8-bit
form whose low four bits are zero that the standard keeps for
management. Linux's bridge, which built this library's fixture, lays
out 6 priority bits and a 10-bit port number instead (``BR_PORT_BITS``
is 10 in ``net/bridge/br_private.h``, and ``br_if.c`` sets a new
port's priority to ``0x8000 >> BR_PORT_BITS``, both read 2026-10-25),
so its default port priority of 32 is ``0x8000`` on the wire: 128
here.

What decode rejects
-------------------
:meth:`STP.decode` raises :class:`~netprotocols.InvalidFieldError` for
the two values that leave no layout to read: a Protocol Identifier
other than 0 (``field="protocol_id"``), the one value every rule of
the standard's validation of received BPDUs requires, and a BPDU Type
other than the three above (``field="bpdu_type"``), since nothing else
says where the BPDU ends. In a walk from LLC DSAP 0x42 only the second
can arise, since :class:`~netprotocols.LLC` does not dispatch a PDU of
another Protocol Identifier there; Wireshark shows the rest of a PDU of
unknown type as data, and here such a PDU ends the walk with the error,
or, lax, on ``stopped_by``. A buffer shorter than its type needs (4, 35 or 36
bytes) raises :class:`~netprotocols.TruncatedHeaderError`. Everything
else is carried verbatim: the version, unused flag bits, a nonzero
Version 1 Length, timer values no bridge would send.

Length, and the bytes after the BPDU
------------------------------------
A BPDU has no length field, but its type gives its exact length, which
is :attr:`STP.header_len`: 4, 35 or 36 octets, never what follows. In
a frame walk the 802.3 Length before the LLC header already ends the
buffer at the end of the PDU (see :mod:`netprotocols.layer2.llc`), so
Ethernet's zero padding and an FCS never reach :meth:`STP.decode`; a
direct call leaves them, too, undecoded. What can reach it is a PDU
longer than its BPDU: "Additional octets in received BPDUs identified
by the validation procedure (14.5) as STP Configuration BPDUs shall be
ignored", says the draft's §14.4, which says the same of RST BPDUs,
and §14.6 i)3) ignores "all octets that appear in the PDU beyond the
largest numbered octet defined" for the version implemented. They stay
outside this layer, after its ``header_len``. ``bytes(STP.decode(x)) ==
x[:header_len]``.

Cisco's PVST+ sends two kinds of BPDU (Cisco's "Troubleshoot PVID and
Type Inconsistencies" document, 24063, read 2026-10-28). Its VLAN 1
BPDUs go untagged to the IEEE address 01-80-C2-00-00-00 as plain BPDUs
at DSAP 0x42, and decode here like any other. Its SSTP BPDUs, sent to
01-00-0C-CC-CC-CD, are the ones that append TLVs to a Configuration or
RST BPDU, and they travel in SNAP under OUI 00-00-0C, PID 0x010B, not
at DSAP 0x42; that is where Wireshark's ``packet-bpdu.c`` attaches its
Cisco TLV parser (``llc.cisco_pid`` ``CISCO_PID_PVSTPP``,
``packet-cisco-pid.h``). The default registry has no entry there, so
such a frame ends the walk at :class:`~netprotocols.SNAP`; reaching
:class:`STP` from it would take an ``llc.snap`` entry at
``(0x00000C << 16) | 0x010B``, and would leave the TLVs, which
Wireshark reads from offset 36 of the BPDU, after the layer.

MSTP is decoded only as far as its RST prefix
---------------------------------------------
An MST BPDU (802.1s, now 802.1Q; Protocol Version 3, type 0x02) is an
RST BPDU followed by a two-octet Version 3 Length, the MST
Configuration Identifier, the CIST's internal fields and up to 64 MSTI
Configuration Messages. :class:`STP` decodes its first 36 octets, the
RST BPDU an 802.1w bridge would read from it, carries its version (3)
verbatim, and leaves the Version 3 information after ``header_len``,
undecoded and not kept in the layer. The draft backs that reading.
Under §14.6 i), an implementation of version 2 interprets a PDU of
version 3 as if it carried version 2, ignoring the parameters and
octets version 2 does not define; and even an MST bridge decodes a
version 3 BPDU as MST only when §14.5 e) holds (102 or more octets, a
Version 1 Length of 0, a Version 3 Length of a whole number of MSTI
messages), and otherwise, by §14.5 d), as an RST BPDU.

Keeping the Version 3 information raw in the layer would need an end
for it. In a walk the 802.3 Length already gives one, but a direct
:meth:`STP.decode` has nothing but the Version 3 Length, and that field
is unreliable on the wire: Wireshark's ``packet-bpdu.c`` notes a Cisco
C3550 IOS release that appears to send it as a count of MSTI messages
rather than of octets, and MST BPDUs whose Version 3 Length is 0 and
whose format selector octet holds the length instead. Read to the end
of the buffer instead, it would take in Ethernet's padding and an FCS,
which ``header_len`` would then cover. In a walk, a caller recovers the
Version 3 information from the frame, after the layer and up to where
the 802.3 Length ends the PDU::

    v3 = frame[packet.consumed : 14 + packet[Ethernet].length]

Behind one VLAN tag the Length is the tag's, 4 bytes later:
``frame[packet.consumed : 18 + packet[VLAN].length]``. Decoding MSTP
properly is later work.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_mac, mac_to_bytes
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)
from netprotocols.utils.mac import validate_mac_addr

__all__ = ["STP"]

#: The BPDU Types (802.1D-2004 §9.3) and their lengths in octets.
_CONFIGURATION = 0x00
_RST = 0x02
_TCN = 0x80
_LENGTHS: dict[int, int] = {_CONFIGURATION: 35, _RST: 36, _TCN: 4}

#: How many of the fields after the prefix (``_BODY_LIMITS``, then the
#: Version 1 Length) each type carries.
_CARRIED: dict[int, int] = {_CONFIGURATION: 9, _RST: 10, _TCN: 0}

#: Display names of the BPDU Types and Protocol Version Identifiers,
#: as Wireshark's packet-bpdu.c (master, fetched 2026-10-25) gives them
#: in ``bpdu_type_vals`` and ``version_id_vals``.
_TYPE_NAMES: dict[int, str] = {
    _CONFIGURATION: "Configuration",
    _RST: "Rapid/Multiple Spanning Tree",
    _TCN: "Topology Change Notification",
}
_VERSION_NAMES: dict[int, str] = {
    0: "Spanning Tree",
    2: "Rapid Spanning Tree",
    3: "Multiple Spanning Tree",
    4: "Shortest Path Tree",
}

#: Port Role values of an RST BPDU (see the module docstring): 1-3 as
#: Wireshark's role_vals names them; 0, which role_vals does not name,
#: is 802.1D-2004's Unknown, which 802.1Q calls Master (the draft's
#: §14.2.9 NOTE).
_ROLE_NAMES: dict[int, str] = {
    0: "Unknown",
    1: "Alternate or Backup",
    2: "Root",
    3: "Designated",
}

#: Flag bits of the Flags octet (802.1D-2004 §9.3.1, §9.3.3).
_TC = 0x01
_PROPOSAL = 0x02
_ROLE_MASK = 0x0C
_LEARNING = 0x10
_FORWARDING = 0x20
_AGREEMENT = 0x40
_TCA = 0x80

#: The fields after the 4-octet prefix that a TCN does not carry, with
#: the largest value each holds: an RST BPDU carries all of them, a
#: Configuration BPDU all but the last.
_BODY_LIMITS: tuple[tuple[str, int], ...] = (
    ("flags", 0xFF),
    ("root_priority", 0xFFFF),
    ("root_path_cost", 0xFFFFFFFF),
    ("bridge_priority", 0xFFFF),
    ("port_id", 0xFFFF),
    ("message_age", 0xFFFF),
    ("max_age", 0xFFFF),
    ("hello_time", 0xFFFF),
    ("forward_delay", 0xFFFF),
)


def _seconds(value: int | None) -> float | None:
    """Convert a timer in 1/256 s units to seconds, keeping ``None``."""
    return None if value is None else value / 256


@dataclass(frozen=True, slots=True)
class STP(Protocol):
    """A Spanning Tree BPDU: Configuration, TCN or RST (802.1D-2004 §9.3).

    The fields after :attr:`bpdu_type` are ``None`` exactly where the
    type does not carry them: all of them in a Topology Change
    Notification, :attr:`version_1_length` in a Configuration BPDU.

    :param protocol_id: Protocol Identifier, always ``0``; anything else
        raises :class:`~netprotocols.InvalidFieldError`.
    :param version: Protocol Version Identifier: ``0`` for STP, ``2``
        for RSTP, ``3`` for MSTP; carried verbatim.
    :param bpdu_type: ``0x00`` Configuration, ``0x02`` RST, ``0x80``
        Topology Change Notification; anything else raises
        :class:`~netprotocols.InvalidFieldError`.
    :param flags: The Flags octet, kept raw; read its bits through
        :attr:`topology_change` and the other flag accessors.
    :param root_priority: The Root Identifier's two priority octets.
    :param root_mac: The Root Identifier's MAC address.
    :param root_path_cost: Root Path Cost (4 octets).
    :param bridge_priority: The Bridge Identifier's two priority octets.
    :param bridge_mac: The Bridge Identifier's MAC address: the sending
        bridge's (in an MST BPDU, the CIST Regional Root's).
    :param port_id: Port Identifier: priority and Port Number.
    :param message_age: Message Age, in 1/256 s.
    :param max_age: Max Age, in 1/256 s.
    :param hello_time: Hello Time, in 1/256 s.
    :param forward_delay: Forward Delay, in 1/256 s.
    :param version_1_length: An RST BPDU's Version 1 Length octet,
        transmitted as ``0``; ``None`` in the other types.
    """

    protocol_id: int
    version: int
    bpdu_type: int
    flags: int | None = None
    root_priority: int | None = None
    root_mac: str | None = None
    root_path_cost: int | None = None
    bridge_priority: int | None = None
    bridge_mac: str | None = None
    port_id: int | None = None
    message_age: int | None = None
    max_age: int | None = None
    hello_time: int | None = None
    forward_delay: int | None = None
    version_1_length: int | None = None

    #: The prefix every BPDU has: Protocol Identifier, Protocol Version
    #: Identifier and BPDU Type.
    _struct: ClassVar[Struct] = Struct("!HBB")

    #: The 31 octets a Configuration and an RST BPDU carry after it.
    _body: ClassVar[Struct] = Struct("!BH6sIH6sHHHHH")

    def __post_init__(self) -> None:
        """Check the prefix, which fields the type carries, and widths.

        :raises InvalidFieldError: a nonzero Protocol Identifier, an
            unknown BPDU Type, a field present that the type does not
            carry or absent that it does, a value too wide for its
            octets, or a MAC address that is not one.
        """
        self._check_prefix(self.protocol_id, self.bpdu_type, offset=None)
        self._check_octets("version", self.version, 0xFF)
        fields = [*_BODY_LIMITS, ("version_1_length", 0xFF)]
        for index, (name, limit) in enumerate(fields):
            self._check_presence(name, index)
            value = getattr(self, name)
            if value is not None:
                self._check_octets(name, value, limit)
        for name in ("root_mac", "bridge_mac"):
            self._check_presence(name, 0)
            value = getattr(self, name)
            if value is not None:
                validate_mac_addr(value, protocol=type(self), field=name)

    def _check_presence(self, name: str, index: int) -> None:
        """Check that field ``name`` is set iff the type carries it.

        ``index`` is the field's position after the prefix: a
        Configuration BPDU carries the first nine, an RST BPDU all ten
        and a TCN none.

        :raises InvalidFieldError: the field is set and the type does
            not carry it, or the other way round.
        """
        expected = index < _CARRIED[self.bpdu_type]
        if (getattr(self, name) is not None) != expected:
            what = "requires" if expected else "has no"
            raise InvalidFieldError(
                f"STP BPDU type {self.bpdu_type:#04x} {what} {name}",
                protocol=type(self),
                field=name,
                expected="a value" if expected else None,
                actual=getattr(self, name),
            )

    @classmethod
    def _check_octets(cls, name: str, value: int, limit: int) -> None:
        """Check that ``value`` fits in 0 to ``limit``.

        :raises InvalidFieldError: it does not.
        """
        if not 0 <= value <= limit:
            raise InvalidFieldError(
                f"STP {name} must be within 0-{limit:#x}, got {value}",
                protocol=cls,
                field=name,
                expected=f"0-{limit:#x}",
                actual=value,
            )

    @classmethod
    def _check_prefix(
        cls, protocol_id: int, bpdu_type: int, *, offset: int | None
    ) -> None:
        """Reject a Protocol Identifier or BPDU Type with no layout.

        :raises InvalidFieldError: the Protocol Identifier is not 0, or
            the type is not 0x00, 0x02 or 0x80. ``offset`` is ``0``
            from :meth:`decode` (``3`` for the type) and ``None`` from
            construction.
        """
        if protocol_id != 0:
            raise InvalidFieldError(
                f"STP Protocol Identifier must be 0, got {protocol_id}",
                protocol=cls,
                field="protocol_id",
                offset=offset,
                expected=0,
                actual=protocol_id,
            )
        if bpdu_type not in _LENGTHS:
            raise InvalidFieldError(
                f"STP BPDU type must be 0x00, 0x02 or 0x80, got {bpdu_type:#x}",
                protocol=cls,
                field="bpdu_type",
                offset=None if offset is None else 3,
                expected="0x00, 0x02 or 0x80",
                actual=bpdu_type,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the BPDU at the start of ``data``; see the module.

        :raises TruncatedHeaderError: ``data`` is shorter than 4 bytes,
            or than the 35 or 36 its type needs (``field="bpdu_type"``).
        :raises InvalidFieldError: the Protocol Identifier is not 0
            (``field="protocol_id"``) or the type is unknown
            (``field="bpdu_type"``).
        """
        protocol_id, version, bpdu_type = cls._unpack_fixed(data)
        cls._check_prefix(protocol_id, bpdu_type, offset=0)
        needed = _LENGTHS[bpdu_type]
        if len(data) < needed:
            raise TruncatedHeaderError(
                f"STP BPDU type {bpdu_type:#04x} needs {needed} bytes, "
                f"buffer holds {len(data)}",
                protocol=cls,
                field="bpdu_type",
                offset=0,
                expected=needed,
                actual=len(data),
            )
        if bpdu_type == _TCN:
            return cls(protocol_id, version, bpdu_type)
        body = cls._body.unpack_from(data, 4)
        return cls(
            protocol_id,
            version,
            bpdu_type,
            flags=body[0],
            root_priority=body[1],
            root_mac=bytes_to_mac(body[2]),
            root_path_cost=body[3],
            bridge_priority=body[4],
            bridge_mac=bytes_to_mac(body[5]),
            port_id=body[6],
            message_age=body[7],
            max_age=body[8],
            hello_time=body[9],
            forward_delay=body[10],
            version_1_length=data[35] if bpdu_type == _RST else None,
        )

    def __bytes__(self) -> bytes:
        """Serialize the BPDU: 4, 35 or 36 octets, as its type has."""
        head = self._struct.pack(self.protocol_id, self.version, self.bpdu_type)
        if self.bpdu_type == _TCN:
            return head
        # __post_init__ has established that a Configuration or RST
        # BPDU carries every one of these.
        body = self._body.pack(
            self.flags,
            self.root_priority,
            mac_to_bytes(self.root_mac or ""),
            self.root_path_cost,
            self.bridge_priority,
            mac_to_bytes(self.bridge_mac or ""),
            self.port_id,
            self.message_age,
            self.max_age,
            self.hello_time,
            self.forward_delay,
        )
        if self.version_1_length is None:
            return head + body
        return head + body + bytes((self.version_1_length,))

    @property
    def header_len(self) -> int:
        """4 octets for a TCN, 35 for a Configuration BPDU, 36 for RST."""
        return _LENGTHS[self.bpdu_type]

    @property
    def bpdu_type_name(self) -> str:
        """Display name of the BPDU Type, e.g. ``"Configuration"``."""
        return _TYPE_NAMES[self.bpdu_type]

    @property
    def version_name(self) -> str:
        """Display name of the version, e.g. ``"Rapid Spanning Tree"``.

        ``"unknown (n)"`` for a version Wireshark does not name.
        """
        return _VERSION_NAMES.get(self.version, f"unknown ({self.version})")

    def _flag(self, bit: int, bpdu_type: int | None = None) -> bool | None:
        """Read flag ``bit``, or ``None`` where the type lacks it.

        ``bpdu_type`` names the one type that defines the bit; ``None``
        means both a Configuration and an RST BPDU do.
        """
        if self.flags is None:
            return None
        if bpdu_type is not None and self.bpdu_type != bpdu_type:
            return None
        return bool(self.flags & bit)

    @property
    def topology_change(self) -> bool | None:
        """The Topology Change flag; ``None`` in a TCN."""
        return self._flag(_TC)

    @property
    def topology_change_ack(self) -> bool | None:
        """The Topology Change Acknowledgment flag.

        ``None`` but in a Configuration BPDU: RSTP leaves the bit unused.
        """
        return self._flag(_TCA, _CONFIGURATION)

    @property
    def proposal(self) -> bool | None:
        """An RST BPDU's Proposal flag; ``None`` in the other types."""
        return self._flag(_PROPOSAL, _RST)

    @property
    def learning(self) -> bool | None:
        """An RST BPDU's Learning flag; ``None`` in the other types."""
        return self._flag(_LEARNING, _RST)

    @property
    def forwarding(self) -> bool | None:
        """An RST BPDU's Forwarding flag; ``None`` in the other types."""
        return self._flag(_FORWARDING, _RST)

    @property
    def agreement(self) -> bool | None:
        """An RST BPDU's Agreement flag; ``None`` in the other types."""
        return self._flag(_AGREEMENT, _RST)

    @property
    def port_role(self) -> int | None:
        """An RST BPDU's two-bit Port Role; ``None`` in the other types.

        1 Alternate or Backup, 2 Root, 3 Designated, 0 Unknown.
        """
        if self.flags is None or self.bpdu_type != _RST:
            return None
        return (self.flags & _ROLE_MASK) >> 2

    @property
    def port_role_name(self) -> str | None:
        """Display name of :attr:`port_role`, e.g. ``"Designated"``."""
        role = self.port_role
        return None if role is None else _ROLE_NAMES[role]

    @property
    def root_priority_component(self) -> int | None:
        """The Root Identifier's settable priority, a multiple of 4096.

        :attr:`root_priority`'s four high bits, as 802.1t reads them.
        """
        return (
            None if self.root_priority is None else self.root_priority & 0xF000
        )

    @property
    def root_system_id_extension(self) -> int | None:
        """The Root Identifier's 12-bit system ID extension (802.1t)."""
        return (
            None if self.root_priority is None else self.root_priority & 0x0FFF
        )

    @property
    def bridge_priority_component(self) -> int | None:
        """The Bridge Identifier's settable priority, a multiple of 4096.

        :attr:`bridge_priority`'s four high bits, as 802.1t reads them.
        """
        priority = self.bridge_priority
        return None if priority is None else priority & 0xF000

    @property
    def bridge_system_id_extension(self) -> int | None:
        """The Bridge Identifier's 12-bit system ID extension (802.1t)."""
        priority = self.bridge_priority
        return None if priority is None else priority & 0x0FFF

    @property
    def root_id_str(self) -> str | None:
        """The Root Identifier as ``"4096/0/02:00:00:00:a0:00"``.

        Priority, system ID extension and MAC, Wireshark's form.
        """
        return _bridge_id_str(self.root_priority, self.root_mac)

    @property
    def bridge_id_str(self) -> str | None:
        """The Bridge Identifier in :attr:`root_id_str`'s form."""
        return _bridge_id_str(self.bridge_priority, self.bridge_mac)

    @property
    def port_priority(self) -> int | None:
        """The Port Identifier's priority: its four high bits, times 16.

        The 8-bit form the standard keeps for management, e.g. ``128``.
        """
        return None if self.port_id is None else self.port_id >> 8 & 0xF0

    @property
    def port_number(self) -> int | None:
        """The Port Identifier's 12-bit Port Number."""
        return None if self.port_id is None else self.port_id & 0x0FFF

    @property
    def message_age_seconds(self) -> float | None:
        """:attr:`message_age` in seconds."""
        return _seconds(self.message_age)

    @property
    def max_age_seconds(self) -> float | None:
        """:attr:`max_age` in seconds."""
        return _seconds(self.max_age)

    @property
    def hello_time_seconds(self) -> float | None:
        """:attr:`hello_time` in seconds."""
        return _seconds(self.hello_time)

    @property
    def forward_delay_seconds(self) -> float | None:
        """:attr:`forward_delay` in seconds."""
        return _seconds(self.forward_delay)


def _bridge_id_str(priority: int | None, mac: str | None) -> str | None:
    """Render a Bridge Identifier as priority/extension/MAC, or ``None``."""
    if priority is None or mac is None:
        return None
    return f"{priority & 0xF000}/{priority & 0x0FFF}/{mac}"
