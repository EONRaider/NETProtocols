"""HSRP — Cisco's Hot Standby Router Protocol: HSRPv1 (RFC 2281) and HSRPv2.

The three formats on UDP port 1985 each have a class: :class:`HSRP` for
the HSRPv1 Hello, Coup and Resign, :class:`HSRPAdvertise` for Cisco's
Op Code 3 interface-state Advertise and :class:`HSRPv2` for HSRPv2 and
HSRP for IPv6.

HSRP lets a group of routers on a LAN present one virtual router to the
hosts on it: one virtual IP address and one virtual MAC address, held by
whichever router is Active, with a Standby router ready to take over
when the Active one stops sending Hellos. RFC 2281 is Informational: it
documents Cisco's protocol, which Cisco calls version 0 on the wire and
HSRPv1 everywhere else. Every message is a 20-byte UDP payload, sent
from and to port 1985, to 224.0.0.2 with TTL 1 (§5.1; TTL 2, which
field captures of Cisco routers are reported to show, decodes the same,
since the TTL is IPv4's and not HSRP's), laid out as::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Version     |   Op Code     |     State     |   Hellotime   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Holdtime    |   Priority    |     Group     |   Reserved    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Authentication  Data                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Authentication  Data                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Virtual IP Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The three Op Codes share that shape and differ only in the value: a
Hello (0) says the sender is running and can become Active or Standby,
a Coup (1) that it wants to become Active, and a Resign (2) that it no
longer wants to be. The State is the sender's own: Initial (0), Learn
(1), Listen (2), Speak (4), Standby (8) or Active (16). The Hellotime
and Holdtime are in seconds and "only meaningful in Hello messages",
though Coups and Resigns carry them too. The Authentication Data is an
8-character clear-text password, ``cisco`` and three NUL bytes when
none is configured (the default §5.1 recommends); it is kept raw, as
sent, and read through :attr:`HSRP.password`. A group's virtual MAC
address, ``00:00:0c:07:ac`` and the group number on any medium but
Token Ring (§6.1), is the Ethernet source of the Hellos its Active
router sends, and is computed by :attr:`HSRP.virtual_mac`.

Every field is kept as its wire value: the eight one-byte fields as
integers, the Authentication Data as its raw 8 bytes and the Virtual IP
Address as a dotted-decimal string. The message has no length field.
The layer is its 20 bytes, or 50 for a message that carries the MD5
Authentication TLV (see "MD5 Authentication" below), and nothing more:
:attr:`HSRP.header_len` is 20 or 50, and whatever follows stays outside
the layer, after it and past a walk's ``packet.consumed``, undecoded
and not kept, as VRRP and STP leave what follows theirs, so the decode
contract's rule 3 holds as for any fixed header and
``bytes(HSRP.decode(x))`` is ``x`` for a message with the TLV and
``x[:20]`` for any other. An Ethernet FCS a capture kept is the
packet's :attr:`~netprotocols.Packet.trailer`. Ethernet's padding
never reaches HSRP: the 20 bytes, behind UDP's 8 and IPv4's 20, already
fill Ethernet's 46-byte minimum payload.

MD5 Authentication
------------------

With MD5 authentication configured, a router appends an MD5
Authentication TLV to the 20 bytes, making a 50-byte message. Its
layout is the one Wireshark's dissector, epan/dissectors/packet-hsrp.c
(commit 6f7207a6), reads at byte 20 of an HSRPv1 message, and the one
it reads for HSRPv2's MD5 Authentication TLV::

    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Type=4     |    Length     |   Algorithm   |   Padding     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Flags             |      IP Address(4octets)      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       IP Address cont.        |         Key ID(4octets)       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Key ID cont.          | Authentication Data(16octets) |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Authentication Data cont.                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Authentication Data cont.                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Authentication Data cont.                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Authentication Data cont.   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The Length, 28, counts the value alone. The Algorithm is 1 for MD5.
packet-hsrp.c describes the Padding byte as zero and the Flags as
undefined, and both are carried verbatim. The IP Address is the sender
interface's, the Key ID names its key chain, and the Authentication
Data is the 16-byte MD5 digest, kept raw and not verified. The TLV is an
:class:`HSRPv2MD5Authentication`, the class HSRPv2's TLV of the same
layout decodes into, held as :attr:`HSRP.md5_authentication`. The
message's own 8-byte Authentication Data is kept raw beside it, as for
any message.

:meth:`HSRP.decode` takes the TLV only where packet-hsrp.c reads one:
when the buffer is exactly 50 bytes long and its bytes 20 and 21 are a
Type of 4 and a Length of 28. Every other buffer decodes to its 20
bytes, with :attr:`HSRP.md5_authentication` ``None`` and what follows
outside the layer: a 50-byte buffer whose bytes 20 and 21 are any
other Type or Length, a Type of 4 with another Length among them,
which packet-hsrp.c reports as an unknown TLV sequence without failing
the message, and a buffer of any other length, whatever its bytes 20
and 21 hold. Nothing in the TLV is judged, so it adds no rejection: a
50-byte buffer decodes wherever its first 20 bytes do, and raises only
what those 20 would. In a walk the buffer ends where the UDP Length
ends the datagram (see "Payload extent" in :mod:`netprotocols._base`),
so the 50 bytes are the whole UDP payload and an FCS after it stays in
the packet's trailer; decoded on its own, :meth:`HSRP.decode` judges
the buffer it is given, so a message with the TLV followed by any byte
decodes to its 20 bytes.

Decoding a guess
----------------

HSRP is reached through ``udp.port``, which is best-effort (see
:mod:`netprotocols.registry`), and any 20 bytes would make a header.
:meth:`HSRP.decode` therefore rejects the three leading values no HSRPv1
message carries: a Version other than 0, an Op Code other than Hello,
Coup or Resign, and a State §5.1 does not list. Each is judged as soon
as its byte is in the buffer, before the length, so a message of another
kind is reported as that (``InvalidFieldError``, ``offset`` 0, 1 or 2)
however short it is, and ``TruncatedHeaderError`` is left for a buffer
whose leading bytes all pass. 1 Version, 3 Op Codes and 6 States pass of
the 16,777,216 values the first three bytes can take, so a random
datagram on port 1985 is rejected all but 18 times in that many (about 1
in 932,000), and always when it is shorter than 20 bytes. That is rare,
not never: a random payload of 20 bytes or more decodes as HSRP that
often. The other fields are not judged: any Hellotime, Holdtime,
Priority, Group, Reserved byte, Authentication Data and Virtual IP
Address decodes, as does any value in an MD5 Authentication TLV's
fields.

Two kinds of message on the same port are not this layout, and
:meth:`HSRP.decode` rejects them rather than misread them as it:

- HSRPv2, which runs on port 1985 too, to 224.0.0.102 rather than
  224.0.0.2, is a sequence of TLVs whose first, the Group State TLV,
  starts with its type, 1, where HSRPv1 has its Version, so
  :meth:`HSRP.decode` raises ``InvalidFieldError`` for every HSRPv2
  message, with ``field`` ``"version"`` and ``actual`` 1, and a message
  that names :class:`HSRPv2`. (HSRPv2's own version, 2, is the TLV's
  third byte.) A walk does not reach that error: it hands the first two
  bytes of the datagram to ``HSRP._for_payload``, which answers
  :class:`HSRPv2` for a first byte of 1, so UDP port 1985 decodes both
  versions (see "HSRPv2" below). The choice holds wherever
  :class:`HSRP` is registered, a port named in ``decode_as`` included.
- Op Code 3, the Advertise message of Cisco's HSRP interface-state
  advertisements, is version 0 too, but a 16-byte message whose Op Code
  is followed by a TLV rather than by this header's fields, so
  :meth:`HSRP.decode` raises ``InvalidFieldError`` for it with
  ``field`` ``"opcode"`` and ``actual`` 3, whatever its length, and a
  message that names :class:`HSRPAdvertise`. A walk does not reach that
  error either: ``HSRP._for_payload`` answers :class:`HSRPAdvertise`
  when the datagram's first two bytes are ``00 03`` (see "Advertise"
  below), wherever :class:`HSRP` is registered.

``HSRP._for_payload`` answers :class:`HSRP` for every other first two
bytes, so UDP port 1985 decodes all three formats, and only a message
that is none of them fails a strict :func:`~netprotocols.decode_frame`.
Walk such traffic with ``decode_frame(frame, lax=True)``, which keeps
Ethernet, IP and UDP and reports the rejection as ``stopped_by``.

Construction checks only that each field fits its byte, that the
Authentication Data is 8 bytes, that the Virtual IP Address is
dotted-decimal and that the MD5 Authentication TLV, if given, is an
:class:`HSRPv2MD5Authentication`, so a message with a Version, Op Code
or State decode rejects builds, and ``HSRP.decode(bytes(message))``
raises for it, which ARCHITECTURE.md's round-trip guarantee allows: it
covers canonical headers, which that one is not. A message built with
an MD5 Authentication TLV serializes to 50 bytes, which decode reads
back with the TLV.

Advertise
---------

The interface-state Advertise has no RFC either. Its layout here is the
one Wireshark's dissector, epan/dissectors/packet-hsrp.c (commit
6f7207a6), reads for a version 0 message to 224.0.0.2 with Op Code 3::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Version     |  Op Code = 3  |           TLV Type            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            TLV Length         |      State    |   Reserved    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Active Group Count        |     Passive Group Count       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           Reserved                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

An interface sends one when HSRP on it enters or leaves the passive
state, when a group on it learns a new Active router, and periodically
while it is passive. The TLV Type is 1 (HSRP interface state) or 2 (IP
redundancy), the State Dormant (1), Passive (2) or Active (3), and the
two counts, of the interface's active and passive groups, range over
0-256 by packet-hsrp.c's description of them. The TLV Length, which
packet-hsrp.c displays but does not hold to any value, and the two
Reserved fields are carried verbatim. A TLV Type 2 (IP redundancy)
message is read with Type 1's layout, as packet-hsrp.c reads both
without branching on the type.

:meth:`HSRPAdvertise.decode` judges four fields, each as soon as its
bytes are in the buffer and before the length: a Version of 0, an Op
Code of 3, a TLV Type of 1 or 2, and a State of 1-3. The TLV Type's high
byte, 0 for both Types, is judged as soon as it is present, and the
whole TLV Type once both its bytes are. Random bytes pass 1 x 1 x 2 x 3
of the 2^40 values of those five bytes, about 1 in 183 billion. Only a
buffer whose leading bytes all pass can raise ``TruncatedHeaderError``,
when it is shorter than 16 bytes. The TLV Length, the counts and the
Reserved fields are not judged. Like :class:`HSRP`'s, the layer is its
16 bytes, and whatever follows stays outside it, so
``bytes(HSRPAdvertise.decode(x)) == x[:16]``.
:meth:`HSRPAdvertise.decode` rejects an HSRPv1 Hello, Coup or Resign at
its Op Code and an HSRPv2 message at its first byte, each with a message
naming the class that decodes it.

Construction checks only that each field fits its width, so an
Advertise with a Version, Op Code, TLV Type or State decode rejects
builds, and decoding its bytes raises.

HSRPv2
------

HSRPv2 is Cisco's and has no RFC. Its layout here is the one Wireshark's
dissector reads, epan/dissectors/packet-hsrp.c (commit 6f7207a6): a
message is a sequence of TLVs, each a 1-byte Type, a 1-byte Length that
counts the value alone, and the value, running to the end of the UDP
datagram. Over IPv4 it is sent from and to UDP port 1985, to
224.0.0.102; HSRP for IPv6 is the same format from and to UDP port
2029, to ff02::66, and that port names :class:`HSRPv2` directly. The
first TLV is the Group State TLV, Type 1 and Length 40::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Type=1     |   Length=40   |    Version    |    Op Code    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     State     |  IP Version   |         Group Number          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Identifier (6 bytes)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Identifier           |      Priority (4 bytes)       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Priority            |     Hello Time (4 bytes)      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Hello Time           |      Hold Time (4 bytes)      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Hold Time           |  Virtual IP Address (16 bytes)|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Virtual IP Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Virtual IP Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Virtual IP Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Virtual IP Address       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The Version is 2. The Op Codes are HSRPv1's: Hello (0), Coup (1) and
Resign (2). The States are numbered apart from HSRPv1's: Disabled (0),
Initial (1), Learn (2), Listen (3), Speak (4), Standby (5) and Active
(6), named here as :class:`HSRP` names their HSRPv1 counterparts. The IP
Version, 4 or 6, says how to read the Virtual IP Address field, which is
16 bytes either way: an IPv6 address fills it, and an IPv4 address takes
its first 4 bytes, the other 12 kept raw as
:attr:`HSRPv2GroupState.virtual_ip_padding`. The Group is 0-4095, the
Identifier is the sender's MAC address, the Priority a 32-bit integer,
and the Hello Time and Hold Time are in milliseconds.

Two more TLVs are decoded where they follow it: the Text Authentication
TLV (Type 3, Length 8), 8 bytes of clear-text password as in HSRPv1's
Authentication Data, and the MD5 Authentication TLV (Type 4, Length
28), an Algorithm byte (1, MD5), a padding byte, 2 bytes of Flags, the
sender's IPv4 address, a 4-byte Key ID and the 16-byte digest, which is
kept raw and not verified. Any other TLV, the Interface State TLV (Type
2) among them, is an :class:`HSRPv2TLV`, its value raw, and a Group
State TLV after the first is decoded as the first is.

:meth:`HSRPv2.decode` judges the Group State TLV's first eight bytes as
soon as each is in the buffer, before the length: the Type must be 1,
the Length 40, the Version 2, the Op Code 0-2, the State 0-6, the IP
Version 4 or 6 and the Group, once both its bytes are present, at most
4095. Only a buffer whose leading bytes all pass can raise
``TruncatedHeaderError``, when it is shorter than the 42-byte TLV. The
rest of the buffer is then walked as TLVs: one whose Length runs past
the buffer, a Type byte with no Length after it, and a Group State,
Text Authentication or MD5 Authentication TLV of another Length or, for
a Group State TLV, with a field the first is held to, raise
``InvalidFieldError``, its ``offset`` counted from the start of the
message. The Priority, the timers, the Identifier and the address are
not judged. The message has no length of its own and keeps the whole
buffer, which a walk ends at the end of the UDP datagram, so
``bytes(HSRPv2.decode(x)) == x`` for every ``x`` decode accepts.

Construction checks that each field fits, that the Group is at most
4095, the IP Version 4 or 6 and the address of that version, and that
the message opens with a Group State TLV; it accepts a Version, Op Code
or State decode rejects. A Group State TLV built without
``virtual_ip_padding`` gets 12 zero bytes for IPv4 and none for IPv6.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, NoReturn, Self, cast

from netprotocols._base import (
    Protocol,
    bytes_to_ipv4,
    bytes_to_ipv6,
    bytes_to_mac,
    ipv4_to_bytes,
    ipv6_to_bytes,
    mac_to_bytes,
)
from netprotocols._tlv import walk_kind_length_value
from netprotocols.utils.exceptions import InvalidFieldError
from netprotocols.utils.ipv4 import validate_ipv4_addr
from netprotocols.utils.mac import validate_mac_addr

__all__ = [
    "HSRP",
    "HSRPAdvertise",
    "HSRPv2",
    "HSRPv2GroupState",
    "HSRPv2MD5Authentication",
    "HSRPv2TLV",
    "HSRPv2TextAuthentication",
]

#: The one version RFC 2281 describes (§5.1: "This document describes
#: version 0").
_VERSION = 0

#: Op Codes (RFC 2281 §5.1). Op Code 3, Cisco's Advertise, is
#: :data:`_ADVERTISE`, decoded by :class:`HSRPAdvertise`.
_OPCODE_NAMES: dict[int, str] = {0: "Hello", 1: "Coup", 2: "Resign"}

#: The Type of HSRPv2's Group State TLV, which opens every HSRPv2
#: message (Wireshark's packet-hsrp.c).
_GROUP_STATE_TYPE = 1

#: The interface-state Advertise message's Op Code, which shares the
#: port and the version but not the layout (Wireshark's packet-hsrp.c).
_ADVERTISE = 3

#: The first two bytes of every Advertise, Version 0 and Op Code 3, as
#: a big-endian 16-bit integer.
_ADVERTISE_LEAD = _VERSION << 8 | _ADVERTISE

#: States (RFC 2281 §5.1), by the value a message carries.
_STATE_NAMES: dict[int, str] = {
    0: "Initial",
    1: "Learn",
    2: "Listen",
    4: "Speak",
    8: "Standby",
    16: "Active",
}

#: The length of the Authentication Data (RFC 2281 §5.1).
_AUTH_DATA_LEN = 8

#: The Authentication Data RFC 2281 §5.1 recommends when none is
#: configured: ``cisco``, NUL-padded to 8 bytes.
_DEFAULT_AUTH_DATA = b"cisco\x00\x00\x00"

#: The first five bytes of a group's virtual MAC address on any medium
#: but Token Ring; the group number is the sixth (RFC 2281 §6.1).
_VIRTUAL_MAC_PREFIX = "00:00:0c:07:ac"

#: The integer fields, each a single byte, in wire order.
_BYTE_FIELDS = (
    "version",
    "opcode",
    "state",
    "hellotime",
    "holdtime",
    "priority",
    "group",
    "reserved",
)


def _reject(owner: type, field: str, offset: int, value: int) -> NoReturn:
    """Raise the decode-time :class:`InvalidFieldError` for ``field``.

    ``offset`` is the field's byte in the message, and ``value`` what
    it holds. Where the value is how a kind of message this class does
    not decode begins (HSRPv2, an Advertise), the error says so.
    """
    expected: str
    if field == "version":
        expected = str(_VERSION)
        message = f"HSRP version must be {_VERSION}, got {value}"
        if value == _GROUP_STATE_TYPE:
            message += " (HSRPv2's Group State TLV type: decode it with HSRPv2)"
    elif field == "opcode":
        expected = "0-2"
        message = f"HSRP opcode must be 0-2, got {value}"
        if value == _ADVERTISE:
            message += " (Cisco's Advertise: decode it with HSRPAdvertise)"
    else:
        expected = ", ".join(str(state) for state in _STATE_NAMES)
        message = f"HSRP state must be one of {expected}, got {value}"
    raise InvalidFieldError(
        message,
        protocol=owner,
        field=field,
        offset=offset,
        expected=expected,
        actual=value,
    )


@dataclass(frozen=True, slots=True)
class HSRP(Protocol):
    """An HSRPv1 message (RFC 2281 §5.1): a Hello, a Coup or a Resign.

    Construction accepts any value that fits each field; :meth:`decode`
    is stricter and rejects a Version other than 0, an unknown Op Code
    and an unknown State (see the module docstring).

    :param version: Version, ``0``: the version RFC 2281 describes,
        HSRPv1 by Cisco's name.
    :param opcode: Op Code: ``0`` Hello, ``1`` Coup, ``2`` Resign (see
        :attr:`opcode_name`).
    :param state: The sender's state: ``0`` Initial, ``1`` Learn, ``2``
        Listen, ``4`` Speak, ``8`` Standby, ``16`` Active (see
        :attr:`state_name`).
    :param hellotime: The sender's interval between Hellos, in seconds;
        ``3`` is RFC 2281's recommended default.
    :param holdtime: How long, in seconds, a receiver should consider
        this Hello valid; ``10`` is the recommended default, and it
        must exceed :attr:`hellotime`, which is not checked.
    :param priority: The sender's priority in the election of the
        Active and Standby routers: the higher wins, the higher IP
        address breaking a tie.
    :param group: The standby group number, ``0``-``255`` (``0``-``2``
        on Token Ring); see :attr:`virtual_mac`.
    :param reserved: The Reserved byte, carried verbatim.
    :param auth_data: The 8 bytes of Authentication Data, kept raw: a
        clear-text password, NUL-padded (see :attr:`password`).
    :param virtual_ip: The group's virtual IP address, dotted-decimal.
    :param md5_authentication: The MD5 Authentication TLV after the 20
        bytes, or ``None``, the default, for a message without one (see
        "MD5 Authentication" in the module docstring).
    :raises InvalidFieldError: if an integer field does not fit its
        byte, ``auth_data`` is not 8 bytes long, or
        ``md5_authentication`` is neither ``None`` nor an
        :class:`HSRPv2MD5Authentication`.
    :raises InvalidIPv4AddressError: if ``virtual_ip`` is not a
        dotted-decimal IPv4 address.

    >>> hsrp = HSRP.decode(
    ...     bytes.fromhex("0000100a0f6e0100") + bytes(8)
    ...     + bytes.fromhex("c00002fe")
    ...     + bytes.fromhex("041c 01 00 0000 c000020b 00000001")
    ...     + bytes(range(16))
    ... )
    >>> hsrp.state_name, hsrp.header_len
    ('Active', 50)
    >>> md5 = hsrp.md5_authentication
    >>> md5.algorithm_name, md5.ip_address, md5.key_id
    ('MD5', '192.0.2.11', 1)
    """

    version: int
    opcode: int
    state: int
    hellotime: int
    holdtime: int
    priority: int
    group: int
    reserved: int
    auth_data: bytes
    virtual_ip: str
    md5_authentication: HSRPv2MD5Authentication | None = None

    _struct: ClassVar[Struct] = Struct("!8B8s4s")

    def __post_init__(self) -> None:
        """Check each field's width, the address's form and the TLV."""
        owner = type(self)
        for name in _BYTE_FIELDS:
            value = getattr(self, name)
            if not 0 <= value <= 0xFF:
                raise InvalidFieldError(
                    f"HSRP {name} must be within 0-255, got {value}",
                    protocol=owner,
                    field=name,
                    expected="0-255",
                    actual=value,
                )
        if len(self.auth_data) != _AUTH_DATA_LEN:
            raise InvalidFieldError(
                f"HSRP auth_data must be {_AUTH_DATA_LEN} bytes, got "
                f"{len(self.auth_data)}",
                protocol=owner,
                field="auth_data",
                expected=_AUTH_DATA_LEN,
                actual=len(self.auth_data),
            )
        validate_ipv4_addr(self.virtual_ip, protocol=owner, field="virtual_ip")
        md5 = self.md5_authentication
        if md5 is not None and not isinstance(md5, HSRPv2MD5Authentication):
            raise InvalidFieldError(
                f"HSRP md5_authentication must be an HSRPv2MD5Authentication "
                f"or None, got {md5!r}",
                protocol=owner,
                field="md5_authentication",
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the message at the start of ``data``.

        The Version, Op Code and State are judged before the length, in
        that order, each once its byte is present (see "Decoding a
        guess" in the module docstring). The message is the first 20
        bytes, and the MD5 Authentication TLV after them when ``data``
        is exactly 50 bytes long and its bytes 20 and 21 are a Type of
        4 and a Length of 28 (see "MD5 Authentication" in the module
        docstring). Anything after the message is left undecoded.

        :param data: The buffer, starting at the Version byte.
        :raises InvalidFieldError: if the Version is not 0 (``field``
            ``"version"``, ``offset`` 0), else the Op Code is not 0-2
            (``"opcode"``, 1), else the State is not one RFC 2281
            lists (``"state"``, 2), at any length.
        :raises TruncatedHeaderError: if ``data`` is shorter than 20 bytes
            and every leading byte it holds passes.
        """
        if len(data) > 0 and data[0] != _VERSION:
            _reject(cls, "version", 0, data[0])
        if len(data) > 1 and data[1] not in _OPCODE_NAMES:
            _reject(cls, "opcode", 1, data[1])
        if len(data) > 2 and data[2] not in _STATE_NAMES:
            _reject(cls, "state", 2, data[2])
        (
            version,
            opcode,
            state,
            hellotime,
            holdtime,
            priority,
            group,
            reserved,
            auth_data,
            virtual_ip,
        ) = cls._unpack_fixed(data)
        md5 = None
        if (
            len(data) == _MD5_MESSAGE_LEN
            and data[_MD5_TLV_AT] == _MD5_AUTH_TYPE
            and data[_MD5_TLV_AT + 1] == _MD5_AUTH.size
        ):
            md5 = _md5_authentication(data, _MD5_TLV_AT + 2)
        return cls(
            version=version,
            opcode=opcode,
            state=state,
            hellotime=hellotime,
            holdtime=holdtime,
            priority=priority,
            group=group,
            reserved=reserved,
            auth_data=auth_data,
            virtual_ip=bytes_to_ipv4(virtual_ip),
            md5_authentication=md5,
        )

    @classmethod
    def _for_payload(cls, lead: int) -> type[Protocol]:
        """Return the class for a payload opening with ``lead``.

        UDP port 1985 carries three formats: an HSRPv2 message opens
        with its Group State TLV's Type, 1, where an HSRPv1 message has
        its Version, 0, and an Advertise opens with Version 0 and Op
        Code 3, so a walk reads ``lead`` before it chooses a header (see
        the module docstring). :class:`HSRPv2` answers a first byte of
        1, :class:`HSRPAdvertise` the two bytes ``00 03``, and ``cls``
        any other ``lead``, which is left to :meth:`decode`.

        :param lead: The first two bytes of the UDP payload, as a
            big-endian 16-bit integer.
        """
        if lead == _ADVERTISE_LEAD:
            return HSRPAdvertise
        return HSRPv2 if lead >> 8 == _GROUP_STATE_TYPE else cls

    def __bytes__(self) -> bytes:
        """Serialize the message: its 20 bytes, then the MD5 TLV if any."""
        header = self._struct.pack(
            self.version,
            self.opcode,
            self.state,
            self.hellotime,
            self.holdtime,
            self.priority,
            self.group,
            self.reserved,
            self.auth_data,
            ipv4_to_bytes(self.virtual_ip),
        )
        if self.md5_authentication is None:
            return header
        return header + bytes(self.md5_authentication)

    @property
    def header_len(self) -> int:
        """The message: 20 bytes, or 50 with the MD5 Authentication TLV."""
        if self.md5_authentication is None:
            return self._struct.size
        return _MD5_MESSAGE_LEN

    @property
    def opcode_name(self) -> str:
        """Name the Op Code, e.g. ``"Coup"``.

        Falls back to ``"unknown (n)"`` for a value RFC 2281 does not
        list (degrades, never raises); only construction can give one,
        Op Code 3, an Advertise's, among them.
        """
        return _OPCODE_NAMES.get(self.opcode, f"unknown ({self.opcode})")

    @property
    def state_name(self) -> str:
        """Name the sender's state, e.g. ``"Standby"``.

        Falls back to ``"unknown (n)"`` for a value RFC 2281 does not
        list, which only construction can give (degrades, never raises).
        """
        return _STATE_NAMES.get(self.state, f"unknown ({self.state})")

    @property
    def password(self) -> bytes:
        """Return the Authentication Data with its NUL padding stripped.

        For the default Authentication Data that is ``b"cisco"``. Only
        trailing NUL bytes are stripped, so no byte before the padding
        is lost; ``b""`` when all eight are NUL.
        """
        return self.auth_data.rstrip(b"\x00")

    @property
    def auth_data_str(self) -> str:
        """Render the Authentication Data for display.

        The :attr:`password` as text when it is printable ASCII, such
        as ``"cisco"`` (``""`` when the field is all NUL bytes), and
        otherwise the 8 bytes in hex, such as ``"0x00ff..."``, which
        never raises.
        """
        password = self.password
        if all(0x20 <= byte < 0x7F for byte in password):
            return password.decode("ascii")
        return "0x" + self.auth_data.hex()

    @property
    def is_default_auth(self) -> bool:
        """Whether the Authentication Data is RFC 2281's default.

        That is ``cisco`` and three NUL bytes (§5.1), which a router
        with no password configured sends.
        """
        return self.auth_data == _DEFAULT_AUTH_DATA

    @property
    def virtual_mac(self) -> str:
        """Return the group's well-known virtual MAC address (§6.1).

        ``00:00:0c:07:ac`` and the group number, e.g.
        ``"00:00:0c:07:ac:01"`` for group 1: the address on any medium
        but Token Ring, which has functional addresses of its own. An
        Active router sends its Hellos from it; a router may use its own
        MAC address instead, which §6.1 strongly discourages.
        """
        return f"{_VIRTUAL_MAC_PREFIX}:{self.group:02x}"


#: Every Op Code packet-hsrp.c names (``hsrp_opcode_vals``).
_ADV_OPCODE_NAMES: dict[int, str] = {**_OPCODE_NAMES, _ADVERTISE: "Advertise"}

#: The Advertise's TLV Types (packet-hsrp.c's ``HSRP_ADV_TYPE_*``).
_ADV_TYPE_NAMES: dict[int, str] = {
    1: "HSRP interface state",
    2: "IP redundancy",
}

#: The Advertise's States (packet-hsrp.c's ``HSRP_ADV_STATE_*``).
_ADV_STATE_NAMES: dict[int, str] = {1: "Dormant", 2: "Passive", 3: "Active"}

#: The Advertise's integer fields and their widths in bits, in wire
#: order.
_ADV_WIDTHS = (
    ("version", 8),
    ("opcode", 8),
    ("tlv_type", 16),
    ("tlv_length", 16),
    ("state", 8),
    ("reserved1", 8),
    ("active_groups", 16),
    ("passive_groups", 16),
    ("reserved2", 32),
)


def _reject_advertise(
    owner: type, field: str, offset: int, value: int
) -> NoReturn:
    """Raise the decode-time :class:`InvalidFieldError` for ``field``.

    ``offset`` is the field's first byte in the message, and ``value``
    what it holds. Where the value is how a kind of message this class
    does not decode begins (HSRPv2, an HSRPv1 Hello, Coup or Resign),
    the error says so.

    :param owner: The class named as ``protocol`` in the error.
    :param field: The field's name.
    :param offset: The field's first byte in the message.
    :param value: The value the field holds.
    :raises InvalidFieldError: always.
    """
    expected: str
    if field == "version":
        expected = str(_VERSION)
        message = f"HSRP Advertise version must be {_VERSION}, got {value}"
        if value == _GROUP_STATE_TYPE:
            message += " (HSRPv2's Group State TLV type: decode it with HSRPv2)"
    elif field == "opcode":
        expected = str(_ADVERTISE)
        message = f"HSRP Advertise opcode must be {_ADVERTISE}, got {value}"
        if value in _OPCODE_NAMES:
            message += f" ({_OPCODE_NAMES[value]}: decode it with HSRP)"
    elif field == "tlv_type":
        expected = "1 or 2"
        message = f"HSRP Advertise TLV type must be 1 or 2, got {value}"
    else:
        expected = "1-3"
        message = f"HSRP Advertise state must be 1-3, got {value}"
    raise InvalidFieldError(
        message,
        protocol=owner,
        field=field,
        offset=offset,
        expected=expected,
        actual=value,
    )


@dataclass(frozen=True, slots=True)
class HSRPAdvertise(Protocol):
    """An HSRP interface-state Advertise: version 0, Op Code 3.

    Its layout is packet-hsrp.c's (see "Advertise" in the module
    docstring). Construction accepts any value that fits each field;
    :meth:`decode` is stricter and rejects a Version other than 0, an
    Op Code other than 3, a TLV Type other than 1 or 2 and a State
    other than 1-3.

    :param version: Version, ``0``.
    :param opcode: Op Code, ``3`` (see :attr:`opcode_name`).
    :param tlv_type: The TLV Type: ``1`` HSRP interface state, ``2`` IP
        redundancy (see :attr:`tlv_type_name`).
    :param tlv_length: The TLV Length, 16 bits, carried verbatim.
    :param state: The interface's state: ``1`` Dormant, ``2`` Passive,
        ``3`` Active (see :attr:`state_name`).
    :param reserved1: The Reserved byte after the State, carried
        verbatim.
    :param active_groups: The number of active groups on the
        interface, 16 bits.
    :param passive_groups: The number of passive groups on the
        interface, 16 bits.
    :param reserved2: The 4 Reserved bytes that end the message, as a
        32-bit integer, carried verbatim.
    :raises InvalidFieldError: if an integer field does not fit its
        width.

    >>> advertise = HSRPAdvertise.decode(
    ...     bytes.fromhex("0003 0001 000e 02 00 0001 0000 00000000")
    ... )
    >>> advertise.opcode_name, advertise.tlv_type_name, advertise.state_name
    ('Advertise', 'HSRP interface state', 'Passive')
    >>> advertise.active_groups, advertise.passive_groups
    (1, 0)
    """

    version: int
    opcode: int
    tlv_type: int
    tlv_length: int
    state: int
    reserved1: int
    active_groups: int
    passive_groups: int
    reserved2: int

    _struct: ClassVar[Struct] = Struct("!BBHHBBHHI")

    def __post_init__(self) -> None:
        """Check each field's width."""
        owner = type(self)
        for name, bits in _ADV_WIDTHS:
            _check_width(owner, name, getattr(self, name), bits)

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the 16-byte Advertise at the start of ``data``.

        The Version, Op Code, TLV Type and State are judged before the
        length, in that order, each once its bytes are present; the TLV
        Type's high byte is judged alone when ``data`` ends after it
        (see "Advertise" in the module docstring). Anything after the
        16 bytes is left undecoded.

        :param data: The buffer, starting at the Version byte.
        :raises InvalidFieldError: if the Version is not 0 (``field``
            ``"version"``, ``offset`` 0), else the Op Code is not 3
            (``"opcode"``, 1), else the TLV Type is not 1 or 2, or
            ``data`` ends after a nonzero high byte of it, whose missing
            low byte is read as 0 (``"tlv_type"``, 2), else the State is
            not 1-3 (``"state"``, 6), at any length.
        :raises TruncatedHeaderError: if ``data`` is shorter than 16
            bytes and every judged field it holds passes.
        """
        if len(data) > 0 and data[0] != _VERSION:
            _reject_advertise(cls, "version", 0, data[0])
        if len(data) > 1 and data[1] != _ADVERTISE:
            _reject_advertise(cls, "opcode", 1, data[1])
        if len(data) > 3:
            tlv_type = data[2] << 8 | data[3]
            if tlv_type not in _ADV_TYPE_NAMES:
                _reject_advertise(cls, "tlv_type", 2, tlv_type)
        elif len(data) > 2 and data[2]:
            _reject_advertise(cls, "tlv_type", 2, data[2] << 8)
        if len(data) > 6 and data[6] not in _ADV_STATE_NAMES:
            _reject_advertise(cls, "state", 6, data[6])
        return cls(*cls._unpack_fixed(data))

    def __bytes__(self) -> bytes:
        """Serialize the Advertise to its 16 on-wire bytes."""
        return self._struct.pack(
            self.version,
            self.opcode,
            self.tlv_type,
            self.tlv_length,
            self.state,
            self.reserved1,
            self.active_groups,
            self.passive_groups,
            self.reserved2,
        )

    @property
    def opcode_name(self) -> str:
        """Name the Op Code, ``"Advertise"`` for 3.

        Op Codes 0-2 are named as :class:`HSRP` names them, and any
        other value, which only construction can give with Op Codes
        0-2, falls back to ``"unknown (n)"`` (degrades, never raises).
        """
        return _ADV_OPCODE_NAMES.get(self.opcode, f"unknown ({self.opcode})")

    @property
    def tlv_type_name(self) -> str:
        """Name the TLV Type, e.g. ``"HSRP interface state"``.

        Falls back to ``"unknown (n)"`` for a value other than 1 or 2,
        which only construction can give (degrades, never raises).
        """
        return _ADV_TYPE_NAMES.get(self.tlv_type, f"unknown ({self.tlv_type})")

    @property
    def state_name(self) -> str:
        """Name the interface's state, e.g. ``"Passive"``.

        Falls back to ``"unknown (n)"`` for a value other than 1-3,
        which only construction can give (degrades, never raises).
        """
        return _ADV_STATE_NAMES.get(self.state, f"unknown ({self.state})")


#: HSRPv2's version, the Group State TLV's first value byte.
_V2_VERSION = 2

#: HSRPv2's States, by the value a Group State TLV carries
#: (packet-hsrp.c's ``HSRP2_STATE_*``), named as :data:`_STATE_NAMES`
#: names their HSRPv1 counterparts.
_V2_STATE_NAMES: dict[int, str] = {
    0: "Disabled",
    1: "Initial",
    2: "Learn",
    3: "Listen",
    4: "Speak",
    5: "Standby",
    6: "Active",
}

#: The IP Versions a Group State TLV can carry, by name.
_IP_VERSION_NAMES: dict[int, str] = {4: "IPv4", 6: "IPv6"}

#: The largest HSRPv2 group number.
_MAX_V2_GROUP = 4095

#: The Types of the TLVs this module decodes into their own classes.
_TEXT_AUTH_TYPE = 3
_MD5_AUTH_TYPE = 4

#: The value Length each typed TLV must have, by Type.
_TLV_LENGTHS: dict[int, int] = {
    _GROUP_STATE_TYPE: 40,
    _TEXT_AUTH_TYPE: 8,
    _MD5_AUTH_TYPE: 28,
}

#: The names of the TLV Types packet-hsrp.c reads.
_TLV_TYPE_NAMES: dict[int, str] = {
    _GROUP_STATE_TYPE: "Group State",
    2: "Interface State",
    _TEXT_AUTH_TYPE: "Text Authentication",
    _MD5_AUTH_TYPE: "MD5 Authentication",
}

#: The MD5 Authentication TLV's Algorithm values, by name.
_MD5_ALGORITHM_NAMES: dict[int, str] = {1: "MD5"}

#: The Virtual IP Address field's length, whatever the IP Version.
_V2_ADDRESS_LEN = 16

#: The length of an IPv4 address.
_IPV4_LEN = 4

#: The length of the MD5 digest.
_MD5_DIGEST_LEN = 16

#: The first four bytes and a half of an HSRPv2 group's virtual MAC
#: address, by IP Version; the group number, in three hex digits, ends
#: it.
_V2_VIRTUAL_MAC_PREFIXES: dict[int, str] = {
    4: "00:00:0c:9f:f",
    6: "00:05:73:a0:0",
}

#: The Group State TLV, header included: Type, Length, Version, Op Code,
#: State, IP Version, Group, Identifier, Priority, Hello Time, Hold Time
#: and the Virtual IP Address field.
_GROUP_STATE = Struct("!6BH6sIII16s")

#: The MD5 Authentication TLV's value: Algorithm, padding, Flags, IP
#: Address, Key ID and digest.
_MD5_AUTH = Struct("!BBH4sI16s")

#: The offset of the MD5 Authentication TLV in an HSRPv1 message: the
#: end of its 20 bytes.
_MD5_TLV_AT = 20

#: The length of an HSRPv1 message that carries the MD5 Authentication
#: TLV: the 20 bytes, then the TLV's Type, Length and 28-byte value.
_MD5_MESSAGE_LEN = _MD5_TLV_AT + 2 + _MD5_AUTH.size

#: The Group State TLV's one-byte fields that decode judges: each one's
#: offset in the TLV, name, accepted values and those values in words.
_V2_JUDGED: tuple[tuple[int, str, frozenset[int], str], ...] = (
    (0, "type", frozenset((_GROUP_STATE_TYPE,)), "1"),
    (1, "length", frozenset((_TLV_LENGTHS[_GROUP_STATE_TYPE],)), "40"),
    (2, "version", frozenset((_V2_VERSION,)), "2"),
    (3, "opcode", frozenset(_OPCODE_NAMES), "0-2"),
    (4, "state", frozenset(_V2_STATE_NAMES), "0-6"),
    (5, "ip_version", frozenset(_IP_VERSION_NAMES), "4 or 6"),
)


def _check_width(owner: type, field: str, value: int, bits: int) -> None:
    """Raise :class:`InvalidFieldError` unless ``value`` fits ``bits``.

    :param owner: The class named as ``protocol`` in a raised error.
    :param field: The field's name.
    :param value: The field's value.
    :param bits: The field's width in bits.
    :raises InvalidFieldError: if ``value`` is negative or wider.
    """
    top = (1 << bits) - 1
    if not 0 <= value <= top:
        raise InvalidFieldError(
            f"{owner.__name__} {field} must be within 0-{top}, got {value}",
            protocol=owner,
            field=field,
            expected=f"0-{top}",
            actual=value,
        )


def _check_len(owner: type, field: str, value: bytes, length: int) -> None:
    """Raise :class:`InvalidFieldError` unless ``value`` is ``length`` long.

    :param owner: The class named as ``protocol`` in a raised error.
    :param field: The field's name.
    :param value: The field's bytes.
    :param length: The length they must have.
    :raises InvalidFieldError: if ``len(value)`` is not ``length``.
    """
    if len(value) != length:
        raise InvalidFieldError(
            f"{owner.__name__} {field} must be {length} bytes, got "
            f"{len(value)}",
            protocol=owner,
            field=field,
            expected=length,
            actual=len(value),
        )


def _check_ipv6(owner: type, address: str) -> None:
    """Raise :class:`InvalidFieldError` unless ``address`` is IPv6 text.

    :param owner: The class named as ``protocol`` in a raised error.
    :param address: The ``virtual_ip`` to check.
    :raises InvalidFieldError: if ``address`` is not a string, or not an
        IPv6 address.
    """
    valid = isinstance(address, str)
    if valid:
        try:
            ipv6_to_bytes(address)
        except OSError:
            valid = False
    if not valid:
        raise InvalidFieldError(
            f"{owner.__name__} virtual_ip {address!r} is not an IPv6 address",
            protocol=owner,
            field="virtual_ip",
            actual=address,
        )


def _judge_group_state(owner: type, data: bytes | memoryview, at: int) -> None:
    """Judge the Group State TLV that starts at ``at`` in ``data``.

    Each of the fields in :data:`_V2_JUDGED` is judged once its byte is
    in ``data``, in wire order, and then the Group once both its bytes
    are (see "HSRPv2" in the module docstring).

    :param owner: The class named as ``protocol`` in a raised error.
    :param data: The message.
    :param at: The offset of the TLV's Type byte in ``data``.
    :raises InvalidFieldError: if a judged field holds a value no Group
        State TLV carries, ``offset`` that field's in ``data``.
    """
    for position, field, accepted, expected in _V2_JUDGED:
        offset = at + position
        if len(data) <= offset:
            return
        value = data[offset]
        if value not in accepted:
            raise InvalidFieldError(
                f"HSRPv2 Group State TLV {field} must be {expected}, got "
                f"{value}",
                protocol=owner,
                field=field,
                offset=offset,
                expected=expected,
                actual=value,
            )
    if len(data) < at + 8:
        return
    group = int.from_bytes(data[at + 6 : at + 8])
    if group > _MAX_V2_GROUP:
        raise InvalidFieldError(
            f"HSRPv2 group must be at most {_MAX_V2_GROUP}, got {group}",
            protocol=owner,
            field="group",
            offset=at + 6,
            expected=f"0-{_MAX_V2_GROUP}",
            actual=group,
        )


@dataclass(frozen=True, slots=True)
class HSRPv2GroupState:
    """An HSRPv2 Group State TLV: Type 1, Length 40.

    Its layout is packet-hsrp.c's (see "HSRPv2" in the module
    docstring). Construction accepts any Version, Op Code and State
    that fits its byte; :meth:`HSRPv2.decode` is stricter.

    :param version: Version, ``2``.
    :param opcode: Op Code: ``0`` Hello, ``1`` Coup, ``2`` Resign (see
        :attr:`opcode_name`).
    :param state: The sender's state: ``0`` Disabled, ``1`` Initial,
        ``2`` Learn, ``3`` Listen, ``4`` Speak, ``5`` Standby, ``6``
        Active (see :attr:`state_name`).
    :param ip_version: ``4`` or ``6``: the version of
        :attr:`virtual_ip`.
    :param group: The standby group number, ``0``-``4095``.
    :param identifier: The sender's MAC address, colon-separated.
    :param priority: The sender's priority in the election of the
        Active and Standby routers, 32 bits.
    :param hellotime: The sender's interval between Hellos, in
        milliseconds, 32 bits.
    :param holdtime: How long, in milliseconds, a receiver should
        consider this Hello valid, 32 bits.
    :param virtual_ip: The group's virtual IP address: dotted-decimal
        for ``ip_version`` 4, RFC 5952 text for 6.
    :param virtual_ip_padding: The 12 bytes of the Virtual IP Address
        field after an IPv4 address, kept raw; ``b""`` for IPv6, whose
        address fills the field. ``None``, the default, stands for
        ``bytes(12)`` for IPv4 and ``b""`` for IPv6, and the field holds
        that value once constructed.
    :raises InvalidFieldError: if an integer field does not fit its
        width, ``group`` exceeds 4095, ``ip_version`` is neither 4 nor
        6, ``virtual_ip`` is not an address of that version, or a given
        ``virtual_ip_padding`` is not 12 bytes for IPv4 and empty for
        IPv6.
    :raises InvalidMACAddressError: if ``identifier`` is not a MAC
        address.

    ``bytes(tlv)`` is the 42-byte TLV, its Type and Length included.
    :func:`dataclasses.replace` copies the current
    ``virtual_ip_padding``, so a replace that changes ``ip_version``
    also needs ``virtual_ip_padding=None``, or the padding of the new
    version, passed with it.
    """

    version: int
    opcode: int
    state: int
    ip_version: int
    group: int
    identifier: str
    priority: int
    hellotime: int
    holdtime: int
    virtual_ip: str
    virtual_ip_padding: bytes | None = None

    #: The TLV's Type.
    type: ClassVar[int] = _GROUP_STATE_TYPE

    def __post_init__(self) -> None:
        """Check each field's width and the address's form.

        A ``virtual_ip_padding`` of ``None`` is replaced by the padding
        of its IP Version: ``bytes(12)`` for IPv4, ``b""`` for IPv6.
        """
        owner = type(self)
        for name in ("version", "opcode", "state", "ip_version"):
            _check_width(owner, name, getattr(self, name), 8)
        if self.ip_version not in _IP_VERSION_NAMES:
            raise InvalidFieldError(
                f"HSRPv2GroupState ip_version must be 4 or 6, got "
                f"{self.ip_version}",
                protocol=owner,
                field="ip_version",
                expected="4 or 6",
                actual=self.ip_version,
            )
        if not 0 <= self.group <= _MAX_V2_GROUP:
            raise InvalidFieldError(
                f"HSRPv2GroupState group must be within 0-{_MAX_V2_GROUP}, "
                f"got {self.group}",
                protocol=owner,
                field="group",
                expected=f"0-{_MAX_V2_GROUP}",
                actual=self.group,
            )
        validate_mac_addr(self.identifier, protocol=owner, field="identifier")
        for name in ("priority", "hellotime", "holdtime"):
            _check_width(owner, name, getattr(self, name), 32)
        if self.ip_version == 4:
            validate_ipv4_addr(
                self.virtual_ip, protocol=owner, field="virtual_ip"
            )
            padding = _V2_ADDRESS_LEN - _IPV4_LEN
        else:
            _check_ipv6(owner, self.virtual_ip)
            padding = 0
        fill = self.virtual_ip_padding
        if fill is None:
            fill = bytes(padding)
            object.__setattr__(self, "virtual_ip_padding", fill)
        _check_len(owner, "virtual_ip_padding", fill, padding)

    def __bytes__(self) -> bytes:
        """Serialize the TLV: Type, Length, then its 40 bytes of value."""
        if self.ip_version == 4:
            address = ipv4_to_bytes(self.virtual_ip) + cast(
                bytes, self.virtual_ip_padding
            )
        else:
            address = ipv6_to_bytes(self.virtual_ip)
        return _GROUP_STATE.pack(
            self.type,
            _TLV_LENGTHS[self.type],
            self.version,
            self.opcode,
            self.state,
            self.ip_version,
            self.group,
            mac_to_bytes(self.identifier),
            self.priority,
            self.hellotime,
            self.holdtime,
            address,
        )

    @property
    def opcode_name(self) -> str:
        """Name the Op Code, e.g. ``"Hello"``.

        Falls back to ``"unknown (n)"`` for a value other than 0-2,
        which only construction can give (degrades, never raises).
        """
        return _OPCODE_NAMES.get(self.opcode, f"unknown ({self.opcode})")

    @property
    def state_name(self) -> str:
        """Name the sender's state, e.g. ``"Active"``.

        Falls back to ``"unknown (n)"`` for a value other than 0-6,
        which only construction can give (degrades, never raises).
        """
        return _V2_STATE_NAMES.get(self.state, f"unknown ({self.state})")

    @property
    def ip_version_name(self) -> str:
        """Name the IP Version, ``"IPv4"`` or ``"IPv6"``.

        Construction accepts no other, so this never raises.
        """
        return _IP_VERSION_NAMES[self.ip_version]

    @property
    def virtual_mac(self) -> str:
        """Return the group's well-known HSRPv2 virtual MAC address.

        ``00:00:0c:9f:f`` and the group number in three hex digits for
        an IPv4 group, ``"00:00:0c:9f:f0:01"`` for group 1, and
        ``00:05:73:a0:0`` and the group number for an IPv6 group,
        ``"00:05:73:a0:00:01"`` for group 1: the ranges Cisco gives
        HSRPv2 over IPv4, 0000.0C9F.F000-0000.0C9F.FFFF (Cisco's
        "Configuring HSRP" chapter for the Nexus 3000 Series, read
        2026-11-07,
        https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus3000/sw/unicast/nexus3000_unicast_config_gd_503_u1_1/l3_hsrp.html),
        and HSRP for IPv6, 0005.73A0.0000-0005.73A0.0FFF (Cisco IOS
        XE's "Configuring First Hop Redundancy Protocols in IPv6", of
        the IPv6 configuration guide for Release 3SG, read 2026-11-07,
        https://www.cisco.com/en/US/docs/ios-xml/ios/ipv6/configuration/xe-3sg/ip6-fhrp.pdf).
        Never raises.
        """
        prefix = _V2_VIRTUAL_MAC_PREFIXES[self.ip_version]
        digits = f"{self.group:03x}"
        return f"{prefix}{digits[0]}:{digits[1:]}"


@dataclass(frozen=True, slots=True)
class HSRPv2TextAuthentication:
    """An HSRPv2 Text Authentication TLV: Type 3, Length 8.

    :param auth_data: The 8 bytes of Authentication Data, kept raw: a
        clear-text password, NUL-padded, as in HSRPv1's (see
        :attr:`password`).
    :raises InvalidFieldError: if ``auth_data`` is not 8 bytes long.

    ``bytes(tlv)`` is the 10-byte TLV, its Type and Length included.
    """

    auth_data: bytes

    #: The TLV's Type.
    type: ClassVar[int] = _TEXT_AUTH_TYPE

    def __post_init__(self) -> None:
        """Check the Authentication Data's length."""
        _check_len(type(self), "auth_data", self.auth_data, _AUTH_DATA_LEN)

    def __bytes__(self) -> bytes:
        """Serialize the TLV: Type, Length, then the Authentication Data."""
        return bytes([self.type, _AUTH_DATA_LEN]) + self.auth_data

    @property
    def password(self) -> bytes:
        """Return the Authentication Data with its NUL padding stripped.

        Only trailing NUL bytes are stripped; ``b""`` when all eight are
        NUL.
        """
        return self.auth_data.rstrip(b"\x00")

    @property
    def auth_data_str(self) -> str:
        """Render the Authentication Data for display.

        The :attr:`password` as text when it is printable ASCII, such
        as ``"cisco"``, and otherwise the 8 bytes in hex, such as
        ``"0x00ff..."``, which never raises.
        """
        password = self.password
        if all(0x20 <= byte < 0x7F for byte in password):
            return password.decode("ascii")
        return "0x" + self.auth_data.hex()

    @property
    def is_default_auth(self) -> bool:
        """Whether the Authentication Data is ``cisco`` and three NULs.

        That is HSRPv1's default Authentication Data (RFC 2281 §5.1).
        """
        return self.auth_data == _DEFAULT_AUTH_DATA


@dataclass(frozen=True, slots=True)
class HSRPv2MD5Authentication:
    """An MD5 Authentication TLV: Type 4, Length 28.

    HSRPv2 carries it among its TLVs (see :attr:`HSRPv2.md5_authentication`)
    and an HSRPv1 message after its 20 bytes (see
    :attr:`HSRP.md5_authentication`), in one layout (see "MD5
    Authentication" in the module docstring).

    :param algorithm: The hash algorithm, ``1`` for MD5 (see
        :attr:`algorithm_name`).
    :param padding: The byte after the Algorithm, carried verbatim.
    :param flags: The 16-bit Flags, carried verbatim.
    :param ip_address: The sender's IPv4 address, dotted-decimal.
    :param key_id: The 32-bit Key ID.
    :param digest: The 16-byte MD5 digest, kept raw and not verified.
    :raises InvalidFieldError: if an integer field does not fit its
        width, or ``digest`` is not 16 bytes long.
    :raises InvalidIPv4AddressError: if ``ip_address`` is not a
        dotted-decimal IPv4 address.

    ``bytes(tlv)`` is the 30-byte TLV, its Type and Length included.
    """

    algorithm: int
    padding: int
    flags: int
    ip_address: str
    key_id: int
    digest: bytes

    #: The TLV's Type.
    type: ClassVar[int] = _MD5_AUTH_TYPE

    def __post_init__(self) -> None:
        """Check each field's width and the address's form."""
        owner = type(self)
        _check_width(owner, "algorithm", self.algorithm, 8)
        _check_width(owner, "padding", self.padding, 8)
        _check_width(owner, "flags", self.flags, 16)
        validate_ipv4_addr(self.ip_address, protocol=owner, field="ip_address")
        _check_width(owner, "key_id", self.key_id, 32)
        _check_len(owner, "digest", self.digest, _MD5_DIGEST_LEN)

    def __bytes__(self) -> bytes:
        """Serialize the TLV: Type, Length, then its 28 bytes of value."""
        return bytes([self.type, _MD5_AUTH.size]) + _MD5_AUTH.pack(
            self.algorithm,
            self.padding,
            self.flags,
            ipv4_to_bytes(self.ip_address),
            self.key_id,
            self.digest,
        )

    @property
    def algorithm_name(self) -> str:
        """Name the Algorithm, ``"MD5"`` for 1.

        Falls back to ``"unknown (n)"`` for any other value (degrades,
        never raises).
        """
        return _MD5_ALGORITHM_NAMES.get(
            self.algorithm, f"unknown ({self.algorithm})"
        )


def _md5_authentication(
    data: bytes | memoryview, at: int
) -> HSRPv2MD5Authentication:
    """Build the MD5 Authentication TLV whose value starts at ``at``.

    Every value of its 28 bytes builds one, so this never raises.

    :param data: A buffer holding the 28-byte value from ``at`` on.
    :param at: The offset of the value, past the Type and Length.
    """
    algorithm, padding, flags, address, key_id, digest = _MD5_AUTH.unpack_from(
        data, at
    )
    return HSRPv2MD5Authentication(
        algorithm=algorithm,
        padding=padding,
        flags=flags,
        ip_address=bytes_to_ipv4(address),
        key_id=key_id,
        digest=digest,
    )


@dataclass(frozen=True, slots=True)
class HSRPv2TLV:
    """An HSRPv2 TLV of a Type this module does not decode, its value raw.

    :param type: The Type, ``0``-``255`` but 1, 3 and 4, which have
        their own classes (see :attr:`type_name`).
    :param value: The value, at most 255 bytes.
    :raises InvalidFieldError: if ``type`` does not fit a byte or is 1,
        3 or 4, or ``value`` is longer than 255 bytes.

    ``bytes(tlv)`` is the TLV: Type, a Length of ``len(value)``, then
    the value.
    """

    type: int
    value: bytes = b""

    def __post_init__(self) -> None:
        """Check the Type and the value's length."""
        owner = type(self)
        _check_width(owner, "type", self.type, 8)
        if self.type in _TLV_LENGTHS:
            raise InvalidFieldError(
                f"HSRPv2TLV type {self.type} is the "
                f"{_TLV_TYPE_NAMES[self.type]} TLV, which has its own class",
                protocol=owner,
                field="type",
                actual=self.type,
            )
        if len(self.value) > 0xFF:
            raise InvalidFieldError(
                f"HSRPv2TLV value must be at most 255 bytes, got "
                f"{len(self.value)}",
                protocol=owner,
                field="value",
                expected="<=255",
                actual=len(self.value),
            )

    def __bytes__(self) -> bytes:
        """Serialize the TLV: Type, Length, then the value."""
        return bytes([self.type, len(self.value)]) + self.value

    @property
    def type_name(self) -> str:
        """Name the Type, e.g. ``"Interface State"``.

        Falls back to ``"unknown (n)"`` for a Type packet-hsrp.c does
        not name (degrades, never raises).
        """
        return _TLV_TYPE_NAMES.get(self.type, f"unknown ({self.type})")


#: Any of the TLVs an :class:`HSRPv2` message holds.
_HSRPv2Record = (
    HSRPv2GroupState
    | HSRPv2TextAuthentication
    | HSRPv2MD5Authentication
    | HSRPv2TLV
)

#: The classes of :data:`_HSRPv2Record`, for ``isinstance``.
_RECORD_CLASSES = (
    HSRPv2GroupState,
    HSRPv2TextAuthentication,
    HSRPv2MD5Authentication,
    HSRPv2TLV,
)


def _record(
    owner: type, data: bytes, kind: int, value: bytes, at: int
) -> _HSRPv2Record:
    """Decode the TLV of Type ``kind`` and ``value`` at ``at`` in ``data``.

    :param owner: The class named as ``protocol`` in a raised error.
    :param data: The message.
    :param kind: The TLV's Type.
    :param value: The TLV's value.
    :param at: The offset of the TLV's Type byte in ``data``.
    :raises InvalidFieldError: if a Group State, Text Authentication or
        MD5 Authentication TLV has another Length (``field``
        ``"length"``), or a Group State TLV a field decode judges that
        holds a value it rejects.
    """
    length = _TLV_LENGTHS.get(kind)
    if length is None:
        return HSRPv2TLV(type=kind, value=value)
    if len(value) != length:
        raise InvalidFieldError(
            f"HSRPv2 {_TLV_TYPE_NAMES[kind]} TLV length must be {length}, "
            f"got {len(value)}",
            protocol=owner,
            field="length",
            offset=at + 1,
            expected=str(length),
            actual=len(value),
        )
    if kind == _TEXT_AUTH_TYPE:
        return HSRPv2TextAuthentication(auth_data=value)
    if kind == _MD5_AUTH_TYPE:
        return _md5_authentication(value, 0)
    _judge_group_state(owner, data, at)
    return _group_state(data[at : at + _GROUP_STATE.size])


def _group_state(tlv: bytes) -> HSRPv2GroupState:
    """Build the Group State TLV ``tlv``, whose judged fields all pass.

    :param tlv: The 42 bytes of the TLV, its Type and Length included.
    """
    (
        _,
        _,
        version,
        opcode,
        state,
        ip_version,
        group,
        identifier,
        priority,
        hellotime,
        holdtime,
        address,
    ) = _GROUP_STATE.unpack(tlv)
    if ip_version == 4:
        virtual_ip = bytes_to_ipv4(address[:_IPV4_LEN])
        padding = address[_IPV4_LEN:]
    else:
        virtual_ip = bytes_to_ipv6(address)
        padding = b""
    return HSRPv2GroupState(
        version=version,
        opcode=opcode,
        state=state,
        ip_version=ip_version,
        group=group,
        identifier=bytes_to_mac(identifier),
        priority=priority,
        hellotime=hellotime,
        holdtime=holdtime,
        virtual_ip=virtual_ip,
        virtual_ip_padding=padding,
    )


@dataclass(frozen=True, slots=True)
class HSRPv2(Protocol):
    """An HSRPv2 message, or an HSRP for IPv6 one: a sequence of TLVs.

    The first is the Group State TLV; Text Authentication, MD5
    Authentication and further Group State TLVs are decoded into their
    classes, and any other TLV is kept raw (see "HSRPv2" in the module
    docstring).

    :param tlvs: The TLVs, in wire order, the first an
        :class:`HSRPv2GroupState`.
    :raises InvalidFieldError: if ``tlvs`` is empty, does not open with
        an :class:`HSRPv2GroupState`, or holds anything but the four TLV
        classes.

    >>> message = HSRPv2.decode(
    ...     bytes.fromhex("0128020006040001020000000001")
    ...     + bytes.fromhex("000000640000 0bb8 00002710 c0000201")
    ...     + bytes(12)
    ... )
    >>> state = message.group_state
    >>> state.opcode_name, state.state_name, state.virtual_ip
    ('Hello', 'Active', '192.0.2.1')
    >>> state.hellotime, state.holdtime, state.virtual_mac
    (3000, 10000, '00:00:0c:9f:f0:01')
    """

    tlvs: tuple[_HSRPv2Record, ...]

    #: The Group State TLV that opens every message, header included.
    _struct: ClassVar[Struct] = _GROUP_STATE

    def __post_init__(self) -> None:
        """Check that the TLVs open with a Group State TLV."""
        owner = type(self)
        if not self.tlvs or not isinstance(self.tlvs[0], HSRPv2GroupState):
            raise InvalidFieldError(
                "HSRPv2 tlvs must open with an HSRPv2GroupState",
                protocol=owner,
                field="tlvs",
            )
        for tlv in self.tlvs:
            if not isinstance(tlv, _RECORD_CLASSES):
                raise InvalidFieldError(
                    f"HSRPv2 tlvs must hold HSRPv2 TLVs, got {tlv!r}",
                    protocol=owner,
                    field="tlvs",
                )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the HSRPv2 message that fills ``data``.

        The Group State TLV's judged fields come first, each once its
        bytes are present, then its length, then the walk of every TLV
        to the end of ``data`` (see "HSRPv2" in the module docstring).

        :param data: The buffer, starting at the Group State TLV's Type.
        :raises InvalidFieldError: if the first TLV's Type is not 1
            (``field`` ``"type"``, ``offset`` 0), its Length not 40
            (``"length"``, 1), its Version not 2 (``"version"``, 2), its
            Op Code not 0-2 (``"opcode"``, 3), its State not 0-6
            (``"state"``, 4), its IP Version neither 4 nor 6
            (``"ip_version"``, 5) or its Group above 4095 (``"group"``,
            6), at any length; or if a later TLV breaks the walk
            (``"tlvs"``), has a Length its Type does not allow
            (``"length"``), or is a Group State TLV with a field the
            first is held to that fails, ``offset`` counted from the
            start of ``data``.
        :raises TruncatedHeaderError: if ``data`` is shorter than the
            42-byte Group State TLV and every judged byte it holds
            passes.
        """
        _judge_group_state(cls, data, 0)
        cls._unpack_fixed(data)
        raw = bytes(data)
        tlvs: list[_HSRPv2Record] = []
        cursor = 0
        for kind, value in walk_kind_length_value(
            raw,
            lone_byte_kinds=frozenset(),
            terminator_kind=None,
            min_option_length=None,
            length_includes_header=False,
            protocol=cls,
            field="tlvs",
        ):
            tlvs.append(_record(cls, raw, kind, value, cursor))
            cursor += 2 + len(value)
        return cls(tlvs=tuple(tlvs))

    def __bytes__(self) -> bytes:
        """Serialize the message: every TLV, in order."""
        return b"".join(bytes(tlv) for tlv in self.tlvs)

    @property
    def header_len(self) -> int:
        """The whole message: every TLV.

        The message runs to the end of the datagram: HSRPv2 is terminal.
        """
        return sum(len(bytes(tlv)) for tlv in self.tlvs)

    @property
    def group_state(self) -> HSRPv2GroupState:
        """The Group State TLV that opens the message."""
        return cast(HSRPv2GroupState, self.tlvs[0])

    @property
    def text_authentication(self) -> HSRPv2TextAuthentication | None:
        """The first Text Authentication TLV; ``None`` if there is none."""
        for tlv in self.tlvs:
            if isinstance(tlv, HSRPv2TextAuthentication):
                return tlv
        return None

    @property
    def md5_authentication(self) -> HSRPv2MD5Authentication | None:
        """The first MD5 Authentication TLV; ``None`` if there is none."""
        for tlv in self.tlvs:
            if isinstance(tlv, HSRPv2MD5Authentication):
                return tlv
        return None
