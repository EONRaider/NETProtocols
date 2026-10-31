"""HSRP — Cisco's Hot Standby Router Protocol, version 1 (RFC 2281).

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
Address as a dotted-decimal string, so
``bytes(HSRP.decode(x)) == x[:20]`` holds by construction. The message
has no length field, and needs none: it is always 20 bytes, so the
decode contract's rule 3 holds as for any fixed header. The layer is
those 20 bytes and nothing more: :attr:`HSRP.header_len` is 20, and
whatever follows stays outside the layer, after it and past a walk's
``packet.consumed``, undecoded and not kept, as VRRP and STP leave what
follows theirs. That is an Ethernet FCS a capture kept, or the 30-byte
MD5 Authentication TLV that some Cisco releases append after the 20
bytes (Wireshark's packet-hsrp.c reads it when a message is exactly 50
bytes long), which is not decoded; a caller who wants it reads it from
the frame, after ``packet.consumed``. Ethernet's padding never
reaches HSRP: the 20 bytes, behind UDP's 8 and IPv4's 20, already fill
Ethernet's 46-byte minimum payload.

Decoding a guess
----------------

HSRP is reached through ``udp.port``, which is best-effort (see
:mod:`netprotocols.registry`), and any 20 bytes would make a header.
:meth:`HSRP.decode` therefore rejects the three leading values no
HSRPv1 message carries: a Version other than 0, an Op Code other than
Hello, Coup or Resign, and a State §5.1 does not list. Each is judged as
soon as its byte is in the buffer, before the length, so a message of
another kind is reported as that (``InvalidFieldError``, ``offset`` 0,
1 or 2) however short it is, and ``TruncatedHeaderError`` is left for a
buffer whose leading bytes all pass. 1 Version, 3 Op Codes and 6 States
pass of the 16,777,216 values the first three bytes can take, so a
random datagram on port 1985 is rejected all but 18 times in that many
(about 1 in 932,000), and always when it is shorter than 20 bytes.
That is rare, not never: of the 90,000 random walks to port 1985
ARCHITECTURE.md describes, about 0.1 are expected to decode an HSRP
layer (90,000 x 18 / 2^24 = 0.097, a little less since a few payloads
are too short to reach 20 bytes), and 2 did, one 46-byte payload walked
both unpadded and padded. The other fields are not judged: any Hellotime,
Holdtime, Priority, Group, Reserved byte, Authentication Data and
Virtual IP Address decodes.

Two kinds of message on the same port are not HSRPv1, and are rejected
by that guard rather than misread as it:

- HSRPv2, which runs on port 1985 too, to 224.0.0.102 rather than
  224.0.0.2, is a sequence of TLVs whose first, the Group State TLV,
  starts with its type, 1, where HSRPv1 has its Version, so every
  HSRPv2 message raises ``InvalidFieldError`` with ``field``
  ``"version"`` and ``actual`` 1. (Its own version, 2, is the TLV's
  third byte.) HSRPv2 is not decoded.
- Op Code 3, the Advertise message of Cisco's HSRP interface-state
  advertisements, is version 0 too, but a 16-byte message whose Op Code
  is followed by a TLV rather than by this header's fields (Wireshark's
  packet-hsrp.c decodes it), so it raises ``InvalidFieldError`` with
  ``field`` ``"opcode"`` and ``actual`` 3, whatever its length. It is
  not decoded either.

A strict :func:`~netprotocols.decode_frame` therefore raises on either,
as it does on NTP's control messages on port 123. Walk such traffic with
``decode_frame(frame, lax=True)``, which keeps Ethernet, IP and UDP and
reports the rejection as ``stopped_by``.

Construction checks only that each field fits its byte, that the
Authentication Data is 8 bytes and that the Virtual IP Address is
dotted-decimal, so a message with a Version, Op Code or State decode
rejects builds, and ``HSRP.decode(bytes(message))`` raises for it,
which ARCHITECTURE.md's round-trip guarantee allows: it covers canonical
headers, which that one is not.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, NoReturn, Self

from netprotocols._base import Protocol, bytes_to_ipv4, ipv4_to_bytes
from netprotocols.utils.exceptions import InvalidFieldError
from netprotocols.utils.ipv4 import validate_ipv4_addr

__all__ = ["HSRP"]

#: The one version RFC 2281 describes (§5.1: "This document describes
#: version 0").
_VERSION = 0

#: Op Codes (RFC 2281 §5.1). Op Code 3, Cisco's Advertise, is named in
#: :data:`_ADVERTISE` only, for the error that rejects it.
_OPCODE_NAMES: dict[int, str] = {0: "Hello", 1: "Coup", 2: "Resign"}

#: The interface-state Advertise message's Op Code, which shares the
#: port and the version but not the layout (Wireshark's packet-hsrp.c).
_ADVERTISE = 3

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
        if value == 1:
            message += " (HSRPv2's Group State TLV type; not decoded)"
    elif field == "opcode":
        expected = "0-2"
        message = f"HSRP opcode must be 0-2, got {value}"
        if value == _ADVERTISE:
            message += " (Cisco's interface-state Advertise; not decoded)"
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
    :raises InvalidFieldError: an integer field does not fit its byte,
        or ``auth_data`` is not 8 bytes long.
    :raises InvalidIPv4AddressError: ``virtual_ip`` is not a
        dotted-decimal IPv4 address.
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

    _struct: ClassVar[Struct] = Struct("!8B8s4s")

    def __post_init__(self) -> None:
        """Check each field's width and the address's form."""
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

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the 20-byte message at the start of ``data``.

        The Version, Op Code and State are judged before the length, in
        that order, each once its byte is present (see "Decoding a
        guess" in the module docstring). Anything after the 20 bytes is
        left undecoded.

        :raises InvalidFieldError: the Version is not 0 (``field``
            ``"version"``, ``offset`` 0), else the Op Code is not 0-2
            (``"opcode"``, 1), else the State is not one RFC 2281
            lists (``"state"``, 2), at any length.
        :raises TruncatedHeaderError: ``data`` is shorter than 20 bytes
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
        )

    def __bytes__(self) -> bytes:
        """Serialize the message to its 20 on-wire bytes."""
        return self._struct.pack(
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

    @property
    def opcode_name(self) -> str:
        """Name the Op Code, e.g. ``"Coup"``.

        Falls back to ``"unknown (n)"`` for a value RFC 2281 does not
        list, which only construction can give (Op Code 3, an
        Advertise, among them).
        """
        return _OPCODE_NAMES.get(self.opcode, f"unknown ({self.opcode})")

    @property
    def state_name(self) -> str:
        """Name the sender's state, e.g. ``"Standby"``.

        Falls back to ``"unknown (n)"`` for a value RFC 2281 does not
        list, which only construction can give.
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
