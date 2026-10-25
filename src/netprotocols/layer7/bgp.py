"""BGP-4 messages (RFC 4271), the inter-domain routing protocol.

BGP runs over TCP port 179. Every message starts with a 19-byte common
header (§4.1)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                           Marker                              |
   +                    (16 bytes, all ones)                       +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Length               |      Type     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

followed by a body whose layout the Type selects: OPEN (1, §4.2),
UPDATE (2, §4.3), NOTIFICATION (3, §4.5), KEEPALIVE (4, §4.4, no body)
and ROUTE-REFRESH (5, RFC 2918). One :class:`BGP` instance is one
message. Its header is decoded into fields and the body is kept as raw
``bytes``, so ``bytes(BGP.decode(x)) == x[:header_len]`` holds by
construction. Accessors parse the body on demand and return ``None``
for a message of another type: :attr:`BGP.version`,
:attr:`BGP.my_as`, :attr:`BGP.hold_time`, :attr:`BGP.bgp_identifier`
and :attr:`BGP.optional_parameters` for OPEN;
:attr:`BGP.withdrawn_routes`, :attr:`BGP.path_attributes` and
:attr:`BGP.nlri` for UPDATE; :attr:`BGP.error_code`,
:attr:`BGP.error_subcode` and :attr:`BGP.error_data` for NOTIFICATION.
A ROUTE-REFRESH body is kept raw.

Validation
----------
BGP is reached through ``tcp.port``, which is a guess (see
:mod:`netprotocols.registry`), so :meth:`BGP.decode` checks everything
the header lets it check, in the order RFC 4271 §6.1 does: the Marker
must be all ones, the Length at least 19, the Type one of the five
above, and the Length within that type's bounds — exactly 19 for
KEEPALIVE, at least 29 for OPEN, 23 for UPDATE and ROUTE-REFRESH and 21
for NOTIFICATION, and at most 4096 for OPEN. A failure raises
:class:`~netprotocols.InvalidFieldError`. Only then is the Length held
against the buffer, so a message the buffer cuts short raises
:class:`~netprotocols.TruncatedHeaderError` rather than an invalid-field
error. The upper bound is 65535 for the other types: RFC 8654 lets
UPDATE, NOTIFICATION and ROUTE-REFRESH grow past RFC 4271's 4096 bytes
once both speakers advertise the Extended Message capability, and the
OPEN that negotiates it may be in another capture or another segment,
so the decoder accepts the larger messages rather than reject a
session it cannot see the start of. RFC 8654 §4 keeps OPEN and
KEEPALIVE at 4096 or less, and so does the decoder.

The body is not validated on decode: an UPDATE whose path attributes
overrun still decodes, and :attr:`BGP.path_attributes` raises
:class:`~netprotocols.InvalidFieldError` when asked for them. That
keeps the message's framing — which the header alone decides —
independent of the parts of the body the decoder can only interpret
with session state it may not have (see *Out of scope* below).

The Marker alone is a strong guard against a wrong port guess: random
bytes pass it once in 2**128 tries. Over 10,000 random 300-byte TCP
payloads sent to port 179 and walked with
``decode_frame(..., lax=True)``, every walk ended with ``stopped_by``
set, as it did for 10,000 payloads of uniformly random length 0-600;
see ARCHITECTURE.md's *Port-based dispatch is best-effort*.

Messages and segments
---------------------
TCP delivers BGP as a byte stream. A segment may hold several messages
back to back, the tail of one message, the head of the next, or none
at all; reassembling the stream is the caller's job, as it is for
:class:`~netprotocols.HTTP` (SECURITY.md). Within one segment the
decoder does what it can without reassembly:

- A segment holding *N* complete messages decodes as *N* :class:`BGP`
  layers. :meth:`BGP.decode` notes whether the bytes after its message
  begin like another one, as a run of up to 16 ``0xff`` bytes, and
  :meth:`BGP.next_protocol` answers :class:`BGP` when they do and
  ``None`` when they do not. ``next_protocol`` is given no bytes, so
  this is the one place the answer can be worked out; it is recorded on
  the instance outside the comparison, so two equal messages compare
  equal wherever in a segment they were found.
- A segment whose last message is cut by the segment boundary decodes
  its complete messages and then raises
  :class:`~netprotocols.TruncatedHeaderError` at the cut one (its
  ``frame_offset`` is where that message starts in the frame). With
  ``lax=True`` the walk keeps the complete messages and reports the
  error on ``packet.stopped_by``.
- A segment that begins inside a message — the rest of one the previous
  segment cut — fails the Marker check with
  :class:`~netprotocols.InvalidFieldError`, or, when it holds fewer
  than the 19 bytes of a header, raises
  :class:`~netprotocols.TruncatedHeaderError` before the Marker is
  read. In lax mode either stops the walk after the TCP layer, as
  :class:`~netprotocols.HTTP` does under ``decode_as``
  (ARCHITECTURE.md).
- A segment with no payload at all (a bare ACK, the handshake, a FIN)
  raises :class:`~netprotocols.TruncatedHeaderError` at the empty
  buffer, as ``DNSOverTCP`` does on port 53: port dispatch happens
  before anyone looks at the payload.

The bytes after the last message are left undecoded unless they begin
with ``0xff`` bytes as above, so a trailer the walk hands the decoder —
Ethernet zero padding, which a BGP segment is too long to need, or a
4-byte FCS — ends the walk cleanly, with ``packet.consumed`` short of
the frame. An FCS of four ``0xff`` bytes would read as the start of a
cut message and raise; that is one value in 2**32.

Each message is one layer, so a segment of many small messages makes a
deep chain: Ethernet, IPv4 and TCP are three layers, and the walk's
default ``max_depth`` of :data:`~netprotocols.MAX_DEPTH` (32) leaves
room for 29 messages. Valid traffic carries more. A 1460-byte MSS
segment with TCP timestamps carries 1448 bytes: 76 KEEPALIVEs (19
bytes each) and the start of a 77th, or 30 of the 47-byte UPDATEs that
announce one /24 with only ORIGIN, a one-AS AS_PATH and NEXT_HOP. A
capture taken with GRO or TSO on, over loopback, or on a jumbo-frame
link holds segments larger than the MSS, up to the 65,495 bytes of TCP
payload an IPv4 packet can carry (3,447 KEEPALIVEs), so no fixed depth
covers every segment. Past the limit a strict walk raises
:class:`~netprotocols.MaxDepthExceededError` on valid traffic, and a
lax one stops with ``packet.stopped_by`` set to that error and
``packet.consumed`` short of the frame. The corpus, captured with
offload off, never reaches it: its busiest segment carries 7 messages.

There are two ways past the limit. One is a larger ``max_depth``: three
more than the segment's whole messages decodes them all in an untagged
Ethernet, IPv4 and TCP frame (add one for each VLAN tag or IPv6
extension header), and one more again reaches a cut message after
them, which then raises :class:`~netprotocols.TruncatedHeaderError`
instead; so ``max_depth=79`` decodes 76 whole KEEPALIVEs. The other,
which needs no bound on the segment, is to carry on where the walk
stopped. The error's ``protocol`` is :class:`BGP` when the next layer
is another message, and ``packet.consumed`` in lax mode, or the
error's ``frame_offset`` in strict mode, is where that message starts::

    packet = decode_frame(frame, lax=True)
    messages = [layer for layer in packet if isinstance(layer, BGP)]
    rest = frame[packet.consumed :]
    while (
        isinstance(packet.stopped_by, MaxDepthExceededError)
        and packet.stopped_by.protocol is BGP
    ):
        packet = decode_frame(rest, start=BGP, lax=True)
        messages.extend(packet)
        rest = rest[packet.consumed :]

Only the lax walk keeps what it decoded: a strict walk's
:class:`~netprotocols.MaxDepthExceededError` carries no layers, so
walking on from its ``frame_offset`` yields the messages after the
limit but not those before it. Use the lax loop above, or a larger
``max_depth``, when every message is wanted.

Out of scope
------------
AS_PATH (and the other attribute values but ORIGIN, NEXT_HOP,
MULTI_EXIT_DISC and LOCAL_PREF) is kept as raw ``bytes``. Its segments
carry 2-byte AS numbers or, between speakers that both advertised the
RFC 6793 capability in their OPENs, 4-byte ones, and the segment format
has no field saying which; BIRD and FRR negotiate 4-byte AS numbers by
default, so real captures, the corpus's included, carry 4-byte ones.
Three other negotiated features change the body in ways the decoder
cannot see either, and are natural follow-ups: capability values
(RFC 5492) stay raw inside the Capabilities optional parameter;
ADD-PATH (RFC 7911) prefixes each NLRI and withdrawn route with a
4-byte path identifier, which :attr:`BGP.nlri` would misread as
prefixes or reject; and the ROUTE-REFRESH body (RFC 2918, RFC 7313) is
kept raw. IPv6 and other address families travel inside the
MP_REACH_NLRI and MP_UNREACH_NLRI attributes (RFC 4760), whose values
stay raw; only the IPv4 unicast Withdrawn Routes and NLRI fields of
RFC 4271 are parsed.
"""

from __future__ import annotations

import builtins
from collections.abc import Iterator
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv4
from netprotocols.registry import Registry
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["BGP", "BGPOptionalParameter", "BGPPathAttribute", "BGPPrefix"]

#: The Marker every message must start with (RFC 4271 §4.1).
_MARKER = b"\xff" * 16

#: The common header's length, and the smallest message.
_HEADER_LEN = 19

#: The message types RFC 4271 §4 and RFC 2918 define.
_OPEN, _UPDATE, _NOTIFICATION, _KEEPALIVE, _ROUTE_REFRESH = 1, 2, 3, 4, 5

_TYPE_NAMES: dict[int, str] = {
    _OPEN: "OPEN",
    _UPDATE: "UPDATE",
    _NOTIFICATION: "NOTIFICATION",
    _KEEPALIVE: "KEEPALIVE",
    _ROUTE_REFRESH: "ROUTE-REFRESH",
}

#: Each type's smallest and largest Length (RFC 4271 §4.2-4.5 and §6.1,
#: RFC 2918 §3; RFC 8654 for the 65535 ceiling, which it does not extend
#: to OPEN or KEEPALIVE).
_LENGTH_BOUNDS: dict[int, tuple[int, int]] = {
    _OPEN: (29, 4096),
    _UPDATE: (23, 0xFFFF),
    _NOTIFICATION: (21, 0xFFFF),
    _KEEPALIVE: (19, 19),
    _ROUTE_REFRESH: (23, 0xFFFF),
}

#: The OPEN body's fixed part: Version, My Autonomous System, Hold
#: Time, BGP Identifier, Optional Parameters Length (RFC 4271 §4.2).
_OPEN_FIXED = Struct("!BHH4sB")

#: RFC 9072's marker for extended optional parameters: a Non-Ext OP
#: Type of 255 after the one-byte Optional Parameters Length.
_EXTENDED_OP_TYPE = 255

_OPTIONAL_PARAMETER_NAMES: dict[int, str] = {
    1: "Authentication (deprecated)",  # RFC 4271 §4.2, deprecated by 5492
    2: "Capabilities",  # RFC 5492
}

#: Path attribute flag bits (RFC 4271 §4.3).
_OPTIONAL, _TRANSITIVE, _PARTIAL, _EXTENDED_LENGTH = 0x80, 0x40, 0x20, 0x10

#: Path attribute type codes, named as the IANA "BGP Path Attributes"
#: registry assigns them
#: (https://www.iana.org/assignments/bgp-parameters, last updated
#: 2026-09-09, fetched 2026-10-25): every permanent registration,
#: deprecated ones included, under the registry's name, except that 16
#: is spelled EXTENDED_COMMUNITIES, like its neighbours, where the
#: registry has "EXTENDED COMMUNITIES". The temporary registrations
#: (34, whose term ran out on 2025-07-28, and 42) are left unnamed. Only
#: the values of 1, 3, 4 and 5 are decoded
#: (:attr:`BGPPathAttribute.value`); every other value is kept raw.
_ATTRIBUTE_NAMES: dict[int, str] = {
    0: "Reserved",
    1: "ORIGIN",
    2: "AS_PATH",
    3: "NEXT_HOP",
    4: "MULTI_EXIT_DISC",
    5: "LOCAL_PREF",
    6: "ATOMIC_AGGREGATE",
    7: "AGGREGATOR",
    8: "COMMUNITIES",
    9: "ORIGINATOR_ID",
    10: "CLUSTER_LIST",
    11: "DPA (deprecated)",
    12: "ADVERTISER (historic) (deprecated)",
    13: "RCID_PATH / CLUSTER_ID (Historic) (deprecated)",
    14: "MP_REACH_NLRI",
    15: "MP_UNREACH_NLRI",
    16: "EXTENDED_COMMUNITIES",
    17: "AS4_PATH",
    18: "AS4_AGGREGATOR",
    19: "SAFI Specific Attribute (SSA) (deprecated)",
    20: "Connector Attribute (deprecated)",
    21: "AS_PATHLIMIT (deprecated)",
    22: "PMSI_TUNNEL",
    23: "Tunnel Encapsulation",
    24: "Traffic Engineering",
    25: "IPv6 Address Specific Extended Community",
    26: "AIGP",
    27: "PE Distinguisher Labels",
    28: "BGP Entropy Label Capability Attribute (deprecated)",
    29: "BGP-LS Attribute",
    30: "Deprecated",
    31: "Deprecated",
    32: "LARGE_COMMUNITY",
    33: "BGPsec_Path",
    35: "Only to Customer (OTC)",
    36: "BGP Domain Path (D-PATH)",
    37: "SFP attribute",
    38: "BFD Discriminator",
    39: "Next Hop Dependent Characteristic (NHC)",
    40: "BGP Prefix-SID",
    41: "BIER",
    128: "ATTR_SET",
    129: "Deprecated",
    241: "Deprecated",
    242: "Deprecated",
    243: "Deprecated",
    255: "Reserved for development",
}

_ORIGIN, _NEXT_HOP, _MED, _LOCAL_PREF = 1, 3, 4, 5

#: ORIGIN values (RFC 4271 §4.3, §5.1.1).
_ORIGIN_NAMES: dict[int, str] = {0: "IGP", 1: "EGP", 2: "INCOMPLETE"}

#: NOTIFICATION error codes and their subcodes, named as the IANA "BGP
#: Error (Notification) Codes" and "BGP Error Subcodes" registries
#: assign them (https://www.iana.org/assignments/bgp-parameters, last
#: updated 2026-09-09, fetched 2026-10-25): RFC 4271 §4.5 for codes 1-6,
#: RFC 7313 for 7, RFC 9687 for 8 and RFC 9815 for 9.
_ERROR_CODE_NAMES: dict[int, str] = {
    0: "Reserved",
    1: "Message Header Error",
    2: "OPEN Message Error",
    3: "UPDATE Message Error",
    4: "Hold Timer Expired",
    5: "Finite State Machine Error",
    6: "Cease",
    7: "ROUTE-REFRESH Message Error",
    8: "Send Hold Timer Expired",
    9: "Loss of LSDB Synchronization",
}

#: Error subcodes by error code, for the codes with a subcode registry:
#: RFC 4271 §4.5 (and RFC Errata 4493's "Unspecific" 0) for codes 1-3,
#: with OPEN's 7 from RFC 5492 and 8-11 from RFC 9234; RFC 6608 for the
#: Finite State Machine Error; RFC 4486 for Cease, with 9 from RFC 8538
#: and 10 from RFC 9384; RFC 7313 for ROUTE-REFRESH. OPEN's 5 and
#: UPDATE's 7, which the registry lists only as "[Deprecated]", keep
#: the names RFC 4271 Appendix A gives them, with "(deprecated)". A
#: code without a registry (4, 8, 9) names only subcode 0,
#: "Unspecific" (RFC 4271 §4.5; RFC 9687 §6 sets it to 0 for code 8),
#: and so does an unknown code.
_ERROR_SUBCODE_NAMES: dict[int, dict[int, str]] = {
    1: {
        0: "Unspecific",
        1: "Connection Not Synchronized",
        2: "Bad Message Length",
        3: "Bad Message Type",
    },
    2: {
        0: "Unspecific",
        1: "Unsupported Version Number",
        2: "Bad Peer AS",
        3: "Bad BGP Identifier",
        4: "Unsupported Optional Parameter",
        5: "Authentication Failure (deprecated)",
        6: "Unacceptable Hold Time",
        7: "Unsupported Capability",
        8: "Deprecated",
        9: "Deprecated",
        10: "Deprecated",
        11: "Role Mismatch",
    },
    3: {
        0: "Unspecific",
        1: "Malformed Attribute List",
        2: "Unrecognized Well-known Attribute",
        3: "Missing Well-known Attribute",
        4: "Attribute Flags Error",
        5: "Attribute Length Error",
        6: "Invalid ORIGIN Attribute",
        7: "AS Routing Loop (deprecated)",
        8: "Invalid NEXT_HOP Attribute",
        9: "Optional Attribute Error",
        10: "Invalid Network Field",
        11: "Malformed AS_PATH",
    },
    5: {
        0: "Unspecified Error",
        1: "Receive Unexpected Message in OpenSent State",
        2: "Receive Unexpected Message in OpenConfirm State",
        3: "Receive Unexpected Message in Established State",
    },
    6: {
        0: "Reserved",
        1: "Maximum Number of Prefixes Reached",
        2: "Administrative Shutdown",
        3: "Peer De-configured",
        4: "Administrative Reset",
        5: "Connection Rejected",
        6: "Other Configuration Change",
        7: "Connection Collision Resolution",
        8: "Out of Resources",
        9: "Hard Reset",
        10: "BFD Down",
    },
    7: {
        0: "Reserved",
        1: "Invalid Message Length",
    },
}

#: Subcode 0 under an error code with no subcode registry (RFC 4271 §4.5).
_UNSPECIFIC: dict[int, str] = {0: "Unspecific"}

#: The Cease subcodes whose data may carry a shutdown communication
#: (RFC 9003 §2, which obsoletes RFC 8203).
_CEASE, _SHUTDOWN_SUBCODES = 6, frozenset({2, 4})


@dataclass(frozen=True, slots=True)
class BGPPrefix:
    """One IPv4 prefix of an UPDATE's Withdrawn Routes or NLRI (§4.3).

    :param length: The prefix length in bits, ``0``-``32``.
    :param prefix: The prefix bytes as sent: the ``ceil(length / 8)``
        leading bytes of the address. Bits past ``length`` in the last
        byte are irrelevant (§4.3) and are kept as sent.

    ``bytes(prefix)`` is the on-wire form, the length byte followed by
    :attr:`prefix`.
    """

    length: int
    prefix: bytes = b""

    def __post_init__(self) -> None:
        """Check the length is 0-32 and the prefix bytes match it.

        :raises InvalidFieldError: either does not hold.
        """
        if not 0 <= self.length <= 32:
            raise InvalidFieldError(
                f"BGP IPv4 prefix length must be within 0-32, "
                f"got {self.length}",
                protocol=type(self),
                field="length",
                expected="0-32",
                actual=self.length,
            )
        if len(self.prefix) != (self.length + 7) // 8:
            raise InvalidFieldError(
                f"a {self.length}-bit BGP prefix takes "
                f"{(self.length + 7) // 8} bytes, got {len(self.prefix)}",
                protocol=type(self),
                field="prefix",
                expected=(self.length + 7) // 8,
                actual=len(self.prefix),
            )

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form: length byte, then prefix."""
        return bytes([self.length]) + self.prefix

    @property
    def network(self) -> IPv4Network:
        """The prefix as an :class:`~ipaddress.IPv4Network`.

        Any bits past :attr:`length` are cleared.
        """
        address = bytes_to_ipv4(self.prefix.ljust(4, b"\x00"))
        return IPv4Network(f"{address}/{self.length}", strict=False)

    def __str__(self) -> str:
        """Render as CIDR, e.g. ``"192.0.2.0/24"``."""
        return str(self.network)


@dataclass(frozen=True, slots=True)
class BGPPathAttribute:
    """One path attribute of an UPDATE (RFC 4271 §4.3).

    :param flags: Attribute Flags: Optional (``0x80``), Transitive
        (``0x40``), Partial (``0x20``) and Extended Length (``0x10``);
        the low four bits are unused and carried verbatim.
    :param type_code: Attribute Type Code — ``1`` ORIGIN, ``2``
        AS_PATH, ``3`` NEXT_HOP, ``4`` MULTI_EXIT_DISC, ``5`` LOCAL_PREF,
        ... (see :attr:`type_name`).
    :param data: The attribute value, kept raw (see :attr:`value` for
        the types decoded further).

    ``bytes(attribute)`` is the on-wire form: the Attribute Length is
    two bytes when the Extended Length flag is set and one otherwise,
    so an attribute without the flag holds at most 255 bytes.
    """

    flags: int
    type_code: int
    data: bytes = b""

    def __post_init__(self) -> None:
        """Check each field fits and the value fits its length's width.

        :raises InvalidFieldError: a field does not fit.
        """
        for name in ("flags", "type_code"):
            value = getattr(self, name)
            if not 0 <= value <= 0xFF:
                raise InvalidFieldError(
                    f"BGP attribute {name} must be within 0-255, got {value}",
                    protocol=type(self),
                    field=name,
                    expected="0-255",
                    actual=value,
                )
        limit = 0xFFFF if self.extended_length else 0xFF
        if len(self.data) > limit:
            raise InvalidFieldError(
                f"BGP attribute value of {len(self.data)} bytes exceeds "
                f"the {limit} its "
                f"{2 if self.extended_length else 1}-byte length can say",
                protocol=type(self),
                field="data",
                expected=f"<={limit} bytes",
                actual=len(self.data),
            )

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire TLV, sized by the Extended Length flag."""
        width = 2 if self.extended_length else 1
        return (
            bytes([self.flags, self.type_code])
            + len(self.data).to_bytes(width, "big")
            + self.data
        )

    @property
    def optional(self) -> bool:
        """Whether the Optional flag (``0x80``) is set."""
        return bool(self.flags & _OPTIONAL)

    @property
    def transitive(self) -> bool:
        """Whether the Transitive flag (``0x40``) is set."""
        return bool(self.flags & _TRANSITIVE)

    @property
    def partial(self) -> bool:
        """Whether the Partial flag (``0x20``) is set."""
        return bool(self.flags & _PARTIAL)

    @property
    def extended_length(self) -> bool:
        """Whether the Extended Length flag (``0x10``) is set.

        When it is, the Attribute Length is two bytes rather than one.
        """
        return bool(self.flags & _EXTENDED_LENGTH)

    @property
    def type_name(self) -> str:
        """Display name of the type code, e.g. ``"AS_PATH"``."""
        return _ATTRIBUTE_NAMES.get(
            self.type_code, f"unknown ({self.type_code})"
        )

    @property
    def value(self) -> int | str | None:
        """The decoded value, for the four single-field attribute types.

        Those are the ORIGIN code (``0`` IGP, ``1`` EGP, ``2``
        INCOMPLETE), the NEXT_HOP address in dotted-decimal, and the
        MULTI_EXIT_DISC and LOCAL_PREF integers.

        ``None`` for every other type — AS_PATH among them, whose AS
        number width the bytes do not say (see the module docstring) —
        and for a value of the wrong length (1 byte for ORIGIN, 4 for
        the others), which RFC 4271 §6.3 calls an Attribute Length
        Error; :attr:`data` holds the bytes either way.
        """
        if self.type_code == _ORIGIN:
            return self.data[0] if len(self.data) == 1 else None
        if len(self.data) != 4:
            return None
        if self.type_code == _NEXT_HOP:
            return bytes_to_ipv4(self.data)
        if self.type_code in (_MED, _LOCAL_PREF):
            return int.from_bytes(self.data, "big")
        return None

    @property
    def value_text(self) -> str:
        """A human-readable rendering of the value.

        The ORIGIN name (``"IGP"``), the NEXT_HOP address, the MED or
        LOCAL_PREF integer, or the hexadecimal :attr:`data` for
        everything else.
        """
        value = self.value
        if value is None:
            return self.data.hex()
        if self.type_code == _ORIGIN:
            return _ORIGIN_NAMES.get(int(value), f"unknown ({value})")
        return str(value)


@dataclass(frozen=True, slots=True)
class BGPOptionalParameter:
    """One optional parameter of an OPEN (RFC 4271 §4.2).

    :param type: Parameter Type — ``2`` Capabilities (RFC 5492), ``1``
        the deprecated Authentication (see :attr:`type_name`).
    :param value: Parameter Value, kept raw. A Capabilities value is a
        list of capability TLVs (4-byte AS numbers, multiprotocol,
        route refresh, ...), not decoded further.
    :param extended_length: Whether the Parameter Length is two bytes
        rather than one. The enclosing OPEN chooses that for all its
        parameters (RFC 9072's encoding, signalled by a Non-Ext OP Type
        of 255; see :attr:`BGP.extended_optional_parameters`), and each
        parameter records it, as :attr:`BGP.optional_parameters` sets it.

    ``bytes(parameter)`` is the on-wire form, the Parameter Length one
    or two bytes by :attr:`extended_length`, so a parameter without it
    holds at most 255 bytes.
    """

    type: int
    value: bytes = b""
    extended_length: bool = False

    def __post_init__(self) -> None:
        """Check the type fits and the value fits its length's width.

        :raises InvalidFieldError: either does not.
        """
        if not 0 <= self.type <= 0xFF:
            raise InvalidFieldError(
                f"BGP optional parameter type must be within 0-255, "
                f"got {self.type}",
                protocol=type(self),
                field="type",
                expected="0-255",
                actual=self.type,
            )
        limit = 0xFFFF if self.extended_length else 0xFF
        if len(self.value) > limit:
            raise InvalidFieldError(
                f"BGP optional parameter value of {len(self.value)} bytes "
                f"exceeds the {limit} its "
                f"{2 if self.extended_length else 1}-byte length can say",
                protocol=type(self),
                field="value",
                expected=f"<={limit} bytes",
                actual=len(self.value),
            )

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire TLV, sized by :attr:`extended_length`."""
        width = 2 if self.extended_length else 1
        return (
            bytes([self.type])
            + len(self.value).to_bytes(width, "big")
            + self.value
        )

    @property
    def type_name(self) -> str:
        """Display name of the parameter type, e.g. ``"Capabilities"``."""
        return _OPTIONAL_PARAMETER_NAMES.get(
            self.type, f"unknown ({self.type})"
        )


def _malformed(message: str, offset: int) -> InvalidFieldError:
    """Build an error in a :class:`BGP` body, positioned within it."""
    return InvalidFieldError(message, protocol=BGP, field="body", offset=offset)


def _walk_prefixes(raw: bytes, base: int) -> Iterator[BGPPrefix]:
    """Yield the IPv4 prefixes of a Withdrawn Routes or NLRI field.

    :param raw: The field's bytes.
    :param base: Where ``raw`` starts in the message body, for the
        offset of a raised error.
    :raises InvalidFieldError: on a prefix length over 32 bits, or a
        prefix that runs past ``raw``.
    """
    cursor = 0
    while cursor < len(raw):
        length = raw[cursor]
        if length > 32:
            raise _malformed(
                f"BGP IPv4 prefix length {length} exceeds 32 bits",
                base + cursor,
            )
        end = cursor + 1 + (length + 7) // 8
        if end > len(raw):
            raise _malformed("BGP prefix runs past its field", base + cursor)
        yield BGPPrefix(length=length, prefix=raw[cursor + 1 : end])
        cursor = end


def _walk_attributes(raw: bytes, base: int) -> Iterator[BGPPathAttribute]:
    """Yield the path attributes of an UPDATE's Path Attributes field.

    :param raw: The field's bytes.
    :param base: Where ``raw`` starts in the message body.
    :raises InvalidFieldError: on an attribute header or value that
        runs past ``raw``.
    """
    cursor = 0
    while cursor < len(raw):
        flags = raw[cursor]
        width = 2 if flags & _EXTENDED_LENGTH else 1
        start = cursor + 2 + width
        if start > len(raw):
            raise _malformed(
                "BGP path attribute header runs past the attributes",
                base + cursor,
            )
        length = int.from_bytes(raw[cursor + 2 : start], "big")
        if start + length > len(raw):
            raise _malformed(
                "BGP path attribute value runs past the attributes",
                base + cursor,
            )
        yield BGPPathAttribute(
            flags=flags,
            type_code=raw[cursor + 1],
            data=raw[start : start + length],
        )
        cursor = start + length


def _walk_parameters(
    raw: bytes, base: int, width: int
) -> Iterator[BGPOptionalParameter]:
    """Yield the optional parameters of an OPEN.

    :param raw: The Optional Parameters bytes.
    :param base: Where ``raw`` starts in the message body.
    :param width: Bytes in each Parameter Length: 1, or 2 under RFC
        9072's extended encoding.
    :raises InvalidFieldError: on a parameter that runs past ``raw``.
    """
    cursor = 0
    while cursor < len(raw):
        start = cursor + 1 + width
        if start > len(raw):
            raise _malformed(
                "BGP optional parameter header runs past the parameters",
                base + cursor,
            )
        length = int.from_bytes(raw[cursor + 1 : start], "big")
        if start + length > len(raw):
            raise _malformed(
                "BGP optional parameter runs past the parameters",
                base + cursor,
            )
        yield BGPOptionalParameter(
            type=raw[cursor],
            value=raw[start : start + length],
            extended_length=width == 2,
        )
        cursor = start + length


@dataclass(frozen=True, slots=True)
class BGP(Protocol):
    """One BGP-4 message (RFC 4271 §4).

    Construction checks that each header field fits and that
    :attr:`length` agrees with :attr:`body`; it does not check the
    Marker or the Type, so a test of another speaker can build a
    message :meth:`decode` would reject.

    :param marker: The 16-byte Marker, all ones (:attr:`MARKER`) in
        every message RFC 4271 allows.
    :param length: The whole message's length in bytes, header
        included: ``19 + len(body)``.
    :param type: Message type — :attr:`OPEN` (1), :attr:`UPDATE` (2),
        :attr:`NOTIFICATION` (3), :attr:`KEEPALIVE` (4) or
        :attr:`ROUTE_REFRESH` (5) (see :attr:`type_name`).
    :param body: Everything after the common header, kept raw and
        parsed on demand by the type's accessors.
    """

    marker: bytes
    length: int
    type: int
    body: bytes = b""
    #: Whether the bytes after this message, in the buffer it was
    #: decoded from, begin like another message; decode context, not a
    #: wire field, so it is neither compared nor hashed (see the module
    #: docstring's *Messages and segments*).
    _followed: bool = field(
        default=False, init=False, repr=False, compare=False
    )

    MARKER: ClassVar[bytes] = _MARKER
    OPEN: ClassVar[int] = _OPEN
    UPDATE: ClassVar[int] = _UPDATE
    NOTIFICATION: ClassVar[int] = _NOTIFICATION
    KEEPALIVE: ClassVar[int] = _KEEPALIVE
    ROUTE_REFRESH: ClassVar[int] = _ROUTE_REFRESH

    _struct: ClassVar[Struct] = Struct("!16sHB")

    def __post_init__(self) -> None:
        """Check each header field fits and the Length matches the body.

        :raises InvalidFieldError: a field does not.
        """
        if len(self.marker) != 16:
            raise InvalidFieldError(
                f"BGP marker must be 16 bytes, got {len(self.marker)}",
                protocol=type(self),
                field="marker",
                expected=16,
                actual=len(self.marker),
            )
        if not 0 <= self.type <= 0xFF:
            raise InvalidFieldError(
                f"BGP type must be within 0-255, got {self.type}",
                protocol=type(self),
                field="type",
                expected="0-255",
                actual=self.type,
            )
        if self.length != _HEADER_LEN + len(self.body) or self.length > 0xFFFF:
            raise InvalidFieldError(
                f"BGP length {self.length} disagrees with a "
                f"{len(self.body)}-byte body",
                protocol=type(self),
                field="length",
                expected=_HEADER_LEN + len(self.body),
                actual=self.length,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the message at the start of ``data``.

        :raises TruncatedHeaderError: ``data`` is shorter than the
            19-byte header, or than the message's Length.
        :raises InvalidFieldError: the Marker is not all ones
            (``field`` ``"marker"``), the Type is not 1-5 (``"type"``),
            or the Length is outside that type's bounds (``"length"``);
            see the module docstring.
        """
        marker, length, type_ = cls._unpack_fixed(data)
        _check_header(marker, length, type_)
        if length > len(data):
            raise TruncatedHeaderError(
                f"BGP message of {length} bytes, buffer holds {len(data)}",
                protocol=cls,
                field="length",
                offset=0,
                expected=length,
                actual=len(data),
            )
        message = cls(
            marker=_MARKER,
            length=length,
            type=type_,
            body=bytes(data[_HEADER_LEN:length]),
        )
        rest = bytes(data[length : length + 16])
        if rest and rest == _MARKER[: len(rest)]:
            object.__setattr__(message, "_followed", True)
        return message

    def __bytes__(self) -> bytes:
        """Serialize the header and the raw body."""
        return (
            self._struct.pack(self.marker, self.length, self.type) + self.body
        )

    @property
    def header_len(self) -> int:
        """The whole message: the 19-byte header and the body."""
        return _HEADER_LEN + len(self.body)

    def next_protocol(
        self, registry: Registry | None = None
    ) -> builtins.type[Protocol] | None:
        """Name the next message in the same segment, if one begins there.

        :class:`BGP` when the bytes after this message began with a
        Marker, or as much of one as the buffer held, when it was
        decoded; ``None`` otherwise, and for a message built rather than
        decoded. The answer is always this class, never a table lookup,
        so ``registry`` has nothing to select.
        """
        return BGP if self._followed else None

    @property
    def type_name(self) -> str:
        """Display name of the message type, e.g. ``"UPDATE"``."""
        return _TYPE_NAMES.get(self.type, f"unknown ({self.type})")

    # OPEN (RFC 4271 §4.2)

    def _open_fixed(self) -> tuple[int, int, int, bytes, int] | None:
        """Unpack an OPEN's fixed fields; ``None`` for other messages."""
        if self.type != _OPEN or len(self.body) < _OPEN_FIXED.size:
            return None
        fields: tuple[int, int, int, bytes, int] = _OPEN_FIXED.unpack_from(
            self.body
        )
        return fields

    @property
    def version(self) -> int | None:
        """An OPEN's protocol version (``4``); ``None`` otherwise."""
        fixed = self._open_fixed()
        return None if fixed is None else fixed[0]

    @property
    def my_as(self) -> int | None:
        """An OPEN's 2-byte My Autonomous System; ``None`` otherwise.

        A speaker with a 4-byte AS number sends AS_TRANS (``23456``) here
        and its real number in a capability (RFC 6793 §3), which this
        library leaves raw.
        """
        fixed = self._open_fixed()
        return None if fixed is None else fixed[1]

    @property
    def hold_time(self) -> int | None:
        """An OPEN's proposed Hold Time in seconds; ``None`` otherwise."""
        fixed = self._open_fixed()
        return None if fixed is None else fixed[2]

    @property
    def bgp_identifier(self) -> str | None:
        """An OPEN's BGP Identifier, dotted-decimal; ``None`` otherwise."""
        fixed = self._open_fixed()
        return None if fixed is None else bytes_to_ipv4(fixed[3])

    @property
    def extended_optional_parameters(self) -> bool | None:
        """Whether an OPEN uses RFC 9072's extended parameter encoding.

        The encoding is signalled by a Non-Ext OP Type of 255 and gives
        each parameter a 2-byte length. ``None`` for other messages.
        """
        fixed = self._open_fixed()
        if fixed is None:
            return None
        return (
            fixed[4] != 0
            and len(self.body) > _OPEN_FIXED.size
            and self.body[_OPEN_FIXED.size] == _EXTENDED_OP_TYPE
        )

    @property
    def optional_parameters(self) -> tuple[BGPOptionalParameter, ...] | None:
        """An OPEN's optional parameters, in wire order.

        Parsed on demand from either encoding; ``None`` for other
        messages.

        :raises InvalidFieldError: the Optional Parameters Length (or
            RFC 9072's Extended Optional Parameters Length) disagrees
            with the message's length, RFC 9072's marker leaves no room
            for its 2-byte length (``offset`` at the marker), or a
            parameter runs past the parameters.
        """
        fixed = self._open_fixed()
        if fixed is None:
            return None
        start, declared, width = _OPEN_FIXED.size, fixed[4], 1
        if self.extended_optional_parameters:
            if len(self.body) < start + 3:
                raise _malformed(
                    "BGP extended optional parameters length is missing",
                    start,
                )
            declared = int.from_bytes(self.body[start + 1 : start + 3], "big")
            start, width = start + 3, 2
        if start + declared != len(self.body):
            raise _malformed(
                f"BGP optional parameters length {declared} disagrees with "
                f"the {len(self.body) - start} bytes the OPEN holds",
                start,
            )
        return tuple(_walk_parameters(self.body[start:], start, width))

    # UPDATE (RFC 4271 §4.3)

    def _update_fields(self) -> tuple[int, int, int] | None:
        """Locate an UPDATE's fields: ``(withdrawn_len, attrs_at, nlri_at)``.

        The Withdrawn Routes Length, and where the Path Attributes and
        the NLRI start in the body; ``None`` for other messages.

        :raises InvalidFieldError: a length runs past the message.
        """
        body = self.body
        if self.type != _UPDATE:
            return None
        if len(body) < 2:
            raise _malformed("BGP UPDATE ends before its lengths", 0)
        withdrawn_len = int.from_bytes(body[:2], "big")
        attrs_at = 2 + withdrawn_len + 2
        if attrs_at > len(body):
            raise _malformed(
                f"BGP Withdrawn Routes Length {withdrawn_len} runs past "
                f"the message",
                0,
            )
        attrs_len = int.from_bytes(body[attrs_at - 2 : attrs_at], "big")
        if attrs_at + attrs_len > len(body):
            raise _malformed(
                f"BGP Total Path Attribute Length {attrs_len} runs past "
                f"the message",
                attrs_at - 2,
            )
        return withdrawn_len, attrs_at, attrs_at + attrs_len

    @property
    def withdrawn_routes(self) -> tuple[BGPPrefix, ...] | None:
        """An UPDATE's Withdrawn Routes, in wire order.

        ``None`` for other messages.

        :raises InvalidFieldError: a length runs past the message, a
            prefix length exceeds 32, or a prefix runs past the field.
        """
        fields = self._update_fields()
        if fields is None:
            return None
        withdrawn_len = fields[0]
        return tuple(_walk_prefixes(self.body[2 : 2 + withdrawn_len], 2))

    @property
    def path_attributes(self) -> tuple[BGPPathAttribute, ...] | None:
        """An UPDATE's path attributes, in wire order.

        ``None`` for other messages.

        :raises InvalidFieldError: a length runs past the message, or an
            attribute runs past the Path Attributes field.
        """
        fields = self._update_fields()
        if fields is None:
            return None
        _, attrs_at, nlri_at = fields
        return tuple(_walk_attributes(self.body[attrs_at:nlri_at], attrs_at))

    @property
    def nlri(self) -> tuple[BGPPrefix, ...] | None:
        """An UPDATE's Network Layer Reachability Information.

        The IPv4 prefixes it announces, which run to the end of the
        message; ``None`` for other messages.

        :raises InvalidFieldError: a length runs past the message, a
            prefix length exceeds 32, or a prefix runs past the message.
        """
        fields = self._update_fields()
        if fields is None:
            return None
        nlri_at = fields[2]
        return tuple(_walk_prefixes(self.body[nlri_at:], nlri_at))

    # NOTIFICATION (RFC 4271 §4.5)

    @property
    def error_code(self) -> int | None:
        """A NOTIFICATION's Error Code; ``None`` for other messages."""
        if self.type != _NOTIFICATION or len(self.body) < 2:
            return None
        return self.body[0]

    @property
    def error_subcode(self) -> int | None:
        """A NOTIFICATION's Error Subcode; ``None`` for other messages."""
        if self.type != _NOTIFICATION or len(self.body) < 2:
            return None
        return self.body[1]

    @property
    def error_data(self) -> bytes | None:
        """A NOTIFICATION's Data, raw, maybe empty; ``None`` otherwise."""
        if self.type != _NOTIFICATION or len(self.body) < 2:
            return None
        return self.body[2:]

    @property
    def error_code_name(self) -> str | None:
        """Display name of a NOTIFICATION's Error Code, e.g. ``"Cease"``.

        ``None`` for other messages.
        """
        code = self.error_code
        if code is None:
            return None
        return _ERROR_CODE_NAMES.get(code, f"unknown ({code})")

    @property
    def error_subcode_name(self) -> str | None:
        """Display name of a NOTIFICATION's Error Subcode.

        Named in the context of its Error Code, e.g. ``"Administrative
        Shutdown"`` for Cease, as the IANA registry names it; subcode 0
        is ``"Unspecific"`` under a code with no subcode registry.
        ``None`` for other messages.
        """
        code, subcode = self.error_code, self.error_subcode
        if code is None or subcode is None:
            return None
        names = _ERROR_SUBCODE_NAMES.get(code, _UNSPECIFIC)
        return names.get(subcode, f"unknown ({subcode})")

    @property
    def shutdown_communication(self) -> str | None:
        """The operator's message in a Cease NOTIFICATION's data.

        Carried by an Administrative Shutdown or Reset (RFC 9003 §2,
        which obsoletes RFC 8203) as a length byte, then that many bytes
        of UTF-8. ``None`` when the message is not one of those, carries
        no communication (no data, or a length of 0, which RFC 9003 §2
        says means none follows), its length byte overruns the data, or
        the bytes are not valid UTF-8, which a receiver must not
        interpret (§2); :attr:`error_data` keeps the raw bytes.
        """
        data = self.error_data
        if (
            data is None
            or self.error_code != _CEASE
            or self.error_subcode not in _SHUTDOWN_SUBCODES
            or not data
            or not data[0]
            or 1 + data[0] > len(data)
        ):
            return None
        try:
            return data[1 : 1 + data[0]].decode("utf-8")
        except UnicodeDecodeError:
            return None


def _check_header(marker: bytes, length: int, type_: int) -> None:
    """Apply RFC 4271 §6.1's header checks to a decoded header.

    :raises InvalidFieldError: see :meth:`BGP.decode`.
    """
    if marker != _MARKER:
        raise InvalidFieldError(
            "BGP marker is not all ones (RFC 4271 §4.1)",
            protocol=BGP,
            field="marker",
            offset=0,
            expected=_MARKER.hex(),
            actual=marker.hex(),
        )
    if length < _HEADER_LEN:
        raise InvalidFieldError(
            f"BGP length {length} is shorter than the 19-byte header",
            protocol=BGP,
            field="length",
            offset=16,
            expected=">=19",
            actual=length,
        )
    bounds = _LENGTH_BOUNDS.get(type_)
    if bounds is None:
        raise InvalidFieldError(
            f"BGP message type {type_} is not one of 1-5",
            protocol=BGP,
            field="type",
            offset=18,
            expected="1-5",
            actual=type_,
        )
    low, high = bounds
    if not low <= length <= high:
        raise InvalidFieldError(
            f"BGP {_TYPE_NAMES[type_]} length {length} is outside {low}-{high}",
            protocol=BGP,
            field="length",
            offset=16,
            expected=f"{low}-{high}",
            actual=length,
        )
