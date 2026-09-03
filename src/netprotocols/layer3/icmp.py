"""ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) headers.

Both classes model the 8-byte header common to all control messages —
type, code, checksum, and the message-specific final 4 bytes (the
"rest of header" in ICMPv4, the start of the message body in ICMPv6) —
plus the message data that follows, kept raw as ``body`` (like
``IGMP``/``DNS``), so a message consumes its whole IP payload and is
self-contained. The layer stays terminal; the accessors read ``rest``
and ``body`` on demand and never re-encode, so ``bytes(X.decode(x)) ==
x`` holds by construction: an echo's ``identifier`` /
``sequence_number`` split from ``rest``, an error message's
``embedded_packet`` exposes the invoking datagram it carries in
``body``, decodable as :class:`~netprotocols.IPv4` /
:class:`~netprotocols.IPv6`, and an ICMPv6 Neighbor Discovery
message's ``ndp_target_address`` / ``ndp_options`` parse the RFC 4861
target and option TLVs (a source/target link-layer address reads back
as a MAC string).
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv6, bytes_to_mac
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["ICMPv4", "ICMPv6", "NDPOption"]

#: Neighbor Discovery option types this library names (RFC 4861 §4.6);
#: unknown types fall back to their numeric value.
_NDP_OPTION_TYPE_NAMES: dict[int, str] = {
    1: "Source Link-Layer Address",
    2: "Target Link-Layer Address",
    3: "Prefix Information",
    4: "Redirected Header",
    5: "MTU",
}

#: Option types that carry a link-layer address (RFC 4861 §4.6.1).
_NDP_LLA_TYPES = frozenset({1, 2})


@dataclass(frozen=True, slots=True)
class NDPOption:
    """One Neighbor Discovery option TLV (RFC 4861 §4.6).

    :param type: Option type — ``1`` Source Link-Layer Address, ``2``
        Target Link-Layer Address, ``3`` Prefix Information, ``4``
        Redirected Header, ``5`` MTU (see :attr:`type_name`).
    :param data: The option's payload after the two type/length bytes,
        kept raw (the wire length counts in 8-octet units, so this is
        ``length * 8 - 2`` bytes).
    """

    type: int
    data: bytes = b""

    @property
    def type_name(self) -> str:
        """Display name of the option type, e.g. ``"Source Link-Layer
        Address"``; falls back to ``"unknown (n)"`` for types this
        library does not name."""
        return _NDP_OPTION_TYPE_NAMES.get(self.type, f"unknown ({self.type})")

    @property
    def link_layer_address(self) -> str | None:
        """The MAC of a Source/Target Link-Layer Address option (types
        1/2) over Ethernet, e.g. ``"84:01:12:be:7e:d9"``; ``None`` for
        other option types and for a payload that is not the 6-byte
        Ethernet form (degrades, never raises)."""
        if self.type in _NDP_LLA_TYPES and len(self.data) == 6:
            return bytes_to_mac(self.data)
        return None


@dataclass(frozen=True, slots=True)
class _ICMP(Protocol):
    """Shared shape of the two ICMP variants.

    :param type: Control message type.
    :param code: Control message subtype.
    :param checksum: Checksum over the whole ICMP message, carried
        verbatim (compute/verify via :mod:`netprotocols.checksum`).
    :param rest: The message-specific final 4 bytes of the header.
    :param body: The message data after the 8-byte header (an echo's
        payload, an error's embedded packet), kept raw.
    """

    type: int
    code: int
    checksum: int
    rest: bytes
    body: bytes = b""

    _struct: ClassVar[Struct] = Struct("!BBH4s")
    type_names: ClassVar[dict[int, str]] = {}

    #: Message types whose ``rest`` packs an echo identifier and
    #: sequence number.
    _echo_types: ClassVar[frozenset[int]] = frozenset()

    #: Error message types whose ``body`` embeds the invoking packet.
    _error_types: ClassVar[frozenset[int]] = frozenset()

    def __post_init__(self) -> None:
        if len(self.rest) != 4:
            raise InvalidFieldError(
                f"{self.__class__.__name__} rest-of-header must be exactly "
                f"4 bytes, got {len(self.rest)}",
                protocol=type(self),
                field="rest",
                expected=4,
                actual=len(self.rest),
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        type_, code, checksum, rest = cls._unpack_fixed(data)
        return cls(
            type=type_,
            code=code,
            checksum=checksum,
            rest=rest,
            body=bytes(data[cls._struct.size :]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(self.type, self.code, self.checksum, self.rest)
            + self.body
        )

    @property
    def header_len(self) -> int:
        # An ICMP message is the whole IP payload: consume it all so the
        # chain ends here with no stray payload (terminal).
        return self._struct.size + len(self.body)

    @property
    def type_name(self) -> str:
        """Display name of the message type, e.g. ``"Echo Request"``."""
        return self.type_names.get(
            self.type, "Unknown, Unassigned or Deprecated"
        )

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x83f7"``."""
        return f"{self.checksum:#06x}"

    # -- message-specific fields (read on demand, never re-encoded) --

    @property
    def identifier(self) -> int | None:
        """The identifier of an echo request/reply (``rest`` bytes 0-1),
        used to match replies to requests; ``None`` for other message
        types."""
        if self.type not in self._echo_types:
            return None
        return int.from_bytes(self.rest[:2], "big")

    @property
    def sequence_number(self) -> int | None:
        """The sequence number of an echo request/reply (``rest`` bytes
        2-3); ``None`` for other message types."""
        if self.type not in self._echo_types:
            return None
        return int.from_bytes(self.rest[2:], "big")

    @property
    def embedded_packet(self) -> bytes | None:
        """The invoking packet an error message embeds — its ``body``,
        starting at the original datagram's IP header, decodable as
        :class:`~netprotocols.IPv4` / :class:`~netprotocols.IPv6`.
        ``None`` for non-error message types and for an error whose body
        is empty (degrades, never raises)."""
        if self.type not in self._error_types or not self.body:
            return None
        return self.body


@dataclass(frozen=True, slots=True)
class ICMPv4(_ICMP):
    """An ICMPv4 message (RFC 792)."""

    #: Echo Reply (0) and Echo Request (8).
    _echo_types: ClassVar[frozenset[int]] = frozenset({0, 8})

    #: Destination Unreachable (3), Redirect (5), Time Exceeded (11),
    #: and Parameter Problem (12) embed the invoking packet (RFC 792).
    _error_types: ClassVar[frozenset[int]] = frozenset({3, 5, 11, 12})

    type_names: ClassVar[dict[int, str]] = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        4: "Source Quench",
        5: "Redirect Message",
        8: "Echo Request",
        9: "Router Advertisement",
        10: "Router Solicitation",
        11: "Time Exceeded",
        12: "Parameter Problem: Bad IP Header",
        13: "Timestamp",
        14: "Timestamp Reply",
        15: "Information Request",
        16: "Information Reply",
        17: "Address Mask Request",
        18: "Address Mask Reply",
        30: "Traceroute",
        42: "Extended Echo Request",
        43: "Extended Echo Reply",
    }


@dataclass(frozen=True, slots=True)
class ICMPv6(_ICMP):
    """An ICMPv6 message (RFC 4443)."""

    #: Echo Request (128) and Echo Reply (129).
    _echo_types: ClassVar[frozenset[int]] = frozenset({128, 129})

    #: The error messages, types 1-4 (RFC 4443 §3): Destination
    #: Unreachable, Packet Too Big, Time Exceeded, Parameter Problem —
    #: all embed as much of the invoking packet as fits.
    _error_types: ClassVar[frozenset[int]] = frozenset({1, 2, 3, 4})

    type_names: ClassVar[dict[int, str]] = {
        1: "Destination Unreachable",
        2: "Packet Too Big",
        3: "Time Exceeded",
        4: "Parameter Problem",
        100: "Private Experimentation",
        101: "Private Experimentation",
        127: "Reserved for Expansion of ICMPv6 Error Messages",
        128: "Echo Request",
        129: "Echo Reply",
        130: "Multicast Listener Query",
        131: "Multicast Listener Report",
        132: "Multicast Listener Done",
        133: "Router Solicitation",
        134: "Router Advertisement",
        135: "Neighbor Solicitation",
        136: "Neighbor Advertisement",
        137: "Redirect Message",
        138: "Router Renumbering",
        139: "ICMP Node Information Query",
        140: "ICMP Node Information Response",
        141: "Inverse Neighbor Discovery Solicitation Message",
        142: "Inverse Neighbor Discovery Advertisement Message",
        143: "Multicast Listener Discovery reports",
        144: "Home Agent Address Discovery Request Message",
        145: "Home Agent Address Discovery Reply Message",
        146: "Mobile Prefix Solicitation",
        147: "Mobile Prefix Advertisement",
        148: "Certification Path Solicitation",
        149: "Certification Path Advertisement",
        151: "Multicast Router Advertisement",
        152: "Multicast Router Solicitation",
        153: "Multicast Router Termination",
        155: "RPL Control Message",
        200: "Private Experimentation",
        201: "Private Experimentation",
        255: "Reserved for Expansion of ICMPv6 Informational Messages",
    }

    #: Neighbor Discovery message types (RFC 4861 §4.1-4.5) mapped to
    #: the offset into ``body`` where the option list starts — past the
    #: fixed fields each message puts there: none for a Router
    #: Solicitation, the reachable-time/retrans timers for a Router
    #: Advertisement, the target address for a Neighbor
    #: Solicitation/Advertisement, target + destination for a Redirect.
    _NDP_OPTIONS_OFFSET: ClassVar[dict[int, int]] = {
        133: 0,
        134: 8,
        135: 16,
        136: 16,
        137: 32,
    }

    # -- Neighbor Discovery (read on demand, never re-encoded) --

    @property
    def ndp_target_address(self) -> str | None:
        """The target address of a Neighbor Solicitation/Advertisement
        (types 135/136) — the 16 bytes after the reserved word, e.g.
        ``"fe80::f6d7:8b9a:993e:5efa"``; ``None`` for other message
        types and for a body too short to hold it (degrades, never
        raises)."""
        if self.type not in (135, 136) or len(self.body) < 16:
            return None
        return bytes_to_ipv6(self.body[:16])

    @property
    def ndp_options(self) -> tuple[NDPOption, ...] | None:
        """The option TLVs of a Neighbor Discovery message (Router
        Solicitation/Advertisement, Neighbor Solicitation/Advertisement,
        Redirect), parsed on demand — one :class:`NDPOption` per option,
        in wire order; ``None`` for non-NDP message types and empty for
        an NDP message carrying no options.

        :raises InvalidFieldError: if the body ends before the message's
            fixed fields, an option's length is zero (lengths count in
            8-octet units and zero must not loop), or an option runs
            past the message (bounded — never hangs or over-reads).
        """
        offset = self._NDP_OPTIONS_OFFSET.get(self.type)
        if offset is None:
            return None
        body = self.body
        if len(body) < offset:
            raise InvalidFieldError(
                f"{self.type_name} body ends before its fixed fields",
                protocol=type(self),
                field="body",
                offset=len(body),
                expected=offset,
                actual=len(body),
            )
        options: list[NDPOption] = []
        cursor = offset
        while cursor < len(body):
            if cursor + 2 > len(body):
                raise InvalidFieldError(
                    "NDP option missing its length byte",
                    protocol=type(self),
                    field="body",
                    offset=cursor,
                )
            length = body[cursor + 1] * 8
            if length == 0:
                raise InvalidFieldError(
                    "NDP option length must not be zero",
                    protocol=type(self),
                    field="body",
                    offset=cursor,
                )
            if cursor + length > len(body):
                raise InvalidFieldError(
                    "NDP option runs past the message",
                    protocol=type(self),
                    field="body",
                    offset=cursor,
                )
            options.append(
                NDPOption(
                    type=body[cursor], data=body[cursor + 2 : cursor + length]
                )
            )
            cursor += length
        return tuple(options)
