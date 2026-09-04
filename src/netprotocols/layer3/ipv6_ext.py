"""IPv6 extension headers (RFC 8200 §4.3-4.6).

Extension headers sit between the IPv6 fixed header and the upper-layer
protocol, each naming what follows via ``next_header`` — so they chain
exactly like every other protocol in this library. They are valid only
inside an IPv6 chain: the shared protocol-number registry dispatches to
these classes exclusively when asked by IPv6 or by another extension
header (see ``_ip_protocol_class``).

The TLV-shaped headers (Hop-by-Hop Options, Routing, Destination
Options) declare their own length in ``hdr_ext_len``, counted in
8-octet units *excluding* the first 8; the Fragment header is a fixed
8 bytes. Option/data contents are kept as raw ``bytes``; on the two
options headers the ``parsed_options`` accessor walks the option TLVs
(RFC 8200 §4.2) on demand and never re-encodes, so the byte-exact
round-trip holds by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols._enums import IPProtocol
from netprotocols.layer3.ip import _ip_protocol_class, _ip_protocol_name
from netprotocols.registry import Registry
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = [
    "IPv6DestinationOptions",
    "IPv6Fragment",
    "IPv6HopByHopOptions",
    "IPv6Option",
    "IPv6Routing",
]

#: The one option type that is a lone byte with no length or data
#: (RFC 8200 §4.2): Pad1, one byte of padding.
_OPT_PAD1 = 0

#: Option types this library names (RFC 8200 §4.2; RFC 2711 for Router
#: Alert; RFC 2675 for Jumbo Payload); unknown types fall back to their
#: numeric value.
_OPTION_TYPE_NAMES: dict[int, str] = {
    _OPT_PAD1: "Pad1",
    1: "PadN",
    5: "Router Alert",
    194: "Jumbo Payload",
}


@dataclass(frozen=True, slots=True)
class IPv6Option:
    """One option TLV from a Hop-by-Hop / Destination Options extension
    header (RFC 8200 §4.2).

    :param type: Option type — ``0`` Pad1, ``1`` PadN, ``5`` Router
        Alert, ``194`` Jumbo Payload (see :attr:`type_name`). The two
        high bits encode the action on an unrecognized option
        (:attr:`unrecognized_action`).
    :param data: The option data after the two type/length bytes, kept
        raw; always empty for Pad1, which is a lone type byte.
    """

    type: int
    data: bytes = b""

    @property
    def type_name(self) -> str:
        """Display name of the option type, e.g. ``"Router Alert"``;
        falls back to ``"unknown (n)"`` for types this library does not
        name."""
        return _OPTION_TYPE_NAMES.get(self.type, f"unknown ({self.type})")

    @property
    def unrecognized_action(self) -> int:
        """What a node must do with an option it does not recognize —
        the two high bits of the type (RFC 8200 §4.2): ``0`` skip it,
        ``1`` discard the packet, ``2`` discard and send an ICMP
        Parameter Problem, ``3`` discard and send the Parameter Problem
        only to a non-multicast destination."""
        return self.type >> 6


def _next_in_ipv6_chain(
    number: int, registry: Registry | None = None
) -> type[Protocol] | None:
    return _ip_protocol_class(number, ipv6=True, registry=registry)


def _next_header_name(number: int) -> str:
    return _ip_protocol_name(number)


@dataclass(frozen=True, slots=True)
class _IPv6OptionsHeader(Protocol):
    """Shared shape of the TLV-style extension headers.

    :param next_header: Protocol number of what follows this header
        (see :class:`~netprotocols.IPProtocol`).
    :param hdr_ext_len: Header length in 8-octet units, excluding the
        first 8 octets; must equal ``(len(options) - 6) // 8``.
    :param options: The header's remaining bytes (TLV-encoded options),
        exactly ``6 + hdr_ext_len * 8`` bytes.
    """

    next_header: int
    hdr_ext_len: int
    options: bytes

    _struct: ClassVar[Struct] = Struct("!BB")

    def __post_init__(self) -> None:
        expected = 6 + self.hdr_ext_len * 8
        if len(self.options) != expected:
            raise InvalidFieldError(
                f"{self.__class__.__name__} hdr_ext_len {self.hdr_ext_len} "
                f"disagrees with options length {len(self.options)} "
                f"(expected {expected} bytes)",
                protocol=type(self),
                field="hdr_ext_len",
                expected=expected,
                actual=len(self.options),
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        next_header, hdr_ext_len = cls._unpack_fixed(data)
        declared = (hdr_ext_len + 1) * 8
        if declared > len(data):
            raise TruncatedHeaderError(
                f"{cls.__name__} declares {declared} bytes, buffer holds "
                f"{len(data)}",
                protocol=cls,
                offset=0,
                field="hdr_ext_len",
                expected=declared,
                actual=len(data),
            )
        return cls(
            next_header=next_header,
            hdr_ext_len=hdr_ext_len,
            options=bytes(data[cls._struct.size : declared]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(self.next_header, self.hdr_ext_len) + self.options
        )

    @property
    def header_len(self) -> int:
        return (self.hdr_ext_len + 1) * 8

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        return _next_in_ipv6_chain(self.next_header, registry)

    @property
    def next_header_name(self) -> str:
        """Display name of what follows, e.g. ``"IPv6-ICMP"``."""
        return _next_header_name(self.next_header)

    @property
    def next_header_enum(self) -> IPProtocol | None:
        """What follows this header as an
        :class:`~netprotocols.IPProtocol` (see
        :attr:`~netprotocols.IPv4.protocol_enum`); ``None`` for a value
        this library does not enumerate."""
        try:
            return IPProtocol(self.next_header)
        except ValueError:
            return None

    @property
    def parsed_options(self) -> tuple[IPv6Option, ...]:
        """The option TLVs as a tuple of :class:`IPv6Option`, in wire
        order, parsed on demand (RFC 8200 §4.2) — padding included:
        Pad1 is a lone type byte, every other option is
        type/length/data.

        :raises InvalidFieldError: if an option's length byte is
            missing or its data runs past the header (bounded — never
            hangs or over-reads).
        """
        raw = self.options
        parsed: list[IPv6Option] = []
        cursor = 0
        while cursor < len(raw):
            option_type = raw[cursor]
            if option_type == _OPT_PAD1:
                parsed.append(IPv6Option(type=option_type))
                cursor += 1
                continue
            if cursor + 1 >= len(raw):
                raise InvalidFieldError(
                    f"{self.__class__.__name__} option missing its length byte",
                    protocol=type(self),
                    field="options",
                    offset=cursor,
                )
            length = raw[cursor + 1]
            if cursor + 2 + length > len(raw):
                raise InvalidFieldError(
                    f"{self.__class__.__name__} option data runs past the "
                    f"header",
                    protocol=type(self),
                    field="options",
                    offset=cursor,
                )
            parsed.append(
                IPv6Option(
                    type=option_type,
                    data=raw[cursor + 2 : cursor + 2 + length],
                )
            )
            cursor += 2 + length
        return tuple(parsed)


@dataclass(frozen=True, slots=True)
class IPv6HopByHopOptions(_IPv6OptionsHeader):
    """The Hop-by-Hop Options header (RFC 8200 §4.3), protocol 0.

    Examined by every node along the path; MLD reports ride behind one
    (carrying a Router Alert option).
    """


@dataclass(frozen=True, slots=True)
class IPv6DestinationOptions(_IPv6OptionsHeader):
    """The Destination Options header (RFC 8200 §4.6), protocol 60."""


@dataclass(frozen=True, slots=True)
class IPv6Routing(Protocol):
    """The Routing header (RFC 8200 §4.4), protocol 43.

    :param next_header: Protocol number of what follows this header
        (see :class:`~netprotocols.IPProtocol`).
    :param hdr_ext_len: Header length in 8-octet units, excluding the
        first 8; must equal ``(len(data) - 4) // 8``.
    :param routing_type: Routing variant (e.g. 2 for Mobile IPv6,
        3 for RPL source routing).
    :param segments_left: Route segments still to be visited.
    :param data: Type-specific data, exactly ``4 + hdr_ext_len * 8``
        bytes.
    """

    next_header: int
    hdr_ext_len: int
    routing_type: int
    segments_left: int
    data: bytes

    _struct: ClassVar[Struct] = Struct("!BBBB")

    def __post_init__(self) -> None:
        expected = 4 + self.hdr_ext_len * 8
        if len(self.data) != expected:
            raise InvalidFieldError(
                f"IPv6Routing hdr_ext_len {self.hdr_ext_len} disagrees "
                f"with data length {len(self.data)} (expected {expected} "
                f"bytes)",
                protocol=type(self),
                field="hdr_ext_len",
                expected=expected,
                actual=len(self.data),
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        next_header, hdr_ext_len, routing_type, segments_left = (
            cls._unpack_fixed(data)
        )
        declared = (hdr_ext_len + 1) * 8
        if declared > len(data):
            raise TruncatedHeaderError(
                f"IPv6Routing declares {declared} bytes, buffer holds "
                f"{len(data)}",
                protocol=cls,
                offset=0,
                field="hdr_ext_len",
                expected=declared,
                actual=len(data),
            )
        return cls(
            next_header=next_header,
            hdr_ext_len=hdr_ext_len,
            routing_type=routing_type,
            segments_left=segments_left,
            data=bytes(data[cls._struct.size : declared]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(
                self.next_header,
                self.hdr_ext_len,
                self.routing_type,
                self.segments_left,
            )
            + self.data
        )

    @property
    def header_len(self) -> int:
        return (self.hdr_ext_len + 1) * 8

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        return _next_in_ipv6_chain(self.next_header, registry)

    @property
    def next_header_name(self) -> str:
        """Display name of what follows, e.g. ``"TCP"``."""
        return _next_header_name(self.next_header)

    @property
    def next_header_enum(self) -> IPProtocol | None:
        """What follows this header as an
        :class:`~netprotocols.IPProtocol` (see
        :attr:`~netprotocols.IPv4.protocol_enum`); ``None`` for a value
        this library does not enumerate."""
        try:
            return IPProtocol(self.next_header)
        except ValueError:
            return None


@dataclass(frozen=True, slots=True)
class IPv6Fragment(Protocol):
    """The Fragment header (RFC 8200 §4.5), protocol 44 — fixed 8 bytes.

    :param next_header: Protocol number of the *reassembled* payload
        (see :class:`~netprotocols.IPProtocol`).
    :param reserved: Reserved byte, carried verbatim.
    :param fragment_offset: Offset of this fragment's data in 8-octet
        units (13 bits).
    :param res: Reserved 2-bit field, carried verbatim.
    :param m_flag: 1 when more fragments follow, 0 on the last one.
    :param identification: Fragment-group identification value.
    """

    next_header: int
    reserved: int
    fragment_offset: int
    res: int
    m_flag: int
    identification: int

    _struct: ClassVar[Struct] = Struct("!BBHI")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        next_header, reserved, offset_res_m, identification = cls._unpack_fixed(
            data
        )
        return cls(
            next_header=next_header,
            reserved=reserved,
            fragment_offset=offset_res_m >> 3,
            res=(offset_res_m >> 1) & 0b11,
            m_flag=offset_res_m & 1,
            identification=identification,
        )

    def __bytes__(self) -> bytes:
        return self._struct.pack(
            self.next_header,
            self.reserved,
            (self.fragment_offset << 3) | (self.res << 1) | self.m_flag,
            self.identification,
        )

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """See :meth:`Protocol.next_protocol`.

        Only the first fragment (``fragment_offset == 0``) starts with
        the upper-layer header; the chain ends here for all others.
        """
        if self.fragment_offset > 0:
            return None
        return _next_in_ipv6_chain(self.next_header, registry)

    @property
    def next_header_name(self) -> str:
        """Display name of the reassembled payload's protocol."""
        return _next_header_name(self.next_header)

    @property
    def next_header_enum(self) -> IPProtocol | None:
        """The reassembled payload's protocol as an
        :class:`~netprotocols.IPProtocol` (see
        :attr:`~netprotocols.IPv4.protocol_enum`); ``None`` for a value
        this library does not enumerate."""
        try:
            return IPProtocol(self.next_header)
        except ValueError:
            return None
