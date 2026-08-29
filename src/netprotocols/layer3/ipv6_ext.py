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
8 bytes. Option/data contents are kept as raw ``bytes`` — TLV parsing
inside options is deliberately out of scope for now.
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

__all__ = [
    "IPv6DestinationOptions",
    "IPv6Fragment",
    "IPv6HopByHopOptions",
    "IPv6Routing",
]


def _next_in_ipv6_chain(number: int) -> type[Protocol] | None:
    from netprotocols.layer3.ip import _ip_protocol_class

    return _ip_protocol_class(number, ipv6=True)


def _next_header_name(number: int) -> str:
    from netprotocols.layer3.ip import _ip_protocol_name

    return _ip_protocol_name(number)


@dataclass(frozen=True, slots=True)
class _IPv6OptionsHeader(Protocol):
    """Shared shape of the TLV-style extension headers.

    :param next_header: Protocol number of what follows this header.
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
                f"(expected {expected} bytes)"
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        next_header, hdr_ext_len = cls._unpack_fixed(data)
        declared = (hdr_ext_len + 1) * 8
        if declared > len(data):
            raise TruncatedHeaderError(
                f"{cls.__name__} declares {declared} bytes, buffer holds "
                f"{len(data)}"
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

    def next_protocol(self) -> type[Protocol] | None:
        return _next_in_ipv6_chain(self.next_header)

    @property
    def next_header_name(self) -> str:
        """Display name of what follows, e.g. ``"IPv6-ICMP"``."""
        return _next_header_name(self.next_header)


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

    :param next_header: Protocol number of what follows this header.
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
                f"bytes)"
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
                f"{len(data)}"
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

    def next_protocol(self) -> type[Protocol] | None:
        return _next_in_ipv6_chain(self.next_header)

    @property
    def next_header_name(self) -> str:
        """Display name of what follows, e.g. ``"TCP"``."""
        return _next_header_name(self.next_header)


@dataclass(frozen=True, slots=True)
class IPv6Fragment(Protocol):
    """The Fragment header (RFC 8200 §4.5), protocol 44 — fixed 8 bytes.

    :param next_header: Protocol number of the *reassembled* payload.
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

    def next_protocol(self) -> type[Protocol] | None:
        """See :meth:`Protocol.next_protocol`.

        Only the first fragment (``fragment_offset == 0``) starts with
        the upper-layer header; the chain ends here for all others.
        """
        if self.fragment_offset > 0:
            return None
        return _next_in_ipv6_chain(self.next_header)

    @property
    def next_header_name(self) -> str:
        """Display name of the reassembled payload's protocol."""
        return _next_header_name(self.next_header)
