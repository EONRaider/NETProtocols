"""IPv4 (RFC 791) and IPv6 (RFC 8200) headers."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import (
    Protocol,
    bytes_to_ipv4,
    bytes_to_ipv6,
    ipv4_to_bytes,
    ipv6_to_bytes,
)
from netprotocols._enums import IPProtocol
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)
from netprotocols.utils.ipv4 import validate_ipv4_addr

__all__ = ["IPv4", "IPv6"]


#: Numbers that only make sense inside an IPv6 chain (RFC 8200 §4.1):
#: extension headers follow the IPv6 fixed header or one another, never
#: an IPv4 header.
_IPV6_ONLY_NUMBERS = frozenset(
    {
        IPProtocol.HOPOPT,
        IPProtocol.IPV6_ROUTE,
        IPProtocol.IPV6_FRAG,
        IPProtocol.IPV6_DSTOPTS,
    }
)


def _ip_protocol_class(number: int, *, ipv6: bool) -> type[Protocol] | None:
    """Map an IP protocol number to the class that decodes its payload.

    The number space is shared between IPv4 ``protocol`` and IPv6
    ``next_header`` (the values are disjoint), so both classes dispatch
    through this single registry — but the IPv6 extension headers are
    handed out only when the caller is part of an IPv6 chain
    (``ipv6=True``): a garbage IPv4 packet with ``protocol=0`` must not
    decode a Hop-by-Hop layer.
    """
    from netprotocols.layer3.gre import GRE
    from netprotocols.layer3.icmp import ICMPv4, ICMPv6
    from netprotocols.layer3.igmp import IGMP
    from netprotocols.layer3.ipv6_ext import (
        IPv6DestinationOptions,
        IPv6Fragment,
        IPv6HopByHopOptions,
        IPv6Routing,
    )
    from netprotocols.layer4.tcp import TCP
    from netprotocols.layer4.udp import UDP

    if not ipv6 and number in _IPV6_ONLY_NUMBERS:
        return None
    mapping: dict[int, type[Protocol]] = {
        IPProtocol.HOPOPT: IPv6HopByHopOptions,
        IPProtocol.ICMP: ICMPv4,
        IPProtocol.IGMP: IGMP,
        IPProtocol.GRE: GRE,
        IPProtocol.IPV6_ROUTE: IPv6Routing,
        IPProtocol.IPV6_FRAG: IPv6Fragment,
        IPProtocol.IPV6_ICMP: ICMPv6,
        IPProtocol.IPV6_DSTOPTS: IPv6DestinationOptions,
        IPProtocol.TCP: TCP,
        IPProtocol.UDP: UDP,
    }
    return mapping.get(number)


def _ip_protocol_name(number: int) -> str:
    try:
        return IPProtocol(number).display_name
    except ValueError:
        return f"unknown ({number})"


@dataclass(frozen=True, slots=True)
class IPv4(Protocol):
    """An IPv4 header.

    :param version: Protocol version; always ``4``.
    :param ihl: Internet header length in 32-bit words; ``5``-``15``,
        and must equal ``5 + len(options) // 4``.
    :param dscp: Differentiated services code point.
    :param ecn: Explicit congestion notification.
    :param total_length: Length in bytes of the entire datagram,
        header and payload included.
    :param identification: Fragment-group identification value.
    :param flags: Fragmentation control flags (3 bits).
    :param fragment_offset: Fragment offset in 8-byte units (13 bits).
    :param ttl: Time to live.
    :param protocol: Protocol number of the payload (see
        :class:`~netprotocols.IPProtocol`).
    :param checksum: Header checksum, carried verbatim (this library
        neither computes nor verifies checksums).
    :param src: Source address in dotted-decimal notation.
    :param dst: Destination address in dotted-decimal notation.
    :param options: Raw options bytes; length must be a multiple of 4
        consistent with ``ihl``.
    """

    version: int
    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src: str
    dst: str
    options: bytes = b""

    _struct: ClassVar[Struct] = Struct("!BBHHHBBH4s4s")

    flag_names: ClassVar[dict[int, str]] = {
        0b000: "Not set",
        0b001: "More fragments (MF)",
        0b010: "Don't fragment (DF)",
    }

    def __post_init__(self) -> None:
        if not 5 <= self.ihl <= 15:
            raise InvalidFieldError(
                f"IPv4 IHL must be within 5-15, got {self.ihl}"
            )
        if self.ihl != 5 + len(self.options) // 4 or len(self.options) % 4:
            raise InvalidFieldError(
                f"IPv4 IHL {self.ihl} disagrees with options length "
                f"{len(self.options)} (expected {(self.ihl - 5) * 4} bytes)"
            )
        validate_ipv4_addr(self.src)
        validate_ipv4_addr(self.dst)

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        (
            ver_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_frag,
            ttl,
            protocol,
            checksum,
            src,
            dst,
        ) = cls._unpack_fixed(data)
        ihl = ver_ihl & 0x0F
        if ihl < 5:
            raise InvalidFieldError(f"IPv4 IHL must be at least 5, got {ihl}")
        if ihl * 4 > len(data):
            raise TruncatedHeaderError(
                f"IPv4 header declares {ihl * 4} bytes, buffer holds "
                f"{len(data)}"
            )
        return cls(
            version=ver_ihl >> 4,
            ihl=ihl,
            dscp=dscp_ecn >> 2,
            ecn=dscp_ecn & 0b11,
            total_length=total_length,
            identification=identification,
            flags=flags_frag >> 13,
            fragment_offset=flags_frag & 0x1FFF,
            ttl=ttl,
            protocol=protocol,
            checksum=checksum,
            src=bytes_to_ipv4(src),
            dst=bytes_to_ipv4(dst),
            options=bytes(data[cls._struct.size : ihl * 4]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(
                (self.version << 4) | self.ihl,
                (self.dscp << 2) | self.ecn,
                self.total_length,
                self.identification,
                (self.flags << 13) | self.fragment_offset,
                self.ttl,
                self.protocol,
                self.checksum,
                ipv4_to_bytes(self.src),
                ipv4_to_bytes(self.dst),
            )
            + self.options
        )

    @property
    def header_len(self) -> int:
        return self.ihl * 4

    def next_protocol(self) -> type[Protocol] | None:
        """See :meth:`Protocol.next_protocol`.

        A non-first fragment (``fragment_offset > 0``) carries a slice
        from the middle of the original payload — no upper-layer header
        exists at its start — so the chain ends here for those.
        """
        if self.fragment_offset > 0:
            return None
        return _ip_protocol_class(self.protocol, ipv6=False)

    @property
    def protocol_name(self) -> str:
        """Display name of the payload protocol, e.g. ``"TCP"``."""
        return _ip_protocol_name(self.protocol)

    @property
    def flags_name(self) -> str:
        """Display name of the fragmentation flags, e.g.
        ``"Don't fragment (DF)"``."""
        return self.flag_names.get(self.flags, f"unknown ({self.flags:#05b})")

    @property
    def checksum_hex_str(self) -> str:
        """The header checksum as a hexadecimal string, e.g. ``"0xf24e"``."""
        return f"{self.checksum:#06x}"


@dataclass(frozen=True, slots=True)
class IPv6(Protocol):
    """An IPv6 header.

    :param version: Protocol version; always ``6``.
    :param traffic_class: Traffic class (8 bits).
    :param flow_label: Flow label (20 bits).
    :param payload_length: Length in bytes of the payload following
        this header.
    :param next_header: Protocol number of the payload (see
        :class:`~netprotocols.IPProtocol`).
    :param hop_limit: Hop limit (the IPv6 analogue of IPv4 TTL).
    :param src: Source address, e.g. ``"fe80::200:86ff:fe05:80da"``.
    :param dst: Destination address.
    """

    version: int
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    src: str
    dst: str

    _struct: ClassVar[Struct] = Struct("!IHBB16s16s")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        (
            ver_tc_flabel,
            payload_length,
            next_header,
            hop_limit,
            src,
            dst,
        ) = cls._unpack_fixed(data)
        return cls(
            version=ver_tc_flabel >> 28,
            traffic_class=(ver_tc_flabel >> 20) & 0xFF,
            flow_label=ver_tc_flabel & 0xFFFFF,
            payload_length=payload_length,
            next_header=next_header,
            hop_limit=hop_limit,
            src=bytes_to_ipv6(src),
            dst=bytes_to_ipv6(dst),
        )

    def __bytes__(self) -> bytes:
        return self._struct.pack(
            (self.version << 28) | (self.traffic_class << 20) | self.flow_label,
            self.payload_length,
            self.next_header,
            self.hop_limit,
            ipv6_to_bytes(self.src),
            ipv6_to_bytes(self.dst),
        )

    def next_protocol(self) -> type[Protocol] | None:
        return _ip_protocol_class(self.next_header, ipv6=True)

    @property
    def next_header_name(self) -> str:
        """Display name of the payload protocol, e.g. ``"IPv6-ICMP"``."""
        return _ip_protocol_name(self.next_header)

    @property
    def traffic_class_hex_str(self) -> str:
        """The traffic class as a hexadecimal string, e.g. ``"0x00"``."""
        return f"{self.traffic_class:#04x}"

    @property
    def flow_label_hex_str(self) -> str:
        """The flow label as a hexadecimal string, e.g. ``"0x9f8c3"``."""
        return f"{self.flow_label:#07x}"
