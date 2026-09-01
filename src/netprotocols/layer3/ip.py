"""IPv4 (RFC 791) and IPv6 (RFC 8200) headers.

The IPv4 options are kept as raw ``bytes`` (IHL aware), so
``bytes(IPv4.decode(x)) == x`` holds by construction; the
``parsed_options`` accessor walks the option TLV list on demand and
never re-encodes, mirroring TCP's. The common kinds — Record Route,
Timestamp, Router Alert (RFC 791 §3.1, RFC 2113) — are named, and
unknown kinds keep their raw data.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
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

__all__ = ["IPv4", "IPv4Option", "IPv6"]


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


#: Payload dispatch tables, populated on first use. The imports they
#: need must stay deferred to keep the layer modules acyclic (see
#: ARCHITECTURE.md), so the tables are built once on the first call
#: rather than at import time — every later call is a dict lookup.
#:
#: The IPv4 table simply omits the IPv6-only numbers, so the chain
#: gating is baked into the table instead of being re-tested per call.
_IPV6_PROTOCOL_CLASSES: dict[int, type[Protocol]] = {}
_IPV4_PROTOCOL_CLASSES: dict[int, type[Protocol]] = {}


def _build_ip_protocol_classes() -> None:
    """Populate the dispatch tables (called once, on first use)."""
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

    _IPV6_PROTOCOL_CLASSES.update(
        {
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
    )
    _IPV4_PROTOCOL_CLASSES.update(
        {
            number: protocol
            for number, protocol in _IPV6_PROTOCOL_CLASSES.items()
            if number not in _IPV6_ONLY_NUMBERS
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
    if not _IPV6_PROTOCOL_CLASSES:
        _build_ip_protocol_classes()
    table = _IPV6_PROTOCOL_CLASSES if ipv6 else _IPV4_PROTOCOL_CLASSES
    return table.get(number)


def _ip_protocol_name(number: int) -> str:
    try:
        return IPProtocol(number).display_name
    except ValueError:
        return f"unknown ({number})"


#: Single-byte IPv4 option kinds that carry no length or value
#: (RFC 791 §3.1): End of Option List terminates the parse,
#: No-Operation pads.
_OPT_EOL = 0
_OPT_NOP = 1

#: IPv4 option kinds this library names (RFC 791 §3.1; RFC 2113 for
#: Router Alert); unknown kinds fall back to their numeric value.
_OPTION_KIND_NAMES: dict[int, str] = {
    _OPT_EOL: "End of Option List",
    _OPT_NOP: "No-Operation",
    7: "Record Route",
    68: "Timestamp",
    148: "Router Alert",
}


@dataclass(frozen=True, slots=True)
class IPv4Option:
    """One IPv4 option (RFC 791 §3.1).

    :param kind: Option kind — ``0`` End of Option List, ``1``
        No-Operation, ``7`` Record Route, ``68`` Timestamp, ``148``
        Router Alert (see :attr:`kind_name`).
    :param data: The option's value bytes after the two kind/length
        bytes, kept raw; empty for the single-byte kinds (EOL, NOP).
    """

    kind: int
    data: bytes = b""

    @property
    def kind_name(self) -> str:
        """Display name of the option kind, e.g. ``"Router Alert"``;
        falls back to ``"unknown (n)"`` for kinds this library does not
        name."""
        return _OPTION_KIND_NAMES.get(self.kind, f"unknown ({self.kind})")


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
        consistent with ``ihl``. Parsed on demand via
        :attr:`parsed_options`.
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
        # As in Ethernet/ARP, the addresses are generated here and
        # cannot fail validation. The constructor's other checks are
        # already established above: the IHL is 4 bits (so <= 15), it
        # was rejected below 5, and the options are sliced to exactly
        # ihl * 4 bytes after the buffer was confirmed to hold them.
        header = object.__new__(cls)
        set_field = object.__setattr__
        set_field(header, "version", ver_ihl >> 4)
        set_field(header, "ihl", ihl)
        set_field(header, "dscp", dscp_ecn >> 2)
        set_field(header, "ecn", dscp_ecn & 0b11)
        set_field(header, "total_length", total_length)
        set_field(header, "identification", identification)
        set_field(header, "flags", flags_frag >> 13)
        set_field(header, "fragment_offset", flags_frag & 0x1FFF)
        set_field(header, "ttl", ttl)
        set_field(header, "protocol", protocol)
        set_field(header, "checksum", checksum)
        set_field(header, "src", bytes_to_ipv4(src))
        set_field(header, "dst", bytes_to_ipv4(dst))
        set_field(header, "options", bytes(data[cls._struct.size : ihl * 4]))
        return header

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

    @property
    def src_address(self) -> IPv4Address:
        """The source address as a stdlib
        :class:`~ipaddress.IPv4Address`, for comparison, subnet
        membership, and arithmetic; :attr:`src` stays the canonical
        string form."""
        return IPv4Address(self.src)

    @property
    def dst_address(self) -> IPv4Address:
        """The destination address as a stdlib
        :class:`~ipaddress.IPv4Address` (see :attr:`src_address`)."""
        return IPv4Address(self.dst)

    # -- options TLV list (parsed on demand, never re-encoded) --

    @property
    def parsed_options(self) -> tuple[IPv4Option, ...]:
        """The options as a tuple of :class:`IPv4Option`, in wire order,
        parsed on demand (RFC 791 §3.1). The single-byte kinds (EOL,
        NOP) carry no data; an End of Option List option ends the parse,
        so whatever follows it is padding and is not returned. Empty for
        a header without options.

        :raises InvalidFieldError: if an option's declared length is
            below the 2-byte minimum or runs past the options bytes
            (bounded — never hangs or over-reads).
        """
        raw = self.options
        parsed: list[IPv4Option] = []
        cursor = 0
        while cursor < len(raw):
            kind = raw[cursor]
            if kind in (_OPT_EOL, _OPT_NOP):
                parsed.append(IPv4Option(kind=kind))
                if kind == _OPT_EOL:
                    break
                cursor += 1
                continue
            if cursor + 1 >= len(raw):
                raise InvalidFieldError("IPv4 option missing its length byte")
            length = raw[cursor + 1]
            if length < 2:
                raise InvalidFieldError(
                    f"IPv4 option length must be at least 2, got {length}"
                )
            if cursor + length > len(raw):
                raise InvalidFieldError(
                    "IPv4 option value runs past the options bytes"
                )
            parsed.append(
                IPv4Option(kind=kind, data=raw[cursor + 2 : cursor + length])
            )
            cursor += length
        return tuple(parsed)


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

    @property
    def src_address(self) -> IPv6Address:
        """The source address as a stdlib
        :class:`~ipaddress.IPv6Address`, for comparison, subnet
        membership, and arithmetic; :attr:`src` stays the canonical
        string form."""
        return IPv6Address(self.src)

    @property
    def dst_address(self) -> IPv6Address:
        """The destination address as a stdlib
        :class:`~ipaddress.IPv6Address` (see :attr:`src_address`)."""
        return IPv6Address(self.dst)
