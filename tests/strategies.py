"""Hypothesis strategies that produce valid protocol instances.

One function per protocol, each generating field combinations that
satisfy that class's own constraints — an interdependent pair like
IPv4's ``ihl``/``options`` or GRE's ``flags``/``fields`` is generated
*consistently*, never independently, so every instance a strategy
produces is one the constructor actually accepts.

Reusable beyond the round-trip property in ``test_fuzz.py``: any test
that wants "an arbitrary valid `SomeProtocol`" can draw from here
instead of hand-rolling field values.
"""

from collections.abc import Mapping

from hypothesis import strategies as st

from netprotocols import (
    ARP,
    DHCP,
    DNS,
    GRE,
    IGMP,
    VLAN,
    DNSOverTCP,
    ICMPv4,
    ICMPv6,
    IPv4,
    IPv6,
    IPv6DestinationOptions,
    IPv6HopByHopOptions,
    IPv6Routing,
    Protocol,
)
from netprotocols._base import bytes_to_ipv4, bytes_to_ipv6, bytes_to_mac


def mac_strings() -> st.SearchStrategy[str]:
    """A string every decoded MAC field could hold — generated the same
    way ``decode()`` generates one, so it is valid by construction."""
    return st.binary(min_size=6, max_size=6).map(bytes_to_mac)


def ipv4_strings() -> st.SearchStrategy[str]:
    """An IPv4 address string, valid by construction (see
    :func:`mac_strings`)."""
    return st.binary(min_size=4, max_size=4).map(bytes_to_ipv4)


def ipv6_strings() -> st.SearchStrategy[str]:
    """An IPv6 address string, valid by construction (see
    :func:`mac_strings`)."""
    return st.binary(min_size=16, max_size=16).map(bytes_to_ipv6)


#: Cap on the generated length of an options/body TLV blob: large
#: enough to matter, small enough that a run stays fast. Where a
#: field's length is dictated by another field (IPv4's ihl, GRE's
#: flags), that field is bounded instead and this constant is unused.
_MAX_BLOB = 64

#: Cap on hdr_ext_len for the IPv6 extension headers. The wire field is
#: a full byte (0-255, up to 2048 bytes of options); bounding it here
#: keeps generated buffers small without narrowing which *shapes* of
#: header get exercised.
_MAX_HDR_EXT_LEN = 20


@st.composite
def arp_headers(draw: st.DrawFn) -> ARP:
    return ARP(
        htype=draw(st.integers(0, 0xFFFF)),
        ptype=draw(st.integers(0, 0xFFFF)),
        hlen=draw(st.integers(0, 0xFF)),
        plen=draw(st.integers(0, 0xFF)),
        oper=draw(st.integers(0, 0xFFFF)),
        sha=draw(mac_strings()),
        spa=draw(ipv4_strings()),
        tha=draw(mac_strings()),
        tpa=draw(ipv4_strings()),
    )


@st.composite
def vlan_headers(draw: st.DrawFn) -> VLAN:
    return VLAN(
        pcp=draw(st.integers(0, 0b111)),
        dei=draw(st.integers(0, 1)),
        vid=draw(st.integers(0, 0xFFF)),
        ethertype=draw(st.integers(0, 0xFFFF)),
    )


@st.composite
def ipv4_headers(draw: st.DrawFn) -> IPv4:
    # ihl and options are the interdependent pair the module docstring
    # warns about: ihl (4 bits, >= 5) declares the options length in
    # 4-byte words, so the two are drawn together.
    ihl = draw(st.integers(5, 15))
    options_len = (ihl - 5) * 4
    return IPv4(
        version=draw(st.integers(0, 0xF)),
        ihl=ihl,
        dscp=draw(st.integers(0, 0x3F)),
        ecn=draw(st.integers(0, 0b11)),
        total_length=draw(st.integers(0, 0xFFFF)),
        identification=draw(st.integers(0, 0xFFFF)),
        flags=draw(st.integers(0, 0b111)),
        fragment_offset=draw(st.integers(0, 0x1FFF)),
        ttl=draw(st.integers(0, 0xFF)),
        protocol=draw(st.integers(0, 0xFF)),
        checksum=draw(st.integers(0, 0xFFFF)),
        src=draw(ipv4_strings()),
        dst=draw(ipv4_strings()),
        options=draw(st.binary(min_size=options_len, max_size=options_len)),
    )


@st.composite
def ipv6_headers(draw: st.DrawFn) -> IPv6:
    return IPv6(
        version=draw(st.integers(0, 0xF)),
        traffic_class=draw(st.integers(0, 0xFF)),
        flow_label=draw(st.integers(0, 0xFFFFF)),
        payload_length=draw(st.integers(0, 0xFFFF)),
        next_header=draw(st.integers(0, 0xFF)),
        hop_limit=draw(st.integers(0, 0xFF)),
        src=draw(ipv6_strings()),
        dst=draw(ipv6_strings()),
    )


def _ipv6_options_headers[P: Protocol](cls: type[P]) -> st.SearchStrategy[P]:
    """Shared strategy for the two TLV-style extension headers
    (:class:`IPv6HopByHopOptions`, :class:`IPv6DestinationOptions`):
    ``hdr_ext_len`` and ``options`` are the interdependent pair —
    ``options`` must be exactly ``6 + hdr_ext_len * 8`` bytes."""

    @st.composite
    def strategy(draw: st.DrawFn) -> P:
        hdr_ext_len = draw(st.integers(0, _MAX_HDR_EXT_LEN))
        options_len = 6 + hdr_ext_len * 8
        return cls(
            next_header=draw(st.integers(0, 0xFF)),
            hdr_ext_len=hdr_ext_len,
            options=draw(st.binary(min_size=options_len, max_size=options_len)),
        )

    return strategy()


ipv6_hop_by_hop_headers = _ipv6_options_headers(IPv6HopByHopOptions)
ipv6_destination_options_headers = _ipv6_options_headers(IPv6DestinationOptions)


@st.composite
def ipv6_routing_headers(draw: st.DrawFn) -> IPv6Routing:
    # hdr_ext_len / data is the same interdependent shape as the TLV
    # options headers above, with a 4-byte fixed portion instead of 6.
    hdr_ext_len = draw(st.integers(0, _MAX_HDR_EXT_LEN))
    data_len = 4 + hdr_ext_len * 8
    return IPv6Routing(
        next_header=draw(st.integers(0, 0xFF)),
        hdr_ext_len=hdr_ext_len,
        routing_type=draw(st.integers(0, 0xFF)),
        segments_left=draw(st.integers(0, 0xFF)),
        data=draw(st.binary(min_size=data_len, max_size=data_len)),
    )


def _icmp_headers[P: Protocol](cls: type[P]) -> st.SearchStrategy[P]:
    """Shared strategy for :class:`ICMPv4`/:class:`ICMPv6`: both are
    the same shape (``rest`` fixed at 4 bytes, ``body`` free)."""

    @st.composite
    def strategy(draw: st.DrawFn) -> P:
        return cls(
            type=draw(st.integers(0, 0xFF)),
            code=draw(st.integers(0, 0xFF)),
            checksum=draw(st.integers(0, 0xFFFF)),
            rest=draw(st.binary(min_size=4, max_size=4)),
            body=draw(st.binary(max_size=_MAX_BLOB)),
        )

    return strategy()


icmpv4_headers = _icmp_headers(ICMPv4)
icmpv6_headers = _icmp_headers(ICMPv6)


@st.composite
def igmp_headers(draw: st.DrawFn) -> IGMP:
    return IGMP(
        type=draw(st.integers(0, 0xFF)),
        max_resp_code=draw(st.integers(0, 0xFF)),
        checksum=draw(st.integers(0, 0xFFFF)),
        body=draw(st.binary(max_size=_MAX_BLOB)),
    )


@st.composite
def dns_headers(draw: st.DrawFn) -> DNS:
    return DNS(
        transaction_id=draw(st.integers(0, 0xFFFF)),
        flags=draw(st.integers(0, 0xFFFF)),
        qdcount=draw(st.integers(0, 0xFFFF)),
        ancount=draw(st.integers(0, 0xFFFF)),
        nscount=draw(st.integers(0, 0xFFFF)),
        arcount=draw(st.integers(0, 0xFFFF)),
        sections=draw(st.binary(max_size=_MAX_BLOB)),
    )


@st.composite
def dns_over_tcp_headers(draw: st.DrawFn) -> DNSOverTCP:
    return DNSOverTCP(message_length=draw(st.integers(0, 0xFFFF)))


@st.composite
def dhcp_headers(draw: st.DrawFn) -> DHCP:
    return DHCP(
        op=draw(st.integers(0, 0xFF)),
        htype=draw(st.integers(0, 0xFF)),
        hlen=draw(st.integers(0, 0xFF)),
        hops=draw(st.integers(0, 0xFF)),
        xid=draw(st.integers(0, 0xFFFFFFFF)),
        secs=draw(st.integers(0, 0xFFFF)),
        flags=draw(st.integers(0, 0xFFFF)),
        ciaddr=draw(ipv4_strings()),
        yiaddr=draw(ipv4_strings()),
        siaddr=draw(ipv4_strings()),
        giaddr=draw(ipv4_strings()),
        chaddr=draw(st.binary(min_size=16, max_size=16)),
        sname=draw(st.binary(min_size=64, max_size=64)),
        file=draw(st.binary(min_size=128, max_size=128)),
        options=draw(st.binary(max_size=_MAX_BLOB)),
    )


@st.composite
def gre_headers(draw: st.DrawFn) -> GRE:
    # flags / fields is the module's other interdependent pair: the
    # flag bits announce exactly which optional fields are present, so
    # fields' length is computed from flags, never drawn independently.
    flags = draw(st.integers(0, 0xFFFF))
    fields_len = GRE._optional_len(flags)
    return GRE(
        flags=flags,
        protocol_type=draw(st.integers(0, 0xFFFF)),
        fields=draw(st.binary(min_size=fields_len, max_size=fields_len)),
    )


#: One entry per protocol without an existing Hypothesis-generated
#: round-trip test (see test_fuzz.py::TestConstrainedRoundTrips for
#: the other four: Ethernet, UDP, TCP, IPv6Fragment). Keyed by class
#: name for readable parametrize IDs.
ROUND_TRIP_STRATEGIES: Mapping[str, st.SearchStrategy[Protocol]] = {
    "ARP": arp_headers(),
    "VLAN": vlan_headers(),
    "IPv4": ipv4_headers(),
    "IPv6": ipv6_headers(),
    "IPv6HopByHopOptions": ipv6_hop_by_hop_headers,
    "IPv6DestinationOptions": ipv6_destination_options_headers,
    "IPv6Routing": ipv6_routing_headers(),
    "ICMPv4": icmpv4_headers,
    "ICMPv6": icmpv6_headers,
    "IGMP": igmp_headers(),
    "DNS": dns_headers(),
    "DNSOverTCP": dns_over_tcp_headers(),
    "DHCP": dhcp_headers(),
    "GRE": gre_headers(),
}
