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
    AH,
    ARP,
    BGP,
    CDP,
    CDPTLV,
    DHCP,
    DNS,
    ESP,
    GRE,
    HSRP,
    HTTP,
    IGMP,
    LLC,
    LLDP,
    LLDPTLV,
    MPLS,
    NTP,
    OSPF,
    OSPFLSA,
    PIM,
    RADIUS,
    RIP,
    SCTP,
    SNAP,
    STP,
    STUN,
    TFTP,
    TLS,
    VLAN,
    VRRP,
    VXLAN,
    AHv6,
    BGPPathAttribute,
    BGPPrefix,
    DNSOverTCP,
    ICMPv4,
    ICMPv6,
    IPv4,
    IPv6,
    IPv6DestinationOptions,
    IPv6HopByHopOptions,
    IPv6Routing,
    LLDPChassisID,
    LLDPPortID,
    MPLSLabel,
    OSPFDatabaseDescription,
    OSPFHello,
    OSPFLSAHeader,
    OSPFLSRequest,
    PIMAssert,
    PIMEncodedGroup,
    PIMEncodedSource,
    PIMEncodedUnicast,
    PIMGroupSet,
    PIMHello,
    PIMHelloOption,
    PIMJoinPrune,
    PIMRegister,
    PIMRegisterStop,
    Protocol,
    SCTPChunk,
    STUNAttribute,
    TLSClientHello,
    TLSExtension,
    VRRPv6,
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


#: An LLDP TLV value: mostly short, sometimes long enough to need the
#: 9th Length bit, up to the 511 bytes the Length can carry.
_lldp_values = st.one_of(
    st.binary(max_size=24), st.binary(min_size=256, max_size=511)
)


@st.composite
def lldp_lldpdus(draw: st.DrawFn) -> LLDP:
    # tlvs is LLDP's one field, constrained as decode produces it: an
    # End of LLDPDU TLV (type 0) comes last, empty, or not at all, and
    # an LLDPDU holds at least one TLV. Half open with the mandatory
    # Chassis ID, Port ID and TTL, so the typed accessors have
    # something to read.
    tlvs: list[LLDPTLV] = []
    if draw(st.booleans()):
        ids = st.tuples(
            st.integers(0, 0xFF), st.binary(min_size=1, max_size=32)
        )
        tlvs.append(LLDPChassisID(*draw(ids)).tlv)
        tlvs.append(LLDPPortID(*draw(ids)).tlv)
        tlvs.append(LLDPTLV(3, draw(st.integers(0, 0xFFFF)).to_bytes(2)))
    tlvs += draw(
        st.lists(
            st.builds(LLDPTLV, st.integers(1, 0x7F), _lldp_values), max_size=6
        )
    )
    if not tlvs or draw(st.booleans()):
        tlvs.append(LLDPTLV(0))
    return LLDP(tlvs=tuple(tlvs))


@st.composite
def mpls_stacks(draw: st.DrawFn) -> MPLS:
    # Construction requires S on the last entry alone, which is also all
    # decode produces, so every buildable stack is canonical.
    depth = draw(st.integers(1, 8))
    return MPLS(
        labels=tuple(
            MPLSLabel(
                label=draw(st.integers(0, 0xFFFFF)),
                traffic_class=draw(st.integers(0, 0b111)),
                bottom_of_stack=int(index == depth - 1),
                ttl=draw(st.integers(0, 0xFF)),
            )
            for index in range(depth)
        )
    )


@st.composite
def llc_headers(draw: st.DrawFn) -> LLC:
    # Canonical Controls only: a U-format one (two low bits 11) is one
    # octet, an I- or S-format one two, as decode reads them.
    if draw(st.booleans()):
        control = draw(st.integers(0, 0x3F)) << 2 | 0x03
    else:
        control = draw(st.integers(0, 0xFFFF).filter(lambda c: c & 3 != 3))
    return LLC(
        dsap=draw(st.integers(0, 0xFF)),
        ssap=draw(st.integers(0, 0xFF)),
        control=control,
    )


@st.composite
def snap_headers(draw: st.DrawFn) -> SNAP:
    return SNAP(
        oui=draw(st.integers(0, 0xFFFFFF)), pid=draw(st.integers(0, 0xFFFF))
    )


@st.composite
def cdp_pdus(draw: st.DrawFn) -> CDP:
    # Any version: decode reads every one the same way. A CDPTLV's
    # Length is never below 4, so every PDU built decodes back whole.
    tlvs = draw(
        st.lists(
            st.builds(
                CDPTLV,
                type=st.integers(0, 0xFFFF),
                value=st.binary(max_size=24),
            ),
            max_size=6,
        )
    )
    return CDP(
        version=draw(st.integers(0, 0xFF)),
        ttl=draw(st.integers(0, 0xFF)),
        checksum=draw(st.integers(0, 0xFFFF)),
        tlvs=tuple(tlvs),
    )


@st.composite
def stp_headers(draw: st.DrawFn) -> STP:
    """A canonical BPDU of each type: a TCN carries nothing after its
    type, a Configuration BPDU no Version 1 Length."""
    bpdu_type = draw(st.sampled_from([0x00, 0x02, 0x80]))
    version = draw(st.integers(0, 0xFF))
    if bpdu_type == 0x80:
        return STP(protocol_id=0, version=version, bpdu_type=bpdu_type)
    u16 = st.integers(0, 0xFFFF)
    return STP(
        protocol_id=0,
        version=version,
        bpdu_type=bpdu_type,
        flags=draw(st.integers(0, 0xFF)),
        root_priority=draw(u16),
        root_mac=draw(mac_strings()),
        root_path_cost=draw(st.integers(0, 0xFFFFFFFF)),
        bridge_priority=draw(u16),
        bridge_mac=draw(mac_strings()),
        port_id=draw(u16),
        message_age=draw(u16),
        max_age=draw(u16),
        hello_time=draw(u16),
        forward_delay=draw(u16),
        version_1_length=(
            draw(st.integers(0, 0xFF)) if bpdu_type == 0x02 else None
        ),
    )


@st.composite
def vxlan_headers(draw: st.DrawFn) -> VXLAN:
    # The round-trip property decodes what it builds, and decode rejects
    # a clear I flag (the constructor does not; test_vxlan.py covers
    # those headers), so the flag is forced on. The other seven flag
    # bits and both reserved fields are carried verbatim, so they are
    # drawn freely.
    return VXLAN(
        flags=draw(st.integers(0, 0xFF)) | VXLAN.I_FLAG,
        reserved1=draw(st.integers(0, 0xFFFFFF)),
        vni=draw(st.integers(0, 0xFFFFFF)),
        reserved2=draw(st.integers(0, 0xFF)),
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


def _ipv6_options_headers[P: (IPv6HopByHopOptions, IPv6DestinationOptions)](
    cls: type[P],
) -> st.SearchStrategy[P]:
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


def _icmp_headers[P: (ICMPv4, ICMPv6)](cls: type[P]) -> st.SearchStrategy[P]:
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


@st.composite
def sctp_chunks(draw: st.DrawFn) -> SCTPChunk:
    return SCTPChunk(
        type=draw(st.integers(0, 0xFF)),
        flags=draw(st.integers(0, 0xFF)),
        value=draw(st.binary(max_size=_MAX_BLOB)),
    )


@st.composite
def sctp_headers(draw: st.DrawFn) -> SCTP:
    # chunks is built from whole, padded chunks rather than drawn as
    # free bytes: decode() leaves a zero tail where a chunk would start
    # undecoded, so free bytes ending in one would not round-trip.
    chunks = draw(st.lists(sctp_chunks(), max_size=4))
    return SCTP(
        src_port=draw(st.integers(0, 0xFFFF)),
        dst_port=draw(st.integers(0, 0xFFFF)),
        verification_tag=draw(st.integers(0, 0xFFFFFFFF)),
        checksum=draw(st.integers(0, 0xFFFFFFFF)),
        chunks=b"".join(bytes(chunk) for chunk in chunks),
    )


@st.composite
def bgp_prefixes(draw: st.DrawFn) -> BGPPrefix:
    length = draw(st.integers(0, 32))
    size = (length + 7) // 8
    return BGPPrefix(
        length=length, prefix=draw(st.binary(min_size=size, max_size=size))
    )


@st.composite
def bgp_path_attributes(draw: st.DrawFn) -> BGPPathAttribute:
    flags = draw(st.integers(0, 0xFF))
    limit = 300 if flags & 0x10 else 0xFF
    return BGPPathAttribute(
        flags=flags,
        type_code=draw(st.integers(0, 0xFF)),
        data=draw(st.binary(max_size=limit)),
    )


@st.composite
def bgp_messages(draw: st.DrawFn) -> BGP:
    # Any of the five types, with a body inside that type's length
    # bounds (decode() rejects the rest); the body is opaque bytes, so
    # an UPDATE or OPEN drawn here need not parse, which is what lets
    # the round trip cover messages whose accessors would raise.
    bounds = {1: (10, 64), 2: (4, 64), 3: (2, 64), 4: (0, 0), 5: (4, 64)}
    type_ = draw(st.sampled_from(sorted(bounds)))
    low, high = bounds[type_]
    body = draw(st.binary(min_size=low, max_size=high))
    return BGP(marker=BGP.MARKER, length=19 + len(body), type=type_, body=body)


@st.composite
def esp_packets(draw: st.DrawFn) -> ESP:
    # Everything past the SPI and sequence number is opaque, so any
    # bytes at all — including none — are a valid remainder.
    return ESP(
        spi=draw(st.integers(0, 0xFFFFFFFF)),
        sequence_number=draw(st.integers(0, 0xFFFFFFFF)),
        ciphertext=draw(st.binary(max_size=_MAX_BLOB)),
    )


#: Cap on an AH header's length in alignment steps (one Payload Len
#: unit under IPv4, two under IPv6), so a header is at most
#: (40 + 2) * 4 = 168 bytes under IPv4 and (80 + 2) * 4 = 328 under
#: IPv6; Payload Len itself runs to 255.
_MAX_AH_STEPS = 40


@st.composite
def ah_headers(draw: st.DrawFn, cls: type[AH] = AH) -> AH:
    # payload_len / icv is AH's interdependent pair: Payload Len sizes
    # the ICV field, and IPv6 (AHv6) needs the whole header to be a
    # multiple of 8 octets, so payload_len is drawn in alignment steps
    # and the ICV is drawn to exactly the length it then declares.
    step = cls._alignment // 4
    payload_len = draw(st.integers(1, _MAX_AH_STEPS)) * step
    icv_len = (payload_len + 2) * 4 - 12
    return cls(
        next_header=draw(st.integers(0, 0xFF)),
        payload_len=payload_len,
        reserved=draw(st.integers(0, 0xFFFF)),
        spi=draw(st.integers(0, 0xFFFFFFFF)),
        sequence_number=draw(st.integers(0, 0xFFFFFFFF)),
        icv=draw(st.binary(min_size=icv_len, max_size=icv_len)),
    )


def _u(bits: int) -> st.SearchStrategy[int]:
    return st.integers(0, (1 << bits) - 1)


@st.composite
def ospf_lsa_headers(draw: st.DrawFn, length: int = 20) -> OSPFLSAHeader:
    """An LSA header declaring ``length`` bytes."""
    return OSPFLSAHeader(
        ls_age=draw(_u(16)),
        options=draw(_u(8)),
        ls_type=draw(_u(8)),
        link_state_id=draw(ipv4_strings()),
        advertising_router=draw(ipv4_strings()),
        ls_sequence_number=draw(_u(32)),
        ls_checksum=draw(_u(16)),
        length=length,
    )


@st.composite
def ospf_lsas(draw: st.DrawFn) -> OSPFLSA:
    body = draw(st.binary(max_size=24))
    return OSPFLSA(draw(ospf_lsa_headers(20 + len(body))), body)


@st.composite
def _ospf_bodies(draw: st.DrawFn, type_: int) -> bytes:
    """A body with message ``type_``'s framing, built from the records
    its accessor returns, so it is one decode accepts."""
    headers = st.lists(ospf_lsa_headers(), max_size=3).map(tuple)
    if type_ == 1:
        return bytes(
            OSPFHello(
                network_mask=draw(ipv4_strings()),
                hello_interval=draw(_u(16)),
                options=draw(_u(8)),
                router_priority=draw(_u(8)),
                router_dead_interval=draw(_u(32)),
                designated_router=draw(ipv4_strings()),
                backup_designated_router=draw(ipv4_strings()),
                neighbors=tuple(draw(st.lists(ipv4_strings(), max_size=4))),
            )
        )
    if type_ == 2:
        return bytes(
            OSPFDatabaseDescription(
                interface_mtu=draw(_u(16)),
                options=draw(_u(8)),
                flags=draw(_u(8)),
                dd_sequence_number=draw(_u(32)),
                lsa_headers=draw(headers),
            )
        )
    if type_ == 3:
        requests = draw(
            st.lists(
                st.builds(
                    OSPFLSRequest, _u(32), ipv4_strings(), ipv4_strings()
                ),
                max_size=3,
            )
        )
        return b"".join(map(bytes, requests))
    if type_ == 4:
        lsas = draw(st.lists(ospf_lsas(), max_size=3))
        return len(lsas).to_bytes(4, "big") + b"".join(map(bytes, lsas))
    if type_ == 5:
        return b"".join(map(bytes, draw(headers)))
    return draw(st.binary(max_size=_MAX_BLOB))


@st.composite
def ospf_packets(draw: st.DrawFn) -> OSPF:
    # packet_length / body and au_type / authentication / auth_trailer
    # are OSPF's interdependent groups: the length is computed from the
    # body, which is built with its type's framing, and under AuType 2
    # and 3 the trailer is drawn to the size Auth Data Len declares.
    type_ = draw(st.sampled_from([1, 2, 3, 4, 5, 0, 6, 255]))
    body = draw(_ospf_bodies(type_))
    au_type = draw(st.sampled_from([0, 1, 2, 3, 4]))
    authentication = draw(st.binary(min_size=8, max_size=8))
    trailer = (
        draw(st.binary(min_size=authentication[3], max_size=authentication[3]))
        if au_type in (2, 3)
        else b""
    )
    return OSPF(
        version=2,
        type=type_,
        packet_length=24 + len(body),
        router_id=draw(ipv4_strings()),
        area_id=draw(ipv4_strings()),
        checksum=draw(_u(16)),
        instance_id=draw(_u(8)),
        au_type=au_type,
        authentication=authentication,
        body=body,
        auth_trailer=trailer,
    )


@st.composite
def vrrp_headers(draw: st.DrawFn, cls: type[VRRP] = VRRP) -> VRRP:
    # version / count_ip_addrs / addresses / auth_data are VRRP's
    # interdependent fields: the version decides whether 8 bytes of
    # authentication data follow, and the count must be the number of
    # addresses, each in the family's own string form. VRRPv6 carries
    # VRRPv3 alone.
    version = draw(st.sampled_from(sorted(cls._versions)))
    addresses = draw(
        st.lists(ipv6_strings() if cls._ipv6 else ipv4_strings(), max_size=8)
    )
    auth_len = 8 if version == 2 else 0
    return cls(
        version=version,
        type=draw(st.integers(0, 0x0F)),
        vrid=draw(st.integers(0, 0xFF)),
        priority=draw(st.integers(0, 0xFF)),
        count_ip_addrs=len(addresses),
        adver_word=draw(st.integers(0, 0xFFFF)),
        checksum=draw(st.integers(0, 0xFFFF)),
        addresses=tuple(addresses),
        auth_data=draw(st.binary(min_size=auth_len, max_size=auth_len)),
    )


_HTTP_TOKENS = st.sampled_from([b"GET", b"POST", b"OPTIONS", b"X-Y.1"])
_HTTP_TARGETS = st.sampled_from(
    [b"/", b"/a/b?c=d", b"*", b"http://h:8/x", b"h:443", b"/\xff%20"]
)
#: Field lines, including the odd ones the grammar resolves rather than
#: rejects: obs-fold, whitespace before the colon, a missing colon,
#: CR/NUL in a value, list fields and Host variants.
_HTTP_FIELDS = st.sampled_from(
    [
        b"Host: h",
        b"Host: h:8",
        b"Host: [::1]",
        b"Host: a b",
        b"X: y",
        b"x: z\r\n folded",
        b"Accept : */*",
        b"No-Colon",
        b"Bad Name: v",
        b"V: a\x00b",
        b"Connection: close",
        b"Connection: keep-alive, , x",
        b"Content-Type: text/plain; charset=latin-1",
        b"\xe9: obs-text",
    ]
)


@st.composite
def _chunked_body(draw: st.DrawFn) -> bytes:
    chunks = draw(st.lists(st.binary(min_size=1, max_size=16), max_size=4))
    body = b""
    for chunk in chunks:
        extension = draw(st.sampled_from([b"", b";a", b";a=b", b';a="q"']))
        body += b"%x%s\r\n%s\r\n" % (len(chunk), extension, chunk)
    trailers = draw(st.lists(st.sampled_from([b"T: v", b"t:w"]), max_size=2))
    return body + b"0\r\n" + b"".join(t + b"\r\n" for t in trailers) + b"\r\n"


@st.composite
def http_messages(draw: st.DrawFn) -> HTTP:
    """A message decodable without context: no ``request_method``, and
    never framed by connection close (``decode(raw)`` would need
    ``closed=True``). Every response therefore carries a length, or is
    a status that never has a body."""
    version = draw(st.sampled_from([b"HTTP/1.1", b"HTTP/1.0"]))
    is_response = draw(st.booleans())
    if is_response:
        status = draw(st.sampled_from([b"200", b"204", b"304", b"404", b"500"]))
        start = (
            version + b" " + status + b" " + draw(st.sampled_from([b"OK", b""]))
        )
        bodyless = status in (b"204", b"304")
    else:
        start = draw(_HTTP_TOKENS) + b" " + draw(_HTTP_TARGETS) + b" " + version
        bodyless = False
    fields = draw(st.lists(_HTTP_FIELDS, max_size=6))
    framing = (
        "none"
        if bodyless
        else draw(
            st.sampled_from(
                ["none", "length", "chunked"]
                if not is_response
                else ["length", "chunked"]
            )
        )
    )
    body = b""
    if framing == "length":
        body = draw(st.binary(max_size=32))
        fields.append(b"Content-Length: %d" % len(body))
    elif framing == "chunked":
        body = draw(_chunked_body())
        fields.append(b"Transfer-Encoding: chunked")
    fields = draw(st.permutations(fields))
    leading = draw(st.sampled_from([b"", b"\r\n"]))
    head = (
        leading
        + start
        + b"\r\n"
        + b"".join(f + b"\r\n" for f in fields)
        + b"\r\n"
    )
    return HTTP(head=head, raw_body=body)


@st.composite
def http_context_responses(draw: st.DrawFn) -> HTTP:
    """A response whose framing depends on the request it answers: a
    HEAD response, or a 2xx to CONNECT. Either has no body whatever its
    Content-Length or Transfer-Encoding says, so it only round-trips
    when decoded with the same ``request_method``."""
    method = draw(st.sampled_from(["HEAD", "CONNECT"]))
    statuses = (
        [b"200", b"301", b"404"] if method == "HEAD" else [b"200", b"201"]
    )
    start = b"HTTP/1.1 " + draw(st.sampled_from(statuses)) + b" X"
    fields = draw(
        st.lists(
            st.sampled_from(
                [
                    b"Content-Length: 42",
                    b"Transfer-Encoding: chunked",
                    b"Connection: keep-alive",
                    b"X: y",
                ]
            ),
            max_size=3,
        )
    )
    head = start + b"\r\n" + b"".join(f + b"\r\n" for f in fields) + b"\r\n"
    return HTTP(head=head, request_method=method)


@st.composite
def http_wire(draw: st.DrawFn) -> bytes:
    """The bytes of a valid message, then a few byte-level mutations and
    possibly a truncation: input near the grammar's edges, which random
    bytes almost never reach."""
    raw = bytearray(bytes(draw(http_messages())))
    for _ in range(draw(st.integers(min_value=0, max_value=4))):
        position = draw(st.integers(min_value=0, max_value=len(raw) - 1))
        raw[position] = draw(st.sampled_from(b"\r\n :;,0aZ\x00\t\xff"))
    cut = draw(st.integers(min_value=0, max_value=len(raw)))
    return bytes(raw[:cut]) if draw(st.booleans()) else bytes(raw)


@st.composite
def rip_messages(draw: st.DrawFn) -> RIP:
    # The body is kept raw whatever it holds, so it is drawn as free
    # bytes, any length: whole entries, a trailer, a remainder. decode()
    # rejects a version other than 1 or 2 and command 0 (the
    # constructor does not; test_rip.py covers those).
    return RIP(
        command=draw(st.integers(1, 0xFF)),
        version=draw(st.sampled_from([1, 2])),
        reserved=draw(st.integers(0, 0xFFFF)),
        body=draw(st.binary(max_size=_MAX_BLOB * 2)),
    )


#: A TFTP string: any bytes but the zero byte that terminates it.
_tftp_strings = st.binary(max_size=_MAX_BLOB).map(
    lambda raw: raw.replace(b"\x00", b"")
)


@st.composite
def _tftp_options(draw: st.DrawFn) -> bytes:
    """RFC 2347 option pairs: a name of at least one byte, a value."""
    pairs = draw(
        st.lists(
            st.tuples(_tftp_strings.filter(bool), _tftp_strings), max_size=4
        )
    )
    return b"".join(name + b"\x00" + value + b"\x00" for name, value in pairs)


@st.composite
def tftp_messages(draw: st.DrawFn) -> TFTP:
    # A canonical message of each opcode decode accepts (1-6): its body
    # ends where decode ends it, so the round trip is exact. Messages
    # decode trims or rejects are built in test_tftp.py.
    opcode = draw(st.integers(1, 6))
    number = draw(st.integers(0, 0xFFFF)).to_bytes(2, "big")
    if opcode in (1, 2):
        body = (
            draw(_tftp_strings)
            + b"\x00"
            + draw(_tftp_strings)
            + b"\x00"
            + draw(_tftp_options())
        )
    elif opcode == 3:
        body = number + draw(st.binary(max_size=_MAX_BLOB * 2))
    elif opcode == 4:
        body = number
    elif opcode == 5:
        body = number + draw(_tftp_strings) + b"\x00"
    else:
        body = draw(_tftp_options())
    return TFTP(opcode=opcode, body=body)


@st.composite
def radius_packets(draw: st.DrawFn) -> RADIUS:
    # The attributes are kept raw whatever they hold, so they are drawn
    # as free bytes, any length; parsed_attributes, not decode(), walks
    # them. Any code decodes, and the Length is the one value the
    # constructor accepts.
    attributes = draw(st.binary(max_size=_MAX_BLOB * 2))
    return RADIUS(
        code=draw(st.integers(0, 0xFF)),
        identifier=draw(st.integers(0, 0xFF)),
        length=20 + len(attributes),
        authenticator=draw(st.binary(min_size=16, max_size=16)),
        attributes=attributes,
    )


@st.composite
def stun_messages(draw: st.DrawFn) -> STUN:
    # Canonical messages only: the magic cookie, and attributes whose
    # bytes are a multiple of 4, which decode() requires (the
    # constructor does not; test_stun.py covers those). Built from
    # attributes, so the walk usually succeeds, or else free bytes.
    attributes = draw(
        st.one_of(
            st.lists(
                st.builds(
                    STUNAttribute,
                    st.integers(0, 0xFFFF),
                    st.binary(max_size=_MAX_BLOB),
                ),
                max_size=4,
            ).map(lambda found: b"".join(map(bytes, found))),
            st.binary(max_size=_MAX_BLOB).map(
                lambda raw: raw[: len(raw) - len(raw) % 4]
            ),
        )
    )
    return STUN(
        message_type=draw(st.integers(0, 0x3FFF)),
        transaction_id=draw(st.binary(min_size=12, max_size=12)),
        attributes=attributes,
    )


@st.composite
def pim_family_addresses(draw: st.DrawFn) -> tuple[int, str]:
    """A PIM address family and an address of it (RFC 7761 §4.9.1)."""
    if draw(st.booleans()):
        return 1, draw(ipv4_strings())
    return 2, draw(ipv6_strings())


@st.composite
def pim_encoded_unicasts(draw: st.DrawFn) -> PIMEncodedUnicast:
    family, address = draw(pim_family_addresses())
    return PIMEncodedUnicast(family, 0, address)


@st.composite
def pim_encoded_groups(draw: st.DrawFn) -> PIMEncodedGroup:
    family, address = draw(pim_family_addresses())
    return PIMEncodedGroup(
        family,
        0,
        draw(st.integers(0, 0xFF)),
        draw(st.integers(0, 0xFF)),
        address,
    )


@st.composite
def pim_encoded_sources(draw: st.DrawFn) -> PIMEncodedSource:
    family, address = draw(pim_family_addresses())
    return PIMEncodedSource(
        family,
        0,
        draw(st.integers(0, 0xFF)),
        draw(st.integers(0, 0xFF)),
        address,
    )


@st.composite
def pim_hello_options(draw: st.DrawFn) -> PIMHelloOption:
    # Type 0 is left out: an empty option of type 0 ending the message
    # is all zero bytes, which decode() takes for padding.
    return PIMHelloOption(
        draw(st.integers(1, 0xFFFF)), draw(st.binary(max_size=_MAX_BLOB))
    )


@st.composite
def pim_join_prunes(draw: st.DrawFn) -> PIMJoinPrune:
    sources = st.lists(pim_encoded_sources(), max_size=3).map(tuple)
    groups = st.builds(PIMGroupSet, pim_encoded_groups(), sources, sources)
    return PIMJoinPrune(
        draw(pim_encoded_unicasts()),
        draw(st.integers(0, 0xFFFF)),
        tuple(draw(st.lists(groups, max_size=3))),
        draw(st.integers(0, 0xFF)),
    )


#: The PIM message types with a typed message, and the strategy for
#: one; any other type keeps its body raw.
_PIM_MESSAGES: dict[int, st.SearchStrategy[object]] = {
    0: st.lists(pim_hello_options(), max_size=4).map(
        lambda options: PIMHello(tuple(options))
    ),
    1: st.builds(
        PIMRegister,
        st.booleans(),
        st.booleans(),
        st.integers(0, 0x3FFFFFFF),
        st.binary(max_size=_MAX_BLOB),
    ),
    2: st.builds(PIMRegisterStop, pim_encoded_groups(), pim_encoded_unicasts()),
    3: pim_join_prunes(),
    5: st.builds(
        PIMAssert,
        pim_encoded_groups(),
        pim_encoded_unicasts(),
        st.booleans(),
        st.integers(0, 0x7FFFFFFF),
        st.integers(0, 0xFFFFFFFF),
    ),
    6: pim_join_prunes(),
    7: pim_join_prunes(),
}


@st.composite
def pim_headers(draw: st.DrawFn) -> PIM:
    # A typed message's body is built from the message, so it ends where
    # its own structure does; decode() leaves anything past that, and a
    # Hello's zero tail, undecoded, so free bytes would not round-trip.
    type_ = draw(st.integers(0, 0x0F))
    strategy = _PIM_MESSAGES.get(type_)
    if strategy is None:
        body = draw(st.binary(max_size=_MAX_BLOB))
    else:
        body = bytes(draw(strategy))  # type: ignore[call-overload]
    return PIM(
        type=type_,
        reserved=draw(st.integers(0, 0xFF)),
        checksum=draw(st.integers(0, 0xFFFF)),
        body=body,
    )


@st.composite
def ntp_messages(draw: st.DrawFn) -> NTP:
    # The body is kept raw whatever it holds, so it is drawn as free
    # bytes: extension fields, a MAC, a remainder. decode() rejects a
    # version outside 1-4 and modes 6 and 7 (the constructor does not;
    # test_ntp.py covers those).
    return NTP(
        leap=draw(st.integers(0, 3)),
        version=draw(st.integers(1, 4)),
        mode=draw(st.integers(0, 5)),
        stratum=draw(st.integers(0, 0xFF)),
        poll=draw(st.integers(-128, 127)),
        precision=draw(st.integers(-128, 127)),
        root_delay=draw(st.integers(0, 0xFFFFFFFF)),
        root_dispersion=draw(st.integers(0, 0xFFFFFFFF)),
        reference_id=draw(st.integers(0, 0xFFFFFFFF)),
        reference_timestamp=draw(st.integers(0, (1 << 64) - 1)),
        origin_timestamp=draw(st.integers(0, (1 << 64) - 1)),
        receive_timestamp=draw(st.integers(0, (1 << 64) - 1)),
        transmit_timestamp=draw(st.integers(0, (1 << 64) - 1)),
        body=draw(st.binary(max_size=_MAX_BLOB * 2)),
    )


@st.composite
def hsrp_messages(draw: st.DrawFn) -> HSRP:
    # Every field is a whole byte, so any value of each is canonical
    # but the three decode() judges: Version 0, an Op Code of 0-2 and
    # one of RFC 2281's six States (the constructor accepts others;
    # test_hsrp.py covers those). The Authentication Data is any 8
    # bytes, not only a password.
    return HSRP(
        version=0,
        opcode=draw(st.integers(0, 2)),
        state=draw(st.sampled_from([0, 1, 2, 4, 8, 16])),
        hellotime=draw(st.integers(0, 0xFF)),
        holdtime=draw(st.integers(0, 0xFF)),
        priority=draw(st.integers(0, 0xFF)),
        group=draw(st.integers(0, 0xFF)),
        reserved=draw(st.integers(0, 0xFF)),
        auth_data=draw(st.binary(min_size=8, max_size=8)),
        virtual_ip=draw(ipv4_strings()),
    )


@st.composite
def tls_extensions(draw: st.DrawFn) -> TLSExtension:
    # Any type, any data: only server_name's data is ever parsed, and
    # its parse is on demand, so a malformed one still round-trips.
    return TLSExtension(
        type=draw(st.integers(0, 0xFFFF)),
        data=draw(st.binary(max_size=_MAX_BLOB)),
    )


@st.composite
def tls_client_hellos(draw: st.DrawFn) -> TLSClientHello:
    # Every field within the length its prefix can carry, and the
    # extensions block present, empty or absent (None, RFC 5246's hello
    # without extensions): canonical for the parse in TLS.client_hello.
    extensions = draw(
        st.one_of(
            st.none(),
            st.lists(tls_extensions(), max_size=4).map(tuple),
        )
    )
    return TLSClientHello(
        legacy_version=draw(st.sampled_from([0x0300, 0x0301, 0x0303])),
        random=draw(st.binary(min_size=32, max_size=32)),
        legacy_session_id=draw(st.binary(max_size=32)),
        cipher_suites=draw(st.binary(max_size=_MAX_BLOB)),
        legacy_compression_methods=draw(st.binary(min_size=1, max_size=4)),
        extensions=extensions,
    )


@st.composite
def tls_records(draw: st.DrawFn) -> TLS:
    # Canonical records only: a ContentType of 20-24 and a version of
    # 0x0300-0x0304, which decode() requires (the constructor does not;
    # test_tls.py covers those). The fragment is opaque bytes, or now
    # and then a ClientHello, so the round trip covers records whose
    # accessors parse and records whose accessors raise.
    hello = draw(st.one_of(st.none(), tls_client_hellos()))
    if hello is None:
        content_type = draw(st.integers(20, 24))
        fragment = draw(st.binary(max_size=_MAX_BLOB))
    else:
        body = bytes(hello)
        content_type = 22
        fragment = b"\x01" + len(body).to_bytes(3, "big") + body
    return TLS(
        content_type=content_type,
        legacy_version=draw(st.integers(0x0300, 0x0304)),
        length=len(fragment),
        fragment=fragment,
    )


#: One entry per protocol without an existing Hypothesis-generated
#: round-trip test (see test_fuzz.py::TestConstrainedRoundTrips for
#: the other four: Ethernet, UDP, TCP, IPv6Fragment). Keyed by class
#: name for readable parametrize IDs.
ROUND_TRIP_STRATEGIES: Mapping[str, st.SearchStrategy[Protocol]] = {
    "ARP": arp_headers(),
    "VLAN": vlan_headers(),
    "LLC": llc_headers(),
    "SNAP": snap_headers(),
    "LLDP": lldp_lldpdus(),
    "MPLS": mpls_stacks(),
    "STP": stp_headers(),
    "CDP": cdp_pdus(),
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
    "SCTP": sctp_headers(),
    "PIM": pim_headers(),
    "ESP": esp_packets(),
    "AH": ah_headers(AH),
    "AHv6": ah_headers(AHv6),
    "VRRP": vrrp_headers(VRRP),
    "VRRPv6": vrrp_headers(VRRPv6),
    "HTTP": http_messages(),
    "VXLAN": vxlan_headers(),
    "OSPF": ospf_packets(),
    "RIP": rip_messages(),
    "TFTP": tftp_messages(),
    "RADIUS": radius_packets(),
    "STUN": stun_messages(),
    "NTP": ntp_messages(),
    "HSRP": hsrp_messages(),
    "TLS": tls_records(),
    "BGP": bgp_messages(),
}
