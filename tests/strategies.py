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
    DHCP,
    DNS,
    ESP,
    GRE,
    HTTP,
    IGMP,
    LLDP,
    LLDPTLV,
    OSPF,
    OSPFLSA,
    PIM,
    RIP,
    SCTP,
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


#: One entry per protocol without an existing Hypothesis-generated
#: round-trip test (see test_fuzz.py::TestConstrainedRoundTrips for
#: the other four: Ethernet, UDP, TCP, IPv6Fragment). Keyed by class
#: name for readable parametrize IDs.
ROUND_TRIP_STRATEGIES: Mapping[str, st.SearchStrategy[Protocol]] = {
    "ARP": arp_headers(),
    "VLAN": vlan_headers(),
    "LLDP": lldp_lldpdus(),
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
    "BGP": bgp_messages(),
}
