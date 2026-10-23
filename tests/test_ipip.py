"""IP-in-IP: IP protocol 4 (RFC 2003; IPv4 in IPv6, RFC 2473) and 41
(6in4, RFC 4213; IPv6 in IPv6, RFC 2473) dispatch straight from the
outer IP header to the inner one. There is no tunnel header to decode,
so what is tested here is the wiring, the walk through it, and that the
walk stays bounded when a hostile frame nests it."""

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    Ethernet,
    ICMPv4,
    ICMPv6,
    IPProtocol,
    IPv4,
    IPv6,
    MaxDepthExceededError,
    Packet,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_IP_PROTO, TABLE_IP_PROTO_V6

PAYLOAD = b"NETProtocols IP-in-IP test"


def make_ipv4(
    *, protocol: int, payload_len: int, fragment_offset: int = 0
) -> IPv4:
    return IPv4(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=20 + payload_len,
        identification=0,
        flags=0,
        fragment_offset=fragment_offset,
        ttl=64,
        protocol=protocol,
        checksum=0,
        src="192.0.2.1",
        dst="192.0.2.2",
    )


def make_ipv6(*, next_header: int, payload_len: int) -> IPv6:
    return IPv6(
        version=6,
        traffic_class=0,
        flow_label=0,
        payload_length=payload_len,
        next_header=next_header,
        hop_limit=64,
        src="2001:db8::1",
        dst="2001:db8::2",
    )


# An echo's identifier and sequence number ride in ``rest``; its data is
# the ICMP layer's own ``body``, so the walk consumes the whole frame.
ECHO_REST = b"\x4e\x50\x00\x01"


def echo_v4() -> ICMPv4:
    return ICMPv4(type=8, code=0, checksum=0, rest=ECHO_REST, body=PAYLOAD)


def echo_v6() -> ICMPv6:
    return ICMPv6(type=128, code=0, checksum=0, rest=ECHO_REST, body=PAYLOAD)


def ethernet(ethertype: int) -> Ethernet:
    return Ethernet(
        dst="02:00:00:00:00:02", src="02:00:00:00:00:01", ethertype=ethertype
    )


def tunnelled(outer: str, inner: str) -> bytes:
    """An ``Ethernet → outer IP → inner IP → ICMP echo`` frame, every
    checksum computed, for each of the four outer/inner families."""
    icmp_len = 8 + len(PAYLOAD)
    if inner == "ipv4":
        inner_ip: IPv4 | IPv6 = make_ipv4(protocol=1, payload_len=icmp_len)
        icmp: ICMPv4 | ICMPv6 = echo_v4()
        protocol = IPProtocol.IPIP
    else:
        inner_ip = make_ipv6(next_header=58, payload_len=icmp_len)
        icmp = echo_v6()
        protocol = IPProtocol.IPV6
    inner_len = inner_ip.header_len + icmp_len
    if outer == "ipv4":
        outer_ip: IPv4 | IPv6 = make_ipv4(
            protocol=protocol, payload_len=inner_len
        )
        eth = ethernet(0x0800)
    else:
        outer_ip = make_ipv6(next_header=protocol, payload_len=inner_len)
        eth = ethernet(0x86DD)
    return bytes(Packet(eth, outer_ip, inner_ip, icmp).with_checksums())


COMBINATIONS = [
    ("ipv4", "ipv4", IPv4, IPv4, ICMPv4),
    ("ipv4", "ipv6", IPv4, IPv6, ICMPv6),
    ("ipv6", "ipv4", IPv6, IPv4, ICMPv4),
    ("ipv6", "ipv6", IPv6, IPv6, ICMPv6),
]
COMBINATION_IDS = ["4in4", "6in4", "4in6", "6in6"]


class TestWiring:
    def test_protocol_numbers_and_display_names(self):
        assert IPProtocol.IPIP == 4
        assert IPProtocol.IPV6 == 41
        assert IPProtocol.IPIP.display_name == "IPv4 encapsulation"
        assert IPProtocol.IPV6.display_name == "IPv6 encapsulation"

    @pytest.mark.parametrize("table", [TABLE_IP_PROTO, TABLE_IP_PROTO_V6])
    def test_both_ip_tables_carry_both_numbers(self, table):
        # Registered in ip.proto, so ip.proto.v6 inherits them: IPv6
        # carries either family (RFC 2473) as readily as IPv4 does.
        assert DEFAULT.get(table, 4) is IPv4
        assert DEFAULT.get(table, 41) is IPv6

    @pytest.mark.parametrize(
        "protocol,inner", [(4, IPv4), (41, IPv6)], ids=["ipip", "6in4"]
    )
    def test_ipv4_dispatches_to_the_inner_header(self, protocol, inner):
        outer = make_ipv4(protocol=protocol, payload_len=40)
        assert outer.next_protocol() is inner
        assert outer.protocol_enum is IPProtocol(protocol)

    @pytest.mark.parametrize(
        "next_header,inner", [(4, IPv4), (41, IPv6)], ids=["4in6", "6in6"]
    )
    def test_ipv6_dispatches_to_the_inner_header(self, next_header, inner):
        outer = make_ipv6(next_header=next_header, payload_len=40)
        assert outer.next_protocol() is inner

    def test_a_non_first_fragment_carries_no_inner_header(self):
        # The general fragment rule, applied to a tunnel: the slice at a
        # non-zero offset is the middle of the inner packet, not its
        # start, so there is nothing to dispatch to.
        outer = make_ipv4(protocol=4, payload_len=40, fragment_offset=8)
        assert outer.next_protocol() is None


class TestWalk:
    @pytest.mark.parametrize(
        "outer,inner,outer_type,inner_type,icmp_type",
        COMBINATIONS,
        ids=COMBINATION_IDS,
    )
    def test_every_combination_walks_to_the_inner_transport(
        self, outer, inner, outer_type, inner_type, icmp_type
    ):
        frame = tunnelled(outer, inner)
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet.layers] == [
            Ethernet,
            outer_type,
            inner_type,
            icmp_type,
        ]
        assert packet.consumed == len(frame)
        assert packet[icmp_type].body == PAYLOAD

    @pytest.mark.parametrize(
        "outer,inner", [c[:2] for c in COMBINATIONS], ids=COMBINATION_IDS
    )
    def test_every_layer_round_trips_byte_exactly(self, outer, inner):
        frame = tunnelled(outer, inner)
        cursor = 0
        for layer in decode_frame(frame).layers:
            assert bytes(layer) == frame[cursor : cursor + layer.header_len]
            cursor += layer.header_len

    def test_a_truncated_inner_header_is_reported_at_its_offset(self):
        frame = tunnelled("ipv4", "ipv4")[: 14 + 20 + 10]
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(frame)
        assert caught.value.protocol is IPv4
        assert caught.value.frame_offset == 14 + 20

    def test_lax_mode_keeps_the_outer_header(self):
        frame = tunnelled("ipv4", "ipv6")[: 14 + 20 + 10]
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet.layers] == [Ethernet, IPv4]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)


class TestHostileNesting:
    """IPv4-in-IPv4 can nest without limit on the wire, each level 20
    bytes, so a hostile frame is a long run of protocol-4 headers. The
    walk's depth ceiling, not the buffer, has to be what stops it."""

    @staticmethod
    def nested(levels: int) -> bytes:
        frame = bytes(make_ipv4(protocol=253, payload_len=0))
        for _ in range(levels):
            frame = bytes(make_ipv4(protocol=4, payload_len=len(frame))) + frame
        return frame

    def test_deep_nesting_hits_the_depth_ceiling(self):
        with pytest.raises(MaxDepthExceededError):
            decode_frame(self.nested(64), start=IPv4)

    def test_nesting_within_the_ceiling_decodes(self):
        packet = decode_frame(self.nested(64), start=IPv4, max_depth=65)
        assert len(packet) == 65
        assert all(isinstance(layer, IPv4) for layer in packet.layers)


class TestCorpusIPIP:
    FRAMES = pcap_frames(FIXTURES / "ipip.pcap")

    def test_captured_frames_are_ip_in_ip(self):
        chains = [
            [type(layer) for layer in decode_frame(frame).layers]
            for frame in self.FRAMES
        ]
        assert chains == [
            [Ethernet, IPv4, IPv4, ICMPv4],
            [Ethernet, IPv4, IPv4, ICMPv4],
            [Ethernet, IPv4, IPv6, ICMPv6],
            [Ethernet, IPv4, IPv6, ICMPv6],
        ]

    def test_the_tunnel_and_the_inner_packet_are_different_networks(self):
        for frame in self.FRAMES:
            outer, inner = decode_frame(frame).layers[1:3]
            assert isinstance(outer, IPv4)
            assert (outer.src, outer.dst) == ("10.9.9.1", "10.9.9.2")
            assert isinstance(inner, (IPv4, IPv6))
            assert inner.src in ("192.0.2.1", "2001:db8::1")
            assert inner.dst in ("192.0.2.2", "2001:db8::2")

    def test_the_kernel_built_outer_headers_name_the_inner_family(self):
        protocols = [decode_frame(f).layers[1].protocol for f in self.FRAMES]
        assert protocols == [4, 4, 41, 41]

    def test_recomputed_checksums_match_the_wire(self):
        # The inner checksums were verified by check_fixtures.py, which
        # shares no code with this library. with_checksums() must reach
        # the same values, which it only does if each transport keys on
        # the IP header nearest before it rather than the outer one.
        for frame in self.FRAMES:
            packet = decode_frame(frame)
            assert packet.with_checksums() == packet
