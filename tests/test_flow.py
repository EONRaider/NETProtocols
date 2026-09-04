import pytest

from netprotocols import (
    TCP,
    UDP,
    FlowKey,
    ICMPv4,
    InvalidFieldError,
    IPv4,
    IPv6,
    Packet,
    flow_key,
)


def make_ipv4(src: str, dst: str, protocol: int = 6) -> IPv4:
    return IPv4(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=40,
        identification=0,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=protocol,
        checksum=0,
        src=src,
        dst=dst,
    )


def make_ipv6(src: str, dst: str, next_header: int = 6) -> IPv6:
    return IPv6(
        version=6,
        traffic_class=0,
        flow_label=0,
        payload_length=20,
        next_header=next_header,
        hop_limit=64,
        src=src,
        dst=dst,
    )


def make_tcp(src_port: int, dst_port: int) -> TCP:
    return TCP(
        src_port=src_port,
        dst_port=dst_port,
        seq=0,
        ack=0,
        data_offset=5,
        reserved=0,
        flags=0,
        window=0,
        checksum=0,
        urgent_pointer=0,
    )


def make_udp(src_port: int, dst_port: int) -> UDP:
    return UDP(src_port=src_port, dst_port=dst_port, length=8, checksum=0)


class TestFlowKeyFunction:
    def test_both_directions_of_a_tcp_conversation_are_equal(self):
        """The core contract: request and reply key identically, and the
        two headers of each direction are constructed independently —
        never assembled into a Packet."""
        request_ip = make_ipv4("10.0.0.1", "10.0.0.2")
        request_tcp = make_tcp(12345, 80)
        reply_ip = make_ipv4("10.0.0.2", "10.0.0.1")
        reply_tcp = make_tcp(80, 12345)

        assert flow_key(request_tcp, ip=request_ip) == flow_key(
            reply_tcp, ip=reply_ip
        )

    def test_canonical_form_orders_the_smaller_address_first(self):
        ip = make_ipv4("10.0.0.1", "10.0.0.2")
        tcp = make_tcp(12345, 80)
        assert flow_key(tcp, ip=ip) == FlowKey(
            "10.0.0.1", "10.0.0.2", 12345, 80, 6
        )

    def test_ipv6_works(self):
        request_ip = make_ipv6("fe80::1", "fe80::2")
        request_tcp = make_tcp(443, 51000)
        reply_ip = make_ipv6("fe80::2", "fe80::1")
        reply_tcp = make_tcp(51000, 443)

        key = flow_key(request_tcp, ip=request_ip)
        assert key == flow_key(reply_tcp, ip=reply_ip)
        assert key.protocol == 6

    def test_udp_works(self):
        request_ip = make_ipv4("10.0.0.1", "10.0.0.2")
        request_udp = make_udp(53000, 53)
        reply_ip = make_ipv4("10.0.0.2", "10.0.0.1")
        reply_udp = make_udp(53, 53000)

        assert flow_key(request_udp, ip=request_ip) == flow_key(
            reply_udp, ip=reply_ip
        )

    def test_ipv4_protocol_and_ipv6_next_header_both_feed_protocol(self):
        """IPv4.protocol and IPv6.next_header are the same semantic
        field under different attribute names; flow_key must read
        whichever one the enclosing header actually has."""
        v4_key = flow_key(make_tcp(1, 2), ip=make_ipv4("1.1.1.1", "2.2.2.2"))
        v6_key = flow_key(make_tcp(1, 2), ip=make_ipv6("fe80::1", "fe80::2"))
        assert v4_key.protocol == 6
        assert v6_key.protocol == 6

    def test_non_tcp_udp_transport_returns_none(self):
        """ICMP (or anything else without ports) has no flow to key on:
        None, not an exception, and no invented port-slot convention."""
        icmp = ICMPv4(type=8, code=0, checksum=0, rest=b"\x00" * 4)
        assert flow_key(icmp) is None
        assert flow_key(icmp, ip=make_ipv4("1.1.1.1", "2.2.2.2")) is None

    def test_missing_ip_raises_for_a_transport_layer_that_needs_it(self):
        with pytest.raises(InvalidFieldError):
            flow_key(make_tcp(1, 2))

    def test_flow_key_is_hashable_and_usable_as_dict_key(self):
        key = flow_key(make_tcp(1, 2), ip=make_ipv4("1.1.1.1", "2.2.2.2"))
        mapping = {key: "value"}
        assert mapping[key] == "value"


class TestPacketFlowKey:
    def test_matches_the_free_function(self):
        ip = make_ipv4("10.0.0.1", "10.0.0.2")
        tcp = make_tcp(12345, 80)
        packet = Packet(ip, tcp)
        assert packet.flow_key() == flow_key(tcp, ip=ip)

    def test_opposite_directions_produce_the_same_key(self):
        request = Packet(make_ipv4("10.0.0.1", "10.0.0.2"), make_tcp(12345, 80))
        reply = Packet(make_ipv4("10.0.0.2", "10.0.0.1"), make_tcp(80, 12345))
        assert request.flow_key() == reply.flow_key()

    def test_finds_layers_regardless_of_what_encloses_them(self):
        """Walks the whole stack, so a leading Ethernet layer (or any
        other layer that isn't IP/TCP/UDP) doesn't confuse it."""
        from netprotocols import Ethernet

        eth = Ethernet(
            dst="ff:ff:ff:ff:ff:ff",
            src="00:11:22:33:44:55",
            ethertype=0x0800,
        )
        ip = make_ipv4("10.0.0.1", "10.0.0.2")
        tcp = make_tcp(12345, 80)
        packet = Packet(eth, ip, tcp)
        assert packet.flow_key() == flow_key(tcp, ip=ip)

    def test_missing_transport_layer_returns_none(self):
        packet = Packet(make_ipv4("10.0.0.1", "10.0.0.2"))
        assert packet.flow_key() is None

    def test_missing_ip_layer_returns_none(self):
        packet = Packet(make_tcp(1, 2))
        assert packet.flow_key() is None

    def test_icmp_packet_returns_none(self):
        icmp = ICMPv4(type=8, code=0, checksum=0, rest=b"\x00" * 4)
        packet = Packet(make_ipv4("10.0.0.1", "10.0.0.2"), icmp)
        assert packet.flow_key() is None

    def test_empty_packet_returns_none(self):
        assert Packet().flow_key() is None
