"""#236: flow keys and the final-destination rules behind an IPv6
Routing header (RFC 8200 §8.1).

The checksum tests for the same change live in tests/test_checksum.py,
which is the file the mutation audit runs; the frame builders and the
independent reference checksum are theirs, imported here.
"""

import pytest

from netprotocols import (
    UDP,
    FlowKey,
    IPv4,
    IPv6,
    IPv6Routing,
    Packet,
    decode_frame,
    flow_key,
)
from netprotocols.layer3.ipv6_ext import _effective_destination
from test_checksum import (
    ROUTE_IDS,
    ROUTES,
    RT_FINAL,
    RT_NEXT_HOP,
    RT_SRC,
    build_frame,
    pton,
    routing_srh,
    routing_type0,
    routing_type2,
)

SRC, NEXT_HOP, FINAL = RT_SRC, RT_NEXT_HOP, RT_FINAL


@pytest.mark.parametrize(
    ("name", "routing", "wire_dst", "final"), ROUTES, ids=ROUTE_IDS
)
class TestFlowKeyBehindRouting:
    def test_flow_key_uses_the_final_destination(
        self, name, routing, wire_dst, final
    ):
        frame = build_frame(routing, wire_dst, final)
        p = decode_frame(frame, start=IPv6)
        lo, hi = sorted([(SRC, 1000), (final, 2000)])
        expected = FlowKey(lo[0], hi[0], lo[1], hi[1], 17)
        assert p.flow_key() == expected
        assert flow_key(p[UDP], ip=p[IPv6], routing=p[IPv6Routing]) == expected
        # The old behaviour keyed on the next hop.
        assert flow_key(p[UDP], ip=p[IPv6]) != expected

    def test_reply_has_the_same_key(self, name, routing, wire_dst, final):
        p = decode_frame(build_frame(routing, wire_dst, final), start=IPv6)
        reply_ip = IPv6(
            version=6,
            traffic_class=0,
            flow_label=0,
            payload_length=8,
            next_header=17,
            hop_limit=64,
            src=final,
            dst=SRC,
        )
        reply_udp = UDP(src_port=2000, dst_port=1000, length=8, checksum=0)
        reply = Packet(reply_ip, reply_udp)
        assert reply.flow_key() == p.flow_key()


class TestFlowKeyFallsBackToIpDst:
    def test_segments_left_zero_uses_ip_dst(self):
        for routing in (
            routing_srh(["2001:db8::77", FINAL], 0),
            routing_type0(["2001:db8::77"], 0),
            routing_type2("2001:db8::77"),
        ):
            routing = routing[:3] + b"\x00" + routing[4:]
            p = decode_frame(build_frame(routing, FINAL, FINAL), start=IPv6)
            expected = flow_key(p[UDP], ip=p[IPv6])
            header = p[IPv6Routing]
            assert flow_key(p[UDP], ip=p[IPv6], routing=header) == expected
            assert p.flow_key() == expected

    def test_unknown_routing_type(self):
        routing = bytes([17, 1, 253, 1]) + bytes(12)
        p = decode_frame(build_frame(routing, NEXT_HOP, NEXT_HOP), start=IPv6)
        assert p.flow_key() == flow_key(p[UDP], ip=p[IPv6])

    def test_ipv4_ignores_routing(self):
        ip = IPv4(
            version=4, ihl=5, dscp=0, ecn=0, total_length=30, identification=0,
            flags=0, fragment_offset=0, ttl=64, protocol=17, checksum=0,
            src="10.0.0.1", dst="10.0.0.2",
        )  # fmt: skip
        routing = IPv6Routing.decode(routing_srh([FINAL, NEXT_HOP], 1))
        assert _effective_destination(ip, routing) == "10.0.0.2"


class TestFinalDestinationRules:
    @staticmethod
    def make(routing_type: int, data: bytes) -> IPv6Routing:
        assert len(data) % 8 == 4
        return IPv6Routing(
            next_header=17,
            hdr_ext_len=(len(data) - 4) // 8,
            routing_type=routing_type,
            segments_left=1,
            data=data,
        )

    def test_type0_last_not_first(self):
        data = bytes(4) + pton("2001:db8::a") + pton("2001:db8::b")
        assert self.make(0, data).final_destination(SRC) == "2001:db8::b"

    def test_type0_empty_list(self):
        assert self.make(0, bytes(4)).final_destination(SRC) is None

    def test_type2_needs_exactly_one(self):
        two = bytes(4) + pton("2001:db8::a") + pton("2001:db8::b")
        assert self.make(2, two).final_destination(SRC) is None
        assert self.make(2, bytes(4)).final_destination(SRC) is None
        one = bytes(4) + pton("2001:db8::a")
        assert self.make(2, one).final_destination(SRC) == "2001:db8::a"

    def test_type3_rebuilds_from_dst_prefix(self):
        # CmprI 0, CmprE 8: Address[1] whole, Address[2] 8 octets.
        data = (
            bytes([0x08, 0, 0, 0])
            + pton("2001:db8::1")
            + bytes([0, 0, 0, 0, 0, 0, 0, 0x99])
        )
        header = self.make(3, data)
        assert header.final_destination("2001:db8:1:2::5") == "2001:db8:1:2::99"

    def test_type3_pad_is_excluded(self):
        data = bytes([0xCC, 0x40, 0, 0]) + bytes([0, 0, 0, 0x99]) + bytes(4)
        header = self.make(3, data)
        assert header.final_destination("2001:db8::5") == "2001:db8::99"

    def test_type3_unresolvable(self):
        good = bytes([0xCC, 0x40, 0, 0]) + bytes([0, 0, 0, 0x99]) + bytes(4)
        assert self.make(3, good).final_destination("nonsense") is None
        # Pad longer than the whole address area.
        big_pad = bytes([0x00, 0xF0, 0, 0]) + bytes(8)
        assert self.make(3, big_pad).final_destination(SRC) is None
        # Two octets before the last entry, but Address[1..n-1] take 4.
        odd = bytes([0xCC, 0x20, 0, 0]) + bytes(2) + bytes([0, 0, 0, 0x99])
        assert self.make(3, odd + bytes(2)).final_destination(SRC) is None

    def test_type3_whole_last_entry(self):
        whole = bytes(4) + pton("2001:db8::99")
        assert self.make(3, whole).final_destination(SRC) == "2001:db8::99"
        # 8 octets before a 16-octet last entry: not a whole Address[1].
        assert self.make(3, whole + bytes(8)).final_destination(SRC) is None

    def test_type4_segment_list_zero(self):
        segments = ("2001:db8::a", "2001:db8::b", "2001:db8::c")
        data = bytes([2, 0, 0, 0]) + b"".join(pton(a) for a in segments)
        assert self.make(4, data).final_destination(SRC) == "2001:db8::a"

    def test_type4_ignores_tlvs_after_the_list(self):
        data = bytes([0, 0, 0, 0]) + pton("2001:db8::a") + bytes(8)
        assert self.make(4, data).final_destination(SRC) == "2001:db8::a"

    def test_type4_last_entry_beyond_data(self):
        data = bytes([1, 0, 0, 0]) + pton("2001:db8::a")
        assert self.make(4, data).final_destination(SRC) is None

    def test_type4_too_short_for_one_segment(self):
        assert self.make(4, bytes(12)).final_destination(SRC) is None

    def test_other_types(self):
        for routing_type in (1, 5, 253):
            data = bytes(4) + pton("2001:db8::a")
            assert self.make(routing_type, data).final_destination(SRC) is None


class TestFlowKeyWhichHeader:
    def _ip(self, dst: str) -> IPv6:
        return IPv6(
            version=6, traffic_class=0, flow_label=0, payload_length=0,
            next_header=43, hop_limit=64, src=SRC, dst=dst,
        )  # fmt: skip

    def test_outer_tunnel_routing_is_not_between(self):
        outer_routing = IPv6Routing.decode(
            routing_srh(["2001:db8::77", NEXT_HOP], 1)
        )
        inner = self._ip("2001:db8::abcd")
        udp = UDP(src_port=1000, dst_port=2000, length=10, checksum=0)
        packet = Packet(self._ip(NEXT_HOP), outer_routing, inner, udp)
        key = packet.flow_key()
        assert key is not None
        assert "2001:db8::abcd" in (key.addr_a, key.addr_b)

    def test_no_ip_before_transport(self):
        routing = IPv6Routing.decode(routing_srh([FINAL, NEXT_HOP], 1))
        udp = UDP(src_port=1000, dst_port=2000, length=10, checksum=0)
        assert Packet(routing, udp).flow_key() is None
