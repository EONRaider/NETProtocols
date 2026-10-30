"""#236: transport checksums and flow keys use the final destination
behind an IPv6 Routing header (RFC 8200 §8.1).

Every expected checksum here is computed by :func:`ref_checksum`, a
stdlib-only ones'-complement sum written in this file from RFC 8200
§8.1 and RFC 1071, sharing no code with ``netprotocols.checksum``.
:data:`ISSUE_FRAME` is the issue's reproduction frame, whose wire
checksum (0x2fad) was computed the same independent way before the
fix existed.
"""

import socket
import struct
from dataclasses import replace
from ipaddress import IPv6Address

import pytest

from netprotocols import (
    UDP,
    FlowKey,
    InvalidFieldError,
    IPv4,
    IPv6,
    IPv6Routing,
    Packet,
    checksum,
    decode_frame,
    flow_key,
)
from netprotocols.layer3.ipv6_ext import effective_destination

SRC = "2001:db8::1"
NEXT_HOP = "2001:db8::2"
FINAL = "2001:db8::99"

ISSUE_FRAME = bytes.fromhex(
    "6000000000322b4020010db800000000000000000000000120010db800000000"
    "0000000000000002110404010100000020010db8000000000000000000000099"
    "20010db800000000000000000000000203e807d0000a2fad6869"
)


def pton(address: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, address)


def ref_checksum(src: str, dst: str, udp: bytes, payload: bytes) -> int:
    """RFC 8200 §8.1 + RFC 768 + RFC 1071, from scratch: ``udp`` is the
    8-byte UDP header with its checksum field zeroed."""
    length = len(udp) + len(payload)
    data = (
        pton(src)
        + pton(dst)
        + struct.pack("!IBBBB", length, 0, 0, 0, 17)
        + udp
        + payload
    )
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total & 0xFFFF) or 0xFFFF


def udp_header(checksum_value: int = 0, payload: bytes = b"hi") -> bytes:
    return struct.pack("!HHHH", 1000, 2000, 8 + len(payload), checksum_value)


def routing_type0(addresses: list[str], segments_left: int) -> bytes:
    body = b"\x00" * 4 + b"".join(pton(a) for a in addresses)
    return bytes([17, len(addresses) * 2, 0, segments_left]) + body


def routing_type2(home: str) -> bytes:
    return bytes([17, 2, 2, 1]) + b"\x00" * 4 + pton(home)


def routing_rpl(
    cmpr_i: int, cmpr_e: int, pad: int, entries: bytes, segments_left: int
) -> bytes:
    body = bytes([cmpr_i << 4 | cmpr_e, pad << 4, 0, 0]) + entries
    body += b"\x00" * pad
    assert len(body) % 8 == 4
    return bytes([17, (len(body) - 4) // 8, 3, segments_left]) + body


def routing_srh(segment_list: list[str], segments_left: int) -> bytes:
    body = bytes([len(segment_list) - 1, 0, 0, 0])
    body += b"".join(pton(a) for a in segment_list)
    assert len(body) % 8 == 4
    return bytes([17, (len(body) - 4) // 8, 4, segments_left]) + body


def build_frame(
    routing: bytes, wire_dst: str, checksum_dst: str, payload: bytes = b"hi"
) -> bytes:
    """IPv6 (dst ``wire_dst``) + ``routing`` + UDP 1000 -> 2000 whose
    checksum is the reference value for ``checksum_dst``."""
    value = ref_checksum(SRC, checksum_dst, udp_header(0, payload), payload)
    transport = udp_header(value, payload) + payload
    ip = (
        struct.pack("!IHBB", 0x60000000, len(routing) + len(transport), 43, 64)
        + pton(SRC)
        + pton(wire_dst)
    )
    return ip + routing + transport


def wire_checksum(frame: bytes) -> int:
    return int.from_bytes(frame[-4:-2], "big")


#: (id, routing header, ip.dst on the wire, the destination RFC 8200
#: §8.1 puts in the pseudo-header)
CASES = [
    (
        "type0",
        routing_type0(["2001:db8::50", NEXT_HOP, FINAL], 2),
        "2001:db8::50",
        FINAL,
    ),
    ("type2", routing_type2(FINAL), NEXT_HOP, FINAL),
    (
        # CmprI 0 (Address[1] whole), CmprE 8 (Address[2] its last 8
        # octets): the final address borrows dst's first 8 octets.
        "rpl-cmpr-i0-e8",
        routing_rpl(
            0,
            8,
            0,
            pton("2001:db8:0:0:0:0:0:50") + pton(FINAL)[8:],
            2,
        ),
        "2001:db8:0:0:0:0:0:5",
        "2001:db8::99",
    ),
    (
        # CmprI 12, CmprE 12: one 4-octet entry (the last) and 4 Pad
        # octets after it.
        "rpl-pad",
        routing_rpl(12, 12, 4, pton("2001:db8::99")[12:], 1),
        "2001:db8::5",
        "2001:db8::99",
    ),
    (
        "rpl-two-entries",
        routing_rpl(
            12, 12, 0, pton("2001:db8::50")[12:] + pton("2001:db8::99")[12:], 2
        ),
        "2001:db8::5",
        "2001:db8::99",
    ),
    (
        "srh",
        routing_srh([FINAL, "2001:db8::77", NEXT_HOP], 2),
        NEXT_HOP,
        FINAL,
    ),
    ("srh-one-hop", routing_srh([FINAL, NEXT_HOP], 1), NEXT_HOP, FINAL),
]
CASE_IDS = [case[0] for case in CASES]


class TestIssueFrame:
    def test_wire_checksum_verifies(self):
        p = decode_frame(ISSUE_FRAME, start=IPv6)
        assert wire_checksum(ISSUE_FRAME) == 0x2FAD
        assert p[UDP].checksum == 0x2FAD
        routing = p[IPv6Routing]
        assert checksum.verify(
            p[UDP], ip=p[IPv6], routing=routing, payload=b"hi"
        )
        assert (
            checksum.compute(p[UDP], ip=p[IPv6], routing=routing, payload=b"hi")
            == 0x2FAD
        )

    def test_without_routing_it_is_the_old_value(self):
        p = decode_frame(ISSUE_FRAME, start=IPv6)
        assert checksum.compute(p[UDP], ip=p[IPv6], payload=b"hi") == 0x3044
        assert not checksum.verify(p[UDP], ip=p[IPv6], payload=b"hi")

    def test_reference_agrees_with_the_issue_frame(self):
        udp = udp_header(0)
        assert ref_checksum(SRC, FINAL, udp, b"hi") == 0x2FAD
        assert ref_checksum(SRC, NEXT_HOP, udp, b"hi") == 0x3044

    def test_with_checksums_rewrites_a_wrong_value(self):
        p = decode_frame(ISSUE_FRAME, start=IPv6)
        bad = Packet(
            *[
                replace(layer, checksum=1) if isinstance(layer, UDP) else layer
                for layer in p.layers
            ]
        )
        fixed = bad.with_checksums(payload=b"hi")
        assert bytes(fixed) + b"hi" == ISSUE_FRAME


@pytest.mark.parametrize(
    ("name", "routing", "wire_dst", "final"), CASES, ids=CASE_IDS
)
class TestEachRoutingType:
    def test_compute_verify_use_the_final_destination(
        self, name, routing, wire_dst, final
    ):
        frame = build_frame(routing, wire_dst, final)
        p = decode_frame(frame, start=IPv6)
        assert p[IPv6].dst == IPv6Address(wire_dst).compressed
        header = p[IPv6Routing]
        assert header.final_destination(p[IPv6].dst) == final
        got = checksum.compute(
            p[UDP], ip=p[IPv6], routing=header, payload=b"hi"
        )
        assert got == wire_checksum(frame)
        assert checksum.verify(
            p[UDP], ip=p[IPv6], routing=header, payload=b"hi"
        )
        # Without the routing header the next hop is used: wrong.
        assert not checksum.verify(p[UDP], ip=p[IPv6], payload=b"hi")

    def test_with_checksums_through_decode_frame(
        self, name, routing, wire_dst, final
    ):
        frame = build_frame(routing, wire_dst, final)
        zeroed = frame[:-4] + b"\x00\x00" + frame[-2:]
        p = decode_frame(zeroed, start=IPv6)
        assert p[UDP].checksum == 0
        fixed = p.with_checksums(payload=b"hi")
        assert bytes(fixed) + b"hi" == frame

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

    def test_memoryview_decode(self, name, routing, wire_dst, final):
        frame = build_frame(routing, wire_dst, final)
        p = decode_frame(memoryview(frame), start=IPv6)
        header = p[IPv6Routing]
        assert header.final_destination(p[IPv6].dst) == final
        assert checksum.verify(
            p[UDP], ip=p[IPv6], routing=header, payload=b"hi"
        )


class TestFallsBackToIpDst:
    def test_segments_left_zero_uses_ip_dst(self):
        # The last hop: ip.dst IS the final destination, while the
        # list's final entry deliberately differs, to pin the `> 0`.
        for routing in (
            routing_srh(["2001:db8::77", FINAL], 0),
            routing_type0(["2001:db8::77"], 0),
            routing_type2("2001:db8::77"),
        ):
            routing = routing[:3] + b"\x00" + routing[4:]
            frame = build_frame(routing, FINAL, FINAL)
            p = decode_frame(frame, start=IPv6)
            header = p[IPv6Routing]
            assert header.segments_left == 0
            assert header.final_destination(FINAL) == "2001:db8::77"
            assert checksum.verify(
                p[UDP], ip=p[IPv6], routing=header, payload=b"hi"
            )
            expected = flow_key(p[UDP], ip=p[IPv6])
            assert flow_key(p[UDP], ip=p[IPv6], routing=header) == expected
            assert p.flow_key() == expected
            zeroed = frame[:-4] + b"\x00\x00" + frame[-2:]
            assert (
                bytes(decode_frame(zeroed, start=IPv6).with_checksums(b"hi"))
                + b"hi"
                == frame
            )

    def test_unknown_routing_type(self):
        routing = bytes([17, 1, 253, 1]) + bytes(12)
        frame = build_frame(routing, NEXT_HOP, NEXT_HOP)
        p = decode_frame(frame, start=IPv6)
        header = p[IPv6Routing]
        assert header.final_destination(NEXT_HOP) is None
        assert checksum.verify(
            p[UDP], ip=p[IPv6], routing=header, payload=b"hi"
        )
        assert p.flow_key() == flow_key(p[UDP], ip=p[IPv6])
        zeroed = frame[:-4] + b"\x00\x00" + frame[-2:]
        assert (
            bytes(decode_frame(zeroed, start=IPv6).with_checksums(b"hi"))
            + b"hi"
            == frame
        )

    def test_malformed_srh_falls_back(self):
        # Last Entry 5 but one segment of data.
        routing = bytes([17, 2, 4, 1, 5, 0, 0, 0]) + pton(FINAL)
        frame = build_frame(routing, NEXT_HOP, NEXT_HOP)
        p = decode_frame(frame, start=IPv6)
        assert p[IPv6Routing].final_destination(NEXT_HOP) is None
        assert checksum.verify(
            p[UDP], ip=p[IPv6], routing=p[IPv6Routing], payload=b"hi"
        )

    def test_ipv4_ignores_routing(self):
        ip = IPv4(
            version=4, ihl=5, dscp=0, ecn=0, total_length=30, identification=0,
            flags=0, fragment_offset=0, ttl=64, protocol=17, checksum=0,
            src="10.0.0.1", dst="10.0.0.2",
        )  # fmt: skip
        udp = UDP(src_port=1, dst_port=2, length=10, checksum=0)
        routing = IPv6Routing.decode(routing_srh([FINAL, NEXT_HOP], 1))
        assert checksum.compute(
            udp, ip=ip, routing=routing, payload=b"hi"
        ) == checksum.compute(udp, ip=ip, payload=b"hi")
        assert effective_destination(ip, routing) == "10.0.0.2"

    def test_no_ip_with_routing(self):
        routing = IPv6Routing.decode(routing_srh([FINAL, NEXT_HOP], 1))
        with pytest.raises(InvalidFieldError, match="requires"):
            checksum.compute(
                UDP(src_port=1, dst_port=2, length=10, checksum=0),
                routing=routing,
                payload=b"hi",
            )


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


class TestWhichRoutingHeader:
    def _ip(self, dst: str) -> IPv6:
        return IPv6(
            version=6, traffic_class=0, flow_label=0, payload_length=0,
            next_header=43, hop_limit=64, src=SRC, dst=dst,
        )  # fmt: skip

    def test_first_of_several_headers_wins(self):
        first = IPv6Routing.decode(routing_srh([FINAL, NEXT_HOP], 1))
        second = IPv6Routing.decode(routing_srh(["2001:db8::77", NEXT_HOP], 1))
        udp = UDP(src_port=1000, dst_port=2000, length=10, checksum=0)
        packet = Packet(self._ip(NEXT_HOP), first, second, udp)
        fixed = packet.with_checksums(payload=b"hi")
        assert fixed[UDP].checksum == ref_checksum(
            SRC, FINAL, udp_header(), b"hi"
        )
        key = packet.flow_key()
        assert key is not None
        assert FINAL in (key.addr_a, key.addr_b)

    def test_outer_tunnel_routing_is_not_between(self):
        outer_routing = IPv6Routing.decode(
            routing_srh(["2001:db8::77", NEXT_HOP], 1)
        )
        inner = self._ip("2001:db8::abcd")
        udp = UDP(src_port=1000, dst_port=2000, length=10, checksum=0)
        packet = Packet(self._ip(NEXT_HOP), outer_routing, inner, udp)
        fixed = packet.with_checksums(payload=b"hi")
        assert fixed[UDP].checksum == ref_checksum(
            SRC, "2001:db8::abcd", udp_header(), b"hi"
        )
        key = packet.flow_key()
        assert key is not None
        assert "2001:db8::abcd" in (key.addr_a, key.addr_b)

    def test_no_ip_before_transport(self):
        routing = IPv6Routing.decode(routing_srh([FINAL, NEXT_HOP], 1))
        udp = UDP(src_port=1000, dst_port=2000, length=10, checksum=0)
        assert Packet(routing, udp).flow_key() is None
