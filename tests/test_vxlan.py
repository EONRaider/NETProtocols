"""VXLAN (RFC 7348): the 8-byte header, its dispatch from UDP port 4789,
and the walk back into the ``ethertype`` table through the inner
Ethernet frame — the first payload in this library that is a whole
frame rather than another IP-family header."""

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    ARP,
    DNS,
    UDP,
    VLAN,
    VXLAN,
    Ethernet,
    ICMPv4,
    InvalidFieldError,
    IPv4,
    MaxDepthExceededError,
    Packet,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_UDP_PORT, Registry

#: Offsets in an Ethernet -> IPv4 -> UDP -> VXLAN frame.
VXLAN_AT = 14 + 20 + 8
INNER_AT = VXLAN_AT + 8

PAYLOAD = b"NETProtocols VXLAN test"


def make_ipv4(*, protocol: int, payload_len: int, src: str, dst: str) -> IPv4:
    return IPv4(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=20 + payload_len,
        identification=0,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=protocol,
        checksum=0,
        src=src,
        dst=dst,
    )


def ethernet(ethertype: int, *, inner: bool = False) -> Ethernet:
    host = "0d" if inner else "0c"
    return Ethernet(
        dst=f"02:00:0a:09:{host}:02",
        src=f"02:00:0a:09:{host}:01",
        ethertype=ethertype,
    )


def vxlan(vni: int = 0x123456) -> VXLAN:
    return VXLAN(flags=VXLAN.I_FLAG, reserved1=0, vni=vni, reserved2=0)


def encapsulate(
    inner: bytes, *, vni: int = 0x123456, src_port: int = 51361
) -> bytes:
    """``Ethernet -> IPv4 -> UDP (dst 4789) -> VXLAN`` around ``inner``,
    a whole Ethernet frame, with every outer checksum computed."""
    udp_len = 8 + 8 + len(inner)
    return (
        bytes(
            Packet(
                ethernet(0x0800),
                make_ipv4(
                    protocol=17,
                    payload_len=udp_len,
                    src="10.9.12.1",
                    dst="10.9.12.2",
                ),
                UDP(
                    src_port=src_port, dst_port=4789, length=udp_len, checksum=0
                ),
                vxlan(vni),
            ).with_checksums(inner)
        )
        + inner
    )


def inner_echo() -> bytes:
    """An inner ``Ethernet -> IPv4 -> ICMPv4`` echo request."""
    icmp = ICMPv4(
        type=8, code=0, checksum=0, rest=b"\x05\xc4\x00\x01", body=PAYLOAD
    )
    ip = make_ipv4(
        protocol=1,
        payload_len=icmp.header_len,
        src="10.9.13.1",
        dst="10.9.13.2",
    )
    return bytes(
        Packet(ethernet(0x0800, inner=True), ip, icmp).with_checksums()
    )


def inner_udp(dst_port: int, payload: bytes) -> bytes:
    """An inner ``Ethernet -> IPv4 -> UDP`` datagram carrying ``payload``."""
    udp_len = 8 + len(payload)
    stack = Packet(
        ethernet(0x0800, inner=True),
        make_ipv4(
            protocol=17,
            payload_len=udp_len,
            src="10.9.13.1",
            dst="10.9.13.2",
        ),
        UDP(src_port=40000, dst_port=dst_port, length=udp_len, checksum=0),
    )
    return bytes(stack.with_checksums(payload)) + payload


def kinds(packet: Packet) -> list[type]:
    return [type(layer) for layer in packet.layers]


class TestHeader:
    def test_decode_a_captured_header(self, raw_vxlan_header):
        header = VXLAN.decode(raw_vxlan_header)
        assert header == VXLAN(
            flags=0x08, reserved1=0, vni=1193046, reserved2=0
        )
        assert header.header_len == 8

    def test_the_vni_is_read_big_endian_across_three_bytes(self):
        header = VXLAN.decode(b"\x08\x00\x00\x00\xab\xcd\xef\x00")
        assert header.vni == 0xABCDEF

    def test_round_trips_both_ways(self, raw_vxlan_header):
        header = VXLAN.decode(raw_vxlan_header)
        assert bytes(header) == raw_vxlan_header
        assert VXLAN.decode(bytes(header)) == header

    def test_reserved_bits_are_carried_verbatim(self):
        """RFC 7348 §5: reserved bits are ignored on receipt — so not
        rejected — and kept, so a header from an extension reusing them
        (Group Based Policy sets 0x80 and a policy ID) round-trips."""
        raw = b"\x88\xab\xcd\xef\x00\x00\x2a\x5a"
        header = VXLAN.decode(raw)
        assert header.flags == 0x88
        assert header.reserved1 == 0xABCDEF
        assert header.vni == 42
        assert header.reserved2 == 0x5A
        assert bytes(header) == raw

    def test_trailing_bytes_are_the_inner_frame(self, raw_vxlan_header):
        header = VXLAN.decode(raw_vxlan_header + b"\xff" * 14)
        assert bytes(header) == raw_vxlan_header

    def test_memoryview_is_accepted(self, raw_vxlan_header):
        view = memoryview(raw_vxlan_header + b"\x00" * 14)
        assert VXLAN.decode(view) == VXLAN.decode(raw_vxlan_header)

    @pytest.mark.parametrize("length", range(8))
    def test_a_short_buffer_raises(self, raw_vxlan_header, length):
        with pytest.raises(TruncatedHeaderError) as caught:
            VXLAN.decode(raw_vxlan_header[:length])
        err = caught.value
        assert err.protocol is VXLAN
        assert (err.offset, err.expected, err.actual) == (0, 8, length)

    @pytest.mark.parametrize("flags", [0x00, 0x80, 0xF7])
    def test_a_clear_i_flag_is_rejected_at_its_byte(self, flags):
        with pytest.raises(InvalidFieldError) as caught:
            VXLAN.decode(bytes([flags]) + b"\x00\x00\x00\x00\x00\x2a\x00")
        err = caught.value
        assert err.protocol is VXLAN
        assert err.field == "flags"
        assert err.offset == 0
        assert err.actual == flags
        assert str(err) == (
            "VXLAN I flag (0x08) must be set for a valid VNI (RFC 7348 §5), "
            f"got flags {flags:#04x}"
        )


class TestConstruction:
    def test_the_i_flag_constant(self):
        assert VXLAN.I_FLAG == 0x08

    @pytest.mark.parametrize(
        "field,value,expected",
        [
            ("flags", -1, "0-255"),
            ("flags", 0x108, "0-255"),
            ("reserved1", -1, "0-16777215"),
            ("reserved1", 0x1000000, "0-16777215"),
            ("vni", -1, "0-16777215"),
            ("vni", 0x1000000, "0-16777215"),
            ("reserved2", -1, "0-255"),
            ("reserved2", 0x100, "0-255"),
        ],
    )
    def test_out_of_range_fields_are_rejected(self, field, value, expected):
        fields = {"flags": 0x08, "reserved1": 0, "vni": 0, "reserved2": 0}
        with pytest.raises(InvalidFieldError) as caught:
            VXLAN(**{**fields, field: value})
        err = caught.value
        assert err.protocol is VXLAN
        assert (err.field, err.expected, err.actual) == (field, expected, value)
        assert err.offset is None

    def test_the_i_flag_is_required(self):
        with pytest.raises(InvalidFieldError) as caught:
            VXLAN(flags=0, reserved1=0, vni=7, reserved2=0)
        err = caught.value
        assert err.field == "flags"
        assert err.offset is None  # a value, not a position in bytes

    def test_the_widest_values_are_accepted(self):
        header = VXLAN(
            flags=0xFF, reserved1=0xFFFFFF, vni=0xFFFFFF, reserved2=0xFF
        )
        assert bytes(header) == b"\xff" * 8

    def test_positional_patterns_follow_wire_order(self):
        match vxlan(42):
            case VXLAN(VXLAN.I_FLAG, 0, vni):
                assert vni == 42
            case _:
                pytest.fail("positional VXLAN pattern did not match")


class TestDispatch:
    def test_registered_on_its_iana_port(self):
        assert DEFAULT.get(TABLE_UDP_PORT, 4789) is VXLAN

    def test_the_payload_is_always_ethernet(self):
        assert vxlan().next_protocol() is Ethernet
        assert vxlan().next_protocol(Registry()) is Ethernet

    @pytest.mark.parametrize(
        "src_port,dst_port,expected",
        [
            # What an endpoint sends: a hashed ephemeral source port.
            (51361, 4789, VXLAN),
            # The destination is tried first, so a VXLAN datagram whose
            # hashed source port lands on a registered port is still
            # VXLAN...
            (53, 4789, VXLAN),
            (68, 4789, VXLAN),
            # ...and a datagram *from* 4789 to a registered port is not.
            (4789, 53, DNS),
            # The source port is the fallback, as for every port entry.
            (4789, 51361, VXLAN),
        ],
        ids=["ephemeral", "src-dns", "src-dhcp", "dst-dns", "src-only"],
    )
    def test_port_precedence(self, src_port, dst_port, expected):
        udp = UDP(src_port=src_port, dst_port=dst_port, length=8, checksum=0)
        assert udp.next_protocol() is expected
        assert udp.next_protocol(Registry.from_defaults()) is expected


class TestWalk:
    """The design question in #180: does the walker re-enter the
    ``ethertype`` table cleanly from a non-``Ethernet`` layer? It does,
    with no walker change — ``VXLAN.next_protocol()`` returns the
    ``Ethernet`` class, and the walk decodes it like any other layer."""

    def test_ipv4_udp_vxlan_ethernet_ipv4_end_to_end(self):
        frame = encapsulate(inner_echo())
        packet = decode_frame(frame)
        assert kinds(packet) == [
            Ethernet,
            IPv4,
            UDP,
            VXLAN,
            Ethernet,
            IPv4,
            ICMPv4,
        ]
        assert packet.consumed == len(frame)
        assert packet[VXLAN].vni == 0x123456
        assert packet.layers[5].dst == "10.9.13.2"
        assert packet[ICMPv4].body == PAYLOAD

    def test_every_layer_round_trips_byte_exactly(self):
        frame = encapsulate(inner_echo())
        cursor = 0
        for layer in decode_frame(frame).layers:
            assert bytes(layer) == frame[cursor : cursor + layer.header_len]
            cursor += layer.header_len

    def test_an_inner_vlan_tag_walks_like_an_outer_one(self):
        inner = inner_echo()
        tagged = (
            inner[:12]
            + b"\x81\x00"
            + bytes(VLAN(pcp=0, dei=0, vid=30, ethertype=0x0800))
            + inner[14:]
        )
        packet = decode_frame(encapsulate(tagged))
        assert kinds(packet)[3:] == [VXLAN, Ethernet, VLAN, IPv4, ICMPv4]
        assert packet[VLAN].vid == 30

    def test_an_inner_arp_ends_the_chain(self):
        arp = ARP(
            htype=1,
            ptype=0x0800,
            hlen=6,
            plen=4,
            oper=1,
            sha="02:00:0a:09:0d:01",
            spa="10.9.13.1",
            tha="00:00:00:00:00:00",
            tpa="10.9.13.2",
        )
        inner = bytes(ethernet(0x0806, inner=True)) + bytes(arp)
        packet = decode_frame(encapsulate(inner))
        assert kinds(packet)[3:] == [VXLAN, Ethernet, ARP]

    def test_decode_as_reaches_the_inner_frame(self):
        """The walk hands the per-call registry through VXLAN to the
        inner layers, so an override applies inside the tunnel too."""
        frame = encapsulate(inner_udp(6969, bytes(DNS.decode(bytes(12)))))
        assert kinds(decode_frame(frame))[-1] is UDP
        packet = decode_frame(frame, decode_as={"udp.port": {6969: DNS}})
        assert kinds(packet)[-2:] == [UDP, DNS]

    def test_an_override_can_take_the_port_away(self):
        """Best-effort like every port entry: a caller who knows port
        4789 carries something else can say so for one walk."""
        frame = encapsulate(inner_echo())
        reg = Registry.from_defaults()
        reg.register(TABLE_UDP_PORT, 4789, DNS, override=True)
        packet = decode_frame(frame, registry=reg)
        assert kinds(packet) == [Ethernet, IPv4, UDP, DNS]

    def test_checksums_pair_each_transport_with_its_own_ip(self):
        """with_checksums() computes the inner UDP over the inner IPv4
        pseudo-header and the outer UDP over the outer one, covering the
        finished inner frame."""
        frame = encapsulate(inner_udp(9999, PAYLOAD))
        packet = decode_frame(frame)
        trailing = frame[packet.consumed :]
        assert trailing == PAYLOAD
        assert packet.with_checksums(trailing) == packet
        outer, inner = (
            layer for layer in packet.layers if isinstance(layer, UDP)
        )
        assert outer.checksum != 0
        assert inner.checksum != 0


class TestTruncatedAndMalformed:
    FRAME = encapsulate(inner_echo())

    def test_truncation_inside_the_header(self):
        frame = self.FRAME[: VXLAN_AT + 5]
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(frame)
        assert caught.value.protocol is VXLAN
        assert caught.value.frame_offset == VXLAN_AT
        packet = decode_frame(frame, lax=True)
        assert kinds(packet) == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    def test_truncation_inside_the_inner_ethernet_header(self):
        frame = self.FRAME[: INNER_AT + 6]
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(frame)
        assert caught.value.protocol is Ethernet
        assert caught.value.frame_offset == INNER_AT
        packet = decode_frame(frame, lax=True)
        assert kinds(packet) == [Ethernet, IPv4, UDP, VXLAN]

    def test_truncation_inside_the_inner_ip_header(self):
        frame = self.FRAME[: INNER_AT + 14 + 10]
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(frame)
        assert caught.value.protocol is IPv4
        assert caught.value.frame_offset == INNER_AT + 14
        packet = decode_frame(frame, lax=True)
        assert kinds(packet) == [Ethernet, IPv4, UDP, VXLAN, Ethernet]

    def test_a_clear_i_flag_is_reported_at_the_vxlan_header(self):
        frame = bytearray(self.FRAME)
        frame[VXLAN_AT] = 0x00
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(bytes(frame))
        assert caught.value.field == "flags"
        assert caught.value.frame_offset == VXLAN_AT
        packet = decode_frame(bytes(frame), lax=True)
        assert kinds(packet) == [Ethernet, IPv4, UDP]


class TestHostileNesting:
    """VXLAN in VXLAN nests without limit on the wire, 50 bytes and four
    layers (Ethernet, IPv4, UDP, VXLAN) per level, so a hostile frame is
    a long run of them. The walk's depth ceiling has to stop it."""

    @staticmethod
    def nested(levels: int) -> bytes:
        frame = bytes(ethernet(0x88B5, inner=True))  # local experimental
        for _ in range(levels):
            frame = encapsulate(frame)
        return frame

    def test_deep_nesting_hits_the_depth_ceiling(self):
        with pytest.raises(MaxDepthExceededError):
            decode_frame(self.nested(16))

    def test_nesting_within_the_ceiling_decodes(self):
        packet = decode_frame(self.nested(16), max_depth=4 * 16 + 1)
        assert len(packet) == 4 * 16 + 1
        assert sum(isinstance(layer, VXLAN) for layer in packet.layers) == 16


TUNNEL = [Ethernet, IPv4, UDP, VXLAN, Ethernet]
ECHO_CHAIN = [*TUNNEL, IPv4, ICMPv4]
ARP_CHAIN = [*TUNNEL, ARP]
UDP_CHAIN = [*TUNNEL, IPv4, UDP]


class TestCorpusVXLAN:
    FRAMES = pcap_frames(FIXTURES / "vxlan.pcap")

    def packets(self) -> list[Packet]:
        return [decode_frame(frame) for frame in self.FRAMES]

    def test_captured_chains(self):
        assert [kinds(packet) for packet in self.packets()] == [
            *([ARP_CHAIN] * 2 + [ECHO_CHAIN] * 4 + [UDP_CHAIN]),
            *([ARP_CHAIN] * 2 + [ECHO_CHAIN] * 2),
        ]

    def test_two_segments_by_vni(self):
        vnis = [packet[VXLAN].vni for packet in self.packets()]
        assert vnis == [0x123456] * 7 + [100] * 4
        for packet in self.packets():
            header = packet[VXLAN]
            assert (header.flags, header.reserved1, header.reserved2) == (
                VXLAN.I_FLAG,
                0,
                0,
            )

    def test_the_tunnel_and_the_overlay_are_different_networks(self):
        for packet in self.packets():
            outer = packet.layers[1]
            assert isinstance(outer, IPv4)
            assert {outer.src, outer.dst} == {"10.9.12.1", "10.9.12.2"}
            inner = packet.layers[5]
            if isinstance(inner, IPv4):
                assert {inner.src, inner.dst} == {"10.9.13.1", "10.9.13.2"}
            else:
                assert isinstance(inner, ARP)
                assert {inner.spa, inner.tpa} == {"10.9.13.1", "10.9.13.2"}

    def test_the_kernel_sends_to_4789_from_a_hashed_port(self):
        """Linux picks the outer source port from a hash of the inner
        flow and always targets 4789, which is why dispatch reaches
        VXLAN through the destination port."""
        for packet in self.packets():
            udp = packet[UDP]
            assert udp.dst_port == 4789
            assert DEFAULT.get(TABLE_UDP_PORT, udp.src_port) is None

    def test_outer_checksums_present_then_absent(self):
        """The VNI 0x123456 segment ran with udpcsum, the VNI 100 one
        with the kernel default, a zero ("not used") outer checksum."""
        checksums = [packet[UDP].checksum for packet in self.packets()]
        assert all(checksums[:7])
        assert checksums[7:] == [0] * 4

    def test_recomputed_checksums_match_the_wire(self):
        # The inner checksums were verified by check_fixtures.py, which
        # shares no code with this library. with_checksums() must reach
        # the same values, which it only does if each transport keys on
        # the IP header nearest before it, inner or outer.
        for frame, packet in zip(self.FRAMES, self.packets(), strict=True):
            trailing = frame[packet.consumed :]
            restored = packet.with_checksums(trailing)
            if packet[UDP].checksum:
                assert restored == packet
            else:
                # A zero outer checksum is not a value to reproduce:
                # with_checksums() always computes one. Everything else,
                # the inner frame included, must come back unchanged.
                assert restored.layers[:2] == packet.layers[:2]
                assert restored.layers[3:] == packet.layers[3:]
                assert restored[UDP].checksum != 0
