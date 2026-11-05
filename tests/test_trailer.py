"""The walk's declared-length bounds and ``Packet.trailer``.

An 802.3 Length, an IPv4 Total Length, an IPv6 Payload Length and a UDP
Length each end the buffer :func:`decode_frame` hands every later
layer; the bytes past the tightest end are the packet's trailer. A
declared end past the captured frame bounds nothing, so a frame cut by
a snap length decodes as it does with no bound at all, which
``unbounded`` reproduces by switching the IP and UDP bounds off.
"""

import struct
import zlib
from contextlib import contextmanager

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    BGP,
    DHCP,
    DNS,
    ESP,
    IGMP,
    SCTP,
    UDP,
    VXLAN,
    Ethernet,
    ICMPv4,
    ICMPv6,
    InvalidFieldError,
    IPv4,
    IPv6,
    MaxDepthExceededError,
    Packet,
    TruncatedHeaderError,
    decode_frame,
    verify,
)

#: Every captured frame, the subdirectory captures included, by name.
ALL_FRAMES = [
    (f"{pcap.relative_to(FIXTURES)}#{index}", frame)
    for pcap in sorted(FIXTURES.glob("*.pcap"))
    + sorted(FIXTURES.glob("*/*.pcap"))
    for index, frame in enumerate(pcap_frames(pcap))
]

#: The captured frames that carry bytes past their declared end: the
#: zero padding after an 802.3 Length's STP BPDU, and after a 2-byte
#: UDP payload under an MPLS label.
FRAMES_WITH_A_TRAILER = {
    "llc.pcap#8": bytes(10),
    "llc.pcap#10": bytes(10),
    "llc.pcap#11": bytes(6),
    "llc.pcap#12": bytes(16),
    "mpls.pcap#4": bytes(8),
}

LAX = pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])


def fcs(frame: bytes) -> bytes:
    """Return the Ethernet FCS of ``frame``, as a capture keeps it."""
    return zlib.crc32(frame).to_bytes(4, "little")


@contextmanager
def unbounded():
    """Walk with the IPv4, IPv6 and UDP bounds switched off.

    Only Ethernet's and VLAN's 802.3 Length then bound the walk.
    """
    saved = {cls: cls._BOUNDS_PAYLOAD for cls in (IPv4, IPv6, UDP)}
    try:
        for cls in saved:
            cls._BOUNDS_PAYLOAD = False
        yield
    finally:
        for cls, value in saved.items():
            cls._BOUNDS_PAYLOAD = value


def walk_without_ip_bounds(frame: bytes, **kwargs) -> Packet:
    with unbounded():
        return decode_frame(frame, **kwargs)


def same_walk(left: Packet, right: Packet) -> bool:
    return (
        left.layers == right.layers
        and type(left.stopped_by) is type(right.stopped_by)
        and str(left.stopped_by) == str(right.stopped_by)
    )


def holds_the_round_trip(frame: bytes, packet: Packet) -> bool:
    """``frame`` is the layers, the undecoded rest, then the trailer."""
    end = len(frame) - len(packet.trailer)
    undecoded = frame[packet.consumed : end]
    return frame == bytes(packet) + undecoded + packet.trailer


def frames_of(name: str) -> list[bytes]:
    return pcap_frames(FIXTURES / name)


ETHERNET_IPV4 = bytes.fromhex("00005e00530200005e0053010800")


def ipv4(payload: bytes, protocol: int) -> bytes:
    """An IPv4 datagram holding ``payload``, its Total Length exact."""
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(payload),
            1,
            0,
            64,
            protocol,
            0,
            bytes.fromhex("c0000201"),
            bytes.fromhex("c0000202"),
        )
        + payload
    )


def udp(payload: bytes) -> bytes:
    """A UDP datagram to the discard port, its Length exact."""
    return struct.pack("!HHHH", 40000, 9, 8 + len(payload), 0) + payload


def with_lengths(frame: bytes, ip_at: int, extra: int) -> bytes:
    """Grow the IPv4 Total Length at ``ip_at``, and the UDP Length after
    it, by ``extra`` bytes."""
    out = bytearray(frame)
    ihl = (out[ip_at] & 0x0F) * 4
    for at in (ip_at + 2, ip_at + ihl + 4):
        (value,) = struct.unpack_from("!H", out, at)
        struct.pack_into("!H", out, at, value + extra)
    return bytes(out)


class TestHarness:
    def test_the_unbounded_walk_restores_the_bounds(self):
        classes = (IPv4, IPv6, UDP)
        before = [cls._BOUNDS_PAYLOAD for cls in classes]
        with unbounded():
            assert not any(cls._BOUNDS_PAYLOAD for cls in classes)
        assert [cls._BOUNDS_PAYLOAD for cls in classes] == before

    def test_the_unbounded_walk_takes_padding_into_the_last_layer(self):
        """The reference walk sees what the bounds keep out: here, a
        padded IGMP frame's padding in IGMP's body."""
        frame = frames_of("igmp.pcap")[0]
        padded = frame + bytes(60 - len(frame))
        assert walk_without_ip_bounds(padded)[IGMP] != decode_frame(padded).get(
            IGMP
        )


class TestTheCorpus:
    """Every captured frame decodes as it does with no IP or UDP bound,
    except the five that carry bytes past their declared end."""

    @pytest.mark.parametrize(
        "name,frame", ALL_FRAMES, ids=[name for name, _ in ALL_FRAMES]
    )
    def test_decodes_as_without_ip_bounds(self, name, frame):
        packet = decode_frame(frame, lax=True)
        reference = walk_without_ip_bounds(frame, lax=True)
        assert same_walk(packet, reference)
        assert packet.trailer == FRAMES_WITH_A_TRAILER.get(name, b"")
        assert holds_the_round_trip(frame, packet)

    def test_the_frames_with_a_trailer_end_in_it(self):
        frames = dict(ALL_FRAMES)
        for name, trailer in FRAMES_WITH_A_TRAILER.items():
            packet = decode_frame(frames[name])
            assert packet.trailer == trailer
            assert frames[name].endswith(trailer)
            assert packet.consumed + len(trailer) <= len(frames[name])


class Test8023Length:
    """An Ethernet 802.3 Length bounds the walk by itself, with every IP
    and UDP bound switched off, and its padding and an FCS after it are
    the trailer."""

    @pytest.mark.parametrize(
        "name", [name for name in FRAMES_WITH_A_TRAILER if "llc" in name]
    )
    def test_the_padding_and_an_fcs_are_the_trailer(self, name):
        frame = dict(ALL_FRAMES)[name]
        wire = frame + fcs(frame)
        packet = walk_without_ip_bounds(wire)
        assert packet.trailer == FRAMES_WITH_A_TRAILER[name] + fcs(frame)
        assert packet.layers == decode_frame(frame).layers
        assert holds_the_round_trip(wire, packet)


class TestSnapLength:
    """A frame cut anywhere before its declared end decodes, in lax
    mode, exactly as the walk with no IP or UDP bound decodes it, and
    has no trailer: a declared length past the capture bounds
    nothing."""

    @pytest.mark.parametrize(
        "name,frame", ALL_FRAMES, ids=[name for name, _ in ALL_FRAMES]
    )
    def test_every_prefix_decodes_as_without_ip_bounds(self, name, frame):
        end = len(frame) - len(decode_frame(frame, lax=True).trailer)
        bounded = [decode_frame(frame[:cut], lax=True) for cut in range(end)]
        with unbounded():
            reference = [
                decode_frame(frame[:cut], lax=True) for cut in range(end)
            ]
        for cut, (packet, expected) in enumerate(
            zip(bounded, reference, strict=True)
        ):
            assert same_walk(packet, expected), cut
            assert packet.trailer == b"", cut


class TestAppendedFCS:
    """A capture that keeps the Ethernet FCS: four bytes past the IP
    datagram, outside every layer."""

    CASES = tuple(
        (name, index)
        for name in (
            "esp.pcap",
            "sctp.pcap",
            "vxlan.pcap",
            "ntp.pcap",
            "icmpv6_echo_lo.pcap",
            "gre.pcap",
            "ipip.pcap",
            "pim.pcap",
        )
        for index in range(len(frames_of(name)))
    )

    @LAX
    @pytest.mark.parametrize(
        "name,index", CASES, ids=[f"{n}#{i}" for n, i in CASES]
    )
    def test_the_fcs_is_the_trailer(self, name, index, lax):
        frame = frames_of(name)[index]
        clean = decode_frame(frame, lax=lax)
        packet = decode_frame(frame + fcs(frame), lax=lax)
        assert clean.trailer == b""
        assert packet.stopped_by is None
        assert packet.layers == clean.layers
        assert packet.consumed == clean.consumed
        assert packet.trailer == fcs(frame)
        assert packet == Packet(*clean.layers, trailer=fcs(frame))
        assert holds_the_round_trip(frame + fcs(frame), packet)

    @pytest.mark.parametrize("index", range(len(frames_of("sctp.pcap"))))
    def test_every_sctp_packet_verifies(self, index):
        frame = frames_of("sctp.pcap")[index]
        packet = decode_frame(frame + fcs(frame))
        assert verify(packet[SCTP])

    @pytest.mark.parametrize("index", range(len(frames_of("esp.pcap"))))
    def test_the_esp_ciphertext_is_the_unpadded_one(self, index):
        frame = frames_of("esp.pcap")[index]
        packet = decode_frame(frame + fcs(frame))
        assert packet[ESP].ciphertext == decode_frame(frame)[ESP].ciphertext

    #: The VXLAN frames whose inner frame is an ICMPv4 echo.
    VXLAN_ECHOES = (2, 3, 4, 5, 9, 10)

    @pytest.mark.parametrize("index", VXLAN_ECHOES)
    def test_the_inner_icmp_message_verifies(self, index):
        frame = frames_of("vxlan.pcap")[index]
        packet = decode_frame(frame + fcs(frame))
        inner = packet.layers[packet.layers.index(packet[VXLAN]) + 1 :]
        assert type(inner[-1]) is ICMPv4
        assert inner[-1] == decode_frame(frame).layers[-1]
        assert verify(inner[-1])


class TestShortFramePadding:
    """Ethernet pads a frame shorter than 60 bytes; the padding is the
    trailer, zeros or not, and the layers are the unpadded frame's."""

    FILLS = pytest.mark.parametrize(
        "fill", [0x00, 0xA5], ids=["zeros", "nonzero"]
    )

    @staticmethod
    def padded(frame: bytes, fill: int, size: int = 60) -> bytes:
        return frame + bytes([fill]) * (size - len(frame))

    @staticmethod
    def empty_udp(dst_port: int) -> bytes:
        """An Ethernet frame carrying an empty UDP datagram: 42 bytes."""
        ip = IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=28,
            identification=1,
            flags=0,
            fragment_offset=0,
            ttl=64,
            protocol=17,
            checksum=0,
            src="192.0.2.1",
            dst="192.0.2.2",
        )
        udp = UDP(src_port=40000, dst_port=dst_port, length=8, checksum=0)
        eth = Ethernet(
            dst="00:00:5e:00:53:02", src="00:00:5e:00:53:01", ethertype=0x0800
        )
        return bytes(Packet(eth, ip, udp).with_checksums())

    @FILLS
    def test_an_empty_echo_keeps_its_body(self, fill):
        eth = Ethernet(
            dst="00:00:5e:00:53:02", src="00:00:5e:00:53:01", ethertype=0x0800
        )
        ip = IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=28,
            identification=1,
            flags=0,
            fragment_offset=0,
            ttl=64,
            protocol=1,
            checksum=0,
            src="192.0.2.1",
            dst="192.0.2.2",
        )
        echo = ICMPv4(type=8, code=0, checksum=0, rest=bytes(4), body=b"")
        frame = bytes(Packet(eth, ip, echo).with_checksums())
        assert len(frame) == 42
        packet = decode_frame(self.padded(frame, fill))
        assert packet.layers == decode_frame(frame).layers
        assert packet[ICMPv4].body == b""
        assert packet.trailer == bytes([fill]) * 18
        assert verify(packet[ICMPv4])

    @FILLS
    @pytest.mark.parametrize("index", range(len(frames_of("igmp.pcap"))))
    def test_igmp_keeps_its_body(self, index, fill):
        frame = frames_of("igmp.pcap")[index]
        packet = decode_frame(self.padded(frame, fill))
        assert packet.layers == decode_frame(frame).layers
        assert packet.trailer == bytes([fill]) * (60 - len(frame))
        assert verify(packet[IGMP])

    @FILLS
    @pytest.mark.parametrize("port,app", [(53, DNS), (67, DHCP)])
    def test_an_empty_datagram_decodes_as_unpadded(self, port, app, fill):
        """The padding of an empty datagram is never read as DNS or
        DHCP: strict raises as it does for the unpadded frame."""
        frame = self.empty_udp(port)
        assert len(frame) == 42
        for data in (frame, self.padded(frame, fill)):
            with pytest.raises(TruncatedHeaderError) as caught:
                decode_frame(data)
            assert (caught.value.protocol, caught.value.actual) == (app, 0)
            assert caught.value.frame_offset == 42
        packet = decode_frame(self.padded(frame, fill), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert packet.trailer == bytes([fill]) * 18

    @pytest.mark.parametrize(
        "name,app", [("udp_dns.pcap", DNS), ("dhcp.pcap", DHCP)]
    )
    @pytest.mark.parametrize(
        "trailer",
        [bytes(6), b"\xa5" * 6, b"\xde\xad\xbe\xef"],
        ids=["zeros", "nonzero", "fcs"],
    )
    def test_dns_and_dhcp_leave_a_trailer_out(self, name, app, trailer):
        for frame in frames_of(name):
            packet = decode_frame(frame + trailer)
            assert packet[app] == decode_frame(frame)[app]
            assert packet.trailer == trailer


class TestNestedBounds:
    """Each declared end bounds what follows it; the trailer is one
    value, everything past the tightest end."""

    def test_vxlan_padding_inside_and_an_fcs_outside(self):
        frame = frames_of("vxlan.pcap")[2]
        padding = b"\xaa" * 6
        grown = with_lengths(frame, 14, len(padding)) + padding
        packet = decode_frame(grown + fcs(grown))
        assert packet.layers[4:] == decode_frame(frame).layers[4:]
        assert packet.trailer == padding + fcs(grown)
        assert type(packet.layers[-1]) is ICMPv4
        assert verify(packet.layers[-1])
        assert holds_the_round_trip(grown + fcs(grown), packet)

    def test_a_udp_length_past_the_ip_end_is_clamped(self):
        """A first fragment's UDP length covers the whole datagram: the
        IP end is the tighter one, and nothing raises."""
        frame = frames_of("udp_dns.pcap")[0]
        out = bytearray(frame)
        ihl = (out[14] & 0x0F) * 4
        struct.pack_into("!H", out, 14 + ihl + 4, 0xFFFF)
        packet = decode_frame(bytes(out) + b"\xde\xad\xbe\xef")
        assert packet[DNS] == decode_frame(frame)[DNS]
        assert packet.trailer == b"\xde\xad\xbe\xef"

    def test_a_short_udp_length_ends_the_payload_early(self):
        """A UDP Length shorter than the IP payload is the tighter end;
        the rest of the datagram joins the trailer."""
        frame = frames_of("udp_dns.pcap")[0]
        out = bytearray(frame)
        ihl = (out[14] & 0x0F) * 4
        udp_at = 14 + ihl
        struct.pack_into("!H", out, udp_at + 4, 8 + 12)
        packet = decode_frame(bytes(out))
        assert packet.trailer == bytes(out[udp_at + 8 + 12 :])
        assert packet.consumed <= udp_at + 8 + 12

    @pytest.mark.parametrize("start,at", [(IPv4, 14), (IPv6, 14)])
    def test_a_walk_from_ip_is_bounded_too(self, start, at):
        name = "udp_dns.pcap"
        frame = next(
            frame
            for frame in frames_of(name)
            if isinstance(decode_frame(frame)[1], start)
        )
        packet = decode_frame(frame[at:] + b"\xde\xad", start=start)
        assert packet.layers == decode_frame(frame).layers[1:]
        assert packet.trailer == b"\xde\xad"

    def test_an_ipv6_zero_payload_length_bounds_nothing(self):
        frame = frames_of("icmpv6_echo_lo.pcap")[0]
        out = bytearray(frame)
        out[14 + 4 : 14 + 6] = bytes(2)
        packet = decode_frame(bytes(out))
        assert packet.trailer == b""
        assert packet[ICMPv6] == decode_frame(frame)[ICMPv6]

    def test_the_trailer_of_a_walk_cut_by_max_depth(self):
        frame = frames_of("igmp.pcap")[0]
        padded = frame + bytes(60 - len(frame))
        packet = decode_frame(padded, lax=True, max_depth=2)
        assert isinstance(packet.stopped_by, MaxDepthExceededError)
        assert packet.trailer == bytes(60 - len(frame))
        with pytest.raises(MaxDepthExceededError):
            decode_frame(padded, max_depth=2)

    @pytest.mark.parametrize(
        "encapsulate",
        [
            lambda inner: ipv4(inner, protocol=4),
            lambda inner: ipv4(b"\x00\x00\x08\x00" + inner, protocol=47),
        ],
        ids=["ip-in-ip", "gre"],
    )
    def test_an_encapsulation_gives_one_combined_trailer(self, encapsulate):
        """The inner datagram's padding, inside the outer datagram, and
        the bytes past the outer datagram form one trailer."""
        inner = ipv4(udp(b"data"), protocol=17)
        inner_padding = b"\x11" * 6
        outer_tail = b"\x22" * 4
        frame = ETHERNET_IPV4 + encapsulate(inner + inner_padding)
        frame += outer_tail
        packet = decode_frame(frame)
        assert packet.stopped_by is None
        assert type(packet.layers[-1]) is UDP
        assert packet.trailer == inner_padding + outer_tail
        assert packet.consumed == len(frame) - len(packet.trailer) - 4
        assert holds_the_round_trip(frame, packet)

    def test_the_trailer_is_a_copy(self):
        """Changing the frame after the walk changes no trailer."""
        frame = bytearray(frames_of("igmp.pcap")[0] + b"\xde\xad\xbe\xef")
        packet = decode_frame(memoryview(frame))
        frame[-4:] = bytes(4)
        assert packet.trailer == b"\xde\xad\xbe\xef"

    def test_a_memoryview_frame_gives_a_bytes_trailer(self):
        frame = frames_of("igmp.pcap")[0] + b"\xde\xad\xbe\xef"
        packet = decode_frame(memoryview(frame))
        assert type(packet.trailer) is bytes
        assert packet.trailer == b"\xde\xad\xbe\xef"


class TestICMPErrorQuotes:
    def test_a_quote_past_its_datagram_is_the_quotes_trailer(self):
        """A whole small datagram, quoted and zero-padded to 128 bytes
        as RFC 4884 pads it: the padding is the embedded chain's
        trailer, not part of the quoted transport's payload."""
        datagram = TestShortFramePadding.empty_udp(9)[14:]
        quote = datagram + b"\x00" * (128 - len(datagram))
        error = ICMPv4(type=3, code=3, checksum=0, rest=bytes(4), body=quote)
        chain = error.embedded_chain
        assert chain is not None
        assert [type(layer) for layer in chain] == [IPv4, UDP]
        assert chain.stopped_by is None
        assert chain.trailer == bytes(128 - len(datagram))

    def test_an_icmpv6_quote_past_its_datagram_is_the_quotes_trailer(self):
        datagram = (
            bytes(
                Packet(
                    IPv6(
                        version=6,
                        traffic_class=0,
                        flow_label=0,
                        payload_length=12,
                        next_header=17,
                        hop_limit=64,
                        src="2001:db8::1",
                        dst="2001:db8::2",
                    ),
                    UDP(src_port=40000, dst_port=9, length=12, checksum=0),
                )
            )
            + b"data"
        )
        quote = datagram + bytes(8)
        error = ICMPv6(type=1, code=4, checksum=0, rest=bytes(4), body=quote)
        chain = error.embedded_chain
        assert chain is not None
        assert [type(layer) for layer in chain] == [IPv6, UDP]
        assert chain.trailer == bytes(8)

    def test_a_cut_quote_is_not_bounded(self):
        """RFC 792's IP header and 8 bytes: the declared lengths reach
        past the quote and bound nothing."""
        frame = frames_of("icmpv4_ttl_exceeded.pcap")[0]
        chain = decode_frame(frame)[ICMPv4].embedded_chain
        assert chain is not None
        assert chain.trailer == b""


class TestContinuationWalks:
    """Walking on from ``packet.consumed`` up to the trailer: an FCS
    after the last message never reaches the continuation walk."""

    def test_bgp_keepalives_past_max_depth_and_an_fcs(self):
        keepalive = b"\xff" * 16 + b"\x00\x13\x04"
        frame = frames_of("bgp.pcap")[0]
        ihl = (frame[14] & 0x0F) * 4
        offset = (frame[14 + ihl + 12] >> 4) * 4
        head = frame[: 14 + ihl + offset]
        segment = keepalive * 40
        out = bytearray(head + segment)
        struct.pack_into("!H", out, 16, ihl + offset + len(segment))
        wire = bytes(out) + b"\xff\xff\xff\xff"
        packet = decode_frame(wire, lax=True)
        messages = [layer for layer in packet if isinstance(layer, BGP)]
        rest = wire[packet.consumed : len(wire) - len(packet.trailer)]
        while (
            isinstance(packet.stopped_by, MaxDepthExceededError)
            and packet.stopped_by.protocol is BGP
        ):
            packet = decode_frame(rest, start=BGP, lax=True)
            messages.extend(packet)
            rest = rest[packet.consumed :]
        assert len(messages) == 40
        assert packet.stopped_by is None
        assert rest == b""


class TestLyingLengthErrors:
    @LAX
    def test_the_frame_offset_is_the_header_start(self, lax):
        frame = frames_of("udp_dns.pcap")[0]
        out = bytearray(frame)
        ihl = (out[14] & 0x0F) * 4
        struct.pack_into("!H", out, 14 + ihl + 4, 5)
        if lax:
            error = decode_frame(bytes(out), lax=True).stopped_by
        else:
            with pytest.raises(InvalidFieldError) as caught:
                decode_frame(bytes(out))
            error = caught.value
        assert isinstance(error, InvalidFieldError)
        assert (error.protocol, error.field) == (UDP, "length")
        assert error.offset is None
        assert error.frame_offset == 14 + ihl
        assert UDP.decode(out[error.frame_offset :]).length == 5
