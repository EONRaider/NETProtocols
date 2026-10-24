"""AH, the IPsec Authentication Header (RFC 4302), IP protocol 51.

AH encrypts nothing, so it decodes in full and chains onward through
``next_header``. What may follow it depends on the IP family around it,
which is why it comes as a pair: ``AH`` dispatches through ``ip.proto``
and ``AHv6`` through ``ip.proto.v6``. Both directions of that gating
are tested here, along with Payload Len's lies, the ICV's length, and
that the corpus ICVs (``ah.pcap``) verify with the published keys when
the test suite — not the library — computes them."""

import hashlib
import hmac
from dataclasses import replace

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    AH,
    ESP,
    TCP,
    UDP,
    AHv6,
    Ethernet,
    ICMPv4,
    ICMPv6,
    InvalidFieldError,
    IPProtocol,
    IPv4,
    IPv6,
    IPv6DestinationOptions,
    IPv6HopByHopOptions,
    MaxDepthExceededError,
    Packet,
    Registry,
    TruncatedHeaderError,
    decode_frame,
    register,
)
from netprotocols.registry import DEFAULT, TABLE_IP_PROTO, TABLE_IP_PROTO_V6
from test_ipip import echo_v6, ethernet, make_ipv4, make_ipv6

#: The published test keys (tests/fixtures/MANIFEST.md), by SPI; every
#: SA uses HMAC-SHA-256-128 (RFC 4868).
AH_KEYS = {
    0x20000001: bytes.fromhex(
        "8eaa03a41a3b08f31a67f3a4b7fd78a2bf3d963a97b0af5a104301ef8fbff685"
    ),
    0x20000002: bytes.fromhex(
        "d2142153fb758a3f698e45720e2af765b2ada021d70ac1bcbde1f5bc38514fd1"
    ),
    0x20000003: bytes.fromhex(
        "008a9a220d8c1bf5edec1838a724b588364c08314bf93206985e776c385e1c7a"
    ),
}
ESP_BUNDLE_KEY = bytes.fromhex(
    "107c873bdbb0c7a11be8aa1d9064e51f63b26098412295c3bd6785958abd44d4"
)
ICV_LEN = 16
ICV = bytes(range(0xA0, 0xA0 + ICV_LEN))


def make_ah(next_header: int, *, cls: type[AH] = AH, spi: int = 0x99) -> AH:
    """An HMAC-SHA-256-128-sized AH: 16 bytes of ICV, padded with 4 more
    under IPv6 to keep the header a multiple of 8 octets."""
    icv = ICV if cls is AH else ICV + bytes(4)
    return cls(
        next_header=next_header,
        payload_len=(12 + len(icv)) // 4 - 2,
        reserved=0,
        spi=spi,
        sequence_number=1,
        icv=icv,
    )


def syn() -> TCP:
    return TCP(
        src_port=40001,
        dst_port=80,
        seq=1,
        ack=0,
        data_offset=5,
        reserved=0,
        flags=0x002,
        window=64240,
        checksum=0,
        urgent_pointer=0,
    )


def udp(payload: bytes) -> UDP:
    return UDP(src_port=40002, dst_port=9, length=8 + len(payload), checksum=0)


def frame_of(*layers, payload: bytes = b"") -> bytes:
    return bytes(Packet(*layers).with_checksums(payload)) + payload


def v4_frame(*inner, payload: bytes = b"") -> bytes:
    """``Ethernet → IPv4 (protocol 51) → inner...``."""
    length = sum(layer.header_len for layer in inner) + len(payload)
    ip = make_ipv4(protocol=51, payload_len=length)
    return frame_of(ethernet(0x0800), ip, *inner, payload=payload)


def v6_frame(*inner, next_header: int = 51, payload: bytes = b"") -> bytes:
    """``Ethernet → IPv6 → inner...``."""
    length = sum(layer.header_len for layer in inner) + len(payload)
    ip = make_ipv6(next_header=next_header, payload_len=length)
    return frame_of(ethernet(0x86DD), ip, *inner, payload=payload)


def chain(frame: bytes) -> list[type]:
    return [type(layer) for layer in decode_frame(frame).layers]


class TestWiring:
    def test_protocol_number_and_display_name(self):
        assert IPProtocol.AH == 51
        assert IPProtocol.AH.display_name == "AH"

    def test_each_family_has_its_own_class(self):
        assert DEFAULT.get(TABLE_IP_PROTO, 51) is AH
        assert DEFAULT.get(TABLE_IP_PROTO_V6, 51) is AHv6

    def test_ahv6_is_an_ah(self):
        # So packet[AH], isinstance and `case AH(...)` find either.
        assert issubclass(AHv6, AH)
        assert packet_layer(v6_frame(make_ah(59, cls=AHv6)), AH).spi == 0x99

    def test_ipv4_dispatches_to_ah(self):
        ip = make_ipv4(protocol=51, payload_len=28)
        assert ip.next_protocol() is AH
        assert ip.protocol_name == "AH"

    def test_ipv6_dispatches_to_ahv6(self):
        assert make_ipv6(next_header=51, payload_len=32).next_protocol() is (
            AHv6
        )

    def test_an_extension_header_dispatches_to_ahv6(self):
        hop = IPv6HopByHopOptions(
            next_header=51, hdr_ext_len=0, options=b"\x01\x04" + bytes(4)
        )
        assert hop.next_protocol() is AHv6

    def test_derived_registries_keep_the_split(self):
        for registry in (Registry.from_defaults(), DEFAULT.derive()):
            assert registry.get(TABLE_IP_PROTO, 51) is AH
            assert registry.get(TABLE_IP_PROTO_V6, 51) is AHv6

    def test_overriding_ip_proto_51_reaches_ipv4_only(self):
        # The v6 entry is the v6 table's own, so a later write to the
        # parent does not inherit over it: replacing AH for one family
        # leaves the other alone.
        registry = Registry.from_defaults()

        class OtherAH(AH):
            pass

        register(TABLE_IP_PROTO, 51, OtherAH, override=True, registry=registry)
        assert registry.get(TABLE_IP_PROTO, 51) is OtherAH
        assert registry.get(TABLE_IP_PROTO_V6, 51) is AHv6


def packet_layer(frame: bytes, cls: type) -> object:
    return decode_frame(frame)[cls]


class TestGating:
    """AH's onward table is its family's. IPv4 -> AH must not conjure
    an IPv6 extension header (ARCHITECTURE.md's gating promise), and
    IPv6 -> AH must still reach one (RFC 8200 §4.1 orders Destination
    Options after AH)."""

    @pytest.mark.parametrize("number", [0, 43, 44, 60])
    def test_ipv4_ah_cannot_conjure_an_extension_header(self, number):
        assert make_ah(number).next_protocol() is None
        assert make_ah(number).next_protocol(Registry.from_defaults()) is None

    def test_ipv6_ah_reaches_destination_options(self):
        ah = make_ah(60, cls=AHv6)
        assert ah.next_protocol() is IPv6DestinationOptions
        assert ah.next_protocol(Registry.from_defaults()) is (
            IPv6DestinationOptions
        )

    @pytest.mark.parametrize(
        "number,expected",
        [(1, ICMPv4), (6, TCP), (17, UDP), (50, ESP), (4, IPv4), (41, IPv6)],
    )
    def test_shared_numbers_chain_from_both(self, number, expected):
        assert make_ah(number).next_protocol() is expected
        assert make_ah(number, cls=AHv6).next_protocol() is expected

    def test_stacked_ah_stays_in_its_family(self):
        assert make_ah(51).next_protocol() is AH
        assert make_ah(51, cls=AHv6).next_protocol() is AHv6

    def test_unknown_next_header_ends_the_chain(self):
        assert make_ah(253).next_protocol() is None

    def test_an_ipv4_walk_stops_at_ah_before_a_v6_only_number(self):
        frame = v4_frame(make_ah(0), payload=b"\x3a\x00" + bytes(6))
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet.layers] == [
            Ethernet,
            IPv4,
            AH,
        ]
        assert packet.consumed == 14 + 20 + 28

    def test_the_family_follows_the_nearest_ip_header(self):
        # IPv4 -> AH -> IPv6 (tunnel mode) -> AH: the inner AH is in an
        # IPv6 chain, so it is AHv6 and may reach Destination Options.
        dst_opts = IPv6DestinationOptions(
            next_header=59, hdr_ext_len=0, options=b"\x01\x04" + bytes(4)
        )
        inner_ah = make_ah(60, cls=AHv6)
        inner = make_ipv6(next_header=51, payload_len=inner_ah.header_len + 8)
        frame = v4_frame(make_ah(41), inner, inner_ah, dst_opts)
        assert chain(frame) == [
            Ethernet,
            IPv4,
            AH,
            IPv6,
            AHv6,
            IPv6DestinationOptions,
        ]


class TestDecode:
    def test_fixed_fields(self, raw_ah_header):
        ah = AH.decode(raw_ah_header)
        assert ah.next_header == 6
        assert ah.payload_len == 5
        assert ah.reserved == 0
        assert ah.spi == 0x20000001
        assert ah.sequence_number == 1
        assert ah.icv == raw_ah_header[12:28]
        assert ah.header_len == 28

    def test_the_icv_length_is_what_payload_len_says(self, raw_ah_header):
        ah = AH.decode(raw_ah_header)
        assert len(ah.icv) == (ah.payload_len + 2) * 4 - 12 == ICV_LEN

    def test_wire_to_object_to_wire(self, raw_ah_header):
        ah = AH.decode(raw_ah_header)
        assert bytes(ah) == raw_ah_header[: ah.header_len]

    @pytest.mark.parametrize("cls", [AH, AHv6])
    def test_object_to_wire_to_object(self, cls):
        ah = make_ah(6, cls=cls)
        assert cls.decode(bytes(ah)) == ah

    def test_memoryview_is_materialized(self, raw_ah_header):
        buffer = bytearray(raw_ah_header)
        ah = AH.decode(memoryview(buffer))
        buffer[:] = bytes(len(buffer))
        assert type(ah.icv) is bytes
        assert bytes(ah) == raw_ah_header[:28]

    def test_trailing_bytes_are_the_next_layers(self, raw_ah_header):
        ah = AH.decode(raw_ah_header)
        assert TCP.decode(raw_ah_header[ah.header_len :]).dst_port == 80

    def test_display_helpers(self, raw_ah_header):
        ah = AH.decode(raw_ah_header)
        assert ah.next_header_name == "TCP"
        assert ah.next_header_enum is IPProtocol.TCP
        assert ah.spi_hex_str == "0x20000001"
        assert make_ah(253).next_header_name == "unknown (253)"
        assert make_ah(253).next_header_enum is None

    def test_null_authentication_is_twelve_bytes_under_ipv4(self):
        # Payload Len 1: the fixed part and an empty ICV.
        ah = AH.decode(b"\x06\x01\x00\x00" + bytes(8))
        assert (ah.header_len, ah.icv) == (12, b"")

    def test_ipv6_carries_padding_in_the_icv_field(self):
        raw = bytes(make_ah(6, cls=AHv6))
        ah = AHv6.decode(raw)
        assert (ah.payload_len, ah.header_len, len(ah.icv)) == (6, 32, 20)
        assert ah.icv == ICV + bytes(4)

    def test_the_two_classes_decode_the_same_bytes(self):
        # Same bytes, same fields: only dispatch and IPv6's alignment
        # rule tell the two apart, and so does equality.
        raw = bytes(make_ah(17, cls=AHv6))
        assert AH.decode(raw).icv == AHv6.decode(raw).icv
        assert AH.decode(raw) != AHv6.decode(raw)

    @pytest.mark.parametrize("cls", [AH, AHv6])
    @pytest.mark.parametrize("length", range(12))
    def test_truncated_fixed_header(self, raw_ah_header, cls, length):
        with pytest.raises(TruncatedHeaderError) as caught:
            cls.decode(raw_ah_header[:length])
        err = caught.value
        assert err.protocol is cls
        assert (err.offset, err.expected, err.actual) == (0, 12, length)


class TestLyingPayloadLen:
    def test_past_the_buffer(self, raw_ah_header):
        lying = raw_ah_header[:1] + b"\x20" + raw_ah_header[2:]
        with pytest.raises(TruncatedHeaderError) as caught:
            AH.decode(lying)
        err = caught.value
        assert err.protocol is AH
        assert err.field == "payload_len"
        assert err.offset == 0
        assert (err.expected, err.actual) == ((0x20 + 2) * 4, len(lying))
        assert str(err) == f"AH declares 136 bytes, buffer holds {len(lying)}"

    def test_one_byte_short_of_the_icv(self, raw_ah_header):
        with pytest.raises(TruncatedHeaderError):
            AH.decode(raw_ah_header[:27])

    @pytest.mark.parametrize("cls", [AH, AHv6])
    def test_shorter_than_the_fixed_part(self, raw_ah_header, cls):
        lying = raw_ah_header[:1] + b"\x00" + raw_ah_header[2:]
        with pytest.raises(InvalidFieldError) as caught:
            cls.decode(lying)
        err = caught.value
        assert err.protocol is cls
        assert err.field == "payload_len"
        assert err.offset == 0
        assert (err.expected, err.actual) == (">=1", 0)

    @pytest.mark.parametrize("payload_len", [1, 5, 255])
    def test_misaligned_under_ipv6(self, payload_len):
        raw = bytes([6, payload_len]) + bytes((payload_len + 2) * 4 - 2)
        with pytest.raises(InvalidFieldError) as caught:
            AHv6.decode(raw)
        err = caught.value
        assert err.protocol is AHv6
        assert err.field == "payload_len"
        assert err.offset == 0
        assert err.expected == "a multiple of 8 bytes"
        assert err.actual == (payload_len + 2) * 4
        # The same bytes are a legal IPv4 AH.
        assert AH.decode(raw).header_len == (payload_len + 2) * 4

    def test_the_walk_reports_the_frame_offset(self):
        frame = v4_frame(make_ah(6), syn())
        lying = frame[:35] + b"\x40" + frame[36:]
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(lying)
        assert caught.value.protocol is AH
        assert caught.value.frame_offset == 14 + 20

    def test_lax_mode_keeps_the_ip_header(self):
        frame = v6_frame(make_ah(6, cls=AHv6), syn())
        lying = frame[:55] + b"\x07" + frame[56:]  # odd: misaligned
        packet = decode_frame(lying, lax=True)
        assert [type(layer) for layer in packet.layers] == [Ethernet, IPv6]
        assert isinstance(packet.stopped_by, InvalidFieldError)
        assert packet.stopped_by.frame_offset == 14 + 40


class TestConstruction:
    def test_payload_len_must_agree_with_the_icv(self):
        with pytest.raises(InvalidFieldError) as caught:
            replace(make_ah(6), icv=ICV[:12])
        err = caught.value
        assert err.protocol is AH
        assert err.field == "payload_len"
        assert err.offset is None
        assert (err.expected, err.actual) == (16, 12)

    def test_payload_len_zero_is_rejected(self):
        with pytest.raises(InvalidFieldError) as caught:
            replace(make_ah(6), payload_len=0, icv=b"")
        assert caught.value.offset is None
        assert caught.value.expected == ">=1"

    def test_ahv6_rejects_an_odd_payload_len(self):
        with pytest.raises(InvalidFieldError) as caught:
            AHv6(
                next_header=6,
                payload_len=5,
                reserved=0,
                spi=1,
                sequence_number=1,
                icv=ICV,
            )
        assert caught.value.protocol is AHv6
        assert caught.value.offset is None
        assert caught.value.actual == 28


class TestWalk:
    def test_ipv4_ah_tcp(self):
        frame = v4_frame(make_ah(6), syn())
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet.layers] == [
            Ethernet,
            IPv4,
            AH,
            TCP,
        ]
        assert packet.consumed == len(frame)

    def test_ipv6_ah_destination_options_udp(self):
        payload = b"NETProtocols AH test"
        dst_opts = IPv6DestinationOptions(
            next_header=17, hdr_ext_len=0, options=b"\x01\x04" + bytes(4)
        )
        frame = v6_frame(
            make_ah(60, cls=AHv6), dst_opts, udp(payload), payload=payload
        )
        assert chain(frame) == [
            Ethernet,
            IPv6,
            AHv6,
            IPv6DestinationOptions,
            UDP,
        ]

    def test_ipv6_hop_by_hop_ah_icmpv6(self):
        hop = IPv6HopByHopOptions(
            next_header=51, hdr_ext_len=0, options=b"\x01\x04" + bytes(4)
        )
        frame = v6_frame(hop, make_ah(58, cls=AHv6), echo_v6(), next_header=0)
        assert chain(frame) == [
            Ethernet,
            IPv6,
            IPv6HopByHopOptions,
            AHv6,
            ICMPv6,
        ]

    @pytest.mark.parametrize("family", ["ipv4", "ipv6"])
    def test_every_layer_round_trips_byte_exactly(self, family):
        if family == "ipv4":
            frame = v4_frame(make_ah(6), syn())
        else:
            frame = v6_frame(make_ah(6, cls=AHv6), syn())
        cursor = 0
        for layer in decode_frame(frame).layers:
            assert bytes(layer) == frame[cursor : cursor + layer.header_len]
            cursor += layer.header_len
        assert cursor == len(frame)

    @pytest.mark.parametrize("family", ["ipv4", "ipv6"])
    def test_with_checksums_reaches_past_ah(self, family):
        # The transport's pseudo-header is the IP header's, two layers
        # up: with_checksums() takes the nearest IP header, so AH in
        # between changes nothing.
        payload = b"NETProtocols AH test"
        if family == "ipv4":
            frame = v4_frame(make_ah(17), udp(payload), payload=payload)
        else:
            frame = v6_frame(
                make_ah(17, cls=AHv6), udp(payload), payload=payload
            )
        packet = decode_frame(frame)
        assert packet[UDP].checksum != 0
        assert packet.with_checksums(payload) == packet
        blank = Packet(*packet.layers[:-1], replace(packet[UDP], checksum=0))
        assert blank.with_checksums(payload) == packet

    def test_a_hostile_stack_of_ah_hits_the_depth_ceiling(self):
        layers = [make_ah(51) for _ in range(40)]
        with pytest.raises(MaxDepthExceededError):
            decode_frame(v4_frame(*layers))


class TestCorpusAH:
    FRAMES = pcap_frames(FIXTURES / "ah.pcap")

    def test_chains(self):
        assert [chain(frame) for frame in self.FRAMES] == [
            [Ethernet, IPv4, AH, TCP],
            [Ethernet, IPv4, AH, ICMPv4],
            [Ethernet, IPv4, AH, UDP],
            [Ethernet, IPv4, AH, IPv4, ICMPv4],
            [Ethernet, IPv4, AH, IPv4, TCP],
            [Ethernet, IPv4, AH, ESP],
        ]

    def test_spis_and_sequence_numbers(self):
        decoded = [decode_frame(frame)[AH] for frame in self.FRAMES]
        assert [(ah.spi, ah.sequence_number) for ah in decoded] == [
            (0x20000001, 1),
            (0x20000001, 2),
            (0x20000001, 3),
            (0x20000002, 1),
            (0x20000002, 2),
            (0x20000003, 1),
        ]
        assert {(ah.payload_len, len(ah.icv)) for ah in decoded} == {(5, 16)}

    def test_the_icvs_verify(self):
        # RFC 4302 §3.3.3: the IPv4 header with its mutable fields
        # zeroed, AH with its ICV zeroed, then the payload. Built from
        # the decoded layers, so this also checks they re-encode exactly.
        for frame in self.FRAMES:
            packet = decode_frame(frame)
            ip, ah = packet[IPv4], packet[AH]
            immutable = replace(
                ip, dscp=0, ecn=0, flags=0, fragment_offset=0, ttl=0, checksum=0
            )
            start = 14 + ip.header_len + ah.header_len
            protected = (
                bytes(immutable)
                + bytes(replace(ah, icv=bytes(len(ah.icv))))
                + frame[start : 14 + ip.total_length]
            )
            mac = hmac.new(AH_KEYS[ah.spi], protected, hashlib.sha256)
            assert ah.icv == mac.digest()[:ICV_LEN]

    def test_the_outer_headers_are_the_scripts(self):
        for index, frame in enumerate(self.FRAMES):
            ip = decode_frame(frame)[IPv4]
            assert (ip.src, ip.dst, ip.protocol) == (
                "10.9.11.1",
                "10.9.11.2",
                51,
            )
            assert ip.identification == 0xA101 + index
            assert (ip.dscp, ip.flags, ip.ttl) == (10, 0b010, 64)

    def test_recomputed_checksums_match_the_wire(self):
        # check_fixtures.py, which shares no code with this library,
        # verified every checksum behind AH; with_checksums() must agree.
        for frame in self.FRAMES:
            packet = decode_frame(frame)
            payload = frame[packet.consumed :]
            assert packet.with_checksums(payload) == packet

    def test_the_bundle_carries_a_verifiable_esp_packet(self):
        esp = decode_frame(self.FRAMES[-1])[ESP]
        assert (esp.spi, esp.sequence_number) == (0x10000003, 1)
        protected = bytes(esp)[:-ICV_LEN]
        mac = hmac.new(ESP_BUNDLE_KEY, protected, hashlib.sha256)
        assert esp.ciphertext[-ICV_LEN:] == mac.digest()[:ICV_LEN]
        assert protected[-1] == 1  # Next Header: ICMP

    def test_the_test_keys_are_the_published_ones(self):
        manifest = (FIXTURES / "MANIFEST.md").read_text()
        for spi, key in [*AH_KEYS.items(), (0x10000003, ESP_BUNDLE_KEY)]:
            assert f"0x{spi:08x}" in manifest
            assert key.hex() in manifest
