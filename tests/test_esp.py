"""ESP, IPsec's Encapsulating Security Payload (RFC 4303), IP protocol
50: the cleartext SPI and sequence number decode, the protected
remainder stays opaque, and the chain ends there by design.

The corpus frames (``esp.pcap``) are NULL-encrypted (RFC 2410), so these
tests can also check, with the test keys MANIFEST.md publishes, that
the opaque bytes really are the protected payload: the ICV verifies and
the inner packet decodes. That is the test suite reading the trailer,
with the key in hand; the library itself never does."""

import hashlib
import hmac

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    ESP,
    UDP,
    ICMPv4,
    IPProtocol,
    IPv4,
    IPv6,
    IPv6DestinationOptions,
    Packet,
    Registry,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_IP_PROTO, TABLE_IP_PROTO_V6
from test_ipip import ethernet, make_ipv4, make_ipv6

#: The published test keys (tests/fixtures/MANIFEST.md), by SPI. Both
#: SAs use HMAC-SHA-256-128 (RFC 4868) over NULL encryption.
ESP_KEYS = {
    0x10000001: bytes.fromhex(
        "e41126360fbc54a0e11a8747218b24d0cc4638f579c3985017b4d0ab1a30398b"
    ),
    0x10000002: bytes.fromhex(
        "4bc3ce948208049b2f5016e06616867773924d2ccb4dab8b3aff93e6d26f3834"
    ),
}
ICV_LEN = 16

CIPHERTEXT = b"\xde\xad\xbe\xef" * 6


def esp_frame(outer: str) -> bytes:
    """``Ethernet → IPv4|IPv6 → ESP`` with an opaque 24-byte remainder."""
    esp = ESP(spi=0x1234, sequence_number=7, ciphertext=CIPHERTEXT)
    if outer == "ipv4":
        ip: IPv4 | IPv6 = make_ipv4(protocol=50, payload_len=esp.header_len)
        eth = ethernet(0x0800)
    else:
        ip = make_ipv6(next_header=50, payload_len=esp.header_len)
        eth = ethernet(0x86DD)
    return bytes(Packet(eth, ip, esp).with_checksums())


def null_esp_payload(esp: ESP) -> tuple[int, bytes]:
    """The (Next Header, payload) a NULL-encrypted ESP packet protects,
    after checking its ICV and RFC 4303 §2.4 default padding — what a
    receiver holding the key would do, done here by the test."""
    protected = bytes(esp)[:-ICV_LEN]
    expected = hmac.new(ESP_KEYS[esp.spi], protected, hashlib.sha256)
    assert esp.ciphertext[-ICV_LEN:] == expected.digest()[:ICV_LEN]
    pad_len, next_header = protected[-2], protected[-1]
    end = len(protected) - 2 - pad_len
    assert protected[end:-2] == bytes(range(1, pad_len + 1))
    return next_header, protected[8:end]


class TestWiring:
    def test_protocol_number_and_display_name(self):
        assert IPProtocol.ESP == 50
        assert IPProtocol.ESP.display_name == "ESP"

    @pytest.mark.parametrize("table", [TABLE_IP_PROTO, TABLE_IP_PROTO_V6])
    def test_both_ip_tables_carry_protocol_50(self, table):
        # Registered once in ip.proto; ip.proto.v6 inherits it.
        assert DEFAULT.get(table, 50) is ESP

    def test_ipv4_dispatches_to_esp(self):
        ip = make_ipv4(protocol=50, payload_len=32)
        assert ip.next_protocol() is ESP
        assert ip.protocol_name == "ESP"
        assert ip.protocol_enum is IPProtocol.ESP

    def test_ipv6_dispatches_to_esp(self):
        ip = make_ipv6(next_header=50, payload_len=32)
        assert ip.next_protocol() is ESP
        assert ip.next_header_name == "ESP"


class TestDecode:
    def test_fixed_fields(self, raw_esp_packet):
        esp = ESP.decode(raw_esp_packet)
        assert esp.spi == 0x10000001
        assert esp.sequence_number == 1
        assert esp.ciphertext == raw_esp_packet[8:]
        assert esp.header_len == len(raw_esp_packet)

    def test_wire_to_object_to_wire(self, raw_esp_packet):
        assert bytes(ESP.decode(raw_esp_packet)) == raw_esp_packet

    def test_object_to_wire_to_object(self):
        esp = ESP(spi=0xFFFFFFFF, sequence_number=0x80000000, ciphertext=b"x")
        assert ESP.decode(bytes(esp)) == esp

    def test_memoryview_is_materialized(self, raw_esp_packet):
        buffer = bytearray(raw_esp_packet)
        esp = ESP.decode(memoryview(buffer))
        buffer[:] = bytes(len(buffer))
        assert type(esp.ciphertext) is bytes
        assert bytes(esp) == raw_esp_packet

    def test_the_fixed_prefix_alone_decodes(self):
        # Nothing about the remainder is knowable, including that one
        # must exist, so an empty one is not an error.
        esp = ESP.decode(b"\x00\x00\x01\x00\x00\x00\x00\x2a")
        assert (esp.spi, esp.sequence_number, esp.ciphertext) == (256, 42, b"")
        assert esp.header_len == 8

    def test_ciphertext_defaults_to_empty(self):
        assert ESP(spi=1, sequence_number=1).ciphertext == b""

    @pytest.mark.parametrize("length", range(8))
    def test_truncated_fixed_prefix(self, raw_esp_packet, length):
        with pytest.raises(TruncatedHeaderError) as caught:
            ESP.decode(raw_esp_packet[:length])
        err = caught.value
        assert err.protocol is ESP
        assert err.offset == 0
        assert (err.expected, err.actual) == (8, length)

    def test_spi_hex_str(self, raw_esp_packet):
        assert ESP.decode(raw_esp_packet).spi_hex_str == "0x10000001"
        assert ESP(spi=0x100, sequence_number=0).spi_hex_str == "0x00000100"

    def test_reserved_spis_are_carried_not_rejected(self):
        assert ESP.decode(bytes(8)).spi == 0


class TestDeadEnd:
    """next_protocol() is None whatever the bytes say, by design: the
    Next Header that names the payload is inside the protected region,
    at an offset only the SA's algorithms determine."""

    def test_next_protocol_is_none(self, raw_esp_packet):
        assert ESP.decode(raw_esp_packet).next_protocol() is None

    def test_no_registry_can_change_that(self, raw_esp_packet):
        # Even a registry with an entry for the trailer's next-header
        # value (1, ICMP, in this packet) is never consulted.
        registry = Registry.from_defaults()
        assert ESP.decode(raw_esp_packet).next_protocol(registry) is None


class TestWalk:
    @pytest.mark.parametrize(
        "outer,ip_type", [("ipv4", IPv4), ("ipv6", IPv6)], ids=["v4", "v6"]
    )
    def test_the_walk_ends_at_esp(self, outer, ip_type):
        frame = esp_frame(outer)
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet.layers][1:] == [ip_type, ESP]
        assert packet.consumed == len(frame)
        assert packet[ESP].ciphertext == CIPHERTEXT
        assert packet.stopped_by is None

    @pytest.mark.parametrize("outer", ["ipv4", "ipv6"])
    def test_every_layer_round_trips_byte_exactly(self, outer):
        frame = esp_frame(outer)
        cursor = 0
        for layer in decode_frame(frame).layers:
            assert bytes(layer) == frame[cursor : cursor + layer.header_len]
            cursor += layer.header_len

    def test_ipv6_destination_options_lead_to_esp(self):
        # RFC 4303 §3.1.1: under IPv6, Destination Options may precede
        # ESP; the extension header's next_header reaches protocol 50
        # through the v6 table just as the fixed header's does.
        esp = ESP(spi=0x1234, sequence_number=7, ciphertext=CIPHERTEXT)
        options = IPv6DestinationOptions(
            next_header=50, hdr_ext_len=0, options=b"\x01\x04\x00\x00\x00\x00"
        )
        ip = make_ipv6(next_header=60, payload_len=8 + esp.header_len)
        frame = bytes(Packet(ethernet(0x86DD), ip, options, esp))
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet.layers][1:] == [
            IPv6,
            IPv6DestinationOptions,
            ESP,
        ]
        assert packet[ESP] == esp
        assert packet.consumed == len(frame)

    def test_link_layer_padding_lands_in_the_ciphertext(self):
        # The documented contract, shared with ICMP's body: the
        # remainder runs to the end of the frame, so a datagram shorter
        # than Ethernet's 60-byte minimum (14 + 20 + 8 + 4 = 46 here)
        # brings the padding with it, and the ciphertext's tail is that
        # padding, not the ICV.
        esp = ESP(spi=0x1234, sequence_number=7, ciphertext=b"\xde\xad\xbe\xef")
        ip = make_ipv4(protocol=50, payload_len=esp.header_len)
        datagram = bytes(Packet(ethernet(0x0800), ip, esp).with_checksums())
        assert len(datagram) == 46
        frame = datagram + bytes(14)
        packet = decode_frame(frame)
        decoded = packet[ESP]
        assert decoded.ciphertext == b"\xde\xad\xbe\xef" + bytes(14)
        ip_len = packet[IPv4].total_length - 20
        assert len(decoded.ciphertext) == ip_len - 8 + 14
        assert packet.consumed == len(frame)

    def test_a_truncated_prefix_is_reported_at_its_frame_offset(self):
        frame = esp_frame("ipv6")[: 14 + 40 + 5]
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(frame)
        assert caught.value.protocol is ESP
        assert caught.value.frame_offset == 14 + 40

    def test_lax_mode_keeps_the_ip_header(self):
        packet = decode_frame(esp_frame("ipv4")[: 14 + 20 + 3], lax=True)
        assert isinstance(packet.layers[-1], IPv4)
        assert isinstance(packet.stopped_by, TruncatedHeaderError)


class TestCorpusESP:
    FRAMES = pcap_frames(FIXTURES / "esp.pcap")

    def test_every_frame_ends_at_esp(self):
        for frame in self.FRAMES:
            packet = decode_frame(frame)
            assert [type(layer).__name__ for layer in packet.layers] == [
                "Ethernet",
                "IPv4",
                "ESP",
            ]
            assert packet.consumed == len(frame)

    def test_spis_and_sequence_numbers(self):
        decoded = [decode_frame(frame)[ESP] for frame in self.FRAMES]
        assert [(esp.spi, esp.sequence_number) for esp in decoded] == [
            (0x10000001, 1),
            (0x10000001, 2),
            (0x10000001, 3),
            (0x10000002, 1),
            (0x10000002, 2),
            (0x10000002, 3),
        ]

    def test_ciphertext_is_exactly_the_rest_of_the_datagram(self):
        # No link-layer trailer was absorbed: each frame is longer than
        # Ethernet's minimum, so the ciphertext ends where the outer
        # header's total length says the datagram does.
        for frame in self.FRAMES:
            packet = decode_frame(frame)
            ip, esp = packet[IPv4], packet[ESP]
            assert len(esp.ciphertext) == ip.total_length - ip.header_len - 8

    def test_the_icvs_verify_and_the_payload_is_what_the_trailer_says(self):
        expected = [(1, ICMPv4)] * 2 + [(17, UDP)] + [(4, IPv4)] * 3
        for frame, (number, cls) in zip(self.FRAMES, expected, strict=True):
            packet = decode_frame(frame)
            next_header, payload = null_esp_payload(packet[ESP])
            assert next_header == number
            inner = decode_frame(payload, start=cls)
            assert type(inner.layers[0]) is cls
            # The protected packet's own checksums hold. In transport
            # mode its pseudo-header is the outer IP header's, so that
            # header is put back in front before recomputing.
            outer = () if cls is IPv4 else (packet[IPv4],)
            rebuilt = Packet(*outer, *inner.layers)
            assert rebuilt.with_checksums(payload[inner.consumed :]) == rebuilt

    def test_transport_mode_payloads(self):
        for frame in self.FRAMES[:2]:
            _, payload = null_esp_payload(decode_frame(frame)[ESP])
            icmp = ICMPv4.decode(payload)
            assert (icmp.type, icmp.body) == (8, b"NETProtocols ESP fixture")

    def test_tunnel_mode_payloads_are_whole_inner_packets(self):
        for frame in self.FRAMES[3:]:
            _, payload = null_esp_payload(decode_frame(frame)[ESP])
            ip = IPv4.decode(payload)
            assert (ip.src, ip.dst) == ("192.0.2.1", "192.0.2.2")
            assert ip.total_length == len(payload)

    def test_the_outer_headers_are_checksummed_ipv4_carrying_esp(self):
        # Which bytes the kernel built is established by the capture
        # script's byte-for-byte compare step, not by anything visible
        # here: no field of an IPv4 header records who wrote it.
        for frame in self.FRAMES:
            ip = decode_frame(frame)[IPv4]
            assert (ip.src, ip.dst, ip.protocol) == (
                "10.9.11.1",
                "10.9.11.2",
                50,
            )
            assert decode_frame(frame).with_checksums() == decode_frame(frame)

    def test_the_test_keys_are_the_published_ones(self):
        manifest = (FIXTURES / "MANIFEST.md").read_text()
        for spi, key in ESP_KEYS.items():
            assert f"0x{spi:08x}" in manifest
            assert key.hex() in manifest
