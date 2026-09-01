import pytest

from netprotocols import ICMPv4, ICMPv6, InvalidFieldError, IPv4, IPv6


class TestICMPv4:
    def test_decode_captures_the_body(self, raw_icmpv4_echo_request):
        """The fixture carries a full ping payload after the 8-byte
        header; decode keeps it as the raw body, so the message consumes
        its whole IP payload."""
        icmp = ICMPv4.decode(raw_icmpv4_echo_request)
        assert icmp.type == 8
        assert icmp.code == 0
        assert icmp.checksum == 0x83F7
        assert icmp.checksum_hex_str == "0x83f7"
        assert icmp.rest == b"\x00\x01\x00\x01"
        assert icmp.type_name == "Echo Request"
        assert icmp.body == raw_icmpv4_echo_request[8:]
        assert icmp.header_len == len(raw_icmpv4_echo_request)

    def test_round_trip(self, raw_icmpv4_echo_request):
        icmp = ICMPv4.decode(raw_icmpv4_echo_request)
        assert bytes(icmp) == raw_icmpv4_echo_request
        assert ICMPv4.decode(bytes(icmp)) == icmp

    def test_echo_identifier_and_sequence(self, raw_icmpv4_echo_request):
        icmp = ICMPv4.decode(raw_icmpv4_echo_request)
        assert icmp.identifier == 1
        assert icmp.sequence_number == 1

    def test_non_echo_types_have_no_echo_fields(self):
        icmp = ICMPv4(type=11, code=0, checksum=0, rest=b"\x00" * 4)
        assert icmp.identifier is None
        assert icmp.sequence_number is None

    def test_error_embeds_the_invoking_packet(self, raw_ipv4_header):
        """A Time Exceeded body starts at the original datagram's IPv4
        header, which must decode."""
        original = raw_ipv4_header + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        icmp = ICMPv4.decode(b"\x0b\x00\x00\x00\x00\x00\x00\x00" + original)
        assert icmp.embedded_packet == original
        embedded = IPv4.decode(icmp.embedded_packet)
        assert embedded.src == "192.168.1.96"
        assert embedded.dst == "192.168.1.254"

    def test_echo_types_have_no_embedded_packet(self, raw_icmpv4_echo_request):
        assert ICMPv4.decode(raw_icmpv4_echo_request).embedded_packet is None

    def test_error_with_an_empty_body_degrades_to_none(self):
        icmp = ICMPv4(type=11, code=0, checksum=0, rest=b"\x00" * 4)
        assert icmp.embedded_packet is None

    def test_unknown_type_name(self):
        icmp = ICMPv4(type=200, code=0, checksum=0, rest=b"\x00" * 4)
        assert icmp.type_name == "Unknown, Unassigned or Deprecated"

    def test_invalid_rest_length_rejected(self):
        with pytest.raises(InvalidFieldError):
            ICMPv4(type=8, code=0, checksum=0, rest=b"\x00\x01")


class TestICMPv6:
    def test_decode(self, raw_icmpv6_echo_request):
        icmp = ICMPv6.decode(raw_icmpv6_echo_request)
        assert icmp.type == 128
        assert icmp.code == 0
        assert icmp.checksum == 0x3F69
        assert icmp.rest == b"\x76\x20\x01\x00"
        assert icmp.type_name == "Echo Request"
        assert icmp.body == raw_icmpv6_echo_request[8:]
        assert icmp.header_len == len(raw_icmpv6_echo_request)

    def test_round_trip(self, raw_icmpv6_echo_request):
        icmp = ICMPv6.decode(raw_icmpv6_echo_request)
        assert bytes(icmp) == raw_icmpv6_echo_request
        assert ICMPv6.decode(bytes(icmp)) == icmp

    def test_echo_identifier_and_sequence(self, raw_icmpv6_echo_request):
        icmp = ICMPv6.decode(raw_icmpv6_echo_request)
        assert icmp.identifier == 0x7620
        assert icmp.sequence_number == 0x0100

    def test_error_embeds_the_invoking_packet(self, raw_ipv6_header):
        """A Time Exceeded (v6 type 3) body starts at the original
        datagram's IPv6 header, which must decode."""
        icmp = ICMPv6.decode(
            b"\x03\x00\x00\x00\x00\x00\x00\x00" + raw_ipv6_header
        )
        assert icmp.embedded_packet == raw_ipv6_header
        assert icmp.identifier is None
        embedded = IPv6.decode(icmp.embedded_packet)
        assert embedded.src == "fe80::1"

    def test_ndp_types_have_no_echo_or_error_fields(self):
        icmp = ICMPv6(
            type=135, code=0, checksum=0, rest=b"\x00" * 4, body=b"\x00" * 16
        )
        assert icmp.identifier is None
        assert icmp.sequence_number is None
        assert icmp.embedded_packet is None

    def test_v4_and_v6_type_tables_differ(self):
        assert (
            ICMPv4(type=0, code=0, checksum=0, rest=b"\x00" * 4).type_name
            == "Echo Reply"
        )
        assert (
            ICMPv6(type=129, code=0, checksum=0, rest=b"\x00" * 4).type_name
            == "Echo Reply"
        )
