import pytest

from netprotocols import (
    ICMPv4,
    ICMPv6,
    InvalidFieldError,
    IPv4,
    IPv6,
    NDPOption,
    TruncatedHeaderError,
)

#: The target of the corpus Neighbor Solicitation/Advertisement pair.
NDP_TARGET = bytes.fromhex("fe80000000000000f6d78b9a993e5efa")


def make_ndp(type_: int, body: bytes) -> ICMPv6:
    return ICMPv6(type=type_, code=0, checksum=0, rest=b"\x00" * 4, body=body)


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

    def test_embedded_chain_decodes_the_truncated_original(
        self, raw_ipv4_header
    ):
        """RFC 792 quotes only the invoking IP header plus 8 bytes of
        what follows — never a full TCP header — so this is a routine
        partial decode, not malformed input: no try/except needed, and
        the walk reports why it stopped rather than raising."""
        original = raw_ipv4_header + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        icmp = ICMPv4.decode(b"\x0b\x00\x00\x00\x00\x00\x00\x00" + original)
        chain = icmp.embedded_chain
        assert chain is not None
        assert len(chain) == 1
        assert isinstance(chain[0], IPv4)
        assert chain[0].src == "192.168.1.96"
        assert isinstance(chain.stopped_by, TruncatedHeaderError)

    def test_echo_types_have_no_embedded_chain(self, raw_icmpv4_echo_request):
        assert ICMPv4.decode(raw_icmpv4_echo_request).embedded_chain is None

    def test_embedded_chain_with_an_empty_body_degrades_to_none(self):
        icmp = ICMPv4(type=11, code=0, checksum=0, rest=b"\x00" * 4)
        assert icmp.embedded_chain is None

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

    def test_embedded_chain_decodes_the_truncated_original(
        self, raw_ipv6_header
    ):
        """As RFC 792 for ICMPv4 error messages: the invoking header
        plus a truncated transport header (RFC 4443 uses "as much of
        the invoking packet as fits" rather than a fixed 8 bytes, but
        a short quote is equally routine) decodes as far as it can,
        with no try/except and no raise for the truncation."""
        original = raw_ipv6_header + b"\x01\x02\x03\x04\x05\x06\x07\x08"
        icmp = ICMPv6.decode(b"\x03\x00\x00\x00\x00\x00\x00\x00" + original)
        chain = icmp.embedded_chain
        assert chain is not None
        assert len(chain) == 1
        assert isinstance(chain[0], IPv6)
        assert chain[0].src == "fe80::1"
        assert isinstance(chain.stopped_by, TruncatedHeaderError)

    def test_echo_types_have_no_embedded_chain(self, raw_icmpv6_echo_request):
        assert ICMPv6.decode(raw_icmpv6_echo_request).embedded_chain is None

    def test_embedded_chain_with_an_empty_body_degrades_to_none(self):
        icmp = ICMPv6(type=1, code=0, checksum=0, rest=b"\x00" * 4)
        assert icmp.embedded_chain is None

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


class TestNDP:
    def test_neighbor_solicitation_target_and_slla(self):
        """The wire layout of the corpus NS: 16-byte target, then a
        Source Link-Layer Address option."""
        icmp = make_ndp(135, NDP_TARGET + b"\x01\x01\x84\x01\x12\xbe\x7e\xd9")
        assert icmp.ndp_target_address == "fe80::f6d7:8b9a:993e:5efa"
        assert icmp.ndp_options is not None
        (option,) = icmp.ndp_options
        assert option.type == 1
        assert option.type_name == "Source Link-Layer Address"
        assert option.link_layer_address == "84:01:12:be:7e:d9"

    def test_neighbor_advertisement_without_options(self):
        icmp = make_ndp(136, NDP_TARGET)
        assert icmp.ndp_target_address == "fe80::f6d7:8b9a:993e:5efa"
        assert icmp.ndp_options == ()

    def test_router_advertisement_mtu_and_prefix_information(self):
        """RA options follow the 8 bytes of timers; MTU and Prefix
        Information are exposed raw."""
        mtu = b"\x05\x01\x00\x00\x00\x00\x05\xdc"
        prefix = b"\x03\x04\x40\xc0" + b"\x00" * 12 + NDP_TARGET
        icmp = make_ndp(134, b"\x00" * 8 + mtu + prefix)
        options = icmp.ndp_options
        assert options is not None
        assert [option.type for option in options] == [5, 3]
        assert options[0].type_name == "MTU"
        assert options[0].data == b"\x00\x00\x00\x00\x05\xdc"
        assert options[0].link_layer_address is None
        assert options[1].type_name == "Prefix Information"
        assert options[1].data == b"\x40\xc0" + b"\x00" * 12 + NDP_TARGET
        assert icmp.ndp_target_address is None  # targets are NS/NA-only

    def test_router_solicitation_options_start_at_the_body(self):
        icmp = make_ndp(133, b"\x01\x01\x84\x01\x12\xbe\x7e\xd9")
        assert icmp.ndp_options is not None
        (option,) = icmp.ndp_options
        assert option.type == 1

    def test_redirect_options_follow_target_and_destination(self):
        icmp = make_ndp(
            137, NDP_TARGET * 2 + b"\x02\x01\xa8\x3b\x76\xda\xa6\x9d"
        )
        assert icmp.ndp_options is not None
        (option,) = icmp.ndp_options
        assert option.type == 2
        assert option.type_name == "Target Link-Layer Address"
        assert option.link_layer_address == "a8:3b:76:da:a6:9d"

    def test_non_ndp_types_return_none(self):
        echo = make_ndp(128, b"payload")
        assert echo.ndp_target_address is None
        assert echo.ndp_options is None

    def test_short_ns_body_degrades_the_target_to_none(self):
        assert make_ndp(135, NDP_TARGET[:8]).ndp_target_address is None

    def test_body_ending_before_the_fixed_fields_raises(self):
        with pytest.raises(InvalidFieldError):
            _ = make_ndp(135, NDP_TARGET[:8]).ndp_options

    def test_zero_option_length_must_not_loop(self):
        with pytest.raises(InvalidFieldError):
            _ = make_ndp(133, b"\x01\x00\x84\x01\x12\xbe\x7e\xd9").ndp_options

    def test_option_running_past_the_message_raises(self):
        with pytest.raises(InvalidFieldError):
            _ = make_ndp(133, b"\x01\x02\x84\x01\x12\xbe\x7e\xd9").ndp_options

    def test_option_missing_its_length_byte_raises(self):
        with pytest.raises(InvalidFieldError):
            _ = make_ndp(136, NDP_TARGET + b"\x01").ndp_options

    def test_unknown_option_type_keeps_raw_data(self):
        icmp = make_ndp(133, b"\x19\x01\x00\x00\x0e\x10\x00\x00")
        assert icmp.ndp_options is not None
        (option,) = icmp.ndp_options
        assert option.type == 25
        assert option.type_name == "unknown (25)"
        assert option.data == b"\x00\x00\x0e\x10\x00\x00"
        assert option.link_layer_address is None

    def test_lla_of_a_non_ethernet_length_degrades_to_none(self):
        assert NDPOption(type=1, data=b"\x00" * 14).link_layer_address is None

    def test_round_trip_unchanged_by_parsing(self):
        raw = b"\x87\x00\x1c\x2a\x00\x00\x00\x00" + NDP_TARGET
        icmp = ICMPv6.decode(raw)
        _ = icmp.ndp_target_address
        _ = icmp.ndp_options
        assert bytes(icmp) == raw
