import pytest

from netprotocols import ICMPv4, ICMPv6, InvalidFieldError


class TestICMPv4:
    def test_decode_tolerates_trailing_payload(self, raw_icmpv4_echo_request):
        """The fixture carries a full ping payload after the 8-byte
        header; decode must consume only the header."""
        icmp = ICMPv4.decode(raw_icmpv4_echo_request)
        assert icmp.type == 8
        assert icmp.code == 0
        assert icmp.checksum == 0x83F7
        assert icmp.checksum_hex_str == "0x83f7"
        assert icmp.rest == b"\x00\x01\x00\x01"
        assert icmp.type_name == "Echo Request"
        assert icmp.header_len == 8

    def test_round_trip(self, raw_icmpv4_echo_request):
        icmp = ICMPv4.decode(raw_icmpv4_echo_request)
        assert bytes(icmp) == raw_icmpv4_echo_request[:8]
        assert ICMPv4.decode(bytes(icmp)) == icmp

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

    def test_round_trip(self, raw_icmpv6_echo_request):
        icmp = ICMPv6.decode(raw_icmpv6_echo_request)
        assert bytes(icmp) == raw_icmpv6_echo_request[:8]
        assert ICMPv6.decode(bytes(icmp)) == icmp

    def test_v4_and_v6_type_tables_differ(self):
        assert (
            ICMPv4(type=0, code=0, checksum=0, rest=b"\x00" * 4).type_name
            == "Echo Reply"
        )
        assert (
            ICMPv6(type=129, code=0, checksum=0, rest=b"\x00" * 4).type_name
            == "Echo Reply"
        )
