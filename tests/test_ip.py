import pytest

from netprotocols import TCP, InvalidFieldError, IPv4, IPv6


class TestIPv4:
    def test_decode(self, raw_ipv4_header):
        ip = IPv4.decode(raw_ipv4_header)
        assert ip.version == 4
        assert ip.ihl == 5
        assert ip.dscp == 0
        assert ip.ecn == 0
        assert ip.total_length == 40
        assert ip.identification == 0xEC6C
        assert ip.flags == 2
        assert ip.flags_name == "Don't fragment (DF)"
        assert ip.fragment_offset == 0
        assert ip.ttl == 64
        assert ip.protocol == 6
        assert ip.protocol_name == "TCP"
        assert ip.checksum == 0x2B51
        assert ip.checksum_hex_str == "0x2b51"
        assert ip.src == "192.168.1.96"
        assert ip.dst == "192.168.1.254"
        assert ip.options == b""
        assert ip.header_len == 20

    def test_round_trip(self, raw_ipv4_header):
        ip = IPv4.decode(raw_ipv4_header)
        assert bytes(ip) == raw_ipv4_header
        assert IPv4.decode(bytes(ip)) == ip

    def test_next_protocol(self, raw_ipv4_header):
        assert IPv4.decode(raw_ipv4_header).next_protocol() is TCP

    def test_decode_with_options(self, raw_ipv4_header):
        """An IHL of 6 makes the 4 bytes after the fixed header part of
        this header (options), not part of the payload."""
        options = b"\x94\x04\x00\x00"  # router alert
        raw = b"\x46" + raw_ipv4_header[1:20] + options + b"\xde\xad\xbe\xef"
        ip = IPv4.decode(raw)
        assert ip.ihl == 6
        assert ip.header_len == 24
        assert ip.options == options
        assert bytes(ip) == raw[:24]

    def test_ihl_options_mismatch_rejected(self):
        with pytest.raises(InvalidFieldError):
            IPv4(
                version=4,
                ihl=5,
                dscp=0,
                ecn=0,
                total_length=44,
                identification=1,
                flags=0,
                fragment_offset=0,
                ttl=64,
                protocol=6,
                checksum=0,
                src="192.168.1.96",
                dst="192.168.1.254",
                options=b"\x94\x04\x00\x00",
            )


class TestIPv6:
    def test_decode(self, raw_ipv6_header):
        ip = IPv6.decode(raw_ipv6_header)
        assert ip.version == 6
        assert ip.traffic_class == 0
        assert ip.flow_label == 0
        assert ip.payload_length == 120
        assert ip.next_header == 6
        assert ip.next_header_name == "TCP"
        assert ip.hop_limit == 255
        assert ip.src == "fe80::1"
        assert ip.dst == "ff02::1"
        assert ip.header_len == 40

    def test_round_trip(self, raw_ipv6_header):
        ip = IPv6.decode(raw_ipv6_header)
        assert bytes(ip) == raw_ipv6_header
        assert IPv6.decode(bytes(ip)) == ip

    def test_next_protocol(self, raw_ipv6_header):
        assert IPv6.decode(raw_ipv6_header).next_protocol() is TCP

    def test_hex_display_properties(self, raw_ipv6_header):
        ip = IPv6.decode(raw_ipv6_header)
        assert ip.traffic_class_hex_str == "0x00"
        assert ip.flow_label_hex_str == "0x00000"
