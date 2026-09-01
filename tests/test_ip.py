import pytest

from netprotocols import TCP, InvalidFieldError, IPv4, IPv4Option, IPv6


def ipv4_with_options(options: bytes) -> IPv4:
    """A minimal header carrying ``options`` (padded to whole words)."""
    if len(options) % 4:
        options += b"\x00" * (4 - len(options) % 4)
    return IPv4(
        version=4,
        ihl=5 + len(options) // 4,
        dscp=0,
        ecn=0,
        total_length=20 + len(options),
        identification=1,
        flags=2,
        fragment_offset=0,
        ttl=64,
        protocol=6,
        checksum=0,
        src="192.0.2.1",
        dst="192.0.2.2",
        options=options,
    )


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


class TestIPv4Options:
    def test_router_alert_from_a_decoded_header(self, raw_ipv4_header):
        """The IHL-6 header of test_decode_with_options: a Router Alert
        (RFC 2113) parses out of the decoded raw options."""
        raw = b"\x46" + raw_ipv4_header[1:20] + b"\x94\x04\x00\x00"
        ip = IPv4.decode(raw)
        (alert,) = ip.parsed_options
        assert alert.kind == 148
        assert alert.kind_name == "Router Alert"
        assert alert.data == b"\x00\x00"
        assert bytes(ip) == raw  # parsing never re-encodes

    def test_record_route(self):
        """NOP + Record Route (a pointer, then two recorded hops)."""
        route_data = b"\x04\xc0\x00\x02\x01\xc0\x00\x02\x02"
        ip = ipv4_with_options(b"\x01" + b"\x07\x0b" + route_data)
        nop, record = ip.parsed_options
        assert nop.kind == 1
        assert nop.kind_name == "No-Operation"
        assert nop.data == b""
        assert record.kind == 7
        assert record.kind_name == "Record Route"
        assert record.data == route_data

    def test_timestamp(self):
        stamps = b"\x05\x00" + b"\x00\x01\x86\xa0" + b"\x00\x01\x86\xa4"
        ip = ipv4_with_options(b"\x44\x0c" + stamps)
        (timestamp,) = ip.parsed_options
        assert timestamp.kind == 68
        assert timestamp.kind_name == "Timestamp"
        assert timestamp.data == stamps

    def test_eol_ends_the_parse(self):
        """Padding after an End of Option List is not returned as more
        options."""
        ip = ipv4_with_options(b"\x94\x04\x00\x00\x00\x00\x00\x00")
        assert [option.kind for option in ip.parsed_options] == [148, 0]
        assert ip.parsed_options[1].kind_name == "End of Option List"

    def test_unknown_kind_keeps_raw_data(self):
        ip = ipv4_with_options(b"\x83\x07\x04\xc0\x00\x02\x01\x01")
        options = ip.parsed_options
        assert options[0].kind == 131  # Loose Source Route, unnamed here
        assert options[0].kind_name == "unknown (131)"
        assert options[0].data == b"\x04\xc0\x00\x02\x01"
        assert options[1].kind == 1

    def test_no_options_parses_empty(self, raw_ipv4_header):
        assert IPv4.decode(raw_ipv4_header).parsed_options == ()

    def test_missing_length_byte_raises(self):
        ip = ipv4_with_options(b"\x01\x01\x01\x94")
        with pytest.raises(InvalidFieldError):
            _ = ip.parsed_options

    def test_length_below_the_minimum_raises(self):
        ip = ipv4_with_options(b"\x94\x01\x00\x00")
        with pytest.raises(InvalidFieldError):
            _ = ip.parsed_options

    def test_length_past_the_options_raises(self):
        ip = ipv4_with_options(b"\x94\x08\x00\x00")
        with pytest.raises(InvalidFieldError):
            _ = ip.parsed_options

    def test_direct_construction(self):
        option = IPv4Option(kind=148, data=b"\x00\x00")
        assert option.kind_name == "Router Alert"
        assert IPv4Option(kind=0).data == b""
