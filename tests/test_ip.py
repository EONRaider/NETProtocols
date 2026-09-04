import socket
from ipaddress import IPv4Address, IPv6Address, ip_network

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netprotocols import (
    TCP,
    InvalidFieldError,
    IPProtocol,
    IPv4,
    IPv4Option,
    IPv6,
)
from netprotocols._base import bytes_to_ipv6, ipv6_to_bytes


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
        assert ip.protocol_enum == IPProtocol.TCP
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

    def test_unknown_protocol_name_degrades(self, raw_ipv4_header):
        unknown = (
            b"\x45" + raw_ipv4_header[1:9] + b"\xfd" + raw_ipv4_header[10:]
        )
        decoded = IPv4.decode(unknown)
        assert decoded.protocol_name == "unknown (253)"
        assert decoded.protocol_enum is None

    def test_ihl_out_of_range_rejected(self, raw_ipv4_header):
        from dataclasses import replace

        with pytest.raises(InvalidFieldError):
            replace(IPv4.decode(raw_ipv4_header), ihl=4)

    def test_address_objects(self, raw_ipv4_header):
        """The `_address` accessors return stdlib ipaddress objects for
        comparison and subnet math; the str fields stay canonical and
        the round-trip is untouched."""
        ip = IPv4.decode(raw_ipv4_header)
        assert ip.src_address == IPv4Address("192.168.1.96")
        assert ip.dst_address == IPv4Address("192.168.1.254")
        assert str(ip.src_address) == ip.src
        assert ip.src_address.is_private
        assert ip.src_address in ip_network("192.168.1.0/24")
        assert int(ip.dst_address) - int(ip.src_address) == 158
        assert bytes(ip) == raw_ipv4_header

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
        assert ip.next_header_enum == IPProtocol.TCP
        assert ip.hop_limit == 255
        assert ip.src == "fe80::1"
        assert ip.dst == "ff02::1"
        assert ip.header_len == 40

    def test_round_trip(self, raw_ipv6_header):
        ip = IPv6.decode(raw_ipv6_header)
        assert bytes(ip) == raw_ipv6_header
        assert IPv6.decode(bytes(ip)) == ip

    def test_address_objects(self, raw_ipv6_header):
        ip = IPv6.decode(raw_ipv6_header)
        assert ip.src_address == IPv6Address("fe80::1")
        assert ip.dst_address == IPv6Address("ff02::1")
        assert str(ip.dst_address) == ip.dst
        assert ip.src_address.is_link_local
        assert ip.dst_address.is_multicast
        assert bytes(ip) == raw_ipv6_header

    def test_next_protocol(self, raw_ipv6_header):
        assert IPv6.decode(raw_ipv6_header).next_protocol() is TCP

    def test_hex_display_properties(self, raw_ipv6_header):
        ip = IPv6.decode(raw_ipv6_header)
        assert ip.traffic_class_hex_str == "0x00"
        assert ip.flow_label_hex_str == "0x00000"

    def test_unknown_next_header_enum_is_none(self, raw_ipv6_header):
        unknown = raw_ipv6_header[:6] + b"\xfd" + raw_ipv6_header[7:]
        decoded = IPv6.decode(unknown)
        assert decoded.next_header_name == "unknown (253)"
        assert decoded.next_header_enum is None

    def test_ipv4_mapped_address_keeps_dotted_form(self, raw_ipv6_header):
        # ::ffff:a.b.c.d (RFC 5952 section 5's still-current mixed
        # notation) — one of the two forms _base.py's hand-rolled
        # bytes_to_ipv6 special-cases to match glibc's inet_ntop
        # exactly (str(ipaddress.IPv6Address(...)) does not, and
        # disagrees with itself across Python versions; see the
        # docstring).
        src = b"\x00" * 10 + b"\xff\xff" + bytes([192, 168, 1, 1])
        header = raw_ipv6_header[:8] + src + raw_ipv6_header[24:]
        ip = IPv6.decode(header)
        assert ip.src == "::ffff:192.168.1.1"
        assert bytes(ip) == header

    def test_ipv4_compatible_legacy_address_keeps_dotted_form(
        self, raw_ipv6_header
    ):
        # ::a.b.c.d without ffff — deprecated by RFC 4291 and absent
        # from real traffic, but glibc's inet_ntop still renders it in
        # dotted-quad, and bytes_to_ipv6 matches that (the other
        # special case in its docstring).
        src = b"\x00" * 12 + bytes([1, 2, 3, 4])
        header = raw_ipv6_header[:8] + src + raw_ipv6_header[24:]
        ip = IPv6.decode(header)
        assert ip.src == "::1.2.3.4"
        assert bytes(ip) == header

    @given(st.binary(min_size=16, max_size=16))
    def test_bytes_to_ipv6_matches_glibc(self, data):
        # bytes_to_ipv6 is a hand-rolled reimplementation of glibc's
        # inet_ntop, kept for Pyodide portability (see _base.py) — this
        # is what guarantees it stays byte-for-byte identical to the
        # platform's own formatting instead of quietly drifting.
        assert bytes_to_ipv6(data) == socket.inet_ntop(socket.AF_INET6, data)

    @given(st.binary(min_size=16, max_size=16))
    def test_ipv6_address_round_trips_through_bytes_to_ipv6(self, data):
        assert ipv6_to_bytes(bytes_to_ipv6(data)) == data

    def test_invalid_address_raises_oserror(self):
        # ipv6_to_bytes wraps ipaddress.AddressValueError back into
        # OSError so this stays the same failure mode socket.inet_pton
        # raised before the ipaddress swap (see _base.py).
        ip = IPv6(
            version=6,
            traffic_class=0,
            flow_label=0,
            payload_length=0,
            next_header=59,
            hop_limit=64,
            src="not-an-address",
            dst="::1",
        )
        with pytest.raises(OSError):
            bytes(ip)


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
        assert alert.value == 0  # "router shall examine packet"
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


class TestIPv4OptionValue:
    """#96: `.value` decodes Record Route, Timestamp and Router Alert
    (RFC 791 §3.1, RFC 2113); every other kind, and malformed data on
    one of these three, degrades to `None` rather than raising."""

    def test_record_route_decodes_the_addresses_recorded_so_far(self):
        # pointer=12: two 4-byte addresses already recorded (RFC 791
        # §3.1 -- the smallest legal pointer, 4, means none yet).
        route_area = (
            IPv4Address("192.0.2.1").packed + IPv4Address("192.0.2.2").packed
        )
        data = bytes([12]) + route_area
        ip = ipv4_with_options(bytes([7, 2 + len(data)]) + data)
        record = ip.parsed_options[0]
        assert record.value == (
            IPv4Address("192.0.2.1"),
            IPv4Address("192.0.2.2"),
        )

    def test_record_route_pointer_at_minimum_is_no_addresses_yet(self):
        data = bytes([4])  # pointer=4, nothing recorded yet
        ip = ipv4_with_options(bytes([7, 2 + len(data)]) + data)
        record = ip.parsed_options[0]
        assert record.value == ()

    def test_record_route_pointer_below_minimum_is_none(self):
        data = bytes([2])  # 2 < 4: not a legal pointer value
        ip = ipv4_with_options(bytes([7, 2 + len(data)]) + data)
        record = ip.parsed_options[0]
        assert record.value is None

    def test_record_route_pointer_past_the_route_area_is_none(self):
        # pointer=12 claims two filled addresses; only one is present.
        data = bytes([12]) + IPv4Address("10.0.0.1").packed
        ip = ipv4_with_options(bytes([7, 2 + len(data)]) + data)
        record = ip.parsed_options[0]
        assert record.value is None

    def test_timestamp_flag_0_is_plain_milliseconds(self):
        entries = (100_000).to_bytes(4, "big") + (100_004).to_bytes(4, "big")
        data = bytes([4, 0]) + entries  # pointer=4, overflow=0, flag=0
        ip = ipv4_with_options(bytes([68, 2 + len(data)]) + data)
        timestamp = ip.parsed_options[0]
        assert timestamp.value == (100_000, 100_004)

    def test_timestamp_flag_1_pairs_address_with_timestamp(self):
        entry = IPv4Address("192.0.2.9").packed + (12_345).to_bytes(4, "big")
        data = bytes([4, 1]) + entry  # flag=1: address precedes timestamp
        ip = ipv4_with_options(bytes([68, 2 + len(data)]) + data)
        timestamp = ip.parsed_options[0]
        assert timestamp.value == ((IPv4Address("192.0.2.9"), 12_345),)

    def test_timestamp_flag_3_also_pairs_address_with_timestamp(self):
        entry = IPv4Address("192.0.2.10").packed + (5).to_bytes(4, "big")
        data = bytes([4, 3]) + entry  # flag=3: prespecified addresses
        ip = ipv4_with_options(bytes([68, 2 + len(data)]) + data)
        timestamp = ip.parsed_options[0]
        assert timestamp.value == ((IPv4Address("192.0.2.10"), 5),)

    def test_timestamp_unrecognized_flag_is_none(self):
        data = bytes([4, 2]) + b"\x00\x00\x00\x00"  # flag=2 is not defined
        ip = ipv4_with_options(bytes([68, 2 + len(data)]) + data)
        timestamp = ip.parsed_options[0]
        assert timestamp.value is None

    def test_router_alert_malformed_length_is_none(self):
        data = b"\x00"  # Router Alert is always exactly 2 bytes
        ip = ipv4_with_options(bytes([148, 2 + len(data)]) + data)
        alert = ip.parsed_options[0]
        assert alert.value is None

    def test_unnamed_kind_value_is_none(self):
        ip = ipv4_with_options(b"\x83\x03\x01")  # Loose Source Route
        option = ip.parsed_options[0]
        assert option.value is None

    def test_direct_construction(self):
        route_area = IPv4Address("198.51.100.1").packed
        option = IPv4Option(kind=7, data=bytes([8]) + route_area)
        assert option.value == (IPv4Address("198.51.100.1"),)
        alert = IPv4Option(kind=148, data=b"\x00\x00")
        assert alert.value == 0
