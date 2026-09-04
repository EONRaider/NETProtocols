"""IPv6 extension headers (RFC 8200 §4.3-4.6), driven by corpus frames."""

import socket
from ipaddress import IPv6Address

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    Ethernet,
    EtherType,
    ICMPv6,
    InvalidFieldError,
    IPProtocol,
    IPv4,
    IPv6,
    IPv6DestinationOptions,
    IPv6Fragment,
    IPv6HopByHopOptions,
    IPv6Option,
    IPv6Routing,
    TruncatedHeaderError,
)
from test_corpus import walk


class TestMLDBehindHopByHop:
    """The flagship corpus scenario: MLD reports ride behind a
    hop-by-hop header carrying a Router Alert option."""

    def frames(self) -> list[bytes]:
        return pcap_frames(FIXTURES / "ipv6_mld.pcap")

    def test_chain_reaches_icmpv6_through_the_extension_header(self):
        for frame in self.frames():
            layers, _ = walk(frame)
            assert [type(layer) for layer in layers] == [
                Ethernet,
                IPv6,
                IPv6HopByHopOptions,
                ICMPv6,
            ]

    def test_hop_by_hop_fields(self):
        layers, _ = walk(self.frames()[0])
        hbh = layers[2]
        assert isinstance(hbh, IPv6HopByHopOptions)
        assert hbh.hdr_ext_len == 0
        assert hbh.header_len == 8
        assert hbh.next_header == IPProtocol.IPV6_ICMP
        assert hbh.next_header_name == "IPv6-ICMP"
        assert hbh.next_header_enum == IPProtocol.IPV6_ICMP
        # Router Alert option (type 5, length 2, value 0 = MLD).
        assert hbh.options[:4] == b"\x05\x02\x00\x00"

    def test_mld_message_types(self):
        types = {walk(frame)[0][3].type for frame in self.frames()}
        # MLDv2 Listener Report (143) and/or v1 report/done (131/132).
        assert types <= {130, 131, 132, 143}
        assert types

    def test_router_alert_option_parses(self):
        """The captured hop-by-hop options are a Router Alert (value 0:
        an MLD message is present) padded out with a PadN."""
        for frame in self.frames():
            hbh = walk(frame)[0][2]
            assert isinstance(hbh, IPv6HopByHopOptions)
            alert = hbh.parsed_options[0]
            assert alert.type == 5
            assert alert.type_name == "Router Alert"
            assert alert.data == b"\x00\x00"
            assert alert.unrecognized_action == 0


class TestFragmentHeader:
    def fragments(self) -> list[IPv6Fragment]:
        frames = pcap_frames(FIXTURES / "ipv6_fragments.pcap")
        out = []
        for frame in frames:
            layers, _ = walk(frame)
            assert type(layers[2]) is IPv6Fragment
            out.append(layers[2])
        return out

    def test_corpus_contains_first_and_non_first_fragments(self):
        offsets = {fragment.fragment_offset for fragment in self.fragments()}
        assert 0 in offsets
        assert any(offset > 0 for offset in offsets)

    def test_first_fragments_chain_to_icmpv6(self):
        for fragment in self.fragments():
            if fragment.fragment_offset == 0:
                assert fragment.next_protocol() is ICMPv6
                assert fragment.m_flag == 1

    def test_non_first_fragments_do_not_chain(self):
        for fragment in self.fragments():
            if fragment.fragment_offset > 0:
                assert fragment.next_protocol() is None

    def test_fragment_group_shares_identification(self):
        fragments = self.fragments()
        assert len({f.identification for f in fragments}) < len(fragments)


class TestDecodeContract:
    RAW_HBH = b"\x3a\x00\x05\x02\x00\x00\x01\x00"  # from the MLD corpus shape

    def test_round_trip(self):
        for cls in (IPv6HopByHopOptions, IPv6DestinationOptions):
            header = cls.decode(self.RAW_HBH)
            assert bytes(header) == self.RAW_HBH
            assert cls.decode(bytes(header)) == header

    def test_routing_round_trip(self):
        raw = b"\x3a\x00\x03\x01" + b"\x00" * 4
        routing = IPv6Routing.decode(raw)
        assert routing.routing_type == 3
        assert routing.segments_left == 1
        assert bytes(routing) == raw
        assert routing.header_len == 8
        assert routing.next_protocol() is ICMPv6
        assert routing.next_header_name == "IPv6-ICMP"
        assert routing.next_header_enum == IPProtocol.IPV6_ICMP

    def test_fragment_round_trip_preserves_reserved_bits(self):
        raw = b"\x3a\xa5\x01\x5b\xde\xad\xbe\xef"
        fragment = IPv6Fragment.decode(raw)
        assert fragment.reserved == 0xA5
        assert fragment.fragment_offset == 0x15B >> 3
        assert fragment.res == 0b01
        assert fragment.m_flag == 1
        assert bytes(fragment) == raw
        assert fragment.next_header_name == "IPv6-ICMP"
        assert fragment.next_header_enum == IPProtocol.IPV6_ICMP

    def test_unknown_next_header_enum_is_none(self):
        # 253/254 are reserved for experimentation (RFC 3692) and named
        # by no IPProtocol member this library enumerates.
        for cls in (IPv6HopByHopOptions, IPv6DestinationOptions):
            header = cls.decode(b"\xfd\x00\x05\x02\x00\x00\x01\x00")
            assert header.next_header_name == "unknown (253)"
            assert header.next_header_enum is None
        routing = IPv6Routing.decode(b"\xfd\x00\x03\x01" + b"\x00" * 4)
        assert routing.next_header_enum is None
        fragment = IPv6Fragment.decode(b"\xfd\xa5\x01\x5b\xde\xad\xbe\xef")
        assert fragment.next_header_enum is None

    def test_trailing_bytes_tolerated(self):
        header = IPv6HopByHopOptions.decode(self.RAW_HBH + b"payload")
        assert header.header_len == 8

    def test_lying_hdr_ext_len_raises(self):
        lying = b"\x3a\x02" + b"\x00" * 6  # declares 24 bytes, holds 8
        with pytest.raises(TruncatedHeaderError):
            IPv6HopByHopOptions.decode(lying)

    def test_truncated_fixed_header_raises(self):
        with pytest.raises(TruncatedHeaderError):
            IPv6Fragment.decode(b"\x3a\x00\x00")

    def test_options_length_invariant(self):
        with pytest.raises(InvalidFieldError):
            IPv6HopByHopOptions(
                next_header=58, hdr_ext_len=1, options=b"\x00" * 6
            )
        with pytest.raises(InvalidFieldError):
            IPv6Routing(
                next_header=58,
                hdr_ext_len=0,
                routing_type=3,
                segments_left=0,
                data=b"\x00" * 12,
            )


class TestOptionTLVs:
    """Option TLV parsing on the two options headers (RFC 8200 §4.2)."""

    def make_hbh(self, options: bytes) -> IPv6HopByHopOptions:
        """A hop-by-hop header carrying ``options`` (whole 8-octet
        units, the 2 fixed bytes included)."""
        return IPv6HopByHopOptions(
            next_header=58,
            hdr_ext_len=(len(options) - 6) // 8,
            options=options,
        )

    def test_router_alert_and_padn(self):
        hbh = self.make_hbh(b"\x05\x02\x00\x00\x01\x00")
        alert, padn = hbh.parsed_options
        assert alert.type == 5
        assert alert.type_name == "Router Alert"
        assert alert.data == b"\x00\x00"
        assert alert.value == 0  # MLD
        assert padn.type == 1
        assert padn.type_name == "PadN"
        assert padn.data == b""

    def test_pad1_is_a_lone_byte(self):
        hbh = self.make_hbh(b"\x00" * 6)
        options = hbh.parsed_options
        assert [option.type_name for option in options] == ["Pad1"] * 6
        assert all(option.data == b"" for option in options)

    def test_jumbo_payload(self):
        hbh = self.make_hbh(b"\xc2\x04\x00\x10\x00\x00")
        (jumbo,) = hbh.parsed_options
        assert jumbo.type == 194
        assert jumbo.type_name == "Jumbo Payload"
        assert jumbo.data == b"\x00\x10\x00\x00"
        assert jumbo.value == 0x00100000
        assert jumbo.unrecognized_action == 3

    def test_destination_options_share_the_parser(self):
        dst = IPv6DestinationOptions(
            next_header=58, hdr_ext_len=0, options=b"\x05\x02\x00\x00\x01\x00"
        )
        assert [option.type for option in dst.parsed_options] == [5, 1]

    def test_unknown_type_keeps_raw_data_and_action_bits(self):
        hbh = self.make_hbh(b"\x8a\x02\xca\xfe\x01\x00")
        unknown = hbh.parsed_options[0]
        assert unknown.type == 138
        assert unknown.type_name == "unknown (138)"
        assert unknown.data == b"\xca\xfe"
        assert unknown.unrecognized_action == 2

    def test_action_bits_on_a_direct_construction(self):
        assert IPv6Option(type=0x40).unrecognized_action == 1
        assert IPv6Option(type=0x05).unrecognized_action == 0

    def test_missing_length_byte_raises(self):
        hbh = self.make_hbh(b"\x00\x00\x00\x00\x00\x05")
        with pytest.raises(InvalidFieldError):
            _ = hbh.parsed_options

    def test_length_past_the_header_raises(self):
        hbh = self.make_hbh(b"\x05\x08\x00\x00\x00\x00")
        with pytest.raises(InvalidFieldError):
            _ = hbh.parsed_options

    def test_round_trip_unchanged_by_parsing(self):
        raw = b"\x3a\x00\x05\x02\x00\x00\x01\x00"
        hbh = IPv6HopByHopOptions.decode(raw)
        _ = hbh.parsed_options
        assert bytes(hbh) == raw


class TestIPv6OptionValue:
    """#96: `.value` decodes Router Alert and Jumbo Payload (RFC 2711
    §2.1, RFC 2675 §2); every other type, and malformed data on one of
    these two, degrades to `None` rather than raising."""

    def test_unnamed_type_value_is_none(self):
        assert IPv6Option(type=138, data=b"\xca\xfe").value is None

    def test_pad1_and_padn_value_is_none(self):
        assert IPv6Option(type=0).value is None
        assert IPv6Option(type=1, data=b"\x00\x00").value is None

    def test_router_alert_wrong_length_is_none(self):
        assert IPv6Option(type=5, data=b"\x00").value is None

    def test_jumbo_payload_wrong_length_is_none(self):
        assert IPv6Option(type=194, data=b"\x00\x10\x00").value is None

    def test_direct_construction(self):
        assert IPv6Option(type=5, data=b"\x00\x01").value == 1  # RSVP
        jumbo_len = 4_294_967_295  # max 32-bit value
        option = IPv6Option(type=194, data=jumbo_len.to_bytes(4, "big"))
        assert option.value == jumbo_len


class TestIPv6RoutingSegments:
    """#96: `segments` decodes RH0 and Mobile IPv6's address list (RFC
    2460 §4.4, RFC 6275 §6.4); RPL (routing_type 3) is deliberately
    left undecoded (its addresses are compressed relative to the
    enclosing packet's destination, context this accessor lacks)."""

    def test_rh0_two_segments(self):
        reserved = b"\x00\x00\x00\x00"
        addr_a = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        addr_b = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        data = reserved + addr_a + addr_b
        routing = IPv6Routing(
            next_header=6,
            hdr_ext_len=len(data) // 8,
            routing_type=0,
            segments_left=2,
            data=data,
        )
        assert routing.segments == (
            IPv6Address("2001:db8::1"),
            IPv6Address("2001:db8::2"),
        )

    def test_rh0_no_segments_is_an_empty_tuple(self):
        data = b"\x00\x00\x00\x00"  # reserved only, no addresses
        routing = IPv6Routing(
            next_header=6,
            hdr_ext_len=0,
            routing_type=0,
            segments_left=0,
            data=data,
        )
        assert routing.segments == ()

    def test_mobile_ipv6_single_home_address(self):
        reserved = b"\x00\x00\x00\x00"
        home = socket.inet_pton(socket.AF_INET6, "2001:db8::dead")
        data = reserved + home
        routing = IPv6Routing(
            next_header=59,
            hdr_ext_len=len(data) // 8,
            routing_type=2,
            segments_left=1,
            data=data,
        )
        assert routing.segments == (IPv6Address("2001:db8::dead"),)

    def test_rpl_is_deliberately_not_decoded(self):
        # RFC 6554 compresses addresses relative to the destination
        # address, so this library does not attempt it -- even data
        # shaped exactly like a valid RH0/MIPv6 payload stays None.
        reserved = b"\x00\x00\x00\x00"
        addr = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        routing = IPv6Routing(
            next_header=6,
            hdr_ext_len=(len(reserved) + len(addr)) // 8,
            routing_type=3,
            segments_left=1,
            data=reserved + addr,
        )
        assert routing.segments is None
        assert routing.data == reserved + addr  # still available raw

    def test_other_routing_types_are_none(self):
        routing = IPv6Routing(
            next_header=59,
            hdr_ext_len=0,
            routing_type=253,  # reserved for experimentation, RFC 3692
            segments_left=0,
            data=b"\x00\x00\x00\x00",
        )
        assert routing.segments is None

    def test_malformed_address_area_is_none(self):
        # 4-byte reserved + 8 bytes: not a whole number of 16-byte
        # addresses.
        data = b"\x00\x00\x00\x00" + b"\xff" * 8
        routing = IPv6Routing(
            next_header=6,
            hdr_ext_len=len(data) // 8,
            routing_type=0,
            segments_left=1,
            data=data,
        )
        assert routing.segments is None


class TestRegistryGating:
    def test_ipv4_never_dispatches_extension_headers(self, raw_ipv4_header):
        for number in (0, 43, 44, 60):
            garbage = (
                b"\x45"
                + raw_ipv4_header[1:9]
                + bytes([number])
                + raw_ipv4_header[10:]
            )
            assert IPv4.decode(garbage).next_protocol() is None

    def test_ipv6_dispatches_extension_headers(self, raw_ipv6_header):
        expected = {
            0: IPv6HopByHopOptions,
            43: IPv6Routing,
            44: IPv6Fragment,
            60: IPv6DestinationOptions,
        }
        for number, cls in expected.items():
            frame = raw_ipv6_header[:6] + bytes([number]) + raw_ipv6_header[7:]
            assert IPv6.decode(frame).next_protocol() is cls

    def test_dispatch_tables_differ_only_by_the_ipv6_only_numbers(self):
        """The gating is baked into the tables: the v6 table is the
        base one plus the extension-header numbers, and nothing else.

        Stated over the *built-in* registrations on a clean registry —
        once third parties can register into ``ip.proto.v6`` directly
        (#87) the live tables may legitimately differ by more, so the
        invariant that matters is the one this library ships.
        """
        from netprotocols._defaults import IPV6_ONLY_NUMBERS, install
        from netprotocols.registry import (
            TABLE_IP_PROTO,
            TABLE_IP_PROTO_V6,
            Registry,
        )

        registry = Registry()
        install(registry)
        base = registry.table(TABLE_IP_PROTO)
        v6 = registry.table(TABLE_IP_PROTO_V6)

        assert base
        assert set(v6) - set(base) == set(IPV6_ONLY_NUMBERS)
        for number, protocol in base.items():
            assert v6[number] is protocol

    def test_the_live_tables_still_gate_the_extension_headers(self):
        """The invariant above holds on the process-wide registry too,
        which is the one ``next_protocol()`` actually reads."""
        from netprotocols._defaults import IPV6_ONLY_NUMBERS
        from netprotocols.layer3.ip import (
            _IPV4_PROTOCOL_CLASSES,
            _IPV6_PROTOCOL_CLASSES,
        )

        assert _IPV4_PROTOCOL_CLASSES
        for number in IPV6_ONLY_NUMBERS:
            assert number not in _IPV4_PROTOCOL_CLASSES
            assert number in _IPV6_PROTOCOL_CLASSES

    def test_extension_headers_chain_among_themselves(self):
        dst_opts = IPv6HopByHopOptions(
            next_header=60, hdr_ext_len=0, options=b"\x01\x04\x00\x00\x00\x00"
        )
        assert dst_opts.next_protocol() is IPv6DestinationOptions


class TestEnumCompleteness:
    def test_every_ip_protocol_member_has_a_display_name(self):
        for member in IPProtocol:
            assert member.display_name

    def test_every_ethertype_member_has_a_display_name(self):
        for member in EtherType:
            assert member.display_name

    def test_extension_header_display_names(self):
        assert IPProtocol.HOPOPT.display_name == "IPv6 Hop-by-Hop Options"
        assert IPProtocol.IPV6_FRAG.display_name == "IPv6 Fragment"
