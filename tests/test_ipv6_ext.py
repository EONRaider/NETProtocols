"""IPv6 extension headers (RFC 8200 §4.3-4.6), driven by corpus frames."""

import pytest

from conftest import FIXTURES, read_pcap
from netprotocols import (
    Ethernet,
    ICMPv6,
    InvalidFieldError,
    IPProtocol,
    IPv4,
    IPv6,
    IPv6DestinationOptions,
    IPv6Fragment,
    IPv6HopByHopOptions,
    IPv6Routing,
    TruncatedHeaderError,
)
from test_corpus import walk


class TestMLDBehindHopByHop:
    """The flagship corpus scenario: MLD reports ride behind a
    hop-by-hop header carrying a Router Alert option."""

    def frames(self) -> list[bytes]:
        return read_pcap(FIXTURES / "ipv6_mld.pcap")

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
        # Router Alert option (type 5, length 2, value 0 = MLD).
        assert hbh.options[:4] == b"\x05\x02\x00\x00"

    def test_mld_message_types(self):
        types = {walk(frame)[0][3].type for frame in self.frames()}
        # MLDv2 Listener Report (143) and/or v1 report/done (131/132).
        assert types <= {130, 131, 132, 143}
        assert types


class TestFragmentHeader:
    def fragments(self) -> list[IPv6Fragment]:
        frames = read_pcap(FIXTURES / "ipv6_fragments.pcap")
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

    def test_fragment_round_trip_preserves_reserved_bits(self):
        raw = b"\x3a\xa5\x01\x5b\xde\xad\xbe\xef"
        fragment = IPv6Fragment.decode(raw)
        assert fragment.reserved == 0xA5
        assert fragment.fragment_offset == 0x15B >> 3
        assert fragment.res == 0b01
        assert fragment.m_flag == 1
        assert bytes(fragment) == raw

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

    def test_extension_headers_chain_among_themselves(self):
        dst_opts = IPv6HopByHopOptions(
            next_header=60, hdr_ext_len=0, options=b"\x01\x04\x00\x00\x00\x00"
        )
        assert dst_opts.next_protocol() is IPv6DestinationOptions


class TestEnumCompleteness:
    def test_every_ip_protocol_member_has_a_display_name(self):
        for member in IPProtocol:
            assert member.display_name

    def test_extension_header_display_names(self):
        assert IPProtocol.HOPOPT.display_name == "IPv6 Hop-by-Hop Options"
        assert IPProtocol.IPV6_FRAG.display_name == "IPv6 Fragment"
