"""Tests of the decode contract shared by all protocols: truncation,
lying length fields, memoryview transients, and chain walking."""

import pytest

from netprotocols import (
    ARP,
    TCP,
    UDP,
    Ethernet,
    ICMPv4,
    IPv4,
    IPv6,
    ProtocolError,
    TruncatedHeaderError,
)


class TestTruncation:
    @pytest.mark.parametrize(
        "protocol,fixture",
        [
            (Ethernet, "raw_eth_header"),
            (ARP, "raw_arp_header"),
            (IPv4, "raw_ipv4_header"),
            (IPv6, "raw_ipv6_header"),
            (TCP, "raw_tcp_header_with_options"),
            (UDP, "raw_udp_header"),
            (ICMPv4, "raw_icmpv4_echo_request"),
        ],
    )
    def test_truncated_fixed_header_raises(self, protocol, fixture, request):
        raw = request.getfixturevalue(fixture)
        with pytest.raises(TruncatedHeaderError):
            protocol.decode(raw[: protocol._struct.size - 1])

    def test_lying_ipv4_ihl_raises(self, raw_ipv4_header):
        """An IHL of 15 claims a 60-byte header; only 20 bytes exist."""
        lying = b"\x4f" + raw_ipv4_header[1:]
        with pytest.raises(TruncatedHeaderError):
            IPv4.decode(lying)

    def test_lying_tcp_offset_raises(self, raw_tcp_header_with_options):
        """A data offset of 15 claims a 60-byte header on a 32-byte
        buffer."""
        raw = raw_tcp_header_with_options
        lying = raw[:12] + b"\xf8" + raw[13:]
        with pytest.raises(TruncatedHeaderError):
            TCP.decode(lying)

    def test_all_errors_share_the_library_base(self, raw_ipv4_header):
        with pytest.raises(ProtocolError):
            IPv4.decode(raw_ipv4_header[:10])


class TestDecodeInputs:
    def test_memoryview_accepted_and_not_retained(self, raw_ipv4_header):
        """Decoding from a memoryview over a mutable buffer must
        materialize every field: later mutation of the buffer must not
        change the decoded instance."""
        buffer = bytearray(raw_ipv4_header)
        ip = IPv4.decode(memoryview(buffer))
        src_before = ip.src
        options_before = ip.options
        buffer[:] = bytes(len(buffer))  # simulate buffer reuse
        assert ip.src == src_before
        assert ip.options == options_before
        assert bytes(ip) == raw_ipv4_header

    def test_trailing_bytes_tolerated(self, raw_eth_header, raw_arp_header):
        eth = Ethernet.decode(raw_eth_header + raw_arp_header)
        assert bytes(eth) == raw_eth_header


class TestChainWalk:
    def test_full_frame_walk(self, raw_eth_header, raw_arp_header):
        """Walking a real frame: each layer's next_protocol() and
        header_len drive the cursor, exactly as a capture tool would."""
        frame = raw_eth_header + raw_arp_header
        layers = []
        cursor, protocol = 0, Ethernet
        while protocol is not None:
            header = protocol.decode(frame[cursor:])
            layers.append(header)
            cursor += header.header_len
            protocol = header.next_protocol()
        assert [type(layer) for layer in layers] == [Ethernet, ARP]
        assert cursor == len(frame)

    def test_ipv4_dispatches_icmpv4_and_ipv6_dispatches_icmpv6(
        self, raw_ipv4_header, raw_ipv6_header
    ):
        from netprotocols.layer3.icmp import ICMPv6

        icmp_ipv4 = (
            b"\x45" + raw_ipv4_header[1:9] + b"\x01" + raw_ipv4_header[10:]
        )
        assert IPv4.decode(icmp_ipv4).next_protocol() is ICMPv4
        icmp_ipv6 = raw_ipv6_header[:6] + b"\x3a" + raw_ipv6_header[7:]
        assert IPv6.decode(icmp_ipv6).next_protocol() is ICMPv6

    def test_unknown_ip_protocol_ends_chain(self, raw_ipv4_header):
        gre = b"\x45" + raw_ipv4_header[1:9] + b"\x2f" + raw_ipv4_header[10:]
        assert IPv4.decode(gre).next_protocol() is None
