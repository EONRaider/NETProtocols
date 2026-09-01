"""Tests of the decode contract shared by all protocols: truncation,
lying length fields, memoryview transients, and chain walking."""

import pytest

from netprotocols import (
    ARP,
    TCP,
    UDP,
    Ethernet,
    ICMPv4,
    InvalidIPv4AddressError,
    InvalidMACAddressError,
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
        # Protocol 253 is reserved for experimentation (RFC 3692) and is
        # not one this library decodes, so the chain ends at IPv4.
        unknown = (
            b"\x45" + raw_ipv4_header[1:9] + b"\xfd" + raw_ipv4_header[10:]
        )
        assert IPv4.decode(unknown).next_protocol() is None


class TestDecodePathValidation:
    """The decoder does not re-validate strings it generated itself,
    but every public constructor still does (#84)."""

    def spy_on(self, module, name):
        """Replace a compiled regex with a spy that fails if used."""
        from unittest import mock

        spy = mock.Mock()
        spy.match.side_effect = AssertionError(
            f"{name} matched on the decode path"
        )
        return mock.patch.object(module, name, spy)

    def test_ethernet_decode_runs_no_mac_regex(self, raw_eth_header):
        from netprotocols.utils import mac

        with self.spy_on(mac, "mac_regex"):
            eth = Ethernet.decode(raw_eth_header)
        assert eth.dst == "ff:ff:ff:ff:ff:ff"
        assert bytes(eth) == raw_eth_header

    def test_arp_decode_runs_no_regex(self, raw_arp_header):
        from netprotocols.utils import ipv4, mac

        with self.spy_on(mac, "mac_regex"), self.spy_on(ipv4, "ipv4_regex"):
            arp = ARP.decode(raw_arp_header)
        assert arp.sha == "00:07:0d:af:f4:54"
        assert arp.tpa == "24.166.173.159"
        assert bytes(arp) == raw_arp_header

    def test_ipv4_decode_runs_no_ipv4_regex(self, raw_ipv4_header):
        from netprotocols.utils import ipv4

        with self.spy_on(ipv4, "ipv4_regex"):
            ip = IPv4.decode(raw_ipv4_header)
        assert ip.src == "192.168.1.96"
        assert bytes(ip) == raw_ipv4_header

    def test_construction_still_validates(self):
        """The strictness the decode path skips is intact for callers."""
        with pytest.raises(InvalidMACAddressError):
            Ethernet(dst="nonsense", src="00:07:0d:af:f4:54", ethertype=0x0800)
        with pytest.raises(InvalidMACAddressError):
            ARP(
                htype=1,
                ptype=0x0800,
                hlen=6,
                plen=4,
                oper=1,
                sha="not-a-mac",
                spa="192.0.2.1",
                tha="00:00:00:00:00:00",
                tpa="192.0.2.2",
            )
        with pytest.raises(InvalidIPv4AddressError):
            IPv4(
                version=4,
                ihl=5,
                dscp=0,
                ecn=0,
                total_length=20,
                identification=1,
                flags=2,
                fragment_offset=0,
                ttl=64,
                protocol=6,
                checksum=0,
                src="999.1.1.1",
                dst="192.0.2.2",
            )

    def test_decoded_instances_equal_constructed_ones(
        self, raw_eth_header, raw_arp_header, raw_ipv4_header
    ):
        """Equality compares every field, so a field the bypass forgot
        to set would raise AttributeError here rather than lurk."""
        eth = Ethernet.decode(raw_eth_header)
        assert eth == Ethernet(
            dst="ff:ff:ff:ff:ff:ff", src="00:07:0d:af:f4:54", ethertype=0x0806
        )
        arp = ARP.decode(raw_arp_header)
        assert arp == ARP(
            htype=1,
            ptype=0x0800,
            hlen=6,
            plen=4,
            oper=1,
            sha="00:07:0d:af:f4:54",
            spa="24.166.172.1",
            tha="00:00:00:00:00:00",
            tpa="24.166.173.159",
        )
        ip = IPv4.decode(raw_ipv4_header)
        assert ip == IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=40,
            identification=0xEC6C,
            flags=2,
            fragment_offset=0,
            ttl=64,
            protocol=6,
            checksum=0x2B51,
            src="192.168.1.96",
            dst="192.168.1.254",
        )
        assert hash(eth) and hash(arp) and hash(ip)
