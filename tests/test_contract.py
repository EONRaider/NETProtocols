"""Tests of the decode contract shared by all protocols: truncation,
lying length fields, memoryview transients, and chain walking."""

import pytest

from netprotocols import (
    AH,
    ARP,
    BGP,
    CDP,
    ESP,
    HSRP,
    HTTP,
    LLC,
    LLDP,
    MPLS,
    NTP,
    OSPF,
    PIM,
    RADIUS,
    RIP,
    SCTP,
    SNAP,
    STP,
    STUN,
    TCP,
    TFTP,
    UDP,
    VRRP,
    VXLAN,
    Ethernet,
    ICMPv4,
    InvalidIPv4AddressError,
    InvalidMACAddressError,
    IPv4,
    IPv6,
    ProtocolError,
    TruncatedHeaderError,
    decode_frame,
)


class TestTruncation:
    @pytest.mark.parametrize(
        "protocol,fixture",
        [
            (Ethernet, "raw_eth_header"),
            (LLDP, "raw_lldp_shutdown"),
            (ARP, "raw_arp_header"),
            (IPv4, "raw_ipv4_header"),
            (IPv6, "raw_ipv6_header"),
            (TCP, "raw_tcp_header_with_options"),
            (UDP, "raw_udp_header"),
            (SCTP, "raw_sctp_packet"),
            (PIM, "raw_pim_join_prune"),
            (ICMPv4, "raw_icmpv4_echo_request"),
            (ESP, "raw_esp_packet"),
            (AH, "raw_ah_header"),
            (VXLAN, "raw_vxlan_header"),
            (OSPF, "raw_ospf_hello"),
            (RIP, "raw_rip_message"),
            (TFTP, "raw_tftp_rrq"),
            (RADIUS, "raw_radius_status_server"),
            (STUN, "raw_stun_message"),
            (NTP, "raw_ntp_message"),
            (HSRP, "raw_hsrp_hello"),
            (VRRP, "raw_vrrpv2_advert"),
            (VRRP, "raw_vrrpv3_advert"),
            (BGP, "raw_bgp_keepalive"),
            (LLC, "raw_llc_header"),
            (SNAP, "raw_snap_header"),
            (MPLS, "raw_mpls_stack"),
            (STP, "raw_stp_config_bpdu"),
            (STP, "raw_stp_tcn"),
            (CDP, "raw_cdp_header"),
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

    def test_lying_ah_payload_len_raises(self, raw_ah_header):
        """A Payload Len of 255 claims a 1028-byte header on a 52-byte
        buffer."""
        lying = raw_ah_header[:1] + b"\xff" + raw_ah_header[2:]
        with pytest.raises(TruncatedHeaderError):
            AH.decode(lying)

    def test_lying_ospf_packet_length_raises(self, raw_ospf_hello):
        """A Packet Length of 0xffff claims a 65535-byte packet on a
        48-byte buffer."""
        lying = raw_ospf_hello[:2] + b"\xff\xff" + raw_ospf_hello[4:]
        with pytest.raises(TruncatedHeaderError):
            OSPF.decode(lying)

    def test_lying_bgp_length_raises(self, raw_bgp_keepalive):
        """An UPDATE whose Length claims 4096 bytes on a 23-byte
        buffer: a message the segment cut, not a malformed one."""
        lying = raw_bgp_keepalive[:16] + b"\x10\x00\x02" + bytes(4)
        with pytest.raises(TruncatedHeaderError):
            BGP.decode(lying)

    def test_lying_radius_length_raises(self, raw_radius_status_server):
        """A Length of 4096 claims a 4096-byte packet on a 38-byte
        buffer: RFC 2865 §3 discards a packet shorter than its Length."""
        raw = raw_radius_status_server
        lying = raw[:2] + b"\x10\x00" + raw[4:]
        with pytest.raises(TruncatedHeaderError):
            RADIUS.decode(lying)

    def test_lying_lldp_tlv_length_raises(self, raw_lldp_shutdown):
        """A Port ID TLV whose Length claims 511 bytes on a 27-byte
        buffer."""
        lying = raw_lldp_shutdown[:9] + b"\x05\xff" + raw_lldp_shutdown[11:]
        with pytest.raises(TruncatedHeaderError):
            LLDP.decode(lying)

    def test_a_stack_cut_before_its_bottom_raises(self, raw_mpls_stack):
        """MPLS has no length to lie with: its S bit ends the stack, so
        a stack cut before its bottom entry is the truncation case."""
        with pytest.raises(TruncatedHeaderError) as excinfo:
            MPLS.decode(raw_mpls_stack[:-1])
        assert (excinfo.value.field, excinfo.value.offset) == ("labels", 4)

    def test_a_tftp_string_without_its_zero_byte_raises(self, raw_tftp_rrq):
        """TFTP has no length to lie with: a zero byte ends each string,
        so a request cut inside its mode is the truncation case."""
        with pytest.raises(TruncatedHeaderError) as excinfo:
            TFTP.decode(raw_tftp_rrq[:14])
        assert (excinfo.value.field, excinfo.value.offset) == ("mode", 11)

    def test_all_errors_share_the_library_base(self, raw_ipv4_header):
        with pytest.raises(ProtocolError):
            IPv4.decode(raw_ipv4_header[:10])


class TestDamagedPayload:
    """A layer without a length field survives a frame that is cut
    short or carries a trailer. SCTP walks its chunks to find its end,
    so past its 12-byte common header it keeps a remainder it cannot
    walk instead of raising (see _base.py); RIP keeps everything past
    its 4-byte header and reports a remainder shorter than an entry. In
    strict and lax walks alike."""

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    @pytest.mark.parametrize(
        "damage",
        [
            pytest.param(lambda raw: raw + b"\xde\xad\xbe\xef", id="trailer"),
            pytest.param(lambda raw: raw[:14], id="cut-chunk"),
        ],
    )
    def test_sctp_keeps_its_common_header(self, raw_sctp_packet, damage, lax):
        raw = damage(raw_sctp_packet)
        packet = decode_frame(raw, start=SCTP, lax=lax)
        assert [type(layer) for layer in packet] == [SCTP]
        assert packet.stopped_by is None
        assert bytes(packet) == raw
        assert bytes(packet)[:12] == raw_sctp_packet[:12]

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    @pytest.mark.parametrize(
        "trailer",
        [
            pytest.param(b"\xde\xad\xbe\xef", id="fcs"),
            pytest.param(bytes(26), id="padding"),
            pytest.param(b"\x04\x1c\x01\x00" + bytes(26), id="md5-tlv"),
        ],
    )
    def test_hsrp_leaves_what_follows_its_message(
        self, raw_hsrp_hello, trailer, lax
    ):
        """HSRP has no length field and needs none: its message is
        always 20 bytes, so an FCS, zero bytes or the MD5 Authentication
        TLV some Cisco releases append are left undecoded."""
        raw = raw_hsrp_hello + trailer
        packet = decode_frame(raw, start=HSRP, lax=lax)
        assert [type(layer) for layer in packet] == [HSRP]
        assert packet.stopped_by is None
        assert packet.consumed == 20
        assert bytes(packet) == raw_hsrp_hello

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    @pytest.mark.parametrize(
        "trailer",
        [b"\xde\xad\xbe\xef", bytes(14), b"blk"],
        ids=["fcs", "padding", "cut-option"],
    )
    def test_tftp_leaves_a_trailer_after_its_last_option(
        self, raw_tftp_rrq, trailer, lax
    ):
        """TFTP has no length field either: a request ends after its
        last whole option pair, so padding, an FCS with no zero byte or
        an option cut short is left undecoded (test_tftp.py pins the
        trailers that read as options)."""
        raw = raw_tftp_rrq + trailer
        packet = decode_frame(raw, start=TFTP, lax=lax)
        assert [type(layer) for layer in packet] == [TFTP]
        assert packet.stopped_by is None
        assert bytes(packet) == raw_tftp_rrq
        assert packet.consumed == len(raw_tftp_rrq)

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    def test_pim_leaves_a_trailer_after_a_bounded_message(
        self, raw_pim_join_prune, lax
    ):
        """PIM has no length field either: a Join/Prune ends where its
        counts say, so a trailer is left undecoded."""
        raw = raw_pim_join_prune + b"\xde\xad\xbe\xef"
        packet = decode_frame(raw, start=PIM, lax=lax)
        assert [type(layer) for layer in packet] == [PIM]
        assert packet.stopped_by is None
        assert bytes(packet) == raw_pim_join_prune

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    def test_pim_keeps_a_cut_message(self, raw_pim_join_prune, lax):
        """Keep a Join/Prune cut mid-address whole in ``body``.

        Past its 4-byte header PIM never raises, so neither walk stops.
        """
        raw = raw_pim_join_prune[:20]
        packet = decode_frame(raw, start=PIM, lax=lax)
        assert [type(layer) for layer in packet] == [PIM]
        assert packet.stopped_by is None
        assert bytes(packet) == raw

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    @pytest.mark.parametrize(
        "damage",
        [
            pytest.param(lambda raw: raw + b"\xde\xad\xbe\xef", id="trailer"),
            pytest.param(lambda raw: raw[:30], id="cut-entry"),
        ],
    )
    def test_rip_keeps_its_whole_entries(self, raw_rip_message, damage, lax):
        """RIP has no length field either: past its 4-byte header it
        keeps everything, and a remainder shorter than an entry is
        reported, not raised."""
        raw = damage(raw_rip_message)
        packet = decode_frame(raw, start=RIP, lax=lax)
        assert [type(layer) for layer in packet] == [RIP]
        assert packet.stopped_by is None
        assert bytes(packet) == raw
        rip = packet[RIP]
        assert len(rip.entries) == (len(raw) - 4) // 20
        assert rip.remainder == raw[4 + 20 * len(rip.entries) :]

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    @pytest.mark.parametrize(
        "trailer",
        [
            pytest.param(b"\xde\xad", id="short"),
            pytest.param(b"\xde\xad\xbe\xef" * 3, id="not-a-mac"),
        ],
    )
    def test_ntp_keeps_what_follows_its_header(
        self, raw_ntp_message, trailer, lax
    ):
        """NTP has no length field either: past its 48-byte header it
        keeps everything, and bytes that are neither an extension field
        nor a MAC are reported as a remainder, not raised."""
        raw = raw_ntp_message + trailer
        packet = decode_frame(raw, start=NTP, lax=lax)
        assert [type(layer) for layer in packet] == [NTP]
        assert packet.stopped_by is None
        assert bytes(packet) == raw
        ntp = packet[NTP]
        assert (ntp.extension_fields, ntp.mac) == ((), None)
        assert ntp.remainder == trailer


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

    def test_mpls_memoryview_accepted_and_not_retained(self, raw_mpls_stack):
        buffer = bytearray(raw_mpls_stack + b"\x45")
        mpls = MPLS.decode(memoryview(buffer))
        buffer[:] = bytes(len(buffer))
        assert bytes(mpls) == raw_mpls_stack
        assert mpls.payload_ethertype == 0x0800

    def test_trailing_bytes_tolerated(self, raw_eth_header, raw_arp_header):
        eth = Ethernet.decode(raw_eth_header + raw_arp_header)
        assert bytes(eth) == raw_eth_header


class TestChainWalk:
    def test_full_frame_walk(self, raw_eth_header, raw_arp_header):
        """Walking a real frame: each layer's next_protocol() and
        header_len drive the cursor, exactly as a capture tool would."""
        frame = raw_eth_header + raw_arp_header
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, ARP]
        assert packet.consumed == len(frame)

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

    def test_http_decode_runs_no_construction_check(self):
        """decode() parses once and builds the instance from that parse;
        the construction check re-parsing head + raw_body would double
        the cost of every decode."""
        from unittest import mock

        from netprotocols.layer7 import http

        raw = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"
        spy = mock.patch.object(
            http,
            "_check_consistency",
            side_effect=AssertionError("re-validated on the decode path"),
        )
        with spy:
            msg = HTTP.decode(raw)
        assert msg == HTTP(head=raw)
        assert bytes(msg) == raw

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
