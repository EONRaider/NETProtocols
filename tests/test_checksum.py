"""Checksum computation and verification, held to the wire by the
real-capture corpus: every checksummed inbound frame must recompute to
its captured value."""

import pytest

from conftest import corpus_frames
from netprotocols import (
    ARP,
    TCP,
    UDP,
    Ethernet,
    ICMPv4,
    ICMPv6,
    InvalidFieldError,
    IPv4,
    IPv6,
    IPv6Fragment,
    Packet,
    compute,
    internet_checksum,
    verify,
)
from test_corpus import walk

CORPUS = corpus_frames()


def transport_cases():
    """Every corpus frame whose transport checksum is verifiable:
    (ids, layer, enclosing ip, wire payload). Fragmented traffic is
    excluded — those checksums span the reassembled datagram."""
    cases = []
    for name, index, frame in CORPUS:
        layers, _ = walk(frame)
        if any(isinstance(layer, IPv6Fragment) for layer in layers):
            continue
        ip = next(
            (layer for layer in layers if isinstance(layer, (IPv4, IPv6))),
            None,
        )
        if ip is None:
            continue
        if isinstance(ip, IPv4) and (
            ip.fragment_offset > 0 or ip.flags & 0b001
        ):
            continue  # any fragment: the checksum spans the reassembly
        # Find the transport by type and the offset just past its
        # header: an application layer (e.g. DNS) may now sit below it,
        # so the transport's payload ends before the chain does. Track
        # the IP datagram's own start offset while walking, so a VLAN
        # shim between Ethernet and IP shifts the datagram bounds too.
        transport = None
        after_transport = 0
        ip_start = 0
        offset = 0
        for layer in layers:
            if layer is ip:
                ip_start = offset
            offset += layer.header_len
            if isinstance(layer, (TCP, UDP, ICMPv4, ICMPv6)):
                transport = layer
                after_transport = offset
                break
        if transport is None:
            continue
        # The wire payload ends at the IP datagram's declared length.
        if isinstance(ip, IPv4):
            end = ip_start + ip.total_length
        else:
            end = ip_start + ip.header_len + ip.payload_length
        payload = frame[after_transport:end]
        cases.append((f"{name}#{index}", transport, ip, payload))
    return cases


CASES = transport_cases()


class TestCorpusChecksums:
    def test_corpus_offers_all_five_checksum_cases(self):
        kinds = {type(transport) for _, transport, _, _ in CASES}
        assert {TCP, UDP, ICMPv4, ICMPv6} <= kinds
        assert any(isinstance(ip, IPv4) for _, _, ip, _ in CASES)
        assert any(isinstance(ip, IPv6) for _, _, ip, _ in CASES)

    @pytest.mark.parametrize(
        "transport,ip,payload",
        [case[1:] for case in CASES],
        ids=[case[0] for case in CASES],
    )
    def test_transport_checksums_recompute_to_wire_values(
        self, transport, ip, payload
    ):
        assert compute(transport, ip=ip, payload=payload) == (
            transport.checksum
        )
        assert verify(transport, ip=ip, payload=payload)

    def test_ipv4_header_checksums_recompute_to_wire_values(self):
        headers = [
            layer
            for _, _, frame in CORPUS
            for layer in walk(frame)[0]
            if isinstance(layer, IPv4)
        ]
        assert headers
        for header in headers:
            assert compute(header) == header.checksum
            assert verify(header)

    def test_corrupted_byte_is_detected(self):
        _, transport, ip, payload = CASES[0]
        corrupted = (
            payload[:-1] + bytes([payload[-1] ^ 0xFF]) if payload else b"\x01"
        )
        assert not verify(transport, ip=ip, payload=corrupted)


class TestChecksumRules:
    def make_udp(self, checksum: int) -> tuple[UDP, IPv4]:
        udp = UDP(src_port=53, dst_port=4242, length=12, checksum=checksum)
        ip = IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=32,
            identification=1,
            flags=2,
            fragment_offset=0,
            ttl=64,
            protocol=17,
            checksum=0,
            src="192.0.2.1",
            dst="192.0.2.2",
        )
        return udp, ip

    def test_udp_zero_checksum_means_not_used_over_ipv4(self):
        udp, ip = self.make_udp(0)
        assert verify(udp, ip=ip, payload=b"1234")

    def test_udp_never_computes_zero(self):
        """Search for a payload whose raw sum folds to 0xFFFF: the UDP
        arm must substitute 0xFFFF, never emit 0x0000."""
        for word in range(0x10000):
            udp, ip = self.make_udp(0)
            payload = word.to_bytes(2, "big") + b"\x00\x00"
            if compute(udp, ip=ip, payload=payload) == 0xFFFF:
                raw_zero_found = True
                break
        else:
            raw_zero_found = False
        assert raw_zero_found

    def test_tcp_legitimately_computes_zero(self):
        """The substitution is UDP-only: for TCP a raw result of 0x0000
        must be returned as-is (regression against misplacing the rule
        in the shared primitive)."""
        base = TCP(
            src_port=1,
            dst_port=2,
            seq=0,
            ack=0,
            data_offset=5,
            reserved=0,
            flags=0,
            window=0,
            checksum=0,
            urgent_pointer=0,
        )
        ip = IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=44,
            identification=1,
            flags=2,
            fragment_offset=0,
            ttl=64,
            protocol=6,
            checksum=0,
            src="192.0.2.1",
            dst="192.0.2.2",
        )
        for word in range(0x10000):
            payload = word.to_bytes(2, "big") + b"\x00\x00"
            if compute(base, ip=ip, payload=payload) == 0:
                assert internet_checksum(b"") == 0xFFFF  # sanity: raw API
                return
        pytest.fail("no payload drove the TCP checksum to 0x0000")

    def test_pseudo_header_layers_require_ip(self):
        udp, _ = self.make_udp(0)
        with pytest.raises(InvalidFieldError):
            compute(udp)

    def test_layers_without_checksums_are_rejected(self):
        eth = Ethernet(
            dst="ff:ff:ff:ff:ff:ff",
            src="00:07:0d:af:f4:54",
            ethertype=0x0800,
        )
        with pytest.raises(InvalidFieldError):
            compute(eth)


class TestPacketWithChecksums:
    def test_round_trip_matches_corpus_frame(self):
        """Rebuild a corpus frame's stack with zeroed checksums; after
        with_checksums() it must be byte-identical to the wire."""
        from dataclasses import replace

        name_frame = next(
            (name, frame) for name, _, frame in CORPUS if name == "udp_dns.pcap"
        )
        _, frame = name_frame
        layers, _ = walk(frame)
        eth, ip, udp = layers[0], layers[1], layers[2]
        assert isinstance(ip, IPv4)
        end = 14 + ip.total_length
        # The DNS message is the UDP payload; the UDP checksum covers it.
        udp_payload = frame[14 + ip.header_len + udp.header_len : end]
        zeroed = Packet(eth, replace(ip, checksum=0), replace(udp, checksum=0))
        restored = zeroed.with_checksums(udp_payload)
        assert bytes(restored) + udp_payload == frame[:end]

    def test_arp_stack_passes_through_unchanged(self):
        eth = Ethernet(
            dst="ff:ff:ff:ff:ff:ff",
            src="00:07:0d:af:f4:54",
            ethertype=0x0806,
        )
        arp = ARP(
            htype=1,
            ptype=0x0800,
            hlen=6,
            plen=4,
            oper=1,
            sha="00:07:0d:af:f4:54",
            spa="192.0.2.1",
            tha="00:00:00:00:00:00",
            tpa="192.0.2.2",
        )
        packet = Packet(eth, arp)
        assert bytes(packet.with_checksums()) == bytes(packet)
