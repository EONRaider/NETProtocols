"""Checksum computation and verification, held to the wire by the
real-capture corpus: every checksummed inbound frame must recompute to
its captured value."""

from dataclasses import replace

import pytest

from conftest import corpus_frames
from netprotocols import (
    ARP,
    GRE,
    IGMP,
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
    """Every verifiable transport checksum in the corpus: (ids, layer,
    enclosing ip, wire payload), one case per transport layer — a VXLAN
    frame carries two, the outer UDP and the inner frame's own.
    Fragmented traffic is excluded — those checksums span the
    reassembled datagram."""
    cases = []
    for name, index, frame in CORPUS:
        layers, _ = walk(frame)
        if any(isinstance(layer, IPv6Fragment) for layer in layers):
            continue
        if any(
            isinstance(layer, IPv4)
            and (layer.fragment_offset > 0 or layer.flags & 0b001)
            for layer in layers
        ):
            continue  # any fragment: the checksum spans the reassembly
        # Find each transport by type and the offset just past its
        # header: an application layer (e.g. DNS) may sit below it, so
        # the transport's payload ends before the chain does. The
        # enclosing IP is the last one before it, not the first: IP-in-IP
        # stacks two, and the pseudo-header is the inner one's. Track
        # that datagram's own start offset while walking, so a VLAN shim
        # or an outer IP header shifts its bounds too.
        ip = None
        ip_start = 0
        offset = 0
        found = 0
        for layer in layers:
            if isinstance(layer, (IPv4, IPv6)):
                ip, ip_start = layer, offset
            offset += layer.header_len
            if ip is None or not isinstance(layer, (TCP, UDP, ICMPv4, ICMPv6)):
                continue
            # The wire payload ends at the IP datagram's declared length.
            if isinstance(ip, IPv4):
                end = ip_start + ip.total_length
            else:
                end = ip_start + ip.header_len + ip.payload_length
            case_id = f"{name}#{index}" + (f"/{found}" if found else "")
            cases.append((case_id, layer, ip, frame[offset:end]))
            found += 1
    return cases


CASES = transport_cases()

#: UDP over IPv4 may send a zero checksum, "none computed" (RFC 768),
#: as a Linux VXLAN device set to noudpcsum does: verify() accepts it,
#: but there is no value for compute() to reproduce, so those cases are
#: held apart.
UNCHECKSUMMED = [
    case
    for case in CASES
    if isinstance(case[1], UDP)
    and isinstance(case[2], IPv4)
    and case[1].checksum == 0
]
CHECKSUMMED = [case for case in CASES if case not in UNCHECKSUMMED]


class TestCorpusChecksums:
    def test_corpus_offers_all_five_checksum_cases(self):
        kinds = {type(transport) for _, transport, _, _ in CHECKSUMMED}
        assert {TCP, UDP, ICMPv4, ICMPv6} <= kinds
        assert any(isinstance(ip, IPv4) for _, _, ip, _ in CHECKSUMMED)
        assert any(isinstance(ip, IPv6) for _, _, ip, _ in CHECKSUMMED)

    def test_tunnelled_transports_are_cases_of_their_own(self):
        """A VXLAN frame's inner transport is checked too, against the
        inner IP header: the outer UDP is not the only case it yields."""
        inner = [
            (transport, ip)
            for case_id, transport, ip, _ in CHECKSUMMED
            if case_id.startswith("vxlan.pcap#") and "/" in case_id
        ]
        assert {type(transport) for transport, _ in inner} == {ICMPv4, UDP}
        assert all(ip.src.startswith("10.9.13.") for _, ip in inner)

    @pytest.mark.parametrize(
        "transport,ip,payload",
        [case[1:] for case in CHECKSUMMED],
        ids=[case[0] for case in CHECKSUMMED],
    )
    def test_transport_checksums_recompute_to_wire_values(
        self, transport, ip, payload
    ):
        assert compute(transport, ip=ip, payload=payload) == (
            transport.checksum
        )
        assert verify(transport, ip=ip, payload=payload)

    def test_zero_udp_checksums_over_ipv4_verify_as_absent(self):
        """The corpus's zero UDP checksums are the four outer datagrams
        of vxlan.pcap's VNI 100 segment, sent by a device set to
        noudpcsum. A zero verifies because it means "none computed",
        not because these datagrams would pass any checksum: a wrong
        nonzero one fails, and the right one is not zero, so zero is
        not what compute() happens to produce."""
        assert len(UNCHECKSUMMED) == 4
        for case_id, udp, ip, payload in UNCHECKSUMMED:
            assert case_id.startswith("vxlan.pcap#")
            assert udp.dst_port == 4789
            # The payload starts with the VXLAN header; bytes 4-6 are
            # the VNI.
            assert int.from_bytes(payload[4:7], "big") == 100
            assert verify(udp, ip=ip, payload=payload)
            correct = compute(udp, ip=ip, payload=payload)
            assert correct != 0
            assert verify(
                replace(udp, checksum=correct), ip=ip, payload=payload
            )
            wrong = 1 if correct != 1 else 2
            assert not verify(
                replace(udp, checksum=wrong), ip=ip, payload=payload
            )

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

    def test_igmp_checksums_recompute_to_wire_values(self):
        """IGMP has no pseudo-header and ignores ``payload`` (its body
        is already part of ``bytes(layer)``) — the one arm of
        :func:`compute`/:func:`verify` the transport-checksum cases
        above never exercise."""
        igmp_layers = [
            layer
            for _, _, frame in CORPUS
            for layer in walk(frame)[0]
            if isinstance(layer, IGMP)
        ]
        assert igmp_layers
        for igmp in igmp_layers:
            assert compute(igmp) == igmp.checksum
            assert verify(igmp)

    def test_corrupted_byte_is_detected(self):
        _, transport, ip, payload = CHECKSUMMED[0]
        corrupted = (
            payload[:-1] + bytes([payload[-1] ^ 0xFF]) if payload else b"\x01"
        )
        assert not verify(transport, ip=ip, payload=corrupted)


class TestGREChecksum:
    """The GRE arm (RFC 2784 §2.5): internet checksum over the GRE
    header plus its payload, checksum field zeroed, no pseudo-header."""

    def make_gre(self, *, keyed: bool = False) -> tuple[GRE, bytes]:
        """A checksummed (optionally RFC 2890 keyed) GRE header and the
        tunnelled payload, the checksum filled to its correct value."""
        payload = bytes(range(64))  # stands in for the inner packet
        flags = 0x8000 | (0x2000 if keyed else 0)
        fields = b"\x00" * 4 + (b"\xca\xfe\xba\xbe" if keyed else b"")
        blank = GRE(flags=flags, protocol_type=0x0800, fields=fields)
        checksum = compute(blank, payload=payload)
        filled = GRE(
            flags=flags,
            protocol_type=0x0800,
            fields=checksum.to_bytes(2, "big") + fields[2:],
        )
        return filled, payload

    def test_checksummed_gre_round_trips_through_verify(self):
        gre, payload = self.make_gre()
        assert gre.checksum is not None
        assert compute(gre, payload=payload) == gre.checksum
        assert verify(gre, payload=payload)

    def test_keyed_and_checksummed_gre_verifies(self):
        gre, payload = self.make_gre(keyed=True)
        assert gre.key == 0xCAFEBABE
        assert verify(gre, payload=payload)

    def test_corrupted_payload_is_detected(self):
        gre, payload = self.make_gre()
        corrupted = payload[:-1] + bytes([payload[-1] ^ 0xFF])
        assert not verify(gre, payload=corrupted)

    def test_computing_without_the_checksum_bit_is_rejected(self):
        plain = GRE(flags=0, protocol_type=0x0800)
        with pytest.raises(InvalidFieldError) as excinfo:
            compute(plain, payload=b"x")
        err = excinfo.value
        assert err.protocol is GRE
        assert err.field == "checksum"
        assert str(err) == (
            "Computing a GRE checksum requires the Checksum-Present "
            "bit and its field (RFC 2784 §2.5)"
        )

    def test_checksum_bit_without_its_field_is_rejected(self):
        broken = GRE(flags=0x8000, protocol_type=0x0800)  # no fields
        with pytest.raises(InvalidFieldError):
            compute(broken)

    def test_absent_checksum_verifies_vacuously(self):
        """A header that carries no checksum cannot fail verification —
        the GRE analogue of the UDP-over-IPv4 zero rule."""
        assert verify(GRE(flags=0, protocol_type=0x0800), payload=b"any")
        keyed = GRE(flags=0x2000, protocol_type=0x0800, fields=b"\x00" * 4)
        assert verify(keyed)

    def test_corpus_gre_frames_verify(self):
        """Every corpus GRE frame — plain and keyed tunnels, none with
        the checksum bit set — passes verify with its true payload."""
        seen = 0
        for name, _, frame in CORPUS:
            if name != "gre.pcap":
                continue
            layers, _ = walk(frame)
            offset = 0
            gre = None
            for layer in layers:
                if isinstance(layer, GRE):
                    gre = layer
                    break
                offset += layer.header_len
            assert gre is not None
            assert verify(gre, payload=frame[offset + gre.header_len :])
            seen += 1
        assert seen == 8


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

    @pytest.mark.parametrize(
        "layer",
        [
            UDP(src_port=53, dst_port=4242, length=12, checksum=0),
            TCP(
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
            ),
            ICMPv6(type=128, code=0, checksum=0, rest=b"\x00" * 4),
        ],
        ids=["udp", "tcp", "icmpv6"],
    )
    def test_pseudo_header_layers_require_ip(self, layer):
        """Every pseudo-header layer's missing-``ip`` error names its
        own class — regression against `compute`'s ICMPv6/TCP/UDP arms
        losing track of which layer asked (each passes `layer` through
        to `_require_ip`, which only uses it to build this message)."""
        with pytest.raises(InvalidFieldError) as excinfo:
            compute(layer)
        err = excinfo.value
        assert err.protocol is type(layer)
        assert err.field == "checksum"
        assert str(err) == (
            f"Computing a {type(layer).__name__} checksum requires the "
            f"enclosing IPv4/IPv6 layer (its pseudo-header covers the "
            f"addresses)"
        )

    def test_layers_without_checksums_are_rejected(self):
        eth = Ethernet(
            dst="ff:ff:ff:ff:ff:ff",
            src="00:07:0d:af:f4:54",
            ethertype=0x0800,
        )
        with pytest.raises(InvalidFieldError) as excinfo:
            compute(eth)
        err = excinfo.value
        assert err.protocol is Ethernet
        assert err.field == "checksum"
        assert str(err) == "Ethernet has no checksum field to compute"

    def test_compute_payload_defaults_to_empty_bytes(self):
        """`compute`'s ``payload`` parameter defaults to ``b""`` —
        regression against a corrupted default silently changing every
        checksum computed without an explicit payload."""
        icmp = ICMPv4(type=8, code=0, checksum=0, rest=b"\x00" * 4)
        assert compute(icmp) == compute(icmp, payload=b"")

    def test_verify_payload_defaults_to_empty_bytes(self):
        from dataclasses import replace

        icmp = ICMPv4(type=8, code=0, checksum=0, rest=b"\x00" * 4)
        filled = replace(icmp, checksum=compute(icmp))
        assert verify(filled)
        assert verify(filled) == verify(filled, payload=b"")

    def test_ipv4_pseudo_header_length_field_is_unsigned(self):
        """The IPv4 pseudo-header's length field is a 16-bit *unsigned*
        value (RFC 793 §3.1; RFC 768) — a segment length above 32767
        (representable unsigned, not signed) must still pack without
        overflowing. The IPv6 pseudo-header's analogous 32-bit length
        field has the same signed/unsigned distinction but only at
        payload sizes (>2 GiB) no realistic test can reach; see the
        note by ``[tool.mutmut]`` in pyproject.toml."""
        payload = b"\x00" * 40000
        udp = UDP(src_port=1, dst_port=2, length=8 + len(payload), checksum=0)
        ip = IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=20 + 8 + len(payload),
            identification=1,
            flags=2,
            fragment_offset=0,
            ttl=64,
            protocol=17,
            checksum=0,
            src="192.0.2.1",
            dst="192.0.2.2",
        )
        checksum = compute(udp, ip=ip, payload=payload)
        assert 0 <= checksum <= 0xFFFF


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
