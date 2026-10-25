"""Checksum computation and verification, held to the wire by the
real-capture corpus: every checksummed inbound frame must recompute to
its captured value. SCTP's CRC32c is tested here too, not in
test_sctp.py, because this file is in the mutation audit's test
selection (pyproject.toml's [tool.mutmut])."""

from dataclasses import replace

import pytest

from conftest import FIXTURES, corpus_frames, pcap_frames
from netprotocols import (
    ARP,
    GRE,
    IGMP,
    PIM,
    SCTP,
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
    SCTPChunk,
    compute,
    crc32c,
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
            if ip is None or not isinstance(
                layer, (TCP, UDP, SCTP, ICMPv4, ICMPv6, PIM)
            ):
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
    def test_corpus_offers_every_transport_checksum_case(self):
        kinds = {type(transport) for _, transport, _, _ in CHECKSUMMED}
        assert {TCP, UDP, SCTP, ICMPv4, ICMPv6, PIM} <= kinds
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


class TestCRC32c:
    """The primitive, pinned to published vectors: the CRC catalogue's
    check value, and RFC 3720 Appendix B.4 (which prints each CRC as
    the bytes iSCSI sends, least significant first)."""

    @pytest.mark.parametrize(
        "data,wire",
        [
            (bytes(32), "aa36918a"),
            (b"\xff" * 32, "43aba862"),
            (bytes(range(32)), "4e79dd46"),
            (bytes(range(31, -1, -1)), "5cdb3f11"),
            (
                bytes.fromhex(
                    "01c00000000000000000000000000000"
                    "14000000000004000000001400000018"
                    "28000000000000000200000000000000"
                ),
                "563a96d9",
            ),
        ],
        ids=["zeros", "ones", "incrementing", "decrementing", "iscsi-read"],
    )
    def test_rfc_3720_vectors(self, data, wire):
        assert crc32c(data).to_bytes(4, "little").hex() == wire

    def test_check_value(self):
        assert crc32c(b"123456789") == 0xE3069283

    def test_empty_input(self):
        assert crc32c(b"") == 0

    def test_every_single_byte(self):
        """One byte reaches one table entry, so this pins all 256
        against a bit-at-a-time reference."""

        def reference(data: bytes) -> int:
            crc = 0xFFFFFFFF
            for byte in data:
                crc ^= byte
                for _ in range(8):
                    crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
            return crc ^ 0xFFFFFFFF

        for byte in range(256):
            assert crc32c(bytes([byte])) == reference(bytes([byte]))

    def test_memoryview_input(self):
        assert crc32c(memoryview(b"123456789")) == 0xE3069283

    def test_is_not_the_ieee_crc(self):
        import zlib

        assert crc32c(b"123456789") != zlib.crc32(b"123456789")


class TestSCTPChecksum:
    """The SCTP arm: CRC32c over the whole packet with the checksum
    field zeroed, no pseudo-header, the CRC sent least significant byte
    first (RFC 9260 Appendix A)."""

    FRAMES = pcap_frames(FIXTURES / "sctp.pcap")

    def sctp(self, index: int) -> SCTP:
        return SCTP.decode(self.FRAMES[index][34:])

    def test_the_field_is_the_crc_byte_swapped(self):
        """COOKIE ACK from the capture: the wire bytes are the CRC in
        little-endian order, so the big-endian field reads it swapped."""
        cookie_ack = self.sctp(3)
        raw = bytes(cookie_ack)
        assert raw[8:12] == bytes.fromhex("b283dbc1")
        crc = crc32c(raw[:8] + bytes(4) + raw[12:])
        assert crc == 0xC1DB83B2
        assert compute(cookie_ack) == 0xB283DBC1 == cookie_ack.checksum
        assert verify(cookie_ack)

    def test_every_captured_packet_recomputes(self):
        for index in range(len(self.FRAMES)):
            sctp = self.sctp(index)
            assert compute(sctp) == sctp.checksum

    def test_the_enclosing_ip_is_ignored(self):
        sctp = self.sctp(0)
        ip = IPv4.decode(self.FRAMES[0][14:])
        assert compute(sctp, ip=ip) == compute(sctp)

    def test_payload_extends_the_covered_bytes(self):
        """Bytes outside the layer object are covered when passed as
        ``payload``, as for the other arms."""
        sctp = self.sctp(4)
        head = SCTP(
            src_port=sctp.src_port,
            dst_port=sctp.dst_port,
            verification_tag=sctp.verification_tag,
            checksum=sctp.checksum,
        )
        assert compute(head, payload=sctp.chunks) == sctp.checksum
        assert verify(head, payload=sctp.chunks)
        assert not verify(head)

    def test_the_checksum_field_is_excluded(self):
        sctp = self.sctp(5)
        assert compute(replace(sctp, checksum=0xFFFFFFFF)) == sctp.checksum

    def test_a_flipped_bit_is_detected(self):
        sctp = self.sctp(5)
        for position in (0, 7, 12, len(bytes(sctp)) - 1):
            raw = bytearray(bytes(sctp))
            raw[position] ^= 0x01
            assert not verify(SCTP.decode(bytes(raw)))

    def test_with_checksums_fills_a_built_packet(self):
        chunks = bytes(SCTPChunk(type=0, flags=3, value=b"\x00" * 12 + b"hi"))
        built = SCTP(
            src_port=1,
            dst_port=2,
            verification_tag=3,
            checksum=0,
            chunks=chunks,
        )
        (filled,) = Packet(built).with_checksums().layers
        assert isinstance(filled, SCTP)
        assert verify(filled)
        assert filled.checksum == compute(built)


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


def _rfc1071(data: bytes) -> int:
    """The internet checksum, written here rather than taken from the
    module under test."""
    data += b"\x00" * (len(data) % 2)
    total = sum(int.from_bytes(data[i : i + 2]) for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


class TestPIMChecksum:
    """The PIM arm (RFC 7761 §4.9): the whole message, or a Register's
    first 8 bytes, with the IPv6 pseudo-header over IPv6. The captured
    frames are FRR's, over IPv4; the IPv6 ones are built."""

    FRAMES = pcap_frames(FIXTURES / "pim.pcap")

    def layers(self, index: int) -> tuple[PIM, IPv4]:
        layers, _ = walk(self.FRAMES[index])
        ip, pim = layers[1], layers[2]
        assert isinstance(ip, IPv4) and isinstance(pim, PIM)
        return pim, ip

    def test_captured_registers_sum_their_first_8_bytes(self):
        for index in (3, 7):
            pim, ip = self.layers(index)
            raw = bytes(pim)
            assert pim.type == 1
            assert compute(pim, ip=ip) == _rfc1071(
                raw[:2] + bytes(2) + raw[4:8]
            )
            assert compute(pim, ip=ip) == pim.checksum

    def test_other_captured_messages_sum_the_whole_message(self):
        pim, ip = self.layers(2)
        raw = bytes(pim)
        assert compute(pim, ip=ip) == _rfc1071(raw[:2] + bytes(2) + raw[4:])

    def test_a_register_summed_whole_verifies(self):
        pim, ip = self.layers(3)
        raw = bytes(pim)
        whole = replace(pim, checksum=_rfc1071(raw[:2] + bytes(2) + raw[4:]))
        assert whole.checksum != pim.checksum
        assert verify(whole, ip=ip)
        assert not verify(replace(pim, checksum=pim.checksum ^ 1), ip=ip)

    def test_only_a_register_verifies_summed_two_ways(self):
        """A Join/Prune whose checksum is the 8-byte sum does not verify:
        the second form is a Register's alone."""
        pim, ip = self.layers(2)
        raw = bytes(pim)
        header_sum = replace(
            pim, checksum=_rfc1071(raw[:2] + bytes(2) + raw[4:8])
        )
        assert not verify(header_sum, ip=ip)
        assert not verify(replace(pim, checksum=pim.checksum ^ 1), ip=ip)

    def ipv6(self) -> IPv6:
        return IPv6(
            version=6,
            traffic_class=0,
            flow_label=0,
            payload_length=0,
            next_header=103,
            hop_limit=1,
            src="fe80::1",
            dst="ff02::d",
        )

    def pseudo(self, length: int) -> bytes:
        return (
            bytes.fromhex("fe800000000000000000000000000001")
            + bytes.fromhex("ff02000000000000000000000000000d")
            + length.to_bytes(4)
            + b"\x00\x00\x00\x67"
        )

    @pytest.mark.parametrize("type_", [0, 3])
    def test_ipv6_prepends_the_pseudo_header(self, type_):
        pim = PIM(type=type_, body=bytes(range(1, 31)))
        raw = bytes(pim)
        expected = _rfc1071(
            self.pseudo(len(raw)) + raw[:2] + bytes(2) + raw[4:]
        )
        assert compute(pim, ip=self.ipv6()) == expected
        assert verify(replace(pim, checksum=expected), ip=self.ipv6())

    def test_an_ipv6_register_counts_8_bytes_in_the_pseudo_header(self):
        pim = PIM(type=1, body=bytes(range(1, 31)))
        raw = bytes(pim)
        expected = _rfc1071(self.pseudo(8) + raw[:2] + bytes(2) + raw[4:8])
        assert compute(pim, ip=self.ipv6()) == expected
        whole = _rfc1071(self.pseudo(len(raw)) + raw[:2] + bytes(2) + raw[4:])
        assert verify(replace(pim, checksum=whole), ip=self.ipv6())

    def test_the_family_decides_the_sum(self):
        pim, ip = self.layers(2)
        assert compute(pim, ip=self.ipv6()) != compute(pim, ip=ip)

    def test_computing_without_the_ip_layer_is_rejected(self):
        pim, _ = self.layers(2)
        for check in (compute, verify):
            with pytest.raises(InvalidFieldError) as excinfo:
                check(pim)
            err = excinfo.value
            assert err.protocol is PIM
            assert err.field == "checksum"
            assert str(err) == (
                "Computing a PIM checksum requires the enclosing IPv4/IPv6 "
                "layer (over IPv6 its pseudo-header covers the addresses)"
            )

    def test_payload_is_ignored(self):
        pim, ip = self.layers(2)
        assert compute(pim, ip=ip, payload=b"\x12\x34") == pim.checksum


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
