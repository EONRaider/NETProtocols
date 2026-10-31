"""Checksum computation and verification, held to the wire by the
real-capture corpus: every checksummed inbound frame must recompute to
its captured value. SCTP's CRC32c is tested here too, not in
test_sctp.py, because this file is in the mutation audit's test
selection (pyproject.toml's [tool.mutmut]); so are CDP's checksum and
STUN's FINGERPRINT."""

import hashlib
import hmac
import importlib.util
import socket
import struct
import zlib
from dataclasses import replace
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from conftest import FIXTURES, corpus_frames, pcap_frames
from netprotocols import (
    ARP,
    CDP,
    CDPTLV,
    ESP,
    GRE,
    IGMP,
    LLC,
    OSPF,
    OSPFLSA,
    PIM,
    SCTP,
    SNAP,
    STUN,
    TCP,
    UDP,
    VRRP,
    Ethernet,
    ICMPv4,
    ICMPv6,
    InvalidFieldError,
    IPv4,
    IPv6,
    IPv6Fragment,
    IPv6Routing,
    OSPFLSAHeader,
    Packet,
    ProtocolError,
    SCTPChunk,
    STUNAttribute,
    VRRPv6,
    compute,
    crc32c,
    decode_frame,
    internet_checksum,
    verify,
)
from netprotocols.checksum import (
    _cdp_sum,
    _pseudo_ip,
    fletcher_checksum,
    lsa_checksum,
    verify_lsa,
)
from test_corpus import walk
from test_esp import ESP_KEYS, ICV_LEN, null_esp_payload
from test_stun import RFC5769_IPV4, RFC5769_IPV6, RFC5769_REQUEST
from test_vrrp import (
    V6_GROUP,
    V6_SRC,
    ones_complement,
    v3_checksum_v4,
    v6_message,
)

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


def hex_id(value):
    """Name a bytes parameter by its hex digits, which every shell and
    mutmut's node-id round trip keep intact."""
    if isinstance(value, bytes):
        return (value.hex() if len(value) <= 16 else f"{len(value)}B") or "0B"
    return None


def cdp_oracle(data: bytes) -> int:
    """Return CDP's checksum of ``data``, built as Wireshark builds it.

    Written out here, not taken from the library, and in the form of
    epan/dissectors/packet-cdp.c rather than lldpd's: an odd PDU gets a
    last word whose high byte is 0 and low byte the final byte, and when
    that byte has its high bit set both bytes of the word are
    decremented. The words are then summed as RFC 1071 sums them.
    """
    if len(data) % 2:
        last = data[-1]
        high, low = 0, last
        if last & 0x80:
            high, low = (high - 1) & 0xFF, low - 1
        data = data[:-1] + bytes((high, low))
    return ones_complement(data)


#: The CDP frames of the LLC fixture: CDPv1, CDPv2, and a CDPv1 whose
#: odd-length PDU ends in 0xA9.
CDP_LAYERS = [
    layer
    for frame in pcap_frames(FIXTURES / "llc.pcap")
    for layer in decode_frame(frame)
    if isinstance(layer, CDP)
]


class TestCDPChecksum:
    """CDP's internet checksum, its odd final byte summed Cisco's way."""

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"\x00",
            b"\x01",
            b"\x7f",
            b"\x80",
            b"\x81",
            b"\xa9",
            b"\xff",
            b"\x12\x34",
            b"\x12\x34\x01",
            b"\x12\x34\x80",
            b"\x00\x7f\x81",
            b"\x00\x00\x00\x01",
            b"\x02\xb4\x00\x00\x00\x01\x00\x05\xfe",
            b"\xff\xff\xff",
            b"\xff\xff" * 3 + b"\xff",
            b"\x80\x00\x80\x00\x7f",
            bytes(range(256)) + b"\xc3",
        ],
        ids=hex_id,
    )
    def test_the_sum_matches_wiresharks_form(self, data):
        """Odd and even lengths (1 and 3 mod 4, 0 and 2), final bytes on
        both sides of 0x80, and sums that fold more than once."""
        assert _cdp_sum(data) == cdp_oracle(data)

    @pytest.mark.parametrize(
        "data,expected",
        [
            (b"\x00\x7f\x81", 0x0000),
            (b"\x01", 0xFFFE),
            (b"\x7f", 0xFF80),
            (b"\x80", 0x0080),
            (b"\xff", 0x0001),
            (b"\xff\xff\xff", 0x0001),
            (b"\x12\x34", 0xEDCB),
        ],
        ids=hex_id,
    )
    def test_pinned_values(self, data, expected):
        """Values worked by hand: ``0x81`` adds ``0xFF80``, so ``00 7f
        81`` sums to ``0xFFFF``; RFC 1071's padding would add ``0x8100``
        and give ``0x7E80``."""
        assert _cdp_sum(data) == expected

    @pytest.mark.parametrize("last", [0x01, 0x7F, 0x80, 0xA9, 0xFF])
    def test_an_odd_byte_is_not_rfc_1071s(self, last):
        data = b"\x02\xb4\x00\x00" + bytes((last,))
        assert _cdp_sum(data) != internet_checksum(data)

    def test_an_odd_zero_byte_is_rfc_1071s_too(self):
        """A final 0x00 adds 0 either way, so the two sums coincide."""
        data = b"\x02\xb4\x00\x00\x00"
        assert _cdp_sum(data) == internet_checksum(data)

    def test_an_even_pdu_is_rfc_1071s(self):
        data = bytes(range(1, 41))
        assert _cdp_sum(data) == internet_checksum(data)

    def test_the_corpus_covers_both_versions_and_an_odd_byte(self):
        """All three PDUs are 91 bytes: two end below 0x80, one above."""
        assert [cdp.version for cdp in CDP_LAYERS] == [1, 2, 1]
        assert [cdp.header_len for cdp in CDP_LAYERS] == [91, 91, 91]
        assert [bytes(cdp)[-1] for cdp in CDP_LAYERS] == [0x63, 0x63, 0xA9]

    @pytest.mark.parametrize("index", range(3), ids=["v1", "v2", "odd"])
    def test_every_captured_pdu_recomputes(self, index):
        cdp = CDP_LAYERS[index]
        assert compute(cdp) == cdp.checksum
        assert verify(cdp)
        assert cdp_oracle(bytes(replace(cdp, checksum=0))) == cdp.checksum

    def test_the_checksum_field_is_excluded(self):
        cdp = CDP_LAYERS[2]
        assert compute(replace(cdp, checksum=0x1234)) == cdp.checksum

    def test_ip_and_payload_are_ignored(self):
        cdp = CDP_LAYERS[0]
        assert (
            compute(
                cdp,
                ip=IPv4.decode(
                    bytes.fromhex("450000140000000040000000c0000201c0000202")
                ),
                payload=b"\x01\x02\x03",
            )
            == cdp.checksum
        )

    @pytest.mark.parametrize("index", range(3), ids=["v1", "v2", "odd"])
    def test_a_changed_byte_is_detected(self, index):
        cdp = CDP_LAYERS[index]
        tlv = cdp.tlvs[-1]
        changed = CDPTLV(tlv.type, tlv.value[:-1] + bytes((tlv.value[-1] ^ 1,)))
        assert not verify(replace(cdp, tlvs=(*cdp.tlvs[:-1], changed)))

    @pytest.mark.parametrize(
        "value", [b"ab", b"abc", b"ab\x80", b"ab\xa9"], ids=hex_id
    )
    def test_with_checksums_fills_a_built_packet(self, value):
        """An odd PDU ending at or past 0x80 too, through the walk."""
        built = Packet(
            Ethernet(
                dst="01:00:0c:cc:cc:cc",
                src="02:00:00:00:00:01",
                ethertype=8 + 4 + 4 + len(value),
            ),
            LLC(dsap=0xAA, ssap=0xAA, control=0x03),
            SNAP(oui=0x00000C, pid=0x2000),
            CDP(version=2, ttl=180, tlvs=(CDPTLV(1, value),)),
        )
        filled = built.with_checksums()
        cdp = filled[CDP]
        assert cdp.checksum == cdp_oracle(bytes(built[CDP]))
        assert verify(cdp)
        assert decode_frame(bytes(filled)) == filled


class TestVRRPChecksum:
    """The VRRP arm: the whole message, checksum field (bytes 6-7)
    zeroed — alone in VRRPv2 (RFC 3768 §5.3.8), behind the IP
    pseudo-header in VRRPv3 (over IPv6 RFC 5798 §5.2.8, over IPv4
    keepalived's default). Every expected value is
    the wire's (keepalived computed the corpus's) or this suite's own
    sum (``test_vrrp.ones_complement``)."""

    FRAMES = pcap_frames(FIXTURES / "vrrp.pcap")

    def advert(self, index: int) -> tuple[VRRP, IPv4]:
        frame = self.FRAMES[index]
        return VRRP.decode(frame[34:]), IPv4.decode(frame[14:])

    def v6(self) -> tuple[VRRPv6, IPv6]:
        message = v6_message()
        ip = IPv6(
            version=6,
            traffic_class=0,
            flow_label=0,
            payload_length=len(message),
            next_header=112,
            hop_limit=255,
            src=V6_SRC,
            dst=V6_GROUP,
        )
        return VRRPv6.decode(message), ip

    def test_the_corpus_covers_both_versions(self):
        versions = [self.advert(i)[0].version for i in range(len(self.FRAMES))]
        assert set(versions) == {2, 3}

    def test_every_captured_advert_recomputes(self):
        for index in range(len(self.FRAMES)):
            vrrp, ip = self.advert(index)
            assert compute(vrrp, ip=ip) == vrrp.checksum, index
            assert verify(vrrp, ip=ip), index

    def test_vrrpv2_has_no_pseudo_header(self):
        """VRRPv2 needs no IP layer, and any one given changes nothing."""
        vrrp, ip = self.advert(0)
        assert vrrp.version == 2
        assert compute(vrrp) == vrrp.checksum == 0x5AF6
        assert compute(vrrp, ip=replace(ip, src="192.0.2.99")) == 0x5AF6
        raw = bytes(vrrp)
        assert ones_complement(raw[:6] + b"\x00\x00" + raw[8:]) == 0x5AF6

    def test_vrrpv3_needs_the_ip_layer(self):
        vrrp, _ = self.advert(9)
        with pytest.raises(InvalidFieldError) as excinfo:
            compute(vrrp)
        err = excinfo.value
        assert err.protocol is VRRP
        assert err.field == "checksum"

    def test_vrrpv3_covers_the_ipv4_pseudo_header(self):
        """Protocol 112, the message's own length, and both addresses:
        a unicast advert's real destination, not the multicast group."""
        vrrp, ip = self.advert(15)
        assert ip.dst == "10.9.20.2"
        expected = v3_checksum_v4(ip.src, ip.dst, bytes(vrrp))
        assert compute(vrrp, ip=ip) == expected == vrrp.checksum
        assert compute(vrrp, ip=replace(ip, dst="224.0.0.18")) != expected
        assert compute(vrrp, ip=replace(ip, src="10.9.20.9")) != expected

    def test_vrrpv3_covers_the_ipv6_pseudo_header(self):
        vrrp, ip = self.v6()
        assert compute(vrrp, ip=ip) == vrrp.checksum
        assert verify(vrrp, ip=ip)
        assert not verify(vrrp, ip=replace(ip, src="fe80::2"))

    def test_the_rfc_9568_ipv4_form_does_not_verify(self):
        """RFC 9568 §5.2.8 leaves the pseudo-header out over IPv4;
        compute() follows keepalived's default, so such an advert fails
        verify()."""
        vrrp, ip = self.advert(9)
        raw = bytes(vrrp)
        without = ones_complement(raw[:6] + b"\x00\x00" + raw[8:])
        assert without != vrrp.checksum
        assert not verify(replace(vrrp, checksum=without), ip=ip)

    def test_the_checksum_field_is_excluded(self):
        for index in (0, 9):
            vrrp, ip = self.advert(index)
            assert compute(replace(vrrp, checksum=0xFFFF), ip=ip) == (
                vrrp.checksum
            )

    def test_a_zero_sum_is_sent_as_zero(self):
        """Return ``0x0000`` for a message whose checksum is zero.

        VRRP has no UDP-style ``0x0000 → 0xFFFF`` substitution. The last
        authentication-data word of this VRRPv2 message was chosen to
        make its checksum zero.
        """
        raw = bytes.fromhex("2133c802010100000a0914330a0914346e702d767272caf6")
        assert ones_complement(raw) == 0x0000
        vrrp = VRRP.decode(raw)
        assert compute(vrrp) == 0x0000
        assert verify(vrrp)
        assert not verify(replace(vrrp, checksum=0xFFFF))

    def test_payload_is_ignored(self):
        """Nothing after the message is part of it: padding passed as
        ``payload`` (as with_checksums() passes its own) cannot reach
        the sum."""
        for index in (0, 9):
            vrrp, ip = self.advert(index)
            assert compute(vrrp, ip=ip, payload=b"\x01\x02") == vrrp.checksum
            assert verify(vrrp, ip=ip, payload=b"\x01\x02")

    def test_a_flipped_bit_is_detected(self):
        for index in (0, 9):
            vrrp, ip = self.advert(index)
            raw = bytes(vrrp)
            for position in (0, 3, 5, 8, len(raw) - 1):
                flipped = bytearray(raw)
                flipped[position] ^= 0x01
                try:
                    corrupted = VRRP.decode(bytes(flipped))
                except ProtocolError:
                    continue  # a flipped version or count no longer decodes
                assert not verify(corrupted, ip=ip), (index, position)

    def test_with_checksums_fills_both_families(self):
        for vrrp, ip in (self.advert(3), self.advert(16), self.v6()):
            stale = replace(vrrp, checksum=0)
            (_, filled) = Packet(ip, stale).with_checksums().layers
            assert filled.checksum == vrrp.checksum


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

    def test_udp_zero_checksum_fails_over_ipv6(self):
        """Over IPv6 the UDP checksum is mandatory (RFC 8200 §8.1), so
        a zero is a wrong checksum, not an absent one: the rule that
        spares IPv4 must be handed the enclosing IP layer."""
        udp, _ = self.make_udp(0)
        ip = IPv6(
            version=6,
            traffic_class=0,
            flow_label=0,
            payload_length=12,
            next_header=17,
            hop_limit=64,
            src="2001:db8::1",
            dst="2001:db8::2",
        )
        assert compute(udp, ip=ip, payload=b"1234") != 0
        assert not verify(udp, ip=ip, payload=b"1234")

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


def ospf_packets() -> list[OSPF]:
    return [walk(frame)[0][2] for frame in pcap_frames(FIXTURES / "ospf.pcap")]


def ospf_instance_1_md5_frame() -> bytes:
    """Return a captured AuType 2 frame moved to Instance ID 1.

    RFC 6549 §2 puts the Instance ID in header byte 14.

    The digest covers header byte 14, so it is recomputed with the
    published key (tests/fixtures/MANIFEST.md); the IPv4 header is
    untouched.
    """
    import hashlib

    frame = bytearray(pcap_frames(FIXTURES / "ospf.pcap")[37])
    frame[34 + 14] = 1
    length = int.from_bytes(frame[36:38], "big")
    packet = bytes(frame[34 : 34 + length])
    # RFC 2328 Appendix D mandates MD5; this recomputes a router's digest.
    digest = hashlib.md5(
        packet + b"NETProtocols-md5", usedforsecurity=False
    ).digest()
    frame[34 + length :] = digest
    return bytes(frame)


def ospf_extended(**fields) -> OSPF:
    """Return an AuType 3 Hello (RFC 7474 §3).

    Its 28-byte trailer is the 8-byte sequence number, then a 20-byte
    digest.
    """
    values = {
        "au_type": 3,
        "authentication": b"\x00\x00\x00\x1c" + (7).to_bytes(4, "big"),
        "auth_trailer": bytes(range(28)),
    }
    values.update(fields)
    return ospf_hello(**values)


def ospf_hello(**fields) -> OSPF:
    body = bytes.fromhex("ffffff00000a0201000000280a0953010a0953020a000002")
    values = {
        "version": 2,
        "type": 1,
        "packet_length": 24 + len(body),
        "router_id": "10.0.0.1",
        "area_id": "0.0.0.1",
        "checksum": 0,
        "instance_id": 0,
        "au_type": 0,
        "authentication": bytes(8),
        "body": body,
    }
    values.update(fields)
    return OSPF(**values)


class TestOSPFChecksum:
    """The packet checksum: the internet checksum of the whole packet
    but the Authentication field (RFC 2328 §D.4.1), none under
    cryptographic authentication (§D.4.3)."""

    def test_every_captured_packet_recomputes(self):
        packets = ospf_packets()
        checksummed = [p for p in packets if p.au_type != 2]
        assert {p.au_type for p in checksummed} == {0, 1}
        assert len(checksummed) == 36
        for ospf in checksummed:
            assert compute(ospf) == ospf.checksum
            assert verify(ospf)

    def test_the_sum_is_over_the_packet_without_its_authentication(self):
        ospf = ospf_hello(checksum=0x1234, authentication=b"password")
        wire = bytes(ospf)
        covered = wire[:12] + b"\x00\x00" + wire[14:16] + wire[24:]
        assert compute(ospf) == internet_checksum(covered)

    def test_the_authentication_field_is_excluded(self):
        ospf = ospf_hello(au_type=1, authentication=b"NPospf1\x00")
        other = replace(ospf, authentication=b"\xff" * 8)
        assert compute(ospf) == compute(other)

    def test_the_checksum_field_is_excluded(self):
        assert compute(ospf_hello(checksum=0xBEEF)) == compute(ospf_hello())

    def test_the_free_header_fields_are_covered(self):
        """Change the checksum with each freely settable header field.

        Those are Type, Router ID, Area ID, Instance ID and AuType.
        Version and Packet Length cannot be changed alone (only 2
        constructs, and the length must match the body); the body is
        tested below.
        """
        base = compute(ospf_hello())
        for changed in (
            ospf_hello(router_id="10.0.0.2"),
            ospf_hello(area_id="0.0.0.2"),
            ospf_hello(instance_id=1),
            ospf_hello(au_type=1),
            ospf_hello(type=6),
        ):
            assert compute(changed) != base

    def test_ip_and_payload_are_ignored(self):
        """An LLS block after the packet is passed as payload by
        with_checksums(); the checksum must not cover it."""
        ospf = ospf_hello()
        assert compute(ospf, payload=b"\x00\x00\x00\x03lls!") == compute(ospf)

    def test_a_flipped_body_bit_is_detected(self):
        ospf = replace(ospf_hello(), checksum=compute(ospf_hello()))
        assert verify(ospf)
        flipped = bytearray(ospf.body)
        flipped[-1] ^= 0x01
        assert not verify(replace(ospf, body=bytes(flipped)))

    def test_cryptographic_authentication_computes_none(self):
        ospf = ospf_packets()[-1]
        assert ospf.au_type == 2
        with pytest.raises(InvalidFieldError) as excinfo:
            compute(ospf)
        err = excinfo.value
        assert err.protocol is OSPF
        assert err.field == "checksum"
        assert str(err) == (
            "An OSPF packet under cryptographic authentication (AuType 2) "
            "carries no checksum; its digest protects it (RFC 2328 §D.4.3)"
        )

    @pytest.mark.parametrize("checksum", [0, 1, 0xFFFF])
    def test_cryptographic_authentication_verifies_vacuously(self, checksum):
        ospf = replace(ospf_packets()[-1], checksum=checksum)
        assert verify(ospf)

    def test_extended_sequence_numbers_compute_none(self):
        """Compute no checksum under AuType 3 either.

        RFC 7474 §5 keeps RFC 5709 §3.1's process, which keeps RFC 2328
        §D.4.3 step 2.
        """
        with pytest.raises(InvalidFieldError) as excinfo:
            compute(ospf_extended())
        assert str(excinfo.value) == (
            "An OSPF packet under cryptographic authentication (AuType 3) "
            "carries no checksum; its digest protects it (RFC 2328 §D.4.3)"
        )

    @pytest.mark.parametrize("checksum", [0, 0x1234])
    def test_extended_sequence_numbers_verify_vacuously(self, checksum):
        """Verify any checksum under AuType 3."""
        assert verify(ospf_extended(checksum=checksum))

    def test_with_checksums_leaves_extended_sequence_numbers_alone(self):
        """Leave the checksum field alone under AuType 3."""
        ospf = ospf_extended(checksum=0x1234)
        packet = Packet(Ethernet.decode(bytes(14)), ospf)
        assert packet.with_checksums()[OSPF].checksum == 0x1234

    @pytest.mark.parametrize("au_type", [0, 1, 4])
    def test_only_au_types_2_and_3_are_spared(self, au_type):
        """Compute, verify and fill the checksum under any other AuType."""
        ospf = ospf_hello(au_type=au_type, checksum=0x1234)
        assert compute(ospf) != 0x1234
        assert not verify(ospf)
        packet = Packet(Ethernet.decode(bytes(14)), ospf)
        assert packet.with_checksums()[OSPF].checksum == compute(ospf)

    def test_a_nonzero_instance_id_keeps_cryptographic_authentication(self):
        """Keep AuType 2 cryptographic under Instance ID 1.

        RFC 6549 §2 makes AuType byte 15 alone, so Instance ID 1 does
        not turn AuType 2 into 258. The digest stays in the layer,
        verify() passes it, and with_checksums() leaves its zero
        checksum alone, which the digest covers.
        """
        frame = ospf_instance_1_md5_frame()
        packet = decode_frame(frame)
        ospf = packet[OSPF]
        assert (ospf.instance_id, ospf.au_type) == (1, 2)
        assert verify(ospf)
        assert bytes(packet.with_checksums()) == frame

    def test_a_nonzero_instance_id_under_au_type_0_is_checksummed(self):
        """Cover the Instance ID in the AuType 0 checksum."""
        frame = pcap_frames(FIXTURES / "ospf.pcap")[1]
        packet = decode_frame(frame)
        moved = replace(packet[OSPF], instance_id=1)
        rebuilt = Packet(packet[0], packet[IPv4], moved).with_checksums()
        assert rebuilt[OSPF].instance_id == 1
        assert rebuilt[OSPF].checksum != packet[OSPF].checksum
        assert verify(rebuilt[OSPF])

    def test_with_checksums_fills_a_built_packet(self):
        frame = pcap_frames(FIXTURES / "ospf.pcap")[1]
        packet = decode_frame(frame)
        blank = Packet(
            packet[0],
            replace(packet[IPv4], checksum=0),
            replace(packet[OSPF], checksum=0),
        )
        assert blank.with_checksums() == packet
        assert bytes(blank.with_checksums()) == frame

    def test_with_checksums_leaves_cryptographic_packets_alone(self):
        for frame in pcap_frames(FIXTURES / "ospf.pcap")[36:]:
            packet = decode_frame(frame)
            assert packet[OSPF].checksum == 0
            blank = Packet(
                packet[0], replace(packet[IPv4], checksum=0), packet[OSPF]
            )
            assert blank.with_checksums() == packet


def fletcher_sums(data: bytes) -> tuple[int, int]:
    """Return RFC 905 B.4's running sums, reimplemented here.

    Both are 0 modulo 255 over a correctly checksummed field. verify_lsa
    makes the same check, and also rejects a zero LS Checksum; this copy
    keeps the tests from trusting the library's sums.
    """
    c0 = c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return c0, c1


class TestFletcherChecksum:
    def placed(self, data: bytes, offset: int) -> bytes:
        field = fletcher_checksum(data, offset).to_bytes(2, "big")
        return data[:offset] + field + data[offset + 2 :]

    @pytest.mark.parametrize(
        "data,offset",
        [
            (b"\x01\x02\x00\x00\x03", 2),
            (bytes(range(1, 40)), 0),
            (bytes(range(200, 256)) * 3, 17),
            (b"\xff" * 9, 7),
            (bytes(range(256)), 254),
        ],
    )
    def test_the_field_zeroes_both_sums(self, data, offset):
        assert fletcher_sums(self.placed(data, offset)) == (0, 0)

    def test_the_field_bytes_are_read_as_zero(self):
        data = bytes(range(10, 30))
        clobbered = data[:6] + b"\xab\xcd" + data[8:]
        assert fletcher_checksum(data, 6) == fletcher_checksum(clobbered, 6)

    def test_zero_is_reported_as_255(self):
        """A computed X or Y of 0 is sent as 255 (RFC 905 B.2(b) makes
        them equal; RFC 1008 §7.2.1's code writes 255), so the field
        never holds a zero byte. Worked by hand: over 01 [X Y] 02,
        C0 = 3 and C1 = 6 with the field zeroed, so X = (2 * 3 - 6) mod
        255 = 0, sent as 255, and Y = 510 - 3 - 255 = 252; over
        02 [X Y] 01, C0 = 3 and C1 = 9, so X = (2 * 3 - 9) mod 255 =
        252 and Y = (510 - 3 - 252) mod 255 = 0, sent as 255."""
        assert fletcher_checksum(b"\x01\x00\x00\x02", 1) == 0xFFFC
        assert fletcher_checksum(b"\x02\x00\x00\x01", 1) == 0xFCFF
        assert fletcher_checksum(bytes(10), 4) == 0xFFFF

    def test_known_values(self):
        # Over 01 02 [X Y] 03: C0 = 6, C1 = 16, X = (2 * 6 - 16) mod
        # 255 = 251, Y = (510 - 6 - 251) mod 255 = 253.
        assert fletcher_checksum(b"\x01\x02\x00\x00\x03", 2) == 0xFBFD
        # Over 05 [X Y]: C0 = 5, C1 = 15, X = (1 * 5 - 15) mod 255 =
        # 245, Y = (510 - 5 - 245) mod 255 = 5.
        assert fletcher_checksum(b"\x05\x00\x00", 1) == 0xF505
        # Over [X Y] 07: C0 = C1 = 7, X = (2 * 7 - 7) = 7,
        # Y = (510 - 7 - 7) mod 255 = 241.
        assert fletcher_checksum(b"\x00\x00\x07", 0) == 0x07F1

    def test_memoryview_input(self):
        data = bytes(range(1, 30))
        assert fletcher_checksum(memoryview(data), 3) == fletcher_checksum(
            data, 3
        )

    @pytest.mark.parametrize(
        "data,offset", [(b"ab", 0), (b"abc", 0), (b"abc", 1)]
    )
    def test_the_field_may_sit_at_either_end(self, data, offset):
        """Accept the field at offset 0 and at len(data) - 2."""
        assert fletcher_sums(self.placed(data, offset)) == (0, 0)

    @pytest.mark.parametrize(
        "data,offset",
        [
            (b"", 0),
            (b"", 14),
            (b"a", 0),
            (b"abc", 2),
            (b"abc", 5),
            (b"abcd", -1),
        ],
    )
    def test_a_field_outside_the_data_raises(self, data, offset):
        """Raise ValueError for a field that does not lie in the data."""
        with pytest.raises(ValueError) as excinfo:
            fletcher_checksum(data, offset)
        assert str(excinfo.value) == (
            f"a 2-byte checksum field at offset {offset} does not fit in "
            f"{len(data)} bytes"
        )


class TestLSAChecksum:
    """Each LSA's LS Checksum: Fletcher over the LSA but its LS Age (RFC
    2328 §12.1.7)."""

    def lsas(self) -> list[OSPFLSA]:
        return [lsa for ospf in ospf_packets() for lsa in ospf.lsas or ()]

    def test_every_captured_lsa_recomputes(self):
        lsas = self.lsas()
        assert len(lsas) == 18
        assert {lsa.header.ls_type for lsa in lsas} == {1, 2, 5}
        for lsa in lsas:
            assert lsa_checksum(lsa) == lsa.header.ls_checksum
            assert verify_lsa(lsa)
            assert fletcher_sums(bytes(lsa)[2:]) == (0, 0)

    def test_ls_age_is_excluded(self):
        lsa = self.lsas()[0]
        aged = OSPFLSA(replace(lsa.header, ls_age=3600), lsa.body)
        assert lsa_checksum(aged) == lsa_checksum(lsa)
        assert verify_lsa(aged)

    def test_the_checksum_field_is_excluded(self):
        lsa = self.lsas()[0]
        blank = OSPFLSA(replace(lsa.header, ls_checksum=0), lsa.body)
        assert lsa_checksum(blank) == lsa.header.ls_checksum
        assert not verify_lsa(blank)

    def test_a_flipped_body_bit_is_detected(self):
        lsa = self.lsas()[0]
        flipped = bytes([lsa.body[0] ^ 0x01]) + lsa.body[1:]
        assert not verify_lsa(OSPFLSA(lsa.header, flipped))

    def test_a_flipped_header_bit_is_detected(self):
        lsa = self.lsas()[0]
        flipped = replace(lsa.header, options=lsa.header.options ^ 0x01)
        assert not verify_lsa(OSPFLSA(flipped, lsa.body))

    def lsa(self, body: bytes, checksum: int | None = None) -> OSPFLSA:
        """Build an LSA around ``body``.

        It is correctly checksummed unless a ``checksum`` is given.
        """
        header = OSPFLSAHeader(
            ls_age=1,
            options=2,
            ls_type=1,
            link_state_id="10.0.0.1",
            advertising_router="10.0.0.1",
            ls_sequence_number=0x80000001,
            ls_checksum=0,
            length=20 + len(body),
        )
        lsa = OSPFLSA(header, body)
        if checksum is None:
            checksum = lsa_checksum(lsa)
        return OSPFLSA(replace(header, ls_checksum=checksum), body)

    def test_a_zero_byte_verifies_as_255(self):
        """Verify a zero checksum byte where the generator writes 0xff.

        RFC 905 B.4 checks the sums, not the field: 0x00 and 0xff are
        equal modulo 255, so the 0x31ff this LSA generates verifies
        stored as 0x3100 too.
        """
        lsa = self.lsa(b"\x01\x02\x03\x16")
        assert lsa.header.ls_checksum == 0x31FF
        assert verify_lsa(lsa)
        assert verify_lsa(self.lsa(lsa.body, 0x3100))
        assert not verify_lsa(self.lsa(lsa.body, 0x3101))

    def test_a_zero_checksum_fails_though_its_sums_are_zero(self):
        """Reject an LS Checksum of 0x0000, which zeroes both sums here.

        This LSA generates 0xffff, and 0x0000 is equal to it modulo
        255, so RFC 905 B.4 alone would pass it; RFC 2328 §12.1.7 says
        the field cannot be zero and calls a zero a checksum failure.
        The zero rule is on the 16-bit value: one zero byte is fine.
        """
        lsa = self.lsa(bytes.fromhex("8a00c200"))
        assert lsa.header.ls_checksum == 0xFFFF
        assert verify_lsa(lsa)
        assert verify_lsa(self.lsa(lsa.body, 0x00FF))
        assert verify_lsa(self.lsa(lsa.body, 0xFF00))
        zero = self.lsa(lsa.body, 0)
        assert fletcher_sums(bytes(zero)[2:]) == (0, 0)
        assert not verify_lsa(zero)

    def test_swapped_adjacent_bytes_are_detected(self):
        """Reject two swapped adjacent bytes.

        The swap leaves C0 at 0 and moves C1 alone, so a check of C0 by
        itself would pass it.
        """
        lsa = self.lsa(b"\x01\x02\x03\x16")
        swapped = self.lsa(b"\x01\x03\x02\x16", lsa.header.ls_checksum)
        assert fletcher_sums(bytes(swapped)[2:])[0] == 0
        assert not verify_lsa(swapped)

    def test_a_c1_preserving_change_is_detected(self):
        """Reject a change that leaves C1 at 0.

        Adding 1 to the second-to-last byte and taking 2 from the last
        moves C0 alone, so a check of C1 by itself would pass it.
        """
        lsa = self.lsa(b"\x01\x02\x03\x16")
        changed = self.lsa(b"\x01\x02\x04\x14", lsa.header.ls_checksum)
        assert fletcher_sums(bytes(changed)[2:])[1] == 0
        assert not verify_lsa(changed)


# --- IPv6 Routing headers: the final destination (#236, RFC 8200 §8.1) ---
#
# These live here, not in a file of their own, because this file is in the
# mutation audit's test selection (pyproject.toml's [tool.mutmut]): a test
# elsewhere never reaches the mutants of ``_pseudo_ip``, ``compute`` or
# ``verify``. Every expected checksum is computed by :func:`ref_checksum`,
# a stdlib-only ones'-complement sum written here from RFC 8200 §8.1 and
# RFC 1071, sharing no code with ``netprotocols.checksum``. ``ISSUE_FRAME``
# is the issue's reproduction frame, whose wire checksum (0x2fad) was
# computed the same independent way before the fix existed.

RT_SRC = "2001:db8::1"
RT_NEXT_HOP = "2001:db8::2"
RT_FINAL = "2001:db8::99"

ISSUE_FRAME = bytes.fromhex(
    "6000000000322b4020010db800000000000000000000000120010db800000000"
    "0000000000000002110404010100000020010db8000000000000000000000099"
    "20010db800000000000000000000000203e807d0000a2fad6869"
)


def pton(address: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, address)


def ref_checksum(src: str, dst: str, next_header: int, message: bytes) -> int:
    """RFC 8200 §8.1 + RFC 1071, from scratch: the checksum of
    ``message`` (its checksum field zeroed) behind the IPv6 pseudo-header
    for ``src``, ``dst`` and ``next_header``. UDP sends a computed zero
    as 0xFFFF (RFC 768)."""
    data = (
        pton(src)
        + pton(dst)
        + struct.pack("!IBBBB", len(message), 0, 0, 0, next_header)
        + message
    )
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    value = ~total & 0xFFFF
    return (value or 0xFFFF) if next_header == 17 else value


def udp_message(
    payload: bytes = b"hi",
    sport: int = 1000,
    dport: int = 2000,
    value: int = 0,
) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), value) + payload


def routing_type0(addresses: list[str], segments_left: int) -> bytes:
    body = b"\x00" * 4 + b"".join(pton(a) for a in addresses)
    return bytes([17, len(addresses) * 2, 0, segments_left]) + body


def routing_type2(home: str) -> bytes:
    return bytes([17, 2, 2, 1]) + b"\x00" * 4 + pton(home)


def routing_rpl(
    cmpr_i: int, cmpr_e: int, pad: int, entries: bytes, segments_left: int
) -> bytes:
    body = bytes([cmpr_i << 4 | cmpr_e, pad << 4, 0, 0]) + entries
    body += b"\x00" * pad
    assert len(body) % 8 == 4
    return bytes([17, (len(body) - 4) // 8, 3, segments_left]) + body


def routing_srh(segment_list: list[str], segments_left: int) -> bytes:
    body = bytes([len(segment_list) - 1, 0, 0, 0])
    body += b"".join(pton(a) for a in segment_list)
    assert len(body) % 8 == 4
    return bytes([17, (len(body) - 4) // 8, 4, segments_left]) + body


def build_upper(
    routings: bytes | list[bytes],
    next_header: int,
    message: bytes,
    offset: int,
    wire_dst: str,
    final: str,
    src: str = RT_SRC,
) -> bytes:
    """IPv6 (dst ``wire_dst``) + the Routing header(s) + ``message``,
    whose 2-byte checksum field at ``offset`` holds the reference value
    for ``final``. Each header's Next Header is patched to name the
    next one (43), the last to ``next_header``."""
    if isinstance(routings, bytes):
        routings = [routings]
    chain = b"".join(
        bytes([43 if i < len(routings) - 1 else next_header]) + header[1:]
        for i, header in enumerate(routings)
    )
    value = ref_checksum(src, final, next_header, message)
    message = (
        message[:offset] + struct.pack("!H", value) + message[offset + 2 :]
    )
    ip = (
        struct.pack("!IHBB", 0x60000000, len(chain) + len(message), 43, 64)
        + pton(src)
        + pton(wire_dst)
    )
    return ip + chain + message


def build_frame(
    routing: bytes | list[bytes],
    wire_dst: str,
    final: str,
    payload: bytes = b"hi",
    src: str = RT_SRC,
    sport: int = 1000,
    dport: int = 2000,
) -> bytes:
    """A UDP datagram ``sport`` -> ``dport`` behind ``routing``."""
    message = udp_message(payload, sport, dport)
    return build_upper(routing, 17, message, 6, wire_dst, final, src)


def wire_checksum(frame: bytes, payload_len: int = 2) -> int:
    """The UDP checksum of a frame :func:`build_frame` made."""
    return int.from_bytes(frame[-payload_len - 2 : -payload_len], "big")


def zero_udp_checksum(frame: bytes, payload_len: int = 2) -> bytes:
    at = len(frame) - payload_len - 2
    return frame[:at] + b"\x00\x00" + frame[at + 2 :]


#: (id, routing header, ip.dst on the wire, the destination RFC 8200
#: §8.1 puts in the pseudo-header)
ROUTES = [
    (
        "type0",
        routing_type0(["2001:db8::50", RT_NEXT_HOP, RT_FINAL], 2),
        "2001:db8::50",
        RT_FINAL,
    ),
    ("type2", routing_type2(RT_FINAL), RT_NEXT_HOP, RT_FINAL),
    (
        # CmprI 0 (Address[1] whole), CmprE 8 (Address[2] its last 8
        # octets): the final address borrows dst's first 8 octets.
        "rpl-cmpr-i0-e8",
        routing_rpl(
            0,
            8,
            0,
            pton("2001:db8:0:0:0:0:0:50") + pton(RT_FINAL)[8:],
            2,
        ),
        "2001:db8:0:0:0:0:0:5",
        "2001:db8::99",
    ),
    (
        # CmprI 12, CmprE 12: one 4-octet entry (the last) and 4 Pad
        # octets after it.
        "rpl-pad",
        routing_rpl(12, 12, 4, pton("2001:db8::99")[12:], 1),
        "2001:db8::5",
        "2001:db8::99",
    ),
    (
        "rpl-two-entries",
        routing_rpl(
            12, 12, 0, pton("2001:db8::50")[12:] + pton("2001:db8::99")[12:], 2
        ),
        "2001:db8::5",
        "2001:db8::99",
    ),
    (
        "srh",
        routing_srh([RT_FINAL, "2001:db8::77", RT_NEXT_HOP], 2),
        RT_NEXT_HOP,
        RT_FINAL,
    ),
    (
        "srh-one-hop",
        routing_srh([RT_FINAL, RT_NEXT_HOP], 1),
        RT_NEXT_HOP,
        RT_FINAL,
    ),
]
ROUTE_IDS = [route[0] for route in ROUTES]
ROUTE_BY_ID = {route[0]: route[1:] for route in ROUTES}

#: transport kind -> (next header, message with a zeroed checksum, the
#: checksum field's offset in it, the bytes ``compute`` is passed as
#: ``payload``: TCP and UDP decode the header alone, the others hold
#: their whole message)
TRANSPORTS = {
    "udp": (17, udp_message(), 6, b"hi"),
    "tcp": (
        6,
        struct.pack("!HHIIBBHHH", 1000, 2000, 1, 0, 5 << 4, 0x18, 8192, 0, 0)
        + b"hi",
        16,
        b"hi",
    ),
    # Echo Request, identifier 1, sequence 2.
    "icmpv6": (58, bytes([128, 0, 0, 0, 0, 1, 0, 2]) + b"hi", 2, b""),
    # PIM Hello, version 2, Hold Time option (1) of 105 s (RFC 7761).
    "pim": (
        103,
        bytes([0x20, 0, 0, 0]) + struct.pack("!HHH", 1, 2, 105),
        2,
        b"",
    ),
    # VRRPv3 advert: VRID 7, priority 200, one address, 100 cs.
    "vrrp": (
        112,
        struct.pack("!BBBBHH", 0x31, 7, 200, 1, 100, 0) + pton("2001:db8::100"),
        6,
        b"",
    ),
}

#: (route id, transport kind): every transport behind types 0, 2, 3 and
#: 4, and PIM and VRRP behind an SRH with one segment left.
TRANSPORT_ROWS = [
    (route, kind)
    for route in ("type0", "type2", "rpl-cmpr-i0-e8", "srh")
    for kind in ("udp", "tcp", "icmpv6")
] + [("srh-one-hop", "pim"), ("srh-one-hop", "vrrp")]


class TestRoutingIssueFrame:
    def test_wire_checksum_verifies(self):
        p = decode_frame(ISSUE_FRAME, start=IPv6)
        assert wire_checksum(ISSUE_FRAME) == 0x2FAD
        assert p[UDP].checksum == 0x2FAD
        routing = p[IPv6Routing]
        assert verify(p[UDP], ip=p[IPv6], routing=routing, payload=b"hi")
        assert (
            compute(p[UDP], ip=p[IPv6], routing=routing, payload=b"hi")
            == 0x2FAD
        )

    def test_without_routing_it_is_the_old_value(self):
        p = decode_frame(ISSUE_FRAME, start=IPv6)
        assert compute(p[UDP], ip=p[IPv6], payload=b"hi") == 0x3044
        assert not verify(p[UDP], ip=p[IPv6], payload=b"hi")

    def test_reference_agrees_with_the_issue_frame(self):
        udp = udp_message()
        assert ref_checksum(RT_SRC, RT_FINAL, 17, udp) == 0x2FAD
        assert ref_checksum(RT_SRC, RT_NEXT_HOP, 17, udp) == 0x3044

    def test_with_checksums_rewrites_a_wrong_value(self):
        p = decode_frame(ISSUE_FRAME, start=IPv6)
        bad = Packet(
            *[
                replace(layer, checksum=1) if isinstance(layer, UDP) else layer
                for layer in p.layers
            ]
        )
        fixed = bad.with_checksums(payload=b"hi")
        assert bytes(fixed) + b"hi" == ISSUE_FRAME


@pytest.mark.parametrize(
    ("name", "routing", "wire_dst", "final"), ROUTES, ids=ROUTE_IDS
)
class TestRoutingEachType:
    def test_compute_verify_use_the_final_destination(
        self, name, routing, wire_dst, final
    ):
        frame = build_frame(routing, wire_dst, final)
        p = decode_frame(frame, start=IPv6)
        assert p[IPv6].dst == IPv6Address(wire_dst).compressed
        header = p[IPv6Routing]
        assert header.final_destination(p[IPv6].dst) == final
        got = compute(p[UDP], ip=p[IPv6], routing=header, payload=b"hi")
        assert got == wire_checksum(frame)
        assert verify(p[UDP], ip=p[IPv6], routing=header, payload=b"hi")
        # Without the routing header the next hop is used: wrong.
        assert not verify(p[UDP], ip=p[IPv6], payload=b"hi")

    def test_with_checksums_through_decode_frame(
        self, name, routing, wire_dst, final
    ):
        frame = build_frame(routing, wire_dst, final)
        p = decode_frame(zero_udp_checksum(frame), start=IPv6)
        assert p[UDP].checksum == 0
        fixed = p.with_checksums(payload=b"hi")
        assert bytes(fixed) + b"hi" == frame

    def test_memoryview_decode(self, name, routing, wire_dst, final):
        frame = build_frame(routing, wire_dst, final)
        p = decode_frame(memoryview(frame), start=IPv6)
        header = p[IPv6Routing]
        assert header.final_destination(p[IPv6].dst) == final
        assert verify(p[UDP], ip=p[IPv6], routing=header, payload=b"hi")


@pytest.mark.parametrize(
    ("route", "kind"),
    TRANSPORT_ROWS,
    ids=[f"{route}-{kind}" for route, kind in TRANSPORT_ROWS],
)
class TestRoutingEveryTransport:
    """TCP, ICMPv6, VRRPv3 and PIM take the final destination as UDP
    does, through ``compute``, ``verify`` and ``Packet.with_checksums``;
    each is checksummed independently by :func:`ref_checksum`."""

    def frame(self, route: str, kind: str) -> tuple[bytes, int, bytes]:
        routing, wire_dst, final = ROUTE_BY_ID[route]
        next_header, message, offset, tail = TRANSPORTS[kind]
        frame = build_upper(
            routing, next_header, message, offset, wire_dst, final
        )
        return frame, len(frame) - len(message) + offset, tail

    def test_compute_and_verify(self, route, kind):
        frame, at, tail = self.frame(route, kind)
        wire = int.from_bytes(frame[at : at + 2], "big")
        p = decode_frame(frame, start=IPv6)
        layer, ip, routing = p.layers[-1], p[IPv6], p[IPv6Routing]
        assert ip.dst != ROUTE_BY_ID[route][2]
        assert compute(layer, ip=ip, routing=routing, payload=tail) == wire
        assert verify(layer, ip=ip, routing=routing, payload=tail)
        assert not verify(
            replace(layer, checksum=wire ^ 1),
            ip=ip,
            routing=routing,
            payload=tail,
        )
        # The next hop, which is all `ip` says, is the wrong address.
        assert compute(layer, ip=ip, payload=tail) != wire
        assert not verify(layer, ip=ip, payload=tail)

    def test_with_checksums(self, route, kind):
        frame, at, tail = self.frame(route, kind)
        zeroed = frame[:at] + b"\x00\x00" + frame[at + 2 :]
        p = decode_frame(zeroed, start=IPv6)
        assert p.layers[-1].checksum == 0
        assert bytes(p.with_checksums(tail)) + tail == frame


class TestRoutingFallsBackToIpDst:
    def test_segments_left_zero_uses_ip_dst(self):
        # The last hop: ip.dst IS the final destination, while the
        # list's final entry deliberately differs, to pin the `> 0`.
        for routing in (
            routing_srh(["2001:db8::77", RT_FINAL], 0),
            routing_type0(["2001:db8::77"], 0),
            routing_type2("2001:db8::77"),
        ):
            routing = routing[:3] + b"\x00" + routing[4:]
            frame = build_frame(routing, RT_FINAL, RT_FINAL)
            p = decode_frame(frame, start=IPv6)
            header = p[IPv6Routing]
            assert header.segments_left == 0
            assert header.final_destination(RT_FINAL) == "2001:db8::77"
            assert verify(p[UDP], ip=p[IPv6], routing=header, payload=b"hi")
            zeroed = zero_udp_checksum(frame)
            assert (
                bytes(decode_frame(zeroed, start=IPv6).with_checksums(b"hi"))
                + b"hi"
                == frame
            )

    def test_unknown_routing_type(self):
        routing = bytes([17, 1, 253, 1]) + bytes(12)
        frame = build_frame(routing, RT_NEXT_HOP, RT_NEXT_HOP)
        p = decode_frame(frame, start=IPv6)
        header = p[IPv6Routing]
        assert header.final_destination(RT_NEXT_HOP) is None
        assert verify(p[UDP], ip=p[IPv6], routing=header, payload=b"hi")
        zeroed = zero_udp_checksum(frame)
        assert (
            bytes(decode_frame(zeroed, start=IPv6).with_checksums(b"hi"))
            + b"hi"
            == frame
        )

    def test_malformed_srh_falls_back(self):
        # Last Entry 5 but one segment of data.
        routing = bytes([17, 2, 4, 1, 5, 0, 0, 0]) + pton(RT_FINAL)
        frame = build_frame(routing, RT_NEXT_HOP, RT_NEXT_HOP)
        p = decode_frame(frame, start=IPv6)
        assert p[IPv6Routing].final_destination(RT_NEXT_HOP) is None
        assert verify(p[UDP], ip=p[IPv6], routing=p[IPv6Routing], payload=b"hi")

    def test_ipv4_ignores_routing(self):
        ip = IPv4(
            version=4, ihl=5, dscp=0, ecn=0, total_length=30, identification=0,
            flags=0, fragment_offset=0, ttl=64, protocol=17, checksum=0,
            src="10.0.0.1", dst="10.0.0.2",
        )  # fmt: skip
        udp = UDP(src_port=1, dst_port=2, length=10, checksum=0)
        routing = IPv6Routing.decode(routing_srh([RT_FINAL, RT_NEXT_HOP], 1))
        assert compute(udp, ip=ip, routing=routing, payload=b"hi") == compute(
            udp, ip=ip, payload=b"hi"
        )

    def test_the_pseudo_header_layer_is_the_same_object_when_unchanged(self):
        """``_pseudo_ip`` hands back ``ip`` itself unless the destination
        changes, so an IPv4 layer is never rebuilt (and revalidated)."""
        ip4 = IPv4(
            version=4, ihl=5, dscp=0, ecn=0, total_length=30, identification=0,
            flags=0, fragment_offset=0, ttl=64, protocol=17, checksum=0,
            src="10.0.0.1", dst="10.0.0.2",
        )  # fmt: skip
        frame = build_frame(
            routing_srh([RT_FINAL, RT_NEXT_HOP], 1), RT_NEXT_HOP, RT_FINAL
        )
        p = decode_frame(frame, start=IPv6)
        ip6, srh = p[IPv6], p[IPv6Routing]
        assert _pseudo_ip(ip4, srh) is ip4
        assert _pseudo_ip(ip6, None) is ip6
        assert _pseudo_ip(None, srh) is None
        assert _pseudo_ip(replace(ip6, dst=RT_FINAL), srh).dst == RT_FINAL
        spent = replace(srh, segments_left=0)
        assert _pseudo_ip(ip6, spent) is ip6
        unknown = replace(srh, routing_type=253)
        assert _pseudo_ip(ip6, unknown) is ip6
        changed = _pseudo_ip(ip6, srh)
        assert changed is not ip6
        assert changed == replace(ip6, dst=RT_FINAL)

    def test_no_ip_with_routing(self):
        routing = IPv6Routing.decode(routing_srh([RT_FINAL, RT_NEXT_HOP], 1))
        with pytest.raises(InvalidFieldError, match="requires"):
            compute(
                UDP(src_port=1, dst_port=2, length=10, checksum=0),
                routing=routing,
                payload=b"hi",
            )


class TestRoutingRPLSourceAndCompression:
    """RPL's last entry takes its first ``CmprE`` octets from the
    packet's *destination*, not its source, and the entries before it
    are ``CmprI`` octets each, not ``CmprE``: the vector has a source
    prefix unlike the destination's and CmprI 8 against CmprE 6."""

    SRC = "2001:db8:ffff::1"
    DST = "2001:db8:a:b::11"
    FINAL = "2001:db8:a:b::99"

    def frame(self) -> bytes:
        # Address[1], Address[2]: the last 8 octets of ::12 and ::13
        # (CmprI 8); Address[3]: the last 10 of ::99 (CmprE 6).
        entries = (
            pton("2001:db8:a:b::12")[8:]
            + pton("2001:db8:a:b::13")[8:]
            + pton(self.FINAL)[6:]
        )
        routing = routing_rpl(8, 6, 6, entries, 3)
        return build_frame(
            routing,
            self.DST,
            self.FINAL,
            payload=b"hello",
            src=self.SRC,
            sport=5353,
            dport=4242,
        )

    def test_the_reference_values(self):
        udp = udp_message(b"hello", 5353, 4242)
        assert ref_checksum(self.SRC, self.FINAL, 17, udp) == 0x3A66
        # Prefix from the source, and the "no address" fallback.
        assert ref_checksum(self.SRC, "2001:db8:ffff:b::99", 17, udp) == 0x3A70
        assert ref_checksum(self.SRC, self.DST, 17, udp) == 0x3AEE

    def test_the_prefix_comes_from_the_destination(self):
        frame = self.frame()
        p = decode_frame(frame, start=IPv6)
        routing = p[IPv6Routing]
        assert routing.final_destination(self.DST) == self.FINAL
        assert wire_checksum(frame, 5) == 0x3A66
        assert (
            compute(p[UDP], ip=p[IPv6], routing=routing, payload=b"hello")
            == 0x3A66
        )
        assert verify(p[UDP], ip=p[IPv6], routing=routing, payload=b"hello")
        zeroed = zero_udp_checksum(frame, 5)
        fixed = decode_frame(zeroed, start=IPv6).with_checksums(b"hello")
        assert bytes(fixed) + b"hello" == frame


class TestRoutingWhichHeader:
    """Several Routing headers: a receiver skips one with no segments
    left (RFC 8200 §4.4 for unrecognized types, and each type's own
    processing rules: RFC 2460 §4.4, RFC 6554 §4.2, RFC 8754 §4.3), so
    the route ends at the last with some."""

    DST = RT_NEXT_HOP
    ALIAS = "2001:db8::77"
    LAST = "2001:db8::aa"

    @pytest.mark.parametrize(
        ("headers", "expected"),
        [
            ([(ALIAS, 0), (LAST, 1)], LAST),  # the first is skipped
            ([(ALIAS, 1), (LAST, 1)], LAST),  # both have some: the later
            ([(ALIAS, 1), (LAST, 0)], ALIAS),  # the later is skipped
            ([(LAST, 1), (ALIAS, 0), (ALIAS, 0)], LAST),
            ([(ALIAS, 0), (ALIAS, 0)], DST),  # none left: ip.dst
        ],
        ids=["0-1", "1-1", "1-0", "1-0-0", "0-0"],
    )
    def test_the_last_with_segments_left_wins(self, headers, expected):
        routings = [routing_srh([last, self.DST], sl) for last, sl in headers]
        frame = build_frame(routings, self.DST, expected)
        assert wire_checksum(frame) == ref_checksum(
            RT_SRC, expected, 17, udp_message()
        )
        p = decode_frame(frame, start=IPv6)
        assert sum(isinstance(x, IPv6Routing) for x in p.layers) == len(headers)
        fixed = decode_frame(zero_udp_checksum(frame), start=IPv6)
        assert bytes(fixed.with_checksums(b"hi")) + b"hi" == frame
        key = p.flow_key()
        assert key is not None
        assert expected in (key.addr_a, key.addr_b)

    def test_the_rules_give_different_checksums(self):
        # So the cases above pin the rule, not a coincidence.
        values = {
            ref_checksum(RT_SRC, dst, 17, udp_message())
            for dst in (self.DST, self.ALIAS, self.LAST)
        }
        assert len(values) == 3

    def test_outer_tunnel_routing_is_not_between(self):
        outer_routing = IPv6Routing.decode(
            routing_srh(["2001:db8::77", RT_NEXT_HOP], 1)
        )
        inner = IPv6(
            version=6, traffic_class=0, flow_label=0, payload_length=0,
            next_header=43, hop_limit=64, src=RT_SRC, dst="2001:db8::abcd",
        )  # fmt: skip
        outer = replace(inner, dst=RT_NEXT_HOP)
        udp = UDP(src_port=1000, dst_port=2000, length=10, checksum=0)
        packet = Packet(outer, outer_routing, inner, udp)
        fixed = packet.with_checksums(payload=b"hi")
        assert fixed[UDP].checksum == ref_checksum(
            RT_SRC, "2001:db8::abcd", 17, udp_message()
        )


# --- The independent checker follows the route too (#259) ---
#
# scripts/check_fixtures.py resolves the final destination with code of
# its own, so each frame above must pass it as it passes the library,
# and the same frame summed for the wire Destination Address (what both
# did before #236 and #259) must fail it.

CHECKER = Path(__file__).resolve().parent.parent / "scripts/check_fixtures.py"


@pytest.fixture(scope="module")
def check_fixtures():
    """Load scripts/check_fixtures.py, which shares no library code."""
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def on_ethernet(packet: bytes) -> bytes:
    """``packet``, an IPv6 packet, in an Ethernet frame."""
    return bytes.fromhex("020000000002020000000001") + b"\x86\xdd" + packet


def transport_frame(route: str, kind: str, final: str | None = None) -> bytes:
    """A ``kind`` message behind ``route``, summed for ``final`` (the
    route's own final destination by default)."""
    routing, wire_dst, route_final = ROUTE_BY_ID[route]
    next_header, message, offset, _ = TRANSPORTS[kind]
    return build_upper(
        routing, next_header, message, offset, wire_dst, final or route_final
    )


#: Routing headers with segments left whose final destination cannot be
#: resolved, so the wire Destination Address stands.
UNRESOLVABLE = [
    # Unknown type 253.
    bytes([17, 1, 253, 1]) + bytes(12),
    # SRH: Last Entry 5 but one segment of data.
    bytes([17, 2, 4, 1, 5, 0, 0, 0]) + pton(RT_FINAL),
    # Mobile IPv6 with two addresses, not one.
    bytes([17, 4, 2, 1]) + bytes(4) + pton(RT_FINAL) * 2,
    # RH0 whose data is not 4 + 16n octets.
    bytes([17, 1, 0, 1]) + bytes(12),
    # RPL, CmprI 0: 8 octets before a 16-octet last entry do not tile
    # 16-octet entries.
    routing_rpl(0, 0, 0, bytes(8) + pton(RT_FINAL), 2),
]
UNRESOLVABLE_IDS = [
    "unknown",
    "srh-short",
    "type2-two",
    "rh0-ragged",
    "rpl-untiled",
]


def esp_null_frame(routing: bytes, final: str) -> bytes:
    """IPv6 to :data:`RT_NEXT_HOP` + ``routing`` + ESP in transport mode
    on the published SA 0x10000001 (NULL encryption, HMAC-SHA-256-128,
    RFC 4303 §2.4 default padding to 8 octets), protecting a UDP
    datagram summed for ``final``."""
    message = udp_message()
    value = ref_checksum(RT_SRC, final, 17, message)
    message = message[:6] + struct.pack("!H", value) + message[8:]
    pad = -(len(message) + 2) % 8
    protected = (
        struct.pack("!II", 0x10000001, 1)
        + message
        + bytes(range(1, pad + 1))
        + bytes([pad, 17])
    )
    icv = hmac.new(ESP_KEYS[0x10000001], protected, hashlib.sha256)
    chain = bytes([50]) + routing[1:] + protected + icv.digest()[:ICV_LEN]
    return (
        struct.pack("!IHBB", 0x60000000, len(chain), 43, 64)
        + pton(RT_SRC)
        + pton(RT_NEXT_HOP)
        + chain
    )


class TestRoutingIndependentChecker:
    def check(self, check_fixtures, packet: bytes) -> list[str]:
        stats = check_fixtures.Counter()
        failures = check_fixtures.check_frame(on_ethernet(packet), stats)
        assert stats["ipv6-ext-header"] >= 1
        return failures

    def test_the_issue_frame(self, check_fixtures):
        assert self.check(check_fixtures, ISSUE_FRAME) == []
        # 0x3044: the issue's value for the wire Destination Address.
        tampered = ISSUE_FRAME[:-4] + b"\x30\x44" + ISSUE_FRAME[-2:]
        assert self.check(check_fixtures, tampered) == ["udp6-checksum"]

    @pytest.mark.parametrize(
        ("name", "routing", "wire_dst", "final"), ROUTES, ids=ROUTE_IDS
    )
    def test_each_type(self, check_fixtures, name, routing, wire_dst, final):
        frame = build_frame(routing, wire_dst, final)
        assert self.check(check_fixtures, frame) == []
        old_rule = build_frame(routing, wire_dst, wire_dst)
        assert self.check(check_fixtures, old_rule) == ["udp6-checksum"]

    @pytest.mark.parametrize(("route", "kind"), TRANSPORT_ROWS)
    def test_every_transport(self, check_fixtures, route, kind):
        assert self.check(check_fixtures, transport_frame(route, kind)) == []
        wire_dst = ROUTE_BY_ID[route][1]
        old_rule = transport_frame(route, kind, final=wire_dst)
        (failure,) = self.check(check_fixtures, old_rule)
        assert failure.endswith("-checksum")

    def test_rpl_takes_its_prefix_from_the_destination(self, check_fixtures):
        case = TestRoutingRPLSourceAndCompression()
        frame = case.frame()
        assert self.check(check_fixtures, frame) == []
        # Prefixed from the source instead: 0x3a70 (see the class above).
        at = len(frame) - 5 - 2
        tampered = frame[:at] + b"\x3a\x70" + frame[at + 2 :]
        assert self.check(check_fixtures, tampered) == ["udp6-checksum"]

    @pytest.mark.parametrize(
        ("headers", "expected"),
        [
            ([("2001:db8::77", 0), ("2001:db8::aa", 1)], "2001:db8::aa"),
            ([("2001:db8::77", 1), ("2001:db8::aa", 1)], "2001:db8::aa"),
            ([("2001:db8::77", 1), ("2001:db8::aa", 0)], "2001:db8::77"),
            ([("2001:db8::77", 0), ("2001:db8::77", 0)], RT_NEXT_HOP),
        ],
        ids=["0-1", "1-1", "1-0", "0-0"],
    )
    def test_the_last_with_segments_left_wins(
        self, check_fixtures, headers, expected
    ):
        routings = [
            routing_srh([last, RT_NEXT_HOP], sl) for last, sl in headers
        ]
        frame = build_frame(routings, RT_NEXT_HOP, expected)
        assert self.check(check_fixtures, frame) == []
        p = decode_frame(frame, start=IPv6)
        assert p.with_checksums(b"hi")[UDP].checksum == wire_checksum(frame)
        for other in {"2001:db8::77", "2001:db8::aa", RT_NEXT_HOP} - {expected}:
            wrong = build_frame(routings, RT_NEXT_HOP, other)
            assert self.check(check_fixtures, wrong) == ["udp6-checksum"]

    @pytest.mark.parametrize("routing", UNRESOLVABLE, ids=UNRESOLVABLE_IDS)
    def test_an_unresolvable_route_falls_back_to_ip_dst(
        self, check_fixtures, routing
    ):
        frame = build_frame(routing, RT_NEXT_HOP, RT_NEXT_HOP)
        p = decode_frame(frame, start=IPv6)
        assert p[IPv6Routing].final_destination(RT_NEXT_HOP) is None
        assert self.check(check_fixtures, frame) == []
        resolved = build_frame(routing, RT_NEXT_HOP, RT_FINAL)
        assert self.check(check_fixtures, resolved) == ["udp6-checksum"]

    @pytest.mark.parametrize("routing", UNRESOLVABLE, ids=UNRESOLVABLE_IDS)
    def test_an_unresolvable_last_route_falls_back_past_an_earlier_one(
        self, check_fixtures, routing
    ):
        # The last Routing header with segments left decides, and when
        # it resolves nothing the wire address stands, not the end of
        # the earlier route the packet has already been routed by.
        routings = [routing_srh(["2001:db8::77", RT_NEXT_HOP], 1), routing]
        frame = build_frame(routings, RT_NEXT_HOP, RT_NEXT_HOP)
        assert self.check(check_fixtures, frame) == []
        p = decode_frame(frame, start=IPv6)
        assert p.with_checksums(b"hi")[UDP].checksum == wire_checksum(frame)
        earlier = build_frame(routings, RT_NEXT_HOP, "2001:db8::77")
        assert self.check(check_fixtures, earlier) == ["udp6-checksum"]

    def test_esp_transport_mode_behind_a_route(self, check_fixtures):
        # ESP in transport mode protects the upper-layer packet, whose
        # pseudo-header is still this packet's (RFC 4303 §3.1.1), so it
        # takes the route's end too.
        routing = routing_srh([RT_FINAL, RT_NEXT_HOP], 1)
        frame = esp_null_frame(routing, RT_FINAL)
        assert self.check(check_fixtures, frame) == []
        old_rule = esp_null_frame(routing, RT_NEXT_HOP)
        assert self.check(check_fixtures, old_rule) == ["udp6-checksum"]
        # The library agrees once the protected datagram is put back
        # behind the headers ESP left in front of it.
        p = decode_frame(frame, start=IPv6)
        _, payload = null_esp_payload(p[ESP])
        udp = UDP.decode(payload)
        rebuilt = Packet(p[IPv6], p[IPv6Routing], udp)
        assert rebuilt.with_checksums(payload[8:])[UDP] == udp

    def test_no_segments_left_uses_ip_dst(self, check_fixtures):
        routing = routing_srh(["2001:db8::77", RT_FINAL], 0)
        assert (
            self.check(check_fixtures, build_frame(routing, RT_FINAL, RT_FINAL))
            == []
        )
        alias = build_frame(routing, RT_FINAL, "2001:db8::77")
        assert self.check(check_fixtures, alias) == ["udp6-checksum"]


#: Every STUN message in the corpus, the two TCP segments' two each.
STUN_MESSAGES = [
    layer
    for frame in pcap_frames(FIXTURES / "stun.pcap")
    for layer in walk(frame)[0]
    if isinstance(layer, STUN)
]

#: The eleven of them that carry a FINGERPRINT.
STUN_FINGERPRINTED = [m for m in STUN_MESSAGES if m.fingerprint is not None]


def stun_with_fingerprint(attributes: bytes, value: bytes = bytes(4)) -> STUN:
    """A Binding Request of ``attributes`` and then a FINGERPRINT."""
    return STUN(
        0x0001,
        transaction_id=bytes(range(12)),
        attributes=attributes + bytes(STUNAttribute(STUN.FINGERPRINT, value)),
    )


class TestSTUNFingerprint:
    """STUN's FINGERPRINT: the IEEE CRC-32 of the message up to the
    attribute, XORed with 0x5354554E (RFC 8489 §14.7, RFC 5389
    §15.5)."""

    def test_the_corpus_carries_eleven(self):
        carrying = [m for m in STUN_MESSAGES if m.fingerprint is not None]
        assert len(STUN_MESSAGES) == 14
        assert len(carrying) == 11

    @pytest.mark.parametrize("index", range(14))
    def test_every_captured_message_verifies(self, index):
        message = STUN_MESSAGES[index]
        assert verify(message)
        if message.fingerprint is not None:
            assert compute(message) == message.fingerprint

    @pytest.mark.parametrize(
        ("raw", "wire"),
        [
            (RFC5769_REQUEST, 0xE57A3BCF),
            (RFC5769_IPV4, 0xC07D4C96),
            (RFC5769_IPV6, 0xC8FB0B4C),
        ],
        ids=["request", "ipv4-response", "ipv6-response"],
    )
    def test_rfc_5769_vectors(self, raw, wire):
        message = STUN.decode(raw)
        assert message.fingerprint == wire
        assert compute(message) == wire
        assert verify(message)

    def test_the_crc_is_ieee_crc32_xored(self):
        """Independently: zlib's CRC-32 of the message but its last 8
        bytes, XORed with "STUN" in ASCII."""
        for message in STUN_MESSAGES:
            if message.fingerprint is not None:
                assert compute(message) == (
                    zlib.crc32(bytes(message)[:-8]) ^ int.from_bytes(b"STUN")
                )

    def test_the_header_and_its_length_are_covered(self):
        """The CRC covers the 20-byte header, whose Length already
        counts the FINGERPRINT attribute (RFC 8489 §14.7)."""
        message = stun_with_fingerprint(bytes(STUNAttribute(0x8022, b"np")))
        filled = Packet(message).with_checksums()[STUN]
        assert verify(filled)
        for change in (
            replace(filled, message_type=0x0011),
            replace(filled, transaction_id=bytes(12)),
            replace(filled, magic_cookie=0x2112A443),
        ):
            assert not verify(change)
            assert compute(change) != filled.fingerprint
        assert compute(filled) == zlib.crc32(bytes(filled)[:-8]) ^ 0x5354554E
        assert bytes(filled)[2:4] == (16).to_bytes(2, "big")

    def test_a_flipped_bit_is_detected(self):
        message = STUN.decode(RFC5769_IPV4)
        raw = bytearray(bytes(message))
        raw[24] ^= 0x01
        assert not verify(STUN.decode(bytes(raw)))

    def test_the_fingerprint_itself_is_excluded(self):
        message = STUN.decode(RFC5769_IPV6)
        other = replace(
            message, attributes=message.attributes[:-4] + b"\xff" * 4
        )
        assert compute(other) == compute(message)
        assert not verify(other)

    def test_ip_and_payload_are_ignored(self):
        message = STUN.decode(RFC5769_REQUEST)
        ip = walk(pcap_frames(FIXTURES / "stun.pcap")[1])[0][1]
        assert compute(message, ip=ip, payload=b"xyz") == compute(message)
        assert verify(message, ip=ip, payload=b"xyz")

    def test_a_message_without_one_verifies_vacuously(self):
        message = STUN(0x0001, attributes=bytes(STUNAttribute(0x8022, b"x")))
        assert verify(message)
        with pytest.raises(InvalidFieldError) as excinfo:
            compute(message)
        err = excinfo.value
        assert (err.protocol, err.field) == (STUN, "attributes")
        assert str(err) == (
            "Computing a STUN fingerprint requires a FINGERPRINT "
            "attribute, last in the message (RFC 8489 §14.7)"
        )

    def test_a_fingerprint_that_is_not_last_fails(self):
        """RFC 8489 §14.7: it must be the last attribute."""
        message = stun_with_fingerprint(b"")
        message = Packet(message).with_checksums()[STUN]
        moved = replace(
            message,
            attributes=message.attributes + bytes(STUNAttribute(0x8022, b"x")),
        )
        assert moved.fingerprint is None
        assert not verify(moved)
        with pytest.raises(InvalidFieldError):
            compute(moved)

    @pytest.mark.parametrize("value", [b"", b"\x00\x00\x00", bytes(8)])
    def test_a_fingerprint_of_another_length_fails(self, value):
        message = stun_with_fingerprint(b"", value)
        assert message.fingerprint is None
        assert not verify(message)

    def test_a_fingerprint_behind_a_malformed_attribute(self):
        """A FINGERPRINT the walk cannot reach is not one it can
        verify, and the message may still carry it, so it fails; one
        the walk reaches before the malformed attribute is not last."""
        hidden = STUN(
            0x0001,
            attributes=b"\x80\x22\x00\x20"
            + bytes(STUNAttribute(STUN.FINGERPRINT, bytes(4))),
        )
        assert hidden.fingerprint is None
        assert not verify(hidden)
        with pytest.raises(InvalidFieldError):
            compute(hidden)
        early = STUN(
            0x0001,
            attributes=bytes(STUNAttribute(STUN.FINGERPRINT, bytes(4)))
            + b"\x80\x22\x00\x20",
        )
        assert early.fingerprint is None
        assert not verify(early)

    def test_a_malformed_list_without_a_fingerprint_fails(self):
        """A list that does not walk whole may hide a FINGERPRINT
        anywhere past the break, so it cannot be one without."""
        broken = STUN(0x0001, attributes=b"\x80\x22\x00\x20")
        assert not verify(broken)
        with pytest.raises(InvalidFieldError):
            compute(broken)

    @staticmethod
    def corrupt(offset: int, mask: int) -> STUN:
        """Fixture frame 1's Binding Success Response, one bit flipped
        at ``offset`` into the message."""
        raw = bytearray(bytes(STUN_FINGERPRINTED[0]))
        raw[offset] ^= mask
        return STUN.decode(bytes(raw))

    def test_a_length_that_breaks_the_walk_fails(self):
        """XOR-MAPPED-ADDRESS's Length 8 -> 12: the walk ends at the
        next attribute, short of the FINGERPRINT, which used to read as
        a message without one."""
        message = self.corrupt(20 + 3, 0x04)
        with pytest.raises(InvalidFieldError):
            _ = message.parsed_attributes
        with pytest.raises(InvalidFieldError):
            compute(message)
        assert message.fingerprint is None
        assert not verify(message)

    def test_a_length_that_swallows_the_fingerprint_fails(self):
        """RESPONSE-ORIGIN's Length 8 -> 40: the walk stays whole, the
        SOFTWARE and the FINGERPRINT folded into RESPONSE-ORIGIN's
        value, but the last 8 bytes still begin like a FINGERPRINT."""
        message = self.corrupt(20 + 24 + 3, 0x20)
        attributes = message.parsed_attributes
        assert [a.type for a in attributes] == [0x0020, 0x0001, 0x802B]
        assert len(attributes[-1].value) == 40
        assert message.attribute(STUN.FINGERPRINT) is None
        assert message.fingerprint is None
        with pytest.raises(InvalidFieldError):
            compute(message)
        assert not verify(message)

    @pytest.mark.parametrize("index", range(11))
    def test_every_single_bit_flip_fails(self, index):
        """CRC-32 catches every single-bit error in what it covers, so
        every flip of a captured FINGERPRINTed message that still
        decodes fails, but two kinds that leave a well-formed message
        with no FINGERPRINT at all, which nothing in the message itself
        can tell from one sent without: a flip of the FINGERPRINT's own
        type, which makes it another attribute, and a Length shrunk to
        end the message on an attribute boundary before it. Each is
        GRE's C bit cleared. The UDP or TCP checksum around the message
        still catches both.

        Over the eleven, 181 of the 7,392 flips verify: the 176 type
        flips and 5 cut-offs. Before presence was read from more than
        the walk, 858 did: 493 in the attributes before the
        FINGERPRINT, 165 in its Length, 24 in the header and the 176.
        """
        message = STUN_FINGERPRINTED[index]
        raw = bytes(message)
        type_flips = cut_offs = 0
        for bit in range(len(raw) * 8):
            flipped = bytearray(raw)
            flipped[bit // 8] ^= 0x80 >> bit % 8
            try:
                corrupted = STUN.decode(bytes(flipped))
            except ProtocolError:
                continue
            if not verify(corrupted):
                continue
            if bit // 8 in (len(raw) - 8, len(raw) - 7):
                type_flips += 1
                continue
            assert bit // 8 in (2, 3)
            kept = corrupted.parsed_attributes
            assert kept == message.parsed_attributes[: len(kept)]
            assert all(a.type != STUN.FINGERPRINT for a in kept)
            cut_offs += 1
        assert type_flips == 16
        assert cut_offs == (index in (1, 4, 7, 8, 10))

    def test_with_checksums_fills_a_built_message(self):
        built = stun_with_fingerprint(bytes(STUNAttribute(0x8022, b"np")))
        filled = Packet(built).with_checksums()
        message = filled[STUN]
        assert message.attributes[:-4] == built.attributes[:-4]
        assert message.fingerprint == compute(built)
        assert verify(message)

    def test_with_checksums_fills_stun_before_udp(self):
        """Innermost first: the UDP checksum covers the filled message."""
        frame = pcap_frames(FIXTURES / "stun.pcap")[1]
        layers = walk(frame)[0]
        eth, ip, udp, message = layers
        zeroed = Packet(
            eth,
            ip,
            replace(udp, checksum=0),
            replace(message, attributes=message.attributes[:-4] + bytes(4)),
        )
        assert bytes(zeroed.with_checksums()) == frame

    def test_with_checksums_leaves_the_rest_alone(self):
        """No FINGERPRINT: nothing to fill; MESSAGE-INTEGRITY, keyed,
        is never touched."""
        plain = STUN(0x0001, attributes=bytes(STUNAttribute(0x8022, b"x")))
        assert Packet(plain).with_checksums()[STUN] == plain
        signed = STUN_MESSAGES[-1]
        assert signed.message_integrity is not None
        refilled = Packet(signed).with_checksums()[STUN]
        assert refilled == signed
