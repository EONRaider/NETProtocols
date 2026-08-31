"""GRE decoding: the flags-driven optional fields, EtherType-based
payload dispatch, and the IP protocol-47 wiring."""

import struct

import pytest

from netprotocols import (
    GRE,
    IPProtocol,
    IPv4,
    IPv6,
    TruncatedHeaderError,
)


def build_gre(
    *,
    protocol_type: int = 0x0800,
    checksum: int | None = None,
    key: int | None = None,
    sequence: int | None = None,
    version: int = 0,
) -> bytes:
    """Assemble a GRE header, setting each flag bit for the optional
    fields that are supplied (RFC 2890 order: checksum, key, sequence)."""
    flags = version & 0x07
    fields = b""
    if checksum is not None:
        flags |= 0x8000
        fields += struct.pack("!HH", checksum, 0)  # checksum + reserved1
    if key is not None:
        flags |= 0x2000
        fields += struct.pack("!I", key)
    if sequence is not None:
        flags |= 0x1000
        fields += struct.pack("!I", sequence)
    return struct.pack("!HH", flags, protocol_type) + fields


def make_ipv4(*, protocol: int, total_length: int, src: str, dst: str) -> IPv4:
    return IPv4(
        version=4,
        ihl=5,
        dscp=0,
        ecn=0,
        total_length=total_length,
        identification=0,
        flags=0,
        fragment_offset=0,
        ttl=64,
        protocol=protocol,
        checksum=0,
        src=src,
        dst=dst,
    )


class TestGREFields:
    def test_minimal_header(self):
        gre = GRE.decode(build_gre(protocol_type=0x0800))
        assert gre.header_len == 4
        assert gre.protocol_type == 0x0800
        assert gre.protocol_name == "IPv4"
        assert gre.version == 0
        assert gre.checksum_present == 0
        assert gre.key_present == 0
        assert gre.sequence_present == 0
        assert gre.checksum is None
        assert gre.key is None
        assert gre.sequence_number is None
        assert gre.checksum_hex_str is None

    def test_checksum_present(self):
        gre = GRE.decode(build_gre(checksum=0x1C2A))
        assert gre.checksum_present == 1
        assert gre.checksum == 0x1C2A
        assert gre.checksum_hex_str == "0x1c2a"
        assert gre.header_len == 8

    def test_key_present(self):
        gre = GRE.decode(build_gre(key=0xDEADBEEF))
        assert gre.key_present == 1
        assert gre.key == 0xDEADBEEF
        assert gre.checksum is None
        assert gre.header_len == 8

    def test_sequence_present(self):
        gre = GRE.decode(build_gre(sequence=42))
        assert gre.sequence_present == 1
        assert gre.sequence_number == 42
        assert gre.header_len == 8

    def test_all_optional_fields_in_order(self):
        gre = GRE.decode(
            build_gre(checksum=0x1111, key=0x22223333, sequence=0x44445555)
        )
        assert gre.checksum == 0x1111
        assert gre.key == 0x22223333
        assert gre.sequence_number == 0x44445555
        assert gre.header_len == 4 + 12  # checksum+reserved, key, sequence

    def test_key_offset_skips_absent_checksum(self):
        # Key present, checksum absent: the key sits right after the
        # fixed 4 bytes, not 4 bytes further in.
        gre = GRE.decode(build_gre(key=0xABCD1234, sequence=9))
        assert gre.checksum is None
        assert gre.key == 0xABCD1234
        assert gre.sequence_number == 9

    def test_version_bits(self):
        assert GRE.decode(build_gre(version=1)).version == 1

    def test_unknown_protocol_type_name(self):
        # Transparent Ethernet Bridging (0x6558) is not decoded here.
        assert GRE.decode(build_gre(protocol_type=0x6558)).protocol_name == (
            "0x6558"
        )


class TestGREChain:
    def test_dispatches_to_ipv4(self):
        gre = GRE.decode(build_gre(protocol_type=0x0800))
        assert gre.next_protocol() is IPv4

    def test_dispatches_to_ipv6(self):
        gre = GRE.decode(build_gre(protocol_type=0x86DD))
        assert gre.next_protocol() is IPv6

    def test_unknown_protocol_type_ends_chain(self):
        gre = GRE.decode(build_gre(protocol_type=0x6558))
        assert gre.next_protocol() is None

    def test_ipv4_protocol_47_dispatches_to_gre(self):
        ip = make_ipv4(
            protocol=47, total_length=24, src="10.0.0.1", dst="10.0.0.2"
        )
        assert ip.next_protocol() is GRE

    def test_ipv6_next_header_47_dispatches_to_gre(self):
        ip = IPv6(
            version=6,
            traffic_class=0,
            flow_label=0,
            payload_length=4,
            next_header=47,
            hop_limit=64,
            src="2001:db8::1",
            dst="2001:db8::2",
        )
        assert ip.next_protocol() is GRE

    def test_protocol_number_and_display_name(self):
        assert IPProtocol.GRE == 47
        assert IPProtocol.GRE.display_name == "GRE"

    def test_full_ipv4_gre_ipv4_walk(self):
        # IP-in-IP over GRE: IPv4 (proto 47) -> GRE (0x0800) -> IPv4.
        inner = make_ipv4(
            protocol=253,  # unknown upper protocol: the chain ends here
            total_length=20,
            src="192.168.0.1",
            dst="192.168.0.2",
        )
        outer = make_ipv4(
            protocol=47, total_length=44, src="10.0.0.1", dst="10.0.0.2"
        )
        frame = bytes(outer) + build_gre(protocol_type=0x0800) + bytes(inner)
        layers = []
        cursor, protocol = 0, IPv4
        while protocol is not None:
            header = protocol.decode(frame[cursor:])
            layers.append(header)
            cursor += header.header_len
            protocol = header.next_protocol()
        assert [type(layer) for layer in layers] == [IPv4, GRE, IPv4]
        assert layers[2].src == "192.168.0.1"


class TestGREContract:
    def test_truncated_fixed_header_raises(self):
        with pytest.raises(TruncatedHeaderError):
            GRE.decode(b"\x00\x00\x08")  # 3 bytes, fixed header needs 4

    def test_flags_declare_optional_fields_past_the_buffer(self):
        # Checksum bit set, but the announced 4 optional bytes are absent.
        with pytest.raises(TruncatedHeaderError):
            GRE.decode(struct.pack("!HH", 0x8000, 0x0800))

    def test_round_trip_byte_exact(self):
        for kwargs in (
            {"protocol_type": 0x0800},
            {"checksum": 0x1C2A},
            {"key": 0xDEADBEEF},
            {"sequence": 7},
            {"checksum": 1, "key": 2, "sequence": 3},
        ):
            raw = build_gre(**kwargs)
            assert bytes(GRE.decode(raw)) == raw

    def test_accessors_tolerate_flags_without_fields(self):
        # A hand-built instance whose flags claim every optional field
        # but whose raw `fields` are empty: the value accessors return
        # None rather than raising past the buffer. (decode() never
        # produces this — it validates the length up front.)
        gre = GRE(flags=0x8000 | 0x2000 | 0x1000, protocol_type=0x0800)
        assert gre.checksum_present == 1
        assert gre.key_present == 1
        assert gre.sequence_present == 1
        assert gre.checksum is None
        assert gre.key is None
        assert gre.sequence_number is None
