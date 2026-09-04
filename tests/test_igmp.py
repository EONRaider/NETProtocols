"""IGMP decoding.

Unit tests run against crafted frames whose checksums are computed by
the library itself. The corpus test activates once a real IGMP capture
is folded in (``scripts/capture_fixtures_igmp.sh``); until then it
skips, so the suite stays green while the owner captures.
"""

import struct

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    IGMP,
    IGMPv3GroupRecord,
    InvalidFieldError,
    IPv4,
    TruncatedHeaderError,
    compute,
    verify,
)
from test_corpus import walk


def build_igmp(type_: int, group: str, max_resp_code: int = 0) -> bytes:
    body = struct.pack("!4B", *(int(o) for o in group.split(".")))
    header = struct.pack("!BBH", type_, max_resp_code, 0)
    checksum = compute(IGMP.decode(header + body))
    return struct.pack("!BBH", type_, max_resp_code, checksum) + body


def ipv4_bytes(addr: str) -> bytes:
    return bytes(int(octet) for octet in addr.split("."))


def build_v3_report(
    records: list[tuple[int, str, list[str], bytes]],
) -> bytes:
    """Assemble an IGMPv3 Membership Report (type 0x22) from
    ``(record_type, multicast, sources, aux_data)`` tuples."""
    body = struct.pack("!HH", 0, len(records))  # reserved + record count
    for record_type, group, sources, aux in records:
        assert len(aux) % 4 == 0, "aux data is measured in 32-bit words"
        body += struct.pack("!BBH", record_type, len(aux) // 4, len(sources))
        body += ipv4_bytes(group)
        body += b"".join(ipv4_bytes(src) for src in sources)
        body += aux
    header = struct.pack("!BBH", 0x22, 0, 0)
    checksum = compute(IGMP.decode(header + body))
    return struct.pack("!BBH", 0x22, 0, checksum) + body


def build_v3_query(
    *,
    group: str = "0.0.0.0",
    s: int = 0,
    qrv: int = 2,
    qqic: int = 125,
    sources: list[str] | None = None,
    max_resp_code: int = 100,
) -> bytes:
    """Assemble an IGMPv3 Membership Query (type 0x11, RFC 3376 §4.1)."""
    sources = sources or []
    body = ipv4_bytes(group)
    body += bytes([((s & 1) << 3) | (qrv & 0x07), qqic])
    body += struct.pack("!H", len(sources))
    body += b"".join(ipv4_bytes(src) for src in sources)
    header = struct.pack("!BBH", 0x11, max_resp_code, 0)
    checksum = compute(IGMP.decode(header + body))
    return struct.pack("!BBH", 0x11, max_resp_code, checksum) + body


class TestIGMPFields:
    def test_v2_membership_report(self):
        raw = build_igmp(0x16, "239.255.42.99")
        igmp = IGMP.decode(raw)
        assert igmp.type == 0x16
        assert igmp.type_name == "IGMPv2 Membership Report"
        assert igmp.group_address == "239.255.42.99"
        assert igmp.max_resp_code == 0
        assert verify(igmp)
        assert igmp.checksum_hex_str == f"{igmp.checksum:#06x}"
        assert igmp.header_len == 8

    def test_membership_query_carries_group(self):
        igmp = IGMP.decode(build_igmp(0x11, "224.0.0.1", max_resp_code=100))
        assert igmp.type_name == "Membership Query"
        assert igmp.group_address == "224.0.0.1"
        assert igmp.max_resp_code == 100

    def test_v3_report_has_no_group_address(self):
        # Type 0x22: bytes 4-7 are reserved + record count, not a group.
        body = struct.pack("!HH", 0, 1) + b"\x01\x00\x00\x00\xe0\x00\x00\xfb"
        header = struct.pack("!BBH", 0x22, 0, 0)
        checksum = compute(IGMP.decode(header + body))
        igmp = IGMP.decode(struct.pack("!BBH", 0x22, 0, checksum) + body)
        assert igmp.type_name == "IGMPv3 Membership Report"
        assert igmp.group_address is None

    def test_unknown_type_degrades(self):
        igmp = IGMP.decode(build_igmp(0x99, "224.0.0.1"))
        assert igmp.type_name == "unknown (0x99)"

    def test_round_trip(self):
        raw = build_igmp(0x17, "239.1.2.3")
        assert bytes(IGMP.decode(raw)) == raw
        assert IGMP.decode(bytes(IGMP.decode(raw))) == IGMP.decode(raw)


class TestIGMPv3GroupRecords:
    def test_single_exclude_record_no_sources(self):
        raw = build_v3_report([(2, "239.255.42.99", [], b"")])
        igmp = IGMP.decode(raw)
        assert igmp.type_name == "IGMPv3 Membership Report"
        assert igmp.group_address is None
        assert igmp.num_group_records == 1
        (record,) = igmp.group_records
        assert isinstance(record, IGMPv3GroupRecord)
        assert record.record_type == 2
        assert record.record_type_name == "MODE_IS_EXCLUDE"
        assert record.multicast_address == "239.255.42.99"
        assert record.source_addresses == ()
        assert record.aux_data == b""
        assert verify(igmp)

    def test_multiple_records_with_sources(self):
        raw = build_v3_report(
            [
                (1, "232.1.1.1", ["10.0.0.1", "10.0.0.2"], b""),
                (4, "239.0.0.5", ["192.0.2.7"], b""),
            ]
        )
        igmp = IGMP.decode(raw)
        assert igmp.num_group_records == 2
        records = igmp.group_records
        assert records is not None
        assert len(records) == 2
        assert records[0].record_type_name == "MODE_IS_INCLUDE"
        assert records[0].multicast_address == "232.1.1.1"
        assert records[0].source_addresses == ("10.0.0.1", "10.0.0.2")
        assert records[1].record_type_name == "CHANGE_TO_EXCLUDE_MODE"
        assert records[1].multicast_address == "239.0.0.5"
        assert records[1].source_addresses == ("192.0.2.7",)
        assert verify(igmp)

    def test_auxiliary_data_is_kept_raw(self):
        aux = b"\xde\xad\xbe\xef"  # one 32-bit word
        raw = build_v3_report([(1, "232.0.0.9", ["203.0.113.1"], aux)])
        (record,) = IGMP.decode(raw).group_records
        assert record.aux_data == aux
        assert record.source_addresses == ("203.0.113.1",)

    def test_zero_records(self):
        igmp = IGMP.decode(build_v3_report([]))
        assert igmp.num_group_records == 0
        assert igmp.group_records == ()

    def test_unknown_record_type_degrades(self):
        (record,) = IGMP.decode(
            build_v3_report([(99, "224.0.0.1", [], b"")])
        ).group_records
        assert record.record_type == 99
        assert record.record_type_name == "unknown (0x63)"

    def test_round_trip_is_byte_exact(self):
        raw = build_v3_report(
            [
                (3, "232.1.1.1", ["10.0.0.1"], b"\x00\x00\x00\x01"),
                (6, "239.9.9.9", [], b""),
            ]
        )
        assert bytes(IGMP.decode(raw)) == raw

    def test_non_v3_types_have_no_records(self):
        igmp = IGMP.decode(build_igmp(0x16, "239.1.2.3"))
        assert igmp.group_records is None
        assert igmp.num_group_records is None

    def test_truncated_source_list_raises(self):
        # One record claims a source, but two bytes are chopped off.
        raw = build_v3_report([(1, "232.1.1.1", ["10.0.0.1"], b"")])
        with pytest.raises(InvalidFieldError):
            _ = IGMP.decode(raw[:-2]).group_records

    def test_lying_source_count_raises(self):
        # Record claims 5 sources but carries none.
        body = struct.pack("!HH", 0, 1) + struct.pack("!BBH", 1, 0, 5)
        body += ipv4_bytes("232.1.1.1")
        igmp = IGMP.decode(struct.pack("!BBH", 0x22, 0, 0) + body)
        with pytest.raises(InvalidFieldError):
            _ = igmp.group_records

    def test_lying_record_count_raises(self):
        # Header says 3 records; body carries one.
        body = struct.pack("!HH", 0, 3) + struct.pack("!BBH", 2, 0, 0)
        body += ipv4_bytes("239.1.1.1")
        igmp = IGMP.decode(struct.pack("!BBH", 0x22, 0, 0) + body)
        with pytest.raises(InvalidFieldError):
            _ = igmp.group_records

    def test_count_field_truncated_raises(self):
        # Type 0x22 but body too short to hold the reserved + count word.
        igmp = IGMP.decode(struct.pack("!BBH", 0x22, 0, 0) + b"\x00")
        with pytest.raises(InvalidFieldError):
            _ = igmp.num_group_records
        with pytest.raises(InvalidFieldError):
            _ = igmp.group_records

    def test_truncated_aux_data_raises(self):
        # Record claims one 32-bit word of aux data but carries none.
        body = struct.pack("!HH", 0, 1) + struct.pack("!BBH", 1, 1, 0)
        body += ipv4_bytes("232.1.1.1")
        igmp = IGMP.decode(struct.pack("!BBH", 0x22, 0, 0) + body)
        with pytest.raises(InvalidFieldError):
            _ = igmp.group_records


class TestIGMPv3Query:
    def test_general_query_fields(self):
        raw = build_v3_query(group="0.0.0.0", s=0, qrv=2, qqic=125)
        igmp = IGMP.decode(raw)
        assert igmp.type_name == "Membership Query"
        assert igmp.group_address == "0.0.0.0"
        assert igmp.s_flag == 0
        assert igmp.qrv == 2
        assert igmp.qqic == 125
        assert igmp.num_query_sources == 0
        assert igmp.query_source_addresses == ()
        assert verify(igmp)

    def test_group_and_source_specific_query(self):
        raw = build_v3_query(
            group="239.1.1.1",
            s=1,
            qrv=3,
            qqic=10,
            sources=["10.0.0.1", "10.0.0.2"],
        )
        igmp = IGMP.decode(raw)
        assert igmp.group_address == "239.1.1.1"
        assert igmp.s_flag == 1
        assert igmp.qrv == 3
        assert igmp.qqic == 10
        assert igmp.num_query_sources == 2
        assert igmp.query_source_addresses == ("10.0.0.1", "10.0.0.2")
        assert verify(igmp)

    def test_v2_query_has_no_v3_fields(self):
        # An 8-byte v2 query: its body is only the 4-byte group address.
        igmp = IGMP.decode(build_igmp(0x11, "224.0.0.1", max_resp_code=100))
        assert igmp.group_address == "224.0.0.1"
        assert igmp.s_flag is None
        assert igmp.qrv is None
        assert igmp.qqic is None
        assert igmp.num_query_sources is None
        assert igmp.query_source_addresses is None

    def test_non_query_types_have_no_query_fields(self):
        igmp = IGMP.decode(build_igmp(0x16, "239.1.2.3"))  # v2 report
        assert igmp.s_flag is None
        assert igmp.query_source_addresses is None

    def test_round_trip_is_byte_exact(self):
        raw = build_v3_query(
            group="239.9.9.9", s=1, qrv=7, qqic=200, sources=["192.0.2.1"]
        )
        assert bytes(IGMP.decode(raw)) == raw

    def test_truncated_source_list_raises(self):
        raw = build_v3_query(sources=["10.0.0.1"])
        with pytest.raises(InvalidFieldError):
            _ = IGMP.decode(raw[:-2]).query_source_addresses

    def test_lying_source_count_raises(self):
        # Query claims 4 sources but carries none.
        body = ipv4_bytes("0.0.0.0") + bytes([0x02, 100])
        body += struct.pack("!H", 4)
        igmp = IGMP.decode(struct.pack("!BBH", 0x11, 100, 0) + body)
        with pytest.raises(InvalidFieldError):
            _ = igmp.query_source_addresses


class TestIGMPContract:
    def test_truncated_raises(self):
        with pytest.raises(TruncatedHeaderError):
            IGMP.decode(b"\x16\x00")

    def test_ipv4_proto_2_dispatches_to_igmp(self):
        ip = IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=28,
            identification=1,
            flags=0,
            fragment_offset=0,
            ttl=1,
            protocol=2,
            checksum=0,
            src="192.168.1.10",
            dst="239.255.42.99",
        )
        assert ip.next_protocol() is IGMP

    def test_igmp_ends_the_chain(self):
        assert (
            IGMP.decode(build_igmp(0x16, "239.1.1.1")).next_protocol() is None
        )


@pytest.mark.skipif(
    not (FIXTURES / "igmp.pcap").exists(),
    reason="IGMP corpus fixture not captured yet "
    "(run scripts/capture_fixtures_igmp.sh)",
)
class TestCorpusIGMP:
    def test_captured_frames_decode_and_verify(self):
        frames = pcap_frames(FIXTURES / "igmp.pcap")
        assert frames
        for frame in frames:
            layers, _ = walk(frame)
            igmp = layers[-1]
            assert isinstance(igmp, IGMP)
            ipv4 = layers[1]
            assert isinstance(ipv4, IPv4)
            assert verify(igmp)
            assert igmp.type in IGMP.type_names
