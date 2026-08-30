"""IGMP decoding.

Unit tests run against crafted frames whose checksums are computed by
the library itself. The corpus test activates once a real IGMP capture
is folded in (``scripts/capture_fixtures_igmp.sh``); until then it
skips, so the suite stays green while the owner captures.
"""

import struct

import pytest

from conftest import FIXTURES, read_pcap
from netprotocols import (
    IGMP,
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
        frames = read_pcap(FIXTURES / "igmp.pcap")
        assert frames
        for frame in frames:
            layers, _ = walk(frame)
            igmp = layers[-1]
            assert isinstance(igmp, IGMP)
            ipv4 = layers[1]
            assert isinstance(ipv4, IPv4)
            assert verify(igmp)
            assert igmp.type in IGMP.type_names
