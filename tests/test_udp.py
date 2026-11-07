import copy
from dataclasses import replace

import pytest

from netprotocols import UDP, TruncatedHeaderError


class TestUDP:
    def test_decode(self, raw_udp_header):
        udp = UDP.decode(raw_udp_header)
        assert udp.src_port == 2398
        assert udp.dst_port == 53
        assert udp.length == 41
        assert udp.checksum == 0x3649
        assert udp.checksum_hex_str == "0x3649"
        assert udp.header_len == 8

    def test_round_trip(self, raw_udp_header):
        udp = UDP.decode(raw_udp_header)
        assert bytes(udp) == raw_udp_header
        assert UDP.decode(bytes(udp)) == udp

    def test_decode_tolerates_trailing_payload(self, raw_udp_header):
        udp = UDP.decode(raw_udp_header + b"dns query payload")
        assert bytes(udp) == raw_udp_header

    def test_well_known_port_chains_to_app_protocol(self, raw_udp_header):
        # raw_udp_header is a DNS datagram (destination port 53).
        from netprotocols import DNS

        assert UDP.decode(raw_udp_header).next_protocol() is DNS

    def test_ordinary_ports_end_the_chain(self):
        udp = UDP(src_port=40000, dst_port=40001, length=8, checksum=0)
        assert udp.next_protocol() is None


class TestLead:
    """The first two bytes of the payload, kept as decode context."""

    HEADER = bytes.fromhex("07c107c1")

    def udp(self, length: int, payload: bytes) -> UDP:
        raw = self.HEADER + length.to_bytes(2) + b"\x00\x00" + payload
        return UDP.decode(raw)

    @pytest.mark.parametrize(
        "length,payload,lead",
        [
            pytest.param(24, b"\xd6\x02" + bytes(14), 0xD602, id="two"),
            pytest.param(24, b"\xd6\x02", 0xD602, id="buffer-of-two"),
            pytest.param(24, b"\xd6", 0xD600, id="buffer-of-one"),
            pytest.param(24, b"", None, id="no-payload-bytes"),
            pytest.param(10, b"\xd6\x02\xff", 0xD602, id="length-10"),
            pytest.param(9, b"\xd6\x02\xff", 0xD600, id="length-9"),
            pytest.param(8, b"\xd6\x02\xff", None, id="length-8"),
            pytest.param(0, b"\xd6\x02", 0xD602, id="length-0"),
            pytest.param(0, b"\xd6", 0xD600, id="length-0-one-byte"),
            pytest.param(5, b"\xd6\x02", 0xD602, id="length-5"),
            pytest.param(5, b"\xd6", 0xD600, id="length-5-one-byte"),
        ],
    )
    def test_the_lead(self, length, payload, lead):
        udp = self.udp(length, payload)
        assert udp._lead == lead
        raw = self.HEADER + length.to_bytes(2) + b"\x00\x00" + payload
        assert UDP.decode(memoryview(raw))._lead == lead

    def test_the_lead_is_not_compared_or_kept_by_replace(self):
        decoded = self.udp(24, b"\x00\x03")
        built = replace(decoded)
        assert (decoded._lead, built._lead) == (0x0003, None)
        assert built == decoded
        assert hash(built) == hash(decoded)
        assert copy.copy(decoded)._lead == copy.deepcopy(decoded)._lead == 3
        assert "_lead" not in repr(decoded)

    def test_a_short_header_is_truncated(self):
        for cut in range(8):
            with pytest.raises(TruncatedHeaderError):
                UDP.decode(self.HEADER[:cut] if cut < 4 else bytes(cut))
