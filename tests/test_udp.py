from netprotocols import UDP


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

    def test_chain_ends_here(self, raw_udp_header):
        assert UDP.decode(raw_udp_header).next_protocol() is None
