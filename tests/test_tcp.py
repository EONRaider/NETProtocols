import pytest

from netprotocols import TCP, InvalidFieldError


class TestTCP:
    def test_decode_with_options(self, raw_tcp_header_with_options):
        """Data offset 8 means a 32-byte header: 20 fixed + 12 options."""
        tcp = TCP.decode(raw_tcp_header_with_options)
        assert tcp.src_port == 1022
        assert tcp.dst_port == 22
        assert tcp.seq == 0xD676F671
        assert tcp.ack == 0x0C7A1457
        assert tcp.data_offset == 8
        assert tcp.header_len == 32
        assert tcp.reserved == 0
        assert tcp.flags == 0x018
        assert tcp.flags_str == "PSH ACK"
        assert tcp.flags_hex_str == "0x018"
        assert tcp.window == 0x215C
        assert tcp.checksum == 0x2008
        assert tcp.checksum_hex_str == "0x2008"
        assert tcp.urgent_pointer == 0
        assert tcp.options == (
            b"\x01\x01\x08\x0a\x00\x08\xca\x61\x00\x01\x69\x2e"
        )

    def test_round_trip(self, raw_tcp_header_with_options):
        tcp = TCP.decode(raw_tcp_header_with_options)
        assert bytes(tcp) == raw_tcp_header_with_options
        assert TCP.decode(bytes(tcp)) == tcp

    def test_decode_without_options(self, raw_tcp_header_with_options):
        """A minimal header (offset 5) ends after 20 bytes; whatever
        follows is payload, not options."""
        minimal = (
            raw_tcp_header_with_options[:12]
            + b"\x50\x18"  # data offset 5, flags PSH ACK
            + raw_tcp_header_with_options[14:20]
            + b"payload bytes"
        )
        tcp = TCP.decode(minimal)
        assert tcp.data_offset == 5
        assert tcp.header_len == 20
        assert tcp.options == b""
        assert bytes(tcp) == minimal[:20]

    def test_chain_ends_here(self, raw_tcp_header_with_options):
        assert TCP.decode(raw_tcp_header_with_options).next_protocol() is None

    def test_offset_options_mismatch_rejected(self):
        with pytest.raises(InvalidFieldError):
            TCP(
                src_port=1022,
                dst_port=22,
                seq=1,
                ack=1,
                data_offset=5,
                reserved=0,
                flags=0x010,
                window=64,
                checksum=0,
                urgent_pointer=0,
                options=b"\x01\x01\x01\x01",
            )

    def test_flag_names_cover_all_nine_bits(self):
        tcp = TCP(
            src_port=1,
            dst_port=2,
            seq=0,
            ack=0,
            data_offset=5,
            reserved=0,
            flags=0x1FF,
            window=0,
            checksum=0,
            urgent_pointer=0,
        )
        assert tcp.flags_str == "FIN SYN RST PSH ACK URG ECE CWR NS"
