import pytest

from netprotocols import TCP, InvalidFieldError, TCPOption


def tcp_with_options(options: bytes) -> TCP:
    """A minimal segment carrying ``options`` (padded to whole words)."""
    if len(options) % 4:
        options += b"\x00" * (4 - len(options) % 4)
    return TCP(
        src_port=1022,
        dst_port=22,
        seq=1,
        ack=1,
        data_offset=5 + len(options) // 4,
        reserved=0,
        flags=0x012,
        window=64,
        checksum=0,
        urgent_pointer=0,
        options=options,
    )


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

    def test_data_offset_out_of_range_rejected(self):
        with pytest.raises(InvalidFieldError):
            TCP(
                src_port=1022,
                dst_port=22,
                seq=1,
                ack=1,
                data_offset=16,
                reserved=0,
                flags=0x010,
                window=64,
                checksum=0,
                urgent_pointer=0,
                options=b"\x00" * 44,
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


class TestTCPOptions:
    def test_timestamps_from_captured_segment(
        self, raw_tcp_header_with_options
    ):
        """The conftest header carries the classic NOP, NOP, Timestamps
        layout of an established connection."""
        options = TCP.decode(raw_tcp_header_with_options).parsed_options
        assert [option.kind for option in options] == [1, 1, 8]
        assert [option.kind_name for option in options] == [
            "No-Operation",
            "No-Operation",
            "Timestamps",
        ]
        assert options[2].data == b"\x00\x08\xca\x61\x00\x01\x69\x2e"
        assert options[2].value == (0x0008CA61, 0x0001692E)

    def test_syn_style_options(self):
        """The typical SYN block: MSS, NOP, Window Scale, SACK-Permitted
        (padded to a whole word with End of Option List)."""
        tcp = tcp_with_options(b"\x02\x04\x05\xb4\x01\x03\x03\x07\x04\x02")
        options = tcp.parsed_options
        assert [option.kind for option in options] == [2, 1, 3, 4, 0]
        mss, _, window_scale, sack_permitted, eol = options
        assert mss.value == 1460
        assert mss.kind_name == "Maximum Segment Size"
        assert window_scale.value == 7
        assert sack_permitted.value is None  # presence is its meaning
        assert sack_permitted.data == b""
        assert eol.kind_name == "End of Option List"

    def test_sack_blocks(self):
        blocks = (
            b"\x00\x00\x10\x00\x00\x00\x14\x00\x00\x00\x20\x00\x00\x00\x24\x00"
        )
        tcp = tcp_with_options(b"\x01\x01\x05\x12" + blocks)
        sack = tcp.parsed_options[2]
        assert sack.kind == 5
        assert sack.value == ((0x1000, 0x1400), (0x2000, 0x2400))

    def test_eol_ends_the_parse(self):
        """Padding after an End of Option List is not returned as more
        options."""
        tcp = tcp_with_options(b"\x02\x04\x05\xb4\x00\x00\x00\x00")
        options = tcp.parsed_options
        assert [option.kind for option in options] == [2, 0]

    def test_unknown_kind_keeps_raw_data(self):
        tcp = tcp_with_options(b"\xfe\x04\xca\xfe")
        (option,) = tcp.parsed_options
        assert option.kind == 254
        assert option.kind_name == "unknown (254)"
        assert option.data == b"\xca\xfe"
        assert option.value is None

    def test_no_options_parses_empty(self):
        tcp = tcp_with_options(b"")
        assert tcp.data_offset == 5
        assert tcp.parsed_options == ()

    def test_missing_length_byte_raises(self):
        tcp = tcp_with_options(b"\x01\x01\x01\x08")
        with pytest.raises(InvalidFieldError):
            _ = tcp.parsed_options

    def test_length_below_tlv_minimum_raises(self):
        tcp = tcp_with_options(b"\x08\x01\x01\x01")
        with pytest.raises(InvalidFieldError):
            _ = tcp.parsed_options

    def test_length_past_the_options_raises(self):
        tcp = tcp_with_options(b"\x08\x0a\x00\x00")
        with pytest.raises(InvalidFieldError):
            _ = tcp.parsed_options

    def test_value_degrades_on_a_length_wrong_for_the_kind(self):
        """A known kind whose data does not have the expected shape
        yields no decoded value — the raw data stays readable."""
        assert TCPOption(kind=2, data=b"\x05").value is None
        assert TCPOption(kind=3, data=b"\x01\x02").value is None
        assert TCPOption(kind=8, data=b"\x00" * 6).value is None
        assert TCPOption(kind=5, data=b"\x00" * 12).value is None
        assert TCPOption(kind=5).value is None

    def test_round_trip_unchanged_by_parsing(self, raw_tcp_header_with_options):
        tcp = TCP.decode(raw_tcp_header_with_options)
        _ = tcp.parsed_options
        assert bytes(tcp) == raw_tcp_header_with_options
