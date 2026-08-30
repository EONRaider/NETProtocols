"""DNS decoding, driven by the real corpus frames in udp_dns.pcap plus
crafted cases for the decode contract and compression safety."""

import struct

import pytest

from conftest import FIXTURES, read_pcap
from netprotocols import (
    DNS,
    UDP,
    Ethernet,
    InvalidFieldError,
    IPv4,
    IPv6,
    TruncatedHeaderError,
)
from test_corpus import walk

CORPUS_DNS = read_pcap(FIXTURES / "udp_dns.pcap")


def build_query(qname_labels: list[str], qtype: int = 1) -> bytes:
    qname = (
        b"".join(bytes([len(label)]) + label.encode() for label in qname_labels)
        + b"\x00"
    )
    return (
        struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack("!HH", qtype, 1)
    )


class TestCorpusDNS:
    def test_udp_53_frames_chain_to_dns(self):
        for frame in CORPUS_DNS:
            layers, _ = walk(frame)
            assert type(layers[-1]) is DNS
            assert isinstance(layers[2], UDP)
            assert type(layers[1]) in (IPv4, IPv6)
            assert layers[0].__class__ is Ethernet

    def test_first_frame_fields(self):
        # Real capture: response for example.com, AAAA query echoed back.
        dns = walk(CORPUS_DNS[0])[0][-1]
        assert isinstance(dns, DNS)
        assert dns.transaction_id == 0xF840
        assert dns.qr == 1
        assert dns.rcode == 0
        assert dns.qdcount == 1
        assert dns.question_name == "example.com"
        assert dns.question_type == 28  # AAAA
        assert dns.question_class == 1  # IN

    def test_every_corpus_frame_round_trips_byte_exact(self):
        for frame in CORPUS_DNS:
            dns = walk(frame)[0][-1]
            assert isinstance(dns, DNS)
            # The DNS message is the tail of the datagram it was sliced
            # from; bytes(dns) reproduces it exactly.
            assert DNS.decode(bytes(dns)) == dns

    def test_names_decompress_to_real_domains(self):
        names = {walk(frame)[0][-1].question_name for frame in CORPUS_DNS}
        assert "example.com" in names
        assert "accounts.youtube.com" in names


class TestDNSFields:
    def test_flag_bits(self):
        # QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, RCODE=0 -> 0x8580.
        dns = DNS(
            transaction_id=1,
            flags=0x8580,
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0,
        )
        assert dns.qr == 1
        assert dns.opcode == 0
        assert dns.aa == 1
        assert dns.tc == 0
        assert dns.rd == 1
        assert dns.ra == 1
        assert dns.rcode == 0
        assert dns.flags_hex_str == "0x8580"

    def test_no_question_returns_none(self):
        dns = DNS.decode(struct.pack("!HHHHHH", 1, 0x8180, 0, 0, 0, 0))
        assert dns.question_name is None
        assert dns.question_type is None
        assert dns.question_class is None

    def test_header_len_consumes_whole_message(self):
        raw = build_query(["example", "com"])
        dns = DNS.decode(raw)
        assert dns.header_len == len(raw)
        assert bytes(dns) == raw


class TestDNSContract:
    def test_truncated_header_raises(self):
        with pytest.raises(TruncatedHeaderError):
            DNS.decode(b"\x00\x01\x02")

    def test_trailing_bytes_are_the_sections(self):
        raw = build_query(["a", "b"]) + b"trailing-answer-bytes"
        dns = DNS.decode(raw)
        assert bytes(dns) == raw  # everything after 12 bytes is sections

    def test_compression_pointer_is_followed(self):
        # A name whose second label is a pointer back to an earlier one.
        header = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        # question: "example.com" at offset 12
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        # answer name: pointer to offset 12 (0xC00C)
        answer = b"\xc0\x0c"
        dns = DNS.decode(header + question + answer)
        assert dns.question_name == "example.com"

    def test_looping_pointer_raises_not_hangs(self):
        # Pointer at offset 12 that references itself.
        loop = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c"
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(loop).question_name

    def test_reserved_label_bits_rejected(self):
        # Label length byte with 0x40 set (reserved), not a pointer.
        bad = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\x40\x00"
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(bad).question_name

    def test_name_running_past_message_raises(self):
        # Declares a 9-byte label but the buffer ends first.
        bad = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\x09abc"
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(bad).question_type


class TestDNSDispatch:
    def test_udp_dst_53_dispatches(self):
        assert (
            UDP(
                src_port=40000, dst_port=53, length=8, checksum=0
            ).next_protocol()
            is DNS
        )

    def test_udp_src_53_dispatches(self):
        assert (
            UDP(
                src_port=53, dst_port=40000, length=8, checksum=0
            ).next_protocol()
            is DNS
        )

    def test_non_dns_ports_do_not_dispatch(self):
        assert (
            UDP(
                src_port=443, dst_port=443, length=8, checksum=0
            ).next_protocol()
            is None
        )

    def test_dns_ends_the_chain(self):
        assert DNS.decode(build_query(["x"])).next_protocol() is None
