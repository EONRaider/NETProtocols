"""DNS decoding, driven by the real corpus frames in udp_dns.pcap plus
crafted cases for the decode contract and compression safety."""

import socket
import struct

import pytest

from conftest import FIXTURES, read_pcap
from netprotocols import (
    DNS,
    TCP,
    UDP,
    DNSOverTCP,
    DNSResourceRecord,
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


def encode_name(name: str) -> bytes:
    if name in (".", ""):
        return b"\x00"
    return (
        b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
        + b"\x00"
    )


def rr(
    name: str, rtype: int, rdata: bytes, *, rclass: int = 1, ttl: int = 300
) -> bytes:
    return (
        encode_name(name)
        + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata))
        + rdata
    )


def build_response(
    question: str,
    qtype: int = 1,
    *,
    answers: tuple[bytes, ...] = (),
    authorities: tuple[bytes, ...] = (),
    additionals: tuple[bytes, ...] = (),
) -> bytes:
    header = struct.pack(
        "!HHHHHH",
        0x1234,
        0x8180,
        1,
        len(answers),
        len(authorities),
        len(additionals),
    )
    body = encode_name(question) + struct.pack("!HH", qtype, 1)
    body += b"".join(answers) + b"".join(authorities) + b"".join(additionals)
    return header + body


def tcp_segment(*, src_port: int, dst_port: int, payload: bytes) -> bytes:
    tcp = TCP(
        src_port=src_port,
        dst_port=dst_port,
        seq=1,
        ack=1,
        data_offset=5,
        reserved=0,
        flags=0x018,  # PSH + ACK
        window=0,
        checksum=0,
        urgent_pointer=0,
    )
    return bytes(tcp) + payload


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

    def test_answers_parse_to_real_records(self):
        records = [
            record
            for frame in CORPUS_DNS
            for record in walk(frame)[0][-1].answers
        ]
        assert records
        assert {"A", "AAAA", "CNAME"} <= {r.rtype_name for r in records}
        # An A record's RDATA decodes to the dotted IPv4 in rdata_text.
        a = next(r for r in records if r.rtype_name == "A")
        assert a.rdata == socket.inet_aton(a.rdata_text)
        # A CNAME's RDATA decompresses to a real target domain.
        cname = next(r for r in records if r.rtype_name == "CNAME")
        assert cname.rdata_text.endswith("google.com")

    def test_authority_soa_and_additional_opt(self):
        stacks = [walk(frame)[0][-1] for frame in CORPUS_DNS]
        soas = [
            r for d in stacks for r in d.authorities if r.rtype_name == "SOA"
        ]
        assert soas  # accounts.youtube.com authority is an SOA
        assert soas[0].rdata_text.count(" ") == 6  # mname rname + 5 fields
        opts = [
            r for d in stacks for r in d.additionals if r.rtype_name == "OPT"
        ]
        assert opts  # every response carried an EDNS OPT pseudo-record


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


class TestDNSResourceRecords:
    @staticmethod
    def _ipv6(addr: str) -> bytes:
        return socket.inet_pton(socket.AF_INET6, addr)

    def test_a_record(self):
        raw = build_response(
            "host.example.com",
            1,
            answers=(rr("host.example.com", 1, socket.inet_aton("192.0.2.1")),),
        )
        (record,) = DNS.decode(raw).answers
        assert isinstance(record, DNSResourceRecord)
        assert record.name == "host.example.com"
        assert record.rtype == 1
        assert record.rtype_name == "A"
        assert record.rclass == 1
        assert record.ttl == 300
        assert record.rdata_text == "192.0.2.1"

    def test_aaaa_record(self):
        raw = build_response(
            "host.example.com",
            28,
            answers=(rr("host.example.com", 28, self._ipv6("2001:db8::1")),),
        )
        (record,) = DNS.decode(raw).answers
        assert record.rtype_name == "AAAA"
        assert record.rdata_text == "2001:db8::1"

    def test_cname_target_name(self):
        raw = build_response(
            "alias.example.com",
            5,
            answers=(
                rr("alias.example.com", 5, encode_name("target.example.com")),
            ),
        )
        (record,) = DNS.decode(raw).answers
        assert record.rtype_name == "CNAME"
        assert record.rdata_text == "target.example.com"

    def test_mx_record(self):
        rdata = struct.pack("!H", 10) + encode_name("mail.example.com")
        raw = build_response(
            "example.com", 15, answers=(rr("example.com", 15, rdata),)
        )
        (record,) = DNS.decode(raw).answers
        assert record.rtype_name == "MX"
        assert record.rdata_text == "10 mail.example.com"

    def test_txt_record(self):
        rdata = bytes([5]) + b"hello" + bytes([6]) + b"world!"
        raw = build_response(
            "example.com", 16, answers=(rr("example.com", 16, rdata),)
        )
        (record,) = DNS.decode(raw).answers
        assert record.rtype_name == "TXT"
        assert record.rdata_text == "helloworld!"

    def test_soa_record(self):
        rdata = (
            encode_name("ns.example.com")
            + encode_name("admin.example.com")
            + struct.pack("!IIIII", 1, 2, 3, 4, 5)
        )
        raw = build_response(
            "example.com", 6, authorities=(rr("example.com", 6, rdata),)
        )
        (record,) = DNS.decode(raw).authorities
        assert record.rtype_name == "SOA"
        assert record.rdata_text == "ns.example.com admin.example.com 1 2 3 4 5"

    def test_unknown_type_keeps_hex_rdata(self):
        raw = build_response(
            "example.com",
            1,
            answers=(rr("example.com", 99, b"\xde\xad\xbe\xef"),),
        )
        (record,) = DNS.decode(raw).answers
        assert record.rtype_name == "99"
        assert record.rdata == b"\xde\xad\xbe\xef"
        assert record.rdata_text == "deadbeef"

    def test_sections_split_by_count(self):
        raw = build_response(
            "example.com",
            1,
            answers=(rr("example.com", 1, socket.inet_aton("192.0.2.1")),),
            authorities=(rr("example.com", 2, encode_name("ns.example.com")),),
            additionals=(
                rr("ns.example.com", 1, socket.inet_aton("192.0.2.53")),
            ),
        )
        dns = DNS.decode(raw)
        assert [r.rtype_name for r in dns.answers] == ["A"]
        assert [r.rtype_name for r in dns.authorities] == ["NS"]
        assert [r.rtype_name for r in dns.additionals] == ["A"]

    def test_no_records_is_empty(self):
        dns = DNS.decode(build_query(["example", "com"]))
        assert dns.answers == ()
        assert dns.authorities == ()
        assert dns.additionals == ()

    def test_round_trip_preserved(self):
        raw = build_response(
            "example.com",
            1,
            answers=(rr("example.com", 1, socket.inet_aton("192.0.2.1")),),
        )
        assert bytes(DNS.decode(raw)) == raw

    def test_rdata_running_past_message_raises(self):
        raw = build_response(
            "example.com",
            1,
            answers=(rr("example.com", 1, socket.inet_aton("192.0.2.1")),),
        )
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(raw[:-2]).answers  # RDATA now overruns the buffer

    def test_lying_answer_count_raises(self):
        header = struct.pack("!HHHHHH", 1, 0x8180, 1, 2, 0, 0)  # ancount=2
        body = encode_name("example.com") + struct.pack("!HH", 1, 1)
        body += rr("example.com", 1, socket.inet_aton("192.0.2.1"))  # only 1
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(header + body).answers

    def test_record_header_truncated_raises(self):
        # An answer name present, but no room for the 10 fixed bytes.
        header = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        body = encode_name("example.com") + struct.pack("!HH", 1, 1)
        body += encode_name("x")  # a name, then the message ends
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(header + body).answers

    def test_question_section_truncated_raises(self):
        # qdcount=1 but the question has no room for QTYPE/QCLASS.
        raw = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + encode_name("a")
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(raw).answers

    def test_txt_character_string_overrun_raises(self):
        rdata = bytes([10]) + b"abc"  # declares 10 bytes, only 3 follow
        raw = build_response(
            "example.com", 16, answers=(rr("example.com", 16, rdata),)
        )
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(raw).answers

    def test_soa_truncated_raises(self):
        rdata = encode_name("ns") + encode_name("r") + b"\x00\x00"
        raw = build_response(
            "example.com", 6, authorities=(rr("example.com", 6, rdata),)
        )
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(raw).authorities


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

    def test_lone_pointer_byte_raises_reading_past_name(self):
        raw = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0"
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(raw).question_type  # via _read_name
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(raw).question_name  # via _labels

    def test_reserved_length_bits_raise_reading_past_name(self):
        raw = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\x40\x00"
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(raw).question_type  # via _read_name

    def test_label_overruns_message_in_labels(self):
        # Declares a 9-byte label but only three bytes follow.
        raw = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\x09abc"
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(raw).question_name  # via _labels

    def test_question_without_qtype_qclass_raises(self):
        raw = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + encode_name("a")
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(raw).question_type


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


class TestDNSOverTCP:
    def test_shim_decodes_length_and_chains(self):
        shim = DNSOverTCP.decode(struct.pack("!H", 56) + b"x" * 56)
        assert shim.message_length == 56
        assert shim.header_len == 2
        assert shim.next_protocol() is DNS
        assert bytes(shim) == struct.pack("!H", 56)

    def test_truncated_prefix_raises(self):
        with pytest.raises(TruncatedHeaderError):
            DNSOverTCP.decode(b"\x00")

    def test_tcp_port_53_dispatches_to_shim(self):
        to_server = TCP.decode(
            tcp_segment(src_port=40000, dst_port=53, payload=b"")
        )
        assert to_server.next_protocol() is DNSOverTCP
        from_server = TCP.decode(
            tcp_segment(src_port=53, dst_port=40000, payload=b"")
        )
        assert from_server.next_protocol() is DNSOverTCP

    def test_non_dns_tcp_port_ends_chain(self):
        https = TCP.decode(tcp_segment(src_port=443, dst_port=443, payload=b""))
        assert https.next_protocol() is None

    def test_full_tcp_dns_walk_with_records(self):
        message = build_response(
            "example.com",
            1,
            answers=(rr("example.com", 1, socket.inet_aton("93.184.216.34")),),
        )
        payload = struct.pack("!H", len(message)) + message
        frame = tcp_segment(src_port=40000, dst_port=53, payload=payload)
        layers = []
        cursor, protocol = 0, TCP
        while protocol is not None:
            header = protocol.decode(frame[cursor:])
            layers.append(header)
            cursor += header.header_len
            protocol = header.next_protocol()
        assert [type(layer) for layer in layers] == [TCP, DNSOverTCP, DNS]
        assert layers[1].message_length == len(message)
        dns = layers[2]
        assert dns.question_name == "example.com"
        (a,) = dns.answers
        assert (a.rtype_name, a.rdata_text) == ("A", "93.184.216.34")
        assert b"".join(bytes(layer) for layer in layers) == frame


class TestSectionParsingIsShared:
    """#85: the three section accessors share one parse, and nothing
    round-trips through `bytes(self)` to get at the message."""

    def response_with_all_three_sections(self) -> bytes:
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 1, 1)
        question = build_query(["example", "test"])[12:]
        # One A record per section, each naming the question by pointer.
        record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4)
        return header + question + (record + b"\x0a\x00\x00\x01") * 3

    def test_reading_all_three_sections_parses_once(self):
        from netprotocols.layer7 import dns as dns_module

        dns_module._parse_records.cache_clear()
        message = DNS.decode(self.response_with_all_three_sections())
        assert len(message.answers) == 1
        assert len(message.authorities) == 1
        assert len(message.additionals) == 1
        info = dns_module._parse_records.cache_info()
        assert (info.misses, info.hits) == (1, 2)

    def test_accessors_agree_with_a_single_parse(self):
        from netprotocols.layer7 import dns as dns_module

        raw = self.response_with_all_three_sections()
        message = DNS.decode(raw)
        answers, authorities, additionals = (
            dns_module._parse_records.__wrapped__(
                message.sections,
                message.qdcount,
                message.ancount,
                message.nscount,
                message.arcount,
            )
        )
        assert message.answers == answers
        assert message.authorities == authorities
        assert message.additionals == additionals
        assert bytes(message) == raw  # round-trip untouched

    def test_cached_records_are_shared_not_copied(self):
        """Equal messages share one parse; the records are frozen, so
        sharing them between callers cannot leak mutation."""
        raw = self.response_with_all_three_sections()
        first, second = DNS.decode(raw), DNS.decode(raw)
        assert first.answers is second.answers
        with pytest.raises(AttributeError):
            first.answers[0].name = "mutated"  # type: ignore[misc]

    def test_pointer_into_the_header_is_rejected(self):
        """Offsets are section-relative now; a pointer below the header
        length cannot address anything real."""
        raw = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x02"
        with pytest.raises(InvalidFieldError):
            _ = DNS.decode(raw).question_name
