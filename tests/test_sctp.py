"""SCTP (RFC 9260): the common header, the chunk walk that bounds the
packet, the chunk accessors, the typed DATA, INIT, INIT ACK, SACK and
I-DATA (RFC 8260) fields, PPID dispatch through ``sctp.ppid``, and
dispatch from IPv4/IPv6 protocol 132.

The real association in tests/fixtures/sctp.pcap (see its MANIFEST
note) anchors the decode, round-trip and typed-field asserts, each
field cross-checked against a ``struct`` decode of the captured bytes;
the edge cases a real stack never sends, and every I-DATA chunk (the
capture has none), are built here. CRC32c itself is tested in
test_checksum.py, where the mutation audit's test selection reaches it.
"""

import struct
import zlib
from dataclasses import dataclass, replace
from typing import ClassVar, Self

import pytest

from conftest import FIXTURES, allocation_peak, pcap_frames
from netprotocols import (
    SCTP,
    Ethernet,
    FlowKey,
    ICMPv4,
    InvalidFieldError,
    IPProtocol,
    IPv4,
    IPv6,
    IPv6HopByHopOptions,
    Packet,
    Protocol,
    SCTPChunk,
    SCTPParameter,
    TruncatedHeaderError,
    compute,
    decode_frame,
    verify,
)
from netprotocols.registry import (
    DEFAULT,
    TABLE_SCTP_PPID,
    WITHHELD,
    Registry,
)

FRAMES = pcap_frames(FIXTURES / "sctp.pcap")

#: Ethernet + a 20-byte IPv4 header, in front of every captured packet.
SCTP_START = 14 + 20


def packet_bytes(index: int) -> bytes:
    """The SCTP packet of capture frame ``index``, exactly."""
    return FRAMES[index][SCTP_START:]


def sctp_of(index: int) -> SCTP:
    layer = decode_frame(FRAMES[index])[SCTP]
    assert isinstance(layer, SCTP)
    return layer


def chunk(type_: int, flags: int = 0, value: bytes = b"") -> bytes:
    return bytes(SCTPChunk(type=type_, flags=flags, value=value))


def make_sctp(chunks: bytes = b"", checksum: int = 0) -> SCTP:
    return SCTP(
        src_port=5000,
        dst_port=5001,
        verification_tag=0x01020304,
        checksum=checksum,
        chunks=chunks,
    )


class TestCapturedAssociation:
    """Every frame of the usrsctp capture, in order."""

    EXPECTED_TYPES = (1, 2, 10, 11, 0, 3, 0, 3, 4, 5, 4, 5, 7, 8, 14, 63)

    def test_every_frame_walks_to_sctp_and_ends_there(self):
        for frame in FRAMES:
            packet = decode_frame(frame)
            assert [type(layer) for layer in packet] == [Ethernet, IPv4, SCTP]
            assert packet.consumed == len(frame)

    def test_the_lifecycle_in_chunk_types(self):
        types = [
            [chunk.type for chunk in sctp_of(index).parsed_chunks]
            for index in range(len(FRAMES))
        ]
        assert types == [[t] for t in self.EXPECTED_TYPES]

    def test_every_captured_checksum_verifies(self):
        for index in range(len(FRAMES)):
            assert verify(sctp_of(index))

    @pytest.mark.parametrize(
        "index,name", [(0, "INIT"), (4, "DATA"), (5, "SACK")]
    )
    def test_init_data_and_sack_round_trip(self, index, name):
        raw = packet_bytes(index)
        header = SCTP.decode(raw)
        assert header.parsed_chunks[0].type_name == name
        assert bytes(header) == raw
        assert SCTP.decode(bytes(header)) == header

    def test_init_fields(self):
        init = sctp_of(0)
        assert (init.src_port, init.dst_port) == (54770, 7)
        assert init.verification_tag == 0  # an INIT has no tag yet
        assert init.checksum == 0x058AF060
        assert init.checksum_hex_str == "0x058af060"
        (only,) = init.parsed_chunks
        assert (only.type, only.flags, only.length) == (1, 0, 100)
        assert only.type_name == "INIT"
        # The INIT's initiate tag is what every later packet to the
        # client carries as its verification tag.
        assert only.value[:4] == bytes.fromhex("ff09ba55")
        assert sctp_of(1).verification_tag_hex_str == "0xff09ba55"

    def test_init_ack_and_cookie_echo(self):
        (init_ack,) = sctp_of(1).parsed_chunks
        assert init_ack.type_name == "INIT ACK"
        (cookie_echo,) = sctp_of(2).parsed_chunks
        assert cookie_echo.type_name == "COOKIE ECHO"
        assert cookie_echo.value.startswith(b"KAME-BSD 1.1")
        (cookie_ack,) = sctp_of(3).parsed_chunks
        assert cookie_ack == SCTPChunk(type=11)
        assert cookie_ack.type_name == "COOKIE ACK"

    def test_data_chunk_is_padded_on_the_wire(self):
        data = sctp_of(4)
        (only,) = data.parsed_chunks
        assert only.type_name == "DATA"
        assert only.flags_str == "B E"  # one unfragmented message
        assert only.value.endswith(b"hello sctp\n")
        assert only.length == 27
        # One byte of padding follows the 27, kept in the raw chunks.
        assert len(data.chunks) == 28
        assert data.chunks[27:] == b"\x00"
        assert bytes(only) == data.chunks

    def test_heartbeat_shutdown_and_unknown_chunks(self):
        names = [sctp_of(i).parsed_chunks[0].type_name for i in range(8, 15)]
        assert names == [
            "HEARTBEAT",
            "HEARTBEAT ACK",
            "HEARTBEAT",
            "HEARTBEAT ACK",
            "SHUTDOWN",
            "SHUTDOWN ACK",
            "SHUTDOWN COMPLETE",
        ]
        (unknown,) = sctp_of(15).parsed_chunks
        assert unknown.type == 63
        assert unknown.type_name == "unknown (63)"
        assert unknown.unrecognized_action == 0
        assert unknown.value == b"NETProtocols unknown chunk"

    def test_ipv4_names_and_dispatches_protocol_132(self):
        ip = decode_frame(FRAMES[0])[IPv4]
        assert isinstance(ip, IPv4)
        assert ip.protocol == IPProtocol.SCTP == 132
        assert ip.protocol_name == "SCTP"
        assert ip.protocol_enum is IPProtocol.SCTP
        assert ip.next_protocol() is SCTP


class TestLinkLayerPadding:
    """In a walk the IP length ends SCTP's buffer, so an Ethernet frame
    padded to 60 bytes leaves its padding in the packet's trailer.
    Decoded on its own, SCTP sees the zero tail and must not swallow
    it."""

    @pytest.mark.parametrize("fill", [0x00, 0xA5], ids=["zeros", "nonzero"])
    def test_a_padded_frame_stops_before_the_padding(self, fill):
        frame = FRAMES[3]  # COOKIE ACK: a 50-byte frame
        padded = frame + bytes([fill]) * (60 - len(frame))
        packet = decode_frame(padded)
        assert packet.consumed == len(frame)
        assert packet.trailer == padded[len(frame) :]
        sctp = packet[SCTP]
        assert isinstance(sctp, SCTP)
        assert bytes(sctp) == packet_bytes(3)
        assert verify(sctp)  # CRC32c is not blind to trailing zeros

    def test_an_unbounded_walk_stops_before_the_padding(self):
        """An IP length of 0 bounds nothing, so the walk hands SCTP the
        padding and its zero-tail scan leaves it undecoded."""
        frame = bytearray(FRAMES[3] + bytes(60 - len(FRAMES[3])))
        if decode_frame(bytes(frame))[1].version == 4:
            frame[16:18] = bytes(2)
        else:
            frame[18:20] = bytes(2)
        packet = decode_frame(bytes(frame))
        assert packet.trailer == b""
        assert packet.consumed == len(FRAMES[3])
        assert bytes(packet[SCTP]) == packet_bytes(3)
        assert verify(packet[SCTP])

    def test_a_padded_packet_decoded_alone_stops_before_the_padding(self):
        raw = packet_bytes(3)
        sctp = SCTP.decode(raw + bytes(10))
        assert sctp.header_len == len(raw)
        assert verify(sctp)

    def test_a_zero_tail_shorter_than_a_chunk_header_is_padding_too(self):
        raw = packet_bytes(3)
        assert SCTP.decode(raw + b"\x00\x00").header_len == len(raw)

    def test_a_nonzero_trailer_is_kept_verbatim(self):
        """A trailer that is not all zeros cannot be told from a broken
        chunk, so it stays in the chunks for parsed_chunks to report."""
        raw = packet_bytes(3) + b"\x00\x00\x00\x00\xde\xad"
        header = SCTP.decode(raw)
        assert bytes(header) == raw
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = header.parsed_chunks
        assert excinfo.value.offset == 4  # relative to chunks
        assert not verify(header)

    def test_zeros_after_a_broken_chunk_are_not_trimmed(self):
        """The zero tail is padding only where a chunk would start."""
        raw = bytes(make_sctp()) + b"\x01\x00\x00\x40" + bytes(8)
        assert SCTP.decode(raw).header_len == len(raw)

    def test_an_unpadded_final_chunk_takes_ethernet_zeros_as_padding(self):
        """A sender bug the zero-tail scan cannot see past, decoding
        on its own: the final chunk's missing padding (RFC 9260 §3.2) is
        filled from the link layer's zeros, so the decoded packet is
        three bytes longer than the one sent, and its CRC does not
        match."""
        unpadded = SCTP.decode(bytes(make_sctp(chunk(0, 3, b"x")))[:17])
        assert unpadded.header_len == 17  # a 5-byte DATA chunk, unpadded
        sent = bytes(replace(unpadded, checksum=compute(unpadded)))
        assert verify(SCTP.decode(sent))
        # Ethernet pads the 14 + 20 + 17 = 51-byte frame to 60.
        padded = SCTP.decode(sent + bytes(9))
        assert padded.header_len == 20
        assert not verify(padded)

    def test_a_packet_with_no_chunks_decodes_empty(self):
        header = SCTP.decode(bytes(make_sctp()) + bytes(8))
        assert header.chunks == b""
        assert header.parsed_chunks == ()
        assert header.header_len == 12

    #: A trailer far larger than the peak memory the scans may allocate.
    LONG_TAIL = bytes(1 << 22)

    def test_a_long_zero_tail_is_scanned_without_a_copy(self):
        """Decode a ``bytes`` packet with a 4 MiB zero trailer: the
        scan reads it through a view, so peak memory stays far below
        it, and the trailer is still left undecoded as padding."""
        raw = packet_bytes(3)
        data = raw + self.LONG_TAIL
        with allocation_peak() as traced:
            decoded = SCTP.decode(data)
        assert decoded.header_len == len(raw)
        assert traced.peak < 1 << 16, traced.peak

    def test_a_nonzero_byte_after_a_long_tail_is_found_without_a_copy(self):
        """Scan 4 MiB of zeros to a final nonzero byte, then raise for
        it: the walk over ``bytes`` chunks never copies the trailer."""
        header = make_sctp(chunk(0, 3, b"x") + self.LONG_TAIL + b"\x01")

        with (
            allocation_peak() as traced,
            pytest.raises(InvalidFieldError) as excinfo,
        ):
            _ = header.parsed_chunks
        assert excinfo.value.offset == 8  # the padded 5-byte DATA chunk
        assert traced.peak < 1 << 16, traced.peak


class TestTruncationAndLyingLengths:
    def test_fixed_header_truncated(self):
        with pytest.raises(TruncatedHeaderError) as excinfo:
            SCTP.decode(packet_bytes(0)[:11])
        assert excinfo.value.protocol is SCTP

    def test_a_chunk_cut_short_of_its_length(self):
        """Past the common header decode never raises: the cut chunk is
        kept, and the accessor reports it."""
        raw = packet_bytes(0)[:60]  # INIT, length 100
        header = SCTP.decode(raw)
        assert (header.src_port, header.dst_port) == (54770, 7)
        assert header.checksum == 0x058AF060
        assert bytes(header) == raw
        assert not verify(header)
        with pytest.raises(TruncatedHeaderError) as excinfo:
            _ = header.parsed_chunks
        err = excinfo.value
        assert err.protocol is SCTP
        assert err.field == "chunks"
        assert err.offset == 0  # relative to chunks
        assert (err.expected, err.actual) == (100, 48)
        assert str(err) == "SCTP chunk declares 100 bytes, 48 remain"

    def test_a_cut_chunk_header(self):
        raw = bytes(make_sctp(chunk(11))) + b"\x01\x00"
        header = SCTP.decode(raw)
        assert bytes(header) == raw
        with pytest.raises(TruncatedHeaderError) as excinfo:
            _ = header.parsed_chunks
        err = excinfo.value
        assert err.field == "chunks"
        assert err.offset == 4
        assert (err.expected, err.actual) == (4, 2)
        assert str(err) == "SCTP chunk header needs 4 bytes, 2 remain"

    @pytest.mark.parametrize("length", [0, 1, 2, 3])
    def test_a_chunk_length_below_four(self, length):
        """Below 4 the chunk would not advance the walk: reported, never
        looped on."""
        raw = bytes(make_sctp()) + bytes([6, 0, 0, length]) + b"\x00" * 8
        header = SCTP.decode(raw)
        assert bytes(header) == raw
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = header.parsed_chunks
        err = excinfo.value
        assert err.protocol is SCTP
        assert err.field == "chunks"
        assert err.offset == 0
        assert (err.expected, err.actual) == (">=4", length)
        assert str(err) == (
            f"SCTP chunk length must be at least 4, got {length}"
        )

    def test_a_final_chunk_missing_its_padding_still_round_trips(self):
        """RFC 9260 §3.2 requires the padding, but a receiver loses
        nothing by tolerating its absence at the very end."""
        raw = bytes(make_sctp()) + bytes(SCTPChunk(0, 3, b"abcde"))[:-3]
        header = SCTP.decode(raw)
        assert bytes(header) == raw
        assert header.parsed_chunks == (SCTPChunk(0, 3, b"abcde"),)

    def test_nonzero_padding_is_kept_verbatim(self):
        """The receiver ignores padding (RFC 9260 §3.2); the codec keeps
        it, so the packet still round-trips and its CRC still covers
        the bytes that were sent."""
        raw = bytes(make_sctp()) + chunk(4, value=b"x")[:5] + b"\xaa\xbb\xcc"
        raw += chunk(11)
        header = SCTP.decode(raw)
        assert bytes(header) == raw
        assert [c.type for c in header.parsed_chunks] == [4, 11]
        assert header.parsed_chunks[0].value == b"x"

    def test_many_minimal_chunks_walk_in_bounded_time(self):
        chunks = chunk(11) * 4096
        header = SCTP.decode(bytes(make_sctp(chunks)))
        assert len(header.parsed_chunks) == 4096

    def test_memoryview_input_is_not_retained(self):
        buffer = bytearray(packet_bytes(4))
        header = SCTP.decode(memoryview(buffer))
        before = header.chunks
        buffer[:] = bytes(len(buffer))
        assert header.chunks == before
        assert isinstance(header.chunks, bytes)


class TestParsedChunksOnConstructedPackets:
    """A constructed packet's chunks are not walked until asked for, so
    the accessor reports offsets relative to ``chunks``."""

    def test_several_chunks_in_order(self):
        chunks = chunk(0, 3, b"hello") + chunk(3, value=bytes(12)) + chunk(11)
        parsed = make_sctp(chunks).parsed_chunks
        assert [c.type_name for c in parsed] == ["DATA", "SACK", "COOKIE ACK"]
        assert parsed[0].value == b"hello"

    def test_a_lying_length_names_the_chunks_attribute(self):
        broken = make_sctp(chunk(11) + b"\x04\x00\x00\x40")
        with pytest.raises(TruncatedHeaderError) as excinfo:
            _ = broken.parsed_chunks
        err = excinfo.value
        assert err.field == "chunks"
        assert err.offset == 4
        assert (err.expected, err.actual) == (64, 4)

    def test_a_short_length_names_the_chunks_attribute(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = make_sctp(b"\x04\x00\x00\x02").parsed_chunks
        assert excinfo.value.offset == 0


class TestSCTPChunk:
    def test_bytes_pads_to_a_multiple_of_four(self):
        assert bytes(SCTPChunk(0, 3, b"abcde")) == (
            b"\x00\x03\x00\x09abcde\x00\x00\x00"
        )
        assert bytes(SCTPChunk(11)) == b"\x0b\x00\x00\x04"
        assert bytes(SCTPChunk(4, 0, b"abcd")) == b"\x04\x00\x00\x08abcd"

    def test_length_excludes_padding(self):
        assert SCTPChunk(0, 0, b"abcde").length == 9

    def test_the_largest_value_fits_the_length_field(self):
        biggest = SCTPChunk(0, 0, bytes(65531))
        assert biggest.length == 0xFFFF
        assert len(bytes(biggest)) == 65536

    def test_a_value_too_long_for_the_length_field(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            SCTPChunk(0, 0, bytes(65532))
        err = excinfo.value
        assert err.protocol is SCTPChunk
        assert err.field == "value"
        assert (err.expected, err.actual) == ("<=65531", 65532)
        assert str(err) == (
            "SCTP chunk value must be at most 65531 bytes, got 65532"
        )

    @pytest.mark.parametrize("name", ["type", "flags"])
    @pytest.mark.parametrize("number", [-1, 256])
    def test_type_and_flags_are_bytes(self, name, number):
        with pytest.raises(InvalidFieldError) as excinfo:
            SCTPChunk(**{"type": 0, name: number})
        err = excinfo.value
        assert err.field == name
        assert (err.expected, err.actual) == ("0-255", number)
        assert str(err) == (
            f"SCTP chunk {name} must be within 0-255, got {number}"
        )

    def test_the_byte_range_edges_are_accepted(self):
        assert bytes(SCTPChunk(255, 255))[:2] == b"\xff\xff"

    @pytest.mark.parametrize(
        "type_,name",
        [
            (0, "DATA"),
            (1, "INIT"),
            (2, "INIT ACK"),
            (3, "SACK"),
            (4, "HEARTBEAT"),
            (6, "ABORT"),
            (7, "SHUTDOWN"),
            (10, "COOKIE ECHO"),
            (11, "COOKIE ACK"),
            (14, "SHUTDOWN COMPLETE"),
            (64, "I-DATA"),
            (192, "FORWARD-TSN"),
            (200, "unknown (200)"),
        ],
    )
    def test_type_names(self, type_, name):
        assert SCTPChunk(type_).type_name == name

    @pytest.mark.parametrize(
        "type_,flags,expected",
        [
            (0, 0x03, "B E"),
            (0, 0x0F, "I U B E"),
            (0, 0x02, "B"),
            (0, 0xF0, ""),  # reserved bits are not named
            (64, 0x05, "U E"),
            (6, 0x01, "T"),
            (14, 0x01, "T"),
            (6, 0x00, ""),
            (1, 0xFF, ""),  # INIT defines no flags
        ],
    )
    def test_flags_str(self, type_, flags, expected):
        assert SCTPChunk(type_, flags).flags_str == expected

    @pytest.mark.parametrize(
        "type_,action", [(0x3F, 0), (0x7F, 1), (0xBF, 2), (0xFF, 3)]
    )
    def test_unrecognized_action_is_the_two_high_bits(self, type_, action):
        assert SCTPChunk(type_).unrecognized_action == action


class TestIPv6Dispatch:
    """The capture host had no IPv6, so IPv6 carriage is constructed."""

    def ipv6_frame(self, next_header: int, payload: bytes) -> bytes:
        ip = IPv6(
            version=6,
            traffic_class=0,
            flow_label=0,
            payload_length=len(payload),
            next_header=next_header,
            hop_limit=64,
            src="2001:db8::1",
            dst="2001:db8::2",
        )
        eth = Ethernet(
            dst="02:00:00:00:00:02",
            src="02:00:00:00:00:01",
            ethertype=0x86DD,
        )
        return bytes(eth) + bytes(ip) + payload

    def test_ipv6_next_header_132_dispatches_to_sctp(self):
        sctp = packet_bytes(0)
        packet = decode_frame(self.ipv6_frame(132, sctp))
        assert [type(layer) for layer in packet] == [Ethernet, IPv6, SCTP]
        assert bytes(packet[SCTP]) == sctp
        ipv6 = packet[IPv6]
        assert isinstance(ipv6, IPv6)
        assert ipv6.next_header_name == "SCTP"
        assert packet.flow_key() == FlowKey(
            "2001:db8::1", "2001:db8::2", 54770, 7, 132
        )

    def test_sctp_behind_an_ipv6_extension_header(self):
        hop_by_hop = IPv6HopByHopOptions(
            next_header=132, hdr_ext_len=0, options=b"\x01\x04" + bytes(4)
        )
        payload = bytes(hop_by_hop) + packet_bytes(5)
        packet = decode_frame(self.ipv6_frame(0, payload))
        assert [type(layer) for layer in packet] == [
            Ethernet,
            IPv6,
            IPv6HopByHopOptions,
            SCTP,
        ]


class TestHeaderAndChecksumBehaviour:
    def test_sctp_ends_the_chain(self):
        assert sctp_of(4).next_protocol() is None

    def test_with_checksums_restores_the_captured_crc(self):
        frame = FRAMES[1]  # INIT ACK
        packet = decode_frame(frame)
        eth, ip, sctp = packet.layers
        assert isinstance(ip, IPv4) and isinstance(sctp, SCTP)
        zeroed = Packet(eth, replace(ip, checksum=0), replace(sctp, checksum=0))
        assert bytes(zeroed.with_checksums()) == frame

    def test_a_corrupted_chunk_fails_verification(self):
        sctp = sctp_of(4)
        flipped = sctp.chunks[:-2] + b"\xff" + sctp.chunks[-1:]
        assert not verify(replace(sctp, chunks=flipped))

    def test_verification_tag_hex_str_pads(self):
        assert make_sctp().verification_tag_hex_str == "0x01020304"
        assert make_sctp(checksum=0xAB).checksum_hex_str == "0x000000ab"


def first_fragment(frame: bytes, ip_payload: int) -> bytes:
    """``frame`` as the first fragment of its IPv4 datagram: More
    Fragments set, ``ip_payload`` bytes of the SCTP packet kept."""
    ip = IPv4.decode(frame[14:])
    head = replace(ip, total_length=20 + ip_payload, flags=0b001, checksum=0)
    head = replace(head, checksum=compute(head))
    return frame[:14] + bytes(head) + frame[SCTP_START:][:ip_payload]


class TestDamagedPacketsKeepTheirHeader:
    """Past the 12-byte common header decode never raises, so SCTP keeps
    its ports, tag and checksum through the damage a capture routinely
    shows TCP and UDP surviving, in strict and lax walks alike; only
    parsed_chunks and verify() see what was lost."""

    LAX = pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])

    def assert_header_kept(self, packet: Packet, index: int, end: int):
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, SCTP]
        assert packet.stopped_by is None
        sctp = packet[SCTP]
        assert isinstance(sctp, SCTP)
        original = sctp_of(index)
        assert (sctp.src_port, sctp.dst_port) == (
            original.src_port,
            original.dst_port,
        )
        assert sctp.verification_tag == original.verification_tag
        assert sctp.checksum == original.checksum
        assert packet.consumed == end
        assert not verify(sctp)
        return sctp

    @pytest.mark.parametrize("index", range(len(FRAMES)))
    def test_an_appended_ethernet_fcs_decoded_alone(self, index):
        """Decoded on its own, a packet followed by 4 nonzero bytes, a
        captured FCS, keeps them as its last bytes, which the CRC
        rejects."""
        raw = packet_bytes(index)
        fcs = zlib.crc32(FRAMES[index]).to_bytes(4, "little")
        sctp = SCTP.decode(raw + fcs)
        assert sctp.header_len == len(raw) + 4
        assert sctp.chunks == sctp_of(index).chunks + fcs
        assert sctp.checksum == sctp_of(index).checksum
        assert not verify(sctp)

    @LAX
    @pytest.mark.parametrize("snap", [96, 128, 200])
    def test_an_init_ack_cut_by_a_snap_length(self, snap, lax):
        cut = FRAMES[1][:snap]  # INIT ACK: one 420-byte chunk
        packet = decode_frame(cut, lax=lax)
        sctp = self.assert_header_kept(packet, 1, snap)
        with pytest.raises(TruncatedHeaderError) as excinfo:
            _ = sctp.parsed_chunks
        assert (excinfo.value.expected, excinfo.value.actual) == (
            420,
            snap - SCTP_START - 12,
        )

    @LAX
    def test_a_first_ipv4_fragment_cut_inside_a_chunk(self, lax):
        frame = first_fragment(FRAMES[1], 200)
        packet = decode_frame(frame, lax=lax)
        ip = packet[IPv4]
        assert isinstance(ip, IPv4)
        assert ip.fragment_offset == 0 and ip.flags & 0b001
        self.assert_header_kept(packet, 1, len(frame))

    @LAX
    def test_sctp_quoted_in_an_icmp_error(self, lax):
        """An ICMP error whose quote holds the whole SCTP common header
        decodes the quote through to SCTP, as it does TCP and UDP."""
        quoted = FRAMES[1][14 : SCTP_START + 64]
        error = ICMPv4(type=3, code=3, checksum=0, rest=bytes(4), body=quoted)
        chain = error.embedded_chain
        assert chain is not None
        assert [type(layer) for layer in chain] == [IPv4, SCTP]
        assert chain.stopped_by is None
        direct = decode_frame(quoted, start=IPv4, lax=lax)
        assert direct.layers == chain.layers
        sctp = chain[SCTP]
        assert isinstance(sctp, SCTP)
        assert (sctp.src_port, sctp.dst_port) == (7, 54770)
        assert sctp.verification_tag == sctp_of(1).verification_tag

    def test_a_quote_shorter_than_the_common_header_still_stops(self):
        """RFC 792's minimum quote is 8 bytes past the IP header, short
        of SCTP's 12, so that chain stops at IPv4, as TCP's does."""
        quoted = FRAMES[1][14 : SCTP_START + 8]
        error = ICMPv4(type=3, code=3, checksum=0, rest=bytes(4), body=quoted)
        chain = error.embedded_chain
        assert chain is not None
        assert [type(layer) for layer in chain] == [IPv4]
        assert isinstance(chain.stopped_by, TruncatedHeaderError)


#: Each typed chunk accessor and the chunk types that carry its field.
ACCESSOR_TYPES: dict[str, frozenset[int]] = {
    "immediate": frozenset({0, 64}),
    "unordered": frozenset({0, 64}),
    "beginning_fragment": frozenset({0, 64}),
    "ending_fragment": frozenset({0, 64}),
    "tsn": frozenset({0, 64}),
    "stream_id": frozenset({0, 64}),
    "stream_sequence_number": frozenset({0}),
    "message_id": frozenset({64}),
    "ppid": frozenset({0, 64}),
    "fragment_sequence_number": frozenset({64}),
    "user_data": frozenset({0, 64}),
    "initiate_tag": frozenset({1, 2}),
    "a_rwnd": frozenset({1, 2, 3}),
    "outbound_streams": frozenset({1, 2}),
    "inbound_streams": frozenset({1, 2}),
    "initial_tsn": frozenset({1, 2}),
    "parameters": frozenset({1, 2}),
    "state_cookie": frozenset({2}),
    "cumulative_tsn_ack": frozenset({3}),
    "num_gap_ack_blocks": frozenset({3}),
    "num_duplicate_tsns": frozenset({3}),
    "gap_ack_blocks": frozenset({3}),
    "duplicate_tsns": frozenset({3}),
}


def only_chunk(index: int) -> SCTPChunk:
    (only,) = sctp_of(index).parsed_chunks
    return only


class TestTypedFieldsOfTheCapturedAssociation:
    """Every typed field of the capture's INIT, INIT ACK, DATA and SACK
    chunks, asserted as a concrete value and cross-checked against a
    ``struct`` decode of the captured value, and against the field it
    must agree with elsewhere in the association."""

    def test_init(self):
        init = only_chunk(0)
        assert struct.unpack_from("!IIHHI", init.value) == (
            init.initiate_tag,
            init.a_rwnd,
            init.outbound_streams,
            init.inbound_streams,
            init.initial_tsn,
        )
        assert init.initiate_tag == 0xFF09BA55
        assert init.a_rwnd == 131072
        assert (init.outbound_streams, init.inbound_streams) == (10, 2048)
        assert init.initial_tsn == 0x8F24E2D4
        # Every packet the server sends carries the client's tag.
        assert sctp_of(1).verification_tag == init.initiate_tag
        assert init.state_cookie is None  # an INIT ACK's alone

    def test_init_parameters(self):
        init = only_chunk(0)
        parameters = init.parameters
        assert parameters is not None
        assert [p.type for p in parameters] == [
            0x8000,
            0xC000,
            0x8008,
            0x8002,
            0x8004,
            0x8003,
            12,
        ]
        assert [p.type_name for p in parameters] == [
            "ECN Capable",
            "Forward-TSN-Supported",
            "Supported Extensions",
            "Random",
            "Requested HMAC Algorithm",
            "Chunk List",
            "Supported Address Types",
        ]
        by_type = {p.type: p.value for p in parameters}
        # FORWARD-TSN, AUTH, ASCONF, ASCONF-ACK and RE-CONFIG.
        assert by_type[0x8008] == bytes([192, 15, 193, 128, 130])
        assert len(by_type[0x8002]) == 32
        assert by_type[0x8004] == b"\x00\x01"  # SHA-1 (RFC 4895 §3.3)
        assert by_type[0x8003] == bytes([128, 193])
        assert by_type[12] == struct.pack("!HH", 5, 6)  # IPv4 and IPv6
        # The 5- and 2-byte values are padded inside the chunk, so the
        # parameters re-encode to exactly the captured bytes.
        assert b"".join(map(bytes, parameters)) == init.value[16:]

    def test_init_parameters_against_a_struct_walk(self):
        init = only_chunk(0)
        walked, at = [], 16
        while at < len(init.value):
            type_, length = struct.unpack_from("!HH", init.value, at)
            walked.append((type_, init.value[at + 4 : at + length]))
            at += length + -length % 4
        assert init.parameters is not None
        assert [(p.type, p.value) for p in init.parameters] == walked

    def test_init_ack(self):
        ack = only_chunk(1)
        assert struct.unpack_from("!IIHHI", ack.value) == (
            ack.initiate_tag,
            ack.a_rwnd,
            ack.outbound_streams,
            ack.inbound_streams,
            ack.initial_tsn,
        )
        assert ack.initiate_tag == 0x3ACA38F7
        assert ack.a_rwnd == 131072
        assert (ack.outbound_streams, ack.inbound_streams) == (10, 2048)
        assert ack.initial_tsn == 0x87C74B24
        assert sctp_of(2).verification_tag == ack.initiate_tag

    def test_init_ack_state_cookie_is_what_cookie_echo_returns(self):
        ack = only_chunk(1)
        assert ack.parameters is not None
        assert [p.type for p in ack.parameters] == [
            0x8000,
            0xC000,
            0x8008,
            0x8002,
            0x8004,
            0x8003,
            7,
        ]
        cookie = ack.state_cookie
        assert cookie is not None
        assert len(cookie) == 324
        assert cookie.startswith(b"KAME-BSD 1.1")
        assert cookie == ack.parameters[-1].value
        # The last parameter: type 7, length 4 + 324, nothing after it.
        at = len(ack.value) - 4 - 324
        assert struct.unpack_from("!HH", ack.value, at) == (7, 4 + 324)
        assert cookie == ack.value[at + 4 :]
        assert cookie == only_chunk(2).value  # the COOKIE ECHO
        assert b"".join(map(bytes, ack.parameters)) == ack.value[16:]

    @pytest.mark.parametrize(
        "index,tsn", [(4, 0x8F24E2D4), (6, 0x87C74B24)], ids=["c2s", "s2c"]
    )
    def test_data(self, index, tsn):
        data = only_chunk(index)
        assert struct.unpack_from("!IHHI", data.value) == (
            data.tsn,
            data.stream_id,
            data.stream_sequence_number,
            data.ppid,
        )
        assert data.tsn == tsn
        assert (data.stream_id, data.stream_sequence_number) == (0, 0)
        assert data.ppid == 0  # no application identifier
        assert data.user_data == b"hello sctp\n" == data.value[12:]
        assert data.flags == 0x03
        assert (data.beginning_fragment, data.ending_fragment) == (True, True)
        assert (data.unordered, data.immediate) == (False, False)
        assert data.message_id is None
        assert data.fragment_sequence_number is None

    def test_each_side_starts_at_its_initial_tsn(self):
        assert only_chunk(4).tsn == only_chunk(0).initial_tsn
        assert only_chunk(6).tsn == only_chunk(1).initial_tsn

    @pytest.mark.parametrize(
        "index,data_index,a_rwnd",
        [(5, 4, 130805), (7, 6, 131072)],
        ids=["s2c", "c2s"],
    )
    def test_sack(self, index, data_index, a_rwnd):
        sack = only_chunk(index)
        assert struct.unpack_from("!IIHH", sack.value) == (
            sack.cumulative_tsn_ack,
            sack.a_rwnd,
            sack.num_gap_ack_blocks,
            sack.num_duplicate_tsns,
        )
        assert sack.cumulative_tsn_ack == only_chunk(data_index).tsn
        assert sack.a_rwnd == a_rwnd
        assert (sack.num_gap_ack_blocks, sack.num_duplicate_tsns) == (0, 0)
        assert sack.gap_ack_blocks == ()
        assert sack.duplicate_tsns == ()

    @pytest.mark.parametrize("index", range(len(FRAMES)))
    def test_every_other_field_of_every_captured_chunk_is_none(self, index):
        for chunk_ in sctp_of(index).parsed_chunks:
            for name, types in ACCESSOR_TYPES.items():
                if chunk_.type not in types:
                    assert getattr(chunk_, name) is None, name


class TestTypedAccessorsAreTotal:
    def test_the_table_names_every_typed_accessor(self):
        """ACCESSOR_TYPES, and so every test below, covers every
        property SCTPChunk has beyond its four display helpers."""
        properties = {
            name
            for name, attr in vars(SCTPChunk).items()
            if isinstance(attr, property)
        }
        display = {"length", "type_name", "flags_str", "unrecognized_action"}
        assert properties - display == set(ACCESSOR_TYPES)

    @pytest.mark.parametrize("flags", [0x00, 0x0F, 0xFF])
    def test_a_type_without_the_field_reads_none(self, flags):
        """Every field fits a 64-byte value, so only the type decides."""
        for type_ in range(256):
            chunk_ = SCTPChunk(type_, flags, bytes(64))
            for name, types in ACCESSOR_TYPES.items():
                if type_ not in types:
                    assert getattr(chunk_, name) is None, (type_, name)

    @pytest.mark.parametrize("type_", sorted({0, 1, 2, 3, 64}))
    def test_an_empty_value_reads_none_but_for_the_flags(self, type_):
        chunk_ = SCTPChunk(type_, 0x0F)
        for name in ACCESSOR_TYPES:
            expected_some = name in (
                "immediate",
                "unordered",
                "beginning_fragment",
                "ending_fragment",
            ) and type_ in (0, 64)
            assert (getattr(chunk_, name) is not None) == expected_some, name


def assert_cut_fields(type_, flags, value, fields):
    """Cut ``value`` at every length and check each field reads its
    value from the cut exactly when the cut holds its ``need`` bytes.

    :param fields: ``{name: (need, expected)}``.
    """
    for cut in range(len(value) + 1):
        chunk_ = SCTPChunk(type_, flags, value[:cut])
        for name, (need, expected) in fields.items():
            got = getattr(chunk_, name)
            if cut < need:
                assert got is None, (name, cut)
            elif callable(expected):
                assert got == expected(value[:cut]), (name, cut)
            else:
                assert got == expected, (name, cut)


class TestDataTruncation:
    VALUE = struct.pack("!IHHI", 0x01020304, 7, 0xBEEF, 46) + b"user data"

    def test_every_field_at_every_cut(self):
        assert_cut_fields(
            0,
            0x03,
            self.VALUE,
            {
                "tsn": (4, 0x01020304),
                "stream_id": (6, 7),
                "stream_sequence_number": (8, 0xBEEF),
                "ppid": (12, 46),
                "user_data": (12, lambda cut: cut[12:]),
            },
        )

    def test_the_user_data_may_be_empty(self):
        assert SCTPChunk(0, 3, self.VALUE[:12]).user_data == b""

    @pytest.mark.parametrize(
        "flags,expected",
        [
            (0x00, (False, False, False, False)),
            (0x08, (True, False, False, False)),
            (0x04, (False, True, False, False)),
            (0x02, (False, False, True, False)),
            (0x01, (False, False, False, True)),
            (0xFF, (True, True, True, True)),
            (0xF0, (False, False, False, False)),  # reserved bits only
        ],
    )
    @pytest.mark.parametrize("type_", [0, 64])
    def test_flags_by_name(self, type_, flags, expected):
        chunk_ = SCTPChunk(type_, flags, self.VALUE)
        assert (
            chunk_.immediate,
            chunk_.unordered,
            chunk_.beginning_fragment,
            chunk_.ending_fragment,
        ) == expected


class TestIData:
    """I-DATA (RFC 8260 §2.1): sctp.pcap holds none, so every chunk here
    is built by hand from the RFC's layout, not taken from a capture."""

    @staticmethod
    def value(word: int, data: bytes = b"fragment") -> bytes:
        # TSN, Stream Identifier, Reserved (nonzero: ignored), MID, and
        # the PPID or FSN word.
        return struct.pack("!IHHII", 0xA0B0C0D0, 3, 0xFFFF, 77, word) + data

    def test_a_first_fragment_carries_the_ppid(self):
        value = self.value(60)
        assert_cut_fields(
            64,
            0x02,
            value,
            {
                "tsn": (4, 0xA0B0C0D0),
                "stream_id": (6, 3),
                "message_id": (12, 77),
                "ppid": (16, 60),
                "user_data": (16, lambda cut: cut[16:]),
                "fragment_sequence_number": (0, None),
                "stream_sequence_number": (0, None),
            },
        )

    @pytest.mark.parametrize("flags", [0x00, 0x01, 0x0D])
    def test_a_later_fragment_carries_the_fsn(self, flags):
        value = self.value(5)
        assert_cut_fields(
            64,
            flags,
            value,
            {
                "tsn": (4, 0xA0B0C0D0),
                "stream_id": (6, 3),
                "message_id": (12, 77),
                "fragment_sequence_number": (16, 5),
                "user_data": (16, lambda cut: cut[16:]),
                "ppid": (0, None),
            },
        )

    def test_the_i_u_b_e_flags(self):
        chunk_ = SCTPChunk(64, 0x0F, self.value(1))
        assert chunk_.flags_str == "I U B E"
        assert chunk_.immediate and chunk_.unordered
        assert chunk_.beginning_fragment and chunk_.ending_fragment

    def test_a_data_chunk_has_no_fsn_whatever_its_b_bit(self):
        for flags in (0x00, 0x02):
            assert (
                SCTPChunk(0, flags, bytes(32)).fragment_sequence_number is None
            )


def init_value(parameters: bytes = b"") -> bytes:
    return struct.pack("!IIHHI", 0x11223344, 4660, 5, 6, 1000) + parameters


class TestInitTruncation:
    @pytest.mark.parametrize("type_", [1, 2])
    def test_every_field_at_every_cut(self, type_):
        parameter = bytes(SCTPParameter(9, struct.pack("!I", 60000)))
        assert_cut_fields(
            type_,
            0,
            init_value(parameter),
            {
                "initiate_tag": (4, 0x11223344),
                "a_rwnd": (8, 4660),
                "outbound_streams": (10, 5),
                "inbound_streams": (12, 6),
                "initial_tsn": (16, 1000),
            },
        )

    @pytest.mark.parametrize("type_", [1, 2])
    @pytest.mark.parametrize("cut", range(16))
    def test_no_parameters_before_the_fixed_fields_end(self, type_, cut):
        assert SCTPChunk(type_, 0, init_value()[:cut]).parameters is None

    @pytest.mark.parametrize("type_", [1, 2])
    def test_only_the_fixed_fields_is_no_parameters(self, type_):
        assert SCTPChunk(type_, 0, init_value()).parameters == ()


class TestParameters:
    def parameters_of(self, raw: bytes, type_: int = 1):
        return SCTPChunk(type_, 0, init_value(raw)).parameters

    def test_inner_padding_is_skipped(self):
        first = SCTPParameter(0x8008, b"\xc0\x0f\xc1")
        second = SCTPParameter(5, bytes([10, 0, 0, 1]))
        raw = bytes(first) + bytes(second)
        assert len(raw) == 8 + 8
        assert self.parameters_of(raw) == (first, second)

    def test_the_last_parameter_needs_no_padding(self):
        """RFC 9260 §3.2: the chunk length leaves out the last
        parameter's padding."""
        last = SCTPParameter(0x8008, b"\xc0\x0f\xc1\x80\x82")
        assert self.parameters_of(bytes(last)[:-3]) == (last,)

    def test_padding_kept_after_the_last_parameter_is_skipped(self):
        last = SCTPParameter(0x8008, b"\xc0")
        assert self.parameters_of(bytes(last)) == (last,)

    @pytest.mark.parametrize("length", [0, 1, 2, 3])
    def test_a_length_below_four(self, length):
        raw = struct.pack("!HH", 5, length) + bytes(8)
        assert self.parameters_of(raw) is None

    def test_a_length_past_the_value(self):
        raw = struct.pack("!HH", 5, 12) + bytes(4)
        assert self.parameters_of(raw) is None
        assert self.parameters_of(raw + bytes(4)) is not None

    @pytest.mark.parametrize("left", [1, 2, 3])
    def test_bytes_too_few_for_a_parameter_header(self, left):
        raw = bytes(SCTPParameter(9, bytes(4))) + b"\x00" * left
        assert self.parameters_of(raw) is None

    def test_many_minimal_parameters_walk(self):
        raw = bytes(SCTPParameter(0xC000)) * 4096
        parameters = self.parameters_of(raw)
        assert parameters is not None
        assert len(parameters) == 4096


class TestStateCookie:
    COOKIE = SCTPParameter(7, b"opaque cookie")

    def test_an_init_ack_without_one(self):
        raw = bytes(SCTPParameter(5, bytes(4)))
        assert SCTPChunk(2, 0, init_value(raw)).state_cookie is None
        assert SCTPChunk(2, 0, init_value()).state_cookie is None

    def test_the_first_of_two_is_read(self):
        raw = bytes(self.COOKIE) + bytes(SCTPParameter(7, b"second"))
        assert SCTPChunk(2, 0, init_value(raw)).state_cookie == b"opaque cookie"

    def test_an_init_has_none_even_when_it_carries_one(self):
        chunk_ = SCTPChunk(1, 0, init_value(bytes(self.COOKIE)))
        assert chunk_.parameters == (self.COOKIE,)
        assert chunk_.state_cookie is None

    def test_parameters_that_do_not_walk(self):
        raw = bytes(self.COOKIE) + b"\x00\x05\x00\x02"
        chunk_ = SCTPChunk(2, 0, init_value(raw))
        assert chunk_.parameters is None
        assert chunk_.state_cookie is None

    def test_an_init_ack_cut_short_of_its_fixed_fields(self):
        assert SCTPChunk(2, 0, init_value()[:15]).state_cookie is None


def sack_value(gaps=(), dups=(), *, num_gaps=None, num_dups=None) -> bytes:
    return (
        struct.pack(
            "!IIHH",
            12,
            4660,
            len(gaps) if num_gaps is None else num_gaps,
            len(dups) if num_dups is None else num_dups,
        )
        + b"".join(struct.pack("!HH", *gap) for gap in gaps)
        + b"".join(struct.pack("!I", dup) for dup in dups)
    )


class TestSack:
    def test_rfc_9260_example(self):
        """RFC 9260 §3.3.4's example: TSNs 10-12, 14-15 and 17
        received, so Cumulative TSN Ack 12 and blocks 2-3 and 5-5."""
        sack = SCTPChunk(3, 0, sack_value([(2, 3), (5, 5)]))
        assert sack.cumulative_tsn_ack == 12
        assert sack.a_rwnd == 4660
        assert (sack.num_gap_ack_blocks, sack.num_duplicate_tsns) == (2, 0)
        assert sack.gap_ack_blocks == ((2, 3), (5, 5))
        assert sack.duplicate_tsns == ()

    def test_duplicates_follow_the_blocks(self):
        sack = SCTPChunk(3, 0, sack_value([(2, 3)], [19, 19, 0xFFFFFFFF]))
        assert sack.gap_ack_blocks == ((2, 3),)
        assert sack.duplicate_tsns == (19, 19, 0xFFFFFFFF)

    def test_every_field_at_every_cut(self):
        value = sack_value([(2, 3), (0xFFFE, 0xFFFF)], [19, 21])
        assert len(value) == 12 + 8 + 8
        assert_cut_fields(
            3,
            0,
            value,
            {
                "cumulative_tsn_ack": (4, 12),
                "a_rwnd": (8, 4660),
                "num_gap_ack_blocks": (10, 2),
                "num_duplicate_tsns": (12, 2),
                "gap_ack_blocks": (20, ((2, 3), (0xFFFE, 0xFFFF))),
                "duplicate_tsns": (28, (19, 21)),
            },
        )

    def test_more_blocks_declared_than_the_value_holds(self):
        """A count the value cannot hold reads None, never the blocks
        that fit, and neither do the duplicates after them."""
        sack = SCTPChunk(3, 0, sack_value([(2, 3), (5, 5)], num_gaps=3))
        assert sack.num_gap_ack_blocks == 3
        assert sack.gap_ack_blocks is None
        assert sack.duplicate_tsns is None
        assert sack.cumulative_tsn_ack == 12

    def test_more_duplicates_declared_than_the_value_holds(self):
        sack = SCTPChunk(3, 0, sack_value([(2, 3)], [19, 20], num_dups=5))
        assert sack.gap_ack_blocks == ((2, 3),)
        assert sack.duplicate_tsns is None

    def test_the_largest_counts_read_none_at_once(self):
        sack = SCTPChunk(3, 0, sack_value(num_gaps=0xFFFF, num_dups=0xFFFF))
        assert sack.gap_ack_blocks is None
        assert sack.duplicate_tsns is None

    def test_bytes_after_the_declared_lists_are_ignored(self):
        sack = SCTPChunk(3, 0, sack_value([(1, 1)], [9]) + bytes(7))
        assert sack.gap_ack_blocks == ((1, 1),)
        assert sack.duplicate_tsns == (9,)


class TestSCTPParameter:
    def test_bytes_pads_to_a_multiple_of_four(self):
        assert bytes(SCTPParameter(0x8008, b"\xc0\x0f\xc1\x80\x82")) == (
            b"\x80\x08\x00\x09\xc0\x0f\xc1\x80\x82\x00\x00\x00"
        )
        assert bytes(SCTPParameter(0xC000)) == b"\xc0\x00\x00\x04"

    def test_length_excludes_padding(self):
        assert SCTPParameter(7, b"abcde").length == 9

    def test_the_largest_value_fits_the_length_field(self):
        assert SCTPParameter(7, bytes(65531)).length == 0xFFFF

    def test_a_value_too_long_for_the_length_field(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            SCTPParameter(7, bytes(65532))
        err = excinfo.value
        assert err.protocol is SCTPParameter
        assert err.field == "value"
        assert (err.expected, err.actual) == ("<=65531", 65532)
        assert str(err) == (
            "SCTP parameter value must be at most 65531 bytes, got 65532"
        )

    @pytest.mark.parametrize("number", [-1, 0x10000])
    def test_the_type_is_16_bits(self, number):
        with pytest.raises(InvalidFieldError) as excinfo:
            SCTPParameter(number)
        err = excinfo.value
        assert err.field == "type"
        assert (err.expected, err.actual) == ("0-65535", number)
        assert str(err) == (
            f"SCTP parameter type must be within 0-65535, got {number}"
        )

    def test_the_type_range_edges_are_accepted(self):
        assert bytes(SCTPParameter(0))[:2] == b"\x00\x00"
        assert bytes(SCTPParameter(0xFFFF))[:2] == b"\xff\xff"

    @pytest.mark.parametrize(
        "type_,name",
        [
            (5, "IPv4 Address"),
            (6, "IPv6 Address"),
            (7, "State Cookie"),
            (8, "Unrecognized Parameter"),
            (9, "Cookie Preservative"),
            (11, "Host Name Address"),
            (12, "Supported Address Types"),
            (0x8000, "ECN Capable"),
            (0x8002, "Random"),
            (0x8003, "Chunk List"),
            (0x8004, "Requested HMAC Algorithm"),
            (0x8005, "Padding"),
            (0x8008, "Supported Extensions"),
            (0xC000, "Forward-TSN-Supported"),
            (0xC006, "Adaptation Layer Indication"),
            (0x1234, "unknown (4660)"),
        ],
    )
    def test_type_names(self, type_, name):
        assert SCTPParameter(type_).type_name == name


@dataclass(frozen=True, slots=True)
class Greeting(Protocol):
    """A toy user-data decoder: it accepts what starts with ``hello``."""

    text: bytes

    _struct: ClassVar[struct.Struct] = struct.Struct("")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        if not bytes(data).startswith(b"hello"):
            raise InvalidFieldError(
                "not a greeting", protocol=cls, field="text", offset=0
            )
        return cls(bytes(data))

    def __bytes__(self) -> bytes:
        return self.text

    @property
    def header_len(self) -> int:
        return len(self.text)


#: The PPID the toy decoder is registered at: 0, which the capture's
#: DATA chunks carry.
GREETING_PPID = 0


@pytest.fixture
def greeting_registry() -> Registry:
    registry = Registry.from_defaults()
    registry.register(TABLE_SCTP_PPID, GREETING_PPID, Greeting)
    return registry


def i_data(flags: int, word: int, data: bytes) -> SCTPChunk:
    """A hand-built I-DATA chunk (sctp.pcap holds none)."""
    return SCTPChunk(64, flags, struct.pack("!IHHII", 1, 0, 0, 0, word) + data)


class TestDecodeUserData:
    def test_the_table_ships_empty(self):
        assert DEFAULT.table(TABLE_SCTP_PPID) == {}
        assert only_chunk(4).decode_user_data() is None

    def test_a_captured_data_chunk_through_a_registered_decoder(
        self, greeting_registry
    ):
        for index in (4, 6):
            decoded = only_chunk(index).decode_user_data(greeting_registry)
            assert decoded == Greeting(b"hello sctp\n")

    def test_the_default_registry_is_live(self):
        DEFAULT.register(TABLE_SCTP_PPID, GREETING_PPID, Greeting)
        try:
            assert only_chunk(4).decode_user_data() == Greeting(b"hello sctp\n")
        finally:
            del DEFAULT.table(TABLE_SCTP_PPID)[GREETING_PPID]
        assert only_chunk(4).decode_user_data() is None

    @pytest.mark.parametrize("flags", [0x00, 0x01, 0x02, 0x0D, 0x0E])
    def test_a_fragment_is_not_decoded(self, greeting_registry, flags):
        data = replace(only_chunk(4), flags=flags)
        assert data.decode_user_data(greeting_registry) is None
        idata = i_data(flags, GREETING_PPID, b"hello")
        assert idata.decode_user_data(greeting_registry) is None

    @pytest.mark.parametrize("flags", [0x03, 0x07, 0x0F, 0xF3])
    def test_an_unfragmented_message_is_decoded(self, greeting_registry, flags):
        data = replace(only_chunk(4), flags=flags)
        assert data.decode_user_data(greeting_registry) == Greeting(
            b"hello sctp\n"
        )

    def test_an_unfragmented_i_data_chunk(self, greeting_registry):
        """Hand-built: the PPID is the fifth word, the user data after
        it."""
        idata = i_data(0x03, GREETING_PPID, b"hello i-data")
        assert idata.decode_user_data(greeting_registry) == Greeting(
            b"hello i-data"
        )
        other = i_data(0x03, 99, b"hello i-data")
        assert other.decode_user_data(greeting_registry) is None

    def test_a_ppid_with_no_entry(self, greeting_registry):
        data = SCTPChunk(0, 3, struct.pack("!IHHI", 1, 0, 0, 46) + b"hello")
        assert data.decode_user_data(greeting_registry) is None

    def test_a_withheld_ppid(self, greeting_registry):
        withheld = greeting_registry.derive(
            {TABLE_SCTP_PPID: {GREETING_PPID: WITHHELD}}
        )
        assert only_chunk(4).decode_user_data(withheld) is None
        greeting_registry.register(
            TABLE_SCTP_PPID, GREETING_PPID, WITHHELD, override=True
        )
        assert only_chunk(4).decode_user_data(greeting_registry) is None

    @pytest.mark.parametrize("type_", [1, 2, 3, 4, 63])
    def test_another_chunk_type(self, greeting_registry, type_):
        chunk_ = replace(only_chunk(4), type=type_)
        assert chunk_.decode_user_data(greeting_registry) is None

    @pytest.mark.parametrize("cut", range(12))
    def test_a_value_too_short_for_the_user_data(self, greeting_registry, cut):
        data = SCTPChunk(0, 3, only_chunk(4).value[:cut])
        assert data.decode_user_data(greeting_registry) is None

    def test_a_decoder_that_rejects_the_user_data_raises(
        self, greeting_registry
    ):
        data = SCTPChunk(0, 3, struct.pack("!IHHI", 1, 0, 0, 0) + b"bye")
        with pytest.raises(InvalidFieldError) as excinfo:
            data.decode_user_data(greeting_registry)
        assert excinfo.value.protocol is Greeting

    def test_the_walk_still_ends_at_sctp(self, greeting_registry):
        packet = decode_frame(FRAMES[4], registry=greeting_registry)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, SCTP]
        assert sctp_of(4).next_protocol(greeting_registry) is None
