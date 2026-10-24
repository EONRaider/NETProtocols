"""SCTP (RFC 9260): the common header, the chunk walk that bounds the
packet, the chunk accessor, and dispatch from IPv4/IPv6 protocol 132.

The real association in tests/fixtures/sctp.pcap (see its MANIFEST
note) anchors the decode and round-trip asserts; the edge cases a real
stack never sends are built here. CRC32c itself is tested in
test_checksum.py, where the mutation audit's test selection reaches it.
"""

import zlib
from dataclasses import replace

import pytest

from conftest import FIXTURES, pcap_frames
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
    SCTPChunk,
    TruncatedHeaderError,
    compute,
    decode_frame,
    verify,
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
    """The walker does not trim to the IP length, so an Ethernet frame
    padded to 60 bytes hands SCTP a zero tail it must not swallow."""

    def test_a_padded_frame_stops_before_the_padding(self):
        frame = FRAMES[3]  # COOKIE ACK: a 50-byte frame
        padded = frame + bytes(60 - len(frame))
        packet = decode_frame(padded)
        assert packet.consumed == len(frame)
        sctp = packet[SCTP]
        assert isinstance(sctp, SCTP)
        assert bytes(sctp) == packet_bytes(3)
        assert verify(sctp)  # CRC32c is not blind to trailing zeros

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
        """A sender bug the walk cannot see past: the final chunk's
        missing padding (RFC 9260 §3.2) is filled from the link layer's
        zeros, so the decoded packet is three bytes longer than the one
        sent, and its CRC no longer matches."""
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

    @LAX
    @pytest.mark.parametrize("index", range(len(FRAMES)))
    def test_an_appended_ethernet_fcs(self, index, lax):
        """A capture that keeps the FCS ends every frame in 4 nonzero
        bytes: kept as the packet's last bytes, which the CRC rejects."""
        frame = FRAMES[index]
        with_fcs = frame + zlib.crc32(frame).to_bytes(4, "little")
        packet = decode_frame(with_fcs, lax=lax)
        sctp = self.assert_header_kept(packet, index, len(with_fcs))
        assert sctp.chunks.startswith(sctp_of(index).chunks)

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
