"""Tests of BGP-4 (RFC 4271) message decoding and its TCP 179 dispatch.

The common header, the four message bodies RFC 4271 defines (and
ROUTE-REFRESH's, raw), dispatch from TCP port 179, and how a segment
holding several messages, or part of one, walks.

Real bytes come from two captures of one BIRD session
(tests/fixtures/MANIFEST.md): ``bgp.pcap``, the corpus frames, whose
payloads are whole messages, and ``bgp/bgp_session.pcap``, every frame
of the session, the bare ACKs and the segments cut mid-message
included. IPv6 cannot be captured on the capture host, so BGP over
IPv6 is covered by constructed frames here.
"""

import random
import struct

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    BGP,
    MAX_DEPTH,
    TCP,
    BGPOptionalParameter,
    BGPPathAttribute,
    BGPPrefix,
    Ethernet,
    InvalidFieldError,
    IPv4,
    IPv6,
    MaxDepthExceededError,
    Packet,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_TCP_PORT

CORPUS = pcap_frames(FIXTURES / "bgp.pcap")
SESSION = pcap_frames(FIXTURES / "bgp" / "bgp_session.pcap")

#: Ethernet, IPv4 and a TCP header with the timestamps option: where the
#: BGP payload starts in every captured frame.
PAYLOAD_AT = 14 + 20 + 32

MARKER = b"\xff" * 16
KEEPALIVE = MARKER + b"\x00\x13\x04"

A, B, C = "10.185.0.1", "10.185.0.2", "10.185.0.3"


def message(type_: int, body: bytes = b"") -> bytes:
    """Build a BGP message with the given type and body."""
    return MARKER + struct.pack("!HB", 19 + len(body), type_) + body


def update(
    withdrawn: bytes = b"", attributes: bytes = b"", nlri: bytes = b""
) -> bytes:
    """Build an UPDATE message from its three variable fields."""
    body = (
        struct.pack("!H", len(withdrawn))
        + withdrawn
        + struct.pack("!H", len(attributes))
        + attributes
        + nlri
    )
    return message(2, body)


def open_body(params: bytes, *, my_as: int = 65001) -> bytes:
    """Build an OPEN body: version 4, ``my_as``, hold time 90, 192.0.2.1."""
    return (
        struct.pack("!BHH4sB", 4, my_as, 90, bytes([192, 0, 2, 1]), len(params))
        + params
    )


def frame(payload: bytes, *, sport: int = 50000, dport: int = 179) -> bytes:
    """``Ethernet -> IPv4 -> TCP`` carrying ``payload``."""
    return (
        bytes(
            Packet(
                Ethernet(
                    dst="02:00:0a:b9:00:02",
                    src="02:00:0a:b9:00:01",
                    ethertype=0x0800,
                ),
                IPv4(
                    version=4,
                    ihl=5,
                    dscp=0,
                    ecn=0,
                    total_length=40 + len(payload),
                    identification=0,
                    flags=2,
                    fragment_offset=0,
                    ttl=1,
                    protocol=6,
                    checksum=0,
                    src="192.0.2.1",
                    dst="192.0.2.2",
                ),
                tcp(sport, dport),
            )
        )
        + payload
    )


def tcp(sport: int, dport: int) -> TCP:
    return TCP(
        src_port=sport,
        dst_port=dport,
        seq=1,
        ack=1,
        data_offset=5,
        reserved=0,
        flags=0x18,
        window=0xFFFF,
        checksum=0,
        urgent_pointer=0,
    )


def bgp_layers(packet: Packet) -> list[BGP]:
    return [layer for layer in packet if isinstance(layer, BGP)]


def corpus_messages() -> list[tuple[str, str, BGP]]:
    """Every message of the corpus file, with its addresses."""
    found = []
    for raw in CORPUS:
        packet = decode_frame(raw)
        ip = packet[IPv4]
        assert isinstance(ip, IPv4)
        found += [(ip.src, ip.dst, msg) for msg in bgp_layers(packet)]
    return found


class TestCorpus:
    def test_every_frame_walks_to_whole_messages(self):
        """Every corpus frame walks strictly to the end of its payload."""
        for raw in CORPUS:
            packet = decode_frame(raw)
            types = [type(layer) for layer in packet]
            assert types[:3] == [Ethernet, IPv4, TCP]
            assert types[3:] and set(types[3:]) == {BGP}
            assert packet.consumed == len(raw)
            assert packet.stopped_by is None
            assert bytes(packet) == raw

    def test_messages_round_trip(self):
        """Every corpus message re-encodes to its bytes and decodes back."""
        for _, _, msg in corpus_messages():
            assert BGP.decode(bytes(msg)) == msg
            assert msg.header_len == msg.length == len(bytes(msg))

    def test_composition(self):
        """The corpus file holds what the capture script asserted."""
        types = [msg.type for _, _, msg in corpus_messages()]
        assert types.count(BGP.OPEN) == 4
        assert types.count(BGP.NOTIFICATION) == 2
        assert types.count(BGP.KEEPALIVE) == 4
        assert types.count(BGP.UPDATE) == 23
        assert len(CORPUS) == 19

    def test_a_segment_carrying_seven_messages(self):
        """One segment of seven UPDATEs walks as seven layers."""
        packet = decode_frame(CORPUS[10])
        messages = bgp_layers(packet)
        assert [msg.type_name for msg in messages] == ["UPDATE"] * 7
        assert [msg.length for msg in messages] == [55, 54, 55, 46, 55, 55, 23]
        assert all(msg.next_protocol() is BGP for msg in messages[:-1])
        assert messages[-1].next_protocol() is None
        # The last is the End-of-RIB marker (RFC 4724 §2): an UPDATE
        # with every field empty.
        assert messages[-1].withdrawn_routes == ()
        assert messages[-1].path_attributes == ()
        assert messages[-1].nlri == ()

    def test_opens(self):
        """Each OPEN decodes its fixed fields and one Capabilities parameter."""
        opens = {
            (src, dst): msg
            for src, dst, msg in corpus_messages()
            if msg.type == BGP.OPEN
        }
        assert set(opens) == {(A, B), (B, A), (A, C), (C, A)}
        b_open = opens[(B, A)]
        assert b_open.type_name == "OPEN"
        assert b_open.version == 4
        assert b_open.my_as == 65002
        assert b_open.hold_time == 9
        assert b_open.bgp_identifier == B
        assert b_open.extended_optional_parameters is False
        (param,) = b_open.optional_parameters
        assert param.type == 2
        assert param.type_name == "Capabilities"
        # BIRD's capabilities, kept raw: the first is Multiprotocol
        # (code 1, length 4) for IPv4 unicast (AFI 1, SAFI 1), and
        # 4-byte AS numbers (code 65, RFC 6793) carry 65002 again.
        assert param.value[:6] == bytes([1, 4, 0, 1, 0, 1])
        assert bytes([65, 4]) + (65002).to_bytes(4, "big") in param.value
        assert opens[(A, C)].my_as == opens[(C, A)].my_as == 65001

    def test_keepalives(self):
        """A KEEPALIVE is the bare header, with no body fields."""
        keepalives = [
            msg for _, _, msg in corpus_messages() if msg.type == BGP.KEEPALIVE
        ]
        assert keepalives
        for msg in keepalives:
            assert bytes(msg) == KEEPALIVE
            assert msg.type_name == "KEEPALIVE"
            assert msg.version is None
            assert msg.nlri is None
            assert msg.error_code is None

    def test_ebgp_update_attributes(self):
        """A's eBGP announcement of 198.51.100.0/25 to B.

        It carries ORIGIN, AS_PATH, NEXT_HOP and MED, the AS_PATH one
        AS_SEQUENCE of one 4-byte AS number, since both speakers
        advertised the RFC 6793 capability.
        """
        (msg,) = [
            msg
            for src, dst, msg in corpus_messages()
            if (src, dst) == (A, B)
            and msg.nlri
            and str(msg.nlri[0]) == "198.51.100.0/25"
        ]
        assert msg.withdrawn_routes == ()
        attributes = msg.path_attributes
        assert [a.type_name for a in attributes] == [
            "ORIGIN",
            "AS_PATH",
            "NEXT_HOP",
            "MULTI_EXIT_DISC",
        ]
        origin, as_path, next_hop, med = attributes
        assert (origin.value, origin.value_text) == (0, "IGP")
        assert origin.transitive and not origin.optional
        assert as_path.value is None
        assert as_path.data == bytes([2, 1]) + (65001).to_bytes(4, "big")
        assert as_path.value_text == as_path.data.hex()
        assert next_hop.value == A
        assert (med.value, med.value_text) == (20, "20")
        assert med.optional and not med.transitive
        assert msg.nlri == (BGPPrefix(25, bytes([198, 51, 100, 0])),)

    def test_ibgp_update_carries_local_pref(self):
        """Every iBGP announcement carries LOCAL_PREF (RFC 4271 §5.1.5).

        The value is BIRD's default, 100.
        """
        ibgp = [
            msg
            for src, dst, msg in corpus_messages()
            if C in (src, dst) and msg.type == BGP.UPDATE and msg.nlri
        ]
        assert ibgp
        for msg in ibgp:
            (local_pref,) = [
                a for a in msg.path_attributes if a.type_name == "LOCAL_PREF"
            ]
            assert local_pref.value == 100

    def test_withdrawals(self):
        """A's withdrawal to each peer lists its five prefixes alone."""
        withdrawals = [
            (dst, msg)
            for src, dst, msg in corpus_messages()
            if msg.type == BGP.UPDATE and msg.withdrawn_routes
        ]
        assert {dst for dst, _ in withdrawals} == {B, C}
        for _, msg in withdrawals:
            assert sorted(str(p) for p in msg.withdrawn_routes) == [
                "192.0.2.0/24",
                "198.51.100.0/25",
                "198.51.100.128/26",
                "203.0.113.0/27",
                "203.0.113.255/32",
            ]
            assert msg.path_attributes == ()
            assert msg.nlri == ()

    def test_notifications(self):
        """Both shutdown NOTIFICATIONs are Cease, Administrative Shutdown."""
        notifications = [
            msg
            for _, _, msg in corpus_messages()
            if msg.type == BGP.NOTIFICATION
        ]
        assert len(notifications) == 2
        for msg in notifications:
            assert msg.type_name == "NOTIFICATION"
            assert (msg.error_code, msg.error_subcode) == (6, 2)
            assert msg.error_code_name == "Cease"
            assert msg.error_subcode_name == "Administrative Shutdown"
            assert msg.shutdown_communication == "NETProtocols fixture shutdown"
            assert msg.error_data == b"\x1dNETProtocols fixture shutdown"


class TestSession:
    """The whole captured session, segment by segment and reassembled.

    What the per-segment walk does with bare segments and with messages
    that straddle a segment boundary, and that the reassembled streams
    are nothing but whole messages.
    """

    def test_a_bare_segment_raises_in_strict_mode(self):
        """A segment with no payload sends an empty buffer into BGP."""
        syn = SESSION[0]
        assert len(syn) == PAYLOAD_AT + 8  # SYN options, no payload
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(syn)
        assert caught.value.protocol is BGP
        packet = decode_frame(syn, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, TCP]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    def test_whole_messages_then_a_cut_one(self):
        """Frame 31: two whole UPDATEs, then the start of a third.

        The first 332 bytes of a 1063-byte UPDATE that frame 33
        finishes.
        """
        raw = SESSION[30]
        cut_at = PAYLOAD_AT + 1063 + 53
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(raw)
        error = caught.value
        assert error.protocol is BGP
        assert error.frame_offset == cut_at
        assert (error.expected, error.actual) == (1063, len(raw) - cut_at)

        packet = decode_frame(raw, lax=True)
        messages = bgp_layers(packet)
        assert [msg.length for msg in messages] == [1063, 53]
        assert len(messages[0].nlri) == 255
        assert messages[1].next_protocol() is BGP
        assert packet.consumed == cut_at
        assert isinstance(packet.stopped_by, TruncatedHeaderError)
        assert packet.stopped_by.frame_offset == cut_at

    @pytest.mark.parametrize("index", [32, 34, 86])
    def test_a_segment_starting_inside_a_message(self, index):
        """A segment that begins inside a message fails the Marker check."""
        raw = SESSION[index]
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(raw)
        assert caught.value.field == "marker"
        assert caught.value.frame_offset == PAYLOAD_AT
        packet = decode_frame(raw, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, TCP]

    @pytest.mark.parametrize("index", [33, 85])
    def test_a_segment_holding_only_the_start_of_one(self, index):
        """A segment that ends inside its only message raises at it."""
        raw = SESSION[index]
        packet = decode_frame(raw, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, TCP]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)
        assert packet.stopped_by.frame_offset == PAYLOAD_AT

    def test_reassembled_streams_are_whole_messages(self):
        """Each direction's reassembled stream is whole messages.

        Reassembled the way a caller would, every stream decodes to the
        end as back-to-back messages, and the corpus frames' messages
        are among them.
        """
        streams: dict[tuple[str, str], bytes] = {}
        for raw in SESSION:
            packet = decode_frame(raw, lax=True)
            ip, segment = packet[IPv4], packet[TCP]
            assert isinstance(ip, IPv4) and isinstance(segment, TCP)
            at = 14 + ip.header_len + segment.header_len
            key = (ip.src, ip.dst)
            streams[key] = streams.get(key, b"") + raw[at:]
        decoded: dict[tuple[str, str], list[BGP]] = {}
        for key, stream in streams.items():
            cursor, decoded[key] = 0, []
            while cursor < len(stream):
                msg = BGP.decode(stream[cursor:])
                decoded[key].append(msg)
                cursor += msg.header_len
            assert cursor == len(stream)
        announced_to_c = {
            str(prefix)
            for msg in decoded[(A, C)]
            if msg.type == BGP.UPDATE
            for prefix in msg.nlri
        }
        assert len(announced_to_c) == 5 + 2 + 600
        assert "10.202.87.0/24" in announced_to_c
        everything = [msg for messages in decoded.values() for msg in messages]
        for _, _, msg in corpus_messages():
            assert msg in everything


class TestDispatch:
    def test_port_179_is_registered(self):
        """TCP port 179 names BGP in the default registry."""
        assert DEFAULT.get(TABLE_TCP_PORT, 179) is BGP

    @pytest.mark.parametrize(
        "sport,dport", [(50000, 179), (179, 50000)], ids=["to", "from"]
    )
    def test_either_direction_dispatches(self, sport, dport):
        """Either port being 179 reaches BGP."""
        packet = decode_frame(frame(KEEPALIVE, sport=sport, dport=dport))
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, TCP, BGP]

    def test_over_ipv6(self):
        """BGP over IPv6 (constructed: the capture host has no IPv6)."""
        raw = (
            bytes(
                Packet(
                    Ethernet(
                        dst="02:00:00:00:00:02",
                        src="02:00:00:00:00:01",
                        ethertype=0x86DD,
                    ),
                    IPv6(
                        version=6,
                        traffic_class=0xC0,
                        flow_label=0,
                        payload_length=20 + 2 * 19,
                        next_header=6,
                        hop_limit=1,
                        src="2001:db8::1",
                        dst="2001:db8::2",
                    ),
                    tcp(179, 40000),
                )
            )
            + KEEPALIVE * 2
        )
        packet = decode_frame(raw)
        assert [type(layer) for layer in packet] == [
            Ethernet,
            IPv6,
            TCP,
            BGP,
            BGP,
        ]

    def test_decode_as_reaches_another_port(self):
        """decode_as reads BGP on a port the caller names."""
        packet = decode_frame(
            frame(KEEPALIVE, dport=1790), decode_as={"tcp.port": {1790: BGP}}
        )
        assert type(packet[3]) is BGP


class TestHeader:
    def test_decode_keepalive(self):
        """A KEEPALIVE decodes to the header alone and round-trips."""
        msg = BGP.decode(KEEPALIVE)
        assert msg == BGP(marker=BGP.MARKER, length=19, type=BGP.KEEPALIVE)
        assert msg.header_len == 19
        assert bytes(msg) == KEEPALIVE
        assert msg.next_protocol() is None

    def test_memoryview_input(self):
        """A memoryview is read but never kept."""
        buffer = bytearray(KEEPALIVE + KEEPALIVE)
        msg = BGP.decode(memoryview(buffer))
        buffer[:] = bytes(len(buffer))
        assert bytes(msg) == KEEPALIVE
        assert isinstance(msg.marker, bytes) and isinstance(msg.body, bytes)
        assert msg.next_protocol() is BGP

    def test_marker_must_be_all_ones(self):
        """One clear Marker bit rejects the message."""
        raw = b"\xff" * 15 + b"\xfe" + KEEPALIVE[16:]
        with pytest.raises(InvalidFieldError) as caught:
            BGP.decode(raw)
        assert (caught.value.field, caught.value.offset) == ("marker", 0)

    def test_length_below_the_header(self):
        """A Length under 19 is rejected before the Type is read."""
        with pytest.raises(InvalidFieldError) as caught:
            BGP.decode(MARKER + b"\x00\x12\x04" + bytes(4))
        assert (caught.value.field, caught.value.offset) == ("length", 16)

    @pytest.mark.parametrize("type_", [0, 6, 255])
    def test_type_must_be_known(self, type_):
        """Types outside 1-5 are rejected."""
        with pytest.raises(InvalidFieldError) as caught:
            BGP.decode(message(type_, bytes(10)))
        assert (caught.value.field, caught.value.offset) == ("type", 18)

    @pytest.mark.parametrize(
        "type_,length",
        [
            (1, 28),
            (1, 4097),
            (2, 22),
            (3, 20),
            (4, 20),
            (5, 22),
        ],
    )
    def test_length_outside_the_types_bounds(self, type_, length):
        """A Length outside its type's bounds is rejected."""
        raw = MARKER + struct.pack("!HB", length, type_) + bytes(length)
        with pytest.raises(InvalidFieldError) as caught:
            BGP.decode(raw)
        assert (caught.value.field, caught.value.offset) == ("length", 16)

    @pytest.mark.parametrize(
        "type_,length",
        [(1, 29), (1, 4096), (2, 23), (2, 0xFFFF), (3, 21), (5, 23)],
    )
    def test_length_at_the_types_bounds(self, type_, length):
        """Messages at each type's bounds decode.

        RFC 8654 extended messages, up to 65535 bytes, decode for the
        types it extends; OPEN stops at 4096.
        """
        body = bytes(length - 19)
        msg = BGP.decode(message(type_, body))
        assert msg.header_len == length

    def test_a_message_longer_than_the_buffer(self):
        """A Length past the buffer raises TruncatedHeaderError."""
        raw = message(2, bytes(40))
        with pytest.raises(TruncatedHeaderError) as caught:
            BGP.decode(raw[:-1])
        error = caught.value
        assert (error.field, error.expected, error.actual) == (
            "length",
            59,
            58,
        )

    def test_a_short_buffer(self):
        """A buffer shorter than the header raises TruncatedHeaderError."""
        with pytest.raises(TruncatedHeaderError):
            BGP.decode(KEEPALIVE[:18])

    def test_route_refresh_keeps_its_body_raw(self):
        """ROUTE-REFRESH (RFC 2918 §3): AFI 1, reserved, SAFI 1."""
        raw = message(5, b"\x00\x01\x00\x01")
        msg = BGP.decode(raw + KEEPALIVE)
        assert msg.type_name == "ROUTE-REFRESH"
        assert msg.body == b"\x00\x01\x00\x01"
        assert msg.header_len == 23
        assert msg.next_protocol() is BGP
        assert msg.version is None
        assert msg.withdrawn_routes is None
        assert msg.error_code is None

    def test_an_unknown_type_name(self):
        """A constructed unknown type renders by number."""
        msg = BGP(marker=BGP.MARKER, length=19, type=7)
        assert msg.type_name == "unknown (7)"

    def test_decode_context_is_not_compared_or_hashed(self):
        """Where a message was found does not change its equality."""
        alone = BGP.decode(KEEPALIVE)
        followed = BGP.decode(KEEPALIVE + KEEPALIVE)
        assert followed.next_protocol() is BGP
        assert alone.next_protocol() is None
        assert alone == followed
        assert hash(alone) == hash(followed)
        assert repr(alone) == repr(followed)

    @pytest.mark.parametrize(
        "kwargs,field",
        [
            ({"marker": b"\xff" * 15, "length": 19, "type": 4}, "marker"),
            ({"marker": MARKER, "length": 19, "type": 256}, "type"),
            ({"marker": MARKER, "length": 19, "type": -1}, "type"),
            ({"marker": MARKER, "length": 20, "type": 4}, "length"),
            (
                {
                    "marker": MARKER,
                    "length": 0x10000,
                    "type": 2,
                    "body": bytes(0x10000 - 19),
                },
                "length",
            ),
        ],
    )
    def test_construction_checks_the_header_fields(self, kwargs, field):
        """The constructor rejects fields that do not fit."""
        with pytest.raises(InvalidFieldError) as caught:
            BGP(**kwargs)
        assert caught.value.field == field

    def test_construction_allows_what_decode_rejects(self):
        """A bad Marker or Type builds, for testing another speaker."""
        msg = BGP(marker=bytes(16), length=19, type=9)
        assert bytes(msg) == bytes(16) + b"\x00\x13\x09"
        with pytest.raises(InvalidFieldError):
            BGP.decode(bytes(msg))


class TestTrailingBytes:
    """Bytes after the last message, which reach the decoder.

    The walker does not trim a frame to the IP length.
    """

    @pytest.mark.parametrize(
        "trailer",
        [bytes(6), bytes(46), b"\x12\x34\x56\x78", b"\xff\xfe\x00\x00"],
        ids=["pad-6", "pad-46", "fcs", "fcs-ff"],
    )
    def test_a_trailer_ends_the_walk_cleanly(self, trailer):
        """Padding or an FCS after the last message is left undecoded."""
        raw = frame(KEEPALIVE * 2) + trailer
        packet = decode_frame(raw)
        assert [type(layer) for layer in packet][3:] == [BGP, BGP]
        assert packet.stopped_by is None
        assert packet.consumed == len(raw) - len(trailer)

    def test_zero_padding_after_one_message(self):
        """Zero bytes after a message do not start another."""
        msg = BGP.decode(KEEPALIVE + bytes(4))
        assert msg.next_protocol() is None
        assert msg.header_len == 19

    @pytest.mark.parametrize("cut", [1, 4, 15, 16, 18, 22])
    def test_the_start_of_another_message_continues_the_walk(self, cut):
        """The start of a Marker after a message continues the walk.

        Bytes that read as a Marker, or as much of one as there is, are
        a message the segment cut: the walk goes on, and raises there.
        An FCS of four 0xff bytes reads the same way (one value in
        2**32).
        """
        raw = frame(KEEPALIVE + update()[:cut])
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(raw)
        assert caught.value.frame_offset == 54 + 19
        packet = decode_frame(raw, lax=True)
        assert len(bgp_layers(packet)) == 1


class TestMaxDepth:
    """Segments of many messages against ``max_depth``.

    A 1448-byte segment (MSS 1460 less TCP timestamps) holds 76
    KEEPALIVEs and the first 4 bytes of a 77th: 79 complete layers.
    """

    SEGMENT = KEEPALIVE * 76 + MARKER[:4]

    def test_the_default_depth_stops_the_walk(self):
        """MAX_DEPTH stops a segment of 76 KEEPALIVEs."""
        raw = frame(self.SEGMENT)
        with pytest.raises(MaxDepthExceededError):
            decode_frame(raw)
        packet = decode_frame(raw, lax=True)
        assert len(packet) == MAX_DEPTH == 32
        assert len(bgp_layers(packet)) == MAX_DEPTH - 3
        assert isinstance(packet.stopped_by, MaxDepthExceededError)

    def test_a_raised_depth_reaches_every_message(self):
        """max_depth=80 reaches all 76 and the cut 77th."""
        raw = frame(self.SEGMENT)
        with pytest.raises(TruncatedHeaderError):
            decode_frame(raw, max_depth=80)
        packet = decode_frame(raw, max_depth=80, lax=True)
        assert len(bgp_layers(packet)) == 76
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    def test_a_full_segment_of_whole_messages(self):
        """76 KEEPALIVEs, the most whole messages 1460 bytes hold."""
        raw = frame(KEEPALIVE * 76)
        assert len(decode_frame(raw, max_depth=79)) == 79


class TestRandomPayloads:
    """The guard against a wrong port guess, as ARCHITECTURE.md has it.

    Random payloads to port 179 never decode as BGP.
    """

    @pytest.mark.parametrize("sizes", ["fixed-300", "uniform-0-600"])
    def test_random_payloads_are_rejected(self, sizes):
        """Seeded random payloads to port 179 never decode as BGP."""
        rng = random.Random(185)
        for _ in range(2000):
            size = 300 if sizes == "fixed-300" else rng.randint(0, 600)
            packet = decode_frame(frame(rng.randbytes(size)), lax=True)
            assert packet.stopped_by is not None
            assert not bgp_layers(packet)


class TestOpen:
    def test_fixed_fields(self):
        """An OPEN's fixed fields, from an AS_TRANS speaker."""
        msg = BGP.decode(message(1, open_body(b"", my_as=23456)))
        assert msg.version == 4
        assert msg.my_as == 23456  # AS_TRANS (RFC 6793 §9)
        assert msg.hold_time == 90
        assert msg.bgp_identifier == "192.0.2.1"
        assert msg.optional_parameters == ()
        assert msg.extended_optional_parameters is False

    def test_optional_parameters(self):
        """Optional parameters walk as type/length/value, named or not."""
        params = (
            b"\x02\x06\x01\x04\x00\x01\x00\x01" + b"\x07\x00" + b"\x01\x01\xaa"
        )
        msg = BGP.decode(message(1, open_body(params)))
        assert msg.optional_parameters == (
            BGPOptionalParameter(2, b"\x01\x04\x00\x01\x00\x01"),
            BGPOptionalParameter(7, b""),
            BGPOptionalParameter(1, b"\xaa"),
        )
        names = [p.type_name for p in msg.optional_parameters]
        assert names == [
            "Capabilities",
            "unknown (7)",
            "Authentication (deprecated)",
        ]

    def test_rfc9072_extended_parameters(self):
        """RFC 9072's extended optional parameters decode.

        Non-Ext OP Len 255, Non-Ext OP Type 255, a 2-byte Extended Opt.
        Parm. Length, and parameters with 2-byte lengths.
        """
        capabilities = bytes(range(256)) + bytes(44)  # 300 bytes
        params = b"\x02" + len(capabilities).to_bytes(2, "big") + capabilities
        body = (
            struct.pack("!BHH4sB", 4, 65001, 90, bytes(4), 255)
            + b"\xff"
            + len(params).to_bytes(2, "big")
            + params
        )
        msg = BGP.decode(message(1, body))
        assert msg.extended_optional_parameters is True
        assert msg.optional_parameters == (
            BGPOptionalParameter(2, capabilities),
        )

    def test_255_bytes_of_ordinary_parameters_are_not_extended(self):
        """An Optional Parameters Length of 255 alone is not RFC 9072."""
        params = b"\x02\xfd" + bytes(253)
        msg = BGP.decode(message(1, open_body(params)))
        assert msg.extended_optional_parameters is False
        assert msg.optional_parameters == (BGPOptionalParameter(2, bytes(253)),)

    @pytest.mark.parametrize(
        "body",
        [
            # Optional Parameters Length 4 with 3 bytes present.
            struct.pack("!BHH4sB", 4, 1, 90, bytes(4), 4) + b"\x02\x01\x00",
            # Length 2 with 3 bytes present.
            struct.pack("!BHH4sB", 4, 1, 90, bytes(4), 2) + b"\x02\x00\x00",
            # A parameter longer than the parameters.
            open_body(b"\x02\x05\x00"),
            # A lone type byte.
            open_body(b"\x02"),
            # Extended, with no room for the extended length.
            struct.pack("!BHH4sB", 4, 1, 90, bytes(4), 255) + b"\xff\x00",
            # Extended, with the extended length disagreeing.
            struct.pack("!BHH4sB", 4, 1, 90, bytes(4), 255)
            + b"\xff\x00\x04\x02\x00\x00",
            # Extended, a parameter whose 2-byte length overruns.
            struct.pack("!BHH4sB", 4, 1, 90, bytes(4), 255)
            + b"\xff\x00\x03\x02\x00\x05",
        ],
    )
    def test_malformed_parameters_raise_from_the_accessor(self, body):
        """Malformed parameters raise from the accessor, not decode."""
        msg = BGP.decode(message(1, body))
        assert msg.version == 4
        with pytest.raises(InvalidFieldError) as caught:
            _ = msg.optional_parameters
        assert caught.value.field == "body"
        assert caught.value.protocol is BGP

    def test_a_constructed_open_too_short_for_its_fields(self):
        """A constructed OPEN too short for its fields has none."""
        msg = BGP(marker=MARKER, length=22, type=BGP.OPEN, body=b"\x04\x00\x01")
        assert msg.version is None
        assert msg.bgp_identifier is None
        assert msg.optional_parameters is None
        assert msg.extended_optional_parameters is None

    def test_other_messages_have_no_open_fields(self):
        """Only an OPEN has OPEN fields."""
        msg = BGP.decode(update())
        for name in (
            "version",
            "my_as",
            "hold_time",
            "bgp_identifier",
            "optional_parameters",
            "extended_optional_parameters",
        ):
            assert getattr(msg, name) is None, name


class TestUpdate:
    def test_all_three_fields(self):
        """Withdrawn Routes, path attributes and NLRI all parse."""
        withdrawn = bytes([8, 10]) + bytes([0])  # 10.0.0.0/8, 0.0.0.0/0
        attributes = (
            bytes([0x40, 1, 1, 2])  # ORIGIN INCOMPLETE
            + bytes([0x40, 2, 0])  # empty AS_PATH
            + bytes([0x40, 3, 4, 192, 0, 2, 1])  # NEXT_HOP
            + bytes([0x40, 5, 4, 0, 0, 0, 200])  # LOCAL_PREF
            + bytes([0xC0, 8, 4, 0xFD, 0xE9, 0, 1])  # COMMUNITIES, raw
        )
        nlri = bytes([32, 192, 0, 2, 7]) + bytes([20, 198, 51, 111])
        msg = BGP.decode(update(withdrawn, attributes, nlri))
        assert [str(p) for p in msg.withdrawn_routes] == [
            "10.0.0.0/8",
            "0.0.0.0/0",
        ]
        assert [a.type_name for a in msg.path_attributes] == [
            "ORIGIN",
            "AS_PATH",
            "NEXT_HOP",
            "LOCAL_PREF",
            "COMMUNITIES",
        ]
        values = [a.value for a in msg.path_attributes]
        assert values == [2, None, "192.0.2.1", 200, None]
        texts = [a.value_text for a in msg.path_attributes]
        assert texts == ["INCOMPLETE", "", "192.0.2.1", "200", "fde90001"]
        assert [str(p) for p in msg.nlri] == ["192.0.2.7/32", "198.51.96.0/20"]
        # Bits past the prefix length are kept as sent, and cleared in
        # the network view (RFC 4271 §4.3: they are irrelevant).
        assert msg.nlri[1].prefix == bytes([198, 51, 111])

    def test_extended_length_attribute(self):
        """An Extended Length (0x10) attribute has a 2-byte length.

        An unnamed type keeps its value raw in a correctly shaped TLV.
        """
        value = bytes(300)
        attributes = bytes([0xD0, 99]) + len(value).to_bytes(2, "big") + value
        attributes += bytes([0x50, 4, 0, 4, 0, 0, 1, 0])  # MED, extended
        msg = BGP.decode(update(attributes=attributes))
        unknown, med = msg.path_attributes
        assert unknown == BGPPathAttribute(0xD0, 99, value)
        assert unknown.type_name == "unknown (99)"
        assert (
            unknown.optional and unknown.transitive and unknown.extended_length
        )
        assert not unknown.partial
        assert med.value == 256
        assert bytes(unknown) + bytes(med) == attributes

    @pytest.mark.parametrize(
        "type_code,name",
        [
            (0, "Reserved"),
            (16, "EXTENDED_COMMUNITIES"),
            (35, "Only to Customer (OTC)"),
            (40, "BGP Prefix-SID"),
            (128, "ATTR_SET"),
            (255, "Reserved for development"),
            (34, "unknown (34)"),  # a temporary registration, lapsed
            (43, "unknown (43)"),
        ],
    )
    def test_attribute_type_names(self, type_code, name):
        """Type codes carry their IANA names; values stay raw."""
        attribute = BGPPathAttribute(0xC0, type_code, b"\x00\x00\x00\x01")
        assert attribute.type_name == name
        assert attribute.value is None
        assert attribute.value_text == "00000001"

    def test_wrong_length_values_are_not_decoded(self):
        """A value of the wrong length stays raw."""
        attributes = (
            bytes([0x40, 1, 2, 0, 0])  # ORIGIN of 2 bytes
            + bytes([0x40, 3, 3, 1, 2, 3])  # NEXT_HOP of 3
            + bytes([0x80, 4, 0])  # MED of 0
            + bytes([0x40, 6, 0])  # ATOMIC_AGGREGATE: no value to decode
            + bytes([0x40, 1, 1, 7])  # ORIGIN 7: unassigned
            + bytes([0xC0, 18, 4, 1, 2, 3, 4])  # AS4_AGGREGATOR, 4 bytes, raw
        )
        msg = BGP.decode(update(attributes=attributes))
        attrs = msg.path_attributes
        assert [a.value for a in attrs] == [None, None, None, None, 7, None]
        assert [a.value_text for a in attrs] == [
            "0000",
            "010203",
            "",
            "",
            "unknown (7)",
            "01020304",
        ]
        assert attrs[3].type_name == "ATOMIC_AGGREGATE"

    @pytest.mark.parametrize(
        "raw,offset",
        [
            (update(withdrawn=bytes([33, 1, 2, 3, 4, 5])), 2),
            (update(withdrawn=bytes([24, 10, 0])), 2),
            (update(nlri=bytes([16, 10, 0]) + bytes([40])), 7),
            (update(nlri=bytes([9, 10])), 4),
            (update(attributes=bytes([0x40, 1])), 4),
            (update(attributes=bytes([0x50, 1, 0])), 4),
            (update(attributes=bytes([0x40, 1, 2, 0])), 4),
            (update(attributes=bytes([0x50, 1, 0, 2, 0])), 4),
        ],
    )
    def test_malformed_fields_raise_from_the_accessors(self, raw, offset):
        """A field that does not walk raises from its accessor."""
        msg = BGP.decode(raw)
        with pytest.raises(InvalidFieldError) as caught:
            _ = (msg.withdrawn_routes, msg.path_attributes, msg.nlri)
        assert caught.value.field == "body"
        assert caught.value.offset == offset

    @pytest.mark.parametrize(
        "body,offset",
        [
            (b"\x00\x03\x00\x00", 0),  # withdrawn length past the end
            (b"\x00\x00\x00\x01", 2),  # attribute length past the end
        ],
    )
    def test_lengths_past_the_message(self, body, offset):
        """A length past the message breaks all three accessors."""
        msg = BGP.decode(message(2, body))
        for name in ("withdrawn_routes", "path_attributes", "nlri"):
            with pytest.raises(InvalidFieldError) as caught:
                getattr(msg, name)
            assert caught.value.offset == offset

    def test_a_constructed_update_too_short_for_its_lengths(self):
        """A constructed UPDATE without its lengths raises."""
        msg = BGP(marker=MARKER, length=20, type=BGP.UPDATE, body=b"\x00")
        with pytest.raises(InvalidFieldError):
            _ = msg.nlri

    def test_other_messages_have_no_update_fields(self):
        """Only an UPDATE has UPDATE fields."""
        msg = BGP.decode(KEEPALIVE)
        assert msg.withdrawn_routes is None
        assert msg.path_attributes is None
        assert msg.nlri is None


class TestPrefixAndAttributeConstruction:
    def test_prefix_wire_form(self):
        """A prefix serializes and renders as CIDR."""
        prefix = BGPPrefix(length=22, prefix=bytes([10, 1, 4]))
        assert bytes(prefix) == bytes([22, 10, 1, 4])
        assert str(prefix) == "10.1.4.0/22"
        assert BGPPrefix(0).network.prefixlen == 0

    @pytest.mark.parametrize(
        "length,prefix,field",
        [
            (33, bytes(5), "length"),
            (-1, b"", "length"),
            (8, b"", "prefix"),
            (8, bytes(2), "prefix"),
        ],
    )
    def test_prefix_checks(self, length, prefix, field):
        """A prefix must be 0-32 bits with matching bytes."""
        with pytest.raises(InvalidFieldError) as caught:
            BGPPrefix(length=length, prefix=prefix)
        assert caught.value.field == field

    @pytest.mark.parametrize(
        "kwargs,field",
        [
            ({"flags": 256, "type_code": 1}, "flags"),
            ({"flags": 0, "type_code": -1}, "type_code"),
            ({"flags": 0x40, "type_code": 2, "data": bytes(256)}, "data"),
            ({"flags": 0x50, "type_code": 2, "data": bytes(0x10000)}, "data"),
        ],
    )
    def test_attribute_checks(self, kwargs, field):
        """An attribute must fit its fields and its length width."""
        with pytest.raises(InvalidFieldError) as caught:
            BGPPathAttribute(**kwargs)
        assert caught.value.field == field

    def test_attribute_wire_form(self):
        """An attribute serializes with a one- or two-byte length."""
        assert bytes(BGPPathAttribute(0x40, 1, b"\x00")) == b"\x40\x01\x01\x00"
        assert (
            bytes(BGPPathAttribute(0x50, 1, b"\x00")) == b"\x50\x01\x00\x01\x00"
        )
        assert BGPPathAttribute(0x20, 1).partial


class TestNotification:
    def test_fields(self):
        """A NOTIFICATION's code, subcode and data."""
        msg = BGP.decode(message(3, b"\x02\x02\xfd\xea"))
        assert msg.error_code_name == "OPEN Message Error"
        assert msg.error_subcode_name == "Bad Peer AS"
        assert msg.error_data == b"\xfd\xea"
        assert msg.shutdown_communication is None

    @pytest.mark.parametrize(
        "code,subcode,code_name,subcode_name",
        [
            (1, 0, "Message Header Error", "Unspecific"),
            (1, 2, "Message Header Error", "Bad Message Length"),
            (2, 7, "OPEN Message Error", "Unsupported Capability"),
            (2, 11, "OPEN Message Error", "Role Mismatch"),
            (2, 12, "OPEN Message Error", "unknown (12)"),
            (3, 11, "UPDATE Message Error", "Malformed AS_PATH"),
            (4, 0, "Hold Timer Expired", "Unspecific"),
            (4, 1, "Hold Timer Expired", "unknown (1)"),
            (5, 0, "Finite State Machine Error", "Unspecified Error"),
            (
                5,
                3,
                "Finite State Machine Error",
                "Receive Unexpected Message in Established State",
            ),
            (6, 0, "Cease", "Reserved"),
            (6, 8, "Cease", "Out of Resources"),
            (6, 9, "Cease", "Hard Reset"),
            (6, 10, "Cease", "BFD Down"),
            (6, 11, "Cease", "unknown (11)"),
            (7, 0, "ROUTE-REFRESH Message Error", "Reserved"),
            (7, 1, "ROUTE-REFRESH Message Error", "Invalid Message Length"),
            (8, 0, "Send Hold Timer Expired", "Unspecific"),
            (9, 0, "Loss of LSDB Synchronization", "Unspecific"),
            (0, 0, "Reserved", "Unspecific"),
            (10, 0, "unknown (10)", "Unspecific"),
            (10, 1, "unknown (10)", "unknown (1)"),
        ],
    )
    def test_names(self, code, subcode, code_name, subcode_name):
        """Error codes and subcodes carry their IANA names.

        Subcode 0 has a name per code where the code has a subcode
        registry, and is "Unspecific" (RFC 4271 §4.5) where it has none;
        anything unassigned is named by number.
        """
        msg = BGP.decode(message(3, bytes([code, subcode])))
        assert msg.error_code_name == code_name
        assert msg.error_subcode_name == subcode_name
        assert msg.error_data == b""

    @pytest.mark.parametrize(
        "body,communication",
        [
            (b"\x06\x04\x02hi", "hi"),  # Administrative Reset
            (b"\x06\x02\x00", ""),
            (b"\x06\x02\x02\xc3\xa9", "é"),
            (b"\x06\x02", None),  # no data
            (b"\x06\x02\x05hi", None),  # length overruns
            (b"\x06\x03\x02hi", None),  # Peer De-configured: no message
            (b"\x02\x02\x02hi", None),  # not a Cease
        ],
    )
    def test_shutdown_communication(self, body, communication):
        """Only a well-formed shutdown communication is decoded."""
        msg = BGP.decode(message(3, body))
        assert msg.shutdown_communication == communication

    def test_a_constructed_notification_without_codes(self):
        """A constructed NOTIFICATION without codes has none."""
        msg = BGP(marker=MARKER, length=20, type=BGP.NOTIFICATION, body=b"\x06")
        assert msg.error_code is None
        assert msg.error_subcode is None
        assert msg.error_data is None
        assert msg.error_code_name is None
        assert msg.error_subcode_name is None
        assert msg.shutdown_communication is None

    def test_other_messages_have_no_notification_fields(self):
        """Only a NOTIFICATION has NOTIFICATION fields."""
        msg = BGP.decode(KEEPALIVE)
        assert msg.error_code is None
        assert msg.error_code_name is None
        assert msg.shutdown_communication is None
