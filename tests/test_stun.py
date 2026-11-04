"""Test STUN (RFC 8489, RFC 5389) decoding and dispatch.

Covered: the 20-byte header and its magic cookie, the class and method
interleaved in the message type, attributes and their padding, the
XOR-MAPPED-ADDRESS un-XOR over IPv4 and IPv6, the decode-time guard
against a wrong port guess and against RFC 3489, messages back to back
over TCP, and dispatch from UDP and TCP port 3478. FINGERPRINT, a
checksum, is tested in test_checksum.py, which is in the mutation
audit's test selection.

The coturn exchanges in tests/fixtures/stun.pcap and the RFC 3489 one
in tests/fixtures/stun/stun_rfc3489.pcap (see their MANIFEST notes)
anchor the decode and round-trip asserts. The kernel they were
captured on had no IPv6, so IPv6 comes from RFC 5769's test vectors;
the cases a real stack does not send are built here.
"""

import binascii
import hashlib
import hmac
import importlib.util
import random
import struct
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    DNS,
    STUN,
    TCP,
    UDP,
    Ethernet,
    InvalidFieldError,
    IPv4,
    MaxDepthExceededError,
    STUNAddress,
    STUNAttribute,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_TCP_PORT, TABLE_UDP_PORT

CHECKER = Path(__file__).resolve().parent.parent / "scripts/check_fixtures.py"
FRAMES = pcap_frames(FIXTURES / "stun.pcap")
CLASSIC = pcap_frames(FIXTURES / "stun" / "stun_rfc3489.pcap")

#: Ethernet, a 20-byte IPv4 header and UDP in front of a UDP message;
#: TCP's header carries 12 bytes of timestamp options.
UDP_START = 14 + 20 + 8
TCP_START = 14 + 20 + 32

#: The frames by scenario, in the order the capture script keeps them.
BINDING = (0, 1)
RFC5780 = (2, 3)
UNKNOWN = (4, 5)
TCP_FRAMES = (6, 7)
SECURE = (8, 9, 10, 11)

#: The test credential coturn was configured with, published in
#: MANIFEST.md, and the long-term key it gives (RFC 8489 §9.2.2).
USERNAME, REALM, PASSWORD = b"npstun", b"np194.test", b"np194-pass"
LONG_TERM_KEY = hashlib.md5(
    b"npstun:np194.test:np194-pass", usedforsecurity=False
).digest()

CLIENT, SERVER = "10.9.194.1", "10.9.194.2"
COTURN = "Coturn-4.6.1 'Gorst'"

#: RFC 5769's test vectors (§2.1-2.3), and the short-term password that
#: keys their MESSAGE-INTEGRITY. The responses pad SOFTWARE's 11 bytes
#: with a space, as RFC 5389 §15 allows, and the request USERNAME's 9
#: with three.
RFC5769_PASSWORD = b"VOkJxbRl1RmTxUk/WvJxBt"
RFC5769_REQUEST = bytes.fromhex(
    "000100582112a442b7e7a701bc34d686fa87dfae"
    "802200105354554e207465737420636c69656e74"
    "002400046e0001ff"
    "80290008932ff9b151263b36"
    "000600096576746a3a68367659202020"
    "000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a2"
    "80280004e57a3bcf"
)
RFC5769_IPV4 = bytes.fromhex(
    "0101003c2112a442b7e7a701bc34d686fa87dfae"
    "8022000b7465737420766563746f7220"
    "002000080001a147e112a643"
    "000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7"
    "80280004c07d4c96"
)
RFC5769_IPV6 = bytes.fromhex(
    "010100482112a442b7e7a701bc34d686fa87dfae"
    "8022000b7465737420766563746f7220"
    "002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d9"
    "00080014a382954e4be67bf11784c97c8292c275bfe3ed41"
    "80280004c8fb0b4c"
)


def start(index: int) -> int:
    return TCP_START if index in TCP_FRAMES else UDP_START


def payload(index: int) -> bytes:
    """Return the STUN bytes of capture frame ``index``, exactly."""
    return FRAMES[index][start(index) :]


def stun_of(index: int, which: int = 0) -> STUN:
    layer = [x for x in decode_frame(FRAMES[index]) if isinstance(x, STUN)]
    return layer[which]


def message(
    attributes: bytes = b"", message_type: int = 0x0001, tid: bytes = b""
) -> bytes:
    """Build a message's wire bytes around raw ``attributes``."""
    tid = tid or bytes(range(12))
    return (
        struct.pack("!HHI", message_type, len(attributes), 0x2112A442)
        + tid
        + attributes
    )


def attr(kind: int, value: bytes, pad: bytes = b"\x00") -> bytes:
    """Build one attribute, padded with ``pad`` bytes."""
    return (
        struct.pack("!HH", kind, len(value)) + value + pad * (-len(value) % 4)
    )


def compose(method: int, klass: int) -> int:
    """Interleave a method and a class into a message type (RFC 8489
    §5, Figure 3), independently of the library's split."""
    return (
        (method & 0x00F)
        | (method & 0x070) << 1
        | (method & 0xF80) << 2
        | (klass & 0b01) << 4
        | (klass & 0b10) << 7
    )


def integrity(key: bytes, raw: bytes) -> bool:
    """Check the MESSAGE-INTEGRITY in ``raw`` with ``key``: HMAC-SHA1
    over the message before it, the header's Length counting up to its
    end (RFC 8489 §14.5)."""
    offset = raw.index(b"\x00\x08\x00\x14", 20)
    covered = raw[:2] + (offset + 4).to_bytes(2, "big") + raw[4:offset]
    mac = hmac.new(key, covered, hashlib.sha1).digest()
    return mac == raw[offset + 4 : offset + 24]


class TestCapturedMessages:
    def test_every_frame_walks_to_stun_and_ends_there(self):
        """Each UDP frame walks to one STUN layer, each TCP frame to
        two, and the walk consumes the frame."""
        for index, frame in enumerate(FRAMES):
            packet = decode_frame(frame)
            if index in TCP_FRAMES:
                expected = [Ethernet, IPv4, TCP, STUN, STUN]
            else:
                expected = [Ethernet, IPv4, UDP, STUN]
            assert [type(layer) for layer in packet] == expected
            assert packet.consumed == len(frame)

    def test_every_message_round_trips_exactly(self):
        for index in range(len(FRAMES)):
            raw = payload(index)
            stun = STUN.decode(raw)
            assert bytes(stun) == raw[: stun.header_len]
            assert STUN.decode(bytes(stun)) == stun

    def test_message_types(self):
        names = [
            stun.message_type_name
            for frame in FRAMES
            for stun in decode_frame(frame)
            if isinstance(stun, STUN)
        ]
        assert names == [
            "Binding Request",
            "Binding Success Response",
            "Binding Request",
            "Binding Error Response",
            "Binding Request",
            "Binding Error Response",
            "Binding Request",
            "Binding Request",
            "Binding Success Response",
            "Binding Success Response",
            "Binding Request",
            "Binding Error Response",
            "Binding Request",
            "Binding Success Response",
        ]

    def test_attribute_types_in_wire_order(self):
        success = [
            "XOR-MAPPED-ADDRESS",
            "MAPPED-ADDRESS",
            "RESPONSE-ORIGIN",
            "SOFTWARE",
            "FINGERPRINT",
        ]
        expected = {
            0: [],
            1: success,
            2: ["RESPONSE-PORT", "CHANGE-REQUEST"],
            3: ["ERROR-CODE", "SOFTWARE", "FINGERPRINT"],
            4: ["unknown (0x7ff0)", "FINGERPRINT"],
            5: ["ERROR-CODE", "UNKNOWN-ATTRIBUTES", "SOFTWARE", "FINGERPRINT"],
            8: ["FINGERPRINT"],
            9: ["ERROR-CODE", "NONCE", "REALM", "SOFTWARE", "FINGERPRINT"],
            10: [
                "USERNAME",
                "REALM",
                "NONCE",
                "MESSAGE-INTEGRITY",
                "FINGERPRINT",
            ],
            11: [*success[:4], "MESSAGE-INTEGRITY", "FINGERPRINT"],
        }
        for index, names in expected.items():
            attributes = stun_of(index).parsed_attributes
            assert [a.type_name for a in attributes] == names, index

    def test_responses_answer_their_requests(self):
        """Each response carries its request's transaction ID, and the
        cookie is the fixed value in every message."""
        for request, response in [(0, 1), (2, 3), (4, 5), (8, 9), (10, 11)]:
            assert (
                stun_of(request).transaction_id
                == stun_of(response).transaction_id
            )
        for which in (0, 1):
            assert (
                stun_of(6, which).transaction_id
                == stun_of(7, which).transaction_id
            )
        for frame in FRAMES:
            for layer in decode_frame(frame):
                if isinstance(layer, STUN):
                    assert layer.magic_cookie == STUN.MAGIC_COOKIE

    @pytest.mark.parametrize("index", [1, 11])
    def test_xor_mapped_address_is_the_requests_source(self, index):
        """The un-XORed address and port are where the request came
        from, as the IP and UDP headers of the request say, and as
        MAPPED-ADDRESS says in the clear."""
        request = decode_frame(FRAMES[index - 1])
        expected = STUNAddress(1, request[UDP].src_port, request[IPv4].src)
        stun = stun_of(index)
        assert stun.xor_mapped_address == expected
        assert stun.mapped_address == expected
        assert stun.xor_mapped_address.family_name == "IPv4"
        raw = stun.attribute(STUN.XOR_MAPPED_ADDRESS).value
        clear = stun.attribute(STUN.MAPPED_ADDRESS).value
        assert raw != clear
        # The wire bytes are the XOR, kept untouched (RFC 8489 §14.2).
        assert int.from_bytes(raw[2:4]) == expected.port ^ 0x2112
        assert raw[4:] == bytes(
            a ^ b for a, b in zip(clear[4:], b"\x21\x12\xa4\x42", strict=True)
        )

    def test_xor_mapped_address_over_tcp(self):
        request = decode_frame(FRAMES[6])
        for which in (0, 1):
            assert stun_of(7, which).xor_mapped_address == STUNAddress(
                1, request[TCP].src_port, CLIENT
            )

    def test_response_origin_is_the_server(self):
        """RFC 5780's RESPONSE-ORIGIN is MAPPED-ADDRESS's encoding."""
        origin = stun_of(1).attribute(0x802B)
        assert origin is not None
        assert origin.type_name == "RESPONSE-ORIGIN"
        assert origin.address == STUNAddress(1, 3478, SERVER)

    def test_software(self):
        for index in (1, 3, 5, 9, 11):
            assert stun_of(index).software == COTURN
        assert stun_of(6).software == "np194 capture client"
        assert stun_of(0).software is None

    def test_rfc_5780_change_request_draws_error_420(self):
        request, error = stun_of(2), stun_of(3)
        change = request.attribute(0x0003)
        assert change is not None and change.value == b"\x00\x00\x00\x06"
        assert error.message_class == 3
        assert error.error_code == 420
        assert error.error_reason == (
            "Unknown attribute: TURN server was configured without RFC "
            "5780 support"
        )
        assert error.unknown_attributes is None

    def test_the_reason_phrase_drops_coturns_nul_padding(self):
        """coturn counts NUL padding into the reason's value."""
        value = stun_of(3).attribute(STUN.ERROR_CODE).value
        assert value.endswith(b"support\x00\x00")
        assert not stun_of(3).error_reason.endswith("\x00")

    def test_an_unknown_comprehension_required_attribute(self):
        request, error = stun_of(4), stun_of(5)
        unknown = request.parsed_attributes[0]
        assert unknown.type == 0x7FF0
        assert unknown.comprehension_required
        assert unknown.value == b"np194"
        assert error.error_code == 420
        assert error.error_reason == "Unknown Attribute"
        assert error.unknown_attributes == (0x7FF0,)

    def test_the_long_term_challenge(self):
        """An unauthenticated request draws 401 with REALM and NONCE,
        which the authenticated request repeats with USERNAME."""
        challenge, request = stun_of(9), stun_of(10)
        assert challenge.error_code == 401
        assert challenge.error_reason == "Unauthorized"
        assert challenge.attribute(0x0014).value == REALM
        nonce = challenge.attribute(0x0015).value
        assert request.attribute(0x0015).value == nonce
        assert request.attribute(0x0014).value == REALM
        assert request.attribute(0x0006).value == USERNAME

    @pytest.mark.parametrize("index", [10, 11])
    def test_message_integrity_verifies_with_the_published_credential(
        self, index
    ):
        """The library returns the HMAC raw; with the published test
        credential it verifies, both the request's and the response's."""
        stun = stun_of(index)
        assert len(stun.message_integrity) == 20
        assert integrity(LONG_TERM_KEY, payload(index))
        assert not integrity(b"another key", payload(index))

    def test_no_message_integrity_elsewhere(self):
        for index in (0, 1, 2, 3, 4, 5, 8, 9):
            assert stun_of(index).message_integrity is None

    def test_padding_is_kept_but_not_parsed(self):
        """USERNAME's 6 bytes and REALM's 10 are each padded with 2
        zero bytes: kept in the raw attributes, not in the values."""
        stun = stun_of(10)
        username, realm = stun.parsed_attributes[:2]
        assert username.value == USERNAME
        assert realm.value == REALM
        assert stun.attributes[:12] == b"\x00\x06\x00\x06npstun\x00\x00"
        assert bytes(username) + bytes(realm) == stun.attributes[:28]

    def test_lengths(self):
        """The Message Length counts the attributes, padding included."""
        for index in (0, 1, 10):
            stun = stun_of(index)
            assert stun.length == len(stun.attributes)
            assert stun.length == int.from_bytes(payload(index)[2:4])
            assert stun.header_len == 20 + stun.length
        assert stun_of(0).length == 0

    def test_rebuilding_from_parsed_attributes(self):
        """The captured padding is zero, so the parsed attributes
        rebuild every captured message exactly."""
        for index in range(len(FRAMES)):
            stun = stun_of(index)
            rebuilt = b"".join(map(bytes, stun.parsed_attributes))
            assert rebuilt == stun.attributes


class TestRFC5769Vectors:
    """RFC 5769's test vectors: published STUN messages."""

    def test_the_request(self):
        stun = STUN.decode(RFC5769_REQUEST)
        assert bytes(stun) == RFC5769_REQUEST
        assert stun.message_type_name == "Binding Request"
        assert stun.transaction_id == bytes.fromhex("b7e7a701bc34d686fa87dfae")
        assert stun.software == "STUN test client"
        assert [a.type_name for a in stun.parsed_attributes] == [
            "SOFTWARE",
            "PRIORITY",
            "ICE-CONTROLLED",
            "USERNAME",
            "MESSAGE-INTEGRITY",
            "FINGERPRINT",
        ]
        assert stun.attribute(0x0006).value == b"evtj:h6vY"
        assert integrity(RFC5769_PASSWORD, RFC5769_REQUEST)

    def test_the_ipv4_response(self):
        stun = STUN.decode(RFC5769_IPV4)
        assert stun.xor_mapped_address == STUNAddress(1, 32853, "192.0.2.1")
        assert stun.software == "test vector"
        assert stun.mapped_address is None
        assert integrity(RFC5769_PASSWORD, RFC5769_IPV4)

    def test_the_ipv6_response(self):
        """The IPv6 address is XORed with the cookie and the
        transaction ID (RFC 8489 §14.2)."""
        stun = STUN.decode(RFC5769_IPV6)
        address = stun.xor_mapped_address
        assert address == STUNAddress(
            2, 32853, "2001:db8:1234:5678:11:2233:4455:6677"
        )
        assert address.family_name == "IPv6"
        assert integrity(RFC5769_PASSWORD, RFC5769_IPV6)

    @pytest.mark.parametrize(
        "raw", [RFC5769_REQUEST, RFC5769_IPV4, RFC5769_IPV6]
    )
    def test_nonzero_padding_round_trips(self, raw):
        """RFC 5389 §15 lets padding be any value, and these vectors pad
        with spaces: decoding keeps them, so the message re-encodes
        exactly, while a rebuilt attribute pads with zeros as RFC 8489
        §14 sends it."""
        stun = STUN.decode(raw)
        assert bytes(stun) == raw
        assert b"\x20" in raw[20:]
        rebuilt = b"".join(map(bytes, stun.parsed_attributes))
        assert len(rebuilt) == len(stun.attributes)
        assert rebuilt != stun.attributes

    def test_the_ipv6_xor_needs_the_transaction_id(self):
        """With another transaction ID only the first 4 address bytes,
        XORed with the cookie alone, come out the same."""
        stun = STUN.decode(RFC5769_IPV6)
        other = replace(stun, transaction_id=bytes(12))
        moved = other.xor_mapped_address
        assert moved.port == 32853
        assert moved.address.startswith("2001:db8:")
        assert moved.address != stun.xor_mapped_address.address


class TestMessageType:
    @pytest.mark.parametrize(
        ("message_type", "klass", "method", "name"),
        [
            (0x0001, 0, 0x001, "Binding Request"),
            (0x0011, 1, 0x001, "Binding Indication"),
            (0x0101, 2, 0x001, "Binding Success Response"),
            (0x0111, 3, 0x001, "Binding Error Response"),
            (0x0003, 0, 0x003, "Allocate Request"),
            (0x0113, 3, 0x003, "Allocate Error Response"),
            (0x0104, 2, 0x004, "Refresh Success Response"),
            (0x0016, 1, 0x006, "Send Indication"),
            (0x0017, 1, 0x007, "Data Indication"),
            (0x0008, 0, 0x008, "CreatePermission Request"),
            (0x0009, 0, 0x009, "ChannelBind Request"),
            (0x000A, 0, 0x00A, "Connect Request"),
            (0x000B, 0, 0x00B, "ConnectionBind Request"),
            (0x001C, 1, 0x00C, "ConnectionAttempt Indication"),
        ],
    )
    def test_known_types(self, message_type, klass, method, name):
        stun = STUN(message_type)
        assert stun.message_class == klass
        assert stun.method == method
        assert stun.message_type_name == name

    @pytest.mark.parametrize("bit", range(14))
    def test_each_bit_lands_in_its_place(self, bit):
        """Bits 4 and 8 are the class's C0 and C1; the other twelve are
        the method's M0-M11 in order (RFC 8489 §5, Figure 3)."""
        stun = STUN(1 << bit)
        if bit == 4:
            assert (stun.message_class, stun.method) == (1, 0)
        elif bit == 8:
            assert (stun.message_class, stun.method) == (2, 0)
        else:
            position = bit - (bit > 4) - (bit > 8)
            assert (stun.message_class, stun.method) == (0, 1 << position)

    def test_every_type_splits_and_recomposes(self):
        for message_type in range(0x4000):
            stun = STUN(message_type)
            assert stun.message_class in range(4)
            assert stun.method in range(0x1000)
            assert compose(stun.method, stun.message_class) == message_type

    def test_unknown_methods_are_named_by_number(self):
        assert STUN(compose(0xFFF, 0)).method_name == "unknown (0xfff)"
        assert STUN(compose(0x002, 2)).message_type_name == (
            "unknown (0x2) Success Response"
        )
        assert STUN(compose(0x005, 1)).method_name == "unknown (0x5)"


class TestDecodeGuard:
    @pytest.mark.parametrize("top", [0x4000, 0x8000, 0xC000])
    def test_the_top_two_bits_must_be_zero(self, top):
        raw = bytearray(payload(0))
        raw[0] |= top >> 8
        with pytest.raises(InvalidFieldError) as excinfo:
            STUN.decode(bytes(raw))
        err = excinfo.value
        assert (err.protocol, err.field, err.offset) == (
            STUN,
            "message_type",
            0,
        )
        assert err.actual == top | 0x0001

    def test_turn_channel_data_is_not_stun(self):
        """A ChannelData message (RFC 8656 §12.4) starts 0b01."""
        channel_data = b"\x40\x00\x00\x04" + b"data" + bytes(12)
        with pytest.raises(InvalidFieldError, match="two zero bits"):
            STUN.decode(channel_data)

    @pytest.mark.parametrize(
        "cookie", [0x00000000, 0x2112A443, 0xA4422112, 0x2112A442 ^ 1 << 31]
    )
    def test_the_magic_cookie_is_verified(self, cookie):
        raw = bytearray(payload(1))
        raw[4:8] = cookie.to_bytes(4, "big")
        with pytest.raises(InvalidFieldError) as excinfo:
            STUN.decode(bytes(raw))
        err = excinfo.value
        assert (err.field, err.offset) == ("magic_cookie", 4)
        assert (err.expected, err.actual) == (0x2112A442, cookie)

    @pytest.mark.parametrize("length", [1, 2, 3, 5, 66])
    def test_the_length_must_be_a_multiple_of_4(self, length):
        raw = message(bytes(68))
        raw = raw[:2] + length.to_bytes(2, "big") + raw[4:]
        with pytest.raises(InvalidFieldError) as excinfo:
            STUN.decode(raw)
        err = excinfo.value
        assert (err.field, err.offset, err.actual) == ("length", 2, length)

    def test_a_length_past_the_buffer_is_truncation(self):
        raw = payload(1)
        with pytest.raises(TruncatedHeaderError) as excinfo:
            STUN.decode(raw[:-4])
        err = excinfo.value
        assert (err.field, err.offset) == ("length", 2)
        assert (err.expected, err.actual) == (len(raw), len(raw) - 4)

    @pytest.mark.parametrize("cut", [0, 1, 19])
    def test_the_fixed_header_cut(self, cut):
        with pytest.raises(TruncatedHeaderError):
            STUN.decode(payload(0)[:cut])

    def test_a_snap_length_cut_in_a_walk(self):
        """Strict raises at the STUN header; lax keeps UDP."""
        cut = FRAMES[1][:-10]
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(cut)
        assert excinfo.value.frame_offset == UDP_START + 2
        packet = decode_frame(cut, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    def test_memoryview_input_is_not_retained(self):
        buffer = bytearray(payload(11))
        stun = STUN.decode(memoryview(buffer))
        assert isinstance(stun.attributes, bytes)
        assert isinstance(stun.transaction_id, bytes)
        before = bytes(stun)
        buffer[:] = bytes(len(buffer))
        assert bytes(stun) == before


class TestRFC3489:
    """The `stun` client speaks RFC 3489, which has no magic cookie;
    coturn answers it in kind. Decode rejects every such message."""

    def test_the_capture_is_classic(self):
        assert len(CLASSIC) == 4
        for frame in CLASSIC:
            assert frame[UDP_START + 4 : UDP_START + 8] != b"\x21\x12\xa4\x42"

    def test_a_strict_walk_raises_at_the_magic_cookie(self):
        for frame in CLASSIC:
            with pytest.raises(InvalidFieldError) as excinfo:
                decode_frame(frame)
            err = excinfo.value
            assert (err.protocol, err.field) == (STUN, "magic_cookie")
            assert err.frame_offset == UDP_START + 4
            assert err.actual == int.from_bytes(
                frame[UDP_START + 4 : UDP_START + 8]
            )

    def test_a_lax_walk_keeps_the_layers_below(self):
        for frame in CLASSIC:
            packet = decode_frame(frame, lax=True)
            assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
            assert isinstance(packet.stopped_by, InvalidFieldError)

    def test_the_rest_of_the_header_is_rfc_5389s(self):
        """The type and length are where RFC 5389 put them: the cookie
        is the only thing missing, which the cookie check alone reports.
        """
        types = [
            int.from_bytes(frame[UDP_START : UDP_START + 2])
            for frame in CLASSIC
        ]
        assert types == [0x0001, 0x0101, 0x0001, 0x0111]
        for frame in CLASSIC:
            raw = bytearray(frame[UDP_START:])
            raw[4:8] = b"\x21\x12\xa4\x42"
            assert STUN.decode(bytes(raw)).length == len(raw) - 20


class TestAttributes:
    @pytest.mark.parametrize("size", range(9))
    def test_values_are_padded_to_4_bytes(self, size):
        value = bytes(range(1, size + 1))
        wire = bytes(STUNAttribute(0x8022, value))
        assert len(wire) == 4 + size + (-size % 4)
        assert wire[4 + size :] == bytes(-size % 4)
        stun = STUN.decode(message(wire + attr(0x0006, b"x")))
        assert stun.parsed_attributes == (
            STUNAttribute(0x8022, value),
            STUNAttribute(0x0006, b"x"),
        )

    def test_padding_of_any_value_is_skipped(self):
        """RFC 5389 §15: padding may be any value; RFC 8489 §14: the
        receiver ignores it."""
        raw = message(attr(0x0006, b"abcde", pad=b"\xff") + attr(0x8022, b"z"))
        stun = STUN.decode(raw)
        assert [a.value for a in stun.parsed_attributes] == [b"abcde", b"z"]
        assert bytes(stun) == raw

    def test_an_attribute_running_past_the_message(self):
        """parsed_attributes raises, with an offset into the
        attributes; the other accessors read what comes before."""
        broken = (
            attr(0x8022, b"np")
            + attr(0x0020, b"\x00\x01\xa1\x47\xe1\x12\xa6\x43")
            + b"\x00\x06\x00\x10abcd"
        )
        stun = STUN.decode(message(broken))
        with pytest.raises(InvalidFieldError) as excinfo:
            stun.parsed_attributes  # noqa: B018
        err = excinfo.value
        assert (err.protocol, err.field, err.offset) == (
            STUN,
            "attributes",
            20,
        )
        assert stun.software == "np"
        assert stun.xor_mapped_address == STUNAddress(1, 32853, "192.0.2.1")
        assert stun.attribute(0x0006) is None
        assert stun.fingerprint is None

    def test_a_cut_attribute_header(self):
        """A decoded message's attributes are a multiple of 4 bytes, so
        an attribute header always fits; a built one's need not."""
        stun = STUN(0x0001, attributes=attr(0x8022, b"np") + b"\x00\x06")
        with pytest.raises(InvalidFieldError) as excinfo:
            stun.parsed_attributes  # noqa: B018
        assert excinfo.value.offset == 8
        assert "missing its length field" in str(excinfo.value)
        assert stun.software == "np"

    def test_the_first_of_duplicates_is_read(self):
        """RFC 8489 §14: only the first occurrence is processed."""
        stun = STUN.decode(message(attr(0x8022, b"one") + attr(0x8022, b"two")))
        assert stun.software == "one"
        assert stun.attribute(0x8022) == STUNAttribute(0x8022, b"one")

    def test_comprehension_ranges(self):
        assert STUNAttribute(0x0000).comprehension_required
        assert STUNAttribute(0x7FFF).comprehension_required
        assert not STUNAttribute(0x8000).comprehension_required
        assert not STUNAttribute(0xFFFF).comprehension_required

    @pytest.mark.parametrize(
        ("kind", "name"),
        [
            (0x0001, "MAPPED-ADDRESS"),
            (0x0008, "MESSAGE-INTEGRITY"),
            (0x0009, "ERROR-CODE"),
            (0x000A, "UNKNOWN-ATTRIBUTES"),
            (0x001C, "MESSAGE-INTEGRITY-SHA256"),
            (0x0020, "XOR-MAPPED-ADDRESS"),
            (0x8022, "SOFTWARE"),
            (0x8028, "FINGERPRINT"),
            (0x0016, "XOR-RELAYED-ADDRESS"),
            (0x8002, "PASSWORD-ALGORITHMS"),
            (0x0005, "CHANGED-ADDRESS"),
            (0x001B, "ACCESS-TOKEN"),
            (0x8025, "TRANSACTION_TRANSMIT_COUNTER"),
            (0x802D, "ECN-CHECK STUN"),
            (0x802E, "THIRD-PARTY-AUTHORIZATION"),
            (0x8030, "MOBILITY-TICKET"),
            (0x802F, "unknown (0x802f)"),
            (0xC000, "unknown (0xc000)"),
            (0x0000, "unknown (0x0000)"),
        ],
    )
    def test_type_names(self, kind, name):
        assert STUNAttribute(kind).type_name == name

    @pytest.mark.parametrize(
        "value",
        [
            b"",
            b"\x00",
            b"\x00\x01\x00\x50",
            b"\x00\x01\x00\x50\xc0\x00\x02",
            b"\x00\x01\x00\x50\xc0\x00\x02\x01\x00",
            b"\x00\x02\x00\x50" + bytes(15),
            b"\x00\x02\x00\x50" + bytes(4),
            b"\x00\x03\x00\x50\xc0\x00\x02\x01",
            b"\x00\x00\x00\x50\xc0\x00\x02\x01",
        ],
    )
    def test_malformed_addresses_answer_none(self, value):
        stun = STUN.decode(message(attr(0x0001, value) + attr(0x0020, value)))
        assert stun.mapped_address is None
        assert stun.xor_mapped_address is None
        assert STUNAttribute(0x0001, value).address is None

    def test_an_unknown_family_is_named_by_number(self):
        assert STUNAddress(3, 80, "x").family_name == "unknown (3)"

    def test_the_reserved_byte_is_ignored(self):
        value = b"\xff\x01\x00\x50\xc0\x00\x02\x01"
        assert STUNAttribute(0x0001, value).address == STUNAddress(
            1, 80, "192.0.2.1"
        )

    def test_an_ipv6_mapped_address(self):
        value = b"\x00\x02\x01\xbb" + bytes.fromhex(
            "20010db8000000000000000000000001"
        )
        assert STUNAttribute(0x0001, value).address == STUNAddress(
            2, 443, "2001:db8::1"
        )

    def test_xor_address_reads_turns_attributes(self):
        """XOR-RELAYED-ADDRESS (RFC 8656 §18.5) shares the encoding."""
        stun = STUN.decode(RFC5769_IPV6)
        value = stun.attribute(STUN.XOR_MAPPED_ADDRESS).value
        relayed = STUNAttribute(0x0016, value)
        assert stun.xor_address(relayed) == stun.xor_mapped_address

    def test_error_codes(self):
        """Class times 100 plus Number; the 21 reserved bits ignored."""
        for code in (300, 400, 401, 420, 438, 500, 699):
            value = bytes([0xFF, 0xFF, 0xF8 | code // 100, code % 100])
            stun = STUN.decode(message(attr(0x0009, value + b"why")))
            assert stun.error_code == code
            assert stun.error_reason == "why"

    @pytest.mark.parametrize(
        ("klass", "number"),
        [(0, 0), (2, 99), (7, 0), (7, 255), (3, 100), (4, 150), (6, 255)],
    )
    def test_an_error_code_out_of_range_answers_none(self, klass, number):
        """RFC 8489 §14.8: the Class is 3-6 and the Number 0-99. Any
        other reads as None, not as a code of 0-955 or as a valid code
        it is not (Class 4, Number 150, is not 550); the reason phrase
        is still read."""
        value = bytes([0, 0, klass, number])
        stun = STUN.decode(message(attr(0x0009, value + b"why")))
        assert stun.error_code is None
        assert stun.error_reason == "why"

    def test_a_short_error_code_answers_none(self):
        stun = STUN.decode(message(attr(0x0009, b"\x00\x00\x04")))
        assert stun.error_code is None
        assert stun.error_reason is None

    def test_text_is_utf8_with_replacement(self):
        stun = STUN.decode(
            message(attr(0x8022, "café ✓".encode() + b"\xff\x00\x00"))
        )
        assert stun.software == "café ✓�"

    def test_unknown_attributes_ignore_an_odd_byte(self):
        stun = STUN.decode(message(attr(0x000A, b"\x7f\xf0\x00\x23\x80")))
        assert stun.unknown_attributes == (0x7FF0, 0x0023)
        stun = STUN.decode(message(attr(0x000A, b"")))
        assert stun.unknown_attributes == ()

    def test_absent_attributes_answer_none(self):
        stun = STUN.decode(payload(0))
        assert stun.parsed_attributes == ()
        for name in (
            "mapped_address",
            "xor_mapped_address",
            "software",
            "error_code",
            "error_reason",
            "unknown_attributes",
            "message_integrity",
            "fingerprint",
        ):
            assert getattr(stun, name) is None, name


class TestOverTCP:
    def test_two_messages_in_one_segment_chain(self):
        packet = decode_frame(FRAMES[6])
        first, second = packet.layers[3], packet.layers[4]
        assert first.next_protocol() is STUN
        assert second.next_protocol() is None
        assert first.header_len + second.header_len == len(payload(6))
        assert second.length == 0

    def test_a_message_built_rather_than_decoded_ends_the_chain(self):
        first = stun_of(6)
        assert first == STUN.decode(bytes(first))
        assert STUN.decode(bytes(first)).next_protocol() is None
        assert replace(first).next_protocol() is None

    @pytest.mark.parametrize(
        "tail",
        [
            b"",
            b"\xde\xad\xbe\xef",
            bytes.fromhex("000100002112a4"),
            bytes.fromhex("000100002112a443"),
            bytes.fromhex("400100002112a442"),
            bytes.fromhex("800100002112a442"),
        ],
        ids=["nothing", "fcs", "seven", "cookie", "channel-data", "top-bit"],
    )
    def test_bytes_that_do_not_begin_a_message_end_the_walk(self, tail):
        raw = payload(1) + tail
        packet = decode_frame(raw, start=STUN)
        assert [type(layer) for layer in packet] == [STUN]
        assert packet.consumed == len(payload(1))

    def test_eight_bytes_like_a_header_chain_on(self):
        """The next message's whole fixed header need not be there: a
        segment that cuts it raises at that message, strict, and keeps
        the first one, lax."""
        raw = payload(6) + payload(0)[:8]
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(raw, start=STUN)
        assert excinfo.value.frame_offset == len(payload(6))
        packet = decode_frame(raw, start=STUN, lax=True)
        assert [type(layer) for layer in packet] == [STUN, STUN]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    def test_a_segment_cut_inside_the_second_message(self):
        frame = FRAMES[7][:-20]
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [
            Ethernet,
            IPv4,
            TCP,
            STUN,
        ]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    def test_a_full_segment_of_bare_headers_exceeds_max_depth(self):
        """The module docstring's max_depth note: a 1448-byte segment
        holds 72 bare 20-byte messages, and the default MAX_DEPTH
        leaves room for 29 after Ethernet, IPv4 and TCP. Strict raises
        at the 30th, lax stops there, and a walk on with start=STUN
        and max_depth=43 decodes the other 43 (at the default, 32 of
        them)."""
        eth, ip, tcp = decode_frame(FRAMES[6]).layers[:3]
        bare = bytes(STUN(0x0001, transaction_id=bytes(range(12))))
        data = bare * 72
        assert len(bare) == 20
        assert len(data) <= 1448
        grown = replace(ip, total_length=20 + tcp.header_len + len(data))
        raw = bytes(eth) + bytes(grown) + bytes(tcp) + data
        stop_at = TCP_START + 29 * 20
        with pytest.raises(MaxDepthExceededError) as excinfo:
            decode_frame(raw)
        assert excinfo.value.protocol is STUN
        assert excinfo.value.frame_offset == stop_at
        packet = decode_frame(raw, lax=True)
        assert sum(isinstance(layer, STUN) for layer in packet) == 29
        assert isinstance(packet.stopped_by, MaxDepthExceededError)
        assert packet.consumed == stop_at
        rest = decode_frame(raw[stop_at:], start=STUN, max_depth=43)
        assert [type(layer) for layer in rest] == [STUN] * 43
        assert rest.stopped_by is None
        assert stop_at + rest.consumed == len(raw)

    def test_followed_is_neither_compared_nor_hashed(self):
        chained = stun_of(6)
        alone = STUN.decode(payload(6)[: chained.header_len])
        assert chained.next_protocol() is STUN
        assert alone.next_protocol() is None
        assert chained == alone
        assert hash(chained) == hash(alone)
        assert "_followed" not in repr(chained)


class TestConstruction:
    def test_build_a_message_from_attributes(self):
        attributes = (
            STUNAttribute(0x0006, b"user"),
            STUNAttribute(0x8022, b"np"),
        )
        stun = STUN(
            0x0001,
            transaction_id=b"\x01" * 12,
            attributes=b"".join(map(bytes, attributes)),
        )
        raw = bytes(stun)
        assert raw[:8] == b"\x00\x01\x00\x10\x21\x12\xa4\x42"
        assert STUN.decode(raw) == stun
        assert stun.parsed_attributes == attributes
        assert stun.magic_cookie == STUN.MAGIC_COOKIE

    def test_defaults(self):
        stun = STUN(0x0001)
        assert bytes(stun) == bytes.fromhex("000100002112a442") + bytes(12)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("message_type", 0x4000),
            ("message_type", -1),
            ("magic_cookie", 1 << 32),
            ("magic_cookie", -1),
            ("attributes", bytes(0x10000)),
        ],
    )
    def test_out_of_range_fields(self, field, value):
        with pytest.raises(InvalidFieldError) as excinfo:
            STUN(**{"message_type": 0x0001, field: value})
        assert excinfo.value.protocol is STUN
        assert excinfo.value.field == field

    def test_the_widest_values_are_accepted(self):
        stun = STUN(0x3FFF, 0xFFFFFFFF, b"\xff" * 12, bytes(0xFFFF))
        assert len(bytes(stun)) == 20 + 0xFFFF

    @pytest.mark.parametrize("size", [0, 11, 13, 16])
    def test_the_transaction_id_is_12_bytes(self, size):
        with pytest.raises(InvalidFieldError) as excinfo:
            STUN(0x0001, transaction_id=bytes(size))
        err = excinfo.value
        assert (err.field, err.expected, err.actual) == (
            "transaction_id",
            12,
            size,
        )

    def test_a_message_decode_rejects_still_builds(self):
        """Neither the cookie nor the 4-byte alignment is checked on
        construction, so a test of another stack can send them."""
        stun = STUN(0x0001, magic_cookie=0, attributes=b"\x00")
        with pytest.raises(InvalidFieldError):
            STUN.decode(bytes(stun))

    @pytest.mark.parametrize(
        ("field", "value"), [("type", 0x10000), ("type", -1)]
    )
    def test_attribute_type_width(self, field, value):
        with pytest.raises(InvalidFieldError) as excinfo:
            STUNAttribute(value)
        assert excinfo.value.field == field

    def test_attribute_value_width(self):
        with pytest.raises(InvalidFieldError) as excinfo:
            STUNAttribute(0x0013, bytes(0x10000))
        assert excinfo.value.field == "value"
        assert len(bytes(STUNAttribute(0x0013, bytes(0xFFFF)))) == 4 + 0x10000

    def test_positional_patterns_follow_wire_order(self):
        stun = stun_of(1)
        match stun:
            case STUN(0x0101, 0x2112A442, tid, _) if len(tid) == 12:
                pass
            case _:
                pytest.fail("STUN's match_args are not in wire order")
        match stun.parsed_attributes[0]:
            case STUNAttribute(0x0020, value) if len(value) == 8:
                pass
            case _:
                pytest.fail("STUNAttribute's match_args are not type, value")


class TestDispatch:
    def test_registered_on_udp_and_tcp_port_3478(self):
        assert DEFAULT.get(TABLE_UDP_PORT, 3478) is STUN
        assert DEFAULT.get(TABLE_TCP_PORT, 3478) is STUN

    @pytest.mark.parametrize(
        ("src_port", "dst_port"), [(50000, 3478), (3478, 50000)]
    )
    def test_either_port(self, src_port, dst_port):
        raw = bytearray(FRAMES[1])
        struct.pack_into("!HH", raw, 34, src_port, dst_port)
        struct.pack_into("!H", raw, 40, 0)
        packet = decode_frame(bytes(raw))
        assert type(packet.layers[-1]) is STUN

    def test_stun_ends_the_chain_over_udp(self):
        assert stun_of(1).next_protocol() is None

    def test_decode_as_can_take_the_port_away(self):
        packet = decode_frame(FRAMES[1], decode_as={"udp.port": {3478: DNS}})
        assert type(packet.layers[-1]) is DNS


@pytest.fixture(scope="module")
def check_fixtures():
    """Load scripts/check_fixtures.py, which shares no library code."""
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestIndependentChecker:
    """scripts/check_fixtures.py verifies every FINGERPRINT and
    MESSAGE-INTEGRITY with code of its own."""

    def test_it_passes_the_captures(self, check_fixtures):
        stats = Counter()
        for frame in FRAMES + CLASSIC:
            assert check_fixtures.check_frame(frame, stats) == []
        assert stats["stun"] == 14
        assert stats["stun-fingerprint"] == 11
        assert stats["stun-message-integrity"] == 2
        assert stats["stun-rfc3489"] == 4

    def test_its_crc32_is_the_ieee_one(self, check_fixtures):
        rng = random.Random(194)
        for size in (0, 1, 7, 64, 300):
            data = rng.randbytes(size)
            assert check_fixtures.crc32(data) == binascii.crc32(data)
        assert check_fixtures.crc32(b"123456789") == 0xCBF43926

    @pytest.mark.parametrize(
        ("index", "position", "failures"),
        [
            (1, -1, ["stun-fingerprint"]),
            (11, -12, ["stun-message-integrity", "stun-fingerprint"]),
            (11, 30, ["stun-message-integrity", "stun-fingerprint"]),
            (10, 26, ["stun-unknown-user", "stun-message-integrity"]),
        ],
        ids=["fingerprint", "integrity", "covered-byte", "username"],
    )
    def test_it_catches_a_changed_byte(
        self, check_fixtures, index, position, failures
    ):
        raw = bytearray(payload(index))
        raw[position] ^= 0x01
        found = check_fixtures._check_stun(bytes(raw), Counter(), stream=False)
        assert found[: len(failures)] == failures

    def test_it_frames_a_tcp_stream(self, check_fixtures):
        stats = Counter()
        assert check_fixtures._check_stun(payload(7), stats, stream=True) == []
        assert stats["stun"] == 2
        # A segment cut inside its second message, or starting inside
        # one, is left unchecked rather than failed.
        stats = Counter()
        cut = payload(7)[:-20]
        assert check_fixtures._check_stun(cut, stats, stream=True) == []
        assert (stats["stun"], stats["stun-unchecked"]) == (1, 1)
        stats = Counter()
        assert check_fixtures._check_stun(cut[30:], stats, stream=True) == []
        assert stats["stun-unchecked"] == 1

    @pytest.mark.parametrize(
        "raw",
        [
            payload(1)[:-4],
            payload(1) + bytes(4),
            message(b"abc"),
            b"\x40" + payload(0)[1:],
        ],
        ids=["short", "long", "unaligned", "top-bit"],
    )
    def test_it_rejects_a_bad_datagram(self, check_fixtures, raw):
        found = check_fixtures._check_stun(raw, Counter(), stream=False)
        assert found == ["stun-header"]

    def test_it_rejects_what_it_cannot_verify(self, check_fixtures):
        sha256 = message(attr(0x001C, bytes(32)))
        assert check_fixtures._check_stun(sha256, Counter(), stream=False) == [
            "stun-integrity-sha256"
        ]
        broken = message(b"\x80\x22\x00\x08abcd")
        assert check_fixtures._check_stun(broken, Counter(), stream=False) == [
            "stun-attributes"
        ]
        misplaced = STUN.decode(RFC5769_IPV4)
        moved = message(
            misplaced.attributes[-8:] + attr(0x8022, b"x"),
            0x0101,
            misplaced.transaction_id,
        )
        assert check_fixtures._check_stun(moved, Counter(), stream=False) == [
            "stun-fingerprint"
        ]

    def test_the_credential_is_the_published_one(self, check_fixtures):
        manifest = (FIXTURES / "MANIFEST.md").read_text()
        for value in (USERNAME, REALM, PASSWORD):
            assert f"`{value.decode()}`" in manifest
        assert (
            check_fixtures._STUN_USERNAME,
            check_fixtures._STUN_REALM,
            check_fixtures._STUN_PASSWORD,
        ) == (USERNAME, REALM, PASSWORD)
