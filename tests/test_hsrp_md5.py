"""Test the MD5 Authentication TLV after an HSRPv1 message.

Covered: the 50-byte message, its TLV's fields, round trips and walk,
the rule that decides when the TLV is read (exactly 50 bytes, Type 4 and
Length 28 at bytes 20 and 21) at every length, every Type and every
Length, that nothing in the TLV is judged, construction, equality, and
scripts/check_fixtures.py passing and counting such a message.

No sender that runs in a Linux netns produces the TLV, so there is no
capture: every vector here is HAND-BUILT, packed field by field with
struct and socket rather than by the library, in the layout of
Wireshark's epan/dissectors/packet-hsrp.c (commit 6f7207a6): the TLV
as its lines 100-121 draw it, a 1-byte Type and Length, a 1-byte
Algorithm and Padding, 2-byte Flags, the 4-byte sender's IP Address, a
4-byte Key ID and the 16-byte digest, read in that order and at those
widths by lines 320-344 and declared by lines 787-815; the Algorithm's
name from lines 313-317; the TLV looked for at byte 20 of a message
whose captured length is exactly 50, and read only when its Type is 4
and its Length 28, by lines 444-459. The tests check that each of the
VECTORS decodes to the fields packet-hsrp.c reads from it, alone and
wrapped in the frame udp_frame() builds.
"""

import importlib.util
import socket
import struct
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from netprotocols import (
    HSRP,
    UDP,
    Ethernet,
    HSRPv2,
    HSRPv2MD5Authentication,
    HSRPv2TextAuthentication,
    InvalidFieldError,
    IPv4,
    TruncatedHeaderError,
    decode_frame,
)

CHECKER = Path(__file__).resolve().parent.parent / "scripts/check_fixtures.py"


def md5_message(
    *,
    opcode: int = 0,
    state: int = 16,
    hellotime: int = 3,
    holdtime: int = 10,
    priority: int = 110,
    group: int = 1,
    auth_data: bytes = bytes(8),
    virtual_ip: str = "192.0.2.254",
    tlv_type: int = 4,
    tlv_length: int = 28,
    algorithm: int = 1,
    padding: int = 0,
    flags: int = 0,
    ip_address: str = "192.0.2.11",
    key_id: int = 1,
    digest: bytes = bytes(range(16)),
) -> bytes:
    """A HAND-BUILT 50-byte HSRPv1 message with an MD5 Authentication
    TLV, packed here: RFC 2281 §5.1's 20 bytes (Version 0 and a zero
    Reserved byte), then the TLV in packet-hsrp.c's order, Type and
    Length, Algorithm and Padding, the 2-byte Flags, the sender's
    address, the 4-byte Key ID and the 16-byte digest. The defaults are
    an Active Hello for group 1 with Authentication Data of 8 NUL
    bytes."""
    header = bytes([0, opcode, state, hellotime, holdtime, priority, group, 0])
    header += auth_data + socket.inet_aton(virtual_ip)
    tlv = struct.pack(
        "!BBBBH4sI",
        tlv_type,
        tlv_length,
        algorithm,
        padding,
        flags,
        socket.inet_aton(ip_address),
        key_id,
    )
    return header + tlv + digest


#: The HAND-BUILT vectors in packet-hsrp.c's layout, by name.
VECTORS = {
    "active_hello": md5_message(),
    "standby_hello": md5_message(
        state=8,
        priority=100,
        ip_address="192.0.2.12",
        digest=bytes(range(0xF0, 0x100)),
    ),
    "coup": md5_message(opcode=1, priority=200, key_id=7),
    "resign": md5_message(opcode=2, key_id=0xFFFFFFFF, digest=bytes(16)),
    "distinct": md5_message(
        opcode=0,
        state=4,
        hellotime=5,
        holdtime=15,
        priority=0x33,
        group=0x44,
        auth_data=b"np-hsrp\x00",
        virtual_ip="10.20.30.40",
        algorithm=0x77,
        padding=0x5A,
        flags=0xABCD,
        ip_address="198.51.100.9",
        key_id=0x01020304,
        digest=bytes(range(0xA0, 0xB0)),
    ),
}

#: Per vector, the Op Code and State names and the TLV's fields
#: packet-hsrp.c reads: Algorithm and its name, Padding, Flags, the
#: sender's IP Address, Key ID and digest.
EXPECTED = {
    "active_hello": (
        "Hello",
        "Active",
        (1, "MD5", 0, 0, "192.0.2.11", 1, bytes(range(16))),
    ),
    "standby_hello": (
        "Hello",
        "Standby",
        (1, "MD5", 0, 0, "192.0.2.12", 1, bytes(range(0xF0, 0x100))),
    ),
    "coup": (
        "Coup",
        "Active",
        (1, "MD5", 0, 0, "192.0.2.11", 7, bytes(range(16))),
    ),
    "resign": (
        "Resign",
        "Active",
        (1, "MD5", 0, 0, "192.0.2.11", 0xFFFFFFFF, bytes(16)),
    ),
    "distinct": (
        "Hello",
        "Speak",
        (
            0x77,
            "unknown (119)",
            0x5A,
            0xABCD,
            "198.51.100.9",
            0x01020304,
            bytes(range(0xA0, 0xB0)),
        ),
    ),
}

#: The default vector.
MESSAGE = VECTORS["active_hello"]

#: Where the message starts in the frames udp_frame() builds.
START = 14 + 20 + 8


def ones_complement(data: bytes) -> int:
    """The RFC 1071 checksum of ``data``, written out here."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def udp_frame(payload: bytes, *, udp_length: int | None = None) -> bytes:
    """``payload`` in Ethernet, IPv4 (192.0.2.11 to 224.0.0.2, TTL 1)
    and UDP from and to port 1985, every checksum computed here;
    ``udp_length`` overrides the UDP Length, the checksum then covering
    what it counts."""
    src, dst = socket.inet_aton("192.0.2.11"), socket.inet_aton("224.0.0.2")
    length = 8 + len(payload) if udp_length is None else udp_length
    udp = struct.pack("!HHHH", 1985, 1985, length, 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 17, length)
    checksum = ones_complement(pseudo + udp[:length]) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", checksum) + udp[8:]
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0xC0, 20 + len(udp), 0, 0, 1, 17, 0, src, dst
    )
    ip = ip[:10] + struct.pack("!H", ones_complement(ip)) + ip[12:]
    return bytes.fromhex("01005e000002 02000a09c30b 0800") + ip + udp


def changed(raw: bytes, position: int, value: int) -> bytes:
    """``raw`` with the byte at ``position`` set to ``value``."""
    return raw[:position] + bytes([value]) + raw[position + 1 :]


@pytest.fixture(scope="module")
def check_fixtures():
    """Load scripts/check_fixtures.py, which shares no library code."""
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- The hand-built vectors -------------------------------------------


class TestVectors:
    @pytest.mark.parametrize("name", VECTORS)
    def test_each_decodes_to_what_packet_hsrp_c_reads(self, name):
        raw = VECTORS[name]
        assert len(raw) == 50
        hsrp = HSRP.decode(raw)
        opcode, state, fields = EXPECTED[name]
        assert (hsrp.opcode_name, hsrp.state_name) == (opcode, state)
        md5 = hsrp.md5_authentication
        assert isinstance(md5, HSRPv2MD5Authentication)
        assert (
            md5.algorithm,
            md5.algorithm_name,
            md5.padding,
            md5.flags,
            md5.ip_address,
            md5.key_id,
            md5.digest,
        ) == fields

    @pytest.mark.parametrize("name", VECTORS)
    def test_each_field_at_packet_hsrp_c_s_offset_and_width(self, name):
        """Lines 320-344: the Type at byte 20, the Length at 21, then
        the Algorithm (1 byte), Padding (1), Flags (2), IP Address (4),
        Key ID (4) and digest (16), unpacked here independently."""
        raw = VECTORS[name]
        kind, length, algorithm, padding, flags = struct.unpack_from(
            "!BBBBH", raw, 20
        )
        address, key_id = struct.unpack_from("!4sI", raw, 26)
        md5 = HSRP.decode(raw).md5_authentication
        assert (kind, length) == (4, 28)
        assert (md5.algorithm, md5.padding, md5.flags) == (
            algorithm,
            padding,
            flags,
        )
        assert md5.ip_address == socket.inet_ntoa(address)
        assert md5.key_id == key_id
        assert md5.digest == raw[34:50]

    @pytest.mark.parametrize("name", VECTORS)
    def test_each_round_trips_all_50_bytes(self, name):
        raw = VECTORS[name]
        hsrp = HSRP.decode(raw)
        assert hsrp.header_len == 50
        assert bytes(hsrp) == raw
        assert bytes(hsrp.md5_authentication) == raw[20:]
        assert HSRP.decode(bytes(hsrp)) == hsrp

    @pytest.mark.parametrize("name", VECTORS)
    def test_the_20_bytes_decode_as_without_the_tlv(self, name):
        """The TLV changes no field of the message before it."""
        raw = VECTORS[name]
        hsrp = HSRP.decode(raw)
        assert replace(hsrp, md5_authentication=None) == HSRP.decode(raw[:20])

    @pytest.mark.parametrize("name", VECTORS)
    def test_each_walks_to_one_50_byte_layer(self, name):
        frame = udp_frame(VECTORS[name])
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP, HSRP]
        assert packet.stopped_by is None
        assert packet.consumed == len(frame) == START + 50
        assert packet[HSRP] == HSRP.decode(VECTORS[name])
        assert bytes(packet) == frame

    def test_the_same_tlv_as_hsrpv2_s(self):
        """packet-hsrp.c reads both with one function (lines 320-344):
        the 30 bytes after an HSRPv2 Group State TLV decode to the same
        record as after an HSRPv1 message's 20 bytes."""
        group_state = (
            bytes.fromhex("01280200060400010200 0a09c30b 00000064")
            + bytes.fromhex("00000bb8 00002710 c00002fe")
            + bytes(12)
        )
        v2 = HSRPv2.decode(group_state + MESSAGE[20:])
        assert v2.md5_authentication == HSRP.decode(MESSAGE).md5_authentication

    def test_the_authentication_data_is_kept_raw_beside_it(self):
        """The 8-byte Authentication Data is decoded as in any message,
        all NUL bytes or a password."""
        hsrp = HSRP.decode(MESSAGE)
        assert (hsrp.auth_data, hsrp.password) == (bytes(8), b"")
        assert (hsrp.auth_data_str, hsrp.is_default_auth) == ("", False)
        cisco = HSRP.decode(md5_message(auth_data=b"cisco\x00\x00\x00"))
        assert cisco.is_default_auth
        assert cisco.md5_authentication == hsrp.md5_authentication


# --- When the TLV is read ---------------------------------------------


class TestTheFiftyByteRule:
    @pytest.mark.parametrize("length", range(20))
    def test_shorter_than_20_bytes_is_truncated(self, length):
        with pytest.raises(TruncatedHeaderError) as caught:
            HSRP.decode(MESSAGE[:length])
        assert (caught.value.expected, caught.value.actual) == (20, length)

    @pytest.mark.parametrize("length", range(20, 50))
    def test_a_cut_tlv_is_left_outside(self, length):
        """20 to 49 bytes: the message is the 20, the rest undecoded."""
        hsrp = HSRP.decode(MESSAGE[:length])
        assert hsrp.md5_authentication is None
        assert hsrp.header_len == 20
        assert bytes(hsrp) == MESSAGE[:20]

    @pytest.mark.parametrize(
        "tail",
        [
            pytest.param(b"\x00", id="51-bytes"),
            pytest.param(b"\xde\xad\xbe\xef", id="fcs"),
            pytest.param(MESSAGE[20:], id="two-tlvs"),
        ],
    )
    def test_a_longer_buffer_leaves_the_tlv_outside(self, tail):
        """Only a buffer of exactly 50 bytes has the TLV read."""
        hsrp = HSRP.decode(MESSAGE + tail)
        assert hsrp.md5_authentication is None
        assert hsrp.header_len == 20

    @pytest.mark.parametrize("kind", [k for k in range(256) if k != 4])
    def test_any_other_type_is_left_outside(self, kind):
        """A 50-byte buffer whose byte 20 is not 4 decodes to 20 bytes,
        without an error, as packet-hsrp.c reports an unknown TLV
        sequence and goes on (lines 455-458)."""
        hsrp = HSRP.decode(changed(MESSAGE, 20, kind))
        assert hsrp.md5_authentication is None
        assert hsrp.header_len == 20
        assert hsrp == HSRP.decode(MESSAGE[:20])

    @pytest.mark.parametrize("length", [n for n in range(256) if n != 28])
    def test_type_4_of_any_other_length_is_left_outside(self, length):
        """Type 4 with a Length other than 28 is not read either, and
        raises nothing."""
        hsrp = HSRP.decode(changed(MESSAGE, 21, length))
        assert hsrp.md5_authentication is None
        assert hsrp.header_len == 20

    def test_nothing_in_the_tlv_is_judged(self):
        """Past the Type and Length, any value of every byte decodes."""
        raw = MESSAGE[:22] + b"\xff" * 28
        md5 = HSRP.decode(raw).md5_authentication
        assert (md5.algorithm, md5.padding, md5.flags) == (255, 255, 0xFFFF)
        assert (md5.ip_address, md5.key_id) == ("255.255.255.255", 2**32 - 1)
        assert md5.algorithm_name == "unknown (255)"
        assert bytes(HSRP.decode(raw)) == raw

    @pytest.mark.parametrize(
        "position,value,field",
        [(0, 2, "version"), (1, 3, "opcode"), (2, 3, "state")],
    )
    def test_the_guard_still_judges_the_20_bytes(self, position, value, field):
        """A 50-byte buffer is rejected as its first 20 bytes are."""
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(changed(MESSAGE, position, value))
        assert caught.value.field == field

    def test_memoryview_input_is_not_retained(self):
        buffer = bytearray(MESSAGE)
        hsrp = HSRP.decode(memoryview(buffer))
        buffer[20:] = bytes(30)
        assert isinstance(hsrp.md5_authentication.digest, bytes)
        assert hsrp == HSRP.decode(MESSAGE)


class TestWalk:
    def test_an_fcs_after_the_datagram_is_the_trailer(self):
        """The walk ends HSRP's buffer at the UDP Length, so an FCS after
        the frame does not make the message 54 bytes."""
        frame = udp_frame(MESSAGE) + b"\xde\xad\xbe\xef"
        packet = decode_frame(frame)
        assert packet[HSRP].md5_authentication is not None
        assert packet.consumed == START + 50
        assert packet.trailer == b"\xde\xad\xbe\xef"

    def test_a_udp_length_of_49_leaves_the_tlv_outside(self):
        """HSRP is handed the 49 bytes the UDP Length gives, so the
        TLV is not read, and the byte past the Length is the trailer."""
        frame = udp_frame(MESSAGE, udp_length=8 + 49)
        packet = decode_frame(frame)
        assert packet[HSRP].md5_authentication is None
        assert packet.consumed == START + 20
        assert packet.trailer == MESSAGE[49:]

    def test_a_udp_length_of_50_bounds_a_longer_payload(self):
        """A 51-byte payload under a UDP Length of 58 is a 50-byte
        message, its last byte the trailer."""
        frame = udp_frame(MESSAGE + b"\x00", udp_length=8 + 50)
        packet = decode_frame(frame)
        assert packet[HSRP].md5_authentication is not None
        assert packet.consumed == START + 50
        assert packet.trailer == b"\x00"


# --- Construction -----------------------------------------------------


def _record() -> HSRPv2MD5Authentication:
    return HSRPv2MD5Authentication(1, 0, 0, "192.0.2.11", 1, bytes(16))


class TestConstruction:
    def test_positional_construction_without_it(self):
        """The ten wire fields alone build a message without the TLV."""
        hsrp = HSRP(0, 0, 16, 3, 10, 110, 1, 0, bytes(8), "192.0.2.254")
        assert hsrp.md5_authentication is None
        assert bytes(hsrp) == MESSAGE[:20]
        assert hsrp.header_len == 20

    def test_build_one_with_the_tlv(self):
        md5 = HSRPv2MD5Authentication(
            algorithm=1,
            padding=0,
            flags=0,
            ip_address="192.0.2.11",
            key_id=1,
            digest=bytes(range(16)),
        )
        hsrp = HSRP(0, 0, 16, 3, 10, 110, 1, 0, bytes(8), "192.0.2.254", md5)
        assert bytes(hsrp) == MESSAGE
        assert hsrp.header_len == 50
        assert HSRP.decode(bytes(hsrp)) == hsrp
        assert decode_frame(udp_frame(bytes(hsrp)))[HSRP] == hsrp

    def test_replace_drops_or_adds_it(self):
        hsrp = HSRP.decode(MESSAGE)
        bare = replace(hsrp, md5_authentication=None)
        assert bytes(bare) == MESSAGE[:20]
        assert replace(bare, md5_authentication=_record()).header_len == 50

    @pytest.mark.parametrize(
        "value",
        [
            pytest.param(MESSAGE[20:], id="bytes"),
            pytest.param(HSRPv2TextAuthentication(bytes(8)), id="text-tlv"),
            pytest.param(0, id="int"),
        ],
    )
    def test_anything_but_the_record_or_none_is_refused(self, value):
        with pytest.raises(InvalidFieldError) as caught:
            replace(HSRP.decode(MESSAGE[:20]), md5_authentication=value)
        assert (caught.value.protocol, caught.value.field) == (
            HSRP,
            "md5_authentication",
        )

    def test_equality_and_the_hash_include_it(self):
        with_tlv = HSRP.decode(MESSAGE)
        bare = HSRP.decode(MESSAGE[:20])
        other = HSRP.decode(changed(MESSAGE, 49, 0xFF))
        assert with_tlv != bare
        assert with_tlv != other
        assert len({with_tlv, bare, other, HSRP.decode(MESSAGE)}) == 3

    def test_positional_patterns_bind_it_last(self):
        match HSRP.decode(MESSAGE):
            case HSRP(0, 0, 16, 3, 10, 110, 1, 0, _, vip, md5):
                assert vip == "192.0.2.254"
                assert md5.key_id == 1
            case _:
                pytest.fail("positional pattern did not match")

    def test_a_ten_field_positional_pattern_still_matches(self):
        """A pattern of the ten wire fields matches a message carrying
        the TLV, which is bound by no position."""
        match HSRP.decode(MESSAGE):
            case HSRP(0, 0, 16, 3, 10, 110, 1, 0, _, vip):
                assert vip == "192.0.2.254"
            case _:
                pytest.fail("ten-field positional pattern did not match")


# --- scripts/check_fixtures.py ----------------------------------------


class TestChecker:
    @pytest.mark.parametrize("name", [n for n in VECTORS if n != "distinct"])
    def test_each_vector_passes_and_counts(self, check_fixtures, name):
        stats: Counter[str] = check_fixtures.Counter()
        assert check_fixtures.check_frame(udp_frame(VECTORS[name]), stats) == []
        assert (stats["hsrp"], stats["hsrp-md5"]) == (1, 1)

    def test_a_message_without_it_does_not_count(self, check_fixtures):
        stats: Counter[str] = check_fixtures.Counter()
        assert check_fixtures.check_frame(udp_frame(MESSAGE[:20]), stats) == []
        assert (stats["hsrp"], stats["hsrp-md5"]) == (1, 0)

    def test_the_distinct_vector_fails_its_algorithm(self, check_fixtures):
        """Its Algorithm, 0x77, is not MD5's 1; the digest is never
        judged."""
        frame = udp_frame(VECTORS["distinct"])
        assert check_fixtures.check_frame(frame, Counter()) == [
            "hsrp-md5-algorithm"
        ]
