"""Test HSRP interface-state Advertise decoding and dispatch.

Covered: the 16-byte Advertise, both TLV Types and all three States, its
round trips, truncation at every length, what follows it in the buffer,
the decode-time guard (every judged field at any length, the other
fields not judged), construction, the display helpers, and dispatch:
UDP port 1985 choosing HSRP, HSRPv2 or HSRPAdvertise by the first two
bytes, which UDP keeps as decode context.

No sender that runs in a Linux netns produces an Advertise, so there is
no capture: every vector here is HAND-BUILT, packed field by field with
struct rather than by the library, in the layout of Wireshark's
epan/dissectors/packet-hsrp.c (commit 6f7207a6): the message as its
lines 27-37 draw it, Version, Op Code 3, then a 2-byte TLV Type, a
2-byte TLV Length, a 1-byte State, a Reserved byte, 2-byte Active and
Passive Group Counts and 4 Reserved bytes, read in that order and at
those widths by lines 425-439 and declared by lines 662-695; the Op
Code's name from lines 235-240, the TLV Types' from lines 260-266, the
States' from lines 268-275, the State read at byte 6 by lines 382-385,
and the counts' range, 0-256, from lines 39-47. The tests check that
each of the VECTORS decodes to the fields packet-hsrp.c reads from it,
alone and wrapped in the frame udp_frame() builds.
"""

import socket
import struct
from dataclasses import replace

import pytest

from netprotocols import (
    HSRP,
    UDP,
    Ethernet,
    HSRPAdvertise,
    HSRPv2,
    InvalidFieldError,
    IPv4,
    TruncatedHeaderError,
    decode_frame,
)


def advertise(
    *,
    version: int = 0,
    opcode: int = 3,
    tlv_type: int = 1,
    tlv_length: int = 14,
    state: int = 2,
    reserved1: int = 0,
    active: int = 1,
    passive: int = 0,
    reserved2: int = 0,
) -> bytes:
    """A HAND-BUILT Advertise, packed here in packet-hsrp.c's order:
    Version and Op Code, one byte each, the 2-byte TLV Type and TLV
    Length, the State and a Reserved byte, the 2-byte Active and Passive
    Group Counts and 4 Reserved bytes. The defaults are a Passive
    interface with 1 active group and no passive one, TLV Type 1 (HSRP
    interface state) and a TLV Length of 14, the bytes from the TLV Type
    to the end."""
    return bytes([version, opcode]) + struct.pack(
        "!HHBBHHI",
        tlv_type,
        tlv_length,
        state,
        reserved1,
        active,
        passive,
        reserved2,
    )


#: The HAND-BUILT vectors in packet-hsrp.c's layout, by name.
VECTORS = {
    "interface_passive": advertise(),
    "interface_dormant": advertise(state=1, active=0, passive=3),
    "interface_active": advertise(state=3, active=256, passive=256),
    "ip_redundancy": advertise(tlv_type=2, state=3, active=2, passive=1),
}

#: Per vector, the fields packet-hsrp.c reads: TLV Type and its name,
#: TLV Length, State and its name, Active and Passive Group Counts.
EXPECTED = {
    "interface_passive": (1, "HSRP interface state", 14, 2, "Passive", 1, 0),
    "interface_dormant": (1, "HSRP interface state", 14, 1, "Dormant", 0, 3),
    "interface_active": (1, "HSRP interface state", 14, 3, "Active", 256, 256),
    "ip_redundancy": (2, "IP redundancy", 14, 3, "Active", 2, 1),
}

#: The default Advertise.
ADVERTISE = VECTORS["interface_passive"]

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


def udp_frame(
    payload: bytes,
    *,
    src_port: int = 1985,
    dst_port: int = 1985,
    udp_length: int | None = None,
) -> bytes:
    """``payload`` in Ethernet, IPv4 (192.0.2.11 to 224.0.0.2, TTL 1)
    and UDP, every checksum computed here; ``udp_length`` overrides the
    UDP Length, the checksum then covering what it counts."""
    src, dst = socket.inet_aton("192.0.2.11"), socket.inet_aton("224.0.0.2")
    length = 8 + len(payload) if udp_length is None else udp_length
    udp = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
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


# --- The hand-built vectors -------------------------------------------


class TestVectors:
    """Each vector's fields, as packet-hsrp.c reads them."""

    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_decodes_to_its_fields(self, name):
        message = HSRPAdvertise.decode(VECTORS[name])
        assert (message.version, message.opcode) == (0, 3)
        assert message.opcode_name == "Advertise"
        assert (
            message.tlv_type,
            message.tlv_type_name,
            message.tlv_length,
            message.state,
            message.state_name,
            message.active_groups,
            message.passive_groups,
        ) == EXPECTED[name]
        assert (message.reserved1, message.reserved2) == (0, 0)

    def test_conftests_advertise_is_the_first_vector(self, raw_hsrp_advertise):
        assert raw_hsrp_advertise == ADVERTISE

    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_round_trips(self, name):
        raw = VECTORS[name]
        message = HSRPAdvertise.decode(raw)
        assert bytes(message) == raw
        assert message.header_len == len(raw) == 16
        assert HSRPAdvertise.decode(bytes(message)) == message
        assert HSRPAdvertise.decode(memoryview(raw)) == message

    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_walks_to_hsrp_advertise(self, name):
        """Ethernet/IPv4/UDP 1985 ends in an HSRPAdvertise layer that
        takes the rest of the frame."""
        raw = VECTORS[name]
        frame = udp_frame(raw)
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [
            Ethernet,
            IPv4,
            UDP,
            HSRPAdvertise,
        ]
        assert packet[HSRPAdvertise] == HSRPAdvertise.decode(raw)
        assert packet.consumed == len(frame)
        assert packet.stopped_by is None

    def test_the_layout(self):
        """Each field at packet-hsrp.c's offset and width: a distinct
        value in every one."""
        raw = advertise(
            tlv_type=2,
            tlv_length=0x0A0B,
            state=3,
            reserved1=0x0C,
            active=0x0D0E,
            passive=0x0F10,
            reserved2=0x11121314,
        )
        assert raw == bytes.fromhex("0003 0002 0a0b 03 0c 0d0e 0f10 11121314")
        message = HSRPAdvertise.decode(raw)
        assert (
            message.tlv_type,
            message.tlv_length,
            message.state,
            message.reserved1,
            message.active_groups,
            message.passive_groups,
            message.reserved2,
        ) == (2, 0x0A0B, 3, 0x0C, 0x0D0E, 0x0F10, 0x11121314)
        assert bytes(message) == raw


class TestDecode:
    @pytest.mark.parametrize(
        "trailer",
        [
            pytest.param(b"\xde\xad\xbe\xef", id="fcs"),
            pytest.param(bytes(30), id="zeros"),
            pytest.param(b"\x04\x1c" + bytes(28), id="md5-tlv"),
        ],
    )
    def test_what_follows_is_left_undecoded(self, trailer):
        message = HSRPAdvertise.decode(ADVERTISE + trailer)
        assert message == HSRPAdvertise.decode(ADVERTISE)
        assert message.header_len == 16
        assert bytes(message) == ADVERTISE

    def test_a_walk_leaves_what_follows_in_the_datagram(self):
        """Bytes after the 16 inside the UDP datagram are past
        ``consumed``; an FCS after it is the trailer."""
        frame = udp_frame(ADVERTISE + bytes(4)) + b"\xde\xad\xbe\xef"
        packet = decode_frame(frame)
        assert packet[HSRPAdvertise] == HSRPAdvertise.decode(ADVERTISE)
        assert packet.consumed == START + 16
        assert packet.trailer == b"\xde\xad\xbe\xef"

    def test_hsrp_advertise_ends_the_chain(self):
        assert HSRPAdvertise.decode(ADVERTISE).next_protocol() is None

    def test_hsrp_decoded_directly_names_hsrp_advertise(self):
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(ADVERTISE)
        error = caught.value
        assert (error.protocol, error.field, error.offset, error.actual) == (
            HSRP,
            "opcode",
            1,
            3,
        )
        assert "decode it with HSRPAdvertise" in str(error)
        assert "not decoded" not in str(error)


#: Each judged field, its offset, and values decode rejects, as the
#: bytes of the message that hold it.
REJECTED = [
    ("version", 0, "0", [1, 2, 0x80, 0xFF]),
    ("opcode", 1, "3", [0, 1, 2, 4, 0xFF]),
    ("tlv_type", 2, "1 or 2", [0, 3, 0x0100, 0x0101, 0xFFFF]),
    ("state", 6, "1-3", [0, 4, 0x10, 0xFF]),
]


def with_value(field: str, offset: int, value: int) -> bytes:
    """ADVERTISE with ``value`` in the field at ``offset``."""
    if field == "tlv_type":
        return ADVERTISE[:2] + struct.pack("!H", value) + ADVERTISE[4:]
    return changed(ADVERTISE, offset, value)


class TestDecodeGuard:
    """The Version, Op Code, TLV Type and State, judged before the
    length."""

    @pytest.mark.parametrize("field,offset,expected,values", REJECTED)
    @pytest.mark.parametrize("length", [None, 16, 40])
    def test_each_judged_field_at_any_length(
        self, field, offset, expected, values, length
    ):
        """At its own length (``None``: cut just after it), the 16
        bytes, or with more after them."""
        width = 2 if field == "tlv_type" else 1
        for value in values:
            raw = with_value(field, offset, value) + bytes(24)
            raw = raw[: offset + width] if length is None else raw[:length]
            with pytest.raises(InvalidFieldError) as caught:
                HSRPAdvertise.decode(raw)
            error = caught.value
            assert error.protocol is HSRPAdvertise
            assert (error.field, error.offset) == (field, offset)
            assert (error.expected, error.actual) == (expected, value)

    def test_the_tlv_type_is_judged_once_both_its_bytes_are_there(self):
        """A first byte of 0 could still be 1 or 2."""
        with pytest.raises(TruncatedHeaderError):
            HSRPAdvertise.decode(bytes([0, 3, 0]))
        with pytest.raises(InvalidFieldError) as caught:
            HSRPAdvertise.decode(bytes([0, 3, 0, 0]))
        assert caught.value.field == "tlv_type"

    def test_the_rejections_name_the_class_that_decodes_them(self):
        """A Version of 1 opens HSRPv2, and Op Codes 0-2 are HSRPv1's
        Hello, Coup and Resign; other values name nothing."""
        for raw, hint in [
            (b"\x01", "decode it with HSRPv2"),
            (b"\x00\x00", "Hello: decode it with HSRP"),
            (b"\x00\x01", "Coup: decode it with HSRP"),
            (b"\x00\x02", "Resign: decode it with HSRP"),
        ]:
            with pytest.raises(InvalidFieldError, match=hint):
                HSRPAdvertise.decode(raw)
        for raw in (b"\x02", b"\x00\x04", b"\x00\x03\x00\x03"):
            with pytest.raises(InvalidFieldError) as caught:
                HSRPAdvertise.decode(raw)
            assert "decode it with" not in str(caught.value)

    @pytest.mark.parametrize("cut", range(16))
    def test_every_truncation_of_a_valid_advertise(self, cut):
        """Every judged field passes, so a cut anywhere in the 16 bytes
        is a truncated header."""
        with pytest.raises(TruncatedHeaderError) as caught:
            HSRPAdvertise.decode(ADVERTISE[:cut])
        error = caught.value
        assert error.protocol is HSRPAdvertise
        assert (error.expected, error.actual) == (16, cut)

    def test_exactly_the_documented_values_pass(self):
        """1 Version, 1 Op Code, 2 TLV Types and 3 States, each field
        judged alone: 6 of the 2**40 values of those five bytes."""

        def passes(raw: bytes) -> bool:
            try:
                HSRPAdvertise.decode(raw)
            except InvalidFieldError:
                return False
            return True

        accepted = {
            field: [
                value
                for value in range(1 << (16 if field == "tlv_type" else 8))
                if passes(with_value(field, offset, value))
            ]
            for field, offset, _, _ in REJECTED
        }
        assert accepted == {
            "version": [0],
            "opcode": [3],
            "tlv_type": [1, 2],
            "state": [1, 2, 3],
        }

    def test_the_other_fields_are_not_judged(self):
        """Any TLV Length, Reserved fields and counts decode, the counts
        past packet-hsrp.c's 0-256 included."""
        raw = ADVERTISE[:4] + b"\xff\xff" + ADVERTISE[6:7] + b"\xff" * 9
        message = HSRPAdvertise.decode(raw)
        assert message.tlv_length == 0xFFFF
        assert message.reserved1 == 0xFF
        assert message.active_groups == message.passive_groups == 0xFFFF
        assert message.reserved2 == 0xFFFFFFFF
        assert bytes(message) == raw


# --- Construction and display -----------------------------------------


#: Each integer field and its width in bits.
WIDTHS = [
    ("version", 8),
    ("opcode", 8),
    ("tlv_type", 16),
    ("tlv_length", 16),
    ("state", 8),
    ("reserved1", 8),
    ("active_groups", 16),
    ("passive_groups", 16),
    ("reserved2", 32),
]


class TestConstruction:
    def test_construction_matches_decode(self):
        built = HSRPAdvertise(
            version=0,
            opcode=3,
            tlv_type=1,
            tlv_length=14,
            state=2,
            reserved1=0,
            active_groups=1,
            passive_groups=0,
            reserved2=0,
        )
        assert built == HSRPAdvertise.decode(ADVERTISE)
        assert bytes(built) == ADVERTISE

    @pytest.mark.parametrize("field,bits", WIDTHS)
    def test_a_field_out_of_range(self, field, bits):
        message = HSRPAdvertise.decode(ADVERTISE)
        for value in (-1, 1 << bits):
            with pytest.raises(InvalidFieldError) as caught:
                replace(message, **{field: value})
            error = caught.value
            assert error.protocol is HSRPAdvertise
            assert (error.field, error.actual) == (field, value)
            assert error.expected == f"0-{(1 << bits) - 1}"
        top = replace(message, **{field: (1 << bits) - 1})
        assert getattr(top, field) == (1 << bits) - 1

    @pytest.mark.parametrize(
        "fields,field",
        [
            ({"version": 1}, "version"),
            ({"opcode": 0}, "opcode"),
            ({"tlv_type": 3}, "tlv_type"),
            ({"state": 0}, "state"),
        ],
    )
    def test_construction_accepts_what_decode_rejects(self, fields, field):
        built = replace(HSRPAdvertise.decode(ADVERTISE), **fields)
        with pytest.raises(InvalidFieldError) as caught:
            HSRPAdvertise.decode(bytes(built))
        assert caught.value.field == field


class TestDisplay:
    @pytest.mark.parametrize(
        "opcode,name",
        [
            (0, "Hello"),
            (1, "Coup"),
            (2, "Resign"),
            (3, "Advertise"),
            (4, "unknown (4)"),
            (255, "unknown (255)"),
        ],
    )
    def test_every_opcode_is_named(self, opcode, name):
        """packet-hsrp.c's four Op Code names."""
        message = replace(HSRPAdvertise.decode(ADVERTISE), opcode=opcode)
        assert message.opcode_name == name

    @pytest.mark.parametrize(
        "tlv_type,name",
        [
            (1, "HSRP interface state"),
            (2, "IP redundancy"),
            (0, "unknown (0)"),
            (3, "unknown (3)"),
            (0xFFFF, "unknown (65535)"),
        ],
    )
    def test_every_tlv_type_is_named(self, tlv_type, name):
        message = replace(HSRPAdvertise.decode(ADVERTISE), tlv_type=tlv_type)
        assert message.tlv_type_name == name

    @pytest.mark.parametrize(
        "state,name",
        [
            (1, "Dormant"),
            (2, "Passive"),
            (3, "Active"),
            (0, "unknown (0)"),
            (16, "unknown (16)"),
        ],
    )
    def test_every_state_is_named(self, state, name):
        message = replace(HSRPAdvertise.decode(ADVERTISE), state=state)
        assert message.state_name == name


# --- Dispatch ---------------------------------------------------------


class TestDispatch:
    def test_hsrp_chooses_by_the_first_two_bytes(self):
        """00 03 names HSRPAdvertise, a first byte of 1 HSRPv2, and
        every other pair is left to HSRP."""
        for first in range(256):
            for second in range(256):
                lead = first << 8 | second
                if (first, second) == (0, 3):
                    expected = HSRPAdvertise
                elif first == 1:
                    expected = HSRPv2
                else:
                    expected = HSRP
                assert HSRP._for_payload(lead) is expected
        assert HSRPAdvertise._for_payload(0x0003) is HSRPAdvertise

    @pytest.mark.parametrize(
        "src_port,dst_port", [(1985, 1985), (40000, 1985), (1985, 40000)]
    )
    def test_port_1985_reaches_hsrp_advertise(self, src_port, dst_port):
        frame = udp_frame(ADVERTISE, src_port=src_port, dst_port=dst_port)
        assert decode_frame(frame)[HSRPAdvertise] == HSRPAdvertise.decode(
            ADVERTISE
        )

    def test_decode_as_carries_the_choice(self):
        """HSRP named for another port chooses HSRPAdvertise there too."""
        frame = udp_frame(ADVERTISE, src_port=40000, dst_port=40001)
        assert [type(layer) for layer in decode_frame(frame)][-1] is UDP
        packet = decode_frame(frame, decode_as={"udp.port": {40001: HSRP}})
        assert packet[HSRPAdvertise] == HSRPAdvertise.decode(ADVERTISE)

    @pytest.mark.parametrize("cut", [2, 3, 7, 15])
    def test_a_short_advertise_is_truncated_in_a_walk(self, cut):
        """A datagram opening with 00 03 is an Advertise, however short."""
        packet = decode_frame(udp_frame(ADVERTISE[:cut]), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        error = packet.stopped_by
        assert isinstance(error, TruncatedHeaderError)
        assert error.protocol is HSRPAdvertise
        assert error.frame_offset == START

    def test_a_judged_field_failing_in_a_walk(self):
        """A bad State after 00 03 is HSRPAdvertise's error, at its
        byte of the frame."""
        frame = udp_frame(changed(ADVERTISE, 6, 9))
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(frame)
        error = caught.value
        assert (error.protocol, error.field) == (HSRPAdvertise, "state")
        assert error.frame_offset == START + 6

    def test_a_one_byte_datagram_goes_to_hsrp(self):
        """With no second byte, 00 is HSRP's, which needs 20 bytes."""
        packet = decode_frame(udp_frame(b"\x00"), lax=True)
        assert packet.stopped_by.protocol is HSRP
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    def test_a_second_byte_past_the_udp_length_is_not_read(self):
        """A UDP Length of 9 ends the payload after 00, so a 03 after it
        in the frame does not make an Advertise."""
        frame = udp_frame(b"\x00\x03" + bytes(20), udp_length=9)
        packet = decode_frame(frame, lax=True)
        assert packet[UDP]._lead == 0x0000
        assert packet.stopped_by.protocol is HSRP
        assert packet.trailer == b"\x03" + bytes(20)

    def test_hsrpv1_on_port_1985_is_unchanged(self):
        hello = bytes.fromhex("000004030a640100636973636f000000c0000201")
        packet = decode_frame(udp_frame(hello))
        assert packet[HSRP] == HSRP.decode(hello)

    def test_op_code_4_is_still_rejected_by_hsrp(self):
        frame = udp_frame(changed(ADVERTISE, 1, 4))
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(frame)
        error = caught.value
        assert (error.protocol, error.field) == (HSRP, "opcode")
        assert error.frame_offset == START + 1
