"""LLDP, the Link Layer Discovery Protocol (IEEE 802.1AB), EtherType 0x88CC.

The captured frames in ``lldp.pcap`` were built by lldpd 1.0.18 (see
``tests/fixtures/MANIFEST.md``): they cover the Chassis ID subtypes 4
and 7, the Port ID subtypes 3, 5 and 7, three TTLs and three shutdown
LLDPDUs, and a 304-byte organizationally specific TLV whose Length
needs the 9th bit. Every TLV type and length the corpus does not reach
— a 511-byte value, odd types, the reserved range, a value cut short,
an LLDPDU with no End TLV, malformed mandatory TLVs — is built here.
``scripts/check_fixtures.py``, which shares no code with the library,
is run over the corpus and over tampered copies of it.
"""

import gc
import importlib.util
import struct
import sys
import time
from collections import Counter
from pathlib import Path
from types import ModuleType

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    LLDP,
    LLDPTLV,
    VLAN,
    Ethernet,
    EtherType,
    InvalidFieldError,
    LLDPChassisID,
    LLDPPortID,
    ProtocolError,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_ETHERTYPE

FRAMES = pcap_frames(FIXTURES / "lldp.pcap")
LLDPDUS = [frame[14:] for frame in FRAMES]

MAC_A = bytes.fromhex("024e5086000a")
MAC_B = bytes.fromhex("024e5086000b")

#: The TLV types of lldpd's full LLDPDUs and of a shutdown LLDPDU.
FULL = (1, 2, 3, 5, 6, 7, 8, 4, 127, 127, 0)
FULL_CUSTOM = (1, 2, 3, 5, 6, 7, 8, 4, 127, 127, 127, 0)
SHUTDOWN = (1, 2, 3, 0)

#: lldpd's custom-tlv on agent A: OUI 0a-4e-50, subtype 1, 300 bytes.
CUSTOM = b"\x0a\x4e\x50\x01" + bytes(i % 256 for i in range(300))


def tlv_bytes(tlv_type: int, value: bytes = b"") -> bytes:
    """Build a TLV's wire form by hand, independently of LLDPTLV."""
    return struct.pack("!H", (tlv_type << 9) | len(value)) + value


#: A minimal well-formed LLDPDU, built by hand: Chassis ID (MAC
#: address), Port ID (interface name), TTL 120, End of LLDPDU.
MINIMAL = (
    tlv_bytes(1, b"\x04" + MAC_A)
    + tlv_bytes(2, b"\x05eth0")
    + tlv_bytes(3, b"\x00\x78")
    + tlv_bytes(0)
)


class TestCapturedLLDPDUs:
    """The six LLDPDUs lldpd sent, decoded field by field."""

    def test_each_frame_dispatches_to_lldp(self):
        """Walk every frame to Ethernet then LLDP, consuming it all."""
        for frame in FRAMES:
            packet = decode_frame(frame)
            assert [type(layer) for layer in packet] == [Ethernet, LLDP]
            assert packet.consumed == len(frame)
            assert packet[0].ethertype == EtherType.LLDP
            assert packet[0].ethertype_name == "LLDP"

    @pytest.mark.parametrize(
        "index,chassis,port,ttl,types",
        [
            (0, (4, MAC_A), (5, b"nplldp-va"), 120, FULL_CUSTOM),
            (1, (7, b"nplldp-chassis-b"), (3, MAC_B), 180, FULL),
            (2, (4, MAC_A), (5, b"nplldp-va"), 0, SHUTDOWN),
            (3, (4, MAC_A), (7, b"np-port-a"), 120, FULL_CUSTOM),
            (4, (4, MAC_A), (7, b"np-port-a"), 0, SHUTDOWN),
            (5, (7, b"nplldp-chassis-b"), (3, MAC_B), 0, SHUTDOWN),
        ],
    )
    def test_fields(self, index, chassis, port, ttl, types):
        """Read the typed mandatory TLVs and the TLV types of each frame."""
        lldp = LLDP.decode(LLDPDUS[index])
        assert lldp.chassis_id == LLDPChassisID(*chassis)
        assert lldp.port_id == LLDPPortID(*port)
        assert lldp.ttl == ttl
        assert lldp.is_shutdown is (ttl == 0)
        assert lldp.has_mandatory_tlvs
        assert tuple(tlv.type for tlv in lldp.tlvs) == types
        assert lldp.tlvs[-1] == LLDPTLV(0)
        assert lldp.header_len == len(LLDPDUS[index])

    def test_subtype_names(self):
        """Name each captured identifier's subtype."""
        a, b = LLDP.decode(LLDPDUS[0]), LLDP.decode(LLDPDUS[1])
        local = LLDP.decode(LLDPDUS[3])
        assert a.chassis_id is not None and a.port_id is not None
        assert b.chassis_id is not None and b.port_id is not None
        assert local.port_id is not None
        assert a.chassis_id.subtype_name == "MAC address"
        assert a.port_id.subtype_name == "Interface name"
        assert b.chassis_id.subtype_name == "Locally assigned"
        assert b.port_id.subtype_name == "MAC address"
        assert local.port_id.subtype_name == "Locally assigned"

    def test_optional_tlvs_stay_raw_and_named(self):
        """Keep the optional TLVs raw, each with its type named."""
        lldp = LLDP.decode(LLDPDUS[0])
        names = [tlv.type_name for tlv in lldp.tlvs]
        assert names == [
            "Chassis Id",
            "Port Id",
            "Time to Live",
            "System Name",
            "System Description",
            "System Capabilities",
            "Management Address",
            "Port Description",
            "Organization Specific",
            "Organization Specific",
            "Organization Specific",
            "End of LLDPDU",
        ]
        assert lldp.tlv(5) == LLDPTLV(5, b"nplldp-a")
        assert lldp.tlv(6) == LLDPTLV(6, b"NETProtocols LLDP fixture, agent A")
        assert lldp.tlv(4) == LLDPTLV(4, b"nplldp-va")
        # The first of the three type-127 TLVs: lldpd's IEEE 802.3 (OUI
        # 00-12-0f) subtype 3, not the custom one after it.
        assert lldp.tlv(127) == LLDPTLV(
            127, bytes.fromhex("00120f0301") + bytes(4)
        )
        # Management Address: length 5, IPv4 (family 1) 10.9.86.1, then
        # the interface numbering subtype, number and OID length.
        management = lldp.tlv(8)
        assert management is not None
        assert management.value[:6] == bytes.fromhex("05010a095601")
        assert lldp.tlv(9) is None

    def test_a_304_byte_tlv_needs_the_ninth_length_bit(self):
        """Read lldpd's 304-byte custom TLV, whose Length needs 9 bits.

        304 is 0x130, so the low bit of the header's first byte belongs
        to the Length.
        """
        for index in (0, 3):
            custom = LLDP.decode(LLDPDUS[index]).tlvs[-2]
            assert custom == LLDPTLV(127, CUSTOM)
            assert custom.length == 304
            start = LLDPDUS[index].index(CUSTOM) - 2
            assert LLDPDUS[index][start : start + 2] == b"\xff\x30"

    @pytest.mark.parametrize("index", range(6))
    def test_round_trips(self, index):
        """Re-encode each LLDPDU exactly, and decode it back equal."""
        raw = LLDPDUS[index]
        lldp = LLDP.decode(raw)
        assert bytes(lldp) == raw[: lldp.header_len] == raw
        assert LLDP.decode(bytes(lldp)) == lldp

    @pytest.mark.parametrize("index", range(6))
    def test_memoryview_decodes_like_bytes(self, index):
        """Decode a view like bytes, keeping no view of the buffer."""
        buffer = bytearray(LLDPDUS[index])
        lldp = LLDP.decode(memoryview(buffer))
        assert lldp == LLDP.decode(LLDPDUS[index])
        assert all(type(tlv.value) is bytes for tlv in lldp.tlvs)
        buffer[:] = bytes(len(buffer))
        assert bytes(lldp) == LLDPDUS[index]


class TestTrailingBytes:
    """The End of LLDPDU TLV bounds the LLDPDU.

    What follows it is left undecoded.
    """

    @pytest.mark.parametrize("index", range(6))
    def test_zero_padding_to_the_ethernet_minimum(self, index):
        """Leave Ethernet's zero padding after End of LLDPDU undecoded.

        veth sent the 41- and 48-byte shutdown frames unpadded; a real
        NIC pads them to 60.
        """
        frame = FRAMES[index] + bytes(max(0, 60 - len(FRAMES[index])))
        frame += bytes(8)  # and then some, for the full LLDPDUs
        packet = decode_frame(frame)
        assert packet.consumed == len(FRAMES[index])
        assert bytes(packet[1]) == LLDPDUS[index]

    @pytest.mark.parametrize("index", range(6))
    def test_a_nonzero_trailer(self, index):
        """Leave a 4-byte trailer after End of LLDPDU undecoded."""
        frame = FRAMES[index] + b"\xde\xad\xbe\xef"
        packet = decode_frame(frame)
        assert packet.consumed == len(FRAMES[index])
        assert packet[1] == LLDP.decode(LLDPDUS[index])

    def test_anything_after_end_is_left_undecoded(self):
        """Even bytes that would walk as TLVs."""
        lldp = LLDP.decode(MINIMAL + tlv_bytes(5, b"x") + b"\x01")
        assert bytes(lldp) == MINIMAL


class TestNoEndOfLLDPDU:
    """An LLDPDU without an End of LLDPDU TLV.

    802.1AB-2016 made the End TLV optional (as Wireshark's dissector
    notes): an LLDPDU may end at the end of the frame instead.
    """

    NO_END = MINIMAL[:-2]

    def test_the_walk_ends_at_the_end_of_the_buffer(self):
        """End an LLDPDU with no End TLV at the end of the buffer."""
        lldp = LLDP.decode(self.NO_END)
        assert [tlv.type for tlv in lldp.tlvs] == [1, 2, 3]
        assert lldp.header_len == len(self.NO_END)
        assert bytes(lldp) == self.NO_END
        assert lldp.has_mandatory_tlvs

    def test_zero_padding_reads_as_an_end_tlv(self):
        """Read zero padding after the last TLV as an End TLV.

        Two bytes of the padding become the End TLV; the rest is left
        undecoded.
        """
        lldp = LLDP.decode(self.NO_END + bytes(20))
        assert lldp.tlvs[-1] == LLDPTLV(0)
        assert lldp.header_len == len(self.NO_END) + 2

    def test_a_nonzero_trailer_that_runs_past_the_buffer_raises(self):
        """``de ad`` reads as type 111 with a Length of 173."""
        with pytest.raises(TruncatedHeaderError) as err:
            LLDP.decode(self.NO_END + b"\xde\xad\xbe\xef")
        assert err.value.offset == len(self.NO_END)
        assert err.value.field == "tlvs"

    def test_a_nonzero_trailer_that_walks_is_a_phantom_tlv(self):
        """``0a 02`` reads as a System Name TLV of 2 bytes."""
        lldp = LLDP.decode(self.NO_END + b"\x0a\x02AB")
        assert lldp.tlvs[-1] == LLDPTLV(5, b"AB")

    @pytest.mark.parametrize(
        "trailer",
        [b"\x00\x02\xaa\xbb", b"\x01\x00" + b"\xaa" * 256],
        ids=["00-02", "01-00"],
    )
    def test_a_trailer_that_reads_as_an_end_tlv_with_a_length(self, trailer):
        """Raise for an End TLV header whose nonzero Length fits."""
        with pytest.raises(InvalidFieldError) as err:
            LLDP.decode(self.NO_END + trailer)
        assert (err.value.field, err.value.offset) == ("tlvs", len(self.NO_END))


class TestFraming:
    """What decode rejects, and nothing else.

    TLVs that do not fit the buffer, and a malformed End TLV.
    """

    @pytest.mark.parametrize("data", [b"", b"\x02"])
    def test_no_tlv_header(self, data):
        """Reject a buffer too short for one TLV header."""
        with pytest.raises(TruncatedHeaderError) as err:
            LLDP.decode(data)
        assert (err.value.offset, err.value.field) == (0, None)
        assert (err.value.expected, err.value.actual) == (2, len(data))
        assert err.value.protocol is LLDP

    def test_a_cut_tlv_header(self):
        """A single byte left where a TLV header would start."""
        with pytest.raises(TruncatedHeaderError) as err:
            LLDP.decode(MINIMAL[:-2] + b"\x00")
        assert err.value.offset == len(MINIMAL) - 2
        assert (err.value.field, err.value.expected) == ("tlvs", len(MINIMAL))
        assert err.value.actual == len(MINIMAL) - 1

    @pytest.mark.parametrize("cut", range(1, len(MINIMAL) - 1))
    def test_every_cut_short_of_a_boundary_raises(self, cut):
        """A snap length that cuts the LLDPDU inside a TLV."""
        boundaries = {9, 16, 20}
        raw = MINIMAL[:cut]
        if cut in boundaries:
            assert bytes(LLDP.decode(raw)) == raw
        else:
            with pytest.raises(TruncatedHeaderError):
                LLDP.decode(raw)

    def test_a_lying_length_names_the_tlv(self):
        """The TTL TLV claims 300 bytes of value."""
        lying = MINIMAL[:16] + struct.pack("!H", (3 << 9) | 300) + b"\x00\x78"
        with pytest.raises(TruncatedHeaderError) as err:
            LLDP.decode(lying)
        assert (err.value.field, err.value.offset) == ("tlvs", 16)
        assert (err.value.expected, err.value.actual) == (318, 20)
        assert err.value.protocol is LLDP

    def test_an_end_tlv_with_a_length_raises(self):
        """Reject an End TLV with a Length, as lldpd does."""
        with pytest.raises(InvalidFieldError) as err:
            LLDP.decode(MINIMAL[:-2] + b"\x00\x02\x00\x00")
        assert (err.value.field, err.value.offset) == ("tlvs", 20)
        assert (err.value.expected, err.value.actual) == (0, 2)

    def test_errors_share_the_library_base(self):
        """Raise only ProtocolError subclasses."""
        with pytest.raises(ProtocolError):
            LLDP.decode(b"\x02\x07")


class TestTLVHeader:
    """The 7-bit Type and 9-bit Length split.

    On lengths and types the corpus does not reach.
    """

    @pytest.mark.parametrize(
        "tlv_type,length,header",
        [
            (0, 0, b"\x00\x00"),
            (1, 7, b"\x02\x07"),
            (5, 255, b"\x0a\xff"),
            (5, 256, b"\x0b\x00"),
            (9, 1, b"\x12\x01"),
            (126, 0, b"\xfc\x00"),
            (127, 511, b"\xff\xff"),
        ],
    )
    def test_header_word(self, tlv_type, length, header):
        """Pack the Type above the 9-bit Length, and walk it back."""
        value = bytes(range(256)) * 2
        tlv = LLDPTLV(tlv_type, value[:length])
        assert bytes(tlv)[:2] == header
        assert len(bytes(tlv)) == 2 + length
        if tlv_type:
            lldp = LLDP.decode(bytes(tlv) + b"\x00\x00")
            assert lldp.tlvs == (tlv, LLDPTLV(0))

    def test_the_longest_tlvs_walk(self):
        """Walk IDs of 255 bytes and values of 511, the largest allowed."""
        raw = (
            tlv_bytes(1, b"\x07" + b"c" * 255)
            + tlv_bytes(2, b"\x07" + b"p" * 255)
            + tlv_bytes(3, b"\x00\x05")
            + tlv_bytes(127, bytes(511))
            + tlv_bytes(126, b"\xff" * 511)
            + tlv_bytes(0)
        )
        lldp = LLDP.decode(raw)
        assert [tlv.length for tlv in lldp.tlvs] == [256, 256, 2, 511, 511, 0]
        assert lldp.chassis_id == LLDPChassisID(7, b"c" * 255)
        assert lldp.port_id == LLDPPortID(7, b"p" * 255)
        assert bytes(lldp) == raw

    @pytest.mark.parametrize(
        "tlv_type,name",
        [
            (7, "System Capabilities"),
            (8, "Management Address"),
            (9, "unknown (9)"),
            (126, "unknown (126)"),
            (127, "Organization Specific"),
        ],
    )
    def test_type_names(self, tlv_type, name):
        """Name the standard TLV types, and the reserved ones as unknown."""
        assert LLDPTLV(tlv_type).type_name == name

    @pytest.mark.parametrize(
        "kwargs,field",
        [
            ({"type": -1}, "type"),
            ({"type": 128}, "type"),
            ({"type": 1, "value": bytes(512)}, "value"),
        ],
    )
    def test_construction_rejects_what_the_header_cannot_carry(
        self, kwargs, field
    ):
        """Reject a type or a value the header word cannot carry."""
        with pytest.raises(InvalidFieldError) as err:
            LLDPTLV(**kwargs)
        assert err.value.field == field
        assert err.value.protocol is LLDPTLV


class TestMandatoryTLVs:
    """Chassis ID, Port ID and TTL, read from the first three positions.

    Decode does not enforce them, and the accessors answer ``None``
    instead of raising.
    """

    def test_out_of_order(self):
        """Read nothing typed from a Port ID TLV in the Chassis ID's place."""
        raw = (
            tlv_bytes(2, b"\x05eth0")
            + tlv_bytes(1, b"\x04" + MAC_A)
            + tlv_bytes(3, b"\x00\x78")
            + tlv_bytes(0)
        )
        lldp = LLDP.decode(raw)
        assert (lldp.chassis_id, lldp.port_id) == (None, None)
        assert lldp.ttl == 120
        assert not lldp.has_mandatory_tlvs
        assert lldp.tlv(1) == LLDPTLV(1, b"\x04" + MAC_A)
        assert bytes(lldp) == raw

    def test_only_an_end_tlv(self):
        """Answer None from every typed accessor of a lone End TLV."""
        lldp = LLDP.decode(b"\x00\x00")
        assert (lldp.chassis_id, lldp.port_id, lldp.ttl) == (None, None, None)
        assert not lldp.is_shutdown
        assert not lldp.has_mandatory_tlvs

    @pytest.mark.parametrize("count", [1, 2])
    def test_too_few_tlvs(self, count):
        """Answer None for a mandatory TLV the LLDPDU stops before."""
        lldp = LLDP.decode(MINIMAL[: (9, 16)[count - 1]])
        assert lldp.chassis_id == LLDPChassisID(4, MAC_A)
        assert lldp.ttl is None
        assert not lldp.has_mandatory_tlvs

    @pytest.mark.parametrize("value", [b"", b"\x04", b"\x07" + bytes(256)])
    def test_an_id_that_cannot_hold_a_subtype_and_1_to_255_bytes(self, value):
        """Answer None for an ID TLV of 0, 1 or 257 bytes."""
        raw = (
            tlv_bytes(1, value)
            + tlv_bytes(2, value)
            + tlv_bytes(3, b"\x00\x78")
            + tlv_bytes(0)
        )
        lldp = LLDP.decode(raw)
        assert (lldp.chassis_id, lldp.port_id) == (None, None)
        assert not lldp.has_mandatory_tlvs

    @pytest.mark.parametrize(
        "value,ttl", [(b"", None), (b"\x01", None), (b"\x01\x2c\xff", 300)]
    )
    def test_ttl_reads_the_first_two_bytes(self, value, ttl):
        """Read the TTL from 2 bytes or more, and None from fewer."""
        raw = MINIMAL[:16] + tlv_bytes(3, value) + tlv_bytes(0)
        lldp = LLDP.decode(raw)
        assert lldp.ttl == ttl
        assert lldp.tlvs[2].value == value
        assert lldp.has_mandatory_tlvs is (ttl is not None)

    def test_a_duplicate_is_kept_and_ignored(self):
        """Keep a second Chassis ID TLV, and read the first."""
        raw = MINIMAL[:-2] + tlv_bytes(1, b"\x07other") + tlv_bytes(0)
        lldp = LLDP.decode(raw)
        assert lldp.chassis_id == LLDPChassisID(4, MAC_A)
        assert lldp.tlvs[3] == LLDPTLV(1, b"\x07other")
        assert lldp.tlv(1) == LLDPTLV(1, b"\x04" + MAC_A)
        assert lldp.has_mandatory_tlvs

    @pytest.mark.parametrize(
        "duplicate",
        [
            tlv_bytes(1, b"\x07other"),
            tlv_bytes(2, b"\x07p"),
            tlv_bytes(3, b"\x00\x05"),
        ],
        ids=["chassis-id", "port-id", "ttl"],
    )
    def test_a_later_duplicate_is_not_looked_for(self, duplicate):
        """Read the first three TLVs only, whatever recurs after them."""
        lldp = LLDP.decode(MINIMAL[:-2] + duplicate + tlv_bytes(0))
        assert (lldp.port_id, lldp.ttl) == (LLDPPortID(5, b"eth0"), 120)
        assert lldp.has_mandatory_tlvs

    @pytest.mark.parametrize("subtype", [0, 8, 255])
    def test_a_reserved_subtype_is_read(self, subtype):
        """Read an ID of a reserved subtype like any other."""
        raw = (
            tlv_bytes(1, bytes((subtype,)) + MAC_A)
            + tlv_bytes(2, bytes((subtype,)) + b"eth0")
            + MINIMAL[16:]
        )
        lldp = LLDP.decode(raw)
        assert lldp.chassis_id == LLDPChassisID(subtype, MAC_A)
        assert lldp.port_id == LLDPPortID(subtype, b"eth0")
        assert lldp.has_mandatory_tlvs

    @pytest.mark.parametrize(
        "subtype,chassis,port",
        [
            (0, "Reserved", "Reserved"),
            (1, "Chassis component", "Interface alias"),
            (2, "Interface alias", "Port component"),
            (3, "Port component", "MAC address"),
            (4, "MAC address", "Network address"),
            (5, "Network address", "Interface name"),
            (6, "Interface name", "Agent circuit Id"),
            (7, "Locally assigned", "Locally assigned"),
            (8, "unknown (8)", "unknown (8)"),
            (255, "unknown (255)", "unknown (255)"),
        ],
    )
    def test_subtype_names(self, subtype, chassis, port):
        """Name every subtype of each identifier as the tables do."""
        assert LLDPChassisID(subtype, b"x").subtype_name == chassis
        assert LLDPPortID(subtype, b"x").subtype_name == port


class TestIdentifiers:
    def test_the_tlv_and_its_bytes(self):
        """Build each identifier's TLV, and serialize it whole."""
        chassis = LLDPChassisID(4, MAC_A)
        port = LLDPPortID(5, b"eth0")
        assert chassis.tlv == LLDPTLV(1, b"\x04" + MAC_A)
        assert port.tlv == LLDPTLV(2, b"\x05eth0")
        assert bytes(chassis) + bytes(port) == MINIMAL[:16]

    def test_a_chassis_id_is_not_a_port_id(self):
        """Tell the two identifier classes apart in equality."""
        assert LLDPChassisID(4, MAC_A) != LLDPPortID(4, MAC_A)

    @pytest.mark.parametrize("cls", [LLDPChassisID, LLDPPortID])
    @pytest.mark.parametrize(
        "subtype,value,field",
        [(-1, b"x", "subtype"), (256, b"x", "subtype"), (4, b"", "id")],
    )
    def test_construction_rejects_what_the_tlv_cannot_carry(
        self, cls, subtype, value, field
    ):
        """Reject a subtype past a byte, or an empty ID."""
        with pytest.raises(InvalidFieldError) as err:
            cls(subtype, value)
        assert (err.value.field, err.value.protocol) == (field, cls)

    @pytest.mark.parametrize("cls", [LLDPChassisID, LLDPPortID])
    def test_an_id_of_256_bytes_is_rejected(self, cls):
        """Reject an ID longer than 255 bytes, and accept 255."""
        with pytest.raises(InvalidFieldError):
            cls(7, bytes(256))
        assert len(bytes(cls(7, bytes(255)))) == 2 + 256


class TestConstruction:
    def test_a_built_lldpdu_matches_the_hand_built_bytes(self):
        """Build an LLDPDU from the typed parts and match the bytes."""
        lldp = LLDP(
            tlvs=(
                LLDPChassisID(4, MAC_A).tlv,
                LLDPPortID(5, b"eth0").tlv,
                LLDPTLV(3, (120).to_bytes(2)),
                LLDPTLV(0),
            )
        )
        assert bytes(lldp) == MINIMAL
        assert LLDP.decode(MINIMAL) == lldp
        assert lldp.header_len == len(MINIMAL)

    def test_no_tlvs(self):
        """Reject an LLDPDU of no TLVs."""
        with pytest.raises(InvalidFieldError) as err:
            LLDP(tlvs=())
        assert err.value.field == "tlvs"

    @pytest.mark.parametrize(
        "tlvs",
        [
            (LLDPTLV(0), LLDPTLV(5, b"x")),
            (LLDPTLV(5, b"x"), LLDPTLV(0, b"\x00")),
            (LLDPTLV(0, b"\x00\x00"),),
        ],
        ids=["end-not-last", "end-with-value", "lone-end-with-value"],
    )
    def test_an_end_tlv_must_be_last_and_empty(self, tlvs):
        """Otherwise the bytes would not decode back to the same TLVs."""
        with pytest.raises(InvalidFieldError) as err:
            LLDP(tlvs=tlvs)
        assert err.value.field == "tlvs"

    @pytest.mark.parametrize(
        "tlvs",
        [
            (LLDPChassisID(4, b"x"),),
            (LLDPTLV(1, b"\x07x"), b"\x00\x00"),
        ],
        ids=["identifier", "bytes"],
    )
    def test_a_tlv_that_is_not_an_lldptlv(self, tlvs):
        """Reject an element that is not an LLDPTLV."""
        with pytest.raises(InvalidFieldError) as err:
            LLDP(tlvs=tlvs)
        assert (err.value.field, err.value.expected) == ("tlvs", "LLDPTLV")
        assert err.value.actual == type(tlvs[-1]).__name__

    def test_no_end_tlv_is_allowed(self):
        """Accept an LLDPDU without an End TLV, which decodes back."""
        lldp = LLDP(tlvs=(LLDPTLV(1, b"\x07x"),))
        assert LLDP.decode(bytes(lldp)) == lldp


class TestDispatch:
    def test_ethertype(self):
        """Register 0x88CC, named LLDP, for the LLDP class."""
        assert EtherType.LLDP == 0x88CC
        assert EtherType.LLDP.display_name == "LLDP"
        assert DEFAULT.get(TABLE_ETHERTYPE, 0x88CC) is LLDP

    def test_lldp_ends_the_chain(self):
        """End the walk at LLDP."""
        assert LLDP.decode(MINIMAL).next_protocol() is None

    def test_behind_a_vlan_tag(self):
        """Chain a VLAN tag to LLDP like any EtherType.

        lldpd can send LLDPDUs tagged (``configure ports ... lldp
        vlan-tx``).
        """
        frame = (
            bytes.fromhex("0180c200000e") + MAC_A + b"\x81\x00"
            b"\x00\x64\x88\xcc" + MINIMAL
        )
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, VLAN, LLDP]
        assert packet[1].vid == 100
        assert packet.consumed == len(frame)


class _ReadCountingBytes(bytes):
    """Bytes that count the bytes read out of them.

    By slicing and indexing, and by copying them whole with ``bytes()``.
    """

    read = 0

    def __getitem__(self, key):
        """Return ``bytes.__getitem__(self, key)``, counting its length."""
        result = bytes.__getitem__(self, key)
        type(self).read += len(result) if isinstance(key, slice) else 1
        return result

    def __bytes__(self):
        """Return a copy, counting every byte of it."""
        type(self).read += len(self)
        return bytes.__bytes__(self)


def _reserved_tlvs(count: int) -> bytes:
    """Build an LLDPDU of ``count`` 1-byte reserved TLVs, then End."""
    return tlv_bytes(9, b"x") * count + tlv_bytes(0)


class TestDecodeCost:
    """LLDPDUs of thousands of 3-byte reserved TLVs.

    Small TLVs make the most of them per byte, the worst case for any
    work the walk does per TLV over the rest of the buffer. Of two such
    mistakes only one can be counted: copying the whole buffer with
    ``bytes()`` calls the ``__bytes__`` a :class:`bytes` subclass
    defines, but copying it through a :class:`memoryview` calls no
    Python code at all. So one test counts the bytes read, and the other
    compares decode times on 8 times the TLVs.
    """

    COUNT = 10000
    RAW = _reserved_tlvs(COUNT)

    def test_it_decodes_whole(self):
        """Decode all 10,001 TLVs."""
        lldp = LLDP.decode(self.RAW)
        assert len(lldp.tlvs) == self.COUNT + 1
        assert lldp.tlvs[0] == LLDPTLV(9, b"x")
        assert lldp.header_len == len(self.RAW)
        assert lldp.chassis_id is None

    def test_the_walk_reads_each_byte_at_most_once(self):
        """Read no more bytes, by slicing or copying, than the buffer has."""
        data = _ReadCountingBytes(self.RAW)
        _ReadCountingBytes.read = 0
        lldp = LLDP.decode(data)
        assert len(lldp.tlvs) == self.COUNT + 1
        assert 0 < _ReadCountingBytes.read <= len(data)

    def test_8_times_the_tlvs_take_about_8_times_as_long(self):
        """Take under 16 times as long: twice what linear work would.

        A wall-clock bound would be flaky on a slow runner, so this
        bounds a ratio of two timings taken side by side, each the best
        of 5. Linear work makes it about 8; copying the rest of the
        buffer through a :class:`memoryview` at each TLV made it 25 or
        more on the machine this test was written on.
        """
        raws = (self.RAW, _reserved_tlvs(8 * self.COUNT))
        best = [float("inf")] * 2
        enabled = gc.isenabled()
        gc.disable()
        try:
            for _ in range(5):
                for index, raw in enumerate(raws):
                    start = time.perf_counter()
                    LLDP.decode(raw)
                    best[index] = min(best[index], time.perf_counter() - start)
        finally:
            if enabled:
                gc.enable()
        assert best[1] / best[0] < 16


def _load_checker() -> ModuleType:
    path = Path(__file__).parent.parent / "scripts" / "check_fixtures.py"
    spec = importlib.util.spec_from_file_location("check_fixtures", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


class TestIndependentChecker:
    """The independent checker, scripts/check_fixtures.py, on LLDP.

    LLDP has no checksum, so it checks the structure: every captured
    frame passes, and a broken one fails.
    """

    checker = _load_checker()

    def check(self, frame: bytes) -> tuple[list[str], dict[str, int]]:
        """Run the checker on one frame; return its failures and stats."""
        stats: Counter[str] = Counter()
        return self.checker.check_frame(frame, stats), dict(stats)

    def test_every_captured_frame_passes(self):
        """Pass every captured frame, three of them shutdowns."""
        shutdowns = 0
        for frame in FRAMES:
            failures, stats = self.check(frame)
            assert failures == []
            assert stats["lldp"] == 1
            shutdowns += stats.get("lldp-shutdown", 0)
        assert shutdowns == 3

    def test_zero_padding_passes(self):
        """Pass a shutdown frame zero-padded to 60 bytes."""
        assert self.check(FRAMES[2] + bytes(19))[0] == []

    @pytest.mark.parametrize(
        "damage,failure",
        [
            (lambda f: f[:-1], "lldp-unwalkable"),
            (lambda f: f[:-2], "lldp-unwalkable"),
            (lambda f: f + b"\xde\xad\xbe\xef", "lldp-bad-end"),
            (lambda f: f[:-2] + b"\x00\x01\x00", "lldp-bad-end"),
            (lambda f: f[:-2] + b"\x00\x05", "lldp-unwalkable"),
            (
                lambda f: f[:14] + f[23:35] + f[14:23] + f[35:],
                "lldp-mandatory-tlvs",
            ),
            (lambda f: f[:-2] + f[14:23] + b"\x00\x00", "lldp-mandatory-tlvs"),
            (lambda f: f[:-2] + f[35:39] + b"\x00\x00", "lldp-mandatory-tlvs"),
            (
                lambda f: f[:-2] + b"\x0a\x01x\x00\x00",
                "lldp-shutdown-extra-tlvs",
            ),
        ],
        ids=[
            "cut-end",
            "no-end",
            "trailer",
            "end-with-length",
            "end-runs-past",
            "port-id-first",
            "duplicate-chassis-id",
            "duplicate-ttl",
            "shutdown-with-system-name",
        ],
    )
    def test_a_broken_lldpdu_fails(self, damage, failure):
        """Each a damaged copy of A's first shutdown LLDPDU (frame 3)."""
        failures, _ = self.check(damage(FRAMES[2]))
        assert failures == [failure]

    @pytest.mark.parametrize(
        "tlv_type,start,end",
        [(1, 14, 23), (2, 23, 35)],
        ids=["chassis", "port"],
    )
    @pytest.mark.parametrize(
        "value", [b"", b"\x04", b"\x07" + bytes(256)], ids=["0", "1", "257"]
    )
    def test_a_malformed_id_fails(self, tlv_type, start, end, value):
        """Fail a Chassis ID or Port ID TLV of 0, 1 or 257 bytes."""
        frame = FRAMES[2][:start] + tlv_bytes(tlv_type, value) + FRAMES[2][end:]
        assert self.check(frame)[0] == ["lldp-mandatory-tlvs"]

    def test_a_ttl_of_three_bytes_fails(self):
        """Fail a Time To Live TLV that is not 2 bytes."""
        frame = FRAMES[2][:35] + tlv_bytes(3, b"\x00\x00\x00") + b"\x00\x00"
        assert self.check(frame)[0] == ["lldp-mandatory-tlvs"]
