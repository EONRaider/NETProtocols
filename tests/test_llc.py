"""Test 802.3 type/length dispatch, LLC and SNAP, and the walk's bound.

IEEE 802.3 Length/Type dispatch, the 802.2 LLC and SNAP headers, and
the walk's bound at the end of an LLC PDU.

The real frames come from tests/fixtures/llc.pcap (see its MANIFEST
entry): 802.1D BPDUs from a Linux bridge, CDP from lldpd, and six
frames scripts/llc_fixture_frames.py built. The padding and FCS cases
are built here, since veth neither pads nor carries an FCS.
``scripts/check_fixtures.py``, which shares no code with the library,
is run over those frames and over tampered copies.
"""

from __future__ import annotations

import importlib.util
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Self

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    ARP,
    GRE,
    LLC,
    LLCSAP,
    SNAP,
    UDP,
    VLAN,
    VXLAN,
    Ethernet,
    ICMPv4,
    InvalidFieldError,
    IPv4,
    Protocol,
    Registry,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import (
    TABLE_ETHERTYPE,
    TABLE_LLC_DSAP,
    TABLE_LLC_SNAP,
)

CHECKER = Path(__file__).resolve().parent.parent / "scripts/check_fixtures.py"

LLC_FRAMES = pcap_frames(FIXTURES / "llc.pcap")
(
    STP_CONFIG_B,
    STP_CONFIG_A,
    STP_CONFIG_A_TC,
    STP_TCN,
    STP_CONFIG_A_TC_TCA,
    CDPV1,
    CDPV2,
    CDPV1_HIGH_BYTE,
    RFC1042_ARP,
    RFC1042_ICMP,
    BRIDGE_TUNNEL_ARP,
    TAGGED_ARP,
    RAW_IPX,
    TYPE_1501,
) = LLC_FRAMES

DST = bytes.fromhex("0180c2000000")
SRC = bytes.fromhex("02000000a001")
FCS = b"\xde\xad\xbe\xef"

#: CDP's key in the llc.snap table: OUI 00-00-0C, PID 0x2000.
CDP_KEY = 0x00000C << 16 | 0x2000


@dataclass(frozen=True, slots=True)
class WholeBuffer(Protocol):
    """A stand-in for a decoder with no length of its own.

    STP's and CDP's will be such decoders: this one keeps every byte it
    is handed, so what it holds shows where the walk ended its buffer.
    """

    body: bytes

    _struct: ClassVar[struct.Struct] = struct.Struct("")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        return cls(bytes(data))

    def __bytes__(self) -> bytes:
        """Serialize the bytes kept."""
        return self.body

    @property
    def header_len(self) -> int:
        return len(self.body)


#: A walk that hands STP's DSAP and CDP's SNAP key to WholeBuffer.
WHOLE = {
    TABLE_LLC_DSAP: {LLCSAP.SPANNING_TREE: WholeBuffer},
    TABLE_LLC_SNAP: {CDP_KEY: WholeBuffer},
}


@pytest.fixture(scope="module")
def check_fixtures():
    """Load scripts/check_fixtures.py, which shares no library code."""
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def frame_8023(pdu: bytes, length: int | None = None) -> bytes:
    """Build an 802.3 frame carrying ``pdu``.

    Its Length is ``len(pdu)`` unless ``length`` says otherwise.
    """
    value = len(pdu) if length is None else length
    return DST + SRC + struct.pack("!H", value) + pdu


def pad(frame: bytes) -> bytes:
    """Zero-pad ``frame`` to Ethernet's 60-byte minimum, as a NIC does."""
    return frame + bytes(max(0, 60 - len(frame)))


def pdu_of(frame: bytes) -> bytes:
    """Return the LLC PDU of an untagged 802.3 frame, as its Length says."""
    return frame[14 : 14 + struct.unpack_from("!H", frame, 12)[0]]


def cdp_checksum(data: bytes) -> int:
    """Return CDP's checksum of ``data``, written out here.

    Not taken from the library: RFC 1071's sum, but an odd final byte is
    not padded into a last word's high byte. It is added as the low
    byte below 0x80, and from 0x80 as ``0xFF00 + v - 1``, lldpd
    1.0.18's src/daemon/frame.c ("sum += 0xff << 8; sum += v - 1;")
    and Wireshark's epan/dissectors/packet-cdp.c, which decrements both
    bytes of the last word.
    """
    total = sum(
        word for (word,) in struct.iter_unpack("!H", data[: len(data) & ~1])
    )
    if len(data) & 1:
        v = data[-1]
        total += (0xFF << 8) + v - 1 if v & 0x80 else v
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def cdp_pdu(*tlvs: bytes) -> bytes:
    """Return the SNAP-framed CDPv2 PDU of ``tlvs``, checksum filled in."""
    body = b"".join(tlvs)
    checksum = cdp_checksum(b"\x02\xb4\x00\x00" + body)
    cdp = b"\x02\xb4" + struct.pack("!H", checksum) + body
    return b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + cdp


def kinds(packet) -> list[type[Protocol]]:
    return [type(layer) for layer in packet]


class TestTypeOrLength:
    """IEEE 802.3 Clause 3.2.6's type/length boundaries.

    Bytes 12-13 are a length up to 1500, a type from 0x0600, and
    undefined between.
    """

    @pytest.mark.parametrize("value", [0, 3, 38, 1500])
    def test_a_length_dispatches_to_llc(self, value):
        eth = Ethernet.decode(DST + SRC + struct.pack("!H", value))
        assert eth.ethertype == value
        assert eth.is_length
        assert eth.length == value
        assert eth.next_protocol() is LLC
        assert eth.next_protocol(Registry.from_defaults()) is LLC

    @pytest.mark.parametrize("value", [1501, 1517, 1535])
    def test_the_undefined_gap_ends_the_walk(self, value):
        eth = Ethernet.decode(DST + SRC + struct.pack("!H", value))
        assert eth.ethertype == value
        assert not eth.is_length
        assert eth.length is None
        assert eth.next_protocol() is None
        assert eth.next_protocol(Registry.from_defaults()) is None

    def test_an_ethertype_dispatches_as_before(self):
        eth = Ethernet.decode(DST + SRC + b"\x08\x06")
        assert not eth.is_length
        assert eth.length is None
        assert eth.next_protocol() is ARP
        assert Ethernet.decode(DST + SRC + b"\x06\x00").next_protocol() is None

    def test_0x0600_is_the_first_ethertype(self):
        """0x0600 dispatches through ``ethertype``; 0x05FF names nothing.

        From Ethernet and from a VLAN tag alike.
        """
        registry = Registry.from_defaults().derive(
            {TABLE_ETHERTYPE: {0x0600: WholeBuffer}}
        )
        tag = b"\x81\x00\x00\x1e"
        for value, after in ((0x0600, [WholeBuffer]), (0x05FF, [])):
            field = struct.pack("!H", value)
            untagged = decode_frame(
                DST + SRC + field + b"xyz", registry=registry
            )
            assert kinds(untagged) == [Ethernet, *after]
            tagged = decode_frame(
                DST + SRC + tag + field + b"xyz", registry=registry
            )
            assert kinds(tagged) == [Ethernet, VLAN, *after]

    def test_vlan_reads_its_inner_field_the_same_way(self):
        assert VLAN(0, 0, 30, 36).next_protocol() is LLC
        assert VLAN(0, 0, 30, 36).length == 36
        assert VLAN(0, 0, 30, 36).is_length
        assert VLAN(0, 0, 30, 1501).next_protocol() is None
        assert VLAN(0, 0, 30, 1501).length is None
        assert VLAN(0, 0, 30, 0x0800).next_protocol() is IPv4
        assert VLAN(0, 0, 30, 36).next_protocol(Registry()) is LLC

    def test_gre_keeps_reading_an_ethertype(self):
        """GRE's Protocol Type is an EtherType only (RFC 2784).

        A value of 1500 or less is not a Length; the default registry
        names nothing there (see TestALowEthertypeKey).
        """
        gre = GRE.decode(b"\x00\x00\x00\x26")
        assert gre.next_protocol() is None

    def test_the_fixture_gap_frame_stops_at_ethernet(self):
        packet = decode_frame(TYPE_1501)
        assert kinds(packet) == [Ethernet]
        assert packet[Ethernet].ethertype == 1501
        assert packet.consumed == 14


class TestALowEthertypeKey:
    """An ``ethertype`` key below 0x0600 is reached as in 2.5.0, except
    from Ethernet and VLAN.

    RFC 1701's "Current List of Protocol Types" assigns GRE OSI network
    layer 0x00FE. A class registered there decodes GRE Protocol Type
    0x00FE and a SNAP PID of 0x00FE under OUI 00-00-00 or 00-00-F8,
    while an Ethernet or VLAN header reads 0x00FE as an 802.3 Length
    and answers LLC.
    """

    OSI = 0x00FE

    @pytest.fixture
    def registry(self):
        return Registry.from_defaults().derive(
            {TABLE_ETHERTYPE: {self.OSI: WholeBuffer}}
        )

    @pytest.fixture
    def gre_osi(self):
        """A real GRE frame (gre.pcap) with its Protocol Type set to
        0x00FE; GRE has no checksum here, and IPv4's does not cover it."""
        frame = bytearray(pcap_frames(FIXTURES / "gre.pcap")[0])
        assert kinds(decode_frame(bytes(frame))) == [
            Ethernet,
            IPv4,
            GRE,
            IPv4,
            ICMPv4,
        ]
        gre_at = 14 + IPv4.decode(frame[14:]).header_len
        assert GRE.decode(frame[gre_at:]).header_len == 4
        struct.pack_into("!H", frame, gre_at + 2, self.OSI)
        return bytes(frame), gre_at

    def test_gre_reaches_it(self, registry, gre_osi):
        frame, gre_at = gre_osi
        packet = decode_frame(frame, registry=registry)
        assert kinds(packet) == [Ethernet, IPv4, GRE, WholeBuffer]
        assert packet.layers[2].protocol_type == self.OSI
        assert packet.layers[3].body == frame[gre_at + 4 :]
        assert packet.consumed == len(frame)

    def test_decode_as_reaches_it_from_gre(self, gre_osi):
        frame, _ = gre_osi
        packet = decode_frame(
            frame, decode_as={TABLE_ETHERTYPE: {self.OSI: WholeBuffer}}
        )
        assert kinds(packet) == [Ethernet, IPv4, GRE, WholeBuffer]

    def test_the_default_registry_ends_the_walk_at_gre(self, gre_osi):
        frame, _ = gre_osi
        assert kinds(decode_frame(frame)) == [Ethernet, IPv4, GRE]

    def test_ethernet_and_vlan_read_it_as_a_length(self, registry):
        """Type/length 0x00FE is a 254-byte LLC PDU, never the key."""
        pdu = bytes([LLCSAP.ISO_NETWORK_LAYER, LLCSAP.ISO_NETWORK_LAYER, 3])
        frame = frame_8023(pdu + bytes(self.OSI - len(pdu)))
        assert Ethernet.decode(frame).length == self.OSI
        assert kinds(decode_frame(frame, registry=registry)) == [
            Ethernet,
            LLC,
        ]
        tagged = frame[:12] + b"\x81\x00\x00\x1e" + frame[12:]
        assert kinds(decode_frame(tagged, registry=registry)) == [
            Ethernet,
            VLAN,
            LLC,
        ]

    @pytest.mark.parametrize("oui", [0x000000, 0x0000F8])
    def test_a_snap_pid_under_an_ethertype_oui_reaches_it(self, registry, oui):
        snap = b"\xaa\xaa\x03" + oui.to_bytes(3, "big") + b"\x00\xfe"
        packet = decode_frame(frame_8023(snap + b"osi"), registry=registry)
        assert kinds(packet) == [Ethernet, LLC, SNAP, WholeBuffer]
        assert packet.layers[-1].body == b"osi"

    def test_a_snap_pid_under_another_oui_does_not(self, registry):
        snap = b"\xaa\xaa\x03\x00\x00\x0c\x00\xfe"
        packet = decode_frame(frame_8023(snap + b"osi"), registry=registry)
        assert kinds(packet) == [Ethernet, LLC, SNAP]


class TestLLCHeader:
    def test_a_bpdu_header(self, raw_llc_header):
        llc = LLC.decode(raw_llc_header + bytes(35))
        assert (llc.dsap, llc.ssap, llc.control) == (0x42, 0x42, 0x03)
        assert llc.header_len == 3
        assert llc.control_format == "U"
        assert llc.dsap_name == "Bridge Spanning Tree"
        assert llc.ssap_name == "Bridge Spanning Tree"
        assert llc.dsap_enum is LLCSAP.SPANNING_TREE
        assert not llc.is_group
        assert not llc.is_response
        assert not llc.is_raw_ipx
        assert bytes(llc) == raw_llc_header

    def test_an_i_format_control_is_two_octets_first_in_the_low_byte(self):
        llc = LLC.decode(b"\xf0\xf0\x02\x05payload")
        assert llc.control == 0x0502
        assert llc.header_len == 4
        assert llc.control_format == "I"
        assert bytes(llc) == b"\xf0\xf0\x02\x05"

    def test_an_s_format_control_is_two_octets(self):
        llc = LLC.decode(b"\x42\x43\x01\x07")
        assert llc.control == 0x0701
        assert llc.control_format == "S"
        assert llc.is_response
        assert llc.ssap_name == "Bridge Spanning Tree"

    def test_a_two_octet_control_never_collides_with_ui(self):
        """``0x00 0x03`` on the wire is an I-format Control, 0x0300."""
        i_format = LLC.decode(b"\x42\x42\x00\x03")
        assert i_format.control == 0x0300
        assert i_format != LLC.decode(b"\x42\x42\x03")
        assert bytes(i_format) == b"\x42\x42\x00\x03"

    def test_names_fall_back_to_hex(self):
        llc = LLC(dsap=0xE1, ssap=0xE0, control=0x03)
        assert llc.dsap_name == "0xe1"
        assert llc.ssap_name == "0xe0"
        assert llc.dsap_enum is None
        assert llc.is_group

    def test_short_buffers_raise(self):
        with pytest.raises(TruncatedHeaderError):
            LLC.decode(b"\x42\x42")
        with pytest.raises(TruncatedHeaderError) as excinfo:
            LLC.decode(b"\xf0\xf0\x00")
        assert excinfo.value.field == "control"
        assert excinfo.value.offset == 2
        assert excinfo.value.expected == 4
        assert excinfo.value.actual == 3

    @pytest.mark.parametrize(
        "fields,field",
        [
            ({"dsap": 0x100, "ssap": 0, "control": 3}, "dsap"),
            ({"dsap": 0, "ssap": -1, "control": 3}, "ssap"),
            ({"dsap": 0, "ssap": 0, "control": 0x103}, "control"),
            ({"dsap": 0, "ssap": 0, "control": 0x10000}, "control"),
            ({"dsap": 0, "ssap": 0, "control": -2}, "control"),
        ],
    )
    def test_the_constructor_rejects_what_does_not_fit(self, fields, field):
        with pytest.raises(InvalidFieldError) as excinfo:
            LLC(**fields)
        assert excinfo.value.field == field

    def test_a_memoryview_is_not_retained(self):
        buffer = bytearray(b"\xf0\xf0\x02\x05")
        llc = LLC.decode(memoryview(buffer))
        buffer[:] = bytes(4)
        assert bytes(llc) == b"\xf0\xf0\x02\x05"


class TestLLCDispatch:
    """Only I-format and UI PDUs carry upper-layer data.

    SNAP needs SSAP 0xAA and UI too; Novell raw 802.3 never dispatches.
    """

    @pytest.fixture
    def registry(self):
        return Registry.from_defaults().derive(
            {TABLE_LLC_DSAP: {0x42: WholeBuffer, 0xFF: WholeBuffer}}
        )

    @pytest.mark.parametrize(
        "control", [0x03, 0x13, 0x0000, 0xFE02], ids=["UI", "UI-P", "I", "I2"]
    )
    def test_ui_and_i_format_dispatch(self, registry, control):
        llc = LLC(dsap=0x42, ssap=0x42, control=control)
        assert llc.next_protocol(registry) is WholeBuffer

    @pytest.mark.parametrize(
        "control",
        [0x0001, 0x0105, 0xAF, 0xBF, 0xE3, 0xF3, 0x7F],
        ids=["RR", "RNR", "XID", "XID-P", "TEST", "TEST-P", "SABME"],
    )
    def test_other_formats_end_the_walk(self, registry, control):
        llc = LLC(dsap=0x42, ssap=0x42, control=control)
        assert llc.next_protocol(registry) is None

    def test_an_unregistered_dsap_ends_the_walk(self, raw_llc_header):
        assert LLC.decode(raw_llc_header).next_protocol() is None

    def test_snap_follows_aa_aa_ui(self):
        assert LLC(0xAA, 0xAA, 0x03).next_protocol() is SNAP
        assert LLC(0xAA, 0xAA, 0x13).next_protocol() is SNAP
        assert LLC(0xAA, 0xAA, 0x03).next_protocol(Registry()) is None

    @pytest.mark.parametrize(
        "ssap,control",
        [(0x42, 0x03), (0xAB, 0x03), (0xAA, 0xAF), (0xAA, 0xE3), (0xAA, 0)],
        ids=["ssap-0x42", "ssap-response", "XID", "TEST", "I-format"],
    )
    def test_no_snap_header_otherwise(self, ssap, control):
        assert LLC(0xAA, ssap, control).next_protocol() is None

    def test_novell_raw_8023_never_dispatches(self, registry):
        llc = LLC.decode(pdu_of(RAW_IPX))
        assert llc.is_raw_ipx
        assert llc.next_protocol(registry) is None
        assert llc.next_protocol() is None
        assert bytes(llc) == pdu_of(RAW_IPX)[: llc.header_len]

    def test_the_global_dsap_dispatches_from_another_ssap(self, registry):
        assert LLC(0xFF, 0xFE, 0x03).next_protocol(registry) is WholeBuffer


class TestSNAPHeader:
    def test_cdp(self, raw_snap_header):
        snap = SNAP.decode(raw_snap_header + b"\x02\xb4")
        assert (snap.oui, snap.pid) == (0x00000C, 0x2000)
        assert snap.oui_str == "00-00-0c"
        assert snap.snap_key == CDP_KEY
        assert not snap.carries_ethertype
        assert snap.header_len == 5
        assert bytes(snap) == raw_snap_header

    @pytest.mark.parametrize("oui", [0x000000, 0x0000F8])
    def test_the_ethertype_ouis_read_the_ethertype_table(self, oui):
        snap = SNAP(oui=oui, pid=0x0806)
        assert snap.carries_ethertype
        assert snap.next_protocol() is ARP
        assert snap.next_protocol(Registry.from_defaults()) is ARP

    def test_a_pid_below_0x0600_is_not_a_length(self):
        assert SNAP(oui=0, pid=0x0026).next_protocol() is None

    def test_another_oui_reads_llc_snap_not_ethertype(self):
        """CDP is OUI 00-00-0C PID 0x2000: not EtherType 0x2000."""
        registry = Registry.from_defaults().derive(
            {TABLE_ETHERTYPE: {0x2000: GRE}, TABLE_LLC_SNAP: {CDP_KEY: VXLAN}}
        )
        assert SNAP(oui=0x00000C, pid=0x2000).next_protocol(registry) is VXLAN
        assert SNAP(oui=0, pid=0x2000).next_protocol(registry) is GRE
        assert SNAP(oui=0x00000C, pid=0x2000).next_protocol() is None

    @pytest.mark.parametrize(
        "fields,field",
        [
            ({"oui": 1 << 24, "pid": 0}, "oui"),
            ({"oui": 0, "pid": -1}, "pid"),
            ({"oui": 0, "pid": 0x10000}, "pid"),
        ],
    )
    def test_the_constructor_rejects_what_does_not_fit(self, fields, field):
        with pytest.raises(InvalidFieldError) as excinfo:
            SNAP(**fields)
        assert excinfo.value.field == field

    def test_short_buffers_raise(self, raw_snap_header):
        with pytest.raises(TruncatedHeaderError):
            SNAP.decode(raw_snap_header[:4])


class TestTheFixture:
    def test_bpdus_decode_as_far_as_llc(self):
        for frame in (
            STP_CONFIG_B,
            STP_CONFIG_A,
            STP_CONFIG_A_TC,
            STP_TCN,
            STP_CONFIG_A_TC_TCA,
        ):
            packet = decode_frame(frame)
            assert kinds(packet) == [Ethernet, LLC]
            assert packet[LLC].dsap_enum is LLCSAP.SPANNING_TREE
            assert packet[Ethernet].length == len(frame) - 14
        assert len(STP_TCN) == 21
        assert packet.consumed == 17

    @pytest.mark.parametrize(
        "frame", [CDPV1, CDPV2, CDPV1_HIGH_BYTE], ids=["v1", "v2", "high"]
    )
    def test_cdp_decodes_as_far_as_snap(self, frame):
        packet = decode_frame(frame)
        assert kinds(packet) == [Ethernet, LLC, SNAP]
        assert packet[SNAP].snap_key == CDP_KEY
        assert packet[SNAP].next_protocol() is None
        assert cdp_checksum(pdu_of(frame)[8:]) == 0

    def test_rfc1042_reaches_arp_through_the_ethertype_table(self):
        packet = decode_frame(RFC1042_ARP)
        assert kinds(packet) == [Ethernet, LLC, SNAP, ARP]
        assert packet[SNAP].oui == 0
        assert packet[ARP].tpa == "10.9.30.2"
        assert packet.consumed == 14 + 36 < len(RFC1042_ARP)

    def test_rfc1042_reaches_icmp_through_ipv4(self):
        packet = decode_frame(RFC1042_ICMP)
        assert kinds(packet) == [Ethernet, LLC, SNAP, IPv4, ICMPv4]
        assert packet.consumed == len(RFC1042_ICMP)

    def test_the_bridge_tunnel_oui_reaches_arp(self):
        packet = decode_frame(BRIDGE_TUNNEL_ARP)
        assert kinds(packet) == [Ethernet, LLC, SNAP, ARP]
        assert packet[SNAP].oui_str == "00-00-f8"

    def test_a_tagged_8023_frame(self):
        packet = decode_frame(TAGGED_ARP)
        assert kinds(packet) == [Ethernet, VLAN, LLC, SNAP, ARP]
        assert packet[VLAN].vid == 30
        assert packet[VLAN].length == 36
        assert packet.consumed == 18 + 36

    def test_novell_raw_8023_stops_at_llc(self):
        packet = decode_frame(RAW_IPX)
        assert kinds(packet) == [Ethernet, LLC]
        assert packet[LLC].is_raw_ipx

    def test_every_frame_round_trips(self):
        for frame in LLC_FRAMES:
            packet = decode_frame(frame)
            assert bytes(packet) == frame[: packet.consumed]


class TestTheWalkBound:
    """After an 802.3 Length, later buffers end where the PDU does.

    Padding and an FCS reach no decoder.
    """

    @pytest.mark.parametrize(
        "trailer",
        [b"", bytes(8), FCS, bytes(8) + FCS],
        ids=["none", "padding", "fcs", "padding-fcs"],
    )
    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    def test_a_trailer_stays_outside_every_layer(self, trailer, lax):
        frame = STP_CONFIG_A + trailer
        packet = decode_frame(frame, decode_as=WHOLE, lax=lax)
        assert kinds(packet) == [Ethernet, LLC, WholeBuffer]
        assert packet[WholeBuffer].body == pdu_of(STP_CONFIG_A)[3:]
        assert packet.consumed == len(STP_CONFIG_A)
        assert packet.stopped_by is None

    @pytest.mark.parametrize(
        "frame", [CDPV1, CDPV2, CDPV1_HIGH_BYTE], ids=["v1", "v2", "high"]
    )
    @pytest.mark.parametrize(
        "trailer", [bytes(4), FCS, bytes(3) + FCS], ids=["zeros", "fcs", "both"]
    )
    def test_a_cdp_pdu_reaches_its_decoder_exactly(self, frame, trailer):
        """CDP's checksum covers exactly its PDU, which the Length bounds.

        With the bound it still verifies, and without it would not.
        """
        packet = decode_frame(frame + trailer, decode_as=WHOLE)
        body = packet[WholeBuffer].body
        assert body == pdu_of(frame)[8:]
        assert cdp_checksum(body) == 0
        assert cdp_checksum(body + trailer) != 0

    def test_a_short_tcn_with_padding_and_fcs(self):
        frame = pad(STP_TCN) + FCS
        packet = decode_frame(frame, decode_as=WHOLE)
        assert packet[WholeBuffer].body == b"\x00\x00\x00\x80"
        assert packet.consumed == 21

    def test_a_tagged_frame_is_bounded_by_the_tag_length(self):
        packet = decode_frame(TAGGED_ARP + FCS)
        assert kinds(packet) == [Ethernet, VLAN, LLC, SNAP, ARP]
        assert bytes(packet) == TAGGED_ARP[:54]

    def test_a_tagged_8023_pdu_reaches_its_decoder_exactly(self):
        """The Length after a tag bounds the PDU on its own.

        The outer field is the 0x8100 EtherType, so only VLAN's Length
        keeps the padding and FCS from the decoder.
        """
        pdu = pdu_of(STP_CONFIG_A)
        tag = b"\x81\x00\x00\x1e" + struct.pack("!H", len(pdu))
        frame = DST + SRC + tag + pdu
        packet = decode_frame(pad(frame) + FCS, decode_as=WHOLE)
        assert kinds(packet) == [Ethernet, VLAN, LLC, WholeBuffer]
        assert packet[WholeBuffer].body == pdu[3:]
        assert packet.consumed == len(frame)

    def test_a_length_past_the_frame_bounds_nothing(self):
        """A frame a snap length cut decodes what was captured."""
        frame = DST + SRC + struct.pack("!H", 1500) + pdu_of(STP_CONFIG_A)
        packet = decode_frame(frame + FCS, decode_as=WHOLE)
        assert packet[WholeBuffer].body == pdu_of(STP_CONFIG_A)[3:] + FCS
        assert packet.consumed == len(frame) + 4

    @pytest.mark.parametrize("length", [0, 1, 2])
    def test_a_length_below_the_llc_header_raises(self, length):
        frame = pad(frame_8023(b"\x42\x42\x03", length))
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.protocol is LLC
        assert excinfo.value.frame_offset == 14
        packet = decode_frame(frame, lax=True)
        assert kinds(packet) == [Ethernet]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    def test_a_length_cutting_a_two_octet_control_raises(self):
        frame = pad(frame_8023(b"\xf0\xf0\x00\x00", 3))
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.frame_offset == 16

    def test_inside_vxlan_an_inner_length_bounds_the_inner_pdu(self):
        outer = pcap_frames(FIXTURES / "vxlan.pcap")[0]
        ihl = (outer[14] & 0x0F) * 4
        inner_at = 14 + ihl + 8 + 8
        frame = outer[:inner_at] + pad(STP_CONFIG_A) + FCS
        packet = decode_frame(frame, decode_as=WHOLE)
        assert kinds(packet)[3:] == [VXLAN, Ethernet, LLC, WholeBuffer]
        assert packet[WholeBuffer].body == pdu_of(STP_CONFIG_A)[3:]

    def test_the_tighter_bound_wins(self):
        """An inner Length cannot widen an outer bound.

        RFC 1042 IPv4/UDP/VXLAN carrying an 802.3 frame: the outer
        Length ends the outer PDU 8 bytes into the inner BPDU, whose own
        Length (38) reaches further.
        """
        outer = pcap_frames(FIXTURES / "vxlan.pcap")[0]
        ihl = (outer[14] & 0x0F) * 4
        ip_udp_vxlan = outer[14 : 14 + ihl + 8 + 8]
        snap_ipv4 = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
        # Cut the inner frame after its Ethernet and LLC headers and 8
        # bytes of BPDU, and put the rest of it, and an FCS, after the
        # outer PDU.
        pdu = snap_ipv4 + ip_udp_vxlan + STP_CONFIG_A[: 14 + 3 + 8]
        frame = frame_8023(pdu) + STP_CONFIG_A[14 + 3 + 8 :] + FCS
        packet = decode_frame(frame, decode_as=WHOLE)
        assert kinds(packet) == [
            Ethernet,
            LLC,
            SNAP,
            IPv4,
            UDP,
            VXLAN,
            Ethernet,
            LLC,
            WholeBuffer,
        ]
        assert packet.layers[6].length == 38
        assert packet[WholeBuffer].body == pdu_of(STP_CONFIG_A)[3:11]
        assert packet.consumed == 14 + len(pdu)

    def test_only_ethernet_and_vlan_bound_their_payload(self):
        """Any other header has no extent, and the walk never asks it."""
        arp = decode_frame(RFC1042_ARP)[ARP]
        assert not arp._BOUNDS_PAYLOAD
        assert arp._payload_extent() is None
        assert Ethernet._BOUNDS_PAYLOAD
        assert VLAN._BOUNDS_PAYLOAD
        assert not LLC._BOUNDS_PAYLOAD
        assert (
            Ethernet.decode(RFC1042_ICMP[:12] + b"\x08\x00")._payload_extent()
            is None
        )

    def test_a_memoryview_walks_the_same(self):
        frame = pad(RFC1042_ARP) + FCS
        assert decode_frame(memoryview(frame)) == decode_frame(frame)


class TestTheChecker:
    """check_fixtures.py validates the frames independently.

    The 802.3 Length against the frame, the LLC/SNAP structure, and
    CDP's checksum.
    """

    def test_every_fixture_frame_passes(self, check_fixtures):
        for frame in LLC_FRAMES:
            assert check_fixtures.check_frame(frame, _counter()) == []

    def test_padding_passes(self, check_fixtures):
        assert check_fixtures.check_frame(pad(STP_TCN), _counter()) == []

    @pytest.mark.parametrize(
        "tamper,failure",
        [
            (lambda f: f + FCS, "8023-trailer-not-padding"),
            (lambda f: f[:12] + b"\x00\x62" + f[14:], "8023-trailer-not"),
            (lambda f: f[:30] + b"\x00" + f[31:], "cdp-checksum"),
            (lambda f: f[:15] + b"\x42" + f[16:], "snap-malformed"),
            (lambda f: f[:12] + b"\x05\xdc" + f[14:], "8023-length-exceeds"),
        ],
        ids=["fcs", "length-short", "byte", "ssap", "length-long"],
    )
    def test_a_tampered_cdp_frame_fails(self, check_fixtures, tamper, failure):
        failures = check_fixtures.check_frame(tamper(CDPV1), _counter())
        assert any(f.startswith(failure) for f in failures), failures

    def test_a_tampered_rfc1042_ipv4_header_fails(self, check_fixtures):
        frame = bytearray(RFC1042_ICMP)
        frame[22 + 8] ^= 0x01  # the TTL, under the IPv4 header checksum
        assert check_fixtures.check_frame(bytes(frame), _counter())

    @pytest.mark.parametrize(
        "frame,failure",
        [
            (STP_TCN[:-1] + b"\x00", "stp-bpdu-malformed"),
            (frame_8023(b"\x42\x42\x03\x00\x00\x00\x00"), "stp-bpdu-malformed"),
            (frame_8023(b"\xff\xff\x00\x10" + bytes(26)), "ipx-length"),
            (frame_8023(b"\x42"), "llc-truncated"),
            (frame_8023(b"\xf0\xf0\x00"), "llc-truncated"),
            (frame_8023(b"\x42\x42\x03" + bytes(34)), "stp-bpdu-malformed"),
            (
                frame_8023(b"\x42\x42\x03" + bytes(43)) + b"\x00",
                "8023-trailer-not-padding",
            ),
            (frame_8023(cdp_pdu(b"\x00\x01\x00\x0a", b"abcd")), "cdp-tlvs"),
            (frame_8023(cdp_pdu(b"\x00\x01\x00\x08", b"abcdXY")), "cdp-tlvs"),
        ],
        ids=[
            "tcn-type",
            "config-short",
            "ipx",
            "llc-short",
            "llc-control",
            "config-34",
            "46-padded",
            "cdp-tlv-overrun",
            "cdp-tail",
        ],
    )
    def test_malformed_pdus_fail(self, check_fixtures, frame, failure):
        failures = check_fixtures.check_frame(frame, _counter())
        assert any(f.startswith(failure) for f in failures), failures

    @pytest.mark.parametrize(
        "frame",
        [
            frame_8023(b"\x42\x42\x03" + bytes(35)),
            frame_8023(b"\x42\x42\x03" + bytes(42)) + b"\x00",
            frame_8023(cdp_pdu(b"\x00\x01\x00\x0a", b"abcdef")),
        ],
        ids=["config-35", "45-padded", "cdp-tlv"],
    )
    def test_the_boundary_cases_pass(self, check_fixtures, frame):
        assert check_fixtures.check_frame(frame, _counter()) == []

    def test_cdp_odd_byte_is_lldpds_form(self, check_fixtures):
        """A final byte from 0x80 adds ``0xFF00 + v - 1`` (lldpd, Wireshark).

        Adding ``v - 0x100`` instead agrees on the fixture's three
        lldpd frames, but not here, where the running sum is that
        small: it gives 0xFFFF.
        """
        data = b"\x00\x7f\x81"
        assert check_fixtures._cdp_checksum(data) == 0
        assert cdp_checksum(data) == 0


def _counter():
    from collections import Counter

    return Counter()
