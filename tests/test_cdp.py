"""Test CDP: the header, the TLV walk, the accessors and the dispatch.

The real frames are the three CDP frames lldpd 1.0.18 sent into
tests/fixtures/llc.pcap (see its MANIFEST entry): CDPv1, CDPv2, and a
CDPv1 whose odd-length PDU ends in 0xA9. Their checksums are tested in
test_checksum.py, which the mutation audit runs. The padding, FCS,
IPv6-address and malformed cases are built here: veth neither pads nor
carries an FCS, and the kernel boots with IPv6 disabled.
"""

from __future__ import annotations

import importlib.util
import struct
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    CDP,
    CDPTLV,
    LLC,
    SNAP,
    CDPAddress,
    Ethernet,
    InvalidFieldError,
    Packet,
    Registry,
    TruncatedHeaderError,
    decode_frame,
    verify,
)
from netprotocols.layer2.cdp import _CAPABILITY_NAMES, _TLV_TYPE_NAMES
from netprotocols.registry import TABLE_LLC_SNAP

CHECKER = Path(__file__).resolve().parent.parent / "scripts/check_fixtures.py"

LLC_FRAMES = pcap_frames(FIXTURES / "llc.pcap")
CDPV1, CDPV2, CDPV1_HIGH_BYTE = LLC_FRAMES[5:8]
FRAMES = [CDPV1, CDPV2, CDPV1_HIGH_BYTE]
IDS = ["v1", "v2", "high"]

FCS = b"\xde\xad\xbe\xef"

#: The Address TLV value lldpd sent: one address, NLPID 0xCC (IP),
#: 10.9.30.1.
LLDPD_ADDRESSES = bytes.fromhex("000000010101cc00040a091e01")

#: An 802.2-form IPv6 address entry, as packet-cdp.c reads one.
IPV6_ENTRY = (
    b"\x02\x08\xaa\xaa\x03\x00\x00\x00\x86\xdd\x00\x10"
    + bytes.fromhex("20010db8000000000000000000000001")
)


#: Wireshark's names, copied from epan/dissectors/packet-cdp.c at commit
#: 31bf085794733ece0436365ad3e0bbcc2292fc9a (gitlab.com/wireshark/wireshark,
#: read 2026-10-28): ``type_vals``, and the ``hf_cdp_capabilities_*``
#: fields' masks and names. Kept apart from cdp.py's tables so a change
#: to one shows up as a failure here.
WIRESHARK_TLV_TYPE_NAMES = {
    0x0001: "Device ID",
    0x0002: "Addresses",
    0x0003: "Port ID",
    0x0004: "Capabilities",
    0x0005: "Software version",
    0x0006: "Platform",
    0x0007: "IP Prefix/Gateway (used for ODR)",
    0x0008: "Protocol Hello",
    0x0009: "VTP Management Domain",
    0x000A: "Native VLAN",
    0x000B: "Duplex",
    0x000E: "VoIP VLAN Reply",
    0x000F: "VoIP VLAN Query",
    0x0010: "Power consumption",
    0x0011: "MTU",
    0x0012: "Trust Bitmap",
    0x0013: "Untrusted Port CoS",
    0x0014: "System Name",
    0x0015: "System Object ID",
    0x0016: "Management Address",
    0x0017: "Location",
    0x0018: "External Port-ID",
    0x0019: "Power Requested",
    0x001A: "Power Available",
    0x001B: "Port Unidirectional",
    0x001D: "EnergyWise",
    0x001F: "Spare PoE",
    0x1000: "BSSID",
    0x1001: "Serial number",
    0x1002: "SSID",
    0x1003: "Radio1 channel",
    0x1006: "SNMP UDP port",
    0x1007: "Web TCP port",
    0x1008: "Source MAC address",
    0x1009: "Radio2 channel",
    0x100A: "Radio1 Operating mode",
    0x100B: "Radio2 Operating mode",
    0x100C: "Radio1 Radio mode",
    0x100D: "Radio2 Radio mode",
}
WIRESHARK_CAPABILITY_NAMES = (
    (0x00000001, "Router"),
    (0x00000002, "Transparent Bridge"),
    (0x00000004, "Source Route Bridge"),
    (0x00000008, "Switch"),
    (0x00000010, "Host"),
    (0x00000020, "IGMP capable"),
    (0x00000040, "Repeater"),
    (0x00000080, "VoIP Phone"),
    (0x00000100, "Remotely Managed Device"),
    (0x00000200, "CVTA/STP Dispute Resolution/Cisco VT Camera"),
    (0x00000400, "Two Port Mac Relay"),
)


def pdu_of(frame: bytes) -> bytes:
    """Return the CDP PDU of an untagged 802.3 SNAP frame."""
    return frame[22 : 14 + struct.unpack_from("!H", frame, 12)[0]]


def tlv(tlv_type: int, value: bytes) -> bytes:
    """Return the on-wire TLV, its Length counting the 4-byte header."""
    return struct.pack("!HH", tlv_type, 4 + len(value)) + value


def frame_of(pdu: bytes) -> bytes:
    """Return an 802.3 LLC/SNAP frame carrying the CDP ``pdu``."""
    snap = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + pdu
    return (
        bytes.fromhex("01000ccccccc020000000001")
        + struct.pack("!H", len(snap))
        + snap
    )


@pytest.fixture(scope="module")
def check_fixtures():
    """Load scripts/check_fixtures.py, which shares no library code."""
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestTheFixture:
    @pytest.mark.parametrize("frame", FRAMES, ids=IDS)
    def test_the_walk_reaches_cdp_through_snap(self, frame):
        """Walk Ethernet, LLC and SNAP to CDP, which ends the walk."""
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, LLC, SNAP, CDP]
        assert packet.consumed == len(frame)
        assert bytes(packet) == frame
        assert packet[CDP].next_protocol() is None

    @pytest.mark.parametrize("frame", FRAMES, ids=IDS)
    def test_the_pdu_round_trips(self, frame):
        """Decode the 91-byte PDU whole, and pack it back to the same bytes."""
        pdu = pdu_of(frame)
        cdp = CDP.decode(pdu)
        assert cdp.header_len == len(pdu) == 91
        assert bytes(cdp) == pdu
        assert verify(cdp)

    def test_the_header(self):
        """Read Version, TTL and Checksum as lldpd sent them."""
        v1, v2, high = (CDP.decode(pdu_of(frame)) for frame in FRAMES)
        assert (v1.version, v1.ttl, v1.checksum) == (1, 4, 0xFDF3)
        assert (v2.version, v2.ttl, v2.checksum) == (2, 4, 0xFCF3)
        assert high.checksum_hex_str == "0xfead"

    def test_the_tlvs_lldpd_sends(self):
        """Keep lldpd's six TLVs in wire order, with Wireshark's names."""
        cdp = CDP.decode(pdu_of(CDPV2))
        assert [t.type for t in cdp.tlvs] == [1, 2, 3, 4, 5, 6]
        assert [t.type_name for t in cdp.tlvs] == [
            "Device ID",
            "Addresses",
            "Port ID",
            "Capabilities",
            "Software version",
            "Platform",
        ]
        assert [t.length for t in cdp.tlvs] == [13, 17, 12, 8, 28, 9]

    def test_the_text_accessors(self):
        """Read the Device ID, Port ID, Software version and Platform."""
        cdp = CDP.decode(pdu_of(CDPV1))
        assert cdp.device_id == "npllc-cdp"
        assert cdp.port_id == "npllc-ab"
        assert cdp.software_version == "NETProtocols LLC fixture"
        assert cdp.platform == "npllc"

    def test_a_byte_outside_ascii_reads_as_an_escape(self):
        """Escape a byte past ASCII in text; keep the raw value intact."""
        cdp = CDP.decode(pdu_of(CDPV1_HIGH_BYTE))
        assert cdp.platform == "npll\\xa9"
        assert cdp.tlv(6).value == b"npll\xa9"

    def test_capabilities(self):
        """Read lldpd's mask, 0x18, as Switch and Host."""
        cdp = CDP.decode(pdu_of(CDPV1))
        assert cdp.capabilities == 0x18
        assert cdp.capability_names == ("Switch", "Host")

    def test_the_address(self):
        """Parse lldpd's one NLPID address as IPv4."""
        cdp = CDP.decode(pdu_of(CDPV1))
        assert cdp.tlv(2).value == LLDPD_ADDRESSES
        (address,) = cdp.addresses
        assert address == CDPAddress(1, b"\xcc", b"\x0a\x09\x1e\x01")
        assert address.protocol_type_name == "NLPID"
        assert address.ip == "10.9.30.1"
        assert cdp.management_addresses is None

    @pytest.mark.parametrize("frame", FRAMES, ids=IDS)
    def test_the_independent_checker_passes_them(self, check_fixtures, frame):
        """Pass the stdlib-only checker, which counts each version."""
        stats = check_fixtures.Counter()
        assert check_fixtures.check_frame(frame, stats) == []
        assert stats[f"cdpv{pdu_of(frame)[0]}"] == 1


class TestDispatch:
    def test_snap_00000c_2000_is_cdp(self):
        """Dispatch Cisco's OUI and PID 0x2000 to CDP, default or derived."""
        assert SNAP(oui=0x00000C, pid=0x2000).next_protocol() is CDP
        assert (
            SNAP(oui=0x00000C, pid=0x2000).next_protocol(
                Registry.from_defaults()
            )
            is CDP
        )

    def test_ethertype_0x2000_is_not_cdp(self):
        """Leave PID 0x2000 under another OUI, and another PID, undispatched."""
        assert SNAP(oui=0, pid=0x2000).next_protocol() is None
        assert SNAP(oui=0x00000C, pid=0x2001).next_protocol() is None
        assert SNAP(oui=0x00000D, pid=0x2000).next_protocol() is None

    def test_the_registry_key(self):
        """Register CDP at (0x00000C << 16) | 0x2000 in llc.snap."""
        assert Registry.from_defaults().get(TABLE_LLC_SNAP, 0x0C2000) is CDP


class TestWhereThePDUEnds:
    """In a walk the 802.3 Length bounds the PDU; standalone, nothing does."""

    @pytest.mark.parametrize("frame", FRAMES, ids=IDS)
    @pytest.mark.parametrize(
        "trailer",
        [bytes(1), bytes(4), bytes(46), FCS, bytes(3) + FCS],
        ids=["zero", "zeros", "padding", "fcs", "both"],
    )
    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    def test_the_walk_keeps_a_trailer_out(self, frame, trailer, lax):
        """Keep padding and an FCS out of CDP behind the 802.3 Length."""
        packet = decode_frame(frame + trailer, lax=lax)
        assert packet[CDP] == CDP.decode(pdu_of(frame))
        assert packet.consumed == len(frame)
        assert packet.stopped_by is None
        assert verify(packet[CDP])

    @pytest.mark.parametrize("frame", FRAMES, ids=IDS)
    @pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 46])
    def test_standalone_zero_padding_is_left_undecoded(self, frame, count):
        """End the walk at a run of zeros: 1-3 bytes, or a Length of 0."""
        pdu = pdu_of(frame)
        cdp = CDP.decode(pdu + bytes(count))
        assert cdp == CDP.decode(pdu)
        assert cdp.header_len == len(pdu)
        assert verify(cdp)

    def test_standalone_an_fcs_with_a_long_length_raises(self):
        """Raise for an FCS read as a TLV whose Length runs past the buffer."""
        pdu = pdu_of(CDPV1)
        with pytest.raises(TruncatedHeaderError) as excinfo:
            CDP.decode(pdu + FCS)
        assert excinfo.value.field == "tlvs"
        assert excinfo.value.offset == len(pdu)
        assert excinfo.value.expected == 0xBEEF
        assert excinfo.value.actual == 4

    def test_standalone_an_fcs_with_a_short_length_raises(self):
        """Raise for an FCS read as a TLV header of Length below 4."""
        pdu = pdu_of(CDPV1)
        with pytest.raises(InvalidFieldError) as excinfo:
            CDP.decode(pdu + b"\xde\xad\x00\x03")
        assert excinfo.value.protocol is CDP
        assert excinfo.value.field == "tlvs"
        assert excinfo.value.offset == len(pdu)
        assert excinfo.value.expected == ">=4"
        assert excinfo.value.actual == 3

    def test_standalone_an_fcs_of_length_4_is_a_phantom_tlv(self):
        """It decodes, and the checksum is what shows it was not sent."""
        pdu = pdu_of(CDPV1)
        cdp = CDP.decode(pdu + b"\xde\xad\x00\x04")
        assert cdp.tlvs[-1] == CDPTLV(0xDEAD)
        assert cdp.header_len == len(pdu) + 4
        assert not verify(cdp)

    def test_a_short_length_inside_the_pdu_raises(self):
        """Raise where Wireshark stops: TLVs follow, nothing is dropped."""
        body = tlv(1, b"sw1") + b"\x00\x05\x00\x02" + tlv(6, b"p")
        with pytest.raises(InvalidFieldError) as excinfo:
            CDP.decode(b"\x02\xb4\x00\x00" + body)
        assert excinfo.value.field == "tlvs"
        assert excinfo.value.offset == 4 + 7
        assert excinfo.value.actual == 2

    @pytest.mark.parametrize("length", [0, 1, 2, 3])
    @pytest.mark.parametrize(
        "header_type,rest",
        [(1, b""), (0, b"abcd"), (0, bytes(4) + b"\x01")],
        ids=["type", "value", "last-byte"],
    )
    def test_every_length_below_4_raises_before_nonzero_bytes(
        self, length, header_type, rest
    ):
        """Raise at Lengths 0-3, which cannot cover their own header,
        when any byte from that header on is nonzero, the last one too."""
        data = (
            b"\x01\xb4\x00\x00"
            + tlv(9, b"x")
            + struct.pack("!HH", header_type, length)
            + rest
        )
        with pytest.raises(InvalidFieldError) as excinfo:
            CDP.decode(data)
        assert excinfo.value.protocol is CDP
        assert excinfo.value.field == "tlvs"
        assert excinfo.value.offset == 9
        assert excinfo.value.expected == ">=4"
        assert excinfo.value.actual == length
        assert f"declares Length {length}, below its 4-byte header" in str(
            excinfo.value
        )

    @pytest.mark.parametrize("count", [4, 5, 8, 46])
    def test_a_zero_tail_after_tlvs_is_left_undecoded(self, count):
        """Stop at zeros after the last TLV; header_len leaves them out."""
        head = b"\x02\xb4\x00\x00" + tlv(1, b"sw1") + tlv(9, b"")
        cdp = CDP.decode(head + bytes(count))
        assert cdp.tlvs == (CDPTLV(1, b"sw1"), CDPTLV(9))
        assert cdp.header_len == len(head)
        assert bytes(cdp) == head

    def test_a_snap_length_cut_raises_in_a_strict_walk(self):
        """Raise at the cut TLV, its offset rebased onto the frame."""
        frame = CDPV1[:-5]
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.protocol is CDP
        assert excinfo.value.field == "tlvs"
        assert excinfo.value.offset == 4 + 13 + 17 + 12 + 8 + 28
        assert excinfo.value.frame_offset == 22 + excinfo.value.offset

    def test_a_snap_length_cut_stops_a_lax_walk(self):
        """Stop a lax walk before CDP, the error on stopped_by."""
        packet = decode_frame(CDPV1[:-5], lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, LLC, SNAP]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    @pytest.mark.parametrize(
        "rest",
        [b"\x01", b"\x00\x06", b"\x00\x06\x00", b"\x00\x00\x01", b"\xde\xad"],
    )
    def test_a_cut_tlv_header_raises(self, rest):
        """1-3 bytes left, not all zero: too few for a TLV header."""
        data = b"\x01\xb4\x00\x00" + tlv(1, b"x") + rest
        with pytest.raises(TruncatedHeaderError) as excinfo:
            CDP.decode(data)
        assert excinfo.value.protocol is CDP
        assert excinfo.value.field == "tlvs"
        assert excinfo.value.offset == 9
        assert excinfo.value.expected == 4
        assert excinfo.value.actual == len(rest)
        assert f"needs 4 bytes, {len(rest)} remain" in str(excinfo.value)

    @pytest.mark.parametrize("count", [1, 2, 3])
    def test_a_cut_tlv_header_of_zeros_is_left_undecoded(self, count):
        """1-3 zero bytes after the last TLV are padding."""
        data = b"\x01\xb4\x00\x00" + tlv(1, b"x") + bytes(count)
        cdp = CDP.decode(data)
        assert cdp.tlvs == (CDPTLV(1, b"x"),)
        assert cdp.header_len == 9

    @staticmethod
    def malformed_frame(check_fixtures) -> bytes:
        """Return the review's frame: a TLV, then 8 bytes no TLV fits.

        Bytes 10-13 read as a TLV of type 0xFFFF and Length 0; the
        checksum is filled over all 18 bytes the 802.3 Length holds,
        the checker's way, so only the TLV walk can tell.
        """
        head = bytes(CDP(2, 180, 0, (CDPTLV(1, b"ab"),)))
        pdu = bytearray(head + bytes.fromhex("ffff0000abcd5432"))
        pdu[2:4] = check_fixtures._cdp_checksum(bytes(pdu)).to_bytes(2)
        return frame_of(bytes(pdu))

    def test_a_short_length_inside_the_802_3_length_fails_a_strict_walk(
        self, check_fixtures
    ):
        """Raise, rebased onto the frame; the checker rejects it too."""
        frame = self.malformed_frame(check_fixtures)
        assert len(frame) == 40
        with pytest.raises(InvalidFieldError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.protocol is CDP
        assert excinfo.value.field == "tlvs"
        assert excinfo.value.offset == 10
        assert excinfo.value.actual == 0
        assert excinfo.value.frame_offset == 22 + 10
        assert check_fixtures.check_frame(frame, check_fixtures.Counter()) == [
            "cdp-malformed"
        ]

    def test_a_short_length_inside_the_802_3_length_stops_a_lax_walk(
        self, check_fixtures
    ):
        """Stop a lax walk before CDP, the error on stopped_by."""
        packet = decode_frame(self.malformed_frame(check_fixtures), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, LLC, SNAP]
        assert packet.consumed == 22
        assert isinstance(packet.stopped_by, InvalidFieldError)
        assert packet.stopped_by.offset == 10

    def test_zeros_inside_the_802_3_length_end_a_walk(self):
        """Stop at zeros the 802.3 Length holds, as standalone."""
        pdu = b"\x02\xb4\x00\x00" + tlv(1, b"x")
        packet = decode_frame(frame_of(pdu + bytes(6)))
        assert packet[CDP] == CDP.decode(pdu)
        assert packet.consumed == 22 + len(pdu)
        assert packet.stopped_by is None

    def test_a_cut_tlv_header_inside_the_802_3_length_fails_a_walk(self):
        """Raise for 1-3 nonzero bytes the 802.3 Length holds."""
        frame = frame_of(b"\x02\xb4\x00\x00" + tlv(1, b"x") + b"\x00\x06")
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(frame + bytes(20))
        assert excinfo.value.field == "tlvs"
        assert excinfo.value.offset == 9
        assert excinfo.value.frame_offset == 22 + 9


class TestDecode:
    def test_a_header_alone(self):
        """Decode a 4-byte PDU with no TLVs."""
        cdp = CDP.decode(b"\x02\xb4\x12\x34")
        assert cdp == CDP(version=2, ttl=180, checksum=0x1234)
        assert cdp.tlvs == ()
        assert cdp.header_len == 4

    @pytest.mark.parametrize("size", range(4))
    def test_a_short_header_raises(self, size):
        """Raise for 0-3 bytes, as for any short fixed header."""
        with pytest.raises(TruncatedHeaderError) as excinfo:
            CDP.decode(b"\x02\xb4\x12\x34"[:size])
        assert excinfo.value.protocol is CDP
        assert excinfo.value.offset == 0
        assert excinfo.value.field is None

    @pytest.mark.parametrize("version", [0, 3, 255])
    def test_any_version_decodes(self, version):
        """The SNAP header says CDP follows: the Version is not checked."""
        data = bytes((version, 60, 0, 0)) + tlv(1, b"router")
        cdp = CDP.decode(data)
        assert cdp.version == version
        assert cdp.device_id == "router"
        assert bytes(cdp) == data

    def test_a_memoryview_decodes_like_bytes(self):
        """Decode a memoryview to the same PDU, its values materialized."""
        pdu = pdu_of(CDPV1_HIGH_BYTE)
        cdp = CDP.decode(memoryview(pdu))
        assert cdp == CDP.decode(pdu)
        assert all(type(t.value) is bytes for t in cdp.tlvs)

    def test_a_memoryview_frame_walks_the_same(self):
        """Walk a padded memoryview frame as its bytes walk."""
        frame = CDPV2 + bytes(6) + FCS
        assert decode_frame(memoryview(frame)) == decode_frame(frame)

    def test_a_tlv_of_length_4_has_an_empty_value(self):
        """Decode a TLV of Length 4 with an empty value."""
        cdp = CDP.decode(b"\x02\xb4\x00\x00\x00\x09\x00\x04")
        assert cdp.tlvs == (CDPTLV(9),)
        assert cdp.tlvs[0].type_name == "VTP Management Domain"

    def test_a_tlv_that_overruns_raises(self):
        """Raise at the TLV whose Length runs past the buffer."""
        data = b"\x02\xb4\x00\x00" + tlv(1, b"ab") + b"\x00\x06\x00\x09abcd"
        with pytest.raises(TruncatedHeaderError) as excinfo:
            CDP.decode(data)
        assert excinfo.value.offset == 10
        assert excinfo.value.expected == 9
        assert excinfo.value.actual == 8
        assert "declares Length 9, buffer holds 8" in str(excinfo.value)


class TestConstruction:
    def test_defaults(self):
        """Default the checksum to 0 and the TLVs to none."""
        cdp = CDP(version=2, ttl=180)
        assert bytes(cdp) == b"\x02\xb4\x00\x00"

    def test_bytes_packs_every_tlv(self):
        """Pack the header and each TLV, Length counting the header."""
        cdp = CDP(2, 180, 0xABCD, (CDPTLV(1, b"a"), CDPTLV(0x1000, b"")))
        assert bytes(cdp) == (
            b"\x02\xb4\xab\xcd\x00\x01\x00\x05a\x10\x00\x00\x04"
        )
        assert cdp.header_len == 13

    @pytest.mark.parametrize(
        "fields,field",
        [
            ({"version": 256, "ttl": 0}, "version"),
            ({"version": -1, "ttl": 0}, "version"),
            ({"version": 1, "ttl": 256}, "ttl"),
            ({"version": 1, "ttl": -1}, "ttl"),
            ({"version": 1, "ttl": 0, "checksum": 0x10000}, "checksum"),
            ({"version": 1, "ttl": 0, "checksum": -1}, "checksum"),
            ({"version": 1, "ttl": 0, "tlvs": (b"\x00\x01\x00\x04",)}, "tlvs"),
        ],
    )
    def test_cdp_rejects_what_does_not_fit(self, fields, field):
        """Refuse a field that overflows, and a TLV of another type."""
        with pytest.raises(InvalidFieldError) as excinfo:
            CDP(**fields)
        assert excinfo.value.field == field
        assert excinfo.value.protocol is CDP

    def test_the_limits_fit(self):
        """Accept the widest values, and round-trip a 65535-byte TLV."""
        cdp = CDP(255, 255, 0xFFFF, (CDPTLV(0xFFFF, bytes(65531)),))
        assert CDP.decode(bytes(cdp)) == cdp
        assert cdp.tlvs[0].length == 0xFFFF

    @pytest.mark.parametrize(
        "fields,field",
        [
            ({"type": 0x10000}, "type"),
            ({"type": -1}, "type"),
            ({"type": 1, "value": bytes(65532)}, "value"),
        ],
    )
    def test_a_tlv_rejects_what_does_not_fit(self, fields, field):
        """Refuse a type past 16 bits and a value too long for Length."""
        with pytest.raises(InvalidFieldError) as excinfo:
            CDPTLV(**fields)
        assert excinfo.value.field == field
        assert excinfo.value.protocol is CDPTLV

    @pytest.mark.parametrize(
        "fields,field",
        [
            ({"protocol_type": 256, "protocol": b"", "address": b""}, "p"),
            ({"protocol_type": -1, "protocol": b"", "address": b""}, "p"),
            ({"protocol_type": 1, "protocol": bytes(256), "address": b""}, "p"),
            (
                {"protocol_type": 1, "protocol": b"", "address": bytes(65536)},
                "a",
            ),
        ],
    )
    def test_an_address_rejects_what_does_not_fit(self, fields, field):
        """Refuse a protocol type, protocol or address too wide."""
        with pytest.raises(InvalidFieldError) as excinfo:
            CDPAddress(**fields)
        assert excinfo.value.field.startswith(
            "protocol" if field == "p" else "address"
        )
        assert excinfo.value.protocol is CDPAddress

    def test_a_range_error_says_what_fits(self):
        """Name the range and the value refused, in the error and text."""
        with pytest.raises(InvalidFieldError) as excinfo:
            CDP(version=1, ttl=256)
        assert excinfo.value.expected == "0-255"
        assert excinfo.value.actual == 256
        assert "CDP ttl must be within 0-255, got 256" in str(excinfo.value)

    def test_a_tlv_of_another_type_is_named(self):
        """Name the type found and its index, in the error and text."""
        with pytest.raises(InvalidFieldError) as excinfo:
            CDP(1, 0, 0, (CDPTLV(1), b"\x00\x01\x00\x04"))
        assert excinfo.value.expected == "CDPTLV"
        assert excinfo.value.actual == "bytes"
        assert "found bytes at index 1" in str(excinfo.value)

    def test_protocol_type_0_fits(self):
        """Accept the lowest protocol type, which no name covers."""
        address = CDPAddress(0, b"", b"")
        assert address.protocol_type_name == "unknown (0)"
        assert bytes(address) == b"\x00\x00\x00\x00"

    def test_with_checksums_makes_a_frame_the_checker_accepts(
        self, check_fixtures
    ):
        """Fill an odd PDU ending past 0x80 so the checker accepts it.

        The library sums it; the independent checker sums it lldpd's way.
        """
        cdp = CDP(1, 180, 0, (CDPTLV(1, b"sw"), CDPTLV(6, b"\xff")))
        pdu = bytes(cdp)
        assert len(pdu) % 2 and pdu[-1] == 0xFF
        built = decode_frame(frame_of(pdu))
        filled = bytes(built.with_checksums())
        assert (
            check_fixtures.check_frame(filled, check_fixtures.Counter()) == []
        )
        assert check_fixtures.check_frame(
            bytes(built), check_fixtures.Counter()
        ) == ["cdp-checksum"]


class TestAccessors:
    def test_a_pdu_without_them(self):
        """Answer None, or no names, when the TLVs are missing."""
        cdp = CDP(2, 180)
        assert cdp.device_id is None
        assert cdp.port_id is None
        assert cdp.software_version is None
        assert cdp.platform is None
        assert cdp.capabilities is None
        assert cdp.capability_names == ()
        assert cdp.addresses is None
        assert cdp.management_addresses is None
        assert cdp.tlv(1) is None

    def test_the_first_tlv_of_a_type_answers(self):
        """Read the first of two TLVs of the same type."""
        cdp = CDP(2, 180, 0, (CDPTLV(1, b"first"), CDPTLV(1, b"second")))
        assert cdp.device_id == "first"
        assert cdp.tlv(1) == CDPTLV(1, b"first")

    @pytest.mark.parametrize(
        "value,expected",
        [(b"", None), (b"\x00\x00\x01", None), (b"\x00\x00\x00\x01", 1)],
    )
    def test_a_short_capabilities_value_is_none(self, value, expected):
        """Answer None for a mask shorter than 4 bytes."""
        assert CDP(2, 180, 0, (CDPTLV(4, value),)).capabilities == expected

    def test_bytes_past_the_capabilities_mask_are_ignored(self):
        """Read only the first 4 bytes of the Capabilities value."""
        cdp = CDP(2, 180, 0, (CDPTLV(4, b"\x00\x00\x00\x29\xff"),))
        assert cdp.capabilities == 0x29
        assert cdp.capability_names == ("Router", "Switch", "IGMP capable")

    def test_every_capability_bit_is_named(self):
        """Name the eleven bits Wireshark names, and no others."""
        cdp = CDP(2, 180, 0, (CDPTLV(4, b"\xff\xff\xff\xff"),))
        assert cdp.capability_names == (
            "Router",
            "Transparent Bridge",
            "Source Route Bridge",
            "Switch",
            "Host",
            "IGMP capable",
            "Repeater",
            "VoIP Phone",
            "Remotely Managed Device",
            "CVTA/STP Dispute Resolution/Cisco VT Camera",
            "Two Port Mac Relay",
        )

    @pytest.mark.parametrize(
        "tlv_type,name",
        [
            (0x0000, "unknown (0x0000)"),
            (0x000C, "unknown (0x000c)"),
            (0x0016, "Management Address"),
            (0x001F, "Spare PoE"),
            (0x1000, "BSSID"),
            (0x100D, "Radio2 Radio mode"),
            (0xFFFF, "unknown (0xffff)"),
        ],
    )
    def test_type_names(self, tlv_type, name):
        """Name types from Wireshark's table; others read as unknown."""
        assert CDPTLV(tlv_type).type_name == name

    def test_the_tables_are_wiresharks(self):
        """Pin every type name and capability bit to Wireshark's."""
        assert _TLV_TYPE_NAMES == WIRESHARK_TLV_TYPE_NAMES
        assert len(_TLV_TYPE_NAMES) == 39
        for tlv_type, name in WIRESHARK_TLV_TYPE_NAMES.items():
            assert CDPTLV(tlv_type).type_name == name
        assert _CAPABILITY_NAMES == WIRESHARK_CAPABILITY_NAMES
        assert len(_CAPABILITY_NAMES) == 11


class TestAddresses:
    @staticmethod
    def addresses(value: bytes, tlv_type: int = 2):
        """Return the addresses of a PDU holding one TLV of ``value``."""
        cdp = CDP(2, 180, 0, (CDPTLV(tlv_type, value),))
        return cdp.addresses if tlv_type == 2 else cdp.management_addresses

    def test_an_ipv6_address(self):
        """Parse an 802.2-form address of EtherType 0x86DD as IPv6."""
        (address,) = self.addresses(b"\x00\x00\x00\x01" + IPV6_ENTRY)
        assert address.protocol_type_name == "802.2"
        assert address.protocol == b"\xaa\xaa\x03\x00\x00\x00\x86\xdd"
        assert address.ip == "2001:db8::1"
        assert bytes(address) == IPV6_ENTRY

    def test_two_addresses_and_the_management_tlv(self):
        """Parse two addresses from a Management Address TLV."""
        ipv4 = LLDPD_ADDRESSES[4:]
        value = b"\x00\x00\x00\x02" + ipv4 + IPV6_ENTRY
        both = self.addresses(value, 0x16)
        assert [a.ip for a in both] == ["10.9.30.1", "2001:db8::1"]
        assert b"".join(bytes(a) for a in both) == value[4:]

    @pytest.mark.parametrize(
        "entry",
        [
            b"\x01\x01\xcc\x00\x03\x0a\x09\x1e",  # IPv4 NLPID, 3 bytes
            b"\x01\x01\x8e\x00\x04\x0a\x09\x1e\x01",  # NLPID 0x8E (IPv6)
            b"\x02\x01\xcc\x00\x04\x0a\x09\x1e\x01",  # 802.2, NLPID byte
            b"\x02\x08\xaa\xaa\x03\x00\x00\x00\x08\x00\x00\x04\x0a\x09\x1e\x01",
            b"\x03\x01\xcc\x00\x04\x0a\x09\x1e\x01",  # unknown type
            IPV6_ENTRY[:10] + b"\x00\x0b" + IPV6_ENTRY[-11:],  # 11 bytes
            b"\x01\x00\x00\x00",  # empty protocol and address
            b"\x01\x01\xcc\x00\x05\x0a\x09\x1e\x01\x02",  # IPv4 NLPID, 5
            IPV6_ENTRY[:10] + b"\x00\x11" + IPV6_ENTRY[-16:] + b"\x02",
            b"\x01" + IPV6_ENTRY[1:],  # NLPID type, 802.2 IPv6 protocol
        ],
        ids=[
            "v4-3",
            "nlpid-8e",
            "8022-short",
            "8022-0800",
            "type-3",
            "v6-11",
            "empty",
            "v4-5",
            "v6-17",
            "nlpid-8022-v6",
        ],
    )
    def test_other_forms_have_no_ip(self, entry):
        """Keep other protocols and lengths, with no ip."""
        (address,) = self.addresses(b"\x00\x00\x00\x01" + entry)
        assert address.ip is None
        assert bytes(address) == entry

    def test_protocol_type_names(self):
        """Name a protocol type packet-cdp.c does not list as unknown."""
        assert CDPAddress(3, b"", b"").protocol_type_name == "unknown (3)"

    def test_a_count_of_zero(self):
        """Parse a count of zero as no addresses."""
        assert self.addresses(b"\x00\x00\x00\x00") == ()

    def test_bytes_past_the_counted_addresses_are_ignored(self):
        """Ignore bytes after the last address counted."""
        addresses = self.addresses(LLDPD_ADDRESSES + b"junk")
        assert [a.ip for a in addresses] == ["10.9.30.1"]

    @pytest.mark.parametrize(
        "value",
        [
            b"",
            b"\x00\x00\x00",
            b"\x00\x00\x00\x01",
            b"\x00\x00\x00\x01\x01",
            b"\x00\x00\x00\x01\x01\x01",
            b"\x00\x00\x00\x01\x01\x01\xcc",
            b"\x00\x00\x00\x01\x01\x01\xcc\x00",
            b"\x00\x00\x00\x01\x01\x01\xcc\x00\x04\x0a\x09\x1e",
            LLDPD_ADDRESSES[:3] + b"\x02" + LLDPD_ADDRESSES[4:],
        ],
        ids=[
            "empty",
            "count-3",
            "no-entry",
            "type",
            "plen",
            "protocol",
            "alen-1",
            "address-3",
            "count-2",
        ],
    )
    def test_a_malformed_value_is_none(self, value):
        """Answer None for a count or an address cut short."""
        assert self.addresses(value) is None

    def test_a_count_past_the_entries_is_none(self):
        """Each entry takes at least 4 bytes, so a huge count ends."""
        value = b"\xff\xff\xff\xff" + b"\x01\x00\x00\x00" * 3
        assert self.addresses(value) is None


class _SliceCountingBytes(bytes):
    """Bytes that count how many bytes their slices and indexes return.

    ``struct.unpack_from`` reads through the buffer protocol, not
    ``__getitem__``, so it is not counted; it reads 4 bytes a TLV.
    """

    read = 0

    def __getitem__(self, key):
        """Return ``bytes(self)[key]``, adding its length to the count."""
        result = bytes(self)[key]
        type(self).read += len(result) if isinstance(key, slice) else 1
        return result


class TestDecodeCost:
    """A 64 KiB PDU of empty TLVs, and an address count of 2**32 - 1.

    A wall-clock bound would be flaky under coverage tracing, so the
    bytes read by slicing and indexing are counted instead: they must
    stay linear in the input's length.
    """

    COUNT = 16000
    BODY = b"\x00\x04\x00\x04" * COUNT
    #: 65000 bytes of 1-byte TLVs, whose values decode slices out.
    VALUED = b"\x00\x04\x00\x05\x01" * 13000

    def test_a_64_kib_pdu_of_empty_tlvs_decodes(self):
        """Decode 16000 empty TLVs and pack them back."""
        cdp = CDP.decode(b"\x02\xb4\x00\x00" + self.BODY)
        assert len(cdp.tlvs) == self.COUNT
        assert cdp.header_len == 4 + len(self.BODY)
        assert bytes(cdp) == b"\x02\xb4\x00\x00" + self.BODY

    @pytest.mark.parametrize("tail", [b"", bytes(46)], ids=["bare", "padded"])
    def test_decode_reads_the_buffer_a_bounded_number_of_times(self, tail):
        """Read the buffer at most once, padded or not."""
        data = _SliceCountingBytes(b"\x02\xb4\x00\x00" + self.VALUED + tail)
        _SliceCountingBytes.read = 0
        cdp = CDP.decode(data)
        assert len(cdp.tlvs) == 13000
        assert 0 < _SliceCountingBytes.read <= len(data)

    def test_a_nonzero_byte_after_padding_is_found_in_one_scan(self):
        """Scan the tail once, on the way out, before raising for it."""
        data = _SliceCountingBytes(
            b"\x02\xb4\x00\x00" + self.VALUED + bytes(46) + b"\x01"
        )
        _SliceCountingBytes.read = 0
        with pytest.raises(InvalidFieldError) as excinfo:
            CDP.decode(data)
        assert excinfo.value.offset == 4 + len(self.VALUED)
        assert 0 < _SliceCountingBytes.read <= len(data)

    def test_a_huge_address_count_reads_the_value_once(self):
        """End a count of 2**32 - 1 when the value runs out."""
        value = _SliceCountingBytes(
            b"\xff\xff\xff\xff" + b"\x01\x00\x00\x00" * self.COUNT
        )
        cdp = CDP(2, 180, 0, (CDPTLV(2, value),))
        _SliceCountingBytes.read = 0
        assert cdp.addresses is None
        assert 0 < _SliceCountingBytes.read <= 2 * len(value)

    def test_many_addresses_parse(self):
        """Parse 16000 minimal addresses."""
        value = (self.COUNT).to_bytes(4) + b"\x01\x00\x00\x00" * self.COUNT
        cdp = CDP(2, 180, 0, (CDPTLV(0x16, value),))
        assert len(cdp.management_addresses) == self.COUNT


def test_replace_keeps_a_valid_pdu():
    """``dataclasses.replace`` re-validates, as construction does."""
    cdp = CDP.decode(pdu_of(CDPV1))
    with pytest.raises(InvalidFieldError):
        replace(cdp, ttl=300)
    assert Packet(replace(cdp, ttl=0))[CDP].ttl == 0
