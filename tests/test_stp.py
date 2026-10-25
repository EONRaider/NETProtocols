"""Test STP: Configuration, TCN and RST BPDUs (IEEE 802.1D, 802.1w).

The Configuration and TCN BPDUs are real: tests/fixtures/llc.pcap holds
five a Linux bridge sent (see its MANIFEST entry). No RST BPDU was
captured, since the kernel's bridge speaks 802.1D only and mstpd is not
installable here, so the RST BPDUs below are built by hand from the
encoding in the module docstring. The padding and FCS cases are built
here as well, since veth neither pads nor carries an FCS.
"""

from __future__ import annotations

import importlib.util
import struct
from collections import Counter
from pathlib import Path

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    LLC,
    STP,
    Ethernet,
    InvalidFieldError,
    InvalidMACAddressError,
    Registry,
    RegistryConflictError,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import TABLE_LLC_DSAP

(
    STP_CONFIG_B,
    STP_CONFIG_A,
    STP_CONFIG_A_TC,
    STP_TCN,
    STP_CONFIG_A_TC_TCA,
) = pcap_frames(FIXTURES / "llc.pcap")[:5]
FIXTURE_FRAMES = [
    STP_CONFIG_B,
    STP_CONFIG_A,
    STP_CONFIG_A_TC,
    STP_TCN,
    STP_CONFIG_A_TC_TCA,
]

DST = bytes.fromhex("0180c2000000")
SRC = bytes.fromhex("02000000a001")
LLC_UI = b"\x42\x42\x03"
FCS = b"\xde\xad\xbe\xef"


def bpdu_of(frame: bytes) -> bytes:
    """Return the BPDU of an 802.3 frame, the bytes its Length covers."""
    (length,) = struct.unpack_from("!H", frame, 12)
    return frame[17 : 14 + length]


def frame_8023(pdu: bytes, length: int | None = None) -> bytes:
    """Build an 802.3 frame carrying ``pdu``, its Length ``len(pdu)``."""
    value = len(pdu) if length is None else length
    return DST + SRC + struct.pack("!H", value) + pdu


def pad(frame: bytes) -> bytes:
    """Zero-pad ``frame`` to Ethernet's 60-byte minimum, as a NIC does."""
    return frame + bytes(max(0, 60 - len(frame)))


CONFIG_A_TC = bpdu_of(STP_CONFIG_A_TC)
TCN = bpdu_of(STP_TCN)


def rst(flags: int, *, version: int = 2, version_1_length: int = 0) -> bytes:
    """Build an RST BPDU on the root's Configuration BPDU.

    Its Protocol Version, type and Flags replaced and a Version 1
    Length appended.
    """
    return (
        b"\x00\x00"
        + bytes((version, 0x02, flags))
        + CONFIG_A_TC[5:]
        + bytes((version_1_length,))
    )


#: An RST BPDU from a designated port that is forwarding and learning,
#: with Agreement and Topology Change set: 0x01 | 0x0C | 0x10 | 0x20 |
#: 0x40.
RST_DESIGNATED = rst(0x7D)

#: The fields every fixture Configuration BPDU from bridge A carries.
A_FIELDS = {
    "root_priority": 0x1000,
    "root_mac": "02:00:00:00:a0:00",
    "root_path_cost": 0,
    "bridge_priority": 0x1000,
    "bridge_mac": "02:00:00:00:a0:00",
    "port_id": 0x8001,
    "message_age": 0,
    "max_age": 20 * 256,
    "hello_time": 256,
    "forward_delay": 2 * 256,
}


def config_fields(**overrides: object) -> dict[str, object]:
    """Return constructor arguments of A's Configuration BPDU, changed."""
    fields: dict[str, object] = {
        "protocol_id": 0,
        "version": 0,
        "bpdu_type": 0x00,
        "flags": 0,
        **A_FIELDS,
    }
    fields.update(overrides)
    return fields


class TestTheFixture:
    @pytest.mark.parametrize(
        "frame",
        FIXTURE_FRAMES,
        ids=["config-b", "config-a", "config-a-tc", "tcn", "config-a-tc-tca"],
    )
    def test_every_bpdu_walks_to_stp_and_round_trips(self, frame):
        """Test that every BPDU walks to STP and round-trips."""
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, LLC, STP]
        assert packet.consumed == len(frame)
        assert bytes(packet) == frame
        stp = packet[STP]
        assert bytes(STP.decode(bpdu_of(frame))) == bpdu_of(frame)
        assert stp.header_len == len(bpdu_of(frame))
        assert STP.decode(bytes(stp)) == stp

    def test_bridge_b_first_claims_to_be_root(self):
        """B's first BPDU, before it hears A's, names itself root."""
        stp = decode_frame(STP_CONFIG_B)[STP]
        assert stp.bpdu_type == 0x00
        assert stp.bpdu_type_name == "Configuration"
        assert stp.version == 0
        assert stp.version_name == "Spanning Tree"
        assert stp.root_priority == stp.bridge_priority == 0x8000
        assert stp.root_mac == stp.bridge_mac == "02:00:00:00:b0:00"
        assert stp.root_id_str == "32768/0/02:00:00:00:b0:00"
        assert stp.flags == 0
        assert stp.topology_change is False
        assert stp.topology_change_ack is False

    @pytest.mark.parametrize(
        "frame,flags,tc,tca",
        [
            (STP_CONFIG_A, 0x00, False, False),
            (STP_CONFIG_A_TC, 0x01, True, False),
            (STP_CONFIG_A_TC_TCA, 0x81, True, True),
        ],
        ids=["plain", "tc", "tc-tca"],
    )
    def test_the_roots_bpdus(self, frame, flags, tc, tca):
        """Test the root's BPDUs."""
        stp = decode_frame(frame)[STP]
        assert stp == STP(**config_fields(flags=flags))
        assert stp.topology_change is tc
        assert stp.topology_change_ack is tca
        assert stp.root_priority_component == 4096
        assert stp.root_system_id_extension == 0
        assert stp.bridge_id_str == "4096/0/02:00:00:00:a0:00"
        assert stp.port_priority == 128
        assert stp.port_number == 1
        assert stp.message_age_seconds == 0.0
        assert stp.max_age_seconds == 20.0
        assert stp.hello_time_seconds == 1.0
        assert stp.forward_delay_seconds == 2.0
        assert stp.version_1_length is None
        for name in ("proposal", "learning", "forwarding", "agreement"):
            assert getattr(stp, name) is None, name
        assert stp.port_role is None
        assert stp.port_role_name is None

    def test_the_tcn_is_the_short_form(self):
        """Test the TCN is the short form."""
        stp = decode_frame(STP_TCN)[STP]
        assert stp == STP(protocol_id=0, version=0, bpdu_type=0x80)
        assert stp.header_len == 4
        assert stp.bpdu_type_name == "Topology Change Notification"
        assert bytes(stp) == b"\x00\x00\x00\x80"
        for name in (
            "flags",
            "root_mac",
            "topology_change",
            "topology_change_ack",
            "root_id_str",
            "port_priority",
            "hello_time_seconds",
            "root_priority_component",
            "bridge_system_id_extension",
        ):
            assert getattr(stp, name) is None, name


class TestRSTBPDUs:
    """RST BPDUs, built here: the kernel bridge sends none."""

    def test_an_rst_bpdu(self):
        """Test an RST BPDU."""
        stp = STP.decode(RST_DESIGNATED)
        assert stp.header_len == 36
        assert bytes(stp) == RST_DESIGNATED
        assert stp.bpdu_type == 0x02
        assert stp.bpdu_type_name == "Rapid/Multiple Spanning Tree"
        assert stp.version_name == "Rapid Spanning Tree"
        assert stp.version_1_length == 0
        assert stp.topology_change is True
        assert stp.proposal is False
        assert stp.port_role == 3
        assert stp.port_role_name == "Designated"
        assert (stp.learning, stp.forwarding, stp.agreement) == (
            True,
            True,
            True,
        )
        assert stp.topology_change_ack is None
        assert stp.root_id_str == "4096/0/02:00:00:00:a0:00"
        assert stp == STP(
            **config_fields(
                version=2, bpdu_type=0x02, flags=0x7D, version_1_length=0
            )
        )

    @pytest.mark.parametrize(
        "role,name",
        [
            (0, "Unknown"),
            (1, "Alternate or Backup"),
            (2, "Root"),
            (3, "Designated"),
        ],
    )
    def test_every_port_role(self, role, name):
        """Test every port role."""
        stp = STP.decode(rst(role << 2))
        assert stp.port_role == role
        assert stp.port_role_name == name
        assert stp.topology_change is False

    @pytest.mark.parametrize(
        "bit,accessor",
        [
            (0x01, "topology_change"),
            (0x02, "proposal"),
            (0x10, "learning"),
            (0x20, "forwarding"),
            (0x40, "agreement"),
        ],
    )
    def test_each_flag_alone(self, bit, accessor):
        """Test each flag alone."""
        stp = STP.decode(rst(bit))
        flags = ("topology_change", "proposal", "learning", "forwarding")
        for name in (*flags, "agreement"):
            assert getattr(stp, name) is (name == accessor), name
        assert stp.port_role == 0

    def test_the_unused_tca_bit_is_carried_but_not_read(self):
        """Bit 8 is unused in an RST BPDU: carried raw, read as None."""
        stp = STP.decode(rst(0x80))
        assert stp.flags == 0x80
        assert stp.topology_change_ack is None
        assert bytes(stp) == rst(0x80)

    def test_a_nonzero_version_1_length_is_carried(self):
        """Test a nonzero version 1 length is carried."""
        stp = STP.decode(rst(0, version_1_length=7))
        assert stp.version_1_length == 7
        assert bytes(stp) == rst(0, version_1_length=7)

    @pytest.mark.parametrize("version", [0, 1, 4, 0xFF])
    def test_the_layout_follows_the_type_not_the_version(self, version):
        """Test that the layout follows the type, not the version."""
        stp = STP.decode(rst(0x0C, version=version))
        assert stp.version == version
        assert stp.header_len == 36
        assert stp.port_role_name == "Designated"

    def test_an_unnamed_version(self):
        """Test an unnamed version."""
        assert STP.decode(rst(0, version=9)).version_name == "unknown (9)"

    def test_a_configuration_bpdu_of_version_2_is_still_one(self):
        """Type 0x00 is a Configuration BPDU whatever the version says."""
        bpdu = b"\x00\x00\x02" + CONFIG_A_TC[3:]
        stp = STP.decode(bpdu)
        assert stp.header_len == 35
        assert stp.version_1_length is None
        assert stp.topology_change_ack is False

    def test_a_system_id_extension(self):
        """802.1t: priority 32768 plus VLAN 100 in the extension."""
        bpdu = rst(0)[:5] + b"\x80\x64" + rst(0)[7:]
        stp = STP.decode(bpdu)
        assert stp.root_priority == 0x8064
        assert stp.root_priority_component == 32768
        assert stp.root_system_id_extension == 100
        assert stp.root_id_str == "32768/100/02:00:00:00:a0:00"
        assert stp.bridge_priority_component == 4096
        assert stp.bridge_system_id_extension == 0

    def test_an_rst_bpdu_walks(self):
        """Test an RST BPDU walks."""
        frame = pad(frame_8023(LLC_UI + RST_DESIGNATED)) + FCS
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, LLC, STP]
        assert packet[STP] == STP.decode(RST_DESIGNATED)
        assert packet.consumed == 14 + 3 + 36


class TestMSTBPDUs:
    """MSTP is decoded only as far as its RST prefix (see the module)."""

    #: An MST BPDU with no MSTI messages: the RST prefix with version
    #: 3, a Version 3 Length of 64 and 64 octets of MST information
    #: (format selector, name, revision, digest, CIST internal root path
    #: cost, CIST bridge identifier, remaining hops).
    MST = (
        rst(0x0C, version=3)
        + b"\x00\x40"
        + b"\x00"
        + b"npstp".ljust(32, b"\x00")
        + bytes(31)
    )

    def test_the_version_3_information_is_left_undecoded(self):
        """Test the version 3 information is left undecoded."""
        assert len(self.MST) == 102
        stp = STP.decode(self.MST)
        assert stp.version == 3
        assert stp.version_name == "Multiple Spanning Tree"
        assert stp.header_len == 36
        assert bytes(stp) == self.MST[:36]

    def test_in_a_walk_it_ends_the_walk_after_36_octets(self):
        """Test that in a walk the BPDU ends the walk after 36 octets."""
        frame = frame_8023(LLC_UI + self.MST) + FCS
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, LLC, STP]
        assert packet.consumed == 14 + 3 + 36
        assert bytes(packet) == frame[: packet.consumed]


class TestTrailingBytes:
    @pytest.mark.parametrize(
        "bpdu", [CONFIG_A_TC, TCN, RST_DESIGNATED], ids=["config", "tcn", "rst"]
    )
    def test_padding_and_an_fcs_stay_outside_a_direct_decode(self, bpdu):
        """Test padding and an FCS stay outside a direct decode."""
        expected = STP.decode(bpdu)
        for trailer in [bytes(n) for n in range(47)] + [FCS, bytes(8) + FCS]:
            stp = STP.decode(bpdu + trailer)
            assert stp == expected, trailer
            assert stp.header_len == len(bpdu), trailer
            assert bytes(stp) == (bpdu + trailer)[: stp.header_len]

    @pytest.mark.parametrize(
        "frame", FIXTURE_FRAMES, ids=["b", "a", "a-tc", "tcn", "a-tc-tca"]
    )
    def test_padding_and_an_fcs_never_reach_the_decoder_in_a_walk(self, frame):
        """Test padding and an FCS never reach the decoder in a walk."""
        packet = decode_frame(pad(frame) + FCS)
        assert packet[STP] == decode_frame(frame)[STP]
        assert packet.consumed == len(frame)

    def test_octets_past_a_configuration_bpdu_are_ignored(self):
        """A longer PDU: the extra octets stay after header_len.

        As a Cisco PVST+ BPDU's Originating VLAN TLV follows its
        Configuration BPDU (Wireshark's dissect_bpdu_pvst_tlv).
        """
        extra = b"\x00\x00\x00\x02\x00\x1e"
        frame = frame_8023(LLC_UI + CONFIG_A_TC + extra)
        packet = decode_frame(frame)
        assert packet[STP] == STP.decode(CONFIG_A_TC)
        assert packet.consumed == len(frame) - len(extra)
        assert bytes(packet) == frame[: packet.consumed]


class TestHostileInput:
    def test_a_64_kib_tail_is_not_read(self):
        """Decode reads its type's octets, never the rest of the buffer.

        Indexing and slicing past the fixed prefix are counted: an RST
        BPDU's decode reads the one Version 1 Length octet and nothing
        else that way, whatever follows.
        """

        class Counting(bytes):
            reads = 0

            def __getitem__(self, key):
                Counting.reads += 1
                return super().__getitem__(key)

        for bpdu, reads in ((CONFIG_A_TC, 0), (RST_DESIGNATED, 1), (TCN, 0)):
            Counting.reads = 0
            stp = STP.decode(Counting(bpdu + bytes(65536)))
            assert stp == STP.decode(bpdu)
            assert Counting.reads == reads

    def test_a_memoryview_is_not_retained(self):
        """Test a memoryview is not retained."""
        buffer = bytearray(RST_DESIGNATED + FCS)
        stp = STP.decode(memoryview(buffer))
        before = STP.decode(RST_DESIGNATED)
        buffer[:] = bytes(len(buffer))
        assert stp == before
        assert bytes(stp) == RST_DESIGNATED
        assert isinstance(stp.root_mac, str)


class TestTruncation:
    @pytest.mark.parametrize("length", [0, 1, 2, 3])
    def test_shorter_than_the_prefix(self, length):
        """Test a buffer shorter than the 4-byte prefix."""
        with pytest.raises(TruncatedHeaderError) as excinfo:
            STP.decode(TCN[:length])
        assert excinfo.value.protocol is STP
        assert excinfo.value.expected == 4

    @pytest.mark.parametrize(
        "bpdu,needed",
        [(CONFIG_A_TC, 35), (RST_DESIGNATED, 36)],
        ids=["config", "rst"],
    )
    @pytest.mark.parametrize("short", [1, 2, 31])
    def test_shorter_than_the_type_needs(self, bpdu, needed, short):
        """Test a buffer shorter than its type needs."""
        with pytest.raises(TruncatedHeaderError) as excinfo:
            STP.decode(bpdu[: needed - short])
        error = excinfo.value
        assert (error.field, error.offset) == ("bpdu_type", 0)
        assert (error.expected, error.actual) == (needed, needed - short)

    def test_a_tcn_needs_only_its_prefix(self):
        """Test a TCN needs only its prefix."""
        assert STP.decode(TCN).header_len == 4

    def test_a_length_cutting_the_bpdu_raises_in_a_walk(self):
        """Test a length cutting the BPDU raises in a walk."""
        frame = pad(frame_8023(LLC_UI + CONFIG_A_TC, 3 + 34)) + FCS
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.protocol is STP
        assert excinfo.value.frame_offset == 17
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, LLC]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)


class TestRejectedBPDUs:
    @pytest.mark.parametrize("bpdu_type", [0x01, 0x03, 0x7F, 0x81, 0xFF])
    def test_an_unknown_type(self, bpdu_type):
        """Test an unknown type."""
        bpdu = b"\x00\x00\x00" + bytes((bpdu_type,)) + CONFIG_A_TC[4:]
        with pytest.raises(InvalidFieldError) as excinfo:
            STP.decode(bpdu)
        error = excinfo.value
        assert (error.field, error.offset, error.actual) == (
            "bpdu_type",
            3,
            bpdu_type,
        )

    @pytest.mark.parametrize("protocol_id", [1, 0x0100, 0xFFFF])
    def test_an_unknown_protocol_identifier(self, protocol_id):
        """Test an unknown protocol identifier."""
        bpdu = struct.pack("!H", protocol_id) + CONFIG_A_TC[2:]
        with pytest.raises(InvalidFieldError) as excinfo:
            STP.decode(bpdu)
        error = excinfo.value
        assert (error.field, error.offset, error.actual) == (
            "protocol_id",
            0,
            protocol_id,
        )

    @pytest.mark.parametrize(
        "bpdu,field,frame_offset",
        [
            (b"\x00\x00\x00\x01", "bpdu_type", 20),
            (b"\x00\x01\x00\x80", "protocol_id", 17),
        ],
        ids=["type", "protocol-id"],
    )
    def test_in_a_walk(self, bpdu, field, frame_offset):
        """Test both rejections in a frame walk, strict and lax."""
        frame = pad(frame_8023(LLC_UI + bpdu))
        with pytest.raises(InvalidFieldError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.field == field
        assert excinfo.value.frame_offset == frame_offset
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, LLC]
        assert isinstance(packet.stopped_by, InvalidFieldError)


class Own(STP):
    """A third party's BPDU decoder, for the registration tests."""

    __slots__ = ()


class TestDispatch:
    def test_dsap_0x42_dispatches_to_stp(self):
        """Test DSAP 0x42 dispatches to STP."""
        llc = LLC(dsap=0x42, ssap=0x42, control=0x03)
        assert llc.next_protocol() is STP
        assert llc.next_protocol(Registry.from_defaults()) is STP
        assert Registry.from_defaults().get(TABLE_LLC_DSAP, 0x42) is STP

    def test_a_decoder_of_ones_own_needs_override_or_a_registry(self):
        """Test the CHANGELOG's migration advice for DSAP 0x42."""
        registry = Registry.from_defaults()
        with pytest.raises(RegistryConflictError):
            registry.register(TABLE_LLC_DSAP, 0x42, Own)
        registry.register(TABLE_LLC_DSAP, 0x42, Own, override=True)
        assert registry.get(TABLE_LLC_DSAP, 0x42) is Own
        derived = Registry.from_defaults().derive({TABLE_LLC_DSAP: {0x42: Own}})
        assert derived.get(TABLE_LLC_DSAP, 0x42) is Own
        packet = decode_frame(
            STP_CONFIG_A, decode_as={TABLE_LLC_DSAP: {0x42: Own}}
        )
        assert isinstance(packet.layers[-1], Own)
        assert Registry.from_defaults().get(TABLE_LLC_DSAP, 0x42) is STP

    def test_the_ssap_is_not_checked(self):
        """Test that a UI PDU at DSAP 0x42 reaches STP from any SSAP."""
        assert LLC(dsap=0x42, ssap=0x43, control=0x03).next_protocol() is STP
        assert LLC(dsap=0x42, ssap=0x00, control=0x00).next_protocol() is STP

    def test_stp_is_terminal(self):
        """Test STP is terminal."""
        assert STP.decode(CONFIG_A_TC).next_protocol() is None
        assert STP.decode(TCN).next_protocol(Registry.from_defaults()) is None

    def test_only_ui_and_i_format_pdus_reach_it(self):
        """An XID at DSAP 0x42 carries no BPDU and ends at LLC."""
        frame = pad(frame_8023(b"\x42\x42\xaf" + bytes(3)))
        assert [type(layer) for layer in decode_frame(frame)] == [
            Ethernet,
            LLC,
        ]

    def test_an_empty_registry_ends_the_walk_at_llc(self):
        """Ethernet names LLC itself; the BPDU needs the llc.dsap entry."""
        packet = decode_frame(STP_CONFIG_A, registry=Registry())
        assert [type(layer) for layer in packet] == [Ethernet, LLC]


class TestConstruction:
    def test_a_tcn(self):
        """Test building a TCN."""
        tcn = STP(protocol_id=0, version=0, bpdu_type=0x80)
        assert bytes(tcn) == TCN

    def test_a_configuration_bpdu(self):
        """Test building a Configuration BPDU."""
        assert bytes(STP(**config_fields(flags=1))) == CONFIG_A_TC

    @pytest.mark.parametrize(
        "fields,field",
        [
            ({"protocol_id": 1}, "protocol_id"),
            ({"bpdu_type": 0x01}, "bpdu_type"),
            ({"version": 0x100}, "version"),
            ({"version": -1}, "version"),
            ({"flags": 0x100}, "flags"),
            ({"root_priority": 0x10000}, "root_priority"),
            ({"root_path_cost": 1 << 32}, "root_path_cost"),
            ({"bridge_priority": -1}, "bridge_priority"),
            ({"port_id": 0x10000}, "port_id"),
            ({"message_age": 0x10000}, "message_age"),
            ({"max_age": -1}, "max_age"),
            ({"hello_time": 0x10000}, "hello_time"),
            ({"forward_delay": 0x10000}, "forward_delay"),
            ({"version_1_length": 0}, "version_1_length"),
            ({"flags": None}, "flags"),
            ({"root_mac": None}, "root_mac"),
            ({"bridge_mac": None}, "bridge_mac"),
            ({"forward_delay": None}, "forward_delay"),
            (
                {"bpdu_type": 0x02, "version_1_length": 0x100},
                "version_1_length",
            ),
            ({"bpdu_type": 0x02}, "version_1_length"),
        ],
    )
    def test_the_constructor_rejects(self, fields, field):
        """Test what the constructor rejects."""
        with pytest.raises(InvalidFieldError) as excinfo:
            STP(**config_fields(**fields))
        assert excinfo.value.field == field

    @pytest.mark.parametrize(
        "field", ["flags", "root_mac", "port_id", "version_1_length"]
    )
    def test_a_tcn_carries_nothing_after_its_type(self, field):
        """Test a TCN carries nothing after its type."""
        value = "02:00:00:00:a0:00" if field == "root_mac" else 0
        with pytest.raises(InvalidFieldError) as excinfo:
            STP(protocol_id=0, version=0, bpdu_type=0x80, **{field: value})
        assert excinfo.value.field == field
        assert excinfo.value.offset is None

    @pytest.mark.parametrize("field", ["root_mac", "bridge_mac"])
    def test_a_mac_is_validated(self, field):
        """Test a MAC is validated."""
        with pytest.raises(InvalidMACAddressError) as excinfo:
            STP(**config_fields(**{field: "02:00:00:00:a0"}))
        assert excinfo.value.field == field

    def test_a_mac_with_dashes_decodes_with_colons(self):
        """Test a MAC with dashes decodes with colons."""
        stp = STP(**config_fields(root_mac="02-00-00-00-A0-00", flags=1))
        assert bytes(stp) == CONFIG_A_TC
        assert STP.decode(bytes(stp)).root_mac == "02:00:00:00:a0:00"


CHECKER = Path(__file__).resolve().parent.parent / "scripts/check_fixtures.py"


@pytest.fixture(scope="module")
def check_fixtures():
    """Load scripts/check_fixtures.py, which shares no library code."""
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestTheChecker:
    """check_fixtures.py validates BPDUs independently of the library."""

    @pytest.mark.parametrize(
        "frame,kind",
        [
            (STP_CONFIG_A_TC_TCA, "stp-config"),
            (STP_TCN, "stp-tcn"),
            (pad(frame_8023(LLC_UI + RST_DESIGNATED)), "stp-rst"),
            (frame_8023(LLC_UI + rst(0x80, version=3) + bytes(66)), "stp-rst"),
        ],
        ids=["config", "tcn", "rst", "mst"],
    )
    def test_good_bpdus_pass(self, check_fixtures, frame, kind):
        """Test good BPDUs pass."""
        stats = Counter()
        assert check_fixtures.check_frame(frame, stats) == []
        assert stats[kind] == stats["stp-bpdu"] == 1

    @pytest.mark.parametrize(
        "bpdu,failure",
        [
            (b"\x00\x00\x00\x01", "stp-bpdu-malformed"),
            (b"\x00\x01\x00\x80", "stp-bpdu-malformed"),
            (RST_DESIGNATED[:35], "stp-bpdu-malformed"),
            (CONFIG_A_TC[:4] + b"\x02" + CONFIG_A_TC[5:], "stp-config-unused"),
            (CONFIG_A_TC[:4] + b"\x40" + CONFIG_A_TC[5:], "stp-config-unused"),
            (rst(0, version=1), "stp-rst-malformed"),
            (rst(0, version_1_length=1), "stp-rst-malformed"),
        ],
        ids=[
            "type",
            "protocol-id",
            "rst-35",
            "config-proposal",
            "config-agreement",
            "rst-version-1",
            "version-1-length",
        ],
    )
    def test_tampered_bpdus_fail(self, check_fixtures, bpdu, failure):
        """Test tampered BPDUs fail."""
        frame = pad(frame_8023(LLC_UI + bpdu))
        failures = check_fixtures.check_frame(frame, Counter())
        assert any(f.startswith(failure) for f in failures), failures
