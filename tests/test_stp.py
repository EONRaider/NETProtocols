"""Test STP: Configuration, TCN, RST and MST BPDUs (IEEE 802.1D, 802.1Q).

The BPDUs of tests/fixtures/llc.pcap and tests/fixtures/stp.pcap are
real (see their MANIFEST entries): llc.pcap holds five Configuration
and TCN BPDUs a Linux bridge sent, and stp.pcap seventeen that mstpd
sent for four Linux bridges, MST, RST, Configuration and TCN BPDUs
among them. The MST BPDUs are checked against an independent ``struct``
decode of their bytes and against the topology
scripts/capture_fixtures_stp.sh sets up. The other RST and MST BPDUs
below are built by hand, each from the encoding in the module
docstring or by changing octets of a captured one, as is every padding
and FCS case, since veth neither pads nor carries an FCS.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import hmac
import importlib.util
import struct
from collections import Counter
from pathlib import Path

import pytest

from conftest import FIXTURES, allocation_peak, pcap_frames
from netprotocols import (
    LLC,
    SNAP,
    STP,
    VLAN,
    Ethernet,
    InvalidFieldError,
    InvalidMACAddressError,
    Registry,
    RegistryConflictError,
    STPMSTConfigurationIdentifier,
    STPMSTIMessage,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import TABLE_LLC_DSAP, TABLE_LLC_SNAP

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
    """RST BPDUs built here, every flag and role (stp.pcap's are below)."""

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


#: A BPDU from a bridge that is not the root, built here field by field
#: so that no two fields share a value an accessor could confuse: an
#: 802.1t root priority of 32768 with system ID extension 356 (0x8164),
#: a bridge priority of 36864 with extension 515 (0x9203), distinct
#: root and bridge MACs, Root Path Cost 100, Port Identifier 0x0401
#: (priority 0, Port Number 1025) and four distinct timers that are not
#: whole seconds.
NON_ROOT_FIELDS = (
    0x8164,
    bytes.fromhex("0200000000a1"),
    100,
    0x9203,
    bytes.fromhex("0200000000b2"),
    0x0401,
    0x0180,
    0x1340,
    0x0280,
    0x0F40,
)


def non_root(bpdu_type: int, version: int, flags: int) -> bytes:
    """Pack :data:`NON_ROOT_FIELDS` with ``struct``, not :class:`STP`."""
    head = struct.pack("!HBBB", 0, version, bpdu_type, flags)
    body = struct.pack("!H6sIH6sHHHHH", *NON_ROOT_FIELDS)
    return head + body + (b"\x00" if bpdu_type == 0x02 else b"")


#: What every field and accessor of :func:`non_root`'s BPDU reads, shared
#: by its Configuration and RST forms.
NON_ROOT_COMMON = {
    "protocol_id": 0,
    "root_priority": 0x8164,
    "root_mac": "02:00:00:00:00:a1",
    "root_path_cost": 100,
    "bridge_priority": 0x9203,
    "bridge_mac": "02:00:00:00:00:b2",
    "port_id": 0x0401,
    "message_age": 0x0180,
    "max_age": 0x1340,
    "hello_time": 0x0280,
    "forward_delay": 0x0F40,
    "root_priority_component": 32768,
    "root_system_id_extension": 356,
    "bridge_priority_component": 36864,
    "bridge_system_id_extension": 515,
    "root_id_str": "32768/356/02:00:00:00:00:a1",
    "bridge_id_str": "36864/515/02:00:00:00:00:b2",
    "port_priority": 0,
    "port_number": 1025,
    "message_age_seconds": 1.5,
    "max_age_seconds": 19.25,
    "hello_time_seconds": 2.5,
    "forward_delay_seconds": 15.25,
    "mst": b"",
    "version_3_length": None,
    "mst_config_id": None,
    "cist_internal_root_path_cost": None,
    "cist_bridge_priority": None,
    "cist_bridge_mac": None,
    "cist_bridge_id_str": None,
    "cist_remaining_hops": None,
    "msti_messages": None,
}

#: A Configuration BPDU with Topology Change and its Acknowledgment set
#: (0x81), and an RST BPDU from a designated port with Topology Change,
#: Learning, Forwarding and Agreement set (0x7D): what each reads beyond
#: :data:`NON_ROOT_COMMON`.
NON_ROOT_CASES = {
    "config": (
        (0x00, 0, 0x81),
        {
            "version": 0,
            "bpdu_type": 0x00,
            "flags": 0x81,
            "version_1_length": None,
            "header_len": 35,
            "bpdu_type_name": "Configuration",
            "version_name": "Spanning Tree",
            "topology_change": True,
            "topology_change_ack": True,
            "proposal": None,
            "learning": None,
            "forwarding": None,
            "agreement": None,
            "port_role": None,
            "port_role_name": None,
        },
    ),
    "rst": (
        (0x02, 2, 0x7D),
        {
            "version": 2,
            "bpdu_type": 0x02,
            "flags": 0x7D,
            "version_1_length": 0,
            "header_len": 36,
            "bpdu_type_name": "Rapid/Multiple Spanning Tree",
            "version_name": "Rapid Spanning Tree",
            "topology_change": True,
            "topology_change_ack": None,
            "proposal": False,
            "learning": True,
            "forwarding": True,
            "agreement": True,
            "port_role": 3,
            "port_role_name": "Designated",
        },
    ),
}


def _public_attributes() -> set[str]:
    """Every dataclass field and public property :class:`STP` has."""
    properties = {
        name
        for name in dir(STP)
        if not name.startswith("_") and isinstance(getattr(STP, name), property)
    }
    return properties | {field.name for field in dataclasses.fields(STP)}


class TestAccessors:
    """Every field and accessor on a non-root BPDU."""

    @pytest.mark.parametrize("case", NON_ROOT_CASES, ids=list(NON_ROOT_CASES))
    def test_a_non_root_bpdu(self, case):
        """Test each field and accessor against the value packed for it."""
        args, specific = NON_ROOT_CASES[case]
        expected = {**NON_ROOT_COMMON, **specific}
        raw = non_root(*args)
        stp = STP.decode(raw)
        assert bytes(stp) == raw
        assert stp.header_len == len(raw)
        actual = {name: getattr(stp, name) for name in expected}
        assert actual == expected
        for name, value in expected.items():
            assert type(actual[name]) is type(value), name

    def test_the_cases_pin_every_public_attribute(self):
        """A new field or accessor must be added to the expected values."""
        for _, specific in NON_ROOT_CASES.values():
            assert set(NON_ROOT_COMMON) | set(specific) == _public_attributes()

    @pytest.mark.parametrize(
        "port_id,priority,number",
        [(0x8001, 128, 1), (0xF0FF, 240, 255), (0x1FFF, 16, 4095)],
    )
    def test_the_port_identifier_splits_4_and_12(
        self, port_id, priority, number
    ):
        """802.1t's split, not Linux's 6 priority and 10 number bits."""
        fields = list(NON_ROOT_FIELDS)
        fields[5] = port_id
        raw = struct.pack("!HBBB", 0, 0, 0, 0) + struct.pack(
            "!H6sIH6sHHHHH", *fields
        )
        stp = STP.decode(raw)
        assert (stp.port_priority, stp.port_number) == (priority, number)

    @pytest.mark.parametrize(
        "version,name",
        [
            (0, "Spanning Tree"),
            (1, "unknown (1)"),
            (2, "Rapid Spanning Tree"),
            (3, "Multiple Spanning Tree"),
            (4, "Shortest Path Tree"),
            (5, "unknown (5)"),
        ],
    )
    def test_every_version_name(self, version, name):
        """Test Wireshark's version_id_vals names, and the fallback."""
        assert STP.decode(non_root(0x02, version, 0)).version_name == name


#: tests/fixtures/stp.pcap's frames, in capture order (see its MANIFEST
#: entry): ten MST BPDUs, two RST BPDUs from C, and D's and B's 802.1D
#: BPDUs.
STP_PCAP = pcap_frames(FIXTURES / "stp.pcap")

#: Each MST frame's index in stp.pcap and its sending port, as
#: scripts/capture_fixtures_stp.sh labels them: ``a`` is A's port to B,
#: ``b1``, ``b2`` and ``b3`` B's ports to A, C and D.
MST_SENDERS = {
    0: "a",
    1: "b1",
    2: "b1",
    3: "a",
    4: "a",
    5: "b1",
    7: "b2",
    9: "b2",
    10: "b2",
    12: "b3",
}
MST_FRAMES = [STP_PCAP[index] for index in MST_SENDERS]
RST_FRAMES = [STP_PCAP[6], STP_PCAP[8]]
OTHER_FRAMES = [STP_PCAP[index] for index in (11, 13, 14, 15, 16)]

#: The region scripts/capture_fixtures_stp.sh configures on A and B:
#: Name NETProtocols, Revision Level 7, VLANs 10-19 on MSTI 1 and 20-29
#: on MSTI 2. The digest is IEEE 802.1Q §13.8's HMAC-MD5, keyed by
#: 0x13AC06A62E47FD51F95D2BA243CD0346, over the 2-octet MSTID of each
#: VID 0-4095.
_VID_TABLE = bytearray(2 * 4096)
for _vid in range(10, 30):
    struct.pack_into("!H", _VID_TABLE, 2 * _vid, 1 if _vid < 20 else 2)
REGION_DIGEST = hmac.new(
    bytes.fromhex("13ac06a62e47fd51f95d2ba243cd0346"), _VID_TABLE, hashlib.md5
).digest()
BRIDGE_A = (0x1000, "02:00:00:00:a0:00")
BRIDGE_B = (0x8000, "02:00:00:00:b0:00")

#: Each sender's MSTI Bridge Priority octets for MSTIs 1 and 2: A's
#: tree priorities are 0 and 12 (x 4096), B's the default 8 and 2.
MSTI_BRIDGE_PRIORITIES = {"a": [0x00, 0xC0], "b": [0x80, 0x20]}


def mst_by_struct(bpdu: bytes) -> dict[str, object]:
    """Decode an MST BPDU's Version 3 information with ``struct`` alone."""
    (v3_length,) = struct.unpack_from("!H", bpdu, 36)
    selector, name, revision, digest = struct.unpack_from("!B32sH16s", bpdu, 38)
    cost, priority, mac, hops = struct.unpack_from("!IH6sB", bpdu, 89)
    mstis = [
        struct.unpack_from("!BH6sIBBB", bpdu, at)
        for at in range(102, 38 + v3_length, 16)
    ]
    return {
        "version_3_length": v3_length,
        "config_id": (selector, name, revision, digest),
        "cist": (cost, priority, ":".join(f"{o:02x}" for o in mac), hops),
        "mstis": [
            (f, p, ":".join(f"{o:02x}" for o in m), c, b, pp, h)
            for f, p, m, c, b, pp, h in mstis
        ],
    }


def mst_bpdu(
    *,
    version: int = 3,
    version_1_length: int = 0,
    v3_length: int | None = None,
    mstis: int = 2,
    selector: int = 0,
) -> bytes:
    """Change stp.pcap's first MST BPDU: its version, lengths, MSTIs.

    ``mstis`` keeps that many 16-octet MSTI messages (the capture's two,
    then copies of the second); ``v3_length`` defaults to the length
    they take.
    """
    real = bpdu_of(STP_PCAP[0])
    messages = (real[102:118] + real[118:134] * 64)[: 16 * mstis]
    length = 64 + 16 * mstis if v3_length is None else v3_length
    return (
        real[:2]
        + bytes((version,))
        + real[3:35]
        + bytes((version_1_length,))
        + struct.pack("!H", length)
        + bytes((selector,))
        + real[39:102]
        + messages
    )


class TestMSTBPDUsOfTheCapture:
    """stp.pcap's MST BPDUs, field by field."""

    @pytest.mark.parametrize("index", list(MST_SENDERS))
    def test_the_accessors_agree_with_struct(self, index):
        """Every MST accessor reads what ``struct`` reads, and records
        re-encode to their octets."""
        frame = STP_PCAP[index]
        bpdu = bpdu_of(frame)
        expected = mst_by_struct(bpdu)
        stp = decode_frame(frame)[STP]
        assert stp.mst == bpdu[36:]
        assert stp.version_3_length == expected["version_3_length"]
        config_id = stp.mst_config_id
        assert (
            config_id.format_selector,
            config_id.name,
            config_id.revision_level,
            config_id.digest,
        ) == expected["config_id"]
        assert bytes(config_id) == bpdu[38:89]
        assert (
            stp.cist_internal_root_path_cost,
            stp.cist_bridge_priority,
            stp.cist_bridge_mac,
            stp.cist_remaining_hops,
        ) == expected["cist"]
        assert [
            (
                m.flags,
                m.regional_root_priority,
                m.regional_root_mac,
                m.internal_root_path_cost,
                m.bridge_priority,
                m.port_priority,
                m.remaining_hops,
            )
            for m in stp.msti_messages
        ] == expected["mstis"]
        assert b"".join(map(bytes, stp.msti_messages)) == bpdu[102:]

    @pytest.mark.parametrize("index", list(MST_SENDERS))
    def test_the_topology_the_script_set_up(self, index):
        """The region, the bridges and the trees the capture configures."""
        sender = MST_SENDERS[index]
        stp = decode_frame(STP_PCAP[index])[STP]
        assert (stp.version, stp.bpdu_type, stp.version_1_length) == (3, 2, 0)
        assert stp.version_name == "Multiple Spanning Tree"
        assert stp.version_3_length == 96
        assert stp.header_len == 134
        config_id = stp.mst_config_id
        assert config_id == STPMSTConfigurationIdentifier(
            0, b"NETProtocols".ljust(32, b"\x00"), 7, REGION_DIGEST
        )
        assert config_id.name_str == "NETProtocols"
        assert config_id.digest_hex_str == "f92468d366cf3c647eb33c03b166ad59"
        bridge = BRIDGE_A if sender == "a" else BRIDGE_B
        assert (stp.cist_bridge_priority, stp.cist_bridge_mac) == bridge
        assert stp.cist_bridge_id_str == f"{bridge[0]}/0/{bridge[1]}"
        mstis = stp.msti_messages
        assert [m.msti_id for m in mstis] == [1, 2]
        priorities = MSTI_BRIDGE_PRIORITIES[sender[0]]
        assert [m.bridge_priority for m in mstis] == priorities
        assert [m.bridge_priority_component for m in mstis] == [
            p << 8 for p in priorities
        ]
        assert [m.port_priority for m in mstis] == [0x80, 0x80]
        assert [m.port_priority_component for m in mstis] == [128, 128]
        assert not any(m.master for m in mstis)
        if sender == "a" or index == 1:
            # A is the CIST root; B's first BPDU, before it hears A,
            # names itself.
            assert stp.cist_internal_root_path_cost == 0
            assert stp.cist_remaining_hops == 20
        else:
            assert stp.cist_internal_root_path_cost == 2000
            assert stp.cist_remaining_hops == 19
        if stp.forwarding:
            assert [m.regional_root_id_str for m in mstis] == [
                "0/1/02:00:00:00:a0:00",
                "8192/2/02:00:00:00:b0:00",
            ]

    @pytest.mark.parametrize("index", list(MST_SENDERS))
    def test_they_walk_and_round_trip(self, index):
        """The whole PDU is the layer, in a walk and decoded directly."""
        frame = STP_PCAP[index]
        bpdu = bpdu_of(frame)
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, LLC, STP]
        assert packet.consumed == len(frame) == 151
        assert bytes(packet) == frame
        stp = packet[STP]
        assert STP.decode(bpdu) == stp
        assert bytes(stp) == bpdu
        assert STP.decode(bytes(stp)) == stp
        assert STP(**_field_values(stp)) == stp

    @pytest.mark.parametrize("index", list(MST_SENDERS))
    def test_padding_and_an_fcs_stay_outside(self, index):
        """The Version 3 Length ends a direct decode; the 802.3 Length a
        walk."""
        frame = STP_PCAP[index]
        bpdu = bpdu_of(frame)
        stp = STP.decode(bpdu)
        for trailer in [bytes(n) for n in range(47)] + [FCS, bytes(8) + FCS]:
            direct = STP.decode(bpdu + trailer)
            assert direct == stp, trailer
            assert direct.header_len == 134
        packet = decode_frame(frame + FCS)
        assert packet[STP] == stp
        assert packet.consumed == len(frame)
        assert packet.trailer == FCS

    @pytest.mark.parametrize("index", list(MST_SENDERS))
    def test_every_cut_decodes_as_an_rst_bpdu(self, index):
        """A cut BPDU fails validation (or truncates) and round-trips."""
        bpdu = bpdu_of(STP_PCAP[index])
        for cut in range(len(bpdu)):
            if cut < 36:
                with pytest.raises(TruncatedHeaderError):
                    STP.decode(bpdu[:cut])
                continue
            stp = STP.decode(bpdu[:cut])
            assert stp.mst == b"", cut
            assert stp.header_len == 36, cut
            assert bytes(stp) == bpdu[:36], cut
            assert stp.msti_messages is None, cut
            assert STP.decode(bytes(stp)) == stp, cut

    def test_the_flags_of_each_msti(self):
        """B's agreement as root port: MSTI 1 Root, MSTI 2 Designated."""
        mstis = decode_frame(STP_PCAP[2])[STP].msti_messages
        assert mstis[0].flags == 0x79
        assert mstis[0].port_role_name == "Root"
        assert (mstis[0].agreement, mstis[0].forwarding) == (True, True)
        assert (mstis[0].learning, mstis[0].topology_change) == (True, True)
        assert mstis[0].proposal is False
        assert mstis[1].flags == 0x4E
        assert mstis[1].port_role_name == "Designated"
        assert (mstis[1].proposal, mstis[1].agreement) == (True, True)
        assert mstis[1].forwarding is False


def _field_values(stp: STP) -> dict[str, object]:
    """Return ``stp``'s dataclass fields as constructor arguments."""
    return {f.name: getattr(stp, f.name) for f in dataclasses.fields(stp)}


#: The MST accessors, which answer None for every BPDU that is not an
#: MST BPDU passing validation.
MST_ACCESSORS = (
    "version_3_length",
    "mst_config_id",
    "cist_internal_root_path_cost",
    "cist_bridge_priority",
    "cist_bridge_mac",
    "cist_bridge_id_str",
    "cist_remaining_hops",
    "msti_messages",
)


def assert_not_mst(stp: STP) -> None:
    """Assert that ``stp`` decoded with no Version 3 information."""
    assert stp.mst == b""
    for name in MST_ACCESSORS:
        assert getattr(stp, name) is None, name


class TestNonMSTBPDUsOfTheCapture:
    @pytest.mark.parametrize(
        "frame",
        RST_FRAMES + OTHER_FRAMES,
        ids=["rst-c", "rst-c-tc", "config-d", "tcn-d", "b3", "b3-tc", "b3-tca"],
    )
    def test_the_mst_accessors_are_none(self, frame):
        """C's RST BPDUs and the 802.1D BPDUs carry no MST part."""
        packet = decode_frame(frame)
        assert packet.consumed == len(frame)
        assert bytes(packet) == frame
        stp = packet[STP]
        assert_not_mst(stp)
        assert bytes(STP.decode(bpdu_of(frame))) == bpdu_of(frame)
        assert STP.decode(bytes(stp)) == stp

    def test_the_rst_bpdus_are_cs(self):
        """C's RST BPDUs: its proposal names C root, its agreement A."""
        proposal, agreement = (decode_frame(f)[STP] for f in RST_FRAMES)
        for stp in (proposal, agreement):
            assert (stp.version, stp.header_len) == (2, 36)
            assert stp.version_1_length == 0
            assert stp.bridge_id_str == "32768/0/02:00:00:00:c0:00"
        assert proposal.flags == 0x4E
        assert proposal.root_id_str == "32768/0/02:00:00:00:c0:00"
        assert proposal.root_path_cost == 0
        assert agreement.flags == 0x79
        assert agreement.root_id_str == "4096/0/02:00:00:00:a0:00"
        assert agreement.root_path_cost == 2000


class TestMSTValidation:
    """IEEE 802.1Q §14.5 e), each condition failed alone.

    Every BPDU here is hand-built from stp.pcap's first MST BPDU by
    changing the octets named (see :func:`mst_bpdu`).
    """

    def test_the_helper_rebuilds_the_capture(self):
        """Test that unchanged, :func:`mst_bpdu` is the captured BPDU."""
        assert mst_bpdu() == bpdu_of(STP_PCAP[0])

    @pytest.mark.parametrize("mstis", [0, 1, 2, 64])
    def test_whole_msti_counts_from_0_to_64(self, mstis):
        """Test whole MSTI counts from 0 to 64."""
        bpdu = mst_bpdu(mstis=mstis)
        stp = STP.decode(bpdu)
        assert stp.version_3_length == 64 + 16 * mstis
        assert len(stp.msti_messages) == mstis
        assert stp.header_len == len(bpdu) == 102 + 16 * mstis
        assert bytes(stp) == bpdu
        assert STP.decode(bytes(stp)) == stp

    def test_no_msti_messages_is_an_empty_tuple(self):
        """Test the 102-octet minimum."""
        stp = STP.decode(mst_bpdu(mstis=0))
        assert stp.msti_messages == ()
        assert stp.mst_config_id.name_str == "NETProtocols"

    @pytest.mark.parametrize("version", [3, 4, 0xFF])
    def test_version_3_or_greater(self, version):
        """§14.5 e) asks for version 3 or greater."""
        stp = STP.decode(mst_bpdu(version=version))
        assert stp.version_3_length == 96

    @pytest.mark.parametrize("version", [0, 1, 2])
    def test_an_earlier_version_is_an_rst_bpdu(self, version):
        """Test an earlier version is an RST BPDU."""
        bpdu = mst_bpdu(version=version)
        stp = STP.decode(bpdu)
        assert_not_mst(stp)
        assert bytes(stp) == bpdu[:36]

    @pytest.mark.parametrize("version_1_length", [1, 0xFF])
    def test_a_nonzero_version_1_length(self, version_1_length):
        """Test a nonzero version 1 length."""
        bpdu = mst_bpdu(version_1_length=version_1_length)
        stp = STP.decode(bpdu)
        assert_not_mst(stp)
        assert stp.version_1_length == version_1_length
        assert bytes(stp) == bpdu[:36]

    @pytest.mark.parametrize(
        "v3_length",
        [0, 1, 63, 65, 79, 81, 95, 97, 64 + 65 * 16, 0xFFFF],
    )
    def test_a_version_3_length_of_no_whole_msti_count(self, v3_length):
        """Below 64, not 64 plus a multiple of 16, or over 64 MSTIs."""
        bpdu = mst_bpdu(v3_length=v3_length, mstis=65)
        stp = STP.decode(bpdu)
        assert_not_mst(stp)
        assert stp.header_len == 36
        assert bytes(stp) == bpdu[:36]

    def test_a_version_3_length_past_the_buffer(self):
        """A whole MSTI count, but more MSTIs than the buffer holds."""
        bpdu = mst_bpdu(v3_length=64 + 3 * 16)
        assert len(bpdu) == 38 + 64 + 2 * 16
        assert_not_mst(STP.decode(bpdu))

    def test_octets_past_the_version_3_length_stay_outside(self):
        """A shorter Version 3 Length ends the BPDU before the buffer."""
        bpdu = mst_bpdu(v3_length=64 + 16)
        stp = STP.decode(bpdu)
        assert stp.header_len == 38 + 64 + 16
        assert len(stp.msti_messages) == 1
        assert bytes(stp) == bpdu[: stp.header_len]

    def test_the_c3550_count_of_msti_messages(self):
        """A Version 3 Length counting MSTI messages fails validation.

        Hand-built: the capture's BPDU with its Version 3 Length set to
        2, its count of MSTI messages, the encoding Wireshark's
        packet-bpdu.c attributes to a Cisco C3550 IOS release. No such
        BPDU was captured.
        """
        bpdu = mst_bpdu(v3_length=2)
        assert len(bpdu) == 134
        stp = STP.decode(bpdu)
        assert_not_mst(stp)
        assert (stp.version, stp.header_len) == (3, 36)
        assert bytes(stp) == bpdu[:36]
        frame = frame_8023(LLC_UI + bpdu)
        packet = decode_frame(frame)
        assert packet[STP] == stp
        assert packet.consumed == 14 + 3 + 36

    def test_the_length_in_the_format_selector(self):
        """A Version 3 Length of 0, the length in the format selector.

        Hand-built: the capture's BPDU with its Version 3 Length set to
        0 and its format selector octet to 96, the length, the encoding
        Wireshark's packet-bpdu.c describes beside the standard one. No
        such BPDU was captured.
        """
        bpdu = mst_bpdu(v3_length=0, selector=96)
        assert len(bpdu) == 134
        stp = STP.decode(bpdu)
        assert_not_mst(stp)
        assert (stp.version, stp.header_len) == (3, 36)
        assert bytes(stp) == bpdu[:36]
        packet = decode_frame(frame_8023(LLC_UI + bpdu))
        assert packet[STP] == stp
        assert packet.consumed == 14 + 3 + 36

    def test_a_nonzero_format_selector_is_carried(self):
        """Test a nonzero format selector is carried."""
        stp = STP.decode(mst_bpdu(selector=1))
        assert stp.mst_config_id.format_selector == 1

    def test_in_a_walk_the_8023_length_bounds_the_pdu(self):
        """A Length cutting the Version 3 information fails validation;
        a longer one leaves its extra octets after the layer."""
        bpdu = mst_bpdu()
        frame = frame_8023(LLC_UI + bpdu, 3 + len(bpdu) - 1) + FCS
        packet = decode_frame(frame)
        assert_not_mst(packet[STP])
        assert packet.consumed == 14 + 3 + 36
        extra = b"\x00\x00\x00\x02\x00\x1e"
        frame = frame_8023(LLC_UI + bpdu + extra) + FCS
        packet = decode_frame(frame)
        assert packet[STP] == STP.decode(bpdu)
        assert packet.consumed == 14 + 3 + len(bpdu)
        assert packet.trailer == FCS

    def test_behind_a_vlan_tag(self):
        """Test an MST BPDU behind an 802.1Q tag."""
        bpdu = mst_bpdu()
        pdu = LLC_UI + bpdu
        tag = b"\x81\x00\x00\x64" + struct.pack("!H", len(pdu))
        frame = DST + SRC + tag + pdu + FCS
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, VLAN, LLC, STP]
        assert packet[STP] == STP.decode(bpdu)
        assert packet.consumed == len(frame) - len(FCS)


class TestMSTConstruction:
    """STP(mst=...) and the two records, built from field values."""

    MST = bpdu_of(STP_PCAP[0])[36:]

    def mst_fields(self, **overrides: object) -> dict[str, object]:
        """Return the captured MST BPDU's fields, changed."""
        fields = _field_values(STP.decode(bpdu_of(STP_PCAP[0])))
        fields.update(overrides)
        return fields

    def test_a_built_mst_bpdu(self):
        """Test a built MST BPDU encodes and decodes back."""
        stp = STP(**self.mst_fields())
        assert bytes(stp) == bpdu_of(STP_PCAP[0])
        assert stp.header_len == 134

    def test_mst_from_records(self):
        """``bytes()`` of the records rebuilds :attr:`STP.mst`."""
        stp = STP.decode(bpdu_of(STP_PCAP[0]))
        cist = struct.pack(
            "!IH6sB",
            stp.cist_internal_root_path_cost,
            stp.cist_bridge_priority,
            bytes.fromhex(stp.cist_bridge_mac.replace(":", "")),
            stp.cist_remaining_hops,
        )
        messages = b"".join(map(bytes, stp.msti_messages))
        rebuilt = (
            struct.pack("!H", 64 + len(messages))
            + bytes(stp.mst_config_id)
            + cist
            + messages
        )
        assert rebuilt == stp.mst

    @pytest.mark.parametrize(
        "overrides",
        [
            {"version": 2},
            {"version_1_length": 1},
            {
                "bpdu_type": 0x00,
                "version_1_length": None,
            },
            {"mst": b"\x00"},
            {"mst": MST[:-1]},
            {"mst": MST + bytes(16)},
            {"mst": b"\x00\x02" + MST[2:]},
            {"mst": struct.pack("!H", 97) + MST[2:] + b"\x00"},
        ],
        ids=[
            "version-2",
            "version-1-length",
            "config",
            "one-octet",
            "short",
            "long",
            "count",
            "not-whole",
        ],
    )
    def test_the_constructor_rejects(self, overrides):
        """Test the constructor rejects an mst that fails validation."""
        with pytest.raises(InvalidFieldError) as excinfo:
            STP(**self.mst_fields(**overrides))
        assert excinfo.value.field == "mst"
        assert excinfo.value.protocol is STP

    def test_a_tcn_with_mst_is_rejected(self):
        """Test a TCN with mst is rejected."""
        with pytest.raises(InvalidFieldError) as excinfo:
            STP(0, 3, 0x80, mst=self.MST)
        assert excinfo.value.field == "mst"

    def test_a_configuration_identifier(self):
        """Test a configuration identifier's bytes and accessors."""
        config_id = STPMSTConfigurationIdentifier(
            1, b"r\xffx".ljust(32, b"\x00"), 0xABCD, bytes(range(16))
        )
        assert bytes(config_id) == (
            b"\x01"
            + b"r\xffx".ljust(32, b"\x00")
            + b"\xab\xcd"
            + bytes(range(16))
        )
        assert config_id.name_str == "r�x"
        assert config_id.digest_hex_str == bytes(range(16)).hex()

    def test_a_name_with_no_zero_octet(self):
        """Test a name with no zero octet."""
        config_id = STPMSTConfigurationIdentifier(0, b"n" * 32, 0, bytes(16))
        assert config_id.name_str == "n" * 32

    @pytest.mark.parametrize(
        "args,field",
        [
            ((-1, bytes(32), 0, bytes(16)), "format_selector"),
            ((256, bytes(32), 0, bytes(16)), "format_selector"),
            ((0, bytes(31), 0, bytes(16)), "name"),
            ((0, bytes(33), 0, bytes(16)), "name"),
            ((0, bytes(32), 0x10000, bytes(16)), "revision_level"),
            ((0, bytes(32), 0, bytes(15)), "digest"),
        ],
    )
    def test_a_configuration_identifier_rejects(self, args, field):
        """Test a configuration identifier rejects bad widths."""
        with pytest.raises(InvalidFieldError) as excinfo:
            STPMSTConfigurationIdentifier(*args)
        assert excinfo.value.field == field
        assert excinfo.value.protocol is STPMSTConfigurationIdentifier

    MSTI = (0x7D, 0x2002, "02:00:00:00:b0:00", 2000, 0x20, 0x80, 19)

    def test_an_msti_message(self):
        """Test an MSTI message's bytes and accessors."""
        message = STPMSTIMessage(*self.MSTI)
        assert bytes(message) == struct.pack(
            "!BH6sIBBB",
            0x7D,
            0x2002,
            bytes.fromhex("02000000b000"),
            2000,
            0x20,
            0x80,
            19,
        )
        assert message.msti_id == 2
        assert message.regional_root_priority_component == 0x2000
        assert message.regional_root_id_str == "8192/2/02:00:00:00:b0:00"
        assert message.bridge_priority_component == 0x2000
        assert message.port_priority_component == 128
        assert message.port_role == 3

    @pytest.mark.parametrize(
        "role,name",
        [
            (0, "Master"),
            (1, "Alternate or Backup"),
            (2, "Root"),
            (3, "Designated"),
        ],
    )
    def test_every_msti_port_role(self, role, name):
        """802.1Q names role 0 Master."""
        message = STPMSTIMessage(role << 2, 1, "02:00:00:00:00:01", 0, 0, 0, 0)
        assert (message.port_role, message.port_role_name) == (role, name)

    @pytest.mark.parametrize(
        "bit,accessor",
        [
            (0x01, "topology_change"),
            (0x02, "proposal"),
            (0x10, "learning"),
            (0x20, "forwarding"),
            (0x40, "agreement"),
            (0x80, "master"),
        ],
    )
    def test_each_msti_flag_alone(self, bit, accessor):
        """Test each MSTI flag alone."""
        message = STPMSTIMessage(bit, 1, "02:00:00:00:00:01", 0, 0, 0, 0)
        names = (
            "topology_change",
            "proposal",
            "learning",
            "forwarding",
            "agreement",
            "master",
        )
        for name in names:
            assert getattr(message, name) is (name == accessor), name
        assert message.port_role == 0

    @pytest.mark.parametrize(
        "index,value,field",
        [
            (0, 0x100, "flags"),
            (1, 0x10000, "regional_root_priority"),
            (3, 1 << 32, "internal_root_path_cost"),
            (4, -1, "bridge_priority"),
            (5, 0x100, "port_priority"),
            (6, 0x100, "remaining_hops"),
        ],
    )
    def test_an_msti_message_rejects(self, index, value, field):
        """Test an MSTI message rejects values too wide."""
        args = list(self.MSTI)
        args[index] = value
        with pytest.raises(InvalidFieldError) as excinfo:
            STPMSTIMessage(*args)
        assert excinfo.value.field == field
        assert excinfo.value.protocol is STPMSTIMessage

    def test_an_msti_message_validates_its_mac(self):
        """Test an MSTI message validates its MAC."""
        args = list(self.MSTI)
        args[2] = "not a mac"
        with pytest.raises(InvalidMACAddressError):
            STPMSTIMessage(*args)


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

        "Additional octets in received BPDUs identified ... as STP
        Configuration BPDUs shall be ignored" (P802.1aq/D1.5++ §14.4;
        also §14.6 i)3).
        """
        extra = b"\x00\x00\x00\x02\x00\x1e"
        frame = frame_8023(LLC_UI + CONFIG_A_TC + extra)
        packet = decode_frame(frame)
        assert packet[STP] == STP.decode(CONFIG_A_TC)
        assert packet.consumed == len(frame) - len(extra)
        assert bytes(packet) == frame[: packet.consumed]

    def test_a_pvst_plus_sstp_bpdu_arrives_in_snap(self):
        """PVST+'s SSTP BPDUs are SNAP OUI 00-00-0C PID 0x010B.

        Those carry the TLVs. PVST+'s VLAN 1 BPDUs go untagged to the
        IEEE address, at DSAP 0x42, like the fixture's (Cisco, "Troubleshoot
        Spanning Tree PVID- and Type-Inconsistencies", does not say they
        carry a TLV; Wireshark parses PVST+ TLVs only under PID 0x010B).

        The default registry has no ``llc.snap`` entry there, so the
        walk ends at SNAP; an entry for STP reaches it, and the TLVs,
        from offset 36 after a pad octet, stay after the layer.
        """
        tlv = b"\x00\x00\x00\x02\x00\x1e"
        snap = b"\xaa\xaa\x03\x00\x00\x0c\x01\x0b"
        frame = pad(frame_8023(snap + CONFIG_A_TC + b"\x00" + tlv))
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, LLC, SNAP]
        key = (0x00000C << 16) | 0x010B
        packet = decode_frame(frame, decode_as={TABLE_LLC_SNAP: {key: STP}})
        assert [type(layer) for layer in packet] == [Ethernet, LLC, SNAP, STP]
        assert packet[STP] == STP.decode(CONFIG_A_TC)
        assert packet.consumed == 14 + 8 + 35


class TestHostileInput:
    def test_decode_indexes_only_the_version_1_length(self):
        """Count the indexing and slicing decode does past its prefix.

        An RST BPDU's decode indexes the one Version 1 Length octet, an
        MST BPDU's that octet and one slice of its Version 3 information,
        and a Configuration BPDU's or a TCN's nothing, whatever follows.
        This counts ``__getitem__`` calls only: ``struct.unpack_from``
        and a ``bytes()`` or memoryview copy read the buffer without one,
        so :meth:`test_decode_never_copies_the_buffer_tail` measures the
        memory instead.
        """

        class Counting(bytes):
            reads = 0

            def __getitem__(self, key):
                Counting.reads += 1
                return super().__getitem__(key)

        cases = (
            (CONFIG_A_TC, 0),
            (RST_DESIGNATED, 1),
            (TCN, 0),
            (mst_bpdu(), 2),
            (mst_bpdu(v3_length=2), 1),
        )
        for bpdu, reads in cases:
            Counting.reads = 0
            stp = STP.decode(Counting(bpdu + bytes(65536)))
            assert stp == STP.decode(bpdu)
            assert Counting.reads == reads

    @pytest.mark.parametrize(
        "wrap", [bytes, bytearray, memoryview], ids=["bytes", "bytearray", "mv"]
    )
    @pytest.mark.parametrize(
        "bpdu",
        [CONFIG_A_TC, RST_DESIGNATED, TCN, mst_bpdu()],
        ids=["config", "rst", "tcn", "mst"],
    )
    def test_decode_never_copies_the_buffer_tail(self, wrap, bpdu):
        """Allocate at peak under half the megabyte after the BPDU.

        Traced with :func:`conftest.allocation_peak`: a copy of the
        whole buffer takes over a megabyte. ``bytes(data)``
        of a :class:`bytes` returns the object itself, so only the
        bytearray and memoryview cases see such a copy.
        """
        trailer = bytes(1 << 20)
        data = wrap(bpdu + trailer)
        with allocation_peak() as traced:
            stp = STP.decode(data)
        assert stp == STP.decode(bpdu)
        assert traced.peak < len(trailer) // 2, traced.peak

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

    def test_an_unknown_type_in_a_walk(self):
        """Test the type rejection in a frame walk, strict and lax.

        A Protocol Identifier other than 0 never reaches STP in a walk
        (see :class:`TestOtherProtocolIdentifiers`).
        """
        frame = pad(frame_8023(LLC_UI + b"\x00\x00\x00\x01"))
        with pytest.raises(InvalidFieldError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.field == "bpdu_type"
        assert excinfo.value.frame_offset == 20
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, LLC]
        assert isinstance(packet.stopped_by, InvalidFieldError)


#: A GVRP PDU (GARP, Protocol Identifier 0x0001) to SAP 0x42, padded as a
#: NIC pads it: one message, attribute type 1 (VID), length 4, JoinIn
#: (2) for VLAN 30, then two end marks.
GVRP_PDU = LLC_UI + b"\x00\x01" + b"\x01" + b"\x04\x02\x00\x1e" + b"\x00\x00"
GVRP = pad(
    bytes.fromhex("0180c2000021")
    + SRC
    + struct.pack("!H", len(GVRP_PDU))
    + GVRP_PDU
)

#: The I-format Control 0x0000, two octets: a PDU it carries dispatches.
LLC_I = b"\x42\x42\x00\x00"


class TestOtherProtocolIdentifiers:
    """LLC ends the walk at a DSAP 0x42 PDU that is not a BPDU."""

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    @pytest.mark.parametrize("fcs", [b"", FCS], ids=["no-fcs", "fcs"])
    def test_a_gvrp_pdu_ends_the_walk_at_llc(self, lax, fcs):
        """Test GARP's Protocol Identifier 0x0001 ends the walk at LLC."""
        packet = decode_frame(GVRP + fcs, lax=lax)
        assert [type(layer) for layer in packet] == [Ethernet, LLC]
        assert packet.stopped_by is None
        assert packet.consumed == 14 + 3
        assert packet[LLC].next_protocol() is None

    @pytest.mark.parametrize(
        "protocol_id", [b"\x00\x01", b"\x01\x00", b"\xff\xff"]
    )
    @pytest.mark.parametrize("head", [LLC_UI, LLC_I], ids=["ui", "i-format"])
    def test_any_nonzero_identifier_after_either_control(
        self, head, protocol_id
    ):
        """Test the two octets after a 1- and a 2-octet Control."""
        frame = pad(frame_8023(head + protocol_id + CONFIG_A_TC[2:]))
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, LLC]
        assert packet.consumed == 14 + len(head)

    @pytest.mark.parametrize("head", [LLC_UI, LLC_I], ids=["ui", "i-format"])
    def test_protocol_identifier_0_still_reaches_stp(self, head):
        """Test a BPDU after a 1- and a 2-octet Control."""
        packet = decode_frame(pad(frame_8023(head + CONFIG_A_TC)) + FCS)
        assert [type(layer) for layer in packet] == [Ethernet, LLC, STP]
        assert packet[STP] == STP.decode(CONFIG_A_TC)

    @pytest.mark.parametrize("head", [LLC_UI, LLC_I], ids=["ui", "i-format"])
    def test_exactly_two_octets_are_read(self, head):
        """Test the boundary: two octets are a Protocol Identifier.

        0x0001 alone ends the walk at LLC without an error; 0x0000 alone
        is a BPDU's prefix cut short, which STP reports.
        """
        frame = pad(frame_8023(head + b"\x00\x01")) + FCS
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, LLC]
        assert packet.stopped_by is None
        frame = pad(frame_8023(head + b"\x00\x00")) + FCS
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.protocol is STP

    @pytest.mark.parametrize("after", [b"", b"\x00", b"\x01"])
    @pytest.mark.parametrize("head", [LLC_UI, LLC_I], ids=["ui", "i-format"])
    def test_fewer_than_two_octets_still_reach_stp(self, head, after):
        """Test that STP reports the truncation, padding and FCS unread.

        A lone 0x01 followed by the padding's zeros would read as a
        Protocol Identifier of 0x0100 if the 802.3 Length did not end
        the buffer first.
        """
        frame = pad(frame_8023(head + after)) + FCS
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.protocol is STP
        assert excinfo.value.frame_offset == 14 + len(head)
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, LLC]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)
        assert packet[LLC].next_protocol() is STP

    def test_a_registered_decoder_is_not_reached_either(self):
        """Test the check applies whatever llc.dsap holds at 0x42."""
        packet = decode_frame(GVRP, decode_as={TABLE_LLC_DSAP: {0x42: Own}})
        assert [type(layer) for layer in packet] == [Ethernet, LLC]

    def test_a_memoryview_is_read_too(self):
        """Test the sniff on a memoryview, which is not retained."""
        buffer = bytearray(GVRP_PDU)
        llc = LLC.decode(memoryview(buffer))
        buffer[3:5] = b"\x00\x00"
        assert llc.next_protocol() is None
        assert LLC.decode(memoryview(buffer)).next_protocol() is STP

    def test_the_sniff_is_outside_equality_hash_and_repr(self):
        """Test equal headers compare equal however they chain."""
        garp = LLC.decode(GVRP_PDU)
        bpdu = LLC.decode(LLC_UI + CONFIG_A_TC)
        built = LLC(dsap=0x42, ssap=0x42, control=0x03)
        assert garp == bpdu == built
        assert hash(garp) == hash(bpdu) == hash(built)
        assert repr(garp) == repr(built)
        assert bytes(garp) == bytes(built) == LLC_UI
        assert (garp.next_protocol(), bpdu.next_protocol()) == (None, STP)
        assert built.next_protocol() is STP
        assert dataclasses.replace(garp).next_protocol() is STP

    @pytest.mark.parametrize(
        "copier",
        [copy.copy, copy.deepcopy],
        ids=["copy", "deepcopy"],
    )
    def test_copies_keep_the_sniff(self, copier):
        """Test what the field's comment says copies do."""
        assert copier(LLC.decode(GVRP_PDU)).next_protocol() is None

    def test_other_dsaps_are_not_sniffed(self):
        """Test that only DSAP 0x42 PDUs are gated on the two octets."""
        llc = LLC.decode(b"\x43\x42\x03\x00\x01")
        assert llc == LLC(dsap=0x43, ssap=0x42, control=0x03)
        registry = Registry.from_defaults().derive(
            {TABLE_LLC_DSAP: {0x43: Own}}
        )
        assert llc.next_protocol(registry) is Own

    def test_a_direct_decode_still_rejects_it(self):
        """Test STP.decode raises on GARP's PDU, at its protocol_id."""
        with pytest.raises(InvalidFieldError) as excinfo:
            STP.decode(GVRP_PDU[3:])
        assert excinfo.value.field == "protocol_id"


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
            (frame_8023(LLC_UI + rst(0x0C, version=3) + bytes(66)), "stp-rst"),
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
            (b"", "stp-bpdu-malformed"),
            (b"\x01", "stp-bpdu-malformed"),
            (RST_DESIGNATED[:35], "stp-bpdu-malformed"),
            (CONFIG_A_TC[:4] + b"\x02" + CONFIG_A_TC[5:], "stp-config-unused"),
            (CONFIG_A_TC[:4] + b"\x40" + CONFIG_A_TC[5:], "stp-config-unused"),
            (rst(0x80), "stp-rst-unused-flags"),
            (rst(0x80, version=3), "stp-rst-unused-flags"),
            (rst(0, version=1), "stp-rst-malformed"),
            (rst(0, version_1_length=1), "stp-rst-malformed"),
        ],
        ids=[
            "type",
            "empty",
            "one-octet",
            "rst-35",
            "config-proposal",
            "config-agreement",
            "rst-bit-8",
            "mst-bit-8",
            "rst-version-1",
            "version-1-length",
        ],
    )
    def test_tampered_bpdus_fail(self, check_fixtures, bpdu, failure):
        """Test tampered BPDUs fail."""
        frame = pad(frame_8023(LLC_UI + bpdu))
        failures = check_fixtures.check_frame(frame, Counter())
        assert any(f.startswith(failure) for f in failures), failures

    @pytest.mark.parametrize(
        "body", [GVRP_PDU[3:], b"\x00\x01"], ids=["gvrp", "exactly-two"]
    )
    @pytest.mark.parametrize("head", [LLC_UI, LLC_I], ids=["ui", "i-format"])
    def test_another_protocol_at_sap_0x42_is_not_a_bpdu(
        self, check_fixtures, head, body
    ):
        """Test GVRP passes, counted and, strict, reported unchecked."""
        pdu = head + body
        stats = Counter()
        assert check_fixtures.check_frame(pad(frame_8023(pdu)), stats) == []
        assert stats["llc-dsap-0x42-protocol-0x0001"] == 1
        assert stats["stp-bpdu"] == 0
        strict = check_fixtures._check_llc(pdu, Counter(), 0, strict=True)
        assert strict == ["unchecked-llc-dsap-0x42-protocol-0x0001"]

    @pytest.mark.parametrize(
        "pdu,control",
        [
            (b"\x42\x42\xe3", 0xE3),
            (b"\x42\x42\xf3\x00\x00\x01", 0xF3),
            (b"\x42\x42\xaf\x81\x01\x00", 0xAF),
            (b"\x42\x43\x01\x01", 0x01),
        ],
        ids=["test", "test-pf-data", "xid", "rr"],
    )
    def test_a_pdu_the_library_does_not_dispatch_is_not_a_bpdu(
        self, check_fixtures, pdu, control
    ):
        """Test TEST, XID and an S-format RR: counted, not checked.

        The library ends their walk at LLC, and the checker agrees.
        """
        frame = pad(frame_8023(pdu))
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, LLC]
        stats = Counter()
        assert check_fixtures.check_frame(frame, stats) == []
        key = f"llc-dsap-0x42-control-0x{control:02x}"
        assert stats[key] == 1
        assert stats["stp-bpdu"] == 0
        assert [k for k in stats if "protocol" in k] == []
        strict = check_fixtures._check_llc(pdu, Counter(), 0, strict=True)
        assert strict == [f"unchecked-{key}"]

    def test_a_ui_pdu_with_the_p_f_bit_set_is_a_bpdu(self, check_fixtures):
        """Test Control 0x13, UI with P/F set: both sides read a BPDU."""
        frame = pad(frame_8023(b"\x42\x42\x13" + CONFIG_A_TC))
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, LLC, STP]
        stats = Counter()
        assert check_fixtures.check_frame(frame, stats) == []
        assert stats["stp-config"] == 1

    def test_an_i_format_bpdu_is_read_after_its_2_octet_control(
        self, check_fixtures
    ):
        """Test the checker sizes the Control as the library does.

        Read one octet early, this RST BPDU would have version 0.
        """
        stats = Counter()
        frame = pad(frame_8023(LLC_I + RST_DESIGNATED))
        assert check_fixtures.check_frame(frame, stats) == []
        assert stats["stp-rst"] == 1
