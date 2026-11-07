"""Test HSRPv2's Interface State TLV.

Covered: the TLV's two counts, round trips and walks over IPv4 and
IPv6, the TLV at every position in a message, the accessor, every
Length but 4 and every truncation, that neither count is judged,
construction, equality, and scripts/check_fixtures.py agreeing with the
library on the TLV's Length.

No sender that runs in a Linux netns produces HSRPv2, so there is no
capture: every vector here is HAND-BUILT, packed field by field with
struct and socket rather than by the library, in the layout of
Wireshark's epan/dissectors/packet-hsrp.c (commit 6f7207a6): the TLV as
its lines 80-87 draw it, a 1-byte Type of 2 and Length of 4, then the
Active Groups and Passive Groups counts, read big-endian, 2 bytes each,
by lines 544-564 and declared 16-bit by lines 777-785; any other Length
falls to the Undefined TLV branch of lines 594-599. The tests check
that each of the VECTORS decodes to the counts packet-hsrp.c reads from
it, alone and wrapped in the frames ipv4_frame() and ipv6_frame()
build.
"""

import importlib.util
import socket
import struct
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from netprotocols import (
    UDP,
    Ethernet,
    HSRPv2,
    HSRPv2GroupState,
    HSRPv2InterfaceState,
    HSRPv2MD5Authentication,
    HSRPv2TextAuthentication,
    HSRPv2TLV,
    InvalidFieldError,
    IPv4,
    IPv6,
    decode_frame,
    layer7,
)

CHECKER = Path(__file__).resolve().parent.parent / "scripts/check_fixtures.py"


def group_state(
    *,
    state: int = 6,
    ip_version: int = 4,
    group: int = 1,
    address: bytes | None = None,
) -> bytes:
    """A HAND-BUILT Group State TLV in packet-hsrp.c's order: Type 1,
    Length 40, Version 2, Op Code 0 (Hello), ``state``, ``ip_version``,
    a 2-byte ``group``, Identifier 02:00:0a:09:c3:0b, Priority 100, Hello
    Time 3000 and Hold Time 10000 ms, and the 16-byte Virtual IP Address
    field, 192.0.2.1 and 12 zero bytes unless ``address`` is given."""
    if address is None:
        address = socket.inet_aton("192.0.2.1") + bytes(12)
    return (
        bytes([1, 40, 2, 0, state, ip_version])
        + struct.pack("!H", group)
        + bytes.fromhex("02000a09c30b")
        + struct.pack("!III", 100, 3000, 10000)
        + address
    )


def interface_state(active: int, passive: int, length: int = 4) -> bytes:
    """A HAND-BUILT Interface State TLV: Type 2, ``length``, then the
    Active Groups and Passive Groups counts, 2 bytes each."""
    return bytes([2, length]) + struct.pack("!HH", active, passive)


#: The IPv6 virtual address of the HSRP for IPv6 vector.
V6_ADDRESS = socket.inet_pton(socket.AF_INET6, "fe80::5:73ff:fea0:1")

#: A HAND-BUILT Text Authentication TLV: Type 3, Length 8, "cisco"
#: NUL-padded.
TEXT_AUTH = bytes([3, 8]) + b"cisco\x00\x00\x00"

#: A HAND-BUILT MD5 Authentication TLV: Type 4, Length 28, Algorithm 1,
#: padding 0, Flags 0, sender 192.0.2.11, Key ID 1, digest 00 01 ... 0f.
MD5_AUTH = (
    bytes([4, 28, 1, 0, 0, 0])
    + socket.inet_aton("192.0.2.11")
    + struct.pack("!I", 1)
    + bytes(range(16))
)

#: The default Group State TLV alone, 42 bytes.
HELLO = group_state()

#: The HAND-BUILT vectors, by name: the IP version of the frame each
#: travels in, the message, the classes of its TLVs and the counts of
#: its first Interface State TLV.
VECTORS: dict[str, tuple[int, bytes, list[type], tuple[int, int]]] = {
    "one_active": (
        4,
        HELLO + interface_state(1, 0),
        [HSRPv2GroupState, HSRPv2InterfaceState],
        (1, 0),
    ),
    "standby_passive": (
        4,
        group_state(state=5, group=2) + interface_state(0, 3),
        [HSRPv2GroupState, HSRPv2InterfaceState],
        (0, 3),
    ),
    "maximum": (
        4,
        HELLO + interface_state(0xFFFF, 0xFFFF),
        [HSRPv2GroupState, HSRPv2InterfaceState],
        (65535, 65535),
    ),
    "distinct": (
        4,
        group_state(group=0x123) + interface_state(0x1234, 0xABCD),
        [HSRPv2GroupState, HSRPv2InterfaceState],
        (4660, 43981),
    ),
    "v6": (
        6,
        group_state(ip_version=6, address=V6_ADDRESS) + interface_state(2, 1),
        [HSRPv2GroupState, HSRPv2InterfaceState],
        (2, 1),
    ),
    "between": (
        4,
        HELLO + TEXT_AUTH + interface_state(4, 5) + MD5_AUTH,
        [
            HSRPv2GroupState,
            HSRPv2TextAuthentication,
            HSRPv2InterfaceState,
            HSRPv2MD5Authentication,
        ],
        (4, 5),
    ),
    "last": (
        4,
        HELLO + TEXT_AUTH + MD5_AUTH + interface_state(6, 7),
        [
            HSRPv2GroupState,
            HSRPv2TextAuthentication,
            HSRPv2MD5Authentication,
            HSRPv2InterfaceState,
        ],
        (6, 7),
    ),
    "twice": (
        4,
        HELLO + interface_state(1, 0) + interface_state(0, 1),
        [HSRPv2GroupState, HSRPv2InterfaceState, HSRPv2InterfaceState],
        (1, 0),
    ),
    "after_second_group_state": (
        4,
        HELLO + group_state(group=2, state=5) + interface_state(8, 9),
        [HSRPv2GroupState, HSRPv2GroupState, HSRPv2InterfaceState],
        (8, 9),
    ),
    "after_raw_tlv": (
        4,
        HELLO + bytes([0, 0]) + interface_state(3, 3),
        [HSRPv2GroupState, HSRPv2TLV, HSRPv2InterfaceState],
        (3, 3),
    ),
}


def ones_complement(data: bytes) -> int:
    """The RFC 1071 checksum of ``data``, written out here."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4_frame(payload: bytes) -> bytes:
    """``payload`` in Ethernet, IPv4 (192.0.2.11 to 224.0.0.102, TTL 1)
    and UDP from and to port 1985, every checksum computed here."""
    src, dst = socket.inet_aton("192.0.2.11"), socket.inet_aton("224.0.0.102")
    udp = struct.pack("!HHHH", 1985, 1985, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 17, len(udp))
    checksum = ones_complement(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", checksum) + udp[8:]
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0xC0, 20 + len(udp), 0, 0, 1, 17, 0, src, dst
    )
    ip = ip[:10] + struct.pack("!H", ones_complement(ip)) + ip[12:]
    return bytes.fromhex("01005e000066 02000a09c30b 0800") + ip + udp


def ipv6_frame(payload: bytes) -> bytes:
    """``payload`` in Ethernet, IPv6 (fe80::a:9c3:b to ff02::66, hop
    limit 255) and UDP from and to port 2029, its checksum computed
    here."""
    src = socket.inet_pton(socket.AF_INET6, "fe80::a:9c3:b")
    dst = socket.inet_pton(socket.AF_INET6, "ff02::66")
    udp = struct.pack("!HHHH", 2029, 2029, 8 + len(payload), 0) + payload
    pseudo = src + dst + struct.pack("!IxxxB", len(udp), 17)
    checksum = ones_complement(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", checksum) + udp[8:]
    ip = struct.pack("!IHBB", 0x60000000, len(udp), 17, 255) + src + dst
    return bytes.fromhex("333300000066 02000a09c30b 86dd") + ip + udp


def frame_of(family: int, payload: bytes) -> bytes:
    """``payload`` in the frame of IP version ``family``."""
    return (ipv4_frame if family == 4 else ipv6_frame)(payload)


#: Where the message starts in the IPv4 frames above.
V4_START = 14 + 20 + 8


@pytest.fixture(scope="module")
def check_fixtures():
    """Load scripts/check_fixtures.py, which shares no library code."""
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- The hand-built vectors -------------------------------------------


class TestVectors:
    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_decodes_to_its_counts(self, name):
        _, raw, classes, (active, passive) = VECTORS[name]
        message = HSRPv2.decode(raw)
        assert [type(tlv) for tlv in message.tlvs] == classes
        assert message.interface_state == HSRPv2InterfaceState(
            active_groups=active, passive_groups=passive
        )

    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_round_trips(self, name):
        _, raw, _, _ = VECTORS[name]
        message = HSRPv2.decode(raw)
        assert bytes(message) == raw
        assert message.header_len == len(raw)
        assert HSRPv2.decode(bytes(message)) == message
        assert HSRPv2.decode(memoryview(raw)) == message

    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_walks_to_hsrpv2(self, name):
        """Ethernet/IPv4/UDP 1985 and Ethernet/IPv6/UDP 2029 both end
        in an HSRPv2 layer holding the TLV."""
        family, raw, _, _ = VECTORS[name]
        frame = frame_of(family, raw)
        packet = decode_frame(frame)
        ip = IPv4 if family == 4 else IPv6
        assert [type(layer) for layer in packet] == [Ethernet, ip, UDP, HSRPv2]
        assert packet[HSRPv2] == HSRPv2.decode(raw)
        assert packet.consumed == len(frame)

    def test_the_tlv_serializes_to_its_hand_packed_bytes(self):
        tlv = HSRPv2.decode(VECTORS["distinct"][1]).interface_state
        assert bytes(tlv) == bytes.fromhex("0204 1234 abcd")
        assert len(bytes(tlv)) == 6
        assert tlv.type == 2

    def test_the_accessor_gives_the_first(self):
        message = HSRPv2.decode(VECTORS["twice"][1])
        assert message.interface_state is message.tlvs[1]
        assert message.tlvs[2] == HSRPv2InterfaceState(0, 1)

    @pytest.mark.parametrize(
        "raw",
        [HELLO, HELLO + TEXT_AUTH, HELLO + MD5_AUTH, HELLO + b"\x05\x00"],
        ids=["alone", "text", "md5", "raw-type-5"],
    )
    def test_the_accessor_without_one(self, raw):
        assert HSRPv2.decode(raw).interface_state is None


# --- Length and truncation --------------------------------------------


#: The prefixes the TLV is tried after, and where it then starts.
PREFIXES = {
    "after-group-state": HELLO,
    "after-text": HELLO + TEXT_AUTH,
    "after-md5": HELLO + MD5_AUTH,
    "after-second-group-state": HELLO + group_state(group=2),
    "after-interface-state": HELLO + interface_state(1, 0),
}


class TestLength:
    @pytest.mark.parametrize("prefix", list(PREFIXES))
    @pytest.mark.parametrize("length", [n for n in range(256) if n != 4])
    def test_every_other_length_is_refused(self, prefix, length):
        """With its value whole, a Length other than 4 raises at the
        Length byte, wherever the TLV is."""
        head = PREFIXES[prefix]
        raw = head + bytes([2, length]) + bytes(length) + TEXT_AUTH
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2.decode(raw)
        error = caught.value
        assert error.protocol is HSRPv2
        assert (error.field, error.offset) == ("length", len(head) + 1)
        assert (error.expected, error.actual) == ("4", length)

    @pytest.mark.parametrize("cut", range(1, 6))
    def test_every_truncation_breaks_the_walk(self, cut):
        """A Type byte alone, or a Length of 4 with fewer than 4 bytes
        after it, breaks the walk at the TLV's first byte."""
        raw = HELLO + interface_state(1, 0)[:cut]
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2.decode(raw)
        assert (caught.value.field, caught.value.offset) == ("tlvs", 42)

    def test_a_cut_after_a_whole_tlv(self):
        """The TLV is whole; the Type byte after it is the cut one."""
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2.decode(HELLO + interface_state(1, 0) + b"\x02")
        assert (caught.value.field, caught.value.offset) == ("tlvs", 48)

    def test_a_walk_reports_the_frame_offset(self):
        """A strict walk raises at the Length byte; a lax one keeps
        Ethernet, IPv4 and UDP."""
        frame = ipv4_frame(HELLO + interface_state(1, 0, length=5) + b"\x00")
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(frame)
        assert caught.value.frame_offset == V4_START + 43
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, InvalidFieldError)
        assert packet.stopped_by.field == "length"


class TestCountsAreNotJudged:
    @given(
        active=st.integers(0, 0xFFFF),
        passive=st.integers(0, 0xFFFF),
    )
    def test_any_counts_decode(self, active, passive):
        raw = HELLO + interface_state(active, passive)
        message = HSRPv2.decode(raw)
        assert message.interface_state == HSRPv2InterfaceState(active, passive)
        assert bytes(message) == raw


# --- Construction -----------------------------------------------------


class TestConstruction:
    @pytest.mark.parametrize("field", ["active_groups", "passive_groups"])
    @pytest.mark.parametrize("value", [-1, 0x10000, 2**32])
    def test_a_count_out_of_range(self, field, value):
        with pytest.raises(InvalidFieldError) as caught:
            replace(HSRPv2InterfaceState(1, 0), **{field: value})
        error = caught.value
        assert (error.protocol, error.field) == (HSRPv2InterfaceState, field)
        assert (error.expected, error.actual) == ("0-65535", value)

    @pytest.mark.parametrize("value", [0, 1, 0xFFFF])
    def test_a_count_at_its_bounds(self, value):
        tlv = HSRPv2InterfaceState(value, value)
        assert bytes(tlv) == interface_state(value, value)

    def test_equality_and_the_hash(self):
        tlv = HSRPv2InterfaceState(active_groups=1, passive_groups=0)
        assert tlv == HSRPv2InterfaceState(1, 0)
        assert tlv != HSRPv2InterfaceState(0, 1)
        assert (
            len({tlv, HSRPv2InterfaceState(1, 0), HSRPv2InterfaceState(0, 1)})
            == 2
        )

    def test_a_message_built_with_one(self):
        state = HSRPv2.decode(HELLO).group_state
        message = HSRPv2((state, HSRPv2InterfaceState(1, 0)))
        assert bytes(message) == VECTORS["one_active"][1]
        assert HSRPv2.decode(bytes(message)) == message
        assert message.header_len == 48

    @pytest.mark.parametrize(
        "value", [b"", bytes(4), bytes.fromhex("00010000"), bytes(5)]
    )
    def test_a_raw_tlv_of_type_2_is_refused(self, value):
        """Type 2 has its own class, at any value length."""
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2TLV(2, value)
        error = caught.value
        assert (error.protocol, error.field, error.actual) == (
            HSRPv2TLV,
            "type",
            2,
        )
        assert "Interface State" in str(error)

    def test_it_cannot_open_a_message(self):
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2((HSRPv2InterfaceState(1, 0),))
        assert caught.value.field == "tlvs"

    def test_it_is_exported(self):
        assert layer7.HSRPv2InterfaceState is HSRPv2InterfaceState
        assert "HSRPv2InterfaceState" in layer7.__all__


# --- scripts/check_fixtures.py ----------------------------------------


class TestChecker:
    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_passes(self, check_fixtures, name):
        family, raw, _, _ = VECTORS[name]
        stats: Counter[str] = check_fixtures.Counter()
        assert check_fixtures.check_frame(frame_of(family, raw), stats) == []
        assert stats["hsrpv2"] == 1

    @pytest.mark.parametrize("length", range(256))
    def test_the_checker_and_the_library_agree_on_the_length(
        self, check_fixtures, length
    ):
        """The checker fails exactly the Lengths decode refuses."""
        raw = HELLO + bytes([2, length]) + bytes(length)
        failures = check_fixtures.check_frame(ipv4_frame(raw), Counter())
        try:
            HSRPv2.decode(raw)
        except InvalidFieldError as error:
            assert error.field == "length"
            assert failures == ["hsrpv2-tlv-length"]
        else:
            assert length == 4
            assert failures == []
