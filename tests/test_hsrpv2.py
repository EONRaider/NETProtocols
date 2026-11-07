"""Test HSRPv2 and HSRP for IPv6 decoding and dispatch.

Covered: the Group State, Interface State, Text Authentication and MD5
Authentication TLVs and raw TLVs of other Types, the round trip,
truncation at every length, every judged field of the Group State TLV,
every malformed TLV, construction, the display helpers, and dispatch:
UDP port 1985 choosing HSRP or HSRPv2 by the first byte, and port 2029
naming HSRPv2.

No sender that runs in a Linux netns produces HSRPv2, so there is no
capture: every vector here is HAND-BUILT, packed field by field with
struct and socket rather than by the library, in the layout of
Wireshark's epan/dissectors/packet-hsrp.c (commit 6f7207a6): the Group
State TLV as its lines 53-78 draw it and lines 479-543 read it, the
Interface State TLV as lines 80-87 and 544-564, the Text
Authentication TLV as lines 89-98 and 565-587, the MD5 Authentication
TLV as lines 100-119 and 319-344, and the walk of lines 474-601. The
tests check that each of the five VECTORS decodes to the fields
packet-hsrp.c reads from it, alone and wrapped in the frames
ipv4_frame() and ipv6_frame() build.
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
    HSRPv2GroupState,
    HSRPv2InterfaceState,
    HSRPv2MD5Authentication,
    HSRPv2TextAuthentication,
    HSRPv2TLV,
    InvalidFieldError,
    InvalidIPv4AddressError,
    InvalidMACAddressError,
    IPv4,
    IPv6,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_UDP_PORT

#: The sender's MAC address, the Identifier of every vector.
IDENTIFIER = "02:00:0a:09:c3:0b"


def group_state(
    *,
    version: int = 2,
    opcode: int = 0,
    state: int = 6,
    ip_version: int = 4,
    group: int = 1,
    priority: int = 100,
    hellotime: int = 3000,
    holdtime: int = 10000,
    address: bytes | None = None,
) -> bytes:
    """A HAND-BUILT Group State TLV, packed here in packet-hsrp.c's
    order: Type 1, Length 40, Version, Op Code, State, IP Version, a
    2-byte Group, the 6-byte Identifier, then the 4-byte Priority, Hello
    Time and Hold Time and the 16-byte Virtual IP Address field. The
    defaults are an Active Hello for IPv4 group 1, virtual IP 192.0.2.1,
    with packet-hsrp.c's default timers, 3000 and 10000 ms."""
    if address is None:
        address = socket.inet_aton("192.0.2.1") + bytes(12)
    return (
        bytes([1, 40, version, opcode, state, ip_version])
        + struct.pack("!H", group)
        + bytes.fromhex(IDENTIFIER.replace(":", ""))
        + struct.pack("!III", priority, hellotime, holdtime)
        + address
    )


#: The IPv6 virtual address of the HSRP for IPv6 vectors.
V6_VIP = "fe80::5:73ff:fea0:1"
V6_ADDRESS = socket.inet_pton(socket.AF_INET6, V6_VIP)

#: A HAND-BUILT Text Authentication TLV: Type 3, Length 8, "cisco"
#: NUL-padded.
TEXT_AUTH = bytes([3, 8]) + b"cisco\x00\x00\x00"

#: A HAND-BUILT MD5 Authentication TLV: Type 4, Length 28, Algorithm 1,
#: a padding byte, 2 bytes of Flags, the sender's address, Key ID 1 and
#: a 16-byte digest.
MD5_AUTH = (
    bytes([4, 28, 1, 0])
    + struct.pack("!H", 0)
    + socket.inet_aton("192.0.2.11")
    + struct.pack("!I", 1)
    + bytes(range(16))
)

#: A HAND-BUILT Interface State TLV (Type 2, Length 4: 1 active group, 0
#: passive).
INTERFACE_STATE = bytes([2, 4]) + struct.pack("!HH", 1, 0)

#: The HAND-BUILT vectors in packet-hsrp.c's layout, by name: the IP
#: version of the frame each travels in, and the message.
VECTORS = {
    "v4_hello_text": (4, group_state() + TEXT_AUTH),
    "v4_coup_md5": (
        4,
        group_state(
            opcode=1,
            state=4,
            group=4095,
            priority=200,
            hellotime=1000,
            holdtime=3000,
            address=socket.inet_aton("198.51.100.7") + bytes(12),
        )
        + MD5_AUTH,
    ),
    "v4_resign_interface_state": (
        4,
        group_state(opcode=2, group=0) + INTERFACE_STATE,
    ),
    "v6_hello_text": (
        6,
        group_state(ip_version=6, state=5, group=10, address=V6_ADDRESS)
        + TEXT_AUTH,
    ),
    "v6_hello": (6, group_state(ip_version=6, address=V6_ADDRESS)),
}

#: The default Group State TLV alone.
HELLO = group_state()


def ones_complement(data: bytes) -> int:
    """The RFC 1071 checksum of ``data``, written out here."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4_frame(
    payload: bytes, *, src_port: int = 1985, dst_port: int = 1985
) -> bytes:
    """``payload`` in Ethernet, IPv4 (192.0.2.11 to 224.0.0.102, TTL 1)
    and UDP, every checksum computed here."""
    src, dst = socket.inet_aton("192.0.2.11"), socket.inet_aton("224.0.0.102")
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    udp += payload
    pseudo = src + dst + struct.pack("!BBH", 0, 17, len(udp))
    checksum = ones_complement(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", checksum) + udp[8:]
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0xC0, 20 + len(udp), 0, 0, 1, 17, 0, src, dst
    )
    ip = ip[:10] + struct.pack("!H", ones_complement(ip)) + ip[12:]
    return bytes.fromhex("01005e000066 02000a09c30b 0800") + ip + udp


def ipv6_frame(
    payload: bytes, *, src_port: int = 2029, dst_port: int = 2029
) -> bytes:
    """``payload`` in Ethernet, IPv6 (fe80::a:9c3:b to ff02::66, hop
    limit 255) and UDP, its checksum computed here."""
    src = socket.inet_pton(socket.AF_INET6, "fe80::a:9c3:b")
    dst = socket.inet_pton(socket.AF_INET6, "ff02::66")
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    udp += payload
    pseudo = src + dst + struct.pack("!IxxxB", len(udp), 17)
    checksum = ones_complement(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", checksum) + udp[8:]
    ip = struct.pack("!IHBB", 0x60000000, len(udp), 17, 255) + src + dst
    return bytes.fromhex("333300000066 02000a09c30b 86dd") + ip + udp


#: Where the message starts in the frames above.
V4_START, V6_START = 14 + 20 + 8, 14 + 40 + 8


def state_of(**fields: object) -> HSRPv2GroupState:
    """The default Group State TLV, decoded, with ``fields`` replaced."""
    return replace(HSRPv2.decode(HELLO).group_state, **fields)


def changed(raw: bytes, position: int, value: int) -> bytes:
    """``raw`` with the byte at ``position`` set to ``value``."""
    return raw[:position] + bytes([value]) + raw[position + 1 :]


# --- The hand-built vectors -------------------------------------------


#: Per vector: Op Code, State, IP Version, Group, Priority, Hello
#: Time, Hold Time, virtual IP and the classes of the TLVs.
EXPECTED = {
    "v4_hello_text": (
        "Hello",
        "Active",
        "IPv4",
        1,
        100,
        3000,
        10000,
        "192.0.2.1",
        [HSRPv2GroupState, HSRPv2TextAuthentication],
    ),
    "v4_coup_md5": (
        "Coup",
        "Speak",
        "IPv4",
        4095,
        200,
        1000,
        3000,
        "198.51.100.7",
        [HSRPv2GroupState, HSRPv2MD5Authentication],
    ),
    "v4_resign_interface_state": (
        "Resign",
        "Active",
        "IPv4",
        0,
        100,
        3000,
        10000,
        "192.0.2.1",
        [HSRPv2GroupState, HSRPv2InterfaceState],
    ),
    "v6_hello_text": (
        "Hello",
        "Standby",
        "IPv6",
        10,
        100,
        3000,
        10000,
        V6_VIP,
        [HSRPv2GroupState, HSRPv2TextAuthentication],
    ),
    "v6_hello": (
        "Hello",
        "Active",
        "IPv6",
        1,
        100,
        3000,
        10000,
        V6_VIP,
        [HSRPv2GroupState],
    ),
}


class TestVectors:
    """Each vector's fields, as packet-hsrp.c reads them."""

    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_decodes_to_its_fields(self, name):
        _, raw = VECTORS[name]
        message = HSRPv2.decode(raw)
        state = message.group_state
        assert (
            state.opcode_name,
            state.state_name,
            state.ip_version_name,
            state.group,
            state.priority,
            state.hellotime,
            state.holdtime,
            state.virtual_ip,
            [type(tlv) for tlv in message.tlvs],
        ) == EXPECTED[name]
        assert state.version == 2
        assert state.identifier == IDENTIFIER

    def test_conftests_hello_is_the_first_vector(self, raw_hsrpv2_hello):
        assert raw_hsrpv2_hello == VECTORS["v4_hello_text"][1]

    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_round_trips(self, name):
        _, raw = VECTORS[name]
        message = HSRPv2.decode(raw)
        assert bytes(message) == raw
        assert message.header_len == len(raw)
        assert HSRPv2.decode(bytes(message)) == message
        assert HSRPv2.decode(memoryview(raw)) == message

    @pytest.mark.parametrize("name", list(VECTORS))
    def test_each_vector_walks_to_hsrpv2(self, name):
        """Ethernet/IPv4/UDP 1985 and Ethernet/IPv6/UDP 2029 both end
        in an HSRPv2 layer that takes the rest of the frame."""
        family, raw = VECTORS[name]
        frame = (ipv4_frame if family == 4 else ipv6_frame)(raw)
        packet = decode_frame(frame)
        ip = IPv4 if family == 4 else IPv6
        assert [type(layer) for layer in packet] == [Ethernet, ip, UDP, HSRPv2]
        assert packet[HSRPv2] == HSRPv2.decode(raw)
        assert packet.consumed == len(frame)

    def test_the_text_authentication_tlv(self):
        auth = HSRPv2.decode(VECTORS["v4_hello_text"][1]).text_authentication
        assert auth == HSRPv2TextAuthentication(b"cisco\x00\x00\x00")
        assert auth.password == b"cisco"
        assert auth.auth_data_str == "cisco"
        assert auth.is_default_auth
        assert bytes(auth) == TEXT_AUTH

    def test_the_md5_authentication_tlv(self):
        """Every field of lines 319-344, the digest kept raw."""
        message = HSRPv2.decode(VECTORS["v4_coup_md5"][1])
        md5 = message.md5_authentication
        assert md5 == HSRPv2MD5Authentication(
            algorithm=1,
            padding=0,
            flags=0,
            ip_address="192.0.2.11",
            key_id=1,
            digest=bytes(range(16)),
        )
        assert md5.algorithm_name == "MD5"
        assert bytes(md5) == MD5_AUTH
        assert message.text_authentication is None

    def test_the_interface_state_tlv(self):
        """Both counts of lines 544-564, 2 bytes each."""
        message = HSRPv2.decode(VECTORS["v4_resign_interface_state"][1])
        tlv = message.interface_state
        assert tlv == HSRPv2InterfaceState(active_groups=1, passive_groups=0)
        assert message.tlvs[1] is tlv
        assert bytes(tlv) == INTERFACE_STATE
        assert message.md5_authentication is None
        assert message.text_authentication is None

    def test_an_unknown_tlv_is_kept_raw(self):
        """A Type packet-hsrp.c does not read is an HSRPv2TLV."""
        message = HSRPv2.decode(HELLO + bytes([5, 3]) + b"abc")
        assert message.tlvs[1] == HSRPv2TLV(type=5, value=b"abc")
        assert message.tlvs[1].type_name == "unknown (5)"
        assert message.interface_state is None

    def test_an_ipv4_address_keeps_its_12_padding_bytes(self):
        """The address takes the field's first 4 bytes; the other 12 are
        kept as sent, zero or not."""
        state = HSRPv2.decode(HELLO).group_state
        assert state.virtual_ip_padding == bytes(12)
        address = socket.inet_aton("192.0.2.1") + bytes(range(1, 13))
        raw = group_state(address=address)
        decoded = HSRPv2.decode(raw)
        assert decoded.group_state.virtual_ip == "192.0.2.1"
        assert decoded.group_state.virtual_ip_padding == bytes(range(1, 13))
        assert bytes(decoded) == raw

    def test_an_ipv6_address_fills_the_field(self):
        state = HSRPv2.decode(VECTORS["v6_hello"][1]).group_state
        assert state.virtual_ip_padding == b""
        assert bytes(state)[26:] == V6_ADDRESS

    def test_the_group_state_tlv_layout(self):
        """bytes() of a constructed TLV is the hand-packed one."""
        state = HSRPv2GroupState(
            version=2,
            opcode=1,
            state=4,
            ip_version=4,
            group=0x0ABC,
            identifier=IDENTIFIER,
            priority=0x01020304,
            hellotime=0x05060708,
            holdtime=0x090A0B0C,
            virtual_ip="192.0.2.1",
            virtual_ip_padding=bytes(12),
        )
        assert bytes(state) == group_state(
            opcode=1,
            state=4,
            group=0x0ABC,
            priority=0x01020304,
            hellotime=0x05060708,
            holdtime=0x090A0B0C,
        )
        assert len(bytes(state)) == 42


# --- Decoding ---------------------------------------------------------


class TestDecode:
    def test_a_message_of_many_tlvs(self):
        """A second Group State TLV is decoded as the first; TLVs of any
        Type, an empty one included, keep their order."""
        second = group_state(group=2, state=5)
        raw = HELLO + TEXT_AUTH + bytes([0, 0]) + second + MD5_AUTH
        raw += bytes([255, 3]) + b"abc"
        message = HSRPv2.decode(raw)
        assert [type(tlv) for tlv in message.tlvs] == [
            HSRPv2GroupState,
            HSRPv2TextAuthentication,
            HSRPv2TLV,
            HSRPv2GroupState,
            HSRPv2MD5Authentication,
            HSRPv2TLV,
        ]
        assert message.tlvs[2] == HSRPv2TLV(0)
        assert message.tlvs[3].group == 2
        assert message.tlvs[5] == HSRPv2TLV(255, b"abc")
        assert message.group_state.group == 1
        assert bytes(message) == raw

    def test_a_zero_tail_is_empty_tlvs(self):
        """Zero bytes after the TLVs walk as Type 0, Length 0."""
        message = HSRPv2.decode(HELLO + bytes(4))
        assert message.tlvs[1:] == (HSRPv2TLV(0), HSRPv2TLV(0))
        assert bytes(message) == HELLO + bytes(4)

    def test_an_fcs_is_the_packets_trailer(self):
        """The walk ends HSRPv2's buffer at UDP's Length."""
        frame = ipv4_frame(HELLO) + b"\xde\xad\xbe\xef"
        packet = decode_frame(frame)
        assert packet[HSRPv2] == HSRPv2.decode(HELLO)
        assert packet.trailer == b"\xde\xad\xbe\xef"

    def test_hsrpv2_ends_the_chain(self):
        assert HSRPv2.decode(HELLO).next_protocol() is None

    def test_hsrp_decoded_directly_names_hsrpv2(self):
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(HELLO)
        error = caught.value
        assert (error.protocol, error.field, error.actual) == (
            HSRP,
            "version",
            1,
        )
        assert "decode it with HSRPv2" in str(error)


#: Each judged byte, its field, and values decode rejects.
REJECTED = [
    (0, "type", "1", [0, 2, 3, 4, 255]),
    (1, "length", "40", [0, 8, 39, 41, 255]),
    (2, "version", "2", [0, 1, 3, 255]),
    (3, "opcode", "0-2", [3, 4, 255]),
    (4, "state", "0-6", [7, 8, 16, 255]),
    (5, "ip_version", "4 or 6", [0, 5, 41, 255]),
]


class TestDecodeGuard:
    """The Group State TLV's first eight bytes, judged before the length."""

    @pytest.mark.parametrize("position,field,expected,values", REJECTED)
    @pytest.mark.parametrize("length", [None, 42, 52])
    def test_each_judged_byte_at_any_length(
        self, position, field, expected, values, length
    ):
        """At its own length (``None``: cut just after it), the TLV's
        42 bytes, or with more after it."""
        for value in values:
            raw = changed(HELLO + TEXT_AUTH, position, value)
            raw = raw[: position + 1] if length is None else raw[:length]
            with pytest.raises(InvalidFieldError) as caught:
                HSRPv2.decode(raw)
            error = caught.value
            assert error.protocol is HSRPv2
            assert (error.field, error.offset) == (field, position)
            assert (error.expected, error.actual) == (expected, value)

    @pytest.mark.parametrize("group", [4096, 0x8000, 0xFFFF])
    def test_a_group_above_4095(self, group):
        """Judged once both its bytes are there."""
        raw = HELLO[:6] + struct.pack("!H", group)
        for cut in (raw, raw + HELLO[8:], raw + HELLO[8:] + TEXT_AUTH):
            with pytest.raises(InvalidFieldError) as caught:
                HSRPv2.decode(cut)
            error = caught.value
            assert (error.field, error.offset) == ("group", 6)
            assert (error.expected, error.actual) == ("0-4095", group)
        with pytest.raises(TruncatedHeaderError):
            HSRPv2.decode(raw[:7])

    @pytest.mark.parametrize("cut", range(42))
    def test_every_truncation_of_a_valid_tlv(self, cut):
        """Every leading byte passes, so a cut anywhere in the 42 bytes
        is a truncated header."""
        with pytest.raises(TruncatedHeaderError) as caught:
            HSRPv2.decode(HELLO[:cut])
        error = caught.value
        assert (error.expected, error.actual) == (42, cut)

    def test_exactly_the_documented_values_pass(self):
        """1 Type, 1 Length, 1 Version, 3 Op Codes, 7 States and 2 IP
        Versions, each byte judged alone; Groups 0-4095."""
        rest = HELLO[6:]

        def passes(lead: bytes) -> bool:
            try:
                HSRPv2.decode(lead + rest)
            except InvalidFieldError:
                return False
            return True

        base = list(HELLO[:6])
        accepted = []
        for position in range(6):
            values = []
            for value in range(256):
                lead = list(base)
                lead[position] = value
                if passes(bytes(lead)):
                    values.append(value)
            accepted.append(values)
        assert accepted == [
            [1],
            [40],
            [2],
            [0, 1, 2],
            [0, 1, 2, 3, 4, 5, 6],
            [4, 6],
        ]

    @pytest.mark.parametrize(
        "lead", [bytes([1]), bytes([1, 40]), bytes([1, 40, 2, 0, 6])]
    )
    def test_leading_bytes_that_pass_end_in_truncation(self, lead):
        with pytest.raises(TruncatedHeaderError):
            HSRPv2.decode(lead)

    def test_the_other_fields_are_not_judged(self):
        """Any Identifier, Priority, timers and address decode."""
        raw = HELLO[:8] + b"\xff" * 34
        message = HSRPv2.decode(raw)
        state = message.group_state
        assert state.identifier == "ff:ff:ff:ff:ff:ff"
        assert state.priority == state.hellotime == state.holdtime == 2**32 - 1
        assert state.virtual_ip == "255.255.255.255"
        assert bytes(message) == raw


class TestMalformedTLVs:
    """Past the first TLV's 42 bytes, the walk raises InvalidFieldError,
    its offset from the start of the message."""

    def test_a_type_byte_without_its_length(self):
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2.decode(HELLO + b"\x02")
        assert (caught.value.field, caught.value.offset) == ("tlvs", 42)

    @pytest.mark.parametrize("kind", [1, 2, 3, 4, 255])
    def test_a_length_past_the_buffer(self, kind):
        for tail in (bytes([kind, 1]), bytes([kind, 9]) + bytes(8)):
            with pytest.raises(InvalidFieldError) as caught:
                HSRPv2.decode(HELLO + TEXT_AUTH + tail)
            assert (caught.value.field, caught.value.offset) == ("tlvs", 52)

    @pytest.mark.parametrize(
        "kind,length,expected",
        [
            (1, 39, "40"),
            (1, 41, "40"),
            (2, 0, "4"),
            (2, 3, "4"),
            (2, 5, "4"),
            (3, 0, "8"),
            (3, 7, "8"),
            (3, 9, "8"),
            (4, 27, "28"),
            (4, 29, "28"),
        ],
    )
    def test_a_typed_tlv_of_another_length(self, kind, length, expected):
        raw = HELLO + bytes([kind, length]) + bytes(length)
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2.decode(raw)
        error = caught.value
        assert (error.field, error.offset) == ("length", 43)
        assert (error.expected, error.actual) == (expected, length)

    @pytest.mark.parametrize(
        "position,value,field",
        [
            (2, 3, "version"),
            (3, 3, "opcode"),
            (4, 7, "state"),
            (5, 0, "ip_version"),
            (6, 0x10, "group"),
        ],
    )
    def test_a_later_group_state_tlv_is_held_to_the_first_rules(
        self, position, value, field
    ):
        raw = HELLO + TEXT_AUTH + changed(HELLO, position, value)
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2.decode(raw)
        assert (caught.value.field, caught.value.offset) == (
            field,
            52 + position,
        )

    def test_a_walk_reports_the_frame_offset(self):
        """A strict walk raises at the bad TLV; a lax one keeps
        Ethernet, IPv4 and UDP."""
        frame = ipv4_frame(HELLO + bytes([3, 7]) + bytes(7))
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(frame)
        assert caught.value.frame_offset == V4_START + 43
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, InvalidFieldError)

    def test_a_short_datagram_to_2029_is_truncated(self):
        packet = decode_frame(ipv6_frame(HELLO[:20]), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv6, UDP]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)
        assert packet.stopped_by.frame_offset == V6_START


# --- Construction -----------------------------------------------------


class TestConstruction:
    @pytest.mark.parametrize(
        "field,value",
        [
            ("version", 256),
            ("opcode", -1),
            ("state", 256),
            ("ip_version", 256),
            ("ip_version", 5),
            ("group", 4096),
            ("group", -1),
            ("priority", 2**32),
            ("hellotime", -1),
            ("holdtime", 2**32),
            ("virtual_ip_padding", bytes(11)),
            ("virtual_ip_padding", b""),
        ],
    )
    def test_a_group_state_field_out_of_range(self, field, value):
        with pytest.raises(InvalidFieldError) as caught:
            state_of(**{field: value})
        assert caught.value.field == field
        assert caught.value.protocol is HSRPv2GroupState

    def test_a_group_state_with_a_bad_address(self):
        with pytest.raises(InvalidIPv4AddressError):
            state_of(virtual_ip="192.0.2")
        with pytest.raises(InvalidIPv4AddressError):
            state_of(virtual_ip=V6_VIP)
        with pytest.raises(InvalidMACAddressError):
            state_of(identifier="02:00:0a")
        for bad in ("192.0.2.1", "fe80::g", 6):
            with pytest.raises(InvalidFieldError) as caught:
                state_of(ip_version=6, virtual_ip=bad, virtual_ip_padding=b"")
            assert caught.value.field == "virtual_ip"
        with pytest.raises(InvalidFieldError) as caught:
            state_of(ip_version=6, virtual_ip=V6_VIP)
        assert caught.value.field == "virtual_ip_padding"

    @staticmethod
    def built(**fields: object) -> HSRPv2GroupState:
        """An Active IPv4 Hello for group 1, built with ``fields``."""
        defaults: dict[str, object] = {
            "version": 2,
            "opcode": 0,
            "state": 6,
            "ip_version": 4,
            "group": 1,
            "identifier": IDENTIFIER,
            "priority": 100,
            "hellotime": 3000,
            "holdtime": 10000,
            "virtual_ip": "192.0.2.1",
        }
        return HSRPv2GroupState(**{**defaults, **fields})

    def test_an_ipv4_group_state_without_padding_gets_12_zero_bytes(self):
        state = self.built()
        assert state.virtual_ip_padding == bytes(12)
        assert state == self.built(virtual_ip_padding=None)
        assert state == self.built(virtual_ip_padding=bytes(12))
        assert hash(state) == hash(self.built(virtual_ip_padding=bytes(12)))
        assert state == HSRPv2.decode(HELLO).group_state
        assert bytes(state) == HELLO

    def test_an_ipv6_group_state_without_padding_gets_none(self):
        state = self.built(ip_version=6, virtual_ip=V6_VIP)
        assert state.virtual_ip_padding == b""
        assert state == self.built(
            ip_version=6, virtual_ip=V6_VIP, virtual_ip_padding=b""
        )
        assert bytes(state) == VECTORS["v6_hello"][1]

    def test_given_padding_is_kept(self):
        state = self.built(virtual_ip_padding=bytes(range(1, 13)))
        assert state.virtual_ip_padding == bytes(range(1, 13))
        assert bytes(state)[30:] == bytes(range(1, 13))
        assert state != self.built()

    @pytest.mark.parametrize(
        "ip_version,virtual_ip,padding",
        [
            (4, "192.0.2.1", b""),
            (4, "192.0.2.1", bytes(11)),
            (4, "192.0.2.1", bytes(13)),
            (6, V6_VIP, bytes(12)),
            (6, V6_VIP, b"\x00"),
        ],
    )
    def test_given_padding_of_another_length(
        self, ip_version, virtual_ip, padding
    ):
        with pytest.raises(InvalidFieldError) as caught:
            self.built(
                ip_version=ip_version,
                virtual_ip=virtual_ip,
                virtual_ip_padding=padding,
            )
        assert caught.value.field == "virtual_ip_padding"
        assert caught.value.expected == (12 if ip_version == 4 else 0)
        assert caught.value.actual == len(padding)

    def test_construction_accepts_what_decode_rejects(self):
        """Any Version, Op Code or State that fits its byte builds, and
        decode rejects the message it serializes to."""
        state = state_of(version=3, opcode=9, state=99)
        assert state.opcode_name == "unknown (9)"
        assert state.state_name == "unknown (99)"
        with pytest.raises(InvalidFieldError):
            HSRPv2.decode(bytes(HSRPv2((state,))))

    def test_an_ipv6_group_state(self):
        state = state_of(ip_version=6, virtual_ip="::1", virtual_ip_padding=b"")
        assert bytes(state)[26:] == bytes(15) + b"\x01"
        assert HSRPv2.decode(bytes(state)).group_state == state

    @pytest.mark.parametrize(
        "kwargs,field",
        [
            ({"auth_data": b"cisco"}, "auth_data"),
            ({"auth_data": bytes(9)}, "auth_data"),
        ],
    )
    def test_a_text_authentication_of_another_length(self, kwargs, field):
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2TextAuthentication(**kwargs)
        assert caught.value.field == field

    @pytest.mark.parametrize(
        "field,value",
        [
            ("algorithm", 256),
            ("padding", -1),
            ("flags", 0x10000),
            ("key_id", 2**32),
            ("digest", bytes(15)),
        ],
    )
    def test_an_md5_authentication_field_out_of_range(self, field, value):
        md5 = HSRPv2.decode(VECTORS["v4_coup_md5"][1]).md5_authentication
        with pytest.raises(InvalidFieldError) as caught:
            replace(md5, **{field: value})
        assert caught.value.field == field
        with pytest.raises(InvalidIPv4AddressError):
            replace(md5, ip_address="::1")

    @pytest.mark.parametrize("kind", [1, 2, 3, 4])
    def test_a_raw_tlv_of_a_typed_type(self, kind):
        """Types 1-4 have their own classes."""
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2TLV(kind, bytes(8))
        assert (caught.value.field, caught.value.actual) == ("type", kind)

    def test_a_raw_tlv_out_of_range(self):
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2TLV(256)
        assert caught.value.field == "type"
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2TLV(5, bytes(256))
        assert caught.value.field == "value"
        assert len(bytes(HSRPv2TLV(5, bytes(255)))) == 257

    def test_a_message_must_open_with_a_group_state_tlv(self):
        state = HSRPv2.decode(HELLO).group_state
        auth = HSRPv2TextAuthentication(bytes(8))
        for tlvs in ((), (auth,), (auth, state)):
            with pytest.raises(InvalidFieldError) as caught:
                HSRPv2(tlvs)
            assert caught.value.field == "tlvs"
        with pytest.raises(InvalidFieldError) as caught:
            HSRPv2((state, b"\x02\x00"))
        assert caught.value.field == "tlvs"
        assert bytes(HSRPv2((state, auth))) == HELLO + bytes([3, 8]) + bytes(8)


# --- Display ----------------------------------------------------------


class TestDisplay:
    @pytest.mark.parametrize(
        "state,name",
        [
            (0, "Disabled"),
            (1, "Initial"),
            (2, "Learn"),
            (3, "Listen"),
            (4, "Speak"),
            (5, "Standby"),
            (6, "Active"),
        ],
    )
    def test_every_state_is_named(self, state, name):
        decoded = HSRPv2.decode(changed(HELLO, 4, state)).group_state
        assert decoded.state_name == name

    @pytest.mark.parametrize(
        "opcode,name", [(0, "Hello"), (1, "Coup"), (2, "Resign")]
    )
    def test_every_opcode_is_named(self, opcode, name):
        decoded = HSRPv2.decode(changed(HELLO, 3, opcode)).group_state
        assert decoded.opcode_name == name

    @pytest.mark.parametrize(
        "ip_version,group,mac",
        [
            (4, 0, "00:00:0c:9f:f0:00"),
            (4, 1, "00:00:0c:9f:f0:01"),
            (4, 0x123, "00:00:0c:9f:f1:23"),
            (4, 4095, "00:00:0c:9f:ff:ff"),
            (6, 0, "00:05:73:a0:00:00"),
            (6, 1, "00:05:73:a0:00:01"),
            (6, 4095, "00:05:73:a0:0f:ff"),
        ],
    )
    def test_the_virtual_mac(self, ip_version, group, mac):
        address = V6_ADDRESS if ip_version == 6 else None
        raw = group_state(ip_version=ip_version, group=group, address=address)
        state = HSRPv2.decode(raw).group_state
        assert state.virtual_mac == mac
        assert state.ip_version_name == f"IPv{ip_version}"

    def test_a_text_authentication_display(self):
        assert HSRPv2TextAuthentication(bytes(8)).auth_data_str == ""
        assert HSRPv2TextAuthentication(bytes(8)).password == b""
        binary = HSRPv2TextAuthentication(b"\x00\xff" + bytes(6))
        assert binary.auth_data_str == "0x00ff000000000000"
        assert not binary.is_default_auth

    def test_unknown_names(self):
        md5 = HSRPv2.decode(VECTORS["v4_coup_md5"][1]).md5_authentication
        assert replace(md5, algorithm=2).algorithm_name == "unknown (2)"
        assert HSRPv2TLV(9).type_name == "unknown (9)"


# --- Dispatch ---------------------------------------------------------


class TestDispatch:
    def test_hsrp_chooses_by_the_first_byte(self):
        """1, the Group State TLV's Type, names HSRPv2 whatever the
        second byte; every other first byte is left to HSRP, but for the
        Advertise's 00 03."""
        for lead in range(1 << 16):
            if lead >> 8 == 1:
                expected = HSRPv2
            elif lead == 0x0003:
                expected = HSRPAdvertise
            else:
                expected = HSRP
            assert HSRP._for_payload(lead) is expected
        assert HSRPv2._for_payload(0) is HSRPv2

    def test_registered_on_ports_1985_and_2029(self):
        assert DEFAULT.get(TABLE_UDP_PORT, 1985) is HSRP
        assert DEFAULT.get(TABLE_UDP_PORT, 2029) is HSRPv2

    @pytest.mark.parametrize(
        "src_port,dst_port", [(1985, 1985), (40000, 1985), (1985, 40000)]
    )
    def test_port_1985_reaches_hsrpv2(self, src_port, dst_port):
        frame = ipv4_frame(HELLO, src_port=src_port, dst_port=dst_port)
        assert decode_frame(frame)[HSRPv2] == HSRPv2.decode(HELLO)

    @pytest.mark.parametrize(
        "src_port,dst_port", [(2029, 2029), (40000, 2029), (2029, 40000)]
    )
    def test_port_2029_names_hsrpv2(self, src_port, dst_port):
        raw = VECTORS["v6_hello"][1]
        frame = ipv6_frame(raw, src_port=src_port, dst_port=dst_port)
        assert decode_frame(frame)[HSRPv2] == HSRPv2.decode(raw)

    def test_hsrpv1_on_port_1985_is_unchanged(self):
        hello = bytes.fromhex("000004030a640100636973636f000000c0000201")
        packet = decode_frame(ipv4_frame(hello))
        assert packet[HSRP] == HSRP.decode(hello)

    def test_an_hsrpv1_message_on_port_2029_is_rejected(self):
        """Port 2029 names HSRPv2 alone, which rejects a Version of 0 at
        its Type."""
        hello = bytes.fromhex("000004030a640100636973636f000000c0000201")
        packet = decode_frame(ipv6_frame(hello), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv6, UDP]
        assert packet.stopped_by.field == "type"

    def test_decode_as_carries_the_choice(self):
        """HSRP named for another port chooses HSRPv2 there too."""
        frame = ipv4_frame(HELLO, src_port=40000, dst_port=40001)
        assert [type(layer) for layer in decode_frame(frame)][-1] is UDP
        packet = decode_frame(frame, decode_as={"udp.port": {40001: HSRP}})
        assert packet[HSRPv2] == HSRPv2.decode(HELLO)
