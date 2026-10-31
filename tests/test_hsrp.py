"""Test HSRPv1 (RFC 2281) decoding and dispatch.

Covered: the 20-byte message, every Op Code and State, its round trips,
truncation at every length, what follows it in the buffer, the
decode-time guard against a wrong port guess (HSRPv2 and Cisco's Op
Code 3 Advertise among what it rejects), the display helpers,
construction, and dispatch from UDP port 1985.

The Cisco routers' exchange in tests/fixtures/hsrp.pcap (a public
Wireshark capture; see its MANIFEST note) anchors the decode,
round-trip and protocol-behaviour asserts: Hellos in Speak, Standby and
Active, two Coups and a Resign. What the capture does not hold (the
Initial and Learn states, HSRPv2, an Advertise, trailers, values the
guard rejects) is built here.
"""

from dataclasses import replace

import pytest

from conftest import FIXTURES
from netprotocols import (
    DNS,
    HSRP,
    UDP,
    Ethernet,
    InvalidFieldError,
    InvalidIPv4AddressError,
    IPv4,
    TruncatedHeaderError,
    decode_frame,
    read_pcap,
)
from netprotocols.registry import DEFAULT, TABLE_UDP_PORT

FRAMES = [
    frame.data for frame in read_pcap((FIXTURES / "hsrp.pcap").read_bytes())
]

#: Ethernet + a 20-byte IPv4 header + UDP, in front of every message.
HSRP_START = 14 + 20 + 8

#: The two routers, by their own (not the virtual) address.
ROUTER_A = "192.168.23.1"
ROUTER_B = "192.168.23.2"

#: The fixture's frames, by what they are (see MANIFEST.md's row).
B_ALONE = range(0, 14)
COUP_FROM_LISTEN = 14
A_FIRST_ACTIVE = 15
RESIGN = 16
COUP_FROM_ACTIVE = 18
B_LAST_STANDBY = 26

#: RFC 2281 §5.1's States, by value.
STATES = {
    0: "Initial",
    1: "Learn",
    2: "Listen",
    4: "Speak",
    8: "Standby",
    16: "Active",
}

#: RFC 2281 §5.1's Op Codes, by value.
OPCODES = {0: "Hello", 1: "Coup", 2: "Resign"}

#: The default Authentication Data (RFC 2281 §5.1).
CISCO = b"cisco\x00\x00\x00"

#: An HSRPv2 Hello, as Wireshark's packet-hsrp.c lays it out: a Group
#: State TLV (type 1, length 40: version 2, Op Code 0, State 6 Active,
#: IP version 4, group 1, a 6-byte identifier, priority 100, Hellotime
#: 3000 and Holdtime 10000 ms, the virtual IP in 16 bytes) and a Text
#: Authentication TLV (type 3, length 8, "cisco").
HSRPV2_HELLO = (
    bytes.fromhex("012802000604000102000c9ff001")
    + (100).to_bytes(4, "big")
    + (3000).to_bytes(4, "big")
    + (10000).to_bytes(4, "big")
    + bytes([192, 168, 23, 250])
    + bytes(12)
    + bytes.fromhex("0308")
    + CISCO
)

#: An Op Code 3 interface-state Advertise, as packet-hsrp.c lays it
#: out: Version 0, Op Code 3, then a TLV, type 1 (HSRP interface state)
#: and length 14, its own 4 bytes counted: State 2 (Passive), a reserved
#: byte, 1 active group, 0 passive groups, 4 reserved bytes. 16 bytes in
#: all.
ADVERTISE = bytes.fromhex("00030001000e02000001000000000000")

#: An MD5 Authentication TLV as packet-hsrp.c lays it out after a
#: 20-byte HSRPv1 message: type 4, length 28, algorithm 1 (MD5), a
#: padding byte, 2 bytes of flags, the sender's address, a 4-byte Key
#: ID and a 16-byte digest. 30 bytes in all.
MD5_TLV = bytes.fromhex("041c01000000c0a8170200000001") + bytes(range(16))


def message_bytes(index: int) -> bytes:
    """Return the HSRP message of capture frame ``index``, exactly."""
    return FRAMES[index][HSRP_START:]


def hsrp_of(index: int) -> HSRP:
    layer = decode_frame(FRAMES[index])[HSRP]
    assert isinstance(layer, HSRP)
    return layer


def message(**fields: object) -> HSRP:
    """The capture's first Hello, with ``fields`` replaced."""
    return replace(HSRP.decode(message_bytes(0)), **fields)


def udp_frame(payload: bytes, src_port: int = 1985) -> bytes:
    """``payload`` in a UDP datagram to port 1985, behind the Ethernet
    and IPv4 headers of the first captured frame, its total length
    rewritten (its header checksum is left stale; nothing here checks
    it)."""
    ip = bytearray(FRAMES[0][14:34])
    ip[2:4] = (20 + 8 + len(payload)).to_bytes(2, "big")
    udp = bytes(
        UDP(
            src_port=src_port,
            dst_port=1985,
            length=8 + len(payload),
            checksum=0,
        )
    )
    return FRAMES[0][:14] + bytes(ip) + udp + payload


class TestCapturedMessages:
    def test_every_frame_walks_to_hsrp_and_ends_there(self):
        """Each frame walks Ethernet, IPv4, UDP, HSRP and consumes it."""
        assert len(FRAMES) == 27
        for frame in FRAMES:
            packet = decode_frame(frame)
            assert [type(layer) for layer in packet] == [
                Ethernet,
                IPv4,
                UDP,
                HSRP,
            ]
            assert packet.consumed == len(frame) == 62
            assert packet.stopped_by is None

    def test_every_message_round_trips_exactly(self):
        """Each captured message re-encodes to its bytes, both ways."""
        for index in range(len(FRAMES)):
            raw = message_bytes(index)
            hsrp = HSRP.decode(raw)
            assert bytes(hsrp) == raw
            assert len(raw) == hsrp.header_len == 20
            assert HSRP.decode(bytes(hsrp)) == hsrp

    def test_the_exchange(self):
        """Who sent what, frame by frame (the MANIFEST row).

        B alone runs Speak, Standby and Active; A, with the higher
        priority, preempts it with a Coup, B resigns, A sends a second
        Coup once Active, and B settles in Speak and then Standby.
        """
        b_early = (ROUTER_B, "Hello", "Speak", 3, 10, 100)
        b_active = (ROUTER_B, "Hello", "Active", 5, 15, 100)
        b_speak = (ROUTER_B, "Hello", "Speak", 5, 15, 100)
        a_active = (ROUTER_A, "Hello", "Active", 5, 15, 110)
        expected = [
            *[b_early] * 4,
            (ROUTER_B, "Hello", "Standby", 3, 10, 100),
            *[b_active] * 9,
            (ROUTER_A, "Coup", "Listen", 5, 15, 110),
            a_active,
            (ROUTER_B, "Resign", "Speak", 5, 15, 100),
            b_speak,
            (ROUTER_A, "Coup", "Active", 5, 15, 110),
            *[a_active, b_speak] * 3,
            a_active,
            (ROUTER_B, "Hello", "Standby", 5, 15, 100),
        ]
        seen = []
        for frame in FRAMES:
            packet = decode_frame(frame)
            hsrp = packet[HSRP]
            seen.append(
                (
                    packet[IPv4].src,
                    hsrp.opcode_name,
                    hsrp.state_name,
                    hsrp.hellotime,
                    hsrp.holdtime,
                    hsrp.priority,
                )
            )
        assert seen == expected

    def test_every_op_code_is_captured(self):
        """24 Hellos, 2 Coups and 1 Resign."""
        opcodes = [hsrp_of(i).opcode for i in range(len(FRAMES))]
        assert [opcodes.count(op) for op in (0, 1, 2)] == [24, 2, 1]

    def test_the_fields_every_message_shares(self):
        """One group, one virtual IP, the default Authentication Data,
        version 0 and a zero Reserved byte."""
        for index in range(len(FRAMES)):
            hsrp = hsrp_of(index)
            assert (hsrp.version, hsrp.group, hsrp.reserved) == (0, 1, 0)
            assert hsrp.virtual_ip == "192.168.23.250"
            assert hsrp.auth_data == CISCO
            assert hsrp.password == b"cisco"
            assert hsrp.auth_data_str == "cisco"
            assert hsrp.is_default_auth

    def test_sent_as_rfc_2281_section_5_1_says(self):
        """From and to UDP 1985, to 224.0.0.2, from the router's own
        address, not the virtual one, as RFC 2281 §5.1 says; but with
        TTL 2, where it says TTL 1, as these routers' IOS sent it (kept
        as captured; HSRP.decode() does not see the IP header)."""
        for frame in FRAMES:
            packet = decode_frame(frame)
            ip, udp = packet[IPv4], packet[UDP]
            assert (udp.src_port, udp.dst_port) == (1985, 1985)
            assert (ip.dst, ip.ttl) == ("224.0.0.2", 2)
            assert ip.src in (ROUTER_A, ROUTER_B)
            assert ip.src != packet[HSRP].virtual_ip
            assert packet[Ethernet].dst == "01:00:5e:00:00:02"

    def test_the_virtual_mac_is_the_active_routers_source(self):
        """A router sends from the group's virtual MAC address if and
        only if it is Active (RFC 2281 §6.1), in Coups as in Hellos;
        otherwise from its own."""
        own = {ROUTER_A: "00:10:7b:7e:f4:aa", ROUTER_B: "00:10:7b:35:f5:b5"}
        for frame in FRAMES:
            packet = decode_frame(frame)
            hsrp = packet[HSRP]
            assert hsrp.virtual_mac == "00:00:0c:07:ac:01"
            if hsrp.state_name == "Active":
                assert packet[Ethernet].src == hsrp.virtual_mac
            else:
                assert packet[Ethernet].src == own[packet[IPv4].src]

    def test_the_coup_comes_from_the_higher_priority(self):
        """A preempts B with a Coup only once B is Active, at a higher
        priority than B's (RFC 2281 §5.2's preemption)."""
        coup, active = hsrp_of(COUP_FROM_LISTEN), hsrp_of(B_ALONE[-1])
        assert (coup.opcode_name, coup.state_name) == ("Coup", "Listen")
        assert (active.opcode_name, active.state_name) == ("Hello", "Active")
        assert coup.priority > active.priority

    def test_the_resign_follows_the_coup(self):
        """B, Active until the Coup, resigns from Speak, and A's second
        Coup is sent once it is Active itself."""
        resign = hsrp_of(RESIGN)
        assert (resign.opcode_name, resign.state_name) == ("Resign", "Speak")
        assert decode_frame(FRAMES[RESIGN])[IPv4].src == ROUTER_B
        second = hsrp_of(COUP_FROM_ACTIVE)
        assert (second.opcode_name, second.state_name) == ("Coup", "Active")
        assert hsrp_of(A_FIRST_ACTIVE).state_name == "Active"

    def test_hello_holdtimes_exceed_their_hellotimes(self):
        """The Holdtime "SHOULD be at least three times the value of
        the Hellotime and MUST be greater than" it (§5.1)."""
        for index in range(len(FRAMES)):
            hsrp = hsrp_of(index)
            assert hsrp.holdtime >= 3 * hsrp.hellotime > 0

    def test_b_ends_in_standby(self):
        """The last frame kept: B's first Standby Hello under A."""
        last = decode_frame(FRAMES[B_LAST_STANDBY])
        assert (last[IPv4].src, last[HSRP].state_name) == (ROUTER_B, "Standby")

    def test_raw_fixture_matches_the_capture(self, raw_hsrp_hello):
        """conftest's raw_hsrp_hello is this capture's first message."""
        assert raw_hsrp_hello == message_bytes(0)

    def test_positional_patterns_follow_wire_order(self):
        """Positional patterns bind the fields in wire order."""
        match HSRP.decode(message_bytes(COUP_FROM_LISTEN)):
            case HSRP(0, 1, 2, 5, 15, 110, 1, 0, auth, vip):
                assert (auth, vip) == (CISCO, "192.168.23.250")
            case _:
                pytest.fail("positional pattern did not match")


class TestMessage:
    @pytest.mark.parametrize("opcode,name", OPCODES.items())
    def test_every_op_code_shares_the_layout(self, opcode, name):
        """Hello, Coup and Resign differ only in the Op Code's value."""
        raw = bytes([0, opcode]) + message_bytes(0)[2:]
        hsrp = HSRP.decode(raw)
        assert (hsrp.opcode, hsrp.opcode_name) == (opcode, name)
        assert replace(hsrp, opcode=0) == HSRP.decode(message_bytes(0))
        assert bytes(hsrp) == raw

    @pytest.mark.parametrize("state,name", STATES.items())
    def test_every_state_decodes(self, state, name):
        """RFC 2281 §5.1's six states, the uncaptured Initial and Learn
        among them."""
        raw = bytes([0, 0, state]) + message_bytes(0)[3:]
        hsrp = HSRP.decode(raw)
        assert (hsrp.state, hsrp.state_name) == (state, name)
        assert bytes(hsrp) == raw

    def test_the_fields_in_wire_order(self, raw_hsrp_hello):
        """Each byte lands in its field (§5.1's figure)."""
        hsrp = HSRP.decode(raw_hsrp_hello)
        assert (
            hsrp.version,
            hsrp.opcode,
            hsrp.state,
            hsrp.hellotime,
            hsrp.holdtime,
            hsrp.priority,
            hsrp.group,
            hsrp.reserved,
        ) == (0, 0, 4, 3, 10, 100, 1, 0)
        assert hsrp.auth_data == raw_hsrp_hello[8:16] == CISCO
        assert hsrp.virtual_ip == "192.168.23.250"

    def test_each_byte_is_its_own_field(self):
        """Distinct values in every position come back where they were."""
        raw = bytes([0, 2, 16, 0x11, 0x22, 0x33, 0x44, 0x55])
        raw += bytes(range(0xA0, 0xA8)) + bytes([10, 20, 30, 40])
        hsrp = HSRP.decode(raw)
        assert (
            hsrp.hellotime,
            hsrp.holdtime,
            hsrp.priority,
            hsrp.group,
            hsrp.reserved,
        ) == (0x11, 0x22, 0x33, 0x44, 0x55)
        assert hsrp.auth_data == bytes(range(0xA0, 0xA8))
        assert hsrp.virtual_ip == "10.20.30.40"
        assert bytes(hsrp) == raw

    @pytest.mark.parametrize("length", range(20))
    def test_truncated_at_every_length(self, raw_hsrp_hello, length):
        """Every prefix short of 20 bytes, its leading bytes valid."""
        with pytest.raises(TruncatedHeaderError) as caught:
            HSRP.decode(raw_hsrp_hello[:length])
        error = caught.value
        assert error.protocol is HSRP
        assert (error.offset, error.expected, error.actual) == (0, 20, length)

    @pytest.mark.parametrize(
        "trailer",
        [
            pytest.param(b"\xde\xad\xbe\xef", id="fcs"),
            pytest.param(bytes(30), id="zeros"),
            pytest.param(MD5_TLV, id="md5-tlv"),
            pytest.param(message_bytes(1), id="another-message"),
        ],
    )
    def test_what_follows_is_left_undecoded(self, raw_hsrp_hello, trailer):
        """The message is always 20 bytes (decode contract rule 3)."""
        hsrp = HSRP.decode(raw_hsrp_hello + trailer)
        assert hsrp == HSRP.decode(raw_hsrp_hello)
        assert hsrp.header_len == 20
        assert bytes(hsrp) == raw_hsrp_hello

    def test_a_walk_leaves_an_md5_authentication_tlv(self):
        """A 50-byte HSRPv1 message, the 30-byte MD5 Authentication TLV
        after the 20 (type 4, length 28), as Wireshark's packet-hsrp.c
        reads it: the walk decodes the 20 and stops there."""
        assert len(MD5_TLV) == 30
        frame = udp_frame(message_bytes(0) + MD5_TLV)
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP, HSRP]
        assert packet.consumed == len(frame) - len(MD5_TLV)
        assert packet[HSRP] == hsrp_of(0)

    def test_memoryview_input_is_not_retained(self, raw_hsrp_hello):
        """A decode from a view copies the bytes out of it."""
        buffer = bytearray(raw_hsrp_hello)
        hsrp = HSRP.decode(memoryview(buffer))
        buffer[8:20] = bytes(12)
        assert isinstance(hsrp.auth_data, bytes)
        assert hsrp == HSRP.decode(raw_hsrp_hello)

    def test_zero_bytes_are_an_initial_hello(self):
        """20 zero bytes pass the guard: a Hello in Initial state."""
        hsrp = HSRP.decode(bytes(20))
        assert (hsrp.opcode_name, hsrp.state_name) == ("Hello", "Initial")
        assert (hsrp.virtual_ip, hsrp.password) == ("0.0.0.0", b"")


class TestDecodeGuard:
    @pytest.mark.parametrize("version", [1, 2, 3, 0x10, 0xFF])
    @pytest.mark.parametrize("length", [1, 20, 60])
    def test_a_version_other_than_0(self, version, length):
        """RFC 2281 describes version 0 only, at any length."""
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(bytes([version]) + bytes(length - 1))
        error = caught.value
        assert error.protocol is HSRP
        assert (error.field, error.offset) == ("version", 0)
        assert (error.expected, error.actual) == ("0", version)

    @pytest.mark.parametrize("opcode", [3, 4, 0x80, 0xFF])
    def test_an_op_code_other_than_hello_coup_resign(self, opcode):
        """Only Hello, Coup and Resign are this layout."""
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(bytes([0, opcode]) + message_bytes(0)[2:])
        error = caught.value
        assert (error.field, error.offset) == ("opcode", 1)
        assert (error.expected, error.actual) == ("0-2", opcode)

    @pytest.mark.parametrize("state", [3, 5, 6, 7, 9, 15, 17, 32, 0xFF])
    def test_a_state_rfc_2281_does_not_list(self, state):
        """The States are 0, 1, 2, 4, 8 and 16; the values between are
        not States."""
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(bytes([0, 0, state]) + message_bytes(0)[3:])
        error = caught.value
        assert (error.field, error.offset) == ("state", 2)
        assert error.expected == "0, 1, 2, 4, 8, 16"
        assert error.actual == state

    def test_the_leading_bytes_are_judged_before_the_length(self):
        """Version, then Op Code, then State, each once its byte is
        there, and only then the length."""
        for raw, field in [
            (b"\x01", "version"),
            (b"\x01\x07\x07", "version"),
            (b"\x00\x03", "opcode"),
            (b"\x00\x03\x03", "opcode"),
            (b"\x00\x00\x03", "state"),
        ]:
            with pytest.raises(InvalidFieldError) as caught:
                HSRP.decode(raw)
            assert caught.value.field == field, raw
        for raw in (b"", b"\x00", b"\x00\x02", b"\x00\x02\x10"):
            with pytest.raises(TruncatedHeaderError):
                HSRP.decode(raw)

    def test_exactly_18_of_the_first_three_bytes_values_pass(self):
        """1 Version x 3 Op Codes x 6 States, each byte judged alone, so
        a random datagram on port 1985 passes 18 times in 2**24."""
        rest = message_bytes(0)[3:]

        def passes(lead: bytes) -> bool:
            try:
                HSRP.decode(lead + rest)
            except InvalidFieldError:
                return False
            return True

        versions = [v for v in range(256) if passes(bytes([v, 0, 0]))]
        opcodes = [o for o in range(256) if passes(bytes([0, o, 0]))]
        states = [s for s in range(256) if passes(bytes([0, 0, s]))]
        assert versions == [0]
        assert opcodes == [0, 1, 2]
        assert states == [0, 1, 2, 4, 8, 16]
        for opcode in range(256):
            for state in (0, 3, 16):
                lead = bytes([0, opcode, state])
                assert passes(lead) == (opcode < 3 and state != 3)

    def test_the_other_fields_are_not_judged(self):
        """Any timers, Priority, Group, Reserved byte, Authentication
        Data and Virtual IP Address decode."""
        raw = bytes([0, 1, 8]) + b"\xff" * 17
        hsrp = HSRP.decode(raw)
        assert (hsrp.hellotime, hsrp.holdtime, hsrp.reserved) == (255,) * 3
        assert hsrp.virtual_ip == "255.255.255.255"
        assert bytes(hsrp) == raw

    def test_hsrpv2_is_rejected_at_its_first_byte(self):
        """An HSRPv2 message starts with its Group State TLV's type, 1,
        where HSRPv1 has its Version: never misread as HSRPv1."""
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(HSRPV2_HELLO)
        error = caught.value
        assert (error.field, error.offset, error.actual) == ("version", 0, 1)
        assert "HSRPv2" in str(error)

    def test_an_advertise_is_rejected_at_its_op_code(self):
        """Cisco's Op Code 3 Advertise is version 0, but not this
        layout, and only 16 bytes: rejected for its Op Code, not its
        length."""
        assert len(ADVERTISE) == 16
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(ADVERTISE)
        error = caught.value
        assert (error.field, error.offset, error.actual) == ("opcode", 1, 3)
        assert "Advertise" in str(error)

    def test_other_rejections_name_neither(self):
        """The hints are for the two known kinds alone."""
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(b"\x02" + bytes(19))
        assert "HSRPv2" not in str(caught.value)
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(b"\x00\x04" + bytes(18))
        assert "Advertise" not in str(caught.value)

    @pytest.mark.parametrize(
        "payload,field",
        [
            pytest.param(HSRPV2_HELLO, "version", id="hsrpv2"),
            pytest.param(ADVERTISE, "opcode", id="advertise"),
        ],
    )
    def test_a_strict_walk_raises_at_the_hsrp_header(self, payload, field):
        """Port 1985 dispatches either to HSRP, which rejects it."""
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(udp_frame(payload))
        error = caught.value
        assert (error.field, error.frame_offset) == (
            field,
            HSRP_START + (field == "opcode"),
        )

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(HSRPV2_HELLO, id="hsrpv2"),
            pytest.param(ADVERTISE, id="advertise"),
        ],
    )
    def test_a_lax_walk_stops_at_udp(self, payload):
        """lax=True keeps Ethernet, IPv4 and UDP and says why."""
        packet = decode_frame(udp_frame(payload), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, InvalidFieldError)
        assert packet.consumed == HSRP_START

    def test_a_short_datagram_is_truncated_in_a_walk(self):
        """A datagram to 1985 shorter than the message, its leading
        bytes valid: the walk stops at HSRP's header."""
        packet = decode_frame(udp_frame(message_bytes(0)[:12]), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)
        assert packet.stopped_by.frame_offset == HSRP_START


class TestDisplay:
    def test_unknown_values_name_themselves(self):
        """Construction accepts what decode rejects; the names fall back."""
        hsrp = message(opcode=3, state=5)
        assert (hsrp.opcode_name, hsrp.state_name) == (
            "unknown (3)",
            "unknown (5)",
        )

    @pytest.mark.parametrize(
        "auth_data,password,shown",
        [
            (CISCO, b"cisco", "cisco"),
            (b"np-hsrp1", b"np-hsrp1", "np-hsrp1"),
            (bytes(8), b"", ""),
            (b"ab\x00cd\x00\x00\x00", b"ab\x00cd", "0x6162006364000000"),
            (b"\x00" * 7 + b"x", b"\x00" * 7 + b"x", "0x" + "00" * 7 + "78"),
            (b"\xff" * 8, b"\xff" * 8, "0x" + "ff" * 8),
            (b"cisc\x7f\x00\x00\x00", b"cisc\x7f", "0x636973637f000000"),
            (b" ~\x00" + bytes(5), b" ~", " ~"),
        ],
    )
    def test_the_authentication_data(self, auth_data, password, shown):
        """Only trailing NUL padding is stripped, and text is shown
        only when it is all printable ASCII; hex otherwise."""
        hsrp = message(auth_data=auth_data)
        assert hsrp.password == password
        assert hsrp.auth_data_str == shown
        assert hsrp.auth_data == auth_data

    def test_the_default_authentication_data(self):
        """Exactly ``cisco`` and three NUL bytes (§5.1)."""
        assert message().is_default_auth
        assert not message(auth_data=b"cisco\x00\x00\x01").is_default_auth
        assert not message(auth_data=b"Cisco\x00\x00\x00").is_default_auth

    @pytest.mark.parametrize(
        "group,mac",
        [
            (0, "00:00:0c:07:ac:00"),
            (1, "00:00:0c:07:ac:01"),
            (10, "00:00:0c:07:ac:0a"),
            (255, "00:00:0c:07:ac:ff"),
        ],
    )
    def test_the_virtual_mac(self, group, mac):
        """``00:00:0c:07:ac`` and the group number (§6.1)."""
        assert message(group=group).virtual_mac == mac


class TestConstruction:
    def test_build_a_coup(self):
        """A message built from fields is its 20 bytes and decodes back."""
        hsrp = HSRP(
            version=0,
            opcode=1,
            state=16,
            hellotime=3,
            holdtime=10,
            priority=120,
            group=7,
            reserved=0,
            auth_data=CISCO,
            virtual_ip="192.0.2.1",
        )
        raw = bytes(hsrp)
        assert raw == (
            bytes([0, 1, 16, 3, 10, 120, 7, 0]) + CISCO + bytes([192, 0, 2, 1])
        )
        assert HSRP.decode(raw) == hsrp
        assert decode_frame(udp_frame(raw))[HSRP] == hsrp

    @pytest.mark.parametrize(
        "name",
        [
            "version",
            "opcode",
            "state",
            "hellotime",
            "holdtime",
            "priority",
            "group",
            "reserved",
        ],
    )
    @pytest.mark.parametrize("value", [-1, 256])
    def test_a_field_too_wide_for_its_byte(self, name, value):
        """Every integer field is one byte."""
        with pytest.raises(InvalidFieldError) as caught:
            message(**{name: value})
        error = caught.value
        assert (error.field, error.expected, error.actual) == (
            name,
            "0-255",
            value,
        )

    @pytest.mark.parametrize("length", [0, 5, 7, 9])
    def test_authentication_data_is_8_bytes(self, length):
        """§5.1's 8 octets, no more and no fewer."""
        with pytest.raises(InvalidFieldError) as caught:
            message(auth_data=b"x" * length)
        error = caught.value
        assert (error.field, error.expected, error.actual) == (
            "auth_data",
            8,
            length,
        )

    @pytest.mark.parametrize(
        "address", ["192.168.23", "256.0.0.1", "::1", "", "a.b.c.d"]
    )
    def test_the_virtual_ip_is_dotted_decimal(self, address):
        """The address is checked on construction, not left to bytes()."""
        with pytest.raises(InvalidIPv4AddressError) as caught:
            message(virtual_ip=address)
        assert (caught.value.protocol, caught.value.field) == (
            HSRP,
            "virtual_ip",
        )

    def test_what_decode_rejects_still_builds(self):
        """Construction accepts what the guard refuses, for tests of
        another stack; decoding it back raises."""
        for fields, field in [
            ({"version": 2}, "version"),
            ({"opcode": 3}, "opcode"),
            ({"state": 3}, "state"),
        ]:
            hsrp = message(**fields)
            assert len(bytes(hsrp)) == 20
            with pytest.raises(InvalidFieldError) as caught:
                HSRP.decode(bytes(hsrp))
            assert caught.value.field == field

    def test_the_widest_values_round_trip(self):
        """Every field at its top value, but the three decode judges."""
        hsrp = HSRP(0, 2, 16, 255, 255, 255, 255, 255, b"\xff" * 8, "0.0.0.0")
        assert HSRP.decode(bytes(hsrp)) == hsrp


class TestDispatch:
    def test_registered_on_port_1985(self):
        """The default registry maps UDP port 1985 to HSRP."""
        assert DEFAULT.get(TABLE_UDP_PORT, 1985) is HSRP

    @pytest.mark.parametrize(
        "src_port,dst_port", [(1985, 1985), (40000, 1985), (1985, 40000)]
    )
    def test_either_port(self, src_port, dst_port):
        """HSRP is sent from and to 1985; either finds it."""
        udp = UDP(src_port=src_port, dst_port=dst_port, length=0, checksum=0)
        assert udp.next_protocol() is HSRP

    def test_a_datagram_from_another_port(self):
        """The destination port alone dispatches a walk."""
        frame = udp_frame(message_bytes(RESIGN), src_port=40000)
        assert decode_frame(frame)[HSRP] == hsrp_of(RESIGN)

    def test_hsrp_ends_the_chain(self):
        """HSRP carries no further protocol."""
        assert hsrp_of(COUP_FROM_ACTIVE).next_protocol() is None

    def test_decode_as_can_take_the_port_away(self):
        """Let a caller decode port 1985 as something else for one walk.

        It is best-effort, like every port entry.
        """
        packet = decode_frame(FRAMES[0], decode_as={"udp.port": {1985: DNS}})
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP, DNS]
