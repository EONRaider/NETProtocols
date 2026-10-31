"""Test HSRPv1 (RFC 2281) decoding and dispatch.

Covered: the 20-byte message, every Op Code and State, its round trips,
truncation at every length, what follows it in the buffer, the
decode-time guard against a wrong port guess (HSRPv2 and Cisco's Op
Code 3 Advertise among what it rejects), the display helpers,
construction, dispatch from UDP port 1985, and scripts/check_fixtures.py's
HSRP checks.

The unit tests build their messages and frames here, byte by byte, so
none of them depends on a capture. The Yersinia capture in
tests/fixtures/hsrp.pcap (see its MANIFEST note) anchors only the tests
about it: its twelve frames, an election and failover in group 1 and a
second group with a configured password. A Cisco IOS exchange, which
sends TTL 2 where RFC 2281 says 1, moves from the 3 s / 10 s timers to
5 s / 15 s on becoming Active and is preempted by a Coup, is built here
as constructed frames, as is what neither holds (the Initial and Learn
states, HSRPv2, an Advertise, trailers, values the guard rejects).
scripts/check_fixtures.py, which shares no code with the library, is
run over the capture, the constructed frames and tampered copies of
both.
"""

import importlib.util
import socket
import struct
from dataclasses import replace
from pathlib import Path

import pytest

from conftest import FIXTURES, pcap_frames
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
)
from netprotocols.registry import DEFAULT, TABLE_UDP_PORT

CHECKER = Path(__file__).resolve().parent.parent / "scripts/check_fixtures.py"

#: Ethernet + a 20-byte IPv4 header + UDP, in front of every message.
HSRP_START = 14 + 20 + 8

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

#: The default Authentication Data (RFC 2281 §5.1), and the configured
#: password of the capture's group 2.
CISCO = b"cisco\x00\x00\x00"
SPARK = b"spark\x00\x00\x00"

#: HSRP's all-routers destination (RFC 2281 §5.1) and its multicast MAC.
ALL_ROUTERS = "224.0.0.2"
ALL_ROUTERS_MAC = "01:00:5e:00:00:02"


def hsrp_bytes(
    *,
    version: int = 0,
    opcode: int = 0,
    state: int = 4,
    hellotime: int = 3,
    holdtime: int = 10,
    priority: int = 100,
    group: int = 1,
    reserved: int = 0,
    auth_data: bytes = CISCO,
    virtual_ip: str = "192.0.2.1",
) -> bytes:
    """A 20-byte HSRPv1 message packed here, field by field in §5.1's
    order, rather than by :class:`HSRP`. The defaults are a Speak Hello
    for group 1 with the recommended timers and the default
    Authentication Data."""
    fields = (version, opcode, state, hellotime, holdtime, priority, group)
    return bytes([*fields, reserved]) + auth_data + socket.inet_aton(virtual_ip)


#: The default constructed message: the bytes of conftest's
#: raw_hsrp_hello.
HELLO = hsrp_bytes()


def ones_complement(data: bytes) -> int:
    """Return the RFC 1071 checksum of ``data``, written out here so the
    constructed frames' checksums do not come from the library or the
    checker."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def udp_datagram(
    payload: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int
) -> bytes:
    """``payload`` behind a UDP header whose checksum is computed."""
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + struct.pack("!BBH", 0, 17, length)
    )
    checksum = ones_complement(pseudo + header + payload) or 0xFFFF
    return header[:6] + struct.pack("!H", checksum) + payload


def udp_frame(
    payload: bytes,
    *,
    src_port: int = 1985,
    dst_port: int = 1985,
    ttl: int = 1,
    src_ip: str = "192.0.2.11",
    dst_ip: str = ALL_ROUTERS,
    src_mac: str = "02:00:00:00:00:0b",
    dst_mac: str = ALL_ROUTERS_MAC,
) -> bytes:
    """``payload`` in a whole Ethernet, IPv4 and UDP frame, every
    checksum in it computed, so check_fixtures.py passes it unless the
    payload itself fails."""
    datagram = udp_datagram(payload, src_ip, dst_ip, src_port, dst_port)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(datagram),
        0,
        0,
        ttl,
        17,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    ip = ip[:10] + struct.pack("!H", ones_complement(ip)) + ip[12:]
    ethernet = mac_bytes(dst_mac) + mac_bytes(src_mac) + b"\x08\x00"
    return ethernet + ip + datagram


def message(**fields: object) -> HSRP:
    """The default constructed message, decoded, with ``fields``
    replaced."""
    return replace(HSRP.decode(HELLO), **fields)


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
    + bytes([192, 0, 2, 1])
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
MD5_TLV = bytes.fromhex("041c01000000c000020b00000001") + bytes(range(16))


@pytest.fixture(scope="module")
def check_fixtures():
    """Load scripts/check_fixtures.py, which shares no library code."""
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- The capture ------------------------------------------------------

#: The capture's two groups' virtual IP addresses.
G1_VIP, G2_VIP = "10.9.195.254", "10.9.195.253"

#: The capture's five routers, by name: own address, own MAC address
#: (pinned on Yersinia's command line).
ROUTERS = {
    "R1": ("10.9.195.11", "02:00:0a:09:c3:0b"),
    "R2": ("10.9.195.12", "02:00:0a:09:c3:0c"),
    "R3": ("10.9.195.13", "02:00:0a:09:c3:0d"),
    "R4": ("10.9.195.21", "02:00:0a:09:c3:15"),
    "R5": ("10.9.195.22", "02:00:0a:09:c3:16"),
}

#: The capture, frame by frame (MANIFEST's row and the capture script's
#: table): sender, Op Code, State, priority, group.
CAPTURE = [
    ("R1", "Hello", "Speak", 120, 1),
    ("R2", "Hello", "Speak", 100, 1),
    ("R1", "Hello", "Standby", 120, 1),
    ("R1", "Hello", "Active", 120, 1),
    ("R2", "Hello", "Standby", 100, 1),
    ("R1", "Resign", "Active", 120, 1),
    ("R2", "Hello", "Speak", 100, 1),
    ("R2", "Hello", "Active", 100, 1),
    ("R3", "Coup", "Active", 200, 1),
    ("R3", "Hello", "Active", 200, 1),
    ("R4", "Hello", "Active", 110, 2),
    ("R5", "Hello", "Standby", 90, 2),
]

#: The capture's frames by what they are.
R1_ACTIVE, R1_RESIGN, R2_ACTIVE, R3_COUP = 3, 5, 7, 8


class TestCapture:
    """tests/fixtures/hsrp.pcap: Yersinia's twelve messages."""

    FRAMES = pcap_frames(FIXTURES / "hsrp.pcap")

    def hsrp_of(self, index: int) -> HSRP:
        layer = decode_frame(self.FRAMES[index])[HSRP]
        assert isinstance(layer, HSRP)
        return layer

    def test_every_frame_walks_to_hsrp_and_ends_there(self):
        """Each frame walks Ethernet, IPv4, UDP, HSRP and consumes it."""
        assert len(self.FRAMES) == 12
        for frame in self.FRAMES:
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
        for frame in self.FRAMES:
            raw = frame[HSRP_START:]
            hsrp = HSRP.decode(raw)
            assert bytes(hsrp) == raw
            assert len(raw) == hsrp.header_len == 20
            assert HSRP.decode(bytes(hsrp)) == hsrp

    def test_the_exchange(self):
        """Who sent what, frame by frame: in group 1, R1 and R2 contend,
        R1 becomes Active and resigns, R2 takes over and R3 preempts it
        with a Coup; in group 2, R4 is Active and R5 Standby."""
        seen = []
        for frame in self.FRAMES:
            packet = decode_frame(frame)
            hsrp = packet[HSRP]
            sender = next(
                name
                for name, (ip, _) in ROUTERS.items()
                if ip == packet[IPv4].src
            )
            seen.append(
                (
                    sender,
                    hsrp.opcode_name,
                    hsrp.state_name,
                    hsrp.priority,
                    hsrp.group,
                )
            )
        assert seen == CAPTURE

    def test_every_op_code_is_captured(self):
        """10 Hellos, 1 Coup and 1 Resign."""
        opcodes = [self.hsrp_of(i).opcode for i in range(len(self.FRAMES))]
        assert [opcodes.count(op) for op in (0, 1, 2)] == [10, 1, 1]

    def test_the_two_groups(self):
        """Group 1 under the default Authentication Data, group 2 under
        the configured password ``spark``, each with its own virtual IP
        and virtual MAC address."""
        for index in range(len(self.FRAMES)):
            hsrp = self.hsrp_of(index)
            if hsrp.group == 1:
                assert hsrp.virtual_ip == G1_VIP
                assert hsrp.auth_data == CISCO
                assert (hsrp.password, hsrp.auth_data_str) == (
                    b"cisco",
                    "cisco",
                )
                assert hsrp.is_default_auth
                assert hsrp.virtual_mac == "00:00:0c:07:ac:01"
            else:
                assert hsrp.group == 2
                assert hsrp.virtual_ip == G2_VIP
                assert hsrp.auth_data == SPARK
                assert (hsrp.password, hsrp.auth_data_str) == (
                    b"spark",
                    "spark",
                )
                assert not hsrp.is_default_auth
                assert hsrp.virtual_mac == "00:00:0c:07:ac:02"

    def test_sent_as_rfc_2281_section_5_1_says(self):
        """Version 0, from and to UDP 1985, to 224.0.0.2 with TTL 1,
        from the router's own address, the recommended 3 s / 10 s
        timers and a zero Reserved byte."""
        for frame in self.FRAMES:
            packet = decode_frame(frame)
            ip, udp, hsrp = packet[IPv4], packet[UDP], packet[HSRP]
            assert (udp.src_port, udp.dst_port) == (1985, 1985)
            assert (ip.dst, ip.ttl) == (ALL_ROUTERS, 1)
            assert packet[Ethernet].dst == ALL_ROUTERS_MAC
            assert ip.src != hsrp.virtual_ip
            assert (hsrp.version, hsrp.reserved) == (0, 0)
            assert (hsrp.hellotime, hsrp.holdtime) == (3, 10)

    def test_the_ip_headers_are_yersinias(self):
        """Yersinia writes the whole frame: IP ID 0 and DSCP 4 (ToS
        0x10), not the CS6 a Cisco router uses."""
        for frame in self.FRAMES:
            ip = decode_frame(frame)[IPv4]
            assert (ip.identification, ip.dscp) == (0, 4)

    def test_each_router_sends_from_its_own_mac(self):
        """The script pins every sender's MAC address, Active or not, so
        none is the group's virtual MAC (which RFC 2281 §6.1 has an
        Active router use; the constructed Cisco exchange below does)."""
        own = dict(ROUTERS.values())
        for frame in self.FRAMES:
            packet = decode_frame(frame)
            assert packet[Ethernet].src == own[packet[IPv4].src]
            assert packet[Ethernet].src != packet[HSRP].virtual_mac

    def test_the_failover(self):
        """R1 resigns from Active, R2 becomes Active, and R3 preempts it
        with a Coup at a higher priority than either."""
        resign = self.hsrp_of(R1_RESIGN)
        assert (resign.opcode_name, resign.state_name) == ("Resign", "Active")
        assert self.hsrp_of(R1_ACTIVE).priority == resign.priority
        active, coup = self.hsrp_of(R2_ACTIVE), self.hsrp_of(R3_COUP)
        assert (active.opcode_name, active.state_name) == ("Hello", "Active")
        assert (coup.opcode_name, coup.state_name) == ("Coup", "Active")
        assert coup.priority > max(active.priority, resign.priority)

    def test_hello_holdtimes_exceed_their_hellotimes(self):
        """The Holdtime "SHOULD be at least three times the value of
        the Hellotime and MUST be greater than" it (§5.1)."""
        for index in range(len(self.FRAMES)):
            hsrp = self.hsrp_of(index)
            assert hsrp.holdtime >= 3 * hsrp.hellotime > 0

    def test_positional_patterns_follow_wire_order(self):
        """Positional patterns bind the fields in wire order."""
        match self.hsrp_of(R3_COUP):
            case HSRP(0, 1, 16, 3, 10, 200, 1, 0, auth, vip):
                assert (auth, vip) == (CISCO, G1_VIP)
            case _:
                pytest.fail("positional pattern did not match")

    def test_check_fixtures_passes_and_counts_it(self, check_fixtures):
        """The checker passes every frame and counts each Op Code."""
        stats = check_fixtures.Counter()
        for frame in self.FRAMES:
            assert check_fixtures.check_frame(frame, stats) == []
        assert (stats["udp"], stats["udp-no-checksum"]) == (12, 0)
        assert stats["hsrp"] == 12
        assert (
            stats["hsrp-hello"],
            stats["hsrp-coup"],
            stats["hsrp-resign"],
        ) == (10, 1, 1)


# --- A Cisco IOS exchange, constructed --------------------------------

#: Two Cisco routers' own addresses and MAC addresses, A preempting B.
CISCO_A = ("192.0.2.1", "02:00:00:00:0a:01")
CISCO_B = ("192.0.2.2", "02:00:00:00:0b:02")
CISCO_VIP = "192.0.2.250"
CISCO_VMAC = "00:00:0c:07:ac:01"


def _cisco(router, opcode, state, hello, hold, priority):
    return (router, OPCODES[opcode], STATES[state], hello, hold, priority)


_B_EARLY = _cisco(CISCO_B, 0, 4, 3, 10, 100)
_B_ACTIVE = _cisco(CISCO_B, 0, 16, 5, 15, 100)
_B_SPEAK = _cisco(CISCO_B, 0, 4, 5, 15, 100)
_A_ACTIVE = _cisco(CISCO_A, 0, 16, 5, 15, 110)

#: How a Cisco IOS pair was seen to run an election in group 1, as
#: (sender, Op Code, State, Hellotime, Holdtime, priority): B alone in
#: Speak and Standby with the 3 s / 10 s defaults, then Active with its
#: configured 5 s / 15 s; A, at the higher priority, preempting with a
#: Coup from Listen; B's Resign from Speak; A's second Coup, from
#: Active; and B settling in Speak and then Standby.
CISCO_EXCHANGE = [
    *[_B_EARLY] * 4,
    _cisco(CISCO_B, 0, 8, 3, 10, 100),
    *[_B_ACTIVE] * 9,
    _cisco(CISCO_A, 1, 2, 5, 15, 110),
    _A_ACTIVE,
    _cisco(CISCO_B, 2, 4, 5, 15, 100),
    _B_SPEAK,
    _cisco(CISCO_A, 1, 16, 5, 15, 110),
    *[_A_ACTIVE, _B_SPEAK] * 3,
    _A_ACTIVE,
    _cisco(CISCO_B, 0, 8, 5, 15, 100),
]

#: The exchange's frames by what they are.
B_LAST_ACTIVE, A_COUP_FROM_LISTEN, B_RESIGN, A_COUP_FROM_ACTIVE = 13, 14, 16, 18

_NAMED_OPCODES = {name: value for value, name in OPCODES.items()}
_NAMED_STATES = {name: value for value, name in STATES.items()}


def cisco_frame(entry, *, ttl: int = 2) -> bytes:
    """One exchange entry as Cisco sent it: TTL 2, and from the group's
    virtual MAC address when, and only when, the sender is Active
    (RFC 2281 §6.1)."""
    (ip, mac), opcode, state, hello, hold, priority = entry
    payload = hsrp_bytes(
        opcode=_NAMED_OPCODES[opcode],
        state=_NAMED_STATES[state],
        hellotime=hello,
        holdtime=hold,
        priority=priority,
        virtual_ip=CISCO_VIP,
    )
    source = CISCO_VMAC if state == "Active" else mac
    return udp_frame(payload, ttl=ttl, src_ip=ip, src_mac=source)


CISCO_FRAMES = [cisco_frame(entry) for entry in CISCO_EXCHANGE]


class TestCiscoExchange:
    """What a Cisco IOS pair sends that RFC 2281 does not require, and
    the Yersinia capture does not hold, pinned as constructed frames."""

    def decoded(self) -> list:
        packets = [decode_frame(frame) for frame in CISCO_FRAMES]
        return [
            (
                (packet[IPv4].src, packet[Ethernet].src),
                packet[HSRP].opcode_name,
                packet[HSRP].state_name,
                packet[HSRP].hellotime,
                packet[HSRP].holdtime,
                packet[HSRP].priority,
            )
            for packet in packets
        ]

    def test_every_frame_walks_to_hsrp(self):
        assert len(CISCO_FRAMES) == 27
        for frame in CISCO_FRAMES:
            packet = decode_frame(frame)
            assert [type(layer) for layer in packet] == [
                Ethernet,
                IPv4,
                UDP,
                HSRP,
            ]
            assert packet.consumed == len(frame) == 62

    def test_ttl_2_decodes_as_ttl_1_does(self):
        """IOS sends TTL 2 where §5.1 says 1; the TTL is IPv4's, so the
        HSRP layer is the same either way, and the checker does not
        judge it."""
        for entry, frame in zip(CISCO_EXCHANGE, CISCO_FRAMES, strict=True):
            packet = decode_frame(frame)
            assert packet[IPv4].ttl == 2
            assert packet[HSRP] == decode_frame(cisco_frame(entry, ttl=1))[HSRP]

    def test_the_exchange_decodes_as_built(self):
        """Every field read back, in order."""
        expected = [
            ((ip, CISCO_VMAC if state == "Active" else mac), op, state, *rest)
            for (ip, mac), op, state, *rest in CISCO_EXCHANGE
        ]
        assert self.decoded() == expected

    def test_the_timers_move_on_becoming_active(self):
        """B sends the 3 s / 10 s defaults until it is Active, and its
        configured 5 s / 15 s from then on, as A always does."""
        timers = [(entry[3], entry[4]) for entry in self.decoded()]
        assert timers[:5] == [(3, 10)] * 5
        assert timers[5:] == [(5, 15)] * 22
        assert self.decoded()[5][2] == "Active"
        for _, _, _, hello, hold, _ in self.decoded():
            assert hold >= 3 * hello > 0

    def test_the_virtual_mac_is_the_active_routers_source(self):
        """A router sends from the group's virtual MAC address if and
        only if it is Active (§6.1), in Coups as in Hellos."""
        own = dict([CISCO_A, CISCO_B])
        for frame in CISCO_FRAMES:
            packet = decode_frame(frame)
            hsrp = packet[HSRP]
            assert hsrp.virtual_mac == CISCO_VMAC
            if hsrp.state_name == "Active":
                assert packet[Ethernet].src == CISCO_VMAC
            else:
                assert packet[Ethernet].src == own[packet[IPv4].src]

    def test_the_preemption_order(self):
        """A preempts B with a Coup from Listen only once B is Active,
        at a higher priority (§5.2); B resigns from Speak; A's second
        Coup comes once A is Active itself."""
        seen = self.decoded()
        assert seen[B_LAST_ACTIVE][1:3] == ("Hello", "Active")
        coup = seen[A_COUP_FROM_LISTEN]
        assert (coup[0][0], coup[1], coup[2]) == (CISCO_A[0], "Coup", "Listen")
        assert coup[5] > seen[B_LAST_ACTIVE][5]
        assert seen[A_COUP_FROM_LISTEN + 1][1:3] == ("Hello", "Active")
        resign = seen[B_RESIGN]
        assert (resign[0][0], resign[1], resign[2]) == (
            CISCO_B[0],
            "Resign",
            "Speak",
        )
        assert seen[A_COUP_FROM_ACTIVE][1:3] == ("Coup", "Active")
        assert seen[-1][0][0] == CISCO_B[0]
        assert seen[-1][2] == "Standby"
        opcodes = [entry[1] for entry in seen]
        assert [opcodes.count(op) for op in OPCODES.values()] == [24, 2, 1]

    def test_check_fixtures_passes_it(self, check_fixtures):
        """The checker passes every frame, TTL 2 and all."""
        stats = check_fixtures.Counter()
        for frame in CISCO_FRAMES:
            assert check_fixtures.check_frame(frame, stats) == []
        assert stats["hsrp"] == 27
        assert (
            stats["hsrp-hello"],
            stats["hsrp-coup"],
            stats["hsrp-resign"],
        ) == (24, 2, 1)


# --- The message ------------------------------------------------------


class TestMessage:
    def test_the_fixture_is_the_default_constructed_message(
        self, raw_hsrp_hello
    ):
        """conftest's raw_hsrp_hello is :data:`HELLO`, built by hand."""
        assert raw_hsrp_hello == HELLO

    @pytest.mark.parametrize("opcode,name", OPCODES.items())
    def test_every_op_code_shares_the_layout(self, opcode, name):
        """Hello, Coup and Resign differ only in the Op Code's value."""
        raw = hsrp_bytes(opcode=opcode)
        hsrp = HSRP.decode(raw)
        assert (hsrp.opcode, hsrp.opcode_name) == (opcode, name)
        assert replace(hsrp, opcode=0) == HSRP.decode(HELLO)
        assert bytes(hsrp) == raw

    @pytest.mark.parametrize("state,name", STATES.items())
    def test_every_state_decodes(self, state, name):
        """RFC 2281 §5.1's six states, the uncaptured Initial, Learn and
        Listen among them."""
        raw = hsrp_bytes(state=state)
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
        assert hsrp.virtual_ip == "192.0.2.1"

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
            pytest.param(hsrp_bytes(state=8), id="another-message"),
        ],
    )
    def test_what_follows_is_left_undecoded(self, raw_hsrp_hello, trailer):
        """The message is always 20 bytes (decode contract rule 3), and
        what follows stays outside the layer."""
        hsrp = HSRP.decode(raw_hsrp_hello + trailer)
        assert hsrp == HSRP.decode(raw_hsrp_hello)
        assert hsrp.header_len == 20
        assert bytes(hsrp) == raw_hsrp_hello

    def test_a_walk_leaves_an_md5_authentication_tlv(self):
        """A 50-byte HSRPv1 message, the 30-byte MD5 Authentication TLV
        after the 20 (type 4, length 28), as Wireshark's packet-hsrp.c
        reads it: the walk decodes the 20 and stops there, leaving the
        TLV in the frame, past ``consumed``."""
        assert len(MD5_TLV) == 30
        frame = udp_frame(HELLO + MD5_TLV)
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP, HSRP]
        assert packet.consumed == len(frame) - len(MD5_TLV)
        assert frame[packet.consumed :] == MD5_TLV
        assert packet[HSRP] == HSRP.decode(HELLO)

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
            HSRP.decode(hsrp_bytes(opcode=opcode))
        error = caught.value
        assert (error.field, error.offset) == ("opcode", 1)
        assert (error.expected, error.actual) == ("0-2", opcode)

    @pytest.mark.parametrize("state", [3, 5, 6, 7, 9, 15, 17, 32, 0xFF])
    def test_a_state_rfc_2281_does_not_list(self, state):
        """The States are 0, 1, 2, 4, 8 and 16; the values between are
        not States."""
        with pytest.raises(InvalidFieldError) as caught:
            HSRP.decode(hsrp_bytes(state=state))
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
        rest = HELLO[3:]

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
        packet = decode_frame(udp_frame(HELLO[:12]), lax=True)
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
            (SPARK, b"spark", "spark"),
            (b"np-hsrp1", b"np-hsrp1", "np-hsrp1"),
            (bytes(8), b"", ""),
            (b"ab\x00cd\x00\x00\x00", b"ab\x00cd", "0x6162006364000000"),
            (b"\x00" * 7 + b"x", b"\x00" * 7 + b"x", "0x" + "00" * 7 + "78"),
            (b"\xff" * 8, b"\xff" * 8, "0x" + "ff" * 8),
            (b"cisc\x7f\x00\x00\x00", b"cisc\x7f", "0x636973637f000000"),
            (b" ~\x00" + bytes(5), b" ~", " ~"),
            (b"ab  \x00\x00\x00\x00", b"ab  ", "ab  "),
            (b"cisco \x00\x00", b"cisco ", "cisco "),
            (b" " * 8, b" " * 8, " " * 8),
        ],
    )
    def test_the_authentication_data(self, auth_data, password, shown):
        """Only trailing NUL padding is stripped, never a trailing space,
        and text is shown only when it is all printable ASCII; hex
        otherwise."""
        hsrp = message(auth_data=auth_data)
        assert hsrp.password == password
        assert hsrp.auth_data_str == shown
        assert hsrp.auth_data == auth_data

    def test_the_default_authentication_data(self):
        """Exactly ``cisco`` and three NUL bytes (§5.1)."""
        assert message().is_default_auth
        assert not message(auth_data=SPARK).is_default_auth
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
        assert raw == hsrp_bytes(opcode=1, state=16, priority=120, group=7)
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
        "address", ["192.0.2", "256.0.0.1", "::1", "", "a.b.c.d"]
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
        resign = hsrp_bytes(opcode=2, state=16)
        frame = udp_frame(resign, src_port=40000)
        assert decode_frame(frame)[HSRP] == HSRP.decode(resign)

    def test_hsrp_ends_the_chain(self):
        """HSRP carries no further protocol."""
        assert HSRP.decode(hsrp_bytes(opcode=1)).next_protocol() is None

    def test_decode_as_can_take_the_port_away(self):
        """Let a caller decode port 1985 as something else for one walk.

        It is best-effort, like every port entry.
        """
        packet = decode_frame(
            udp_frame(HELLO), decode_as={"udp.port": {1985: DNS}}
        )
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP, DNS]
