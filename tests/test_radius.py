"""Test RADIUS (RFC 2865, RFC 2866) decoding and dispatch.

Covered: the 20-byte header, the attribute list and the attribute
types decoded to typed values, the extent the Length gives a packet
(padding after it, a buffer cut short of it, a Length below the
header), the authenticators verified against the published test secret
(RFC 2865 §3, RFC 2866 §3, RFC 3579 §3.2), and dispatch from UDP ports
1812 and 1813.

The FreeRADIUS exchanges in tests/fixtures/radius.pcap (see its
MANIFEST note) anchor the decode and round-trip asserts; the cases a
real server does not send are built here.
"""

import hashlib
import hmac
import importlib.util
from collections import Counter
from dataclasses import replace
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    DNS,
    RADIUS,
    UDP,
    Ethernet,
    InvalidFieldError,
    IPv4,
    RADIUSAttribute,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_UDP_PORT

FRAMES = pcap_frames(FIXTURES / "radius.pcap")

CHECKER = Path(__file__).resolve().parent.parent / "scripts/check_fixtures.py"

#: Ethernet + a 20-byte IPv4 header + UDP, in front of every packet.
RADIUS_START = 14 + 20 + 8

#: The fixture's frames, in the order the capture script asserts: each
#: request followed by its reply.
PAP_ACCEPT, PAP_REJECT, CHAP_ACCEPT, ACCT_START, ACCT_STOP, STATUS = range(
    0, 12, 2
)
REQUESTS = range(0, 12, 2)
ACCOUNTING = (ACCT_START, ACCT_START + 1, ACCT_STOP, ACCT_STOP + 1)

#: The test values FreeRADIUS and radclient were configured with,
#: published in MANIFEST.md.
SECRET = b"np193-radius-secret"
PASSWORD = b"np193-pass"
WRONG_PASSWORD = b"np193-wrong"


#: Every attribute type named, written from FreeRADIUS 3.2.5's
#: dictionary.rfc2865 (RFC 2865 §5), dictionary.rfc2866 (RFC 2866 §5)
#: and dictionary.rfc2869 (RFC 2869 §5: 55, 77, 85 and 87; 79 and 80,
#: first defined there, are RFC 3579 §3's now).
NAMED_TYPES = {
    1: "User-Name",
    2: "User-Password",
    3: "CHAP-Password",
    4: "NAS-IP-Address",
    5: "NAS-Port",
    6: "Service-Type",
    7: "Framed-Protocol",
    8: "Framed-IP-Address",
    9: "Framed-IP-Netmask",
    10: "Framed-Routing",
    11: "Filter-Id",
    12: "Framed-MTU",
    13: "Framed-Compression",
    14: "Login-IP-Host",
    15: "Login-Service",
    16: "Login-TCP-Port",
    18: "Reply-Message",
    19: "Callback-Number",
    20: "Callback-Id",
    22: "Framed-Route",
    23: "Framed-IPX-Network",
    24: "State",
    25: "Class",
    26: "Vendor-Specific",
    27: "Session-Timeout",
    28: "Idle-Timeout",
    29: "Termination-Action",
    30: "Called-Station-Id",
    31: "Calling-Station-Id",
    32: "NAS-Identifier",
    33: "Proxy-State",
    34: "Login-LAT-Service",
    35: "Login-LAT-Node",
    36: "Login-LAT-Group",
    37: "Framed-AppleTalk-Link",
    38: "Framed-AppleTalk-Network",
    39: "Framed-AppleTalk-Zone",
    40: "Acct-Status-Type",
    41: "Acct-Delay-Time",
    42: "Acct-Input-Octets",
    43: "Acct-Output-Octets",
    44: "Acct-Session-Id",
    45: "Acct-Authentic",
    46: "Acct-Session-Time",
    47: "Acct-Input-Packets",
    48: "Acct-Output-Packets",
    49: "Acct-Terminate-Cause",
    50: "Acct-Multi-Session-Id",
    51: "Acct-Link-Count",
    55: "Event-Timestamp",
    60: "CHAP-Challenge",
    61: "NAS-Port-Type",
    62: "Port-Limit",
    63: "Login-LAT-Port",
    77: "Connect-Info",
    79: "EAP-Message",
    80: "Message-Authenticator",
    85: "Acct-Interim-Interval",
    87: "NAS-Port-Id",
}

#: Every packet code named: RFC 2865 §3 (1-5, 11-13 and 255; 4 and 5
#: are RFC 2866's), RFC 5997 (Status-Server, 12) and RFC 5176 (40-45),
#: in FreeRADIUS 3.2.5's spelling (dictionary.freeradius.internal,
#: Packet-Type; 255 is RFC 2865 §3's "Reserved").
NAMED_CODES = {
    1: "Access-Request",
    2: "Access-Accept",
    3: "Access-Reject",
    4: "Accounting-Request",
    5: "Accounting-Response",
    11: "Access-Challenge",
    12: "Status-Server",
    13: "Status-Client",
    40: "Disconnect-Request",
    41: "Disconnect-ACK",
    42: "Disconnect-NAK",
    43: "CoA-Request",
    44: "CoA-ACK",
    45: "CoA-NAK",
    255: "Reserved",
}


def packet_bytes(index: int) -> bytes:
    """Return the RADIUS packet of capture frame ``index``, exactly."""
    return FRAMES[index][RADIUS_START:]


def radius_of(index: int) -> RADIUS:
    layer = decode_frame(FRAMES[index])[RADIUS]
    assert isinstance(layer, RADIUS)
    return layer


def attribute(radius: RADIUS, kind: int) -> RADIUSAttribute:
    """Return the only attribute of type ``kind`` in ``radius``."""
    (found,) = [a for a in radius.parsed_attributes if a.type == kind]
    return found


def build(
    attributes: bytes = b"", code: int = 1, identifier: int = 7
) -> RADIUS:
    return RADIUS(
        code=code,
        identifier=identifier,
        length=20 + len(attributes),
        authenticator=bytes(range(16)),
        attributes=attributes,
    )


def with_length(raw: bytes, length: int) -> bytes:
    """Return ``raw`` with its Length field set to ``length``."""
    return raw[:2] + length.to_bytes(2, "big") + raw[4:]


@pytest.fixture(scope="module")
def check_fixtures():
    """Load scripts/check_fixtures.py, which shares no library code."""
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestCapturedPackets:
    def test_every_frame_walks_to_radius_and_ends_there(self):
        """Each frame walks Ethernet, IPv4, UDP, RADIUS and consumes it all."""
        for frame in FRAMES:
            packet = decode_frame(frame)
            assert [type(layer) for layer in packet] == [
                Ethernet,
                IPv4,
                UDP,
                RADIUS,
            ]
            assert packet.consumed == len(frame)
            assert packet[RADIUS].next_protocol() is None

    def test_every_packet_round_trips_exactly(self):
        """Each captured packet re-encodes to its bytes, both ways."""
        for index in range(len(FRAMES)):
            raw = packet_bytes(index)
            radius = RADIUS.decode(raw)
            assert bytes(radius) == raw
            assert RADIUS.decode(bytes(radius)) == radius
            assert radius.header_len == radius.length == len(raw)

    def test_codes_in_capture_order(self):
        """Six requests, each answered (RFC 2865 §4, RFC 2866 §4)."""
        assert [radius_of(i).code_name for i in range(len(FRAMES))] == [
            "Access-Request",
            "Access-Accept",
            "Access-Request",
            "Access-Reject",
            "Access-Request",
            "Access-Accept",
            "Accounting-Request",
            "Accounting-Response",
            "Accounting-Request",
            "Accounting-Response",
            "Status-Server",
            "Access-Accept",
        ]

    def test_each_reply_carries_its_requests_identifier(self):
        """RFC 2865 §3: the Identifier matches a reply to its request."""
        for request in REQUESTS:
            assert (
                radius_of(request).identifier
                == radius_of(request + 1).identifier
            )

    def test_authentication_on_1812_accounting_on_1813(self):
        """Requests go to 1812 or 1813 and replies come back from it."""
        for index in range(len(FRAMES)):
            udp = decode_frame(FRAMES[index])[UDP]
            port = udp.dst_port if index in REQUESTS else udp.src_port
            assert port == (1813 if index in ACCOUNTING else 1812)

    def test_an_access_request_reads_its_named_attributes(self):
        """User-Name, NAS-IP-Address and NAS-Port decode to typed values."""
        for index in (PAP_ACCEPT, PAP_REJECT, CHAP_ACCEPT):
            radius = radius_of(index)
            assert radius.user_name == "np193-user"
            assert radius.nas_ip_address == IPv4Address("10.9.193.2")
            assert radius.nas_port == 7
            assert radius.framed_ip_address is None

    def test_user_password_is_kept_raw(self):
        """RFC 2865 §5.2: the hidden password, a multiple of 16 bytes."""
        for index in (PAP_ACCEPT, PAP_REJECT):
            hidden = attribute(radius_of(index), 2)
            assert hidden.type_name == "User-Password"
            assert hidden.value == hidden.data
            assert len(hidden.data) == 16
            assert PASSWORD not in hidden.data
        assert all(
            a.type != 2 for a in radius_of(CHAP_ACCEPT).parsed_attributes
        )

    def test_an_access_accept_carries_the_framed_address(self):
        """The server's reply items: Framed-IP-Address, Reply-Message."""
        for index in (PAP_ACCEPT + 1, CHAP_ACCEPT + 1):
            radius = radius_of(index)
            assert radius.framed_ip_address == IPv4Address("10.9.193.50")
            message = attribute(radius, 18)
            assert message.type_name == "Reply-Message"
            assert message.data == b"np193 test user"
            assert message.value is None
            assert radius.user_name is None

    @pytest.mark.parametrize(
        "index,status", [(ACCT_START, 1), (ACCT_STOP, 2)], ids=["start", "stop"]
    )
    def test_accounting_requests(self, index, status):
        """RFC 2866 §5: Acct-Status-Type Start (1), then Stop (2)."""
        radius = radius_of(index)
        assert attribute(radius, 40).type_name == "Acct-Status-Type"
        assert attribute(radius, 40).data == status.to_bytes(4, "big")
        assert attribute(radius, 44).type_name == "Acct-Session-Id"
        assert attribute(radius, 44).data == b"np193-0001"
        assert radius.framed_ip_address == IPv4Address("10.9.193.50")
        assert radius.user_name == "np193-user"

    def test_an_accounting_stop_carries_the_session_counters(self):
        """RFC 2866 §5.3-5.4, §5.7-5.10: octets, time, packets, cause."""
        names = {
            a.type_name: int.from_bytes(a.data)
            for a in radius_of(ACCT_STOP).parsed_attributes
            if a.type in (42, 43, 46, 47, 48, 49)
        }
        assert names == {
            "Acct-Session-Time": 42,
            "Acct-Input-Octets": 1234,
            "Acct-Output-Octets": 5678,
            "Acct-Input-Packets": 12,
            "Acct-Output-Packets": 34,
            "Acct-Terminate-Cause": 1,
        }

    def test_an_accounting_response_is_the_header_alone(self):
        """FreeRADIUS answers an Accounting-Request with no attributes."""
        for index in (ACCT_START + 1, ACCT_STOP + 1):
            radius = radius_of(index)
            assert (radius.length, radius.attributes) == (20, b"")
            assert radius.parsed_attributes == ()

    def test_status_server_carries_a_message_authenticator(self):
        """RFC 5997 §2: a Status-Server must carry one.

        radclient sends nothing else (§5 recommends a NAS-IP-Address or
        NAS-Identifier too).
        """
        (only,) = radius_of(STATUS).parsed_attributes
        assert (only.type, only.type_name, len(only.data)) == (
            80,
            "Message-Authenticator",
            16,
        )

    def test_attributes_reencode_to_their_wire_bytes(self):
        """The attributes re-encoded, joined, are the attribute bytes."""
        for index in range(len(FRAMES)):
            radius = radius_of(index)
            joined = b"".join(bytes(a) for a in radius.parsed_attributes)
            assert joined == radius.attributes


class TestAuthenticators:
    """Verify what the shared secret protects, outside the library.

    Computing or verifying these is out of scope for :class:`RADIUS`
    (#193); verifying them here shows the published secret is the one
    the capture used, and that the bytes kept raw are the bytes sent.
    """

    def test_every_response_authenticator_verifies(self):
        """RFC 2865 §3: MD5(Code+ID+Length+RequestAuth+Attributes+Secret)."""
        for request in REQUESTS:
            asked, reply = radius_of(request), radius_of(request + 1)
            raw = bytes(reply)
            digest = hashlib.md5(
                raw[:4] + asked.authenticator + raw[20:] + SECRET,
                usedforsecurity=False,
            ).digest()
            assert reply.authenticator == digest

    def test_every_accounting_request_authenticator_verifies(self):
        """RFC 2866 §3: MD5 over the packet with a zero Authenticator."""
        for index in (ACCT_START, ACCT_STOP):
            raw = packet_bytes(index)
            digest = hashlib.md5(
                raw[:4] + bytes(16) + raw[20:] + SECRET,
                usedforsecurity=False,
            ).digest()
            assert radius_of(index).authenticator == digest

    def test_every_message_authenticator_verifies(self):
        """RFC 3579 §3.2: HMAC-MD5 over the packet, the value zeroed.

        A reply's is computed over its request's Authenticator.
        """
        checked = 0
        for index in range(len(FRAMES)):
            radius = radius_of(index)
            request = radius_of(index - index % 2)
            offset = 20
            for found in radius.parsed_attributes:
                if found.type == 80:
                    raw = bytes(
                        replace(radius, authenticator=request.authenticator)
                    )
                    zeroed = raw[: offset + 2] + bytes(16) + raw[offset + 18 :]
                    mac = hmac.new(SECRET, zeroed, hashlib.md5).digest()
                    assert found.data == mac
                    checked += 1
                offset += len(bytes(found))
        assert checked == 8

    @pytest.mark.parametrize(
        "index,password",
        [(PAP_ACCEPT, PASSWORD), (PAP_REJECT, WRONG_PASSWORD)],
    )
    def test_user_password_unhides_with_the_secret(self, index, password):
        """RFC 2865 §5.2: XOR with MD5(Secret + Request Authenticator)."""
        radius = radius_of(index)
        hidden = attribute(radius, 2).data
        pad = hashlib.md5(
            SECRET + radius.authenticator, usedforsecurity=False
        ).digest()
        clear = bytes(a ^ b for a, b in zip(hidden, pad, strict=True))
        assert clear == password.ljust(16, b"\x00")

    def test_chap_password_is_the_request_authenticators_answer(self):
        """RFC 2865 §5.3: MD5(CHAP Ident + password + challenge).

        With no CHAP-Challenge attribute the challenge is the Request
        Authenticator.
        """
        radius = radius_of(CHAP_ACCEPT)
        chap = attribute(radius, 3)
        assert chap.type_name == "CHAP-Password"
        assert len(chap.data) == 17
        digest = hashlib.md5(
            chap.data[:1] + PASSWORD + radius.authenticator,
            usedforsecurity=False,
        ).digest()
        assert chap.data[1:] == digest

    def test_the_test_secrets_are_the_published_ones(self):
        """The values here are the ones MANIFEST.md publishes."""
        manifest = (FIXTURES / "MANIFEST.md").read_text()
        for value in (SECRET, PASSWORD, WRONG_PASSWORD):
            assert value.decode() in manifest

    def test_check_fixtures_verifies_the_requests(self, check_fixtures):
        """The checker verifies what one frame holds, and nothing fails."""
        stats = check_fixtures.Counter()
        for frame in FRAMES:
            assert check_fixtures.check_frame(frame, stats) == []
        assert stats["radius"] == 12
        assert stats["radius-accounting-authenticator"] == 2
        assert stats["radius-message-authenticator"] == 4

    @pytest.mark.parametrize(
        "index,failure",
        [
            (ACCT_START, "radius-accounting-authenticator"),
            (PAP_ACCEPT, "radius-message-authenticator"),
            (STATUS, "radius-message-authenticator"),
        ],
    )
    def test_check_fixtures_catches_a_changed_byte(
        self, check_fixtures, index, failure
    ):
        """A changed attribute byte fails the keyed check, not just UDP's."""
        frame = bytearray(FRAMES[index])
        frame[-1] ^= 0x01
        failures = check_fixtures.check_frame(bytes(frame), Counter())
        assert failure in failures


#: A 4-byte Ethernet FCS a capture kept, nonzero.
FCS = b"\xde\xad\xbe\xef"


class TestExtent:
    """The Length gives the packet's extent (RFC 2865 §3)."""

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    @pytest.mark.parametrize("index", range(len(FRAMES)))
    def test_bytes_past_the_length_are_left_undecoded(self, index, lax):
        """Padding or an FCS after the packet is not the packet's."""
        frame = FRAMES[index] + FCS
        packet = decode_frame(frame, lax=lax)
        assert packet.stopped_by is None
        assert packet.consumed == len(FRAMES[index])
        assert packet[RADIUS] == radius_of(index)

    def test_a_length_into_trailing_bytes_reads_them_pending_235(self):
        """Documents current behaviour, pending #235; update it with #235.

        The walk does not end the buffer at UDP's length, so a Length
        that overstates the datagram takes trailing bytes, here an FCS
        reading ``12 04 be ef``, as attributes instead of raising: the
        example in the module docstring, ARCHITECTURE.md and the
        CHANGELOG. When #235 bounds RADIUS by the UDP length, this
        decode raises instead and this test fails.
        """
        index = ACCT_START + 1
        assert index == 7
        frame = bytearray(FRAMES[index])
        start = RADIUS_START
        frame[start + 2 : start + 4] = (24).to_bytes(2, "big")
        packet = decode_frame(bytes(frame) + b"\x12\x04\xbe\xef")
        radius = packet[RADIUS]
        assert radius.length == 24
        assert radius.parsed_attributes == (RADIUSAttribute(18, b"\xbe\xef"),)
        assert radius.parsed_attributes[0].type_name == "Reply-Message"

    def test_padding_inside_the_datagram_is_ignored(self):
        """RFC 2865 §3: octets past the Length are padding, ignored."""
        raw = packet_bytes(ACCT_START + 1)
        radius = RADIUS.decode(raw + bytes(30))
        assert radius == RADIUS.decode(raw)
        assert bytes(radius) == raw

    @pytest.mark.parametrize("cut", [20, 21, 40, 79])
    def test_a_buffer_shorter_than_the_length_raises(self, cut):
        """RFC 2865 §3: a packet shorter than its Length is discarded."""
        raw = packet_bytes(PAP_ACCEPT)
        assert len(raw) == 80
        with pytest.raises(TruncatedHeaderError) as caught:
            RADIUS.decode(raw[:cut])
        error = caught.value
        assert (error.field, error.expected, error.actual) == (
            "length",
            80,
            cut,
        )

    def test_a_cut_capture_stops_a_lax_walk_at_radius(self):
        """A lax walk keeps Ethernet, IPv4 and UDP and reports the cut."""
        frame = FRAMES[PAP_ACCEPT][:-10]
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(frame)
        assert caught.value.frame_offset == RADIUS_START
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    @pytest.mark.parametrize("cut", [0, 1, 4, 19])
    def test_the_fixed_header_cut(self, cut):
        """Fewer than 20 bytes cannot hold the header."""
        with pytest.raises(TruncatedHeaderError) as caught:
            RADIUS.decode(packet_bytes(STATUS)[:cut])
        assert caught.value.expected == 20

    @pytest.mark.parametrize("length", [0, 1, 19])
    def test_a_length_below_the_header_raises(self, length):
        """RFC 2865 §3: the minimum length is 20."""
        raw = with_length(packet_bytes(STATUS), length)
        with pytest.raises(InvalidFieldError) as caught:
            RADIUS.decode(raw)
        error = caught.value
        assert (error.field, error.offset, error.actual) == (
            "length",
            2,
            length,
        )

    def test_a_length_past_4096_decodes(self):
        """RFC 7930 §2 lets RADIUS over TCP and TLS run to 65535 bytes."""
        filler = bytes(RADIUSAttribute(26, bytes(253))) * 20
        radius = build(filler)
        assert radius.length == 5120
        assert RADIUS.decode(bytes(radius)) == radius

    def test_memoryview_input_is_not_retained(self):
        """A decoded packet does not alias a memoryview it came from."""
        buffer = bytearray(packet_bytes(ACCT_STOP))
        radius = RADIUS.decode(memoryview(buffer))
        before = radius.parsed_attributes
        buffer[:] = bytes(len(buffer))
        assert radius.parsed_attributes == before
        assert bytes(radius) == packet_bytes(ACCT_STOP)


class TestAttributes:
    @pytest.mark.parametrize("length", [0, 1])
    def test_an_attribute_length_below_2_raises_on_demand(self, length):
        """RFC 2865 §5: the Length counts the 2-byte header too.

        The header still decodes; only the walk raises.
        """
        raw = bytes(build(bytes([1, length]) + b"np193"))
        radius = RADIUS.decode(raw)
        with pytest.raises(InvalidFieldError) as caught:
            _ = radius.parsed_attributes
        assert (caught.value.field, caught.value.offset) == ("attributes", 0)
        with pytest.raises(InvalidFieldError):
            _ = radius.user_name

    def test_an_attribute_past_the_packet_raises_on_demand(self):
        """An attribute whose Length runs past the packet's raises."""
        good = bytes(RADIUSAttribute(5, (7).to_bytes(4, "big")))
        radius = RADIUS.decode(bytes(build(good + b"\x01\x10np193")))
        with pytest.raises(InvalidFieldError) as caught:
            _ = radius.parsed_attributes
        assert (caught.value.field, caught.value.offset) == ("attributes", 6)

    def test_a_lone_type_byte_raises_on_demand(self):
        """A Type with no Length byte after it is cut short."""
        radius = RADIUS.decode(bytes(build(b"\x01")))
        with pytest.raises(InvalidFieldError):
            _ = radius.parsed_attributes

    def test_the_walk_never_reads_past_the_length(self):
        """Bytes past the Length are not attributes, even if they parse."""
        raw = bytes(build()) + bytes(RADIUSAttribute(1, b"np193"))
        radius = RADIUS.decode(raw)
        assert radius.parsed_attributes == ()
        assert radius.user_name is None

    def test_an_empty_value_parses(self):
        """A 2-byte attribute is structurally whole; its value is empty."""
        radius = build(b"\x12\x02")
        assert radius.parsed_attributes == (RADIUSAttribute(18, b""),)

    def test_repeated_attributes_are_all_kept(self):
        """RFC 2865 §5: some types repeat; the accessors read the first."""
        names = [RADIUSAttribute(1, b"first"), RADIUSAttribute(1, b"second")]
        radius = build(b"".join(map(bytes, names)))
        assert radius.parsed_attributes == tuple(names)
        assert radius.user_name == "first"

    def test_type_0_is_an_attribute_not_a_terminator(self):
        """RADIUS has no lone-byte or end-of-list types, unlike TCP."""
        parts = [RADIUSAttribute(0, b"\x00"), RADIUSAttribute(5, bytes(4))]
        radius = build(b"".join(map(bytes, parts)))
        assert radius.parsed_attributes == tuple(parts)
        assert radius.nas_port == 0

    @pytest.mark.parametrize("kind", [4, 5, 8])
    @pytest.mark.parametrize("size", [0, 3, 5])
    def test_a_wrong_length_address_or_integer_is_none(self, kind, size):
        """An address or integer that is not 4 bytes is not read."""
        radius = build(bytes(RADIUSAttribute(kind, bytes(size))))
        assert radius.parsed_attributes[0].value is None
        assert radius.nas_ip_address is None
        assert radius.nas_port is None
        assert radius.framed_ip_address is None

    def test_a_user_name_that_is_not_utf8_is_replaced(self):
        """RFC 2865 §5.1 allows any octets; the library reads UTF-8."""
        radius = build(bytes(RADIUSAttribute(1, b"np\xff193")))
        assert radius.user_name == "np�193"
        assert radius.parsed_attributes[0].data == b"np\xff193"

    def test_nas_port_is_unsigned(self):
        """RFC 2865 §5: an integer is 32-bit unsigned; all ones is 2^32-1."""
        radius = build(bytes(RADIUSAttribute(5, b"\xff\xff\xff\xff")))
        assert radius.parsed_attributes[0].value == 4294967295
        assert radius.nas_port == 4294967295

    def test_vendor_specific_is_kept_raw(self):
        """RFC 2865 §5.26: Vendor-Id, then the vendor's own attributes."""
        data = (311).to_bytes(4, "big") + b"\x01\x06np19"
        found = RADIUSAttribute(26, data)
        assert (found.type_name, found.value) == ("Vendor-Specific", data)

    def test_the_named_types(self):
        """Every type is named as its RFC names it, or falls back.

        See :data:`NAMED_TYPES`: RFC 2865 §5, RFC 2866 §5, RFC 3579 §3
        and four types of RFC 2869 §5; every other type is unknown.
        """
        assert {
            kind: RADIUSAttribute(kind).type_name for kind in range(256)
        } == {
            kind: NAMED_TYPES.get(kind, f"unknown ({kind})")
            for kind in range(256)
        }

    @pytest.mark.parametrize("kind", [17, 21, 52, 64, 81, 241, 255])
    def test_unnamed_types_fall_back(self, kind):
        """A type not named here displays as unknown, its value raw."""
        found = RADIUSAttribute(kind, b"np193")
        assert found.type_name == f"unknown ({kind})"
        assert found.value is None
        assert found.data == b"np193"


class TestConstruction:
    def test_build_a_packet_from_attributes(self):
        """A packet built from attributes decodes back to itself."""
        parts = [
            RADIUSAttribute(1, b"np193-user"),
            RADIUSAttribute(4, bytes([192, 0, 2, 1])),
            RADIUSAttribute(5, (3).to_bytes(4, "big")),
        ]
        radius = build(b"".join(map(bytes, parts)))
        assert RADIUS.decode(bytes(radius)) == radius
        assert radius.parsed_attributes == tuple(parts)
        assert radius.nas_ip_address == IPv4Address("192.0.2.1")

    def test_an_access_request_without_message_authenticator(self):
        """The plain RFC 2865 form radclient 3.2.5 no longer sends."""
        raw = packet_bytes(PAP_ACCEPT)
        radius = RADIUS.decode(raw)
        rest = tuple(a for a in radius.parsed_attributes if a.type != 80)
        attributes = b"".join(map(bytes, rest))
        plain = replace(
            radius, length=20 + len(attributes), attributes=attributes
        )
        assert RADIUS.decode(bytes(plain)).parsed_attributes == rest
        assert plain.length == len(raw) - 18

    @pytest.mark.parametrize("delta", [-1, 1])
    def test_a_length_that_disagrees_is_refused(self, delta):
        """The Length must be 20 plus the attributes."""
        with pytest.raises(InvalidFieldError) as caught:
            replace(build(b"\x01\x03x"), length=23 + delta)
        assert (caught.value.field, caught.value.expected) == ("length", 23)

    def test_a_length_past_16_bits_is_refused(self):
        """No Length field holds more than 65535."""
        filler = bytes(RADIUSAttribute(26, bytes(253))) * 258
        with pytest.raises(InvalidFieldError) as caught:
            build(filler)
        assert (caught.value.field, caught.value.expected) == (
            "length",
            "<=65535",
        )
        assert "at most 65535" in str(caught.value)

    def test_the_length_boundary_is_65535(self):
        """65,515 bytes of attributes fill a Length of 65535; one more cannot.

        256 attributes of 255 bytes, then one of the remainder.
        """
        full = bytes(RADIUSAttribute(26, bytes(253))) * 256
        widest = build(full + bytes(RADIUSAttribute(26, bytes(233))))
        assert (len(widest.attributes), widest.length) == (65515, 65535)
        assert RADIUS.decode(bytes(widest)) == widest
        assert len(widest.parsed_attributes) == 257
        with pytest.raises(InvalidFieldError) as caught:
            build(full + bytes(RADIUSAttribute(26, bytes(234))))
        assert (caught.value.field, caught.value.expected) == (
            "length",
            "<=65535",
        )

    @pytest.mark.parametrize("size", [0, 15, 17])
    def test_the_authenticator_is_16_bytes(self, size):
        """The Authenticator is exactly 16 bytes."""
        with pytest.raises(InvalidFieldError) as caught:
            replace(build(), authenticator=bytes(size))
        assert (caught.value.field, caught.value.actual) == (
            "authenticator",
            size,
        )

    @pytest.mark.parametrize(
        "field,value", [("code", 256), ("code", -1), ("identifier", 256)]
    )
    def test_out_of_range_header_fields(self, field, value):
        """A header field too wide for its byte is refused."""
        with pytest.raises(InvalidFieldError) as caught:
            replace(build(), **{field: value})
        assert (caught.value.field, caught.value.expected) == (field, "0-255")

    def test_the_widest_values_are_accepted(self):
        """Every field's widest value builds and round-trips."""
        radius = replace(build(), code=255, identifier=255)
        assert RADIUS.decode(bytes(radius)) == radius
        widest = RADIUSAttribute(255, bytes(253))
        assert bytes(widest)[:2] == b"\xff\xff"
        assert build(bytes(widest)).parsed_attributes == (widest,)

    def test_attribute_fields_are_checked(self):
        """An attribute type fits a byte and its data 253 bytes."""
        with pytest.raises(InvalidFieldError) as caught:
            RADIUSAttribute(256)
        assert caught.value.field == "type"
        with pytest.raises(InvalidFieldError) as caught:
            RADIUSAttribute(26, bytes(254))
        assert (caught.value.field, caught.value.actual) == ("data", 254)

    def test_code_constants(self):
        """The class names the codes of RFC 2865 §3."""
        assert (
            RADIUS.ACCESS_REQUEST,
            RADIUS.ACCESS_ACCEPT,
            RADIUS.ACCESS_REJECT,
            RADIUS.ACCOUNTING_REQUEST,
            RADIUS.ACCOUNTING_RESPONSE,
            RADIUS.ACCESS_CHALLENGE,
            RADIUS.STATUS_SERVER,
        ) == (1, 2, 3, 4, 5, 11, 12)

    @pytest.mark.parametrize(
        "code,name",
        [
            (11, "Access-Challenge"),
            (13, "Status-Client"),
            (40, "Disconnect-Request"),
            (42, "Disconnect-NAK"),
            (43, "CoA-Request"),
            (45, "CoA-NAK"),
            (255, "Reserved"),
            (0, "unknown (0)"),
            (6, "unknown (6)"),
            (21, "unknown (21)"),
            (50, "unknown (50)"),
        ],
    )
    def test_other_codes_decode_and_are_named(self, code, name):
        """Every code decodes; RFC 2865/2866/5997/5176's are named.

        IANA assigns others too (6-10, 21-34, 50-52, ...), not named.
        """
        radius = replace(build(), code=code)
        assert RADIUS.decode(bytes(radius)).code_name == name

    def test_the_named_codes(self):
        """See :data:`NAMED_CODES`; every other code is unknown."""
        assert {
            code: replace(build(), code=code).code_name for code in range(256)
        } == {
            code: NAMED_CODES.get(code, f"unknown ({code})")
            for code in range(256)
        }

    def test_positional_patterns_follow_wire_order(self):
        """Positional patterns bind the header fields in wire order."""
        match RADIUS.decode(packet_bytes(STATUS)):
            case RADIUS(12, identifier, 38, authenticator, attributes):
                assert identifier == radius_of(STATUS + 1).identifier
                assert len(authenticator) == 16
                assert attributes[:2] == b"\x50\x12"
            case _:
                pytest.fail("positional pattern did not match")


class TestDispatch:
    @pytest.mark.parametrize("port", [1812, 1813])
    def test_registered_on_1812_and_1813(self, port):
        """The default registry maps both IANA ports to RADIUS."""
        assert DEFAULT.get(TABLE_UDP_PORT, port) is RADIUS

    @pytest.mark.parametrize(
        "src_port,dst_port", [(40000, 1812), (1812, 40000), (40000, 1813)]
    )
    def test_either_direction(self, src_port, dst_port):
        """A request goes to the port and its reply comes back from it."""
        udp = UDP(src_port=src_port, dst_port=dst_port, length=0, checksum=0)
        assert udp.next_protocol() is RADIUS

    @pytest.mark.parametrize("port", [1645, 1646, 3799])
    def test_legacy_and_dynamic_authorization_ports_are_not(self, port):
        """1645/1646 predate IANA's ports; 3799 is RFC 5176's."""
        udp = UDP(src_port=40000, dst_port=port, length=0, checksum=0)
        assert udp.next_protocol() is None

    def test_decode_as_reads_another_port(self):
        """A capture on a legacy port decodes with ``decode_as``."""
        frame = bytearray(FRAMES[PAP_ACCEPT])
        frame[36:38] = (1645).to_bytes(2, "big")
        assert [type(layer) for layer in decode_frame(bytes(frame))] == [
            Ethernet,
            IPv4,
            UDP,
        ]
        packet = decode_frame(
            bytes(frame), decode_as={"udp.port": {1645: RADIUS}}
        )
        assert packet[RADIUS] == radius_of(PAP_ACCEPT)

    def test_decode_as_can_take_the_port_away(self):
        """Port dispatch is best-effort, like every port entry."""
        packet = decode_frame(
            FRAMES[STATUS], decode_as={"udp.port": {1812: DNS}}
        )
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP, DNS]
