"""Test RIP (RFC 1058, RFC 2453, RFC 4822) decoding and dispatch.

Covered: the header, the 20-byte entries and the authentication entry
and trailer, how a message's extent is read with no length field, the
decode-time guard against a wrong port guess, and dispatch from UDP
port 520.

The BIRD exchanges in tests/fixtures/rip.pcap (see its MANIFEST note)
anchor the decode and round-trip asserts; the cases a real router does
not send are built here.
"""

import hashlib
import hmac
from dataclasses import replace

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    DNS,
    RIP,
    UDP,
    Ethernet,
    InvalidFieldError,
    InvalidIPv4AddressError,
    IPv4,
    RIPAuthentication,
    RIPEntry,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_UDP_PORT

FRAMES = pcap_frames(FIXTURES / "rip.pcap")

#: Ethernet + a 20-byte IPv4 header + UDP, in front of every message.
RIP_START = 14 + 20 + 8

#: The fixture's frames by scenario, in the order the capture script
#: selects them: 10.9.52.1's Request, 10.9.52.2's, then their Responses
#: in the same order (and, for v2, 10.9.52.1's periodic update).
V1 = range(0, 4)
V2 = range(4, 9)
PLAINTEXT = range(9, 13)
MD5 = range(13, 17)
SHA256 = range(17, 21)
REQUESTS = [0, 1, 4, 5, 9, 10, 13, 14, 17, 18]

#: The test keys BIRD was configured with, published in MANIFEST.md.
MD5_KEY = b"nprip-md5-key"
SHA256_KEY = b"nprip-sha256-key"


def message_bytes(index: int) -> bytes:
    """Return the RIP message of capture frame ``index``, exactly."""
    return FRAMES[index][RIP_START:]


def rip_of(index: int) -> RIP:
    layer = decode_frame(FRAMES[index])[RIP]
    assert isinstance(layer, RIP)
    return layer


def entry(
    address: str = "192.0.2.0",
    mask: str = "255.255.255.0",
    metric: int = 1,
    afi: int = 2,
    route_tag: int = 0,
    next_hop: str = "0.0.0.0",
) -> bytes:
    return bytes(RIPEntry(afi, route_tag, address, mask, next_hop, metric))


def crypto_auth(packet_length: int, auth_data_len: int = 16) -> bytes:
    """Build a type 3 authentication entry (RFC 4822).

    It holds Packet Length, Key ID 1, Auth Data Len, sequence number 7
    and 8 zero bytes.
    """
    data = (
        packet_length.to_bytes(2, "big")
        + bytes([1, auth_data_len])
        + (7).to_bytes(4, "big")
        + bytes(8)
    )
    return bytes(RIPAuthentication(3, data))


class TestCapturedMessages:
    def test_every_frame_walks_to_rip_and_ends_there(self):
        """Each frame walks Ethernet, IPv4, UDP, RIP and consumes it all."""
        for frame in FRAMES:
            packet = decode_frame(frame)
            assert [type(layer) for layer in packet] == [
                Ethernet,
                IPv4,
                UDP,
                RIP,
            ]
            assert packet.consumed == len(frame)

    def test_every_message_round_trips_exactly(self):
        """Each captured message re-encodes to its bytes, both ways."""
        for index in range(len(FRAMES)):
            raw = message_bytes(index)
            rip = RIP.decode(raw)
            assert bytes(rip) == raw
            assert RIP.decode(bytes(rip)) == rip

    def test_versions_and_commands(self):
        """Four RIPv1 frames, then RIPv2; the Requests where expected."""
        assert [rip_of(i).version for i in range(len(FRAMES))] == [1] * 4 + [
            2
        ] * 17
        for index in range(len(FRAMES)):
            expected = "Request" if index in REQUESTS else "Response"
            assert rip_of(index).command_name == expected

    def test_requests_ask_for_the_whole_table(self):
        """RFC 2453 §3.9.1: one entry, AFI 0, metric 16."""
        for index in REQUESTS:
            (route,) = rip_of(index).routes
            assert (route.afi, route.afi_name, route.metric) == (
                0,
                "Unspecified",
                16,
            )

    def test_ripv1_zeroes_the_ripv2_fields(self):
        """RIPv1 sends the v2-only fields as zero, and they read so."""
        for index in V1:
            rip = rip_of(index)
            assert rip.reserved == 0
            for route in rip.routes:
                assert (route.route_tag, route.subnet_mask, route.next_hop) == (
                    0,
                    "0.0.0.0",
                    "0.0.0.0",
                )

    def test_ripv1_responses_carry_classful_networks(self):
        """BIRD advertises classful networks over RIPv1."""
        assert {r.address for r in rip_of(2).routes} == {
            "10.0.0.0",
            "172.20.0.0",
            "192.0.2.0",
        }
        assert all(r.metric == 1 for r in rip_of(3).routes)

    def test_ripv2_responses_carry_masks(self):
        """RIPv2 routes carry their masks, a /25 among them."""
        routes = {
            (r.address, r.subnet_mask, r.afi_name, r.metric)
            for r in rip_of(6).routes
        }
        assert routes == {
            ("10.20.1.0", "255.255.255.0", "IP", 1),
            ("10.20.2.0", "255.255.255.0", "IP", 1),
            ("10.20.3.128", "255.255.255.128", "IP", 1),
            ("10.9.52.0", "255.255.255.0", "IP", 1),
        }

    def test_the_periodic_update_poisons_the_peers_routes(self):
        """Send the peer's routes back poisoned, at metric 16.

        Split horizon with poisoned reverse: the routes learnt from
        10.9.52.2 go back to it unreachable.
        """
        rip = rip_of(8)
        assert len(rip.entries) == 7
        poisoned = {r.address for r in rip.routes if r.metric == 16}
        assert poisoned == {"10.30.1.0", "10.30.2.0", "10.30.3.128"}

    def test_routes_reencode_to_their_wire_bytes(self):
        """Re-encoded entries are the body's leading bytes."""
        for index in range(len(FRAMES)):
            rip = rip_of(index)
            joined = b"".join(bytes(e) for e in rip.entries)
            assert rip.body.startswith(joined)
            assert len(joined) == 20 * len(rip.entries)

    def test_unauthenticated_messages(self):
        """A message without authentication has no trailer or remainder."""
        for index in [*V1, *V2]:
            rip = rip_of(index)
            assert rip.authentication is None
            assert rip.authentication_trailer is None
            assert rip.remainder == b""
            assert rip.routes == rip.entries

    def test_plaintext_password(self):
        """A type 2 entry reads as a password, not as a route."""
        for index in PLAINTEXT:
            rip = rip_of(index)
            auth = rip.authentication
            assert auth is not None
            assert (auth.afi, auth.auth_type) == (0xFFFF, 2)
            assert auth.auth_type_name == "Plain-text password"
            assert auth.password == b"nprip-pw"
            assert auth.data == b"nprip-pw".ljust(16, b"\x00")
            assert auth.packet_length is None
            assert rip.entries[0] == auth
            assert auth not in rip.routes
            assert rip.authentication_trailer is None

    @pytest.mark.parametrize(
        "indices,key_id,auth_data_len,trailer_len",
        [(MD5, 1, 20, 20), (SHA256, 2, 32, 36)],
        ids=["keyed-md5", "hmac-sha256"],
    )
    def test_cryptographic_authentication(
        self, indices, key_id, auth_data_len, trailer_len
    ):
        """Run the trailer from the Packet Length offset to the end.

        BIRD declares Auth Data Len 20 for a 16-byte MD5 digest and 32
        for a 32-byte HMAC-SHA-256 one, so it does not size the
        trailer.
        """
        for index in indices:
            rip = rip_of(index)
            auth = rip.authentication
            assert auth is not None
            assert auth.auth_type_name == "Cryptographic Hash Function"
            assert (auth.key_id, auth.auth_data_len) == (key_id, auth_data_len)
            assert auth.password is None
            assert auth.data[8:] == bytes(8)
            assert auth.packet_length == 4 + 20 * len(rip.entries)
            trailer = rip.authentication_trailer
            assert trailer is not None
            assert len(trailer) == trailer_len
            assert trailer[:4] == b"\xff\xff\x00\x01"
            assert rip.remainder == b""
            assert rip.header_len == auth.packet_length + trailer_len

    def test_sequence_numbers(self):
        """Send sequence number 0 in a Request, then a larger one.

        Per router: its Request carries 0 and its first Response, two
        frames later, a nonzero number (BIRD's clock).
        """
        for indices in (MD5, SHA256):
            for request in indices[:2]:
                numbers = [
                    rip_of(i).authentication.sequence_number
                    for i in (request, request + 2)
                ]
                assert numbers[0] == 0 < numbers[1]

    def test_the_digests_verify_with_the_published_keys(self):
        """Verify every digest with the published keys.

        Keyed MD5 runs over the message to the trailer's header and the
        16-byte zero-padded key (RFC 4822 §2.4); HMAC-SHA-256 over the
        same bytes and Apad (§2.5).
        """
        for index in MD5:
            rip = rip_of(index)
            covered = bytes(rip)[: rip.authentication.packet_length + 4]
            digest = hashlib.md5(covered + MD5_KEY.ljust(16, b"\x00"))
            assert rip.authentication_trailer[4:] == digest.digest()
        for index in SHA256:
            rip = rip_of(index)
            covered = bytes(rip)[: rip.authentication.packet_length + 4]
            apad = bytes.fromhex("878fe1f3") * 8
            mac = hmac.new(SHA256_KEY, covered + apad, hashlib.sha256)
            assert rip.authentication_trailer[4:] == mac.digest()

    def test_the_test_keys_are_the_published_ones(self):
        """The keys here are the ones MANIFEST.md publishes."""
        manifest = (FIXTURES / "MANIFEST.md").read_text()
        for key in (MD5_KEY, SHA256_KEY, b"nprip-pw"):
            assert key.decode() in manifest


#: Every fixture frame, with the 4-byte nonzero trailer an Ethernet FCS
#: adds when a capture keeps it.
FCS = b"\xde\xad\xbe\xef"


class TestTrailersAndTruncation:
    """Read a message whose buffer ends somewhere other than its end.

    RIP has no length field and the walk does not trim to UDP's (#235),
    so whatever follows the datagram reaches the decoder.
    """

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    @pytest.mark.parametrize("index", range(len(FRAMES)))
    def test_an_appended_fcs_keeps_every_entry(self, index, lax):
        """A 4-byte trailer after a real frame changes no entry."""
        frame = FRAMES[index] + FCS
        packet = decode_frame(frame, lax=lax)
        assert packet.stopped_by is None
        assert packet.consumed == len(frame)
        rip = packet[RIP]
        assert rip.entries == rip_of(index).entries
        assert rip.authentication == rip_of(index).authentication
        if index in [*MD5, *SHA256]:
            # After a trailer, the FCS cannot be told from the digest.
            assert rip.authentication_trailer == (
                rip_of(index).authentication_trailer + FCS
            )
            assert rip.remainder == b""
        else:
            assert rip.remainder == FCS

    def test_zero_padding_follows_only_an_empty_message(self):
        """Keep Ethernet's padding after an empty message as remainder.

        A header-only message is 32 bytes of IPv4, so Ethernet pads it
        with 14 zeros, which are fewer than an entry.
        """
        rip = RIP.decode(b"\x02\x02\x00\x00" + bytes(14))
        assert rip.entries == ()
        assert rip.remainder == bytes(14)

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    @pytest.mark.parametrize("cut", range(1, 20))
    def test_a_snap_length_cut_inside_an_entry(self, cut, lax):
        """Decode the whole entries before a cut, and keep the cut one.

        The 7-entry periodic update is cut inside its fifth entry: the
        four before it decode, and the cut one is the remainder.
        """
        whole = 4 + 4 * 20
        frame = FRAMES[8][: RIP_START + whole + cut]
        packet = decode_frame(frame, lax=lax)
        assert packet.stopped_by is None
        rip = packet[RIP]
        assert rip.entries == rip_of(8).entries[:4]
        assert rip.remainder == message_bytes(8)[whole : whole + cut]
        assert bytes(rip) == frame[RIP_START:]

    def test_a_cut_before_the_trailer_ends_at_the_last_whole_entry(self):
        """Name no trailer when Packet Length points past the buffer.

        The cut message then reads like an unauthenticated one.
        """
        raw = message_bytes(15)[: 4 + 20 * 3 + 5]
        rip = RIP.decode(raw)
        assert rip.authentication_trailer is None
        assert rip.entries == rip_of(15).entries[:3]
        assert rip.remainder == raw[64:]

    def test_a_cut_inside_the_trailer_keeps_what_arrived(self):
        """A trailer cut short keeps the bytes that arrived."""
        raw = message_bytes(19)
        packet_length = rip_of(19).authentication.packet_length
        rip = RIP.decode(raw[: packet_length + 10])
        assert (
            rip.authentication_trailer
            == raw[packet_length : packet_length + 10]
        )
        assert rip.entries == rip_of(19).entries

    def test_a_cut_inside_the_trailer_header_keeps_what_arrived(self):
        """A trailer cut inside its 4-byte header is still the trailer."""
        raw = message_bytes(19)
        packet_length = rip_of(19).authentication.packet_length
        rip = RIP.decode(raw[: packet_length + 2])
        assert rip.authentication_trailer == b"\xff\xff"
        assert rip.remainder == b""

    def test_a_cut_at_the_trailer_leaves_it_empty(self):
        """A message cut where its trailer starts has an empty trailer."""
        packet_length = rip_of(19).authentication.packet_length
        rip = RIP.decode(message_bytes(19)[:packet_length])
        assert rip.authentication_trailer == b""
        assert rip.remainder == b""

    def test_the_fixed_header_cut(self):
        """A buffer shorter than the 4-byte header raises."""
        for length in range(4):
            with pytest.raises(TruncatedHeaderError):
                RIP.decode(message_bytes(6)[:length])

    def test_memoryview_input_is_not_retained(self):
        """A decoded message does not alias a memoryview it came from."""
        buffer = bytearray(message_bytes(15))
        rip = RIP.decode(memoryview(buffer))
        before = rip.entries
        buffer[:] = bytes(len(buffer))
        assert rip.entries == before
        assert bytes(rip) == message_bytes(15)


class TestPacketLength:
    """Locate the trailer only by a usable Packet Length.

    That is one past the authentication entry, on an entry boundary and
    within the body, at bytes that start as a trailer does.
    """

    def test_a_packet_length_pointing_at_a_route_names_no_trailer(self):
        """Read a route, not a trailer, where Packet Length points at it.

        The trailer must start ``0xFFFF 0x0001``; a Packet Length that
        points at a route instead falls back to 20-byte entries.
        """
        routes = entry() + entry("198.51.100.0")
        trailer = b"\xff\xff\x00\x01" + bytes(16)
        rip = RIP.decode(
            b"\x02\x02\x00\x00" + crypto_auth(24) + routes + trailer
        )
        assert rip.authentication_trailer is None
        assert [r.address for r in rip.routes] == ["192.0.2.0", "198.51.100.0"]
        assert rip.remainder == b""
        assert len(rip.entries) == 4
        assert rip.entries[3].auth_type_name == "Authentication Trailer"

    @pytest.mark.parametrize(
        "tail,kinds,remainder",
        [
            (
                bytes(RIPAuthentication(2, b"pw".ljust(16, b"\x00"))),
                [RIPAuthentication],
                b"",
            ),
            (crypto_auth(44), [RIPAuthentication], b""),
            (entry(afi=0xFF00), [RIPEntry], b""),
            (b"\xff\xff\x12\x34", [], b"\xff\xff\x12\x34"),
        ],
        ids=["type-2-entry", "type-3-entry", "afi-0xff00-route", "ffff-tail"],
    )
    def test_a_packet_length_pointing_at_a_near_trailer(
        self, tail, kinds, remainder
    ):
        """Require all four trailer header bytes where Packet Length points.

        Bytes there that share one, two or three leading bytes with
        ``0xFFFF 0x0001`` (``0xFF00``, ``0xFFFF 0x12``, ``0xFFFF 0x00``)
        are read as entries and remainder, not as a trailer.
        """
        head = crypto_auth(44) + entry()
        rip = RIP.decode(b"\x02\x02\x00\x00" + head + tail)
        assert rip.authentication_trailer is None
        assert rip.entries[:2] == RIP.decode(b"\x02\x02\x00\x00" + head).entries
        assert [type(e) for e in rip.entries[2:]] == kinds
        assert rip.remainder == remainder
        tiled = b"".join(bytes(e) for e in rip.entries) + rip.remainder
        assert tiled == head + tail

    def test_entries_after_the_trailer_header_are_the_trailers(self):
        """Read everything from a real trailer header on as the trailer.

        RFC 4822 puts the trailer last, so a Packet Length that points
        at ``0xFFFF 0x0001`` before a route folds the route into it.
        """
        trailer = b"\xff\xff\x00\x01" + bytes(16) + entry("198.51.100.0")
        rip = RIP.decode(
            b"\x02\x02\x00\x00" + crypto_auth(44) + entry() + trailer
        )
        assert rip.authentication_trailer == trailer
        assert [r.address for r in rip.routes] == ["192.0.2.0"]
        assert rip.remainder == b""

    def test_a_trailer_that_is_not_a_multiple_of_twenty(self):
        """A 36-byte HMAC-SHA-256 trailer is located by Packet Length."""
        trailer = b"\xff\xff\x00\x01" + bytes(range(32))
        raw = b"\x02\x02\x00\x00" + crypto_auth(44, 32) + entry() + trailer
        rip = RIP.decode(raw)
        assert len(rip.entries) == 2
        assert rip.authentication_trailer == trailer

    @pytest.mark.parametrize(
        "packet_length",
        [0, 4, 23, 25, 43, 45, 84, 0xFFFF],
        ids=lambda n: f"{n}",
    )
    def test_an_unusable_packet_length_names_no_trailer(self, packet_length):
        """A Packet Length out of place falls back to 20-byte entries."""
        raw = b"\x02\x02\x00\x00" + crypto_auth(packet_length) + entry()
        raw += b"\xff\xff\x00\x01" + bytes(16)
        rip = RIP.decode(raw)
        assert rip.authentication_trailer is None
        assert rip.authentication.packet_length == packet_length
        # Read as 20-byte entries instead: the 20-byte MD5 trailer then
        # becomes an authentication entry, never a route.
        assert len(rip.entries) == 3
        assert isinstance(rip.entries[2], RIPAuthentication)
        assert rip.entries[2].auth_type_name == "Authentication Trailer"
        assert len(rip.routes) == 1

    def test_a_packet_length_covering_only_the_authentication_entry(self):
        """Packet Length 24 leaves no room for routes, only a trailer."""
        raw = b"\x01\x02\x00\x00" + crypto_auth(24) + b"\xff\xff\x00\x01"
        rip = RIP.decode(raw + bytes(16))
        assert rip.routes == ()
        assert rip.authentication_trailer == b"\xff\xff\x00\x01" + bytes(16)

    def test_a_trailer_needs_a_type_3_first_entry(self):
        """Find no trailer behind anything but a type 3 entry.

        A plain-text password entry's 16 bytes are a password, even when
        they could read as a Packet Length.
        """
        auth = bytes(RIPAuthentication(2, b"\x00\x18" + bytes(14)))
        rip = RIP.decode(b"\x02\x02\x00\x00" + auth + entry())
        assert rip.authentication_trailer is None
        assert len(rip.entries) == 2

    def test_an_authentication_entry_out_of_place(self):
        """Recognise an authentication entry that is not first.

        RFC 2453 §4.1 puts it first; a later one is still read as
        authentication, not as a route, but is not the message's.
        """
        auth = bytes(RIPAuthentication(2, b"pw".ljust(16, b"\x00")))
        rip = RIP.decode(b"\x02\x02\x00\x00" + entry() + auth)
        assert rip.authentication is None
        assert isinstance(rip.entries[1], RIPAuthentication)
        assert rip.entries[1].password == b"pw"
        assert len(rip.routes) == 1


class TestAuthenticationEntries:
    """Read an authentication entry's fields and name its type."""

    def test_the_widest_cryptographic_fields(self):
        """Read every type 3 field unsigned, its widest value included."""
        auth = RIPAuthentication(3, b"\xff" * 8 + bytes(8))
        assert (
            auth.packet_length,
            auth.key_id,
            auth.auth_data_len,
            auth.sequence_number,
        ) == (0xFFFF, 0xFF, 0xFF, 0xFFFFFFFF)

    def test_a_first_entry_with_afi_0xff00_is_a_route(self):
        """Authenticate only with AFI 0xFFFF, both bytes of it."""
        rip = RIP.decode(b"\x02\x02\x00\x00" + entry(afi=0xFF00))
        assert rip.authentication is None
        (route,) = rip.routes
        assert route.afi == 0xFF00
        assert rip.entries == (route,)

    def test_a_password_keeps_its_leading_bytes(self):
        """Strip only the NUL padding on the right (RFC 2453 §4.1).

        The password is left-justified, so a leading NUL or space is
        part of it.
        """
        auth = RIPAuthentication(2, b"\x00 pw ".ljust(16, b"\x00"))
        assert auth.password == b"\x00 pw "

    def test_authentication_type_0_is_named_none(self):
        """Name type 0 as IANA's registry does."""
        assert RIPAuthentication(0).auth_type_name == "none"

    def test_unknown_authentication_types(self):
        """An unknown authentication type decodes, its fields ``None``."""
        auth = RIPAuthentication(9, bytes(range(16)))
        rip = RIP.decode(b"\x02\x02\x00\x00" + bytes(auth))
        assert rip.authentication == auth
        assert auth.auth_type_name == "unknown (9)"
        assert (auth.password, auth.key_id, auth.sequence_number) == (
            None,
            None,
            None,
        )
        assert rip.authentication_trailer is None


class TestDecodeGuard:
    """What decode() rejects, because no RIP message carries it."""

    @pytest.mark.parametrize("version", [0, 3, 4, 255])
    def test_a_version_other_than_1_or_2(self, version):
        """A version outside 1-2 is rejected at its byte."""
        raw = bytes([2, version, 0, 0]) + entry()
        with pytest.raises(InvalidFieldError) as caught:
            RIP.decode(raw)
        assert (caught.value.field, caught.value.offset) == ("version", 1)
        assert caught.value.actual == version

    def test_command_0(self):
        """Command 0, which IANA lists as invalid, is rejected."""
        with pytest.raises(InvalidFieldError) as caught:
            RIP.decode(b"\x00\x02\x00\x00" + entry())
        assert (caught.value.field, caught.value.offset) == ("command", 0)
        assert (caught.value.actual, caught.value.expected) == (0, "1-255")

    def test_a_rejected_guess_is_reported_at_the_rip_header(self):
        """A rejected guess keeps the layers below and names its offset."""
        frame = FRAMES[6][:RIP_START] + b"\x02\x00" + message_bytes(6)[2:]
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert packet.stopped_by.frame_offset == RIP_START + 1
        with pytest.raises(InvalidFieldError):
            decode_frame(frame)

    def test_exactly_510_of_the_two_byte_prefixes_pass(self):
        """Accept 510 command-version pairs, reject 65,026 (99.2%).

        Command and version alone decide, so this is exact for random
        datagrams.
        """
        passed = 0
        for command in range(256):
            for version in range(256):
                try:
                    RIP.decode(bytes([command, version, 0, 0]))
                except InvalidFieldError:
                    continue
                passed += 1
        assert passed == 255 * 2

    @pytest.mark.parametrize(
        "command,name",
        [
            (3, "TraceOn"),
            (4, "TraceOff"),
            (5, "Reserved"),
            (6, "Triggered Request"),
            (7, "Triggered Response"),
            (8, "Triggered Acknowledgement"),
            (9, "Update Request"),
            (10, "Update Response"),
            (11, "Update Acknowledge"),
            (12, "unknown (12)"),
            (255, "unknown (255)"),
        ],
    )
    def test_other_commands_decode_and_are_preserved(self, command, name):
        """Obsolete and extension commands decode and round-trip."""
        raw = bytes([command, 1, 0, 0]) + b"/tmp/rip.trace"
        rip = RIP.decode(raw)
        assert rip.command == command
        assert rip.command_name == name
        assert bytes(rip) == raw
        assert rip.remainder == b"/tmp/rip.trace"

    def test_nonzero_must_be_zero_fields_in_ripv1_are_kept(self):
        """Decode a RIPv1 message whose must-be-zero bytes are not zero.

        RFC 1058 §3.4 tells a receiver to ignore such a message; a
        decoder shows it as it is.
        """
        raw = b"\x02\x01\xab\xcd" + entry(route_tag=7, next_hop="192.0.2.1")
        rip = RIP.decode(raw)
        assert rip.reserved == 0xABCD
        (route,) = rip.routes
        assert (route.route_tag, route.next_hop) == (7, "192.0.2.1")
        assert bytes(rip) == raw


class TestConstruction:
    def test_build_a_message_from_entries(self):
        """A message built from entries decodes back to itself."""
        routes = [entry("192.0.2.0"), entry("198.51.100.0", metric=16)]
        rip = RIP(command=2, version=2, body=b"".join(routes))
        assert RIP.decode(bytes(rip)) == rip
        assert [r.address for r in rip.routes] == ["192.0.2.0", "198.51.100.0"]

    @pytest.mark.parametrize(
        "field,value,expected",
        [
            ("command", 256, "0-255"),
            ("command", -1, "0-255"),
            ("version", 256, "0-255"),
            ("reserved", 0x10000, "0-65535"),
        ],
    )
    def test_out_of_range_header_fields(self, field, value, expected):
        """A header field too wide for its bytes is refused."""
        with pytest.raises(InvalidFieldError) as caught:
            replace(RIP(2, 2), **{field: value})
        assert (caught.value.field, caught.value.expected) == (field, expected)

    def test_a_version_decode_rejects_still_builds(self):
        """Construction accepts a version decode rejects."""
        rip = RIP(command=2, version=0)
        assert bytes(rip) == b"\x02\x00\x00\x00"
        with pytest.raises(InvalidFieldError):
            RIP.decode(bytes(rip))

    def test_the_widest_values_are_accepted(self):
        """Every field's widest value builds and round-trips."""
        rip = RIP(command=255, version=2, reserved=0xFFFF)
        assert RIP.decode(bytes(rip)) == rip
        route = RIPEntry(
            0xFFFE, 0xFFFF, "255.255.255.255", "0.0.0.0", "0.0.0.0", 0xFFFFFFFF
        )
        assert RIP.decode(b"\x02\x02\x00\x00" + bytes(route)).routes == (route,)

    @pytest.mark.parametrize(
        "field,value",
        [("afi", 0x10000), ("route_tag", -1), ("metric", 1 << 32)],
    )
    def test_out_of_range_entry_fields(self, field, value):
        """An entry field too wide for its bytes is refused."""
        base = RIPEntry(2, 0, "192.0.2.0", "255.255.255.0", "0.0.0.0", 1)
        with pytest.raises(InvalidFieldError) as caught:
            replace(base, **{field: value})
        assert caught.value.field == field

    @pytest.mark.parametrize("field", ["address", "subnet_mask", "next_hop"])
    def test_entry_addresses_are_validated(self, field):
        """An entry address must be dotted-decimal."""
        base = RIPEntry(2, 0, "192.0.2.0", "255.255.255.0", "0.0.0.0", 1)
        with pytest.raises(InvalidIPv4AddressError) as caught:
            replace(base, **{field: "192.0.2"})
        assert caught.value.field == field

    def test_authentication_data_is_16_bytes(self):
        """Authentication data is exactly 16 bytes."""
        with pytest.raises(InvalidFieldError) as caught:
            RIPAuthentication(2, b"short")
        assert (caught.value.field, caught.value.actual) == ("data", 5)
        with pytest.raises(InvalidFieldError):
            RIPAuthentication(0x10000)
        assert bytes(RIPAuthentication(2)) == b"\xff\xff\x00\x02" + bytes(16)

    def test_unknown_afi_name(self):
        """An address family not named here displays as unknown."""
        assert RIPEntry(7, 0, "0.0.0.0", "0.0.0.0", "0.0.0.0", 0).afi_name == (
            "unknown (7)"
        )

    def test_positional_patterns_follow_wire_order(self):
        """Positional patterns bind the header fields in wire order."""
        match RIP.decode(message_bytes(6)):
            case RIP(2, 2, 0, body):
                assert len(body) == 80
            case _:
                pytest.fail("positional pattern did not match")


class TestDispatch:
    def test_registered_on_port_520(self):
        """The default registry maps UDP port 520 to RIP."""
        assert DEFAULT.get(TABLE_UDP_PORT, 520) is RIP

    @pytest.mark.parametrize(
        "src_port,dst_port", [(520, 520), (40000, 520), (520, 40000)]
    )
    def test_either_port(self, src_port, dst_port):
        """Dispatch on either port.

        A router answers a Request from another port back to that port,
        from 520 (RFC 2453 §3.9.1).
        """
        udp = UDP(src_port=src_port, dst_port=dst_port, length=0, checksum=0)
        assert udp.next_protocol() is RIP

    def test_ripng_is_not_decoded(self):
        """RIPng (RFC 2080, UDP 521) is RIP for IPv6, out of scope."""
        udp = UDP(src_port=521, dst_port=521, length=0, checksum=0)
        assert udp.next_protocol() is None

    def test_rip_ends_the_chain(self):
        """RIP carries no further protocol."""
        assert rip_of(6).next_protocol() is None

    def test_decode_as_can_take_the_port_away(self):
        """Let a caller decode port 520 as something else for one walk.

        It is best-effort, like every port entry.
        """
        packet = decode_frame(FRAMES[6], decode_as={"udp.port": {520: DNS}})
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP, DNS]
