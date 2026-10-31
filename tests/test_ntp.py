"""Test NTP (RFC 5905, RFC 1305, RFC 7822) decoding and dispatch.

Covered: the 48-byte header, the timestamp conversions, how the bytes
after the header are split into extension fields, a MAC and a
remainder with no length field to go by, the decode-time guard against
a wrong port guess, and dispatch from UDP port 123.

The chronyd and ntpdig exchanges in tests/fixtures/ntp.pcap (see its
MANIFEST note) anchor the decode, round-trip and timestamp asserts; the
cases those daemons do not send (a Kiss-o'-Death, a crypto-NAK, a
control message, malformed extension fields) are built here.
"""

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from conftest import FIXTURES
from netprotocols import (
    DNS,
    NTP,
    NTPMAC,
    UDP,
    Ethernet,
    InvalidFieldError,
    IPv4,
    NTPExtensionField,
    TruncatedHeaderError,
    decode_frame,
    read_pcap,
)
from netprotocols.layer7.ntp import ntp_to_datetime, ntp_to_unix
from netprotocols.registry import DEFAULT, TABLE_UDP_PORT

CAPTURED = list(read_pcap((FIXTURES / "ntp.pcap").read_bytes()))
FRAMES = [frame.data for frame in CAPTURED]

#: Ethernet + a 20-byte IPv4 header + UDP, in front of every message.
NTP_START = 14 + 20 + 8

#: The fixture's frames by scenario, in the order the capture script
#: selects them: a request from 10.9.191.2, then 10.9.191.1's answer.
SNTP = (0, 1)
MD5 = (2, 3)
SHA1 = (4, 5)
V3 = (6, 7)
EXTFIELD = (8, 9)
NTS = (10, 11)
SYMMETRIC = (12, 13, 14, 15)
BROADCAST = 16
#: Each request and the answer to it.
EXCHANGES = [SNTP, MD5, SHA1, V3, EXTFIELD, NTS, (12, 13), (14, 15)]
#: The requests ntpdig sent, with a real Transmit Timestamp.
NTPDIG_REQUESTS = [0, 2, 4]

#: The test keys chronyd and ntpdig were configured with, published in
#: MANIFEST.md, by Key ID.
KEYS = {1: ("md5", b"np191-md5-key"), 2: ("sha1", b"np191-sha1-key")}

#: chronyd's Reference ID for its local reference, 127.127.1.1.
LOCAL_REFID = 0x7F7F0101

#: Seconds from 1900 to 1970 (RFC 5905 §6, Figure 4).
NTP_TO_UNIX = 2_208_988_800


def message_bytes(index: int) -> bytes:
    """Return the NTP message of capture frame ``index``, exactly."""
    return FRAMES[index][NTP_START:]


def ntp_of(index: int) -> NTP:
    layer = decode_frame(FRAMES[index])[NTP]
    assert isinstance(layer, NTP)
    return layer


def captured_at(index: int) -> datetime:
    """Return when tcpdump captured frame ``index``, in UTC."""
    nanoseconds = CAPTURED[index].timestamp
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
        microseconds=nanoseconds // 1000
    )


def header(first_byte: int = 0x23, **fields: int) -> bytes:
    """A 48-byte header: ``first_byte`` (default v4 client), then zeros.

    Keyword arguments set the NTP fields after the first byte.
    """
    base = NTP.decode(bytes([first_byte]) + bytes(47))
    return bytes(replace(base, **fields))


def udp_frame(payload: bytes) -> bytes:
    """``payload`` in a UDP datagram to port 123, behind the IPv4 and
    Ethernet headers of the first captured frame, padded to Ethernet's
    60-byte minimum as a NIC would pad it."""
    ip = bytearray(FRAMES[SNTP[0]][14:34])
    ip[2:4] = (20 + 8 + len(payload)).to_bytes(2, "big")
    ip[10:12] = bytes(2)
    udp = bytes(
        UDP(src_port=40000, dst_port=123, length=8 + len(payload), checksum=0)
    )
    frame = FRAMES[SNTP[0]][:14] + bytes(ip) + udp + payload
    return frame + bytes(max(0, 60 - len(frame)))


#: Control messages (modes 6 and 7), which NTP.decode() rejects: an
#: ntpq read-variables request (RFC 9327, a 12-byte header and no data),
#: a mode 6 response carrying 60 bytes of variables, and mode 7
#: requests of 48 and 192 bytes.
CONTROL_MESSAGES = {
    "mode-6-request-12": bytes.fromhex("160200010000000000000000"),
    "mode-6-response-72": bytes.fromhex("16820001061500000000003c") + b"v" * 60,
    "mode-7-request-48": bytes.fromhex("17000310") + bytes(44),
    "mode-7-request-192": bytes.fromhex("17000310") + bytes(188),
}


def field(field_type: int, value_len: int) -> bytes:
    """An extension field whose value is ``value_len`` bytes of 0xAB."""
    return bytes(NTPExtensionField(field_type, b"\xab" * value_len))


class TestCapturedMessages:
    def test_every_frame_walks_to_ntp_and_ends_there(self):
        """Each frame walks Ethernet, IPv4, UDP, NTP and consumes it all."""
        for frame in FRAMES:
            packet = decode_frame(frame)
            assert [type(layer) for layer in packet] == [
                Ethernet,
                IPv4,
                UDP,
                NTP,
            ]
            assert packet.consumed == len(frame)

    def test_every_message_round_trips_exactly(self):
        """Each captured message re-encodes to its bytes, both ways."""
        for index in range(len(FRAMES)):
            raw = message_bytes(index)
            ntp = NTP.decode(raw)
            assert bytes(ntp) == raw
            assert ntp.header_len == len(raw)
            assert NTP.decode(bytes(ntp)) == ntp

    def test_versions_and_modes(self):
        """NTPv3 in the v3 exchange, NTPv4 elsewhere; six modes."""
        assert [ntp_of(i).version for i in range(len(FRAMES))] == (
            [4] * 6 + [3] * 2 + [4] * 9
        )
        assert [ntp_of(i).mode_name for i in range(len(FRAMES))] == [
            *["client", "server"] * 6,
            *["symmetric active", "symmetric passive"] * 2,
            "broadcast",
        ]

    def test_every_answer_echoes_the_request(self):
        """An answer's Origin Timestamp is the request's Transmit (§8).

        That holds for chrony's requests too, whose Transmit Timestamp
        is random rather than a time.
        """
        for request, answer in EXCHANGES:
            assert (
                ntp_of(answer).origin_timestamp
                == ntp_of(request).transmit_timestamp
            )

    @pytest.mark.parametrize("index", [1, 3, 5, 7, 9, 11, 13, 15, BROADCAST])
    def test_the_server_speaks_from_its_local_reference(self, index):
        """chronyd with "local stratum 8": stratum 8, 127.127.1.1."""
        ntp = ntp_of(index)
        assert (ntp.leap, ntp.leap_name) == (0, "no warning")
        assert (ntp.stratum, ntp.stratum_name) == (8, "secondary server")
        assert (ntp.reference_id, ntp.reference_id_str, ntp.kiss_code) == (
            LOCAL_REFID,
            "127.127.1.1",
            None,
        )
        assert (ntp.precision, ntp.precision_seconds) == (-25, 2.0**-25)
        assert (ntp.root_delay, ntp.root_dispersion) == (0, 0)
        assert ntp.reference_time is not None

    def test_ntpdig_asks_with_an_unsynchronized_empty_header(self):
        """ntpdig fills in the version, mode and Transmit Timestamp only.

        Leap Indicator 3 says its clock is unsynchronized; the Reference
        ID is zero, so there is no kiss code, and the other three
        timestamps are zero, "unknown" (RFC 5905 §6).
        """
        for index in NTPDIG_REQUESTS:
            ntp = ntp_of(index)
            assert ntp.leap_name == "unknown (clock unsynchronized)"
            assert (ntp.stratum, ntp.poll, ntp.precision) == (0, 0, 0)
            assert ntp.stratum_name == "unspecified or invalid"
            assert (ntp.reference_id_str, ntp.kiss_code) == ("", None)
            assert ntp.reference_time is None
            assert ntp.origin_time is None
            assert ntp.receive_time is None

    def test_ntpdig_transmit_times_match_the_capture_clock(self):
        """A real Transmit Timestamp converts to when it was captured.

        ntpdig stamps its request from the same clock tcpdump reads, so
        the conversion is off by microseconds, not by an era or a time
        zone.
        """
        for index in NTPDIG_REQUESTS:
            sent = ntp_of(index).transmit_time
            assert sent is not None
            assert sent.tzinfo is UTC
            assert abs(sent - captured_at(index)) < timedelta(milliseconds=5)
            unix = ntp_to_unix(ntp_of(index).transmit_timestamp)
            assert unix is not None
            assert abs(unix - CAPTURED[index].timestamp / 1e9) < 0.005

    def test_the_servers_times_bracket_the_request(self):
        """The server received after the request was captured, and sent
        its answer before the answer was captured."""
        for request, answer in EXCHANGES:
            ntp = ntp_of(answer)
            assert ntp.receive_time is not None
            assert ntp.transmit_time is not None
            slack = timedelta(milliseconds=5)
            assert captured_at(request) - slack <= ntp.receive_time
            assert ntp.receive_time <= ntp.transmit_time
            assert ntp.transmit_time <= captured_at(answer) + slack

    def test_chrony_hides_its_clock_from_the_server(self):
        """chrony's requests leave every timestamp but Transmit zero, and
        fill Transmit with random bits, which need not convert near the
        capture time."""
        for index in (V3[0], EXTFIELD[0], NTS[0]):
            ntp = ntp_of(index)
            assert (ntp.leap, ntp.stratum, ntp.poll) == (0, 0, 6)
            assert ntp.poll_seconds == 64.0
            assert ntp.precision == 32
            assert ntp.origin_time is ntp.receive_time is None
            assert ntp.transmit_timestamp != 0

    def test_the_peer_before_and_after_it_synchronizes(self):
        """chrony's peer starts unsynchronized, then names the server.

        Unsynchronized: Leap Indicator 3, stratum 0 with no kiss code,
        and chrony's 1-second root delay and dispersion. Synchronized to
        10.9.191.1: stratum 9, and the server's IPv4 address as its
        Reference ID (RFC 5905 §7.3).
        """
        first, later = ntp_of(SYMMETRIC[0]), ntp_of(SYMMETRIC[2])
        assert (first.leap, first.stratum, first.kiss_code) == (3, 0, None)
        assert first.root_delay == first.root_dispersion == 0x00010000
        assert first.root_delay_seconds == first.root_dispersion_seconds == 1
        assert (later.leap, later.stratum) == (0, 9)
        assert later.reference_id == 0x0A09BF01
        assert later.reference_id_str == "10.9.191.1"
        assert later.root_delay_seconds == later.root_delay / 65536
        assert later.reference_time is not None

    def test_the_broadcast(self):
        """A broadcast answers nothing: Origin and Receive are zero."""
        ntp = ntp_of(BROADCAST)
        assert ntp.origin_time is ntp.receive_time is None
        assert ntp.transmit_time is not None
        assert (ntp.poll, ntp.poll_seconds) == (1, 2.0)
        assert decode_frame(FRAMES[BROADCAST])[IPv4].dst == "10.9.191.255"

    def test_plain_messages_have_nothing_after_the_header(self):
        """No extension field, MAC or remainder in a plain message."""
        for index in [*SNTP, *V3, *SYMMETRIC, BROADCAST]:
            ntp = ntp_of(index)
            assert ntp.body == b""
            assert (ntp.extension_fields, ntp.mac) == ((), None)
            assert ntp.remainder == b""

    @pytest.mark.parametrize(
        "index,key_id,digest_len",
        [(2, 1, 16), (3, 1, 16), (4, 2, 20), (5, 2, 20)],
    )
    def test_symmetric_key_macs(self, index, key_id, digest_len):
        """A MAC is the Key Identifier and a digest (RFC 5905 §7.3)."""
        ntp = ntp_of(index)
        mac = ntp.mac
        assert mac is not None
        assert (mac.key_id, len(mac.digest)) == (key_id, digest_len)
        assert not mac.is_crypto_nak
        assert ntp.extension_fields == ()
        assert ntp.remainder == b""
        assert bytes(mac) == ntp.body

    @pytest.mark.parametrize("index", [2, 3, 4, 5])
    def test_the_macs_verify_with_the_published_keys(self, index):
        """Each digest is the hash of the key, then the 48-byte header.

        ntpdig made the requests' and chronyd the answers', so the two
        implementations agree with each other and with MANIFEST.md.
        """
        ntp = ntp_of(index)
        mac = ntp.mac
        assert mac is not None
        algorithm, key = KEYS[mac.key_id]
        covered = message_bytes(index)[:48]
        assert hashlib.new(algorithm, key + covered).digest() == mac.digest

    def test_chronys_experimental_extension_field(self):
        """chrony's "extfield F323": one 28-byte field each way.

        0xF323 is chrony's own experimental type, in the range RFC 9748
        reserves for Private or Experimental Use, which says so.
        """
        for index in EXTFIELD:
            ntp = ntp_of(index)
            (only,) = ntp.extension_fields
            assert (only.type, len(bytes(only))) == (0xF323, 28)
            assert only.type_name == "Private or Experimental Use (0xf323)"
            assert (ntp.mac, ntp.remainder) == (None, b"")
            assert bytes(only) == ntp.body

    def test_network_time_security(self):
        """NTS (RFC 8915): the request carries a Unique Identifier, an NTS
        Cookie and an NTS Authenticator, and the answer echoes the
        Unique Identifier and carries its own Authenticator, whose
        ciphertext holds the new cookies."""
        request, answer = ntp_of(NTS[0]), ntp_of(NTS[1])
        assert [f.type for f in request.extension_fields] == [
            0x0104,
            0x0204,
            0x0404,
        ]
        assert [f.type_name for f in answer.extension_fields] == [
            "Unique Identifier",
            "NTS Authenticator and Encrypted Extension Fields",
        ]
        assert request.extension_fields[1].type_name == "NTS Cookie"
        assert request.extension_fields[0] == answer.extension_fields[0]
        for ntp in (request, answer):
            assert (ntp.mac, ntp.remainder) == (None, b"")
            joined = b"".join(bytes(f) for f in ntp.extension_fields)
            assert joined == ntp.body

    def test_raw_fixture_matches_the_capture(self, raw_ntp_message):
        """conftest's raw_ntp_message is the first answer, verbatim."""
        assert raw_ntp_message == message_bytes(SNTP[1])


class TestTimestamps:
    @pytest.mark.parametrize(
        "seconds,expected",
        [
            (2_208_988_800, datetime(1970, 1, 1, tzinfo=UTC)),
            (2_272_060_800, datetime(1972, 1, 1, tzinfo=UTC)),
            (3_155_587_200, datetime(1999, 12, 31, tzinfo=UTC)),
            (63_104, datetime(2036, 2, 8, tzinfo=UTC)),
        ],
        ids=["1970", "1972", "1999", "2036-era-1"],
    )
    def test_rfc_5905_figure_4(self, seconds, expected):
        """RFC 5905 §6, Figure 4's dates, the 2036 one in era 1."""
        assert ntp_to_datetime(seconds << 32) == expected
        assert ntp_to_unix(seconds << 32) == expected.timestamp()

    def test_the_era_boundary(self):
        """RFC 4330 §3: a clear top bit is era 1, from 2036-02-07T06:28:16.

        The last second of era 0 is the one before it, and a set top
        bit reaches back to 1968.
        """
        last = datetime(2036, 2, 7, 6, 28, 15, tzinfo=UTC)
        assert ntp_to_datetime(0xFFFFFFFF << 32) == last
        assert ntp_to_datetime(1) == last + timedelta(seconds=1)
        assert ntp_to_datetime(0x80000000 << 32) == datetime(
            1968, 1, 20, 3, 14, 8, tzinfo=UTC
        )
        assert ntp_to_datetime(0x7FFFFFFF << 32) == datetime(
            2104, 2, 26, 9, 42, 23, tzinfo=UTC
        )

    def test_the_fraction(self):
        """The 32-bit fraction is 2**-32 s; a datetime truncates it to
        the microsecond, the float keeps it."""
        epoch = NTP_TO_UNIX << 32
        assert ntp_to_unix(epoch | 0x80000000) == 0.5
        assert ntp_to_datetime(epoch | 0x80000000) == datetime(
            1970, 1, 1, 0, 0, 0, 500_000, tzinfo=UTC
        )
        assert ntp_to_datetime(epoch | 0xFFFFFFFF) == datetime(
            1970, 1, 1, 0, 0, 0, 999_999, tzinfo=UTC
        )
        unix = ntp_to_unix(epoch | 0xFFFFFFFF)
        assert unix is not None
        assert 0.999999 < unix < 1

    def test_zero_is_unknown(self):
        """The value 0 means "unknown" (RFC 5905 §6), not 1900 or 2036."""
        assert ntp_to_datetime(0) is None
        assert ntp_to_unix(0) is None
        ntp = NTP(0, 4, 3)
        assert ntp.reference_time is ntp.origin_time is None
        assert ntp.receive_time is ntp.transmit_time is None

    def test_the_properties_keep_the_raw_value(self):
        """The ``*_time`` properties convert alongside the raw field."""
        ntp = NTP.decode(message_bytes(SNTP[1]))
        assert ntp.transmit_timestamp == 0xEE90302594F33BB4
        assert ntp.transmit_time == ntp_to_datetime(0xEE90302594F33BB4)
        assert ntp.origin_time == ntp_to_datetime(ntp.origin_timestamp)
        assert ntp.receive_time == ntp_to_datetime(ntp.receive_timestamp)
        assert ntp.reference_time == ntp_to_datetime(0xEE903023F016AF37)


class TestAfterTheHeader:
    """How the body is split with no length field to go by (RFC 7822)."""

    def test_a_crypto_nak(self):
        """Four zero bytes are a MAC of Key Identifier 0, no digest."""
        ntp = NTP.decode(header(0x24) + bytes(4))
        assert ntp.mac == NTPMAC(0)
        assert ntp.mac is not None and ntp.mac.is_crypto_nak
        assert (ntp.extension_fields, ntp.remainder) == ((), b"")

    def test_an_fcs_reads_as_a_crypto_nak(self):
        """The blind spot: 4 trailing bytes have a MAC's length.

        Only the UDP length could tell an Ethernet FCS apart.
        """
        ntp = NTP.decode(header() + b"\xde\xad\xbe\xef")
        assert ntp.mac == NTPMAC(0xDEADBEEF)
        assert ntp.mac is not None and not ntp.mac.is_crypto_nak

    def test_an_extension_field_and_a_mac(self):
        """A field, then a MAC once 20 or 24 bytes are left."""
        for digest_len in (16, 20):
            mac = bytes(NTPMAC(7, b"\x11" * digest_len))
            ntp = NTP.decode(header() + field(0x0104, 12) + mac)
            assert [f.type for f in ntp.extension_fields] == [0x0104]
            assert ntp.mac == NTPMAC(7, b"\x11" * digest_len)

    def test_a_last_field_without_a_mac(self):
        """RFC 7822 §3: a last field without a MAC is at least 28 bytes,
        so it walks as a field; one of 16 bytes walks too."""
        for value_len in (12, 24, 100):
            ntp = NTP.decode(header() + field(0x0204, value_len))
            assert len(ntp.extension_fields) == 1
            assert (ntp.mac, ntp.remainder) == (None, b"")

    def test_a_field_of_a_macs_length_is_read_as_a_mac(self):
        """A last field of 20 or 24 bytes, which RFC 7822 rules out, has
        a MAC's length, and reads as one."""
        ntp = NTP.decode(header() + field(0x0104, 16))
        assert ntp.extension_fields == ()
        assert ntp.mac == NTPMAC(0x01040014, b"\xab" * 16)

    @pytest.mark.parametrize(
        "length",
        [12, 18, 0x1000],
        ids=["below-16", "not-a-multiple-of-4", "past-the-body"],
    )
    def test_a_length_rfc_7822_forbids_ends_the_walk(self, length):
        """The walk stops at a Length below 16, not a multiple of 4, or
        past the body, and what is left is the remainder."""
        bad = length.to_bytes(2, "big").rjust(4, b"\x01") + b"\x00" * 24
        good = field(0x0104, 12)
        ntp = NTP.decode(header() + good + bad)
        assert [bytes(f) for f in ntp.extension_fields] == [good]
        assert (ntp.mac, ntp.remainder) == (None, bad)

    def test_a_cut_field_is_a_remainder(self):
        """A field cut by a snap length is kept, as the remainder."""
        cut = field(0x0204, 60)[:40]
        ntp = NTP.decode(header() + cut)
        assert (ntp.extension_fields, ntp.mac) == ((), None)
        assert ntp.remainder == cut

    def test_ntpv3_has_no_extension_fields(self):
        """Below version 4 nothing walks as a field (RFC 7822 is v4)."""
        body = field(0x0104, 24)
        ntp = NTP.decode(header(0x1B) + body)
        assert (ntp.version, ntp.extension_fields) == (3, ())
        assert (ntp.mac, ntp.remainder) == (None, body)

    def test_ntpv3_des_authenticator(self):
        """RFC 1305 Appendix C: a Key ID and a 64-bit DES checksum.

        Twelve bytes are a MAC below version 4 only.
        """
        des = bytes(NTPMAC(9, b"\x22" * 8))
        assert NTP.decode(header(0x1B) + des).mac == NTPMAC(9, b"\x22" * 8)
        v4 = NTP.decode(header(0x23) + des)
        assert (v4.mac, v4.remainder) == (None, des)

    def test_ntpv3_macs(self):
        """NTPv3 reads 4, 20 and 24 bytes as a MAC too, as v4 does."""
        for length in (4, 20, 24):
            ntp = NTP.decode(header(0x1B) + bytes(range(length)))
            assert ntp.mac is not None
            assert bytes(ntp.mac) == bytes(range(length))

    def test_the_fixed_header_cut(self):
        """Fewer than 48 bytes cannot hold the header."""
        with pytest.raises(TruncatedHeaderError) as caught:
            NTP.decode(message_bytes(SNTP[1])[:47])
        assert (caught.value.expected, caught.value.actual) == (48, 47)

    def test_memoryview_input_is_not_retained(self):
        """A decode from a view copies the body out of it."""
        buffer = bytearray(message_bytes(MD5[1]))
        ntp = NTP.decode(memoryview(buffer))
        buffer[60:70] = bytes(10)
        assert isinstance(ntp.body, bytes)
        assert ntp == NTP.decode(message_bytes(MD5[1]))


class TestDecodeGuard:
    @pytest.mark.parametrize("version", [0, 5, 6, 7])
    def test_a_version_outside_1_to_4(self, version):
        """A version RFC 5905 and its predecessors do not define."""
        with pytest.raises(InvalidFieldError) as caught:
            NTP.decode(bytes([version << 3 | 3]) + bytes(47))
        error = caught.value
        assert (error.field, error.offset, error.actual) == (
            "version",
            0,
            version,
        )

    def test_ntpv2_decodes(self):
        """NTPv2 (RFC 1119) has the Mode field and the header."""
        ntp = NTP.decode(bytes([2 << 3 | 4]) + bytes(47))
        assert (ntp.version, ntp.mode_name) == (2, "server")

    def test_ntpv1_decodes_as_mode_0(self):
        """NTPv1 (RFC 1059) shares the header only by position.

        It has no Mode field, so the three bits are zero and a real
        NTPv1 message reads as mode 0, reserved.
        """
        ntp = NTP.decode(bytes([1 << 3]) + bytes(47))
        assert (ntp.version, ntp.mode, ntp.mode_name) == (1, 0, "reserved")

    @pytest.mark.parametrize("mode", [6, 7])
    def test_control_messages_are_not_decoded(self, mode):
        """Modes 6 and 7 are control messages, not this header."""
        with pytest.raises(InvalidFieldError) as caught:
            NTP.decode(bytes([0x20 | mode]) + bytes(47))
        assert (caught.value.field, caught.value.actual) == ("mode", mode)

    @pytest.mark.parametrize(
        "message", CONTROL_MESSAGES.values(), ids=list(CONTROL_MESSAGES)
    )
    def test_a_control_message_is_rejected_at_any_length(self, message):
        """ntpq's and ntpdc's messages raise for their mode, whether
        shorter than 48 bytes, exactly 48 or longer."""
        with pytest.raises(InvalidFieldError) as caught:
            NTP.decode(message)
        error = caught.value
        assert (error.field, error.offset, error.expected) == (
            "mode",
            0,
            "0-5",
        )
        assert error.actual == message[0] & 7

    @pytest.mark.parametrize(
        "message", CONTROL_MESSAGES.values(), ids=list(CONTROL_MESSAGES)
    )
    def test_a_strict_walk_raises_on_a_control_message(self, message):
        """Port 123 dispatches ntpq's traffic to NTP, which rejects it
        for its mode, at the NTP header, not for its length."""
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(udp_frame(message))
        error = caught.value
        assert (error.field, error.frame_offset) == ("mode", NTP_START)

    @pytest.mark.parametrize(
        "message", CONTROL_MESSAGES.values(), ids=list(CONTROL_MESSAGES)
    )
    def test_a_lax_walk_stops_at_udp(self, message):
        """lax=True keeps Ethernet, IPv4 and UDP and says why it stopped."""
        packet = decode_frame(udp_frame(message), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, InvalidFieldError)
        assert packet.stopped_by.field == "mode"
        assert packet.stopped_by.frame_offset == NTP_START

    @pytest.mark.parametrize(
        "message", CONTROL_MESSAGES.values(), ids=list(CONTROL_MESSAGES)
    )
    def test_decode_as_none_takes_port_123_out(self, message):
        """decode_as={"udp.port": {123: None}} ends a strict walk at UDP.

        The registry accepts None at run time, though decode_as is
        annotated with classes only; the module docstring says so.
        """
        packet = decode_frame(
            udp_frame(message),
            decode_as={"udp.port": {123: None}},  # type: ignore[dict-item]
        )
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert packet.stopped_by is None

    def test_the_first_byte_is_judged_before_the_length(self):
        """Version, then mode, then length, whatever the length."""
        with pytest.raises(InvalidFieldError) as caught:
            NTP.decode(bytes([0x3E]))  # version 7, mode 6
        assert (caught.value.field, caught.value.actual) == ("version", 7)
        with pytest.raises(InvalidFieldError) as caught:
            NTP.decode(bytes([0x07]) + bytes(60))  # version 0, mode 7
        assert caught.value.field == "version"
        with pytest.raises(InvalidFieldError) as caught:
            NTP.decode(bytes([0x27]))  # version 4, mode 7
        assert (caught.value.field, caught.value.actual) == ("mode", 7)

    @pytest.mark.parametrize("first", [0x23, 0x24, 0x1B, 0x20, 0x08])
    def test_a_short_time_message_is_truncated(self, first):
        """A first byte that passes, and fewer than 48 bytes."""
        for length in (1, 12, 47):
            with pytest.raises(TruncatedHeaderError) as caught:
                NTP.decode(bytes([first]) + bytes(length - 1))
            error = caught.value
            assert (error.offset, error.expected) == (0, 48)
            assert error.actual == length

    def test_an_empty_buffer_is_truncated(self):
        """No first byte to judge."""
        with pytest.raises(TruncatedHeaderError) as caught:
            NTP.decode(b"")
        assert (caught.value.expected, caught.value.actual) == (48, 0)

    def test_mode_0_decodes(self):
        """Mode 0 is reserved, not a control message."""
        assert NTP.decode(bytes([0x20]) + bytes(47)).mode_name == "reserved"

    def test_exactly_96_of_the_256_first_bytes_pass(self):
        """4 Leap Indicators x 4 versions x 6 modes, so a random
        datagram on port 123 is rejected 62.5% of the time."""
        passed = 0
        for first in range(256):
            try:
                NTP.decode(bytes([first]) + bytes(47))
            except InvalidFieldError:
                continue
            passed += 1
        assert passed == 96

    def test_a_rejected_guess_is_reported_at_the_ntp_header(self):
        """A lax walk keeps the layers below, and says where it stopped."""
        frame = bytearray(FRAMES[SNTP[0]])
        frame[NTP_START] = 0x26  # mode 6
        packet = decode_frame(bytes(frame), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, InvalidFieldError)
        assert packet.stopped_by.frame_offset == NTP_START

    @pytest.mark.parametrize(
        "stratum,name",
        [
            (0, "unspecified or invalid"),
            (1, "primary server"),
            (15, "secondary server"),
            (16, "unsynchronized"),
            (17, "reserved"),
            (255, "reserved"),
        ],
    )
    def test_every_stratum_decodes(self, stratum, name):
        """Figure 11's strata, the reserved ones included, decode."""
        ntp = NTP.decode(header(0x24, stratum=stratum))
        assert (ntp.stratum, ntp.stratum_name) == (stratum, name)


class TestDisplay:
    @pytest.mark.parametrize(
        "leap,name",
        [
            (0, "no warning"),
            (1, "last minute of the day has 61 seconds"),
            (2, "last minute of the day has 59 seconds"),
            (3, "unknown (clock unsynchronized)"),
        ],
    )
    def test_leap_names(self, leap, name):
        """RFC 5905 Figure 9."""
        assert NTP(leap, 4, 4).leap_name == name

    def test_mode_names(self):
        """RFC 5905 Figure 10, the two modes decode rejects included."""
        assert [NTP(0, 4, mode).mode_name for mode in range(8)] == [
            "reserved",
            "symmetric active",
            "symmetric passive",
            "client",
            "server",
            "broadcast",
            "NTP control message",
            "reserved for private use",
        ]

    @pytest.mark.parametrize("code", ["RATE", "DENY", "RSTR", "NTSN"])
    def test_a_kiss_o_death(self, code):
        """Stratum 0 carries a kiss code in the Reference ID (§7.4)."""
        refid = int.from_bytes(code.encode(), "big")
        ntp = NTP.decode(header(0x24, reference_id=refid))
        assert (ntp.kiss_code, ntp.reference_id_str) == (code, code)

    def test_a_reference_clock_at_stratum_1(self):
        """Stratum 1 names a reference clock, NUL-padded ASCII."""
        refid = int.from_bytes(b"GPS\x00", "big")
        ntp = NTP.decode(header(0x24, stratum=1, reference_id=refid))
        assert (ntp.reference_id_str, ntp.kiss_code) == ("GPS", None)

    def test_an_unprintable_reference_id_below_stratum_2(self):
        """Neither a kiss code nor a name: shown in hex."""
        ntp = NTP.decode(header(0x24, stratum=1, reference_id=LOCAL_REFID))
        assert ntp.reference_id_str == "0x7f7f0101"
        stratum_0 = NTP.decode(header(0x24, reference_id=0x01020304))
        assert (stratum_0.kiss_code, stratum_0.reference_id_str) == (
            None,
            "0x01020304",
        )

    def test_an_address_from_stratum_2(self):
        """From stratum 2 the Reference ID is an IPv4 address (or an
        IPv6 address's hash), whatever its bytes spell."""
        refid = int.from_bytes(b"INIT", "big")
        ntp = NTP.decode(header(0x24, stratum=16, reference_id=refid))
        assert ntp.reference_id_str == "73.78.73.84"
        assert ntp.kiss_code is None

    @pytest.mark.parametrize(
        "version,seconds",
        [(1, -1.0), (2, -1.0), (3, -1.0), (4, 65535.0)],
    )
    def test_root_delay_is_signed_below_version_4(self, version, seconds):
        """RFC 1305 and RFC 2030: a signed 16.16 Root Delay; RFC 5905's
        short format for NTPv4 is unsigned. The raw field is the same."""
        ntp = NTP(0, version, 4, root_delay=0xFFFF0000)
        assert ntp.root_delay == 0xFFFF0000
        assert ntp.root_delay_seconds == seconds
        decoded = NTP.decode(bytes(ntp))
        assert (decoded.root_delay, decoded.root_delay_seconds) == (
            0xFFFF0000,
            seconds,
        )

    @pytest.mark.parametrize("version", [3, 4])
    def test_root_delay_signs_agree_below_the_top_bit(self, version):
        """Below 0x80000000 both readings give the same seconds."""
        ntp = NTP(0, version, 4, root_delay=0x7FFF8000)
        assert ntp.root_delay_seconds == 32767.5

    def test_the_smallest_negative_ntpv3_root_delay(self):
        """0x80000000 is -32768 seconds signed."""
        assert NTP(0, 3, 4, root_delay=0x80000000).root_delay_seconds == (
            -32768.0
        )

    def test_root_dispersion_is_unsigned_in_every_version(self):
        """No version lets the dispersion go negative."""
        for version in (1, 2, 3, 4):
            ntp = NTP(0, version, 4, root_dispersion=0xFFFF0000)
            assert ntp.root_dispersion_seconds == 65535.0

    def test_short_format_and_log2_seconds(self):
        """Root Delay and Dispersion are 16.16; Poll and Precision log2."""
        ntp = NTP(
            0,
            4,
            4,
            poll=-6,
            precision=-20,
            root_delay=0x00018000,
            root_dispersion=0xFFFFFFFF,
        )
        assert (ntp.poll_seconds, ntp.precision_seconds) == (2**-6, 2**-20)
        assert ntp.root_delay_seconds == 1.5
        assert ntp.root_dispersion_seconds == 0xFFFFFFFF / 65536

    def test_extension_field_names(self):
        """IANA's names as RFC 9748 left them; anything else in hex."""
        assert NTPExtensionField(0x0304).type_name == "NTS Cookie Placeholder"
        assert NTPExtensionField(0x2005).type_name == "UDP Checksum Complement"
        assert NTPExtensionField(0x0002).type_name == "unknown (0x0002)"
        assert NTPExtensionField(0xEFFF).type_name == "unknown (0xefff)"

    @pytest.mark.parametrize("field_type", [0xF000, 0xF323, 0xFFFF])
    def test_the_experimental_range_is_named(self, field_type):
        """RFC 9748 reserves 0xF000-0xFFFF for Private or Experimental
        Use; IANA cannot assign them."""
        assert NTPExtensionField(field_type).type_name == (
            f"Private or Experimental Use ({field_type:#06x})"
        )


class TestConstruction:
    def test_build_a_client_request(self):
        """A request built from fields decodes back to itself."""
        ntp = NTP(
            leap=3,
            version=4,
            mode=3,
            transmit_timestamp=0xEE90302594864000,
            body=bytes(NTPMAC(1, bytes(16))),
        )
        raw = bytes(ntp)
        assert raw[:1] == b"\xe3"
        assert len(raw) == 68
        assert NTP.decode(raw) == ntp
        assert ntp.transmit_time == ntp_of(SNTP[0]).transmit_time

    @pytest.mark.parametrize(
        "name,value,expected",
        [
            ("leap", 4, "0-3"),
            ("version", 8, "0-7"),
            ("mode", -1, "0-7"),
            ("stratum", 256, "0-255"),
            ("poll", 128, "-128-127"),
            ("precision", -129, "-128-127"),
            ("root_delay", 1 << 32, "0-4294967295"),
            ("reference_id", -1, "0-4294967295"),
            ("transmit_timestamp", 1 << 64, f"0-{(1 << 64) - 1}"),
        ],
    )
    def test_out_of_range_fields(self, name, value, expected):
        """A field too wide for its bits is refused."""
        with pytest.raises(InvalidFieldError) as caught:
            replace(NTP(0, 4, 3), **{name: value})
        assert (caught.value.field, caught.value.expected) == (name, expected)

    def test_what_decode_rejects_still_builds(self):
        """Construction accepts a version and a mode decode rejects."""
        for ntp in (NTP(0, 0, 3), NTP(0, 4, 6)):
            assert len(bytes(ntp)) == 48
            with pytest.raises(InvalidFieldError):
                NTP.decode(bytes(ntp))

    def test_the_widest_values_round_trip(self):
        """Every field's widest value builds and round-trips."""
        top = (1 << 64) - 1
        ntp = NTP(
            3,
            4,
            5,
            255,
            -128,
            127,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            top,
            top,
            top,
            top,
        )
        assert NTP.decode(bytes(ntp)) == ntp

    def test_extension_fields_and_macs(self):
        """Their wire forms, and the widths they check."""
        assert bytes(NTPExtensionField(0x0104, b"\x01" * 12)) == (
            b"\x01\x04\x00\x10" + b"\x01" * 12
        )
        with pytest.raises(InvalidFieldError) as caught:
            NTPExtensionField(0x10000)
        assert caught.value.field == "type"
        with pytest.raises(InvalidFieldError) as caught:
            NTPExtensionField(1, bytes(0xFFFC))
        assert caught.value.field == "value"
        assert bytes(NTPMAC(2, b"\x02" * 20)) == b"\x00\x00\x00\x02" + (
            b"\x02" * 20
        )
        with pytest.raises(InvalidFieldError) as caught:
            NTPMAC(1 << 32)
        assert caught.value.field == "key_id"

    def test_positional_patterns_follow_wire_order(self):
        """Positional patterns bind the header fields in wire order."""
        match NTP.decode(message_bytes(SNTP[1])):
            case NTP(0, 4, 4, 8, 0, -25, 0, 0, refid):
                assert refid == LOCAL_REFID
            case _:
                pytest.fail("positional pattern did not match")


class TestDispatch:
    def test_registered_on_port_123(self):
        """The default registry maps UDP port 123 to NTP."""
        assert DEFAULT.get(TABLE_UDP_PORT, 123) is NTP

    @pytest.mark.parametrize(
        "src_port,dst_port", [(40000, 123), (123, 40000), (123, 123)]
    )
    def test_either_port(self, src_port, dst_port):
        """A client sends to 123 and hears back from it; symmetric peers
        and broadcast servers send from 123 to 123."""
        udp = UDP(src_port=src_port, dst_port=dst_port, length=0, checksum=0)
        assert udp.next_protocol() is NTP

    def test_ntp_ends_the_chain(self):
        """NTP carries no further protocol."""
        assert ntp_of(NTS[0]).next_protocol() is None

    def test_decode_as_can_take_the_port_away(self):
        """Let a caller decode port 123 as something else for one walk.

        It is best-effort, like every port entry.
        """
        packet = decode_frame(FRAMES[0], decode_as={"udp.port": {123: DNS}})
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP, DNS]
