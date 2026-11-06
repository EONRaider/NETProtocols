"""Test NTP control message (mode 6, RFC 9327) decoding and dispatch.

Covered: the 12-byte header and its R, E and M bits, the opcode,
error and system status names, the data and its padding, where the
MAC is looked for and when it is found, truncation at every field,
the ``name=value`` splitter, and how UDP port 123 chooses between
``NTP`` and ``NTPControl`` by the first byte.

The cases ntpq and ntpd do not send are built here. The ntpq and ntpd
exchanges in tests/fixtures/ntp_control.pcap (see its MANIFEST note)
anchor the decode, round-trip and MAC asserts: each field is checked
against an independent ``struct`` read of the frame and against what
ntpq printed during the capture.
"""

import hashlib
import hmac
import struct
from dataclasses import replace

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    NTP,
    NTPMAC,
    UDP,
    Ethernet,
    InvalidFieldError,
    IPv4,
    NTPControl,
    NTPSystemStatus,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_UDP_PORT

TIME_FRAMES = pcap_frames(FIXTURES / "ntp.pcap")

#: Ethernet + a 20-byte IPv4 header + UDP, in front of every message.
START = 14 + 20 + 8


def reference(message: bytes) -> dict[str, object]:
    """Read the header of ``message`` with ``struct`` alone."""
    flags, bits, seq, status, assoc, offset, count = struct.unpack_from(
        "!BBHHHHH", message
    )
    return {
        "leap": flags >> 6,
        "version": (flags >> 3) & 7,
        "mode": flags & 7,
        "response": bool(bits & 0x80),
        "error": bool(bits & 0x40),
        "more": bool(bits & 0x20),
        "opcode": bits & 0x1F,
        "sequence": seq,
        "status": status,
        "association_id": assoc,
        "offset": offset,
        "count": count,
        "data": message[12 : 12 + count],
    }


def udp_frame(payload: bytes, src_port: int = 40000, dst_port: int = 123):
    """``payload`` in a UDP datagram behind the Ethernet and IPv4
    headers of the first frame of ntp.pcap, padded to Ethernet's 60-byte
    minimum as a NIC would pad it."""
    ip = bytearray(TIME_FRAMES[0][14:34])
    ip[2:4] = (20 + 8 + len(payload)).to_bytes(2, "big")
    ip[10:12] = bytes(2)
    udp = bytes(
        UDP(
            src_port=src_port,
            dst_port=dst_port,
            length=8 + len(payload),
            checksum=0,
        )
    )
    frame = TIME_FRAMES[0][:14] + bytes(ip) + udp + payload
    return frame + bytes(max(0, 60 - len(frame)))


def control(**fields: object) -> bytes:
    """A version 2 control message with ``fields`` set, serialized."""
    return bytes(NTPControl(**fields))  # type: ignore[arg-type]


#: A read variables request for the system variables as ntpq sends it:
#: version 2, Leap Indicator 3, sequence 1, no data.
READ_REQUEST = bytes.fromhex("d60200010000000000000000")

#: A read variables response with 345 bytes of variables, padded to 348.
READ_RESPONSE = control(
    leap=3,
    response=True,
    opcode=2,
    sequence=1,
    status=0xC016,
    data=b"a=1," * 86 + b"b",
    padding=bytes(3),
)

#: A runtime configuration request with an MD5 MAC after the data
#: padded to 8 bytes.
MAC_REQUEST = control(
    leap=3,
    opcode=8,
    sequence=1,
    data=b"logconfig =syncall",
    padding=bytes(2),
    mac=NTPMAC(3, b"\xab" * 16),
)


class TestNames:
    @pytest.mark.parametrize(
        "opcode,name",
        [
            (0, "reserved (0)"),
            (1, "read status"),
            (2, "read variables"),
            (3, "write variables"),
            (4, "read clock variables"),
            (5, "write clock variables"),
            (6, "set trap address/port"),
            (7, "trap response"),
            (8, "runtime configuration"),
            (9, "export configuration to file"),
            (10, "retrieve remote address stats"),
            (11, "retrieve ordered list"),
            (12, "request client-specific nonce"),
            (31, "unset trap address/port"),
        ],
    )
    def test_opcode_names(self, opcode, name):
        assert NTPControl(opcode=opcode).opcode_name == name

    @pytest.mark.parametrize("opcode", range(13, 31))
    def test_reserved_opcodes(self, opcode):
        assert NTPControl(opcode=opcode).opcode_name == f"reserved ({opcode})"

    @pytest.mark.parametrize(
        "code,name",
        [
            (0, "unspecified"),
            (1, "authentication failure"),
            (2, "invalid message length or format"),
            (3, "invalid opcode"),
            (4, "unknown Association ID"),
            (5, "unknown variable name"),
            (6, "invalid variable value"),
            (7, "administratively prohibited"),
            (8, "reserved (8)"),
            (255, "reserved (255)"),
        ],
    )
    def test_error_names(self, code, name):
        message = NTPControl(response=True, error=True, status=code << 8)
        assert (message.error_code, message.error_name) == (code, name)

    @pytest.mark.parametrize(
        "response,error", [(False, False), (True, False), (False, True)]
    )
    def test_only_an_error_response_has_an_error_code(self, response, error):
        message = NTPControl(response=response, error=error, status=0x0500)
        assert (message.error_code, message.error_name) == (None, None)

    def test_system_status_words(self):
        status = NTPSystemStatus.from_word(0x0615)
        assert status == NTPSystemStatus(0, 6, 1, 5)
        assert status.leap_name == "no warning"
        assert status.clock_source_name == "UDP/NTP"
        assert status.event_name == "clock synchronized"
        assert NTPSystemStatus(0, 10, 0, 0).clock_source_name == (
            "reserved (10)"
        )
        assert NTPSystemStatus(0, 63, 15, 15).event_name == (
            "leapseconds table outdated, updated file needed"
        )

    @pytest.mark.parametrize(
        "fields",
        [
            {"response": False},
            {"error": True},
            {"association_id": 1},
            *(
                {"opcode": opcode}
                for opcode in (0, *range(4, 7), *range(8, 32))
            ),
        ],
    )
    def test_where_there_is_no_system_status_word(self, fields):
        """Only a response, not an error, to association 0, for read
        status, read variables, write variables or a trap response
        (RFC 9327 §3.1 and §4)."""
        base = {"response": True, "opcode": 2, "status": 0xC016}
        assert NTPControl(**{**base, **fields}).system_status is None

    @pytest.mark.parametrize("opcode", [1, 2, 3, 7])
    def test_where_there_is_a_system_status_word(self, opcode):
        message = NTPControl(response=True, opcode=opcode, status=0xC016)
        assert message.system_status == NTPSystemStatus(3, 0, 1, 6)

    def test_a_system_trap_carries_a_system_status_word(self):
        """Hand-built, as the capture holds no trap: a trap response
        (opcode 7) for association 0, a system trap, whose Status is
        the system status word 0x0615 (RFC 9327 §4)."""
        raw = bytes.fromhex("168700050615000000000000")
        message = NTPControl.decode(raw)
        assert (message.response, message.error) == (True, False)
        assert (message.opcode, message.association_id) == (7, 0)
        assert message.opcode_name == "trap response"
        assert message.system_status == NTPSystemStatus(0, 6, 1, 5)
        assert bytes(message) == raw

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param("168700050615000300000000", id="peer-trap"),
            pytest.param("16c700050615000000000000", id="error"),
        ],
    )
    def test_a_trap_with_no_system_status_word(self, raw):
        """Hand-built, as the capture holds no trap: a trap response for
        association 3, a peer trap, and an error response to opcode 7
        carry no system status word (RFC 9327 §3.4 and §4)."""
        message = NTPControl.decode(bytes.fromhex(raw))
        assert message.opcode == 7
        assert message.system_status is None

    @pytest.mark.parametrize(
        "name,value,high",
        [
            ("leap", 4, 3),
            ("clock_source", 64, 0x3F),
            ("event_count", 16, 0x0F),
            ("event_code", -1, 0x0F),
        ],
    )
    def test_system_status_fields_fit(self, name, value, high):
        fields = {
            "leap": 0,
            "clock_source": 0,
            "event_count": 0,
            "event_code": 0,
        }
        with pytest.raises(InvalidFieldError) as caught:
            NTPSystemStatus(**{**fields, name: value})
        assert (caught.value.field, caught.value.expected) == (
            name,
            f"0-{high}",
        )


class TestVariables:
    def test_quoted_commas_and_white_space(self):
        message = NTPControl(
            data=b' a=1, b="x, y" ,c,, d = 2 ,\r\n=e,"q"=3\r\n'
        )
        assert message.variables == (
            ("a", "1"),
            ("b", '"x, y"'),
            ("c", None),
            ("d", "2"),
            ("", "e"),
            ('"q"', "3"),
        )

    def test_only_the_first_equals_sign_splits(self):
        assert NTPControl(data=b"a==b=c").variables == (("a", "=b=c"),)

    def test_an_unclosed_quote_runs_to_the_end(self):
        assert NTPControl(data=b'a="b, c').variables == (("a", '"b, c'),)

    @pytest.mark.parametrize("data", [b"", b",", b" , \r\n, "])
    def test_nothing_to_split(self, data):
        assert NTPControl(data=data).variables == ()

    def test_bytes_that_are_not_ascii(self):
        assert NTPControl(data=b"a=\xff\x00").variables == (("a", "�\x00"),)

    def test_binary_data_never_raises(self):
        """A read status response's association list, and every byte
        value, split into something."""
        data = struct.pack("!4H", 17768, 0x8011, 17767, 0x9014)
        assert NTPControl(data=data).variables
        assert NTPControl(data=bytes(range(256))).variables


class TestAfterTheData:
    def test_a_mac_after_8_byte_padding(self):
        """Data ending 1 byte past a multiple of 4 and of 8: 7 bytes of
        padding, then the MAC."""
        raw = control(opcode=8, data=b"x" * 5) + bytes(7)
        raw += bytes(NTPMAC(3, b"\xab" * 16))
        message = NTPControl.decode(raw)
        assert (message.count, len(message.padding)) == (5, 7)
        assert message.mac == NTPMAC(3, b"\xab" * 16)
        assert bytes(message) == raw

    def test_the_4_byte_end_is_not_where_a_mac_starts(self):
        """With the data ending on a multiple of 4 and not of 8, a
        request's MAC starts 4 bytes later: a SHA-1 MAC right after the
        header is read as 4 bytes of padding and an MD5 MAC."""
        raw = control() + bytes(NTPMAC(4, b"\xab" * 20))
        message = NTPControl.decode(raw)
        assert message.mac == NTPMAC(0xABABABAB, b"\xab" * 16)
        assert message.padding == b"\x00\x00\x00\x04"
        assert bytes(message) == raw

    @pytest.mark.parametrize("digest_len", [16, 20])
    def test_a_mac_on_a_4_byte_boundary_is_not_recognised(self, digest_len):
        """Hand-built, as ntpd and ntpsec do not send it: a read
        variables response with 8 bytes of data, so the data ends at
        20, and a MAC right there, on a multiple of 4 and not of 8. A
        SHA-1 MAC reads as its Key ID for padding and a 20-byte MAC
        from its digest; an MD5 MAC as remainder."""
        mac = bytes(NTPMAC(7, bytes(range(digest_len))))
        raw = control(response=True, opcode=2, data=b"abcdefgh") + mac
        message = NTPControl.decode(raw)
        if digest_len == 20:
            assert message.padding == mac[:4]
            assert message.mac == NTPMAC(0x00010203, mac[8:])
            assert message.remainder == b""
        else:
            assert (message.padding, message.mac) == (b"", None)
            assert message.remainder == mac
        assert bytes(message) == raw

    def test_an_error_responses_mac_follows_its_header(self):
        raw = control(response=True, error=True, status=0x0100)
        raw += bytes(NTPMAC(3, b"\xcd" * 16))
        message = NTPControl.decode(raw)
        assert (message.padding, message.mac) == (b"", NTPMAC(3, b"\xcd" * 16))

    def test_an_error_responses_mac_follows_its_data_padded_to_4(self):
        raw = control(response=True, error=True, status=0x0100, data=b"x")
        raw += bytes(3) + bytes(NTPMAC(3, b"\xcd" * 16))
        message = NTPControl.decode(raw)
        assert message.padding == bytes(3)
        assert message.mac == NTPMAC(3, b"\xcd" * 16)

    @pytest.mark.parametrize("tail_len", [4, 8, 16, 19, 21, 28])
    def test_a_tail_of_no_macs_length_is_a_remainder(self, tail_len):
        raw = control(data=b"abcd") + b"\xee" * tail_len
        message = NTPControl.decode(raw)
        assert (message.padding, message.mac) == (b"", None)
        assert message.remainder == b"\xee" * tail_len
        assert bytes(message) == raw

    def test_short_padding_is_kept(self):
        """A message the datagram ends before its padding does."""
        raw = control(data=b"abcde")
        message = NTPControl.decode(raw + b"\x00")
        assert (message.padding, message.remainder) == (b"\x00", b"")

    def test_no_padding_when_the_data_is_aligned(self):
        message = NTPControl.decode(control(data=b"abcd"))
        assert (message.padding, message.mac, message.remainder) == (
            b"",
            None,
            b"",
        )

    def test_memoryview_input_is_not_retained(self):
        buffer = bytearray(MAC_REQUEST)
        message = NTPControl.decode(memoryview(buffer))
        buffer[:] = bytes(len(buffer))
        assert bytes(message) == MAC_REQUEST


class TestTruncation:
    @pytest.mark.parametrize("length", range(1, 12))
    def test_every_cut_of_the_header(self, length):
        """Every field of the 12-byte header, cut."""
        with pytest.raises(TruncatedHeaderError) as caught:
            NTPControl.decode(READ_REQUEST[:length])
        error = caught.value
        assert (error.offset, error.expected, error.actual) == (0, 12, length)

    def test_an_empty_buffer(self):
        with pytest.raises(TruncatedHeaderError) as caught:
            NTPControl.decode(b"")
        assert (caught.value.expected, caught.value.actual) == (12, 0)

    def test_every_cut_of_the_data(self):
        """A Count that runs past the buffer, by any amount."""
        raw = READ_RESPONSE
        for length in range(12, 12 + 345):
            with pytest.raises(TruncatedHeaderError) as caught:
                NTPControl.decode(raw[:length])
            error = caught.value
            assert (error.field, error.offset) == ("data", 12)
            assert (error.expected, error.actual) == (12 + 345, length)

    def test_a_cut_after_the_data_decodes(self):
        raw = READ_RESPONSE
        message = NTPControl.decode(raw[: 12 + 345])
        assert (message.count, message.padding) == (345, b"")

    def test_a_count_past_the_datagram_in_a_walk(self):
        """The walk ends the buffer at UDP's Length, so a Count past
        the datagram is not read into the frame's padding."""
        raw = control(data=b"abcd")
        lying = raw[:10] + struct.pack("!H", 20) + raw[12:]
        with pytest.raises(TruncatedHeaderError) as caught:
            decode_frame(udp_frame(lying))
        error = caught.value
        assert (error.field, error.frame_offset) == ("data", START + 12)
        packet = decode_frame(udp_frame(lying), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]

    @pytest.mark.parametrize("count", [469, 0xFFFF])
    def test_a_count_above_468(self, count):
        raw = bytes.fromhex("d602000100000000") + bytes(2)
        raw += struct.pack("!H", count) + bytes(count)
        with pytest.raises(InvalidFieldError) as caught:
            NTPControl.decode(raw)
        error = caught.value
        assert (error.field, error.offset, error.actual) == (
            "count",
            10,
            count,
        )

    @pytest.mark.parametrize("version", [0, 5, 7])
    def test_a_version_outside_1_to_4(self, version):
        with pytest.raises(InvalidFieldError) as caught:
            NTPControl.decode(bytes([version << 3 | 6]))
        assert (caught.value.field, caught.value.offset) == ("version", 0)

    @pytest.mark.parametrize("mode", [0, 3, 4, 7])
    def test_any_mode_but_6(self, mode):
        """Judged before the length."""
        with pytest.raises(InvalidFieldError) as caught:
            NTPControl.decode(bytes([0x10 | mode]))
        error = caught.value
        assert (error.field, error.offset, error.actual) == ("mode", 0, mode)

    def test_the_first_byte_before_the_count(self):
        raw = bytearray(READ_REQUEST)
        raw[10:12] = b"\xff\xff"
        raw[0] = 0x14  # version 2, mode 4
        with pytest.raises(InvalidFieldError) as caught:
            NTPControl.decode(bytes(raw))
        assert caught.value.field == "mode"


class TestConstruction:
    @pytest.mark.parametrize("bit", ["response", "error", "more"])
    def test_each_flag_bit(self, bit):
        message = NTPControl(**{bit: True})
        decoded = NTPControl.decode(bytes(message))
        assert decoded == message
        flags = {"response": 0x80, "error": 0x40, "more": 0x20}
        assert bytes(message)[1] == flags[bit]

    @pytest.mark.parametrize(
        "name,value",
        [
            ("leap", 4),
            ("version", 8),
            ("opcode", 32),
            ("sequence", 0x10000),
            ("status", -1),
            ("association_id", 0x10000),
            ("offset", -1),
        ],
    )
    def test_out_of_range_fields(self, name, value):
        with pytest.raises(InvalidFieldError) as caught:
            NTPControl(**{name: value})
        assert caught.value.field == name

    def test_data_beyond_its_count(self):
        with pytest.raises(InvalidFieldError) as caught:
            NTPControl(data=bytes(0x10000))
        assert caught.value.field == "data"

    def test_what_decode_rejects_still_builds(self):
        """A version 0 message, or 469 bytes of data, builds; decode
        rejects it."""
        for message in (NTPControl(version=0), NTPControl(data=bytes(469))):
            with pytest.raises(InvalidFieldError):
                NTPControl.decode(bytes(message))

    def test_ntp_control_ends_the_chain(self):
        assert NTPControl.decode(READ_RESPONSE).next_protocol() is None


class TestDispatch:
    def test_port_123_still_names_ntp(self):
        assert DEFAULT.get(TABLE_UDP_PORT, 123) is NTP

    def test_time_messages_still_reach_ntp(self):
        """Every frame of ntp.pcap (modes 1-5) decodes as before."""
        for frame in TIME_FRAMES:
            packet = decode_frame(frame)
            assert type(packet[-1]) is NTP
            assert bytes(packet[NTP]) == frame[START:]
            assert packet[NTP] == NTP.decode(frame[START:])

    @pytest.mark.parametrize(
        "src_port,dst_port", [(40000, 123), (123, 40000), (123, 123)]
    )
    def test_mode_6_reaches_ntp_control(self, src_port, dst_port):
        frame = udp_frame(READ_REQUEST, src_port, dst_port)
        udp = decode_frame(frame)[UDP]
        assert udp.next_protocol() is NTPControl
        assert type(decode_frame(frame)[-1]) is NTPControl

    def test_mode_7_is_refused(self):
        frame = udp_frame(bytes.fromhex("17000310") + bytes(44))
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(frame)
        error = caught.value
        assert (error.protocol, error.field) == (NTP, "mode")

    def test_ntp_refuses_mode_6_called_directly(self):
        with pytest.raises(InvalidFieldError, match="NTPControl") as caught:
            NTP.decode(READ_REQUEST)
        assert (caught.value.field, caught.value.actual) == ("mode", 6)

    @pytest.mark.parametrize("first", range(256))
    def test_the_first_byte_chooses(self, first):
        expected = NTPControl if first & 7 == 6 else NTP
        assert NTP._for_payload(first) is expected

    def test_a_built_udp_header_has_seen_no_payload(self):
        udp = UDP(src_port=40000, dst_port=123, length=20, checksum=0)
        assert udp.next_protocol() is NTP

    def test_an_empty_datagram_has_no_first_byte(self):
        """A UDP Length of 8 says the payload is empty, so the padding
        after it is not read as a first byte."""
        frame = udp_frame(b"")
        padded = frame[:START] + b"\x26" + frame[START + 1 :]
        assert UDP.decode(padded[34:])._lead is None
        assert UDP.decode(padded[34:]).next_protocol() is NTP

    def test_the_first_byte_is_not_compared(self):
        decoded = decode_frame(udp_frame(READ_REQUEST))[UDP]
        assert decoded._lead == 0xD6
        built = replace(decoded)
        assert built._lead is None
        assert built == decoded
        assert hash(built) == hash(decoded)

    def test_decode_as_reaches_ntp_control_through_ntp(self):
        """A caller who names NTP for another port gets the same choice."""
        frame = udp_frame(READ_RESPONSE, 123, 9999)
        frame = frame[:34] + struct.pack("!H", 40001) + frame[36:]
        packet = decode_frame(frame, decode_as={"udp.port": {9999: NTP}})
        assert type(packet[-1]) is NTPControl

    def test_decode_as_ntp_control_refuses_a_time_message(self):
        with pytest.raises(InvalidFieldError) as caught:
            decode_frame(
                TIME_FRAMES[0], decode_as={"udp.port": {123: NTPControl}}
            )
        assert (caught.value.protocol, caught.value.field) == (
            NTPControl,
            "mode",
        )


FRAMES = pcap_frames(FIXTURES / "ntp_control.pcap")

#: The fixture's frames, in the order the capture script keeps them.
RV = (0, 1)
AS = (2, 3)
VERSION = (4, 5, 6, 7)
UNKNOWN = (8, 9, 10, 11)
PEER = (12, 13, 14, 15, 16)
MD5 = (17, 18)
SHA1 = (19, 20)
REQUESTS = [0, 2, 4, 6, 8, 10, 12, 14, 17, 19]

#: The test keys ntpd and ntpq were configured with, published in
#: MANIFEST.md, by Key ID.
KEYS = {3: ("md5", b"np272-md5-key"), 4: ("sha1", b"np272-sha1-key")}

#: What ntpq printed during the capture, for the values a decoded
#: message carries: the system status word of "rv", the association
#: IDs and peer status words of "as", the variable of "rv 0 version",
#: and the association ID and status word of "rv &1".
NTPQ_SYSTEM_STATUS = 0xC016
NTPQ_ASSOCIATIONS = [(17767, 0x9014), (17768, 0x8011)]
NTPQ_VERSION = 'version="ntpd ntpsec-1.2.2"'
NTPQ_PEER = (17767, 0x9014)


def message_bytes(index: int) -> bytes:
    """Return the control message of capture frame ``index``, exactly."""
    return FRAMES[index][START:]


def control_of(index: int) -> NTPControl:
    layer = decode_frame(FRAMES[index])[NTPControl]
    assert isinstance(layer, NTPControl)
    return layer


class TestCapturedMessages:
    def test_every_frame_walks_to_ntp_control_and_ends_there(self):
        for frame in FRAMES:
            packet = decode_frame(frame)
            assert [type(layer) for layer in packet] == [
                Ethernet,
                IPv4,
                UDP,
                NTPControl,
            ]
            assert packet.stopped_by is None
            assert packet.consumed == len(frame)

    def test_every_message_round_trips_exactly(self):
        for index in range(len(FRAMES)):
            message = message_bytes(index)
            control_message = NTPControl.decode(message)
            assert bytes(control_message) == message
            assert control_message.header_len == len(message)
            assert NTPControl.decode(bytes(control_message)) == control_message

    @pytest.mark.parametrize("index", range(21))
    def test_every_field_matches_an_independent_read(self, index):
        message = control_of(index)
        expected = reference(message_bytes(index))
        assert expected.pop("mode") == message.mode == 6
        for name, value in expected.items():
            assert getattr(message, name) == value, name

    def test_ntpq_and_ntpd_flags(self):
        """ntpq sends version 2 with Leap Indicator 3, and the server,
        unsynchronized, answers with the same."""
        for index in range(len(FRAMES)):
            message = control_of(index)
            assert (message.leap, message.version) == (3, 2)
            assert message.leap_name == "unknown (clock unsynchronized)"
            assert message.response is (index not in REQUESTS)

    def test_every_response_repeats_its_sequence_number(self):
        exchanges = [RV, AS, VERSION[:2], VERSION[2:], UNKNOWN[:2]]
        exchanges += [UNKNOWN[2:], PEER[:2], PEER[2:], MD5, SHA1]
        for request, *responses in exchanges:
            for response in responses:
                assert (
                    control_of(response).sequence
                    == control_of(request).sequence
                )

    def test_the_opcodes(self):
        names = [control_of(index).opcode_name for index in range(21)]
        assert names[:2] == ["read variables"] * 2
        assert names[2:6] == ["read status"] * 4
        assert names[17:] == ["runtime configuration"] * 4

    def test_the_system_status_word_ntpq_showed(self):
        """ntpq printed "status=c016 leap_alarm, sync_unspec, 1 event,
        restart" for the "rv" response's Status."""
        message = control_of(RV[1])
        assert message.status == NTPQ_SYSTEM_STATUS
        assert message.system_status == NTPSystemStatus(3, 0, 1, 6)
        status = message.system_status
        assert status.leap_name == "unknown (clock unsynchronized)"
        assert status.clock_source_name == "unspecified or unknown"
        assert status.event_name == "system restart"

    def test_every_captured_rv_and_as_response_has_ntpqs_status(self):
        """The responses to read variables and read status for
        association 0 carry the system status word ntpq printed."""
        for index in (
            RV[1],
            AS[1],
            VERSION[1],
            VERSION[3],
            UNKNOWN[1],
            PEER[1],
        ):
            message = control_of(index)
            assert message.opcode in (1, 2)
            assert message.system_status == NTPSystemStatus(3, 0, 1, 6)

    def test_a_configuration_response_has_no_system_status_word(self):
        """Capture frame 19, the ":config" response, has Status 0x0000
        at association 0, which is not a system status word."""
        message = control_of(MD5[1])
        assert (message.response, message.error) == (True, False)
        assert (message.association_id, message.status) == (0, 0)
        assert message.opcode_name == "runtime configuration"
        assert message.system_status is None

    def test_the_association_list_ntpq_showed(self):
        """The read status response's data is the association IDs and
        peer status words ntpq listed, newest first."""
        data = control_of(AS[1]).data
        assert control_of(AS[1]).variables
        words = struct.unpack(f"!{len(data) // 2}H", data)
        listed = sorted(zip(words[0::2], words[1::2], strict=True))
        assert listed == NTPQ_ASSOCIATIONS

    def test_the_variable_ntpq_showed(self):
        message = control_of(VERSION[3])
        assert message.data == NTPQ_VERSION.encode() + b"\r\n"
        assert message.variables == (("version", '"ntpd ntpsec-1.2.2"'),)
        assert control_of(VERSION[2]).variables == (("version", None),)

    def test_an_error_response(self):
        """ntpq printed "Server error code UNKNOWNVAR"."""
        message = control_of(UNKNOWN[3])
        assert (message.response, message.error, message.count) == (
            True,
            True,
            0,
        )
        assert (message.error_code, message.error_name) == (
            5,
            "unknown variable name",
        )
        assert message.system_status is None

    def test_a_response_in_two_fragments(self):
        """ntpq printed "associd=17767 status=9014" for "rv &1"; the
        response came in two fragments, the first with the M bit set
        and 468 bytes of data, the most a message holds."""
        first, last = control_of(PEER[3]), control_of(PEER[4])
        assert (first.more, last.more) == (True, False)
        assert (first.offset, first.count) == (0, 468)
        assert last.offset == first.count
        for fragment in (first, last):
            assert (fragment.association_id, fragment.status) == NTPQ_PEER
            assert fragment.system_status is None
        whole = replace(first, data=first.data + last.data)
        variables = dict(whole.variables)
        assert variables["srcadr"] == "127.127.1.0"
        assert variables["srchost"] == '"LOCAL(0)"'
        assert variables["stratum"] == "8"

    def test_the_data_is_padded_to_4_bytes(self):
        """The padding ntpsec sends is whatever its buffer held, not
        always zeros, and is kept as it came."""
        assert control_of(RV[1]).padding == bytes(3)
        assert control_of(VERSION[2]).padding == bytes(1)
        assert control_of(AS[1]).padding == b""
        assert control_of(PEER[4]).padding == b"0."
        for index in range(17):
            message = control_of(index)
            assert (message.mac, message.remainder) == (None, b"")
            assert (12 + message.count + len(message.padding)) % 4 == 0

    @pytest.mark.parametrize(
        "index,key_id,digest_len,start",
        [(17, 3, 16, 32), (18, 3, 16, 32), (19, 4, 20, 32), (20, 4, 20, 12)],
    )
    def test_the_macs(self, index, key_id, digest_len, start):
        """The MAC follows the data padded to 8 bytes, and in an error
        response the 12-byte header; it verifies with the published
        key over every byte before it."""
        message = control_of(index)
        assert message.mac is not None
        assert (message.mac.key_id, len(message.mac.digest)) == (
            key_id,
            digest_len,
        )
        assert 12 + message.count + len(message.padding) == start
        algorithm, key = KEYS[key_id]
        raw = message_bytes(index)
        digest = hashlib.new(algorithm, key + raw[:start]).digest()
        assert hmac.compare_digest(digest, message.mac.digest)

    def test_the_configuration_exchange(self):
        """ntpq printed "Config Succeeded" for key 3, and "Server error
        code PERMISSION" for key 4, which is not the control key."""
        assert control_of(MD5[0]).variables == (("logconfig", "syncall"),)
        assert control_of(MD5[1]).data == b"Config Succeeded\r\n"
        refused = control_of(SHA1[1])
        assert (refused.error_code, refused.error_name) == (
            1,
            "authentication failure",
        )

    def test_build_ntpqs_read_variables_request(self):
        message = NTPControl(leap=3, opcode=2, sequence=2, data=b"version")
        assert bytes(replace(message, padding=b"\x00")) == message_bytes(
            VERSION[2]
        )
        assert message.count == 7
