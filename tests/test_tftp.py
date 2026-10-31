"""Test TFTP (RFC 1350, RFC 2347-2349) decoding and dispatch.

Covered: the six opcodes and their fields, option negotiation, how a
message's extent is read with no length field, truncation (a missing
terminating zero byte among it), the decode-time guard against a wrong
port guess, and dispatch, which reaches TFTP by port 69 for the request
alone.

The tftpd-hpa, tftp-hpa and curl transfers in tests/fixtures/tftp.pcap
(see its MANIFEST note) anchor the decode and round-trip asserts; the
cases those programs do not send are built here.
"""

from dataclasses import replace

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    DNS,
    TFTP,
    UDP,
    Ethernet,
    InvalidFieldError,
    IPv4,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import DEFAULT, TABLE_UDP_PORT

FRAMES = pcap_frames(FIXTURES / "tftp.pcap")

#: Ethernet + a 20-byte IPv4 header + UDP, in front of every message.
TFTP_START = 14 + 20 + 8

#: The fixture's transfers, in capture order (see the capture script):
#: each starts with its request to port 69.
RRQ = range(0, 7)
RRQ_EVEN = range(7, 14)
WRQ = range(14, 20)
NOT_FOUND = range(20, 23)
DENIED = range(23, 26)
OPTIONS = range(26, 33)
TRANSFERS = [RRQ, RRQ_EVEN, WRQ, NOT_FOUND, DENIED, OPTIONS]
REQUESTS = [transfer[0] for transfer in TRANSFERS]

#: Every frame's opcode, in capture order.
OPCODES = (
    ["RRQ"] + ["DATA", "ACK"] * 3
    + ["RRQ"] + ["DATA", "ACK"] * 3
    + ["WRQ", "ACK"] + ["DATA", "ACK"] * 2
    + ["RRQ", "ERROR", "ACK"]
    + ["RRQ", "ERROR", "ACK"]
    + ["RRQ", "OACK", "ACK"] + ["DATA", "ACK"] * 2
)  # fmt: skip

#: The files' contents, as the capture script writes them.
LINE = b"netprotocols tftp fixture, RFC 1350 block data.\n"


def contents(size: int) -> bytes:
    return (LINE * (size // len(LINE) + 1))[:size]


def message_bytes(index: int) -> bytes:
    """Return the TFTP message of capture frame ``index``, exactly."""
    return FRAMES[index][TFTP_START:]


def tftp_of(index: int) -> TFTP:
    return TFTP.decode(message_bytes(index))


def udp_of(index: int) -> UDP:
    layer = decode_frame(FRAMES[index])[UDP]
    assert isinstance(layer, UDP)
    return layer


def server_tid(transfer: range) -> int:
    """Return the server's transfer identifier: the source port of its
    first reply (RFC 1350 §4)."""
    return udp_of(transfer[1]).src_port


class TestCapturedMessages:
    def test_every_message_round_trips_exactly(self):
        """Each captured message decodes whole and re-encodes to its
        bytes, both ways."""
        for index in range(len(FRAMES)):
            raw = message_bytes(index)
            tftp = TFTP.decode(raw)
            assert tftp.header_len == len(raw)
            assert bytes(tftp) == raw
            assert TFTP.decode(bytes(tftp)) == tftp

    def test_opcodes(self):
        """The capture holds every opcode, in lockstep order."""
        assert [tftp_of(i).opcode_name for i in range(len(FRAMES))] == OPCODES
        assert {tftp_of(i).opcode for i in range(len(FRAMES))} == set(
            range(1, 7)
        )

    def test_requests(self):
        """RRQs and the WRQ name the file and octet mode (RFC 1350 §5)."""
        names = ["boot.bin", "even.bin", "upload.bin", "missing.bin"]
        names += ["secret.bin", "boot.bin"]
        for index, name in zip(REQUESTS, names, strict=True):
            tftp = tftp_of(index)
            assert tftp.opcode_name == ("WRQ" if index in WRQ else "RRQ")
            assert (tftp.filename, tftp.mode) == (name, "octet")
            assert (tftp.block, tftp.data, tftp.error_code) == (None,) * 3
        assert tftp_of(0).body == b"boot.bin\x00octet\x00"

    def test_requests_without_options(self):
        """tftp-hpa sends no options."""
        for index in REQUESTS[:-1]:
            tftp = tftp_of(index)
            assert tftp.options == ()
            assert (tftp.blksize, tftp.tsize, tftp.timeout) == (None,) * 3

    @pytest.mark.parametrize(
        "transfer,sizes",
        [
            (RRQ, [512, 512, 276]),
            (RRQ_EVEN, [512, 512, 0]),
            (WRQ, [512, 88]),
            (OPTIONS, [1024, 276]),
        ],
        ids=["rrq", "rrq-even", "wrq", "options"],
    )
    def test_data_blocks(self, transfer, sizes):
        """Blocks count from 1 and end short (RFC 1350 §6).

        A file whose size is a multiple of the block size ends in an
        empty block; the negotiated 1024 replaces 512.
        """
        data = [tftp_of(i) for i in transfer if tftp_of(i).opcode == 3]
        assert [d.block for d in data] == list(range(1, len(sizes) + 1))
        assert [len(d.data) for d in data] == sizes
        assert b"".join(d.data for d in data) == contents(sum(sizes))
        assert all(d.filename is None and d.options == () for d in data)

    def test_every_data_block_is_acknowledged(self):
        """Each DATA is followed by the ACK of its block number."""
        for index in range(len(FRAMES) - 1):
            tftp = tftp_of(index)
            if tftp.opcode == 3:
                ack = tftp_of(index + 1)
                assert (ack.opcode_name, ack.block) == ("ACK", tftp.block)
                assert ack.body == tftp.body[:2]
                assert ack.data is None

    def test_ack_of_block_0(self):
        """Block 0 acknowledges a WRQ (RFC 1350 §4) and an OACK (RFC
        2347)."""
        assert (tftp_of(15).opcode_name, tftp_of(15).block) == ("ACK", 0)
        assert (tftp_of(28).opcode_name, tftp_of(28).block) == ("ACK", 0)

    def test_file_not_found(self):
        """ERROR code 1, with tftpd-hpa's message."""
        tftp = tftp_of(21)
        assert (tftp.error_code, tftp.error_name) == (1, "File not found")
        assert tftp.error_message == "File not found"
        assert tftp.body == b"\x00\x01File not found\x00"
        assert (tftp.block, tftp.filename) == (None, None)

    def test_permission_denied_is_code_0(self):
        """tftpd-hpa reports an open() failure as code 0, Not defined,
        with strerror's text as the message."""
        tftp = tftp_of(24)
        assert (tftp.error_code, tftp.error_name) == (0, "Not defined")
        assert tftp.error_message == "Permission denied"

    def test_the_client_acks_block_1_after_an_error(self):
        """tftp-hpa answers an ERROR with an ACK of block 1 to the
        server's port, as BSD tftp does; the capture keeps it."""
        for transfer in (NOT_FOUND, DENIED):
            ack = tftp_of(transfer[2])
            assert (ack.opcode_name, ack.block) == ("ACK", 1)
            assert udp_of(transfer[2]).dst_port == server_tid(transfer)

    def test_option_negotiation(self):
        """curl asks for tsize 0, blksize 1024 and timeout 6 (RFC 2348,
        RFC 2349); the server's OACK accepts all three and gives the
        file's size."""
        rrq, oack = tftp_of(26), tftp_of(27)
        assert rrq.options == (
            ("tsize", "0"),
            ("blksize", "1024"),
            ("timeout", "6"),
        )
        assert (rrq.tsize, rrq.blksize, rrq.timeout) == (0, 1024, 6)
        assert oack.options == (
            ("tsize", "1300"),
            ("blksize", "1024"),
            ("timeout", "6"),
        )
        assert (oack.tsize, oack.blksize, oack.timeout) == (1300, 1024, 6)
        assert oack.windowsize is None
        assert (oack.filename, oack.mode, oack.block) == (None, None, None)
        assert (
            oack.body == b"tsize\x001300\x00blksize\x001024\x00timeout\x006\x00"
        )

    def test_option_names_match_in_any_case(self):
        """RFC 2347: option names are case-insensitive."""
        oack = tftp_of(27)
        assert oack.option("BLKSIZE") == oack.option("BlkSize") == "1024"
        assert oack.option("windowsize") is None


class TestDispatch:
    def test_registered_on_port_69(self):
        """The default registry maps UDP port 69 to TFTP."""
        assert DEFAULT.get(TABLE_UDP_PORT, 69) is TFTP

    def test_requests_walk_to_tftp_and_end_there(self):
        """A request goes to port 69, so a walk reaches TFTP."""
        for index in REQUESTS:
            packet = decode_frame(FRAMES[index])
            assert [type(layer) for layer in packet] == [
                Ethernet,
                IPv4,
                UDP,
                TFTP,
            ]
            assert packet[UDP].dst_port == 69
            assert packet.consumed == len(FRAMES[index])
            assert packet[TFTP] == tftp_of(index)

    def test_the_rest_of_a_transfer_ends_at_udp(self):
        """The stateless limit: every reply and everything after it runs
        between two ephemeral ports (RFC 1350 §4), which no port table
        names, so a default walk stops at UDP for the 27 of them."""
        rest = [i for i in range(len(FRAMES)) if i not in REQUESTS]
        assert len(rest) == 27
        for index in rest:
            packet = decode_frame(FRAMES[index])
            assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
            assert 69 not in (packet[UDP].src_port, packet[UDP].dst_port)
            assert packet.consumed == TFTP_START

    @pytest.mark.parametrize("transfer", TRANSFERS)
    def test_decode_as_the_servers_tid_decodes_the_transfer(self, transfer):
        """Naming the server's TID decodes both directions, since every
        datagram after the request has it as one of its ports."""
        registry = {"udp.port": {server_tid(transfer): TFTP}}
        for index in transfer:
            packet = decode_frame(FRAMES[index], decode_as=registry)
            assert packet[TFTP] == tftp_of(index)
            assert packet.consumed == len(FRAMES[index])

    @pytest.mark.parametrize("src_port,dst_port", [(40000, 69), (69, 40000)])
    def test_either_port(self, src_port, dst_port):
        """Dispatch on either port: a server that answers from 69 (which
        RFC 1350 §4 does not allow) has its replies dispatched too."""
        udp = UDP(src_port=src_port, dst_port=dst_port, length=0, checksum=0)
        assert udp.next_protocol() is TFTP

    def test_tftp_ends_the_chain(self):
        """TFTP carries no further protocol."""
        assert tftp_of(0).next_protocol() is None

    def test_decode_as_can_take_the_port_away(self):
        """Let a caller decode port 69 as something else for one walk."""
        packet = decode_frame(FRAMES[0], decode_as={"udp.port": {69: DNS}})
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP, DNS]


#: The 4-byte nonzero trailer an Ethernet FCS adds when a capture keeps
#: it.
FCS = b"\xde\xad\xbe\xef"


class TestExtent:
    """Read a message whose buffer runs on past its datagram.

    TFTP has no length field and the walk does not trim to UDP's
    (#235), so Ethernet padding and an FCS reach the decoder. veth does
    not pad, so the captured frames carry neither: they are added here.
    """

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    @pytest.mark.parametrize("trailer", [bytes(14), FCS], ids=["pad", "fcs"])
    @pytest.mark.parametrize(
        "index", [i for i in range(len(FRAMES)) if OPCODES[i] != "DATA"]
    )
    def test_a_trailer_is_left_undecoded(self, index, trailer, lax):
        """Every opcode but DATA ends where its structure does: an ACK
        after 4 bytes, an ERROR at its message's zero byte, a request or
        an OACK after its last whole option pair."""
        frame = FRAMES[index] + trailer
        tid = server_tid(next(t for t in TRANSFERS if index in t))
        packet = decode_frame(
            frame, lax=lax, decode_as={"udp.port": {tid: TFTP}}
        )
        assert packet.stopped_by is None
        assert packet[TFTP] == tftp_of(index)
        assert packet.consumed == len(FRAMES[index])
        assert bytes(packet) == FRAMES[index]

    def test_an_ack_padded_to_the_ethernet_minimum(self):
        """A 46-byte ACK frame goes out padded to 60 bytes; the ACK is
        still 4."""
        raw = message_bytes(2) + bytes(14)
        tftp = TFTP.decode(raw)
        assert (tftp.header_len, tftp.block) == (4, 1)
        assert bytes(tftp) == raw[: tftp.header_len]

    @pytest.mark.parametrize("trailer", [bytes(14), FCS], ids=["pad", "fcs"])
    def test_a_trailer_joins_the_data(self, trailer):
        """DATA runs to the end of the buffer: only UDP's length tells
        the trailer from the data, so it is part of the data."""
        raw = message_bytes(5) + trailer
        tftp = TFTP.decode(raw)
        assert tftp.data == contents(1300)[1024:] + trailer
        assert bytes(tftp) == raw

    def test_the_empty_final_block_padded(self):
        """The empty block 3 would reach a decoder over Ethernet as 14
        bytes of padding, read as data."""
        tftp = TFTP.decode(message_bytes(12) + bytes(14))
        assert (tftp.block, tftp.data) == (3, bytes(14))

    @pytest.mark.parametrize("cut", range(1, 38))
    def test_a_request_cut_inside_its_options(self, cut):
        """An option pair cut short is left undecoded, like a trailer:
        the pairs before it decode."""
        raw = message_bytes(26)
        tftp = TFTP.decode(raw[: 17 + cut])
        whole = tftp_of(26).options
        assert tftp.options == whole[: len(tftp.options)]
        assert bytes(tftp) == raw[: tftp.header_len]
        assert tftp.header_len <= 17 + cut

    def test_an_empty_option_name_ends_the_options(self):
        """A zero byte where a name would start ends the options, so
        padding never reads as an empty option."""
        raw = b"\x00\x01f\x00octet\x00blksize\x00512\x00\x00tsize\x000\x00"
        tftp = TFTP.decode(raw)
        assert tftp.options == (("blksize", "512"),)
        assert tftp.header_len == raw.index(b"\x00\x00tsize") + 1

    def test_padding_completes_a_name_left_without_a_value(self):
        """With an odd number of option strings, the last a name with no
        value, the first padding byte ends an empty value: the pair
        decodes and takes that byte. Without the padding the name is
        left undecoded; only the UDP length tells the two apart
        (#235)."""
        raw = b"\x00\x01f\x00octet\x00blksize\x00512\x00tsize\x00"
        alone = TFTP.decode(raw)
        assert alone.options == (("blksize", "512"),)
        assert alone.header_len == len(raw) - len(b"tsize\x00")
        padded = TFTP.decode(raw + bytes(8))
        assert padded.options == (("blksize", "512"), ("tsize", ""))
        assert padded.header_len == len(raw) + 1
        assert padded.tsize is None

    @pytest.mark.parametrize("index", [26, 27], ids=["rrq", "oack"])
    def test_an_fcs_holding_an_option_reads_as_one(self, index):
        """An FCS that holds a name, a zero byte, a value and a zero
        byte is one more option pair to the decoder; only the UDP
        length could tell it from one (#235)."""
        raw = message_bytes(index)
        tftp = TFTP.decode(raw + b"\x12\x00\x34\x00")
        assert tftp.options == (*tftp_of(index).options, ("\x12", "4"))
        assert tftp.header_len == len(raw) + 4

    @pytest.mark.parametrize("index", [26, 27], ids=["rrq", "oack"])
    @pytest.mark.parametrize(
        "fcs",
        [b"\x00\x12\x00\x34", b"\x12\x00\x34\x56", b"\x12\x34\x56\x00"],
        ids=["leading-zero", "one-zero-mid", "one-zero-last"],
    )
    def test_an_fcs_short_of_an_option_is_left_undecoded(self, index, fcs):
        """An FCS that starts with a zero byte, or holds fewer than two,
        is left undecoded."""
        tftp = TFTP.decode(message_bytes(index) + fcs)
        assert tftp == tftp_of(index)


class TestTruncation:
    def test_shorter_than_the_opcode(self):
        """One byte is not an opcode."""
        with pytest.raises(TruncatedHeaderError) as caught:
            TFTP.decode(b"\x00")
        assert (caught.value.offset, caught.value.expected) == (0, 2)

    @pytest.mark.parametrize("index", REQUESTS)
    def test_a_request_without_its_terminating_zero_bytes(self, index):
        """Each cut before the mode's zero byte raises, naming the
        string that has none (RFC 1350 §5)."""
        raw = message_bytes(index)
        mode_start = raw.index(b"\x00", 2) + 1
        mode_end = raw.index(b"\x00", mode_start)
        for cut in range(2, mode_end + 1):
            with pytest.raises(TruncatedHeaderError) as caught:
                TFTP.decode(raw[:cut])
            field, offset = (
                ("filename", 2) if cut < mode_start else ("mode", mode_start)
            )
            assert (caught.value.field, caught.value.offset) == (field, offset)
            assert caught.value.protocol is TFTP
        assert TFTP.decode(raw[: mode_end + 1]).mode == "octet"

    @pytest.mark.parametrize("index", [1, 2, 21], ids=["data", "ack", "error"])
    @pytest.mark.parametrize("cut", [2, 3])
    def test_a_number_cut_short(self, index, cut):
        """DATA and ACK need a 2-byte block number, ERROR a 2-byte
        error code."""
        with pytest.raises(TruncatedHeaderError) as caught:
            TFTP.decode(message_bytes(index)[:cut])
        field = "error_code" if index == 21 else "block"
        assert (caught.value.field, caught.value.offset) == (field, 2)
        assert (caught.value.expected, caught.value.actual) == (4, cut)

    @pytest.mark.parametrize("index", [21, 24])
    def test_an_error_message_without_its_zero_byte(self, index):
        """An ERROR's message ends in a zero byte too."""
        raw = message_bytes(index)
        for cut in range(4, len(raw)):
            with pytest.raises(TruncatedHeaderError) as caught:
                TFTP.decode(raw[:cut])
            assert (caught.value.field, caught.value.offset) == (
                "error_message",
                4,
            )

    def test_an_empty_data_block_needs_no_more(self):
        """Four bytes are a whole DATA: block 3, no data."""
        assert TFTP.decode(message_bytes(12)).data == b""

    @pytest.mark.parametrize("cut", range(2, 36))
    def test_an_oack_cut_anywhere_decodes_its_whole_pairs(self, cut):
        """An OACK has no mandatory string: a cut one keeps its whole
        pairs."""
        tftp = TFTP.decode(message_bytes(27)[:cut])
        assert tftp.options == tftp_of(27).options[: len(tftp.options)]

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    def test_a_cut_request_in_a_walk(self, lax):
        """A snap length that cuts a request's mode stops the walk at
        TFTP: strict raises, lax keeps the layers before it."""
        frame = FRAMES[0][: TFTP_START + 12]
        if not lax:
            with pytest.raises(TruncatedHeaderError) as caught:
                decode_frame(frame)
            assert caught.value.frame_offset == TFTP_START + 11
            return
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)
        assert packet.stopped_by.field == "mode"

    def test_memoryview_input_is_not_retained(self):
        """A decode from a memoryview copies what it keeps."""
        for index in (0, 5, 21, 27):
            buffer = bytearray(message_bytes(index))
            tftp = TFTP.decode(memoryview(buffer))
            assert tftp == tftp_of(index)
            buffer[2:] = bytes(len(buffer) - 2)
            assert tftp == tftp_of(index)
            assert isinstance(tftp.body, bytes)


class TestDecodeGuard:
    @pytest.mark.parametrize("opcode", [0, 7, 0x0100, 0xFFFF])
    def test_an_opcode_other_than_1_to_6(self, opcode):
        """No TFTP message carries it."""
        with pytest.raises(InvalidFieldError) as caught:
            TFTP.decode(opcode.to_bytes(2, "big") + b"boot.bin\x00octet\x00")
        assert (caught.value.field, caught.value.offset) == ("opcode", 0)
        assert caught.value.actual == opcode

    def test_exactly_6_of_the_two_byte_prefixes_pass(self):
        """The opcode alone decides, so 65,530 of 65,536 prefixes fail
        the guard; the 6 that pass may still be cut short."""
        passed = 0
        for prefix in range(0x10000):
            try:
                TFTP.decode(prefix.to_bytes(2, "big") + b"a\x00b\x00cd")
            except InvalidFieldError:
                continue
            passed += 1
        assert passed == 6

    @pytest.mark.parametrize("lax", [False, True], ids=["strict", "lax"])
    def test_a_rejected_guess_is_reported_at_the_tftp_header(self, lax):
        """A datagram to port 69 with opcode 9 is not TFTP."""
        frame = FRAMES[0][: TFTP_START + 1] + b"\x09" + FRAMES[0][44:]
        if not lax:
            with pytest.raises(InvalidFieldError) as caught:
                decode_frame(frame)
            assert caught.value.frame_offset == TFTP_START
            return
        packet = decode_frame(frame, lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4, UDP]
        assert isinstance(packet.stopped_by, InvalidFieldError)

    @pytest.mark.parametrize(
        "raw",
        [
            pytest.param(b"\x00\x01\x00octet\x00", id="empty-filename"),
            pytest.param(b"\x00\x02f\x00\x00", id="empty-mode"),
            pytest.param(b"\x00\x01f\x00NetASCII\x00", id="mixed-case-mode"),
            pytest.param(b"\x00\x01f\x00mail\x00", id="obsolete-mail-mode"),
            pytest.param(b"\x00\x01f\x00binary\x00", id="unknown-mode"),
            pytest.param(b"\x00\x01f\x00octet\x00x\x00\x00", id="empty-value"),
            pytest.param(b"\x00\x05\x00\x09\x00", id="unknown-error-code"),
            pytest.param(b"\x00\x05\x00\x08\x00", id="empty-error-message"),
            pytest.param(b"\x00\x06", id="empty-oack"),
            pytest.param(b"\x00\x04\xff\xff", id="ack-65535"),
        ],
    )
    def test_what_rfc_1350_does_not_name_still_decodes(self, raw):
        """Nothing past the mandatory structure is checked."""
        tftp = TFTP.decode(raw)
        assert bytes(tftp) == raw

    @pytest.mark.parametrize(
        "code,name",
        [
            # RFC 1350's appendix, "Error Codes", without the trailing
            # period; code 0 reads "Not defined, see error message (if
            # any)."
            (0, "Not defined"),
            (1, "File not found"),
            (2, "Access violation"),
            (3, "Disk full or allocation exceeded"),
            (4, "Illegal TFTP operation"),
            (5, "Unknown transfer ID"),
            (6, "File already exists"),
            (7, "No such user"),
            # RFC 2347 defines code 8 "to indicate that a transfer
            # should be terminated due to option negotiation".
            (8, "Terminate transfer due to option negotiation"),
        ],
    )
    def test_every_error_code_the_rfcs_define_is_named(self, code, name):
        """Each code of RFC 1350's table, and RFC 2347's 8, by name."""
        raw = b"\x00\x05" + code.to_bytes(2, "big") + b"text\x00"
        assert TFTP.decode(raw).error_name == name

    def test_unknown_and_option_negotiation_error_codes(self):
        """Code 8 is RFC 2347's; others fall back to unknown."""
        assert TFTP(5, b"\x00\x08\x00").error_name == (
            "Terminate transfer due to option negotiation"
        )
        assert TFTP(5, b"\x00\x09\x00").error_name == "unknown (9)"
        assert TFTP(5, b"\x00\x09\x00").error_message == ""


class TestOptions:
    def test_windowsize_and_unknown_options(self):
        """windowsize (RFC 7440) reads as a number; any option is kept
        in wire order."""
        tftp = TFTP(1, b"f\x00octet\x00windowsize\x0016\x00x-vendor\x00on\x00")
        assert tftp.windowsize == 16
        assert tftp.options == (("windowsize", "16"), ("x-vendor", "on"))
        assert tftp.option("X-VENDOR") == "on"

    @pytest.mark.parametrize(
        "value", ["", "abc", "-1", "1e3", " 512", "\u0665"]
    )
    def test_a_value_that_is_not_decimal_reads_as_none(self, value):
        """Only ASCII digits are a number; the raw value stays."""
        body = b"f\x00octet\x00blksize\x00" + value.encode() + b"\x00"
        tftp = TFTP(1, body)
        assert tftp.blksize is None
        assert tftp.option("blksize") == value.encode().decode(
            "ascii", "backslashreplace"
        )

    @pytest.mark.parametrize(
        "raw",
        [
            b"\x00\x01f\x00octet\x00blksize\x00" + b"9" * 5000 + b"\x00",
            b"\x00\x06tsize\x00" + b"1" * 4301 + b"\x00",
        ],
        ids=["rrq-5000", "oack-4301"],
    )
    def test_a_value_past_ints_digit_limit_reads_as_none(self, raw):
        """int() raises ValueError for a string over 4,300 digits; the
        number accessors answer None instead, and the raw value stays."""
        tftp = TFTP.decode(raw)
        numbers = (tftp.blksize, tftp.timeout, tftp.tsize, tftp.windowsize)
        assert numbers == (None,) * 4
        value = raw.split(b"\x00")[-2]
        assert tftp.options[-1][1] == value.decode()

    @pytest.mark.parametrize(
        "value,number",
        [
            ("18446744073709551615", 2**64 - 1),
            ("99999999999999999999", 10**20 - 1),
            ("0" * 5000 + "512", 512),
            ("0" * 5000, 0),
            ("100000000000000000000", None),
            ("0" + "9" * 21, None),
        ],
        ids=["2**64-1", "20-digits", "leading-zeros", "zeros", "21", "0+21"],
    )
    def test_a_number_reads_up_to_20_significant_digits(self, value, number):
        """Any 64-bit size reads as a number; a value over 20 digits,
        leading zeros aside, reads as None."""
        for name in ("blksize", "timeout", "tsize", "windowsize"):
            tftp = TFTP(6, f"{name}\x00{value}\x00".encode())
            assert getattr(tftp, name) == number
            assert tftp.option(name) == value

    def test_the_first_of_a_repeated_option_wins(self):
        """option() returns the first match, in wire order."""
        tftp = TFTP(6, b"blksize\x00512\x00BLKSIZE\x001024\x00")
        assert tftp.blksize == 512
        assert len(tftp.options) == 2

    def test_bytes_outside_ascii_read_as_escapes(self):
        """Strings are netascii; any other byte is escaped, not lost."""
        tftp = TFTP.decode(b"\x00\x01caf\xc3\xa9\x00octet\x00")
        assert tftp.filename == "caf\\xc3\\xa9"
        error = TFTP.decode(b"\x00\x05\x00\x00\xff\x00")
        assert error.error_message == "\\xff"


class TestConstruction:
    def test_build_each_opcode(self):
        """A message built from its body decodes back to itself."""
        for tftp in (
            TFTP(1, b"pxelinux.0\x00octet\x00tsize\x000\x00"),
            TFTP(2, b"upload.bin\x00netascii\x00"),
            TFTP(3, b"\x00\x07" + bytes(512)),
            TFTP(4, b"\x00\x07"),
            TFTP(5, b"\x00\x06File already exists\x00"),
            TFTP(6, b"blksize\x001428\x00"),
        ):
            assert TFTP.decode(bytes(tftp)) == tftp
            assert bytes(tftp)[:2] == tftp.opcode.to_bytes(2, "big")

    @pytest.mark.parametrize("value", [-1, 0x10000])
    def test_an_opcode_too_wide_is_refused(self, value):
        """The opcode is 16 bits."""
        with pytest.raises(InvalidFieldError) as caught:
            TFTP(value)
        assert (caught.value.field, caught.value.expected) == (
            "opcode",
            "0-65535",
        )

    def test_an_opcode_decode_rejects_still_builds(self):
        """Construction accepts any 16-bit opcode."""
        tftp = replace(TFTP(1), opcode=0xFFFF)
        assert bytes(tftp) == b"\xff\xff"
        assert tftp.opcode_name == "unknown (65535)"
        with pytest.raises(InvalidFieldError):
            TFTP.decode(bytes(tftp))

    def test_a_body_past_its_structural_end_decodes_shorter(self):
        """Decode ends an ACK after its block number, so bytes a
        constructed one carries past it are not decoded back."""
        tftp = TFTP(4, b"\x00\x01extra")
        assert tftp.block == 1
        assert TFTP.decode(bytes(tftp)) == TFTP(4, b"\x00\x01")

    def test_malformed_bodies_answer_none(self):
        """A constructed body without its strings or numbers answers
        None, never raises."""
        assert (TFTP(1, b"no-nul").filename, TFTP(1, b"f\x00").mode) == (
            None,
            None,
        )
        assert TFTP(1, b"no-nul").options == ()
        assert TFTP(5, b"\x00\x01no-nul").error_message is None
        assert TFTP(5, b"\x00").error_code is None
        assert TFTP(5, b"\x00").error_name is None
        assert (TFTP(3, b"\x00").block, TFTP(3, b"\x00").data) == (None, None)

    def test_accessors_answer_none_for_other_opcodes(self):
        """Each accessor answers only for the opcodes that carry it."""
        data = TFTP(3, b"\x00\x01f\x00octet\x00")
        assert (data.filename, data.mode, data.options) == (None, None, ())
        assert (data.error_code, data.error_message) == (None, None)
        error = TFTP(5, b"\x00\x01\x00")
        assert (error.block, error.data, error.options) == (None, None, ())
        rrq = TFTP(1, b"\x00\x01\x00\x00")
        assert (rrq.block, rrq.error_code, rrq.error_name) == (None,) * 3

    def test_positional_patterns_follow_wire_order(self):
        """``case TFTP(opcode, body)`` matches in wire order, and the
        accessors work as keyword patterns."""
        match tftp_of(0):
            case TFTP(1, body, filename="boot.bin"):
                assert body == b"boot.bin\x00octet\x00"
            case _:
                pytest.fail("the RRQ did not match")
