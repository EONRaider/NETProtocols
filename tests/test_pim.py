"""Tests for PIM-SM (RFC 7761).

Covered: the common header, message-type dispatch, the typed messages
and encoded addresses, how a message bounds itself without a length
field, the checksum, and dispatch from IPv4/IPv6 protocol 103.

The FRR capture in tests/fixtures/pim.pcap (see its MANIFEST note)
anchors the decode, round-trip and checksum asserts. IPv6 PIM cannot be
captured on the capture host (its kernel boots with IPv6 disabled), so
the IPv6 cases are built here, with their pseudo-header checksums
computed by this file's own internet checksum, not the library's.
"""

import importlib.util
import struct
import sys
from collections import Counter
from dataclasses import replace
from ipaddress import IPv6Address
from pathlib import Path
from types import ModuleType

import pytest

from conftest import FIXTURES, pcap_frames
from netprotocols import (
    PIM,
    UDP,
    Ethernet,
    InvalidFieldError,
    IPProtocol,
    IPv4,
    IPv6,
    IPv6HopByHopOptions,
    Packet,
    PIMAssert,
    PIMEncodedGroup,
    PIMEncodedSource,
    PIMEncodedUnicast,
    PIMGroupSet,
    PIMHello,
    PIMHelloOption,
    PIMJoinPrune,
    PIMLANPruneDelay,
    PIMRegister,
    PIMRegisterStop,
    TruncatedHeaderError,
    compute,
    decode_frame,
    verify,
)
from netprotocols.registry import DEFAULT, TABLE_IP_PROTO, TABLE_IP_PROTO_V6

FRAMES = pcap_frames(FIXTURES / "pim.pcap")

#: Ethernet + a 20-byte IPv4 header, in front of every captured message.
PIM_START = 14 + 20

#: The capture's addresses (see scripts/capture_fixtures_pim.sh).
R1, R2, R1_SECONDARY = "10.184.12.1", "10.184.12.2", "10.184.13.1"
SOURCE, G1, G2 = "10.184.1.2", "239.184.0.1", "239.184.0.2"

#: Encoded-Source flag bytes: S, S+R, S+W+R.
SPT, RPT, WC_RPT = 0x04, 0x05, 0x07


def message_bytes(index: int) -> bytes:
    """Return the PIM message of capture frame ``index``, exactly."""
    frame = FRAMES[index]
    total_length = struct.unpack_from("!H", frame, 14 + 2)[0]
    return frame[PIM_START : 14 + total_length]


def pim_of(index: int) -> PIM:
    layer = decode_frame(FRAMES[index])[PIM]
    assert isinstance(layer, PIM)
    return layer


def unicast(address: str) -> PIMEncodedUnicast:
    family = 2 if ":" in address else 1
    return PIMEncodedUnicast(family, 0, address)


def group(address: str) -> PIMEncodedGroup:
    family, width = (2, 128) if ":" in address else (1, 32)
    return PIMEncodedGroup(family, 0, 0, width, address)


def source(address: str, flags: int) -> PIMEncodedSource:
    family, width = (2, 128) if ":" in address else (1, 32)
    return PIMEncodedSource(family, 0, flags, width, address)


def join_prune(group_address: str, joined=(), pruned=()) -> PIMJoinPrune:
    return PIMJoinPrune(
        upstream_neighbor=unicast(R1),
        holdtime=210,
        groups=(PIMGroupSet(group(group_address), joined, pruned),),
    )


def ones_complement_checksum(data: bytes) -> int:
    """RFC 1071, written here independently of netprotocols.checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for (word,) in struct.iter_unpack("!H", data):
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


class TestCapturedMessages:
    """Every frame of the FRR capture, in order."""

    EXPECTED_TYPES = (0, 0, 3, 1, 3, 3, 2, 1, 3, 3, 3, 3, 0)

    def test_every_frame_walks_to_pim_and_ends_there(self):
        """Test every frame walks to pim and ends there."""
        for frame in FRAMES:
            packet = decode_frame(frame)
            assert [type(layer) for layer in packet] == [Ethernet, IPv4, PIM]
            assert packet[IPv4].protocol == IPProtocol.PIM
            assert packet.consumed == len(frame)

    def test_message_types(self):
        """Test message types."""
        assert tuple(pim_of(i).type for i in range(len(FRAMES))) == (
            self.EXPECTED_TYPES
        )
        assert pim_of(0).type_name == "Hello"
        assert pim_of(2).type_name == "Join/Prune"
        assert pim_of(3).type_name == "Register"
        assert pim_of(6).type_name == "Register-Stop"

    def test_every_message_is_version_2_with_a_zero_reserved_byte(self):
        """Test every message is version 2 with a zero reserved byte."""
        for index in range(len(FRAMES)):
            assert (pim_of(index).version, pim_of(index).reserved) == (2, 0)

    def test_round_trip(self):
        """Test round trip."""
        for index in range(len(FRAMES)):
            raw = message_bytes(index)
            pim = PIM.decode(raw)
            assert bytes(pim) == raw
            assert PIM.decode(bytes(pim)) == pim
            assert pim.header_len == len(raw)

    def test_hello_with_every_frr_option(self):
        """Test hello with every frr option."""
        hello = pim_of(0).message
        assert isinstance(hello, PIMHello)
        assert [option.type for option in hello.options] == [1, 2, 19, 20, 24]
        assert [option.type_name for option in hello.options] == [
            "Holdtime",
            "LAN Prune Delay",
            "DR Priority",
            "Generation ID",
            "Address List",
        ]
        assert hello.holdtime == 105
        assert hello.lan_prune_delay == PIMLANPruneDelay(
            t=False, propagation_delay=500, override_interval=2500
        )
        assert hello.dr_priority == 1
        assert hello.generation_id == 0x75553E5A
        assert hello.address_list == (unicast(R1_SECONDARY),)

    def test_hello_without_an_address_list(self):
        """Test hello without an address list."""
        hello = pim_of(1).message
        assert isinstance(hello, PIMHello)
        assert hello.generation_id == 0x57EB8AA0
        assert hello.address_list is None
        assert hello.option(24) is None

    def test_goodbye_hello(self):
        """Check the goodbye: a pimd shutting down sends Holdtime 0.

        That is RFC 7761 §4.3.1, with the Generation ID it has used all
        along.
        """
        hello = pim_of(12).message
        assert isinstance(hello, PIMHello)
        assert hello.holdtime == 0
        assert hello.generation_id == 0x57EB8AA0

    @pytest.mark.parametrize(
        "index,expected",
        [
            (2, join_prune(G2, joined=(source(R1, WC_RPT),))),
            (4, join_prune(G1, joined=(source(SOURCE, SPT),))),
            (5, join_prune(G2, joined=(source(SOURCE, SPT),))),
            (8, join_prune(G1, pruned=(source(SOURCE, SPT),))),
            (9, join_prune(G2, pruned=(source(R1, WC_RPT),))),
            (10, join_prune(G2, pruned=(source(SOURCE, SPT),))),
            (
                11,
                join_prune(
                    G2,
                    joined=(source(R1, WC_RPT),),
                    pruned=(source(SOURCE, RPT),),
                ),
            ),
        ],
        ids=[
            "join-star-g",
            "join-s-g-rp-r2",
            "join-s-g-rp-r1",
            "prune-s-g",
            "prune-star-g",
            "prune-s-g-rp-r1",
            "join-star-g-prune-s-g-rpt",
        ],
    )
    def test_join_prune(self, index, expected):
        """Test join prune."""
        assert pim_of(index).message == expected

    def test_join_prune_source_flags(self):
        """Test join prune source flags."""
        message = pim_of(11).message
        assert isinstance(message, PIMJoinPrune)
        (group_set,) = message.groups
        (star,), (rpt,) = group_set.joined, group_set.pruned
        assert (star.sparse, star.wildcard, star.rpt) == (True, True, True)
        assert (rpt.sparse, rpt.wildcard, rpt.rpt) == (True, False, True)
        assert not group_set.group.bidirectional
        assert not group_set.group.admin_scope

    def test_register_carries_the_source_datagram(self):
        """Test register carries the source datagram."""
        register = pim_of(3).message
        assert isinstance(register, PIMRegister)
        assert (register.border, register.null_register) == (False, False)
        inner = register.encapsulated
        assert inner.stopped_by is None
        assert [type(layer) for layer in inner] == [IPv4, UDP]
        assert (inner[IPv4].src, inner[IPv4].dst) == (SOURCE, G1)
        assert inner[UDP].dst_port == 5000
        assert register.packet[inner.consumed :] == b"NETProtocols PIM 00"
        assert verify(inner[IPv4])
        assert verify(
            inner[UDP],
            ip=inner[IPv4],
            payload=register.packet[inner.consumed :],
        )

    def test_null_register_carries_a_dummy_header(self):
        """Check a Null-Register's packet, a bare IPv4 header.

        It names the source and group (RFC 7761 §4.9.3); FRR leaves its checksum
        zero, which a receiver must then not check. It names PIM but
        carries none, so its walk stops there.
        """
        register = pim_of(7).message
        assert isinstance(register, PIMRegister)
        assert register.null_register
        inner = register.encapsulated
        assert [type(layer) for layer in inner] == [IPv4]
        dummy = inner[IPv4]
        assert (dummy.src, dummy.dst) == (SOURCE, G1)
        assert (dummy.total_length, dummy.protocol, dummy.checksum) == (
            20,
            IPProtocol.PIM,
            0,
        )
        assert isinstance(inner.stopped_by, TruncatedHeaderError)

    def test_register_stop(self):
        """Test register stop."""
        assert pim_of(6).message == PIMRegisterStop(group(G1), unicast(SOURCE))

    def test_addresses(self):
        """Test addresses."""
        frame = decode_frame(FRAMES[0])
        assert (frame[IPv4].src, frame[IPv4].dst) == (R1, "224.0.0.13")
        frame = decode_frame(FRAMES[3])
        assert (frame[IPv4].src, frame[IPv4].dst) == ("10.184.1.1", R2)


class TestCapturedChecksums:
    def test_every_checksum_verifies_and_recomputes(self):
        """Test every checksum verifies and recomputes."""
        for frame in FRAMES:
            packet = decode_frame(frame)
            pim, ip = packet[PIM], packet[IPv4]
            assert verify(pim, ip=ip)
            assert compute(pim, ip=ip) == pim.checksum
            assert packet.with_checksums() == packet

    def test_frr_sums_only_a_registers_first_8_bytes(self):
        """Test frr sums only a registers first 8 bytes."""
        for index in (3, 7):
            raw = message_bytes(index)
            covered = raw[:2] + b"\x00\x00" + raw[4:8]
            assert ones_complement_checksum(covered) == pim_of(index).checksum
            whole = raw[:2] + b"\x00\x00" + raw[4:]
            assert ones_complement_checksum(whole) != pim_of(index).checksum

    def test_a_register_summed_whole_verifies_too(self):
        """Accept a Register summed over the whole message.

        RFC 7761 §4.9.3: a receiver should accept a Register whose
        checksum covers the whole message, data packet included.
        """
        packet = decode_frame(FRAMES[3])
        raw = message_bytes(3)
        whole = ones_complement_checksum(raw[:2] + b"\x00\x00" + raw[4:])
        summed_whole = replace(packet[PIM], checksum=whole)
        assert verify(summed_whole, ip=packet[IPv4])
        assert compute(summed_whole, ip=packet[IPv4]) != whole

    def test_a_tampered_message_fails(self):
        """Test a tampered message fails."""
        for index in range(len(FRAMES)):
            packet = decode_frame(FRAMES[index])
            pim = packet[PIM]
            assert not verify(
                replace(pim, checksum=pim.checksum ^ 1), ip=packet[IPv4]
            )

    def test_a_tampered_register_header_fails_and_its_data_does_not(self):
        """Test a tampered register header fails and its data does not."""
        packet = decode_frame(FRAMES[3])
        pim = packet[PIM]
        flipped_header = pim.body[:3] + bytes([pim.body[3] ^ 1]) + pim.body[4:]
        assert not verify(replace(pim, body=flipped_header), ip=packet[IPv4])
        flipped_data = pim.body[:-1] + bytes([pim.body[-1] ^ 1])
        assert verify(replace(pim, body=flipped_data), ip=packet[IPv4])

    def test_the_checksum_needs_the_ip_layer(self):
        """Test the checksum needs the ip layer."""
        with pytest.raises(InvalidFieldError) as excinfo:
            compute(pim_of(0))
        assert excinfo.value.protocol is PIM
        assert excinfo.value.field == "checksum"

    def test_with_checksums_fills_a_built_message(self):
        """Test with checksums fills a built message."""
        packet = decode_frame(FRAMES[2])
        zeroed = Packet(
            packet[Ethernet],
            replace(packet[IPv4], checksum=0),
            replace(packet[PIM], checksum=0),
        )
        assert zeroed.with_checksums() == packet


class TestTrailingBytes:
    """Real frames with Ethernet's zero padding or a trailer appended.

    PIM has no length field and the walk does not trim a frame to the
    IP datagram (see the module docstring); the trailer is FCS-like, 4
    bytes.
    """

    FCS = b"\xde\xad\xbe\xef"

    @pytest.mark.parametrize("index", [2, 6, 8, 11], ids=lambda i: f"frame{i}")
    @pytest.mark.parametrize("padding", [1, 2, 3, 4, 8, 26])
    def test_a_bounded_message_leaves_zero_padding(self, index, padding):
        """Test a bounded message leaves zero padding."""
        frame = FRAMES[index] + bytes(padding)
        packet = decode_frame(frame)
        assert packet[PIM] == pim_of(index)
        assert packet.consumed == len(FRAMES[index])
        assert verify(packet[PIM], ip=packet[IPv4])

    @pytest.mark.parametrize("index", [2, 6, 8, 11], ids=lambda i: f"frame{i}")
    def test_a_bounded_message_leaves_a_nonzero_trailer(self, index):
        """Test a bounded message leaves a nonzero trailer."""
        frame = FRAMES[index] + self.FCS
        packet = decode_frame(frame)
        assert packet[PIM] == pim_of(index)
        assert frame[packet.consumed :] == self.FCS
        assert verify(packet[PIM], ip=packet[IPv4])

    @pytest.mark.parametrize("index", [0, 1, 12], ids=lambda i: f"frame{i}")
    @pytest.mark.parametrize("padding", [1, 2, 3, 4, 5, 8, 26])
    def test_a_hello_leaves_zero_padding(self, index, padding):
        """Test a hello leaves zero padding."""
        packet = decode_frame(FRAMES[index] + bytes(padding))
        assert packet[PIM] == pim_of(index)
        assert packet.consumed == len(FRAMES[index])

    @pytest.mark.parametrize("index", [0, 1, 12], ids=lambda i: f"frame{i}")
    @pytest.mark.parametrize("padding", [0, 4])
    def test_a_hello_keeps_a_trailer_that_does_not_walk(self, index, padding):
        """Keep a trailer that reads as an option of 48879 bytes.

        ``de ad be ef`` does not walk, so the whole remainder is kept,
        the message does not parse, and the checksum fails.
        """
        frame = FRAMES[index] + bytes(padding) + self.FCS
        packet = decode_frame(frame)
        pim = packet[PIM]
        assert packet.consumed == len(frame)
        assert pim.body.endswith(self.FCS)
        with pytest.raises(InvalidFieldError):
            _ = pim.message
        assert not verify(pim, ip=packet[IPv4])

    def test_a_hello_reads_a_trailer_that_walks_as_a_phantom_option(self):
        """Read an FCS whose last two bytes are zero as an empty option.

        Only the checksum can tell.
        """
        packet = decode_frame(FRAMES[1] + b"\xab\xcd\x00\x00")
        hello = packet[PIM].message
        assert isinstance(hello, PIMHello)
        assert hello.options[-1] == PIMHelloOption(0xABCD)
        assert not verify(packet[PIM], ip=packet[IPv4])

    @pytest.mark.parametrize(
        "trailer,phantom",
        [
            (b"\xff\xff\x00\x00", PIMHelloOption(0xFFFF)),
            (b"\x12\x34\xed\xcb", None),
        ],
        ids=["phantom-option", "unwalkable"],
    )
    def test_a_trailer_that_adds_nothing_to_the_sum_verifies(
        self, trailer, phantom
    ):
        """Verify a nonzero trailer whose words sum to zero, over IPv4.

        ``ffff + 0000`` and ``1234 + edcb`` are both one's-complement
        zero, so the checksum cannot see them: one walks as a phantom
        option, the other makes :attr:`PIM.message` raise.
        """
        packet = decode_frame(FRAMES[1] + trailer)
        assert packet[PIM].body.endswith(trailer)
        assert verify(packet[PIM], ip=packet[IPv4])
        if phantom is None:
            with pytest.raises(InvalidFieldError):
                _ = packet[PIM].message
        else:
            hello = packet[PIM].message
            assert isinstance(hello, PIMHello)
            assert hello.options[-1] == phantom

    @pytest.mark.parametrize("trailer", [bytes(8), FCS], ids=["zeros", "fcs"])
    def test_a_register_keeps_the_trailer_and_still_verifies(self, trailer):
        """Keep the trailer in a Register's data packet.

        The data packet runs to the end of the buffer, so the trailer
        lands in it, but its checksum covers 8 bytes only.
        """
        packet = decode_frame(FRAMES[3] + trailer)
        register = packet[PIM].message
        assert isinstance(register, PIMRegister)
        assert register.packet.endswith(trailer)
        assert verify(packet[PIM], ip=packet[IPv4])
        assert register.encapsulated[IPv4].total_length == 47


class TestTruncation:
    def test_a_buffer_shorter_than_the_header_raises(self):
        """Test a buffer shorter than the header raises."""
        for size in range(4):
            with pytest.raises(TruncatedHeaderError):
                PIM.decode(message_bytes(0)[:size])

    @pytest.mark.parametrize(
        "index", [0, 2, 3, 6, 11], ids=lambda i: f"frame{i}"
    )
    def test_a_cut_message_keeps_its_header(self, index):
        """Decode a message cut anywhere past the header.

        The rest is kept verbatim; a cut that leaves no whole structure
        behind makes :attr:`PIM.message` raise, and every cut fails the
        checksum.
        """
        raw = message_bytes(index)
        ip = decode_frame(FRAMES[index])[IPv4]
        for cut in range(4, len(raw)):
            pim = PIM.decode(raw[:cut])
            # A Hello cut just past an option, leaving only zero bytes
            # of the next one's type, reads those as padding.
            assert bytes(pim) == raw[: pim.header_len]
            assert not any(raw[pim.header_len : cut])
            assert (pim.type, pim.checksum) == (
                pim_of(index).type,
                pim_of(index).checksum,
            )
            if pim.type != 1:  # a Register sums its first 8 bytes only
                assert not verify(pim, ip=ip) or cut == len(raw)

    def test_a_cut_join_prune_raises_from_message(self):
        """Test a cut join prune raises from message."""
        raw = message_bytes(2)
        for cut in range(4, len(raw)):
            with pytest.raises(TruncatedHeaderError) as excinfo:
                _ = PIM.decode(raw[:cut]).message
            assert excinfo.value.field == "body"
            assert excinfo.value.protocol is PIM

    def test_a_cut_hello_option_raises_from_message(self):
        """Test a cut hello option raises from message."""
        raw = message_bytes(1)
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = PIM.decode(raw[:-1]).message
        assert str(excinfo.value) == "PIM option data runs past the header"
        assert excinfo.value.offset == 22  # the Generation ID option

    def test_a_cut_register_header_raises_from_message(self):
        """Test a cut register header raises from message."""
        with pytest.raises(TruncatedHeaderError):
            _ = PIM.decode(message_bytes(3)[:7]).message

    def test_a_lying_source_count_keeps_the_body(self):
        """Keep the body whole when a source count lies.

        Join/Prune's counts bound it; one that claims more sources than
        the message holds cannot.
        """
        raw = bytearray(message_bytes(2))
        raw[4 + 6 + 4 + 8 + 1] = 2  # number of joined sources: 2
        pim = PIM.decode(bytes(raw))
        assert pim.header_len == len(raw)
        with pytest.raises(TruncatedHeaderError):
            _ = pim.message
        # Zero padding after it reads as a source of family 0.
        pim = PIM.decode(bytes(raw) + bytes(8))
        assert pim.header_len == len(raw) + 8
        with pytest.raises(InvalidFieldError):
            _ = pim.message


class TestVersion:
    @pytest.mark.parametrize("version", [0, 1, 3, 15])
    def test_decode_rejects_other_versions(self, version):
        """Test decode rejects other versions."""
        raw = bytes([version << 4]) + message_bytes(0)[1:]
        with pytest.raises(InvalidFieldError) as excinfo:
            PIM.decode(raw)
        err = excinfo.value
        assert (err.field, err.offset, err.expected, err.actual) == (
            "version",
            0,
            2,
            version,
        )

    def test_the_constructor_rejects_other_versions(self):
        """Test the constructor rejects other versions."""
        with pytest.raises(InvalidFieldError):
            PIM(version=1)

    def test_a_lax_walk_reports_it(self):
        """Test a lax walk reports it."""
        frame = bytearray(FRAMES[0])
        frame[PIM_START] = 0x10
        packet = decode_frame(bytes(frame), lax=True)
        assert [type(layer) for layer in packet] == [Ethernet, IPv4]
        assert isinstance(packet.stopped_by, InvalidFieldError)
        assert packet.stopped_by.frame_offset == PIM_START


class TestConstruction:
    @pytest.mark.parametrize(
        "field,value",
        [("type", 16), ("type", -1), ("reserved", 256), ("checksum", 0x10000)],
    )
    def test_header_fields_are_range_checked(self, field, value):
        """Test header fields are range checked."""
        with pytest.raises(InvalidFieldError) as excinfo:
            PIM(**{field: value})
        assert excinfo.value.field == field

    def test_defaults_build_an_empty_hello(self):
        """Test defaults build an empty hello."""
        assert bytes(PIM()) == b"\x20\x00\x00\x00"

    @pytest.mark.parametrize(
        "family,encoding,address,field",
        [
            (3, 0, "10.0.0.1", "family"),
            (1, 1, "10.0.0.1", "encoding"),
            (1, 0, "2001:db8::1", "address"),
            (2, 0, "10.0.0.1", "address"),
            (1, 0, "not an address", "address"),
        ],
    )
    def test_encoded_addresses_check_family_encoding_and_address(
        self, family, encoding, address, field
    ):
        """Test encoded addresses check family, encoding and address."""
        for build in (
            lambda: PIMEncodedUnicast(family, encoding, address),
            lambda: PIMEncodedGroup(family, encoding, 0, 32, address),
            lambda: PIMEncodedSource(family, encoding, 4, 32, address),
        ):
            with pytest.raises(InvalidFieldError) as excinfo:
                build()
            assert excinfo.value.field == field

    @pytest.mark.parametrize("field", ["flags", "mask_len"])
    def test_group_and_source_bytes_are_range_checked(self, field):
        """Test group and source bytes are range checked."""
        for cls in (PIMEncodedGroup, PIMEncodedSource):
            values = {
                "family": 1,
                "encoding": 0,
                "flags": 0,
                "mask_len": 32,
                "address": G1,
            }
            values[field] = 256
            with pytest.raises(InvalidFieldError) as excinfo:
                cls(**values)
            assert excinfo.value.field == field

    def test_message_limits(self):
        """Test message limits."""
        with pytest.raises(InvalidFieldError) as excinfo:
            PIMHelloOption(0x10000)
        assert excinfo.value.field == "type"
        with pytest.raises(InvalidFieldError) as excinfo:
            PIMHelloOption(1, bytes(0x10000))
        assert excinfo.value.field == "value"
        with pytest.raises(InvalidFieldError) as excinfo:
            PIMJoinPrune(unicast(R1), 210, (PIMGroupSet(group(G1)),) * 256)
        assert excinfo.value.field == "groups"
        with pytest.raises(InvalidFieldError) as excinfo:
            PIMJoinPrune(unicast(R1), 0x10000)
        assert excinfo.value.field == "holdtime"
        with pytest.raises(InvalidFieldError) as excinfo:
            PIMGroupSet(group(G1), joined=(source(SOURCE, SPT),) * 0x10000)
        assert excinfo.value.field == "joined"
        with pytest.raises(InvalidFieldError) as excinfo:
            PIMRegister(reserved=1 << 30)
        assert excinfo.value.field == "reserved"
        with pytest.raises(InvalidFieldError) as excinfo:
            PIMAssert(group(G1), unicast(SOURCE), False, 1 << 31, 0)
        assert excinfo.value.field == "metric_preference"

    def test_built_messages_decode_back(self):
        """Each typed message's bytes, as a body, parse back to it."""
        messages = {
            0: PIMHello((PIMHelloOption(1, b"\x00\x69"), PIMHelloOption(26))),
            1: PIMRegister(null_register=True, packet=bytes(20)),
            2: PIMRegisterStop(group(G1), unicast(SOURCE)),
            3: join_prune(G2, (source(R1, WC_RPT),), (source(SOURCE, RPT),)),
            5: PIMAssert(group(G1), unicast(SOURCE), True, 0x7FFFFFFF, 7),
            6: join_prune(G1, (source(SOURCE, SPT),)),
            7: join_prune(G1, (source(SOURCE, SPT),)),
        }
        for type_, message in messages.items():
            pim = PIM.decode(bytes(PIM(type=type_, body=bytes(message))))
            assert pim.message == message, type_

    def test_graft_and_graft_ack_name_their_type(self):
        """Test graft and graft ack name their type."""
        assert PIM(type=6).type_name == "Graft"
        assert PIM(type=7).type_name == "Graft-Ack"


class TestAssert:
    """An Assert built from RFC 7761 §4.9.6.

    No capture holds one: it needs two forwarders on one LAN.
    """

    RAW = bytes.fromhex(
        "25000000"  # PIMv2 Assert, reserved, checksum 0
        "01000020efb80001"  # group 239.184.0.1/32
        "01000ab80102"  # source 10.184.1.2
        "80000078"  # R=1, metric preference 120
        "0000000a"  # metric 10
    )

    def test_decode(self):
        """Test decode."""
        message = PIM.decode(self.RAW).message
        assert message == PIMAssert(
            group(G1),
            unicast(SOURCE),
            rpt=True,
            metric_preference=120,
            metric=10,
        )
        assert bytes(PIM.decode(self.RAW)) == self.RAW

    def test_a_cut_metric_raises(self):
        """Test a cut metric raises."""
        with pytest.raises(TruncatedHeaderError):
            _ = PIM.decode(self.RAW[:-1]).message


class TestRawMessageTypes:
    """Types without a typed message decode whole, with the body raw."""

    @pytest.mark.parametrize(
        "type_,name",
        [
            (4, "Bootstrap"),
            (8, "Candidate-RP-Advertisement"),
            (9, "State Refresh"),
            (10, "unknown (10)"),
            (15, "unknown (15)"),
        ],
    )
    def test_body_kept_whole(self, type_, name):
        """Test body kept whole."""
        body = b"\x00\x01\x02\x03" + bytes(6)
        pim = PIM.decode(bytes([0x20 | type_, 0, 0x12, 0x34]) + body)
        assert pim.body == body
        assert pim.message is None
        assert pim.type_name == name
        assert pim.checksum_hex_str == "0x1234"


class TestEncodedAddresses:
    def test_ipv6_encodings(self):
        """Size IPv6 native encodings (family 2) at 16 bytes.

        That holds whatever IP family carries the message.
        """
        message = PIMJoinPrune(
            upstream_neighbor=unicast("fe80::1"),
            holdtime=210,
            groups=(
                PIMGroupSet(
                    group("ff3e::8000:1"),
                    joined=(source("2001:db8::10", SPT),),
                    pruned=(source("2001:db8::20", RPT),),
                ),
            ),
        )
        body = bytes(message)
        assert len(body) == (2 + 16) + 4 + (4 + 16) + 4 + 2 * (4 + 16)
        assert PIM(type=3, body=body).message == message

    @pytest.mark.parametrize(
        "family,encoding", [(0, 0), (3, 0), (1, 1), (2, 1)]
    )
    def test_an_unknown_family_or_encoding_cannot_be_sized(
        self, family, encoding
    ):
        """Raise for a family or encoding type that cannot be sized.

        Encoding type 1 is defined only for an Encoded-Source (RFC
        5384); this address is the Register-Stop's Encoded-Group.
        """
        raw = bytearray(message_bytes(2))
        raw[4:6] = bytes((family, encoding))
        pim = PIM.decode(bytes(raw) + bytes(4))
        assert pim.header_len == len(raw) + 4
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = pim.message
        assert (excinfo.value.field, excinfo.value.offset) == ("body", 0)

    def test_a_join_attribute_source_is_not_supported(self):
        """Report RFC 5384's type 1 Encoded-Source, never guess past it.

        Its join attributes are TLVs ending at the one with the E bit
        set (§3.4.1), so it could be sized; it is out of scope.
        """
        raw = bytearray(message_bytes(4))
        source_offset = 6 + 4 + 8 + 4
        raw[4 + source_offset + 1] = 1
        with pytest.raises(InvalidFieldError) as excinfo:
            _ = PIM.decode(bytes(raw)).message
        assert excinfo.value.offset == source_offset

    def test_flag_bits(self):
        """Test flag bits."""
        assert PIMEncodedGroup(1, 0, 0x81, 4, "224.0.0.0").bidirectional
        assert PIMEncodedGroup(1, 0, 0x81, 4, "224.0.0.0").admin_scope
        assert not PIMEncodedSource(1, 0, 0x04, 32, SOURCE).wildcard

    def test_reserved_flag_bits_round_trip(self):
        """Test reserved flag bits round trip."""
        built = PIMEncodedSource(1, 0, 0xFF, 32, SOURCE)
        message = join_prune(G1, joined=(built,))
        assert PIM(type=3, body=bytes(message)).message == message


class TestHelloOptions:
    def hello(self, *options: PIMHelloOption) -> PIMHello:
        """Build a Hello from ``options`` and parse it back."""
        message = PIM(body=b"".join(map(bytes, options))).message
        assert isinstance(message, PIMHello)
        return message

    def test_an_absent_option_is_none(self):
        """Test an absent option is none."""
        hello = self.hello()
        assert hello.options == ()
        for name in (
            "holdtime",
            "lan_prune_delay",
            "dr_priority",
            "generation_id",
            "address_list",
        ):
            assert getattr(hello, name) is None

    @pytest.mark.parametrize(
        "option_type,name",
        [
            (1, "holdtime"),
            (2, "lan_prune_delay"),
            (19, "dr_priority"),
            (20, "generation_id"),
        ],
    )
    def test_a_value_of_the_wrong_length_raises(self, option_type, name):
        """Test a value of the wrong length raises."""
        hello = self.hello(PIMHelloOption(option_type, b"\x00\x00\x00"))
        with pytest.raises(InvalidFieldError) as excinfo:
            getattr(hello, name)
        assert excinfo.value.expected in (2, 4)
        assert excinfo.value.actual == 3

    def test_the_first_option_of_a_type_wins(self):
        """Test the first option of a type wins."""
        hello = self.hello(
            PIMHelloOption(1, b"\x00\x1e"), PIMHelloOption(1, b"\xff\xff")
        )
        assert hello.holdtime == 30

    def test_lan_prune_delay_t_bit(self):
        """Test lan prune delay t bit."""
        hello = self.hello(PIMHelloOption(2, b"\x81\xf4\x09\xc4"))
        assert hello.lan_prune_delay == PIMLANPruneDelay(True, 500, 2500)

    def test_an_ipv6_address_list(self):
        """Test an ipv6 address list."""
        addresses = (unicast("2001:db8::1"), unicast("2001:db8::2"))
        hello = self.hello(PIMHelloOption(24, b"".join(map(bytes, addresses))))
        assert hello.address_list == addresses

    def test_a_cut_address_list_raises(self):
        """Test a cut address list raises."""
        hello = self.hello(PIMHelloOption(24, bytes(unicast(R1))[:-1]))
        with pytest.raises(TruncatedHeaderError) as excinfo:
            _ = hello.address_list
        assert excinfo.value.offset == 0

    def test_option_names(self):
        """Test option names."""
        assert PIMHelloOption(26).type_name == "Join Attribute"
        assert PIMHelloOption(22).type_name == "Bidirectional Capable"
        assert PIMHelloOption(65001).type_name == "unknown (65001)"

    def test_a_zero_option_before_others_is_an_option(self):
        """Keep an empty type-0 option followed by another.

        Only an all-zero remainder is padding.
        """
        hello = self.hello(PIMHelloOption(0), PIMHelloOption(1, b"\x00\x1e"))
        assert hello.options == (
            PIMHelloOption(0),
            PIMHelloOption(1, b"\x00\x1e"),
        )

    def test_options_after_the_walk_are_bytes_of_the_hello(self):
        """Test options after the walk are bytes of the hello."""
        hello = self.hello(PIMHelloOption(1, b"\x00\x1e"))
        assert bytes(hello) == b"\x00\x01\x00\x02\x00\x1e"


class _SliceCountingBytes(bytes):
    """Bytes that count how many bytes their slices and indexes return."""

    read = 0

    def __getitem__(self, key):
        """Return ``bytes(self)[key]``, adding its length to the count."""
        result = bytes(self)[key]
        type(self).read += len(result) if isinstance(key, slice) else 1
        return result


class TestHelloCost:
    """A Hello made of empty type-0 options, the worst case for the walk.

    Each such option is where padding could start, so the parser must
    know whether only zero bytes follow it; rescanning the rest of the
    body for that at every option made decode and :attr:`PIM.message`
    quadratic (a 64 KB Hello took seconds). A wall-clock bound would be
    flaky under coverage tracing and on slow runners, so the cost is
    counted instead: the bytes the parser reads out of the body by
    slicing and indexing must stay linear in its length.
    """

    COUNT = 16000
    BODY = bytes(4) * COUNT + b"\x00\x01\x00\x00"

    def test_a_64_kb_hello_of_empty_options_decodes(self):
        """Decode it whole: the options run to the last, nonzero one."""
        pim = PIM.decode(b"\x20\x00\x00\x00" + self.BODY)
        assert pim.header_len == 4 + len(self.BODY) == 64008
        hello = pim.message
        assert isinstance(hello, PIMHello)
        assert len(hello.options) == self.COUNT + 1
        assert hello.options[-1] == PIMHelloOption(1)

    @pytest.mark.parametrize("tail", [b"", bytes(6)], ids=["bare", "padded"])
    def test_the_walk_reads_the_body_a_bounded_number_of_times(self, tail):
        """Read the body's bytes a bounded number of times, padded or not."""
        body = _SliceCountingBytes(self.BODY + tail)
        _SliceCountingBytes.read = 0
        hello = PIM(body=body).message
        assert isinstance(hello, PIMHello)
        assert len(hello.options) == self.COUNT + 1
        assert _SliceCountingBytes.read <= 4 * len(body)


def ipv6_frame(pim: PIM, src: str = "fe80::1", dst: str = "ff02::d") -> bytes:
    """Build an Ethernet/IPv6 frame carrying ``pim``, checksum correct.

    The checksum is computed here with :func:`ones_complement_checksum`
    over the RFC 8200 §8.1 pseudo-header: the covered length is the
    message's, or 8 for a Register (RFC 7761 §4.9).
    """
    message = bytes(replace(pim, checksum=0))
    covered = message[:8] if pim.type == 1 else message
    pseudo = (
        IPv6Address(src).packed
        + IPv6Address(dst).packed
        + struct.pack("!I3xB", len(covered), 103)
    )
    checksum = ones_complement_checksum(pseudo + covered)
    message = message[:2] + struct.pack("!H", checksum) + message[4:]
    ip = IPv6(
        version=6,
        traffic_class=0,
        flow_label=0,
        payload_length=len(message),
        next_header=103,
        hop_limit=1,
        src=src,
        dst=dst,
    )
    eth = Ethernet(
        dst="33:33:00:00:00:0d", src="02:00:00:00:00:01", ethertype=0x86DD
    )
    return bytes(eth) + bytes(ip) + message


IPV6_HELLO = PIM(
    type=0,
    body=bytes(
        PIMHello(
            (
                PIMHelloOption(1, b"\x00\x69"),
                PIMHelloOption(20, b"\x12\x34\x56\x78"),
                PIMHelloOption(24, bytes(unicast("2001:db8::1"))),
            )
        )
    ),
)
IPV6_JOIN = PIM(
    type=3,
    body=bytes(
        PIMJoinPrune(
            unicast("fe80::2"),
            210,
            (PIMGroupSet(group("ff3e::1"), (source("2001:db8::10", SPT),)),),
        )
    ),
)
IPV6_REGISTER = PIM(
    type=1,
    body=bytes(
        PIMRegister(packet=bytes.fromhex("6000000000001140") + bytes(32))
    ),
)


class TestIPv6:
    """Built IPv6 frames.

    The capture host cannot send IPv6 (see the module docstring).
    """

    @pytest.mark.parametrize(
        "pim",
        [IPV6_HELLO, IPV6_JOIN, IPV6_REGISTER],
        ids=["hello", "join", "register"],
    )
    def test_ipv6_next_header_103_dispatches_to_pim(self, pim):
        """Test ipv6 next header 103 dispatches to pim."""
        frame = ipv6_frame(pim)
        packet = decode_frame(frame)
        assert [type(layer) for layer in packet] == [Ethernet, IPv6, PIM]
        assert packet[PIM].body == pim.body
        assert bytes(packet) == frame

    @pytest.mark.parametrize(
        "pim",
        [IPV6_HELLO, IPV6_JOIN, IPV6_REGISTER],
        ids=["hello", "join", "register"],
    )
    def test_the_pseudo_header_checksum(self, pim):
        """Test the pseudo header checksum."""
        packet = decode_frame(ipv6_frame(pim))
        assert verify(packet[PIM], ip=packet[IPv6])
        assert compute(packet[PIM], ip=packet[IPv6]) == packet[PIM].checksum
        # The addresses are covered: another source fails.
        other = replace(packet[IPv6], src="fe80::99")
        assert not verify(packet[PIM], ip=other)

    def test_an_ipv4_sum_does_not_verify_over_ipv6(self):
        """Test an ipv4 sum does not verify over ipv6."""
        packet = decode_frame(ipv6_frame(IPV6_HELLO))
        message = bytes(replace(packet[PIM], checksum=0))
        bare = replace(packet[PIM], checksum=ones_complement_checksum(message))
        assert not verify(bare, ip=packet[IPv6])

    def test_an_ipv6_register_encapsulates_ipv6(self):
        """Test an ipv6 register encapsulates ipv6."""
        packet = decode_frame(ipv6_frame(IPV6_REGISTER))
        register = packet[PIM].message
        assert isinstance(register, PIMRegister)
        inner = register.encapsulated
        assert isinstance(inner[0], IPv6)
        assert inner[IPv6].next_header == 17

    def test_with_checksums_fills_the_pseudo_header_checksum(self):
        """Test with checksums fills the pseudo header checksum."""
        packet = decode_frame(ipv6_frame(IPV6_JOIN))
        zeroed = Packet(
            packet[Ethernet], packet[IPv6], replace(packet[PIM], checksum=0)
        )
        assert zeroed.with_checksums() == packet

    def test_pim_behind_an_ipv6_extension_header(self):
        """Decode PIM behind a Hop-by-Hop header.

        PIM Hellos carry no Router Alert, but nothing stops a header
        between IPv6 and PIM; the v6 table inherits 103.
        """
        frame = bytearray(ipv6_frame(IPV6_HELLO))
        hop_by_hop = IPv6HopByHopOptions(
            next_header=103, hdr_ext_len=0, options=b"\x01\x04" + bytes(4)
        )
        frame[14 + 6] = 0  # IPv6 next header: Hop-by-Hop
        frame[14 + 4 : 14 + 6] = struct.pack("!H", len(frame) - 54 + 8)
        frame[54:54] = bytes(hop_by_hop)
        packet = decode_frame(bytes(frame))
        assert [type(layer) for layer in packet] == [
            Ethernet,
            IPv6,
            IPv6HopByHopOptions,
            PIM,
        ]
        assert packet[PIM].body == IPV6_HELLO.body

    def test_the_ipv6_message_body_parses(self):
        """Test the ipv6 message body parses."""
        packet = decode_frame(ipv6_frame(IPV6_HELLO))
        hello = packet[PIM].message
        assert isinstance(hello, PIMHello)
        assert hello.address_list == (unicast("2001:db8::1"),)


class TestDispatch:
    def test_protocol_number_and_display_name(self):
        """Test protocol number and display name."""
        assert IPProtocol.PIM == 103
        assert IPProtocol.PIM.display_name == "PIM"

    @pytest.mark.parametrize("table", [TABLE_IP_PROTO, TABLE_IP_PROTO_V6])
    def test_both_ip_tables_carry_it(self, table):
        """Test both ip tables carry it."""
        assert DEFAULT.get(table, 103) is PIM

    def test_pim_ends_the_chain(self):
        """Test pim ends the chain."""
        assert pim_of(3).next_protocol() is None


def _load_checker() -> ModuleType:
    path = Path(__file__).parent.parent / "scripts" / "check_fixtures.py"
    spec = importlib.util.spec_from_file_location("check_fixtures", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


class TestIndependentChecker:
    """The independent checker, scripts/check_fixtures.py, on PIM.

    It shares no code with this library: every captured frame passes,
    and tampering fails.
    """

    checker = _load_checker()

    def check(self, frame: bytes) -> tuple[list[str], dict[str, int]]:
        """Run the checker on one frame; return its failures and stats."""
        stats: Counter[str] = Counter()
        return self.checker.check_frame(frame, stats), dict(stats)

    def test_every_captured_frame_passes(self):
        """Test every captured frame passes."""
        for frame in FRAMES:
            failures, stats = self.check(frame)
            assert failures == []
            assert stats["pim"] >= 1

    def test_the_registers_encapsulated_packets_are_checked(self):
        """Test the registers encapsulated packets are checked."""
        _, stats = self.check(FRAMES[3])
        assert (stats["pim-register"], stats["udp"]) == (1, 1)
        _, stats = self.check(FRAMES[7])
        assert stats["pim-null-register-unchecked"] == 1

    @pytest.mark.parametrize("index", range(13))
    def test_a_flipped_message_byte_fails(self, index):
        """Test a flipped message byte fails."""
        frame = bytearray(FRAMES[index])
        frame[PIM_START + 5] ^= 0x01
        failures, _ = self.check(bytes(frame))
        assert failures == ["pim-checksum"]

    def test_a_flipped_encapsulated_byte_fails_the_inner_check(self):
        """Test a flipped encapsulated byte fails the inner check."""
        frame = bytearray(FRAMES[3])
        frame[-1] ^= 0x01
        failures, _ = self.check(bytes(frame))
        assert failures == ["udp-checksum"]

    def test_a_register_summed_whole_passes(self):
        """Test a register summed whole passes."""
        frame = bytearray(FRAMES[3])
        message = bytes(frame[PIM_START:])
        whole = ones_complement_checksum(
            message[:2] + b"\x00\x00" + message[4:]
        )
        frame[PIM_START + 2 : PIM_START + 4] = struct.pack("!H", whole)
        assert self.check(bytes(frame))[0] == []

    @pytest.mark.parametrize(
        "pim",
        [IPV6_HELLO, IPV6_JOIN, IPV6_REGISTER],
        ids=["hello", "join", "register"],
    )
    def test_ipv6_frames(self, pim):
        """Test ipv6 frames."""
        frame = ipv6_frame(pim)
        assert self.check(frame)[0] == []
        tampered = bytearray(frame)
        tampered[14 + 8] ^= 0x01  # the IPv6 source address
        assert self.check(bytes(tampered))[0] == ["pim-checksum"]

    def test_another_version_fails(self):
        """Test another version fails."""
        frame = bytearray(FRAMES[0])
        frame[PIM_START] = 0x10
        assert self.check(bytes(frame))[0] == ["pim-version"]

    @staticmethod
    def ipv6_null_register(source_address: str, dummy_len: int = 4) -> bytes:
        """Build an IPv6 Null-Register as RFC 7761 §4.9.3 describes it.

        Its packet is a dummy IPv6 header from ``source_address`` to
        ``ff3e::1`` (next header 103, payload length 4) and the dummy PIM
        header after it, cut to ``dummy_len`` bytes: version, type and
        reserved zero, its checksum over the pseudo-header of that
        source and group, computed here.
        """
        src = IPv6Address(source_address).packed
        grp = IPv6Address("ff3e::1").packed
        pseudo = src + grp + struct.pack("!I3xB", 4, 103)
        dummy_pim = struct.pack(
            "!HH", 0, ones_complement_checksum(pseudo + bytes(4))
        )
        header = struct.pack("!IHBB", 6 << 28, 4, 103, 255) + src + grp
        packet = header + dummy_pim[:dummy_len]
        register = PIMRegister(null_register=True, packet=packet)
        return ipv6_frame(PIM(type=1, body=bytes(register)))

    #: Sources whose third and fourth bytes (the dummy IPv6 header's
    #: bytes 10-11, an IPv4 header's checksum) are nonzero and zero.
    NULL_REGISTER_SOURCES = ["2001:db8::10", "::1"]

    @pytest.mark.parametrize("source_address", NULL_REGISTER_SOURCES)
    def test_an_ipv6_null_registers_dummy_pim_header_is_checked(
        self, source_address
    ):
        """Check the dummy PIM header's checksum, not parse it as PIM."""
        frame = self.ipv6_null_register(source_address)
        failures, stats = self.check(frame)
        assert failures == []
        assert stats["pim"] == 1
        assert stats["pim-null-register-v6"] == 1
        assert "pim-null-register-unchecked" not in stats
        for offset in (-1, -6):  # its checksum; the dummy header's group
            tampered = bytearray(frame)
            tampered[offset] ^= 0x01
            failures, _ = self.check(bytes(tampered))
            assert failures == ["pim-null-register-checksum"]

    def test_an_ipv6_null_register_without_a_dummy_pim_header(self):
        """Pass one without the dummy PIM header, which has no checksum.

        RFC 7761 §4.9.3 checks it only "if the dummy PIM header is
        present".
        """
        frame = self.ipv6_null_register("2001:db8::10", dummy_len=0)
        failures, stats = self.check(frame)
        assert failures == []
        assert stats["pim-null-register-unchecked"] == 1

    def test_an_ipv6_null_registers_cut_dummy_pim_header(self):
        """Count a dummy PIM header cut short as truncated."""
        frame = self.ipv6_null_register("2001:db8::10", dummy_len=2)
        failures, stats = self.check(frame)
        assert failures == []
        assert stats["pim-null-register-truncated"] == 1
