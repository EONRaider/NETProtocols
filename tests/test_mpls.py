"""Test MPLS label stacks (RFC 3032 §2.1).

The entries, the stack as one layer, the payload convention, the walk
through Ethernet, VLAN and GRE, the bounds on a stack whose bottom
never comes, the captured corpus and the independent checker.
"""

import importlib.util
import struct
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType

import pytest

import netprotocols.layer2.mpls as mpls_module
from conftest import FIXTURES, pcap_frames
from netprotocols import (
    GRE,
    MPLS,
    UDP,
    VLAN,
    Ethernet,
    EtherType,
    ICMPv4,
    ICMPv6,
    InvalidFieldError,
    IPv4,
    IPv6,
    MPLSLabel,
    Packet,
    Protocol,
    TruncatedHeaderError,
    decode_frame,
    verify,
)
from netprotocols.registry import DEFAULT, TABLE_ETHERTYPE
from test_ipip import echo_v4, echo_v6, make_ipv4, make_ipv6


def entry(label: int, *, bottom: int = 0, tc: int = 0, ttl: int = 64) -> bytes:
    """Pack one 4-byte label stack entry."""
    return struct.pack("!I", (label << 12) | (tc << 9) | (bottom << 8) | ttl)


def stack(*labels: int) -> bytes:
    """Pack a label stack of ``labels``, top first, S on the last."""
    return b"".join(
        entry(label, bottom=int(i == len(labels) - 1))
        for i, label in enumerate(labels)
    )


def built(*labels: int) -> MPLS:
    """Decode the :class:`MPLS` layer :func:`stack` encodes."""
    return MPLS.decode(stack(*labels))


def ethernet(ethertype: int, dst: str = "02:00:00:00:00:02") -> Ethernet:
    """Build an Ethernet header between two local MACs."""
    return Ethernet(dst=dst, src="02:00:00:00:00:01", ethertype=ethertype)


def icmp_packet() -> bytes:
    """Build an IPv4 ICMP echo, checksums computed."""
    icmp = echo_v4()
    ip = make_ipv4(protocol=1, payload_len=8 + len(icmp.body))
    return bytes(Packet(ip, icmp).with_checksums())


def icmpv6_packet() -> bytes:
    """Build an IPv6 ICMPv6 echo, checksum computed."""
    icmp = echo_v6()
    ip = make_ipv6(next_header=58, payload_len=8 + len(icmp.body))
    return bytes(Packet(ip, icmp).with_checksums())


def labelled(payload: bytes, *labels: int, ethertype: int = 0x8847) -> bytes:
    """Build an Ethernet frame carrying ``payload`` under labels."""
    return bytes(ethernet(ethertype)) + stack(*labels) + payload


def kinds(packet: Packet) -> list[type[Protocol]]:
    """List the classes of a packet's layers."""
    return [type(layer) for layer in packet.layers]


class TestLabelEntry:
    """One label stack entry: fields, packing and names."""

    def test_from_word_splits_the_fields(self):
        """Split a word into its four fields."""
        # Label 0x12345; then 0xB = 101 1: traffic class 5, S set; TTL.
        label = MPLSLabel.from_word(0x12345_B_FF)
        assert label == MPLSLabel(
            label=0x12345, traffic_class=0b101, bottom_of_stack=1, ttl=0xFF
        )

    def test_the_word_and_bytes_pack_the_fields_back(self):
        """Pack the fields back into the word and 4 bytes."""
        label = MPLSLabel(
            label=0xABCDE, traffic_class=3, bottom_of_stack=1, ttl=7
        )
        assert label.word == 0xABCDE_7_07
        assert bytes(label) == b"\xab\xcd\xe7\x07"
        assert MPLSLabel.from_word(label.word) == label

    @pytest.mark.parametrize(
        "field,value,top",
        [
            ("label", 1 << 20, 0xFFFFF),
            ("label", -1, 0xFFFFF),
            ("traffic_class", 8, 7),
            ("bottom_of_stack", 2, 1),
            ("ttl", 256, 0xFF),
        ],
    )
    def test_out_of_range_fields_are_rejected(self, field, value, top):
        """Reject each field one past its width."""
        fields = {"label": 16, "traffic_class": 0, "bottom_of_stack": 1}
        fields["ttl"] = 64
        fields[field] = value
        with pytest.raises(InvalidFieldError) as excinfo:
            MPLSLabel(**fields)
        assert excinfo.value.field == field
        assert excinfo.value.expected == f"0-{top}"
        assert excinfo.value.actual == value
        assert excinfo.value.protocol is MPLSLabel

    def test_the_widest_values_are_accepted(self):
        """Accept every field at its widest."""
        label = MPLSLabel(
            label=0xFFFFF, traffic_class=7, bottom_of_stack=1, ttl=255
        )
        assert bytes(label) == b"\xff\xff\xff\xff"

    @pytest.mark.parametrize(
        "value,name",
        [
            (0, "IPv4 Explicit NULL Label"),
            (1, "Router Alert Label"),
            (2, "IPv6 Explicit NULL Label"),
            (3, "Implicit NULL Label"),
            (4, "MPLS Network Actions"),
            (7, "Entropy Label Indicator (ELI)"),
            (13, "Generic Associated Channel Label"),
            (14, "OAM Alert Label"),
            (15, "Extension Label (XL)"),
        ],
    )
    def test_special_purpose_labels_are_named_as_iana_names_them(
        self, value, name
    ):
        """Name each assigned special-purpose label as IANA does."""
        label = MPLSLabel(
            label=value, traffic_class=0, bottom_of_stack=1, ttl=1
        )
        assert label.label_name == name
        assert label.is_special_purpose

    @pytest.mark.parametrize("value", [5, 6, 8, 9, 10, 11, 12])
    def test_unassigned_special_purpose_labels_have_no_name(self, value):
        """Leave the unassigned special-purpose labels unnamed."""
        label = MPLSLabel(
            label=value, traffic_class=0, bottom_of_stack=1, ttl=1
        )
        assert label.label_name is None
        assert label.is_special_purpose

    @pytest.mark.parametrize("value", [16, 1000, 0xFFFFF])
    def test_ordinary_labels_are_not_special_purpose(self, value):
        """Leave labels from 16 up unnamed and ordinary."""
        label = MPLSLabel(
            label=value, traffic_class=0, bottom_of_stack=1, ttl=1
        )
        assert label.label_name is None
        assert not label.is_special_purpose


class TestDecode:
    """Decoding a stack: entries, bounds and decode context."""

    def test_a_single_label(self):
        """Decode a one-entry stack."""
        raw = entry(0x12345, bottom=1, tc=5, ttl=63)
        mpls = MPLS.decode(raw + icmp_packet())
        assert mpls.labels == (
            MPLSLabel(
                label=0x12345, traffic_class=5, bottom_of_stack=1, ttl=63
            ),
        )
        assert mpls.bottom is mpls.labels[0]
        assert mpls.header_len == 4
        assert bytes(mpls) == raw

    def test_a_three_label_stack_top_first(self):
        """Decode a three-entry stack, top first."""
        raw = stack(16001, 7, 0xABCDE)
        mpls = MPLS.decode(raw + icmp_packet())
        assert [e.label for e in mpls.labels] == [16001, 7, 0xABCDE]
        assert [e.bottom_of_stack for e in mpls.labels] == [0, 0, 1]
        assert mpls.bottom.label == 0xABCDE
        assert mpls.header_len == 12
        assert bytes(mpls) == raw

    @pytest.mark.parametrize("depth", [1, 2, 3, 8])
    def test_round_trips_both_ways(self, depth):
        """Round-trip wire to object and object to wire."""
        raw = stack(*range(100, 100 + depth)) + icmp_packet()
        mpls = MPLS.decode(raw)
        assert bytes(mpls) == raw[: mpls.header_len]
        assert MPLS.decode(bytes(mpls)) == mpls

    def test_the_stack_ends_at_the_first_bottom_entry(self):
        """Entries after the bottom of stack are the payload's bytes."""
        raw = stack(100) + stack(200, 300)
        mpls = MPLS.decode(raw)
        assert [e.label for e in mpls.labels] == [100]

    @pytest.mark.parametrize(
        "trailer", [bytes(18), b"\xde\xad\xbe\xef", bytes(10) + b"\x01\x02"]
    )
    def test_padding_and_an_fcs_stay_out_of_the_stack(self, trailer):
        """Leave padding and an FCS after the stack undecoded."""
        raw = stack(100, 200)
        mpls = MPLS.decode(raw + icmp_packet() + trailer)
        assert mpls.header_len == 8
        assert bytes(mpls) == raw

    def test_memoryview_is_accepted_and_not_retained(self):
        """Decode a memoryview without keeping a view of it."""
        buffer = bytearray(stack(100, 200) + icmp_packet())
        mpls = MPLS.decode(memoryview(buffer))
        expected = MPLS.decode(bytes(buffer))
        buffer[:] = bytes(len(buffer))
        assert mpls == expected
        assert mpls.next_protocol() is IPv4
        assert all(type(e.label) is int for e in mpls.labels)
        assert type(mpls.labels) is tuple

    def test_equality_and_hash_ignore_the_payload(self):
        """Compare and hash stacks without their payload.

        The payload sniff is decode context: equal stacks compare and
        hash equal wherever they were found, and still chain apart.
        """
        as_ipv4 = MPLS.decode(stack(100) + icmp_packet())
        as_ipv6 = MPLS.decode(stack(100) + icmpv6_packet())
        as_cw = MPLS.decode(stack(100) + bytes(4))
        constructed = MPLS(labels=as_ipv4.labels)
        assert as_ipv4 == as_ipv6 == as_cw == constructed
        assert len({as_ipv4, as_ipv6, as_cw, constructed}) == 1
        assert as_ipv4.next_protocol() is IPv4
        assert as_ipv6.next_protocol() is IPv6
        assert as_cw.next_protocol() is None
        assert constructed.next_protocol() is None

    def test_the_sniff_is_not_in_the_repr(self):
        """Keep the decode context out of the repr."""
        assert "nibble" not in repr(built(100))


class TestConstruction:
    """Building a stack: what the constructor accepts."""

    def test_an_empty_stack_is_rejected(self):
        """Reject a stack of no entries."""
        with pytest.raises(InvalidFieldError) as excinfo:
            MPLS(labels=())
        assert excinfo.value.field == "labels"
        assert excinfo.value.protocol is MPLS

    @pytest.mark.parametrize(
        "flags", [[0], [1, 1], [0, 0], [1, 0], [0, 1, 1], [1, 0, 1]]
    )
    def test_s_must_be_set_on_the_last_entry_alone(self, flags):
        """Reject S bits anywhere but on the last entry alone."""
        labels = tuple(
            MPLSLabel(label=100, traffic_class=0, bottom_of_stack=f, ttl=1)
            for f in flags
        )
        with pytest.raises(InvalidFieldError) as excinfo:
            MPLS(labels=labels)
        assert excinfo.value.field == "labels"
        assert excinfo.value.actual == flags

    def test_a_built_stack_round_trips(self):
        """Round-trip a stack built from entries."""
        labels = (
            MPLSLabel(label=16, traffic_class=1, bottom_of_stack=0, ttl=255),
            MPLSLabel(label=2, traffic_class=0, bottom_of_stack=1, ttl=1),
        )
        mpls = MPLS(labels=labels)
        assert MPLS.decode(bytes(mpls)) == mpls
        assert bytes(mpls) == b"".join(map(bytes, labels))

    def test_positional_patterns_bind_the_stack(self):
        """Match a stack with positional patterns."""
        match built(100, 0):
            case MPLS((MPLSLabel(label=top), MPLSLabel(label=0))):
                assert top == 100
            case _:
                pytest.fail("the stack did not match")


class TestTruncation:
    """A stack the buffer ends before its bottom entry."""

    @pytest.mark.parametrize("length", [0, 1, 2, 3])
    def test_a_buffer_shorter_than_an_entry_raises(self, length):
        """Raise on a buffer shorter than one entry."""
        with pytest.raises(TruncatedHeaderError) as excinfo:
            MPLS.decode(entry(100, bottom=1)[:length])
        error = excinfo.value
        assert (error.field, error.offset) == ("labels", 0)
        assert (error.expected, error.actual) == (4, length)
        assert error.protocol is MPLS

    @pytest.mark.parametrize("cut", [0, 1, 3])
    def test_a_stack_without_its_bottom_raises_where_it_would_start(self, cut):
        """Raise where the missing bottom entry would start."""
        raw = entry(100) + entry(200) + entry(300, bottom=1)[:cut]
        with pytest.raises(TruncatedHeaderError) as excinfo:
            MPLS.decode(raw)
        error = excinfo.value
        assert (error.field, error.offset) == ("labels", 8)
        assert (error.expected, error.actual) == (12, 8 + cut)

    def test_a_cut_stack_is_reported_at_its_frame_offset(self):
        """Report a cut stack at its frame offset; keep Ethernet in lax mode."""
        frame = bytes(ethernet(0x8847)) + entry(100) + entry(200)
        with pytest.raises(TruncatedHeaderError) as excinfo:
            decode_frame(frame)
        assert excinfo.value.frame_offset == 14 + 8
        packet = decode_frame(frame, lax=True)
        assert kinds(packet) == [Ethernet]
        assert isinstance(packet.stopped_by, TruncatedHeaderError)


class _CountingEntry:
    """Stands in for the module's entry ``Struct``, counting reads."""

    def __init__(self) -> None:
        """Wrap the real entry struct."""
        self.offsets: list[int] = []
        self.buffers: set[int] = set()
        self.real = mpls_module._ENTRY
        self.size = self.real.size

    def unpack_from(self, data, offset=0):
        """Record the read, then unpack as the real struct does."""
        self.offsets.append(offset)
        self.buffers.add(id(data))
        return self.real.unpack_from(data, offset)

    def pack(self, *values):
        """Pack as the real struct does."""
        return self.real.pack(*values)


class TestHostileStacks:
    """A hostile stack as long as the buffer.

    A stack has no length: only its S bit ends it, so a hostile
    frame can make one as long as the buffer. Decoding must read each
    entry once, in place: slicing the rest of the buffer at each entry
    would make a 64 KB stack quadratic.
    """

    COUNT = 16000

    def test_a_64_kb_stack_without_a_bottom_raises(self, monkeypatch):
        """Raise on 64 KB of entries with no bottom, reading each once."""
        raw = entry(100) * self.COUNT
        counter = _CountingEntry()
        monkeypatch.setattr(mpls_module, "_ENTRY", counter)
        with pytest.raises(TruncatedHeaderError) as excinfo:
            MPLS.decode(raw)
        assert excinfo.value.offset == 4 * self.COUNT
        # Every entry read once, from the buffer itself, not a slice.
        assert counter.offsets == list(range(0, 4 * self.COUNT, 4))
        assert counter.buffers == {id(raw)}

    def test_a_64_kb_stack_decodes_as_one_layer(self, monkeypatch):
        """Decode 16,000 entries as one layer, reading each once."""
        raw = entry(100) * (self.COUNT - 1) + entry(200, bottom=1)
        counter = _CountingEntry()
        monkeypatch.setattr(mpls_module, "_ENTRY", counter)
        mpls = MPLS.decode(raw + icmp_packet())
        assert len(mpls.labels) == self.COUNT
        assert mpls.header_len == len(raw)
        assert len(counter.offsets) == self.COUNT

    def test_a_deep_stack_is_one_layer_of_the_walk(self):
        """Count a deep stack once against max_depth.

        The whole stack is one layer, so max_depth counts it once.
        """
        frame = labelled(icmp_packet(), *range(100, 1100))
        packet = decode_frame(frame, max_depth=4)
        assert kinds(packet) == [Ethernet, MPLS, IPv4, ICMPv4]
        assert len(packet[MPLS].labels) == 1000


class TestDispatch:
    """The EtherTypes and the payload convention."""

    @pytest.mark.parametrize(
        "ethertype,member,name",
        [
            (0x8847, EtherType.MPLS, "MPLS"),
            (
                0x8848,
                EtherType.MPLS_UPSTREAM_ASSIGNED,
                "MPLS with upstream-assigned label",
            ),
        ],
    )
    def test_both_ethertypes_are_registered(self, ethertype, member, name):
        """Dispatch both MPLS EtherTypes, named as IANA names them."""
        assert EtherType(ethertype) is member
        assert member.display_name == name
        assert DEFAULT.get(TABLE_ETHERTYPE, ethertype) is MPLS
        assert ethernet(ethertype).ethertype_name == name
        assert ethernet(ethertype).next_protocol() is MPLS

    @pytest.mark.parametrize(
        "labels,first_byte,expected",
        [
            ((100,), 0x45, IPv4),
            ((100,), 0x60, IPv6),
            ((100,), 0x4F, IPv4),
            ((100,), 0x00, None),  # pseudowire control word (RFC 4385)
            ((100,), 0x10, None),  # associated channel header (RFC 5586)
            ((100,), 0x50, None),
            ((100,), 0xF0, None),
            ((0,), 0x45, IPv4),
            ((0,), 0x60, IPv4),  # the label settles it
            ((0,), 0x00, IPv4),
            ((2,), 0x60, IPv6),
            ((2,), 0x45, IPv6),
            ((13,), 0x45, None),  # GAL: an ACH follows
            ((14,), 0x60, None),  # OAM Alert: an OAM message follows
            ((1,), 0x45, IPv4),  # Router Alert has no rule of its own
            ((0, 100), 0x60, IPv6),  # only the bottom label counts
            ((100, 2, 16), 0x45, IPv4),
            ((100, 7, 0x54321), 0x45, IPv4),  # ELI, then entropy label
            ((100, 7, 0x54321), 0x60, IPv6),
            ((100, 7, 0x54321, 0), 0x60, IPv4),
        ],
    )
    def test_the_payload_convention(self, labels, first_byte, expected):
        """Name the payload by bottom label, then by first nibble."""
        mpls = MPLS.decode(stack(*labels) + bytes([first_byte]) + bytes(39))
        assert mpls.next_protocol() is expected
        family = {IPv4: EtherType.IPV4, IPv6: EtherType.IPV6, None: None}
        assert mpls.payload_ethertype is family[expected]

    @pytest.mark.parametrize(
        "label,expected", [(100, None), (0, IPv4), (2, IPv6), (13, None)]
    )
    def test_an_empty_payload_leaves_only_the_label(self, label, expected):
        """Answer from the bottom label when no payload follows."""
        assert built(label).next_protocol() is expected

    @pytest.mark.parametrize(
        "label,expected", [(100, None), (0, IPv4), (2, IPv6), (14, None)]
    )
    def test_a_built_stack_answers_from_its_bottom_label(self, label, expected):
        """Answer from the bottom label for a stack never decoded."""
        mpls = MPLS(
            labels=(
                MPLSLabel(
                    label=label, traffic_class=0, bottom_of_stack=1, ttl=1
                ),
            )
        )
        assert mpls.next_protocol() is expected

    def test_the_payload_dispatches_through_the_callers_registry(self):
        """Look the payload up in the registry the caller passes."""
        derived = DEFAULT.derive({TABLE_ETHERTYPE: {0x0800: ICMPv4}})
        mpls = MPLS.decode(stack(100) + icmp_packet())
        assert mpls.next_protocol(derived) is ICMPv4
        assert mpls.next_protocol() is IPv4

    def test_decode_as_reaches_the_labelled_packet(self):
        """Reach the labelled packet with decode_as."""
        frame = labelled(icmp_packet(), 100)
        packet = decode_frame(frame, decode_as={TABLE_ETHERTYPE: {0x0800: UDP}})
        assert kinds(packet) == [Ethernet, MPLS, UDP]


class TestWalk:
    """Frame walks through MPLS, constructed frame by frame."""

    def test_one_label_carrying_ipv4(self):
        """Walk one label to an ICMP echo."""
        frame = labelled(icmp_packet(), 0x12345)
        packet = decode_frame(frame)
        assert kinds(packet) == [Ethernet, MPLS, IPv4, ICMPv4]
        assert packet.consumed == len(frame)
        assert packet[ICMPv4].body == echo_v4().body

    def test_a_three_label_stack_carrying_ipv4(self):
        """Walk three labels to an ICMP echo."""
        frame = labelled(icmp_packet(), 16001, 16002, 16003)
        packet = decode_frame(frame)
        assert kinds(packet) == [Ethernet, MPLS, IPv4, ICMPv4]
        assert len(packet[MPLS].labels) == 3

    def test_ipv6_explicit_null_carrying_ipv6(self):
        """Walk an IPv6 Explicit NULL bottom label to IPv6."""
        frame = labelled(icmpv6_packet(), 100, 2)
        packet = decode_frame(frame)
        assert kinds(packet) == [Ethernet, MPLS, IPv6, ICMPv6]
        assert packet.consumed == len(frame)

    def test_ipv4_explicit_null_carrying_ipv4(self):
        """Walk an IPv4 Explicit NULL bottom label to IPv4."""
        packet = decode_frame(labelled(icmp_packet(), 0))
        assert kinds(packet) == [Ethernet, MPLS, IPv4, ICMPv4]

    def test_the_upstream_assigned_ethertype_walks_the_same(self):
        """Walk EtherType 0x8848 as 0x8847."""
        frame = labelled(icmp_packet(), 100, 200, ethertype=0x8848)
        packet = decode_frame(frame)
        assert kinds(packet) == [Ethernet, MPLS, IPv4, ICMPv4]

    def test_a_vlan_tagged_frame(self):
        """Walk a VLAN tag to MPLS."""
        frame = (
            bytes(ethernet(0x8100))
            + bytes(VLAN(pcp=0, dei=0, vid=30, ethertype=0x8847))
            + stack(100)
            + icmp_packet()
        )
        assert kinds(decode_frame(frame)) == [
            Ethernet,
            VLAN,
            MPLS,
            IPv4,
            ICMPv4,
        ]

    def test_mpls_in_gre(self):
        """Walk MPLS in GRE (RFC 4023).

        GRE's Protocol Type is an EtherType, so 0x8847 reaches MPLS
        through the same table with no code of its own.
        """
        inner = stack(100, 200) + icmp_packet()
        gre = GRE(flags=0, protocol_type=0x8847)
        outer = make_ipv4(protocol=47, payload_len=gre.header_len + len(inner))
        frame = (
            bytes(Packet(ethernet(0x0800), outer, gre).with_checksums(inner))
            + inner
        )
        packet = decode_frame(frame)
        assert kinds(packet) == [Ethernet, IPv4, GRE, MPLS, IPv4, ICMPv4]
        assert packet.consumed == len(frame)

    def test_a_control_word_ends_the_walk(self):
        """End the walk at a pseudowire control word.

        An Ethernet pseudowire with an RFC 4448 control word.
        """
        inner_frame = bytes(ethernet(0x0800, "46:00:00:00:00:02"))
        frame = labelled(bytes(4) + inner_frame + icmp_packet(), 100, 200)
        packet = decode_frame(frame)
        assert kinds(packet) == [Ethernet, MPLS]
        assert packet.stopped_by is None
        assert frame[packet.consumed :][4:] == inner_frame + icmp_packet()

    def test_a_pseudowire_without_a_control_word_is_misread(self):
        """Misread a pseudowire without a control word, as documented.

        The convention's failure (RFC 4928): a frame whose destination
        MAC starts with nibble 4 reads as IPv4; walking it explicitly
        from the end of the stack decodes it.
        """
        inner_frame = bytes(ethernet(0x0800, "46:00:00:00:00:02"))
        frame = labelled(inner_frame + icmp_packet(), 100, 200)
        packet = decode_frame(frame, lax=True)
        assert kinds(packet)[:3] == [Ethernet, MPLS, IPv4]
        rest = frame[14 + 8 :]
        assert kinds(decode_frame(rest, start=Ethernet)) == [
            Ethernet,
            IPv4,
            ICMPv4,
        ]

    @pytest.mark.parametrize(
        "trailer", [bytes(12), b"\x12\x34\x56\x78", bytes(8) + b"\xff" * 4]
    )
    def test_padding_and_an_fcs_reach_the_inner_packet(self, trailer):
        """Hand padding and an FCS to the labelled packet.

        The IPv4 header bounds itself; its UDP payload is left
        undecoded, padding and FCS included.
        """
        datagram = b"NP"
        udp = UDP(
            src_port=40000, dst_port=9, length=8 + len(datagram), checksum=0
        )
        ip = make_ipv4(protocol=17, payload_len=udp.length)
        inner = bytes(Packet(ip, udp).with_checksums(datagram)) + datagram
        frame = labelled(inner + trailer, 100)
        packet = decode_frame(frame)
        assert kinds(packet) == [Ethernet, MPLS, IPv4, UDP]
        assert packet.consumed == 14 + 4 + 28
        assert verify(packet[UDP], ip=packet[IPv4], payload=datagram)
        cursor = 0
        for layer in packet.layers:
            assert bytes(layer) == frame[cursor : cursor + layer.header_len]
            cursor += layer.header_len

    def test_with_checksums_fills_the_labelled_packet(self):
        """Fill the labelled packet's checksums through the stack."""
        icmp = echo_v4()
        ip = make_ipv4(protocol=1, payload_len=8 + len(icmp.body))
        packet = Packet(ethernet(0x8847), built(100, 200), ip, icmp)
        filled = packet.with_checksums()
        assert verify(filled[IPv4])
        assert verify(filled[ICMPv4], ip=filled[IPv4])
        assert decode_frame(bytes(filled)) == filled

    def test_the_flow_key_is_the_labelled_packets(self):
        """Key the flow on the labelled packet, as without MPLS."""
        datagram = b"NP"
        udp = UDP(src_port=40000, dst_port=9, length=10, checksum=0)
        ip = make_ipv4(protocol=17, payload_len=10)
        inner = bytes(Packet(ip, udp).with_checksums(datagram)) + datagram
        plain = decode_frame(bytes(ethernet(0x0800)) + inner)
        assert decode_frame(labelled(inner, 100, 200)).flow_key() == (
            plain.flow_key()
        )


#: The labels, top first, of each frame of tests/fixtures/mpls.pcap, in
#: capture order (scripts/mpls_fixture_packets.py's PLAN).
CAPTURED_STACKS = [
    (0x12345,),
    (16001, 16002),
    (16001, 16002, 16003),
    (16001, 7, 0xABCDE),
    (16001, 0),
    (16001, 2),
    (0x54321,),
    (16001, 0x23456),
]


class TestCorpusMPLS:
    """The captured frames of tests/fixtures/mpls.pcap.

    Label stacks built by scripts/mpls_fixture_packets.py around IPv4
    datagrams the kernel built (one IPv6 datagram, and one pseudowire
    control word, are the script's own).
    """

    FRAMES = pcap_frames(FIXTURES / "mpls.pcap")

    def packets(self) -> list[Packet]:
        """Walk every captured frame."""
        return [decode_frame(frame) for frame in self.FRAMES]

    def test_captured_chains(self):
        """Each frame walks through MPLS to its labelled packet."""
        assert [kinds(packet)[2:] for packet in self.packets()] == [
            [IPv4, ICMPv4],
            [IPv4, UDP],
            [IPv4, ICMPv4],
            [IPv4, ICMPv4],
            [IPv4, UDP],
            [IPv6, UDP],
            [IPv4, ICMPv4],
            [],
        ]
        assert all(
            kinds(packet)[:2] == [Ethernet, MPLS] for packet in self.packets()
        )

    def test_captured_stacks(self):
        """The stacks decode to the labels the script pushed."""
        stacks = [
            tuple(entry.label for entry in packet[MPLS].labels)
            for packet in self.packets()
        ]
        assert stacks == CAPTURED_STACKS

    def test_the_three_label_stack_keeps_each_entrys_fields(self):
        """Traffic class and TTL are read per entry, top first."""
        labels = self.packets()[2][MPLS].labels
        assert [(e.traffic_class, e.ttl) for e in labels] == [
            (5, 64),
            (3, 63),
            (0, 64),
        ]

    def test_the_entropy_label_indicator_is_named(self):
        """RFC 6790: label 7, then an entropy label with TTL 0."""
        eli, entropy = self.packets()[3][MPLS].labels[1:]
        assert eli.label_name == "Entropy Label Indicator (ELI)"
        assert (entropy.label, entropy.ttl) == (0xABCDE, 0)
        assert not entropy.is_special_purpose

    def test_both_ethertypes(self):
        """Seven frames use 0x8847 and the multicast one 0x8848."""
        ethertypes = [packet[Ethernet].ethertype for packet in self.packets()]
        assert ethertypes == [0x8847] * 6 + [0x8848, 0x8847]
        assert self.packets()[6][Ethernet].dst == "01:00:5e:00:00:01"

    def test_explicit_null_labels_decide_the_payload(self):
        """The IPv4 and IPv6 Explicit NULL frames, by their labels."""
        v4, v6 = self.packets()[4][MPLS], self.packets()[5][MPLS]
        assert v4.bottom.label_name == "IPv4 Explicit NULL Label"
        assert v4.payload_ethertype is EtherType.IPV4
        assert v6.bottom.label_name == "IPv6 Explicit NULL Label"
        assert v6.payload_ethertype is EtherType.IPV6

    def test_the_padding_reaches_the_inner_packet(self):
        """Leave the padded frame's padding undecoded.

        The short datagram's frame is padded to 60 bytes; the IPv4
        header bounds itself, and the padding stays undecoded.
        """
        frame, packet = self.FRAMES[4], self.packets()[4]
        assert len(frame) == 60
        assert packet.consumed == 14 + 8 + 28
        assert frame[packet.consumed :] == b"NP" + bytes(8)
        assert packet[IPv4].total_length == 30

    def test_the_pseudowire_stops_after_the_stack(self):
        """Stop the pseudowire frame's walk after the stack.

        The control word stops the walk; the Ethernet frame after it
        decodes on its own.
        """
        frame, packet = self.FRAMES[7], self.packets()[7]
        assert packet.consumed == 14 + 8
        assert packet.stopped_by is None
        assert packet[MPLS].payload_ethertype is None
        rest = frame[packet.consumed :]
        assert rest[:4] == b"\x00\x00\x00\x01"
        inner = decode_frame(rest[4:])
        assert kinds(inner) == [Ethernet, IPv4, ICMPv4]
        assert bytes(inner) == rest[4:]

    def test_every_layer_round_trips_byte_exactly(self):
        """Each layer re-serializes to the bytes it was decoded from."""
        for frame, packet in zip(self.FRAMES, self.packets(), strict=True):
            cursor = 0
            for layer in packet.layers:
                assert bytes(layer) == frame[cursor : cursor + layer.header_len]
                cursor += layer.header_len

    def test_recomputed_checksums_match_the_wire(self):
        """Recompute every captured checksum to its wire value.

        with_checksums() reaches the kernel's own values through the
        label stack (the script's, for the IPv6 datagram).
        """
        for frame, packet in zip(self.FRAMES, self.packets(), strict=True):
            trailing = frame[packet.consumed :]
            if isinstance(packet.layers[-1], UDP):
                # The datagram's own payload: not the padding after it.
                trailing = trailing[: packet[UDP].length - 8]
            assert packet.with_checksums(trailing) == packet


def _load_checker() -> ModuleType:
    """Load scripts/check_fixtures.py.

    It shares no code with the library.
    """
    path = Path(__file__).parent.parent / "scripts" / "check_fixtures.py"
    spec = importlib.util.spec_from_file_location("check_fixtures", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


class TestIndependentChecker:
    """The independent checker, scripts/check_fixtures.py, on MPLS.

    Every captured frame passes, each labelled packet's checksums are
    verified, and tampering fails.
    """

    checker = _load_checker()

    def check(self, frame: bytes) -> tuple[list[str], dict[str, int]]:
        """Run the checker on one frame; return its failures and stats."""
        stats: Counter[str] = Counter()
        return self.checker.check_frame(frame, stats), dict(stats)

    def test_every_captured_frame_passes_and_is_read_through(self):
        """No failure, and each labelled packet's transport is checked."""
        transports = []
        for frame in TestCorpusMPLS.FRAMES:
            failures, stats = self.check(frame)
            assert failures == []
            assert stats["mpls-stack"] == 1
            transports.append(
                sorted(k for k in stats if k in ("icmpv4", "udp", "udp6"))
            )
        assert transports == [
            ["icmpv4"],
            ["udp"],
            ["icmpv4"],
            ["icmpv4"],
            ["udp"],
            ["udp6"],
            ["icmpv4"],
            ["icmpv4"],
        ]

    def test_the_pseudowire_frame_is_checked_as_ethernet(self):
        """The checker reads past the control word, as MANIFEST says."""
        _, stats = self.check(TestCorpusMPLS.FRAMES[7])
        assert stats["mpls-pseudowire"] == 1
        assert stats["ipv4"] == 1

    @pytest.mark.parametrize("index", range(8))
    def test_a_flipped_payload_byte_fails(self, index):
        """Fail each frame with a flipped byte in its labelled packet.

        The last byte of each labelled packet is under a checksum (the
        padded frame's is padding, so its datagram's last byte).
        """
        frame = bytearray(TestCorpusMPLS.FRAMES[index])
        position = -9 if index == 4 else -1
        frame[position] ^= 0x01
        failures, _ = self.check(bytes(frame))
        assert failures in (
            ["icmpv4-checksum"],
            ["udp-checksum"],
            ["udp6-checksum"],
        )

    def test_a_flipped_ip_header_byte_fails(self):
        """The kernel's IPv4 header checksum is verified too."""
        frame = bytearray(TestCorpusMPLS.FRAMES[1])
        frame[14 + 8 + 8] ^= 0x01  # the inner IPv4 TTL
        failures, _ = self.check(bytes(frame))
        assert "ipv4-header-checksum" in failures

    def test_a_stack_without_its_bottom_is_unread_unless_strict(self):
        """A cut stack is a statistic, or a failure under strict."""
        frame = bytes(ethernet(0x8847)) + entry(100) + entry(200)
        failures, stats = self.check(frame)
        assert (failures, stats["mpls-truncated"]) == ([], 1)
        strict = self.checker._check_mpls(frame[14:], Counter(), 0, strict=True)
        assert strict == ["unchecked-mpls-truncated"]

    @pytest.mark.parametrize(
        "labels,payload",
        [((13,), b"\x10\x00\x00\x07"), ((100,), b"\x50"), ((100,), b"")],
        ids=["gal", "nibble-5", "empty"],
    )
    def test_a_payload_it_cannot_name_is_unread_unless_strict(
        self, labels, payload
    ):
        """GAL, an unknown nibble or nothing: unread, or strict-failed."""
        frame = labelled(payload, *labels)
        failures, stats = self.check(frame)
        assert (failures, stats["mpls-unchecked-payload"]) == ([], 1)
        strict = self.checker._check_mpls(frame[14:], Counter(), 0, strict=True)
        assert strict == ["unchecked-mpls-payload"]

    def test_mpls_in_gre_is_read_through(self):
        """GRE's Protocol Type reaches the checker's MPLS walk too."""
        inner = stack(100, 200) + icmp_packet()
        gre = GRE(flags=0, protocol_type=0x8847)
        outer = make_ipv4(protocol=47, payload_len=gre.header_len + len(inner))
        frame = (
            bytes(Packet(ethernet(0x0800), outer, gre).with_checksums(inner))
            + inner
        )
        failures, stats = self.check(frame)
        assert failures == []
        assert (stats["gre"], stats["mpls-stack"], stats["icmpv4"]) == (1, 1, 1)
