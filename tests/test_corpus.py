"""Corpus-wide invariants over the real-capture fixtures.

Every frame in tests/fixtures/ was captured from live traffic and
validated for internal checksum consistency by scripts/check_fixtures.py
before being committed (see tests/fixtures/MANIFEST.md). These tests
hold the library to its contract against all of them at once.
"""

import contextlib

import pytest

from conftest import FIXTURES, corpus_frames, read_pcap
from netprotocols import (
    ARP,
    TCP,
    UDP,
    VLAN,
    Ethernet,
    ICMPv4,
    ICMPv6,
    IPv4,
    IPv6,
    Protocol,
    ProtocolError,
)

CORPUS = corpus_frames()


def walk(frame: bytes) -> tuple[list[Protocol], int]:
    """The documented chain walk; returns (layers, bytes consumed)."""
    layers: list[Protocol] = []
    cursor = 0
    protocol: type[Protocol] | None = Ethernet
    while protocol is not None:
        header = protocol.decode(frame[cursor:])
        layers.append(header)
        cursor += header.header_len
        protocol = header.next_protocol()
    return layers, cursor


def corpus_ids() -> list[str]:
    return [f"{name}#{index}" for name, index, _ in CORPUS]


class TestCorpusInvariants:
    def test_corpus_is_present_and_generous(self):
        assert len(CORPUS) >= 40
        assert len(list(FIXTURES.glob("*.pcap"))) >= 10

    @pytest.mark.parametrize(
        "frame", [f for _, _, f in CORPUS], ids=corpus_ids()
    )
    def test_decodes_raising_nothing_outside_protocol_error(self, frame):
        # ProtocolError is acceptable by contract; nothing else is.
        with contextlib.suppress(ProtocolError):
            walk(frame)

    @pytest.mark.parametrize(
        "frame", [f for _, _, f in CORPUS], ids=corpus_ids()
    )
    def test_every_layer_round_trips_byte_exactly(self, frame):
        layers, _ = walk(frame)
        cursor = 0
        for layer in layers:
            assert bytes(layer) == frame[cursor : cursor + layer.header_len]
            cursor += layer.header_len

    @pytest.mark.parametrize(
        "frame", [f for _, _, f in CORPUS], ids=corpus_ids()
    )
    def test_consumption_never_exceeds_frame(self, frame):
        _, consumed = walk(frame)
        assert consumed <= len(frame)


class TestCorpusCoverage:
    """The corpus must keep exercising every protocol the library ships."""

    def test_protocol_coverage(self):
        seen = {
            type(layer) for _, _, frame in CORPUS for layer in walk(frame)[0]
        }
        assert {
            Ethernet,
            VLAN,
            ARP,
            IPv4,
            IPv6,
            ICMPv4,
            ICMPv6,
            TCP,
            UDP,
        } <= seen

    def test_arp_covers_both_operations(self):
        opers = {
            layer.oper
            for _, _, frame in CORPUS
            for layer in walk(frame)[0]
            if isinstance(layer, ARP)
        }
        assert {1, 2} <= opers

    def test_tcp_options_present_in_real_traffic(self):
        assert any(
            layer.options
            for _, _, frame in CORPUS
            for layer in walk(frame)[0]
            if isinstance(layer, TCP)
        )

    def test_tcp_options_parse_across_the_corpus(self):
        """Every options-bearing captured segment parses; the corpus
        rides established connections, so the options are the classic
        NOP, NOP, Timestamps layout (no SYN was captured — see the
        MANIFEST — so MSS and friends are exercised by crafted tests)."""
        options = [
            option
            for _, _, frame in CORPUS
            for layer in walk(frame)[0]
            if isinstance(layer, TCP)
            for option in layer.parsed_options
        ]
        kinds = {option.kind for option in options}
        assert kinds == {1, 8}  # No-Operation + Timestamps
        for option in options:
            if option.kind == 8:
                assert option.kind_name == "Timestamps"
                tsval_tsecr = option.value
                assert isinstance(tsval_tsecr, tuple)
                assert len(tsval_tsecr) == 2


class TestFragmentHandling:
    """Regression: real fragmented traffic exposed that IPv4 chained
    non-first fragments into garbage upper-layer decodes (mid-payload
    bytes decoded as 'ICMPv4 type 192')."""

    def fragments(self) -> list[IPv4]:
        frames = read_pcap(FIXTURES / "ipv4_fragments.pcap")
        layers = [walk(frame)[0] for frame in frames]
        return [stack[1] for stack in layers if isinstance(stack[1], IPv4)]

    def test_corpus_contains_a_fragment_pair(self):
        offsets = {ip.fragment_offset for ip in self.fragments()}
        assert 0 in offsets
        assert any(offset > 0 for offset in offsets)

    def test_non_first_fragments_do_not_chain(self):
        for ip in self.fragments():
            if ip.fragment_offset > 0:
                assert ip.next_protocol() is None

    def test_first_fragments_chain_to_real_icmp(self):
        for ip in self.fragments():
            if ip.fragment_offset == 0:
                assert ip.next_protocol() is ICMPv4


class TestRepresentativeFrames:
    """Hand-verified field asserts, one frame per scenario family."""

    def test_ttl_exceeded_error_message(self):
        frame = read_pcap(FIXTURES / "icmpv4_ttl_exceeded.pcap")[0]
        layers, _ = walk(frame)
        assert [type(layer) for layer in layers] == [Ethernet, IPv4, ICMPv4]
        icmp = layers[2]
        assert isinstance(icmp, ICMPv4)
        assert icmp.type == 11
        assert icmp.type_name == "Time Exceeded"
        # The error embeds the invoking packet: its bytes must decode as
        # the original IPv4 header, addressed like the outer datagram in
        # reverse (the expiring probe travelled the other way).
        outer = layers[1]
        assert isinstance(outer, IPv4)
        assert icmp.embedded_packet is not None
        embedded = IPv4.decode(icmp.embedded_packet)
        assert embedded.dst == outer.dst or embedded.src == outer.dst

    def test_loopback_echo_pair(self):
        frames = read_pcap(FIXTURES / "icmpv4_echo_lo.pcap")
        echoes = [walk(frame)[0][2] for frame in frames]
        types = [icmp.type for icmp in echoes]  # type: ignore[attr-defined]
        assert 8 in types and 0 in types
        # Every echo exposes its identifier/sequence, and each reply
        # mirrors a request's pair.
        pairs = {
            (icmp.identifier, icmp.sequence_number)  # type: ignore[attr-defined]
            for icmp in echoes
        }
        assert None not in {pair[0] for pair in pairs}
        requests = {
            (icmp.identifier, icmp.sequence_number)  # type: ignore[attr-defined]
            for icmp in echoes
            if icmp.type == 8  # type: ignore[attr-defined]
        }
        replies = {
            (icmp.identifier, icmp.sequence_number)  # type: ignore[attr-defined]
            for icmp in echoes
            if icmp.type == 0  # type: ignore[attr-defined]
        }
        assert requests == replies

    def test_ndp_neighbor_discovery(self):
        frames = read_pcap(FIXTURES / "ipv6_ndp_mld.pcap")
        ndp = [
            layer
            for frame in frames
            for layer in walk(frame)[0]
            if isinstance(layer, ICMPv6) and layer.type in (135, 136)
        ]
        types = {icmp.type for icmp in ndp}
        assert 135 in types  # Neighbor Solicitation
        assert 136 in types  # Neighbor Advertisement
        # Every NS/NA exposes its target address, and the captured
        # source/target link-layer-address options read back as MACs.
        lla_types = set()
        for icmp in ndp:
            assert icmp.ndp_target_address is not None
            for option in icmp.ndp_options or ():
                if option.type in (1, 2):
                    lla_types.add(option.type)
                    mac = option.link_layer_address
                    assert mac is not None
                    assert len(mac.split(":")) == 6
        assert {1, 2} <= lla_types

    def test_dns_responses_over_both_ip_versions(self):
        frames = read_pcap(FIXTURES / "udp_dns.pcap")
        stacks = [[type(layer) for layer in walk(frame)[0]] for frame in frames]
        assert any(stack[1] is IPv4 and stack[2] is UDP for stack in stacks)
        assert any(stack[1] is IPv6 and stack[2] is UDP for stack in stacks)
        for frame in frames:
            udp = walk(frame)[0][2]
            assert isinstance(udp, UDP)
            assert udp.src_port == 53

    def test_vlan_single_and_qinq_tags_chain_to_the_payload(self):
        frames = read_pcap(FIXTURES / "vlan_icmp.pcap")
        stacks = [walk(frame)[0] for frame in frames]

        # A single 802.1Q tag: exactly one VLAN layer between Ethernet
        # and the tagged payload (ARP or IPv4).
        single = next(
            s
            for s in stacks
            if [type(x) for x in s[:3]] == [Ethernet, VLAN, IPv4]
        )
        assert single[1].vid == 100
        assert single[1].ethertype_name == "IPv4"
        assert type(single[3]) is ICMPv4

        # A QinQ frame carrying IPv4: one VLAN layer per tag, outer
        # S-VID then inner C-VID, then the payload chains normally.
        qinq = next(
            s
            for s in stacks
            if [type(x) for x in s[:4]] == [Ethernet, VLAN, VLAN, IPv4]
        )
        assert (qinq[1].vid, qinq[2].vid) == (200, 30)
        assert type(qinq[4]) is ICMPv4

        # Both single-tag and QinQ frames are present, and ARP rides a
        # tagged frame too (one VLAN layer per tag regardless of payload).
        tag_counts = {sum(isinstance(x, VLAN) for x in s) for s in stacks}
        assert {1, 2} <= tag_counts
        assert any(any(isinstance(x, ARP) for x in s) for s in stacks)
