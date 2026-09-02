"""The shipped chain walker (#88): decode_frame()."""

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

import pytest

from conftest import corpus_frames
from netprotocols import (
    ARP,
    DNS,
    MAX_DEPTH,
    UDP,
    DNSOverTCP,
    Ethernet,
    IPv4,
    MaxDepthExceededError,
    Packet,
    Protocol,
    ProtocolError,
    TruncatedHeaderError,
    decode_frame,
)
from netprotocols.registry import (
    TABLE_ETHERTYPE,
    TABLE_UDP_PORT,
    Registry,
    UnknownTableError,
)

CORPUS = [frame for _, _, frame in corpus_frames()]


def kinds(packet: Packet) -> list[str]:
    return [type(layer).__name__ for layer in packet]


@pytest.fixture
def ipv4_frame() -> bytes:
    """A corpus frame whose chain reaches IPv4."""
    for frame in CORPUS:
        if "IPv4" in kinds(decode_frame(frame, lax=True)):
            return frame
    pytest.skip("no IPv4 frame in the corpus")


@pytest.fixture
def dhcp_frame() -> bytes:
    """A corpus frame whose chain reaches DHCP on UDP port 67."""
    for frame in CORPUS:
        packet = decode_frame(frame, lax=True)
        if "DHCP" in kinds(packet) and packet[2].dst_port == 67:
            return frame
    pytest.skip("no DHCP-to-server frame in the corpus")


@pytest.fixture
def arp_frame() -> bytes:
    for frame in CORPUS:
        packet = decode_frame(frame, lax=True)
        if len(packet) == 2 and isinstance(packet[1], ARP):
            return frame
    pytest.skip("no ARP frame in the corpus")


class TestReturnsAPacket:
    def test_decodes_the_whole_chain(self, ipv4_frame):
        packet = decode_frame(ipv4_frame)
        assert isinstance(packet, Packet)
        assert isinstance(packet[0], Ethernet)
        assert len(packet) >= 2

    def test_consumed_is_the_offset_the_walk_reached(self, ipv4_frame):
        packet = decode_frame(ipv4_frame)
        assert packet.consumed == sum(
            layer.header_len for layer in packet.layers
        )
        assert packet.consumed <= len(ipv4_frame)

    def test_a_clean_walk_reports_no_stop_reason(self, ipv4_frame):
        assert decode_frame(ipv4_frame).stopped_by is None

    def test_layers_round_trip_against_the_frame(self, ipv4_frame):
        packet = decode_frame(ipv4_frame)
        assert bytes(packet) == ipv4_frame[: packet.consumed]

    @pytest.mark.parametrize("frame", CORPUS[:40])
    def test_matches_a_hand_rolled_walk_over_the_corpus(self, frame):
        """The shipped walker must agree with the loop it replaces —
        this is what makes retiring the copies safe."""
        expected: list[Protocol] = []
        cursor, protocol = 0, Ethernet
        try:
            while protocol is not None:
                header = protocol.decode(frame[cursor:])
                expected.append(header)
                cursor += header.header_len
                protocol = header.next_protocol()
        except ProtocolError:
            pytest.skip("frame does not decode cleanly")
        packet = decode_frame(frame)
        assert list(packet.layers) == expected
        assert packet.consumed == cursor


class TestStartingLayer:
    def test_defaults_to_ethernet(self, ipv4_frame):
        assert isinstance(decode_frame(ipv4_frame)[0], Ethernet)

    def test_start_at_ipv4(self, ipv4_frame):
        whole = decode_frame(ipv4_frame)
        inner = ipv4_frame[whole[0].header_len :]
        packet = decode_frame(inner, start=IPv4)
        assert isinstance(packet[0], IPv4)
        assert kinds(packet) == kinds(whole)[1:]

    def test_start_at_arp(self, arp_frame):
        inner = arp_frame[14:]
        packet = decode_frame(inner, start=ARP)
        assert kinds(packet) == ["ARP"]

    def test_a_wrong_starting_layer_raises_rather_than_guessing(
        self, arp_frame
    ):
        with pytest.raises(ProtocolError):
            decode_frame(arp_frame[14:], start=IPv4)


class TestDepthIsBounded:
    def test_the_default_is_generous_against_real_traffic(self):
        deepest = max(len(decode_frame(f, lax=True)) for f in CORPUS)
        assert deepest < MAX_DEPTH

    def test_exceeding_the_depth_raises(self, ipv4_frame):
        with pytest.raises(MaxDepthExceededError):
            decode_frame(ipv4_frame, max_depth=1)

    def test_the_error_names_what_came_next(self, ipv4_frame):
        with pytest.raises(MaxDepthExceededError) as excinfo:
            decode_frame(ipv4_frame, max_depth=1)
        assert "IPv4" in str(excinfo.value)
        assert "max_depth" in str(excinfo.value)

    def test_depth_error_is_a_protocol_error(self, ipv4_frame):
        """One handler still guards the whole pipeline."""
        with pytest.raises(ProtocolError):
            decode_frame(ipv4_frame, max_depth=1)

    def test_a_depth_that_exactly_fits_does_not_raise(self, ipv4_frame):
        depth = len(decode_frame(ipv4_frame))
        assert len(decode_frame(ipv4_frame, max_depth=depth)) == depth

    def test_zero_depth_is_rejected(self, ipv4_frame):
        with pytest.raises(ValueError, match="at least 1"):
            decode_frame(ipv4_frame, max_depth=0)

    def test_singular_header_in_the_message(self, ipv4_frame):
        with pytest.raises(MaxDepthExceededError, match="1 header "):
            decode_frame(ipv4_frame, max_depth=1)


class TestLaxMode:
    def test_strict_raises_on_a_truncated_frame(self, ipv4_frame):
        with pytest.raises(TruncatedHeaderError):
            decode_frame(ipv4_frame[:18])

    def test_lax_keeps_the_layers_it_decoded(self, ipv4_frame):
        packet = decode_frame(ipv4_frame[:18], lax=True)
        assert kinds(packet) == ["Ethernet"]

    def test_lax_reports_the_reason_it_stopped(self, ipv4_frame):
        packet = decode_frame(ipv4_frame[:18], lax=True)
        assert isinstance(packet.stopped_by, TruncatedHeaderError)

    def test_lax_reports_a_depth_stop_too(self, ipv4_frame):
        packet = decode_frame(ipv4_frame, max_depth=1, lax=True)
        assert len(packet) == 1
        assert isinstance(packet.stopped_by, MaxDepthExceededError)

    def test_lax_on_a_clean_frame_is_identical_to_strict(self, ipv4_frame):
        assert decode_frame(ipv4_frame, lax=True) == decode_frame(ipv4_frame)

    def test_lax_never_raises_on_arbitrary_bytes(self):
        for length in range(0, 64):
            packet = decode_frame(bytes(length), lax=True)
            assert isinstance(packet, Packet)

    def test_lax_does_not_relax_the_individual_decoders(self, ipv4_frame):
        """Lax is about the walk, not the headers: every layer it does
        return decoded under the ordinary strict rules."""
        packet = decode_frame(ipv4_frame[:18], lax=True)
        for index, layer in enumerate(packet.layers):
            start = sum(x.header_len for x in packet.layers[:index])
            assert bytes(layer) == ipv4_frame[start : start + layer.header_len]

    def test_lax_still_raises_for_a_non_protocol_error(self, ipv4_frame):
        """ValueError is a caller mistake, not malformed input."""
        with pytest.raises(ValueError):
            decode_frame(ipv4_frame, max_depth=0, lax=True)


class TestMemoryviewInput:
    def test_a_memoryview_walks_identically(self, ipv4_frame):
        assert decode_frame(memoryview(ipv4_frame)) == decode_frame(ipv4_frame)

    def test_a_memoryview_slice_starting_mid_buffer(self, ipv4_frame):
        padded = b"\x00" * 16 + ipv4_frame
        view = memoryview(padded)[16:]
        assert decode_frame(view) == decode_frame(ipv4_frame)

    def test_layers_from_a_memoryview_round_trip_to_bytes(self, ipv4_frame):
        packet = decode_frame(memoryview(ipv4_frame))
        assert bytes(packet) == ipv4_frame[: packet.consumed]


class TestRegistryOverrides:
    """Per-call decoder overrides, the "Decode As" of #87's Q4."""

    #: A minimal well-formed DNS message: id 12, no flags, all four
    #: section counts zero. Enough for a forced decoder to succeed, so
    #: these tests measure dispatch rather than truncation.
    DNS_MESSAGE = b"\x00\x0c" + bytes(10)

    def frame_with_udp_ports(
        self, src: int, dst: int, payload: bytes = b""
    ) -> bytes:
        eth = Ethernet(
            dst="ff:ff:ff:ff:ff:ff", src="00:0c:29:b1:c2:d3", ethertype=0x0800
        )
        udp_payload = (
            bytes(
                UDP(
                    src_port=src,
                    dst_port=dst,
                    length=8 + len(payload),
                    checksum=0,
                )
            )
            + payload
        )
        ip = IPv4(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=20 + len(udp_payload),
            identification=1,
            flags=0,
            fragment_offset=0,
            ttl=64,
            protocol=17,
            checksum=0,
            src="192.168.1.10",
            dst="192.168.1.20",
            options=b"",
        )
        return bytes(eth) + bytes(ip) + udp_payload

    def test_an_unknown_port_ends_the_chain_by_default(self):
        frame = self.frame_with_udp_ports(40000, 6969)
        assert kinds(decode_frame(frame, lax=True))[-1] == "UDP"

    def test_decode_as_forces_a_decoder_for_this_call(self):
        frame = self.frame_with_udp_ports(40000, 6969, self.DNS_MESSAGE)
        packet = decode_frame(
            frame, lax=True, decode_as={TABLE_UDP_PORT: {6969: DNS}}
        )
        assert "DNS" in kinds(packet)

    def test_decode_as_does_not_leak_into_the_next_call(self):
        frame = self.frame_with_udp_ports(40000, 6969)
        decode_frame(frame, lax=True, decode_as={TABLE_UDP_PORT: {6969: DNS}})
        assert kinds(decode_frame(frame, lax=True))[-1] == "UDP"

    def test_decode_as_can_override_a_built_in(self, dhcp_frame):
        """A real DHCP frame stops being read as DHCP when port 67 is
        pointed elsewhere for the call."""
        assert "DHCP" in kinds(decode_frame(dhcp_frame))
        packet = decode_frame(
            dhcp_frame, lax=True, decode_as={TABLE_UDP_PORT: {67: DNS}}
        )
        assert "DHCP" not in kinds(packet)
        assert "DNS" in kinds(packet)

    def test_an_explicit_registry_is_honoured(self):
        frame = self.frame_with_udp_ports(40000, 6969, self.DNS_MESSAGE)
        registry = Registry.from_defaults()
        registry.register(TABLE_UDP_PORT, 6969, DNS)
        packet = decode_frame(frame, lax=True, registry=registry)
        assert "DNS" in kinds(packet)

    def test_decode_as_layers_on_top_of_an_explicit_registry(self):
        """decode_as wins over the registry it is applied to."""
        frame = self.frame_with_udp_ports(
            40000, 6969, b"\x00\x0c" + self.DNS_MESSAGE
        )
        registry = Registry.from_defaults()
        registry.register(TABLE_UDP_PORT, 6969, DNS)
        assert kinds(decode_frame(frame, lax=True, registry=registry))[3] == (
            "DNS"
        )
        packet = decode_frame(
            frame,
            lax=True,
            registry=registry,
            decode_as={TABLE_UDP_PORT: {6969: DNSOverTCP}},
        )
        assert kinds(packet)[3:] == ["DNSOverTCP", "DNS"]

    def test_an_empty_registry_stops_at_the_first_layer(self, ipv4_frame):
        packet = decode_frame(ipv4_frame, registry=Registry())
        assert kinds(packet) == ["Ethernet"]

    def test_an_explicit_registry_reaches_every_dispatch_point(
        self, ipv4_frame
    ):
        """from_defaults() must walk exactly as the global does — the
        proof that threading a registry did not skip a layer."""
        for frame in CORPUS:
            explicit = decode_frame(
                frame, lax=True, registry=Registry.from_defaults()
            )
            assert kinds(explicit) == kinds(decode_frame(frame, lax=True))

    def test_a_registry_override_reaches_the_ethertype_table(self, arp_frame):
        """Overriding EtherType 0x0806 sends ARP bytes to IPv4, which
        rejects them — so the override is proved by the walk changing
        from a clean two-layer decode to a diagnosed stop."""
        assert kinds(decode_frame(arp_frame)) == ["Ethernet", "ARP"]
        packet = decode_frame(
            arp_frame, lax=True, decode_as={TABLE_ETHERTYPE: {0x0806: IPv4}}
        )
        assert kinds(packet) == ["Ethernet"]
        assert isinstance(packet.stopped_by, ProtocolError)


class TestPacketMetadata:
    def test_a_constructed_packet_reports_no_stop_reason(self, ipv4_frame):
        packet = decode_frame(ipv4_frame)
        assert Packet(*packet.layers).stopped_by is None

    def test_equality_distinguishes_a_partial_walk(self, ipv4_frame):
        partial = decode_frame(ipv4_frame[:18], lax=True)
        assert partial != Packet(*partial.layers)

    def test_repr_surfaces_the_stop_reason(self, ipv4_frame):
        partial = decode_frame(ipv4_frame[:18], lax=True)
        assert "stopped_by" in repr(partial)
        assert "stopped_by" not in repr(decode_frame(ipv4_frame))

    def test_with_checksums_preserves_the_stop_reason(self, ipv4_frame):
        partial = decode_frame(ipv4_frame[:18], lax=True)
        assert partial.with_checksums().stopped_by is partial.stopped_by


@dataclass(frozen=True, slots=True)
class NonAdvancing(Protocol):
    """A zero-length header that chains to itself.

    The pathological shape a third-party registration could produce:
    ``header_len`` is 0, so the cursor never moves and the chain never
    ends. Nothing in the decode contract forbids it — bounding the walk
    is what makes it survivable.
    """

    _struct: ClassVar[Struct] = Struct("")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        return cls()

    def __bytes__(self) -> bytes:
        return b""

    def next_protocol(self, registry=None) -> type[Protocol] | None:
        return NonAdvancing


class TestHostileChains:
    def test_a_non_advancing_chain_is_bounded_not_hung(self):
        with pytest.raises(MaxDepthExceededError):
            decode_frame(b"\x00" * 64, start=NonAdvancing)

    def test_the_bound_is_exactly_max_depth(self):
        packet = decode_frame(
            b"\x00" * 64, start=NonAdvancing, max_depth=5, lax=True
        )
        assert len(packet) == 5
        assert isinstance(packet.stopped_by, MaxDepthExceededError)

    def test_a_non_advancing_chain_consumes_nothing(self):
        packet = decode_frame(
            b"\x00" * 64, start=NonAdvancing, max_depth=3, lax=True
        )
        assert packet.consumed == 0


class TestCallerMistakesAreNotSwallowed:
    """Lax mode absorbs malformed *input*, never a bad call."""

    def test_an_unknown_decode_as_table_raises(self, ipv4_frame):
        with pytest.raises(UnknownTableError):
            decode_frame(ipv4_frame, decode_as={"udp.ports": {53: DNS}})

    def test_it_raises_in_lax_mode_too(self, ipv4_frame):
        with pytest.raises(UnknownTableError):
            decode_frame(
                ipv4_frame, lax=True, decode_as={"udp.ports": {53: DNS}}
            )

    def test_a_negative_max_depth_raises_in_lax_mode_too(self, ipv4_frame):
        with pytest.raises(ValueError):
            decode_frame(ipv4_frame, lax=True, max_depth=-1)
