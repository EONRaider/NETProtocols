import pytest

from netprotocols import (
    ARP,
    TCP,
    UDP,
    Ethernet,
    InvalidFieldError,
    IPv4,
    Packet,
    TruncatedHeaderError,
)


@pytest.fixture
def eth_arp_packet(raw_eth_header, raw_arp_header) -> Packet:
    return Packet(Ethernet.decode(raw_eth_header), ARP.decode(raw_arp_header))


@pytest.fixture
def ip_tcp_packet(raw_ipv4_header, raw_tcp_header_with_options) -> Packet:
    return Packet(
        IPv4.decode(raw_ipv4_header), TCP.decode(raw_tcp_header_with_options)
    )


class TestPacket:
    def test_bytes_joins_layers(
        self, eth_arp_packet, raw_eth_header, raw_arp_header
    ):
        assert bytes(eth_arp_packet) == raw_eth_header + raw_arp_header

    def test_payload_property_was_removed(self, eth_arp_packet):
        """Packet has no ``payload`` attribute; ``bytes(packet)`` gives
        its bytes."""
        with pytest.raises(AttributeError):
            _ = eth_arp_packet.payload

    def test_layers_are_ordered_and_indexable(self, eth_arp_packet):
        assert len(eth_arp_packet) == 2
        assert isinstance(eth_arp_packet[0], Ethernet)
        assert isinstance(eth_arp_packet[1], ARP)

    def test_equality(self, raw_eth_header):
        eth = Ethernet.decode(raw_eth_header)
        assert Packet(eth) == Packet(eth)
        assert Packet(eth) != Packet()
        assert Packet(eth) != (eth,)

    def test_non_protocol_member_rejected(self):
        with pytest.raises(InvalidFieldError):
            Packet(b"raw bytes are not a protocol")  # type: ignore[arg-type]

    def test_inner_layer_instances_accepted(self, raw_arp_header):
        """A member may be an indirect Protocol subclass, such as a
        decoded ARP or IPv4 instance."""
        packet = Packet(ARP.decode(raw_arp_header))
        assert len(packet) == 1

    def test_int_key_still_indexes_by_position(self, eth_arp_packet):
        """An int key is positional, not a lookup for a layer of type
        ``int``."""
        assert eth_arp_packet[0] is eth_arp_packet.layers[0]
        assert eth_arp_packet[-1] is eth_arp_packet.layers[-1]
        with pytest.raises(IndexError):
            eth_arp_packet[99]

    def test_type_key_returns_first_matching_layer(self, ip_tcp_packet):
        assert ip_tcp_packet[IPv4] is ip_tcp_packet.layers[0]
        assert ip_tcp_packet[TCP] is ip_tcp_packet.layers[1]

    def test_type_key_raises_key_error_on_no_match(self, ip_tcp_packet):
        with pytest.raises(KeyError):
            ip_tcp_packet[UDP]

    def test_get_returns_first_matching_layer(self, ip_tcp_packet):
        assert ip_tcp_packet.get(TCP) is ip_tcp_packet.layers[1]

    def test_get_returns_none_on_no_match(self, ip_tcp_packet):
        assert ip_tcp_packet.get(UDP) is None


class TestPacketHashing:
    def test_equal_packets_hash_equal(self, raw_eth_header):
        eth = Ethernet.decode(raw_eth_header)
        assert hash(Packet(eth)) == hash(Packet(eth))

    def test_stopped_by_changes_the_hash(self, raw_eth_header):
        eth = Ethernet.decode(raw_eth_header)
        clean = Packet(eth)
        stopped = Packet(eth, stopped_by=TruncatedHeaderError("truncated"))
        assert hash(clean) != hash(stopped)
        assert clean != stopped

    def test_packet_usable_as_dict_key(self, raw_eth_header):
        eth = Ethernet.decode(raw_eth_header)
        mapping = {Packet(eth): "value"}
        assert mapping[Packet(eth)] == "value"

    def test_packet_usable_as_set_member(self, raw_eth_header):
        eth = Ethernet.decode(raw_eth_header)
        members = {Packet(eth), Packet(eth)}
        assert len(members) == 1


class TestPacketTrailer:
    """``Packet.trailer``: the bytes past a frame's declared end."""

    FCS = b"\xde\xad\xbe\xef"

    def test_defaults_to_empty_bytes(self, eth_arp_packet):
        assert eth_arp_packet.trailer == b""
        assert type(eth_arp_packet.trailer) is bytes

    @pytest.mark.parametrize("kind", [bytes, bytearray, memoryview])
    def test_a_bytes_like_trailer_is_stored_as_a_bytes_copy(
        self, raw_eth_header, kind
    ):
        source = bytearray(self.FCS)
        packet = Packet(Ethernet.decode(raw_eth_header), trailer=kind(source))
        source[0] = 0
        assert packet.trailer == self.FCS
        assert type(packet.trailer) is bytes

    @pytest.mark.parametrize("trailer", ["dead", 4, None, [0xDE]])
    def test_a_trailer_that_is_not_bytes_like_is_rejected(
        self, raw_eth_header, trailer
    ):
        with pytest.raises(InvalidFieldError) as caught:
            Packet(Ethernet.decode(raw_eth_header), trailer=trailer)
        error = caught.value
        assert error.field == "trailer"
        assert (error.expected, error.actual) == (bytes, type(trailer))

    def test_the_trailer_is_keyword_only(self, raw_eth_header):
        with pytest.raises(InvalidFieldError):
            Packet(Ethernet.decode(raw_eth_header), self.FCS)  # type: ignore[arg-type]

    def test_bytes_and_consumed_exclude_the_trailer(
        self, eth_arp_packet, raw_eth_header, raw_arp_header
    ):
        packet = Packet(*eth_arp_packet.layers, trailer=self.FCS)
        assert bytes(packet) == raw_eth_header + raw_arp_header
        assert packet.consumed == eth_arp_packet.consumed

    def test_equality_and_hash_include_the_trailer(self, eth_arp_packet):
        layers = eth_arp_packet.layers
        with_fcs = Packet(*layers, trailer=self.FCS)
        assert with_fcs == Packet(*layers, trailer=bytearray(self.FCS))
        assert hash(with_fcs) == hash(Packet(*layers, trailer=self.FCS))
        assert with_fcs != eth_arp_packet
        assert with_fcs != Packet(*layers, trailer=self.FCS[:3])
        assert hash(with_fcs) != hash(eth_arp_packet)
        assert len({with_fcs, eth_arp_packet, Packet(*layers)}) == 2

    def test_repr_shows_only_a_non_empty_trailer(self, eth_arp_packet):
        layers = eth_arp_packet.layers
        assert "trailer" not in repr(eth_arp_packet)
        assert repr(Packet(*layers, trailer=self.FCS)) == (
            f"Packet{layers!r} trailer={self.FCS!r}"
        )
        stop = TruncatedHeaderError("cut")
        assert repr(Packet(*layers, stopped_by=stop, trailer=self.FCS)) == (
            f"Packet{layers!r} stopped_by={stop!r} trailer={self.FCS!r}"
        )

    def test_with_checksums_carries_the_trailer(self, ip_tcp_packet):
        packet = Packet(*ip_tcp_packet.layers, trailer=self.FCS)
        assert packet.with_checksums().trailer == self.FCS
        assert ip_tcp_packet.with_checksums().trailer == b""

    def test_pickles_with_its_trailer(self, eth_arp_packet):
        import pickle

        stop = TruncatedHeaderError("cut")
        packet = Packet(
            *eth_arp_packet.layers, stopped_by=stop, trailer=self.FCS
        )
        for protocol in range(2, pickle.HIGHEST_PROTOCOL + 1):
            copy = pickle.loads(pickle.dumps(packet, protocol=protocol))
            assert copy == packet
            assert copy.trailer == self.FCS
            assert type(copy.stopped_by) is TruncatedHeaderError
