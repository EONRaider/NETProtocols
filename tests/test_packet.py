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
        """Deleted at 2.0.0 (breaking change, #90): it was always exactly
        ``bytes(self)``, a redundant duplicate of ``__bytes__``."""
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

    def test_non_protocol_member_rejected(self):
        with pytest.raises(InvalidFieldError):
            Packet(b"raw bytes are not a protocol")  # type: ignore[arg-type]

    def test_inner_layer_instances_accepted(self, raw_arp_header):
        """Regression: the old implementation validated members against
        direct Protocol subclasses only, so indirect subclasses such as
        decoded ARP/IPv4 instances were spuriously rejected."""
        packet = Packet(ARP.decode(raw_arp_header))
        assert len(packet) == 1

    def test_int_key_still_indexes_by_position(self, eth_arp_packet):
        """Unchanged behaviour: an int key is positional, not a lookup
        for a layer of type ``int``."""
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
