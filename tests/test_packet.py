import pytest

from netprotocols import ARP, Ethernet, InvalidFieldError, Packet


@pytest.fixture
def eth_arp_packet(raw_eth_header, raw_arp_header) -> Packet:
    return Packet(Ethernet.decode(raw_eth_header), ARP.decode(raw_arp_header))


class TestPacket:
    def test_bytes_joins_layers(
        self, eth_arp_packet, raw_eth_header, raw_arp_header
    ):
        assert bytes(eth_arp_packet) == raw_eth_header + raw_arp_header
        assert eth_arp_packet.payload == raw_eth_header + raw_arp_header

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
