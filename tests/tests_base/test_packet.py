#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from netprotocols import ARP, Ethernet, Packet


class TestPacket:
    def test_build_arp_packet(self,
                              mock_eth_header,
                              raw_eth_header,
                              mock_arp_header,
                              raw_arp_header):
        """
        GIVEN instances of Ethernet and ARP
        WHEN those instances are passed as arguments to the initializer
            of Packet
        THEN an instance of packet containing 'ethernet' and 'arp' as
            attributes must be correctly initialized
        """
        packet = Packet(mock_eth_header, mock_arp_header)

        assert isinstance(packet.ethernet, Ethernet)
        assert isinstance(packet.arp, ARP)
        assert len(bytes(packet)) == len(bytes(packet.ethernet)) + \
               len(bytes(packet.arp))  # Total length == 42
