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
        assert repr(packet) == \
               "Ethernet(dst=ff:ff:ff:ff:ff:ff, src=00:07:0d:af:f4:54, " \
               "eth=2054), ARP(htype=1, ptype=2048, hlen=6, oper=2, " \
               "sha=00:07:0d:af:f4:54, spa=24.166.172.1, " \
               "tha=00:00:00:00:00:00, tpa=24.166.173.159)"
        assert isinstance(packet.encapsulated_protos, tuple)
        assert isinstance(packet.encapsulated_protos[0], Ethernet)
        assert isinstance(packet.encapsulated_protos[1], ARP)
        assert len(bytes(packet)) == len(bytes(packet.ethernet) +
                                         bytes(packet.arp))  # 42 bytes
        assert packet.payload == \
               b'\xff\xff\xff\xff\xff\xff\x00\x07\r\xaf\xf4T\x08\x06\x00\x01' \
               b'\x08\x00\x06\x04\x00\x02\x00\x07\r\xaf\xf4T\x18\xa6\xac\x01' \
               b'\x00\x00\x00\x00\x00\x00\x18\xa6\xad\x9f'
