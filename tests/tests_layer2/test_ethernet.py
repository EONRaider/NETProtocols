#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from netprotocols import Ethernet


"""
From WireShark sample captures at
https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/
arp-storm.pcap
"""


class TestEthernet:
    def test_build_ethernet_header(self, mock_eth_header):
        """GIVEN a set of MAC addresses and Ethertype
        WHEN those values are valid and correctly formatted
        THEN an instance of Ethernet must be initialized without errors
        """
        assert mock_eth_header.src == "00:07:0d:af:f4:54"
        assert mock_eth_header.dst == "ff:ff:ff:ff:ff:ff"
        assert mock_eth_header.eth == 0x0806
        assert (
            bytes(mock_eth_header) == b"\xff\xff\xff\xff\xff\xff\x00\x07\r"
            b"\xaf\xf4T\x08\x06"
        )
        assert (
            repr(mock_eth_header)
            == "Ethernet(dst=ff:ff:ff:ff:ff:ff, src=00:07:0d:af:f4:54, "
            "eth=2054)"
        )

    def test_decode_ethernet_header(self, raw_eth_header):
        """GIVEN a byte-string representation of an Ethernet frame
        header
        WHEN this header is successfully decoded
        THEN an instance of Ethernet must initialize each of its
            attributes in alignment with the byte fields
        """
        eth_header = Ethernet.decode(raw_eth_header)

        assert eth_header.src == "00:07:0d:af:f4:54"
        assert eth_header.dst == "ff:ff:ff:ff:ff:ff"
        assert eth_header.eth == 0x0806
        assert (
            bytes(eth_header) == b"\xff\xff\xff\xff\xff\xff\x00\x07\r\xaf"
            b"\xf4T\x08\x06"
        )
        assert eth_header.encapsulated_proto == "ARP"
