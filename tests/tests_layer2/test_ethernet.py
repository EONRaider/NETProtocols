#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from netprotocols import Ethernet

import pytest

'''
From WireShark sample captures at 
https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/
arp-storm.pcap
'''


class TestEthernet:
    def test_build_ethernet_header(self, mock_eth_header):
        """
        GIVEN a set of MAC addresses and Ethertype
        WHEN those values are valid and correctly formatted
        THEN an instance of Ethernet must be initialized without errors
        """
        assert bytes(mock_eth_header.dst) == b"\xff\xff\xff\xff\xff\xff"
        assert bytes(mock_eth_header.src) == b"\x00\x07\x0d\xaf\xf4\x54"
        assert mock_eth_header.eth == 0x0806

    def test_decode_ethernet_header(self, raw_eth_header):
        """
        GIVEN a byte-string representation of an Ethernet frame header
        WHEN this header is successfully decoded
        THEN an instance of Ethernet must initialize each of its
            attributes in alignment with the byte fields
        """
        eth_header = Ethernet.decode(raw_eth_header)

        assert eth_header.src == "00:07:0d:af:f4:54"
        assert eth_header.dst == "ff:ff:ff:ff:ff:ff"
        assert eth_header.eth == 0x0806
        assert eth_header.encapsulated_proto == "ARP"
