#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from netprotocols import ARP

import pytest

'''
From WireShark sample captures at 
https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/
arp-storm.pcap
'''


class TestARP:
    def test_build_arp_header(self, mock_arp_header):
        """
        GIVEN a set of attributes defining an ARP packet
        WHEN those values are valid and correctly formatted
        THEN an instance of ARP must be initialized without errors
        """
        assert mock_arp_header.htype == 1
        assert mock_arp_header.ptype == 0x0800
        assert mock_arp_header.hlen == 6
        assert mock_arp_header.plen == 4
        assert mock_arp_header.oper == 2
        assert bytes(mock_arp_header.sha) == b"\x00\x07\x0d\xaf\xf4\x54"
        assert bytes(mock_arp_header.spa) == b"\x18\xa6\xac\x01"
        assert bytes(mock_arp_header.tha) == b"\x00\x00\x00\x00\x00\x00"
        assert bytes(mock_arp_header.tpa) == b"\x18\xa6\xad\x9f"
        assert mock_arp_header.encapsulated_proto == "undefined"

    def test_decode_arp_header(self, raw_arp_header):
        """
        GIVEN a byte-string representation of an ARP packet header
        WHEN this header is successfully decoded
        THEN an instance of ARP must initialize each of its attributes
            in alignment with the byte fields
        """
        arp_header = ARP.decode(raw_arp_header)

        assert arp_header.htype == 1
        assert arp_header.ptype == 0x0800
        assert arp_header.hlen == 6
        assert arp_header.plen == 4
        assert arp_header.oper == 1
        assert arp_header.sha == "00:07:0d:af:f4:54"
        assert arp_header.spa == "24.166.172.1"
        assert arp_header.tha == "00:00:00:00:00:00"
        assert arp_header.tpa == "24.166.173.159"
        assert arp_header.encapsulated_proto == "undefined"
