#!/usr/bin/env python3
# https://github.com/EONRaider/Protocols

__author__ = "EONRaider @ keybase.io/eonraider"

import pytest

from protocols.layer2.ethernet import Ethernet


class MockEthFrame:
    dst_mac = "11:22:33:aa:bb:cc"
    src_mac = "ab:bc:cd:11:22:33"
    ethertype = 0x86dd


@pytest.fixture()
def raw_eth_header():
    return b"\xdc\xd9\xae\x71\xc2\xa3\x00\xc0\xca\xa8\x20\x21\x08\x00"


class TestEthernet:
    def test_build_ethernet_header(self):
        """
        GIVEN a set of MAC addresses and Ethertype
        WHEN those values are valid and correctly formatted
        THEN an instance of Ethernet must be initialized without errors
        """
        eth_header = Ethernet(dst=MockEthFrame.dst_mac,
                              src=MockEthFrame.src_mac,
                              eth=MockEthFrame.ethertype)

        assert bytes(eth_header.dst) == b"\x11\x22\x33\xaa\xbb\xcc"
        assert bytes(eth_header.src) == b"\xab\xbc\xcd\x11\x22\x33"
        assert eth_header.eth == MockEthFrame.ethertype

    def test_decode_ethernet_header(self, raw_eth_header):
        """
        GIVEN a byte-string representation of an Ethernet frame header
        WHEN this header is successfully decoded
        THEN an instance of Ethernet must initialize each of its
            attributes in alignment with the byte fields
        """
        eth_header = Ethernet.decode(raw_eth_header)

        assert eth_header.src == "00:c0:ca:a8:20:21"
        assert eth_header.dst == "dc:d9:ae:71:c2:a3"
        assert eth_header.eth == 0x0800
        assert eth_header.encapsulated_proto == "IPv4"
