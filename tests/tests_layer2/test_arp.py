#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import pytest

from netprotocols.layer2.arp import ARP


@pytest.fixture
def mock_arp_header():
    return ARP(
        htype=1,
        ptype=0x0800,
        hlen=6,
        plen=4,
        oper=2,
        sha="00:c0:ca:11:22:33",
        spa="192.168.1.96",
        tha="dc:d9:ae:aa:bb:cc",
        tpa="192.168.1.254"
    )


@pytest.fixture
def raw_arp_header():
    return b"\x00\x01\x08\x00\x06\x04\x00\x02\x00\xc0\xca\x11\x22\x33\xc0\xa8" \
           b"\x01\x60\xdc\xd9\xae\xaa\xbb\xcc\xc0\xa8\x01\xfe"


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
        assert bytes(mock_arp_header.sha) == b"\x00\xc0\xca\x11\x22\x33"
        assert bytes(mock_arp_header.spa) == b"\xc0\xa8\x01\x60"
        assert bytes(mock_arp_header.tha) == b"\xdc\xd9\xae\xaa\xbb\xcc"
        assert bytes(mock_arp_header.tpa) == b"\xc0\xa8\x01\xfe"
        assert mock_arp_header.encapsulated_proto is None

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
        assert arp_header.oper == 2
        assert arp_header.sha == "00:c0:ca:11:22:33"
        assert arp_header.spa == "192.168.1.96"
        assert arp_header.tha == "dc:d9:ae:aa:bb:cc"
        assert arp_header.tpa == "192.168.1.254"
        assert arp_header.encapsulated_proto is None
