#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from netprotocols import UDP

import pytest


@pytest.fixture
def mock_udp_header():
    return UDP(sport=2398, dport=53, len=41, chksum=0x3649)


@pytest.fixture
def raw_udp_header():
    return b"\x09\x5e\x00\x35\x00\x29\x36\x49"


class TestUDP:
    def test_build_udp_header(self, mock_udp_header):
        """GIVEN a set of attributes defining a UDP packet
        WHEN those values are valid and correctly formatted
        THEN an instance of UDP must be initialized without errors
        """
        assert mock_udp_header.sport == 2398
        assert mock_udp_header.dport == 53
        assert mock_udp_header.len == 41
        assert mock_udp_header.chksum == 0x3649
        assert mock_udp_header.encapsulated_proto == "undefined"
        assert (
            repr(mock_udp_header)
            == "UDP(sport=2398, dport=53, len=41, chksum=13897)"
        )

    def test_decode_udp_header(self, raw_udp_header):
        """GIVEN a byte-string representation of a UDP packet header
        WHEN this header is successfully decoded
        THEN an instance of UDP must initialize each of its attributes
            in alignment with the byte fields
        """
        udp_header = UDP.decode(raw_udp_header)

        assert udp_header.sport == 2398
        assert udp_header.dport == 53
        assert udp_header.len == 41
        assert udp_header.chksum == 0x3649
        assert udp_header.encapsulated_proto == "undefined"
