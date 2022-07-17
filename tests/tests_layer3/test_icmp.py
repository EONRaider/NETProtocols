#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from netprotocols import ICMPv4, ICMPv6

import pytest


@pytest.fixture
def mock_icmpv4_header():
    return ICMPv4(type=8, code=0, chksum=0x83F7, rest=b"\x00\x01\x00\x01")


@pytest.fixture
def raw_icmpv4_header():
    return (
        b"\x08\x00\x83\xf7\x00\x01\x00\x01\xbf\xc8\xea\x61\x00\x00\x00\x00"
        b"\x08\x09\x03\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17"
        b"\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27"
        b"\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
    )


@pytest.fixture
def mock_icmpv6_header():
    return ICMPv6(type=128, code=0, chksum=0x3F69, m_body=b"\x76\x20\x01\x00")


@pytest.fixture
def raw_icmpv6_header():
    return b"\x80\x00\x3f\x69\x76\x20\x01\x00\x02\xc9\xe7\x36\x37\x43\x06\x00"


class TestICMP:
    def test_build_icmpv4_header(self, mock_icmpv4_header):
        """GIVEN a set of attributes defining an ICMPv4 packet
        WHEN those values are valid and correctly formatted
        THEN an instance of ICMPv4 must be initialized without errors
        """
        assert mock_icmpv4_header.type == 8
        assert mock_icmpv4_header.code == 0
        assert mock_icmpv4_header.chksum == 0x83F7
        assert bytes(mock_icmpv4_header.rest) == b"\x00\x01\x00\x01"
        assert mock_icmpv4_header.encapsulated_proto == "undefined"
        assert mock_icmpv4_header.type_str == "Echo Request"
        assert (
            repr(mock_icmpv4_header) == "ICMPv4(type=8, code=0, chksum=33783, "
            "rest=b'\\x00\\x01\\x00\\x01')"
        )

    def test_decode_icmpv4_header(self, raw_icmpv4_header):
        """GIVEN a byte-string representation of an ICMPv4 packet header
        WHEN this header is successfully decoded
        THEN an instance of ICMPv4 must initialize each of its
            attributes in alignment with the byte fields
        """
        icmpv4_header = ICMPv4.decode(raw_icmpv4_header)

        assert icmpv4_header.type == 8
        assert icmpv4_header.code == 0
        assert icmpv4_header.chksum == 0x83F7
        assert icmpv4_header.rest == b"\x00\x01\x00\x01"
        assert icmpv4_header.encapsulated_proto == "undefined"
        assert icmpv4_header.type_str == "Echo Request"

    def test_build_icmpv6_header(self, mock_icmpv6_header):
        """GIVEN a set of attributes defining an ICMPv6 packet
        WHEN those values are valid and correctly formatted
        THEN an instance of ICMPv6 must be initialized without errors
        """
        assert mock_icmpv6_header.type == 128
        assert mock_icmpv6_header.code == 0
        assert mock_icmpv6_header.chksum == 0x3F69
        assert bytes(mock_icmpv6_header.m_body) == b"\x76\x20\x01\x00"
        assert mock_icmpv6_header.type_str == "Echo Request"
        assert (
            repr(mock_icmpv6_header)
            == "ICMPv6(type=128, code=0, chksum=16233, "
            "m_body=b'v \\x01\\x00')"
        )

    def test_decode_icmpv6_header(self, raw_icmpv6_header):
        """GIVEN a byte-string representation of an ICMPv6 packet header
        WHEN this header is successfully decoded
        THEN an instance of ICMPv6 must initialize each of its
            attributes in alignment with the byte fields
        """
        icmpv6_header = ICMPv6.decode(raw_icmpv6_header)

        assert icmpv6_header.type == 128
        assert icmpv6_header.code == 0
        assert icmpv6_header.chksum == 0x3F69
        assert icmpv6_header.m_body == b"\x76\x20\x01\x00"
        assert icmpv6_header.type_str == "Echo Request"
