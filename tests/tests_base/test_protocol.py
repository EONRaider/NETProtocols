#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from ctypes import Array, c_ubyte
from socket import AF_INET6

from netprotocols import Protocol

import pytest


@pytest.fixture
def mac_bytes():
    return b"\x00\xc0\xca\xa8\x19\x74"


@pytest.fixture
def mac_string():
    return "00:c0:ca:a8:19:74"


@pytest.fixture
def ipv4_addr_bytes():
    return b"\xb9\x9f\x68\x5b"


@pytest.fixture
def ipv4_addr_string():
    return "185.159.104.91"


@pytest.fixture
def ipv6_addr_bytes():
    return b"\xfe\x80\x00\x00\x00\x00\x00\x00" \
           b"\x02\x00\x86\xff\xfe\x05\x80\xda"


@pytest.fixture
def ipv6_addr_string():
    return "fe80::200:86ff:fe05:80da"


class TestProtocol:
    def test_decode_raw_packet(self, raw_ipv4_header):
        """
        GIVEN a network protocol header
        WHEN this header is valid and correctly formatted
        THEN an instance of Protocol must be initialized without errors
        """
        ipv4_header = Protocol.decode(raw_ipv4_header)

        assert isinstance(ipv4_header, Protocol)
        assert ipv4_header.encapsulated_proto is None

    def test_convert_hdwr_to_addr_array(self, mac_bytes, mac_string):
        """
        GIVEN a string of characters
        WHEN this string corresponds to an IEEE 802 compliant MAC
            address
        THEN this string must be converted into an instance of class
            Array with length equal to 6 bytes without errors
        """
        addr_array = Protocol.hdwr_to_addr_array(mac_string)

        assert isinstance(addr_array, Array)
        assert bytes(addr_array) == mac_bytes
        assert len(addr_array) == 6

    def test_convert_addr_array_to_hdwr(self, mac_bytes, mac_string):
        """
        GIVEN a byte-string
        WHEN this byte-string corresponds to an IEEE 802 compliant MAC
            address
        THEN this byte-string must be correctly converted into its
            string representation by the Protocol.addr_array_to_hdwr
            static method
        """
        addr_array = (c_ubyte * 6)(*mac_bytes)

        assert Protocol.addr_array_to_hdwr(addr_array) == mac_string

    def test_convert_ipv4_proto_addr_to_array(self,
                                              ipv4_addr_bytes,
                                              ipv4_addr_string):
        """
        GIVEN a string of characters
        WHEN this string corresponds to an RFC 791 compliant IPv4
            address
        THEN this string must be converted into an instance of class
            Array with length equal to 4 bytes without errors
        """
        addr_array = Protocol.proto_addr_to_array(ipv4_addr_string)

        assert isinstance(addr_array, Array)
        assert bytes(addr_array) == ipv4_addr_bytes
        assert len(addr_array) == 4

    def test_convert_array_to_ipv4_proto_addr(self,
                                              ipv4_addr_bytes,
                                              ipv4_addr_string):
        """
        GIVEN a byte-string
        WHEN this byte-string corresponds to an RFC 791 compliant IPv4
            address
        THEN this byte-string must be correctly converted into its
            string representation by the Protocol.array_to_proto_addr
            static method
        """
        addr_array = (c_ubyte * 4)(*ipv4_addr_bytes)

        assert Protocol.array_to_proto_addr(addr_array) == ipv4_addr_string

    def test_convert_ipv6_proto_addr_to_array(self,
                                              ipv6_addr_bytes,
                                              ipv6_addr_string):
        """
        GIVEN a string of characters
        WHEN this string corresponds to an RFC 2460 compliant IPv6
            address
        THEN this string must be converted into an instance of class
            Array with length equal to 16 bytes without errors
        """
        addr_array = Protocol.proto_addr_to_array(ipv6_addr_string, AF_INET6)

        assert isinstance(addr_array, Array)
        assert bytes(addr_array) == ipv6_addr_bytes
        assert len(addr_array) == 16

    def test_convert_array_to_ipv6_proto_addr(self,
                                              ipv6_addr_bytes,
                                              ipv6_addr_string):
        """
        GIVEN a byte-string
        WHEN this byte-string corresponds to an RFC 2460 compliant IPv6
            address
        THEN this byte-string must be correctly converted into its
            string representation by the Protocol.array_to_proto_addr
            static method
        """
        addr_array = (c_ubyte * 16)(*ipv6_addr_bytes)

        assert Protocol.array_to_proto_addr(
            addr_array, AF_INET6) == ipv6_addr_string
