#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from netprotocols import IPv4, IPv6

import pytest


@pytest.fixture
def mock_ipv4_header():
    return IPv4(
        version=4,
        ihl=5,
        dscp=0,
        ecp=0,
        len=40,
        id=0xEC6C,
        flags=2,
        offset=0,
        ttl=64,
        proto=0x06,
        chksum=0x2B51,
        src="192.168.1.96",
        dst="192.168.1.254",
    )


@pytest.fixture
def mock_ipv6_header():
    return IPv6(
        version=6,
        tclass=0,
        flabel=0,
        payload_len=120,
        next_header=0x06,
        hop_limit=255,
        src="fe80::1",
        dst="ff02::1",
    )


@pytest.fixture
def raw_ipv6_header():
    return (
        b"\x60\x00\x00\x00\x00\x78\x06\xff\xfe\x80\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x01\xff\x02\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x01"
    )


class TestIPv4:
    def test_build_ipv4_header(self, mock_ipv4_header):
        """GIVEN a set of attributes defining an IPv4 packet
        WHEN those values are valid and correctly formatted
        THEN an instance of IPv4 must be initialized without errors
        """
        assert mock_ipv4_header.version == 4
        assert mock_ipv4_header.ihl == 5
        assert mock_ipv4_header.dscp == 0
        assert mock_ipv4_header.ecp == 0
        assert mock_ipv4_header.len == 40
        assert mock_ipv4_header.id == 0xEC6C
        assert mock_ipv4_header.flags == 2
        assert mock_ipv4_header.offset == 0
        assert mock_ipv4_header.ttl == 64
        assert mock_ipv4_header.proto == 0x06
        assert mock_ipv4_header.chksum == 0x2B51
        assert mock_ipv4_header.chksum_hex_str == "0x2b51"
        assert bytes(mock_ipv4_header.src) == b"\xc0\xa8\x01\x60"
        assert bytes(mock_ipv4_header.dst) == b"\xc0\xa8\x01\xfe"
        assert mock_ipv4_header.encapsulated_proto == "TCP"
        assert mock_ipv4_header.flags_str == "Don't fragment (DF)"
        assert (
            repr(mock_ipv4_header)
            == "IPv4(version=4, ihl=5, dscp=0, ecp=0, len=40, id=60524, "
            "flags=2, offset=0, ttl=64, proto=6, chksum=11089, "
            'src="192.168.1.96", dst="192.168.1.254")'
        )

    def test_decode_ipv4_header(self, raw_ipv4_header):
        """GIVEN a byte-string representation of an IPv4 packet header
        WHEN this header is successfully decoded
        THEN an instance of IPv4 must initialize each of its attributes
            in alignment with the byte fields
        """
        ipv4_header = IPv4.decode(raw_ipv4_header)

        assert ipv4_header.version == 4
        assert ipv4_header.ihl == 5
        assert ipv4_header.dscp == 0
        assert ipv4_header.ecp == 0
        assert ipv4_header.len == 40
        assert ipv4_header.id == 0xEC6C
        assert ipv4_header.flags == 2
        assert ipv4_header.offset == 0
        assert ipv4_header.ttl == 64
        assert ipv4_header.proto == 0x06
        assert ipv4_header.chksum == 0x2B51
        assert ipv4_header.chksum_hex_str == "0x2b51"
        assert ipv4_header.src == "192.168.1.96"
        assert ipv4_header.dst == "192.168.1.254"
        assert ipv4_header.encapsulated_proto == "TCP"
        assert ipv4_header.flags_str == "Don't fragment (DF)"


class TestIPv6:
    def test_build_ipv6_header(self, mock_ipv6_header):
        """GIVEN a set of attributes defining an IPv6 packet
        WHEN those values are valid and correctly formatted
        THEN an instance of IPv6 must be initialized without errors
        """
        assert mock_ipv6_header.version == 6
        assert mock_ipv6_header.tclass == 0
        assert mock_ipv6_header.tclass_hex_str == "0x000"
        assert mock_ipv6_header.flabel == 0
        assert mock_ipv6_header.flabel_hex_str == "0x000"
        assert mock_ipv6_header.payload_len == 120
        assert mock_ipv6_header.next_header == 0x06
        assert mock_ipv6_header.hop_limit == 255
        assert (
            bytes(mock_ipv6_header.src) == b"\xfe\x80\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x01"
        )
        assert (
            bytes(mock_ipv6_header.dst) == b"\xff\x02\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x01"
        )
        assert mock_ipv6_header.encapsulated_proto == "TCP"
        assert (
            repr(mock_ipv6_header)
            == "IPv6(version=6, tclass=0, flabel=0, payload_len=120, "
            'next_header=6, hop_limit=255, src="fe80::1", dst="ff02::1")'
        )

    def test_decode_ipv6_header(self, raw_ipv6_header):
        """GIVEN a byte-string representation of an IPv6 packet header
        WHEN this header is successfully decoded
        THEN an instance of IPv6 must initialize each of its attributes
            in alignment with the byte fields
        """
        ipv6_header = IPv6.decode(raw_ipv6_header)

        assert ipv6_header.version == 6
        assert ipv6_header.tclass == 0
        assert ipv6_header.tclass_hex_str == "0x000"
        assert ipv6_header.flabel == 0
        assert ipv6_header.flabel_hex_str == "0x000"
        assert ipv6_header.payload_len == 120
        assert ipv6_header.next_header == 0x06
        assert ipv6_header.hop_limit == 255
        assert ipv6_header.src == "fe80::1"
        assert ipv6_header.dst == "ff02::1"
        assert ipv6_header.encapsulated_proto == "TCP"
