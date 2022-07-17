#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from netprotocols import TCP

import pytest


@pytest.fixture
def mock_tcp_header():
    return TCP(
        sport=1022,
        dport=22,
        seq=209327191,
        ack=3598120581,
        offset=8,
        reserved=0,
        flags=0x018,
        window=8540,
        chksum=0x2008,
        urg=0,
    )


@pytest.fixture
def raw_tcp_header():
    return (
        b"\x03\xfe\x00\x16\xd6\x76\xf6\x71\x0c\x7a\x14\x57\x80\x18\x21\x5c"
        b"\x20\x08\x00\x00\x01\x01\x08\x0a\x00\x08\xca\x61\x00\x01\x69\x2e"
    )


class TestTCP:
    def test_build_tcp_header(self, mock_tcp_header):
        """GIVEN a set of attributes defining an TCP packet
        WHEN those values are valid and correctly formatted
        THEN an instance of TCP must be initialized without errors
        """
        assert mock_tcp_header.sport == 1022
        assert mock_tcp_header.dport == 22
        assert mock_tcp_header.seq == 209327191
        assert mock_tcp_header.ack == 3598120581
        assert mock_tcp_header.offset == 8
        assert mock_tcp_header.reserved == 0
        assert mock_tcp_header.flags == 0x018
        assert mock_tcp_header.window == 8540
        assert mock_tcp_header.chksum == 0x2008
        assert mock_tcp_header.urg == 0
        assert mock_tcp_header.flags_hex_str == "0x018"
        assert mock_tcp_header.flags_str == "PSH ACK"
        assert mock_tcp_header.encapsulated_proto == "undefined"
        assert (
            repr(mock_tcp_header)
            == "TCP(sport=1022, dport=22, seq=209327191, ack=3598120581, "
            "offset=8, reserved=0, flags=24, window=8540, chksum=8200, "
            "urg=0)"
        )

    def test_decode_tcp_header(self, raw_tcp_header):
        """GIVEN a byte-string representation of an TCP packet header
        WHEN this header is successfully decoded
        THEN an instance of TCP must initialize each of its attributes
            in alignment with the byte fields
        """
        tcp_header = TCP.decode(raw_tcp_header)

        assert tcp_header.sport == 1022
        assert tcp_header.dport == 22
        assert tcp_header.seq == 3598120561
        assert tcp_header.ack == 209327191
        assert tcp_header.offset == 8
        assert tcp_header.reserved == 0
        assert tcp_header.flags == 0x018
        assert tcp_header.window == 8540
        assert tcp_header.chksum == 0x2008
        assert tcp_header.urg == 0
        assert tcp_header.flags_hex_str == "0x018"
        assert tcp_header.flags_str == "PSH ACK"
        assert tcp_header.encapsulated_proto == "undefined"
