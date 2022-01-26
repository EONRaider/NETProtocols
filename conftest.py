#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from netprotocols import ARP, Ethernet

import pytest


@pytest.fixture
def mock_eth_header():
    return Ethernet(
        dst="ff:ff:ff:ff:ff:ff",
        src="00:07:0d:af:f4:54",
        eth=0x0806
    )


@pytest.fixture
def raw_eth_header():
    return b"\xff\xff\xff\xff\xff\xff\x00\x07\x0d\xaf\xf4\x54\x08\x06"


@pytest.fixture
def mock_arp_header():
    return ARP(
        htype=1,
        ptype=0x0800,
        hlen=6,
        plen=4,
        oper=2,
        sha="00:07:0d:af:f4:54",
        spa="24.166.172.1",
        tha="00:00:00:00:00:00",
        tpa="24.166.173.159"
    )


@pytest.fixture
def raw_arp_header():
    return b"\x00\x01\x08\x00\x06\x04\x00\x01\x00\x07\x0d\xaf\xf4\x54" \
           b"\x18\xa6\xac\x01\x00\x00\x00\x00\x00\x00\x18\xa6\xad\x9f"


@pytest.fixture
def raw_ipv4_header():
    return b"\x45\x00\x00\x28\xec\x6c\x40\x00\x40\x06\x2b\x51\xc0\xa8\x01\x60" \
           b"\xc0\xa8\x01\xfe"
