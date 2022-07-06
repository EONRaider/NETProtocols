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
def raw_ipv4_header():
    return b"\x45\x00\x00\x28\xec\x6c\x40\x00\x40\x06\x2b\x51\xc0\xa8\x01\x60" \
           b"\xc0\xa8\x01\xfe"
