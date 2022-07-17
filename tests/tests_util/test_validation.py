#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import pytest

from netprotocols.utils.exceptions import InvalidMACAddress
from netprotocols.utils.validation import MACAddress, validate_mac_address


class MAC:
    mac = MACAddress()

    def __init__(self, mac):
        self.mac = mac


class TestValidation:
    @pytest.mark.parametrize(
        "mac_addr",
        [
            "11:11:11:11:11:11",
            "22-22-22-22-22-22",
            "AA:BB:CC:DD:EE:FF",
            "AA:BB:CC:44:55:66",
            "AA-BB-CC-44-55-66",
        ],
    )
    def test_descriptor_values(self, mac_addr):
        mac_address1 = MAC(mac_addr)
        assert isinstance(mac_address1.mac, str)

    @pytest.mark.parametrize(
        "mac_addr",
        [
            None,
            123456,
            "some_string",
            "11:22:33",
            "11:22:33:44:55:TT",
            "AA-BB-CC-DD-EE-PP",
        ],
    )
    def test_descriptor_exceptions(self, mac_addr):
        with pytest.raises(InvalidMACAddress):
            MAC(mac_addr)

    @pytest.mark.parametrize(
        "mac_addr, is_valid",
        [
            ("11:11:11:11:11:11", True),
            ("22-22-22-22-22-22", True),
            ("AA:BB:CC:DD:EE:FF", True),
            ("AA:BB:CC:44:55:66", True),
            ("AA-BB-CC-44-55-66", True),
            ("AA:BB:CC:44:GG:66", False),
            ("AA-BB-OO-44-GG-66", False),
            (123456, False),
            (None, False),
        ],
    )
    def test_validate_mac_address(self, mac_addr, is_valid):
        assert validate_mac_address(mac_addr) is is_valid
