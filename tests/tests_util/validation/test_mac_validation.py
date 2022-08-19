#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import pytest
from dataclasses import dataclass

from netprotocols.utils.exceptions import InvalidMACAddressException
from netprotocols.utils.validation.mac import (
    ValidMACAddress,
    validate_mac_addr,
)


@dataclass
class MAC:
    mac: str = ValidMACAddress()


class TestMACValidation:
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
        """GIVEN a value of type string
        WHEN this value corresponds to a valid MAC address
        THEN an instance of a class that uses the ValidMACAddress
            descriptor must be initialized without errors
        """
        mac_address1 = MAC(mac_addr)
        assert issubclass(mac_address1.mac.__class__, str)

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
        """GIVEN a value of type string
        WHEN this string do not correspond to a valid MAC address
        THEN an exception must be raised
        """
        with pytest.raises(InvalidMACAddressException):
            MAC(mac_addr)

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
    def test_validate_mac_address_valid(self, mac_addr):
        """GIVEN a valid MAC address
        WHEN this value is passed as an argument to the
            validate_mac_address function
        THEN the function must return the string without exceptions
        """
        assert validate_mac_addr(mac_addr) == mac_addr

    @pytest.mark.parametrize(
        "mac_addr",
        [
            "AA:BB:CC:44:GG:66",
            "AA-BB-OO-44-GG-66",
            123456,
            None,
        ],
    )
    def test_validate_mac_address_invalid(self, mac_addr):
        """GIVEN an invalid MAC address
        WHEN this value is passed as an argument to the
            validate_mac_address function
        THEN an exception must be raised
        """
        with pytest.raises(InvalidMACAddressException):
            validate_mac_addr(mac_addr)
