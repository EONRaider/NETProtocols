#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import pytest
from dataclasses import dataclass

from netprotocols.utils.exceptions import InvalidIPv4AddressException
from netprotocols.utils.validation.ipv4 import (
    ValidIPv4Address,
    validate_ipv4_addr,
)


@dataclass
class IPv4:
    ipv4: str = ValidIPv4Address()


class TestIPv4Validation:
    @pytest.mark.parametrize(
        "ipv4_addr",
        [
            "192.168.0.1",
            "127.0.0.1",
            "10.0.10.1",
            "168.189.222.11",
            "56.123.92.100",
        ],
    )
    def test_descriptor_values(self, ipv4_addr):
        """GIVEN a value of type string
        WHEN ths string corresponds to a valid IPv4 address
        THEN an instance of a class that uses the ValidIPv4Address
            descriptor must be initialized without errors
        """
        ipv4_address = IPv4(ipv4_addr)
        assert isinstance(ipv4_address.ipv4, str)

    @pytest.mark.parametrize(
        "ipv4_addr",
        [
            None,
            [],
            {},
            tuple(),
            "some_string",
            "300.128.0.10",
            "20.10.2.500",
            "192.168.1.2.3.4",
        ],
    )
    def test_descriptor_exceptions(self, ipv4_addr):
        """GIVEN a value
        WHEN this value corresponds to an invalid IPv4 address or is
            not of type string
        THEN an exception must be raised
        """
        with pytest.raises(InvalidIPv4AddressException):
            IPv4(ipv4_addr)

    @pytest.mark.parametrize(
        "ipv4_addr",
        [
            "192.168.1.0",
            "127.0.0.1",
            "168.2.3.4",
            "50.60.70.80",
            "200.100.50.10",
        ],
    )
    def test_validate_ipv4_address_valid(self, ipv4_addr):
        """GIVEN a valid IPv4 address
        WHEN ths value is passed as an argument to the
            validate_ipv4_address function
        THEN the function must return the string without exceptions
        """
        assert validate_ipv4_addr(ipv4_addr) == ipv4_addr

    @pytest.mark.parametrize(
        "ipv4_addr",
        [
            "192.168.1.500",
            "400.100.2.9",
            "10.10.10.10.10",
            [],
            {},
            tuple(),
            None,
        ],
    )
    def test_validate_ipv4_address_invalid(self, ipv4_addr):
        """GIVEN an invalid IPv4 address
        WHEN ths value is passed as an argument to the
            validate_ipv4_address function
        THEN an exception must be raised
        """
        with pytest.raises(InvalidIPv4AddressException):
            validate_ipv4_addr(ipv4_addr)
