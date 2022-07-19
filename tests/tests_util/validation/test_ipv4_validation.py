#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import pytest
from dataclasses import dataclass

from netprotocols.utils.exceptions import InvalidIPv4Address
from netprotocols.utils.validation.ipv4 import (
    IPv4Address,
    validate_ipv4_address,
)


@dataclass
class IPv4:
    ipv4: str = IPv4Address()


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
        """GIVEN a set of strings
        WHEN those strings correspond to valid IPv4 addresses
        THEN an instance of a class that uses the IPv4Address descriptor
            must be initialized without errors
        """
        ipv4_address = IPv4(ipv4_addr)
        assert isinstance(ipv4_address.ipv4, str)

    @pytest.mark.parametrize(
        "ipv4_addr",
        [
            None,
            123456,
            "some_string",
            "300.128.0.10",
            "20.10.2.500",
            "192.168.1.2.3.4",
        ],
    )
    def test_descriptor_exceptions(self, ipv4_addr):
        """GIVEN a set of strings
        WHEN those strings correspond to invalid IPv4 addresses
        THEN an InvalidIPv4Address exception must be raised at each
            instantiation
        """
        with pytest.raises(InvalidIPv4Address):
            IPv4(ipv4_addr)

    @pytest.mark.parametrize(
        "ipv4_addr, is_valid",
        [
            ("192.168.1.0", True),
            ("127.0.0.1", True),
            ("168.2.3.4", True),
            ("50.60.70.80", True),
            ("200.100.50.10", True),
            ("192.168.1.500", False),
            ("400.100.2.9", False),
            (123456, False),
            (None, False),
        ],
    )
    def test_validate_ipv4_address(self, ipv4_addr, is_valid):
        """GIVEN a set of values of different types
        WHEN those values are passed as parameters to the
            validate_ipv4_address function
        THEN the function must return the correct boolean object
            corresponding to the validation of each value
        """
        assert validate_ipv4_address(ipv4_addr) is is_valid
