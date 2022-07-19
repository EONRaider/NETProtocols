#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import re
import pytest
from itertools import repeat

from netprotocols.utils import random_mac
from netprotocols.utils.exceptions import InvalidManufacturerCode
from netprotocols.utils.validation.mac import mac_regex


class TestRandomMac:
    def test_random_mac_no_manufacturer(self):
        """GIVEN a call to the random_mac function
        WHEN no manufacturer code is supplied
        THEN a random MAC address must be returned without exceptions
        """
        for _ in repeat(None, 100):
            result = re.match(mac_regex, random_mac())
            assert result

    @pytest.mark.parametrize(
        "manufacturer",
        ["11:22:33", "AA:BB:CC", "11:BB:33", "AA:22:CC", "00:00:00"],
    )
    def test_random_mac_with_manufacturer(self, manufacturer):
        """GIVEN a call to the random_mac function
        WHEN a valid manufacturer code is supplied
        THEN a MAC address containing the manufacturer code appended to
            a random device ID must be returned without exceptions
        """
        result = re.match(mac_regex, random_mac(manufacturer)).group()
        assert (
                re.match(mac_regex, result).group(
                    "manufacturer_id") == manufacturer
        )

    @pytest.mark.parametrize(
        "manufacturer",
        ["AA:BB", "AA:BB:TT", "AA:BB:TT:LL", "11:22:33:44:55:66", {}, "", 1, []]
    )
    def test_random_mac_invalid_manufacturer(self, manufacturer):
        """GIVEN a call to the random_mac function
        WHEN malformed or invalid manufacturer codes are supplied
        THEN an InvalidManufacturerCode exception must be raised
        """
        with pytest.raises(InvalidManufacturerCode):
            random_mac(manufacturer)
