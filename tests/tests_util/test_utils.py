#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import re

import pytest

import netprotocols.utils as utils


class TestUtils:
    def test_random_mac(self):
        """
        GIVEN a call to the utils.random_mac function
        WHEN the arguments list is correctly passed
        THEN a random MAC address must be returned without exceptions
        """
        valid_mac = re.compile(r"^([\da-fA-F:]){17}$")

        mac_addr = utils.random_mac()
        assert bool(re.match(valid_mac, mac_addr)) is True

        mac_addr = utils.random_mac(manufacturer="AA:BB:CC")
        assert bool(re.match(valid_mac, mac_addr)) is True

        with pytest.raises(TypeError):
            utils.random_mac(manufacturer="AA:BB")
        with pytest.raises(TypeError):
            utils.random_mac(manufacturer="AA:BB:TT")
        with pytest.raises(TypeError):
            utils.random_mac(manufacturer="AA:BB:TT:LL")
