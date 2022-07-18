#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import re

from netprotocols.utils.exceptions import InvalidMACAddress


mac_regex = re.compile(
    r"^([\dA-F]{2}[:-]){5}([\dA-F]{2})$", flags=re.IGNORECASE
)


class MACAddress:
    """Descriptor for managed attributes in classes that require the
    validation of MAC addresses before assignment/manipulation."""

    def __get__(self, instance, owner=None) -> str:
        return self.value

    def __set__(self, instance, value: str) -> None:
        try:
            if not (mac_addr := re.match(mac_regex, value)).group():
                """Raised if 'value' is of type string but does not
                represent a valid MAC address"""
                raise TypeError
        except (TypeError, AttributeError):
            # Raised if 'value' is not of type str
            raise InvalidMACAddress(
                "Incorrect format/type for MAC address value."
            )
        self.value = mac_addr.group()


def validate_mac_address(mac_address: str) -> bool:
    """Evaluate a string representing an IEEE 802 compliant MAC address.

    :returns: True if valid and False otherwise.
    """
    try:
        return bool(re.match(mac_regex, mac_address))
    except TypeError:
        # Raised if 'mac_addr' is not of type str
        return False
