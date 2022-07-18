#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import re

from netprotocols.utils.exceptions import InvalidIPv4Address


ipv4_regex = re.compile(
    r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$", flags=re.IGNORECASE
)


class IPv4Address:
    """Descriptor for managed attributes in classes that require the
    validation of IPv4 addresses before assignment/manipulation."""

    def __get__(self, instance, owner=None) -> str:
        return self.value

    def __set__(self, instance, value: str) -> None:
        try:
            if not (ipv4_addr := re.match(ipv4_regex, value)).group():
                """Raised if 'value' is of type string but does not
                represent a valid IPv4 address"""
                raise TypeError
        except (TypeError, AttributeError):
            # Raised if 'value' is not of type str
            raise InvalidIPv4Address(
                "Incorrect format/type for IPv4 address value."
            )
        self.value = ipv4_addr.group()


def validate_ipv4_address(ipv4_address: str) -> bool:
    """Evaluate a string representing a valid IPv4 address.

    :returns: True if valid and False otherwise.
    """
    try:
        return bool(re.match(ipv4_regex, ipv4_address))
    except TypeError:
        # Raised if 'ipv4_address' is not of type str
        return False
