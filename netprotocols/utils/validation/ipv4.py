#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import ipaddress

from netprotocols.utils.exceptions import InvalidIPv4Address
from netprotocols.utils.validation._base import Validator


class ValidIPv4Address(Validator):
    """Descriptor for managed attributes in classes that require the
    validation of IPv4 addresses before assignment/manipulation."""

    @staticmethod
    def validate(value: str) -> str:
        try:
            if not issubclass(value.__class__, str):
                raise ipaddress.AddressValueError
            return str(ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError:
            raise InvalidIPv4Address(
                f"Invalid format or type for IPv4 address value: {value}"
            )


def validate_ipv4_address(ipv4_address: str) -> bool:
    """Evaluate a string representing a valid IPv4 address.

    :returns: True if valid and False otherwise.
    """
    try:
        return bool(ValidIPv4Address.validate(ipv4_address))
    except InvalidIPv4Address:
        return False
