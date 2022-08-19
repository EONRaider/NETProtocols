#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

from ipaddress import AddressValueError, IPv4Address
from typing import Union

from netprotocols.utils.exceptions import InvalidIPv4AddressException
from netprotocols.utils.validation._base import Validator


class ValidIPv4Address(Validator):
    """Descriptor for managed attributes in classes that require the
    validation of IPv4 addresses before assignment/manipulation."""

    @staticmethod
    def validate(value: Union[str, IPv4Address]) -> str:
        try:
            if issubclass(value.__class__, IPv4Address):
                return value
            return str(IPv4Address(value))
        except AddressValueError as e:
            raise InvalidIPv4AddressException(
                f"Invalid format or type for IPv4 address value: {value}"
            ) from e


def validate_ipv4_addr(ip: str) -> str:
    """Evaluate a string representing a valid IPv4 address.

    :returns: The supplied string if it corresponds to a valid IPv4
        address.

    :raises InvalidIPv4AddressException: If the supplied string does not
        correspond to a valid IPv4 address.
    """
    return ValidIPv4Address.validate(ip)
