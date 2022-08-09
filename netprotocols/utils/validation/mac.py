#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import re

from netprotocols.utils.exceptions import InvalidMACAddress
from netprotocols.utils.validation._base import Validator

mac_regex = re.compile(
    r"^(?P<manufacturer_id>([\dA-F]{2}[:-]){2}[\dA-F]{2})"
    r"[:-]"
    r"(?P<device_id>([\dA-F]{2}[:-]){2}[\dA-F]{2})$",
    flags=re.IGNORECASE,
)


class ValidMACAddress(Validator):
    """Descriptor for managed attributes in classes that require the
    validation of MAC addresses before assignment/manipulation."""

    @staticmethod
    def validate(value: str) -> str:
        try:
            return re.match(mac_regex, value).group()
        except (TypeError, AttributeError):
            """
            TypeError: Raised if 'value' is not of type str.
            AttributeError: Raised if 'value' is of type str but doesn't
                represent a valid MAC address.
            """
            raise InvalidMACAddress(
                f"Invalid format or type for MAC address value: {value}"
            )


def validate_mac_address(mac_address: str) -> bool:
    """Evaluate a string representing an IEEE 802 compliant MAC address.

    :returns: True if valid and False otherwise.
    """
    try:
        return bool(ValidMACAddress.validate(mac_address))
    except InvalidMACAddress:
        return False
