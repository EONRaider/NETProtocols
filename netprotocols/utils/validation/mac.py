#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import re

from netprotocols.utils.exceptions import InvalidMACAddressException
from netprotocols.utils.validation._base import Validator

mac_regex = re.compile(
    r"^(?P<oui>([\dA-F]{2}[:-]){2}[\dA-F]{2})"
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
        except (TypeError, AttributeError) as e:
            """
            TypeError: Raised if 'value' is not of type str.
            AttributeError: Raised if 'value' is of type str but doesn't
                represent a valid MAC address.
            """
            raise InvalidMACAddressException(
                f"InvalidMACAddressException: Invalid format or type for MAC "
                f'address value "{value}"'
            ) from e


def validate_mac_addr(mac: str) -> str:
    """Evaluate a string representing an IEEE 802 compliant MAC address.

    :returns: The supplied string if it corresponds to a valid MAC
        address.

    :raises InvalidMACAddressException: If the supplied string does not
        correspond to a valid MAC address.
    """
    return ValidMACAddress.validate(mac)
