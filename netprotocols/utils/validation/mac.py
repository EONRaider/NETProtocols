#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import re
from dataclasses import dataclass

from netprotocols.utils.exceptions import InvalidMACAddressException
from netprotocols.utils.validation._base import Validator

mac_regex = re.compile(
    r"^(?P<oui>([\dA-F]{2}[:-]){2}[\dA-F]{2})"
    r"[:-]"
    r"(?P<device_id>([\dA-F]{2}[:-]){2}[\dA-F]{2})$",
    flags=re.IGNORECASE,
)


@dataclass
class _MACAddress:
    addr: str  # String representation of the MAC address
    device: str  # Device unique identifier
    oui: str  # IEEE-assigned Organizationally Unique Identifier


class ValidMACAddress(Validator):
    """Descriptor for managed attributes in classes that require the
    validation of MAC addresses before assignment/manipulation."""

    @staticmethod
    def validate(value: str) -> _MACAddress:
        try:
            valid_mac = re.match(mac_regex, value)
            return _MACAddress(
                addr=valid_mac.group(),
                device=valid_mac.group("device_id"),
                oui=valid_mac.group("oui"),
            )
        except (TypeError, AttributeError):
            """
            TypeError: Raised if 'value' is not of type str.
            AttributeError: Raised if 'value' is of type str but doesn't
                represent a valid MAC address.
            """
            raise InvalidMACAddressException(
                f'InvalidMACAddressException: Invalid format or type for MAC '
                f'address value "{value}"'
            )


def validate_mac_address(mac_address: str) -> bool:
    """Evaluate a string representing an IEEE 802 compliant MAC address.

    :returns: True if valid and False otherwise.
    """
    try:
        return bool(ValidMACAddress.validate(mac_address))
    except InvalidMACAddressException:
        return False
