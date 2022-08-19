#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import string
import re
from random import choices

from netprotocols.utils.exceptions import InvalidManufacturerCode
from netprotocols.utils.validation.mac import mac_regex


def random_mac(manufacturer: str = None) -> str:
    """Return a string containing a randomly generated IEEE 802
    compliant MAC address that includes an optionally fixed OUI
    (Organizationally Unique Identifier)."""

    try:
        if manufacturer is not None:
            re.match(mac_regex, f"{manufacturer}:00:00:00").group()
    except AttributeError:
        raise InvalidManufacturerCode(
            "A manufacturer code must be a string consisting of 3 octets "
            "represented as hexadecimal characters separated by colons (i.e. "
            '"AA:BB:CC")'
        )

    rand_mac: str = ":".join(
        "".join(choices(string.hexdigits.upper(), k=2))
        for _ in range(3 if manufacturer else 6)
    )

    return ":".join((manufacturer, rand_mac)) if manufacturer else rand_mac
