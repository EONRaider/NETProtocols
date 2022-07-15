#!/usr/bin/env python3
# https://github.com/EONRaider/NETProtocols

__author__ = "EONRaider @ keybase.io/eonraider"

import string
import re
from random import choices


def random_mac(manufacturer: str = "") -> str:
    """Return a string containing a randomly generated IEEE 802
    compliant MAC address that includes an optionally fixed manufacturer
    code."""
    if len(manufacturer) != 0 and not \
            bool(re.match(r"^([\da-fA-F:]){8}$", manufacturer)):
        raise TypeError("A manufacturer code must be a string consisting of "
                        "3 octets represented as hexadecimal characters "
                        "separated by colons (i.e. \"AA:BB:CC\"")

    device_only: bool = True if len(manufacturer) == 0 else False
    device_code: str = ":".join("".join(choices(string.hexdigits.upper(), k=2))
                                for _ in range(6 if device_only else 3))

    return device_code if device_only else ":".join((manufacturer, device_code))
