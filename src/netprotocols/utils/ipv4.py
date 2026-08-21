"""IPv4 address validation."""

import re

from netprotocols.utils.exceptions import InvalidIPv4AddressError

__all__ = ["ipv4_regex", "validate_ipv4_addr"]

_octet = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
ipv4_regex = re.compile(rf"^({_octet}\.){{3}}{_octet}$")


def validate_ipv4_addr(addr: str) -> str:
    """Evaluate a string representing an IPv4 address in dotted-decimal
    notation.

    :returns: The supplied string, unchanged, if it is a valid IPv4
        address.
    :raises InvalidIPv4AddressError: If the supplied value is not a
        string or does not represent a valid IPv4 address.
    """
    try:
        match = ipv4_regex.match(addr)
    except TypeError as e:
        raise InvalidIPv4AddressError(
            f"Invalid type for IPv4 address value {addr!r}"
        ) from e
    if match is None:
        raise InvalidIPv4AddressError(
            f"Invalid format for IPv4 address value {addr!r}"
        )
    return addr
