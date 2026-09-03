"""MAC address validation and generation."""

import re
import string
from random import choices

from netprotocols.utils.exceptions import (
    InvalidMACAddressError,
    InvalidManufacturerCodeError,
)

__all__ = ["mac_regex", "random_mac", "validate_mac_addr"]

mac_regex = re.compile(
    r"^(?P<oui>([\dA-F]{2}[:-]){2}[\dA-F]{2})"
    r"[:-]"
    r"(?P<device_id>([\dA-F]{2}[:-]){2}[\dA-F]{2})$",
    flags=re.IGNORECASE,
)


def validate_mac_addr(
    mac: str,
    *,
    protocol: type[object] | None = None,
    field: str | None = None,
) -> str:
    """Evaluate a string representing an IEEE 802 compliant MAC address.

    :param protocol: The class this address belongs to, attached to a
        raised error for diagnostics; the header ``__post_init__``
        methods that call this pass their own class.
    :param field: Name of the field being validated, likewise attached
        for diagnostics.
    :returns: The supplied string, unchanged, if it is a valid MAC
        address.
    :raises InvalidMACAddressError: If the supplied value is not a
        string or does not represent a valid MAC address.
    """
    try:
        match = mac_regex.match(mac)
    except TypeError as e:
        raise InvalidMACAddressError(
            f"Invalid type for MAC address value {mac!r}",
            protocol=protocol,
            field=field,
            actual=mac,
        ) from e
    if match is None:
        raise InvalidMACAddressError(
            f"Invalid format for MAC address value {mac!r}",
            protocol=protocol,
            field=field,
            actual=mac,
        )
    return mac


def random_mac(manufacturer: str | None = None) -> str:
    """Return a randomly generated IEEE 802 compliant MAC address.

    :param manufacturer: Optional OUI (Organizationally Unique
        Identifier) to fix as the address prefix, given as three
        colon-separated octets in hexadecimal, e.g. ``"AA:BB:CC"``.
    :raises InvalidManufacturerCodeError: If ``manufacturer`` is not a
        valid OUI prefix.
    """
    if manufacturer is not None and not mac_regex.match(
        f"{manufacturer}:00:00:00"
    ):
        raise InvalidManufacturerCodeError(
            "A manufacturer code must be a string consisting of 3 octets "
            "represented as hexadecimal characters separated by colons "
            '(i.e. "AA:BB:CC")',
            field="manufacturer",
            actual=manufacturer,
        )
    rand_mac: str = ":".join(
        "".join(choices(string.hexdigits.upper(), k=2))
        for _ in range(3 if manufacturer else 6)
    )
    return f"{manufacturer}:{rand_mac}" if manufacturer else rand_mac
