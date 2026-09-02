"""Exception hierarchy for netprotocols.

Every exception raised by this library derives from :class:`ProtocolError`,
so callers can guard an entire decode pipeline with a single handler.
"""

__all__ = [
    "InvalidFieldError",
    "InvalidIPv4AddressError",
    "InvalidMACAddressError",
    "InvalidManufacturerCodeError",
    "MaxDepthExceededError",
    "ProtocolError",
    "TruncatedHeaderError",
]


class ProtocolError(Exception):
    """Base class for all errors raised by netprotocols."""


class TruncatedHeaderError(ProtocolError):
    """A buffer is shorter than the header it claims to contain.

    Raised when the fixed portion of a header does not fit in the
    supplied buffer, or when a variable-length header (IPv4 IHL, TCP
    data offset) declares a length that exceeds the available bytes.
    """


class InvalidFieldError(ProtocolError):
    """A header field holds a value that violates its protocol's rules.

    Examples: an IPv4 IHL below 5, a TCP data offset below 5, or an
    options payload whose length disagrees with the declared header
    length.
    """


class InvalidMACAddressError(InvalidFieldError):
    """A string does not represent a valid IEEE 802 MAC address."""


class InvalidIPv4AddressError(InvalidFieldError):
    """A string does not represent a valid IPv4 address."""


class InvalidManufacturerCodeError(InvalidFieldError):
    """A string does not represent a valid OUI manufacturer prefix."""


class MaxDepthExceededError(ProtocolError):
    """A frame's header chain is longer than the walker was allowed.

    Raised by :func:`~netprotocols.decode_frame` rather than by any
    single decoder: every header validates its own length, so a chain
    always terminates, but a crafted frame can nest far enough to waste
    a capture tool's time. The bound turns that from a long walk into an
    immediate, named error.
    """
