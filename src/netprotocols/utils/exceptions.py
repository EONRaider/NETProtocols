"""Exception hierarchy for netprotocols.

Every exception raised by this library derives from :class:`ProtocolError`,
so callers can guard an entire decode pipeline with a single handler.
"""

from __future__ import annotations

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
    """Base class for all errors raised by netprotocols.

    Strictness is the library's security story — it raises where scapy
    silently fills in defaults — so what a raise *carries* matters as
    much as the fact that it raised. Every raise site in ``src/``
    attaches structured context alongside the message, so a fuzzing
    harness, a conformance suite, or a protocol-validation tool can act
    on *where* and *what* failed without regexing the prose.

    Every field below is optional and defaults to ``None``: not every
    error has a buffer position (a :class:`~netprotocols.Packet` built
    from the wrong type has no bytes to be positioned in) or a single
    field (a length/count mismatch is about the relationship between
    two fields, not one).

    :ivar protocol: The class whose parsing raised, e.g. ``IPv4``.
    :ivar field: Name of the attribute most directly at fault, e.g.
        ``"ihl"``. When it names a raw ``bytes`` attribute parsed on
        demand (``"options"``, ``"body"``, ``"sections"``), ``offset``
        is relative to *that* attribute rather than to a ``decode()``
        call — see ``offset`` below.
    :ivar offset: Byte offset of the problem. Relative to the ``data``
        buffer passed to ``decode()`` when ``field`` is ``None`` or
        names a fixed-header value; relative to the attribute ``field``
        names when it names one (see above). ``None`` when there is no
        buffer to be positioned in — most notably a validation error
        raised from ``__post_init__``, which sees only field *values*,
        never the bytes they came from.
    :ivar frame_offset: ``offset`` rebased to the whole captured frame.
        ``None`` unless the error passed through
        :func:`~netprotocols.decode_frame`, which is the only code
        holding the cursor needed to do the rebasing — a bare
        ``SomeClass.decode()`` call has no frame to rebase against, so
        this stays ``None`` there even when ``offset`` is set.
    :ivar expected: What was expected, when stating that adds
        information beyond the message text.
    :ivar actual: What was found instead.
    """

    def __init__(
        self,
        message: str,
        *,
        protocol: type[object] | None = None,
        offset: int | None = None,
        field: str | None = None,
        expected: object = None,
        actual: object = None,
        frame_offset: int | None = None,
    ) -> None:
        super().__init__(message)
        self.protocol = protocol
        self.offset = offset
        self.field = field
        self.expected = expected
        self.actual = actual
        self.frame_offset = frame_offset


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
