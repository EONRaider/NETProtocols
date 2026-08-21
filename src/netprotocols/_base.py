"""The Protocol base class and the decode contract shared by all headers.

Decode contract
---------------
``decode(data)`` receives the *entire remaining buffer* — everything from
the start of this protocol's header to the end of the captured frame —
and must:

1. Parse the fixed portion with the class-level ``struct.Struct``,
   raising :class:`TruncatedHeaderError` if the buffer is too short.
2. For variable-length headers (IPv4, TCP), validate the declared
   length (raising :class:`InvalidFieldError` for nonsense values and
   :class:`TruncatedHeaderError` when the declared length exceeds the
   buffer) and materialize the options as ``bytes``.
3. Tolerate trailing bytes: whatever follows the header is the next
   layer's problem, reachable via ``instance.header_len``.

``memoryview`` input is accepted and used as a decode-time transient
only; no view is ever stored on an instance.
"""

from __future__ import annotations

import socket
from abc import ABC, abstractmethod
from struct import Struct
from struct import error as StructError
from typing import Any, ClassVar, Self

from netprotocols.utils.exceptions import TruncatedHeaderError

__all__ = [
    "Protocol",
    "bytes_to_ipv4",
    "bytes_to_ipv6",
    "bytes_to_mac",
    "ipv4_to_bytes",
    "ipv6_to_bytes",
    "mac_to_bytes",
]


def mac_to_bytes(mac: str) -> bytes:
    """Pack ``"00:c0:ca:a8:19:74"`` (``:`` or ``-`` separated) into 6 bytes."""
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def bytes_to_mac(data: bytes) -> str:
    """Render 6 raw bytes as a colon-separated lowercase MAC address."""
    return ":".join(format(octet, "02x") for octet in data)


def ipv4_to_bytes(addr: str) -> bytes:
    """Pack a dotted-decimal IPv4 address string into 4 bytes."""
    return socket.inet_pton(socket.AF_INET, addr)


def bytes_to_ipv4(data: bytes) -> str:
    """Render 4 raw bytes as a dotted-decimal IPv4 address string."""
    return socket.inet_ntop(socket.AF_INET, data)


def ipv6_to_bytes(addr: str) -> bytes:
    """Pack an IPv6 address string into 16 bytes."""
    return socket.inet_pton(socket.AF_INET6, addr)


def bytes_to_ipv6(data: bytes) -> str:
    """Render 16 raw bytes as an RFC 5952 IPv6 address string."""
    return socket.inet_ntop(socket.AF_INET6, data)


class Protocol(ABC):
    """Abstract base for all protocol headers.

    Concrete protocols are frozen, slotted dataclasses whose fields
    mirror the on-wire header. Each class declares the layout of its
    fixed portion as a ``struct.Struct`` (compiled once, at class
    definition time) and implements the decode contract described in
    this module's docstring.
    """

    __slots__ = ()

    #: Layout of the fixed portion of the header, network byte order.
    _struct: ClassVar[Struct]

    @classmethod
    def _unpack_fixed(cls, data: bytes | memoryview) -> tuple[Any, ...]:
        """Unpack the fixed portion of the header from ``data``.

        :raises TruncatedHeaderError: if ``data`` is shorter than the
            fixed portion.
        """
        try:
            return cls._struct.unpack_from(data)
        except StructError as e:
            raise TruncatedHeaderError(
                f"{cls.__name__} header needs {cls._struct.size} bytes, "
                f"buffer holds {len(data)}"
            ) from e

    @classmethod
    @abstractmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the header at the start of ``data`` (see decode contract)."""

    @abstractmethod
    def __bytes__(self) -> bytes:
        """Serialize this header back to its exact on-wire form."""

    @property
    def header_len(self) -> int:
        """Length of this header in bytes.

        Fixed-size protocols inherit this default; variable-length
        headers (IPv4, TCP) override it to account for options.
        """
        return self._struct.size

    def next_protocol(self) -> type[Protocol] | None:
        """The class that decodes this header's payload, if known.

        ``None`` means the chain ends here: either the protocol never
        encapsulates another (ARP, UDP), or the encapsulated protocol
        is not implemented by this library.
        """
        return None
