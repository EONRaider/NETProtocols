"""UDP datagram header (RFC 768)."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, hex_str
from netprotocols.layer4._ports import udp_app_class
from netprotocols.registry import Registry

__all__ = ["UDP"]


@dataclass(frozen=True, slots=True)
class UDP(Protocol):
    """A UDP header.

    :param src_port: Source port.
    :param dst_port: Destination port.
    :param length: Length in bytes of header plus payload.
    :param checksum: Checksum, carried verbatim (compute/verify via
        :mod:`netprotocols.checksum`).
    """

    src_port: int
    dst_port: int
    length: int
    checksum: int

    _struct: ClassVar[Struct] = Struct("!HHHH")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the 8-byte UDP header at the start of ``data``.

        :param data: The buffer, starting at the source port.
        :raises TruncatedHeaderError: if ``data`` is shorter than the
            8-byte header.
        """
        src_port, dst_port, length, checksum = cls._unpack_fixed(data)
        return cls(
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            checksum=checksum,
        )

    def __bytes__(self) -> bytes:
        return self._struct.pack(
            self.src_port, self.dst_port, self.length, self.checksum
        )

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """Return the class for the application protocol, by port.

        The protocol is chosen by well-known port (best-effort; see
        :mod:`netprotocols.layer4._ports`) from ``registry``'s tables, or
        the default ones when it is ``None``; ``None`` when neither port
        is recognized.
        """
        return udp_app_class(self.src_port, self.dst_port, registry)

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x1c2a"``."""
        return hex_str(self.checksum, 6)
