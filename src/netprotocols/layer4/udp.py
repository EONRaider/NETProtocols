"""UDP datagram header (RFC 768)."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol

__all__ = ["UDP"]


@dataclass(frozen=True, slots=True)
class UDP(Protocol):
    """A UDP header.

    :param src_port: Source port.
    :param dst_port: Destination port.
    :param length: Length in bytes of header plus payload.
    :param checksum: Checksum, carried verbatim (this library neither
        computes nor verifies checksums).
    """

    src_port: int
    dst_port: int
    length: int
    checksum: int

    _struct: ClassVar[Struct] = Struct("!HHHH")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
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

    def next_protocol(self) -> type[Protocol] | None:
        """The application protocol carried by this datagram, chosen by
        well-known port (best-effort — see
        :mod:`netprotocols.layer4._ports`); ``None`` when neither port
        is recognized."""
        from netprotocols.layer4._ports import udp_app_class

        return udp_app_class(self.src_port, self.dst_port)

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x1c2a"``."""
        return f"{self.checksum:#06x}"
