"""TCP segment header (RFC 793 / 9293)."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["TCP"]


@dataclass(frozen=True, slots=True)
class TCP(Protocol):
    """A TCP header.

    :param src_port: Source port.
    :param dst_port: Destination port.
    :param seq: Sequence number.
    :param ack: Acknowledgement number.
    :param data_offset: Header length in 32-bit words; ``5``-``15``,
        and must equal ``5 + len(options) // 4``.
    :param reserved: Reserved field (3 bits).
    :param flags: Flag bits, NS through FIN (9 bits).
    :param window: Window size.
    :param checksum: Checksum, carried verbatim (this library neither
        computes nor verifies checksums).
    :param urgent_pointer: Urgent pointer.
    :param options: Raw options bytes; length must be a multiple of 4
        consistent with ``data_offset``.
    """

    src_port: int
    dst_port: int
    seq: int
    ack: int
    data_offset: int
    reserved: int
    flags: int
    window: int
    checksum: int
    urgent_pointer: int
    options: bytes = b""

    _struct: ClassVar[Struct] = Struct("!HHIIHHHH")

    #: Flag names by bit position, least-significant first.
    flag_names: ClassVar[tuple[str, ...]] = (
        "FIN",
        "SYN",
        "RST",
        "PSH",
        "ACK",
        "URG",
        "ECE",
        "CWR",
        "NS",
    )

    def __post_init__(self) -> None:
        if not 5 <= self.data_offset <= 15:
            raise InvalidFieldError(
                f"TCP data offset must be within 5-15, got {self.data_offset}"
            )
        if (
            self.data_offset != 5 + len(self.options) // 4
            or len(self.options) % 4
        ):
            raise InvalidFieldError(
                f"TCP data offset {self.data_offset} disagrees with options "
                f"length {len(self.options)} (expected "
                f"{(self.data_offset - 5) * 4} bytes)"
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        (
            src_port,
            dst_port,
            seq,
            ack,
            offset_flags,
            window,
            checksum,
            urgent_pointer,
        ) = cls._unpack_fixed(data)
        data_offset = offset_flags >> 12
        if data_offset < 5:
            raise InvalidFieldError(
                f"TCP data offset must be at least 5, got {data_offset}"
            )
        if data_offset * 4 > len(data):
            raise TruncatedHeaderError(
                f"TCP header declares {data_offset * 4} bytes, buffer holds "
                f"{len(data)}"
            )
        return cls(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            data_offset=data_offset,
            reserved=(offset_flags >> 9) & 0b111,
            flags=offset_flags & 0x1FF,
            window=window,
            checksum=checksum,
            urgent_pointer=urgent_pointer,
            options=bytes(data[cls._struct.size : data_offset * 4]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(
                self.src_port,
                self.dst_port,
                self.seq,
                self.ack,
                (self.data_offset << 12) | (self.reserved << 9) | self.flags,
                self.window,
                self.checksum,
                self.urgent_pointer,
            )
            + self.options
        )

    @property
    def header_len(self) -> int:
        return self.data_offset * 4

    def next_protocol(self) -> type[Protocol] | None:
        """The application protocol carried by this segment, chosen by
        well-known port (best-effort — see
        :mod:`netprotocols.layer4._ports`); ``None`` when neither port is
        recognized. DNS over TCP is length-prefixed, so it chains through
        a :class:`~netprotocols.DNSOverTCP` shim."""
        from netprotocols.layer4._ports import tcp_app_class

        return tcp_app_class(self.src_port, self.dst_port)

    @property
    def flags_str(self) -> str:
        """Space-separated names of the flags set on the segment, e.g.
        ``"SYN ACK"``."""
        return " ".join(
            name
            for shift, name in enumerate(self.flag_names)
            if (self.flags >> shift) & 1
        )

    @property
    def flags_hex_str(self) -> str:
        """The flag bits as a hexadecimal string, e.g. ``"0x012"``."""
        return f"{self.flags:#05x}"

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x2e5b"``."""
        return f"{self.checksum:#06x}"
