"""UDP datagram header (RFC 768)."""

from __future__ import annotations

from dataclasses import dataclass, field
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, hex_str
from netprotocols.layer4._ports import udp_app_class
from netprotocols.registry import Registry
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["UDP"]

#: The 8-byte header and the first two bytes of the payload after it.
_LEAD = Struct("!HHHHH")


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
    #: The first two bytes of the payload as a big-endian 16-bit
    #: integer, its low byte 0 when the payload or the buffer ends after
    #: the first, which :meth:`next_protocol` hands to the class its
    #: port names; ``None`` when :meth:`decode` saw no payload, or for a
    #: header built rather than decoded. Decode context, not a wire
    #: field, so it is neither compared nor hashed. :func:`copy.copy`
    #: and :func:`copy.deepcopy` keep it; :func:`dataclasses.replace`
    #: builds a new header, which has it unset.
    _lead: int | None = field(
        default=None, init=False, repr=False, compare=False
    )

    _struct: ClassVar[Struct] = Struct("!HHHH")

    #: The Length bounds what follows (see :meth:`_payload_extent`).
    _BOUNDS_PAYLOAD: ClassVar[bool] = True

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the 8-byte UDP header at the start of ``data``.

        The first two bytes of the payload, as far as the buffer holds
        them and the Length does not say the payload ends sooner, are
        kept as decode context for :meth:`next_protocol`, a byte that is
        not there read as 0; none are kept for a Length of 8.

        :param data: The buffer, starting at the source port.
        :raises TruncatedHeaderError: if ``data`` is shorter than the
            8-byte header.
        """
        if len(data) > 9:
            src_port, dst_port, length, checksum, lead = _LEAD.unpack_from(data)
            udp = cls(
                src_port=src_port,
                dst_port=dst_port,
                length=length,
                checksum=checksum,
            )
            if length != 8:
                if length == 9:
                    lead &= 0xFF00
                object.__setattr__(udp, "_lead", lead)
            return udp
        src_port, dst_port, length, checksum = cls._unpack_fixed(data)
        udp = cls(
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            checksum=checksum,
        )
        if len(data) > 8 and length != 8:
            object.__setattr__(udp, "_lead", data[8] << 8)
        return udp

    def __bytes__(self) -> bytes:
        return self._struct.pack(
            self.src_port, self.dst_port, self.length, self.checksum
        )

    def _payload_extent(self) -> int | None:
        """Return the payload's length, ``length - 8``.

        ``None`` for a ``length`` of 0, which bounds nothing.

        :raises InvalidFieldError: if ``length`` is 1 to 7, shorter than
            the 8-byte header (``field="length"``).
        """
        if self.length == 0:
            return None
        if self.length < 8:
            raise InvalidFieldError(
                f"UDP length {self.length} is shorter than its 8-byte header",
                protocol=type(self),
                field="length",
                expected=">=8",
                actual=self.length,
            )
        return self.length - 8

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """Return the class for the application protocol, by port.

        The protocol is chosen by well-known port (best-effort; see
        :mod:`netprotocols.layer4._ports`) from ``registry``'s tables, or
        the default ones when it is ``None``; ``None`` when neither port
        is recognized. The class the port names then sees the payload's
        first two bytes, when :meth:`decode` kept them, and answers the
        class that decodes it: :class:`~netprotocols.NTP` answers
        :class:`~netprotocols.NTPControl` for a mode 6 message, and
        :class:`~netprotocols.HSRP` answers :class:`~netprotocols.HSRPv2`
        for an HSRPv2 one and :class:`~netprotocols.HSRPAdvertise` for an
        Advertise.
        """
        protocol = udp_app_class(self.src_port, self.dst_port, registry)
        if protocol is None or self._lead is None:
            return protocol
        return protocol._for_payload(self._lead)

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x1c2a"``."""
        return hex_str(self.checksum, 6)
