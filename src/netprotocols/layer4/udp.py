"""UDP datagram header (RFC 768)."""

from __future__ import annotations

from dataclasses import dataclass, field
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, hex_str, slot_setters
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

        The first two bytes of the payload are kept as decode context
        for :meth:`next_protocol`. None are kept when ``data`` ends at
        the 8-byte header or the Length is 8. The second byte is read as
        0 when the Length is 9 or ``data`` ends after the first payload
        byte. A Length of 0, which bounds nothing, or of 1 to 7, shorter
        than the header, takes both bytes from ``data``; for a Length of
        1 to 7, :func:`~netprotocols.decode_frame` refuses the datagram
        before it dispatches the payload (see :meth:`_payload_extent`).

        :param data: The buffer, starting at the source port.
        :raises TruncatedHeaderError: if ``data`` is shorter than the
            8-byte header.
        """
        if len(data) > 9:
            src_port, dst_port, length, checksum, lead = _LEAD.unpack_from(data)
            if length == 8:
                lead = None
            elif length == 9:
                lead &= 0xFF00
        else:
            src_port, dst_port, length, checksum = cls._unpack_fixed(data)
            lead = data[8] << 8 if len(data) > 8 and length != 8 else None
        if cls is not UDP:
            # A subclass may add fields or checks of its own, so it is
            # built through its constructor.
            udp = cls(
                src_port=src_port,
                dst_port=dst_port,
                length=length,
                checksum=checksum,
            )
            if lead is not None:
                object.__setattr__(udp, "_lead", lead)
            return udp
        # UDP has no __post_init__, and every field is unpacked from its
        # own wire width, so the instance is built directly, without
        # __init__ (see "Decode-path construction" in _base.py).
        (
            set_src_port,
            set_dst_port,
            set_length,
            set_checksum,
            set_lead,
        ) = _UDP_SETTERS
        udp = object.__new__(cls)
        set_src_port(udp, src_port)
        set_dst_port(udp, dst_port)
        set_length(udp, length)
        set_checksum(udp, checksum)
        set_lead(udp, lead)
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


#: The slot setters :meth:`UDP.decode` builds its instance with.
_UDP_SETTERS = slot_setters(
    UDP,
    "src_port",
    "dst_port",
    "length",
    "checksum",
    "_lead",
)
