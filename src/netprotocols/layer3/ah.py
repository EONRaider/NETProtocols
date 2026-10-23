"""AH — the IPsec Authentication Header (RFC 4302).

AH is IPsec's integrity-only header, IP protocol 51. Unlike ESP it
encrypts nothing, so every field decodes in the clear (RFC 4302 §2):
Next Header, Payload Len, a reserved word, the Security Parameters
Index, the anti-replay Sequence Number, and the Integrity Check Value.
The ICV is a keyed MAC computed with the Security Association's shared
key, which this library will never hold, so it is kept as raw bytes and
never verified.

Payload Len counts the whole header in 4-octet units, minus 2 — so
``(payload_len + 2) * 4`` bytes, of which the first 12 are fixed and the
rest is the ICV field (RFC 4302 §2.2). The ICV's length depends on the
integrity algorithm (16 bytes for HMAC-SHA-256-128, 12 for
HMAC-SHA1-96), which the packet does not name; Payload Len is what
says where AH ends.

Because AH protects without hiding, its payload is worth decoding, and
``next_protocol()`` chains onward through ``next_header`` the way the
IPv6 extension headers do. What may follow AH depends on the IP family
around it, though, so there are two classes:

* :class:`AH`, reached from IPv4, dispatches through the ``ip.proto``
  table — so an IPv4 packet whose AH names ``next_header = 0`` cannot
  conjure an IPv6 Hop-by-Hop layer.
* :class:`AHv6`, reached from IPv6 and its extension headers, dispatches
  through ``ip.proto.v6`` — so a Destination Options header after AH, an
  order RFC 8200 §4.1 permits, keeps decoding. It also enforces the
  IPv6 rule that the header is a multiple of 8 octets.

``AHv6`` subclasses ``AH``, so ``isinstance(layer, AH)``,
``packet[AH]`` and ``case AH(...)`` find either. The family each one is
used in is set by the registry, not by the bytes: the two are
registered against protocol 51 in ``ip.proto`` and ``ip.proto.v6``
respectively.

``bytes(AH.decode(x)) == x`` holds by construction: the fixed fields
are packed back and the ICV is carried verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, hex_str
from netprotocols._enums import IPProtocol
from netprotocols.layer3.ip import (
    _ip_protocol_class,
    _ip_protocol_enum,
    _ip_protocol_name,
)
from netprotocols.registry import Registry
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["AH", "AHv6"]


@dataclass(frozen=True, slots=True)
class AH(Protocol):
    """An Authentication Header (RFC 4302 §2) in an IPv4 chain; see
    :class:`AHv6` for IPv6.

    :param next_header: Protocol number of what AH protects — the
        upper-layer protocol in transport mode, ``4`` or ``41`` (a whole
        IP packet) in tunnel mode (see :class:`~netprotocols.IPProtocol`).
    :param payload_len: Header length in 4-octet units, minus 2: the
        header is ``(payload_len + 2) * 4`` bytes. At least ``1`` (the
        12 fixed bytes and an empty ICV, as with NULL authentication),
        and it must agree with ``len(icv)``.
    :param reserved: Reserved 16 bits, zero on send (RFC 4302 §2.3) but
        carried verbatim.
    :param spi: Security Parameters Index (32 bits), which together with
        the destination identifies the SA. ``0`` is reserved for local
        use and ``1``-``255`` by IANA (RFC 4302 §2.4); both are carried
        verbatim, not rejected.
    :param sequence_number: Anti-replay counter (32 bits), the low half
        when the SA uses Extended Sequence Numbers — the high half is
        never transmitted (RFC 4302 §2.5.1).
    :param icv: The Integrity Check Value field, exactly
        ``(payload_len + 2) * 4 - 12`` bytes, kept raw and never
        verified. It includes any padding the algorithm's ICV needed to
        keep the header aligned (RFC 4302 §2.6) — 4 bytes for
        HMAC-SHA-256-128 under IPv6 — which the packet does not mark
        apart from the ICV itself.
    """

    next_header: int
    payload_len: int
    reserved: int
    spi: int
    sequence_number: int
    icv: bytes

    _struct: ClassVar[Struct] = Struct("!BBHII")

    #: Whether ``next_header`` dispatches in an IPv6 chain.
    _ipv6: ClassVar[bool] = False

    #: The header's required alignment in bytes (RFC 4302 §2.2). Any
    #: ``payload_len`` gives a multiple of 4, which is all IPv4 needs.
    _alignment: ClassVar[int] = 4

    def __post_init__(self) -> None:
        self._check_payload_len(self.payload_len, offset=None)
        expected = (self.payload_len + 2) * 4 - self._struct.size
        if len(self.icv) != expected:
            raise InvalidFieldError(
                f"{type(self).__name__} payload_len {self.payload_len} "
                f"disagrees with ICV length {len(self.icv)} (expected "
                f"{expected} bytes)",
                protocol=type(self),
                field="payload_len",
                expected=expected,
                actual=len(self.icv),
            )

    @classmethod
    def _check_payload_len(
        cls, payload_len: int, *, offset: int | None
    ) -> None:
        """Reject a Payload Len that cannot describe this header:
        shorter than its own fixed part, or (IPv6) misaligned.

        :raises InvalidFieldError: ``offset`` is passed through — ``0``
            from :meth:`decode`, ``None`` from construction.
        """
        if payload_len < 1:
            raise InvalidFieldError(
                f"{cls.__name__} payload_len must be at least 1 (a "
                f"{cls._struct.size}-byte header), got {payload_len}",
                protocol=cls,
                offset=offset,
                field="payload_len",
                expected=">=1",
                actual=payload_len,
            )
        header_len = (payload_len + 2) * 4
        if header_len % cls._alignment:
            raise InvalidFieldError(
                f"{cls.__name__} payload_len {payload_len} declares a "
                f"{header_len}-byte header, not a multiple of "
                f"{cls._alignment} octets as RFC 4302 §2.2 requires here",
                protocol=cls,
                offset=offset,
                field="payload_len",
                expected=f"a multiple of {cls._alignment} bytes",
                actual=header_len,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        next_header, payload_len, reserved, spi, sequence_number = (
            cls._unpack_fixed(data)
        )
        cls._check_payload_len(payload_len, offset=0)
        declared = (payload_len + 2) * 4
        if declared > len(data):
            raise TruncatedHeaderError(
                f"{cls.__name__} declares {declared} bytes, buffer holds "
                f"{len(data)}",
                protocol=cls,
                offset=0,
                field="payload_len",
                expected=declared,
                actual=len(data),
            )
        return cls(
            next_header=next_header,
            payload_len=payload_len,
            reserved=reserved,
            spi=spi,
            sequence_number=sequence_number,
            icv=bytes(data[cls._struct.size : declared]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(
                self.next_header,
                self.payload_len,
                self.reserved,
                self.spi,
                self.sequence_number,
            )
            + self.icv
        )

    @property
    def header_len(self) -> int:
        return (self.payload_len + 2) * 4

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """The class that decodes what AH protects, chosen by
        ``next_header`` from the dispatch table of this header's IP
        family — ``ip.proto`` for :class:`AH`, ``ip.proto.v6`` for
        :class:`AHv6` — so an AH-wrapped TCP segment keeps decoding into
        :class:`~netprotocols.TCP`, and an IPv6 extension header can
        follow AH only inside an IPv6 chain."""
        return _ip_protocol_class(
            self.next_header, ipv6=self._ipv6, registry=registry
        )

    @property
    def next_header_name(self) -> str:
        """Display name of what follows, e.g. ``"TCP"``."""
        return _ip_protocol_name(self.next_header)

    @property
    def next_header_enum(self) -> IPProtocol | None:
        """What follows this header as an
        :class:`~netprotocols.IPProtocol` (see
        :attr:`~netprotocols.IPv4.protocol_enum`); ``None`` for a value
        this library does not enumerate."""
        return _ip_protocol_enum(self.next_header)

    @property
    def spi_hex_str(self) -> str:
        """The SPI as a hexadecimal string, e.g. ``"0x20000001"`` — the
        form IPsec tooling (``ip xfrm``, tcpdump) prints it in."""
        return hex_str(self.spi, 10)


@dataclass(frozen=True, slots=True)
class AHv6(AH):
    """An Authentication Header in an IPv6 chain (RFC 4302 §2, §3.1.1).

    The same wire format as :class:`AH`, which it subclasses, with the
    two differences IPv6 makes: ``next_header`` dispatches through the
    ``ip.proto.v6`` table, so a Destination Options header may follow,
    and the header must be a multiple of 8 octets — an even
    ``payload_len`` — or construction and :meth:`decode` raise
    :class:`~netprotocols.InvalidFieldError`. HMAC-SHA-256-128's
    16-byte ICV therefore travels with 4 bytes of padding here
    (``payload_len`` 6), all of it in :attr:`icv`.
    """

    _ipv6: ClassVar[bool] = True
    _alignment: ClassVar[int] = 8
