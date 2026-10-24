"""ESP — IPsec Encapsulating Security Payload (RFC 4303).

ESP is IPsec's encryption container, IP protocol 50, reached from IPv4
and IPv6 alike. Only its first eight bytes are cleartext framing: the
Security Parameters Index naming the Security Association (SA) the
packet belongs to, and the anti-replay Sequence Number (RFC 4303 §2.1,
§2.2). Everything after them — the payload, any cipher-specific IV,
the padding, the Pad Length and Next Header trailer, and the Integrity
Check Value — is protected by the SA's keys and algorithms, none of
which is visible from the packet, so the remainder is kept as one
opaque ``ciphertext`` field.

This library has no cryptography and will not gain any, so it does not
decrypt, verify, or even locate the trailer: where the ICV starts
depends on the SA's algorithms, and the Pad Length and Next Header
bytes are encrypted along with the payload unless the SA uses a
confidentiality-free transform (e.g. NULL, RFC 2410; AES-GMAC, RFC 4543).
Without the SA there is no way to tell where the ciphertext ends and
the trailer begins, so the chain ends here —
:meth:`ESP.next_protocol` returns ``None`` by design.

``bytes(ESP.decode(x)) == x`` holds by construction: the two fixed
fields are packed back and ``ciphertext`` is carried verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, hex_str
from netprotocols.registry import Registry

__all__ = ["ESP"]


@dataclass(frozen=True, slots=True)
class ESP(Protocol):
    """An ESP packet (RFC 4303 §2): the cleartext SPI and sequence
    number, then everything else as opaque bytes.

    ESP is a **dead end for the decode chain**, and that is correct
    rather than a gap: :meth:`next_protocol` always returns ``None``.
    The payload's protocol is named by the Next Header byte of the ESP
    trailer, which sits inside the protected region: encrypted unless
    the SA uses a confidentiality-free transform (e.g. NULL, RFC 2410;
    AES-GMAC, RFC 4543), and just before an ICV whose length only the
    SA's algorithms determine. Nothing in the packet says which cipher
    or algorithm the SA uses, so the decoder cannot tell whether that
    byte is readable, or which byte it is, and never reads the trailer.
    A frame walk therefore stops at ``ESP`` with the whole protected
    payload in :attr:`ciphertext`.

    :param spi: Security Parameters Index (32 bits), which together with
        the destination identifies the SA. ``0`` is reserved for local
        use and ``1``-``255`` by IANA (RFC 4303 §2.1); both are carried
        verbatim, not rejected.
    :param sequence_number: Anti-replay counter (32 bits), the low half
        when the SA uses Extended Sequence Numbers — the high half is
        never transmitted (RFC 4303 §2.2.1).
    :param ciphertext: Everything after the first 8 bytes, kept raw:
        payload data (with any IV), padding, Pad Length, Next Header and
        ICV, none of whose boundaries the packet reveals. It runs to the
        end of the buffer handed to :meth:`decode`, which a frame walk
        makes the rest of the frame — so link-layer padding after a
        datagram shorter than the link's minimum lands here too.
    """

    spi: int
    sequence_number: int
    ciphertext: bytes = b""

    _struct: ClassVar[Struct] = Struct("!II")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        spi, sequence_number = cls._unpack_fixed(data)
        return cls(
            spi=spi,
            sequence_number=sequence_number,
            ciphertext=bytes(data[cls._struct.size :]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(self.spi, self.sequence_number) + self.ciphertext
        )

    @property
    def header_len(self) -> int:
        # The protected remainder is part of this layer, as an ICMP
        # message's body is: the chain ends here with nothing left over.
        return self._struct.size + len(self.ciphertext)

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """Always ``None``: ESP ends the decode chain by design.

        The protocol of the protected payload is the trailer's Next
        Header field, which is encrypted unless the SA uses a
        confidentiality-free transform (e.g. NULL, AES-GMAC) and sits at an
        offset that only the SA's algorithms determine (RFC
        4303 §2.4-2.8). Without the SA there is nothing to dispatch on,
        so stopping here is the correct answer, not an unimplemented
        one. ``registry`` is accepted for the uniform signature and
        never consulted.
        """
        return None

    @property
    def spi_hex_str(self) -> str:
        """The SPI as a hexadecimal string, e.g. ``"0x10000001"`` — the
        form IPsec tooling (``ip xfrm``, tcpdump) prints it in."""
        return hex_str(self.spi, 10)
