"""DNS message header (RFC 1035), the first application-layer protocol.

The 12-byte header is decoded in full; the four message sections
(question, answer, authority, additional) are kept as raw ``bytes``.
This is deliberate: DNS names use *compression* — a name may end in a
pointer to an earlier offset in the message — so re-encoding parsed
records cannot reproduce the original byte stream, and the library's
byte-exact round-trip guarantee is load-bearing. Keeping the sections
raw makes ``bytes(DNS.decode(x)) == x`` hold by construction; the
name-reading accessors below parse on demand and never re-encode.

Full resource-record parsing is a roadmap follow-up.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["DNS"]

#: A compressed name must not follow more than this many pointers; the
#: bound makes a maliciously looping name terminate instead of hanging.
_MAX_NAME_POINTERS = 128


@dataclass(frozen=True, slots=True)
class DNS(Protocol):
    """A DNS message.

    :param transaction_id: Query/response correlation identifier.
    :param flags: The 16-bit flags word (QR, Opcode, AA, TC, RD, RA,
        Z, RCODE); read the parts via the properties below.
    :param qdcount: Number of entries in the question section.
    :param ancount: Number of resource records in the answer section.
    :param nscount: Number of records in the authority section.
    :param arcount: Number of records in the additional section.
    :param sections: The message body after the 12-byte header — the
        four sections, kept raw (names may be compressed).
    """

    transaction_id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    sections: bytes = b""

    _struct: ClassVar[Struct] = Struct("!HHHHHH")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        transaction_id, flags, qdcount, ancount, nscount, arcount = (
            cls._unpack_fixed(data)
        )
        return cls(
            transaction_id=transaction_id,
            flags=flags,
            qdcount=qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount,
            sections=bytes(data[cls._struct.size :]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(
                self.transaction_id,
                self.flags,
                self.qdcount,
                self.ancount,
                self.nscount,
                self.arcount,
            )
            + self.sections
        )

    @property
    def header_len(self) -> int:
        # A DNS message is the whole UDP payload: consume it all so the
        # chain ends here with no stray payload.
        return self._struct.size + len(self.sections)

    # -- flags word (RFC 1035 §4.1.1) --

    @property
    def qr(self) -> int:
        """0 for a query, 1 for a response."""
        return self.flags >> 15

    @property
    def opcode(self) -> int:
        """Query type: 0 standard, 1 inverse, 2 status."""
        return (self.flags >> 11) & 0xF

    @property
    def aa(self) -> int:
        """Authoritative answer bit."""
        return (self.flags >> 10) & 1

    @property
    def tc(self) -> int:
        """Truncation bit."""
        return (self.flags >> 9) & 1

    @property
    def rd(self) -> int:
        """Recursion desired bit."""
        return (self.flags >> 8) & 1

    @property
    def ra(self) -> int:
        """Recursion available bit."""
        return (self.flags >> 7) & 1

    @property
    def rcode(self) -> int:
        """Response code: 0 no error, 3 NXDOMAIN, ..."""
        return self.flags & 0xF

    @property
    def flags_hex_str(self) -> str:
        """The flags word as a hexadecimal string, e.g. ``"0x8180"``."""
        return f"{self.flags:#06x}"

    # -- first question (parsed on demand, never re-encoded) --

    def _read_name(self, offset: int) -> int:
        """Follow the (possibly compressed) name at ``offset`` in the
        whole message; return the offset just past its in-line portion.

        :raises InvalidFieldError: on a malformed or looping name.
        """
        message = bytes(self)
        pointers = 0
        cursor = offset
        while True:
            if cursor >= len(message):
                raise InvalidFieldError("DNS name runs past the message")
            length = message[cursor]
            if length == 0:
                return cursor + 1
            if length & 0xC0 == 0xC0:  # compression pointer
                pointers += 1
                if pointers > _MAX_NAME_POINTERS:
                    raise InvalidFieldError("DNS name compression loops")
                if cursor + 1 >= len(message):
                    raise InvalidFieldError("truncated DNS compression pointer")
                cursor = ((length & 0x3F) << 8) | message[cursor + 1]
            elif length & 0xC0:
                raise InvalidFieldError("reserved DNS label length bits set")
            else:
                cursor += 1 + length
        # unreachable

    def _labels(self, offset: int) -> str:
        """Decode the dotted name beginning at ``offset``.

        :raises InvalidFieldError: on a label that overruns the message,
            a reserved length prefix, or looping compression pointers
            (bounded — never hangs).
        """
        message = bytes(self)
        labels: list[str] = []
        pointers = 0
        cursor = offset
        while True:
            if cursor >= len(message):
                raise InvalidFieldError("DNS name runs past the message")
            length = message[cursor]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:  # compression pointer
                pointers += 1
                if pointers > _MAX_NAME_POINTERS:
                    raise InvalidFieldError("DNS name compression loops")
                if cursor + 1 >= len(message):
                    raise InvalidFieldError("truncated DNS compression pointer")
                cursor = ((length & 0x3F) << 8) | message[cursor + 1]
                continue
            if length & 0xC0:
                raise InvalidFieldError("reserved DNS label length bits set")
            if cursor + 1 + length > len(message):
                raise InvalidFieldError("DNS label runs past the message")
            labels.append(
                message[cursor + 1 : cursor + 1 + length].decode(
                    "ascii", "replace"
                )
            )
            cursor += 1 + length
        return ".".join(labels) if labels else "."

    @property
    def question_name(self) -> str | None:
        """The QNAME of the first question, decompressed, or ``None``
        when the message carries no question.

        :raises InvalidFieldError: if the name is malformed or its
            compression pointers loop (bounded — never hangs).
        """
        if self.qdcount == 0:
            return None
        return self._labels(self._struct.size)

    def _question_fixed(self) -> tuple[int, int] | None:
        if self.qdcount == 0:
            return None
        end = self._read_name(self._struct.size)
        message = bytes(self)
        if end + 4 > len(message):
            raise InvalidFieldError("DNS question truncated")
        qtype = int.from_bytes(message[end : end + 2], "big")
        qclass = int.from_bytes(message[end + 2 : end + 4], "big")
        return qtype, qclass

    @property
    def question_type(self) -> int | None:
        """QTYPE of the first question (1 = A, 28 = AAAA, ...), or
        ``None`` when there is no question."""
        fixed = self._question_fixed()
        return None if fixed is None else fixed[0]

    @property
    def question_class(self) -> int | None:
        """QCLASS of the first question (1 = IN), or ``None`` when there
        is no question."""
        fixed = self._question_fixed()
        return None if fixed is None else fixed[1]
