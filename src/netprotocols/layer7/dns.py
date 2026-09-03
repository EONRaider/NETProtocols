"""DNS message header (RFC 1035), the first application-layer protocol.

The 12-byte header is decoded in full; the four message sections
(question, answer, authority, additional) are kept as raw ``bytes``.
This is deliberate: DNS names use *compression* — a name may end in a
pointer to an earlier offset in the message — so re-encoding parsed
records cannot reproduce the original byte stream, and the library's
byte-exact round-trip guarantee is load-bearing. Keeping the sections
raw makes ``bytes(DNS.decode(x)) == x`` hold by construction; the
question and resource-record accessors below parse on demand and never
re-encode.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv4, bytes_to_ipv6
from netprotocols.registry import Registry
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["DNS", "DNSOverTCP", "DNSResourceRecord"]

#: A compressed name must not follow more than this many pointers; the
#: bound makes a maliciously looping name terminate instead of hanging.
_MAX_NAME_POINTERS = 128

#: Length of the fixed header. The parser works from the ``sections``
#: bytes that follow it, so every internal offset below is relative to
#: the start of ``sections``; only a compression pointer, which counts
#: from the start of the *message*, needs translating (by subtracting
#: this) — a pointer into the header lands below zero and is rejected.
_HEADER_LEN = 12

#: How many parsed messages the record cache keeps. The cache is keyed
#: by the raw section bytes and the counts, so it is shared by equal
#: messages and bounded: reading all three sections of one message
#: parses it once instead of three times, without storing anything on
#: the (frozen) instance.
_RECORD_CACHE_SIZE = 128

#: DNS resource-record types this library names (RFC 1035 §3.2.2 and
#: later assignments); unknown types keep their numeric value.
_RR_TYPE_NAMES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    65: "HTTPS",
    257: "CAA",
}


@dataclass(frozen=True, slots=True)
class DNSResourceRecord:
    """One DNS resource record (RFC 1035 §4.1.3).

    :param name: The owner name, decompressed to dotted form.
    :param rtype: Record type — ``1`` A, ``28`` AAAA, ``5`` CNAME, ...
        (see :attr:`rtype_name`).
    :param rclass: Record class (``1`` = IN). For an OPT record (type
        ``41``) this field carries the requestor's UDP payload size.
    :param ttl: Time to live in seconds.
    :param rdata: The record's RDATA, kept raw.
    :param rdata_text: A decoded, human-readable view of ``rdata`` — an
        IPv4/IPv6 address for A/AAAA, the target name for CNAME/NS/PTR,
        ``"preference exchange"`` for MX, the concatenated strings for
        TXT, the field tuple for SOA; the hexadecimal RDATA for types
        this library does not special-case.
    """

    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    rdata_text: str

    @property
    def rtype_name(self) -> str:
        """Display name of the record type, e.g. ``"AAAA"``; falls back
        to the numeric type for records unknown to this library."""
        return _RR_TYPE_NAMES.get(self.rtype, str(self.rtype))


def _read_name(sections: bytes, at: int) -> int:
    """The offset just past the name's in-line bytes at ``at``.

    A compression pointer ends the in-line name (this does not follow
    it — :func:`_labels` does), so the result advances the cursor to the
    field after the name.

    :raises InvalidFieldError: on a malformed name.
    """
    cursor = at
    while True:
        if not 0 <= cursor < len(sections):
            raise InvalidFieldError(
                "DNS name runs past the message",
                protocol=DNS,
                field="sections",
                offset=cursor,
            )
        length = sections[cursor]
        if length == 0:
            return cursor + 1
        if length & 0xC0 == 0xC0:  # a pointer ends the in-line name
            if cursor + 1 >= len(sections):
                raise InvalidFieldError(
                    "truncated DNS compression pointer",
                    protocol=DNS,
                    field="sections",
                    offset=cursor,
                )
            return cursor + 2
        if length & 0xC0:
            raise InvalidFieldError(
                "reserved DNS label length bits set",
                protocol=DNS,
                field="sections",
                offset=cursor,
            )
        cursor += 1 + length


def _labels(sections: bytes, at: int) -> str:
    """Decode the dotted name beginning at ``at``.

    :raises InvalidFieldError: on a label that overruns the message, a
        reserved length prefix, a pointer into the header, or looping
        compression pointers (bounded — never hangs).
    """
    labels: list[str] = []
    pointers = 0
    cursor = at
    while True:
        if not 0 <= cursor < len(sections):
            raise InvalidFieldError(
                "DNS name runs past the message",
                protocol=DNS,
                field="sections",
                offset=cursor,
            )
        length = sections[cursor]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointers += 1
            if pointers > _MAX_NAME_POINTERS:
                raise InvalidFieldError(
                    "DNS name compression loops",
                    protocol=DNS,
                    field="sections",
                    offset=cursor,
                    expected=f"<={_MAX_NAME_POINTERS} pointers",
                    actual=pointers,
                )
            if cursor + 1 >= len(sections):
                raise InvalidFieldError(
                    "truncated DNS compression pointer",
                    protocol=DNS,
                    field="sections",
                    offset=cursor,
                )
            target = ((length & 0x3F) << 8) | sections[cursor + 1]
            cursor = target - _HEADER_LEN  # pointers count from the message
            continue
        if length & 0xC0:
            raise InvalidFieldError(
                "reserved DNS label length bits set",
                protocol=DNS,
                field="sections",
                offset=cursor,
            )
        if cursor + 1 + length > len(sections):
            raise InvalidFieldError(
                "DNS label runs past the message",
                protocol=DNS,
                field="sections",
                offset=cursor,
            )
        labels.append(
            sections[cursor + 1 : cursor + 1 + length].decode(
                "ascii", "replace"
            )
        )
        cursor += 1 + length
    return ".".join(labels) if labels else "."


def _decode_txt(rdata: bytes) -> str:
    """Concatenate the character-strings of a TXT record (§3.3.14)."""
    parts: list[str] = []
    cursor = 0
    while cursor < len(rdata):
        length = rdata[cursor]
        cursor += 1
        if cursor + length > len(rdata):
            raise InvalidFieldError(
                "DNS TXT character-string overruns",
                protocol=DNS,
                field="rdata",
                offset=cursor,
            )
        parts.append(rdata[cursor : cursor + length].decode("ascii", "replace"))
        cursor += length
    return "".join(parts)


def _decode_rdata(sections: bytes, rtype: int, at: int, rdlength: int) -> str:
    """A human-readable rendering of the RDATA at ``at``; names follow
    compression against the whole message."""
    rdata = sections[at : at + rdlength]
    if rtype == 1 and rdlength == 4:  # A
        return bytes_to_ipv4(rdata)
    if rtype == 28 and rdlength == 16:  # AAAA
        return bytes_to_ipv6(rdata)
    if rtype in (2, 5, 12):  # NS, CNAME, PTR — a single name
        return _labels(sections, at)
    if rtype == 15 and rdlength >= 2:  # MX — preference + exchange
        preference = int.from_bytes(rdata[:2], "big")
        return f"{preference} {_labels(sections, at + 2)}"
    if rtype == 16:  # TXT
        return _decode_txt(rdata)
    if rtype == 6:  # SOA — mname, rname, then five 32-bit fields
        mname = _labels(sections, at)
        rname_at = _read_name(sections, at)
        rname = _labels(sections, rname_at)
        fixed = _read_name(sections, rname_at)
        if fixed + 20 > len(sections):
            raise InvalidFieldError(
                "DNS SOA record truncated",
                protocol=DNS,
                field="sections",
                offset=fixed,
            )
        serial, refresh, retry, expire, minimum = (
            int.from_bytes(sections[fixed + i : fixed + i + 4], "big")
            for i in range(0, 20, 4)
        )
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    return rdata.hex()


def _parse_rr(sections: bytes, at: int) -> tuple[DNSResourceRecord, int]:
    """Parse the resource record at ``at``; return it and the offset of
    the next record."""
    name = _labels(sections, at)
    cursor = _read_name(sections, at)
    if cursor + 10 > len(sections):
        raise InvalidFieldError(
            "DNS resource record truncated",
            protocol=DNS,
            field="sections",
            offset=cursor,
        )
    rtype = int.from_bytes(sections[cursor : cursor + 2], "big")
    rclass = int.from_bytes(sections[cursor + 2 : cursor + 4], "big")
    ttl = int.from_bytes(sections[cursor + 4 : cursor + 8], "big")
    rdlength = int.from_bytes(sections[cursor + 8 : cursor + 10], "big")
    cursor += 10
    if cursor + rdlength > len(sections):
        raise InvalidFieldError(
            "DNS RDATA runs past the message",
            protocol=DNS,
            field="sections",
            offset=cursor,
            expected=rdlength,
            actual=len(sections) - cursor,
        )
    record = DNSResourceRecord(
        name=name,
        rtype=rtype,
        rclass=rclass,
        ttl=ttl,
        rdata=sections[cursor : cursor + rdlength],
        rdata_text=_decode_rdata(sections, rtype, cursor, rdlength),
    )
    return record, cursor + rdlength


def _first_record(sections: bytes, qdcount: int) -> int:
    """Offset of the first resource record: past the questions.

    :raises InvalidFieldError: if the question section is truncated.
    """
    cursor = 0
    for _ in range(qdcount):
        cursor = _read_name(sections, cursor)
        cursor += 4  # QTYPE + QCLASS
        if cursor > len(sections):
            raise InvalidFieldError(
                "DNS question section truncated",
                protocol=DNS,
                field="sections",
                offset=cursor,
            )
    return cursor


@lru_cache(maxsize=_RECORD_CACHE_SIZE)
def _parse_records(
    sections: bytes, qdcount: int, ancount: int, nscount: int, arcount: int
) -> tuple[
    tuple[DNSResourceRecord, ...],
    tuple[DNSResourceRecord, ...],
    tuple[DNSResourceRecord, ...],
]:
    """Parse the answer, authority and additional sections in one pass.

    Cached on the (immutable) section bytes and counts, so reading all
    three accessors of a message parses it once. Records are frozen
    dataclasses, so sharing them between callers is safe.

    :raises InvalidFieldError: if a record, its RDATA, or a name runs
        past the message (bounded — never hangs or over-reads).
    """
    cursor = _first_record(sections, qdcount)
    parsed: list[tuple[DNSResourceRecord, ...]] = []
    for count in (ancount, nscount, arcount):
        records: list[DNSResourceRecord] = []
        for _ in range(count):
            record, cursor = _parse_rr(sections, cursor)
            records.append(record)
        parsed.append(tuple(records))
    return parsed[0], parsed[1], parsed[2]


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

    @property
    def question_name(self) -> str | None:
        """The QNAME of the first question, decompressed, or ``None``
        when the message carries no question.

        :raises InvalidFieldError: if the name is malformed or its
            compression pointers loop (bounded — never hangs).
        """
        if self.qdcount == 0:
            return None
        return _labels(self.sections, 0)

    def _question_fixed(self) -> tuple[int, int] | None:
        if self.qdcount == 0:
            return None
        end = _read_name(self.sections, 0)
        if end + 4 > len(self.sections):
            raise InvalidFieldError(
                "DNS question truncated",
                protocol=type(self),
                field="sections",
                offset=end,
            )
        qtype = int.from_bytes(self.sections[end : end + 2], "big")
        qclass = int.from_bytes(self.sections[end + 2 : end + 4], "big")
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

    # -- resource records (parsed on demand, never re-encoded) --

    def _resource_records(
        self,
    ) -> tuple[
        tuple[DNSResourceRecord, ...],
        tuple[DNSResourceRecord, ...],
        tuple[DNSResourceRecord, ...],
    ]:
        """The three record sections, parsed once (see
        :func:`_parse_records`) and shared by the accessors below."""
        return _parse_records(
            self.sections,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @property
    def answers(self) -> tuple[DNSResourceRecord, ...]:
        """The answer-section resource records, parsed on demand."""
        return self._resource_records()[0]

    @property
    def authorities(self) -> tuple[DNSResourceRecord, ...]:
        """The authority-section resource records, parsed on demand."""
        return self._resource_records()[1]

    @property
    def additionals(self) -> tuple[DNSResourceRecord, ...]:
        """The additional-section resource records, parsed on demand."""
        return self._resource_records()[2]


@dataclass(frozen=True, slots=True)
class DNSOverTCP(Protocol):
    """The two-octet length prefix that frames a DNS message over TCP
    (RFC 1035 §4.2.2).

    Over TCP a DNS message is preceded by its length as a 16-bit field.
    This models that prefix as a 2-byte shim between :class:`~netprotocols.TCP`
    and the :class:`DNS` message — like a VLAN tag between Ethernet and
    its payload — so the chain walk decodes ``[..., TCP, DNSOverTCP,
    DNS]`` and the DNS message parses at its true offset. It is reached
    only from :meth:`~netprotocols.TCP.next_protocol` on a DNS port.

    :param message_length: Length in bytes of the DNS message that
        follows this prefix.
    """

    message_length: int

    _struct: ClassVar[Struct] = Struct("!H")

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        (message_length,) = cls._unpack_fixed(data)
        return cls(message_length=message_length)

    def __bytes__(self) -> bytes:
        return self._struct.pack(self.message_length)

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """The DNS message this length prefix frames.

        A length shim has no wire field to dispatch on — it always
        frames a DNS message — so ``registry`` is accepted for
        signature compatibility and has nothing to select.
        """
        return DNS
