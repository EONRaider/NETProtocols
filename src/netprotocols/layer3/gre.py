"""GRE — Generic Routing Encapsulation (RFC 2784, RFC 2890).

GRE tunnels one protocol inside another: it rides IP as protocol 47 and
carries a payload named by a 2-byte ``protocol_type`` that is an
*EtherType* (``0x0800`` IPv4, ``0x86DD`` IPv6, ...), so the chain walk
continues into the encapsulated packet exactly as it would after an
Ethernet header.

The header is four fixed bytes (a flags/version word and the protocol
type) followed by optional fields whose presence the flag bits announce:
a checksum (with its reserved word) when the Checksum-Present bit is set,
a key when the Key-Present bit is set, and a sequence number when the
Sequence-Number-Present bit is set (RFC 2890, in that order). Those
optional bytes are kept raw and surfaced through accessors, so
``bytes(GRE.decode(x)) == x`` holds regardless of which are present.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import TruncatedHeaderError

__all__ = ["GRE"]

_CHECKSUM_PRESENT = 0x8000  # bit 0
_KEY_PRESENT = 0x2000  # bit 2
_SEQUENCE_PRESENT = 0x1000  # bit 3


@dataclass(frozen=True, slots=True)
class GRE(Protocol):
    """A GRE header.

    :param flags: The flags/version word (bit 0 checksum-present, bit 2
        key-present, bit 3 sequence-present, bits 13-15 version); read
        the parts via the properties below.
    :param protocol_type: EtherType of the encapsulated payload, e.g.
        ``0x0800`` for IPv4 (see :class:`~netprotocols.EtherType`).
    :param fields: The optional checksum/reserved, key, and sequence
        fields the flags announce, kept raw and read via the accessors.
    """

    flags: int
    protocol_type: int
    fields: bytes = b""

    _struct: ClassVar[Struct] = Struct("!HH")

    @staticmethod
    def _optional_len(flags: int) -> int:
        """Bytes of optional fields the flags in ``flags`` announce."""
        return (
            (4 if flags & _CHECKSUM_PRESENT else 0)
            + (4 if flags & _KEY_PRESENT else 0)
            + (4 if flags & _SEQUENCE_PRESENT else 0)
        )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        flags, protocol_type = cls._unpack_fixed(data)
        optional_len = cls._optional_len(flags)
        end = cls._struct.size + optional_len
        if len(data) < end:
            raise TruncatedHeaderError(
                f"GRE header declares {end} bytes, buffer holds {len(data)}"
            )
        return cls(
            flags=flags,
            protocol_type=protocol_type,
            fields=bytes(data[cls._struct.size : end]),
        )

    def __bytes__(self) -> bytes:
        return self._struct.pack(self.flags, self.protocol_type) + self.fields

    @property
    def header_len(self) -> int:
        return self._struct.size + len(self.fields)

    def next_protocol(self) -> type[Protocol] | None:
        """The class that decodes the encapsulated payload, chosen by
        ``protocol_type`` (an EtherType); ``None`` when it is not one
        this library decodes."""
        from netprotocols.layer2.ethernet import _ethertype_class

        return _ethertype_class(self.protocol_type)

    @property
    def checksum_present(self) -> int:
        """1 if the checksum (and its reserved word) is present."""
        return int(bool(self.flags & _CHECKSUM_PRESENT))

    @property
    def key_present(self) -> int:
        """1 if the key field is present (RFC 2890)."""
        return int(bool(self.flags & _KEY_PRESENT))

    @property
    def sequence_present(self) -> int:
        """1 if the sequence-number field is present (RFC 2890)."""
        return int(bool(self.flags & _SEQUENCE_PRESENT))

    @property
    def version(self) -> int:
        """The version number (bits 13-15); 0 for RFC 2784 GRE."""
        return self.flags & 0x07

    @property
    def protocol_name(self) -> str:
        """Display name of ``protocol_type``, e.g. ``"IPv4"``; falls back
        to the hexadecimal value for EtherTypes unknown to this library."""
        from netprotocols.layer2.ethernet import _ethertype_name

        return _ethertype_name(self.protocol_type)

    @property
    def checksum(self) -> int | None:
        """The header checksum, carried verbatim, or ``None`` when the
        checksum-present bit is clear (this library neither computes nor
        verifies it)."""
        if not self.checksum_present or len(self.fields) < 2:
            return None
        return int.from_bytes(self.fields[:2], "big")

    @property
    def key(self) -> int | None:
        """The 32-bit key (RFC 2890), or ``None`` when its bit is clear."""
        if not self.key_present:
            return None
        offset = 4 if self.checksum_present else 0
        if len(self.fields) < offset + 4:
            return None
        return int.from_bytes(self.fields[offset : offset + 4], "big")

    @property
    def sequence_number(self) -> int | None:
        """The 32-bit sequence number (RFC 2890), or ``None`` when its
        bit is clear."""
        if not self.sequence_present:
            return None
        offset = (4 if self.checksum_present else 0) + (
            4 if self.key_present else 0
        )
        if len(self.fields) < offset + 4:
            return None
        return int.from_bytes(self.fields[offset : offset + 4], "big")

    @property
    def checksum_hex_str(self) -> str | None:
        """The checksum as a hexadecimal string, e.g. ``"0x1c2a"``, or
        ``None`` when no checksum is present."""
        checksum = self.checksum
        return None if checksum is None else f"{checksum:#06x}"
