"""IGMP header — IPv4 multicast group management (RFC 1112/2236/3376).

IGMP rides directly on IPv4 (protocol 2) and never encapsulates another
protocol. The message types do not share one fixed layout — a v3
membership report replaces the group-address field with a record count
— so only the common first four bytes (type, max-response code,
checksum) are modelled as fields; the remainder is kept as raw
``body``. The ``group_address`` accessor reads bytes 4-7 as an IPv4
address for the message types that carry one there, and returns
``None`` otherwise. Parsing the v3 group-record array is a roadmap
follow-up.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv4

__all__ = ["IGMP"]

#: Message types whose bytes 4-7 hold a group address (RFC 2236 §2;
#: RFC 3376 §4.1 for the v3 query). The v3 report (0x22) does not.
_GROUP_ADDRESS_TYPES = frozenset({0x11, 0x12, 0x16, 0x17})


@dataclass(frozen=True, slots=True)
class IGMP(Protocol):
    """An IGMP message.

    :param type: Message type — ``0x11`` query, ``0x12`` v1 report,
        ``0x16`` v2 report, ``0x17`` leave group, ``0x22`` v3 report.
    :param max_resp_code: Maximum response code (queries; 0 in reports).
    :param checksum: Checksum over the whole IGMP message, carried
        verbatim (compute/verify via :mod:`netprotocols.checksum`).
    :param body: The message-type-specific remainder (group address, or
        a v3 record count and group records), kept raw.
    """

    type: int
    max_resp_code: int
    checksum: int
    body: bytes = b""

    _struct: ClassVar[Struct] = Struct("!BBH")

    type_names: ClassVar[dict[int, str]] = {
        0x11: "Membership Query",
        0x12: "IGMPv1 Membership Report",
        0x16: "IGMPv2 Membership Report",
        0x17: "Leave Group",
        0x22: "IGMPv3 Membership Report",
    }

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        type_, max_resp_code, checksum = cls._unpack_fixed(data)
        return cls(
            type=type_,
            max_resp_code=max_resp_code,
            checksum=checksum,
            body=bytes(data[cls._struct.size :]),
        )

    def __bytes__(self) -> bytes:
        return (
            self._struct.pack(self.type, self.max_resp_code, self.checksum)
            + self.body
        )

    @property
    def header_len(self) -> int:
        # IGMP is the whole IP payload: consume it all (terminal).
        return self._struct.size + len(self.body)

    @property
    def type_name(self) -> str:
        """Display name of the message type, e.g. ``"Membership Query"``."""
        return self.type_names.get(self.type, f"unknown ({self.type:#04x})")

    @property
    def group_address(self) -> str | None:
        """The multicast group in dotted-decimal, for the message types
        that carry it in bytes 4-7 (query, v1/v2 report, leave); ``None``
        for the v3 report, which uses that space for a record count."""
        if self.type in _GROUP_ADDRESS_TYPES and len(self.body) >= 4:
            return bytes_to_ipv4(self.body[:4])
        return None

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x0b3a"``."""
        return f"{self.checksum:#06x}"
