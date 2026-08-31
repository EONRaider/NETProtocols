"""IGMP header — IPv4 multicast group management (RFC 1112/2236/3376).

IGMP rides directly on IPv4 (protocol 2) and never encapsulates another
protocol. The message types do not share one fixed layout — a v3
membership report replaces the group-address field with an array of
group records — so only the common first four bytes (type,
max-response code, checksum) are modelled as fields; the remainder is
kept as raw ``body``. The ``group_address`` accessor reads bytes 4-7 as
an IPv4 address for the message types that carry one there; for the v3
report (type ``0x22``) the ``group_records`` accessor parses the record
array. Both read the raw body on demand and never re-encode, so
``bytes(IGMP.decode(x)) == x`` holds by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv4
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["IGMP", "IGMPv3GroupRecord"]

#: Message types whose bytes 4-7 hold a group address (RFC 2236 §2;
#: RFC 3376 §4.1 for the v3 query). The v3 report (0x22) does not.
_GROUP_ADDRESS_TYPES = frozenset({0x11, 0x12, 0x16, 0x17})

#: The IGMPv3 Membership Report message type (RFC 3376 §4.2).
_V3_REPORT_TYPE = 0x22

#: IGMPv3 group-record types (RFC 3376 §4.2.12).
_RECORD_TYPE_NAMES: dict[int, str] = {
    1: "MODE_IS_INCLUDE",
    2: "MODE_IS_EXCLUDE",
    3: "CHANGE_TO_INCLUDE_MODE",
    4: "CHANGE_TO_EXCLUDE_MODE",
    5: "ALLOW_NEW_SOURCES",
    6: "BLOCK_OLD_SOURCES",
}


@dataclass(frozen=True, slots=True)
class IGMPv3GroupRecord:
    """One group record from an IGMPv3 Membership Report (RFC 3376 §4.2.4).

    :param record_type: Record type — ``1`` MODE_IS_INCLUDE, ``2``
        MODE_IS_EXCLUDE, ``3`` CHANGE_TO_INCLUDE_MODE, ``4``
        CHANGE_TO_EXCLUDE_MODE, ``5`` ALLOW_NEW_SOURCES, ``6``
        BLOCK_OLD_SOURCES (see :attr:`record_type_name`).
    :param multicast_address: The record's multicast group, dotted-decimal.
    :param source_addresses: The source addresses (dotted-decimal); empty
        for a record that carries none.
    :param aux_data: Auxiliary data, kept raw (RFC 3376 defines none, so
        this is normally empty).
    """

    record_type: int
    multicast_address: str
    source_addresses: tuple[str, ...] = ()
    aux_data: bytes = b""

    @property
    def record_type_name(self) -> str:
        """Display name of the record type, e.g. ``"MODE_IS_EXCLUDE"``."""
        return _RECORD_TYPE_NAMES.get(
            self.record_type, f"unknown ({self.record_type:#04x})"
        )


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
        for the v3 report, which uses that space for a record count (read
        its groups via :attr:`group_records`)."""
        if self.type in _GROUP_ADDRESS_TYPES and len(self.body) >= 4:
            return bytes_to_ipv4(self.body[:4])
        return None

    @property
    def num_group_records(self) -> int | None:
        """Number of group records in a v3 Membership Report (message
        bytes 6-7), or ``None`` for other message types.

        :raises InvalidFieldError: if the report ends before the count.
        """
        if self.type != _V3_REPORT_TYPE:
            return None
        if len(self.body) < 4:
            raise InvalidFieldError(
                "IGMPv3 report truncated before the record count"
            )
        return int.from_bytes(self.body[2:4], "big")

    @property
    def group_records(self) -> tuple[IGMPv3GroupRecord, ...] | None:
        """The group records of a v3 Membership Report (type ``0x22``),
        parsed on demand; ``None`` for other message types.

        :raises InvalidFieldError: if a record, its source list, or its
            auxiliary data runs past the message (bounded — never hangs
            or over-reads).
        """
        count = self.num_group_records
        if count is None:
            return None
        body = self.body
        records: list[IGMPv3GroupRecord] = []
        cursor = 4  # past the reserved word (bytes 0-1) and count (2-3)
        for _ in range(count):
            if cursor + 8 > len(body):
                raise InvalidFieldError("IGMPv3 group record truncated")
            record_type = body[cursor]
            aux_words = body[cursor + 1]
            num_sources = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
            multicast = bytes_to_ipv4(body[cursor + 4 : cursor + 8])
            cursor += 8
            sources: list[str] = []
            for _ in range(num_sources):
                if cursor + 4 > len(body):
                    raise InvalidFieldError(
                        "IGMPv3 group record source list truncated"
                    )
                sources.append(bytes_to_ipv4(body[cursor : cursor + 4]))
                cursor += 4
            aux_len = aux_words * 4
            if cursor + aux_len > len(body):
                raise InvalidFieldError("IGMPv3 auxiliary data truncated")
            aux_data = body[cursor : cursor + aux_len]
            cursor += aux_len
            records.append(
                IGMPv3GroupRecord(
                    record_type=record_type,
                    multicast_address=multicast,
                    source_addresses=tuple(sources),
                    aux_data=aux_data,
                )
            )
        return tuple(records)

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x0b3a"``."""
        return f"{self.checksum:#06x}"
