"""ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) headers.

Both classes model the 8-byte header common to all control messages:
type, code, checksum, and the message-specific final 4 bytes (the
"rest of header" in ICMPv4, the start of the message body in ICMPv6).
Message-specific payloads beyond those 8 bytes are left to the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["ICMPv4", "ICMPv6"]


@dataclass(frozen=True, slots=True)
class _ICMP(Protocol):
    """Shared shape of the two ICMP variants.

    :param type: Control message type.
    :param code: Control message subtype.
    :param checksum: Checksum, carried verbatim (this library neither
        computes nor verifies checksums).
    :param rest: The message-specific final 4 bytes of the header.
    """

    type: int
    code: int
    checksum: int
    rest: bytes

    _struct: ClassVar[Struct] = Struct("!BBH4s")
    type_names: ClassVar[dict[int, str]] = {}

    def __post_init__(self) -> None:
        if len(self.rest) != 4:
            raise InvalidFieldError(
                f"{self.__class__.__name__} rest-of-header must be exactly "
                f"4 bytes, got {len(self.rest)}"
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        type_, code, checksum, rest = cls._unpack_fixed(data)
        return cls(type=type_, code=code, checksum=checksum, rest=rest)

    def __bytes__(self) -> bytes:
        return self._struct.pack(self.type, self.code, self.checksum, self.rest)

    @property
    def type_name(self) -> str:
        """Display name of the message type, e.g. ``"Echo Request"``."""
        return self.type_names.get(
            self.type, "Unknown, Unassigned or Deprecated"
        )

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x83f7"``."""
        return f"{self.checksum:#06x}"


@dataclass(frozen=True, slots=True)
class ICMPv4(_ICMP):
    """An ICMPv4 header (RFC 792)."""

    type_names: ClassVar[dict[int, str]] = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        4: "Source Quench",
        5: "Redirect Message",
        8: "Echo Request",
        9: "Router Advertisement",
        10: "Router Solicitation",
        11: "Time Exceeded",
        12: "Parameter Problem: Bad IP Header",
        13: "Timestamp",
        14: "Timestamp Reply",
        15: "Information Request",
        16: "Information Reply",
        17: "Address Mask Request",
        18: "Address Mask Reply",
        30: "Traceroute",
        42: "Extended Echo Request",
        43: "Extended Echo Reply",
    }


@dataclass(frozen=True, slots=True)
class ICMPv6(_ICMP):
    """An ICMPv6 header (RFC 4443)."""

    type_names: ClassVar[dict[int, str]] = {
        1: "Destination Unreachable",
        2: "Packet Too Big",
        3: "Time Exceeded",
        4: "Parameter Problem",
        100: "Private Experimentation",
        101: "Private Experimentation",
        127: "Reserved for Expansion of ICMPv6 Error Messages",
        128: "Echo Request",
        129: "Echo Reply",
        130: "Multicast Listener Query",
        131: "Multicast Listener Report",
        132: "Multicast Listener Done",
        133: "Router Solicitation",
        134: "Router Advertisement",
        135: "Neighbor Solicitation",
        136: "Neighbor Advertisement",
        137: "Redirect Message",
        138: "Router Renumbering",
        139: "ICMP Node Information Query",
        140: "ICMP Node Information Response",
        141: "Inverse Neighbor Discovery Solicitation Message",
        142: "Inverse Neighbor Discovery Advertisement Message",
        143: "Multicast Listener Discovery reports",
        144: "Home Agent Address Discovery Request Message",
        145: "Home Agent Address Discovery Reply Message",
        146: "Mobile Prefix Solicitation",
        147: "Mobile Prefix Advertisement",
        148: "Certification Path Solicitation",
        149: "Certification Path Advertisement",
        151: "Multicast Router Advertisement",
        152: "Multicast Router Solicitation",
        153: "Multicast Router Termination",
        155: "RPL Control Message",
        200: "Private Experimentation",
        201: "Private Experimentation",
        255: "Reserved for Expansion of ICMPv6 Informational Messages",
    }
