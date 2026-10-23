"""VXLAN — Virtual eXtensible Local Area Network (RFC 7348).

VXLAN stretches a layer-2 segment across an IP fabric by carrying each
whole Ethernet frame in a UDP datagram, to the IANA-assigned port 4789,
behind an 8-byte header (§5)::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |R|R|R|R|I|R|R|R|            Reserved                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                VXLAN Network Identifier (VNI) |   Reserved    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The payload is always a complete inner Ethernet frame (without its
FCS), so :meth:`VXLAN.next_protocol` names :class:`~netprotocols.Ethernet`
unconditionally and the walk re-enters the ``ethertype`` table from the
top: inner VLAN tags, ARP, IPv4 and IPv6 need no dispatch of their own.

Only the I flag (``0x08``) is defined; RFC 7348 requires it set for a
valid VNI and requires every reserved bit to be sent as zero and ignored
on receipt. The decoder follows both rules: it rejects a header with
the I flag clear and keeps the reserved bits verbatim without judging
them, so a header from an extension that reuses them (Group Based
Policy, for one) still decodes and round-trips exactly.

The I flag is also the decoder's one defence against a wrong guess.
VXLAN is reached through ``udp.port``, which is best-effort (see
:mod:`netprotocols.registry`), and an inner Ethernet header accepts any
14 bytes, so without the check every datagram that merely used port
4789 would decode as a tunnel holding a garbage frame. Requiring the
flag turns such a datagram into a diagnosed one in about half of cases;
nothing in the header can do better without rejecting what the RFC
says to ignore.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol
from netprotocols.layer2.ethernet import Ethernet
from netprotocols.registry import Registry
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["VXLAN"]


@dataclass(frozen=True, slots=True)
class VXLAN(Protocol):
    """A VXLAN header (RFC 7348 §5).

    :param flags: The flags byte. Only the I flag (:attr:`I_FLAG`,
        ``0x08``) is defined, and it must be set; the other seven bits
        are reserved and carried verbatim.
    :param reserved1: The 24 reserved bits after the flags, carried
        verbatim (``0`` on transmit, per the RFC).
    :param vni: VXLAN Network Identifier, ``0``-``16777215``: the
        layer-2 segment the inner frame belongs to.
    :param reserved2: The 8 reserved bits after the VNI, carried
        verbatim (``0`` on transmit, per the RFC).
    """

    flags: int
    reserved1: int
    vni: int
    reserved2: int

    #: The I flag: set when the VNI is valid, which RFC 7348 requires.
    I_FLAG: ClassVar[int] = 0x08

    #: Two 32-bit words: flags + reserved, then VNI + reserved.
    _struct: ClassVar[Struct] = Struct("!II")

    def __post_init__(self) -> None:
        if not 0 <= self.flags <= 0xFF:
            raise InvalidFieldError(
                f"VXLAN flags must be within 0-255, got {self.flags}",
                protocol=type(self),
                field="flags",
                expected="0-255",
                actual=self.flags,
            )
        if not self.flags & self.I_FLAG:
            raise _missing_i_flag(type(self), self.flags)
        if not 0 <= self.reserved1 <= 0xFFFFFF:
            raise InvalidFieldError(
                f"VXLAN reserved1 must be within 0-16777215, "
                f"got {self.reserved1}",
                protocol=type(self),
                field="reserved1",
                expected="0-16777215",
                actual=self.reserved1,
            )
        if not 0 <= self.vni <= 0xFFFFFF:
            raise InvalidFieldError(
                f"VXLAN VNI must be within 0-16777215, got {self.vni}",
                protocol=type(self),
                field="vni",
                expected="0-16777215",
                actual=self.vni,
            )
        if not 0 <= self.reserved2 <= 0xFF:
            raise InvalidFieldError(
                f"VXLAN reserved2 must be within 0-255, got {self.reserved2}",
                protocol=type(self),
                field="reserved2",
                expected="0-255",
                actual=self.reserved2,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the 8-byte header at the start of ``data``.

        :raises TruncatedHeaderError: ``data`` is shorter than 8 bytes.
        :raises InvalidFieldError: the I flag is clear (``field`` is
            ``"flags"``, ``offset`` ``0``).
        """
        flags_word, vni_word = cls._unpack_fixed(data)
        flags = flags_word >> 24
        if not flags & cls.I_FLAG:
            # Raised here rather than left to __post_init__, which has
            # no bytes to point into: this is a wire error at offset 0.
            raise _missing_i_flag(cls, flags, offset=0)
        return cls(
            flags=flags,
            reserved1=flags_word & 0xFFFFFF,
            vni=vni_word >> 8,
            reserved2=vni_word & 0xFF,
        )

    def __bytes__(self) -> bytes:
        return self._struct.pack(
            (self.flags << 24) | self.reserved1,
            (self.vni << 8) | self.reserved2,
        )

    def next_protocol(
        self, registry: Registry | None = None
    ) -> type[Protocol] | None:
        """The inner Ethernet frame this header carries.

        VXLAN has no field naming its payload — it is always an Ethernet
        frame — so there is nothing for ``registry`` to select here. The
        walk hands the same registry on to the inner
        :class:`~netprotocols.Ethernet`, whose EtherType it does
        select.
        """
        return Ethernet


def _missing_i_flag(
    protocol: type[VXLAN], flags: int, *, offset: int | None = None
) -> InvalidFieldError:
    return InvalidFieldError(
        f"VXLAN I flag (0x08) must be set for a valid VNI (RFC 7348 §5), "
        f"got flags {flags:#04x}",
        protocol=protocol,
        field="flags",
        offset=offset,
        expected="I flag (0x08) set",
        actual=flags,
    )
