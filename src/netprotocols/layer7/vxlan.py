"""VXLAN — Virtual eXtensible Local Area Network (RFC 7348).

VXLAN stretches a layer-2 segment across an IP fabric by carrying each
whole Ethernet frame in a UDP datagram, normally to the IANA-assigned
port 4789, behind an 8-byte header (§5)::

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

Only port 4789 is registered. Linux still gives a vxlan device
``dstport`` 8472, the port it used before IANA assigned one, when
``ip link add`` names none, so a capture from such a device needs the
port named for the walk:
``decode_frame(frame, decode_as={"udp.port": {8472: VXLAN}})``.

Only the I flag (``0x08``) is defined; RFC 7348 requires it set for a
valid VNI and requires every reserved bit to be sent as zero and ignored
on receipt. The decoder follows both rules: it rejects a header with
the I flag clear and keeps the reserved bits verbatim without judging
them, so a header from an extension that reuses them (Group Based
Policy, for one) still decodes and round-trips exactly.

Construction checks only that each field fits its width, so
``VXLAN(flags=0, ...)`` builds and ``bytes()`` of it is a header with
the I flag clear: what a test of how another stack drops such headers
needs to send. The I-flag rule is decode-only, and
``VXLAN.decode(bytes(header))`` raises for a header that constructed
without complaint. That makes VXLAN the one class in this library
whose constructor accepts what its own decoder refuses; the
round-trip guarantee in ARCHITECTURE.md names the exception.

The rule is enforced on decode because the I flag is the decoder's one
defence against a wrong guess. VXLAN is reached through ``udp.port``,
which is best-effort (see :mod:`netprotocols.registry`), and an inner
Ethernet header accepts any 14 bytes, so without the check every
datagram that merely used port 4789 would decode as a tunnel holding a
garbage frame. Requiring the flag diagnoses such a datagram about half
the time; nothing in the header can do better without rejecting what
the RFC says to ignore.

The cost falls on a capture that really is VXLAN but has the flag
clear. A strict :func:`~netprotocols.decode_frame` raises
:class:`~netprotocols.InvalidFieldError` whose ``frame_offset`` is the
VXLAN header's; a lax one keeps only the outer layers (Ethernet, IP,
UDP) and reports the same error as ``stopped_by``. The inner frame
starts 8 bytes past that offset, so for that error ``err`` a second
walk decodes it:
``decode_frame(frame[err.frame_offset + 8:], start=Ethernet)``. That
walk is a new one, so a ``registry`` or ``decode_as`` the first walk
used must be passed to it again.
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

    Construction accepts any value that fits each field, the I flag
    clear included; :meth:`decode` is stricter and rejects a header
    without it (see the module docstring for why, and for decoding a
    capture whose I flag is clear).

    :param flags: The flags byte. Only the I flag (:attr:`I_FLAG`,
        ``0x08``) is defined, and RFC 7348 requires it set; it is not
        checked here, only by :meth:`decode`. The other seven bits are
        reserved and carried verbatim.
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
            # Checked here and not in __post_init__: a constructed
            # header may have the flag clear on purpose, but a decoded
            # one without it is most likely not VXLAN at all.
            raise InvalidFieldError(
                f"VXLAN I flag (0x08) must be set for a valid VNI "
                f"(RFC 7348 §5), got flags {flags:#04x}",
                protocol=cls,
                field="flags",
                offset=0,
                expected="I flag (0x08) set",
                actual=flags,
            )
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
