"""VRRP — the Virtual Router Redundancy Protocol (RFC 3768, RFC 5798).

VRRP lets a group of routers share virtual IP addresses: the master of
a virtual router, the group named by its Virtual Router ID (VRID),
multicasts an ADVERTISEMENT once per interval, and a backup takes over
when they stop. It rides directly on IP as protocol 112 and never
encapsulates anything, so the layer is terminal.

Both versions in use share one 8-byte fixed header (RFC 3768 §5.1, RFC
5798 §5.1): Version and Type (a nibble each), Virtual Rtr ID, Priority,
Count IP Addrs, a 16-bit word, and the Checksum, then ``Count`` virtual
addresses. The version decides the rest:

* VRRPv2 (RFC 3768), IPv4 only (§1.2): the word is Auth Type (8 bits) and
  Adver Int (8 bits, in seconds), and 8 bytes of Authentication Data
  follow the addresses (§5.3.10) — the plaintext password when Auth
  Type is ``1``, zeros otherwise. The checksum covers the VRRP message
  alone (§5.3.8).
* VRRPv3 (RFC 5798), IPv4 and IPv6: the word is 4 reserved bits and Max
  Adver Int (12 bits, in centiseconds), with no authentication data,
  and the checksum adds the IPv6 pseudo-header over IPv6 (§5.2.8).
  Over IPv4, keepalived adds the IPv4 one by default, and RFC 9568,
  which obsoletes RFC 5798 and keeps this layout and its section
  numbers, leaves it out; see :mod:`netprotocols.checksum`.

So the version nibble is the one field :meth:`VRRP.decode` rejects (as
:class:`~netprotocols.InvalidFieldError`, ``field="version"``) when it
is neither: without it, nothing says whether the word holds an
authentication type or where the message ends. Everything else is
carried verbatim — an unknown Type, a Priority of ``0`` (the master
resigning, RFC 5798 §5.2.4), a Count of ``0`` (below RFC 5798
§5.2.5's minimum of 1), the reserved bits —
because none of it changes the layout. Dispatch is by IP protocol
number, which says outright what follows, so there is no wrong guess to
guard against as there is for a port. The word is kept raw, as ICMP
keeps its rest-of-header word, and read through per-version accessors
(:attr:`VRRP.auth_type`, :attr:`VRRP.adver_int`,
:attr:`VRRP.max_adver_int`, :attr:`VRRP.reserved`) that return
``None`` where the version has no such field.

Nothing in the header says how wide an address is: 4 bytes or 16
depends on the IP family that carried it. That is decided the way AH's
onward dispatch is, by the registry: :class:`VRRP`, registered in
``ip.proto``, reads IPv4 addresses, and its subclass :class:`VRRPv6`,
registered in ``ip.proto.v6``, reads IPv6 ones and accepts only VRRPv3.

VRRP has no length field of its own, but the version and the count
give its exact length, which is :attr:`VRRP.header_len`. Whatever
follows in the buffer is not VRRP — an Ethernet frame's padding, or an
FCS — and is left undecoded (decode contract rule 3): a VRRPv3 advert
for one IPv4 address is only 12 bytes, in a frame Ethernet pads to its
60-byte minimum, and that padding must stay out of a checksum whose
VRRPv3 pseudo-header carries the message's length.

``bytes(VRRP.decode(x)) == x[:header_len]`` holds by construction: the
fixed fields are packed back, the addresses re-encoded from their
strings, and the authentication data carried verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import (
    Protocol,
    bytes_to_ipv4,
    bytes_to_ipv6,
    hex_str,
    ipv4_to_bytes,
    ipv6_to_bytes,
)
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["VRRP", "VRRPv6"]

#: The length of VRRPv2's Authentication Data (RFC 3768 §5.1), present
#: whatever the Auth Type; VRRPv3 has none.
_AUTH_DATA_LEN = 8

#: Message types (RFC 3768 §5.3.2, RFC 5798 §5.2.2): only
#: ADVERTISEMENT is defined.
_TYPE_NAMES: dict[int, str] = {1: "Advertisement"}

#: VRRPv2 authentication types, as RFC 2338 §5.3.6 defined them. RFC
#: 3768 §5.3.6 keeps only ``0`` and reserves ``1`` and ``2`` for
#: compatibility with RFC 2338, but implementations still send ``1``
#: (keepalived's ``auth_type PASS``).
_AUTH_TYPE_NAMES: dict[int, str] = {
    0: "No Authentication",
    1: "Simple Text Password",
    2: "IP Authentication Header",
}


@dataclass(frozen=True, slots=True)
class VRRP(Protocol):
    """A VRRP advertisement carried over IPv4.

    VRRPv2 (RFC 3768 §5.1) or VRRPv3 (RFC 5798 §5.1); see
    :class:`VRRPv6` for VRRPv3 over IPv6.

    :param version: ``2`` (RFC 3768) or ``3`` (RFC 5798); anything else
        raises :class:`~netprotocols.InvalidFieldError`, because the
        version decides the layout.
    :param type: Message type (4 bits); ``1`` is ADVERTISEMENT, the only
        one defined. Others are carried verbatim (see :attr:`type_name`).
    :param vrid: Virtual Router ID, ``1``-``255`` in use.
    :param priority: The sender's priority: ``255`` for the router that
        owns the virtual addresses, ``0`` for a master resigning
        (RFC 3768 §5.3.4, RFC 5798 §5.2.4).
    :param count_ip_addrs: Number of virtual addresses; must equal
        ``len(addresses)``.
    :param adver_word: The 16 bits between Count and Checksum, kept raw:
        Auth Type and Adver Int in VRRPv2, the reserved nibble and Max
        Adver Int in VRRPv3. Read the parts through :attr:`auth_type`,
        :attr:`adver_int`, :attr:`reserved` and :attr:`max_adver_int`.
    :param checksum: The checksum, carried verbatim (compute/verify via
        :mod:`netprotocols.checksum`).
    :param addresses: The virtual addresses, in the family's string
        form: dotted-decimal here. Not validated on construction, like
        :class:`~netprotocols.IPv6`'s: a malformed one fails only in
        ``bytes()``.
    :param auth_data: VRRPv2's 8 bytes of Authentication Data, kept raw
        (the password, null-padded, when :attr:`auth_type` is ``1``);
        empty, the default, in VRRPv3.
    """

    version: int
    type: int
    vrid: int
    priority: int
    count_ip_addrs: int
    adver_word: int
    checksum: int
    addresses: tuple[str, ...]
    auth_data: bytes = b""

    _struct: ClassVar[Struct] = Struct("!BBBBHH")

    #: The versions this class's IP family carries.
    _versions: ClassVar[frozenset[int]] = frozenset({2, 3})

    #: Whether the addresses are IPv6 (16 bytes) rather than IPv4 (4).
    _ipv6: ClassVar[bool] = False

    def __post_init__(self) -> None:
        """Validate the fields :meth:`__bytes__` could not pack faithfully.

        :raises InvalidFieldError: a version with no layout, a type that
            overflows its nibble, or a count or authentication data that
            disagrees with the addresses and the version.
        """
        self._check_version(self.version, offset=None)
        if not 0 <= self.type <= 0x0F:
            raise InvalidFieldError(
                f"{type(self).__name__} type must be within 0-15, got "
                f"{self.type}",
                protocol=type(self),
                field="type",
                expected="0-15",
                actual=self.type,
            )
        self._check_lengths()

    def _check_lengths(self) -> None:
        """Reject a count or authentication data that does not fit.

        The count must be the number of addresses, and the
        authentication data 8 bytes in VRRPv2 and none in VRRPv3.

        :raises InvalidFieldError: on either disagreement.
        """
        if self.count_ip_addrs != len(self.addresses):
            raise InvalidFieldError(
                f"{type(self).__name__} count_ip_addrs "
                f"{self.count_ip_addrs} disagrees with "
                f"{len(self.addresses)} addresses",
                protocol=type(self),
                field="count_ip_addrs",
                expected=len(self.addresses),
                actual=self.count_ip_addrs,
            )
        expected = _AUTH_DATA_LEN if self.version == 2 else 0
        if len(self.auth_data) != expected:
            raise InvalidFieldError(
                f"VRRPv{self.version} carries {expected} bytes of "
                f"authentication data, got {len(self.auth_data)}",
                protocol=type(self),
                field="auth_data",
                expected=expected,
                actual=len(self.auth_data),
            )

    @classmethod
    def _check_version(cls, version: int, *, offset: int | None) -> None:
        """Reject a version this class cannot lay out.

        :raises InvalidFieldError: ``offset`` is passed through — ``0``
            from :meth:`decode`, ``None`` from construction.
        """
        if version not in cls._versions:
            allowed = " or ".join(str(v) for v in sorted(cls._versions))
            raise InvalidFieldError(
                f"{cls.__name__} version must be {allowed}, got {version}",
                protocol=cls,
                offset=offset,
                field="version",
                expected=allowed,
                actual=version,
            )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the advert at the start of ``data``; see the module.

        :raises TruncatedHeaderError: ``data`` is shorter than the fixed
            header, or than the addresses (``field="count_ip_addrs"``)
            or authentication data (``field="auth_data"``) it declares.
        :raises InvalidFieldError: the version is not one this class's
            IP family carries (``field="version"``).
        """
        ver_type, vrid, priority, count, adver_word, checksum = (
            cls._unpack_fixed(data)
        )
        version = ver_type >> 4
        cls._check_version(version, offset=0)
        width = 16 if cls._ipv6 else 4
        addresses_end = cls._struct.size + count * width
        end = addresses_end + (_AUTH_DATA_LEN if version == 2 else 0)
        if end > len(data):
            raise TruncatedHeaderError(
                f"{cls.__name__} declares {end} bytes, buffer holds "
                f"{len(data)}",
                protocol=cls,
                offset=0,
                field=(
                    "count_ip_addrs"
                    if addresses_end > len(data)
                    else "auth_data"
                ),
                expected=end,
                actual=len(data),
            )
        to_str = bytes_to_ipv6 if cls._ipv6 else bytes_to_ipv4
        return cls(
            version=version,
            type=ver_type & 0x0F,
            vrid=vrid,
            priority=priority,
            count_ip_addrs=count,
            adver_word=adver_word,
            checksum=checksum,
            addresses=tuple(
                to_str(bytes(data[offset : offset + width]))
                for offset in range(cls._struct.size, addresses_end, width)
            ),
            auth_data=bytes(data[addresses_end:end]),
        )

    def __bytes__(self) -> bytes:
        """Serialize the advert, re-encoding its address strings."""
        to_bytes = ipv6_to_bytes if self._ipv6 else ipv4_to_bytes
        return (
            self._struct.pack(
                (self.version << 4) | self.type,
                self.vrid,
                self.priority,
                self.count_ip_addrs,
                self.adver_word,
                self.checksum,
            )
            + b"".join(to_bytes(address) for address in self.addresses)
            + self.auth_data
        )

    @property
    def header_len(self) -> int:
        """Return the length of the whole message.

        That is the fixed header, the addresses and any authentication
        data, never what follows them in the buffer.
        """
        width = 16 if self._ipv6 else 4
        return (
            self._struct.size
            + len(self.addresses) * width
            + len(self.auth_data)
        )

    @property
    def type_name(self) -> str:
        """Display name of the message type, e.g. ``"Advertisement"``."""
        return _TYPE_NAMES.get(self.type, f"unknown ({self.type})")

    @property
    def auth_type(self) -> int | None:
        """VRRPv2's Auth Type (RFC 3768 §5.3.6), or ``None`` in VRRPv3.

        It is :attr:`adver_word`'s high byte; VRRPv3 has no
        authentication.
        """
        return self.adver_word >> 8 if self.version == 2 else None

    @property
    def auth_type_name(self) -> str | None:
        """Display name of :attr:`auth_type`, or ``None`` in VRRPv3.

        E.g. ``"Simple Text Password"``, or ``"unknown (7)"``.
        """
        auth_type = self.auth_type
        if auth_type is None:
            return None
        return _AUTH_TYPE_NAMES.get(auth_type, f"unknown ({auth_type})")

    @property
    def adver_int(self) -> int | None:
        """VRRPv2's Adver Int (RFC 3768 §5.3.7), or ``None`` in VRRPv3.

        In seconds, :attr:`adver_word`'s low byte; VRRPv3 carries
        :attr:`max_adver_int` instead.
        """
        return self.adver_word & 0xFF if self.version == 2 else None

    @property
    def reserved(self) -> int | None:
        """VRRPv3's reserved nibble (RFC 5798 §5.2.6), or ``None`` in VRRPv2.

        Zero on send, but carried verbatim.
        """
        return self.adver_word >> 12 if self.version == 3 else None

    @property
    def max_adver_int(self) -> int | None:
        """VRRPv3's Max Adver Int (RFC 5798 §5.2.7), or ``None`` in VRRPv2.

        In centiseconds, :attr:`adver_word`'s low 12 bits; VRRPv2
        carries :attr:`adver_int` instead.
        """
        return self.adver_word & 0x0FFF if self.version == 3 else None

    @property
    def advertisement_interval(self) -> float:
        """Return the interval between advertisements, in seconds.

        Whichever field and unit the version carries it in:
        :attr:`adver_int`, or :attr:`max_adver_int` divided by 100.
        """
        if self.version == 2:
            return float(self.adver_word & 0xFF)
        return (self.adver_word & 0x0FFF) / 100

    @property
    def checksum_hex_str(self) -> str:
        """The checksum as a hexadecimal string, e.g. ``"0x5af6"``."""
        return hex_str(self.checksum, 6)


@dataclass(frozen=True, slots=True)
class VRRPv6(VRRP):
    """A VRRP advertisement carried over IPv6 (RFC 5798 §5.1).

    The same layout as :class:`VRRP`, which it subclasses, with 16-byte
    IPv6 addresses, written in :attr:`addresses` as
    :class:`~netprotocols.IPv6` writes its own (RFC 5952). VRRPv2 is
    defined for IPv4 alone (RFC 3768 §1.2), so a version other than
    ``3`` raises :class:`~netprotocols.InvalidFieldError` here. The
    first address is the virtual router's link-local one (RFC 5798
    §5.2.9).
    """

    _versions: ClassVar[frozenset[int]] = frozenset({3})
    _ipv6: ClassVar[bool] = True
