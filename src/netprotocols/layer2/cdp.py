"""CDP — the Cisco Discovery Protocol.

A CDP speaker multicasts a PDU on each port to tell its neighbours what
it is: its name, its addresses, the port it sent from, what it can do,
and for how many seconds to believe it. Over Ethernet the PDU follows an
IEEE 802.3 Length, an LLC header (DSAP and SSAP 0xAA, UI) and a SNAP
header of OUI 00-00-0C (Cisco) and PID 0x2000; the default registry
puts :class:`CDP` at that key of the ``llc.snap`` table (see
:mod:`netprotocols.layer2.llc`). The PDU encapsulates nothing, so the
layer is terminal.

There is no RFC. The format below is Wireshark's dissector,
epan/dissectors/packet-cdp.c, and the frames lldpd 1.0.18 sends with
``-c`` (``tests/fixtures/llc.pcap``)::

    +---------+---------+-------------------+
    | Version |   TTL   |     Checksum      |   4-byte header
    +---------+---------+-------------------+
    |       Type        |      Length       |   one TLV; Length counts
    +-------------------+-------------------+   these 4 bytes too
    |        Value (Length - 4 bytes)       |
    +---------------------------------------+
    |                 ...                   |   more TLVs

Version and TTL are one byte each (TTL in seconds); the Checksum covers
the whole PDU (see :func:`~netprotocols.checksum.compute`). CDP version
1 and version 2 share this format, version 2 adding TLV types, so
:meth:`CDP.decode` reads any Version the same way and rejects none:
the SNAP header says outright that a CDP PDU follows, so there is no
wrong guess to guard against, and a Version of 0 or 3 is kept for the
caller to see.

Every TLV is kept raw, in wire order, as a :class:`CDPTLV`, its
:attr:`~CDPTLV.type_name` naming the types Wireshark names. Typed
accessors read the common ones: :attr:`CDP.device_id`,
:attr:`CDP.port_id`, :attr:`CDP.software_version` and
:attr:`CDP.platform` (text), :attr:`CDP.capabilities` and
:attr:`CDP.capability_names` (a 32-bit mask), and
:attr:`CDP.addresses` and :attr:`CDP.management_addresses` (lists of
:class:`CDPAddress`). Each reads the first TLV of its type and answers
``None`` when there is none, or when its value is too short for a
Capabilities mask or does not parse as an address list
(:attr:`CDP.capability_names` answers ``()`` instead); none raises.

Where a CDP PDU ends
--------------------
CDP has no length for the whole PDU: the TLVs run to the end of the
802.3 Length, and the checksum covers exactly those bytes. In a walk,
:func:`~netprotocols.decode_frame` ends the buffer it hands
:meth:`CDP.decode` there (see :mod:`netprotocols.layer2.llc`), so
Ethernet's zero padding and a captured FCS never reach it. Called
directly, ``decode`` has no Length to go by and reads TLVs from byte 4
to the end of its buffer, so the caller bounds it, e.g. with
``frame[22 : 14 + eth.length]`` for an untagged frame. Either way,
the TLVs must fill the buffer ``decode`` is handed:

* ``decode`` stops, without raising, only where every byte left is
  zero: fewer than 4 bytes are left, or a TLV header's Length is below
  4, the size of the header it counts, and from there to the end of
  the buffer the bytes are all zero. Those zeros are left undecoded
  (decode contract rule 3) and :attr:`CDP.header_len` ends before
  them, so Ethernet's zero padding, of any length, stays out of the
  PDU. Rule 3 holds for those zeros only, as for SCTP: nothing else
  is left undecoded.
* Otherwise a TLV Length below 4 raises
  :class:`~netprotocols.InvalidFieldError`, and 1-3 bytes left after
  the last TLV raise :class:`~netprotocols.TruncatedHeaderError`, each
  with ``field="tlvs"`` and the offset where the TLV would start. In a
  walk, where the 802.3 Length ends the buffer, such bytes are inside
  the PDU the sender declared: a strict
  :func:`~netprotocols.decode_frame` raises, and a lax one stops
  before CDP with the error on ``stopped_by``.
* A TLV whose Length is 4 or more but runs past the buffer raises
  :class:`~netprotocols.TruncatedHeaderError` (``field="tlvs"``, the
  offset of the TLV's header), as any header that lies about its
  length does. That is also what a snap length cutting a TLV short
  raises inside a walk.
* So a nonzero trailer such as a 4-byte FCS, read as a TLV header
  whose last 2 bytes are the Length, raises for a Length below 4 or
  one that runs past the buffer, and with exactly 4 decodes as a
  phantom TLV with an empty value. In that one case
  :func:`~netprotocols.checksum.verify`, which sums the bytes decoded,
  ``bytes(cdp)``, is the signal: it fails unless the phantom TLV
  happens to leave the ones'-complement sum unchanged.

Wireshark's dissector, epan/dissectors/packet-cdp.c, differs on two
points: at a TLV Length below 4 it adds an "invalid length" item,
stops, and shows whatever follows as plain data, without marking the
frame malformed; and with 1-3 bytes left it tries to read a 4-byte TLV
header from them and marks the frame malformed, even when they are
zero (the TLV loop of ``dissect_cdp``, commit 31bf0857).

A header shorter than its fixed 4 bytes raises
:class:`~netprotocols.TruncatedHeaderError` (offset 0, no ``field``).

The walk is local to this module rather than
:func:`~netprotocols._tlv.walk_kind_length_value`, the TLV walker
TCP, IPv4, IPv6 and PIM share. Its 2-byte Type and Length, with
``length_includes_header=True``, are CDP's TLV header, floor of 4
included, but it raises :class:`~netprotocols.InvalidFieldError` for
a header cut short and for a Length that runs past the bytes, where
the decode contract asks for :class:`~netprotocols.TruncatedHeaderError`,
and it knows no zero tail: ending there would take a wrapper that
catches its errors and translates them. The LLDP decoder keeps its own
walk for the same reasons.

``bytes(CDP.decode(x)) == x[:header_len]`` holds by construction: the
header is packed back from its three fields and each TLV from its type
and its value, carried verbatim.

Wireshark's Port ID heuristic is not reproduced: its dissector widens a
Port ID TLV by 3 bytes when the byte after it is neither 0x00 nor 0x10
("because that's what makes one capture work"). Here every TLV is
exactly as long as its Length says.
"""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, Self

from netprotocols._base import Protocol, bytes_to_ipv4, bytes_to_ipv6
from netprotocols.utils.exceptions import (
    InvalidFieldError,
    TruncatedHeaderError,
)

__all__ = ["CDP", "CDPTLV", "CDPAddress"]

#: A TLV's header: Type and Length, two bytes each.
_TLV_HEADER = Struct("!HH")
_TLV_HEADER_LEN = 4
_MAX_VALUE_LENGTH = 0xFFFF - _TLV_HEADER_LEN

#: The TLV types the accessors read.
_DEVICE_ID = 0x0001
_ADDRESS = 0x0002
_PORT_ID = 0x0003
_CAPABILITIES = 0x0004
_SOFTWARE_VERSION = 0x0005
_PLATFORM = 0x0006
_MANAGEMENT_ADDRESS = 0x0016

# The names and numbers below are Wireshark's, copied verbatim from
# epan/dissectors/packet-cdp.c (``type_vals``; the
# ``hf_cdp_capabilities_*`` field names and masks; ``proto_type_vals``)
# and, for NLPID_IP, epan/dissectors/packet-osi.h, at commit
# 31bf085794733ece0436365ad3e0bbcc2292fc9a, fetched 2026-10-25 from
# gitlab.com/wireshark/wireshark. Types 0x1000-0x100D are HP's, sent by
# its access points, as packet-cdp.c lists them.

#: TLV type names.
_TLV_TYPE_NAMES: dict[int, str] = {
    0x0001: "Device ID",
    0x0002: "Addresses",
    0x0003: "Port ID",
    0x0004: "Capabilities",
    0x0005: "Software version",
    0x0006: "Platform",
    0x0007: "IP Prefix/Gateway (used for ODR)",
    0x0008: "Protocol Hello",
    0x0009: "VTP Management Domain",
    0x000A: "Native VLAN",
    0x000B: "Duplex",
    0x000E: "VoIP VLAN Reply",
    0x000F: "VoIP VLAN Query",
    0x0010: "Power consumption",
    0x0011: "MTU",
    0x0012: "Trust Bitmap",
    0x0013: "Untrusted Port CoS",
    0x0014: "System Name",
    0x0015: "System Object ID",
    0x0016: "Management Address",
    0x0017: "Location",
    0x0018: "External Port-ID",
    0x0019: "Power Requested",
    0x001A: "Power Available",
    0x001B: "Port Unidirectional",
    0x001D: "EnergyWise",
    0x001F: "Spare PoE",
    0x1000: "BSSID",
    0x1001: "Serial number",
    0x1002: "SSID",
    0x1003: "Radio1 channel",
    0x1006: "SNMP UDP port",
    0x1007: "Web TCP port",
    0x1008: "Source MAC address",
    0x1009: "Radio2 channel",
    0x100A: "Radio1 Operating mode",
    0x100B: "Radio2 Operating mode",
    0x100C: "Radio1 Radio mode",
    0x100D: "Radio2 Radio mode",
}

#: Capabilities bits, low to high, and their names.
_CAPABILITY_NAMES: tuple[tuple[int, str], ...] = (
    (0x00000001, "Router"),
    (0x00000002, "Transparent Bridge"),
    (0x00000004, "Source Route Bridge"),
    (0x00000008, "Switch"),
    (0x00000010, "Host"),
    (0x00000020, "IGMP capable"),
    (0x00000040, "Repeater"),
    (0x00000080, "VoIP Phone"),
    (0x00000100, "Remotely Managed Device"),
    (0x00000200, "CVTA/STP Dispute Resolution/Cisco VT Camera"),
    (0x00000400, "Two Port Mac Relay"),
)

#: An address's protocol types, and their names.
_PROTOCOL_TYPE_NLPID = 1
_PROTOCOL_TYPE_802_2 = 2
_PROTOCOL_TYPE_NAMES: dict[int, str] = {
    _PROTOCOL_TYPE_NLPID: "NLPID",
    _PROTOCOL_TYPE_802_2: "802.2",
}

#: The protocol of an IPv4 address: NLPID 0xCC (NLPID_IP).
_NLPID_IP = b"\xcc"
#: The protocol of an IPv6 address: an 802.2 LLC/SNAP header, OUI
#: 00-00-00 and EtherType 0x86DD, the one 802.2 form packet-cdp.c
#: reads as an address.
_SNAP_IPV6 = b"\xaa\xaa\x03\x00\x00\x00\x86\xdd"


def _check_range(
    owner: type, field: str, value: int, low: int, high: int
) -> None:
    """Reject ``value`` outside ``low``-``high``.

    :raises InvalidFieldError: naming ``owner`` and ``field``.
    """
    if not low <= value <= high:
        raise InvalidFieldError(
            f"{owner.__name__} {field} must be within {low}-{high}, got "
            f"{value}",
            protocol=owner,
            field=field,
            expected=f"{low}-{high}",
            actual=value,
        )


@dataclass(frozen=True, slots=True)
class CDPTLV:
    """One TLV of a CDP PDU, its value kept raw.

    :param type: TLV type, ``0``-``0xFFFF`` (see :attr:`type_name`).
    :param value: The TLV's value, at most 65531 bytes: its Length,
        which counts the 4-byte header too, must fit 16 bits.

    ``bytes(tlv)`` is the on-wire TLV: Type, Length, then the value.
    """

    type: int
    value: bytes = b""

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring).

        :raises InvalidFieldError: a type that overflows 16 bits, or a
            value too long for the Length.
        """
        _check_range(type(self), "type", self.type, 0, 0xFFFF)
        _check_range(type(self), "value", len(self.value), 0, _MAX_VALUE_LENGTH)

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return _TLV_HEADER.pack(self.type, self.length) + self.value

    @property
    def length(self) -> int:
        """Return the TLV's Length: its value plus the 4-byte header."""
        return _TLV_HEADER_LEN + len(self.value)

    @property
    def type_name(self) -> str:
        """Name the TLV type, e.g. ``"Platform"``.

        A type Wireshark does not name reads ``"unknown (0x....)"``.
        """
        name = _TLV_TYPE_NAMES.get(self.type)
        return f"unknown ({self.type:#06x})" if name is None else name


@dataclass(frozen=True, slots=True)
class CDPAddress:
    """One address of an Addresses or Management Address TLV.

    The layout is packet-cdp.c's ``dissect_address_tlv``: a protocol
    type byte, a protocol length byte, that many bytes of protocol, a
    2-byte address length, and that many bytes of address.

    :param protocol_type: ``1`` for an NLPID protocol, ``2`` for an
        802.2 LLC/SNAP header (see :attr:`protocol_type_name`).
    :param protocol: The protocol, at most 255 bytes: NLPID ``0xCC``
        for IPv4, or ``AA AA 03 00 00 00 86 DD`` for IPv6.
    :param address: The address, at most 65535 bytes.
    """

    protocol_type: int
    protocol: bytes
    address: bytes

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring).

        :raises InvalidFieldError: a protocol type that overflows its
            byte, or a protocol or address too long for its length.
        """
        _check_range(type(self), "protocol_type", self.protocol_type, 0, 0xFF)
        _check_range(type(self), "protocol", len(self.protocol), 0, 0xFF)
        _check_range(type(self), "address", len(self.address), 0, 0xFFFF)

    def __bytes__(self) -> bytes:
        """Serialize to the on-wire form."""
        return (
            bytes((self.protocol_type, len(self.protocol)))
            + self.protocol
            + len(self.address).to_bytes(2)
            + self.address
        )

    @property
    def protocol_type_name(self) -> str:
        """Name the protocol type: ``"NLPID"`` or ``"802.2"``.

        Any other value reads ``"unknown (n)"``.
        """
        name = _PROTOCOL_TYPE_NAMES.get(self.protocol_type)
        return f"unknown ({self.protocol_type})" if name is None else name

    @property
    def ip(self) -> str | None:
        """Return the address as an IPv4 or IPv6 string, or ``None``.

        IPv4 for NLPID ``0xCC`` and a 4-byte address, IPv6 for the
        802.2 header of EtherType 0x86DD and a 16-byte address, the two
        forms packet-cdp.c reads; ``None`` for any other.
        """
        if (
            self.protocol_type == _PROTOCOL_TYPE_NLPID
            and self.protocol == _NLPID_IP
            and len(self.address) == 4
        ):
            return bytes_to_ipv4(self.address)
        if (
            self.protocol_type == _PROTOCOL_TYPE_802_2
            and self.protocol == _SNAP_IPV6
            and len(self.address) == 16
        ):
            return bytes_to_ipv6(self.address)
        return None


def _read_address(value: bytes, cursor: int) -> tuple[CDPAddress, int] | None:
    """Read the address at ``cursor``, or ``None`` if it runs past.

    :returns: The address, and the offset just past it.
    """
    size = len(value)
    if cursor + 2 > size:
        return None
    protocol_type, protocol_length = value[cursor], value[cursor + 1]
    protocol_end = cursor + 2 + protocol_length
    if protocol_end + 2 > size:
        return None
    address_end = (
        protocol_end
        + 2
        + int.from_bytes(value[protocol_end : protocol_end + 2])
    )
    if address_end > size:
        return None
    address = CDPAddress(
        protocol_type=protocol_type,
        protocol=value[cursor + 2 : protocol_end],
        address=value[protocol_end + 2 : address_end],
    )
    return address, address_end


def _parse_addresses(value: bytes) -> tuple[CDPAddress, ...] | None:
    """Parse a 4-byte address count and that many addresses.

    ``None`` when the count is cut short or an address runs past the
    value. Bytes after the last address counted are ignored, as
    packet-cdp.c ignores them. The count is 32 bits, but each address
    takes at least 4 bytes, so the loop ends within ``len(value) / 4``
    rounds whatever it says.
    """
    if len(value) < 4:
        return None
    count = int.from_bytes(value[:4])
    addresses: list[CDPAddress] = []
    cursor = 4
    while len(addresses) < count:
        entry = _read_address(value, cursor)
        if entry is None:
            return None
        address, cursor = entry
        addresses.append(address)
    return tuple(addresses)


def _end_tlvs(
    protocol: type, data: bytes | memoryview, cursor: int, length: int | None
) -> None:
    """Let the TLVs end at ``cursor`` only if every byte from it is zero.

    A run of zero bytes there is padding, left undecoded; anything else
    is a TLV the PDU cannot hold. The remainder is scanned once, on the
    way out of the walk, so decoding stays linear.

    :param protocol: The class to attach to a raised error.
    :param data: The buffer being decoded.
    :param cursor: Where the next TLV would start.
    :param length: That TLV's Length, below 4, or ``None`` when fewer
        than 4 bytes are left to hold its header.
    :raises TruncatedHeaderError: ``length`` is ``None`` and the bytes
        left are not all zero.
    :raises InvalidFieldError: ``length`` is below 4 and the bytes
        left are not all zero.
    """
    if not any(data[cursor:]):
        return
    if length is None:
        raise TruncatedHeaderError(
            f"CDP TLV header at offset {cursor} needs {_TLV_HEADER_LEN} "
            f"bytes, {len(data) - cursor} remain",
            protocol=protocol,
            field="tlvs",
            offset=cursor,
            expected=_TLV_HEADER_LEN,
            actual=len(data) - cursor,
        )
    raise InvalidFieldError(
        f"CDP TLV at offset {cursor} declares Length {length}, below "
        f"its {_TLV_HEADER_LEN}-byte header",
        protocol=protocol,
        field="tlvs",
        offset=cursor,
        expected=f">={_TLV_HEADER_LEN}",
        actual=length,
    )


@dataclass(frozen=True, slots=True)
class CDP(Protocol):
    """A Cisco Discovery Protocol PDU; see the module docstring.

    :param version: CDP version, ``0``-``255``: ``1`` or ``2`` on the
        wire, any other decoded and kept as is.
    :param ttl: How many seconds a receiver keeps this information,
        ``0``-``255``.
    :param checksum: The checksum field, ``0``-``0xFFFF``; see
        :func:`~netprotocols.checksum.compute`.
    :param tlvs: The TLVs, in wire order.
    """

    version: int
    ttl: int
    checksum: int = 0
    tlvs: tuple[CDPTLV, ...] = ()

    #: Version, TTL and Checksum.
    _struct: ClassVar[Struct] = Struct("!BBH")

    def __post_init__(self) -> None:
        """Validate the fields (see the class docstring).

        :raises InvalidFieldError: a version, TTL or checksum that
            overflows its field, or a TLV that is not a :class:`CDPTLV`.
        """
        _check_range(type(self), "version", self.version, 0, 0xFF)
        _check_range(type(self), "ttl", self.ttl, 0, 0xFF)
        _check_range(type(self), "checksum", self.checksum, 0, 0xFFFF)
        for index, tlv in enumerate(self.tlvs):
            if not isinstance(tlv, CDPTLV):
                raise InvalidFieldError(
                    f"CDP tlvs must all be CDPTLV; found "
                    f"{type(tlv).__name__} at index {index}",
                    protocol=type(self),
                    field="tlvs",
                    expected="CDPTLV",
                    actual=type(tlv).__name__,
                )

    @classmethod
    def decode(cls, data: bytes | memoryview) -> Self:
        """Decode the CDP PDU at the start of ``data``; see the module.

        :raises TruncatedHeaderError: ``data`` is shorter than the
            4-byte header (no ``field``); a TLV whose Length is 4 or
            more runs past it, or 1-3 bytes are left after the last TLV
            and not all are zero (``field="tlvs"``, the offset of that
            TLV, or of those bytes).
        :raises InvalidFieldError: a TLV's Length is below 4 and the
            bytes from its header to the end of ``data`` are not all
            zero (``field="tlvs"``, the offset of that TLV).
        """
        version, ttl, checksum = cls._unpack_fixed(data)
        size = len(data)
        tlvs: list[CDPTLV] = []
        cursor = cls._struct.size
        while cursor < size:
            if size - cursor < _TLV_HEADER_LEN:
                _end_tlvs(cls, data, cursor, None)
                break
            tlv_type, length = _TLV_HEADER.unpack_from(data, cursor)
            if length < _TLV_HEADER_LEN:
                _end_tlvs(cls, data, cursor, length)
                break
            end = cursor + length
            if end > size:
                raise TruncatedHeaderError(
                    f"CDP TLV at offset {cursor} declares Length "
                    f"{length}, buffer holds {size - cursor}",
                    protocol=cls,
                    field="tlvs",
                    offset=cursor,
                    expected=length,
                    actual=size - cursor,
                )
            tlvs.append(
                CDPTLV(tlv_type, bytes(data[cursor + _TLV_HEADER_LEN : end]))
            )
            cursor = end
        return cls(version, ttl, checksum, tuple(tlvs))

    def __bytes__(self) -> bytes:
        """Serialize the header and every TLV."""
        return self._struct.pack(
            self.version, self.ttl, self.checksum
        ) + b"".join(bytes(tlv) for tlv in self.tlvs)

    @property
    def header_len(self) -> int:
        """Return the PDU's length: the header and every TLV."""
        return self._struct.size + sum(tlv.length for tlv in self.tlvs)

    @property
    def checksum_hex_str(self) -> str:
        """Return the checksum as a hexadecimal string, e.g. ``"0xfdf3"``."""
        return f"{self.checksum:#06x}"

    def tlv(self, tlv_type: int) -> CDPTLV | None:
        """Return the first TLV of type ``tlv_type``, or ``None``."""
        return next((t for t in self.tlvs if t.type == tlv_type), None)

    def _text(self, tlv_type: int) -> str | None:
        """Return the first ``tlv_type`` TLV's value as text, or ``None``.

        Read as ASCII; a byte outside it reads as a backslash escape, so
        no value raises and none is lost.
        """
        tlv = self.tlv(tlv_type)
        if tlv is None:
            return None
        return tlv.value.decode("ascii", "backslashreplace")

    @property
    def device_id(self) -> str | None:
        """Return the Device ID (type 1), e.g. a hostname, or ``None``."""
        return self._text(_DEVICE_ID)

    @property
    def port_id(self) -> str | None:
        """Return the Port ID (type 3), the sending interface, or ``None``."""
        return self._text(_PORT_ID)

    @property
    def software_version(self) -> str | None:
        """Return the Software version (type 5), or ``None``."""
        return self._text(_SOFTWARE_VERSION)

    @property
    def platform(self) -> str | None:
        """Return the Platform (type 6), e.g. a model name, or ``None``."""
        return self._text(_PLATFORM)

    @property
    def capabilities(self) -> int | None:
        """Return the Capabilities (type 4) mask, or ``None``.

        The value's first 4 bytes, big-endian, as packet-cdp.c reads
        them; ``None`` when there is no such TLV or its value is
        shorter (see :attr:`capability_names`).
        """
        tlv = self.tlv(_CAPABILITIES)
        if tlv is None or len(tlv.value) < 4:
            return None
        return int.from_bytes(tlv.value[:4])

    @property
    def capability_names(self) -> tuple[str, ...]:
        """Name the bits set in :attr:`capabilities`, low bit first.

        E.g. ``("Switch", "Host")``. Bits Wireshark does not name are
        left out; no Capabilities gives ``()``.
        """
        mask = self.capabilities or 0
        return tuple(name for bit, name in _CAPABILITY_NAMES if mask & bit)

    @property
    def addresses(self) -> tuple[CDPAddress, ...] | None:
        """Return the Addresses (type 2) TLV's addresses, or ``None``.

        ``None`` when there is no such TLV, or its count or an address
        runs past its value.
        """
        tlv = self.tlv(_ADDRESS)
        return None if tlv is None else _parse_addresses(tlv.value)

    @property
    def management_addresses(self) -> tuple[CDPAddress, ...] | None:
        """Return the Management Address (type 22) TLV's addresses.

        Laid out as :attr:`addresses` is, and ``None`` in the same cases.
        """
        tlv = self.tlv(_MANAGEMENT_ADDRESS)
        return None if tlv is None else _parse_addresses(tlv.value)
