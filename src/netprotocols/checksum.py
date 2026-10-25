"""Checksum computation and verification: the internet checksum (RFC
1071) and SCTP's CRC32c (RFC 9260 Appendix A).

The primitive, :func:`internet_checksum`, returns the raw ones'-
complement result — ``0x0000`` is a legal return value, and TCP, ICMP,
and the IPv4 header checksum legitimately transmit it. The famous
``0x0000 → 0xFFFF`` substitution is a **UDP-only transmit rule**
(RFC 768; RFC 8200 §8.1) and lives solely in the UDP arm of
:func:`compute`.

SCTP alone does not use the internet checksum: its packets carry a
CRC32c (the Castagnoli CRC, also iSCSI's), computed by :func:`crc32c`
over the whole packet with no pseudo-header.

Length fields are trusted, not reconciled: UDP uses ``layer.length``
for the pseudo-header, TCP uses ``layer.header_len + len(payload)``,
and nothing checks ``IPv4.total_length`` against the payload you pass.
Feed these helpers the payload exactly as it appears on the wire.
"""

from __future__ import annotations

import struct
from functools import reduce

from netprotocols._base import (
    Protocol,
    ipv4_to_bytes,
    ipv6_to_bytes,
)
from netprotocols._enums import IPProtocol
from netprotocols.layer3.gre import GRE
from netprotocols.layer3.icmp import ICMPv4, ICMPv6
from netprotocols.layer3.igmp import IGMP
from netprotocols.layer3.ip import IPv4, IPv6
from netprotocols.layer3.pim import PIM
from netprotocols.layer4.sctp import SCTP
from netprotocols.layer4.tcp import TCP
from netprotocols.layer4.udp import UDP
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["compute", "crc32c", "internet_checksum", "verify"]


def internet_checksum(data: bytes | memoryview) -> int:
    """The RFC 1071 checksum of ``data``: the ones' complement of the
    ones'-complement sum of its 16-bit words (odd lengths are padded
    with a zero byte).

    Returns the raw result: ``0x0000`` is a legal value here. Protocol
    rules such as UDP's zero substitution belong to :func:`compute`.
    """
    if len(data) % 2:
        data = bytes(data) + b"\x00"
    words: tuple[int, ...] = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


#: The Castagnoli polynomial 0x1EDC6F41, bit-reflected (RFC 3720 §12.1,
#: RFC 9260 Appendix A).
_CRC32C_POLY = 0x82F63B78

#: The CRC of each byte value, for the byte-at-a-time loop in
#: :func:`crc32c`: eight shift-and-conditionally-xor steps, one per bit.
#: Built by a module-level expression rather than a helper function so
#: the mutation audit (see pyproject.toml's [tool.mutmut]) never sees an
#: import-time call it cannot attribute to a test; the table is pinned
#: through :func:`crc32c`'s test vectors instead.
_CRC32C_TABLE: tuple[int, ...] = tuple(
    reduce(
        lambda crc, _: (crc >> 1) ^ (_CRC32C_POLY if crc & 1 else 0),
        range(8),
        byte,
    )
    for byte in range(256)
)


def crc32c(data: bytes | memoryview) -> int:
    """The CRC32c (Castagnoli) of ``data``: reflected, initial value and
    final xor ``0xFFFFFFFF`` (RFC 3720 §12.1, RFC 9260 Appendix A), e.g.
    ``crc32c(b"123456789") == 0xE3069283``.

    Not :func:`zlib.crc32`, which is the IEEE 802.3 CRC-32 — a
    different polynomial — and the standard library has no CRC32c.

    This is the CRC as a number. SCTP transmits it least significant
    byte first, so the packet's checksum field, read big-endian, is
    this value byte-swapped; :func:`compute` applies that for an
    :class:`~netprotocols.SCTP` layer.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _pseudo_header(ip: IPv4 | IPv6, protocol: int, length: int) -> bytes:
    """The pseudo-header prepended to transport checksums.

    IPv4 (RFC 793/768): src, dst, zero byte, protocol, 16-bit length.
    IPv6 (RFC 8200 §8.1): src, dst, 32-bit length, three zero bytes,
    next-header.
    """
    if isinstance(ip, IPv4):
        return (
            ipv4_to_bytes(ip.src)
            + ipv4_to_bytes(ip.dst)
            + struct.pack("!BBH", 0, protocol, length)
        )
    return (
        ipv6_to_bytes(ip.src)
        + ipv6_to_bytes(ip.dst)
        + struct.pack("!IBBBB", length, 0, 0, 0, protocol)
    )


def _require_ip(layer: Protocol, ip: IPv4 | IPv6 | None) -> IPv4 | IPv6:
    if ip is None:
        raise InvalidFieldError(
            f"Computing a {type(layer).__name__} checksum requires the "
            f"enclosing IPv4/IPv6 layer (its pseudo-header covers the "
            f"addresses)",
            protocol=type(layer),
            field="checksum",
        )
    return ip


def _zeroed(layer_bytes: bytes, checksum_offset: int) -> bytes:
    return (
        layer_bytes[:checksum_offset]
        + b"\x00\x00"
        + layer_bytes[checksum_offset + 2 :]
    )


def _gre_checksum(layer: GRE, payload: bytes) -> int:
    """GRE header plus payload, checksum field (bytes 4-5) zeroed, no
    pseudo-header (RFC 2784 §2.5). Only meaningful when the
    Checksum-Present bit announces the field."""
    if layer.checksum is None:
        raise InvalidFieldError(
            "Computing a GRE checksum requires the Checksum-Present "
            "bit and its field (RFC 2784 §2.5)",
            protocol=type(layer),
            field="checksum",
        )
    return internet_checksum(_zeroed(bytes(layer), 4) + payload)


def _sctp_checksum(layer: SCTP, payload: bytes) -> int:
    """The whole packet, checksum field (bytes 8-11) zeroed, no
    pseudo-header. The CRC goes on the wire least significant byte
    first, and the field reads its four bytes big-endian."""
    packet = bytes(layer)
    crc = crc32c(packet[:8] + b"\x00\x00\x00\x00" + packet[12:] + payload)
    field: int = struct.unpack("!I", crc.to_bytes(4, "little"))[0]
    return field


#: The PIM Register message type, whose checksum covers only the PIM
#: header and the 4-byte Register header after it (RFC 7761 §4.9.3).
_PIM_REGISTER = 1
_PIM_REGISTER_HEADER_LEN = 8


def _pim_covered(layer: PIM, ip: IPv4 | IPv6 | None) -> bytes:
    """The PIM message bytes the checksum covers, checksum field (bytes
    2-3) zeroed: the whole message, or a Register's first 8 bytes (RFC
    7761 §4.9.3). ``ip`` is required, since only the family says
    whether a pseudo-header goes in front."""
    if ip is None:
        raise InvalidFieldError(
            "Computing a PIM checksum requires the enclosing IPv4/IPv6 "
            "layer (over IPv6 its pseudo-header covers the addresses)",
            protocol=type(layer),
            field="checksum",
        )
    message = _zeroed(bytes(layer), 2)
    if layer.type == _PIM_REGISTER:
        return message[:_PIM_REGISTER_HEADER_LEN]
    return message


def _pim_sum(covered: bytes, ip: IPv4 | IPv6 | None) -> int:
    """The internet checksum over ``covered``, behind the IPv6
    pseudo-header (next header 103, the covered length) when ``ip`` is
    IPv6, alone over IPv4 (RFC 7761 §4.9)."""
    if isinstance(ip, IPv6):
        covered = _pseudo_header(ip, IPProtocol.PIM, len(covered)) + covered
    return internet_checksum(covered)


def _pim_checksum(layer: PIM, ip: IPv4 | IPv6 | None) -> int:
    """The PIM checksum: the internet checksum over the message, or over
    a Register's first 8 bytes, with the IPv6 pseudo-header in front
    over IPv6, whose length is then the covered length (RFC 7761
    §4.9)."""
    return _pim_sum(_pim_covered(layer, ip), ip)


def _verify_pim(layer: PIM, ip: IPv4 | IPv6 | None) -> bool:
    """Verify a PIM checksum. A Register's is also accepted computed
    over the whole message, encapsulated packet included, as RFC 7761
    §4.9.3 asks for interoperability with senders that sum it all."""
    if layer.checksum == _pim_checksum(layer, ip):
        return True
    if layer.type != _PIM_REGISTER:
        return False
    return layer.checksum == _pim_sum(_zeroed(bytes(layer), 2), ip)


def _transport_checksum(
    layer: ICMPv6 | TCP | UDP, ip: IPv4 | IPv6 | None, payload: bytes
) -> int:
    """The checksums behind a pseudo-header built from ``ip``: ICMPv6,
    TCP and UDP, the last with its zero substitution."""
    enclosing = _require_ip(layer, ip)
    if isinstance(layer, ICMPv6):
        segment = _zeroed(bytes(layer), 2) + payload
        return internet_checksum(
            _pseudo_header(enclosing, IPProtocol.IPV6_ICMP, len(segment))
            + segment
        )
    if isinstance(layer, TCP):
        segment = _zeroed(bytes(layer), 16) + payload
        return internet_checksum(
            _pseudo_header(enclosing, IPProtocol.TCP, len(segment)) + segment
        )
    datagram = _zeroed(bytes(layer), 6) + payload
    raw = internet_checksum(
        _pseudo_header(enclosing, IPProtocol.UDP, layer.length) + datagram
    )
    # UDP-only transmit rule: 0 means "no checksum", so a computed
    # 0x0000 is sent as 0xFFFF (RFC 768; mandatory path RFC 8200).
    return raw or 0xFFFF


def compute(
    layer: Protocol,
    *,
    ip: IPv4 | IPv6 | None = None,
    payload: bytes = b"",
) -> int:
    """The correct checksum field value for ``layer``.

    :param layer: The header to checksum. ``IPv4`` covers its own
        header only (options included; ``ip``/``payload`` ignored);
        ``ICMPv4`` covers header plus ``payload`` (no pseudo-header);
        ``GRE`` covers header plus ``payload`` with no pseudo-header
        (RFC 2784 §2.5) and requires the Checksum-Present bit;
        ``TCP``, ``UDP``, and ``ICMPv6`` prepend the pseudo-header
        built from ``ip``; ``SCTP`` is a CRC32c over the whole packet,
        its chunks included, with no pseudo-header (``ip`` ignored),
        returned as the field's big-endian reading of the CRC's
        little-endian wire bytes (RFC 9260 Appendix A); ``PIM`` covers
        the whole message, or only the first 8 bytes of a Register
        (RFC 7761 §4.9.3), behind the IPv6 pseudo-header over IPv6 and
        alone over IPv4 (``payload`` ignored).
    :param ip: The enclosing IP layer, required for TCP/UDP/ICMPv6, and
        for PIM, whose coverage depends on the family.
    :param payload: The bytes following ``layer`` on the wire. A decoded
        ``ICMPv4``/``ICMPv6``/``IGMP``/``PIM`` message, and a decoded
        ``SCTP`` packet, already carries its whole body in
        ``bytes(layer)``, so pass a ``payload`` only for bytes the layer
        object does not itself hold.
    :raises InvalidFieldError: For layers without a checksum field, or
        a missing ``ip`` where the pseudo-header needs one.
    """
    if isinstance(layer, IPv4):
        return internet_checksum(_zeroed(bytes(layer), 10))
    if isinstance(layer, ICMPv4):
        return internet_checksum(_zeroed(bytes(layer), 2) + payload)
    if isinstance(layer, IGMP):
        # Whole message, checksum field (bytes 2-3) zeroed, no
        # pseudo-header; the body is already part of bytes(layer).
        return internet_checksum(_zeroed(bytes(layer), 2))
    if isinstance(layer, GRE):
        return _gre_checksum(layer, payload)
    if isinstance(layer, SCTP):
        return _sctp_checksum(layer, payload)
    if isinstance(layer, PIM):
        return _pim_checksum(layer, ip)
    if isinstance(layer, (ICMPv6, TCP, UDP)):
        return _transport_checksum(layer, ip, payload)
    raise InvalidFieldError(
        f"{type(layer).__name__} has no checksum field to compute",
        protocol=type(layer),
        field="checksum",
    )


def verify(
    layer: Protocol,
    *,
    ip: IPv4 | IPv6 | None = None,
    payload: bytes = b"",
) -> bool:
    """Whether ``layer``'s checksum field matches a recomputation.

    It accepts what the governing RFC tells a receiver to accept, which
    can be more than :func:`compute` produces: a UDP-over-IPv4 checksum
    of ``0``, a GRE header without the C bit, and a PIM Register summed
    over the whole message, each described below.

    A UDP-over-IPv4 checksum of ``0`` means "no checksum in use" and
    verifies as True (over IPv6 the checksum is mandatory and ``0`` is
    invalid). A GRE header whose Checksum-Present bit is clear carries
    no checksum at all (RFC 2784 §2.5) and likewise verifies as True —
    a frame cannot fail a checksum it does not have. A PIM Register
    verifies with its checksum over its first 8 bytes, as RFC 7761
    §4.9.3 computes it, or over the whole message, as it asks a
    receiver to accept too ("for interoperability reasons"). So a
    whole-message Register verifies, but
    :meth:`~netprotocols.Packet.with_checksums` rewrites its checksum to
    the 8-byte form :func:`compute` returns.
    """
    if (
        isinstance(layer, UDP)
        and layer.checksum == 0
        and not isinstance(ip, IPv6)
    ):
        return True
    if isinstance(layer, GRE) and not layer.checksum_present:
        return True
    if isinstance(layer, PIM):
        return _verify_pim(layer, ip)
    wire: int = layer.checksum  # type: ignore[attr-defined]
    return compute(layer, ip=ip, payload=payload) == wire
