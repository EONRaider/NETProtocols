"""Internet checksum computation and verification (RFC 1071).

The primitive, :func:`internet_checksum`, returns the raw ones'-
complement result — ``0x0000`` is a legal return value, and TCP, ICMP,
and the IPv4 header checksum legitimately transmit it. The famous
``0x0000 → 0xFFFF`` substitution is a **UDP-only transmit rule**
(RFC 768; RFC 8200 §8.1) and lives solely in the UDP arm of
:func:`compute`.

Length fields are trusted, not reconciled: UDP uses ``layer.length``
for the pseudo-header, TCP uses ``layer.header_len + len(payload)``,
and nothing checks ``IPv4.total_length`` against the payload you pass.
Feed these helpers the payload exactly as it appears on the wire.
"""

from __future__ import annotations

import struct

from netprotocols._base import (
    Protocol,
    ipv4_to_bytes,
    ipv6_to_bytes,
)
from netprotocols._enums import IPProtocol
from netprotocols.layer3.icmp import ICMPv4, ICMPv6
from netprotocols.layer3.ip import IPv4, IPv6
from netprotocols.layer4.tcp import TCP
from netprotocols.layer4.udp import UDP
from netprotocols.utils.exceptions import InvalidFieldError

__all__ = ["compute", "internet_checksum", "verify"]


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
            f"addresses)"
        )
    return ip


def _zeroed(layer_bytes: bytes, checksum_offset: int) -> bytes:
    return (
        layer_bytes[:checksum_offset]
        + b"\x00\x00"
        + layer_bytes[checksum_offset + 2 :]
    )


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
        ``TCP``, ``UDP``, and ``ICMPv6`` prepend the pseudo-header
        built from ``ip``.
    :param ip: The enclosing IP layer, required for TCP/UDP/ICMPv6.
    :param payload: The bytes following ``layer`` on the wire.
    :raises InvalidFieldError: For layers without a checksum field, or
        a missing ``ip`` where the pseudo-header needs one.
    """
    if isinstance(layer, IPv4):
        return internet_checksum(_zeroed(bytes(layer), 10))
    if isinstance(layer, ICMPv4):
        return internet_checksum(_zeroed(bytes(layer), 2) + payload)
    if isinstance(layer, ICMPv6):
        enclosing = _require_ip(layer, ip)
        segment = _zeroed(bytes(layer), 2) + payload
        return internet_checksum(
            _pseudo_header(enclosing, IPProtocol.IPV6_ICMP, len(segment))
            + segment
        )
    if isinstance(layer, TCP):
        enclosing = _require_ip(layer, ip)
        segment = _zeroed(bytes(layer), 16) + payload
        return internet_checksum(
            _pseudo_header(enclosing, IPProtocol.TCP, len(segment)) + segment
        )
    if isinstance(layer, UDP):
        enclosing = _require_ip(layer, ip)
        datagram = _zeroed(bytes(layer), 6) + payload
        raw = internet_checksum(
            _pseudo_header(enclosing, IPProtocol.UDP, layer.length) + datagram
        )
        # UDP-only transmit rule: 0 means "no checksum", so a computed
        # 0x0000 is sent as 0xFFFF (RFC 768; mandatory path RFC 8200).
        return raw or 0xFFFF
    raise InvalidFieldError(
        f"{type(layer).__name__} has no checksum field to compute"
    )


def verify(
    layer: Protocol,
    *,
    ip: IPv4 | IPv6 | None = None,
    payload: bytes = b"",
) -> bool:
    """Whether ``layer``'s checksum field matches a recomputation.

    A UDP-over-IPv4 checksum of ``0`` means "no checksum in use" and
    verifies as True (over IPv6 the checksum is mandatory and ``0`` is
    invalid).
    """
    if (
        isinstance(layer, UDP)
        and layer.checksum == 0
        and not isinstance(ip, IPv6)
    ):
        return True
    wire: int = layer.checksum  # type: ignore[attr-defined]
    return compute(layer, ip=ip, payload=payload) == wire
