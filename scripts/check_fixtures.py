#!/usr/bin/env python3
"""Validate the internal checksum consistency of captured fixture pcaps.

Standalone (stdlib only, its own RFC 1071, CRC32c, CRC-32 and Fletcher
implementations, its own minimal parsers, no import of netprotocols), so
it disqualifies a capture even when netprotocols itself has a bug, and
the tests cross-validate the library's checksum module against it.

Usage: python3 scripts/check_fixtures.py tests/fixtures/staging
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import struct
import sys
from collections import Counter
from collections.abc import Iterator
from contextvars import ContextVar
from pathlib import Path


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total: int = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


#: CRC32c's Castagnoli polynomial, bit-reflected (RFC 9260 Appendix A).
_CRC32C_POLY = 0x82F63B78


def crc32c(data: bytes) -> int:
    """SCTP's CRC32c, bit by bit: slow, and independent of the library's
    table-driven loop."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (_CRC32C_POLY if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


#: The IEEE 802.3 CRC-32 polynomial, bit-reflected: STUN's FINGERPRINT
#: CRC (RFC 8489 §14.7 cites ITU V.42, which uses the same one).
_CRC32_POLY = 0xEDB88320


def crc32(data: bytes) -> int:
    """The IEEE CRC-32, bit by bit: slow, and independent of the
    standard library's ``binascii.crc32``, which the library uses."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (_CRC32_POLY if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def fletcher_verifies(data: bytes, offset: int) -> bool:
    """Check ``data`` against the ISO 8473 Fletcher checksum it carries.

    The checksum is the two bytes at ``offset``. With it in place, both
    running sums must be ``0`` modulo 255 (RFC 905 Annex B.4), and the
    field must not be ``0x0000``: RFC 2328 §12.1.7 forbids a zero LS
    Checksum and counts one as a failure, though B.4's sums can come
    out zero over it. The library's ``verify_lsa`` makes the same
    check; this is its own implementation, sharing no code with it.
    """
    if data[offset : offset + 2] == b"\x00\x00":
        return False
    c0 = c1 = 0
    for byte in data:
        c0 = (c0 + byte) % 255
        c1 = (c1 + c0) % 255
    return c0 == 0 and c1 == 0


def read_pcap(path: Path) -> Iterator[bytes]:
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("not a pcap: too short")
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        raise ValueError(f"not a pcap: magic {magic.hex()}")
    (network,) = struct.unpack_from(f"{endian}I", data, 20)
    if network != 1:
        raise ValueError(f"linktype {network} is not Ethernet")
    cursor = 24
    while cursor + 16 <= len(data):
        _, _, incl_len, _ = struct.unpack_from(f"{endian}IIII", data, cursor)
        cursor += 16
        yield data[cursor : cursor + incl_len]
        cursor += incl_len


def pseudo_v4(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return src + dst + struct.pack("!BBH", 0, proto, length)


def pseudo_v6(src: bytes, dst: bytes, proto: int, length: int) -> bytes:
    return src + dst + struct.pack("!IBBBB", length, 0, 0, 0, proto)


def _check_icmpv4(upper: bytes, stats: Counter[str]) -> list[str]:
    stats["icmpv4"] += 1
    if (
        internet_checksum(upper[:2] + b"\x00\x00" + upper[4:])
        != struct.unpack_from("!H", upper, 2)[0]
    ):
        return ["icmpv4-checksum"]
    return []


def _check_igmp(upper: bytes, stats: Counter[str]) -> list[str]:
    stats["igmp"] += 1
    # IGMP: whole message, checksum at bytes 2-3, no pseudo-header.
    if (
        internet_checksum(upper[:2] + b"\x00\x00" + upper[4:])
        != struct.unpack_from("!H", upper, 2)[0]
    ):
        return ["igmp-checksum"]
    return []


#: The corpus's OSPF test secrets, published in tests/fixtures/MANIFEST.md:
#: the AuType 1 password, NUL-padded to the 8-byte field, and the AuType
#: 2 keyed-MD5 keys by Key ID.
_OSPF_SIMPLE_PASSWORD = b"NPospf1\x00"
_OSPF_MD5_KEYS = {1: b"NETProtocols-md5"}
_OSPF_MD5_LEN = 16


def _check_ospf(upper: bytes, stats: Counter[str]) -> list[str]:
    # OSPFv2 (RFC 2328 §A.3.1): a 24-byte header whose Packet Length
    # bounds the packet, then (AuType 2) the digest after it.
    stats["ospf"] += 1
    if len(upper) < 24:
        return ["ospf-truncated"]
    version, kind, length = struct.unpack_from("!BBH", upper, 0)
    if version != 2 or not 24 <= length <= len(upper):
        return ["ospf-header"]
    packet = upper[:length]
    failures = _check_ospf_auth(upper, packet, stats)
    if kind == 4:
        failures += _check_ospf_lsas(packet[24:], stats)
    return failures


def _check_ospf_auth(
    upper: bytes, packet: bytes, stats: Counter[str]
) -> list[str]:
    """Check an OSPF packet's checksum, password or digest.

    The packet checksum under AuType 0 and 1 (the internet checksum of
    the packet but its Authentication field, RFC 2328 §D.4.1), the
    published password under AuType 1, or the keyed-MD5 digest under
    AuType 2 (§D.4.3: MD5 over the packet and the key NUL-padded to 16
    bytes; the packet checksum is not computed and must be zero).
    AuType is header byte 15: RFC 6549 §2 defines byte 14 as the
    Instance ID.
    Any other AuType fails as ``ospf-autype-N``, AuType 3 (RFC 7474)
    included: its HMAC-SHA digest needs a key the corpus does not
    publish and an HMAC-SHA check this checker does not have, so it
    cannot be verified, and an unverifiable frame must not pass.
    """
    au_type = packet[15]
    wire = struct.unpack_from("!H", packet, 12)[0]
    authentication = packet[16:24]
    if au_type in (0, 1):
        covered = packet[:12] + b"\x00\x00" + packet[14:16] + packet[24:]
        failures = (
            [] if internet_checksum(covered) == wire else ["ospf-checksum"]
        )
        if au_type == 1:
            stats["ospf-simple-auth"] += 1
            if authentication != _OSPF_SIMPLE_PASSWORD:
                failures.append("ospf-simple-auth-mismatch")
        return failures
    if au_type != 2:
        # Unverifiable here, AuType 3 too: no published key, no HMAC-SHA.
        return [f"ospf-autype-{au_type}"]
    return _check_ospf_md5(upper, packet, wire, stats)


def _check_ospf_md5(
    upper: bytes, packet: bytes, wire: int, stats: Counter[str]
) -> list[str]:
    stats["ospf-md5"] += 1
    authentication = packet[16:24]
    key = _OSPF_MD5_KEYS.get(authentication[2])
    if key is None or authentication[3] != _OSPF_MD5_LEN:
        return ["ospf-unknown-key"]
    digest = upper[len(packet) : len(packet) + _OSPF_MD5_LEN]
    # RFC 2328 Appendix D mandates MD5; this only verifies the router's digest.
    expected = hashlib.md5(
        packet + key.ljust(16, b"\x00"), usedforsecurity=False
    ).digest()
    failures = [] if wire == 0 else ["ospf-checksum"]
    if not hmac.compare_digest(digest, expected):
        failures.append("ospf-md5-digest")
    return failures


def _check_ospf_lsas(body: bytes, stats: Counter[str]) -> list[str]:
    """Check every LSA's LS Checksum in a Link State Update's body.

    Fletcher over the LSA but its 2-byte LS Age (RFC 2328 §12.1.7).
    Only updates carry whole LSAs; Database Descriptions and
    acknowledgments carry headers alone, which their checksum does not
    cover.
    """
    if len(body) < 4:
        return ["ospf-lsa-length"]
    cursor = 4
    failures: list[str] = []
    for _ in range(struct.unpack_from("!I", body, 0)[0]):
        if len(body) - cursor < 20:
            return [*failures, "ospf-lsa-length"]
        length = struct.unpack_from("!H", body, cursor + 18)[0]
        if length < 20 or cursor + length > len(body):
            return [*failures, "ospf-lsa-length"]
        stats["ospf-lsa"] += 1
        lsa = body[cursor + 2 : cursor + length]
        # LS Checksum: header bytes 16-17, 14-15 once LS Age is cut.
        if not fletcher_verifies(lsa, 14):
            failures.append("ospf-lsa-checksum")
        cursor += length
    return failures


def _check_tcp(
    src: bytes, dst: bytes, upper: bytes, stats: Counter[str]
) -> list[str]:
    stats["tcp"] += 1
    upper_len = len(upper)
    zeroed = upper[:16] + b"\x00\x00" + upper[18:]
    if (
        internet_checksum(pseudo_v4(src, dst, 6, upper_len) + zeroed)
        != struct.unpack_from("!H", upper, 16)[0]
    ):
        return ["tcp-checksum"]
    return _check_tcp_payload(upper, stats)


def _check_udp(
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    stats["udp"] += 1
    upper_len = len(upper)
    wire = struct.unpack_from("!H", upper, 6)[0]
    failures: list[str] = []
    if wire == 0:
        # RFC 768: a zero checksum over IPv4 means none was computed,
        # which is also Linux's default for VXLAN (RFC 7348 §5 allows
        # it). Nothing to verify, but a tunnel inside is still checked.
        stats["udp-no-checksum"] += 1
    else:
        zeroed = upper[:6] + b"\x00\x00" + upper[8:]
        computed = (
            internet_checksum(pseudo_v4(src, dst, 17, upper_len) + zeroed)
            or 0xFFFF
        )
        if computed != wire:
            failures.append("udp-checksum")
    return failures + _check_udp_payload(
        src, dst, upper, stats, depth, strict=strict
    )


def _check_sctp(upper: bytes, stats: Counter[str]) -> list[str]:
    # SCTP: CRC32c over the whole packet with the checksum field (bytes
    # 8-11) zeroed and no pseudo-header, sent least significant byte
    # first (RFC 9260 Appendix A). The packet is the whole IP payload.
    stats["sctp"] += 1
    crc = crc32c(upper[:8] + b"\x00" * 4 + upper[12:])
    if crc.to_bytes(4, "little") != upper[8:12]:
        return ["sctp-checksum"]
    return []


#: VRRP's IP protocol number (RFC 3768 §5.2.4, RFC 5798 §5.1.1.4).
_VRRP = 112


def _check_vrrp(
    src: bytes, dst: bytes, upper: bytes, stats: Counter[str], *, ipv6: bool
) -> list[str] | None:
    """Validate a VRRP advertisement, the whole IP payload ``upper``.

    Returns ``None`` when it is too short for the 8-byte fixed header.

    The checksum covers the VRRP message, checksum field (bytes 6-7)
    zeroed: alone in VRRPv2 (RFC 3768 §5.3.8), behind the IPv6
    pseudo-header with protocol 112 in VRRPv3 over IPv6 (RFC 9568
    §5.2.8). VRRPv3 over IPv4 is accepted in two forms: behind the IPv4
    pseudo-header with protocol 112, keepalived's default, or over the
    message alone, as RFC 9568 §5.2.8 computes it; a frame that matches
    only the second is counted as ``vrrpv3-no-pseudo-header``. The
    message's length follows from its version and address count (RFC
    3768 §5.1: 8 bytes, the addresses, and 8 bytes of authentication
    data; RFC 5798 §5.1: no authentication data), and must be the IP
    payload's exactly. VRRPv2 is defined for IPv4 alone.
    """
    if len(upper) < 8:
        return None
    version, count = upper[0] >> 4, upper[3]
    if version not in ((3,) if ipv6 else (2, 3)):
        return ["vrrp-version"]
    stats[f"vrrpv{version}"] += 1
    width = 16 if ipv6 else 4
    if len(upper) != 8 + count * width + (8 if version == 2 else 0):
        return ["vrrp-length"]
    wire = struct.unpack_from("!H", upper, 6)[0]
    message = upper[:6] + b"\x00\x00" + upper[8:]
    if version == 2:
        return [] if internet_checksum(message) == wire else ["vrrp-checksum"]
    pseudo = pseudo_v6 if ipv6 else pseudo_v4
    if internet_checksum(pseudo(src, dst, _VRRP, len(upper)) + message) == wire:
        return []
    if not ipv6 and internet_checksum(message) == wire:
        stats["vrrpv3-no-pseudo-header"] += 1
        return []
    return ["vrrp-checksum"]


#: The GRE flags word's C, R, K and S bits (RFC 1701, RFC 2784 §2,
#: RFC 2890 §2) and enhanced GRE's A bit (RFC 2637 §4.1).
_GRE_C, _GRE_R, _GRE_K, _GRE_S, _GRE_A = 0x8000, 0x4000, 0x2000, 0x1000, 0x80

#: Version 0's flags bits 8-12, which RFC 1701 and RFC 2784 §2.3 both
#: reserve; bits 1-7, RFC 1701's R, K, S, s and Recursion Control, are
#: read as RFC 1701 defines them.
_GRE_RESERVED_FLAGS = 0x00F8

#: Enhanced GRE's bits that RFC 2637 §4.1 sets to zero: C, R, s,
#: Recursion Control and Flags bits 9-12.
_GRE_V1_ZERO = 0xCF78

#: Enhanced GRE's one Protocol Type, PPP (RFC 2637 §4.1).
_GRE_V1_PPP = 0x880B


def _gre_routing(
    upper: bytes, start: int
) -> tuple[list[int], int, bool] | None:
    """Walk the Source Route Entries of a GRE Routing field from
    ``start`` to the first of them whose SRE Length is ``0``, the last
    (RFC 1701).

    Each SRE is a 2-byte Address Family, a 1-byte SRE Offset and a
    1-byte SRE Length, then that many bytes of Routing Information.
    Returns each SRE's offset from ``start``, the offset in ``upper``
    after the last one, and whether that one is the NULL SRE (Address
    Family ``0`` as well), or ``None`` when an SRE runs past ``upper``
    or the bytes end before the last.
    """
    starts: list[int] = []
    cursor = start
    while cursor + 4 <= len(upper):
        starts.append(cursor - start)
        family, _, length = struct.unpack_from("!HBB", upper, cursor)
        cursor += 4 + length
        if length == 0:
            return starts, cursor, family == 0
    return None


def _check_gre(
    upper: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    """Validate a GRE packet, ``upper``: the IP payload, as far as the
    IPv4 Total Length or the IPv6 Payload Length declares it, after any
    IPv6 extension headers; Ethernet padding is not read.

    A 4-byte header (flags word and Protocol Type) is followed by the
    optional words its flags announce, then the tunnelled packet. The
    Version, the flags word's last 3 bits, selects the layout: ``0``
    for GRE (RFC 1701, RFC 2784, RFC 2890), ``1`` for enhanced GRE
    (see :func:`_check_gre_v1`); any other fails. In version 0, the C
    or R bit announces the Checksum and Offset words, the K bit the
    Key, the S bit the Sequence Number, and the R bit, after them, a
    Routing field: Source Route Entries ending in the NULL SRE (see
    :func:`_gre_routing`), whose last SRE must be the NULL SRE and
    whose Offset must point to the first byte of one of them. The s
    bit and Recursion Control are read and not checked; flags bits
    8-12 must be zero. The tunnelled packet, named by the Protocol
    Type, is validated in turn. With the C bit set, the Checksum must
    be the internet checksum of the GRE header and payload, every byte
    of ``upper``, with the Checksum field zeroed (RFC 2784 §2.5); with
    it clear, no checksum is read. A packet shorter than the header
    its flags announce cannot be checked: it passes unread, or fails
    under ``strict``.
    """
    stats["gre"] += 1
    gre_flags, inner_ethertype = struct.unpack_from("!HH", upper, 0)
    version = gre_flags & 0x7
    if version == 1:
        return _check_gre_v1(upper, gre_flags, stats, strict=strict)
    if version != 0:
        return ["gre-version"]
    end = (
        4
        + (4 if gre_flags & (_GRE_C | _GRE_R) else 0)
        + (4 if gre_flags & _GRE_K else 0)
        + (4 if gre_flags & _GRE_S else 0)
    )
    routing = _gre_routing(upper, end) if gre_flags & _GRE_R else None
    if end > len(upper) or (gre_flags & _GRE_R and routing is None):
        stats["gre-truncated"] += 1
        return ["unchecked-gre-truncated"] if strict else []
    failures: list[str] = []
    if gre_flags & _GRE_RESERVED_FLAGS:
        failures.append("gre-reserved-flags")
    if routing is not None:
        stats["gre-routing"] += 1
        starts, end, terminated = routing
        if not terminated:
            failures.append("gre-routing-null")
            return failures
        if struct.unpack_from("!H", upper, 6)[0] not in starts:
            failures.append("gre-routing-offset")
    if gre_flags & _GRE_C:
        stats["gre-checksum"] += 1
        covered = upper[:4] + b"\x00\x00" + upper[6:]
        if internet_checksum(covered) != struct.unpack_from("!H", upper, 4)[0]:
            failures.append("gre-checksum")
    return failures + _check_l3(
        inner_ethertype, upper[end:], stats, depth + 1, strict=strict
    )


def _check_gre_v1(
    upper: bytes, gre_flags: int, stats: Counter[str], *, strict: bool
) -> list[str]:
    """Validate an enhanced GRE packet (RFC 2637 §4.1), ``upper``, whose
    flags word is ``gre_flags``.

    The K bit must be set and the C, R and s bits, Recursion Control
    and Flags bits 9-12 clear, and the Protocol Type must be PPP's
    ``0x880B``. The Key, always present, holds the Payload Length and
    Call ID; the S bit announces the Sequence Number and the A bit, after
    it, the Acknowledgment Number. The Payload Length must count the
    bytes after the header exactly, and the S bit must be set exactly
    when there are any. The PPP payload is not read: it passes, or
    fails under ``strict``. A packet shorter than the header its flags
    announce cannot be checked: it passes unread, or fails under
    ``strict``.
    """
    stats["gre-v1"] += 1
    if not gre_flags & _GRE_K:
        return ["gre-v1-key"]
    if gre_flags & _GRE_V1_ZERO:
        return ["gre-v1-flags"]
    if struct.unpack_from("!H", upper, 2)[0] != _GRE_V1_PPP:
        return ["gre-v1-protocol"]
    end = (
        8 + (4 if gre_flags & _GRE_S else 0) + (4 if gre_flags & _GRE_A else 0)
    )
    if end > len(upper):
        stats["gre-truncated"] += 1
        return ["unchecked-gre-truncated"] if strict else []
    payload = len(upper) - end
    if struct.unpack_from("!H", upper, 4)[0] != payload:
        return ["gre-v1-payload-length"]
    if bool(gre_flags & _GRE_S) != bool(payload):
        return ["gre-v1-sequence"]
    if not payload:
        return []
    stats["gre-v1-ppp"] += 1
    return ["unchecked-gre-ppp"] if strict else []


def _check_ipv4(
    payload: bytes, stats: Counter[str], depth: int, *, strict: bool = False
) -> list[str]:
    failures: list[str] = []
    ihl = (payload[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(payload):
        # An IHL below 5 (RFC 791) or past the bytes leaves no header to
        # check; reading on would slice empty addresses or crash.
        return ["ipv4-ihl"]
    header = payload[:ihl]
    stats["ipv4"] += 1
    if (
        internet_checksum(header[:10] + b"\x00\x00" + header[12:ihl])
        != struct.unpack_from("!H", header, 10)[0]
    ):
        failures.append("ipv4-header-checksum")
    proto = header[9]
    total_length = struct.unpack_from("!H", header, 2)[0]
    flags_frag = struct.unpack_from("!H", header, 6)[0]
    if flags_frag & 0x1FFF:
        stats["ipv4-fragment"] += 1
        # Non-first fragment: no upper-layer header.
        return failures + (["unchecked-fragment"] if strict else [])
    if flags_frag & 0x2000 == 0x2000 and flags_frag & 0x1FFF == 0:
        stats["ipv4-first-fragment"] += 1
        # First fragment: the upper checksum spans all parts.
        return failures + (["unchecked-fragment"] if strict else [])
    upper = payload[ihl:total_length]
    return failures + _check_upper_v4(
        proto, header, upper, stats, depth, strict=strict
    )


def _check_transport_v4(
    proto: int,
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool,
) -> list[str] | None:
    """Validate a transport carried directly over IPv4 (ICMP, IGMP,
    TCP, UDP, SCTP) or VRRP, or return ``None`` when ``proto`` is none
    of them or ``upper`` is too short for its header, leaving the
    tunnels and the strict fallback to :func:`_check_upper_v4`."""
    upper_len = len(upper)
    if proto == 1 and upper_len >= 8:
        return _check_icmpv4(upper, stats)
    if proto == 2 and upper_len >= 8:
        return _check_igmp(upper, stats)
    if proto == 6 and upper_len >= 20:
        return _check_tcp(src, dst, upper, stats)
    if proto == 17 and upper_len >= 8:
        return _check_udp(src, dst, upper, stats, depth, strict=strict)
    if proto == 132 and upper_len >= 12:
        return _check_sctp(upper, stats)
    if proto == _VRRP:
        return _check_vrrp(src, dst, upper, stats, ipv6=False)
    return None


def _check_upper_v4(
    proto: int,
    ip_header: bytes,
    upper: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    """Validate what the IPv4 header ``ip_header`` carries as protocol
    ``proto`` — directly, or behind IPsec in transport mode, where the
    pseudo-header (and AH's ICV) is still the IPv4 header's.

    ``strict`` is for a payload an IPsec ICV vouched for: one this
    cannot check (an unknown protocol, or too short for its header)
    fails instead of passing unread, since MANIFEST.md promises the
    protected packet's checksums verify.

    ``depth`` counts the encapsulations (GRE, IP-in-IP, IPsec) above
    ``upper``. Every one of them is dispatched from here or from
    :func:`_check_upper_v6` and recurses back through one of the two
    or through :func:`_check_l3`; all three refuse a depth past
    ``_MAX_DEPTH``, so a tunnel chain ending in anything (an IP
    payload, ARP, an unknown EtherType) is bounded."""
    if depth > _MAX_DEPTH:
        return ["nesting-too-deep"]
    src, dst = ip_header[12:16], ip_header[16:20]
    transport = _check_transport_v4(
        proto, src, dst, upper, stats, depth, strict=strict
    )
    if transport is not None:
        return transport
    if proto == 47 and len(upper) >= 4:
        return _check_gre(upper, stats, depth, strict=strict)
    if proto in _IP_IN_IP:
        return _check_ip_in_ip(proto, upper, stats, depth, strict=strict)
    if proto == 50:
        return _check_esp(ip_header, upper, stats, depth, ipv6=False)
    if proto == 51:
        return _check_ah(ip_header, upper, stats, depth)
    routing = _check_routing_v4(proto, src, dst, upper, stats, depth, strict)
    if routing is not None:
        return routing
    return [f"unchecked-protocol-{proto}"] if strict else []


def _check_routing_v4(
    proto: int,
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter[str],
    depth: int,
    strict: bool,
) -> list[str] | None:
    """Validate a PIM or OSPF message carried by IPv4, or return
    ``None`` for any other protocol."""
    if proto == _PIM:
        return _check_pim(
            src, dst, upper, stats, depth, ipv6=False, strict=strict
        )
    if proto == 89:
        return _check_ospf(upper, stats)
    return None


def _check_icmpv6(
    src: bytes, dst: bytes, upper: bytes, stats: Counter[str]
) -> list[str]:
    stats["icmpv6"] += 1
    upper_len = len(upper)
    zeroed = upper[:2] + b"\x00\x00" + upper[4:]
    if (
        internet_checksum(pseudo_v6(src, dst, 58, upper_len) + zeroed)
        != struct.unpack_from("!H", upper, 2)[0]
    ):
        return ["icmpv6-checksum"]
    return []


def _check_tcp6(
    src: bytes, dst: bytes, upper: bytes, stats: Counter[str]
) -> list[str]:
    stats["tcp6"] += 1
    upper_len = len(upper)
    zeroed = upper[:16] + b"\x00\x00" + upper[18:]
    if (
        internet_checksum(pseudo_v6(src, dst, 6, upper_len) + zeroed)
        != struct.unpack_from("!H", upper, 16)[0]
    ):
        return ["tcp6-checksum"]
    return _check_tcp_payload(upper, stats)


def _check_udp6(
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    stats["udp6"] += 1
    upper_len = len(upper)
    zeroed = upper[:6] + b"\x00\x00" + upper[8:]
    computed = (
        internet_checksum(pseudo_v6(src, dst, 17, upper_len) + zeroed) or 0xFFFF
    )
    failures: list[str] = []
    if computed != struct.unpack_from("!H", upper, 6)[0]:
        failures.append("udp6-checksum")
    return failures + _check_udp_payload(
        src, dst, upper, stats, depth, strict=strict
    )


#: PIM's IP protocol number (RFC 7761 §4.9) and its Register type, the
#: one message whose checksum covers only the first 8 bytes (§4.9.3).
_PIM = 103
_PIM_REGISTER = 1


def _pim_sum(src: bytes, dst: bytes, covered: bytes, *, ipv6: bool) -> int:
    # RFC 7761 §4.9: over IPv6 the pseudo-header goes in front, its
    # length the covered length; over IPv4 there is none.
    if ipv6:
        covered = pseudo_v6(src, dst, _PIM, len(covered)) + covered
    return internet_checksum(covered)


def _check_pim(
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter[str],
    depth: int,
    *,
    ipv6: bool,
    strict: bool = False,
) -> list[str]:
    """Validate a PIM message: its checksum over the whole message, or
    over a Register's first 8 bytes. A Register summed over the whole
    message passes too, which RFC 7761 §4.9.3 asks receivers to accept;
    its encapsulated packet is then validated in turn."""
    if len(upper) < 4:
        stats["pim-truncated"] += 1
        return ["unchecked-pim-truncated"] if strict else []
    stats["pim"] += 1
    if upper[0] >> 4 != 2:
        return ["pim-version"]
    wire = struct.unpack_from("!H", upper, 2)[0]
    zeroed = upper[:2] + b"\x00\x00" + upper[4:]
    if upper[0] & 0x0F != _PIM_REGISTER:
        if _pim_sum(src, dst, zeroed, ipv6=ipv6) != wire:
            return ["pim-checksum"]
        return []
    stats["pim-register"] += 1
    if wire not in (
        _pim_sum(src, dst, zeroed[:8], ipv6=ipv6),
        _pim_sum(src, dst, zeroed, ipv6=ipv6),
    ):
        return ["pim-checksum"]
    return _check_pim_register(upper, stats, depth, strict=strict)


def _check_pim_register(
    upper: bytes, stats: Counter[str], depth: int, *, strict: bool
) -> list[str]:
    """Validate the packet a PIM Register encapsulates, from its IP
    header; a Null-Register's dummy header goes to
    :func:`_check_null_register` first."""
    if len(upper) < 8:
        stats["pim-register-truncated"] += 1
        return ["unchecked-pim-register-truncated"] if strict else []
    inner = upper[8:]
    if upper[4] & 0x40:
        null_register = _check_null_register(inner, stats, strict=strict)
        if null_register is not None:
            return null_register
    ethertype = 0x86DD if inner[:1] and inner[0] >> 4 == 6 else 0x0800
    return _check_l3(ethertype, inner, stats, depth + 1, strict=strict)


def _check_null_register(
    inner: bytes, stats: Counter[str], *, strict: bool
) -> list[str] | None:
    """Validate a Null-Register's dummy header, or return ``None``.

    ``None`` means it is an IP packet to check like any other. A dummy
    IPv4 header may carry a zero header checksum, which RFC 7761 §4.9.3
    says a receiver must not check; one that carries a checksum is
    checked like any packet. A dummy IPv6 header is followed by a dummy
    PIM header of version 0, not a PIM message, so it is checked by
    :func:`_check_null_register_v6` instead. The version nibble decides
    which: bytes 10-11 are an IPv6 header's source address.
    """
    version = inner[0] >> 4 if inner else None
    if version == 4 and len(inner) >= 20 and inner[10:12] == b"\x00\x00":
        stats["pim-null-register-unchecked"] += 1
        return []
    if version == 6 and len(inner) >= 40:
        return _check_null_register_v6(inner, stats, strict=strict)
    return None


def _check_null_register_v6(
    inner: bytes, stats: Counter[str], *, strict: bool
) -> list[str]:
    """Validate an IPv6 Null-Register's dummy PIM header (RFC 7761 §4.9.3).

    It is the 4 bytes after the dummy IPv6 header, version, type and
    reserved all zero, whose checksum covers them under the IPv6
    pseudo-header of the dummy header's source and group, upper-layer
    length 4 and next header 103. The RFC asks a receiver to check that
    checksum "if the dummy PIM header is present", and names nothing
    else to check. One that is absent has no checksum to check, like a
    dummy IPv4 header's zero one; one cut short cannot be checked.
    """
    stats["pim-null-register-v6"] += 1
    dummy = inner[40:44]
    if not dummy:
        stats["pim-null-register-unchecked"] += 1
        return []
    if len(dummy) < 4:
        stats["pim-null-register-truncated"] += 1
        return ["unchecked-pim-null-register-truncated"] if strict else []
    pseudo = pseudo_v6(inner[8:24], inner[24:40], _PIM, len(dummy))
    wire = struct.unpack_from("!H", dummy, 2)[0]
    if internet_checksum(pseudo + dummy[:2] + b"\x00\x00") != wire:
        return ["pim-null-register-checksum"]
    return []


#: The IANA-assigned VXLAN destination port (RFC 7348 §5).
_VXLAN_PORT = 4789

#: RIP's port (RFC 2453 §3.9.1 for RIPv2, RFC 1058 §3.1 for RIPv1).
_RIP_PORT = 520

#: RADIUS's authentication and accounting ports (RFC 2865 §3, RFC 2866
#: §3) and Dynamic Authorization's (RFC 5176 §2.3).
_RADIUS_PORTS = (1812, 1813, 3799)

#: STUN's port, over UDP and TCP alike (RFC 8489 §6).
_STUN_PORT = 3478

#: NTP's port (RFC 5905).
_NTP_PORT = 123

#: HSRP's port (RFC 2281 §5.1), HSRPv2's over IPv4 too.
_HSRP_PORT = 1985

#: HSRP for IPv6's port, which carries the HSRPv2 format.
_HSRP_V6_PORT = 2029

#: The ports :func:`_check_udp_payload` dispatches on after RADIUS's: a
#: datagram from or to one of them is not read as RADIUS, whatever its
#: other port, so a reply of one of these protocols sent to a client
#: whose ephemeral port is 1812, 1813 or 3799 is read as that protocol.
_NON_RADIUS_PORTS = frozenset(
    (_STUN_PORT, _NTP_PORT, _HSRP_PORT, _HSRP_V6_PORT)
)


def _check_udp_payload(
    src: bytes,
    dst: bytes,
    datagram: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    """Validate what a UDP datagram from ``src`` to ``dst`` carries,
    where it is something this checker can verify past the UDP
    checksum: a VXLAN tunnel (see :func:`_check_vxlan`), a RIPv2
    message's keyed digest (see :func:`_check_rip`), a RADIUS packet's
    keyed authenticators (see :func:`_check_radius`), a STUN message's
    FINGERPRINT and MESSAGE-INTEGRITY (see :func:`_check_stun`), an NTP
    message's MAC (see :func:`_check_ntp`) or an HSRP message's fields
    (see :func:`_check_hsrp` and, for an HSRPv2 message, which opens
    with the byte 1 on port 1985 and is any message on port 2029,
    :func:`_check_hsrpv2`). A datagram is RADIUS when its server's port
    (see :func:`_radius_server_port`) is a RADIUS port and neither port
    is a STUN, NTP or HSRP one (see :data:`_NON_RADIUS_PORTS`)."""
    src_port, dst_port = struct.unpack_from("!HH", datagram)
    if dst_port == _VXLAN_PORT:
        return _check_vxlan(datagram, stats, depth, strict=strict)
    if _RIP_PORT in (src_port, dst_port):
        return _check_rip(datagram, stats)
    other = _NON_RADIUS_PORTS.intersection((src_port, dst_port))
    if _radius_server_port(datagram) in _RADIUS_PORTS and not other:
        return _check_radius(src, dst, datagram, stats, strict=strict)
    if _STUN_PORT in (src_port, dst_port):
        end = struct.unpack_from("!H", datagram, 4)[0]
        return _check_stun(datagram[8:end], stats, stream=False)
    if _NTP_PORT in (src_port, dst_port):
        return _check_ntp(datagram, stats)
    if _HSRP_V6_PORT in (src_port, dst_port):
        return _check_hsrpv2(src, datagram, stats)
    if _HSRP_PORT in (src_port, dst_port):
        end = struct.unpack_from("!H", datagram, 4)[0]
        if datagram[8:end][:1] == b"\x01":
            return _check_hsrpv2(src, datagram, stats)
        return _check_hsrp(datagram, stats)
    return []


def _radius_server_port(datagram: bytes) -> int:
    """The port of the RADIUS server that ``datagram``, a UDP datagram,
    would be sent from or to: its source port when its first payload
    byte is a reply's Code (see :data:`_RADIUS_ANSWERS`), and its
    destination port otherwise, as for a request or a payload too short
    to hold a Code."""
    src_port, dst_port, end = struct.unpack_from("!HHH", datagram)
    code = datagram[8:end][:1]
    if code and code[0] in _RADIUS_ANSWERS:
        return int(src_port)
    return int(dst_port)


def _check_tcp_payload(segment: bytes, stats: Counter[str]) -> list[str]:
    """Validate what a TCP segment carries past the TCP checksum: STUN
    messages on port 3478 (see :func:`_check_stun`) and TLS records on
    port 443 (see :func:`_check_tls`), the only TCP payloads this
    checker reads."""
    ports = struct.unpack_from("!HH", segment)
    payload = segment[(segment[12] >> 4) * 4 :]
    if _STUN_PORT in ports:
        return _check_stun(payload, stats, stream=True)
    if _TLS_PORT in ports and payload:
        return _check_tls(payload, stats)
    return []


#: HTTPS's port, where the corpus carries TLS (RFC 9846, RFC 5246).
_TLS_PORT = 443

#: TLS ContentTypes (RFC 9846 §5.1; heartbeat, RFC 6520), by the
#: counter name of each.
_TLS_CONTENT_TYPES = {
    20: "change-cipher-spec",
    21: "alert",
    22: "handshake",
    23: "application-data",
    24: "heartbeat",
}

#: The largest record length any TLS version allows (RFC 5246 §6.2.3).
_TLS_MAX_LENGTH = 2**14 + 2048


def _tls_record_header_ok(data: bytes) -> bool:
    """Whether ``data`` begins with a plausible TLS record header: a
    ContentType of 20-24 and a version of 0x0300-0x0304."""
    return (
        len(data) >= 5
        and data[0] in _TLS_CONTENT_TYPES
        and data[1] == 3
        and data[2] <= 4
    )


def _check_tls(data: bytes, stats: Counter[str]) -> list[str]:
    """Validate the TLS records in a TCP segment on port 443.

    TLS has no checksum of its own, and TCP's covers every byte, so
    this checks the records' framing and what can be read in the clear:
    each record's length is at most 2**14 + 2048 (``tls-length``); a
    Handshake, Alert or ChangeCipherSpec record is not empty
    (``tls-empty``, RFC 9846 §5.1, RFC 5246 §6.2.1); a ChangeCipherSpec
    record is the single byte 1 (``tls-ccs``, RFC 5246 §7.1, RFC 9846
    §5); and a ClientHello, a Handshake record starting with type 1,
    is whole in its record and its fields, session ID (at most 32
    bytes), cipher suites, compression methods and extensions, tile it
    (``tls-hello``), with a server_name extension, if any, holding one
    well-formed host_name: printable ASCII, not an IP address, no
    trailing dot (``tls-sni``, RFC 6066 §3). Over TCP a segment can
    begin or end inside a record, which only reassembly could check:
    such a segment is counted ``tls-unchecked`` here and not failed,
    and :func:`check_capture_frame` fails it (``tls-split``) unless it
    comes from a session capture. The corpus has none;
    tests/fixtures/tls/tls_session.pcap has Chromium's two-segment
    ClientHellos.

    A Handshake record after a ChangeCipherSpec in the same segment is
    not read as a ClientHello: under TLS 1.2 every record after it is
    protected under the new cipher spec (RFC 5246 §7.1), so the
    Finished that follows, still Handshake on the wire, is ciphertext,
    and one in 256 starts with the byte 1 (TLS 1.3 sends its encrypted
    handshake as application_data, RFC 9846 §5.2). The check is per
    segment and keeps no state, so a Finished carried alone in a later
    segment than its ChangeCipherSpec is read as a ClientHello and, if
    its ciphertext starts with 1, almost always fails ``tls-hello``: a
    false failure, never a false pass. No capture here has one: in
    tls.pcap (frames 10 and 11) and tls_session.pcap (99 and 100) the
    TLS 1.2 client's and server's Finished each share a segment with
    their ChangeCipherSpec, and scripts/capture_fixtures_tls.sh, which
    runs this checker on each capture, exits before it unless they
    do. Under TLS 1.3's middlebox compatibility mode a client's dummy
    ChangeCipherSpec may instead come before its second ClientHello,
    after a HelloRetryRequest (RFC 9846 §E.4), so a segment holding
    both leaves that plaintext ClientHello unchecked: a skipped check,
    a possible false pass, never a false failure. Neither capture has
    a HelloRetryRequest or another Handshake record after a
    ChangeCipherSpec, and the script pins each scenario's frame count
    and its corpus frames' content types, so none could enter
    unnoticed."""
    after_ccs = False
    while data:
        if not _tls_record_header_ok(data):
            stats["tls-unchecked"] += 1
            return []
        kind, length = data[0], struct.unpack_from("!H", data, 3)[0]
        if length > _TLS_MAX_LENGTH:
            return ["tls-length"]
        if 5 + length > len(data):
            stats["tls-unchecked"] += 1
            return []
        fragment, data = data[5 : 5 + length], data[5 + length :]
        stats["tls"] += 1
        stats[f"tls-{_TLS_CONTENT_TYPES[kind]}"] += 1
        if kind in (20, 21, 22) and not fragment:
            return ["tls-empty"]
        if kind == 20 and fragment != b"\x01":
            return ["tls-ccs"]
        if kind == 22 and fragment[0] == 1 and not after_ccs:
            stats["tls-client-hello"] += 1
            failure = _check_tls_client_hello(fragment, stats)
            if failure:
                return [failure]
        after_ccs = after_ccs or kind == 20
    return []


def _tls_vector(data: bytes, at: int, width: int) -> tuple[bytes, int] | None:
    """The ``width``-byte length-prefixed vector at ``at`` in ``data``,
    and where it ends; ``None`` if it runs past ``data``."""
    end = at + width + int.from_bytes(data[at : at + width], "big")
    if at + width > len(data) or end > len(data):
        return None
    return data[at + width : end], end


def _check_tls_client_hello(fragment: bytes, stats: Counter[str]) -> str | None:
    """Check a ClientHello's framing and its server_name (RFC 9846
    §4.2.2, RFC 5246 §7.4.1.2, RFC 6066 §3); the failure, or ``None``."""
    length = int.from_bytes(fragment[1:4], "big")
    if len(fragment) < 4 or 4 + length > len(fragment):
        return "tls-hello"
    body = fragment[4 : 4 + length]
    session_id = _tls_vector(body, 34, 1)
    if session_id is None or len(session_id[0]) > 32:
        return "tls-hello"
    suites = _tls_vector(body, session_id[1], 2)
    methods = None if suites is None else _tls_vector(body, suites[1], 1)
    if methods is None:
        return "tls-hello"
    if methods[1] == len(body):
        return None  # no extensions block (RFC 5246 §7.4.1.2)
    block = _tls_vector(body, methods[1], 2)
    if block is None or block[1] != len(body):
        return "tls-hello"
    extensions, cursor = block[0], 0
    while cursor < len(extensions):
        found = _tls_vector(extensions, cursor + 2, 2)
        if cursor + 4 > len(extensions) or found is None:
            return "tls-hello"
        if extensions[cursor : cursor + 2] == b"\x00\x00":
            stats["tls-server-name"] += 1
            if not _tls_host_name_ok(found[0]):
                return "tls-sni"
        cursor = found[1]
    return None


def _tls_host_name_ok(data: bytes) -> bool:
    """Whether a server_name extension's data is a ServerNameList of one
    host_name that RFC 6066 §3 allows: printable ASCII, no trailing dot,
    and not a literal IPv4 or IPv6 address."""
    names = _tls_vector(data, 0, 2)
    if names is None or names[1] != len(data) or names[0][:1] != b"\x00":
        return False
    host = _tls_vector(names[0], 1, 2)
    if host is None or host[1] != len(names[0]) or not host[0]:
        return False
    name = host[0]
    if not all(0x21 <= byte < 0x7F for byte in name) or name.endswith(b"."):
        return False
    try:
        ipaddress.ip_address(name.decode("ascii"))
    except ValueError:
        return True
    return False


#: The Magic Cookie that starts bytes 4-7 of every STUN message since
#: RFC 5389 (RFC 8489 §5); an RFC 3489 message has none.
_STUN_COOKIE = bytes.fromhex("2112a442")

#: The corpus's STUN long-term credential (RFC 8489 §9.2), published in
#: tests/fixtures/MANIFEST.md: coturn was configured with it.
_STUN_USERNAME = b"npstun"
_STUN_REALM = b"np194.test"
_STUN_PASSWORD = b"np194-pass"

_STUN_MESSAGE_INTEGRITY = 0x0008
_STUN_USERNAME_ATTRIBUTE = 0x0006
_STUN_INTEGRITY_SHA256 = 0x001C
_STUN_FINGERPRINT = 0x8028


def _check_stun(data: bytes, stats: Counter[str], *, stream: bool) -> list[str]:
    """Verify every STUN message in ``data``, back to back.

    Over UDP ``data`` is one datagram's payload, which must be exactly
    one message; over TCP (``stream``) a segment's, which can hold
    several (RFC 8489 §6.2.2). A Message Length that is not a multiple
    of 4, a type whose top two bits are set, or a datagram the message
    does not fill exactly fails; what cannot be checked at all is left
    (see :func:`_stun_message_end`)."""
    failures: list[str] = []
    while data:
        end = _stun_message_end(data, stats, stream=stream)
        if end is None:
            return failures
        if end % 4 or data[0] >> 6 or (not stream and end != len(data)):
            return [*failures, "stun-header"]
        failures += _check_stun_message(data[:end], stats)
        data = data[end:]
    return failures


def _stun_message_end(
    data: bytes, stats: Counter[str], *, stream: bool
) -> int | None:
    """Where the STUN message at the start of ``data`` ends, by its
    Message Length; ``None``, counted, for one this checker cannot read.

    That is a message without the Magic Cookie, RFC 3489's, with nothing
    to verify, or over TCP also the middle of a message an earlier
    segment began; and over TCP a message longer than the segment."""
    if len(data) < 20 or data[4:8] != _STUN_COOKIE:
        stats["stun-unchecked" if stream else "stun-rfc3489"] += 1
        return None
    end: int = 20 + struct.unpack_from("!H", data, 2)[0]
    if end > len(data) and stream:
        stats["stun-unchecked"] += 1
        return None
    return end


def _stun_attributes(message: bytes) -> list[tuple[int, int, bytes]] | None:
    """Walk a STUN message's attributes into (type, offset, value),
    each value padded to 4 bytes (RFC 8489 §14); ``None`` if one runs
    past the message."""
    attributes, cursor = [], 20
    while cursor < len(message):
        if cursor + 4 > len(message):
            return None
        kind, length = struct.unpack_from("!HH", message, cursor)
        if cursor + 4 + length > len(message):
            return None
        attributes.append(
            (kind, cursor, message[cursor + 4 : cursor + 4 + length])
        )
        cursor += 4 + length + (-length % 4)
    return attributes


def _check_stun_message(message: bytes, stats: Counter[str]) -> list[str]:
    """Verify one STUN message's attributes (see
    :func:`_check_stun_attribute`)."""
    stats["stun"] += 1
    attributes = _stun_attributes(message)
    if attributes is None:
        return ["stun-attributes"]
    failures: list[str] = []
    for index, attribute in enumerate(attributes):
        last = index == len(attributes) - 1
        failures += _check_stun_attribute(message, attribute, last, stats)
    return failures


def _check_stun_attribute(
    message: bytes,
    attribute: tuple[int, int, bytes],
    last: bool,
    stats: Counter[str],
) -> list[str]:
    """Verify a FINGERPRINT or a MESSAGE-INTEGRITY in ``message``.

    FINGERPRINT must be the ``last`` attribute and equal the CRC-32 of
    the message before it, XOR 0x5354554E (RFC 8489 §14.7).
    MESSAGE-INTEGRITY is verified with the published long-term
    credential (see :func:`_stun_integrity_verifies`); a USERNAME other
    than the published one, or a MESSAGE-INTEGRITY-SHA256, which this
    checker does not compute, fails, as an unpublished IPsec SPI does.
    """
    kind, offset, value = attribute
    if kind == _STUN_USERNAME_ATTRIBUTE and value != _STUN_USERNAME:
        return ["stun-unknown-user"]
    if kind == _STUN_INTEGRITY_SHA256:
        return ["stun-integrity-sha256"]
    if kind == _STUN_MESSAGE_INTEGRITY:
        stats["stun-message-integrity"] += 1
        if not _stun_integrity_verifies(message, offset, value):
            return ["stun-message-integrity"]
    if kind == _STUN_FINGERPRINT:
        stats["stun-fingerprint"] += 1
        want = crc32(message[:offset]) ^ 0x5354554E
        if not last or value != want.to_bytes(4, "big"):
            return ["stun-fingerprint"]
    return []


def _stun_integrity_verifies(message: bytes, offset: int, mac: bytes) -> bool:
    """Check a MESSAGE-INTEGRITY at ``offset``: HMAC-SHA1 over the
    message before it, with the header's Length counting up to the end
    of the attribute (RFC 8489 §14.5, RFC 5389 §15.4), keyed by the
    long-term key MD5(username ":" realm ":" password) (RFC 8489
    §9.2.2, RFC 5389 §15.4)."""
    # MD5 is what RFC 8489 §9.2.2 mandates for the long-term key; this
    # only rebuilds coturn's key from the published test credential.
    key = hashlib.md5(
        b":".join([_STUN_USERNAME, _STUN_REALM, _STUN_PASSWORD]),
        usedforsecurity=False,
    ).digest()
    covered = (
        message[:2] + struct.pack("!H", offset + 24 - 20) + message[4:offset]
    )
    want = hmac.new(key, covered, hashlib.sha1).digest()
    return hmac.compare_digest(want, mac)


def _check_vxlan(
    datagram: bytes, stats: Counter[str], depth: int, *, strict: bool = False
) -> list[str]:
    """Validate a VXLAN payload (destination port 4789, RFC 7348 §5):
    an 8-byte header and then a whole Ethernet frame, validated in
    turn.

    The destination port alone decides which datagrams are peeled,
    which is stricter than the library's port selection (it falls back
    to the source port when the destination is not registered). The
    checker does not apply the decoder's I-flag rule: it validates
    checksums, not VXLAN semantics. An encapsulating endpoint sends to
    the tunnel's port, 4789 in every capture here, from a source port
    hashed from the inner flow, so every tunnel datagram matches by its
    destination alone."""
    if len(datagram) < 8 + 8:
        stats["vxlan-truncated"] += 1
        return ["vxlan-truncated"] if strict else []
    stats["vxlan"] += 1
    return _check_ethernet(datagram[16:], stats, depth + 1, strict=strict)


#: The keys of the corpus's RIPv2 cryptographic authentication (RFC
#: 4822), by Key ID: the test passwords published in
#: tests/fixtures/MANIFEST.md, as BIRD was configured with them.
_RIP_SAS = {
    1: ("keyed-md5", b"nprip-md5-key"),
    2: ("hmac-sha256", b"nprip-sha256-key"),
}

#: RFC 4822 §2.5's Apad, the fill the Authentication Data holds while
#: an HMAC-SHA digest is computed.
_RIP_APAD = bytes.fromhex("878fe1f3")


def _rip_digest(algorithm: str, key: bytes, covered: bytes) -> bytes:
    """The Authentication Data of a RIPv2 message whose bytes up to and
    including the trailer's 4-byte header are ``covered``: keyed MD5
    over them and the key zero-padded to 16 bytes (RFC 4822 §2.4), or
    HMAC-SHA-256 over them and Apad (§2.5). The published key is shorter
    than L (32 bytes), so §2.5's Ko, the key zero-padded to L, gives the
    same pads as standard HMAC's padding to B; they differ only for a
    key longer than L and no longer than B, which §2.5 hashes."""
    if algorithm == "keyed-md5":
        # MD5 is the algorithm RFC 4822 §2.4 mandates; this only checks
        # the digest the router sent, so it is not a security use.
        return hashlib.md5(
            covered + key.ljust(16, b"\x00"), usedforsecurity=False
        ).digest()
    return hmac.new(key, covered + _RIP_APAD * 8, hashlib.sha256).digest()


def _check_rip(datagram: bytes, stats: Counter[str]) -> list[str]:
    """Verify a RIPv2 message's RFC 4822 digest, if it carries one.

    The UDP checksum already covers every RIP byte; this checks the
    digest on top of it. A message is cryptographically authenticated
    when its first entry has AFI 0xFFFF and Authentication Type 3; its
    RIPv2 Packet Length field is then the offset of the trailer, which
    is the 4 bytes 0xFFFF 0x0001 and the digest, to the datagram's end.
    Any other message (RIPv1, no authentication, a plain-text password)
    has nothing to verify. A Key ID with no published key is a failure,
    as an unknown IPsec SPI is (see :func:`_verify_icv`)."""
    rip = datagram[8 : struct.unpack_from("!H", datagram, 4)[0]]
    stats["rip"] += 1
    if len(rip) < 24 or rip[4:8] != b"\xff\xff\x00\x03":
        return []
    sa = _RIP_SAS.get(rip[10])
    if sa is None:
        return ["rip-unknown-sa"]
    trailer = struct.unpack_from("!H", rip, 8)[0]
    if rip[trailer : trailer + 4] != b"\xff\xff\x00\x01":
        return ["rip-trailer"]
    algorithm, key = sa
    stats[f"rip-{algorithm}"] += 1
    digest = _rip_digest(algorithm, key, rip[: trailer + 4])
    if not hmac.compare_digest(digest, rip[trailer + 4 :]):
        return [f"rip-{algorithm}"]
    return []


#: The shared secret between the corpus's RADIUS client and server: the
#: test secret published in tests/fixtures/MANIFEST.md, as FreeRADIUS
#: and radclient were configured with it.
_RADIUS_SECRET = b"np193-radius-secret"

#: RADIUS codes whose Authenticator is random, so that a
#: Message-Authenticator in them is computed over it as sent:
#: Access-Request (RFC 3579 §3.2) and Status-Server (RFC 5997 §3).
_RADIUS_RANDOM_AUTHENTICATOR = (1, 12)

#: RADIUS request codes whose Request Authenticator is MD5 over the
#: packet with a zero Authenticator and then the secret, each mapped to
#: the name its check is counted and reported under:
#: Accounting-Request (RFC 2866 §3), and Disconnect-Request and
#: CoA-Request, whose Request Authenticator is computed as an
#: Accounting-Request's (RFC 5176 §2.3).
_RADIUS_HASHED_AUTHENTICATOR = {4: "accounting", 40: "disconnect", 43: "coa"}

#: RADIUS codes whose Message-Authenticator is computed with the
#: Authenticator field zeroed, before the Request Authenticator, which
#: then covers it: Disconnect-Request and CoA-Request (RFC 5176 §3.4).
_RADIUS_ZEROED_AUTHENTICATOR = (40, 43)
_RADIUS_MESSAGE_AUTHENTICATOR = 80

#: RADIUS request codes: Access-Request (RFC 2865 §3),
#: Accounting-Request (RFC 2866 §3), Status-Server (RFC 5997 §3),
#: Disconnect-Request and CoA-Request (RFC 5176 §2.3).
_RADIUS_REQUESTS = (1, 4, 12, 40, 43)

#: RADIUS reply codes, whose Response Authenticator and
#: Message-Authenticator are computed over their request's
#: Authenticator, each mapped to the request codes it answers:
#: Access-Accept, Access-Reject and Access-Challenge an Access-Request
#: (RFC 2865 §3), Accounting-Response an Accounting-Request (RFC 2866
#: §3), Disconnect-ACK and Disconnect-NAK a Disconnect-Request, CoA-ACK
#: and CoA-NAK a CoA-Request (RFC 5176 §2.3), and Access-Accept,
#: Access-Reject and Accounting-Response a Status-Server, which RFC 5997
#: §2 says a server answers with Access-Accept on an authentication port
#: or Accounting-Response on an accounting port and MAY answer with
#: Access-Reject; it does not recommend Access-Challenge, which is not
#: mapped to Status-Server.
_RADIUS_ANSWERS = {
    2: (1, 12),
    3: (1, 12),
    5: (4, 12),
    11: (1,),
    41: (40,),
    42: (40,),
    44: (43,),
    45: (43,),
}

#: A RADIUS exchange: the client's address and port, the server's
#: address and port, and the Identifier (RFC 2865 §3).
RadiusExchange = tuple[bytes, int, bytes, int, int]


class RadiusExchanges:
    """The Codes and Authenticators of one capture's RADIUS requests
    that no reply has answered yet, by exchange (see
    :data:`RadiusExchange`), in capture order."""

    def __init__(self) -> None:
        self._pending: dict[RadiusExchange, list[tuple[int, bytes]]] = {}

    def ask(
        self, exchange: RadiusExchange, code: int, authenticator: bytes
    ) -> None:
        """Record a request of ``exchange`` and ``code`` as
        unanswered."""
        self._pending.setdefault(exchange, []).append((code, authenticator))

    def answer(
        self, exchange: RadiusExchange, codes: tuple[int, ...]
    ) -> bytes | None:
        """Remove and return the Authenticator of the most recent
        unanswered request of ``exchange`` whose Code is in ``codes``,
        or ``None`` when there is none."""
        pending = self._pending.get(exchange, [])
        for index in range(len(pending) - 1, -1, -1):
            if pending[index][0] in codes:
                return pending.pop(index)[1]
        return None

    def waiting(self, exchange: RadiusExchange) -> bool:
        """Whether a request of ``exchange`` is unanswered."""
        return bool(self._pending.get(exchange))


#: The :class:`RadiusExchanges` of the capture whose frame
#: :func:`check_frame` is checking, set for that call alone; ``None``
#: when it was given none, so that no request is recorded and every
#: reply is unpaired.
_RADIUS_EXCHANGES: ContextVar[RadiusExchanges | None] = ContextVar(
    "radius_exchanges", default=None
)


def _radius_attributes(radius: bytes) -> list[tuple[int, int]] | None:
    """The (type, offset) of each attribute of a RADIUS packet, or
    ``None`` when they do not tile the packet exactly: a Length below 2
    or one that runs past the packet's end (RFC 2865 §5)."""
    found, offset = [], 20
    while offset + 2 <= len(radius):
        length = radius[offset + 1]
        if length < 2:
            return None
        found.append((radius[offset], offset))
        offset += length
    return found if offset == len(radius) else None


def _check_radius(
    src: bytes,
    dst: bytes,
    datagram: bytes,
    stats: Counter[str],
    *,
    strict: bool = False,
) -> list[str]:
    """Verify a RADIUS packet sent from ``src`` to ``dst``.

    The UDP checksum already covers every RADIUS byte. On top of it,
    the Length must fit the datagram and the attributes tile the packet,
    and, with the published secret: the Request Authenticator of an
    Accounting-Request, a Disconnect-Request or a CoA-Request, MD5 over
    the packet with a zero Authenticator and then the secret (RFC 2866
    §3, RFC 5176 §2.3), counted and reported under that request's name
    (see :data:`_RADIUS_HASHED_AUTHENTICATOR`); the Message-Authenticator
    of an Access-Request or a Status-Server, HMAC-MD5 under the secret
    over the packet with that attribute's value zeroed (RFC 3579 §3.2),
    and of a Disconnect-Request or a CoA-Request, the same over the
    packet with its Authenticator zeroed as well (RFC 5176 §3.4), each
    of a request's two reported on its own; and a reply's
    authenticators, against the request it answers (see
    :func:`_check_radius_reply`). Each request is recorded in the
    capture's :class:`RadiusExchanges` under its exchange (see
    :data:`RadiusExchange`), from which a reply takes the most recent
    unanswered request of the same exchange whose Code it answers (see
    :data:`_RADIUS_ANSWERS`). A reply whose exchange has unanswered
    requests of none of those Codes is counted
    ``radius-reply-code-mismatch`` and not checked, and fails under
    ``strict``. Bytes after the Length are padding (RFC 2865 §3) and are
    not checked."""
    radius = datagram[8 : struct.unpack_from("!H", datagram, 4)[0]]
    stats["radius"] += 1
    if len(radius) < 20:
        return ["radius-truncated"]
    length = struct.unpack_from("!H", radius, 2)[0]
    if not 20 <= length <= len(radius):
        return ["radius-length"]
    radius = radius[:length]
    attributes = _radius_attributes(radius)
    if attributes is None:
        return ["radius-attributes"]
    code, identifier = radius[0], radius[1]
    src_port, dst_port = struct.unpack_from("!HH", datagram)
    exchanges = _RADIUS_EXCHANGES.get()
    if code in _RADIUS_ANSWERS:
        request = None
        if exchanges is not None:
            exchange = (dst, dst_port, src, src_port, identifier)
            request = exchanges.answer(exchange, _RADIUS_ANSWERS[code])
            if request is None and exchanges.waiting(exchange):
                stats["radius-reply-code-mismatch"] += 1
                return (
                    ["unchecked-radius-reply-code-mismatch"] if strict else []
                )
        return _check_radius_reply(
            radius, attributes, request, stats, strict=strict
        )
    if code in _RADIUS_REQUESTS and exchanges is not None:
        exchanges.ask(
            (src, src_port, dst, dst_port, identifier), code, radius[4:20]
        )
    failures: list[str] = []
    zeroed = radius[:4] + bytes(16) + radius[20:]
    name = _RADIUS_HASHED_AUTHENTICATOR.get(code)
    if name is not None:
        stats[f"radius-{name}-authenticator"] += 1
        # MD5 is what RFC 2866 §3 mandates; this only checks the hash
        # the client sent, so it is not a security use.
        digest = hashlib.md5(
            zeroed + _RADIUS_SECRET, usedforsecurity=False
        ).digest()
        if not hmac.compare_digest(digest, radius[4:20]):
            failures.append(f"radius-{name}-authenticator")
    if code in _RADIUS_RANDOM_AUTHENTICATOR:
        signed = radius
    elif code in _RADIUS_ZEROED_AUTHENTICATOR:
        signed = zeroed
    else:
        return failures
    for kind, offset in attributes:
        if kind == _RADIUS_MESSAGE_AUTHENTICATOR:
            stats["radius-message-authenticator"] += 1
            if not _radius_message_authenticator_verifies(signed, offset):
                failures.append("radius-message-authenticator")
            break
    return failures


def _check_radius_reply(
    radius: bytes,
    attributes: list[tuple[int, int]],
    request: bytes | None,
    stats: Counter[str],
    *,
    strict: bool,
) -> list[str]:
    """Verify a RADIUS reply against ``request``, the Authenticator of
    the request it answers.

    Its Response Authenticator must be MD5 over the reply with
    ``request`` in place of the Authenticator, then the secret (RFC 2865
    §3, RFC 2866 §3, RFC 5176 §2.3), and its Message-Authenticator, when
    it carries one, HMAC-MD5 under the secret over the reply with
    ``request`` in place of the Authenticator and that attribute's value
    zeroed (RFC 3579 §3.2). Each is reported on its own. A reply with no
    ``request`` is counted ``radius-reply-unpaired`` and not checked,
    and fails under ``strict``."""
    if request is None:
        stats["radius-reply-unpaired"] += 1
        return ["unchecked-radius-reply-unpaired"] if strict else []
    signed = radius[:4] + request + radius[20:]
    failures: list[str] = []
    stats["radius-response-authenticator"] += 1
    # MD5 is what RFC 2865 §3 mandates; this only checks the hash the
    # server sent, so it is not a security use.
    digest = hashlib.md5(signed + _RADIUS_SECRET, usedforsecurity=False)
    if not hmac.compare_digest(digest.digest(), radius[4:20]):
        failures.append("radius-response-authenticator")
    for kind, offset in attributes:
        if kind == _RADIUS_MESSAGE_AUTHENTICATOR:
            stats["radius-reply-message-authenticator"] += 1
            if not _radius_message_authenticator_verifies(signed, offset):
                failures.append("radius-reply-message-authenticator")
            break
    return failures


def _radius_message_authenticator_verifies(signed: bytes, offset: int) -> bool:
    """Whether the Message-Authenticator at ``offset`` in ``signed``, a
    RADIUS packet holding the Authenticator the attribute is computed
    over, is 18 bytes long and its HMAC-MD5 under the secret over
    ``signed`` with the attribute's value zeroed (RFC 3579 §3.2)."""
    if signed[offset + 1] != 18:
        return False
    zeroed = signed[: offset + 2] + bytes(16) + signed[offset + 18 :]
    digest = hmac.new(_RADIUS_SECRET, zeroed, hashlib.md5).digest()
    return hmac.compare_digest(digest, signed[offset + 2 : offset + 18])


#: The symmetric keys of the corpus's NTP MACs, by Key ID: the test
#: keys published in tests/fixtures/MANIFEST.md, as chrony and ntpdig
#: were configured with them.
_NTP_KEYS = {
    1: ("md5", b"np191-md5-key"),
    2: ("sha1", b"np191-sha1-key"),
    3: ("md5", b"np272-md5-key"),
    4: ("sha1", b"np272-sha1-key"),
}


def _ntp_mac_offset(ntp: bytes, stats: Counter[str]) -> int | None:
    """Where an NTP message's MAC would start: after the 48-byte header
    and, in NTPv4, the extension fields (RFC 7822 §3), each a 2-byte
    type and a 2-byte Length counting its header, at least 16 and a
    multiple of 4. The walk stops when 24 bytes or fewer are left, the
    most a MAC takes (a Key ID and a SHA-1 digest), since the last
    extension field of a message without a MAC is longer than that.
    ``None`` when an extension field's Length breaks those rules."""
    offset = 48
    if (ntp[0] >> 3) & 0x07 != 4:
        return offset
    while len(ntp) - offset > 24:
        length = struct.unpack_from("!H", ntp, offset + 2)[0]
        if length < 16 or length % 4 or offset + length > len(ntp):
            return None
        stats["ntp-extension-field"] += 1
        offset += length
    return offset


def _check_ntp(datagram: bytes, stats: Counter[str]) -> list[str]:
    """Verify an NTP message's MAC, if it carries one.

    The UDP checksum already covers every NTP byte; this checks the
    MAC on top of it. A MAC is a 4-byte Key ID and a digest of the key
    followed by everything before the MAC, as RFC 5905's reference
    implementation computes it: MD5's 16 bytes or SHA-1's 20. A message
    ends at its header and extension fields, or in a MAC of one of
    those two lengths; anything else is a failure, and so is a Key ID
    with no published key, as an unknown IPsec SPI is (see
    :func:`_verify_icv`)."""
    ntp = datagram[8 : struct.unpack_from("!H", datagram, 4)[0]]
    stats["ntp"] += 1
    if ntp and ntp[0] & 0x07 == 6:
        return _check_ntp_control(ntp, stats)
    if len(ntp) < 48:
        return ["ntp-truncated"]
    offset = _ntp_mac_offset(ntp, stats)
    if offset is None:
        return ["ntp-extension-field"]
    mac = ntp[offset:]
    if not mac:
        return []
    if len(mac) not in (20, 24):
        return ["ntp-trailer"]
    sa = _NTP_KEYS.get(struct.unpack_from("!I", mac)[0])
    if sa is None:
        return ["ntp-unknown-key"]
    algorithm, key = sa
    stats[f"ntp-{algorithm}"] += 1
    # MD5 and SHA-1 are what the senders used; this only checks the MAC
    # they sent, so it is not a security use.
    digest = hashlib.new(
        algorithm, key + ntp[:offset], usedforsecurity=False
    ).digest()
    if not hmac.compare_digest(digest, mac[4:]):
        return [f"ntp-{algorithm}"]
    return []


def _check_ntp_control(ntp: bytes, stats: Counter[str]) -> list[str]:
    """Validate an NTP control message (mode 6, RFC 9327 §2) and verify
    its MAC, if it carries one.

    The 12-byte header's Count gives the data's length, which must fit
    the datagram. Without a MAC the data is padded to a multiple of 4
    bytes and the message ends there. A MAC starts where ntpd and ntpsec
    put it: after the data padded to a multiple of 8 bytes, or, in an
    error response (R and E set), after the data padded to a multiple of
    4 bytes, which is right after the header when the Count is 0, as
    ``NTPControl.decode`` looks for it. It is a 4-byte Key ID and MD5's
    16-byte or SHA-1's 20-byte digest of the key followed by everything
    before the MAC, as for a time message (see :func:`_check_ntp`).
    Anything else after the data is a failure, and so is a Key ID with
    no published key."""
    stats["ntp-control"] += 1
    if len(ntp) < 12:
        return ["ntp-control-truncated"]
    flags, count = ntp[1], struct.unpack_from("!H", ntp, 10)[0]
    end = 12 + count
    if end > len(ntp):
        return ["ntp-control-truncated"]
    aligned = (end + 3) & ~3
    start = aligned if flags & 0xC0 == 0xC0 else (end + 7) & ~7
    if len(ntp) == aligned:
        return []
    mac = ntp[start:]
    if len(ntp) < start or len(mac) not in (20, 24):
        return ["ntp-control-trailer"]
    sa = _NTP_KEYS.get(struct.unpack_from("!I", mac)[0])
    if sa is None:
        return ["ntp-control-unknown-key"]
    algorithm, key = sa
    stats[f"ntp-control-{algorithm}"] += 1
    # As in _check_ntp: this checks the MAC the sender sent, so it is not
    # a security use.
    digest = hashlib.new(
        algorithm, key + ntp[:start], usedforsecurity=False
    ).digest()
    if not hmac.compare_digest(digest, mac[4:]):
        return [f"ntp-control-{algorithm}"]
    return []


#: HSRP's Op Codes (RFC 2281 §5.1), by the counter each one counts.
_HSRP_OP_CODES = {0: "hello", 1: "coup", 2: "resign"}

#: HSRP's states (RFC 2281 §5.1): Initial, Learn, Listen, Speak,
#: Standby and Active.
_HSRP_STATES = (0, 1, 2, 4, 8, 16)


def _check_hsrp(datagram: bytes, stats: Counter[str]) -> list[str]:
    """Validate an HSRPv1 message (RFC 2281 §5.1).

    HSRP carries no checksum of its own, and the UDP checksum already
    covers every HSRP byte, so this checks the message's fields
    instead. It must be the whole UDP payload, exactly 20 bytes, sent
    from and to port 1985 (no MD5 Authentication TLV, which some Cisco
    releases append, follows any message here), with Version 0, an Op
    Code of Hello, Coup or Resign and a State the RFC defines; a
    Hello's Holdtime must exceed its Hellotime, which the RFC says only
    for Hellos. Two further rules are this corpus's conventions, not
    RFC 2281 requirements: the Reserved byte must be zero, which every
    sender captured here transmits, and the Authentication Data must be
    a clear-text password, printable ASCII padded with NUL bytes. The
    Holdtime rule too is on what the sender transmitted, not on what a
    receiver requires: nothing in RFC 2281 tells a receiver to drop a
    message that breaks it, or any of the conventions. HSRPv2 is
    checked by :func:`_check_hsrpv2` instead."""
    hsrp = datagram[8 : struct.unpack_from("!H", datagram, 4)[0]]
    stats["hsrp"] += 1
    if len(hsrp) != 20:
        return ["hsrp-length"]
    if struct.unpack_from("!HH", datagram) != (_HSRP_PORT, _HSRP_PORT):
        return ["hsrp-port"]
    version, op_code, state, hellotime, holdtime = hsrp[:5]
    if version != 0:
        return ["hsrp-version"]
    if op_code not in _HSRP_OP_CODES:
        return ["hsrp-op-code"]
    stats[f"hsrp-{_HSRP_OP_CODES[op_code]}"] += 1
    if state not in _HSRP_STATES:
        return ["hsrp-state"]
    if hsrp[7] != 0:  # a corpus convention, not an RFC 2281 rule
        return ["hsrp-reserved"]
    if op_code == 0 and holdtime <= hellotime:
        return ["hsrp-holdtime"]
    # NUL is not printable, so this also fails a NUL before the padding.
    password = hsrp[8:16].rstrip(b"\x00")
    if not all(0x20 <= b < 0x7F for b in password):
        return ["hsrp-auth-data"]
    return []


#: HSRPv2's States (Wireshark's packet-hsrp.c, ``HSRP2_STATE_*``):
#: Disabled, Init, Learn, Listen, Speak, Standby and Active.
_HSRPV2_STATES = range(7)

#: The value length of each HSRPv2 TLV Type packet-hsrp.c reads at a
#: fixed length: Group State, Interface State, Text Authentication and
#: MD5 Authentication.
_HSRPV2_TLV_LENGTHS = {1: 40, 2: 4, 3: 8, 4: 28}


def _check_hsrpv2(
    src: bytes, datagram: bytes, stats: Counter[str]
) -> list[str]:
    """Validate an HSRPv2 message, as Wireshark's packet-hsrp.c reads it.

    HSRPv2 has no RFC and no checksum of its own, so, as for HSRPv1,
    this checks the message's fields. Over IPv4 it must be sent from
    and to port 1985 and over IPv6, as HSRP for IPv6, from and to port
    2029. Its UDP payload must be whole TLVs, each a Type, a Length that
    counts the value alone and the value, the first a Group State TLV
    (Type 1), and every Group State, Interface State, Text
    Authentication and MD5 Authentication TLV of the length
    packet-hsrp.c reads (40, 4, 8 and 28). The Interface State TLV's
    length is judged as packet-hsrp.c lays it out, an Active Groups
    and a Passive Groups count of 2 bytes each, although
    ``netprotocols.HSRPv2`` keeps that TLV raw at any length. Each
    Group State TLV must
    hold Version 2, an Op Code of Hello, Coup or Resign, a State
    packet-hsrp.c defines, the IP Version of the IP header carrying it
    and a Group of at most 4095, and in a Hello a Hold Time above the
    Hello Time. As this corpus's conventions, an IPv4 virtual address
    must be followed by 12 zero bytes in its 16-byte field and a Text
    Authentication TLV's data must be a clear-text password, printable
    ASCII padded with NUL bytes."""
    hsrp = datagram[8 : struct.unpack_from("!H", datagram, 4)[0]]
    stats["hsrpv2"] += 1
    family, port = (4, _HSRP_PORT) if len(src) == 4 else (6, _HSRP_V6_PORT)
    if struct.unpack_from("!HH", datagram) != (port, port):
        return ["hsrpv2-port"]
    tlvs: list[tuple[int, bytes]] = []
    cursor = 0
    while cursor < len(hsrp):
        end = cursor + 2 + (hsrp[cursor + 1] if cursor + 1 < len(hsrp) else 0)
        if cursor + 2 > len(hsrp) or end > len(hsrp):
            return ["hsrpv2-tlv"]
        tlvs.append((hsrp[cursor], hsrp[cursor + 2 : end]))
        cursor = end
    if not tlvs or tlvs[0][0] != 1:
        return ["hsrpv2-group-state"]
    for kind, value in tlvs:
        if len(value) != _HSRPV2_TLV_LENGTHS.get(kind, len(value)):
            return ["hsrpv2-tlv-length"]
    for kind, value in tlvs:
        if kind == 1:
            failure = _check_hsrpv2_group_state(value, family, stats)
            if failure is not None:
                return [failure]
        # NUL is not printable, so this also fails a NUL before the
        # padding.
        if kind == 3 and not all(
            0x20 <= b < 0x7F for b in value.rstrip(b"\x00")
        ):
            return ["hsrpv2-auth-data"]
    return []


def _check_hsrpv2_group_state(
    value: bytes, family: int, stats: Counter[str]
) -> str | None:
    """The failure, if any, of a Group State TLV's 40-byte ``value`` sent
    over IP version ``family`` (see :func:`_check_hsrpv2`)."""
    version, op_code, state, ip_version, group = struct.unpack_from(
        "!BBBBH", value
    )
    hellotime, holdtime = struct.unpack_from("!II", value, 16)
    if version != 2:
        return "hsrpv2-version"
    if op_code not in _HSRP_OP_CODES:
        return "hsrpv2-op-code"
    stats[f"hsrpv2-{_HSRP_OP_CODES[op_code]}"] += 1
    if state not in _HSRPV2_STATES:
        return "hsrpv2-state"
    if ip_version != family:
        return "hsrpv2-ip-version"
    if group > 4095:
        return "hsrpv2-group"
    if op_code == 0 and holdtime <= hellotime:
        return "hsrpv2-holdtime"
    # a corpus convention, not packet-hsrp.c's
    if ip_version == 4 and any(value[28:40]):
        return "hsrpv2-padding"
    return None


#: IP protocol numbers whose payload is a whole IP packet: 4 carries
#: IPv4 (RFC 2003, and RFC 2473 inside IPv6), 41 carries IPv6 (RFC
#: 4213, RFC 2473), mapped to the EtherType that names the inner header.
_IP_IN_IP = {4: 0x0800, 41: 0x86DD}


def _check_ip_in_ip(
    proto: int,
    upper: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    # No header of its own: the payload is the tunnelled packet,
    # validated in turn.
    stats["ip-in-ip"] += 1
    return _check_l3(_IP_IN_IP[proto], upper, stats, depth + 1, strict=strict)


#: The integrity keys of the corpus's IPsec Security Associations,
#: keyed by SPI — the test keys published in tests/fixtures/MANIFEST.md.
#: Every SA uses HMAC-SHA-256-128 (RFC 4868), and every ESP SA NULL
#: encryption (RFC 2410), so the protected payload is readable once the
#: ICV verifies.
_ESP_NULL_SAS = {
    0x10000001: bytes.fromhex(
        "e41126360fbc54a0e11a8747218b24d0cc4638f579c3985017b4d0ab1a30398b"
    ),
    0x10000002: bytes.fromhex(
        "4bc3ce948208049b2f5016e06616867773924d2ccb4dab8b3aff93e6d26f3834"
    ),
    0x10000003: bytes.fromhex(
        "107c873bdbb0c7a11be8aa1d9064e51f63b26098412295c3bd6785958abd44d4"
    ),
}
_AH_SAS = {
    0x20000001: bytes.fromhex(
        "8eaa03a41a3b08f31a67f3a4b7fd78a2bf3d963a97b0af5a104301ef8fbff685"
    ),
    0x20000002: bytes.fromhex(
        "d2142153fb758a3f698e45720e2af765b2ada021d70ac1bcbde1f5bc38514fd1"
    ),
    0x20000003: bytes.fromhex(
        "008a9a220d8c1bf5edec1838a724b588364c08314bf93206985e776c385e1c7a"
    ),
}
_ICV_LEN = 16

#: How many encapsulations (GRE, IP-in-IP, IPsec) one frame may nest
#: before the checker refuses it. The corpus peaks at 2 (ah.pcap's
#: AH-over-ESP bundle); the bound keeps a hostile capture from
#: exhausting the interpreter's stack.
_MAX_DEPTH = 8


def _icv(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()[:_ICV_LEN]


def _verify_icv(
    protocol: str,
    sas: dict[int, bytes],
    spi: int,
    covered: bytes,
    wire_icv: bytes,
) -> list[str]:
    """Verify an IPsec ICV: HMAC-SHA-256-128 over ``covered`` with the
    key of SA ``spi`` in ``sas``. Returns ``[]`` or one failure,
    prefixed with ``protocol`` ("esp", "ah").

    An SPI with no key in ``sas`` is a failure, not a skip, in every
    mode. MANIFEST.md promises every IPsec ICV in the corpus verifies, so
    an unknown SPI is either a corrupted frame or a fixture on an SA whose
    key is not published; a fixture on a new SA publishes its key there
    and adds it here.
    """
    key = sas.get(spi)
    if key is None:
        return [f"{protocol}-unknown-sa"]
    if not hmac.compare_digest(_icv(key, covered), wire_icv):
        return [f"{protocol}-icv"]
    return []


def _check_esp(
    ip_header: bytes,
    upper: bytes,
    stats: Counter[str],
    depth: int,
    *,
    ipv6: bool,
) -> list[str]:
    # ESP (RFC 4303): SPI and sequence number, then (under NULL
    # encryption) the payload, padding, Pad Length, Next Header, and the
    # ICV over everything before it.
    stats["esp"] += 1
    if len(upper) < 8 + 2 + _ICV_LEN:
        return ["esp-truncated"]
    protected, wire_icv = upper[:-_ICV_LEN], upper[-_ICV_LEN:]
    spi = struct.unpack_from("!I", upper, 0)[0]
    failures = _verify_icv("esp", _ESP_NULL_SAS, spi, protected, wire_icv)
    if failures:
        return failures
    pad_len, next_header = protected[-2], protected[-1]
    end = len(protected) - 2 - pad_len
    # RFC 4303 §2.4: the default padding is the bytes 1, 2, 3, ...
    if end < 8 or protected[end:-2] != bytes(range(1, pad_len + 1)):
        return ["esp-padding"]
    inner = protected[8:end]
    # strict: the ICV vouched for this payload, so one the checker
    # cannot read fails rather than passing unchecked.
    if next_header in _IP_IN_IP:
        # Tunnel mode (RFC 4303 §3.1.2): the payload is a whole IP
        # packet, counted as ESP's, not as IP-in-IP.
        stats["esp-tunnel"] += 1
        return _check_l3(
            _IP_IN_IP[next_header], inner, stats, depth + 1, strict=True
        )
    # Transport mode: the upper-layer protocol's pseudo-header is still
    # the enclosing IP header's.
    check = _check_upper_v6 if ipv6 else _check_upper_v4
    return check(next_header, ip_header, inner, stats, depth + 1, strict=True)


def _check_ah(
    ip_header: bytes, upper: bytes, stats: Counter[str], depth: int
) -> list[str]:
    # AH (RFC 4302): next header, payload len, reserved, SPI, sequence
    # number, then the ICV — over the IPv4 header with its mutable
    # fields zeroed, the AH header with its ICV zeroed, and the payload
    # (RFC 4302 §3.3.3).
    stats["ah"] += 1
    if len(upper) < 12:
        return ["ah-truncated"]
    if len(ip_header) != 20:
        # Options have their own mutability rules (RFC 4302 Appendix
        # A), which are not implemented: an ICV over options fails
        # rather than passing unread.
        return ["ah-ipv4-options-unverified"]
    next_header, payload_len = upper[0], upper[1]
    ah_len = (payload_len + 2) * 4
    if ah_len != 12 + _ICV_LEN:
        return ["ah-length"]
    if len(upper) < ah_len:
        return ["ah-truncated"]
    # Zeroed: TOS (byte 1), flags + fragment offset (6-7), TTL (8), and
    # the header checksum (10-11).
    immutable = (
        ip_header[:1]
        + b"\x00"
        + ip_header[2:6]
        + b"\x00\x00\x00"
        + ip_header[9:10]
        + b"\x00\x00"
        + ip_header[12:20]
    )
    payload = upper[ah_len:]
    blank = upper[:12] + bytes(_ICV_LEN) + payload
    spi = struct.unpack_from("!I", upper, 4)[0]
    failures = _verify_icv(
        "ah", _AH_SAS, spi, immutable + blank, upper[12:ah_len]
    )
    if failures:
        return failures
    # strict, as for ESP: the ICV vouched for this payload.
    if next_header in _IP_IN_IP:
        # Tunnel mode (RFC 4302 §3.1): the payload is a whole IP
        # packet, counted as AH's, not as IP-in-IP.
        stats["ah-tunnel"] += 1
        return _check_l3(
            _IP_IN_IP[next_header], payload, stats, depth + 1, strict=True
        )
    # Transport mode, or a bundle (AH over ESP): the pseudo-header is
    # still the enclosing IPv4 header's.
    return _check_upper_v4(
        next_header, ip_header, payload, stats, depth + 1, strict=True
    )


def _check_ipv6(
    payload: bytes, stats: Counter[str], depth: int, *, strict: bool = False
) -> list[str]:
    failures: list[str] = []
    stats["ipv6"] += 1
    payload_length, next_header = struct.unpack_from("!HB", payload, 4)
    upper = payload[40 : 40 + payload_length]
    final_dst = None
    # Walk extension headers (hop-by-hop 0, routing 43, dest-opts 60).
    while next_header in (0, 43, 60) and len(upper) >= 8:
        stats["ipv6-ext-header"] += 1
        ext_len = (upper[1] + 1) * 8
        if next_header == 43:
            final_dst = _route_end(upper[:ext_len], payload[24:40], final_dst)
        next_header, upper = upper[0], upper[ext_len:]
    if next_header == 44 and len(upper) >= 8:
        if struct.unpack_from("!H", upper, 2)[0] & 0xFFF8:
            stats["ipv6-fragment"] += 1
            # Non-first fragment: no upper header.
            return failures + (["unchecked-fragment"] if strict else [])
        stats["ipv6-first-fragment"] += 1
        # The upper-layer checksum spans the reassembled datagram, not
        # this fragment's slice: nothing verifiable here.
        return failures + (["unchecked-fragment"] if strict else [])
    # RFC 8200 §8.1: behind a route with segments left, every
    # pseudo-header below, transport mode under ESP's included, takes
    # the route's end for the Destination Address, so the header is
    # passed on as the pseudo-header sees it. Nothing below reads the
    # wire address from it: ESP's ICV covers only ESP, AH over IPv6 is
    # not verified, and a tunnelled packet brings its own header.
    seen = payload[:24] + (final_dst or payload[24:40])
    return failures + _check_upper_v6(
        next_header, seen, upper, stats, depth, strict=strict
    )


def _rh0_final(data: bytes, dst: bytes) -> bytes | None:
    """Type 0 (RFC 2460 §4.4): 4 reserved octets, then the addresses
    in visiting order; the last is the final destination."""
    addresses = data[4:]
    if not addresses or len(addresses) % 16:
        return None
    return addresses[-16:]


def _mobile_ipv6_final(data: bytes, dst: bytes) -> bytes | None:
    """Type 2 (RFC 6275 §6.4): 4 reserved octets and one Home Address."""
    return data[4:] if len(data) == 20 else None


def _rpl_final(data: bytes, dst: bytes) -> bytes | None:
    """Type 3 (RFC 6554 §3): ``Address[1..n-1]`` take ``16 - CmprI``
    octets each and ``Address[n]`` takes ``16 - CmprE``, then ``Pad``
    octets end the header. ``Address[n]`` is completed with the first
    ``CmprE`` octets of the packet's Destination Address. Entries that
    do not tile the area resolve nothing."""
    cmpr_i, cmpr_e, pad = data[0] >> 4, data[0] & 0x0F, data[1] >> 4
    entries = data[4:]
    size = 16 - cmpr_e
    start = len(entries) - pad - size
    if start < 0 or start % (16 - cmpr_i):
        return None
    return dst[:cmpr_e] + entries[start : start + size]


def _srh_final(data: bytes, dst: bytes) -> bytes | None:
    """Type 4 (RFC 8754 §2): Last Entry, Flags and Tag, then the Segment
    List in reverse order; Segment List[0] is the final destination,
    and must lie inside a list Last Entry says is there."""
    if len(data) < 4 + (data[0] + 1) * 16:
        return None
    return data[4:20]


#: The IPv6 Routing header types whose final destination is resolved
#: (RFC 8200 §8.1), each by its own rule; any other leaves ``dst``.
_ROUTING_FINAL = {
    0: _rh0_final,
    2: _mobile_ipv6_final,
    3: _rpl_final,
    4: _srh_final,
}


def _route_end(
    header: bytes, dst: bytes, current: bytes | None
) -> bytes | None:
    """The pseudo-header destination after the Routing header ``header``.

    RFC 8200 §8.1 puts the final destination of a route in the
    pseudo-header. A receiver skips a Routing header with no segments
    left (RFC 8200 §4.4; RFC 2460 §4.4, RFC 6554 §4.2, RFC 8754 §4.3),
    so the last one with segments left decides, and ``current`` (the
    choice so far) stands when ``header`` has none, or is cut short.
    A route it cannot resolve, of an unknown type or the wrong shape,
    falls back to ``dst``, the IPv6 header's Destination Address.
    """
    if len(header) < (header[1] + 1) * 8 or not header[3]:
        return current
    resolve = _ROUTING_FINAL.get(header[2])
    final = resolve(header[4:], dst) if resolve else None
    return final or dst


def _check_transport_v6(
    next_header: int,
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool,
) -> list[str] | None:
    """The IPv6 counterpart of :func:`_check_transport_v4` (ICMPv6,
    TCP, UDP, SCTP, VRRP)."""
    upper_len = len(upper)
    if next_header == 58 and upper_len >= 4:
        return _check_icmpv6(src, dst, upper, stats)
    if next_header == 6 and upper_len >= 20:
        return _check_tcp6(src, dst, upper, stats)
    if next_header == 17 and upper_len >= 8:
        return _check_udp6(src, dst, upper, stats, depth, strict=strict)
    if next_header == 132 and upper_len >= 12:
        return _check_sctp(upper, stats)
    if next_header == _VRRP:
        return _check_vrrp(src, dst, upper, stats, ipv6=True)
    return None


def _check_upper_v6(
    next_header: int,
    ip_header: bytes,
    upper: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    """The IPv6 counterpart of :func:`_check_upper_v4`, bounding
    nesting and honouring ``strict`` the same way.

    ``ip_header`` is the IPv6 header as its pseudo-headers see it: its
    Destination Address is the end of a route (see :func:`_route_end`)
    when the packet has one, and ESP in transport mode passes it back
    here unchanged, so the payload it protects is summed the same way.
    """
    if depth > _MAX_DEPTH:
        return ["nesting-too-deep"]
    src, dst = ip_header[8:24], ip_header[24:40]
    transport = _check_transport_v6(
        next_header, src, dst, upper, stats, depth, strict=strict
    )
    if transport is not None:
        return transport
    if next_header == 47 and len(upper) >= 4:
        return _check_gre(upper, stats, depth, strict=strict)
    if next_header in _IP_IN_IP:
        return _check_ip_in_ip(next_header, upper, stats, depth, strict=strict)
    if next_header == 50:
        return _check_esp(ip_header, upper, stats, depth, ipv6=True)
    if next_header == 51:
        # The ICV would cover the IPv6 header and its extension headers
        # under their own mutability rules (RFC 4302 §3.3.3.1.2), which
        # are not implemented, so it fails rather than passing
        # unverified.
        stats["ah"] += 1
        return ["ah-ipv6-unverified"]
    if next_header == _PIM:
        return _check_pim(
            src, dst, upper, stats, depth, ipv6=True, strict=strict
        )
    return [f"unchecked-protocol-{next_header}"] if strict else []


def _check_arp(
    payload: bytes, stats: Counter[str], depth: int, *, strict: bool = False
) -> list[str]:
    """Count an ARP packet, which carries no checksum.

    Under strict, require the 28-byte Ethernet/IPv4 form.
    """
    stats["arp"] += 1
    if strict and len(payload) < 28:
        return ["unchecked-ethertype-0x0806"]
    return []


#: The MPLS bottom labels RFC 3032 §2.1 reserves for a payload: IPv4
#: and IPv6 Explicit NULL. The two that announce a non-IP payload, the
#: GAL (13, RFC 5586) and the OAM Alert Label (14, RFC 3429), map to
#: ``None``.
_MPLS_BOTTOM_LABELS = {0: 0x0800, 2: 0x86DD, 13: None, 14: None}

#: The first nibble after a label stack read as an IP version
#: (RFC 4928 §2), mapped to the EtherType that names that header.
_MPLS_NIBBLES = {4: 0x0800, 6: 0x86DD}


def _mpls_stack_end(payload: bytes) -> tuple[int, int] | None:
    """Find the end of an MPLS label stack.

    Return the offset just past the entry with its Bottom of Stack bit
    set, and that entry's label, or ``None`` when the bytes end first.
    """
    for offset in range(0, len(payload) - 3, 4):
        word = struct.unpack_from("!I", payload, offset)[0]
        if word & 0x100:
            return offset + 4, word >> 12
    return None


def _check_mpls(
    payload: bytes, stats: Counter[str], depth: int, *, strict: bool = False
) -> list[str]:
    """Validate an MPLS frame (EtherType 0x8847 or 0x8848, RFC 3032).

    Walk the label stack to the entry with its Bottom of Stack bit set,
    then validate what follows: an IPv4 or IPv6 packet, named by an
    Explicit NULL bottom label or else by its first nibble (the same
    convention the library documents, implemented here on its own), or,
    after a pseudowire control word (first nibble 0, RFC 4385 §3), the
    Ethernet frame an Ethernet pseudowire (RFC 4448) carries. A
    pseudowire's payload type is signalled, not encoded, and the
    corpus's only pseudowire is Ethernet. Anything else passes unread,
    or fails under ``strict``; so does a stack whose bottom never comes.
    """
    end = _mpls_stack_end(payload)
    if end is None:
        stats["mpls-truncated"] += 1
        return ["unchecked-mpls-truncated"] if strict else []
    offset, bottom = end
    stats["mpls-stack"] += 1
    inner = payload[offset:]
    nibble = inner[0] >> 4 if inner else None
    if bottom in _MPLS_BOTTOM_LABELS:
        ethertype = _MPLS_BOTTOM_LABELS[bottom]
    else:
        ethertype = None if nibble is None else _MPLS_NIBBLES.get(nibble)
    if ethertype is not None:
        return _check_l3(ethertype, inner, stats, depth + 1, strict=strict)
    if bottom not in _MPLS_BOTTOM_LABELS and nibble == 0 and len(inner) >= 4:
        stats["mpls-pseudowire"] += 1
        return _check_ethernet(inner[4:], stats, depth + 1, strict=strict)
    stats["mpls-unchecked-payload"] += 1
    return ["unchecked-mpls-payload"] if strict else []


#: The EtherTypes :func:`_check_l3` hands to a helper of their own.
def _check_lldp_l3(
    payload: bytes, stats: Counter[str], depth: int, *, strict: bool
) -> list[str]:
    """Adapt :func:`_check_lldp` to the ``_L3_HELPERS`` signature: an
    LLDPDU ends the walk, so neither ``depth`` nor ``strict`` applies."""
    del depth, strict
    return _check_lldp(payload, stats)


_L3_HELPERS = {
    0x0806: _check_arp,
    0x8847: _check_mpls,
    0x8848: _check_mpls,
    0x88CC: _check_lldp_l3,
}


def _check_l3(
    ethertype: int,
    payload: bytes,
    stats: Counter[str],
    depth: int = 0,
    *,
    strict: bool = False,
) -> list[str]:
    """Validate the checksums reachable from an L3 payload named by
    ``ethertype``. Recurses through a GRE tunnel, whose inner protocol
    is itself an EtherType, through an MPLS label stack (see
    :func:`_check_mpls`), through IP-in-IP (IP protocols 4 and 41),
    through VXLAN, whose payload is a whole Ethernet frame, and through
    NULL-encrypted ESP and IPv4 AH after verifying the ICV, and checks a
    RIPv2 message's RFC 4822 digest with its published key. IPsec on an
    SA whose key is not published fails, as does RIP on a Key ID whose
    key is not, and so do IPv6 AH and IPv4 AH behind header options,
    whose ICV this cannot compute. Nesting
    deeper than ``_MAX_DEPTH`` fails. Under ``strict`` (anything an ESP
    or AH ICV vouched for, at any depth below it) a payload the checker
    cannot read fails too: an unknown protocol or EtherType, a header
    too short to check, or a fragment. Returns a list of failure
    strings."""
    if depth > _MAX_DEPTH:
        return ["nesting-too-deep"]
    helper = _L3_HELPERS.get(ethertype)
    if helper is not None:
        return helper(payload, stats, depth, strict=strict)

    if ethertype == 0x0800 and len(payload) >= 20:
        return _check_ipv4(payload, stats, depth, strict=strict)

    if ethertype == 0x86DD and len(payload) >= 40:
        return _check_ipv6(payload, stats, depth, strict=strict)

    if strict:
        return [f"unchecked-ethertype-0x{ethertype:04x}"]
    stats[f"other-0x{ethertype:04x}"] += 1
    return []


def _lldp_tlvs(payload: bytes) -> tuple[list[tuple[int, bytes]], int] | None:
    """Walk an LLDPDU's TLVs through End of LLDPDU.

    Each is a 7-bit type and a 9-bit length in one big-endian word, then
    the value (IEEE 802.1AB §8). Returns the ``(type, value)`` pairs and
    the offset after End, or ``None`` when a TLV runs past the payload
    or no End TLV ends the walk.
    """
    tlvs: list[tuple[int, bytes]] = []
    cursor = 0
    while cursor + 2 <= len(payload):
        word = struct.unpack_from("!H", payload, cursor)[0]
        end = cursor + 2 + (word & 0x1FF)
        if end > len(payload):
            return None
        tlvs.append((word >> 9, payload[cursor + 2 : end]))
        cursor = end
        if word >> 9 == 0:
            return tlvs, cursor
    return None


def _lldp_mandatory_tlvs_ok(tlvs: list[tuple[int, bytes]]) -> bool:
    """Check that an LLDPDU opens with its three mandatory TLVs.

    They are Chassis ID, Port ID and Time To Live, well formed, and none
    of them may appear again.
    """
    if [tlv_type for tlv_type, _ in tlvs[:3]] != [1, 2, 3]:
        return False
    chassis_id, port_id, ttl = (value for _, value in tlvs[:3])
    if not all(2 <= len(value) <= 256 for value in (chassis_id, port_id)):
        return False
    return len(ttl) == 2 and not {1, 2, 3} & {t for t, _ in tlvs[3:]}


def _check_lldp(payload: bytes, stats: Counter[str]) -> list[str]:
    """Validate an LLDPDU's structure; LLDP has no checksum to verify.

    The TLVs must walk to an End of LLDPDU TLV of length 0, with only
    zero bytes (Ethernet padding) after it. The first three must be
    Chassis ID and Port ID, each a subtype byte and a 1-255 byte ID,
    and a 2-byte Time To Live, and none of those three types may
    appear again; a shutdown LLDPDU (TTL 0) carries nothing else.
    """
    stats["lldp"] += 1
    walked = _lldp_tlvs(payload)
    if walked is None:
        return ["lldp-unwalkable"]
    tlvs, end = walked
    if tlvs[-1][1] or payload[end:].strip(b"\x00"):
        return ["lldp-bad-end"]
    if not _lldp_mandatory_tlvs_ok(tlvs):
        return ["lldp-mandatory-tlvs"]
    if tlvs[2][1] == b"\x00\x00":
        stats["lldp-shutdown"] += 1
        if len(tlvs) != 4:
            return ["lldp-shutdown-extra-tlvs"]
    return []


def check_frame(
    frame: bytes,
    stats: Counter[str],
    exchanges: RadiusExchanges | None = None,
) -> list[str]:
    """Validate one Ethernet frame; returns a list of failure strings.

    ``exchanges`` holds the RADIUS requests of the capture the frame is
    from, seen in its earlier frames; this frame's are added to it, and
    its replies are verified against it (see :func:`_check_radius`).
    Without it, the frame's RADIUS replies are unpaired."""
    token = _RADIUS_EXCHANGES.set(exchanges)
    try:
        return _check_ethernet(frame, stats, 0)
    finally:
        _RADIUS_EXCHANGES.reset(token)


#: The name a session capture ends with: every frame of a few
#: connections, kept in a directory beside the corpus rather than in it
#: (tests/fixtures/bgp/bgp_session.pcap, tests/fixtures/tls/
#: tls_session.pcap; see MANIFEST.md), where TCP's segments begin and
#: end wherever TCP cut the stream.
SESSION_SUFFIX = "_session.pcap"


def check_capture_frame(
    frame: bytes,
    stats: Counter[str],
    *,
    session: bool,
    exchanges: RadiusExchanges | None = None,
) -> list[str]:
    """Validate one frame of a capture, as :func:`check_frame` does with
    ``exchanges``, and in a capture that is not a session one
    (``session``, see :data:`SESSION_SUFFIX`) fail a TCP segment on port
    443 that carries data but not whole TLS records (``tls-split``),
    which :func:`_check_tls` only counts as ``tls-unchecked``: every
    corpus segment on 443 must be whole records, while a session capture
    keeps the segments a record spans."""
    before = stats["tls-unchecked"]
    failures = check_frame(frame, stats, exchanges)
    if not session and stats["tls-unchecked"] > before:
        failures.append("tls-split")
    return failures


def _check_ethernet(
    frame: bytes, stats: Counter[str], depth: int, *, strict: bool = False
) -> list[str]:
    """Validate an Ethernet frame: the captured one, or one a VXLAN
    tunnel carries (at ``depth`` > 0)."""
    if depth > _MAX_DEPTH:
        return ["nesting-too-deep"]
    if len(frame) < 14:
        stats["runt"] += 1
        return ["unchecked-runt"] if strict else []
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    payload = frame[14:]

    # Peel 802.1Q/802.1ad VLAN tag shims (4 bytes each: TCI + inner
    # EtherType); the innermost payload is then validated as usual.
    while ethertype in (0x8100, 0x88A8, 0x9100):
        if len(payload) < 4:
            stats["vlan-truncated"] += 1
            return ["unchecked-vlan-truncated"] if strict else []
        stats["vlan-tag"] += 1
        ethertype = struct.unpack_from("!H", payload, 2)[0]
        payload = payload[4:]

    return _check_type_or_length(
        ethertype, payload, stats, depth, strict=strict
    )


def _check_type_or_length(
    value: int,
    payload: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    """Validate what an Ethernet or VLAN Length/Type field names.

    IEEE 802.3 Clause 3.2.6: 0x0600 or more is an EtherType, 1500 or
    less the length of an 802.2 LLC PDU (see :func:`_check_8023`), and
    the values between are undefined, so there is nothing to check."""
    if value >= 0x0600:
        return _check_l3(value, payload, stats, depth, strict=strict)
    if value <= 1500:
        return _check_8023(value, payload, stats, depth, strict=strict)
    stats["type-undefined"] += 1
    return [f"unchecked-type-{value}"] if strict else []


def _check_8023(
    length: int,
    payload: bytes,
    stats: Counter[str],
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    """Validate an 802.3 Length against the frame, then the LLC PDU.

    The Length must fit in the frame, and anything after the PDU must
    be the zero padding a sender adds to a PDU shorter than the 46-byte
    minimum payload; a longer PDU, or a nonzero byte there, fails. That
    the padding brings the frame to exactly 60 bytes is not checked:
    this sees only the bytes after the field, not how many came before
    it (a tag, an enclosing tunnel), and a tagged frame may be padded to
    60 or 64 bytes depending on where the tag was added. Only the
    ``length`` bytes of the PDU are checked further, so padding never
    enters a checksum."""
    if length > len(payload):
        return ["8023-length-exceeds-frame"]
    trailer = payload[length:]
    if trailer and (any(trailer) or length >= 46):
        return ["8023-trailer-not-padding"]
    stats["8023"] += 1
    if trailer:
        stats["8023-padded"] += 1
    return _check_llc(payload[:length], stats, depth, strict=strict)


#: The two OUIs under which a SNAP PID is an EtherType: RFC 1042's and
#: IEEE 802.1H's bridge-tunnel OUI.
_ETHERTYPE_OUIS = (b"\x00\x00\x00", b"\x00\x00\xf8")

#: CDP's SNAP OUI (Cisco) and PID.
_CDP_SNAP = b"\x00\x00\x0c\x20\x00"


def _check_llc(
    pdu: bytes, stats: Counter[str], depth: int, *, strict: bool = False
) -> list[str]:
    """Validate an 802.2 LLC PDU: its Control field fits (1 octet when
    the two low bits are 11, else 2), then SNAP (DSAP 0xAA), an 802.1D
    BPDU or another protocol's PDU (DSAP 0x42) or a Novell raw 802.3 IPX
    packet (0xFFFF where the DSAP and SSAP would be), whose IPX length
    must be the PDU's."""
    if pdu[:2] == b"\xff\xff":
        stats["ipx-raw"] += 1
        if len(pdu) < 4 or struct.unpack_from("!H", pdu, 2)[0] != len(pdu):
            return ["ipx-length-mismatch"]
        return []
    if len(pdu) < 3 or len(pdu) < (3 if pdu[2] & 0x03 == 0x03 else 4):
        return ["llc-truncated"]
    stats["llc"] += 1
    if pdu[0] == 0xAA:
        return _check_snap(pdu, stats, depth, strict=strict)
    if pdu[0] == 0x42:
        return _check_sap_0x42(pdu, stats, strict=strict)
    stats[f"llc-dsap-0x{pdu[0]:02x}"] += 1
    return [f"unchecked-llc-dsap-0x{pdu[0]:02x}"] if strict else []


def _check_sap_0x42(
    pdu: bytes, stats: Counter[str], *, strict: bool = False
) -> list[str]:
    """Validate a PDU to the Bridge Spanning Tree SAP. Only a UI (either
    P/F) or I-format PDU carries one, as the library dispatches; any
    other Control is counted and not checked. After its 1-octet (UI) or
    2-octet Control comes a BPDU when its first two octets, the Protocol
    Identifier, are 0x0000 or fewer than two octets follow, and
    otherwise another protocol's PDU, such as GARP's (Protocol
    Identifier 0x0001), counted and not checked."""
    control = pdu[2]
    if control & ~0x10 != 0x03 and control & 0x01:
        key = f"llc-dsap-0x42-control-0x{control:02x}"
        stats[key] += 1
        return [f"unchecked-{key}"] if strict else []
    body = pdu[3 if control & 0x03 == 0x03 else 4 :]
    if len(body) >= 2 and body[:2] != b"\x00\x00":
        key = f"llc-dsap-0x42-protocol-0x{body[:2].hex()}"
        stats[key] += 1
        return [f"unchecked-{key}"] if strict else []
    return _check_bpdu(body, stats)


#: 802.1D BPDU Types: their names in the stats, the octets each needs
#: (802.1D-2004 §9.3; a receiver ignores octets past these, P802.1aq/
#: D1.5++ §14.4) and the Flags bits the type leaves unused, which "shall
#: be transmitted as 0" (§14.4 a)-g)): all but Topology Change and its
#: Acknowledgment in a Configuration BPDU, and bit 8 in an RST BPDU.
_BPDU_TYPES = {
    0x00: ("config", 35, 0x7E),
    0x02: ("rst", 36, 0x80),
    0x80: ("tcn", 4, 0x00),
}


def _check_bpdu(bpdu: bytes, stats: Counter[str]) -> list[str]:
    """Validate an 802.1D BPDU: Protocol Identifier 0, a known BPDU Type
    and as many octets as it needs, 35 for a Configuration BPDU (type
    0x00), 36 for an RST BPDU (0x02) and 4 for a Topology Change
    Notification (0x80), and, for an RST BPDU, a Protocol Version of 2
    or more: the receiver-side checks of §14.5, which discards a type
    0x02 BPDU of version 0 or 1. The rest are sender-side checks on the
    fixture, of what a well-behaved bridge transmits but a receiver
    ignores or tolerates: unused Flags bits 0 (§14.4 a)-g) "ignored on
    receipt") and an RST BPDU's Version 1 Length 0 (§14.4 p); §14.5 c)
    does not check it, and d)2) decodes a nonzero one as RST)."""
    kind = bpdu[3] if len(bpdu) > 3 else -1
    name, needed, unused = _BPDU_TYPES.get(kind, ("", 0, 0))
    if bpdu[:2] != b"\x00\x00" or not needed or len(bpdu) < needed:
        return ["stp-bpdu-malformed"]
    if unused and bpdu[4] & unused:
        return [f"stp-{name}-unused-flags"]
    if name == "rst" and (bpdu[2] < 2 or bpdu[35] != 0):
        return ["stp-rst-malformed"]
    stats["stp-bpdu"] += 1
    stats[f"stp-{name}"] += 1
    return []


def _check_snap(
    pdu: bytes, stats: Counter[str], depth: int, *, strict: bool = False
) -> list[str]:
    """Validate a SNAP PDU: SSAP 0xAA, a UI Control, then a 3-byte OUI
    and 2-byte PID. Under OUI 00-00-00 or 00-00-F8 the PID is an
    EtherType, checked as one; under Cisco's, PID 0x2000 is CDP."""
    if len(pdu) < 8 or pdu[1] != 0xAA or pdu[2] != 0x03:
        return ["snap-malformed"]
    stats["snap"] += 1
    oui, pid = pdu[3:6], struct.unpack_from("!H", pdu, 6)[0]
    if oui in _ETHERTYPE_OUIS:
        return _check_l3(pid, pdu[8:], stats, depth + 1, strict=strict)
    if pdu[3:8] == _CDP_SNAP:
        return _check_cdp(pdu[8:], stats)
    stats[f"snap-{oui.hex()}-0x{pid:04x}"] += 1
    return [f"unchecked-snap-{oui.hex()}-0x{pid:04x}"] if strict else []


def _cdp_checksum(data: bytes) -> int:
    """The internet checksum as CDP computes it.

    An odd final byte is not padded into the high-order byte of a last
    word, as RFC 1071 does, but added as the low byte when below 0x80,
    and when not as 0xFF00 plus the byte less 1: a sign-extended octet,
    less 1 to compensate for Cisco's off-by-one. That is lldpd 1.0.18's
    form, src/daemon/frame.c frame_checksum(), "sum += 0xff << 8;
    sum += v - 1;", and Wireshark's, epan/dissectors/packet-cdp.c
    (master 31bf0857, read 2026-10-25), which decrements both bytes of
    the last word ("padded_buffer[data_length]--;
    padded_buffer[data_length-1]--;"). lldpd's CDP frames verify with
    it on both sides of 0x80 (llc.pcap holds one of each).
    """
    total: int = sum(
        word for (word,) in struct.iter_unpack("!H", data[: len(data) & ~1])
    )
    if len(data) & 1:
        v = data[-1]
        total += (0xFF << 8) + v - 1 if v & 0x80 else v
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _check_cdp(pdu: bytes, stats: Counter[str]) -> list[str]:
    """Validate a CDP PDU (version 1 or 2): its TLVs, each at least 4
    bytes long, end exactly where the 802.3 Length ends the PDU, and
    its checksum, over exactly those bytes, verifies."""
    if len(pdu) < 4 or pdu[0] not in (1, 2):
        return ["cdp-malformed"]
    offset = 4
    while offset + 4 <= len(pdu):
        tlv_length = struct.unpack_from("!H", pdu, offset + 2)[0]
        if tlv_length < 4:
            return ["cdp-malformed"]
        offset += tlv_length
    if offset != len(pdu):
        return ["cdp-tlvs-overrun"]
    stats[f"cdpv{pdu[0]}"] += 1
    return [] if _cdp_checksum(pdu) == 0 else ["cdp-checksum"]


def main() -> int:
    staging = Path(
        sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/staging"
    )
    pcaps = sorted(staging.glob("*.pcap"))
    if not pcaps:
        print(f"No pcaps found in {staging}/")
        return 1

    corpus_stats: Counter[str] = Counter()
    bad_files = 0
    total_frames = 0
    for pcap in pcaps:
        stats: Counter[str] = Counter()
        failures: Counter[str] = Counter()
        frames = 0
        session = pcap.name.endswith(SESSION_SUFFIX)
        exchanges = RadiusExchanges()
        try:
            for frame in read_pcap(pcap):
                frames += 1
                for failure in check_capture_frame(
                    frame, stats, session=session, exchanges=exchanges
                ):
                    failures[failure] += 1
        except ValueError as e:
            print(f"[FAIL] {pcap.name}: {e}")
            bad_files += 1
            continue
        total_frames += frames
        corpus_stats.update(stats)
        verdict = "OK  " if not failures else "FAIL"
        detail = ", ".join(f"{k}x{v}" for k, v in sorted(stats.items()))
        print(f"[{verdict}] {pcap.name}: {frames} frames ({detail})")
        for failure, count in sorted(failures.items()):
            print(f"       !! {failure} x{count}")
        if failures:
            bad_files += 1

    print(f"\nCorpus: {total_frames} frames across {len(pcaps)} files")
    print(
        "Coverage:",
        ", ".join(f"{k}={v}" for k, v in sorted(corpus_stats.items())),
    )
    if bad_files:
        print(
            f"\n{bad_files} file(s) FAILED checksum consistency — "
            f"do not commit these; re-capture or investigate offload "
            f"(ethtool -K <iface> tx off rx off)."
        )
        return 1
    print("\nAll files internally consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
