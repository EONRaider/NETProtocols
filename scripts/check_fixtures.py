#!/usr/bin/env python3
"""Validate the internal checksum consistency of captured fixture pcaps.

Deliberately standalone (stdlib only, its own RFC 1071, CRC32c and
Fletcher implementations, its own minimal parsers): it must be able to
disqualify a capture even if netprotocols itself has a bug, and later
it cross-validates the library's checksum module (plan item L-2) with
an independent implementation.

Usage: python3 scripts/check_fixtures.py tests/fixtures/staging
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import sys
from collections import Counter
from pathlib import Path


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


#: CRC32c's Castagnoli polynomial, bit-reflected (RFC 9260 Appendix A).
_CRC32C_POLY = 0x82F63B78


def crc32c(data: bytes) -> int:
    """SCTP's CRC32c, bit by bit: slow, and deliberately not the
    library's table-driven loop."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (_CRC32C_POLY if crc & 1 else 0)
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


def read_pcap(path: Path):
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


def _check_icmpv4(upper: bytes, stats: Counter) -> list[str]:
    stats["icmpv4"] += 1
    if (
        internet_checksum(upper[:2] + b"\x00\x00" + upper[4:])
        != struct.unpack_from("!H", upper, 2)[0]
    ):
        return ["icmpv4-checksum"]
    return []


def _check_igmp(upper: bytes, stats: Counter) -> list[str]:
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


def _check_ospf(upper: bytes, stats: Counter) -> list[str]:
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


def _check_ospf_auth(upper: bytes, packet: bytes, stats: Counter) -> list[str]:
    """Check an OSPF packet's checksum, password or digest.

    The packet checksum under AuType 0 and 1 (the internet checksum of
    the packet but its Authentication field, RFC 2328 §D.4.1), the
    published password under AuType 1, or the keyed-MD5 digest under
    AuType 2 (§D.4.3: MD5 over the packet and the key NUL-padded to 16
    bytes; the packet checksum is not computed and must be zero).
    AuType is header byte 15: RFC 6549 §2 made byte 14 the Instance ID.
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
    upper: bytes, packet: bytes, wire: int, stats: Counter
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


def _check_ospf_lsas(body: bytes, stats: Counter) -> list[str]:
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
    src: bytes, dst: bytes, upper: bytes, stats: Counter
) -> list[str]:
    stats["tcp"] += 1
    upper_len = len(upper)
    zeroed = upper[:16] + b"\x00\x00" + upper[18:]
    if (
        internet_checksum(pseudo_v4(src, dst, 6, upper_len) + zeroed)
        != struct.unpack_from("!H", upper, 16)[0]
    ):
        return ["tcp-checksum"]
    return []


def _check_udp(
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter,
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
    return failures + _check_udp_payload(upper, stats, depth, strict=strict)


def _check_sctp(upper: bytes, stats: Counter) -> list[str]:
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
    src: bytes, dst: bytes, upper: bytes, stats: Counter, *, ipv6: bool
) -> list[str] | None:
    """Validate a VRRP advertisement, the whole IP payload ``upper``.

    Returns ``None`` when it is too short for the 8-byte fixed header.

    The checksum covers the VRRP message, checksum field (bytes 6-7)
    zeroed: alone in VRRPv2 (RFC 3768 §5.3.8), behind the IP
    pseudo-header with protocol 112 in VRRPv3, over IPv4 as over IPv6.
    RFC 5798 §5.2.8 cites only RFC 2460's pseudo-header, IPv6's; the
    IPv4 one is keepalived's default. RFC 9568 §5.2.8's IPv4 form,
    without the pseudo-header, is not accepted: the corpus's VRRPv3
    adverts are all keepalived's default form. The message's length
    follows from its version and address count (RFC 3768 §5.1: 8
    bytes, the addresses, and 8 bytes of authentication data; RFC 5798
    §5.1: no authentication data), and must be the IP payload's
    exactly. VRRPv2 is defined for IPv4 alone.
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
    covered = upper[:6] + b"\x00\x00" + upper[8:]
    if version == 3:
        pseudo = pseudo_v6 if ipv6 else pseudo_v4
        covered = pseudo(src, dst, _VRRP, len(upper)) + covered
    if internet_checksum(covered) != struct.unpack_from("!H", upper, 6)[0]:
        return ["vrrp-checksum"]
    return []


def _check_gre(
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter,
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    # GRE: a 4-byte header (flags word + inner EtherType) plus the
    # optional checksum/key/sequence words the flag bits announce
    # (RFC 2890), then the tunnelled packet — validated in turn.
    stats["gre"] += 1
    gre_flags = struct.unpack_from("!H", upper, 0)[0]
    inner_ethertype = struct.unpack_from("!H", upper, 2)[0]
    optional = (
        (4 if gre_flags & 0x8000 else 0)
        + (4 if gre_flags & 0x2000 else 0)
        + (4 if gre_flags & 0x1000 else 0)
    )
    return _check_l3(
        inner_ethertype, upper[4 + optional :], stats, depth + 1, strict=strict
    )


def _check_ipv4(
    payload: bytes, stats: Counter, depth: int, *, strict: bool = False
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
    stats: Counter,
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
    stats: Counter,
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
        return _check_gre(src, dst, upper, stats, depth, strict=strict)
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
    stats: Counter,
    depth: int,
    strict: bool,
) -> list[str] | None:
    """Validate a PIM or OSPF message carried by IPv4, or return
    ``None`` for any other protocol. Split from :func:`_check_upper_v4`
    to keep that dispatcher small."""
    if proto == _PIM:
        return _check_pim(
            src, dst, upper, stats, depth, ipv6=False, strict=strict
        )
    if proto == 89:
        return _check_ospf(upper, stats)
    return None


def _check_icmpv6(
    src: bytes, dst: bytes, upper: bytes, stats: Counter
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
    src: bytes, dst: bytes, upper: bytes, stats: Counter
) -> list[str]:
    stats["tcp6"] += 1
    upper_len = len(upper)
    zeroed = upper[:16] + b"\x00\x00" + upper[18:]
    if (
        internet_checksum(pseudo_v6(src, dst, 6, upper_len) + zeroed)
        != struct.unpack_from("!H", upper, 16)[0]
    ):
        return ["tcp6-checksum"]
    return []


def _check_udp6(
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter,
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
    return failures + _check_udp_payload(upper, stats, depth, strict=strict)


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
    stats: Counter,
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
    upper: bytes, stats: Counter, depth: int, *, strict: bool
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
    inner: bytes, stats: Counter, *, strict: bool
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
    inner: bytes, stats: Counter, *, strict: bool
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


def _check_udp_payload(
    datagram: bytes, stats: Counter, depth: int, *, strict: bool = False
) -> list[str]:
    """Validate what a UDP datagram carries, where it is something this
    checker can verify past the UDP checksum: a VXLAN tunnel (see
    :func:`_check_vxlan`) or a RIPv2 message's keyed digest (see
    :func:`_check_rip`)."""
    src_port, dst_port = struct.unpack_from("!HH", datagram)
    if dst_port == _VXLAN_PORT:
        return _check_vxlan(datagram, stats, depth, strict=strict)
    if _RIP_PORT in (src_port, dst_port):
        return _check_rip(datagram, stats)
    return []


def _check_vxlan(
    datagram: bytes, stats: Counter, depth: int, *, strict: bool = False
) -> list[str]:
    """Validate a VXLAN payload (destination port 4789, RFC 7348 §5):
    an 8-byte header and then a whole Ethernet frame, validated in
    turn.

    The destination port alone decides which datagrams are peeled,
    which is deliberately stricter than the library's port selection
    (it falls back to the source port when the destination is not
    registered). The checker does not apply the decoder's I-flag
    rule: it validates checksums, not VXLAN semantics. An
    encapsulating endpoint sends to the tunnel's port, 4789 in every
    capture here, from a source port hashed from the inner flow, so
    every tunnel datagram matches by its destination alone. Matching
    the library's fallback exactly would mean copying its port table
    into a checker that must stay independent of it, and peeling a
    datagram that is not VXLAN would report its bytes as checksum
    failures; skipping one costs only the inner check."""
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


def _check_rip(datagram: bytes, stats: Counter) -> list[str]:
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


#: IP protocol numbers whose payload is a whole IP packet: 4 carries
#: IPv4 (RFC 2003, and RFC 2473 inside IPv6), 41 carries IPv6 (RFC
#: 4213, RFC 2473), mapped to the EtherType that names the inner header.
_IP_IN_IP = {4: 0x0800, 41: 0x86DD}


def _check_ip_in_ip(
    proto: int,
    upper: bytes,
    stats: Counter,
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
#: AH-over-ESP bundle); the bound exists so a hostile capture cannot
#: exhaust the interpreter's stack.
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

    An SPI with no key in ``sas`` is a failure, not a skip. MANIFEST.md
    promises every IPsec ICV in the corpus verifies, and an unknown SPI
    is either a corrupted frame or a fixture on an SA whose key was
    never published — a fixture on a new SA publishes its key there and
    adds it here. There is deliberately no mode that tolerates unknown
    SAs: this checks the corpus, where every key is published, and a
    capture of genuinely encrypted IPsec cannot be verified, so it
    cannot back MANIFEST's promise and does not belong in the corpus.
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
    stats: Counter,
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
    ip_header: bytes, upper: bytes, stats: Counter, depth: int
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
        # A); no corpus frame carries any, so none are implemented, and
        # an ICV this cannot compute fails rather than passing unread.
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
    payload: bytes, stats: Counter, depth: int, *, strict: bool = False
) -> list[str]:
    failures: list[str] = []
    stats["ipv6"] += 1
    payload_length, next_header = struct.unpack_from("!HB", payload, 4)
    upper = payload[40 : 40 + payload_length]
    # Walk extension headers (hop-by-hop 0, routing 43, dest-opts 60).
    while next_header in (0, 43, 60) and len(upper) >= 8:
        stats["ipv6-ext-header"] += 1
        ext_len = (upper[1] + 1) * 8
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
    return failures + _check_upper_v6(
        next_header, payload[:40], upper, stats, depth, strict=strict
    )


def _check_transport_v6(
    next_header: int,
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter,
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
    stats: Counter,
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    """The IPv6 counterpart of :func:`_check_upper_v4`, bounding
    nesting and honouring ``strict`` the same way."""
    if depth > _MAX_DEPTH:
        return ["nesting-too-deep"]
    src, dst = ip_header[8:24], ip_header[24:40]
    transport = _check_transport_v6(
        next_header, src, dst, upper, stats, depth, strict=strict
    )
    if transport is not None:
        return transport
    if next_header in _IP_IN_IP:
        return _check_ip_in_ip(next_header, upper, stats, depth, strict=strict)
    if next_header == 50:
        return _check_esp(ip_header, upper, stats, depth, ipv6=True)
    if next_header == 51:
        # The ICV would cover the IPv6 header and its extension headers
        # under their own mutability rules (RFC 4302 §3.3.3.1.2), which
        # are not implemented; no corpus frame needs them, so one that
        # does fails rather than passing unverified.
        stats["ah"] += 1
        return ["ah-ipv6-unverified"]
    if next_header == _PIM:
        return _check_pim(
            src, dst, upper, stats, depth, ipv6=True, strict=strict
        )
    return [f"unchecked-protocol-{next_header}"] if strict else []


def _check_l3(
    ethertype: int,
    payload: bytes,
    stats: Counter,
    depth: int = 0,
    *,
    strict: bool = False,
) -> list[str]:
    """Validate the checksums reachable from an L3 payload named by
    ``ethertype``. Recurses through a GRE tunnel, whose inner protocol
    is itself an EtherType, through IP-in-IP (IP protocols 4 and 41),
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
    if ethertype == 0x0806:
        stats["arp"] += 1
        # ARP carries no checksum; under strict, at least insist on the
        # 28-byte Ethernet/IPv4 form rather than vouching for a stub.
        if strict and len(payload) < 28:
            return ["unchecked-ethertype-0x0806"]
        return []

    if ethertype == 0x0800 and len(payload) >= 20:
        return _check_ipv4(payload, stats, depth, strict=strict)

    if ethertype == 0x86DD and len(payload) >= 40:
        return _check_ipv6(payload, stats, depth, strict=strict)

    if strict:
        return [f"unchecked-ethertype-0x{ethertype:04x}"]
    stats[f"other-0x{ethertype:04x}"] += 1
    return []


def check_frame(frame: bytes, stats: Counter) -> list[str]:
    """Validate one Ethernet frame; returns a list of failure strings."""
    return _check_ethernet(frame, stats, 0)


def _check_ethernet(
    frame: bytes, stats: Counter, depth: int, *, strict: bool = False
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
    stats: Counter,
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
    stats: Counter,
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
    pdu: bytes, stats: Counter, depth: int, *, strict: bool = False
) -> list[str]:
    """Validate an 802.2 LLC PDU: its Control field fits (1 octet when
    the two low bits are 11, else 2), then SNAP (DSAP 0xAA), an 802.1D
    BPDU (DSAP 0x42) or a Novell raw 802.3 IPX packet (0xFFFF where the
    DSAP and SSAP would be), whose IPX length must be the PDU's."""
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
        return _check_bpdu(pdu[3:], stats)
    stats[f"llc-dsap-0x{pdu[0]:02x}"] += 1
    return [f"unchecked-llc-dsap-0x{pdu[0]:02x}"] if strict else []


def _check_bpdu(bpdu: bytes, stats: Counter) -> list[str]:
    """Validate an 802.1D BPDU's framing: Protocol Identifier 0, and as
    long as its type needs, 35 bytes for a Configuration BPDU (type
    0x00) and 4 for a Topology Change Notification (type 0x80)."""
    needed = {0x00: 35, 0x80: 4}.get(bpdu[3] if len(bpdu) > 3 else -1)
    if bpdu[:2] != b"\x00\x00" or needed is None or len(bpdu) < needed:
        return ["stp-bpdu-malformed"]
    stats["stp-bpdu"] += 1
    return []


def _check_snap(
    pdu: bytes, stats: Counter, depth: int, *, strict: bool = False
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
    total = sum(
        word for (word,) in struct.iter_unpack("!H", data[: len(data) & ~1])
    )
    if len(data) & 1:
        v = data[-1]
        total += (0xFF << 8) + v - 1 if v & 0x80 else v
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _check_cdp(pdu: bytes, stats: Counter) -> list[str]:
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

    corpus_stats: Counter = Counter()
    bad_files = 0
    total_frames = 0
    for pcap in pcaps:
        stats: Counter = Counter()
        failures: Counter = Counter()
        frames = 0
        try:
            for frame in read_pcap(pcap):
                frames += 1
                for failure in check_frame(frame, stats):
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
