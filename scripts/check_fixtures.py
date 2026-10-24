#!/usr/bin/env python3
"""Validate the internal checksum consistency of captured fixture pcaps.

Deliberately standalone (stdlib only, its own RFC 1071 implementation,
its own minimal parsers): it must be able to disqualify a capture even
if netprotocols itself has a bug, and later it cross-validates the
library's checksum module (plan item L-2) with an independent
implementation.

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
    src, dst = header[12:16], header[16:20]
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
        proto, src, dst, upper, stats, depth, strict=strict
    )


def _check_upper_v4(
    proto: int,
    src: bytes,
    dst: bytes,
    upper: bytes,
    stats: Counter,
    depth: int,
    *,
    strict: bool = False,
) -> list[str]:
    """Validate what an IPv4 header (``src``/``dst``) carries as
    protocol ``proto`` — directly, or behind IPsec in transport mode,
    where the pseudo-header is still the IPv4 header's.

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
    upper_len = len(upper)
    if proto == 1 and upper_len >= 8:
        return _check_icmpv4(upper, stats)
    if proto == 2 and upper_len >= 8:
        return _check_igmp(upper, stats)
    if proto == 6 and upper_len >= 20:
        return _check_tcp(src, dst, upper, stats)
    if proto == 17 and upper_len >= 8:
        return _check_udp(src, dst, upper, stats, depth, strict=strict)
    if proto == 47 and upper_len >= 4:
        return _check_gre(src, dst, upper, stats, depth, strict=strict)
    if proto in _IP_IN_IP:
        return _check_ip_in_ip(proto, upper, stats, depth, strict=strict)
    if proto == 50:
        return _check_esp(src, dst, upper, stats, depth, ipv6=False)
    return [f"unchecked-protocol-{proto}"] if strict else []


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


#: The IANA-assigned VXLAN destination port (RFC 7348 §5).
_VXLAN_PORT = 4789


def _check_udp_payload(
    datagram: bytes, stats: Counter, depth: int, *, strict: bool = False
) -> list[str]:
    """Validate what a UDP datagram tunnels, if anything: a VXLAN
    payload (destination port 4789, RFC 7348 §5) is an 8-byte header
    and then a whole Ethernet frame, validated in turn.

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
    if struct.unpack_from("!H", datagram, 2)[0] != _VXLAN_PORT:
        return []
    if len(datagram) < 8 + 8:
        stats["vxlan-truncated"] += 1
        return ["vxlan-truncated"] if strict else []
    stats["vxlan"] += 1
    return _check_ethernet(datagram[16:], stats, depth + 1, strict=strict)


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
}
_ICV_LEN = 16

#: How many encapsulations (GRE, IP-in-IP, IPsec) one frame may nest
#: before the checker refuses it. The corpus peaks at 1; the bound
#: exists so a hostile capture cannot exhaust the interpreter's stack.
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
    src: bytes,
    dst: bytes,
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
    return check(next_header, src, dst, inner, stats, depth + 1, strict=True)


def _check_ipv6(
    payload: bytes, stats: Counter, depth: int, *, strict: bool = False
) -> list[str]:
    failures: list[str] = []
    stats["ipv6"] += 1
    payload_length, next_header = struct.unpack_from("!HB", payload, 4)
    src, dst = payload[8:24], payload[24:40]
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
        next_header, src, dst, upper, stats, depth, strict=strict
    )


def _check_upper_v6(
    next_header: int,
    src: bytes,
    dst: bytes,
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
    upper_len = len(upper)
    if next_header == 58 and upper_len >= 4:
        return _check_icmpv6(src, dst, upper, stats)
    if next_header == 6 and upper_len >= 20:
        return _check_tcp6(src, dst, upper, stats)
    if next_header == 17 and upper_len >= 8:
        return _check_udp6(src, dst, upper, stats, depth, strict=strict)
    if next_header in _IP_IN_IP:
        return _check_ip_in_ip(next_header, upper, stats, depth, strict=strict)
    if next_header == 50:
        return _check_esp(src, dst, upper, stats, depth, ipv6=True)
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
    NULL-encrypted ESP after verifying its ICV; ESP on an
    SA whose key is not published fails. Nesting deeper than
    ``_MAX_DEPTH`` fails. Under ``strict`` (anything an ESP ICV
    vouched for, at any depth below it) a payload the checker cannot
    read fails too: an unknown protocol or EtherType, a header too
    short to check, or a fragment. Returns a list of failure strings."""
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

    return _check_l3(ethertype, payload, stats, depth, strict=strict)


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
