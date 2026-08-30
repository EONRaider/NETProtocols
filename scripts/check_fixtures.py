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


def check_frame(frame: bytes, stats: Counter) -> list[str]:
    """Validate one Ethernet frame; returns a list of failure strings."""
    failures: list[str] = []
    if len(frame) < 14:
        stats["runt"] += 1
        return failures
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    payload = frame[14:]

    if ethertype == 0x0806:
        stats["arp"] += 1
        return failures

    if ethertype == 0x0800 and len(payload) >= 20:
        ihl = (payload[0] & 0x0F) * 4
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
            return failures  # non-first fragment: no upper-layer header
        if flags_frag & 0x2000 == 0x2000 and flags_frag & 0x1FFF == 0:
            stats["ipv4-first-fragment"] += 1
            return failures  # first fragment: upper checksum spans all parts
        upper = payload[ihl:total_length]
        upper_len = len(upper)
        if proto == 1 and upper_len >= 8:
            stats["icmpv4"] += 1
            if (
                internet_checksum(upper[:2] + b"\x00\x00" + upper[4:])
                != struct.unpack_from("!H", upper, 2)[0]
            ):
                failures.append("icmpv4-checksum")
        elif proto == 2 and upper_len >= 8:
            stats["igmp"] += 1
            # IGMP: whole message, checksum at bytes 2-3, no pseudo-header.
            if (
                internet_checksum(upper[:2] + b"\x00\x00" + upper[4:])
                != struct.unpack_from("!H", upper, 2)[0]
            ):
                failures.append("igmp-checksum")
        elif proto == 6 and upper_len >= 20:
            stats["tcp"] += 1
            zeroed = upper[:16] + b"\x00\x00" + upper[18:]
            if (
                internet_checksum(pseudo_v4(src, dst, 6, upper_len) + zeroed)
                != struct.unpack_from("!H", upper, 16)[0]
            ):
                failures.append("tcp-checksum")
        elif proto == 17 and upper_len >= 8:
            stats["udp"] += 1
            wire = struct.unpack_from("!H", upper, 6)[0]
            if wire == 0:
                stats["udp-no-checksum"] += 1
            else:
                zeroed = upper[:6] + b"\x00\x00" + upper[8:]
                computed = (
                    internet_checksum(
                        pseudo_v4(src, dst, 17, upper_len) + zeroed
                    )
                    or 0xFFFF
                )
                if computed != wire:
                    failures.append("udp-checksum")
        return failures

    if ethertype == 0x86DD and len(payload) >= 40:
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
                return failures  # non-first fragment: no upper header
            stats["ipv6-first-fragment"] += 1
            # The upper-layer checksum spans the reassembled datagram,
            # not this fragment's slice: nothing verifiable here.
            return failures
        upper_len = len(upper)
        if next_header == 58 and upper_len >= 4:
            stats["icmpv6"] += 1
            zeroed = upper[:2] + b"\x00\x00" + upper[4:]
            if (
                internet_checksum(pseudo_v6(src, dst, 58, upper_len) + zeroed)
                != struct.unpack_from("!H", upper, 2)[0]
            ):
                failures.append("icmpv6-checksum")
        elif next_header == 6 and upper_len >= 20:
            stats["tcp6"] += 1
            zeroed = upper[:16] + b"\x00\x00" + upper[18:]
            if (
                internet_checksum(pseudo_v6(src, dst, 6, upper_len) + zeroed)
                != struct.unpack_from("!H", upper, 16)[0]
            ):
                failures.append("tcp6-checksum")
        elif next_header == 17 and upper_len >= 8:
            stats["udp6"] += 1
            zeroed = upper[:6] + b"\x00\x00" + upper[8:]
            computed = (
                internet_checksum(pseudo_v6(src, dst, 17, upper_len) + zeroed)
                or 0xFFFF
            )
            if computed != struct.unpack_from("!H", upper, 6)[0]:
                failures.append("udp6-checksum")
        return failures

    stats[f"other-0x{ethertype:04x}"] += 1
    return failures


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
