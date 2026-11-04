#!/usr/bin/env python3
"""Encoding-throughput benchmark: whole-frame ``bytes(...)`` re-serialization.

    uv run --group bench python scripts/benchmark_encode.py

Decodes a single synthetic Ethernet/IPv4/UDP frame with each library,
then times re-serializing the whole decoded frame back to bytes. This
is the half of "codec" throughput ``scripts/benchmark.py`` does not
cover: decode-then-encode, not decode alone. Every library re-encodes
the same work, all 42 bytes of three layers, and each output is
asserted equal to ``FRAME`` before anything is timed. dpkt and
netprotocols both rebuild their bytes from fields on every call; scapy
returns a cached copy of the bytes it was built from unless a field
changed, so its number here is not a like-for-like repack (see
docs/CLAIMS.md 1.3).
"""

from __future__ import annotations

import argparse
import platform
import sys
import time
from collections.abc import Callable
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY / "src"))

#: One synthetic frame for a whole-frame, like-for-like comparison: every
#: library decodes all of it in strict mode and re-encodes it to these
#: exact bytes. Ethernet (IPv4), IPv4 (proto UDP, no options) and UDP with
#: no payload: a netprotocols Packet holds decoded headers only, so bytes
#: it leaves undecoded would not come back out. The UDP ports, 40000 and
#: 50000, are registered in no library's dispatch (port 53 would dispatch
#: to DNS in netprotocols, and a short payload is a truncated DNS header),
#: and both checksums are precomputed and valid, so no library computes
#: one while encoding (dpkt fills a zero IPv4 checksum when it serializes).
FRAME = bytes.fromhex(
    "001122334455"
    "66778899aabb"
    "0800"
    "4500001c00000000401166cf0a0000010a000002"
    "9c40c35000088c4a"
)


def best_of(work: Callable[[], object], trials: int, reps: int) -> float:
    """Highest ops/sec across ``trials`` timed passes of ``reps`` calls."""
    work()  # warm caches and imports
    best_seconds = min(_timed(work, reps) for _ in range(trials))
    return reps / best_seconds


def _timed(work: Callable[[], object], reps: int) -> float:
    start = time.perf_counter()
    for _ in range(reps):
        work()
    return time.perf_counter() - start


def _check(library: str, encoded: bytes) -> None:
    """Fail loudly unless ``library`` re-encodes ``FRAME`` byte for byte."""
    if encoded != FRAME:
        raise SystemExit(
            f"{library} re-encoded {len(encoded)} bytes that differ from "
            f"FRAME ({len(FRAME)} bytes):\n  got  {encoded.hex()}\n"
            f"  want {FRAME.hex()}"
        )


def bench_netprotocols(trials: int, reps: int) -> float:
    from netprotocols import decode_frame

    packet = decode_frame(FRAME)
    _check("netprotocols", bytes(packet))
    return best_of(lambda: bytes(packet), trials, reps)


def bench_dpkt(trials: int, reps: int) -> float | None:
    try:
        import dpkt
    except ImportError:
        return None
    frame = dpkt.ethernet.Ethernet(FRAME)
    _check("dpkt", bytes(frame))
    return best_of(lambda: bytes(frame), trials, reps)


def bench_scapy(trials: int, reps: int) -> float | None:
    try:
        from scapy.layers.l2 import Ether
    except ImportError:
        return None
    frame = Ether(FRAME)
    _check("scapy", bytes(frame))
    return best_of(lambda: bytes(frame), trials, reps)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=9)
    parser.add_argument("--reps", type=int, default=20_000)
    args = parser.parse_args()

    print(
        f"CPython {platform.python_version()} / {platform.machine()} "
        f"/ {platform.system()}"
    )
    print(f"best of {args.trials} trials, {args.reps} reps/trial\n")

    ours = bench_netprotocols(args.trials, args.reps)
    print(f"  {'netprotocols':<14} {ours:>12,.0f} ops/sec")

    for name, bench in (("dpkt", bench_dpkt), ("scapy", bench_scapy)):
        rate = bench(args.trials, args.reps)
        if rate is None:
            print(f"  {name:<14} not installed — skipped")
        else:
            print(
                f"  {name:<14} {rate:>12,.0f} ops/sec  "
                f"({ours / rate:.2f}x ours)"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
