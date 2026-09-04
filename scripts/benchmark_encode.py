#!/usr/bin/env python3
"""Encoding-throughput benchmark: ``bytes(header)`` re-serialization.

    uv run --group bench python scripts/benchmark_encode.py

Decodes a single synthetic Ethernet/IPv4/UDP frame with each library,
then times re-serializing the decoded object back to bytes. This is the
half of "codec" throughput ``scripts/benchmark.py`` does not cover:
decode-then-encode, not decode alone. dpkt and netprotocols both rebuild
their bytes from fields on every call; scapy returns a cached copy of
the bytes it was built from unless a field changed, so its number here
is not a like-for-like repack (see docs/CLAIMS.md 1.3).
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

#: One synthetic Ethernet frame: dst/src MAC, EtherType IPv4, a minimal
#: IPv4 header (proto UDP) and a minimal UDP header with 4 bytes payload.
FRAME = bytes.fromhex(
    "001122334455"
    "66778899aabb"
    "0800"
    "4500002e00000000401100000a0000010a000002"
    "0035003500160000"
    "00000000"
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


def bench_netprotocols(trials: int, reps: int) -> float:
    from netprotocols import Ethernet

    header = Ethernet.decode(FRAME)
    return best_of(lambda: bytes(header), trials, reps)


def bench_dpkt(trials: int, reps: int) -> float | None:
    try:
        import dpkt
    except ImportError:
        return None
    header = dpkt.ethernet.Ethernet(FRAME)
    return best_of(lambda: bytes(header), trials, reps)


def bench_scapy(trials: int, reps: int) -> float | None:
    try:
        from scapy.layers.l2 import Ether
    except ImportError:
        return None
    header = Ether(FRAME)
    return best_of(lambda: bytes(header), trials, reps)


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
