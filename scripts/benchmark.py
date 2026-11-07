#!/usr/bin/env python3
"""Decode-throughput benchmark over the real-capture fixture corpus.

    uv run --group bench python scripts/benchmark.py
    uv run --group bench python scripts/benchmark.py --compare

The workload is every frame in ``tests/fixtures/`` walked from
``Ethernet`` to the end of its chain — the corpus exercises DNS, DHCP,
GRE, VLAN tags and IPv6 extension headers, which a single synthetic TCP
frame does not. Frames the library rejects are counted, not skipped, so
a change that "speeds things up" by decoding less shows up.

Comparison mode (``--compare``) times `dpkt` and `scapy` on the same
frames, and prints exactly what each library was asked to do. Both are
dev-only extras: the package itself has zero runtime dependencies.

Absolute frames/sec is a property of the machine as much as the code;
quote it with the machine named. ``scripts/benchmark_ab.py`` compares
two trees of this library on one machine, which is what CI gates on.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parent.parent
FIXTURES = REPOSITORY / "tests" / "fixtures"

sys.path.insert(0, str(REPOSITORY / "src"))
sys.path.insert(0, str(REPOSITORY / "scripts"))

from _pcap import corpus_frames  # noqa: E402

from netprotocols import ProtocolError, decode_frame  # noqa: E402


def decode_netprotocols(frames: list[bytes]) -> int:
    decoded = 0
    for frame in frames:
        try:
            decode_frame(frame)
        except ProtocolError:
            continue
        decoded += 1
    return decoded


def decode_dpkt(frames: list[bytes]) -> int:
    import dpkt

    decoded = 0
    for frame in frames:
        try:
            dpkt.ethernet.Ethernet(frame)
        except Exception:  # dpkt has no shared "malformed frame" exception
            continue
        decoded += 1
    return decoded


def decode_scapy(frames: list[bytes]) -> int:
    from scapy.layers.l2 import Ether

    decoded = 0
    for frame in frames:
        try:
            packet = Ether(frame)
            packet.layers()  # force the lazy chain to materialize
        except Exception:  # scapy has no shared "malformed frame" exception
            continue
        decoded += 1
    return decoded


def best_of(work: Callable[[], Any], trials: int) -> float:
    """Shortest wall-clock time of ``trials`` runs, after one warm-up run."""
    work()  # warm caches and imports
    return min(_timed(work) for _ in range(trials))


def _timed(work: Callable[[], Any]) -> float:
    start = time.perf_counter()
    work()
    return time.perf_counter() - start


def measure(
    frames: list[bytes], repetitions: int, trials: int
) -> dict[str, Any]:
    def decode_pass() -> None:
        for _ in range(repetitions):
            decode_netprotocols(frames)

    seconds = best_of(decode_pass, trials)
    return {
        "frames_per_sec": round((repetitions * len(frames)) / seconds, 1),
        "frames": len(frames),
        "repetitions": repetitions,
        "trials": trials,
    }


def compare(frames: list[bytes], repetitions: int, trials: int) -> list[str]:
    """Time the comparators on the same frames; skip any not installed."""
    contenders = [
        ("netprotocols", decode_netprotocols, "walks and materializes"),
        ("dpkt", decode_dpkt, "builds its object chain eagerly"),
        ("scapy", decode_scapy, "dissects, then .layers() forces it"),
    ]
    lines = ["", "Comparison (same frames, same loop):", ""]
    results: list[tuple[str, float, int, str]] = []
    for name, decoder, note in contenders:
        try:
            decoded = decoder(frames)
        except ImportError:
            lines.append(f"  {name:<14} not installed — skipped")
            continue

        def one_pass(decoder: Any = decoder) -> None:
            for _ in range(repetitions):
                decoder(frames)

        seconds = best_of(one_pass, trials)
        results.append(
            (name, (repetitions * len(frames)) / seconds, decoded, note)
        )
    if results:
        ours = next((r[1] for r in results if r[0] == "netprotocols"), None)
        for name, rate, decoded, note in results:
            ratio = "" if ours is None else f"  ({rate / ours:.2f}x ours)"
            lines.append(
                f"  {name:<14} {rate:>10,.0f} frames/sec{ratio}\n"
                f"  {'':<14} {decoded}/{len(frames)} frames decoded; {note}"
            )
        lines.extend(_comparison_caveats())
    return lines


def _comparison_caveats() -> list[str]:
    """Print how the libraries' work per frame differs.

    Printed with the throughput table, which is not comparable without
    it.
    """
    return [
        "",
        "  Caveats — the libraries are not asked for identical work:",
        "   - They do not parse to the same depth. On the DNS-over-TCP",
        "     frames dpkt stops at TCP and leaves the payload as raw",
        "     bytes, where netprotocols continues into DNSOverTCP and",
        "     DNS. Where the depths differ, netprotocols is doing more.",
        "   - netprotocols materializes every header as a frozen",
        "     dataclass; dpkt builds objects with lazy attributes;",
        "     scapy is asked for .layers() so its dissection is not",
        "     deferred past the timed region.",
        "   - One machine, one corpus, one CPython. Quote the machine",
        "     with the number, and re-measure before every release.",
    ]


def _netprotocols_chain(frame: bytes) -> list[str]:
    return [type(layer).__name__ for layer in decode_frame(frame).layers]


def _dpkt_chain(frame: bytes) -> list[str]:
    import dpkt

    layer: Any = dpkt.ethernet.Ethernet(frame)
    names = []
    while True:
        names.append(type(layer).__name__)
        payload = getattr(layer, "data", None)
        if payload is None or isinstance(payload, (bytes, bytearray)):
            if payload:
                names.append(f"<{len(payload)} raw bytes>")
            return names
        layer = payload


def depth_report(frames: list[bytes]) -> list[str]:
    """Report where each library stops decoding, frame by frame.

    Each library decodes the same bytes, so a throughput figure can be
    read next to the work each one performed.
    """
    lines = ["", "Decode depth on the same frames:", ""]
    deeper, same, example = 0, 0, ""
    for frame in frames:
        try:
            ours = _netprotocols_chain(frame)
        except ProtocolError:
            continue
        try:
            theirs = _dpkt_chain(frame)
        except ImportError:
            return [*lines, "  dpkt not installed - skipped"]
        except Exception:  # a parse failure is itself a result
            continue
        opaque = [name for name in theirs if name.startswith("<")]
        if len(ours) > len(theirs) - len(opaque):
            deeper += 1
            if not example:
                example = (
                    f"    netprotocols: {' -> '.join(ours)}\n"
                    f"    dpkt:         {' -> '.join(theirs)}"
                )
        else:
            same += 1
    lines.append(f"  netprotocols decodes further on {deeper} frames")
    lines.append(f"  both stop at the same layer on {same} frames")
    if example:
        lines.extend(["", "  A frame where they differ:", example])
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=40)
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument(
        "--compare", action="store_true", help="also time dpkt and scapy"
    )
    parser.add_argument(
        "--depth",
        action="store_true",
        help="report where each library stops decoding",
    )
    parser.add_argument("--json", type=Path, help="write the results here")
    args = parser.parse_args()

    frames = corpus_frames(FIXTURES)
    if not frames:
        print(f"No fixtures found under {FIXTURES}", file=sys.stderr)
        return 1

    result = measure(frames, args.repetitions, args.trials)
    result["recorded"] = {
        "on": f"CPython {platform.python_version()} / {platform.machine()}"
        f" / {platform.system()}",
        "python": platform.python_version(),
        "netprotocols": __import__("netprotocols").__version__,
    }

    print(
        f"netprotocols {result['recorded']['netprotocols']} — "
        f"{result['frames']} corpus frames, "
        f"{result['repetitions']} repetitions, best of {result['trials']}"
    )
    print(f"  {result['frames_per_sec']:>12,.0f} frames/sec")
    print(f"  on {result['recorded']['on']}")

    if args.compare:
        print("\n".join(compare(frames, args.repetitions, args.trials)))
    if args.depth:
        print("\n".join(depth_report(frames)))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
