#!/usr/bin/env python3
"""Decode-throughput benchmark over the real-capture fixture corpus.

    uv run --group bench python scripts/benchmark.py
    uv run --group bench python scripts/benchmark.py --compare
    uv run --group bench python scripts/benchmark.py --check

The workload is every frame in ``tests/fixtures/`` walked from
``Ethernet`` to the end of its chain — the corpus exercises DNS, DHCP,
GRE, VLAN tags and IPv6 extension headers, which a single synthetic TCP
frame does not. Frames the library rejects are counted, not skipped, so
a change that "speeds things up" by decoding less shows up.

Comparison mode (``--compare``) times `dpkt` and `scapy` on the same
frames, and prints exactly what each library was asked to do — the
comparison is only worth publishing if that is on the record. Both are
dev-only extras: the package itself still has zero runtime dependencies.

Cross-machine comparison
------------------------
Absolute frames/sec is a property of the machine as much as the code, so
a committed baseline cannot be compared to a run on someone else's
hardware — or on whichever shared runner CI lands. Every run therefore
also times a fixed calibration workload built from the same primitives
as the decode path (``struct`` unpacking, slicing, dict lookups) and
reports throughput normalized by it. The normalized figure is what
``--check`` compares; the absolute one is what you quote, with the
machine named.

``--check`` re-measures with whatever settings the baseline recorded,
rather than trusting the caller to match them.

Normalization cancels how fast the *machine* is; it does not cancel the
interpreter. Measured here, the same code and machine normalize to 6.8
on CPython 3.12 and 7.6 on 3.13, because the release speeds the decode
path and the calibration workload up by different amounts. A baseline
is therefore tied to the Python version that recorded it — ``--check``
says so when they differ, and the CI job pins one version.
"""

from __future__ import annotations

import argparse
import json
import platform
import struct
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

#: Calibration passes per trial. Fixed, and large enough that a pass
#: takes tens of milliseconds: timing a workload that runs for barely a
#: millisecond measures the scheduler, not the machine, and the noise
#: lands straight in the normalized figure the regression gate reads.
CALIBRATION_PASSES = 1000

REPOSITORY = Path(__file__).resolve().parent.parent
FIXTURES = REPOSITORY / "tests" / "fixtures"
BASELINE = REPOSITORY / "benchmarks" / "baseline.json"

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


def calibration_workload() -> int:
    """A fixed unit of work built from the decode path's primitives.

    Used only as a speed reference for the machine, so a baseline
    recorded elsewhere stays comparable. Deliberately not a decode: it
    must not change when the decoder does.
    """
    header = struct.Struct("!BBHHHBBH4s4s")
    buffer = bytes(range(64))
    table = {number: number * 2 for number in range(16)}
    total = 0
    for _ in range(200):
        fields = header.unpack_from(buffer)
        total += fields[0] + len(buffer[20:40])
        total += table.get(fields[1] & 0x0F, 0)
    return total


def best_of(work: Callable[[], Any], trials: int) -> float:
    """Shortest wall-clock time of ``trials`` runs.

    The minimum, not the mean: a benchmark process is only ever
    interrupted, never helped, so the fastest run is the closest to the
    cost of the code itself.
    """
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
    frames_per_sec = (repetitions * len(frames)) / seconds

    def calibration_pass() -> None:
        for _ in range(CALIBRATION_PASSES):
            calibration_workload()

    calibration_seconds = best_of(calibration_pass, trials)
    calibration_per_sec = CALIBRATION_PASSES / calibration_seconds

    return {
        "frames_per_sec": round(frames_per_sec, 1),
        "calibration_per_sec": round(calibration_per_sec, 1),
        "normalized": round(frames_per_sec / calibration_per_sec, 4),
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
    """Read these before quoting the table above anywhere.

    The point of this harness is a comparison someone can trust, and no
    two of these libraries do quite the same work per frame. Saying so
    is part of the measurement, not a disclaimer bolted onto it.
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
    return [type(layer).__name__ for layer in decode_frame(frame)]


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
    """Where the libraries stop, frame by frame.

    Throughput means little without this: a decoder that gives up
    earlier has less to do. This reports where each library stops on
    the same bytes, so a speed comparison can be read next to the work
    each one actually performed.
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


def check(
    current: dict[str, Any], baseline_path: Path, threshold: float
) -> int:
    """Compare a run against a committed baseline; 0 if within bounds."""
    if not baseline_path.exists():
        print(f"No baseline at {baseline_path}; run --update-baseline first.")
        return 1
    baseline = json.loads(baseline_path.read_text())
    before = baseline["normalized"]
    now = current["normalized"]
    change = (now - before) / before * 100
    print(
        f"\nnormalized throughput: {now:.4f} against baseline "
        f"{before:.4f} ({change:+.1f}%)"
    )
    print(f"baseline recorded: {baseline['recorded']['on']}")
    running = platform.python_version()
    recorded_on = baseline["recorded"].get("python", running)
    if recorded_on.rsplit(".", 1)[0] != running.rsplit(".", 1)[0]:
        print(
            f"NOTE: this run is CPython {running}, the baseline is "
            f"{recorded_on}. Normalization cancels machine speed, not the "
            "interpreter, so the comparison below is indicative only."
        )
    if change < -threshold:
        print(
            f"REGRESSION: more than {threshold:.0f}% below the baseline.\n"
            "If this is expected, re-record with --update-baseline and say "
            "why in the pull request."
        )
        return 1
    print(f"Within the {threshold:.0f}% threshold.")
    return 0


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
    parser.add_argument(
        "--check", action="store_true", help="fail on a regression"
    )
    parser.add_argument("--update-baseline", action="store_true")
    # CI passes this explicitly so the gate's number is visible in
    # ci.yml; the default matches it so a local run gates the same.
    parser.add_argument("--threshold", type=float, default=15.0)
    parser.add_argument("--json", type=Path, help="write the results here")
    args = parser.parse_args()

    frames = corpus_frames(FIXTURES)
    if not frames:
        print(f"No fixtures found under {FIXTURES}", file=sys.stderr)
        return 1

    repetitions, trials = args.repetitions, args.trials
    if args.check and BASELINE.exists():
        # Both figures are a best-of, so they tighten as trials rise --
        # at different rates. A baseline is therefore only comparable to
        # a run with the same settings, and the baseline's win.
        recorded = json.loads(BASELINE.read_text())
        repetitions = recorded.get("repetitions", repetitions)
        trials = recorded.get("trials", trials)
        if (repetitions, trials) != (args.repetitions, args.trials):
            print(
                f"Measuring with the baseline's settings "
                f"({repetitions} repetitions, best of {trials})."
            )

    result = measure(frames, repetitions, trials)
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
    print(f"  {result['normalized']:>12.4f} normalized (machine-independent)")
    print(f"  on {result['recorded']['on']}")

    if args.compare:
        print("\n".join(compare(frames, args.repetitions, args.trials)))
    if args.depth:
        print("\n".join(depth_report(frames)))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n")
    if args.update_baseline:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(result, indent=2) + "\n")
        print(f"\nBaseline written to {BASELINE.relative_to(REPOSITORY)}")
    if args.check:
        status = check(result, BASELINE, args.threshold)
        if status != 0:
            print(
                "\nRe-measuring once before failing: a shared runner can "
                "lose a slice of CPU to a neighbour mid-run. A real "
                "regression fails this second attempt too."
            )
            second = measure(frames, repetitions, trials)
            second["recorded"] = result["recorded"]
            status = check(second, BASELINE, args.threshold)
        return status
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
