#!/usr/bin/env python3
"""Decode-throughput benchmark over the real-capture fixture corpus.

    uv run --group bench python scripts/benchmark.py
    uv run --group bench python scripts/benchmark.py --compare
    uv run --group bench python scripts/benchmark.py --compare \
        --fixture ospf.pcap --fixture bgp.pcap
    uv run --group bench python scripts/benchmark.py --same-depth

The workload is every frame in ``tests/fixtures/`` walked from
``Ethernet`` to the end of its chain — the corpus exercises DNS, DHCP,
GRE, VLAN tags and IPv6 extension headers, which a single synthetic TCP
frame does not. Frames the library rejects are counted, not skipped, so
a change that "speeds things up" by decoding less shows up.

Comparison mode (``--compare``) times `dpkt` and `scapy` on the same
frames, and prints exactly what each library was asked to do. Both are
dev-only extras: the package itself has zero runtime dependencies.

``--fixture NAME``, repeatable, restricts the workload to the frames of
the named captures in ``tests/fixtures/``, each named by its file name
with or without ``.pcap``. ``--same-depth`` restricts it further to the
frames netprotocols and dpkt decode to the same depth, as ``--depth``
counts layers; it implies ``--compare``, and the selection pass is not
timed. The selection is made against dpkt alone: scapy is timed on the
same frames, but whether it decodes them to that depth is not checked.
``--json`` records the selection beside the figures.

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

from _pcap import read_pcap  # noqa: E402

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


def capture_name(name: str) -> str:
    """Return a capture's file name, adding ``.pcap`` if it is missing.

    :param name: A capture file name, with or without ``.pcap``.
    :return: The file name ending in ``.pcap``.
    """
    return name if name.endswith(".pcap") else f"{name}.pcap"


def select_frames(
    corpus: dict[str, list[bytes]], names: list[str]
) -> list[bytes]:
    """Return the frames of the named captures, in corpus order.

    :param corpus: Each capture's frames, keyed by its file name.
    :param names: Capture file names, each with or without ``.pcap``;
        an empty list selects every capture.
    :return: The frames of the selected captures.
    :raises ValueError: if a name matches no capture in ``corpus``.
    """
    wanted = {capture_name(name) for name in names}
    unknown = sorted(wanted - corpus.keys())
    if unknown:
        raise ValueError(
            f"unknown fixture {', '.join(unknown)}; "
            f"choose from: {', '.join(sorted(corpus))}"
        )
    return [
        frame
        for name in sorted(corpus)
        if not wanted or name in wanted
        for frame in corpus[name]
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


def depth_gap(
    frame: bytes,
    ours: Callable[[bytes], list[str]],
    theirs: Callable[[bytes], list[str]],
) -> tuple[list[str], list[str], int] | None:
    """Compare the layer chains two decoders give for one frame.

    Opaque payloads, the names ``theirs`` writes as ``<...>``, are not
    counted as layers.

    :param frame: The frame to decode.
    :param ours: Returns netprotocols' layer names for a frame.
    :param theirs: Returns the other library's layer names for a frame.
    :return: Both chains and the number of layers ``ours`` decodes
        beyond ``theirs``, negative where ``theirs`` decodes more; or
        ``None`` if either decoder rejects the frame.
    :raises ImportError: if ``theirs`` cannot import its library.
    """
    try:
        our_chain = ours(frame)
    except ProtocolError:
        return None
    try:
        their_chain = theirs(frame)
    except ImportError:
        raise
    except Exception:  # a parse failure is itself a result
        return None
    opaque = [name for name in their_chain if name.startswith("<")]
    return (
        our_chain,
        their_chain,
        len(our_chain) - (len(their_chain) - len(opaque)),
    )


def same_depth_frames(
    frames: list[bytes],
    ours: Callable[[bytes], list[str]],
    theirs: Callable[[bytes], list[str]],
) -> list[bytes]:
    """Return the frames both decoders decode to the same depth.

    :param frames: The frames to select from.
    :param ours: Returns netprotocols' layer names for a frame.
    :param theirs: Returns the other library's layer names for a frame.
    :return: The frames, in order, whose depth gap is zero.
    :raises ImportError: if ``theirs`` cannot import its library.
    """
    selected = []
    for frame in frames:
        measured = depth_gap(frame, ours, theirs)
        if measured is not None and measured[2] == 0:
            selected.append(frame)
    return selected


def depth_report(frames: list[bytes]) -> list[str]:
    """Report where each library stops decoding, frame by frame.

    Each library decodes the same bytes, so a throughput figure can be
    read next to the work each one performed.
    """
    lines = ["", "Decode depth on the same frames:", ""]
    deeper, same, example = 0, 0, ""
    for frame in frames:
        try:
            measured = depth_gap(frame, _netprotocols_chain, _dpkt_chain)
        except ImportError:
            return [*lines, "  dpkt not installed - skipped"]
        if measured is None:
            continue
        ours, theirs, gap = measured
        if gap > 0:
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


def main(argv: list[str] | None = None) -> int:
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
        "--fixture",
        action="append",
        default=[],
        metavar="NAME",
        help="time only this capture's frames (repeatable)",
    )
    parser.add_argument(
        "--same-depth",
        action="store_true",
        help="time only the frames netprotocols and dpkt decode to the"
        " same depth (selected against dpkt, not scapy); implies --compare",
    )
    parser.add_argument("--json", type=Path, help="write the results here")
    args = parser.parse_args(argv)

    corpus = {path.name: read_pcap(path) for path in FIXTURES.glob("*.pcap")}
    if not corpus:
        print(f"No fixtures found under {FIXTURES}", file=sys.stderr)
        return 1
    fixtures = sorted({capture_name(name) for name in args.fixture})
    try:
        frames = select_frames(corpus, args.fixture)
    except ValueError as error:
        parser.error(str(error))
    total = sum(len(captured) for captured in corpus.values())
    selection = []
    if args.fixture:
        selection.append(f"{len(frames)} frames in {', '.join(fixtures)}")
    if args.same_depth:
        args.compare = True
        try:
            same = same_depth_frames(frames, _netprotocols_chain, _dpkt_chain)
        except ImportError:
            parser.error("--same-depth needs dpkt: run with --group bench")
        selection.append(
            f"{len(same)} of {len(frames)} decoded to the same depth by"
            " netprotocols and dpkt (scapy's depth is not checked)"
        )
        frames = same
    if not frames:
        print("No frames selected", file=sys.stderr)
        return 1

    result = measure(frames, args.repetitions, args.trials)
    result["recorded"] = {
        "on": f"CPython {platform.python_version()} / {platform.machine()}"
        f" / {platform.system()}",
        "python": platform.python_version(),
        "netprotocols": __import__("netprotocols").__version__,
    }
    result["selection"] = {
        "fixtures": fixtures,
        "same_depth": args.same_depth,
        "frames_selected": len(frames),
        "frames_total": total,
    }

    print(
        f"netprotocols {result['recorded']['netprotocols']} — "
        f"{result['frames']} corpus frames, "
        f"{result['repetitions']} repetitions, best of {result['trials']}"
    )
    print(f"  {result['frames_per_sec']:>12,.0f} frames/sec")
    print(f"  on {result['recorded']['on']}")
    if selection:
        print(f"  selected {len(frames)} of {total} corpus frames:")
        print("\n".join(f"    {line}" for line in selection))

    if args.compare:
        print("\n".join(compare(frames, args.repetitions, args.trials)))
    if args.depth:
        print("\n".join(depth_report(frames)))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
