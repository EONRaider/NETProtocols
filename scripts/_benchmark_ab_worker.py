#!/usr/bin/env python3
"""One tree's side of ``scripts/benchmark_ab.py``, run in its own process.

    python -I -S -B _benchmark_ab_worker.py SRC FIXTURES probe
    python -I -S -B _benchmark_ab_worker.py SRC FIXTURES time \\
        --repetitions 20 --trials 5 --skip 3,17

``SRC`` is a tree's ``src`` directory. It goes first on ``sys.path``,
followed by this file's own directory for ``_pcap``, which imports only
the standard library. ``netprotocols`` is therefore imported from
``SRC`` and from nowhere else. ``-I`` drops ``PYTHONPATH``, the user
site directory and the script's directory from ``sys.path``; ``-S``
drops ``site-packages``, and with it any installed or editable
``netprotocols``; ``-B`` writes no bytecode into ``SRC``.

The frames are every frame of every ``*.pcap`` directly under
``FIXTURES``, numbered from 0 in ``_pcap.corpus_frames`` order.

``probe`` decodes each frame once and prints, as one JSON object, where
``netprotocols`` was imported from, every loaded ``netprotocols``
module that has no file or whose file lies outside ``SRC``, the
library's version, whether bytecode writing and ``site`` are on, the
frame count, and the numbers of the frames whose decode raised.

``time`` drops the frames numbered in ``--skip``, then times
``--repetitions`` decode passes over the rest, ``--trials`` times after
one untimed warm-up, and prints the shortest time in seconds, the frame
count and the number of frames whose decode raised.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any


def _load(src: Path) -> Any:
    sys.path[:0] = [str(src), str(Path(__file__).resolve().parent)]
    import netprotocols

    return netprotocols


def _decode_all(decode: Callable[[bytes], Any], frames: list[bytes]) -> int:
    """Decode each frame once; return how many raised."""
    rejected = 0
    for frame in frames:
        try:
            decode(frame)
        except Exception:  # a frame a tree cannot decode is counted
            rejected += 1
    return rejected


def probe(library: Any, src: Path, frames: list[bytes]) -> dict[str, Any]:
    """Report the import's provenance and the frames that raise."""
    root = src.resolve()
    outside = []
    for name, module in sorted(sys.modules.items()):
        if name != "netprotocols" and not name.startswith("netprotocols."):
            continue
        file = getattr(module, "__file__", None)
        if file is None or not Path(file).resolve().is_relative_to(root):
            outside.append(name)
    raises = []
    for number, frame in enumerate(frames):
        if _decode_all(library.decode_frame, [frame]):
            raises.append(number)
    return {
        "file": str(Path(library.__file__).resolve()),
        "outside": outside,
        "version": getattr(library, "__version__", "unknown"),
        "frames": len(frames),
        "raises": raises,
        "bytecode_written": not sys.dont_write_bytecode,
        "site": not sys.flags.no_site,
    }


def time_decode(
    library: Any, frames: list[bytes], repetitions: int, trials: int
) -> dict[str, Any]:
    """Time decode passes over ``frames``; report the shortest."""
    decode = library.decode_frame

    def one_pass() -> int:
        rejected = 0
        for _ in range(repetitions):
            rejected = _decode_all(decode, frames)
        return rejected

    rejected = one_pass()
    best = float("inf")
    for _ in range(trials):
        start = time.perf_counter()
        one_pass()
        best = min(best, time.perf_counter() - start)
    return {"seconds": best, "frames": len(frames), "rejected": rejected}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("src", type=Path)
    parser.add_argument("fixtures", type=Path)
    parser.add_argument("mode", choices=("probe", "time"))
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--skip", default="")
    args = parser.parse_args(argv)

    library = _load(args.src)
    from _pcap import corpus_frames

    frames = corpus_frames(args.fixtures)
    if args.mode == "probe":
        result = probe(library, args.src, frames)
    else:
        skip = {int(number) for number in args.skip.split(",") if number}
        kept = [f for n, f in enumerate(frames) if n not in skip]
        result = time_decode(library, kept, args.repetitions, args.trials)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
