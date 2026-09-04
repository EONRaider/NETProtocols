#!/usr/bin/env python3
"""Import-time benchmark: cold-process ``import X``, best of N.

    uv run --group bench python scripts/benchmark_import.py

Each library is timed in its own fresh subprocess — module caching
makes re-importing within one process meaningless past the first call.
Reports the fastest of ``--trials`` runs (a process is only ever slowed
by scheduler noise, never sped up) alongside the module count each
import pulled into ``sys.modules``. See docs/CLAIMS.md 1.4.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

_PROBE = (
    "import sys, time\n"
    "before = set(sys.modules)\n"
    "start = time.perf_counter()\n"
    "import {module}\n"
    "elapsed_ms = (time.perf_counter() - start) * 1000\n"
    "loaded = len(set(sys.modules) - before)\n"
    "print(f'{{elapsed_ms:.1f}} {{loaded}}')\n"
)


def best_of(module: str, trials: int) -> tuple[float | None, int | None]:
    best_ms, modules = None, None
    for _ in range(trials):
        result = subprocess.run(
            [sys.executable, "-c", _PROBE.format(module=module)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return None, None  # not installed, or import failed
        ms, loaded = result.stdout.split()
        ms = float(ms)
        if best_ms is None or ms < best_ms:
            best_ms, modules = ms, int(loaded)
    return best_ms, modules


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=5)
    args = parser.parse_args()

    for module in ("netprotocols", "dpkt", "scapy.all"):
        ms, modules = best_of(module, args.trials)
        if ms is None:
            print(f"  {module:<14} not installed — skipped")
        else:
            print(f"  {module:<14} {ms:>8.1f} ms   {modules} modules loaded")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
