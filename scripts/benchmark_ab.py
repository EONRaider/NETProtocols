#!/usr/bin/env python3
"""Same-machine A/B decode benchmark: a head tree against a base tree.

    uv run --frozen python scripts/benchmark_ab.py --base origin/master
    uv run --frozen python scripts/benchmark_ab.py --base HEAD
    uv run --frozen python scripts/benchmark_ab.py --base-src ../other/src

The base is a git revision of this repository (``--base``), whose
``src`` directory is exported with ``git archive`` into a temporary
directory, or an existing ``src`` directory (``--base-src``). The head
is ``--head-src``, by default this checkout's ``src``. Only the base's
``src`` is used: the timing code and the corpus both come from this
checkout, so a base without this script, or with an older version of
it, is measured the same way.

Each measurement runs ``_benchmark_ab_worker.py`` in a fresh process of
this interpreter with ``-I -S -B``, with one tree's ``src`` first on
``sys.path`` and ``site-packages`` off, so each process imports only
its own tree's ``netprotocols`` and writes no bytecode. Both trees are
first copied, or exported, into one temporary directory without any
``__pycache__``, so each compiles its own sources from scratch.

Both trees decode the frames of ``--fixtures``, by default this
checkout's ``tests/fixtures``. A probe pass decodes every frame once in
each tree first; the frames the base raises on are dropped for both
trees, and the frames only the head raises on are kept and counted.

``--pairs`` pairs of measurements follow, alternating which tree goes
first. Each pair gives a ratio, head time over base time, so above 1.0
means the head is slower. The script prints every pair, then the
median, minimum, maximum and quartiles of the ratios, and exits 1 when
the median is more than ``--threshold`` percent above 1.0.

``--base HEAD`` on a clean checkout, or ``--base-src`` naming the head's
own ``src``, compares a tree with itself, so the ratios measure only
the noise of the machine.

Exit status: 0 within the threshold, 1 over it, 2 when the comparison
cannot run.
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parent.parent
WORKER = Path(__file__).resolve().parent / "_benchmark_ab_worker.py"

#: Fails when the median ratio is more than this many percent above 1.0.
THRESHOLD = 10.0


class ComparisonError(Exception):
    """The comparison cannot run: a tree is missing or fails to load."""


def export_tree(repository: Path, revision: str, destination: Path) -> Path:
    """Export ``revision``'s ``src`` directory under ``destination``.

    :param repository: The git working tree to read the revision from.
    :param revision: Any revision ``git rev-parse`` accepts.
    :param destination: An existing directory to extract into.
    :returns: The extracted ``src`` directory.
    :raises ComparisonError: if the revision is not in the repository,
        as in a clone too shallow to hold it, or holds no ``src``.
    """
    resolved = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "rev-parse",
            "--verify",
            "--quiet",
            f"{revision}^{{commit}}",
        ],
        capture_output=True,
        text=True,
    )
    if resolved.returncode != 0:
        raise ComparisonError(
            f"revision {revision!r} is not in {repository}; a shallow "
            "clone may not hold it (fetch with fetch-depth: 0)"
        )
    commit = resolved.stdout.strip()
    archive = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "archive",
            "--format=tar",
            commit,
            "--",
            "src",
        ],
        capture_output=True,
    )
    if archive.returncode != 0:
        raise ComparisonError(
            f"cannot export src from {commit}: "
            f"{archive.stderr.decode(errors='replace').strip()}"
        )
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
        tar.extractall(destination, filter="data")
    return destination / "src"


def copy_tree(src: Path, destination: Path) -> Path:
    """Copy a ``src`` directory to ``destination/src``, without bytecode.

    :param src: The ``src`` directory to copy.
    :param destination: An existing directory to copy into.
    :returns: The copied ``src`` directory.
    :raises ComparisonError: if ``src`` holds no ``netprotocols`` package.
    """
    if not (src / "netprotocols" / "__init__.py").is_file():
        raise ComparisonError(f"{src} holds no netprotocols package")
    copied = destination / "src"
    shutil.copytree(
        src, copied, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    return copied


def run_worker(
    src: Path, fixtures: Path, mode: str, *options: str
) -> dict[str, Any]:
    """Run the worker on one tree and return the JSON it prints.

    :param src: The tree's ``src`` directory.
    :param fixtures: The directory of captures to decode.
    :param mode: ``probe`` or ``time``.
    :param options: Further worker arguments.
    :returns: The worker's result.
    :raises ComparisonError: if the worker exits with a non-zero status.
    """
    command = [
        sys.executable,
        "-I",
        "-S",
        "-B",
        str(WORKER),
        str(src),
        str(fixtures),
        mode,
        *options,
    ]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode != 0:
        raise ComparisonError(
            f"the worker failed on {src} (status {completed.returncode}):"
            f"\n{completed.stderr.strip()}"
        )
    result: dict[str, Any] = json.loads(completed.stdout)
    return result


def summarize(ratios: Sequence[float]) -> dict[str, float]:
    """Return the median, extremes, quartiles and spread of ``ratios``.

    :param ratios: At least one ratio.
    :returns: ``median``, ``min``, ``max``, ``spread`` (max minus min),
        and ``q1`` and ``q3``, which equal the median for one ratio.
    """
    median = statistics.median(ratios)
    if len(ratios) > 1:
        q1, _, q3 = statistics.quantiles(ratios, n=4, method="inclusive")
    else:
        q1 = q3 = median
    return {
        "median": median,
        "min": min(ratios),
        "max": max(ratios),
        "spread": max(ratios) - min(ratios),
        "q1": q1,
        "q3": q3,
    }


def compare(
    base: Path,
    head: Path,
    fixtures: Path,
    pairs: int,
    repetitions: int,
    trials: int,
) -> dict[str, Any]:
    """Probe both trees, then time them in alternating pairs.

    :param base: The base tree's ``src``.
    :param head: The head tree's ``src``.
    :param fixtures: The directory of captures both trees decode.
    :param pairs: How many pairs of measurements to take.
    :param repetitions: Decode passes per timed run.
    :param trials: Timed runs per measurement; the shortest is kept.
    :returns: The probes, the skipped frames, each pair's times and
        ratio, and :func:`summarize` of the ratios.
    :raises ComparisonError: if a worker fails, imports any
        ``netprotocols`` module from outside its tree, runs with
        ``site`` or bytecode writing on, or no frame is left.
    """
    probes = {
        "base": run_worker(base, fixtures, "probe"),
        "head": run_worker(head, fixtures, "probe"),
    }
    for name, found in probes.items():
        print(f"{name}: netprotocols {found['version']} from {found['file']}")
        if found["outside"]:
            raise ComparisonError(
                f"{name} loaded modules from outside its tree: "
                f"{', '.join(found['outside'])}"
            )
        if found["site"] or found["bytecode_written"]:
            raise ComparisonError(
                f"{name}'s worker ran with site-packages or bytecode on"
            )
    total = probes["head"]["frames"]
    skipped = sorted(probes["base"]["raises"])
    head_only = sorted(set(probes["head"]["raises"]) - set(skipped))
    if len(skipped) >= total:
        raise ComparisonError(f"the base decodes none of {total} frames")
    print(
        f"frames: {total} in {fixtures}, {len(skipped)} skipped for both "
        f"trees because the base raises on them, {len(head_only)} kept "
        "that only the head raises on"
    )
    print(
        f"{pairs} pairs, {repetitions} repetitions per run, best of "
        f"{trials}; ratio = head time / base time"
    )

    options = (
        "--repetitions",
        str(repetitions),
        "--trials",
        str(trials),
        "--skip",
        ",".join(map(str, skipped)),
    )
    measured = []
    for number in range(pairs):
        order = ("base", "head") if number % 2 == 0 else ("head", "base")
        seconds = {
            name: run_worker(
                base if name == "base" else head, fixtures, "time", *options
            )["seconds"]
            for name in order
        }
        ratio = seconds["head"] / seconds["base"]
        measured.append({"first": order[0], **seconds, "ratio": ratio})
        print(
            f"  pair {number + 1:>2} ({order[0]} first): base "
            f"{seconds['base']:.4f} s, head {seconds['head']:.4f} s, "
            f"ratio {ratio:.4f}"
        )
    return {
        "probes": probes,
        "frames": total,
        "skipped": skipped,
        "head_only_raises": head_only,
        "repetitions": repetitions,
        "trials": trials,
        "pairs": measured,
        "summary": summarize([pair["ratio"] for pair in measured]),
    }


def verdict(summary: dict[str, float], threshold: float) -> int:
    """Print the summary and return 1 if the median exceeds the threshold.

    :param summary: :func:`summarize` of the ratios.
    :param threshold: The allowed slowdown, in percent.
    :returns: 0 within the threshold, 1 over it.
    """
    change = (summary["median"] - 1) * 100
    print(
        f"median ratio {summary['median']:.4f} ({change:+.1f}%); "
        f"min {summary['min']:.4f}, max {summary['max']:.4f}, "
        f"spread {summary['spread']:.4f}, quartiles {summary['q1']:.4f}"
        f"-{summary['q3']:.4f}"
    )
    if summary["median"] > 1 + threshold / 100:
        print(
            f"REGRESSION: the head is more than {threshold:g}% slower than "
            "the base."
        )
        return 1
    print(f"Within the {threshold:g}% threshold.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    base = parser.add_mutually_exclusive_group(required=True)
    base.add_argument("--base", help="a git revision of this repository")
    base.add_argument("--base-src", type=Path, help="a base src directory")
    parser.add_argument("--head-src", type=Path, default=REPOSITORY / "src")
    parser.add_argument(
        "--fixtures", type=Path, default=REPOSITORY / "tests" / "fixtures"
    )
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--pairs", type=int, default=15)
    parser.add_argument("--repetitions", type=int, default=20)
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--threshold", type=float, default=THRESHOLD)
    parser.add_argument("--json", type=Path, help="write the results here")
    args = parser.parse_args(argv)
    if args.pairs < 1:
        parser.error("--pairs must be at least 1")

    with tempfile.TemporaryDirectory(prefix="benchmark-ab-") as scratch:
        base_dir, head_dir = Path(scratch, "base"), Path(scratch, "head")
        base_dir.mkdir()
        head_dir.mkdir()
        try:
            if args.base is not None:
                base_src = export_tree(args.repository, args.base, base_dir)
                print(f"base: {args.base}, exported to {base_src}")
            else:
                base_src = copy_tree(args.base_src, base_dir)
                print(f"base: {args.base_src}, copied to {base_src}")
            head_src = copy_tree(args.head_src, head_dir)
            print(f"head: {args.head_src}, copied to {head_src}")
            result = compare(
                base_src,
                head_src,
                args.fixtures,
                args.pairs,
                args.repetitions,
                args.trials,
            )
        except ComparisonError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
    status = verdict(result["summary"], args.threshold)
    if args.json:
        result["threshold"] = args.threshold
        args.json.write_text(json.dumps(result, indent=2) + "\n")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
