"""Atheris coverage-guided fuzz harness for :func:`decode_frame`.

Run directly (not via pytest): ``decode_frame`` is documented to return
a :class:`~netprotocols.walk.Packet` or raise
:class:`~netprotocols.utils.exceptions.ProtocolError` for any input --
never anything else -- so any other exception here is a real bug.

    python tests/fuzz/fuzz_decode_frame.py -max_total_time=120

Every frame in ``tests/fixtures/*.pcap`` is handed to libFuzzer as a
seed input, so mutation starts from real Ethernet/VLAN/IP/transport
chains instead of an empty input that strict decoding rejects at the
first header. Seeds go in through ``-seed_inputs=`` rather than as a
corpus directory, so libFuzzer never writes new inputs back among them.
"""

import contextlib
import hashlib
import os
import sys
import tempfile
from pathlib import Path

import atheris

# Instrumented so libFuzzer gets coverage feedback; otherwise it fuzzes blind.
with atheris.instrument_imports():
    from netprotocols.pcap import read_pcap
    from netprotocols.utils.exceptions import ProtocolError
    from netprotocols.walk import decode_frame

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

#: Fixed rather than per-run: libFuzzer exits the process from C, so
#: no Python cleanup runs and a fresh temporary directory would leak on
#: every run. Files are named by content hash, so reruns, and the
#: workers ``-jobs``/``-fork`` start, reuse them instead of rewriting.
SEED_DIR = Path(tempfile.gettempdir()) / "netprotocols-fuzz-seeds"


def seed_inputs() -> list[Path]:
    """Write every fixture frame to :data:`SEED_DIR`; return their paths.

    Non-recursive on purpose: the subdirectories hold captures kept
    outside the corpus (the BGP and TLS sessions, MPLS cut at a 20-byte
    snap length, classic RFC 3489 STUN, and the HTTP session with its
    byte streams), and a local, git-ignored ``tests/fixtures/staging/``
    may hold copies of the corpus captures. Identical frames collapse to
    one file. Exits if no frame is found, so a moved fixture directory
    fails the run instead of silently falling back to fuzzing from
    nothing.
    """
    SEED_DIR.mkdir(parents=True, exist_ok=True)
    seeds: dict[Path, None] = {}
    for capture in sorted(FIXTURES.glob("*.pcap")):
        for frame in read_pcap(capture.read_bytes()):
            seed = SEED_DIR / hashlib.sha256(frame.data).hexdigest()
            if not seed.exists():
                # Written aside and renamed, so a concurrent worker
                # never reads a half-written seed.
                partial = SEED_DIR / f"{seed.name}.{os.getpid()}.tmp"
                partial.write_bytes(frame.data)
                os.replace(partial, seed)
            seeds[seed] = None
    if not seeds:
        sys.exit(f"no seed frames found in {FIXTURES}/*.pcap")
    return list(seeds)


def TestOneInput(data: bytes) -> None:
    with contextlib.suppress(ProtocolError):
        decode_frame(data, lax=False)


# Ahead of the caller's own arguments, so a -seed_inputs= passed on the
# command line comes later and takes precedence.
seeds = ",".join(str(seed) for seed in seed_inputs())
atheris.Setup(
    [sys.argv[0], f"-seed_inputs={seeds}", *sys.argv[1:]], TestOneInput
)
atheris.Fuzz()
