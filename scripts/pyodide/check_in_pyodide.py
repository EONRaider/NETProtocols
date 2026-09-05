"""Proof-of-browser-support check, run *inside* a real Pyodide runtime.

Executed by ``scripts/pyodide/run_in_pyodide.mjs``, never directly with
CPython — it assumes the WebAssembly build of CPython that Pyodide ships,
mounted at ``/repo`` in Pyodide's virtual filesystem (see the ``.mjs``
driver for how that mount happens).

This is the real thing, not a simulation of it. ``scapy`` and ``dpkt``
both fail to import under Pyodide because their POSIX-only stdlib
imports (``fcntl``, pulled in unconditionally by scapy's Linux arch
loader; see ``docs/CLAIMS.md`` 3.1 for the exact call sites) do not
exist there — a fact that could quietly stop being true if a future
Pyodide release starts shipping stub versions of them. So step one
below re-asserts that the modules are still genuinely absent from
*this* interpreter before trusting anything that follows; if that
assertion ever fails, the job fails loudly instead of passing for the
wrong reason. Step two then imports the built wheel (installed by the
driver's Node-side setup) and decodes the entire real-capture corpus
with it, proving the library does its actual job here, not just that
``import netprotocols`` succeeds.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

REPO = Path("/repo")
FIXTURES = REPO / "tests" / "fixtures"

#: Modules scapy/dpkt need but Pyodide's WebAssembly build of CPython
#: does not provide (no ioctls, ttys, rlimits, or /etc/passwd under
#: WASM). See docs/CLAIMS.md 3.1 for the byte-accurate import chain.
POSIX_ONLY_MODULES = ("fcntl", "termios", "resource", "grp", "pwd")


def assert_posix_modules_absent() -> None:
    still_present = []
    for name in POSIX_ONLY_MODULES:
        try:
            __import__(name)
        except ImportError:
            continue
        still_present.append(name)
    if still_present:
        raise RuntimeError(
            "Expected these POSIX-only stdlib modules to be unavailable "
            f"under Pyodide, but they imported successfully: "
            f"{still_present}. Pyodide may have started shipping stubs "
            "for them — if so, this job no longer proves anything about "
            "scapy/dpkt failing to import here, and the browser claim "
            "needs a different proof before it can be trusted again."
        )


def install_wheel() -> None:
    """Extract the wheel built by the CI job's ``uv build`` step onto
    ``sys.path``, exactly as a real ``pip``/``micropip`` install would
    leave it, minus the network fetch micropip would otherwise need."""
    import tempfile
    import zipfile

    (wheel,) = (REPO / "dist").glob("*.whl")
    target = Path(tempfile.mkdtemp(prefix="netprotocols-wheel-"))
    zipfile.ZipFile(wheel).extractall(target)
    sys.path.insert(0, str(target))


def read_pcap(path: Path) -> list[bytes]:
    """Minimal classic-pcap reader (standalone, like scripts/benchmark.py
    and scripts/check_fixtures.py — this job must not depend on the
    library it is trying to prove works)."""
    data = path.read_bytes()
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        raise ValueError(f"{path.name}: not a pcap")
    frames, cursor = [], 24
    while cursor + 16 <= len(data):
        (incl_len,) = struct.unpack_from(f"{endian}I", data, cursor + 8)
        cursor += 16
        frames.append(data[cursor : cursor + incl_len])
        cursor += incl_len
    return frames


def corpus_frames() -> list[bytes]:
    return [
        frame
        for pcap in sorted(FIXTURES.glob("*.pcap"))
        for frame in read_pcap(pcap)
    ]


def main() -> int:
    assert_posix_modules_absent()
    install_wheel()

    import netprotocols
    from netprotocols import ProtocolError, decode_frame

    frames = corpus_frames()
    if len(frames) < 40:
        print(f"FAIL: corpus too small ({len(frames)} frames)")
        return 1

    decoded = protocol_errors = 0
    for frame in frames:
        try:
            decode_frame(frame)
            decoded += 1
        except ProtocolError:
            # Acceptable by contract (test_corpus.py's own rule for
            # the same corpus: ProtocolError does not count as a bug).
            protocol_errors += 1
        except Exception as exc:  # the failure mode this job exists to catch
            print(
                "FAIL: a corpus frame raised something other than "
                f"ProtocolError under Pyodide: {exc!r}"
            )
            return 1

    print(
        f"OK: netprotocols {netprotocols.__version__} imported and decoded "
        f"the real {len(frames)}-frame corpus under a real Pyodide "
        f"runtime ({decoded} decoded cleanly, {protocol_errors} raised "
        f"ProtocolError, 0 raised anything else). Confirmed genuinely "
        f"unavailable here: {', '.join(POSIX_ONLY_MODULES)}."
    )
    return 0


main()
