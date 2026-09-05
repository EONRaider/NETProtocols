"""Minimal classic-pcap reader shared by the standalone verification
scripts under ``scripts/`` (``benchmark.py``, ``pyodide/check_in_pyodide.py``).

Stdlib only, and never imports netprotocols — each caller's own
docstring explains why *that* independence matters (a benchmark or a
Pyodide-import proof must not depend on the code it is measuring or
proving works). Sharing this module between those callers does not
compromise it: this file is standalone from netprotocols exactly like
they are, it just isn't reimplemented three times over.
"""

from __future__ import annotations

import struct
from pathlib import Path


def read_pcap(path: Path) -> list[bytes]:
    """Minimal classic-pcap reader."""
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


def corpus_frames(fixtures_dir: Path) -> list[bytes]:
    return [
        frame
        for pcap in sorted(fixtures_dir.glob("*.pcap"))
        for frame in read_pcap(pcap)
    ]
