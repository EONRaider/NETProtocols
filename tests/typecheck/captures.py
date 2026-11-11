"""Call sites of the capture readers for mypy.

``mypy --strict`` checks this module (see ``[tool.mypy]`` in
pyproject.toml). The functions are never called: each statement is a
call site that must type-check, and each one marked ``type: ignore``
must keep failing, or the ignore is reported as unused.
"""

import io
from pathlib import Path
from typing import BinaryIO, TextIO

from netprotocols import read_captures, read_packets, read_pcap, read_pcapng


class ReadOnly:
    """A stream with nothing but ``read``."""

    def read(self, size: int, /) -> bytes:
        """Return no bytes, as at the end of a stream."""
        return b""


def accepted(data: bytes, file: BinaryIO, path: Path) -> None:
    """Read a capture from every kind of input the readers take."""
    read_pcap(data)
    read_pcapng(bytearray(data))
    read_captures(memoryview(data))
    read_packets(io.BytesIO(data))
    read_packets(file)
    read_captures(ReadOnly())
    with path.open("rb") as opened:
        read_pcap(opened)


def refused(text: str, file: TextIO) -> None:
    """Pass inputs the readers do not take."""
    read_pcap(text)  # type: ignore[arg-type]
    read_packets(file)  # type: ignore[arg-type]
