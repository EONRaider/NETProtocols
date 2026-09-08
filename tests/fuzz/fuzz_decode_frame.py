"""Atheris coverage-guided fuzz harness for :func:`decode_frame`.

Run directly (not via pytest): ``decode_frame`` is documented to return
a :class:`~netprotocols.walk.Packet` or raise
:class:`~netprotocols.utils.exceptions.ProtocolError` for any input --
never anything else -- so any other exception here is a real bug.

    python tests/fuzz/fuzz_decode_frame.py -max_total_time=120
"""

import contextlib
import sys

import atheris

from netprotocols.utils.exceptions import ProtocolError
from netprotocols.walk import decode_frame


def TestOneInput(data: bytes) -> None:
    with contextlib.suppress(ProtocolError):
        decode_frame(data, lax=False)


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
