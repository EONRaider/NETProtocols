"""Atheris coverage-guided fuzz harness for :meth:`HTTP.decode`.

Run directly (not via pytest). The first input byte picks the decode
context (``request_method`` and ``closed``); the rest is the message.
Anything other than a :class:`~netprotocols.utils.exceptions.ProtocolError`
is a bug, and so is a decoded message that

- does not encode back to the prefix of the input it was cut from,
- has an accessor that raises, or
- decodes differently when its own bytes are decoded again.

    python tests/fuzz/fuzz_http_decode.py -max_total_time=120

Every captured byte stream in ``tests/fixtures/http/`` (each connection's
requests and responses, see ``scripts/capture_fixtures_http.sh``) is
handed to libFuzzer as a seed, prefixed with the context byte that
decodes it: a response stream answering a HEAD carries ``HEAD``. As in
``fuzz_decode_frame.py``, seeds go in through ``-seed_inputs=`` so
libFuzzer never writes new inputs back among them.
"""

import hashlib
import os
import sys
import tempfile
from pathlib import Path

import atheris

# Instrumented, or libFuzzer gets no coverage feedback and mutates
# blind: the corpus would never grow past its first input.
with atheris.instrument_imports():
    from netprotocols import HTTP
    from netprotocols.utils.exceptions import ProtocolError

_METHODS = (None, "HEAD", "CONNECT", "GET")

HTTP_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "http"

#: Fixed rather than per-run, for the reasons fuzz_decode_frame.py gives:
#: libFuzzer exits from C, so no Python cleanup would remove a fresh one.
SEED_DIR = Path(tempfile.gettempdir()) / "netprotocols-http-fuzz-seeds"


def _context(stream: Path) -> int:
    """The context byte that decodes ``stream`` the way it was sent."""
    if stream.suffix == ".response":
        request = stream.with_suffix(".request").read_bytes()
        if request.startswith(b"HEAD "):
            return _METHODS.index("HEAD")
    return _METHODS.index(None)


def seed_inputs() -> list[Path]:
    """Write every captured stream, behind its context byte, to
    :data:`SEED_DIR`; return their paths. Exits if none is found, so a
    moved fixture directory fails the run instead of fuzzing from
    nothing."""
    SEED_DIR.mkdir(parents=True, exist_ok=True)
    seeds: dict[Path, None] = {}
    streams = [
        *HTTP_FIXTURES.glob("*.request"),
        *HTTP_FIXTURES.glob("*.response"),
    ]
    for stream in sorted(streams):
        data = bytes([_context(stream)]) + stream.read_bytes()
        seed = SEED_DIR / hashlib.sha256(data).hexdigest()
        if not seed.exists():
            # Written aside and renamed, so a concurrent worker never
            # reads a half-written seed.
            partial = SEED_DIR / f"{seed.name}.{os.getpid()}.tmp"
            partial.write_bytes(data)
            os.replace(partial, seed)
        seeds[seed] = None
    if not seeds:
        sys.exit(f"no seed streams found in {HTTP_FIXTURES}")
    return list(seeds)


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    request_method = _METHODS[data[0] % len(_METHODS)]
    closed = bool(data[0] & 0x80)
    message = data[1:]
    try:
        msg = HTTP.decode(message, request_method=request_method, closed=closed)
    except ProtocolError:
        return
    assert bytes(msg) == message[: msg.header_len]
    for name in (
        "is_response",
        "method",
        "target",
        "http_version",
        "status_code",
        "reason_phrase",
        "fields",
        "framing",
        "connection_disposition",
        "content",
        "trailers",
        "anomalies",
    ):
        getattr(msg, name)
    for field in msg.fields:
        msg.header(field.name)
    again = HTTP.decode(
        bytes(msg), request_method=msg.request_method, closed=True
    )
    assert again == msg
    assert again.anomalies == msg.anomalies


# Ahead of the caller's own arguments, so a -seed_inputs= passed on the
# command line comes later and takes precedence.
seeds = ",".join(str(seed) for seed in seed_inputs())
atheris.Setup(
    [sys.argv[0], f"-seed_inputs={seeds}", *sys.argv[1:]], TestOneInput
)
atheris.Fuzz()
