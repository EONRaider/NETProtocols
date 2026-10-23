"""Atheris coverage-guided fuzz harness for :meth:`HTTP.decode`.

Run directly (not via pytest). The first input byte picks the decode
context (``request_method`` and ``closed``); the rest is the message.
Anything other than a :class:`~netprotocols.utils.exceptions.ProtocolError`
is a bug, and so is a decoded message that

- does not encode back to the prefix of the input it was cut from,
- has an accessor that raises, or
- decodes differently when its own bytes are decoded again.

    python tests/fuzz/fuzz_http_decode.py -max_total_time=120
"""

import sys

import atheris

# Instrumented, or libFuzzer gets no coverage feedback and mutates
# blind: the corpus would never grow past its first input.
with atheris.instrument_imports():
    from netprotocols import HTTP
    from netprotocols.utils.exceptions import ProtocolError

_METHODS = (None, "HEAD", "CONNECT", "GET")


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


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
