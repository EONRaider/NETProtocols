"""``match`` statements over the reassembly event unions.

They are :data:`~netprotocols.reassembly.FragmentEvent` and
:data:`~netprotocols.reassembly.StreamEvent`.

``mypy --strict`` checks this module (see ``[tool.mypy]`` in
pyproject.toml). The functions are never called: a ``match`` naming
every event type is exhaustive, so ``assert_never`` type-checks, and
one that leaves a type out must keep failing, or the ``type: ignore``
is reported as unused.
"""

from typing import assert_never

from netprotocols.reassembly import (
    Anomaly,
    Datagram,
    Evicted,
    Expired,
    FragmentEvent,
    Gap,
    LateData,
    OutOfOrder,
    Overlap,
    Retransmission,
    StreamData,
    StreamEnd,
    StreamEvent,
)


def exhaustive(event: FragmentEvent) -> str:
    """Name every event type."""
    match event:
        case Datagram(data=data):
            return f"datagram of {len(data)} bytes"
        case Overlap(resolved=resolved):
            return f"overlap, resolved={resolved}"
        case Retransmission(start=start, end=end):
            return f"retransmission of {start}-{end}"
        case Evicted(bound=bound):
            return f"evicted by {bound.value}"
        case Expired(timeout=timeout):
            return f"expired by {timeout.value}"
        case Anomaly(kind=kind):
            return f"anomaly {kind.value}"
        case _:
            assert_never(event)


def missing_one(event: FragmentEvent) -> str:
    """Leave :class:`Anomaly` out."""
    match event:
        case Datagram() | Overlap() | Retransmission():
            return "data"
        case Evicted() | Expired():
            return "flush"
        case _:
            assert_never(event)  # type: ignore[arg-type]


def exhaustive_stream(event: StreamEvent) -> str:
    """Name every stream event type."""
    match event:
        case StreamData(offset=offset, data=data):
            return f"{len(data)} bytes at {offset}"
        case StreamEnd(reason=reason):
            return f"end by {reason.value}"
        case OutOfOrder(expected=expected):
            return f"held past {expected}"
        case Gap(reason=reason):
            return f"gap by {reason.value}"
        case LateData(offset=offset):
            return f"late bytes at {offset}"
        case Overlap(contrary=contrary):
            return f"overlap, contrary={contrary}"
        case Retransmission(verified=verified):
            return f"retransmission, verified={verified}"
        case Evicted(bound=bound):
            return f"evicted by {bound.value}"
        case Expired(timeout=timeout):
            return f"expired by {timeout.value}"
        case Anomaly(kind=kind):
            return f"anomaly {kind.value}"
        case _:
            assert_never(event)


def missing_late_data(event: StreamEvent) -> str:
    """Leave :class:`LateData` out."""
    match event:
        case StreamData() | StreamEnd() | OutOfOrder() | Gap():
            return "stream"
        case Overlap() | Retransmission() | Anomaly():
            return "report"
        case Evicted() | Expired():
            return "flush"
        case _:
            assert_never(event)  # type: ignore[arg-type]
