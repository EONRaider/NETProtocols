"""``match`` statements over :data:`~netprotocols.reassembly.FragmentEvent`.

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
    Overlap,
    Retransmission,
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
