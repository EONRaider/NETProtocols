"""Walking a captured frame: :func:`decode_frame`.

A frame is a chain of headers, each naming what it carries. Every
decoded header answers two questions — ``header_len`` (how many bytes
it consumed) and ``next_protocol()`` (which class decodes what follows)
— and walking the chain is the loop those two answers imply.

That loop used to live in the README, in ARCHITECTURE.md, and in a
private copy in the test suite, which meant everyone using this library
maintained their own. It lives here now, with the parts a copy-pasted
loop never has: a bounded depth, an explicit starting layer, a mode
that reports partial success instead of raising, and a hook for
per-call decoder overrides.

    >>> packet = decode_frame(frame)
    >>> [type(layer).__name__ for layer in packet]
    ['Ethernet', 'IPv4', 'TCP']

Strict by default
-----------------

Malformed input raises, exactly as ``decode()`` does — the chain has no
opinion of its own about what is valid. Pass ``lax=True`` when a
capture tool would rather keep the layers it got than lose frame
4,000,001 to an exception::

    packet = decode_frame(frame, lax=True)
    if packet.stopped_by is not None:
        log.warning("stopped after %d layers: %s",
                    len(packet), packet.stopped_by)

Lax mode never invents a layer and never guesses: it returns what
decoded cleanly, and the exception that ended the walk. It is not a
lenient *parser* — each individual header is decoded as strictly as
ever — it only declines to throw away the work that succeeded.

Starting somewhere other than Ethernet
--------------------------------------

A buffer that begins at IPv4 — a tunnel payload, a packet quoted inside
an ICMP error, a capture with a non-Ethernet link type — says so::

    decode_frame(buf, start=IPv4)

Bounded depth
-------------

Every header validates its own declared length against the buffer, so a
chain always terminates; but nothing stopped a crafted frame from
nesting far enough to waste real time. ``max_depth`` bounds it, and
exceeding it raises :class:`~netprotocols.MaxDepthExceededError` (or,
in lax mode, ends the walk and is reported). The default of
:data:`MAX_DEPTH` is generous for nested headers: the deepest such
chain in the project's corpus is 7 layers (an ICMP echo tunnelled
through VXLAN: Ethernet, IPv4, UDP, VXLAN, then the inner Ethernet,
IPv4 and ICMPv4), and even a doubly-tagged QinQ frame carrying IPv6
with three extension headers and DNS over TCP reaches 11. A tunnel
nested inside a tunnel is what the ceiling is for: each level of VXLAN
adds four layers, so the default stops a frame nested eight levels
deep. BGP is the exception that nests nothing, and for it the default
bounds correctness as well as cost: every message in a TCP segment is a
layer of its own, so a segment of more than 29 messages exceeds the
default, and valid segments do. The corpus's deepest chain is one, 10
layers (a segment of 7 UPDATEs), but a 1448-byte segment can hold 76
KEEPALIVEs or 30 one-prefix UPDATEs, and one captured with GRO or TSO
on, over loopback or on a jumbo-frame link is larger still. A strict
walk of such a segment raises :class:`~netprotocols.MaxDepthExceededError`
and a lax one stops short with ``stopped_by`` set; a larger
``max_depth``, or a second walk from ``packet.consumed`` with
``start=BGP``, decodes the rest. See :mod:`netprotocols.layer7.bgp`.

802.3 Length
------------

An Ethernet or VLAN header whose Length/Type field holds an IEEE 802.3
Length (1500 or less) says where the LLC PDU after it ends, and the
walk ends the buffer it hands every later layer there: Ethernet's zero
padding after a short PDU, and a captured FCS, reach no decoder and
are left past ``packet.consumed``. It is the one enclosing length the
walk honours; IPv4's, IPv6's and UDP's are not (#235). A Length beyond
the end of the frame bounds nothing, so a frame cut by a snap length
decodes what was captured, and a Length shorter than the 3-byte LLC
header makes the LLC decode raise
:class:`~netprotocols.TruncatedHeaderError`. See
:mod:`netprotocols.layer2.llc`.

On ``memoryview``
-----------------

The walk slices whatever it is given and does not convert. Handing it
``bytes`` keeps the common single-frame case fastest; handing it a
``memoryview`` over a large contiguous buffer keeps the slices
zero-copy, which is what pays when frames are being cut out of a whole
capture file. Converting internally would be worse than either:
measured on the corpus, wrapping each frame in a ``memoryview`` runs at
0.95x the plain-``bytes`` walk, because for a single small frame the
view costs more to build than the copy it saves.
"""

from __future__ import annotations

from collections.abc import Mapping

from netprotocols._base import Protocol
from netprotocols.layer2.ethernet import Ethernet
from netprotocols.packet import Packet
from netprotocols.registry import DEFAULT, Registry
from netprotocols.utils.exceptions import (
    MaxDepthExceededError,
    ProtocolError,
)

__all__ = ["MAX_DEPTH", "decode_frame"]

#: Default ceiling on how many headers one frame may chain. Generous
#: against nested headers (the corpus peaks at 7, a VXLAN-tunnelled
#: echo) and small enough that a hostile frame cannot turn one walk into
#: thousands of decodes. Not generous for BGP, one layer per message: a
#: valid TCP segment of more than 29 messages exceeds it (the corpus
#: peaks at 7, a 10-layer chain); see :mod:`netprotocols.layer7.bgp`.
MAX_DEPTH = 32


def decode_frame(
    data: bytes | memoryview,
    *,
    start: type[Protocol] = Ethernet,
    max_depth: int = MAX_DEPTH,
    lax: bool = False,
    registry: Registry | None = None,
    decode_as: Mapping[str, Mapping[int, type[Protocol]]] | None = None,
) -> Packet:
    """Decode a frame's whole header chain into a :class:`Packet`.

    :param data: The frame, from the first byte of ``start``'s header.
        Trailing bytes the chain does not decode are fine and are left
        alone; ``packet.consumed`` says where the walk stopped.
    :param start: The class decoding the first header. Defaults to
        :class:`~netprotocols.Ethernet`; name another to walk a buffer
        that begins mid-stack, such as ``start=IPv4`` for a tunnel
        payload or an ICMP error's quoted packet.
    :param max_depth: Maximum number of headers to decode before
        raising :class:`~netprotocols.MaxDepthExceededError`.
    :param lax: When true, a :class:`~netprotocols.ProtocolError`
        raised while walking the chain ends the walk instead of
        propagating, and is reported on the returned packet's
        ``stopped_by``. An error in ``decode_as`` is raised before the
        walk begins, whatever this says (see below). Strict decoding of
        each individual header is unchanged.
    :param registry: Dispatch tables to resolve ``next_protocol()``
        against. Defaults to the process-wide registry.
    :param decode_as: Per-call decoder overrides, keyed by table then by
        wire value — ``{"udp.port": {6969: DNS}}`` reads DNS on port
        6969 for this call alone. Applied on top of ``registry``.

    :raises MaxDepthExceededError: the chain is longer than
        ``max_depth`` (strict mode only).
    :raises ProtocolError: any header failed to decode (strict mode
        only).
    :raises UnknownTableError: ``decode_as`` names a table that is not
        one of :data:`~netprotocols.registry.TABLES`, whatever ``lax``
        says.
    :raises InvalidRegistryKeyError: ``decode_as`` names a key outside
        the range its table accepts, such as an ``ethertype`` key below
        0x0600 (see "Key ranges" in :mod:`netprotocols.registry`),
        whatever ``lax`` says.
    :raises ValueError: ``max_depth`` is below 1.

    Building the override registry costs a small copy, so a caller
    walking many frames with the same overrides should derive one
    registry and pass it as ``registry=`` rather than repeating
    ``decode_as`` per frame.
    """
    if max_depth < 1:
        raise ValueError(f"max_depth must be at least 1, got {max_depth}")
    if decode_as:
        base = DEFAULT if registry is None else registry
        registry = base.derive(decode_as)

    layers: list[Protocol] = []
    cursor = 0
    # Where the buffers handed to decode() end: the frame's end, until an
    # 802.3 Length bounds the PDU (see "802.3 Length" above).
    end = len(data)
    protocol: type[Protocol] | None = start
    stopped_by: ProtocolError | None = None

    try:
        while protocol is not None:
            if len(layers) == max_depth:
                raise _too_deep(max_depth, protocol, cursor)
            header = protocol.decode(data[cursor:end])
            layers.append(header)
            cursor += header.header_len
            if header._BOUNDS_PAYLOAD:
                end = _bounded(header, cursor, end)
            protocol = header.next_protocol(registry)
    except ProtocolError as error:
        # decode() raises with offset relative to the slice it was
        # handed (data[cursor:end]); rebase it to the whole frame here,
        # since this is the only code with the cursor to do it. Always
        # set, strict or lax, so a caller catching the re-raise still
        # gets a correct frame_offset.
        if error.frame_offset is None:
            error.frame_offset = (
                cursor if error.offset is None else cursor + error.offset
            )
        if not lax:
            raise
        stopped_by = error

    return Packet._from_decoded(layers, stopped_by)


def _too_deep(
    max_depth: int, protocol: type[Protocol], cursor: int
) -> MaxDepthExceededError:
    """Build the error for a chain still going after ``max_depth``."""
    plural = "" if max_depth == 1 else "s"
    return MaxDepthExceededError(
        f"chain still going after {max_depth} header{plural} "
        f"({protocol.__name__} next); raise max_depth if this "
        f"frame is genuinely this deep",
        protocol=protocol,
        offset=cursor,
        frame_offset=cursor,
    )


def _bounded(header: Protocol, cursor: int, end: int) -> int:
    """Return where the buffers after ``header`` end, given its extent.

    ``cursor`` is the offset just past ``header`` and ``end`` the
    current bound. The tighter of the two wins, so a length larger than
    what was captured bounds nothing and a bound never grows.
    """
    extent = header._payload_extent()
    if extent is None:
        return end
    return min(end, cursor + extent)
