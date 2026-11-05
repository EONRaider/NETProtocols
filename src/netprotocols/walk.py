"""Walking a captured frame: :func:`decode_frame`.

A frame is a chain of headers, each naming what it carries. Every
decoded header answers two questions — ``header_len`` (how many bytes
it consumed) and ``next_protocol()`` (which class decodes what follows)
— and walking the chain is the loop those two answers imply.

:func:`decode_frame` is that loop, with a bounded depth, an explicit
starting layer, a mode that reports partial success instead of
raising, and a hook for per-call decoder overrides.

    >>> frame = bytes.fromhex(
    ...     "00005e005302" "00005e005301" "0800"
    ...     "45000028" "00014000" "4006b6cb" "c0000201" "c0000202"
    ...     "c0000050" "00000000" "00000000" "5002ffff" "6b8e0000"
    ... )
    >>> packet = decode_frame(frame)
    >>> [type(layer).__name__ for layer in packet]
    ['Ethernet', 'IPv4', 'TCP']

Strict by default
-----------------

Malformed input raises, exactly as ``decode()`` does. The chain's one
judgement of its own is a declared length too short to hold its own
header (see "Declared lengths" below). Pass ``lax=True`` when a
capture tool would rather keep the layers it got than lose frame
4,000,001 to an exception::

    packet = decode_frame(frame, lax=True)
    if packet.stopped_by is not None:
        log.warning("stopped after %d layers: %s",
                    len(packet), packet.stopped_by)

Lax mode never invents a layer and never guesses: it returns what
decoded cleanly, and the exception that ended the walk. It is not a
lenient *parser* — each individual header is decoded as strictly as
in strict mode — it only declines to throw away the work that succeeded.

Starting somewhere other than Ethernet
--------------------------------------

A buffer that begins at IPv4 — a tunnel payload, a packet quoted inside
an ICMP error, a capture with a non-Ethernet link type — says so::

    decode_frame(buf, start=IPv4)

Bounded depth
-------------

Every header validates its own declared length against the buffer, so a
chain always terminates; but a crafted frame can nest far enough to
waste real time. ``max_depth`` bounds it, and exceeding it raises
:class:`~netprotocols.MaxDepthExceededError` (or, in lax mode, ends the
walk and is reported). The default of :data:`MAX_DEPTH` is generous for
nested headers: an ICMP echo tunnelled through VXLAN is 7 layers
(Ethernet, IPv4, UDP, VXLAN, then the inner Ethernet, IPv4 and ICMPv4),
and even a doubly-tagged QinQ frame carrying IPv6 with three extension
headers and DNS over TCP reaches 11. A tunnel nested inside a tunnel is
what the ceiling is for: each level of VXLAN adds four layers, so the
default stops a frame nested eight levels deep. BGP, STUN over TCP and
TLS are the exceptions that nest nothing, and for them the default
bounds correctness as well as cost: every message, or TLS record, in a
TCP segment is a layer of its own, so a segment of more than 29 of them,
the room the default leaves after Ethernet, IPv4 and TCP, exceeds it,
and valid segments do. A 1448-byte segment can hold 76 BGP KEEPALIVEs or
30 one-prefix UPDATEs (:mod:`netprotocols.layer7.bgp`), 72 STUN messages
that are bare 20-byte headers (:mod:`netprotocols.layer7.stun`), and 65
of TLS 1.3's smallest protected records, 22 bytes with a 16-byte AEAD
tag, or 103 of the 14-byte ones TLS_AES_128_CCM_8_SHA256 allows
(:mod:`netprotocols.layer7.tls`), where 30 of 22 bytes already exceed
the 29; one captured with GRO or TSO on, over loopback or on a
jumbo-frame link is larger still. A strict walk of a segment past the
limit raises :class:`~netprotocols.MaxDepthExceededError` and a lax one
stops short with ``stopped_by`` set. A larger ``max_depth`` decodes the
rest, and so does walking on from ``packet.consumed`` with ``start=BGP``
(or ``start=STUN``, ``start=TLS``) over
``frame[packet.consumed : len(frame) - len(packet.trailer)]``, as many
times as it takes: a walk that starts there has room for 32 messages
or records, so the 76 KEEPALIVEs, 72 STUN messages or 65 TLS records
above take three walks and the 103 records four (the loop in
:mod:`netprotocols.layer7.bgp`).

Declared lengths
----------------

Four length fields say where the payload after a header ends: an IEEE
802.3 Length (1500 or less) in an Ethernet or VLAN header's
Length/Type field, IPv4's Total Length, IPv6's Payload Length and
UDP's Length. The walk ends the buffer it hands every later layer at
the tightest end these give, so Ethernet's padding after a short
frame, and a captured FCS, reach no decoder. Those bytes are the
returned packet's :attr:`~netprotocols.Packet.trailer`, a copy of the
frame past that end, and the frame is the layers, then the bytes the
last layer carries that no decoder read, then the trailer::

    undecoded = frame[packet.consumed : len(frame) - len(packet.trailer)]
    assert frame == bytes(packet) + undecoded + packet.trailer

In an encapsulation (VXLAN, GRE, IP in IP, MPLS) an inner length is
the tighter end, and whatever lies between it and an outer end joins
the one trailer. The bound applies wherever the walk starts, so a walk
with ``start=IPv4`` is bounded by that header's Total Length.

A declared end beyond the end of the frame bounds nothing, so a frame
cut by a snap length decodes what was captured, and a looser end never
widens a tighter one: a first fragment's UDP Length, which counts the
whole datagram, or a quoted packet's lengths in an ICMP error. An IPv4
Total Length, IPv6 Payload Length or UDP Length of 0 bounds nothing
either. A length shorter than its own header, an IPv4 Total Length
below the header's ``ihl * 4`` bytes or a UDP Length of 1 to 7, raises
:class:`~netprotocols.InvalidFieldError` naming that field
(``"total_length"`` or ``"length"``), its ``offset`` ``None`` and its
``frame_offset`` the start of that header; a lax walk keeps the header
and stops there, with the trailer the earlier ends left. A length long
enough for its own header but too short for what follows makes the
next decoder raise
:class:`~netprotocols.TruncatedHeaderError`, as an 802.3 Length
shorter than the 3-byte LLC header does (see
:mod:`netprotocols.layer2.llc`).

On ``memoryview``
-----------------

The walk slices whatever it is given and does not convert: each
decoder receives a slice of the caller's own ``bytes`` or
``memoryview``. A ``memoryview`` over a large contiguous buffer keeps
the slices zero-copy; with ``bytes``, each layer's slice copies the
rest of the frame, which for a small frame is a few dozen bytes.
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
#: against nested headers (a VXLAN-tunnelled echo is 7) and small
#: enough that a hostile frame cannot turn one walk into thousands of
#: decodes. Not generous for BGP, STUN over TCP or TLS, one layer per
#: message or record: a valid TCP segment of more than 29 exceeds it. A
#: 1448-byte segment holds 76 BGP KEEPALIVEs or 30 one-prefix UPDATEs,
#: 72 bare 20-byte STUN headers, or 65 of TLS 1.3's 22-byte protected
#: records (103 of 14 bytes). Walk on from ``packet.consumed`` with
#: ``start=BGP``, ``start=STUN`` or ``start=TLS`` as many times as it
#: takes, up to ``packet.trailer`` (each such walk takes up to 32
#: more, so 76 KEEPALIVEs need three walks), or pass a larger
#: ``max_depth``; see
#: :mod:`netprotocols.layer7.bgp`, :mod:`netprotocols.layer7.stun` and
#: :mod:`netprotocols.layer7.tls`.
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

    Each call with ``decode_as`` builds an override registry, a small
    copy; a caller walking many frames with the same overrides can
    derive one registry once and pass it as ``registry=`` instead.

    :param data: The frame, from the first byte of ``start``'s header.
        Trailing bytes the chain does not decode are fine and are left
        alone; ``packet.consumed`` says where the walk stopped, and
        ``packet.trailer`` holds the bytes past the declared lengths'
        end (see "Declared lengths" above).
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

    :raises MaxDepthExceededError: if the chain is longer than
        ``max_depth`` (strict mode only).
    :raises ProtocolError: if any header failed to decode, or declares
        an IPv4 Total Length or UDP Length shorter than itself (strict
        mode only).
    :raises UnknownTableError: if ``decode_as`` names a table that is not
        one of :data:`~netprotocols.registry.TABLES`, whatever ``lax``
        says.
    :raises InvalidRegistryKeyError: if ``decode_as`` names an
        ``llc.dsap`` or ``llc.snap`` key outside the range that table
        accepts, such as a DSAP above 0xFF (see "Key ranges" in
        :mod:`netprotocols.registry`), whatever ``lax`` says.
    :raises ValueError: if ``max_depth`` is below 1.
    """
    if max_depth < 1:
        raise ValueError(f"max_depth must be at least 1, got {max_depth}")
    if decode_as:
        base = DEFAULT if registry is None else registry
        registry = base.derive(decode_as)

    layers: list[Protocol] = []
    cursor = 0
    # Where the buffers handed to decode() end: the frame's end, until a
    # declared length bounds the payload (see "Declared lengths" above).
    # The bytes past it are the packet's trailer.
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

    trailer = b"" if end == len(data) else bytes(data[end:])
    return Packet._from_decoded(layers, stopped_by, trailer)


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

    :param header: The header just decoded, whose class sets
        ``_BOUNDS_PAYLOAD``.
    :param cursor: The frame offset just past ``header``.
    :param end: The frame offset where the current bound ends.
    :raises ProtocolError: if ``header`` declares a length shorter than
        itself; its ``frame_offset`` is the start of ``header``.
    """
    try:
        extent = header._payload_extent()
    except ProtocolError as error:
        error.frame_offset = cursor - header.header_len
        raise
    if extent is None:
        return end
    return min(end, cursor + extent)
