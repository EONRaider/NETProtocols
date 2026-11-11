"""Reassembly of IP fragments into datagrams and TCP segments into streams.

:class:`FragmentReassembler` and :class:`StreamReassembler` each take
a decoded :class:`~netprotocols.packet.Packet` together with the frame
it was decoded from, its capture timestamp and a reference the caller
picks (a frame index), and return the events that frame caused. They
are the library's only stateful objects: :func:`~netprotocols.decode_frame`
and every ``decode()`` stay per-frame, and this module is reached as
``netprotocols.reassembly`` only; ``import netprotocols`` does not
import it.

>>> from netprotocols import IPv4, decode_frame
>>> from netprotocols.reassembly import Datagram, FragmentReassembler
>>> first = bytes.fromhex(
...     "4500001c" "00072000" "4011d6c6" "c0000201" "c0000202"
...     "0fa00fa1" "00180000"
... )
>>> last = bytes.fromhex(
...     "45000024" "00070001" "4011f6bd" "c0000201" "c0000202"
... ) + b"hello, fragments"
>>> reassembler = FragmentReassembler()
>>> reassembler.feed(decode_frame(first, start=IPv4), first, timestamp=1)
()
>>> (datagram,) = reassembler.feed(
...     decode_frame(last, start=IPv4), last, timestamp=2
... )
>>> isinstance(datagram, Datagram), datagram.completing_ref, datagram.refs
(True, 1, (0, 1))
>>> datagram.data[datagram.payload_offset + 8 :]
b'hello, fragments'

The reassembler finds the outermost IP header of the packet that is a
fragment (an IPv4 header with MF set or a nonzero Fragment Offset, or
an IPv6 header followed by an :class:`~netprotocols.IPv6Fragment`
header with M set or a nonzero offset) and slices the fragment's data
out of the frame, up to the end its IP header declares, clamped to the
frame less :attr:`~netprotocols.packet.Packet.trailer`. Fragments are
grouped by :class:`FragmentKey` (RFC 791 §2.3, RFC 8200 §4.5). A packet
with no such header, an IPv6 atomic fragment (RFC 6946 §4) included,
returns only the expiries its timestamp causes.

**Clock.** Every call to a reassembler's ``feed``, whether or not its
packet holds anything the reassembler takes, and every call to its
``advance`` moves the capture clock to its timestamp, unless that is 0
or lower than the clock, and returns the expiries that causes.

**Events.** Every event is a frozen, slotted, keyword-only dataclass
naming the frames that contributed to it as :class:`Span` values, and
the frame whose own fragment or segment caused it as
``completing_ref``. :data:`FragmentEvent` and :data:`StreamEvent` are
the unions of the event types each reassembler returns. Each call to
:meth:`FragmentReassembler.feed` returns, in order: the expiries the
frame's timestamp triggers in other datagrams, in deadline order; the
evictions of other datagrams that storing its data requires, oldest
first; then the events of its own datagram, in the order of the
datagram offset each concerns, ending with the :class:`Datagram`,
:class:`Evicted` or discarding event that ends it.
Events caused by an expiry, by the eviction of a datagram to make room
for another, by :meth:`~FragmentReassembler.advance` or by
:meth:`~FragmentReassembler.close` carry ``completing_ref=None``.

**Overlaps.** Overlapping IPv4 fragments are resolved by the
:class:`OverlapPolicy` of the receiver: ``targets`` maps networks to
policies, the longest prefix holding the destination winning, and
``policy`` applies elsewhere. Held state is always one version of each
byte. Bytes that overlap and differ produce an :class:`Overlap` under
every policy; bytes that overlap and agree produce a
:class:`Retransmission`. An overlapping IPv6 fragment that is not an
exact duplicate discards its datagram (RFC 5722 §4, as amended by
erratum 3089), as do the ``discard`` and ``linux-discard`` policies for
the IPv4 overlaps each one names; the key keeps no state afterwards, so
a later fragment under it starts a new datagram. These three rules
judge overlap on the fragments' declared ranges, so a fragment the snap
length cut still overlaps where its header says it does. Under IPv6 and
``discard`` an exact duplicate supplies the bytes the held fragment's
capture lacks; under ``linux-discard`` a duplicate inside a run is
dropped, as Linux drops it, and none of its bytes is stored. Linux
records a dropped last fragment's end but checks for completion only
after a fragment it stores, so such a duplicate completes no datagram;
a later fragment that fills a remaining hole does.

**Rules.** Each fragment is checked against the rules below. Every
discard is reported by an :class:`Anomaly`; a discarded datagram's
anomaly carries the spans of every fragment it held and of the
arriving one.

- A bad IPv4 header checksum is :attr:`AnomalyKind.BAD_CHECKSUM`; the
  fragment is used or dropped per :class:`ChecksumMode`. A fragment
  whose IP header declares a length of 0 is
  :attr:`AnomalyKind.UNVERIFIED_CHECKSUM`, and is used under
  :attr:`ChecksumMode.KEEP` only: no checksum it carries can show it
  came from the capture host's offload, so :attr:`ChecksumMode.AUTO`
  drops it as :attr:`ChecksumMode.DROP` does.
- A fragment with no data is :attr:`AnomalyKind.EMPTY_FRAGMENT`. It
  discards an IPv6 datagram, and an IPv4 datagram under
  ``linux-discard``; elsewhere only the fragment is dropped.
- A fragment with MF or M set whose data length is not a multiple of 8
  is :attr:`AnomalyKind.MISALIGNED` (RFC 8200 §4.5). An IPv6 fragment
  is dropped; an IPv4 fragment's data is cut to a multiple of 8 and
  used, and a fragment left with no data discards its datagram.
- A fragment that would end the reassembled datagram past 65,535 bytes
  (RFC 791 §3.1, RFC 8200 §4.5) is :attr:`AnomalyKind.OVERSIZE`. The
  length counts the header the rebuilt datagram takes, the first
  fragment's once it has arrived; an IPv6 first fragment is judged
  against the furthest byte already held too. It discards an IPv4
  datagram; an IPv6 fragment is dropped alone, so a valid first
  fragment can still complete the datagram. An IPv4 datagram whose
  first fragment, arriving last, makes it too long, and any datagram
  whose rebuilt header and payload exceed 65,535 bytes, is discarded
  when it completes, with the same anomaly.
- An IPv6 first fragment whose data does not hold the header chain
  through the upper-layer header (RFC 7112 §5), a TCP header with its
  options included, is :attr:`AnomalyKind.INCOMPLETE_HEADER_CHAIN`,
  and is dropped. A first
  fragment the snap length cut is not judged by this rule, since its
  missing bytes may hold the chain.
- A last fragment that disagrees with a known end, or data past one, is
  :attr:`AnomalyKind.INCONSISTENT_END`, and discards the datagram.
- Reported, the fragment used: :attr:`AnomalyKind.TRUNCATED` (captured
  bytes shorter than the declared length, the rest a hole),
  :attr:`AnomalyKind.TINY_FRAGMENT` (an IPv4 first fragment of TCP or
  UDP too short for its header, RFC 1858 §3),
  :attr:`AnomalyKind.TCP_OFFSET_ONE` (an IPv4 fragment of TCP at offset
  1, RFC 1858 §4), :attr:`AnomalyKind.HOP_LIMIT_CHANGED` and
  :attr:`AnomalyKind.NEXT_HEADER_CHANGED` (a TTL, Hop Limit or Fragment
  Next Header other than the datagram's first-arriving fragment's).
- An IPv4 datagram that completes more than 30 seconds after its first
  fragment, under the global age timeout, is
  :attr:`AnomalyKind.SLOW_REASSEMBLY`, reported before its
  :class:`Datagram`.

**Bounds.** :class:`FragmentBounds` caps what is held and sets the
timeouts. What is held is charged as :data:`FLOW_OVERHEAD` per datagram
plus, per stored piece, :data:`PIECE_OVERHEAD`, its data and any header
kept for the reassembled datagram; a declared range a discarding rule
keeps with no captured byte in it is charged :data:`PIECE_OVERHEAD` and
counts against ``max_fragments`` as a piece. Timeouts run on capture timestamps
in nanoseconds (:data:`SECOND`), never on the wall clock: the capture
clock is the highest timestamp fed, and a datagram expires when its
deadline is at or before it. A datagram that
outgrows ``max_flow_bytes`` or ``max_fragments`` is discarded, and so
is one that would alone exceed ``max_total_bytes``. To make room under
``max_total_bytes`` or ``max_flows``, the datagram with the earliest
first fragment is evicted, ties going to the one that started first;
when that is the arriving fragment's own datagram, it is the one
evicted, with the fragment's reference. After every call,
:attr:`FragmentReassembler.usage` is within ``max_total_bytes`` and
``max_flows``.

**TCP streams.** :class:`StreamReassembler` delivers each direction of
each TCP connection as a byte stream:

>>> from netprotocols.reassembly import StreamReassembler
>>> syn = bytes.fromhex(
...     "45000028" "00014000" "4006b6cb" "c0000201" "c0000202"
...     "0fa00050" "000003e8" "00000000" "5002ffff" "18070000"
... )
>>> data = bytes.fromhex(
...     "45000036" "00014000" "4006b6bd" "c0000201" "c0000202"
...     "0fa00050" "000003e9" "00000000" "5010ffff" "6c310000"
... ) + b"hello, streams"
>>> streams = StreamReassembler()
>>> streams.feed(decode_frame(syn, start=IPv4), syn, timestamp=1)
()
>>> (run,) = streams.feed(decode_frame(data, start=IPv4), data, timestamp=2)
>>> run.offset, run.data, run.completing_ref
(0, b'hello, streams', 1)

A connection is keyed by :func:`~netprotocols.flow.flow_key` of the
packet's first TCP layer and the IP header nearest before it, and has
two :class:`Direction` values. Each direction numbers its bytes from 0:
the byte after the SYN's sequence number, or, without a SYN, the first
byte of the first segment with data or FIN, reported once as
:attr:`AnomalyKind.MIDSTREAM`. Sequence numbers map to offsets by the
serial-number rule (RFC 9293 §3.4, RFC 1982), so a stream crosses a
wrap of the sequence space. A packet with no TCP layer, or whose first
TCP layer is inside an IP fragment, returns only the expiries its
timestamp causes; the caller feeds the reassembled datagram instead.

- **Delivery.** Bytes contiguous with a direction's delivered end are
  delivered at once as one :class:`StreamData` per call and direction,
  split where a :class:`Gap` falls, ``spans`` tiling its ``data``; a segment past a hole is held, with
  :class:`OutOfOrder`. Delivered bytes are final. A segment the snap
  length cut delivers its captured bytes and a ``Gap(TRUNCATED)`` for
  the rest. A direction ends with ``StreamEnd(FIN)`` when delivery
  reaches the end its FIN fixed.
- **Overlaps.** Bytes that overlap held bytes are resolved by the
  receiver's :class:`OverlapPolicy`, ``first`` or ``last``, chosen
  through ``targets`` as for fragments. Bytes that repeat delivered
  ones are compared with the bytes the direction retains: from
  ``retain_bytes`` below the peer's highest acknowledgement, capped at
  the delivered end, or below the delivered end without one. A
  difference is an :class:`Overlap` whose ``kept`` is the delivered
  version, with ``contrary`` set under ``last``; equal bytes are a
  :class:`Retransmission`, and bytes the direction cannot compare a
  ``Retransmission(verified=False)``.
- **Acknowledged holes.** When the peer first acknowledges past the
  lowest hole, a grace starts, held to that acknowledgement. Once
  ``ack_gap_grace`` has passed, a frame that acknowledges at or past it,
  or carries data of the direction past the delivered end, declares
  each hole below it a ``Gap(ACKED)``, up to the highest offset the
  direction received, and delivers the bytes after each with that
  frame's reference; a grace for the holes past it then starts. An
  acknowledgement past the highest offset received is
  :attr:`AnomalyKind.ACK_BEYOND_DATA`, once per direction. Bytes that
  arrive later for an acknowledged gap are :class:`LateData`.
- **RST.** An RST is :attr:`AnomalyKind.RST_RECEIVED` at once and makes
  the connection's end pending until the closed timeout after it. Data
  of either direction past what it had received when the RST came
  cancels it, :attr:`AnomalyKind.DATA_AFTER_RST` once per direction,
  and continues the stream at the same offsets. When the timeout
  passes, at :meth:`~StreamReassembler.close`, or when a SYN with
  another ISN comes, held data is flushed and each open direction ends
  with ``StreamEnd(RST)``; that SYN starts a new connection,
  :attr:`AnomalyKind.SYN_AFTER_RST`, and the flush carries its
  reference. Data on an RST is :attr:`AnomalyKind.RST_WITH_DATA`, not
  stream data.
- **SYN.** Data on a SYN is delivered from offset 0,
  :attr:`AnomalyKind.SYN_DATA`. A SYN that repeats the ISN is a
  :class:`Retransmission`; one with another ISN replaces it while the
  direction has delivered nothing, and is ignored otherwise, each
  :attr:`AnomalyKind.ISN_CHANGED`. A SYN for a connection whose every
  direction ended by FIN starts a new connection.
- **Dropped, and reported.** A segment that is neither a SYN nor an RST
  without ACK (:attr:`AnomalyKind.DATA_WITHOUT_ACK`); data before offset
  0 (:attr:`AnomalyKind.BEFORE_STREAM_START`); data past a FIN's end
  (:attr:`AnomalyKind.DATA_AFTER_FIN`); a FIN that disagrees with an
  earlier one or ends before data received
  (:attr:`AnomalyKind.INCONSISTENT_FIN`); and a segment whose checksum
  :class:`ChecksumMode` rejects (:attr:`AnomalyKind.BAD_CHECKSUM`). A
  segment whose IP header declares a length of 0 is
  :attr:`AnomalyKind.UNVERIFIED_CHECKSUM`, and is used as a bad
  checksum would be; one the snap length cut is used under every mode.
- **Reported, and used.** :attr:`AnomalyKind.OUT_OF_WINDOW` (data past
  the furthest right window edge the receiver advertised, once both
  SYNs were seen), :attr:`AnomalyKind.URGENT` (URG, once per
  direction; urgent bytes stay inline),
  :attr:`AnomalyKind.HOP_LIMIT_CHANGED` (a hop limit other than the
  direction's previous segment's), :attr:`AnomalyKind.SELF_CONNECTED`
  and :attr:`AnomalyKind.TRUNCATED`.

**Stream bounds.** :class:`StreamBounds` caps what is held. A
connection is charged :data:`FLOW_OVERHEAD`, each of its directions
:data:`PIECE_OVERHEAD`, each held chunk :data:`PIECE_OVERHEAD` and its
data, each acknowledged gap it records :data:`PIECE_OVERHEAD`, and each
retained run :data:`PIECE_OVERHEAD`, the bytes its ``bytearray`` has
allocated, and a fixed charge per frame it names. A connection over
``max_flow_bytes`` first sheds retained bytes, oldest first, then
recorded acknowledged gaps, oldest first, then has its lowest hole
declared a ``Gap(CAP)`` and the held
bytes after it delivered, until it fits; one whose fixed state alone
does not fit is evicted. To make room under ``max_flows`` or
``max_total_bytes``, the least recently active connection that has not
carried data both ways is evicted, or else the least recently active
one, its own frame's connection included. An evicted or expired
connection is flushed: each hole a ``Gap(FLUSH)``, held bytes
delivered, each open direction a :class:`StreamEnd`, then
:class:`Evicted` or :class:`Expired`. Idle timeouts run from the
latest frame, longer once data has gone both ways and shorter once
every direction has ended by FIN.

**Order of a stream's events.** Expiries and evictions of other
connections come first, with ``completing_ref=None``; then the flush of
a connection a SYN ended; then the segment's own direction's events
and the other direction's, each in stream offset order; then its own
connection's eviction, with its reference.

**Errors.** Hostile, malformed and inconsistent input produces events,
never an exception. The methods raise :class:`TypeError` for an
argument of the wrong type and :class:`ValueError` for a negative
timestamp or a frame shorter than its packet; the constructors raise
:class:`ValueError` for an invalid bound, network or policy.
"""

from __future__ import annotations

import bisect
import enum
import heapq
import ipaddress
import itertools
import typing
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import NamedTuple

from netprotocols._base import Protocol, ipv4_to_bytes, ipv6_to_bytes
from netprotocols.checksum import internet_checksum
from netprotocols.flow import FlowKey, flow_key
from netprotocols.layer3.ip import IPv4, IPv6
from netprotocols.layer3.ipv6_ext import (
    IPv6Fragment,
    IPv6Routing,
    _effective_destination,
)
from netprotocols.layer4.tcp import TCP
from netprotocols.packet import Packet, _enclosing_ip

__all__ = [
    "FLOW_OVERHEAD",
    "NO_TIMEOUT",
    "PIECE_OVERHEAD",
    "SECOND",
    "Anomaly",
    "AnomalyKind",
    "Bound",
    "ChecksumMode",
    "Datagram",
    "Direction",
    "EndReason",
    "Evicted",
    "Expired",
    "FragmentBounds",
    "FragmentEvent",
    "FragmentKey",
    "FragmentReassembler",
    "FragmentTarget",
    "Gap",
    "GapReason",
    "LateData",
    "OutOfOrder",
    "Overlap",
    "OverlapPolicy",
    "Retransmission",
    "Span",
    "StreamBounds",
    "StreamData",
    "StreamEnd",
    "StreamEvent",
    "StreamReassembler",
    "Timeout",
    "Usage",
]

#: One second in the nanoseconds every timestamp and timeout counts.
SECOND = 1_000_000_000

#: Bytes charged for each datagram in progress, beyond its pieces.
FLOW_OVERHEAD = 1024

#: Bytes charged for each stored piece, beyond its data.
PIECE_OVERHEAD = 512

#: The largest IPv4 Total Length and IPv6 reassembled Payload Length.
_MAX_DATAGRAM = 65_535

#: The largest IPv4 header, in bytes.
_MAX_IPV4_HEADER = 60

#: Completion time past the first fragment above which an IPv4
#: datagram is :attr:`AnomalyKind.SLOW_REASSEMBLY` under the global age
#: timeout.
_SLOW_IPV4 = 30 * SECOND

#: Bytes of the upper-layer header an IPv6 first fragment must hold, by
#: protocol number; any other needs 1.
_UPPER_HEADER_BYTES = {6: 20, 17: 8, 58: 8, 59: 0}

#: IPv6 extension headers walked through when checking a header chain.
_EXTENSION_HEADERS = frozenset({0, 43, 44, 51, 60})


class OverlapPolicy(enum.Enum):
    """Which version of an overlapped byte a receiver keeps.

    The values are Snort frag3's policy names. "Held" is a fragment
    already stored, "arriving" the one being fed, and "begins" and
    "ends" refer to whole fragments as they arrived.
    """

    #: Held, always. HP-UX 11.00, Mac OS, SunOS 5.5.1 to 5.8.
    FIRST = "first"
    #: Arriving, always. Cisco IOS.
    LAST = "last"
    #: Held where the held fragment begins at or before the arriving
    #: one, arriving where it begins after. FreeBSD, AIX, IRIX, OpenVMS,
    #: Tru64 and others in frag3's table.
    BSD = "bsd"
    #: As :attr:`BSD`, and arriving over a held fragment that begins at
    #: the same offset. Linux before commit 7969e5c40dfd, OpenBSD.
    LINUX = "linux"
    #: Held, except over a held fragment the arriving one begins before
    #: and ends after. Windows 95 to XP.
    WINDOWS = "windows"
    #: Held, except over a held fragment the arriving one begins before
    #: and ends at or after the end of.
    SOLARIS = "solaris"
    #: Every overlap but an exact duplicate (same offset, length and
    #: bytes) discards the datagram, as RFC 5722 §4 does for IPv6.
    DISCARD = "discard"
    #: A fragment inside one run of held contiguous fragments, as Linux
    #: builds runs, is dropped, the held bytes kept; any other overlap
    #: discards the datagram. Linux with commits 7969e5c40dfd,
    #: ade446403bfb and 0ff89efb5246.
    LINUX_DISCARD = "linux-discard"


class Direction(enum.Enum):
    """The direction of a TCP event relative to its flow key."""

    #: From ``addr_a``/``port_a`` to ``addr_b``/``port_b``.
    A_TO_B = "a_to_b"
    #: From ``addr_b``/``port_b`` to ``addr_a``/``port_a``.
    B_TO_A = "b_to_a"


class Bound(enum.Enum):
    """The cap whose limit an :class:`Evicted` event enforced."""

    #: The charged bytes of one datagram or TCP connection.
    MAX_FLOW_BYTES = "max_flow_bytes"
    #: The charged bytes of the reassembler.
    MAX_TOTAL_BYTES = "max_total_bytes"
    #: The datagrams or connections held at once.
    MAX_FLOWS = "max_flows"
    #: The pieces one datagram holds.
    MAX_FRAGMENTS = "max_fragments"


class Timeout(enum.Enum):
    """The timeout an :class:`Expired` event enforced."""

    #: Measured from the datagram's latest fragment, or the
    #: connection's latest frame.
    IDLE = "idle"
    #: Measured from the datagram's first-arriving fragment, or the
    #: connection's first frame.
    AGE = "age"


class AnomalyKind(enum.Enum):
    """A rule a fragment or segment breaks, or an evasion pattern it matches."""

    #: The fragment would end the datagram past 65,535 bytes.
    OVERSIZE = "oversize"
    #: MF or M set and a data length that is not a multiple of 8.
    MISALIGNED = "misaligned"
    #: A last fragment disagreeing with a known end, or data past one.
    INCONSISTENT_END = "inconsistent_end"
    #: A fragment with no data.
    EMPTY_FRAGMENT = "empty_fragment"
    #: An IPv6 first fragment without the whole header chain.
    INCOMPLETE_HEADER_CHAIN = "incomplete_header_chain"
    #: An IPv4 first fragment too short for its TCP or UDP header.
    TINY_FRAGMENT = "tiny_fragment"
    #: An IPv4 fragment of TCP at offset 1.
    TCP_OFFSET_ONE = "tcp_offset_one"
    #: Captured bytes shorter than the declared length.
    TRUNCATED = "truncated"
    #: An IPv4 header or TCP checksum that does not verify.
    BAD_CHECKSUM = "bad_checksum"
    #: A bad checksum taken as one a NIC was left to fill.
    CHECKSUM_OFFLOAD = "checksum_offload"
    #: A fragment or segment whose IP header declares a length of 0.
    UNVERIFIED_CHECKSUM = "unverified_checksum"
    #: A TTL or Hop Limit other than the datagram's first-arriving
    #: fragment's, or the TCP direction's previous segment's.
    HOP_LIMIT_CHANGED = "hop_limit_changed"
    #: A Fragment Next Header other than the first-arriving fragment's.
    NEXT_HEADER_CHANGED = "next_header_changed"
    #: An IPv4 datagram completed more than 30 seconds after its first
    #: fragment, which a Linux target has discarded.
    SLOW_REASSEMBLY = "slow_reassembly"
    #: A TCP direction whose first segment with data or FIN came without
    #: a SYN, so its offset 0 is that segment's sequence number.
    MIDSTREAM = "midstream"
    #: TCP data before a direction's offset 0, which cannot be placed.
    BEFORE_STREAM_START = "before_stream_start"
    #: TCP data on a SYN.
    SYN_DATA = "syn_data"
    #: A SYN whose ISN differs from the direction's.
    ISN_CHANGED = "isn_changed"
    #: A TCP segment that is neither a SYN nor an RST, with ACK clear.
    DATA_WITHOUT_ACK = "data_without_ack"
    #: A FIN that disagrees with the end an earlier FIN fixed, or that
    #: ends before data already received.
    INCONSISTENT_FIN = "inconsistent_fin"
    #: TCP data past the end a FIN fixed.
    DATA_AFTER_FIN = "data_after_fin"
    #: An RST carrying data, which is diagnostic text, not stream data.
    RST_WITH_DATA = "rst_with_data"
    #: An RST; the connection's end is pending.
    RST_RECEIVED = "rst_received"
    #: TCP data above what a direction held when an RST arrived.
    DATA_AFTER_RST = "data_after_rst"
    #: A SYN with a new ISN that ended a connection whose RST was pending.
    SYN_AFTER_RST = "syn_after_rst"
    #: A TCP connection from an endpoint to itself on the same port.
    SELF_CONNECTED = "self_connected"
    #: TCP data past the furthest right window edge its receiver
    #: advertised.
    OUT_OF_WINDOW = "out_of_window"
    #: An acknowledgement past the highest offset its direction received.
    ACK_BEYOND_DATA = "ack_beyond_data"
    #: A TCP segment with URG set.
    URGENT = "urgent"


class EndReason(enum.Enum):
    """Why a TCP direction ended, as a :class:`StreamEnd` reports it."""

    #: Delivery reached the end the direction's FIN fixed.
    FIN = "fin"
    #: An RST was confirmed: its closed timeout passed with no data after
    #: it, a SYN with a new ISN followed it, or
    #: :meth:`StreamReassembler.close` came first.
    RST = "rst"
    #: The connection's idle timeout.
    IDLE = "idle"
    #: The connection's age timeout.
    AGE = "age"
    #: A bound evicted the connection.
    EVICTED = "evicted"
    #: :meth:`StreamReassembler.close`.
    CLOSE = "close"


class GapReason(enum.Enum):
    """Why a TCP direction skipped bytes it never received."""

    #: ``max_flow_bytes`` forced the lowest hole out.
    CAP = "cap"
    #: The capture cut the segment that declared them.
    TRUNCATED = "truncated"
    #: The connection was flushed by an expiry, an eviction, an RST or
    #: :meth:`StreamReassembler.close`.
    FLUSH = "flush"
    #: The peer acknowledged past them, and the hole stayed open
    #: ``ack_gap_grace`` after the first acknowledgement past it while
    #: it was the lowest.
    ACKED = "acked"


class ChecksumMode(enum.Enum):
    """What a fragment or segment with a bad checksum does.

    A fragment's IPv4 header checksum is judged; a TCP segment's IPv4
    header checksum and TCP checksum are.
    """

    #: The fragment or segment is dropped.
    DROP = "drop"
    #: The fragment or segment is used.
    KEEP = "keep"
    #: A bad checksum that is a value a stack leaves for its NIC to fill
    #: is taken as offloaded, and the fragment or segment used, with
    #: :attr:`AnomalyKind.CHECKSUM_OFFLOAD`, from a source in ``local``
    #: (from any source when ``local`` is not given); any other bad
    #: checksum is dropped. For an IPv4 header the value is 0, which
    #: Windows leaves. For TCP it is the folded pseudo-header sum,
    #: uncomplemented, with the segment's length, as Linux, FreeBSD and
    #: Windows checksum offload leave it, or without any length, as
    #: Windows large send offload does.
    AUTO = "auto"


class Span(NamedTuple):
    """The bytes one frame supplied to an event.

    :param ref: The frame's reference, as passed to
        :meth:`FragmentReassembler.feed` or :meth:`StreamReassembler.feed`.
    :param start: The first byte the frame supplied, as an offset into
        the reassembled payload or the TCP direction's byte stream.
    :param end: One past the last byte, half-open.
    :param timestamp: The frame's capture time, in nanoseconds.
    :param hop_limit: The IPv4 TTL or IPv6 Hop Limit it arrived with.
    """

    ref: int
    start: int
    end: int
    timestamp: int
    hop_limit: int


class Usage(NamedTuple):
    """What a reassembler holds, in the units its bounds charge.

    :param flows: The datagrams in progress, or the TCP connections.
    :param bytes: The bytes charged for them.
    """

    flows: int
    bytes: int


class FragmentKey(NamedTuple):
    """The fields a receiver reassembles a datagram on.

    :param version: ``4`` or ``6``.
    :param src: The source address, as the IP header decodes it.
    :param dst: The destination address, as the IP header decodes it.
    :param protocol: The IPv4 Protocol; ``None`` for IPv6, whose
        Fragment Next Header is not part of the key.
    :param identification: The IPv4 Identification, or the IPv6
        Fragment header's.
    """

    version: int
    src: str
    dst: str
    protocol: int | None
    identification: int


def _positive(value: object) -> bool:
    """Return whether ``value`` is an ``int``, not a ``bool``, above 0."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


@dataclass(frozen=True, slots=True, kw_only=True)
class FragmentBounds:
    """The caps and timeouts of a :class:`FragmentReassembler`.

    :param max_flow_bytes: Charged bytes one datagram may hold. ``None``
        means ``65_535 + 60 + max_fragments * PIECE_OVERHEAD +
        FLOW_OVERHEAD`` (:data:`PIECE_OVERHEAD`, :data:`FLOW_OVERHEAD`),
        which a valid datagram never exceeds.
    :param max_total_bytes: Charged bytes across all datagrams.
    :param max_flows: Datagrams in progress at once.
    :param max_fragments: Pieces one datagram may hold.
    :param idle_timeout: Nanoseconds from a datagram's latest fragment
        to its expiry, or ``None`` for none.
    :param age_timeout: Nanoseconds from a datagram's first-arriving
        fragment to its expiry, or ``None`` for none.
    :raises ValueError: if a cap is not a positive ``int``, or a
        timeout is neither ``None`` nor a positive ``int``.
    """

    max_flow_bytes: int | None = None
    max_total_bytes: int = 32 * 1024 * 1024
    max_flows: int = 16_384
    max_fragments: int = 128
    idle_timeout: int | None = None
    age_timeout: int | None = 60 * SECOND

    def __post_init__(self) -> None:
        """Check every cap and timeout.

        :raises ValueError: if a cap is not a positive ``int``, or a
            timeout is neither ``None`` nor a positive ``int``.
        """
        for name in ("max_total_bytes", "max_flows", "max_fragments"):
            if not _positive(getattr(self, name)):
                raise ValueError(f"{name} must be a positive int")
        for name in ("max_flow_bytes", "idle_timeout", "age_timeout"):
            value = getattr(self, name)
            if value is not None and not _positive(value):
                raise ValueError(f"{name} must be None or a positive int")


class _NoTimeout(enum.Enum):
    """The type of :data:`NO_TIMEOUT`."""

    #: No timeout.
    NO_TIMEOUT = "no_timeout"


#: A :class:`FragmentTarget` timeout that turns that timeout off for the
#: target's hosts, whatever the bounds set.
NO_TIMEOUT = _NoTimeout.NO_TIMEOUT


@dataclass(frozen=True, slots=True, kw_only=True)
class FragmentTarget:
    """The fragment handling of the hosts in one ``targets`` network.

    :param policy: Their overlap policy; ``None`` means the
        reassembler's ``policy``.
    :param age_timeout: Their age timeout in nanoseconds,
        :data:`NO_TIMEOUT` for none, or ``None`` for the bounds'
        ``age_timeout``.
    :param idle_timeout: Their idle timeout in nanoseconds,
        :data:`NO_TIMEOUT` for none, or ``None`` for the bounds'
        ``idle_timeout``.
    :raises ValueError: if ``policy`` is neither ``None`` nor an
        :class:`OverlapPolicy`, or a timeout is neither ``None``,
        :data:`NO_TIMEOUT` nor a positive ``int``.
    """

    policy: OverlapPolicy | None = None
    age_timeout: int | _NoTimeout | None = None
    idle_timeout: int | _NoTimeout | None = None

    def __post_init__(self) -> None:
        """Check the policy and the timeouts.

        :raises ValueError: if ``policy`` is neither ``None`` nor an
            :class:`OverlapPolicy`, or a timeout is neither ``None``,
            :data:`NO_TIMEOUT` nor a positive ``int``.
        """
        if self.policy is not None and not isinstance(
            self.policy, OverlapPolicy
        ):
            raise ValueError(f"{self.policy!r} is not an OverlapPolicy")
        for name in ("age_timeout", "idle_timeout"):
            value = getattr(self, name)
            if value not in (None, NO_TIMEOUT) and not _positive(value):
                raise ValueError(
                    f"{name} must be None, NO_TIMEOUT or a positive int"
                )


@dataclass(frozen=True, slots=True, kw_only=True)
class StreamBounds:
    """The caps and timeouts of a :class:`StreamReassembler`.

    :param max_flow_bytes: Charged bytes one TCP connection, both
        directions, may hold.
    :param max_total_bytes: Charged bytes across all connections.
    :param max_flows: Connections held at once.
    :param retain_bytes: Delivered bytes a direction keeps below its
        peer's highest acknowledgement, or below its delivered end
        without one, to compare retransmissions against.
    :param idle_timeout_new: Nanoseconds from the latest frame of a
        connection that has not carried data in both directions to its
        expiry, or ``None`` for none.
    :param idle_timeout_established: The same for a connection that has
        carried data in both directions.
    :param idle_timeout_closed: The same once every direction has ended
        by FIN; also the time from an RST to its confirmation.
    :param age_timeout: Nanoseconds from a connection's first frame to
        its expiry, or ``None`` for none.
    :param ack_gap_grace: Nanoseconds a hole must stay open after the
        first acknowledgement past it before a later frame declares it
        a :class:`Gap`.
    :raises ValueError: if a cap or ``ack_gap_grace`` is not a positive
        ``int``, or a timeout is neither ``None`` nor a positive
        ``int``.
    """

    max_flow_bytes: int = 4 * 1024 * 1024
    max_total_bytes: int = 128 * 1024 * 1024
    max_flows: int = 65_536
    retain_bytes: int = 64 * 1024
    idle_timeout_new: int | None = 60 * SECOND
    idle_timeout_established: int | None = 3_600 * SECOND
    idle_timeout_closed: int | None = 120 * SECOND
    age_timeout: int | None = None
    ack_gap_grace: int = SECOND

    def __post_init__(self) -> None:
        """Check every cap and timeout.

        :raises ValueError: if a cap or ``ack_gap_grace`` is not a
            positive ``int``, or a timeout is neither ``None`` nor a
            positive ``int``.
        """
        for name in (
            "max_flow_bytes",
            "max_total_bytes",
            "max_flows",
            "retain_bytes",
            "ack_gap_grace",
        ):
            if not _positive(getattr(self, name)):
                raise ValueError(f"{name} must be a positive int")
        for name in (
            "idle_timeout_new",
            "idle_timeout_established",
            "idle_timeout_closed",
            "age_timeout",
        ):
            value = getattr(self, name)
            if value is not None and not _positive(value):
                raise ValueError(f"{name} must be None or a positive int")


@dataclass(frozen=True, slots=True, kw_only=True)
class _Event:
    """The fields every reassembly event has.

    :param flow: The datagram's :class:`FragmentKey`, or the TCP
        connection's :class:`~netprotocols.flow.FlowKey`.
    :param direction: The TCP direction relative to the flow key's
        ``addr_a``; ``None`` for fragments and for an event about a
        whole connection.
    :param spans: The contributing frames, sorted by ``start`` then
        ``ref``.
    :param completing_ref: The reference of the fed frame whose own
        fragment or segment caused the event; ``None`` when an expiry,
        the eviction of a datagram or connection to make room for
        another, ``advance`` or ``close`` caused it.
    :param first_timestamp: The earliest ``timestamp`` among ``spans``;
        with no spans, that of the datagram's first-arriving fragment
        or the connection's first frame.
    :param last_timestamp: The latest ``timestamp`` among ``spans``;
        with no spans, the latest of the datagram's fragments or the
        connection's frames.
    """

    flow: FragmentKey | FlowKey
    direction: Direction | None
    spans: tuple[Span, ...]
    completing_ref: int | None
    first_timestamp: int
    last_timestamp: int

    @property
    def refs(self) -> tuple[int, ...]:
        """The sorted, distinct references of :attr:`spans`."""
        return tuple(sorted({span.ref for span in self.spans}))


@dataclass(frozen=True, slots=True, kw_only=True)
class Datagram(_Event):
    """A datagram whose last missing fragment arrived.

    ``data`` is the whole datagram, header included, which
    :func:`~netprotocols.decode_frame` decodes with ``start`` set to
    :class:`~netprotocols.IPv4` or :class:`~netprotocols.IPv6`. The
    header is the one of the fragment that supplied the payload's first
    byte (``header_ref``), rewritten as RFC 791 §3.1 and RFC 8200 §4.5
    give it. IPv4: Total Length set to the reassembled length, MF
    cleared, Fragment Offset 0, DF and the reserved bit kept, the
    Header Checksum recomputed. IPv6: the Per-Fragment headers, the
    Next Header of the last one set to the Fragment header's Next
    Header, the Fragment header removed and Payload Length recomputed.
    ``spans`` tile the payload, ``data[payload_offset:]``.

    :param version: ``4`` or ``6``.
    :param data: The reassembled datagram, header included.
    :param payload_offset: Where the payload starts in ``data``: the
        IPv4 header's length, or the IPv6 Per-Fragment headers'.
    :param header_ref: The reference of the frame the header came from.
    """

    version: int
    data: bytes
    payload_offset: int
    header_ref: int


@dataclass(frozen=True, slots=True, kw_only=True)
class Overlap(_Event):
    """Arriving bytes that overlap held or delivered bytes and differ.

    Under a rule that discards on overlap (every IPv6 overlap but an
    exact duplicate, and the ``discard`` and ``linux-discard``
    policies), any overlap the rule names, equal or not. One event per
    fed frame, covering the smallest range that holds every differing
    byte, or every overlapping byte under a discarding rule. ``kept``
    and ``other`` are that range's two versions, ``kept`` the one the
    policy keeps; where only one version exists, both hold it. When the
    datagram is discarded, ``kept`` is the held version and ``spans``
    hold every fragment the datagram held and the arriving one;
    otherwise ``spans`` are those of ``kept_spans`` and
    ``other_spans``. Ranges count fragments' declared lengths: where the
    snap length cut the arriving fragment short of the range's end,
    ``kept``, ``other`` and their spans stop where its capture does.

    For a TCP direction, bytes not yet delivered are resolved by the
    receiver's policy; delivered bytes are final, so over them ``kept``
    is always the delivered version.

    :param start: The range's first byte, as a payload offset.
    :param end: One past its last byte.
    :param policy: The :class:`OverlapPolicy` applied;
        :attr:`OverlapPolicy.DISCARD` for IPv6 fragments.
    :param kept: The range's bytes as kept.
    :param other: The range's other version.
    :param kept_spans: The frames that supplied ``kept``, tiling it.
    :param other_spans: The frames that supplied ``other``, tiling it.
    :param resolved: ``False`` when the datagram was discarded; always
        ``True`` for TCP.
    :param contrary: Whether delivered bytes differ that the policy
        would have replaced had they not been delivered: always
        ``False`` for fragments, and for TCP under ``last`` only.
    """

    start: int
    end: int
    policy: OverlapPolicy
    kept: bytes
    other: bytes
    kept_spans: tuple[Span, ...]
    other_spans: tuple[Span, ...]
    resolved: bool
    contrary: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class Retransmission(_Event):
    """Arriving bytes that repeat held or delivered bytes exactly.

    For TCP, also bytes that repeat ones the direction received but
    cannot compare: delivered bytes it no longer retains, bytes a gap
    skipped other than an acknowledged one, and bytes the capture cut
    from either version. A SYN that repeats its direction's ISN is one
    over ``(0, 0)``.

    :param start: The first repeated byte, as a payload or stream
        offset.
    :param end: One past the last.
    :param verified: Whether every repeated byte was compared; always
        ``True`` for fragments.
    """

    start: int
    end: int
    verified: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class Evicted(_Event):
    """A datagram a bound discarded, or a TCP connection it flushed.

    A connection's flush comes first, as :class:`Gap`,
    :class:`StreamData` and :class:`StreamEnd` events.

    :param bound: The cap enforced.
    :param held_bytes: The data bytes the datagram held, or the
        undelivered bytes the connection held.
    :param missing: The ranges of the payload no span covers, as
        ``(start, end)`` pairs; the last ``end`` is ``None`` when the
        last fragment never arrived. Empty for a connection, whose
        holes its :class:`Gap` events report.
    """

    bound: Bound
    held_bytes: int
    missing: tuple[tuple[int, int | None], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Expired(_Event):
    """A datagram or TCP connection a timeout or ``close`` removed.

    A connection's flush comes first, as for :class:`Evicted`.

    :param timeout: The timeout whose deadline came first.
    :param held_bytes: The data bytes the datagram held, or the
        undelivered bytes the connection held.
    :param missing: The ranges of the payload no span covers, as for
        :class:`Evicted`.
    """

    timeout: Timeout
    held_bytes: int
    missing: tuple[tuple[int, int | None], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Anomaly(_Event):
    """A fragment or segment that breaks a rule or matches an evasion pattern.

    A segment's offsets are those of its direction, or run from 0 while
    the direction's offset 0 is unknown.

    :param kind: The rule.
    :param start: The first byte concerned, as a payload or stream
        offset.
    :param end: One past the last.
    """

    kind: AnomalyKind
    start: int
    end: int


@dataclass(frozen=True, slots=True, kw_only=True)
class StreamData(_Event):
    """Bytes of a TCP direction that became contiguous with its delivered end.

    ``spans`` tile ``data``, so ``offset + len(data)`` is the next
    run's ``offset``, except across a :class:`Gap`.

    :param offset: The stream offset of ``data[0]``.
    :param data: The bytes.
    """

    offset: int
    data: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class StreamEnd(_Event):
    """A TCP direction that ended; no :class:`StreamData` of it follows.

    :param offset: The direction's final offset, one past its last
        delivered or skipped byte.
    :param reason: Why it ended.
    """

    offset: int
    reason: EndReason


@dataclass(frozen=True, slots=True, kw_only=True)
class OutOfOrder(_Event):
    """A TCP segment held past a hole in its direction.

    :param start: Its first byte, as a stream offset.
    :param end: One past its last declared byte.
    :param expected: The direction's next expected offset.
    """

    start: int
    end: int
    expected: int


@dataclass(frozen=True, slots=True, kw_only=True)
class Gap(_Event):
    """Bytes a TCP direction skipped without receiving them.

    :param start: The first skipped byte, as a stream offset.
    :param end: One past the last.
    :param reason: Why they were skipped.
    """

    start: int
    end: int
    reason: GapReason


@dataclass(frozen=True, slots=True, kw_only=True)
class LateData(_Event):
    """Bytes that arrived for the range of a :class:`Gap` the peer acknowledged.

    They lie outside the ordered :class:`StreamData` runs; ``spans``
    tile ``data``.

    :param offset: The stream offset of ``data[0]``.
    :param data: The bytes.
    """

    offset: int
    data: bytes


#: Every event type :class:`FragmentReassembler` returns.
FragmentEvent = (
    Datagram | Overlap | Retransmission | Evicted | Expired | Anomaly
)

#: Every event type :class:`StreamReassembler` returns.
StreamEvent = (
    StreamData
    | StreamEnd
    | OutOfOrder
    | Gap
    | LateData
    | Overlap
    | Retransmission
    | Evicted
    | Expired
    | Anomaly
)


class _Source:
    """One fragment as it arrived, shared by the pieces it supplied."""

    __slots__ = (
        "end",
        "header",
        "hop_limit",
        "next_at",
        "ref",
        "start",
        "timestamp",
    )

    def __init__(
        self,
        ref: int,
        timestamp: int,
        hop_limit: int,
        start: int,
        end: int,
        header: bytes,
        next_at: int,
    ) -> None:
        self.ref = ref
        self.timestamp = timestamp
        self.hop_limit = hop_limit
        self.start = start
        self.end = end
        #: The IPv4 header, or the IPv6 Per-Fragment headers followed by
        #: the Fragment header's Next Header; empty past offset 0.
        self.header = header
        #: Where the IPv6 Next Header naming the Fragment header is.
        self.next_at = next_at

    def span(self, start: int, end: int) -> Span:
        """Return this fragment's :class:`Span` over ``[start, end)``.

        :param start: The first byte, as a payload offset.
        :param end: One past the last.
        """
        return Span(self.ref, start, end, self.timestamp, self.hop_limit)


class _Piece:
    """Stored bytes of one fragment, at a payload offset."""

    __slots__ = ("data", "end", "source", "start")

    def __init__(self, start: int, data: bytes, source: _Source) -> None:
        self.start = start
        self.end = start + len(data)
        self.data = data
        self.source = source


def _charge(piece: _Piece) -> int:
    """Return the bytes charged for one stored piece.

    That is :data:`PIECE_OVERHEAD`, its data, and the header its
    fragment kept for the reassembled datagram.

    :param piece: The piece.
    """
    return PIECE_OVERHEAD + len(piece.data) + len(piece.source.header)


class _Flow:
    """One datagram in progress."""

    __slots__ = (
        "age",
        "bare",
        "charge",
        "covered",
        "created",
        "deadline",
        "end",
        "first_hop",
        "first_next",
        "header_extra",
        "idle",
        "key",
        "last",
        "pieces",
        "policy",
        "reach",
        "runs",
        "seq",
        "slow",
        "starts",
    )

    def __init__(
        self,
        key: FragmentKey,
        seq: int,
        timestamp: int,
        policy: OverlapPolicy,
        timeouts: tuple[int | None, int | None, bool],
    ) -> None:
        self.key = key
        self.seq = seq
        self.created = timestamp
        self.last = timestamp
        self.policy = policy
        self.age, self.idle, self.slow = timeouts
        self.pieces: list[_Piece] = []
        self.starts: list[int] = []
        self.runs: list[list[int]] = []
        self.end: int | None = None
        self.reach = 0
        self.covered = 0
        self.charge = FLOW_OVERHEAD
        self.bare = 0
        self.first_hop = -1
        self.first_next = -1
        self.header_extra: int | None = None
        self.deadline: tuple[int, Timeout] | None = None

    def due(self) -> tuple[int, Timeout] | None:
        """Return the earliest deadline and its timeout, if any."""
        age = None if self.age is None else self.created + self.age
        idle = None if self.idle is None else self.last + self.idle
        if age is not None and (idle is None or age <= idle):
            return age, Timeout.AGE
        if idle is not None:
            return idle, Timeout.IDLE
        return None

    def spans(self) -> list[Span]:
        """Return the spans of every held piece."""
        return [
            piece.source.span(piece.start, piece.end) for piece in self.pieces
        ]


class _Located(NamedTuple):
    """Where a fed frame's fragment is."""

    ip: IPv4 | IPv6
    fragment: IPv6Fragment | None
    routing: IPv6Routing | None
    ip_at: int
    data_at: int
    next_at: int


class _Arrival(NamedTuple):
    """One fragment sliced out of a fed frame."""

    key: FragmentKey
    receiver: str
    source: _Source
    data: bytes
    declared: int | None
    more: bool
    fragment_offset: int
    protocol: int
    extra_header: int
    checksum_bad: bool
    checksum_zero: bool


class _Stop(NamedTuple):
    """The end of a fragment's processing, and the event that ends it."""

    event: FragmentEvent | None


class _Plan(NamedTuple):
    """How an arriving fragment changes its datagram's pieces.

    ``dropped`` marks a ``linux-discard`` duplicate, which Linux drops
    before it checks whether the datagram is complete: its end, when it
    is the last fragment, is recorded, but it completes nothing.
    """

    first: int
    last: int
    pieces: list[_Piece]
    event: FragmentEvent | None
    discard: bool
    dropped: bool = False


def _event_times(
    spans: list[Span], default: tuple[int, int] = (0, 0)
) -> tuple[tuple[Span, ...], int, int]:
    """Return ``spans`` sorted, with their earliest and latest timestamp.

    :param spans: The spans of an event.
    :param default: The two timestamps when ``spans`` is empty.
    """
    ordered = tuple(sorted(spans, key=lambda span: (span.start, span.ref)))
    if not ordered:
        return ordered, default[0], default[1]
    times = [span.timestamp for span in ordered]
    return ordered, min(times), max(times)


def _missing(
    spans: list[Span], end: int | None
) -> tuple[tuple[int, int | None], ...]:
    """Return the payload ranges no span covers.

    :param spans: The spans of a discarded datagram.
    :param end: The payload's length, or ``None`` when no last fragment
        arrived.
    """
    holes: list[tuple[int, int | None]] = []
    cursor = 0
    for span in sorted(spans, key=lambda span: (span.start, span.end)):
        if span.start > cursor:
            holes.append((cursor, span.start))
        cursor = max(cursor, span.end)
    if end is None:
        holes.append((cursor, None))
    elif cursor < end:
        holes.append((cursor, end))
    return tuple(holes)


def _first_difference(held: bytes, arriving: bytes) -> int:
    """Return the index of the first byte where two runs differ.

    :param held: One version.
    :param arriving: The other, of the same length, and different.
    """
    low, high = 0, len(held)
    while high - low > 1:
        middle = (low + high) // 2
        if held[low:middle] != arriving[low:middle]:
            high = middle
        else:
            low = middle
    return low


def _difference(held: bytes, arriving: bytes) -> tuple[int, int] | None:
    """Return the smallest range holding every byte where two runs differ.

    The range is ``(first, last + 1)``, relative to the runs' start;
    ``None`` when they are equal.

    :param held: One version.
    :param arriving: The other, of the same length.
    """
    if held == arriving:
        return None
    first = _first_difference(held, arriving)
    last = len(held) - 1 - _first_difference(held[::-1], arriving[::-1])
    return first, last + 1


def _arriving_wins(
    policy: OverlapPolicy, held: _Source, arriving: _Source
) -> bool:
    """Return whether ``arriving`` replaces ``held`` where they overlap.

    :param policy: The receiver's policy.
    :param held: The fragment that supplied the held bytes.
    :param arriving: The arriving fragment.
    """
    if policy is OverlapPolicy.LAST:
        return True
    if policy is OverlapPolicy.BSD:
        return held.start > arriving.start
    if policy is OverlapPolicy.LINUX:
        return held.start >= arriving.start
    if policy is OverlapPolicy.WINDOWS:
        return arriving.start < held.start and arriving.end > held.end
    if policy is OverlapPolicy.SOLARIS:
        return arriving.start < held.start and arriving.end >= held.end
    return False


def _chain_complete(next_header: int, data: bytes) -> bool:
    """Return whether ``data`` holds the IPv6 header chain it starts.

    The chain runs through the extension headers to the upper-layer
    header (RFC 7112 §5), which must be whole: for TCP the header and its
    options, as many bytes as its Data Offset gives and at least 20; 8
    bytes for UDP and ICMPv6, none for No Next Header and 1 for anything
    else.

    :param next_header: The Fragment header's Next Header.
    :param data: The first fragment's data.
    """
    cursor = 0
    while next_header in _EXTENSION_HEADERS:
        if cursor + 2 > len(data):
            return False
        if next_header == 44:
            length = 8
        elif next_header == 51:
            length = (data[cursor + 1] + 2) * 4
        else:
            length = (data[cursor + 1] + 1) * 8
        next_header = data[cursor]
        cursor += length
    needed = _UPPER_HEADER_BYTES.get(next_header, 1)
    if next_header == 6 and cursor + 13 <= len(data):
        needed = max(needed, (data[cursor + 12] >> 4) * 4)
    return cursor + needed <= len(data)


def _network(
    text: object, name: str
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse one network written as :func:`ipaddress.ip_network` accepts it.

    :param text: The network, or a bare address.
    :param name: The argument's name, for the error message.
    :raises ValueError: if it is not a string or does not parse.
    """
    if not isinstance(text, str):
        raise ValueError(f"{name}: {text!r} is not a network string")
    return ipaddress.ip_network(text, strict=False)


def _networks(
    texts: Iterable[str], name: str
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse networks written as :func:`ipaddress.ip_network` accepts them.

    :param texts: The networks, or bare addresses.
    :param name: The argument's name, for the error message.
    :raises ValueError: if one is not a string or does not parse.
    """
    return [_network(text, name) for text in texts]


def _locate(packet: Packet) -> _Located | None:
    """Find the outermost IP header of ``packet`` that is a fragment.

    ``None`` when no IP header is one.

    :param packet: The decoded packet.
    """
    offset = 0
    layers = packet.layers
    for index, layer in enumerate(layers):
        if isinstance(layer, IPv4):
            if layer.flags & 1 or layer.fragment_offset:
                end = offset + layer.header_len
                return _Located(layer, None, None, offset, end, 0)
        elif isinstance(layer, IPv6):
            cursor = offset + layer.header_len
            routing: IPv6Routing | None = None
            next_at = 6
            for later in layers[index + 1 :]:
                if isinstance(later, (IPv4, IPv6)):
                    break
                if isinstance(later, IPv6Fragment):
                    if later.m_flag or later.fragment_offset:
                        return _Located(
                            layer, later, routing, offset, cursor + 8, next_at
                        )
                    break
                if isinstance(later, IPv6Routing) and later.segments_left > 0:
                    routing = later
                next_at = cursor - offset
                cursor += later.header_len
        offset += layer.header_len
    return None


def _slice(
    packet: Packet,
    frame: bytes | bytearray | memoryview,
    located: _Located,
    timestamp: int,
    ref: int,
) -> _Arrival:
    """Slice one located fragment out of its frame.

    :param packet: The decoded packet.
    :param frame: The frame.
    :param located: Where the fragment is.
    :param timestamp: The frame's capture time.
    :param ref: The frame's reference.
    """
    ip, fragment, routing, ip_at, data_at, next_at = located
    bound = len(frame) - len(packet.trailer)
    if isinstance(ip, IPv4):
        declared_end = ip.total_length
        key = FragmentKey(4, ip.src, ip.dst, ip.protocol, ip.identification)
        header = bytes(frame[ip_at:data_at])
        more = bool(ip.flags & 1)
        fragment_offset = ip.fragment_offset
        protocol = ip.protocol
        hop_limit = ip.ttl
        checksum_bad = internet_checksum(header) != 0
        checksum_zero = ip.checksum == 0
        extra_header = len(header)
    else:
        fragment = typing.cast(IPv6Fragment, fragment)
        declared_end = ip.payload_length and ip.payload_length + 40
        key = FragmentKey(6, ip.src, ip.dst, None, fragment.identification)
        header = bytes(frame[ip_at : data_at - 8]) + bytes(
            [fragment.next_header]
        )
        more = bool(fragment.m_flag)
        fragment_offset = fragment.fragment_offset
        protocol = fragment.next_header
        hop_limit = ip.hop_limit
        checksum_bad = checksum_zero = False
        extra_header = data_at - 8 - ip_at - 40
    if declared_end:
        declared: int | None = max(0, ip_at + declared_end - data_at)
        stop = min(ip_at + declared_end, bound)
    else:
        declared = None
        stop = bound
    data = bytes(frame[data_at : max(data_at, stop)])
    start = fragment_offset * 8
    length = len(data) if declared is None else declared
    source = _Source(
        ref,
        timestamp,
        hop_limit,
        start,
        start + length,
        header if start == 0 else b"",
        next_at,
    )
    return _Arrival(
        key=key,
        receiver=_effective_destination(ip, routing),
        source=source,
        data=data,
        declared=declared,
        more=more,
        fragment_offset=fragment_offset,
        protocol=protocol,
        extra_header=extra_header,
        checksum_bad=checksum_bad,
        checksum_zero=checksum_zero,
    )


def _header_extra(source: _Source, key: FragmentKey) -> int:
    """Return the header bytes a datagram's length limit counts.

    That is the IPv4 header, or the IPv6 Per-Fragment headers past the
    40-byte IPv6 header, of the fragment at offset 0.

    :param source: The fragment at offset 0.
    :param key: Its datagram's key.
    """
    if key.version == 4:
        return len(source.header)
    return len(source.header) - 41


def _timeout(value: int | _NoTimeout) -> int | None:
    """Return a target's timeout as the bounds hold one.

    :param value: A positive ``int``, or :data:`NO_TIMEOUT`.
    """
    return None if isinstance(value, _NoTimeout) else value


def _check_timestamp(value: object) -> None:
    """Check that ``value`` is a capture timestamp.

    :param value: The argument.
    :raises TypeError: if it is not an ``int``, or is a ``bool``.
    :raises ValueError: if it is negative.
    """
    _check_int(value, "timestamp")
    if typing.cast(int, value) < 0:
        raise ValueError(f"timestamp must not be negative, got {value}")


def _check_int(value: object, name: str) -> None:
    """Check that ``value`` is an ``int`` and not a ``bool``.

    :param value: The argument.
    :param name: Its name, for the error message.
    :raises TypeError: if it is not.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an int, not {type(value).__name__}")


def _check_feed(
    packet: object, frame: object, timestamp: object, ref: object
) -> None:
    """Check the arguments of a ``feed`` call.

    :param packet: The packet argument.
    :param frame: The frame argument.
    :param timestamp: The timestamp argument.
    :param ref: The ref argument.
    :raises TypeError: if ``packet`` is not a
        :class:`~netprotocols.packet.Packet`, ``frame`` is not bytes, or
        ``timestamp`` or ``ref`` is not an ``int``.
    :raises ValueError: if ``timestamp`` is negative, or ``frame`` is
        shorter than ``packet.consumed + len(packet.trailer)``.
    """
    if not isinstance(packet, Packet):
        raise TypeError("packet must be a Packet")
    if not isinstance(frame, (bytes, bytearray, memoryview)):
        raise TypeError("frame must be bytes or a memoryview")
    _check_timestamp(timestamp)
    if ref is not None:
        _check_int(ref, "ref")
    if len(frame) < packet.consumed + len(packet.trailer):
        raise ValueError(
            f"frame holds {len(frame)} bytes, fewer than the packet's "
            f"{packet.consumed + len(packet.trailer)}"
        )


class FragmentReassembler:
    """Reassemble IPv4 and IPv6 fragments into :class:`Datagram` events.

    A reassembler is not thread-safe. Events are returned by the call
    that causes them and never queued, so what it holds is exactly the
    datagrams in progress and their pieces (:attr:`usage`).

    :param bounds: The caps and the global timeouts; ``None`` means
        ``FragmentBounds()``.
    :param policy: The overlap policy of an IPv4 receiver no ``targets``
        network holds.
    :param targets: Networks, written as :func:`ipaddress.ip_network`
        accepts them, mapped to the policy, or the
        :class:`FragmentTarget`, of the hosts in them. The longest
        prefix holding a datagram's receiver applies: its destination,
        or, behind an IPv6 Routing header with segments left before the
        Fragment header, the route's final destination. The policy
        applies to IPv4 datagrams, the timeouts to both versions.
    :param checksums: What a bad IPv4 header checksum does.
    :param local: The capture host's networks, from which
        :attr:`ChecksumMode.AUTO` accepts the offload pattern; ``None``
        accepts it from any source.
    :raises TypeError: if ``bounds`` is not a :class:`FragmentBounds`.
    :raises ValueError: if ``policy``, a ``targets`` value or
        ``checksums`` is not a member of its type, ``local`` is a
        ``str`` rather than an iterable of them, or a network does not
        parse.
    """

    def __init__(
        self,
        *,
        bounds: FragmentBounds | None = None,
        policy: OverlapPolicy = OverlapPolicy.FIRST,
        targets: Mapping[str, OverlapPolicy | FragmentTarget] | None = None,
        checksums: ChecksumMode = ChecksumMode.AUTO,
        local: Iterable[str] | None = None,
    ) -> None:
        if bounds is None:
            bounds = FragmentBounds()
        if not isinstance(bounds, FragmentBounds):
            raise TypeError("bounds must be a FragmentBounds")
        if not isinstance(policy, OverlapPolicy):
            raise ValueError(f"{policy!r} is not an OverlapPolicy")
        if not isinstance(checksums, ChecksumMode):
            raise ValueError(f"{checksums!r} is not a ChecksumMode")
        self._bounds = bounds
        self._policy = policy
        self._checksums = checksums
        self._flow_cap = (
            bounds.max_flow_bytes
            if bounds.max_flow_bytes is not None
            else _MAX_DATAGRAM
            + _MAX_IPV4_HEADER
            + bounds.max_fragments * PIECE_OVERHEAD
            + FLOW_OVERHEAD
        )
        self._targets: list[
            tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, FragmentTarget]
        ] = []
        for text, value in (targets or {}).items():
            if isinstance(value, OverlapPolicy):
                value = FragmentTarget(policy=value)
            if not isinstance(value, FragmentTarget):
                raise ValueError(
                    f"targets[{text!r}]: {value!r} is not an OverlapPolicy "
                    "or a FragmentTarget"
                )
            self._targets.append((_network(text, "targets"), value))
        self._targets.sort(key=lambda entry: -entry[0].prefixlen)
        if isinstance(local, str):
            raise ValueError("local must be an iterable of networks, not a str")
        self._local = None if local is None else _networks(local, "local")
        self._flows: dict[FragmentKey, _Flow] = {}
        self._deadlines: list[tuple[int, int, FragmentKey]] = []
        self._ages: list[tuple[int, int, FragmentKey]] = []
        self._total = 0
        self._clock: int | None = None
        self._fed = 0
        self._seq = 0

    @property
    def usage(self) -> Usage:
        """The datagrams in progress and the bytes charged for them."""
        return Usage(len(self._flows), self._total)

    def feed(
        self,
        packet: Packet,
        frame: bytes | memoryview,
        *,
        timestamp: int,
        ref: int | None = None,
    ) -> tuple[FragmentEvent, ...]:
        """Take one frame and return every event it caused.

        Every frame moves the capture clock to its timestamp, unless
        that is 0 or lower than the highest seen, and returns the
        expiries the clock causes. A packet none of whose IP headers is
        a fragment returns those expiries only, and changes nothing
        else but the count of frames fed.

        :param packet: The packet :func:`~netprotocols.decode_frame`
            decoded from ``frame``, a lax walk's included.
        :param frame: The frame.
        :param timestamp: Its capture time, in nanoseconds.
        :param ref: Its reference in events; ``None`` means the number
            of frames fed before it.
        :raises TypeError: if ``packet`` is not a
            :class:`~netprotocols.packet.Packet`, ``frame`` is not
            bytes, or ``timestamp`` or ``ref`` is not an ``int``.
        :raises ValueError: if ``timestamp`` is negative, or ``frame``
            is shorter than ``packet.consumed + len(packet.trailer)``.
        """
        _check_feed(packet, frame, timestamp, ref)
        if ref is None:
            ref = self._fed
        self._fed += 1
        events: list[FragmentEvent] = []
        self._tick(timestamp, events)
        located = _locate(packet)
        if located is None:
            return tuple(events)
        arrival = _slice(packet, frame, located, timestamp, ref)
        own: list[FragmentEvent] = []
        terminal = self._take(arrival, own, events)
        own.sort(key=lambda event: getattr(event, "start", 0))
        events.extend(own)
        if terminal is not None:
            events.append(terminal)
        return tuple(events)

    def advance(self, timestamp: int) -> tuple[FragmentEvent, ...]:
        """Move the capture clock to ``timestamp`` and return the expiries.

        :param timestamp: The capture time, in nanoseconds; 0, or one
            lower than the clock, moves nothing.
        :raises TypeError: if ``timestamp`` is not an ``int``.
        :raises ValueError: if ``timestamp`` is negative.
        """
        _check_timestamp(timestamp)
        events: list[FragmentEvent] = []
        self._tick(timestamp, events)
        return tuple(events)

    def close(self) -> tuple[FragmentEvent, ...]:
        """Discard every datagram in progress as :class:`Expired`.

        Datagrams go in deadline order, then those with no deadline,
        ties in the order they started, each reported under the timeout
        whose deadline comes first (:attr:`Timeout.AGE` when it has
        none). The reassembler is empty afterwards.
        """
        events: list[FragmentEvent] = []
        flows = sorted(
            self._flows.values(),
            key=lambda flow: (
                flow.deadline is None,
                flow.deadline[0] if flow.deadline else 0,
                flow.seq,
            ),
        )
        for flow in flows:
            timeout = flow.deadline[1] if flow.deadline else Timeout.AGE
            self._expire(flow, timeout, events)
        self._deadlines.clear()
        self._ages.clear()
        return tuple(events)

    def _target(self, receiver: str) -> FragmentTarget | None:
        """Return the target of the longest prefix holding ``receiver``.

        :param receiver: The receiver's address.
        """
        if not self._targets:
            return None
        address = ipaddress.ip_address(receiver)
        for network, target in self._targets:
            if address in network:
                return target
        return None

    def _is_local(self, address: str) -> bool:
        """Return whether ``address`` may carry the offload pattern.

        :param address: A fragment's source address.
        """
        if self._local is None:
            return True
        parsed = ipaddress.ip_address(address)
        return any(parsed in network for network in self._local)

    def _tick(self, timestamp: int, events: list[FragmentEvent]) -> None:
        """Move the clock and expire every datagram due by it.

        :param timestamp: A capture time.
        :param events: Where the expiries are appended.
        """
        if timestamp and (self._clock is None or timestamp > self._clock):
            self._clock = timestamp
        if self._clock is None:
            return
        while self._deadlines and self._deadlines[0][0] <= self._clock:
            deadline, seq, key = heapq.heappop(self._deadlines)
            flow = self._flows.get(key)
            if (
                flow is not None
                and flow.seq == seq
                and flow.deadline is not None
                and flow.deadline[0] == deadline
            ):
                self._expire(flow, flow.deadline[1], events)

    def _expire(
        self, flow: _Flow, timeout: Timeout, events: list[FragmentEvent]
    ) -> None:
        """Discard ``flow`` with an :class:`Expired` event.

        :param flow: The datagram.
        :param timeout: The timeout reported.
        :param events: Where the event is appended.
        """
        self._remove(flow)
        spans = flow.spans()
        ordered, first, last = _event_times(spans, (flow.created, flow.last))
        events.append(
            Expired(
                flow=flow.key,
                direction=None,
                spans=ordered,
                completing_ref=None,
                first_timestamp=first,
                last_timestamp=last,
                timeout=timeout,
                held_bytes=flow.covered,
                missing=_missing(spans, flow.end),
            )
        )

    def _evicted(
        self,
        flow: _Flow,
        bound: Bound,
        ref: int | None,
        arriving: list[Span],
        end: int | None = None,
    ) -> Evicted:
        """Discard ``flow`` and return its :class:`Evicted` event.

        :param flow: The datagram.
        :param bound: The cap enforced.
        :param ref: The ``completing_ref``.
        :param arriving: The spans the arriving fragment would have
            added, when its own datagram is the one discarded.
        :param end: The payload's length the arriving fragment declares,
            when it is the last fragment and its datagram is the one
            discarded.
        """
        self._remove(flow)
        spans = flow.spans() + arriving
        if end is None:
            end = flow.end
        ordered, first, last = _event_times(spans, (flow.created, flow.last))
        return Evicted(
            flow=flow.key,
            direction=None,
            spans=ordered,
            completing_ref=ref,
            first_timestamp=first,
            last_timestamp=last,
            bound=bound,
            held_bytes=flow.covered,
            missing=_missing(spans, end),
        )

    def _remove(self, flow: _Flow) -> None:
        """Drop ``flow`` from the reassembler, if it is held.

        :param flow: The datagram.
        """
        if self._flows.get(flow.key) is flow:
            del self._flows[flow.key]
            self._total -= flow.charge
            self._compact()

    def _compact(self) -> None:
        """Rebuild the deadline and age heaps once most entries are stale."""
        limit = 2 * len(self._flows) + 64
        if len(self._deadlines) > limit:
            self._deadlines = [
                (flow.deadline[0], flow.seq, flow.key)
                for flow in self._flows.values()
                if flow.deadline is not None
            ]
            heapq.heapify(self._deadlines)
        if len(self._ages) > limit:
            self._ages = [
                (flow.created, flow.seq, flow.key)
                for flow in self._flows.values()
            ]
            heapq.heapify(self._ages)

    def _schedule(self, flow: _Flow) -> None:
        """Record ``flow``'s earliest deadline in the deadline heap.

        :param flow: The datagram.
        """
        due = flow.due()
        if due != flow.deadline:
            flow.deadline = due
            if due is not None:
                heapq.heappush(self._deadlines, (due[0], flow.seq, flow.key))
                self._compact()

    def _oldest(self) -> _Flow:
        """Return the held datagram whose first fragment came first.

        Ties go to the one that started first. At least one datagram is
        held.
        """
        while True:
            _, seq, key = self._ages[0]
            flow = self._flows.get(key)
            if flow is not None and flow.seq == seq:
                return flow
            heapq.heappop(self._ages)

    def _victim(self, flow: _Flow) -> _Flow:
        """Return the datagram a cap evicts to make room for ``flow``'s data.

        That is the datagram whose first fragment came first, ties going
        to the one that started first, among those held and ``flow``
        itself; at least one datagram is held, or ``flow`` is.

        :param flow: The arriving fragment's datagram, held or not.
        """
        oldest = self._oldest()
        if (flow.created, flow.seq) < (oldest.created, oldest.seq):
            return flow
        return oldest

    def _new_flow(self, arrival: _Arrival) -> _Flow:
        """Build the state of the datagram ``arrival`` starts.

        :param arrival: Its first-arriving fragment.
        """
        target = self._target(arrival.receiver)
        policy = self._policy
        age = self._bounds.age_timeout
        idle = self._bounds.idle_timeout
        slow = arrival.key.version == 4
        if target is not None:
            if target.policy is not None:
                policy = target.policy
            if target.age_timeout is not None:
                age = _timeout(target.age_timeout)
                slow = False
            if target.idle_timeout is not None:
                idle = _timeout(target.idle_timeout)
        if arrival.key.version == 6:
            policy = OverlapPolicy.DISCARD
        self._seq += 1
        flow = _Flow(
            arrival.key,
            self._seq,
            arrival.source.timestamp,
            policy,
            (age, idle, slow),
        )
        flow.first_hop = arrival.source.hop_limit
        flow.first_next = arrival.protocol
        return flow

    @staticmethod
    def _anomaly(
        arrival: _Arrival,
        kind: AnomalyKind,
        start: int,
        end: int,
        flow: _Flow | None = None,
    ) -> Anomaly:
        """Build an :class:`Anomaly` the arriving fragment caused.

        :param arrival: The arriving fragment.
        :param kind: The rule.
        :param start: The first byte concerned.
        :param end: One past the last.
        :param flow: The datagram it discards, whose spans join the
            arriving fragment's, if any.
        """
        source = arrival.source
        spans = [source.span(source.start, source.start + len(arrival.data))]
        if flow is not None:
            spans += flow.spans()
        ordered, first, last = _event_times(spans)
        return Anomaly(
            flow=arrival.key,
            direction=None,
            spans=ordered,
            completing_ref=source.ref,
            first_timestamp=first,
            last_timestamp=last,
            kind=kind,
            start=start,
            end=end,
        )

    def _checked(self, arrival: _Arrival, own: list[FragmentEvent]) -> bool:
        """Apply :class:`ChecksumMode` and return whether the fragment is used.

        :param arrival: The fragment.
        :param own: Where its anomalies are appended.
        """
        start = arrival.source.start
        end = arrival.source.end
        if arrival.declared is None:
            own.append(
                self._anomaly(
                    arrival, AnomalyKind.UNVERIFIED_CHECKSUM, start, end
                )
            )
            return self._checksums is ChecksumMode.KEEP
        if not arrival.checksum_bad:
            return True
        own.append(self._anomaly(arrival, AnomalyKind.BAD_CHECKSUM, start, end))
        if self._checksums is ChecksumMode.KEEP:
            return True
        if (
            self._checksums is ChecksumMode.AUTO
            and arrival.checksum_zero
            and self._is_local(arrival.key.src)
        ):
            own.append(
                self._anomaly(arrival, AnomalyKind.CHECKSUM_OFFLOAD, start, end)
            )
            return True
        return False

    def _take(
        self,
        arrival: _Arrival,
        own: list[FragmentEvent],
        events: list[FragmentEvent],
    ) -> FragmentEvent | None:
        """Apply the rules to one fragment and store what it supplies.

        Return the event that ends its datagram, if one does.

        :param arrival: The fragment.
        :param own: Where its datagram's other events are appended.
        :param events: Where the events of other datagrams are appended.
        """
        flow = self._flows.get(arrival.key)
        if not self._checked(arrival, own):
            return None
        self._report_rfc1858(arrival, own)
        data = arrival.data
        for rule in (
            self._rule_empty,
            self._rule_misaligned,
            self._rule_oversize,
            self._rule_header_chain,
            self._rule_inconsistent_end,
        ):
            result = rule(arrival, flow, data, own)
            if isinstance(result, _Stop):
                return result.event
            data = result
        self._report_differences(arrival, flow, data, own)
        return self._store(arrival, flow, data, own, events)

    def _discard(
        self, arrival: _Arrival, flow: _Flow | None, kind: AnomalyKind, end: int
    ) -> _Stop:
        """Discard ``flow``, if held, and stop with the anomaly that says so.

        :param arrival: The fragment that broke the rule.
        :param flow: Its datagram, or ``None``.
        :param kind: The rule.
        :param end: One past the last byte the anomaly concerns.
        """
        if flow is not None:
            self._remove(flow)
        start = arrival.source.start
        return _Stop(self._anomaly(arrival, kind, start, end, flow))

    def _report(
        self,
        arrival: _Arrival,
        kind: AnomalyKind,
        bounds: tuple[int, int],
        own: list[FragmentEvent],
    ) -> None:
        """Append an :class:`Anomaly` about the arriving fragment alone.

        :param arrival: The fragment.
        :param kind: The rule.
        :param bounds: The ``[start, end)`` it concerns.
        :param own: Where it is appended.
        """
        own.append(self._anomaly(arrival, kind, *bounds))

    def _report_rfc1858(
        self, arrival: _Arrival, own: list[FragmentEvent]
    ) -> None:
        """Report a tiny first fragment and a TCP fragment at offset 1.

        :param arrival: The fragment.
        :param own: Where the anomalies are appended.
        """
        if arrival.key.version != 4:
            return
        source = arrival.source
        start = source.start
        length = source.end - start
        minimum = {6: 20, 17: 8}.get(arrival.protocol, 0)
        if start == 0 and 0 < length < minimum:
            self._report(
                arrival, AnomalyKind.TINY_FRAGMENT, (start, source.end), own
            )
        if arrival.protocol == 6 and arrival.fragment_offset == 1:
            self._report(
                arrival, AnomalyKind.TCP_OFFSET_ONE, (start, source.end), own
            )

    def _rule_empty(
        self,
        arrival: _Arrival,
        flow: _Flow | None,
        data: bytes,
        own: list[FragmentEvent],
    ) -> bytes | _Stop:
        """Drop a fragment with no data, or discard its datagram.

        Return ``data``, or a :class:`_Stop`.

        :param arrival: The fragment.
        :param flow: Its datagram, or ``None``.
        :param data: Its data.
        :param own: Where an anomaly is appended.
        """
        start = arrival.source.start
        if arrival.source.end != start:
            return data
        if flow is not None and (
            arrival.key.version == 6
            or flow.policy is OverlapPolicy.LINUX_DISCARD
        ):
            return self._discard(
                arrival, flow, AnomalyKind.EMPTY_FRAGMENT, start
            )
        self._report(arrival, AnomalyKind.EMPTY_FRAGMENT, (start, start), own)
        return _Stop(None)

    def _rule_misaligned(
        self,
        arrival: _Arrival,
        flow: _Flow | None,
        data: bytes,
        own: list[FragmentEvent],
    ) -> bytes | _Stop:
        """Drop, cut or discard on a non-final length not a multiple of 8.

        Return ``data``, cut to a multiple of 8 for IPv4, or a
        :class:`_Stop`.

        :param arrival: The fragment.
        :param flow: Its datagram, or ``None``.
        :param data: Its data.
        :param own: Where an anomaly is appended.
        """
        source = arrival.source
        start = source.start
        length = source.end - start
        if not (arrival.more and length % 8):
            return data
        if arrival.key.version == 4 and length < 8:
            return self._discard(
                arrival, flow, AnomalyKind.MISALIGNED, start + length
            )
        self._report(
            arrival, AnomalyKind.MISALIGNED, (start, start + length), own
        )
        if arrival.key.version == 6:
            return _Stop(None)
        length -= length % 8
        source.end = start + length
        return data[:length]

    def _rule_oversize(
        self,
        arrival: _Arrival,
        flow: _Flow | None,
        data: bytes,
        own: list[FragmentEvent],
    ) -> bytes | _Stop:
        """Drop or discard a fragment that ends past 65,535 bytes.

        Return ``data``, or a :class:`_Stop`.

        :param arrival: The fragment.
        :param flow: Its datagram, or ``None``.
        :param data: Its data.
        :param own: Where an anomaly is appended.
        """
        source = arrival.source
        start = source.start
        header = arrival.extra_header
        reach = source.end
        if flow is not None:
            if start and flow.header_extra is not None:
                header = flow.header_extra
            elif not start and arrival.key.version == 6:
                reach = max(reach, flow.reach)
        if header + reach <= _MAX_DATAGRAM:
            return data
        if arrival.key.version == 4:
            return self._discard(
                arrival, flow, AnomalyKind.OVERSIZE, source.end
            )
        self._report(arrival, AnomalyKind.OVERSIZE, (start, source.end), own)
        return _Stop(None)

    def _rule_header_chain(
        self,
        arrival: _Arrival,
        flow: _Flow | None,
        data: bytes,
        own: list[FragmentEvent],
    ) -> bytes | _Stop:
        """Drop an IPv6 first fragment without its whole header chain.

        Return ``data``, or a :class:`_Stop`.

        :param arrival: The fragment.
        :param flow: Its datagram, or ``None``.
        :param data: Its data.
        :param own: Where an anomaly is appended.
        """
        source = arrival.source
        if (
            arrival.key.version == 6
            and source.start == 0
            and len(data) == source.end
            and not _chain_complete(arrival.protocol, data)
        ):
            self._report(
                arrival,
                AnomalyKind.INCOMPLETE_HEADER_CHAIN,
                (0, source.end),
                own,
            )
            return _Stop(None)
        return data

    def _rule_inconsistent_end(
        self,
        arrival: _Arrival,
        flow: _Flow | None,
        data: bytes,
        own: list[FragmentEvent],
    ) -> bytes | _Stop:
        """Discard a datagram whose fragments disagree on its end.

        Return ``data``, or a :class:`_Stop`.

        :param arrival: The fragment.
        :param flow: Its datagram, or ``None``.
        :param data: Its data.
        :param own: Unused; the rule appends nothing.
        """
        if flow is None:
            return data
        end = arrival.source.end
        known = flow.end
        if (known is not None and end > known) or (
            not arrival.more
            and ((known is not None and known != end) or flow.reach > end)
        ):
            return self._discard(
                arrival, flow, AnomalyKind.INCONSISTENT_END, end
            )
        return data

    def _report_differences(
        self,
        arrival: _Arrival,
        flow: _Flow | None,
        data: bytes,
        own: list[FragmentEvent],
    ) -> None:
        """Report a truncated fragment, and one unlike the first-arriving.

        :param arrival: The fragment.
        :param flow: Its datagram, or ``None``.
        :param data: Its data.
        :param own: Where the anomalies are appended.
        """
        source = arrival.source
        start = source.start
        bounds = (start, source.end)
        if start + len(data) < source.end:
            self._report(
                arrival,
                AnomalyKind.TRUNCATED,
                (start + len(data), source.end),
                own,
            )
        if flow is None:
            return
        if source.hop_limit != flow.first_hop:
            self._report(arrival, AnomalyKind.HOP_LIMIT_CHANGED, bounds, own)
        if arrival.key.version == 6 and arrival.protocol != flow.first_next:
            self._report(arrival, AnomalyKind.NEXT_HEADER_CHANGED, bounds, own)

    def _store(
        self,
        arrival: _Arrival,
        held: _Flow | None,
        data: bytes,
        own: list[FragmentEvent],
        events: list[FragmentEvent],
    ) -> FragmentEvent | None:
        """Resolve overlaps, enforce the caps, store, and complete.

        Return the event that ends the datagram, if one does.

        :param arrival: The fragment.
        :param held: Its datagram, or ``None`` when it starts one.
        :param data: Its data, cut to a multiple of 8 when misaligned.
        :param own: Where the datagram's other events are appended.
        :param events: Where the events of other datagrams are appended.
        """
        source = arrival.source
        flow = self._new_flow(arrival) if held is None else held
        plan = self._plan(flow, source, data)
        if plan.discard:
            self._remove(flow)
            return plan.event
        if plan.event is not None:
            own.append(plan.event)
        replaced = flow.pieces[plan.first : plan.last]
        charge = (
            flow.charge
            - sum(map(_charge, replaced))
            + sum(map(_charge, plan.pieces))
        )
        count = len(flow.pieces) - len(replaced) + len(plan.pieces)
        bare = 0
        if flow.runs:
            after = flow.pieces[: plan.first] + plan.pieces
            bare = _bare_runs(flow.runs, after + flow.pieces[plan.last :])
        charge += (bare - flow.bare) * PIECE_OVERHEAD
        count += bare
        arriving = [
            source.span(piece.start, piece.end)
            for piece in plan.pieces
            if piece.source is source
        ]
        last_end = None if arrival.more else source.end
        evicted = self._make_room(
            flow,
            held is None,
            (count, charge),
            (source.ref, arriving, last_end),
            events,
        )
        if evicted is not None:
            return evicted
        self._apply(flow, held is None, plan, replaced, charge)
        flow.bare = bare
        flow.reach = max(flow.reach, source.end)
        if not arrival.more:
            flow.end = source.end
        flow.last = max(flow.last, source.timestamp)
        complete = flow.end is not None and flow.covered == flow.end
        if complete and not plan.dropped:
            return self._complete(flow, source, own)
        self._schedule(flow)
        return None

    def _make_room(
        self,
        flow: _Flow,
        new: bool,
        size: tuple[int, int],
        arrival: tuple[int, list[Span], int | None],
        events: list[FragmentEvent],
    ) -> Evicted | None:
        """Enforce the caps before ``flow`` takes the arriving fragment.

        Other datagrams evicted to make room are appended to ``events``.
        Return the :class:`Evicted` of ``flow`` itself when it is the one
        that goes, else ``None``.

        :param flow: The arriving fragment's datagram.
        :param new: Whether the fragment starts it.
        :param size: Its piece count and charge once the fragment is
            stored.
        :param arrival: The fragment's reference, the spans it would
            add, and the payload's length when it is the last fragment.
        :param events: Where the other datagrams' events are appended.
        """
        count, charge = size
        ref, arriving, end = arrival
        bounds = self._bounds
        own_cap = None
        if count > bounds.max_fragments:
            own_cap = Bound.MAX_FRAGMENTS
        elif charge > self._flow_cap:
            own_cap = Bound.MAX_FLOW_BYTES
        elif charge > bounds.max_total_bytes:
            own_cap = Bound.MAX_TOTAL_BYTES
        if own_cap is not None:
            return self._evicted(flow, own_cap, ref, arriving, end)
        growth = charge if new else charge - flow.charge
        while new and len(self._flows) >= bounds.max_flows:
            victim = self._victim(flow)
            if victim is flow:
                return self._evicted(flow, Bound.MAX_FLOWS, ref, arriving, end)
            events.append(self._evicted(victim, Bound.MAX_FLOWS, None, []))
        while self._total + growth > bounds.max_total_bytes:
            victim = self._victim(flow)
            if victim is flow:
                return self._evicted(
                    flow, Bound.MAX_TOTAL_BYTES, ref, arriving, end
                )
            events.append(
                self._evicted(victim, Bound.MAX_TOTAL_BYTES, None, [])
            )
        return None

    def _apply(
        self,
        flow: _Flow,
        new: bool,
        plan: _Plan,
        replaced: list[_Piece],
        charge: int,
    ) -> None:
        """Store a planned fragment in ``flow`` and update the charges.

        :param flow: The datagram.
        :param new: Whether the fragment starts it.
        :param plan: How the fragment changes its pieces.
        :param replaced: The pieces the plan replaces.
        :param charge: The datagram's charge afterwards.
        """
        if new:
            self._flows[flow.key] = flow
            heapq.heappush(self._ages, (flow.created, flow.seq, flow.key))
        self._total += charge - (0 if new else flow.charge)
        flow.charge = charge
        flow.pieces[plan.first : plan.last] = plan.pieces
        flow.starts[plan.first : plan.last] = [
            piece.start for piece in plan.pieces
        ]
        flow.covered += sum(len(piece.data) for piece in plan.pieces) - sum(
            len(piece.data) for piece in replaced
        )
        if flow.pieces and flow.pieces[0].start == 0:
            flow.header_extra = _header_extra(flow.pieces[0].source, flow.key)

    @staticmethod
    def _overlapped(
        flow: _Flow, start: int, end: int
    ) -> tuple[int, int, list[_Piece]]:
        """Return where the pieces ``[start, end)`` overlaps are, and them.

        :param flow: The datagram.
        :param start: The arriving fragment's first byte.
        :param end: One past its last captured byte.
        :returns: The index of the first overlapped piece, one past the
            last, and the pieces; with no overlap, the index the
            fragment's piece takes twice and no pieces.
        """
        pieces = flow.pieces
        first = bisect.bisect_right(flow.starts, start) - 1
        if first < 0 or pieces[first].end <= start:
            first += 1
        last = first
        while last < len(pieces) and pieces[last].start < end:
            last += 1
        return first, last, pieces[first:last]

    @staticmethod
    def _verdict(
        flow: _Flow, source: _Source, data: bytes, overlapped: list[_Piece]
    ) -> str:
        """Return how the datagram's policy takes the arriving fragment.

        Under ``linux-discard`` and ``discard`` (every IPv6 datagram's
        rule) the decision is made on the fragments' declared ranges,
        their runs: ``"insert"`` for a fragment that overlaps no run,
        which is then added to the runs; ``"duplicate"`` for one inside
        a single ``linux-discard`` run, or the same range as one
        ``discard`` run with equal captured bytes; ``"overlap"`` for any
        other, which discards the datagram. Under the other policies,
        ``"resolve"``.

        :param flow: The datagram.
        :param source: The arriving fragment.
        :param data: Its data.
        :param overlapped: The held pieces it overlaps.
        """
        start = source.start
        if flow.policy is OverlapPolicy.LINUX_DISCARD:
            verdict = _linux_verdict(flow.runs, start, source.end)
            if verdict == "insert":
                _linux_insert(flow.runs, start, source.end)
            return verdict
        if flow.policy is not OverlapPolicy.DISCARD:
            return "resolve"
        touched = _touched(flow.runs, start, source.end)
        if not touched:
            bisect.insort(flow.runs, [start, source.end])
            return "insert"
        same = touched == [[start, source.end]]
        if same and _differing(overlapped, source, data) is None:
            return "duplicate"
        return "overlap"

    def _plan(self, flow: _Flow, source: _Source, data: bytes) -> _Plan:
        """Resolve the arriving fragment against the pieces it overlaps.

        :param flow: The datagram.
        :param source: The arriving fragment.
        :param data: Its data.
        """
        start = source.start
        end = start + len(data)
        first, last, overlapped = self._overlapped(flow, start, end)
        if not data:
            overlapped = []
        verdict = self._verdict(flow, source, data, overlapped)
        if verdict == "overlap":
            return self._discarding(flow, source, data, first, overlapped)
        if not overlapped:
            return self._unopposed(flow, source, data, first, verdict)
        winners = [
            verdict == "resolve"
            and _arriving_wins(flow.policy, piece.source, source)
            for piece in overlapped
        ]
        bounds = (max(start, overlapped[0].start), min(end, overlapped[-1].end))
        differing = _differing(overlapped, source, data)
        event: Overlap | Retransmission
        if differing is not None:
            event = self._overlap(
                flow, source, data, overlapped, winners, differing, True
            )
        else:
            event = _retransmission(flow, source, overlapped, bounds)
        if (
            verdict == "duplicate"
            and flow.policy is OverlapPolicy.LINUX_DISCARD
        ):
            return _Plan(first, last, overlapped, event, False, dropped=True)
        pieces = _merged(overlapped, winners, source, data)
        return _Plan(first, last, pieces, event, False)

    def _discarding(
        self,
        flow: _Flow,
        source: _Source,
        data: bytes,
        first: int,
        overlapped: list[_Piece],
    ) -> _Plan:
        """Plan the discard of a datagram the arriving fragment overlaps.

        The :class:`Overlap` covers the declared overlap of the fragment
        with the runs it touches; its bytes stop where the fragment's
        capture does.

        :param flow: The datagram.
        :param source: The arriving fragment.
        :param data: Its data.
        :param first: The index of the first piece it overlaps.
        :param overlapped: The held pieces it overlaps, in order.
        """
        start = source.start
        touched = _touched(flow.runs, start, source.end)
        low = max(start, touched[0][0])
        high = min(source.end, max(run[1] for run in touched))
        captured = max(low, min(high, start + len(data)))
        winners = [False] * len(overlapped)
        discarded = self._overlap(
            flow, source, data, overlapped, winners, (low, captured), False
        )
        return _Plan(first, first, [], replace(discarded, end=high), True)

    @staticmethod
    def _unopposed(
        flow: _Flow,
        source: _Source,
        data: bytes,
        first: int,
        verdict: str,
    ) -> _Plan:
        """Plan a fragment that overlaps no held piece.

        A ``linux-discard`` duplicate is dropped; any other fragment's
        captured bytes are stored.

        :param flow: The datagram.
        :param source: The arriving fragment.
        :param data: Its data.
        :param first: The index its piece takes.
        :param verdict: What :meth:`_verdict` returned.
        """
        linux_duplicate = (
            verdict == "duplicate"
            and flow.policy is OverlapPolicy.LINUX_DISCARD
        )
        if linux_duplicate:
            return _Plan(first, first, [], None, False, dropped=True)
        if not data:
            return _Plan(first, first, [], None, False)
        piece = _Piece(source.start, data, source)
        return _Plan(first, first, [piece], None, False)

    @staticmethod
    def _overlap(
        flow: _Flow,
        source: _Source,
        data: bytes,
        overlapped: list[_Piece],
        winners: list[bool],
        bounds: tuple[int, int],
        resolved: bool,
    ) -> Overlap:
        """Build the :class:`Overlap` of one arriving fragment.

        :param flow: The datagram.
        :param source: The arriving fragment.
        :param data: Its data.
        :param overlapped: The held pieces it overlaps, in order.
        :param winners: Whether it replaces each of them.
        :param bounds: The ``[start, end)`` the event covers.
        :param resolved: ``False`` when the datagram is discarded.
        """
        start = source.start
        low, high = bounds
        kept = bytearray()
        other = bytearray()
        kept_spans: list[Span] = []
        other_spans: list[Span] = []

        def both(a: int, b: int) -> None:
            """Add the arriving bytes of ``[a, b)`` to both versions.

            :param a: The first byte, as a payload offset.
            :param b: One past the last.
            """
            chunk = data[a - start : b - start]
            kept.extend(chunk)
            other.extend(chunk)
            kept_spans.append(source.span(a, b))
            other_spans.append(source.span(a, b))

        cursor = low
        for piece, wins in zip(overlapped, winners, strict=True):
            a, b = max(low, piece.start), min(high, piece.end)
            if a >= b:
                continue
            if a > cursor:
                both(cursor, a)
            held = piece.data[a - piece.start : b - piece.start]
            arriving = data[a - start : b - start]
            if wins:
                kept.extend(arriving)
                other.extend(held)
                kept_spans.append(source.span(a, b))
                other_spans.append(piece.source.span(a, b))
            else:
                kept.extend(held)
                other.extend(arriving)
                kept_spans.append(piece.source.span(a, b))
                other_spans.append(source.span(a, b))
            cursor = b
        if cursor < high:
            both(cursor, high)
        if resolved:
            spans = list(set(kept_spans) | set(other_spans))
        else:
            spans = flow.spans()
            if data:
                spans.append(source.span(start, start + len(data)))
        ordered, first, last = _event_times(spans, (flow.created, flow.last))
        return Overlap(
            flow=flow.key,
            direction=None,
            spans=ordered,
            completing_ref=source.ref,
            first_timestamp=first,
            last_timestamp=last,
            start=low,
            end=high,
            policy=flow.policy,
            kept=bytes(kept),
            other=bytes(other),
            kept_spans=tuple(kept_spans),
            other_spans=tuple(other_spans),
            resolved=resolved,
            contrary=False,
        )

    def _complete(
        self, flow: _Flow, source: _Source, own: list[FragmentEvent]
    ) -> Datagram | Anomaly:
        """Remove a datagram with no hole left and return its :class:`Datagram`.

        A datagram whose rebuilt header and payload would exceed 65,535
        bytes is discarded instead, and its
        :attr:`AnomalyKind.OVERSIZE` returned.

        :param flow: The datagram.
        :param source: The fragment that filled its last hole.
        :param own: Where a :attr:`AnomalyKind.SLOW_REASSEMBLY` is
            appended.
        """
        self._remove(flow)
        payload = b"".join(piece.data for piece in flow.pieces)
        header_source = flow.pieces[0].source
        extra = _header_extra(header_source, flow.key)
        if extra + len(payload) > _MAX_DATAGRAM:
            ordered, first, last = _event_times(flow.spans())
            return Anomaly(
                flow=flow.key,
                direction=None,
                spans=ordered,
                completing_ref=source.ref,
                first_timestamp=first,
                last_timestamp=last,
                kind=AnomalyKind.OVERSIZE,
                start=_MAX_DATAGRAM - extra,
                end=len(payload),
            )
        header = bytearray(header_source.header)
        if flow.key.version == 4:
            header[2:4] = (len(header) + len(payload)).to_bytes(2, "big")
            header[6:8] = ((header[6] & 0xC0) << 8).to_bytes(2, "big")
            header[10:12] = b"\x00\x00"
            header[10:12] = internet_checksum(bytes(header)).to_bytes(2, "big")
        else:
            header[header_source.next_at] = header.pop()
            header[4:6] = (len(header) - 40 + len(payload)).to_bytes(2, "big")
        ordered, first, last = _event_times(flow.spans())
        if flow.slow and flow.last - flow.created > _SLOW_IPV4:
            own.append(
                Anomaly(
                    flow=flow.key,
                    direction=None,
                    spans=ordered,
                    completing_ref=source.ref,
                    first_timestamp=first,
                    last_timestamp=last,
                    kind=AnomalyKind.SLOW_REASSEMBLY,
                    start=0,
                    end=len(payload),
                )
            )
        return Datagram(
            flow=flow.key,
            direction=None,
            spans=ordered,
            completing_ref=source.ref,
            first_timestamp=first,
            last_timestamp=last,
            version=flow.key.version,
            data=bytes(header) + payload,
            payload_offset=len(header),
            header_ref=header_source.ref,
        )


def _differing(
    overlapped: list[_Piece], source: _Source, data: bytes
) -> tuple[int, int] | None:
    """Return the smallest range holding every byte where versions differ.

    ``None`` when the arriving fragment's bytes equal every held byte it
    overlaps.

    :param overlapped: The held pieces it overlaps, in order.
    :param source: The arriving fragment.
    :param data: Its data.
    """
    start = source.start
    end = start + len(data)
    found: list[tuple[int, int]] = []
    for piece in overlapped:
        low, high = max(start, piece.start), min(end, piece.end)
        difference = _difference(
            piece.data[low - piece.start : high - piece.start],
            data[low - start : high - start],
        )
        if difference is not None:
            found.append((low + difference[0], low + difference[1]))
    if not found:
        return None
    return found[0][0], found[-1][1]


def _retransmission(
    flow: _Flow,
    source: _Source,
    overlapped: list[_Piece],
    bounds: tuple[int, int],
) -> Retransmission:
    """Build the :class:`Retransmission` of a fragment repeating held bytes.

    :param flow: The datagram.
    :param source: The arriving fragment.
    :param overlapped: The held pieces it overlaps, in order.
    :param bounds: The ``[start, end)`` of every overlapped byte.
    """
    low, high = bounds
    spans = [
        piece.source.span(max(low, piece.start), min(high, piece.end))
        for piece in overlapped
    ]
    spans.append(source.span(low, high))
    ordered, first, last = _event_times(spans)
    return Retransmission(
        flow=flow.key,
        direction=None,
        spans=ordered,
        completing_ref=source.ref,
        first_timestamp=first,
        last_timestamp=last,
        start=low,
        end=high,
        verified=True,
    )


def _merged(
    overlapped: list[_Piece], winners: list[bool], source: _Source, data: bytes
) -> list[_Piece]:
    """Return the pieces that replace ``overlapped`` once a fragment is stored.

    Held pieces the fragment does not replace stay; it fills every other
    byte of its range, and a replaced piece keeps its bytes outside it.

    :param overlapped: The held pieces it overlaps, in order.
    :param winners: Whether it replaces each of them.
    :param source: The arriving fragment.
    :param data: Its data.
    """
    start = source.start
    end = start + len(data)
    new: list[_Piece] = []
    cursor = start
    for piece, wins in zip(overlapped, winners, strict=True):
        if wins:
            if piece.start < start:
                new.append(
                    _Piece(
                        piece.start,
                        piece.data[: start - piece.start],
                        piece.source,
                    )
                )
            continue
        if piece.start > cursor:
            new.append(
                _Piece(
                    cursor, data[cursor - start : piece.start - start], source
                )
            )
        new.append(piece)
        cursor = max(cursor, piece.end)
    if cursor < end:
        new.append(_Piece(cursor, data[cursor - start :], source))
    tail = overlapped[-1]
    if winners[-1] and tail.end > end:
        new.append(_Piece(end, tail.data[end - tail.start :], tail.source))
    return new


def _touched(runs: list[list[int]], start: int, end: int) -> list[list[int]]:
    """Return the runs that ``[start, end)`` overlaps, in order.

    :param runs: The datagram's runs, as ``[start, end]`` pairs.
    :param start: The fragment's first byte.
    :param end: One past its last declared byte.
    """
    return [run for run in runs if run[0] < end and start < run[1]]


def _bare_runs(runs: list[list[int]], pieces: list[_Piece]) -> int:
    """Return how many runs hold no stored piece.

    A piece lies inside the run of the fragment that supplied it, so a
    run holds one when a piece starts inside it.

    :param runs: The datagram's runs, as ``[start, end]`` pairs.
    :param pieces: Its pieces, in order.
    """
    starts = [piece.start for piece in pieces]
    bare = 0
    for run_start, run_end in runs:
        index = bisect.bisect_left(starts, run_start)
        if index == len(starts) or starts[index] >= run_end:
            bare += 1
    return bare


def _linux_verdict(runs: list[list[int]], start: int, end: int) -> str:
    """Classify a fragment against Linux's runs of held fragments.

    Return ``"insert"`` when it overlaps no run, ``"duplicate"`` when
    one run holds it whole, ``"overlap"`` otherwise.

    :param runs: The datagram's runs, as ``[start, end]`` pairs.
    :param start: The fragment's first byte.
    :param end: One past its last.
    """
    touched = _touched(runs, start, end)
    if not touched:
        return "insert"
    if len(touched) == 1 and touched[0][0] <= start and end <= touched[0][1]:
        return "duplicate"
    return "overlap"


def _linux_insert(runs: list[list[int]], start: int, end: int) -> None:
    """Add a stored fragment to the runs, as Linux builds them.

    A fragment that ends past every held fragment and starts where the
    last one ends extends the last run; any other starts a run of its
    own.

    :param runs: The datagram's runs, as ``[start, end]`` pairs.
    :param start: The fragment's first byte.
    :param end: One past its last.
    """
    if runs and end > runs[-1][1] and start == runs[-1][1]:
        runs[-1][1] = end
        return
    bisect.insort(runs, [start, end])


#: TCP flag bits.
_FIN = 0x01
_SYN = 0x02
_RST = 0x04
_ACK = 0x10
_URG = 0x20

#: The size of the TCP sequence space, and half of it.
_SEQ_SPACE = 1 << 32
_SEQ_HALF = 1 << 31

#: Bytes charged for each frame a retained run of delivered bytes names,
#: beyond the run's :data:`PIECE_OVERHEAD` and data.
_SPAN_OVERHEAD = 192

#: Bits of a direction's ``notes``: the anomalies it reports once, and
#: its state flags.
_NOTE_MIDSTREAM = 1
_NOTE_URGENT = 2
_NOTE_AFTER_RST = 4
_NOTE_BEYOND = 8
_SENT = 16
_ENDED = 32
_SYNCED = 64

#: The stream policies :class:`StreamReassembler` offers.
_STREAM_POLICIES = (OverlapPolicy.FIRST, OverlapPolicy.LAST)


def _serial(value: int, near: int) -> int:
    """Return the integer congruent to ``value`` modulo 2**32 nearest ``near``.

    That is the serial-number comparison of RFC 9293 §3.4 and RFC 1982.

    :param value: A residue modulo 2**32.
    :param near: The point the result is placed around.
    """
    return near + (value - near + _SEQ_HALF) % _SEQ_SPACE - _SEQ_HALF


def _fold(data: bytes) -> int:
    """Return the folded ones'-complement sum of ``data``, uncomplemented.

    :param data: The bytes summed.
    """
    return ~internet_checksum(data) & 0xFFFF


def _pseudo(source: bytes, destination: bytes, length: int) -> bytes:
    """Return the TCP pseudo-header for ``length`` bytes of segment.

    :param source: The packed source address.
    :param destination: The packed destination address the checksum
        uses.
    :param length: The segment's length, header included.
    """
    if len(source) == 4:
        tail = bytes([0, 6]) + (length & 0xFFFF).to_bytes(2, "big")
    else:
        tail = (length & 0xFFFFFFFF).to_bytes(4, "big") + bytes([0, 0, 0, 6])
    return source + destination + tail


def _window_scale(options: bytes) -> int | None:
    """Return the shift of a Window Scale option, at most 14, if any.

    :param options: A TCP header's options.
    """
    index = 0
    while index < len(options):
        kind = options[index]
        if kind == 0:
            break
        if kind == 1:
            index += 1
            continue
        if index + 1 >= len(options) or options[index + 1] < 2:
            break
        if kind == 3 and options[index + 1] == 3 and index + 2 < len(options):
            return min(options[index + 2], 14)
        index += options[index + 1]
    return None


class _Origin:
    """The frame one segment came from."""

    __slots__ = ("hop_limit", "ref", "timestamp")

    def __init__(self, ref: int, timestamp: int, hop_limit: int) -> None:
        self.ref = ref
        self.timestamp = timestamp
        self.hop_limit = hop_limit

    def span(self, start: int, end: int) -> Span:
        """Return this frame's :class:`Span` over ``[start, end)``.

        :param start: The first byte, as a stream offset.
        :param end: One past the last.
        """
        return Span(self.ref, start, end, self.timestamp, self.hop_limit)


class _Chunk:
    """Bytes one segment supplied, at a stream offset.

    ``data`` is ``None`` for a declared range the capture cut.
    """

    __slots__ = ("data", "end", "origin", "start")

    def __init__(
        self, start: int, end: int, data: bytes | None, origin: _Origin
    ) -> None:
        self.start = start
        self.end = end
        self.data = data
        self.origin = origin

    def cut(self, start: int, end: int) -> _Chunk:
        """Return the part of this chunk over ``[start, end)``.

        :param start: The first byte, inside the chunk.
        :param end: One past the last, inside the chunk.
        """
        if start == self.start and end == self.end:
            return self
        data = self.data
        if data is not None:
            data = data[start - self.start : end - self.start]
        return _Chunk(start, end, data, self.origin)


def _chunk_charge(chunk: _Chunk) -> int:
    """Return the bytes charged for one held chunk.

    :param chunk: The chunk.
    """
    return PIECE_OVERHEAD + (0 if chunk.data is None else len(chunk.data))


class _Run:
    """Contiguous delivered bytes a direction retains, and their frames."""

    __slots__ = ("data", "origins", "start", "starts")

    def __init__(self, start: int, data: bytes, origin: _Origin) -> None:
        self.start = start
        self.data = bytearray(data)
        #: Where each frame's bytes begin; each runs to the next start.
        self.starts = [start]
        self.origins = [origin]

    @property
    def end(self) -> int:
        """One past the run's last byte."""
        return self.start + len(self.data)

    def charge(self) -> int:
        """Return the bytes charged for the run.

        That is :data:`PIECE_OVERHEAD`, the bytes its ``bytearray`` has
        allocated, and ``_SPAN_OVERHEAD`` per frame it names.
        """
        return (
            PIECE_OVERHEAD
            + self.data.__alloc__()
            + _SPAN_OVERHEAD * len(self.starts)
        )

    def chunks(self, low: int, high: int) -> list[_Chunk]:
        """Return the run's bytes over ``[low, high)``, one chunk per frame.

        :param low: The first byte, at or after the run's start.
        :param high: One past the last, at or before the run's end.
        """
        found: list[_Chunk] = []
        index = max(0, bisect.bisect_right(self.starts, low) - 1)
        while index < len(self.starts) and self.starts[index] < high:
            begin = max(low, self.starts[index])
            stop = high
            if index + 1 < len(self.starts):
                stop = min(high, self.starts[index + 1])
            data = bytes(self.data[begin - self.start : stop - self.start])
            found.append(_Chunk(begin, stop, data, self.origins[index]))
            index += 1
        return found

    def trim(self, low: int) -> None:
        """Drop the run's bytes before ``low``, inside the run.

        :param low: The new first byte.
        """
        index = bisect.bisect_right(self.starts, low) - 1
        del self.starts[:index]
        del self.origins[:index]
        self.starts[0] = low
        del self.data[: low - self.start]
        self.start = low


class _Dir:
    """One direction of a TCP connection."""

    __slots__ = (
        "ack",
        "base",
        "edge",
        "fin",
        "gaps",
        "held",
        "hop",
        "mark",
        "next",
        "notes",
        "pending",
        "reach",
        "runs",
        "scale",
    )

    def __init__(self) -> None:
        #: The sequence number of offset 0.
        self.base: int | None = None
        #: The Window Scale shift of its SYN, if it had one.
        self.scale: int | None = None
        #: The delivered end: delivered or skipped bytes end here.
        self.next = 0
        #: One past the highest declared byte received.
        self.reach = 0
        #: Undelivered chunks past a hole, in order.
        self.held: list[_Chunk] | None = None
        #: Retained delivered bytes, in order.
        self.runs: list[_Run] | None = None
        #: ACKED gaps inside the retained window, as ``[start, end]``.
        self.gaps: list[list[int]] | None = None
        #: The peer's highest acknowledgement, as an offset.
        self.ack: int | None = None
        #: The capture clock when an acknowledgement first passed the
        #: lowest hole, and the acknowledgement it holds the hole's
        #: declaration to.
        self.pending: tuple[int, int] | None = None
        #: The furthest right window edge its receiver advertised.
        self.edge: int | None = None
        #: The end its FIN fixed, and the FIN's frame.
        self.fin: tuple[int, _Origin] | None = None
        #: What it had received when the latest RST arrived.
        self.mark: int | None = None
        #: The hop limit of its latest segment; -1 before one.
        self.hop = -1
        #: ``_NOTE_*``, ``_SENT``, ``_ENDED`` and ``_SYNCED`` bits.
        self.notes = 0

    @property
    def started(self) -> bool:
        """Whether offset 0 is known and the direction has not ended."""
        return self.base is not None and not self.notes & _ENDED

    def offset(self, seq: int) -> int:
        """Return the stream offset of a sequence number.

        The offset 0 is known.

        :param seq: The sequence number.
        """
        base = typing.cast(int, self.base)
        return _serial((seq - base) % _SEQ_SPACE, self.next)


class _Conn:
    """One TCP connection."""

    __slots__ = (
        "a",
        "b",
        "charge",
        "created",
        "full",
        "key",
        "last",
        "rst",
        "scheduled",
        "seq",
    )

    def __init__(self, key: FlowKey, seq: int, timestamp: int) -> None:
        self.key = key
        self.seq = seq
        self.created = timestamp
        self.last = timestamp
        self.a: _Dir | None = None
        self.b: _Dir | None = None
        self.charge = FLOW_OVERHEAD
        #: Whether both directions have carried data.
        self.full = False
        #: The pending RST's frame, while its end is pending.
        self.rst: _Origin | None = None
        #: The time of the connection's entry in the deadline heap.
        self.scheduled: int | None = None

    def dirs(self) -> list[tuple[int, _Dir]]:
        """Return the directions present, with their sides, ``A_TO_B`` first."""
        return [
            (side, found)
            for side, found in ((0, self.a), (1, self.b))
            if found is not None
        ]

    def finished(self) -> bool:
        """Return whether every direction present has ended by FIN."""
        present = self.dirs()
        return bool(present) and all(
            found.notes & _ENDED for _, found in present
        )


def _direction(side: int) -> Direction:
    """Return the :class:`Direction` of a side.

    :param side: 0 for ``A_TO_B``, 1 for ``B_TO_A``.
    """
    return Direction.A_TO_B if side == 0 else Direction.B_TO_A


class _Segment(NamedTuple):
    """One TCP segment sliced out of a fed frame."""

    key: FlowKey
    side: int
    source: str
    receiver: str
    seq: int
    ack: int
    flags: int
    window: int
    scale: int | None
    data: bytes
    length: int
    origin: _Origin
    unknown: bool
    ip_bad: bool
    ip_zero: bool
    tcp_bad: bool
    pattern: bool


def _fragmented(layers: tuple[Protocol, ...]) -> bool:
    """Return whether any of ``layers`` is the header of an IP fragment.

    That is an IPv4 header with MF set or a nonzero Fragment Offset, or
    an IPv6 Fragment header with M set or a nonzero offset.

    :param layers: Decoded headers.
    """
    for layer in layers:
        if isinstance(layer, IPv4) and (
            layer.flags & 1 or layer.fragment_offset
        ):
            return True
        if isinstance(layer, IPv6Fragment) and (
            layer.m_flag or layer.fragment_offset
        ):
            return True
    return False


def _find_tcp(
    packet: Packet,
) -> tuple[TCP, int, IPv4 | IPv6, int, IPv6Routing | None] | None:
    """Find the packet's first TCP layer and the IP header nearest before it.

    ``None`` when there is no TCP layer, no IP header before it, or an IP
    fragment header before it.

    :param packet: The decoded packet.
    :returns: The TCP layer, its offset in the frame, the IP header, its
        offset, and the IPv6 Routing header with segments left between
        them, if any.
    """
    layers = packet.layers
    offsets: list[int] = []
    offset = 0
    for index, layer in enumerate(layers):
        offsets.append(offset)
        if isinstance(layer, TCP):
            ip, routing = _enclosing_ip(layers, index)
            if ip is None or _fragmented(layers[:index]):
                return None
            at = max(i for i in range(index) if layers[i] is ip)
            return layer, offset, ip, offsets[at], routing
        offset += layer.header_len
    return None


def _checksums(
    tcp: TCP,
    segment: bytes,
    source: str,
    receiver: str,
    complete: bool,
) -> tuple[bool, bool]:
    """Judge a TCP checksum.

    :param tcp: The TCP header.
    :param segment: The captured segment, header included.
    :param source: The source address.
    :param receiver: The destination address the checksum uses.
    :param complete: Whether ``segment`` is all its IP header declares;
        ``False`` for a segment the snap length cut, which is not judged.
    :returns: Whether the checksum is bad, and whether it is one of the
        sums a stack leaves for its NIC to fill: the pseudo-header's,
        with the segment's length or without any.
    """
    pack = ipv6_to_bytes if ":" in source else ipv4_to_bytes
    src = pack(source)
    dst = pack(receiver)
    pseudo = _pseudo(src, dst, len(segment))
    pattern = tcp.checksum in (_fold(pseudo), _fold(_pseudo(src, dst, 0)))
    if not complete:
        return False, pattern
    return internet_checksum(pseudo + segment) != 0, pattern


def _slice_segment(
    packet: Packet,
    frame: bytes | bytearray | memoryview,
    timestamp: int,
    ref: int,
) -> _Segment | None:
    """Slice the packet's TCP segment out of its frame.

    ``None`` when the packet holds no TCP segment a stream can take.

    :param packet: The decoded packet.
    :param frame: The frame.
    :param timestamp: The frame's capture time.
    :param ref: The frame's reference.
    """
    found = _find_tcp(packet)
    if found is None:
        return None
    tcp, tcp_at, ip, ip_at, routing = found
    receiver = _effective_destination(ip, routing)
    key = typing.cast(FlowKey, flow_key(tcp, ip=ip, routing=routing))
    side = 0 if (ip.src, tcp.src_port) == (key.addr_a, key.port_a) else 1
    bound = len(frame) - len(packet.trailer)
    data_at = tcp_at + tcp.header_len
    ip_bad = ip_zero = False
    if isinstance(ip, IPv4):
        declared = ip.total_length
        hop = ip.ttl
        header = bytes(frame[ip_at : ip_at + ip.header_len])
        ip_bad = internet_checksum(header) != 0
        ip_zero = ip.checksum == 0
    else:
        declared = ip.payload_length and ip.payload_length + 40
        hop = ip.hop_limit
    stop = min(ip_at + declared, bound) if declared else bound
    data = bytes(frame[data_at : max(data_at, stop)])
    length = max(0, ip_at + declared - data_at) if declared else len(data)
    complete = bool(declared) and len(data) == length
    segment = bytes(frame[tcp_at:data_at]) + data
    tcp_bad, pattern = _checksums(tcp, segment, ip.src, receiver, complete)
    return _Segment(
        key=key,
        side=side,
        source=ip.src,
        receiver=receiver,
        seq=tcp.seq,
        ack=tcp.ack,
        flags=tcp.flags,
        window=tcp.window,
        scale=_window_scale(tcp.options) if tcp.flags & _SYN else None,
        data=data,
        length=length,
        origin=_Origin(ref, timestamp, hop),
        unknown=not declared,
        ip_bad=ip_bad,
        ip_zero=ip_zero,
        tcp_bad=tcp_bad,
        pattern=pattern,
    )


def _uncovered(
    low: int, high: int, covered: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    """Return the ranges of ``[low, high)`` no range of ``covered`` holds.

    :param low: The first byte.
    :param high: One past the last.
    :param covered: Ranges inside ``[low, high)``, as ``(start, end)``.
    """
    found: list[tuple[int, int]] = []
    cursor = low
    for start, end in sorted(covered):
        if start > cursor:
            found.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < high:
        found.append((cursor, high))
    return found


def _hull(ranges: list[tuple[int, int]]) -> tuple[int, int]:
    """Return the smallest range holding every range of ``ranges``.

    :param ranges: At least one ``(start, end)`` range.
    """
    return min(start for start, _ in ranges), max(end for _, end in ranges)


def _coalesced(chunks: list[_Chunk]) -> list[_Chunk]:
    """Join adjacent chunks of one frame that are both data or both cut.

    :param chunks: Chunks in order, none overlapping.
    """
    joined: list[_Chunk] = []
    for chunk in chunks:
        if joined:
            prior = joined[-1]
            if (
                prior.origin is chunk.origin
                and prior.end == chunk.start
                and (prior.data is None) == (chunk.data is None)
            ):
                data = None
                if prior.data is not None and chunk.data is not None:
                    data = prior.data + chunk.data
                joined[-1] = _Chunk(prior.start, chunk.end, data, prior.origin)
                continue
        joined.append(chunk)
    return joined


def _merged_chunks(
    overlapped: list[_Chunk],
    bounds: tuple[int, int],
    arriving: _Chunk,
    last: bool,
) -> list[_Chunk]:
    """Return the chunks that replace ``overlapped`` once a range is stored.

    The arriving bytes fill every byte of ``bounds`` no held chunk holds,
    and replace a held chunk's bytes where they win: always over a range
    the capture cut, and under ``last`` over held bytes. A range the
    capture cut never replaces held bytes.

    :param overlapped: The held chunks ``bounds`` overlaps, in order.
    :param bounds: The ``[low, high)`` stored.
    :param arriving: The arriving chunk, holding ``bounds``.
    :param last: Whether the policy is ``last``.
    """
    low, high = bounds
    new: list[_Chunk] = []
    cursor = low
    for held in overlapped:
        if held.start < low:
            new.append(held.cut(held.start, low))
        start, end = max(held.start, low), min(held.end, high)
        if start > cursor:
            new.append(arriving.cut(cursor, start))
        wins = arriving.data is not None and (held.data is None or last)
        new.append(arriving.cut(start, end) if wins else held.cut(start, end))
        if held.end > high:
            new.append(held.cut(high, held.end))
        cursor = max(cursor, end)
    if cursor < high:
        new.append(arriving.cut(cursor, high))
    return _coalesced(new)


class _Found:
    """What an arriving segment overlaps, gathered before it is stored."""

    __slots__ = ("late", "opponents", "unverified", "winners")

    def __init__(self) -> None:
        #: Delivered or held bytes it overlaps with bytes of its own.
        self.opponents: list[_Chunk] = []
        #: Whether it replaces each of them.
        self.winners: list[bool] = []
        #: Repeated ranges whose bytes could not be compared.
        self.unverified: list[tuple[int, int]] = []
        #: Ranges of ACKED gaps it fills.
        self.late: list[tuple[int, int]] = []


class _Work:
    """One fed segment and the events it produces."""

    __slots__ = ("events", "own", "prefix", "segment", "start", "suffix")

    def __init__(self, segment: _Segment, events: list[StreamEvent]) -> None:
        self.segment = segment
        #: Events of other connections, returned first.
        self.events = events
        #: Events of the connection a SYN ended, returned next.
        self.prefix: list[StreamEvent] = []
        #: The segment's own connection's events, sorted by offset.
        self.own: list[StreamEvent] = []
        #: Events of its own connection's eviction, returned last.
        self.suffix: list[StreamEvent] = []
        #: The stream offset of its first byte, once known.
        self.start = 0

    @property
    def ref(self) -> int:
        """The segment's frame reference."""
        return self.segment.origin.ref


def _sort_key(event: StreamEvent, mine: Direction) -> tuple[int, int]:
    """Return where an event of a segment's own connection sorts.

    Events of the segment's direction come first, those of the other
    direction next, each in stream offset order.

    :param event: The event.
    :param mine: The segment's direction.
    """
    group = 0 if event.direction is mine else 1
    if isinstance(event, (StreamData, StreamEnd, LateData)):
        return group, event.offset
    return group, getattr(event, "start", 0)


class _Fields(typing.TypedDict):
    """The fields every event has, for a stream event's constructor."""

    flow: FragmentKey | FlowKey
    direction: Direction | None
    spans: tuple[Span, ...]
    completing_ref: int | None
    first_timestamp: int
    last_timestamp: int


def _fields(
    key: FlowKey,
    side: int | None,
    spans: list[Span],
    ref: int | None,
    times: tuple[int, int],
) -> _Fields:
    """Return the fields every stream event has.

    :param key: The connection's key.
    :param side: The direction's side, or ``None`` for the connection.
    :param spans: The contributing frames.
    :param ref: The ``completing_ref``.
    :param times: The two timestamps when ``spans`` is empty.
    """
    ordered, first, last = _event_times(spans, times)
    return _Fields(
        flow=key,
        direction=None if side is None else _direction(side),
        spans=ordered,
        completing_ref=ref,
        first_timestamp=first,
        last_timestamp=last,
    )


def _differing_ranges(
    opponents: list[_Chunk], start: int, data: bytes
) -> list[tuple[int, int]]:
    """Return, per opponent, the smallest range where the versions differ.

    :param opponents: Held or delivered chunks, each inside the arriving
        segment's captured bytes, in order.
    :param start: The arriving segment's first byte.
    :param data: Its captured bytes.
    """
    found: list[tuple[int, int]] = []
    for chunk in opponents:
        held = typing.cast(bytes, chunk.data)
        arriving = data[chunk.start - start : chunk.end - start]
        difference = _difference(held, arriving)
        if difference is not None:
            found.append(
                (chunk.start + difference[0], chunk.start + difference[1])
            )
    return found


def _versions(
    opponents: list[_Chunk],
    winners: list[bool],
    arriving: _Chunk,
    bounds: tuple[int, int],
) -> tuple[bytes, bytes, list[Span], list[Span]]:
    """Return the kept and other versions of a range, and their spans.

    Where only the arriving segment holds a byte, both versions hold it.
    The range ends inside the last opponent it overlaps.

    :param opponents: The chunks the segment overlaps, in order.
    :param winners: Whether it replaces each of them.
    :param arriving: The segment's captured bytes, holding ``bounds``.
    :param bounds: The ``[low, high)`` range.
    """
    low, high = bounds
    kept = bytearray()
    other = bytearray()
    kept_spans: list[Span] = []
    other_spans: list[Span] = []
    cursor = low
    for chunk, wins in zip(opponents, winners, strict=True):
        start, end = max(low, chunk.start), min(high, chunk.end)
        if start >= end:
            continue
        for part in ([(cursor, start)] if start > cursor else []) + [
            (start, end)
        ]:
            mine = arriving.cut(*part)
            theirs = mine if part[0] < start else chunk.cut(*part)
            first, second = (mine, theirs) if wins else (theirs, mine)
            kept.extend(typing.cast(bytes, first.data))
            other.extend(typing.cast(bytes, second.data))
            kept_spans.append(first.origin.span(*part))
            other_spans.append(second.origin.span(*part))
        cursor = end
    return bytes(kept), bytes(other), kept_spans, other_spans


def _stored(pieces: list[_Chunk], arriving: _Chunk, last: bool) -> list[_Chunk]:
    """Return ``pieces`` once ``arriving`` is stored among them.

    :param pieces: Chunks in order, none overlapping.
    :param arriving: The chunk stored.
    :param last: Whether the policy is ``last``.
    """
    first = 0
    while first < len(pieces) and pieces[first].end <= arriving.start:
        first += 1
    stop = first
    while stop < len(pieces) and pieces[stop].start < arriving.end:
        stop += 1
    merged = _merged_chunks(
        pieces[first:stop], (arriving.start, arriving.end), arriving, last
    )
    return pieces[:first] + merged + pieces[stop:]


def _held_bytes(conn: _Conn) -> int:
    """Return the undelivered data bytes a connection holds.

    :param conn: The connection.
    """
    return sum(
        len(chunk.data)
        for _, found in conn.dirs()
        for chunk in found.held or ()
        if chunk.data is not None
    )


class StreamReassembler:
    """Reassemble TCP segments into the byte stream of each direction.

    A reassembler is not thread-safe. Events are returned by the call
    that causes them and never queued, so what it holds is exactly the
    connections, their held segments and their retained bytes
    (:attr:`usage`).

    :param bounds: The caps and timeouts; ``None`` means
        ``StreamBounds()``.
    :param policy: The overlap policy of a receiver no ``targets``
        network holds: :attr:`OverlapPolicy.FIRST` or
        :attr:`OverlapPolicy.LAST`.
    :param targets: Networks, written as :func:`ipaddress.ip_network`
        accepts them, mapped to the policy of the hosts in them. The
        longest prefix holding a direction's receiver applies.
    :param checksums: What a bad IPv4 header or TCP checksum does.
    :param local: The capture host's networks, from which
        :attr:`ChecksumMode.AUTO` accepts the offload patterns; ``None``
        accepts them from any source.
    :raises TypeError: if ``bounds`` is not a :class:`StreamBounds`.
    :raises ValueError: if ``policy`` or a ``targets`` value is not
        ``first`` or ``last``, ``checksums`` is not a
        :class:`ChecksumMode`, ``local`` is a ``str`` rather than an
        iterable of them, or a network does not parse.
    """

    def __init__(
        self,
        *,
        bounds: StreamBounds | None = None,
        policy: OverlapPolicy = OverlapPolicy.FIRST,
        targets: Mapping[str, OverlapPolicy] | None = None,
        checksums: ChecksumMode = ChecksumMode.AUTO,
        local: Iterable[str] | None = None,
    ) -> None:
        if bounds is None:
            bounds = StreamBounds()
        if not isinstance(bounds, StreamBounds):
            raise TypeError("bounds must be a StreamBounds")
        if not _stream_policy(policy):
            raise ValueError(f"{policy!r} is not a stream OverlapPolicy")
        if not isinstance(checksums, ChecksumMode):
            raise ValueError(f"{checksums!r} is not a ChecksumMode")
        self._bounds = bounds
        self._policy = policy
        self._checksums = checksums
        self._targets: list[
            tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, OverlapPolicy]
        ] = []
        for text, value in (targets or {}).items():
            if not _stream_policy(value):
                raise ValueError(
                    f"targets[{text!r}]: {value!r} is not a stream "
                    "OverlapPolicy"
                )
            self._targets.append((_network(text, "targets"), value))
        self._targets.sort(key=lambda entry: -entry[0].prefixlen)
        if isinstance(local, str):
            raise ValueError("local must be an iterable of networks, not a str")
        self._local = None if local is None else _networks(local, "local")
        #: Connections not yet carrying data both ways, least recently
        #: active first.
        self._half: OrderedDict[FlowKey, _Conn] = OrderedDict()
        #: Connections carrying data both ways, least recently active
        #: first.
        self._full: OrderedDict[FlowKey, _Conn] = OrderedDict()
        self._deadlines: list[tuple[int, int, FlowKey]] = []
        self._total = 0
        self._clock: int | None = None
        self._fed = 0
        self._seq = 0

    @property
    def usage(self) -> Usage:
        """The connections held and the bytes charged for them."""
        return Usage(len(self._half) + len(self._full), self._total)

    def feed(
        self,
        packet: Packet,
        frame: bytes | memoryview,
        *,
        timestamp: int,
        ref: int | None = None,
    ) -> tuple[StreamEvent, ...]:
        """Take one frame and return every event it caused.

        Every frame moves the capture clock to its timestamp, unless
        that is 0 or lower than the highest seen, and returns the
        expiries the clock causes. A packet with no TCP layer, or whose
        first TCP layer is inside an IP fragment, returns those
        expiries only.

        :param packet: The packet :func:`~netprotocols.decode_frame`
            decoded from ``frame``, a lax walk's included.
        :param frame: The frame.
        :param timestamp: Its capture time, in nanoseconds.
        :param ref: Its reference in events; ``None`` means the number
            of frames fed before it.
        :raises TypeError: if ``packet`` is not a
            :class:`~netprotocols.packet.Packet`, ``frame`` is not
            bytes, or ``timestamp`` or ``ref`` is not an ``int``.
        :raises ValueError: if ``timestamp`` is negative, or ``frame``
            is shorter than ``packet.consumed + len(packet.trailer)``.
        """
        _check_feed(packet, frame, timestamp, ref)
        if ref is None:
            ref = self._fed
        self._fed += 1
        events: list[StreamEvent] = []
        self._tick(timestamp, events)
        segment = _slice_segment(packet, frame, timestamp, ref)
        if segment is None:
            return tuple(events)
        work = _Work(segment, events)
        self._take(work)
        mine = _direction(segment.side)
        work.own.sort(key=lambda event: _sort_key(event, mine))
        return tuple(events + work.prefix + work.own + work.suffix)

    def advance(self, timestamp: int) -> tuple[StreamEvent, ...]:
        """Move the capture clock to ``timestamp`` and return the expiries.

        :param timestamp: The capture time, in nanoseconds; 0, or one
            lower than the clock, moves nothing.
        :raises TypeError: if ``timestamp`` is not an ``int``.
        :raises ValueError: if ``timestamp`` is negative.
        """
        _check_timestamp(timestamp)
        events: list[StreamEvent] = []
        self._tick(timestamp, events)
        return tuple(events)

    def close(self) -> tuple[StreamEvent, ...]:
        """Flush every connection and return the events.

        Connections go in deadline order, then those with no deadline,
        ties in the order they started. A connection whose RST is
        pending ends with ``StreamEnd(RST)`` for each open direction;
        any other is flushed, each open direction ends with
        ``StreamEnd(CLOSE)``, and :class:`Expired` follows under the
        timeout whose deadline comes first (:attr:`Timeout.IDLE` when it
        has none). The reassembler is empty afterwards.
        """
        events: list[StreamEvent] = []
        ordered = []
        for conn in [*self._half.values(), *self._full.values()]:
            due = self._due(conn)
            order = (due is None, due[0] if due else 0, conn.seq)
            ordered.append((order, conn, due))
        ordered.sort(key=lambda entry: entry[0])
        for _, conn, due in ordered:
            if conn.rst is not None:
                self._flush(conn, EndReason.RST, None, events)
                continue
            timeout = Timeout.IDLE if due is None else due[1]
            self._expired(conn, typing.cast(Timeout, timeout), events, True)
        self._deadlines.clear()
        return tuple(events)

    # -- lookup, accounting and time ----------------------------------

    def _find(self, key: FlowKey) -> _Conn | None:
        """Return the connection held under ``key``, if any.

        :param key: The flow key.
        """
        return self._half.get(key) or self._full.get(key)

    def _charge(self, conn: _Conn, delta: int) -> None:
        """Add ``delta`` bytes to a connection's charge and the total.

        :param conn: The connection.
        :param delta: The change.
        """
        conn.charge += delta
        self._total += delta

    def _side(self, conn: _Conn, side: int) -> _Dir:
        """Return a direction of a connection, creating it when absent.

        A direction is charged :data:`PIECE_OVERHEAD`, as state with no
        captured bytes.

        :param conn: The connection.
        :param side: 0 for ``A_TO_B``, 1 for ``B_TO_A``.
        """
        found = conn.a if side == 0 else conn.b
        if found is None:
            found = _Dir()
            if side == 0:
                conn.a = found
            else:
                conn.b = found
            self._charge(conn, PIECE_OVERHEAD)
        return found

    def _target(self, receiver: str) -> OverlapPolicy:
        """Return the policy of the longest prefix holding ``receiver``.

        :param receiver: The receiver's address.
        """
        if self._targets:
            address = ipaddress.ip_address(receiver)
            for network, policy in self._targets:
                if address in network:
                    return policy
        return self._policy

    def _policy_of(self, conn: _Conn, side: int) -> OverlapPolicy:
        """Return the policy of a direction's receiver.

        :param conn: The connection.
        :param side: The direction's side.
        """
        key = conn.key
        return self._target(key.addr_b if side == 0 else key.addr_a)

    def _is_local(self, address: str) -> bool:
        """Return whether ``address`` may carry the offload patterns.

        :param address: A segment's source address.
        """
        if self._local is None:
            return True
        parsed = ipaddress.ip_address(address)
        return any(parsed in network for network in self._local)

    def _touch(self, conn: _Conn, timestamp: int) -> None:
        """Record activity on a connection.

        :param conn: The connection.
        :param timestamp: The frame's capture time.
        """
        conn.last = max(conn.last, timestamp)
        (self._full if conn.full else self._half).move_to_end(conn.key)

    def _due(self, conn: _Conn) -> tuple[int, Timeout | EndReason] | None:
        """Return a connection's earliest deadline and what it enforces.

        :param conn: The connection.
        """
        bounds = self._bounds
        found: list[tuple[int, int, Timeout | EndReason]] = []
        if bounds.age_timeout is not None:
            found.append((conn.created + bounds.age_timeout, 0, Timeout.AGE))
        if conn.rst is not None:
            if bounds.idle_timeout_closed is not None:
                deadline = conn.rst.timestamp + bounds.idle_timeout_closed
                found.append((deadline, 1, EndReason.RST))
        else:
            idle = bounds.idle_timeout_new
            if conn.finished():
                idle = bounds.idle_timeout_closed
            elif conn.full:
                idle = bounds.idle_timeout_established
            if idle is not None:
                found.append((conn.last + idle, 2, Timeout.IDLE))
        if not found:
            return None
        deadline, _, kind = min(found, key=lambda entry: entry[:2])
        return deadline, kind

    def _schedule(self, conn: _Conn) -> None:
        """Put a connection's deadline in the heap when it came earlier.

        A later deadline is found when the earlier entry is popped.

        :param conn: The connection.
        """
        due = self._due(conn)
        if due is not None and (
            conn.scheduled is None or due[0] < conn.scheduled
        ):
            conn.scheduled = due[0]
            heapq.heappush(self._deadlines, (due[0], conn.seq, conn.key))
            self._compact()

    def _compact(self) -> None:
        """Rebuild the deadline heap once most entries are stale."""
        if len(self._deadlines) > 2 * (len(self._half) + len(self._full)) + 64:
            self._deadlines = [
                (conn.scheduled, conn.seq, conn.key)
                for conn in [*self._half.values(), *self._full.values()]
                if conn.scheduled is not None
            ]
            heapq.heapify(self._deadlines)

    def _tick(self, timestamp: int, events: list[StreamEvent]) -> None:
        """Move the clock and expire every connection due by it.

        :param timestamp: A capture time.
        :param events: Where the expiries are appended.
        """
        if timestamp and (self._clock is None or timestamp > self._clock):
            self._clock = timestamp
        clock = self._clock
        if clock is None:
            return
        while self._deadlines and self._deadlines[0][0] <= clock:
            deadline, seq, key = heapq.heappop(self._deadlines)
            conn = self._find(key)
            if conn is None or conn.seq != seq or conn.scheduled != deadline:
                continue
            conn.scheduled = None
            due = self._due(conn)
            if due is None:
                continue
            if due[0] != deadline:
                conn.scheduled = due[0]
                heapq.heappush(self._deadlines, (due[0], conn.seq, conn.key))
            elif isinstance(due[1], EndReason):
                self._flush(conn, EndReason.RST, None, events)
            else:
                self._expired(conn, due[1], events, False)

    def _expired(
        self,
        conn: _Conn,
        timeout: Timeout,
        events: list[StreamEvent],
        closing: bool,
    ) -> None:
        """Flush a connection a timeout or :meth:`close` ends.

        :param conn: The connection.
        :param timeout: The timeout reported by :class:`Expired`.
        :param events: Where the events are appended.
        :param closing: Whether :meth:`close` ends it.
        """
        held = _held_bytes(conn)
        reason = EndReason.CLOSE
        if not closing:
            reason = EndReason.AGE if timeout is Timeout.AGE else EndReason.IDLE
        self._flush(conn, reason, None, events)
        events.append(
            Expired(
                **_fields(conn.key, None, [], None, (conn.created, conn.last)),
                timeout=timeout,
                held_bytes=held,
                missing=(),
            )
        )

    def _remove(self, conn: _Conn) -> None:
        """Drop a connection from the reassembler.

        :param conn: The connection.
        """
        del (self._full if conn.full else self._half)[conn.key]
        self._total -= conn.charge
        self._compact()

    def _open(self, work: _Work) -> _Conn:
        """Start the connection a segment's key names.

        :param work: The segment.
        """
        segment = work.segment
        key = segment.key
        self._seq += 1
        conn = _Conn(key, self._seq, segment.origin.timestamp)
        self._half[key] = conn
        self._total += conn.charge
        if key.addr_a == key.addr_b and key.port_a == key.port_b:
            self._anomaly(work, AnomalyKind.SELF_CONNECTED, (0, 0))
        return conn

    # -- events ---------------------------------------------------------

    def _anomaly(
        self, work: _Work, kind: AnomalyKind, bounds: tuple[int, int]
    ) -> None:
        """Append an :class:`Anomaly` about the arriving segment.

        :param work: The segment.
        :param kind: The rule.
        :param bounds: The ``[start, end)`` it concerns.
        """
        segment = work.segment
        span = segment.origin.span(work.start, work.start + len(segment.data))
        times = (segment.origin.timestamp, segment.origin.timestamp)
        work.own.append(
            Anomaly(
                **_fields(segment.key, segment.side, [span], work.ref, times),
                kind=kind,
                start=bounds[0],
                end=bounds[1],
            )
        )

    def _once(
        self,
        found: _Dir,
        note: int,
        work: _Work,
        kind: AnomalyKind,
        bounds: tuple[int, int],
    ) -> None:
        """Append an :class:`Anomaly` a direction reports once.

        :param found: The segment's direction.
        :param note: The bit that records it.
        :param work: The segment.
        :param kind: The rule.
        :param bounds: The ``[start, end)`` it concerns.
        """
        if not found.notes & note:
            found.notes |= note
            self._anomaly(work, kind, bounds)

    def _extent(self, conn: _Conn | None, work: _Work) -> tuple[int, int]:
        """Return the stream range a segment's data declares.

        The offsets are 0 to its length while its direction's offset 0
        is unknown. The start is recorded in ``work``.

        :param conn: The segment's connection, if held.
        :param work: The segment.
        """
        segment = work.segment
        start = 0
        if conn is not None:
            found = conn.a if segment.side == 0 else conn.b
            if found is not None and found.base is not None:
                seq = segment.seq + (1 if segment.flags & _SYN else 0)
                start = found.offset(seq)
        work.start = start
        return start, start + segment.length

    # -- the segment's rules --------------------------------------------

    def _take(self, work: _Work) -> None:
        """Apply the rules to one segment and store what it supplies.

        :param work: The segment.
        """
        segment = work.segment
        conn = self._find(segment.key)
        if not self._usable(conn, work):
            return
        if segment.flags & _RST:
            self._reset(conn, work)
            return
        if not segment.flags & (_ACK | _SYN):
            bounds = self._extent(conn, work)
            self._anomaly(work, AnomalyKind.DATA_WITHOUT_ACK, bounds)
            return
        if segment.flags & _SYN:
            conn = self._synchronize(conn, work)
            if conn is None:
                return
        elif conn is None:
            conn = self._open(work)
        self._segment(conn, work)
        self._enforce(conn, work)

    def _usable(self, conn: _Conn | None, work: _Work) -> bool:
        """Apply :class:`ChecksumMode` and return whether the segment is used.

        :param conn: The segment's connection, if held.
        :param work: The segment.
        """
        segment = work.segment
        bounds = self._extent(conn, work)
        used = True
        if segment.unknown:
            self._anomaly(work, AnomalyKind.UNVERIFIED_CHECKSUM, bounds)
            used = self._accept(work, segment.pattern, bounds)
        if segment.ip_bad:
            self._anomaly(work, AnomalyKind.BAD_CHECKSUM, bounds)
            used = self._accept(work, segment.ip_zero, bounds) and used
        if segment.tcp_bad:
            self._anomaly(work, AnomalyKind.BAD_CHECKSUM, bounds)
            used = self._accept(work, segment.pattern, bounds) and used
        return used

    def _accept(
        self, work: _Work, pattern: bool, bounds: tuple[int, int]
    ) -> bool:
        """Return whether a checksum that did not verify is used anyway.

        :param work: The segment.
        :param pattern: Whether the checksum is an offload pattern.
        :param bounds: The segment's stream range.
        """
        if self._checksums is ChecksumMode.KEEP:
            return True
        if (
            self._checksums is ChecksumMode.AUTO
            and pattern
            and self._is_local(work.segment.source)
        ):
            self._anomaly(work, AnomalyKind.CHECKSUM_OFFLOAD, bounds)
            return True
        return False

    def _reset(self, conn: _Conn | None, work: _Work) -> None:
        """Take an RST: report it and make the connection's end pending.

        :param conn: The segment's connection, if held.
        :param work: The segment.
        """
        segment = work.segment
        bounds = self._extent(conn, work)
        if conn is not None:
            self._touch(conn, segment.origin.timestamp)
            self._hop(self._side(conn, segment.side), work, bounds)
        if segment.length:
            self._anomaly(work, AnomalyKind.RST_WITH_DATA, bounds)
        self._anomaly(work, AnomalyKind.RST_RECEIVED, (bounds[0], bounds[0]))
        if conn is None:
            return
        if conn.rst is None:
            conn.rst = segment.origin
            for side in (0, 1):
                found = self._side(conn, side)
                found.mark = found.reach
                found.notes &= ~_NOTE_AFTER_RST
        self._enforce(conn, work)

    def _synchronize(self, conn: _Conn | None, work: _Work) -> _Conn | None:
        """Take a SYN; return its connection, or ``None`` when it is ignored.

        :param conn: The segment's connection, if held.
        :param work: The segment.
        """
        segment = work.segment
        if conn is not None and conn.finished():
            self._remove(conn)
            conn = None
        if conn is not None and conn.rst is not None:
            found = conn.a if segment.side == 0 else conn.b
            if found is None or not self._same_isn(found, segment):
                self._flush(conn, EndReason.RST, work.ref, work.prefix)
                conn = self._open(work)
                self._set_isn(self._side(conn, segment.side), work)
                bounds = self._extent(conn, work)
                self._anomaly(work, AnomalyKind.SYN_AFTER_RST, bounds)
                return conn
        if conn is None:
            conn = self._open(work)
            self._set_isn(self._side(conn, segment.side), work)
            return conn
        found = self._side(conn, segment.side)
        if self._same_isn(found, segment):
            self._repeated_syn(conn, work)
        elif found.base is None:
            self._set_isn(found, work)
        elif found.next == 0 and not found.notes & _ENDED:
            self._anomaly(work, AnomalyKind.ISN_CHANGED, (0, 0))
            self._rebase(conn, found, work)
        else:
            bounds = self._extent(conn, work)
            self._anomaly(work, AnomalyKind.ISN_CHANGED, bounds)
            return None
        return conn

    @staticmethod
    def _same_isn(found: _Dir, segment: _Segment) -> bool:
        """Return whether a SYN repeats its direction's ISN.

        :param found: The direction.
        :param segment: The SYN.
        """
        return bool(found.notes & _SYNCED) and found.base == (
            (segment.seq + 1) % _SEQ_SPACE
        )

    def _repeated_syn(self, conn: _Conn, work: _Work) -> None:
        """Report a SYN that repeats its direction's ISN.

        :param conn: The connection.
        :param work: The SYN.
        """
        segment = work.segment
        span = segment.origin.span(0, 0)
        times = (segment.origin.timestamp, segment.origin.timestamp)
        work.own.append(
            Retransmission(
                **_fields(conn.key, segment.side, [span], work.ref, times),
                start=0,
                end=0,
                verified=True,
            )
        )

    def _set_isn(self, found: _Dir, work: _Work) -> None:
        """Set a direction's offset 0 from the SYN being taken.

        :param found: The direction.
        :param work: The SYN.
        """
        segment = work.segment
        found.base = (segment.seq + 1) % _SEQ_SPACE
        found.scale = segment.scale
        found.notes |= _SYNCED
        if segment.length:
            work.start = 0
            self._anomaly(work, AnomalyKind.SYN_DATA, (0, segment.length))

    def _rebase(self, conn: _Conn, found: _Dir, work: _Work) -> None:
        """Replace a direction's ISN before it delivered anything.

        Held chunks, and the offsets the direction recorded, move with
        offset 0; whatever lands before it is dropped and reported.

        :param conn: The connection.
        :param found: The direction.
        :param work: The SYN with the new ISN.
        """
        segment = work.segment
        old = typing.cast(int, found.base)
        found.base = (segment.seq + 1) % _SEQ_SPACE
        found.scale = segment.scale
        delta = _serial((old - found.base) % _SEQ_SPACE, 0)
        kept: list[_Chunk] = []
        dropped: list[tuple[int, int]] = []
        change = 0
        for chunk in found.held or ():
            start, end = chunk.start + delta, chunk.end + delta
            change -= _chunk_charge(chunk)
            if start < 0:
                dropped.append((start, min(end, 0)))
            if end > 0:
                moved = _Chunk(start, end, chunk.data, chunk.origin)
                moved = moved.cut(max(start, 0), end)
                kept.append(moved)
                change += _chunk_charge(moved)
        found.held = kept or None
        self._charge(conn, change)
        found.reach = max(0, found.reach + delta)
        if found.fin is not None:
            end = found.fin[0] + delta
            found.fin = (end, found.fin[1]) if end >= 0 else None
        found.ack = _shifted(found.ack, delta)
        found.pending = None
        self._rearm(found)
        found.edge = _shifted(found.edge, delta)
        found.mark = _shifted(found.mark, delta)
        if dropped:
            self._anomaly(work, AnomalyKind.BEFORE_STREAM_START, _hull(dropped))

    def _hop(self, found: _Dir, work: _Work, bounds: tuple[int, int]) -> None:
        """Report a hop limit other than the direction's previous segment's.

        :param found: The direction.
        :param work: The segment.
        :param bounds: Its stream range.
        """
        hop = work.segment.origin.hop_limit
        if 0 <= found.hop != hop:
            self._anomaly(work, AnomalyKind.HOP_LIMIT_CHANGED, bounds)
        found.hop = hop

    def _segment(self, conn: _Conn, work: _Work) -> None:
        """Take an accepted segment that is not an RST.

        :param conn: Its connection.
        :param work: The segment.
        """
        segment = work.segment
        found = self._side(conn, segment.side)
        self._touch(conn, segment.origin.timestamp)
        bounds = self._extent(conn, work)
        self._hop(found, work, bounds)
        if segment.flags & _URG:
            self._once(found, _NOTE_URGENT, work, AnomalyKind.URGENT, bounds)
        if found.base is None and (segment.length or segment.flags & _FIN):
            found.base = segment.seq
            bounds = self._extent(conn, work)
            self._once(
                found, _NOTE_MIDSTREAM, work, AnomalyKind.MIDSTREAM, bounds
            )
        peer = conn.b if segment.side == 0 else conn.a
        acked = None
        if peer is not None and segment.flags & _ACK:
            acked = self._acknowledge(conn, peer, found, work)
        if found.base is not None:
            self._carry(conn, found, work)
        if peer is not None and acked is not None and acked > peer.next:
            self._confirm(conn, peer, work, acked)
        if not conn.full and all(
            side is not None and side.notes & _SENT for side in (conn.a, conn.b)
        ):
            del self._half[conn.key]
            self._full[conn.key] = conn
            conn.full = True

    def _carry(self, conn: _Conn, found: _Dir, work: _Work) -> None:
        """Take a segment's data and FIN into its direction, and deliver.

        :param conn: The connection.
        :param found: The segment's direction.
        :param work: The segment.
        """
        segment = work.segment
        start, end = self._extent(conn, work)
        if segment.length:
            self._data(conn, found, (start, end), work)
        if segment.flags & _FIN:
            self._fin(found, end, work)
        self._deliver(conn, found, work.ref, work.own, True)
        self._retain_window(conn, found)
        if segment.length and end > found.next:
            self._confirm(conn, found, work, None)

    def _fin(self, found: _Dir, end: int, work: _Work) -> None:
        """Fix a direction's end at a FIN, or report it inconsistent.

        :param found: The segment's direction.
        :param end: The end the FIN declares.
        :param work: The segment.
        """
        if found.fin is None and end >= found.reach:
            found.fin = (end, work.segment.origin)
        elif found.fin is None or found.fin[0] != end:
            self._anomaly(work, AnomalyKind.INCONSISTENT_FIN, (end, end))

    def _data(
        self, conn: _Conn, found: _Dir, bounds: tuple[int, int], work: _Work
    ) -> None:
        """Apply the data rules to a segment and place its bytes.

        :param conn: The connection.
        :param found: The segment's direction.
        :param bounds: The stream range its data declares.
        :param work: The segment.
        """
        start, end = bounds
        data = work.segment.data
        if start < 0:
            self._anomaly(work, AnomalyKind.BEFORE_STREAM_START, bounds)
            return
        if start + len(data) < end:
            captured = (start + len(data), end)
            self._anomaly(work, AnomalyKind.TRUNCATED, captured)
        if found.fin is not None and end > found.fin[0]:
            limit = found.fin[0]
            self._anomaly(
                work, AnomalyKind.DATA_AFTER_FIN, (max(start, limit), end)
            )
            end = limit
            data = data[: max(0, end - start)]
            if start >= end:
                return
        if found.edge is not None and end > found.edge:
            self._anomaly(
                work, AnomalyKind.OUT_OF_WINDOW, (max(start, found.edge), end)
            )
        if found.mark is not None and end > found.mark:
            self._once(
                found,
                _NOTE_AFTER_RST,
                work,
                AnomalyKind.DATA_AFTER_RST,
                (max(start, found.mark), end),
            )
            conn.rst = None
        found.reach = max(found.reach, end)
        found.notes |= _SENT
        self._place(conn, found, (start, end), data, work)

    # -- acknowledgements -------------------------------------------------

    def _acknowledge(
        self, conn: _Conn, peer: _Dir, sender: _Dir, work: _Work
    ) -> int | None:
        """Take a segment's acknowledgement of the other direction.

        Return the acknowledged offset, or ``None`` when the other
        direction's offset 0 is unknown or the acknowledgement falls
        before it.

        :param conn: The connection.
        :param peer: The direction acknowledged.
        :param sender: The segment's direction.
        :param work: The segment.
        """
        segment = work.segment
        if peer.base is None:
            return None
        acked = peer.offset(segment.ack)
        if peer.fin is not None and acked == peer.fin[0] + 1:
            acked -= 1
        if acked < 0:
            return None
        if peer.ack is None or acked > peer.ack:
            peer.ack = acked
        if peer.notes & sender.notes & _SYNCED:
            shift = 0
            if not segment.flags & _SYN and None not in (
                sender.scale,
                peer.scale,
            ):
                shift = typing.cast(int, sender.scale)
            edge = acked + (segment.window << shift)
            if peer.edge is None or edge > peer.edge:
                peer.edge = edge
        self._rearm(peer)
        self._retain_window(conn, peer)
        return acked

    def _rearm(self, found: _Dir) -> None:
        """Start the grace of a direction's lowest acknowledged hole.

        A pending grace whose acknowledgement lies past the delivered
        end stands; otherwise one starts at the capture clock, held to
        the highest acknowledgement, when that lies past the delivered
        end, and none is pending when it does not.

        :param found: The direction.
        """
        ack = found.ack
        if ack is None or ack <= found.next:
            found.pending = None
        elif found.pending is None or found.pending[1] <= found.next:
            found.pending = (self._clock or 0, ack)

    def _confirm(
        self, conn: _Conn, found: _Dir, work: _Work, acked: int | None
    ) -> None:
        """Declare the holes the peer acknowledged once their grace passed.

        The pending grace holds an acknowledgement; once
        ``ack_gap_grace`` has passed since it started, a frame confirms
        it: an acknowledgement at or past it, or data of the direction
        past the delivered end. Each hole below that acknowledgement, up
        to the highest offset the direction received, becomes a
        ``Gap(ACKED)`` and the held bytes after it are delivered, with
        the confirming frame's reference; a grace for the holes past it
        then starts.

        :param conn: The connection.
        :param found: The direction whose holes are acknowledged.
        :param work: The confirming segment.
        :param acked: The offset the segment acknowledges, or ``None``
            for data of the direction.
        """
        pending = found.pending
        if pending is None or (acked is not None and acked < pending[1]):
            return
        since, point = pending
        if (self._clock or 0) < since + self._bounds.ack_gap_grace:
            return
        side = 0 if found is conn.a else 1
        limit = min(point, found.reach)
        if point > found.reach and not found.notes & _NOTE_BEYOND:
            found.notes |= _NOTE_BEYOND
            segment = work.segment
            times = (segment.origin.timestamp, segment.origin.timestamp)
            work.own.append(
                Anomaly(
                    **_fields(conn.key, side, [], work.ref, times),
                    kind=AnomalyKind.ACK_BEYOND_DATA,
                    start=found.reach,
                    end=point,
                )
            )
        while found.next < limit:
            end = limit if not found.held else min(limit, found.held[0].start)
            bounds = (found.next, end)
            self._gap(conn, found, bounds, GapReason.ACKED, work.ref, work.own)
            found.next = end
            self._deliver(conn, found, work.ref, work.own, True)
        self._rearm(found)
        self._retain_window(conn, found)

    def _gap(
        self,
        conn: _Conn,
        found: _Dir,
        bounds: tuple[int, int],
        reason: GapReason,
        ref: int | None,
        out: list[StreamEvent],
    ) -> None:
        """Append a :class:`Gap`.

        A ``Gap(ACKED)`` is also recorded among the retained bytes, so
        bytes arriving for it later are :class:`LateData`.

        :param conn: The connection.
        :param found: The direction.
        :param bounds: The ``[start, end)`` skipped.
        :param reason: Why.
        :param ref: The ``completing_ref``.
        :param out: Where the event is appended.
        """
        side = 0 if found is conn.a else 1
        out.append(
            Gap(
                **_fields(conn.key, side, [], ref, (conn.created, conn.last)),
                start=bounds[0],
                end=bounds[1],
                reason=reason,
            )
        )
        if reason is GapReason.ACKED:
            if found.gaps is None:
                found.gaps = []
            found.gaps.append(list(bounds))
            self._charge(conn, PIECE_OVERHEAD)

    # -- placing bytes --------------------------------------------------

    def _place(
        self,
        conn: _Conn,
        found: _Dir,
        bounds: tuple[int, int],
        data: bytes,
        work: _Work,
    ) -> None:
        """Compare a segment's bytes with what its direction holds; store them.

        :param conn: The connection.
        :param found: The segment's direction.
        :param bounds: The ``[start, end)`` its data declares.
        :param data: Its captured bytes, from ``start``.
        :param work: The segment.
        """
        start, end = bounds
        expected = found.next
        policy = self._policy_of(conn, work.segment.side)
        gathered = _Found()
        if start < expected:
            behind = (start, min(end, expected))
            self._behind(found, behind, (start, data), gathered)
        stored = False
        if end > expected:
            ahead = (max(start, expected), end)
            self._gather_ahead(found, ahead, (start, data), policy, gathered)
            stored = self._ahead(conn, found, ahead, (start, data), work)
        self._report(conn, (start, data), policy, gathered, expected, work)
        self._late(conn, found, (start, data), gathered.late, work)
        if stored and start > expected:
            segment = work.segment
            span = segment.origin.span(start, start + len(data))
            times = (segment.origin.timestamp, segment.origin.timestamp)
            work.own.append(
                OutOfOrder(
                    **_fields(conn.key, segment.side, [span], work.ref, times),
                    start=start,
                    end=end,
                    expected=expected,
                )
            )

    def _gather_ahead(
        self,
        found: _Dir,
        bounds: tuple[int, int],
        arriving: tuple[int, bytes],
        policy: OverlapPolicy,
        gathered: _Found,
    ) -> None:
        """Gather what a segment's bytes past the delivered end overlap.

        :param found: The segment's direction.
        :param bounds: The ``[low, high)`` it declares past the
            delivered end.
        :param arriving: Its first byte and captured bytes.
        :param policy: The receiver's policy.
        :param gathered: Where the overlaps are recorded.
        """
        low, high = bounds
        start, data = arriving
        captured = max(low, min(high, start + len(data)))
        held = found.held or []
        first, stop = _overlapping(held, low, high)
        for chunk in held[first:stop]:
            begin, end = max(chunk.start, low), min(chunk.end, captured)
            if begin < end and chunk.data is None:
                gathered.unverified.append((begin, end))
            elif begin < end:
                gathered.opponents.append(chunk.cut(begin, end))
                gathered.winners.append(policy is OverlapPolicy.LAST)
            begin, end = max(chunk.start, captured), min(chunk.end, high)
            if begin < end:
                gathered.unverified.append((begin, end))

    def _ahead(
        self,
        conn: _Conn,
        found: _Dir,
        bounds: tuple[int, int],
        arriving: tuple[int, bytes],
        work: _Work,
    ) -> bool:
        """Store a segment's bytes past the delivered end.

        Return whether anything of it was stored.

        :param conn: The connection.
        :param found: The segment's direction.
        :param bounds: The ``[low, high)`` it declares past the
            delivered end.
        :param arriving: Its first byte and captured bytes.
        :param work: The segment.
        """
        low, high = bounds
        start, data = arriving
        origin = work.segment.origin
        policy = self._policy_of(conn, work.segment.side)
        last = policy is OverlapPolicy.LAST
        captured = max(low, min(high, start + len(data)))
        held = found.held or []
        first, stop = _overlapping(held, low, high)
        before = held[first:stop]
        pieces = before
        if captured > low:
            chunk = data[low - start : captured - start]
            pieces = _stored(pieces, _Chunk(low, captured, chunk, origin), last)
        if high > captured:
            pieces = _stored(pieces, _Chunk(captured, high, None, origin), last)
        held[first:stop] = pieces
        found.held = held or None
        change = sum(map(_chunk_charge, pieces)) - sum(
            map(_chunk_charge, before)
        )
        self._charge(conn, change)
        return any(chunk.origin is origin for chunk in pieces)

    def _behind(
        self,
        found: _Dir,
        bounds: tuple[int, int],
        arriving: tuple[int, bytes],
        gathered: _Found,
    ) -> None:
        """Gather what a segment's bytes before the delivered end repeat.

        Retained bytes it overlaps are compared, ACKED gaps it fills are
        late, and every other declared byte is an unverified repeat.

        :param found: The segment's direction.
        :param bounds: The ``[low, high)`` it declares before the
            delivered end.
        :param arriving: Its first byte and captured bytes.
        :param gathered: Where the overlaps are recorded.
        """
        low, high = bounds
        start, data = arriving
        captured = min(high, start + len(data))
        covered: list[tuple[int, int]] = []
        runs = found.runs or []
        index = max(0, bisect.bisect_right(runs, low, key=_run_start) - 1)
        for run in itertools.takewhile(
            lambda run: run.start < captured, runs[index:]
        ):
            begin, end = max(low, run.start), min(captured, run.end)
            for chunk in run.chunks(begin, end) if begin < end else ():
                gathered.opponents.append(chunk)
                gathered.winners.append(False)
                covered.append((chunk.start, chunk.end))
        gaps = found.gaps or []
        index = max(0, bisect.bisect_right(gaps, low, key=_gap_start) - 1)
        for gap in itertools.takewhile(
            lambda gap: gap[0] < captured, gaps[index:]
        ):
            begin, end = max(low, gap[0]), min(captured, gap[1])
            if begin < end:
                gathered.late.append((begin, end))
                covered.append((begin, end))
        gathered.unverified.extend(_uncovered(low, high, covered))

    def _report(
        self,
        conn: _Conn,
        arriving: tuple[int, bytes],
        policy: OverlapPolicy,
        gathered: _Found,
        expected: int,
        work: _Work,
    ) -> None:
        """Report what a segment's bytes overlapped.

        Bytes that differ from a held or delivered version make one
        :class:`Overlap`; otherwise the repeated bytes make one
        :class:`Retransmission`, verified when every one of them was
        compared. Repeated bytes that could not be compared alongside an
        :class:`Overlap` make a ``Retransmission(verified=False)``.

        :param conn: The connection.
        :param arriving: The segment's first byte and captured bytes.
        :param policy: The receiver's policy.
        :param gathered: What it overlapped.
        :param expected: The delivered end before it arrived.
        :param work: The segment.
        """
        start, data = arriving
        origin = work.segment.origin
        pairs = sorted(
            zip(gathered.opponents, gathered.winners, strict=True),
            key=lambda pair: pair[0].start,
        )
        opponents = [chunk for chunk, _ in pairs]
        winners = [wins for _, wins in pairs]
        differing = _differing_ranges(opponents, start, data)
        unverified = gathered.unverified
        if differing:
            bounds = _hull(differing)
            whole = _Chunk(start, start + len(data), data, origin)
            kept, other, kept_spans, other_spans = _versions(
                opponents, winners, whole, bounds
            )
            spans = sorted(set(kept_spans) | set(other_spans))
            work.own.append(
                Overlap(
                    **_fields(
                        conn.key, work.segment.side, spans, work.ref, (0, 0)
                    ),
                    start=bounds[0],
                    end=bounds[1],
                    policy=policy,
                    kept=kept,
                    other=other,
                    kept_spans=tuple(kept_spans),
                    other_spans=tuple(other_spans),
                    resolved=True,
                    contrary=policy is OverlapPolicy.LAST
                    and differing[0][0] < expected,
                )
            )
            if unverified:
                self._repeat(conn, [], _hull(unverified), False, work)
            return
        ranges = [(chunk.start, chunk.end) for chunk in opponents] + unverified
        if ranges:
            self._repeat(conn, opponents, _hull(ranges), not unverified, work)

    def _repeat(
        self,
        conn: _Conn,
        opponents: list[_Chunk],
        bounds: tuple[int, int],
        verified: bool,
        work: _Work,
    ) -> None:
        """Append the :class:`Retransmission` of a segment.

        :param conn: The connection.
        :param opponents: The chunks whose bytes it repeated.
        :param bounds: The ``[start, end)`` repeated.
        :param verified: Whether every repeated byte was compared.
        :param work: The segment.
        """
        low, high = bounds
        spans = [
            chunk.origin.span(max(low, chunk.start), min(high, chunk.end))
            for chunk in opponents
        ]
        spans.append(work.segment.origin.span(low, high))
        work.own.append(
            Retransmission(
                **_fields(conn.key, work.segment.side, spans, work.ref, (0, 0)),
                start=low,
                end=high,
                verified=verified,
            )
        )

    def _late(
        self,
        conn: _Conn,
        found: _Dir,
        arriving: tuple[int, bytes],
        late: list[tuple[int, int]],
        work: _Work,
    ) -> None:
        """Deliver a segment's bytes for ACKED gaps as :class:`LateData`.

        The bytes join the retained ones, so a later repeat of them is
        compared.

        :param conn: The connection.
        :param found: The segment's direction.
        :param arriving: Its first byte and captured bytes.
        :param late: The ranges of ACKED gaps it fills.
        :param work: The segment.
        """
        start, data = arriving
        origin = work.segment.origin
        for low, high in late:
            piece = data[low - start : high - start]
            work.own.append(
                LateData(
                    **_fields(
                        conn.key,
                        work.segment.side,
                        [origin.span(low, high)],
                        work.ref,
                        (0, 0),
                    ),
                    offset=low,
                    data=piece,
                )
            )
            gaps = typing.cast(list[list[int]], found.gaps)
            index = bisect.bisect_right(gaps, low, key=_gap_start) - 1
            gap = gaps[index]
            remaining = [
                part
                for part in ([gap[0], low], [high, gap[1]])
                if part[0] < part[1]
            ]
            gaps[index : index + 1] = remaining
            self._charge(conn, (len(remaining) - 1) * PIECE_OVERHEAD)
            found.gaps = gaps or None
            self._retain(conn, found, low, piece, origin)

    # -- delivering bytes -------------------------------------------------

    def _deliver(
        self,
        conn: _Conn,
        found: _Dir,
        ref: int | None,
        out: list[StreamEvent],
        retain: bool,
    ) -> None:
        """Deliver the held chunks contiguous with a direction's delivered end.

        Contiguous bytes make one :class:`StreamData`; a range the
        capture cut makes a ``Gap(TRUNCATED)``. When delivery reaches the
        end a FIN fixed, the direction ends.

        :param conn: The connection.
        :param found: The direction.
        :param ref: The ``completing_ref`` of the events.
        :param out: Where the events are appended.
        :param retain: Whether the delivered bytes are retained.
        """
        held = found.held or []
        count = 0
        while count < len(held) and held[count].start == found.next:
            found.next = held[count].end
            count += 1
        taken = held[:count]
        del held[:count]
        found.held = held or None
        self._charge(conn, -sum(map(_chunk_charge, taken)))
        side = 0 if found is conn.a else 1
        index = 0
        while index < len(taken):
            stop = index
            cut = taken[index].data is None
            while stop < len(taken) and (taken[stop].data is None) == cut:
                stop += 1
            group = taken[index:stop]
            if cut:
                bounds = (group[0].start, group[-1].end)
                self._gap(conn, found, bounds, GapReason.TRUNCATED, ref, out)
            else:
                self._emit(conn, side, group, ref, out)
                for chunk in group if retain else ():
                    data = typing.cast(bytes, chunk.data)
                    self._retain(conn, found, chunk.start, data, chunk.origin)
            index = stop
        self._rearm(found)
        self._end_fin(conn, found, ref, out)

    def _emit(
        self,
        conn: _Conn,
        side: int,
        chunks: list[_Chunk],
        ref: int | None,
        out: list[StreamEvent],
    ) -> None:
        """Append the :class:`StreamData` of contiguous chunks.

        :param conn: The connection.
        :param side: The direction's side.
        :param chunks: The chunks, in order, every one holding bytes.
        :param ref: The ``completing_ref``.
        :param out: Where the event is appended.
        """
        spans = [chunk.origin.span(chunk.start, chunk.end) for chunk in chunks]
        out.append(
            StreamData(
                **_fields(conn.key, side, spans, ref, (0, 0)),
                offset=chunks[0].start,
                data=b"".join(
                    typing.cast(bytes, chunk.data) for chunk in chunks
                ),
            )
        )

    def _end_fin(
        self,
        conn: _Conn,
        found: _Dir,
        ref: int | None,
        out: list[StreamEvent],
    ) -> None:
        """End a direction whose delivery reached the end its FIN fixed.

        :param conn: The connection.
        :param found: The direction.
        :param ref: The ``completing_ref``.
        :param out: Where the :class:`StreamEnd` is appended.
        """
        fin = found.fin
        if fin is None or found.next < fin[0] or found.notes & _ENDED:
            return
        found.notes |= _ENDED
        side = 0 if found is conn.a else 1
        out.append(
            StreamEnd(
                **_fields(
                    conn.key, side, [fin[1].span(fin[0], fin[0])], ref, (0, 0)
                ),
                offset=fin[0],
                reason=EndReason.FIN,
            )
        )

    # -- retained bytes ---------------------------------------------------

    def _retain(
        self, conn: _Conn, found: _Dir, start: int, data: bytes, origin: _Origin
    ) -> None:
        """Add delivered bytes to a direction's retained runs.

        :param conn: The connection.
        :param found: The direction.
        :param start: The bytes' first offset.
        :param data: The bytes.
        :param origin: The frame that supplied them.
        """
        runs = found.runs
        if runs is None:
            runs = found.runs = []
        index = bisect.bisect_right(runs, start, key=_run_start)
        before = 0
        if index and runs[index - 1].end == start:
            run = runs[index - 1]
            before = run.charge()
            run.data += data
            run.starts.append(start)
            run.origins.append(origin)
        else:
            run = _Run(start, data, origin)
            runs.insert(index, run)
            index += 1
        if index < len(runs) and runs[index].start == run.end:
            after = runs.pop(index)
            before += after.charge()
            run.data += after.data
            run.starts += after.starts
            run.origins += after.origins
        self._charge(conn, run.charge() - before)

    def _retain_window(self, conn: _Conn, found: _Dir) -> None:
        """Trim a direction's retained bytes to its window.

        The window runs ``retain_bytes`` below the peer's highest
        acknowledgement, capped at the delivered end, or below the
        delivered end without one.

        :param conn: The connection.
        :param found: The direction.
        """
        anchor = found.next if found.ack is None else min(found.ack, found.next)
        self._trim(conn, found, anchor - self._bounds.retain_bytes)

    def _trim(self, conn: _Conn, found: _Dir, low: int) -> None:
        """Drop a direction's retained bytes before ``low``.

        The ACKED gaps it records are kept.

        :param conn: The connection.
        :param found: The direction.
        :param low: The first offset kept.
        """
        change = 0
        runs = found.runs or []
        count = 0
        while count < len(runs) and runs[count].end <= low:
            change -= runs[count].charge()
            count += 1
        del runs[:count]
        if runs and runs[0].start < low:
            change -= runs[0].charge()
            runs[0].trim(low)
            change += runs[0].charge()
        found.runs = runs or None
        self._charge(conn, change)

    def _shed(self, conn: _Conn, found: _Dir, excess: int) -> None:
        """Free ``excess`` bytes of a direction's retained state.

        Its oldest retained bytes go first, then its oldest ACKED gaps.
        A run that is cut drops at least an eighth of its bytes and is
        copied to a ``bytearray`` of its new size.

        :param conn: The connection.
        :param found: The direction.
        :param excess: The bytes to free.
        """
        while excess > 0 and found.runs:
            before = conn.charge
            run = found.runs[0]
            take = max(excess, len(run.data) >> 3)
            low = run.end if take >= len(run.data) else run.start + take
            self._trim(conn, found, low)
            if found.runs and found.runs[0] is run:
                charge = run.charge()
                run.data = bytearray(run.data)
                self._charge(conn, run.charge() - charge)
            excess -= before - conn.charge
        gaps = found.gaps or []
        count = min(len(gaps), max(0, -(-excess // PIECE_OVERHEAD)))
        del gaps[:count]
        found.gaps = gaps or None
        self._charge(conn, -count * PIECE_OVERHEAD)

    # -- bounds -----------------------------------------------------------

    def _enforce(self, conn: _Conn, work: _Work) -> None:
        """Enforce the caps once a segment is stored, and schedule its expiry.

        The connection first sheds its retained bytes, then forces its
        lowest holes out as ``Gap(CAP)``, until it fits under
        ``max_flow_bytes`` and ``max_total_bytes``; a connection that
        cannot is evicted. Then the least recently active connection
        not yet carrying data both ways, or else the least recently
        active one, is evicted until ``max_flows`` and
        ``max_total_bytes`` hold.

        :param conn: The segment's connection.
        :param work: The segment.
        """
        bounds = self._bounds
        cap = min(bounds.max_flow_bytes, bounds.max_total_bytes)
        if conn.charge > cap:
            self._squeeze(conn, cap, work)
        if conn.charge > cap:
            bound = Bound.MAX_TOTAL_BYTES
            if conn.charge > bounds.max_flow_bytes:
                bound = Bound.MAX_FLOW_BYTES
            self._evict(conn, bound, work.ref, work.suffix)
        while len(self._half) + len(self._full) > bounds.max_flows:
            self._evict_victim(Bound.MAX_FLOWS, conn, work)
        while self._total > bounds.max_total_bytes:
            self._evict_victim(Bound.MAX_TOTAL_BYTES, conn, work)
        if self._find(conn.key) is conn:
            self._schedule(conn)

    def _squeeze(self, conn: _Conn, cap: int, work: _Work) -> None:
        """Bring a connection under ``cap`` with its own data.

        Retained bytes go first, the segment's direction before the
        other; then each direction's lowest hole is declared a
        ``Gap(CAP)`` and the held bytes after it delivered.

        :param conn: The connection.
        :param cap: The charge it must fit under.
        :param work: The segment.
        """
        side = work.segment.side
        order = [
            found
            for _, found in sorted(
                conn.dirs(), key=lambda pair: pair[0] != side
            )
        ]
        for found in order:
            self._shed(conn, found, conn.charge - cap)
        for found in order:
            while conn.charge > cap and found.held:
                start = found.held[0].start
                bounds = (found.next, start)
                self._gap(
                    conn, found, bounds, GapReason.CAP, work.ref, work.own
                )
                found.next = start
                self._deliver(conn, found, work.ref, work.own, True)
                self._shed(conn, found, conn.charge - cap)

    def _evict_victim(self, bound: Bound, conn: _Conn, work: _Work) -> None:
        """Evict the connection a cap's eviction order picks.

        :param bound: The cap enforced.
        :param conn: The segment's connection, which carries its
            reference when it is the one evicted.
        :param work: The segment.
        """
        victim = next(iter((self._half or self._full).values()))
        if victim is conn:
            self._evict(conn, bound, work.ref, work.suffix)
        else:
            self._evict(victim, bound, None, work.events)

    def _evict(
        self,
        conn: _Conn,
        bound: Bound,
        ref: int | None,
        out: list[StreamEvent],
    ) -> None:
        """Flush a connection a bound evicts, ending with :class:`Evicted`.

        :param conn: The connection.
        :param bound: The cap enforced.
        :param ref: The ``completing_ref`` of its events.
        :param out: Where they are appended.
        """
        held = _held_bytes(conn)
        self._flush(conn, EndReason.EVICTED, ref, out)
        out.append(
            Evicted(
                **_fields(conn.key, None, [], ref, (conn.created, conn.last)),
                bound=bound,
                held_bytes=held,
                missing=(),
            )
        )

    def _flush(
        self,
        conn: _Conn,
        reason: EndReason,
        ref: int | None,
        out: list[StreamEvent],
    ) -> None:
        """Deliver everything a connection holds, end it, and remove it.

        Each hole becomes a ``Gap(FLUSH)``, up to the end a FIN fixed
        when there is one, and the held bytes are delivered; a direction
        whose FIN is then reached ends with ``StreamEnd(FIN)``, and every
        other open direction with ``StreamEnd(reason)``.

        :param conn: The connection.
        :param reason: Why it ends.
        :param ref: The ``completing_ref`` of its events.
        :param out: Where they are appended.
        """
        for side, found in conn.dirs():
            while found.held:
                start = found.held[0].start
                if start > found.next:
                    bounds = (found.next, start)
                    self._gap(conn, found, bounds, GapReason.FLUSH, ref, out)
                    found.next = start
                self._deliver(conn, found, ref, out, False)
            if found.fin is not None and found.fin[0] > found.next:
                bounds = (found.next, found.fin[0])
                self._gap(conn, found, bounds, GapReason.FLUSH, ref, out)
                found.next = found.fin[0]
                self._end_fin(conn, found, ref, out)
            if found.started:
                found.notes |= _ENDED
                out.append(
                    StreamEnd(
                        **_fields(
                            conn.key, side, [], ref, (conn.created, conn.last)
                        ),
                        offset=found.next,
                        reason=reason,
                    )
                )
        self._remove(conn)


def _run_start(run: _Run) -> int:
    """Return where a retained run starts.

    :param run: The run.
    """
    return run.start


def _gap_start(gap: list[int]) -> int:
    """Return where a recorded ACKED gap starts.

    :param gap: The gap, as ``[start, end]``.
    """
    return gap[0]


def _chunk_start(chunk: _Chunk) -> int:
    """Return where a held chunk starts.

    :param chunk: The chunk.
    """
    return chunk.start


def _overlapping(held: list[_Chunk], low: int, high: int) -> tuple[int, int]:
    """Return where the held chunks ``[low, high)`` overlaps are.

    :param held: A direction's held chunks, in order.
    :param low: The first byte.
    :param high: One past the last.
    :returns: The index of the first chunk overlapped and one past the
        last; with no overlap, the index a chunk at ``low`` takes, twice.
    """
    first = bisect.bisect_right(held, low, key=_chunk_start) - 1
    if first < 0 or held[first].end <= low:
        first += 1
    stop = first
    while stop < len(held) and held[stop].start < high:
        stop += 1
    return first, stop


def _shifted(value: int | None, delta: int) -> int | None:
    """Return an offset moved by ``delta``, or ``None`` before offset 0.

    :param value: The offset, or ``None``.
    :param delta: The move.
    """
    if value is None or value + delta < 0:
        return None
    return value + delta


def _stream_policy(value: object) -> bool:
    """Return whether ``value`` is a policy :class:`StreamReassembler` offers.

    :param value: The policy argument.
    """
    return isinstance(value, OverlapPolicy) and value in _STREAM_POLICIES
