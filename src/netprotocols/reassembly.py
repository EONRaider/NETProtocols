"""Reassembly of IPv4 and IPv6 fragments into whole datagrams.

:class:`FragmentReassembler` takes each decoded
:class:`~netprotocols.packet.Packet` together with the frame it was
decoded from, its capture timestamp and a reference the caller picks
(a frame index), and returns the events that frame caused. It is the
library's only stateful decoder: :func:`~netprotocols.decode_frame` and
every ``decode()`` stay per-frame, and this module is reached as
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

**Clock.** Every call to :meth:`FragmentReassembler.feed`, whether or
not its packet holds a fragment, and every call to
:meth:`FragmentReassembler.advance` moves the capture clock to its
timestamp, unless that is 0 or lower than the clock, and returns the
expiries that causes.

**Events.** Every event is a frozen, slotted, keyword-only dataclass
naming the frames that contributed to it as :class:`Span` values, and
the frame whose own fragment caused it as ``completing_ref``.
:data:`FragmentEvent` is the union of the event types this module
returns. Each call to :meth:`FragmentReassembler.feed` returns, in
order: the expiries the frame's timestamp triggers in other datagrams,
in deadline order; the evictions of other datagrams that storing its
data requires, oldest first; then the events of its own datagram, in
the order of the datagram offset each concerns, ending with the
:class:`Datagram`, :class:`Evicted` or discarding event that ends it.
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
dropped, as Linux drops it, and none of its bytes is stored.

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
import typing
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import NamedTuple

from netprotocols.checksum import internet_checksum
from netprotocols.flow import FlowKey
from netprotocols.layer3.ip import IPv4, IPv6
from netprotocols.layer3.ipv6_ext import (
    IPv6Fragment,
    IPv6Routing,
    _effective_destination,
)
from netprotocols.packet import Packet

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
    "Evicted",
    "Expired",
    "FragmentBounds",
    "FragmentEvent",
    "FragmentKey",
    "FragmentReassembler",
    "FragmentTarget",
    "Overlap",
    "OverlapPolicy",
    "Retransmission",
    "Span",
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
    """The direction of an event relative to its flow key."""

    #: From ``addr_a``/``port_a`` to ``addr_b``/``port_b``.
    A_TO_B = "a_to_b"
    #: From ``addr_b``/``port_b`` to ``addr_a``/``port_a``.
    B_TO_A = "b_to_a"


class Bound(enum.Enum):
    """The cap whose limit an :class:`Evicted` event enforced."""

    #: The charged bytes of one datagram.
    MAX_FLOW_BYTES = "max_flow_bytes"
    #: The charged bytes of the reassembler.
    MAX_TOTAL_BYTES = "max_total_bytes"
    #: The datagrams held at once.
    MAX_FLOWS = "max_flows"
    #: The pieces one datagram holds.
    MAX_FRAGMENTS = "max_fragments"


class Timeout(enum.Enum):
    """The timeout an :class:`Expired` event enforced."""

    #: Measured from the datagram's latest fragment.
    IDLE = "idle"
    #: Measured from the datagram's first-arriving fragment.
    AGE = "age"


class AnomalyKind(enum.Enum):
    """A rule a fragment breaks, or an evasion pattern it matches."""

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
    #: An IPv4 header checksum that does not verify.
    BAD_CHECKSUM = "bad_checksum"
    #: A bad checksum taken as one a NIC was left to fill.
    CHECKSUM_OFFLOAD = "checksum_offload"
    #: A fragment whose IP header declares a length of 0.
    UNVERIFIED_CHECKSUM = "unverified_checksum"
    #: A TTL or Hop Limit other than the first-arriving fragment's.
    HOP_LIMIT_CHANGED = "hop_limit_changed"
    #: A Fragment Next Header other than the first-arriving fragment's.
    NEXT_HEADER_CHANGED = "next_header_changed"
    #: An IPv4 datagram completed more than 30 seconds after its first
    #: fragment, which a Linux target has discarded.
    SLOW_REASSEMBLY = "slow_reassembly"


class ChecksumMode(enum.Enum):
    """What a fragment with a bad IPv4 header checksum does."""

    #: The fragment is dropped.
    DROP = "drop"
    #: The fragment is used.
    KEEP = "keep"
    #: A checksum of 0, which Windows leaves for its NIC to fill, is
    #: taken as offloaded and the fragment used, with
    #: :attr:`AnomalyKind.CHECKSUM_OFFLOAD`, from a source in ``local``
    #: (from any source when ``local`` is not given); any other bad
    #: checksum is dropped.
    AUTO = "auto"


class Span(NamedTuple):
    """The bytes one frame supplied to an event.

    :param ref: The frame's reference, as passed to
        :meth:`FragmentReassembler.feed`.
    :param start: The first byte the frame supplied, as an offset into
        the reassembled payload.
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

    :param flows: The datagrams in progress.
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
class _Event:
    """The fields every reassembly event has.

    :param flow: The datagram's :class:`FragmentKey`, or a
        :class:`~netprotocols.flow.FlowKey`.
    :param direction: The direction relative to a flow key's
        ``addr_a``; ``None`` for fragments.
    :param spans: The contributing frames, sorted by ``start`` then
        ``ref``.
    :param completing_ref: The reference of the fed frame whose own
        fragment caused the event; ``None`` when an expiry, the
        eviction of a datagram to make room for another,
        :meth:`FragmentReassembler.advance` or
        :meth:`FragmentReassembler.close` caused it.
    :param first_timestamp: The earliest ``timestamp`` among ``spans``;
        with no spans, that of the datagram's first-arriving fragment.
    :param last_timestamp: The latest ``timestamp`` among ``spans``;
        with no spans, the latest of the datagram's fragments.
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
    """Arriving bytes that overlap held bytes and differ from them.

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

    :param start: The range's first byte, as a payload offset.
    :param end: One past its last byte.
    :param policy: The :class:`OverlapPolicy` applied;
        :attr:`OverlapPolicy.DISCARD` for IPv6.
    :param kept: The range's bytes as kept.
    :param other: The range's other version.
    :param kept_spans: The frames that supplied ``kept``, tiling it.
    :param other_spans: The frames that supplied ``other``, tiling it.
    :param resolved: ``False`` when the datagram was discarded.
    :param contrary: Always ``False`` for fragments.
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
    """Arriving bytes that repeat held bytes exactly.

    :param start: The first repeated byte, as a payload offset.
    :param end: One past the last.
    :param verified: Whether the bytes were compared; always ``True``
        for fragments.
    """

    start: int
    end: int
    verified: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class Evicted(_Event):
    """A datagram a bound discarded.

    :param bound: The cap enforced.
    :param held_bytes: The data bytes the datagram held.
    :param missing: The ranges of the payload no span covers, as
        ``(start, end)`` pairs; the last ``end`` is ``None`` when the
        last fragment never arrived.
    """

    bound: Bound
    held_bytes: int
    missing: tuple[tuple[int, int | None], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Expired(_Event):
    """A datagram a timeout, or :meth:`FragmentReassembler.close`, discarded.

    :param timeout: The timeout whose deadline came first.
    :param held_bytes: The data bytes the datagram held.
    :param missing: The ranges of the payload no span covers, as for
        :class:`Evicted`.
    """

    timeout: Timeout
    held_bytes: int
    missing: tuple[tuple[int, int | None], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class Anomaly(_Event):
    """A fragment that breaks a rule or matches an evasion pattern.

    :param kind: The rule.
    :param start: The first byte concerned, as a payload offset.
    :param end: One past the last.
    """

    kind: AnomalyKind
    start: int
    end: int


#: Every event type :class:`FragmentReassembler` returns.
FragmentEvent = (
    Datagram | Overlap | Retransmission | Evicted | Expired | Anomaly
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
    """How an arriving fragment changes its datagram's pieces."""

    first: int
    last: int
    pieces: list[_Piece]
    event: FragmentEvent | None
    discard: bool


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
        if flow.end is not None and flow.covered == flow.end:
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
            return _Plan(first, last, overlapped, event, False)
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
        if linux_duplicate or not data:
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
