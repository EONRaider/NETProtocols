Design note: reassembly of IP fragments and TCP streams
=======================================================

This note specifies the design of ``netprotocols.reassembly``, the
opt-in, stateful module for issue
`#373 <https://github.com/EONRaider/NETProtocols/issues/373>`__. It
specifies the public API, the bounds and their defaults, fragment and
stream reassembly, the response to each known evasion, the documents
that change, the test plan and the split into pull requests. It
describes a module that does not exist yet. Each design decision is
marked **Decision**, with the options weighed, the accepted one and
its trade-off, and :ref:`reassembly-decisions` lists them all.

.. contents::
   :local:
   :depth: 1


Constraints
-----------

These come from the maintainer's decisions on #373 and are not open
here.

- The module is separate. :func:`netprotocols.decode_frame` and every
  ``decode()`` stay per-frame and stateless, so the decode contract,
  ``bytes(decode(x)) == x[:header_len]``, is untouched, and the change
  is new public API: a minor release.
- IPv4 fragments and TCP segments that overlap are resolved by a
  policy chosen per target, in the Snort/Suricata style, defaulting to
  ``first``. Overlapping IPv6 fragments are always discarded
  (`RFC 5722 §4 <https://www.rfc-editor.org/rfc/rfc5722.html#section-4>`__,
  as corrected by
  `erratum 3089 <https://www.rfc-editor.org/errata/eid3089>`__).
  An overlap whose bytes differ is always reported as an event, under
  every policy, and never resolved silently: that is the insertion and
  evasion class of
  `Ptacek & Newsham (1998) <https://insecure.org/stf/secnet_ids/secnet_ids.html>`__.
- Every bound is measured on capture timestamps
  (:class:`netprotocols.pcap.CapturedFrame`'s ``timestamp``, in
  nanoseconds), never on the wall clock, so a replay of the same
  capture produces the same events.
- Every output event names the frame that completed it and every frame
  that contributed to it. RootWire attaches each reassembled message
  to its completing frame.
- Fragment reassembly ships first. TCP stream reassembly follows and
  reuses the bounds, the frame references and the event types the
  fragment step establishes.

The module reassembles IPv4 and IPv6 datagrams and TCP byte streams,
and nothing above them: SCTP user messages (RFC 9260 §6.9), TLS
handshake messages split across records, and the TFTP transfer state
of ARCHITECTURE's port-dispatch section stay the caller's.


1. Public API
-------------

1.1 Input: a decoded packet and its frame
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A :class:`netprotocols.packet.Packet` holds the layers the walk
decoded, and ``bytes(packet)`` is their encoding. For TCP that is the
header only. ``HTTP``'s ``header_len`` covers its whole message and
``TLS``'s its whole record, so a packet can hold application bytes, but
only a unit a decoder accepted whole: a partial message or record
stops the walk. A non-first fragment's data gets no layer at all, since
:meth:`netprotocols.IPv4.next_protocol` gives it no class. The bytes no
decoder read are
``frame[packet.consumed : len(frame) - len(packet.trailer)]``. A packet
alone therefore cannot be reassembled, and the reassemblers take the
packet *and* the frame it was decoded from::

    events = reassembler.feed(packet, frame, timestamp=ts, ref=index)

The reassembler finds the layers it needs in ``packet.layers`` and
slices their payload out of ``frame``. A layer's offset in the frame is
the sum of the ``header_len`` of the layers before it, and the end of
the payload is the end the IP header declares (Total Length, or Payload
Length), clamped to ``len(frame) - len(packet.trailer)``. When the IP
header declares a length of 0 (a TSO capture), the end is the frame's
end less the trailer, as :attr:`netprotocols.packet.Packet.trailer`
already computes it.

**Decision: the input type.** There are three possible shapes.

.. list-table::
   :header-rows: 1
   :widths: 22 39 39

   * - Input
     - For
     - Against
   * - Raw frame only
     - Simplest call; the module controls the walk.
     - Every caller that also needs the packet decodes each frame
       twice. The module enters the decode path: it must take
       ``start``, ``registry``, ``decode_as`` and ``lax`` and keep them
       in step with ``decode_frame``.
   * - ``Packet`` only
     - One decode; the module never calls a decoder.
     - Does not work: a fragment's data and a segment's payload are
       in the packet only where a decoder accepted them whole.
   * - ``Packet`` and frame (accepted)
     - One decode, done by the caller with whatever ``start``,
       registry and ``lax`` it uses. The module never calls a decoder
       on input, so it stays out of the decode path and is
       independent of the link type.
     - Two arguments that must belong together. A mismatched pair
       is a caller error the module can detect only partly (below).

*Accepted:* the packet and the frame. Reassembly needs the
payload, which only the frame holds, and needs the header fields,
which only the decode yields; taking both costs nothing and avoids the
second decode RootWire would otherwise pay on every frame.

``feed`` raises :class:`ValueError` when ``len(frame)`` is shorter than
``packet.consumed + len(packet.trailer)``, the one mismatch it can
detect without re-decoding. A packet built by hand rather than by
``decode_frame`` is accepted on the same terms.

1.2 Reassembler objects
~~~~~~~~~~~~~~~~~~~~~~~

Two classes, one per step, sharing the bounds, frame references and
event types:

.. code-block:: python

    class FragmentReassembler:
        def __init__(
            self,
            *,
            bounds: FragmentBounds = FragmentBounds(),
            policy: OverlapPolicy = OverlapPolicy.FIRST,
            targets: Mapping[str, OverlapPolicy] | None = None,
            checksums: ChecksumMode = ChecksumMode.AUTO,
            local: Iterable[str] | None = None,
        ) -> None: ...

        def feed(
            self,
            packet: Packet,
            frame: bytes | memoryview,
            *,
            timestamp: int,
            ref: int | None = None,
        ) -> tuple[FragmentEvent, ...]: ...

        def advance(self, timestamp: int) -> tuple[FragmentEvent, ...]: ...

        def close(self) -> tuple[FragmentEvent, ...]: ...

        @property
        def usage(self) -> Usage: ...

``StreamReassembler`` has the same four methods and the same
arguments, takes ``StreamBounds`` and returns ``StreamEvent``.
``StreamBounds`` holds the stream timeouts, among them
``ack_gap_grace`` (decision 15, section 2.5).

- ``feed`` takes one frame and returns, in a fixed order, every event
  that frame caused: first the expiries its timestamp triggers in
  other flows (section 2.4), in deadline order; then the evictions of
  other flows that storing its data requires (section 2.3), in
  eviction order, each flow's events together; then the events of its
  own flow in stream or datagram offset order. A frame the reassembler
  does not apply to still moves the capture clock, and returns only the
  expiries its timestamp triggers (``()`` when there are none): for
  ``FragmentReassembler``, a packet none of whose IP headers is a
  fragment; for
  ``StreamReassembler``, a packet with no TCP layer, or whose TCP
  layer is inside an IP fragment (a first fragment's TCP header is
  decoded by the walk but its payload is partial; the caller feeds the
  reassembled datagram instead, section 1.6).
- ``advance(timestamp)`` moves the capture clock without a frame and
  returns the expiries it causes. A live caller calls it when a
  capture is idle.
- ``close()`` ends the capture: every flow is flushed as if it had
  expired (section 2.3) and the reassembler is empty afterwards.
- ``usage`` is a ``Usage(flows, bytes)`` named tuple of what is held,
  in the units the bounds charge (section 2.1).

Draining is synchronous: events are returned by the call that causes
them and never queued inside the reassembler, so held state is exactly
the flows and their pieces. A reassembler is not thread-safe; a caller
shards by key if it needs parallelism.

``targets`` maps networks, written as ``ipaddress`` accepts them
(``"10.0.0.0/8"``, ``"2001:db8::/32"``, a bare address), to the policy
of the hosts in them, as Suricata's
`host-os-policy <https://docs.suricata.io/en/latest/configuration/suricata-yaml.html#host-os-policy>`__
does. The policy that applies is the longest prefix containing the
*receiver*: a datagram's destination, or the receiving end of a TCP
direction. Behind an IPv6 Routing header with segments left, the
Destination Address is the next hop, not the receiver (RFC 8200 §8.1),
so the receiver is :meth:`netprotocols.IPv6Routing.final_destination`,
as :func:`netprotocols.flow.flow_key` resolves it. No match means
``policy``. The constructor raises
:class:`ValueError` for an unparsable network, and for a policy a
reassembler does not offer (``StreamReassembler`` offers a subset,
section 4.5).

1.3 Frame references
~~~~~~~~~~~~~~~~~~~~

Every event refers to frames by the ``ref`` the caller passed with
them. Object identity is never used: packets are values, and two equal
frames are distinct frames. ``ref=None`` means the reassembler's own
count of frames fed so far, starting at 0, which equals the frame index
of a caller that feeds every frame of a capture in order.

Each contributing frame appears as a ``Span``, a named tuple:

.. code-block:: python

    class Span(NamedTuple):
        ref: int
        start: int      # first byte this frame supplied
        end: int        # one past the last byte, half-open
        timestamp: int  # the frame's capture time, in nanoseconds
        hop_limit: int  # the IPv4 TTL or IPv6 Hop Limit it arrived with

``start`` and ``end`` are offsets into the reassembled datagram's
payload, or into the direction's byte stream. A span covers the bytes
that frame supplied *after* overlap resolution, so the spans of an
event tile its data exactly: a caller can map any byte range of a
reassembled message back to frames N..M without the module knowing
where messages begin. The hop limit is there because TTL-based
insertion (section 5) shows up as overlapping spans whose hop limits
differ.

**Decision: the type of a reference.** An ``int`` or an opaque,
caller-chosen token (a type parameter, ``FragmentReassembler[R]``).

*Accepted:* ``int``. It is what RootWire and every pcap reader
have (a frame index), it is totally ordered, so "frames N..M" and
sorting spans mean something, it costs a small integer per span, and it
keeps the classes non-generic. *Trade-off:* a caller whose frames are
identified by something else (a ring-buffer slot, a database key)
keeps its own mapping from the integer it passes.

1.4 Event types
~~~~~~~~~~~~~~~

Every event is a frozen, slotted dataclass, as
:class:`netprotocols.TCPOption` and the other non-layer values with
structure are, and is also keyword-only, which they are not. Not a
named tuple: two different event types with equal
fields must not compare equal, which tuples would, and dataclasses give
``match`` class patterns. ``Span``, ``Usage`` and ``FragmentKey`` are
named tuples, like :class:`netprotocols.flow.FlowKey`: small values
with no behaviour.

Fields every event has:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Field
     - Meaning
   * - ``flow``
     - ``FragmentKey`` (section 3.1) or :class:`netprotocols.flow.FlowKey`.
   * - ``direction``
     - ``Direction.A_TO_B`` or ``Direction.B_TO_A`` relative to the
       flow key's ``addr_a``/``port_a``; ``None`` for fragments.
   * - ``spans``
     - The contributing frames, as ``Span`` (section 1.3), sorted by
       ``start`` then ``ref``.
   * - ``completing_ref``
     - The ``ref`` of the fed frame whose own fragment or segment
       caused the event (below); ``None`` when a timeout, the eviction
       of a flow, ``advance`` or ``close`` caused it.
   * - ``first_timestamp``, ``last_timestamp``
     - The earliest and latest ``timestamp`` among ``spans``.

``refs`` is a property: the sorted, distinct refs of ``spans``.

``completing_ref`` has one definition for every event type. It is the
``ref`` of the frame passed to ``feed`` when that frame's fragment or
segment caused the event in its own flow: the fragment that filled a
datagram's last hole (``Datagram``), the segment that made a run
contiguous with the delivered end, that pushed its own direction past
``max_flow_bytes``, or that confirmed the ACK-based gap before it
(section 4.7) (``StreamData``, ``Gap``),
the fragment that pushed its own datagram past ``max_flow_bytes`` or
``max_fragments``, or past ``max_total_bytes`` on its own, or whose own
datagram is evicted as the oldest to make room under
``max_total_bytes`` or ``max_flows`` (``Evicted``), and the arriving
piece of an
``Overlap``, ``Retransmission``, ``OutOfOrder``, ``LateData`` or
``Anomaly``. It is ``None`` for every event a flush produces: an
expiry, the eviction of another flow to make room (``max_total_bytes``,
``max_flows``), ``advance`` and ``close``; the exception is the flush
a SYN confirms (decision 12, section 4.4), which carries the SYN's
ref. A
``feed`` that triggers an expiry or eviction in another flow therefore
returns that flow's events with ``None``, never with its own ref. A
message decoded from a direction's runs (section 4.8) takes the
``completing_ref`` of the run that holds its last byte; when that is
``None``, no frame completed the message, and its frames are still the
spans of its runs.

The event types:

.. list-table::
   :header-rows: 1
   :widths: 18 32 50

   * - Type
     - Emitted when
     - Further fields
   * - ``Datagram``
     - The last missing fragment of a datagram arrives.
     - ``version`` (4 or 6), ``data`` (the whole datagram, header
       included, section 3.6), ``payload_offset``, ``header_ref`` (the
       first fragment's ref).
   * - ``StreamData``
     - Bytes of a direction become contiguous with what it has
       delivered (section 4.7).
     - ``offset`` (stream offset of ``data[0]``), ``data``.
   * - ``StreamEnd``
     - A direction ends: its FIN is reached, an RST, an expiry, an
       eviction, or ``close()``.
     - ``offset`` (the stream's final offset), ``reason``
       (``EndReason``).
   * - ``Overlap``
     - Bytes of an arriving fragment or segment overlap held or
       delivered bytes and differ from them; or, under a rule that
       discards a datagram on overlap (IPv6, and the ``discard`` and
       ``linux-discard`` policies, section 3.4), overlap them other
       than as a duplicate the rule allows, equal or not.
     - ``start``, ``end``, ``policy`` (the ``OverlapPolicy`` applied),
       ``kept`` and ``other`` (the two versions of the range),
       ``kept_spans`` and ``other_spans``, ``resolved`` (``False``
       when the datagram is discarded), ``contrary`` (section 4.6).
   * - ``Retransmission``
     - Arriving bytes repeat held or delivered bytes exactly, under a
       rule that keeps the datagram or stream going (section 3.3), or
       repeat delivered bytes the reassembler no longer retains.
     - ``start``, ``end``, ``verified`` (``False`` when the bytes
       could not be compared).
   * - ``OutOfOrder``
     - A TCP segment arrives beyond the next expected stream offset
       and is held.
     - ``start``, ``end``, ``expected``.
   * - ``Gap``
     - A TCP direction skips bytes it never received: a cap forced it,
       the capture truncated them, the flow is being flushed, or the
       peer acknowledged past them (section 4.7).
     - ``start``, ``end``, ``reason`` (``GapReason``).
   * - ``LateData``
     - Bytes arrive for the range of a gap already declared on an
       acknowledgement (section 4.7).
     - ``offset`` (stream offset of ``data[0]``), ``data``; its
       ``spans`` tile ``data``, and it is outside the ordered runs.
   * - ``Evicted``
     - A bound removed state (section 2.3).
     - ``bound`` (``Bound``), ``held_bytes``, ``missing`` (the holes
       of a discarded datagram, as ``(start, end)`` pairs).
   * - ``Expired``
     - A timeout removed state (section 2.4).
     - ``timeout`` (``Timeout.IDLE`` or ``Timeout.AGE``),
       ``held_bytes``, ``missing``.
   * - ``Anomaly``
     - A fragment or segment breaks a rule or matches an evasion
       pattern (sections 3 to 5).
     - ``kind`` (``AnomalyKind``), ``start``, ``end``.

``FragmentEvent`` and ``StreamEvent`` are the unions of the types each
reassembler can return, so a ``match`` over them type-checks as
exhaustive under ``mypy --strict`` with ``typing.assert_never``.
``OverlapPolicy``, ``Direction``, ``EndReason``, ``GapReason``,
``Bound``, ``Timeout``, ``AnomalyKind`` and ``ChecksumMode`` are
``enum.Enum`` classes with string values, as
:class:`netprotocols.HTTPAnomalyKind` is; ``OverlapPolicy``'s values are
frag3's policy-type spellings (``"first"``, ``"bsd"``, ...), which
Suricata's defrag engine uses internally; Suricata's
``host-os-policy`` keys are operating-system names instead
(``hpux11``, ``old-linux``, ...).

``Overlap`` events are bounded: one per fed frame and flow, covering
the smallest range that holds every differing byte (every overlapping
byte, under a discarding rule), with ``kept`` and
``other`` the full contents of that range. A frame overlapping many
held pieces yields one event, not one per piece, so the event volume
an attacker can cause is linear in the frames sent.

1.5 Errors
~~~~~~~~~~

Hostile, malformed and inconsistent input never raises: it produces
events. ``feed``, ``advance`` and ``close`` raise only for misuse of the
API:

- :class:`TypeError` for an argument of the wrong type, such as a
  ``ref`` that is not an ``int``, or a ``frame`` that is not bytes;
- :class:`ValueError` for a ``frame`` too short for its ``packet``
  (section 1.1), for a negative ``timestamp``, and for invalid bounds,
  networks or policies at construction.

None of them is a :class:`netprotocols.ProtocolError`, which names
bytes a decoder rejected. A packet whose walk stopped early
(``stopped_by`` set) is processed as far as its layers go.

1.6 Use
~~~~~~~

The reassembled datagram is decoded with the existing walk, and a TCP
segment rebuilt from fragments is fed to the stream reassembler like
any other packet, with the completing frame's ref:

.. code-block:: python

    from netprotocols import IPv4, IPv6, decode_frame
    from netprotocols.pcap import read_pcap
    from netprotocols.reassembly import (
        Datagram,
        FragmentReassembler,
        StreamReassembler,
    )

    fragments = FragmentReassembler()
    streams = StreamReassembler()
    for index, captured in enumerate(read_pcap(buffer)):
        packet = decode_frame(captured.data, lax=True)
        frame, ts = captured.data, captured.timestamp
        for event in fragments.feed(packet, frame, timestamp=ts, ref=index):
            handle((event,))
            if isinstance(event, Datagram):
                start = IPv4 if event.version == 4 else IPv6
                data = event.data
                whole = decode_frame(data, start=start, lax=True)
                handle(streams.feed(whole, data, timestamp=ts, ref=index))
        handle(streams.feed(packet, frame, timestamp=ts, ref=index))
    handle(fragments.close() + streams.close())

The ``Datagram`` event is handled before the stream events its
datagram causes, and maps the ref those events carry (``index``, the
``Datagram``'s ``completing_ref``) to every fragment frame. Every call
passes ``ref``: the default counts ``feed`` calls (section 1.3), so a
re-fed datagram would shift it for every later frame. A tunnelled
datagram (IP in IP, GRE) whose outer header is fragmented is handled
the same way: the reassembler acts on the outermost IP header that is
a fragment, and the caller feeds the rebuilt datagram back to reach
the inner one. The module is imported as ``netprotocols.reassembly``;
see section 6.4 for why the package does not re-export it.


2. Bounds
---------

Bounds are part of the API: each has a documented default, a
documented eviction, and an event.

2.1 What is charged
~~~~~~~~~~~~~~~~~~~

Each flow (a datagram in progress, or a TCP connection) is charged
``FLOW_OVERHEAD`` bytes, and each stored piece (a fragment, a held
segment, a retained delivered run) is charged its data length plus
``PIECE_OVERHEAD``. A fragment's declared range that is kept with no
captured byte in it (a fragment the snap length cut to its header,
under a rule that decides overlaps on declared ranges, section 3.3) is
charged ``PIECE_OVERHEAD`` and counts against ``max_fragments`` like a
piece. The two constants are module-level and are fixed
in the fragment pull request by measuring CPython's actual allocation
per flow and per piece with ``tracemalloc``; the test in section 7.4
holds them to it. The figures below assume the expected order of
magnitude, 1 KiB per flow and 256 bytes per piece. Charging overhead
per piece is what makes a flood of one-byte segments or eight-byte
fragments cost what it really costs.

2.2 Caps
~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 22 20 58

   * - Cap
     - Applies to
     - Meaning
   * - ``max_flow_bytes``
     - one flow
     - Charged bytes one datagram, or one TCP connection (both
       directions), may hold.
   * - ``max_total_bytes``
     - the reassembler
     - Charged bytes across all flows.
   * - ``max_flows``
     - the reassembler
     - Flows held at once.
   * - ``max_fragments``
     - one datagram
     - Fragments one datagram may hold (fragments only).
   * - ``retain_bytes``
     - one TCP direction
     - Delivered bytes kept to compare retransmissions against
       (streams only, section 4.6).

2.3 Eviction
~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 18 30 52

   * - Bound reached
     - Which state goes
     - What happens to its data
   * - ``max_flow_bytes``, ``max_fragments`` (fragments)
     - The datagram that exceeded it.
     - Discarded. ``Evicted`` carries the spans of the held fragments
       and the missing ranges; no partial datagram is emitted. A
       datagram that cannot fit under the cap cannot complete, and a
       partial one cannot be decoded as a datagram.
   * - ``max_flow_bytes`` (streams)
     - The held data of the direction that exceeded it, from its
       lowest hole.
     - Not discarded: the lowest hole is declared a ``Gap`` (reason
       ``CAP``), the held bytes after it are delivered as
       ``StreamData``, and this repeats until the flow is under the
       cap. Retained delivered bytes are trimmed first. The flow
       stays open. Data already captured is never silently dropped.
   * - ``max_total_bytes``, ``max_flows``
     - Fragments: the oldest datagram by first-fragment time (the
       order is a decision, below). Streams:
       the least recently active flow among those not yet carrying data
       in both directions (half-open, or one-sided), and if there is
       none, the least recently active flow.
     - Fragments: discarded, as above. Streams: the held data is
       flushed as for ``close()``: each hole becomes a ``Gap`` (reason
       ``FLUSH``), held bytes are delivered, then ``StreamEnd``
       (reason ``EVICTED``) for each open direction, then
       ``Evicted``.

Every event of an evicted flow carries ``completing_ref=None``
(section 1.4). Ties in age are broken by feed order, so eviction is
deterministic. The cap is enforced before the arriving frame's data is
stored: the reassembler evicts until the new piece fits, and a piece
larger than ``max_flow_bytes`` on its own is reported as ``Evicted``
immediately. After every call, ``usage.bytes <= max_total_bytes`` and
``usage.flows <= max_flows``.

Preferring half-open TCP flows as victims means a SYN flood evicts its
own flows before an established, idle one (a BGP session between
keepalives). The preference is bypassed by a flood that spoofs both
directions of each flow, which makes every flooded flow two-sided; the
caps still hold, and the victims are then the least recently active
flows. An evicted TCP flow that sends again is picked up
mid-stream (section 4.2), with an ``Anomaly`` saying so, so an attacker
who floods to flush a flow's state does not make the rest of that flow
invisible.

**Decision: the fragment eviction order.** When
``max_total_bytes`` or ``max_flows`` is reached, a datagram in progress
must go, or the arriving one must be refused.

- *Oldest first* (by first-fragment time): simple and deterministic,
  and a datagram that has waited longest is the likeliest never to
  complete. A flood of new datagrams evicts every legitimate datagram
  still in progress, since each flooded one is younger.
- *Refuse the arriving datagram*: datagrams in progress survive a
  flood, but while the reassembler is full no new datagram, legitimate
  or not, is reassembled until something expires.
- *Largest source first*: evict from the source address holding the
  most charged bytes, which isolates one flooding source. A flood from
  spoofed sources defeats it, and the bookkeeping is a per-source
  count.

*Accepted:* oldest first. Every eviction is an ``Evicted`` event
with the spans and holes, so a flood that pushes out legitimate
datagrams is visible, and the age timeout already removes old
datagrams in the same order. *Trade-off:* the one stated above: under
a flood the legitimate datagrams in progress are the victims.

2.4 Timeouts
~~~~~~~~~~~~

The reassembler keeps a capture clock: the highest timestamp it has
been given by ``feed`` or ``advance``. Every timeout compares a flow's
times with that clock.

- The *idle* timeout runs from the flow's last frame.
- The *age* timeout runs from its first frame.

A frame whose timestamp is lower than the clock (captures merged from
several interfaces, a clock stepped back) is processed normally and
recorded with its own timestamp in its spans, but never moves the
clock back, and never makes a flow's last-activity time earlier. Expiry
is checked at the start of each ``feed`` and ``advance``, for every flow
whose deadline is at or before the clock, in deadline order (ties by
feed order). A frame with timestamp 0, as from a pcapng Simple Packet
Block, never advances the clock: such a capture expires nothing, and
only the caps bound it.

On expiry, a datagram is discarded (``Expired`` with its spans and
missing ranges); a TCP flow is flushed as on eviction, with
``StreamEnd`` reason ``IDLE`` or ``AGE`` and then ``Expired``. Every
event of an expiry carries ``completing_ref=None``.

2.5 Defaults
~~~~~~~~~~~~

Timeouts are integers in nanoseconds, the unit of
``CapturedFrame.timestamp``; ``SECOND = 1_000_000_000`` is exported to
write them.

.. list-table:: ``FragmentBounds`` defaults
   :header-rows: 1
   :widths: 24 18 58

   * - Bound
     - Default
     - Justification
   * - Datagram size
     - 65,535 bytes (fixed)
     - Not a setting: the protocol maximum. An IPv4 Total Length is 16
       bits and includes the header
       (`RFC 791 §3.1 <https://www.rfc-editor.org/rfc/rfc791.html#section-3.1>`__);
       an IPv6 reassembled Payload Length may not exceed 65,535
       (`RFC 8200 §4.5 <https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5>`__),
       and a jumbogram cannot carry a Fragment header
       (`RFC 2675 §3 <https://www.rfc-editor.org/rfc/rfc2675.html#section-3>`__).
       A fragment past the limit is an ``Anomaly`` (section 3.5).
   * - ``max_flow_bytes``
     - 65,535 + 60 + ``max_fragments`` × ``PIECE_OVERHEAD`` +
       ``FLOW_OVERHEAD``
     - One maximal datagram, its largest IPv4 header, and the overhead
       of a full fragment count: a valid datagram never hits it.
       Settable lower.
   * - ``max_fragments``
     - 128
     - A 65,535-byte IPv4 datagram cut into 576-byte fragments takes
       119 fragments of 552 data bytes; over IPv6's 1,280-byte minimum
       MTU, 54 of 1,232. 576 octets is the datagram every host must accept
       (RFC 791 §3.1), not the smallest MTU: every module must forward
       68 octets unfragmented
       (`RFC 791 §3.2 <https://www.rfc-editor.org/rfc/rfc791.html#section-3.2>`__),
       and a maximal datagram over a 68-byte MTU legally takes 1,365
       fragments of 48 data bytes. The cap drops a maximal datagram
       cut for an MTU under 532 bytes, which is rare, in exchange for
       bounding the tiny-fragment flood of section 5.
   * - ``max_total_bytes``
     - 32 MiB
     - Suricata's default defrag memcap. With the overheads of section
       2.1 it holds about 330 maximal datagrams at once (each at
       ``max_flow_bytes``) to 430 (each in 45 fragments for a 1,500-byte
       link), or over 5,000 typical ones, such as a 4,096-byte EDNS
       response cut for a 1,500-byte link.
   * - ``max_flows``
     - 16,384
     - At about 1.3 KiB for the smallest datagram in progress (one
       eight-byte fragment and the overheads), 32 MiB would admit some
       26,000; the lower flow cap binds first under a flood of
       single-fragment datagrams and bounds the expiry scan.
   * - idle timeout
     - none
     - RFC 8200 §4.5 times reassembly from the first-arriving
       fragment, which the age timeout does.
       `RFC 1122 §3.3.2 <https://www.rfc-editor.org/rfc/rfc1122.html#page-56>`__
       requires a reassembly timeout without saying where it starts.
   * - age timeout
     - 60 s, both versions
     - RFC 8200 §4.5: 60 seconds from the first-arriving fragment.
       RFC 1122 §3.3.2 recommends 60 to 120 seconds; Suricata's
       default is 60. Linux uses 30 seconds for IPv4
       (``IP_FRAG_TIME`` in
       `include/net/ip.h <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/ip.h>`__)
       and 60 for IPv6; see the decision below.
   * - ``local`` (constructor argument)
     - ``None``
     - The capture host's addresses (decision 16), from which the
       offload checksum pattern is accepted; ``None`` accepts it from
       any source (section 5.1).

.. list-table:: ``StreamBounds`` defaults
   :header-rows: 1
   :widths: 24 18 58

   * - Bound
     - Default
     - Justification
   * - ``max_flow_bytes``
     - 4 MiB
     - 2 MiB per direction of held out-of-order data and retained
       bytes. Data is held only past a hole, and a sender can have at
       most a window in flight past it; 2 MiB is about the
       bandwidth-delay product of 1 Gbit/s at 16 ms, a full window on
       most LAN and Internet paths, though far below RFC 7323's 1 GiB
       maximum
       (`§2.3 <https://www.rfc-editor.org/rfc/rfc7323.html#section-2.3>`__).
       A larger hole becomes a ``Gap``, not lost memory.
   * - ``retain_bytes``
     - 64 KiB per direction
     - The largest unscaled window
       (`RFC 9293 §3.1 <https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1>`__).
       A scaled window, which ``max_flow_bytes`` assumes up to 2 MiB,
       lets a retransmission repeat data further back; a repeat older
       than ``retain_bytes`` is reported unverified, which is a
       decision (section 4.6).
   * - ``max_total_bytes``
     - 128 MiB
     - 32 flows at their full per-flow cap at once. Half of
       Suricata's ``stream.reassembly.memcap`` (256 MiB), which is sized
       for a sensor; a desktop analyzer process stays well under 1 GiB
       with the overhead measured in section 7.4.
   * - ``max_flows``
     - 65,536
     - Empty flows alone are then charged 64 MiB at a 1 KiB
       ``FLOW_OVERHEAD``, half the byte cap, so a SYN flood cannot take
       the whole budget either way. Suricata's ``flow.hash-size`` is
       also 65,536, but it counts hash buckets, not flows; Suricata
       bounds flows by ``flow.memcap``.
   * - idle timeout, new
     - 60 s
     - A flow that has not carried data in both directions. Suricata's
       ``flow-timeouts.tcp.new``. Bounds a half-open flood in time as
       the caps bound it in space.
   * - idle timeout, established
     - 3,600 s
     - Six times Suricata's ``flow-timeouts.tcp.established`` (600 s).
       An analyzer keeps a connection that idles for minutes (a
       database pool, an SSH session) rather than end it and pick it
       up again mid-stream; the caps bound what idle flows hold.
   * - idle timeout, closed
     - 120 s
     - After FIN in both directions, or RST. One Maximum Segment
       Lifetime (RFC 9293 §3.4.2 takes it as 2 minutes), long enough to
       see late retransmissions and the data after an RST of section
       4.4. Suricata's ``flow-timeouts.tcp.closed`` is 60 s.
   * - age timeout
     - none
     - See below.
   * - ``ack_gap_grace``
     - 1 s
     - How long a hole must stay open after the first ACK past it
       before it is declared a gap (decision 15, section 4.7). Long
       enough for the reordering of a merged or multi-queue capture,
       short against the stall it replaces.
   * - ``local`` (constructor argument)
     - ``None``
     - As for fragments (decision 16).

The Suricata figures are the defaults in the
`suricata.yaml.in <https://raw.githubusercontent.com/OISF/suricata/master/suricata.yaml.in>`__
Suricata ships: ``defrag.memcap`` 32 MiB, ``defrag.timeout`` 60,
``flow-timeouts.tcp`` ``new`` 60, ``established`` 600 and ``closed``
60, ``stream.reassembly.memcap`` 256 MiB and ``stream.midstream``
false. The example on the
`configuration page <https://docs.suricata.io/en/latest/configuration/suricata-yaml.html#ip-defrag>`__
shows other figures for the timeouts.

**Decision: fragment timeouts per target, or one global
timeout.** Linux expires an IPv4 datagram after 30 seconds and an IPv6
one after 60. With one 60-second age timeout, the observer completes an
IPv4 datagram whose last fragment arrives 30 to 60 seconds after its
first, which a Linux target has already discarded: an insertion.

- *One global age timeout* (60 s, both versions): the simplest
  setting, and RFC 8200's figure, but it silently disagrees with Linux
  IPv4 targets.
- *Per version*: an IPv4 and an IPv6 default (30 s and 60 s, Linux's
  figures). It matches Linux for both, and expires IPv4 datagrams
  earlier than RFC 1122's 60 to 120 seconds for every other target.
- *Per target*: ``targets`` maps a network to its policy and its
  fragment timeouts, as Suricata's ``defrag.host-config`` sets a
  timeout per network; the global value applies elsewhere. ``targets``
  then takes a small record instead of a bare ``OverlapPolicy``.
- *Global, with a report*: one 60-second timeout, and an
  ``Anomaly(SLOW_REASSEMBLY)`` on a datagram that completes more than
  30 seconds after its first fragment, so the caller sees the cases a
  Linux target dropped.

*Accepted:* per target, with a global default of 60 s for both
versions, and the ``SLOW_REASSEMBLY`` anomaly for IPv4 under the
default. It keeps RFC 8200's figure where the target is unknown, lets
a caller who knows its Linux hosts emulate them, and never leaves the
30-to-60-second window silent. *Trade-off:* a richer ``targets`` value
and one more anomaly kind; a caller who configures nothing still
completes datagrams a Linux IPv4 target dropped, though each is
reported.

**Decision: a total-age timeout for TCP.** *Accepted:*
none by default, settable. A BGP session or a database connection
lives for days; an age cutoff would end it with a ``StreamEnd`` and
pick it up again mid-stream, which is noise. Delivered bytes are not
held (only ``retain_bytes`` of them), so a long-lived flow costs no
more memory than a short one, and the idle timeout and caps already
bound what a flow holds. *Trade-off:* a flow that trickles one byte
inside every idle period is never expired by time; the flow cap and
eviction order still bound how many such flows exist.


3. Fragment reassembly
----------------------

3.1 Keys
~~~~~~~~

``FragmentKey(version, src, dst, protocol, identification)``:

- IPv4: source, destination, protocol and Identification, the four
  fields RFC 791 reassembles on
  (`§2.3 <https://www.rfc-editor.org/rfc/rfc791.html#section-2.3>`__).
- IPv6: source, destination and the Fragment header's Identification
  (RFC 8200 §4.5), with ``protocol`` ``None``. The Fragment header's
  Next Header is not part of the key; fragments that disagree on it
  produce an ``Anomaly`` and the first fragment's value is used
  (section 3.6).

Addresses are the strings :class:`netprotocols.IPv4` and
:class:`netprotocols.IPv6` decode, as ``FlowKey``'s are. The key is
directional: a datagram is reassembled by its receiver, and the
destination selects the policy.

3.2 Which fragments are taken
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An IPv4 header is a fragment when its MF flag is set or its Fragment
Offset is not 0. An IPv6 packet is a fragment when an
:class:`netprotocols.IPv6Fragment` header follows its IPv6 header
before any further IP header, with M set or a nonzero offset. The
fragment's data runs from the end of that header to the declared end
of the IP packet.

An IPv6 *atomic fragment*, offset 0 and M 0, is processed in isolation,
as `RFC 6946 §4 <https://www.rfc-editor.org/rfc/rfc6946.html#section-4>`__
requires: it creates no state, is never combined with fragments of the
same key, and returns no event, since ``decode_frame`` already walks
past its Fragment header to the whole payload. An IPv4 header with MF
clear and offset 0 is not a fragment and returns nothing either.

3.3 Overlaps
~~~~~~~~~~~~

Arriving data that overlaps held data is compared byte for byte.

- *Identical bytes, IPv4* (an exact duplicate, or a partial overlap
  whose bytes agree) produce ``Retransmission`` (``verified=True``) and
  change nothing, unless the policy discards on that overlap
  (``discard``, ``linux-discard``, section 3.4): then it is handled as
  the IPv6 case below.
- *Exact duplicate, IPv6* (same offset, length and bytes): the same.
  RFC 8200 §4.5 allows exact duplicates to be dropped rather than
  treated as overlaps.
- *Differing bytes, IPv4*: the target's policy decides which version
  each byte keeps, and an ``Overlap`` event reports the range, both
  versions and both sets of spans. The datagram goes on, unless the
  policy discards on that overlap: then ``Overlap(resolved=False)`` and
  the datagram is abandoned, as for IPv6.
- *Any other overlap, IPv6*, whether or not the bytes differ: the
  datagram is abandoned. ``Overlap`` (``resolved=False``) reports it,
  with ``kept`` and ``other`` equal when the bytes agree, and the held
  fragments and the key's state are dropped.

The IPv6 rule is RFC 5722's and is fixed, but it is not Linux's. Linux
inserts IPv6 fragments with the same ``inet_frag_queue_insert`` as
IPv4 (`net/ipv4/inet_fragment.c`_), which returns ``IPFRAG_DUP`` for a
fragment contained in a run of held contiguous fragments: the fragment
is dropped without comparing its bytes and the datagram is kept. A
contained fragment with differing bytes therefore makes the observer
discard a datagram a Linux target delivers, the evasion decision 7
names for IPv4. It is reported as the ``Overlap(resolved=False)``; the
held bytes are lost to the caller with the datagram.

.. _net/ipv4/inet_fragment.c: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/inet_fragment.c

After a discard the reassembler keeps nothing for the key: a later
fragment with the same key starts a new datagram, which completes if
its fragments do. RFC 5722 §4 as published also discarded constituent
fragments "not yet received"; verified erratum 3089 removed those words
as not implementable, since honouring them means keeping state per key
for a Maximum Segment Lifetime, a resource-exhaustion vector of its
own. RFC 8200 §4.5 discards "all the fragments that have been received
for that packet", and Linux keeps no state once it kills a queue
(``inet_frag_kill`` in
`net/ipv6/reassembly.c <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/reassembly.c>`__).
An observer that refused later fragments would drop a datagram the
target delivers, after one overlapping pair and a clean train under the
same Identification: an evasion. No anomaly marks the new datagram,
since that would need the per-key state back; the earlier ``Overlap``
carries the same ``flow``, so a caller can correlate the two. The same
holds for an IPv4 datagram discarded by the ``discard`` policy or any
other rule of section 3.5.

Policies resolve overlaps when a fragment arrives, against the held
fragments it overlaps, so held state is always one non-overlapping
version of each byte plus the spans that supplied it.

The rules that discard on overlap (IPv6, ``discard`` and
``linux-discard``) judge overlap on the fragments' declared ranges,
the offset and length their headers give, not on the bytes a capture
holds: a fragment the snap length cut still overlaps where its header
says it does. Under IPv6 and ``discard``, an exact duplicate has the
same declared range as a held fragment and equal bytes wherever both
were captured, and it supplies the bytes the held fragment's capture
lacks. Under ``linux-discard`` a fragment inside one run is a duplicate
whatever its range within the run, and it is dropped, as Linux drops
it: the held bytes stand, and none of its bytes is stored. Linux
records the end a dropped last fragment declares (``ip_frag_queue``
sets ``INET_FRAG_LAST_IN`` and the length before
``inet_frag_queue_insert`` returns ``IPFRAG_DUP``) but checks for
completion only after a fragment it inserts, so the duplicate completes
nothing; a later fragment that fills a remaining hole completes the
datagram.

3.4 Named policies
~~~~~~~~~~~~~~~~~~

The names are the policy types of Snort's frag3, which the
`Snort manual <http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node17.html>`__
credits to Shankar and Paxson's
`Active Mapping <https://www.icir.org/vern/papers/activemap-oak03.pdf>`__
(2003). Suricata's defrag engine implements the same set
(`src/defrag.c <https://raw.githubusercontent.com/OISF/suricata/master/src/defrag.c>`__),
and its ``DefragSturgesNovak*`` unit tests give the reassembled bytes of
one overlapping fragment pattern under each policy, which serve as the
reference vectors (section 7.2). "Held" is a fragment already stored;
"arriving" is the one being fed.

.. list-table::
   :header-rows: 1
   :widths: 13 47 40

   * - Policy
     - Which bytes win an overlap
     - Targets in frag3's table
   * - ``first``
     - Held, always.
     - HP-UX 11.00, Mac OS, SunOS 5.5.1 to 5.8 (Solaris 2.5.1 to 8)
   * - ``last``
     - Arriving, always.
     - Cisco IOS
   * - ``bsd``
     - Held, where the held fragment begins at or before the arriving
       one; arriving, where the held fragment begins after it.
     - AIX 2 and 4.3, FreeBSD, HP-UX B.10.20, IRIX 4.0.5F to 6.4, NCD
       thin clients, OpenVMS 7.1, OS/2, OSF/1 V3.0 to V5.1, SunOS
       4.1.4, Tru64 V5.0A and V5.1, VAX/VMS
   * - ``bsd-right``
     - A variant of ``bsd`` that favours the arriving fragment in
       overlaps at a held fragment's right end.
     - HP JetDirect printers
   * - ``linux``
     - As ``bsd``, except that the arriving fragment also wins over a
       held one that begins at the same offset.
     - Linux 2.2 and 2.4, OpenBSD
   * - ``windows``
     - Held, except over a held fragment the arriving one begins before
       and ends after, which the arriving one replaces.
     - Windows 95, 98, NT 4, 2000 and XP
   * - ``solaris``
     - Held, except over a held fragment the arriving one begins before
       and ends at or after the end of, which the arriving one
       replaces.
     - None; Suricata maps its ``solaris`` host-os-policy key to it,
       and its ``old-solaris`` key to ``first``

These model stacks measured before 2005. ``linux`` is Linux before
commit
`7969e5c40dfd <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7969e5c40dfd04799d4341f1b7cd266b6e47f227>`__
(August 2018), including stable kernels before its backport. That
commit makes Linux discard an IPv4 datagram on any overlap, as RFC 5722
requires for IPv6, exact duplicates included. Commit
`ade446403bfb <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ade446403bfb79d3528d56071a84b15351a139ad>`__
(December 2018) then drops a fragment contained in a run of fragments
already held as a duplicate, without comparing its bytes, and keeps
the datagram; only a partial overlap still discards it. In both cases
Linux keeps no state for the key afterwards. A kernel version does not
say which rule a host has, since both commits were backported to the
stable series. The ``ip_fragment.c`` (and, for the third column,
``reassembly.c``) of each stable tag shows:

.. list-table::
   :header-rows: 1
   :widths: 16 28 28 28

   * - Series
     - Overlap discards (7969e5c40dfd) from
     - Contained fragment kept (ade446403bfb) from
     - Empty fragment discards the queue (0ff89efb5246, 2475f59c618e)
       from
   * - Mainline
     - 4.19
     - 4.20
     - 4.20
   * - 4.19
     - 4.19
     - 4.19.14
     - 4.19.37
   * - 4.14
     - 4.14.71
     - 4.14.92
     - 4.14.114
   * - 4.9
     - 4.9.134
     - 4.9.149
     - 4.9.172
   * - 4.4
     - 4.4.174
     - 4.4.174
     - never (4.4.302, the last, drops only the fragment)

The third column is decision 8's empty-fragment rule: commit
`0ff89efb5246 <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0ff89efb524631ac9901b81446b453c29711c376>`__
for IPv4 and
`2475f59c618e <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=2475f59c618ea58e9f72ae5ded2db392ee47810d>`__
for IPv6, both 2018, with the same stable tags for both files. Before
them, both versions drop only the empty fragment (``goto err``), so a
kernel with both overlap commits, 4.19.14 to 4.19.36 or 4.14.92 to
4.14.113 for example, still keeps the datagram.

The ``discard`` policy, the IPv6 path applied to IPv4, discards on
every overlap but an exact duplicate. It matches neither Linux rule
exactly: the kernels with only the first commit discard on exact
duplicates too, and current kernels keep contained fragments.

**Decision: which named policies to offer.** *Accepted:*
for IPv4 fragments, ``first`` (the default), ``last``, ``bsd``,
``linux``, ``windows``, ``solaris`` and ``discard``; not ``bsd-right``.
The current-Linux policy is the next decision.

- The six frag3 policies other than ``bsd-right`` cover every
  general-purpose operating system frag3 lists, and Suricata's unit
  tests give one fragment pattern with the expected output under each,
  so each costs one table row in the tests (section 7.2), not a
  separate design.
- ``discard`` costs nothing beyond the IPv6 path already required, and
  models a stack that applies RFC 5722's rule, with its exact-duplicate
  allowance, to IPv4.
- ``bsd-right`` models one printer family, and its rule is the least
  well documented of the set: Suricata accepts the name but its
  reassembly has no case for it, and its exact behaviour would have to
  be established by testing a JetDirect, which no netns script can do.
  Adding it later is one more enum value, with no API change.

*Trade-off:* a caller who must emulate an HP JetDirect, or a stack not
on the list, gets the nearest policy and still sees every disagreement
as an ``Overlap`` event. The policies describe historical stacks, so
the guarantee that matters is the event, not the emulation; ``discard``
models no stack cited here, only the RFC's rule.

**Decision: a policy for current Linux.** No policy above
models Linux with commit ade446403bfb: ``linux`` is its behaviour
before 7969e5c40dfd, and ``discard`` discards a datagram over a
contained fragment with differing bytes, which current Linux drops as
a duplicate while keeping the datagram.

- *Add* ``linux-discard``, named by its rule, not by a kernel
  version: a partial overlap discards the datagram, with
  ``Overlap(resolved=False)`` even when the bytes agree, and a fragment
  contained in a run of held contiguous fragments is dropped, the held
  bytes winning, with an ``Overlap`` when its bytes differ. The
  reassembler compares the bytes Linux does not, so the event is still
  emitted.
- *Rely on* ``discard``: one policy fewer, but it disagrees with
  current Linux on contained fragments with differing bytes, where the
  observer drops a datagram the target delivers: an evasion, visible
  only as the ``Overlap``.
- *Neither*: the default ``first`` agrees with current Linux on
  contained fragments and disagrees on partial overlaps, where the
  observer completes a datagram the target discarded.

Two more Linux behaviours change an outcome, and ``linux-discard``
does not model them. When more than ``ipfrag_max_dist`` (default 64)
fragments from the same source address arrive between two fragments
of one IPv4 queue, ``ip_frag_too_far`` makes Linux drop the queue's
held fragments and start it again, so an attacker who interleaves
fragments can make Linux lose part of a datagram the observer still
completes: an insertion. And a fragment that still
finds a completed queue (``INET_FRAG_COMPLETE``) is dropped as a
duplicate; here, as in Linux once the queue is gone, a late fragment
starts a new datagram that expires.

*Accepted:* add ``linux-discard``. Linux is a common target in
the captures this library reads, its rule is fixed by two cited
commits, and its reference vectors can come from a netns capture
against the running kernel. *Trade-off:* a caller must know which rule
a host runs, which its kernel's series and patch level give (table
above), not its major version; kernels between the two commits are
modelled by neither policy; ``ipfrag_max_dist`` is not emulated; and
the rule depends on Linux's run structure, so a later kernel change
needs a new value, not a changed one.

3.5 Rules applied to each fragment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The response to each rule is *discard* (the fragment, or the datagram,
as a receiver must) or *report* (an ``Anomaly``, and the fragment is
used). Every discard also emits its ``Anomaly``. For three rules
receivers disagree on what is discarded, and the response is a
decision (below the table).

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Condition
     - Response
     - Source
   * - Fragment would end past 65,535 bytes. IPv4: header + offset × 8
       + data length, the Total Length. IPv6: the Per-Fragment headers
       after the 40-byte IPv6 header + offset × 8 + data length, the
       reassembled Payload Length, which excludes the IPv6 header.
     - ``Anomaly(OVERSIZE)``, whose spans are the fragments held and
       the arriving one: the "ping of death". The fragment or the
       datagram is discarded, per the decision below.
     - RFC 791 §3.1; RFC 8200 §4.5
   * - IPv6 fragment with M set whose data length is not a multiple
       of 8.
     - ``Anomaly(MISALIGNED)``; the fragment or the datagram is
       discarded, per the decision below.
     - RFC 8200 §4.5
   * - IPv4 fragment with MF set whose data length is not a multiple
       of 8.
     - ``Anomaly(MISALIGNED)``, then per the decision below. No
       conforming fragmenter produces it, since every non-final
       fragment ends on an 8-octet boundary, but RFC 791 sets no rule
       for a receiver that gets one.
     - RFC 791 §2.3
   * - Last fragment (MF/M clear) disagrees with an end already known,
       or data lies past a known end.
     - Discard the datagram, ``Anomaly(INCONSISTENT_END)``. The
       datagram has no single length.
     -
   * - Fragment with no data.
     - ``Anomaly(EMPTY_FRAGMENT)``; the fragment or the datagram is
       discarded, per the decision below.
     -
   * - IPv6 first fragment that does not hold the whole header chain
       through the upper-layer header: for TCP its whole header,
       options included, as its Data Offset gives it (at least 20
       bytes); 8 bytes for UDP and ICMPv6, as Linux checks; none for No
       Next Header; 1 byte for any other. A first fragment the snap
       length cut is not judged by this rule.
     - Discard the fragment, ``Anomaly(INCOMPLETE_HEADER_CHAIN)``.
     - RFC 8200 §4.5;
       `RFC 7112 §5 <https://www.rfc-editor.org/rfc/rfc7112.html#section-5>`__
   * - IPv4 first fragment of TCP (or UDP) too short to hold the
       transport header (20 bytes for TCP, 8 for UDP).
     - Report, ``Anomaly(TINY_FRAGMENT)``: the tiny-fragment attack.
     - `RFC 1858 §3 <https://www.rfc-editor.org/rfc/rfc1858.html#section-3>`__
   * - IPv4 fragment of TCP at offset 1 (8 bytes), which can overwrite
       the TCP flags.
     - Report, ``Anomaly(TCP_OFFSET_ONE)``, and resolve by policy.
     - RFC 1858 §4;
       `RFC 3128 <https://www.rfc-editor.org/rfc/rfc3128.html>`__
   * - Captured bytes shorter than the declared length (snap length).
     - Store what was captured; the rest is a hole the datagram cannot
       fill. ``Anomaly(TRUNCATED)``.
     -
   * - Bad IPv4 header checksum.
     - Per ``checksums`` (section 5.1): discard the fragment, or keep
       it; ``Anomaly(BAD_CHECKSUM)`` either way.
     - RFC 1122 §3.2.1.2
   * - Fragments of one datagram arriving with different TTL or Hop
       Limit, or different IPv6 Fragment Next Header.
     - Report, ``Anomaly(HOP_LIMIT_CHANGED)`` or
       ``Anomaly(NEXT_HEADER_CHANGED)``.
     - Section 5

Reporting rather than discarding the tiny and offset-one fragments is
deliberate: the reassembler observes; whether the target dropped them
is not visible in a capture, and RFC 1858's rules are filtering
advice for routers, not receiver requirements.

**Decision: what OVERSIZE, MISALIGNED and EMPTY_FRAGMENT
discard.** Receivers differ:

- RFC 8200 §4.5 discards only the offending IPv6 fragment, for an
  oversize or a misaligned one; the datagram can still complete.
- Current Linux (`net/ipv6/reassembly.c`_, `net/ipv4/ip_fragment.c`_)
  kills the whole queue for an IPv6 oversize or misaligned fragment,
  for an empty fragment of either version (since the two commits in
  the third column of section 3.4's table; earlier kernels drop only
  the empty fragment), and for an IPv4 datagram whose
  reassembled length exceeds 65,535. For a misaligned IPv4 fragment
  it truncates the data to a multiple of 8 (``end &= ~7``) and keeps
  the fragment, discarding the queue only if nothing is left.

.. _net/ipv6/reassembly.c: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/reassembly.c
.. _net/ipv4/ip_fragment.c: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_fragment.c

The options, for each of the three rules:

- *Fragment*: discard the offending fragment only. RFC 8200's rule;
  an observer that follows it completes datagrams a Linux target
  discarded (an insertion).
- *Datagram*: discard every held fragment. Linux's rule for most
  cases; an observer that follows it drops datagrams an RFC-following
  target completes after a valid replacement fragment (an evasion).
- *Truncate and keep*, for a misaligned IPv4 fragment only: Linux's
  rule. An observer that discards it misses datagrams Linux completes.
- *By policy*: Linux's rules for an IPv4 receiver whose policy is
  ``linux-discard``, another choice elsewhere. IPv6 has no per-target
  policy, so this applies to IPv4 only.

*Accepted:* for IPv6, *fragment* for OVERSIZE and MISALIGNED,
following RFC 8200's text, and *datagram* for EMPTY_FRAGMENT, which
the RFC does not cover. For IPv4, *truncate and keep* for MISALIGNED,
the only receiver behaviour cited here, and *datagram* for OVERSIZE,
whatever the policy; for EMPTY_FRAGMENT, *by policy*: *datagram* under
``linux-discard``, *fragment* elsewhere. ``linux-discard`` thereby
models kernels with all three commits of section 3.4's table; on a
kernel with the overlap commits but not the empty-fragment one, it
discards a datagram the target keeps after an empty fragment, which
the ``EMPTY_FRAGMENT`` anomaly reports. *Trade-off:* no choice
matches every target, so the guarantee is the ``Anomaly``: each case
is reported whatever was discarded. Following the RFC for IPv6 means
disagreeing with Linux there.

3.6 The reassembled datagram
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A ``Datagram`` holds the whole datagram, so a caller decodes it with
``decode_frame(event.data, start=IPv4)`` (or ``IPv6``) and the existing
decoders, checksums included.

- IPv4: the header is the first fragment's (offset 0), options
  included, since the first fragment carries every option and later
  fragments only those with the copied flag (RFC 791 §3.1). Total
  Length is set to the reassembled length, MF is cleared, Fragment
  Offset is set to 0, DF and the reserved bit are kept as the first
  fragment had them, and the Header Checksum is recomputed. TTL,
  Identification and the rest are the first fragment's.
- IPv6: the Per-Fragment headers (RFC 8200's term; RFC 2460 called
  them the Unfragmentable Part) are the first fragment's headers up to
  the Fragment header; the Next Header of their last header is set to
  the Fragment header's Next Header; the Fragment header is removed;
  and Payload Length is recomputed, all as RFC 8200 §4.5 specifies. A
  Fragment header later fragments carry differently is not used.

``payload_offset`` is where the reassembled payload starts in ``data``:
the length of the IPv4 header, or of the IPv6 Per-Fragment headers,
which RFC 8200 defines as the IPv6 header plus the extension headers
before the Fragment header. It is not called ``header_len``: for IPv6
it differs from ``IPv6.header_len``, which is always 40, since the
library decodes each extension header as a layer of its own.

**Decision: a synthesized header, or the payload only.** The
datagram's header is new bytes: no captured frame holds it. The decode
contract still holds for it, as for any input: for IPv4,
``bytes(IPv4.decode(event.data)) == event.data[:event.payload_offset]``,
since any valid header round-trips; for IPv6, the ``header_len`` of
the ``IPv6`` layer and of the layers ``decode_frame`` yields for the
Per-Fragment headers sum to ``payload_offset``. Extension headers
that were in the fragmentable part, such as Destination Options for
the final receiver, start at ``payload_offset``. What
does not hold is any equality with a captured header: re-encoding the
first fragment's decoded IPv4 header gives the first fragment's bytes,
which differ in Total Length, flags, offset and checksum.
The alternative is to emit the reassembled payload plus the first
fragment's header as captured, and let the caller build a header.

*Accepted:* the synthesized header, with ``header_ref`` naming
the frame it came from, and the rules above documented on the event.
It is what a receiving stack hands up, it decodes with the existing
walk and no glue, and it gives the checksum helpers a header whose
length covers the whole message, which ARCHITECTURE's checksum section
requires for a message reassembled from IPv6 fragments. *Trade-off:*
the event's bytes are not wire bytes, and a caller that diffs output
against the capture must know which fields were rewritten: Total
Length, the flags, Fragment Offset and Header Checksum for IPv4; for
IPv6 the last Per-Fragment header's Next Header and the Payload
Length, with the Fragment header removed. The
original header is one ``header_ref`` lookup away.


4. TCP streams
--------------

4.1 Flow identity and direction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A TCP connection is keyed by :func:`netprotocols.flow.flow_key` of the
packet's first TCP layer and the IP header nearest before it, the rule
:meth:`netprotocols.packet.Packet.flow_key` applies to the first
transport layer, so tunnels and IPv6 Routing headers key as they do
there. Each connection holds two directions; a segment's direction is
``A_TO_B`` when its ``(ip.src, tcp.src_port)`` equals the key's
``(addr_a, port_a)``, ``B_TO_A`` otherwise. A connection from an
endpoint to itself on the same port (the LAND pattern) has one
direction by construction and is reported as
``Anomaly(SELF_CONNECTED)``.

A key's connection ends when both directions have ended or it expires;
a SYN for a key whose connection has ended, or whose directions are
closed, starts a new connection under the same key. What an RST does,
including what a SYN or data after it does and where the offsets of
any new connection start, is decision 12 (section 4.4). A caller
therefore treats a
``StreamEnd`` as the end of that connection's runs: later
``StreamData`` under the same ``flow`` belongs to a new connection.

4.2 Stream offsets and mid-stream pickup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each direction numbers its bytes from 0. With a SYN seen, offset 0 is
the byte at sequence ISN + 1 (the SYN occupies ISN,
`RFC 9293 §3.4 <https://www.rfc-editor.org/rfc/rfc9293.html#section-3.4>`__).
Without one, the first segment carrying data in that direction sets
offset 0 at its sequence number, and an ``Anomaly(MIDSTREAM)`` is
emitted once for the direction. A segment that then arrives with data
before offset 0 cannot be placed and is dropped with
``Anomaly(BEFORE_STREAM_START)``.

**Decision: pick up mid-stream by default.** *Accepted:*
yes. Captures routinely start inside connections, and an analyzer that
shows nothing for them is wrong in a way the user cannot see; the
anomaly says the stream's start is unknown. *Trade-off:* the opposite
of Suricata's default (``stream.midstream: false``). A sensor refuses
mid-stream pickup because an attacker can fabricate a connection with
no handshake; here the anomaly carries that information to the caller,
who may ignore such streams.

4.3 Sequence-number wraparound and PAWS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Offsets are unbounded Python integers. A segment's 32-bit sequence
number is mapped to the offset nearest the direction's next expected
offset whose value modulo 2\ :sup:`32` matches, which is the
serial-number comparison of RFC 9293 §3.4 and
`RFC 1982 <https://www.rfc-editor.org/rfc/rfc1982.html>`__: any segment
within 2\ :sup:`31` bytes of the expected point is placed correctly
across a wrap. Since a direction holds at most ``max_flow_bytes`` of
undelivered data, every segment the reassembler can store is far
inside that range.

PAWS (`RFC 7323 §5 <https://www.rfc-editor.org/rfc/rfc7323.html#section-5>`__)
rejects a segment whose timestamp is older than the last one accepted,
to protect against an old duplicate from a previous wrap being
accepted as current.

**Decision: implement PAWS.** *Accepted:* no. A stale
segment can pass for current data only when its direction's sequence
space wraps within the segment's lifetime: 2\ :sup:`32` bytes inside
one Maximum Segment Lifetime, about 290 Mbit/s sustained with RFC
9293's 2-minute MSL. Even then the serial-number mapping places the
stale segment behind the delivered end, where it is compared with the
retained bytes, or ahead of it, where it is held and the current data
for the same bytes later overlaps it; either way a difference is
reported, never delivered silently. And a passive observer applying
PAWS where the target does not, or the reverse, is itself an ambiguity
(section 5). *Trade-off:* on a fast link a
segment from 4 GiB earlier with differing bytes is reported as an
``Overlap`` against retained data, or as ``Retransmission(verified=False)``
past ``retain_bytes``, rather than rejected; a target with PAWS would
have dropped it. A ``paws`` option can be added later without changing
any event.

4.4 Control flags and data on them
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- *Data on SYN* is placed at offset 0 and delivered when contiguous.
  TCP allows it, queued until the connection is established
  (`RFC 9293 §3.10.7.2 <https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.2>`__),
  and TCP Fast Open delivers it at once
  (`RFC 7413 <https://www.rfc-editor.org/rfc/rfc7413.html>`__).
  ``Anomaly(SYN_DATA)`` marks it, since a target without Fast Open may
  discard it if the handshake fails.
- *Duplicate SYN*: the same ISN is a ``Retransmission``. A different
  ISN before any data was delivered in that direction replaces the
  ISN, with ``Anomaly(ISN_CHANGED)``; after data was delivered, the
  SYN is ignored with ``Anomaly(ISN_CHANGED)``: a synchronized
  receiver answers an in-window SYN with a challenge ACK, not a reset
  (`RFC 5961 §4 <https://www.rfc-editor.org/rfc/rfc5961.html#section-4>`__).
- *Data without ACK*: a segment other than a SYN or an RST with the
  ACK bit clear is dropped, as a receiver must
  (`RFC 9293 §3.10.7.4 <https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4>`__),
  with ``Anomaly(DATA_WITHOUT_ACK)``. An RST is processed whether or
  not ACK is set, since that section checks the RST bit before the ACK
  field.
- *FIN*: data on the FIN segment is stream data. The FIN fixes the
  direction's end at its sequence number plus its data length. When
  delivery reaches that end, ``StreamEnd(reason=FIN)``. A later FIN
  at a different sequence number is ignored with
  ``Anomaly(INCONSISTENT_FIN)``; data past the end is dropped with
  ``Anomaly(DATA_AFTER_FIN)``; holes before the end may still fill.
- *RST*: data on an RST is diagnostic text, not stream data
  (`RFC 1122 §4.2.2.12 <https://www.rfc-editor.org/rfc/rfc1122.html#page-87>`__),
  and is reported as ``Anomaly(RST_WITH_DATA)``. What the RST does to
  the connection is the decision below.

Whether the target accepted an RST depends on its window check
(`RFC 5961 §3 <https://www.rfc-editor.org/rfc/rfc5961.html#section-3>`__)
and on whether the RST reached it at all (a TTL too low, section 5),
neither of which a capture shows. Ptacek & Newsham's RST evasion is an
RST the target rejects but the observer accepts: the observer tears
down its state, and the data that follows reaches the target unseen.
Three terms hold under every option below:

- *Data after the RST* is judged per direction. An RST occupies no
  sequence space, so each direction has its own mark: the highest
  stream offset it had received, delivered or held, when the RST
  arrived. Bytes of that direction above its mark are data after the
  RST, whether contiguous with the delivered end or out of order;
  either direction's counts.
- Bytes at or below a direction's mark are *retransmissions across the
  RST*. The connection keeps its retained bytes (``retain_bytes``,
  section 4.6) until it is removed, so they are compared as any
  retransmission is, and a difference is an ``Overlap``.
- ``StreamEnd(reason=RST)`` is emitted for both directions at once,
  and no ``StreamData`` of that connection follows it.

**Decision: what an RST does.**

- *(a) Defer*: on the RST, ``Anomaly(RST_RECEIVED)``; ``StreamEnd(RST)``
  only after ``rst_grace`` of capture time passes with no data after
  the RST, with ``completing_ref=None``. Data after the RST within the
  grace period cancels it, with ``Anomaly(DATA_AFTER_RST)``, and the
  connection goes on; data after the ``StreamEnd`` is handled as in
  (c). Held and out-of-order data stay held during the grace period.
- *(b) Continue*: the RST never ends the connection on its own. It is
  reported at once as ``Anomaly(RST_RECEIVED)``, with the RST's frame
  as ``completing_ref``, and the connection has a pending end:

  - *Clock.* The pending end's deadline is the RST's timestamp plus the
    closed timeout (section 2.5), on the capture clock of section 2.4.
    Retransmissions across the RST and segments without new data do
    not move it.
  - *Data after the RST* cancels the pending end: the RST is taken as
    rejected, ``Anomaly(DATA_AFTER_RST)`` is emitted once per
    direction, the data continues the same connection at the same
    offsets, in order or not, and the connection returns to the
    established idle timeout. It can later end by FIN, by timeout, or
    by another RST, which starts a new pending end.
  - *Confirmation.* When the deadline passes with no data after the
    RST, or at ``close()``, held data is flushed as on expiry and
    ``StreamEnd(RST)`` follows for both directions, with
    ``completing_ref=None``. The connection is then removed: a later
    segment under the key starts a new connection picked up
    mid-stream (section 4.2), with offsets from 0 and
    ``Anomaly(MIDSTREAM)``, as after any expiry.
  - *A SYN while the end is pending* whose ISN differs from the
    direction's (for a direction picked up mid-stream, which has no
    known ISN, any SYN counts as one with a new ISN) is a reconnection
    on the same tuple, which NAT, load tests and BGP restarts produce
    within seconds of an RST. It confirms the RST at once: held data is
    flushed, ``StreamEnd(RST)`` is emitted for both directions with the
    SYN's frame as ``completing_ref``, and the SYN starts a new
    connection under the key, with offsets from 0 after its ISN and
    ``Anomaly(SYN_AFTER_RST)``. Without a pending RST, such a SYN after
    data is still ignored with ``ISN_CHANGED`` (section 4.4). A SYN with
    the old ISN is a retransmission and changes nothing.

- *(c) End now*: contiguous data is delivered, held data is flushed as
  for ``close()`` (``Gap`` with reason ``FLUSH``), and
  ``StreamEnd(RST)`` follows at once. The connection is kept, holding
  its retained bytes, for the closed timeout. Data after the RST
  starts a new connection under the same key with
  ``Anomaly(DATA_AFTER_RST)``, whose offsets continue from each
  direction's ``StreamEnd.offset`` rather than restarting at 0, so a
  caller can join the two by offset.

*Accepted:* (b). It is the only option where an RST alone, rejected by
the target, cannot cut a stream: the bytes after it stay in the same
connection at the same offsets, so a message that spans the RST
decodes whole, and the ``RST_RECEIVED`` anomaly still tells the caller
at once. *Trade-off:* a caller learns that the connection ended only
at the closed timeout (120 s of capture time after the RST), at a new
SYN, or at ``close()``, so a close-delimited HTTP body that ends in an
RST is decoded that much later, and the state stays held that long.
The SYN rule reopens the evasion for an attacker who forges two
packets: an RST and then a SYN with a new ISN, both with a TTL too low
to reach the target, end the stream for the caller while the target's
connection goes on. Each is reported (``RST_RECEIVED``,
``SYN_AFTER_RST``), and the real data that follows lands outside the
new connection's sequence space, as out-of-window or before-start data
with its anomalies. The alternative, keeping the old connection
alongside the new one and placing each segment in whichever sequence
space it fits, closes that route but needs two connections per key and
a connection identity on every event; it is not part of the design.
Ignoring the SYN instead would lose every real reconnection within the
closed timeout. The reverse case is an insertion: if the target did
accept the RST, data sent after it was refused there, yet is delivered
here, marked by ``Anomaly(DATA_AFTER_RST)``. Option (a) bounds the
delay to ``rst_grace``, but an attacker who waits longer than it gets
(c)'s outcome. Under (c), and under (a) past the grace period, a
rejected RST gives the caller a ``StreamEnd`` it acts on: section 4.8
sets ``closed=True``, a close-delimited body is cut short, and the
rest of the message arrives in a new connection where no decoder can
frame it without the caller joining the two. That is the Ptacek &
Newsham evasion, reported but not prevented.

4.5 Windows and overlaps
~~~~~~~~~~~~~~~~~~~~~~~~

When both SYNs were seen, the scale of each window is known: the
shift each Window Scale option carries when both SYNs have one, and 0
when either lacks it
(`RFC 7323 §2.2 <https://www.rfc-editor.org/rfc/rfc7323.html#section-2.2>`__).
The reassembler then tracks each receiver's right window edge from the
other direction's ACK and window fields. Data past the furthest edge
seen is ``Anomaly(OUT_OF_WINDOW)`` and is still stored, subject to the
caps: a capture can miss the window update that made it valid, and
dropping it would lose real data on a lossy capture. Without both
SYNs, no window check is made.

Overlapping segments follow the fragment rules of section 3.3:
identical bytes are a ``Retransmission``, differing bytes an
``Overlap`` resolved by the receiver's policy.
``StreamReassembler`` offers ``first`` (the default) and ``last``.
The frag3 policies describe IP fragment reassembly; operating systems'
TCP segment-overlap behaviour differs from their fragment behaviour,
and Suricata's stream policies use a longer list of targets. Adding
per-OS TCP policies needs its own reference vectors and is a
follow-up, with no API change: the enum gains values and
``StreamReassembler`` accepts them.

4.6 Retransmissions with differing content
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Delivered bytes are final: a ``StreamData`` event is never revised. A
segment that overlaps bytes already delivered is compared with the
last ``retain_bytes`` of the direction:

- equal bytes: ``Retransmission(verified=True)``;
- differing bytes: ``Overlap``, with ``kept`` the delivered bytes,
  whatever the policy, and ``contrary=True`` when the policy would have
  chosen the arriving bytes had they not been delivered (always, under
  ``last``);
- bytes older than the retained window: ``Retransmission(verified=False)``.

Policies therefore decide only among bytes not yet delivered: data
held past a hole. The ``contrary`` flag makes the remaining case, a
target that would have taken the later version, visible.

**Decision: retransmissions older than** ``retain_bytes``. A
segment that repeats delivered bytes more than ``retain_bytes`` behind
the delivered end cannot be compared, and is reported as
``Retransmission(verified=False)``. If its bytes differ, that is an
inconsistent overlap the reassembler does not report as one: an
exception to the rule that every inconsistent overlap is reported.
With a scaled window, which ``max_flow_bytes`` assumes up to 2 MiB, a
sender can retransmit that far back.

- *64 KiB*, the largest unscaled window: covers every retransmission
  of an unscaled connection, and leaves differing retransmissions
  further back on scaled ones unverified.
- *The tracked window*: retain as much as the receiver's advertised
  window, up to half of ``max_flow_bytes``, when both SYNs were seen.
  Every retransmission inside the window is verified, at up to 2 MiB
  retained per direction. Retained bytes count against the caps but
  are trimmed first (section 2.3), so they never force a ``Gap``; the
  cost is memory, up to the caps, on every busy flow.
- *ACK-anchored*: retain from the peer's highest acknowledgement of the
  direction up to the delivered end, plus a fixed 64 KiB below that
  acknowledgement. A receiver never replaces bytes it has acknowledged
  (segment acceptance in RFC 9293 §3.10.7.4 trims what lies before
  RCV.NXT), so a differing repeat below the acknowledgement cannot
  change what the target holds; repeats above it are bounded by the
  window and always verified. The anchor is capped at the delivered
  end, so an acknowledgement beyond it, forged or not, retains no
  less than the plain 64 KiB case. Retention follows the bytes in
  flight, usually far less than the window. It needs the other
  direction in the capture; a one-sided capture falls back to 64 KiB.
- *Report unverified repeats as overlaps*: an ``Overlap`` with
  ``kept`` empty for every repeat older than the retained window. No
  exception remains, but every ordinary retransmission that far back
  is reported as a possible inconsistency, so the event stops meaning
  that bytes differed.

*Accepted:* ACK-anchored, with the remaining exception accepted
and documented: ``Retransmission(verified=False)`` is the report, and
SECURITY.md's scope (section 6.2) names it. It leaves unverified only
repeats more than 64 KiB below what the receiver has acknowledged,
which cannot change the target's bytes. *Trade-off:* the retained
amount varies with the acknowledgements seen, so memory per flow is
less predictable than a fixed 64 KiB; a lost or spoofed ACK moves the
anchor, though never past the delivered end; under cap pressure
retained bytes are trimmed first (section 2.3), which shrinks the
window and widens the exception for that flow; and a one-sided capture
keeps the plain 64 KiB exception, in which a differing retransmission
further back on a scaled connection is an insertion the caller sees
only as an unverified retransmission.

**Decision: when to deliver.** Delivering on contiguity (the
issue's "as they become available") delivers before a later, differing
retransmission can be seen. The alternative delivers a run only once
the receiver has acknowledged it, as Suricata hands data to its
application-layer parsers, so overlaps arriving before the ACK are
resolved by policy first. *Accepted:* deliver on contiguity, with
the ``contrary`` flag, and offer ACK-gated delivery later as an option.
Contiguity delivery makes a run's ``completing_ref`` the segment of the
sending direction that made the run contiguous (section 1.4), which is
what RootWire attaches messages to; ACK-gating would make it the
peer's ACK for every run, and delivers nothing for a one-sided
capture without a fallback. The ACK-based gap of section 4.7 makes it
the peer's ACK only for a run that a declared gap
releases, the one case where an ACK and no data segment is what made
the bytes deliverable. *Trade-off:* under ``last``, and under any
future per-OS TCP policy that favours later data, the delivered stream
can differ from what the target reassembled; every such case is an
``Overlap`` with ``contrary=True``, never silent.

4.7 Delivering byte runs
~~~~~~~~~~~~~~~~~~~~~~~~

Each ``feed`` that makes bytes contiguous with a direction's delivered
end emits one ``StreamData`` holding all of them: the arriving
segment's new bytes and any held segments it unblocks. Its ``spans``
tile ``data``, so ``offset + len(data)`` is the next run's ``offset``,
except across a ``Gap``, whose ``start`` and ``end`` say what is missing.

A truncated segment (captured bytes shorter than the IP header
declares) is a known loss: its captured bytes are delivered and a
``Gap`` with reason ``TRUNCATED`` covers the rest at once, so the next
segment is not held behind a hole that can never fill. A segment with
a bad checksum follows ``checksums`` (section 5.1).

**Decision: a gap when the peer acknowledges past a hole.** A
segment the capture missed but the receiver got is never
retransmitted: the receiver acknowledges past it. The direction then
holds everything after the hole until ``max_flow_bytes`` forces a
``Gap`` (2 MiB of data) or the idle timeout ends the flow (3,600 s),
and delivers nothing in between. Captures that drop packets show this
routinely.

- *No ACK-based gap*: the hole is filled only by data, a cap or a
  timeout. Nothing is skipped on the receiver's word, and delivery
  stalls as above.
- *Gap on ACK, late bytes reported*: when the other direction
  acknowledges a sequence number past the start of a hole, the
  acknowledged part of the hole is declared ``Gap(reason=ACKED)`` and
  the held data after it is delivered. Bytes that arrive later for the
  gap's range repeat nothing, so they are not a ``Retransmission``:
  they are reported as ``Anomaly(LATE_DATA)`` with their range, and
  their content is lost to the caller: captured data is dropped,
  though reported.
- *Gap on ACK, late bytes delivered*: as above, but bytes that arrive
  for a declared gap's range are delivered in a ``LateData`` event
  (``offset``, ``data``, ``spans``), outside the ordered runs, so no
  captured byte is lost. A caller that has already decoded past the gap
  decides whether to use them.

In both gap options the acknowledgement is mapped to stream offsets by
the serial-number rule of section 4.3 from the direction's offset 0,
which the SYN or mid-stream pickup (section 4.2) sets, so the rule
needs neither SYN, only that both directions are captured; window
tracking (section 4.5) is not required. Two limits apply to both:

- *Cap.* A gap never extends past the highest offset the direction has
  received, delivered or held. An acknowledgement beyond it is capped
  there and reported once as ``Anomaly(ACK_BEYOND_DATA)``, so a forged
  ACK far ahead cannot push the delivered end past data still to
  come.
- *Confirmation.* An ACK can be captured before the data it
  acknowledges: merged multi-interface captures and multi-queue
  capture reorder frames (section 2.4). A hole is therefore declared a
  gap only when it is still open ``ack_gap_grace`` of capture time
  after the first ACK past it (1 s by default), and a later frame, an
  ACK at or past the same point or data of the direction beyond the
  hole, confirms it. Data that fills the hole within the grace period
  cancels it.

The released run's ``completing_ref`` is the frame that confirmed the
gap (section 1.4), since that frame made the bytes deliverable; the
alternative is ``None``, as for a flush, which leaves such a run with
no completing frame.

*Accepted:* gap on ACK, late bytes delivered, with the cap, the
confirmation, and the confirming frame as ``completing_ref``. It turns
a stall of up to an hour into a reported gap on exactly the lossy,
often mid-stream captures where it happens, and keeps every captured
byte. *Trade-off:* one more event type, which a caller that ignores it
treats as a loss. The grace period delays delivery past a real loss by
``ack_gap_grace``; a reordering longer than that still yields a
spurious ``Gap`` and ``LateData`` in a benign capture; a shorter grace
period makes that likelier, a longer one delays more. An ACK the
receiver never sent (spoofed, or from an attacker on the path) makes
the observer skip bytes the receiver may still accept, up to the
highest offset seen: an evasion, reported as the ``Gap`` and, when the
bytes arrive, as ``LateData``. The confirmation does not stop it, since
an attacker can send the second ACK too.

``URG`` and the urgent pointer are ignored: urgent bytes stay inline,
as most stacks deliver them and as
`RFC 6093 §6 <https://www.rfc-editor.org/rfc/rfc6093.html#section-6>`__
advises applications to expect, and ``Anomaly(URGENT)`` is emitted once
per direction, since stacks have disagreed on the pointer's meaning
(RFC 6093 §3).

4.8 Message framing stays with the decoders
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The reassembler delivers bytes, never messages. A caller appends each
direction's runs to a buffer and decodes from its start with the
existing classes, which raise :class:`netprotocols.TruncatedHeaderError`
while the buffer ends inside a message:

.. code-block:: python

    from netprotocols import HTTP, TruncatedHeaderError

    def messages(buffer: bytearray, closed: bool) -> list[HTTP]:
        """Decode every whole HTTP/1.1 message at the buffer's start."""
        found = []
        while buffer:
            try:
                message = HTTP.decode(bytes(buffer), closed=closed)
            except TruncatedHeaderError:
                break  # wait for the next StreamData
            found.append(message)
            del buffer[: message.header_len]
        return found

- HTTP: :class:`netprotocols.HTTP`, as above; ``closed`` is ``True``
  once the direction's ``StreamEnd`` has been seen, and
  ``request_method`` comes from the matching request on the other
  direction.
- TLS: ``TLS.decode()`` per record; the SNI of a ClientHello that
  spans segments is read from the record decoded from the buffer.
- BGP: ``BGP.decode()`` per message, or
  ``decode_frame(buffer, start=BGP)`` for consecutive messages.
- DNS over TCP: ``decode_frame(buffer, start=DNSOverTCP)``, whose
  two-byte length prefix frames each message.

To attach a message to frames, the caller keeps the buffer's stream
offset: the message occupies
``[offset, offset + message.header_len)``, the spans of the runs that
overlap that range are its frames, and its completing frame is the
``completing_ref`` of the run that holds its last byte (section 1.4),
or none when that is ``None``. A desynchronized buffer (a ``Gap``
inside a message, or a decoder error other than truncation) is the
caller's to resynchronize, as a protocol decoder's framing rules are.

4.9 Out of scope
~~~~~~~~~~~~~~~~

- Urgent-data semantics beyond the inline delivery and anomaly above.
- SACK (`RFC 2018 <https://www.rfc-editor.org/rfc/rfc2018.html>`__):
  its blocks describe what the receiver holds, which would only matter
  for ACK-gated delivery.
- Exact receiver-window emulation, congestion and RTT analysis.
- PAWS (section 4.3) and per-OS TCP overlap policies (section 4.5), as
  follow-ups.
- MPTCP subflow merging, TCP-AO and TCP MD5 signature verification.
- Reassembly above TCP: messages, TLS records and handshakes, and
  HTTP/2 or QUIC streams.
- SCTP user-message reassembly.


5. Evasion and robustness
-------------------------

Ptacek & Newsham's techniques rely on the observer and the target
disagreeing about which packets were accepted (*insertion*: the
observer accepts what the target rejects; *evasion*: the reverse). A
passive reassembler cannot know the target's verdict; its response is
to emulate the target where a rule is fixed by the RFCs, and to report
wherever the outcome depends on the target or the path.

5.1 Checksums
~~~~~~~~~~~~~

A fragment with a bad IPv4 header checksum, or a segment with a bad
TCP checksum, is discarded by any receiver, which makes it the
simplest insertion. Captures taken on a sending host with checksum
offload record outgoing segments with checksums the NIC had yet to
fill.

A segment the snap length cut cannot have its checksum computed. It is
used under every mode, since a capture artifact is not something a
sender can forge, and ``TRUNCATED`` already marks it. A segment whose
IP header declares a length of 0 is different: on the wire such a
header is invalid and every receiver drops it, and only the capture
host's own outgoing TSO and GSO frames carry it legitimately. Its
pieces therefore follow the mode as a bad checksum would (below), and
each one is reported as ``Anomaly(UNVERIFIED_CHECKSUM)``.

**Decision: bad checksums.** ``decode()`` carries checksums
verbatim and verification is explicit, through
:mod:`netprotocols.checksum` (ARCHITECTURE.md, "The encode side, and
the round-trip guarantee"), so the library has no default to follow
here. ``ChecksumMode`` has:

- ``DROP``: a piece with a bad checksum is not used. It closes the
  insertion. On a capture taken on a host with transmit checksum
  offload, which is RootWire's usual case, every outgoing segment has
  a checksum the NIC had yet to fill, so the host's own direction of
  every connection disappears. Suricata validates in
  ``stream.checksum-validation: yes``, but its
  ``pcap-file.checksum-checks`` defaults to ``auto``, which turns
  validation off when it detects offload statistically.
- ``KEEP``: the piece is used. Nothing is lost on an offloaded capture,
  and a bad-checksum piece that differs from another version of the
  same bytes is still an ``Overlap``; but a bad-checksum piece that
  fills a hole first wins under ``first``, an insertion reported only
  by its ``BAD_CHECKSUM`` anomaly. Length-0 segments forged by anyone
  are used too.
- ``AUTO`` by history: a sender (the direction, for TCP) whose
  checksums have all been bad so far is taken to be offloaded and its
  pieces are used; from its first checksum that verifies, its bad ones
  are dropped. Forged pieces sent before any good one are used. And a
  single good checksum flips the sender for good: one spoofed valid
  segment injected into an offloaded host's direction, or one segment
  that host's stack happened to checksum in software, and the rest of
  that direction is dropped, an evasion.
- ``AUTO`` by pattern: each bad TCP checksum is judged on its own. One
  that equals the folded pseudo-header sum a stack leaves in the field
  for the NIC to complete is taken as an unfilled offload and used,
  with ``Anomaly(CHECKSUM_OFFLOAD)``; any other bad checksum is
  dropped. Linux writes
  ``th->check = ~tcp_v4_check(len, saddr, daddr, 0)``
  (`include/net/tcp.h <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/tcp.h>`__,
  and the IPv6 equivalent); FreeBSD writes the same sum with
  ``in_pseudo()``
  (`tcp_output.c <https://raw.githubusercontent.com/freebsd/freebsd-src/main/sys/netinet/tcp_output.c>`__);
  Windows writes it for
  `checksum offload <https://learn.microsoft.com/en-us/windows-hardware/drivers/network/offloading-checksum-tasks>`__
  and, for
  `large send offload <https://learn.microsoft.com/en-us/windows-hardware/drivers/network/offloading-the-segmentation-of-large-tcp-packets>`__,
  the sum without the TCP length, with an IPv4 Total Length of 0 under
  LSOv2; with IPv4 header checksum offload it leaves that checksum 0.
  A length-0 segment is used
  only when its checksum matches one of these patterns, computed for
  Linux, FreeBSD and Windows checksum offload over the segment's
  captured length, since its IP header gives none, and for Windows
  LSO without any length, as that pattern has none. There is no
  per-sender state to flip. The IPv4 header checksum is judged the
  same way: Linux computes it itself, so only Windows' 0 is a pattern.
  Anyone can compute these sums, so against an attacker this option is
  as open as ``KEEP``: a forged segment carrying the pattern is used,
  and its ``CHECKSUM_OFFLOAD`` anomaly looks like every legitimate
  offloaded segment's. What it filters is accidental corruption.
- ``AUTO`` from local senders: as by pattern, but the pattern is
  accepted only where offload can legitimately appear, on frames the
  capture host sent. The caller declares the host's addresses
  (``local=``, networks as ``targets`` takes them), and a pattern from
  any other source is a bad checksum, dropped. A weaker variant with no
  argument accepts the pattern only on frames longer than the link
  MTU, which only TSO and GSO produce; it misses offloaded segments of
  ordinary size and needs the MTU, which a capture does not record.

Each mode emits ``Anomaly(BAD_CHECKSUM)`` for every bad checksum.
*Accepted:* ``AUTO`` from local senders, with ``local`` naming
the capture host's addresses, and, when the caller gives no ``local``,
``AUTO`` by pattern. A capture taken on the host it analyses, RootWire's
case, keeps its outgoing direction, which ``DROP`` loses, and a
forged pattern from any other address is dropped; a caller that knows
nothing about the capture still keeps offloaded directions. *Trade-off:*
without ``local``, the default is as open to forged segments as
``KEEP`` and filters only accidental corruption, so a caller reading
hostile traffic passes ``local`` or chooses ``DROP``; with ``local``,
a forged segment that spoofs a local source address still carries the
pattern through; an offloaded host whose addresses the caller does not
declare loses its outgoing direction as under ``DROP``; and a sender
whose offload leaves some other value is dropped until its pattern is
added.
Transport checksums of fragmented datagrams are not checked by the
fragment reassembler: they cover the whole datagram, which the caller
verifies on the ``Datagram`` with :mod:`netprotocols.checksum`.

5.2 Techniques and responses
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Technique
     - Response
   * - Bad IP or TCP checksum (insertion)
     - ``checksums`` policy, ``Anomaly(BAD_CHECKSUM)`` (section 5.1).
   * - TTL or Hop Limit too low to reach the target (insertion)
     - The path is unknown, so nothing is dropped. Every span carries
       its hop limit, an ``Overlap`` shows both versions' hop limits,
       and a datagram or direction whose frames arrive with differing
       hop limits emits ``Anomaly(HOP_LIMIT_CHANGED)``.
   * - IP options a target rejects (bad source route, malformed)
     - Not interpreted. The decoded options are on the packet the
       caller fed; the reassembler uses the first fragment's options as
       captured.
   * - Overlapping IPv4 fragments, new data overwrites or old data
       wins
     - Policy per target (section 3.4), and ``Overlap`` for any
       differing byte, under every policy.
   * - Overlapping IPv6 fragments
     - Datagram discarded (RFC 5722 §4, erratum 3089), ``Overlap``
       with ``resolved=False``; a later fragment under the same key
       starts a new datagram, as RFC 8200 §4.5 and Linux do (section
       3.3). A contained fragment that Linux would drop as a duplicate
       discards the datagram here: an evasion against Linux targets,
       reported by the ``Overlap``.
   * - Overlapping TCP segments, retransmission with different data
     - Policy for undelivered bytes, ``Overlap`` (with ``contrary``)
       for delivered ones (sections 4.5, 4.6).
   * - Tiny first fragment hiding the TCP header (RFC 1858 §3)
     - ``Anomaly(TINY_FRAGMENT)``; the datagram reassembles, so the
       header is seen whole.
   * - Fragment at offset 1 overwriting TCP flags (RFC 1858 §4, RFC
       3128)
     - ``Anomaly(TCP_OFFSET_ONE)``, resolved by policy, reported by
       ``Overlap`` if bytes differ.
   * - IPv6 header chain split across fragments (RFC 7112)
     - First fragment discarded, ``Anomaly(INCOMPLETE_HEADER_CHAIN)``.
   * - Atomic fragment colliding with a real fragment train (RFC 6946)
     - Processed in isolation; never joins a train.
   * - Oversized datagram ("ping of death")
     - ``Anomaly(OVERSIZE)``; the fragment or the datagram discarded
       (section 3.5).
   * - Fragment timeout desynchronization (the observer and the target
       time out at different moments)
     - Age timeout from the first fragment, per target
       (section 2.5); every abandoned datagram is an ``Expired`` event
       with its spans and holes, so a train completed after the
       observer gave up is visible as an ``Expired`` followed by a new
       datagram under the same key. A datagram the observer completes
       after a Linux IPv4 target's 30 seconds is the reverse case,
       which section 2.5's decision covers.
   * - Inconsistent last fragment or length
     - Datagram discarded, ``Anomaly(INCONSISTENT_END)``.
   * - Data on SYN
     - Delivered, ``Anomaly(SYN_DATA)`` (section 4.4).
   * - SYN resent with a new ISN (desynchronization)
     - ``Anomaly(ISN_CHANGED)``; ISN replaced only before data
       (section 4.4).
   * - Spoofed or out-of-window RST tearing down observer state
     - Per the RST decision (section 4.4). Under the accepted option,
       the RST is an ``Anomaly(RST_RECEIVED)``, the connection is not
       ended, and data after it continues the same stream with
       ``Anomaly(DATA_AFTER_RST)``; the ``StreamEnd(RST)`` waits for
       the closed timeout or a SYN with a new ISN. A forged RST
       followed by a forged SYN still ends the stream, reported as
       ``SYN_AFTER_RST``. Under the other options a rejected RST alone
       ends the stream for the caller, reported but not prevented.
   * - FIN games: data after FIN, second FIN
     - ``Anomaly(DATA_AFTER_FIN)``, ``Anomaly(INCONSISTENT_FIN)``.
   * - Data without ACK
     - Dropped, ``Anomaly(DATA_WITHOUT_ACK)``.
   * - Out-of-window data
     - ``Anomaly(OUT_OF_WINDOW)``, stored under the caps.
   * - Old segment accepted across a sequence wrap (PAWS)
     - Not emulated; reported as ``Overlap`` or unverified
       ``Retransmission`` (section 4.3).
   * - Urgent pointer ambiguity
     - Inline delivery, ``Anomaly(URGENT)``.
   * - Mid-stream connection fabricated without a handshake
     - Picked up, ``Anomaly(MIDSTREAM)``.
   * - Truncated capture hiding bytes
     - ``Anomaly(TRUNCATED)``; for TCP an immediate ``Gap``.

5.3 State exhaustion
~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Flood
     - What stops it
   * - SYN flood, half-open flows
     - ``max_flows`` and ``max_total_bytes`` with ``FLOW_OVERHEAD``
       charged per flow; half-open flows are evicted first; their idle
       timeout is 60 s.
   * - Fragment flood, many identifications
     - ``max_flows`` (16,384) and ``max_total_bytes`` (32 MiB), oldest
       datagram first; age timeout 60 s.
   * - Tiny-fragment flood within one datagram
     - ``max_fragments`` (128) and ``PIECE_OVERHEAD`` charged per
       fragment.
   * - Out-of-order flood within one connection (a hole, then data
       past it)
     - ``max_flow_bytes`` forces a ``Gap`` and delivers, so a
       connection never holds more than its cap.
   * - One-byte segment flood
     - ``PIECE_OVERHEAD`` per held segment; delivered segments are
       merged into retained runs, not kept per segment.
   * - Overlap storm (many differing retransmissions)
     - No state grows: resolution replaces bytes. At most one
       ``Overlap`` per frame and flow (section 1.4).
   * - Hash-collision flooding of the flow table
     - Keys are tuples of ``str`` and ``int``, hashed with Python's
       randomized string hashing. Iteration order, and therefore event
       order, never depends on hash values: flows are kept in
       insertion-ordered structures, so replay is deterministic under
       any ``PYTHONHASHSEED``.

The work per frame is bounded too: a fragment overlaps at most
``max_fragments`` held fragments, and a segment at most the pieces of
its direction, whose number is bounded by ``max_flow_bytes`` divided
by ``PIECE_OVERHEAD``.


6. Documents that change
------------------------

Each pull request updates the documents for what it ships. The
statements "reassembly is the caller's" become "the caller's, or
``netprotocols.reassembly``'s" where the module does the reassembly,
and stay as they are where it does not.

6.1 ARCHITECTURE.md
~~~~~~~~~~~~~~~~~~~

Every line ``grep -n -i reassembl ARCHITECTURE.md`` finds at master
``b729e0e``:

.. list-table::
   :header-rows: 1
   :widths: 14 30 56

   * - Line
     - Topic
     - Change
   * - 787
     - SCTP user messages
     - SCTP reassembly stays the caller's; only the comparison "as for
       HTTP over TCP" changes, to say that a TCP stream can be
       reassembled by ``netprotocols.reassembly`` and an SCTP message
       cannot.
   * - 1017
     - TFTP transfer tracking
     - Tracking the transfer stays the caller's; "as reassembly is for
       ``HTTP`` and ``BGP``" becomes "as reassembling the stream is for
       ``HTTP`` and ``BGP``, unless ``netprotocols.reassembly`` does it".
   * - 1198-1199
     - BGP messages across segments
     - "the caller's, or ``netprotocols.reassembly``'s".
   * - 1275-1276
     - TLS ClientHello spanning segments
     - The SNI comes from reassembling the stream, "yourself or with
       ``netprotocols.reassembly``", and ``TLS.decode()`` on that.
   * - 1316
     - TLS handshake messages across records
     - Unchanged: record-layer reassembly is out of scope (section 4.9).
   * - 1341
     - HTTP
     - "Reassemble the connection, with ``netprotocols.reassembly`` or
       your own, and call ``HTTP.decode()`` on its bytes."
   * - 1414-1415
     - Checksums of a message reassembled from IPv6 fragments
     - Add that a ``Datagram``'s IPv6 header has a Payload Length that
       covers the reassembled datagram, so it serves as ``ip``.

Also: a new section after "Port-based dispatch is best-effort" that
states the module's contract (sections 1 to 4 of this note, as
shipped), a sentence in "The decode contract" that ``decode()`` stays
stateless and the reassemblers are the library's only objects that
keep state across frames (a ``Registry`` is mutable, but holds
configuration, not traffic), and a ``reassembly.py`` entry in "Layout map".

6.2 README.md, SECURITY.md and docstrings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- README line 194 (BGP, "no reassembly"), 196 (TLS, "read from a
  reassembled stream"), 197 (HTTP, "from a buffer you reassembled")
  and 350 ("Decoding HTTP": "which you reassemble"): each names
  ``netprotocols.reassembly`` as one way to get the stream. A new
  section, "Reassembling fragments and streams", holds the loop of
  section 1.6 and the bounds table.
- SECURITY.md lines 50-51, 58-59 and 63, which put TCP reassembly and
  segment-overlap tricks outside ``HTTP``'s, ``BGP``'s and ``TLS``'s
  scope: they stay outside the decoders' scope, and a new paragraph
  puts them in the module's: state beyond the documented bounds, an
  inconsistent overlap resolved without an ``Overlap`` event (a
  retransmission older than ``retain_bytes``, reported as unverified,
  is the documented exception, section 4.6), an event
  missing a contributing or completing frame, or output that depends on
  anything but the input and its timestamps.
- Docstrings that say the same: ``layer7/http.py`` lines 7-8,
  ``layer7/bgp.py`` 66, ``layer7/stun.py`` 130, ``layer7/tls.py`` 75,
  113, 116 and 601, and ``checksum.py`` 74-75 and 738-739.
  ``layer7/tftp.py`` 76 and ``layer4/sctp.py`` 62 and 537 stay:
  transfer tracking and SCTP reassembly are not the module's; so do
  ``layer7/bgp.py`` 68, which says what the decoder does without
  reassembly, and ``layer7/tls.py`` 227, on handshake messages across
  records (section 4.9).

6.3 docs/CLAIMS.md
~~~~~~~~~~~~~~~~~~

No claim says the library is stateless; none needs withdrawing.
Affected:

- §3.2, "Zero dependencies, no I/O, no sockets", counts the stdlib
  modules ``src/`` imports. The module uses only the standard library
  (``ipaddress`` for target networks, ``bisect`` for held pieces), so
  the claim stays true and the count is re-derived.
- §1.4 (import time) and §1.5 (wheel size, ``src/`` lines) are
  re-measured at the release, under Rule 4. Import time is unaffected
  if the package does not import the module (section 6.4).
- §6, "Claims we must not make", gains: "reassembles exactly as
  <operating system> does". The named policies follow frag3's mapping
  of stacks measured before 2005, and ``linux-discard``
  follows the kernel commits of section 3.4's table, not every
  kernel since.

6.4 Package exports
~~~~~~~~~~~~~~~~~~~

**Decision: re-export from** ``netprotocols``. The package's
convention is to re-export: ``netprotocols/__init__.py`` imports the
public names of ``pcap``, ``flow`` and ``checksum`` as well as every
protocol, and the docstring of ``tests/test_exports.py`` states that
"the top-level package re-exports every public name".

- *No re-export*: the reassemblers are reached as
  ``netprotocols.reassembly`` only, and ``import netprotocols`` does not
  import them.
- *Eager re-export*: the names are imported in ``__init__.py`` like the
  rest, and every ``import netprotocols`` pays for the module.
- *Lazy re-export*: a module ``__getattr__``
  (`PEP 562 <https://peps.python.org/pep-0562/>`__) imports
  ``netprotocols.reassembly`` on the first access to one of its names,
  so ``from netprotocols import FragmentReassembler`` works with no
  import cost until it is used; ``__all__`` lists the names and a
  ``TYPE_CHECKING`` import gives type checkers the same view.

*Accepted:* no re-export. The per-frame decoder pays no import
cost (CLAIMS §1.4) and the stateful API is visibly separate from the
stateless one. *Trade-off:* it breaks the re-export convention above,
callers write one more import line, and ``tests/test_exports.py`` has
no notion of a public submodule today: recording the module as one is
new work. The lazy re-export keeps the convention at no import cost,
at the price of the only ``__getattr__`` in the package.

6.5 CHANGELOG.md
~~~~~~~~~~~~~~~~

Each pull request adds its entries under ``## [Unreleased]``: the new
module under ``### Added``, the documentation changes above under
``### Changed``, and test and capture-script work under
``### Development``, each naming its issue.


7. Test plan
------------

7.1 Real captures
~~~~~~~~~~~~~~~~~

A new netns script, ``scripts/capture_fixtures_reassembly.sh``, in the
style of the existing ones (veth pair, offload off, provenance in
``tests/fixtures/MANIFEST.md``), writes to
``tests/fixtures/reassembly/``, outside the corpus globs as ``http/``
and ``tls/`` are:

- fragmented UDP over IPv4: a 4,000-byte datagram over a 1,500-byte
  MTU, and a DNS response over 1,232 bytes from a local server queried
  with a 4,096-byte EDNS buffer;
- the same over IPv6 with a 1,280-byte MTU;
- a multi-segment HTTP exchange: curl against ``http.server`` with a
  body of a few hundred kilobytes and a reduced MSS, so responses span
  dozens of segments, with one connection closed by RST;
- a multi-segment TLS handshake, as ``tls/tls_session.pcap`` already
  has (Chromium's 1,738-byte ClientHello in two segments).

The existing fixtures are used first: ``ipv4_fragments.pcap`` and
``ipv6_fragments.pcap`` each hold two whole datagrams and one orphan
last fragment, which gives two ``Datagram`` events and an ``Expired`` on
``close()``; ``tcp_http.pcap`` holds a chunked response in two
segments; ``http/http.pcap`` and ``tls/tls_session.pcap`` have their
streams already extracted.

7.2 Crafted overlap cases
~~~~~~~~~~~~~~~~~~~~~~~~~

The overlap cases that real stacks do not emit are built inside the
tests, as crafted bytes labelled **crafted** there, never as committed
pcaps:

- the overlapping fragment pattern of Suricata's ``DefragSturgesNovak*``
  tests, once per offered IPv4 policy, with the expected reassembled
  bytes in a table in the test, one row per policy, taken from those
  tests; for ``linux-discard``, the pattern and the expected outcome
  come from a netns capture against the running kernel
  (``tests/fixtures/reassembly/linux_overlaps.pcap``: script-built
  fragment trains and the kernel's echo replies, labelled so in
  MANIFEST, with the netns's ``ReasmOKs`` and ``ReasmOverlaps``
  counters across each train recorded there, since a reply needs a
  valid echo request and its absence alone does not show a discard);
- the same pattern over IPv6, expecting the RFC 5722 discard, and then
  a clean train under the same key, expecting a new ``Datagram``;
- identical duplicates (``Retransmission``, no ``Overlap``) for both
  versions;
- RFC 1858 tiny-fragment and offset-1 cases, an oversized datagram,
  a misaligned fragment, an empty fragment, two inconsistent last
  fragments and an IPv6 first fragment with a split header chain, each
  asserting the discard decided in section 3.5;
- TCP: a retransmission with different bytes, before and after
  delivery, under ``first`` and ``last``; data after FIN; data after
  an RST in each direction, in order and out of order, and a differing
  retransmission across it, under option (b) of decision 12; a SYN with a
  changed ISN; a sequence wrap inside a stream; data without ACK; an
  RST without ACK; a bad checksum under each ``ChecksumMode`` value,
  and an offloaded direction under ``AUTO``.

Every ``Overlap`` case also asserts the event's ``kept``, ``other``,
both span sets, ``completing_ref``, and that the case produces it under
every policy.

7.3 Deterministic bounds
~~~~~~~~~~~~~~~~~~~~~~~~

Each cap and timeout is triggered by constructed inputs with chosen
timestamps, with small bounds passed to the constructor:

- each cap of section 2.2 at exactly its limit and one byte or one flow
  past it, asserting the victim of section 2.3 and its event;
- each timeout at its deadline minus one nanosecond (no expiry) and at
  the deadline (expiry), through ``feed`` and through ``advance``;
- a timestamp lower than the clock, which must not expire or revive
  anything;
- determinism: the same capture fed twice gives equal event tuples, and
  a subprocess run under two ``PYTHONHASHSEED`` values gives the same
  ``repr`` of the events.

7.4 Memory bound
~~~~~~~~~~~~~~~~

With ``allocation_peak`` from ``tests/conftest.py``:

- a flood of 200,000 SYNs from distinct source ports into a
  ``StreamReassembler`` with ``max_flows=1_024`` and
  ``max_total_bytes=1 MiB``, and of 200,000 single-fragment datagrams
  into a ``FragmentReassembler`` with the same bounds. Each asserts
  ``usage`` within the caps after every ``feed``, the number of
  ``Evicted`` events, and that the peak is at most
  ``1.5 * max_total_bytes``: the reassembler's own state plus the
  transient allocations of one ``feed``, with events discarded as they
  are returned;
- the overhead constants: *n* flows (and *n* pieces) are added and
  the traced growth divided by *n* must not exceed ``FLOW_OVERHEAD``
  (and ``PIECE_OVERHEAD``), so the accounting never undercounts.

7.5 Properties
~~~~~~~~~~~~~~

Hypothesis, under the existing profiles:

- any payload up to 65,000 bytes, cut into fragments on 8-byte
  boundaries, with exact duplicates added and the order shuffled,
  reassembles to one ``Datagram`` whose payload is the original and
  whose spans tile it;
- any payload cut into TCP segments, with a random ISN (wraps
  included), consistent retransmissions added and the order shuffled,
  yields ``StreamData`` runs that concatenate to the payload, with no
  ``Overlap``;
- with differing duplicates added, the delivered bytes equal a
  byte-level reference model of the policy in the test (for ``first``:
  each byte's earliest version among those not yet delivered when it
  arrived), and there is at least one ``Overlap``;
- under arbitrary bounds, ``usage`` never exceeds them.

7.6 Differential checks
~~~~~~~~~~~~~~~~~~~~~~~

Against independent references, never against dpkt, scapy or
pypacker, which neither ``src/`` nor ``tests/`` imports:

- tshark: ``ip.reassembled_in``, ``ipv6.reassembled.in``,
  ``ip.reassembled.data`` and ``ipv6.reassembled.data`` for each
  fragment capture, and ``-z follow,tcp,raw`` for each connection, are
  taken at capture time and recorded in the tests (the reassembled-in
  frame, the length and the SHA-256 of the data) and in MANIFEST, with
  the tshark version. The tests
  compare ``Datagram.data``'s payload and ``completing_ref`` with
  tshark's reassembled data and reassembled-in frame, and the
  concatenated ``StreamData`` with the followed stream, so CI needs no
  tshark. On the script-built capture of the kernel's trains,
  ``ip.fragment.overlap.conflict`` must flag the trains in which
  ``Overlap`` reports differing bytes.
- ``scripts/extract_http_streams.py``, the stdlib-only extractor the
  HTTP and TLS tests already use: its ``NN.request`` and
  ``NN.response`` files must equal the module's streams for
  ``http/http.pcap`` and ``tls/tls_session.pcap``, and the SNI read
  through the module must equal the one ``tests/test_tls.py`` reads.


8. Milestones
-------------

Two issues, one pull request each, after this note is accepted.

**Issue A: IPv4 and IPv6 fragment reassembly.** Ships
``netprotocols.reassembly`` with ``FragmentReassembler``,
``FragmentBounds``, ``Span``, ``FragmentKey``, ``Usage``, the shared
event types the fragment path emits, ``OverlapPolicy`` with the
policies decided in section 3.4, and ``ChecksumMode``. Acceptance:

- the API of sections 1 and 2 for fragments, type-checked under
  ``mypy --strict``, every public name documented and the Sphinx build
  clean;
- every rule of sections 3.2 to 3.6, each with a test;
- the existing and new fragment captures reassemble to tshark's
  reassembled data, with ``completing_ref`` equal to tshark's
  reassembled-in frame;
- the crafted overlap captures produce each policy's expected bytes
  and an ``Overlap`` under every policy; IPv6 discards, and a later
  train under the same key reassembles as a new datagram;
- a datagram discarded by an expiry or an eviction that another
  datagram's fragment triggered carries ``completing_ref=None``;
- the bound, determinism, memory and property tests of section 7 for
  fragments, with ``FLOW_OVERHEAD`` and ``PIECE_OVERHEAD`` measured and
  fixed;
- the documentation changes of section 6 that concern fragments,
  ARCHITECTURE's new section included, and CHANGELOG entries;
- ``decode()`` and ``decode_frame()`` unchanged: the corpus, contract
  and benchmark gates pass with no change to their expectations.

**Issue B: TCP stream reassembly.** Depends on A. Ships
``StreamReassembler`` and ``StreamBounds``, reusing A's bounds
machinery, ``Span``, ``Overlap``, ``Retransmission``, ``Evicted``,
``Expired`` and ``Anomaly``, and adding ``StreamData``, ``StreamEnd``,
``OutOfOrder`` and ``Gap``. Acceptance:

- every rule of section 4, each with a test, ``first`` and ``last``
  offered;
- ``http/http.pcap`` and ``tls/tls_session.pcap`` reassemble to the
  extractor's files and to tshark's followed streams; the new HTTP
  capture decodes, message by message, with ``HTTP.decode()`` on the
  runs as in section 4.8, and each message's completing frame is the
  ``completing_ref`` of the run that holds its last byte (section 1.4);
- a flow flushed by an expiry or an eviction that another flow's frame
  triggered carries ``completing_ref=None`` on every event;
- the crafted TCP cases of section 7.2 and the stream properties of
  section 7.5;
- the SYN-flood memory bound of section 7.4;
- the remaining documentation changes of section 6 (HTTP, TLS, BGP,
  SECURITY.md, docstrings) and CHANGELOG entries.

Follow-ups, filed when wanted: per-OS TCP overlap policies with
reference vectors, ACK-gated delivery, PAWS, and ``bsd-right``.

The names the decisions of :ref:`reassembly-decisions` add ship in the
issue of their step, with their tests: ``linux-discard``,
``ChecksumMode.AUTO``, ``local``, per-target fragment timeouts and the
anomaly kind ``CHECKSUM_OFFLOAD`` in A; ``GapReason.ACKED``,
``ack_gap_grace``, ``LateData``, and the anomaly kinds
``RST_RECEIVED``, ``SYN_AFTER_RST`` and ``ACK_BEYOND_DATA`` in B.


.. _reassembly-decisions:

Decisions
---------

Each decision is accepted as listed; its section gives the options
weighed and the trade-off.

.. list-table::
   :header-rows: 1
   :widths: 6 30 64

   * - #
     - Decision
     - Accepted
   * - 1
     - Input type (1.1)
     - The decoded ``Packet`` and its frame.
   * - 2
     - Type of a frame reference (1.3)
     - ``int``, defaulting to the feed count.
   * - 3
     - Fragment eviction order (2.3)
     - Oldest datagram first, by first-fragment time.
   * - 4
     - Fragment timeouts, per target or global (2.5)
     - Per target, 60 s for both versions by default, and
       ``Anomaly(SLOW_REASSEMBLY)`` past 30 s for IPv4.
   * - 5
     - TCP total-age timeout (2.5)
     - None by default, settable.
   * - 6
     - Named IPv4 fragment policies (3.4)
     - ``first`` (default), ``last``, ``bsd``, ``linux``, ``windows``,
       ``solaris`` and ``discard``; not ``bsd-right``.
   * - 7
     - A policy for current Linux (3.4)
     - Add ``linux-discard``; document ``linux`` as Linux before
       7969e5c40dfd, with the stable backports.
   * - 8
     - What OVERSIZE, MISALIGNED and EMPTY_FRAGMENT discard (3.5)
     - IPv6: the fragment for OVERSIZE and MISALIGNED, the datagram for
       EMPTY_FRAGMENT. IPv4: truncate and keep a MISALIGNED fragment,
       the datagram for OVERSIZE, and for EMPTY_FRAGMENT the datagram
       under ``linux-discard``, the fragment otherwise.
   * - 9
     - Reassembled header (3.6)
     - Synthesized from the first fragment, with ``header_ref``.
   * - 10
     - Mid-stream pickup (4.2)
     - On, with ``Anomaly(MIDSTREAM)``.
   * - 11
     - PAWS (4.3)
     - Not implemented.
   * - 12
     - What an RST does (4.4)
     - Continue the connection: ``Anomaly(RST_RECEIVED)`` at once;
       ``StreamEnd(RST)`` at the closed timeout after the RST with no
       data after it, or at once on a SYN with a new ISN; data after
       the RST cancels it.
   * - 13
     - When to deliver TCP data (4.6)
     - On contiguity, with ``Overlap.contrary``; ACK-gating later.
   * - 14
     - Retransmissions older than ``retain_bytes`` (4.6)
     - ACK-anchored retention plus 64 KiB below the acknowledgement;
       older repeats reported as ``Retransmission(verified=False)``,
       the documented exception to "always reported".
   * - 15
     - Gap when the peer acknowledges past a hole (4.7)
     - Yes, ``Gap(reason=ACKED)``, capped at the highest offset
       received and confirmed after a 1 s grace; late bytes delivered
       as ``LateData``; the confirming frame as ``completing_ref``.
   * - 16
     - Bad checksums (5.1)
     - ``ChecksumMode.AUTO``: the offload pattern accepted only from the
       caller's ``local`` addresses, or from any source when ``local``
       is not given.
   * - 17
     - Re-export from ``netprotocols`` (6.4)
     - No; ``netprotocols.reassembly`` only.

The defaults of section 2.5 are accepted with these.
