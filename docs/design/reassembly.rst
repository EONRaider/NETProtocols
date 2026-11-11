Design note: reassembly of IP fragments and TCP streams
=======================================================

This note settles the design of ``netprotocols.reassembly``, the
opt-in, stateful module for issue
`#373 <https://github.com/EONRaider/NETProtocols/issues/373>`__. It
specifies the public API, the bounds and their defaults, fragment and
stream reassembly, the response to each known evasion, the documents
that change, the test plan and the split into pull requests. It
describes a module that does not exist yet: every name below is a
proposal. Each point that needs the maintainer is marked
**Decision needed**, with a recommendation and its trade-off, and
:ref:`reassembly-decisions` lists them all.

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
  (`RFC 5722 §4 <https://www.rfc-editor.org/rfc/rfc5722.html#section-4>`__).
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

A :class:`netprotocols.packet.Packet` holds headers only:
``bytes(packet)`` is the layers, and the bytes no decoder read (a TCP
payload where the walk stopped at TCP, a non-first fragment's data,
which :meth:`netprotocols.IPv4.next_protocol` gives no class) are
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

**Decision needed: the input type.** Three shapes were weighed.

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
     - Does not work: the payload bytes are not in the packet.
   * - ``Packet`` and frame (recommended)
     - One decode, done by the caller with whatever ``start``,
       registry and ``lax`` it uses. The module never calls a decoder
       on input, so it stays out of the decode path and is
       independent of the link type.
     - Two arguments that must belong together. A mismatched pair
       is a caller error the module can detect only partly (below).

*Recommendation:* the packet and the frame. Reassembly needs the
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
            checksums: ChecksumMode = ChecksumMode.DROP,
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

``StreamReassembler`` has the same four methods, takes
``StreamBounds`` and returns ``StreamEvent``.

- ``feed`` takes one frame and returns, in a fixed order, every event
  that frame caused: first the expiries its timestamp triggers in
  other flows (section 2.4), then the events of its own flow in stream
  or datagram offset order. A frame the reassembler does not apply to
  returns ``()``: for ``FragmentReassembler``, a packet with no IP
  header that is a fragment; for ``StreamReassembler``, a packet with
  no TCP layer, or whose TCP layer is inside an IP fragment (a first
  fragment's TCP header is decoded by the walk but its payload is
  partial; the caller feeds the reassembled datagram instead, section
  1.6).
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
direction. No match means ``policy``. The constructor raises
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

**Decision needed: the type of a reference.** An ``int`` or an opaque,
caller-chosen token (a type parameter, ``FragmentReassembler[R]``).

*Recommendation:* ``int``. It is what RootWire and every pcap reader
have (a frame index), it is totally ordered, so "frames N..M" and
sorting spans mean something, it costs a small integer per span, and it
keeps the classes non-generic. *Trade-off:* a caller whose frames are
identified by something else (a ring-buffer slot, a database key)
keeps its own mapping from the integer it passes.

1.4 Event types
~~~~~~~~~~~~~~~

Every event is a frozen, slotted, keyword-only dataclass, as
:class:`netprotocols.TCPOption` and the other non-layer values with
structure are. Not a named tuple: two different event types with equal
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
     - The ``ref`` of the frame whose ``feed`` produced the event;
       ``None`` when ``advance`` or ``close`` produced it.
   * - ``first_timestamp``, ``last_timestamp``
     - The earliest and latest ``timestamp`` among ``spans``.

``refs`` is a property: the sorted, distinct refs of ``spans``.

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
       included, section 3.6), ``header_len``, ``header_ref`` (the
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
       delivered bytes and differ from them.
     - ``start``, ``end``, ``policy`` (the ``OverlapPolicy`` applied),
       ``kept`` and ``other`` (the two versions of the range),
       ``kept_spans`` and ``other_spans``, ``resolved`` (``False`` for
       IPv6, whose datagram is discarded), ``contrary`` (section 4.6).
   * - ``Retransmission``
     - Arriving bytes repeat held or delivered bytes exactly, or
       repeat delivered bytes the reassembler no longer retains.
     - ``start``, ``end``, ``verified`` (``False`` when the bytes
       could not be compared).
   * - ``OutOfOrder``
     - A TCP segment arrives beyond the next expected stream offset
       and is held.
     - ``start``, ``end``, ``expected``.
   * - ``Gap``
     - A TCP direction skips bytes it never received: a cap forced it,
       the capture truncated them, or the flow is being flushed.
     - ``start``, ``end``, ``reason`` (``GapReason``).
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
Suricata's spellings (``"first"``, ``"bsd"``, ...).

``Overlap`` events are bounded: one per fed frame and flow, covering
the smallest range that holds every differing byte, with ``kept`` and
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
  (section 1.1), and for invalid bounds, networks or policies at
  construction.

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
            if isinstance(event, Datagram):
                start = IPv4 if event.version == 4 else IPv6
                whole = decode_frame(event.data, start=start, lax=True)
                handle(streams.feed(whole, event.data, timestamp=ts, ref=index))
            handle((event,))
        handle(streams.feed(packet, frame, timestamp=ts, ref=index))
    handle(fragments.close() + streams.close())

The ``Datagram`` event maps the ref the stream events carry to every
fragment frame. A tunnelled datagram (IP in IP, GRE) whose outer
header is fragmented is handled the same way: the reassembler acts on
the outermost IP header that is a fragment, and the caller feeds the
rebuilt datagram back to reach the inner one. The module is imported
as ``netprotocols.reassembly``; see section 6.4 for why the package
does not re-export it.


2. Bounds
---------

Bounds are part of the API: each has a documented default, a
documented eviction, and an event.

2.1 What is charged
~~~~~~~~~~~~~~~~~~~

Each flow (a datagram in progress, or a TCP connection) is charged
``FLOW_OVERHEAD`` bytes, and each stored piece (a fragment, a held
segment, a retained delivered run) is charged its data length plus
``PIECE_OVERHEAD``. The two constants are module-level and are fixed in
the fragment pull request by measuring CPython's actual allocation per
flow and per piece with ``tracemalloc``; the test in section 7.4 holds
them to it. The figures below assume the expected order of magnitude,
1 KiB per flow and 256 bytes per piece. Charging overhead per piece is what makes a flood of
one-byte segments or eight-byte fragments cost what it really costs.

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
     - Flows held at once, IPv6 discard markers (section 3.3)
       included.
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
     - Fragments: the oldest datagram by first-fragment time. Streams:
       the least recently active flow among those not yet carrying data
       in both directions (half-open, or one-sided), and if there is
       none, the least recently active flow.
     - Fragments: discarded, as above. Streams: the held data is
       flushed as for ``close()``: each hole becomes a ``Gap`` (reason
       ``FLUSH``), held bytes are delivered, then ``StreamEnd``
       (reason ``EVICTED``) for each open direction, then
       ``Evicted``.

Ties in age are broken by feed order, so eviction is deterministic.
The cap is enforced before the arriving frame's data is stored: the
reassembler evicts until the new piece fits, and a piece larger than
``max_flow_bytes`` on its own is reported as ``Evicted`` immediately.
After every call, ``usage.bytes <= max_total_bytes`` and
``usage.flows <= max_flows``.

Preferring half-open TCP flows as victims means a SYN flood evicts its
own flows before an established, idle one (a BGP session between
keepalives). An evicted TCP flow that sends again is picked up
mid-stream (section 4.2), with an ``Anomaly`` saying so, so an attacker
who floods to flush a flow's state does not make the rest of that flow
invisible.

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
``StreamEnd`` reason ``IDLE`` or ``AGE`` and then ``Expired``.

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
     - A 65,535-byte IPv4 datagram over a 576-byte MTU, the size every
       host must accept (RFC 791 §3.1), takes 119 fragments of 552
       data bytes; over IPv6's 1,280-byte minimum MTU, 52. Datagrams cut
       finer than that come from no ordinary stack, and are the tiny-
       fragment flood of section 5.
   * - ``max_total_bytes``
     - 32 MiB
     - Suricata's default defrag memcap. It holds some 500 maximal
       datagrams at once, or over 5,000 typical ones, such as a
       4,096-byte EDNS response cut for a 1,500-byte link.
   * - ``max_flows``
     - 16,384
     - At about 1.3 KiB for the smallest datagram in progress (one
       eight-byte fragment and the overheads), 32 MiB would admit some
       26,000; the lower flow cap binds first under a flood of
       single-fragment datagrams and bounds the expiry scan.
   * - idle timeout
     - none
     - RFC 8200 §4.5 and
       `RFC 1122 §3.3.2 <https://www.rfc-editor.org/rfc/rfc1122.html#page-56>`__
       time reassembly from the first fragment, which the age timeout
       does.
   * - age timeout
     - 60 s
     - RFC 8200 §4.5: 60 seconds from the first-arriving fragment.
       RFC 1122 §3.3.2 recommends 60 to 120 seconds; Suricata's
       default is 60.

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
       (`RFC 9293 §3.1 <https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1>`__):
       a retransmission repeats unacknowledged data, which an unscaled
       window bounds. Older repeats are reported unverified.
   * - ``max_total_bytes``
     - 128 MiB
     - 32 flows at their full per-flow cap at once. Half of
       Suricata's stream reassembly memcap (256 MiB), which is sized
       for a sensor; a desktop analyzer process stays well under 1 GiB
       with the overhead measured in section 7.4.
   * - ``max_flows``
     - 65,536
     - Suricata's default flow hash size. Empty flows alone are then
       charged 64 MiB at a 1 KiB ``FLOW_OVERHEAD``, half the byte cap,
       so a SYN flood cannot take the whole budget either way.
   * - idle timeout, new
     - 60 s
     - A flow that has not carried data in both directions. Suricata's
       ``flow-timeouts.tcp.new``. Bounds a half-open flood in time as
       the caps bound it in space.
   * - idle timeout, established
     - 3,600 s
     - Suricata's ``flow-timeouts.tcp.established``. Long enough for a
       BGP session's keepalive interval and an idle keep-alive HTTP
       connection.
   * - idle timeout, closed
     - 120 s
     - After FIN in both directions, or RST. Suricata's
       ``flow-timeouts.tcp.closed``, and one Maximum Segment Lifetime
       (RFC 9293 §3.4.2), long enough to see late retransmissions and
       the data-after-RST of section 4.4.
   * - age timeout
     - none
     - See below.

The Suricata figures are its documented
`defrag and flow defaults <https://docs.suricata.io/en/latest/configuration/suricata-yaml.html#ip-defrag>`__.

**Decision needed: a total-age timeout for TCP.** *Recommendation:*
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
  change nothing.
- *Exact duplicate, IPv6* (same offset, length and bytes): the same.
  RFC 8200 §4.5 allows exact duplicates to be dropped rather than
  treated as overlaps.
- *Differing bytes, IPv4*: the target's policy decides which version
  each byte keeps, and an ``Overlap`` event reports the range, both
  versions and both sets of spans. The datagram goes on.
- *Any other overlap, IPv6*, whether or not the bytes differ: the
  datagram is abandoned. ``Overlap`` (``resolved=False``) reports it,
  with ``kept`` and ``other`` equal when the bytes agree; the held
  fragments are dropped and the key is replaced by a *discard marker*
  until the datagram's age timeout. RFC 5722 §4
  requires discarding "any constituent fragments, including those not
  yet received", so a fragment arriving for a marked key is dropped with
  ``Anomaly(kind=FRAGMENT_AFTER_DISCARD)``. A marker is charged
  ``FLOW_OVERHEAD`` and counts against ``max_flows``.

Policies resolve overlaps when a fragment arrives, against the held
fragments it overlaps, so held state is always one non-overlapping
version of each byte plus the spans that supplied it.

3.4 Named policies
~~~~~~~~~~~~~~~~~~

The names are the target-based set of Snort's frag3 and Suricata's
defrag engine, from Novak's *Target-Based Fragmentation Reassembly*
(2005). "Held" is a fragment already stored; "arriving" is the one
being fed.

.. list-table::
   :header-rows: 1
   :widths: 13 52 35

   * - Policy
     - Which bytes win an overlap
     - Targets, as frag3 documents them
   * - ``first``
     - Held, always.
     - Mac OS, HP-UX 11.00
   * - ``last``
     - Arriving, always.
     - Cisco IOS
   * - ``bsd``
     - Held, where the held fragment begins at or before the arriving
       one; arriving, where the held fragment begins after it.
     - AIX, FreeBSD, HP-UX 10.20, IRIX, OpenBSD, OpenVMS, OS/2, OSF/1,
       SunOS 4.1.4, Tru64
   * - ``bsd-right``
     - A variant of ``bsd`` that favours the arriving fragment in
       overlaps at a held fragment's right end.
     - HP JetDirect printers
   * - ``linux``
     - As ``bsd``, except that the arriving fragment also wins over a
       held one that begins at the same offset.
     - Linux 2.4 and 2.6
   * - ``windows``
     - Held, except over a held fragment the arriving one begins before
       and ends after, which the arriving one replaces.
     - Windows 95 to XP
   * - ``solaris``
     - Held, except over a held fragment the arriving one begins before
       and ends at or after the end of, which the arriving one
       replaces.
     - Solaris 2.5.1 to 8

These model the stacks Novak measured. Some current stacks discard an
IPv4 datagram whose fragments overlap, as RFC 5722 requires for IPv6;
a ``discard`` policy would model them, and is the IPv6 path applied to
IPv4.

**Decision needed: which named policies to offer.** *Recommendation:*
for IPv4 fragments, ``first`` (the default), ``last``, ``bsd``,
``linux``, ``windows``, ``solaris`` and ``discard``; not ``bsd-right``.

- The six Novak policies other than ``bsd-right`` cover every general-
  purpose operating system frag3 lists, and Novak's paper gives one
  fragment pattern with the expected output under each, so each costs
  one table row in the tests (section 7.2), not a separate design.
- ``discard`` costs nothing beyond the IPv6 path already required, and
  is the right model for stacks that follow RFC 5722's reasoning on
  IPv4 too.
- ``bsd-right`` models one printer family, and its rule is the least
  well documented of the set: its exact behaviour would have to be
  established by testing a JetDirect, which no netns script can do.
  Adding it later is one more enum value, with no API change.

*Trade-off:* a caller who must emulate an HP JetDirect, or a stack not
on the list, gets the nearest policy and still sees every disagreement
as an ``Overlap`` event. The policies describe historical stacks, so
the guarantee that matters is the event, not the emulation.

3.5 Rules applied to each fragment
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The response to each rule is either *discard* (the fragment, or the
datagram, as a receiver must) or *report* (an ``Anomaly``, and the
fragment is used).

.. list-table::
   :header-rows: 1
   :widths: 30 35 35

   * - Condition
     - Response
     - Source
   * - Fragment would end past 65,535 bytes: IPv4 header + offset × 8
       + data length; IPv6 Unfragmentable Part + offset × 8 + data
       length.
     - Discard the datagram: ``Anomaly(OVERSIZE)``, whose spans are
       the fragments held and the arriving one. This is the "ping of
       death".
     - RFC 791 §3.1; RFC 8200 §4.5
   * - IPv6 fragment with M set whose data length is not a multiple
       of 8.
     - Discard the fragment, ``Anomaly(MISALIGNED)``.
     - RFC 8200 §4.5
   * - IPv4 fragment with MF set whose data length is not a multiple
       of 8.
     - Discard the fragment, ``Anomaly(MISALIGNED)``: no conforming
       fragmenter produces it, since every non-final fragment ends on
       an 8-octet boundary.
     - RFC 791 §2.3
   * - Last fragment (MF/M clear) disagrees with an end already known,
       or data lies past a known end.
     - Discard the datagram, ``Anomaly(INCONSISTENT_END)``. The
       datagram has no single length.
     -
   * - Fragment with no data.
     - Discard the fragment, ``Anomaly(EMPTY_FRAGMENT)``.
     -
   * - IPv6 first fragment that does not hold the whole header chain
       through the upper-layer header.
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
- IPv6: the Unfragmentable Part is the first fragment's headers up to
  the Fragment header; the Next Header of its last header is set to
  the Fragment header's Next Header; the Fragment header is removed;
  and Payload Length is recomputed, all as RFC 8200 §4.5 specifies. A
  Fragment header later fragments carry differently is not used.

``header_len`` is the length of that header (IPv4) or of the IPv6
header plus the Unfragmentable Part's extension headers.

**Decision needed: a synthesized header, or the payload only.** The
datagram's header is new bytes: no captured frame holds it. The decode
contract still holds for it, as for any input:
``bytes(IPv4.decode(event.data)) == event.data[:event.header_len]``. What
does not hold is any equality with a captured header: re-encoding the
first fragment's decoded IPv4 header gives the first fragment's bytes,
which differ in Total Length, flags, offset and checksum.
The alternative is to emit the reassembled payload plus the first
fragment's header as captured, and let the caller build a header.

*Recommendation:* the synthesized header, with ``header_ref`` naming
the frame it came from, and the rules above documented on the event.
It is what a receiving stack hands up, it decodes with the existing
walk and no glue, and it gives the checksum helpers a header whose
length covers the whole message, which ARCHITECTURE's checksum section
requires for a message reassembled from IPv6 fragments. *Trade-off:*
the event's bytes are not wire bytes, and a caller that diffs output
against the capture must know which four fields were rewritten. The
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
closed, starts a new connection under the same key.

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

**Decision needed: pick up mid-stream by default.** *Recommendation:*
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

**Decision needed: implement PAWS.** *Recommendation:* no. PAWS only
matters when 2\ :sup:`32` bytes cross a direction within one segment
lifetime, which at the default idle and cap sizes makes a stale
segment land beyond the window and be reported anyway; and a passive
observer applying PAWS where the target does not, or the reverse, is
itself an ambiguity (section 5). *Trade-off:* on a fast link a
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
- *Data without ACK*: a segment other than a SYN with the ACK bit
  clear is dropped, as a receiver must
  (`RFC 9293 §3.10.7.4 <https://www.rfc-editor.org/rfc/rfc9293.html#section-3.10.7.4>`__),
  with ``Anomaly(DATA_WITHOUT_ACK)``.
- *FIN*: data on the FIN segment is stream data. The FIN fixes the
  direction's end at its sequence number plus its data length. When
  delivery reaches that end, ``StreamEnd(reason=FIN)``. A later FIN
  at a different sequence number is ignored with
  ``Anomaly(INCONSISTENT_FIN)``; data past the end is dropped with
  ``Anomaly(DATA_AFTER_FIN)``; holes before the end may still fill.
- *RST*: contiguous data is delivered, then ``StreamEnd(reason=RST)``
  for both directions; the connection moves to the closed timeout
  instead of being removed. Data on an RST is diagnostic text, not
  stream data
  (`RFC 1122 §4.2.2.12 <https://www.rfc-editor.org/rfc/rfc1122.html#page-87>`__),
  and is reported as ``Anomaly(RST_WITH_DATA)``. Data that arrives in
  sequence after an RST is still reassembled and delivered, with
  ``Anomaly(DATA_AFTER_RST)``: whether the target accepted the RST
  depends on its window check
  (`RFC 5961 §3 <https://www.rfc-editor.org/rfc/rfc5961.html#section-3>`__),
  which a capture cannot show, and tearing state down on an RST is the
  evasion Ptacek & Newsham describe.

4.5 Windows and overlaps
~~~~~~~~~~~~~~~~~~~~~~~~

When both SYNs were seen with their Window Scale options
(`RFC 7323 §2.2 <https://www.rfc-editor.org/rfc/rfc7323.html#section-2.2>`__),
the reassembler tracks each receiver's right window edge from the
other direction's ACK and window fields. Data past the furthest edge
seen is ``Anomaly(OUT_OF_WINDOW)`` and is still stored, subject to the
caps: a capture can miss the window update that made it valid, and
dropping it would lose real data on a lossy capture. Without both
SYNs, no window check is made.

Overlapping segments follow the fragment rules of section 3.3:
identical bytes are a ``Retransmission``, differing bytes an
``Overlap`` resolved by the receiver's policy.
``StreamReassembler`` offers ``first`` (the default) and ``last``.
The Novak policies describe IP fragment reassembly; operating systems'
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

**Decision needed: when to deliver.** Delivering on contiguity (the
issue's "as they become available") delivers before a later, differing
retransmission can be seen. The alternative delivers a run only once
the receiver has acknowledged it, as Suricata hands data to its
application-layer parsers, so overlaps arriving before the ACK are
resolved by policy first. *Recommendation:* deliver on contiguity, with
the ``contrary`` flag, and offer ACK-gated delivery later as an option.
Contiguity delivery makes the completing frame the frame that carried
the last byte, which is what RootWire attaches messages to; ACK-gating
would make it the peer's ACK, and delivers nothing for a one-sided
capture without a fallback. *Trade-off:* under ``last``, and under any
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
offset: the message occupies ``[offset, offset + message.header_len)``,
and the spans of the runs that overlap that range are its frames, the
last of them its completing frame. A desynchronized buffer (a
``Gap`` inside a message, or a decoder error other than truncation) is
the caller's to resynchronize, as a protocol decoder's framing rules
are.

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

**Decision needed: the default for bad checksums.** ``ChecksumMode``
has ``DROP`` (the piece is not used) and ``KEEP`` (it is used); both
emit ``Anomaly(BAD_CHECKSUM)``. *Recommendation:* ``DROP``. It closes
the insertion, matches Suricata's ``checksum-validation: yes`` default
and this library's habit of validating, and the anomaly tells a caller
reading an offloaded capture exactly why a direction is empty.
*Trade-off:* such a caller must pass ``checksums=ChecksumMode.KEEP``,
and a capture mixing both kinds has no right setting for both.
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
     - Datagram discarded and later fragments refused (RFC 5722 §4);
       ``Overlap`` with ``resolved=False``.
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
     - Discarded, ``Anomaly(OVERSIZE)``.
   * - Fragment timeout desynchronization (the observer and the target
       time out at different moments)
     - Age timeout of 60 s from the first fragment; every abandoned
       datagram is an ``Expired`` event with its spans and holes, so a
       train completed after the observer gave up is visible as an
       ``Expired`` followed by a new datagram under the same key.
   * - Inconsistent last fragment or length
     - Datagram discarded, ``Anomaly(INCONSISTENT_END)``.
   * - Data on SYN
     - Delivered, ``Anomaly(SYN_DATA)`` (section 4.4).
   * - SYN resent with a new ISN (desynchronization)
     - ``Anomaly(ISN_CHANGED)``; ISN replaced only before data
       (section 4.4).
   * - Spoofed or out-of-window RST tearing down observer state
     - State kept for the closed timeout, later data delivered with
       ``Anomaly(DATA_AFTER_RST)``.
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
   * - IPv6 overlap to plant discard markers
     - Markers are charged and count against ``max_flows``; they
       expire with the age timeout.
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
``96eee3d``:

.. list-table::
   :header-rows: 1
   :widths: 14 30 56

   * - Line
     - Topic
     - Change
   * - 785
     - SCTP user messages
     - SCTP reassembly stays the caller's; only the comparison "as for
       HTTP over TCP" changes, to say that a TCP stream can be
       reassembled by ``netprotocols.reassembly`` and an SCTP message
       cannot.
   * - 1015
     - TFTP transfer tracking
     - Tracking the transfer stays the caller's; "as reassembly is for
       ``HTTP`` and ``BGP``" becomes "as reassembling the stream is for
       ``HTTP`` and ``BGP``, unless ``netprotocols.reassembly`` does it".
   * - 1196-1197
     - BGP messages across segments
     - "the caller's, or ``netprotocols.reassembly``'s".
   * - 1273-1274
     - TLS ClientHello spanning segments
     - The SNI comes from reassembling the stream, "yourself or with
       ``netprotocols.reassembly``", and ``TLS.decode()`` on that.
   * - 1314
     - TLS handshake messages across records
     - Unchanged: record-layer reassembly is out of scope (section 4.9).
   * - 1339
     - HTTP
     - "Reassemble the connection, with ``netprotocols.reassembly`` or
       your own, and call ``HTTP.decode()`` on its bytes."
   * - 1412-1413
     - Checksums of a message reassembled from IPv6 fragments
     - Add that a ``Datagram``'s IPv6 header has a Payload Length that
       covers the reassembled datagram, so it serves as ``ip``.

Also: a new section after "Port-based dispatch is best-effort" that
states the module's contract (sections 1 to 4 of this note, as
shipped), a sentence in "The decode contract" that ``decode()`` stays
stateless and the reassemblers are the library's only stateful
objects, and a ``reassembly.py`` entry in "Layout map".

6.2 README.md, SECURITY.md and docstrings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- README line 194 (BGP, "no reassembly"), 196 (TLS, "read from a
  reassembled stream"), 197 (HTTP, "from a buffer you reassembled")
  and 343 ("Decoding HTTP": "which you reassemble"): each names
  ``netprotocols.reassembly`` as one way to get the stream. A new
  section, "Reassembling fragments and streams", holds the loop of
  section 1.6 and the bounds table.
- SECURITY.md lines 50-51, 58-59 and 63, which put TCP reassembly and
  segment-overlap tricks outside ``HTTP``'s, ``BGP``'s and ``TLS``'s
  scope: they stay outside the decoders' scope, and a new paragraph
  puts them in the module's: state beyond the documented bounds, an
  inconsistent overlap resolved without an ``Overlap`` event, an event
  missing a contributing or completing frame, or output that depends on
  anything but the input and its timestamps.
- Docstrings that say the same: ``layer7/http.py`` lines 7-8,
  ``layer7/bgp.py`` 66, ``layer7/stun.py`` 130, ``layer7/tls.py`` 75,
  113, 116 and 601, and ``checksum.py`` 74-75 and 738-739.
  ``layer7/tftp.py`` 76 and ``layer4/sctp.py`` 62 and 531 stay:
  transfer tracking and SCTP reassembly are not the module's.

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
  <operating system> does". The named policies follow Novak's 2005
  measurements, not current kernels.

6.4 Package exports
~~~~~~~~~~~~~~~~~~~

**Decision needed: re-export from** ``netprotocols``. *Recommendation:*
no. The reassemblers are reached as ``netprotocols.reassembly`` and
``import netprotocols`` does not import them, so the per-frame decoder
pays no import cost (CLAIMS §1.4) and the stateful API is visibly
separate from the stateless one. *Trade-off:* one more import line for
callers, and ``tests/test_exports.py`` records the module as a public
submodule rather than top-level names.

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

A generator, ``scripts/craft_reassembly_overlaps.py``, rewrites
datagrams from the real captures into overlap cases and writes them as
pcaps, each labelled **crafted** in MANIFEST with the generator and the
source frame:

- Novak's fragment pattern, once per offered IPv4 policy, with the
  expected reassembled bytes in a table in the test, one row per
  policy, taken from Novak's paper;
- the same pattern over IPv6, expecting the RFC 5722 discard and the
  refusal of a later fragment;
- identical duplicates (``Retransmission``, no ``Overlap``) for both
  versions;
- RFC 1858 tiny-fragment and offset-1 cases, an oversized datagram,
  a misaligned fragment, two inconsistent last fragments and an IPv6
  first fragment with a split header chain;
- TCP: a retransmission with different bytes, before and after
  delivery, under ``first`` and ``last``; data after FIN; data after
  RST; a SYN with a changed ISN; a sequence wrap inside a stream;
  data without ACK; a bad checksum under both ``ChecksumMode`` values.

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

- tshark: the capture script records ``ip.reassembled_in``,
  ``ipv6.reassembled.in``, ``ip.reassembled.data`` and
  ``ipv6.reassembled.data`` for each fragment capture, and
  ``-z follow,tcp,raw`` for each connection, into committed files
  beside the captures, with the tshark version in MANIFEST. The tests
  compare ``Datagram.data``'s payload and ``completing_ref`` with
  tshark's reassembled data and reassembled-in frame, and the
  concatenated ``StreamData`` with the followed stream, so CI needs no
  tshark. On the crafted captures, ``ip.fragment.overlap.conflict``
  must flag the frames ``Overlap`` names.
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
  and an ``Overlap`` under every policy; IPv6 discards;
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
  frame that carried its last byte;
- the crafted TCP cases of section 7.2 and the stream properties of
  section 7.5;
- the SYN-flood memory bound of section 7.4;
- the remaining documentation changes of section 6 (HTTP, TLS, BGP,
  SECURITY.md, docstrings) and CHANGELOG entries.

Follow-ups, filed when wanted: per-OS TCP overlap policies with
reference vectors, ACK-gated delivery, PAWS, and ``bsd-right``.


.. _reassembly-decisions:

Decisions needed
----------------

.. list-table::
   :header-rows: 1
   :widths: 6 30 64

   * - #
     - Decision
     - Recommendation
   * - 1
     - Input type (1.1)
     - The decoded ``Packet`` and its frame.
   * - 2
     - Type of a frame reference (1.3)
     - ``int``, defaulting to the feed count.
   * - 3
     - TCP total-age timeout (2.5)
     - None by default, settable.
   * - 4
     - Named IPv4 fragment policies (3.4)
     - ``first`` (default), ``last``, ``bsd``, ``linux``, ``windows``,
       ``solaris`` and ``discard``; not ``bsd-right``.
   * - 5
     - Reassembled IPv4 header (3.6)
     - Synthesized from the first fragment, with ``header_ref``.
   * - 6
     - Mid-stream pickup (4.2)
     - On, with ``Anomaly(MIDSTREAM)``.
   * - 7
     - PAWS (4.3)
     - Not implemented.
   * - 8
     - When to deliver TCP data (4.6)
     - On contiguity, with ``Overlap.contrary``; ACK-gating later.
   * - 9
     - Bad checksums (5.1)
     - ``ChecksumMode.DROP``.
   * - 10
     - Re-export from ``netprotocols`` (6.4)
     - No; ``netprotocols.reassembly`` only.

The defaults of section 2.5 are proposed for acceptance with these.
