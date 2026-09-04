# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Development
- **The round-trip property (`bytes(decode(x)) == x`) is now
  Hypothesis-generated for all 18 protocols, not 4.** It previously
  held only for `Ethernet`, `UDP`, `TCP` and `IPv6Fragment`; the other
  14 rested on a single example each. `tests/strategies.py` adds one
  reusable strategy per protocol — reusable because a strategy that
  generates *valid* instances is useful for more than this one
  property — and `tests/test_fuzz.py::TestGeneralizedRoundTrips`
  asserts the property in one method, parametrized over all 14.

  The interdependent-field protocols the issue specifically flagged
  are generated as *consistent* combinations, never independently: IPv4
  draws `ihl` first and sizes `options` to match; the three IPv6
  extension headers draw `hdr_ext_len` first and size their TLV bytes
  to match; GRE draws `flags` first and computes `fields`' length from
  the same `_optional_len()` the decoder itself uses, so the two can
  never silently disagree.

  The 14 single-example assertions already living in each protocol's
  own test file (`test_arp.py::test_round_trip` and so on) are kept as
  regression anchors — a fixed example pinned to a real captured header
  catches a specific regression fast and readably, which a generated
  property does not replace.

  One adjacent gap closed while surveying this: `DHCP` and `GRE` were
  missing from `test_fuzz.py::ALL_PROTOCOLS` entirely, so neither had
  ever been fuzzed with untrusted bytes for basic decode safety (`any
  input either decodes or raises ProtocolError, never anything else`).
  Both are now included.

### Added
- **`match`/`case` dissection is documented.** It already worked on
  every decoded header, with zero code changes needed — a frozen
  dataclass auto-generates `__match_args__`, and every field with a
  fixed wire vocabulary is an `IntEnum`, so a value pattern binds the
  plain `int` the decoder stored. None of that appeared anywhere:

  ```python
  match packet.layers:
      case [_, IPv4(protocol=IPProtocol.TCP) as ip, TCP(flags_str=f), *_] \
              if "SYN" in f and "ACK" not in f:
          print(f"connection attempt from {ip.src}")
  ```

  README gains a first-screen example and a dedicated section;
  ARCHITECTURE.md explains the two mechanisms and the two ways a
  contributor can quietly break them (reordering a class's fields
  changes what a positional pattern binds to; degrading a fixed-
  vocabulary field from `IntEnum` to a bare `int` makes a value
  pattern stop matching without raising). `tests/test_pattern_matching.py`
  pins both mechanisms directly and runs the README's own example over
  the corpus, so a regression in either is caught rather than
  incidental.

- **Structured diagnostics on every `ProtocolError`.** Every exception
  used to carry only a formatted string — the full attribute set on a
  raised `TruncatedHeaderError` was `args`, `add_note`,
  `with_traceback`. A fuzzing harness, conformance suite, or
  protocol-validation tool that wanted to know *where* a parse failed
  had to regex the message. Every raise site in `src/` now attaches:

  ```python
  try:
      packet = decode_frame(frame)
  except ProtocolError as e:
      print(e.protocol, e.field, e.offset, e.frame_offset, e.expected, e.actual)
      # <class 'netprotocols.layer3.ip.IPv4'> ihl 0 14 >=5 0
  ```

  - `protocol` — the class that raised. Set on every single raise site.
  - `field` — the attribute at fault, where one field is at fault.
  - `offset` — byte offset of the problem, relative to the `decode()`
    buffer for a fixed-header error, or to the `field` attribute
    (`options`, `body`, `sections`) for an on-demand parse — a TCP
    option error's offset is relative to `header.options`, not the
    frame. `None` for a `__post_init__` validation error, which sees
    field values, never the bytes they came from.
  - `frame_offset` — `offset` rebased to the whole captured frame.
    `decode_frame` is the only code holding the cursor needed to do
    this, so it's the only thing that sets it; a bare
    `SomeClass.decode()` call leaves it `None`.
  - `expected` / `actual` — added wherever there's a concrete pair to
    state beyond the message text.

  All five default to `None`, and **no message string changed** — every
  existing `str(err)` and `match=` assertion holds. New public name:
  `MaxDepthExceededError` gains the same attributes as every other
  `ProtocolError` subclass (it already existed as of the `decode_frame`
  work; this is the first release to give it structured context too).

- **`decode_frame()`: the chain walker ships with the library.** The
  README taught a hand-rolled eight-line loop, ARCHITECTURE.md showed
  it again, and the test suite kept its own copy — so the library's
  most-used function was the one function it did not provide. It does
  now, with the parts a copy-pasted loop never has:

  ```python
  from netprotocols import decode_frame

  packet = decode_frame(frame)     # Packet(Ethernet(...), IPv4(...), TCP(...))
  frame[packet.consumed:]          # whatever the chain did not decode
  ```

  - **An explicit starting layer.** `decode_frame(buf, start=IPv4)`
    walks a buffer that begins mid-stack — a tunnel payload, a packet
    quoted inside an ICMP error, a non-Ethernet link type. There was
    previously no way to ask for this.
  - **Bounded depth.** `max_depth` (default 32) caps the chain and
    raises the new `MaxDepthExceededError`, rooted at `ProtocolError`
    like everything else. Every header already validated its own
    length, so a chain always terminated; the bound turns a crafted
    frame's very long walk into an immediate named error. The deepest
    chain in the 97-frame corpus is 5.
  - **A lax mode that reports instead of raising.** `lax=True` ends the
    walk on a `ProtocolError` and returns the layers decoded so far,
    with the reason on `packet.stopped_by` — what a capture tool needs
    when frame 4,000,001 is malformed. It relaxes the *walk*, never a
    decoder: every layer returned was decoded under the ordinary strict
    rules.
  - **Per-call decoder overrides.** `decode_as={"udp.port": {6969: DNS}}`
    reads DNS on a nonstandard port for one call, without touching
    global state; `registry=` takes a prepared registry for bulk work.

  `Packet` gains `stopped_by` (why a walk ended early, `None` for a
  packet you built) and `consumed` (the bytes its headers occupy).
  Both default to the constructed-packet values, so `Packet(eth, ip)`
  is unchanged.

  On `memoryview`: the walker slices what it is given and does not
  convert. Measured on the corpus, wrapping each frame in a
  `memoryview` runs at **0.95x** the plain-`bytes` walk — for one small
  frame the view costs more to build than the copy it saves — while a
  `memoryview` over a large capture buffer keeps slices zero-copy.
  Converting internally would have been worse than either.

- **A public protocol registry: third parties can now extend the decode
  walk without editing library source.** Dispatch was four hardcoded
  functions with dict literals inside them and no hook of any kind — a
  protocol this library does not implement (MPLS, VXLAN, a proprietary
  telemetry header) could only be added by forking. It is now five named
  tables owned by `netprotocols.registry`, and registering against one
  is all it takes:

  ```python
  from netprotocols.registry import register

  @register("ethertype", 0x8847)
  class MPLS(Protocol):
      ...

  register("ip.proto", 132, SCTP)   # for a class you did not write
  ```

  The tables are `ethertype`, `ip.proto`, `ip.proto.v6`, `udp.port` and
  `tcp.port`, each named after the wire field it dispatches on.
  `ip.proto.v6` **inherits** `ip.proto`, which is how the IPv6-only
  gating generalises: the four extension headers are registered in the
  v6 table alone, so an IPv4 packet with `protocol=0` still cannot
  conjure a Hop-by-Hop layer — and because inheritance is resolved at
  registration rather than at lookup, the gating costs nothing on the
  hot path. Dispatch behaviour is unchanged entry for entry.

  Registrations land in the process-wide `DEFAULT` registry;
  `Registry.from_defaults()` gives an isolated one for embedding or test
  isolation, and `Registry.derive()` makes a copy-on-write child.
  Registering over an existing key raises `RegistryConflictError` unless
  `override=True` is passed, so two packages claiming the same port
  cannot silently resolve by import order; re-registering the *same*
  class to the same key is a no-op, since a decorator re-runs whenever
  its module does.

  New public names: `Registry`, `register`, `register_all`, `DEFAULT`,
  `RegistryConflictError`, `UnknownTableError`.

### Changed
- **`next_protocol()` accepts an optional registry.** Threading a
  per-call registry through the walk needs the dispatch to be
  redirectable, and `next_protocol()` read the process-wide tables
  directly. It now takes `registry=None`, passed to the same dispatch
  helpers as before, so no table knowledge is duplicated and the
  default path stays a single `dict.get`. Measured in one process, the
  optional parameter costs **+2.1 ns** per dispatch — roughly 0.1% of a
  frame decode. Every existing zero-argument call is unaffected.
- **Port-based dispatch is a table lookup rather than a rebuild.**
  `udp_app_class` and `tcp_app_class` re-ran their deferred imports and
  rebuilt a `dict` literal on every call — they were outside the scope
  of the earlier dispatch-hoisting work, which named only the EtherType
  and IP-protocol functions. Both now read the registry's flat tables:
  `udp.port` 303.1 → 46.0 ns (6.6x), `tcp.port` 186.8 → 45.1 ns (4.1x),
  measured old and new shapes in one process. `ethertype` loses its
  lazy-build guard (51.8 → 47.7 ns) and `ip.proto` is unchanged, having
  already been a table. Corpus throughput moves about 1% — only 28 of
  the 97 corpus frames reach a transport header and therefore do a port
  dispatch at all — which is below this machine's run-to-run noise; the
  per-call figures above are the measurement that resolves.
- **The layer modules no longer import each other's classes.** The
  built-in decoder map moved into `_defaults.py`, which registers it
  once from `__init__.py` after every protocol class exists, so the
  function-body imports that kept the module graph acyclic are gone
  from `vlan.py`, `gre.py`, `tcp.py`, `udp.py` and `ipv6_ext.py`; those
  dispatch helpers are now ordinary module-level imports. The tables
  are built at package import instead of on first dispatch, so the
  lazy-build branch is off the hot path entirely.
- **DNS section parsing happens once, and no longer re-serializes the
  message to read it.** Six helpers called `bytes(self)` — a full
  re-serialization of the whole message — so a single `.answers` access
  rebuilt the message 14 times; and `answers`, `authorities` and
  `additionals` each re-parsed *all three* sections, so reading all
  three parsed the message three times. The parsers are now module-level
  functions working directly from the `sections` bytes the instance
  already holds, in section-relative offsets (a compression pointer,
  which counts from the start of the message, is translated once), and
  the three accessors share a single parse cached on those immutable
  bytes. Measured here on a corpus response: `.answers` 16.84 → 0.20 us,
  all three sections 52.08 → 0.54 us, and one uncached parse 17.03 →
  12.17 us from dropping the re-serializations alone. Nothing is stored
  on the frozen instance — the cache is a bounded module-level memo
  keyed by value, so equal messages share a parse and records (frozen
  dataclasses) are shared rather than copied. The byte-exact round-trip
  is unchanged. A compression pointer that addresses the fixed header
  now raises `InvalidFieldError` instead of decoding header bytes as
  labels. No API change.
- **The decoder no longer re-validates the addresses it just
  generated.** Every header's `__post_init__` ran the address
  validators, including for instances built by `decode()` — so a MAC
  mechanically rendered from six bytes by `bytes_to_mac()` was
  immediately matched against `mac_regex` to confirm what the
  conversion had already guaranteed. `Ethernet`, `ARP` and `IPv4` now
  build their decoded instance directly (`object.__new__` plus
  `object.__setattr__` per field), skipping `__init__` and
  `__post_init__` on that path only. Measured here: `Ethernet.decode`
  2330 → 830 ns (2.8x), `IPv4.decode` 4936 → 2596 ns (1.9x), a corpus
  walk 76,500 → 113,200 frames/sec (1.48x). **Strictness on
  construction is unchanged** — every public constructor still
  validates and still raises, which is now asserted alongside a test
  that the decode path runs no regex at all. The `__post_init__` checks
  bypassed this way are ones `decode()` establishes itself (documented
  at each site and in `_base.py`). No API change.
- **Protocol dispatch is a table lookup, not a table construction.**
  `_ethertype_class()` and `_ip_protocol_class()` re-ran their deferred
  imports and rebuilt a `dict` literal on *every* call — once per layer
  per frame, the hottest path in the library. Both now populate a
  module-level table on first use (the imports stay deferred, so the
  layer modules remain acyclic) and reduce the call to a lookup.
  Measured here: `_ip_protocol_class` 1439 → 104 ns (13.9x),
  `_ethertype_class` 712 → 86 ns (8.3x), and a corpus walk 58,300 →
  76,500 frames/sec (1.31x). The IPv6-only gating is unchanged: the
  IPv4 table simply omits those numbers, so an IPv4 packet with
  `protocol=0` still cannot decode a Hop-by-Hop layer, now asserted at
  the table level as well as through the public API. No API change.
- `bytes_to_mac` renders addresses with `bytes.hex(":")` instead of a
  generator over `format()`. The old form ran seven generator steps and
  six `format()` calls per address, twice per Ethernet frame, and showed
  up in a corpus profile as 88,200 generator calls. Measured 16–29×
  faster on the call depending on run. Output is byte-for-byte
  identical, and `memoryview.hex` takes a separator too, so a
  decode-time view still works. No API change.

### Removed
- **BREAKING: `Packet.payload` is gone.** It was always exactly
  `bytes(self)` — a redundant duplicate of `__bytes__`/`bytes(packet)`,
  which already existed and is the unambiguous spelling — so it is
  deleted outright rather than deprecated. This is the breaking change
  behind the 2.0.0 major bump. Replace `packet.payload` with
  `bytes(packet)`.

### Added
- **`Packet` indexes by protocol type, not just position, and is
  hashable.** `packet[TCP]` returns the first `TCP` layer in wire order
  (`KeyError` if there is none); `packet.get(TCP)` returns `None`
  instead of raising. `packet[0]` keeps indexing positionally —
  `__getitem__` branches on whether the key is an `int` or a type.
  `Packet.__hash__` mirrors exactly what `__eq__` already compares
  (`layers`, and `stopped_by`'s type and `str()`, not its identity —
  `ProtocolError` has no custom `__eq__`), so a `Packet` is now usable
  as a dict key or set member.

### Fixed
- **The release workflow can no longer publish untested code.** Pushing
  a `v*` tag ran `uv build` and `uv publish` with no dependency on the
  lint, typecheck or test jobs — and because the CI workflow triggers
  only on pushes and pull requests targeting `master`, a tag push ran
  **no checks at all**. A tag against broken code published to PyPI
  unchallenged, and a published version can only be yanked, never
  replaced. `ci.yml` is now also a reusable workflow (`workflow_call`),
  and `release.yml` invokes it against the tagged commit with the
  publish job gated behind it, so the release gate and the pull-request
  gate are one definition and cannot drift apart.

### Fixed
- **A mistagged release can no longer publish the wrong version.**
  `release.yml` built from `pyproject.toml` and never consulted the tag,
  so pushing `v1.4.0` while the project still read `1.3.0` would either
  fail at upload against an existing version or, if that version was
  never released, silently publish the wrong one. The QA ladder cannot
  catch this — every check passes, because the code is fine and only the
  tag is wrong. The release now reads the version back out of the built
  artifact and refuses to publish unless it matches the tag.
- **The README no longer advertises shipped work as upcoming.** Its
  Roadmap section listed the eight decoder-depth items tracked by #67 —
  all of which shipped in 1.3.0, with #67 itself closed — so the front
  page presented finished work as planned and pointed readers at a
  closed issue. It now links the current roadmap (#107) and its five
  release-mapped epics instead of restating individual items, which is
  what went stale.
- **ARCHITECTURE.md no longer misstates the corpus or the source
  layout.** It described "93 frames across 16 scenarios" long after the
  corpus reached 97 across 17, and its layout map omitted `vlan.py`,
  `gre.py` and `dhcp.py`. The counts now live in
  `tests/fixtures/MANIFEST.md` and the README alone — ARCHITECTURE.md
  points at the MANIFEST rather than keeping a third copy, which is
  what drifted.
- **Layer sub-packages now export everything their layer defines.**
  `from netprotocols.layer7 import DHCP` failed while
  `from netprotocols import DHCP` worked, because each layer's own
  `__init__` carried a subset of what the top-level package re-exports.
  `layer3` was missing `GRE`, `IPv4Option`, `IPv6Option`, `NDPOption`
  and `IGMPv3GroupRecord`; `layer4` was missing `TCPOption`; `layer7`
  exported only `DNS`, omitting `DHCP`, `DNSOverTCP` and
  `DNSResourceRecord`. Purely additive — no name changed meaning.

### Development
- **Comparative claims are under embargo until the roadmap closes.**
  `docs/CLAIMS.md` gains a standing rule and a per-claim
  `COMPARATIVE — HELD` marker: nothing mentioning scapy, dpkt or any
  other library reaches the README, release notes or package metadata
  until #107 is finished. The measurements keep being recorded — the
  register exists to hold evidence, not to publish it — and ship once,
  together, rather than in pieces that each need defending. The
  rationale is in the numbers: claim 1.2 went from "2.9x slower than
  dpkt" to "1.16x faster" inside a single tier.
- Three differentiators found during Tier 1 are now tracked as claims
  rather than living in pull-request descriptions: decode depth (1.6 —
  the corpus walk reaches a deeper layer than dpkt on 27 of 97 frames,
  reproducible with `scripts/benchmark.py --depth`, which this change
  adds), the CI throughput gate (1.7), and strict construction on a
  decode path that pays nothing for it (5.4). The stale "we are ~86% of
  dpkt" line in "Claims we must not make" is corrected, and a rule
  added that a superiority claim must name its axis — scapy crafts,
  sends and covers thousands of protocols, so the codec axes are where
  the evidence is.
- **A reproducible decode benchmark, and a CI job that fails on a
  regression.** `scripts/benchmark.py` walks the 97-frame corpus and
  reports frames/sec; `--compare` times `dpkt` and `scapy` on the same
  frames (both dev-only extras in a new `bench` dependency group — the
  package still has zero runtime dependencies). Because absolute
  throughput is a property of the machine, every run also times a fixed
  calibration workload and reports a normalized figure, which is what
  `--check` compares against `benchmarks/baseline.json`. **The CI job
  blocks at 15% below the baseline**: measured, that is about four
  times the noise it must tolerate — the job's first run landed 3.7%
  from a baseline recorded on entirely different hardware, and
  run-to-run spread on one machine is ~2%, while the Tier 1 changes
  moved the number by 30-90% each. A failing check re-measures once
  before failing, so a runner that loses CPU to a neighbour does not
  block an unrelated pull request. Comparison output carries its own
  caveats — notably that the libraries are not asked for identical
  work, since dpkt leaves the DNS-over-TCP payload as raw bytes where
  this library decodes it — because a benchmark nobody can check is the
  problem #86 set out to fix, not the goal.
- `tests/test_version.py` holds `netprotocols.__version__` against the
  version in `pyproject.toml`. The two were kept in step by hand and
  nothing checked them, so a bump that missed one would ship a package
  whose metadata and `__version__` disagree.
- `tests/test_docs.py` holds documented facts against the fixtures:
  the MANIFEST's and README's frame/scenario counts must match the real
  corpus, ARCHITECTURE.md must not reintroduce a third copy of them,
  and the layout map must mention every shipped module. It also
  guards the README's Roadmap section against pointing back at the
  superseded #67 or re-listing work that has already shipped.
- `tests/test_exports.py` keeps the layer and top-level export sets in
  agreement, deriving the expectation from each object's `__module__`
  rather than a hand-written list, so a protocol added to the top level
  but forgotten in its layer fails the suite.
- Coverage is now enforced, not merely reported: `fail_under = 98` in
  `[tool.coverage.report]`. The suite covers 99% of 1441 statements —
  the only misses are `Packet.__repr__` and its `__eq__`
  `NotImplemented` branch — so the gate is set below the current figure
  to leave room for a legitimately unreachable branch, and well above
  the level at which the bar would stop meaning anything.
- `tests/test_workflows.py` asserts the release gate stays wired:
  that `ci.yml` remains callable, that some release job invokes it,
  that `publish` depends on that job, and that every local `uses: ./…`
  reference resolves to a workflow declaring `workflow_call`. The
  wiring is otherwise easy to remove silently — releases keep working
  while the gate quietly stops existing — and it cannot be verified by
  running it, since publishing is irreversible.
- `docs/CLAIMS.md` records the positioning claims produced by the
  post-1.3.0 competitive analysis, each with its evidence, a
  reproduction path and a publication status — `VERIFIED`,
  `GATED ON #nn`, or `NEEDS RE-MEASUREMENT`. Several of the strongest
  claims are not true yet (decode throughput against dpkt is gated on
  the Tier 1 performance work; the browser claim is untested until a
  Pyodide CI job exists), so the register also lists what must not be
  said and why. Feeds the README as each roadmap tier lands; see #101
  and the roadmap in #107.

## [1.3.0] - 2026-09-01

### Added
- **IEEE 802.1Q VLAN tags** (`VLAN`, 802.1Q-2018 §9.6 / 802.1ad QinQ):
  single and stacked (QinQ `0x88A8`, legacy double-tagged `0x9100`)
  tags decode as one layer per tag; the Tag Control Information word is
  split into `pcp`/`dei`/`vid` dataclass fields validated in
  `__post_init__` (`InvalidFieldError`), with the packed 16-bit view
  kept as the `tci` property; `VLAN` is registered in the
  property-based fuzz suite and the `EtherType` display names are
  covered by the enum completeness test.
- **IGMPv3 group records** (`IGMPv3GroupRecord`, RFC 3376 §4.2): a v3
  Membership Report (type `0x22`) now parses its group-record array on
  demand. `IGMP.group_records` yields one `IGMPv3GroupRecord` per record
  (record type + display name, multicast group, source-address list,
  raw auxiliary data) and `IGMP.num_group_records` reads the count;
  other message types return `None`. Parsing reads the raw body and
  never re-encodes, so the byte-exact round-trip is preserved, and a
  lying record/source count or a truncated record raises
  `InvalidFieldError` (bounded — never hangs or over-reads).
- **IGMPv3 query fields** (RFC 3376 §4.1): a v3 Membership Query (type
  `0x11`) now exposes its fields past the group address — the `s_flag`
  (suppress router-side processing), `qrv`, `qqic`, and
  `query_source_addresses` accessors parse the raw body on demand. A v2
  (8-byte) query and non-query types return `None`, and a source count
  that runs past the message raises `InvalidFieldError`.
- **DHCP** (`netprotocols.DHCP`, RFC 2131/2132) — the fixed BOOTP header
  (op, xid, the client/your/server/gateway addresses, the 16-byte client
  hardware address, and the server-name / boot-file fields) decodes in
  full; the magic cookie and TLV options are kept raw and parsed on
  demand. `option_map` walks the options (concatenating a value split
  across appearances, RFC 3396) and `message_type` / `message_type_name`
  read the DHCP message type (option 53). Dispatched from UDP by
  well-known port (67/68); terminal, with a byte-exact round-trip and
  the same bounded-parse contract as DNS (`InvalidFieldError` on a
  missing cookie or an option that overruns the buffer).
- **GRE** (`netprotocols.GRE`, RFC 2784/2890) — Generic Routing
  Encapsulation, dispatched from IPv4/IPv6 protocol 47. The four-byte
  header (flags/version + protocol type) decodes with the optional
  checksum, key, and sequence-number fields that the flag bits announce
  kept raw and surfaced through accessors. The payload chains onward by
  the `protocol_type` EtherType, so a GRE-tunnelled IPv4/IPv6 packet
  keeps decoding; the round-trip stays byte-exact regardless of which
  optional fields are present.
- **GRE checksum arm** (`netprotocols.checksum`, RFC 2784 §2.5):
  `compute`/`verify` now cover GRE — the internet checksum over the GRE
  header plus its payload with the checksum field zeroed and no
  pseudo-header. `compute(gre, payload=...)` requires the
  Checksum-Present bit (and its field) and raises `InvalidFieldError`
  otherwise; `verify` of a header whose Checksum-Present bit is clear
  returns `True` — a frame cannot fail a checksum it does not carry —
  mirroring the UDP-over-IPv4 zero rule.
- **Richer address accessors** (README roadmap): read-only `_address`
  properties return stdlib `ipaddress` objects alongside the canonical
  `str` fields, for comparison, subnet membership, and arithmetic —
  `IPv4.src_address`/`dst_address` and `ARP.spa_address`/`tpa_address`
  as `ipaddress.IPv4Address`, `IPv6.src_address`/`dst_address` as
  `ipaddress.IPv6Address`, and the four `DHCP` address fields as
  `ciaddr_address`/`yiaddr_address`/`siaddr_address`/`giaddr_address`.
  Purely additive: the `str` fields stay the round-tripping
  representation. MAC addresses stay `str` — the stdlib has no EUI
  type.
- **IPv4 options** (`IPv4Option`, RFC 791 §3.1): the options TLV list
  now parses on demand, mirroring the TCP-option work —
  `IPv4.parsed_options` yields one `IPv4Option` per option in wire
  order (kind + `kind_name`, raw `data`). The common kinds are named:
  End of Option List and No-Operation (single-byte; EOL ends the parse,
  so padding after it is not returned), Record Route (7), Timestamp
  (68), and Router Alert (148, RFC 2113); unknown kinds keep their raw
  `data` with a numeric fallback name. Parsing reads the raw `options`
  bytes and never re-encodes, so the byte-exact round-trip is
  preserved; an option length below the 2-byte minimum or one that runs
  past the options raises `InvalidFieldError` (bounded — never hangs or
  over-reads).
- **DNS resource records** (`DNSResourceRecord`, RFC 1035 §4.1.3): the
  answer, authority, and additional sections parse on demand —
  `DNS.answers` / `DNS.authorities` / `DNS.additionals` yield records
  (name, type + `rtype_name`, class, TTL, raw `rdata`, and a decoded
  `rdata_text`: IPv4/IPv6 for A/AAAA, the target name for CNAME/NS/PTR,
  and MX/TXT/SOA; hexadecimal otherwise). Parsing reads the raw sections
  and never re-encodes, so the byte-exact round-trip holds; a record or
  compressed name that runs past the message raises `InvalidFieldError`.
- **TCP options** (`TCPOption`, RFC 9293 §3.1): the options TLV list
  now parses on demand — `TCP.parsed_options` yields one `TCPOption`
  per option in wire order (kind + `kind_name`, raw `data`, and a
  decoded `value` where this library understands the kind: the segment
  size for MSS, the shift count for Window Scale, a `(tsval, tsecr)`
  pair for Timestamps, and `(left_edge, right_edge)` pairs for SACK;
  RFC 7323/2018). EOL and NOP are single-byte (EOL ends the parse);
  unknown kinds keep their raw `data` with `value` degrading to `None`.
  Parsing reads the raw `options` bytes and never re-encodes, so the
  byte-exact round-trip is preserved, and an option length below the
  TLV minimum or one that runs past the options raises
  `InvalidFieldError` (bounded — never hangs or over-reads).
- **ICMP message bodies** (RFC 792 / RFC 4443): `ICMPv4`/`ICMPv6` gain a
  raw `body` field — the message data after the 8-byte header — so a
  decoded message is self-contained (like `IGMP`/`DNS`), `header_len`
  consumes the whole IP payload, and the layer stays terminal with a
  byte-exact round-trip. Echo requests/replies (v4 types 8/0, v6
  128/129) expose `identifier` / `sequence_number` split from `rest`,
  and the error messages (v4 Destination Unreachable / Redirect / Time
  Exceeded / Parameter Problem; v6 types 1-4) expose `embedded_packet` —
  the invoking datagram, decodable as `IPv4`/`IPv6`. The accessors read
  on demand and degrade to `None` for other message types or an empty
  body, never raising. A decoded message now carries its body in
  `bytes(layer)`, so `checksum.compute`/`verify` need no separate
  `payload` for it (passing one for a header-only object still works).
- **IPv6 Neighbor Discovery** (`NDPOption`, RFC 4861): `ICMPv6` now
  parses NDP messages on demand — `ndp_target_address` reads the
  16-byte target of a Neighbor Solicitation/Advertisement (135/136),
  and `ndp_options` walks the option TLVs of Router
  Solicitation/Advertisement, Neighbor Solicitation/Advertisement, and
  Redirect at each message's own options offset. Each `NDPOption`
  carries its `type` + `type_name` and raw `data`; a Source/Target
  Link-Layer Address option (1/2) reads back as a MAC string via
  `link_layer_address`, and Prefix Information (3) / MTU (5) stay raw.
  Non-NDP message types return `None`. Option lengths count in 8-octet
  units: a zero length (which must not loop), a length past the
  message, or a body shorter than the message's fixed fields raises
- **IPv6 extension-header options** (`IPv6Option`, RFC 8200 §4.2): the
  Hop-by-Hop and Destination Options headers now parse their option
  TLVs on demand — `parsed_options` yields one `IPv6Option` per option
  in wire order, padding included (Pad1 is a lone type byte; everything
  else is type/length/data). Each option carries its `type` +
  `type_name` (Pad1, PadN, Router Alert per RFC 2711, Jumbo Payload per
  RFC 2675; unknown types keep their numeric value) and raw `data`, and
  exposes the action-on-unrecognized bits (the two high bits of the
  type) as `unrecognized_action`. Parsing reads the raw `options` bytes
  and never re-encodes, so the byte-exact round-trip is preserved; a
  missing length byte or option data that runs past the header raises
  `InvalidFieldError` (bounded — never hangs or over-reads).
- **DNS over TCP** (`DNSOverTCP`, RFC 1035 §4.2.2): `TCP.next_protocol()`
  now dispatches application protocols by well-known port
  (`layer4._ports.tcp_app_class`). DNS over TCP is length-prefixed, so
  port 53 chains through a 2-byte `DNSOverTCP` length shim — a layer
  between `TCP` and the `DNS` message, like a VLAN tag between Ethernet
  and its payload — and the walk reaches the DNS message (records and
  all) at its true offset. Non-DNS ports still end the chain at TCP.

### Development
- The real-capture fixture corpus gained `vlan_icmp.pcap` (802.1Q
  single tag VID 100 + 802.1ad QinQ S-VID 200 / C-VID 30, over ARP and
  ICMPv4), so the `VLAN` layer rides the corpus-wide invariants and the
  transport-checksum recompute like every other protocol. It is a
  direct tcpdump capture of real kernel-tagged frames — built over
  802.1Q / 802.1ad vlan devices on a veth pair with VLAN and checksum
  offload disabled so the tags stay in-band in the saved bytes and the
  inner checksums are genuine kernel output; see
  `tests/fixtures/MANIFEST.md` and `scripts/capture_fixtures_vlan.sh`.
- The corpus gained real-capture `dhcp.pcap` (a DHCP DORA exchange from
  `dnsmasq` + `dhclient`) and `gre.pcap` (IPv4-in-GRE ICMPv4 echo over a
  plain and a keyed kernel tunnel), so the `DHCP` and `GRE` layers ride
  the corpus-wide invariants on genuine bytes.
  `scripts/capture_fixtures_dhcp.sh` and `scripts/capture_fixtures_gre.sh`
  produce them, and `scripts/check_fixtures.py` now peels a GRE header to
  verify the tunnelled inner IPv4/ICMP checksums.
- The corpus gained real-capture `dns_tcp.pcap` (an A and a TXT query +
  response from `dig +tcp` against `dnsmasq` over a veth pair, offload
  disabled), so the TCP application dispatch and the `DNSOverTCP`
  length shim (#57) ride the corpus-wide invariants and the
  TCP-checksum recompute on genuine bytes — every frame decodes
  `Ethernet→IPv4→TCP→DNSOverTCP→DNS` with the length prefix agreeing
  with the message it frames and a resolvable answer.
  `scripts/capture_fixtures_dns_tcp.sh` produces it; the corpus is now
  97 frames across 17 scenarios.
- Contributor documentation: a `CONTRIBUTING.md` (dev setup, the QA
  ladder, the decode contract, the add-a-protocol enforcement points,
  and the fixture-capture workflow), a pull-request template, and
  bug-report / protocol-request issue templates under `.github/`.
- README refresh: the Protocol coverage table gains the shipped `DHCP`
  and `GRE` rows, the `DNS` row notes resource-record parsing and the
  DNS-over-TCP length shim, and the `IGMP` row notes the IGMPv3 report
  and query parsing. The Roadmap section now lists only the remaining
  items, linking the open decoder-depth issues (#59-#66, tracked by
  #67), and the stale corpus figure is corrected to 93 frames across 16
  scenarios here and in `ARCHITECTURE.md`.

## [1.2.0] - 2026-08-30

### Added
- **IGMP** (`netprotocols.IGMP`, RFC 1112/2236/3376) — IPv4 multicast
  group management, dispatched from IPv4 protocol 2. The common
  four-byte header (type, max-response code, checksum) is decoded; the
  `group_address` accessor reads the group for the message types that
  carry one, and `netprotocols.checksum` gains an IGMP arm. v3
  group-record parsing is a roadmap follow-up.
- **DNS** (`netprotocols.DNS`, RFC 1035) — the first application-layer
  protocol. The 12-byte header and flag bits are decoded; the four
  message sections are kept raw with on-demand, read-only accessors
  (`question_name`, `question_type`, `question_class`) that decompress
  names safely (bounded pointer-following; malformed or looping names
  raise `InvalidFieldError`, never hang). Round-trip stays byte-exact.
- **Port-based dispatch** on UDP: `UDP.next_protocol()` reaches an
  application protocol by well-known port (`netprotocols.layer4._ports`,
  `{53: DNS}` for now), checked destination-then-source. Documented as
  best-effort — a mis-dispatch degrades to the malformed-frame path.

## [1.1.0] - 2026-08-29

### Added
- **IPv6 extension headers** (RFC 8200 §4.3-4.6): `IPv6HopByHopOptions`,
  `IPv6Routing`, `IPv6Fragment`, `IPv6DestinationOptions`. The decode
  chain now reaches ICMPv6/TCP/UDP behind them (MLD reports decode
  fully). Extension headers dispatch only inside an IPv6 chain, and a
  Fragment header chains onward only from the first fragment.
- **Checksums** (`netprotocols.checksum`): `internet_checksum()`
  (RFC 1071), `compute()`/`verify()` covering the IPv4 header checksum,
  ICMPv4, and TCP/UDP/ICMPv6 with IPv4/IPv6 pseudo-headers, and
  `Packet.with_checksums()` for filling a whole stack on encode. The
  UDP-only zero substitution is confined to the UDP arm.
- **Property-based fuzzing** of the decode path (hypothesis, dev-only):
  decode() raises nothing outside `ProtocolError` for any input; the
  chain walk never consumes past the frame; constrained round trips.
- `IPProtocol` gains `HOPOPT`, `IPV6_ROUTE`, `IPV6_FRAG`,
  `IPV6_DSTOPTS` with display names.

### Development
- The real-capture fixture corpus grew to 65 frames across 12
  scenarios (MLD behind hop-by-hop, IPv6 fragment pairs); checksum
  tests recompute every verifiable corpus frame to its captured wire
  value.

## [1.0.1] - 2026-08-29

### Fixed
- `IPv4.next_protocol()` chained non-first fragments
  (`fragment_offset > 0`) into garbage upper-layer decodes — a slice
  from the middle of a fragmented payload has no header at its start.
  Discovered by the new real-capture fixture corpus on live fragmented
  traffic; the chain now ends at the IPv4 layer for those frames, as it
  already did for unknown protocols.

### Added (development)
- A real-capture fixture corpus under `tests/fixtures/` (56 frames,
  10 scenarios, every checksum internally verified — see its
  MANIFEST.md) with corpus-wide invariant tests, plus the capture and
  validation scripts under `scripts/`.

## [1.0.0] - 2026-08-21

Complete rewrite. The public API is new; see the README and
ARCHITECTURE.md for the current usage.

### Changed
- The parsing core moved from `ctypes.BigEndianStructure` subclasses to
  frozen, slotted dataclasses parsed with `struct.Struct`. Decoded and
  constructed instances are now identical in type and compare equal
  field-by-field.
- `next_protocol()` (returning the class that decodes the payload, or
  `None`) replaces the stringly-typed `encapsulated_proto` chain.
  Protocol number registries are exposed as `EtherType`, `IPProtocol`,
  and `ARPOperation` enums.
- `header_len` is now an instance property: IPv4 honors IHL and TCP
  honors the data offset, and both expose their raw `options` bytes.
- Field names modernized (`ethertype`, `src_port`, `total_length`,
  `checksum`, ...); display helpers are properties such as
  `protocol_name`, `flags_str`, and `checksum_hex_str`.
- Packaging moved to PEP 621 (`hatchling` + `uv`), src layout, Python
  3.12+, MIT license, `py.typed` (mypy strict clean).
- Validators are plain functions (`validate_mac_addr`,
  `validate_ipv4_addr`) raising exceptions rooted at `ProtocolError`.

### Fixed
- `TCP.header_len` was hardcoded to 32 bytes; the base header is 20 and
  the real length follows the data offset.
- Decoding ignored IPv4 IHL and TCP data offset, so headers carrying
  options were mis-sliced.
- Serialization returned a zeroed buffer (`Protocol.__str__`);
  `bytes(header)` now re-emits the exact on-wire form, options included.
- `Packet` rejected instances of indirect `Protocol` subclasses
  (e.g. `IPv4`, `ICMPv4`) due to validation against direct subclasses
  only; membership is now checked with `isinstance`.
- Malformed input (truncated buffers, lying IHL/data-offset values) now
  raises typed exceptions (`TruncatedHeaderError`, `InvalidFieldError`)
  instead of arbitrary `ValueError`/`struct.error` leaks.

### Removed
- The `Validator` descriptor infrastructure (it stored state on the
  descriptor itself — class-shared — and was never wired into any
  protocol class).
- Poetry manifests and the `setup.py`-era metadata.

## [0.8.0] - 2022-08-19

Last release of the ctypes-based implementation, published to PyPI in
2022. The repository had drifted behind the published releases; the
0.8.0 sources were recovered from the PyPI sdist and committed (tagged
`v0.8.0`) before the 1.0.0 rewrite. Releases 0.4.4 through 0.8.0 exist
on PyPI only; their individual histories were not preserved.
