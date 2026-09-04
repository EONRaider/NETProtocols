# Marketing claims register

Positioning statements for the README, release notes and package
metadata — each with its evidence, how to reproduce it, and whether it
is safe to publish **today**.

Several of the strongest claims here are **not true yet**. They become
true when specific roadmap issues land. Publishing one early would be a
self-inflicted wound, which is why this file exists instead of a note
in someone's head.

Tracked by [#101](https://github.com/EONRaider/NETProtocols/issues/101);
roadmap context in [#107](https://github.com/EONRaider/NETProtocols/issues/107).

> **Standing embargo: no comparative claims until the roadmap closes.**
> Nothing in this file that mentions scapy, dpkt or any other library
> goes into the README, release notes, package metadata or a post until
> [#107](https://github.com/EONRaider/NETProtocols/issues/107) is
> finished. Keep measuring, keep recording — that is what the file is
> for — and ship the comparison once, complete, rather than in pieces
> that each need defending. Entries under embargo are marked
> `COMPARATIVE — HELD`.

## Rules

1. **No claim without evidence** — a reproduction command, or a
   `file:line` citation.
2. **Every claim carries a status:**
   - `VERIFIED` — measured, safe to publish now.
   - `GATED ON #nn` — will be true when that issue lands. Do not
     publish before it closes.
   - `NEEDS RE-MEASUREMENT` — was true when measured; stale enough to
     re-check before quoting.
3. **Comparative numbers name versions** — the competitor's exact
   version and the Python version both were measured under. "Faster
   than scapy" without a version is not a claim, it is a vibe.
4. **Re-measure before every release that quotes a number.** Hardware
   moves, upstream releases move, and our own hot path is about to
   move a great deal.
5. **Comparative claims stay unpublished until the roadmap closes.**
   The numbers move under our feet: claim 1.2 went from "2.9× slower
   than dpkt" to "1.16× faster" inside a single tier, and Tier 2
   onwards will move them again. A comparison published mid-flight is
   one we have to defend, retract, or re-measure in public.

## Measurement baseline

Unless a claim says otherwise, figures were taken on 2026-09-01 at
commit `0f86821` (v1.3.0):

- CPython 3.12.3, single machine, x86-64 Linux.
- Comparators: `dpkt 1.9.8`, `scapy 2.7.0`.
- Workload: all 97 frames of `tests/fixtures/`, walked
  `Ethernet → … → payload`, 300 repetitions, mean of repeated runs.
- Run-to-run variance ≈ ±4%.

The corpus is the right workload because it exercises DNS, DHCP and
IPv6 extension headers rather than one synthetic TCP frame. A
single-synthetic-frame benchmark flatters us: it put us at 75,151 pkt/s
against dpkt's 123,719 (a 1.6× gap) where the corpus shows 2.9×,
because the uncached DNS accessors of #85 never get exercised. **Quote
the corpus figure.**

### Re-measured after Tier 1 (2026-09-01, #86)

Tier 1 (#82, #83, #84, #85) has merged, so every figure above that
compares decode throughput is stale. Re-measured with the harness this
tier delivered:

```
uv run --group bench python scripts/benchmark.py --compare
```

- CPython 3.12.3, x86-64 Linux, 97 corpus frames, 30 repetitions,
  **best of 9** — not the mean of 300 used above. The minimum is the
  more stable statistic (a timed run is only ever interrupted, never
  helped), but it reads a few per cent faster than a mean, so the two
  methods are not directly comparable.
- Run-to-run variance of the normalized figure ≈ ±2%.

| | frames/sec | vs. netprotocols |
|---|---|---|
| **netprotocols (post-Tier-1)** | **121,945** | — |
| dpkt 1.9.8 | 105,292 | 0.86× |
| scapy 2.7.0 | 19,657 | 0.16× |

Two things must travel with those numbers:

1. **The libraries are not asked for identical work.** On the
   DNS-over-TCP frames dpkt stops at TCP and leaves the payload as raw
   bytes; netprotocols continues into `DNSOverTCP` and `DNS`. Where the
   depths differ, we are doing more, not less — but the comparison is
   not like-for-like and should never be quoted as if it were. The
   harness prints this caveat under every comparison run.
2. **Normalization cancels machine speed, not the interpreter.** The
   same code and machine normalize to 6.8 on CPython 3.12 and 7.6 on
   3.13. A baseline belongs to the Python that recorded it.

Note also that the v1.3.0 figure of 36,500 f/s above predates #83, which
alone accounts for most of the gap to the ~58,000 f/s the same corpus
walk showed once that had merged.

---

## 1. Performance

### 1.1 "2.1× faster than scapy at decoding"
**Status: VERIFIED — and now understated**

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

Was 36,500 frames/sec against scapy 2.7.0's 17,100. Re-measured after
Tier 1: **121,945 against 19,657, a 6.2× gap** (see the re-measurement
above for the method and its caveats).

Reproduce: `uv run --group bench python scripts/benchmark.py --compare`.

The wording is a positioning decision, not a measurement one: 6.2× is
what the corpus shows on one machine, and whoever writes the README
should pick the number they are willing to defend on someone else's.

### 1.2 "Within 15% of dpkt on decode"
**Status: gate satisfied — measured, and the claim is now too modest**

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

#82, #83, #84 (and #85) have merged and #86 has re-measured on the real
tree, which is exactly what this claim was waiting for. Measured:
**121,945 f/s against dpkt 1.9.8's 105,292 — 1.16× dpkt**, where
v1.3.0 was 2.9× slower. The prediction in #103 was 86% of dpkt; the
extra came from #85, which the scratch prototype did not include, and
from best-of rather than mean.

Before this is published as "faster than dpkt", two caveats from the
re-measurement section apply and are not optional: the two libraries do
not parse to the same depth (we go deeper on the DNS frames), and this
is one machine. A cautious public form — "matches dpkt on the corpus
walk while decoding further into the stack" — is defensible on the
evidence; "1.16× faster than dpkt" is defensible only with the machine
and the depth caveat attached.

Recommend re-running the harness on a second machine before this
reaches the README. Front-page wording is the maintainer's call.

### 1.3 "5.3× faster than dpkt at encoding"
**Status: VERIFIED** — and never yet claimed

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

`bytes(header)` re-serialization, ops/sec:

| Library | ops/sec | Note |
|---|---|---|
| **NETProtocols 1.3.0** | **1,443,863** | repacks from fields |
| scapy 2.7.0 | 685,620 | returns cached original bytes — not a real repack |
| dpkt 1.9.8 | 270,485 | repacks from fields |

Nobody benchmarks this direction. It is the half of "codec" we already
win, and it is true right now. Measured under CPython 3.13 on a single
synthetic Ethernet header; **re-measure under 3.12 before quoting
alongside the corpus decode numbers**, so the two share a baseline.

### 1.4 "Imports in 40 ms; scapy takes 570–870 ms"
**Status: VERIFIED**

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

Also: 85 modules loaded against `scapy.all`'s 259 (dpkt: 117).

Worth pairing with the observation that importing scapy performs live
host introspection — it populated four interfaces and eight routes on
the measuring machine simply by being imported. A codec that turns
bytes into objects should never touch the host.

### 1.5 "~46× smaller wheel than scapy"
**Status: NEEDS RE-MEASUREMENT** at each release

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

50 KB wheel against scapy's 2.47 MB; 3,732 lines against 246,813.
Both move with releases — re-check before quoting.

### 1.6 "Decodes further into the stack than dpkt, on the same bytes"
**Status: VERIFIED (the measurement)**

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

On the 97-frame corpus, netprotocols reaches a deeper layer than dpkt
on **27 frames** and stops at the same layer on the other 70. dpkt
leaves DHCP and DNS payloads opaque:

```
netprotocols: Ethernet -> IPv4 -> UDP -> DHCP
dpkt:         Ethernet -> IP   -> UDP -> <300 raw bytes>
```

Reproduce: `uv run --group bench python scripts/benchmark.py --depth`.

This is the control on every throughput figure in 1.1-1.3, not a
footnote to them: a decoder that stops earlier has less to do, so
"faster" only means something stated beside "and it decoded more".
When the embargo lifts, the depth number travels with the speed number
in the same sentence.

### 1.7 "Decode throughput is regression-gated in CI"
**Status: VERIFIED** — non-comparative, so not under embargo

Every pull request runs the corpus benchmark and fails at 15% below
`benchmarks/baseline.json` (`.github/workflows/ci.yml`). Throughput is
normalized against a fixed calibration workload so a baseline survives
a change of machine, and a failing check re-measures once before
failing so a noisy runner does not block unrelated work.

Reproduce: `uv run --group bench python scripts/benchmark.py --check`.

The tempting comparative form — "no other Python packet library gates
performance in CI" — is **not claimed**: their CI has not been audited,
and rule 1 applies to us as much as to them.

---

## 2. Typing

### 2.1 The `mypy --strict` comparison
**Status: VERIFIED** — the single strongest demo we have

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

```
# scapy 2.7.0 — a field name that does not exist
p.ThisFieldDoesNotExist   → Any     (no error)

# dpkt 1.9.8 — the whole module
import dpkt.ethernet      → error: missing library stubs or py.typed

# NETProtocols — a typo in a real field name
ip.proto                  → error: "IPv4" has no attribute
                              "proto"; maybe "protocol"?
```

Supporting facts, all verifiable:

- Scapy **does** ship `py.typed`, so the marker alone proves nothing.
  Its own mypy configuration enables 88 files, of which **two of the
  ninety-two under `scapy/layers/`** — the dissectors anyone actually
  touches are unchecked. `Packet.__getattr__` erases every field to
  `Any`.
- dpkt ships no `py.typed`; `types-dpkt` and `dpkt-stubs` do not exist
  on PyPI. Everything downstream becomes `Any`.
- Ours is `mypy strict = true` over the whole of `src/`, enforced in
  CI.

This fits in one screenshot and belongs near the top of the README.

### 2.2 "The only Python packet library you can dissect with `match`/`case`"
**Status: VERIFIED (the capability); COMPARATIVE — HELD (the claim)**

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

The capability itself is no longer gated: #93 landed it in
documentation and a regression suite. It already worked, with no code
changes, and now says so where a reader can find it — a first-screen
README example, a dedicated section there, and the mechanism explained
in ARCHITECTURE.md (`__match_args__` from `@dataclass`, `IntEnum`
subclassing `int`) so a contributor knows what would quietly break it.
`tests/test_pattern_matching.py` pins both mechanisms and runs the
README's own example over the corpus.

#94 refined the mechanism rather than replacing it: `IPv4`, `TCP` and
`DHCP` run to 11-15 fields, wide enough that the plain auto-generated
`__match_args__` is unusable positionally, so those three now
hand-declare a short, documented, tested tuple instead (`IPv4.src,
dst, protocol`; every other header still relies on the plain
auto-generated one). Keyword patterns are unaffected either way.

```python
match ip:
    case IPv4(protocol=IPProtocol.TCP, ttl=t) if t > 32:
        ...
```

What stays held is the *comparative* sentence — dpkt builds
`__slots__` from a metaclass and generates no `__match_args__`; scapy
routes fields through `__getattr__`; `construct` returns dicts — under
Rule 5 like every other claim naming a competitor. Neither README.md
nor ARCHITECTURE.md make the comparative form; both describe only this
library's own mechanism.

### 2.3 "No library combines all five"
**Status: VERIFIED, with one named exception**

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

Zero dependencies + frozen-dataclass headers + `IntEnum` registries +
`match`/`case` dissection + `py.typed` with real (non-`Any`) field
types under `mypy --strict`.

**Name the exception rather than waiting to be caught by it:**
`PyTCP-net_proto` does the same thing. It is GPL-3.0, requires Python
3.14, is marked Alpha, carries a dependency, and is a package carved
out of a full TCP/IP stack rather than a standalone codec. We are MIT,
3.12, zero-dependency and Production/Stable.

---

## 3. Purity and portability

### 3.1 "Runs where scapy cannot — including the browser"
**Status: VERIFIED (the capability, via CI's `pyodide` job); COMPARATIVE — HELD (the claim)**

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

Blocking exactly the modules Pyodide removes (`fcntl`, `termios`,
`resource`, `grp`, `pwd`) and re-importing:

```
OK    netprotocols
OK    dpkt
OK    pypacker
FAIL  scapy.layers.l2 : ModuleNotFoundError: No module named 'fcntl'
FAIL  scapy.all       : ModuleNotFoundError: No module named 'fcntl'
```

Scapy's `from fcntl import ioctl` is **unconditional** in
`scapy/arch/linux/__init__.py:11` and `scapy/arch/unix.py:13`, and
`scapy.arch` is on the import path of every scapy import. Scapy cannot
be *imported* under Pyodide — not "cannot sniff". It is also absent
from Pyodide's built package set.

Gated because we should test it before we sell it.

### 3.2 "Zero dependencies, no I/O, no sockets"
**Status: VERIFIED — but do not lead with it**

11 stdlib imports; `socket` used for exactly four
`inet_pton`/`inet_ntop` calls (`_base.py:55-70`) and no socket ever
created; no `ctypes`, `subprocess`, `fcntl`, `threading` or file access
anywhere in `src/`.

⚠️ **dpkt shares this property.** Purity alone is not a differentiator
— it is one we hold jointly with the fastest incumbent. Always pair it
with typing and validation. The correct framing is "pure *and* typed
*and* validating", never "pure" on its own.

### 3.3 MicroPython / embedded
**Status: DO NOT CLAIM**

MicroPython ships `struct` but not `dataclasses`, and `enum` is not
core. A library built on frozen dataclasses and `IntEnum` will not run
there without a separate build. Say nothing about embedded targets.

---

## 4. Licensing and maintenance

### 4.1 The permissive-licence wedge
> "The only MIT-licensed, strictly-typed, zero-dependency packet codec
> still being maintained."

**Status: VERIFIED** — and probably the most actionable claim here

> ⏸ **COMPARATIVE — HELD until the roadmap (#107) closes.** The
> evidence below stands and should keep being re-measured; none of it
> is published anywhere until then.

| Project | Licence |
|---|---|
| **netprotocols** | **MIT** |
| dpkt | BSD |
| pcapkit | BSD-3 |
| pyshark | MIT |
| construct | MIT |
| dnspython | ISC |
| scapy | GPL-2.0 |
| pypacker | GPLv2 |
| stackforge | GPL-3.0 |
| PyTCP-net_proto | GPL-3.0 |
| nfstream | LGPL-3.0 |

For anyone embedding a packet codec in a commercial product, the GPL
column is unavailable. That leaves dpkt and us — and dpkt was last
released **2022-08-18**, last committed **2024-05-05**, still
advertises Python 2.7 and 3.5–3.9 in its classifiers, is still marked
`Development Status :: 4 - Beta` after twelve years, has 95 open
issues, and cannot be type-checked at all.

This may be a stronger and more immediately usable wedge than the
browser story. It also costs nothing to start saying.

### 4.2 Tone when writing about competitors
**Status: STANDING RULE**

State facts with dates and versions; do not editorialise. "dpkt's last
release was August 2022" is a fact a reader can check. "dpkt is
abandoned" is a characterisation we would have to defend, and it
insults people who may yet pick it back up. Scapy is an extraordinary
piece of work that does far more than we do — say so, then say what we
do differently.

---

## 5. Correctness and proof

### 5.1 "Byte-exact round-tripping, verified against real captured traffic"
**Status: VERIFIED**

`tests/test_corpus.py:66-71` asserts `bytes(layer) ==
frame[cursor:cursor+layer.header_len]` for **every layer of all 97
frames**, across 17 scenarios captured with tcpdump over real kernel
VLAN, GRE and DHCP topologies. Every frame's checksums verify
internally (`scripts/check_fixtures.py`).

### 5.2 "Property-based fuzzing of every decoder"
**Status: VERIFIED**

Hypothesis fuzzing asserts that decoding never raises outside
`ProtocolError`, that chain walks terminate, that layers recompose,
that five TLV/name accessors never hang, and that `bytes(decode(x)) ==
x` is Hypothesis-generated for **all 18** protocols, up from 4.
`tests/strategies.py` holds one reusable strategy per protocol;
`tests/test_fuzz.py::TestGeneralizedRoundTrips` parametrizes the
property over all 14 that were missing it (#97). Reproduce:
`uv run pytest tests/test_fuzz.py::TestGeneralizedRoundTrips -v`.

CI runs two Hypothesis profiles (#98): every push/PR runs a fixed 200
examples with `derandomize=True`, so a landed PR's result is
reproducible; a scheduled `.github/workflows/fuzz.yml` additionally
runs the *entire* suite nightly under a `"nightly"` profile — 10,000
examples, a real random seed each run — so fuzzing explores new
ground every night instead of replaying the same 200 inputs forever.
Reproduce a nightly-style run locally:
`HYPOTHESIS_PROFILE=nightly uv run pytest`.

### 5.3 "99% test coverage"
**Status: VERIFIED**

1,935 statements, 1 missed (99.95%). Enforced, not merely reported:
`[tool.coverage.report]` sets `fail_under = 98`, and the `test` CI job
runs with `--cov-report=term` on every push and pull request, so a
regression below the gate fails the build (#79).

### 5.4 "Validation that cannot be skipped, on a decode path that does not pay for it"
**Status: VERIFIED**

Public constructors validate every address and reject bad input
(`InvalidMACAddressError`, `InvalidIPv4AddressError`), while
`decode()` builds instances directly and runs **no regex at all** —
the strings it validates against were mechanically generated from raw
bytes moments earlier.

`tests/test_contract.py::TestDecodePathValidation` pins both halves: a
spy replaces the compiled patterns and fails the test if the decode
path so much as calls `.match`, alongside assertions that
`Ethernet(dst="nonsense", ...)` still raises. Measured cost of removing
the redundant work: `Ethernet.decode` 2330 → 830 ns, `IPv4.decode`
4936 → 2596 ns (#84).

The pairing is the point, and it is ours to lose: strictness usually
costs throughput, and here it costs none. Stated without a competitor
it needs no embargo.

### 5.5 "Extend the decode walk without forking the library"
**Status: VERIFIED** (#87)

Any protocol this library does not implement can be registered against
the wire value that names it, and then participates in frame walks like
a built-in:

```python
from netprotocols import Protocol
from netprotocols.registry import register

@register("ethertype", 0x8847)
class MPLS(Protocol):
    ...
```

Five tables — `ethertype`, `ip.proto`, `ip.proto.v6`, `udp.port`,
`tcp.port` — each named after the field it dispatches on. The registry
*is* the dispatch mechanism, not a hook bolted onto hardcoded
functions: the built-in decoders go in through the same public
`register()` a third party calls (`src/netprotocols/_defaults.py`), so
there is no privileged path and nothing to fall out of sync.

Reproduce: `uv run pytest tests/test_registry.py` — 39 tests covering
registration, conflict handling, table inheritance and isolation from
the process-wide default.

Three properties worth stating alongside it, because they are what
make the extension point safe rather than merely present:

- **Conflicts are loud.** Registering over an occupied key raises
  `RegistryConflictError` naming the incumbent class, unless
  `override=True` is passed. Two packages claiming the same port cannot
  silently resolve by import order.
- **Isolation is available.** `Registry.from_defaults()` gives a
  registry whose registrations never reach the rest of the process —
  the case that matters for anyone embedding this library rather than
  writing an application.
- **The IPv6 gating generalised rather than being special-cased.**
  `ip.proto.v6` inherits `ip.proto`, so the extension headers stay
  unreachable from IPv4 by virtue of which table they live in, and the
  guarantee survives third-party registration.

**Not yet claimable, and deliberately so:** whether competitors offer
an equivalent. scapy's `bind_layers` and dpkt's per-module dicts both
exist and neither has been audited for what it actually guarantees, so
no comparative form of this claim is written here. See the embargo in
the Rules and #124.

### 5.6 "Port dispatch is a table lookup"
**Status: VERIFIED** (#87)

Measured old and new shapes in a single process, so machine speed
cancels:

| Table | Before | After | |
|---|---|---|---|
| `udp.port` | 303.1 ns | 46.0 ns | **6.6×** |
| `tcp.port` | 186.8 ns | 45.1 ns | **4.1×** |
| `ethertype` | 51.8 ns | 47.7 ns | 1.1× |
| `ip.proto` | 58.1 ns | 57.9 ns | unchanged |

The two port functions re-ran their deferred imports and rebuilt a
`dict` literal on every call; they were outside the scope of #82, which
named only the EtherType and IP-protocol functions. `ip.proto` was
already a table and did not move.

**State the per-call figures, not a corpus figure.** Corpus throughput
moves about 1%, because only 28 of the 97 corpus frames reach a
transport header and therefore do a port dispatch at all — and 1% is
below this machine's run-to-run noise, which spans roughly ±10% between
consecutive runs. Two interleaved A/B sets disagreed on the sign. The
per-call measurement is the one that resolves; quoting a corpus number
here would be quoting noise.

### 5.7 "The chain walker ships with the library"
**Status: VERIFIED** (#88)

`decode_frame(frame)` returns a `Packet` of every decoded layer. Before
this, the README taught a hand-rolled loop, ARCHITECTURE.md showed it
again, and the test suite carried a private copy — the most-used
function in the library was the one it did not ship.

Reproduce: `uv run pytest tests/test_walk.py` — 79 tests, including one
that walks the corpus with a hand-rolled loop and asserts the shipped
walker agrees layer for layer, which is what made retiring the copies
safe.

Four properties are the actual claim, since a walker by itself is
eight lines:

- **Bounded depth.** `max_depth` (default 32) raises
  `MaxDepthExceededError`. Chains already terminated — every header
  validates its own declared length — so this bounds *cost*, not
  correctness: a crafted frame cannot turn one walk into thousands of
  decodes. Corpus maximum is 5 layers.
- **An explicit start layer.** `decode_frame(buf, start=IPv4)`, for
  buffers that begin mid-stack. gopacket has this; scapy and dpkt make
  you name the class and hand-roll the rest.
- **Partial success is reported, not guessed at.** `lax=True` returns
  the layers that decoded plus `packet.stopped_by`. Not a lenient
  parser — every returned layer met the ordinary strict rules.
- **Per-call decoder overrides.** `decode_as={"udp.port": {6969: DNS}}`
  without touching global state, built on #87's `Registry.derive()`.

**Comparative forms are held.** dpkt's and scapy's equivalents have not
been audited here, and the interesting comparison — what each does with
a *malformed* frame — is a behavioural claim needing evidence, not a
feature-table tick. See the embargo in the Rules.

### 5.8 "memoryview walking, measured rather than assumed"
**Status: VERIFIED** (#88)

The roadmap proposed walking with `memoryview` internally. Measured on
the corpus, that is **0.95x** — 5% *slower* — because for one small
frame the view costs more to build than the copy it saves.

So the walker slices whatever it is handed and never converts: `bytes`
stays fastest for a single frame, and a `memoryview` over a large
contiguous capture buffer keeps slices zero-copy, which is the case
#100 measured at 1.8x. Byte-exact round-tripping through a
`memoryview` is asserted over the corpus.

This one is worth stating publicly *as a process claim*: the obvious
optimisation was proposed, measured, and rejected on its own numbers,
and both the number and its reproduction are written down. Rule 1 with
teeth.

### 5.9 "Explains bad input instead of merely rejecting it"
**Status: VERIFIED** (#91)

Strictness is this library's security story — it raises where scapy
silently fills in defaults — but until now every exception carried
only a formatted string. Verified in the issue: the full attribute set
on a raised `TruncatedHeaderError` was `args`, `add_note`,
`with_traceback`. A fuzzing harness, conformance suite, or
protocol-validation tool that wanted to know *where* a parse failed
had to regex the message.

Every raise site in `src/` now attaches structured context:

```python
try:
    packet = decode_frame(frame)
except ProtocolError as e:
    print(e.protocol, e.field, e.offset, e.frame_offset, e.expected, e.actual)
    # <class 'netprotocols.layer3.ip.IPv4'> ihl 0 14 >=5 0
```

`protocol` is set at every one of the 62 raise sites in the library
(verified by an AST sweep during development, not just by eye); `field`
and `offset`/`frame_offset` are set wherever there's a byte position or
a single attribute to name. `offset` is honestly scoped: relative to
the `decode()` buffer for a fixed-header error, relative to the
attribute `field` names (`options`, `body`, `sections`) for an
on-demand parse, and `None` — never guessed — for a `__post_init__`
validation error, which sees field values and never the bytes they
came from. `decode_frame` is the only code holding the cursor needed to
rebase a layer-relative `offset` to the whole frame, so it is the only
thing that sets `frame_offset`.

No message string changed to make this true — every existing `str(err)`
and `match=` assertion in the suite holds unchanged; the diagnostic
fields are additive.

Reproduce: `uv run pytest tests/test_diagnostics.py` — 32 tests across
all three raise shapes (decode-time, construction-time, on-demand
property) plus the rebasing behaviour end to end.

**Why this is a differentiator, not a nicety.** Scapy mostly does not
raise at all. dpkt raises bare `UnpackError` / `NeedData` with nothing
attached. For the audience this library is built for — people parsing
untrusted input — this is the difference between a library that
rejects bad input and one that explains it. No competitor offers it,
though that comparative form stays held under the standing embargo
until this claim is audited the same way #124 audits the CI gate.


---

## 6. Claims we must not make

- ❌ **"Faster than dpkt"** (unqualified) — no longer false, and still
  not publishable. Post-Tier-1 measurement puts decode at 1.16× dpkt on
  one machine and 1.06-1.16× across two CI runners (1.2), while
  decoding further on 27 of 97 frames (1.6). Unqualified, it still
  hides the machine, the corpus and the depth difference — and under
  the standing embargo it is not published at all until #107 closes.
- ❌ **"Superior to scapy"** with no axis named. Scapy crafts, sends,
  sniffs, fuzzes and covers thousands of protocols; we decode and
  re-encode a couple of dozen headers. On *codec* axes — typing,
  purity, round-trip fidelity, throughput, licence, import cost — the
  evidence in this file is strong and getting stronger. On coverage and
  capability it is not a contest we are in, and one screenshot of
  `scapy.all` settles it. Name the axis and the claim is defensible;
  omit it and it is refutable in a sentence.
- ❌ **"Pure Python and zero-dependency, unlike the alternatives"** —
  dpkt is both. See 3.2.
- ❌ **"More protocols than X"** — we will never out-cover scapy and
  should not enter that race.
- ❌ **"Nobody else does typed packet parsing"** — `PyTCP-net_proto`
  does. Name it and win on licence, Python floor and maturity instead.
- ❌ **Any benchmark number without a reproduction command** — the
  entire published literature in this space is self-benchmarked by the
  winner, run on a Core 2 Duo, or comparing CPython 3.6 against
  CPython 2.7. Being the exception is itself a differentiator, and #86
  exists to make it possible.
