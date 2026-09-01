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

---

## 1. Performance

### 1.1 "2.1× faster than scapy at decoding"
**Status: VERIFIED**

36,500 frames/sec against scapy 2.7.0's 17,100 on the corpus walk.

Reproduce: the benchmark harness from #86, once it lands. Until then,
the scratch method described in the baseline above.

### 1.2 "Within 15% of dpkt on decode"
**Status: GATED ON #82, #83, #84** — false today

Today: 36,500 f/s against dpkt's 104,000 — we are **2.9× slower**.
With the three Tier 1 fixes applied to a scratch copy: **89,200 f/s**,
or 86% of dpkt, while passing all 698 tests unmodified.

Do not publish any decode-throughput comparison against dpkt until
those three issues have merged and #86 has re-measured on the real
tree.

### 1.3 "5.3× faster than dpkt at encoding"
**Status: VERIFIED** — and never yet claimed

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

Also: 85 modules loaded against `scapy.all`'s 259 (dpkt: 117).

Worth pairing with the observation that importing scapy performs live
host introspection — it populated four interfaces and eight routes on
the measuring machine simply by being imported. A codec that turns
bytes into objects should never touch the host.

### 1.5 "~46× smaller wheel than scapy"
**Status: NEEDS RE-MEASUREMENT** at each release

50 KB wheel against scapy's 2.47 MB; 3,732 lines against 246,813.
Both move with releases — re-check before quoting.

---

## 2. Typing

### 2.1 The `mypy --strict` comparison
**Status: VERIFIED** — the single strongest demo we have

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
**Status: VERIFIED (the capability); GATED ON #93 (the claim)**

It already works, with no code changes:

```python
match ip:
    case IPv4(protocol=IPProtocol.TCP, ttl=t) if t > 32:
        ...
```

Two facts make it work: frozen dataclasses auto-generate
`__match_args__`, and `IntEnum` subclasses `int`, so the registries in
`_enums.py` are usable as value patterns against plain-`int` fields.

Competitors cannot: dpkt builds `__slots__` from a metaclass and
generates no `__match_args__`; scapy routes fields through
`__getattr__`; `construct` returns dicts.

Gated only because claiming a feature that appears in no documentation
is a bad look. Land #93 first, then say it loudly.

### 2.3 "No library combines all five"
**Status: VERIFIED, with one named exception**

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
**Status: GATED ON #99**

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
**Status: PARTLY TRUE — precision required**

What is true: Hypothesis fuzzing asserts that decoding never raises
outside `ProtocolError`, that chain walks terminate, that layers
recompose, and that five TLV/name accessors never hang.

What is **not** yet true: `bytes(decode(x)) == x` is
Hypothesis-generated for only **4 of 18** protocols (#97), and CI runs
a fixed 200 examples with `derandomize=True` (#98).

Until those land, say "property-based fuzzing of the decode path", not
"of every protocol", and do not imply the round-trip is universally
generated. The corpus evidence in 5.1 is strong and honest; lean on it.

### 5.3 "99% test coverage"
**Status: VERIFIED, GATE PENDING #79**

1,441 statements, 3 missed. But coverage is currently *reported* and
never *enforced*, so this is a snapshot rather than a guarantee until
#79 adds `fail_under`.

---

## 6. Claims we must not make

- ❌ **"Faster than dpkt"** (unqualified) — false for decode today, and
  even after Tier 1 we are ~86%. The honest version is "within 15% of
  dpkt on decode and 5× faster on encode".
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
