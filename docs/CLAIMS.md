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

> **Embargo lifted 2026-09-04.** [#107](https://github.com/EONRaider/NETProtocols/issues/107)
> closed once its last two pieces landed: [#124](https://github.com/EONRaider/NETProtocols/issues/124)
> (auditing ten competitor projects' CI for a performance gate — none
> gate, see 1.7) and a full re-measurement of every comparative claim
> below against the roadmap's finished state. Every section that
> previously carried a `COMPARATIVE — HELD` banner is now published,
> with the date and commit it was re-measured at. The discipline that
> produced this file doesn't stop here — Rule 4 (re-measure before
> every release that quotes a number) still applies to everything
> below, embargo or not.

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
5. **Comparative claims stayed unpublished until the roadmap closed —
   done as of 2026-09-04.** The numbers moved under our feet the whole
   way: claim 1.2 went from "2.9× slower than dpkt" after Tier 1's
   measurement, to "1.16× faster" later that same tier, to "~11%
   slower" once Tiers 2-4 landed and were re-measured for the embargo
   lift. That volatility is exactly why this rule existed — a
   comparison published mid-flight is one we would have had to defend,
   retract, or re-measure in public. It doesn't relax now that
   publishing has started: Rule 4 still binds every number below at
   every release.

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

### Re-measured for the embargo lift (2026-09-04, #107/#124)

Tiers 2-4 (#87's dispatch rewrite, #88's chain walker, #91's structured
errors, #93-#96's typing work, #97-#100's fuzzing/pcap/pyodide additions)
have all merged since the Tier 1 re-measurement above. Re-measured with
the same harness, matching the Tier 1 methodology (30 repetitions, best
of 9):

```
uv run --group bench python scripts/benchmark.py --compare --repetitions 30 --trials 9 --depth
```

- CPython 3.12.3, x86-64 Linux, 97 corpus frames, same machine class as
  every prior measurement in this file, run-to-run variance ≈ ±3%.

| | frames/sec | vs. netprotocols |
|---|---|---|
| **netprotocols (post-Tier-4, 2.0.0)** | **94,453** | — |
| dpkt 1.9.8 | 105,525 | 1.12× (dpkt is faster) |
| scapy 2.7.0 | 16,826 | 0.18× |

**This reverses the Tier 1 finding for the dpkt comparison.** Tier 1 put
netprotocols 1.16× *faster* than dpkt; three tiers of added surface —
registry dispatch (#87), the chain walker (#88), and per-raise-site
structured error context (#91) among them — moved the needle back the
other way. netprotocols now decodes the corpus at 94,453 f/s against
dpkt's 105,525, roughly **11% slower**. The vs.-scapy gap also narrowed,
from 6.2× (Tier 1) to **5.6×**, though it remains a wide margin. Decode
depth is unchanged: netprotocols still reaches further than dpkt on 27
of 97 frames and matches it on the other 70 (see 1.6) — the two
libraries still do different amounts of work, so the caveats from the
Tier 1 re-measurement above still apply in full, including to a claim
that is now more modest than it once was rather than less.

This is reported plainly rather than smoothed over: the point of this
register (Rule 1, Rule 4) is that a number gets published because it
was measured, not because it was flattering. "Within 15%" (1.2) is
still true (it was, through 2.4.0; 2.5.0's corpus ended it, see 1.2) — more true than it was, since the gap narrowed from the
2.9× that motivated Tier 1 in the first place — it just now describes
the other direction.

### Re-measured after closing the dpkt-throughput regression (2026-09-04, #147)

Re-measuring every held claim once #107/#124 closed surfaced a
regression none of the five tiers had been watching for: decode
throughput against dpkt had reversed from the Tier 1 finding (1.16×
faster) to ~11% slower, without anyone profiling why. #147 root-caused
it with `cProfile`/`pstats` against the corpus decode loop rather than
guessing from the tier history — two of the three tiers first
suspected turned out on inspection not to touch the decode happy path
at all.

**What the profile actually showed**, against the loop
`scripts/benchmark.py` measured at the time (a hand-rolled walk loop,
not `decode_frame()` — see the methodology fix below):

1. **`bytes_to_ipv6` (added by #99, not one of the three originally
   suspected tiers) accounted for ~18% of total corpus decode time.**
   #99 replaced `socket.inet_ntop` with a hand-rolled RFC 5952
   canonicalizer for a real, non-negotiable reason — Pyodide's CPython
   build has `AF_INET6` disabled — but formatted each of the 8 address
   words with a separate f-string inside a generator, markedly slower
   than the C-level socket call it replaced. #99 landed chronologically
   after #91 (the last of the three suspects the roadmap named), so it
   was invisible to that suspect list even though it lands squarely in
   the Tier-1-to-now window that produced the regression.
2. **`decode_frame()`'s `Packet(*layers, ...)` construction paid an
   `isinstance(layer, Protocol)` check per layer that goes through
   `Protocol`'s ABC `__instancecheck__` machinery** — ~7-8% of
   `decode_frame()`'s own time. Every element in that list came from
   this module's own `protocol.decode()` calls immediately before, so
   the invariant was already guaranteed; the check was pure redundant
   validation on an internal path, not a relaxation of anything the
   *public* `Packet(...)` constructor still validates for arbitrary
   caller-supplied arguments.
3. **#87's registry dispatch and #91's structured diagnostics were
   both ruled out directly, not just re-confirmed.** Reading every
   `next_protocol()` override confirmed each keeps the documented
   single-`dict.get` fast path when no registry override is passed;
   reading every raise site #91 touched confirmed diagnostic fields
   are populated only inside a raise, never on the happy path. Neither
   shows up in the profile in any meaningful way (~2-3% combined,
   matching #87's own prior 5.6 measurement of a *win*).

**Fixes**, both behavior-preserving and verified as such before being
measured for speed:

- `bytes_to_ipv6` rewritten to format all eight words with one
  `%`-formatting call instead of eight separate f-string calls through
  a generator, then slice the pre-split result for the compressed
  forms. Byte-identical to the previous implementation and to glibc's
  `inet_ntop` — verified by the existing
  `test_bytes_to_ipv6_matches_glibc` hypothesis test (`tests/test_ip.py`)
  plus a 200,000-address differential run against the prior
  implementation during development, zero mismatches. 2.1× faster in
  isolation.
- `Packet` gained a private `_from_decoded()` fast-construction path
  (`object.__new__` plus direct attribute assignment, the same
  shortcut `_base.py` already documents for Ethernet/ARP/IPv4 field
  construction), used only by `decode_frame()`. The public
  `Packet(...)` constructor is untouched and still validates arbitrary
  arguments.

**A methodology fix, not just a code fix:** `scripts/benchmark.py`'s
measured/gated function had never called `decode_frame()` — #88
shipped it as the documented public chain-walking API, but the
benchmark kept its own hand-rolled copy of the pre-#88 loop, unchanged
since before Tier 1. Every decode-throughput figure published in this
file to date, including the "94,453 f/s" one this section replaces,
described code real callers of the documented API never actually ran.
`decode_netprotocols()` and `_netprotocols_chain()` now call
`decode_frame()` directly, and the now-dead hand-rolled `walk()` was
deleted rather than kept side by side. This is why the number below is
not a clean apples-to-apples successor to the figure it replaces:

- Under the **old** methodology (hand-rolled loop), the two fixes
  above closed the dpkt gap from 1.12× back to near parity (~1.02-1.03×
  across repeated runs) — the two accidental-overhead fixes alone did
  almost all of that work, confirming the profile.
- Under the **new** methodology (`decode_frame()`, what ships),
  `decode_frame()` carries real, deliberate overhead beyond that
  hand-rolled loop — the bounded-depth check (section 5) and
  materializing every layer into a returned `Packet` — measured at
  +5.9% over the hand-rolled loop after the `Packet` fast path (down
  from +16.5% before it). That is capability, not accident, and this
  register does not trade it away to chase a bigger number.

Re-measured with the harness both fixes and the methodology fix apply
to:

```
uv run --group bench python scripts/benchmark.py --compare --repetitions 30 --trials 9 --depth
```

- CPython 3.12.3, x86-64 Linux, 97 corpus frames, same machine class as
  every prior measurement in this file, run-to-run variance ≈ ±2%.

| | frames/sec | vs. netprotocols |
|---|---|---|
| **netprotocols (post-#147, 2.2.0, via `decode_frame()`)** | **97,739** | — |
| dpkt 1.9.8 | 106,619 | 1.09× (dpkt is faster) |
| scapy 2.7.0 | 18,144 | 0.19× |

netprotocols now decodes the corpus at 97,739 f/s against dpkt's
106,619 — dpkt is ~9% faster, an improvement on the ~11% gap this
section replaces even after accounting for the harder, more honest
workload now being measured. The vs.-scapy gap is essentially
unchanged, 5.4× against the prior 5.6× (noise-level). Decode depth is
unchanged: netprotocols still reaches further than dpkt on 27 of 97
frames and matches it on the other 70 (see 1.6).

`benchmarks/baseline.json` — five tiers and this fix stale at a
v1.3.0-era figure (114,388 f/s) that predated everything above — was
refreshed to this tree's number (98,007.5 f/s / 6.5677 normalized,
matching methodology).

---

### Re-measured for 2.3.0 (2026-10-23)

Every number the README quotes, re-measured before tagging 2.3.0 (the
HTTP/1.1 codec, #214/#223/#226), on **a different machine from every
figure above**: a cloud container, Intel Xeon @ 2.10 GHz, 4 vCPUs,
CPython 3.12.3, x86-64 Linux; `dpkt 1.9.8`, `scapy 2.7.0`. Ratios carry
across machines far better than absolute rates, so compare the ratios.

| Claim | Command | Result |
|---|---|---|
| 1.1 / 1.2 decode | `benchmark.py --compare --repetitions 30 --trials 9` | netprotocols 99,814 f/s, dpkt 106,497 (we are 6.3% slower), scapy 21,826 (we are 4.6× faster) |
| 1.3 encode | `benchmark_encode.py` | netprotocols 1,324,381 ops/s, dpkt 292,408 (4.53×), scapy 658,403 |
| 1.4 import | `benchmark_import.py`, best of three runs | netprotocols 56.8 ms (83 modules), scapy.all 487.0 ms (8.6×); at `657b65f`, the commit before #223 made the package import `http.py`, 55.6 ms (82 modules) |
| 1.5 wheel | `uv build` | `netprotocols-2.3.0-py3-none-any.whl` 108,598 bytes (106.1 KiB), 23.9× smaller than scapy's 2,590,982; `src/` 7,953 lines |
| 1.6 depth | `benchmark.py --depth` | deeper on 27 frames, same layer on 70: unchanged |

What moved, and why:

- **Decode is unaffected by HTTP**, which is not port-dispatched, so
  `decode_frame()` never reaches it; the dpkt gap (6.3%, from ~9%) and
  the scapy ratio (4.6×, from 5.4×) moved with the machine. scapy runs
  relatively faster here than on the machine above; the 1.1 headline,
  "2.1×", stays a conservative floor.
- **Import cost grew by about a millisecond** from the codec itself
  (55.6 → 56.8 ms, one more module), inside run-to-run noise of a few
  milliseconds on this machine.
- **The wheel grew 16 KiB** with `layer7/http.py`, the largest module
  in the package, so the ratio against scapy fell from 28.0× to 23.9×.
- The module count reads 83 here where 1.4 recorded 93 for 2.0-era
  code; the count depends on the interpreter's own startup imports, so
  it is quoted with the time it came from, not on its own.

---

### Re-measured for 2.4.0 (2026-10-25)

Every number the README quotes, re-measured before tagging 2.4.0 (Tier 1
of #170: IP-in-IP, VXLAN, ESP, AH and SCTP, #230-#234), on the same
machine class as the 2.3.0 figures above: a cloud container, Intel Xeon
@ 2.10 GHz, 4 vCPUs, CPython 3.12.3, x86-64 Linux; `dpkt 1.9.8`,
`scapy 2.8.0`. **The corpus is not the one any earlier figure used**:
it grew from 97 frames in 17 scenarios to 140 in 22 with the tier's
five captures, so the decode rates here are not comparable with any
earlier section's, only the ratios measured on the same run.

| Claim | Command | Result |
|---|---|---|
| 1.1 / 1.2 decode | `benchmark.py --compare --repetitions 30 --trials 9`, three runs | netprotocols 119,098 / 113,681 / 118,365 f/s; dpkt 115,637 / 120,066 / 116,215; scapy 27,880 / 29,160 / 29,004. Against dpkt: 3.0% faster, 5.3% slower, 1.8% faster. Against scapy: 4.27×, 3.90×, 4.08×. Quoted: the median run, 118,365 against 116,215 and 29,004 (**4.1×**) |
| 1.3 encode | `benchmark_encode.py` | netprotocols 1,416,774 ops/s, dpkt 338,650 (**4.18×**), scapy 700,191 |
| 1.4 import | `benchmark_import.py`, best of three runs | netprotocols **55.0 ms** (87 modules), scapy.all **428.0 ms** (7.8×); dpkt 33.9 ms (107 modules) |
| 1.5 wheel | `uv build --wheel` on a `git archive` of the release commit | `netprotocols-2.4.0-py3-none-any.whl` 127,409 bytes (124.4 KiB), **21.7×** smaller than `scapy-2.8.0-py3-none-any.whl`'s 2,762,122 (2.63 MiB); `src/` 9,099 lines |
| 1.6 depth | `benchmark.py --depth` | deeper on **39 of 140** frames, same layer on 101 |

What moved, and why:

- **Decode against dpkt is at parity on this corpus**, inside run-to-run
  noise in both directions (from 5.3% slower to 3.0% faster over three
  runs), where 2.3.0 read 6.3% slower on the 97-frame corpus. Nothing
  in the decode hot path changed; what changed is the workload, whose
  43 new frames are all tunnels, IPsec and SCTP, and on the 11 VXLAN
  frames netprotocols decodes the tunnelled frame that dpkt leaves raw
  (see 1.6). No per-scenario rates were taken, so which frames moved
  the gap is not measured here. This is **not** a "faster than dpkt"
  result (section 6): the README keeps the 15% band, and the sign of
  the gap flipped between consecutive runs.
- **The depth lead grew by 12 frames, all from the new captures**: the
  11 VXLAN frames, whose tunnelled Ethernet frame dpkt leaves as raw
  bytes after the UDP header, and one SCTP frame (the script-built
  packet with an unknown chunk type) that dpkt leaves raw after IPv4.
  The other 27 are the DHCP, DNS, DNS-over-TCP, IPv6 fragment, MLD and
  VLAN/ARP frames counted since 1.6 was first measured.
- **Import cost is unchanged** within noise (55.0 ms against 56.8 ms),
  with four more modules (87, from 83): `vxlan.py`, `esp.py`, `ah.py`
  and `sctp.py`. `scapy.all` read 428.0 ms against 2.3.0's 487.0 ms;
  if the correction below holds, both were scapy 2.8.0, so that is the
  machine from run to run, not scapy. The ratio fell from 8.6× to 7.8×.
- **The wheel grew 18.3 KiB** against 2.3.0's real wheel (108,658
  bytes; see the correction below) with the five protocols and SCTP's
  CRC32c code, and that growth alone is why the ratio fell: against the
  2.7.0 wheel the 2.3.0 figure used, it would be 20.3×. scapy 2.8.0's
  own wheel is 0.16 MiB larger than 2.7.0's, which lifts it back to
  21.7×.
- **Two corrections to the 2.3.0 figures above.** They name `scapy 2.7.0`,
  but `uv.lock` had pinned `scapy 2.8.0` since `ca17292` (2026-10-09),
  two weeks before 2.3.0 was tagged, and `uv run --group bench` installs
  what the lock pins. The 2.3.0 scapy figures were therefore most likely
  taken against 2.8.0, and its 1.5 ratio set netprotocols' wheel against
  the 2.7.0 wheel's size (2,590,982 bytes) rather than the 2.8.0 one
  that run would have installed. Separately, its 108,598-byte wheel was
  built before that release's README edits, which ship in the wheel's
  `METADATA`: rebuilt from the release commit (`7837c1a`), the 2.3.0
  wheel is 108,658 bytes, the size of the wheel on PyPI, so its ratio
  against 2.7.0's wheel was 23.8×, not 23.9×. The 2.3.0 rows are left
  as recorded. The figures here name the version the lock pins, measure
  its own wheel, and take netprotocols' wheel from `uv build --wheel`
  run on a `git archive` of the release commit itself.

### Re-measured for 2.5.0 (2026-10-25)

Every number the README quotes, re-measured before tagging 2.5.0 (Tier 2
of #170: VRRP, RIP, OSPF, PIM and BGP, #243 and #245-#248), on the same
machine class as the 2.4.0 figures above: a cloud container, Intel Xeon
@ 2.10 GHz, 4 vCPUs, CPython 3.12.3, x86-64 Linux; `dpkt 1.9.8`,
`scapy 2.8.0`. **The corpus is not the one any earlier figure used**:
it grew from 140 frames in 22 scenarios to 265 in 27 with the tier's
five captures, so the decode rates here are not comparable with any
earlier section's, only the ratios measured on the same run.

| Claim | Command | Result |
|---|---|---|
| 1.1 / 1.2 decode | `benchmark.py --compare --repetitions 30 --trials 9`, three runs | netprotocols 107,199 / 108,099 / 104,092 f/s; dpkt 139,696 / 137,385 / 133,900; scapy 31,814 / 31,137 / 30,661. dpkt faster by 1.30×, 1.27×, 1.29×. Against scapy: 3.37×, 3.47×, 3.39×. Quoted: the median run, 107,199 against 139,696 (**dpkt 1.30× faster**) and 31,814 (**3.4×**) |
| 1.3 encode | `benchmark_encode.py` | netprotocols 1,601,847 ops/s, dpkt 346,818 (**4.62×**), scapy 806,257 |
| 1.4 import | `benchmark_import.py`, best of three runs | netprotocols **70.0 ms** (92 modules), scapy.all **396.9 ms** (5.7×); dpkt 32.5 ms (107 modules) |
| 1.5 wheel | `uv build --wheel` on a `git archive` of the release commit | `netprotocols-2.5.0-py3-none-any.whl` 180,744 bytes (176.5 KiB), **15.3×** smaller than `scapy-2.8.0-py3-none-any.whl`'s 2,762,122 (2.63 MiB); `src/` 13,749 lines |
| 1.6 depth | `benchmark.py --depth` | deeper on **79 of 265** frames, same layer on 186 |

The first two decode runs' headers print "netprotocols 2.4.0": the
version was bumped while they ran, and the decoded tree was the same
2.5.0 code in all three.

What moved, and why:

- **dpkt now decodes this corpus about 1.3× faster, and the claim
  "within 15% of dpkt" (1.2) no longer holds.** It is the workload, not
  a regression. Measured file by file, best of 7 passes of 30
  repetitions each (a throwaway harness over `benchmark.py`'s own
  `decode_netprotocols` and `decode_dpkt`, not a committed script), the
  five new captures take netprotocols 1.46× dpkt's time, and the 140
  frames 2.4.0 was measured on 1.14× in that run and 1.02-1.10× in the
  A/B below:

  | Fixture | Frames | netprotocols f/s | dpkt f/s | dpkt faster by |
  |---|---|---|---|---|
  | `ospf.pcap` | 54 | 115,282 | 160,858 | 1.40× |
  | `bgp.pcap` | 19 | 88,795 | 143,987 | 1.62× |
  | `pim.pcap` | 13 | 72,277 | 165,868 | 2.29× |
  | `rip.pcap` | 21 | 138,089 | 173,787 | 1.26× |
  | `vrrp.pcap` | 18 | 118,974 | 136,079 | 1.14× |
  | the five together | 125 | 107,239 | 156,417 | 1.46× |
  | the other 22 files | 140 | 112,865 | 129,067 | 1.14× (this run) |

  The same harness run twice on the 2.4.0 tree (`0a33a5d`) and twice on
  this one, alternating, over those 140 frames read 119,777 and 118,200
  f/s for 2.4.0 and 114,797 and 114,806 for 2.5.0, with dpkt between
  117,313 and 127,185 across the four runs: netprotocols' gap to dpkt
  was 1.06× and 1.03× on 2.4.0 and 1.02× and 1.10× on 2.5.0, inside
  each other's noise, and 2.4.0's own `benchmark.py --compare` on its
  140-frame corpus, re-run on this machine, still reads 1.03×. The
  ~3% lower absolute rate on those frames is below what this harness
  resolves; whether it is real is not established here. The routing
  frames are where dpkt leads: it decodes OSPF, PIM and VRRP from IP
  itself, to the same layer as netprotocols (1.6). Why it is faster on
  them was not profiled for this release; what netprotocols does there
  that dpkt does not is known (frozen dataclasses against dpkt's lazy
  attributes, and framing walked at decode: PIM's structural bound and
  Hello option walk, OSPF's packet-length checks, BGP's one layer per
  message), but how much each costs is not measured. BGP and RIP are
  decoded further than dpkt goes, so part of their gap is work dpkt does
  not do.
- **The depth lead grew by 40 frames, all from the new captures**: the
  19 BGP frames, whose messages dpkt leaves as raw bytes after TCP (it
  does not dispatch port 179), and the 21 RIP frames, which it leaves
  raw after UDP (port 520). The other 39 are the frames counted at
  2.4.0.
- **Import cost grew 15 ms** (70.0 ms against 55.0 ms) with five more
  modules (92, from 87): `vrrp.py`, `rip.py`, `ospf.py`, `pim.py` and
  `bgp.py`, which define 27 frozen dataclasses between them, each
  generated at import. `scapy.all` read 396.9 ms against 428.0 ms, the
  machine from run to run. The ratio fell from 7.8× to 5.7×.
- **Encode moved within noise** (4.62× against 4.18×): Tier 2 did not
  touch the encode benchmark's path, and both libraries' rates rose
  between the runs (netprotocols 13.1%, dpkt 2.4%).
- **The wheel grew 52.1 KiB** with the five protocols, and the
  ratio fell from 21.7× to 15.3×.

### Re-measured for 2.6.0 (2026-10-28)

Every number the README quotes, re-measured before tagging 2.6.0 (Tier 3
of #170: MPLS, LLDP, LLC/SNAP, STP and CDP, #252-#256), on the same
machine class as the 2.5.0 figures above: a cloud container, Intel Xeon
@ 2.10 GHz, 4 vCPUs, CPython 3.12.3, x86-64 Linux; `dpkt 1.9.8`,
`scapy 2.8.0`. **The corpus is not the one any earlier figure used**:
it grew from 265 frames in 27 scenarios to 293 in 30 with the tier's
three captures (`mpls.pcap`, `lldp.pcap`, `llc.pcap`), so the decode
rates here are not comparable with any earlier section's, only the
ratios measured on the same run. The figures in the table were taken
on the release tree (`netprotocols 2.6.0` in each header). The A/B
figures below come from two extracts beside it: the 2.5.0 tree
(`7549dc0`), and `c008e18`, this release's library code before the
version bump with the three new captures removed, whose headers
therefore print "netprotocols 2.5.0".

| Claim | Command | Result |
|---|---|---|
| 1.1 / 1.2 decode | `benchmark.py --compare --repetitions 30 --trials 9`, three runs | netprotocols 94,224 / 87,744 / 84,869 f/s; dpkt 120,665 / 116,720 / 113,563; scapy 26,108 / 25,978 / 26,446. dpkt faster by 1.28×, 1.33×, 1.34×. Against scapy: 3.61×, 3.38×, 3.21×. Quoted: the median run, 87,744 against 116,720 (**dpkt 1.33× faster**) and 25,978 (**3.4×**). dpkt decodes 292 of the 293 frames in every run (see the depth bullet below) |
| 1.3 encode | `benchmark_encode.py` | netprotocols 1,532,546 ops/s, dpkt 329,211 (**4.66×**), scapy 740,740 |
| 1.4 import | `benchmark_import.py`, best of three runs | netprotocols **89.8 ms** (97 modules), scapy.all **436.2 ms** (4.9×); dpkt 35.5 ms (107 modules) |
| 1.5 wheel | `uv build --wheel` on a `git archive` of the release commit | `netprotocols-2.6.0-py3-none-any.whl` 225,832 bytes (220.5 KiB), **12.2×** smaller than `scapy-2.8.0-py3-none-any.whl`'s 2,762,122 (2.63 MiB); `src/` 16,943 lines |
| 1.6 depth | `benchmark.py --depth` | deeper on **94 of 293** frames, "same layer" on 198 (the script's words; see below), and one frame dpkt cannot decode |

What moved, and why:

- **The headline ratios held: dpkt is still about 1.3× faster on the
  whole corpus, netprotocols still 3.4× faster than scapy.** What no
  longer holds is the README's sub-claim that the 140 frames the
  corpus held at 2.4.0 "are still within 10%". Measured with the same
  kind of throwaway harness 2.5.0 used (best of 7 passes of 30
  repetitions over `benchmark.py`'s own `decode_netprotocols` and
  `decode_dpkt`, not a committed script), file by file, twice:

  | Fixture | Frames | netprotocols f/s | dpkt f/s | dpkt faster by | second run |
  |---|---|---|---|---|---|
  | `mpls.pcap` | 8 | 89,697 | 89,799 | 1.00× | 1.04× |
  | `lldp.pcap` | 6 | 96,527 | 491,622 | 5.09× | 4.85× |
  | `llc.pcap` | 14 | 88,726 | 93,455 | 1.05× | 0.86× |
  | the three together | 28 | 79,863 | 90,521 | 1.13× | 1.24× |
  | the five Tier 2 files | 125 | 97,730 | 148,637 | 1.52× | 1.50× |
  | the other 22 files | 140 | 106,108 | 110,357 | 1.04× | 1.19× |
  | all 30 | 293 | 89,414 | 112,469 | 1.26× | 1.41× |

  The LLDP row is not a like-for-like comparison: dpkt 1.9.8 does not
  dispatch EtherType 0x88CC and leaves the LLDPDU as raw bytes after
  Ethernet, so it does almost no work on those frames (as with
  `vxlan.pcap`'s inner frames, #250). On MPLS and LLC/SNAP, which dpkt
  does decode (labels into `Ethernet.mpls_labels`, LLC, SNAP, STP and
  CDP through `dpkt.llc`, `dpkt.stp` and `dpkt.cdp`), the two are level.
  The Tier 2 routing captures are still where dpkt leads, at about two
  thirds of netprotocols' time.

  On the 140 frames 2.4.0 was measured on, the harness was run sixteen
  times on this tree and sixteen on the 2.5.0 tree (`7549dc0`, its own
  venv on the same interpreter and lock), alternating. dpkt's lead
  there had a median of **1.14×** on 2.6.0 (0.98-1.20×, and 2.03× in
  one run in which netprotocols read 52,887 f/s, a disturbed run that
  is listed rather than dropped) against **1.07×** on 2.5.0
  (0.94-1.19×). So "within 10%" no longer describes those frames,
  and today it held for 2.5.0 itself on only 11 of its 16 runs.
- **Whether Tier 3 slowed the old frames is not resolved.** Every
  frame's walk now passes Ethernet's type-versus-length branch, and
  `decode_frame()` tests each layer's `_BOUNDS_PAYLOAD`, so a small real
  cost is plausible. Over the 265 frames both trees share, in the same
  sixteen alternating pairs, netprotocols' median was 88,645 f/s on
  2.6.0 against 91,693 on 2.5.0 (3.3% lower, lower in 12 of 16 pairs),
  while dpkt, the same code in both venvs, read a median 122,268
  against 122,013. On the 140 frames the median was 2.1% lower (11 of
  16 pairs). `benchmark.py --compare` itself, run three times each,
  alternating, on 2.5.0 and on `c008e18` (this release's library code)
  with the three new captures removed, read netprotocols 100,532 /
  95,789 / 94,303 against 84,995 / 92,036 / 97,489 f/s, and the gate's
  normalized figure 5.5598 / 5.8932 / 5.5451 against 5.8346 / 5.5992 /
  4.7109, the opposite sign. The run-to-run spread on this machine is
  about ±8%, so a cost of a few percent is likely but not established
  here, and was not profiled. Profiling the decode path is #250.
- **The depth lead grew by 15 frames, all from the new captures**, but
  only 7 of them are frames dpkt leaves as raw bytes; checked frame by
  frame with `benchmark.py`'s own `_netprotocols_chain` and `_dpkt_chain`:
  - **all 6 LLDP frames**: dpkt stops at Ethernet with the LLDPDU raw;
  - **the VLAN-tagged 802.3 SNAP/ARP frame** of `llc.pcap`: dpkt leaves
    everything after the Ethernet header and its tag raw;
  - **3 of the 8 MPLS frames** (the UDP ones) count one layer deeper
    only because netprotocols makes the label stack a layer of its own;
    dpkt parses the labels too, into `Ethernet.mpls_labels`, and stops
    at UDP like netprotocols. The ICMP ones count the same, because
    dpkt's ICMP Echo object makes up the layer;
  - **3 CDP and 2 SNAP/ARP frames** count deeper only because
    netprotocols makes SNAP a layer of its own where dpkt folds it into
    `LLC` (`oui`, `type`). dpkt decodes CDP's TLVs into `CDP.tlvs`
    too; the chain shows them as raw bytes only because dpkt then sets
    `.data` to the TLVs' bytes.
  The README names MPLS label stacks and SNAP headers beside 802.1Q
  tags, which it already counted on the same terms. The five STP
  BPDUs that dpkt decodes (`dpkt.stp`) count the same. The sixth BPDU,
  the 802.1D Topology Change Notification, is the one frame dpkt cannot
  decode: `dpkt.stp.STP` needs 35 bytes and raises `NeedData` on the
  4-byte TCN, so `--depth` skips it (94 + 198 is 292) and every
  `--compare` run reports dpkt at 292/293. Two frames go further in
  dpkt and are counted "the same": `mpls.pcap`'s Ethernet pseudowire
  (dpkt decodes the inner Ethernet frame; netprotocols' `MPLS` stops
  at the control word's first nibble of 0, the module's documented
  convention),
  and `llc.pcap`'s Novell raw 802.3 IPX frame (dpkt recognises its
  0xFFFF checksum as IPX; netprotocols reads those two octets as an LLC
  header and stops at `LLC`). The script's "same layer" means "not deeper": by layer count
  dpkt has more on 58 of the 198 (57 of 2.5.0's 186), mostly ICMP Echo,
  GRE and VRRP objects, and this bullet does not try to correct that
  count.
- **Import cost grew about 20 ms** (89.8 ms against 70.0 ms) with five
  more modules (97, from 92): `layer2/mpls.py`, `lldp.py`, `llc.py`,
  `stp.py` and `cdp.py`. To separate the code from the machine, the
  2.5.0 tree was re-run alternating with this one, three times each:
  75.6 / 79.2 / 71.4 ms against 92.8 / 86.8 / 91.8 ms. The 19.8 ms
  therefore splits into about 15.4 ms of Tier 3 (best against best,
  86.8 against 71.4), about 1.4 ms of machine (the 2.5.0 tree's 71.4 ms
  today against 70.0 at its release), and about 3 ms of spread between
  the three quoted runs (best 89.8) and the alternating ones (best
  86.8) on the same tree. `scapy.all` (436.2 ms against 396.9) and dpkt
  (35.5 against 32.5) read 9-10% slower than at 2.5.0, more than
  netprotocols' own code did. Under `python -X importtime`, best of five, the
  five modules' own (self) times are 1.3 ms (`mpls`), 3.0 ms (`lldp`),
  1.6 ms (`llc`), 1.3 ms (`stp`) and 2.1 ms (`cdp`), about 9.2 ms, and
  `_enums` grew 0.2 ms; the rest of the growth is not attributed here.
  The modules define 13 dataclasses between them, against Tier 2's 27,
  so the dataclass count does not explain it. The ratio fell from 5.7×
  to 4.9×.
- **Encode moved within noise** (4.66× against 4.62×): Tier 3 did not
  touch the encode benchmark's path, `Ethernet.__bytes__` (its changes
  to `ethernet.py` and `_base.py` are dispatch and the payload bound),
  and both libraries' rates fell about equally between the runs
  (netprotocols 4.3%, dpkt 5.1%).
- **The wheel grew 44.0 KiB** with the five protocols, and
  the ratio fell from 15.3× to 12.2×.

## 1. Performance

### 1.1 "2.1× faster than scapy at decoding"
**Status: VERIFIED — and still understated**

*Published 2026-09-04 (embargo lifted, #107). Re-measured 2026-09-04
after #147 closed the dpkt-throughput regression below — see that
section for the methodology change (the benchmark now measures
`decode_frame()`, not a hand-rolled loop that predated it).*

Was 36,500 frames/sec against scapy 2.7.0's 17,100 at v1.3.0. Tier 1
brought it to 6.2×; post-Tiers-2-4 it read 5.6×; re-measured via
`decode_frame()` after #147 (see the regression-close re-measurement
above): **97,739 against 18,144, a 5.4× gap** — flat against the prior
figure within this file's own noise band. The headline "2.1×" claim
was always a conservative floor and stays true by a wide margin.

Reproduce: `uv run --group bench python scripts/benchmark.py --compare`.

*Re-measured for 2.3.0 (2026-10-23, another machine; see above):
99,814 against 21,826, **4.6×**.*

*Re-measured for 2.4.0 (2026-10-25, the 140-frame corpus; see above):
median of three runs 118,365 against scapy 2.8.0's 29,004, **4.1×**
(3.90-4.27× across the runs).*

*Re-measured for 2.5.0 (2026-10-25, the 265-frame corpus; see above):
median of three runs 107,199 against scapy 2.8.0's 31,814, **3.4×**
(3.37-3.47× across the runs).*

*Re-measured for 2.6.0 (2026-10-28, the 293-frame corpus; see above):
median of three runs 87,744 against scapy 2.8.0's 25,978, **3.4×**
(3.21-3.61× across the runs).*

The wording is a positioning decision, not a measurement one: 5.4× is
what the corpus shows on one machine today, and whoever writes the
README should pick the number they are willing to defend on someone
else's.

### 1.2 "dpkt decodes 1.3× faster" (was "Within 15% of dpkt on decode", true through 2.4.0)
**Status: VERIFIED for 2.6.0 — the 15% claim no longer holds, on the 265-frame corpus or the 293-frame one**

*Re-measured for 2.6.0 (2026-10-28, the 293-frame corpus; see above):
**dpkt 1.33× faster** on the median run (87,744 against 116,720;
1.28-1.34× across three runs), so the heading's figure holds. The
2.5.0 note below that the 140 frames of 2.4.0's corpus "still read
within 10%" no longer does: over sixteen alternating runs of the
file-by-file harness dpkt led on them by a median 1.14× on 2.6.0
against 1.07× on 2.5.0, and whether Tier 3's dispatch changes cost
those frames a few percent is not resolved. The Tier 2 routing
captures are still where dpkt leads (1.50-1.52×); on Tier 3's MPLS and
LLC/SNAP captures the two are level, and LLDP, which dpkt does not
decode, reads about 5× in its favour. Profiling and narrowing the gap
is [#250](https://github.com/EONRaider/NETProtocols/issues/250).*

*Re-measured for 2.5.0 (2026-10-25, the 265-frame corpus; see above):
**dpkt 1.30× faster** on the median run (107,199 against 139,696;
1.27-1.30× across three runs). The 140 frames the claim was last
measured on still read within 10% (1.02-1.10× in a file-by-file A/B
against 2.4.0, which read 1.03-1.06×); the gap is the Tier 2 routing
captures, on which dpkt takes about two thirds of netprotocols' time.
The README now quotes the 1.3× and says where it comes from; closing
it is decode-path work on the routing protocols, not something a
re-measurement can recover. The history below is the claim as it
stood.*

*Published 2026-09-04 (embargo lifted, #107). Re-measured 2026-09-04
after #147 closed the dpkt-throughput regression below.*

v1.3.0 was 2.9× slower than dpkt. Tier 1 (#82-#86) briefly put
netprotocols 1.16× *faster*. Post-Tiers-2-4 it read ~11% slower — a
regression nobody had profiled, closed by #147 (see the re-measurement
above for the full root-cause writeup and the methodology fix that
switched the benchmark to `decode_frame()`, the documented public API,
in the same pass). Re-measured via `decode_frame()`: **97,739 f/s
against dpkt 1.9.8's 106,619 — netprotocols is now ~9% slower**,
comfortably still inside the 15% band the claim names, and a smaller
gap than the figure it replaces despite now measuring more work per
call (the bounded-depth check and full `Packet` construction that the
old hand-rolled benchmark loop never exercised).

Reproduce: `uv run --group bench python scripts/benchmark.py --compare --repetitions 30 --trials 9`.

*Re-measured for 2.3.0 (2026-10-23, another machine; see above):
99,814 against dpkt's 106,497, **~6% slower**, inside the band.*

*Re-measured for 2.4.0 (2026-10-25, the 140-frame corpus; see above):
**at parity** — from 5.3% slower to 3.0% faster over three runs (median
118,365 against 116,215), inside the band. The two caveats below still
apply, now as 39 of 140 frames decoded deeper.*

Two caveats from the re-measurement section apply and are not optional:
the two libraries do not parse to the same depth (netprotocols goes
deeper on 27 of 97 frames), and this is one machine. The defensible
public form was "within 15% of dpkt on the corpus walk, while decoding
further into the stack on more than a quarter of it" — not "faster than
dpkt," which is no longer true and was never true robustly enough to
have shipped it while it briefly was. From 2.5.0 the defensible form is
"dpkt decodes the corpus about 1.3× faster; netprotocols decodes
further into the stack on 79 of its 265 frames" (1.6); for 2.6.0, on
94 of its 293.

### 1.3 "4.2× faster than dpkt at encoding"
**Status: VERIFIED**

*Published 2026-09-04 (embargo lifted, #107). Re-measured under
CPython 3.12, resolving the cross-version caveat this section used to
carry — it now shares a baseline with the corpus decode numbers above.*

`bytes(header)` re-serialization on a decoded synthetic Ethernet
header, best of 9 trials × 20,000 reps, ops/sec:

| Library | ops/sec | Note |
|---|---|---|
| **NETProtocols 2.0.0** | **1,150,600** | repacks from fields |
| scapy 2.7.0 | 559,309 | returns cached original bytes — not a real repack |
| dpkt 1.9.8 | 254,037 | repacks from fields |

Reproduce: `uv run --group bench python scripts/benchmark_encode.py`
(added this session; previously this figure had no checked-in
reproduction script, which Rule 1 does not actually permit — fixed
along with the re-measurement).

*Re-measured for 2.3.0 (2026-10-23, another machine; see above):
netprotocols 1,324,381 ops/s, dpkt 292,408, **4.53×**; scapy 658,403.*

*Re-measured for 2.6.0 (2026-10-28; see above): netprotocols 1,532,546
ops/s, dpkt 329,211, **4.66×**; scapy 2.8.0 740,740. Tier 3 did not
touch the encode path; both rates fell about 5% with the machine.*

*Re-measured for 2.5.0 (2026-10-25; see above): netprotocols 1,601,847
ops/s, dpkt 346,818, **4.62×**; scapy 2.8.0 806,257. Tier 2 did not
touch the encode path either.*

*Re-measured for 2.4.0 (2026-10-25; see above): netprotocols 1,416,774
ops/s, dpkt 338,650, **4.18×**; scapy 2.8.0 700,191. Tier 1 did not
touch the encode path; dpkt's rate rose more than ours between the two
runs (15.8% against 7.0%), most likely the machine from run to run
rather than either library.*

Nobody benchmarks this direction; it remains the half of "codec" this
library already wins. The ratio against dpkt narrowed from the 5.3×
recorded at v1.3.0 to 4.5× by 2.2.x (4.53× for 2.3.0, 4.18× for 2.4.0;
see their dated lines above) — netprotocols' own absolute rate dropped
somewhat less than its decode rate did over the same tiers (encoding
never touched the registry/walker/error-context surface that grew
decode's cost), while dpkt's own number held essentially flat. Still a
wide, clean win.

### 1.4 "Imports in 90 ms; scapy takes 436+ ms"
**Status: VERIFIED**

*Re-measured for 2.6.0 (2026-10-28; see above): best of three
`benchmark_import.py` runs, netprotocols **89.8 ms** (97 modules),
`scapy.all` 2.8.0 **436.2 ms**, **4.9×**. Of the 19.8 ms against
2.5.0's figure, the five Tier 3 modules cost about 15 ms in alternating
runs against the 2.5.0 tree on the same machine, the machine about
1.4 ms (the 2.5.0 tree read 71.4 ms against its 70.0 ms), and about
3 ms is run-to-run spread on this tree; see the 2.6.0 re-measurement
above.*

*Re-measured for 2.5.0 (2026-10-25; see above): best of three
`benchmark_import.py` runs, netprotocols **70.0 ms** (92 modules),
`scapy.all` 2.8.0 **396.9 ms**, **5.7×**. The five Tier 2 modules cost
about 15 ms.*

*Re-measured for 2.4.0 (2026-10-25; see above): best of three
`benchmark_import.py` runs, netprotocols **55.0 ms** (87 modules),
`scapy.all` 2.8.0 **428.0 ms**, **7.8×**.*

*Re-measured for 2.3.0 (2026-10-23, another machine; see above): best
of three `benchmark_import.py` runs, netprotocols **56.8 ms** (83
modules), `scapy.all` **487.0 ms**, **8.6×**. The HTTP codec costs
about a millisecond of it. The figures below are the 2026-09-04
measurement.*

*Published 2026-09-04 (embargo lifted, #107).*

Reproduce: `uv run --group bench python scripts/benchmark_import.py`
(added this session, Rule 1). Best of 5 fresh-process runs each:
netprotocols **54.0 ms**, scapy.all **458.3 ms** — netprotocols imports
**8.5× faster**, down from the implied ~14-21× at v1.3.0's "40 ms vs
570-870 ms." netprotocols' own import cost grew (40 ms → 54 ms) as
Tiers 2-4 added the registry, walker, diagnostics and new protocol
modules; scapy's did not move enough to change the picture. Also: 93
modules loaded against `scapy.all`'s 259 (dpkt, not part of this claim:
117 modules, 41.0 ms).

Worth pairing with the observation that importing scapy still performs
live host introspection — it populated four interfaces and eight routes
on the measuring machine simply by being imported, unchanged from the
original measurement. A codec that turns bytes into objects should
never touch the host.

### 1.5 "~22× smaller wheel than scapy"
**Status: VERIFIED** — re-measure at each release (Rule 4)

*Re-measured for 2.6.0 (2026-10-28): `netprotocols-2.6.0-py3-none-any.whl`
is 225,832 bytes (220.5 KiB) against `scapy-2.8.0-py3-none-any.whl`'s
2,762,122 (2.63 MiB), **12.2× smaller**. `src/` is 16,943 lines.*

*Re-measured for 2.5.0 (2026-10-25): `netprotocols-2.5.0-py3-none-any.whl`
is 180,744 bytes (176.5 KiB) against `scapy-2.8.0-py3-none-any.whl`'s
2,762,122 (2.63 MiB), **15.3× smaller**. `src/` is 13,749 lines.*

*Re-measured for 2.4.0 (2026-10-25): `netprotocols-2.4.0-py3-none-any.whl`
is 127,409 bytes (124.4 KiB) against `scapy-2.8.0-py3-none-any.whl`'s
2,762,122 (2.63 MiB), **21.7× smaller**. `src/` is 9,099 lines.*

*Re-measured for 2.3.0 (2026-10-23): `netprotocols-2.3.0-py3-none-any.whl`
is 108,598 bytes (106.1 KiB) against scapy 2.7.0's 2,590,982, **23.9×
smaller**; `layer7/http.py` added 16 KiB. `src/` is 7,953 lines. The
figures below are the 2.2.1 measurement.*

*Published 2026-09-04 (embargo lifted, #107). Re-measured 2026-09-04:
the prior figure here was built from `netprotocols-2.0.0`, two releases
behind the tree every other number in this file now describes — this
was stale, not a real regression.*

90.4 KiB wheel (`uv build`, `netprotocols-2.2.1-py3-none-any.whl`,
92,553 bytes, deterministic across repeated builds) against scapy
2.7.0's 2.47 MiB (2,590,982 bytes, current PyPI `bdist_wheel`) —
**28.0× smaller**, down from the ~46× recorded at v1.3.0 and the 29.6×
this section previously quoted from the 2.0.0-era build. 6,466 lines
(`wc -l` over `src/`) against scapy's unchanged 246,813 — netprotocols
grew from 3,732 lines as Tiers 2-4 added the registry, walker,
structured diagnostics and new protocol coverage, plus smaller
increments since; scapy's line count and wheel size are both stable
since the version on file. Both move with releases — re-check before
quoting.

### 1.6 "Decodes further into the stack than dpkt, on the same bytes"
**Status: VERIFIED**

*Published 2026-09-04 (embargo lifted, #107). Re-confirmed unchanged
against the Tiers-2-4 tree, again after #147's `decode_frame()`
methodology fix, and again for 2.3.0 (2026-10-23) — same 27/70 split as
originally measured. Re-measured for 2.4.0 (2026-10-25) on the
140-frame corpus: **39 deeper, 101 the same**, the 12 new ones being
the 11 VXLAN frames and one SCTP frame (see the 2.4.0 re-measurement
above). Re-measured for 2.5.0 (2026-10-25) on the 265-frame corpus:
**79 deeper, 186 the same**, the 40 new ones being the 19 BGP and 21
RIP frames (see the 2.5.0 re-measurement above). Re-measured for 2.6.0
(2026-10-28) on the 293-frame corpus: **94 deeper, 198 the same**, and
one frame skipped because dpkt raises on it (an STP Topology Change
Notification). Of the 15 new, 7 are frames dpkt leaves raw (the 6 LLDP
frames and a VLAN-tagged 802.3 SNAP frame) and 8 count deeper because
netprotocols makes an MPLS label stack or a SNAP header a layer of its
own where dpkt folds it into `Ethernet` or `LLC`; "the same" counts
every frame that is not deeper, including two that dpkt decodes
further (see the 2.6.0 re-measurement above); depth
comes from the decoders' own strictness, untouched by anything the
throughput fix or the benchmark-methodology change did.*

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
"faster" only means something stated beside "and it decoded more". The
depth number travels with the speed number as the very next point,
including in README.md, where it is the bullet immediately following
the throughput one (corrected 2026-09-04 from "the same sentence",
which overstated how tightly the two are joined there — an independent
audit for #101 caught the mismatch).

### 1.7 "Decode throughput is regression-gated in CI"
**Status: VERIFIED** — including the comparative form, per the #124 audit below

Every pull request runs the corpus benchmark and fails at 15% below
`benchmarks/baseline.json` (`.github/workflows/ci.yml`). Throughput is
normalized against a fixed calibration workload so a baseline survives
a change of machine, and a failing check re-measures once before
failing so a noisy runner does not block unrelated work.

Reproduce: `uv run --group bench python scripts/benchmark.py --check`.

**"No other Python packet library in this comparison set gates
performance in CI" — audited 2026-09-04 (#124), and the claim is now
made.** Every project below was inspected at the commit/date shown; two
distinctions were applied throughout: *running* a benchmark is not
*gating* on one (a build must actually fail on regression), and a
microbenchmark (one synthetic frame) is noted as such rather than
counted as equivalent to a corpus benchmark.

| Project | Repo @ commit (date inspected) | Runs a benchmark in CI | Fails build on regression | Commits a baseline | Gates? |
|---|---|---|---|---|---|
| dpkt | `kbandla/dpkt` @ `4f8958e` (2024-05-05, last commit) | No — no benchmark code anywhere in the tree or its history | No | No | **No** |
| scapy | `secdev/scapy` @ `03f455c` (2026-09-03) | No — `test/benchmark/dissection_and_build.py` is a microbenchmark (one hardcoded packet, `N=10000`) that only `print()`s a number; never invoked by `.github/workflows/unittests.yml` or `tox.ini` | No | No | **No** |
| pypacker | `gitlab.com/mike01/pypacker` @ `8ae3890` (2026-07-27) — canonical repo; the `mike01/pypacker` GitHub mirror is frozen since 2020 | No — no CI pipeline exists on the canonical repo at all. Historically (GitHub/Travis, deleted 2018) ran the full unittest file, which incidentally included assertion-free perf-logging methods (`tests/test_pypacker.py::PerfTestCase`) | No | No — only `logger.info()` output, never compared | **No** |
| construct | `construct/construct` @ `28c6e57` (2025-04-22) | Yes — `tests/test_benchmarks.py` is a real corpus-style `pytest-benchmark` suite (190+ cases), **but** CI runs it with `--benchmark-disable` (`.github/workflows/main.yml:33`), which collects zero timing data | No | No — `make benchsave` exists but is never invoked by CI | **No** |
| pcapkit | `JarryShaw/PyPCAPKit` @ `d86947e` (2026-08-31) | No — zero benchmark infrastructure; the only "benchmark" hit is an unrelated port-name comment | No | No | **No** |
| dnspython | `rthalley/dnspython` @ `bc3009d` (2026-08-31) | No — no benchmark tooling in the dependency list or CI steps | No | No | **No** |
| pyshark | `KimiNewt/pyshark` @ `91441d3` (2026-03-22) | No — CI runs `pytest` only | No | No | **No** |
| nfstream | `nfstream/nfstream` @ `1426d78` (2026-08-01) | No — five CI workflows (build/test × 3 OSes, CodeQL, fuzz), none time anything | No | No | **No** |
| stackforge | `AKOrojo/stackforge` @ `f0cf66b` (2026-03-15) | No — real Criterion benches exist (`crates/stackforge-core/benches/{packet_parse,layer_dispatch,pcap_throughput}.rs`), but `.github/workflows/test.yml` runs `cargo test`/`pytest`, never `cargo bench` | No | No | **No** |
| PyTCP-net_proto | `ccie18643/PyTCP` (`packages/net_proto/`) @ `e24ab3e` (2026-08-09) | No — `.github/workflows/ci.yml` runs lint, `make test`, and a privileged real-TAP smoke test; a manual `tools/bench_rx_ring.py` microbenchmark exists but is wired to no CI job and benchmarks the RX daemon, not `net_proto` itself | No | No | **No** |

Zero of ten. The closest any project comes is construct (a real corpus
suite, deliberately disabled in CI) and stackforge (real Criterion
benches, never invoked) — both have the harness and skip the gate.
Reproduce this table: each repo was attached read-only via `add_repo`
and inspected at the commit shown; re-run before quoting, since CI
configuration is exactly the kind of thing that changes without a
version bump.

---

## 2. Typing

### 2.1 The `mypy --strict` comparison
**Status: VERIFIED** — the single strongest demo we have

*Published 2026-09-04 (embargo lifted, #107). Re-run against scapy
2.7.0 and dpkt 1.9.8 (unchanged versions) at their current commits.*

*Re-run for 2.4.0 (2026-10-25) against scapy 2.8.0, the version
`uv.lock` pins: `from scapy.layers.inet import IP; p = IP();
reveal_type(p.ThisFieldDoesNotExist)` under `mypy --strict` still
reveals `Any` with no error. The file counts below were not re-counted
for 2.4.0; they stand as of `secdev/scapy` @ `03f455c`.*

```
# scapy 2.8.0 — a field name that does not exist
p.ThisFieldDoesNotExist   → Any     (no error)

# dpkt 1.9.8 — the whole module
import dpkt.ethernet      → error: missing library stubs or py.typed

# NETProtocols — a typo in a real field name
ip.proto                  → error: "IPv4" has no attribute
                              "proto"; maybe "protocol"?
```

Supporting facts, all re-verified against `secdev/scapy` @ `03f455c`
(2026-09-03) and `kbandla/dpkt` @ `4f8958e` (2024-05-05, unchanged):

- Scapy **does** ship `py.typed`, so the marker alone proves nothing.
  Its own mypy configuration (`.config/mypy/mypy_enabled.txt`) now
  enables **89 files** (up from 88; a prior pass at this figure counted
  107 by taking a raw `wc -l` of that file, which includes its blank
  lines and comments — filtering those out the same way scapy's own
  `.config/mypy/mypy_check.py` does gives 89, corrected 2026-09-04), of
  which **two of the one-hundred-twenty-one under `scapy/layers/`**
  (`can.py`, `l2.py`; up from "two of ninety-two" as the directory
  grew) — the dissectors anyone actually touches are still unchecked.
  `Packet.__getattr__` erases every field to `Any`.
- dpkt still ships no `py.typed`; `types-dpkt` and `dpkt-stubs` still
  do not exist on PyPI (both 404 on `pypi.org/pypi/<name>/json`).
  Everything downstream becomes `Any`.
- Ours is `mypy strict = true` over the whole of `src/`, enforced in
  CI, unchanged.

This fits in one screenshot and belongs near the top of the README.

### 2.2 "The only Python packet library you can dissect with `match`/`case`"
**Status: VERIFIED**

*Published 2026-09-04 (embargo lifted, #107). The comparative form
below was held pending the roadmap; the capability itself has been
verified since #93.*

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

The comparative sentence is now published: dpkt builds `__slots__`
from a metaclass and generates no `__match_args__`; scapy routes
fields through `__getattr__`; `construct` returns dicts. None of the
three gives a reader a `case IPv4(protocol=...)` pattern to match
against. This was re-checked against the same commits inspected for
2.1 (`secdev/scapy` @ `03f455c`, `kbandla/dpkt` @ `4f8958e`) plus
`construct/construct` @ `28c6e57` (2025-04-22, inspected for #124) —
`construct`'s `Struct`/`Container` types are dict-like, not
dataclasses, and generate no `__match_args__` either.

### 2.3 "No library combines all five"
**Status: VERIFIED, with one named exception**

*Published 2026-09-04 (embargo lifted, #107).*

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
**Status: VERIFIED**

*Published 2026-09-04 (embargo lifted, #107). Corrected 2026-09-04: the
original text of this section credited the whole table below to #99's
real-Pyodide CI job, which overstated what that job actually runs —
see the note after the table.*

Blocking exactly the modules Pyodide removes (`fcntl`, `termios`,
`resource`, `grp`, `pwd`) under ordinary CPython and re-importing:

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

This table is a **simulation** — a `sys.meta_path` blocklist run under
ordinary CPython, not Pyodide itself — and it is the only evidence
behind the dpkt/pypacker rows above. #99's CI `pyodide` job
(`scripts/pyodide/check_in_pyodide.py`) runs under a **real** Pyodide
WebAssembly runtime, but only imports and decodes the full corpus with
netprotocols there; it never attempts `import dpkt` or `import
pypacker` inside Pyodide at all. What #99 adds on top of the
simulation: it confirms, inside the real runtime, that the five
POSIX-only modules above are genuinely still absent (so the
simulation's precondition holds) and that netprotocols decodes the
entire real-capture corpus there raising nothing but `ProtocolError`.
So "scapy cannot import under Pyodide" is real-Pyodide-verified by
inference (scapy's unconditional `fcntl` import, confirmed absent in
CI) plus source citation; "dpkt and pypacker import cleanly under
Pyodide" is verified only by the CPython-side simulation above, not by
#99's CI job.

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

*Published 2026-09-04 (embargo lifted, #107).*

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
released **2022-08-18**, last committed **2024-05-05** (both
unchanged, re-confirmed against PyPI's JSON API and `kbandla/dpkt` @
`4f8958e`), still advertises Python 2.7 and 3.5–3.9 in its classifiers,
is still marked `Development Status :: 4 - Beta` after twelve years,
has **77 open issues** (down from 95; re-counted 2026-09-04), and
cannot be type-checked at all.

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

`tests/test_corpus.py:70-75` asserts `bytes(layer) ==
frame[cursor:cursor+layer.header_len]` for **every layer of all 293
frames**, across 30 scenarios captured with tcpdump over real kernel
VLAN, GRE, IP-in-IP, VXLAN and DHCP topologies, a userspace SCTP
association, keepalived VRRP routers, BIRD RIP routers and BGP
speakers, FRR OSPF and PIM-SM routers, script-built IPsec ESP and AH,
script-built MPLS label stacks around kernel-built datagrams, lldpd
LLDP agents, and Linux STP bridges with lldpd speaking CDP over IEEE
802.3 LLC/SNAP framing. Every frame's checksums (SCTP's CRC32c,
VRRP's, PIM's, CDP's, and OSPF's packet and LSA checksums included),
every ESP and AH ICV, and every RIPv2 and OSPF keyed-MD5 digest verify
internally (`scripts/check_fixtures.py`).

### 5.2 "Property-based fuzzing of every decoder"
**Status: VERIFIED**

Hypothesis fuzzing asserts that decoding never raises outside
`ProtocolError`, that chain walks terminate, that layers recompose,
that six TLV/name accessors never hang, that `HTTP`'s, `VRRP`'s,
`RIP`'s, `OSPF`'s, `MPLS`'s, `LLDP`'s, `LLC`'s, `SNAP`'s, `STP`'s and
`CDP`'s accessors never raise at all, and that
`bytes(decode(x)) == x` is Hypothesis-generated for **all 36**
protocols, up from 4. `tests/strategies.py` holds one
reusable strategy per protocol;
`tests/test_fuzz.py::TestGeneralizedRoundTrips` parametrizes the
property over the 32 without a hand-written one (#97 added the first
14; `HTTP` is the 15th, `VXLAN` the 16th, `ESP` the 17th, `AH` and
`AHv6` the 18th and 19th, `SCTP` the 20th, `VRRP` and `VRRPv6` the
21st and 22nd, `RIP` the 23rd, `OSPF` the 24th, `PIM`
the 25th, `BGP` the 26th, `MPLS` the 27th, `LLDP` the 28th, `LLC` and `SNAP` the 29th and
30th, `STP` the 31st, `CDP` the 32nd). Reproduce:
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

*Statement count refreshed 2026-09-04 (an independent audit for #101
caught it): this section previously read "1,935 statements", which had
already drifted from 1,441 — still sitting, unfixed until now, in
`pyproject.toml`'s own inline comment above `fail_under`. The
percentage read as stable across both drifts by coincidence: the miss
count never moved while the codebase grew around it. Exactly the kind
of thing Rule 4 exists to catch.*

5,023 statements, 1 missed (99.98%; re-measured 2026-10-28, after
CDP, and the miss is still `Packet.__eq__`'s `NotImplemented`
branch). Enforced, not merely reported:
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

@register("ethertype", 0x88B5)  # IEEE 802 Local Experimental
class Telemetry(Protocol):
    ...
```

Seven tables — `ethertype`, `llc.dsap`, `llc.snap`, `ip.proto`,
`ip.proto.v6`, `udp.port`, `tcp.port` — each named after the field it
dispatches on. The registry *is* the dispatch mechanism, not a hook
bolted onto hardcoded functions: the built-in decoders go in through the
same public `register()` a third party calls
(`src/netprotocols/_defaults.py`), so there is no privileged path and
nothing to fall out of sync.

Reproduce: `uv run pytest tests/test_registry.py` — 40 tests covering
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
no comparative form of this claim is written here. This is separate
from — and not resolved by — #124's CI-gate audit or the roadmap's
embargo lift, both of which were scoped to the eleven claims that
carried a `COMPARATIVE — HELD` banner; this one never did, because it
was never measured in the first place. It would need its own audit,
the same way #124 gave 1.7 one, before a comparative form belongs here.

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

Reproduce: `uv run pytest tests/test_walk.py` — 85 tests (up from the
79 recorded when this section was written, caught by an independent
audit for #101 on 2026-09-04; the file didn't gain tests, one already
there — `test_matches_a_hand_rolled_walk_over_the_corpus`, parametrized
over the first 40 corpus frames — now collects its full 40 instances
because the corpus has since grown past that slice). One of the 85
walks the corpus with a hand-rolled loop and asserts the shipped walker
agrees layer for layer, which is what made retiring the copies safe.

Four properties are the actual claim, since a walker by itself is
eight lines:

- **Bounded depth.** `max_depth` (default 32) raises
  `MaxDepthExceededError`. Chains already terminated — every header
  validates its own declared length — so for nested headers this
  bounds *cost*, not correctness: a crafted frame cannot turn one walk
  into thousands of decodes. BGP is the exception (#185): each message
  in a TCP segment is a layer, so a valid segment of more than 29
  messages — 30 one-prefix UPDATEs fit in a 1448-byte segment, and
  GRO, TSO, loopback and jumbo frames make segments far larger —
  exceeds the default, and the strict walk raises on valid traffic
  (lax stops short). There the caller raises `max_depth` or walks on
  with `decode_frame(frame[packet.consumed:], start=BGP)`
  (`layer7/bgp.py`'s module docstring; tested in `tests/test_bgp.py`'s
  `TestMaxDepth`). Corpus maximum is 10 layers (a TCP segment carrying
  7 BGP messages, one layer each); 7 for nested headers (an ICMP echo
  tunnelled through VXLAN).
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
feature-table tick. Like 5.5, this predates and is unrelated to the
roadmap's now-lifted embargo — it stays unpublished because nobody has
looked, not because #107 was open.

### 5.8 "memoryview walking, measured rather than assumed"
**Status: VERIFIED** (#88)

The roadmap proposed walking with `memoryview` internally. Measured on
the corpus, that is **0.95x** — 5% *slower* — because for one small
frame the view costs more to build than the copy it saves.

So the walker slices whatever it is handed and never converts: `bytes`
stays fastest for a single frame. `netprotocols.pcap` (#100) tried the
same idea one level up — slicing each frame lazily out of a
`memoryview` over the whole capture buffer, instead of copying the
buffer once and slicing `bytes` per frame — on the theory that a
memoryview over a *large contiguous* buffer would keep those slices
zero-copy. Measured, it was not a win: **0.91x-0.98x** across
synthetic captures from ~6MB to ~140MB, sometimes measurably slower.
The reason generalizes #88's own finding rather than contradicting it:
a real capture is many *small* frames, not one large one, and a
`memoryview` slice's own object overhead is paid per frame — it adds
up faster than the one-time copy it was meant to avoid. `read_pcap`/
`read_pcapng`/`read_captures` therefore copy their input once up
front and return plain `bytes` per frame regardless of whether they
were given `bytes` or a `memoryview`; the parameter still accepts
either, for caller convenience, not for a performance contract.

This one is worth stating publicly *as a process claim* twice over:
the obvious optimisation was proposed, measured, and rejected on its
own numbers — once for a single frame (#88), and again for a whole
capture's worth of them (#100) — and every number and its reproduction
is written down. Rule 1 with teeth.

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

`protocol` is set at every one of the 60 raise sites in the library
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

Reproduce: `uv run pytest tests/test_diagnostics.py` — 37 tests across
all three raise shapes (decode-time, construction-time, on-demand
property) plus the rebasing behaviour end to end.

**Why this is a differentiator, not a nicety.** Scapy mostly does not
raise at all. dpkt raises bare `UnpackError` / `NeedData` with nothing
attached. For the audience this library is built for — people parsing
untrusted input — this is the difference between a library that
rejects bad input and one that explains it. No competitor offers it,
though that comparative form stays unpublished until this specific
claim gets its own audit the way #124 gave 1.7 one — the roadmap's
embargo lift did not cover it, since it was never a measured `HELD`
section to begin with.


---

## 6. Claims we must not make

- ❌ **"Faster than dpkt"** (unqualified) — false again, and was never
  safe to publish unqualified even in the one tier where it was true.
  Post-Tier-1 measurement briefly put decode at 1.16× dpkt; re-measured
  after Tiers 2-4 (1.2) netprotocols is ~11% *slower*, still decoding
  further on 27 of 97 frames (1.6). The number moved twice inside one
  roadmap — proof, not incidentally, of why this file holds comparative
  claims until they are re-measured rather than trusting the last
  number on file. Re-measured for 2.4.0 on the 140-frame corpus, it
  reads at parity: faster on two runs of three, slower on the third,
  which is exactly the kind of result this entry keeps out of the
  README. On 2.5.0's 265-frame corpus dpkt is 1.3× faster outright
  (1.2), and on 2.6.0's 293-frame corpus too.
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
