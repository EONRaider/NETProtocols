# How NETProtocols works

This is a guided tour of the library's inner workings, written for
anyone who wants to contribute a protocol, fix a bug, or simply
understand how raw bytes become Python objects and back. No prior
experience with packet dissection is assumed — only curiosity and a
little Python.

## A header is just bytes at fixed positions

Here are the first 14 bytes of a real captured frame — an Ethernet II
header announcing an ARP packet:

```
ff ff ff ff ff ff   00 07 0d af f4 54   08 06
└───────────────┘   └───────────────┘   └───┘
 destination MAC       source MAC     EtherType
   (broadcast)                        0x0806 = ARP
```

Every protocol header works like this: a sequence of fields, each at a
known offset with a known width, in network byte order (big-endian).
Parsing one is nothing more than slicing the right bytes and
interpreting them as integers or addresses.

## From bytes to a dataclass

Each protocol is a **frozen, slotted dataclass** whose fields mirror
the wire format, plus a class-level `struct.Struct` describing the
fixed portion's layout. For the header above:

```python
@dataclass(frozen=True, slots=True)
class Ethernet(Protocol):
    dst: str        # "ff:ff:ff:ff:ff:ff"
    src: str        # "00:07:0d:af:f4:54"
    ethertype: int  # 0x0806

    _struct: ClassVar[Struct] = Struct("!6s6sH")
```

The format string `"!6s6sH"` reads: network byte order (`!`), two
6-byte strings (the MACs), one unsigned 16-bit integer (the
EtherType). The `Struct` is compiled once at class definition time —
decoding a million frames reuses the same compiled object.

Three design choices worth knowing:

- **Frozen + slots**: instances are immutable (safe to share, hash,
  and compare) and carry no `__dict__` (cheap to allocate by the
  million during live capture).
- **Friendly field types**: addresses are stored as their canonical
  strings, everything else as `int`, options as `bytes`. What you see
  in a `repr()` is what you work with.
- **Bitfields are explicit**: where the wire packs several fields into
  one integer (IPv4's version/IHL byte, TCP's offset/flags word), the
  decode method splits them with shifts and masks you can read:

  ```python
  ihl = ver_ihl & 0x0F
  version = ver_ihl >> 4
  ```

## Structural pattern matching

Every decoded header works with `match`/`case` today, and nothing in
`src/` was written to make that true — it falls out of the two design
choices above, for reasons worth being precise about:

```python
match eth:
    case Ethernet(ethertype=EtherType.IPV4):
        ...

match ip:
    case IPv4(protocol=IPProtocol.TCP, ttl=t) if t > 32:
        ...
```

1. **`@dataclass` auto-generates `__match_args__`** from the field
   declaration order — `Ethernet.__match_args__ ==
   ('dst', 'src', 'ethertype')` — so a *positional* class pattern
   (`case Ethernet(dst, src, ethertype)`) works with no extra code. An
   ordinary class has to declare `__match_args__` by hand to get that.
   Most headers here never do either — but a few of the widest ones
   are a deliberate exception: `IPv4`, `TCP` and `DHCP` run to 14, 11
   and 15 fields respectively, so their full auto-generated tuple is
   unusable positionally (nobody writes, or gets right, a
   fourteen-slot pattern). Those three hand-declare a short
   `__match_args__` instead — `IPv4.__match_args__ ==
   ('src', 'dst', 'protocol')` — the two or three fields someone
   drafting a positional pattern actually reaches for. The override is
   documented at each class and pinned by
   `tests/test_pattern_matching.py`, so it cannot drift the way an
   *accidental* override would; keyword patterns
   (`case IPv4(protocol=6)`) are unaffected by any of this and stay
   the documented default (#94). `HTTP` curates one too, of
   properties rather than fields — `('method', 'target',
   'status_code')` — because its two fields are the raw head and body.
2. **Every field with a fixed vocabulary of wire values is an
   `IntEnum`**, defined in [`_enums.py`](src/netprotocols/_enums.py),
   and `IntEnum` subclasses `int`. A *value* pattern therefore matches
   the plain integer the wire actually carries —
   `case Ethernet(ethertype=EtherType.IPV4)` matches an instance whose
   `ethertype` field holds the `int` `0x0800` — with no cast, no
   adapter, and no separate "typed" view to keep in sync with the raw
   field.

Keyword class patterns (`ClassName(field=pattern)`) work on *any*
object exposing that attribute; `__match_args__` is only needed for
the positional form. What a frozen dataclass adds is that the
attribute is guaranteed to exist exactly as declared, with no
proxying: a class pattern here either matches a real field or fails
outright — a mistyped field name in a keyword pattern silently never
matches rather than raising, on any object, dataclass or not, so this
buys reliability rather than a new failure mode, not immunity from
that one. (How this compares to other Python packet libraries is
tracked in `docs/CLAIMS.md`, not stated here — see the embargo notes
there.)

**Keeping this working is a contributor obligation, not a given.**
Field declaration order is part of a class's public API — reordering
fields changes what a positional pattern binds to, silently, for
anyone matching by position. (The curated three are the exception:
`IPv4`/`TCP`/`DHCP`'s hand-declared `__match_args__` is independent of
field order, so reordering *their* fields cannot break positional
matching — but adding or renaming one of the fields the curated tuple
names does need the tuple, and the test pinning it, updated by hand.)
And a field carrying a closed set of wire values should stay an
`IntEnum` sourced from `_enums.py` rather than degrade to a bare
`int`; the moment it does, `case Header(field=SomeEnum.X)` stops
matching and fails silently (the pattern falls through to the next
`case`, it does not raise) rather than loudly.

## The decode contract

`decode(data)` is the heart of the library, and every protocol obeys
the same three rules (spelled out in [`_base.py`](src/netprotocols/_base.py)):

1. **It receives the entire remaining buffer** — everything from the
   start of its header to the end of the captured frame — and parses
   the fixed portion with `_struct.unpack_from`. A buffer too short
   for the fixed portion raises `TruncatedHeaderError`. One enclosing
   length shortens that buffer in a walk: after an Ethernet or VLAN
   header holding an IEEE 802.3 Length, every later layer's buffer ends
   where the Length ends the LLC PDU (see *802.3 framing* below).
2. **Variable-length headers finish the job themselves.** IPv4 reads
   its IHL and TCP reads its data offset, sanity-checks it (5–15, and
   the declared bytes must exist in the buffer — a header that *lies*
   about its length raises `TruncatedHeaderError`), then slices its
   `options` as materialized `bytes`.
3. **Trailing bytes are fine.** Whatever follows the header belongs to
   the next layer. After decoding, `instance.header_len` says exactly
   how many bytes this header consumed — a *property*, so IPv4 answers
   `ihl * 4` and TCP answers `data_offset * 4`.

**Three protocols vary this.** The first is text framing. `HTTP` has no
fixed portion to unpack: `decode()` scans for the empty line that ends
the head, then for the end the head's framing gives the body, so rule 1
is a scan rather than an unpack and `header_len` covers the whole
message, not a `_struct` size. Its `decode()` also takes keyword-only
context the bytes cannot carry — `request_method` (a response to `HEAD`,
or a 2xx to `CONNECT`, has no body whatever its headers say) and
`closed` (the buffer ends where the connection did) — and
`request_method` is stored, but normalized: kept only when it changes
the framing, so two messages with equal bytes and equal framing compare
equal.

The second is `SCTP`. Like ICMPv4, ICMPv6 and IGMP it has no length of
its own: the packet is the whole IP payload, and the walk does not trim
a frame to the IP header's declared length. Those three keep the whole
buffer, Ethernet's zero padding included: ICMPv4's and IGMP's internet
checksum is unchanged by appended zero bytes, and an IPv6 frame carrying
ICMPv6 is never short enough to be padded. SCTP's CRC32c does change
when zero bytes are appended, so `decode()` walks the chunk headers to
find where the packet ends and leaves a run of zero bytes where the next
chunk would start undecoded, since that cannot begin a chunk and is what
an Ethernet sender normally pads a short frame with. Rule 3 holds for
those zeros; any other trailing bytes become part of the packet. Past
the 12-byte common header `decode()` never raises, like the three it
resembles: a remainder the walk cannot parse — a chunk cut by a snap
length, an IP fragment or an ICMP error's quote, or a nonzero trailer
such as an Ethernet FCS, which cannot be told from a broken chunk — is
kept verbatim in `chunks`, the ports and verification tag still decode,
and `verify()` returns `False`. `parsed_chunks` raises only when the
remainder does not walk: a trailer that happens to (an FCS whose bytes
read as a chunk header) parses as a phantom chunk, so `verify()` is the
reliable signal. See
[`layer4/sctp.py`](src/netprotocols/layer4/sctp.py)'s module docstring.

The third is `PIM`. It has no length either, and bounds itself by its
own structure:
a Join/Prune, Register-Stop or Assert ends where its counts and
encoded addresses say, so anything after it is left undecoded, and a
Hello, whose options run to the end of the message, leaves a run of
zero bytes where the next option would start, as SCTP leaves one where
a chunk would. A Register's encapsulated packet runs to the end of the
buffer, which its checksum, over the first 8 bytes only, does not
cover. Past the 4-byte header it never raises either: a body its
parser cannot read is kept whole, for `PIM.message` to report. See
[`layer3/pim.py`](src/netprotocols/layer3/pim.py)'s module docstring.

`RIP` has the same problem one layer up: its 20-byte entries fill the
rest of the UDP datagram, and the walk does not trim to UDP's length
either. It keeps the whole buffer after its 4-byte header, as ICMPv4
and IGMP do, leaving no trailing bytes, so `bytes(RIP.decode(x)) == x`.
Its accessors read whole entries, up to the RFC 4822 authentication
trailer that the first entry's Packet Length locates (when the bytes
there start as a trailer does, `0xFFFF 0x0001`), and report what
is left, fewer than 20 bytes, as `remainder`: an entry a snap length
cut, or a trailer such as an Ethernet FCS, which only the UDP length
could tell apart. Past the header neither `decode()` nor any accessor
raises. Ethernet's zero padding reaches only a message with no entries,
since one entry already fills the minimum frame. See
[`layer7/rip.py`](src/netprotocols/layer7/rip.py)'s module docstring.

`NTP` is the same case: after its 48-byte header come NTPv4 extension
fields (RFC 7822) and a MAC, both optional, up to the end of the UDP
datagram, which nothing in the message bounds. It keeps the whole
buffer after the header, so `bytes(NTP.decode(x)) == x`, and its
accessors split it: extension fields until what is left has a MAC's
length (4, 20 or 24 bytes, the rule RFC 7822 §3's minimum field length
is there for), then the MAC, and anything else as `remainder`. A
4-byte Ethernet FCS after a plain message has a crypto-NAK's length,
and only the UDP length could tell them apart. Past the header
neither `decode()` nor any accessor raises, and Ethernet's padding
never reaches it: the header alone fills the minimum frame. See
[`layer7/ntp.py`](src/netprotocols/layer7/ntp.py)'s module docstring.

`TFTP` has no length field either, but most of its messages bound
themselves: an ACK is 4 bytes, an ERROR ends at the zero byte after its
message, and a request or an OACK after its last whole option pair, a
zero byte where the next name would start ending the options. So it
obeys rule 3 like a header with a length field,
`bytes(TFTP.decode(x)) == x[:header_len]`, and leaves Ethernet's
padding (which every ACK, at 4 bytes, gets in an untagged frame over
IPv4 with no options) and an FCS undecoded, except that a trailer
holding a zero byte can be read in, which only the UDP length could
rule out (#235): after a name with no value, the trailer's first zero
byte ends that value, so padding decodes `("tsize", "")` and takes one
byte, and after whole pairs an FCS that holds a name, a zero byte, a
value and a zero byte, such as `12 00 34 00`, reads as one more pair. A
DATA message cannot bound itself at all: its data has no terminator, so
it runs to the end of the buffer, and a trailer joins it, as it joins
an ICMP `body`. Its
strings are terminated rather than length-prefixed, so a missing
terminator is TFTP's truncation case: a filename, mode or error message
with no zero byte after it raises `TruncatedHeaderError`, as a lying
length does in rule 2, while an option pair cut short is left undecoded,
since only UDP's length could tell it from a trailer. See
[`layer7/tftp.py`](src/netprotocols/layer7/tftp.py)'s module docstring.

`VRRP` has no length field either, but needs no walk: its version and
address count give its exact length (8 bytes, the addresses, and
VRRPv2's 8 bytes of authentication data), so it obeys rule 3 like a
header with a length field and leaves Ethernet's padding undecoded. It
must: a VRRPv3 advert for one IPv4 address is 12 bytes, padded on the
wire, and VRRPv3's pseudo-header carries the message's length.
`STP` is the same case at layer 2: a BPDU has no length field, but its
BPDU Type gives its exact length (4, 35 or 36 octets), so it leaves
whatever follows undecoded, including the extra octets of a PDU longer
than its BPDU, which a receiver ignores (§14.4 of the IEEE 802.1 draft
the module cites). See
[`layer2/stp.py`](src/netprotocols/layer2/stp.py)'s module docstring.

`LLDP` has no length for the whole LLDPDU either, but bounds itself
by its last TLV: its TLVs each carry a Length, and the End of LLDPDU
TLV ends the walk, so it obeys rule 3 like a header with a length
field and leaves Ethernet's padding and an FCS undecoded. A TLV whose
Length runs past the buffer raises `TruncatedHeaderError`, as a lying
length does in rule 2. Wireshark's dissector notes that 802.1AB-2016
made the End TLV optional, so an LLDPDU that reaches the end of the
buffer without one decodes too; there nothing marks where a trailer
starts, so the walk reads one as TLVs: two or more zero bytes read as
an End TLV, and other bytes as another TLV or a framing error. The
mandatory Chassis ID, Port ID and Time To Live TLVs are read by
accessors from the first three positions, which answer `None` rather
than raise when the order is broken, since that is not framing. See
[`layer2/lldp.py`](src/netprotocols/layer2/lldp.py)'s module
docstring.

**802.3 framing.** Bytes 12-13 of an Ethernet header are a type or a
length (IEEE 802.3 Clause 3.2.6): from 0x0600 an EtherType, up to 1500
the length of an IEEE 802.2 LLC PDU, and undefined between, where the
walk ends. `Ethernet.ethertype` holds the raw value either way, and
`VLAN` reads the 2 bytes after a tag the same way. Neither `LLC` nor
`SNAP` has a length of its own, and a short PDU arrives padded to
Ethernet's minimum, often with an FCS after it; STP's BPDUs are that
short, and CDP's checksum covers exactly its PDU. So the Length is the
one enclosing length `decode_frame()` honours: after a header that
holds one (a class setting `_BOUNDS_PAYLOAD`, answering
`_payload_extent()`, both private while #235 settles the public form),
it ends the buffer it hands every later layer at the PDU's end. A
bound past the end of the frame bounds nothing, so a frame a snap
length cut decodes what was captured; a later, looser bound never
widens an earlier one; and a Length shorter than the LLC header leaves
`LLC.decode()` too few bytes, so the walk raises
`TruncatedHeaderError`. IPv4's, IPv6's and UDP's lengths are still not
honoured (#235), so padding behind a short IPv4 packet in Ethernet II
framing reaches its last layer as before. A third-party tag header
(an E-tag, a VN-tag) can answer `LLC` from its own `next_protocol()`,
but can bound the PDU after it only through that private hook, pending
#235. Called directly,
`LLC.decode()` has no Length to go by and leaves the rest of its buffer
to the caller, who can slice `frame[14 : 14 + eth.length]`. See
[`layer2/llc.py`](src/netprotocols/layer2/llc.py)'s module docstring.

`CDP`, which SNAP dispatches at OUI 00-00-0C PID 0x2000, is the first
decoder behind that bound. It has no length of its own: its TLVs run to
the end of the PDU, and its checksum covers the whole PDU, so in a walk
it decodes the PDU and nothing else. Its `decode()` walks TLVs
to the end of the buffer it is handed and stops early, without
raising, only where every byte left is zero, so Ethernet's zero padding
is left undecoded when it is called directly; rule 3 holds for those
zeros only, as for SCTP. Otherwise a TLV Length below 4 raises
`InvalidFieldError`, 1-3 bytes left after the last TLV raise
`TruncatedHeaderError`, and so does a TLV whose Length runs past the
buffer, in a walk too, where those bytes are inside the 802.3 Length.
Wireshark's dissector instead stops at a Length below 4 whatever
follows, and marks 1-3 bytes left malformed even when they are zero.
The zero rule has one blind spot: zeros after the last TLV but inside
the 802.3 Length belong to the PDU the sender declared, yet a walk
leaves them undecoded without raising, so `consumed` stopping short of
the Length's end is the only structural signal. `verify()` sums the
bytes decoded, without them; where the TLVs end at an odd offset on a
nonzero byte and the sender summed the whole Length, it returns
`False`.
`scripts/check_fixtures.py` rejects such a frame, and Wireshark marks
1-3 such zeros malformed and shows 4 or more as a TLV of invalid
Length 0.
See [`layer2/cdp.py`](src/netprotocols/layer2/cdp.py)'s module
docstring.

Decoding accepts `bytes` or `memoryview`. Views are a decode-time
transient only: every stored field is a scalar or materialized
`bytes`, so no decoded object ever aliases the buffer it came from.
You can safely reuse or mutate capture buffers.

Errors form a small typed hierarchy rooted at `ProtocolError`:

```
ProtocolError
├── TruncatedHeaderError     buffer shorter than the header claims
├── InvalidFieldError        field value violates the protocol's rules
│   ├── InvalidMACAddressError
│   ├── InvalidIPv4AddressError
│   └── InvalidManufacturerCodeError
└── MaxDepthExceededError    a frame's chain exceeded decode_frame's max_depth
```

**Every raise carries structured context, not just a message.** A
formatted string is easy for a human to read and impossible for a
fuzzer, conformance suite, or validation tool to act on without
regexing it — so every raise site in `src/` attaches `protocol` (the
class that raised) and, where meaningful, `field` (the attribute at
fault), `offset`, and `expected`/`actual`:

```python
try:
    packet = decode_frame(frame)
except ProtocolError as e:
    print(e.protocol, e.field, e.offset, e.frame_offset, e.expected, e.actual)
```

`offset` is relative to whatever buffer the error was found in. An
error raised by `decode()` is relative to that call's `data` argument,
whatever `field` names: OSPF's framing errors name `field="body"` (or
`"auth_trailer"`) and still count from the start of the OSPF header,
which is what lets `decode_frame` rebase them. An error raised later,
by an accessor that parses a raw `bytes` attribute on demand
(`options`, `body`, `sections`, `chunks`), is relative to that
attribute — a TCP option error's `offset` is relative to
`header.options`, an ICMPv6 NDP option's or an IGMPv3 group record's
to `body`, not to the frame. `decode_frame` is the only code holding
the cursor needed to rebase a layer's own offset to the whole frame,
so it does — the result lands in `frame_offset`, left `None` by a
bare `SomeClass.decode()` call with no frame to rebase against. A
`__post_init__` validation error (values, not bytes) leaves `offset`
`None` too; there is nothing to be positioned in. `HTTP` is the
exception on both counts: its `field` names a grammar element
(`"chunk-size"`, `"start_line"`, `"raw_body"`), and its `offset` is
relative to the start of the message — the `decode()` buffer, or
`head + raw_body` for an error raised while constructing one, which
does have bytes to point into.

All five fields default to `None` and adding them never changes a
message string — every existing `str(err)` and `match=` assertion
holds unchanged.

## Walking a frame: the next_protocol() chain

A captured frame is a chain of headers, each one naming what it
carries. In this library that fact is typed: every decoded header
answers `next_protocol()` with the *class* that decodes its payload,
or `None` when the chain ends (nothing encapsulated, a protocol this
library doesn't implement yet, or a payload no header names in the
clear — ESP's Next Header sits in its protected trailer, encrypted
unless the Security Association uses a confidentiality-free transform
(e.g. NULL, RFC 2410, or AES-GMAC, RFC 4543), and at an offset only
the SA determines, so the decoder never reads it).

`BGP`, `STUN`, `TLS`, `MPLS` and `LLC` are the five exceptions: they
answer from decode context rather than from a wire field alone. A BGP
message carries no payload: a TCP segment can hold several messages
back to back, each decoded as its own layer, so `BGP.next_protocol()`
names the next message *beside* it — `BGP` when the bytes after this
message begin another one, `None` when they do not. STUN over TCP is
the same case, and `STUN.next_protocol()` answers `STUN` the same way,
when the 8 bytes after the message begin like a message's header, its
magic cookie in place; so are TLS records, and `TLS.next_protocol()`
answers `TLS` when as much of the next 3 bytes as the segment holds
passes `TLS.decode()`'s guard. An MPLS label stack carries
a packet but no field naming its protocol (see *MPLS: dispatch by
convention* below), so `MPLS.next_protocol()` infers one, partly from
the first byte after the stack. SAP 0x42 carries GARP's PDUs (Protocol
Identifier 0x0001) beside STP's BPDUs (0x0000), so `LLC.decode()`
records, for a DSAP 0x42 PDU it would dispatch, whether the two octets
after its Control are present and not 0x0000, and `LLC.next_protocol()`
then answers `None`, whatever `llc.dsap` holds at 0x42; fewer than two
octets still reach `STP`, which reports the truncation. Only the bytes
can say, and `next_protocol()` is handed none, so each `decode()`
records what it saw on the instance in a field kept out of the
dataclass's comparison and hash (`compare=False`, the mechanism `HTTP`
uses for its `_message` parse cache). Two equal headers compare equal
however they were found, and can still chain differently. The rules of
the decode contract hold for all five unchanged; see *Port-based
dispatch is best-effort* below,
[`_base.py`](src/netprotocols/_base.py)'s *Decode context in
next_protocol*, the module docstrings of
[`layer7/bgp.py`](src/netprotocols/layer7/bgp.py),
[`layer7/stun.py`](src/netprotocols/layer7/stun.py),
[`layer7/tls.py`](src/netprotocols/layer7/tls.py) and
[`layer2/mpls.py`](src/netprotocols/layer2/mpls.py), and
[`layer2/llc.py`](src/netprotocols/layer2/llc.py)'s *DSAP 0x42*.

```mermaid
flowchart LR
  E[Ethernet] -->|0x0806| A[ARP]
  E -->|0x0800| I4[IPv4]
  E -->|0x86DD| I6[IPv6]
  E -->|0x8100, 0x88A8, 0x9100| V[VLAN tag]
  E -->|length ≤ 1500| L[LLC]
  V -->|length ≤ 1500| L
  L -->|DSAP 0xAA, SSAP 0xAA, UI| SN[SNAP]
  L -->|DSAP 0x42, UI or I, Protocol ID 0| STP[STP BPDU]
  SN -->|OUI 00-00-00 or 00-00-F8, PID 0x0806| A
  SN -->|OUI 00-00-00 or 00-00-F8, PID 0x0800| I4
  SN -->|OUI 00-00-0C, PID 0x2000| CDP[CDP]
  V -->|0x8100, 0x88A8, 0x9100| V
  V -->|0x0806| A
  V -->|0x0800| I4
  V -->|0x86DD| I6
  E -->|0x8847, 0x8848| M[MPLS label stack]
  V -->|0x8847, 0x8848| M
  M -->|bottom label 0, or first nibble 4| I4
  M -->|bottom label 2, or first nibble 6| I6
  E -->|0x88CC| LD[LLDP]
  V -->|0x88CC| LD
  I4 -->|1| IC4[ICMPv4]
  I4 -->|6| T[TCP]
  I4 -->|17| U[UDP]
  I4 -->|132| S[SCTP]
  I4 -->|103| P[PIM]
  I6 -->|58| IC6[ICMPv6]
  I6 -->|6| T
  I6 -->|17| U
  I6 -->|132| S
  I6 -->|103| P
  I4 -->|4| I4
  I4 -->|41| I6
  I6 -->|4| I4
  I6 -->|41| I6
  I4 -->|50| ESP[ESP]
  I6 -->|50| ESP
  I6 -->|0, 43, 44, 60| X[IPv6 extension headers]
  X --> X
  X -->|58| IC6
  X -->|6| T
  X -->|17| U
  X -->|132| S
  X -->|50| ESP
  I4 -->|51| AH[AH]
  AH -->|6| T
  AH -->|17| U
  AH -->|50| ESP
  I6 -->|51| AH6[AHv6]
  X -->|51| AH6
  AH6 -->|0, 43, 44, 60| X
  AH6 -->|6| T
  AH6 -->|17| U
  AH6 -->|50| ESP
  I4 -->|89| OSPF[OSPFv2]
  I4 -->|112| VR[VRRP]
  I6 -->|112| VR6[VRRPv6]
  X -->|112| VR6
  U -->|4789| VX[VXLAN]
  VX -->|always| E
  U -->|520| R[RIP]
  U -->|69, the request only| TF[TFTP]
  U -->|1812, 1813| RAD[RADIUS]
  U -->|123| NT[NTP]
  U -->|1985| HS[HSRP]
  T -->|179| BGP[BGP message]
  BGP -->|another message in the segment| BGP
  U -->|3478| STUN[STUN message]
  T -->|3478| STUN
  STUN -->|another message in the segment| STUN
  T -->|443| TLS[TLS record]
  TLS -->|another record in the segment| TLS
```

IPv6 extension headers (Hop-by-Hop Options, Routing, Fragment,
Destination Options) chain like any other protocol — each names what
follows via `next_header` — and may stack. Two guardrails: the
registry hands them out only inside an IPv6 chain (a garbage IPv4
packet with `protocol=0` cannot conjure a Hop-by-Hop layer), and a
Fragment header chains onward only when `fragment_offset == 0` — a
non-first fragment carries a slice from the middle of the original
payload, so no upper-layer header exists at its start. The same
offset rule applies to fragmented IPv4.

IPsec's AH chains the same way, through its own `next_header`, onward
to anything the IP header before it could have carried (the diagram
draws only the transport, ESP and extension-header edges). It comes as
a pair for that reason: `AH` after IPv4 and `AHv6` after IPv6 have one
wire format but dispatch through their own family's table, so IPv4 →
AH → `0` stops rather than conjuring a Hop-by-Hop layer, while IPv6 →
AH → Destination Options — an order RFC 8200 §4.1 permits — keeps
decoding. VRRP is the other pair, for a different reason: it ends the
walk, but its list of virtual addresses is 4 bytes an entry after IPv4
and 16 after IPv6, which nothing in the VRRP header says, so `VRRP`
reads the one and its subclass `VRRPv6` the other. ESP, the other IPsec header,
ends the walk: what it carries is named only inside its protected
trailer.

VLAN tags chain the same way: a tag's `next_protocol` dispatches the
inner EtherType through the same registry Ethernet uses, so a QinQ
(`0x88A8`) or legacy double-tagged (`0x9100`) frame decodes as one
`VLAN` layer per tag and the innermost payload (IPv4/IPv6/ARP) chains
normally. The Tag Control Information word is split into its semantic
bitfields — `pcp`, `dei`, `vid` — as dataclass fields validated in
`__post_init__`, with the packed 16-bit view kept as the `tci`
property (the same pattern `IPv6` uses for `version` /
`traffic_class` / `flow_label`).

**MPLS: dispatch by convention.** An MPLS label stack (RFC 3032) sits
where a VLAN tag does, after Ethernet's EtherType (0x8847, or 0x8848
for a multicast frame whose top label is upstream-assigned, RFC 5332),
and decodes as one `MPLS` layer however many 4-byte entries it holds:
the stack ends at the entry with its Bottom of Stack bit set, so it
bounds itself, and a deep stack counts once against `max_depth`. What
it does not have is a field naming the packet it carries. RFC 3032
§2.2 leaves that to the binding of the label popped at the egress,
which a capture never shows, so `MPLS.next_protocol()` follows a
convention. A bottom label reserved for a payload settles it — 0, IPv4
Explicit NULL, is IPv4 and 2, IPv6 Explicit NULL, is IPv6, whatever
the bytes say, while 13 (GAL) and 14 (OAM Alert) are followed by a
channel header or an OAM message and stop the walk. Otherwise the
first nibble after the stack is read as an IP version, 4 or 6, as
routers that load-balance IP over MPLS do (RFC 4928); anything else, a
pseudowire control word's 0 among them, stops the walk. The class
comes from the `ethertype` table at 0x0800 or 0x86DD, so a `registry`
or `decode_as` override reaches the labelled packet too. The nibble is
a guess, as a port is: an Ethernet pseudowire sent without a control
word, whose inner destination MAC address happens to begin with 4 or
6, decodes as an IP header, which is the misreading RFC 4928 and RFC
4385's control word exist to prevent. GRE dispatches its Protocol Type
through the `ethertype` table too, so MPLS in GRE (RFC 4023) reaches
`MPLS` with no code of its own. See
[`layer2/mpls.py`](src/netprotocols/layer2/mpls.py)'s module
docstring.

The numbers on the arrows are the wire values — EtherTypes out of
Ethernet, IP protocol numbers out of IPv4/IPv6; MPLS's arrows, which
no wire field names, are the convention above — and they live in
[`_enums.py`](src/netprotocols/_enums.py) as `EtherType` and
`IPProtocol`. IPv4 and IPv6 share one registry because the number
space is shared (1 is ICMPv4, 58 is ICMPv6, 6 is TCP, 17 is UDP, 132
is SCTP, 103 is PIM — no collisions; 51 is AH and 112 is VRRP in
both, each decoded by a class of each family's own). 89 is the
exception: it is OSPF in both families, but OSPFv2 (RFC 2328) after
IPv4 and OSPFv3 (RFC 5340), a different wire format, after IPv6, and
this library decodes only OSPFv2, so `OSPF` is reached from IPv4
alone.

A complete frame walk is a five-line loop — which is exactly why it
ships as [`decode_frame()`](src/netprotocols/walk.py) rather than as
something every caller retypes:

```python
packet = decode_frame(frame)          # Packet(Ethernet(...), IPv4(...), TCP(...))
```

Underneath it is the loop the two answers imply:

```python
layers, cursor, end, protocol = [], 0, len(frame), start
while protocol is not None:
    header = protocol.decode(frame[cursor:end])
    layers.append(header)
    cursor += header.header_len
    if header._BOUNDS_PAYLOAD:  # an 802.3 Length (see above)
        end = _bounded(header, cursor, end)
    protocol = header.next_protocol(registry)
```

The shipped version adds what a copy-pasted loop never has: a bounded
depth (`max_depth`, so a crafted frame cannot make the walk grind), an
explicit `start=` layer for buffers that begin mid-stack, a `lax=True`
mode that reports partial success on `packet.stopped_by` instead of
raising, and the `registry`/`decode_as` hook above. The walk slices
whatever it is handed and never converts: `bytes` stays fastest for one
frame, a `memoryview` over a big capture buffer stays zero-copy.
Wrapping each frame in a `memoryview` internally measured *slower*
(0.95x on the corpus), so the walker does not.

**Where do those arrows live?** Not in the protocol classes. Every
one of them is a row in a dispatch table owned by
[`registry.py`](src/netprotocols/registry.py), and `next_protocol()`
is a single `dict.get` against one of seven tables named after the wire
field they dispatch on:

| Table | Dispatches on | Read by |
|---|---|---|
| `ethertype` | Ethernet II EtherType (from Ethernet and VLAN, 0x0600 and up only; from GRE and SNAP, any value) | `Ethernet`, `VLAN`, `GRE`, `SNAP` (OUI 00-00-00, 00-00-F8); `MPLS` at 0x0800 and 0x86DD, by convention |
| `llc.dsap` | IEEE 802.2 LLC DSAP | `LLC` |
| `llc.snap` | SNAP `(oui << 16) \| pid`, any other OUI | `SNAP` |
| `ip.proto` | IPv4 `protocol` | `IPv4`, `AH` |
| `ip.proto.v6` | IPv6 `next_header` | `IPv6`, extension headers, `AHv6` |
| `udp.port` | UDP well-known port | `UDP` |
| `tcp.port` | TCP well-known port | `TCP` |

`ip.proto.v6` **inherits** `ip.proto`: the two share a number space
but not a table, because the four extension headers must be reachable
only inside an IPv6 chain. Registering in `ip.proto` reaches both,
except at a key `ip.proto.v6` owns itself (51 and 112, below); registering in
`ip.proto.v6` reaches the v6 chain alone. Inheritance
is resolved when you register, not when you look up, so the gating
costs nothing on the hot path — an IPv4 packet with `protocol=0`
cannot conjure a Hop-by-Hop layer because the table it reads has no
entry for `0`.

A child's own registration also *shadows* the inherited entry, which
is how AH's and VRRP's pairs are wired: `AHv6` is registered in
`ip.proto.v6` first, then `AH` in `ip.proto` (and `VRRPv6`, then
`VRRP`, likewise), and the parent write is not inherited over a
key the child already owns. That works the other way round too: a
third party replacing protocol 51 or 112 in `ip.proto` (`override=True`)
changes IPv4 dispatch only, and must register in `ip.proto.v6` as well
to reach IPv6. `_defaults.FAMILY_SPECIFIC_NUMBERS` names the numbers
wired this way, and the tests hold the two tables to differing only at
those keys, the IPv6-only numbers and the IPv4-only one below.

A child can also own a key with no class. Protocol 89 is OSPFv2 in
`ip.proto` and would be inherited into `ip.proto.v6`, where it means
OSPFv3, so every OSPFv3 packet would fail to decode as OSPFv2; instead
the defaults withhold 89 from `ip.proto.v6` (`_defaults.IPV4_ONLY_NUMBERS`)
before registering `OSPF` in `ip.proto`. A withheld key is skipped by
inheritance as an override is, so an IPv6 packet with next header 89
ends its walk at the IPv6 header, as it did before `OSPF` existed, and
a later write to `ip.proto` does not reach it; an OSPFv3 decoder
registered directly in `ip.proto.v6` fills it. `OSPF.decode()` also
rejects any version but 2, for a caller who sends it OSPFv3 on purpose
(`start=` or `decode_as`).

A row need not name a class of its own. IP-in-IP (protocols 4 and 41)
has no header between the outer IP header and the inner one, so its
rows in `ip.proto` point straight at `IPv4` and `IPv6`, and a tunneled
packet walks `IPv4 → IPv4 → …` with no marker layer, as in scapy and
dpkt. Anything that needs "the" IP header of a transport layer must
therefore take the nearest one before it, as `Packet.with_checksums()`
and `Packet.flow_key()` do, not the first.

**Extending the walk without forking.** The tables are public. A
protocol this library does not implement — a proprietary telemetry
header, say, sent under 0x88B5, which IANA's EtherType registry lists
as "IEEE Std 802 - Local Experimental Ethertype", so no built-in
decoder holds it — is one registration away from participating in
frame walks like any built-in:

```python
from netprotocols import Protocol
from netprotocols.registry import register

@register("ethertype", 0x88B5)
class Telemetry(Protocol):
    ...
```

Registrations land in the process-wide `DEFAULT` registry. When they
must not — you are embedding this library, or isolating a test — build
your own with `Registry.from_defaults()` and hand it to the caller
that walks frames. Registering over an existing entry raises
`RegistryConflictError` unless you pass `override=True`, so two
packages claiming the same port cannot silently resolve by import
order; re-registering the *same* class to the same key is a no-op,
because a decorator re-runs whenever its module does.

**Why is the built-in map in its own module?** `Ethernet` must name
`ARP`, `IPv4`, and `IPv6` — but `arp.py` imports from the Ethernet
side of the world (EtherType names). Importing layer modules from each
other at module level would create cycles, so the built-in
registrations live together in
[`_defaults.py`](src/netprotocols/_defaults.py), whose imports sit
inside `install()` and run once from `__init__.py` after every
protocol class exists. Shared enums stay in the dependency-free
`_enums.py`. The layer modules bind their table at import, and every
class a header chooses by a field value (EtherType, IP protocol, port)
comes out of a table, never from an import. Three modules do import
another's class, where there is no field to look up. `layer3/icmp.py`
names `IPv4` and `IPv6` to start the walk of the packet an ICMP error
quotes, which is not dispatch; `layer7/vxlan.py` names `Ethernet`
directly, because a VXLAN payload is always an Ethernet frame; and
`layer2/ethernet.py` names `LLC`, because whatever an 802.3 Length's
value, an LLC header follows it. None can form a cycle: `ip.py` and
`llc.py` import no other layer module, and `ethernet.py` imports only
`llc.py`.

## Port-based dispatch is best-effort

The `ethertype`, `llc.*` and `ip.proto` tables dispatch on a single
authoritative field: it exists to say what follows (MPLS, which looks
up the `ethertype` table by convention, is the exception described
above). The two port tables break that model, and differ in kind
rather than just in name.
A port is a *guess* — any service may run on any port, and the
discriminator is split across the source and destination ports.
Dispatch therefore checks the destination port first (a request
targets the server's well-known port) and then the source port (a
response comes from it). DNS on UDP 53 and DHCP on 67/68 decode as a
fourth layer; on TCP, port 53 names `DNSOverTCP`, a shim that consumes
the 2-byte length prefix (RFC 1035 §4.2.2) and chains onward, so the
walk stays uniform.

VXLAN on UDP 4789 (RFC 7348) is the one port entry whose payload is a
whole Ethernet frame. `VXLAN.next_protocol()` always answers
`Ethernet`, and the walk carries on from there exactly as it does at
the start of a frame — the inner frame's VLAN tags, ARP, IPv4 or IPv6
dispatch through the same `ethertype` table, and the registry a caller
passed reaches them too. The walker needed no change for this:
`start=` only chooses the first class, and every later one comes from
the previous header's `next_protocol()`, whatever its layer. An
encapsulating endpoint normally sends to 4789, the IANA port (RFC 7348
§5), from a source port hashed from the inner flow, so the
destination-first lookup finds VXLAN even when that hash lands on
another registered port. The same precedence means a DNS reply to a
client whose ephemeral port happens to be 4789 dispatches to VXLAN,
never to DNS (and is then rejected at the I flag about half the time).
Only 4789 is registered, and Linux still gives a vxlan device `dstport`
8472, the port it used before IANA assigned one, when `ip link add`
names none, so a capture from such a device needs
`decode_as={"udp.port": {8472: VXLAN}}`. An ICMP echo tunnelled through
VXLAN walks seven layers (`Ethernet → IPv4 → UDP → VXLAN → Ethernet →
IPv4 → ICMPv4`), and a hostile frame nested in itself gains four per
level until `max_depth` stops it.

Because the guess can be wrong, each application class validates on
decode, but it can only reject what its format lets it tell apart from
noise, and for most formats that is little. DNS needs only its 12-byte
header and DHCP its 236-byte fixed part; past that, almost any bytes
decode cleanly as either, and even a datagram to port 53 with no
payload at all, padded to Ethernet's 60-byte minimum, decodes the
padding as a DNS header. VXLAN can reject more, because its header has
one bit it requires: the I flag, which random bytes leave clear half the
time. Over 10,000 random 300-byte UDP payloads per port, decoded with
`decode_frame(..., lax=True)`, the walk ended with `stopped_by` set for
50.1% of those sent to 4789 and for none of those sent to 53 or 67.
With lengths drawn uniformly from 0-600 bytes instead, in frames not
padded to Ethernet's minimum, the figures are about 52%, 2% and 39%,
and every DNS and DHCP rejection is a payload too short for the fixed
header; padded to the minimum, as on the wire, the DNS figure falls to
0%, since the padding itself decodes as a DNS header. The VXLAN
header cannot reject more than it does: RFC 7348 says to ignore its
reserved bits, so rejecting those would refuse real traffic, such as
the Group Based Policy extension's.

RIP on UDP 520 rejects far more, because two of its four header bytes
have values no RIP message carries: `RIP.decode()` requires version 1
or 2 and a nonzero command, which 510 of the 65,536 two-byte prefixes
satisfy, so about 99.2% of random datagrams are rejected. Measured the
same way, the walk stopped for about 99.2% in each case: the 300-byte
payloads sent to 520, and the 0-600 byte ones unpadded and padded, the
differences between them within sampling noise; an empty datagram
padded to the minimum is rejected too, since the padding reads as
version 0. It goes no further. The obsolete and extension commands
(TraceOn, TraceOff, the triggered and update messages) decode, and so
does a RIPv1 message with nonzero must-be-zero fields, which RFC 1058
tells a receiver to ignore but a decoder should show. Past the header,
any 20 bytes are an entry.

RADIUS on UDP 1812 and 1813 (RFC 2865, RFC 2866) rejects a little
more again, through its Length alone: `RADIUS.decode()` requires at least
the 20 bytes of its header (`InvalidFieldError` below that) and no more
than the buffer holds (`TruncatedHeaderError` past it). A random
300-byte payload therefore passes only when its third and fourth bytes
read 20-300, 281 of 65,536 values, and one of n bytes with n - 19 of
them, which over lengths drawn uniformly from 0-600 averages 281 too.
Measured the same way (`random.Random` seeds 0-2), the walk stopped
for about 99.6% in each case (99.57% expected): the 300-byte payloads
and the 0-600 byte ones, padded or not, on either port. The Code is
not checked: every value decodes, and the codes of RFC 2865, RFC 2866,
RFC 5997 and RFC 5176 are named (IANA assigns others, such as 6-10,
21-34 and 50-52, which are not). Nor are the attributes: a packet
whose attribute list does not walk still decodes, and
`parsed_attributes` raises when asked, so an accepted guess can still
read as garbage. Bytes past the Length are padding (RFC 2865 §3) and
stay undecoded, past `packet.consumed`. The walk does not yet end the
buffer at UDP's length (#235), though, so a Length that overstates the
datagram reaches into whatever follows it in the frame, such as an
Ethernet FCS, and reads it as attributes instead of raising. Only 1812
and 1813 are registered: the legacy 1645 and 1646, and Dynamic
Authorization's 3799 (RFC 5176, whose Disconnect and CoA packets share
the format), need `decode_as`.

TFTP on UDP 69 (RFC 1350) rejects more: `TFTP.decode()` requires an
opcode of 1-6, which 6 of the 65,536 two-byte prefixes are, and then the
mandatory fields that opcode carries, whole. Measured the same way, over
three seeds, the walk stopped for 99.98-100% of the 300-byte payloads
sent to 69 and of the 0-600 byte ones unpadded and padded: about 5 of
the 90,000 decoded a `TFTP` layer, a count small enough to vary by a few
between runs. The opcode alone lets through 6 in 65,536, about 8 of
90,000; of those, a DATA, ACK or OACK almost always decodes, but an RRQ
or WRQ needs two zero bytes after its opcode and an ERROR one after its
code, which random bytes lack about two thirds and one third of the
time, so about 6 are expected. What the port cannot do is find the
transfer. Only the request goes to port 69: the server answers from an
ephemeral port of its own, its transfer identifier, and every DATA, ACK,
OACK and ERROR after that runs between two ephemeral ports (RFC 1350
§4), which no port table can name. So a stateless walk decodes a `TFTP`
layer for the RRQ or WRQ alone, and stops at UDP for the rest of the
transfer, as for any datagram between unregistered ports; of the 33
frames in `tests/fixtures/tftp.pcap`, the 6 requests decode one. A
caller who follows the transfer has the server's port from the source
port of its first reply, and names it for the walk,
`decode_as={"udp.port": {tid: TFTP}}`, which covers both directions
since every later datagram has it as one of its two ports; tracking the
transfer is the caller's, as reassembly is for `HTTP` and `BGP`. A
server that answers from port 69 itself, which RFC 1350 does not allow,
has its replies dispatched by the source-port fallback.

NTP on UDP 123 (RFC 5905) rejects less: of the first byte's 256
values, 96 are a time message, a version from 1 to 4 and a mode other
than 6 or 7, the control messages (RFC 9327's mode 6, ntpd's private
mode 7) whose headers `NTP.decode()` does not read; anything shorter
than the 48-byte header is rejected too. Measured the same way, the
walk stopped for 61.2-62.9% of the 300-byte payloads (`random.Random`
seeds 0-2), against the 62.5% the first byte predicts, and for
65.5-66.3% of the 0-600 byte ones, padded or not: padding never makes
a payload 48 bytes long. Past the first byte any 47 bytes are a
header, and the stratum, the Reference ID and the timestamps are not
judged, so a Kiss-o'-Death and a reserved stratum decode.

The first byte is judged before the length, so every control message
raises `InvalidFieldError` with `field` `"mode"`, however long, and a
bad version raises with `field` `"version"`; only a time message's
first byte, or an empty buffer, can end in `TruncatedHeaderError`.
That makes real traffic fail a strict walk: `ntpq` (mode 6, a 12-byte
request and longer responses) and `ntpdc` (mode 7) talk to port 123,
and `decode_frame()` raises on every one of their messages. Walk them
with `lax=True`, which keeps Ethernet, IP and UDP and reports the
rejection as `stopped_by`. A typed way to take a port out of dispatch for one
walk, and decoding mode 6, are planned follow-ups.

HSRP on UDP 1985 (RFC 2281) rejects far more, though less than BGP and
STUN below: its first three bytes must be a Version of 0, one of the
three Op Codes (Hello, Coup, Resign) and one of the six States, which
18 of the 2^24 values of those bytes are, about one in 932,000, and
the payload must then hold the whole 20-byte message. Measured the
same way (`random.Random` seeds 0-2, each 10,000 random 300-byte
payloads and 10,000 of uniformly random length 0-600, the latter
walked both unpadded and padded: 90,000 walks to port 1985 in all),
about 0.1 of those walks are expected to decode an HSRP layer
(90,000 x 18 / 2^24 = 0.097, a little less in fact, since a few of the
random-length payloads are too short to reach 20 bytes), and 2 did:
the same 46-byte payload of seed 2, whose first
bytes, `00 00 04`, are a Hello in Speak, once unpadded and once padded.
The other 89,998 ended with `stopped_by` set. Padding cannot make a message,
since a minimum-size frame leaves 18 bytes after the UDP header. With
the Version forced to 0,
`HSRP.decode()` accepted 31 of 100,000 random 300-byte payloads
(`random.Random(0)`), near the 27 expected. Past those three bytes any
17 are a message: the timers, the Priority, the Group, the Reserved
byte, the Authentication Data and the Virtual IP Address are not
judged.

The guard is also what keeps HSRPv2 (Cisco's TLV-based successor,
sent to 224.0.0.102 on the same port) from being read as HSRPv1: an
HSRPv2 message starts with a TLV type, 1, where HSRPv1 has its
Version, so `HSRP.decode()` rejects every one at `version`, and it
rejects Cisco's Op Code 3 interface-state Advertise, version 0 but
laid out as a TLV, at `opcode`. Each byte is judged before the length,
so either is reported as what it is however short. Neither is decoded,
and as with NTP's control messages a strict walk raises on them: walk
such traffic with `lax=True`. Only 1985 is registered; HSRPv2 over
IPv6 uses port 2029, which nothing here decodes.

BGP on TCP 179 (RFC 4271) has the strongest guard of any port entry:
every message opens with a 16-byte Marker of all ones, which random
bytes match once in 2^128, and then a Length and Type whose bounds
depend on each other (§6.1). Measured the same way, over 10,000 random
300-byte payloads and 10,000 of uniformly random length 0-600, padded
or not, every walk to port 179 ended with `stopped_by` set and none
decoded a BGP layer; with the Marker forced to all ones, the Length and
Type checks alone still rejected 9,998 to 10,000 of 10,000 random
300-byte payloads (`random.Random` seeds 0-4). What the port cannot tell the decoder is where a message
starts: TCP cuts its byte stream where it likes, so a segment can hold
several messages, the tail of one, or the head of the next. Each
message decodes as one `BGP` layer, and `BGP.next_protocol()` answers
`BGP` while another message begins in the same segment. It is handed no
bytes, so `BGP.decode()` records the answer on the instance, in a field
outside its comparison and hash (see *Walking a frame* above). A
segment that ends inside a message raises `TruncatedHeaderError` at
that message (lax mode keeps the ones before it); one that begins
inside a message fails the Marker check, or raises
`TruncatedHeaderError` if it is shorter than a header; a bare ACK, like
one on port 53, sends an empty payload into the decoder. A segment of many small messages is a deep
chain, and here `max_depth` bounds correctness, not just cost: the
default leaves room for 29 messages after Ethernet, IPv4 and TCP, and
valid segments hold more. A 1448-byte one holds 76 KEEPALIVEs or 30
one-prefix UPDATEs, and a capture taken with GRO or TSO on, over
loopback or on a jumbo-frame link sees segments of up to 64 KB, so a
strict walk raises `MaxDepthExceededError` on valid traffic and a lax
one stops with `stopped_by` set and `consumed` short of the frame. A
larger `max_depth` or a second walk,
`decode_frame(frame[packet.consumed:], start=BGP)`, decodes the rest;
the busiest segment of the captured session in the corpus, taken with
offload off, carries 7. Reassembling
the stream is the caller's, as it is for `HTTP` below: see
[`layer7/bgp.py`](src/netprotocols/layer7/bgp.py)'s module docstring.

STUN on UDP and TCP 3478 (RFC 8489, RFC 5389) is guarded nearly as
well, by its fixed header: the two bits above the Message Type must be
zero, the 32-bit Magic Cookie `0x2112A442` must follow the Message
Length, and the Length must be a multiple of 4, so random bytes pass
once in 2^36, before the Length is held against the buffer. Measured
the same way, every walk to port 3478 ended with `stopped_by` set and
none decoded a STUN layer, over UDP for 10,000 random 300-byte payloads
and 10,000 of uniformly random length 0-600, padded or not, and over
TCP for 10,000 random 300-byte segments (`random.Random` seeds 0-2).
With the cookie forced in place, `STUN.decode()` accepted 28 of
100,000 random 300-byte payloads (`random.Random(0)`), near the 27
expected: a quarter have the two top bits clear, and 71 of the 65,536
Lengths are multiples of 4 that fit in the 280 bytes after the header.
The cookie is also what separates STUN from RFC 3489, its first
version, whose 16-byte transaction ID took the cookie's place:
`STUN.decode()` rejects a classic message at `magic_cookie`, which is
what RFC 5389 put the cookie there for. Over TCP, messages follow one
another with no framing but their own Length, as BGP's do, and chain
the same way, so `max_depth` bounds correctness here too: a message
can be a bare 20-byte header, the default leaves room for 29 after
Ethernet, IPv4 and TCP, and a 1448-byte segment holds 72, so a strict
walk of a valid segment can raise `MaxDepthExceededError` and a lax
one stop short. BGP's two ways past it work the same, with
`start=STUN`; the corpus's TCP segments carry 2. See
[`layer7/stun.py`](src/netprotocols/layer7/stun.py)'s module docstring.

TLS on TCP 443 (RFC 9846 §5.1, which obsoletes RFC 8446 as TLS 1.3's
specification, and RFC 5246 §6.2, TLS 1.2's, which RFC 9846 also
obsoletes) has a weaker guard than BGP's or STUN's, but one byte at a
time, as HSRP's is: a ContentType of 20-24 (change_cipher_spec, alert,
handshake, application_data and RFC 6520's heartbeat), a version whose
first byte is 3 and second 0-4 (SSL 3.0 to TLS 1.3 in form), each judged
as soon as it is in the buffer, then a length of at most 2^14 + 2048
(RFC 5246 §6.2.3's ciphertext bound, the loosest any version sets),
judged once both its bytes are, and only then the length against the
buffer. Random bytes pass the first three 25 times in 2^24, about once
in 671,000. Measured the same way (`random.Random` seeds 0-2, each
10,000 random 300-byte TCP payloads to port 443 and 10,000 of uniformly
random length 0-600, the latter walked unpadded and padded: 90,000
walks), every walk ended with `stopped_by` set and none decoded a TLS
layer: about 0.13 of them are expected to pass the first three checks
(90,000 x 25 / 2^24) and about 0.0006 to hold a whole record as well.
With the first three bytes forced to a valid header, `TLS.decode()`
accepted 449 of 100,000 random 300-byte payloads (`random.Random(0)`),
near the 452 expected: a length of 0-295 is 296 of the 65,536 values.
The fragment is not judged, and an SSL 2.0-compatible ClientHello, its
first byte's top bit set, is turned away at the ContentType. Records
follow one another in the stream as BGP's messages do, and chain the
same way, so the rest of BGP's paragraph holds here: a segment that ends
inside a record raises `TruncatedHeaderError` at it, one that begins
inside one almost always fails the guard, a bare ACK raises
`TruncatedHeaderError` at the empty payload
(`tests/fixtures/tcp_https.pcap`'s five IPv6 ACKs do, and
`tests/test_corpus.py` walks them lax), and `max_depth` bounds
correctness. One difference from BGP's port: an IPv4 bare ACK with no
TCP options is a 54-byte frame, and where the capture holds the padding
that brings it to Ethernet's 60 bytes, the walk, which does not yet end
a buffer at IPv4's Total Length (#235), hands TLS those 6 zero bytes,
which it rejects as a ContentType of 0 (`InvalidFieldError`,
`field="content_type"`), where BGP, judging nothing before its 19-byte
header is whole, still raises `TruncatedHeaderError`. As for
`max_depth`, the decoder's worst case is a bare 5-byte header, 289 to a
1448-byte segment; the smallest protected TLS 1.3 record is 5 + 1 + 16
= 22 bytes (an empty Application Data fragment is protected with its
inner content type and, under AES-GCM, ChaCha20-Poly1305 or AES-CCM, a
16-byte tag; RFC 9846 §5.2), or 5 + 1 + 8 = 14 with
TLS_AES_128_CCM_8_SHA256's 8-byte tag, so a
1448-byte segment holds 65 or 103 records and 30 of 22 bytes, 660 bytes,
already exceed the 29 the default leaves; the corpus's busiest segment
carries 6. The case that matters is a ClientHello larger than a segment:
Chromium's, with its X25519MLKEM768 key share, is a 1738-byte record
that TCP carried in two segments in
`tests/fixtures/tls/tls_session.pcap`, so a strict walk raises at both
and a lax one stops at TCP. There is no lenient mode that reads a
partial hello: the SNI of such a client comes from reassembling its
stream and calling `TLS.decode()` on that, as for `HTTP` below.
`TLS.client_hello` and `TLS.server_name` parse the fragment on demand
and never in `decode()`; there is no cryptography, and nothing past the
ClientHello's fields and its server_name extension is decoded (the
ServerHello, certificates, key exchange and every other extension stay
raw, handshake messages fragmented across records or coalesced into one
are not reassembled or split, and DTLS and QUIC, on UDP 443, are not
decoded). Under Encrypted Client Hello the name read is the outer
ClientHello's, the client-facing server's. Only 443 is registered: DNS
over TLS's 853, the mail ports 465, 993 and 995, and 8443 need
`decode_as`. See [`layer7/tls.py`](src/netprotocols/layer7/tls.py)'s
module docstring.

A rejected guess takes the ordinary decode-error path: the chain keeps
the layers it did decode and records the failure. An accepted one
yields a layer that decoded cleanly and is wrong, and nothing in the
`Packet` says so. A caller who needs certainty does not leave it to the
port: `decode_as` or a derived `Registry` names the class for a port
the caller knows, overriding the default for that walk. Third-party
entries in the port tables carry the same risk and no more: a wrong
registration costs what a wrong guess does.

`HTTP` is deliberately absent from the `tcp.port` table. The unit a
datagram protocol decodes is the payload; HTTP's is a message, which
TCP delivers as a byte stream cut wherever it likes. Registering it
(`decode_as={"tcp.port": {80: HTTP}}` works) only decodes the messages
that happen to fit in one segment. Of the 98 frames in
`tests/fixtures/http/http.pcap`, 8 decode; the 70 with no payload
(handshake, ACKs, FINs) and the 8 holding only the start of a message
raise `TruncatedHeaderError`, and the 12 that begin mid-message raise
`InvalidFieldError`. So it needs `lax=True`, and it is still not
reassembly. Reassemble the connection and call `HTTP.decode()` on its
bytes instead. HTTPS is not HTTP on the wire: port 443 dispatches to
`TLS`, and the HTTP inside it is encrypted.

## The encode side, and the round-trip guarantee

Every class also works in reverse. Constructors take the friendly
forms (string addresses, integer fields) and validate some of them in
`__post_init__`: Ethernet, ARP and IPv4 check address formats (IPv6,
DHCP, VRRP and OSPF do not, so a malformed address there fails only
in `bytes()`; for OSPF's `router_id`, `area_id` and its records'
address fields, such as an LSA header's `advertising_router`, that
is the `OSError` from `socket.inet_pton`), and IPv4's IHL and TCP's
data offset must agree with
`len(options)`. For a valid header, `bytes()` re-emits the exact
on-wire form. Constructors do not check everything decode does, so
some headers can be built that decode would never produce (see
below).

The test suite enforces the round trip in both directions for every
protocol:

```python
Protocol.decode(bytes(header)) == header        # object → wire → object
bytes(Protocol.decode(raw)) == raw[:header_len] # wire → object → wire
```

The first holds for canonical headers, the ones decode itself
produces, when decode is given the context it produced them with
(HTTP's `request_method` and `closed`). A constructor accepts more
than that, and for those headers the first line can fail: spellings
are normalised on the way back (a MAC written with dashes decodes with
colons, an IPv6 address decodes compressed); GRE's optional `fields`
must agree with its flag bits; and VXLAN accepts a clear I flag on
purpose, so that a test of another stack can send one, though
`VXLAN.decode()` rejects it as its guard against a wrong port guess
(see *Port-based dispatch is best-effort*). The round-trip property
tests generate canonical headers only: addresses spelled as decode
spells them, GRE fields sized from its flags, VXLAN with the I flag
set, and HTTP messages that either need no context or are decoded with
the context they carry.

One deliberate boundary: **decode and encode carry checksums
verbatim** — exactly what you want when faithfully re-encoding
captured traffic. Computing and verifying them is explicit, via
`netprotocols.checksum`: `compute()`/`verify()` handle the IPv4 header
checksum, ICMPv4, and TCP/UDP/ICMPv6 with their IPv4/IPv6
pseudo-headers, PIM (the pseudo-header over IPv6 only, a Register's
first 8 bytes only), and `Packet.with_checksums(payload)` fills a whole
stack before sending. (The RFC 768 subtlety lives where it belongs:
the `0x0000 → 0xFFFF` substitution applies to UDP alone.) SCTP is the
one transport that does not use the internet checksum: its CRC32c
(`crc32c()`, RFC 9260 Appendix A) covers the whole packet with no
pseudo-header, and goes on the wire least significant byte first, so
`compute()` returns it byte-swapped to match the field as decoded.
STUN's FINGERPRINT is a checksum that lives in an attribute rather
than a header field: the IEEE CRC-32 of the message up to it, XORed
with `0x5354554E` (RFC 8489 §14.7). `compute()` returns it for a
message whose last attribute is one, `verify()` accepts a message with
none, and `with_checksums()` rewrites it. A message has none only when
its attributes walk whole, none of them a FINGERPRINT, and its last 8
bytes do not begin like one, so a corrupted earlier Length cannot hide
it from `verify()`. MESSAGE-INTEGRITY, the keyed
HMAC beside it, needs the credential's key, which this library never
has, so it is carried raw, like an AH ICV.
VRRP's checksum is the internet checksum of the message alone in
VRRPv2 and behind the IP pseudo-header in VRRPv3. RFC 5798 §5.2.8
cites only IPv6's pseudo-header; adding IPv4's too is keepalived's
default, and `compute()`'s. RFC 9568, which obsoletes RFC 5798, leaves
it out over IPv4, and `verify()` returns `False` for an advert
checksummed that way.

Behind an IPv6 Routing header with segments left, RFC 8200 §8.1 puts
the route's *final* destination in the pseudo-header, while `ip.dst`
is the next hop. `compute()`, `verify()` and `flow_key()` take the
Routing header as a keyword-only `routing`, and `Packet.with_checksums()`
and `Packet.flow_key()` pass the last one with segments left between
the nearest IP header and the transport (a receiver skips one with
none left: RFC 8200 §4.4 for unrecognized types, and each type's own
processing rules, RFC 2460 §4.4, RFC 6554 §4.2 and RFC 8754 §4.3, so
the route ends at the last that has some).
`IPv6Routing.final_destination(dst)` resolves it for types 0, 2, 3
(RPL, from `dst`'s prefix) and 4 (SRH, Segment List[0]); for another
type, malformed data, no segments left or IPv4 the address stays
`ip.dst`.

That is also why `SCTP.decode()` bounds its own extent (see "The decode
contract" above): otherwise Ethernet's padding would land inside the
CRC's span, and a packet under 46 bytes from a real NIC would fail to
verify.

OSPF carries two checksums. The packet's is the internet checksum of
the whole packet but its 64-bit Authentication field, with no
pseudo-header, and `compute()` covers only the packet's own bytes, so
an RFC 5613 LLS block after it never enters; under cryptographic
authentication (AuType 2, or 3 from RFC 7474) none is computed (the
digest protects the packet), so `compute()` raises, `verify()` returns
`True` and `with_checksums()` leaves the field alone. Each LSA's LS
Checksum is an ISO 8473 Fletcher checksum of the LSA but its LS Age;
an LSA is not a layer, so it has functions of its own:
`lsa_checksum()` generates the field with `fletcher_checksum()`, and
`verify_lsa()` checks it the way RFC 905 B.4 does, by both running sums
being zero, so a byte stored as `0x00` where the generator writes
`0xff` passes; and, since RFC 2328 §12.1.7 says the field cannot be
zero, it fails a field of `0x0000` even where those sums are zero.

`Packet` is the thin composition layer: it holds an ordered tuple of
headers and `bytes(packet)` joins them, ready for a raw socket.

## Layout map

```
src/netprotocols/
├── __init__.py     public API re-exports, __version__, registry install
├── _base.py        Protocol ABC, decode contract, address helpers
├── _tlv.py         walk_kind_length_value(): shared TCP/IPv4/IPv6
│                   options, PIM Hello options, RADIUS attributes and
│                   STUN attributes TLV walker
├── _enums.py       EtherType, LLCSAP, IPProtocol, ARPOperation,
│                   ARPHardwareType (imports nothing)
├── registry.py     public dispatch tables: register(), Registry
├── walk.py         decode_frame(): the shipped chain walker
├── _defaults.py    the built-in decoder map, installed at import
├── packet.py       Packet composition, with_checksums(), flow_key()
├── checksum.py     RFC 1071 internet_checksum, SCTP's crc32c,
│                   compute, verify (CDP's odd-byte sum and STUN's
│                   FINGERPRINT among them), OSPF's LSA Fletcher
│                   checksum
├── flow.py         FlowKey, flow_key(): canonical bidirectional keys
├── pcap.py         read_captures()/read_pcap()/read_pcapng(): classic
│                   pcap and pcapng readers, from bytes not filenames
├── layer2/         ethernet.py, arp.py, vlan.py (802.1Q / 802.1ad),
│                   llc.py (802.2 LLC + SNAP, after an 802.3 Length),
│                   cdp.py (Cisco Discovery Protocol, after SNAP),
│                   lldp.py (LLDP, IEEE 802.1AB),
│                   mpls.py (MPLS label stack: MPLS + MPLSLabel),
│                   stp.py (802.1D / 802.1w BPDUs)
├── layer3/         ip.py (IPv4 + IPv6), icmp.py (ICMPv4 + ICMPv6),
│                   igmp.py, gre.py, esp.py (IPsec ESP),
│                   ah.py (IPsec AH: AH + AHv6),
│                   ospf.py (OSPFv2: OSPF + its message records),
│                   pim.py (PIM-SM),
│                   vrrp.py (VRRPv2/v3: VRRP + VRRPv6),
│                   ipv6_ext.py (Hop-by-Hop, Routing, Fragment,
│                   Destination Options)
├── layer4/         tcp.py, udp.py, sctp.py, _ports.py (port-table
│                   dispatch)
├── layer7/         dns.py, dhcp.py, http.py (the HTTP/1.1 grammar
│                   and the HTTP codec class), vxlan.py, rip.py
│                   (RIPv1 + RIPv2), bgp.py (BGP-4 messages),
│                   tftp.py (TFTP, with RFC 2347 options),
│                   radius.py (RADIUS + RADIUSAttribute),
│                   stun.py (STUN messages, over UDP and TCP),
│                   ntp.py (NTPv1-v4 time messages),
│                   hsrp.py (HSRPv1 Hello, Coup and Resign),
│                   tls.py (TLS records, the ClientHello and its
│                   SNI: TLS + TLSClientHello + TLSExtension)
└── utils/          validators (mac.py, ipv4.py), exceptions.py
tests/              one file per protocol + test_contract.py
                    (truncation, lying lengths, chain walks),
                    test_corpus.py (invariants over the real-capture
                    corpus in tests/fixtures/ — see its MANIFEST.md for
                    the frame and scenario counts), test_checksum.py
                    (corpus checksums recompute to wire values), and
                    test_fuzz.py (hypothesis properties: decode never
                    raises outside ProtocolError)
```

Tooling: [uv](https://docs.astral.sh/uv/) manages the environment
(`uv sync`); `uv run pytest`, `uv run mypy` (strict), and
`uv run ruff check` are the three gates CI enforces on Python
3.12–3.14.

## Cookbook: adding a protocol

Say you want to add DNS (sitting behind UDP). The pattern is always
the same:

1. **Model the fixed header.** Create `layer7/dns.py` with a frozen,
   slotted dataclass: one field per header field, a `_struct` for the
   fixed portion (`"!HHHHHH"` for DNS: id, flags, and four counts).
2. **Implement `decode()`.** Call `cls._unpack_fixed(data)`, split any
   bitfields explicitly, and construct the instance. If the header is
   variable-length, validate the declared length against `len(data)`
   (raise `TruncatedHeaderError` when the buffer can't satisfy it) and
   materialize the variable part as `bytes`.
3. **Implement `__bytes__()`.** Pack the same fields back; the
   round-trip tests will hold you honest. When a payload is
   self-referential — DNS names compress by pointing at earlier bytes,
   so re-encoding a parsed record cannot reproduce the original — keep
   that region as raw `bytes` and parse it through read-only accessors
   that never re-encode. `bytes(decode(x)) == x` then holds by
   construction (see `layer7/dns.py`).
4. **Wire the chain.** Register the class against the value that
   names it, in the table that carries that value — `register("udp.port",
   53, DNS)`. Nothing in the layer below changes. If you are adding a
   protocol *to this library* rather than to your own program, add the
   wire value to `_enums.py` too (display name in lockstep — a test
   enforces it) and put the registration in `_defaults.py` alongside
   the rest. Numbers valid only inside an IPv6 chain go in
   `ip.proto.v6` rather than `ip.proto`, which is the whole of the
   gating. Reuse the shared helpers rather than re-deriving the same
   pattern in a new module: `hex_str`
   ([`_base.py`](src/netprotocols/_base.py)) for a hex-formatted
   field, the `_ip_protocol_enum`
   ([`layer3/ip.py`](src/netprotocols/layer3/ip.py)) /
   `_ethertype_enum` ([`layer2/ethernet.py`](src/netprotocols/layer2/ethernet.py))
   pattern for an enum-or-`None` accessor, and `walk_kind_length_value`
   ([`_tlv.py`](src/netprotocols/_tlv.py)) for TLV-shaped options.
5. **Add display properties** for anything a human would want rendered
   (`flags_str`-style names, hex strings). Degrade gracefully on
   unknown values — return `"unknown (47)"`, never raise from a
   display helper.
6. **Test with real bytes.** Capture or craft a real header, add it as
   a fixture, and cover: a decode with asserted fields, both round
   trips, truncated input, and (if variable-length) an options case
   and a lying-length case. Export the class from `__init__.py`.

Steps 1–3, 5 and 6 are the same whether the protocol ships here or in
your own package; only step 4 differs, and only in *where* the
registration lives. A protocol carried as a byte stream, as HTTP is
over TCP, skips step 4 altogether (see "Port-based dispatch is
best-effort" above) and replaces step 1's struct with a scan.

If you follow the six steps, your protocol automatically composes with
`Packet`, participates in frame walks, and inherits the library's
error behavior — that's the whole point of the shared contract.
