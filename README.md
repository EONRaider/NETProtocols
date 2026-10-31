# NETProtocols

[![CodeFactor](https://www.codefactor.io/repository/github/eonraider/netprotocols/badge/master)](https://www.codefactor.io/repository/github/eonraider/netprotocols/overview/master)
[![CI](https://github.com/EONRaider/NETProtocols/actions/workflows/ci.yml/badge.svg)](https://github.com/EONRaider/NETProtocols/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/EONRaider/NETProtocols/badge)](https://securityscorecards.dev/viewer/?uri=github.com/EONRaider/NETProtocols)
![Python Version](https://img.shields.io/badge/python-3.12%2B-blue?logo=python)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Typed](https://img.shields.io/badge/typing-strict-informational)

Low-level implementations of common networking protocols, in pure
Python with zero dependencies.

Decode raw header bytes into typed, immutable protocol objects — or
build those objects from field values and serialize them back to their
exact on-wire form. Every header is a frozen dataclass whose fields
mirror the wire format, so decoded traffic is introspectable,
comparable, and round-trippable.

```pycon
>>> from netprotocols import Ethernet
>>> eth = Ethernet.decode(frame)
>>> eth
Ethernet(dst='ff:ff:ff:ff:ff:ff', src='00:07:0d:af:f4:54', ethertype=2054)
>>> eth.ethertype_name
'ARP'
>>> eth.next_protocol()
<class 'netprotocols.layer2.arp.ARP'>
>>> bytes(eth) == frame[:eth.header_len]
True
```

Every header is also a structural pattern — no extra code, because a
frozen dataclass auto-generates `__match_args__` and every enum field
is an `IntEnum`, so a bare wire value matches a named one:

```python
match ip:
    case IPv4(protocol=IPProtocol.TCP, ttl=t) if t > 32:
        ...
    case IPv4(protocol=IPProtocol.UDP):
        ...
```

## Installation

```
pip install netprotocols
```

Requires Python 3.12+. Fully typed (`py.typed`, mypy strict).

## Why NETProtocols

Measured against `dpkt 1.9.8` and `scapy 2.8.0` on the 293 frames of
real captured traffic the corpus held at 2.6.0 (CPython 3.12.3, x86-64
Linux; re-measured for 2.6.0 on 2026-10-28 — see
[docs/CLAIMS.md](docs/CLAIMS.md) for every number below, its
reproduction command, and its caveats):

- **3.4× faster than scapy on decode; dpkt is 1.3× faster** —
  `uv run --group bench python scripts/benchmark.py --compare`. dpkt is
  the faster of the two comparators. The routing captures 2.5.0 added
  (OSPF, BGP, PIM, RIP, VRRP) are where it pulls ahead, taking about
  two thirds of netprotocols' time on them. On the 140 frames the
  corpus held at 2.4.0 the two are no longer within 10% of each other:
  dpkt is ahead there by a median 1.14× across runs. On the MPLS and
  LLC/SNAP captures 2.6.0 added they are level; dpkt leaves LLDP
  undecoded, so it is about 5× faster on those six frames. Narrowing
  the gap is
  [#250](https://github.com/EONRaider/NETProtocols/issues/250). The gap
  moves both ways as this library and dpkt each change, and this file's
  job is to say so honestly rather than only when it's flattering.
- **Decodes further into the stack than dpkt on 94 of those 293
  frames** — BGP, RIP, LLDP, DNS, DHCP and VXLAN-tunnelled payloads
  that dpkt leaves as raw bytes, and 802.1Q tags, MPLS label stacks and
  SNAP headers it folds into the Ethernet and LLC headers, netprotocols
  decodes as layers of their own. A throughput number means little
  without knowing how much work it bought.
- **4.7× faster than dpkt at re-encoding** (`bytes(header)`,
  `scripts/benchmark_encode.py`) — the other half of "codec" that
  nobody else benchmarks.
- **Imports in 90 ms; `scapy.all` takes 436+ ms** (`scripts/benchmark_import.py`),
  and never touches the host doing it — importing scapy populates live
  interface and routing tables as a side effect of the import
  statement.
- **A 220.5 KiB wheel against scapy's 2.63 MiB** — 12.2× smaller.
- **Regression-gated in CI, which — as far as we could establish by
  auditing ten comparable Python packet libraries' CI configurations
  (dpkt, scapy, pypacker, construct, pcapkit, dnspython, pyshark,
  nfstream, stackforge, PyTCP-net_proto; full citations in
  [docs/CLAIMS.md §1.7](docs/CLAIMS.md#17-decode-throughput-is-regression-gated-in-ci)) — none of them gate on one.**
  Three of the ten (scapy, construct, stackforge) ship benchmark code
  that targets the library being compared but never runs in CI
  (construct disables it explicitly; stackforge's Criterion benches are
  never invoked). A fourth, PyTCP-net_proto, ships a benchmark too, but
  it exercises its RX daemon rather than the compared `net_proto`
  package, and isn't wired to CI either. None of the ten fails a build
  on a performance regression.
- **Typed where the alternatives are not.** `mypy --strict` over the
  whole of `src/`, enforced in CI. scapy ships `py.typed` but enables
  strict checking on 89 of its files, 2 of the 121 under
  `scapy/layers/` — the dissectors most code touches stay `Any`. dpkt
  ships no `py.typed` at all, and no third-party stub package exists
  for it.
- **The only MIT-licensed, strictly-typed, zero-dependency packet codec
  still under active maintenance.** scapy is GPL-2.0; pypacker is
  GPLv2; the newer entrants `stackforge` and `PyTCP-net_proto` are both
  GPL-3.0. The other permissive option, dpkt (BSD), last released
  2022-08-18 and last committed 2024-05-05, still targets Python 2.7
  and 3.5–3.9, and remains marked Beta after twelve years.
- **Runs where scapy cannot — including in the browser.** Under a real
  Pyodide runtime in CI, netprotocols imports and decodes the full
  corpus cleanly. Scapy cannot even be attempted there: it is absent
  from Pyodide's package set, and `from fcntl import ioctl` is
  unconditional in `scapy/arch/` — confirmed by that same CI run still
  missing the module, plus the source citation. dpkt and pypacker were
  both confirmed to import cleanly under the same missing modules, but
  via a separate CPython-side simulation, not inside the CI job.
- **The only one of these libraries a `match`/`case` statement
  dissects out of the box.** dpkt builds `__slots__` from a metaclass
  and generates no `__match_args__`; scapy routes fields through
  `__getattr__`; construct returns dicts. None gives you a pattern to
  match against.

None of this makes scapy less than an extraordinary piece of software —
it crafts, sends, sniffs and fuzzes across thousands of protocols, and
this library does none of that. The comparison above is scoped to what
both are: a codec that turns bytes into typed objects and back.

One `mypy --strict` run says more than the bullets above:

```
# scapy 2.8.0 — a field name that does not exist
p.ThisFieldDoesNotExist   → Any     (no error)

# dpkt 1.9.8 — the whole module
import dpkt.ethernet      → error: missing library stubs or py.typed

# netprotocols — a typo in a real field name
ip.proto                  → error: "IPv4" has no attribute
                              "proto"; maybe "protocol"?
```

## Protocol coverage

| Layer | Protocol | Class | Notes |
|---|---|---|---|
| 2 | Ethernet II / IEEE 802.3 | `Ethernet` | IEEE 802.3; the type/length field dispatches as an EtherType from 0x0600 and as an 802.3 Length (then LLC) up to 1500, which also bounds the walk's later layers |
| 2 | IEEE 802.1Q VLAN tag (802.1ad QinQ) | `VLAN` | 802.1Q-2018 §9.6, PCP/DEI/VID, tag stacking; the inner type/length field reads as Ethernet's does |
| 2 | IEEE 802.2 LLC | `LLC` | ISO/IEC 8802-2, DSAP/SSAP and a 1- or 2-octet Control; I-format and UI PDUs dispatch on DSAP (`llc.dsap`); Novell raw 802.3 recognized (`is_raw_ipx`; the other fields are then IPX bytes), never dispatched |
| 2 | SNAP | `SNAP` | IEEE Std 802, RFC 1042; OUI and PID: OUI 00-00-00 and 00-00-F8 dispatch the PID as an EtherType, any other OUI through `llc.snap` |
| 2 | LLDP | `LLDP`, `LLDPTLV`, `LLDPChassisID`, `LLDPPortID` | IEEE 802.1AB, EtherType 0x88CC; every TLV through End of LLDPDU, the End TLV's bound leaving padding and an FCS undecoded; Chassis ID and Port ID (subtype and ID) and Time To Live typed, every other TLV raw with its type named |
| 2 | Spanning Tree BPDU (STP, RSTP) | `STP` | IEEE 802.1D-2004 §9.3, 802.1w; LLC DSAP 0x42 (`llc.dsap`); Configuration (35 octets), RST (36) and Topology Change Notification (4) BPDUs in one class, branching on the BPDU Type; per-type flag accessors (TC, TCA, Proposal, Port Role, Learning, Forwarding, Agreement), the 802.1t priority / system ID extension split, timers raw and in seconds; MST BPDUs decoded only as far as their RST prefix |
| 2 | CDP | `CDP` | Cisco Discovery Protocol, versions 1 and 2, after SNAP OUI 00-00-0C PID 0x2000 (`llc.snap`); the 4-byte header and the TLVs, kept raw and named from Wireshark's packet-cdp.c, with accessors for Device ID, Addresses, Port ID, Capabilities, Software version, Platform and Management Address; its checksum (RFC 1071 but for an odd final byte) in `compute`/`verify` |
| 2 | ARP | `ARP` | RFC 826, IPv4-over-Ethernet binding |
| 2 | MPLS label stack | `MPLS` | RFC 3032 §2.1, EtherTypes 0x8847 and 0x8848 (and GRE's Protocol Type, RFC 4023); the whole stack as one layer of `MPLSLabel` entries (label, traffic class, S, TTL); no field names the payload, so it dispatches by convention to IPv4 or IPv6 — the bottom label when it is an Explicit NULL, otherwise the first nibble after the stack — and stops at a pseudowire control word |
| 3 | IPv4 | `IPv4` | RFC 791, IHL/options aware |
| 3 | IPv6 | `IPv6` | RFC 8200 |
| 3 | IPv6 Hop-by-Hop Options | `IPv6HopByHopOptions` | RFC 8200 §4.3 |
| 3 | IPv6 Routing | `IPv6Routing` | RFC 8200 §4.4 |
| 3 | IPv6 Fragment | `IPv6Fragment` | RFC 8200 §4.5, first-fragment chaining |
| 3 | IPv6 Destination Options | `IPv6DestinationOptions` | RFC 8200 §4.6 |
| 3 | ICMPv4 | `ICMPv4` | RFC 792, 8-byte header |
| 3 | ICMPv6 | `ICMPv6` | RFC 4443, 8-byte header |
| 3 | IGMP | `IGMP` | RFC 1112/2236/3376, IPv4 multicast management; IGMPv3 report group records + query fields |
| 3 | GRE | `GRE` | RFC 2784/2890, IP protocol 47; payload chains onward by EtherType |
| 3 | IP-in-IP | `IPv4`, `IPv6` | RFC 2003/4213/2473, IP protocols 4 and 41; no header of its own, so the outer IP header dispatches straight to the inner one |
| 3 | IPsec ESP | `ESP` | RFC 4303, IP protocol 50; SPI and sequence number decoded, the protected remainder kept as opaque `ciphertext` — the chain ends here by design, since without the Security Association nothing says where the Next Header is |
| 3 | IPsec AH | `AH`, `AHv6` | RFC 4302, IP protocol 51; fixed fields decoded and the ICV kept raw (never verified), then the payload chains onward by `next_header` through the outer IP family's table — `AHv6`, an `AH` subclass, is what IPv6 dispatches to |
| 3 | OSPFv2 | `OSPF` | RFC 2328, IP protocol 89 over IPv4; the 24-byte header, then Hello, Database Description, LS Request, LS Update and LS Acknowledgment parsed by typed accessors; LSA headers decoded, LSA bodies kept raw; packet checksum and LSA Fletcher checksum compute/verify. OSPFv3 (RFC 5340, IPv6) is not decoded: IPv6 protocol 89 ends the walk |
| 3 | PIM-SM | `PIM` | RFC 7761, IP protocol 103 from IPv4 and IPv6; common header + message-type dispatch: Hello options, Register (encapsulated packet decodable), Register-Stop, Join/Prune (also Graft/Graft-Ack), Assert parsed on demand; other types kept raw; checksum compute/verify, IPv6 pseudo-header included |
| 3 | VRRP | `VRRP`, `VRRPv6` | RFC 3768 (VRRPv2) and RFC 5798 (VRRPv3), IP protocol 112; one class branches on the version nibble (VRRPv2's Auth Type, Adver Int and authentication data; VRRPv3's Max Adver Int) and decodes the virtual-address list at the width of the IP family that carried it — `VRRPv6`, a `VRRP` subclass, is what IPv6 dispatches to; checksum compute/verify |
| 4 | TCP | `TCP` | RFC 9293, data-offset/options aware |
| 4 | UDP | `UDP` | RFC 768 |
| 4 | SCTP | `SCTP` | RFC 9260, IP protocol 132; common header + chunk list (`SCTPChunk`) parsed on demand; CRC32c compute/verify |
| 7 | DNS | `DNS` | RFC 1035, over UDP and TCP (`DNSOverTCP` length shim); on-demand name decompression + resource-record parsing |
| 7 | DHCP | `DHCP` | RFC 2131/2132, over UDP 67/68; TLV options parsed on demand |
| 7 | VXLAN | `VXLAN` | RFC 7348, over UDP 4789; the payload is a whole Ethernet frame, which walks on through the EtherType table |
| 7 | RIP | `RIP` | RFC 1058/2453, RIPv1 and RIPv2 over UDP 520; route entries (`RIPEntry`) and the authentication entry (`RIPAuthentication`: plain-text password, RFC 4822 keyed MD5/HMAC-SHA) parsed on demand; RIPng is not decoded |
| 7 | TFTP | `TFTP` | RFC 1350, over UDP 69; RRQ, WRQ, DATA, ACK, ERROR and the RFC 2347 OACK, fields read on demand (filename, mode, block, data, error code and message), options as name/value pairs with `blksize`, `timeout`, `tsize` (RFC 2348/2349) and `windowsize` (RFC 7440) as numbers; port 69 reaches the request only, since the transfer runs between two ephemeral ports (RFC 1350 §4) — the rest needs `decode_as` with the server's port |
| 7 | BGP-4 | `BGP` | RFC 4271, over TCP 179; one layer per message, chaining to the next in the same segment; OPEN fields and optional parameters, UPDATE withdrawn routes, path attributes (`BGPPathAttribute`, ORIGIN/NEXT_HOP/MED/LOCAL_PREF values decoded) and NLRI (`BGPPrefix`), NOTIFICATION codes; KEEPALIVE and ROUTE-REFRESH; no reassembly |
| 7 | HTTP/1.1 | `HTTP` | RFC 9112/9110; one message per decode from a buffer you reassembled; ambiguities reported as anomalies; not port-dispatched |

## Decoding a captured frame

`decode_frame()` walks the whole chain and hands back a `Packet`:

```python
from netprotocols import TCP, decode_frame

packet = decode_frame(frame)
print(packet)                 # Packet(Ethernet(...), IPv4(...), TCP(...))
print(packet[1].src)          # '192.168.1.96' — position, unchanged
print(packet[TCP].flags_str)  # first TCP layer, or KeyError if none
print(packet.get(TCP))        # same lookup, None instead of raising
print(packet.consumed)        # bytes the headers occupied
```

It works because every header answers two questions: `header_len` (how
many bytes it consumed) and `next_protocol()` (which class decodes what
follows). Trailing bytes are fine — `frame[packet.consumed:]` is
whatever the chain did not decode.

Start somewhere other than Ethernet when the buffer does — a tunnel
payload, a packet quoted inside an ICMP error, a non-Ethernet link
type:

```python
decode_frame(buf, start=IPv4)
```

Malformed input raises exceptions rooted at a single base class:

```python
from netprotocols import ProtocolError, TruncatedHeaderError, InvalidFieldError

try:
    packet = decode_frame(frame)
except TruncatedHeaderError:   # buffer shorter than the header claims
    ...
except InvalidFieldError:      # nonsense field values (IHL < 5, bad address)
    ...
except ProtocolError:          # catches every library error
    ...
```

Every exception carries structured context alongside its message —
`err.protocol` names the class that raised, `err.field` names the
attribute at fault where one field is at fault, and `err.offset` /
`err.frame_offset` locate the problem in bytes (in the header's own
buffer, and rebased to the whole frame when the error came through
`decode_frame`) — so a fuzzer, conformance suite, or validation tool
can act on *where* and *what* failed without parsing the message:

```python
try:
    packet = decode_frame(frame)
except ProtocolError as e:
    print(f"{e.protocol.__name__} at byte {e.frame_offset}: {e}")
    # IPv4 at byte 14: IPv4 IHL must be at least 5, got 0
```

A capture tool would usually rather keep the layers it got than lose
frame 4,000,001 to an exception. `lax=True` reports instead of raising:

```python
packet = decode_frame(frame, lax=True)
if packet.stopped_by is not None:
    log.warning("stopped after %d layers: %s", len(packet), packet.stopped_by)
```

Lax mode never invents a layer and never guesses — each header is
decoded exactly as strictly as before; the walk just declines to throw
away the part that worked. Chain depth is bounded (`max_depth`,
default 32), so a crafted frame cannot make the walker grind.

One case where reaching for `lax=True` is the *right* default, not
just a convenience: an ICMP error message's embedded packet. RFC 792
only guarantees the invoking IP header plus 8 bytes of what follows —
never a full TCP/UDP header — so decoding it with the strict path
raises on ordinary, correctly formed traffic. `ICMPv4`/`ICMPv6` expose
this pre-wired as `embedded_chain`:

```python
icmp.embedded_chain  # decode_frame(icmp.embedded_packet, lax=True, start=IPv4)
                      # → Packet([IPv4(...)]), stopped_by=TruncatedHeaderError(...)
```

`embedded_packet` stays available for the raw bytes; reach for
`embedded_chain` when you want them already decoded and are prepared
to read `stopped_by`. Outside this one RFC-mandated case, a *complete*
frame that fails to decode is still a bug to raise on — `lax=True`
elsewhere is a capture tool's choice, not a default.

## Reading captures

`read_captures()` takes the bytes of a capture file — not a path — and
auto-detects classic pcap vs. pcapng from its magic number:

```python
from netprotocols import decode_frame, read_captures

data = open("traffic.pcap", "rb").read()  # or however you got the bytes
for timestamp, frame in read_captures(data):
    packet = decode_frame(frame, lax=True)
    ...
```

Each `CapturedFrame` is `(timestamp, data)` — `timestamp` normalized to
nanoseconds since the Unix epoch regardless of the source format's own
resolution (classic pcap's microseconds or nanoseconds; pcapng's
per-interface `if_tsresol`). `read_pcap()`/`read_pcapng()` are the same
thing for a caller who already knows the format and wants to skip
detection. A malformed or truncated capture raises
`MalformedCaptureError`, the same `ProtocolError` family every other
exception in this library belongs to.

## Flow keys

`Packet.flow_key()` (or the free function, `netprotocols.flow_key()`,
for a header pair that never went through `decode_frame`) returns a
canonical, direction-independent key for a TCP, UDP or SCTP
conversation — both directions of one flow produce the same key:

```python
request = decode_frame(client_to_server_frame)
reply = decode_frame(server_to_client_frame)
assert request.flow_key() == reply.flow_key()
```

It returns `None`, not an error, when there is nothing to key on: no
enclosing IP layer, no TCP/UDP/SCTP layer, or a transport layer without
ports at all (ICMPv4/ICMPv6 — this library does not invent a port-slot
convention for message types that have none).

## Decoding HTTP

`HTTP.decode()` reads one HTTP/1.1 message (RFC 9112) from the start of
a buffer and leaves whatever follows it alone; `header_len` says where
the message ended. The buffer has to be the connection's bytes, which
you reassemble: a TCP segment is rarely a whole message, so `HTTP` is
not in the port tables and `decode_frame` stops at TCP. Reading the
messages pipelined on one side of a connection is a loop:

```python
from netprotocols import HTTP, HTTPDisposition


def messages(stream, request_methods=()):
    """Each message on one side of a connection, in order. For the
    server's side, pass the methods of the requests it answered."""
    methods = iter(request_methods)
    while stream:
        msg = HTTP.decode(stream, request_method=next(methods, None))
        yield msg
        stream = stream[msg.header_len :]
        if msg.connection_disposition is not HTTPDisposition.CONTINUE:
            break  # closed, or no longer HTTP (an upgrade or a tunnel)
```

`TruncatedHeaderError` means the message is not all there yet; once the
connection has closed, pass `closed=True`, which a response delimited by
the close needs and which turns a short message into `InvalidFieldError`.
A response's framing can depend on the request it answers, which the
bytes do not say: a response to `HEAD`, or a 2xx to `CONNECT`, has no
body whatever its `Content-Length` claims, so pass `request_method`.

```pycon
>>> msg = HTTP.decode(response, request_method="HEAD")
>>> msg.status_code, msg.framing, msg.header("content-length"), msg.raw_body
(200, <HTTPFraming.NONE: 'none'>, '42', b'')
```

The message is held verbatim (`bytes(msg) == msg.head + msg.raw_body`),
and anything implementations read differently is decoded the way RFC
9112 resolves it and reported, not rejected, so a smuggling attempt
shows up instead of hiding behind an exception:

```pycon
>>> msg = HTTP.decode(
...     b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n"
...     b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
... )
>>> msg.framing, msg.connection_disposition
(<HTTPFraming.CHUNKED: 'chunked'>, <HTTPDisposition.CLOSE: 'close'>)
>>> [(a.kind.name, a.field, a.offset) for a in msg.anomalies]
[('CL_AND_TE', 'content-length', 26)]
```

## Structural pattern matching

Every decoded header works with `match`/`case` today, with no code
written for it: a frozen dataclass auto-generates `__match_args__`,
and every enum field is an `IntEnum`, so a class pattern can match a
named value against the plain `int` the wire actually carries. See
[ARCHITECTURE.md](ARCHITECTURE.md#structural-pattern-matching) for why
both of those hold and how to keep them holding.

`IPv4`, `TCP` and `DHCP` are wide enough (11-15 fields) that their
full auto-generated positional form is unusable, so those three
additionally curate a short `__match_args__` by hand — the fields
someone matching by position actually reaches for:

```python
match ip:
    case IPv4(src, dst, IPProtocol.TCP):
        print(f"TCP: {src} -> {dst}")
```

Keyword patterns (`case IPv4(protocol=IPProtocol.TCP)`) work on every
field regardless, curated or not, and stay the documented default.
`HTTP`'s fields are raw bytes, so its `__match_args__` names properties
instead: `case HTTP("GET", target)` for a request, `case HTTP(None,
None, 404)` for a response.

```python
from netprotocols import IPv4, IPProtocol, TCP

match packet.layers:
    case [_, IPv4(protocol=IPProtocol.TCP) as ip, TCP(flags_str=f), *_] \
            if "SYN" in f and "ACK" not in f:
        print(f"connection attempt from {ip.src}")
    case [_, IPv4() as ip, TCP(), *_]:
        print(f"TCP from {ip.src}")
    case _:
        print("not a TCP-over-IPv4 frame")
```

## Decoding a protocol we do not ship

The dispatch tables are public, so a protocol this library does not
implement can join the walk without forking it:

```python
from netprotocols import Protocol
from netprotocols.registry import register

@register("ethertype", 0x88B5)  # IEEE 802 Local Experimental
class Telemetry(Protocol):
    ...
```

The seven tables are `ethertype`, `llc.dsap`, `llc.snap`, `ip.proto`,
`ip.proto.v6`, `udp.port` and `tcp.port`, each named after the wire
field it dispatches on. To
change decoding for one call only — DNS on a nonstandard port in one
capture — say so per call instead of registering globally:

```python
decode_frame(frame, decode_as={"udp.port": {6969: DNS}})
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for how the tables fit together
and how `ip.proto.v6` inherits `ip.proto`.

## Building and serializing headers

Constructors take friendly values (string MAC/IP addresses, integer
fields) and validate them; `bytes()` emits the exact on-wire form.
`Packet` concatenates a stack of layers:

```python
from netprotocols import ARP, Ethernet, Packet, random_mac

sha = random_mac()
frame = Packet(
    Ethernet(dst="ff:ff:ff:ff:ff:ff", src=sha, ethertype=0x0806),
    ARP(htype=1, ptype=0x0800, hlen=6, plen=4, oper=1,
        sha=sha, spa="192.168.1.96",
        tha="00:00:00:00:00:00", tpa="192.168.1.254"),
)
raw = bytes(frame)  # ready for a raw socket
```

Checksums are computed and verified on request — never silently:
`compute()`/`verify()` in `netprotocols.checksum` (the internet
checksum, VRRP's with or without its pseudo-header by version, PIM's,
CDP's with its odd final byte summed as Cisco does, and SCTP's CRC32c
via `crc32c()`; OSPF's LSA checksums via
`lsa_checksum()`/`verify_lsa()`), and
`Packet.with_checksums()` to fill a whole stack before sending.

## Display helpers

Every class exposes human-readable properties next to the raw fields:
`Ethernet.ethertype_name`, `IPv4.protocol_name`, `IPv4.flags_name`,
`TCP.flags_str` (`"SYN ACK"`), `ARP.oper_name`, `ICMPv4.type_name`,
and hexadecimal renderings such as `checksum_hex_str`. Unknown values
degrade gracefully (`"0x88b5"`, `"unknown (47)"`) instead of raising.

## How it works

See [ARCHITECTURE.md](ARCHITECTURE.md) for a guided tour: how a header
byte layout maps onto a dataclass, the decode contract, the
`next_protocol()` chain, and a cookbook for adding a new protocol.

This library is the engine behind
[RootWire](https://github.com/EONRaider/RootWire), a network traffic
monitor built on it (formerly Packet-Sniffer).

## Roadmap

The current roadmap,
[#170](https://github.com/EONRaider/NETProtocols/issues/170), closes the
protocol gap against dpkt, scapy and pypacker in five tiers: transport
and tunneling, routing, L2 discovery, AAA and infrastructure services,
and TLS record framing with SNI. That issue tracks each tier's
protocols and target version, so they are not restated here. The
HTTP/1.1 codec
([#214](https://github.com/EONRaider/NETProtocols/pull/214),
[#223](https://github.com/EONRaider/NETProtocols/pull/223),
[#226](https://github.com/EONRaider/NETProtocols/pull/226)) shipped as
2.3.0 outside those tiers, and the first tier — IP-in-IP, VXLAN, ESP, AH
and SCTP
([#230](https://github.com/EONRaider/NETProtocols/pull/230),
[#231](https://github.com/EONRaider/NETProtocols/pull/231),
[#232](https://github.com/EONRaider/NETProtocols/pull/232),
[#233](https://github.com/EONRaider/NETProtocols/pull/233),
[#234](https://github.com/EONRaider/NETProtocols/pull/234)) — as 2.4.0,
and the second — VRRP, RIP, OSPF, PIM and BGP
([#243](https://github.com/EONRaider/NETProtocols/pull/243),
[#245](https://github.com/EONRaider/NETProtocols/pull/245),
[#246](https://github.com/EONRaider/NETProtocols/pull/246),
[#247](https://github.com/EONRaider/NETProtocols/pull/247),
[#248](https://github.com/EONRaider/NETProtocols/pull/248)) — as 2.5.0,
and the third — MPLS, LLDP, LLC/SNAP, STP and CDP
([#252](https://github.com/EONRaider/NETProtocols/pull/252),
[#253](https://github.com/EONRaider/NETProtocols/pull/253),
[#254](https://github.com/EONRaider/NETProtocols/pull/254),
[#255](https://github.com/EONRaider/NETProtocols/pull/255),
[#256](https://github.com/EONRaider/NETProtocols/pull/256)) — as 2.6.0
(see [CHANGELOG.md](CHANGELOG.md)).

The roadmap before it, the post-1.3.0
[#107](https://github.com/EONRaider/NETProtocols/issues/107), is
complete — five tiers plus a competitor CI audit
([#124](https://github.com/EONRaider/NETProtocols/issues/124)) and the
comparative-claims embargo lift that closed it out:

| Version | Theme |
|---|---|
| [1.3.1](https://github.com/EONRaider/NETProtocols/issues/102) | Hygiene |
| [1.4.0](https://github.com/EONRaider/NETProtocols/issues/103) | Decode performance |
| [2.0.0](https://github.com/EONRaider/NETProtocols/issues/104) | A public protocol registry, a shipped chain walker, flow keys — **released** |
| [2.1.0](https://github.com/EONRaider/NETProtocols/issues/105) | Typed accessors and pattern-matching ergonomics |
| [2.2.0](https://github.com/EONRaider/NETProtocols/issues/106) | Universal round-trip properties, nightly fuzzing, a pcap reader — **released** |

Everything through 2.2.0 has landed on `master`. The since-landed
decode-throughput fix
([#147](https://github.com/EONRaider/NETProtocols/issues/147)) and a
CodeFactor tooling cleanup
([#156](https://github.com/EONRaider/NETProtocols/issues/156)) are now
released as
[2.2.1](https://github.com/EONRaider/NETProtocols/releases/tag/v2.2.1).
2.1.0's and 1.3.1/1.4.0's work shipped folded into 2.0.0 and 2.2.0
rather than as their own versions, but the roadmap's original "only at
a major version bump" release policy wasn't actually held to: 2.0.0,
2.2.0, 2.2.1, 2.3.0, 2.4.0, 2.5.0 and now 2.6.0 are all on PyPI, and the comparative claims above
draw on the finished tree. The wave before that one — TCP
and IPv4 option parsing, ICMP message bodies, NDP, IPv6
extension-header TLV options, the GRE checksum arm, a DNS-over-TCP
corpus fixture and `ipaddress` accessors — shipped in 1.3.0; see
[CHANGELOG.md](CHANGELOG.md).

## Contributing

Development uses [uv](https://docs.astral.sh/uv/): `uv sync`, then
`uv run pytest`, `uv run mypy`, and `uv run ruff check` — all three are
enforced by CI; the test suite runs across Python 3.12–3.14, while
`mypy` and `ruff check` run on 3.12. The test suite is anchored by a
326-frame corpus of real captured traffic across 31 scenarios
([tests/fixtures/MANIFEST.md](tests/fixtures/MANIFEST.md), which says
which layers a script built rather than the kernel) plus
property-based fuzzing of the decode path. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow and
[ARCHITECTURE.md](ARCHITECTURE.md) for the design and the
add-a-protocol cookbook.

## License

[MIT](LICENSE)
