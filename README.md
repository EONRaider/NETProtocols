# NETProtocols

[![CI](https://github.com/EONRaider/NETProtocols/actions/workflows/ci.yml/badge.svg)](https://github.com/EONRaider/NETProtocols/actions/workflows/ci.yml)
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

## Protocol coverage

| Layer | Protocol | Class | Notes |
|---|---|---|---|
| 2 | Ethernet II | `Ethernet` | IEEE 802.3 |
| 2 | IEEE 802.1Q VLAN tag (802.1ad QinQ) | `VLAN` | 802.1Q-2018 §9.6, PCP/DEI/VID, tag stacking |
| 2 | ARP | `ARP` | RFC 826, IPv4-over-Ethernet binding |
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
| 4 | TCP | `TCP` | RFC 9293, data-offset/options aware |
| 4 | UDP | `UDP` | RFC 768 |
| 7 | DNS | `DNS` | RFC 1035, over UDP and TCP (`DNSOverTCP` length shim); on-demand name decompression + resource-record parsing |
| 7 | DHCP | `DHCP` | RFC 2131/2132, over UDP 67/68; TLV options parsed on demand |

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

## Flow keys

`Packet.flow_key()` (or the free function, `netprotocols.flow_key()`,
for a header pair that never went through `decode_frame`) returns a
canonical, direction-independent key for a TCP/UDP conversation — both
directions of one flow produce the same key:

```python
request = decode_frame(client_to_server_frame)
reply = decode_frame(server_to_client_frame)
assert request.flow_key() == reply.flow_key()
```

It returns `None`, not an error, when there is nothing to key on: no
enclosing IP layer, no TCP/UDP layer, or a transport layer without
ports at all (ICMPv4/ICMPv6 — this library does not invent a port-slot
convention for message types that have none).

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

@register("ethertype", 0x8847)
class MPLS(Protocol):
    ...
```

The five tables are `ethertype`, `ip.proto`, `ip.proto.v6`, `udp.port`
and `tcp.port`, each named after the wire field it dispatches on. To
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
`compute()`/`verify()` in `netprotocols.checksum`, and
`Packet.with_checksums()` to fill a whole stack before sending.

## Display helpers

Every class exposes human-readable properties next to the raw fields:
`Ethernet.ethertype_name`, `IPv4.protocol_name`, `IPv4.flags_name`,
`TCP.flags_str` (`"SYN ACK"`), `ARP.oper_name`, `ICMPv4.type_name`,
and hexadecimal renderings such as `checksum_hex_str`. Unknown values
degrade gracefully (`"0x88cc"`, `"unknown (47)"`) instead of raising.

## How it works

See [ARCHITECTURE.md](ARCHITECTURE.md) for a guided tour: how a header
byte layout maps onto a dataclass, the decode contract, the
`next_protocol()` chain, and a cookbook for adding a new protocol.

This library is the engine behind
[RootWire](https://github.com/EONRaider/RootWire), a network traffic
monitor built on it (formerly Packet-Sniffer).

## Roadmap

Planned work lives in the issue tracker rather than being restated
here, so this section cannot drift out of date the way a copied list
does. The current plan is
[#107](https://github.com/EONRaider/NETProtocols/issues/107) — five
tiers, each mapped to a release:

| Version | Theme |
|---|---|
| [1.3.1](https://github.com/EONRaider/NETProtocols/issues/102) | Hygiene |
| [1.4.0](https://github.com/EONRaider/NETProtocols/issues/103) | Decode performance |
| [2.0.0](https://github.com/EONRaider/NETProtocols/issues/104) | A public protocol registry, a shipped chain walker, flow keys |
| [2.1.0](https://github.com/EONRaider/NETProtocols/issues/105) | Typed accessors and pattern-matching ergonomics |
| [2.2.0](https://github.com/EONRaider/NETProtocols/issues/106) | Universal round-trip properties, nightly fuzzing, a pcap reader |

The previous wave — TCP and IPv4 option parsing, ICMP message bodies,
NDP, IPv6 extension-header TLV options, the GRE checksum arm, a
DNS-over-TCP corpus fixture and `ipaddress` accessors — shipped in
1.3.0; see [CHANGELOG.md](CHANGELOG.md).

## Contributing

Development uses [uv](https://docs.astral.sh/uv/): `uv sync`, then
`uv run pytest`, `uv run mypy`, and `uv run ruff check` — all three are
enforced by CI on Python 3.12–3.14. The test suite is anchored by a
97-frame corpus of real captured traffic across 17 scenarios
([tests/fixtures/MANIFEST.md](tests/fixtures/MANIFEST.md)) plus
property-based fuzzing of the decode path. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow and
[ARCHITECTURE.md](ARCHITECTURE.md) for the design and the
add-a-protocol cookbook.

## License

[MIT](LICENSE)
