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
| 3 | IGMP | `IGMP` | RFC 1112/2236/3376, IPv4 multicast management |
| 4 | TCP | `TCP` | RFC 9293, data-offset/options aware |
| 4 | UDP | `UDP` | RFC 768 |
| 7 | DNS | `DNS` | RFC 1035, over UDP; header + on-demand name decompression |

## Decoding a captured frame

Each class decodes its own header from the start of a buffer and
tolerates trailing bytes, so you can walk a whole frame with two pieces
of information every header provides: `header_len` (how many bytes it
consumed) and `next_protocol()` (which class decodes what follows).

```python
from netprotocols import Ethernet

def decode_frame(frame: bytes) -> list:
    layers, cursor, protocol = [], 0, Ethernet
    while protocol is not None:
        header = protocol.decode(frame[cursor:])
        layers.append(header)
        cursor += header.header_len
        protocol = header.next_protocol()
    return layers  # e.g. [Ethernet(...), IPv4(...), TCP(...)]
```

Malformed input raises exceptions rooted at a single base class:

```python
from netprotocols import ProtocolError, TruncatedHeaderError, InvalidFieldError

try:
    layers = decode_frame(frame)
except TruncatedHeaderError:   # buffer shorter than the header claims
    ...
except InvalidFieldError:      # nonsense field values (IHL < 5, bad address)
    ...
except ProtocolError:          # catches every library error
    ...
```

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

- More protocols: DHCP, GRE (802.1Q VLAN tags, DNS, and IGMP have shipped).
- Full DNS resource-record parsing (the header and question are decoded today; answer/authority/additional sections are kept raw).
- IGMPv3 group-record parsing (the common header is decoded today; v3 report records are kept raw in the body).
- Optional richer address accessors (`ipaddress` / EUI objects
  alongside the `str` fields).
- TLV parsing inside IPv6 extension-header options.

## Contributing

Development uses [uv](https://docs.astral.sh/uv/): `uv sync`, then
`uv run pytest`, `uv run mypy`, and `uv run ruff check` — all three are
enforced by CI on Python 3.12–3.14. The test suite is anchored by a
77-frame corpus of real captured traffic
([tests/fixtures/MANIFEST.md](tests/fixtures/MANIFEST.md)) plus
property-based fuzzing of the decode path. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow and
[ARCHITECTURE.md](ARCHITECTURE.md) for the design and the
add-a-protocol cookbook.

## License

[MIT](LICENSE)
