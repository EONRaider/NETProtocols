#!/usr/bin/env python3
"""Reassemble the HTTP byte streams of a captured pcap, one per side.

    python3 scripts/extract_http_streams.py CAPTURE.pcap OUT_DIR

For each TCP connection to ``--port`` (80 by default), in the order the
connections opened, this writes ``NN.request`` (every byte the client
sent) and ``NN.response`` (every byte the server sent) to ``OUT_DIR``.
Those files are what the HTTP tests and the Atheris harness read, so
neither has to reassemble TCP itself. :func:`extract` takes any port:
``tests/test_tls.py`` and ``scripts/capture_fixtures_tls.sh`` call it
with 443 to reassemble the TLS session capture, whose ClientHellos can
span segments.

Deliberately standalone, like ``check_fixtures.py``: stdlib only, its own
minimal Ethernet/IPv4/TCP parsing, and no netprotocols import, so a
codec bug cannot shape the vectors the codec is tested against. It
handles exactly what the capture script produces: Ethernet II, IPv4,
one capture point, no IP fragments, no gaps. Anything else (a gap in
the sequence space, an overlapping segment whose bytes differ, a
non-IPv4 frame) stops it rather than writing a stream that was never on
the wire.
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

from _pcap import read_pcap

_SYN = 0x02
_ETHERTYPE_IPV4 = 0x0800
_IPPROTO_TCP = 6


@dataclass
class _Direction:
    """One side of a connection: its initial sequence number and the
    payload bytes it sent, keyed by sequence number."""

    isn: int | None = None
    segments: dict[int, bytes] = field(default_factory=dict)

    def add(self, seq: int, payload: bytes) -> None:
        known = self.segments.get(seq)
        if known is not None and known != payload:
            raise ValueError(f"segment at seq {seq} retransmitted differently")
        self.segments[seq] = payload

    def stream(self) -> bytes:
        """The payload bytes in sequence order, refusing a gap or a
        conflicting overlap (a retransmission is fine)."""
        if self.isn is None:
            raise ValueError("connection has no SYN in the capture")
        expected = (self.isn + 1) & 0xFFFFFFFF
        out = bytearray()
        for seq in sorted(self.segments, key=lambda s: (s - expected) % 2**32):
            payload = self.segments[seq]
            offset = (seq - expected) % 2**32
            if offset > len(out):
                raise ValueError(f"gap before seq {seq}")
            overlap = out[offset:]
            if payload[: len(overlap)] != overlap[: len(payload)]:
                raise ValueError(f"overlap at seq {seq} differs")
            out += payload[len(overlap) :]
        return bytes(out)


def _tcp_segments(frame: bytes):
    """``(src, sport, dst, dport, seq, flags, payload)`` of an
    Ethernet/IPv4/TCP frame."""
    (ethertype,) = struct.unpack_from("!H", frame, 12)
    if ethertype != _ETHERTYPE_IPV4:
        raise ValueError(f"EtherType {ethertype:#06x} is not IPv4")
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    (total_length,) = struct.unpack_from("!H", ip, 2)
    if ip[9] != _IPPROTO_TCP:
        raise ValueError(f"IP protocol {ip[9]} is not TCP")
    (fragment,) = struct.unpack_from("!H", ip, 6)
    if fragment & 0x3FFF:
        raise ValueError("IP fragments are not handled")
    tcp = ip[ihl:total_length]
    sport, dport, seq = struct.unpack_from("!HHI", tcp, 0)
    data_offset = (tcp[12] >> 4) * 4
    return ip[12:16], sport, ip[16:20], dport, seq, tcp[13], tcp[data_offset:]


def extract(frames: list[bytes], port: int) -> list[tuple[bytes, bytes]]:
    """``(request stream, response stream)`` per connection to ``port``,
    in the order the connections opened."""
    connections: dict[tuple[bytes, int], tuple[_Direction, _Direction]] = {}
    for frame in frames:
        src, sport, dst, dport, seq, flags, payload = _tcp_segments(frame)
        if dport == port:
            key, side = (src, sport), 0
        elif sport == port:
            key, side = (dst, dport), 1
        else:
            continue
        direction = connections.setdefault(key, (_Direction(), _Direction()))[
            side
        ]
        if flags & _SYN:
            direction.isn = seq
        elif payload:
            direction.add(seq, payload)
    return [
        (client.stream(), server.stream())
        for client, server in connections.values()
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("capture", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--port", type=int, default=80)
    args = parser.parse_args(argv)

    streams = extract(read_pcap(args.capture), args.port)
    if not streams:
        print(f"no TCP connection to port {args.port}", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    for number, (request, response) in enumerate(streams, start=1):
        (args.out / f"{number:02d}.request").write_bytes(request)
        (args.out / f"{number:02d}.response").write_bytes(response)
        print(
            f"{number:02d}: {len(request)} request bytes, "
            f"{len(response)} response bytes"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
