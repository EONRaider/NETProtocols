#!/usr/bin/env python3
"""Measure how often a walk to a UDP port rejects random payloads.

    uv run --frozen python scripts/measure_port_guard.py
    PYTHONPATH=/path/to/other/tree/src python3 scripts/measure_port_guard.py
    uv run --frozen python scripts/measure_port_guard.py \
        --port 1985 --count HSRP --count HSRPv2

For each of the seeds 0, 1 and 2 the script draws, from
``random.Random(seed)``, 10,000 payloads of 300 random bytes; it then
seeds a new ``random.Random(seed)``, or with ``--one-generator`` goes
on drawing from the first, and draws 10,000 payloads, each of a length
drawn uniformly from 0 to 600 bytes and then that many random bytes.
Each payload is put behind an Ethernet header (EtherType IPv4),
a 20-byte IPv4 header (protocol 17, header checksum zero) and an
8-byte UDP header from port 40000 to the port measured, 123 unless
``--port`` names another, whose Length covers the payload, and the
frame is walked with ``decode_frame(frame, lax=True)``. The 300-byte
payloads are walked once, unpadded; the 0-600 byte ones twice, unpadded
and zero-padded to Ethernet's 60-byte minimum frame.

For each seed and each of the three sets it prints the share of walks
that ended with ``stopped_by`` set, as a percentage to two decimals,
and, for each class name ``--count`` gives, ``NTPControl`` unless it
gives one, how many walks ended in a layer of a class of that name
(none on a tree without one). The first line names the file
``netprotocols`` was imported from, which is the tree measured:
``PYTHONPATH`` picks another tree's ``src``.

Standard library and ``netprotocols`` only.
"""

from __future__ import annotations

import argparse
import random
import struct
import sys
from collections.abc import Sequence

import netprotocols
from netprotocols import decode_frame

#: The seeds of ``random.Random``, one measurement each.
SEEDS = (0, 1, 2)
#: The payloads drawn per set and seed.
PAYLOADS = 10_000
#: The length of every payload of the fixed-length set.
FIXED_LENGTH = 300
#: The largest length of the variable-length set, whose least is 0.
MAX_LENGTH = 600
#: The UDP source port of every frame, and the default destination.
SOURCE_PORT, DESTINATION_PORT = 40000, 123
#: The class whose layers are counted when ``--count`` names none.
DEFAULT_COUNT = "NTPControl"
#: Ethernet's minimum frame without the FCS.
ETHERNET_MINIMUM = 60

_ETHERNET = bytes.fromhex("020000000000 020000000001 0800")
_IPV4 = struct.Struct("!BBHHHBBH4s4s")
_UDP = struct.Struct("!HHHH")


def frame(payload: bytes, padded: bool, port: int = DESTINATION_PORT) -> bytes:
    """Return ``payload`` behind Ethernet, IPv4 and UDP to ``port``.

    :param payload: The UDP payload.
    :param padded: Whether to zero-pad the frame to 60 bytes.
    :param port: The UDP destination port.
    """
    udp = _UDP.pack(SOURCE_PORT, port, 8 + len(payload), 0)
    ipv4 = _IPV4.pack(
        0x45,
        0,
        _IPV4.size + len(udp) + len(payload),
        0,
        0,
        64,
        17,
        0,
        bytes((10, 0, 0, 1)),
        bytes((10, 0, 0, 2)),
    )
    whole = _ETHERNET + ipv4 + udp + payload
    if padded:
        whole += bytes(max(0, ETHERNET_MINIMUM - len(whole)))
    return whole


def walk(
    payloads: Sequence[bytes],
    padded: bool,
    port: int = DESTINATION_PORT,
    counted: Sequence[str] = (DEFAULT_COUNT,),
) -> tuple[float, list[int]]:
    """Walk every payload; return the stopped share and the counts.

    :param payloads: The UDP payloads.
    :param padded: Whether each frame is zero-padded to 60 bytes.
    :param port: The UDP destination port.
    :param counted: The class names whose final layers are counted.
    """
    stopped = 0
    counts = [0] * len(counted)
    for payload in payloads:
        packet = decode_frame(frame(payload, padded, port), lax=True)
        stopped += packet.stopped_by is not None
        last = type(packet.layers[-1]).__name__
        for index, name in enumerate(counted):
            counts[index] += last == name
    return stopped / len(payloads) * 100, counts


def main(argv: Sequence[str] | None = None) -> int:
    """Print the measurement of each seed.

    :param argv: The command-line arguments, ``sys.argv[1:]`` if None.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=DESTINATION_PORT)
    parser.add_argument("--count", action="append", dest="counted")
    parser.add_argument("--one-generator", action="store_true")
    args = parser.parse_args(argv)
    port: int = args.port
    counted: list[str] = args.counted or [DEFAULT_COUNT]
    print(f"netprotocols from {netprotocols.__file__}")
    for seed in SEEDS:
        rng = random.Random(seed)  # nosec B311
        fixed = [rng.randbytes(FIXED_LENGTH) for _ in range(PAYLOADS)]
        if not args.one_generator:
            rng = random.Random(seed)  # nosec B311
        variable = [
            rng.randbytes(rng.randint(0, MAX_LENGTH)) for _ in range(PAYLOADS)
        ]
        results = (
            ("300-byte", walk(fixed, False, port, counted)),
            ("0-600 unpadded", walk(variable, False, port, counted)),
            ("0-600 padded", walk(variable, True, port, counted)),
        )
        cells = "  ".join(
            f"{name} {share:.2f}% ("
            + ", ".join(
                f"{c} {n}" for c, n in zip(counted, counts, strict=True)
            )
            + ")"
            for name, (share, counts) in results
        )
        print(f"seed {seed}: {cells}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
