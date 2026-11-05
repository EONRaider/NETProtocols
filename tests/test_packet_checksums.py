"""Packet rebuilding covers each checksum supported by compute()."""

from dataclasses import replace

import pytest

from conftest import FIXTURES, corpus_frames, pcap_frames
from netprotocols import (
    CDP,
    GRE,
    IGMP,
    OSPF,
    PIM,
    SCTP,
    STUN,
    TCP,
    UDP,
    VRRP,
    ICMPv4,
    ICMPv6,
    InvalidFieldError,
    IPv4,
    IPv6,
    Packet,
    compute,
    decode_frame,
    verify,
)
from test_corpus import walk
from test_vrrp import ones_complement


def checksum_cases():
    """Collect each checksummed layer type found in the corpus.

    A checksummed GRE header, which the corpus does not hold, is added
    by hand. Each case is a layer and its enclosing IP header.
    """
    seen = set()
    cases = []
    for name, index, frame in corpus_frames():
        ip = None
        for layer in walk(frame)[0]:
            if isinstance(layer, (IPv4, IPv6)):
                ip = layer
            if type(layer) in seen:
                continue
            try:
                compute(layer, ip=ip, payload=b"payload")
            except InvalidFieldError:
                continue
            seen.add(type(layer))
            cases.append(pytest.param(layer, ip, id=f"{name}#{index}"))
    cases.append(
        pytest.param(
            GRE(flags=0x8000, protocol_type=0x0800, fields=bytes(4)),
            None,
            id="checksummed-gre",
        )
    )
    return cases


CHECKSUM_CASES = checksum_cases()


def test_checksum_case_coverage():
    assert {type(case.values[0]) for case in CHECKSUM_CASES} == {
        IPv4,
        ICMPv4,
        ICMPv6,
        TCP,
        UDP,
        SCTP,
        IGMP,
        GRE,
        VRRP,
        PIM,
        CDP,
        OSPF,
        STUN,
    }


@pytest.mark.parametrize("layer,ip", CHECKSUM_CASES)
def test_with_checksums_matches_compute_for_each_corpus_type(layer, ip):
    """Refill each case's stale checksum with compute()'s value.

    The corpus IGMP messages end at their IP datagram's declared end,
    so the bytes with_checksums() covers are the bytes compute() covers.
    """
    payload = b"payload"
    expected = compute(layer, ip=ip, payload=payload)
    if isinstance(layer, GRE):
        stale = replace(
            layer, fields=(expected ^ 1).to_bytes(2, "big") + layer.fields[2:]
        )
    elif isinstance(layer, STUN):
        stale = replace(
            layer,
            attributes=layer.attributes[:-4]
            + (expected ^ 1).to_bytes(4, "big"),
        )
    else:
        stale = replace(layer, checksum=expected ^ 1)
    packet = Packet(stale) if ip is None or layer is ip else Packet(ip, stale)
    filled = packet.with_checksums(payload).layers[-1]
    actual = filled.fingerprint if isinstance(filled, STUN) else filled.checksum
    assert actual == expected
    assert verify(filled, ip=ip, payload=payload)
    assert packet.layers[-1] == stale


@pytest.mark.parametrize("kind", [0x12, 0x16, 0x11, 0x22])
def test_with_checksums_igmp_versions(kind):
    # v1 report, v2 report, v3 query with one source, v3 empty report.
    body = {
        0x12: bytes.fromhex("e0010203"),
        0x16: bytes.fromhex("e0010203"),
        0x11: bytes.fromhex("e0010203 02 7d 0001 c0000201"),
        0x22: bytes(4),
    }[kind]
    layer = IGMP(type=kind, max_resp_code=0, checksum=0, body=body)
    filled = Packet(layer).with_checksums(b"outside-message")[IGMP]
    assert ones_complement(bytes(filled)) == 0
    assert verify(filled)
    assert filled.body == body
    assert layer.checksum == 0


def test_with_checksums_restores_real_igmp_frames():
    frames = pcap_frames(FIXTURES / "igmp.pcap")
    assert frames
    for frame in frames:
        packet = decode_frame(frame)
        stale = Packet(
            *(
                replace(layer, checksum=layer.checksum ^ 1)
                if isinstance(layer, (IPv4, IGMP))
                else layer
                for layer in packet.layers
            )
        )
        assert bytes(stale.with_checksums()) == bytes(packet)


@pytest.mark.parametrize("flags", [0x8000, 0xA000, 0x9000, 0xB000])
@pytest.mark.parametrize("tail", [b"", b"odd", bytes(range(64))])
def test_with_checksums_gre_preserves_optional_fields_and_covers_payload(
    flags, tail
):
    fields = b"\x12\x34\xab\xcd"
    if flags & 0x2000:
        fields += bytes.fromhex("cafebabe")
    if flags & 0x1000:
        fields += bytes.fromhex("00010203")
    layer = GRE(flags=flags, protocol_type=0x1234, fields=fields)
    filled = Packet(layer).with_checksums(tail)[GRE]
    assert ones_complement(bytes(filled) + tail) == 0
    assert verify(filled, payload=tail)
    assert filled.fields[2:] == fields[2:]
    assert filled.flags == flags
    assert filled.protocol_type == layer.protocol_type
    assert layer.fields == fields


@pytest.mark.parametrize(
    "flags,fields",
    [
        (0, b""),
        (0x2000, b"key!"),
        (0x1000, b"seq!"),
        (0x3000, b"key!seq!"),
        (0x8000, b""),
        (0x8000, b"\x12"),
    ],
)
def test_with_checksums_leaves_gre_without_checksum_unchanged(flags, fields):
    """Keep a GRE header whose checksum is ``None`` as it is.

    That is one with the Checksum-Present bit clear, or with it set and
    ``fields`` too short to hold the checksum.
    """
    layer = GRE(flags=flags, protocol_type=0x0800, fields=fields)
    assert layer.checksum is None
    assert Packet(layer).with_checksums(b"payload")[GRE] is layer


def test_with_checksums_fills_gre_after_its_inner_packet():
    # Reuse captured encapsulated IPv4 bytes under a checksummed GRE header.
    frame = pcap_frames(FIXTURES / "gre.pcap")[0]
    packet = decode_frame(frame)
    gre_index = next(
        i for i, layer in enumerate(packet.layers) if isinstance(layer, GRE)
    )
    layers = list(packet.layers)
    layers[gre_index] = GRE(
        flags=0x8000,
        protocol_type=packet.layers[gre_index].protocol_type,
        fields=bytes(4),
    )
    growth = layers[gre_index].header_len - packet.layers[gre_index].header_len
    for index, layer in enumerate(layers):
        if isinstance(layer, IPv4):
            layers[index] = replace(
                layer,
                checksum=layer.checksum ^ 1,
                total_length=layer.total_length
                + (growth if index < gre_index else 0),
            )
        elif isinstance(layer, (UDP, ICMPv4)):
            layers[index] = replace(layer, checksum=layer.checksum ^ 1)
    stale = Packet(*layers)
    tail = frame[packet.consumed :]
    for index, layer in enumerate(stale.layers[:gre_index]):
        if isinstance(layer, IPv4):
            assert layer.total_length == sum(
                item.header_len for item in stale.layers[index:]
            ) + len(tail)
    filled = stale.with_checksums(tail)
    inner = b"".join(bytes(layer) for layer in filled.layers[gre_index + 1 :])
    assert ones_complement(bytes(filled.layers[gre_index]) + inner + tail) == 0
    assert filled.layers[gre_index + 1 :] == packet.layers[gre_index + 1 :]
