"""Tests for scripts/check_fixtures.py, the corpus's checksum oracle.

The checker is loaded by path, so it stays independent of netprotocols.
It runs over every directory of committed captures and must pass them
all. Each failure string it can emit is then produced by a minimally
tampered copy of a frame it accepts, a committed fixture frame wherever
one carries the field, and a test fails when the script gains a failure
string no case here produces.

Frames for the strict mode, which applies to whatever an IPsec ICV
covers, are built inside ESP from esp.pcap's Security Association, its
ICV recomputed with the key MANIFEST.md publishes.
"""

import ast
import functools
import hashlib
import hmac
import importlib.util
import itertools
import re
import struct
import subprocess
import sys
import zlib
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check_fixtures.py"
FIXTURES = ROOT / "tests" / "fixtures"


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_fixtures", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


def check(frame: bytes, *, session: bool = False) -> list[str]:
    """The checker's failures for one frame of a capture."""
    stats: Counter[str] = Counter()
    failures: list[str] = checker.check_capture_frame(
        frame, stats, session=session
    )
    return failures


@functools.cache
def pcap_frames(path: Path) -> tuple[bytes, ...]:
    """Every frame of the pcap at ``path``, read by the checker's own
    reader."""
    return tuple(checker.read_pcap(path))


def frame(pcap: str, index: int) -> bytes:
    """Frame ``index`` of the committed fixture ``pcap``."""
    return pcap_frames(FIXTURES / pcap)[index]


# The corpus.


#: Every directory under tests/fixtures that holds a capture, but the
#: untracked tests/fixtures/staging/ and what is under it.
PCAP_DIRS = sorted(
    {
        pcap.parent
        for pcap in FIXTURES.rglob("*.pcap")
        if "staging" not in pcap.relative_to(FIXTURES).parts
    }
)


def test_the_corpus_directories_include_the_top_level() -> None:
    assert FIXTURES in PCAP_DIRS
    assert len(PCAP_DIRS) > 1


@pytest.mark.parametrize(
    "directory", PCAP_DIRS, ids=lambda d: str(d.relative_to(ROOT))
)
def test_every_committed_capture_passes(directory: Path) -> None:
    """The script, run as CONTRIBUTING.md runs it, in isolated mode,
    exits 0 on every directory that holds a committed capture."""
    result = subprocess.run(
        [sys.executable, "-I", str(CHECKER), str(directory)],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.endswith("\nAll files internally consistent.\n")
    assert "[FAIL]" not in result.stdout


# Byte-level helpers, independent of both the checker and the library.


def internet_checksum(data: bytes) -> int:
    """The ones'-complement sum of ``data``'s 16-bit words, complemented
    (RFC 1071), an odd final byte padded with a zero."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def put(data: bytes, offset: int, value: bytes) -> bytes:
    """``data`` with ``value`` written at ``offset``."""
    return data[:offset] + value + data[offset + len(value) :]


def flip(data: bytes, offset: int) -> bytes:
    """``data`` with every bit of the byte at ``offset`` inverted."""
    return put(data, offset, bytes([data[offset] ^ 0xFF]))


def l4(frame: bytes) -> int:
    """Where the IPv4 payload of an untagged Ethernet frame starts."""
    return 14 + (frame[14] & 0x0F) * 4


def udp_data(frame: bytes) -> int:
    """Where the UDP payload of an Ethernet/IPv4/UDP frame starts."""
    return l4(frame) + 8


def tcp_data(frame: bytes) -> int:
    """Where the TCP payload of an Ethernet/IPv4/TCP frame starts."""
    return l4(frame) + (frame[l4(frame) + 12] >> 4) * 4


def reseal(frame: bytes) -> bytes:
    """An Ethernet/IPv4 frame with its IPv4 header checksum and its TCP
    checksum, or its UDP checksum when that is not zero, recomputed
    over the bytes the IPv4 Total Length bounds."""
    header_end = l4(frame)
    end = 14 + struct.unpack_from("!H", frame, 16)[0]
    frame = put(frame, 24, b"\x00\x00")
    checksum = internet_checksum(frame[14:header_end])
    frame = put(frame, 24, checksum.to_bytes(2, "big"))
    proto = frame[23]
    if proto == 6:
        at = header_end + 16
    elif proto == 17 and frame[header_end + 6 : header_end + 8] != b"\0\0":
        at = header_end + 6
    else:
        return frame
    pseudo = frame[26:34] + struct.pack("!BBH", 0, proto, end - header_end)
    frame = put(frame, at, b"\x00\x00")
    checksum = internet_checksum(pseudo + frame[header_end:end])
    if proto == 17:
        checksum = checksum or 0xFFFF
    return put(frame, at, checksum.to_bytes(2, "big"))


def ipv4_frame(template: bytes, proto: int, payload: bytes) -> bytes:
    """``payload`` as protocol ``proto`` in ``template``'s Ethernet and
    IPv4 headers, Total Length and checksums recomputed."""
    header = template[14 : l4(template)]
    header = put(header, 2, struct.pack("!H", len(header) + len(payload)))
    header = put(header, 9, bytes([proto]))
    return reseal(template[:14] + header + payload)


def ipv4_packet(proto: int, payload: bytes) -> bytes:
    """``payload`` as protocol ``proto`` in an IPv4 packet with
    icmpv4_echo_lo.pcap's addresses."""
    return ipv4_frame(ECHO, proto, payload)[14:]


#: An Ethernet/IPv4/ICMPv4 echo request, and its IPv4 packet.
ECHO = frame("icmpv4_echo_lo.pcap", 0)
ECHO_PACKET = ECHO[14:]

#: esp.pcap's transport-mode frame: NULL encryption over an ICMPv4 echo.
ESP_TEMPLATE = frame("esp.pcap", 0)


def esp(
    next_header: int, inner: bytes, *, padding: bytes | None = None
) -> bytes:
    """``inner`` in ESP on ``ESP_TEMPLATE``'s Security Association, with
    RFC 4303 §2.4's default padding unless ``padding`` is given."""
    if padding is None:
        padding = bytes(range(1, -(len(inner) + 2) % 4 + 1))
    spi_and_sequence = ESP_TEMPLATE[34:42]
    (spi,) = struct.unpack_from("!I", spi_and_sequence)
    protected = (
        spi_and_sequence + inner + padding + bytes([len(padding), next_header])
    )
    key = checker._ESP_NULL_SAS[spi]
    icv = hmac.new(key, protected, hashlib.sha256).digest()[:16]
    return ipv4_frame(ESP_TEMPLATE, 50, protected + icv)


def gre(ethertype: int, payload: bytes) -> bytes:
    """A GRE packet with no optional fields."""
    return struct.pack("!HH", 0, ethertype) + payload


def strict_l3(ethertype: int, payload: bytes) -> bytes:
    """``payload``, named by ``ethertype``, in GRE inside ESP."""
    return esp(47, gre(ethertype, payload))


def vxlan(inner_frame: bytes, *, header: bytes = bytes(8)) -> bytes:
    """``inner_frame`` in VXLAN, UDP checksum zero, without IP."""
    body = header + inner_frame
    return struct.pack("!HHHH", 49152, 4789, 8 + len(body), 0) + body


def strict_l2(inner_frame: bytes) -> bytes:
    """``inner_frame`` in VXLAN inside ESP."""
    return esp(17, vxlan(inner_frame))


def mpls_entry(label: int, *, bottom: bool) -> bytes:
    """One MPLS label stack entry, TTL 64 (RFC 3032 §2.1)."""
    return struct.pack("!I", label << 12 | (0x100 if bottom else 0) | 64)


def pim_register(body: bytes, *, null: bool) -> bytes:
    """A PIM Register (RFC 7761 §4.9.3) carrying ``body``, its checksum
    over its first 8 bytes, the N bit set when ``null``."""
    flags = struct.pack("!I", 0x40000000 if null else 0)
    message = b"\x21\x00\x00\x00" + flags + body
    checksum = internet_checksum(message[:8])
    return put(message, 2, checksum.to_bytes(2, "big"))


#: A dummy IPv6 header for a Null-Register: source 2001:db8::1, group
#: ff0e::1.
DUMMY_IPV6 = (
    bytes.fromhex("60000000000067ff")
    + bytes.fromhex("20010db8000000000000000000000001")
    + bytes.fromhex("ff0e0000000000000000000000000001")
)


def dummy_pim(source: bytes, group: bytes) -> bytes:
    """A Null-Register's dummy PIM header under the IPv6 pseudo-header."""
    pseudo = source + group + struct.pack("!IBBBB", 4, 0, 0, 0, 103)
    return b"\x00\x00" + internet_checksum(pseudo + bytes(4)).to_bytes(2, "big")


GOOD_DUMMY_PIM = dummy_pim(DUMMY_IPV6[8:24], DUMMY_IPV6[24:40])


def reseal_ospf(frame: bytes) -> bytes:
    """An Ethernet/IPv4/OSPF frame of AuType 0 or 1 with its OSPF
    checksum recomputed (RFC 2328 §D.4.1)."""
    at = l4(frame)
    length = struct.unpack_from("!H", frame, at + 2)[0]
    packet = frame[at : at + length]
    covered = packet[:12] + packet[14:16] + packet[24:]
    checksum = internet_checksum(covered)
    return put(frame, at + 12, checksum.to_bytes(2, "big"))


def stun_resealed(frame: bytes) -> bytes:
    """An Ethernet/IPv4/UDP frame with one STUN message whose last
    attribute is FINGERPRINT, that CRC (RFC 8489 §14.7) and the UDP
    checksum recomputed."""
    end = 14 + struct.unpack_from("!H", frame, 16)[0]
    crc = zlib.crc32(frame[udp_data(frame) : end - 8]) ^ 0x5354554E
    return reseal(put(frame, end - 4, crc.to_bytes(4, "big")))


def stun_attribute(frame: bytes, kind: int) -> int:
    """The frame offset of the first STUN attribute of type ``kind``."""
    cursor = udp_data(frame) + 20
    while True:
        found, length = struct.unpack_from("!HH", frame, cursor)
        if found == kind:
            return cursor
        cursor += 4 + length + (-length % 4)


def radius_attribute(frame: bytes, kind: int) -> int:
    """The frame offset of the first RADIUS attribute of type ``kind``."""
    cursor = udp_data(frame) + 20
    while frame[cursor] != kind:
        cursor += frame[cursor + 1]
    return cursor


def udp_length(frame: bytes, length: int) -> bytes:
    """An Ethernet/IPv4/UDP frame with its UDP Length set, resealed."""
    return reseal(put(frame, l4(frame) + 4, struct.pack("!H", length)))


def ip_in_ip(packet: bytes, times: int) -> bytes:
    """``packet``, an IPv4 packet, wrapped ``times`` times in IPv4 as
    IP protocol 4, in ``ECHO``'s Ethernet header."""
    for _ in range(times):
        packet = ipv4_packet(4, packet)
    return ECHO[:14] + packet


def cdp_last_tlv(frame: bytes) -> int:
    """The frame offset of the last TLV of a SNAP-encapsulated CDP PDU."""
    pdu = 14 + 8
    end = 14 + struct.unpack_from("!H", frame, 12)[0]
    cursor = last = pdu + 4
    while cursor < end:
        last = cursor
        cursor += struct.unpack_from("!H", frame, cursor + 2)[0]
    return last


def rst_bpdu(flags: int = 0, version: int = 2) -> bytes:
    """llc.pcap's Configuration BPDU rebuilt as an RST BPDU: Protocol
    Version ``version``, BPDU Type 2, ``flags``, and a Version 1 Length
    of 0 after it (802.1D-2004 §9.3.3)."""
    config = frame("llc.pcap", 0)
    bpdu = 14 + 3
    rst = put(config, 12, struct.pack("!H", 3 + 36))
    rst = put(rst, bpdu + 2, bytes([version, 2, flags]))
    return rst + b"\x00"


def lldp_with(tlvs: bytes, end: bytes = b"\x00\x00") -> bytes:
    """lldp.pcap's shutdown LLDPDU with ``tlvs`` before its End TLV."""
    shutdown = frame("lldp.pcap", 2)
    return shutdown[:-2] + tlvs + end


def llc_frame(pdu: bytes) -> bytes:
    """``pdu`` in llc.pcap's 802.3 header, its Length set to fit."""
    return frame("llc.pcap", 3)[:12] + struct.pack("!H", len(pdu)) + pdu


# Every failure string, each from a frame the checker passes.


#: (failure, good frame, tampered frame, failures expected from it).
Case = tuple[str, Callable[[], tuple[bytes, bytes]], list[str] | None]

CASES: list[Case] = []


def case(
    failure: str, *, expected: list[str] | None = None
) -> Callable[
    [Callable[[], tuple[bytes, bytes]]], Callable[[], tuple[bytes, bytes]]
]:
    """Register a builder of (good, tampered) frames whose tampered
    frame fails as ``expected``, by default ``[failure]`` alone."""

    def register(
        build: Callable[[], tuple[bytes, bytes]],
    ) -> Callable[[], tuple[bytes, bytes]]:
        CASES.append((failure, build, expected))
        return build

    return register


# IPv4 and the transports over it.


@case("ipv4-ihl")
def _() -> tuple[bytes, bytes]:
    return ECHO, put(ECHO, 14, b"\x44")


@case("ipv4-header-checksum")
def _() -> tuple[bytes, bytes]:
    return ECHO, flip(ECHO, 24)


@case("icmpv4-checksum")
def _() -> tuple[bytes, bytes]:
    return ECHO, flip(ECHO, l4(ECHO) + 2)


@case("igmp-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("igmp.pcap", 0)
    return good, flip(good, l4(good) + 2)


@case("tcp-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("bgp.pcap", 0)
    return good, flip(good, l4(good) + 16)


@case("udp-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("udp_dns.pcap", 0)
    return good, flip(good, l4(good) + 6)


@case("sctp-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("sctp.pcap", 0)
    return good, flip(good, l4(good) + 8)


@case("nesting-too-deep")
def _() -> tuple[bytes, bytes]:
    return ip_in_ip(ECHO_PACKET, 8), ip_in_ip(ECHO_PACKET, 9)


# IPv6.


@case("icmpv6-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("icmpv6_echo_lo.pcap", 0)
    return good, flip(good, 14 + 40 + 2)


@case("tcp6-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("tcp_http.pcap", 0)
    return good, flip(good, 14 + 40 + 16)


@case("udp6-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("udp_dns.pcap", 1)
    return good, flip(good, 14 + 40 + 6)


@case("ah-ipv6-unverified")
def _() -> tuple[bytes, bytes]:
    good = frame("icmpv6_echo_lo.pcap", 0)
    return good, put(good, 14 + 6, bytes([51]))


# VRRP.


@case("vrrp-version")
def _() -> tuple[bytes, bytes]:
    good = frame("vrrp.pcap", 0)
    return good, put(good, l4(good), bytes([0x10 | good[l4(good)] & 0x0F]))


@case("vrrp-length")
def _() -> tuple[bytes, bytes]:
    good = frame("vrrp.pcap", 0)
    return good, put(good, l4(good) + 3, bytes([good[l4(good) + 3] + 1]))


@case("vrrp-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("vrrp.pcap", 0)
    return good, flip(good, l4(good) + 6)


# GRE.


def gre_with_checksum(payload: bytes, *, key: bool = False) -> bytes:
    """A GRE packet with the C bit set and a correct Checksum (RFC 2784
    §2.5), and with the K and S bits and their words when ``key``."""
    flags = 0xB000 if key else 0x8000
    optional = struct.pack("!II", 42, 7) if key else b""
    header = struct.pack("!HHHH", flags, 0x0800, 0, 0) + optional
    checksum = internet_checksum(header + payload)
    return put(header, 4, checksum.to_bytes(2, "big")) + payload


GRE_TEMPLATE = frame("gre.pcap", 0)


@case("gre-checksum")
def _() -> tuple[bytes, bytes]:
    good = ipv4_frame(GRE_TEMPLATE, 47, gre_with_checksum(ECHO_PACKET))
    return good, flip(good, l4(good) + 5)


@case("unchecked-gre-truncated")
def _() -> tuple[bytes, bytes]:
    packet = gre_with_checksum(ECHO_PACKET)
    return esp(47, packet), esp(47, packet[:5])


# OSPF.


@case("ospf-truncated")
def _() -> tuple[bytes, bytes]:
    good = frame("ospf.pcap", 0)
    return good, reseal(put(good, 16, struct.pack("!H", 20 + 20)))


@case("ospf-header")
def _() -> tuple[bytes, bytes]:
    good = frame("ospf.pcap", 0)
    return good, put(good, l4(good), b"\x03")


@case("ospf-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("ospf.pcap", 0)
    return good, flip(good, l4(good) + 12)


@case("ospf-simple-auth-mismatch")
def _() -> tuple[bytes, bytes]:
    good = frame("ospf.pcap", 18)
    return good, flip(good, l4(good) + 16)


@case("ospf-autype-3")
def _() -> tuple[bytes, bytes]:
    good = frame("ospf.pcap", 0)
    return good, put(good, l4(good) + 15, b"\x03")


@case("ospf-checksum", expected=["ospf-checksum", "ospf-md5-digest"])
def _() -> tuple[bytes, bytes]:
    good = frame("ospf.pcap", 36)
    return good, put(good, l4(good) + 12, b"\x00\x01")


@case("ospf-unknown-key")
def _() -> tuple[bytes, bytes]:
    good = frame("ospf.pcap", 36)
    return good, put(good, l4(good) + 18, b"\x09")


@case("ospf-md5-digest")
def _() -> tuple[bytes, bytes]:
    good = frame("ospf.pcap", 36)
    return good, flip(good, len(good) - 1)


@case("ospf-lsa-length")
def _() -> tuple[bytes, bytes]:
    good = frame("ospf.pcap", 9)
    count = struct.unpack_from("!I", good, l4(good) + 24)[0]
    more = put(good, l4(good) + 24, struct.pack("!I", count + 1))
    return good, reseal_ospf(more)


@case("ospf-lsa-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("ospf.pcap", 9)
    return good, reseal_ospf(flip(good, l4(good) + 24 + 4 + 16))


# PIM.


@case("pim-version")
def _() -> tuple[bytes, bytes]:
    good = frame("pim.pcap", 0)
    return good, put(good, l4(good), bytes([0x30 | good[l4(good)] & 0x0F]))


@case("pim-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("pim.pcap", 0)
    return good, flip(good, l4(good) + 2)


@case("pim-checksum")
def _() -> tuple[bytes, bytes]:
    good = frame("pim.pcap", 3)
    return good, flip(good, l4(good) + 2)


@case("pim-null-register-checksum")
def _() -> tuple[bytes, bytes]:
    template = frame("pim.pcap", 0)
    good = ipv4_frame(
        template, 103, pim_register(DUMMY_IPV6 + GOOD_DUMMY_PIM, null=True)
    )
    return good, flip(good, len(good) - 1)


@case("unchecked-pim-truncated")
def _() -> tuple[bytes, bytes]:
    hello = frame("pim.pcap", 0)
    message = hello[l4(hello) :]
    return esp(103, message), esp(103, message[:3])


@case("unchecked-pim-register-truncated")
def _() -> tuple[bytes, bytes]:
    register = pim_register(ECHO_PACKET, null=False)
    return esp(103, register), esp(103, pim_register(b"", null=False)[:6])


@case("unchecked-pim-null-register-truncated")
def _() -> tuple[bytes, bytes]:
    good = pim_register(DUMMY_IPV6 + GOOD_DUMMY_PIM, null=True)
    cut = pim_register(DUMMY_IPV6 + GOOD_DUMMY_PIM[:2], null=True)
    return esp(103, good), esp(103, cut)


# TLS over TCP port 443.


TLS_HELLO = frame("tls.pcap", 2)
TLS_CCS = frame("tls.pcap", 10)


@case("tls-length")
def _() -> tuple[bytes, bytes]:
    at = tcp_data(TLS_HELLO) + 3
    return TLS_HELLO, reseal(put(TLS_HELLO, at, struct.pack("!H", 0x4801)))


@case("tls-hello")
def _() -> tuple[bytes, bytes]:
    at = tcp_data(TLS_HELLO) + 5 + 4 + 34
    return TLS_HELLO, reseal(put(TLS_HELLO, at, b"\x21"))


@case("tls-sni")
def _() -> tuple[bytes, bytes]:
    at = TLS_HELLO.index(b"tls.np196.test")
    return TLS_HELLO, reseal(put(TLS_HELLO, at, b" "))


@case("tls-split")
def _() -> tuple[bytes, bytes]:
    at = tcp_data(TLS_HELLO) + 3
    length = struct.unpack_from("!H", TLS_HELLO, at)[0]
    longer = put(TLS_HELLO, at, struct.pack("!H", length + 1))
    return TLS_HELLO, reseal(longer)


def tls_ccs_offset() -> int:
    """Where ``TLS_CCS``'s ChangeCipherSpec record starts."""
    first = tcp_data(TLS_CCS)
    return first + 5 + struct.unpack_from("!H", TLS_CCS, first + 3)[0]


@case("tls-ccs")
def _() -> tuple[bytes, bytes]:
    return TLS_CCS, reseal(put(TLS_CCS, tls_ccs_offset() + 5, b"\x02"))


@case("tls-empty")
def _() -> tuple[bytes, bytes]:
    empty = put(TLS_CCS, tls_ccs_offset() + 3, b"\x00\x00")
    return TLS_CCS, reseal(empty)


# STUN.


STUN_AUTH = frame("stun.pcap", 10)


@case("stun-header")
def _() -> tuple[bytes, bytes]:
    at = udp_data(STUN_AUTH)
    return STUN_AUTH, reseal(put(STUN_AUTH, at, b"\x40"))


@case("stun-attributes")
def _() -> tuple[bytes, bytes]:
    at = udp_data(STUN_AUTH) + 20 + 2
    return STUN_AUTH, reseal(put(STUN_AUTH, at, b"\x00\xff"))


@case(
    "stun-unknown-user",
    expected=["stun-unknown-user", "stun-message-integrity"],
)
def _() -> tuple[bytes, bytes]:
    at = stun_attribute(STUN_AUTH, 0x0006) + 4
    return STUN_AUTH, stun_resealed(flip(STUN_AUTH, at))


@case("stun-integrity-sha256")
def _() -> tuple[bytes, bytes]:
    at = stun_attribute(STUN_AUTH, 0x0008)
    return STUN_AUTH, stun_resealed(put(STUN_AUTH, at, b"\x00\x1c"))


@case("stun-message-integrity")
def _() -> tuple[bytes, bytes]:
    at = stun_attribute(STUN_AUTH, 0x0008) + 4
    return STUN_AUTH, stun_resealed(flip(STUN_AUTH, at))


@case("stun-fingerprint")
def _() -> tuple[bytes, bytes]:
    return STUN_AUTH, reseal(flip(STUN_AUTH, len(STUN_AUTH) - 1))


# VXLAN, RIP, RADIUS, NTP and HSRP over UDP.


@case("vxlan-truncated")
def _() -> tuple[bytes, bytes]:
    datagram = vxlan(ECHO)
    return strict_l2(ECHO), esp(17, datagram[:15])


RIP_MD5 = frame("rip.pcap", 13)
RIP_SHA256 = frame("rip.pcap", 17)


@case("rip-unknown-sa")
def _() -> tuple[bytes, bytes]:
    return RIP_MD5, reseal(put(RIP_MD5, udp_data(RIP_MD5) + 10, b"\x09"))


@case("rip-trailer")
def _() -> tuple[bytes, bytes]:
    at = udp_data(RIP_MD5) + 8
    trailer = struct.unpack_from("!H", RIP_MD5, at)[0]
    moved = put(RIP_MD5, at, struct.pack("!H", trailer - 4))
    return RIP_MD5, reseal(moved)


@case("rip-keyed-md5")
def _() -> tuple[bytes, bytes]:
    return RIP_MD5, reseal(flip(RIP_MD5, len(RIP_MD5) - 1))


@case("rip-hmac-sha256")
def _() -> tuple[bytes, bytes]:
    return RIP_SHA256, reseal(flip(RIP_SHA256, len(RIP_SHA256) - 1))


RADIUS_REQUEST = frame("radius.pcap", 0)
RADIUS_ACCOUNTING = frame("radius.pcap", 6)


@case("radius-truncated")
def _() -> tuple[bytes, bytes]:
    return RADIUS_REQUEST, udp_length(RADIUS_REQUEST, 8 + 19)


@case("radius-length")
def _() -> tuple[bytes, bytes]:
    at = udp_data(RADIUS_REQUEST) + 2
    return RADIUS_REQUEST, reseal(put(RADIUS_REQUEST, at, b"\x00\x13"))


@case("radius-attributes")
def _() -> tuple[bytes, bytes]:
    at = udp_data(RADIUS_REQUEST) + 20 + 1
    return RADIUS_REQUEST, reseal(put(RADIUS_REQUEST, at, b"\x01"))


@case("radius-accounting-authenticator")
def _() -> tuple[bytes, bytes]:
    at = udp_data(RADIUS_ACCOUNTING) + 4
    return RADIUS_ACCOUNTING, reseal(flip(RADIUS_ACCOUNTING, at))


@case("radius-message-authenticator")
def _() -> tuple[bytes, bytes]:
    at = radius_attribute(RADIUS_REQUEST, 80) + 2
    return RADIUS_REQUEST, reseal(flip(RADIUS_REQUEST, at))


@case("radius-message-authenticator")
def _() -> tuple[bytes, bytes]:
    at = radius_attribute(RADIUS_REQUEST, 80)
    # Type 80, Length 18 becomes two attributes: 80 of Length 2, then
    # an unassigned type 0 of Length 16.
    split = put(RADIUS_REQUEST, at + 1, b"\x02\x00\x10")
    return RADIUS_REQUEST, reseal(split)


NTP_PLAIN = frame("ntp.pcap", 0)
NTP_MD5 = frame("ntp.pcap", 2)
NTP_SHA1 = frame("ntp.pcap", 4)
NTP_EXTENSION = frame("ntp.pcap", 8)


@case("ntp-truncated")
def _() -> tuple[bytes, bytes]:
    return NTP_PLAIN, udp_length(NTP_PLAIN, 8 + 47)


@case("ntp-extension-field")
def _() -> tuple[bytes, bytes]:
    at = udp_data(NTP_EXTENSION) + 48 + 2
    return NTP_EXTENSION, reseal(put(NTP_EXTENSION, at, b"\x00\x0f"))


@case("ntp-trailer")
def _() -> tuple[bytes, bytes]:
    length = struct.unpack_from("!H", NTP_MD5, l4(NTP_MD5) + 4)[0]
    return NTP_MD5, udp_length(NTP_MD5, length - 1)


@case("ntp-unknown-key")
def _() -> tuple[bytes, bytes]:
    at = udp_data(NTP_MD5) + 48 + 3
    return NTP_MD5, reseal(put(NTP_MD5, at, b"\x09"))


@case("ntp-md5")
def _() -> tuple[bytes, bytes]:
    return NTP_MD5, reseal(flip(NTP_MD5, len(NTP_MD5) - 1))


@case("ntp-sha1")
def _() -> tuple[bytes, bytes]:
    return NTP_SHA1, reseal(flip(NTP_SHA1, len(NTP_SHA1) - 1))


HSRP_HELLO = frame("hsrp.pcap", 0)


def hsrp(offset: int, value: int) -> tuple[bytes, bytes]:
    """``HSRP_HELLO`` and a copy with HSRP byte ``offset`` set."""
    at = udp_data(HSRP_HELLO) + offset
    return HSRP_HELLO, reseal(put(HSRP_HELLO, at, bytes([value])))


@case("hsrp-length")
def _() -> tuple[bytes, bytes]:
    return HSRP_HELLO, udp_length(HSRP_HELLO, 8 + 19)


@case("hsrp-port")
def _() -> tuple[bytes, bytes]:
    at = l4(HSRP_HELLO)
    return HSRP_HELLO, reseal(put(HSRP_HELLO, at, struct.pack("!H", 1986)))


@case("hsrp-version")
def _() -> tuple[bytes, bytes]:
    return hsrp(0, 1)


@case("hsrp-op-code")
def _() -> tuple[bytes, bytes]:
    return hsrp(1, 3)


@case("hsrp-state")
def _() -> tuple[bytes, bytes]:
    return hsrp(2, 3)


@case("hsrp-holdtime")
def _() -> tuple[bytes, bytes]:
    return hsrp(4, HSRP_HELLO[udp_data(HSRP_HELLO) + 3])


@case("hsrp-reserved")
def _() -> tuple[bytes, bytes]:
    return hsrp(7, 1)


@case("hsrp-auth-data")
def _() -> tuple[bytes, bytes]:
    return hsrp(8, 1)


# IPsec.


AH_TRANSPORT = frame("ah.pcap", 1)
ICMP_MESSAGE = ECHO[l4(ECHO) :]


@case("esp-unknown-sa")
def _() -> tuple[bytes, bytes]:
    at = l4(ESP_TEMPLATE)
    return ESP_TEMPLATE, put(ESP_TEMPLATE, at, struct.pack("!I", 0x10000009))


@case("esp-icv")
def _() -> tuple[bytes, bytes]:
    return ESP_TEMPLATE, flip(ESP_TEMPLATE, len(ESP_TEMPLATE) - 1)


@case("esp-truncated")
def _() -> tuple[bytes, bytes]:
    cut = ESP_TEMPLATE[l4(ESP_TEMPLATE) :][:25]
    return ESP_TEMPLATE, ipv4_frame(ESP_TEMPLATE, 50, cut)


@case("esp-padding")
def _() -> tuple[bytes, bytes]:
    good = esp(1, ICMP_MESSAGE)
    padding = bytes(range(1, -(len(ICMP_MESSAGE) + 2) % 4 + 1)) or b"\x01"
    return good, esp(1, ICMP_MESSAGE, padding=padding[::-1] + b"\x00\x00\x00")


@case("ah-unknown-sa")
def _() -> tuple[bytes, bytes]:
    at = l4(AH_TRANSPORT) + 4
    return AH_TRANSPORT, put(AH_TRANSPORT, at, struct.pack("!I", 0x20000009))


@case("ah-icv")
def _() -> tuple[bytes, bytes]:
    return AH_TRANSPORT, flip(AH_TRANSPORT, l4(AH_TRANSPORT) + 12)


@case("ah-truncated")
def _() -> tuple[bytes, bytes]:
    cut = AH_TRANSPORT[l4(AH_TRANSPORT) :][:11]
    return AH_TRANSPORT, ipv4_frame(AH_TRANSPORT, 51, cut)


@case("ah-truncated")
def _() -> tuple[bytes, bytes]:
    cut = AH_TRANSPORT[l4(AH_TRANSPORT) :][:20]
    return AH_TRANSPORT, ipv4_frame(AH_TRANSPORT, 51, cut)


@case("ah-length")
def _() -> tuple[bytes, bytes]:
    return AH_TRANSPORT, put(AH_TRANSPORT, l4(AH_TRANSPORT) + 1, b"\x04")


@case("ah-ipv4-options-unverified")
def _() -> tuple[bytes, bytes]:
    # Four bytes of options: three No Operation and an End of Option
    # List (RFC 791 §3.1).
    total = struct.unpack_from("!H", AH_TRANSPORT, 16)[0]
    header = put(AH_TRANSPORT[14:34], 0, b"\x46")
    header = put(header, 2, struct.pack("!H", total + 4))
    with_options = AH_TRANSPORT[:14] + header + b"\x01\x01\x01\x00"
    return AH_TRANSPORT, reseal(with_options + AH_TRANSPORT[34:])


# Strict mode: what an ICV vouched for must be readable.


@case("unchecked-protocol-200")
def _() -> tuple[bytes, bytes]:
    return esp(1, ICMP_MESSAGE), esp(200, ICMP_MESSAGE)


@case("unchecked-fragment")
def _() -> tuple[bytes, bytes]:
    more_fragments = put(ECHO_PACKET, 6, b"\x20\x00")
    header = put(more_fragments[:20], 10, b"\x00\x00")
    checksum = internet_checksum(header).to_bytes(2, "big")
    first_fragment = put(more_fragments, 10, checksum)
    return esp(4, ECHO_PACKET), esp(4, first_fragment)


@case("unchecked-fragment")
def _() -> tuple[bytes, bytes]:
    later_fragment = put(ECHO_PACKET, 6, b"\x00\x01")
    header = put(later_fragment[:20], 10, b"\x00\x00")
    checksum = internet_checksum(header).to_bytes(2, "big")
    return esp(4, ECHO_PACKET), esp(4, put(later_fragment, 10, checksum))


ECHO6_PACKET = frame("icmpv6_echo_lo.pcap", 0)[14:]


@case("unchecked-fragment")
def _() -> tuple[bytes, bytes]:
    # A Fragment header (RFC 8200 §4.5): Next Header 58, offset 0 and
    # the M flag set.
    payload_length = struct.unpack_from("!H", ECHO6_PACKET, 4)[0]
    header = put(ECHO6_PACKET[:40], 4, struct.pack("!H", payload_length + 8))
    header = put(header, 6, b"\x2c")
    fragment = struct.pack("!BBHI", 58, 0, 0x0001, 1)
    return esp(41, ECHO6_PACKET), esp(41, header + fragment + ECHO6_PACKET[40:])


@case("unchecked-ethertype-0x0801")
def _() -> tuple[bytes, bytes]:
    return strict_l3(0x0800, ECHO_PACKET), strict_l3(0x0801, ECHO_PACKET)


ARP = frame("arp_exchange.pcap", 0)[14:42]


@case("unchecked-ethertype-0x0806")
def _() -> tuple[bytes, bytes]:
    return strict_l3(0x0806, ARP), strict_l3(0x0806, ARP[:27])


@case("unchecked-mpls-truncated")
def _() -> tuple[bytes, bytes]:
    good = mpls_entry(0, bottom=True) + ECHO_PACKET
    return strict_l3(0x8847, good), strict_l3(
        0x8847, mpls_entry(0, bottom=False)
    )


@case("unchecked-mpls-payload")
def _() -> tuple[bytes, bytes]:
    good = mpls_entry(0, bottom=True) + ECHO_PACKET
    gal = mpls_entry(13, bottom=True) + ECHO_PACKET
    return strict_l3(0x8847, good), strict_l3(0x8847, gal)


@case("unchecked-runt")
def _() -> tuple[bytes, bytes]:
    return strict_l2(ECHO), strict_l2(ECHO[:13])


@case("unchecked-vlan-truncated")
def _() -> tuple[bytes, bytes]:
    tagged = frame("vlan_icmp.pcap", 2)
    return strict_l2(tagged), strict_l2(tagged[:17])


@case("unchecked-type-1501")
def _() -> tuple[bytes, bytes]:
    return strict_l2(ECHO), strict_l2(put(ECHO, 12, struct.pack("!H", 1501)))


STP_CONFIG = frame("llc.pcap", 0)


@case("unchecked-llc-dsap-0x43")
def _() -> tuple[bytes, bytes]:
    return strict_l2(STP_CONFIG), strict_l2(put(STP_CONFIG, 14, b"\x43"))


@case("unchecked-llc-dsap-0x42-control-0x01")
def _() -> tuple[bytes, bytes]:
    return strict_l2(STP_CONFIG), strict_l2(put(STP_CONFIG, 16, b"\x01"))


@case("unchecked-llc-dsap-0x42-protocol-0x0001")
def _() -> tuple[bytes, bytes]:
    return strict_l2(STP_CONFIG), strict_l2(put(STP_CONFIG, 18, b"\x01"))


SNAP_IPV4 = frame("llc.pcap", 9)


@case("unchecked-snap-000001-0x0800")
def _() -> tuple[bytes, bytes]:
    return strict_l2(SNAP_IPV4), strict_l2(put(SNAP_IPV4, 19, b"\x01"))


# 802.3, LLC, STP, CDP and LLDP.


@case("8023-length-exceeds-frame")
def _() -> tuple[bytes, bytes]:
    length = struct.unpack_from("!H", STP_CONFIG, 12)[0]
    return STP_CONFIG, put(STP_CONFIG, 12, struct.pack("!H", length + 1))


@case("8023-trailer-not-padding")
def _() -> tuple[bytes, bytes]:
    padded = frame("llc.pcap", 8)
    return padded, put(padded, len(padded) - 1, b"\x01")


@case("ipx-length-mismatch")
def _() -> tuple[bytes, bytes]:
    ipx = frame("llc.pcap", 12)
    length = struct.unpack_from("!H", ipx, 16)[0]
    return ipx, put(ipx, 16, struct.pack("!H", length + 1))


@case("llc-truncated")
def _() -> tuple[bytes, bytes]:
    # DSAP and SSAP 0xF0 (NetBIOS), then a UI Control of one octet, or
    # an I-format Control, which needs two.
    return llc_frame(b"\xf0\xf0\x03"), llc_frame(b"\xf0\xf0\x00")


@case("snap-malformed")
def _() -> tuple[bytes, bytes]:
    return SNAP_IPV4, put(SNAP_IPV4, 15, b"\xab")


@case("stp-bpdu-malformed")
def _() -> tuple[bytes, bytes]:
    return STP_CONFIG, put(STP_CONFIG, 14 + 3 + 3, b"\x01")


@case("stp-config-unused-flags")
def _() -> tuple[bytes, bytes]:
    flags = STP_CONFIG[14 + 3 + 4]
    return STP_CONFIG, put(STP_CONFIG, 14 + 3 + 4, bytes([flags | 0x02]))


@case("stp-rst-unused-flags")
def _() -> tuple[bytes, bytes]:
    return rst_bpdu(), rst_bpdu(flags=0x80)


@case("stp-rst-malformed")
def _() -> tuple[bytes, bytes]:
    return rst_bpdu(), rst_bpdu(version=1)


CDP = frame("llc.pcap", 5)


@case("cdp-malformed")
def _() -> tuple[bytes, bytes]:
    return CDP, put(CDP, 14 + 8, b"\x03")


@case("cdp-malformed")
def _() -> tuple[bytes, bytes]:
    return CDP, put(CDP, cdp_last_tlv(CDP) + 2, b"\x00\x03")


@case("cdp-tlvs-overrun")
def _() -> tuple[bytes, bytes]:
    at = cdp_last_tlv(CDP) + 2
    length = struct.unpack_from("!H", CDP, at)[0]
    return CDP, put(CDP, at, struct.pack("!H", length + 4))


@case("cdp-checksum")
def _() -> tuple[bytes, bytes]:
    return CDP, flip(CDP, 14 + 8 + 2)


LLDP = frame("lldp.pcap", 0)


@case("lldp-unwalkable")
def _() -> tuple[bytes, bytes]:
    word = struct.unpack_from("!H", LLDP, 14)[0]
    return LLDP, put(LLDP, 14, struct.pack("!H", word | 0x1FF))


@case("lldp-bad-end")
def _() -> tuple[bytes, bytes]:
    shutdown = frame("lldp.pcap", 2)
    return shutdown, shutdown + b"\x01"


@case("lldp-mandatory-tlvs")
def _() -> tuple[bytes, bytes]:
    word = struct.unpack_from("!H", LLDP, 14)[0]
    return LLDP, put(LLDP, 14, struct.pack("!H", 4 << 9 | word & 0x1FF))


@case("lldp-shutdown-extra-tlvs")
def _() -> tuple[bytes, bytes]:
    # A System Name TLV (type 5) of one byte.
    return lldp_with(b""), lldp_with(struct.pack("!H", 5 << 9 | 1) + b"x")


@pytest.mark.parametrize(
    ("failure", "build", "expected"),
    CASES,
    ids=[failure for failure, _, _ in CASES],
)
def test_a_tampered_frame_fails(
    failure: str,
    build: Callable[[], tuple[bytes, bytes]],
    expected: list[str] | None,
) -> None:
    good, tampered = build()
    assert check(good) == []
    assert check(tampered) == (expected or [failure])


def test_a_split_tls_record_passes_in_a_session_capture() -> None:
    builds = [build for failure, build, _ in CASES if failure == "tls-split"]
    _, split = builds[0]()
    assert check(split, session=True) == []


# GRE checksums (RFC 2784 §2.5).


GRE_FRAMES = pcap_frames(FIXTURES / "gre.pcap")


def gre_flags(gre_frame: bytes) -> int:
    """The GRE flags word of an Ethernet/IPv4/GRE frame."""
    flags: int = struct.unpack_from("!H", gre_frame, l4(gre_frame))[0]
    return flags


class TestGREChecksum:
    def test_committed_frames_have_the_c_bit_clear_and_are_not_summed(
        self,
    ) -> None:
        """gre.pcap holds plain (flags clear) and keyed (K bit only)
        frames; each passes, and none is counted as summed."""
        assert {gre_flags(gre_frame) for gre_frame in GRE_FRAMES} == {
            0x0000,
            0x2000,
        }
        for gre_frame in GRE_FRAMES:
            stats: Counter[str] = Counter()
            assert checker.check_frame(gre_frame, stats) == []
            assert stats["gre"] == 1
            assert stats["gre-checksum"] == 0

    def test_a_clear_c_bit_reads_no_checksum(self) -> None:
        """With the C bit clear, bytes 4-7 of a keyed frame are its Key,
        which no checksum covers: any value passes."""
        keyed = next(f for f in GRE_FRAMES if gre_flags(f) == 0x2000)
        for offset in (4, 5, 6, 7):
            rekeyed = flip(keyed, l4(keyed) + offset)
            stats: Counter[str] = Counter()
            assert checker.check_frame(rekeyed, stats) == []
            assert stats["gre-checksum"] == 0

    @pytest.mark.parametrize("key", [False, True], ids=["c", "c-k-s"])
    def test_a_correct_checksum_passes(self, key: bool) -> None:
        packet = gre_with_checksum(ECHO_PACKET, key=key)
        stats: Counter[str] = Counter()
        good = ipv4_frame(GRE_TEMPLATE, 47, packet)
        assert checker.check_frame(good, stats) == []
        assert stats["gre-checksum"] == 1
        assert stats["icmpv4"] == 1

    @pytest.mark.parametrize("key", [False, True], ids=["c", "c-k-s"])
    @pytest.mark.parametrize(
        ("offset", "bits"),
        [(0, 0x40), (4, 0xFF), (5, 0x01), (6, 0x80)],
        ids=["routing-bit", "checksum-high", "checksum-low", "reserved1"],
    )
    def test_a_tampered_header_byte_fails(
        self, key: bool, offset: int, bits: int
    ) -> None:
        """The checksum covers the whole header: the flags word (here
        its Routing Present bit, which nothing else reads), the
        Checksum itself and Reserved1."""
        packet = gre_with_checksum(ECHO_PACKET, key=key)
        tampered = put(packet, offset, bytes([packet[offset] ^ bits]))
        bad = ipv4_frame(GRE_TEMPLATE, 47, tampered)
        assert checker.check_frame(bad, Counter()) == ["gre-checksum"]

    @pytest.mark.parametrize("offset", [8, 12], ids=["key", "sequence"])
    def test_a_tampered_key_or_sequence_fails(self, offset: int) -> None:
        packet = gre_with_checksum(ECHO_PACKET, key=True)
        bad = ipv4_frame(GRE_TEMPLATE, 47, flip(packet, offset))
        assert checker.check_frame(bad, Counter()) == ["gre-checksum"]

    @pytest.mark.parametrize("key", [False, True], ids=["c", "c-k-s"])
    def test_a_tampered_payload_fails_and_is_still_checked(
        self, key: bool
    ) -> None:
        packet = gre_with_checksum(ECHO_PACKET, key=key)
        bad = ipv4_frame(GRE_TEMPLATE, 47, flip(packet, len(packet) - 1))
        assert checker.check_frame(bad, Counter()) == [
            "gre-checksum",
            "icmpv4-checksum",
        ]

    def test_an_odd_length_packet_is_padded_for_the_sum(self) -> None:
        payload = ECHO_PACKET + b"\x01"
        packet = gre_with_checksum(payload)
        assert len(packet) % 2
        good = ipv4_frame(GRE_TEMPLATE, 47, packet)
        assert checker.check_frame(good, Counter()) == []
        bad = ipv4_frame(GRE_TEMPLATE, 47, flip(packet, len(packet) - 1))
        assert checker.check_frame(bad, Counter()) == ["gre-checksum"]

    @pytest.mark.parametrize(
        "trailer",
        [bytes(18), bytes.fromhex("deadbeef"), bytes(6) + b"\xff" * 4],
        ids=["zero-padding", "fcs", "padding-and-fcs"],
    )
    def test_bytes_after_the_ip_datagram_are_not_summed(
        self, trailer: bytes
    ) -> None:
        """The sum ends where the outer IPv4 Total Length ends the
        datagram: Ethernet padding or a frame check sequence after it
        changes nothing, whether the Checksum is right or wrong."""
        good = ipv4_frame(GRE_TEMPLATE, 47, gre_with_checksum(ECHO_PACKET))
        stats: Counter[str] = Counter()
        assert checker.check_frame(good + trailer, stats) == []
        assert stats["gre-checksum"] == 1
        bad = flip(good, l4(good) + 5)
        assert checker.check_frame(bad + trailer, Counter()) == ["gre-checksum"]

    def test_a_checksum_over_the_trailer_too_fails(self) -> None:
        """A Checksum computed over the bytes past the IPv4 Total Length
        as well does not verify."""
        trailer = bytes.fromhex("12345678")
        summed = gre_with_checksum(ECHO_PACKET + trailer)
        packet = summed[: -len(trailer)]
        bad = ipv4_frame(GRE_TEMPLATE, 47, packet) + trailer
        assert checker.check_frame(bad, Counter()) == ["gre-checksum"]

    def test_a_cut_header_passes_unread_outside_strict(self) -> None:
        packet = gre_with_checksum(ECHO_PACKET)[:5]
        stats: Counter[str] = Counter()
        cut = ipv4_frame(GRE_TEMPLATE, 47, packet)
        assert checker.check_frame(cut, stats) == []
        assert stats["gre-truncated"] == 1

    def test_the_helper_matches_rfc_1071s_example(self) -> None:
        """RFC 1071 §3's worked example: the words 0001 f203 f4f5 f6f7
        sum to ddf2, whose complement is 220d."""
        assert internet_checksum(bytes.fromhex("0001f203f4f5f6f7")) == 0x220D


# The pcap file and the command line.


def run_main(
    directory: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, str]:
    """``main()``'s exit status and output for ``directory``."""
    monkeypatch.setattr(sys, "argv", ["check_fixtures.py", str(directory)])
    status: int = checker.main()
    return status, capsys.readouterr().out


PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def pcap_file(frames: list[bytes], header: bytes = PCAP_HEADER) -> bytes:
    """A little-endian classic pcap holding ``frames``."""
    records = b"".join(
        struct.pack("<IIII", 0, 0, len(data), len(data)) + data
        for data in frames
    )
    return header + records


FILE_FAILURES = {
    "not a pcap: too short": PCAP_HEADER[:23],
    "not a pcap: magic 0badcafe": bytes.fromhex("0badcafe") + PCAP_HEADER[4:],
    "linktype 101 is not Ethernet": PCAP_HEADER[:20] + struct.pack("<I", 101),
}


class TestMain:
    def test_a_good_capture_passes(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "echo.pcap").write_bytes(pcap_file([ECHO]))
        status, out = run_main(tmp_path, monkeypatch, capsys)
        assert status == 0
        assert "[OK  ] echo.pcap: 1 frames" in out
        assert out.endswith("\nAll files internally consistent.\n")

    def test_a_failing_frame_fails_the_run(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        bad = flip(ECHO, 24)
        (tmp_path / "echo.pcap").write_bytes(pcap_file([ECHO, bad, bad]))
        status, out = run_main(tmp_path, monkeypatch, capsys)
        assert status == 1
        assert "[FAIL] echo.pcap: 3 frames" in out
        assert "!! ipv4-header-checksum x2" in out
        assert "1 file(s) FAILED checksum consistency" in out

    @pytest.mark.parametrize(
        ("failure", "data"),
        list(FILE_FAILURES.items()),
        ids=list(FILE_FAILURES),
    )
    def test_an_unreadable_file_fails_the_run(
        self,
        failure: str,
        data: bytes,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / "good.pcap").write_bytes(pcap_file([ECHO]))
        (tmp_path / "bad.pcap").write_bytes(data)
        status, out = run_main(tmp_path, monkeypatch, capsys)
        assert status == 1
        assert f"[FAIL] bad.pcap: {failure}\n" in out
        assert "[OK  ] good.pcap" in out

    def test_a_tls_split_in_a_session_capture_passes(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        builds = [b for failure, b, _ in CASES if failure == "tls-split"]
        _, split = builds[0]()
        (tmp_path / "x_session.pcap").write_bytes(pcap_file([split]))
        (tmp_path / "x.pcap").write_bytes(pcap_file([split]))
        status, out = run_main(tmp_path, monkeypatch, capsys)
        assert status == 1
        assert "[OK  ] x_session.pcap" in out
        assert "[FAIL] x.pcap" in out
        assert "!! tls-split x1" in out

    def test_an_empty_directory_fails(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        status, out = run_main(tmp_path, monkeypatch, capsys)
        assert status == 1
        assert out == f"No pcaps found in {tmp_path}/\n"


# Every failure string in the script has a case above.


def _patterns(node: ast.expr, names: dict[str, list[str]]) -> list[str]:
    """Regexes for the strings ``node``, a str literal or f-string,
    evaluates to; none for anything else. A replacement field that is a
    bare name bound in ``names`` takes each of that name's regexes in
    turn, and any other replacement field matches any text."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [re.escape(node.value)]
    if not isinstance(node, ast.JoinedStr):
        return []
    choices: list[list[str]] = []
    for part in node.values:
        if isinstance(part, ast.Constant):
            choices.append([re.escape(str(part.value))])
        elif (
            isinstance(part, ast.FormattedValue)
            and isinstance(part.value, ast.Name)
            and part.format_spec is None
            and part.value.id in names
        ):
            choices.append(names[part.value.id])
        else:
            choices.append([".+"])
    return ["".join(parts) for parts in itertools.product(*choices)]


def _local_strings(function: ast.FunctionDef) -> dict[str, list[str]]:
    """The regexes of the strings each name ``function`` binds, by plain
    assignments, to a str literal or f-string."""
    names: dict[str, list[str]] = {}
    for node in ast.walk(function):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            target = node.targets[0].id
            names.setdefault(target, []).extend(_patterns(node.value, {}))
    return {name: patterns for name, patterns in names.items() if patterns}


def _emitted(node: ast.AST) -> list[ast.expr]:
    """The expressions ``node`` hands back as a failure: the elements of
    a list display, the value of a ``return``, and the first argument of
    an ``.append`` call or of a ``ValueError``."""
    if isinstance(node, ast.List):
        return list(node.elts)
    if isinstance(node, ast.Return) and node.value is not None:
        return [node.value]
    if isinstance(node, ast.Call) and node.args:
        func = node.func
        if (isinstance(func, ast.Attribute) and func.attr == "append") or (
            isinstance(func, ast.Name) and func.id == "ValueError"
        ):
            return [node.args[0]]
    return []


def emitted_failures() -> set[str]:
    """Regexes for every failure string the script can emit, each
    expression :func:`_emitted` finds in its functions, with the names
    each function binds to strings resolved (see :func:`_patterns`)."""
    tree = ast.parse(CHECKER.read_text())
    found: set[str] = set()
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue
        names = _local_strings(function)
        for node in ast.walk(function):
            for expr in _emitted(node):
                found.update(_patterns(expr, names))
    return found


def _specificity(pattern: str) -> int:
    """How many literal characters ``pattern`` holds."""
    return len(re.sub(r"\\(.)", r"\1", pattern.replace(".+", "")))


def uncovered(patterns: set[str], kinds: set[str]) -> list[str]:
    """The ``patterns`` no kind in ``kinds`` is assigned to.

    Each kind is assigned only to the patterns it matches with the most
    literal characters, so a kind that a literal pattern names exactly
    never also stands for an f-string pattern it happens to match."""
    assigned: set[str] = set()
    for kind in kinds:
        matching = [p for p in patterns if re.fullmatch(p, kind)]
        if matching:
            best = max(map(_specificity, matching))
            assigned.update(p for p in matching if _specificity(p) == best)
    return sorted(patterns - assigned)


def test_the_scan_finds_known_failures() -> None:
    patterns = emitted_failures()
    assert re.escape("gre-checksum") in patterns
    assert "unchecked\\-protocol\\-.+" in patterns
    assert "not\\ a\\ pcap:\\ magic\\ .+" in patterns
    # A name bound to an f-string earlier in the function is resolved.
    assert "unchecked\\-llc\\-dsap\\-0x42\\-control\\-0x.+" in patterns
    assert "unchecked\\-.+" not in patterns


def test_a_kind_stands_only_for_its_most_specific_pattern() -> None:
    patterns = {"rip\\-.+", "rip\\-trailer"}
    assert uncovered(patterns, {"rip-trailer"}) == ["rip\\-.+"]
    assert uncovered(patterns, {"rip-trailer", "rip-keyed-md5"}) == []


def test_every_failure_string_has_a_case() -> None:
    covered = {failure for failure, _, _ in CASES} | set(FILE_FAILURES)
    missing = uncovered(emitted_failures(), covered)
    assert not missing, f"no case produces {missing}"
