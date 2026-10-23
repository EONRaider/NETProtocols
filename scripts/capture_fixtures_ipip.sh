#!/usr/bin/env bash
# Capture IP-in-IP fixtures for the corpus (RFC 2003, RFC 4213, RFC 2473).
#
#     sudo scripts/capture_fixtures_ipip.sh
#
# IP-in-IP has no header of its own: the outer IP header's protocol
# field says the payload is another whole IP packet -- 4 for IPv4
# (RFC 2003; IPv4 in IPv6 is RFC 2473), 41 for IPv6 (6in4, RFC 4213;
# IPv6 in IPv6, RFC 2473). This captures all four outer/inner
# combinations, two ICMP echo requests each, over a veth pair between
# two netns: Ethernet -> IPv4|IPv6 (protocol 4|41) -> IPv4|IPv6 ->
# ICMPv4|ICMPv6.
#
# The packets are encapsulated by the kernel itself, not spliced: a raw
# IP socket opened for protocol 4 or 41 has the kernel build and
# transmit the outer header (and, on IPv4, its checksum), with the
# inner packet as the payload. That is the same encapsulation a tunnel
# endpoint performs, and it works where the ipip/sit tunnel drivers
# are not built, as on many minimal or VM kernels. The inner packets
# are assembled here with correct checksums; check_fixtures.py peels
# the outer header and verifies them.
#
# The two IPv6-outer combinations need a kernel with IPv6; on one
# without it (no /proc/net/if_inet6), only the IPv4-outer ones are
# captured, and the script says so. The inner IPv6 packets of 6in4 are
# plain payload bytes, so they need no kernel IPv6 at all.
#
# veth is a purely local link, so tx/rx offload is disabled first
# (ethtool -K) or the outer IPv4 checksum is left to "offload" and never
# computed. IPv6 addresses are added with nodad, so the IPv6 sends do
# not race duplicate-address detection.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSA=npipa
NSB=npipb
A=npipva
B=npipvb
cleanup() {
    ip netns del "$NSA" 2>/dev/null || true
    ip netns del "$NSB" 2>/dev/null || true
    ip link del "$A" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

OUTER="ipv4 ipv6"
if [[ ! -e /proc/net/if_inet6 ]]; then
    OUTER="ipv4"
    echo "[!] This kernel has no IPv6: capturing IPv4-outer frames only."
fi

echo "[*] veth + two netns (A 10.9.9.1, B 10.9.9.2; IPv6 fd00:9::1/2 if available)"
ip netns add "$NSA"; ip netns add "$NSB"
ip link add "$A" type veth peer name "$B"
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add 10.9.9.1/24 dev "$A"
ip -n "$NSB" addr add 10.9.9.2/24 dev "$B"
if [[ $OUTER == *ipv6* ]]; then
    ip -n "$NSA" addr add fd00:9::1/64 dev "$A" nodad
    ip -n "$NSB" addr add fd00:9::2/64 dev "$B" nodad
fi
ip netns exec "$NSA" ethtool -K "$A" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSB" ethtool -K "$B" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSA" link set lo up; ip -n "$NSA" link set "$A" up
ip -n "$NSB" link set lo up; ip -n "$NSB" link set "$B" up
sleep 1

SEND_PY=$(cat <<'PY'
import socket
import struct
import sys


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


PAYLOAD = b"NETProtocols IP-in-IP fixture"
INNER4 = (socket.inet_pton(socket.AF_INET, "192.0.2.1"),
          socket.inet_pton(socket.AF_INET, "192.0.2.2"))
INNER6 = (socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
          socket.inet_pton(socket.AF_INET6, "2001:db8::2"))


def inner_ipv4(seq: int) -> bytes:
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x4E50, seq) + PAYLOAD
    icmp = icmp[:2] + struct.pack("!H", checksum(icmp)) + icmp[4:]
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), seq, 0, 64, 1, 0, *INNER4
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + icmp


def inner_ipv6(seq: int) -> bytes:
    icmp = struct.pack("!BBHHH", 128, 0, 0, 0x4E50, seq) + PAYLOAD
    pseudo = INNER6[0] + INNER6[1] + struct.pack("!I3xB", len(icmp), 58)
    icmp = icmp[:2] + struct.pack("!H", checksum(pseudo + icmp)) + icmp[4:]
    header = struct.pack("!IHBB", 6 << 28, len(icmp), 58, 64)
    return header + INNER6[0] + INNER6[1] + icmp


OUTER = {
    "ipv4": (socket.AF_INET, ("10.9.9.2", 0)),
    "ipv6": (socket.AF_INET6, ("fd00:9::2", 0)),
}
for family, outer_dst in (OUTER[name] for name in sys.argv[1:]):
    for protocol, build in ((4, inner_ipv4), (41, inner_ipv6)):
        with socket.socket(family, socket.SOCK_RAW, protocol) as sock:
            for seq in (1, 2):
                sock.sendto(build(seq), outer_dst)
PY
)

echo "[>] ipip (raw-socket encapsulation: IPv4/IPv6 outer x protocol 4/41)"
FILTER='(ip and (ip proto 4 or ip proto 41)) or (ip6 and (ip6 proto 4 or ip6 proto 41))'
ip netns exec "$NSB" tcpdump -i "$B" -w "$OUT/ipip.pcap" --immediate-mode -U -q \
    "$FILTER" >/dev/null 2>&1 &
pid=$!
sleep 1

# shellcheck disable=SC2086 # OUTER is a deliberate word list
ip netns exec "$NSA" python3 -c "$SEND_PY" $OUTER
sleep 1

kill -INT "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

echo
echo "[*] Validating..."
CHECKER_PY=$(command -v python3)
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
else
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
fi

echo
echo "[i] Expect zero checksum failures and two frames per combination:"
echo "    IPv4-in-IPv4 and IPv6-in-IPv4, plus IPv4-in-IPv6 and IPv6-in-IPv6"
echo "    on a kernel with IPv6 -- 8 frames, or 4 without. Every inner packet"
echo "    is an ICMP echo request. Fold tests/fixtures/staging/ipip.pcap into"
echo "    tests/fixtures/."
