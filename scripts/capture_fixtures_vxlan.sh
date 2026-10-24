#!/usr/bin/env bash
# Capture a VXLAN fixture for the corpus (RFC 7348).
#
#     sudo scripts/capture_fixtures_vxlan.sh
#
# VXLAN carries a whole Ethernet frame in a UDP datagram to port 4789,
# behind an 8-byte header naming the segment (the 24-bit VNI). A real
# capture needs a real tunnel: this builds a kernel VXLAN device in each
# of two netns over a veth underlay, addresses the overlay, and captures
# the underlay, so each frame is Ethernet -> IPv4 -> UDP (dst 4789) ->
# VXLAN -> Ethernet -> ARP | IPv4 -> ICMPv4 | UDP.
#
# Two segments are captured in turn, each with a fresh ARP exchange:
#
#   VNI 1193046 (0x123456, three distinct bytes, so a byte-order slip
#   in the 24-bit field cannot go unnoticed), with udpcsum: the outer
#   UDP checksum is computed, and check_fixtures.py verifies it over
#   the whole encapsulated frame. Two echoes, then one inner UDP
#   datagram between fixed ports to a listener, so the inner transport
#   checksum is keyed on the inner IPv4 header, not the outer one.
#
#   VNI 100, with noudpcsum: the outer UDP checksum is zero, "not used"
#   under RFC 768, as RFC 7348 §5 says it SHOULD be sent. One echo.
#
# dstport 4789 is passed explicitly: without it, Linux uses its
# pre-IANA 8472. udpcsum and noudpcsum are passed explicitly too,
# rather than left to a kernel default. The underlay and vxlan MAC
# addresses are fixed; a
# re-capture still differs in IPv4 identification, the echo identifier
# and timestamps, and the outer UDP source ports, which the kernel
# hashes from each inner flow (RFC 7348 §5). Offload is off
# on both the veth and the vxlan devices, or the inner and outer
# checksums are left to "offload" and never computed.
#
# The kernel must be able to create a vxlan device (CONFIG_VXLAN); the
# script checks first and stops if it cannot. Every exchange must
# succeed, and the capture must hold exactly the frames above (2 ARP,
# 4 ICMP and 1 UDP on VNI 1193046; 2 ARP and 2 ICMP on VNI 100), or the
# script stops with an error. Whatever was captured by then is left in
# tests/fixtures/staging for inspection and must not be folded in.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump ping python3 ethtool; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSA=npvxa
NSB=npvxb
A=npvxva
B=npvxvb
VX=npvx0
pid=""
listener=""
cleanup() {
    # Stop the capture and the listener first: both run inside the
    # netns that are deleted next.
    if [[ -n $pid ]]; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    if [[ -n $listener ]]; then
        kill "$listener" 2>/dev/null || true
        wait "$listener" 2>/dev/null || true
    fi
    ip netns del "$NSA" 2>/dev/null || true
    ip netns del "$NSB" 2>/dev/null || true
    ip link del "$A" 2>/dev/null || true
}
trap cleanup EXIT
cleanup
fail() { echo "[!] $*" >&2; exit 1; }

no6() {
    $1 sysctl -qw net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    $1 sysctl -qw net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
}
offload_off() {  # netns device
    ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off \
        >/dev/null 2>&1 || true
}

echo "[*] underlay veth + two netns (10.9.12.1 <-> 10.9.12.2)"
ip netns add "$NSA"; ip netns add "$NSB"
no6 "ip netns exec $NSA"; no6 "ip netns exec $NSB"
if ! probe=$(ip -n "$NSA" link add "$VX" type vxlan id 1 dstport 4789 2>&1); then
    echo "This kernel cannot create a vxlan device (CONFIG_VXLAN, or" >&2
    echo "'modprobe vxlan'); a VXLAN capture needs one. ip said:" >&2
    echo "    $probe" >&2
    exit 1
fi
ip -n "$NSA" link del "$VX"
ip link add "$A" address 02:00:0a:09:0c:01 type veth \
    peer name "$B" address 02:00:0a:09:0c:02
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add 10.9.12.1/24 dev "$A"
ip -n "$NSB" addr add 10.9.12.2/24 dev "$B"
offload_off "$NSA" "$A"
offload_off "$NSB" "$B"
ip -n "$NSA" link set lo up; ip -n "$NSA" link set "$A" up
ip -n "$NSB" link set lo up; ip -n "$NSB" link set "$B" up

mk_vxlan() {  # netns underlay-dev local remote overlay-cidr mac vni csum-mode
    local ns=$1 dev=$2 local_ip=$3 remote_ip=$4 cidr=$5 mac=$6 vni=$7 csum=$8
    ip -n "$ns" link add "$VX" address "$mac" type vxlan id "$vni" \
        local "$local_ip" remote "$remote_ip" dstport 4789 dev "$dev" "$csum"
    offload_off "$ns" "$VX"
    ip -n "$ns" addr add "$cidr" dev "$VX"
    ip -n "$ns" link set "$VX" up
}
segment() {  # vni csum-mode
    ip -n "$NSA" link del "$VX" 2>/dev/null || true
    ip -n "$NSB" link del "$VX" 2>/dev/null || true
    mk_vxlan "$NSA" "$A" 10.9.12.1 10.9.12.2 10.9.13.1/24 02:00:0a:09:0d:01 "$1" "$2"
    mk_vxlan "$NSB" "$B" 10.9.12.2 10.9.12.1 10.9.13.2/24 02:00:0a:09:0d:02 "$1" "$2"
}

echo "[>] vxlan (ARP, ICMPv4 echo and UDP across two VXLAN segments)"
ip netns exec "$NSA" tcpdump -i "$A" -w "$OUT/vxlan.pcap" --immediate-mode \
    -U -q udp port 4789 >/dev/null 2>&1 &
pid=$!
sleep 1

# Segment 1: VNI 0x123456, outer UDP checksum computed.
segment 1193046 udpcsum
ip netns exec "$NSA" ping -c 2 -i 0.3 -I 10.9.13.1 10.9.13.2 >/dev/null ||
    fail "VNI 1193046: the echoes across the tunnel went unanswered."
ip netns exec "$NSB" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.9.13.2", 9999))
s.settimeout(5)
s.recv(2048)
' &
listener=$!
sleep 0.5
ip netns exec "$NSA" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.9.13.1", 40000))
s.sendto(b"NETProtocols VXLAN test", ("10.9.13.2", 9999))
'
wait "$listener" ||
    fail "VNI 1193046: the UDP datagram did not reach the listener."
listener=""

# Segment 2: VNI 100, a zero ("not used") outer UDP checksum. Recreating
# the devices empties the overlay neighbour tables, so ARP recurs.
segment 100 noudpcsum
ip netns exec "$NSA" ping -c 1 -I 10.9.13.1 10.9.13.2 >/dev/null ||
    fail "VNI 100: the echo across the tunnel went unanswered."

sleep 1
kill -INT "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
pid=""

echo "[*] Checking the capture holds exactly the expected frames..."
python3 - "$OUT/vxlan.pcap" <<'PY'
import struct
import sys
from collections import Counter

data = open(sys.argv[1], "rb").read()
endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
seen = Counter()
cursor = 24
while cursor + 16 <= len(data):
    incl = struct.unpack_from(endian + "I", data, cursor + 8)[0]
    frame = data[cursor + 16 : cursor + 16 + incl]
    if len(frame) != incl:
        sys.exit(f"record at byte {cursor} declares {incl} bytes, "
                 f"{len(frame)} remain: truncated capture")
    cursor += 16 + incl
    if len(frame) < 14 + 20 + 8 + 8 + 14 + 20:
        seen["runt"] += 1  # too short for the shortest frame expected
        continue
    udp = frame[14 + (frame[14] & 0x0F) * 4 :]
    dst_port, _, checksum = struct.unpack_from("!HHH", udp, 2)
    inner = udp[16:]
    kind = {0x0806: "arp", 0x0800: "ipv4"}.get(
        struct.unpack_from("!H", inner, 12)[0], "other"
    )
    if kind == "ipv4":
        kind = {1: "icmp", 17: "udp"}.get(inner[14 + 9], "other")
    if dst_port != 4789 or udp[8] != 0x08:
        kind = "not-vxlan"
    vni = int.from_bytes(udp[12:15], "big")
    seen[(vni, "csum" if checksum else "no-csum", kind)] += 1
if cursor != len(data):
    sys.exit(f"{len(data) - cursor} stray bytes after the last record")
expected = Counter({
    (1193046, "csum", "arp"): 2,
    (1193046, "csum", "icmp"): 4,
    (1193046, "csum", "udp"): 1,
    (100, "no-csum", "arp"): 2,
    (100, "no-csum", "icmp"): 2,
})
if seen != expected:
    sys.exit(f"[!] Unexpected capture: {dict(seen)}, expected {dict(expected)}")
print(f"[+] {sum(seen.values())} frames, as expected.")
PY

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
echo "[i] Expect vxlan + inner arp/ipv4/icmpv4/udp counts, udp-no-checksum"
echo "    for the VNI 100 frames, and zero checksum failures."
echo "    Fold tests/fixtures/staging/vxlan.pcap into tests/fixtures/."
