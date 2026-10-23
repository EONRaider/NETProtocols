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
#   VNI 100, with noudpcsum, the kernel's default for IPv4 VXLAN: the
#   outer UDP checksum is zero, "not used" under RFC 768, which RFC 7348
#   §5 permits. One echo.
#
# dstport 4789 is passed explicitly: iproute2's default is Linux's
# pre-IANA 8472. The underlay and vxlan MAC addresses are fixed; a
# re-capture still differs in IPv4 identification, the echo identifier
# and timestamps, and the outer UDP source ports, which the kernel
# hashes from each inner flow (RFC 7348 §5). Offload is off
# on both the veth and the vxlan devices, or the inner and outer
# checksums are left to "offload" and never computed.

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
cleanup() {
    ip netns del "$NSA" 2>/dev/null || true
    ip netns del "$NSB" 2>/dev/null || true
    ip link del "$A" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

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
ip netns exec "$NSA" ping -c 2 -i 0.3 -I 10.9.13.1 10.9.13.2 >/dev/null || true
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
wait "$listener" || true

# Segment 2: VNI 100, the default zero outer UDP checksum. Recreating
# the devices empties the overlay neighbour tables, so ARP recurs.
segment 100 noudpcsum
ip netns exec "$NSA" ping -c 1 -I 10.9.13.1 10.9.13.2 >/dev/null || true

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
echo "[i] Expect vxlan + inner arp/ipv4/icmpv4/udp counts, udp-no-checksum"
echo "    for the VNI 100 frames, and zero checksum failures."
echo "    Fold tests/fixtures/staging/vxlan.pcap into tests/fixtures/."
