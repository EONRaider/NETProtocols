#!/usr/bin/env bash
# Capture an IPv4-in-GRE fixture for the corpus (RFC 2784/2890).
#
#     sudo scripts/capture_fixtures_gre.sh
#
# GRE tunnels one protocol inside another; a real capture needs an
# actual tunnel. This builds a kernel GRE tunnel over a veth pair (two
# netns), pings across the overlay, and captures the underlay — so each
# frame is Ethernet -> IPv4 (proto 47) -> GRE -> IPv4 -> ICMPv4. It
# captures a plain tunnel (GRE flags all clear) and then a keyed tunnel
# (the RFC 2890 key field), and validates with check_fixtures.py, which
# peels the GRE header and verifies the inner IPv4/ICMP checksums.
#
# veth is a purely local link, so tx/rx offload is disabled first
# (ethtool -K): otherwise the outer IPv4 checksum is left to "offload"
# and never actually computed. The gre kernel module autoloads when the
# first tunnel device is created.

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
NSA=npgrea
NSB=npgreb
A=npgva
B=npgvb
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

echo "[*] underlay veth + two netns (10.9.4.1 <-> 10.9.4.2)"
no6 ""
ip netns add "$NSA"; ip netns add "$NSB"
no6 "ip netns exec $NSA"; no6 "ip netns exec $NSB"
ip link add "$A" type veth peer name "$B"
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add 10.9.4.1/24 dev "$A"
ip -n "$NSB" addr add 10.9.4.2/24 dev "$B"
ip netns exec "$NSA" ethtool -K "$A" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSB" ethtool -K "$B" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSA" link set lo up; ip -n "$NSA" link set "$A" up
ip -n "$NSB" link set lo up; ip -n "$NSB" link set "$B" up

mk_tunnel() {  # netns local remote [extra args: key 0x2a, csum, ...]
    local ns=$1 local_ip=$2 remote_ip=$3; shift 3
    ip -n "$ns" tunnel add npgre0 mode gre local "$local_ip" \
        remote "$remote_ip" "$@"
    ip -n "$ns" link set npgre0 up
    ip netns exec "$ns" ethtool -K npgre0 tx off rx off >/dev/null 2>&1 || true
}
address_overlay() {  # netns cidr
    ip -n "$1" addr add "$2" dev npgre0
}

echo "[>] gre (ICMPv4 echo over a plain and a keyed GRE tunnel)"
ip netns exec "$NSA" tcpdump -i "$A" -w "$OUT/gre.pcap" --immediate-mode -U -q \
    ip proto 47 >/dev/null 2>&1 &
pid=$!
sleep 1

# Plain tunnel (GRE flags all clear).
mk_tunnel "$NSA" 10.9.4.1 10.9.4.2
mk_tunnel "$NSB" 10.9.4.2 10.9.4.1
address_overlay "$NSA" 10.9.5.1/24
address_overlay "$NSB" 10.9.5.2/24
ip netns exec "$NSA" ping -c 2 -i 0.3 -I 10.9.5.1 10.9.5.2 >/dev/null || true

# Keyed tunnel (exercises the RFC 2890 key field).
ip -n "$NSA" tunnel del npgre0 2>/dev/null || true
ip -n "$NSB" tunnel del npgre0 2>/dev/null || true
mk_tunnel "$NSA" 10.9.4.1 10.9.4.2 key 0x2a
mk_tunnel "$NSB" 10.9.4.2 10.9.4.1 key 0x2a
address_overlay "$NSA" 10.9.5.1/24
address_overlay "$NSB" 10.9.5.2/24
ip -n "$NSA" neigh flush dev "$A" 2>/dev/null || true
ip netns exec "$NSA" ping -c 2 -i 0.3 -I 10.9.5.1 10.9.5.2 >/dev/null || true

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
echo "[i] Expect gre + inner ipv4/icmpv4 counts and zero checksum failures."
echo "    Fold tests/fixtures/staging/gre.pcap into tests/fixtures/."
