#!/usr/bin/env bash
# Capture a DHCP DORA fixture for the corpus (RFC 2131/2132).
#
#     sudo scripts/capture_fixtures_dhcp.sh
#
# A real DHCP exchange needs a server and a client. This runs dnsmasq
# (DHCP only) on one end of a veth pair and dhclient on the other, and
# captures the four DORA messages (DISCOVER / OFFER / REQUEST / ACK),
# each Ethernet -> IPv4 -> UDP -> DHCP. check_fixtures.py verifies the
# UDP checksum (which covers the DHCP payload).
#
# veth is a purely local link, so tx/rx offload is disabled first
# (ethtool -K) or the server's UDP checksums are left to "offload" and
# never computed. dhclient builds its own packets in userspace, so its
# DISCOVER/REQUEST carry real checksums regardless.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump dnsmasq dhclient python3 ethtool; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSS=npdhs
NSC=npdhc
S=npdhsv
C=npdhcv
dnsmasq_pid=""
cleanup() {
    [[ -n $dnsmasq_pid ]] && kill "$dnsmasq_pid" 2>/dev/null || true
    ip netns del "$NSS" 2>/dev/null || true
    ip netns del "$NSC" 2>/dev/null || true
    ip link del "$S" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

no6() {
    $1 sysctl -qw net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    $1 sysctl -qw net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
}

echo "[*] veth + two netns (server 10.9.6.1; client via DHCP)"
no6 ""
ip netns add "$NSS"; ip netns add "$NSC"
no6 "ip netns exec $NSS"; no6 "ip netns exec $NSC"
ip link add "$S" type veth peer name "$C"
ip link set "$S" netns "$NSS"
ip link set "$C" netns "$NSC"
ip -n "$NSS" addr add 10.9.6.1/24 dev "$S"
ip netns exec "$NSS" ethtool -K "$S" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSC" ethtool -K "$C" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSS" link set lo up; ip -n "$NSS" link set "$S" up
ip -n "$NSC" link set lo up; ip -n "$NSC" link set "$C" up

echo "[>] dhcp (DORA exchange: dnsmasq server + dhclient)"
ip netns exec "$NSS" dnsmasq --no-daemon --port=0 --interface="$S" \
    --bind-interfaces --except-interface=lo \
    --dhcp-range=10.9.6.50,10.9.6.99,1h --dhcp-authoritative \
    --dhcp-leasefile=/tmp/np.leases --pid-file=/tmp/np-dnsmasq.pid \
    >/dev/null 2>&1 &
dnsmasq_pid=$!
sleep 1

ip netns exec "$NSS" tcpdump -i "$S" -w "$OUT/dhcp.pcap" --immediate-mode -U -q \
    'udp port 67 or udp port 68' >/dev/null 2>&1 &
pid=$!
sleep 1

ip netns exec "$NSC" dhclient -1 -v "$C" >/dev/null 2>&1 || true
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
echo "[i] Expect 4 frames (ipv4 + udp), zero checksum failures, and the"
echo "    four DORA message types. Fold tests/fixtures/staging/dhcp.pcap"
echo "    into tests/fixtures/."
