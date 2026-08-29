#!/usr/bin/env bash
# Supplementary corpus capture: the two scenarios the first run missed
# (see tests/fixtures/MANIFEST.md "Known gaps").
#
#     sudo scripts/capture_fixtures_supplement.sh
#
# 1. MLD behind hop-by-hop: the original run filtered with BPF `icmp6`,
#    which matches next_header == 58 directly and therefore *excludes*
#    MLD (which rides behind a hop-by-hop header, next_header == 0).
#    This captures `ip6 proto 0` while joining/leaving a multicast
#    group to provoke reports.
# 2. IPv6 fragment pair: an oversized ping -6 to an external host
#    fragments on any 1500-MTU path (ip6 proto 44, inbound).

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for tcpdump (or run it via sudo)." >&2
    exit 1
fi

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
echo "[*] Default interface: $IFACE"

capture() {
    local name=$1 iface=$2 count=$3 filter=$4; shift 4; shift
    echo "[>] $name"
    tcpdump -i "$iface" -c "$count" -w "$OUT/$name.pcap" --immediate-mode \
        -q $filter >/dev/null 2>&1 &
    local pid=$!
    sleep 1
    "$@" >/dev/null 2>&1 || true
    for _ in $(seq 20); do kill -0 $pid 2>/dev/null || break; sleep 1; done
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
}

mld_traffic() {
    python3 - "$IFACE" <<'PY' || true
import socket, struct, sys, time
ifindex = socket.if_nametoindex(sys.argv[1])
group = socket.inet_pton(socket.AF_INET6, "ff02::deca:fbad")
mreq = group + struct.pack("@I", ifindex)
for _ in range(3):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    time.sleep(1.5)
    sock.close()  # leaving also emits an MLD Done/Report
    time.sleep(1.5)
PY
}
capture ipv6_mld "$IFACE" 4 "ip6 proto 0" -- mld_traffic

ipv6_frag_traffic() {
    # An IPv6-reachable anycast resolver; 2000-byte payload fragments
    # on the way back.
    ping -6 -c 3 -i 0.5 -W 3 -s 2000 2606:4700:4700::1111
}
capture ipv6_fragments "$IFACE" 8 "inbound and ip6 proto 44" -- ipv6_frag_traffic

echo
echo "[*] Validating supplement..."
CHECKER_PY=$(command -v python3)
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
else
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
fi
