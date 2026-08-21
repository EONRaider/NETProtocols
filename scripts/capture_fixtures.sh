#!/usr/bin/env bash
# Capture the real-frame fixture corpus (issue #27, plan item L-0).
#
# Run once with sudo from the repository root:
#
#     sudo scripts/capture_fixtures.sh
#
# Writes per-scenario pcaps into tests/fixtures/staging/ and finishes by
# running scripts/check_fixtures.py over them. Frames used for checksum
# ground truth are captured INBOUND only (outbound frames often carry
# checksums left unfilled for NIC offload). Nothing is committed by this
# script: review the checker report, then hand the staging directory to
# the test-writing step.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for tcpdump (or run it via sudo)." >&2
    exit 1
fi

command -v tcpdump >/dev/null || { echo "tcpdump is required." >&2; exit 1; }

OUT="tests/fixtures/staging"
mkdir -p "$OUT"

IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
GATEWAY=$(ip route show default | awk '/default/ {print $3; exit}')
[[ -n $IFACE ]] || { echo "No default interface found." >&2; exit 1; }
echo "[*] Default interface: $IFACE (gateway $GATEWAY)"
echo "[*] Writing to $OUT/"

# capture NAME IFACE COUNT FILTER -- TRAFFIC_CMD...
# Starts a bounded tcpdump, runs the traffic generator, waits.
capture() {
    local name=$1 iface=$2 count=$3 filter=$4; shift 4; shift # consume --
    echo "[>] $name"
    tcpdump -i "$iface" -c "$count" -w "$OUT/$name.pcap" --immediate-mode \
        -q $filter >/dev/null 2>&1 &
    local pid=$!
    sleep 1
    "$@" >/dev/null 2>&1 || true
    # Give tcpdump up to 15s to fill its count, then stop it either way.
    for _ in $(seq 15); do kill -0 $pid 2>/dev/null || break; sleep 1; done
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
}

# --- Loopback scenarios (checksum ground truth: lo has no offload issue
# --- for inbound copies; we still filter inbound where it matters).
capture icmpv4_echo_lo lo 6 "icmp" -- ping -c 3 -i 0.3 127.0.0.1
capture icmpv6_echo_lo lo 6 "icmp6" -- ping -c 3 -i 0.3 ::1

# --- Default-interface scenarios, inbound-only where checksums matter.
capture udp_dns "$IFACE" 4 "inbound and udp and port 53" -- \
    sh -c 'dig +tries=1 +time=3 example.com @1.1.1.1; dig +tries=1 +time=3 AAAA example.com @1.1.1.1'
capture tcp_http "$IFACE" 12 "inbound and tcp and port 80" -- \
    curl -s -m 8 -o /dev/null http://example.com/
capture tcp_https "$IFACE" 12 "inbound and tcp and port 443" -- \
    curl -s -m 8 -o /dev/null https://example.com/
capture icmpv4_external "$IFACE" 4 "inbound and icmp" -- \
    ping -c 3 -i 0.4 -W 2 1.1.1.1
# A 2000-byte ping fragments on any 1500-MTU path: inbound echo replies
# arrive as an IPv4 fragment pair.
capture ipv4_fragments "$IFACE" 6 "inbound and (icmp or ip[6:2] & 0x3fff != 0)" -- \
    ping -c 3 -i 0.4 -W 2 -s 2000 1.1.1.1
# TTL-exceeded errors from intermediate hops.
capture icmpv4_ttl_exceeded "$IFACE" 4 "inbound and icmp[icmptype] == 11" -- \
    sh -c 'ping -c 2 -W 2 -t 2 1.1.1.1; ping -c 2 -W 2 -t 3 1.1.1.1'

# --- ARP (no checksums; both directions welcome). Flush the gateway
# --- neighbor entry to force a fresh exchange.
arp_traffic() {
    ip neigh del "$GATEWAY" dev "$IFACE" 2>/dev/null || true
    ping -c 1 -W 2 "$GATEWAY"
}
capture arp_exchange "$IFACE" 4 "arp" -- arp_traffic

# --- IPv6 NDP / MLD, ambient + provoked. MLD reports ride behind a
# --- hop-by-hop header (the L-1 fixture). Joining a multicast group
# --- provokes a report; pinging the all-nodes address provokes NDP.
ipv6_traffic() {
    ping -6 -c 2 -W 2 "ff02::1%$IFACE" || true
    python3 - "$IFACE" <<'PY' || true
import socket, struct, sys, time
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
ifindex = socket.if_nametoindex(sys.argv[1])
group = socket.inet_pton(socket.AF_INET6, "ff02::deca:fbad")
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                group + struct.pack("@I", ifindex))
time.sleep(3)
PY
}
capture ipv6_ndp_mld "$IFACE" 10 "icmp6" -- ipv6_traffic

echo
echo "[*] Captures done. Validating..."
CHECKER_PY=$(command -v python3)
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
else
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
fi
