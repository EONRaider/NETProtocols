#!/usr/bin/env bash
# Capture an IGMP fixture for the corpus (plan item I-2).
#
#     sudo scripts/capture_fixtures_igmp.sh
#
# IGMP is IPv4 multicast group management — it never appeared in the
# original corpus (which provoked IPv6 MLD, not IPv4 IGMP). Joining an
# IPv4 multicast group makes the kernel emit a membership report
# (IGMPv2 type 0x16 or IGMPv3 type 0x22, depending on the host's
# configured version); a querier on the LAN may also produce a
# membership query (type 0x11). This captures `ip proto 2` on the
# default interface while joining a group, then validates.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for tcpdump (or run it via sudo)." >&2
    exit 1
fi

command -v tcpdump >/dev/null || { echo "tcpdump is required." >&2; exit 1; }

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
[[ -n $IFACE ]] || { echo "No default interface found." >&2; exit 1; }
echo "[*] Default interface: $IFACE"

join_group() {
    python3 - "$IFACE" <<'PY' || true
import socket, struct, sys, time
group = "239.255.42.99"  # an administratively-scoped group (RFC 2365)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
mreq = socket.inet_aton(group) + socket.inet_aton("0.0.0.0")
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
time.sleep(3)  # report is emitted on join; hold briefly
sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
sys.stderr.write(f"joined and left {group} on {sys.argv[1]}\n")
PY
}

echo "[>] igmp (join 239.255.42.99 to provoke a membership report)"
tcpdump -i "$IFACE" -c 4 -w "$OUT/igmp.pcap" --immediate-mode -q \
    ip proto 2 >/dev/null 2>&1 &
pid=$!
sleep 1
join_group
for _ in $(seq 15); do kill -0 $pid 2>/dev/null || break; sleep 1; done
kill $pid 2>/dev/null || true
wait $pid 2>/dev/null || true

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
echo "[i] If no frames were captured, your host may emit IGMPv3 only when"
echo "    a querier is present, or multicast may be disabled on $IFACE."
echo "    The igmp.pcap in staging (if non-empty and OK above) is ready to"
echo "    fold into the corpus."
