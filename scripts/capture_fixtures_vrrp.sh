#!/usr/bin/env bash
# Capture a VRRP fixture for the corpus (RFC 3768 VRRPv2, RFC 5798 VRRPv3).
#
#     sudo scripts/capture_fixtures_vrrp.sh
#
# Two keepalived routers, A (10.9.20.1, priority 200) and B (10.9.20.2,
# priority 100), in two netns over a veth pair, run through four
# segments, one virtual router (VRID) each:
#
#   VRID 51  VRRPv2, auth_type PASS, two virtual addresses, multicast:
#            A is master, resigns (a priority-0 advert), B takes over
#            and resigns in turn.
#   VRID 52  VRRPv2, no authentication, one address, multicast: A only.
#   VRID 53  VRRPv3, one address (the minimal 12-byte advert),
#            multicast: the same failover as VRID 51.
#   VRID 54  VRRPv3, three addresses, Max Adver Int 0.5 s, unicast
#            between the two routers: A is master while B listens as
#            backup, then B stops and A resigns.
#
# keepalived builds every VRRP message, its checksum included, in
# userspace, and the IPv4 header too (a raw socket with IP_HDRINCL,
# header checksum left 0 for the kernel to fill). Each frame is
# Ethernet -> IPv4 (protocol 112) -> VRRP.
#
# A master advertises once per interval for as long as it runs, so how
# many adverts the raw capture holds depends on timing. The script
# therefore drives each segment by watching the capture (the next step
# waits until the adverts it needs have been seen), captures everything
# to a scratch file, and then keeps a fixed selection: from each router
# in each segment, its first two adverts with a nonzero priority and
# its priority-0 advert. The kept frames' composition is asserted
# exactly at the end.
#
# Both directions are captured on B's side of the veth pair. Offload
# is turned off first (ethtool -K) as best effort: the result is not
# checked. What is guaranteed is that check_fixtures.py verifies every
# IPv4 header checksum and VRRP checksum in the capture.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool keepalived; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSA=npvr-a
NSB=npvr-b
A=npvr-va
B=npvr-vb
WORK=
TCPDUMP_PID=
A_PID=
B_PID=
cleanup() {
    for pid in $A_PID $B_PID $TCPDUMP_PID; do
        kill "$pid" 2>/dev/null || true
    done
    for ns in "$NSA" "$NSB"; do
        if [[ -e /run/netns/$ns ]]; then
            ip netns pids "$ns" | xargs -r kill 2>/dev/null || true
        fi
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del "$A" 2>/dev/null || true
    if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)
RAW="$WORK/raw.pcap"

echo "[*] veth + two netns (A 10.9.20.1, B 10.9.20.2)"
ip netns add "$NSA"; ip netns add "$NSB"
ip link add "$A" type veth peer name "$B"
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add 10.9.20.1/24 dev "$A"
ip -n "$NSB" addr add 10.9.20.2/24 dev "$B"
ip netns exec "$NSA" ethtool -K "$A" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSB" ethtool -K "$B" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSA" link set lo up; ip -n "$NSA" link set "$A" up
ip -n "$NSB" link set lo up; ip -n "$NSB" link set "$B" up
sleep 1

# How many adverts in the raw capture come from <src> for <vrid>, with
# a nonzero priority ("live") or priority 0 ("resign").
COUNT_PY=$(cat <<'PY'
import socket
import struct
import sys

path, src, vrid, kind = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
try:
    raw = open(path, "rb").read()
except FileNotFoundError:
    raw = b""
count = 0
offset = 24
while offset + 16 <= len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    frame = raw[offset + 16 : offset + 16 + caplen]
    offset += 16 + caplen
    if len(frame) < 14 + 20 + 8:
        continue
    ip = frame[14:]
    vrrp = ip[(ip[0] & 0x0F) * 4 :]
    if socket.inet_ntoa(ip[12:16]) != src or vrrp[1] != vrid:
        continue
    if (vrrp[2] == 0) == (kind == "resign"):
        count += 1
print(count)
PY
)

# Wait (up to 30 s) until the raw capture holds at least <n> adverts
# of <kind> from <src> for <vrid>.
wait_adverts() {
    local src=$1 vrid=$2 kind=$3 n=$4 tries=300
    until (( $(python3 -c "$COUNT_PY" "$RAW" "$src" "$vrid" "$kind") >= n )); do
        if (( --tries == 0 )); then
            echo "Timed out waiting for $n $kind adverts from $src (VRID $vrid)." >&2
            exit 1
        fi
        sleep 0.1
    done
}

# conf <router> <version> <vrid> <priority> <advert_int> <extra> <vips...>
conf() {
    local router=$1 version=$2 vrid=$3 priority=$4 interval=$5 extra=$6
    shift 6
    local iface=$A
    [[ $router == b ]] && iface=$B
    {
        echo "global_defs {"
        echo "    router_id npvr-$router"
        echo "    vrrp_version $version"
        echo "}"
        echo "vrrp_instance np$vrid {"
        echo "    state BACKUP"
        echo "    interface $iface"
        echo "    virtual_router_id $vrid"
        echo "    priority $priority"
        echo "    advert_int $interval"
        echo "$extra"
        echo "    virtual_ipaddress {"
        printf '        %s/24\n' "$@"
        echo "    }"
        echo "}"
    } > "$WORK/$router-$vrid.conf"
}

# start <router> <vrid>: run keepalived (VRRP only, in the foreground)
# in the router's netns, and record its PID.
start() {
    local router=$1 vrid=$2 ns=$NSA
    [[ $router == b ]] && ns=$NSB
    ip netns exec "$ns" keepalived --dont-fork --log-console --no-syslog \
        --vrrp --use-file "$WORK/$router-$vrid.conf" \
        --pid "$WORK/$router.pid" --vrrp_pid "$WORK/$router-vrrp.pid" \
        > "$WORK/$router-$vrid.log" 2>&1 &
    if [[ $router == a ]]; then A_PID=$!; else B_PID=$!; fi
}

# stop <router>: SIGTERM; a master sends its priority-0 advert on the
# way out (RFC 3768 §6.4.3, RFC 5798 §6.4.3).
stop() {
    local pid
    if [[ $1 == a ]]; then pid=$A_PID; A_PID=; else pid=$B_PID; B_PID=; fi
    kill -TERM "$pid"
    wait "$pid" || true
}

PASS_AUTH='    authentication {
        auth_type PASS
        auth_pass np-vrrp
    }'
UNICAST_A='    unicast_src_ip 10.9.20.1
    unicast_peer {
        10.9.20.2
    }'
UNICAST_B='    unicast_src_ip 10.9.20.2
    unicast_peer {
        10.9.20.1
    }'

# failover <vrid>: A masters and resigns, B takes over and resigns.
failover() {
    local vrid=$1
    start a "$vrid"
    wait_adverts 10.9.20.1 "$vrid" live 1
    start b "$vrid"
    wait_adverts 10.9.20.1 "$vrid" live 3
    stop a
    wait_adverts 10.9.20.1 "$vrid" resign 1
    wait_adverts 10.9.20.2 "$vrid" live 2
    stop b
    wait_adverts 10.9.20.2 "$vrid" resign 1
}

ip netns exec "$NSB" tcpdump -i "$B" -w "$RAW" --immediate-mode -U -q \
    'ip proto 112' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "[>] VRID 51: VRRPv2, PASS authentication, two addresses, failover"
conf a 2 51 200 1 "$PASS_AUTH" 10.9.20.51 10.9.20.52
conf b 2 51 100 1 "$PASS_AUTH" 10.9.20.51 10.9.20.52
failover 51

echo "[>] VRID 52: VRRPv2, no authentication, one address"
conf a 2 52 200 1 "" 10.9.20.60
start a 52
wait_adverts 10.9.20.1 52 live 2
stop a
wait_adverts 10.9.20.1 52 resign 1

echo "[>] VRID 53: VRRPv3, one address, failover"
conf a 3 53 200 1 "" 10.9.20.70
conf b 3 53 100 1 "" 10.9.20.70
failover 53

echo "[>] VRID 54: VRRPv3, three addresses, 0.5 s interval, unicast"
conf a 3 54 200 0.5 "$UNICAST_A" 10.9.20.81 10.9.20.82 10.9.20.83
conf b 3 54 100 0.5 "$UNICAST_B" 10.9.20.81 10.9.20.82 10.9.20.83
start a 54
wait_adverts 10.9.20.1 54 live 1
start b 54
wait_adverts 10.9.20.1 54 live 4
# B is the backup, so it stops without a word; A then resigns.
stop b
stop a
wait_adverts 10.9.20.1 54 resign 1
sleep 1

kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=

# Keep, in capture order, each router's first two live adverts and its
# resignation in each segment; drop the rest of the periodic adverts.
SELECT_PY=$(cat <<'PY'
import struct
import sys
from collections import Counter

raw = open(sys.argv[1], "rb").read()
assert raw[:4] == b"\xd4\xc3\xb2\xa1", "expected a little-endian classic pcap"
assert struct.unpack_from("<I", raw, 20)[0] == 1, "expected Ethernet framing"
out = [raw[:24]]
live = Counter()
kept = 0
offset = 24
while offset + 16 <= len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    record = raw[offset : offset + 16 + caplen]
    offset += 16 + caplen
    ip = record[16 + 14 :]
    vrrp = ip[(ip[0] & 0x0F) * 4 :]
    key = (ip[12:16], vrrp[1])
    if vrrp[2] != 0:
        live[key] += 1
        if live[key] > 2:
            continue
    out.append(record)
    kept += 1
open(sys.argv[2], "wb").write(b"".join(out))
print(f"[i] kept {kept} of the raw capture's VRRP frames")
PY
)
python3 -c "$SELECT_PY" "$RAW" "$OUT/vrrp.pcap"

echo
echo "[*] Validating..."
CHECKER_PY=$(command -v python3)
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
else
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
fi

COMPOSITION_PY=$(cat <<'PY'
import socket
import struct
import sys

raw = open(sys.argv[1], "rb").read()
frames = []
offset = 24
while offset < len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    frames.append(raw[offset + 16 : offset + 16 + caplen])
    offset += 16 + caplen
A, B, GROUP = "10.9.20.1", "10.9.20.2", "224.0.0.18"
# (source, destination, version, VRID, priority, addresses, auth type)
v2_pass = (2, 51)
v2_none = (2, 52)
v3_mcast = (3, 53)
v3_ucast = (3, 54)
expected = (
    [(A, GROUP, *v2_pass, 200, 2, 1)] * 2
    + [(A, GROUP, *v2_pass, 0, 2, 1)]
    + [(B, GROUP, *v2_pass, 100, 2, 1)] * 2
    + [(B, GROUP, *v2_pass, 0, 2, 1)]
    + [(A, GROUP, *v2_none, 200, 1, 0)] * 2
    + [(A, GROUP, *v2_none, 0, 1, 0)]
    + [(A, GROUP, *v3_mcast, 200, 1, None)] * 2
    + [(A, GROUP, *v3_mcast, 0, 1, None)]
    + [(B, GROUP, *v3_mcast, 100, 1, None)] * 2
    + [(B, GROUP, *v3_mcast, 0, 1, None)]
    + [(A, B, *v3_ucast, 200, 3, None)] * 2
    + [(A, B, *v3_ucast, 0, 3, None)]
)
got = []
for number, frame in enumerate(frames, 1):
    ip = frame[14:]
    assert ip[9] == 112, f"frame {number} is not VRRP"
    vrrp = ip[(ip[0] & 0x0F) * 4 : struct.unpack_from("!H", ip, 2)[0]]
    version, count = vrrp[0] >> 4, vrrp[3]
    assert vrrp[0] & 0x0F == 1, f"frame {number} is not an advertisement"
    assert len(vrrp) == 8 + 4 * count + (8 if version == 2 else 0), (
        f"frame {number}: VRRP length {len(vrrp)} disagrees with its count"
    )
    got.append(
        (
            socket.inet_ntoa(ip[12:16]),
            socket.inet_ntoa(ip[16:20]),
            version,
            vrrp[1],
            vrrp[2],
            count,
            vrrp[4] if version == 2 else None,
        )
    )
assert got == expected, f"unexpected composition:\n{got}"
print(f"[+] {len(frames)} VRRP adverts, as expected")
PY
)
python3 -c "$COMPOSITION_PY" "$OUT/vrrp.pcap"

echo
echo "[i] Expect zero checksum failures. Fold tests/fixtures/staging/vrrp.pcap"
echo "    into tests/fixtures/."
