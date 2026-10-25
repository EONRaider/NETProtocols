#!/usr/bin/env bash
# Capture a PIM-SM fixture for the corpus (RFC 7761).
#
#     sudo scripts/capture_fixtures_pim.sh
#
# Two FRR routers (zebra + pimd, FRR 8.4) between a multicast source and
# a receiver, four netns in a line over three veth pairs:
#
#     nppim-src --- nppim-r1 ===== nppim-r2 --- nppim-rcv
#     10.184.1.2    .1.1  .12.1    .12.2  .2.1  10.184.2.2
#
# The R1-R2 link also carries a secondary address on R1 (10.184.13.1),
# so R1's Hellos carry an Address List option (RFC 7761 §4.3.4). Two
# groups use static RPs on opposite routers, so both kinds of tree
# cross the captured link:
#
# * 239.184.0.1 has its RP on R2. R1, the source's DR, encapsulates the
#   source's first packets in Registers to R2; R2 joins the (S,G)
#   shortest-path tree towards R1 and answers with a Register-Stop. With
#   a short Register-Suppression time, R1 later probes R2 with a
#   Null-Register (§4.4.1), which R2 answers with another Register-Stop.
# * 239.184.0.2 has its RP on R1, so R2 sends the (*,G) Join (WC and RPT
#   bits) across the link, then an (S,G) Join when it switches to the
#   shortest-path tree.
#
# The receiver joins both groups (IGMPv3, from a socket with
# IP_ADD_MEMBERSHIP), the source sends to both, then the receiver leaves
# and R2 prunes what it had joined. Finally R2's pimd is stopped, which
# sends a Hello with Holdtime 0 (§4.3.1).
#
# tcpdump on R1's side of the R1-R2 link captures `ip proto 103`. Hello
# (30 s) and Join/Prune (60 s) timers, and the order in which the two
# groups' events interleave, vary from run to run, so the script keeps
# one frame of each kind it needs (the first, in capture order) and
# asserts that every kind was seen; the committed fixture is that
# selection, written by this script.
#
# pimd builds every PIM message, its checksum included (over the whole
# message, or over the first 8 bytes for a Register, RFC 7761 §4.9.3),
# and the outer IPv4 header too: FRR 8.4's pim_msg_send() fills in the
# identification, TOS, TTL, total length and addresses and sends with
# IP_HDRINCL (IPPROTO_RAW for Registers), so the kernel fills in only
# the header checksum and total length, as it always does for such a
# socket. The Register's encapsulated packet is the source's
# UDP datagram as R1 received it, its IPv4 header and UDP checksum
# built by the source's kernel. veth offloads are off on every link,
# and check_fixtures.py verifies every checksum, the encapsulated
# packet's included.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
FRR=/usr/lib/frr
for daemon in zebra pimd; do
    [[ -x $FRR/$daemon ]] || { echo "$FRR/$daemon is missing: install frr." >&2; exit 1; }
done
id frr >/dev/null 2>&1 || { echo "FRR's frr user is missing." >&2; exit 1; }

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
RAW="$OUT/pim-raw.pcap"
NAMESPACES=(nppim-src nppim-r1 nppim-r2 nppim-rcv)
# FRR's daemons run as the frr user, so their state lives where it can
# write: one directory per router under FRR's own run directory.
STATE=/var/run/frr
TCPDUMP_PID=
RECEIVER_PID=
cleanup() {
    [[ -n $RECEIVER_PID ]] && kill "$RECEIVER_PID" 2>/dev/null || true
    [[ -n $TCPDUMP_PID ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
    for ns in "${NAMESPACES[@]}"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    done
    sleep 1
    for ns in "${NAMESPACES[@]}"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$STATE/nppim-r1" "$STATE/nppim-r2"
}
trap cleanup EXIT
cleanup

echo "[*] Four netns over three veth pairs"
for ns in "${NAMESPACES[@]}"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done
veth() {  # veth <ns-a> <if-a> <ns-b> <if-b>
    ip link add "$2" type veth peer name "$4"
    ip link set "$2" netns "$1"
    ip link set "$4" netns "$3"
    ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
    ip netns exec "$3" ethtool -K "$4" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
    ip -n "$1" link set "$2" up
    ip -n "$3" link set "$4" up
}
veth nppim-src nppim-sv nppim-r1 nppim-r1a
veth nppim-r1 nppim-r1b nppim-r2 nppim-r2a
veth nppim-r2 nppim-r2b nppim-rcv nppim-rv
ip -n nppim-src addr add 10.184.1.2/24 dev nppim-sv
ip -n nppim-r1 addr add 10.184.1.1/24 dev nppim-r1a
ip -n nppim-r1 addr add 10.184.12.1/24 dev nppim-r1b
ip -n nppim-r1 addr add 10.184.13.1/24 dev nppim-r1b
ip -n nppim-r2 addr add 10.184.12.2/24 dev nppim-r2a
ip -n nppim-r2 addr add 10.184.2.1/24 dev nppim-r2b
ip -n nppim-rcv addr add 10.184.2.2/24 dev nppim-rv
ip -n nppim-src route add default via 10.184.1.1
ip -n nppim-rcv route add default via 10.184.2.1
ip -n nppim-r1 route add 10.184.2.0/24 via 10.184.12.2
ip -n nppim-r2 route add 10.184.1.0/24 via 10.184.12.1
for ns in nppim-r1 nppim-r2; do
    ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
    # Reverse-path filtering would drop multicast arriving on an
    # interface the kernel would not route the source back through.
    for conf in all default; do
        ip netns exec "$ns" sysctl -qw "net.ipv4.conf.$conf.rp_filter=0"
    done
done
for ifname in nppim-r1a nppim-r1b; do
    ip netns exec nppim-r1 sysctl -qw "net.ipv4.conf.$ifname.rp_filter=0"
done
for ifname in nppim-r2a nppim-r2b; do
    ip netns exec nppim-r2 sysctl -qw "net.ipv4.conf.$ifname.rp_filter=0"
done

ip netns exec nppim-r1 tcpdump -i nppim-r1b -w "$RAW" --immediate-mode -U -q \
    'ip proto 103' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "[*] zebra + pimd on R1 and R2"
start_router() {  # start_router <n> <interface>...
    local n=$1 dir=$STATE/nppim-r$1
    shift
    mkdir -p "$dir"
    {
        echo "hostname nppim-r$n"
        # RP for 239.184.0.1 is R2, for 239.184.0.2 R1.
        echo "ip pim rp 10.184.12.2 239.184.0.1/32"
        echo "ip pim rp 10.184.12.1 239.184.0.2/32"
        # Short enough for a Null-Register probe within the capture.
        echo "ip pim register-suppress-time 15"
        for ifname in "$@"; do
            echo "interface $ifname"
            echo " ip pim"
        done
        [[ $n == 2 ]] && { echo "interface nppim-r2b"; echo " ip igmp"; }
    } >"$dir/pimd.conf"
    echo "hostname nppim-r$n" >"$dir/zebra.conf"
    chown -R frr:frr "$dir"
    ip netns exec "nppim-r$n" "$FRR/zebra" -d -N "nppim-r$n" -P 0 \
        -f "$dir/zebra.conf" -i "$dir/zebra.pid" -z "$dir/zserv.api" \
        --vty_socket "$dir" >/dev/null 2>&1
    sleep 1
    ip netns exec "nppim-r$n" "$FRR/pimd" -d -N "nppim-r$n" -P 0 \
        -f "$dir/pimd.conf" -i "$dir/pimd.pid" -z "$dir/zserv.api" \
        --vty_socket "$dir" >/dev/null 2>&1
}
start_router 1 nppim-r1a nppim-r1b
start_router 2 nppim-r2a nppim-r2b
echo "[i] Waiting 10 s for the routers to become neighbours..."
sleep 10

echo "[>] Receiver joins 239.184.0.1 and 239.184.0.2 for 45 s"
ip netns exec nppim-rcv python3 -c '
import socket, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for group in ("239.184.0.1", "239.184.0.2"):
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                    socket.inet_aton(group) + socket.inet_aton("10.184.2.2"))
time.sleep(45)
' &
RECEIVER_PID=$!
sleep 5

echo "[>] Source sends to both groups once a second for 35 s"
ip netns exec nppim-src python3 -c '
import socket, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 16)
for number in range(35):
    for group in ("239.184.0.1", "239.184.0.2"):
        sock.sendto(b"NETProtocols PIM %02d" % number, (group, 5000))
    time.sleep(1)
'
# The receiver leaves when its socket closes, and R2 prunes.
wait "$RECEIVER_PID"
RECEIVER_PID=
sleep 10

echo "[>] Stopping R2's pimd (a Hello with Holdtime 0)"
kill "$(cat "$STATE/nppim-r2/pimd.pid")"
sleep 3
kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=

echo
echo "[*] Selecting one frame of each kind"
SELECT_PY=$(cat <<'PY'
import struct
import sys

R1, R2 = bytes([10, 184, 12, 1]), bytes([10, 184, 12, 2])
G1, G2 = bytes([239, 184, 0, 1]), bytes([239, 184, 0, 2])
SOURCE = bytes([10, 184, 1, 2])

raw = open(sys.argv[1], "rb").read()
assert raw[:4] == b"\xd4\xc3\xb2\xa1", "expected a little-endian classic pcap"
assert struct.unpack_from("<I", raw, 20)[0] == 1, "expected Ethernet framing"
records = []
offset = 24
while offset < len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    records.append(raw[offset : offset + 16 + caplen])
    offset += 16 + caplen


def hello_options(body):
    options, cursor = {}, 0
    while cursor + 4 <= len(body):
        kind, length = struct.unpack_from("!HH", body, cursor)
        options[kind] = body[cursor + 4 : cursor + 4 + length]
        cursor += 4 + length
    return options


def join_prune(body):
    """(group, joined, pruned) per group set; each source a (flags,
    address) pair. Native IPv4 encodings only."""
    assert body[:2] == b"\x01\x00", "upstream neighbour is not native IPv4"
    groups, cursor = [], 10
    for _ in range(body[7]):
        group = body[cursor + 4 : cursor + 8]
        joined, pruned = struct.unpack_from("!HH", body, cursor + 8)
        cursor += 12
        sources = []
        for _ in range(joined + pruned):
            sources.append((body[cursor + 2] & 0x07, body[cursor + 4 : cursor + 8]))
            cursor += 8
        groups.append((group, tuple(sources[:joined]), tuple(sources[joined:])))
    assert cursor == len(body), "Join/Prune has bytes past its group sets"
    return tuple(groups)


def kind_of(frame):
    ip = frame[14:]
    pim = ip[(ip[0] & 0x0F) * 4 : struct.unpack_from("!H", ip, 2)[0]]
    assert pim[0] >> 4 == 2, "not PIMv2"
    msg_type, src, body = pim[0] & 0x0F, ip[12:16], pim[4:]
    if msg_type == 0:
        options = hello_options(body)
        holdtime = struct.unpack("!H", options[1])[0]
        if holdtime == 0:
            return "hello-goodbye" if src == R2 else None
        if src == R1 and 24 in options:
            return "hello-r1-address-list"
        return "hello-r2" if src == R2 else None
    if msg_type == 1:
        null = body[0] & 0x40
        inner_dst = body[20:24]
        if inner_dst != G1:
            return None
        return "null-register" if null else "register"
    if msg_type == 2:
        return "register-stop"
    if msg_type != 3:
        return None
    group_sets = join_prune(body)
    if len(group_sets) != 1:
        # pimd may aggregate several groups into one Join/Prune; every
        # kind below has one group set, so such a message is skipped
        # (WANTED and the composition check still demand each kind).
        return None
    (group, joined, pruned), = group_sets
    WC_RPT, RPT, SPT = 0x07, 0x05, 0x04
    if group == G2 and joined == ((WC_RPT, R1),) and not pruned:
        return "join-star-g2"
    if group == G1 and joined == ((SPT, SOURCE),) and not pruned:
        return "join-s-g1"
    if group == G2 and joined == ((SPT, SOURCE),) and not pruned:
        return "join-s-g2"
    if group == G2 and joined == ((WC_RPT, R1),) and pruned == ((RPT, SOURCE),):
        return "join-star-g2-prune-s-g2-rpt"
    if group == G1 and pruned == ((SPT, SOURCE),) and not joined:
        return "prune-s-g1"
    if group == G2 and pruned == ((WC_RPT, R1),) and not joined:
        return "prune-star-g2"
    if group == G2 and pruned == ((SPT, SOURCE),) and not joined:
        return "prune-s-g2"
    return None


WANTED = [
    "hello-r1-address-list",
    "hello-r2",
    "join-star-g2",
    "register",
    "join-s-g1",
    "join-s-g2",
    "register-stop",
    "null-register",
    "join-star-g2-prune-s-g2-rpt",
    "prune-s-g1",
    "prune-star-g2",
    "prune-s-g2",
    "hello-goodbye",
]
chosen = {}
for record in records:
    kind = kind_of(record[16:])
    if kind is not None and kind not in chosen:
        chosen[kind] = record
missing = [kind for kind in WANTED if kind not in chosen]
assert not missing, f"not captured: {missing} (got {sorted(chosen)})"
# The first Register-Stop answers a data Register, which comes first.
keep = sorted(chosen.values(), key=records.index)
with open(sys.argv[2], "wb") as out:
    out.write(raw[:24])
    out.writelines(keep)
order = [kind_of(record[16:]) for record in keep]
print(f"[+] {len(records)} PIM frames captured, {len(keep)} kept: {order}")
PY
)
python3 -c "$SELECT_PY" "$RAW" "$OUT/pim.pcap"
rm -f "$RAW"

echo
echo "[*] Validating..."
CHECKER_PY=$(command -v python3)
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
else
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
fi

# The selection's composition: 13 frames, by PIM type.
COMPOSITION_PY=$(cat <<'PY'
import struct
import sys
from collections import Counter

raw = open(sys.argv[1], "rb").read()
frames = []
offset = 24
while offset < len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    frames.append(raw[offset + 16 : offset + 16 + caplen])
    offset += 16 + caplen
assert len(frames) == 13, f"expected 13 PIM frames, kept {len(frames)}"
types = []
for number, frame in enumerate(frames, 1):
    ip = frame[14:]
    assert ip[9] == 103, f"frame {number} is not PIM"
    pim = ip[(ip[0] & 0x0F) * 4 :]
    types.append(pim[0] & 0x0F)
# Hello x3, Register x2 (data, null), Register-Stop x1, Join/Prune x7.
assert Counter(types) == Counter({0: 3, 1: 2, 2: 1, 3: 7}), types
print(f"[+] 13 PIM frames, by type: {types}")
PY
)
python3 -c "$COMPOSITION_PY" "$OUT/pim.pcap"

echo
echo "[i] Expect zero checksum failures. Fold tests/fixtures/staging/pim.pcap"
echo "    into tests/fixtures/."
