#!/usr/bin/env bash
# Capture the IPv4 fragment-reassembly fixtures for
# netprotocols.reassembly.
#
#     sudo scripts/capture_fixtures_reassembly.sh
#
# Builds two netns joined by a veth pair (nprasv in npras, the server,
# 10.9.79.1/24; npracv in nprac, the client, 10.9.79.2/24), with fixed
# MAC addresses, permanent neighbor entries on both ends, and tx/rx
# checksum offload, TSO, GSO and GRO off on both veth ends, so the
# kernel computes every checksum and fragments every datagram itself.
# The link's MTU is veth's default, 1500. It writes two captures to
# tests/fixtures/staging/reassembly/:
#
#   ipv4_udp_fragments.pcap  the client's inbound fragments: a
#       4000-byte UDP datagram the server's kernel fragments (python3
#       sendto() from 10.9.79.1:4000 to 10.9.79.2:4001), then
#       dnsmasq's answers to two `dig +bufsize=4096` TXT queries, each
#       a DNS message over the 1232 bytes of dig's default buffer.
#   linux_overlaps.pcap  ICMP echo requests cut into fragments by the
#       python3 program below, overlapping or duplicated on purpose,
#       sent from the client with an AF_PACKET socket, and the server's
#       echo replies, both directions on the server's veth end. The
#       running kernel reassembles each train or discards it. Its
#       reassembly counters in the server's netns (/proc/net/snmp
#       ReasmReqds, ReasmOKs and ReasmFails, /proc/net/netstat
#       ReasmOverlaps), read before and after each train, say which:
#       their differences are written, one row per train, to
#       linux_overlaps.counters beside the capture. A reply carries the
#       reassembled data back when it is a valid echo request; a train
#       whose bytes break the ICMP checksum gets no reply even when it
#       is reassembled, so the counters, not the replies, show a
#       discard. The trains are listed in the program and in
#       tests/fixtures/MANIFEST.md.
#
# The first keeps only fragments (BPF: a nonzero MF flag or Fragment
# Offset), so the DNS queries, the ICMP port unreachable the 4000-byte
# datagram draws and every other frame stay out. The second keeps ICMP
# echo requests and replies, fragments included, and nothing else.
#
# Each capture is checked by scripts/check_fixtures.py, then by tshark,
# which must report three datagrams reassembled in
# ipv4_udp_fragments.pcap, and echo replies in linux_overlaps.pcap for
# exactly the trains the kernel is expected to reassemble, 2, 3 and 5,
# whose ReasmOKs must each rise by 1, while trains 1 and 4 leave
# ReasmOKs unchanged and raise ReasmOverlaps.
# Any other outcome stops the script with an error, and whatever was
# captured by then is left in the staging directory for inspection and
# must not be folded in.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump dnsmasq dig python3 ethtool tshark; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging/reassembly"
mkdir -p "$OUT"
NSS=npras
NSC=nprac
S=nprasv
C=npracv
MAC_S=02:00:0a:09:4f:01
MAC_C=02:00:0a:09:4f:02
pid=""
dnsmasq_pid=""

fail() {
    echo "[!] $*" >&2
    exit 1
}
stop_capture() {
    [[ -n $pid ]] || return 0
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    pid=""
}
cleanup() {
    stop_capture
    if [[ -n $dnsmasq_pid ]]; then
        kill "$dnsmasq_pid" 2>/dev/null || true
    fi
    ip netns del "$NSS" 2>/dev/null || true
    ip netns del "$NSC" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

offload_off() {  # netns dev
    ip netns exec "$1" ethtool -K "$2" tx off rx off >/dev/null ||
        fail "$2: ethtool could not turn tx/rx checksum offload off."
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1 || true
}
start_capture() {  # netns dev file filter
    rm -f "$3"
    ip netns exec "$1" tcpdump -i "$2" -w "$3" --immediate-mode -U -q \
        "$4" >/dev/null 2>&1 &
    pid=$!
    sleep 1
}

echo "[*] veth + two netns (server 10.9.79.1, client 10.9.79.2)"
ip netns add "$NSS"
ip netns add "$NSC"
ip link add "$S" netns "$NSS" address "$MAC_S" type veth \
    peer name "$C" netns "$NSC" address "$MAC_C"
ip -n "$NSS" addr add 10.9.79.1/24 dev "$S"
ip -n "$NSC" addr add 10.9.79.2/24 dev "$C"
offload_off "$NSS" "$S"
offload_off "$NSC" "$C"
ip -n "$NSS" link set lo up
ip -n "$NSC" link set lo up
ip -n "$NSS" link set "$S" up
ip -n "$NSC" link set "$C" up
ip -n "$NSS" neigh replace 10.9.79.2 lladdr "$MAC_C" dev "$S" nud permanent
ip -n "$NSC" neigh replace 10.9.79.1 lladdr "$MAC_S" dev "$C" nud permanent
sleep 1

echo "[>] dnsmasq answering TXT queries for big.reassembly.test"
TXT=""
for letter in a b c d e f g h i j; do
    chunk=$(printf "%0.s$letter" $(seq 250))
    TXT="$TXT,\"$chunk\""
done
ip netns exec "$NSS" dnsmasq --no-daemon --no-resolv --no-hosts \
    --interface="$S" --bind-interfaces --except-interface=lo \
    --edns-packet-max=4096 --local-ttl=300 \
    --txt-record="big.reassembly.test$TXT" \
    --pid-file=/tmp/np-dnsmasq-reassembly.pid >/dev/null 2>&1 &
dnsmasq_pid=$!
sleep 1

echo "[>] ipv4_udp_fragments.pcap"
start_capture "$NSC" "$C" "$OUT/ipv4_udp_fragments.pcap" \
    'ip and ip[6:2] & 0x3fff != 0'
ip netns exec "$NSS" python3 -I - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("10.9.79.1", 4000))
    sock.sendto(bytes(range(256)) * 15 + bytes(range(160)), ("10.9.79.2", 4001))
PY
sleep 0.3
for _ in 1 2; do
    ip netns exec "$NSC" dig +bufsize=4096 +tries=1 +time=3 @10.9.79.1 \
        big.reassembly.test TXT >/dev/null || fail "dig failed."
    sleep 0.3
done
sleep 1
stop_capture

echo "[>] linux_overlaps.pcap (script-built trains against the kernel)"
start_capture "$NSS" "$S" "$OUT/linux_overlaps.pcap" \
    'icmp[0] == 0 or icmp[0] == 8 or (ip and ip[6:2] & 0x3fff != 0)'
SENDER=$(cat <<'PY'
import socket
import struct
import sys
import time

interface, mac_c, mac_s, number = sys.argv[1:5]
CLIENT, SERVER = "10.9.79.2", "10.9.79.1"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def echo(identifier, data):
    """An ICMP echo request, its checksum over ``data``."""
    total = checksum(struct.pack("!BBHHH", 8, 0, 0, identifier, 1) + data)
    return struct.pack("!BBHHH", 8, 0, total, identifier, 1) + data


def fragment(identification, offset, more, data):
    """An Ethernet frame holding one fragment, offset in bytes."""
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(data),
        identification,
        (0x2000 if more else 0) | offset // 8,
        64,
        1,
        0,
        socket.inet_aton(CLIENT),
        socket.inet_aton(SERVER),
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    ethernet = bytes.fromhex(mac_s.replace(":", "") + mac_c.replace(":", ""))
    return ethernet + b"\x08\x00" + header + data


# The fragment pattern of Suricata's DefragSturgesNovak* tests: offset,
# fill letter and length; Q, at 176, is the last.
PATTERN = [
    (0, "A", 24), (32, "B", 16), (48, "C", 24), (80, "D", 8),
    (104, "E", 16), (120, "F", 24), (144, "G", 16), (160, "H", 16),
    (176, "I", 8), (8, "J", 32), (48, "K", 24), (72, "L", 24),
    (96, "M", 24), (128, "N", 8), (152, "O", 8), (160, "P", 8),
    (176, "Q", 16),
]


def pattern(message, identification, count):
    """The first ``count`` fragments of PATTERN, the first 8 bytes of
    the fragment at 0 replaced by ``message``'s echo header."""
    frames = []
    for offset, letter, length in PATTERN[:count]:
        data = letter.encode() * length
        if offset == 0:
            data = message[:8] + data[8:]
        frames.append(fragment(identification, offset, letter != "Q", data))
    return frames


def train(message, identification, pieces, last):
    """``message`` cut at the (offset, end) pairs ``pieces``; the piece
    ending at ``last`` has MF clear."""
    return [
        fragment(identification, offset, end != last, message[offset:end])
        for offset, end in pieces
    ]


clean = echo(0x4F02, bytes(range(184)))
held = echo(0x4F03, bytes(range(56)))
differing = held[:16] + b"\xee" * 8 + held[24:]
TRAINS = [
    # 1, ID 0x7901: the whole pattern.
    pattern(echo(0x4F01, b"x" * 184), 0x7901, 17),
    # 2, ID 0x7902: the pattern's first ten fragments, through J, then
    # a clean train of the same ID in three fragments.
    pattern(clean, 0x7902, 10)
    + train(clean, 0x7902, [(0, 64), (64, 128), (128, 192)], 192),
    # 3, ID 0x7903: two fragments in order, then one inside them whose
    # last 8 bytes differ, then the last.
    train(held, 0x7903, [(0, 24), (24, 48)], 64)
    + train(differing, 0x7903, [(8, 24)], 64)
    + train(held, 0x7903, [(48, 64)], 64),
    # 4, ID 0x7904: a fragment overlapping the first in part, with
    # equal bytes, then the last.
    train(echo(0x4F04, bytes(range(56))), 0x7904, [(0, 24), (16, 40), (40, 64)], 64),
    # 5, ID 0x7905: an exact duplicate of the first fragment.
    train(echo(0x4F05, bytes(range(40))), 0x7905, [(0, 24), (0, 24), (24, 48)], 48),
]
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
    sock.bind((interface, 0))
    for frame in TRAINS[int(number) - 1]:
        sock.send(frame)
        time.sleep(0.05)
PY
)
reasm_counters() {  # ReasmReqds ReasmOKs ReasmFails ReasmOverlaps, server netns
    ip netns exec "$NSS" python3 -I -c '
def table(path, prefix):
    rows = [line.split() for line in open(path) if line.startswith(prefix)]
    return dict(zip(rows[0][1:], map(int, rows[1][1:])))
ip = table("/proc/net/snmp", "Ip:")
ext = table("/proc/net/netstat", "IpExt:")
print(ip["ReasmReqds"], ip["ReasmOKs"], ip["ReasmFails"], ext["ReasmOverlaps"])'
}
COUNTERS="$OUT/linux_overlaps.counters"
printf 'train\tReasmReqds\tReasmOKs\tReasmFails\tReasmOverlaps\n' >"$COUNTERS"
for train in 1 2 3 4 5; do
    read -r reqds0 oks0 fails0 overlaps0 < <(reasm_counters)
    ip netns exec "$NSC" python3 -I -c "$SENDER" "$C" "$MAC_C" "$MAC_S" "$train"
    sleep 0.5
    read -r reqds1 oks1 fails1 overlaps1 < <(reasm_counters)
    printf '%s\t%s\t%s\t%s\t%s\n' "$train" $((reqds1 - reqds0)) \
        $((oks1 - oks0)) $((fails1 - fails0)) $((overlaps1 - overlaps0)) \
        >>"$COUNTERS"
done
sleep 1
stop_capture

echo "[*] Checking checksums..."
python3 -I scripts/check_fixtures.py "$OUT" ||
    fail "check_fixtures.py rejected a capture."

echo "[*] Checking tshark's reassembly..."
found=$(tshark -2 -r "$OUT/ipv4_udp_fragments.pcap" -T fields \
    -e ip.reassembled_in 2>/dev/null | sort -un | grep -c .) || true
[[ $found -eq 3 ]] ||
    fail "ipv4_udp_fragments.pcap: tshark reassembled $found datagrams, not 3."
replies=$(tshark -r "$OUT/linux_overlaps.pcap" -Y 'icmp.type == 0' \
    -T fields -e icmp.ident 2>/dev/null | tr '\n' ' ')
[[ $replies == "20226 20227 20229 " ]] ||
    fail "linux_overlaps.pcap: echo replies for identifiers '$replies'."
echo "[*] Checking the kernel's reassembly counters..."
cat "$COUNTERS"
oks=$(awk 'NR > 1 {printf "%s ", $3}' "$COUNTERS")
[[ $oks == "0 1 1 0 1 " ]] ||
    fail "linux_overlaps.counters: ReasmOKs rose by '$oks', not 0 1 1 0 1."
overlaps=$(awk 'NR > 1 {printf "%s ", ($5 > 0)}' "$COUNTERS")
[[ $overlaps == "1 1 0 1 0 " ]] ||
    fail "linux_overlaps.counters: ReasmOverlaps rose for '$overlaps'."

if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
fi

echo
echo "[i] Fold tests/fixtures/staging/reassembly/*.pcap into"
echo "    tests/fixtures/reassembly/."
