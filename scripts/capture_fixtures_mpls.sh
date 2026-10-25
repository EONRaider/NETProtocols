#!/usr/bin/env bash
# Capture an MPLS fixture for the corpus (RFC 3032 label stacks).
#
#     sudo scripts/capture_fixtures_mpls.sh
#
# The kernel can neither forward nor encapsulate MPLS without
# CONFIG_MPLS_ROUTING (no /proc/sys/net/mpls), which the capture host
# and many minimal kernels lack, so no daemon or kernel path here sends
# a labelled frame. The capture is built in two steps over one veth
# pair between two netns, A (10.9.60.1) and B (10.9.60.2):
#
#   1. The kernel sends real IPv4 traffic from A to B: two ICMP echo
#      requests (ping) and two UDP datagrams to a listener on B, one of
#      2 bytes of payload and one longer. tcpdump on B captures them
#      inbound, offload off, so every IPv4 header and ICMP/UDP checksum
#      in them is the kernel's.
#   2. scripts/mpls_fixture_packets.py, in A, builds an Ethernet header
#      and an MPLS label stack in front of each of those datagrams (see
#      its PLAN) and sends the frames whole through an AF_PACKET socket;
#      tcpdump on B captures them as tests/fixtures/staging/mpls.pcap.
#      The script then reads the capture back and checks that every
#      frame arrived byte for byte as built.
#
# The eight frames: one label carrying IPv4; two labels carrying IPv4
# (UDP); three labels with distinct traffic classes carrying IPv4; an
# Entropy Label Indicator and an entropy label (RFC 6790) carrying IPv4;
# an IPv4 Explicit NULL bottom label carrying the short UDP datagram,
# zero padded to Ethernet's 60-byte minimum by the script; an IPv6
# Explicit NULL bottom label carrying an IPv6 UDP datagram the script
# builds and checksums itself (the host has IPv6 disabled); EtherType
# 0x8848 to a multicast MAC (RFC 5332 §4) carrying IPv4; and an
# Ethernet pseudowire, a control word (RFC 4448 §4.6) then the kernel's
# first whole frame. The capture must hold exactly those, or the script
# stops with an error; whatever was captured by then is left in
# tests/fixtures/staging for inspection and must not be folded in.
#
# veth is a purely local link, so tx/rx offload is disabled first
# (ethtool -K) to keep every checksum computed in software.

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
PACKETS="scripts/mpls_fixture_packets.py"
NSA=npmplsa
NSB=npmplsb
A=npmplsva
B=npmplsvb
WORK=""
TCPDUMP_PID=""
LISTENER_PID=""
stop_tcpdump() {
    if [[ -n $TCPDUMP_PID ]]; then
        kill -INT "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
        TCPDUMP_PID=""
    fi
}
cleanup() {
    # Stop the capture and the listener first: both run inside the
    # netns that are deleted next.
    stop_tcpdump
    if [[ -n $LISTENER_PID ]]; then
        kill "$LISTENER_PID" 2>/dev/null || true
        wait "$LISTENER_PID" 2>/dev/null || true
        LISTENER_PID=""
    fi
    ip netns del "$NSA" 2>/dev/null || true
    ip netns del "$NSB" 2>/dev/null || true
    ip link del "$A" 2>/dev/null || true
    [[ -z $WORK ]] || rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
fail() { echo "[!] $*" >&2; exit 1; }
WORK=$(mktemp -d)

no6() {
    ip netns exec "$1" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    ip netns exec "$1" sysctl -qw net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
}

echo "[*] veth + two netns (A 10.9.60.1, B 10.9.60.2)"
ip netns add "$NSA"; ip netns add "$NSB"
no6 "$NSA"; no6 "$NSB"
ip link add "$A" address 02:00:0a:09:3c:01 type veth \
    peer name "$B" address 02:00:0a:09:3c:02
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add 10.9.60.1/24 dev "$A"
ip -n "$NSB" addr add 10.9.60.2/24 dev "$B"
ip netns exec "$NSA" ethtool -K "$A" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSB" ethtool -K "$B" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSA" link set lo up; ip -n "$NSA" link set "$A" up
ip -n "$NSB" link set lo up; ip -n "$NSB" link set "$B" up
# A static neighbour entry each way, so no ARP exchange lands between
# the datagrams the plan counts on.
ip -n "$NSA" neigh add 10.9.60.2 lladdr 02:00:0a:09:3c:02 dev "$A"
ip -n "$NSB" neigh add 10.9.60.1 lladdr 02:00:0a:09:3c:01 dev "$B"
sleep 1

echo "[>] step 1: the kernel's IPv4 datagrams, captured inbound on B"
ip netns exec "$NSB" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.9.60.2", 9999))
s.settimeout(10)
s.recv(2048)
s.recv(2048)
' &
LISTENER_PID=$!
ip netns exec "$NSB" tcpdump -i "$B" -Q in -w "$WORK/inner.pcap" --immediate-mode -U -q \
    'ip and src host 10.9.60.1 and (icmp or udp port 9999)' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
ip netns exec "$NSA" ping -c 2 -i 0.3 10.9.60.2 >/dev/null ||
    fail "the echoes from A to B went unanswered."
ip netns exec "$NSA" python3 -c '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.9.60.1", 40000))
s.sendto(b"NP", ("10.9.60.2", 9999))
time.sleep(0.3)
s.sendto(b"NETProtocols MPLS fixture: a kernel-built UDP datagram",
         ("10.9.60.2", 9999))
'
wait "$LISTENER_PID" || fail "the UDP datagrams did not reach the listener."
LISTENER_PID=""
sleep 1
stop_tcpdump

echo "[>] step 2: the labelled frames, built in A, captured on B"
ip netns exec "$NSB" tcpdump -i "$B" -w "$OUT/mpls.pcap" --immediate-mode -U -q \
    'ether proto 0x8847 or ether proto 0x8848' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
ip netns exec "$NSA" python3 "$PACKETS" send "$WORK/inner.pcap" "$A" "$WORK/mpls.sent"
sleep 1
stop_tcpdump
python3 "$PACKETS" compare "$OUT/mpls.pcap" "$WORK/mpls.sent" ||
    fail "the captured frames differ from the frames the script built."

echo "[*] Checking the capture holds exactly the expected frames..."
python3 - "$OUT/mpls.pcap" <<'PY'
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
    ethertype = struct.unpack_from("!H", frame, 12)[0]
    offset, labels = 14, []
    while offset + 4 <= len(frame):
        word = struct.unpack_from("!I", frame, offset)[0]
        labels.append(word >> 12)
        offset += 4
        if word & 0x100:
            break
    else:
        sys.exit("a frame's label stack has no bottom entry")
    payload = frame[offset:]
    if payload[:4] == bytes(2) + b"\x00\x01":
        kind = "pw:" + {1: "icmp", 17: "udp"}.get(payload[4 + 14 + 9], "?")
    elif payload[0] >> 4 == 4:
        kind = "ipv4:" + {1: "icmp", 17: "udp"}.get(payload[9], "?")
    elif payload[0] >> 4 == 6:
        kind = "ipv6:" + {17: "udp"}.get(payload[6], "?")
    else:
        kind = "other"
    seen[(hex(ethertype), tuple(labels), kind)] += 1
if cursor != len(data):
    sys.exit(f"{len(data) - cursor} stray bytes after the last record")
expected = Counter({
    ("0x8847", (0x12345,), "ipv4:icmp"): 1,
    ("0x8847", (16001, 16002), "ipv4:udp"): 1,
    ("0x8847", (16001, 16002, 16003), "ipv4:icmp"): 1,
    ("0x8847", (16001, 7, 0xABCDE), "ipv4:icmp"): 1,
    ("0x8847", (16001, 0), "ipv4:udp"): 1,
    ("0x8847", (16001, 2), "ipv6:udp"): 1,
    ("0x8848", (0x54321,), "ipv4:icmp"): 1,
    ("0x8847", (16001, 0x23456), "pw:icmp"): 1,
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
echo "[i] Expect 8 MPLS frames (mpls-stack x8) and zero checksum failures."
echo "    Fold tests/fixtures/staging/mpls.pcap into tests/fixtures/."
