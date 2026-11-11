#!/usr/bin/env bash
# Capture a two-interface pcapng fixture for read_packets().
#
#     sudo scripts/capture_fixtures_pcapng_interfaces.sh
#
# dumpcap captures two interfaces into one pcapng file, writing an
# Interface Description Block for each, with its if_name option, and
# an Enhanced Packet Block per frame that names its interface by
# index. This builds two netns joined by a veth pair (npifa0 in
# npifcapa, 10.9.72.1/30; npifb0 in npifcapb, 10.9.72.2/30) and runs
# `dumpcap -i lo -i npifa0` in npifcapa while npifcapa pings, one echo
# at a time, its own loopback (127.0.0.1) and its veth peer, twice
# each: lo, veth, lo, veth. It writes
#
#   tests/fixtures/staging/interfaces.pcapng   8 frames: interface 0
#       (lo) carries frames 0, 1, 4 and 5, interface 1 (npifa0) frames
#       2, 3, 6 and 7, each an ICMPv4 echo request then its reply.
#
# Both netns run with IPv6 off, both veth ends have fixed MAC addresses
# and permanent neighbor entries for each other, so no ARP, NDP or MLD
# frame is sent, and a capture filter of `icmp` on each interface keeps
# anything else out. tx/rx checksum offload is disabled on each veth
# end (ethtool -K), so the kernel computes every checksum.
#
# The capture is then checked with the standard library alone: one
# Section Header Block, exactly two Interface Description Blocks, of
# link type Ethernet and named lo and npifa0 in that order, and eight
# Enhanced Packet Blocks whose interface IDs, IPv4 addresses, ICMP types
# and sequence numbers are the ones above, each IPv4 header and ICMP
# checksum verifying. scripts/check_fixtures.py reads classic pcap
# only, so it does not read this file.
#
# Every echo must be answered, and the capture must hold exactly the
# sections, interfaces and frames above, with no Simple Packet Block,
# or the script stops with an error. Whatever
# was captured by then is left in tests/fixtures/staging for inspection
# and must not be folded in.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and dumpcap." >&2
    exit 1
fi
for tool in ip dumpcap ping python3 ethtool; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
FILE="$OUT/interfaces.pcapng"
mkdir -p "$OUT"
NSA=npifcapa
NSB=npifcapb
A=npifa0
B=npifb0
MAC_A=02:00:0a:09:48:01
MAC_B=02:00:0a:09:48:02
pid=""

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
    ip netns del "$NSA" 2>/dev/null || true
    ip netns del "$NSB" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

no6() {  # netns; a kernel without IPv6 has nothing to turn off
    ip netns exec "$1" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 \
        >/dev/null 2>&1 || true
    ip netns exec "$1" sysctl -qw net.ipv6.conf.default.disable_ipv6=1 \
        >/dev/null 2>&1 || true
}
offload_off() {  # netns dev
    ip netns exec "$1" ethtool -K "$2" tx off rx off >/dev/null ||
        fail "$2: ethtool could not turn tx/rx checksum offload off."
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1 || true
}

echo "[*] veth + two netns (10.9.72.1 <-> 10.9.72.2)"
ip netns add "$NSA"
ip netns add "$NSB"
no6 "$NSA"
no6 "$NSB"
ip link add "$A" netns "$NSA" address "$MAC_A" type veth \
    peer name "$B" netns "$NSB" address "$MAC_B"
ip -n "$NSA" addr add 10.9.72.1/30 dev "$A"
ip -n "$NSB" addr add 10.9.72.2/30 dev "$B"
offload_off "$NSA" "$A"
offload_off "$NSB" "$B"
ip -n "$NSA" link set lo up
ip -n "$NSB" link set lo up
ip -n "$NSA" link set "$A" up
ip -n "$NSB" link set "$B" up
ip -n "$NSA" neigh replace 10.9.72.2 lladdr "$MAC_B" dev "$A" nud permanent
ip -n "$NSB" neigh replace 10.9.72.1 lladdr "$MAC_A" dev "$B" nud permanent

echo "[>] dumpcap -i lo -i $A (pcapng)"
rm -f "$FILE"
ip netns exec "$NSA" dumpcap -q -i lo -f icmp -i "$A" -f icmp \
    -w "$FILE" >/dev/null 2>&1 &
pid=$!
for _ in $(seq 50); do
    [[ -s $FILE ]] && break
    sleep 0.1
done
[[ -s $FILE ]] || fail "dumpcap did not start writing $FILE."
sleep 1

for target in 127.0.0.1 10.9.72.2 127.0.0.1 10.9.72.2; do
    ip netns exec "$NSA" ping -c 1 -W 2 "$target" >/dev/null ||
        fail "the echo to $target went unanswered."
    sleep 0.3
done

sleep 1
stop_capture

echo "[*] Checking interfaces.pcapng holds exactly the expected frames..."
python3 -I - "$FILE" <<'PY'
import socket
import struct
import sys

data = open(sys.argv[1], "rb").read()
if data[:4] != b"\x0a\x0d\x0d\x0a":
    sys.exit("[!] not a pcapng: no Section Header Block first")
endian = "<" if data[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
sections = 0
interfaces = []
packets = []
cursor = 0
while cursor < len(data):
    block_type, block_len = struct.unpack_from(endian + "II", data, cursor)
    if block_len < 12 or cursor + block_len > len(data):
        sys.exit(f"[!] block at byte {cursor}: bad length {block_len}")
    trailing = struct.unpack_from(endian + "I", data, cursor + block_len - 4)
    if trailing[0] != block_len:
        sys.exit(f"[!] block at byte {cursor}: trailing length differs")
    body = data[cursor + 8 : cursor + block_len - 4]
    if block_type == 0x0A0D0D0A:
        sections += 1
    elif block_type == 1:
        linktype = struct.unpack_from(endian + "H", body)[0]
        name = None
        offset = 8
        while offset + 4 <= len(body):
            code, length = struct.unpack_from(endian + "HH", body, offset)
            if code == 0:
                break
            if code == 2 and name is None:
                name = body[offset + 4 : offset + 4 + length].decode()
            offset += 4 + length + (-length % 4)
        interfaces.append((linktype, name))
    elif block_type == 6:
        interface_id, _, _, captured = struct.unpack_from(
            endian + "IIII", body
        )
        packets.append((interface_id, body[20 : 20 + captured]))
    elif block_type == 3:
        sys.exit("[!] unexpected Simple Packet Block")
    cursor += block_len

if sections != 1:
    sys.exit(f"[!] {sections} sections, expected 1")
if interfaces != [(1, "lo"), (1, "npifa0")]:
    sys.exit(f"[!] interfaces {interfaces}, expected Ethernet lo, npifa0")
if len(packets) != 8:
    sys.exit(f"[!] {len(packets)} packets, expected 8")


def checksum_ok(octets):
    """Whether the ones' complement sum of ``octets``, the checksum
    field among them, is 0xFFFF (RFC 1071)."""
    if len(octets) % 2:
        octets += b"\x00"
    total = sum(struct.unpack(f"!{len(octets) // 2}H", octets))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


PEERS = {0: ("127.0.0.1", "127.0.0.1"), 1: ("10.9.72.1", "10.9.72.2")}
for index, (interface_id, frame) in enumerate(packets):
    expected_id = (index // 2) % 2
    request = index % 2 == 0
    try:
        if interface_id != expected_id:
            raise ValueError(f"interface {interface_id}, not {expected_id}")
        if struct.unpack_from("!H", frame, 12)[0] != 0x0800:
            raise ValueError("its EtherType is not IPv4")
        packet = frame[14:]
        if len(packet) < 20 or packet[0] != 0x45 or packet[9] != 1:
            raise ValueError("not an option-free IPv4 ICMP packet")
        if struct.unpack_from("!H", packet, 2)[0] != len(packet):
            raise ValueError("its Total Length does not end the packet")
        if not checksum_ok(packet[:20]):
            raise ValueError("its IPv4 header checksum does not verify")
        src = socket.inet_ntoa(packet[12:16])
        dst = socket.inet_ntoa(packet[16:20])
        local, peer = PEERS[interface_id]
        if (src, dst) != ((local, peer) if request else (peer, local)):
            raise ValueError(f"{src} -> {dst}")
        icmp = packet[20:]
        kind, code, _, echo_id, sequence = struct.unpack_from("!BBHHH", icmp)
        if (kind, code) != ((8 if request else 0), 0) or sequence != 1:
            raise ValueError(f"ICMP type {kind} code {code} seq {sequence}")
        if not checksum_ok(icmp):
            raise ValueError("its ICMP checksum does not verify")
    except (ValueError, struct.error) as e:
        sys.exit(f"[!] packet {index}: {e}")
print("[+] 8 packets on lo and npifa0, as expected, checksums valid.")
PY

if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
fi

echo
echo "[i] Fold tests/fixtures/staging/interfaces.pcapng into"
echo "    tests/fixtures/pcapng/."
