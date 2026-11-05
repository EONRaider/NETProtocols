#!/usr/bin/env bash
# Capture IPv4-in-GRE fixtures for the corpus (RFC 2784, RFC 2890).
#
#     sudo scripts/capture_fixtures_gre.sh
#
# GRE tunnels one protocol inside another; a real capture needs an
# actual tunnel. This builds kernel GRE tunnels over veth pairs, each
# between two netns, pings across each overlay, and captures the
# underlay, so each frame is Ethernet -> IPv4 (proto 47) -> GRE -> IPv4
# -> ICMPv4. It writes two captures to tests/fixtures/staging/:
#
#   gre.pcap       2 echoes over a plain tunnel (GRE flags all clear),
#                  then 2 over a keyed tunnel (the RFC 2890 Key field,
#                  0x2a): 8 frames. Netns npgrea and npgreb, underlay
#                  10.9.4.0/24, overlay 10.9.5.0/24.
#   gre_csum.pcap  2 echoes over a checksummed tunnel (`csum`: the
#                  RFC 2784 §2.5 Checksum field, sent and required by
#                  both ends): 4 frames. Netns npgrecsa and npgrecsb,
#                  underlay 10.9.197.0/25, overlay 10.9.197.128/25.
#
# Each gre_csum.pcap frame is asserted, in order, by parsing the pcap
# with the standard library: an echo request from 10.9.197.129 to .130
# over the underlay from 10.9.197.1 to .2, then its reply the other way,
# twice, with ICMP sequence numbers 1 and 2 and one identifier; both
# IPv4 headers are 20 bytes, each Total Length ends its packet, and the
# GRE flags word is exactly 0x8000 (the C bit alone, version 0), with
# Protocol Type 0x0800 and Reserved1 zero. The script stops if anything
# differs. It then runs scripts/check_fixtures.py over
# tests/fixtures/staging/, which verifies the GRE Checksum of every
# frame with the C bit set, peels the GRE header and verifies the inner
# IPv4/ICMP checksums, and stops unless that run passes and reports 4
# GRE checksums for gre_csum.pcap.
#
# veth is a purely local link, so tx/rx checksum offload is disabled on
# each end first (ethtool -K): otherwise the outer checksums are left
# to "offload" and never computed. The gre kernel module autoloads when
# the first tunnel device is created.

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
NSCA=npgrecsa
NSCB=npgrecsb
CA=npgvcsa
CB=npgvcsb
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
    ip netns del "$NSCA" 2>/dev/null || true
    ip netns del "$NSCB" 2>/dev/null || true
    ip link del "$A" 2>/dev/null || true
    ip link del "$CA" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

no6() {
    $1 sysctl -qw net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    $1 sysctl -qw net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
}
offload_off() {  # netns dev
    ip netns exec "$1" ethtool -K "$2" tx off rx off >/dev/null ||
        fail "$2: ethtool could not turn tx/rx checksum offload off."
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1 || true
}
mk_underlay() {  # netns-a netns-b veth-a veth-b cidr-a cidr-b
    ip netns add "$1"; ip netns add "$2"
    no6 "ip netns exec $1"; no6 "ip netns exec $2"
    ip link add "$3" type veth peer name "$4"
    ip link set "$3" netns "$1"
    ip link set "$4" netns "$2"
    ip -n "$1" addr add "$5" dev "$3"
    ip -n "$2" addr add "$6" dev "$4"
    offload_off "$1" "$3"
    offload_off "$2" "$4"
    ip -n "$1" link set lo up; ip -n "$1" link set "$3" up
    ip -n "$2" link set lo up; ip -n "$2" link set "$4" up
}
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
start_capture() {  # netns dev file
    ip netns exec "$1" tcpdump -i "$2" -w "$3" --immediate-mode -U -q \
        ip proto 47 >/dev/null 2>&1 &
    pid=$!
    sleep 1
}
echoes() {  # netns source destination tunnel-name
    ip netns exec "$1" ping -c 2 -i 0.3 -I "$2" "$3" >/dev/null ||
        fail "$4 tunnel: the echoes across it went unanswered."
}

echo "[*] underlay veth + two netns (10.9.4.1 <-> 10.9.4.2)"
no6 ""
mk_underlay "$NSA" "$NSB" "$A" "$B" 10.9.4.1/24 10.9.4.2/24

echo "[>] gre (ICMPv4 echo over a plain and a keyed GRE tunnel)"
start_capture "$NSA" "$A" "$OUT/gre.pcap"

# Plain tunnel (GRE flags all clear).
mk_tunnel "$NSA" 10.9.4.1 10.9.4.2
mk_tunnel "$NSB" 10.9.4.2 10.9.4.1
address_overlay "$NSA" 10.9.5.1/24
address_overlay "$NSB" 10.9.5.2/24
echoes "$NSA" 10.9.5.1 10.9.5.2 plain

# Keyed tunnel (exercises the RFC 2890 key field).
ip -n "$NSA" tunnel del npgre0 2>/dev/null || true
ip -n "$NSB" tunnel del npgre0 2>/dev/null || true
mk_tunnel "$NSA" 10.9.4.1 10.9.4.2 key 0x2a
mk_tunnel "$NSB" 10.9.4.2 10.9.4.1 key 0x2a
address_overlay "$NSA" 10.9.5.1/24
address_overlay "$NSB" 10.9.5.2/24
ip -n "$NSA" neigh flush dev "$A" 2>/dev/null || true
echoes "$NSA" 10.9.5.1 10.9.5.2 keyed

sleep 1
stop_capture

echo "[*] underlay veth + two netns (10.9.197.1 <-> 10.9.197.2)"
mk_underlay "$NSCA" "$NSCB" "$CA" "$CB" 10.9.197.1/25 10.9.197.2/25

echo "[>] gre_csum (ICMPv4 echo over a checksummed GRE tunnel)"
start_capture "$NSCA" "$CA" "$OUT/gre_csum.pcap"

# Checksummed tunnel (exercises the RFC 2784 checksum field).
mk_tunnel "$NSCA" 10.9.197.1 10.9.197.2 csum
mk_tunnel "$NSCB" 10.9.197.2 10.9.197.1 csum
address_overlay "$NSCA" 10.9.197.129/25
address_overlay "$NSCB" 10.9.197.130/25
echoes "$NSCA" 10.9.197.129 10.9.197.130 checksummed

sleep 1
stop_capture

echo "[*] Checking gre_csum.pcap holds exactly the expected frames..."
python3 -I - "$OUT/gre_csum.pcap" <<'PY'
import socket
import struct
import sys

data = open(sys.argv[1], "rb").read()
if len(data) < 24:
    sys.exit("[!] gre_csum.pcap: not a pcap, too short")
endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
frames = []
cursor = 24
while cursor + 16 <= len(data):
    incl = struct.unpack_from(endian + "I", data, cursor + 8)[0]
    frame = data[cursor + 16 : cursor + 16 + incl]
    if len(frame) != incl:
        sys.exit(f"[!] record at byte {cursor} declares {incl} bytes, "
                 f"{len(frame)} remain: truncated capture")
    frames.append(frame)
    cursor += 16 + incl
if cursor != len(data):
    sys.exit(f"[!] {len(data) - cursor} stray bytes after the last record")
if len(frames) != 4:
    sys.exit(f"[!] {len(frames)} frames, expected 4")

UNDERLAY = ("10.9.197.1", "10.9.197.2")
OVERLAY = ("10.9.197.129", "10.9.197.130")


def ipv4(packet, proto):
    """The source, destination and payload of the option-free IPv4
    packet of protocol ``proto`` that ``packet`` holds exactly."""
    if len(packet) < 20 or packet[0] != 0x45 or packet[9] != proto:
        raise ValueError(f"not an option-free IPv4 packet of protocol {proto}")
    if struct.unpack_from("!H", packet, 2)[0] != len(packet):
        raise ValueError("its Total Length does not end the packet")
    return (
        socket.inet_ntoa(packet[12:16]),
        socket.inet_ntoa(packet[16:20]),
        packet[20:],
    )


echo_ids = []
for index, frame in enumerate(frames):
    request = index % 2 == 0
    try:
        if struct.unpack_from("!H", frame, 12)[0] != 0x0800:
            raise ValueError("its EtherType is not IPv4")
        src, dst, gre = ipv4(frame[14:], 47)
        if (src, dst) != (UNDERLAY if request else UNDERLAY[::-1]):
            raise ValueError(f"underlay {src} -> {dst}")
        flags, protocol, _, reserved1 = struct.unpack_from("!HHHH", gre)
        if flags != 0x8000:
            raise ValueError(f"GRE flags word 0x{flags:04x}, not 0x8000")
        if protocol != 0x0800 or reserved1 != 0:
            raise ValueError(
                f"GRE Protocol Type 0x{protocol:04x}, Reserved1 {reserved1}"
            )
        src, dst, icmp = ipv4(gre[8:], 1)
        if (src, dst) != (OVERLAY if request else OVERLAY[::-1]):
            raise ValueError(f"overlay {src} -> {dst}")
        kind, code, _, echo_id, sequence = struct.unpack_from("!BBHHH", icmp)
        if (kind, code) != ((8 if request else 0), 0):
            raise ValueError(f"ICMP type {kind} code {code}")
        if sequence != index // 2 + 1:
            raise ValueError(f"ICMP sequence {sequence}")
    except (ValueError, struct.error) as e:
        sys.exit(f"[!] frame {index}: {e}")
    echo_ids.append(echo_id)
if len(set(echo_ids)) != 1:
    sys.exit(f"[!] the echoes carry identifiers {echo_ids}, expected one")
print("[+] 4 frames, as expected, each with the C bit set.")
PY

echo
echo "[*] Validating..."
CHECKER_PY=$(command -v python3)
run_checker() {
    if [[ -n ${SUDO_USER:-} ]]; then
        sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
    else
        "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
    fi
}
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
fi
status=0
report=$(run_checker) || status=$?
printf '%s\n' "$report"
[[ $status -eq 0 ]] || fail "check_fixtures.py failed (exit $status)."
grep -Eq '^\[OK  \] gre_csum\.pcap: 4 frames \((.*, )?gre-checksumx4[,)]' \
    <<<"$report" ||
    fail "check_fixtures.py did not verify 4 GRE checksums in gre_csum.pcap."

echo
echo "[i] Expect gre and inner ipv4/icmpv4 counts for both captures,"
echo "    gre-checksum for gre_csum.pcap alone, and zero checksum failures."
echo "    Fold tests/fixtures/staging/gre_csum.pcap into tests/fixtures/;"
echo "    tests/fixtures/staging/gre.pcap re-captures tests/fixtures/gre.pcap."
