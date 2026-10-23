#!/usr/bin/env bash
# Capture an SCTP fixture for the corpus (RFC 9260).
#
#     sudo scripts/capture_fixtures_sctp.sh
#
# One real SCTP association between two netns over a veth pair, from
# usrsctp's example programs (Debian/Ubuntu: libusrsctp-examples): the
# echo_server on one side, the client on the other, sending one line of
# data and then idling long enough for both ends to send a HEARTBEAT
# before closing. The capture holds the whole lifecycle -- INIT, INIT
# ACK, COOKIE ECHO, COOKIE ACK, DATA and SACK each way, HEARTBEAT and
# HEARTBEAT ACK, SHUTDOWN, SHUTDOWN ACK, SHUTDOWN COMPLETE -- as
# Ethernet -> IPv4 (protocol 132) -> SCTP.
#
# usrsctp is a userspace SCTP stack, so this works on kernels built
# without SCTP (no sctp module, socket(..., IPPROTO_SCTP) refused). Run
# without UDP encapsulation, as here, it sends over a raw IPv4 socket
# with IP_HDRINCL: usrsctp builds the IPv4 header and the whole SCTP
# packet, CRC32c included, and the kernel fills in the IPv4 total
# length and header checksum (and the identification, where usrsctp
# leaves it zero).
#
# Real stacks never send an unknown chunk type, so the script then
# sends one SCTP packet of its own, built here with a correct CRC32c:
# a single chunk of unassigned type 63 to the server's port, under a
# verification tag no association uses. It goes out through a raw IPv4
# socket for protocol 132 without IP_HDRINCL, so the kernel builds that
# packet's IPv4 header. To the server it is an out-of-the-blue packet,
# which it discards without reply: the type's high bits say to (RFC
# 9260 §3.2), and usrsctp's example programs set its sctp_blackhole
# sysctl, so they never answer an out-of-the-blue packet with an ABORT
# either (§8.4).
#
# Both directions are captured on the server's side of the veth pair.
# That is sound here, unlike for kernel-checksummed traffic: veth
# offload is disabled first (ethtool -K), and the SCTP checksums are
# computed in userspace either way; check_fixtures.py verifies every
# one, and the IPv4 header checksums.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
USRSCTP=/usr/lib/usrsctp
for program in echo_server client; do
    if [[ ! -x $USRSCTP/$program ]]; then
        echo "$USRSCTP/$program is missing: install libusrsctp-examples." >&2
        exit 1
    fi
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSA=npsca
NSB=npscb
A=npscva
B=npscvb
SERVER_PID=
cleanup() {
    [[ -n $SERVER_PID ]] && kill "$SERVER_PID" 2>/dev/null || true
    ip netns del "$NSA" 2>/dev/null || true
    ip netns del "$NSB" 2>/dev/null || true
    ip link del "$A" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

echo "[*] veth + two netns (A 10.9.10.1 client, B 10.9.10.2 server)"
ip netns add "$NSA"; ip netns add "$NSB"
ip link add "$A" type veth peer name "$B"
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add 10.9.10.1/24 dev "$A"
ip -n "$NSB" addr add 10.9.10.2/24 dev "$B"
ip netns exec "$NSA" ethtool -K "$A" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSB" ethtool -K "$B" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSA" link set lo up; ip -n "$NSA" link set "$A" up
ip -n "$NSB" link set lo up; ip -n "$NSB" link set "$B" up
sleep 1

# One SCTP packet with a single chunk of unassigned type 63 (high bits
# 00: a receiver that does not know it stops and discards the packet,
# RFC 9260 §3.2), its 26-byte value padded to 28.
UNKNOWN_PY=$(cat <<'PY'
import socket
import struct

POLY = 0x82F63B78


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (POLY if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


value = b"NETProtocols unknown chunk"
chunk = struct.pack("!BBH", 63, 0, 4 + len(value)) + value
chunk += bytes(-len(chunk) % 4)
header = struct.pack("!HHI", 40000, 7, 0x4E505354)
crc = crc32c(header + b"\x00" * 4 + chunk)
packet = header + crc.to_bytes(4, "little") + chunk
with socket.socket(socket.AF_INET, socket.SOCK_RAW, 132) as sock:
    sock.sendto(packet, ("10.9.10.2", 0))
PY
)

echo "[>] sctp (usrsctp association, then one unknown-chunk packet)"
ip netns exec "$NSB" tcpdump -i "$B" -w "$OUT/sctp.pcap" --immediate-mode -U -q \
    'ip proto 132' >/dev/null 2>&1 &
tcpdump_pid=$!
sleep 1

ip netns exec "$NSB" "$USRSCTP/echo_server" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 1

# The client sends what it reads from stdin and shuts the association
# down at EOF. usrsctp's default heartbeat interval is 30 s, so holding
# stdin open for 45 s lets both ends send one.
echo "[i] Idling the association 45 s for its heartbeats..."
{ echo "hello sctp"; sleep 45; } |
    ip netns exec "$NSA" timeout 60 "$USRSCTP/client" 10.9.10.2 7 >/dev/null 2>&1 || true
sleep 2

ip netns exec "$NSA" python3 -c "$UNKNOWN_PY"
sleep 1

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=
kill -INT "$tcpdump_pid" 2>/dev/null || true
wait "$tcpdump_pid" 2>/dev/null || true

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
echo "[i] Expect zero checksum failures and 16 SCTP frames: the"
echo "    association's INIT through SHUTDOWN COMPLETE, with a HEARTBEAT /"
echo "    HEARTBEAT ACK pair from each end, then the unknown type-63 chunk"
echo "    (unanswered). Fold tests/fixtures/staging/sctp.pcap into"
echo "    tests/fixtures/."
