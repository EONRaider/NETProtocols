#!/usr/bin/env bash
# Capture an NTP fixture for the corpus (RFC 5905, RFC 1305, RFC 7822,
# RFC 8915).
#
#     sudo scripts/capture_fixtures_ntp.sh
#
# chronyd serves time from one netns (10.9.191.1, "local stratum 8")
# and NTP clients query it from another (10.9.191.2), over a veth pair,
# on UDP port 123. Eight scenarios run in turn, each captured to its
# own scratch file:
#
#   sntp       ntpdig (ntpsec) asks once: NTPv4 client and server
#              (modes 3 and 4), the plain 48-byte header
#   md5        ntpdig with symmetric key 1, MD5: both packets end in a
#              20-byte MAC (Key ID, then a 16-byte digest)
#   sha1       ntpdig with symmetric key 2, SHA-1: a 24-byte MAC
#   v3         chronyd as a client with "version 3": NTPv3 (RFC 1305),
#              which the server answers in kind
#   extfield   chronyd as a client with "extfield F323": an NTPv4
#              extension field (RFC 7822) each way, chrony's
#              experimental type 0xF323
#   nts        chronyd as a client with "nts": Network Time Security
#              (RFC 8915) extension fields, a Unique Identifier, an NTS
#              Cookie and an NTS Authenticator, after an NTS-KE
#              handshake over TCP 4460 that the capture filter leaves
#              out; the certificate is a throwaway, made here
#   symmetric  chronyd as a symmetric active peer of the server, which
#              answers in symmetric passive mode (modes 1 and 2); the
#              peer first unsynchronized, then synchronized to the
#              server, at stratum 9 with the server's address as its
#              Reference ID
#   broadcast  the server restarted with "broadcast": mode 5 to
#              10.9.191.255
#
# Every chronyd runs with -x, so none of them touches the system clock,
# and the clients run with -Q, which only measures; ntpdig is run
# without -s or -S, so it only prints. The server's keys, certificate,
# pid and drift files live in a scratch directory, and nothing outside
# it, the two netns and the veth pair is created or changed.
#
# Each scenario's capture can hold retries and, for the peer and the
# broadcasts, more packets than one; so the fixture keeps a fixed
# selection, which the script asserts exactly, by sender, version,
# mode, stratum and length after the header, and stops otherwise:
# per client scenario the first request and the server's answer to it
# (its Origin Timestamp is the request's Transmit Timestamp, RFC 5905
# §8); in the symmetric one the first active packet at stratum 0 and
# the first at stratum 9, each with its answer; and the first
# broadcast.
#
# What the daemons built: every NTP byte, the MACs, extension fields
# and NTS cookies included. What the kernel built: the UDP header and
# its checksum (offload is off on both veth ends, so it is computed),
# the IPv4 header and the Ethernet header. Both directions are
# captured on 10.9.191.1's side of the pair. The symmetric keys are
# test keys, published in tests/fixtures/MANIFEST.md, so that
# check_fixtures.py can verify every MAC independently.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool chronyd ntpdig openssl; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
echo "[*] $(chronyd -v 2>&1 | head -n 1)"

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
WORK=$(mktemp -d)
NSA=np191-a
NSB=np191-b
A=v191a
B=v191b
SERVER_IP=10.9.191.1
TCPDUMP_PID=
SERVER_PID=
stop() {  # pid
    [[ -n $1 ]] || return 0
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}
cleanup() {
    stop "$SERVER_PID"; SERVER_PID=
    stop "$TCPDUMP_PID"; TCPDUMP_PID=
    ip netns del "$NSA" 2>/dev/null || true
    ip netns del "$NSB" 2>/dev/null || true
    ip link del "$A" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "[!] $*" >&2; exit 1; }

echo "[*] veth + two netns (server 10.9.191.1, client 10.9.191.2)"
ip netns del "$NSA" 2>/dev/null || true
ip netns del "$NSB" 2>/dev/null || true
ip netns add "$NSA"; ip netns add "$NSB"
ip link add "$A" address 02:00:0a:09:bf:01 type veth \
    peer name "$B" address 02:00:0a:09:bf:02
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add 10.9.191.1/24 brd 10.9.191.255 dev "$A"
ip -n "$NSB" addr add 10.9.191.2/24 brd 10.9.191.255 dev "$B"
for pair in "$NSA $A" "$NSB $B"; do
    set -- $pair
    ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off \
        >/dev/null 2>&1 || true
    ip -n "$1" link set lo up
    ip -n "$1" link set "$2" up
done
sleep 1

# The symmetric keys, in each implementation's keyfile format: the same
# ASCII keys, published in MANIFEST.md.
cat >"$WORK/chrony.keys" <<'KEYS'
1 MD5 ASCII:np191-md5-key
2 SHA1 ASCII:np191-sha1-key
KEYS
cat >"$WORK/ntpsec.keys" <<'KEYS'
1 MD5 np191-md5-key
2 SHA1 np191-sha1-key
KEYS
chmod 600 "$WORK/chrony.keys" "$WORK/ntpsec.keys"

# A throwaway certificate for NTS-KE, valid for the server's address.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -days 2 -subj "/CN=$SERVER_IP" -addext "subjectAltName=IP:$SERVER_IP" \
    -keyout "$WORK/nts.key" -out "$WORK/nts.crt" >/dev/null 2>&1 ||
    fail "openssl could not make the NTS certificate."

server_start() {  # extra-directive...
    {
        echo 'local stratum 8'
        echo 'allow all'
        echo 'cmdport 0'
        echo "bindcmdaddress $WORK/server.sock"
        echo "pidfile $WORK/server.pid"
        echo "driftfile $WORK/server.drift"
        echo "keyfile $WORK/chrony.keys"
        echo "ntsserverkey $WORK/nts.key"
        echo "ntsservercert $WORK/nts.crt"
        local directive
        for directive in "$@"; do
            echo "$directive"
        done
    } >"$WORK/server.conf"
    ip netns exec "$NSA" chronyd -x -d -u root -f "$WORK/server.conf" \
        >>"$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 2
    kill -0 "$SERVER_PID" 2>/dev/null ||
        fail "chronyd (server) exited: $(cat "$WORK/server.log")"
}
server_stop() { stop "$SERVER_PID"; SERVER_PID=; }

capture_start() {  # name
    ip netns exec "$NSA" tcpdump -i "$A" -w "$WORK/$1.pcap" \
        --immediate-mode -U -q 'udp port 123' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
}
capture_stop() {
    sleep 1
    kill -INT "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    TCPDUMP_PID=
}

ntpdig_scenario() {  # name ntpdig-option...
    local name=$1
    shift
    echo "[>] ntp: $name"
    capture_start "$name"
    ip netns exec "$NSB" ntpdig -t 2 "$@" "$SERVER_IP" ||
        fail "$name: ntpdig got no answer."
    capture_stop
}

chrony_client_scenario() {  # name server-options
    echo "[>] ntp: $1"
    capture_start "$1"
    ip netns exec "$NSB" chronyd -Q -x -u root -t 15 \
        "server $SERVER_IP iburst maxsamples 1 $2" \
        "ntstrustedcerts $WORK/nts.crt" "pidfile $WORK/client.pid" \
        "cmdport 0" >>"$WORK/client.log" 2>&1 ||
        fail "$1: chronyd (client) failed: $(cat "$WORK/client.log")"
    capture_stop
}

server_start
ntpdig_scenario sntp
ntpdig_scenario md5 -a 1 -k "$WORK/ntpsec.keys"
ntpdig_scenario sha1 -a 2 -k "$WORK/ntpsec.keys"
chrony_client_scenario v3 'version 3'
chrony_client_scenario extfield 'extfield F323'
chrony_client_scenario nts 'nts'

echo "[>] ntp: symmetric"
{
    echo "peer $SERVER_IP minpoll 0 maxpoll 0"
    echo 'cmdport 0'
    echo "bindcmdaddress $WORK/peer.sock"
    echo "pidfile $WORK/peer.pid"
} >"$WORK/peer.conf"
capture_start symmetric
# Long enough for the peer to synchronize to the server and say so.
ip netns exec "$NSB" timeout 6 chronyd -x -d -u root -f "$WORK/peer.conf" \
    >>"$WORK/peer.log" 2>&1 || true
capture_stop
server_stop

echo "[>] ntp: broadcast"
server_start "broadcast 2 10.9.191.255"
capture_start broadcast
sleep 3
capture_stop
server_stop

echo "[*] Selecting and checking the fixture frames..."
python3 - "$WORK" "$OUT/ntp.pcap" <<'PY'
import struct
import sys
from pathlib import Path

work, out = Path(sys.argv[1]), Path(sys.argv[2])
NAMES = {bytes([10, 9, 191, 1]): "A", bytes([10, 9, 191, 2]): "B"}


def records(path):
    data = path.read_bytes()
    if data[:4] != b"\xd4\xc3\xb2\xa1":
        sys.exit(f"{path.name}: not a little-endian microsecond pcap")
    cursor = 24
    while cursor + 16 <= len(data):
        incl, orig = struct.unpack_from("<II", data, cursor + 8)
        record = data[cursor : cursor + 16 + incl]
        if len(record) != 16 + incl or incl != orig:
            sys.exit(f"{path.name}: truncated record at byte {cursor}")
        yield data[:24], record
        cursor += 16 + incl
    if cursor != len(data):
        sys.exit(f"{path.name}: {len(data) - cursor} stray bytes")


def describe(frame):
    """(sender, version, mode, stratum, bytes after the 48-byte header,
    Origin Timestamp, Transmit Timestamp, Reference ID) of one frame,
    read independently of netprotocols."""
    ihl = (frame[14] & 0x0F) * 4
    ip, udp = frame[14:], frame[14 + ihl :]
    if ip[9] != 17 or 123 not in struct.unpack_from("!HH", udp):
        sys.exit("a captured frame is not UDP to or from port 123")
    ntp = udp[8 : struct.unpack_from("!H", udp, 4)[0]]
    if len(ntp) < 48:
        sys.exit("a captured NTP message is shorter than its header")
    origin, transmit = struct.unpack_from("!Q8xQ", ntp, 24)
    return (
        NAMES[ip[12:16]],
        (ntp[0] >> 3) & 7,
        ntp[0] & 7,
        ntp[1],
        len(ntp) - 48,
        origin,
        transmit,
        ntp[12:16],
    )


def exchange(frames, request_mode, first=lambda d: True):
    """The first request from B in ``request_mode`` that ``first``
    accepts, and A's answer to it."""
    for _, record in frames:
        request = describe(record[16:])
        sender, mode = request[0], request[2]
        if (sender, mode) == ("B", request_mode) and first(request):
            break
    else:
        sys.exit(f"no mode {request_mode} request captured")
    for _, answer in frames:
        reply = describe(answer[16:])
        if reply[0] == "A" and reply[5] == request[6]:
            return [record, answer]
    sys.exit(f"no answer to the mode {request_mode} request captured")


selected, header = [], None
for name in ("sntp", "md5", "sha1", "v3", "extfield", "nts"):
    frames = list(records(work / f"{name}.pcap"))
    header = header or frames[0][0]
    selected += [(name, r) for r in exchange(frames, 3)]
frames = list(records(work / "symmetric.pcap"))
for synchronized in (False, True):
    pair = exchange(frames, 1, lambda d: (d[3] != 0) == synchronized)
    selected += [("symmetric", r) for r in pair]
for _, record in records(work / "broadcast.pcap"):
    if describe(record[16:])[2] == 5:
        selected.append(("broadcast", record))
        break
else:
    sys.exit("broadcast: no mode 5 packet captured")

expected = [
    ("sntp", "B", 4, 3, 0, 0),
    ("sntp", "A", 4, 4, 8, 0),
    ("md5", "B", 4, 3, 0, 20),
    ("md5", "A", 4, 4, 8, 20),
    ("sha1", "B", 4, 3, 0, 24),
    ("sha1", "A", 4, 4, 8, 24),
    ("v3", "B", 3, 3, 0, 0),
    ("v3", "A", 3, 4, 8, 0),
    ("extfield", "B", 4, 3, 0, 28),
    ("extfield", "A", 4, 4, 8, 28),
    ("nts", "B", 4, 3, 0, 140),
    ("nts", "A", 4, 4, 8, 140),
    ("symmetric", "B", 4, 1, 0, 0),
    ("symmetric", "A", 4, 2, 8, 0),
    ("symmetric", "B", 4, 1, 9, 0),
    ("symmetric", "A", 4, 2, 8, 0),
    ("broadcast", "A", 4, 5, 8, 0),
]
seen = [(name, *describe(r[16:])[:5]) for name, r in selected]
if seen != expected:
    sys.exit(f"[!] Unexpected selection: {seen}, expected {expected}")
# The synchronized peer names the server as its reference (RFC 5905 §7.3).
if describe(selected[14][1][16:])[7] != bytes([10, 9, 191, 1]):
    sys.exit("[!] The stratum 9 peer does not name 10.9.191.1 as reference")
out.write_bytes(header + b"".join(record for _, record in selected))
print(f"[+] {len(selected)} frames, as expected.")
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
echo "[i] Expect udp + ntp counts, ntp-md5 and ntp-sha1 MACs verified, and"
echo "    zero failures. Fold tests/fixtures/staging/ntp.pcap into"
echo "    tests/fixtures/."
