#!/usr/bin/env bash
# Capture an NTP control message (mode 6) fixture for the corpus
# (RFC 9327).
#
#     sudo scripts/capture_fixtures_ntp_control.sh
#
# ntpd (ntpsec) runs in one netns (10.9.172.1) and ntpq queries it from
# another (10.9.172.2), over a veth pair, on UDP port 123. The server
# has two associations, the LOCAL refclock and an unreachable server at
# the client's address, so that a read status response lists two. Seven
# ntpq runs follow one another, each captured to its own scratch file:
#
#   rv        "rv": read variables, association 0, no names: the
#             server's default system variables in one response
#   as        "as": read status, association 0: the association IDs
#             and peer status words, binary
#   version   "rv 0 version": a read status, then a read variables
#             naming one variable
#   unknown   "rv 0 nosuchvar": a read status, then a read variables
#             naming a variable the server does not have, answered by
#             an error response (E bit, error code 5)
#   peer      "rv &1": a read status, then a read variables for the
#             first association, answered in two fragments, the first
#             with the M bit set
#   md5       ":config logconfig =syncall" authenticated with key 3,
#             MD5: request and response both end in a 20-byte MAC
#   sha1      the same with key 4, SHA-1, which the server does not
#             accept as its control key: an error response (error code
#             1, authentication failure) that still ends in a 24-byte MAC
#
# ntpd runs with "disable ntp" and "disable kernel", so it never
# adjusts the system clock. Its keys, configuration, pid and drift
# files live in a scratch directory, and nothing outside it, the two
# netns and the veth pair is created or changed. The only configuration
# ntpd applies at runtime is the log mask the md5 run sets.
#
# The script keeps every mode 6 datagram of every run and asserts the
# selection exactly, by sender, opcode, R, E and M bits and the length
# of the MAC, and stops otherwise. It checks each header against what
# ntpq printed during the run: the status words, association IDs and
# variables ntpq shows are the ones the responses carry.
#
# What the daemons built: every NTP byte, MACs included. What the
# kernel built: the UDP header and its checksum (offload is off on both
# veth ends, so it is computed), the IPv4 header and the Ethernet
# header. Both directions are captured on 10.9.172.1's side of the
# pair. The keys are test keys, published in tests/fixtures/MANIFEST.md,
# so that check_fixtures.py can verify every MAC independently.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool ntpd ntpq; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
echo "[*] $(ntpd --version 2>&1 | head -n 1)"

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
WORK=$(mktemp -d)
NSA=np272-s
NSB=np272-c
A=v272s
B=v272c
SERVER_IP=10.9.172.1
CLIENT_IP=10.9.172.2
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

echo "[*] veth + two netns (server $SERVER_IP, client $CLIENT_IP)"
ip netns del "$NSA" 2>/dev/null || true
ip netns del "$NSB" 2>/dev/null || true
ip netns add "$NSA"; ip netns add "$NSB"
ip link add "$A" address 02:00:0a:09:ac:01 type veth \
    peer name "$B" address 02:00:0a:09:ac:02
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add "$SERVER_IP/24" dev "$A"
ip -n "$NSB" addr add "$CLIENT_IP/24" dev "$B"
for pair in "$NSA $A" "$NSB $B"; do
    read -r ns dev <<<"$pair"
    ip netns exec "$ns" ethtool -K "$dev" tx off rx off tso off gso off \
        gro off >/dev/null 2>&1 || true
    ip -n "$ns" link set lo up
    ip -n "$ns" link set "$dev" up
done
sleep 1

# The test keys, published in MANIFEST.md. Key 3 is the control key.
cat >"$WORK/ntp.keys" <<'KEYS'
3 MD5 np272-md5-key
4 SHA1 np272-sha1-key
KEYS
chmod 600 "$WORK/ntp.keys"

cat >"$WORK/ntp.conf" <<CONF
driftfile $WORK/ntp.drift
keys $WORK/ntp.keys
trustedkey 3 4
controlkey 3
disable ntp
disable kernel
refclock local stratum 8
server $CLIENT_IP
restrict $CLIENT_IP
CONF

ip netns exec "$NSA" ntpd -n -c "$WORK/ntp.conf" -p "$WORK/ntp.pid" \
    -l "$WORK/ntpd.log" >/dev/null 2>&1 &
SERVER_PID=$!
sleep 3
kill -0 "$SERVER_PID" 2>/dev/null || fail "ntpd exited: $(cat "$WORK/ntpd.log")"

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

ntpq_run() {  # name ntpq-argument...
    local name=$1
    shift
    echo "[>] ntp control: $name"
    capture_start "$name"
    timeout 20 ip netns exec "$NSB" ntpq -n "$@" "$SERVER_IP" \
        >"$WORK/$name.txt" 2>&1 || fail "$name: ntpq failed."
    capture_stop
    sed 's/^/    /' "$WORK/$name.txt"
}

ntpq_run rv -c rv
ntpq_run as -c as
ntpq_run version -c 'rv 0 version'
ntpq_run unknown -c 'rv 0 nosuchvar'
ntpq_run peer -c 'rv &1'
ntpq_run md5 -a 3 -k "$WORK/ntp.keys" -c ':config logconfig =syncall'
ntpq_run sha1 -a 4 -k "$WORK/ntp.keys" -c ':config logconfig =syncall'
stop "$SERVER_PID"; SERVER_PID=

echo "[*] Selecting and checking the fixture frames..."
python3 - "$WORK" "$OUT/ntp_control.pcap" <<'PY'
import hashlib
import hmac
import re
import struct
import sys
from pathlib import Path

work, out = Path(sys.argv[1]), Path(sys.argv[2])
NAMES = {bytes([10, 9, 172, 1]): "A", bytes([10, 9, 172, 2]): "B"}
KEYS = {3: ("md5", b"np272-md5-key"), 4: ("sha1", b"np272-sha1-key")}
RUNS = ("rv", "as", "version", "unknown", "peer", "md5", "sha1")


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


def control(frame):
    """The sender and the mode 6 message of one frame, read
    independently of netprotocols, or None for another mode."""
    ihl = (frame[14] & 0x0F) * 4
    ip, udp = frame[14:], frame[14 + ihl :]
    if ip[9] != 17 or 123 not in struct.unpack_from("!HH", udp):
        sys.exit("a captured frame is not UDP to or from port 123")
    message = udp[8 : struct.unpack_from("!H", udp, 4)[0]]
    if message[0] & 7 != 6:
        return None
    return NAMES[ip[12:16]], message


def fields(message):
    """(opcode, R, E, M, sequence, status, association, offset, data,
    MAC length): the MAC follows the data padded to 8 bytes, or, in an
    error response, the 12-byte header."""
    flags, seq, status, assoc, offset, count = struct.unpack_from(
        "!xBHHHHH", message
    )
    error = flags & 0x40
    if len(message) < 12 + count:
        sys.exit("a control message's Count runs past its datagram")
    start = 12 if error else (12 + count + 7) & ~7
    mac = len(message) - start if len(message) > start + 3 else 0
    if not mac and len(message) != (12 + count + 3) & ~3:
        sys.exit("a control message without a MAC is not padded to 4")
    if mac:
        key_id = struct.unpack_from("!I", message, start)[0]
        algorithm, key = KEYS[key_id]
        digest = hashlib.new(
            algorithm, key + message[:start], usedforsecurity=False
        ).digest()
        if not hmac.compare_digest(digest, message[start + 4 :]):
            sys.exit(f"a control message's {algorithm} MAC does not verify")
    return (
        flags & 0x1F,
        flags >> 7,
        error >> 6,
        (flags >> 5) & 1,
        seq,
        status,
        assoc,
        offset,
        message[12 : 12 + count],
        mac,
    )


header, selected = None, []
for name in RUNS:
    for pcap_header, record in records(work / f"{name}.pcap"):
        found = control(record[16:])
        if found is not None:
            header = header or pcap_header
            selected.append((name, found[0], fields(found[1]), record))

expected = [
    ("rv", "B", 2, 0, 0, 0, 0),
    ("rv", "A", 2, 1, 0, 0, 0),
    ("as", "B", 1, 0, 0, 0, 0),
    ("as", "A", 1, 1, 0, 0, 0),
    ("version", "B", 1, 0, 0, 0, 0),
    ("version", "A", 1, 1, 0, 0, 0),
    ("version", "B", 2, 0, 0, 0, 0),
    ("version", "A", 2, 1, 0, 0, 0),
    ("unknown", "B", 1, 0, 0, 0, 0),
    ("unknown", "A", 1, 1, 0, 0, 0),
    ("unknown", "B", 2, 0, 0, 0, 0),
    ("unknown", "A", 2, 1, 1, 0, 0),
    ("peer", "B", 1, 0, 0, 0, 0),
    ("peer", "A", 1, 1, 0, 0, 0),
    ("peer", "B", 2, 0, 0, 0, 0),
    ("peer", "A", 2, 1, 0, 1, 0),
    ("peer", "A", 2, 1, 0, 0, 0),
    ("md5", "B", 8, 0, 0, 0, 20),
    ("md5", "A", 8, 1, 0, 0, 20),
    ("sha1", "B", 8, 0, 0, 0, 24),
    ("sha1", "A", 8, 1, 1, 0, 24),
]
seen = [(name, who, *f[:4], f[9]) for name, who, f, _ in selected]
if seen != expected:
    sys.exit(f"[!] Unexpected selection: {seen}, expected {expected}")


def text(name):
    return (work / f"{name}.txt").read_text()


def check(condition, what):
    if not condition:
        sys.exit(f"[!] {what}")


by_run = {}
for name, _, f, _ in selected:
    by_run.setdefault(name, []).append(f)
# Every response carries its request's sequence number (RFC 9327 §2).
for name, run in by_run.items():
    for request, response in zip(run[0::2], run[1::2]):
        check(request[4] == response[4], f"{name}: sequence mismatch")
status = re.search(r"associd=0 status=([0-9a-f]{4})", text("rv"))
check(status is not None, "rv: ntpq printed no system status")
rv = by_run["rv"][1]
check(rv[5] == int(status[1], 16), "rv: status differs from ntpq's")
version = re.search(r'version="([^"]*)"', text("rv"))[1]
check(f'version="{version}"'.encode() in rv[8], "rv: version not in data")
rows = re.findall(r"^\s*\d+\s+(\d+)\s+([0-9a-f]{4})\s", text("as"), re.M)
pairs = struct.unpack(f"!{len(by_run['as'][1][8]) // 2}H", by_run["as"][1][8])
# ntpq sorts the list by association ID; ntpd sends it newest first.
listed = sorted(zip(pairs[0::2], pairs[1::2]))
check(
    [(int(a), int(s, 16)) for a, s in rows] == listed,
    "as: association list differs from ntpq's",
)
check(len(rows) == 2, "as: expected two associations")
check(text("version").strip() == f'version="{version}"', "version: ntpq")
check(
    by_run["version"][3][8].rstrip(b"\r\n") == f'version="{version}"'.encode(),
    "version: data differs from ntpq's",
)
check("UNKNOWNVAR" in text("unknown"), "unknown: ntpq printed no UNKNOWNVAR")
check(by_run["unknown"][3][5] >> 8 == 5, "unknown: error code is not 5")
peer = re.search(r"associd=(\d+) status=([0-9a-f]{4})", text("peer"))
first, last = by_run["peer"][3], by_run["peer"][4]
check(int(peer[1]) == int(rows[0][0]) == first[6] == last[6], "peer: assoc")
check(int(peer[2], 16) == first[5] == last[5], "peer: status")
check(last[7] == len(first[8]), "peer: second fragment offset")
check("Config Succeeded" in text("md5"), "md5: ntpq printed no success")
check("PERMISSION" in text("sha1"), "sha1: ntpq printed no PERMISSION")
check(by_run["sha1"][1][5] >> 8 == 1, "sha1: error code is not 1")
out.write_bytes(header + b"".join(record for *_, record in selected))
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
echo "[i] Expect udp + ntp-control counts, ntp-control-md5 and"
echo "    ntp-control-sha1 MACs verified, and zero failures. Fold"
echo "    tests/fixtures/staging/ntp_control.pcap into tests/fixtures/."
