#!/usr/bin/env bash
# Capture a RADIUS Dynamic Authorization fixture for the corpus (RFC
# 5176, RFC 3579).
#
#     sudo scripts/capture_fixtures_radius_coa.sh
#
# A FreeRADIUS 3 server in one netns, listening as a NAS on UDP 3799
# (`listen { type = coa }`), and radclient in another, a veth pair
# apart, exchange four requests, one at a time, each waiting for its
# answer:
#
#   coa-ack         CoA-Request for the session the NAS holds
#                   (User-Name, Acct-Session-Id, Session-Timeout), with
#                   a Message-Authenticator, answered by a CoA-ACK with
#                   a Message-Authenticator
#   coa-nak         CoA-Request for a session it does not hold, answered
#                   by a CoA-NAK carrying Error-Cause 503
#                   (Session-Context-Not-Found)
#   disconnect-ack  Disconnect-Request for the session it holds, with a
#                   Message-Authenticator, answered by a Disconnect-ACK
#                   with a Message-Authenticator
#   disconnect-nak  Disconnect-Request for a session it does not hold,
#                   answered by a Disconnect-NAK carrying Error-Cause 503
#
# The coa virtual server's recv-coa section, which FreeRADIUS runs for
# both request types, answers ACK, with a Message-Authenticator, for the
# known User-Name and Acct-Session-Id and NAK, with the Error-Cause and
# no Message-Authenticator, for anything else. FreeRADIUS computes each
# reply's Message-Authenticator when it encodes the reply.
#
# What FreeRADIUS and radclient built: every RADIUS byte, the Request
# and Response Authenticators and the Message-Authenticators included.
# What the kernel built: the UDP header and its checksum (offload is
# off on both veth ends, so it is computed), the IPv4 header and the
# Ethernet header. Both directions are captured on the server's side of
# the pair.
#
# The shared secret is the test value published in
# tests/fixtures/MANIFEST.md, the one radius.pcap's client uses, so
# that check_fixtures.py verifies every authenticator with it.
#
# The script never touches /etc/freeradius: it copies the configuration
# tree to a scratch directory, drops the EAP module (it needs
# certificates the package does not ship) and every enabled site,
# writes a coa site of its own, adds the client there, and runs
# `freeradius -X -d <copy>` in the foreground.
#
# The script asserts the composition exactly, frame by frame: sender,
# ports, Code, Identifier pairing, which attributes each frame carries
# and the Error-Cause of each NAK, and stops otherwise.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool freeradius radclient; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
echo "[*] $(freeradius -v 2>&1 | head -1)"

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
WORK=$(mktemp -d)
NSS=npcoa-s
NSC=npcoa-c
S=v237s
C=v237c
SERVER=10.9.237.1
CLIENT=10.9.237.2
#: The test secret published in tests/fixtures/MANIFEST.md.
SECRET=np193-radius-secret
USER=np237-user
SESSION=np237-0001

TCPDUMP_PID=
RADIUSD_PID=
stop() {  # pid
    [[ -n $1 ]] || return 0
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}
cleanup() {
    stop "$RADIUSD_PID"; RADIUSD_PID=
    stop "$TCPDUMP_PID"; TCPDUMP_PID=
    ip netns del "$NSS" 2>/dev/null || true
    ip netns del "$NSC" 2>/dev/null || true
    ip link del "$S" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "[!] $*" >&2; exit 1; }

echo "[*] veth + two netns (NAS $SERVER, client $CLIENT)"
ip netns del "$NSS" 2>/dev/null || true
ip netns del "$NSC" 2>/dev/null || true
ip netns add "$NSS"; ip netns add "$NSC"
ip link add "$S" address 02:00:0a:09:ed:01 type veth \
    peer name "$C" address 02:00:0a:09:ed:02
ip link set "$S" netns "$NSS"
ip link set "$C" netns "$NSC"
ip -n "$NSS" addr add "$SERVER/24" dev "$S"
ip -n "$NSC" addr add "$CLIENT/24" dev "$C"
for pair in "$NSS $S" "$NSC $C"; do
    read -r ns dev <<<"$pair"
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 \
        >/dev/null 2>&1 || true
    ip netns exec "$ns" ethtool -K "$dev" tx off rx off tso off gso off gro off \
        >/dev/null 2>&1 || true
    ip -n "$ns" link set lo up
    ip -n "$ns" link set "$dev" up
done
sleep 1

echo "[*] FreeRADIUS configuration, copied to $WORK/raddb"
RADDB="$WORK/raddb"
cp -a /etc/freeradius/3.0 "$RADDB"
rm -f "$RADDB/mods-enabled/eap" "$RADDB/sites-enabled/"*
mkdir -p "$WORK/log" "$WORK/run"
# Point every path the server writes at the scratch directory, and run
# as root: the copy is root's, and nothing here needs a lesser user.
sed -i \
    -e "s|^raddbdir = .*|raddbdir = $RADDB|" \
    -e "s|^logdir = .*|logdir = $WORK/log|" \
    -e "s|^run_dir = .*|run_dir = $WORK/run|" \
    -e 's|^\(\s*\)user = freerad|\1#user = freerad|' \
    -e 's|^\(\s*\)group = freerad|\1#group = freerad|' \
    "$RADDB/radiusd.conf"
cat >>"$RADDB/clients.conf" <<EOF

client npcoa {
	ipaddr = $CLIENT
	secret = $SECRET
}
EOF
cat >"$RADDB/sites-enabled/npcoa" <<EOF
listen {
	type = coa
	ipaddr = $SERVER
	port = 3799
	virtual_server = npcoa
}
server npcoa {
	recv-coa {
		if (&User-Name == "$USER" && &Acct-Session-Id == "$SESSION") {
			update reply {
				&Message-Authenticator := 0x00
			}
			ok
		}
		else {
			update reply {
				&Error-Cause := Session-Context-Not-Found
			}
			reject
		}
	}
	send-coa {
		ok
	}
}
EOF

ip netns exec "$NSS" tcpdump -i "$S" -w "$WORK/radius_coa.pcap" \
    --immediate-mode -U -q 'udp port 3799' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1
ip netns exec "$NSS" freeradius -X -d "$RADDB" >"$WORK/radiusd.log" 2>&1 &
RADIUSD_PID=$!
for _ in $(seq 50); do
    grep -q "Ready to process requests" "$WORK/radiusd.log" && break
    kill -0 "$RADIUSD_PID" 2>/dev/null || break
    sleep 0.2
done
grep -q "Ready to process requests" "$WORK/radiusd.log" || {
    tail -30 "$WORK/radiusd.log" >&2
    fail "FreeRADIUS did not start."
}

send() {  # name command attributes
    echo "[>] radius: $1"
    # One try each (-r 1), so no request is retransmitted into the
    # capture.
    printf '%s\n' "$3" | ip netns exec "$NSC" \
        radclient -r 1 -t 5 "$SERVER:3799" "$2" "$SECRET" >"$WORK/$1.out" 2>&1 \
        || true
    sed 's/^/      /' "$WORK/$1.out"
}

send coa-ack coa "User-Name = \"$USER\", Acct-Session-Id = \"$SESSION\", \
Session-Timeout = 3600, Message-Authenticator = 0x00"
send coa-nak coa "User-Name = \"np237-gone\", \
Acct-Session-Id = \"np237-0002\", Session-Timeout = 3600"
send disconnect-ack disconnect "User-Name = \"$USER\", \
Acct-Session-Id = \"$SESSION\", Message-Authenticator = 0x00"
send disconnect-nak disconnect "User-Name = \"np237-gone\", \
Acct-Session-Id = \"np237-0002\""

sleep 1
kill -0 "$RADIUSD_PID" 2>/dev/null || fail "FreeRADIUS exited early."
stop "$RADIUSD_PID"; RADIUSD_PID=
kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=

echo "[*] Checking the capture's composition..."
python3 - "$WORK/radius_coa.pcap" "$OUT/radius_coa.pcap" <<'PY'
import struct
import sys
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])
SERVER, CLIENT = bytes([10, 9, 237, 1]), bytes([10, 9, 237, 2])

data = src.read_bytes()
if data[:4] != b"\xd4\xc3\xb2\xa1":
    sys.exit("not a little-endian microsecond pcap")
records, cursor = [], 24
while cursor + 16 <= len(data):
    incl, orig = struct.unpack_from("<II", data, cursor + 8)
    if incl != orig or cursor + 16 + incl > len(data):
        sys.exit(f"truncated record at byte {cursor}")
    records.append(data[cursor + 16 : cursor + 16 + incl])
    cursor += 16 + incl
if cursor != len(data):
    sys.exit(f"{len(data) - cursor} stray bytes")


def describe(frame):
    """(from the NAS, the NAS's port, code, identifier, attribute types,
    Error-Cause values) of one frame, read independently of
    netprotocols."""
    ihl = (frame[14] & 0x0F) * 4
    ip, udp = frame[14:], frame[14 + ihl :]
    if ip[9] != 17:
        sys.exit("a captured frame is not UDP")
    sport, dport, ulen = struct.unpack_from("!HHH", udp)
    radius = udp[8:ulen]
    code, identifier, length = struct.unpack_from("!BBH", radius)
    if length != len(radius):
        sys.exit(f"RADIUS Length {length} is not the datagram's {len(radius)}")
    types, causes, offset = [], [], 20
    while offset < length:
        types.append(radius[offset])
        if radius[offset] == 101:
            causes.extend(struct.unpack_from("!I", radius, offset + 2))
        offset += radius[offset + 1]
    if offset != length:
        sys.exit("the attributes overrun the RADIUS Length")
    from_server = ip[12:16] == SERVER
    if (ip[12:16], ip[16:20]) not in ((SERVER, CLIENT), (CLIENT, SERVER)):
        sys.exit("a frame between unexpected addresses")
    port = sport if from_server else dport
    return from_server, port, code, identifier, sorted(set(types)), causes


#: Per frame: from the NAS?, its port, Code, the attribute types it
#: carries (sorted, distinct) and the Error-Cause (101) values, in wire
#: order. 1 User-Name, 27 Session-Timeout, 44 Acct-Session-Id, 80
#: Message-Authenticator. Codes: 40 Disconnect-Request, 41
#: Disconnect-ACK, 42 Disconnect-NAK, 43 CoA-Request, 44 CoA-ACK, 45
#: CoA-NAK. Error-Cause 503 is Session-Context-Not-Found.
EXPECTED = [
    (False, 3799, 43, [1, 27, 44, 80], []),
    (True, 3799, 44, [80], []),
    (False, 3799, 43, [1, 27, 44], []),
    (True, 3799, 45, [101], [503]),
    (False, 3799, 40, [1, 44, 80], []),
    (True, 3799, 41, [80], []),
    (False, 3799, 40, [1, 44], []),
    (True, 3799, 42, [101], [503]),
]
seen = [describe(frame) for frame in records]
got = [(f, p, c, t, e) for f, p, c, _, t, e in seen]
if got != EXPECTED:
    sys.exit(f"[!] Unexpected capture:\n  {got}\nexpected\n  {EXPECTED}")
for request, response in zip(seen[::2], seen[1::2]):
    if request[3] != response[3]:
        sys.exit("a response's Identifier is not its request's")
out.write_bytes(data)
print(f"[+] {len(records)} frames, as expected.")
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
echo "[i] Expect radius x8, radius-coa-authenticator x2,"
echo "    radius-disconnect-authenticator x2, radius-message-authenticator x2,"
echo "    radius-response-authenticator x4 and"
echo "    radius-reply-message-authenticator x2 verified, and zero failures."
echo "    Fold tests/fixtures/staging/radius_coa.pcap into tests/fixtures/."
