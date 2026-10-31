#!/usr/bin/env bash
# Capture a RADIUS fixture for the corpus (RFC 2865, RFC 2866, RFC 3579,
# RFC 5997).
#
#     sudo scripts/capture_fixtures_radius.sh
#
# A FreeRADIUS 3 server in one netns and radclient in another, a veth
# pair apart, exchange six requests on UDP 1812 (authentication) and
# 1813 (accounting), one at a time, each waiting for its answer:
#
#   pap-accept   Access-Request, PAP, the right password (User-Name,
#                User-Password, NAS-IP-Address, NAS-Port), answered by
#                an Access-Accept carrying a Framed-IP-Address
#   pap-reject   the same with a wrong password, answered by an
#                Access-Reject (after FreeRADIUS's 1-second reject delay)
#   chap-accept  Access-Request, CHAP (RFC 2865 §5.3, the Request
#                Authenticator as the challenge), the right password,
#                answered by an Access-Accept
#   acct-start   Accounting-Request, Acct-Status-Type Start (RFC 2866),
#                answered by an Accounting-Response
#   acct-stop    Accounting-Request, Acct-Status-Type Stop, with session
#                time and octet and packet counters, answered by an
#                Accounting-Response
#   status       Status-Server (RFC 5997), with the Message-Authenticator
#                it requires, answered by an Access-Accept
#
# radclient 3.2.5 adds a Message-Authenticator (RFC 3579 §3.2) to every
# Access-Request and Status-Server it sends, and FreeRADIUS 3.2.5 to
# every Access-Accept and Access-Reject (both the BlastRADIUS
# hardening), so every authentication frame here carries one; requests
# without one are built in tests/test_radius.py.
#
# What FreeRADIUS and radclient built: every RADIUS byte, the
# authenticators, the PAP-obfuscated User-Password and the
# Message-Authenticators included. What the kernel built: the UDP
# header and its checksum (offload is off on both veth ends, so it is
# computed), the IPv4 header and the Ethernet header. Both directions
# are captured on the server's side of the pair.
#
# The shared secret, the user's password and the wrong one are test
# values, published in tests/fixtures/MANIFEST.md, so that
# tests/test_radius.py can verify every authenticator independently,
# and check_fixtures.py those one frame holds (an Accounting-Request's
# Request Authenticator, a request's Message-Authenticator). The script never touches /etc/freeradius:
# it copies the configuration tree to a scratch directory, drops the EAP
# module (it needs certificates the package does not ship) and the
# inner-tunnel site, writes a minimal site of its own, adds the client
# and the user there, and runs `freeradius -X -d <copy>` in the
# foreground.
#
# The script asserts the composition exactly, frame by frame: sender,
# ports, Code, Identifier pairing and which attributes each frame
# carries, and stops otherwise.

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
NSS=np193-srv
NSC=np193-cli
S=v193s
C=v193c
SERVER=10.9.193.1
CLIENT=10.9.193.2
#: The test values published in tests/fixtures/MANIFEST.md.
SECRET=np193-radius-secret
USER=np193-user
PASSWORD=np193-pass
WRONG=np193-wrong

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

echo "[*] veth + two netns (server $SERVER, client $CLIENT)"
ip netns del "$NSS" 2>/dev/null || true
ip netns del "$NSC" 2>/dev/null || true
ip netns add "$NSS"; ip netns add "$NSC"
ip link add "$S" address 02:00:0a:09:c1:01 type veth \
    peer name "$C" address 02:00:0a:09:c1:02
ip link set "$S" netns "$NSS"
ip link set "$C" netns "$NSC"
ip -n "$NSS" addr add "$SERVER/24" dev "$S"
ip -n "$NSC" addr add "$CLIENT/24" dev "$C"
for pair in "$NSS $S" "$NSC $C"; do
    set -- $pair
    ip netns exec "$1" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 \
        >/dev/null 2>&1 || true
    ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off \
        >/dev/null 2>&1 || true
    ip -n "$1" link set lo up
    ip -n "$1" link set "$2" up
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

client np193 {
	ipaddr = $CLIENT
	secret = $SECRET
	require_message_authenticator = no
}
EOF
{
    echo "$USER	Cleartext-Password := \"$PASSWORD\""
    echo "	Framed-IP-Address = 10.9.193.50,"
    echo "	Reply-Message = \"np193 test user\""
    echo
    cat "$RADDB/mods-config/files/authorize"
} >"$WORK/authorize"
mv "$WORK/authorize" "$RADDB/mods-config/files/authorize"
cat >"$RADDB/sites-enabled/np193" <<EOF
server np193 {
	listen {
		type = auth
		ipaddr = $SERVER
		port = 1812
	}
	listen {
		type = acct
		ipaddr = $SERVER
		port = 1813
	}
	authorize {
		preprocess
		chap
		files
		pap
	}
	authenticate {
		Auth-Type PAP {
			pap
		}
		Auth-Type CHAP {
			chap
		}
	}
	preacct {
		preprocess
		acct_unique
	}
	accounting {
		detail
	}
	post-auth {
		Post-Auth-Type REJECT {
			attr_filter.access_reject
		}
	}
}
EOF

ip netns exec "$NSS" tcpdump -i "$S" -w "$WORK/radius.pcap" \
    --immediate-mode -U -q 'udp port 1812 or udp port 1813' \
    >/dev/null 2>&1 &
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

send() {  # name command port attributes
    echo "[>] radius: $1"
    # One try each (-r 1) with a timeout past the reject delay, so no
    # request is retransmitted into the capture.
    printf '%s\n' "$4" | ip netns exec "$NSC" \
        radclient -r 1 -t 5 "$SERVER:$3" "$2" "$SECRET" >"$WORK/$1.out" 2>&1 \
        || true
    sed 's/^/      /' "$WORK/$1.out"
}

send pap-accept auth 1812 "User-Name = \"$USER\", \
User-Password = \"$PASSWORD\", NAS-IP-Address = $CLIENT, NAS-Port = 7"
send pap-reject auth 1812 "User-Name = \"$USER\", \
User-Password = \"$WRONG\", NAS-IP-Address = $CLIENT, NAS-Port = 7"
send chap-accept auth 1812 "User-Name = \"$USER\", \
CHAP-Password = \"$PASSWORD\", NAS-IP-Address = $CLIENT, NAS-Port = 7"
send acct-start acct 1813 "Acct-Status-Type = Start, \
Acct-Session-Id = \"np193-0001\", User-Name = \"$USER\", \
NAS-IP-Address = $CLIENT, NAS-Port = 7, Framed-IP-Address = 10.9.193.50"
send acct-stop acct 1813 "Acct-Status-Type = Stop, \
Acct-Session-Id = \"np193-0001\", User-Name = \"$USER\", \
NAS-IP-Address = $CLIENT, NAS-Port = 7, Framed-IP-Address = 10.9.193.50, \
Acct-Session-Time = 42, Acct-Input-Octets = 1234, \
Acct-Output-Octets = 5678, Acct-Input-Packets = 12, \
Acct-Output-Packets = 34, Acct-Terminate-Cause = User-Request"
send status status 1812 "Message-Authenticator = 0x00"

sleep 1
kill -0 "$RADIUSD_PID" 2>/dev/null || fail "FreeRADIUS exited early."
stop "$RADIUSD_PID"; RADIUSD_PID=
kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=

echo "[*] Checking the capture's composition..."
python3 - "$WORK/radius.pcap" "$OUT/radius.pcap" <<'PY'
import struct
import sys
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])
SERVER, CLIENT = bytes([10, 9, 193, 1]), bytes([10, 9, 193, 2])

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
    """(from server, server port, code, identifier, attribute types) of
    one frame, read independently of netprotocols."""
    ihl = (frame[14] & 0x0F) * 4
    ip, udp = frame[14:], frame[14 + ihl :]
    if ip[9] != 17:
        sys.exit("a captured frame is not UDP")
    sport, dport, ulen = struct.unpack_from("!HHH", udp)
    radius = udp[8:ulen]
    code, identifier, length = struct.unpack_from("!BBH", radius)
    if length != len(radius):
        sys.exit(f"RADIUS Length {length} is not the datagram's {len(radius)}")
    types, offset = [], 20
    while offset < length:
        types.append(radius[offset])
        offset += radius[offset + 1]
    if offset != length:
        sys.exit("the attributes overrun the RADIUS Length")
    from_server = ip[12:16] == SERVER
    if (ip[12:16], ip[16:20]) not in ((SERVER, CLIENT), (CLIENT, SERVER)):
        sys.exit("a frame between unexpected addresses")
    port = sport if from_server else dport
    return from_server, port, code, identifier, sorted(set(types))


#: Per frame: from the server?, its port, Code, and the attribute types
#: it carries (sorted, distinct). 1 User-Name, 2 User-Password, 3
#: CHAP-Password, 4 NAS-IP-Address, 5 NAS-Port, 8 Framed-IP-Address, 18
#: Reply-Message, 40 Acct-Status-Type, 42/43 Acct-Input/Output-Octets, 44
#: Acct-Session-Id, 46 Acct-Session-Time, 47/48 Acct-Input/Output-
#: Packets, 49 Acct-Terminate-Cause, 80 Message-Authenticator.
REQUEST = [1, 2, 4, 5, 80]
START = [1, 4, 5, 8, 40, 44]
STOP = [1, 4, 5, 8, 40, 42, 43, 44, 46, 47, 48, 49]
EXPECTED = [
    (False, 1812, 1, REQUEST),
    (True, 1812, 2, [8, 18, 80]),
    (False, 1812, 1, REQUEST),
    (True, 1812, 3, [18, 80]),
    (False, 1812, 1, [1, 3, 4, 5, 80]),
    (True, 1812, 2, [8, 18, 80]),
    (False, 1813, 4, START),
    (True, 1813, 5, []),
    (False, 1813, 4, STOP),
    (True, 1813, 5, []),
    (False, 1812, 12, [80]),
    (True, 1812, 2, [80]),
]
seen = [describe(frame) for frame in records]
got = [(f, p, c, t) for f, p, c, _, t in seen]
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
echo "[i] Expect radius x12, radius-accounting-authenticator x2 and"
echo "    radius-message-authenticator x4 verified, and zero failures. Fold"
echo "    tests/fixtures/staging/radius.pcap into tests/fixtures/."
