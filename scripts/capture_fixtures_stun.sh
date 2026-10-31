#!/usr/bin/env bash
# Capture a STUN fixture for the corpus (RFC 5389, RFC 8489).
#
#     sudo scripts/capture_fixtures_stun.sh
#
# coturn's turnserver runs in STUN-only mode (--stun-only: every TURN
# request is ignored) in one netns, on 10.9.194.2 port 3478, UDP and
# TCP, with no TLS or DTLS, adding a FINGERPRINT to everything it sends
# (--fingerprint). Clients in a second netns, a veth pair away, run six
# scenarios against it in turn, each in its own tcpdump capture:
#
#   binding   turnutils_stunclient: a Binding Request and its Success
#             Response (XOR-MAPPED-ADDRESS, MAPPED-ADDRESS,
#             RESPONSE-ORIGIN, SOFTWARE, FINGERPRINT).
#   rfc5780   turnutils_stunclient -f: a Binding Request with
#             CHANGE-REQUEST and RESPONSE-PORT (RFC 5780), which a
#             server with one address answers with error 420.
#   unknown   A script-built Binding Request carrying an unknown
#             comprehension-required attribute (0x7FF0) and a
#             FINGERPRINT: error 420 with UNKNOWN-ATTRIBUTES.
#   tcp       Two script-built Binding Requests in one TCP write, the
#             first with SOFTWARE and FINGERPRINT; the server answers
#             both on the same connection (RFC 5389 §7.2.2: no framing
#             but STUN's own Message Length).
#   secure    A second server, --secure-stun with the long-term
#             credential mechanism (RFC 5389 §10.2) and one published
#             test user: an unauthenticated Binding Request draws error
#             401 with REALM and NONCE, and a script-built request
#             repeating them with USERNAME and MESSAGE-INTEGRITY draws a
#             Success Response with MESSAGE-INTEGRITY of its own.
#   classic   The `stun` client (stun-client 0.97), which speaks RFC
#             3489: no magic cookie, a 16-byte transaction ID. coturn
#             answers it in kind, with MAPPED-ADDRESS, SOURCE-ADDRESS,
#             CHANGED-ADDRESS and SERVER, and with error 420 for a
#             change request it cannot honour.
#
# The first five go to tests/fixtures/staging/stun.pcap (the corpus);
# the classic exchange, which netprotocols.STUN rejects at its magic
# cookie by design, goes to tests/fixtures/staging/stun/stun_rfc3489.pcap,
# outside the corpus globs. Only TCP segments that carry data are kept:
# a bare ACK on port 3478 hands STUN an empty payload, as one on port
# 179 hands BGP. The script asserts the selection exactly, message by
# message: direction, transport, message type, attribute types in order,
# matching transaction IDs, error codes, and every FINGERPRINT.
#
# What coturn built: every response. What turnutils_stunclient and the
# `stun` client built: their requests (binding, rfc5780, classic, and
# the secure scenario's first request). What this script built: the
# other requests (unknown, tcp, and the authenticated one), in the
# Python client below. What the kernel built: the UDP and TCP headers
# and their checksums (offload is off on both veth ends, so they are
# computed), the IPv4 header and the Ethernet header. Both directions
# are captured on the client's side of the pair. The kernel has no
# IPv6, so XOR-MAPPED-ADDRESS over IPv6 is left to RFC 5769's test
# vectors in tests/test_stun.py. The credentials below are test
# credentials, published in tests/fixtures/MANIFEST.md, so that
# check_fixtures.py can verify every MESSAGE-INTEGRITY independently.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip ss tcpdump python3 ethtool timeout turnserver \
    turnutils_stunclient stun; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
echo "[*] coturn $(turnserver --version 2>&1 | head -1)"

OUT="tests/fixtures/staging"
mkdir -p "$OUT/stun"
NSC=np194-client
NSS=np194-server
C=v194c
S=v194s
CLIENT=10.9.194.1
SERVER=10.9.194.2
REALM=np194.test
USER=npstun
PASSWORD=np194-pass
WORK=
TCPDUMP_PID=
TURN_PID=
stop() {  # pid
    [[ -n $1 ]] || return 0
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}
cleanup() {
    stop "$TURN_PID"; TURN_PID=
    stop "$TCPDUMP_PID"; TCPDUMP_PID=
    for ns in "$NSC" "$NSS"; do
        if [[ -e /run/netns/$ns ]]; then
            ip netns pids "$ns" | xargs -r kill 2>/dev/null || true
        fi
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del "$C" 2>/dev/null || true
    if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
fail() { echo "[!] $*" >&2; exit 1; }
WORK=$(mktemp -d)

echo "[*] veth + two netns (client $CLIENT, server $SERVER)"
ip netns add "$NSC"; ip netns add "$NSS"
ip link add "$C" address 02:00:0a:09:c2:01 type veth \
    peer name "$S" address 02:00:0a:09:c2:02
ip link set "$C" netns "$NSC"
ip link set "$S" netns "$NSS"
ip -n "$NSC" addr add "$CLIENT/24" dev "$C"
ip -n "$NSS" addr add "$SERVER/24" dev "$S"
for pair in "$NSC $C" "$NSS $S"; do
    set -- $pair
    ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off \
        >/dev/null 2>&1 || true
    ip -n "$1" link set lo up
    ip -n "$1" link set "$2" up
done
sleep 1

# turnserver in the foreground (backgrounded here), no config file (-n),
# its log and SQLite user database in the scratch directory.
start_server() {  # name extra-flags...
    local name=$1
    shift
    ip netns exec "$NSS" turnserver -n --stun-only --no-tls --no-dtls \
        --no-cli --fingerprint -L "$SERVER" --listening-port 3478 \
        --log-file "$WORK/turnserver-$name.log" --simple-log \
        --no-stdout-log --pidfile "$WORK/turnserver.pid" \
        --db "$WORK/turndb-$name" "$@" >/dev/null 2>&1 &
    TURN_PID=$!
    local tries=100
    until ip netns exec "$NSS" ss -Hlun 'sport = :3478' | grep -q . &&
        ip netns exec "$NSS" ss -Hltn 'sport = :3478' | grep -q .; do
        kill -0 "$TURN_PID" 2>/dev/null || fail "$name: turnserver exited."
        (( --tries )) || fail "$name: turnserver is not listening."
        sleep 0.1
    done
}

start_capture() {  # name
    ip netns exec "$NSC" tcpdump -i "$C" -w "$WORK/$1.pcap" \
        --immediate-mode -U -q 'port 3478' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
}

stop_capture() {
    sleep 1
    kill -INT "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    TCPDUMP_PID=
}

# The script's own STUN client: stdlib only, every request built here.
CLIENT_PY=$(cat <<'PY'
import hashlib
import hmac
import os
import socket
import struct
import sys
import zlib

COOKIE = 0x2112A442
SERVER = (sys.argv[2], 3478)


def attribute(kind, value):
    return struct.pack("!HH", kind, len(value)) + value + bytes(-len(value) % 4)


def header(length, tid):
    return struct.pack("!HHI", 0x0001, length, COOKIE) + tid


def request(attributes, *, key=None):
    """A Binding Request: ``attributes``, then MESSAGE-INTEGRITY over
    the message so far when ``key`` is given (RFC 5389 §15.4: the
    header's Length already counting it), then FINGERPRINT (§15.5)."""
    tid, body = os.urandom(12), b"".join(attributes)
    if key is not None:
        mac = hmac.new(key, header(len(body) + 24, tid) + body, hashlib.sha1)
        body += attribute(0x0008, mac.digest())
    crc = zlib.crc32(header(len(body) + 8, tid) + body) ^ 0x5354554E
    body += attribute(0x8028, struct.pack("!I", crc))
    return header(len(body), tid) + body


def attributes_of(message):
    found, cursor = {}, 20
    while cursor + 4 <= len(message):
        kind, length = struct.unpack_from("!HH", message, cursor)
        found.setdefault(kind, message[cursor + 4 : cursor + 4 + length])
        cursor += 4 + length + (-length % 4)
    return found


def exchange(sock, message):
    sock.sendto(message, SERVER)
    return sock.recvfrom(2048)[0]


mode = sys.argv[1]
if mode == "unknown":
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        exchange(sock, request([attribute(0x7FF0, b"np194")]))
elif mode == "secure":
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        challenge = attributes_of(exchange(sock, request([])))
        realm, nonce = challenge[0x0014], challenge[0x0015]
        user, password = sys.argv[3].encode(), sys.argv[4].encode()
        # The long-term key (RFC 5389 §15.4): MD5(username:realm:password).
        key = hashlib.md5(b":".join([user, realm, password])).digest()
        exchange(
            sock,
            request(
                [
                    attribute(0x0006, user),
                    attribute(0x0014, realm),
                    attribute(0x0015, nonce),
                ],
                key=key,
            ),
        )
elif mode == "tcp":
    first = request([attribute(0x8022, b"np194 capture client")])
    second = header(0, os.urandom(12))
    with socket.create_connection(SERVER, timeout=3) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(first + second)
        received = b""
        while True:
            # Read until both responses have arrived whole.
            cursor = count = 0
            while cursor + 20 <= len(received):
                end = cursor + 20 + struct.unpack_from("!H", received, cursor + 2)[0]
                if end > len(received):
                    break
                cursor, count = end, count + 1
            if count == 2:
                break
            chunk = sock.recv(4096)
            if not chunk:
                sys.exit("tcp: the server closed before answering both")
            received += chunk
        sock.shutdown(socket.SHUT_RDWR)
else:
    sys.exit(f"unknown mode {mode}")
PY
)

run_client() {  # mode args...
    ip netns exec "$NSC" python3 -c "$CLIENT_PY" "$1" "$SERVER" "${@:2}"
}

start_server plain

echo "[>] stun: binding"
start_capture binding
ip netns exec "$NSC" turnutils_stunclient "$SERVER" >/dev/null
stop_capture

echo "[>] stun: rfc5780"
start_capture rfc5780
# The client waits on for an answer from an alternate address the
# server does not have; the capture needs only its first two exchanges.
ip netns exec "$NSC" timeout 3 turnutils_stunclient -f "$SERVER" \
    >/dev/null || true
stop_capture

echo "[>] stun: unknown"
start_capture unknown
run_client unknown
stop_capture

echo "[>] stun: tcp"
start_capture tcp
run_client tcp
stop_capture

echo "[>] stun: classic"
start_capture classic
# -i names the client's address: without it the client looks up its
# own host name first, which a netns without DNS leaves hanging. The
# client exits 1 when its NAT tests end without a verdict.
ip netns exec "$NSC" timeout 20 stun "$SERVER" -i "$CLIENT" \
    >/dev/null 2>&1 </dev/null || true
stop_capture

stop "$TURN_PID"; TURN_PID=
start_server secure --secure-stun --lt-cred-mech --realm "$REALM" \
    --user "$USER:$PASSWORD"

echo "[>] stun: secure"
start_capture secure
run_client secure "$USER" "$PASSWORD"
stop_capture
stop "$TURN_PID"; TURN_PID=

echo "[*] Selecting and checking the fixture frames..."
python3 - "$WORK" "$OUT/stun.pcap" "$OUT/stun/stun_rfc3489.pcap" <<'PY'
import struct
import sys
import zlib
from pathlib import Path

work, corpus_out, classic_out = Path(sys.argv[1]), *map(Path, sys.argv[2:])
CLIENT, SERVER = bytes([10, 9, 194, 1]), bytes([10, 9, 194, 2])
COOKIE = b"\x21\x12\xa4\x42"


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


def payload(frame):
    """(direction, transport, payload) of one frame, read independently
    of netprotocols."""
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    direction = {(CLIENT, SERVER): "c", (SERVER, CLIENT): "s"}[
        (ip[12:16], ip[16:20])
    ]
    upper = ip[ihl : struct.unpack_from("!H", ip, 2)[0]]
    if 3478 not in struct.unpack_from("!HH", upper):
        sys.exit("a captured frame is not to or from port 3478")
    if ip[9] == 17:
        return direction, "udp", upper[8 : struct.unpack_from("!H", upper, 4)[0]]
    if ip[9] == 6:
        return direction, "tcp", upper[(upper[12] >> 4) * 4 :]
    sys.exit(f"unexpected IP protocol {ip[9]}")


def messages(data):
    """Split ``data`` into STUN messages and describe each: message type,
    transaction ID, attribute types and the attributes by type."""
    found = []
    while data:
        if len(data) < 20:
            sys.exit(f"{len(data)} bytes left, short of a STUN header")
        kind, length = struct.unpack_from("!HH", data)
        message, data = data[: 20 + length], data[20 + length :]
        if len(message) != 20 + length or length % 4:
            sys.exit(f"a STUN message's Length {length} does not frame it")
        tid = message[4:20] if message[4:8] != COOKIE else message[8:20]
        types, values, cursor = [], {}, 20
        while cursor < len(message):
            attr, size = struct.unpack_from("!HH", message, cursor)
            types.append(attr)
            values.setdefault(attr, message[cursor + 4 : cursor + 4 + size])
            cursor += 4 + size + (-size % 4)
        if cursor != len(message):
            sys.exit("an attribute runs past its message")
        if 0x8028 in values:
            # The fingerprint: CRC-32 of the message before it, XOR
            # 0x5354554E (RFC 5389 §15.5); a sanity check here, verified
            # independently by check_fixtures.py.
            want = zlib.crc32(message[:-8]) ^ 0x5354554E
            if types[-1] != 0x8028 or values[0x8028] != want.to_bytes(4):
                sys.exit("a FINGERPRINT does not verify")
        found.append((kind, tid, types, values))
    return found


def error_code(values):
    value = values[0x0009]
    return (value[2] & 0x07) * 100 + value[3]


def capture(name):
    """Every record of a scenario, with its data, bare TCP dropped."""
    kept = []
    for pcap_header, record in records(work / f"{name}.pcap"):
        direction, transport, data = payload(record[16:])
        if data:
            kept.append((pcap_header, record, direction, transport, messages(data)))
    return kept


SUCCESS = [0x0020, 0x0001, 0x802B, 0x8022, 0x8028]
selected, classic = [], []
header = None


def expect(name, kept, shape):
    """Check ``kept`` frame by frame against ``shape``: (direction,
    transport, [(message type, attribute types), ...]) per frame."""
    got = [
        (d, t, [(m[0], m[2]) for m in found]) for _, _, d, t, found in kept
    ]
    if got != shape:
        sys.exit(f"{name}: captured {got}, expected {shape}")


def pair(name, kept, predicate):
    """The first request matching ``predicate`` and the response with its
    transaction ID."""
    for index, (_, _, direction, _, found) in enumerate(kept):
        if direction == "c" and predicate(found[0]):
            tid = found[0][1]
            for later in kept[index + 1 :]:
                if later[2] == "s" and later[4][0][1] == tid:
                    return [kept[index], later]
    sys.exit(f"{name}: no matching request and response")


kept = capture("binding")
expect("binding", kept, [("c", "udp", [(1, [])]), ("s", "udp", [(0x101, SUCCESS)])])
selected += kept

kept = pair(
    "rfc5780", capture("rfc5780"), lambda m: 0x0003 in m[3] and 0x0027 in m[3]
)
expect(
    "rfc5780",
    kept,
    [
        ("c", "udp", [(1, [0x0027, 0x0003])]),
        ("s", "udp", [(0x111, [0x0009, 0x8022, 0x8028])]),
    ],
)
if error_code(kept[1][4][0][3]) != 420:
    sys.exit("rfc5780: the error is not 420")
selected += kept

kept = capture("unknown")
expect(
    "unknown",
    kept,
    [
        ("c", "udp", [(1, [0x7FF0, 0x8028])]),
        ("s", "udp", [(0x111, [0x0009, 0x000A, 0x8022, 0x8028])]),
    ],
)
values = kept[1][4][0][3]
if error_code(values) != 420 or values[0x000A] != b"\x7f\xf0":
    sys.exit("unknown: not error 420 naming attribute 0x7FF0")
selected += kept

kept = capture("tcp")
client = [m for k in kept if k[2] == "c" for m in k[4]]
server = [m for k in kept if k[2] == "s" for m in k[4]]
if [k[2:4] for k in kept][:1] != [("c", "tcp")] or len(kept[0][4]) != 2:
    sys.exit("tcp: the two requests are not in one segment")
if [(m[0], m[2]) for m in client] != [(1, [0x8022, 0x8028]), (1, [])]:
    sys.exit(f"tcp: unexpected requests {client}")
if [(m[0], m[2]) for m in server] != [(0x101, SUCCESS)] * 2 or [
    m[1] for m in server
] != [m[1] for m in client]:
    sys.exit(f"tcp: unexpected responses {server}")
selected += kept

kept = capture("secure")
expect(
    "secure",
    kept,
    [
        ("c", "udp", [(1, [0x8028])]),
        ("s", "udp", [(0x111, [0x0009, 0x0015, 0x0014, 0x8022, 0x8028])]),
        ("c", "udp", [(1, [0x0006, 0x0014, 0x0015, 0x0008, 0x8028])]),
        ("s", "udp", [(0x101, SUCCESS[:4] + [0x0008, 0x8028])]),
    ],
)
if error_code(kept[1][4][0][3]) != 401:
    sys.exit("secure: the first answer is not error 401")
selected += kept

raw = capture("classic")
for _, _, _, _, found in raw:
    if found[0][1][:4] == COOKIE:
        sys.exit("classic: a message carries the magic cookie")
for flags in (b"\x00\x00\x00\x00", b"\x00\x00\x00\x04"):
    classic += pair("classic", raw, lambda m, f=flags: m[3].get(3) == f)
expect(
    "classic",
    classic,
    [
        ("c", "udp", [(1, [0x0003])]),
        ("s", "udp", [(0x101, [0x0001, 0x0004, 0x0005, 0x8022])]),
        ("c", "udp", [(1, [0x0003])]),
        ("s", "udp", [(0x111, [0x0009, 0x8022])]),
    ],
)

header = selected[0][0]
corpus_out.write_bytes(header + b"".join(k[1] for k in selected))
classic_out.write_bytes(header + b"".join(k[1] for k in classic))
print(f"[+] {len(selected)} corpus frames, {len(classic)} RFC 3489 frames.")
PY

echo
echo "[*] Validating..."
CHECKER_PY=$(command -v python3)
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT/stun"
else
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT/stun"
fi

echo
echo "[i] Expect udp, tcp and stun counts, every stun-fingerprint and"
echo "    stun-message-integrity verified, and zero failures. Fold"
echo "    tests/fixtures/staging/stun.pcap into tests/fixtures/ and"
echo "    staging/stun/stun_rfc3489.pcap into tests/fixtures/stun/."
