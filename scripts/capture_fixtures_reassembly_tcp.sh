#!/usr/bin/env bash
# Capture the TCP stream-reassembly fixture for netprotocols.reassembly.
#
#     sudo scripts/capture_fixtures_reassembly_tcp.sh
#
# Builds two netns joined by a veth pair (nprtsv in nprts, the server,
# 10.9.80.1/24; nprtcv in nprtc, the client, 10.9.80.2/24), with fixed
# MAC addresses, permanent neighbor entries on both ends, IPv6 off, and
# tx/rx checksum offload, TSO, GSO and GRO off on both veth ends, so the
# kernel computes every checksum and sends every segment as it is on the
# wire. Both ends route the subnet with advmss 536, so neither side
# sends a segment of more than 536 data bytes and a large response spans
# hundreds of segments.
#
# A stdlib http.server handler (protocol_version "HTTP/1.1") serves:
#
#   GET /big      200, Content-Length, a 200,000-byte body
#   GET /chunked  200, chunked, eight chunks of 2,500 bytes and a trailer
#   GET /hello    200, Content-Length, a short body
#
# and two clients drive it:
#
#   connection 1  curl fetching /big then /chunked on one connection,
#                 which curl closes with a FIN;
#   connection 2  a python3 socket client sending GET /hello and, once
#                 the response is read, closing with SO_LINGER 0, so its
#                 kernel ends the connection with an RST.
#
# The capture, on the server's veth end, keeps every TCP segment of both
# connections, handshakes and teardowns included, and writes
# tests/fixtures/staging/reassembly/http_stream.pcap.
#
# It is then checked by scripts/check_fixtures.py, and by tshark, which
# must find two TCP streams and an RST from the client in the second;
# the length and SHA-256 of each direction of each stream as tshark's
# `-z follow,tcp,raw` gives it are printed, to be recorded in
# tests/fixtures/MANIFEST.md and tests/test_stream_reassembly.py. Any
# other outcome stops the script with an error, and whatever was
# captured by then is left in the staging directory for inspection and
# must not be folded in.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump curl python3 ethtool tshark; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging/reassembly"
mkdir -p "$OUT"
NSS=nprts
NSC=nprtc
S=nprtsv
C=nprtcv
SERVER=10.9.80.1
CLIENT=10.9.80.2
MAC_S=02:00:0a:09:50:01
MAC_C=02:00:0a:09:50:02
CAPTURE="$OUT/http_stream.pcap"
pid=""
server_pid=""

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
    if [[ -n $server_pid ]]; then
        kill "$server_pid" 2>/dev/null || true
    fi
    ip netns del "$NSS" 2>/dev/null || true
    ip netns del "$NSC" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

setup_ns() {  # netns dev address peer-address peer-mac
    ip netns exec "$1" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 \
        >/dev/null 2>&1 || true
    ip -n "$1" addr add "$3/24" dev "$2"
    ip netns exec "$1" ethtool -K "$2" tx off rx off >/dev/null ||
        fail "$2: ethtool could not turn tx/rx checksum offload off."
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off \
        >/dev/null 2>&1 || true
    ip -n "$1" link set lo up
    ip -n "$1" link set "$2" up
    ip -n "$1" route replace 10.9.80.0/24 dev "$2" advmss 536
    ip -n "$1" neigh replace "$4" lladdr "$5" dev "$2" nud permanent
}

echo "[*] veth + two netns (server $SERVER, client $CLIENT)"
ip netns add "$NSS"
ip netns add "$NSC"
ip link add "$S" netns "$NSS" address "$MAC_S" type veth \
    peer name "$C" netns "$NSC" address "$MAC_C"
setup_ns "$NSS" "$S" "$SERVER" "$CLIENT" "$MAC_C"
setup_ns "$NSC" "$C" "$CLIENT" "$SERVER" "$MAC_S"
sleep 1

SERVER_PY=$(cat <<'PY'
import http.server
import sys

BIG = bytes((index * 7 + index // 251) % 256 for index in range(200_000))
HELLO = b"Hello from the NETProtocols stream fixture.\n"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NETProtocols-fixture"

    def version_string(self):
        return self.server_version

    def date_time_string(self, timestamp=None):
        return "Wed, 11 Nov 2026 00:00:00 GMT"

    def log_message(self, *args):
        pass

    def _whole(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _chunked(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Trailer", "X-Fixture")
        self.end_headers()
        for number in range(8):
            part = bytes([0x61 + number]) * 2500
            self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
        self.wfile.write(b"0\r\nX-Fixture: trailer\r\n\r\n")

    def do_GET(self):
        if self.path == "/big":
            self._whole(BIG)
        elif self.path == "/chunked":
            self._chunked()
        elif self.path == "/hello":
            self._whole(HELLO)
        else:
            self.send_error(404)


http.server.HTTPServer((sys.argv[1], 80), Handler).serve_forever()
PY
)
RESET_PY=$(cat <<'PY'
import socket
import struct
import sys

host = sys.argv[1]
with socket.create_connection((host, 80)) as sock:
    sock.sendall(f"GET /hello HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    received = b""
    while not received.endswith(b"stream fixture.\n"):
        chunk = sock.recv(4096)
        if not chunk:
            sys.exit("the server closed before its response ended")
        received += chunk
    sock.setsockopt(
        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
    )
PY
)

echo "[>] http.server on $SERVER:80"
ip netns exec "$NSS" python3 -I -c "$SERVER_PY" "$SERVER" &
server_pid=$!
sleep 1

echo "[>] http_stream.pcap"
rm -f "$CAPTURE"
ip netns exec "$NSS" tcpdump -i "$S" -w "$CAPTURE" --immediate-mode -U -q \
    'tcp port 80' >/dev/null 2>&1 &
pid=$!
sleep 1
ip netns exec "$NSC" curl -sS -o /dev/null -o /dev/null \
    "http://$SERVER/big" "http://$SERVER/chunked" || fail "curl failed."
sleep 0.5
ip netns exec "$NSC" python3 -I -c "$RESET_PY" "$SERVER" ||
    fail "the reset client failed."
sleep 1
stop_capture

echo "[*] Checking checksums..."
python3 -I scripts/check_fixtures.py "$OUT" ||
    fail "check_fixtures.py rejected a capture."

echo "[*] Checking tshark's streams..."
streams=$(tshark -r "$CAPTURE" -T fields -e tcp.stream 2>/dev/null |
    sort -un | tr '\n' ' ')
[[ $streams == "0 1 " ]] ||
    fail "http_stream.pcap: TCP streams '$streams', not '0 1 '."
resets=$(tshark -r "$CAPTURE" -Y "tcp.flags.reset == 1" -T fields \
    -e tcp.stream -e ip.src 2>/dev/null | sort -u | tr '\n' ' ')
[[ $resets == "1	$CLIENT " ]] ||
    fail "http_stream.pcap: resets '$resets', not one from the client."
for stream in 0 1; do
    tshark -r "$CAPTURE" -q -z "follow,tcp,raw,$stream" 2>/dev/null |
        python3 -I -c '
import hashlib
import sys

sides = {"client": bytearray(), "server": bytearray()}
started = False
for line in sys.stdin:
    if line.startswith("Node 1:"):
        started = True
        continue
    if not started or line.startswith("="):
        continue
    side = "server" if line.startswith("\t") else "client"
    sides[side] += bytes.fromhex(line.strip())
for side, data in sides.items():
    print(sys.argv[1], side, len(data), hashlib.sha256(data).hexdigest())
' "$stream"
done
tshark --version 2>/dev/null | head -1

if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
fi

echo
echo "[i] Fold tests/fixtures/staging/reassembly/http_stream.pcap into"
echo "    tests/fixtures/reassembly/."
