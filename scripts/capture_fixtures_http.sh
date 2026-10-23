#!/usr/bin/env bash
# Capture HTTP/1.1 fixtures (RFC 9112) and extract their byte streams.
#
#     sudo scripts/capture_fixtures_http.sh
#
# A real HTTP exchange needs a server and a client. This runs a stdlib
# http.server handler on one end of a veth pair and drives it from the
# other: curl for six single-request connections (GET with
# Content-Length, HEAD, a conditional GET answered 304, a POST, a GET
# answered chunked with a trailer, and a GET of a 404) and a raw Python
# socket for one pipelined connection (GET, HEAD and a chunked GET in one
# write, the last asking to close). curl cannot pipeline: libcurl's
# CURLMOPT_PIPELINING "has no effect" for HTTP/1.1 since 7.62.0.
#
# The handler sets protocol_version = "HTTP/1.1": http.server's default
# is "HTTP/1.0", which closes the connection after every response and
# would make pipelining impossible.
#
# The capture keeps every segment of every connection, handshake and
# teardown included. It lands in tests/fixtures/staging/http.pcap, and
# scripts/extract_http_streams.py then writes each connection's two
# byte streams (NN.request / NN.response) to tests/fixtures/staging/http/.
# Fold both into tests/fixtures/http/: that directory sits outside the
# corpus's non-recursive *.pcap globs, because HTTP is not
# port-dispatched and a bare TCP segment is not an HTTP message.
#
# veth is a purely local link, so tx/rx offload is disabled first
# (ethtool -K) or the TCP checksums are left to "offload" and never
# computed; check_fixtures.py verifies them.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump curl python3 ethtool; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSS=nphts
NSC=nphtc
S=nphtsv
C=nphtcv
SERVER=10.9.8.1
server_pid=""
cleanup() {
    [[ -n $server_pid ]] && kill "$server_pid" 2>/dev/null || true
    ip netns del "$NSS" 2>/dev/null || true
    ip netns del "$NSC" 2>/dev/null || true
    ip link del "$S" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

no6() {
    $1 sysctl -qw net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    $1 sysctl -qw net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
}

echo "[*] veth + two netns (server $SERVER; client 10.9.8.2)"
no6 ""
ip netns add "$NSS"; ip netns add "$NSC"
no6 "ip netns exec $NSS"; no6 "ip netns exec $NSC"
ip link add "$S" type veth peer name "$C"
ip link set "$S" netns "$NSS"
ip link set "$C" netns "$NSC"
ip -n "$NSS" addr add "$SERVER/24" dev "$S"
ip -n "$NSC" addr add 10.9.8.2/24 dev "$C"
ip netns exec "$NSS" ethtool -K "$S" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSC" ethtool -K "$C" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSS" link set lo up; ip -n "$NSS" link set "$S" up
ip -n "$NSC" link set lo up; ip -n "$NSC" link set "$C" up

echo "[>] http (stdlib http.server; curl + a pipelined socket client)"
SERVER_PY=$(cat <<'PY'
import http.server
import sys

BODY = b"Hello from the NETProtocols HTTP fixture.\n"
ETAG = '"v1"'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NETProtocols-fixture"

    def version_string(self):
        return self.server_version

    def log_message(self, *args):
        pass

    def _hello(self, head):
        if self.headers.get("If-None-Match") == ETAG:
            self.send_response(304)
            self.send_header("ETag", ETAG)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("ETag", ETAG)
        self.end_headers()
        if not head:
            self.wfile.write(BODY)

    def _chunked(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Trailer", "X-Fixture")
        self.end_headers()
        for part in (b"chunked ", b"transfer ", b"coding\n"):
            self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
        self.wfile.write(b"0\r\nX-Fixture: trailer\r\n\r\n")

    def do_GET(self):
        if self.path == "/chunked":
            self._chunked()
        elif self.path == "/hello":
            self._hello(head=False)
        else:
            self.send_error(404)

    def do_HEAD(self):
        self._hello(head=True)

    def do_POST(self):
        data = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(201)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


http.server.HTTPServer((sys.argv[1], 80), Handler).serve_forever()
PY
)
PIPELINE_PY=$(cat <<'PY'
import socket
import sys

host = sys.argv[1]
requests = (
    f"GET /hello HTTP/1.1\r\nHost: {host}\r\n\r\n"
    f"HEAD /hello HTTP/1.1\r\nHost: {host}\r\n\r\n"
    f"GET /chunked HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
).encode()
with socket.create_connection((host, 80), timeout=5) as sock:
    sock.sendall(requests)
    while sock.recv(65536):
        pass
PY
)
ip netns exec "$NSS" python3 -c "$SERVER_PY" "$SERVER" &
server_pid=$!
sleep 1

ip netns exec "$NSS" tcpdump -i "$S" -w "$OUT/http.pcap" \
    --immediate-mode -U -q 'tcp port 80' >/dev/null 2>&1 &
pid=$!
sleep 1

base="http://$SERVER"
in_client() { ip netns exec "$NSC" "$@"; }
in_client curl -sS -o /dev/null "$base/hello"
in_client curl -sS -o /dev/null --head "$base/hello"
in_client curl -sS -o /dev/null -H 'If-None-Match: "v1"' "$base/hello"
in_client curl -sS -o /dev/null --data-binary 'name=netprotocols' "$base/echo"
in_client curl -sS -o /dev/null "$base/chunked"
in_client curl -sS -o /dev/null "$base/missing"
in_client python3 -c "$PIPELINE_PY" "$SERVER"
sleep 1

kill -INT "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

echo
echo "[*] Validating and extracting the byte streams..."
CHECKER_PY=$(command -v python3)
run_as_user() {
    if [[ -n ${SUDO_USER:-} ]]; then
        sudo -u "$SUDO_USER" "$@"
    else
        "$@"
    fi
}
[[ -n ${SUDO_USER:-} ]] && chown -R "$SUDO_USER" "$OUT"
run_as_user "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
run_as_user "$CHECKER_PY" scripts/extract_http_streams.py \
    "$OUT/http.pcap" "$OUT/http"

echo
echo "[i] Expect zero checksum failures and seven connections: six from"
echo "    curl (GET, HEAD, a 304, a POST, a chunked GET, a 404) and one"
echo "    pipelined (GET, HEAD, chunked GET). Fold"
echo "    tests/fixtures/staging/http.pcap and tests/fixtures/staging/http/"
echo "    into tests/fixtures/http/."
