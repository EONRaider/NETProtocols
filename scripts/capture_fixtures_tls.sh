#!/usr/bin/env bash
# Capture TLS fixtures (RFC 8446, RFC 5246) for the corpus, ours and not
# a public one.
#
#     sudo scripts/capture_fixtures_tls.sh
#
# nginx (nginx-light, OpenSSL 3) serves HTTPS on 10.9.196.2 port 443 in
# one netns, with a self-signed ECDSA P-256 certificate for
# tls.np196.test that this script generates in a scratch directory and
# deletes on exit: no private key is ever written under the repository.
# Clients in a second netns, a veth pair away, reach it by that host
# name, never by address (RFC 6066 §3 forbids an IP literal in
# server_name): the client netns gets an /etc/hosts of its own through
# /etc/netns/<ns>/hosts, which `ip netns exec` bind-mounts over
# /etc/hosts. Five scenarios run in turn, each in its own tcpdump
# capture, each client a real TLS stack:
#
#   chromium  Headless Chromium (BoringSSL) fetching https://tls.np196.test/.
#             Its ClientHello carries GREASE values, a randomized
#             extension order and an X25519MLKEM768 key share beside
#             X25519's, which makes it a 1738-byte record (a 1733-byte
#             fragment) that TCP carries in two segments at the
#             1448-byte MSS. Chromium
#             opens two connections, abandoning the first after the
#             server's flight, so the capture holds two ClientHellos
#             whose extension orders differ.
#   curl      curl (OpenSSL 3.0), TLS 1.3: a 512-byte ClientHello
#             (OpenSSL's padding extension).
#   gnutls    gnutls-cli (GnuTLS 3.8), TLS 1.3, whose ClientHello
#             record says TLS 1.2 (0x0303) where the others say 1.0.
#   nosni     openssl s_client -noservername (OpenSSL 3.0), TLS 1.3: a
#             real ClientHello with no server_name extension.
#   tls12     curl capped at TLS 1.2 (--tls-max 1.2): ServerHello,
#             Certificate, ServerKeyExchange and ServerHelloDone in the
#             clear, ChangeCipherSpec each way, an encrypted Finished
#             each way under content type Handshake, and the client's
#             close_notify Alert, encrypted under content type Alert.
#
# Two pcaps come out, as for BGP:
#
#   tests/fixtures/staging/tls/tls_session.pcap  every frame of every
#       connection, handshakes, bare ACKs, FINs and Chromium's split
#       ClientHellos included. It belongs in tests/fixtures/tls/,
#       outside the corpus's non-recursive *.pcap globs, because a bare
#       ACK on port 443 hands TLS an empty payload and a ClientHello cut
#       by a segment boundary raises TruncatedHeaderError, so a strict
#       walk of it raises (TCP delivers a byte stream, not records;
#       reassembly is the caller's -- see SECURITY.md).
#   tests/fixtures/staging/tls.pcap  the corpus frames, 15 segments each
#       a whole number of complete records: every data segment of the
#       TLS 1.2 connection (7); the first data segment each way of the
#       curl, gnutls and nosni connections, the ClientHello and the
#       server's flight (6); and from Chromium's second connection, the
#       one that sends a request, the server's flight and the client's
#       next segment, its ChangeCipherSpec and Finished (2).
#
# The script asserts both: the number of connections per scenario, that
# each side of each connection reassembles into whole records only, each
# ClientHello's record version, session ID, server_name and, for
# Chromium, its GREASE, the X25519MLKEM768 key share, the two segments
# and the two extension orders; each ServerHello; the TLS 1.2 record
# sequence; every corpus frame's content types, in order; and the
# session's layout that tests/test_tls.py hard-codes and
# tests/fixtures/MANIFEST.md lists (the frames each scenario adds, the
# bare ACK at frame 2, the split ClientHellos at 3-4 and 15-16). It parses
# the pcaps with the standard library and reassembles each connection
# with scripts/extract_http_streams.py, whose extract() takes any port,
# so neither depends on netprotocols. It then runs
# scripts/check_fixtures.py over both, which verifies every IPv4 and TCP
# checksum and that every segment on port 443 that carries data is
# whole records in tls.pcap, failing it otherwise; in tls_session.pcap,
# whose name marks it a session capture, it counts the four split
# segments as tls-unchecked instead.
#
# What the clients and nginx built: every TLS byte. What the kernel
# built: the TCP and IPv4 headers and their checksums (offload is off on
# both veth ends, so they are computed) and the Ethernet header, from
# the MAC addresses pinned below. Both directions are captured on the
# client's end of the pair. Keys, randoms, session IDs and GREASE values
# are fresh in every run, so a re-capture differs in those bytes and in
# the timestamps, but not in the structure the script asserts.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip ss tcpdump python3 ethtool timeout openssl curl gnutls-cli \
    nginx; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
# Chromium: $CHROME if set, else the Playwright build, else one on PATH.
if [[ -z ${CHROME:-} ]]; then
    for candidate in /opt/pw-browsers/chromium-*/chrome-linux*/chrome; do
        [[ -x $candidate ]] && CHROME=$candidate
    done
fi
CHROME=${CHROME:-$(command -v chromium || command -v chromium-browser || true)}
[[ -n $CHROME && -x $CHROME ]] || { echo "Chromium is required (set CHROME)." >&2; exit 1; }
echo "[*] $("$CHROME" --version 2>/dev/null | head -n 1)"
echo "[*] $(openssl version)"
echo "[*] $(gnutls-cli --version 2>/dev/null | head -n 1)"
echo "[*] $(nginx -v 2>&1)"

OUT="tests/fixtures/staging"
mkdir -p "$OUT/tls"
NSC=np-tls-client
NSS=np-tls-server
C=vtlsc
S=vtlss
CLIENT=10.9.196.1
SERVER=10.9.196.2
HOST=tls.np196.test
WORK=
TCPDUMP_PID=
NGINX_PID=
stop() {  # pid
    [[ -n $1 ]] || return 0
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}
cleanup() {
    stop "$NGINX_PID"; NGINX_PID=
    stop "$TCPDUMP_PID"; TCPDUMP_PID=
    for ns in "$NSC" "$NSS"; do
        if [[ -e /run/netns/$ns ]]; then
            ip netns pids "$ns" | xargs -r kill 2>/dev/null || true
        fi
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del "$C" 2>/dev/null || true
    rm -rf "/etc/netns/$NSC"
    if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
fail() { echo "[!] $*" >&2; exit 1; }
cleanup
WORK=$(mktemp -d)

echo "[*] veth + two netns (client $CLIENT, server $SERVER as $HOST)"
ip netns add "$NSC"; ip netns add "$NSS"
ip link add "$C" address 02:00:0a:09:c4:01 type veth \
    peer name "$S" address 02:00:0a:09:c4:02
ip link set "$C" netns "$NSC"
ip link set "$S" netns "$NSS"
ip -n "$NSC" addr add "$CLIENT/24" dev "$C"
ip -n "$NSS" addr add "$SERVER/24" dev "$S"
bring_up() {  # netns iface
    ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off \
        >/dev/null 2>&1 || true
    ip -n "$1" link set lo up
    ip -n "$1" link set "$2" up
}
bring_up "$NSC" "$C"
bring_up "$NSS" "$S"
mkdir -p "/etc/netns/$NSC"
printf '127.0.0.1 localhost\n%s %s\n' "$SERVER" "$HOST" \
    >"/etc/netns/$NSC/hosts"
sleep 1

echo "[*] Self-signed ECDSA P-256 certificate for $HOST (scratch only)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -days 2 \
    -subj "/CN=$HOST" -addext "subjectAltName=DNS:$HOST" 2>/dev/null

# nginx in the foreground of its own process (backgrounded here), every
# path it writes in the scratch directory. Session tickets are off, so
# a TLS 1.2 handshake has no NewSessionTicket.
cat >"$WORK/nginx.conf" <<EOF
daemon off;
master_process off;
error_log $WORK/error.log;
pid $WORK/nginx.pid;
events {}
http {
    access_log off;
    client_body_temp_path $WORK/body;
    proxy_temp_path $WORK/proxy;
    fastcgi_temp_path $WORK/fastcgi;
    uwsgi_temp_path $WORK/uwsgi;
    scgi_temp_path $WORK/scgi;
    server {
        listen $SERVER:443 ssl;
        server_name $HOST;
        ssl_certificate $WORK/cert.pem;
        ssl_certificate_key $WORK/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_tickets off;
        location / {
            default_type text/plain;
            return 200 "hello from the NETProtocols TLS fixture\n";
        }
    }
}
EOF
ip netns exec "$NSS" nginx -c "$WORK/nginx.conf" -p "$WORK" &
NGINX_PID=$!
tries=100
until ip netns exec "$NSS" ss -Hltn 'sport = :443' | grep -q .; do
    kill -0 "$NGINX_PID" 2>/dev/null || fail "nginx exited: $(cat "$WORK/error.log")"
    (( --tries )) || fail "nginx is not listening."
    sleep 0.1
done

start_capture() {  # name
    ip netns exec "$NSC" tcpdump -i "$C" -w "$WORK/$1.pcap" \
        --immediate-mode -U -q "host $SERVER and tcp port 443" \
        >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
}

stop_capture() {
    sleep 1
    stop "$TCPDUMP_PID"; TCPDUMP_PID=
}

# Every client runs with an empty environment, so no proxy variable of
# the host's reaches it.
in_client() {
    ip netns exec "$NSC" env -i PATH="$PATH" HOME="$WORK" "$@"
}
# A function, not a variable: $(...) would strip the request's final
# line feed.
request() {
    printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$HOST"
}

echo "[>] tls: chromium"
start_capture chromium
# Headless Chromium fetches the page in about a second but does not
# exit after --dump-dom in a netns without D-Bus, so it is given 20
# seconds and then stopped; the capture has what it needs by then.
in_client timeout 20 "$CHROME" --headless --no-sandbox --disable-gpu \
    --no-zygote --disable-dev-shm-usage --no-first-run --no-proxy-server \
    --disable-background-networking --disable-component-update \
    --disable-sync --ignore-certificate-errors \
    --user-data-dir="$WORK/chromium" --dump-dom "https://$HOST/" \
    >/dev/null 2>&1 || true
stop_capture

echo "[>] tls: curl"
start_capture curl
in_client curl -sS -k -o /dev/null "https://$HOST/"
stop_capture

echo "[>] tls: gnutls"
start_capture gnutls
request | in_client gnutls-cli --insecure --port 443 "$HOST" \
    >/dev/null 2>&1 || fail "gnutls-cli failed"
stop_capture

echo "[>] tls: nosni"
start_capture nosni
request | in_client openssl s_client -connect "$HOST:443" \
    -noservername -quiet >/dev/null 2>&1 || fail "openssl s_client failed"
stop_capture

echo "[>] tls: tls12"
start_capture tls12
in_client curl -sS -k --tlsv1.2 --tls-max 1.2 -o /dev/null "https://$HOST/"
stop_capture

stop "$NGINX_PID"; NGINX_PID=

echo "[*] Asserting the capture and selecting the corpus frames..."
python3 -I - "$WORK" "$OUT/tls.pcap" "$OUT/tls/tls_session.pcap" <<'PY'
import struct
import sys
from pathlib import Path

# extract() reassembles each connection; it parses frames itself and
# never imports netprotocols. Its sibling _pcap.py is imported too.
sys.path.insert(0, "scripts")
from extract_http_streams import extract  # noqa: E402

work, corpus_out, session_out = Path(sys.argv[1]), *map(Path, sys.argv[2:])
SCENARIOS = ("chromium", "curl", "gnutls", "nosni", "tls12")
HOST = b"tls.np196.test"
CCS, ALERT, HANDSHAKE, APPDATA = 20, 21, 22, 23
X25519MLKEM768, X25519 = 0x11EC, 0x001D

# The session capture's layout, which tests/test_tls.py hard-codes
# (BARE_ACK, SPLIT_HEAD and SPLIT_TAIL, PAYLOAD_AT) and
# tests/fixtures/MANIFEST.md lists: the frames each scenario adds, in
# turn; in Chromium's, the client's bare ACK ending the first handshake,
# and each connection's ClientHello, a 1448-byte head and a 290-byte
# tail; and where the payload starts in those frames, after Ethernet,
# IPv4 and a TCP header with the timestamps option.
SESSION_FRAMES = {"chromium": 36, "curl": 18, "gnutls": 18, "nosni": 20, "tls12": 16}
BARE_ACK = 2
SPLIT_HELLOS = ((3, 4), (15, 16))
HELLO_SEGMENTS = (1448, 290)
PAYLOAD_AT = 14 + 20 + 32


def grease(value):
    """RFC 8701's reserved values: 0x0A0A, 0x1A1A, ... 0xFAFA."""
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def records(path):
    """The pcap's global header and every record, timestamps kept."""
    data = path.read_bytes()
    if data[:4] != b"\xd4\xc3\xb2\xa1":
        sys.exit(f"{path.name}: not a little-endian microsecond pcap")
    found, cursor = [], 24
    while cursor + 16 <= len(data):
        incl, orig = struct.unpack_from("<II", data, cursor + 8)
        record = data[cursor : cursor + 16 + incl]
        if len(record) != 16 + incl or incl != orig:
            sys.exit(f"{path.name}: truncated record at byte {cursor}")
        found.append(record)
        cursor += 16 + incl
    if cursor != len(data):
        sys.exit(f"{path.name}: {len(data) - cursor} stray bytes")
    return data[:24], found


def segment(frame):
    """(client port, direction, payload) of an Ethernet/IPv4/TCP frame."""
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    tcp = ip[ihl : struct.unpack_from("!H", ip, 2)[0]]
    sport, dport = struct.unpack_from("!HH", tcp)
    if 443 not in (sport, dport):
        sys.exit("a captured segment is not to or from port 443")
    side = "c" if dport == 443 else "s"
    return (sport if side == "c" else dport), side, tcp[(tcp[12] >> 4) * 4 :]


def split(data, what):
    """Split ``data`` into (content type, version, fragment) records,
    every one whole."""
    found = []
    while data:
        if len(data) < 5:
            sys.exit(f"{what}: {len(data)} bytes, short of a record header")
        kind, version, length = struct.unpack_from("!BHH", data)
        if kind not in range(20, 25) or version >> 8 != 3:
            sys.exit(f"{what}: not a TLS record header: {data[:5].hex()}")
        if len(data) < 5 + length:
            sys.exit(f"{what}: a {length}-byte record runs past the data")
        found.append((kind, version, data[5 : 5 + length]))
        data = data[5 + length :]
    return found


def u16_list(body, at, what):
    (length,) = struct.unpack_from("!H", body, at)
    if at + 2 + length > len(body):
        sys.exit(f"{what}: a length runs past the message")
    return body[at + 2 : at + 2 + length], at + 2 + length


def client_hello(record, what):
    """Parse a ClientHello record into its session ID, cipher suites and
    extensions ((type, data) in wire order)."""
    kind, _, fragment = record
    if kind != HANDSHAKE or fragment[0] != 1:
        sys.exit(f"{what}: the first record is not a ClientHello")
    length = int.from_bytes(fragment[1:4], "big")
    body = fragment[4 : 4 + length]
    if len(body) != length or 4 + length != len(fragment):
        sys.exit(f"{what}: the ClientHello does not fill its record")
    at = 2 + 32
    session_id = body[at + 1 : at + 1 + body[at]]
    suites, at = u16_list(body, at + 1 + body[at], what)
    at += 1 + body[at]
    block, at = u16_list(body, at, what)
    if at != len(body):
        sys.exit(f"{what}: bytes after the extensions")
    extensions, cursor = [], 0
    while cursor < len(block):
        kind, size = struct.unpack_from("!HH", block, cursor)
        extensions.append((kind, block[cursor + 4 : cursor + 4 + size]))
        cursor += 4 + size
    if cursor != len(block):
        sys.exit(f"{what}: an extension runs past the block")
    suites = [int.from_bytes(suites[i : i + 2], "big") for i in range(0, len(suites), 2)]
    return session_id, suites, extensions


def server_name(extensions, what):
    """The host_name of the server_name extension (RFC 6066 §3)."""
    data = dict(extensions).get(0)
    if data is None:
        return None
    names, _ = u16_list(data, 0, what)
    if names[0] != 0:
        sys.exit(f"{what}: the first server name is not a host_name")
    host, _ = u16_list(names, 1, what)
    return host


def check_session_layout(frames, counts):
    """Exit unless ``frames``, the session in capture order, and
    ``counts``, the frames each scenario added, have the layout above."""
    if counts != SESSION_FRAMES:
        sys.exit(
            f"session frames per scenario {counts}, expected {SESSION_FRAMES}: "
            "update tests/fixtures/MANIFEST.md and tests/test_tls.py"
        )

    def client_payload(index, size):
        frame = frames[index]
        port, side, payload = segment(frame)
        if side != "c" or len(payload) != size or len(frame) != PAYLOAD_AT + size:
            sys.exit(
                f"session frame {index}: {len(frame)} bytes, side {side}, a "
                f"{len(payload)}-byte payload; expected the client's {size} "
                f"bytes at {PAYLOAD_AT}"
            )
        return port, payload

    bare_port, _ = client_payload(BARE_ACK, 0)
    for head, tail in SPLIT_HELLOS:
        head_port, first = client_payload(head, HELLO_SEGMENTS[0])
        tail_port, rest = client_payload(tail, HELLO_SEGMENTS[1])
        found = split(first + rest, f"session frames {head} and {tail}")
        kind, _, fragment = found[0]
        if (
            head_port != tail_port
            or len(found) != 1
            or kind != HANDSHAKE
            or fragment[0] != 1
        ):
            sys.exit(f"session frames {head} and {tail} are not one ClientHello")
    if bare_port != segment(frames[SPLIT_HELLOS[0][0]])[0]:
        sys.exit(f"session frame {BARE_ACK} is not the first connection's")


def key_share_groups(extensions):
    data = dict(extensions)[51]
    groups, cursor = [], 2
    while cursor < len(data):
        group, size = struct.unpack_from("!HH", data, cursor)
        groups.append(group)
        cursor += 4 + size
    return groups


header, session, selected = None, [], []
summary, counts = [], {}
for name in SCENARIOS:
    head, captured = records(work / f"{name}.pcap")
    header = header or head
    session += captured
    counts[name] = len(captured)
    frames = [record[16:] for record in captured]
    streams = extract(frames, 443)
    want = 2 if name == "chromium" else 1
    if len(streams) != want:
        sys.exit(f"{name}: {len(streams)} connections, expected {want}")
    # Each connection's data segments per side, in capture order.
    ports, data_segments = [], {}
    for record in captured:
        port, side, payload = segment(record[16:])
        if port not in ports:
            ports.append(port)
        if payload:
            data_segments.setdefault((port, side), []).append((record, payload))
    hellos = []
    for index, (client, server) in enumerate(streams):
        what = f"{name} connection {index + 1}"
        sent, answered = split(client, what + " client"), split(server, what + " server")
        session_id, suites, extensions = client_hello(sent[0], what)
        hellos.append(extensions)
        host = server_name(extensions, what)
        if host != (None if name == "nosni" else HOST):
            sys.exit(f"{what}: server_name {host!r}")
        record_version = 0x0303 if name == "gnutls" else 0x0301
        if sent[0][1] != record_version:
            sys.exit(f"{what}: ClientHello record version {sent[0][1]:#06x}")
        if len(session_id) != (0 if name == "tls12" else 32):
            sys.exit(f"{what}: a {len(session_id)}-byte session ID")
        shello = answered[0]
        if shello[0] != HANDSHAKE or shello[2][0] != 2:
            sys.exit(f"{what}: the server's first record is not a ServerHello")
        first = data_segments[(ports[index], "c")][0][1]
        if name == "chromium":
            if not grease(suites[0]) or not grease(extensions[0][0]):
                sys.exit(f"{what}: no leading GREASE cipher and extension")
            groups = key_share_groups(extensions)
            if X25519MLKEM768 not in groups or X25519 not in groups:
                sys.exit(f"{what}: key shares {groups}")
            if len(first) >= 5 + len(sent[0][2]):
                sys.exit(f"{what}: the ClientHello fits one segment")
            if len(first) + len(data_segments[(ports[index], "c")][1][1]) != 5 + len(sent[0][2]):
                sys.exit(f"{what}: the ClientHello spans more than two segments")
        elif len(first) != 5 + len(sent[0][2]):
            sys.exit(f"{what}: the ClientHello is not its first segment")
        summary.append(
            f"{what}: ClientHello {5 + len(sent[0][2])} bytes in "
            f"{2 if name == 'chromium' else 1} segment(s), "
            f"{len(extensions)} extensions, server_name {host!r}"
        )
        if name == "tls12":
            kinds = [(r[0], r[2][0] if r[0] == HANDSHAKE else None) for r in sent + answered]
            if [k for k in kinds[: len(sent)]][:3] != [(HANDSHAKE, 1), (HANDSHAKE, 16), (CCS, None)]:
                sys.exit(f"{what}: client records {kinds[: len(sent)]}")
            if [r[0] for r in sent][-1] != ALERT:
                sys.exit(f"{what}: the client does not end with an Alert")
            if [k[1] for k in kinds[len(sent) :]][:4] != [2, 11, 12, 14]:
                sys.exit(f"{what}: server records {kinds[len(sent):]}")
    if name == "chromium":
        orders = [[kind for kind, _ in hello if not grease(kind)] for hello in hellos]
        if sorted(orders[0]) != sorted(orders[1]) or orders[0] == orders[1]:
            sys.exit("chromium: the two extension orders are not a permutation")

    # The corpus selection, and the content types each frame must hold.
    def pick(port_index, side, nth, kinds):
        record, payload = data_segments[(ports[port_index], side)][nth]
        got = [r[0] for r in split(payload, f"{name} corpus frame")]
        if got != kinds:
            sys.exit(f"{name}: corpus frame {side}{nth + 1} holds {got}, expected {kinds}")
        selected.append(record)

    flight13 = [HANDSHAKE, CCS, APPDATA, APPDATA, APPDATA, APPDATA]
    if name == "chromium":
        pick(1, "s", 0, flight13)
        pick(1, "c", 2, [CCS, APPDATA])
    elif name in ("curl", "gnutls", "nosni"):
        pick(0, "c", 0, [HANDSHAKE])
        pick(0, "s", 0, flight13)
    else:
        pick(0, "c", 0, [HANDSHAKE])
        pick(0, "s", 0, [HANDSHAKE] * 4)
        pick(0, "c", 1, [HANDSHAKE, CCS, HANDSHAKE])
        pick(0, "s", 1, [CCS, HANDSHAKE])
        pick(0, "c", 2, [APPDATA])
        pick(0, "s", 2, [APPDATA])
        pick(0, "c", 3, [ALERT])
        if len(data_segments[(ports[0], "c")]) != 4 or len(data_segments[(ports[0], "s")]) != 3:
            sys.exit("tls12: more data segments than the seven selected")

# Capture order: the scenarios ran one after another.
order = {id(record): i for i, record in enumerate(session)}
selected.sort(key=lambda record: order[id(record)])
if len(selected) != 15:
    sys.exit(f"selected {len(selected)} corpus frames, expected 15")
check_session_layout([record[16:] for record in session], counts)
corpus_out.write_bytes(header + b"".join(selected))
session_out.write_bytes(header + b"".join(session))
print("\n".join(summary))
print(f"[+] {len(selected)} corpus frames, {len(session)} session frames.")
PY

echo
echo "[*] Validating..."
CHECKER_PY=$(command -v python3)
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT/tls"
else
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT/tls"
fi

echo
echo "[i] Expect tcp and tls counts and zero failures. Fold"
echo "    tests/fixtures/staging/tls.pcap into tests/fixtures/ and"
echo "    staging/tls/tls_session.pcap into tests/fixtures/tls/."
