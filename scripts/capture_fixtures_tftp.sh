#!/usr/bin/env bash
# Capture a TFTP fixture for the corpus (RFC 1350, RFC 2347-2349).
#
#     sudo scripts/capture_fixtures_tftp.sh
#
# A tftpd-hpa server (in.tftpd, in --secure mode on a scratch
# directory, with --create so uploads are allowed) and two clients, the
# tftp-hpa client and curl, run in two netns over a veth pair. Six
# transfers run in turn:
#
#   rrq        tftp-hpa reads a 1300-byte file in octet mode: DATA
#              blocks 1 and 2 of 512 bytes and a short final block 3 of
#              276, each ACKed (RFC 1350 §6)
#   rrq-even   tftp-hpa reads a 1024-byte file: two full blocks, then
#              an empty block 3, which ends a transfer whose size is a
#              multiple of 512 (RFC 1350 §6)
#   wrq        tftp-hpa writes a 600-byte file: the server ACKs block 0
#              (RFC 1350 §4), then DATA 1 (512) and DATA 2 (88)
#   not-found  tftp-hpa reads a file that does not exist: ERROR code 1,
#              File not found
#   denied     tftp-hpa reads a file the server's user (nobody) cannot
#              open: ERROR code 0, Not defined, with tftpd-hpa's
#              message "Permission denied" (strerror(EACCES))
#   options    curl reads a 1300-byte file in octet mode, asking for
#              tsize 0 (RFC 2349), blksize 1024 (RFC 2348) and a
#              timeout (RFC 2349): the server answers with an OACK
#              (RFC 2347) for all three, curl ACKs block 0, then DATA 1
#              (1024) and DATA 2 (276)
#
# After either ERROR the tftp-hpa client sends one more datagram, an
# ACK of block 1 to the server's transfer port, as BSD tftp's recvfile
# does ("ok to ack, since user has seen err msg"); the capture keeps
# it, as sent.
#
# Only the request goes to port 69. The server answers every request
# from a fresh ephemeral port, its transfer identifier, and the rest of
# the transfer runs between the two ephemeral ports (RFC 1350 §4), so
# tcpdump filters on the hosts, not on the port, to keep the whole
# transfer. A transfer is lockstep, one datagram in flight, so the
# capture holds exactly the datagrams listed above, unless one is
# retransmitted, which the script would reject.
#
# What the clients and the server built: every TFTP byte. What the
# kernel built: the UDP header and its checksum (offload is off on both
# veth ends, so it is computed), the IPv4 header and the Ethernet
# header. Both directions are captured on the server's side of the
# pair. The script asserts the capture's composition exactly, by
# direction, port 69 or not, opcode, block number, data length, error
# code and option names, and stops otherwise.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool in.tftpd tftp curl; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
echo "[*] $(in.tftpd -V 2>&1 | head -n 1) (server)"
echo "[*] $(tftp -V 2>&1 | head -n 1) (client)"
echo "[*] $(curl -V 2>&1 | head -n 1)"

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSS=np192-s
NSC=np192-c
S=v192s
C=v192c
SERVER_IP=10.9.192.1
CLIENT_IP=10.9.192.2
WORK=
TCPDUMP_PID=
TFTPD_PID=
cleanup() {
    for pid in $TFTPD_PID $TCPDUMP_PID; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    for ns in "$NSS" "$NSC"; do
        if [[ -e /run/netns/$ns ]]; then
            ip netns pids "$ns" | xargs -r kill 2>/dev/null || true
        fi
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del "$S" 2>/dev/null || true
    if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
fail() { echo "[!] $*" >&2; exit 1; }
cleanup
WORK=$(mktemp -d)
ROOT="$WORK/root"
FILES="$WORK/client"
RAW="$WORK/raw.pcap"

echo "[*] veth + two netns (server $SERVER_IP, client $CLIENT_IP)"
ip netns add "$NSS"; ip netns add "$NSC"
ip link add "$S" address 02:00:0a:09:c0:01 type veth \
    peer name "$C" address 02:00:0a:09:c0:02
ip link set "$S" netns "$NSS"
ip link set "$C" netns "$NSC"
ip -n "$NSS" addr add "$SERVER_IP/24" dev "$S"
ip -n "$NSC" addr add "$CLIENT_IP/24" dev "$C"
for pair in "$NSS $S" "$NSC $C"; do
    set -- $pair
    ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off \
        >/dev/null 2>&1 || true
    ip -n "$1" link set lo up
    ip -n "$1" link set "$2" up
done
sleep 1

echo "[*] Files: the server's --secure root, and the client's upload"
mkdir -p "$ROOT" "$FILES"
# Fixed, printable contents, so a re-capture carries the same bytes.
python3 - "$ROOT" "$FILES" <<'PY'
import sys
from pathlib import Path

root, files = Path(sys.argv[1]), Path(sys.argv[2])
line = b"netprotocols tftp fixture, RFC 1350 block data.\n"  # 48 bytes


def text(size: int) -> bytes:
    return (line * (size // len(line) + 1))[:size]


(root / "boot.bin").write_bytes(text(1300))
(root / "even.bin").write_bytes(text(1024))
(root / "secret.bin").write_bytes(text(100))
(files / "upload.bin").write_bytes(text(600))
PY
chmod 0777 "$ROOT"
chmod 0644 "$ROOT/boot.bin" "$ROOT/even.bin"
# Not world-readable: tftpd-hpa refuses to serve it (ERROR code 0,
# "Permission denied"; see the header).
chmod 0600 "$ROOT/secret.bin"

ip netns exec "$NSS" tcpdump -i "$S" -w "$RAW" --immediate-mode -U -q \
    "udp and host $SERVER_IP and host $CLIENT_IP" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

# --ipv4: the daemon exits if it cannot open an IPv6 socket, which a
# kernel without IPv6 refuses. --address takes the port alone: tftpd-hpa
# 5.2 fails to resolve a numeric host there (exit 66, EX_NOINPUT), and
# the server's netns holds only the veth address and loopback anyway.
ip netns exec "$NSS" in.tftpd --ipv4 --foreground --listen --address :69 \
    --user nobody --secure --create "$ROOT" &
TFTPD_PID=$!
sleep 1
kill -0 "$TFTPD_PID" 2>/dev/null || fail "in.tftpd exited early."

client() {  # name tftp-command
    echo "[>] tftp: $1"
    ip netns exec "$NSC" tftp -m octet "$SERVER_IP" -c $2 || true
    sleep 1
}

cd "$FILES"
client rrq "get boot.bin boot.bin"
client rrq-even "get even.bin even.bin"
client wrq "put upload.bin upload.bin"
client not-found "get missing.bin missing.bin"
client denied "get secret.bin secret.bin"
echo "[>] tftp: options (curl)"
ip netns exec "$NSC" curl -sS --tftp-blksize 1024 \
    -o "$FILES/options.bin" "tftp://$SERVER_IP/boot.bin"
sleep 1
cd - >/dev/null

cmp -s "$FILES/boot.bin" "$ROOT/boot.bin" || fail "rrq: wrong contents."
cmp -s "$FILES/even.bin" "$ROOT/even.bin" || fail "rrq-even: wrong contents."
cmp -s "$FILES/upload.bin" "$ROOT/upload.bin" || fail "wrq: wrong contents."
cmp -s "$FILES/options.bin" "$ROOT/boot.bin" || fail "options: wrong contents."

kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=

echo "[*] Checking the capture's composition..."
python3 - "$RAW" "$OUT/tftp.pcap" "$SERVER_IP" "$CLIENT_IP" <<'PY'
import socket
import struct
import sys
from pathlib import Path

raw, out = Path(sys.argv[1]), Path(sys.argv[2])
server, client = socket.inet_aton(sys.argv[3]), socket.inet_aton(sys.argv[4])

data = raw.read_bytes()
if data[:4] != b"\xd4\xc3\xb2\xa1":
    sys.exit("not a little-endian microsecond pcap")


def records():
    cursor = 24
    while cursor + 16 <= len(data):
        incl, orig = struct.unpack_from("<II", data, cursor + 8)
        if incl != orig or cursor + 16 + incl > len(data):
            sys.exit(f"truncated record at byte {cursor}")
        yield data[cursor + 16 : cursor + 16 + incl]
        cursor += 16 + incl
    if cursor != len(data):
        sys.exit(f"{len(data) - cursor} stray bytes")


def describe(frame):
    """One frame's (direction, to or from port 69, opcode, details),
    read independently of netprotocols."""
    if frame[12:14] != b"\x08\x00" or frame[23] != 17:
        sys.exit("a captured frame is not IPv4 UDP")
    ihl = (frame[14] & 0x0F) * 4
    src, dst = frame[26:30], frame[30:34]
    udp = frame[14 + ihl :]
    sport, dport, length = struct.unpack_from("!HHH", udp)
    tftp = udp[8:length]
    if len(udp) != length:
        sys.exit("a frame carries bytes past its UDP datagram")
    direction = {(client, server): "c>s", (server, client): "s>c"}[src, dst]
    port69 = 69 in (sport, dport)
    opcode = struct.unpack_from("!H", tftp)[0]
    body = tftp[2:]
    if opcode in (1, 2):
        fields = body.split(b"\x00")
        if fields[-1] != b"" or len(fields) % 2 != 1:
            sys.exit(f"malformed request: {body!r}")
        names = tuple(f.decode().lower() for f in fields[2:-1:2])
        detail = (fields[0].decode(), fields[1].decode().lower(), names)
    elif opcode == 3:
        detail = (struct.unpack_from("!H", body)[0], len(body) - 2)
    elif opcode == 4:
        if len(body) != 2:
            sys.exit("an ACK is not 4 bytes")
        detail = (struct.unpack_from("!H", body)[0],)
    elif opcode == 5:
        if body[-1:] != b"\x00" or b"\x00" in body[2:-1]:
            sys.exit(f"malformed ERROR: {body!r}")
        detail = (struct.unpack_from("!H", body)[0],)
    elif opcode == 6:
        fields = body.split(b"\x00")
        if fields[-1] != b"" or len(fields) % 2 != 1:
            sys.exit(f"malformed OACK: {body!r}")
        detail = (tuple(f.decode().lower() for f in fields[0:-1:2]),)
    else:
        sys.exit(f"unexpected opcode {opcode}")
    return (direction, port69, opcode, *detail)


def transfer(sender, receiver, sizes, first_block=1):
    """DATA from sender, each ACKed by receiver, lockstep."""
    steps = []
    for block, size in enumerate(sizes, first_block):
        steps.append((sender, False, 3, block, size))
        steps.append((receiver, False, 4, block))
    return steps


OPTIONS = ("tsize", "blksize", "timeout")
expected = [
    # rrq: 1300 bytes, 512 + 512 + 276.
    ("c>s", True, 1, "boot.bin", "octet", ()),
    *transfer("s>c", "c>s", [512, 512, 276]),
    # rrq-even: 1024 bytes end in an empty block.
    ("c>s", True, 1, "even.bin", "octet", ()),
    *transfer("s>c", "c>s", [512, 512, 0]),
    # wrq: ACK 0, then 600 bytes, 512 + 88.
    ("c>s", True, 2, "upload.bin", "octet", ()),
    ("s>c", False, 4, 0),
    *transfer("c>s", "s>c", [512, 88]),
    # not-found and denied: an ERROR each, which the tftp-hpa client
    # answers with an ACK of block 1, as BSD tftp's recvfile does.
    ("c>s", True, 1, "missing.bin", "octet", ()),
    ("s>c", False, 5, 1),
    ("c>s", False, 4, 1),
    ("c>s", True, 1, "secret.bin", "octet", ()),
    ("s>c", False, 5, 0),
    ("c>s", False, 4, 1),
    # options: curl asks for tsize, blksize and timeout; the server
    # acknowledges all three; ACK 0; then 1024 + 276.
    ("c>s", True, 1, "boot.bin", "octet", OPTIONS),
    ("s>c", False, 6, OPTIONS),
    ("c>s", False, 4, 0),
    *transfer("s>c", "c>s", [1024, 276]),
]

frames = list(records())
seen = [describe(frame) for frame in frames]
if seen != expected:
    for index, got in enumerate(seen):
        want = expected[index] if index < len(expected) else None
        mark = "  " if got == want else "!!"
        print(f"{mark} frame {index}: {got}, expected {want}")
    sys.exit(f"[!] {len(seen)} frames, expected {len(expected)}")
out.write_bytes(data)
print(f"[+] {len(frames)} frames, as expected.")
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
echo "[i] Expect ipv4 + udp counts and zero failures. Fold"
echo "    tests/fixtures/staging/tftp.pcap into tests/fixtures/."
