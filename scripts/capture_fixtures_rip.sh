#!/usr/bin/env bash
# Capture a RIP fixture for the corpus (RFC 1058, RFC 2453, RFC 4822).
#
#     sudo scripts/capture_fixtures_rip.sh
#
# Two BIRD 2 routers, one per netns, speak RIP to each other over a
# veth pair on UDP port 520. Each exports three static routes (and,
# over RIPv2, its connected /24), so every Response carries several
# route entries. Five
# scenarios run in turn, each with a fresh pair of daemons:
#
#   v1         RIPv1 (RFC 1058), broadcast to 10.9.52.255
#   v2         RIPv2 (RFC 2453), multicast to 224.0.0.9, no authentication
#   plaintext  RIPv2 with a simple password (RFC 2453 §4.1, type 2)
#   md5        RIPv2 with keyed MD5 (RFC 4822, type 3), key ID 1
#   sha256     RIPv2 with HMAC-SHA-256 (RFC 4822, type 3), key ID 2
#
# The two cryptographic scenarios end every message in an RFC 4822
# authentication trailer: 20 bytes for keyed MD5 and 36 for
# HMAC-SHA-256, which is not a multiple of a route entry's 20 bytes.
# BIRD fills in Auth Data Len inconsistently between the two (20 for
# keyed MD5, counting the trailer's own 4-byte header as Quagga did, but
# 32 for HMAC-SHA-256, the digest alone, as RFC 4822 says), and the
# fixture keeps both as sent.
#
# On start each daemon sends a Request for the whole table (one entry,
# AFI 0, metric 16, RFC 2453 §3.9.1) and then a Response. Updates
# follow every 5 seconds, and triggered ones in between, at times the
# capture cannot pin down. So the full capture of each scenario goes to
# a scratch directory, and the fixture keeps a fixed selection: each
# router's first Request and first Response, and in the v2 scenario the
# first Response 10.9.52.1 sent at least 6 seconds after the scenario's
# first captured frame, past its 5-second update timer: a whole-table
# update, which by then also carries the peer's routes, poisoned
# (metric 16, split horizon with poisoned reverse). The
# script asserts that selection exactly, by router, version, command,
# authentication type and route-entry count, and stops otherwise.
#
# What BIRD built: every RIP byte, including the authentication entries
# and trailers. What the kernel built: the UDP header and its checksum
# (offload is off on both veth ends, so it is computed), the IPv4
# header and the Ethernet header. Both directions are captured on
# 10.9.52.1's side of the pair. The passwords below are test keys,
# published in tests/fixtures/MANIFEST.md, so that check_fixtures.py
# can verify every keyed-MD5 and HMAC-SHA-256 digest independently.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool bird; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
WORK=$(mktemp -d)
NSA=nprip-a
NSB=nprip-b
A=nprip-va
B=nprip-vb
TCPDUMP_PID=
BIRD_A=
BIRD_B=
stop() {  # pid
    [[ -n $1 ]] || return 0
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}
cleanup() {
    stop "$BIRD_A"; BIRD_A=
    stop "$BIRD_B"; BIRD_B=
    stop "$TCPDUMP_PID"; TCPDUMP_PID=
    ip netns del "$NSA" 2>/dev/null || true
    ip netns del "$NSB" 2>/dev/null || true
    ip link del "$A" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "[!] $*" >&2; exit 1; }

echo "[*] veth + two netns (A 10.9.52.1, B 10.9.52.2)"
ip netns del "$NSA" 2>/dev/null || true
ip netns del "$NSB" 2>/dev/null || true
ip netns add "$NSA"; ip netns add "$NSB"
ip link add "$A" address 02:00:0a:09:34:01 type veth \
    peer name "$B" address 02:00:0a:09:34:02
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add 10.9.52.1/24 brd 10.9.52.255 dev "$A"
ip -n "$NSB" addr add 10.9.52.2/24 brd 10.9.52.255 dev "$B"
for pair in "$NSA $A" "$NSB $B"; do
    set -- $pair
    ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off \
        >/dev/null 2>&1 || true
    ip -n "$1" link set lo up
    ip -n "$1" link set "$2" up
done
sleep 1

#: The static routes each router exports, besides its connected
#: 10.9.52.0/24. RIPv1 carries no subnet mask (RFC 1058 §3.2), and BIRD
#: sends a v1 router only classful networks, never a subnet such as the
#: connected /24, so the v1 routes are a class A, B and C network.
V2_ROUTES_A="10.20.1.0/24 10.20.2.0/24 10.20.3.128/25"
V2_ROUTES_B="10.30.1.0/24 10.30.2.0/24 10.30.3.128/25"
V1_ROUTES_A="10.0.0.0/8 172.20.0.0/16 192.0.2.0/24"
V1_ROUTES_B="11.0.0.0/8 172.30.0.0/16 198.51.100.0/24"

bird_conf() {  # router-id interface routes interface-options
    echo "router id $1;"
    echo 'protocol device {}'
    echo "protocol direct { ipv4; interface \"$2\"; }"
    echo 'protocol static {'
    echo '    ipv4;'
    local route
    for route in $3; do
        echo "    route $route blackhole;"
    done
    echo '}'
    echo 'protocol rip {'
    echo '    ipv4 { import all; export all; };'
    echo "    interface \"$2\" { update time 5; $4 };"
    echo '}'
}

scenario() {  # name interface-options [routes-a routes-b]
    local name=$1 options=$2
    local routes_a=${3:-$V2_ROUTES_A} routes_b=${4:-$V2_ROUTES_B}
    echo "[>] rip: $name"
    bird_conf 10.9.52.1 "$A" "$routes_a" "$options" >"$WORK/a.conf"
    bird_conf 10.9.52.2 "$B" "$routes_b" "$options" >"$WORK/b.conf"
    ip netns exec "$NSA" tcpdump -i "$A" -w "$WORK/$name.pcap" \
        --immediate-mode -U -q 'udp port 520' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
    ip netns exec "$NSA" bird -f -c "$WORK/a.conf" -s "$WORK/a.ctl" \
        -P "$WORK/a.pid" &
    BIRD_A=$!
    ip netns exec "$NSB" bird -f -c "$WORK/b.conf" -s "$WORK/b.ctl" \
        -P "$WORK/b.pid" &
    BIRD_B=$!
    # Past two 5-second update intervals, so a periodic update is sent.
    sleep 12
    kill -0 "$BIRD_A" 2>/dev/null || fail "$name: BIRD on A exited early."
    kill -0 "$BIRD_B" 2>/dev/null || fail "$name: BIRD on B exited early."
    stop "$BIRD_A"; BIRD_A=
    stop "$BIRD_B"; BIRD_B=
    sleep 1
    kill -INT "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
    TCPDUMP_PID=
}

scenario v1 'version 1; mode broadcast;' "$V1_ROUTES_A" "$V1_ROUTES_B"
scenario v2 'version 2; mode multicast;'
scenario plaintext \
    'version 2; mode multicast; authentication plaintext; password "nprip-pw";'
scenario md5 'version 2; mode multicast; authentication cryptographic;
    password "nprip-md5-key" { id 1; algorithm keyed md5; };'
scenario sha256 'version 2; mode multicast; authentication cryptographic;
    password "nprip-sha256-key" { id 2; algorithm hmac sha256; };'

echo "[*] Selecting and checking the fixture frames..."
python3 - "$WORK" "$OUT/rip.pcap" <<'PY'
import struct
import sys
from pathlib import Path

work, out = Path(sys.argv[1]), Path(sys.argv[2])
A, B = bytes([10, 9, 52, 1]), bytes([10, 9, 52, 2])
NAMES = {A: "A", B: "B"}


def records(path):
    data = path.read_bytes()
    if data[:4] != b"\xd4\xc3\xb2\xa1":
        sys.exit(f"{path.name}: not a little-endian microsecond pcap")
    cursor = 24
    while cursor + 16 <= len(data):
        _, _, incl, orig = struct.unpack_from("<IIII", data, cursor)
        record = data[cursor : cursor + 16 + incl]
        if len(record) != 16 + incl or incl != orig:
            sys.exit(f"{path.name}: truncated record at byte {cursor}")
        yield data[:24], struct.unpack_from("<I", data, cursor)[0], record
        cursor += 16 + incl
    if cursor != len(data):
        sys.exit(f"{path.name}: {len(data) - cursor} stray bytes")


def describe(frame):
    """(sender, version, command, auth type, route entries) of one
    frame, read independently of netprotocols."""
    ihl = (frame[14] & 0x0F) * 4
    ip, udp = frame[14:], frame[14 + ihl :]
    if ip[9] != 17 or struct.unpack_from("!HH", udp) != (520, 520):
        sys.exit("a captured frame is not RIP between ports 520")
    rip = udp[8 : struct.unpack_from("!H", udp, 4)[0]]
    command, version = rip[0], rip[1]
    end, auth = len(rip), 0
    if rip[4:6] == b"\xff\xff":
        auth = struct.unpack_from("!H", rip, 6)[0]
        if auth == 3:
            end = struct.unpack_from("!H", rip, 8)[0]
    routes = [
        rip[cursor : cursor + 20]
        for cursor in range(4, end, 20)
        if rip[cursor : cursor + 2] != b"\xff\xff"
    ]
    return NAMES[ip[12:16]], version, command, auth, routes


selected = []
header = None
expected = []
for name, version, auth in (
    ("v1", 1, 0),
    ("v2", 2, 0),
    ("plaintext", 2, 2),
    ("md5", 2, 3),
    ("sha256", 2, 3),
):
    frames = list(records(work / f"{name}.pcap"))
    header = header or frames[0][0]
    start = frames[0][1]
    wanted = [("A", 1), ("B", 1), ("A", 2), ("B", 2)]
    for want in wanted:
        for _, _, record in frames:
            sender, _, command, _, _ = describe(record[16:])
            if (sender, command) == want:
                selected.append((name, record))
                break
        else:
            sys.exit(f"{name}: no {want} message captured")
    # A Request is the one whole-table entry (AFI 0, metric 16).
    for router in "AB":
        expected += [(name, router, version, 1, auth, 1)]
    # A first Response advertises the router's three static routes and,
    # over RIPv2 only, its connected /24.
    for router in "AB":
        expected += [(name, router, version, 2, auth, 3 if version == 1 else 4)]
    if name == "v2":
        for _, second, record in frames:
            sender, _, command, _, routes = describe(record[16:])
            if sender == "A" and command == 2 and second >= start + 6:
                selected.append((name, record))
                break
        else:
            sys.exit("v2: no periodic Response from A captured")
        expected.append((name, "A", 2, 2, 0, 7))

seen = []
for name, record in selected:
    sender, version, command, auth, routes = describe(record[16:])
    if command == 1 and [(r[:2], r[16:]) for r in routes] != [
        (b"\x00\x00", b"\x00\x00\x00\x10")
    ]:
        sys.exit(f"{name}: {sender}'s Request is not a whole-table request")
    seen.append((name, sender, version, command, auth, len(routes)))
order = sorted(seen), sorted(expected)
if order[0] != order[1]:
    sys.exit(f"[!] Unexpected selection: {seen}, expected {expected}")
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
echo "[i] Expect udp + rip counts, rip-md5 and rip-hmac-sha256 digests"
echo "    verified, and zero failures. Fold tests/fixtures/staging/rip.pcap"
echo "    into tests/fixtures/."
