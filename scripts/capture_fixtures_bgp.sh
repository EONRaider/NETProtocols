#!/usr/bin/env bash
# Capture BGP-4 fixtures (RFC 4271) between real BGP speakers.
#
#     sudo scripts/capture_fixtures_bgp.sh
#
# Three BIRD 2 instances, each in its own netns, share one Linux bridge
# in a fourth: A (AS 65001, 10.185.0.1) holds an eBGP session with B
# (AS 65002, 10.185.0.2) and an iBGP session with C (AS 65001,
# 10.185.0.3). tcpdump on the bridge sees both sessions in one capture.
# The script then drives the sessions through:
#
#   1. session establishment: an OPEN each way on each session (with
#      BIRD's capabilities -- 4-byte ASNs, route refresh, graceful
#      restart and the rest -- in their Optional Parameters), and the
#      KEEPALIVEs that confirm them and keep them up (keepalive time 3);
#   2. the initial UPDATEs, each speaker's routes written as one burst
#      when its session comes up: A originates five prefixes of
#      different lengths, each with its own MULTI_EXIT_DISC, so they
#      cannot share an UPDATE and go out back to back, several BGP
#      messages to one TCP segment; B, whose session is enabled only
#      once A-C is up, originates two prefixes with a MED and 600 /24s
#      without one, which BIRD packs into a few UPDATEs, written back
#      to back, so messages straddle segment boundaries; C originates
#      one; A passes B's routes on to C over iBGP, with LOCAL_PREF (some
#      of those UPDATEs longer than a 1448-byte segment), and C's to B;
#   3. a withdrawal: A disables its five prefixes, so UPDATEs carrying
#      Withdrawn Routes go to B and C;
#   4. a shutdown: A disables both sessions, sending each peer a
#      NOTIFICATION (Cease, Administrative Shutdown, RFC 4486) that
#      carries an RFC 8203 shutdown communication, and withdrawing B's
#      602 routes from C.
#
# Two pcaps come out of the one capture:
#
#   tests/fixtures/staging/bgp/bgp_session.pcap  every frame, handshake,
#       bare ACKs and the segments cut mid-message included. It belongs
#       in tests/fixtures/bgp/, outside the corpus's non-recursive
#       *.pcap globs, because a bare ACK or a segment that starts or
#       ends inside a BGP message is not a frame decode_frame() walks
#       cleanly in strict mode (TCP delivers a byte stream, not
#       messages; reassembly is the caller's -- see SECURITY.md).
#   tests/fixtures/staging/bgp.pcap  the corpus frames: every segment
#       whose payload is a whole number of complete BGP messages, except
#       that of those carrying only a KEEPALIVE the first in each
#       direction of each session is kept (see the selection step).
#
# veth is a purely local link, so tx/rx checksum offload is disabled
# (ethtool -K) or the kernel leaves the TCP checksums to "offload" and
# never computes them; TSO/GSO/GRO go too, so no segment is built or
# coalesced beyond the 1460-byte MSS. check_fixtures.py verifies every
# TCP checksum, which covers the BGP messages.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump bird birdc python3 ethtool; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT/bgp"
NSW=npbgp-sw
NSA=npbgp-a
NSB=npbgp-b
NSC=npbgp-c
BR=npbgp-br
WORK=
TCPDUMP_PID=
BIRD_PIDS=()
cleanup() {
    for pid in "${BIRD_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    [[ -n $TCPDUMP_PID ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
    for ns in "$NSA" "$NSB" "$NSC" "$NSW"; do
        ip netns del "$ns" 2>/dev/null || true
    done
    [[ -n $WORK ]] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

no_offload() {
    # $1 netns, $2 device
    ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off >/dev/null
}

echo "[*] bridge $BR in $NSW; A 10.185.0.1, B 10.185.0.2, C 10.185.0.3"
ip netns add "$NSW"
ip -n "$NSW" link add "$BR" type bridge
for host in a b c; do
    ns="npbgp-$host"
    ip netns add "$ns"
    ip -n "$NSW" link add "npbgp-${host}0" type veth peer name "npbgp-${host}1" netns "$ns"
    ip -n "$NSW" link set "npbgp-${host}0" master "$BR"
    no_offload "$NSW" "npbgp-${host}0"
    no_offload "$ns" "npbgp-${host}1"
    ip -n "$NSW" link set "npbgp-${host}0" up
    ip -n "$ns" link set lo up
    ip -n "$ns" link set "npbgp-${host}1" up
done
ip -n "$NSA" addr add 10.185.0.1/24 dev npbgp-a1
ip -n "$NSB" addr add 10.185.0.2/24 dev npbgp-b1
ip -n "$NSC" addr add 10.185.0.3/24 dev npbgp-c1
ip -n "$NSW" link set "$BR" up

# A: five prefixes of different lengths (RFC 5737 documentation space),
# each with its own MED so that each needs an UPDATE of its own.
cat >"$WORK/a.conf" <<'EOF'
router id 10.185.0.1;
protocol device {}
protocol static s_a {
    ipv4;
    route 192.0.2.0/24 blackhole { bgp_med = 10; };
    route 198.51.100.0/25 blackhole { bgp_med = 20; };
    route 198.51.100.128/26 blackhole { bgp_med = 30; };
    route 203.0.113.0/27 blackhole { bgp_med = 40; };
    route 203.0.113.255/32 blackhole { bgp_med = 50; };
}
protocol bgp peer_b {
    local 10.185.0.1 as 65001;
    neighbor 10.185.0.2 as 65002;
    hold time 9; keepalive time 3; connect retry time 1;
    ipv4 { import all; export all; };
}
protocol bgp peer_c {
    local 10.185.0.1 as 65001;
    neighbor 10.185.0.3 as 65001;
    hold time 9; keepalive time 3; connect retry time 1;
    ipv4 { import all; export all; next hop self; };
}
EOF

# B: two prefixes, and 600 /24s (10.200.0.0-10.202.87.0) that share one
# attribute set and so one UPDATE.
{
    cat <<'EOF'
router id 10.185.0.2;
protocol device {}
protocol static s_b {
    ipv4;
    route 172.16.0.0/16 blackhole { bgp_med = 5; };
    route 172.17.1.0/24 blackhole { bgp_med = 5; };
}
protocol bgp peer_a {
    disabled;
    local 10.185.0.2 as 65002;
    neighbor 10.185.0.1 as 65001;
    hold time 9; keepalive time 3; connect retry time 1;
    ipv4 { import all; export all; };
}
protocol static s_bulk {
    ipv4;
EOF
    for i in $(seq 0 599); do
        echo "    route 10.$((200 + i / 256)).$((i % 256)).0/24 blackhole;"
    done
    echo "}"
} >"$WORK/b.conf"

cat >"$WORK/c.conf" <<'EOF'
router id 10.185.0.3;
protocol device {}
protocol static s_c {
    ipv4;
    route 100.64.0.0/10 blackhole;
}
protocol bgp peer_a {
    local 10.185.0.3 as 65001;
    neighbor 10.185.0.1 as 65001;
    hold time 9; keepalive time 3; connect retry time 1;
    ipv4 { import all; export all; };
}
EOF

birdc_in() {
    # $1 host letter, then the birdc command
    local host=$1
    shift
    birdc -s "$WORK/$host.ctl" "$@"
}

echo "[>] bgp (BIRD on A, B and C)"
ip netns exec "$NSW" tcpdump -i "$BR" -w "$OUT/bgp/bgp_session.pcap" \
    --immediate-mode -U -q 'tcp port 179' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

for host in a b c; do
    ip netns exec "npbgp-$host" bird -f -c "$WORK/$host.conf" \
        -s "$WORK/$host.ctl" -P "$WORK/$host.pid" >"$WORK/$host.log" 2>&1 &
    BIRD_PIDS+=($!)
done

established() {
    # $1 host letter, $2 protocol name
    birdc_in "$1" show protocols "$2" 2>/dev/null | grep -q Established
}
wait_for() {
    # $1 host letter, $2 protocol name
    for _ in $(seq 60); do
        established "$1" "$2" && return 0
        sleep 0.5
    done
    return 1
}
# B's session is enabled only once A-C is up and every static route is
# in B's table, so that B's routes go out as one burst, in an order
# that does not depend on how fast the daemons start.
echo "[i] Waiting for the A-C session..."
wait_for a peer_c || { echo "A-C session never came up." >&2; exit 1; }
sleep 2
birdc_in b enable peer_a >/dev/null
echo "[i] Waiting for the A-B session..."
wait_for a peer_b || { echo "A-B session never came up." >&2; exit 1; }

# A few keepalive intervals, so the steady state is in the capture too.
sleep 7

echo "[i] Withdrawal from A..."
birdc_in a disable s_a >/dev/null
sleep 4

echo "[i] Shutdown from A..."
birdc_in a disable peer_b '"NETProtocols fixture shutdown"' >/dev/null
birdc_in a disable peer_c '"NETProtocols fixture shutdown"' >/dev/null
sleep 3

for pid in "${BIRD_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
done
BIRD_PIDS=()
sleep 1
kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=

# Split the capture: every frame stays in bgp/bgp_session.pcap; the
# corpus file keeps the frames whose TCP payload is a whole number of
# complete BGP messages -- all of them, except that of the frames
# carrying nothing but a KEEPALIVE only the first in each direction of
# each session is kept (the rest differ only in their TCP fields). Then
# assert what the session carried, reassembled per direction, and what
# the corpus file holds. Stdlib only: this must not trust the library
# it produces fixtures for.
SPLIT_PY=$(cat <<'PY'
import struct
import sys
from collections import Counter, defaultdict

MARKER = b"\xff" * 16
A, B, C = "10.185.0.1", "10.185.0.2", "10.185.0.3"
OPEN, UPDATE, NOTIFICATION, KEEPALIVE = 1, 2, 3, 4


def read_pcap(path):
    raw = open(path, "rb").read()
    assert raw[:4] == b"\xd4\xc3\xb2\xa1", "expected a little-endian classic pcap"
    assert struct.unpack_from("<I", raw, 20)[0] == 1, "expected Ethernet framing"
    records, offset = [], 24
    while offset < len(raw):
        caplen, wirelen = struct.unpack_from("<II", raw, offset + 8)
        assert caplen == wirelen, "a frame was cut by the snap length"
        records.append(raw[offset : offset + 16 + caplen])
        offset += 16 + caplen
    return raw[:24], records


def segment(record):
    """(src, dst, seq, TCP payload) of one Ethernet/IPv4/TCP frame."""
    frame = record[16:]
    assert frame[12:14] == b"\x08\x00", "not IPv4"
    ip = frame[14:]
    assert ip[9] == 6, "not TCP"
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack_from("!H", ip, 2)[0]
    assert total == len(ip), "the IPv4 datagram is padded or cut"
    tcp = ip[ihl:total]
    assert 179 in struct.unpack_from("!HH", tcp), "not BGP's port"
    src = ".".join(map(str, ip[12:16]))
    dst = ".".join(map(str, ip[16:20]))
    seq = struct.unpack_from("!I", tcp, 4)[0]
    return src, dst, seq, tcp[(tcp[12] >> 4) * 4 :]


def messages(stream):
    """The (offset, type, body) of each message of a reassembled stream,
    which must be a whole number of messages."""
    found, at = [], 0
    while at < len(stream):
        assert stream[at : at + 16] == MARKER, f"no marker at {at}"
        length, type_ = struct.unpack_from("!HB", stream, at + 16)
        assert 19 <= length and at + length <= len(stream), f"bad length at {at}"
        found.append((at, type_, stream[at + 19 : at + length]))
        at += length
    return found


def prefixes(raw):
    found, at = [], 0
    while at < len(raw):
        bits = raw[at]
        assert bits <= 32, "an IPv4 prefix longer than 32 bits"
        found.append(raw[at : at + 1 + (bits + 7) // 8])
        at += 1 + (bits + 7) // 8
    assert at == len(raw), "a prefix list overruns"
    return found


def update_parts(body):
    """(withdrawn prefixes, attribute type codes, NLRI prefixes)."""
    withdrawn_len = struct.unpack_from("!H", body)[0]
    at = 2 + withdrawn_len
    attrs_len = struct.unpack_from("!H", body, at)[0]
    attrs = body[at + 2 : at + 2 + attrs_len]
    codes, cursor = [], 0
    while cursor < len(attrs):
        flags, code = attrs[cursor], attrs[cursor + 1]
        if flags & 0x10:
            cursor += 4 + struct.unpack_from("!H", attrs, cursor + 2)[0]
        else:
            cursor += 3 + attrs[cursor + 2]
        codes.append(code)
    assert cursor == len(attrs), "the path attributes overrun"
    return (
        prefixes(body[2 : 2 + withdrawn_len]),
        codes,
        prefixes(body[at + 2 + attrs_len :]),
    )


session_path, corpus_path = sys.argv[1], sys.argv[2]
header, records = read_pcap(session_path)

# Reassemble each direction (veth neither reorders nor drops, which the
# sequence numbers confirm), then place every segment on its stream.
streams = defaultdict(bytes)
placed = []
next_seq = {}
for record in records:
    src, dst, seq, payload = segment(record)
    direction = (src, dst)
    if payload:
        if direction in next_seq:
            assert seq == next_seq[direction], f"{src}->{dst} out of order"
        next_seq[direction] = (seq + len(payload)) & 0xFFFFFFFF
    placed.append((record, direction, len(streams[direction]), len(payload)))
    streams[direction] += payload


def prefix(text):
    """The wire form of a dotted prefix, e.g. "192.0.2.0/24"."""
    address, bits = text.split("/")
    octets = bytes(map(int, address.split(".")))
    return bytes([int(bits)]) + octets[: (int(bits) + 7) // 8]


# Which UPDATE carries which prefixes is BIRD's choice and varies from
# run to run (it caps an UPDATE's NLRI well short of 4096 bytes, and
# packs whatever is queued when it writes), so what is checked exactly
# is what each direction announced and withdrew, and which attributes
# came with it.
A_OWN = {
    prefix(p)
    for p in (
        "192.0.2.0/24",
        "198.51.100.0/25",
        "198.51.100.128/26",
        "203.0.113.0/27",
        "203.0.113.255/32",
    )
}
B_MED = {prefix("172.16.0.0/16"), prefix("172.17.1.0/24")}
B_OWN = B_MED | {prefix(f"10.{200 + i // 256}.{i % 256}.0/24") for i in range(600)}
WITH_MED = A_OWN | B_MED
C_OWN = {prefix("100.64.0.0/10")}
expected = {  # direction: (announced, withdrawn)
    (A, B): (A_OWN | C_OWN, A_OWN),
    (B, A): (B_OWN, set()),
    (A, C): (A_OWN | B_OWN, A_OWN | B_OWN),
    (C, A): (C_OWN, set()),
}
assert set(streams) == set(expected), sorted(streams)
parsed = {}
for direction, stream in sorted(streams.items()):
    found = messages(stream)
    parsed[direction] = found
    types = Counter(type_ for _, type_, _ in found)
    assert set(types) <= {OPEN, UPDATE, NOTIFICATION, KEEPALIVE}, types
    assert types[OPEN] == 1, f"{direction}: {types}"
    assert types[KEEPALIVE] >= 2, f"{direction}: {types}"
    assert types[NOTIFICATION] == (direction[0] == A), f"{direction}: {types}"
    announced, withdrawn = [], []
    for _, type_, body in found:
        if type_ == NOTIFICATION:
            assert body[:2] == b"\x06\x02", "not Cease / Administrative Shutdown"
        if type_ != UPDATE:
            continue
        gone, codes, nlri = update_parts(body)
        withdrawn += gone
        announced += nlri
        if nlri:  # ORIGIN, AS_PATH, NEXT_HOP; LOCAL_PREF over iBGP
            assert {1, 2, 3} <= set(codes), f"{direction}: {codes}"
            assert (5 in codes) == (C in direction), f"{direction}: {codes}"
            assert (4 in codes) == (set(nlri) <= WITH_MED), f"{direction}: MED"
    assert len(announced) == len(set(announced)), f"{direction} repeats"
    assert len(withdrawn) == len(set(withdrawn)), f"{direction} repeats"
    assert (set(announced), set(withdrawn)) == expected[direction], direction
    print(
        f"[+] {direction[0]} -> {direction[1]}: {dict(sorted(types.items()))}, "
        f"{len(announced)} prefixes announced, {len(withdrawn)} withdrawn"
    )

# Each segment: does it start and end on a message boundary, and how
# many messages does it hold whole?
kinds = Counter()
kept, keepalive_only_seen = [], set()
for record, direction, start, length in placed:
    if not length:
        kinds["bare"] += 1
        continue
    end = start + length
    bounds = [(at, at + 19 + len(body), type_) for at, type_, body in parsed[direction]]
    whole = [type_ for at, stop, type_ in bounds if start <= at and stop <= end]
    starts_inside = all(at != start for at, _, _ in bounds)
    ends_inside = all(stop != end for _, stop, _ in bounds)
    if starts_inside:
        kinds["starts inside a message"] += 1
    if ends_inside:
        kinds["ends inside a message"] += 1
        if whole and not starts_inside:
            kinds["whole messages, then a cut one"] += 1
    if starts_inside or ends_inside:
        continue
    kinds["whole messages only"] += 1
    if len(whole) > 1:
        kinds["several whole messages"] += 1
    if set(whole) == {KEEPALIVE}:
        if direction in keepalive_only_seen:
            continue
        keepalive_only_seen.add(direction)
    kept.append((record, direction, whole))
for kind in (
    "several whole messages",
    "whole messages, then a cut one",
    "starts inside a message",
):
    assert kinds[kind], f"no segment of the kind: {kind}"
print(f"[+] {len(records)} frames: {dict(sorted(kinds.items()))}")

# The corpus file.
with open(corpus_path, "wb") as out:
    out.write(header)
    for record, *_ in kept:
        out.write(record)
kept_types = Counter(type_ for *_, whole in kept for type_ in whole)
keepalive_only = sum(set(whole) == {KEEPALIVE} for *_, whole in kept)
assert kept_types[OPEN] == 4, kept_types
assert kept_types[NOTIFICATION] == 2, kept_types
assert keepalive_only == 4, keepalive_only
deepest = max(len(whole) for *_, whole in kept)
assert 1 < deepest <= 29, f"a corpus frame carries {deepest} BGP messages"
print(
    f"[+] corpus: {len(kept)} frames, {dict(sorted(kept_types.items()))}, "
    f"at most {deepest} messages in one segment"
)
PY
)

echo
echo "[*] Splitting and checking the composition..."
python3 -c "$SPLIT_PY" "$OUT/bgp/bgp_session.pcap" "$OUT/bgp.pcap"

echo
echo "[*] Validating..."
CHECKER_PY=$(command -v python3)
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT/bgp"
else
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT/bgp"
fi

echo
echo "[i] Expect zero checksum failures. Fold tests/fixtures/staging/bgp.pcap"
echo "    into tests/fixtures/ and tests/fixtures/staging/bgp/bgp_session.pcap"
echo "    into tests/fixtures/bgp/."
