#!/usr/bin/env bash
# Capture an OSPFv2 fixture for the corpus (RFC 2328).
#
#     sudo scripts/capture_fixtures_ospf.sh
#
# Two FRR routers (zebra + ospfd, FRR 8.4) in two netns over a veth
# pair, one broadcast network in area 0, so each frame is Ethernet ->
# IPv4 (protocol 89) -> OSPF. Router A (router ID 10.0.0.1, priority 10)
# also redistributes a connected /32 on its loopback (192.0.2.1, RFC
# 5737), so its database holds an AS-external LSA as well as its
# router LSA.
#
# Three adjacencies are brought up in turn, one per authentication type
# (RFC 2328 Appendix D), each from freshly started daemons:
#
#   AuType 0, no authentication.
#   AuType 1, simple password ("NPospf1", published in MANIFEST.md).
#   AuType 2, cryptographic: keyed MD5 (RFC 2328 §D.4.3), key ID 1, key
#             "NETProtocols-md5" (published in MANIFEST.md). The packet
#             checksum is not computed (FRR sends 0), and a 16-byte
#             digest follows each packet, outside its Packet Length.
#
# For each, router A is started first and left alone until it has
# elected itself Designated Router, off the capture. Only then does the
# capture start and router B come up: B hears A's Hello declaring
# itself DR, leaves its Waiting state at once (RFC 2328 §9.2,
# BackupSeen), and the whole adjacency -- Hellos to 2-Way, the Database
# Description exchange, Link State Requests, Link State Updates
# (router, network and AS-external LSAs) and Link State
# Acknowledgments -- is captured within seconds instead of after a
# 40 s wait timer. The capture of each adjacency stops once both
# routers report each other Full and hold all four LSAs, plus a few
# seconds for the delayed acknowledgments; it stops before any daemon
# is killed, so no shutdown flush is captured.
#
# The three captures are concatenated into one pcap, in that order.
# Both directions are kept: tcpdump runs on B's side of the veth pair,
# with offload disabled on both ends. Every OSPF byte is built by
# ospfd in userspace, packet checksum and LSA checksums included; the
# kernel builds the IPv4 header (TOS 0xc0, TTL 1) and the Ethernet
# header. check_fixtures.py verifies the IPv4 header checksum, every
# OSPF packet checksum (AuType 0 and 1), every MD5 digest (AuType 2)
# with the published key, and every LSA's Fletcher checksum.
#
# The script then asserts the capture is the one described: every frame
# is OSPFv2 with no data after the packet (no LLS block, RFC 5613: the
# IP payload is exactly Packet Length, plus the digest under AuType 2,
# and no Hello or Database Description sets the L bit), and the three
# segments carry AuType 0, 1 and 2 in turn. Each segment must hold
# exactly 6 Hellos, 5 Database Descriptions, 2 Link State Requests and
# 2 Link State Acknowledgments, and its updates exactly six LSAs: two
# router LSAs from each router (each re-originates its own once the
# adjacency is Full), A's network LSA (it is the DR) and A's AS-external
# LSA. Only how B's two router LSAs are packed is left open, as it
# varied between runs: together in one update or one per update, so 3
# or 4 updates. The Hello count depends on where the routers' 2 s hello
# timers fall, and was 6 in every segment of every run. A capture that
# differs stops the script, and must not be folded in.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool vtysh; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
FRR=/usr/lib/frr
for daemon in zebra ospfd; do
    if [[ ! -x $FRR/$daemon ]]; then
        echo "$FRR/$daemon is missing: install frr." >&2
        exit 1
    fi
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSA=npospf-a
NSB=npospf-b
A=npospf-va
B=npospf-vb
SIMPLE_KEY=NPospf1
MD5_KEY=NETProtocols-md5
# ospfd runs as the frr user, which cannot reach a directory under a
# private home or scratch area: give it a world-traversable one.
WORK=$(mktemp -d /tmp/npospf.XXXXXX)
chmod 755 "$WORK"
TCPDUMP_PID=
cleanup() {
    [[ -n $TCPDUMP_PID ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
    for ns in "$NSA" "$NSB"; do
        # Every process in our own namespaces is a daemon we started.
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
    done
    sleep 1
    ip netns del "$NSA" 2>/dev/null || true
    ip netns del "$NSB" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
ip netns del "$NSA" 2>/dev/null || true
ip netns del "$NSB" 2>/dev/null || true

echo "[*] veth + two netns (A 10.9.83.1, B 10.9.83.2)"
ip netns add "$NSA"; ip netns add "$NSB"
ip link add "$A" type veth peer name "$B"
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" link set "$A" address 02:00:5e:83:00:01
ip -n "$NSB" link set "$B" address 02:00:5e:83:00:02
ip -n "$NSA" addr add 10.9.83.1/24 dev "$A"
ip -n "$NSB" addr add 10.9.83.2/24 dev "$B"
ip -n "$NSA" addr add 192.0.2.1/32 dev lo
ip netns exec "$NSA" ethtool -K "$A" tx off rx off tso off gso off gro off >/dev/null
ip netns exec "$NSB" ethtool -K "$B" tx off rx off tso off gso off gro off >/dev/null
for ns in "$NSA" "$NSB"; do ip -n "$ns" link set lo up; done
ip -n "$NSA" link set "$A" up
ip -n "$NSB" link set "$B" up
sleep 1

# The ospfd interface lines for one authentication type.
auth_config() {
    case $1 in
        none) ;;
        simple)
            echo " ip ospf authentication"
            echo " ip ospf authentication-key $SIMPLE_KEY"
            ;;
        md5)
            echo " ip ospf authentication message-digest"
            echo " ip ospf message-digest-key 1 md5 $MD5_KEY"
            ;;
    esac
}

# start_router <segment> <a|b>: write the configs and start zebra and
# ospfd in that router's netns, with their own pid files, zebra socket
# and vty sockets under $WORK.
start_router() {
    local segment=$1 side=$2 ns dev rid priority dir
    if [[ $side == a ]]; then
        ns=$NSA dev=$A rid=10.0.0.1 priority=10
    else
        ns=$NSB dev=$B rid=10.0.0.2 priority=1
    fi
    dir=$WORK/$segment-$side
    mkdir -p "$dir"
    echo "hostname zebra-$side" >"$dir/zebra.conf"
    {
        echo "hostname ospfd-$side"
        echo "interface $dev"
        echo " ip ospf hello-interval 2"
        echo " ip ospf dead-interval 8"
        echo " ip ospf priority $priority"
        auth_config "$segment"
        echo "router ospf"
        echo " ospf router-id $rid"
        echo " network 10.9.83.0/24 area 0"
        [[ $side == a ]] && echo " redistribute connected"
        true
    } >"$dir/ospfd.conf"
    chown -R frr:frr "$dir"
    ip netns exec "$ns" "$FRR/zebra" -d -f "$dir/zebra.conf" -i "$dir/zebra.pid" \
        -z "$dir/zserv" --vty_socket "$dir" -A 127.0.0.1 -P 0 2>/dev/null
    ip netns exec "$ns" "$FRR/ospfd" -d -f "$dir/ospfd.conf" -i "$dir/ospfd.pid" \
        -z "$dir/zserv" --vty_socket "$dir" -A 127.0.0.1 -P 0 2>/dev/null
}

# vty <segment> <a|b> <command>
vty() {
    local ns=$NSA
    [[ $2 == b ]] && ns=$NSB
    ip netns exec "$ns" vtysh --vty_socket "$WORK/$1-$2" -c "$3" 2>/dev/null
}

# wait_until <seconds> <description> <command...>
wait_until() {
    local limit=$1 what=$2
    shift 2
    for _ in $(seq "$limit"); do
        "$@" && return 0
        sleep 1
    done
    echo "Timed out waiting for $what." >&2
    exit 1
}

a_is_dr() { vty "$1" a "show ip ospf interface $A" | grep -q "State DR"; }
both_full() {
    vty "$1" a "show ip ospf neighbor" | grep -q "Full/Backup" &&
        vty "$1" b "show ip ospf neighbor" | grep -q "Full/DR"
}
# Two router LSAs, A's network LSA and A's AS-external LSA, on both.
lsdb_complete() {
    local side out
    for side in a b; do
        out=$(vty "$1" "$side" "show ip ospf database")
        grep -q "^10.0.0.1 " <<<"$out" || return 1
        grep -q "^10.0.0.2 " <<<"$out" || return 1
        grep -q "^10.9.83.1 " <<<"$out" || return 1
        grep -q "^192.0.2.1 " <<<"$out" || return 1
    done
}

stop_routers() {
    for ns in "$NSA" "$NSB"; do
        ip netns pids "$ns" | xargs -r kill
    done
    for _ in $(seq 20); do
        [[ -z $(ip netns pids "$NSA")$(ip netns pids "$NSB") ]] && return 0
        sleep 0.5
    done
    echo "The routing daemons did not exit." >&2
    exit 1
}

for segment in none simple md5; do
    echo "[>] ospf, authentication: $segment"
    start_router "$segment" a
    wait_until 30 "router A to become DR ($segment)" a_is_dr "$segment"
    ip netns exec "$NSB" tcpdump -i "$B" -w "$OUT/ospf-$segment.part" -U -q \
        'ip proto 89' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
    start_router "$segment" b
    wait_until 40 "a Full adjacency ($segment)" both_full "$segment"
    wait_until 20 "both databases to fill ($segment)" lsdb_complete "$segment"
    # FRR delays its acknowledgments (RFC 2328 §13.5) by about a second.
    sleep 4
    kill -INT "$TCPDUMP_PID"
    wait "$TCPDUMP_PID" || true
    TCPDUMP_PID=
    stop_routers
done

# Concatenate the three classic pcaps: one file header, then every
# record of each in turn.
MERGE_PY=$(cat <<'PY'
import sys

out, parts = sys.argv[1], sys.argv[2:]
blobs = [open(path, "rb").read() for path in parts]
headers = {blob[:24] for blob in blobs}
assert len(headers) == 1, "the three captures disagree on their pcap header"
with open(out, "wb") as sink:
    sink.write(blobs[0][:24])
    for blob in blobs:
        sink.write(blob[24:])
PY
)
python3 -c "$MERGE_PY" "$OUT/ospf.pcap" \
    "$OUT/ospf-none.part" "$OUT/ospf-simple.part" "$OUT/ospf-md5.part"
rm -f "$OUT"/ospf-*.part

echo
echo "[*] Validating..."
CHECKER_PY=$(command -v python3)
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
else
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
fi

COMPOSITION_PY=$(cat <<'PY'
import struct
import sys
from collections import Counter

raw = open(sys.argv[1], "rb").read()
assert raw[:4] == b"\xd4\xc3\xb2\xa1", "expected a little-endian classic pcap"
assert struct.unpack_from("<I", raw, 20)[0] == 1, "expected Ethernet framing"
frames = []
offset = 24
while offset < len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    frames.append(raw[offset + 16 : offset + 16 + caplen])
    offset += 16 + caplen

NAMES = {1: "Hello", 2: "DBD", 3: "LSR", 4: "LSU", 5: "LSAck"}
A, B = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])
segments: list[tuple[int, Counter, Counter]] = []
for number, frame in enumerate(frames, 1):
    assert frame[12:14] == b"\x08\x00", f"frame {number} is not IPv4"
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    assert ihl == 20 and ip[9] == 89, f"frame {number} is not plain OSPF"
    total = struct.unpack_from("!H", ip, 2)[0]
    assert total == len(ip), f"frame {number} carries link-layer padding"
    ospf = ip[ihl:total]
    version, kind, length = struct.unpack_from("!BBH", ospf)
    assert version == 2, f"frame {number} is OSPF version {version}"
    au_type = ospf[15]  # byte 14 is the Instance ID (RFC 6549 §2)
    trailer = ospf[19] if au_type == 2 else 0
    # Nothing after the packet but the digest: no LLS block (RFC 5613).
    assert len(ospf) == length + trailer, f"frame {number} carries extra data"
    if kind in (1, 2):
        options = ospf[24 + 6] if kind == 1 else ospf[24 + 2]
        assert not options & 0x10, f"frame {number} sets the L bit"
    if not segments or segments[-1][0] != au_type:
        segments.append((au_type, Counter(), Counter()))
    _, kinds, lsas = segments[-1]
    kinds[NAMES[kind]] += 1
    if kind == 4:
        cursor = 28
        for _ in range(struct.unpack_from("!I", ospf, 24)[0]):
            lsas[(ospf[cursor + 3], ospf[cursor + 8 : cursor + 12])] += 1
            cursor += struct.unpack_from("!H", ospf, cursor + 18)[0]
        assert cursor == length, f"frame {number}'s LSAs do not fill it"

assert [au for au, _, _ in segments] == [0, 1, 2], (
    f"expected AuType 0, 1, 2 in turn, got {[au for au, _, _ in segments]}"
)
MESSAGES = Counter({"Hello": 6, "DBD": 5, "LSR": 2, "LSAck": 2})
# (LS type, advertising router): router (1), network (2), external (5).
LSAS = Counter({(1, A): 2, (2, A): 1, (5, A): 1, (1, B): 2})
for au_type, kinds, lsas in segments:
    print(
        f"[+] AuType {au_type}: {sum(kinds.values())} frames, "
        + ", ".join(f"{NAMES[k]} {kinds[NAMES[k]]}" for k in NAMES)
        + f"; {sum(lsas.values())} LSAs"
    )
    updates = kinds.pop("LSU")
    assert kinds == MESSAGES, f"AuType {au_type}: unexpected messages {kinds}"
    assert updates in (3, 4), f"AuType {au_type}: {updates} updates"
    assert lsas == LSAS, f"AuType {au_type}: unexpected LSAs {lsas}"
print(f"[+] {len(frames)} OSPFv2 frames")
PY
)
python3 -c "$COMPOSITION_PY" "$OUT/ospf.pcap"

echo
echo "[i] Expect zero checksum failures. Fold tests/fixtures/staging/ospf.pcap"
echo "    into tests/fixtures/."
