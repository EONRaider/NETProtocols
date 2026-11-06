#!/usr/bin/env bash
# Capture a multi-area OSPFv2 fixture for the corpus (RFC 2328, RFC
# 3101).
#
#     sudo scripts/capture_fixtures_ospf_areas.sh
#
# Four FRR routers (zebra + ospfd, FRR 8.4) in four netns, joined by
# three veth pairs, each its own broadcast network and area:
#
#   link 0, area 0.0.0.0 (backbone)  10.9.84.0/26    A .1   -- B .2
#   link 1, area 0.0.0.1             10.9.84.64/26   B .65  -- C .66
#   link 2, area 0.0.0.2 (NSSA)      10.9.84.128/26  B .129 -- D .130
#
#   A  router ID 10.0.0.1, backbone only.
#   B  router ID 10.0.0.2, the area border router of all three areas,
#      and the NSSA translator of area 2.
#   C  router ID 10.0.0.3, area 1, an AS boundary router: it
#      redistributes its connected 192.0.2.3/32 (RFC 5737), so it
#      originates an AS-external-LSA (type 5) and B describes it to the
#      backbone in an ASBR-summary-LSA (type 4).
#   D  router ID 10.0.0.4, area 2, an NSSA AS boundary router: it
#      redistributes its connected 192.0.2.4/32 as an NSSA-LSA (type
#      7), which B translates into an AS-external-LSA of its own.
#
# B summarizes each area's networks into the others in Summary-LSAs
# (type 3), and into the NSSA also sends a type-3 default route
# (0.0.0.0/0, metric 1). Every frame is Ethernet -> IPv4 (protocol 89)
# -> OSPF with no authentication (AuType 0).
#
# B and C are started first, off the capture, and left until B has
# elected itself Designated Router on links 0 and 2 (where it is
# alone) and B and C are Full on link 1. Two adjacencies are then
# captured in turn, each on B's side of its veth pair:
#
#   segment 1, link 2: D comes up. D hears B's Hello declaring itself
#              DR (RFC 2328 §9.2, BackupSeen), and the adjacency --
#              Hellos, the Database Description exchange, Link State
#              Requests, Link State Updates and Link State
#              Acknowledgments -- follows within seconds. The capture
#              stops once B and D are Full, B holds D's NSSA-LSA and
#              its own translation of it, and D holds B's router,
#              network and summary LSAs for area 2.
#   segment 2, link 0: A comes up in the same way. The capture stops
#              once A and B are Full and A holds every backbone LSA:
#              both router LSAs, B's network LSA, B's summaries of
#              areas 1 and 2, B's ASBR-summary of C, and the
#              AS-external LSAs of C and of B's translation.
#
# Each capture stops a few seconds after that, for the delayed
# acknowledgments, before any daemon is stopped, so no shutdown flush
# is captured. The two captures are concatenated into one pcap, link 2
# then link 0. Offload is disabled on both ends of every veth pair.
# Every OSPF byte is built by ospfd in userspace, packet checksum and
# LSA checksums included; the kernel builds the IPv4 header and the
# Ethernet header. check_fixtures.py verifies the IPv4 header checksum,
# every OSPF packet checksum and every LSA's Fletcher checksum.
#
# Right after each capture stops, the script records FRR's link-state
# database, as `show ip ospf database <type>` prints it, from both
# routers on the captured link into
# tests/fixtures/staging/ospf_areas_lsdb.txt; tests/test_ospf.py
# checks every decoded LSA body against the values it holds.
#
# The script then asserts every frame: Ethernet and IPv4 with protocol
# 89 and no link-layer padding, OSPFv2 with AuType 0, no data after the
# packet and no L bit (RFC 5613), and the LSAs of every update filling
# it. Each segment's frames must all be in its area, and must hold
# every message type and exactly the LSAs, by LS type, Link State ID
# and advertising router, listed in COMPOSITION_PY below. How many
# times each LSA is sent, and so the message counts, depends on timer
# alignment and is left open. A capture that differs stops the script,
# and must not be folded in.

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
LSDB="$OUT/ospf_areas_lsdb.txt"
ROUTERS=(a b c d)
declare -A NS=(
    [a]=npospfar-a [b]=npospfar-b [c]=npospfar-c [d]=npospfar-d
)
declare -A RID=(
    [a]=10.0.0.1 [b]=10.0.0.2 [c]=10.0.0.3 [d]=10.0.0.4
)
# The veth devices of links 0, 1 and 2: the other router's end and B's.
A0=npospfar-a0 B0=npospfar-b0
B1=npospfar-b1 C1=npospfar-c1
B2=npospfar-b2 D2=npospfar-d2
WORK=
TCPDUMP_PID=
cleanup() {
    if [[ -n $TCPDUMP_PID ]]; then kill "$TCPDUMP_PID" 2>/dev/null || true; fi
    for r in "${ROUTERS[@]}"; do
        # Every process in our own namespaces is a daemon we started.
        ip netns pids "${NS[$r]}" 2>/dev/null | xargs -r kill 2>/dev/null || true
    done
    sleep 1
    for r in "${ROUTERS[@]}"; do
        ip netns del "${NS[$r]}" 2>/dev/null || true
    done
    # A setup that failed between creating a veth pair and moving its
    # ends leaves one in the root namespace; deleting it removes its
    # peer as well.
    for dev in "$B0" "$B1" "$B2"; do
        ip link del "$dev" 2>/dev/null || true
    done
    if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
# ospfd runs as the frr user, which cannot reach a directory under a
# private home or scratch area: give it a world-traversable one.
WORK=$(mktemp -d /tmp/npospfar.XXXXXX)
chmod 755 "$WORK"

echo "[*] four netns, three veth pairs in 10.9.84.0/24"
for r in "${ROUTERS[@]}"; do
    ip netns add "${NS[$r]}"
    ip -n "${NS[$r]}" link set lo up
done
# link <b-side device> <other device> <other router> <link number>
#      <B's address> <other address>
link() {
    local bdev=$1 odev=$2 other=$3 n=$4 baddr=$5 oaddr=$6
    ip link add "$bdev" type veth peer name "$odev"
    ip link set "$bdev" netns "${NS[b]}"
    ip link set "$odev" netns "${NS[$other]}"
    ip -n "${NS[b]}" link set "$bdev" address "02:00:5e:84:0$n:02"
    ip -n "${NS[$other]}" link set "$odev" address "02:00:5e:84:0$n:01"
    ip -n "${NS[b]}" addr add "$baddr/26" dev "$bdev"
    ip -n "${NS[$other]}" addr add "$oaddr/26" dev "$odev"
    ip netns exec "${NS[b]}" ethtool -K "$bdev" tx off rx off tso off gso off gro off >/dev/null
    ip netns exec "${NS[$other]}" ethtool -K "$odev" tx off rx off tso off gso off gro off >/dev/null
    ip -n "${NS[b]}" link set "$bdev" up
    ip -n "${NS[$other]}" link set "$odev" up
}
link "$B0" "$A0" a 0 10.9.84.2 10.9.84.1
link "$B1" "$C1" c 1 10.9.84.65 10.9.84.66
link "$B2" "$D2" d 2 10.9.84.129 10.9.84.130
ip -n "${NS[c]}" addr add 192.0.2.3/32 dev lo
ip -n "${NS[d]}" addr add 192.0.2.4/32 dev lo
sleep 1

# interface_config <device> <priority>
interface_config() {
    echo "interface $1"
    echo " ip ospf hello-interval 2"
    echo " ip ospf dead-interval 8"
    echo " ip ospf priority $2"
}

# start_router <a|b|c|d>: write the configs and start zebra and ospfd
# in that router's netns, with their own pid files, zebra socket and
# vty sockets under $WORK. B has priority 10 on every link, the others
# 1, so B is every link's Designated Router.
start_router() {
    local r=$1 dir=$WORK/$1
    mkdir -p "$dir"
    echo "hostname zebra-$r" >"$dir/zebra.conf"
    {
        echo "hostname ospfd-$r"
        case $r in
            a) interface_config "$A0" 1 ;;
            b)
                interface_config "$B0" 10
                interface_config "$B1" 10
                interface_config "$B2" 10
                ;;
            c) interface_config "$C1" 1 ;;
            d) interface_config "$D2" 1 ;;
        esac
        echo "router ospf"
        echo " ospf router-id ${RID[$r]}"
        case $r in
            a) echo " network 10.9.84.0/26 area 0" ;;
            b)
                echo " network 10.9.84.0/26 area 0"
                echo " network 10.9.84.64/26 area 1"
                echo " network 10.9.84.128/26 area 2"
                echo " area 2 nssa"
                ;;
            c)
                echo " network 10.9.84.64/26 area 1"
                echo " redistribute connected"
                ;;
            d)
                echo " network 10.9.84.128/26 area 2"
                echo " area 2 nssa"
                echo " redistribute connected"
                ;;
        esac
    } >"$dir/ospfd.conf"
    chown -R frr:frr "$dir"
    ip netns exec "${NS[$r]}" "$FRR/zebra" -d -f "$dir/zebra.conf" \
        -i "$dir/zebra.pid" -z "$dir/zserv" --vty_socket "$dir" \
        -A 127.0.0.1 -P 0 2>/dev/null
    ip netns exec "${NS[$r]}" "$FRR/ospfd" -d -f "$dir/ospfd.conf" \
        -i "$dir/ospfd.pid" -z "$dir/zserv" --vty_socket "$dir" \
        -A 127.0.0.1 -P 0 2>/dev/null
}

# vty <a|b|c|d> <command>
vty() {
    ip netns exec "${NS[$1]}" vtysh --vty_socket "$WORK/$1" -c "$2" 2>/dev/null
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

# is_dr <router> <device>
is_dr() { vty "$1" "show ip ospf interface $2" | grep -q "State DR"; }
# full <router> <neighbor router ID>
full() { vty "$1" "show ip ospf neighbor" | grep -q "^${RID[$2]} .*Full/"; }
# holds <router> <database type> <Link State ID> <advertising router>
holds() {
    vty "$1" "show ip ospf database $2 $3" |
        grep -q "^  Advertising Router: $4\$"
}

b_and_c_ready() {
    is_dr b "$B0" && is_dr b "$B1" && is_dr b "$B2" && full b c && full c b &&
        holds b external 192.0.2.3 10.0.0.3 &&
        holds b asbr-summary 10.0.0.3 10.0.0.2
}
segment1_done() {
    full b d && full d b &&
        holds b nssa-external 192.0.2.4 10.0.0.4 &&
        holds b external 192.0.2.4 10.0.0.2 &&
        holds d router 10.0.0.2 10.0.0.2 &&
        holds d network 10.9.84.129 10.0.0.2 &&
        holds d summary 10.9.84.0 10.0.0.2 &&
        holds d summary 10.9.84.64 10.0.0.2
}
segment2_done() {
    full a b && full b a &&
        holds a router 10.0.0.1 10.0.0.1 &&
        holds a router 10.0.0.2 10.0.0.2 &&
        holds a network 10.9.84.2 10.0.0.2 &&
        holds a summary 10.9.84.64 10.0.0.2 &&
        holds a summary 10.9.84.128 10.0.0.2 &&
        holds a asbr-summary 10.0.0.3 10.0.0.2 &&
        holds a external 192.0.2.3 10.0.0.3 &&
        holds a external 192.0.2.4 10.0.0.2
}

# record_lsdb <segment> <router...>
record_lsdb() {
    local segment=$1 r kind
    shift
    for r in "$@"; do
        for kind in router network summary asbr-summary external nssa-external; do
            echo "### segment $segment, router ${RID[$r]}: show ip ospf database $kind"
            vty "$r" "show ip ospf database $kind"
        done
    done >>"$LSDB"
}

# capture <segment> <B's device> <router to start> <done predicate>
capture() {
    local segment=$1 dev=$2 joiner=$3 done=$4
    echo "[>] segment $segment: router ${RID[$joiner]} joins on $dev"
    ip netns exec "${NS[b]}" tcpdump -i "$dev" -w "$OUT/ospf_areas-$segment.part" \
        -U -q 'ip proto 89' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
    start_router "$joiner"
    wait_until 60 "segment $segment to converge" "$done"
    # FRR delays its acknowledgments (RFC 2328 §13.5) by about a second.
    sleep 4
    kill -INT "$TCPDUMP_PID"
    # tcpdump exits 0 on SIGINT; anything else means a broken capture.
    local status=0
    wait "$TCPDUMP_PID" || status=$?
    TCPDUMP_PID=
    if (( status != 0 )); then
        echo "tcpdump exited with status $status (segment $segment)." >&2
        exit 1
    fi
}

echo "[*] starting B and C off the capture"
start_router b
start_router c
wait_until 90 "B to be DR everywhere and Full with C" b_and_c_ready
: >"$LSDB"
capture 1 "$B2" d segment1_done
record_lsdb 1 b d
capture 2 "$B0" a segment2_done
record_lsdb 2 a b

# Concatenate the two classic pcaps: one file header, then every record
# of each in turn.
MERGE_PY=$(cat <<'PY'
import sys

out, parts = sys.argv[1], sys.argv[2:]
blobs = [open(path, "rb").read() for path in parts]
headers = {blob[:24] for blob in blobs}
assert len(headers) == 1, "the captures disagree on their pcap header"
with open(out, "wb") as sink:
    sink.write(blobs[0][:24])
    for blob in blobs:
        sink.write(blob[24:])
PY
)
python3 -c "$MERGE_PY" "$OUT/ospf_areas.pcap" \
    "$OUT/ospf_areas-1.part" "$OUT/ospf_areas-2.part"
rm -f "$OUT"/ospf_areas-*.part

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
import socket
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
# Each segment's area and every LSA its updates carry, as (LS type,
# Link State ID, advertising router).
EXPECTED = [
    (
        "0.0.0.2",
        {
            (1, "10.0.0.2", "10.0.0.2"),
            (1, "10.0.0.4", "10.0.0.4"),
            (2, "10.9.84.129", "10.0.0.2"),
            (3, "0.0.0.0", "10.0.0.2"),
            (3, "10.9.84.0", "10.0.0.2"),
            (3, "10.9.84.64", "10.0.0.2"),
            (7, "192.0.2.4", "10.0.0.4"),
        },
    ),
    (
        "0.0.0.0",
        {
            (1, "10.0.0.1", "10.0.0.1"),
            (1, "10.0.0.2", "10.0.0.2"),
            (2, "10.9.84.2", "10.0.0.2"),
            (3, "10.9.84.64", "10.0.0.2"),
            (3, "10.9.84.128", "10.0.0.2"),
            (4, "10.0.0.3", "10.0.0.2"),
            (5, "192.0.2.3", "10.0.0.3"),
            (5, "192.0.2.4", "10.0.0.2"),
        },
    ),
]
segments: list[tuple[str, Counter, set]] = []
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
    assert ospf[15] == 0, f"frame {number} is not AuType 0"
    # Nothing after the packet: no LLS block (RFC 5613).
    assert len(ospf) == length, f"frame {number} carries extra data"
    if kind in (1, 2):
        options = ospf[24 + 6] if kind == 1 else ospf[24 + 2]
        assert not options & 0x10, f"frame {number} sets the L bit"
    area = socket.inet_ntoa(ospf[8:12])
    if not segments or segments[-1][0] != area:
        segments.append((area, Counter(), set()))
    _, kinds, lsas = segments[-1]
    kinds[NAMES[kind]] += 1
    if kind == 4:
        cursor = 28
        for _ in range(struct.unpack_from("!I", ospf, 24)[0]):
            lsas.add(
                (
                    ospf[cursor + 3],
                    socket.inet_ntoa(ospf[cursor + 4 : cursor + 8]),
                    socket.inet_ntoa(ospf[cursor + 8 : cursor + 12]),
                )
            )
            cursor += struct.unpack_from("!H", ospf, cursor + 18)[0]
        assert cursor == length, f"frame {number}'s LSAs do not fill it"

assert [s[0] for s in segments] == [a for a, _ in EXPECTED], (
    f"expected areas {[a for a, _ in EXPECTED]}, got {[s[0] for s in segments]}"
)
for (area, kinds, lsas), (_, expected) in zip(segments, EXPECTED):
    print(
        f"[+] area {area}: {sum(kinds.values())} frames, "
        + ", ".join(f"{NAMES[k]} {kinds[NAMES[k]]}" for k in NAMES)
        + f"; {len(lsas)} distinct LSAs"
    )
    assert set(kinds) == set(NAMES.values()), f"area {area}: {kinds}"
    assert lsas == expected, (
        f"area {area}: missing {expected - lsas}, unexpected {lsas - expected}"
    )
print(f"[+] {len(frames)} OSPFv2 frames")
PY
)
python3 -c "$COMPOSITION_PY" "$OUT/ospf_areas.pcap"

echo
echo "[i] Expect zero checksum failures. Fold tests/fixtures/staging/ospf_areas.pcap"
echo "    and ospf_areas_lsdb.txt into tests/fixtures/."
