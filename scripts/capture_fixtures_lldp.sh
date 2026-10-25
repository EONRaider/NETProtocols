#!/usr/bin/env bash
# Capture an LLDP fixture for the corpus (IEEE 802.1AB).
#
#     sudo scripts/capture_fixtures_lldp.sh
#
# Two lldpd 1.0.18 agents, A and B, one in each of two netns over a
# veth pair, speaking LLDP only (no -c/-e/-f/-s, so no CDP, EDP, FDP or
# SONMP frame is sent). Each agent reads its configuration from its own
# file (-O) before it sends anything, so its first LLDPDU already
# carries it, and the two differ so that the identifiers do:
#
#   A  chassis ID: A's MAC address (subtype 4, lldpd's default)
#      port ID: the interface name (portidsubtype ifname, subtype 5)
#      TTL 120 s (the defaults, tx-interval 30 s x tx-hold 4)
#      an organizationally specific TLV (type 127) of lldpd's
#      custom-tlv, whose 304-byte value sets the 9th Length bit
#   B  chassis ID: a locally assigned string (system chassisid,
#      subtype 7)
#      port ID: B's MAC address (portidsubtype macaddress, subtype 3)
#      TTL 180 s (tx-hold 6)
#
# Both set a fixed system name and description, and advertise their
# IPv4 address as a Management Address TLV (-m). Then A's port ID is
# changed at run time to a locally assigned value (portidsubtype local,
# subtype 7): lldpd first sends a shutdown LLDPDU (TTL 0) for the old
# port ID, then an LLDPDU with the new one. Finally A and B are stopped
# with SIGTERM, and each sends a shutdown LLDPDU on the way out.
#
# lldpd builds every byte of each frame (it sends through a raw
# PF_PACKET socket, Ethernet header included). tcpdump on B's side of
# the pair captures `ether proto 0x88cc`, both directions. An agent
# repeats its LLDPDU every tx-interval for as long as it runs, so the
# script drives each step by watching the capture, then keeps a fixed
# selection: the first LLDPDU of each kind — sender, port ID subtype,
# shutdown or not — in capture order. The kept frames' composition is
# asserted exactly at the end. LLDP carries no checksum.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool lldpd lldpcli; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSA=nplldp-a
NSB=nplldp-b
A=nplldp-va
B=nplldp-vb
MAC_A=02:4e:50:86:00:0a
MAC_B=02:4e:50:86:00:0b
WORK=
TCPDUMP_PID=
A_PID=
B_PID=
cleanup() {
    for pid in $A_PID $B_PID $TCPDUMP_PID; do
        kill "$pid" 2>/dev/null || true
    done
    for ns in "$NSA" "$NSB"; do
        if [[ -e /run/netns/$ns ]]; then
            ip netns pids "$ns" | xargs -r kill 2>/dev/null || true
        fi
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del "$A" 2>/dev/null || true
    if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
# lldpd's privilege-separated child runs as _lldpd and must reach its
# control socket, so the work directory is world-searchable.
WORK=$(mktemp -d /tmp/nplldp.XXXXXX)
chmod 755 "$WORK"
RAW="$WORK/raw.pcap"

echo "[*] veth + two netns (A 10.9.86.1 $MAC_A, B 10.9.86.2 $MAC_B)"
ip netns add "$NSA"; ip netns add "$NSB"
ip link add "$A" address "$MAC_A" type veth peer name "$B" address "$MAC_B"
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add 10.9.86.1/24 dev "$A"
ip -n "$NSB" addr add 10.9.86.2/24 dev "$B"
ip netns exec "$NSA" ethtool -K "$A" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSB" ethtool -K "$B" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSA" link set lo up; ip -n "$NSA" link set "$A" up
ip -n "$NSB" link set lo up; ip -n "$NSB" link set "$B" up
sleep 1

# 300 bytes of custom-tlv content, 0x00-0xff then 0x00-0x2b: with the
# 3-byte OUI and the subtype, a 304-byte TLV value.
OUI_INFO=$(python3 -c 'print(",".join(f"{i % 256:02x}" for i in range(300)))')
cat > "$WORK/a.conf" <<EOF
configure system hostname nplldp-a
configure system description "NETProtocols LLDP fixture, agent A"
configure lldp portidsubtype ifname
configure lldp custom-tlv oui 0a,4e,50 subtype 1 oui-info $OUI_INFO
EOF
cat > "$WORK/b.conf" <<EOF
configure system hostname nplldp-b
configure system description "NETProtocols LLDP fixture, agent B"
configure system chassisid nplldp-chassis-b
configure lldp portidsubtype macaddress
configure lldp tx-hold 6
EOF

# How many LLDPDUs in the raw capture are of one kind: from <mac>, with
# Port ID subtype <subtype>, and a shutdown (TTL 0) or not ("live").
COUNT_PY=$(cat <<'PY'
import struct
import sys

path, mac, subtype, kind = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
try:
    raw = open(path, "rb").read()
except FileNotFoundError:
    raw = b""
count = 0
offset = 24
while offset + 16 <= len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    frame = raw[offset + 16 : offset + 16 + caplen]
    offset += 16 + caplen
    if len(frame) < 14 or frame[6:12].hex(":") != mac:
        continue
    tlvs, cursor = [], 14
    while cursor + 2 <= len(frame) and len(tlvs) < 3:
        word = struct.unpack_from("!H", frame, cursor)[0]
        tlvs.append(frame[cursor + 2 : cursor + 2 + (word & 0x1FF)])
        cursor += 2 + (word & 0x1FF)
    if len(tlvs) < 3 or tlvs[1][:1] != bytes([subtype]):
        continue
    if (tlvs[2][:2] == b"\x00\x00") == (kind == "shutdown"):
        count += 1
print(count)
PY
)

# Wait (up to 30 s) until the raw capture holds at least one LLDPDU of
# the kind COUNT_PY counts.
wait_lldpdu() {
    local mac=$1 subtype=$2 kind=$3 tries=300
    until (( $(python3 -c "$COUNT_PY" "$RAW" "$mac" "$subtype" "$kind") >= 1 )); do
        if (( --tries == 0 )); then
            echo "Timed out waiting for a $kind LLDPDU from $mac (port ID subtype $subtype)." >&2
            exit 1
        fi
        sleep 0.1
    done
}

# start <agent>: run lldpd (LLDP only, in the foreground) in the agent's
# netns, on its veth end alone, with its own control socket and
# configuration file, and record its PID.
start() {
    local agent=$1 ns=$NSA iface=$A ip=10.9.86.1
    if [[ $agent == b ]]; then ns=$NSB; iface=$B; ip=10.9.86.2; fi
    ip netns exec "$ns" lldpd -d -u "$WORK/$agent.sock" -I "$iface" \
        -m "$ip" -O "$WORK/$agent.conf" > "$WORK/$agent.log" 2>&1 &
    if [[ $agent == a ]]; then A_PID=$!; else B_PID=$!; fi
}

# stop <agent>: SIGTERM, on which lldpd sends a shutdown LLDPDU.
stop() {
    local pid
    if [[ $1 == a ]]; then pid=$A_PID; A_PID=; else pid=$B_PID; B_PID=; fi
    kill -TERM "$pid"
    wait "$pid" || true
}

ip netns exec "$NSB" tcpdump -i "$B" -w "$RAW" --immediate-mode -U -q \
    'ether proto 0x88cc' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "[>] A: chassis ID MAC address, port ID interface name"
start a
wait_lldpdu "$MAC_A" 5 live
echo "[>] B: chassis ID locally assigned, port ID MAC address"
start b
wait_lldpdu "$MAC_B" 3 live
echo "[>] A: port ID changed to a locally assigned value"
ip netns exec "$NSA" lldpcli -u "$WORK/a.sock" \
    configure lldp portidsubtype local np-port-a
wait_lldpdu "$MAC_A" 5 shutdown
wait_lldpdu "$MAC_A" 7 live
echo "[>] A, then B, stopped"
stop a
wait_lldpdu "$MAC_A" 7 shutdown
stop b
wait_lldpdu "$MAC_B" 3 shutdown
sleep 1

kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=

# Keep, in capture order, the first LLDPDU of each kind (sender, Port ID
# subtype, shutdown or not); drop the periodic repeats.
SELECT_PY=$(cat <<'PY'
import struct
import sys

raw = open(sys.argv[1], "rb").read()
assert raw[:4] == b"\xd4\xc3\xb2\xa1", "expected a little-endian classic pcap"
assert struct.unpack_from("<I", raw, 20)[0] == 1, "expected Ethernet framing"
out = [raw[:24]]
seen = set()
total = 0
offset = 24
while offset + 16 <= len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    record = raw[offset : offset + 16 + caplen]
    offset += 16 + caplen
    total += 1
    frame = record[16:]
    # Chassis ID, Port ID and TTL TLVs are 2-byte headers then values.
    cursor, values = 14, []
    for _ in range(3):
        word = struct.unpack_from("!H", frame, cursor)[0]
        values.append(frame[cursor + 2 : cursor + 2 + (word & 0x1FF)])
        cursor += 2 + (word & 0x1FF)
    kind = (frame[6:12], values[1][0], values[2] == b"\x00\x00")
    if kind in seen:
        continue
    seen.add(kind)
    out.append(record)
open(sys.argv[2], "wb").write(b"".join(out))
print(f"[i] kept {len(seen)} of the raw capture's {total} LLDPDUs")
PY
)
python3 -c "$SELECT_PY" "$RAW" "$OUT/lldp.pcap"

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

raw = open(sys.argv[1], "rb").read()
frames = []
offset = 24
while offset < len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    frames.append(raw[offset + 16 : offset + 16 + caplen])
    offset += 16 + caplen
A = bytes.fromhex("024e5086000a")
B = bytes.fromhex("024e5086000b")
NEAREST_BRIDGE = bytes.fromhex("0180c200000e")
CHASSIS_A = b"\x04" + A
CHASSIS_B = b"\x07nplldp-chassis-b"
PORT_A_IFNAME = b"\x05nplldp-va"
PORT_A_LOCAL = b"\x07np-port-a"
PORT_B = b"\x03" + B
# The TLV types of a full LLDPDU and of a shutdown LLDPDU, in order.
FULL = (1, 2, 3, 5, 6, 7, 8, 4, 127, 127, 0)
FULL_CUSTOM = (1, 2, 3, 5, 6, 7, 8, 4, 127, 127, 127, 0)
SHUTDOWN = (1, 2, 3, 0)
# lldpd's custom-tlv: OUI 0a-4e-50, subtype 1, 300 bytes of content.
CUSTOM = b"\x0a\x4e\x50\x01" + bytes(i % 256 for i in range(300))
# (source, chassis ID, port ID, TTL, TLV types, the values of the
# organizationally specific TLVs with the custom OUI)
expected = [
    (A, CHASSIS_A, PORT_A_IFNAME, 120, FULL_CUSTOM, (CUSTOM,)),
    (B, CHASSIS_B, PORT_B, 180, FULL, ()),
    (A, CHASSIS_A, PORT_A_IFNAME, 0, SHUTDOWN, ()),
    (A, CHASSIS_A, PORT_A_LOCAL, 120, FULL_CUSTOM, (CUSTOM,)),
    (A, CHASSIS_A, PORT_A_LOCAL, 0, SHUTDOWN, ()),
    (B, CHASSIS_B, PORT_B, 0, SHUTDOWN, ()),
]
got = []
for number, frame in enumerate(frames, 1):
    assert frame[:6] == NEAREST_BRIDGE, f"frame {number}: not to 01:80:c2:00:00:0e"
    assert frame[12:14] == b"\x88\xcc", f"frame {number} is not LLDP"
    tlvs, cursor = [], 14
    while True:
        word = struct.unpack_from("!H", frame, cursor)[0]
        tlvs.append((word >> 9, frame[cursor + 2 : cursor + 2 + (word & 0x1FF)]))
        cursor += 2 + (word & 0x1FF)
        if word >> 9 == 0:
            break
    assert cursor == len(frame), f"frame {number}: bytes after End of LLDPDU"
    assert tlvs[-1] == (0, b""), f"frame {number}: End of LLDPDU has a value"
    got.append(
        (
            frame[6:12],
            tlvs[0][1],
            tlvs[1][1],
            int.from_bytes(tlvs[2][1]),
            tuple(t for t, _ in tlvs),
            tuple(v for t, v in tlvs if t == 127 and v[:3] == b"\x0a\x4e\x50"),
        )
    )
assert got == expected, f"unexpected composition:\n{got}"
print(f"[+] {len(frames)} LLDPDUs, as expected")
PY
)
python3 -c "$COMPOSITION_PY" "$OUT/lldp.pcap"

echo
echo "[i] Fold tests/fixtures/staging/lldp.pcap into tests/fixtures/."
