#!/usr/bin/env bash
# Capture an HSRPv1 fixture for the corpus (RFC 2281), ours and not a
# public one.
#
#     sudo scripts/capture_fixtures_hsrp.sh
#
# RFC 2281 is Cisco's, and no open-source router runs HSRP, so there is
# no daemon to elect a virtual router here the way chronyd keeps time in
# capture_fixtures_ntp.sh. Yersinia (Debian/Kali's `yersinia`, 0.8.2) is
# the sender instead: its HSRP attack 0 crafts and sends one raw HSRPv1
# message per invocation and exits, with every field set from the
# command line, so a table of invocations produces a fixed set of frames
# in a fixed order. We run it in one netns, out its veth, and capture on
# the other end of the pair in a second netns, so only the veth traffic
# is seen and nothing of the host.
#
# The table is a scripted sequence of Hello, Coup and Resign messages on
# one LAN, across two standby groups, and not a faithful run of RFC
# 2281's state machine (§5.3-5.7): frame 7, for instance, has R2 go from
# Standby to Speak after R1's Resign, where §5.7's table (event i,
# "CFI/6") takes a Standby router straight to Active.
#
#   Group 1, virtual IP 10.9.195.254, the default authentication data
#   `cisco` (§5.1), three routers:
#     R1 10.9.195.11 priority 120, R2 10.9.195.12 priority 100,
#     R3 10.9.195.13 priority 200.
#      1  R1 Hello    Speak    R1 comes up and contends
#      2  R2 Hello    Speak    R2 contends
#      3  R1 Hello    Standby  R1, the higher priority, is Standby
#      4  R1 Hello    Active   then Active, the virtual router
#      5  R2 Hello    Standby  R2 settles as Standby
#      6  R1 Resign   Active   R1 steps down (Op Code Resign)
#      7  R2 Hello    Speak    R2 contends for Active
#      8  R2 Hello    Active   R2 becomes Active
#      9  R3 Coup     Active   R3 preempts with priority 200 (Op Code
#                              Coup)
#     10  R3 Hello    Active   R3 is now the virtual router
#
#   Group 2, virtual IP 10.9.195.253, a configured password `spark`
#   (non-default authentication data), two routers:
#     R4 10.9.195.21 priority 110, R5 10.9.195.22 priority 90.
#     11  R4 Hello    Active   R4 is Active for group 2
#     12  R5 Hello    Standby  R5 is Standby for group 2
#
# Twelve frames: ten Hellos, one Coup, one Resign; the States Speak,
# Standby and Active; both the default `cisco` and the non-default
# `spark` authentication data; every message HSRPv1 (Version 0) to
# 224.0.0.2 (Ethernet 01:00:5e:00:00:02) from and to UDP 1985, with the
# Hellotime 3 and Holdtime 10 RFC 2281 recommends and a zero Reserved
# byte. Every Hello's Holdtime exceeds its Hellotime, as §5.1 requires.
#
# What Yersinia built: the whole frame, Ethernet through the 20 HSRP
# bytes, including the IPv4 and UDP checksums (it writes raw frames, so
# offload never touches them; offload is turned off on both veth ends
# all the same, as the other capture scripts do). Yersinia sets the TTL
# to 1 (RFC 2281 §5.1), the IP ID to 0 and the DSCP to 4 (IP ToS 0x10)
# rather than the CS6/precedence 6 a Cisco router uses — none of which
# any corpus check rejects. Source MAC addresses are pinned on the command line
# (`-source`), since Yersinia randomizes them otherwise, so the capture
# is byte-for-byte reproducible but for the pcap record timestamps.
#
# The script asserts the twelve frames one by one, by sender, Op Code,
# State, priority, Hellotime, Holdtime, group, virtual IP,
# authentication data, source IP, source MAC, destination (224.0.0.2 and
# its multicast MAC), ports (1985 to 1985), Version and the Reserved and
# TTL bytes, parsing the pcap itself with the standard library, and
# stops if anything differs. It then runs scripts/check_fixtures.py over
# the result, which revalidates every IPv4 and UDP checksum and the HSRP
# fields independently.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool yersinia; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
echo "[*] $(yersinia -V 2>&1 | head -n 1)"

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
WORK=
NSTX=np195-tx
NSRX=np195-rx
TX=v195a
RX=v195b
TX_IP=10.9.195.1
RX_IP=10.9.195.2
GROUP_MCAST=224.0.0.2
GROUP_MCAST_MAC=01:00:5e:00:00:02
TCPDUMP_PID=

stop() {  # pid
    [[ -n $1 ]] || return 0
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}
cleanup() {
    stop "$TCPDUMP_PID"; TCPDUMP_PID=
    ip netns del "$NSTX" 2>/dev/null || true
    ip netns del "$NSRX" 2>/dev/null || true
    ip link del "$TX" 2>/dev/null || true
    if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
fail() { echo "[!] $*" >&2; exit 1; }
cleanup
WORK=$(mktemp -d)

echo "[*] veth + two netns (sender $TX_IP, capture $RX_IP)"
ip netns add "$NSTX"; ip netns add "$NSRX"
ip link add "$TX" address 02:00:0a:09:c3:a1 type veth \
    peer name "$RX" address 02:00:0a:09:c3:b2
ip link set "$TX" netns "$NSTX"
ip link set "$RX" netns "$NSRX"
ip -n "$NSTX" addr add "$TX_IP/24" dev "$TX"
ip -n "$NSRX" addr add "$RX_IP/24" dev "$RX"
bring_up() {  # netns iface
    ip netns exec "$1" ethtool -K "$2" tx off rx off tso off gso off gro off \
        >/dev/null 2>&1 || true
    ip -n "$1" link set lo up
    ip -n "$1" link set "$2" up
}
bring_up "$NSTX" "$TX"
bring_up "$NSRX" "$RX"
sleep 1

# One Yersinia HSRP attack-0 invocation per frame, in order. The single-
# byte header fields (Op Code, State, Hellotime, Holdtime, priority,
# Reserved) are hexadecimal, as Yersinia's CLI wants; the group is
# decimal. See the table in the header comment.
#   fields: opcode state hello hold prio group vip pass srcmac srcip
FRAMES=$(cat <<'TBL'
00 04 03 0a 78 1 10.9.195.254 cisco 02:00:0a:09:c3:0b 10.9.195.11
00 04 03 0a 64 1 10.9.195.254 cisco 02:00:0a:09:c3:0c 10.9.195.12
00 08 03 0a 78 1 10.9.195.254 cisco 02:00:0a:09:c3:0b 10.9.195.11
00 10 03 0a 78 1 10.9.195.254 cisco 02:00:0a:09:c3:0b 10.9.195.11
00 08 03 0a 64 1 10.9.195.254 cisco 02:00:0a:09:c3:0c 10.9.195.12
02 10 03 0a 78 1 10.9.195.254 cisco 02:00:0a:09:c3:0b 10.9.195.11
00 04 03 0a 64 1 10.9.195.254 cisco 02:00:0a:09:c3:0c 10.9.195.12
00 10 03 0a 64 1 10.9.195.254 cisco 02:00:0a:09:c3:0c 10.9.195.12
01 10 03 0a c8 1 10.9.195.254 cisco 02:00:0a:09:c3:0d 10.9.195.13
00 10 03 0a c8 1 10.9.195.254 cisco 02:00:0a:09:c3:0d 10.9.195.13
00 10 03 0a 6e 2 10.9.195.253 spark 02:00:0a:09:c3:15 10.9.195.21
00 08 03 0a 5a 2 10.9.195.253 spark 02:00:0a:09:c3:16 10.9.195.22
TBL
)

echo "[*] Capturing on $RX, HSRP sent from $TX"
ip netns exec "$NSRX" tcpdump -i "$RX" -w "$WORK/hsrp.pcap" \
    --immediate-mode -U -q 'udp port 1985' >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

count=0
while read -r op st he ho pr gr vip pw mac sip; do
    [[ -n $op ]] || continue
    count=$((count + 1))
    ip netns exec "$NSTX" yersinia hsrp -attack 0 -interface "$TX" \
        -version 00 -opcode "$op" -state "$st" -hello "$he" -hold "$ho" \
        -priority "$pr" -group "$gr" -reserved 00 -ipvirtual "$vip" \
        -password "$pw" -source "$mac" -dest "$GROUP_MCAST_MAC" \
        -ipsource "$sip" -ipdest "$GROUP_MCAST" -sport 1985 -dport 1985 \
        >>"$WORK/yersinia.log" 2>&1 ||
        fail "frame $count: yersinia failed: $(tail -n 2 "$WORK/yersinia.log")"
    sleep 0.3
done <<<"$FRAMES"

sleep 1
stop "$TCPDUMP_PID"; TCPDUMP_PID=
echo "[*] Sent $count HSRP messages."

echo "[*] Asserting the capture frame by frame..."
python3 -I - "$WORK/hsrp.pcap" "$OUT/hsrp.pcap" <<'PY'
import struct
import sys
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])

# What we told Yersinia to send, in order: Op Code, State, priority,
# Hellotime, Holdtime, group, virtual IP, authentication data, source
# IP, source MAC. The single-byte values here are decimal.
HELLO, COUP, RESIGN = 0, 1, 2
SPEAK, STANDBY, ACTIVE = 4, 8, 16
G1, G2 = "10.9.195.254", "10.9.195.253"
CISCO, SPARK = b"cisco\x00\x00\x00", b"spark\x00\x00\x00"
R1M, R2M, R3M = "02:00:0a:09:c3:0b", "02:00:0a:09:c3:0c", "02:00:0a:09:c3:0d"
R4M, R5M = "02:00:0a:09:c3:15", "02:00:0a:09:c3:16"
R1I, R2I, R3I = "10.9.195.11", "10.9.195.12", "10.9.195.13"
R4I, R5I = "10.9.195.21", "10.9.195.22"
expected = [
    (HELLO,  SPEAK,   120, 3, 10, 1, G1, CISCO, R1I, R1M),
    (HELLO,  SPEAK,   100, 3, 10, 1, G1, CISCO, R2I, R2M),
    (HELLO,  STANDBY, 120, 3, 10, 1, G1, CISCO, R1I, R1M),
    (HELLO,  ACTIVE,  120, 3, 10, 1, G1, CISCO, R1I, R1M),
    (HELLO,  STANDBY, 100, 3, 10, 1, G1, CISCO, R2I, R2M),
    (RESIGN, ACTIVE,  120, 3, 10, 1, G1, CISCO, R1I, R1M),
    (HELLO,  SPEAK,   100, 3, 10, 1, G1, CISCO, R2I, R2M),
    (HELLO,  ACTIVE,  100, 3, 10, 1, G1, CISCO, R2I, R2M),
    (COUP,   ACTIVE,  200, 3, 10, 1, G1, CISCO, R3I, R3M),
    (HELLO,  ACTIVE,  200, 3, 10, 1, G1, CISCO, R3I, R3M),
    (HELLO,  ACTIVE,  110, 3, 10, 2, G2, SPARK, R4I, R4M),
    (HELLO,  STANDBY,  90, 3, 10, 2, G2, SPARK, R5I, R5M),
]

MCAST_IP = bytes([224, 0, 0, 2])
MCAST_MAC = bytes.fromhex("01005e000002")


def records(path):
    data = path.read_bytes()
    if len(data) < 24 or data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        sys.exit(f"{path.name}: not a little-endian pcap")
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


def mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def dotted(raw):
    return ".".join(str(b) for b in raw)


selected, header = [], None
for head, record in records(src):
    header = header or head
    selected.append(record)

if len(selected) != len(expected):
    sys.exit(f"[!] captured {len(selected)} frames, expected {len(expected)}")

ops = {HELLO: 0, COUP: 0, RESIGN: 0}
for i, (record, want) in enumerate(zip(selected, expected), start=1):
    frame = record[16:]
    eth_dst, eth_src = frame[0:6], frame[6:12]
    if frame[12:14] != b"\x08\x00":
        sys.exit(f"[!] frame {i}: not IPv4")
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if ip[0] >> 4 != 4 or ip[9] != 17:
        sys.exit(f"[!] frame {i}: not IPv4/UDP")
    ttl, ip_src, ip_dst = ip[8], ip[12:16], ip[16:20]
    udp = ip[ihl:]
    sport, dport, ulen = struct.unpack_from("!HHH", udp)
    hsrp = udp[8:ulen]
    if eth_dst != MCAST_MAC:
        sys.exit(f"[!] frame {i}: dst MAC {mac(eth_dst)} != {mac(MCAST_MAC)}")
    if ip_dst != MCAST_IP:
        sys.exit(f"[!] frame {i}: dst IP {dotted(ip_dst)} != 224.0.0.2")
    if (sport, dport) != (1985, 1985):
        sys.exit(f"[!] frame {i}: ports {sport}->{dport} != 1985->1985")
    if ttl != 1:
        sys.exit(f"[!] frame {i}: TTL {ttl} != 1")
    if len(hsrp) != 20:
        sys.exit(f"[!] frame {i}: HSRP payload {len(hsrp)} bytes, expected 20")
    version, opcode, state, hello, hold, priority, group, reserved = hsrp[:8]
    auth, vip = hsrp[8:16], dotted(hsrp[16:20])
    ops[opcode] = ops.get(opcode, 0) + 1
    if version != 0:
        sys.exit(f"[!] frame {i}: HSRP version {version} != 0")
    if reserved != 0:
        sys.exit(f"[!] frame {i}: Reserved byte {reserved} != 0")
    got = (opcode, state, priority, hello, hold, group, vip, auth,
           dotted(ip_src), mac(eth_src))
    if got != want:
        sys.exit(f"[!] frame {i}: {got} != expected {want}")
    if opcode == HELLO and not hold > hello:
        sys.exit(f"[!] frame {i}: Holdtime {hold} !> Hellotime {hello}")

if (ops[HELLO], ops[COUP], ops[RESIGN]) != (10, 1, 1):
    sys.exit(f"[!] op-code mix {ops} != 10 Hello / 1 Coup / 1 Resign")

out.write_bytes(header + b"".join(selected))
print(f"[+] {len(selected)} frames "
      f"({ops[HELLO]} Hello, {ops[COUP]} Coup, {ops[RESIGN]} Resign), "
      f"as expected.")
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
echo "[i] Expect udp + hsrp counts (hsrp-hello x10, hsrp-coup x1,"
echo "    hsrp-resign x1) and zero failures. Fold"
echo "    tests/fixtures/staging/hsrp.pcap into tests/fixtures/."
