#!/usr/bin/env bash
# Capture the LLC fixture for the corpus: IEEE 802.3 frames whose
# type/length field holds a Length, followed by an 802.2 LLC header.
#
#     sudo scripts/capture_fixtures_llc.sh
#
# Three netns. A and B each hold a Linux bridge with STP on (802.1D,
# CONFIG_BRIDGE_STP): A's npllc-bra at priority 0x1000, so it becomes
# the root, and B's npllc-brb at the default 0x8000. One veth pair joins
# A's port npllc-ab to B's port npllc-ba, and a second joins B's port
# npllc-bx to netns X. Everything is captured on B's port npllc-ba,
# both directions, in four steps:
#
#   1. The A-B link comes up. Each bridge first believes it is the root
#      and sends a Configuration BPDU; B then hears A's, better one and
#      stops, and A goes on sending one each hello time (1 s). When A's
#      port starts forwarding, A, the root, flags a topology change
#      (TC) in its BPDUs.
#   2. B's second port comes up. When it starts forwarding, B detects a
#      topology change and, not being the root, sends a Topology Change
#      Notification BPDU towards A, which acknowledges it (TCA).
#   3. lldpd (its own control socket, pidfile and interface list, in A,
#      on npllc-ab) runs twice: with -cc it sends CDPv1 and with -ccc
#      CDPv2 (LLC/SNAP, OUI 00-00-0C, PID 0x2000), each without waiting
#      to hear a CDP peer. Its LLDP frames are left out of the capture
#      by the capture filter.
#   4. scripts/llc_fixture_frames.py, in A, sends six frames it builds
#      byte for byte through an AF_PACKET socket on npllc-ab: RFC 1042
#      ARP (padded to 60 bytes) and ICMP-in-IPv4, IEEE 802.1H ARP, RFC
#      1042 ARP behind an 802.1Q tag, Novell raw 802.3 IPX, and a frame
#      whose type/length value, 1501, is undefined.
#
# The kernel's bridge code builds every BPDU (Ethernet header, LLC
# header and BPDU), and lldpd builds every CDP frame, its checksum
# included, in userspace; veth adds no padding, so a TCN is a 21-byte
# frame. The bridges and veths get fixed MAC addresses, so the bridge
# and port IDs in the BPDUs are the same on every run, and lldpd runs
# under its own UTS namespace with the hostname npllc-cdp, and with -S
# and -P, so the CDP frames name no detail of the capture host.
#
# BPDUs and CDP frames repeat for as long as their senders run, so the
# script drives each step by watching the capture, captures to a
# scratch file, and keeps a fixed selection: the first frame of each
# kind (classified below). The kept frames' composition is asserted
# exactly at the end. Offload is turned off first (ethtool -K) as best
# effort; check_fixtures.py verifies the IPv4 and ICMP checksums, every
# CDP checksum and every 802.3 Length against its frame.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for netns, bridges and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool lldpd unshare; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSA=npllc-a
NSB=npllc-b
NSX=npllc-x
AB=npllc-ab
BA=npllc-ba
BX=npllc-bx
XB=npllc-xb
WORK=
TCPDUMP_PID=
LLDPD_PID=
cleanup() {
    for pid in $LLDPD_PID $TCPDUMP_PID; do
        kill "$pid" 2>/dev/null || true
    done
    for ns in "$NSA" "$NSB" "$NSX"; do
        if [[ -e /run/netns/$ns ]]; then
            ip netns pids "$ns" | xargs -r kill 2>/dev/null || true
        fi
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del "$AB" 2>/dev/null || true
    ip link del "$BX" 2>/dev/null || true
    if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
cleanup
# lldpd's privilege-separated child and the lldpcli it spawns must
# reach the control socket and configuration, so the scratch directory
# is world-traversable (and private to this run).
WORK=$(mktemp -d /run/npllc.XXXXXX)
chmod 755 "$WORK"
RAW="$WORK/raw.pcap"

echo "[*] netns A, B, X; bridges with STP on; veths A-B and B-X"
ip netns add "$NSA"; ip netns add "$NSB"; ip netns add "$NSX"
ip link add "$AB" address 02:00:00:00:a0:01 type veth \
    peer name "$BA" address 02:00:00:00:b0:01
ip link add "$BX" address 02:00:00:00:b0:02 type veth \
    peer name "$XB" address 02:00:00:00:c0:01
ip link set "$AB" netns "$NSA"
ip link set "$BA" netns "$NSB"
ip link set "$BX" netns "$NSB"
ip link set "$XB" netns "$NSX"
# hello_time and forward_delay are in hundredths of a second: 1 s and
# 2 s, the shortest 802.1D allows, so the ports reach forwarding fast.
ip -n "$NSA" link add npllc-bra address 02:00:00:00:a0:00 type bridge \
    stp_state 1 priority 4096 hello_time 100 forward_delay 200
ip -n "$NSB" link add npllc-brb address 02:00:00:00:b0:00 type bridge \
    stp_state 1 priority 32768 hello_time 100 forward_delay 200
ip -n "$NSA" link set "$AB" master npllc-bra
ip -n "$NSB" link set "$BA" master npllc-brb
ip -n "$NSB" link set "$BX" master npllc-brb
ip -n "$NSA" addr add 10.9.30.1/24 dev npllc-bra
for ns in "$NSA" "$NSB" "$NSX"; do ip -n "$ns" link set lo up; done
ip netns exec "$NSA" ethtool -K "$AB" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSB" ethtool -K "$BA" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSA" link set npllc-bra up
ip -n "$NSB" link set npllc-brb up
# B's port is up, but has no carrier until A's end comes up below.
ip -n "$NSB" link set "$BA" up

# The label of each frame in a pcap, one per line (see classify()).
CLASSIFY_PY=$(cat <<'PY'
import struct
import sys

A_PORT = bytes.fromhex("02000000a001")
B_PORT = bytes.fromhex("02000000b001")


def classify(frame):
    """A label naming the kind of frame, e.g. "stp-config-a-tc"."""
    value = struct.unpack_from("!H", frame, 12)[0]
    body = frame[14:]
    if value == 0x8100:
        value = struct.unpack_from("!H", frame, 16)[0]
        body = frame[18:]
        if body[:8] == bytes.fromhex("aaaa030000000806"):
            return "vlan-rfc1042-arp"
    if value == 1501:
        return "type-1501"
    if value > 1500:
        return f"ethertype-{value:#06x}"
    pdu = body[:value]
    sender = {A_PORT: "a", B_PORT: "b"}.get(frame[6:12], "other")
    if pdu[:3] == b"\x42\x42\x03":
        bpdu = pdu[3:]
        if bpdu[3:4] == b"\x80":
            return f"stp-tcn-{sender}"
        flags = bpdu[4]
        suffix = "-tc" if flags & 0x01 else ""
        suffix += "-tca" if flags & 0x80 else ""
        return f"stp-config-{sender}{suffix}"
    if pdu[:8] == bytes.fromhex("aaaa0300000c2000"):
        return f"cdpv{pdu[8]}"
    if pdu[:8] == bytes.fromhex("aaaa030000000806"):
        return "rfc1042-arp"
    if pdu[:8] == bytes.fromhex("aaaa030000000800"):
        return "rfc1042-ipv4"
    if pdu[:8] == bytes.fromhex("aaaa030000f80806"):
        return "8021h-arp"
    if pdu[:2] == b"\xff\xff":
        return "raw-ipx"
    return f"llc-{pdu[:3].hex()}"


def records(raw):
    offset = 24
    while offset + 16 <= len(raw):
        caplen = struct.unpack_from("<I", raw, offset + 8)[0]
        if offset + 16 + caplen > len(raw):
            return
        yield raw[offset : offset + 16 + caplen]
        offset += 16 + caplen


try:
    raw = open(sys.argv[1], "rb").read()
except FileNotFoundError:
    raw = b""
for record in records(raw):
    print(classify(record[16:]))
PY
)

# Wait (up to 30 s) until the raw capture holds a frame labelled <label>.
wait_for() {
    local label=$1 tries=300
    until python3 -c "$CLASSIFY_PY" "$RAW" | grep -qx -- "$label"; do
        if (( --tries == 0 )); then
            echo "Timed out waiting for a $label frame." >&2
            exit 1
        fi
        sleep 0.1
    done
}

# Run lldpd in A with <cdp flags> until a <label> frame is captured,
# then stop it.
run_lldpd() {
    local flags=$1 label=$2
    ip netns exec "$NSA" unshare --uts sh -c '
        hostname npllc-cdp
        exec lldpd -d "$@"' lldpd "$flags" -k -S "NETProtocols LLC fixture" \
        -P "npllc" -u "$WORK/lldpd.socket" -p "$WORK/lldpd.pid" \
        -I "$AB" -O "$WORK/lldpd.conf" > "$WORK/lldpd$flags.log" 2>&1 &
    LLDPD_PID=$!
    wait_for "$label"
    kill -TERM "$LLDPD_PID"
    wait "$LLDPD_PID" || true
    LLDPD_PID=
}

ip netns exec "$NSB" tcpdump -i "$BA" -w "$RAW" --immediate-mode -U -q \
    'not ether proto 0x88cc' >/dev/null 2>&1 &
TCPDUMP_PID=$!
# B's first BPDU goes out the moment the link comes up, so wait until
# tcpdump has opened its file before bringing it up.
tries=100
until [[ -s $RAW ]]; do
    if (( --tries == 0 )); then echo "tcpdump did not start." >&2; exit 1; fi
    sleep 0.1
done
sleep 0.5

echo "[>] 1. A-B link up: Configuration BPDUs, A becomes the root"
ip -n "$NSA" link set "$AB" up
wait_for stp-config-b
wait_for stp-config-a
wait_for stp-config-a-tc

echo "[>] 2. B's second port up: B sends a TCN, A acknowledges it"
ip -n "$NSB" link set "$BX" up
ip -n "$NSX" link set "$XB" up
wait_for stp-tcn-b
wait_for stp-config-a-tc-tca

echo "[>] 3. lldpd: CDPv1, then CDPv2"
# One transmission a second rather than the default 30 s.
echo "configure lldp tx-interval 1" > "$WORK/lldpd.conf"
chmod 644 "$WORK/lldpd.conf"
run_lldpd -cc cdpv1
run_lldpd -ccc cdpv2

echo "[>] 4. script-built frames"
ip netns exec "$NSA" python3 scripts/llc_fixture_frames.py send "$AB"
wait_for type-1501
sleep 1

kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
TCPDUMP_PID=

# Keep, in capture order, the first frame of each kind.
SELECT_PY=$(cat <<'PY'
import struct
import subprocess
import sys

raw_path, out_path, classify = sys.argv[1], sys.argv[2], sys.argv[3]
raw = open(raw_path, "rb").read()
assert raw[:4] == b"\xd4\xc3\xb2\xa1", "expected a little-endian classic pcap"
assert struct.unpack_from("<I", raw, 20)[0] == 1, "expected Ethernet framing"
labels = subprocess.run(
    [sys.executable, "-c", classify, raw_path],
    check=True, capture_output=True, text=True,
).stdout.split()
out = [raw[:24]]
seen = set()
offset = 24
for label in labels:
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    record = raw[offset : offset + 16 + caplen]
    offset += 16 + caplen
    if label not in seen:
        seen.add(label)
        out.append(record)
open(out_path, "wb").write(b"".join(out))
print(f"[i] kept {len(out) - 1} of the raw capture's {len(labels)} frames")
PY
)
python3 -c "$SELECT_PY" "$RAW" "$OUT/llc.pcap" "$CLASSIFY_PY"

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
import subprocess
import sys

path, classify = sys.argv[1], sys.argv[2]
labels = subprocess.run(
    [sys.executable, "-c", classify, path],
    check=True, capture_output=True, text=True,
).stdout.split()
expected = [
    "stp-config-b",
    "stp-config-a",
    "stp-config-a-tc",
    "stp-tcn-b",
    "stp-config-a-tc-tca",
    "cdpv1",
    "cdpv2",
    "rfc1042-arp",
    "rfc1042-ipv4",
    "8021h-arp",
    "vlan-rfc1042-arp",
    "raw-ipx",
    "type-1501",
]
assert labels == expected, f"unexpected composition:\n{labels}"
raw = open(path, "rb").read()
offset = 24
lengths = []
while offset < len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    lengths.append(caplen)
    offset += 16 + caplen
# A Configuration BPDU is 35 bytes and a TCN 4, after the 3-byte LLC
# header; the script-built frames are padded to 60 bytes but for the
# 79-byte ICMP one.
assert lengths[:5] == [52, 52, 52, 21, 52], lengths
assert lengths[7:] == [60, 79, 60, 60, 60, 60], lengths
print(f"[+] {len(labels)} frames, as expected")
PY
)
python3 -c "$COMPOSITION_PY" "$OUT/llc.pcap" "$CLASSIFY_PY"

echo
echo "[i] Expect zero failures. Fold tests/fixtures/staging/llc.pcap"
echo "    into tests/fixtures/."
