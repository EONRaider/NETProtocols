#!/usr/bin/env bash
# Capture an 802.1Q / 802.1ad VLAN fixture for the corpus.
#
#     sudo scripts/capture_fixtures_vlan.sh
#
# Tagged frames never reach a host on an ordinary access port — the
# switch strips the tag first — so a VLAN fixture has to be produced
# on a link that carries tags in-band. There are two ways to get one;
# both put the *same bytes* on the wire, because inserting an 802.1Q
# tag is a pure shim: it copies no field and is covered by no checksum,
# so the inner IPv4/ICMP checksums are identical either way.
#
#   (A) Pure capture, on a kernel with the 8021q driver
#       (CONFIG_VLAN_8021Q=y). Build real vlan devices over a veth and
#       let the kernel tag/untag; tcpdump on the parent device sees the
#       tags in-band. A single 802.1Q device carries VID 100; a QinQ
#       stack carries an 802.1ad S-TAG (VID 200) around an 802.1Q C-TAG
#       (VID 30):
#
#         ip link add link veth0 name veth0.100 type vlan id 100
#         ip link add link veth0 name veth0.200 type vlan proto 802.1ad id 200
#         ip link add link veth0.200 name veth0.200.30 type vlan id 30
#
#       veth advertises hardware VLAN tx offload, which would move the
#       tag into skb metadata (and out of the saved bytes); veth also
#       leaves local checksums to "offload" (never actually computed on
#       a purely local link). So path (A) turns both off with
#       `ethtool -K` before capturing — that forces the tag inline and
#       the inner IPv4/ICMP checksums to their real values, which is
#       what check_fixtures.py verifies.
#
#   (B) Synthesis from a real capture, for kernels without 8021q.
#       Capture a real untagged ICMP exchange over a veth pair — genuine
#       kernel Ethernet / ARP / IPv4 / ICMP with real checksums — then
#       splice a tag shim in after the MAC addresses. The result is
#       byte-for-byte what path (A) would have captured for the same
#       traffic.
#
# This script runs (A) when the 8021q driver and ethtool are both
# present and falls back to (B) otherwise, printing which path produced
# the fixture. Either way it validates with check_fixtures.py before you
# fold the pcap into the corpus. The committed tests/fixtures/vlan_icmp.pcap
# was produced by path (A); the MANIFEST records that.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump ping python3; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NS="npvlan"
A="npveth0"          # parent, stays in the root netns
B="npveth1"          # parent, moved into $NS
cleanup() { ip netns del "$NS" 2>/dev/null || true; ip link del "$A" 2>/dev/null || true; }
trap cleanup EXIT
cleanup

# Kill IPv6 autoconf (link-local DAD, MLD reports, router solicitations)
# in a netns so a capture there holds only the traffic we provoke.
# default.* must be set before the devices are created and brought up.
no6() {  # $1 = "" (root netns) or "ip netns exec $NS"
    $1 sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || true
    $1 sysctl -qw net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
}

echo "[*] veth pair + netns"
no6 ""
ip netns add "$NS"
no6 "ip netns exec $NS"
ip link add "$A" type veth peer name "$B"
ip link set "$B" netns "$NS"
ip -n "$NS" link set lo up

# Path (A) needs the 8021q driver *and* ethtool (to turn off veth's
# VLAN/checksum offload). Probe the driver by creating a throwaway vlan
# device on the parent.
have_A=0
if command -v ethtool >/dev/null \
   && ip link add link "$A" name "$A.probe" type vlan id 4094 2>/dev/null; then
    have_A=1
    ip link del "$A.probe" 2>/dev/null || true
fi

echo "[>] vlan_icmp (ARP + ICMPv4 echo across a single tag and a QinQ stack)"
if [[ $have_A -eq 1 ]]; then
    echo "    path (A): kernel 8021q driver present — capturing real tagged frames"

    # Real vlan devices on both ends: single 802.1Q (VID 100) and a QinQ
    # stack (802.1ad S-TAG VID 200 over 802.1Q C-TAG VID 30).
    ip link add link "$A"     name "$A.100"    type vlan id 100
    ip link add link "$A"     name "$A.200"    type vlan proto 802.1ad id 200
    ip link add link "$A.200" name "$A.200.30" type vlan id 30
    ip -n "$NS" link add link "$B"     name "$B.100"    type vlan id 100
    ip -n "$NS" link add link "$B"     name "$B.200"    type vlan proto 802.1ad id 200
    ip -n "$NS" link add link "$B.200" name "$B.200.30" type vlan id 30

    # Turn off VLAN and checksum offload so the tag lands inline and the
    # inner IPv4/ICMP checksums are computed (not left to "offload").
    for d in "$A" "$A.100" "$A.200" "$A.200.30"; do
        ethtool -K "$d" tx off rx off tso off gso off gro off \
            txvlan off rxvlan off >/dev/null 2>&1 || true
    done
    for d in "$B" "$B.100" "$B.200" "$B.200.30"; do
        ip netns exec "$NS" ethtool -K "$d" tx off rx off tso off gso off \
            gro off txvlan off rxvlan off >/dev/null 2>&1 || true
    done

    # Addresses on the tagged devices: one subnet per flow.
    ip      addr add 10.9.1.1/24 dev "$A.100"        # single-tag flow
    ip -n "$NS" addr add 10.9.1.2/24 dev "$B.100"
    ip      addr add 10.9.2.1/24 dev "$A.200.30"     # QinQ flow
    ip -n "$NS" addr add 10.9.2.2/24 dev "$B.200.30"
    for d in "$A" "$A.100" "$A.200" "$A.200.30"; do ip link set "$d" up; done
    for d in "$B" "$B.100" "$B.200" "$B.200.30"; do ip -n "$NS" link set "$d" up; done

    # Fresh ARP (a tagged who-has/is-at pair) in front of each flow.
    ip neigh flush dev "$A.100" 2>/dev/null || true
    ip neigh flush dev "$A.200.30" 2>/dev/null || true

    # Capture on the PARENT: it carries both flows with tags in-band.
    tcpdump -i "$A" -w "$OUT/vlan_icmp.pcap" --immediate-mode -U -q \
        >/dev/null 2>&1 &
    pid=$!
    sleep 1
    ping -c 2 -i 0.3 -I 10.9.1.1 10.9.1.2 >/dev/null || true   # single 802.1Q
    ping -c 2 -i 0.3 -I 10.9.2.1 10.9.2.2 >/dev/null || true   # QinQ
    sleep 1
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
else
    echo "    path (B): 8021q driver (or ethtool) unavailable — synthesizing"
    echo "              tags over a real untagged capture"

    ip addr add 10.9.0.1/24 dev "$A"
    ip link set "$A" up
    ip -n "$NS" addr add 10.9.0.2/24 dev "$B"
    ip -n "$NS" link set "$B" up
    ip neigh flush dev "$A" 2>/dev/null || true

    tcpdump -i "$A" -w "$OUT/vlan_untagged.pcap" --immediate-mode -U -q \
        ip or arp >/dev/null 2>&1 &
    pid=$!
    sleep 1
    ping -c 3 -i 0.3 10.9.0.2 >/dev/null
    sleep 1
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true

    python3 - "$OUT/vlan_untagged.pcap" "$OUT/vlan_icmp.pcap" <<'PY'
"""Splice VLAN tags into real captured frames (stdlib only).

Single 802.1Q (VID 100) on even frames; 802.1ad S-TAG (VID 200) around
an 802.1Q C-TAG (VID 30) on odd frames. A tag is 4 bytes: TCI then the
EtherType it precedes. The outermost TPID replaces Ethernet.ethertype;
each tag then names the next tag's TPID, and the innermost names the
original payload EtherType -- exactly the on-wire encapsulation.
"""
import struct, sys

def read_pcap(path):
    d = open(path, "rb").read()
    endian = "<" if d[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    c = 24
    while c + 16 <= len(d):
        _, _, incl, _ = struct.unpack_from(endian + "IIII", d, c)
        c += 16
        yield d[c:c + incl]
        c += incl

def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1))
        for fr in frames:
            f.write(struct.pack("<IIII", 0, 0, len(fr), len(fr)))
            f.write(fr)

def tag(frame, tags):
    inner_et = struct.unpack_from("!H", frame, 12)[0]
    body = b""
    for i, (tpid, tci) in enumerate(tags):
        nxt = tags[i + 1][0] if i + 1 < len(tags) else inner_et
        body += struct.pack("!HH", tci, nxt)
    return frame[:12] + struct.pack("!H", tags[0][0]) + body + frame[14:]

SINGLE = [(0x8100, 100)]                 # C-TAG VID 100, PCP 0
QINQ = [(0x88A8, 200), (0x8100, 30)]     # S-TAG VID 200 over C-TAG VID 30
out = [
    tag(fr, SINGLE if i % 2 == 0 else QINQ)
    for i, fr in enumerate(read_pcap(sys.argv[1]))
]
write_pcap(sys.argv[2], out)
print(f"    synthesized {len(out)} tagged frames -> {sys.argv[2]}")
PY

    rm -f "$OUT/vlan_untagged.pcap"
fi

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
echo "[i] Expect vlan-tag counts on every frame (two per QinQ frame, one"
echo "    per single-tag frame), ARP + ICMPv4 echo, zero checksum failures."
echo "    Fold tests/fixtures/staging/vlan_icmp.pcap into tests/fixtures/."
