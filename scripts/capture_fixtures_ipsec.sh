#!/usr/bin/env bash
# Capture IPsec fixtures for the corpus: ESP (RFC 4303).
#
#     sudo scripts/capture_fixtures_ipsec.sh
#
# The packets are genuine, verifiable IPsec: ESP with NULL encryption
# (RFC 2410) and HMAC-SHA-256-128 integrity (RFC 4868), in transport
# mode (ICMP and UDP riding ESP directly) and tunnel mode (a whole
# inner IPv4 packet), with the RFC 4303 padding / Pad Length / Next
# Header trailer and an ICV over every packet. NULL encryption keeps the
# payload readable, so check_fixtures.py can verify each ICV with the
# test keys published in tests/fixtures/MANIFEST.md and then the inner
# packet's own checksums.
#
# Many kernels -- minimal and VM builds in particular -- ship without
# the xfrm ESP transform (`ip xfrm state add ... proto esp` fails with
# "Requested type not found"), so the kernel cannot do the IPsec
# processing itself. scripts/ipsec_fixture_packets.py builds the ESP
# packets in stdlib Python instead and sends them through a raw socket
# opened for protocol 50, so the kernel still builds and checksums the
# outer IPv4 header exactly as an IPsec endpoint's stack would. After
# the capture the same script reads the pcap back and checks, frame by
# frame, that every byte it built arrived unchanged.
#
# veth is a purely local link, so tx/rx offload is disabled first
# (ethtool -K) to keep every checksum computed in software.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump python3 ethtool; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
PACKETS="scripts/ipsec_fixture_packets.py"
NSA=npesa
NSB=npesb
A=npesva
B=npesvb
WORK=""
cleanup() {
    ip netns del "$NSA" 2>/dev/null || true
    ip netns del "$NSB" 2>/dev/null || true
    ip link del "$A" 2>/dev/null || true
    [[ -z $WORK ]] || rm -rf "$WORK"
}
trap cleanup EXIT
cleanup
WORK=$(mktemp -d)

echo "[*] veth + two netns (A 10.9.11.1, B 10.9.11.2)"
ip netns add "$NSA"; ip netns add "$NSB"
ip link add "$A" type veth peer name "$B"
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip -n "$NSA" addr add 10.9.11.1/24 dev "$A"
ip -n "$NSB" addr add 10.9.11.2/24 dev "$B"
ip netns exec "$NSA" ethtool -K "$A" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSB" ethtool -K "$B" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSA" link set lo up; ip -n "$NSA" link set "$A" up
ip -n "$NSB" link set lo up; ip -n "$NSB" link set "$B" up
sleep 1

# capture KIND FILTER: send one kind of packet from A, capture it on B,
# then cross-check the capture against what the script built.
capture() {
    local kind=$1 filter=$2
    echo "[>] $kind"
    ip netns exec "$NSB" tcpdump -i "$B" -w "$OUT/$kind.pcap" --immediate-mode -U -q \
        "$filter" >/dev/null 2>&1 &
    local pid=$!
    sleep 1
    ip netns exec "$NSA" python3 "$PACKETS" send "$kind" "$WORK/$kind.sent"
    sleep 1
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    python3 "$PACKETS" compare "$kind" "$OUT/$kind.pcap" "$WORK/$kind.sent"
}

capture esp 'ip proto 50'

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
echo "[i] Expect zero checksum or ICV failures and 6 ESP frames: three"
echo "    transport-mode (ICMP x2, UDP) and three tunnel-mode (inner IPv4"
echo "    carrying ICMP x2, UDP). Fold tests/fixtures/staging/esp.pcap into"
echo "    tests/fixtures/."
