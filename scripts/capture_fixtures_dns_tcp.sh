#!/usr/bin/env bash
# Capture a DNS-over-TCP fixture for the corpus (RFC 1035 §4.2.2).
#
#     sudo scripts/capture_fixtures_dns_tcp.sh
#
# A real DNS exchange over TCP needs a server and a client. This runs
# dnsmasq (DNS only, answering from its own records) on one end of a
# veth pair and dig +tcp on the other, querying an A and a TXT record,
# and captures the data-bearing segments: each one decodes
# Ethernet -> IPv4 -> TCP -> DNSOverTCP -> DNS, so the TCP application
# dispatch and the 2-byte length shim ride the corpus invariants on
# genuine bytes. check_fixtures.py verifies the TCP checksum, which
# covers the length-prefixed DNS message.
#
# The capture keeps only segments that carry TCP payload. The bare
# handshake/teardown segments of the connection are real too, but they
# hold no DNS message: walking one would send the empty payload into
# the DNSOverTCP shim — the documented malformed-frame path of
# port-based dispatch — while every committed corpus frame must decode
# its full chain cleanly.
#
# veth is a purely local link, so tx/rx offload is disabled first
# (ethtool -K) or the checksums are left to "offload" and never
# computed.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for veth/netns setup and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump dnsmasq dig python3 ethtool; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

OUT="tests/fixtures/staging"
mkdir -p "$OUT"
NSS=npdts
NSC=npdtc
S=npdtsv
C=npdtcv
dnsmasq_pid=""
cleanup() {
    [[ -n $dnsmasq_pid ]] && kill "$dnsmasq_pid" 2>/dev/null || true
    ip netns del "$NSS" 2>/dev/null || true
    ip netns del "$NSC" 2>/dev/null || true
    ip link del "$S" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

no6() {
    $1 sysctl -qw net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
    $1 sysctl -qw net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
}

echo "[*] veth + two netns (server 10.9.7.1; client 10.9.7.2)"
no6 ""
ip netns add "$NSS"; ip netns add "$NSC"
no6 "ip netns exec $NSS"; no6 "ip netns exec $NSC"
ip link add "$S" type veth peer name "$C"
ip link set "$S" netns "$NSS"
ip link set "$C" netns "$NSC"
ip -n "$NSS" addr add 10.9.7.1/24 dev "$S"
ip -n "$NSC" addr add 10.9.7.2/24 dev "$C"
ip netns exec "$NSS" ethtool -K "$S" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec "$NSC" ethtool -K "$C" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
ip -n "$NSS" link set lo up; ip -n "$NSS" link set "$S" up
ip -n "$NSC" link set lo up; ip -n "$NSC" link set "$C" up

echo "[>] dns over tcp (dnsmasq server + dig +tcp: A and TXT queries)"
ip netns exec "$NSS" dnsmasq --no-daemon --no-resolv --no-hosts \
    --interface="$S" --bind-interfaces --except-interface=lo \
    --host-record=netprotocols.test,10.9.7.42 \
    --txt-record=netprotocols.test,"NETProtocols DNS-over-TCP fixture" \
    --local-ttl=300 --pid-file=/tmp/np-dnsmasq-dns.pid \
    >/dev/null 2>&1 &
dnsmasq_pid=$!
sleep 1

# Only segments carrying TCP payload: total length minus the IP and TCP
# header lengths must be nonzero (the DNS query and its response).
FILTER='tcp port 53 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
ip netns exec "$NSS" tcpdump -i "$S" -w "$OUT/dns_tcp.pcap" \
    --immediate-mode -U -q "$FILTER" >/dev/null 2>&1 &
pid=$!
sleep 1

ip netns exec "$NSC" dig +tcp +tries=1 +time=3 @10.9.7.1 \
    netprotocols.test A >/dev/null || true
ip netns exec "$NSC" dig +tcp +tries=1 +time=3 @10.9.7.1 \
    netprotocols.test TXT >/dev/null || true
sleep 1

kill -INT "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

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
echo "[i] Expect 4 frames (ipv4 + tcp), zero checksum failures: the A"
echo "    and TXT queries and their responses, each decoding"
echo "    Ethernet -> IPv4 -> TCP -> DNSOverTCP -> DNS. Fold"
echo "    tests/fixtures/staging/dns_tcp.pcap into tests/fixtures/."
