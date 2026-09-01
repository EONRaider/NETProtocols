# Real-capture fixture corpus

Captured 2026-08-29 with `scripts/capture_fixtures.sh` and
`scripts/capture_fixtures_supplement.sh` (tcpdump on `lo` and the
default interface) and validated by `scripts/check_fixtures.py`:
**every frame's checksums verify internally** (IPv4 header, TCP/UDP
pseudo-header, ICMPv4/v6; fragment slices carry no verifiable
upper-layer checksum — it spans the reassembled datagram). Frames used
as checksum ground truth were captured **inbound only** — outbound
frames routinely leave checksums to NIC offload. 97 frames across 17
scenarios. Addresses are as-captured from the capture host's network.

Four scenarios (`vlan_icmp.pcap`, `dhcp.pcap`, `gre.pcap`,
`dns_tcp.pcap`) are captured separately by their own
`scripts/capture_fixtures_*.sh` over purpose-built topologies — real
kernel vlan devices, a DHCP server/client, a GRE tunnel, and a DNS
server queried over TCP — see their rows and the notes below.

| File | Frames | Contents |
|---|---|---|
| `arp_exchange.pcap` | 4 | ARP requests ×3 + reply ×1 (fresh exchange after neighbor flush) |
| `icmpv4_echo_lo.pcap` | 6 | Loopback echo request/reply pairs (types 8 and 0) |
| `icmpv4_external.pcap` | 2 | Inbound echo replies from 1.1.1.1 |
| `icmpv4_ttl_exceeded.pcap` | 3 | Time Exceeded (type 11) errors from intermediate hops |
| `icmpv6_echo_lo.pcap` | 6 | Loopback ICMPv6 echo pairs (types 128/129) |
| `igmp.pcap` | 4 | IGMPv3 Membership Reports (type 0x22) provoked by joining an IPv4 multicast group |
| `ipv4_fragments.pcap` | 5 | Fragmented 2028-byte echo replies: first fragments (offset 0, MF) + non-first fragments |
| `ipv6_fragments.pcap` | 5 | Fragmented 2048-byte ICMPv6 echo replies: first fragments (offset 0) + non-first fragments behind fragment headers (next_header 44) |
| `ipv6_mld.pcap` | 4 | MLD reports behind hop-by-hop extension headers (next_header 0) — provoked by multicast group join/leave |
| `ipv6_ndp_mld.pcap` | 10 | NDP Neighbor Solicitation/Advertisement (135/136) + echo 128/129 |
| `tcp_http.pcap` | 4 | Inbound HTTP-port segments over IPv6: ACK, PSH-ACK ×2, FIN-ACK — all carrying options |
| `tcp_https.pcap` | 12 | Inbound HTTPS segments over IPv4 (7) and IPv6 (5): ACK/PSH-ACK with options |
| `udp_dns.pcap` | 4 | DNS responses (src port 53) over IPv4 (1) and IPv6 (3), with payloads |
| `vlan_icmp.pcap` | 12 | 802.1Q single-tag (VID 100) and 802.1ad QinQ (S-VID 200 / C-VID 30) frames carrying ARP + ICMPv4 echo — **direct capture** of real kernel-tagged traffic (see VLAN note) |
| `dhcp.pcap` | 4 | DHCP DORA exchange (DISCOVER / OFFER / REQUEST / ACK) over IPv4/UDP — **direct capture** via dnsmasq + dhclient over a veth pair (see DHCP note) |
| `gre.pcap` | 8 | IPv4-in-GRE ICMPv4 echo over a plain and a keyed (RFC 2890) kernel GRE tunnel — `Ethernet→IPv4→GRE→IPv4→ICMPv4`; **direct capture** (see GRE note) |
| `dns_tcp.pcap` | 4 | DNS over TCP (RFC 1035 §4.2.2): A and TXT queries + responses from `dig +tcp` against `dnsmasq` — `Ethernet→IPv4→TCP→DNSOverTCP→DNS`; **direct capture** (see DNS-over-TCP note) |

Consumed by `tests/test_corpus.py` (corpus-wide invariants +
representative field asserts), mirrored into RootWire's test
suite, and later reused as fuzz seeds and pcap-replay goldens.

## Capture notes

- The MLD scenario needed a second pass: the original filter used BPF
  `icmp6`, which matches only `next_header == 58` *directly* — it
  structurally cannot see ICMPv6 behind a hop-by-hop header. The
  supplement captures `ip6 proto 0` instead.
- No inbound SYN-ACK was caught (handshake timing vs. capture start);
  options-bearing segments are otherwise abundant.
- Unknown-EtherType frames are exercised by deliberately synthetic
  fixtures in the unit tests (their point is being unknown), not by the
  corpus.
- `vlan_icmp.pcap` was produced by `scripts/capture_fixtures_vlan.sh`.
  A VLAN tag never reaches a host on an access port, so the script
  builds real 802.1Q / 802.1ad vlan devices over a veth pair, lets the
  kernel `8021q` driver tag the frames, and captures on the parent
  device with tcpdump. veth's VLAN and checksum offload is turned off
  (`ethtool -K`) first, so the tags land **in-band** in the saved bytes
  (EtherType `0x8100` / `0x88a8` at offset 12, not stripped into
  ancillary data) and the inner IPv4/ICMP checksums are computed to
  their real values — `check_fixtures` verifies those inner checksums
  like any other frame. On a kernel without the `8021q` driver the
  script falls back to splicing tag shims over a real untagged capture,
  which is byte-identical; the committed fixture is a direct capture.
- `dhcp.pcap` was produced by `scripts/capture_fixtures_dhcp.sh`: a real
  DHCP DORA exchange between `dnsmasq` (DHCP only) and `dhclient` over a
  veth pair, captured on the server side. The four messages decode
  `Ethernet→IPv4→UDP→DHCP`; `check_fixtures` verifies the UDP checksum,
  which covers the DHCP payload. Offload is disabled first so the
  server's checksums are computed rather than left to "offload".
- `gre.pcap` was produced by `scripts/capture_fixtures_gre.sh`: ICMPv4
  echo across a kernel GRE tunnel built over a veth pair, captured on
  the underlay so each frame is `Ethernet→IPv4 (proto 47)→GRE→IPv4→
  ICMPv4`. Half the frames ride a plain tunnel (GRE flags all clear) and
  half a keyed tunnel (the RFC 2890 key field). `check_fixtures` peels
  the GRE header and verifies the inner IPv4/ICMP checksums.
- `dns_tcp.pcap` was produced by `scripts/capture_fixtures_dns_tcp.sh`:
  a real DNS exchange over TCP — `dig +tcp` querying an A and a TXT
  record against `dnsmasq` answering from its own records — over a veth
  pair, captured on the server side with offload disabled so the TCP
  checksums are computed for real (`check_fixtures` verifies them; the
  TCP checksum covers the length-prefixed DNS message). Only the
  data-bearing segments are kept: each committed frame decodes
  `Ethernet→IPv4→TCP→DNSOverTCP→DNS` cleanly, whereas the connection's
  bare handshake/teardown segments carry no DNS message — walking one
  sends an empty payload into the length shim, the documented
  malformed-frame path of port-based dispatch.

## Provenance note

This corpus exposed a real defect on arrival: non-first IPv4 fragments
were chained into garbage upper-layer decodes ("ICMPv4 type 192" from
mid-payload bytes) because `IPv4.next_protocol()` ignored
`fragment_offset`. Fixed alongside the corpus's introduction; see
`tests/test_corpus.py::TestFragmentHandling`.
