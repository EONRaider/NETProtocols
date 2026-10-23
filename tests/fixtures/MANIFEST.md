# Real-capture fixture corpus

Captured 2026-08-29 with `scripts/capture_fixtures.sh` and
`scripts/capture_fixtures_supplement.sh` (tcpdump on `lo` and the
default interface) and validated by `scripts/check_fixtures.py`:
**every frame's checksums verify internally** (IPv4 header, TCP/UDP
pseudo-header, ICMPv4/v6, SCTP's CRC32c; fragment slices carry no verifiable
upper-layer checksum — it spans the reassembled datagram). Frames used
as checksum ground truth were captured **inbound only** — outbound
frames routinely leave checksums to NIC offload. 117 frames across 19
scenarios. Addresses are as-captured from the capture host's network.

Six scenarios (`vlan_icmp.pcap`, `dhcp.pcap`, `gre.pcap`,
`dns_tcp.pcap`, `ipip.pcap`, `sctp.pcap`) are captured separately by
their own `scripts/capture_fixtures_*.sh` over purpose-built topologies
— real kernel vlan devices, a DHCP server/client, a GRE tunnel, a DNS
server queried over TCP, kernel IP-in-IP encapsulation, and a
userspace SCTP association — see their rows and the notes below.

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
| `tcp_http.pcap` | 4 | Inbound HTTP-port segments over IPv6: ACK, PSH-ACK ×2, FIN-ACK — all carrying options; the two PSH-ACK payloads together are one chunked response, which `tests/test_http.py` decodes as `HTTP` |
| `tcp_https.pcap` | 12 | Inbound HTTPS segments over IPv4 (7) and IPv6 (5): ACK/PSH-ACK with options |
| `udp_dns.pcap` | 4 | DNS responses (src port 53) over IPv4 (1) and IPv6 (3), with payloads |
| `vlan_icmp.pcap` | 12 | 802.1Q single-tag (VID 100) and 802.1ad QinQ (S-VID 200 / C-VID 30) frames carrying ARP + ICMPv4 echo — **direct capture** of real kernel-tagged traffic (see VLAN note) |
| `dhcp.pcap` | 4 | DHCP DORA exchange (DISCOVER / OFFER / REQUEST / ACK) over IPv4/UDP — **direct capture** via dnsmasq + dhclient over a veth pair (see DHCP note) |
| `gre.pcap` | 8 | IPv4-in-GRE ICMPv4 echo over a plain and a keyed (RFC 2890) kernel GRE tunnel — `Ethernet→IPv4→GRE→IPv4→ICMPv4`; **direct capture** (see GRE note) |
| `dns_tcp.pcap` | 4 | DNS over TCP (RFC 1035 §4.2.2): A and TXT queries + responses from `dig +tcp` against `dnsmasq` — `Ethernet→IPv4→TCP→DNSOverTCP→DNS`; **direct capture** (see DNS-over-TCP note) |
| `ipip.pcap` | 4 | IP-in-IP ICMP echo requests: IPv4 in IPv4 (protocol 4, RFC 2003) ×2 and IPv6 in IPv4 (protocol 41, 6in4, RFC 4213) ×2 — `Ethernet→IPv4→IPv4→ICMPv4` and `Ethernet→IPv4→IPv6→ICMPv6`; **direct capture** (see IP-in-IP note) |
| `sctp.pcap` | 16 | One SCTP association (RFC 9260) from usrsctp over raw IPv4: INIT / INIT ACK / COOKIE ECHO / COOKIE ACK, DATA + SACK each way, HEARTBEAT + HEARTBEAT ACK from each end, SHUTDOWN / SHUTDOWN ACK / SHUTDOWN COMPLETE; then one script-built packet carrying an unknown chunk type (63) — `Ethernet→IPv4→SCTP`; **direct capture**, both directions (see SCTP note) |

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
- `ipip.pcap` was produced by `scripts/capture_fixtures_ipip.sh`: ICMP
  echo requests sent through raw IP sockets opened for protocol 4 and
  41 over a veth pair, so the kernel builds the outer IPv4 header (and
  its checksum) exactly as a tunnel endpoint would, captured on the
  receiving side with offload disabled. The inner packets are built by
  the script with real checksums; `check_fixtures` peels the outer
  header and verifies them. The capture host's kernel had no IPv6, so
  only the IPv4-outer combinations are here; IPv4 in IPv6 and IPv6 in
  IPv6 (RFC 2473) are covered by constructed frames in
  `tests/test_ipip.py`, and the script captures them too on a kernel
  with IPv6.

- `sctp.pcap` was produced by `scripts/capture_fixtures_sctp.sh`: the
  capture host's kernel has no SCTP, so the association is between
  usrsctp's example `client` and `echo_server` (Ubuntu's
  `libusrsctp-examples`, usrsctp 0.9.5.0) in two netns over a veth
  pair, running without UDP encapsulation. usrsctp then sends through
  a raw IPv4 socket with `IP_HDRINCL`, so for frames 1-15 **usrsctp
  built the IPv4 header and the whole SCTP packet**, CRC32c included,
  and the kernel filled in the IPv4 total length and header checksum
  (and the identification on the INIT and INIT ACK, where usrsctp left
  it zero). The client sent one line, idled 45 s so each end sent a
  HEARTBEAT, and closed. Frame 16, the unknown chunk (type 63, under a
  verification tag no association uses), was **built by the script**,
  CRC32c included, and sent through a raw protocol-132 socket without
  `IP_HDRINCL`, so **the kernel built its IPv4 header**. The server
  discards it without reply: the type's high bits say so (RFC 9260
  §3.2), and usrsctp's examples set its `sctp_blackhole` sysctl, so
  they never answer an out-of-the-blue packet with an ABORT; ABORT is
  covered by constructed chunks in `tests/test_sctp.py`. Both
  directions were captured on the server's side of the veth pair,
  which is sound here: offload was disabled and every checksum in the
  file is computed in software (the CRC32c in userspace), and
  `check_fixtures` verifies all of them. veth does not pad frames to
  Ethernet's 60-byte minimum, so the short packets here carry no
  trailer; `tests/test_sctp.py` pads them by hand to cover a real NIC's.
  The kernel had no IPv6, so SCTP over IPv6 is covered by constructed
  frames in `tests/test_sctp.py`.

## HTTP captures (`tests/fixtures/http/`)

Outside the corpus on purpose: the corpus globs are non-recursive, and
none of the counts above include these. HTTP is not port-dispatched —
a TCP segment is not an HTTP message — so these frames would add
nothing to the per-frame invariants; what they are for is the byte
streams.

`http.pcap` (98 frames, every TCP checksum verified by
`check_fixtures`) was produced by `scripts/capture_fixtures_http.sh`:
Python's `http.server` (`protocol_version = "HTTP/1.1"`) on one end of
a veth pair, curl and a raw socket client on the other, offload
disabled, every segment kept. `scripts/extract_http_streams.py`
(stdlib only, no netprotocols import) wrote each connection's byte
streams, `NN.request` and `NN.response`, in the order the connections
opened; `tests/test_http.py` reassembles them again through
`decode_frame` and checks they match before decoding them.

| Connection | Client | Requests | Responses |
|---|---|---|---|
| 01 | curl | `GET /hello` | 200, Content-Length |
| 02 | curl | `HEAD /hello` | 200, Content-Length 42 and no body |
| 03 | curl | `GET /hello`, `If-None-Match` | 304 |
| 04 | curl | `POST /echo` | 201, the body echoed |
| 05 | curl | `GET /chunked` | 200, chunked, one trailer field |
| 06 | curl | `GET /missing` | 404, `Connection: close` |
| 07 | socket | `GET /hello`, `HEAD /hello`, `GET /chunked` with `Connection: close`, pipelined in one write | the three responses, in order |

curl cannot pipeline (libcurl's `CURLMOPT_PIPELINING` has no effect for
HTTP/1.1 since 7.62.0), hence the socket client for 07. The streams
also seed `tests/fuzz/fuzz_http_decode.py`.

## Provenance note

This corpus exposed a real defect on arrival: non-first IPv4 fragments
were chained into garbage upper-layer decodes ("ICMPv4 type 192" from
mid-payload bytes) because `IPv4.next_protocol()` ignored
`fragment_offset`. Fixed alongside the corpus's introduction; see
`tests/test_corpus.py::TestFragmentHandling`.
