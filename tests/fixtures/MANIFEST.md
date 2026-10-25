# Real-capture fixture corpus

Captured 2026-08-29 with `scripts/capture_fixtures.sh` and
`scripts/capture_fixtures_supplement.sh` (tcpdump on `lo` and the
default interface) and validated by `scripts/check_fixtures.py`:
**every frame's checksums verify internally** (IPv4 header, TCP/UDP
pseudo-header, ICMPv4/v6, VRRP, SCTP's CRC32c; fragment slices carry no
verifiable upper-layer checksum — it spans the reassembled datagram),
as does every IPsec ICV, with the test keys published below. Frames
used as checksum ground truth were captured **inbound only** — outbound
frames routinely leave checksums to NIC offload. 158 frames across 23
scenarios. Addresses are as-captured from the capture host's network.

Ten scenarios (`vlan_icmp.pcap`, `dhcp.pcap`, `gre.pcap`,
`dns_tcp.pcap`, `ipip.pcap`, `vxlan.pcap`, `esp.pcap`, `ah.pcap`,
`sctp.pcap`, `vrrp.pcap`) are captured separately by their own
`scripts/capture_fixtures_*.sh` over purpose-built topologies — real
kernel vlan devices, a DHCP server/client, a GRE tunnel, a DNS server
queried over TCP, kernel IP-in-IP encapsulation, a kernel VXLAN tunnel,
a userspace SCTP association, IPsec ESP and AH built by a script
and sent through raw sockets, and two keepalived VRRP routers — see
their rows and the notes below.

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
| `vxlan.pcap` | 11 | VXLAN (RFC 7348) over a kernel tunnel on UDP 4789, two segments: VNI 1193046 (`0x123456`) with the outer UDP checksum computed — ARP request/reply, two echo request/reply pairs, one UDP datagram — then VNI 100 with a zero (`noudpcsum`) outer checksum — ARP request/reply, one echo pair — `Ethernet→IPv4→UDP→VXLAN→Ethernet→ARP` / `→IPv4→ICMPv4` / `→IPv4→UDP`; **direct capture** (see VXLAN note) |
| `esp.pcap` | 6 | IPsec ESP (RFC 4303), NULL encryption + HMAC-SHA-256-128, two SAs: transport mode carrying ICMPv4 echo ×2 and UDP ×1 (SPI `0x10000001`, sequence 1-3), tunnel mode carrying inner IPv4 with ICMPv4 echo ×2 and UDP ×1 (SPI `0x10000002`, sequence 1-3) — `Ethernet→IPv4→ESP`, where the walk ends by design; **direct capture** of script-built ESP (see IPsec note) |
| `ah.pcap` | 6 | IPsec AH (RFC 4302), HMAC-SHA-256-128, three SAs: transport mode protecting a TCP SYN (MSS option), an ICMPv4 echo and a UDP datagram (SPI `0x20000001`, sequence 1-3); tunnel mode protecting inner IPv4 with an ICMPv4 echo and a TCP SYN (SPI `0x20000002`, sequence 1-2); and an AH-over-ESP bundle, AH (SPI `0x20000003`) protecting NULL-encrypted ESP (SPI `0x10000003`) carrying an ICMPv4 echo — `Ethernet→IPv4→AH→` then TCP, ICMPv4, UDP, IPv4 (→ ICMPv4 or TCP) or ESP; **direct capture** of script-built datagrams (see IPsec note) |
| `sctp.pcap` | 16 | One SCTP association (RFC 9260) from usrsctp over raw IPv4: INIT / INIT ACK / COOKIE ECHO / COOKIE ACK, DATA + SACK each way, HEARTBEAT + HEARTBEAT ACK from each end, SHUTDOWN / SHUTDOWN ACK / SHUTDOWN COMPLETE; then one script-built packet carrying an unknown chunk type (63) — `Ethernet→IPv4→SCTP`; **direct capture**, both directions (see SCTP note) |
| `vrrp.pcap` | 18 | VRRP adverts from two keepalived 2.2.8 routers, A (`10.9.20.1`, priority 200) and B (`10.9.20.2`, priority 100), four virtual routers: VRID 51, VRRPv2 with `auth_type PASS` (Auth Type 1, password `np-vrrp`) and two addresses — A ×2, A's priority-0 resignation, B taking over ×2, B's resignation; VRID 52, VRRPv2 without authentication (8 zero bytes of Authentication Data), one address — A ×2 and its resignation; VRID 53, VRRPv3 with one address (the minimal 12-byte message) — the same failover as VRID 51; VRID 54, VRRPv3 unicast from A to B, three addresses, Max Adver Int 50 cs — A ×2 and its resignation — `Ethernet→IPv4→VRRP`; **direct capture**, both directions, of a selection from the raw capture (see VRRP note) |

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
- `esp.pcap` was produced by `scripts/capture_fixtures_ipsec.sh`. The
  capture host's kernel has no xfrm ESP transform (`ip xfrm state add
  … proto esp` fails with "Requested type not found"), so it cannot do
  the IPsec processing itself; `scripts/ipsec_fixture_packets.py`
  (stdlib only) builds each ESP packet instead — SPI, sequence number,
  the NULL-encrypted (RFC 2410) payload, the RFC 4303 §2.4 default
  padding (`01 02 …`) to a 4-byte boundary, Pad Length, Next Header,
  and an HMAC-SHA-256-128 ICV (RFC 4868) over all of it — and sends it
  through a raw socket opened for protocol 50 over a veth pair, captured
  on the receiving side with offload disabled. **What the kernel built:
  the outer IPv4 header** (identification, DF, TTL 64, checksum) and the
  Ethernet header. **What the script built: every byte from the SPI
  on**, which the script confirms after the capture by comparing each
  captured datagram past its IPv4 header with what it sent, byte for
  byte. In transport mode the payload is an ICMPv4 echo or UDP datagram
  whose checksum covers the outer header's pseudo-header; in tunnel mode
  it is a whole inner IPv4 packet (`192.0.2.1 → 192.0.2.2`, RFC 5737)
  between the hosts behind the two gateways. `check_fixtures` verifies
  each ICV with the keys below, then the padding, then the inner
  packet's checksums; a frame on an SPI not listed below fails. The
  kernel has no IPv6, so IPv6-outer ESP is covered by constructed
  frames in `tests/test_esp.py`.
- `ah.pcap` was produced by the same script. AH's ICV covers the outer
  IPv4 header (RFC 4302 §3.3.3: every field but TOS, flags, fragment
  offset, TTL and the header checksum, which are zeroed for the
  computation), so unlike ESP the script has to build that header
  itself, with an explicit identification (`0xa101`-`0xa106`), DSCP AF11
  (a mutable field set non-zero on purpose), DF and TTL 64, and send the
  whole datagram with `IP_HDRINCL` (a raw `IPPROTO_RAW` socket).
  **What the script built: every byte of the IPv4 datagram** — header,
  AH with its ICV, and payload. **What the kernel did:** prepended the
  Ethernet header, and it owns three header fields even under
  `IP_HDRINCL`: probed on the capture host, it replaced a deliberately
  wrong total length (0, 999) and a zero header checksum with the
  correct values, and filled in a zero source address (a zero
  identification with DF set it left as 0). The script sends correct
  values for all three, and its post-capture comparison found every
  captured datagram byte-identical to the one it built — so whatever
  the kernel recomputed, it recomputed to the bytes the ICV covers.
  Transport mode protects a TCP SYN, an ICMPv4 echo and a UDP datagram,
  tunnel mode an inner IPv4 packet (`192.0.2.1 → 192.0.2.2`) carrying an
  ICMPv4 echo or a TCP SYN, and the last frame is an AH-over-ESP
  transport-adjacency bundle (RFC 4301 §4.5). `check_fixtures` verifies
  each AH ICV with the keys below, then what it protects: the transport
  checksums against the outer header's pseudo-header, the inner IPv4
  packet, or the bundled ESP packet's own ICV, padding and payload. A
  frame on an SPI not listed below fails, as does AH behind IPv4 header
  options or an IPv6 header, whose ICV `check_fixtures` does not
  compute. IPv6-outer AH, with the 4 bytes of ICV padding
  HMAC-SHA-256-128 needs there, is covered by constructed frames in
  `tests/test_ah.py`.

- `vxlan.pcap` was produced by `scripts/capture_fixtures_vxlan.sh`: a
  kernel VXLAN device (`dstport 4789`) in each of two netns over a veth
  underlay, the overlay addressed and exercised with a fresh ARP
  exchange, `ping`, and one UDP datagram between fixed ports (40000 →
  9999), captured on the underlay with offload disabled on both the
  veth and the vxlan devices. Both directions are kept: every frame was
  built by the kernel, and every checksum computed in software. The
  first segment ran with `udpcsum`, so the outer UDP checksum is real
  and `check_fixtures` verifies it over the whole encapsulated frame;
  the second with `noudpcsum`, so it is zero ("not used", RFC 768), as
  RFC 7348 §5 says it SHOULD be sent. `check_fixtures`
  peels the VXLAN header on destination port 4789 and verifies the
  inner frame's checksums too. The outer source ports are the kernel's
  hash of each inner flow; none is a registered port. This file's echo
  and UDP frames are the corpus's deepest chains, at 7 layers.

- `vrrp.pcap` was produced by `scripts/capture_fixtures_vrrp.sh`:
  keepalived 2.2.8 in two netns over a veth pair, run through four
  segments (one VRID each, see the row above), captured on B's side
  with offload disabled. **What keepalived built: the whole IPv4
  datagram but its header checksum** — it sends through a raw socket
  with `IP_HDRINCL` (TOS `0xc0`, TTL 255, its own identification
  counter), and `strace`, run once while developing the script,
  showed it handing the kernel a zero header checksum for the kernel
  to fill — plus every byte of the VRRP message, checksum included.
  **What the kernel built:** the IPv4 header checksum and the Ethernet
  header. A master advertises once per interval for as long as it
  runs, so the script drives each segment by watching the capture,
  then keeps a fixed selection: each router's first two adverts with a
  nonzero priority in each segment, and its priority-0 advert; the gaps
  this leaves in the identification counters are adverts it dropped.
  It asserts the kept frames' composition exactly. `check_fixtures`
  verifies every VRRP checksum: the message alone for VRRPv2 (RFC 3768
  §5.3.8), behind the IPv4 pseudo-header for VRRPv3 (RFC 5798 §5.2.8) —
  with the real destination, so for VRID 54 the unicast peer's address
  rather than `224.0.0.18`. That is keepalived's default; its
  `v3_checksum_as_v2` option, and RFC 9568, which obsoletes RFC 5798,
  leave the IPv4 pseudo-header out, and such an advert fails both
  `check_fixtures` and `verify()`. It also requires each message's
  length, from its version and count, to be the IP payload's exactly.
  veth does not pad a short frame, so none of these frames carries
  Ethernet padding (they are 46-58 bytes); `tests/test_vrrp.py` pads
  them to 60 bytes, and appends a 4-byte trailer, to show the walk
  leaves both undecoded. The kernel has no IPv6, so VRRPv3 over IPv6
  is covered by constructed frames in `tests/test_vrrp.py`, with
  checksums computed there and checked by `check_fixtures` too.

### IPsec test keys

Published so anyone can verify the captures: these keys protect
nothing. Every SA uses HMAC-SHA-256-128 (RFC 4868: HMAC-SHA-256 with a
256-bit key, the output truncated to its first 16 bytes) for integrity;
every ESP SA uses NULL encryption (RFC 2410). Sequence numbers are
32-bit (no ESN). The keys are also hard-coded, independently, in
`scripts/check_fixtures.py`, `tests/test_esp.py` and `tests/test_ah.py`.

| SPI | Protocol | Mode | Integrity key (hex) |
|---|---|---|---|
| `0x10000001` | ESP | transport | `e41126360fbc54a0e11a8747218b24d0cc4638f579c3985017b4d0ab1a30398b` |
| `0x10000002` | ESP | tunnel | `4bc3ce948208049b2f5016e06616867773924d2ccb4dab8b3aff93e6d26f3834` |
| `0x10000003` | ESP | transport, inside the AH bundle | `107c873bdbb0c7a11be8aa1d9064e51f63b26098412295c3bd6785958abd44d4` |
| `0x20000001` | AH | transport | `8eaa03a41a3b08f31a67f3a4b7fd78a2bf3d963a97b0af5a104301ef8fbff685` |
| `0x20000002` | AH | tunnel | `d2142153fb758a3f698e45720e2af765b2ada021d70ac1bcbde1f5bc38514fd1` |
| `0x20000003` | AH | transport, over the bundled ESP | `008a9a220d8c1bf5edec1838a724b588364c08314bf93206985e776c385e1c7a` |

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
