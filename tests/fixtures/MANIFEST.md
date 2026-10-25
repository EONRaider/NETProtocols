# Real-capture fixture corpus

Captured 2026-08-29 with `scripts/capture_fixtures.sh` and
`scripts/capture_fixtures_supplement.sh` (tcpdump on `lo` and the
default interface) and validated by `scripts/check_fixtures.py`:
**every frame's checksums verify internally** (IPv4 header, TCP/UDP
pseudo-header, ICMPv4/v6, VRRP, PIM, SCTP's CRC32c, CDP, the OSPF packet
checksum and every OSPF LSA's Fletcher checksum; fragment slices carry no
verifiable upper-layer checksum — it spans the reassembled datagram),
as does every IPsec ICV, every RIPv2 keyed digest and every OSPF MD5
digest, with the test keys published below. Frames
used as checksum ground truth were captured **inbound only** — outbound
frames routinely leave checksums to NIC offload. 279 frames across 28
scenarios. Addresses are as-captured from the capture host's network.

Fifteen scenarios (`vlan_icmp.pcap`, `dhcp.pcap`, `gre.pcap`,
`dns_tcp.pcap`, `ipip.pcap`, `vxlan.pcap`, `esp.pcap`, `ah.pcap`,
`sctp.pcap`, `vrrp.pcap`, `rip.pcap`, `ospf.pcap`, `pim.pcap`,
`bgp.pcap`, `llc.pcap`) are captured separately by their own
`scripts/capture_fixtures_*.sh` over purpose-built topologies — real kernel vlan devices, a DHCP
server/client, a GRE tunnel, a DNS server queried over TCP, kernel
IP-in-IP encapsulation, a kernel VXLAN tunnel, a userspace SCTP
association, IPsec ESP and AH built by a script and sent through raw
sockets, two keepalived VRRP routers, two BIRD routers speaking RIP,
two FRR OSPF routers, two FRR PIM-SM routers, BGP sessions between
three BIRD speakers, and two STP bridges with lldpd speaking CDP — see
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
| `rip.pcap` | 21 | RIP between two BIRD 2.14 routers on UDP 520, five scenarios of 4 frames each (each router's first Request, for the whole table, and its first Response, carrying its routes): RIPv1 broadcast (3 classful routes per Response), RIPv2 multicast with no authentication (4 routes, plus one periodic update of 7 entries, 3 of them poisoned reverse at metric 16), a plain-text password, keyed MD5 and HMAC-SHA-256 (RFC 4822, with a 20- and a 36-byte authentication trailer) — `Ethernet→IPv4→UDP→RIP`; **direct capture**, both directions (see RIP note) |
| `ospf.pcap` | 54 | OSPFv2 (RFC 2328) between two FRR 8.4 routers on one broadcast network in area 0, three adjacencies in turn: AuType 0 (no authentication), AuType 1 (simple password) and AuType 2 (keyed MD5), 18 frames each — 6 Hellos (one with an empty neighbor list, DR/BDR election), 5 Database Descriptions (the I/M/MS exchange, LSA headers), 2 Link State Requests, 3 Link State Updates (router, network and AS-external LSAs, 6 per adjacency) and 2 Link State Acknowledgments — `Ethernet→IPv4→OSPF`; **direct capture**, both directions (see OSPF note) |
| `bgp.pcap` | 19 | BGP-4 (RFC 4271) over TCP 179 between BIRD 2.14 speakers, an eBGP (AS 65001-65002) and an iBGP (AS 65001) session: an OPEN each way on each, a KEEPALIVE each way on each, 23 UPDATEs (announcements with ORIGIN, AS_PATH, NEXT_HOP, MULTI_EXIT_DISC and, over iBGP, LOCAL_PREF; End-of-RIB markers; a five-prefix withdrawal to each peer), one segment carrying 7 messages and others 2-6, and a Cease / Administrative Shutdown NOTIFICATION to each peer — `Ethernet→IPv4→TCP→BGP` (→ `BGP` …); **direct capture**, both directions, only the segments that hold whole messages, and of those carrying nothing but a KEEPALIVE only the first per direction per session (see BGP note) |
| `sctp.pcap` | 16 | One SCTP association (RFC 9260) from usrsctp over raw IPv4: INIT / INIT ACK / COOKIE ECHO / COOKIE ACK, DATA + SACK each way, HEARTBEAT + HEARTBEAT ACK from each end, SHUTDOWN / SHUTDOWN ACK / SHUTDOWN COMPLETE; then one script-built packet carrying an unknown chunk type (63) — `Ethernet→IPv4→SCTP`; **direct capture**, both directions (see SCTP note) |
| `vrrp.pcap` | 18 | VRRP adverts from two keepalived 2.2.8 routers, A (`10.9.20.1`, priority 200) and B (`10.9.20.2`, priority 100), four virtual routers: VRID 51, VRRPv2 with `auth_type PASS` (Auth Type 1, password `np-vrrp`) and two addresses — A ×2, A's priority-0 resignation, B taking over ×2, B's resignation; VRID 52, VRRPv2 without authentication (8 zero bytes of Authentication Data), one address — A ×2 and its resignation; VRID 53, VRRPv3 with one address (the minimal 12-byte message) — the same failover as VRID 51; VRID 54, VRRPv3 unicast from A to B, three addresses, Max Adver Int 50 cs — A ×2 and its resignation — `Ethernet→IPv4→VRRP`; **direct capture**, both directions, of a selection from the raw capture (see VRRP note) |
| `pim.pcap` | 13 | PIM-SM (RFC 7761) between two FRR 8.4 routers (zebra + pimd) on the link between them: Hello ×3 (R1's with Holdtime, LAN Prune Delay, DR Priority, Generation ID and Address List; R2's without an Address List; R2's Holdtime-0 goodbye), Register ×2 (a data Register carrying the source's UDP datagram, a Null-Register), Register-Stop ×1, and Join/Prune ×7 — (*,G) and (S,G) joins, (S,G) and (*,G) prunes, and one message joining (*,G) while pruning (S,G,rpt) — `Ethernet→IPv4→PIM`; **direct capture**, a selection of one frame of each kind, R1's outbound Hello and Registers among them (see PIM note) |
| `llc.pcap` | 14 | Frames whose type/length field is not an EtherType: in all but the last it is an IEEE 802.3 Length, and in all but the raw IPX one an 802.2 LLC header follows it. Five 802.1D BPDUs from two Linux bridges (Configuration BPDUs from each, the root's with Topology Change and with Topology Change + Acknowledgment, and a 21-byte Topology Change Notification) — `Ethernet→LLC` (DSAP 0x42); CDPv1 and CDPv2 from lldpd 1.0.18, and a CDPv1 frame whose odd-length PDU ends in the byte 0xA9 — `Ethernet→LLC→SNAP` (OUI 00-00-0C, PID 0x2000); and six script-built frames: RFC 1042 ARP padded to 60 bytes and RFC 1042 ICMPv4 echo — `Ethernet→LLC→SNAP→ARP` / `→IPv4→ICMPv4`; IEEE 802.1H (OUI 00-00-F8) ARP; RFC 1042 ARP behind an 802.1Q tag (VID 30) — `Ethernet→VLAN→LLC→SNAP→ARP`; Novell raw 802.3 IPX — `Ethernet→LLC`; and a type/length value of 1501 — `Ethernet`; **direct capture**, both directions, a selection of one frame of each kind (see LLC note) |

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
  corpus. The one exception is `llc.pcap`'s script-built frame whose
  type/length value, 1501, IEEE 802.3 leaves undefined.
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
  and UDP frames are the deepest chains outside `bgp.pcap`, at 7 layers.

- `bgp.pcap` was produced by `scripts/capture_fixtures_bgp.sh`: three
  BIRD 2.14 instances in their own netns on one Linux bridge — A (AS
  65001) with an eBGP session to B (AS 65002) and an iBGP session to C
  (AS 65001) — captured on the bridge, so both sessions and both
  directions are in one file. Offload (checksum, TSO, GSO, GRO) was
  disabled on every veth end first, so the kernel computed every TCP
  checksum and no segment exceeds the 1460-byte MSS; `check_fixtures`
  verifies them all. **What BIRD built: every BGP message** (the TCP
  payload); **what the kernel built: the Ethernet, IPv4 and TCP
  headers.** A originates five prefixes of different lengths (/24 to
  /32), each with its own MED, B two with a MED and 600 /24s without
  one, C one; then A withdraws its five and shuts both sessions down
  with an RFC 9003 shutdown communication. Both speakers advertised
  4-byte AS numbers (RFC 6793), so every AS_PATH carries 4-byte ones.
  The script writes every frame to `bgp/bgp_session.pcap` (see below)
  and keeps here only the frames whose payload is a whole number of
  complete messages — of those carrying nothing but a KEEPALIVE, only
  the first in each direction of each session — since a bare ACK or a
  segment that starts or ends inside a message does not walk cleanly.
  It checks what each direction's reassembled stream announced and
  withdrew, prefix by prefix, before writing either file. The busiest
  segment carries 7 UPDATEs, a 10-layer chain and the corpus's deepest.
  The kernel had no IPv6, so BGP over IPv6 is covered by constructed
  frames in `tests/test_bgp.py`.

- `vrrp.pcap` was produced by `scripts/capture_fixtures_vrrp.sh`:
  keepalived 2.2.8 in two netns over a veth pair, run through four
  segments (one VRID each, see the row above), captured on B's side.
  The script asks ethtool to turn offload off first but, like the
  other capture scripts, does not check that it did; what is
  guaranteed is that `check_fixtures` verifies every IPv4 header
  checksum and VRRP checksum in the file. **What keepalived built:
  the whole IPv4 datagram but its header checksum** — it sends
  through a raw socket with `IP_HDRINCL` (TOS `0xc0`, TTL 255, its
  own identification counter), and `strace`, run once while
  developing the script, showed it handing the kernel a zero header
  checksum for the kernel to fill — plus every byte of the VRRP
  message, checksum included.
  **What the kernel built:** the IPv4 header checksum and the Ethernet
  header. A master advertises once per interval for as long as it
  runs, so the script drives each segment by watching the capture,
  then keeps a fixed selection: each router's first two adverts with a
  nonzero priority in each segment, and its priority-0 advert; the gaps
  this leaves in the identification counters are adverts it dropped.
  It asserts the kept frames' composition exactly. `check_fixtures`
  verifies every VRRP checksum: the message alone for VRRPv2 (RFC 3768
  §5.3.8), behind the IPv4 pseudo-header for VRRPv3 — with the real
  destination, so for VRID 54 the unicast peer's address rather than
  `224.0.0.18`. That is keepalived's default; RFC 5798 §5.2.8 cites
  only RFC 2460's pseudo-header, which is IPv6's. keepalived's
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

- `ospf.pcap` was produced by `scripts/capture_fixtures_ospf.sh`: FRR
  8.4's `zebra` and `ospfd` in each of two netns over a veth pair, with
  2 s hello and 8 s dead intervals; router A (router ID 10.0.0.1,
  priority 10) also redistributes a connected /32, 192.0.2.1, so it
  originates an AS-external LSA. For each AuType the daemons are started
  fresh, A first and alone until it has elected itself Designated
  Router, off the capture; then the capture starts and B comes up, so
  the whole adjacency (2-Way, the Database Description exchange, the
  requests, the flooding and its acknowledgments) is captured within
  seconds of B's first Hello, and the capture stops once both routers
  are Full with all four LSAs in both databases, before any daemon is
  stopped. The three
  captures are concatenated, AuType 0, 1, 2 in that order. **What
  ospfd built: every OSPF byte** — header, messages, the packet
  checksum, every LSA and its LS checksum, and the MD5 digest. **What
  the kernel built:** the IPv4 header (TOS `0xc0`, TTL 1, to
  224.0.0.5 or the neighbor) and the Ethernet header. Both directions
  were captured on B's side of the veth pair with offload disabled; all
  of those checksums are computed in software (OSPF's in userspace).
  `check_fixtures` verifies the IPv4 header checksums, the OSPF packet
  checksum of every AuType 0 and 1 packet (the internet checksum of the
  packet but its Authentication field, RFC 2328 §D.4.1), the published
  password of every AuType 1 packet, the keyed-MD5 digest (RFC 2328
  §D.4.3) of every AuType 2 packet, whose packet checksum must be zero,
  with the published key, and every LSA's Fletcher checksum (RFC 2328
  §12.1.7) in its own verification form. ospfd sent no Link-Local
  Signaling (RFC 5613): no Hello or Database Description sets the L bit,
  and every IP payload is exactly Packet Length (plus the 16-byte digest
  under MD5), which the script asserts. Bytes after a packet (LLS,
  Ethernet padding, an FCS) and OSPFv3 over IPv6 (the kernel had no
  IPv6) are covered by constructed frames in `tests/test_ospf.py`. How
  B's two router LSAs are packed into updates varied between runs (one
  update, or one each); this capture has them together.

### OSPF test secrets

Published for the same reason as the IPsec keys below. Also hard-coded,
independently, in `scripts/check_fixtures.py` and `tests/test_ospf.py`.

| AuType | Secret |
|---|---|
| 1, simple password | `NPospf1` (NUL-padded to the 8-byte field) |
| 2, keyed MD5, Key ID 1 | `NETProtocols-md5` |

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

- `pim.pcap` was produced by `scripts/capture_fixtures_pim.sh`: four
  netns in a line over three veth pairs — a multicast source, two FRR
  8.4 routers (zebra + pimd, R1 `10.184.12.1` with a secondary
  `10.184.13.1` on the captured link, R2 `10.184.12.2`) and a receiver
  that joins two groups from a socket with `IP_ADD_MEMBERSHIP` (IGMPv3,
  `ip igmp` on R2's receiver-facing interface). Static RPs are on
  opposite routers — R2 for `239.184.0.1`, R1 for `239.184.0.2` — so
  both a (*,G) tree and a Register exchange cross the R1–R2 link, where
  tcpdump captured `ip proto 103` on R1's side. So R1's own Hello and
  both Registers (frames 1, 4 and 8) are outbound frames, despite the
  inbound-only rule above, and the other ten are R2's, inbound. That
  is harmless here, as for SCTP: pimd computes every PIM checksum
  itself, in userspace, before the kernel sees the packet, the kernel
  computes IPv4 header checksums in software, the script asks ethtool
  to turn veth offloads off, and `check_fixtures` verifies all of
  them. `ip pim
  register-suppress-time 15` brings R1's Null-Register probe inside the
  capture. The receiver then leaves (R2 prunes), and R2's pimd is
  stopped (its goodbye Hello). Hello and Join/Prune timers make the raw
  capture's frame count vary, so the script keeps the first frame of
  each of the 13 kinds it names and fails unless it saw all of them;
  the committed file is that selection. **pimd built every PIM
  message**, checksum included, **and the outer IPv4 headers**: FRR
  8.4's `pim_msg_send()` fills in the identification, TOS, TTL, total
  length and addresses and sends with `IP_HDRINCL` (`IPPROTO_RAW` for
  Registers), so **the kernel filled in only the IPv4 header checksum
  and total length**, as it always does for such a socket.
  FRR sums a Register's checksum over its first 8 bytes
  only, as RFC 7761 §4.9.3 specifies; `check_fixtures` accepts that or
  the whole-message form the RFC asks receivers to accept too. The data
  Register's encapsulated packet is the source's datagram as R1
  received it (IPv4 header and UDP checksum built by the source's
  kernel), and `check_fixtures` verifies it too. The Null-Register's
  dummy IPv4 header carries a zero header checksum, which RFC 7761
  §4.9.3 says a receiver must not check, so `check_fixtures` counts it
  as `pim-null-register-unchecked` (an IPv6 Null-Register's dummy PIM
  header, which no capture here holds, is checked by its own checksum;
  `tests/test_pim.py` builds two). veth does not pad frames, and the
  shortest here (the Register-Stop, a 38-byte datagram) would get 8
  bytes of zero padding from a real NIC; `tests/test_pim.py` appends
  padding and a 4-byte trailer by hand. The kernel had no IPv6, so PIM
  over IPv6 is covered by constructed frames in `tests/test_pim.py`,
  their pseudo-header checksums computed there independently. No
  capture holds an Assert, Bootstrap, Candidate-RP-Advertisement or
  Graft: `tests/test_pim.py` builds an Assert and Graft messages, and
  decodes the other types with their body kept raw.

- `rip.pcap` was produced by `scripts/capture_fixtures_rip.sh`: two
  BIRD 2.14 daemons, one per netns over a veth pair, each exporting
  three static blackhole routes (and, over RIPv2, its connected
  10.9.52.0/24) with a 5-second update timer, run once per scenario
  with tcpdump on 10.9.52.1's side of the pair and offload disabled on
  both ends. **BIRD built every RIP byte**, the authentication entries
  and trailers included; **the kernel built the UDP header** (its
  checksum computed in software, and verified by `check_fixtures`),
  **the IPv4 header and the Ethernet header**. Updates follow at times
  a capture cannot pin down, so the script captures each scenario whole
  and keeps a fixed selection, asserting it exactly: per scenario, each
  router's first Request and first Response, and in the RIPv2 scenario
  10.9.52.1's first Response whose whole-second pcap timestamp is 6 or
  more past the scenario's first captured frame's, hence more than 5 s
  after it (not necessarily the first Response more than 5 s after),
  past its 5-second update timer: a whole-table update, carrying the
  peer's routes back poisoned. BIRD sends a RIPv1 router only classful
  networks, so the v1 routes are a class A, B and C network and the
  connected /24 is not advertised. In the RFC 4822 scenarios BIRD fills
  in Auth Data Len as 20 for keyed MD5, counting the trailer's 4-byte
  header with the 16-byte digest, and as 32 for HMAC-SHA-256, the digest
  alone, as the RFC says; `tests/test_rip.py` pins both. The sequence
  numbers of the Responses come from BIRD's clock, so a re-capture
  differs in them, the digests, the IPv4 identification and the
  timestamps. Everything here is IPv4: RIP has no IPv6 form (RIPng,
  RFC 2080, is a separate protocol on UDP 521, not decoded), and veth
  does not pad, so no frame carries Ethernet padding or an FCS;
  `tests/test_rip.py` appends a 4-byte trailer to every frame and cuts
  one inside an entry to cover both.

- `llc.pcap` was produced by `scripts/capture_fixtures_llc.sh`: three
  netns, A and B each holding a Linux bridge with STP on (802.1D, 1 s
  hello time, 2 s forward delay; A at priority 0x1000, so the root),
  a veth pair between A's port and B's, and a second from B's other
  port to netns X, with tcpdump on B's port facing A capturing both
  directions (`not ether proto 0x88cc`, so no LLDP). Bringing the A-B
  link up gives each bridge's first Configuration BPDU, then A's, as
  root, and A's with the Topology Change flag once its port forwards;
  bringing B's second port up makes B, not the root, send a Topology
  Change Notification, which A acknowledges. lldpd 1.0.18 then runs in
  A on A's port, with its own control socket, pidfile and interface
  list, `-cc` (CDPv1 forced), then `-ccc` (CDPv2 forced), then `-cc`
  again with the platform name `npll` and the byte 0xA9, in its own
  UTS namespace with hostname `npllc-cdp`, `-k`, `-S` and `-P`, so the
  frames carry no detail of the capture host. Last,
  `scripts/llc_fixture_frames.py` (stdlib only) sends six frames from A
  through an `AF_PACKET` socket. **The kernel's bridge code built every
  BPDU** (Ethernet header, LLC header and BPDU), **lldpd built every
  CDP frame** in userspace, its checksum included, and **the script
  built every byte of the other six**, their zero padding to 60 bytes
  and the IPv4 header and ICMP checksums included; `AF_PACKET` sends a
  frame as it is given. The bridges and veths have fixed MAC addresses,
  so the BPDUs' bridge and port IDs are the same on every run. BPDUs
  repeat every second and CDP frames too, so the script keeps the first
  frame of each of the 14 kinds it names and fails unless it saw all of
  them, in order. `check_fixtures` holds each 802.3 Length against its
  frame (only the zero padding of a PDU shorter than 46 bytes may
  follow), checks the LLC and SNAP framing and the BPDU and raw IPX
  lengths, walks the CDP TLVs to the Length's end and verifies the CDP
  checksum over exactly that PDU (91 bytes in all three, odd: where RFC
  1071 pads a final byte into the high byte of a word, CDP's checksum
  adds it as a signed octet, as the low byte when it is below 0x80 and
  as its value less 0x100 when not; the third frame, ending in 0xA9, is
  there to pin that, and lldpd's frames verify that way), and verifies
  the IPv4 and ICMP checksums inside RFC 1042 framing. veth does not
  pad, so the BPDUs and CDP frames carry no padding (the TCN is a
  21-byte frame); `tests/test_llc.py` appends padding and a 4-byte
  FCS by hand. The library decodes BPDUs only as far as their LLC
  header and CDP as far as SNAP: STP and CDP decoders are later work.

### RIP test keys

Published so anyone can verify the captures: these passwords protect
nothing. `check_fixtures` verifies every keyed-MD5 digest (MD5 over the
message up to and including the trailer's header, then the key
zero-padded to 16 bytes, RFC 4822 §2.4) and every HMAC-SHA-256 digest
(over the same bytes followed by the Apad `0x878FE1F3` repeated over
the digest's length, §2.5), keyed by Key ID; the keys are also
hard-coded, independently, in `scripts/check_fixtures.py` and
`tests/test_rip.py`.

| Scenario | Authentication | Key ID | Password |
|---|---|---|---|
| plaintext | plain-text password (type 2) | — | `nprip-pw` |
| md5 | keyed MD5 (type 3) | 1 | `nprip-md5-key` |
| sha256 | HMAC-SHA-256 (type 3) | 2 | `nprip-sha256-key` |

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

## BGP session capture (`tests/fixtures/bgp/`)

Outside the corpus on purpose, like the HTTP captures above: none of
the counts above include it. `bgp_session.pcap` (94 frames, every TCP
checksum verified by `check_fixtures`) is every frame of the session
`bgp.pcap` was cut from, the handshakes, bare ACKs, FINs and
KEEPALIVE-only segments included. Its point is the segments a
per-segment walk cannot decode whole: frame 31 holds two complete
UPDATEs and the first 332 bytes of a 1063-byte third, which frame 33
finishes; frames 34-35 and 86-87 each split one UPDATE (2090 and 2430
bytes) between them. `tests/test_bgp.py` walks those strictly and in
lax mode, and reassembles each direction's stream to check it is
nothing but whole messages.

## Provenance note

This corpus exposed a real defect on arrival: non-first IPv4 fragments
were chained into garbage upper-layer decodes ("ICMPv4 type 192" from
mid-payload bytes) because `IPv4.next_protocol()` ignored
`fragment_offset`. Fixed alongside the corpus's introduction; see
`tests/test_corpus.py::TestFragmentHandling`.
