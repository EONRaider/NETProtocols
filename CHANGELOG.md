# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`VRRP` and `VRRPv6`: the Virtual Router Redundancy Protocol, VRRPv2 (RFC 3768) and VRRPv3 (RFC 5798) (#181).** IP protocol 112 (`IPProtocol.VRRP`, "VRRP") now dispatches to `netprotocols.VRRP` from IPv4 and to its subclass `VRRPv6` from IPv6 and its extension headers. One class decodes both versions and branches on the version nibble: the fixed fields `version`, `type`, `vrid`, `priority`, `count_ip_addrs` and `checksum`, the 16 bits between Count and Checksum kept raw as `adver_word` and read through per-version accessors that return `None` where the version has no such field (`auth_type`/`auth_type_name` and `adver_int` in seconds for VRRPv2; `reserved` and `max_adver_int` in centiseconds for VRRPv3; `advertisement_interval` in seconds for either), the virtual `addresses`, and VRRPv2's 8 bytes of `auth_data` (the null-padded password under Auth Type 1, keepalived's `auth_type PASS`). The address width depends on the IP family, not on anything in the header, which is why the class comes as a pair: `VRRP` reads 4-byte addresses and `VRRPv6` 16-byte ones, and `VRRPv6` accepts VRRPv3 only, since RFC 3768 defines VRRPv2 for IPv4 alone. VRRP has no length field, but the version and count give its exact length, which is `header_len`, so Ethernet padding and an FCS after the message are left undecoded and `bytes(VRRP.decode(x)) == x[:header_len]`. A version other than 2 or 3 raises `InvalidFieldError` (`field="version"`, `offset=0`), because the version decides the layout; an unknown type, a priority of 0 (a master resigning), a count of 0 and the reserved bits are carried verbatim. A count, or VRRPv2's authentication data, past the buffer raises `TruncatedHeaderError` (`field="count_ip_addrs"` or `"auth_data"`). Construction also checks `count_ip_addrs == len(addresses)`, the authentication data's length against the version (8 bytes or none), and that `type` fits its nibble. The walk ends at VRRP. Registering over protocol 112 in `ip.proto` reaches IPv4 only, as for AH's 51; `_defaults.FAMILY_SPECIFIC_NUMBERS` now names both.
- **VRRP checksums in `compute`/`verify`/`Packet.with_checksums()`.** The internet checksum of the whole message with the checksum field zeroed: alone for VRRPv2 (RFC 3768 §5.3.8, `ip` not needed), behind the IP pseudo-header with protocol 112 for VRRPv3 over IPv4 and IPv6 (`ip` required). `payload` is ignored, as for IGMP. Over IPv6 that is RFC 5798 §5.2.8's rule; over IPv4, §5.2.8 cites only RFC 2460's pseudo-header, which is IPv6's, and the IPv4 one is what keepalived 2.2.8 sends by default. RFC 9568 §5.2.8, which obsoletes RFC 5798, leaves the pseudo-header out over IPv4, as keepalived's `v3_checksum_as_v2` option does, and `verify()` returns `False` for such an advert.
- **`RIP`: the Routing Information Protocol, versions 1 and 2 (RFC 1058, RFC 2453, #182).** UDP port 520 dispatches, best-effort like every port entry, to the new `netprotocols.RIP` (also `netprotocols.layer7.RIP`), which decodes the 4-byte header into `command`, `version` and `reserved` (bytes 2-3: must be zero in RFC 1058 and RFC 2453, RFC 1388's Routing Domain) and keeps everything after it as raw `body`, so `bytes(RIP.decode(x)) == x`. `entries` parses the 20-byte entries on demand: a route is a `RIPEntry` (`afi`, `route_tag`, `address`, `subnet_mask`, `next_hop`, `metric`; RIPv1 zeroes the v2-only fields, which are kept verbatim either way), and an entry with AFI 0xFFFF is a `RIPAuthentication` (`auth_type`, the raw 16 `data` bytes, and `password` for type 2, or `packet_length`, `key_id`, `auth_data_len` and `sequence_number` for RFC 4822's type 3), never a route; `routes` and `authentication` select them. RIP has no length field and the walk does not trim to UDP's (#235), so the entries end at the RFC 4822 authentication trailer, which the first entry's Packet Length locates when the bytes there start with the trailer's `0xFFFF 0x0001` (`authentication_trailer`, raw, to the end of the body: Auth Data Len does not size it, since BIRD declares 20 for a 16-byte MD5 digest and 32 for a 32-byte HMAC-SHA-256 one), or at the last whole entry, with anything shorter than an entry after it — an entry cut by a snap length, or an Ethernet FCS — in `remainder`; past the header neither decode nor any accessor raises. Against a wrong port guess, `decode()` rejects a version other than 1 or 2 and command 0 (`InvalidFieldError`), which 99.2% of random datagrams fail; construction accepts them. The other commands, TraceOn to Update Acknowledge (`command_name`, with IANA's names), and RIPv1 messages with nonzero must-be-zero fields decode. RIPng (RFC 2080, UDP 521, the IPv6 protocol) is not decoded; RIP itself has no IPv6 form.
- **`OSPF`: OSPFv2 (RFC 2328), IP protocol 89 (#183).** IPv4 protocol 89 (`IPProtocol.OSPF`, "OSPF") now dispatches to `netprotocols.OSPF` (also `netprotocols.layer3.OSPF`), which decodes the 24-byte common header — `version`, `type`, `packet_length`, `router_id`, `area_id`, `checksum`, `instance_id` and `au_type` (one byte each: RFC 6549 §2 split RFC 2328's 16-bit AuType into an Instance ID and an 8-bit AuType), the raw 8-byte `authentication` — and keeps the message as raw `body`, so `bytes(OSPF.decode(x)) == x[:header_len]` by construction. One accessor per message type parses the body on demand and returns `None` for the other types: `hello` (`OSPFHello`: network mask, hello and dead intervals, options, priority, DR, BDR and the neighbor list), `database_description` (`OSPFDatabaseDescription`: interface MTU, options, the I/M/MS flags, DD sequence number and its `OSPFLSAHeader`s), `ls_requests` (`OSPFLSRequest`s), `lsas` (a Link State Update's `OSPFLSA`s, each a decoded 20-byte `OSPFLSAHeader` and a raw `body`) and `ls_acknowledgments` (`OSPFLSAHeader`s). **LSA bodies are not decoded**: the Router, Network, Summary and AS-external (and other) LSA contents stay raw `bytes`, as follow-up work. `decode()` and the constructor check each known message's framing (whole neighbors, LSA headers and requests; an update's LSA count and lengths walking its body exactly), raising `InvalidFieldError` with `field="body"` otherwise, so no accessor raises; a type outside 1-5 keeps its body as is. Packet Length bounds the packet: below 24 raises `InvalidFieldError`, past the buffer `TruncatedHeaderError`. Under cryptographic authentication (AuType 2) the digest after the packet, Auth Data Len bytes, is kept in `auth_trailer` and counted in `header_len`, with `key_id`, `auth_data_len` and `crypto_sequence_number` accessors; AuType 3 (RFC 7474, extended sequence numbers) is framed the same way, its trailer the 64-bit sequence number and the digest, which Auth Data Len counts together, and the same accessors read its 32-bit Key ID and 64-bit sequence number; nothing else after the packet is consumed, so an RFC 5613 LLS block, Ethernet padding or an FCS is left after the OSPF layer. Records have `__bytes__`, so a packet can be built from them, and display helpers (`type_name`, `au_type_name`, `options_str`, `flags_str`, `ls_type_name`, hex strings). Only version 2 decodes: OSPFv3 (RFC 5340), which IPv6 carries under the same number, is not implemented, so `ip.proto.v6` withholds protocol 89 (`_defaults.IPV4_ONLY_NUMBERS`) and an IPv6 packet with next header 89 still ends its walk at the IPv6 header; `OSPF.decode()` rejects version 3 with `InvalidFieldError` (`field="version"`) for a caller who sends it there anyway. The registry gains the private mechanism for that: a withheld key owns no class, inheritance skips it as it skips an override, `derive()` copies it, and a registration made directly in the child table fills it.
- **OSPF checksums in `netprotocols.checksum` (the new functions are also exported from `netprotocols`).** `compute(ospf)` is the internet checksum of the packet with its checksum field zeroed and its Authentication field left out (RFC 2328 §D.4.1), no pseudo-header (`ip` and `payload` are ignored); under cryptographic authentication (AuType 2 or 3), which computes none (§D.4.3; RFC 7474 §5 keeps that for AuType 3), `compute()` raises `InvalidFieldError`, `verify()` returns `True` (the digest, which this library cannot check without the key, protects the packet) and `Packet.with_checksums()` leaves the field alone. New `fletcher_checksum(data, offset)` computes the ISO 8473 Fletcher checksum field (RFC 905 Annex B), raising `ValueError` unless the 2-byte field at `offset` lies inside `data`. `lsa_checksum(lsa)` generates an `OSPFLSA`'s LS Checksum, over the LSA but its LS Age (RFC 2328 §12.1.7), and `verify_lsa(lsa)` checks it as RFC 905 B.4 does, by both running sums being zero, so a field stored with `0x00` where the generator writes `0xff` (equal modulo 255) verifies too, plus RFC 2328 §12.1.7's rule that the LS Checksum cannot be zero: a field of `0x0000` fails even where those sums are zero.

### Development

- **A real OSPFv2 capture joins the corpus: `ospf.pcap`, 54 frames (233 across 25 scenarios).** `scripts/capture_fixtures_ospf.sh` runs FRR 8.4's `zebra` and `ospfd` in two netns over a veth pair and captures three adjacencies in turn, one per AuType (none, simple password, keyed MD5), each with every message type: Hellos, the Database Description exchange, Link State Requests, Link State Updates carrying router, network and AS-external LSAs, and Link State Acknowledgments. The script fails unless each adjacency holds exactly 6 Hellos, 5 Database Descriptions, 2 requests, 2 acknowledgments and six LSAs (two router LSAs from each router, A's network and AS-external LSAs) in 3 or 4 updates, and no frame carries data after its packet (FRR sent no LLS). The test password and MD5 key are published in `tests/fixtures/MANIFEST.md`. `scripts/check_fixtures.py` verifies, with its own implementations, every AuType 0/1 packet checksum, the AuType 1 password, every AuType 2 keyed-MD5 digest (and that its packet checksum is zero) and every LSA's Fletcher checksum, in RFC 905 B.4's verification form plus RFC 2328 §12.1.7's rule that it is never zero; it reads AuType from header byte 15, past RFC 6549's Instance ID. `tests/test_ospf.py` loads the checker and holds it to failing a flipped body byte, LSA byte, password byte, digest byte, key ID and checksum, two swapped LSA bytes (which move only one Fletcher sum), a change that moves only the other, and an LS Checksum of `0x0000` whose sums are zero, and to passing a valid frame with a nonzero Instance ID. The kernel had no IPv6, so OSPFv3 over IPv6 is covered by a constructed frame, as are LLS blocks, padding and FCS trailers. `OSPF` joins the fuzz suite (`ALL_PROTOCOLS`, a round-trip strategy built from the message records, and an accessor-safety property that also feeds OSPF-shaped buffers), the truncation and lying-length contract tests, the corpus checksum cases and the corpus coverage set. The registry tests now hold `ip.proto` and `ip.proto.v6` to differing at the IPv6-only numbers, at 51, and at 89, which only `ip.proto` holds.
- **A real RIP capture joins the corpus: `rip.pcap`, 21 frames (179 across 24 scenarios).** `scripts/capture_fixtures_rip.sh` runs two BIRD 2.14 routers in two netns over a veth pair through five scenarios — RIPv1 broadcast, RIPv2 multicast, a plain-text password, keyed MD5 and HMAC-SHA-256 — and keeps a fixed, asserted selection of each: every router's first Request and first Response, and one whole-table periodic update with poisoned-reverse routes. `scripts/check_fixtures.py` now verifies each RFC 4822 digest with the published test keys (`rip-keyed-md5`, `rip-hmac-sha256`), fails on a Key ID with no published key (`rip-unknown-sa`) or a missing trailer header (`rip-trailer`), and counts RIP datagrams (`rip`); its VXLAN peeling moves into `_check_vxlan`. `RIP` joins the fuzz suite (`ALL_PROTOCOLS`, a round-trip strategy, and a property that decode and every accessor are total and that entries, trailer and remainder tile the body), the contract tests (truncation, a trailer and a cut entry under strict and lax walks) and the corpus coverage set.
- **A real VRRP capture joins the corpus: `vrrp.pcap`, 18 frames (158 across 23 scenarios).** `scripts/capture_fixtures_vrrp.sh` runs keepalived 2.2.8 as two routers in two netns over a veth pair through four virtual routers: VRRPv2 with `auth_type PASS` and two addresses, failing over from A to B with a priority-0 advert from each; VRRPv2 without authentication; VRRPv3 with one address, failing over the same way; and VRRPv3 unicast with three addresses and a 0.5 s interval. A master advertises for as long as it runs, so the script drives each step by watching the capture, keeps each router's first two live adverts and its resignation per segment, and fails unless the kept frames are exactly those 18. keepalived builds each IPv4 header (`IP_HDRINCL`) and every VRRP byte; the kernel fills the IPv4 header checksum. `scripts/check_fixtures.py` verifies every VRRP checksum independently (no pseudo-header for VRRPv2, the IPv4 or IPv6 one for VRRPv3), and fails a message whose length disagrees with its version and count or the IP payload, a version other than 2 or 3, and VRRPv2 over IPv6. veth does not pad, so Ethernet padding, a nonzero trailer and VRRPv3 over IPv6 (the capture host has no IPv6) are covered by constructed frames in `tests/test_vrrp.py`, whose checksums it computes itself and also runs through `check_fixtures.py`, as it does tampered copies of the capture. `VRRP` and `VRRPv6` join the fuzz suite (`ALL_PROTOCOLS`, round-trip strategies, an accessor property, a padding and trailer property), the truncation contract test, the corpus coverage set and `tests/test_checksum.py`; `checksum.compute()`'s UDP arm moves into a helper, as GRE's and SCTP's did, to keep its complexity where it was.

## [2.4.0] - 2026-10-25

### Added

- **IP-in-IP decodes through (#177).** IP protocol 4 (IPv4 in IPv4, RFC 2003; IPv4 in IPv6, RFC 2473) and 41 (6in4, RFC 4213; IPv6 in IPv6, RFC 2473) now dispatch from the outer IP header straight to the inner `IPv4` or `IPv6`, from either outer family, so `decode_frame` walks a tunneled packet to its inner transport instead of stopping at the outer header. The encapsulation has no header of its own, so there is no new class, only two `ip.proto` rows and two `IPProtocol` members, `IPIP` and `IPV6` ("IPv4 encapsulation", "IPv6 encapsulation"). A hostile run of nested protocol-4 headers is stopped by `max_depth`, like any other long chain.
- **`ESP`: IPsec Encapsulating Security Payload headers (RFC 4303) (#178).** IP protocol 50 now dispatches from IPv4 and IPv6 to `netprotocols.ESP`, which decodes the cleartext 8-byte prefix, `spi` and `sequence_number` (with `spi_hex_str` for display), and keeps everything after it — payload, IV, padding, Pad Length, Next Header and ICV — as one opaque `ciphertext: bytes`, so `bytes(ESP.decode(x)) == x`; like an ICMP `body`, it runs to the end of the frame, so on a datagram shorter than Ethernet's minimum it ends with the link-layer padding, not the ICV. There is no cryptography: without the Security Association's keys and algorithms nothing in the packet says where the ciphertext ends and the trailer begins, so `ESP.next_protocol()` returns `None` and a frame walk ends at ESP by design. `IPProtocol` gains `ESP` ("ESP").
- **`AH` and `AHv6`: the IPsec Authentication Header (RFC 4302) (#179).** IP protocol 51 now dispatches to `netprotocols.AH` from IPv4 and to its subclass `AHv6` from IPv6 and its extension headers. Both decode the fixed fields — `next_header`, `payload_len`, `reserved`, `spi`, `sequence_number` — and keep the ICV raw in `icv`, sized by Payload Len (`(payload_len + 2) * 4 - 12` bytes, any alignment padding included) and never verified. `next_protocol()` chains onward through `next_header`, so an AH-wrapped TCP segment keeps decoding into `TCP`; the pair exists because the onward table must be the outer family's: `AH` reads `ip.proto`, so IPv4 → AH → 0 cannot conjure a Hop-by-Hop layer, and `AHv6` reads `ip.proto.v6`, so IPv6 → AH → Destination Options (RFC 8200 §4.1) keeps decoding. `isinstance(layer, AH)`, `packet[AH]` and `case AH(...)` match either. A Payload Len below 1 raises `InvalidFieldError`, one past the buffer `TruncatedHeaderError`, and `AHv6` also rejects a header that is not a multiple of 8 octets (an odd Payload Len), all with `field="payload_len"`. `IPProtocol` gains `AH` ("AH"). Registering over protocol 51 in `ip.proto` now reaches IPv4 only: `AHv6` is `ip.proto.v6`'s own entry, which inheritance does not overwrite; `_defaults.FAMILY_SPECIFIC_NUMBERS` names it.
- **`VXLAN`: VXLAN tunnels decode through to the inner frame (RFC 7348, #180).** UDP port 4789 dispatches to the new `netprotocols.VXLAN` (also `netprotocols.layer7.VXLAN`), which decodes the 8-byte header into `flags`, `reserved1`, `vni` and `reserved2`, in wire order, with `bytes(VXLAN.decode(x)) == x`. `next_protocol()` always returns `Ethernet`: the payload is a whole Ethernet frame, so `decode_frame` walks on into the inner frame's VLAN tags, ARP, IPv4 or IPv6 through the existing `ethertype` table, and a `registry` or `decode_as` passed to the walk applies inside the tunnel too. The walker needed no change. RFC 7348 §5 requires the I flag (`VXLAN.I_FLAG`, `0x08`), and decoding a header without it raises `InvalidFieldError` (`field="flags"`, `offset=0`); that check is also what diagnoses about half of the non-VXLAN datagrams that happen to use port 4789, instead of decoding them as a tunnel around a garbage inner frame. Construction accepts a clear I flag, so such a header can be built to test how another stack drops it, and `bytes()` of it is the header with the I flag clear; `decode()` rejects it (ARCHITECTURE.md's round-trip guarantee now says it covers canonical headers, the ones decode produces given its context). The cost is on decode: a capture whose I flag is clear raises at the VXLAN header's `frame_offset` (a `lax=True` walk keeps only Ethernet, IP and UDP), and its inner frame, 8 bytes on, decodes with a second `decode_frame(..., start=Ethernet)` walk. The reserved bits are kept verbatim and never rejected, since the RFC says to ignore them on receipt and extensions such as Group Based Policy reuse them. Lookup tries the destination port first, so a datagram to 4789 dispatches to VXLAN whatever source port the sender's flow hash picked, even a registered one (and so does a DNS reply to a client whose ephemeral port is 4789, which dispatches to VXLAN, never to DNS). Only 4789 is registered: a capture from a Linux device created without a `dstport`, which then uses Linux's pre-IANA 8472, needs `decode_as={"udp.port": {8472: VXLAN}}`. A frame that nests VXLAN in itself is stopped by `max_depth`, four layers per level.
- **SCTP (#176): `netprotocols.SCTP`, layer 4, RFC 9260.** IP protocol 132 (`IPProtocol.SCTP`, "SCTP") now dispatches from IPv4 and IPv6, extension headers included, to `SCTP`, which decodes the 12-byte common header (`src_port`, `dst_port`, `verification_tag`, `checksum`) and keeps the chunks as raw `chunks` bytes, padding included, so `bytes(SCTP.decode(x)) == x[:header_len]` holds by construction. `parsed_chunks` splits them on demand into a flat tuple of `SCTPChunk(type, flags, value)`, which names the RFC 9260 chunk types (DATA, INIT, INIT ACK, SACK, HEARTBEAT, HEARTBEAT ACK, ABORT, SHUTDOWN, SHUTDOWN ACK, ERROR, COOKIE ECHO, COOKIE ACK, ECNE, CWR, SHUTDOWN COMPLETE) and the common extensions (AUTH, I-DATA, ASCONF, ASCONF-ACK, RE-CONFIG, PAD, FORWARD-TSN, I-FORWARD-TSN) via `type_name`, falling back to `"unknown (n)"`; `flags_str` names the DATA/I-DATA I/U/B/E bits and the ABORT/SHUTDOWN COMPLETE T bit, and `unrecognized_action` reads the type's two high bits. `bytes(SCTPChunk(...))` emits the padded wire form, so a packet can be built from a list of chunks. SCTP has no length field, the chain walk does not trim to the IP length, and CRC32c, unlike the internet checksum, changes when zero bytes are appended, so `decode` walks the chunk headers to find where the packet ends: a run of zero bytes where the next chunk would start is left undecoded as link-layer padding (a short Ethernet frame's). Past the 12-byte common header `decode` never raises, like `ICMPv4` and `IGMP`: a remainder the walk cannot parse (a chunk cut by a snap length, an IP fragment or an ICMP error's quote; a nonzero trailer such as an Ethernet FCS) is kept verbatim in `chunks`, so the ports, verification tag and checksum survive in strict and lax walks and in `ICMPv4.embedded_chain` (when the quote holds the whole 12-byte common header), and `verify()` returns `False` for the cut packet. `parsed_chunks` raises on such a remainder when it does not walk (a trailer that happens to walk parses as a phantom chunk, so `verify()` is the reliable signal): `InvalidFieldError` for a chunk length below 4, `TruncatedHeaderError` for a chunk that runs past the bytes, so a hostile length can neither loop nor over-read. A final chunk whose padding the buffer cuts short is accepted as is. `flow_key()` and `Packet.flow_key()` key SCTP on its ports like TCP and UDP. The chain ends at SCTP; payload-protocol dispatch is not implemented.
- **`netprotocols.crc32c()`, and SCTP checksums in `compute`/`verify`/`Packet.with_checksums()`.** The standard library has no CRC32c (`zlib.crc32` is the IEEE CRC-32), so `checksum.py` gains a table-driven Castagnoli CRC, pinned to RFC 3720 Appendix B.4's vectors. `compute(sctp)` is the CRC32c of the whole packet with the checksum field zeroed and no pseudo-header (`ip` is ignored), returned byte-swapped: the CRC goes on the wire least significant byte first (RFC 9260 Appendix A), and `SCTP.checksum` reads its four bytes big-endian. `with_checksums()` fills SCTP layers like the other transports.

### Fixed

- **`Packet.flow_key()` keys a tunneled flow on the inner IP header.** It used the first IPv4/IPv6 layer in the packet, which in a tunnel is the outer one: the key carried the tunnel endpoints' addresses and the tunnel's protocol number (4, 41, or 47 for GRE, which already reached this) instead of the conversation's. It now uses the IP header nearest before the transport layer, as `Packet.with_checksums()` already did, and returns `None` when no IP header precedes the transport.
- **`flow_key()` takes the protocol number from the transport layer, not the IP header.** `FlowKey.protocol` was read from `IPv4.protocol` / `IPv6.next_header`, which name whatever directly follows the IP header: an IPv6 flow behind a Hop-by-Hop, Routing or Destination Options header was keyed protocol 0, 43 or 60, and an AH-protected one 51, so neither matched the same conversation's unwrapped key. (A Routing header with segments left still keys on the IPv6 destination, which is the next segment rather than the final destination, so a source-routed flow's two directions can still differ.) It is now 6 for `TCP` and 17 for `UDP` wherever the segment sits, as `FlowKey`'s docstring already promised; `Packet.flow_key()` and `flow_key()` share one transport-to-number table in `netprotocols.flow`.

### Development

- **Every comparative number the README quotes was re-measured for this release** (Rule 4 of `docs/CLAIMS.md`), on the same machine class as 2.3.0's figures but on the 140-frame corpus Tier 1 grew from 97, against `dpkt 1.9.8` and `scapy 2.8.0`: decode is at parity with dpkt (from 5.3% slower to 3.0% faster over three runs; the README keeps "within 15%") and 4.1× ahead of scapy, encode 4.18× ahead of dpkt, import 55.0 ms against `scapy.all`'s 428.0 ms, and the wheel is 124.4 KiB, 21.7× smaller than scapy 2.8.0's 2.63 MiB. Decode depth against dpkt is 39 of 140 frames deeper, the 12 new ones being the VXLAN frames and one SCTP frame. `docs/CLAIMS.md` records each run and what moved, and corrects the 2.3.0 figures' scapy version: `uv.lock` already pinned 2.8.0 when they were taken, so they most likely name 2.7.0 in error.
- **The nightly mutation gate no longer reports a new function's mutants as untested.** `mutation.yml` restores `mutants/` from the previous night, and that directory holds `mutmut-stats.json`, mutmut's map from each function to the tests that call it. mutmut 3.8 re-traces only tests it has never seen, so a function added since then and called only by existing tests (here `checksum.py`'s `_gre_checksum` and `_sctp_checksum`) mapped to no tests, and all 49 of their mutants failed the gate as "no tests". The workflow now deletes the map before each run, so mutmut traces its configured test selection in full; a local reproduction went from 49 "no tests" to 49 killed. `tests/test_workflows.py` pins the step.
- **A real SCTP association joins the corpus: `sctp.pcap`, 16 frames (140 across 22 scenarios).** The capture host's kernel has no SCTP, so `scripts/capture_fixtures_sctp.sh` runs usrsctp's example client and echo server (`libusrsctp-examples`) in two netns over a veth pair, on raw IPv4: INIT through SHUTDOWN COMPLETE, with DATA, SACK and a HEARTBEAT exchange from each end, then one script-built packet with an unknown chunk type (63); the script fails unless the client completes the association and the capture holds those 16 frames, one chunk each. usrsctp builds those packets' IPv4 headers (`IP_HDRINCL`, the kernel filling length and checksum); the kernel builds the script-built packet's. `scripts/check_fixtures.py` verifies every SCTP CRC32c with its own bit-at-a-time implementation, and `tests/test_sctp.py` covers truncation, lying lengths, link-layer padding, nonzero chunk padding and IPv6 carriage with constructed packets. SCTP joins the fuzz suite (`ALL_PROTOCOLS`, a round-trip strategy, a chunk-accessor property), the truncation contract test, the corpus checksum cases and the corpus coverage set. `registry.py`'s two `register("ip.proto", 132, SCTP)` examples, and the registry tests that registered stand-ins at 132, now use 253 (reserved for experimentation, RFC 3692), since 132 is built in and a different class there raises `RegistryConflictError`.
- **An IPsec AH capture joins the corpus: `ah.pcap`, 6 frames (124 across 21 scenarios).** `scripts/ipsec_fixture_packets.py` now also builds AH with HMAC-SHA-256-128 — transport mode over a TCP SYN, an ICMPv4 echo and UDP, tunnel mode over inner IPv4, and an AH-over-ESP bundle — computing each ICV over the IPv4 header's immutable fields, the AH header and the payload (RFC 4302 §3.3.3). Because the ICV covers the outer header, the script builds that header itself and `scripts/capture_fixtures_ipsec.sh` sends whole datagrams with `IP_HDRINCL`; the post-capture comparison found them byte-identical on the wire. The new keys are published in `tests/fixtures/MANIFEST.md`, and `scripts/check_fixtures.py` verifies every AH ICV with them before the checksums, inner packet or ESP packet behind it, which it then requires to be readable, as it does ESP's; an AH frame on an unpublished SPI fails, as does one whose ICV the checker cannot compute (IPv4 header options, or an IPv6 outer header). `esp.pcap` is unchanged. IPv6-outer AH, with its 4 bytes of ICV padding, is covered by constructed frames in `tests/test_ah.py`, and `with_checksums()` is tested to recompute a transport checksum through AH from either family. `AH` and `AHv6` join the fuzz, round-trip, contract and corpus-coverage suites, and the registry tests now hold `ip.proto` and `ip.proto.v6` to differing only at the IPv6-only numbers and at 51.
- **An IPsec ESP capture joins the corpus: `esp.pcap`, 6 frames (118 across 20 scenarios).** The capture host's kernel has no xfrm ESP transform, so the new stdlib-only `scripts/ipsec_fixture_packets.py` builds genuine ESP — NULL encryption (RFC 2410), HMAC-SHA-256-128 integrity (RFC 4868), RFC 4303 padding and trailer — in transport mode (ICMPv4, UDP) and tunnel mode (inner IPv4), and `scripts/capture_fixtures_ipsec.sh` sends it through a raw protocol-50 socket over a veth pair, so the kernel builds the outer IPv4 header; the script then checks that every byte it built arrived unchanged. The test keys are published in `tests/fixtures/MANIFEST.md`, and `scripts/check_fixtures.py` verifies every ESP ICV with them, then the padding and the inner packet's checksums. An ESP frame on an SPI with no published key fails the checker rather than being skipped, as does anything an ICV vouched for that it cannot read, at any depth below the ESP header (an unknown protocol or EtherType, a header too short to check, a fragment); and tunnel nesting past its depth bound (8 encapsulations) now fails instead of passing unchecked, whatever the chain ends in, for GRE and IP-in-IP as well as ESP; an IPv4 header with an invalid IHL now fails as `ipv4-ihl` on every path, where it was checked on (or crashed the checker). IPv6-outer ESP is covered by constructed frames in `tests/test_esp.py`, since the capture host has no IPv6. `ESP` joins the fuzz, round-trip, contract and corpus-coverage suites.
- **A real VXLAN capture joins the corpus: `vxlan.pcap`, 11 frames (112 across 19 scenarios).** `scripts/capture_fixtures_vxlan.sh` builds a kernel VXLAN tunnel on port 4789 between two netns over a veth underlay and captures ARP, ICMP echoes and one UDP datagram across two segments: VNI 1193046 (`0x123456`) with `udpcsum`, so the outer UDP checksum is real, and VNI 100 with `noudpcsum`, so the outer checksum is zero. `scripts/check_fixtures.py` peels VXLAN on destination port 4789 and verifies the inner frame's checksums. `tests/test_checksum.py` now checks every transport in a frame against its nearest enclosing IP header, not just the first, so a VXLAN frame yields both its outer UDP and its inner transport, and holds zero UDP-over-IPv4 checksums apart as "not used" (they must `verify()`; there is nothing to recompute). The corpus's deepest chain is now 7 layers, and `walk.py`, `docs/CLAIMS.md` and ARCHITECTURE.md say so. ARCHITECTURE.md no longer lists VXLAN among protocols this library does not implement.
- **A real IP-in-IP capture joins the corpus: `ipip.pcap`, 4 frames (101 across 18 scenarios).** `scripts/capture_fixtures_ipip.sh` sends ICMP echoes through raw IP sockets opened for protocols 4 and 41 over a veth pair, so the kernel builds the outer header as a tunnel endpoint would; this works where the `ipip`/`sit` drivers are not built. The capture host had no IPv6, so the corpus holds IPv4 in IPv4 and IPv6 in IPv4; the script also captures the two IPv6-outer combinations on a kernel with IPv6, and `tests/test_ipip.py` covers them with constructed frames. `scripts/check_fixtures.py` peels IP-in-IP and verifies the inner checksums. `tests/test_checksum.py` now pairs each transport with its nearest enclosing IP header rather than the first. The coverage figure in `docs/CLAIMS.md` §5.3 and `pyproject.toml` is re-measured (2,682 statements, 1 missed).
- **README's Roadmap section now leads with the current roadmap, #170**, instead of describing the completed #107 as if nothing had replaced it and promising that "new planned work will open fresh issues" — #170 had been open since 2026-09-09. It names #170's five tier themes without restating its tiers or target versions, which moved up one minor version when 2.3.0 shipped the HTTP codec outside them; `tests/test_docs.py` now checks the section leads with #170 and links none of the tier epics.
- **Fixed a concurrency-group deadlock that cancelled the 2.3.0 release run before any job could start.** `ci.yml`'s concurrency group was keyed on `${{ github.workflow }}`, which inside a `workflow_call` resolves to the *caller's* name ("Release"), not "CI" — so release.yml calling ci.yml on a tag push made both the top-level run and the nested `ci` job claim the identical group `Release-refs/tags/<tag>`, and GitHub cancelled the run as a self-deadlock. The group now uses a literal `ci` prefix instead. `tests/test_workflows.py` gains a guard: no workflow declaring `workflow_call` may key its own concurrency group on `github.workflow`.

## [2.3.0] - 2026-10-23

### Added

- **`HTTP`: an HTTP/1.1 codec (RFC 9112, RFC 9110).** `HTTP.decode(data, *, request_method=None, closed=False)` decodes one complete message from an already-reassembled buffer and leaves any pipelined bytes after it alone (`header_len` is where it ends). The instance holds `head` and `raw_body` verbatim, so `bytes(msg) == head + raw_body` whatever odd bytes the sender used, and constructing one runs the same parse, also requiring `head` to be exactly one head and `raw_body` exactly the body its framing delimits. Accessors cover the start line (`method`, `target`, `http_version`, `status_code`, `reason_phrase`), `fields`, `header()`/`header_values()` (ASCII case-insensitive, invalid names never match), `framing` (`HTTPFraming`), `connection_disposition` (`HTTPDisposition`: `CONTINUE`/`CLOSE`/`TUNNEL`), `content` (chunked framing removed), `trailers` and `anomalies`; none of them raises. Everything the grammar resolved rather than rejected is an `HTTPAnomaly` with its kind, field, first offset and count. `request_method` is the decode context a response needs (HEAD, and CONNECT answered with a 2xx, change its framing) and is stored only when it does; `closed=True` says the buffer ends at connection close, which a close-delimited response needs. HTTP is not port-dispatched, and TCP reassembly remains the caller's. New `HTTPAnomalyKind` members check a request's Host (RFC 9112 §3.2): `HOST_MISSING` (HTTP/1.1), `HOST_DUPLICATE`, `HOST_INVALID` (not RFC 3986 `uri-host [":" port]`), `HOST_AMBIGUOUS` (a comma or percent-encoding) and `HOST_TARGET_MISMATCH` (differs from an absolute-form target's authority, compared case-insensitively without percent-decoding or default ports). An HTTP error's `offset` is relative to the start of the message, also when constructing; `utils/exceptions.py` documents that exception to the attribute-relative rule.

### Development

- **Real HTTP/1.1 captures, `tests/fixtures/http/`.** `scripts/capture_fixtures_http.sh` runs Python's `http.server` (`protocol_version = "HTTP/1.1"`) on one end of a veth pair and drives it from the other: curl for six connections (GET, HEAD, a conditional GET answered 304, POST, a chunked response with a trailer, a 404) and a raw socket for one pipelined connection, since curl no longer pipelines HTTP/1.1. The new stdlib-only `scripts/extract_http_streams.py` writes each connection's request and response byte streams beside the 98-frame capture, outside the corpus's non-recursive `*.pcap` glob, so the corpus counts are unchanged. `tests/test_http.py` reassembles the streams again through `decode_frame`, so the extractor and the codec must agree on the wire bytes, then decodes every message (no anomalies; HEAD and 304 framed `NONE`, the chunked trailer read, the pipelined stream split by the README's loop). The streams seed `tests/fuzz/fuzz_http_decode.py`: two minutes now reach `cov: 388 ft: 1441` from `262/892` unseeded. A new strategy generates HEAD and CONNECT-2xx responses for the context round-trip property, which `http_messages()` never covered.
- **HTTP documentation.** README: a coverage row and a *Decoding HTTP* section (the pipelining loop, `request_method`/`closed`, anomalies), with every example run against the captures by `tests/test_docs.py`. ARCHITECTURE.md: text framing in the decode contract, HTTP's offset convention, its property-based `__match_args__`, why it is absent from the `tcp.port` table (`decode_as` decodes 8 of the capture's 98 frames), the layout map and the cookbook. SECURITY.md: what is in scope for `HTTP` and what it cannot see by design. `docs/CLAIMS.md` §5.2–5.3 and the `pyproject.toml` coverage comment are re-measured (19 protocols; 2,676 statements, 1 missed).
- **`HTTP` joins the fuzzing and property suites.** `ALL_PROTOCOLS`, a round-trip strategy (context-free messages), a mutated-message strategy feeding two new properties (accessors never raise; arbitrary `head`/`raw_body`/`request_method` either fail to construct or round-trip exactly), a decode-path test that construction's re-parse never runs inside `decode()`, the offset convention in `tests/test_diagnostics.py`, and a new Atheris harness, `tests/fuzz/fuzz_http_decode.py`, run by `fuzz.yml`'s `atheris` job with its imports instrumented. `tests/test_http.py` decodes the chunked response `tcp_http.pcap` carries across two TCP segments.
- **HTTP/1.1 message grammar (`netprotocols.layer7.http`).** The byte-level parsers the coming HTTP codec builds on: head scan, request/status line, field lines, RFC 9110 list parsing, Transfer-Encoding, Content-Length, RFC 9112 §6.3 framing, chunked bodies with trailers, and connection disposition. Ambiguities real implementations disagree on — CL+TE, bare LF, obs-fold, whitespace before the colon, chunk-extension and chunk-line oddities — decode by the RFC's resolution and are reported as located, aggregated anomalies instead of raising; only an unrepresentable message raises. The module joins the nightly mutation audit (`'netprotocols.layer7.http.x__*'`). It passes that audit with no survivors: equivalent mutants were designed out (literals hoisted to module level, dead initial values removed, the CONNECT 2xx range checked once, the chunk-extension walker replaced by a module-level regex), every raise site is pinned to its exact message and structured fields, and anomalies are asserted as full records. Trailing whitespace after a chunk extension (`5;a `) is flagged `CHUNK_EXTENSION_INVALID`, as RFC 9112 §7.1.1 allows none.
- **The nightly mutation run can now fail on a surviving mutant.** `mutmut run` (3.8.0) exits 0 however many mutants survive, so `mutation.yml` was green whatever it found. A new final step, `scripts/check_mutmut_survivors.py`, fails the job on any undetected mutant not accepted in the new triage record `scripts/mutmut_survivors.txt`, on a stale entry there, and on a scoped file with no checked mutant at all; unknown mutmut statuses fail closed. The two accepted survivors and their reasoning moved into that record from a `pyproject.toml` comment.
- **Closed a mutation-testing gap the gate exposed.** A third survivor — `_tlv.walk_kind_length_value` discarding a caller's `min_option_length` when the length byte counts its own header — was neither triaged nor killed, because no call site passes a floor above the structural 2. Two direct tests in `tests/test_tlv.py` now pin it.
- **Mutation runs can no longer report false survivors from warm caches.** mutmut 3 runs the clean suite in-process and then forks once per mutant, so a `functools` cache warmed by the original code (DNS's section parsers) could answer in the child and hide a mutant. `tests/conftest.py` now clears every package-level cache before each test, discovering them rather than listing them.
- **Hypothesis profiles load for every test selection.** They were registered only when `tests/test_fuzz.py` was imported, which mutmut's test selection never does, so property tests under mutation ran randomized and under the default deadline. They now live in `tests/conftest.py`.
- **`fuzz.yml` and `mutation.yml` key their concurrency groups on the triggering event**, so the nightly cron can no longer cancel a manually dispatched run. CONTRIBUTING.md gains *Mutation testing* and *Releasing* sections, the latter making those manual runs a release prerequisite.
- **New guards in `tests/test_workflows.py`**: every harness under `tests/fuzz/` must be run by `fuzz.yml`, the survivor gate must follow `mutmut run` and read the full status listing, and both nightly concurrency groups must be event-keyed.
- **`pyproject.toml`'s mutmut comment now says that decorated functions are never mutated**, so the `@lru_cache` DNS section parsers sit outside the audit whatever the filters say.

- **Tightened three DNS corpus assertions in `tests/test_dns.py` from substring/`endswith` checks to exact equality, closing 3 open CodeQL `py/incomplete-url-substring-sanitization` alerts (#166).** `test_names_decompress_to_real_domains` asserted `"example.com" in names` / `"accounts.youtube.com" in names` against a `set` decoded from a fixed pcap corpus, and `test_answers_parse_to_real_records` asserted `cname.rdata_text.endswith("google.com")` against the same corpus — not security-relevant trust checks, but exactly the substring/suffix pattern the rule flags regardless of what the value's actually validating. Both now compare against the known exact decoded values instead (`names == {"example.com", "accounts.youtube.com"}`, `rdata_text == "www3.l.google.com"`), which removes the pattern CodeQL keys on and is strictly more precise than the checks it replaces.
- **Consolidated six open Dependabot updates and grouped `github/codeql-action` so its sub-actions can no longer be bumped apart (#198, #199, #204, #205, #206, #207).** Dependabot tracks `github/codeql-action/init`, `/analyze`, and `/upload-sarif` as three separate dependencies and opened one PR each; `analyze` refuses a config file written by a different `init` release ("Loaded a configuration file for version '4.37.9', but running version '4.38.1'"), so #204 and #206 each failed CodeQL alone and neither could ever merge. All three now move to v4.38.1 together, alongside `astral-sh/setup-uv` 10.0.1 → 10.2.0, `hypothesis` 6.167.1 → 6.168.0, `ruff` 0.16.6 → 0.16.7, and `mutmut` 3.7.0 → 3.8.0 (lockfile byte-identical to Dependabot's). `dependabot.yml` gains a `codeql-action` group for the `github-actions` ecosystem, and `tests/test_workflows.py` gains `TestCodeQLActionVersionLockstep`, which fails the ordinary test job — naming the mismatched steps — whenever `github/codeql-action/*` steps across all workflows are pinned to more than one commit.
- **The Atheris `decode_frame` harness now gets coverage feedback.** `tests/fuzz/fuzz_decode_frame.py` imported `netprotocols` outside `atheris.instrument_imports()`, so libFuzzer saw no edges and the nightly `atheris` job was mutating random bytes blind: a two-minute local run executed 30.4M inputs with the corpus never leaving `corp: 1/1b`. With the imports instrumented, the same two minutes grow it from `cov: 15` to `cov: 98 ft: 284 corp: 59/4925b`, with no crash found.
- **The Atheris `decode_frame` harness now starts from the real-capture fixtures.** Unseeded, two minutes of fuzzing plateaued at 98 edges: strict decoding rejects almost every mutated frame at the first header, so libFuzzer rarely got past Ethernet/IP. The harness now hands every frame in `tests/fixtures/*.pcap` (92 unique of 97) to libFuzzer through `-seed_inputs=`, so the nightly job needs no change and never writes new inputs back among the seeds. Seeds are content-addressed files in a fixed temporary directory, because libFuzzer exits from C and no Python cleanup runs. The harness exits instead of fuzzing if it finds no frame, so a moved fixture directory can't silently put it back to fuzzing from nothing. The seeds alone start at `cov: 115`; the same two minutes now reach `cov: 146 ft: 511 corp: 122/12556b`, with no crash found.
- **Every comparative number the README quotes was re-measured for this release** (Rule 4 of `docs/CLAIMS.md`), on a different machine from the 2.2.x figures (CPython 3.12.3, x86-64 Linux): decode is ~6% behind dpkt and 4.6× ahead of scapy, encode 4.53× ahead of dpkt, import 56.8 ms against `scapy.all`'s 487.0 ms (the HTTP codec costs about a millisecond of it), and the wheel is 106.1 KiB, 23.9× smaller than scapy's, after `layer7/http.py` added 16 KiB. Decode depth against dpkt is unchanged (27 of 97 frames deeper). `docs/CLAIMS.md` records each run and what moved.

## [2.2.1] - 2026-09-07

### Fixed
- **Closed a decode-throughput regression against dpkt that nobody had
  been watching tier over tier (#147).** Re-measuring every held claim
  after #107/#124 closed showed netprotocols had gone from 1.16× faster
  than dpkt right after Tier 1 to ~11% slower after Tiers 2-4 — a
  reversal none of the five tiers' own re-measurements had caught,
  because none of them profiled, only re-measured before/after.
  `cProfile` against the corpus decode loop found two causes, neither
  of them the tiers first suspected: `bytes_to_ipv6` (added by #99 for
  Pyodide portability, not one of the three tiers originally named)
  formatted its eight address words one f-string at a time through a
  generator, ~18% of total corpus decode time; `decode_frame()`'s
  `Packet` construction paid a redundant `isinstance` check, through
  `Protocol`'s ABC machinery, on a list already guaranteed to hold only
  `Protocol` instances, ~7-8% of `decode_frame()`'s own time. Both
  fixed without changing observable behavior: `bytes_to_ipv6` now
  formats all eight words in one `%`-format call (verified
  byte-identical against glibc's `inet_ntop` via the existing
  hypothesis test, 2.1× faster in isolation); `Packet` gained an
  internal `_from_decoded()` fast-construction path, used only by
  `decode_frame()` — the public `Packet(...)` constructor still
  validates arbitrary arguments exactly as before.
- **`scripts/benchmark.py` now measures `decode_frame()`, the
  documented public chain-walking API, instead of a hand-rolled loop
  that predated it (#147).** The benchmark's `decode_netprotocols()`
  kept its own copy of the pre-#88 walk loop, never updated when
  `decode_frame()` shipped, so every decode-throughput figure this
  project has published — including every number in `docs/CLAIMS.md`
  section 1 before this release — described code the documented API's
  callers never actually ran. `benchmarks/baseline.json`, five tiers
  and this fix stale at a v1.3.0-era figure, was refreshed to match.

See `docs/CLAIMS.md`'s "Re-measured after closing the
dpkt-throughput regression" section for the full profiling writeup,
before/after numbers under both the old and new benchmark
methodology, and updated 1.1/1.2/1.6 figures.

### Development
- **Addressed CodeFactor's static-analysis findings on the tooling
  scripts (#156).** `scripts/pyodide/check_in_pyodide.py` extracted
  the built wheel into a hardcoded, predictable `/tmp/netprotocols-
  wheel` path; it now uses `tempfile.mkdtemp()`, verified against a
  real Pyodide runtime (`node scripts/pyodide/run_in_pyodide.mjs`)
  decoding the full corpus unchanged. `scripts/check_fixtures.py`'s
  `_check_l3` — one 137-line function walking IPv4, IPv6, GRE
  tunneling, VLAN and every upper-layer checksum — is split into one
  small function per protocol; output is byte-identical on the full
  97-frame fixture corpus before and after. `scripts/benchmark.py`'s
  three broad `except Exception: continue` blocks are unchanged but
  now documented: `dpkt` and `scapy` have no shared "malformed frame"
  exception the way this project's own `ProtocolError` does, so a
  bare `except` is the correct interop boundary, not a swallowed bug.
  The flagged duplication between `benchmark.py` and
  `check_in_pyodide.py`'s minimal pcap readers — nearly byte-identical
  `read_pcap`/`corpus_frames` functions — is now shared via a new
  `scripts/_pcap.py`. An initial pass left the duplication in place,
  reasoning both scripts' docstrings required each verification path
  to stand fully independent of the others; re-reading them shows that
  claim is narrower than stated — "standalone" there means not
  depending on netprotocols (the thing each script verifies), the same
  usage `CONTRIBUTING.md` and `check_fixtures.py`'s own docstring use,
  never independence from sibling scripts. `_pcap.py` is itself
  stdlib-only and does not import netprotocols, so it preserves the
  property the docstrings actually document. Verified against a real
  Pyodide runtime after the extraction: the corpus still decodes
  unchanged, and `check_fixtures.py`'s own, materially different
  `read_pcap` (it additionally validates linktype and length) is
  untouched, since it was never part of this duplication.

### Documentation
- **Corrected six README.md claims an independent audit against the
  live repo found stale or overstated, none of them accidental
  regressions — each had simply drifted from what it once described.**
  Wheel size (85.6 KB / ~30× smaller than scapy) was measured against
  the `2.0.0` wheel, two releases behind; rebuilt from `HEAD`, it's
  88.3 KB / ~29× (`docs/CLAIMS.md` §1.5 corrected to match). The typing
  bullet's "107 of [scapy's] files" enable strict mypy checking was a
  raw `wc -l` over scapy's enabled-files list including blank lines
  and comments; filtered the way scapy's own tooling does, it's 89
  (`docs/CLAIMS.md` §2.1 corrected, with the mismeasurement documented
  so it doesn't recur). The Pyodide/browser bullet credited "dpkt and
  pypacker import cleanly" to the real-Pyodide CI job; that job only
  ever imports netprotocols under Pyodide (confirmed by reading
  `scripts/pyodide/check_in_pyodide.py`) — the dpkt/pypacker rows come
  from a separate `sys.meta_path`-blocklist simulation under ordinary
  CPython, not from CI (`docs/CLAIMS.md` §3.1 reworded to say so
  explicitly). The CI-gating bullet's closing clause, "the rest have no
  performance benchmark at all," was contradicted by the very citation
  it points to — `docs/CLAIMS.md` §1.7 documents that scapy and
  PyTCP-net_proto do ship benchmark scripts, just not CI-wired; reworded
  to the claim the table actually supports (none of the ten *gates* on
  a regression). The Contributing section's "`pytest`, `mypy`, and
  `ruff check` — all three are enforced by CI on Python 3.12-3.14"
  overstated the matrix: only `pytest` runs on 3.12-3.14; `mypy` and
  `ruff check` each run on 3.12 only. The Roadmap section's "everything
  through 2.2.0 has landed on `master`" didn't mention that a further,
  unreleased fix (#147) has since landed on top of 2.2.0 — added a
  clause naming it. A seventh finding — the Roadmap's claim that "only
  2.0.0 was an actual PyPI release" — is contradicted by PyPI itself
  (2.2.0, and in fact five earlier minor/patch versions, are also
  published there); left unfixed pending a maintainer decision on
  whether 2.2.0's publication was intentional, since fixing the prose
  first would paper over a real process question.
- **Resolved the seventh finding above: 2.2.0's PyPI publication was
  confirmed intentional.** The Roadmap section's "per the roadmap's own
  release policy, only 2.0.0 was an actual PyPI release" is now
  "the roadmap's original 'only at a major version bump' release policy
  wasn't actually held to: both 2.0.0 and 2.2.0 — a minor release — are
  on PyPI," and the roadmap table's 2.2.0 row gained the same
  **released** marker 2.0.0 already carried. Issue #107, the source
  both docs draw this from, updated its own stated policy line with a
  dated correction rather than silently rewriting history.
- **A fresh independent audit for #101 found four more genuine drifts
  and fixed them, none of them regressions — just the register falling
  behind a codebase and a README that both kept moving.** `docs/CLAIMS.md`
  §5.3's statement count (1,935) had drifted from the live count of
  2,091 as the codebase grew — the coverage percentage held steady only
  because the miss count never moved, masking it; `pyproject.toml`'s own
  inline comment was still quoting an even older 1,441 and is now
  corrected too. §5.7's "79 tests" for `tests/test_walk.py` undercounted
  the live 85: one test parametrized over the corpus's first 40 frames
  now collects its full 40 instances because the corpus has since grown
  past that slice, not because tests were added. §1.6 overstated its own
  claim about README.md, saying the decode-depth figure travels with the
  throughput figure "in the same sentence" there; they're adjacent
  bullets, not one sentence — corrected. README's Pyodide/browser bullet
  said outright that "pypacker was not tested", contradicted by
  `docs/CLAIMS.md` §3.1's own simulation table two paragraphs away, which
  shows pypacker importing cleanly under the identical CPython-side
  check used for dpkt; reworded to say so, and to stop implying the
  scapy-import failure was observed directly inside the real Pyodide CI
  run rather than established by source citation plus that simulation.
  README's CI-gating bullet lumped PyTCP-net_proto in with three
  libraries whose benchmark code targets the library being compared;
  `docs/CLAIMS.md` §1.7's own citation notes PyTCP-net_proto's benchmark
  exercises its RX daemon instead — reworded to keep that distinction
  rather than flattening it.
- **Restored this file's own missing `## [2.2.0]` version header.** A
  prior documentation commit deleted it while inserting an adjacent
  bullet, which silently re-merged the entire tagged, PyPI-published
  2.2.0 release back under `## [Unreleased]` — the section below is
  what a `git show` of the `v2.2.0` tag's own CHANGELOG.md actually
  contained at release time.

## [2.2.0] - 2026-09-04

### Added
- **Typed accessors for every enum-backed field.** `_enums.py` defines
  `EtherType`, `IPProtocol`, `ARPOperation` and `ARPHardwareType`, but
  until now no decoded field exposed them — only the `*_name` display
  strings, and the enums themselves were used only for dispatch. Every
  field with a fixed wire vocabulary now has an `*_enum` companion
  alongside the existing `int` field and its `*_name` string, mirroring
  the `src`/`src_address` precedent 1.3.0 established for IP addresses:
  `Ethernet.ethertype_enum`, `VLAN.ethertype_enum`, `GRE.protocol_enum`,
  `IPv4.protocol_enum`, `IPv6.next_header_enum` (and the three IPv6
  extension headers that share the field: `IPv6HopByHopOptions`,
  `IPv6DestinationOptions`, `IPv6Routing`, `IPv6Fragment`),
  `ARP.oper_enum`, `ARP.ptype_enum`, `ARP.htype_name`/`ARP.htype_enum`
  (new — `ARPHardwareType` was exported but referenced nowhere), and
  `DHCP.htype_name`/`DHCP.htype_enum`. Each returns `None` — never
  raises — for a wire value this library does not enumerate, so
  `bytes(decode(x)) == x` is unaffected for unrecognized values; the
  raw `int` field stays canonical and round-trips regardless (#95).
- **IPv4, TCP and DHCP curate a short `__match_args__` by hand.** Their
  full auto-generated positional form runs to 11-15 fields — unusable
  positionally, since nobody writes, or gets right, a fourteen-slot
  pattern. `IPv4.__match_args__ == ('src', 'dst', 'protocol')`,
  `TCP.__match_args__ == ('src_port', 'dst_port', 'flags')`,
  `DHCP.__match_args__ == ('op', 'chaddr', 'yiaddr')` — the two or
  three fields someone drafting `case IPv4(...)` actually reaches for.
  Every other header (including the still-wide `IPv6`, at 8 fields)
  keeps the plain auto-generated tuple, and keyword patterns
  (`case IPv4(protocol=6)`) are unaffected either way and stay the
  documented default. `__match_args__` is part of the public API once
  documented, so the chosen order is pinned by
  `tests/test_pattern_matching.py` rather than left free to drift.
  ARCHITECTURE.md and `docs/CLAIMS.md` are updated to describe this as
  a deliberate, tested exception rather than the "this library never
  hand-declares `__match_args__`" absolute they stated before (#94).
- **DNS resource records expose typed RDATA, and every question, not
  just the first.** `DNSResourceRecord.rdata_text` decoded A/AAAA/MX/
  SOA/etc. into a display string only; a new `rdata_value` field adds
  the typed decoding alongside it (`rdata_text` is unchanged) —
  `ipaddress.IPv4Address`/`IPv6Address` for A/AAAA, the decompressed
  target `str` for NS/CNAME/PTR, a new `MXRecord(preference, exchange)`
  for MX, a new `SOARecord(mname, rname, serial, refresh, retry,
  expire, minimum)` for SOA, `list[str]` of character-strings for TXT,
  and `None` — never raises — for the types this library does not
  decode. Computed eagerly at parse time, like `rdata_text` always has
  been: a name inside RDATA (a CNAME's target, for instance) can use
  DNS compression against the *whole* message, so decoding it needs
  the same message-wide context `rdata_text` already required, which a
  property computed lazily from `rdata` alone could not resolve.
  Separately, `DNS.questions` adds a `tuple[DNSQuestion, ...]` walking
  every entry of the question section — `question_name`/`question_type`
  /`question_class` exposed only the first and are unchanged (#96).
- **A typed `DHCPOption`, alongside `DHCP.option_map`.** `option_map`
  was the only accessor in the library returning a bare
  `dict[int, bytes]` rather than typed objects; it is unchanged (still
  returns exactly what it always did). A new `parsed_options` property
  wraps the same, already RFC-3396-concatenated, mapping into a
  `tuple[DHCPOption, ...]`, mirroring `TCPOption`/`IPv4Option`: `code`,
  `data`, `code_name`, and a decoded `.value` for the option codes this
  library understands — a single `ipaddress.IPv4Address` for Subnet
  Mask (1)/Requested IP Address (50)/Server Identifier (54), a tuple of
  one or more for Router (3)/Domain Name Server (6) (RFC 2132 permits
  repeating either), the integer seconds for IP Address Lease Time
  (51), the raw byte for Message Type (53). `None` — never raises —
  for codes this library does not decode and malformed option data
  (#96).
- **`IPv4Option.value` decodes Record Route, Timestamp and Router
  Alert.** `IPv4Option` had `kind_name` and no `.value` — the three
  common kinds (RFC 791 §3.1, RFC 2113) were named but their contents
  left raw, unlike `TCPOption`, which already decodes its values.
  Record Route (7) decodes to a `tuple[ipaddress.IPv4Address, ...]` of
  the addresses recorded so far — the option's own pointer byte says
  how many of the address slots are actually filled, not the option's
  total length. Timestamp (68) decodes to `tuple[int, ...]` of plain
  millisecond timestamps when its flag selects that shape, or
  `tuple[tuple[ipaddress.IPv4Address, int], ...]` of (address,
  timestamp) pairs when the flag says each entry carries one — the
  overflow counter and pointer are not decoded, read `data` raw for
  those. Router Alert (148) decodes to the 2-byte value as `int`.
  `None` — never raises — for every other kind and for malformed data
  on one of these three (a bad pointer, an unrecognized Timestamp
  flag, a short buffer) (#96).
- **`IPv6Routing.segments` and `IPv6Option.value` for Router Alert /
  Jumbo Payload.** `IPv6Routing.data` was entirely unparsed — no
  segment-list extraction for any routing type. RH0 (`routing_type`
  ``0``, deprecated by RFC 5095 but still seen — RFC 2460 §4.4) and
  Mobile IPv6 (``2``, RFC 6275 §6.4) both store a 4-byte reserved field
  followed by one IPv6 address per segment; `segments` decodes that
  into a `tuple[ipaddress.IPv6Address, ...]`. RPL Source Routing (``3``,
  RFC 6554) is deliberately **not** decoded: RFC 6554 §3 elides a
  shared prefix from each intermediate address relative to the
  enclosing packet's *destination* address, context this
  one-extension-header accessor does not have — `data` stays available
  raw. `None` for every other routing type and for malformed address
  data. Separately, `IPv6Option.value` (Hop-by-Hop / Destination
  Options TLVs) now decodes Router Alert (5, RFC 2711 §2.1) and Jumbo
  Payload (194, RFC 2675 §2) into typed `int`s, the last of #96's four
  pieces (`IPv6Option` "likewise decode[d] no values"); `None` for
  every other type and malformed data, same contract throughout this
  tier (#96).
- **CI proves the library runs under a real Pyodide (WebAssembly)
  runtime**, not just that the modules `scapy`/`dpkt` need are
  individually blocked. A new `pyodide` job (`.github/workflows/ci.yml`)
  boots actual Pyodide under Node via `scripts/pyodide/run_in_pyodide.mjs`,
  installs the wheel this job just built, and decodes the entire
  real-capture fixture corpus with it — see
  `scripts/pyodide/check_in_pyodide.py`. That surfaced a genuine bug
  along the way: `IPv6.decode()`/`bytes(IPv6(...))` used
  `socket.inet_ntop`/`inet_pton(AF_INET6, ...)`, and Pyodide's CPython
  build has `AF_INET6` sockets disabled, so every IPv6 frame failed to
  decode there. `_base.py`'s `ipv6_to_bytes`/`bytes_to_ipv6` are now a
  pure-Python implementation (`ipaddress` for parsing; a hand-rolled
  RFC 5952 canonicalizer, differentially verified against glibc's
  `inet_ntop` across 500,000+ random addresses plus both of its
  dotted-quad special cases, for formatting — `str(ipaddress.IPv6Address)`
  was tried first and rejected: it disagrees with glibc on IPv4-mapped
  addresses, and disagrees with *itself* between Python 3.11 and 3.12).
  IPv4 addressing is unaffected; behavior for every existing platform
  is unchanged, exception type included (#99).
- **Nightly fuzzing with a moving seed.** `tests/test_fuzz.py`'s
  `"netprotocols"` Hypothesis profile is deterministic on purpose (200
  examples, `derandomize=True`) so a pull request is reproducible — but
  that also means every build since it was written has run the *same*
  200 inputs. A new `"nightly"` profile (10,000 examples, a real random
  seed each run) runs the whole suite on a new schedule,
  `.github/workflows/fuzz.yml` (03:00 UTC daily, plus manual dispatch),
  kept out of `ci.yml` deliberately — `ci.yml` is reused by
  `release.yml` via `workflow_call`, and a `schedule:` trigger there
  would fire the whole PR/release gate on a cron, not just this
  exploratory job. `.hypothesis/`'s example database accumulates
  across nightly runs via `actions/cache` (keyed by run id with a
  prefix restore-key, since a fixed key would restore forever but
  never actually save a new entry) and uploads as a workflow artifact
  on failure, so a counterexample is recoverable without repo write
  access; a failed scheduled run's own red build is the notification
  (GitHub already does this by default), so nothing here files an
  issue on top of it. Reproduce locally:
  `HYPOTHESIS_PROFILE=nightly uv run pytest`. Also adds a targeted
  strategy building well-formed TCP SYN options (MSS, window scale,
  SACK-Permitted, SACK, timestamps) — the real-capture corpus never
  caught a SYN, so unlike NOP/Timestamps these otherwise depend on
  `max_examples` alone stumbling into a well-formed TLV by chance
  (#98).
- **A pcap/pcapng reader that takes bytes, not filenames.** New
  `netprotocols.pcap`: `read_captures(buffer)` auto-detects classic
  pcap vs. pcapng from its magic number and yields `CapturedFrame`
  (`timestamp` in nanoseconds since the Unix epoch, normalized from
  whatever resolution the source recorded, `data` the frame's raw
  bytes); `read_pcap()`/`read_pcapng()` are the same for a caller who
  already knows the format. pcapng support covers exactly the block
  types frames can come from — Section Header, Interface Description
  (read only for its `if_tsresol` option), Enhanced Packet, and Simple
  Packet (which the format gives no timestamp at all, hence `0`);
  every other block type is skipped wholesale. A malformed or
  truncated capture raises the new `MalformedCaptureError`
  (`ProtocolError` family, no `lax` mode — a corrupt *container* is a
  different failure shape than a malformed header inside one already-
  extracted frame). Format detection is eager; producing frames is
  lazy (a generator), so a bad record downstream doesn't invalidate
  what already iterated cleanly, and a huge capture is never forced
  into a list of frames nobody asked for.

  `tests/conftest.py` drops the private classic-pcap reader every test
  file reached for — `pcap_frames()` is now a thin adapter over the
  shipped `read_pcap()`, and `~10` test files were migrated onto it (a
  real migration, not a rename: `tests/test_pcap.py` keeps its own
  independent reference reader, deliberately never importing the
  module it is cross-checking, the same "standalone, so a shared bug
  can't cancel itself out" precedent as `scripts/benchmark.py` and
  `scripts/check_fixtures.py`).

  One design idea was tried and reverted on measurement: slicing each
  frame lazily out of a `memoryview` over the whole buffer, to keep
  large captures zero-copy. Measured across synthetic captures up to
  ~140MB, it was 0.91x-0.98x — never faster, sometimes slower — because
  a real capture is many *small* frames, and a `memoryview` slice's own
  overhead is paid per frame; #88's identical finding for a single
  frame generalizes rather than being contradicted. `docs/CLAIMS.md`
  5.8 is corrected accordingly — it previously forward-referenced this
  issue with an unverified "1.8x" figure (#100).

### Documentation
- **The comparative-claims embargo is lifted (#107, #124).** `docs/CLAIMS.md`
  1.7 gained a per-project table auditing ten comparable Python packet
  libraries' CI configurations (dpkt, scapy, pypacker, construct,
  pcapkit, dnspython, pyshark, nfstream, stackforge, PyTCP-net_proto)
  for an actual performance-regression gate — cited file:line or
  workflow, dated 2026-09-04; none of the ten gate on one, so the
  comparative form of 1.7's claim is now stated with that evidence
  (#124). Every section that previously carried a
  `COMPARATIVE — HELD` banner is re-measured against the current tree
  and published: decode throughput (1.1, 1.2), encoding throughput
  (1.3), import time (1.4), wheel size (1.5), decode depth (1.6), the
  `mypy --strict` comparison (2.1), `match`/`case` exclusivity (2.2),
  the five-property combination (2.3), Pyodide/browser support (3.1),
  and the permissive-licence wedge (4.1). One finding moved against
  this project rather than for it and is reported as such: three tiers
  of added surface since Tier 1 (#87's dispatch rewrite, #88's chain
  walker, #91's structured errors chief among them) reversed decode
  throughput from 1.16× faster than dpkt back to roughly 11% slower —
  still within the 15% band claim 1.2 names, just no longer ahead.
  Two new reproduction scripts back claims that previously had none:
  `scripts/benchmark_encode.py` (1.3) and `scripts/benchmark_import.py`
  (1.4). `README.md` gains a "Why NETProtocols" section drawing the
  now-published claims into the project's front door, in the tone
  `docs/CLAIMS.md` 4.2 sets for writing about competitors.

## [2.0.0] - 2026-09-04

### Development
- **The round-trip property (`bytes(decode(x)) == x`) is now
  Hypothesis-generated for all 18 protocols, not 4.** It previously
  held only for `Ethernet`, `UDP`, `TCP` and `IPv6Fragment`; the other
  14 rested on a single example each. `tests/strategies.py` adds one
  reusable strategy per protocol — reusable because a strategy that
  generates *valid* instances is useful for more than this one
  property — and `tests/test_fuzz.py::TestGeneralizedRoundTrips`
  asserts the property in one method, parametrized over all 14.

  The interdependent-field protocols the issue specifically flagged
  are generated as *consistent* combinations, never independently: IPv4
  draws `ihl` first and sizes `options` to match; the three IPv6
  extension headers draw `hdr_ext_len` first and size their TLV bytes
  to match; GRE draws `flags` first and computes `fields`' length from
  the same `_optional_len()` the decoder itself uses, so the two can
  never silently disagree.

  The 14 single-example assertions already living in each protocol's
  own test file (`test_arp.py::test_round_trip` and so on) are kept as
  regression anchors — a fixed example pinned to a real captured header
  catches a specific regression fast and readably, which a generated
  property does not replace.

  One adjacent gap closed while surveying this: `DHCP` and `GRE` were
  missing from `test_fuzz.py::ALL_PROTOCOLS` entirely, so neither had
  ever been fuzzed with untrusted bytes for basic decode safety (`any
  input either decodes or raises ProtocolError, never anything else`).
  Both are now included.

### Added
- **`match`/`case` dissection is documented.** It already worked on
  every decoded header, with zero code changes needed — a frozen
  dataclass auto-generates `__match_args__`, and every field with a
  fixed wire vocabulary is an `IntEnum`, so a value pattern binds the
  plain `int` the decoder stored. None of that appeared anywhere:

  ```python
  match packet.layers:
      case [_, IPv4(protocol=IPProtocol.TCP) as ip, TCP(flags_str=f), *_] \
              if "SYN" in f and "ACK" not in f:
          print(f"connection attempt from {ip.src}")
  ```

  README gains a first-screen example and a dedicated section;
  ARCHITECTURE.md explains the two mechanisms and the two ways a
  contributor can quietly break them (reordering a class's fields
  changes what a positional pattern binds to; degrading a fixed-
  vocabulary field from `IntEnum` to a bare `int` makes a value
  pattern stop matching without raising). `tests/test_pattern_matching.py`
  pins both mechanisms directly and runs the README's own example over
  the corpus, so a regression in either is caught rather than
  incidental.

- **Structured diagnostics on every `ProtocolError`.** Every exception
  used to carry only a formatted string — the full attribute set on a
  raised `TruncatedHeaderError` was `args`, `add_note`,
  `with_traceback`. A fuzzing harness, conformance suite, or
  protocol-validation tool that wanted to know *where* a parse failed
  had to regex the message. Every raise site in `src/` now attaches:

  ```python
  try:
      packet = decode_frame(frame)
  except ProtocolError as e:
      print(e.protocol, e.field, e.offset, e.frame_offset, e.expected, e.actual)
      # <class 'netprotocols.layer3.ip.IPv4'> ihl 0 14 >=5 0
  ```

  - `protocol` — the class that raised. Set on every single raise site.
  - `field` — the attribute at fault, where one field is at fault.
  - `offset` — byte offset of the problem, relative to the `decode()`
    buffer for a fixed-header error, or to the `field` attribute
    (`options`, `body`, `sections`) for an on-demand parse — a TCP
    option error's offset is relative to `header.options`, not the
    frame. `None` for a `__post_init__` validation error, which sees
    field values, never the bytes they came from.
  - `frame_offset` — `offset` rebased to the whole captured frame.
    `decode_frame` is the only code holding the cursor needed to do
    this, so it's the only thing that sets it; a bare
    `SomeClass.decode()` call leaves it `None`.
  - `expected` / `actual` — added wherever there's a concrete pair to
    state beyond the message text.

  All five default to `None`, and **no message string changed** — every
  existing `str(err)` and `match=` assertion holds. New public name:
  `MaxDepthExceededError` gains the same attributes as every other
  `ProtocolError` subclass (it already existed as of the `decode_frame`
  work; this is the first release to give it structured context too).

- **`decode_frame()`: the chain walker ships with the library.** The
  README taught a hand-rolled eight-line loop, ARCHITECTURE.md showed
  it again, and the test suite kept its own copy — so the library's
  most-used function was the one function it did not provide. It does
  now, with the parts a copy-pasted loop never has:

  ```python
  from netprotocols import decode_frame

  packet = decode_frame(frame)     # Packet(Ethernet(...), IPv4(...), TCP(...))
  frame[packet.consumed:]          # whatever the chain did not decode
  ```

  - **An explicit starting layer.** `decode_frame(buf, start=IPv4)`
    walks a buffer that begins mid-stack — a tunnel payload, a packet
    quoted inside an ICMP error, a non-Ethernet link type. There was
    previously no way to ask for this.
  - **Bounded depth.** `max_depth` (default 32) caps the chain and
    raises the new `MaxDepthExceededError`, rooted at `ProtocolError`
    like everything else. Every header already validated its own
    length, so a chain always terminated; the bound turns a crafted
    frame's very long walk into an immediate named error. The deepest
    chain in the 97-frame corpus is 5.
  - **A lax mode that reports instead of raising.** `lax=True` ends the
    walk on a `ProtocolError` and returns the layers decoded so far,
    with the reason on `packet.stopped_by` — what a capture tool needs
    when frame 4,000,001 is malformed. It relaxes the *walk*, never a
    decoder: every layer returned was decoded under the ordinary strict
    rules.
  - **Per-call decoder overrides.** `decode_as={"udp.port": {6969: DNS}}`
    reads DNS on a nonstandard port for one call, without touching
    global state; `registry=` takes a prepared registry for bulk work.

  `Packet` gains `stopped_by` (why a walk ended early, `None` for a
  packet you built) and `consumed` (the bytes its headers occupy).
  Both default to the constructed-packet values, so `Packet(eth, ip)`
  is unchanged.

  On `memoryview`: the walker slices what it is given and does not
  convert. Measured on the corpus, wrapping each frame in a
  `memoryview` runs at **0.95x** the plain-`bytes` walk — for one small
  frame the view costs more to build than the copy it saves — while a
  `memoryview` over a large capture buffer keeps slices zero-copy.
  Converting internally would have been worse than either.

- **A public protocol registry: third parties can now extend the decode
  walk without editing library source.** Dispatch was four hardcoded
  functions with dict literals inside them and no hook of any kind — a
  protocol this library does not implement (MPLS, VXLAN, a proprietary
  telemetry header) could only be added by forking. It is now five named
  tables owned by `netprotocols.registry`, and registering against one
  is all it takes:

  ```python
  from netprotocols.registry import register

  @register("ethertype", 0x8847)
  class MPLS(Protocol):
      ...

  register("ip.proto", 132, SCTP)   # for a class you did not write
  ```

  The tables are `ethertype`, `ip.proto`, `ip.proto.v6`, `udp.port` and
  `tcp.port`, each named after the wire field it dispatches on.
  `ip.proto.v6` **inherits** `ip.proto`, which is how the IPv6-only
  gating generalises: the four extension headers are registered in the
  v6 table alone, so an IPv4 packet with `protocol=0` still cannot
  conjure a Hop-by-Hop layer — and because inheritance is resolved at
  registration rather than at lookup, the gating costs nothing on the
  hot path. Dispatch behaviour is unchanged entry for entry.

  Registrations land in the process-wide `DEFAULT` registry;
  `Registry.from_defaults()` gives an isolated one for embedding or test
  isolation, and `Registry.derive()` makes a copy-on-write child.
  Registering over an existing key raises `RegistryConflictError` unless
  `override=True` is passed, so two packages claiming the same port
  cannot silently resolve by import order; re-registering the *same*
  class to the same key is a no-op, since a decorator re-runs whenever
  its module does.

  New public names: `Registry`, `register`, `register_all`, `DEFAULT`,
  `RegistryConflictError`, `UnknownTableError`.

### Changed
- **`next_protocol()` accepts an optional registry.** Threading a
  per-call registry through the walk needs the dispatch to be
  redirectable, and `next_protocol()` read the process-wide tables
  directly. It now takes `registry=None`, passed to the same dispatch
  helpers as before, so no table knowledge is duplicated and the
  default path stays a single `dict.get`. Measured in one process, the
  optional parameter costs **+2.1 ns** per dispatch — roughly 0.1% of a
  frame decode. Every existing zero-argument call is unaffected.
- **Port-based dispatch is a table lookup rather than a rebuild.**
  `udp_app_class` and `tcp_app_class` re-ran their deferred imports and
  rebuilt a `dict` literal on every call — they were outside the scope
  of the earlier dispatch-hoisting work, which named only the EtherType
  and IP-protocol functions. Both now read the registry's flat tables:
  `udp.port` 303.1 → 46.0 ns (6.6x), `tcp.port` 186.8 → 45.1 ns (4.1x),
  measured old and new shapes in one process. `ethertype` loses its
  lazy-build guard (51.8 → 47.7 ns) and `ip.proto` is unchanged, having
  already been a table. Corpus throughput moves about 1% — only 28 of
  the 97 corpus frames reach a transport header and therefore do a port
  dispatch at all — which is below this machine's run-to-run noise; the
  per-call figures above are the measurement that resolves.
- **The layer modules no longer import each other's classes.** The
  built-in decoder map moved into `_defaults.py`, which registers it
  once from `__init__.py` after every protocol class exists, so the
  function-body imports that kept the module graph acyclic are gone
  from `vlan.py`, `gre.py`, `tcp.py`, `udp.py` and `ipv6_ext.py`; those
  dispatch helpers are now ordinary module-level imports. The tables
  are built at package import instead of on first dispatch, so the
  lazy-build branch is off the hot path entirely.
- **DNS section parsing happens once, and no longer re-serializes the
  message to read it.** Six helpers called `bytes(self)` — a full
  re-serialization of the whole message — so a single `.answers` access
  rebuilt the message 14 times; and `answers`, `authorities` and
  `additionals` each re-parsed *all three* sections, so reading all
  three parsed the message three times. The parsers are now module-level
  functions working directly from the `sections` bytes the instance
  already holds, in section-relative offsets (a compression pointer,
  which counts from the start of the message, is translated once), and
  the three accessors share a single parse cached on those immutable
  bytes. Measured here on a corpus response: `.answers` 16.84 → 0.20 us,
  all three sections 52.08 → 0.54 us, and one uncached parse 17.03 →
  12.17 us from dropping the re-serializations alone. Nothing is stored
  on the frozen instance — the cache is a bounded module-level memo
  keyed by value, so equal messages share a parse and records (frozen
  dataclasses) are shared rather than copied. The byte-exact round-trip
  is unchanged. A compression pointer that addresses the fixed header
  now raises `InvalidFieldError` instead of decoding header bytes as
  labels. No API change.
- **The decoder no longer re-validates the addresses it just
  generated.** Every header's `__post_init__` ran the address
  validators, including for instances built by `decode()` — so a MAC
  mechanically rendered from six bytes by `bytes_to_mac()` was
  immediately matched against `mac_regex` to confirm what the
  conversion had already guaranteed. `Ethernet`, `ARP` and `IPv4` now
  build their decoded instance directly (`object.__new__` plus
  `object.__setattr__` per field), skipping `__init__` and
  `__post_init__` on that path only. Measured here: `Ethernet.decode`
  2330 → 830 ns (2.8x), `IPv4.decode` 4936 → 2596 ns (1.9x), a corpus
  walk 76,500 → 113,200 frames/sec (1.48x). **Strictness on
  construction is unchanged** — every public constructor still
  validates and still raises, which is now asserted alongside a test
  that the decode path runs no regex at all. The `__post_init__` checks
  bypassed this way are ones `decode()` establishes itself (documented
  at each site and in `_base.py`). No API change.
- **Protocol dispatch is a table lookup, not a table construction.**
  `_ethertype_class()` and `_ip_protocol_class()` re-ran their deferred
  imports and rebuilt a `dict` literal on *every* call — once per layer
  per frame, the hottest path in the library. Both now populate a
  module-level table on first use (the imports stay deferred, so the
  layer modules remain acyclic) and reduce the call to a lookup.
  Measured here: `_ip_protocol_class` 1439 → 104 ns (13.9x),
  `_ethertype_class` 712 → 86 ns (8.3x), and a corpus walk 58,300 →
  76,500 frames/sec (1.31x). The IPv6-only gating is unchanged: the
  IPv4 table simply omits those numbers, so an IPv4 packet with
  `protocol=0` still cannot decode a Hop-by-Hop layer, now asserted at
  the table level as well as through the public API. No API change.
- `bytes_to_mac` renders addresses with `bytes.hex(":")` instead of a
  generator over `format()`. The old form ran seven generator steps and
  six `format()` calls per address, twice per Ethernet frame, and showed
  up in a corpus profile as 88,200 generator calls. Measured 16–29×
  faster on the call depending on run. Output is byte-for-byte
  identical, and `memoryview.hex` takes a separator too, so a
  decode-time view still works. No API change.

### Removed
- **BREAKING: `Packet.payload` is gone.** It was always exactly
  `bytes(self)` — a redundant duplicate of `__bytes__`/`bytes(packet)`,
  which already existed and is the unambiguous spelling — so it is
  deleted outright rather than deprecated. This is the breaking change
  behind the 2.0.0 major bump. Replace `packet.payload` with
  `bytes(packet)`.

### Added
- **`Packet` indexes by protocol type, not just position, and is
  hashable.** `packet[TCP]` returns the first `TCP` layer in wire order
  (`KeyError` if there is none); `packet.get(TCP)` returns `None`
  instead of raising. `packet[0]` keeps indexing positionally —
  `__getitem__` branches on whether the key is an `int` or a type.
  `Packet.__hash__` mirrors exactly what `__eq__` already compares
  (`layers`, and `stopped_by`'s type and `str()`, not its identity —
  `ProtocolError` has no custom `__eq__`), so a `Packet` is now usable
  as a dict key or set member.

- **Canonical, direction-independent flow keys.** `netprotocols.flow`
  is a new small module (`FlowKey`, `flow_key()`) that folds a TCP/UDP
  segment and its enclosing IPv4/IPv6 header into a key that is
  identical for both directions of one conversation:

  ```python
  from netprotocols import flow_key

  flow_key(tcp, ip=ipv4) == flow_key(reply_tcp, ip=reply_ipv4)  # True
  ```

  `FlowKey` is a `NamedTuple` — canonicalizing the two directions is
  comparing the two `(address, port)` endpoint tuples and always
  emitting the lexicographically smaller one first, which a plain
  tuple already orders natively; every other frozen dataclass in this
  codebase models a wire format (`decode()`/`__bytes__`/`_struct`), and
  a derived key isn't one. `Packet.flow_key()` is the convenience form:
  it walks `self.layers` for the first IPv4/IPv6 and TCP/UDP layers and
  delegates to the free function, `None` if either is missing. Reads
  whichever of `IPv4.protocol` / `IPv6.next_header` the enclosing
  header actually has — the same semantic field, different attribute
  name. A transport layer with no ports (ICMP) returns `None` from
  both forms, rather than raising or inventing a port-slot convention
  for a message type that has none.

- **`ICMPv4`/`ICMPv6` gain `embedded_chain`: an error message's
  embedded packet, already decoded.** `decode_frame(lax=True,
  start=...)` already handled this — an RFC-792 error message quotes
  only the invoking IP header plus 8 bytes of what follows, never a
  full TCP/UDP header, so decoding it needs the lax path and no
  `try`/`except`, verified with zero new code before this landed.
  `embedded_chain` is the pre-wired convenience next to the existing
  raw `embedded_packet`, same shape as an accessor-plus-typed-view pair
  elsewhere in this codebase:

  ```python
  icmp.embedded_chain
  # decode_frame(icmp.embedded_packet, lax=True, start=IPv4)
  # → Packet([IPv4(...)]), stopped_by=TruncatedHeaderError(...)
  ```

  `None` for the same cases `embedded_packet` degrades to (non-error
  message types, an empty body); starts at `IPv4` for an `ICMPv4`
  message, `IPv6` for `ICMPv6`. The README documents the distinction
  the issue asked for: `embedded_chain`'s `lax=True` is the *right*
  default here because the truncation is RFC-mandated, expected input
  — not a license to reach for `lax=True` on a complete frame that
  fails to decode, which is still a bug to raise on.

### Fixed
- **The release workflow can no longer publish untested code.** Pushing
  a `v*` tag ran `uv build` and `uv publish` with no dependency on the
  lint, typecheck or test jobs — and because the CI workflow triggers
  only on pushes and pull requests targeting `master`, a tag push ran
  **no checks at all**. A tag against broken code published to PyPI
  unchallenged, and a published version can only be yanked, never
  replaced. `ci.yml` is now also a reusable workflow (`workflow_call`),
  and `release.yml` invokes it against the tagged commit with the
  publish job gated behind it, so the release gate and the pull-request
  gate are one definition and cannot drift apart.

### Fixed
- **A mistagged release can no longer publish the wrong version.**
  `release.yml` built from `pyproject.toml` and never consulted the tag,
  so pushing `v1.4.0` while the project still read `1.3.0` would either
  fail at upload against an existing version or, if that version was
  never released, silently publish the wrong one. The QA ladder cannot
  catch this — every check passes, because the code is fine and only the
  tag is wrong. The release now reads the version back out of the built
  artifact and refuses to publish unless it matches the tag.
- **The README no longer advertises shipped work as upcoming.** Its
  Roadmap section listed the eight decoder-depth items tracked by #67 —
  all of which shipped in 1.3.0, with #67 itself closed — so the front
  page presented finished work as planned and pointed readers at a
  closed issue. It now links the current roadmap (#107) and its five
  release-mapped epics instead of restating individual items, which is
  what went stale.
- **ARCHITECTURE.md no longer misstates the corpus or the source
  layout.** It described "93 frames across 16 scenarios" long after the
  corpus reached 97 across 17, and its layout map omitted `vlan.py`,
  `gre.py` and `dhcp.py`. The counts now live in
  `tests/fixtures/MANIFEST.md` and the README alone — ARCHITECTURE.md
  points at the MANIFEST rather than keeping a third copy, which is
  what drifted.
- **Layer sub-packages now export everything their layer defines.**
  `from netprotocols.layer7 import DHCP` failed while
  `from netprotocols import DHCP` worked, because each layer's own
  `__init__` carried a subset of what the top-level package re-exports.
  `layer3` was missing `GRE`, `IPv4Option`, `IPv6Option`, `NDPOption`
  and `IGMPv3GroupRecord`; `layer4` was missing `TCPOption`; `layer7`
  exported only `DNS`, omitting `DHCP`, `DNSOverTCP` and
  `DNSResourceRecord`. Purely additive — no name changed meaning.

### Development
- **Comparative claims are under embargo until the roadmap closes.**
  `docs/CLAIMS.md` gains a standing rule and a per-claim
  `COMPARATIVE — HELD` marker: nothing mentioning scapy, dpkt or any
  other library reaches the README, release notes or package metadata
  until #107 is finished. The measurements keep being recorded — the
  register exists to hold evidence, not to publish it — and ship once,
  together, rather than in pieces that each need defending. The
  rationale is in the numbers: claim 1.2 went from "2.9x slower than
  dpkt" to "1.16x faster" inside a single tier.
- Three differentiators found during Tier 1 are now tracked as claims
  rather than living in pull-request descriptions: decode depth (1.6 —
  the corpus walk reaches a deeper layer than dpkt on 27 of 97 frames,
  reproducible with `scripts/benchmark.py --depth`, which this change
  adds), the CI throughput gate (1.7), and strict construction on a
  decode path that pays nothing for it (5.4). The stale "we are ~86% of
  dpkt" line in "Claims we must not make" is corrected, and a rule
  added that a superiority claim must name its axis — scapy crafts,
  sends and covers thousands of protocols, so the codec axes are where
  the evidence is.
- **A reproducible decode benchmark, and a CI job that fails on a
  regression.** `scripts/benchmark.py` walks the 97-frame corpus and
  reports frames/sec; `--compare` times `dpkt` and `scapy` on the same
  frames (both dev-only extras in a new `bench` dependency group — the
  package still has zero runtime dependencies). Because absolute
  throughput is a property of the machine, every run also times a fixed
  calibration workload and reports a normalized figure, which is what
  `--check` compares against `benchmarks/baseline.json`. **The CI job
  blocks at 15% below the baseline**: measured, that is about four
  times the noise it must tolerate — the job's first run landed 3.7%
  from a baseline recorded on entirely different hardware, and
  run-to-run spread on one machine is ~2%, while the Tier 1 changes
  moved the number by 30-90% each. A failing check re-measures once
  before failing, so a runner that loses CPU to a neighbour does not
  block an unrelated pull request. Comparison output carries its own
  caveats — notably that the libraries are not asked for identical
  work, since dpkt leaves the DNS-over-TCP payload as raw bytes where
  this library decodes it — because a benchmark nobody can check is the
  problem #86 set out to fix, not the goal.
- `tests/test_version.py` holds `netprotocols.__version__` against the
  version in `pyproject.toml`. The two were kept in step by hand and
  nothing checked them, so a bump that missed one would ship a package
  whose metadata and `__version__` disagree.
- `tests/test_docs.py` holds documented facts against the fixtures:
  the MANIFEST's and README's frame/scenario counts must match the real
  corpus, ARCHITECTURE.md must not reintroduce a third copy of them,
  and the layout map must mention every shipped module. It also
  guards the README's Roadmap section against pointing back at the
  superseded #67 or re-listing work that has already shipped.
- `tests/test_exports.py` keeps the layer and top-level export sets in
  agreement, deriving the expectation from each object's `__module__`
  rather than a hand-written list, so a protocol added to the top level
  but forgotten in its layer fails the suite.
- Coverage is now enforced, not merely reported: `fail_under = 98` in
  `[tool.coverage.report]`. The suite covers 99% of 1441 statements —
  the only misses are `Packet.__repr__` and its `__eq__`
  `NotImplemented` branch — so the gate is set below the current figure
  to leave room for a legitimately unreachable branch, and well above
  the level at which the bar would stop meaning anything.
- `tests/test_workflows.py` asserts the release gate stays wired:
  that `ci.yml` remains callable, that some release job invokes it,
  that `publish` depends on that job, and that every local `uses: ./…`
  reference resolves to a workflow declaring `workflow_call`. The
  wiring is otherwise easy to remove silently — releases keep working
  while the gate quietly stops existing — and it cannot be verified by
  running it, since publishing is irreversible.
- `docs/CLAIMS.md` records the positioning claims produced by the
  post-1.3.0 competitive analysis, each with its evidence, a
  reproduction path and a publication status — `VERIFIED`,
  `GATED ON #nn`, or `NEEDS RE-MEASUREMENT`. Several of the strongest
  claims are not true yet (decode throughput against dpkt is gated on
  the Tier 1 performance work; the browser claim is untested until a
  Pyodide CI job exists), so the register also lists what must not be
  said and why. Feeds the README as each roadmap tier lands; see #101
  and the roadmap in #107.

## [1.3.0] - 2026-09-01

### Added
- **IEEE 802.1Q VLAN tags** (`VLAN`, 802.1Q-2018 §9.6 / 802.1ad QinQ):
  single and stacked (QinQ `0x88A8`, legacy double-tagged `0x9100`)
  tags decode as one layer per tag; the Tag Control Information word is
  split into `pcp`/`dei`/`vid` dataclass fields validated in
  `__post_init__` (`InvalidFieldError`), with the packed 16-bit view
  kept as the `tci` property; `VLAN` is registered in the
  property-based fuzz suite and the `EtherType` display names are
  covered by the enum completeness test.
- **IGMPv3 group records** (`IGMPv3GroupRecord`, RFC 3376 §4.2): a v3
  Membership Report (type `0x22`) now parses its group-record array on
  demand. `IGMP.group_records` yields one `IGMPv3GroupRecord` per record
  (record type + display name, multicast group, source-address list,
  raw auxiliary data) and `IGMP.num_group_records` reads the count;
  other message types return `None`. Parsing reads the raw body and
  never re-encodes, so the byte-exact round-trip is preserved, and a
  lying record/source count or a truncated record raises
  `InvalidFieldError` (bounded — never hangs or over-reads).
- **IGMPv3 query fields** (RFC 3376 §4.1): a v3 Membership Query (type
  `0x11`) now exposes its fields past the group address — the `s_flag`
  (suppress router-side processing), `qrv`, `qqic`, and
  `query_source_addresses` accessors parse the raw body on demand. A v2
  (8-byte) query and non-query types return `None`, and a source count
  that runs past the message raises `InvalidFieldError`.
- **DHCP** (`netprotocols.DHCP`, RFC 2131/2132) — the fixed BOOTP header
  (op, xid, the client/your/server/gateway addresses, the 16-byte client
  hardware address, and the server-name / boot-file fields) decodes in
  full; the magic cookie and TLV options are kept raw and parsed on
  demand. `option_map` walks the options (concatenating a value split
  across appearances, RFC 3396) and `message_type` / `message_type_name`
  read the DHCP message type (option 53). Dispatched from UDP by
  well-known port (67/68); terminal, with a byte-exact round-trip and
  the same bounded-parse contract as DNS (`InvalidFieldError` on a
  missing cookie or an option that overruns the buffer).
- **GRE** (`netprotocols.GRE`, RFC 2784/2890) — Generic Routing
  Encapsulation, dispatched from IPv4/IPv6 protocol 47. The four-byte
  header (flags/version + protocol type) decodes with the optional
  checksum, key, and sequence-number fields that the flag bits announce
  kept raw and surfaced through accessors. The payload chains onward by
  the `protocol_type` EtherType, so a GRE-tunnelled IPv4/IPv6 packet
  keeps decoding; the round-trip stays byte-exact regardless of which
  optional fields are present.
- **GRE checksum arm** (`netprotocols.checksum`, RFC 2784 §2.5):
  `compute`/`verify` now cover GRE — the internet checksum over the GRE
  header plus its payload with the checksum field zeroed and no
  pseudo-header. `compute(gre, payload=...)` requires the
  Checksum-Present bit (and its field) and raises `InvalidFieldError`
  otherwise; `verify` of a header whose Checksum-Present bit is clear
  returns `True` — a frame cannot fail a checksum it does not carry —
  mirroring the UDP-over-IPv4 zero rule.
- **Richer address accessors** (README roadmap): read-only `_address`
  properties return stdlib `ipaddress` objects alongside the canonical
  `str` fields, for comparison, subnet membership, and arithmetic —
  `IPv4.src_address`/`dst_address` and `ARP.spa_address`/`tpa_address`
  as `ipaddress.IPv4Address`, `IPv6.src_address`/`dst_address` as
  `ipaddress.IPv6Address`, and the four `DHCP` address fields as
  `ciaddr_address`/`yiaddr_address`/`siaddr_address`/`giaddr_address`.
  Purely additive: the `str` fields stay the round-tripping
  representation. MAC addresses stay `str` — the stdlib has no EUI
  type.
- **IPv4 options** (`IPv4Option`, RFC 791 §3.1): the options TLV list
  now parses on demand, mirroring the TCP-option work —
  `IPv4.parsed_options` yields one `IPv4Option` per option in wire
  order (kind + `kind_name`, raw `data`). The common kinds are named:
  End of Option List and No-Operation (single-byte; EOL ends the parse,
  so padding after it is not returned), Record Route (7), Timestamp
  (68), and Router Alert (148, RFC 2113); unknown kinds keep their raw
  `data` with a numeric fallback name. Parsing reads the raw `options`
  bytes and never re-encodes, so the byte-exact round-trip is
  preserved; an option length below the 2-byte minimum or one that runs
  past the options raises `InvalidFieldError` (bounded — never hangs or
  over-reads).
- **DNS resource records** (`DNSResourceRecord`, RFC 1035 §4.1.3): the
  answer, authority, and additional sections parse on demand —
  `DNS.answers` / `DNS.authorities` / `DNS.additionals` yield records
  (name, type + `rtype_name`, class, TTL, raw `rdata`, and a decoded
  `rdata_text`: IPv4/IPv6 for A/AAAA, the target name for CNAME/NS/PTR,
  and MX/TXT/SOA; hexadecimal otherwise). Parsing reads the raw sections
  and never re-encodes, so the byte-exact round-trip holds; a record or
  compressed name that runs past the message raises `InvalidFieldError`.
- **TCP options** (`TCPOption`, RFC 9293 §3.1): the options TLV list
  now parses on demand — `TCP.parsed_options` yields one `TCPOption`
  per option in wire order (kind + `kind_name`, raw `data`, and a
  decoded `value` where this library understands the kind: the segment
  size for MSS, the shift count for Window Scale, a `(tsval, tsecr)`
  pair for Timestamps, and `(left_edge, right_edge)` pairs for SACK;
  RFC 7323/2018). EOL and NOP are single-byte (EOL ends the parse);
  unknown kinds keep their raw `data` with `value` degrading to `None`.
  Parsing reads the raw `options` bytes and never re-encodes, so the
  byte-exact round-trip is preserved, and an option length below the
  TLV minimum or one that runs past the options raises
  `InvalidFieldError` (bounded — never hangs or over-reads).
- **ICMP message bodies** (RFC 792 / RFC 4443): `ICMPv4`/`ICMPv6` gain a
  raw `body` field — the message data after the 8-byte header — so a
  decoded message is self-contained (like `IGMP`/`DNS`), `header_len`
  consumes the whole IP payload, and the layer stays terminal with a
  byte-exact round-trip. Echo requests/replies (v4 types 8/0, v6
  128/129) expose `identifier` / `sequence_number` split from `rest`,
  and the error messages (v4 Destination Unreachable / Redirect / Time
  Exceeded / Parameter Problem; v6 types 1-4) expose `embedded_packet` —
  the invoking datagram, decodable as `IPv4`/`IPv6`. The accessors read
  on demand and degrade to `None` for other message types or an empty
  body, never raising. A decoded message now carries its body in
  `bytes(layer)`, so `checksum.compute`/`verify` need no separate
  `payload` for it (passing one for a header-only object still works).
- **IPv6 Neighbor Discovery** (`NDPOption`, RFC 4861): `ICMPv6` now
  parses NDP messages on demand — `ndp_target_address` reads the
  16-byte target of a Neighbor Solicitation/Advertisement (135/136),
  and `ndp_options` walks the option TLVs of Router
  Solicitation/Advertisement, Neighbor Solicitation/Advertisement, and
  Redirect at each message's own options offset. Each `NDPOption`
  carries its `type` + `type_name` and raw `data`; a Source/Target
  Link-Layer Address option (1/2) reads back as a MAC string via
  `link_layer_address`, and Prefix Information (3) / MTU (5) stay raw.
  Non-NDP message types return `None`. Option lengths count in 8-octet
  units: a zero length (which must not loop), a length past the
  message, or a body shorter than the message's fixed fields raises
- **IPv6 extension-header options** (`IPv6Option`, RFC 8200 §4.2): the
  Hop-by-Hop and Destination Options headers now parse their option
  TLVs on demand — `parsed_options` yields one `IPv6Option` per option
  in wire order, padding included (Pad1 is a lone type byte; everything
  else is type/length/data). Each option carries its `type` +
  `type_name` (Pad1, PadN, Router Alert per RFC 2711, Jumbo Payload per
  RFC 2675; unknown types keep their numeric value) and raw `data`, and
  exposes the action-on-unrecognized bits (the two high bits of the
  type) as `unrecognized_action`. Parsing reads the raw `options` bytes
  and never re-encodes, so the byte-exact round-trip is preserved; a
  missing length byte or option data that runs past the header raises
  `InvalidFieldError` (bounded — never hangs or over-reads).
- **DNS over TCP** (`DNSOverTCP`, RFC 1035 §4.2.2): `TCP.next_protocol()`
  now dispatches application protocols by well-known port
  (`layer4._ports.tcp_app_class`). DNS over TCP is length-prefixed, so
  port 53 chains through a 2-byte `DNSOverTCP` length shim — a layer
  between `TCP` and the `DNS` message, like a VLAN tag between Ethernet
  and its payload — and the walk reaches the DNS message (records and
  all) at its true offset. Non-DNS ports still end the chain at TCP.

### Development
- The real-capture fixture corpus gained `vlan_icmp.pcap` (802.1Q
  single tag VID 100 + 802.1ad QinQ S-VID 200 / C-VID 30, over ARP and
  ICMPv4), so the `VLAN` layer rides the corpus-wide invariants and the
  transport-checksum recompute like every other protocol. It is a
  direct tcpdump capture of real kernel-tagged frames — built over
  802.1Q / 802.1ad vlan devices on a veth pair with VLAN and checksum
  offload disabled so the tags stay in-band in the saved bytes and the
  inner checksums are genuine kernel output; see
  `tests/fixtures/MANIFEST.md` and `scripts/capture_fixtures_vlan.sh`.
- The corpus gained real-capture `dhcp.pcap` (a DHCP DORA exchange from
  `dnsmasq` + `dhclient`) and `gre.pcap` (IPv4-in-GRE ICMPv4 echo over a
  plain and a keyed kernel tunnel), so the `DHCP` and `GRE` layers ride
  the corpus-wide invariants on genuine bytes.
  `scripts/capture_fixtures_dhcp.sh` and `scripts/capture_fixtures_gre.sh`
  produce them, and `scripts/check_fixtures.py` now peels a GRE header to
  verify the tunnelled inner IPv4/ICMP checksums.
- The corpus gained real-capture `dns_tcp.pcap` (an A and a TXT query +
  response from `dig +tcp` against `dnsmasq` over a veth pair, offload
  disabled), so the TCP application dispatch and the `DNSOverTCP`
  length shim (#57) ride the corpus-wide invariants and the
  TCP-checksum recompute on genuine bytes — every frame decodes
  `Ethernet→IPv4→TCP→DNSOverTCP→DNS` with the length prefix agreeing
  with the message it frames and a resolvable answer.
  `scripts/capture_fixtures_dns_tcp.sh` produces it; the corpus is now
  97 frames across 17 scenarios.
- Contributor documentation: a `CONTRIBUTING.md` (dev setup, the QA
  ladder, the decode contract, the add-a-protocol enforcement points,
  and the fixture-capture workflow), a pull-request template, and
  bug-report / protocol-request issue templates under `.github/`.
- README refresh: the Protocol coverage table gains the shipped `DHCP`
  and `GRE` rows, the `DNS` row notes resource-record parsing and the
  DNS-over-TCP length shim, and the `IGMP` row notes the IGMPv3 report
  and query parsing. The Roadmap section now lists only the remaining
  items, linking the open decoder-depth issues (#59-#66, tracked by
  #67), and the stale corpus figure is corrected to 93 frames across 16
  scenarios here and in `ARCHITECTURE.md`.

## [1.2.0] - 2026-08-30

### Added
- **IGMP** (`netprotocols.IGMP`, RFC 1112/2236/3376) — IPv4 multicast
  group management, dispatched from IPv4 protocol 2. The common
  four-byte header (type, max-response code, checksum) is decoded; the
  `group_address` accessor reads the group for the message types that
  carry one, and `netprotocols.checksum` gains an IGMP arm. v3
  group-record parsing is a roadmap follow-up.
- **DNS** (`netprotocols.DNS`, RFC 1035) — the first application-layer
  protocol. The 12-byte header and flag bits are decoded; the four
  message sections are kept raw with on-demand, read-only accessors
  (`question_name`, `question_type`, `question_class`) that decompress
  names safely (bounded pointer-following; malformed or looping names
  raise `InvalidFieldError`, never hang). Round-trip stays byte-exact.
- **Port-based dispatch** on UDP: `UDP.next_protocol()` reaches an
  application protocol by well-known port (`netprotocols.layer4._ports`,
  `{53: DNS}` for now), checked destination-then-source. Documented as
  best-effort — a mis-dispatch degrades to the malformed-frame path.

## [1.1.0] - 2026-08-29

### Added
- **IPv6 extension headers** (RFC 8200 §4.3-4.6): `IPv6HopByHopOptions`,
  `IPv6Routing`, `IPv6Fragment`, `IPv6DestinationOptions`. The decode
  chain now reaches ICMPv6/TCP/UDP behind them (MLD reports decode
  fully). Extension headers dispatch only inside an IPv6 chain, and a
  Fragment header chains onward only from the first fragment.
- **Checksums** (`netprotocols.checksum`): `internet_checksum()`
  (RFC 1071), `compute()`/`verify()` covering the IPv4 header checksum,
  ICMPv4, and TCP/UDP/ICMPv6 with IPv4/IPv6 pseudo-headers, and
  `Packet.with_checksums()` for filling a whole stack on encode. The
  UDP-only zero substitution is confined to the UDP arm.
- **Property-based fuzzing** of the decode path (hypothesis, dev-only):
  decode() raises nothing outside `ProtocolError` for any input; the
  chain walk never consumes past the frame; constrained round trips.
- `IPProtocol` gains `HOPOPT`, `IPV6_ROUTE`, `IPV6_FRAG`,
  `IPV6_DSTOPTS` with display names.

### Development
- The real-capture fixture corpus grew to 65 frames across 12
  scenarios (MLD behind hop-by-hop, IPv6 fragment pairs); checksum
  tests recompute every verifiable corpus frame to its captured wire
  value.

## [1.0.1] - 2026-08-29

### Fixed
- `IPv4.next_protocol()` chained non-first fragments
  (`fragment_offset > 0`) into garbage upper-layer decodes — a slice
  from the middle of a fragmented payload has no header at its start.
  Discovered by the new real-capture fixture corpus on live fragmented
  traffic; the chain now ends at the IPv4 layer for those frames, as it
  already did for unknown protocols.

### Added (development)
- A real-capture fixture corpus under `tests/fixtures/` (56 frames,
  10 scenarios, every checksum internally verified — see its
  MANIFEST.md) with corpus-wide invariant tests, plus the capture and
  validation scripts under `scripts/`.

## [1.0.0] - 2026-08-21

Complete rewrite. The public API is new; see the README and
ARCHITECTURE.md for the current usage.

### Changed
- The parsing core moved from `ctypes.BigEndianStructure` subclasses to
  frozen, slotted dataclasses parsed with `struct.Struct`. Decoded and
  constructed instances are now identical in type and compare equal
  field-by-field.
- `next_protocol()` (returning the class that decodes the payload, or
  `None`) replaces the stringly-typed `encapsulated_proto` chain.
  Protocol number registries are exposed as `EtherType`, `IPProtocol`,
  and `ARPOperation` enums.
- `header_len` is now an instance property: IPv4 honors IHL and TCP
  honors the data offset, and both expose their raw `options` bytes.
- Field names modernized (`ethertype`, `src_port`, `total_length`,
  `checksum`, ...); display helpers are properties such as
  `protocol_name`, `flags_str`, and `checksum_hex_str`.
- Packaging moved to PEP 621 (`hatchling` + `uv`), src layout, Python
  3.12+, MIT license, `py.typed` (mypy strict clean).
- Validators are plain functions (`validate_mac_addr`,
  `validate_ipv4_addr`) raising exceptions rooted at `ProtocolError`.

### Fixed
- `TCP.header_len` was hardcoded to 32 bytes; the base header is 20 and
  the real length follows the data offset.
- Decoding ignored IPv4 IHL and TCP data offset, so headers carrying
  options were mis-sliced.
- Serialization returned a zeroed buffer (`Protocol.__str__`);
  `bytes(header)` now re-emits the exact on-wire form, options included.
- `Packet` rejected instances of indirect `Protocol` subclasses
  (e.g. `IPv4`, `ICMPv4`) due to validation against direct subclasses
  only; membership is now checked with `isinstance`.
- Malformed input (truncated buffers, lying IHL/data-offset values) now
  raises typed exceptions (`TruncatedHeaderError`, `InvalidFieldError`)
  instead of arbitrary `ValueError`/`struct.error` leaks.

### Removed
- The `Validator` descriptor infrastructure (it stored state on the
  descriptor itself — class-shared — and was never wired into any
  protocol class).
- Poetry manifests and the `setup.py`-era metadata.

## [0.8.0] - 2022-08-19

Last release of the ctypes-based implementation, published to PyPI in
2022. The repository had drifted behind the published releases; the
0.8.0 sources were recovered from the PyPI sdist and committed (tagged
`v0.8.0`) before the 1.0.0 rewrite. Releases 0.4.4 through 0.8.0 exist
on PyPI only; their individual histories were not preserved.
