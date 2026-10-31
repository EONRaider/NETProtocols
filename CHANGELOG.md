# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`TFTP`: the Trivial File Transfer Protocol (RFC 1350), with option negotiation (RFC 2347-2349) (#192).** UDP port 69 dispatches, best-effort like every port entry, to the new `netprotocols.TFTP` (also `netprotocols.layer7.TFTP`), which decodes the 2-byte `opcode` and keeps the message after it as raw `body`, read on demand by opcode: `filename`, `mode` and `options` for an RRQ or WRQ, `block` and `data` for DATA, `block` for ACK, `error_code`, `error_name` and `error_message` for ERROR, and `options` for an OACK (opcode 6, RFC 2347), each `None` (`()` for `options`) where the opcode does not carry it; `opcode_name` names the opcode. Strings are zero-terminated rather than length-prefixed, so they are split with `bytes.find`, not the shared TLV walker, and read as ASCII with any other byte as a backslash escape. Options are `(name, value)` string pairs in wire order; `option(name)` matches a name in any case (RFC 2347), and `blksize` (RFC 2348), `timeout`, `tsize` (RFC 2349) and `windowsize` (RFC 7440) read their value as a number, or `None` if it is absent, not decimal or over 20 digits (leading zeros aside; 20 hold any 64-bit size, and `int()` would raise `ValueError` past 4,300). TFTP has no length field and the walk does not trim to UDP's (#235), so each opcode ends where its structure does and leaves the rest undecoded, `bytes(TFTP.decode(x)) == x[:header_len]`: an ACK after 4 bytes (an untagged Ethernet frame over IPv4 with no options pads it with 14 zeros), an ERROR at its message's zero byte, a request or an OACK after its last whole option pair (a zero byte where a name would start ends the options, so padding after whole pairs is left undecoded, and an option cut short is left undecoded with it). Without the UDP length (#235) a trailer holding a zero byte can still be read as option bytes: after a name with no value, the trailer's first zero byte ends that value (padding decodes `(name, "")` and gives up one byte), and after whole pairs an FCS holding a name, a zero byte, a value and a zero byte (`12 00 34 00`) reads as one more pair. DATA cannot, and its `data` runs to the end of the buffer, a trailer included. `decode()` raises `InvalidFieldError` for an opcode other than 1-6 (65,530 of 65,536 two-byte prefixes, so a wrong port guess is almost always rejected) and `TruncatedHeaderError` for a mandatory field cut short: a block number or error code under 2 bytes, or a filename, mode or error message with no terminating zero byte. **Dispatch reaches the request only.** A client sends its RRQ or WRQ to port 69, but the server answers from an ephemeral port of its own, and the rest of the transfer runs between two ephemeral ports (RFC 1350 §4), which no port table can name: a stateless walk stops at UDP for every DATA, ACK, OACK and ERROR. A caller following the transfer takes the server's port from its first reply and walks with `decode_as={"udp.port": {port: TFTP}}`, which covers both directions, or calls `TFTP.decode()` on the UDP payload.
- **`STUN`: Session Traversal Utilities for NAT (RFC 8489, and RFC 5389, which it obsoletes; #194).** UDP and TCP port 3478 now dispatch, best-effort like every port entry, to `netprotocols.STUN` (also `netprotocols.layer7.STUN`), which decodes the 20-byte header into `message_type`, `magic_cookie` and `transaction_id` and keeps the attributes raw, padding included, as `attributes`, so `bytes(STUN.decode(x)) == x[:header_len]`; `length` is `len(attributes)`, not a field. The 14-bit Message Type stays one field, and accessors split the class and method interleaved in it (`message_class`, `method`, `class_name`, `method_name`, `message_type_name`, e.g. "Binding Success Response"). `decode()` verifies the magic cookie (`0x2112A442`, `STUN.MAGIC_COOKIE`) and rejects a message without it with `InvalidFieldError` (`field="magic_cookie"`), so an RFC 3489 message, whose 16-byte transaction ID takes the cookie's place, is not decoded; it also rejects nonzero top two bits (`"message_type"`, which also turns TURN ChannelData away) and a Message Length that is not a multiple of 4 (`"length"`), and raises `TruncatedHeaderError` for a Length past the buffer. Over random payloads to port 3478 every walk stopped. `parsed_attributes` walks the attributes on demand as `STUNAttribute(type, value)` through the shared TLV walker, which gains a private `align` parameter for STUN's 4-byte padding, and raises `InvalidFieldError` on a malformed list; `STUNAttribute` names IANA's attribute types (`type_name`), says which are comprehension-required, reads an address in the clear (`address`), and re-encodes zero-padded as RFC 8489 §14 sends it, while padding of any other value, which RFC 5389 §15 allowed, survives a decode-encode round trip. The other accessors never raise, reading the attributes up to the first malformed one: `attribute(kind)` (the first of duplicates), `mapped_address` and `xor_mapped_address` (`STUNAddress(family, port, address)`, the latter un-XORed with the cookie, and over IPv6 the cookie and transaction ID, leaving the wire bytes untouched), `xor_address()` for TURN's other XOR-encoded addresses, `software`, `error_code` (300-699, `None` for a Class outside 3-6 or a Number above 99, which RFC 8489 §14.8 rules out) and `error_reason`, `unknown_attributes`, `message_integrity` (the raw HMAC-SHA1, unverified: it needs the credential's key) and `fingerprint`. Over TCP, where messages follow one another with no framing but their Length (RFC 8489 §6.2.2), each message decodes as its own layer and `STUN.next_protocol()` answers `STUN` while the next 8 bytes begin like a message, as BGP does; as for BGP, a segment of more than 29 messages exceeds the default `max_depth`, and a 1448-byte one can hold 72 bare 20-byte headers (a larger `max_depth` or a second walk with `start=STUN` decodes the rest). TLS/DTLS (port 5349), RFC 6544 framing and ChannelData are not decoded.
- **STUN's FINGERPRINT in `compute`/`verify`/`Packet.with_checksums()`.** `compute(stun)` is the IEEE CRC-32 (`binascii.crc32`) of the message up to its FINGERPRINT attribute, the header's Length already counting it, XORed with `0x5354554E` (RFC 8489 §14.7, RFC 5389 §15.5; `ip` and `payload` ignored), and raises `InvalidFieldError` unless the last attribute is a 4-byte FINGERPRINT. `verify()` accepts a message with no FINGERPRINT, as it does a GRE header without the C bit, and fails one whose FINGERPRINT is not last. No one field says whether a message has one, so it has none only when its attributes walk whole, none of them a FINGERPRINT, and its last 8 bytes do not begin like one: a corrupted Length earlier in the list, which would end the walk short of the FINGERPRINT or fold it into a longer value, fails rather than reading as a message without one. `with_checksums()` rewrites the attribute's value and leaves MESSAGE-INTEGRITY alone; it now carries a rebuilt layer's decode context across `dataclasses.replace()`, which resets it, so the first of two STUN messages in a TCP segment still names the second in `next_protocol()`. `compute()` and `verify()` were restructured to stay at radon B (8) and A (5): the checksums that cover only the layer's own bytes (IPv4, IGMP, CDP, OSPF, STUN) share one helper, and the "carries no checksum" rules (UDP over IPv4 at 0, GRE without the C bit, OSPF under cryptographic authentication, STUN without FINGERPRINT) another.

### Fixed

- **Transport checksums and flow keys use the final destination behind an IPv6 Routing header (RFC 8200 §8.1, #236).** The pseudo-header of a TCP, UDP, ICMPv6, VRRPv3 or PIM checksum over IPv6 used `ip.dst`, which on a packet in flight behind a Routing header with `segments_left > 0` is the next hop, so `compute()` gave the wrong value, `verify()` called a correct packet corrupt, and `Packet.with_checksums()` would write the wrong one; `flow_key()` keyed the two directions of a source-routed flow differently. `checksum.compute()`, `checksum.verify()` and `flow.flow_key()` take a new keyword-only `routing: IPv6Routing | None = None`, and `Packet.with_checksums()` and `Packet.flow_key()` pass the last `IPv6Routing` with `segments_left > 0` between the nearest IP header and the transport, since a receiver skips one with none left (RFC 8200 §4.4 for unrecognized types, and each type's own processing rules: RFC 2460 §4.4, RFC 6554 §4.2, RFC 8754 §4.3) and RFC 8200 §4.1 says each extension header "should occur at most once" (a Routing header before an inner IP header, as in a tunnel, does not apply to it). With `routing` given, IPv6 and segments left, the address is the new `IPv6Routing.final_destination(dst)`: the last address of type 0 (RFC 2460 §4.4) and the Home Address of type 2 (RFC 6275 §6.4); for type 3 (RFC 6554 §3) the last entry, rebuilt from the first `CmprE` octets of `dst` and the octets the header carries, `Pad` excluded; for type 4 (RFC 8754 §2) Segment List[0]. It returns `None` for another routing type or data of the wrong shape, and the address stays `ip.dst` then; it stays `ip.dst` too with no segments left, which the method itself does not check (it ignores `segments_left`), and over IPv4. It never raises and works on a layer decoded from a `memoryview`. Callers that pass no `routing` behave as before. `IPv6Routing.segments` still returns `None` for types 3 and 4.
- **SCTP's zero-tail scan no longer copies the trailer (#257).** The chunk walk behind `SCTP.decode()` and `SCTP.parsed_chunks` checks that what follows the last chunk is all zero bytes; on `bytes` input it sliced the rest of the buffer first, so a direct decode of a packet with a long trailer allocated a copy of it. The scan now reads through a `memoryview`, as CDP's does, and peak memory stays flat whatever the trailer's length. Results are unchanged. Inside a walk the frame bounds the trailer, so this mattered only for a direct decode.

### Development

- **A real TFTP capture joins the corpus: `tftp.pcap`, 33 frames (326 across 31 scenarios).** `scripts/capture_fixtures_tftp.sh` runs tftpd-hpa 5.2 (`--secure --create`) in one netns and the tftp-hpa 5.2 client and curl in another, over a veth pair, and captures six transfers whole, filtering by host rather than by port, so the ephemeral-port DATA and ACK flow is kept: a three-block RRQ ending in a short block, an RRQ ending in an empty block, a WRQ, ERROR codes 1 and 0, and curl's RRQ with `tsize`, `blksize` and `timeout`, answered by an OACK. The script asserts the composition frame by frame and checks that each file arrived intact; `check_fixtures.py` verifies every UDP checksum without change. `TFTP` joins the fuzz suite (`ALL_PROTOCOLS`, a round-trip strategy over canonical messages of all six opcodes, and a property, seeded from the captured messages and from number options with digit runs past `int()`'s 4,300-digit limit, that decode keeps a prefix that round-trips and that every accessor answers), the contract tests (truncation, a string without its zero byte, and padding, an FCS and a cut option after a request) and the corpus coverage set.
- **A real STUN capture joins the corpus: `stun.pcap`, 12 frames (338 across 32 scenarios, with `tftp.pcap`), and an RFC 3489 one outside it.** `scripts/capture_fixtures_stun.sh` runs coturn 4.6.1's `turnserver` in STUN-only mode in one netns and clients in another, over a veth pair with offload off: `turnutils_stunclient`'s Binding Request and Success Response (XOR-MAPPED-ADDRESS, MAPPED-ADDRESS, RESPONSE-ORIGIN, SOFTWARE, FINGERPRINT) and its RFC 5780 request drawing error 420; a script-built request with an unknown comprehension-required attribute drawing 420 with UNKNOWN-ATTRIBUTES; two script-built requests in one TCP segment and their two responses in one segment back; and, against a server requiring the long-term credential mechanism, the 401 challenge and an authenticated exchange with MESSAGE-INTEGRITY both ways. The `stun` client's RFC 3489 exchange goes to `tests/fixtures/stun/stun_rfc3489.pcap`, outside the corpus globs, since `STUN` rejects it by design. The script asserts the selection message by message. `scripts/check_fixtures.py` now verifies every STUN FINGERPRINT with its own bit-at-a-time CRC-32, and every MESSAGE-INTEGRITY with the test credential published in `tests/fixtures/MANIFEST.md`, over UDP and over TCP segments on port 3478, failing a datagram the message does not fill, an unknown USERNAME and a MESSAGE-INTEGRITY-SHA256 it cannot compute. The kernel had no IPv6, so RFC 5769's published test vectors, IPv6 XOR-MAPPED-ADDRESS among them, cover it in `tests/test_stun.py`. `STUN` joins the fuzz suite (`ALL_PROTOCOLS`, a round-trip strategy, and a property that decode and every accessor are total and that the parsed attributes tile the raw ones), the truncation contract test, the corpus coverage set and the layout-map check.
- **`scripts/check_fixtures.py` uses the final destination behind an IPv6 Routing header too (RFC 8200 §8.1, #259).** The fixture checker, the corpus's independent checksum oracle, skipped Routing headers unread and built every IPv6 pseudo-header from the wire Destination Address, so a correct capture taken behind a route with segments left (SRv6, RPL) would have been rejected, and the checker disagreed with the library after #236. It now resolves the final destination with code of its own, sharing none with `netprotocols`, by the same rules: types 0 and 2 the last (type 2: the only) address, type 3 the last entry completed with the first `CmprE` octets of the Destination Address, type 4 Segment List[0]; the last Routing header with segments left decides, and an unknown type or data of the wrong shape falls back to the wire address. Every corpus frame checks exactly as before. The pseudo-header of a transport-mode payload under ESP takes the final destination too, as the packet's own; a packet tunnelled inside does not, since the route is not its. New tests in `tests/test_checksum.py` run the checker over the #236 vectors, each transport behind each type, ESP transport mode, several Routing headers and the fallbacks (alone, and after a Routing header that does resolve): each frame summed for the address the rules give passes, and the same frame summed for another fails, which for a resolved route is the wire address (the old rule) and for a fallback the address the route would have resolved to.
- **The nightly mutation run works again, on mutmut 3.8.1.** It had two independent breaks. Dependabot's bump of `pytest` to 9.2.0 (#261) removed `Item._nodeid`, which mutmut 3.8.0's pytest plugin read after every test, so the stats phase died on its first test with `AttributeError: 'Function' object has no attribute '_nodeid'`; mutmut 3.8.1 reads `item.nodeid`, `uv.lock` now pins it, and the `dev` group's floor is `mutmut>=3.8.1`, since 3.8.0 cannot run with the locked `pytest`. Behind that, the new checker tests in `tests/test_checksum.py` (#263) load `scripts/check_fixtures.py` by a path relative to the test file, and mutmut runs the tests from a `mutants/` copy that held no `scripts/`, so they failed with `FileNotFoundError`; `[tool.mutmut]` now lists `scripts` in `also_copy` (the directory: mutmut 3.8.1 copies a file entry without creating its parent directory). A local run of the workflow's command checked 2481 mutants and found no survivor beyond the two in `scripts/mutmut_survivors.txt`.

## [2.6.0] - 2026-10-28

### Added

- **`MPLS`: the MPLS label stack (RFC 3032 §2.1, #187).** EtherTypes 0x8847 (`EtherType.MPLS`, "MPLS") and 0x8848 (`EtherType.MPLS_UPSTREAM_ASSIGNED`, "MPLS with upstream-assigned label": IANA's names; RFC 5332 §4 retired 0x8848's original "multicast" meaning) now dispatch to `netprotocols.MPLS` (also `netprotocols.layer2.MPLS`), from Ethernet, VLAN tags and GRE alike, so MPLS in GRE (RFC 4023) needs no code of its own. One `MPLS` layer holds the whole stack, top first, as `labels`, a tuple of `MPLSLabel` entries (`label`, `traffic_class` — RFC 5462's name for RFC 3032's Exp field — `bottom_of_stack` and `ttl`, with `word`, `bytes()`, `is_special_purpose`, and `label_name`, the base special-purpose labels named as IANA's registry names them); `bottom` is the last entry. `decode()` reads entries until the first with the S bit set, so the stack bounds itself and `bytes(MPLS.decode(x)) == x[:header_len]`; what follows, Ethernet padding and FCS included, is the labelled packet's. A stack whose S bit never comes raises `TruncatedHeaderError` (`field="labels"`, `offset` where the missing entry would start), in time linear in the buffer, and a deep stack counts once against `max_depth`. Construction requires a non-empty stack with S set on the last entry alone, so every stack that can be built round-trips. MPLS names no payload protocol, so `next_protocol()` follows a documented convention: a bottom label of 0 or 2 (IPv4 or IPv6 Explicit NULL) names IPv4 or IPv6, 13 (GAL) and 14 (OAM Alert) stop the walk, and otherwise the first nibble after the stack is read as an IP version, 4 or 6 (RFC 4928 §2), so a pseudowire control word or associated channel header (first nibble 0 or 1, RFC 4385) stops it. The class comes from the `ethertype` table at 0x0800 or 0x86DD, so `registry` and `decode_as` overrides reach the labelled packet; `payload_ethertype` says which the convention chose. `next_protocol()` is handed no bytes, so `decode()` records the nibble on the instance outside its comparison and hash, as `BGP` records whether another message follows; a stack built rather than decoded answers from its bottom label alone. The guess fails, as RFC 4928 describes, on an Ethernet pseudowire sent without a control word whose inner destination MAC begins with nibble 4 or 6, which decodes as an IP header; the module docstring says how to walk such a payload explicitly. Since 0x8847 and 0x8848 are now built in, code that registered a different class at either on the default registry (as the `register()` examples in 2.5.0's `registry.py`, README.md, ARCHITECTURE.md and `docs/CLAIMS.md` did), or on one built from it with `Registry.from_defaults()` or `derive()`, now raises `RegistryConflictError`; pass `override=True` to replace `MPLS`, or `decode_as={"ethertype": {0x8847: ..., 0x8848: ...}}` (each key you used) to override it for one walk.
- **`LLDP`: the Link Layer Discovery Protocol (IEEE 802.1AB), layer 2 (#186).** EtherType 0x88CC (`EtherType.LLDP`, "LLDP") now dispatches to `netprotocols.LLDP` (also `netprotocols.layer2.LLDP`) from Ethernet and from a VLAN tag, and the walk ends there. An LLDPDU is a run of TLVs, each a 16-bit header word (a 7-bit Type, a 9-bit Length) and Length bytes of value; `LLDP.tlvs` keeps every one, in wire order, as an `LLDPTLV(type, value)` with `length` and `type_name` (Wireshark's names for types 0-8 and 127, "unknown (n)" for the reserved 9-126), through the End of LLDPDU TLV, so `bytes(LLDP.decode(x)) == x[:header_len]` holds by construction. The End TLV bounds the LLDPDU: Ethernet padding, an FCS or anything else after it is left undecoded. An LLDPDU that reaches the end of the buffer without one decodes too, since 802.1AB-2016 made the End TLV optional, as Wireshark's dissector notes (lldpd 1.0.18's receiver still discards one); without an End TLV a trailer is read as TLVs: two or more zero bytes read as an End TLV, and anything else as another TLV or a framing error. `decode` checks framing only: a buffer shorter than one TLV header raises `TruncatedHeaderError` as any too-short header does (offset 0, no `field`), a later TLV header cut short or a TLV whose Length runs past the buffer raises it with `field="tlvs"` and the TLV's offset, and an End TLV with a nonzero Length raises `InvalidFieldError`. The mandatory order is reported, not enforced: `chassis_id` (`LLDPChassisID`) and `port_id` (`LLDPPortID`), each a `subtype` and the raw `id` with `subtype_name`, and `ttl` (an `int`, its first two bytes) read the first, second and third TLV and are `None` when that TLV is of another type, an ID's value is not 2 to 256 bytes or the TTL's is shorter than 2 bytes, so none raises; `has_mandatory_tlvs` says whether all three are there (any subtype passes), `is_shutdown` whether the TTL is 0, and `tlv(type)` finds the first TLV of a type. Subtype numbers follow the IEEE 802.1 LLDP MIBs and the display names Wireshark's dissector. Every other TLV, organizationally specific ones included, keeps its value raw. The walk is local to `layer2/lldp.py`; `_tlv.walk_kind_length_value`, which TCP, IPv4, IPv6 and PIM share, is unchanged. EtherType 0x88CC no longer serves the tests and README as the example of an unknown EtherType; 0x88B5, IEEE 802's Local Experimental EtherType 1, does.
- **`LLC` and `SNAP`: IEEE 802.2 LLC and SNAP headers after an IEEE 802.3 Length (#188).** An Ethernet or VLAN type/length field of 1500 or less is a frame Length (IEEE 802.3 Clause 3.2.6), and `next_protocol()` now answers `netprotocols.LLC` (also `netprotocols.layer2`) for it: DSAP, SSAP and a 1-octet (U-format) or 2-octet (I- and S-format) Control, stored with its first octet as the integer's low byte so the format bits are its two low bits. I-format and UI PDUs dispatch on the DSAP through the new `llc.dsap` table (`registry.TABLE_LLC_DSAP`), at DSAP 0x42 only when the two octets after the Control are 0x0000, or fewer than two octets follow (next entry); other formats, such as XID and TEST, end the walk. Accessors: `control_format`, `is_group`, `is_response`, `is_raw_ipx`, `dsap_name`, `ssap_name`, `dsap_enum`. The new `LLCSAP` enum holds the IEEE Registration Authority's assigned LSAPs and the global DSAP, with display names. `SNAP` (OUI and PID, RFC 1042) is a built-in `llc.dsap` entry, at 0xAA, reached only when the SSAP is 0xAA too and the Control is UI; `STP`, at 0x42, is the other (next entry). Under OUI 00-00-00 (RFC 1042) or 00-00-F8 (IEEE 802.1H bridge-tunnel) the PID is an EtherType and dispatches through `ethertype`; under any other OUI it goes through the new `llc.snap` table (`registry.TABLE_LLC_SNAP`), keyed `(oui << 16) | pid` (`SNAP.snap_key`). This departs from #188, which recommended reading every PID in `ethertype`: RFC 9542 §3 makes the PID a number the OUI's owner assigns, so CDP (OUI 00-00-0C, PID 0x2000) is not EtherType 0x2000. A Novell raw 802.3 frame (0xFFFF where the SAPs would be: an IPX checksum) decodes as an `LLC` layer with `is_raw_ipx` set and ends the walk; that layer's other fields and accessors then read IPX bytes and are meaningless (the fixture's frame reads as an I-format Control 0x1E00, the IPX length). STP (DSAP 0x42) decodes as `STP` (next entry), and CDP as `CDP` (the entry after it).
- **`STP`: Spanning Tree BPDUs, IEEE 802.1D and 802.1w (RSTP) (#189).** LLC DSAP 0x42 (`LLCSAP.SPANNING_TREE`) now dispatches, for a UI or I-format PDU, to `netprotocols.STP` (also `netprotocols.layer2.STP`), the walk's last layer, unless the two octets after the Control are present and not 0x0000: GARP's PDUs, such as GVRP's, share the SAP with Protocol Identifier 0x0001 (IEEE P802.1aq/D1.5++ §14.5 NOTE 1 leaves other Protocol Identifiers to other protocols), and their walk ends at `LLC`, whatever class `llc.dsap` holds at 0x42. `LLC.decode()` records that check on the instance outside its comparison and hash, so equal LLC headers still compare and hash equal; a header built with the constructor or `dataclasses.replace()` has seen no bytes and dispatches. Fewer than two octets still reach `STP`, which reports the truncation. One class decodes the three BPDU Types and branches on the type, as ICMP does: the Configuration BPDU (type 0x00, 35 octets, 802.1D-2004 §9.3.1), the RST BPDU (0x02, 36 octets, §9.3.3: the same fields and a Version 1 Length) and the Topology Change Notification (0x80, §9.3.2), which is the 4-octet prefix alone and decodes as the short form of the class, every field after `bpdu_type` `None`. Fields: `protocol_id`, `version`, `bpdu_type`, then `flags`, `root_priority`, `root_mac`, `root_path_cost`, `bridge_priority`, `bridge_mac`, `port_id`, `message_age`, `max_age`, `hello_time`, `forward_delay` (the timers raw, in 1/256 s) and `version_1_length` (RST only). The flag accessors answer `None` in a type that leaves their bit unused: `topology_change` (Configuration and RST), `topology_change_ack` (Configuration only), and `proposal`, `port_role`/`port_role_name`, `learning`, `forwarding` and `agreement` (RST only); the raw octet stays in `flags`. The two priority octets of a Bridge Identifier are kept whole (802.1D-1998 made all 16 bits a priority) and split as 802.1t does by `root_priority_component`/`root_system_id_extension` and `bridge_priority_component`/`bridge_system_id_extension`; also `root_id_str`/`bridge_id_str` (Wireshark's priority/extension/MAC form), `port_priority`/`port_number`, `*_seconds` for the four timers, `bpdu_type_name` and `version_name`. The flag bits, port role values and field layout follow the unapproved IEEE 802.1 draft "P802.1aq/D1.5++suggested changes, May 16, 2009" (`aq-seaman-merged-bpdu-encoding-0509.pdf`, whose Clause 14 merges 802.1D Clause 9 with 802.1Q-2005 Clause 14), except that its §14.4 o) mislabels octets 34-35 as Max Age: they carry Forward Delay, as in Wireshark's `packet-bpdu.c` and Linux's `br_stp_bpdu.c`. The type and version names and port role names 1-3 are Wireshark's (`packet-bpdu.c`, fetched 2026-10-25); role 0, which Wireshark does not name, is `Unknown`, 802.1D-2004's name for it (802.1Q calls it Master; the draft's §14.2.9 NOTE). `header_len` is exactly the type's length: Ethernet padding and an FCS never reach the decoder in a walk (the 802.3 Length bounds the PDU), a direct `decode()` leaves them undecoded, and the octets of a PDU longer than its BPDU, which a receiver ignores (§14.4 and §14.6 i)3) of that draft), stay after the layer. Cisco PVST+'s SSTP BPDUs, the ones that carry TLVs, travel in SNAP under OUI 00-00-0C, PID 0x010B, not at DSAP 0x42 (Wireshark parses their TLVs only there), and walk as far as `SNAP`; an `llc.snap` entry at `(0x00000C << 16) | 0x010B` would reach `STP` from there. PVST+'s VLAN 1 BPDUs go untagged to the IEEE address, at DSAP 0x42, and decode as `STP` (Cisco does not say they carry a TLV; Wireshark parses PVST+ TLVs only under PID 0x010B) (Cisco document 24063, "Troubleshoot Spanning Tree PVID- and Type-Inconsistencies"; the full URL is in `layer2/stp.py`'s module docstring). A Protocol Identifier other than 0 (on a direct `STP.decode()`; a walk from LLC DSAP 0x42 does not reach it) and a BPDU Type other than the three raise `InvalidFieldError` (`field="protocol_id"`, offset 0, or `field="bpdu_type"`, offset 3), since neither leaves a layout to read; a buffer shorter than its type needs raises `TruncatedHeaderError` (`field="bpdu_type"`). The version, unused flag bits and a nonzero Version 1 Length are carried verbatim, and a type 0x02 BPDU is laid out as RST whatever its version. **MSTP is out of scope**: an MST BPDU (802.1s/802.1Q, version 3) decodes as its 36-octet RST prefix, and its Version 3 Length, MST configuration and MSTI messages are left undecoded after the layer, as a version 2 implementation reads them (§14.6 i), and §14.5 d) and e), of the draft). In a walk the 802.3 Length already ends the PDU, but kept raw in the layer they would need an end on a direct `decode()` too, where only the Version 3 Length could give one, and that field is unreliable on the wire (Wireshark's `packet-bpdu.c` notes a Cisco C3550 release that appears to send it in MSTI-message units, and MST BPDUs that carry a Version 3 Length of 0 and put the length in the format selector octet): read to the end of the buffer instead, they would take in padding and an FCS. In a walk a caller recovers them with `frame[packet.consumed : 14 + packet[Ethernet].length]` (behind one VLAN tag, `18 + packet[VLAN].length`). The real BPDUs are the corpus's 802.1D ones; RST BPDUs are tested with constructed frames only, since neither the kernel bridge nor any installable package here speaks RSTP.
- **`CDP`: the Cisco Discovery Protocol, versions 1 and 2 (#190).** SNAP OUI 00-00-0C PID 0x2000 now dispatches through `llc.snap` to `netprotocols.CDP` (also `netprotocols.layer2`), which decodes the 4-byte header (`version`, `ttl`, `checksum`) and the TLVs after it as `CDPTLV(type, value)`, each a 2-byte Type and a 2-byte Length that counts the 4-byte TLV header, kept raw in wire order with `type_name` from Wireshark's packet-cdp.c (commit 31bf0857, fetched 2026-10-25), so `bytes(CDP.decode(x)) == x[:header_len]`. Any Version decodes, since the SNAP header says outright that CDP follows. Accessors read the first TLV of their type and return `None` when it is missing or malformed: `device_id`, `port_id`, `software_version`, `platform` (ASCII, a byte outside it as a backslash escape), `capabilities` (the 32-bit mask) and `capability_names`, and `addresses` and `management_addresses` (type 22), lists of `CDPAddress` (protocol type, protocol, address, with `ip` for NLPID 0xCC IPv4 and the 802.2 form of EtherType 0x86DD IPv6), plus `tlv(type)`. CDP has no PDU length: in a walk the 802.3 Length bounds it, so padding and an FCS stay out. `decode` stops early without raising only where every byte left is zero, so zero padding is left undecoded when it is called directly; otherwise a TLV Length below 4 raises `InvalidFieldError` and 1-3 bytes left after the last TLV raise `TruncatedHeaderError`, in a walk too (both `field="tlvs"`, at the offset where the TLV would start), as does a TLV that runs past the buffer. Zeros after the last TLV but inside the 802.3 Length are part of the declared PDU, yet a walk leaves them undecoded without raising: `consumed` stopping short of the Length's end is the only structural signal, `verify()` (which sums the bytes decoded) fails on them only where the TLVs end at an odd offset on a nonzero byte and the sender summed the whole Length, and `scripts/check_fixtures.py` rejects such a frame. Wireshark's packet-cdp.c differs: it stops at a Length below 4 whatever follows, and marks 1-3 bytes left malformed even when they are zero. A nonzero trailer that happens to read as whole TLVs (a 4-byte FCS ending in 0x0004) decodes as phantom TLVs; there `verify()` is the check that the bytes decoded are the PDU the sender summed. Wireshark's Port ID length heuristic is not reproduced. The walk ends at CDP.
- **CDP checksums in `compute`/`verify`/`Packet.with_checksums()`.** The internet checksum of the whole PDU, checksum field zeroed, no pseudo-header (`ip` and `payload` ignored), except that an odd final byte `v` is added as the low byte of a last word below 0x80 and as `0xFF00 + v - 1` from 0x80, as lldpd 1.0.18's `frame_checksum()` and Wireshark's packet-cdp.c sum it; `internet_checksum()` alone gives the wrong value for an odd-length PDU whose final byte is not 0x00 (there the two coincide). `with_checksums()` fills it as it fills IPv4's.
- **`Ethernet.is_length`/`Ethernet.length` and `VLAN.is_length`/`VLAN.length`**: whether the raw `ethertype` field holds an 802.3 Length, and the Length or `None`. The field itself is unchanged in type and meaning.

### Changed

- **Ethernet and VLAN dispatch branch on type versus length.** A value of 0x0600 or more dispatches through `ethertype` exactly as before; 1500 or less answers `LLC` (it used to look the value up in `ethertype`, which accepted a key there: registering one, such as 0x0026, a Configuration BPDU's Length, was the only way to decode STP; see the Behaviour change entry below); 1501-1535, which IEEE 802.3 leaves undefined, answers `None`. GRE's Protocol Type and a SNAP PID are EtherTypes only and keep the plain lookup. No frame in the 2.5.0 corpus has a type/length value below 0x0600, and every one of them decodes exactly as before.
- **`decode_frame()` ends every later layer's buffer at the end of the LLC PDU an 802.3 Length gives**, so Ethernet zero padding and an FCS after a short PDU reach no decoder and stay past `packet.consumed`. A Length past the end of the frame bounds nothing (a frame a snap length cut decodes what was captured), a tighter bound is never widened by a later one, and a Length shorter than the 3-byte LLC header makes `LLC.decode()` raise `TruncatedHeaderError`. It is the only enclosing length the walk honours; IPv4's, IPv6's and UDP's are not (#235). The hook is private (`Protocol._BOUNDS_PAYLOAD`, `_payload_extent()`) while #235 settles a public form.
- **Behaviour change: an `ethertype` entry at 1500 or less is no longer reached from Ethernet or VLAN.** The table accepts any key, as in 2.5.0, but Ethernet and VLAN no longer look a type/length value of 1500 or less up there: they answer `LLC` for it, and nothing for 1501-1535 (see the entry above). So a class registered at, say, 0x0026 to decode STP over raw Ethernet is no longer reached from an Ethernet frame. GRE still looks any value up in `ethertype`, so such an entry still answers GRE Protocol Type 0x0026, as in 2.5.0, and the new `SNAP` looks a PID under OUI 00-00-00 or 00-00-F8 up there too, so it now also answers an RFC 1042 or 802.1H SNAP PID of 0x0026. RFC 1701's "Current List of Protocol Types" assigns GRE three values below 0x0600, SNA 0x0004, OSI network layer 0x00FE and PUP 0x0200, and an entry at 0x00FE is reached from GRE Protocol Type 0x00FE exactly as before. This dispatch change is inherent to #188's type/length reading. To migrate a raw-Ethernet decoder, register it in `llc.dsap` under its DSAP or, for a SNAP protocol, in `llc.snap` under `(oui << 16) | pid`. STP needs no migration: the built-in `STP` now holds DSAP 0x42, the one key that covers what 2.5.0 needed one key per 802.3 Length for (0x0026 for a Configuration BPDU, 0x0007 for a Topology Change Notification, 0x0027 for an RST BPDU, and more for MST BPDUs, whose Length varies); a decoder of one's own goes there with `override=True`, or in a registry of its own (`Registry.from_defaults().derive(...)`, or `decode_frame(decode_as=...)`), and is handed, like `STP`, only a PDU whose first two octets are 0x0000, or that holds fewer than two, never GARP's. The decoder is handed different bytes: in 2.5.0 it got everything from the LLC header to the end of the frame, padding and FCS included, and from `llc.dsap` it gets the PDU after the LLC header (from `llc.snap`, after the SNAP header), ending where the 802.3 Length does, so a migrated decoder must parse from there. The two new tables refuse a key their field cannot carry, `llc.dsap` one outside 0-0xFF and `llc.snap` one outside 0 to 2**40 - 1, raising the new `InvalidRegistryKeyError` (a `ProtocolError`, exported from `netprotocols` and `netprotocols.registry`) from `register()`, `register_all()`, `Registry.derive()` and `decode_frame(decode_as=...)` (whatever `lax` says). `register_all()` is not atomic, for this error as for a `RegistryConflictError`: the keys before the one that raises stay registered. Every other table, `ethertype` included, accepts any key, as before.

### Development

- **Every comparative number the README quotes was re-measured for this release** (Rule 4 of `docs/CLAIMS.md`), on the same machine class as 2.5.0's figures but on the 293-frame corpus Tier 3 grew from 265 (30 scenarios, from 27), against `dpkt 1.9.8` and `scapy 2.8.0`. The headline ratios held: dpkt decodes the corpus 1.33× faster (1.28-1.34× over three runs) and netprotocols stays 3.4× ahead of scapy. **The README's sub-claim that the 140 frames of 2.4.0's corpus "are still within 10%" of dpkt no longer holds and is replaced**: over sixteen alternating runs of a file-by-file harness, dpkt leads on them by a median 1.14× on this tree against 1.07× on 2.5.0's. Whether Tier 3's type-versus-length dispatch and payload bound cost the old frames anything is not resolved: netprotocols' median over the 265 frames both trees share is 3.3% lower than 2.5.0's (lower in 12 of 16 alternating pairs, with dpkt's own median flat), inside this machine's run-to-run spread of about ±8%, and it was not profiled ([#250](https://github.com/EONRaider/NETProtocols/issues/250)). On the new MPLS and LLC/SNAP captures the two libraries are level; dpkt does not decode LLDP, so it is about 5× faster on those six frames. Encode is 4.66× ahead of dpkt, import 89.8 ms (from 70.0 ms; the five new modules cost about 15 ms against the 2.5.0 tree run alternately on the same machine) against `scapy.all`'s 436.2 ms, and the wheel is 220.5 KiB, 12.2× smaller than scapy 2.8.0's 2.63 MiB. Decode depth against dpkt is 94 of 293 frames deeper; of the 15 new, 7 are frames dpkt leaves raw (the six LLDP frames and a VLAN-tagged 802.3 SNAP frame), and 8 are MPLS and SNAP frames on which netprotocols makes the label stack or the SNAP header a layer of its own where dpkt folds it into `Ethernet` or `LLC`; STP and CDP are decoded by dpkt too. dpkt cannot decode one frame, the 4-byte STP Topology Change Notification (`NeedData`), so `--depth` skips it and every comparison reports dpkt at 292/293. `docs/CLAIMS.md` records each run, the per-file table, the A/B and the frame-by-frame depth breakdown.
- **`scripts/check_fixtures.py` checks RST BPDUs and a Configuration BPDU's flags (#189).** Its independent `_check_bpdu` now knows the RST BPDU (type 0x02, 36 octets, a Protocol Version of 2 or more, which a receiver's validation requires) and counts each type (`stp-config`, `stp-rst`, `stp-tcn`). Its BPDU check covers only the DSAP 0x42 PDUs the library dispatches, UI (either P/F) and I-format; any other Control there (XID, TEST, S-format) is counted (`llc-dsap-0x42-control-0xaf`, say) and not checked. A UI or I-format PDU whose Protocol Identifier is not 0, such as GARP's, is counted (`llc-dsap-0x42-protocol-0x0001`) and not checked rather than failed as a malformed BPDU, and an I-format PDU's BPDU is read after its 2-octet Control, as the library reads it. It also holds each BPDU to what its sender must transmit, which a receiver ignores or tolerates: the Flags bits its type leaves unused 0 (six in a Configuration BPDU, bit 8 in an RST BPDU) and an RST BPDU's Version 1 Length 0. The `llc.pcap` BPDUs now decode to `STP`, and the corpus coverage test requires it; no frame is added, so the corpus counts are unchanged.
- **The three CDP frames of `llc.pcap` now decode to `CDP`**: the corpus coverage set, the corpus checksum cases (`tests/test_checksum.py`, in the mutation audit's selection) and the fuzz suites (`ALL_PROTOCOLS`, a round-trip strategy, accessor and trailer properties) cover it. No frame was added. `scripts/check_fixtures.py` keeps its own CDP check, which shares no code with the library.
- **An IEEE 802.3 LLC/SNAP capture joins the corpus: `llc.pcap`, 14 frames (293 across 30 scenarios).** `scripts/capture_fixtures_llc.sh` runs two Linux bridges with STP on in two netns and lldpd 1.0.18 in its own UTS namespace, and captures on a bridge port: five kernel-built 802.1D BPDUs (both bridges' Configuration BPDUs, the root's with TC and with TC + TCA, a 21-byte TCN), CDPv1 and CDPv2 from lldpd (and a CDPv1 frame whose odd-length PDU ends in 0xA9: CDP's checksum adds a final byte from 0x80 as 0xFF00 plus the byte less 1, as lldpd's `frame_checksum()` and Wireshark's packet-cdp.c do, and the frame shows it is not padded as RFC 1071 pads it and that the `- 1` matters; only a test, `test_cdp_odd_byte_is_lldpds_form`, tells that form from adding the byte less 0x100), and six frames the new stdlib-only `scripts/llc_fixture_frames.py` builds and sends through `AF_PACKET` (RFC 1042 ARP padded to 60 bytes and ICMP-in-IPv4, 802.1H ARP, RFC 1042 ARP behind an 802.1Q tag, Novell raw 802.3 IPX, and a type/length value of 1501). It keeps the first frame of each kind and asserts the composition exactly. `scripts/check_fixtures.py` now reads the type/length field as IEEE 802.3 does, after VLAN tags too, holds each Length against its frame (only zero padding may follow a PDU shorter than 46 bytes), checks the LLC Control width, SNAP framing, BPDU and raw IPX lengths, walks the CDP TLVs and verifies the CDP checksum over exactly the PDU, and checks an RFC 1042 or 802.1H payload as its EtherType, IPv4 and ICMP checksums included.
- **A real LLDP capture joins the corpus: `lldp.pcap`, 6 frames (279 across 29 scenarios).** `scripts/capture_fixtures_lldp.sh` runs two lldpd 1.0.18 agents, LLDP only, in two netns over a veth pair, each configured from its own file before its first LLDPDU: A with its MAC address as Chassis ID, its interface name as Port ID and a 304-byte custom organizationally specific TLV (which needs the 9th Length bit), B with a locally assigned Chassis ID, its MAC address as Port ID and a TTL of 180. It then changes A's Port ID to a locally assigned value at run time, which makes lldpd send a shutdown LLDPDU for the old one, and stops both agents, which send one each. It keeps the first LLDPDU of each kind (sender, Port ID subtype, shutdown or not) and asserts the six exactly: their Chassis ID, Port ID, TTL and TLV type sequence. `scripts/check_fixtures.py` checks LLDPDUs structurally, since LLDP has no checksum: the TLVs must walk to an empty End TLV with only zero bytes after it, the first three must be a well-formed Chassis ID, Port ID and 2-byte TTL that do not recur, and a shutdown LLDPDU must carry nothing else; its ARP and fallback arms move into a `_check_non_ip` helper so `_check_l3` does not grow. `tests/test_lldp.py` holds the checker to failing tampered copies. `LLDP` joins the fuzz suite (`ALL_PROTOCOLS`, a round-trip strategy, an accessor-safety property fed LLDP-shaped buffers, and a padding and trailer property), the truncation and lying-length contract tests and the corpus coverage set; a decode-cost test counts the bytes a 10,000-TLV LLDPDU's walk reads by slicing or copying it whole, and another, with `tracemalloc`, checks that decoding a 1,000-TLV LLDPDU followed by a megabyte after its End TLV, as `bytes` and as a `memoryview`, peaks under half a megabyte of allocation, which a copy of the rest of the buffer at any TLV, over a megabyte, would exceed. Neither bounds per-TLV quadratic work that leaves no large allocation behind, such as rebuilding the TLV list at every TLV.
- **A captured MPLS fixture joins the corpus: `mpls.pcap`, 8 frames (273 across 28 scenarios).** The capture host's kernel has `CONFIG_MPLS_ROUTING` off, so `scripts/capture_fixtures_mpls.sh` has the kernel send two ICMP echo requests and two UDP datagrams over a veth pair between two netns, offload off, captures them inbound, and then `scripts/mpls_fixture_packets.py` (stdlib only) wraps those datagrams in script-built Ethernet headers and label stacks and sends them through an `AF_PACKET` socket: one label, two labels, three labels with distinct traffic classes, an Entropy Label Indicator and entropy label, IPv4 and IPv6 Explicit NULL bottom labels (the IPv6 datagram script-built, since the host has IPv6 disabled; the IPv4 Explicit NULL frame zero padded to 60 bytes), EtherType 0x8848 to a multicast MAC, and an Ethernet pseudowire with a control word. The script reads the capture back and fails unless every byte arrived as built, and the capture script fails unless the capture holds exactly those eight frames. A second tcpdump captures the same frames with a 20-byte snap length as `tests/fixtures/mpls/mpls_snaplen.pcap`, outside the corpus globs like `bgp/bgp_session.pcap`, so truncation is tested on captured frames too: six stacks cut after their first entry, and two whole one-entry stacks whose IPv4 header is cut. `scripts/check_fixtures.py` walks each label stack to its bottom entry in its own code and verifies the labelled packet's checksums, IPv4 or IPv6 by the same convention, and the Ethernet frame after the pseudowire's control word; its ARP branch moved into a `_check_arp` helper beside the new `_check_mpls`, so `_check_l3` dispatches the two through a table and stays at radon B. `tests/test_mpls.py` holds the checker to failing a flipped byte in each frame's labelled packet. MPLS joins the fuzz suite (`ALL_PROTOCOLS`, a round-trip strategy, accessor-safety and trailer properties), the truncation and memoryview contract tests and the corpus coverage set.
- **The `register()` examples no longer use MPLS's EtherType.** `registry.py`, README.md, ARCHITECTURE.md and `docs/CLAIMS.md` §5.5 registered a hypothetical class at 0x8847 as "a protocol this library does not implement", which now raises `RegistryConflictError`; they, and `tests/test_registry.py`'s stand-ins, use 0x88B5 ("IEEE Std 802 - Local Experimental Ethertype" in IANA's registry) and a `Telemetry` class instead, and `tests/test_docs.py` runs each document's example, and the three in `registry.py`'s docstrings, to check each registers on a free key. README's "Why NETProtocols" now names the corpus its figures were measured on, which this release's re-measurement (the first Development entry) makes the 293 frames the corpus holds at 2.6.0.

## [2.5.0] - 2026-10-25

### Added

- **`VRRP` and `VRRPv6`: the Virtual Router Redundancy Protocol, VRRPv2 (RFC 3768) and VRRPv3 (RFC 5798) (#181).** IP protocol 112 (`IPProtocol.VRRP`, "VRRP") now dispatches to `netprotocols.VRRP` from IPv4 and to its subclass `VRRPv6` from IPv6 and its extension headers. One class decodes both versions and branches on the version nibble: the fixed fields `version`, `type`, `vrid`, `priority`, `count_ip_addrs` and `checksum`, the 16 bits between Count and Checksum kept raw as `adver_word` and read through per-version accessors that return `None` where the version has no such field (`auth_type`/`auth_type_name` and `adver_int` in seconds for VRRPv2; `reserved` and `max_adver_int` in centiseconds for VRRPv3; `advertisement_interval` in seconds for either), the virtual `addresses`, and VRRPv2's 8 bytes of `auth_data` (the null-padded password under Auth Type 1, keepalived's `auth_type PASS`). The address width depends on the IP family, not on anything in the header, which is why the class comes as a pair: `VRRP` reads 4-byte addresses and `VRRPv6` 16-byte ones, and `VRRPv6` accepts VRRPv3 only, since RFC 3768 defines VRRPv2 for IPv4 alone. VRRP has no length field, but the version and count give its exact length, which is `header_len`, so Ethernet padding and an FCS after the message are left undecoded and `bytes(VRRP.decode(x)) == x[:header_len]`. A version other than 2 or 3 raises `InvalidFieldError` (`field="version"`, `offset=0`), because the version decides the layout; an unknown type, a priority of 0 (a master resigning), a count of 0 and the reserved bits are carried verbatim. A count, or VRRPv2's authentication data, past the buffer raises `TruncatedHeaderError` (`field="count_ip_addrs"` or `"auth_data"`). Construction also checks `count_ip_addrs == len(addresses)`, the authentication data's length against the version (8 bytes or none), and that `type` fits its nibble. The walk ends at VRRP. Registering over protocol 112 in `ip.proto` reaches IPv4 only, as for AH's 51; `_defaults.FAMILY_SPECIFIC_NUMBERS` now names both.
- **VRRP checksums in `compute`/`verify`/`Packet.with_checksums()`.** The internet checksum of the whole message with the checksum field zeroed: alone for VRRPv2 (RFC 3768 §5.3.8, `ip` not needed), behind the IP pseudo-header with protocol 112 for VRRPv3 over IPv4 and IPv6 (`ip` required). `payload` is ignored, as for IGMP. Over IPv6 that is RFC 5798 §5.2.8's rule; over IPv4, §5.2.8 cites only RFC 2460's pseudo-header, which is IPv6's, and the IPv4 one is what keepalived 2.2.8 sends by default. RFC 9568 §5.2.8, which obsoletes RFC 5798, leaves the pseudo-header out over IPv4, as keepalived's `v3_checksum_as_v2` option does, and `verify()` returns `False` for such an advert.
- **`RIP`: the Routing Information Protocol, versions 1 and 2 (RFC 1058, RFC 2453, #182).** UDP port 520 dispatches, best-effort like every port entry, to the new `netprotocols.RIP` (also `netprotocols.layer7.RIP`), which decodes the 4-byte header into `command`, `version` and `reserved` (bytes 2-3: must be zero in RFC 1058 and RFC 2453, RFC 1388's Routing Domain) and keeps everything after it as raw `body`, so `bytes(RIP.decode(x)) == x`. `entries` parses the 20-byte entries on demand: a route is a `RIPEntry` (`afi`, `route_tag`, `address`, `subnet_mask`, `next_hop`, `metric`; RIPv1 zeroes the v2-only fields, which are kept verbatim either way), and an entry with AFI 0xFFFF is a `RIPAuthentication` (`auth_type`, the raw 16 `data` bytes, and `password` for type 2, or `packet_length`, `key_id`, `auth_data_len` and `sequence_number` for RFC 4822's type 3), never a route; `routes` and `authentication` select them. RIP has no length field and the walk does not trim to UDP's (#235), so the entries end at the RFC 4822 authentication trailer, which the first entry's Packet Length locates when the bytes there start with the trailer's `0xFFFF 0x0001` (`authentication_trailer`, raw, to the end of the body: Auth Data Len does not size it, since BIRD declares 20 for a 16-byte MD5 digest and 32 for a 32-byte HMAC-SHA-256 one), or at the last whole entry, with anything shorter than an entry after it — an entry cut by a snap length, or an Ethernet FCS — in `remainder`; past the header neither decode nor any accessor raises. Against a wrong port guess, `decode()` rejects a version other than 1 or 2 and command 0 (`InvalidFieldError`), which 99.2% of random datagrams fail; construction accepts them. The other commands, TraceOn to Update Acknowledge (`command_name`, with IANA's names), and RIPv1 messages with nonzero must-be-zero fields decode. RIPng (RFC 2080, UDP 521, the IPv6 protocol) is not decoded; RIP itself has no IPv6 form.
- **`OSPF`: OSPFv2 (RFC 2328), IP protocol 89 (#183).** IPv4 protocol 89 (`IPProtocol.OSPF`, "OSPF") now dispatches to `netprotocols.OSPF` (also `netprotocols.layer3.OSPF`), which decodes the 24-byte common header — `version`, `type`, `packet_length`, `router_id`, `area_id`, `checksum`, `instance_id` and `au_type` (one byte each: RFC 6549 §2 split RFC 2328's 16-bit AuType into an Instance ID and an 8-bit AuType), the raw 8-byte `authentication` — and keeps the message as raw `body`, so `bytes(OSPF.decode(x)) == x[:header_len]` by construction. One accessor per message type parses the body on demand and returns `None` for the other types: `hello` (`OSPFHello`: network mask, hello and dead intervals, options, priority, DR, BDR and the neighbor list), `database_description` (`OSPFDatabaseDescription`: interface MTU, options, the I/M/MS flags, DD sequence number and its `OSPFLSAHeader`s), `ls_requests` (`OSPFLSRequest`s), `lsas` (a Link State Update's `OSPFLSA`s, each a decoded 20-byte `OSPFLSAHeader` and a raw `body`) and `ls_acknowledgments` (`OSPFLSAHeader`s). **LSA bodies are not decoded**: the Router, Network, Summary and AS-external (and other) LSA contents stay raw `bytes`, as follow-up work. `decode()` and the constructor check each known message's framing (whole neighbors, LSA headers and requests; an update's LSA count and lengths walking its body exactly), raising `InvalidFieldError` with `field="body"` otherwise, so no accessor raises; a type outside 1-5 keeps its body as is. Packet Length bounds the packet: below 24 raises `InvalidFieldError`, past the buffer `TruncatedHeaderError`. Under cryptographic authentication (AuType 2) the digest after the packet, Auth Data Len bytes, is kept in `auth_trailer` and counted in `header_len`, with `key_id`, `auth_data_len` and `crypto_sequence_number` accessors; AuType 3 (RFC 7474, extended sequence numbers) is framed the same way, its trailer the 64-bit sequence number and the digest, which Auth Data Len counts together, and the same accessors read its 32-bit Key ID and 64-bit sequence number; nothing else after the packet is consumed, so an RFC 5613 LLS block, Ethernet padding or an FCS is left after the OSPF layer. Records have `__bytes__`, so a packet can be built from them, and display helpers (`type_name`, `au_type_name`, `options_str`, `flags_str`, `ls_type_name`, hex strings). Only version 2 decodes: OSPFv3 (RFC 5340), which IPv6 carries under the same number, is not implemented, so `ip.proto.v6` withholds protocol 89 (`_defaults.IPV4_ONLY_NUMBERS`) and an IPv6 packet with next header 89 still ends its walk at the IPv6 header; `OSPF.decode()` rejects version 3 with `InvalidFieldError` (`field="version"`) for a caller who sends it there anyway. The registry gains the private mechanism for that: a withheld key owns no class, inheritance skips it as it skips an override, `derive()` copies it, and a registration made directly in the child table fills it.
- **OSPF checksums in `netprotocols.checksum` (the new functions are also exported from `netprotocols`).** `compute(ospf)` is the internet checksum of the packet with its checksum field zeroed and its Authentication field left out (RFC 2328 §D.4.1), no pseudo-header (`ip` and `payload` are ignored); under cryptographic authentication (AuType 2 or 3), which computes none (§D.4.3; RFC 7474 §5 keeps that for AuType 3), `compute()` raises `InvalidFieldError`, `verify()` returns `True` (the digest, which this library cannot check without the key, protects the packet) and `Packet.with_checksums()` leaves the field alone. New `fletcher_checksum(data, offset)` computes the ISO 8473 Fletcher checksum field (RFC 905 Annex B), raising `ValueError` unless the 2-byte field at `offset` lies inside `data`. `lsa_checksum(lsa)` generates an `OSPFLSA`'s LS Checksum, over the LSA but its LS Age (RFC 2328 §12.1.7), and `verify_lsa(lsa)` checks it as RFC 905 B.4 does, by both running sums being zero, so a field stored with `0x00` where the generator writes `0xff` (equal modulo 255) verifies too, plus RFC 2328 §12.1.7's rule that the LS Checksum cannot be zero: a field of `0x0000` fails even where those sums are zero.
- **PIM-SM (#184): `netprotocols.PIM`, layer 3, RFC 7761.** IP protocol 103 (`IPProtocol.PIM`, "PIM") now dispatches from IPv4 and IPv6, extension headers included, to one `PIM` class for both families, which decodes the 4-byte common header (`version`, `type`, `reserved`, `checksum`) and keeps the rest as raw `body`, so `bytes(PIM.decode(x)) == x[:header_len]` holds by construction. `PIM.message` dispatches on `type`, through a parser table in the shape of IGMP's message types, to a typed message parsed on demand: `PIMHello` (type 0; its option TLVs as `PIMHelloOption(type, value)` with `type_name`, plus `holdtime`, `lan_prune_delay` (`PIMLANPruneDelay`), `dr_priority`, `generation_id` and `address_list` read from them), `PIMRegister` (1; the B and N bits and the encapsulated packet, which `encapsulated` decodes in a lax walk from its IP header), `PIMRegisterStop` (2), `PIMJoinPrune` (3, and Graft and Graft-Ack, 6 and 7, which share its format; `PIMGroupSet`s of joined and pruned sources) and `PIMAssert` (5). Bootstrap (4), Candidate-RP-Advertisement (8), State Refresh (9) and other types decode with their body raw, and `message` is `None` for them; `type_name` names types 0-12 (DF Election, ECMP Redirect and PIM Flooding Mechanism, 10-12, from the IANA registry). Encoded-Unicast, Encoded-Group and Encoded-Source addresses (§4.9.1) are `PIMEncodedUnicast`, `PIMEncodedGroup` (with `bidirectional`, `admin_scope`) and `PIMEncodedSource` (with `sparse`, `wildcard`, `rpt`), sized by their own address family, so an IPv6-encoded message decodes whatever IP family carries it; only native IPv4 and IPv6 encodings are supported, and any other family or encoding (RFC 5384's join-attribute Encoded-Source included) makes `message` raise `InvalidFieldError`. Every typed message, option and address has a `bytes()`, so a message can be built from them. PIM has no length field, and the walk does not trim to the IP length, so `decode` bounds the message by its own structure: Join/Prune, Graft, Graft-Ack, Register-Stop and Assert end where their counts and addresses say, leaving any trailer (Ethernet padding, an FCS) undecoded; a Hello's options are walked and a run of zero bytes where the next option would start is left undecoded as padding; a Register's data packet and the raw types' bodies run to the end of the buffer. Past the header `decode` never raises: a body its parser cannot read (cut short, an unknown address family, a nonzero trailer after a Hello that does not walk) is kept whole, for `message` to raise on. A version other than 2 raises `InvalidFieldError` (`field="version"`) from `decode` and the constructor.
- **PIM checksums in `compute`/`verify`/`Packet.with_checksums()`.** `compute(pim, ip=...)` is the internet checksum over the whole message, or over a Register's first 8 bytes (RFC 7761 §4.9.3), with the IPv6 pseudo-header (next header 103, the covered length) in front over IPv6 and none over IPv4; `ip` is required, since the family decides which. `verify()` also accepts a Register whose checksum covers the whole message, which §4.9.3 says should be accepted "for interoperability reasons"; `with_checksums()` fills PIM layers like the transports, so it rewrites such a Register to the 8-byte form.
- **`BGP`: BGP-4 messages (RFC 4271) over TCP port 179 (#185).** TCP port 179 now dispatches, best-effort like every port entry, to `netprotocols.BGP` (also `netprotocols.layer7.BGP`), one message per instance: the 19-byte common header as `marker`, `length` and `type`, and the body kept raw in `body`, so `bytes(BGP.decode(x)) == x[:header_len]`, where `header_len` is the message's Length, not the buffer. Decode applies RFC 4271 §6.1's header checks — an all-ones Marker, a Type of 1-5 (OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH) and that type's Length bounds (KEEPALIVE exactly 19, OPEN 29-4096, UPDATE and ROUTE-REFRESH from 23 and NOTIFICATION from 21, up to the 65535 of RFC 8654's extended messages) — and raises `TruncatedHeaderError` for a message the buffer cuts short. Accessors parse the body on demand and return `None` for other types: `version`, `my_as`, `hold_time`, `bgp_identifier`, `optional_parameters` (`BGPOptionalParameter`, either the RFC 4271 encoding or RFC 9072's extended one, flagged by `extended_optional_parameters` and recorded on each parameter as `extended_length`, which sets the width of the Parameter Length `bytes(parameter)` writes and is part of its equality; Capabilities named, its value raw) for OPEN; `withdrawn_routes` and `nlri` (`BGPPrefix`, IPv4, bit lengths up to 32) and `path_attributes` (`BGPPathAttribute`: flags, type code and raw `data`, the Attribute Length one or two bytes by the Extended Length flag; ORIGIN, NEXT_HOP, MULTI_EXIT_DISC and LOCAL_PREF values decoded in `value`, and every permanent type code in the IANA BGP Path Attributes registry named, its value kept raw) for UPDATE; `error_code`, `error_subcode`, `error_data`, their names as the IANA BGP Parameters registry (fetched 2026-10-25) assigns them (error codes 0-9 and the subcodes of every code with a subcode registry, RFC 4271 §4.5's "Unspecific" 0 for the codes without one), and an RFC 9003 `shutdown_communication` (strict UTF-8, `None` when absent or invalid) for NOTIFICATION. A malformed body raises `InvalidFieldError` from its accessor, not from decode. ROUTE-REFRESH's body stays raw. A TCP segment holding several messages decodes as one `BGP` layer each: `next_protocol()` answers `BGP` while another message begins in the same segment, which `decode()` records outside the instance's comparison and hash. A message the segment cuts raises `TruncatedHeaderError` (lax mode keeps the messages before it), a segment that starts inside one fails the Marker check, and reassembly stays the caller's, as for `HTTP`. Each message being a layer, a segment of more than 29 messages exceeds the default `max_depth`, so valid traffic can raise `MaxDepthExceededError` (or, lax, stop short): a 1448-byte segment holds up to 76 KEEPALIVEs or 30 one-prefix UPDATEs, and GRO, TSO, loopback and jumbo-frame captures carry larger segments. The module docstring, `walk.py`, ARCHITECTURE.md and `docs/CLAIMS.md` §5.7 document it and the two ways past it: a larger `max_depth`, or a second walk with `decode_frame(frame[packet.consumed:], start=BGP)`. Out of scope and left raw, as #185 asks: AS_PATH (its AS number width, 2 or 4 bytes, is negotiated in the OPENs), capability values, ADD-PATH path identifiers, ROUTE-REFRESH's fields and the MP_REACH/MP_UNREACH attributes that carry IPv6 routes. The capture host has no IPv6, so BGP over IPv6 is tested with constructed frames.

### Development

- **Every comparative number the README quotes was re-measured for this release** (Rule 4 of `docs/CLAIMS.md`), on the same machine class as 2.4.0's figures but on the 265-frame corpus Tier 2 grew from 140, against `dpkt 1.9.8` and `scapy 2.8.0`. **The README's "within 15% of dpkt on decode" no longer holds and is replaced**: dpkt decodes the corpus 1.30× faster (1.27-1.30× over three runs), while netprotocols stays 3.4× ahead of scapy. A file-by-file A/B against the 2.4.0 tree puts the gap in the five new routing captures, on which dpkt takes about two thirds of netprotocols' time, while the 140 frames 2.4.0 was measured on still read within 10% of dpkt on both trees, so it is the workload rather than a regression; why dpkt is faster on those protocols was not profiled. Encode is 4.62× ahead of dpkt, import 70.0 ms (from 55.0 ms, the five new modules) against `scapy.all`'s 396.9 ms, and the wheel is 176.5 KiB, 15.3× smaller than scapy 2.8.0's 2.63 MiB. Decode depth against dpkt is 79 of 265 frames deeper, the 40 new ones being the BGP and RIP frames, which dpkt leaves as raw bytes. `docs/CLAIMS.md` records each run, the per-file table and the A/B, and renames claim 1.2 for the figure it now holds.
- **The decode benchmark baseline is re-recorded on the 265-frame corpus.** `benchmarks/baseline.json` was recorded at 2.2.1 on the 97-frame corpus (6.5677 normalized); it now holds 2.5.0 on 265 frames, 5.4344 normalized (97,453 f/s, 30 repetitions, best of 9, CPython 3.12.3), via `scripts/benchmark.py --update-baseline`. The corpus `--check` walks grew with Tier 1 and Tier 2 captures that cost more per frame than the old ones, so normalized throughput fell with the workload: the same library code read -14.1% on master (`03387af`) and -17.1% (-16.5% on the re-measure) on the release PR, either side of the 15% gate on runner noise alone, and the file-by-file A/B of 2.4.0 against 2.5.0 in `docs/CLAIMS.md` shows no regression beyond that harness's noise on the 140 frames 2.4.0 had. Re-anchoring accepts the drift since 2.2.1: the gate now guards against regressions relative to 2.5.0 on this corpus.
- **A real BGP capture joins the corpus: `bgp.pcap`, 19 frames (265 across 27 scenarios), and its whole session goes into `tests/fixtures/bgp/`.** `scripts/capture_fixtures_bgp.sh` runs three BIRD 2.14 speakers in netns on one bridge, an eBGP and an iBGP session, with offload disabled, through OPENs, KEEPALIVEs, UPDATEs (five prefixes each with its own MED, 600 /24s that BIRD packs into a few UPDATEs, some longer than a segment), a withdrawal and a Cease NOTIFICATION with an RFC 9003 shutdown communication. It reassembles each direction to assert what was announced and withdrawn, prefix by prefix, and that the capture holds a segment of several whole messages, one of whole messages then a cut one, and one starting inside a message; it writes every frame to `bgp/bgp_session.pcap` (94 frames, outside the corpus globs) and the frames whose payload is whole messages to `bgp.pcap`. `scripts/check_fixtures.py` needed no change: it verifies the TCP checksums that cover the BGP payload. The corpus's deepest chain is now 10 layers (a segment of 7 UPDATEs); `walk.py` and `docs/CLAIMS.md` §5.7 say so. `tests/test_fuzz.py` gains BGP accessor-safety and built-UPDATE properties.
- **A real PIM-SM capture joins the corpus: `pim.pcap`, 13 frames (246 across 26 scenarios).** `scripts/capture_fixtures_pim.sh` runs two FRR 8.4 routers (zebra + pimd) between a multicast source and an IGMPv3 receiver, four netns over three veth pairs, with static RPs on opposite routers for two groups so that a (*,G) tree and a Register exchange both cross the captured link, then has the receiver leave and stops one pimd. It keeps the first frame of each of 13 kinds — Hellos with Holdtime, LAN Prune Delay, DR Priority, Generation ID and Address List options, a Holdtime-0 goodbye, a data Register and a Null-Register, a Register-Stop, and Join/Prune messages with joined and pruned (*,G), (S,G) and (S,G,rpt) entries — and fails unless it saw all of them. FRR sums its Registers' checksums over the first 8 bytes. `scripts/check_fixtures.py` verifies every PIM checksum (IPv4, and IPv6 with its pseudo-header), accepts either Register form, and checks the Register's encapsulated packet in turn, skipping only a Null-Register's zero dummy IPv4 header checksum, which RFC 7761 says a receiver must not check; an IPv6 Null-Register's dummy PIM header (version 0, after the dummy IPv6 header) is checked by its own checksum over the dummy header's source and group, as §4.9.3 asks, rather than as a PIM message; `tests/test_pim.py` runs it on the frames and on tampered copies. The capture host has no IPv6, so PIM over IPv6 is covered by constructed frames whose pseudo-header checksums the test computes itself; Assert, Graft and the raw types are covered by constructed messages, and real frames are tested with zero padding and a 4-byte trailer appended. PIM joins the fuzz suite (`ALL_PROTOCOLS`, a round-trip strategy, an accessor-safety property and trailer properties), the truncation and damaged-payload contract tests, the corpus checksum cases and the corpus coverage set.
- **`_tlv.walk_kind_length_value` takes a `width`** (default 1), the size of the kind and length fields, so PIM Hello options (2-byte type and length) walk through it. The floor and overrun message are now derived once per call, which takes the walker from radon C (13) to B (10); a seeded 3000-case comparison against a verbatim copy of the previous walker pins every byte-wide caller (TCP, IPv4, IPv6 options) to identical results and errors. `checksum.compute()`'s PIM arm is one call to a `_pim_checksum` helper, beside the `_pseudo_header_checksum` helper the ICMPv6, TCP and UDP arms already use, so `compute()` stays at radon B. The scoped mutation runs on `netprotocols._tlv.*` and `netprotocols.checksum.*` leave no survivor beyond the one already allowlisted.
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
