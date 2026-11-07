# Roadmap (draft): new protocols, after #310

> **Status: draft, not filed.** Nothing here starts until #310's closing issue (Tier 6's claims re-measure) is closed. Issue numbers are not assigned yet; each item becomes one issue when its tier opens.

## Context

#310 deepens the existing decoders and adds no new protocols. This roadmap is the breadth that follows it. It is grounded in three surveys of `master` at `9da02d7`:

- **The competitor gap that CLAIMS already measured.** `docs/CLAIMS.md` (≈2190–2240) lists 11 protocols that dpkt, scapy and pypacker all decode and this library does not: PPP, PPPoE, 802.11, Radiotap, Linux SLL, DTP, AoE, RTP, Diameter, SMB and Portmap. Five more are decoded by dpkt and pypacker but not by scapy: IPX, RFB, SIP, Telnet and TPKT. All three competitors decode ASN.1 BER/DER.
- **Gaps the code names about itself:**
  - OSPFv3: IPv6 protocol 89 is `WITHHELD`.
  - RIPng (`rip.py`), DTLS and QUIC (`tls.py`), STUN over TLS and DTLS (`stun.py`).
  - LLC SAP 0xFE (ISO network layer, which carries IS-IS) has a display name but no decoder.
  - ICMPv6 MLD types 130–132 and 143 are named but have no typed bodies.
  - GRE stops at EtherTypes 0x6558 (TEB/NVGRE), 0x88BE (ERSPAN) and 0x880B (PPP).
- **The library's audience:** offensive and defensive security, and Linux networking. That ranks name-service poisoning, L2 access control, VPN handshakes and directory/auth protocols ahead of telemetry and ICS.

No open issue requests a protocol today. `.github/ISSUE_TEMPLATE/protocol_request.yml` still links to the old roadmap #22; the closing issue fixes that.

Every tier keeps the standards in force under #310:
- the docstring and comment standard;
- the ban on work markers (`scripts/check_markers.py`);
- real captures only, with provenance in MANIFEST.md;
- the full QA ladder;
- independent implementation and review (`.claude/skills/steward/SKILL.md`).

## Capture environment

The capture rules don't change.
- Every capture comes from real daemons, in a network namespace, over veth with offload disabled.
- Each issue's first step is to prove that a real sender exists.
- With no real sender, the maintainer chooses between stopping and labelled hand-built vectors cross-checked against Wireshark, as with #280–#282.
- Never scapy, dpkt or pypacker.

**New for this roadmap.** Each issue states which kernel features its capture needs, because the cloud container's kernel varies between restarts.

On 2026-11-07, kernel 6.18.44-fc-v310 had:
- **Working:** veth, bridge, macvlan, vxlan (including `gpe`), TUN/TAP, AF_PACKET, raw IPv4 sockets and xfrm.
- **Missing:** AF_INET6, GRE/gretap/ERSPAN, ipip/sit, geneve, wireguard, macsec, gtp, bonding, vrf, l2tp, dummy, SCTP sockets and `/dev/ppp`.

Earlier containers in this repository's history did capture GRE over IPv6. A capture that needs a missing feature either waits for a container that has it or runs on the maintainer's machine, and its MANIFEST entry records which.

## Tiers

Versions are provisional and continue from #310's 2.12.0. Following #310's convention, a version label is a development milestone, not a release promise. A small tier may fold into the next release.

| Version | Tier | Theme | Items | Ships to PyPI? |
|---|---|---|---|---|
| — | 0 | Dispatch prerequisites and decisions | GRE TEB/NVGRE → Ethernet; first-bytes split for shared ports; policy for ports with no IANA assignment; stateless template handling | Rides Tier 1 |
| 2.13.0 | 1 | Name-service poisoning surface | mDNS, LLMNR, NBNS / NetBIOS datagram, SSDP | Yes |
| 2.14.0 | 2 | L2 access and attack surface | EAPOL / 802.1X + EAP, Cisco DTP + VTP, PPPoE + PPP (LCP, IPCP, PAP, CHAP), LACP, MACsec SecTAG | Yes |
| 2.15.0 | 3 | Tunnels and overlays | Geneve, GTP-U (+ GTP-C headers), L2TPv2/v3, ERSPAN II/III, WireGuard; VXLAN-GPE optional | Yes |
| 2.16.0 | 4 | VPN and secure-transport handshakes | IKEv2 + NAT-T (ESP-in-UDP), DTLS records, SSH banner + binary packet / KEXINIT, QUIC invariants + v1/v2 headers | Yes |
| 2.17.0 | 5 | ASN.1 and directory/auth | BER/DER reader → SNMP v1/v2c/v3 → LDAP / CLDAP → Kerberos v5 | Yes |
| 2.18.0 | 6 | Windows and RPC services | SMB2/3 header + NBSS, ONC RPC / Portmap | Yes |
| 2.19.0 | 7 | Routing completion | BFD, RIPng, LDP, IS-IS, OSPFv3, MLDv1/v2 typed bodies | Yes |
| 2.20.0 | 8 | Telemetry and logs | Syslog, NetFlow v5 → v9 / IPFIX, sFlow v5, DHCPv6 | Yes |
| 2.21.0 | 9 | ICS / IoT and VoIP | Modbus/TCP, MQTT 3.1.1/5, CoAP, SIP + SDP, RTP / RTCP | Yes |
| — | — | Closing | Re-measure every competitive claim; rerun `survey_protocols.py`; refresh CLAIMS' gap list and ARCHITECTURE's layout map; fix `protocol_request.yml` | Rides the last release |

The total is about 45–50 PRs at one issue per PR. Tiers 0–4 (about 25 PRs) need no new parsing substrate. If the maintainer wants a shorter commitment, they could stand alone as this roadmap, with Tiers 5–9 as its successor.

### Tier 0: dispatch prerequisites and decisions (no release of its own)

- **GRE TEB (0x6558) → Ethernet,** with NVGRE's VSID/FlowID accessors. This is a registration plus accessors; ERSPAN's headers come in Tier 3. The capture needs `gretap`.
- **Decisions.** None of these is settled yet; they are listed under "Decisions needed".

### Tier 1: name-service poisoning surface

These are the protocols Responder-style poisoning abuses. All but LLMNR have a sender in apt that runs in a netns.

| Item | Spec | Dispatch | Decodes as | Real sender | Kernel needs | Size |
|---|---|---|---|---|---|---|
| mDNS | RFC 6762 | UDP 5353 | DNS wire format, plus the QU and cache-flush bits | avahi-daemon 0.8 (`enable-dbus=no`) | IPv4 multicast | S |
| LLMNR | RFC 4795 | UDP 5355 | DNS-like, with different flags | systemd-resolved 255.4 only | IPv4 multicast; **sender unproven in a netns** | S |
| NBNS / NetBIOS datagram | RFC 1001, 1002 | UDP 137/138 | DNS-like, with the half-ASCII name encoding | samba `nmbd`, `nmblookup`, nbtscan 1.7.2 | IPv4 broadcast | M |
| SSDP | UPnP Device Architecture 2.0 | UDP 1900 | One HTTP message per datagram; reuse `HTTP` if it accepts `M-SEARCH *` | minissdpd 1.6.0, miniupnpd 2.3.4, gupnp-tools | IPv4 multicast | S |

Every one of these registers a new port with a weak, DNS-like guard. Each re-measures the guard with `scripts/measure_port_guard.py` and records the figures in ARCHITECTURE.

### Tier 2: L2 access and attack surface

| Item | Spec | Dispatch | Decodes as | Real sender | Kernel needs | Size |
|---|---|---|---|---|---|---|
| EAPOL / 802.1X + EAP | IEEE 802.1X-2020, RFC 3748 | EtherType 0x888E | 4-byte header, EAP, EAPOL-Key | hostapd 2.10 (`driver=wired`) with wpa_supplicant `-Dwired` | veth | M |
| Cisco DTP + VTP | Wireshark dissectors (no RFC) | SNAP PIDs 0x2004 / 0x2003 | Version plus TLVs | Yersinia 0.8.2 (already the HSRP corpus sender) | veth | S |
| PPPoE + PPP (LCP, IPCP, PAP, CHAP) | RFC 2516, 1661, 1332, 1334, 1994 | EtherType 0x8863/0x8864; also reached via GRE v1 and L2TP | 6-byte header plus tags; PPP protocol field | rp-pppoe 3.15, ppp 2.4.9 | discovery: veth; sessions: `/dev/ppp` | M |
| LACP / Marker | IEEE 802.1AX | EtherType 0x8809 | Fixed 110-byte LACPDU | kernel bonding (802.3ad) | bonding | S |
| MACsec SecTAG | IEEE 802.1AE | EtherType 0x88E5 | 8- or 16-byte SecTAG, chaining on when E=0; ICV kept raw | kernel macsec | macsec | S |

EAPOL ties into RADIUS's EAP-Message attribute. Every item in this tier adds EtherType or SNAP entries, so the tier serializes on `_enums.py` and `_defaults.py`.

### Tier 3: tunnels and overlays

| Item | Spec | Dispatch | Decodes as | Real sender | Kernel needs | Size |
|---|---|---|---|---|---|---|
| Geneve | RFC 8926 | UDP 6081 | 8-byte header plus TLV options, then Ethernet | kernel geneve | geneve | S |
| GTP-U (+ GTP-C headers) | 3GPP TS 29.281, 29.060, 29.274 | UDP 2152 / 2123 | 8-byte header plus extension-header chain, then IP | osmo-ggsn 1.9.0 over TAP (verify `sgsnemu`), kernel gtp | TAP, or gtp | S–M |
| L2TPv2 (and v3) | RFC 2661, 3931 | UDP 1701; IP protocol 115 | Flag-dependent header plus control AVPs; hidden AVPs kept raw | xl2tpd 1.3.18 | control channel: UDP only; data: PPP | M |
| ERSPAN II/III | draft-foschiano-erspan | GRE 0x88BE | 8- or 12-byte header, then Ethernet | kernel erspan | erspan | S |
| WireGuard | WireGuard whitepaper (no RFC) | UDP 51820 by convention | Type byte, three zero bytes, fixed message sizes | wireguard-go over TUN, wireguard-tools | TUN | S |
| VXLAN-GPE (optional) | expired draft; IANA port 4790 | UDP 4790 | VXLAN plus a Next Protocol byte | kernel vxlan `gpe` | vxlan | S |

### Tier 4: VPN and secure-transport handshakes

These decode handshakes and record or packet headers only. Encrypted contents stay opaque, as ESP's do.

| Item | Spec | Dispatch | Decodes as | Real sender | Size |
|---|---|---|---|---|---|
| IKEv2 + NAT-T / ESP-in-UDP | RFC 7296, 3948 | UDP 500 / 4500 | 28-byte header plus payload chain; SK payload opaque; 4500 splits IKE from ESP on its first four bytes and chains to the existing `ESP` | strongSwan 5.9.13, libreswan 4.14 | M |
| DTLS records | RFC 9147, 6347 | UDP, no fixed port | 13-byte record header, in `tls.py` | `openssl s_server -dtls` (installed), ocserv / openconnect | S–M |
| SSH | RFC 4253 | TCP 22 | Banner, packet length, KEXINIT name-lists (HASSH inputs); stops after NEWKEYS | openssh 9.6p1 | S–M |
| QUIC | RFC 8999, 9000 §17, 9369 | UDP 443 | Invariants plus long-header fields; the short header needs connection context; Initial payloads not decrypted (no pure-Python AES-GCM) | ngtcp2 0.12.1 client/server, python3-aioquic 0.9.25 | M |

DTLS and QUIC both touch `tls.py`, so they land in sequence. Registering UDP 443 for QUIC changes what existing frames on that port decode to, so the CHANGELOG records it under "Changed".

### Tier 5: ASN.1 and directory/auth

| Item | Spec | Dispatch | Notes | Real sender | Size |
|---|---|---|---|---|---|
| BER/DER reader | X.690 | — | A lazy TLV walker shared by the rest of this tier; fuzzed for depth and indefinite lengths | — | M |
| SNMP v1/v2c/v3 | RFC 1157, 3416, 3412, 3414 | UDP 161/162 | An encrypted v3 scopedPDU stays opaque | snmpd / snmp 5.9.4 | M |
| LDAP / CLDAP | RFC 4511 | TCP/UDP 389 | LDAPMessage, including simple-bind credentials | slapd / ldap-utils 2.6.10 | M |
| Kerberos v5 | RFC 4120 | UDP/TCP 88 (TCP adds a 4-byte length prefix) | Outer structure and cleartext fields (etypes, principals, AS-REQ/TGS-REQ); encrypted parts opaque | krb5-kdc / krb5-user 1.20.1, heimdal-kdc | L |

The BER reader is a new shared module. Like `_tlv.py`, it likely joins the mutation-audited set, which is the maintainer's decision.

### Tier 6: Windows and RPC services

| Item | Spec | Dispatch | Decodes as | Real sender | Size |
|---|---|---|---|---|---|
| SMB2/3 header + NBSS | MS-SMB2, RFC 1002 | TCP 445/139 | 4-byte NBSS header plus the 64-byte SMB2 header; transform header opaque | samba + smbclient 4.19.5 | M |
| ONC RPC / Portmap | RFC 5531, 1833 | UDP/TCP 111 | XDR | rpcbind 1.2.6 | S–M |

### Tier 7: routing completion

The protocols that FRR and BIRD already speak in the corpus's routing captures.

| Item | Spec | Dispatch | Real sender | Kernel needs | Size |
|---|---|---|---|---|---|
| BFD | RFC 5880, 5881, 5883 | UDP 3784/4784 | frr bfdd | IPv4 | S |
| RIPng | RFC 2080 | UDP 521 | frr ripngd, bird2 | **IPv6** | S |
| LDP | RFC 5036 | UDP/TCP 646 | frr ldpd (verify without the MPLS kernel module) | IPv4 | M |
| IS-IS | ISO/IEC 10589, RFC 1195, 5305 | LLC SAP 0xFE plus NLPID 0x83 (needs a small dispatch-by-NLPID shim) | frr isisd (AF_PACKET) | veth | M–L |
| OSPFv3 | RFC 5340 | IPv6 protocol 89 (replaces `WITHHELD`) | frr ospf6d, bird2 | **IPv6** | L |
| MLDv1/v2 typed bodies | RFC 2710, 9777 | ICMPv6 130–132, 143 | kernel, smcroute 2.5.6, pimd | **IPv6** | S |

OSPFv3 can share OSPFv2's LSA code where the formats agree. MLDv2 follows `IGMPv3GroupRecord`.

### Tier 8: telemetry and logs

| Item | Spec | Dispatch | Decodes as | Real sender | Size |
|---|---|---|---|---|---|
| Syslog | RFC 5424, 3164, 5426, 6587 | UDP 514, TCP 514/601 | Text: PRI split plus structured data | `logger` (installed), rsyslog 8.2312 | S |
| NetFlow v5 → v9 / IPFIX | RFC 3954, 7011 | UDP 2055/9995/4739 | v5 fixed records; v9/IPFIX template sets (see decisions) | softflowd 1.1.0, pmacct 1.7.8, fprobe; nfdump 1.7.3 | M |
| sFlow v5 | sFlow.org v5 | UDP 6343 | XDR samples; sampled headers chain to Ethernet | pmacct sfprobe (verify) | M |
| DHCPv6 | RFC 8415 | UDP 546/547 | 4-byte header plus nested option TLVs | kea-dhcp6 2.4.1, dnsmasq 2.91, dhcpcd 10.0.6 | S–M; **IPv6** |

### Tier 9: ICS / IoT and VoIP

| Item | Spec | Dispatch | Decodes as | Real sender | Size |
|---|---|---|---|---|---|
| Modbus/TCP | Modbus.org v1.1b3 | TCP 502 | 7-byte MBAP header plus function code | mbpoll 1.4.11, python3-pymodbus 3.6.9, libmodbus | S |
| MQTT 3.1.1 / 5 | OASIS | TCP 1883 | Fixed header plus varint length; CONNECT credentials | mosquitto 2.0.18; curl `mqtt://` (installed) | S–M |
| CoAP | RFC 7252 | UDP 5683 | 4-byte header, token, delta-encoded options | libcoap3-bin 4.3.4 | S–M |
| SIP + SDP | RFC 3261, 8866 | UDP/TCP 5060 | HTTP-like text | kamailio 5.7.4, sipsak, baresip | M |
| RTP / RTCP | RFC 3550 | dynamic ports (`decode_as` only) | 12-byte header | ffmpeg 6.1.1 `-f rtp` (installed), gstreamer | S |

### Considered, not scheduled

- **Linux SLL / SLL2 (pcap link types 113/276):** a small `pcap.py` change. It could ride any tier.
- **802.11 + Radiotap:** a different walk root, needs `mac80211_hwsim` on the maintainer's machine. Probably its own roadmap.
- **CFM, AoE, RARP, IPX:** low value, and mostly lack senders.
- **Diameter:** freeDiameter 1.2.1 exists. Medium value; it could join Tier 5 or 6.
- **DNP3:** no real sender in apt, so the real-capture rule blocks it.

## Versioning scheme

#310's SemVer rules carry over unchanged:
- A new decoder, accessor or dispatch entry is MINOR.
- A registration that changes what an existing valid frame decodes to must be called out under CHANGELOG "Changed". Examples are UDP 443 for QUIC, 5353 for mDNS, 1900 for SSDP and 4500 for NAT-T.

There is one release per tier through a release PR (`RELEASE.md`), with one GitHub milestone per version.

## Concurrency

#310's lanes, three-PR limit, per-agent worktrees and merge rules carry over unchanged.

### Files that serialize merges

| Shared file(s) | Touched by | Rule |
|---|---|---|
| `_enums.py`, `_defaults.py` | almost every item | Not serialized beyond a trivial merge, except where two items register the same number |
| `layer7/tls.py` | DTLS → QUIC (Tier 4) | In that order |
| `layer7/dns.py` | mDNS, LLMNR, NBNS (Tier 1) | In that order, if they share code |
| BER reader module | Tier 5 | The reader first, then SNMP, LDAP and Kerberos |
| `pcap.py` | SLL, if scheduled | Alone |
| `scripts/check_fixtures.py`, MANIFEST, README/CHANGELOG corpus counts | every capture PR | One capture PR merges at a time and recomputes the counts |

### Capture subnets

The free ranges are `10.9.204.0/24`–`10.9.236.0/24` and `10.9.238.0/24`–`10.9.254.0/24`. #310's reserved `10.9.198`–`10.9.202` appear in no script on master, and can be released when #310 closes.

Proposed blocks, one /24 per issue within its tier's block:

| Tier | Block |
|---|---|
| 0 | `10.9.204` |
| 1 | `10.9.205`–`10.9.208` |
| 2 | `10.9.209`–`10.9.213` |
| 3 | `10.9.214`–`10.9.219` |
| 4 | `10.9.220`–`10.9.223` |
| 5 | `10.9.224`–`10.9.227` |
| 6 | `10.9.228`–`10.9.229` |
| 7 | `10.9.230`–`10.9.235` |
| 8 | `10.9.238`–`10.9.241` |
| 9 | `10.9.242`–`10.9.246` |

IPv6 captures each take a `fd09:<issue>:1::/64` ULA, following #326.

## Decisions needed before a tier starts

- **Scope:** all ten tiers as one roadmap, or Tiers 0–4 now with Tiers 5–9 as a successor.
- **Tier 0:**
  - **Unassigned ports.** Should ports with no IANA assignment (WireGuard's 51820, RTP, DTLS) be registered, or reachable only through `decode_as`?
  - **Shared ports.** Is the first-bytes `_for_payload()` split (HSRP's and NTP's pattern) the rule for every port that carries two formats, such as 4500 (IKE vs ESP-in-UDP)?
  - **Stateless decoding.** How does a stateless decoder treat NetFlow v9 / IPFIX data sets whose template is in another datagram? Options: keep them raw, or offer an opt-in template cache.
- **Tier 4:** whether QUIC registers UDP 443 by default, given its weak guard and the change to what existing UDP 443 frames decode to.
- **Tier 5:** whether the BER reader joins the mutation-audited modules.
- **All tiers:** whether a capture that needs a kernel feature missing from the cloud container waits for a container that has it, or runs on the maintainer's machine.
- **LLMNR:** if no real sender runs in a netns, either stop or use labelled hand-built vectors, as with #280.

## Closing the roadmap

The last issue does the following:
- re-measures every competitive claim, as #197 and #310's closing issue did;
- reruns `scripts/survey_protocols.py`;
- refreshes CLAIMS' gap list and ARCHITECTURE's layout map;
- fixes `protocol_request.yml`'s link.

It is opened last, and closing it closes this roadmap.

## Sources

- **Repository** (`master` at `9da02d7`): `src/netprotocols/_defaults.py`, `_enums.py`, `registry.py`, `layer4/_ports.py`; `layer3/{gre,icmp,ospf,ipv6_ext}.py`; `layer7/{rip,stun,tls,http}.py`; README coverage table; ARCHITECTURE port-guard section and cookbook; CONTRIBUTING; `tests/fixtures/MANIFEST.md`; `docs/CLAIMS.md` competitor gap; `scripts/survey_protocols.py`.
- **GitHub:** #170 and #310, with their comments; the open-issue search.
- **Packages:** `apt-cache policy` on Ubuntu 24.04.5 (2026-11-07). Not packaged: hsflowd, sipp, openl2tp, accel-ppp, mstpd, quiche, opendnp3, boringtun, libgtpnl-tools, open5gs.
- **Kernel probes:** `ip link add` for each device type inside `unshare -n`, and `socket()` probes, on kernel 6.18.44-fc-v310.
- **Specs:** RFCs at https://www.rfc-editor.org/rfc/rfcNNNN for every RFC named above; IEEE 802.1X-2020, 802.1AE, 802.1AX, 1588-2019; ISO/IEC 10589; 3GPP TS 29.281, 29.060 and 29.274; [MS-SMB2]; OASIS MQTT; Modbus.org Application Protocol v1.1b3; UPnP Device Architecture 2.0; sFlow v5; the WireGuard whitepaper.
