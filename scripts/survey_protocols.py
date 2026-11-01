#!/usr/bin/env python3
"""Protocol-coverage survey: #170's gap list against dpkt, scapy, pypacker.

    python3 -I scripts/survey_protocols.py \\
        --dpkt /tmp/survey-dpkt-src/dpkt \\
        --scapy /tmp/survey-scapy-src/scapy \\
        --pypacker /tmp/survey-pypacker-src/pypacker-5.4/pypacker

Each ``--<library>`` names the package directory of a competitor
release unpacked from PyPI (the commands that fetch, hash-check and
unpack them are in docs/CLAIMS.md 7.1). Nothing under those directories
is imported or executed: every check is a regular expression run over a
source file read as text, so the survey runs on any Python 3.12+ with
no third-party package installed, and ``-I`` keeps the interpreter from
importing anything that sits beside the script or in the working
directory.

#170 built its five tiers by cross-referencing the three libraries'
module lists against this one's. This repeats that, one row per item on
the roadmap's list, and adds what #170 did not write down: the file and
class that answer each cell, so a reader can check any one of them in
seconds. A cell names a decoder that exists in the release; it does not
say the library's own decode walk reaches it (dpkt does not dispatch
TCP or UDP ports at all, for one, docs/CLAIMS.md 1.6). Two things that
do decide whether a decoder is usable are reported beside it: a caveat
the competitor's own source states, and, for scapy, whether
``import scapy.all`` loads the module (``contrib/`` modules need
``load_contrib()``, and a ``layers/`` module outside ``conf.load_layers``
needs ``load_layer()``).

The second table lists the protocols all three releases decode and
netprotocols does not. It is a survey, not a gap list: the register's
standing rule is never to race scapy on coverage (docs/CLAIMS.md 6).
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import NamedTuple

REPOSITORY = Path(__file__).resolve().parent.parent
NETPROTOCOLS = REPOSITORY / "src" / "netprotocols"


class Check(NamedTuple):
    """A regular expression that must (or must not) match a source file."""

    path: str  # relative to the package directory
    pattern: str  # searched with re.MULTILINE
    note: str = ""  # a caveat, reported when the check holds
    absent: bool = False  # the check holds when the pattern does NOT match


class Row(NamedTuple):
    protocol: str
    issue: str
    ours: tuple[Check, ...]
    dpkt: tuple[Check, ...]
    scapy: tuple[Check, ...]
    pypacker: tuple[Check, ...]


def cls(path: str, name: str) -> Check:
    """A class definition, ``class <name>`` at the start of a line."""
    return Check(path, rf"^class {name}\b")


#: #170's gap list: every item of its five tiers, in tier order (#171-#175).
GAP = (
    Row(
        "SCTP",
        "#176",
        (cls("layer4/sctp.py", "SCTP"),),
        (cls("sctp.py", "SCTP"),),
        (cls("layers/sctp.py", "SCTP"),),
        (cls("layer4/sctp.py", "SCTP"),),
    ),
    Row(
        "IP-in-IP",
        "#177",
        (
            Check(
                "_defaults.py",
                r"add\(TABLE_IP_PROTO, IPProtocol\.IPIP, IPv4\)",
            ),
        ),
        (Check("ipip.py", r"^from \.ip import IP as IPIP"),),
        (Check("layers/inet.py", r"^bind_layers\(IP, IP, frag=0, proto=4\)"),),
        (
            Check("layer3/ip.py", r"IP_PROTO_IP6: ip6\.IP6"),
            Check(
                "layer3/ip.py",
                r"IP_PROTO_IPIP:",
                "IPv6 in IP only: no handler for protocol 4",
                absent=True,
            ),
        ),
    ),
    Row(
        "IPsec ESP",
        "#178",
        (cls("layer3/esp.py", "ESP"),),
        (cls("esp.py", "ESP"),),
        (cls("layers/ipsec.py", "ESP"),),
        (cls("layer3/esp.py", "ESP"),),
    ),
    Row(
        "IPsec AH",
        "#179",
        (cls("layer3/ah.py", "AH"),),
        (cls("ah.py", "AH"),),
        (cls("layers/ipsec.py", "AH"),),
        (
            cls("layer3/ip6.py", "IP6AHHeader"),
            Check(
                "layer3/ip.py",
                r"IP_PROTO_AH:",
                "an IPv6 extension header only: IPv4 has no handler for it",
                absent=True,
            ),
        ),
    ),
    Row(
        "VXLAN",
        "#180",
        (cls("layer7/vxlan.py", "VXLAN"),),
        (),
        (cls("layers/vxlan.py", "VXLAN"),),
        (),
    ),
    Row(
        "VRRP",
        "#181",
        (cls("layer3/vrrp.py", "VRRP"),),
        (cls("vrrp.py", "VRRP"),),
        (cls("layers/vrrp.py", "VRRP"),),
        (cls("layer12/vrrp.py", "VRRP"),),
    ),
    Row(
        "RIP",
        "#182",
        (cls("layer7/rip.py", "RIP"),),
        (cls("rip.py", "RIP"),),
        (cls("layers/rip.py", "RIP"),),
        (cls("layer567/rip.py", "RIP"),),
    ),
    Row(
        "OSPF",
        "#183",
        (cls("layer3/ospf.py", "OSPF"),),
        (cls("ospf.py", "OSPF"),),
        (cls("contrib/ospf.py", "OSPF_Hdr"),),
        (cls("layer3/ospf.py", "OSPF"),),
    ),
    Row(
        "PIM",
        "#184",
        (cls("layer3/pim.py", "PIM"),),
        (cls("pim.py", "PIM"),),
        (cls("contrib/pim.py", "PIMv2Hdr"),),
        (cls("layer3/pim.py", "PIM"),),
    ),
    Row(
        "BGP",
        "#185",
        (cls("layer7/bgp.py", "BGP"),),
        (cls("bgp.py", "BGP"),),
        (cls("contrib/bgp.py", "BGPHeader"),),
        (cls("layer567/bgp.py", "BGP"),),
    ),
    Row(
        "LLDP",
        "#186",
        (cls("layer2/lldp.py", "LLDP"),),
        (),
        (cls("contrib/lldp.py", "LLDPDU"),),
        (cls("layer12/lldp.py", "LLDP"),),
    ),
    Row(
        "MPLS",
        "#187",
        (cls("layer2/mpls.py", "MPLS"),),
        (
            Check(
                "ethernet.py",
                r"^class MPLSlabel\b",
                "labels folded into Ethernet.mpls_labels, not a layer",
            ),
        ),
        (cls("contrib/mpls.py", "MPLS"),),
        (),
    ),
    Row(
        "802.2 LLC / SNAP",
        "#188",
        (cls("layer2/llc.py", "LLC"), cls("layer2/llc.py", "SNAP")),
        (cls("llc.py", "LLC"),),
        (cls("layers/l2.py", "LLC"), cls("layers/l2.py", "SNAP")),
        (
            cls("layer12/llc.py", "LLC"),
            Check(
                "layer12/ethernet.py",
                r"LLC format\) .* not supported",
                'its Ethernet reads no 802.3 Length: "not supported"',
            ),
        ),
    ),
    Row(
        "STP",
        "#189",
        (cls("layer2/stp.py", "STP"),),
        (cls("stp.py", "STP"),),
        (cls("layers/l2.py", "STP"),),
        (cls("layer12/stp.py", "STP"),),
    ),
    Row(
        "CDP",
        "#190",
        (cls("layer2/cdp.py", "CDP"),),
        (cls("cdp.py", "CDP"),),
        (cls("contrib/cdp.py", "CDPv2_HDR"),),
        (),
    ),
    Row(
        "NTP",
        "#191",
        (cls("layer7/ntp.py", "NTP"),),
        (cls("ntp.py", "NTP"),),
        (cls("layers/ntp.py", "NTPHeader"),),
        (cls("layer567/ntp.py", "NTP"),),
    ),
    Row(
        "TFTP",
        "#192",
        (cls("layer7/tftp.py", "TFTP"),),
        (cls("tftp.py", "TFTP"),),
        (cls("layers/tftp.py", "TFTP"),),
        (cls("layer567/tftp.py", "TFTP"),),
    ),
    Row(
        "RADIUS",
        "#193",
        (cls("layer7/radius.py", "RADIUS"),),
        (cls("radius.py", "RADIUS"),),
        (cls("layers/radius.py", "Radius"),),
        (cls("layer567/radius.py", "Radius"),),
    ),
    Row(
        "STUN",
        "#194",
        (cls("layer7/stun.py", "STUN"),),
        (cls("stun.py", "STUN"),),
        (cls("contrib/stun.py", "STUN"),),
        (cls("layer567/stun.py", "STUN"),),
    ),
    Row(
        "HSRP",
        "#195",
        (cls("layer7/hsrp.py", "HSRP"),),
        (cls("hsrp.py", "HSRP"),),
        (cls("layers/hsrp.py", "HSRP"),),
        (cls("layer567/hsrp.py", "HSRP"),),
    ),
    Row(
        "TLS records + SNI",
        "#196",
        (cls("layer7/tls.py", "TLS"),),
        (cls("ssl.py", "TLS"),),
        (cls("layers/tls/record.py", "TLS"),),
        (cls("layer4/ssl.py", "SSL"),),
    ),
)


def elsewhere(
    protocol: str, name: str, dpkt: str, scapy: str, pypacker: str
) -> Row:
    """A row for a protocol all three decode and netprotocols does not.

    Each library is ``"<file>:<class>"``; ``name`` is the class this
    library would export, which the "netprotocols" check asserts is
    absent from ``__all__``.
    """
    return Row(
        protocol,
        "",
        (Check("__init__.py", rf'^\s*"{name}",$', absent=True),),
        (cls(*dpkt.split(":")),),
        (cls(*scapy.split(":")),),
        (cls(*pypacker.split(":")),),
    )


#: Protocols every one of the three releases decodes and this one does not.
ELSEWHERE = (
    elsewhere(
        "PPP", "PPP", "ppp.py:PPP", "layers/ppp.py:PPP", "layer12/ppp.py:PPP"
    ),
    elsewhere(
        "PPPoE",
        "PPPoE",
        "pppoe.py:PPPoE",
        "layers/ppp.py:PPPoE",
        "layer12/pppoe.py:PPPoE",
    ),
    elsewhere(
        "IEEE 802.11",
        "IEEE80211",
        "ieee80211.py:IEEE80211",
        "layers/dot11.py:Dot11",
        "layer12/ieee80211.py:IEEE80211",
    ),
    elsewhere(
        "Radiotap",
        "Radiotap",
        "radiotap.py:Radiotap",
        "layers/dot11.py:RadioTap",
        "layer12/radiotap.py:Radiotap",
    ),
    elsewhere(
        "Cisco DTP",
        "DTP",
        "dtp.py:DTP",
        "contrib/dtp.py:DTP",
        "layer12/dtp.py:DTP",
    ),
    elsewhere(
        "ATA over Ethernet",
        "AOE",
        "aoe.py:AOE",
        "contrib/aoe.py:AOE",
        "layer12/aoe.py:AOE",
    ),
    elsewhere(
        "RTP", "RTP", "rtp.py:RTP", "layers/rtp.py:RTP", "layer567/rtp.py:RTP"
    ),
    elsewhere(
        "Diameter",
        "Diameter",
        "diameter.py:Diameter",
        "contrib/diameter.py:DiamG",
        "layer567/diameter.py:Diameter",
    ),
    elsewhere(
        "SMB",
        "SMB",
        "smb.py:SMB",
        "layers/smb.py:SMB_Header",
        "layer567/smb.py:SMB",
    ),
)


def read(root: Path, relative: str) -> str | None:
    """The text of ``root/relative``, or ``None`` if there is no such file."""
    path = root / relative
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def evaluate(root: Path, checks: tuple[Check, ...]) -> tuple[bool, str]:
    """Whether every check holds, and the cell text that says so."""
    if not checks:
        return False, "—"
    found, places, notes = True, [], []
    for check in checks:
        text = read(root, check.path)
        matched = text is not None and bool(
            re.search(check.pattern, text, re.MULTILINE)
        )
        if matched == check.absent:
            found = False
            places.append(f"FAILED {check.path}: /{check.pattern}/")
            continue
        caveat = check.absent or (check.note and "class" not in check.pattern)
        if not caveat:
            what = re.sub(r"^\^(class )?|\\b$", "", check.pattern)
            places.append(f"`{check.path}` {what.replace(chr(92), '')}")
        if check.note:
            notes.append(f"({check.note})")
    return found, " ".join([", ".join(places), *notes]).strip()


def scapy_loaded_layers(root: Path) -> set[str]:
    """``conf.load_layers``, the ``layers/`` modules ``scapy.all`` loads."""
    text = read(root, "config.py") or ""
    match = re.search(r"load_layers: List\[str\] = \[(.*?)\]", text, re.DOTALL)
    return set(re.findall(r"'([\w.]+)'", match.group(1))) if match else set()


def scapy_note(checks: tuple[Check, ...], loaded: set[str]) -> str:
    """Whether ``import scapy.all`` loads the module a scapy cell names."""
    for check in checks:
        parts = check.path.removesuffix(".py").split("/")
        if parts[0] == "contrib":
            return " (contrib: `load_contrib()`)"
        if parts[0] == "layers" and parts[1] not in loaded:
            return " (`load_layer()`, not in `scapy.all`)"
    return ""


def version(package: Path) -> str:
    """The version an unpacked wheel or sdist declares beside ``package``."""
    candidates = [
        *package.parent.glob("*.dist-info/METADATA"),
        package.parent / "PKG-INFO",
    ]
    for metadata in candidates:
        if metadata.is_file():
            text = metadata.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"^Version: (\S+)$", text, re.MULTILINE)
            if match:
                return match.group(1)
    return "unknown"


def our_version() -> str:
    """``netprotocols.__version__``, read from source, not imported."""
    tree = ast.parse((NETPROTOCOLS / "__init__.py").read_text("utf-8"))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "__version__"
            and isinstance(node.value, ast.Constant)
        ):
            return str(node.value.value)
    return "unknown"


def table(
    rows: tuple[Row, ...],
    roots: dict[str, Path],
    loaded: set[str],
    with_issue: bool,
) -> tuple[list[str], dict[str, int]]:
    """Markdown table lines and, per library, how many rows it covers."""
    libraries = ("ours", "dpkt", "scapy", "pypacker")
    header = ["Protocol", *(["Issue"] if with_issue else [])]
    header += ["netprotocols", "dpkt", "scapy", "pypacker"]
    lines = ["| " + " | ".join(header) + " |", "|---" * len(header) + "|"]
    covered = dict.fromkeys(libraries, 0)
    for row in rows:
        cells = [row.protocol, *([row.issue] if with_issue else [])]
        for library in libraries:
            checks: tuple[Check, ...] = getattr(row, library)
            found, text = evaluate(roots[library], checks)
            if library == "ours" and not with_issue and found:
                text = "—"  # the absent check held: not exported here
            if found and library == "scapy":
                text += scapy_note(checks, loaded)
            covered[library] += found
            cells.append(text)
        lines.append("| " + " | ".join(cells) + " |")
    return lines, covered


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    for library in ("dpkt", "scapy", "pypacker"):
        parser.add_argument(
            f"--{library}",
            type=Path,
            required=True,
            help=f"the unpacked {library} package directory",
        )
    args = parser.parse_args()
    roots = {
        "ours": NETPROTOCOLS,
        "dpkt": args.dpkt,
        "scapy": args.scapy,
        "pypacker": args.pypacker,
    }
    for library, root in roots.items():
        if not (root / "__init__.py").is_file():
            parser.error(f"{library}: {root} is not a package directory")
    loaded = scapy_loaded_layers(args.scapy)

    print(
        f"netprotocols source tree (__version__ {our_version()}), "
        f"dpkt {version(args.dpkt)}, scapy {version(args.scapy)}, "
        f"pypacker {version(args.pypacker)}; "
        f"Python {sys.version.split()[0]}"
    )
    print()
    lines, covered = table(GAP, roots, loaded, with_issue=True)
    print("\n".join(lines))
    print()
    print(
        f"Of #170's {len(GAP)} items: netprotocols {covered['ours']}, "
        f"dpkt {covered['dpkt']}, scapy {covered['scapy']}, "
        f"pypacker {covered['pypacker']}."
    )
    gap_closed = covered["ours"] == len(GAP)
    print()
    lines, covered = table(ELSEWHERE, roots, loaded, with_issue=False)
    print("\n".join(lines))
    print()
    print(
        f"Decoded by all three and not exported by netprotocols: "
        f"{covered['ours']} of {len(ELSEWHERE)} (dpkt has "
        f"{covered['dpkt']}, scapy {covered['scapy']}, pypacker "
        f"{covered['pypacker']})."
    )
    return 0 if gap_closed else 1


if __name__ == "__main__":
    sys.exit(main())
