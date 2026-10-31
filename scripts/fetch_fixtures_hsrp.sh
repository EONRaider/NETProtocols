#!/usr/bin/env bash
# Fetch and trim the HSRP fixture for the corpus (RFC 2281).
#
#     scripts/fetch_fixtures_hsrp.sh
#
# No open-source HSRP speaker exists to capture from, so unlike the
# capture_fixtures_*.sh scripts this one captures nothing: it downloads
# a public capture of two Cisco routers, "hsrp-and-ospf-in-LAN" from
# the Wireshark wiki's SampleCaptures page, attached there as
#
#   https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/hsrp-and-ospf-in-LAN
#
# and listed as "HSRP state changes and OSPF LSAs sent during link
# up/down/up". The Wireshark wiki's License page puts its original
# content under the GNU General Public License; see the HSRP note in
# tests/fixtures/MANIFEST.md, which records the terms and provenance.
#
# The download is checked against the SHA-256 recorded below, then
# trimmed with one tcpdump command, which keeps the first 27 frames to
# or from UDP port 1985 and drops the capture's OSPF frames and the
# later steady-state HSRP Hellos:
#
#   tcpdump -r hsrp-and-ospf-in-LAN -w hsrp.pcap -c 27 'udp port 1985'
#
# Those 27 frames run from router B's first Hello, alone on the link,
# through router A's preemption (Coup, B's Resign, A's second Coup) to
# B's first Hello in Standby state under A. tcpdump writes each kept
# record unchanged, and the script checks that: the output must be the
# input's 24-byte file header followed by the selected records, byte
# for byte, timestamps included. It then asserts the selection exactly,
# by sender, op code, state, Hellotime, Holdtime and priority, and
# validates the result with check_fixtures.py.
#
# Everything is downloaded into a scratch directory, removed on exit,
# and treated as untrusted data: it is read by tcpdump and by the stdlib
# Python below, run with -I, and never executed.

set -euo pipefail

for tool in curl tcpdump python3 sha256sum; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

URL="https://gitlab.com/wireshark/wireshark/-/wikis/uploads/__moin_import__/attachments/SampleCaptures/hsrp-and-ospf-in-LAN"
SOURCE_SHA256="757bc3e6acd7122a253393c10463765ebd76eeceef1e56ad1963b6465ecb4909"
OUT="tests/fixtures/staging"
mkdir -p "$OUT"
WORK=$(mktemp -d)
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT
fail() { echo "[!] $*" >&2; exit 1; }

echo "[*] Downloading hsrp-and-ospf-in-LAN"
curl --fail --silent --show-error --location -o "$WORK/source" "$URL"
echo "$SOURCE_SHA256  $WORK/source" | sha256sum --check --quiet ||
    fail "The download does not match the recorded SHA-256."

echo "[*] Keeping the first 27 frames on UDP port 1985"
# -Z keeps tcpdump from dropping to its own user when run as root, so it
# can write into the scratch directory.
tcpdump -Z "$(id -un)" -r "$WORK/source" -w "$WORK/hsrp.pcap" -c 27 \
    'udp port 1985' 2>/dev/null

python3 -I - "$WORK/source" "$WORK/hsrp.pcap" "$OUT/hsrp.pcap" <<'PY'
import struct
import sys
from pathlib import Path

source, trimmed, out = (Path(arg) for arg in sys.argv[1:])


def records(data: bytes) -> tuple[bytes, list[bytes]]:
    """The file header and the records, each with its 16-byte header,
    of a little-endian classic pcap."""
    if data[:4] != b"\xd4\xc3\xb2\xa1":
        sys.exit("[!] Not a little-endian microsecond pcap")
    found, offset = [], 24
    while offset + 16 <= len(data):
        (incl_len,) = struct.unpack_from("<I", data, offset + 8)
        found.append(data[offset : offset + 16 + incl_len])
        offset += 16 + incl_len
    if offset != len(data):
        sys.exit("[!] Trailing bytes after the last record")
    return data[:24], found


def hsrp(record: bytes) -> bytes | None:
    """The UDP payload of an untagged IPv4 frame on port 1985, or None."""
    frame = record[16:]
    if frame[12:14] != b"\x08\x00" or frame[23] != 17:
        return None
    ihl = (frame[14] & 0x0F) * 4
    udp = frame[14 + ihl :]
    if 1985 not in struct.unpack_from("!HH", udp):
        return None
    return udp[8:]


header, every = records(source.read_bytes())
selected = [record for record in every if hsrp(record) is not None][:27]
data = trimmed.read_bytes()
if data != header + b"".join(selected):
    sys.exit("[!] tcpdump did not keep the selected records verbatim")

# (sender's last IPv4 octet, op code, state, hellotime, holdtime,
# priority): B (192.168.23.2) alone, Speak, Standby, then Active under
# its configured 5 s / 15 s timers; A (192.168.23.1, priority 110)
# preempts with a Coup from Listen, B resigns, A sends a second Coup
# from Active, and B settles in Speak and then Standby.
B_EARLY = (2, 0, 4, 3, 10, 100)
B_ACTIVE = (2, 0, 16, 5, 15, 100)
B_SPEAK = (2, 0, 4, 5, 15, 100)
A_ACTIVE = (1, 0, 16, 5, 15, 110)
expected = [
    *[B_EARLY] * 4,
    (2, 0, 8, 3, 10, 100),
    *[B_ACTIVE] * 9,
    (1, 1, 2, 5, 15, 110),
    A_ACTIVE,
    (2, 2, 4, 5, 15, 100),
    B_SPEAK,
    (1, 1, 16, 5, 15, 110),
    A_ACTIVE,
    B_SPEAK,
    A_ACTIVE,
    B_SPEAK,
    A_ACTIVE,
    B_SPEAK,
    A_ACTIVE,
    (2, 0, 8, 5, 15, 100),
]
seen = []
for record in selected:
    message = hsrp(record)
    assert message is not None
    if len(message) != 20 or message[0] != 0 or message[6] != 1:
        sys.exit("[!] Not a 20-byte HSRPv1 message for group 1")
    if message[8:20] != b"cisco\x00\x00\x00" + bytes([192, 168, 23, 250]):
        sys.exit("[!] Unexpected authentication data or virtual IP")
    seen.append((record[16 + 29], *message[1:6]))
if seen != expected:
    sys.exit(f"[!] Unexpected selection: {seen}, expected {expected}")
out.write_bytes(data)
print(f"[+] {len(selected)} frames, as expected.")
PY

echo
echo "[*] Validating..."
python3 scripts/check_fixtures.py "$OUT"

echo
echo "[i] Expect udp + hsrp counts (hsrp-hello, hsrp-coup, hsrp-resign) and"
echo "    zero failures. Fold tests/fixtures/staging/hsrp.pcap into"
echo "    tests/fixtures/."
