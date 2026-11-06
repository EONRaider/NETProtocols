#!/usr/bin/env bash
# Capture the STP fixture for the corpus: MST BPDUs (IEEE 802.1Q MSTP,
# Protocol Version 3) from two bridges in one MST region, and, from
# the same bridges' neighbours, RST BPDUs (version 2) and 802.1D
# Configuration and Topology Change Notification BPDUs (version 0).
#
#     sudo env PATH=/path/to/mstpd/sbin:$PATH scripts/capture_fixtures_stp.sh
#
# THIS SCRIPT RUNS IN THE INITIAL NETWORK NAMESPACE, the host's own,
# not in a netns of its own as the other capture scripts do. Linux
# bridges speak RSTP and MSTP only through a userspace daemon, here
# mstpd (https://github.com/mstpd/mstpd, built from a release tag; see
# tests/fixtures/MANIFEST.md), and the kernel hands a bridge's STP to
# userspace (stp_state 2, BR_USER_STP) only when its /sbin/bridge-stp
# helper says so, and only for a bridge in the initial network
# namespace: in any other netns, stp_state 1 always means the kernel's
# own 802.1D STP (net/bridge/br_stp_if.c, br_stp_start()).
#
# What it creates in the initial netns, and removes on exit (normal or
# not, from an EXIT trap):
#   - four bridges and three veth pairs, every link named npmstp-*,
#     with no IP addresses;
#   - /sbin/bridge-stp, a helper marked with a comment line of its own
#     that claims only bridges named npmstp-* for userspace STP (any
#     other bridge gets the kernel's STP, as with no helper at all);
#     it is removed only if it still carries that mark;
#   - one mstpd process, in the foreground (-d), so no pidfile, and
#     tcpdump processes on B's three ports;
#   - a scratch directory from mktemp -d.
# It leaves only tests/fixtures/staging/stp.pcap. It refuses to run,
# touching nothing, if /sbin/bridge-stp exists without its mark (it
# never overwrites another helper), if mstpd is already running, or if
# any npmstp-* link exists.
#
# The four bridges, B in the middle:
#
#   npmstp-bra  A  MSTP, region "NETProtocols" revision 7, CIST
#                  priority 0x1000 (the root), MSTI 1 priority 0x0000
#                  (its regional root), MSTI 2 priority 0xC000
#   npmstp-brb  B  MSTP, the same region, CIST priority 0x8000, MSTI 1
#                  priority 0x8000, MSTI 2 priority 0x2000 (its regional
#                  root)
#   npmstp-brc  C  forced to RSTP (setforcevers rstp)
#   npmstp-brd  D  forced to 802.1D STP (setforcevers stp)
#
# In both A and B, VLANs 10-19 map to FID 1 and MSTI 1, VLANs 20-29 to
# FID 2 and MSTI 2, so every MST BPDU carries two MSTI Configuration
# Messages (Version 3 Length 96) and the same Configuration Digest,
# which the script recomputes (HMAC-MD5 of the VID-to-MSTID table,
# IEEE 802.1Q §13.8) and holds against every MST BPDU. B's three ports
# face A (npmstp-ba), C (npmstp-bc) and D (npmstp-bd); tcpdump runs on
# each, both directions, and the three captures are merged by time. The
# links come up one at a time:
#
#   1. A-B: A and B each send a proposal; B agrees, its port to A
#      becomes its root port, and both flag a topology change, then
#      settle (MST BPDUs both ways, inside the region).
#   2. B-C: C (RSTP) and B (MSTP, to C a different region) exchange
#      the proposal and agreement: RST BPDUs from C, MST BPDUs from B.
#   3. B-D: D (802.1D) sends a Configuration BPDU and then Topology
#      Change Notifications; B, after its migration delay, falls back
#      to Configuration BPDUs on that port, with the Topology Change
#      flag, then the Topology Change Acknowledgment.
#
# mstpd builds every BPDU (Ethernet header, LLC header and BPDU) in
# userspace and sends it through a packet socket; veth adds no padding.
# The bridges and veths get fixed MAC addresses, so the bridge and
# port IDs are the same on every run. BPDUs repeat every hello time (2
# s, the only value 802.1Q-2005 and later allow) for as long as mstpd
# runs, so the script drives each step by watching the capture and
# keeps a fixed selection: the first frame of each kind named below,
# a kind being the sending port, the BPDU type and version, and the
# CIST Flags. The kept frames are asserted at the end: their kinds,
# step by step; their lengths; every MST BPDU's Version 1 and Version
# 3 Lengths, MST Configuration Identifier, CIST Bridge Identifier and
# Remaining Hops, and its MSTI messages' MSTIDs, Regional Roots and
# priorities; and tshark's reading of each against the script's own.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "This script needs root for bridges, the STP helper and tcpdump." >&2
    exit 1
fi
for tool in ip tcpdump tshark python3 ethtool mstpd mstpctl; do
    command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done
echo "[*] mstpd $(mstpd -V)"

OUT="tests/fixtures/staging"
HELPER=/sbin/bridge-stp
HELPER_MARK="# npmstp: temporary helper of scripts/capture_fixtures_stp.sh"
BRIDGES=(npmstp-bra npmstp-brb npmstp-brc npmstp-brd)
VETHS=(npmstp-ab npmstp-bc npmstp-bd)
CAPTURE_PORTS=(npmstp-ba npmstp-bc npmstp-bd)

if [[ -e $HELPER ]] && ! grep -qxF "$HELPER_MARK" "$HELPER"; then
    echo "$HELPER exists and is not this script's; not replacing it." >&2
    exit 1
fi
if pgrep -x mstpd >/dev/null; then
    echo "mstpd is already running; stop it first." >&2
    exit 1
fi
if ip -o link show | grep -q ': npmstp-'; then
    echo "npmstp-* links exist; remove them first." >&2
    exit 1
fi

mkdir -p "$OUT"
WORK=
MSTPD_PID=
TCPDUMP_PIDS=()
HELPER_OURS=
cleanup() {
    for pid in "${TCPDUMP_PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for link in "${VETHS[@]}" "${BRIDGES[@]}"; do
        ip link del "$link" 2>/dev/null || true
    done
    if [[ -n $MSTPD_PID ]]; then
        kill "$MSTPD_PID" 2>/dev/null || true
        wait "$MSTPD_PID" 2>/dev/null || true
    fi
    if [[ -n $HELPER_OURS ]] && grep -qxF "$HELPER_MARK" "$HELPER" 2>/dev/null; then
        rm -f "$HELPER"
    fi
    if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT
WORK=$(mktemp -d)

echo "[*] $HELPER: user STP for npmstp-* bridges only"
HELPER_OURS=1
cat > "$HELPER" <<EOF
#!/bin/sh
$HELPER_MARK
# The kernel runs "$HELPER <bridge> start|stop"; exit 0 to "start"
# hands that bridge's STP to userspace (mstpd).
case "\$1" in npmstp-*) exit 0 ;; *) exit 1 ;; esac
EOF
chmod 755 "$HELPER"

mstpd -d -v 2 > "$WORK/mstpd.log" 2>&1 &
MSTPD_PID=$!
tries=50
until mstpctl showbridge >/dev/null 2>&1; do
    if (( --tries == 0 )); then echo "mstpd did not start." >&2; exit 1; fi
    sleep 0.1
done

echo "[*] bridges A, B, C, D; veths A-B, B-C, B-D"
ip link add npmstp-bra address 02:00:00:00:a0:00 type bridge
ip link add npmstp-brb address 02:00:00:00:b0:00 type bridge
ip link add npmstp-brc address 02:00:00:00:c0:00 type bridge
ip link add npmstp-brd address 02:00:00:00:d0:00 type bridge
ip link add npmstp-ab address 02:00:00:00:a0:01 type veth \
    peer name npmstp-ba address 02:00:00:00:b0:01
ip link add npmstp-bc address 02:00:00:00:b0:02 type veth \
    peer name npmstp-cb address 02:00:00:00:c0:01
ip link add npmstp-bd address 02:00:00:00:b0:03 type veth \
    peer name npmstp-db address 02:00:00:00:d0:01
ip link set npmstp-ab master npmstp-bra
ip link set npmstp-ba master npmstp-brb
ip link set npmstp-bc master npmstp-brb
ip link set npmstp-cb master npmstp-brc
ip link set npmstp-bd master npmstp-brb
ip link set npmstp-db master npmstp-brd
for br in "${BRIDGES[@]}"; do
    ip link set "$br" type bridge stp_state 1
    state=$(cat "/sys/class/net/$br/bridge/stp_state")
    if [[ $state != 2 ]]; then
        echo "$br: stp_state $state, not 2 (user STP)." >&2
        exit 1
    fi
done
mstpctl addbridge "${BRIDGES[@]}"
for br in "${BRIDGES[@]}"; do
    # The shortest timers 802.1Q allows, so ports reach forwarding fast:
    # Max Age 6 s needs a Forward Delay of at least 4 s (§13.25).
    mstpctl setmaxage "$br" 6
    mstpctl setfdelay "$br" 4
done
for br in npmstp-bra npmstp-brb; do
    mstpctl setforcevers "$br" mstp
    mstpctl setmstconfid "$br" 7 NETProtocols
    mstpctl createtree "$br" 1
    mstpctl createtree "$br" 2
    mstpctl setvid2fid "$br" 1:10-19 2:20-29
    mstpctl setfid2mstid "$br" 1:1 2:2
done
# Priorities in steps of 4096 (0-15).
mstpctl settreeprio npmstp-bra 0 1
mstpctl settreeprio npmstp-bra 1 0
mstpctl settreeprio npmstp-bra 2 12
mstpctl settreeprio npmstp-brb 2 2
mstpctl setforcevers npmstp-brc rstp
mstpctl setforcevers npmstp-brd stp
for veth in npmstp-ab npmstp-ba npmstp-bc npmstp-cb npmstp-bd npmstp-db; do
    ethtool -K "$veth" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
done
for br in "${BRIDGES[@]}"; do ip link set "$br" up; done
# B's ports are up, but have no carrier until their peers come up.
for port in "${CAPTURE_PORTS[@]}"; do ip link set "$port" up; done

# The label of each frame in the pcaps given, merged by time, one per
# line: "<kind>-<sender>-<CIST flags>", kind mst, rst, config or tcn,
# sender the sending port (a, b1 to A, b2 to C, b3 to D, c, d).
CLASSIFY_PY=$(cat <<'PY'
import struct
import sys

SENDERS = {
    "02000000a001": "a",
    "02000000b001": "b1",
    "02000000b002": "b2",
    "02000000b003": "b3",
    "02000000c001": "c",
    "02000000d001": "d",
}


def classify(frame):
    sender = SENDERS.get(frame[6:12].hex(), "other")
    if frame[:6] != bytes.fromhex("0180c2000000") or frame[14:17] != b"BB\x03":
        return f"other-{sender}"
    bpdu = frame[17:]
    version, kind = bpdu[2], bpdu[3]
    if kind == 0x80:
        return f"tcn-{sender}"
    name = {(0, 0x00): "config", (2, 0x02): "rst", (3, 0x02): "mst"}.get(
        (version, kind), f"v{version}-t{kind:02x}"
    )
    return f"{name}-{sender}-{bpdu[4]:02x}"


def records(path):
    try:
        raw = open(path, "rb").read()
    except FileNotFoundError:
        return
    offset = 24
    while offset + 16 <= len(raw):
        caplen = struct.unpack_from("<I", raw, offset + 8)[0]
        if offset + 16 + caplen > len(raw):
            return
        yield raw[offset : offset + 16 + caplen]
        offset += 16 + caplen


def merged(paths):
    """Every record of the pcaps, ordered by timestamp (stable)."""
    out = [r for path in paths for r in records(path)]
    return sorted(out, key=lambda r: struct.unpack_from("<II", r))


if __name__ == "__main__":
    for record in merged(sys.argv[1:]):
        print(classify(record[16:]))
PY
)
RAWS=()
for port in "${CAPTURE_PORTS[@]}"; do RAWS+=("$WORK/raw-$port.pcap"); done

# Wait (up to 30 s) until the raw captures hold a frame of each <label>.
wait_for() {
    local label tries
    for label in "$@"; do
        tries=300
        until python3 -c "$CLASSIFY_PY" "${RAWS[@]}" | grep -qx -- "$label"; do
            if (( --tries == 0 )); then
                echo "Timed out waiting for a $label frame." >&2
                exit 1
            fi
            sleep 0.1
        done
    done
}

for port in "${CAPTURE_PORTS[@]}"; do
    # -Z root: write the scratch file without dropping privileges.
    tcpdump -i "$port" -w "$WORK/raw-$port.pcap" -Z root --immediate-mode -U -q \
        'ether dst 01:80:c2:00:00:00' >/dev/null 2>&1 &
    TCPDUMP_PIDS+=($!)
done
# The first BPDUs go out the moment a link comes up, so wait until
# every tcpdump has opened its file.
for raw in "${RAWS[@]}"; do
    tries=100
    until [[ -s $raw ]]; do
        if (( --tries == 0 )); then echo "tcpdump did not start." >&2; exit 1; fi
        sleep 0.1
    done
done
sleep 0.5

# The kinds kept, step by step. The CIST Flags (IEEE 802.1Q §14.4.1):
#   4e  Agreement, Designated, Proposal (a fresh port's first BPDU)
#   79  Agreement, Forwarding, Learning, Root, Topology Change
#   7d  Agreement, Forwarding, Learning, Designated, Topology Change
#   7c  Agreement, Forwarding, Learning, Designated
#   78  Agreement, Forwarding, Learning, Root
#   01  Topology Change, 81 Topology Change and its Acknowledgment
STEP1=(mst-a-4e mst-b1-4e mst-b1-79 mst-a-7d mst-a-7c mst-b1-78)
STEP2=(rst-c-4e mst-b2-4e rst-c-79 mst-b2-7d mst-b2-7c)
STEP3=(config-d-00 mst-b3-4e tcn-d config-b3-00 config-b3-01 config-b3-81)

echo "[>] 1. A-B link up: MST BPDUs inside the region"
ip link set npmstp-ab up
wait_for "${STEP1[@]}"

echo "[>] 2. B-C link up: C's RST BPDUs, B's MST BPDUs to another region"
ip link set npmstp-cb up
wait_for "${STEP2[@]}"

echo "[>] 3. B-D link up: D's 802.1D BPDUs, B's fallback to them"
ip link set npmstp-db up
wait_for "${STEP3[@]}"
sleep 1

for pid in "${TCPDUMP_PIDS[@]}"; do
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
done
TCPDUMP_PIDS=()
mstpctl showbridge npmstp-brb > "$WORK/brb.txt"
grep -q "regional root   1.000.02:00:00:00:A0:00" "$WORK/brb.txt" || {
    cat "$WORK/brb.txt" >&2
    echo "B did not take A as its CIST regional root." >&2
    exit 1
}

# Keep, in capture order, the first frame of each kind in the steps.
SELECT_PY=$(cat <<'PY'
import struct
import sys

out_path, classify, kinds, paths = (
    sys.argv[1], sys.argv[2], set(sys.argv[3].split()), sys.argv[4:]
)
scope = {"__name__": "classify"}
exec(classify, scope)
for path in paths:
    raw = open(path, "rb").read()
    assert raw[:4] == b"\xd4\xc3\xb2\xa1", "expected a little-endian classic pcap"
    assert struct.unpack_from("<I", raw, 20)[0] == 1, "expected Ethernet framing"
    header = raw[:24]
records = scope["merged"](paths)
out = [header]
seen = set()
for record in records:
    label = scope["classify"](record[16:])
    if label in kinds and label not in seen:
        seen.add(label)
        out.append(record)
open(out_path, "wb").write(b"".join(out))
print(f"[i] kept {len(out) - 1} of the raw captures' {len(records)} frames")
PY
)
python3 -c "$SELECT_PY" "$OUT/stp.pcap" "$CLASSIFY_PY" \
    "${STEP1[*]} ${STEP2[*]} ${STEP3[*]}" "${RAWS[@]}"

echo
echo "[*] Validating..."
CHECKER_PY=$(command -v python3)
if [[ -n ${SUDO_USER:-} ]]; then
    chown -R "$SUDO_USER" "$OUT"
    sudo -u "$SUDO_USER" "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
else
    "$CHECKER_PY" scripts/check_fixtures.py "$OUT"
fi

# tshark's reading of each frame, one line each, tab-separated.
tshark -r "$OUT/stp.pcap" -T fields -E separator=/t -E occurrence=a \
    -E aggregator=, \
    -e stp.version -e stp.type -e stp.flags -e stp.version_1_length \
    -e mstp.version_3_length -e mstp.config_format_selector \
    -e mstp.config_name -e mstp.config_revision_level \
    -e mstp.config_digest -e mstp.msti.msti_id 2>/dev/null \
    > "$WORK/tshark.tsv"

COMPOSITION_PY=$(cat <<'PY'
import hashlib
import hmac
import struct
import sys

path, classify, tshark_path = sys.argv[1], sys.argv[2], sys.argv[3]
steps = [step.split() for step in sys.argv[4:]]
scope = {"__name__": "classify"}
exec(classify, scope)
raw = open(path, "rb").read()
frames = []
offset = 24
while offset < len(raw):
    caplen = struct.unpack_from("<I", raw, offset + 8)[0]
    frames.append(raw[offset + 16 : offset + 16 + caplen])
    offset += 16 + caplen
labels = [scope["classify"](frame) for frame in frames]

# Step by step: every kind once, and each step's frames after the last.
cursor = 0
for number, step in enumerate(steps, 1):
    got = labels[cursor : cursor + len(step)]
    assert sorted(got) == sorted(step), f"step {number}: {got} != {step}"
    cursor += len(step)
assert cursor == len(labels), f"unexpected frames: {labels[cursor:]}"

# IEEE 802.1Q §13.8: the Configuration Digest is HMAC-MD5, keyed by
# 0x13AC06A62E47FD51F95D2BA243CD0346, over the MSTID (2 octets) of
# each VID 0-4095. Here VIDs 10-19 map to MSTI 1 and 20-29 to MSTI 2.
table = bytearray(2 * 4096)
for vid in range(10, 30):
    struct.pack_into("!H", table, 2 * vid, 1 if vid < 20 else 2)
DIGEST = hmac.new(
    bytes.fromhex("13ac06a62e47fd51f95d2ba243cd0346"), table, hashlib.md5
).digest()
NAME = b"NETProtocols".ljust(32, b"\x00")
A, B = bytes.fromhex("02000000a000"), bytes.fromhex("02000000b000")
BRIDGE_ID = {"a": (0x1000, A), "b1": (0x8000, B), "b2": (0x8000, B), "b3": (0x8000, B)}
# Each BPDU's length after the 3-byte LLC header, and the frame's.
SIZES = {"config": 35, "tcn": 4, "rst": 36, "mst": 36 + 2 + 64 + 2 * 16}

tshark = [line.rstrip("\n").split("\t") for line in open(tshark_path)]
assert len(tshark) == len(frames), "tshark read a different frame count"

for number, (frame, label, fields) in enumerate(zip(frames, labels, tshark), 1):
    kind, sender = label.split("-")[:2]
    length = struct.unpack_from("!H", frame, 12)[0]
    assert length == 3 + SIZES[kind] == len(frame) - 14, (
        f"frame {number}: 802.3 Length {length}, frame {len(frame)} bytes"
    )
    bpdu = frame[17:]
    assert bpdu[:2] == b"\x00\x00", f"frame {number}: Protocol Identifier"
    version, kind_octet = bpdu[2], bpdu[3]
    if kind == "tcn":
        assert fields[:2] == ["0", "0x80"], f"frame {number}: tshark {fields}"
        continue
    flags = f"0x{bpdu[4]:02x}"
    if kind != "mst":
        assert fields[:3] == [str(version), f"0x{kind_octet:02x}", flags], (
            f"frame {number}: tshark {fields}"
        )
        if kind == "rst":
            assert bpdu[35] == 0, f"frame {number}: Version 1 Length"
        continue
    v1_length = bpdu[35]
    v3_length = struct.unpack_from("!H", bpdu, 36)[0]
    assert v1_length == 0, f"frame {number}: Version 1 Length {v1_length}"
    assert v3_length == 64 + 2 * 16 == len(bpdu) - 38, (
        f"frame {number}: Version 3 Length {v3_length}"
    )
    selector, name = bpdu[38], bpdu[39:71]
    revision = struct.unpack_from("!H", bpdu, 71)[0]
    digest = bpdu[73:89]
    assert (selector, name, revision, digest) == (0, NAME, 7, DIGEST), (
        f"frame {number}: MST Configuration Identifier"
    )
    cist_bridge = struct.unpack_from("!H6s", bpdu, 93)
    assert cist_bridge == BRIDGE_ID[sender], f"frame {number}: CIST Bridge ID"
    hops = bpdu[101]
    if sender == "a":
        assert hops == 20, f"frame {number}: CIST Remaining Hops {hops}"
    msti = []
    for start in range(102, len(bpdu), 16):
        message = bpdu[start : start + 16]
        regional_root = struct.unpack_from("!H6s", message, 1)
        msti.append(
            (regional_root[0] & 0x0FFF, regional_root, message[13], message[14] >> 4)
        )
    ids = [m[0] for m in msti]
    assert ids == [1, 2], f"frame {number}: MSTIDs {ids}"
    # Each MSTI's Bridge Priority octet: the top 4 bits of the sender's
    # priority for it (§14.4.1 r)); the Port Priority, 0x80 by default.
    priorities = [m[2] for m in msti]
    expected = [0x00, 0xC0] if sender == "a" else [0x80, 0x20]
    assert priorities == expected, f"frame {number}: MSTI priorities {priorities}"
    assert [m[3] for m in msti] == [8, 8], f"frame {number}: MSTI port priorities"
    if bpdu[4] & 0x20:  # Forwarding: converged, the roots settled.
        assert msti[0][1] == (0x0001, A), f"frame {number}: MSTI 1 root"
        assert msti[1][1] == (0x2002, B), f"frame {number}: MSTI 2 root"
    assert fields[:9] == [
        "3", "0x02", flags, "0", str(v3_length), "0", "NETProtocols", "7",
        DIGEST.hex(),
    ], f"frame {number}: tshark {fields}"
    assert fields[9] == "1,2", f"frame {number}: tshark MSTIDs {fields[9]}"
counts = {k: sum(label.startswith(k + "-") for label in labels) for k in SIZES}
print(f"[+] {len(frames)} frames, as expected: {counts}")
print(f"[i] Configuration Digest {DIGEST.hex()}")
PY
)
python3 -c "$COMPOSITION_PY" "$OUT/stp.pcap" "$CLASSIFY_PY" "$WORK/tshark.tsv" \
    "${STEP1[*]}" "${STEP2[*]}" "${STEP3[*]}"

echo
echo "[i] Expect zero failures. Fold tests/fixtures/staging/stp.pcap"
echo "    into tests/fixtures/."
