#!/usr/bin/env python3
"""Render the collected evidence into a human-readable REPORT.md.

Reads the same tmp/evidence inputs as analyze.py and emits markdown that
explains WHAT was tested, WHY each size was chosen, what each layer proves,
and what the verdict means — so the artifact bundle is self-explanatory
instead of a pile of JSONL files.
"""
import argparse
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--dir", required=True)
p.add_argument("--out", default=None, help="REPORT.md path (default: <dir>/REPORT.md)")
a = p.parse_args()
EV = Path(a.dir)
OUT = Path(a.out) if a.out else EV / "REPORT.md"


def jlines(name):
    f = EV / name
    if not f.exists():
        return []
    rows = []
    for line in f.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "size" in r:
            rows.append(r)
    return rows


def kvfile(name):
    f = EV / name
    out = {}
    if not f.exists():
        return out
    for line in f.read_text().splitlines():
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip()
    return out


# ------------------------------------------------------------------ inputs
df = kvfile("df-control.txt")
cap = kvfile("capture.txt")
counters = kvfile("felix-counters.txt")
icmp_fwd = jlines("icmp-sweep.jsonl")
icmp_rev = jlines("icmp-sweep-rev.jsonl")
udp_fwd = jlines("udp-sweep.jsonl")
udp_rev = jlines("udp-sweep-rev.jsonl")
report = {}
rp = EV / "report.json"
if rp.exists():
    report = json.loads(rp.read_text())
verdict = report.get("verdict", "UNKNOWN")

# ------------------------------------------------------------------ sizes
# Re-derive the tail arithmetic for the table (sizes are MTU-derived).
# Guards: empty/partial evidence (harness failed before sweeps) must render a
# readable report, not crash.
mtu = None
boundary = None
sizes = sorted({r["size"] for r in udp_fwd} or {r["size"] for r in icmp_fwd})
if sizes:
    single = [s for s in sizes if s < 2 * min(sizes)]
    if single:
        boundary = max(single)
        mtu = boundary + 20


rows = []
seen = set()
for r in udp_fwd + udp_rev:
    if r["size"] in seen:
        continue
    seen.add(r["size"])
    if boundary is None:
        continue
    b = boundary
    # UDP probe payload is the whole datagram payload: IP total = size + 28.
    # The IP-layer payload that gets fragmented = size + 8 (UDP header).
    payload = r["size"] + 8
    fc = (payload + b - 1) // b
    tail = payload - b * (fc - 1)  # bytes in the LAST fragment
    rows.append((r["size"], fc, tail))
rows.sort()

udp_fwd_ok = {r["size"]: r["ok"] for r in udp_fwd}
udp_rev_ok = {r["size"]: r["ok"] for r in udp_rev}
icmp_fwd_ok = {r["size"]: r["ok"] for r in icmp_fwd}

# ------------------------------------------------------------------ report
L = []
L.append("# Fragment-drop e2e — evidence report")
L.append("")
if verdict == "BUG REPRODUCED":
    L.append("> **VERDICT: BUG REPRODUCED (the check is red on purpose)**")
    L.append(">")
    L.append("> The Calico BPF dataplane still drops IPv4 datagrams whose "
             "**last fragment carries 1–7 bytes** of payload. A fix is NOT "
             "present in the image under test. This check turns green the "
             "moment an image under test delivers the full band.")
elif verdict == "FIX VERIFIED":
    L.append("> **VERDICT: FIX VERIFIED (green)**")
    L.append(">")
    L.append("> Every probe size — including the 1–7-byte-tail failure band — "
             "was delivered with byte-exact payloads in both directions.")
else:
    L.append(f"> **VERDICT: {verdict}** — evidence did not form a clean signal; "
             "see problems below. Never report this as bug-present or bug-fixed.")
L.append("")
L.append("## The bug in one paragraph")
L.append("")
L.append("felix's tc BPF program on each pod veth (`FROM_WEP`) parses every "
         "packet and rejects any **non-first IPv4 fragment** that carries "
         "fewer than 8 payload bytes (`UDP_SIZE`): `parse_packet_ip_v4()` "
         "demands IP header + 8 accessible bytes, a last fragment with a "
         "1–7 byte tail fails that check and is shot with `CALI_REASON_SHORT`. "
         "The datagram can never reassemble — silent loss, no PMTUD feedback, "
         "no counters outside felix's \"too short packets\".")
L.append("")
L.append("## What was sent (all probes DF-OFF — fragmentation is the point)")
L.append("")
if boundary:
    L.append(f"Pod MTU measured: **{mtu}** → per-fragment IP payload boundary: "
             f"**{boundary}**. Sweep sizes are derived from it, so each packet "
             "fragments AND the final fragment's tail lands exactly where we aim:")
L.append("")
L.append("| Payload size | Fragments | Last-fragment tail | In 1–7B bug band? | a→b delivered | b→a delivered |")
L.append("|---|---|---|---|---|---|")
for size, fc, tail in rows:
    band = "yes" if 1 <= tail <= 7 else "**no (control)**" if tail == 8 else "no"
    fwd = "✅" if udp_fwd_ok.get(size) else "❌"
    rev = "✅" if udp_rev_ok.get(size) else "❌"
    L.append(f"| {size} | {fc} | {tail} B | {band} | {fwd} | {rev} |")
L.append("")
L.append("Delivery = UDP echo with a SHA256-chosen payload; the reply must be "
         "**byte-exact**, so truncation or corruption counts as failure, not just loss. "
         "The 8-byte-tail size is the control: even the buggy dataplane passes it, "
         "proving the path itself is healthy.")
L.append("")
L.append("## Controls and guards")
L.append("")
L.append(f"- **DF control**: full-size DF ping at exact pod MTU: "
         f"{'PASS ✅' if df.get('df_at_mtu') == '1' else 'FAIL ❌'}; "
         f"one byte above MTU (must be rejected): "
         f"{'correctly dropped ✅' if df.get('df_over_mtu_fails') == '1' else 'WAS DELIVERED ❌ (DF not enforced — probes invalid)'}")
L.append(f"- **Fragments on the wire** (tcpdump on the receiving pod): "
         f"**{cap.get('fragments_on_wire', '?')}** captured — the oversized datagrams "
         "really were fragmented and reached the far side, so the loss is mid-path "
         "(the veth BPF), not at the sender")
L.append(f"- **felix \"too short packets\" counter**: before="
         f"{counters.get('too_short_before', '?')}, after="
         f"{counters.get('too_short_after', '?')} "
         "(best-effort: the public node image ships no `calico-bpf` CLI)")
L.append("- **CNI guards**: no flannel links on the node; the sink pod's IP "
         "routes over a `cali*` veth — the probe is running on real calico BPF, "
         "not a fallback CNI (a wrong-CNI cluster would make everything below vacuously green)")
L.append("- **ICMP raw sweep**: also runs (advisory): on stock BPF, raw-ICMP "
         "replies to workloads are policy-dropped, so that layer can't separate "
         "bug from noise — UDP is the authoritative signal")
L.append("")
L.append("## Raw files in this artifact")
L.append("")
L.append("| File | Content |")
L.append("|---|---|")
L.append("| `REPORT.md` | this file |")
L.append("| `report.json` | machine-readable verdict + all rows |")
L.append("| `udp-sweep.jsonl` / `udp-sweep-rev.jsonl` | per-size UDP echo results (SHA256 payload, byte-exact check) |")
L.append("| `icmp-sweep.jsonl` / `icmp-sweep-rev.jsonl` | per-size raw ICMP echo results (advisory) |")
L.append("| `df-control.txt` | DF-at-MTU control results |")
L.append("| `capture.txt` / `capture-sample.txt` | tcpdump fragment capture count + sample |")
L.append("| `felix-counters.txt` | felix too-short counter before/after |")
L.append("| `guards.txt` | only present if a guard FAILED (then the run aborts) |")
L.append("")
L.append("## Verdict semantics")
L.append("")
L.append("- **BUG REPRODUCED** → the `stock` GitHub check is **RED on purpose**: "
         "the bug is still present in the image under test. It flips green when "
         "an image delivers the whole band — i.e. when the fix lands.")
L.append("- **FIX VERIFIED** → green: the failure band is delivered byte-exact.")
L.append("- **INCONCLUSIVE** → red, different meaning: the harness itself could "
         "not reach a verdict (control failed, no fragments on wire, mixed shapes). "
         "Fix the harness, don't report either outcome.")

OUT.write_text("\n".join(L) + "\n")
print(f"REPORT.md written to {OUT}")
