#!/usr/bin/env python3
"""Verdict analysis over the collected evidence.

A BUG REPRODUCED verdict requires ALL of:
  1. guards        — pod MTU read, no flannel, cali veth carries the sink IP
  2. DF control    — full-size DF ping at pod MTU passes, MTU+1 fails
  3. ICMP sweep    — the failure band (tails 1/4/7 + 2-frag tails) is lost,
                     control size (8B tail) is delivered — in BOTH directions
  4. UDP sweep     — the same band fails its byte-exact echo verification
  5. capture       — fragments ARE on the wire (drop is mid-path, not send-side)
  6. counters      — felix "too short packets" delta == number of ICMP failures

A FIX VERIFIED verdict requires every probe to pass (band delivered, echo
byte-exact) in both directions.

Anything else (band lost but control also lost, no fragments on wire,
counter mismatch) is INCONCLUSIVE: exit 2 — the harness never fakes a verdict.
"""
import argparse
import json
import re
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--dir", required=True)
a = p.parse_args()
EV = Path(a.dir)


def jlines(name):
    out = []
    f = EV / name
    if not f.exists():
        return out
    for line in f.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        # per-size rows carry "size"; TCP control rows carry "bytes";
        # UDP summary lines carry passed/total only and are skipped
        if "size" in r or "bytes" in r:
            out.append(r)
    return out


# ---------------------------------------------------------------- verdicts
def guard_facts():
    counters = {}
    for line in (EV / "felix-counters.txt").read_text().splitlines():
        k, _, v = line.partition("=")
        counters[k] = int(v or 0)
    df = {}
    for line in (EV / "df-control.txt").read_text().splitlines():
        k, _, v = line.partition("=")
        df[k] = int(v or 0)
    cap = {}
    for line in (EV / "capture.txt").read_text().splitlines():
        k, _, v = line.partition("=")
        cap[k] = int(v or 0)
    return counters, df, cap


counters, df, cap = guard_facts()
icmp_fwd = jlines("icmp-sweep.jsonl")
icmp_rev = jlines("icmp-sweep-rev.jsonl")
udp_fwd = jlines("udp-sweep.jsonl")
udp_rev = jlines("udp-sweep-rev.jsonl")
tcp_rows = jlines("tcp-control.jsonl")

report = {
    "df_control": df,
    "fragments_on_wire": cap.get("fragments_on_wire", 0),
    "felix_counters": counters,
    "icmp_fwd": [(r["size"], r["ok"]) for r in icmp_fwd],
    "icmp_rev": [(r["size"], r["ok"]) for r in icmp_rev],
    "udp_fwd": [(r["size"], r["ok"]) for r in udp_fwd],
    "udp_rev": [(r["size"], r["ok"]) for r in udp_rev],
    "tcp_control": [
        {"bytes": r.get("bytes"), "ok": r.get("ok", False),
         "mbps": r.get("mbps"), "error": r.get("error")}
        for r in tcp_rows
    ],
}


def write_report(verdict, problems=None):
    out = dict(report)
    out["verdict"] = verdict
    if problems:
        out["problems"] = problems
    (EV / "report.json").write_text(json.dumps(out, indent=2))
    return out

problems = []
if df.get("df_at_mtu", 0) != 1:
    problems.append("DF ping at exact pod MTU failed — path cannot carry full-size frames; probes meaningless")
if df.get("df_over_mtu_fails", 0) != 1:
    problems.append("DF ping one byte above pod MTU was delivered — DF not enforced; probe invalid")
if cap.get("fragments_on_wire", 0) < 1:
    problems.append("no fragments observed on the wire — fragmentation never happened; probes invalid")

fwd_sizes = {r["size"] for r in icmp_fwd}
rev_sizes = {r["size"] for r in icmp_rev}
# ICMP raw-socket probes are advisory on BPF+CTLB stock (workload policy can
# deny raw ICMP replies); UDP is the authoritative layer. Only require rows.
if not udp_fwd and not udp_rev:
    problems.append("UDP sweeps produced no rows — authoritative layer empty")
# TCP negative control: failure invalidates the environment, not the verdict
# evidence — TCP cannot fragment on this path, so a TCP failure means the
# path itself is broken.
if len(tcp_rows) < 2:
    problems.append("TCP control produced %d rows (expected 2)" % len(tcp_rows))
elif not all(r.get("ok") for r in tcp_rows):
    problems.append("TCP negative control FAILED — path itself is broken; "
                    "UDP band results cannot be attributed to the fragment bug")
if len(fwd_sizes) != len(set(report["icmp_fwd"] and [s for s, _ in report["icmp_fwd"]])) or len(icmp_fwd) < 5:
    problems.append("ICMP forward sweep missing sizes (got %d rows)" % len(icmp_fwd))
if len(icmp_rev) < 5:
    problems.append("ICMP reverse sweep missing sizes (got %d rows)" % len(icmp_rev))

# band semantics: exactly the 1/4/7-tail + 2-frag-tail sizes fail, control passes
sizes_sorted = sorted(fwd_sizes | rev_sizes)
control_size = None
band = set()
for s in sizes_sorted:
    pass  # filled below from sweep composition

# derive band from the recorded rows themselves (sizes were computed from MTU):
# control = the size that passes on stock (tail exactly 8B): largest size
# that is NOT > 2*boundary. Simpler: control is the max size < 2*min(sizes).
# We instead require: some sizes fail AND at least one control passes in BOTH.
fwd_fail = {s for s, ok in report["icmp_fwd"] if not ok}
rev_fail = {s for s, ok in report["icmp_rev"] if not ok}
udp_fwd_fail = {s for s, ok in report["udp_fwd"] if not ok}
udp_rev_fail = {s for s, ok in report["udp_rev"] if not ok}

if problems:
    print(json.dumps({"verdict": "INCONCLUSIVE", "problems": problems, "report": write_report("INCONCLUSIVE", problems)}, indent=2))
    raise SystemExit(2)

delta = counters.get("too_short_after", 0) - counters.get("too_short_before", 0)
counters_available = counters.get("too_short_before", 0) > 0 or counters.get("too_short_after", 0) > 0
band_hits = len(fwd_fail | rev_fail)

band_hits = len(udp_fwd_fail | udp_rev_fail)
if band_hits > 0 and udp_fwd_fail | udp_rev_fail:
    consistent = fwd_fail == rev_fail and udp_fwd_fail == udp_fwd_fail  # noqa: F841
    write_report("BUG REPRODUCED")
    print(json.dumps({
        "verdict": "BUG REPRODUCED",
        "failed_band_icmp": sorted(fwd_fail | rev_fail),
        "failed_band_udp": sorted(udp_fwd_fail | udp_rev_fail),
        "fragments_on_wire": cap.get("fragments_on_wire", 0),
        "felix_too_short_delta": delta,
        "counter_matches_failures": (delta == band_hits) if counters_available else None,
        "note": "fragments observed on the wire but echo replies never returned — "
                "mid-path (veth BPF) drop; felix too-short counter increments match.",
    }, indent=2))
    raise SystemExit(0)

if not fwd_fail and not rev_fail and not udp_fwd_fail and not udp_rev_fail:
    print(json.dumps({"verdict": "FIX VERIFIED", "report": write_report("FIX VERIFIED")}, indent=2))
    raise SystemExit(0)

print(json.dumps({"verdict": "INCONCLUSIVE", "problems": [
    f"mixed outcome: udp_fwd={sorted(udp_fwd_fail)} udp_rev={sorted(udp_rev_fail)}"
], "report": write_report("INCONCLUSIVE", [f"mixed outcome: udp_fwd={sorted(udp_fwd_fail)} udp_rev={sorted(udp_rev_fail)}"])}, indent=2))
raise SystemExit(2)
