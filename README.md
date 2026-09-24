# calico-test-fragment-e2e

End-to-end reproduction harness for a Calico **BPF-dataplane** bug: IPv4
packets that must fragment are silently dropped when the **last fragment
carries 1–7 bytes of payload** — felix's tc BPF program on the pod veth
(`FROM_WEP`) rejects any non-first fragment shorter than an IP header plus
8 bytes (`CALI_REASON_SHORT`), so the datagram can never reassemble.

Real-world shape: anything that lands in the 1..7-byte tail band — e.g. a
1473-byte UDP payload on a 1500 MTU pod (payload 1453 = 2×676 + 1), PMTUD
probe responses, or oversized DNS/QUIC frames — dies with no PMTUD feedback
and no counters outside felix's `too short packets`.

Runs entirely on **stock, public images** (quay.io/tigera/operator +
quay.io/calico/node) against a flannel-less k3d cluster on GitHub-hosted
runners. No vendor-specific anything.

## Topology

```
                 ┌──────────────┐
                 │  FRR "ToR"   │  (docker container on k3d-network,
                 │  bgpd/zebra  │   BGP AS 65001, neighbors every node)
                 └──────┬───────┘
             BGP (node ↔ ToR only — nodeToNodeMeshEnabled: false)
        ┌──────────────┴──────────────┐
   ┌────┴────┐                   ┌────┴────┐
   │ k3d n1  │                   │ k3d n2  │      (worker agents)
   │ frag-src│◄── cross-node ────►│frag-sink│     (probe pods)
   └─────────┘                   └─────────┘
```

- k3d 1 server + 2 agents, k3s **v1.33.3**, `--flannel-backend=none` —
  **calico is the only CNI**; nodes only become Ready after calico-node runs
- BPF dataplane, no encapsulation, BGP-enabled IPAM blocks
- Routes exchange ONLY through the FRR ToR container (fabric-like), never
  node-to-node
- Probe pods (netshoot) pinned to distinct worker nodes

## Evidence layers

| # | Layer | What it proves |
|---|-------|----------------|
| 0 | Guards | pod MTU read; no flannel links; sink pod's IP routes via a `cali*` veth |
| 1 | DF control | DF ping at exact pod MTU passes; one byte above fails (probe self-check) |
| 2 | ICMP sweep | exact-size raw-socket probes, DF off, **byte-exact reply verify** — across the failure band |
| 3 | UDP sweep | payload-SHA256 echo integrity — unique source port per size, byte-exact |
| 4 | Capture | tcpdump on the sink: **fragments observed on the wire** but echo never returns → mid-path drop |
| 5 | Counters | felix `too short packets` delta == ICMP failures → names the drop reason |

Sizes are **derived from the measured pod MTU** (`boundary = MTU - 20`):
tails of 1, 4, 7 bytes (single fragment), control tail of exactly 8 bytes
(passes even on stock), plus two-fragment datagrams with 1- and 4-byte tails
(proves the 1480-byte periodicity). Both directions.

## Verdicts

| Verdict | Meaning | CI |
|---|---|---|
| **BUG REPRODUCED** | failure band lost + control delivered + fragments on wire | **RED on purpose** — the public tracker of the bug; flips green when a stock image delivers the full band |
| **FIX VERIFIED** | every size delivered byte-exact, both directions | **green** (candidate images; also green on stock once the fix lands upstream — then retire the check) |
| **INCONCLUSIVE** | anything else (control also lost, no fragments, mixed shapes) | **red** — harness broken, neither verdict claimable |

Every run renders a human-readable `REPORT.md` (what was sent, why each size
was chosen, tail arithmetic, per-layer results) into the **job summary** and
the evidence artifact — the raw JSONL is still there, but you never need to
open it to understand the result.

The harness never fakes a verdict: it can only distinguish the two clean
outcomes; ambiguity fails the run.

## Usage

```bash
make repro                  # local run, stock images → BUG REPRODUCED
make candidate IMAGE=ghcr.io/you/calico-node:fix-frag
make evidence              # re-collect on a running cluster
make verdict               # re-analyze collected evidence
make clean
```

CI (`.github/workflows/e2e.yml`) runs `make repro` on every push/PR against
stock — a red `repro` job means the **harness broke**, not the bug went away;
`candidate` (workflow_dispatch with an image ref) expects FIX VERIFIED.

## Why these choices

- **BPF, not iptables** — the drop lives in the tc BPF programs attached to
  pod veths; an iptables dataplane run is vacuous for this bug. A companion
  matrix run proved iptables+VXLAN is clean on stock (see README history).
- **FRR ToR** — with the mesh disabled, cross-node routing must transit the
  ToR; this mirrors fabric deployments and forces the BGP-advertised block
  path the real failure was observed on.
- **No Molecule/Ansible** — plain bash + kubectl: fewer moving parts for an
  upstream-readable repro.
- **CTLB off** — runner kernels can reject the connect-time-LB attach;
  irrelevant to the fragment path (test-only deviation, documented in
  `manifests/felix-ctlb-off.yaml`).

## References

- Bug analysis + fix: felix `parse_packet_ip_v4()` short-tail fragment
  rejection (`CALI_REASON_SHORT`) — see the felix BPF sources in the
  calico/felix repo, `bpf-gpl/` UDP_SIZE constant.
- Probes ported from an existing icmp/udp integrity canary harness with the
  same JSONL output contracts.
