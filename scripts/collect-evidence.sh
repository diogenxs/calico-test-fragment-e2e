#!/usr/bin/env bash
# Layered evidence collection — runs INSIDE the source probe pod unless noted.
# Every step writes JSONL/JSON into tmp/evidence/ for analyze.py.
#
# Layers:
#   0. pod MTU + CNI guards (cali veth present, flannel absent)
#   1. DF control  — full-size DF ping at exact pod MTU must PASS
#   2. ICMP sweep  — exact-size raw-socket probes across the failure band
#   3. UDP sweep   — payload-SHA256 echo integrity across the failure band
#   4. capture     — tcpdump on the sink: fragments observed on the wire
#   5. counters    — calico-node felix "too short packets" delta == failures
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EV="$REPO_ROOT/tmp/evidence"
mkdir -p "$EV"

POD=frag-src
KX() { kubectl exec "$POD" -- "$@" >/dev/null 2>&1; }     # silent
KXO() { kubectl exec "$POD" -- "$@"; }                     # output

log() { printf '\e[36m[e2e]\e[0m %s\n' "$*" >&2; }

# ------------------------------------------------------- layer 0: guards
MTU="$(KXO ip -o link show eth0 | grep -oE 'mtu [0-9]+' | awk '{print $2}')"
log "pod MTU: $MTU"
BOUNDARY=$((MTU - 20))          # bytes of IP payload per fragment frame
log "boundary: $BOUNDARY"

# sizes: last-frag tails 1,4,7 (single-frag) + control 8B + 2-frag 1B tail
SIZES="$((BOUNDARY-7)),$((BOUNDARY-4)),$((BOUNDARY-1)),$BOUNDARY,$((BOUNDARY*2-7)),$((BOUNDARY*2-4))"
log "sweep sizes: $SIZES"

# flannel guard: flannel.1 / cni0 must NOT exist on the node
NODE_A="$(kubectl get pod -o jsonpath='{.spec.nodeName}' frag-src)"
NODE_B="$(kubectl get pod -o jsonpath='{.spec.nodeName}' frag-sink)"
FLANNEL_A="$(docker exec "$NODE_A" sh -c 'ip link show flannel.1 2>/dev/null | wc -l')"
echo "flannel present on $NODE_A: $FLANNEL_A"
[ "$FLANNEL_A" -eq 0 ] || { echo "FLANNEL GUARD FAILED" | tee "$EV/guards.txt"; exit 2; }

# cali veth guard: sink pod IP must map to a cali* veth on its node
SINK_IP="$(kubectl get pod frag-sink -o jsonpath='{.status.podIP}')"
VETH="$(docker exec "$NODE_B" sh -c "ip route | grep '$SINK_IP' | grep -oE 'cali[0-9a-f]+' | head -1")"
log "sink veth: $VETH"
[ -n "$VETH" ] || { echo "CALI VETH GUARD FAILED for $SINK_IP" | tee "$EV/guards.txt"; exit 2; }

# snapshot felix counters before the sweep (best-effort: not every image
# ships the calico-bpf binary; absence is recorded, not fatal)
read_too_short() {
    # best-effort: images without the calico-bpf CLI yield an empty string.
    # NEVER let this kill the evidence run (set -e + pipefail protection).
    local out=""
    out="$(kubectl -n calico-system exec ds/calico-node -c calico-node -- calico-bpf stats 2>/dev/null \
        | grep -i 'too short' | awk '{print $NF}' | head -1 || true)"
    printf '%s' "$out"
}
BEFORE="$(read_too_short)"
[ -n "$BEFORE" ] || BEFORE=0
echo "too_short_before=$BEFORE" | tee "$EV/felix-counters.txt"

# ------------------------------------------------------- layer 1: DF control
# a full-size DF ping at the exact pod MTU must pass (path carries pod MTU);
# MTU+1-28 must fail (proves the DF bit is honored — guards the probe itself)
DF_OK=1; DF_OVER_OK=1
KXO ping -c 2 -W 3 -M do -s $((MTU-28)) "$SINK_IP" || DF_OK=0
KXO ping -c 2 -W 3 -M do -s $((MTU-27)) "$SINK_IP" && DF_OVER_OK=0 || true
printf 'df_at_mtu=%s\ndf_over_mtu_fails=%s\n' "$DF_OK" "$DF_OVER_OK" | tee "$EV/df-control.txt"

# ------------------------------------------------------- layer 2: ICMP sweep
log "ICMP exact-size sweep (raw socket, no DF)"
# copy the probe into the source pod, run it against the sink
kubectl cp "$REPO_ROOT/probes/icmp_exact.py" "$POD:/icmp_exact.py" >/dev/null
kubectl cp "$REPO_ROOT/probes/udp_echo_server.py" frag-sink:/udp_echo_server.py >/dev/null
kubectl cp "$REPO_ROOT/probes/udp_echo_sweep.py" "$POD:/udp_echo_sweep.py" >/dev/null
kubectl exec frag-sink -- sh -c 'nohup python3 /udp_echo_server.py --port 37000 >/dev/null 2>&1 &' || true
# tcpdump capture on the sink (fragments only)
kubectl exec frag-sink -- sh -c 'rm -f /tmp/frag.pcap; nohup tcpdump -i eth0 -c 200 -n "ip[6:2] & 0x3fff != 0" -w /tmp/frag.pcap >/tmp/tcpdump.log 2>&1 &' || true

for SZ in ${SIZES//,/ }; do
    kubectl exec "$POD" -- python3 /icmp_exact.py "$SINK_IP" "$SZ" >> "$EV/icmp-sweep.jsonl" 2>/dev/null || \
        echo "{\"size\": $SZ, \"ok\": false, \"error\": \"probe rc!=0\"}" >> "$EV/icmp-sweep.jsonl"
done

# ------------------------------------------------------- layer 3: UDP sweep
log "UDP echo integrity sweep (payload SHA256)"
# BOTH echo servers up-front (a->b needs sink's, b->a needs src's);
# stagger ports so the reverse sweep can't hit a stale socket
kubectl cp "$REPO_ROOT/probes/udp_echo_server.py" frag-sink:/udp_echo_server.py >/dev/null
kubectl cp "$REPO_ROOT/probes/udp_echo_server.py" "$POD:/udp_echo_server.py" >/dev/null
kubectl exec frag-sink -- sh -c 'nohup python3 /udp_echo_server.py --port 37000 >/dev/null 2>&1 &' || true
kubectl exec "$POD" -- sh -c 'nohup python3 /udp_echo_server.py --port 37000 >/dev/null 2>&1 &' || true
sleep 2
kubectl exec "$POD" -- python3 /udp_echo_sweep.py "$SINK_IP" --sizes "$SIZES" \
    > "$EV/udp-sweep.jsonl" 2>/dev/null || true
# reverse direction: sink -> src
kubectl cp "$REPO_ROOT/probes/icmp_exact.py" frag-sink:/icmp_exact.py >/dev/null
kubectl cp "$REPO_ROOT/probes/udp_echo_sweep.py" frag-sink:/udp_echo_sweep.py >/dev/null
SRC_IP="$(kubectl get pod frag-src -o jsonpath='{.status.podIP}')"
for SZ in ${SIZES//,/ }; do
    kubectl exec frag-sink -- python3 /icmp_exact.py "$SRC_IP" "$SZ" >> "$EV/icmp-sweep-rev.jsonl" 2>/dev/null || \
        echo "{\"size\": $SZ, \"ok\": false, \"error\": \"probe rc!=0\"}" >> "$EV/icmp-sweep-rev.jsonl"
done
kubectl exec frag-sink -- python3 /udp_echo_sweep.py "$SRC_IP" --sizes "$SIZES" \
    > "$EV/udp-sweep-rev.jsonl" 2>/dev/null || true

# ------------------------------------------------------- layer 4: capture
sleep 3
FRAGS="$(kubectl exec frag-sink -- sh -c 'tcpdump -nn -r /tmp/frag.pcap 2>/dev/null | wc -l')"
echo "fragments_on_wire=$FRAGS" | tee "$EV/capture.txt"
kubectl exec frag-sink -- sh -c 'tcpdump -nn -r /tmp/frag.pcap 2>/dev/null | head -40' > "$EV/capture-sample.txt" || true

# ------------------------------------------------------- layer 5: counters
AFTER="$(read_too_short)"
[ -n "$AFTER" ] || AFTER="$BEFORE"
echo "too_short_after=$AFTER" | tee -a "$EV/felix-counters.txt"
log "evidence collection complete"
