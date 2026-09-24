#!/usr/bin/env bash
# calico-test-fragment-e2e — driver for the short-tail IPv4 fragment e2e.
#
# Brings up a flannel-less k3d cluster (calico is the only CNI, BPF dataplane,
# no node-to-node mesh — routes exchanged via an external FRR container acting
# as the top-of-rack), runs the layered evidence probes, and emits a verdict:
#
#   BUG REPRODUCED — the image under test drops the failure-band sizes
#   FIX VERIFIED   — every probe passes on the image under test
#
# Exit code 0 in both cases (the harness itself must be green); exit code 2
# means the harness could not reach a verdict (environment broken, probe
# invalid — never report that as either outcome).
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K3D_CLUSTER="calico-frag-e2e"
K3S_IMAGE="rancher/k3s:v1.33.3-k3s1"
FRR_IMAGE="quay.io/frrouting/frr:10.2.1"
NETSHOOT_IMAGE="docker.io/nicolaka/netshoot:latest"
POD_NETWORK="10.42.0.0/16"
SVC_NETWORK="10.43.0.0/16"
BGP_AS="65001"
OPERATOR_MANIFEST_URL="${OPERATOR_MANIFEST_URL:-https://raw.githubusercontent.com/projectcalico/calico/v3.32.2/manifests/tigera-operator.yaml}"
CALICO_NODE_IMAGE="${CALICO_NODE_IMAGE:-}"   # empty = whatever stock the operator renders

log() { printf '\e[36m[e2e]\e[0m %s\n' "$*" >&2; }
die() { printf '\e[31m[e2e] FATAL\e[0m %s\n' "$*" >&2; exit 2; }

# ---------------------------------------------------------------- cluster up
cmd_up() {
    log "creating k3d cluster $K3D_CLUSTER (k3s $K3S_IMAGE, no flannel, no NP)"
    k3d cluster create "$K3D_CLUSTER" \
        --image "$K3S_IMAGE" \
        --servers 1 --agents 2 \
        --network k3d-network \
        --k3s-arg '--flannel-backend=none@server:0' \
        --k3s-arg '--disable-network-policy@server:0' \
        --k3s-arg '--disable=traefik@server:0' \
        --k3s-arg '--disable=metrics-server@server:0' \
        --k3s-arg '--node-taint=node-role.kubernetes.io/control-plane:NoSchedule@server:0' \
        --wait
    log "cluster ready"
}

# ------------------------------------------------------- deploy calico + ToR
cmd_deploy() {
    log "starting the FRR top-of-rack container on k3d-network"
    docker rm -f frr-tor >/dev/null 2>&1 || true
    docker run -d --name frr-tor --network k3d-network --privileged \
        "$FRR_IMAGE" >/dev/null
    # generate the bgpd config (per-daemon file layout: /etc/frr/bgpd.conf),
    # enable bgpd in the daemon table, restart, wait for it to accept sessions
    TOR_IP="$(docker inspect -f '{{ index (index .NetworkSettings.Networks "k3d-network") "IPAddress" }}' frr-tor)"
    log "FRR ToR at $TOR_IP"
    {
        echo "frr version 10"
        echo "frr defaults traditional"
        echo ""
        echo "router bgp $BGP_AS"
        echo " bgp router-id $TOR_IP"
        echo " no bgp ebgp-requires-policy"
        echo " neighbor K3SNODE peer-group"
        echo " neighbor K3SNODE remote-as $BGP_AS"
        # iBGP split-horizon: without route-reflector the ToR cannot
        # re-advertise node A's block to node B (same-AS peers). Make every
        # node a route-reflector client.
        echo " neighbor K3SNODE route-reflector-client"
        # explicit neighbors: the k3d NODE CONTAINER IPs (172.x), not pod CIDR —
        # calico's bird sessions originate from the node IP, and the manual
        # test proved this pattern Establishes in seconds.
        for c in $(docker ps --format '{{.Names}}' | grep -E "^k3d-$K3D_CLUSTER-(server|agent)"); do
            NODE_IP="$(docker inspect -f '{{ index (index .NetworkSettings.Networks "k3d-network") "IPAddress" }}' "$c")"
            echo " neighbor $NODE_IP peer-group K3SNODE"
        done
        echo " address-family ipv4 unicast"
        echo "  neighbor K3SNODE next-hop-self"
        echo " exit-address-family"
        echo "exit"
    } | docker exec -i frr-tor sh -c 'cat > /etc/frr/bgpd.conf'
    docker exec frr-tor sh -c "chown frr:frr /etc/frr/bgpd.conf && chmod 640 /etc/frr/bgpd.conf"
    docker exec frr-tor sh -c "sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons"
    docker restart frr-tor >/dev/null
    # wait for bgpd to accept a vtysh session
    for _ in $(seq 1 30); do
        docker exec frr-tor vtysh -c 'show bgp summary json' >/dev/null 2>&1 && break
        sleep 2
    done
    docker exec frr-tor vtysh -c 'show bgp summary' >/dev/null 2>&1 || die "FRR bgpd did not come up"

    log "applying stock tigera-operator manifest ($OPERATOR_MANIFEST_URL)"
    kubectl apply -f "$OPERATOR_MANIFEST_URL" >/dev/null
    log "waiting for the calico CRDs to be established"
    for _ in $(seq 1 60); do
        kubectl get crd installations.operator.tigera.io >/dev/null 2>&1 && break
        sleep 2
    done
    kubectl get crd installations.operator.tigera.io >/dev/null 2>&1 || die "operator CRDs never appeared"
    kubectl wait --for condition=Established crd/installations.operator.tigera.io --timeout=120s
    kubectl wait --for condition=Established crd/bgpconfigurations.crd.projectcalico.org --timeout=120s 2>/dev/null || true
    kubectl wait --for condition=Established crd/bgppeers.crd.projectcalico.org --timeout=120s 2>/dev/null || true
    kubectl apply -f "$REPO_ROOT/manifests/installation.yaml"
    kubectl apply -f "$REPO_ROOT/manifests/frr-tor-peer.yaml"

    # point the BGPPeer at the ToR container
    kubectl patch bgppeer frr-tor --type merge -p "{\"spec\":{\"peerIP\":\"$TOR_IP\"}}" \
        || die "could not patch BGPPeer frr-tor peerIP"

    if [ -n "$CALICO_NODE_IMAGE" ]; then
        # e.g. ghcr.io/org/calico-node:fix-frag -> registry ghcr.io/org/ + path node
        # the operator resolves <registry>calico/node (imagePath unset). We accept
        # full refs where the tail after the registry is calico/node[:tag].
        REG="$(dirname "$(dirname "$CALICO_NODE_IMAGE")")"
        TAG="$(echo "$CALICO_NODE_IMAGE" | awk -F: '{print $NF}')"
        log "candidate image: $CALICO_NODE_IMAGE (registry=$REG tag=$TAG)"
        kubectl patch installation default --type merge \
            -p "{\"spec\":{\"registry\":\"$REG\"}}" >/dev/null \
            || die "could not patch Installation.registry for the candidate image"
    fi

    log "waiting for tigera-operator deployment"
    kubectl -n tigera-operator wait --for=condition=Available deployment/tigera-operator --timeout=300s
    log "waiting for the calico-system namespace (operator creates it)"
    for _ in $(seq 1 60); do
        kubectl get namespace calico-system >/dev/null 2>&1 && break
        sleep 5
    done
    kubectl get namespace calico-system >/dev/null 2>&1 || die "operator never created calico-system"
    log "waiting for calico-node daemonset (calico is the CNI — nodes Ready only after)"
    for _ in $(seq 1 120); do
        DESIRED=$(kubectl -n calico-system get ds calico-node -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo 0)
        READY=$(kubectl -n calico-system get ds calico-node -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
        [ -n "$DESIRED" ] && [ "$DESIRED" != "0" ] && [ "$READY" = "$DESIRED" ] && break
        sleep 5
    done
    READY=$(kubectl -n calico-system get ds calico-node -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)
    DESIRED=$(kubectl -n calico-system get ds calico-node -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo 0)
    [ "$READY" = "$DESIRED" ] && [ -n "$DESIRED" ] && [ "$DESIRED" != "0" ] || {
        kubectl -n calico-system get pods >&2; die "calico-node never became ready (ready=$READY desired=$DESIRED)"; }
    log "calico healthy ($READY/$DESIRED)"
}

# ---------------------------------------------------------------- probe pods
cmd_probes() {
    log "deploying probe pods (netshoot, pinned to distinct agent nodes)"
    # k3s agents carry no role labels — pin nodeName explicitly, one pod per agent
    NODE_A="$(kubectl get nodes -o name | sort | sed -n 1p | cut -d/ -f2)"
    NODE_B="$(kubectl get nodes -o name | sort | sed -n 2p | cut -d/ -f2)"
    python3 - "$REPO_ROOT/manifests/probe-pods.yaml" "$REPO_ROOT/tmp/probe-pods-pinned.yaml" "$NODE_A" "$NODE_B" <<'PYEOF'
import sys
src, dst, a, b = sys.argv[1:5]
docs = open(src).read().split("\n---\n")
assert len(docs) == 2, "template shape changed"
assert all(d.count("nodeName: PLACEHOLDER") == 1 for d in docs), "placeholder missing"
docs[0] = docs[0].replace("nodeName: PLACEHOLDER", f"nodeName: {a}")
docs[1] = docs[1].replace("nodeName: PLACEHOLDER", f"nodeName: {b}")
open(dst, "w").write("\n---\n".join(docs))
print(f"pinned: frag-src -> {a}, frag-sink -> {b}")
PYEOF
    kubectl delete pod frag-src frag-sink --grace-period=0 --force >/dev/null 2>&1 || true
    kubectl apply -f "$REPO_ROOT/tmp/probe-pods-pinned.yaml"
    kubectl wait --for=condition=Ready pod/frag-src --timeout=300s
    kubectl wait --for=condition=Ready pod/frag-sink --timeout=300s
    SRC_IP="$(kubectl get pod frag-src -o jsonpath='{.status.podIP}')"
    SINK_IP="$(kubectl get pod frag-sink -o jsonpath='{.status.podIP}')"
    log "src=$SRC_IP sink=$SINK_IP"
    printf 'SRC_IP=%s\nSINK_IP=%s\n' "$SRC_IP" "$SINK_IP" | tee "$REPO_ROOT/tmp/probe-ips"
}

# ------------------------------------------------------------------- evidence
cmd_evidence() {
    log "running the layered evidence stack"
    bash "$REPO_ROOT/scripts/collect-evidence.sh"
}

# -------------------------------------------------------------------- verdict
cmd_verdict() {
    log "analyzing evidence"
    python3 "$REPO_ROOT/evidence/analyze.py" --dir "$REPO_ROOT/tmp/evidence"
}

cmd_destroy() {
    k3d cluster delete "$K3D_CLUSTER" >/dev/null 2>&1 || true
    docker rm -f frr-tor >/dev/null 2>&1 || true
    log "cluster destroyed"
}

mkdir -p "$REPO_ROOT/tmp"
case "${1:-}" in
    up)        cmd_up ;;
    deploy)    cmd_deploy ;;
    probes)    cmd_probes ;;
    evidence)  cmd_evidence ;;
    verdict)   cmd_verdict ;;
    destroy)   cmd_destroy ;;
    all)       cmd_up; cmd_deploy; cmd_probes; cmd_evidence; cmd_verdict ;;
    *) echo "usage: $0 {up|deploy|probes|evidence|verdict|destroy|all}" >&2; exit 64 ;;
esac
