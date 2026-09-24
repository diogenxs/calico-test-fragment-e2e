#!/usr/bin/env bash
# Local verification helpers (the CI workflow calls the same scripts).
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

usage() {
    cat <<'EOF'
make repro                 full local run against stock calico (expect BUG REPRODUCED)
make candidate IMAGE=ref   full run against a candidate image (expect FIX VERIFIED)
make evidence              collect evidence only (cluster must be up)
make verdict               analyze collected evidence only
make clean                 destroy the cluster + FRR container
EOF
    exit 64
}

case "${1:-}" in
    repro)    bash scripts/run-e2e.sh all ;;
    candidate) [ -n "${IMAGE:-}" ] || { echo "IMAGE=... required" >&2; exit 64; }
               CALICO_NODE_IMAGE="$IMAGE" bash scripts/run-e2e.sh all ;;
    evidence) bash scripts/run-e2e.sh evidence ;;
    verdict)  bash scripts/run-e2e.sh verdict ;;
    clean)    bash scripts/run-e2e.sh destroy ;;
    *)        usage ;;
esac
