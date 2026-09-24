#!/usr/bin/env python3
"""Generate a complete, operator-valid ImageSet pinning calico/node to a
candidate digest while every other component stays at the operator's own
version (v3.32.2).

Contract (source-verified: tigera/operator pkg/controller/utils/imageset/
imageset.go + pkg/components/references.go):
  - the ImageSet is named after the OPERATOR'S OWN version (calico-v3.32.2),
    NOT the target image version — the operator looks up exactly that name
  - entry keys are "<default-image-path><name>" = "calico/<name>"
  - the set must contain EVERY component the operator renders, or validation
    fails ("ImageSet did not contain image calico/<x>")
  - digests below are the multi-arch INDEX digests for v3.32.2 (containerd
    resolves the per-arch child on pull), live-validated against the operator

Usage: gen-imageset.py --node-digest sha256:... > imageset.yaml
"""
import argparse

# v3.32.2 index digests, live-validated (operator accepted the full set and
# rendered digest-pinned refs for every component)
V3322 = {
    "apiserver": "sha256:f3f69d9be62e2ad84d0d7b7a47e5563cce484c603e95221145f569017d20bbbd",
    "cni": "sha256:0ef740bc587f25565905adf1d1f61a7faff0d571c449c6bdd789feed743d3ef7",
    "csi": "sha256:a4e6bc025131e754a96d9f4432bfc5e6cd42add6d59a701750988186d51d9b1f",
    "envoy-gateway": "sha256:051d9c9545c47b1e0e9f424cc63b69a937444d947a7d0a1b4a543cba64b2b41d",
    "envoy-proxy": "sha256:d68855196c31d8ae4586021d839703af4f03429ca5b84faa3b2318d3a42a9895",
    "envoy-ratelimit": "sha256:a506007cb1764f134f310a15e44a5da40e3a701d3d7f2fe485268b45180c7fe9",
    "goldmane": "sha256:0d04491bcf37a150408955837855fb97b4aa775ea5b3ba0d27f54874708f6838",
    "guardian": "sha256:cc62aca2b60e36b905c6e02cb4d1f5188619943b82c25e8cb176ae6eca49c3f7",
    "istio-install-cni": "sha256:9d3a9ecb60bdd00f56ac8eed598f465cb0d040007888bdccf841aa24c9018c52",
    "istio-pilot": "sha256:1b80b20cd2ab18c3f3d4ba6717afde92e3df6e1ec9db6ef7a03836f2ffcc234b",
    "istio-proxyv2": "sha256:6cf90e29e632e6e6d665de6126963d9ef363bc8869c0fd939a0110f57c91f5a4",
    "istio-ztunnel": "sha256:7420419e86be88f1de132156d28983ff3bc6f3c4b8843cf11b79e01d02c8d48f",
    "key-cert-provisioner": "sha256:aa66718e7f331ec6ff565c2b6100fcf47c6ba6c22d52fe3c86e68689303330bb",
    "kube-controllers": "sha256:7870b67ebb13fabc3005252b44fe6e78b21635649bd3072b80afa1684b6565d0",
    "node-driver-registrar": "sha256:abbeca287aeae48927b37cef8cbc17601357b132382ca6be4deb327c2c8d9aa2",
    "pod2daemon-flexvol": "sha256:a759b3914d5898a66751ee57871199ef870d0f42bdc3f9115fe1ded3b1a6ce01",
    "typha": "sha256:62b67d7ec399335e9e1a5681c793796126aee8764467308b2c9c4b0f60ce8a01",
    "webhooks": "sha256:93d689019b8c2b62ff044c0d3c49c2a1c40c7c2f7ad68e6ab1bf982295acc71d",
    "whisker": "sha256:b1313d6f65fc4c87ccbfd2f373353a2f8df7e59df5a4e5c84e77cab06818e597",
    "whisker-backend": "sha256:9c82844238c9f7eb6feb3fac1e0c62437bf520a15c7be1580b6909eaa537d479",
}

p = argparse.ArgumentParser()
p.add_argument("--node-digest", required=True, help="candidate calico/node image digest")
a = p.parse_args()

out = [
    "apiVersion: operator.tigera.io/v1",
    "kind: ImageSet",
    "metadata:",
    "  name: calico-v3.32.2",
    "spec:",
    "  images:",
    "    - image: calico/node",
    "      digest: %s" % a.node_digest,
]
for name in sorted(V3322):
    if name == "node":
        continue
    out.append("    - image: calico/%s" % name)
    out.append("      digest: %s" % V3322[name])
print("\n".join(out))
