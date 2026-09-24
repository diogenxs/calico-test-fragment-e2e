#!/usr/bin/env python3
"""Bounded UDP echo integrity sweep — run inside the source pod.

Per size: unique source port (no late-reply contamination), SHA256 payload,
byte-exact echo verification. Emits one JSON per line + a summary line.

Ported from an existing icmp/udp integrity canary harness — same semantics.
"""
import argparse
import hashlib
import json
import socket
import time

p = argparse.ArgumentParser()
p.add_argument("destination")
p.add_argument("--port", type=int, default=37000)
p.add_argument("--sizes", required=True)
p.add_argument("--mode", choices=["dont", "want", "do"], default="dont")
p.add_argument("--timeout", type=float, default=1.5)
a = p.parse_args()
sizes = [int(n) for n in a.sizes.split(",")]
if len(sizes) > 200 or any(not 16 <= n <= 8000 for n in sizes):
    p.error("Use at most 200 payload sizes between 16 and 8000 bytes")
if not 0 < a.timeout <= 10:
    p.error("Timeout must be between 0 and 10 seconds")
results = []
for size in sizes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(a.timeout)
        s.setsockopt(socket.IPPROTO_IP, 10, {"dont": 0, "want": 1, "do": 2}[a.mode])
        s.connect((a.destination, a.port))
        seed = hashlib.sha256(str(time.time_ns()).encode()).digest()
        data = (seed * 250)[:size]
        result = {
            "size": size,
            "ip_size": size + 28,
            "mode": a.mode,
            "destination": a.destination,
            "source_port": s.getsockname()[1],
            "payload_sha256": hashlib.sha256(data).hexdigest(),
            "started_at_ns": time.time_ns(),
        }
        try:
            start = time.monotonic()
            s.send(data)
            reply = s.recv(65535)
            result.update(ok=reply == data, received=len(reply), rtt_ms=round((time.monotonic() - start) * 1000, 3))
        except OSError as e:
            result.update(ok=False, error=str(e))
        results.append(result)
        print(json.dumps(result), flush=True)
print(json.dumps({"passed": sum(r["ok"] for r in results), "total": len(results)}), flush=True)
raise SystemExit(0 if all(r["ok"] for r in results) else 1)
