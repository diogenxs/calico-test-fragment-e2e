#!/usr/bin/env python3
"""TCP transfer integrity client — run inside the source pod.

Streams --bytes of deterministic pseudo-random data, receives the
SHA256 hexdigest of what the server saw, and reports byte-exact
integrity + throughput as one JSON line. TCP is the negative control:
it must pass even on dataplanes that drop the 1-7-byte-tail fragments.
"""
import argparse
import hashlib
import json
import socket
import time

p = argparse.ArgumentParser()
p.add_argument("destination")
p.add_argument("--port", type=int, default=37001)
p.add_argument("--bytes", type=int, default=10485760)
a = p.parse_args()


def gen(n):
    """Deterministic byte stream (seeded SHA256 expansion)."""
    out = b""
    block = hashlib.sha256(b"tcp-control").digest()
    while len(out) < n:
        out += block
        block = hashlib.sha256(block).digest()
    return out[:n]


data = gen(a.bytes)
expected = hashlib.sha256(data).hexdigest()
result = {"bytes": a.bytes, "destination": a.destination, "port": a.port}
with socket.create_connection((a.destination, a.port), timeout=10) as s:
    s.settimeout(30)
    started = time.monotonic()
    s.sendall(data)
    s.shutdown(socket.SHUT_WR)
    digest = b""
    while len(digest) < 64:
        chunk = s.recv(64 - len(digest))
        if not chunk:
            break
        digest += chunk
    elapsed = time.monotonic() - started
result.update(
    ok=digest.decode(errors="replace") == expected,
    server_sha256=digest.decode(errors="replace")[:64],
    elapsed_s=round(elapsed, 3),
    mbps=round((a.bytes * 8 / elapsed / 1e6), 1) if elapsed > 0 else None,
)
print(json.dumps(result), flush=True)
raise SystemExit(0 if result["ok"] else 1)
