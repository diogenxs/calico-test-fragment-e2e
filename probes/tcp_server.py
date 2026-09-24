#!/usr/bin/env python3
"""TCP transfer integrity server — run inside the destination pod.

Accepts repeated connections; reads exactly --bytes, replies with the
SHA256 hexdigest of what it received, closes. Negative-control layer:
TCP must be UNAFFECTED by the fragment drop (MSS keeps segments below
the path MTU, so TCP never fragments and never lands in the 1-7B band).
"""
import argparse
import hashlib
import socket

p = argparse.ArgumentParser()
p.add_argument("--port", type=int, default=37001)
p.add_argument("--bytes", type=int, default=10485760)
a = p.parse_args()

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", a.port))
srv.listen(4)
print(f"tcp integrity server on :{a.port}, expecting {a.bytes} bytes/conn", flush=True)
while True:
    conn, addr = srv.accept()
    h = hashlib.sha256()
    remaining = a.bytes
    while remaining > 0:
        chunk = conn.recv(min(65536, remaining))
        if not chunk:
            break
        h.update(chunk)
        remaining -= len(chunk)
    conn.sendall(h.hexdigest().encode())
    conn.close()
