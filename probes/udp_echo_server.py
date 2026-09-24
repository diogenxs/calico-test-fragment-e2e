#!/usr/bin/env python3
"""Minimal UDP echo server — run inside the destination (sink) pod.

Replies with the exact bytes received (the integrity contract the sweep
verifies). One process per port.
"""
import argparse
import socket

p = argparse.ArgumentParser()
p.add_argument("--port", type=int, default=37000)
a = p.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", a.port))
print(f"udp echo on :{a.port}", flush=True)
while True:
    data, addr = sock.recvfrom(65535)
    sock.sendto(data, addr)
