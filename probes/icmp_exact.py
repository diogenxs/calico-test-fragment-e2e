#!/usr/bin/env python3
"""Exact-size IPv4 ICMP echo probe with byte-exact reply verification.

Sends one raw ICMP echo of an exact payload size with the DF bit OFF
(IP_PMTUDISC_DONT) and verifies the reply body is byte-identical to what
was sent — catches truncation/corruption, not just loss.

Ported from an existing icmp/udp integrity canary harness — same semantics.
"""
import argparse
import hashlib
import json
import socket
import struct
import time


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


parser = argparse.ArgumentParser()
parser.add_argument("destination")
parser.add_argument("size", type=int)
parser.add_argument("--timeout", type=float, default=2.0)
args = parser.parse_args()
if not 0 <= args.size <= 8000:
    parser.error("size must be between 0 and 8000")

ident = 0xBEEF
seq = int(time.time_ns() / 1e9) & 0xFFFF
payload = (hashlib.sha256(str(time.time_ns()).encode()).digest() * 250)[: args.size]
header = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
packet = struct.pack("!BBHHH", 8, 0, checksum(header + payload), ident, seq) + payload
result = {"size": args.size, "ip_size": args.size + 28, "destination": args.destination}
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
    sock.settimeout(args.timeout)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_PMTUDISC_DONT, 0)  # DF off — must fragment
    started = time.monotonic()
    sock.sendto(packet, (args.destination, 0))
    try:
        while True:
            reply, _ = sock.recvfrom(65535)
            ihl = (reply[0] & 0x0F) * 4
            kind, code, _, reply_id, reply_seq = struct.unpack("!BBHHH", reply[ihl : ihl + 8])
            if (kind, code, reply_id, reply_seq) != (0, 0, ident, seq):
                continue
            body = reply[ihl + 8 :]
            result.update(
                ok=body == payload,
                received=len(body),
                raw_received=len(reply),
                prefix_matches=body[: len(payload)] == payload,
                extra_tail=body[len(payload) :].hex(),
                rtt_ms=round((time.monotonic() - started) * 1000, 3),
            )
            break
    except TimeoutError as error:
        result.update(ok=False, error=str(error))
print(json.dumps(result))
raise SystemExit(0 if result.get("ok") else 1)
