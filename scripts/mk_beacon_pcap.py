#!/usr/bin/env python3
"""mk_beacon_pcap.py - a PCAP with a regular C2 beacon buried in noise, for the Day 29 labs.

Usage: python3 mk_beacon_pcap.py OUT.pcap

Beacon detection needs *many* connections over time, not one. This writes a deterministic libpcap
(DLT_EN10MB, valid Ethernet/IPv4/TCP, correct checksums) in which WS-ALICE calls home to the C2
203.0.113.50:443 every ~60 seconds for 24 beacons (a few seconds of deterministic jitter each), while
a handful of ordinary web connections to other hosts happen at irregular times. Each connection is a
short SYN/SYN-ACK/ACK/RST so Suricata and tcpdump see real flows. The regular cadence to one
destination, low in jitter, is the signature a RITA-style analyzer keys on. Teaching traffic, not a
real capture. Standard library only.
"""
import struct
import sys

CM = bytes.fromhex("020000000a28")
GW = bytes.fromhex("0200000000fe")
CLIENT = bytes(map(int, "10.20.30.40".split(".")))
C2 = bytes(map(int, "203.0.113.50".split(".")))
NOISE_IPS = [bytes(map(int, ip.split("."))) for ip in
             ("93.184.216.34", "140.82.121.4", "151.101.1.69", "142.250.72.14")]


def csum(d):
    if len(d) % 2:
        d += b"\x00"
    s = sum(struct.unpack(f">{len(d)//2}H", d))
    s = (s >> 16) + (s & 0xFFFF)
    return (~(s + (s >> 16))) & 0xFFFF


def ipv4(src, dst, payload, ident):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, 6, 0, src, dst)
    h = h[:10] + struct.pack(">H", csum(h)) + h[12:]
    return h + payload


def tcp(src, dst, sport, dport, seq, ack, flags):
    seg = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 64240, 0, 0)
    pseudo = src + dst + struct.pack(">BBH", 0, 6, len(seg))
    return seg[:16] + struct.pack(">H", csum(pseudo + seg)) + seg[18:]


def conn(pkts, t, src, dst, smac, dmac, sport, dport, ident):
    """A short TCP connection: SYN, SYN-ACK, ACK, RST. Appends (sec,usec,frame) tuples."""
    def add(dt, a, b, amac, bmac, sp, dp, seq, ack, fl, idn):
        frame = bmac + amac + b"\x08\x00" + ipv4(a, b, tcp(a, b, sp, dp, seq, ack, fl), idn)
        pkts.append((int(t + dt), int((t + dt) % 1 * 1_000_000), frame))
    add(0.000, src, dst, smac, dmac, sport, dport, 1000, 0, 0x02, ident)
    add(0.030, dst, src, dmac, smac, dport, sport, 2000, 1001, 0x12, ident)
    add(0.031, src, dst, smac, dmac, sport, dport, 1001, 2001, 0x10, ident)
    add(0.400, src, dst, smac, dmac, sport, dport, 1001, 2001, 0x14, ident)   # RST-ACK (close)


def main(out):
    pkts = []
    base = 1792000000
    # 24 beacons to the C2, every 60s with a small deterministic jitter
    for i in range(24):
        t = base + i * 60 + (i * 7) % 5
        conn(pkts, t, CLIENT, C2, CM, GW, 49000 + i, 443, 100 + i)
    # noise: ordinary web browsing to other hosts at irregular times
    noise_times = [15, 133, 204, 377, 512, 820, 999, 1330]
    for j, dt in enumerate(noise_times):
        conn(pkts, base + dt, CLIENT, NOISE_IPS[j % len(NOISE_IPS)], CM, GW, 51000 + j, 443, 900 + j)
    pkts.sort(key=lambda p: (p[0], p[1]))
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for sec, usec, raw in pkts:
            f.write(struct.pack("<IIII", sec, usec, len(raw), len(raw)) + raw)
    print(f"wrote {out}: {len(pkts)} packets, {24} beacons + {len(noise_times)} noise connections")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
