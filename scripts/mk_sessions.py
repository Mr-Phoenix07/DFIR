#!/usr/bin/env python3
"""mk_sessions.py - generate a large, deterministic set of network session records for Day 30.

Usage: python3 mk_sessions.py OUT.csv [--rows N]

Tools like Arkime, Zui and Malcolm don't grep packets at terabyte scale - they reduce a capture to
one **session record** per connection (the 5-tuple, times, byte counts, service) and index those in a
searchable store (OpenSearch / a Zed lake). This writes that kind of dataset as CSV: ~N ordinary
flows from an internal /24 out to the internet over a day, with the WS-ALICE **beacon** (10.20.30.40
-> 203.0.113.50:443, every ~60s, small and regular) hidden inside - the needle you'll query for.

Byte-identical on every run (values derived from SHA-256 of a counter, no RNG). It represents the
metadata the big platforms index, so the labs can show the index-and-query workflow with SQLite in
place of a cluster. Standard library only.
"""
import argparse
import csv
import hashlib
import struct
import sys

SERVICES = {443: "ssl", 80: "http", 53: "dns", 22: "ssh", 123: "ntp", 445: "smb"}
DPORTS = [443, 443, 443, 80, 80, 53, 53, 123, 22, 445]
BASE = 1792000000
BEACONS = 200


def rb(seed, n):
    """Deterministic bytes from a labelled counter."""
    return hashlib.sha256(seed.encode() + struct.pack("<I", n)).digest()


def normal(i):
    h = rb("flow", i)
    src = f"10.20.30.{10 + h[0] % 200}"
    dst = f"{30 + h[1] % 170}.{h[2]}.{h[3]}.{1 + h[4] % 254}"
    dport = DPORTS[h[5] % len(DPORTS)]
    sport = 1024 + (struct.unpack('<H', h[6:8])[0] % 60000)
    ts = BASE + (struct.unpack('<I', h[8:12])[0] % 86400)
    dur = round((h[12] % 600) / 10.0, 1)
    sb = 200 + struct.unpack('<H', h[13:15])[0] % 20000
    db = 200 + struct.unpack('<H', h[15:17])[0] % 200000
    return [ts, src, sport, dst, dport, "tcp" if dport != 53 else "udp",
            SERVICES.get(dport, "-"), dur, sb, db, "SF"]


def beacon(i):
    ts = BASE + 3600 + i * 60 + (i * 7) % 5           # every ~60s with small jitter
    sport = 49000 + (i % 200)
    sb = 512 + (i * 3) % 40                            # small, consistent payloads
    db = 1024 + (i * 5) % 60
    return [ts, "10.20.30.40", sport, "203.0.113.50", 443, "tcp", "ssl", 0.3, sb, db, "SF"]


def main(out, rows):
    recs = [normal(i) for i in range(rows - BEACONS)] + [beacon(i) for i in range(BEACONS)]
    recs.sort(key=lambda r: (r[0], r[1], r[2], r[3]))   # by time, then a stable tie-break
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ts", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
                    "service", "duration", "src_bytes", "dst_bytes", "state"])
        w.writerows(recs)
    print(f"wrote {out}: {len(recs)} session records ({BEACONS} of them a beacon)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("out")
    ap.add_argument("--rows", type=int, default=20000)
    a = ap.parse_args()
    main(a.out, a.rows)
