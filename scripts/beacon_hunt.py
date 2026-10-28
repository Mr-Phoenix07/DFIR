#!/usr/bin/env python3
"""beacon_hunt.py - find C2 beaconing in a PCAP by the regularity of its connections.

Usage: beacon_hunt.py FILE.pcap [--min-conns N] [--cv Z]

A beacon is malware calling home on a schedule. Any one connection looks ordinary; the tell is the
*cadence* - many connections to one destination at a near-constant interval. This reads a libpcap
file, takes each TCP connection start (a lone SYN), groups them by destination IP:port, and for each
destination reports how many there were, the mean interval between them, and the jitter as a
coefficient of variation (stdev / mean). A low CV over many connections is a beacon; human browsing
is bursty and irregular (high CV, or too few connections to matter).

This is the core idea behind RITA (which runs it over Zeek's conn.log at enterprise scale, with more
signals - data sizes, FQDN rarity, duration). Here it runs standalone on a capture so you can see the
method. A low-jitter destination is a strong lead, not a verdict: confirm the destination and that the
regularity isn't a legitimate poll (update check, NTP, telemetry). Standard library only; DLT_EN10MB.
"""
import argparse
import statistics
import struct
import sys


def syn_starts(path):
    data = open(path, "rb").read()
    if data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        sys.exit("not a libpcap file")
    le = data[:4] == b"\xd4\xc3\xb2\xa1"
    end = "<" if le else ">"
    off = 24
    out = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, caplen, _ = struct.unpack_from(end + "IIII", data, off)
        off += 16
        pkt = data[off:off + caplen]
        off += caplen
        if len(pkt) < 14 + 20 or pkt[12:14] != b"\x08\x00":
            continue
        ip = pkt[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 6:                                   # TCP only
            continue
        dst_ip = ".".join(str(b) for b in ip[16:20])
        tcp = ip[ihl:]
        if len(tcp) < 14:
            continue
        dport = struct.unpack_from(">H", tcp, 2)[0]
        flags = tcp[13]
        if flags & 0x12 == 0x02:                         # SYN set, ACK clear = connection start
            out.append((ts_sec + ts_usec / 1e6, f"{dst_ip}:{dport}"))
    return out


def main(path, min_conns, cv_thresh):
    starts = syn_starts(path)
    groups = {}
    for t, dest in starts:
        groups.setdefault(dest, []).append(t)
    print(f"{'destination':<24} {'conns':>5} {'mean_s':>8} {'jitter_cv':>10}  verdict")
    rows = []
    for dest, times in groups.items():
        times.sort()
        if len(times) < 2:
            rows.append((dest, len(times), 0.0, 0.0, "too few"))
            continue
        deltas = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.fmean(deltas)
        cv = (statistics.pstdev(deltas) / mean) if mean else 0.0
        beacon = len(times) >= min_conns and cv < cv_thresh
        rows.append((dest, len(times), mean, cv, "BEACON" if beacon else "-"))
    for dest, n, mean, cv, verdict in sorted(rows, key=lambda r: (r[4] != "BEACON", -r[1])):
        print(f"{dest:<24} {n:>5} {mean:>8.1f} {cv:>10.3f}  {verdict}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("pcap")
    ap.add_argument("--min-conns", type=int, default=8)
    ap.add_argument("--cv", type=float, default=0.15)
    a = ap.parse_args()
    main(a.pcap, a.min_conns, a.cv)
