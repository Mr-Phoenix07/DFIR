#!/usr/bin/env python3
"""eve_summary.py - summarise a Suricata eve.json: alerts and logged flows.

Usage: eve_summary.py EVE_JSON

Suricata writes one JSON object per line to eve.json: signature **alerts**, and - the point of
network security monitoring - a **flow** record for every connection it saw, alert or not. This
prints the alert signatures with counts, the total flows logged, and the flows grouped by
destination IP (where a single destination with a high flow count is the first hint of a beacon).
It reads only the stable fields, so the output is reproducible. Standard library only; run with -I.
"""
import collections
import json
import sys


def main(path):
    alerts = collections.Counter()
    flows = 0
    by_dest = collections.Counter()
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        e = json.loads(line)
        et = e.get("event_type")
        if et == "alert":
            alerts[e["alert"]["signature"]] += 1
        elif et == "flow":
            flows += 1
            if "dest_ip" in e:
                by_dest[e["dest_ip"]] += 1
    print(f"alerts: {sum(alerts.values())}")
    for sig, n in sorted(alerts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  [{n}] {sig}")
    print(f"flows logged: {flows}")
    print("flows by destination:")
    for ip, n in sorted(by_dest.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {ip:<16} {n}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
