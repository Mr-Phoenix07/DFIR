#!/usr/bin/env python3
"""sysmon_linux_view.py - print Sysmon for Linux events from syslog lines, one per line.

Usage: sysmon_linux_view.py [SYSLOG_FILE ...]        (reads standard input when no file is given)

Sysmon for Linux writes each event to syslog as one line holding the event's XML
(`... sysmon: <Event><System>...</System><EventData>...</EventData></Event>`). This prints
the event ID, its name and the fields that identify what happened. Fields that change on every
run (times, process IDs and GUIDs, source ports) are left out, so two runs of the same activity
print the same lines. /opt/sysmon/sysmonLogView, installed with Sysmon, prints every field.
"""
import re
import sys
import xml.etree.ElementTree as ET

NAMES = {1: "ProcessCreate", 3: "NetworkConnect", 4: "ServiceStateChange", 5: "ProcessTerminate",
         9: "RawAccessRead", 11: "FileCreate", 16: "ConfigChange", 23: "FileDelete", 255: "Error"}
SHOW = {  # event ID -> fields to print, in this order
    1: ["RuleName", "Image", "CommandLine", "ParentImage"],
    3: ["RuleName", "Image", "Protocol", "Initiated", "DestinationIp", "DestinationPort"],
    4: ["State", "Version", "SchemaVersion"],
    5: ["Image"],
    11: ["RuleName", "Image", "TargetFilename"],
    16: ["Configuration", "ConfigurationFileHash"],
    23: ["Image", "TargetFilename"],
}


def events(lines):
    for line in lines:
        m = re.search(r"<Event>.*</Event>", line)
        if " sysmon: " not in line or not m:
            continue
        ev = ET.fromstring(m.group(0))
        eid = int(ev.findtext("System/EventID"))
        data = {d.get("Name"): (d.text or "") for d in ev.iter("Data")}
        yield eid, data


def main(paths):
    streams = [open(p, encoding="utf-8", errors="replace") for p in paths] or [sys.stdin]
    for f in streams:
        for eid, data in events(f):
            fields = SHOW.get(eid, sorted(data))
            shown = " | ".join(f"{k}={data[k]}" for k in fields if k in data and data[k] not in ("", "-"))
            print(f"{eid:>3} {NAMES.get(eid, '?'):<18} {shown}")


if __name__ == "__main__":
    main(sys.argv[1:])
