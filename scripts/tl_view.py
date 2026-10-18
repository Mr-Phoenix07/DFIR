#!/usr/bin/env python3
"""tl_view.py - merge, filter and print Plaso CSV timelines compactly in a terminal.

Usage: tl_view.py FILE.csv [FILE2.csv ...] [--from ISO] [--to ISO] [--grep REGEX] [--tag REGEX] [--width N]

Input: psort "dynamic" CSV files with at least the fields datetime, timestamp_desc, source and
message (psort -o dynamic --fields datetime,timestamp_desc,source,source_long,message,display_name).
Several files (for example one per storage file) are merged into one time-ordered list.

What it does to make a super timeline readable on screen:
  - one line per moment and item: the same datetime and message seen under several timestamp
    descriptions (Plaso writes one event per timestamp) becomes one line, with the descriptions
    combined; file times are shown as MACB (M modified, A accessed, C metadata changed, B born)
  - long messages are shortened: event-log records to "EVTX <id> <provider>: <the readable
    strings>", $MFT records to "$SI/$FN <path>", file-stat records to the path
  - --from/--to keep a time window (ISO, UTC, compared as text: 2026-09-29T01:00),
    --grep keeps lines whose full original message or source file matches REGEX (case-insensitive),
    --tag keeps events whose Plaso tags (the "tag" field, after psort --analysis tagging) match REGEX
Standard library only. For real work, open the CSV in Timeline Explorer or load the .plaso file
into Timesketch: this is a quick look, not a replacement.
"""
import argparse
import ast
import csv
import re
import sys

MACB = {"Content Modification Time": "M", "Last Access Time": "A",
        "Metadata Modification Time": "C", "Creation Time": "B"}
WORDS = {"Creation Time": "born", "Content Modification Time": "modified", "Last Access Time": "accessed",
         "Metadata Modification Time": "changed", "Last Visited Time": "visited", "Start Time": "start",
         "End Time": "end", "Last Time Executed": "last run", "Previous Last Time Executed": "earlier run"}
SKIP = re.compile(r"^(-|S-1-[\d-]+|0x[0-9a-fA-F]+|%%\d+|\{?[0-9A-Fa-f-]{36}\}?|\d+|None|WORKGROUP|"
                  r"(MD5|SHA1|SHA256|IMPHASH)=.*)$")


def shorten(msg):
    m = re.match(r"\[(\d+) / 0x[0-9a-f]+\] (?:Provider identifier: \{[^}]*\} )?Source Name: (.*?) Strings: \[(.*?)\] "
                 r"(?:Hostname|Computer Name):", msg)
    if m:
        eid, provider, strings = m.groups()
        provider = provider.replace("Microsoft-Windows-", "")
        seen, keep = set(), []
        for s in re.findall(r"'(?:[^'\\]|\\.)*'", strings):
            try:
                s = ast.literal_eval(s)           # the strings are Python literals: undo the escaping
            except (ValueError, SyntaxError):
                s = s.strip("'")
            s = " ".join(s.split())[:100]
            if s and not SKIP.match(s) and s.lower() not in seen:
                seen.add(s.lower())
                keep.append(s)
        return f"EVTX {eid} {provider}: " + "; ".join(keep)
    m = re.match(r"NTFS:\\\$MFT File reference: (\S+) Attribute name: \$(STANDARD_INFORMATION|FILE_NAME)"
                 r".*?Path hints: ([^;]*)", msg)
    if m:
        ref, attr, path = m.groups()
        return f"{'$SI' if attr == 'STANDARD_INFORMATION' else '$FN'} {path}  (MFT {ref})"
    m = re.match(r"(?:NTFS|OS):(\S.*?) Type: (file|directory)$", msg)
    if m:
        return f"file {m.group(1)}"
    return msg


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--from", dest="start")
    ap.add_argument("--to", dest="end")
    ap.add_argument("--grep")
    ap.add_argument("--tag")
    ap.add_argument("--width", type=int, default=150)
    a = ap.parse_args()
    pattern = re.compile(a.grep, re.I) if a.grep else None
    tag = re.compile(a.tag, re.I) if a.tag else None
    merged = {}
    for path in a.files:
        with open(path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                dt = r["datetime"]
                if (a.start and dt < a.start) or (a.end and dt > a.end):
                    continue
                if pattern and not (pattern.search(r["message"]) or pattern.search(r.get("display_name", ""))):
                    continue
                if tag and not tag.search(r.get("tag", "") or ""):
                    continue
                key = (dt, r["source"], shorten(r["message"]))
                merged.setdefault(key, set()).add(r["timestamp_desc"])
    for (dt, source, text), descs in sorted(merged.items()):
        if source == "FILE" and descs <= set(MACB):        # file times as MACB
            what = "".join(c if c in {MACB[d] for d in descs} else "." for c in "MACB")
        elif source == "EVT":                                # an event record: when it was written
            what = "recorded"
        elif source == "REG" and descs == {"Content Modification Time"}:
            what = "key written"
        else:
            what = "+".join(sorted(WORDS.get(d, d.replace(" Time", "").lower()) for d in descs))
        line = f"{dt[:10]} {dt[11:23]}  {source:<7} {what:<11} {text}"
        print(line[:a.width])


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
