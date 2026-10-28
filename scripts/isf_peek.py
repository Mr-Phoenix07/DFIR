#!/usr/bin/env python3
"""isf_peek.py - summarise a Volatility Intermediate Symbol File (ISF), the output of dwarf2json.

Usage: isf_peek.py kernel.isf.json

Volatility turns raw memory into structure using an ISF: a JSON file of the kernel's types, symbols
and enums for one exact build. For Windows it downloads the matching ISF automatically (Day 24); for
Linux and macOS there is no symbol server, so you build the ISF yourself with dwarf2json from the
kernel's DWARF debug info (full types) and/or its System.map / kallsyms (symbols only). This prints
the ISF's metadata and how many of each kind it holds, so you can confirm a built ISF before putting
it in Volatility's symbols directory.

A symbols-only ISF (from System.map/kallsyms) has symbols but no user_types - enough for some
address lookups, but full analysis needs the types from a DWARF-bearing vmlinux. Standard library
only; run with -I since the JSON is tool output.
"""
import json
import sys


def main(path):
    with open(path) as f:
        isf = json.load(f)
    meta = isf.get("metadata", {})
    producer = meta.get("producer", {})
    print(f"{path}")
    print(f"  producer: {producer.get('name', '?')} {producer.get('version', '')}".rstrip())
    for osname in ("linux", "mac", "windows"):
        if osname in meta:
            srcs = meta[osname].get("symbols", []) or meta[osname].get("types", [])
            kinds = ",".join(sorted({s.get("kind", "?") for s in srcs})) if srcs else "-"
            print(f"  target: {osname}   sources: {kinds}")
    for kind in ("base_types", "user_types", "enums", "symbols"):
        print(f"  {kind:11}: {len(isf.get(kind, {}))}")
    types = "types+symbols" if isf.get("user_types") else "symbols only (no types - add a DWARF vmlinux for full analysis)"
    print(f"  completeness: {types}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
