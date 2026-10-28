#!/usr/bin/env python3
"""lime_view.py - read the range headers of a LiME-format memory image.

Usage: lime_view.py IMAGE

LiME (and AVML, which writes the same format) stores physical memory as System RAM ranges, each
preceded by a 32-byte header (magic "EMiL", version, s_addr, e_addr inclusive, 8 reserved bytes).
This walks those headers and prints each range's physical span and size, the gaps between ranges
(non-System-RAM holes that a raw/padded image would have zero-filled), and the totals - the quick
check that an acquisition is well-formed and covers what you expect, before handing it to Volatility.

It validates each magic and that the ranges fit the file; it does not decode memory contents.
Standard library only.
"""
import struct
import sys

MAGIC = 0x4C694D45
HDR = 32


def main(path):
    data = open(path, "rb").read()
    off, ranges = 0, []
    while off + HDR <= len(data):
        magic, version, s_addr, e_addr = struct.unpack_from("<IIQQ", data, off)
        if magic != MAGIC:
            sys.exit(f"bad magic {magic:#x} at offset {off} (not a LiME image, or corrupt)")
        length = e_addr - s_addr + 1
        body = off + HDR
        if body + length > len(data):
            sys.exit(f"range at {off} claims {length} bytes but the file ends early (truncated)")
        ranges.append((s_addr, e_addr, length, version))
        off = body + length
    trailing = len(data) - off
    print(f"{path}: {len(ranges)} range(s), LiME version {ranges[0][3] if ranges else '?'}")
    prev_end = None
    for s_addr, e_addr, length, _ in ranges:
        if prev_end is not None and s_addr > prev_end + 1:
            gap = s_addr - (prev_end + 1)
            print(f"    -- gap: {gap} bytes of non-System-RAM ({prev_end + 1:#x}..{s_addr - 1:#x}) --")
        print(f"  {s_addr:#014x} - {e_addr:#014x}   {length:>10} bytes")
        prev_end = e_addr
    total = sum(r[2] for r in ranges)
    print(f"  total System RAM: {total} bytes in {len(ranges)} range(s); file {len(data)} bytes"
          + (f"; {trailing} trailing bytes" if trailing else ""))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
