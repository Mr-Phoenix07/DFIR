#!/usr/bin/env python3
"""mem_image_check.py - identify a memory image's format and OS before you point Volatility at it.

Usage: mem_image_check.py IMAGE [IMAGE ...]

Volatility picks a *translation layer* and *symbol table* from what the image actually is, so the
first question on any capture is "what am I holding?" This reads the first bytes of each file and
reports:

  * its size (and whether that looks like a plausible RAM amount);
  * its container format, by magic number - raw/padded, ELF core dump (Linpmem, /proc/kcore),
    LiME (Linux, Day 26), a Windows crash dump (PAGEDU / PAGEDUMP / PAGEDU64, Day 27), a Windows
    hibernation file (HIBR / hibr, Day 27), or EWF/E01 (expert witness);
  * any Linux kernel banner ("Linux version ...") in the first and last slice, which Volatility's
    own banners plugin uses to choose a Linux symbol table.

It does NOT parse OS structures - that is Volatility's job (processes, DLLs, handles, network).
This is the 30-second triage that tells you which Volatility layer and symbols you will need, and
flags a truncated or wrong-format file before it wastes an analysis run. Standard library only.
"""
import argparse
import os
import re
import sys

# (magic bytes, offset, label) - checked in order
MAGICS = [
    (b"\x7fELF", 0, "ELF core dump (e.g. Linpmem, /proc/kcore, crash) - Volatility: elf layer"),
    (b"EMiL", 0, "LiME format (Linux Memory Extractor, Day 26) - Volatility: lime layer"),
    (b"PAGEDU64", 0, "Windows crash dump, 64-bit (Day 27) - Volatility: crash layer"),
    (b"PAGEDUMP", 0, "Windows crash dump, 32-bit (Day 27) - Volatility: crash layer"),
    (b"PAGEDU", 0, "Windows crash dump (Day 27) - Volatility: crash layer"),
    (b"HIBR", 0, "Windows hibernation file (Day 27) - needs conversion first"),
    (b"hibr", 0, "Windows hibernation file, slimmed (Day 27) - needs conversion first"),
    (b"EVF\x09\x0d\x0a\xff\x00", 0, "EWF / E01 expert-witness image - Volatility reads it directly"),
    (b"\x53\xff\x00\xf0\x53\xff\x00\xf0", 0, "Windows hibernation (restored) slice"),
]
BANNER = re.compile(rb"Linux version \d[^\x00\n]{5,120}")


def human_size(n):
    v = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if v < 1024 or unit == "TiB":
            if unit == "B":
                return f"{int(v)} B"
            num = f"{v:.2f}".rstrip("0").rstrip(".")   # 16.00 -> 16, 1.50 -> 1.5
            return f"{num} {unit}"
        v /= 1024


def check(path):
    size = os.path.getsize(path)
    print(f"{path}")
    print(f"  size:   {size} bytes ({human_size(size)})")
    looks_ram = size % (1024 * 1024) == 0
    print(f"  pages:  {size // 4096} x 4096" + ("" if looks_ram else "   (not a whole number of MiB - truncated?)"))

    with open(path, "rb") as f:
        head = f.read(65536)
        if size > 65536:
            f.seek(max(0, size - 65536))
            tail = f.read(65536)
        else:
            tail = b""

    fmt = None
    for magic, off, label in MAGICS:
        if head[off:off + len(magic)] == magic:
            fmt = label
            break
    print(f"  format: {fmt if fmt else 'no known container magic -> raw / padded physical memory'}")

    banners = sorted(set(m.group(0).decode("latin-1", "replace") for m in BANNER.finditer(head + tail)))
    if banners:
        for b in banners[:3]:
            print(f"  banner: {b}")
    else:
        print("  banner: no Linux kernel banner in first/last 64 KiB "
              "(Windows image, or banner elsewhere - let Volatility's banners plugin scan it all)")


def main(paths):
    for i, p in enumerate(paths):
        if i:
            print()
        if not os.path.isfile(p):
            print(f"{p}\n  not a file")
            continue
        check(p)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("images", nargs="+")
    a = ap.parse_args()
    try:
        main(a.images)
    except BrokenPipeError:
        sys.exit(0)
