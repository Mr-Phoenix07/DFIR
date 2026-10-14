#!/usr/bin/env python3
"""ese_header.py - show the file header of an ESE (JET Blue) database: SRUDB.dat, Windows.edb, ntds.dit...

Usage: ese_header.py FILE.dat [FILE2.dat ...]

Prints the format, page size and the database STATE: 3 = clean shutdown (every change is in the
file), 2 = dirty shutdown (copied while in use, or the system stopped: recent changes may still sit
in the transaction logs, *.log, next to it). Also the consistent / attach / detach times and the log
generation the database needs. On Windows, `esentutl /mh FILE` shows the same and
`esentutl /r <base> /i` + `esentutl /p FILE` replay the logs and repair (on a COPY). Standard
library only; offsets follow libesedb's format documentation. The header has a copy at offset 4096.
"""
import struct
import sys

STATES = {1: "just created", 2: "dirty shutdown", 3: "clean shutdown", 4: "being converted", 5: "force detach"}


def logtime(h, off):
    s, mi, hr, d, mo, y = struct.unpack_from("<6B", h, off)
    return "-" if not any((s, mi, hr, d, mo, y)) else f"{1900 + y:04d}-{mo:02d}-{d:02d} {hr:02d}:{mi:02d}:{s:02d}"


def lgpos(h, off):
    ib, isec, gen = struct.unpack_from("<HHI", h, off)
    return f"generation {gen:#x}" if gen else "-"


def show(path):
    with open(path, "rb") as f:
        h = f.read(4096)
    sig, fmt, ftype = struct.unpack_from("<III", h, 4)
    state = struct.unpack_from("<I", h, 0x34)[0]
    rev, page = struct.unpack_from("<II", h, 0xE8)
    print(path)
    if sig != 0x89ABCDEF:
        print("  not an ESE database (no 0x89ABCDEF signature at offset 4)")
        return
    print(f"  format {fmt:#x},{rev}  page size {page}  file type {'database' if ftype == 0 else 'streaming file'}")
    print(f"  state {state} ({STATES.get(state, 'unknown')})")
    print(f"  consistent {logtime(h, 0x40)} ({lgpos(h, 0x38)})")
    print(f"  attach     {logtime(h, 0x48)} ({lgpos(h, 0x50)})")
    print(f"  detach     {logtime(h, 0x58)} ({lgpos(h, 0x60)})")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for p in sys.argv[1:]:
        show(p)
