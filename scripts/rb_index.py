#!/usr/bin/env python3
"""rb_index.py - decode Recycle Bin index files: $I files (Vista-11) and INFO2 (XP), byte by byte.

Usage: rb_index.py FILE [FILE ...]        ($I... files or INFO2; folders are searched recursively)

$I files ($Recycle.Bin\\<SID>\\$I<random>.<ext>), one per deleted item; its content is in $R<same name>:
  0  int64  version: 1 = Vista to 8.1, 2 = Windows 10/11
  8  int64  original size in bytes (for a folder: the size of everything in it)
  16 FILETIME deletion time (UTC)
  v1: 24  original path, UTF-16, fixed 520 bytes (260 characters)
  v2: 24  int32 path length in characters (with the final NUL), 28  path, UTF-16
INFO2 (XP: RECYCLER\\<SID>\\INFO2) is one file for all items: a 20-byte header (version, ...,
record size at offset 12), then fixed-size records: ANSI path (260 bytes), record number (the 'n' in
the Dc<n>.<ext> content file), drive number (0 = A:), deletion FILETIME, size, Unicode path.
Standard library only; an independent check of RBCmd's output.
"""
import datetime
import os
import struct
import sys


def filetime(v):
    return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)).strftime("%Y-%m-%d %H:%M:%S")


def dollar_i(path, data):
    version, size, deleted = struct.unpack_from("<qqq", data, 0)
    if version == 1:
        name = data[24:24 + 520].decode("utf-16-le").split("\0", 1)[0]
    elif version == 2:
        length = struct.unpack_from("<i", data, 24)[0]
        name = data[28:28 + 2 * length].decode("utf-16-le").rstrip("\0")
    else:
        print(f"{path}: unknown $I version {version}")
        return
    print(f"{os.path.basename(path)}  v{version}  {len(data):>4} bytes  deleted {filetime(deleted)}  "
          f"size {size:>10}  {name}")


def info2(path, data):
    version, _, _, recsize = struct.unpack_from("<IIII", data, 0)
    print(f"{os.path.basename(path)}  version {version}, {recsize}-byte records")
    for off in range(20, len(data) - recsize + 1, recsize):
        rec = data[off:off + recsize]
        index, drive, deleted, size = struct.unpack_from("<IIqI", rec, 260)
        name = rec[280:280 + 520].decode("utf-16-le").split("\0", 1)[0]
        ansi = rec[:260].split(b"\0", 1)[0].decode("latin-1")
        status = "" if ansi else "  (ANSI path's first byte zeroed: removed from the bin)"
        print(f"  Dc{index}  drive {chr(65 + drive)}:  deleted {filetime(deleted)}  size {size:>10}  {name}{status}")


def handle(path):
    with open(path, "rb") as f:
        data = f.read()
    base = os.path.basename(path)
    if base.upper().startswith("INFO2"):
        info2(path, data)
    elif base.startswith("$I"):
        dollar_i(path, data)


def main(args):
    if not args:
        sys.exit(__doc__)
    for a in args:
        if os.path.isdir(a):
            for root, dirs, files in os.walk(a):
                dirs.sort()
                for f in sorted(files):
                    handle(os.path.join(root, f))
        else:
            handle(a)


if __name__ == "__main__":
    main(sys.argv[1:])
