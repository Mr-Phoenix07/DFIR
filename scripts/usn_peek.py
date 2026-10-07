#!/usr/bin/env python3
"""usn_peek.py - decode an NTFS change journal ($UsnJrnl:$J) record by record.

Usage:
  usn_peek.py J_FILE                      every record: offset, USN, time, file, parent, reasons, name
  usn_peek.py J_FILE --summary            counts by record version and by reason
  usn_peek.py J_FILE --name PATTERN       only records whose name contains PATTERN (case-insensitive)

Handles USN_RECORD_V2 and V3 (records with names) and V4 (range-tracking records, no name). Skips the
sparse, zero-filled start of a real $J quickly. Each record is checked (length, version, name inside
the record) before it is trusted; anything that fails is skipped 8 bytes at a time and counted, so
you can see when a file is damaged or isn't a journal. Times are UTC with 100-ns precision.
Standard library only; meant for learning and for cross-checking other parsers.
"""
import argparse
import datetime as dt
import mmap
import re
import signal
import struct
import sys
from collections import Counter

REASONS = [
    (0x00000001, "DataOverwrite"), (0x00000002, "DataExtend"), (0x00000004, "DataTruncation"),
    (0x00000010, "NamedDataOverwrite"), (0x00000020, "NamedDataExtend"), (0x00000040, "NamedDataTruncation"),
    (0x00000100, "FileCreate"), (0x00000200, "FileDelete"), (0x00000400, "EaChange"),
    (0x00000800, "SecurityChange"), (0x00001000, "RenameOldName"), (0x00002000, "RenameNewName"),
    (0x00004000, "IndexableChange"), (0x00008000, "BasicInfoChange"), (0x00010000, "HardLinkChange"),
    (0x00020000, "CompressionChange"), (0x00040000, "EncryptionChange"), (0x00080000, "ObjectIdChange"),
    (0x00100000, "ReparsePointChange"), (0x00200000, "StreamChange"), (0x00400000, "TransactedChange"),
    (0x00800000, "IntegrityChange"), (0x80000000, "Close"),
]
NONZERO = re.compile(rb"[^\x00]")


def reasons(mask):
    return "|".join(name for bit, name in REASONS if mask & bit) or hex(mask)


def filetime(ft):
    if ft == 0:
        return ""
    secs, rem = divmod(ft, 10_000_000)
    t = dt.datetime(1601, 1, 1) + dt.timedelta(seconds=secs)
    return f"{t:%Y-%m-%d %H:%M:%S}.{rem:07d}"


def ref64(r):
    """NTFS file reference: low 48 bits = MFT entry, high 16 bits = sequence number."""
    return f"{r & 0xFFFFFFFFFFFF}-{r >> 48}"


def parse(buf, off):
    """Return a dict for a valid record at off, or None."""
    if off + 8 > len(buf):
        return None
    length, major, minor = struct.unpack_from("<IHH", buf, off)
    if length < 0x38 or length > 0x10000 or length % 8 or off + length > len(buf) or major not in (2, 3, 4):
        return None
    rec = {"offset": off, "length": length, "version": major}
    if major == 2:
        if length < 0x3C:
            return None
        fref, pref, usn, ts, reason, src, sec, attrs, nlen, noff = struct.unpack_from("<QQqQIIIIHH", buf, off + 8)
        rec.update(file=ref64(fref), parent=ref64(pref))
    elif major == 3:
        if length < 0x4C:
            return None
        flo, fhi, plo, phi = struct.unpack_from("<QQQQ", buf, off + 8)
        usn, ts, reason, src, sec, attrs, nlen, noff = struct.unpack_from("<qQIIIIHH", buf, off + 40)
        rec.update(file=ref64(flo), parent=ref64(plo))
    else:  # V4: range tracking, no timestamp and no name
        flo, fhi, plo, phi, usn, reason, src = struct.unpack_from("<QQQQqII", buf, off + 8)
        if usn != off:
            return None
        rec.update(file=ref64(flo), parent=ref64(plo), usn=usn, time="", reason=reason, name="", attrs=0)
        return rec
    if usn != off or nlen % 2 or noff + nlen > length:
        return None  # in a $J file a record's USN equals its offset
    rec.update(usn=usn, time=filetime(ts), reason=reason, attrs=attrs,
               name=bytes(buf[off + noff:off + noff + nlen]).decode("utf-16-le", "replace"))
    return rec


def walk(buf):
    off, junk = 0, 0
    while off + 8 <= len(buf):
        if struct.unpack_from("<Q", buf, off)[0] == 0:
            m = NONZERO.search(buf, off)
            if not m:
                break
            off = m.start() & ~7
            continue
        rec = parse(buf, off)
        if rec is None:
            junk += 8
            off += 8
            continue
        yield rec
        off += rec["length"]
    walk.junk = junk


def main():
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # quiet when piped into head
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("jfile")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--name", help="show only records whose name contains this text")
    args = ap.parse_args()
    with open(args.jfile, "rb") as f:
        try:
            buf = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:
            sys.exit("empty file")
    versions, why = Counter(), Counter()
    if not args.summary:
        print("Offset\tUSN\tTimestamp(UTC)\tEntry-Seq\tParent\tReasons\tName")
    for r in walk(buf):
        versions[r["version"]] += 1
        for _, n in REASONS:
            if n in reasons(r["reason"]).split("|"):
                why[n] += 1
        if args.summary or (args.name and args.name.lower() not in r["name"].lower()):
            continue
        name = r["name"] if r["version"] != 4 else "(V4 range-tracking record)"
        print(f"{r['offset']}\t{r['usn']}\t{r['time']}\t{r['file']}\t{r['parent']}\t{reasons(r['reason'])}\t{name}")
    if args.summary:
        print("Records by version: " + ", ".join(f"V{k}: {v}" for k, v in sorted(versions.items())))
        print(f"Bytes skipped as not-a-record: {walk.junk}")
        print("Records by reason flag:")
        for n, c in why.most_common():
            print(f"  {c:>6}  {n}")


if __name__ == "__main__":
    main()
