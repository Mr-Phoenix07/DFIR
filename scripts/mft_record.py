#!/usr/bin/env python3
"""mft_record.py - decode one NTFS $MFT FILE record, field by field, to learn the structure.

Usage:
  mft_record.py MFT_FILE ENTRY [--size 1024] [--hex]

MFT_FILE is an extracted $MFT (e.g. `icat image.raw 0 > MFT`). ENTRY is the record number (the
"inode" in The Sleuth Kit). It prints the record header, checks and applies the fixups (update
sequence array), then walks every attribute and decodes $STANDARD_INFORMATION, $FILE_NAME and $DATA
(resident content or the data runs). Times are UTC with full 100-ns precision.
Standard library only.
"""
import argparse
import datetime as dt
import signal
import struct
import sys

ATTR_TYPES = {0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST", 0x30: "$FILE_NAME", 0x40: "$OBJECT_ID",
              0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME", 0x70: "$VOLUME_INFORMATION", 0x80: "$DATA",
              0x90: "$INDEX_ROOT", 0xA0: "$INDEX_ALLOCATION", 0xB0: "$BITMAP", 0xC0: "$REPARSE_POINT",
              0xD0: "$EA_INFORMATION", 0xE0: "$EA", 0x100: "$LOGGED_UTILITY_STREAM"}
NAMESPACES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32 & DOS"}
FILE_ATTRS = [(0x1, "ReadOnly"), (0x2, "Hidden"), (0x4, "System"), (0x20, "Archive"), (0x100, "Temporary"),
              (0x200, "Sparse"), (0x400, "ReparsePoint"), (0x800, "Compressed"), (0x2000, "NotIndexed"),
              (0x4000, "Encrypted"), (0x10000000, "Directory")]


def ft(v):
    """FILETIME (100-ns ticks since 1601-01-01 UTC) -> text with 7 decimal places."""
    if v == 0:
        return "(zero)"
    secs, rem = divmod(v, 10_000_000)
    return f"{dt.datetime(1601, 1, 1) + dt.timedelta(seconds=secs):%Y-%m-%d %H:%M:%S}.{rem:07d}"


def flags(v, table):
    return "|".join(n for b, n in table if v & b) or "none"


def apply_fixups(rec):
    usa_off, usa_cnt = struct.unpack_from("<HH", rec, 4)
    usn = rec[usa_off:usa_off + 2]
    ok = True
    for i in range(1, usa_cnt):
        end = i * 512
        if rec[end - 2:end] != usn:
            ok = False
        rec[end - 2:end] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
    return usa_off, usa_cnt, usn.hex(), ok


def runs(data):
    """Decode a data-run list into (start_cluster, length) pairs (None start = sparse)."""
    out, pos, lcn = [], 0, 0
    while pos < len(data) and data[pos]:
        hdr = data[pos]
        ln_size, off_size = hdr & 0x0F, hdr >> 4
        length = int.from_bytes(data[pos + 1:pos + 1 + ln_size], "little")
        if off_size:
            lcn += int.from_bytes(data[pos + 1 + ln_size:pos + 1 + ln_size + off_size], "little", signed=True)
            out.append((lcn, length))
        else:
            out.append((None, length))
        pos += 1 + ln_size + off_size
    return out


def show_times(label, raw):
    c, m, r, a = struct.unpack_from("<4Q", raw, 0)
    print(f"      {label} Created        : {ft(c)}")
    print(f"      {label} Modified       : {ft(m)}")
    print(f"      {label} Record changed : {ft(r)}")
    print(f"      {label} Accessed       : {ft(a)}")


def main():
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mft")
    ap.add_argument("entry", type=int)
    ap.add_argument("--size", type=int, default=1024, help="FILE record size (default 1024)")
    ap.add_argument("--hex", action="store_true", help="also print the first 64 bytes")
    a = ap.parse_args()
    with open(a.mft, "rb") as f:
        f.seek(a.entry * a.size)
        rec = bytearray(f.read(a.size))
    if len(rec) < a.size:
        sys.exit("entry is beyond the end of the file")
    if a.hex:
        for i in range(0, 64, 16):
            print(f"  {i:04x}: {rec[i:i + 16].hex(' ')}")
    sig = bytes(rec[:4])
    if sig != b"FILE":
        sys.exit(f"signature is {sig!r}, not b'FILE' (BAAD = failed fixup check, zeros = never used)")
    lsn, seq, links, first, fl, used, alloc, base, next_id = struct.unpack_from("<QHHHHIIQH", rec, 8)
    usa_off, usa_cnt, usn, ok = apply_fixups(rec)
    print(f"FILE record {a.entry}")
    print(f"  $LogFile sequence number (LSN): {lsn}")
    print(f"  Sequence number               : {seq}   (bumped each time the record is reused)")
    print(f"  Hard link count               : {links}")
    print(f"  Flags                         : {fl:#06x} = {'IN USE' if fl & 1 else 'NOT IN USE (deleted)'}"
          f"{', DIRECTORY' if fl & 2 else ''}")
    print(f"  Used / allocated size         : {used} / {alloc} bytes")
    print(f"  Base record                   : {base & 0xFFFFFFFFFFFF}{' (this is an extension record)' if base else ''}")
    print(f"  Fixups                        : {usa_cnt - 1} sectors, USN {usn}, {'OK' if ok else 'MISMATCH (torn write?)'}")
    off = first
    while off + 8 <= a.size:
        atype, alen = struct.unpack_from("<II", rec, off)
        if atype == 0xFFFFFFFF or alen == 0:
            print(f"  End-of-attributes marker at offset {off:#x}")
            break
        nonres, nlen, noff, aflags, aid = struct.unpack_from("<BBHHH", rec, off + 8)
        aname = rec[off + noff:off + noff + 2 * nlen].decode("utf-16-le") if nlen else ""
        kind = "non-resident" if nonres else "resident"
        print(f"  Attribute {ATTR_TYPES.get(atype, hex(atype))}{':' + aname if aname else ''} "
              f"(type {atype:#x}, id {aid}, {kind}, {alen} bytes at offset {off:#x})")
        if not nonres:
            vlen, voff = struct.unpack_from("<IH", rec, off + 0x10)
            val = bytes(rec[off + voff:off + voff + vlen])
            if atype == 0x10:
                show_times("$SI", val)
                print(f"      File attributes : {flags(struct.unpack_from('<I', val, 0x20)[0], FILE_ATTRS)}")
                if vlen >= 72:
                    sid, = struct.unpack_from("<I", val, 0x34)
                    usn_si, = struct.unpack_from("<Q", val, 0x40)
                    print(f"      Security ID     : {sid}    $UsnJrnl USN of last change: {usn_si}")
            elif atype == 0x30:
                pref, = struct.unpack_from("<Q", val, 0)
                nl, ns = val[0x40], val[0x41]
                name = val[0x42:0x42 + 2 * nl].decode("utf-16-le")
                print(f"      Name            : {name}   (namespace {NAMESPACES.get(ns, ns)})")
                print(f"      Parent          : entry {pref & 0xFFFFFFFFFFFF}, sequence {pref >> 48}")
                show_times("$FN", val[8:])
                asz, rsz = struct.unpack_from("<QQ", val, 0x28)
                print(f"      Sizes in $FN    : allocated {asz}, real {rsz} (often stale: only updated on rename/move)")
            elif atype == 0x80:
                shown = val[:64]
                print(f"      Resident data   : {vlen} bytes: {shown!r}{' ...' if vlen > 64 else ''}")
        else:
            svcn, evcn, roff = struct.unpack_from("<QQH", rec, off + 0x10)
            asz, rsz, isz = struct.unpack_from("<QQQ", rec, off + 0x28)
            print(f"      Sizes           : allocated {asz}, real {rsz}, initialised {isz}")
            for lcn, ln in runs(rec[off + roff:off + alen]):
                print(f"      Data run        : {ln} cluster(s) at LCN {lcn}" if lcn is not None
                      else f"      Data run        : {ln} sparse cluster(s)")
        off += alen


if __name__ == "__main__":
    main()
