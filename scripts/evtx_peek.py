#!/usr/bin/env python3
"""evtx_peek.py - show the structure of a Windows XML event log (.evtx) file.

Usage: evtx_peek.py FILE.evtx [--records N] [--templates]

Prints the file header and every chunk header (with CRC32 checks), and optionally
  --records N   the first N event records of each chunk: size, record ID, time written,
                which template they use and the types of their substitution values
  --templates   the templates defined in each chunk (offset, GUID, size, element names)

Layout follows the libevtx documentation ("Windows XML Event Log (EVTX) format").
Standard library only; read-only.
"""
import struct
import sys
import uuid
import zlib
from datetime import datetime, timedelta, timezone

VALUE_TYPES = {0x00: "Null", 0x01: "String", 0x02: "AnsiString", 0x03: "Int8", 0x04: "UInt8", 0x05: "Int16",
               0x06: "UInt16", 0x07: "Int32", 0x08: "UInt32", 0x09: "Int64", 0x0A: "UInt64", 0x0B: "Real32",
               0x0C: "Real64", 0x0D: "Bool", 0x0E: "Binary", 0x0F: "GUID", 0x10: "SizeT", 0x11: "FILETIME",
               0x12: "SYSTEMTIME", 0x13: "SID", 0x14: "HexInt32", 0x15: "HexInt64", 0x21: "BinXml",
               0x81: "String[]"}


def filetime(v):
    if v == 0:
        return "-"
    t = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=v // 10)
    return t.strftime("%Y-%m-%d %H:%M:%S.") + f"{v % 10_000_000:07d}"


def name_at(chunk, off):
    """A BinXML name structure: next offset (4), hash (2), characters (2), UTF-16, NUL."""
    n = struct.unpack_from("<H", chunk, off + 6)[0]
    return chunk[off + 8:off + 8 + n * 2].decode("utf-16-le", "replace")


def element_names(chunk, start, end):
    """Walk a template body and list the element and attribute names it defines, in order."""
    names, i = [], start
    while i < end:
        tok = chunk[i]
        if tok in (0x01, 0x41):                       # open start element: dep id, size, name offset
            off = struct.unpack_from("<I", chunk, i + 7)[0]
            names.append(name_at(chunk, off))
            i += 11
            if off == i:
                i += 8 + struct.unpack_from("<H", chunk, i + 6)[0] * 2 + 2
            if tok == 0x41:
                i += 4
        elif tok in (0x06, 0x46):                     # attribute: name offset
            off = struct.unpack_from("<I", chunk, i + 1)[0]
            names.append("@" + name_at(chunk, off))
            i += 5
            if off == i:
                i += 8 + struct.unpack_from("<H", chunk, i + 6)[0] * 2 + 2
        elif tok in (0x05, 0x45):                     # value text: type, length-prefixed UTF-16
            i += 2 + 2 + struct.unpack_from("<H", chunk, i + 2)[0] * 2
        elif tok in (0x0D, 0x0E):                     # substitution: index, type
            i += 4
        elif tok == 0x0F:
            i += 4
        elif tok in (0x02, 0x03, 0x04):
            i += 1
        elif tok == 0x00:
            break
        else:
            names.append(f"<token 0x{tok:02x}>")
            break
    return names


def main(path, records=0, templates=False):
    data = open(path, "rb").read()
    h = data[:128]
    if h[:8] != b"ElfFile\0":
        sys.exit(f"{path}: not an EVTX file (signature {h[:8]!r})")
    first, last, next_id, hsize, minor, major, block, nchunks = struct.unpack_from("<QQQIHHHH", h, 8)
    flags, stored = struct.unpack_from("<II", h, 120)
    calc = zlib.crc32(h[:120]) & 0xFFFFFFFF
    state = ", ".join(n for b, n in ((1, "DIRTY"), (2, "FULL")) if flags & b) or "clean"
    print(f"File            : {path} ({len(data)} bytes)")
    print(f"Format version  : {major}.{minor}    header size {hsize}, header block {block} bytes")
    print(f"Chunks          : {nchunks} in header (first {first}, last {last}); "
          f"{(len(data) - block) // 65536} chunk slots in the file")
    print(f"Next record ID  : {next_id}")
    print(f"Flags           : 0x{flags:x} ({state})")
    print(f"Header CRC32    : stored 0x{stored:08x}, calculated 0x{calc:08x} -> {'OK' if stored == calc else 'MISMATCH'}")
    for n in range(nchunks):
        base = block + n * 65536
        c = data[base:base + 65536]
        if c[:8] != b"ElfChnk\0":
            print(f"\nChunk {n} at 0x{base:x}: no ElfChnk signature")
            continue
        fnum, lnum, fid, lid, chsize, last_off, free_off, rec_crc = struct.unpack_from("<QQQQIIII", c, 8)
        hdr_crc = struct.unpack_from("<I", c, 124)[0]
        calc_h = zlib.crc32(c[:120] + c[128:512]) & 0xFFFFFFFF
        calc_r = zlib.crc32(c[512:free_off]) & 0xFFFFFFFF
        strings = sum(1 for i in range(64) if struct.unpack_from("<I", c, 128 + i * 4)[0])
        tmpls = [struct.unpack_from("<I", c, 384 + i * 4)[0] for i in range(32)]
        print(f"\nChunk {n} at file offset 0x{base:x}")
        print(f"  Records       : IDs {fid}-{lid} (numbers {fnum}-{lnum}), {lid - fid + 1} records")
        print(f"  Last record at: 0x{last_off:x}; free space from 0x{free_off:x} ({65536 - free_off} bytes free)")
        print(f"  Header CRC32  : stored 0x{hdr_crc:08x}, calculated 0x{calc_h:08x} -> {'OK' if hdr_crc == calc_h else 'MISMATCH'}")
        print(f"  Records CRC32 : stored 0x{rec_crc:08x}, calculated 0x{calc_r:08x} -> {'OK' if rec_crc == calc_r else 'MISMATCH'}")
        print(f"  String table  : {strings} of 64 buckets used; template table: {sum(1 for t in tmpls if t)} of 32 used")
        if templates:
            seen, todo = set(), [t for t in tmpls if t]
            while todo:
                off = todo.pop(0)
                if off in seen or off == 0:
                    continue
                seen.add(off)
                nxt, = struct.unpack_from("<I", c, off)
                guid = uuid.UUID(bytes_le=bytes(c[off + 4:off + 20]))
                size, = struct.unpack_from("<I", c, off + 20)
                names = element_names(c, off + 24, off + 24 + size)
                print(f"  Template at 0x{off:04x}: GUID {guid}, {size} bytes: {' '.join(names[:12])}"
                      + (" ..." if len(names) > 12 else ""))
                todo.append(nxt)
        off, shown = 512, 0
        while off < free_off and shown < records:
            sig, size, rid, written = struct.unpack_from("<IIQQ", c, off)
            if sig != 0x00002A2A:
                print(f"  0x{off:04x}: no record signature")
                break
            body = c[off + 24:off + size - 4]
            desc = ""
            i = 4 if body[:1] == b"\x0f" else 0
            if body[i:i + 1] == b"\x0c":
                tid, toff = struct.unpack_from("<II", body, i + 2)
                j = i + 10
                inline = (off + 24 + j) == toff
                if inline:
                    j += 24 + struct.unpack_from("<I", body, j + 20)[0]
                count, = struct.unpack_from("<I", body, j)
                types = [VALUE_TYPES.get(body[j + 4 + k * 4 + 2], hex(body[j + 4 + k * 4 + 2])) for k in range(count)]
                desc = (f"template at 0x{toff:04x} ({'defined here' if inline else 'reused'}), "
                        f"{count} values: {' '.join(types)}")
            print(f"  Record {rid} at 0x{off:04x}: {size} bytes, written {filetime(written)}")
            if desc:
                print(f"      {desc}")
            off += size
            shown += 1


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    n = int(args[args.index("--records") + 1]) if "--records" in args else 0
    main(args[0], n, "--templates" in args)
