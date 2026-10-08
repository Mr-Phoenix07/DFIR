#!/usr/bin/env python3
"""regf_peek.py - look inside a Windows registry hive or transaction log, structure first.

Usage:
  regf_peek.py HIVE                 base block, checksum, dirty check, hbins and cell statistics
  regf_peek.py HIVE --tree          every key (with last-write time) and value, from the root
  regf_peek.py HIVE --deleted       keys and values found in FREE cells (deleted but not overwritten)
  regf_peek.py HIVE.LOG1            a transaction log: its base block and the log entries (HvLE)

It reads the hive exactly as stored on disk: it does NOT apply transaction logs. Use rla (Eric
Zimmerman) or yarp to replay the logs first when the hive is dirty. Standard library only;
meant for learning and for cross-checking other parsers.
"""
import argparse
import datetime as dt
import signal
import struct
import sys
from collections import Counter

FILE_TYPES = {0: "primary hive", 1: "transaction log (old format)", 2: "transaction log (old format, alternate)",
              6: "transaction log (new format, Windows 8.1+)"}
VTYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BE",
          6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 11: "REG_QWORD"}
BASE = 0x1000


def ft(v):
    if not v:
        return "(zero)"
    secs, rem = divmod(v, 10_000_000)
    try:
        return f"{dt.datetime(1601, 1, 1) + dt.timedelta(seconds=secs):%Y-%m-%d %H:%M:%S}.{rem:07d}"
    except OverflowError:
        return f"(invalid {v:#x})"


def checksum(base):
    c = 0
    for i in range(127):
        c ^= struct.unpack_from("<I", base, i * 4)[0]
    return {0: 1, 0xFFFFFFFF: 0xFFFFFFFE}.get(c, c)


class Hive:
    def __init__(self, data):
        self.d = data

    def cell(self, off):
        """Return (allocated, payload) for the cell at hive-bins offset `off`."""
        pos = BASE + off
        size = struct.unpack_from("<i", self.d, pos)[0]
        return size < 0, self.d[pos + 4:pos + abs(size)]

    def value_data(self, dsize, doff):
        if dsize & 0x80000000:
            return struct.pack("<I", doff)[:dsize & 0x7FFFFFFF]
        if dsize > 16344:
            return None  # big data ("db") not supported here
        _, payload = self.cell(doff)
        return payload[:dsize]

    def decode(self, vtype, data):
        if data is None:
            return "(big data cell: not decoded)"
        if vtype in (1, 2):
            text = data.decode("utf-16-le", "replace").split("\0")[0]
            return text if len(text) <= 100 else f"{text[:60]}... ({len(text)} characters)"
        if vtype == 7:
            return " | ".join(s for s in data.decode("utf-16-le", "replace").split("\0") if s)
        if vtype == 4 and len(data) >= 4:
            v = struct.unpack_from("<I", data)[0]
            return f"{v} ({v:#x})"
        if vtype == 11 and len(data) >= 8:
            v = struct.unpack_from("<Q", data)[0]
            return f"{v} ({v:#x})"
        return data[:24].hex(" ") + (" ..." if len(data) > 24 else "")

    def vk(self, payload):
        nlen, dsize, doff, vtype, flags = struct.unpack_from("<HIIIH", payload, 2)
        raw = payload[0x14:0x14 + nlen]
        name = raw.decode("latin-1") if flags & 1 else raw.decode("utf-16-le", "replace")
        try:
            data = self.value_data(dsize, doff)
        except struct.error:
            data = b""
        return name or "(default)", vtype, data

    def nk(self, payload):
        flags, when = struct.unpack_from("<HQ", payload, 2)
        parent, nsub, _, sublist, _, nval, vallist = struct.unpack_from("<IIIIIII", payload, 0x10)
        nlen = struct.unpack_from("<H", payload, 0x48)[0]
        raw = payload[0x4C:0x4C + nlen]
        name = raw.decode("latin-1") if flags & 0x20 else raw.decode("utf-16-le", "replace")
        return dict(name=name, when=when, flags=flags, parent=parent, nsub=nsub, sublist=sublist,
                    nval=nval, vallist=vallist)

    def subkeys(self, listoff):
        if listoff == 0xFFFFFFFF:
            return []
        _, p = self.cell(listoff)
        sig, n = p[:2], struct.unpack_from("<H", p, 2)[0]
        if sig in (b"lf", b"lh"):
            return [struct.unpack_from("<I", p, 4 + 8 * i)[0] for i in range(n)]
        if sig == b"li":
            return [struct.unpack_from("<I", p, 4 + 4 * i)[0] for i in range(n)]
        if sig == b"ri":
            out = []
            for i in range(n):
                out += self.subkeys(struct.unpack_from("<I", p, 4 + 4 * i)[0])
            return out
        return []

    def walk(self, off, path, out):
        _, p = self.cell(off)
        k = self.nk(p)
        here = path + "\\" + k["name"] if path else k["name"]
        out.append(f"{ft(k['when'])}  {here}")
        if k["nval"] and k["vallist"] != 0xFFFFFFFF:
            _, vl = self.cell(k["vallist"])
            for i in range(k["nval"]):
                _, vp = self.cell(struct.unpack_from("<I", vl, 4 * i)[0])
                name, vtype, data = self.vk(vp)
                out.append(f"{'':29}  {name} [{VTYPES.get(vtype, vtype)}] = {self.decode(vtype, data)}")
        for sk in self.subkeys(k["sublist"]):
            self.walk(sk, here, out)

    def cells(self, size):
        """Yield (hive-bins offset, allocated, payload) for every cell of every hbin."""
        hb = 0
        while hb < size:
            pos = BASE + hb
            if self.d[pos:pos + 4] != b"hbin":
                return
            hb_size = struct.unpack_from("<I", self.d, pos + 8)[0]
            c = hb + 0x20
            while c < hb + hb_size:
                csize = struct.unpack_from("<i", self.d, BASE + c)[0]
                if csize == 0:
                    break
                yield c, csize < 0, self.d[BASE + c + 4:BASE + c + abs(csize)]
                c += abs(csize)
            hb += hb_size


def show_log(d):
    print("HvLE log entries (each one = a set of dirty pages to write back into the hive):")
    off = 512
    while off + 40 <= len(d):
        if d[off:off + 4] != b"HvLE":
            off += 512
            continue
        size, flags, seq, hbsize, npages = struct.unpack_from("<IIIII", d, off + 4)
        refs = [struct.unpack_from("<II", d, off + 40 + 8 * i) for i in range(npages)]
        print(f"  offset {off:>6}  sequence {seq:<4} hive-bins size {hbsize:<8} dirty pages: "
              + ", ".join(f"{o:#x}+{s:#x}" for o, s in refs))
        off += size
    if off == 512:
        print("  none (an empty or old-format log)")


def main():
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file")
    ap.add_argument("--tree", action="store_true")
    ap.add_argument("--deleted", action="store_true")
    a = ap.parse_args()
    d = open(a.file, "rb").read()
    if d[:4] != b"regf":
        sys.exit(f"not a hive: signature {d[:4]!r} (expected b'regf')")
    prim, sec, when, major, minor, ftype, fmt, root, size = struct.unpack_from("<IIQIIIIII", d, 4)
    stored = struct.unpack_from("<I", d, 0x1FC)[0]
    calc = checksum(d[:0x200])
    name = d[0x30:0x70].decode("utf-16-le", "replace").split("\0")[0]
    print(f"File            : {a.file} ({len(d)} bytes)")
    print(f"Type            : {FILE_TYPES.get(ftype, ftype)}, format {fmt}, version {major}.{minor}")
    print(f"Sequence numbers: primary {prim}, secondary {sec} -> "
          + ("CLEAN (equal)" if prim == sec else "DIRTY (not equal): changes may be in the .LOG1/.LOG2 files"))
    print(f"Last written    : {ft(when)} UTC")
    print(f"Root key cell   : {root:#x}    hive bins data size: {size} bytes")
    print(f"Embedded name   : {name}")
    print(f"Checksum        : stored {stored:#010x}, calculated {calc:#010x} -> {'OK' if stored == calc else 'MISMATCH'}")
    if ftype in (1, 2, 6):
        show_log(d)
        return
    h = Hive(d)
    stats, hbins, deleted = Counter(), 0, []
    for off, alloc, p in h.cells(size):
        kind = p[:2].decode("latin-1") if p[:2] in (b"nk", b"vk", b"sk", b"lf", b"lh", b"li", b"ri", b"db") else "data/list"
        stats[(kind, alloc)] += 1
        if not alloc and p[:2] in (b"nk", b"vk"):
            deleted.append((off, p))
    hbins = sum(1 for i in range(0, size, 4096) if d[BASE + i:BASE + i + 4] == b"hbin")
    print(f"hbins           : {hbins} found with an 'hbin' signature at 4 KB boundaries")
    print("Cells           : " + ", ".join(f"{k} {'used' if al else 'FREE'}: {n}" for (k, al), n in sorted(stats.items())))
    if a.tree:
        out = []
        h.walk(root, "", out)
        print("\n" + "\n".join(out))
    if a.deleted:
        print("\nKeys and values in free cells:")
        for off, p in deleted:
            try:
                if p[:2] == b"nk":
                    k = h.nk(p)
                    print(f"  cell {off:#07x}  KEY   {k['name']}  last write {ft(k['when'])}  values {k['nval']}  parent cell {k['parent']:#x}")
                else:
                    name, vtype, data = h.vk(p)
                    print(f"  cell {off:#07x}  VALUE {name} [{VTYPES.get(vtype, vtype)}] = {h.decode(vtype, data)}")
            except (struct.error, IndexError):
                print(f"  cell {off:#07x}  {p[:2].decode()} (partly overwritten)")


if __name__ == "__main__":
    main()
