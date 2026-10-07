#!/usr/bin/env python3
"""logfile_peek.py - look inside an NTFS $LogFile (the transaction journal) for learning and triage.

Usage:
  logfile_peek.py LOGFILE                 restart area summary + operation counts + file names seen
  logfile_peek.py LOGFILE --records       one line per log record (LSN, transaction, redo/undo operation, name)

What it does:
  1. Reads the two restart pages ("RSTR") and prints the log version, page size, current LSN and
     the number of sequence-number bits (needed to turn an LSN into a file offset).
  2. Applies the update sequence array (fixups) to every log record page ("RCRD").
  3. Finds log record headers by self-consistency: a record header whose own LSN maps back to the
     offset it was found at. Records that continue on the next page are followed across pages.
  4. Decodes the NTFS client data: redo/undo operation, target attribute, and, where the redo or undo
     data holds an index entry or a whole FILE record, the file name inside it.

It does NOT replay transactions, rebuild full paths, or handle every corner case (for example the
"fast" and "tail" page copies used to recover the last pages after a crash). It is a teaching aid
that shows what NTFS Log Tracker and similar tools decode for you. Standard library only.
"""
import argparse
import signal
import struct
import sys
from collections import Counter

OPS = ["Noop", "CompensationLogRecord", "InitializeFileRecordSegment", "DeallocateFileRecordSegment",
       "WriteEndOfFileRecordSegment", "CreateAttribute", "DeleteAttribute", "UpdateResidentValue",
       "UpdateNonresidentValue", "UpdateMappingPairs", "DeleteDirtyClusters", "SetNewAttributeSizes",
       "AddIndexEntryRoot", "DeleteIndexEntryRoot", "AddIndexEntryAllocation", "DeleteIndexEntryAllocation",
       "WriteEndOfIndexBuffer", "SetIndexEntryVcnRoot", "SetIndexEntryVcnAllocation", "UpdateFileNameRoot",
       "UpdateFileNameAllocation", "SetBitsInNonresidentBitMap", "ClearBitsInNonresidentBitMap", "HotFix",
       "EndTopLevelAction", "PrepareTransaction", "CommitTransaction", "ForgetTransaction",
       "OpenNonresidentAttribute", "OpenAttributeTableDump", "AttributeNamesDump", "DirtyPageTableDump",
       "TransactionTableDump", "UpdateRecordDataRoot", "UpdateRecordDataAllocation",
       "UpdateRelativeDataIndex", "UpdateRelativeDataAllocation", "ZeroEndOfFileRecord"]
ADD_INDEX = {0x0C, 0x0E}
DEL_INDEX = {0x0D, 0x0F}
HEADER_LEN = 0x30


def op_name(code):
    return OPS[code] if code < len(OPS) else hex(code)


def unprotect(page, sector=512):
    """Apply the update sequence array: restore the last 2 bytes of every 512-byte sector."""
    buf = bytearray(page)
    usa_off, usa_cnt = struct.unpack_from("<HH", buf, 4)
    if usa_cnt < 2 or usa_off + usa_cnt * 2 > len(buf):
        return None
    usn = buf[usa_off:usa_off + 2]
    for i in range(1, usa_cnt):
        end = i * sector
        if end > len(buf):
            break
        if buf[end - 2:end] != usn:
            return None  # torn write or not a valid page
        buf[end - 2:end] = buf[usa_off + 2 * i:usa_off + 2 * i + 2]
    return bytes(buf)


def name_from_fn(fn):
    """Return the name stored in a $FILE_NAME value (or None)."""
    if len(fn) < 0x42:
        return None
    n = fn[0x40]
    raw = fn[0x42:0x42 + 2 * n]
    return raw.decode("utf-16-le", "replace") if len(raw) == 2 * n and n else None


def name_from_index_entry(entry):
    if len(entry) < 0x10:
        return None
    key_len = struct.unpack_from("<H", entry, 10)[0]
    return name_from_fn(entry[0x10:0x10 + key_len]) if key_len >= 0x42 else None


def name_from_file_record(rec):
    """Find the first $FILE_NAME (0x30) attribute in a FILE record image and return its name."""
    if rec[:4] != b"FILE" or len(rec) < 0x18:
        return None
    off = struct.unpack_from("<H", rec, 0x14)[0]
    while off + 0x18 <= len(rec):
        atype, alen = struct.unpack_from("<II", rec, off)
        if atype == 0xFFFFFFFF or alen == 0 or off + alen > len(rec):
            return None
        if atype == 0x30 and rec[off + 8] == 0:
            voff = struct.unpack_from("<H", rec, off + 0x14)[0]
            return name_from_fn(rec[off + voff:off + alen])
        off += alen
    return None


class LogFile:
    def __init__(self, data):
        self.data = data
        rstr = None
        for base in (0, 0x1000):
            page = data[base:base + 0x1000]
            if page[:4] == b"RSTR":
                rstr = unprotect(page)
                if rstr:
                    break
        if not rstr:
            sys.exit("No valid restart page (RSTR) found: is this a $LogFile? (an all-0xFF file is an empty log)")
        self.sys_page, self.page_size = struct.unpack_from("<II", rstr, 0x10)
        ra_off, self.minor, self.major = struct.unpack_from("<HHH", rstr, 0x18)
        ra = rstr[ra_off:]
        self.current_lsn = struct.unpack_from("<Q", ra, 0)[0]
        self.clients, = struct.unpack_from("<H", ra, 8)
        self.ra_flags, = struct.unpack_from("<H", ra, 0x0E)
        self.seq_bits, = struct.unpack_from("<I", ra, 0x10)
        self.file_size, = struct.unpack_from("<Q", ra, 0x18)
        self.data_off, = struct.unpack_from("<H", ra, 0x26)
        client_off, = struct.unpack_from("<H", ra, 0x16)
        cl = ra[client_off:]
        name_len, = struct.unpack_from("<I", cl, 0x1C)
        self.client_name = cl[0x20:0x20 + name_len].decode("utf-16-le", "replace")
        self.client_restart_lsn, = struct.unpack_from("<Q", cl, 8)
        self.pages = {}
        for off in range(2 * self.page_size, len(data) - self.page_size + 1, self.page_size):
            page = data[off:off + self.page_size]
            if page[:4] == b"RCRD":
                fixed = unprotect(page)
                if fixed:
                    self.pages[off] = fixed

    def lsn_to_offset(self, lsn):
        return ((lsn << self.seq_bits) & 0xFFFFFFFFFFFFFFFF) >> (self.seq_bits - 3)

    def lap(self, lsn):
        """Sequence number: how many times the circular log had wrapped when this record was written."""
        return lsn >> (64 - self.seq_bits)

    def read_span(self, page_off, pos, length):
        """Read `length` bytes of record data starting at pos in page page_off, following page boundaries."""
        out = bytearray()
        while length > 0 and page_off in self.pages:
            chunk = self.pages[page_off][pos:pos + length]
            out += chunk
            length -= len(chunk)
            page_off += self.page_size
            if page_off >= len(self.data):
                page_off = 4 * self.page_size if self.major < 2 else 2 * self.page_size  # wrap to the first log page
            pos = self.data_off
        return bytes(out)

    def records(self):
        seen = set()
        for page_off, page in sorted(self.pages.items()):
            for pos in range(self.data_off, self.page_size - HEADER_LEN + 1, 8):
                lsn = struct.unpack_from("<Q", page, pos)[0]
                if lsn == 0 or lsn in seen or self.lsn_to_offset(lsn) != page_off + pos:
                    continue
                seen.add(lsn)
                prev, undo_next, dlen, client, rtype, tid, flags = struct.unpack_from("<QQIIIIH", page, pos + 8)
                yield lsn, prev, dlen, rtype, tid, flags, self.read_span(page_off, pos + HEADER_LEN, dlen)


def decode(rtype, client):
    """Return (redo_op, undo_op, target_attribute, name) for NTFS client data."""
    if rtype != 1 or len(client) < 0x20:
        return None, None, None, None
    redo, undo, r_off, r_len, u_off, u_len, target = struct.unpack_from("<7H", client, 0)
    name = None
    if redo in ADD_INDEX:
        name = name_from_index_entry(client[r_off:r_off + r_len])
    elif undo in ADD_INDEX:  # e.g. DeleteIndexEntry*: the undo data holds the entry being removed
        name = name_from_index_entry(client[u_off:u_off + u_len])
    elif redo == 0x02:  # InitializeFileRecordSegment: redo data is the new FILE record
        name = name_from_file_record(client[r_off:r_off + r_len])
    return redo, undo, target, name


def main():
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("logfile")
    ap.add_argument("--records", action="store_true", help="print every log record")
    args = ap.parse_args()
    with open(args.logfile, "rb") as f:
        lf = LogFile(f.read())
    print(f"$LogFile: {len(lf.data)} bytes, LFS version {lf.major}.{lf.minor}, log page size {lf.page_size}, "
          f"client '{lf.client_name}'")
    print(f"Current LSN: {lf.current_lsn} (file offset {lf.lsn_to_offset(lf.current_lsn):#x}), "
          f"client restart LSN: {lf.client_restart_lsn}, sequence-number bits: {lf.seq_bits}, "
          f"log record pages (RCRD): {len(lf.pages)}")
    ops, names, n, restarts, lsns, laps = Counter(), [], 0, 0, [], Counter()
    for lsn, prev, dlen, rtype, tid, flags, client in sorted(lf.records()):
        n += 1
        lsns.append(lsn)
        laps[lf.lap(lsn)] += 1
        if rtype == 2:
            restarts += 1
            if args.records:
                print(f"{lsn:>10} lap={lf.lap(lsn)} tx={tid:<4} client restart area")
            continue
        redo, undo, target, name = decode(rtype, client)
        if redo is None:
            continue
        ops[(op_name(redo), op_name(undo))] += 1
        if name:
            names.append((lsn, op_name(redo), name))
        if args.records:
            print(f"{lsn:>10} lap={lf.lap(lsn)} tx={tid:<4} {op_name(redo):<28} {op_name(undo):<28} {name or ''}")
    if args.records:
        return
    print(f"Log records found: {n} ({restarts} client restart areas), LSN range {min(lsns)}..{max(lsns)}")
    print("Records per lap (older laps are leftovers the log has not overwritten yet): "
          + ", ".join(f"lap {k}: {v}" for k, v in sorted(laps.items())))
    print("\nRedo / undo operations:")
    for (r, u), c in ops.most_common():
        print(f"  {c:>4}  {r:<28} / {u}")
    print("\nFile names in index-entry and FILE-record operations (oldest first):")
    for lsn, op, name in names:
        print(f"  LSN {lsn:>10} (lap {lf.lap(lsn)})  {op:<28} {name}")


if __name__ == "__main__":
    main()
