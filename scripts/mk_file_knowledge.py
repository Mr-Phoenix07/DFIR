#!/usr/bin/env python3
"""mk_file_knowledge.py - write the Day 13 "file and folder knowledge" artifacts for WS-ALICE.

Usage: python3 mk_file_knowledge.py OUTDIR

Writes (byte-identical on every run, standard library only):
  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/*.lnk
      Shell links (MS-SHLLINK) as Explorer writes them when a file is opened: target ID list
      (shell items with BEEF0004 extension blocks), LinkInfo (volume serial and label, or the
      network share), relative path, working directory and a TrackerDataBlock (machine ID and
      object IDs). The .lnk files get their modification times; a Linux copy can't keep the
      creation time Windows gave them.
  Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms
      Jump Lists: OLE compound files holding one LNK stream per entry plus a DestList stream
      (version 4) for Excel, Notepad and Explorer.
  Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat
      A registry hive with ShellBags (Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU).

The story continues Days 9-12: MFT entry numbers, times and names match the Day 10 disk
(budget.xlsx = entry 72, renamed Q3-forecast.xlsx at 01:02:03; notes.txt = entry 73, deleted).
These are synthetic teaching artifacts; layouts follow the MS-SHLLINK and MS-CFB specifications
and the libyal format notes, and were checked with LECmd, JLECmd, RegRipper and liblnk.
"""
import ntpath
import os
import struct
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mk_reg_hives import K, REG_BINARY, REG_DWORD, build, ft  # noqa: E402

HOST = "ws-alice"
MAC = 0xE4F89C5A217D                      # E4:F8:9C:5A:21:7D (an Intel OUI)
C_SERIAL, C_LABEL = 0x6C2F3E1A, ""        # same C: volume as Day 12's Prefetch
E_SERIAL, E_LABEL = 0x5E1D7A2C, "TRANSFER"
C_DROID = uuid.UUID("7a4c1d2e-9b3f-4e8a-a1c6-2f5d8e0b3c71")   # volume object IDs
E_DROID = uuid.UUID("c93e5f17-2d64-48b0-9e1a-6b7c0f2d4a58")
RECENT_DIR = "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Recent"

MY_COMPUTER = "20D04FE0-3AEA-1069-A2D8-08002B30309D"
NETWORK = "F02C1A0D-BE21-4350-88B0-7367FC96EF3C"


# ---------------------------------------------------------------- helpers

def fat(text):
    """'2026-09-29 01:33:41' (UTC) -> FAT date, FAT time (2-second resolution)."""
    d, t = text.split(".")[0].split()
    y, mo, da = (int(x) for x in d.split("-"))
    h, mi, s = (int(x) for x in t.split(":"))
    return struct.pack("<HH", ((y - 1980) << 9) | (mo << 5) | da, (h << 11) | (mi << 5) | (s // 2))


def droid(when):
    """A version-1 GUID (object ID) created at `when` on WS-ALICE's network card."""
    ticks = ft(when) - ft("1582-10-15 00:00:00")        # UUID time: 100 ns since 1582-10-15
    return uuid.UUID(fields=(ticks & 0xFFFFFFFF, (ticks >> 32) & 0xFFFF, ((ticks >> 48) & 0x0FFF) | 0x1000,
                             0x80 | 0x1A, 0x2A, MAC))


def u16z(s):
    return (s + "\0").encode("utf-16-le")


# ---------------------------------------------------------------- shell items (libfwsi)

def item(body):
    return struct.pack("<H", len(body) + 2) + body


def root_item(guid, sort_index):
    return item(bytes([0x1F, sort_index]) + uuid.UUID(guid).bytes_le)


def volume_item(letter):
    return item(bytes([0x2F]) + f"{letter}:\\".encode().ljust(22, b"\0"))


def network_item(kind, location):
    """0x42 server or 0xC3 share item: flags 0x80 = a description follows the location."""
    return item(bytes([kind, 0x01 if kind == 0xC3 else 0x00, 0x80 | (kind & 0x0F)]) + location.encode() + b"\0"
                + b"Microsoft Network\0" + b"\x02\x00")


def file_item(name, is_dir, size, modified, created, accessed, mft=(0, 0)):
    """File entry shell item (0x31 folder / 0x32 file) with a version 9 BEEF0004 extension block."""
    short = (name if len(name) <= 12 else name[:6].upper() + "~1" + os.path.splitext(name)[1][:4].upper())
    short = short.encode() + b"\0"
    if len(short) % 2:
        short += b"\0"
    head = (bytes([0x31 if is_dir else 0x32, 0]) + struct.pack("<I", 0 if is_dir else size) + fat(modified)
            + struct.pack("<H", 0x10 if is_dir else 0x20) + short)
    beef_at = 2 + len(head)
    ref = struct.pack("<IHH", mft[0], 0, mft[1])
    beef = (struct.pack("<HI", 9, 0xBEEF0004) + fat(created) + fat(accessed) + struct.pack("<HH", 0x2E, 0)
            + ref + b"\0" * 8 + struct.pack("<H", 0) + b"\0" * 8 + u16z(name) + struct.pack("<H", beef_at))
    return item(head + struct.pack("<H", len(beef) + 2) + beef)


# ---------------------------------------------------------------- the file system as WS-ALICE saw it

T_DAY10 = "2026-09-28 09:15:00.4372815"     # alice's folders and files on the Day 10 disk
T_E_COPY = "2026-09-29 01:33:20.6170042"    # E:\finance created by the copy

FOLDERS = {   # path -> (MFT entry, sequence, created, modified)
    "C:\\Users": (64, 1, T_DAY10, T_DAY10),
    "C:\\Users\\alice": (65, 1, T_DAY10, T_DAY10),
    "C:\\Users\\alice\\Documents": (66, 1, T_DAY10, "2026-09-29 01:02:03.1180043"),
    "C:\\Users\\alice\\AppData": (69, 1, T_DAY10, T_DAY10),
    "C:\\Users\\alice\\AppData\\Local": (70, 1, T_DAY10, T_DAY10),
    "C:\\Users\\alice\\AppData\\Local\\Temp": (71, 1, T_DAY10, "2026-09-28 10:14:22.5501734"),
    "C:\\Users\\alice\\AppData\\Local\\Temp\\rc": (118, 1, "2026-09-28 10:14:22.5501734", "2026-09-28 10:14:22.6912270"),
    "E:\\finance": (41, 1, T_E_COPY, "2026-09-29 01:33:21.0346118"),
    "\\\\203.0.113.50\\drop": (0, 0, "2026-09-27 22:40:51.0000000", "2026-09-27 22:41:09.0000000"),
}

FILES = {     # path -> (MFT entry, sequence, size, created, modified, accessed)
    "C:\\Users\\alice\\Documents\\notes.txt": (73, 1, 60, T_DAY10, T_DAY10, T_DAY10),
    "C:\\Users\\alice\\AppData\\Local\\Temp\\rc.zip":
        (117, 1, 2048, "2026-09-28 10:13:57.8823011", "2026-09-28 10:13:57.9910345", "2026-09-28 10:13:57.9910345"),
    "C:\\Users\\alice\\Documents\\budget.xlsx": (72, 1, 6144, T_DAY10, T_DAY10, T_DAY10),
    "C:\\Users\\alice\\Documents\\Q3-forecast.xlsx": (72, 1, 6144, T_DAY10, T_DAY10, T_DAY10),
    "\\\\203.0.113.50\\drop\\upload-howto.txt":
        (0, 0, 412, "2026-09-27 22:41:09.0000000", "2026-09-27 22:41:09.0000000", "2026-09-29 01:05:30.0000000"),
    "E:\\finance\\spec-01.txt": (42, 1, 16, "2026-09-29 01:33:21.0346118", T_DAY10, "2026-09-29 01:33:21.0346118"),
}

OBJECT_IDS = {   # object IDs given to targets by the link-tracking service when first linked
    72: droid("2026-09-28 16:20:11.2245901"),       # budget.xlsx, kept when it was renamed
    73: droid("2026-09-28 09:16:40.5170023"),       # notes.txt
    117: droid("2026-09-28 10:14:31.3080119"),      # rc.zip
    "C:\\Users\\alice\\Documents": droid("2026-03-02 09:41:07.1100003"),
    118: droid("2026-09-29 01:04:58.4031227"),      # Temp\rc
    ("E", 41): droid("2026-09-29 01:33:41.8812006"),  # E:\finance
    ("E", 42): droid("2026-09-29 01:34:12.2290518"),  # E:\finance\spec-01.txt
}


def stamps(path):
    if path in FILES:
        entry, seq, size, c, m, a = FILES[path]
        return entry, seq, size, c, m, a, False
    entry, seq, c, m = FOLDERS[path]
    return entry, seq, 0, c, m, m, True


def id_list(path):
    """The target ID list Explorer builds for a path."""
    items = []
    if path.startswith("\\\\"):
        server, share, *rest = path[2:].split("\\")
        items += [root_item(NETWORK, 0x58), network_item(0x42, f"\\\\{server}"),
                  network_item(0xC3, f"\\\\{server}\\{share}")]
        base = f"\\\\{server}\\{share}"
    else:
        drive, *rest = path.split("\\")
        items += [root_item(MY_COMPUTER, 0x50), volume_item(drive[0])]
        base = drive
    for part in rest:
        base += "\\" + part
        entry, seq, size, c, m, a, is_dir = stamps(base)
        items.append(file_item(part, is_dir, size, m, c, a, (entry, seq)))
    return items


def object_id(path):
    entry = stamps(path)[0]
    if path.startswith("E:"):
        return OBJECT_IDS.get(("E", entry))
    return OBJECT_IDS.get(entry) or OBJECT_IDS.get(path)


# ---------------------------------------------------------------- shell link (MS-SHLLINK)

def string_data(s):
    return struct.pack("<H", len(s)) + s.encode("utf-16-le")


def link_info(path):
    if path.startswith("\\\\"):
        share, suffix = ntpath.split(path)
        net = struct.pack("<IIIII", 0x14 + len(share) + 1, 0x2, 0x14, 0, 0x00020000) + share.encode() + b"\0"
        body_len = 0x1C + len(net) + len(suffix) + 1
        return (struct.pack("<IIIIIII", body_len, 0x1C, 0x2, 0, 0, 0x1C, 0x1C + len(net))
                + net + suffix.encode() + b"\0")
    serial, label = (E_SERIAL, E_LABEL) if path.startswith("E:") else (C_SERIAL, C_LABEL)
    vol = struct.pack("<IIII", 0x10 + len(label) + 1, 2 if path.startswith("E:") else 3, serial, 0x10) + label.encode() + b"\0"
    local = path.encode() + b"\0"
    body_len = 0x1C + len(vol) + len(local) + 1
    return (struct.pack("<IIIIIII", body_len, 0x1C, 0x1, 0x1C, 0x1C + len(vol), 0, 0x1C + len(vol) + len(local))
            + vol + local + b"\0")


def tracker(path):
    oid = object_id(path)
    if oid is None:
        return b""
    vol = E_DROID if path.startswith("E:") else C_DROID
    return (struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + HOST.encode().ljust(16, b"\0")
            + vol.bytes_le + oid.bytes_le + vol.bytes_le + oid.bytes_le)


def shell_link(path):
    entry, seq, size, c, m, a, is_dir = stamps(path)
    flags = 0x01 | 0x02 | 0x10 | 0x80                       # ID list, LinkInfo, working dir, Unicode
    rel = None
    if path.startswith("C:"):
        rel = ntpath.relpath(path, RECENT_DIR)
        flags |= 0x08
    ids = b"".join(id_list(path)) + b"\0\0"
    header = struct.pack("<I16sIIQQQIIIH", 0x4C, uuid.UUID("00021401-0000-0000-C000-000000000046").bytes_le, flags,
                         0x10 if is_dir else 0x20, ft(c), ft(a), ft(m), size, 0, 1, 0) + b"\0" * 10
    out = header + struct.pack("<H", len(ids)) + ids + link_info(path)
    if rel:
        out += string_data(rel)
    out += string_data(path if is_dir else ntpath.dirname(path))
    return out + tracker(path) + b"\0\0\0\0"


# ---------------------------------------------------------------- Jump Lists: DestList + compound file

def dest_list(entries, pinned):
    """entries: newest first, as (entry id, path, last used, count, pinned order or -1)."""
    body = b""
    for eid, path, when, count, pin in entries:
        oid = object_id(path) or uuid.UUID(int=0)
        vol = (E_DROID if path.startswith("E:") else C_DROID) if oid.int else uuid.UUID(int=0)
        body += (struct.pack("<Q", (eid * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF)
                 + vol.bytes_le + oid.bytes_le + vol.bytes_le + oid.bytes_le + HOST.encode().ljust(16, b"\0")
                 + struct.pack("<iif", eid, 0, float(count)) + struct.pack("<Q", ft(when))
                 + struct.pack("<iiiii", pin, -1, count, 0, 0) + string_data(path) + b"\0\0\0\0")
    last_id = max(e[0] for e in entries)
    header = struct.pack("<iiifiiii", 4, len(entries), pinned, 0.0, last_id, 0, last_id + len(entries), 0)
    return header + body


def cfb(streams):
    """A version 3 OLE compound file (512-byte sectors) whose streams are all < 4096 bytes."""
    names = sorted(streams, key=lambda n: (len(n), n.upper()))
    mini, minifat, starts = b"", [], {}
    for n in names:
        data = streams[n]
        count = (len(data) + 63) // 64
        starts[n] = len(minifat)
        minifat += [len(minifat) + i + 1 for i in range(count)]
        minifat[-1] = -2
        mini += data.ljust(count * 64, b"\0")

    entries = [None] * (len(names) + 1)

    def place(lo, hi):
        if lo > hi:
            return -1
        mid = (lo + hi) // 2
        entries[mid + 1] = (names[mid], place(lo, mid - 1), place(mid + 1, hi))
        return mid + 1

    top = place(0, len(names) - 1)

    def dirent(name, kind, left, right, child, start, size):
        raw = name.encode("utf-16-le") + b"\0\0"
        return (raw.ljust(64, b"\0") + struct.pack("<HBBiii", len(raw), kind, 1, left, right, child)
                + b"\0" * 16 + b"\0" * 4 + b"\0" * 16 + struct.pack("<iII", start, size, 0))

    mini_sectors = (len(mini) + 511) // 512
    minifat_bytes = b"".join(struct.pack("<i", x) for x in minifat)
    minifat_sectors = (len(minifat_bytes) + 511) // 512
    dir_count = len(entries)
    dir_sectors = (dir_count * 128 + 511) // 512
    # sector layout: [FAT][directory][mini FAT][mini stream]
    fat_sectors = 1
    first_dir = fat_sectors
    first_minifat = first_dir + dir_sectors
    first_mini = first_minifat + minifat_sectors
    total = first_mini + mini_sectors
    fat_tab = [-3]
    for start, count in ((first_dir, dir_sectors), (first_minifat, minifat_sectors), (first_mini, mini_sectors)):
        fat_tab += [start + i + 1 for i in range(count)]
        fat_tab[-1] = -2
    assert len(fat_tab) == total <= 128
    fat_tab += [-1] * (128 - len(fat_tab))

    dirs = dirent("Root Entry", 5, -1, -1, top, first_mini, len(mini))
    for n, left, right in entries[1:]:
        dirs += dirent(n, 2, left, right, -1, starts[n], len(streams[n]))
    dirs = dirs.ljust(dir_sectors * 512, b"\0")
    for off in range(dir_count * 128, len(dirs), 128):     # unused entries: no siblings, no child
        dirs = dirs[:off + 68] + struct.pack("<iii", -1, -1, -1) + dirs[off + 80:]

    header = (bytes.fromhex("D0CF11E0A1B11AE1") + b"\0" * 16 + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
              + b"\0" * 6 + struct.pack("<IIIIIIIII", 0, fat_sectors, first_dir, 0, 4096, first_minifat,
                                        minifat_sectors, 0xFFFFFFFE, 0)
              + struct.pack("<i", 0) + struct.pack("<i", -1) * 108)
    body = (b"".join(struct.pack("<i", x) for x in fat_tab) + dirs + minifat_bytes.ljust(minifat_sectors * 512, b"\0")
            + mini.ljust(mini_sectors * 512, b"\0"))
    return header + body


def jump_list(entries, pinned=0):
    streams = {"DestList": dest_list(entries, pinned)}
    for eid, path, *_ in entries:
        streams[format(eid, "x")] = shell_link(path)
    return cfb(streams)


# ---------------------------------------------------------------- ShellBags in UsrClass.dat

def bag_key(name, when, children, slots):
    """A BagMRU key. children: (shell item, last browsed, grandchildren). Values 0..n hold the
    children's shell items, MRUListEx orders them newest first, NodeSlot points into Shell\\Bags."""
    values, keys = [], []
    for i, (shell_item, child_when, grandchildren) in enumerate(children):
        values.append((str(i), REG_BINARY, shell_item))
        keys.append(bag_key(str(i), child_when, grandchildren, slots))
    if children:
        order = sorted(range(len(children)), key=lambda i: children[i][1], reverse=True)
        values.append(("MRUListEx", REG_BINARY, b"".join(struct.pack("<I", i) for i in order) + b"\xff" * 4))
    slots.append(name)
    values.append(("NodeSlot", REG_DWORD, struct.pack("<I", len(slots))))
    return K(name, when, values, keys)


def usrclass():
    c = id_list("C:\\Users\\alice\\AppData\\Local\\Temp\\rc")
    docs = id_list("C:\\Users\\alice\\Documents")[-1]
    e = id_list("E:\\finance")
    net = id_list("\\\\203.0.113.50\\drop\\upload-howto.txt")
    t_docs, t_rc, t_drop, t_fin = ("2026-09-28 16:19:52.6610045", "2026-09-29 01:04:58.4031227",
                                   "2026-09-29 01:05:02.9120338", "2026-09-29 01:33:41.8812006")
    # My Computer > C:\ > Users > alice > {Documents, AppData > Local > Temp > rc};  My Computer > E:\ > finance
    # Network > \\203.0.113.50 > \\203.0.113.50\drop
    alice = [(docs, t_docs, []), (c[4], t_rc, [(c[5], t_rc, [(c[6], t_rc, [(c[7], t_rc, [])])])])]
    my_computer = [(c[1], t_rc, [(c[2], t_rc, [(c[3], t_rc, alice)])]), (e[1], t_fin, [(e[2], t_fin, [])])]
    tree = [(c[0], t_fin, my_computer), (net[0], t_drop, [(net[1], t_drop, [(net[2], t_drop, [])])])]
    bagmru = bag_key("BagMRU", t_fin, tree, [])
    key = K("Shell", t_fin, children=[bagmru, K("Bags", t_fin)])
    for name in ("Windows", "Microsoft", "Software", "Local Settings"):
        key = K(name, t_fin, children=[key])
    root = K("S-1-5-21-3623811015-3361044348-30300820-1001_Classes", t_fin, children=[key])
    return build(root, "\\??\\C:\\Users\\alice\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat", ft(t_fin))


# ---------------------------------------------------------------- output

RECENT = [   # (lnk name, target, .lnk last written)
    ("notes.txt.lnk", "C:\\Users\\alice\\Documents\\notes.txt", "2026-09-28 11:02:15.3304411"),
    ("rc.zip.lnk", "C:\\Users\\alice\\AppData\\Local\\Temp\\rc.zip", "2026-09-28 10:14:31.3080119"),
    ("budget.xlsx.lnk", "C:\\Users\\alice\\Documents\\budget.xlsx", "2026-09-28 17:48:09.6620873"),
    ("Q3-forecast.xlsx.lnk", "C:\\Users\\alice\\Documents\\Q3-forecast.xlsx", "2026-09-29 01:03:44.0517706"),
    ("upload-howto.txt.lnk", "\\\\203.0.113.50\\drop\\upload-howto.txt", "2026-09-29 01:05:31.7765020"),
    ("spec-01.txt.lnk", "E:\\finance\\spec-01.txt", "2026-09-29 01:34:12.2290518"),
]

JUMP_LISTS = {   # AppID -> (entries newest first: id, path, last used, count, pin), pinned count
    "b8ab77100df80ab2": ([
        (2, "C:\\Users\\alice\\Documents\\Q3-forecast.xlsx", "2026-09-29 01:03:44.0517706", 1, -1),
        (1, "C:\\Users\\alice\\Documents\\budget.xlsx", "2026-09-28 17:48:09.6620873", 4, -1)], 0),
    "9b9cdc69c1c24e2b": ([
        (3, "E:\\finance\\spec-01.txt", "2026-09-29 01:34:12.2290518", 1, -1),
        (2, "\\\\203.0.113.50\\drop\\upload-howto.txt", "2026-09-29 01:05:31.7765020", 1, -1),
        (1, "C:\\Users\\alice\\Documents\\notes.txt", "2026-09-28 11:02:15.3304411", 3, -1)], 0),
    "f01b4d95cf55d32a": ([
        (4, "E:\\finance", "2026-09-29 01:33:41.8812006", 1, -1),
        (3, "\\\\203.0.113.50\\drop", "2026-09-29 01:05:02.9120338", 1, -1),
        (2, "C:\\Users\\alice\\AppData\\Local\\Temp\\rc", "2026-09-29 01:04:58.4031227", 1, -1),
        (1, "C:\\Users\\alice\\Documents", "2026-09-28 16:19:52.6610045", 12, 0)], 1),
}


def set_mtime(path, when):
    t = (ft(when) - 116444736000000000) / 10_000_000
    os.utime(path, (t, t))


def main(outdir):
    recent = os.path.join(outdir, "Users/alice/AppData/Roaming/Microsoft/Windows/Recent")
    auto = os.path.join(recent, "AutomaticDestinations")
    local = os.path.join(outdir, "Users/alice/AppData/Local/Microsoft/Windows")
    for d in (auto, local):
        os.makedirs(d, exist_ok=True)
    for name, target, when in RECENT:
        p = os.path.join(recent, name)
        with open(p, "wb") as f:
            f.write(shell_link(target))
        set_mtime(p, when)
    for appid, (entries, pinned) in JUMP_LISTS.items():
        p = os.path.join(auto, appid + ".automaticDestinations-ms")
        with open(p, "wb") as f:
            f.write(jump_list(entries, pinned))
        set_mtime(p, max(e[2] for e in entries))
    p = os.path.join(local, "UsrClass.dat")
    with open(p, "wb") as f:
        f.write(usrclass())
    set_mtime(p, "2026-09-29 07:55:02.7710042")
    for dirpath, _, files in sorted(os.walk(outdir)):
        for fn in sorted(files):
            fp = os.path.join(dirpath, fn)
            print(f"{os.path.getsize(fp):7d}  {os.path.relpath(fp, outdir)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
