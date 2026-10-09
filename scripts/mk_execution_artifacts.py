#!/usr/bin/env python3
"""mk_execution_artifacts.py - write the Day 12 evidence-of-execution artifacts for WS-ALICE.

Usage: python3 mk_execution_artifacts.py OUTDIR

Writes (byte-identical on every run, standard library only):
  SYSTEM                      AppCompatCache (Shimcache, Windows 10/11 format) and BAM entries, plus
                              Select, ComputerName, Session Manager\\Environment and ShutdownTime.
                              It is the hive as collected after alice rebooted at 07:55 on 2026-09-29,
                              so the Shimcache written at that shutdown includes the night's files.
  Amcache.hve                 Root\\InventoryApplicationFile entries (Windows 10/11 format)
  Prefetch/RCLONE.EXE-....pf  Prefetch format version 30 (Windows 10/11), but UNCOMPRESSED: Windows
  Prefetch/PSEXESVC.EXE-..pf  compresses these files (MAM / Xpress Huffman); tools accept both forms.
The Prefetch file names use the real Windows path hash (verified against real Windows prefetch files).
These are synthetic teaching artifacts; the SHA-1 values hash the stand-in file contents used in
Days 9-10, not real programs.
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mk_reg_hives import (K, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_QWORD, REG_SZ,  # noqa: E402
                          build, ft, sz)

ALICE = "S-1-5-21-3623811015-3361044348-30300820-1001"
VOLUME_SERIAL = 0x6C2F3E1A
VOLUME_CREATED = ft("2026-03-02 08:41:17.3528112")
VOLUME_ID = f"\\VOLUME{{{VOLUME_CREATED:016x}-{VOLUME_SERIAL:08x}}}"
DEVICE = "\\Device\\HarddiskVolume3"


def scca_hash(device_path):
    """Prefetch file-name hash used since Windows Vista (the 'SCCA hash'), over the UTF-16 upper-case path."""
    data = device_path.upper().encode("utf-16-le")
    h, i = 314159, 0
    while i + 8 < len(data):
        c = data[i + 1] * 37
        for j in range(2, 7):
            c = (c + data[i + j]) * 37
        c += data[i] * 442596621 + data[i + 7]
        h = (c - h * 803794207) % 0x100000000
        i += 8
    while i < len(data):
        h = (37 * h + data[i]) % 0x100000000
        i += 1
    return h


# ---------------------------------------------------------------- Prefetch (format version 30)

def prefetch_v30(exe, files, dirs, run_times, run_count):
    """files: [(path below the volume, mft entry, mft sequence)]; run_times newest first (max 8)."""
    names = [VOLUME_ID + p for p, _, _ in files]
    strings, offs = b"", []
    for n in names:
        offs.append(len(strings))
        strings += n.encode("utf-16-le") + b"\0\0"
    metrics = b"".join(struct.pack("<IIIIIIQ", i, 1, 1, offs[i], len(n), 0x200, (seq << 48) | entry)
                       for i, (n, (_, entry, seq)) in enumerate(zip(names, files)))
    traces = b"".join(struct.pack("<IBBH", 0x108, 0x0A, 0xC0, 0xFFFF) for _ in files)
    # volume information block: 1 entry (96 bytes), device path, file references, directory strings
    dev = VOLUME_ID.encode("utf-16-le") + b"\0\0"
    refs = struct.pack("<II", 3, len(files)) + b"\0" * 8 + b"".join(
        struct.pack("<Q", (seq << 48) | entry) for _, entry, seq in files)
    dstr = b"".join(struct.pack("<H", len(VOLUME_ID + d)) + (VOLUME_ID + d).encode("utf-16-le") + b"\0\0" for d in dirs)
    dev_off = 96
    ref_off = (dev_off + len(dev) + 7) & ~7
    dir_off = ref_off + len(refs)
    vol = struct.pack("<IIQIIIIII", dev_off, len(VOLUME_ID), VOLUME_CREATED, VOLUME_SERIAL,
                      ref_off, len(refs), dir_off, len(dirs), 2).ljust(96, b"\0")
    volinfo = vol + dev + b"\0" * (ref_off - dev_off - len(dev)) + refs + dstr
    m_off = 84 + 220
    t_off = m_off + len(metrics)
    s_off = t_off + len(traces)
    v_off = s_off + len(strings)
    size = v_off + len(volinfo)
    times = [ft(t) for t in run_times] + [0] * (8 - len(run_times))
    fi = struct.pack("<9I", m_off, len(files), t_off, len(files), s_off, len(strings), v_off, 1, len(volinfo))
    fi += struct.pack("<II", len(dirs), 1) + struct.pack("<8Q", *times) + b"\0" * 16
    fi += struct.pack("<I", run_count) + struct.pack("<II", 5, 3)
    fi = fi.ljust(220, b"\0")
    exe_path = DEVICE + files[[p.split("\\")[-1] for p, _, _ in files].index(exe)][0]
    header = struct.pack("<I4sII", 30, b"SCCA", 0x11, size) + exe.encode("utf-16-le").ljust(60, b"\0")
    header += struct.pack("<II", scca_hash(exe_path), 0)
    return f"{exe}-{scca_hash(exe_path):08X}.pf", header + fi + metrics + traces + strings + volinfo


SYS32 = "\\WINDOWS\\SYSTEM32\\"
RC = "\\USERS\\ALICE\\APPDATA\\LOCAL\\TEMP\\RC\\"

PREFETCH = [
    ("RCLONE.EXE", [
        (SYS32 + "NTDLL.DLL", 0x1A2E, 1), (RC + "RCLONE.EXE", 0x2B871, 1), (SYS32 + "KERNEL32.DLL", 0x1A31, 1),
        (SYS32 + "KERNELBASE.DLL", 0x1A33, 1), (SYS32 + "WS2_32.DLL", 0x1B07, 1), (SYS32 + "CRYPT32.DLL", 0x1B2C, 1),
        ("\\$MFT", 0, 1), (RC + "RC.CONF", 0x2B873, 1),
        ("\\USERS\\ALICE\\DOCUMENTS\\Q3-FORECAST.XLSX", 0x2A0F1, 2),
        ("\\USERS\\ALICE\\DOCUMENTS\\PROJECTS\\SPEC-01.TXT", 0x2A112, 1)],
     ["\\USERS", "\\USERS\\ALICE", "\\USERS\\ALICE\\APPDATA", "\\USERS\\ALICE\\APPDATA\\LOCAL",
      "\\USERS\\ALICE\\APPDATA\\LOCAL\\TEMP", "\\USERS\\ALICE\\APPDATA\\LOCAL\\TEMP\\RC",
      "\\USERS\\ALICE\\DOCUMENTS", "\\USERS\\ALICE\\DOCUMENTS\\PROJECTS", "\\WINDOWS", "\\WINDOWS\\SYSTEM32"],
     ["2026-09-29 07:58:21.4413920", "2026-09-29 01:22:11.3024417", "2026-09-29 01:12:47.6629015"], 3),
    ("PSEXESVC.EXE", [
        (SYS32 + "NTDLL.DLL", 0x1A2E, 1), ("\\WINDOWS\\PSEXESVC.EXE", 0x2B6F0, 1), (SYS32 + "KERNEL32.DLL", 0x1A31, 1),
        (SYS32 + "KERNELBASE.DLL", 0x1A33, 1), (SYS32 + "ADVAPI32.DLL", 0x1A40, 1), (SYS32 + "USERENV.DLL", 0x1B90, 1),
        ("\\$MFT", 0, 1)],
     ["\\WINDOWS", "\\WINDOWS\\SYSTEM32"],
     ["2026-09-29 01:05:13.2280133"], 1),
]


# ---------------------------------------------------------------- SYSTEM hive: Shimcache and BAM

SHIMCACHE = [  # newest first, as Windows writes it: (path, file's last-modified time, "executed" flag)
    (r"C:\Users\alice\AppData\Local\Temp\svchost.exe", "2019-03-14 10:00:00", 0),
    (r"C:\Users\alice\AppData\Local\Temp\rc\rclone.exe", "2025-11-14 16:05:00", 1),
    (r"C:\Windows\PSEXESVC.exe", "2026-09-29 01:05:12.0731180", 1),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "2026-08-12 03:14:55.1173300", 1),
    (r"C:\Windows\System32\cmd.exe", "2026-08-12 03:14:52.8812001", 1),
    (r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "2026-09-10 11:20:31.5540022", 1),
]


def appcompatcache():
    entries = b""
    for path, mtime, executed in SHIMCACHE:
        p = path.encode("utf-16-le")
        data = b"\0" * 8 + struct.pack("<I", executed)
        body = struct.pack("<H", len(p)) + p + struct.pack("<Q", ft(mtime)) + struct.pack("<I", len(data)) + data
        entries += b"10ts" + struct.pack("<II", 0, len(body)) + body
    header = bytearray(0x34)
    struct.pack_into("<I", header, 0, 0x34)
    struct.pack_into("<I", header, 0x28, len(SHIMCACHE))
    return bytes(header) + entries


def bam_value(when):
    return struct.pack("<Q", ft(when)) + b"\0" * 16


def system_hive():
    bam_alice = [
        (DEVICE + r"\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", REG_BINARY, bam_value("2026-09-29 01:09:31.5120044")),
        (DEVICE + r"\Users\alice\AppData\Local\Temp\rc\rclone.exe", REG_BINARY, bam_value("2026-09-29 01:12:47.6629015")),
        ("Version", REG_DWORD, struct.pack("<I", 1)), ("SequenceNumber", REG_DWORD, struct.pack("<I", 23))]
    bam_system = [
        (DEVICE + r"\Users\alice\AppData\Local\Temp\rc\rclone.exe", REG_BINARY, bam_value("2026-09-29 07:58:21.4413920")),
        ("Version", REG_DWORD, struct.pack("<I", 1)), ("SequenceNumber", REG_DWORD, struct.pack("<I", 4))]
    boot = "2026-09-29 07:58:19.0021345"
    cs = K("ControlSet001", "2026-03-02 09:00:00.1234567", children=[
        K("Control", "2026-09-29 07:55:02.7710042", children=[
            K("ComputerName", "2026-03-02 09:00:00.1234567", children=[
                K("ComputerName", "2026-03-02 09:00:00.1234567", [("ComputerName", REG_SZ, sz("WS-ALICE"))])]),
            K("Session Manager", "2026-09-29 07:55:02.7710042", children=[
                K("AppCompatCache", "2026-09-29 07:55:02.7710042", [("AppCompatCache", REG_BINARY, appcompatcache())]),
                K("Environment", "2026-03-02 09:00:00.1234567", [
                    ("PROCESSOR_ARCHITECTURE", REG_SZ, sz("AMD64")),
                    ("TEMP", REG_EXPAND_SZ, sz(r"%SystemRoot%\TEMP"))])]),
            K("Windows", "2026-09-29 07:55:02.7710042", [("ShutdownTime", REG_BINARY, struct.pack("<Q", ft("2026-09-29 07:55:02.7710042")))])]),
        K("Services", boot, children=[
            K("bam", "2026-03-02 09:00:00.1234567", children=[
                K("State", "2026-03-02 09:00:00.1234567", children=[
                    K("UserSettings", boot, children=[
                        K(ALICE, "2026-09-29 01:12:47.6629015", bam_alice),
                        K("S-1-5-18", "2026-09-29 07:58:21.4413920", bam_system)])])])])])
    sel = K("Select", "2026-03-02 09:00:00.1234567",
            [(n, REG_DWORD, struct.pack("<I", v)) for n, v in (("Current", 1), ("Default", 1), ("Failed", 0), ("LastKnownGood", 1))])
    return K("ROOT", boot, children=[cs, sel])


# ---------------------------------------------------------------- Amcache.hve

def amcache_file(name, path, content, when, size=None, publisher="", product="", version="", link_date="",
                 os_component=0, binary_type="pe64_amd64", usn=0):
    sha1 = hashlib.sha1(content).hexdigest()
    key = f"{name.lower()}|{hashlib.sha1(path.lower().encode()).hexdigest()[:16]}"
    vals = [("ProgramId", REG_SZ, sz("0000f519feec486de87ed73cb92d3cac802400000000")),
            ("FileId", REG_SZ, sz("0000" + sha1)), ("LowerCaseLongPath", REG_SZ, sz(path.lower())),
            ("LongPathHash", REG_SZ, sz(key)), ("Name", REG_SZ, sz(name)), ("OriginalFileName", REG_SZ, sz(name.lower())),
            ("Publisher", REG_SZ, sz(publisher)), ("Version", REG_SZ, sz(version)),
            ("BinFileVersion", REG_SZ, sz(version)), ("BinaryType", REG_SZ, sz(binary_type)),
            ("ProductName", REG_SZ, sz(product)), ("ProductVersion", REG_SZ, sz(version)),
            ("LinkDate", REG_SZ, sz(link_date)), ("BinProductVersion", REG_SZ, sz(version)),
            ("Size", REG_QWORD, struct.pack("<Q", size if size is not None else len(content))),
            ("Language", REG_DWORD, struct.pack("<I", 0)), ("IsPeFile", REG_DWORD, struct.pack("<I", 1)),
            ("IsOsComponent", REG_DWORD, struct.pack("<I", os_component)), ("Usn", REG_QWORD, struct.pack("<Q", usn))]
    return K(key, when, vals)


def amcache_hive():
    files = K("InventoryApplicationFile", "2026-09-29 01:22:12.0019931", children=[
        amcache_file("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     b"powershell stand-in", "2026-08-12 03:20:04.4410078", size=455680,
                     publisher="Microsoft Corporation", product="Microsoft® Windows® Operating System",
                     version="10.0.26100.1", link_date="06/13/2087 21:47:32", os_component=1, usn=4818104),
        amcache_file("PSEXESVC.exe", r"C:\Windows\PSEXESVC.exe", b"psexesvc stand-in",
                     "2026-09-29 01:05:14.0310071", size=199688, publisher="Sysinternals - www.sysinternals.com",
                     product="Sysinternals PsExec", version="2.43", link_date="04/11/2023 14:13:17", usn=91338712),
        amcache_file("rclone.exe", r"C:\Users\alice\AppData\Local\Temp\rc\rclone.exe",
                     b"MZ" + b"\0" * 8190, "2026-09-29 01:12:49.7746215", size=8192,
                     product="Rclone", version="1.68.2", usn=91340104)])
    return K("{11517B7C-E79D-4e20-961B-75A811715ADD}", "2026-09-29 01:22:12.0019931",
             children=[K("Root", "2026-09-29 01:22:12.0019931", children=[files])])


def main(outdir):
    os.makedirs(os.path.join(outdir, "Prefetch"), exist_ok=True)
    outputs = [("SYSTEM", build(system_hive(), r"\SystemRoot\System32\Config\SYSTEM", ft("2026-09-29 07:58:21.4413920"))),
               ("Amcache.hve", build(amcache_hive(), r"\??\C:\Windows\AppCompat\Programs\Amcache.hve",
                                     ft("2026-09-29 01:22:12.0019931")))]
    for exe, files, dirs, runs, count in PREFETCH:
        name, data = prefetch_v30(exe, files, dirs, runs, count)
        outputs.append((os.path.join("Prefetch", name), data))
    for name, data in outputs:
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)
        print(f"{len(data):>7}  {name}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "execution")
