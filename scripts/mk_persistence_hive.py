#!/usr/bin/env python3
"""mk_persistence_hive.py - build registry hives salted with Windows persistence for the Day 22 lab.

Usage: python3 mk_persistence_hive.py OUTDIR

Writes SOFTWARE, SYSTEM and NTUSER.DAT for a second compromised workstation, FIN-WS-07 (user dana),
from the same intrusion as WS-ALICE (Days 9 to 21). On top of a believable baseline of autostart
entries, the attacker left seven classic persistence mechanisms, each in a different place the
autostart hunters (Autoruns, PersistenceSniper, Trawler) look:

  SOFTWARE  ...\\CurrentVersion\\Run\\MsEdgeUpdate                 HKLM Run key                 (T1547.001)
  SOFTWARE  ...\\Winlogon\\Userinit  (userinit.exe,...,winlogon.exe)  Winlogon Userinit hijack  (T1547.004)
  SOFTWARE  ...\\Image File Execution Options\\sethc.exe\\Debugger  accessibility / IFEO debugger (T1546.008)
  SOFTWARE  ...\\CurrentVersion\\Windows\\AppInit_DLLs             AppInit_DLLs                 (T1546.010)
  SOFTWARE  ...\\Schedule\\TaskCache\\{Tree,Tasks}\\EdgeUpdate     scheduled task               (T1053.005)
  SYSTEM    ControlSet001\\Services\\WinDefendUpd                  auto-start service           (T1543.003)
  SYSTEM    ControlSet001\\Control\\Lsa\\Security Packages         LSA security package (SSP)   (T1547.005)
  NTUSER    ...\\CurrentVersion\\Run\\Updater                      HKCU Run key                 (T1547.001)

Every malicious value points at a user-writable path (Temp, AppData, ProgramData) - the signal an
offline scanner keys on. A matching scheduled-task XML is written to Tasks/EdgeUpdate, the way
Windows stores it under C:\\Windows\\System32\\Tasks. The output is byte-identical on every run and
each key keeps a chosen last-write time; the persistence times match the WS-ALICE super timeline
(scheduled task 01:21:05, Run key 01:21:30, service 01:22:10 on 2026-09-29). Standard library only;
it reuses the regf builder from mk_reg_hives.py.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from mk_reg_hives import (K, build, ft, sz, multi_sz, security_descriptor,  # noqa: E402
                          REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD)

INSTALL = "2026-01-12 08:30:00.1000000"            # baseline: image laid down in January
GUID = "{3F2504E0-4F89-41D3-9A0C-0305E82C3301}"    # the malicious task's cache GUID

# story times (2026-09-29, UTC), aligned with the WS-ALICE intrusion timeline of Day 21
T_TASK = "2026-09-29 01:21:05.4425108"
T_RUN = "2026-09-29 01:21:30.0187744"
T_SVC = "2026-09-29 01:22:10.5550001"

TASK_XML = (
    '<?xml version="1.0" encoding="UTF-16"?>\r\n'
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\r\n'
    '  <RegistrationInfo>\r\n    <Author>FIN-WS-07\\dana</Author>\r\n    <Date>2026-09-29T01:21:05</Date>\r\n'
    '    <URI>\\EdgeUpdate</URI>\r\n  </RegistrationInfo>\r\n'
    '  <Triggers>\r\n    <LogonTrigger>\r\n      <Enabled>true</Enabled>\r\n    </LogonTrigger>\r\n'
    '    <BootTrigger>\r\n      <Enabled>true</Enabled>\r\n    </BootTrigger>\r\n  </Triggers>\r\n'
    '  <Principals>\r\n    <Principal id="Author">\r\n      <RunLevel>HighestAvailable</RunLevel>\r\n'
    '    </Principal>\r\n  </Principals>\r\n'
    '  <Actions Context="Author">\r\n    <Exec>\r\n'
    '      <Command>C:\\Users\\dana\\AppData\\Local\\Temp\\edge\\edgeupd.exe</Command>\r\n'
    '      <Arguments>/sync</Arguments>\r\n    </Exec>\r\n  </Actions>\r\n</Task>')


def dynamic_info(reg_when, launch_when):
    """A 36-byte Windows 8/10 TaskCache DynamicInfo record (libyal dynamic_info2_record)."""
    return struct.pack("<IQQIIQ", 3, ft(reg_when), ft(launch_when), 0x80070420, 0, ft(launch_when))


def software_hive():
    cv = [("ProductName", REG_SZ, sz("Windows 10 Pro")), ("DisplayVersion", REG_SZ, sz("24H2")),
          ("CurrentBuild", REG_SZ, sz("26100")), ("EditionID", REG_SZ, sz("Professional")),
          ("RegisteredOwner", REG_SZ, sz("dana")), ("InstallTime", REG_QWORD, struct.pack("<Q", ft(INSTALL)))]

    # Run key: one legitimate entry, one planted (HKLM needs admin - the attacker had SYSTEM via PsExec)
    run = K("Run", T_RUN, [
        ("SecurityHealth", REG_EXPAND_SZ, sz(r"%windir%\system32\SecurityHealthSystray.exe")),
        ("MsEdgeUpdate", REG_SZ, sz(r"C:\ProgramData\Microsoft\Crypto\msedgeupdate.exe"))])

    # Winlogon: a second executable appended after the legitimate userinit.exe
    winlogon = K("Winlogon", T_RUN, [
        ("Userinit", REG_SZ, sz(r"C:\Windows\system32\userinit.exe,C:\Windows\Temp\winlogon.exe,")),
        ("Shell", REG_SZ, sz("explorer.exe")),
        ("VMApplet", REG_SZ, sz("SystemPropertiesPerformance.exe /pagefile"))])

    # Image File Execution Options: a Debugger on sethc.exe (sticky keys) - the classic accessibility hijack
    ifeo = K("Image File Execution Options", INSTALL, children=[
        K("sethc.exe", T_TASK, [("Debugger", REG_SZ, sz(r"C:\Windows\System32\cmd.exe"))]),
        K("your_program.exe", INSTALL, [("GlobalFlag", REG_DWORD, struct.pack("<I", 0))])])

    # AppInit_DLLs: a DLL loaded into every GUI process, turned on
    windows = K("Windows", T_TASK, [
        ("AppInit_DLLs", REG_SZ, sz(r"C:\ProgramData\Intel\drv.dll")),
        ("LoadAppInit_DLLs", REG_DWORD, struct.pack("<I", 1)),
        ("RequireSignedAppInit_DLLs", REG_DWORD, struct.pack("<I", 0))])

    # Scheduled task: TaskCache Tree entry (Id -> GUID) plus the Tasks\{GUID} record
    tree = K("Tree", INSTALL, children=[
        K("EdgeUpdate", T_TASK, [
            ("Id", REG_SZ, sz(GUID)),
            ("Index", REG_DWORD, struct.pack("<I", 3)),
            ("SD", REG_BINARY, security_descriptor())])])
    tasks = K("Tasks", INSTALL, children=[
        K(GUID, T_TASK, [
            ("Path", REG_SZ, sz(r"\EdgeUpdate")),
            ("URI", REG_SZ, sz(r"\EdgeUpdate")),
            ("Hash", REG_BINARY, bytes.fromhex("9f86d081884c7d659a2feaa0c55ad015"
                                               "a3bf4f1b2b0b822cd15d6c15b0f00a08")),
            ("DynamicInfo", REG_BINARY, dynamic_info(T_TASK, "2026-09-29 01:21:06.0000000")),
            ("Triggers", REG_BINARY, bytes.fromhex("15000000030000000000000000000000"))])])
    schedule = K("Schedule", INSTALL, children=[K("TaskCache", INSTALL, children=[tree, tasks])])

    # AppInit_DLLs lives under Windows NT\CurrentVersion\Windows (not Windows\CurrentVersion)
    return K("ROOT", INSTALL, children=[K("Microsoft", INSTALL, children=[
        K("Windows", INSTALL, children=[K("CurrentVersion", INSTALL, children=[run])]),
        K("Windows NT", INSTALL, children=[
            K("CurrentVersion", INSTALL, cv, [winlogon, ifeo, schedule, windows])])])])


def system_hive():
    svc = lambda name, when, path, start, display: K(name, when, [  # noqa: E731
        ("Type", REG_DWORD, struct.pack("<I", 0x10)), ("Start", REG_DWORD, struct.pack("<I", start)),
        ("ErrorControl", REG_DWORD, struct.pack("<I", 1)), ("ImagePath", REG_EXPAND_SZ, sz(path)),
        ("DisplayName", REG_SZ, sz(display)), ("ObjectName", REG_SZ, sz("LocalSystem"))])
    lsa = K("Lsa", INSTALL, [
        # the standard packages plus a planted security package (SSP) at the end
        ("Authentication Packages", REG_MULTI_SZ, multi_sz(["msv1_0"])),
        ("Notification Packages", REG_MULTI_SZ, multi_sz(["scecli"])),
        # first seven are the Windows 10/11 defaults; "secupd" is the attacker's SSP DLL
        ("Security Packages", REG_MULTI_SZ, multi_sz(
            ["kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "secupd"]))])
    control = K("Control", INSTALL, children=[
        K("ComputerName", INSTALL, children=[
            K("ComputerName", INSTALL, [("ComputerName", REG_SZ, sz("FIN-WS-07"))])]),
        lsa])
    services = K("Services", T_SVC, children=[
        svc("W32Time", INSTALL, r"%SystemRoot%\system32\svchost.exe -k LocalService", 3, "Windows Time"),
        svc("Dnscache", INSTALL, r"%SystemRoot%\system32\svchost.exe -k NetworkService", 2, "DNS Client"),
        svc("WinDefendUpd", T_SVC, r"C:\ProgramData\Microsoft\Crypto\defender.exe", 2,
            "Windows Defender Update Service")])
    cs = K("ControlSet001", INSTALL, children=[control, services])
    sel = K("Select", INSTALL, [(n, REG_DWORD, struct.pack("<I", v))
                                for n, v in (("Current", 1), ("Default", 1), ("Failed", 0), ("LastKnownGood", 1))])
    return K("ROOT", T_SVC, children=[cs, sel])


def ntuser_hive():
    run = K("Run", T_RUN, [
        ("OneDrive", REG_SZ, sz(r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background')),
        ("Updater", REG_SZ, sz(r"C:\Users\dana\AppData\Roaming\update\updater.exe"))])
    runonce = K("RunOnce", INSTALL, [])
    cv = K("CurrentVersion", T_RUN, children=[run, runonce])
    return K("ROOT", T_RUN, children=[K("Software", INSTALL, children=[
        K("Microsoft", INSTALL, children=[K("Windows", INSTALL, children=[cv])])])])


def main(outdir):
    os.makedirs(os.path.join(outdir, "Tasks"), exist_ok=True)
    for fname, root, internal, when in (
            ("SOFTWARE", software_hive(), r"\SystemRoot\System32\Config\SOFTWARE", T_TASK),
            ("SYSTEM", system_hive(), r"\SystemRoot\System32\Config\SYSTEM", T_SVC),
            ("NTUSER.DAT", ntuser_hive(), r"\??\C:\Users\dana\ntuser.dat", T_RUN)):
        with open(os.path.join(outdir, fname), "wb") as f:
            f.write(build(root, internal, ft(when)))
    with open(os.path.join(outdir, "Tasks", "EdgeUpdate"), "wb") as f:
        f.write(TASK_XML.encode("utf-16"))        # UTF-16 LE with BOM, as Windows stores task XML
    print(f"wrote SOFTWARE, SYSTEM, NTUSER.DAT and Tasks/EdgeUpdate under {outdir}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
