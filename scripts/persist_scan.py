#!/usr/bin/env python3
"""persist_scan.py - hunt Windows autostart persistence in offline registry hives.

Usage: persist_scan.py HIVEDIR [--all]

HIVEDIR holds the hives from a triage collection (as laid out by mk_persistence_hive.py or copied
from C:\\Windows\\System32\\config and a user profile): SOFTWARE, SYSTEM and/or NTUSER.DAT, and
optionally a Tasks/ folder with scheduled-task XML (C:\\Windows\\System32\\Tasks). It reads the
Auto-Start Extensibility Points (ASEPs) that attackers abuse and that live-system hunters such as
Sysinternals Autoruns, PersistenceSniper and Trawler enumerate, and marks the suspicious entries:

  HKLM / HKCU Run and RunOnce    Winlogon Userinit and Shell    AppInit_DLLs
  Image File Execution Options Debuggers (accessibility hijacks) and SilentProcessExit
  Services with an auto/boot start    LSA Security and Notification packages    Scheduled tasks

An entry is flagged when its executable or DLL sits in a user-writable location (Temp, AppData,
ProgramData, a user profile, Windows\\Temp), when a value that should hold a fixed default has been
changed (Userinit, Shell), or when a list that should hold only known Windows names has an extra
one (Security Packages). This is a triage aid, not a verdict: an unflagged entry is not proven good
(an attacker can hijack a trusted path), and a flagged one may be legitimate software - always
confirm the file's signature and reputation. By default every ASEP that has entries is shown so you
see the baseline next to the outliers; --all also prints the empty ASEPs that were checked.

Standard library only; it reuses the hive parser from regf_peek.py. It reads the hive as stored and
does NOT apply transaction logs - replay dirty hives first (Day 11).
"""
import argparse
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import regf_peek  # noqa: E402

# roots a signed Windows/vendor binary normally starts from; anything else is worth a second look
GOOD_ROOTS = (r"c:\windows\system32", r"c:\windows\syswow64", r"c:\windows\winsxs",
              r"c:\program files", r"c:\program files (x86)", r"c:\windows\microsoft.net",
              r"c:\windows\servicing", r"c:\windows\explorer.exe", r"c:\windows\system32")
# locations any user (or malware running as the user) can write to
BAD_MARKERS = ("\\temp\\", "\\appdata\\", "\\programdata\\", "\\users\\public\\", "\\downloads\\",
               "\\$recycle", "\\windows\\temp\\", "\\perflogs\\", "\\documents\\", "\\desktop\\")
# the Windows 10/11 default LSA Security Packages (anything else is a planted SSP)
GOOD_SSP = {"", "kerberos", "msv1_0", "schannel", "wdigest", "tspkg", "pku2u", "cloudap",
            "negoexts", "livessp", "credssp"}
GOOD_NOTIFY = {"", "scecli"}
ENV = {"%systemroot%": r"c:\windows", "%windir%": r"c:\windows",
       "%programfiles%": r"c:\program files", "%systemdrive%": "c:"}


def expand(path):
    out = path.strip().strip('"').lower()      # lower-cased: used only for matching, not display
    for k, v in ENV.items():
        out = out.replace(k, v)
    return out


def exe_of(command):
    """Pull the executable path out of a command line (first quoted token, or up to the first space)."""
    command = command.strip()
    if command.startswith('"'):
        return command[1:].split('"', 1)[0]
    m = re.match(r"(.*?\.(?:exe|dll|bat|cmd|ps1|vbs|js|scr|com|pif))(?:\s|$)", command, re.I)
    return m.group(1) if m else command.split(" ")[0]


def suspicious(command):
    """Return a short reason string if the command's target looks user-writable/unusual, else ''."""
    p = expand(exe_of(command)).lower().replace("/", "\\")
    for marker in BAD_MARKERS:
        if marker in p:
            return f"path under {marker.strip(chr(92))}"
    if re.match(r"^[a-z]:\\", p) and not any(p.startswith(r) for r in GOOD_ROOTS):
        return "path outside system/program directories"
    return ""


class Reg:
    """Navigate a hive by key path and read values, on top of regf_peek's parser."""

    def __init__(self, path):
        data = open(path, "rb").read()
        if data[:4] != b"regf":
            raise ValueError(f"{path}: not a registry hive")
        self.h = regf_peek.Hive(data)
        self.root = struct.unpack_from("<I", data, 0x24)[0]

    def key(self, path):
        off = self.root
        for part in filter(None, path.split("\\")):
            off = self._child(off, part)
            if off is None:
                return None
        return off

    def _child(self, off, name):
        _, p = self.h.cell(off)
        for sk in self.h.subkeys(self.h.nk(p)["sublist"]):
            _, cp = self.h.cell(sk)
            if self.h.nk(cp)["name"].lower() == name.lower():
                return sk
        return None

    def when(self, off):
        _, p = self.h.cell(off)
        return regf_peek.ft(self.h.nk(p)["when"])

    def subkeys(self, off):
        _, p = self.h.cell(off)
        for sk in self.h.subkeys(self.h.nk(p)["sublist"]):
            _, cp = self.h.cell(sk)
            yield self.h.nk(cp)["name"], sk

    def values(self, off):
        """name -> (vtype, decoded string)."""
        out = {}
        _, p = self.h.cell(off)
        k = self.h.nk(p)
        if k["nval"] and k["vallist"] != 0xFFFFFFFF:
            _, vl = self.h.cell(k["vallist"])
            for i in range(k["nval"]):
                _, vp = self.h.cell(struct.unpack_from("<I", vl, 4 * i)[0])
                name, vtype, data = self.h.vk(vp)
                out[name] = (vtype, self.h.decode(vtype, data))
        return out


FLAG, OK = "[!]", "   "
findings = 0


def line(flag, text):
    global findings
    findings += flag
    print(f"  {FLAG if flag else OK} {text}")


def section(title):
    print(f"\n== {title} ==")


def run_keys(reg, base, label, show_all):
    for sub in ("Run", "RunOnce"):
        off = reg.key(base + "\\" + sub)
        if off is None:
            if show_all:
                print(f"\n== {label} {sub} ==\n  (key not present)")
            continue
        vals = reg.values(off)
        if not vals and not show_all:
            continue
        print(f"\n== {label} {sub} ==   (last write {reg.when(off)})")
        for name, (_, data) in sorted(vals.items()):
            line(bool(suspicious(data)), f"{name} = {data}" + (f"   <-- {suspicious(data)}" if suspicious(data) else ""))


def main(hivedir, show_all):
    sw = os.path.join(hivedir, "SOFTWARE")
    sy = os.path.join(hivedir, "SYSTEM")
    nt = os.path.join(hivedir, "NTUSER.DAT")
    software = Reg(sw) if os.path.exists(sw) else None
    system = Reg(sy) if os.path.exists(sy) else None
    ntuser = Reg(nt) if os.path.exists(nt) else None

    if software:
        run_keys(software, r"Microsoft\Windows\CurrentVersion", "HKLM", show_all)
    if ntuser:
        run_keys(ntuser, r"Software\Microsoft\Windows\CurrentVersion", "HKCU", show_all)

    if software:
        off = software.key(r"Microsoft\Windows NT\CurrentVersion\Winlogon")
        if off is not None:
            section(f"Winlogon (last write {software.when(off)})")
            v = software.values(off)
            userinit = v.get("Userinit", (0, ""))[1]
            shell = v.get("Shell", (0, ""))[1]
            extra = [e for e in userinit.split(",") if e.strip()][1:]
            line(bool(extra), f"Userinit = {userinit}" + ("   <-- extra program after userinit.exe" if extra else ""))
            line(shell.lower() not in ("explorer.exe", ""),
                 f"Shell = {shell}" + ("   <-- not the default explorer.exe" if shell.lower() not in ("explorer.exe", "") else ""))

        off = software.key(r"Microsoft\Windows NT\CurrentVersion\Windows")
        if off is not None:
            v = software.values(off)
            appinit = v.get("AppInit_DLLs", (0, ""))[1]
            loaded = v.get("LoadAppInit_DLLs", (0, ""))[1]
            if appinit or show_all:
                section("AppInit_DLLs")
                line(bool(appinit), f"AppInit_DLLs = {appinit or '(empty)'}   LoadAppInit_DLLs = {loaded}"
                     + ("   <-- DLL injected into every GUI process" if appinit else ""))

        ifeo = software.key(r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
        if ifeo is not None:
            hits = []
            for name, off in software.subkeys(ifeo):
                v = software.values(off)
                if "Debugger" in v:
                    hits.append((name, "Debugger", v["Debugger"][1]))
            if hits or show_all:
                section("Image File Execution Options (Debugger hijacks)")
                for name, which, data in hits:
                    line(True, f"{name}\\{which} = {data}   <-- launches instead of {name}")
                if not hits:
                    print("  (no Debugger values)")

    if system:
        svc = system.key(r"ControlSet001\Services")
        if svc is not None:
            section("Services (auto / boot start)")
            rows = []
            for name, off in system.subkeys(svc):
                v = system.values(off)
                start = v.get("Start", (0, ""))[1].split(" ")[0]
                image = v.get("ImagePath", (0, ""))[1]
                if start in ("0", "1", "2") and image:
                    rows.append((name, start, image, system.when(off)))
            for name, start, image, when in sorted(rows):
                sus = suspicious(image)
                line(bool(sus), f"{name:<16} start={start} {image}" + (f"   <-- {sus} ({when})" if sus else ""))

        lsa = system.key(r"ControlSet001\Control\Lsa")
        if lsa is not None:
            section("LSA packages")
            v = system.values(lsa)
            for val, good in (("Security Packages", GOOD_SSP), ("Notification Packages", GOOD_NOTIFY),
                              ("Authentication Packages", {"", "msv1_0"})):
                pkgs = [p.strip() for p in re.split(r"\s*\|\s*|\s+", v.get(val, (0, ""))[1]) if p.strip()]
                bad = [p for p in pkgs if p.lower() not in good]
                line(bool(bad), f"{val}: {' '.join(pkgs) or '(none)'}"
                     + (f"   <-- unexpected: {', '.join(bad)}" if bad else ""))

    if software:
        tree = software.key(r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree")
        if tree is not None:
            section("Scheduled tasks (TaskCache)")
            tasks = []

            def walk_tree(off, prefix):
                for name, koff in software.subkeys(off):
                    v = software.values(koff)
                    if "Id" in v:
                        tasks.append((prefix + "\\" + name, v["Id"][1], software.when(koff)))
                    else:
                        walk_tree(koff, prefix + "\\" + name)
            walk_tree(tree, "")
            for path, guid, when in sorted(tasks):
                cmd = task_command(hivedir, path)
                sus = suspicious(cmd) if cmd else ""
                detail = f" -> {cmd}" if cmd else "  (no XML on disk)"
                line(bool(sus), f"{path}{detail}" + (f"   <-- {sus}" if sus else f"   (registered {when})"))

    print(f"\n{findings} entr{'y' if findings == 1 else 'ies'} flagged for review"
          f" (of the ASEPs checked). Confirm each file's signature before acting.")
    return 0


def task_command(hivedir, task_path):
    """Read C:\\Windows\\System32\\Tasks\\<task_path> (if collected) and return 'command args'."""
    rel = task_path.strip("\\").replace("\\", os.sep)
    fp = os.path.join(hivedir, "Tasks", rel)
    if not os.path.isfile(fp):
        return ""
    raw = open(fp, "rb").read()
    text = raw.decode("utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8", "replace")
    cmd = re.search(r"<Command>(.*?)</Command>", text, re.S)
    args = re.search(r"<Arguments>(.*?)</Arguments>", text, re.S)
    if not cmd:
        return ""
    return (cmd.group(1).strip() + " " + (args.group(1).strip() if args else "")).strip()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("hivedir", help="folder with SOFTWARE, SYSTEM and/or NTUSER.DAT")
    ap.add_argument("--all", action="store_true", help="also show ASEPs that were checked but are empty")
    a = ap.parse_args()
    sys.exit(main(a.hivedir, a.all))
