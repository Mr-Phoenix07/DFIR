# Day 22: Windows Persistence Hunting

> **Phase 2: Windows Forensics** · **Level:** 🔴 Advanced · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-19
>
> **Tools today:** 🛠️ Autoruns (Sysinternals) · 🛠️ PersistenceSniper · 🛠️ Trawler

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain what **persistence** is, why Windows has well over a hundred **Auto-Start Extensibility Points (ASEPs)**, and map the main families to MITRE ATT&CK.
2. Recognise the classic mechanisms — Run keys, Winlogon, services, scheduled tasks, IFEO debuggers, AppInit/AppCert DLLs, LSA packages — by what they look like in the registry and on disk.
3. Sweep a **live** system with **Autoruns/autorunsc**, **PersistenceSniper** and **Trawler**, using signature checks, Microsoft-hiding and allow-listing to cut the noise.
4. Hunt persistence **offline**, in a dead-box image or triage collection, where those live tools can't run — reading the hives, the TaskCache and the task XML directly.
5. Triage a finding: tell a user-writable red flag from a signed built-in, and know why an unflagged entry is still not proof of innocence.

---

## Part 1: The lesson

Yesterday's super timeline showed the WS-ALICE attacker plant three persistence mechanisms in two minutes — a scheduled task, a Run key and a service. Persistence is how an implant **survives a reboot or a logoff**: the attacker registers their code in one of the many places Windows will start a program on its own, so it runs again without them lifting a finger. For a defender it is one of the highest-value things to hunt, because it is where the attacker has to **leave something behind**.

### 1.1 Auto-Start Extensibility Points

Windows starts programs automatically from a startling number of places — Sysinternals Autoruns, the most complete map of them, covers **well over a hundred**. Each is an **ASEP**: a registry value, a file-system location, a database entry or an object whose presence makes Windows (or an application) launch code at a defined moment — boot, logon, a service start, the launch of Explorer or a browser, the handling of a file type, even a crash. Attackers abuse them because many are user-writable, few are watched, and a single value can survive for years.

MITRE ATT&CK groups the techniques under a handful of tactics; the ones you will meet most:

| MITRE | Technique | Where it lives |
|---|---|---|
| T1547.001 | Registry Run / RunOnce keys & Startup folder | `...\CurrentVersion\Run` (HKLM/HKCU), `Shell:Startup` |
| T1547.004 | Winlogon helper | `...\Winlogon` Userinit, Shell, Notify |
| T1547.005 | Security Support Provider | `...\Lsa` Security Packages |
| T1543.003 | Windows service | `SYSTEM\...\Services\<name>` |
| T1053.005 | Scheduled task | `...\Schedule\TaskCache` + `System32\Tasks\*` |
| T1546.008 | Accessibility / IFEO debugger | `...\Image File Execution Options\<exe>\Debugger` |
| T1546.010 | AppInit DLLs | `...\Windows NT\CurrentVersion\Windows\AppInit_DLLs` |
| T1546.015 | COM object hijack | `HKCU\...\CLSID\<guid>\InprocServer32` |
| T1546.003 | WMI event subscription | `root\subscription` (__EventFilter, CommandLineConsumer) |
| T1037 | Logon script | `HKCU\Environment\UserInitMprLogonScript` |

The lesson's point is not to memorise the list — no one does — but to **use a tool that knows the list**, and to know how to read what it returns.

### 1.2 What each mechanism looks like

A few you will see again and again, and should recognise on sight:

- **Run / RunOnce** — a value whose data is a command line, under `Software\Microsoft\Windows\CurrentVersion\Run` in HKLM (every user, needs admin) or HKCU (that user). RunOnce deletes itself after firing. The most common, lowest-effort persistence.
- **Winlogon Userinit / Shell** — `Userinit` should be exactly `C:\Windows\system32\userinit.exe,` and `Shell` exactly `explorer.exe`. A **second** program appended to Userinit, or a changed Shell, runs at every interactive logon.
- **Services** — a subkey under `...\Services` with an `ImagePath` and a `Start` of 0 (boot), 1 (system) or 2 (auto). A service whose image sits in a user-writable directory is a red flag.
- **Scheduled tasks** — split across the registry (`TaskCache\Tree\<name>` holds an `Id`; `TaskCache\Tasks\<Id>` holds `DynamicInfo` with the registration time) and an **XML file** under `C:\Windows\System32\Tasks\` that carries the actual command. A task created straight in the registry, without the XML and `SD`, is a *GhostTask* and is invisible to the Task Scheduler UI.
- **IFEO Debugger** — `...\Image File Execution Options\<program.exe>\Debugger` tells Windows to launch the *debugger* instead of the program. Set it on `sethc.exe` (Sticky Keys) or `utilman.exe` and you have a SYSTEM shell from the logon screen.
- **AppInit_DLLs / AppCertDLLs** — a DLL path here is loaded into **every** process that links `user32.dll` (AppInit, when `LoadAppInit_DLLs=1`) or that calls `CreateProcess` (AppCert).
- **LSA Security Packages** — a DLL name added here is loaded into **lsass.exe**, the classic home of credential-stealing SSPs such as mimilib.

### 1.3 Live hunting versus the dead box

The three tools today were built to run on a **live, running Windows host**: they read the live registry, enumerate running services and tasks, resolve each image to a file on disk and check its Authenticode signature. That is the right tool when you have a box in front of you and can run code on it.

In most DFIR work you have an **image or a triage collection**, not a live host — and these tools largely can't run against it. Two of them have a dead-box mode (Autoruns' `autorunsc -z <offline system>`, Trawler's `-drivetarget`), but they still need a Windows machine to run *on*, with the hives mounted. When your workstation is Linux/SIFT and the evidence is a KAPE collection, you hunt the same ASEPs **offline**: parse the hives (RegRipper, RECmd, Plaso), read the TaskCache and the task XML, and compare against a known-good baseline. That is exactly what Trawler's drive-retargeting does under the hood, and what today's lab does with pinned **RegRipper** and a small standard-library sweeper, `persist_scan.py`.

Whichever side you work from, three ideas cut the noise:

- **Signatures.** A signed Microsoft or known-vendor binary in its normal directory is almost never the implant. Autoruns' *Hide Signed Microsoft Entries* and PersistenceSniper's signature column exist for this.
- **Allow-listing / baselining.** Trawler ships allow-lists for default Windows 10/2016/2019/2022 entries and can take a **snapshot** of a golden image to diff against; PersistenceSniper takes a `-DiffCSV`. Diffing a host against a known-good image is the single biggest noise reducer.
- **Location.** An autostart whose target is under `\Temp\`, `\AppData\`, `\ProgramData\` or a user profile deserves a hard look, whatever its name.

### 1.4 The case: FIN-WS-07

Today's evidence is a **second** compromised workstation from the WS-ALICE campaign — `FIN-WS-07`, user `dana` — delivered as a triage collection of three hives (`SOFTWARE`, `SYSTEM`, `NTUSER.DAT`) and the `System32\Tasks` folder. Somewhere in it the attacker left **seven** persistence mechanisms, mixed in with the machine's legitimate autostarts. You will sweep them offline, confirm each with a second parser, and place them on a timeline. A note of caution the labs will keep returning to: a hunter that flags an entry has given you a **lead, not a verdict** — the last step is always to confirm the file.

---

## Part 2: Tools

All three tools are **Windows-only** and expect to run with administrative rights (PersistenceSniper and Trawler even try to elevate to SYSTEM for a few checks). The hands-on labs in Part 3 run on Linux/SIFT against an image, so the tool commands below are given for reference and for when you do have a live host; they are **not** run in the lab.

### 🛠️ Tool 1: Autoruns / autorunsc (Sysinternals)

The most complete autostart map there is: a GUI (`Autoruns.exe`) with a tab per ASEP family, and a command-line twin (`autorunsc.exe`) that prints CSV/XML for triage and scripting. Validated against **v14.3** (published 2026-06-17).

#### Requirements

- Windows 7 or later; administrator (some locations are readable only as admin/SYSTEM).
- For signature and VirusTotal checks, outbound HTTPS.

#### Installation

```powershell
# Download the Sysinternals Autoruns package (GUI + autorunsc), then unzip
# https://download.sysinternals.com/files/Autoruns.zip
# Or run straight from Sysinternals Live:
#   https://live.sysinternals.com/autoruns.exe
# Or with winget:
winget install Microsoft.Sysinternals.Autoruns
```

#### Configuration

Accept the EULA once (GUI dialog, or `-accepteula` / first run). In the GUI, **Options → Hide Signed Microsoft Entries** and **Options → Scan Options → Verify code signatures** and **Check VirusTotal.com** are the settings that matter. `autorunsc` takes the same choices as switches.

#### Verify the installation

```powershell
autorunsc.exe -accepteula -h -nobanner -c -a l * | Select-Object -First 3
```

#### First use

```powershell
# Full sweep, all categories (-a *), with hashes (-h), signatures (-s), timestamps in UTC (-t),
# every user profile (*), as CSV (autorunsc writes to stdout — redirect it):
autorunsc.exe -accepteula -nobanner -a * -s -h -t -c * > autoruns.csv
# Offline/dead-box: point -z at a mounted image's Windows system root
autorunsc.exe -accepteula -nobanner -a * -c -z F:\Windows > offline.csv
```

#### Troubleshooting

- Missing entries → not elevated, or run only for the current user; add `*` for all profiles and run as admin.
- A blank Publisher → run with `-s` to verify signatures; an unsigned autostart in a user path is the thing to look at.
- VirusTotal rate-limited or disabled → accept its terms with `-vt` once; results can lag minutes.

### 🛠️ Tool 2: PersistenceSniper

A PowerShell module (Blue-team, by Federico Lagrasta) that checks **60+** techniques in one call and returns them as objects you can filter, sort, diff and export. Validated against **v1.17.1**. Its licence is the *Commons Clause* version of MIT — free for non-commercial use.

#### Requirements

- Windows PowerShell 5.0+ (or PowerShell 7); administrator.
- To install from the Gallery, outbound HTTPS to PowerShell Gallery.

#### Installation

```powershell
# From the PowerShell Gallery (signed):
Install-Module PersistenceSniper -Scope CurrentUser
Import-Module PersistenceSniper
# Or from source:
#   git clone https://github.com/last-byte/PersistenceSniper
#   Import-Module .\PersistenceSniper\PersistenceSniper\PersistenceSniper.psd1
```

#### Configuration

No config file. Behaviour is chosen per call: `-PersistenceMethod` to run one check (default `All`), `-IncludeHighFalsePositivesChecks` to add the noisy ones (services, scheduled tasks, app paths), `-VTApiKey` to enrich with VirusTotal.

#### Verify the installation

```powershell
(Get-Module PersistenceSniper).Version
Find-AllPersistence -PersistenceMethod RunAndRunOnce | Format-Table Technique, Path, Value
```

#### First use

```powershell
# Sweep this host; review interactively
Find-AllPersistence | Out-GridView
# Save a baseline, then on another host show only what differs from it
Find-AllPersistence -OutputCSV .\baseline.csv
Find-AllPersistence -DiffCSV .\baseline.csv -OutputCSV .\findings.csv
# Only the MITRE-catalogued findings
Find-AllPersistence | Where-Object Classification -Like "MITRE ATT&CK T*"
```

#### Troubleshooting

- `Running scripts is disabled` → `Set-ExecutionPolicy -Scope Process RemoteSigned` for the session.
- Lots of noise → drop `-IncludeHighFalsePositivesChecks`, and use `-DiffCSV` against a golden image.
- A `Signature`/`IsBuiltinBinary` column that reads false on a system path → confirm with Autoruns `-s`; PersistenceSniper reports, it does not decide.

### 🛠️ Tool 3: Trawler

A single PowerShell script (by Joe Avanzato) that inspects a very wide set of artifacts and returns **only** the entries that match a detection rule, each with a risk, a MITRE technique and metadata — fewer, higher-signal results than a full dump. Validated against the **2025-05** build. MIT licence.

#### Requirements

- Windows PowerShell 5.0+; administrator.
- No install — it's one `.ps1`.

#### Installation

```powershell
# Download the single script
#   https://raw.githubusercontent.com/joeavanzato/Trawler/main/trawler.ps1
# Or clone:
#   git clone https://github.com/joeavanzato/Trawler
```

#### Configuration

Chosen by switch: `-ScanOptions` to pick checks (tab-completes; e.g. `Services,ScheduledTasks,IFEO`), `-snapshot` to capture a golden-image allow-list and later load it, `-drivetarget` to scan a mounted image, `-daysago` for the time-based detections, `-hashmode` (SHA1/SHA256/MD5).

#### Verify the installation

```powershell
Get-Help .\trawler.ps1 -Parameter ScanOptions
```

#### First use

```powershell
# Full local sweep; writes detections_<timestamp>.csv (and .json) to the given folder
.\trawler.ps1 -OutputLocation .
# Just a few check groups, with a fixed output name
.\trawler.ps1 -ScanOptions Services,ScheduledTasks,IFEO -OutputLocation . -filename det -notimestamp
# Dead-box: a mounted image rooted at F:\ (loads its hives under ANALYSIS_*)
.\trawler.ps1 -drivetarget "F:"
```

#### Troubleshooting

- Running as a plain user → many checks are skipped; run elevated.
- Too many results on a specialised host → build a `-snapshot` on a golden image and load it as an allow-list.
- Drive-retargeting misses live-only artifacts (running processes, network connections, WMI) — expected; combine with a live tool when you have one.

---

## Part 3: Hands-on labs

You hunt **FIN-WS-07** offline, the way you would a KAPE collection on a Linux box. `mk_persistence_hive.py` builds the three hives and the task XML; `persist_scan.py` (standard library) sweeps the ASEPs; **RegRipper** is pinned to a known commit so its output is stable, and corroborates each finding; `regf_peek.py` reads the raw hive. Nothing here needs a Windows host.

Run on Ubuntu 24.04 or SIFT. RegRipper needs Perl (its `lib/` is bundled, so no CPAN modules); the rest is Python 3 and `binutils` (for `strings`).

```bash
sudo apt update && sudo apt install -y git perl python3 binutils
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-022/{evidence,work,notes} ~/tools && cd ~/cases/LAB-022
export TZ=UTC
[ -d ~/tools/RegRipper3.0 ] || git clone -q https://github.com/keydet89/RegRipper3.0.git ~/tools/RegRipper3.0
git -C ~/tools/RegRipper3.0 checkout -q ec96dd4
R=~/tools/RegRipper3.0
rip() { PERL5LIB=$R/lib perl $R/rip.pl "$@" 2>/dev/null; }
git -C ~/tools/RegRipper3.0 log -1 --format='RegRipper pinned at %h (%as)'
perl -I $R/lib -MParse::Win32Registry -e 'print "Parse::Win32Registry loaded\n"'
```

```
RegRipper pinned at ec96dd4 (2026-05-27)
Parse::Win32Registry loaded
```

### Lab 1: Build and verify the collection (10 min)

Generate the evidence, hash it into your notes, and confirm each hive is a clean primary (sequence numbers equal — no transaction log to replay, Day 11):

```bash
python3 ~/DFIR/scripts/mk_persistence_hive.py evidence/FIN-WS-07
(cd evidence && find FIN-WS-07 -type f | LC_ALL=C sort | xargs -d '\n' sha256sum | cut -c1-16,65- > ../notes/collection.sha256)
cat notes/collection.sha256
for h in SOFTWARE SYSTEM NTUSER.DAT; do python3 ~/DFIR/scripts/regf_peek.py evidence/FIN-WS-07/$h | sed -n '3p'; done
```

```
wrote SOFTWARE, SYSTEM, NTUSER.DAT and Tasks/EdgeUpdate under evidence/FIN-WS-07
829e343f1922cb48  FIN-WS-07/NTUSER.DAT
37d9c96b2e8e2391  FIN-WS-07/SOFTWARE
cf9faac52ff7b35f  FIN-WS-07/SYSTEM
f58152704de7811e  FIN-WS-07/Tasks/EdgeUpdate
Sequence numbers: primary 1, secondary 1 -> CLEAN (equal)
Sequence numbers: primary 1, secondary 1 -> CLEAN (equal)
Sequence numbers: primary 1, secondary 1 -> CLEAN (equal)
```

Four files — three hives and one scheduled-task XML — and three **CLEAN** hives. The build is deterministic, so your hashes match these exactly.

### Lab 2: Sweep the autostarts offline (25 min)

One command walks the ASEPs the live tools would, across all three hives plus the task XML, and marks the suspicious ones (`[!]`). This is the offline equivalent of `autorunsc -a *` or `Find-AllPersistence`:

```bash
python3 ~/DFIR/scripts/persist_scan.py evidence/FIN-WS-07
```

```

== HKLM Run ==   (last write 2026-09-29 01:21:30.0187744)
  [!] MsEdgeUpdate = C:\ProgramData\Microsoft\Crypto\msedgeupdate.exe   <-- path under programdata
      SecurityHealth = %windir%\system32\SecurityHealthSystray.exe

== HKCU Run ==   (last write 2026-09-29 01:21:30.0187744)
      OneDrive = "C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background
  [!] Updater = C:\Users\dana\AppData\Roaming\update\updater.exe   <-- path under appdata

== Winlogon (last write 2026-09-29 01:21:30.0187744) ==
  [!] Userinit = C:\Windows\system32\userinit.exe,C:\Windows\Temp\winlogon.exe,   <-- extra program after userinit.exe
      Shell = explorer.exe

== AppInit_DLLs ==
  [!] AppInit_DLLs = C:\ProgramData\Intel\drv.dll   LoadAppInit_DLLs = 1 (0x1)   <-- DLL injected into every GUI process

== Image File Execution Options (Debugger hijacks) ==
  [!] sethc.exe\Debugger = C:\Windows\System32\cmd.exe   <-- launches instead of sethc.exe

== Services (auto / boot start) ==
      Dnscache         start=2 %SystemRoot%\system32\svchost.exe -k NetworkService
  [!] WinDefendUpd     start=2 C:\ProgramData\Microsoft\Crypto\defender.exe   <-- path under programdata (2026-09-29 01:22:10.5550001)

== LSA packages ==
  [!] Security Packages: kerberos msv1_0 schannel wdigest tspkg pku2u cloudap secupd   <-- unexpected: secupd
      Notification Packages: scecli
      Authentication Packages: msv1_0

== Scheduled tasks (TaskCache) ==
  [!] \EdgeUpdate -> C:\Users\dana\AppData\Local\Temp\edge\edgeupd.exe /sync   <-- path under temp

8 entries flagged for review (of the ASEPs checked). Confirm each file's signature before acting.
```

Read it like an analyst. The baseline entries are left unmarked: `SecurityHealth` and `OneDrive` in their normal paths, `W32Time`/`Dnscache` as `svchost` services (`W32Time` isn't even listed — its `Start` is manual, so it can't auto-run), the default LSA packages, `Shell = explorer.exe`. **Eight** entries are flagged, every one pointing into `Temp`, `AppData` or `ProgramData`, or changing a value that should hold a fixed default:

- two **Run** keys (HKLM `MsEdgeUpdate`, HKCU `Updater`),
- **Winlogon** `Userinit` with a second program appended,
- **AppInit_DLLs** turned on with a DLL in ProgramData,
- an **IFEO Debugger** on `sethc.exe` (a Sticky-Keys backdoor — cmd.exe from the lock screen),
- an auto-start **service** (`WinDefendUpd`) whose image is in ProgramData,
- a planted **LSA** security package (`secupd`),
- a **scheduled task** (`\EdgeUpdate`) running from `Temp`.

That is seven mechanisms (the Run count is two keys); the scan found all of them. Remember the rule: these are leads. The next labs confirm them.

### Lab 3: Corroborate with RegRipper (20 min)

Never conclude from one parser. RegRipper, pinned so its output matches, reads the same hives with purpose-built plugins and raises its own alerts:

```bash
echo '--- run (HKLM, SOFTWARE) ---'
rip -r evidence/FIN-WS-07/SOFTWARE -p run | grep -E 'CurrentVersion\\Run$|LastWrite Time 2026'
rip -r evidence/FIN-WS-07/SOFTWARE -p run | grep -E '^  [A-Za-z].* - ' | sort
echo '--- winlogon_tln (SOFTWARE) ---'
rip -r evidence/FIN-WS-07/SOFTWARE -p winlogon_tln
echo '--- imagefile (SOFTWARE) ---'
rip -r evidence/FIN-WS-07/SOFTWARE -p imagefile | grep -E 'sethc|Debugger'
echo '--- appinitdlls (SOFTWARE) ---'
rip -r evidence/FIN-WS-07/SOFTWARE -p appinitdlls | grep -E ' AppInit_DLLs :|ALERT'
echo '--- services (SYSTEM) ---'
rip -r evidence/FIN-WS-07/SYSTEM -p services | grep -B1 -A5 'Name      = WinDefendUpd'
echo '--- lsa (SYSTEM) ---'
rip -r evidence/FIN-WS-07/SYSTEM -p lsa | grep -E 'Packages +:'
```

```
--- run (HKLM, SOFTWARE) ---
Microsoft\Windows\CurrentVersion\Run
LastWrite Time 2026-09-29 01:21:30Z
  MsEdgeUpdate - C:\ProgramData\Microsoft\Crypto\msedgeupdate.exe
  SecurityHealth - %windir%\system32\SecurityHealthSystray.exe
--- winlogon_tln (SOFTWARE) ---
1790644890|ALERT|||Microsoft\Windows NT\CurrentVersion\Winlogon Userinit value has multiple entries: C:\Windows\system32\userinit.exe,C:\Windows\Temp\winlogon.exe,
--- imagefile (SOFTWARE) ---
sethc.exe  LastWrite: 2026-09-29 01:21:05Z
  Debugger             : C:\Windows\System32\cmd.exe
--- appinitdlls (SOFTWARE) ---
  AppInit_DLLs : C:\ProgramData\Intel\drv.dll
ALERT: appinitdlls: Entry not blank: C:\ProgramData\Intel\drv.dll
--- services (SYSTEM) ---
Tue Sep 29 01:22:10 2026 Z
  Name      = WinDefendUpd
  Display   = Windows Defender Update Service
  ImagePath = C:\ProgramData\Microsoft\Crypto\defender.exe
  Type      = Own_Process
  Start     = Auto Start
  Group     = 
--- lsa (SYSTEM) ---
Authentication Packages  : msv1_0
Notification Packages    : scecli
Security Packages        : kerberos msv1_0 schannel wdigest tspkg pku2u cloudap secupd
```

Every finding is independently confirmed: `run` lists both Run values, `winlogon_tln` **ALERTs** on the multi-entry Userinit, `imagefile` shows the `sethc.exe` Debugger, `appinitdlls` **ALERTs** that the value is not blank, `services` shows `WinDefendUpd` auto-starting from ProgramData, and `lsa` prints the package list with `secupd` on the end. Two tools, one story — that is how you turn a lead into a finding.

### Lab 4: The scheduled task, both halves (15 min)

A scheduled task lives in two places. The registry `TaskCache` holds the registration/last-run times; the XML under `System32\Tasks\` holds the **command**. Read both:

```bash
rip -r evidence/FIN-WS-07/SOFTWARE -p taskcache | grep -vE '^taskcache|^\(Soft|^[[:space:]]*$'
echo '--- task XML on disk (System32\Tasks\EdgeUpdate) ---'
strings -e l evidence/FIN-WS-07/Tasks/EdgeUpdate | grep -E '<(Command|Arguments|Date)>' | sed 's/^ *//'
```

```
EdgeUpdate
LastWrite: 2026-09-29 01:21:05Z
Id: {3F2504E0-4F89-41D3-9A0C-0305E82C3301}
Task Reg Time: 2026-09-29 01:21:05Z
Task Last Run: 2026-09-29 01:21:06Z
Task Completed: 2026-09-29 01:21:06Z
--- task XML on disk (System32\Tasks\EdgeUpdate) ---
<Date>2026-09-29T01:21:05</Date>
<Command>C:\Users\dana\AppData\Local\Temp\edge\edgeupd.exe</Command>
<Arguments>/sync</Arguments>
```

RegRipper's `taskcache` recovers the task's **registration time** (2026-09-29 01:21:05) from the `DynamicInfo` blob, and the on-disk XML gives the payload — `edgeupd.exe` in a Temp folder, triggered at logon and at boot. The registration time is attacker activity you can place on the timeline; the `<Date>` in the XML agrees with it.

### Lab 5: Persistence on a timeline (10 min)

Each registry key carries a last-write time. Pull the persistence keys out of all three hives and sort them, and the planting stands out as a burst:

```bash
for h in SOFTWARE SYSTEM NTUSER.DAT; do
  python3 ~/DFIR/scripts/regf_peek.py evidence/FIN-WS-07/$h --tree |
    grep -E '(sethc\.exe|Tree\\EdgeUpdate|CurrentVersion\\Windows|Winlogon|CurrentVersion\\Run|Services\\WinDefendUpd)$' |
    sed -E "s/^(2026-09-29 [0-9:]+)\.[0-9]+  +ROOT.(.*)$/\1 | $h | \2/"
done | sort | sed -E 's/Microsoft.Windows NT.CurrentVersion./…NT\\/; s/(Software.)?Microsoft.Windows.CurrentVersion./…CV\\/; s/ControlSet001./…/'
```

```
2026-09-29 01:21:05 | SOFTWARE | …NT\Image File Execution Options\sethc.exe
2026-09-29 01:21:05 | SOFTWARE | …NT\Schedule\TaskCache\Tree\EdgeUpdate
2026-09-29 01:21:05 | SOFTWARE | …NT\Windows
2026-09-29 01:21:30 | NTUSER.DAT | …CV\Run
2026-09-29 01:21:30 | SOFTWARE | …NT\Winlogon
2026-09-29 01:21:30 | SOFTWARE | …CV\Run
2026-09-29 01:22:10 | SYSTEM | …Services\WinDefendUpd
```

Seven keys written in **65 seconds**, 01:21:05 to 01:22:10 on 2026-09-29 — the same window Day 21's super timeline showed. Legitimate software is installed over months (this machine's baseline keys are dated January); persistence planted by hand clusters in seconds. A tight burst of autostart writes, late at night, is itself a detection.

---

## ✅ Knowledge check

1. Windows has "well over a hundred" places a program can auto-start. Why does that favour the attacker, and what single practice most reduces the defender's noise?
2. You find `Userinit = C:\Windows\system32\userinit.exe,C:\Windows\Temp\winlogon.exe,`. What is wrong, what should it be, and when does the extra program run?
3. A service's `ImagePath` is `C:\ProgramData\Microsoft\Crypto\defender.exe` with `Start = 2`. Name two things that make this suspicious and one way to be sure.
4. `persist_scan.py` left `W32Time` unflagged even though it's a service. Why? And why is "unflagged" not the same as "clean"?
5. Autoruns and PersistenceSniper are the obvious tools, but your evidence is a KAPE collection on a Linux box. Why can't you just run them, and what do you do instead?
6. A scheduled task appears in `TaskCache\Tree` with an `SD` value but there is **no** XML under `System32\Tasks`. What is this called and why does it matter?
7. An attacker adds `secupd` to `HKLM\SYSTEM\...\Lsa\Security Packages`. Into which process does that DLL load, and why is that the goal?
8. The seven persistence keys were all written between 01:21:05 and 01:22:10. What does that tell you, and what would an attacker do to defeat this particular observation?

<details>
<summary><b>Answers</b></summary>

1. Many ASEPs are **user-writable, unmonitored, and persistent**, and no human remembers them all — so a single value hides easily. The biggest noise reducer is **baselining/diffing** against a known-good image (Trawler `-snapshot`, PersistenceSniper `-DiffCSV`): everything expected drops out, leaving the deltas.
2. `Userinit` should be exactly `C:\Windows\system32\userinit.exe,`. A **second** executable has been appended; it runs at **every interactive logon** (after the real userinit). Fix/triage: confirm the appended binary's path and signature.
3. Suspicious: the image sits under **ProgramData** (user-writable, not a normal service location), and the name **masquerades** as a Defender component while not being a signed Microsoft binary; `Start=2` means it runs at every boot. Be sure by checking the file's **Authenticode signature** and reputation (and whether a real service by that name exists).
4. `W32Time`'s `Start` is **3 (manual)**, so it does not auto-start; the scan only reports boot/system/auto services. "Unflagged" only means it didn't match a heuristic — an attacker can hijack a **signed binary in a trusted path** (DLL search-order, a legitimate service's config), which no path/name rule would catch. Always combine signals.
5. They are **Windows-only** and read a **live** system (live registry, running services, on-disk signatures). Autoruns' `-z` and Trawler's `-drivetarget` need a Windows host with the image mounted; on Linux you hunt the **same ASEPs offline** — parse the hives (RegRipper/RECmd/Plaso), the TaskCache and the task XML, and diff against a baseline.
6. A **GhostTask** (registry-only scheduled task). It matters because, created directly in the registry without the usual XML, it may **not appear** in the Task Scheduler UI or standard task listings, so only a tool that reads `TaskCache` (or the XML's absence) will find it.
7. Into **lsass.exe**, as a Security Support Provider loaded at boot. That is the goal because lsass handles credentials — a malicious SSP (e.g. mimilib) can **log or steal plaintext passwords** as users authenticate.
8. It shows the persistence was **planted by hand in one short session**, not installed by legitimate software over time — a burst of autostart writes is itself a detection. To defeat it an attacker would **timestomp the registry** (harder than file times — last-write is set by the kernel on write), spread the changes out, or hijack **existing** keys rather than create new ones, so there is no fresh write to cluster.

</details>

---

## 📚 Further reading

- MITRE ATT&CK: tactic **Persistence (TA0003)**, techniques **T1547** (Boot or Logon Autostart), **T1053** (Scheduled Task/Job), **T1543** (Create or Modify System Process), **T1546** (Event Triggered Execution)
- Hexacorn, *Beyond good ol' Run key* series (over 150 parts) — the deepest catalogue of ASEPs
- Grzegorz Tworek, *persistence-info.github.io* — one page per technique, with detection notes
- Sysinternals *Autoruns* documentation (https://learn.microsoft.com/sysinternals/downloads/autoruns)
- PersistenceSniper wiki (https://github.com/last-byte/PersistenceSniper/wiki) and Trawler wiki (https://github.com/joeavanzato/Trawler)
- `libyal/winreg-kb`, *Task Scheduler Keys* and *Services and drivers* — the on-disk formats the parsers read

---

## ⏭️ Tomorrow: Day 23

**Memory forensics fundamentals & Windows RAM acquisition.** Tools: **WinPmem**, **Magnet RAM Capture**, **Belkasoft Live RAM Capturer**.
Persistence lives on disk; the running implant, its injected code, its keys and its network sockets live only in RAM. Tomorrow we start the memory phase by capturing it correctly — before it's gone.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
