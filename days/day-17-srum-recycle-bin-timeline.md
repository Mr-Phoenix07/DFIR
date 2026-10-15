# Day 17: SRUM, Recycle Bin & Windows Timeline (ActivitiesCache)

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~3.5 hours (reading + labs) · **Posted:** 2026-10-14
>
> **Tools today:** 🛠️ SrumECmd · 🛠️ RBCmd · 🛠️ WxTCmd

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain what **SRUM** records (network bytes, resource use and energy per program and user), where it lives, and why a copied `SRUDB.dat` is often **dirty**.
2. Decode **Recycle Bin** `$I` files (Vista–8.1 and Windows 10/11 formats) and XP's `INFO2`, and say what a deletion record proves and what it doesn't.
3. Parse the **Windows Timeline** database (`ActivitiesCache.db`) and handle its **write-ahead log** without changing the evidence.
4. Run SrumECmd, RBCmd and WxTCmd, and know which of them works off Windows and what to use instead.
5. Combine the three into a story: which program ran, how long it had focus, how much it sent, and what was thrown away.

---

## Part 1: The lesson

Days 10 to 16 told you **that** things happened on WS-ALICE: files created and timestomped, programs executed, logons, services, a three-minute rclone run. Today's artifacts measure **how much** and **how long**: how many bytes a program sent, how long a window had focus, and what a user deleted and when. All three are kept by Windows for its own reasons (battery and data reports, the Timeline view, undo), not for security, so they often survive when logs don't.

### 1.1 SRUM: the System Resource Usage Monitor

| | |
|---|---|
| **Where** | `C:\Windows\System32\sru\SRUDB.dat`, an **ESE** (JET Blue) database, with its transaction logs (`SRU*.log`, `SRUtmp.log`, `SRU.chk`) beside it. Windows 8 and later |
| **What** | Per **program** and **user**, per interval: **bytes sent and received** (and on which network interface/profile), **CPU cycles and bytes read/written** in the foreground and background, energy use, push notifications, and (Windows 10/11) per-app timeline data |
| **Configuration** | Providers are listed under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions`. User SIDs are resolved with the SOFTWARE hive's `ProfileList`, Wi-Fi profile names with `Microsoft\WlanSvc\Interfaces` |
| **Retention** | Typically weeks (commonly cited: about 30 to 60 days, depending on the table) |

The main tables, by the names SrumECmd gives them:

| Table (GUID) | Name | Key fields | Answers |
|---|---|---|---|
| `{973F5D5C-...}` | **NetworkUsages** | AppId, UserId, InterfaceLuid, L2ProfileId, **BytesSent**, **BytesRecvd** | How much did this program upload? On which network? |
| `{DD6636C4-...}` | NetworkConnections | InterfaceLuid, L2ProfileId, ConnectedTime, ConnectStartTime | When was the machine on which network, for how long? |
| `{D10CA2FE-...89}` | **AppResourceUseInfo** | Foreground/BackgroundCycleTime, Foreground/Background **BytesRead/Written** | Did this program run, as whom, and how much did it read or write? |
| `{5C8CF1C7-...}` | AppTimelineProvider | per-app usage timeline | When was the app in use? |
| `{FEE4E14F-...}` | EnergyUsage | battery charge levels | Was the laptop on battery, and when? |
| `{D10CA2FE-...86}` | PushNotifications | notifications per app | Which apps were active |
| `SruDbIdMapTable` | (ID map) | IdIndex → program path, service name or SID | Turns the numbers in AppId/UserId into names |

**How to read SRUM data:**

- **Records are aggregated and written roughly once an hour** (and at shutdown), so a record's `TimeStamp` is when an interval was written, not when the traffic happened. The newest activity may not be in the file yet.
- **Programs are named by path** (`\device\harddiskvolume3\users\alice\appdata\local\temp\rc\rclone.exe`) or, for services, by service name (`BITS`, `wuauserv`). A program that has since been deleted still has its rows: SRUM is **evidence of execution and of data volume** even when the binary is gone.
- **No destinations.** SRUM says *how many* bytes rclone sent over *which* interface, never *where* to (for that: Sysmon, firewall or proxy logs).
- **Dirty copies.** A live system keeps `SRUDB.dat` open; a copy taken while it runs (most triage collections) is usually in **dirty shutdown** state, with the latest pages still in the transaction logs. SrumECmd tells you to repair a **copy** on Windows with `esentutl /r sru /i` (replay the logs) and `esentutl /p SRUDB.dat` (repair). Collect the whole `sru` folder, not just the `.dat`.

On WS-ALICE, SRUM would put **numbers** on Day 16's rclone run: bytes sent per hour by `...\temp\rc\rclone.exe` under alice's SID, and bytes read from disk (her Documents). The labs use a **real Windows 11 SRUM database** from a public sample collection to practise exactly that kind of reading.

### 1.2 The Recycle Bin

| Windows | Location | Files |
|---|---|---|
| Vista to 11 | `<drive>:\$Recycle.Bin\<user SID>\` (one per NTFS volume) | **`$I<random6>.<ext>`**: metadata. **`$R<same>.<ext>`**: the content (a folder if a folder was deleted) |
| 2000 / XP | `<drive>:\RECYCLER\<user SID>\` | One **`INFO2`** index for all items + content files **`Dc<n>.<ext>`** |

The `$I` file is tiny and self-explanatory:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | **Version**: 1 = Vista to 8.1, 2 = Windows 10/11 |
| 8 | 8 | **Original size** in bytes (for a folder: everything inside it) |
| 16 | 8 | **Deletion time** (FILETIME, UTC) |
| 24 | v1: 520 / v2: 4 + n | **Original path**: v1 a fixed 520-byte UTF-16 field; v2 a length (characters, with the final NUL) then the UTF-16 path |

**What it proves:** the item at that path, of that size, was **deleted to the Recycle Bin** at that time, by the user whose **SID folder** holds it. **What it doesn't:** that the user did it by hand (a script can too), or what happened next.

**Gaps and anti-forensics:**

- **Not everything goes there**: `Shift+Delete`, `del` in `cmd`, PowerShell's `Remove-Item`, deletions over network shares and on removable media like USB sticks skip the Recycle Bin. Day 10's deleted `spec-1x.txt` files never appear in it.
- **Emptying** the bin deletes the `$I`/`$R` files: look for them in the MFT, the `$UsnJrnl` (Day 10) and unallocated space.
- **Restoring** an item moves `$R` back and deletes `$I`. In XP's `INFO2` the record stays, with the first byte of its ANSI path set to zero.
- The `$I` file's own MFT timestamps (Day 10) should match its deletion time: a mismatch deserves a look.

### 1.3 Windows Timeline: ActivitiesCache.db

| | |
|---|---|
| **Where** | `C:\Users\<user>\AppData\Local\ConnectedDevicesPlatform\<L.user or account ID>\ActivitiesCache.db`, a **SQLite** database with **`-wal`** and **`-shm`** files |
| **Since** | Windows 10 1803 (the Timeline view, `Win+Tab`). Windows 11 removed that view, but the database can still be found and filled: today's Windows 11 sample has 30 records |
| **Tables** | `Activity` (what happened), `ActivityOperation` (changes queued for sync), `Activity_PackageId` (which program or package an activity belongs to) |
| **Retention** | Each record has an `ExpirationTime`; history typically covers weeks |

| ActivityType | Meaning (WxTCmd's names) | Why it matters |
|---|---|---|
| 5 | **ExecuteOpen**: a program or a file in a program was opened | Program **and file** paths (e.g. `C:\temp.txt` in Notepad), with the volume |
| 6 | **InFocus**: the program was in the foreground | **Start, end and duration** of use |
| 10 | CloudClipboard | Clipboard **content** (only with clipboard history/sync on) |
| 16 | CopyPaste | Copy and paste happened, with time and program |
| 2 | ToastNotification | Notifications shown |

**The write-ahead log matters.** SQLite in WAL mode writes new data to `ActivitiesCache.db-wal` first and only later copies it into the `.db` (a *checkpoint*). In today's Windows 11 sample the `.db` is a **4 KB** empty shell and **all** the data is in the 2 MB `-wal`: collect all three files together. And never open the original read-write: SQLite checkpoints on close and **rewrites the evidence** (Lab 3 shows it on a copy).

### 1.4 Putting them together

| Question | SRUM | Timeline | Recycle Bin |
|---|---|---|---|
| Did the program run? | Yes, hourly, with user | Yes, with open/focus times | — |
| How long was it used? | Foreground cycles (rough) | **InFocus duration** | — |
| How much data did it move? | **Bytes sent/received**, bytes read/written | — | — |
| Which files were involved? | — | Files opened in apps (type 5) | **Deleted files**: path, size, time |
| Who? | User SID | The profile the database belongs to | The SID folder |

---

## Part 2: Tools

All three are Eric Zimmerman's command-line tools (MIT licence), built on .NET 9. On Windows, download them from https://ericzimmerman.github.io/ (or with `Get-ZimmermanTools.ps1`); on Linux and macOS, build them from source with the .NET SDK, as on Days 12 to 14.

---

### 🛠️ Tool 1: SrumECmd

| | |
|---|---|
| **What** | Parses `SRUDB.dat` (with the SOFTWARE hive) into one CSV per table: NetworkUsages, NetworkConnections, AppResourceUseInfo, AppTimelineProvider, EnergyUsage, PushNotifications, vfuprov |
| **Why in DFIR** | The fastest way to turn SRUM into a timeline of data volume and execution per program and user; works with KAPE (`-d` finds `SRUDB.dat` and `SOFTWARE` in a collection) |
| **Platforms** | **Windows only.** It uses Windows' own ESE library (`esent.dll` through ManagedEsent). Built on Linux it starts but exits: *"Non-Windows platforms not supported due to the need to load ESI specific Windows libraries!"* (Lab 1). **The labs read SRUM on Linux with dissect.esedb and libesedb instead** |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/Srum |

#### Requirements

Windows with the .NET 9 runtime; `SRUDB.dat` in a **clean** state (repair a copy with `esentutl` if it's dirty); the SOFTWARE hive from the same machine (optional but recommended).

#### Installation

```powershell
# Windows: from https://ericzimmerman.github.io/ (or Get-ZimmermanTools.ps1), then
.\SrumECmd.exe --version
```

```bash
# Linux/macOS: it builds, but exits at start-up (see above); use dissect.esedb (Lab 1) instead
sudo apt install -y dotnet-sdk-10.0 git
git clone https://github.com/EricZimmerman/Srum.git ~/tools/src/Srum
dotnet publish ~/tools/src/Srum/SrumECmd/SrumECmd.csproj -c Release -f net9.0 -o ~/tools/SrumECmd
```

#### Configuration

| Option | Meaning |
|---|---|
| `-f SRUDB.dat` | The database to parse |
| `-r SOFTWARE` | The SOFTWARE hive: SIDs to user names (ProfileList), Wi-Fi profile IDs to names (WlanSvc) |
| `-d DIR` | Search a folder (e.g. a KAPE collection) for `SRUDB.dat` and `SOFTWARE` |
| `--csv DIR` | Output folder: one `<timestamp>_SrumECmd_<Table>_Output.csv` per table |
| `--dt FORMAT` | Timestamp format |
| `--debug`, `--trace` | More logging |

#### Verify the installation

```powershell
.\SrumECmd.exe --version
```

#### First use

```powershell
# on a COPY of C:\Windows\System32\sru (all files) and the SOFTWARE hive
esentutl.exe /mh .\SRUDB.dat                    # check "State:" (Clean Shutdown / Dirty Shutdown)
esentutl.exe /r sru /i                          # if dirty: replay the logs, then
esentutl.exe /p .\SRUDB.dat                     # repair
.\SrumECmd.exe -f .\SRUDB.dat -r .\SOFTWARE --csv C:\Cases\WS-ALICE\srum
```

Open `*_SrumECmd_NetworkUsages_Output.csv` in Timeline Explorer, filter the program column for paths under `\Users\` and `\Temp\`, and sort by bytes sent.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "Error processing file! ... This almost always means the database is dirty" | Repair a copy with `esentutl /r sru /i` then `esentutl /p SRUDB.dat`, run as Administrator, with the folder not read-only |
| "Non-Windows platforms not supported ..." | It needs Windows: use a Windows VM, or dissect.esedb / libesedb on Linux (Lab 1) |
| User names missing (only SIDs) | Add `-r` with the same machine's SOFTWARE hive |
| The newest hour of activity is missing | SRUM writes roughly hourly; it may never have reached the file |

---

### 🛠️ Tool 2: RBCmd

| | |
|---|---|
| **What** | Parses Recycle Bin index files: `$I` (Vista to 11) and `INFO2` (XP) |
| **Why in DFIR** | One line per deleted item: original path, size, deletion time; run over a whole collection with `-d` |
| **Platforms** | Windows; **built from source and run on Ubuntu 24.04** (2026.5.0) |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/RBCmd |

#### Requirements

The `$I` or `INFO2` files (a triage collection's `$Recycle.Bin` folder); .NET 9 runtime (Windows) or the .NET SDK to build it (Linux).

#### Installation

```powershell
# Windows: from https://ericzimmerman.github.io/
.\RBCmd.exe --version
```

```bash
# Linux/macOS (validated here)
git clone https://github.com/EricZimmerman/RBCmd.git ~/tools/src/RBCmd
dotnet publish ~/tools/src/RBCmd/RBCmd/RBCmd.csproj -c Release -f net9.0 -o ~/tools/RBCmd
DOTNET_ROLL_FORWARD=Major ~/tools/RBCmd/RBCmd --version
```

#### Configuration

| Option | Meaning |
|---|---|
| `-f FILE` | One `$I` or `INFO2` file |
| `-d DIR` | Search a folder recursively |
| `--csv DIR`, `--csvf NAME` | CSV output folder and file name |
| `-q` | Show only file names while processing |
| `--dt FORMAT` | Timestamp format (default `yyyy-MM-dd HH:mm:ss`) |

#### Verify the installation

```bash
DOTNET_ROLL_FORWARD=Major ~/tools/RBCmd/RBCmd -f ~/tools/src/RBCmd/RecycleBin.Test/TestFiles/WinXp*/INFO2
```

#### First use

```bash
rbcmd -d '/cases/WS-ALICE/C/$Recycle.Bin' --csv /cases/WS-ALICE/out --csvf recyclebin.csv
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| A file is skipped | RBCmd takes `$I*` files and files named exactly `INFO2`; renamed copies (like the `INFO2_MultiFiles` test file) are ignored: rename, or decode with `rb_index.py` |
| `$` vanishes from paths in the shell | Quote paths with single quotes: `'$Recycle.Bin'` (in double quotes, `$R...` is a shell variable) |
| `$I` without `$R` | The content was deleted from the bin, or wasn't collected; the metadata still stands |
| Size doesn't match the `$R` file | For folders, the `$I` size is the total of the folder's contents |

---

### 🛠️ Tool 3: WxTCmd

| | |
|---|---|
| **What** | Parses the Windows Timeline database (`ActivitiesCache.db`) into CSVs of activities, pending operations and package IDs |
| **Why in DFIR** | Which programs and files a user opened, and **for how long** each was in focus, with known-folder GUIDs translated into paths |
| **Platforms** | Windows; **runs natively on Linux** (see its `LINUX.md`: publish it for `linux-x64`). **Built and run on Ubuntu 24.04** (2026.5.0) |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/WxTCmd |

#### Requirements

`ActivitiesCache.db` **with its `-wal` and `-shm` files** in the same folder; .NET 9 runtime (Windows) or SDK (Linux).

#### Installation

```powershell
# Windows: from https://ericzimmerman.github.io/
.\WxTCmd.exe --version
```

```bash
# Linux (validated here; LINUX.md describes the same build)
git clone https://github.com/EricZimmerman/WxTCmd.git ~/tools/src/WxTCmd
dotnet publish ~/tools/src/WxTCmd/WxTCmd/WxTCmd.csproj -c Release -f net9.0 -r linux-x64 -o ~/tools/WxTCmd
DOTNET_ROLL_FORWARD=Major ~/tools/WxTCmd/WxTCmd --version
```

#### Configuration

| Option | Meaning |
|---|---|
| `-f FILE` | `ActivitiesCache.db` (keep `-wal`/`-shm` next to it) |
| `--csv DIR` | Output: `*_Activity.csv`, `*_Activity_PackageIDs.csv` and, when present, `*_ActivityOperations.csv`, named with the run time and the profile folder (`L.<user>`) |
| `--dt FORMAT` | Timestamp format |

#### Verify the installation

```bash
DOTNET_ROLL_FORWARD=Major ~/tools/WxTCmd/WxTCmd --version
```

#### First use

```bash
cp -r '/cases/WS-ALICE/C/Users/alice/AppData/Local/ConnectedDevicesPlatform' /cases/work/cdp   # work on a copy
wxtcmd -f /cases/work/cdp/L.alice/ActivitiesCache.db --csv /cases/WS-ALICE/out
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| "no such table" / 0 entries, but the file is there | The data is in `-wal`: copy the `-wal` and `-shm` with it |
| The evidence file changed after you looked at it | It was opened read-write and checkpointed: work on copies, or `sqlite3 -readonly` |
| Paths start with a GUID | Known-folder GUIDs (e.g. `{1AC14E77-...}` = System32); WxTCmd maps the known ones |
| Windows 11 machine has few or no records | Timeline was removed from Windows 11; what remains depends on version and settings |

---

## Part 3: Hands-on labs

Three artifacts, three kinds of data: a **real Windows 11 SRUM database** (clean and dirty copies) and a **real Windows 11 Timeline database** from Andrew Rathbun's public *DFIR Artifact Museum*, **WS-ALICE's Recycle Bin** from the Day 9 collection, and **real `$I`/`INFO2` files** from RBCmd's test set (Windows XP to 10). Everything is pinned to fixed versions.

Run on Ubuntu 24.04 or SIFT.

```bash
sudo apt update && sudo apt install -y git curl dotnet-sdk-10.0 libesedb-utils sqlite3 python3-venv
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-017/{evidence,work,notes,samples} ~/tools && cd ~/cases/LAB-017
export TZ=UTC
```

Build the three tools from fixed commits, and install dissect.esedb (a pure-Python ESE reader) in a virtual environment (a few minutes):

```bash
for t in Srum:c228b70b5768afe6d12c52a4f8702bdc0997ee29 RBCmd:756498f9b5e94327abe5398b19435b7142f7265c \
         WxTCmd:adbf96ed9c73dc6806d97b96160bb96bccd48f7a; do
  repo=${t%%:*}; commit=${t#*:}
  if [ ! -d ~/tools/src/$repo ]; then
    git init -q ~/tools/src/$repo
    git -C ~/tools/src/$repo fetch -q --depth 1 https://github.com/EricZimmerman/$repo.git $commit
    git -c advice.detachedHead=false -C ~/tools/src/$repo checkout -q FETCH_HEAD
  fi
done
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
dotnet publish ~/tools/src/Srum/SrumECmd/SrumECmd.csproj -c Release -f net9.0 -o ~/tools/SrumECmd -v quiet > /dev/null
dotnet publish ~/tools/src/RBCmd/RBCmd/RBCmd.csproj -c Release -f net9.0 -o ~/tools/RBCmd -v quiet > /dev/null
dotnet publish ~/tools/src/WxTCmd/WxTCmd/WxTCmd.csproj -c Release -f net9.0 -r linux-x64 -o ~/tools/WxTCmd -v quiet > /dev/null
[ -d ~/tools/dissect-venv ] || python3 -m venv ~/tools/dissect-venv
~/tools/dissect-venv/bin/pip install -q dissect.esedb==3.18 dissect.cstruct==4.7 dissect.util==3.24 2> /dev/null
srumecmd() { DOTNET_ROLL_FORWARD=Major ~/tools/SrumECmd/SrumECmd "$@"; }
rbcmd() { DOTNET_ROLL_FORWARD=Major ~/tools/RBCmd/RBCmd "$@"; }
wxtcmd() { DOTNET_ROLL_FORWARD=Major ~/tools/WxTCmd/WxTCmd "$@"; }
srum_view() { ~/tools/dissect-venv/bin/python ~/DFIR/scripts/srum_view.py "$@"; }
for t in srumecmd rbcmd wxtcmd; do echo "$t $($t --version | cut -c1-17)"; done
esedbinfo -V | head -n 1
```

```
srumecmd 2026.5.0+c228b70b
rbcmd 2026.5.0+756498f9
wxtcmd 2026.5.0+adbf96ed
esedbinfo 20181229
```

### Lab 1: SRUM on Linux, clean and dirty (30 min)

```bash
MUSEUM=https://raw.githubusercontent.com/AndrewRathbun/DFIRArtifactMuseum/fdcb1fab0c7b00e89129668d9c30174dd4ea3e5b/Windows
mkdir -p samples/srum-clean samples/srum-dirty
curl -sSfL -o samples/srum-clean/SRUDB.dat $MUSEUM/SRUM/Win11/RathbunVM/Clean/SRUDB.dat
curl -sSfL -o samples/srum-dirty/SRUDB.dat $MUSEUM/SRUM/Win11/RathbunVM/Dirty/SRUDB.dat
sha256sum samples/srum-*/SRUDB.dat | cut -c1-16,65- | tee notes/srum.sha256
python3 ~/DFIR/scripts/ese_header.py samples/srum-clean/SRUDB.dat samples/srum-dirty/SRUDB.dat
esedbinfo samples/srum-clean/SRUDB.dat | grep -c '^Table:'
esedbinfo samples/srum-dirty/SRUDB.dat 2>&1 | grep -m 1 checksum
srumecmd -f samples/srum-clean/SRUDB.dat --csv work/srum 2>&1 | grep -v '^$' | tail -n 1
```

```
f2aeeafe6843aefb  samples/srum-clean/SRUDB.dat
b1b0e0e9e95cdc44  samples/srum-dirty/SRUDB.dat
samples/srum-clean/SRUDB.dat
  format 0x620,200  page size 4096  file type database
  state 3 (clean shutdown)
  consistent 2022-07-19 17:01:26 (-)
  attach     2022-07-19 17:01:26 (-)
  detach     2022-07-19 17:01:26 (-)
samples/srum-dirty/SRUDB.dat
  format 0x620,200  page size 4096  file type database
  state 2 (dirty shutdown)
  consistent 2022-07-03 02:22:47 (generation 0x5c)
  attach     2022-07-19 16:57:14 (generation 0x5c)
  detach     - (-)
14
libesedb_file_header_read_data: mismatch in file header checksum ( 0x86e49714 != 0x818fe739 ).
Non-Windows platforms not supported due to the need to load ESI specific Windows libraries! Exiting...
```

The two files are the same Windows 11 VM's `SRUDB.dat`, as published by the sample collection: one as collected, one repaired. The header tells which is which, and more:

- **Dirty**: state **2 (dirty shutdown)**, attached (opened by Windows) at 2022-07-19 16:57:14 and **never detached**: it was copied from a running system. It was last consistent on 2022-07-03 02:22:47 and needs **log generation 0x5c** (its `SRU*.log` files) to catch up.
- **Clean**: state **3**, and its consistent, attach and detach times are all 2022-07-19 17:01:26: most likely the moment it was repaired, four minutes after the dirty copy was opened.
- **libesedb** (2018) lists the clean copy's 14 tables but refuses the dirty copy's header checksum. **SrumECmd** builds on Linux but stops at start-up: it needs Windows' ESE library. So on Linux, use **dissect.esedb**, through `srum_view.py` (in `scripts/`):

```bash
srum_view samples/srum-clean/SRUDB.dat
srum_view samples/srum-clean/SRUDB.dat --network 8 | cut -c1-140
srum_view samples/srum-clean/SRUDB.dat --app ninite
srum_view samples/srum-dirty/SRUDB.dat --network 3 | cut -c1-140
```

```
SruDbIdMapTable           1044 records
SruDbCheckpointTable         0 records
EnergyEstimator            810 records  2022-07-01 02:10 -> 2022-07-03 02:06
AppTimelineProvider        791 records  2022-07-01 02:10 -> 2022-07-03 02:06
vfuprov                     33 records  2022-05-28 03:28 -> 2022-07-03 02:06
NetworkUsages              143 records  2022-05-28 03:28 -> 2022-07-03 02:06
AppResourceUseInfo         662 records  2022-05-28 03:28 -> 2022-07-03 02:06
NetworkConnections           9 records  2022-05-28 03:28 -> 2022-07-03 02:06
EnergyUsage                 13 records  2022-05-28 03:28 -> 2022-07-03 02:06
EnergyUsage (long term)      2 records  2022-05-28 03:28 -> 2022-07-03 02:05
   BytesSent   BytesRecvd Recs  User / program
    23835185   3001496268    3  -  -
     7679234    194794750    3  S-1-5-21-2209459975-2648094048-902850153-1001  DoSvc
     4316502      1933341    3  S-1-5-18  wuauserv
     3140439     15083896    3  S-1-5-21-2209459975-2648094048-902850153-1001  \device\harddiskvolume3\program files (x86)\microsoft\edge\ap
     1894271      1211967    3  S-1-5-21-2209459975-2648094048-902850153-1001  DiagTrack
     1668640      3274272    3  S-1-5-21-2209459975-2648094048-902850153-1001  wuauserv
      901441     27485445    3  S-1-5-21-2209459975-2648094048-902850153-1001  BITS
      594151       133692    3  S-1-5-18  WinDefend
2022-05-28 03:28  AppResourceUseInfo S-1-5-21-2209459975-2648094048-902850153-1001  \Device\HarddiskVolume3\Users\CFUser\Desktop\Ninite 7Zip Chrome Everything SumatraPDF Installer.exe
                  fg read 1935360 written 1892352 | bg read 0 written 0
2022-05-28 03:28  AppResourceUseInfo S-1-5-21-2209459975-2648094048-902850153-1001  \Device\HarddiskVolume3\Users\CFUser\AppData\Local\Temp\3438ab3a-a7c4-11ec-9f41-ec63d7728336\Ninite.exe
                  fg read 8150528 written 96399360 | bg read 0 written 0
2022-05-28 03:28  NetworkUsages      S-1-5-21-2209459975-2648094048-902850153-1001  \device\harddiskvolume3\users\cfuser\appdata\local\temp\3438ab3a-a7c4-11ec-9f41-ec63d7728336\ninite.exe
                  sent 162027 recvd 8115566
2022-05-28 03:28  NetworkUsages      S-1-5-21-2209459975-2648094048-902850153-1001  \device\harddiskvolume3\users\cfuser\desktop\ninite 7zip chrome everything sumatrapdf installer.exe
                  sent 7346 recvd 89594
   BytesSent   BytesRecvd Recs  User / program
    23835185   3001496268    3  -  -
     7679234    194794750    3  S-1-5-21-2209459975-2648094048-902850153-1001  DoSvc
     4316502      1933341    3  S-1-5-18  wuauserv
```

- **Tables and time span:** NetworkUsages has 143 records between 2022-05-28 and 2022-07-03, written at only a few distinct times (03:28, ...): SRUM writes roughly hourly and only while the machine runs, and this VM was rarely on.
- **Top senders:** Windows services by name (`DoSvc` = Delivery Optimization, `wuauserv` = Windows Update, `BITS`, `DiagTrack`), Edge by path, each under a **user SID** (S-1-5-18 = SYSTEM; the `-1001` account owns the `C:\Users\CFUser` profile, as the Ninite paths show). The first row's program and user don't resolve to a name in `SruDbIdMapTable`.
- **Ninite**: an installer run from the user's Desktop unpacked `Ninite.exe` into `AppData\Local\Temp\<GUID>\`, which **received 8 MB and wrote 96 MB** to disk. Legitimate here, but it's exactly the shape of WS-ALICE's rclone (`...\Temp\rc\rclone.exe`): SRUM keeps the path, the user and the volumes **even after the program is deleted**. On WS-ALICE you'd look for rclone's `BytesSent` and its `BytesRead` (alice's Documents) in the 01:00 to 02:00 records.
- **Dirty copy:** dissect.esedb read it as it is and gives the same top senders. What it can't give you is anything still in the transaction logs; on a real case, replay and repair a copy on Windows and compare.

### Lab 2: WS-ALICE's Recycle Bin, and the formats over time (25 min)

```bash
python3 ~/DFIR/scripts/mk_win_triage_lab.py evidence/WS-ALICE > /dev/null
RB='evidence/WS-ALICE/$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001'
ls -l "$RB" | awk 'NR > 1 {print $5, $9}'
xxd "$RB/\$I7Q2KD1.ps1"
rbcmd -f "$RB/\$I7Q2KD1.ps1" | grep -E '^(Version|File size|File name|Deleted on):'
python3 ~/DFIR/scripts/rb_index.py "$RB"
```

```
94 $I7Q2KD1.ps1
412 $R7Q2KD1.ps1
00000000: 0200 0000 0000 0000 9c01 0000 0000 0000  ................
00000010: 800e 101f af4f dd01 2100 0000 4300 3a00  .....O..!...C.:.
00000020: 5c00 5500 7300 6500 7200 7300 5c00 6100  \.U.s.e.r.s.\.a.
00000030: 6c00 6900 6300 6500 5c00 4400 6500 7300  l.i.c.e.\.D.e.s.
00000040: 6b00 7400 6f00 7000 5c00 7300 7400 6100  k.t.o.p.\.s.t.a.
00000050: 6700 6500 2e00 7000 7300 3100 0000       g.e...p.s.1...
Version: 2 (Windows 10/11)
File size: 412 (412B)
File name: C:\Users\alice\Desktop\stage.ps1
Deleted on: 2026-09-29 01:09:05
$I7Q2KD1.ps1  v2    94 bytes  deleted 2026-09-29 01:09:05  size        412  C:\Users\alice\Desktop\stage.ps1
```

Decode the 94-byte `$I` by hand: `0200 0000 0000 0000` = **version 2** (Windows 10/11); `9c01 ...` = **412 bytes** (0x19C), the same size as the `$R` file; `800e 101f af4f dd01` = the FILETIME **2026-09-29 01:09:05 UTC**; `2100 0000` = **33 characters** (32 + the final NUL); then the UTF-16 path. RBCmd and `rb_index.py` agree.

**alice deleted `C:\Users\alice\Desktop\stage.ps1` at 01:09:05**, 26 seconds before she started the hidden PowerShell (01:09:31, Days 14 and 16). The SID folder (`...-1001`) says it was her Recycle Bin, and the content is still there in `$R7Q2KD1.ps1` (Day 9's stand-in): a "deleted" staging script you can still read.

```bash
cp -r ~/tools/src/RBCmd/RecycleBin.Test/TestFiles samples/recyclebin
rbcmd -d samples/recyclebin --csv work/rb --csvf samples.csv -q > /dev/null
cut -d, -f1-5 work/rb/samples.csv | sed "s#$PWD/samples/recyclebin/##" | LC_ALL=C sort
python3 ~/DFIR/scripts/rb_index.py samples/recyclebin/WinXp*/INFO2_MultiFiles
```

```
SourceName,FileType,FileName,FileSize,DeletedOn
samples/recyclebin/Win10 - DEFCON 2018 Desktop/$I2JRX90,$I,C:\temp,14155310,2018-08-07 19:54:58
samples/recyclebin/Win10 - DEFCON 2018 Desktop/$IFATB0K,$I,C:\vss,3276800,2018-08-07 19:54:50
samples/recyclebin/Win7 - nfury/$I6SODDB,$I,C:\Windows\System32\dllhost,102742,2012-04-06 18:42:04
samples/recyclebin/Win7 - nfury/$ID5HSV3.exe,$I,C:\Windows\System32\hythonize.exe,3943584,2012-04-06 18:43:07
samples/recyclebin/Win7 - nfury/$IZI9VH9.exe,$I,C:\Windows\System32\hythonized.exe,2990574,2012-04-06 18:43:07
samples/recyclebin/Win7 - nromanoff/$IPFXZSB,$I,C:\Users\Public\Pictures\Sample Pictures,5838271,2012-04-01 14:16:47
samples/recyclebin/Win7 - nromanoff/$ISEBKEC.zip,$I,C:\Users\nromanoff\Documents\New-Site-HQ-And-Landing-Pad.zip,13449655,2012-03-16 20:27:20
samples/recyclebin/Win8.1 - Donald Blake/$I3VPA17,$I,C:\Users\Donald\SkyDrive\Documents\Lean startup,16131820,2013-10-21 19:59:21
samples/recyclebin/Win8.1 - Donald Blake/$IEMAANA,$I,C:\Users\Donald\SkyDrive\Documents\Articles,1399035,2013-10-21 19:59:21
samples/recyclebin/Win8.1 - Donald Blake/$IG1VEXX.xls,$I,C:\Users\Donald\SkyDrive\Documents\WACC Calc Spreadsheet -SECRET.xls,16384,2013-10-21 18:32:52
samples/recyclebin/Win8.1 - Donald Blake/$ISFWPA9.xls,$I,C:\Users\Donald\SkyDrive\Documents\WACC Calc Spreadsheet -SECRET-Bifrost.xls,16384,2013-10-21 18:32:52
samples/recyclebin/WinXp - mueller1/INFO2,INFO2,Z:\WINDOWS\explorer.exe,1005568,2008-01-30 15:13:03
INFO2_MultiFiles  version 5, 800-byte records
  Dc1  drive C:  deleted 2018-11-20 02:04:54  size          0  C:\Documents and Settings\test\Desktop\this file has a really really really really really really really really really really really really really really really really really really really really really really really really really really really long name11.txt
  Dc2  drive C:  deleted 2018-11-20 02:04:54  size       4096  C:\Documents and Settings\test\Desktop\first file.txt  (ANSI path's first byte zeroed: removed from the bin)
  Dc3  drive C:  deleted 2018-11-20 02:04:54  size       4096  C:\Documents and Settings\test\Desktop\Folder1  (ANSI path's first byte zeroed: removed from the bin)
  Dc4  drive C:  deleted 2018-11-20 02:04:54  size     360448  C:\Documents and Settings\test\Desktop\Folder2
```

Real deletions from four Windows versions:

- **Windows 7, nfury**: `hythonize.exe`, `hythonized.exe` and `dllhost` (**no extension**, 102,742 bytes) deleted from `System32` within a minute: someone cleaning up suspicious files in a system folder. `$I` files here are version 1: always **544 bytes**, the path in a fixed 520-byte field.
- **Windows 8.1, Donald Blake**: two versions of a spreadsheet named `-SECRET` deleted in the same second, then two **folders** (`Lean startup`, `Articles`): for folders, the size is everything that was inside.
- **Windows 10, DEFCON 2018**: two folders deleted from the root, `C:\vss` and `C:\temp`, 8 seconds apart.
- **Windows XP**: one `INFO2` for the whole bin. RBCmd only reads files named exactly `INFO2`, so it skipped `INFO2_MultiFiles`; `rb_index.py` shows its four records, two of them with the ANSI path's first byte zeroed: marked as removed from the bin (restored or purged), while the record itself is still there.

### Lab 3: Windows Timeline and its write-ahead log (30 min)

```bash
mkdir -p samples/timeline11 samples/dbonly work/rw
for f in ActivitiesCache.db ActivitiesCache.db-wal ActivitiesCache.db-shm; do
  curl -sSfL -o samples/timeline11/$f $MUSEUM/WindowsTimeline/Win11/RathbunVM/$f
done
(cd samples/timeline11 && sha256sum ActivitiesCache.db* | cut -c1-16,65- && ls -l ActivitiesCache.db* | awk '{print $5, $9}')
cp samples/timeline11/ActivitiesCache.db samples/dbonly/
sqlite3 -readonly samples/dbonly/ActivitiesCache.db 'SELECT count(*) FROM Activity;' 2>&1
sqlite3 -readonly samples/timeline11/ActivitiesCache.db 'SELECT count(*) FROM Activity;'
sqlite3 -readonly samples/timeline11/ActivitiesCache.db '.tables'
cp samples/timeline11/ActivitiesCache.db* work/rw/
sqlite3 work/rw/ActivitiesCache.db 'SELECT count(*) FROM Activity;'
ls -l work/rw | awk 'NR > 1 {print $5, $9}'
```

```
b82d1534443cd79c  ActivitiesCache.db
62125e518e08632b  ActivitiesCache.db-shm
4a724f9870e4f20c  ActivitiesCache.db-wal
4096 ActivitiesCache.db
32768 ActivitiesCache.db-shm
2228952 ActivitiesCache.db-wal
Error: in prepare, no such table: Activity
30
Activity            AppSettings         ManualSequence    
ActivityOperation   Asset               Metadata          
Activity_PackageId  DataEncryptionKeys  SmartLookup       
30
176128 ActivitiesCache.db
```

- The `.db` is a **4 KB** shell; the data is in the **2.2 MB `-wal`**. Copied alone, the database has **no tables at all**; with its WAL, it has 30 activities in nine tables.
- Opening a copy **read-write** (no `-readonly`) and closing it made SQLite **checkpoint**: the `.db` grew to 176,128 bytes and the `-wal` and `-shm` files were deleted. Done to the original evidence, that changes its hashes and destroys the WAL as a separate artifact. Hash first, work on copies, use `-readonly`.

```bash
cp -r samples/timeline11 work/timeline11
wxtcmd -f work/timeline11/ActivitiesCache.db --csv work/wxt | grep -E 'entries found'
python3 - work/wxt/*_Activity.csv <<'EOF'
import csv, sys, collections
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")))
print(collections.Counter(r["ActivityType"] for r in rows).most_common())
for r in sorted(rows, key=lambda r: (r["StartTime"], r["ActivityType"], r["EndTime"])):
    if r["ActivityType"] in ("ExecuteOpen", "InFocus"):
        what = r["DisplayText"] if r["ActivityType"] == "ExecuteOpen" else f'in focus {r["Duration"] or "00:00:00"} until {r["EndTime"][11:]}'
        content = f' | {r["ContentInfo"].split(" (")[0]}' if r["ContentInfo"] else ""
        print(f'{r["StartTime"]}  {r["ActivityType"]:<11} {r["Executable"]:<46} {what}{content}')
EOF
```

```
ActivityOperation entries found: 0
Activity_PackageId entries found: 80
Activity entries found: 30
[('CopyPaste', 11), ('InFocus', 9), ('ExecuteOpen', 6), ('11', 4)]
2022-03-05 13:36:58  ExecuteOpen Microsoft.Windows.Explorer                     File Explorer
2022-03-05 13:36:58  InFocus     Microsoft.Windows.Explorer                     in focus 00:00:16 until 13:37:14
2022-03-05 13:37:08  ExecuteOpen D:\setup64.exe                                 setup64.exe
2022-03-05 13:37:14  ExecuteOpen Microsoft.Windows.WindowsInstaller             Microsoft.Windows.WindowsInstaller
2022-03-05 13:37:15  InFocus     D:\setup64.exe                                 in focus 00:02:04 until 13:39:19
2022-03-05 13:39:19  InFocus     D:\setup64.exe                                 in focus 00:00:16 until 13:39:35
2022-03-05 13:40:29  ExecuteOpen Microsoft.WindowsTerminal_8wekyb3d8bbwe!App    Windows Terminal
2022-03-05 13:40:29  InFocus     Microsoft.WindowsTerminal_8wekyb3d8bbwe!App    in focus 07:15:55 until 20:56:24
2022-03-05 13:44:07  InFocus     Microsoft.Windows.Explorer                     in focus 00:07:04 until 13:51:11
2022-03-05 13:44:29  ExecuteOpen Microsoft.WindowsNotepad_8wekyb3d8bbwe!App     Notepad
2022-03-05 13:44:29  InFocus     Microsoft.WindowsNotepad_8wekyb3d8bbwe!App     in focus 00:00:15 until 13:44:44
2022-03-05 13:44:46  ExecuteOpen Microsoft.WindowsNotepad_8wekyb3d8bbwe!App     temp.txt (Notepad) | C:\temp.txt
2022-03-05 13:44:46  InFocus     Microsoft.WindowsNotepad_8wekyb3d8bbwe!App     in focus 00:00:00 until 13:44:46
2022-03-05 13:44:46  InFocus     Microsoft.WindowsNotepad_8wekyb3d8bbwe!App     in focus 00:00:05 until 13:44:51
2022-03-05 20:56:24  InFocus     Microsoft.Windows.Explorer                     in focus 00:14:12 until 21:10:36
```

A test VM's afternoon, minute by minute: File Explorer, then **`D:\setup64.exe`** (an installer on a mounted disc, D:) opened at 13:37:08 and in focus for about two and a half minutes, Windows Installer, **Windows Terminal** opened at 13:40:29, and Notepad opening **`C:\temp.txt`** at 13:44:46. Terminal's one InFocus record runs 7 h 16 min, to 20:56:24, and overlaps the Explorer and Notepad records: focus records can overlap, so treat long durations as approximate. The eleven **CopyPaste** records (in the CSV) say copy and paste happened in Terminal and Explorer, but not *what*: clipboard history wasn't on. On a case, the same output tells you which file alice had open in which program, and for how long, as long as the machine still keeps the activity (WS-ALICE is Windows 11: check the database, with its WAL, rather than assume).

---

## ✅ Knowledge check

1. Which SRUM table would you use to estimate how much rclone uploaded, and what can't it tell you?
2. You collect `SRUDB.dat` from a running machine. Why might SrumECmd fail, and how do you fix it without touching the original?
3. A NetworkUsages record has `TimeStamp` 03:28. Did the traffic happen at 03:28?
4. What three facts does a `$I` file give you, and what does the folder it sits in add?
5. Name three ways a file can be deleted without ever appearing in the Recycle Bin.
6. In the Windows 11 Timeline sample, the `.db` file is 4 KB. Where is the data, and what mistake would lose it?
7. You run `sqlite3 ActivitiesCache.db` on the original evidence to "just count rows". What happened to the evidence?
8. Which Timeline activity type tells you how long a program was used?

<details>
<summary><b>Answers</b></summary>

1. **NetworkUsages**: `BytesSent` per program (by path) and user, per interval and interface. It can't tell you the destination (IP or host), the exact time within the interval, or which files were sent (AppResourceUseInfo's bytes read gives a hint).
2. The copy is in **dirty shutdown** state (the database was open; recent changes are in the `SRU*.log` files). Copy the whole `sru` folder, and on Windows replay and repair the **copy**: `esentutl /r sru /i`, then `esentutl /p SRUDB.dat`. On Linux, dissect.esedb can often read a dirty copy as it is (without the changes still in the logs).
3. No: SRUM aggregates usage and writes about once an hour; 03:28 is when the record was written. The traffic happened in the interval before it.
4. The original **path**, the **size** and the **deletion time** (UTC). The `<SID>` folder says **whose** Recycle Bin it is, i.e. which user account deleted it.
5. Any three of: `Shift+Delete`; `del` in `cmd` or `Remove-Item` in PowerShell; deleting on a network share or a removable drive; emptying the Recycle Bin afterwards (the record is then gone too); deleting from a program that doesn't use the shell's recycle function.
6. In `ActivitiesCache.db-wal` (the write-ahead log); copying only the `.db` gives an empty database ("no such table"). Collect `.db`, `-wal` and `-shm` together.
7. On close, SQLite checkpointed the WAL into the `.db` and removed the `-wal`: the original files changed (different sizes and hashes). Always work on copies or open with `-readonly`, and hash before and after.
8. **InFocus (6)**: start time, end time and duration in the foreground. ExecuteOpen (5) only says when something was opened.

</details>

---

## 📚 Further reading

- Eric Zimmerman, *SrumECmd*, *RBCmd* and *WxTCmd* READMEs (including SrumECmd's guide to repairing a dirty `SRUDB.dat`)
- Andrew Rathbun, *DFIR Artifact Museum* (https://github.com/AndrewRathbun/DFIRArtifactMuseum): the SRUM and Timeline samples used today, clean and dirty
- Joachim Metz, *libesedb* documentation: the ESE file format and header
- Fox-IT, *dissect.esedb* (https://github.com/fox-it/dissect.esedb): the ESE and SRUM reader used in Lab 1
- SQLite, *Write-Ahead Logging* (https://www.sqlite.org/wal.html)

---

## ⏭️ Tomorrow: Day 18

**Browser forensics: Chromium, Firefox and Edge.** Tools: **Hindsight**, **BrowsingHistoryView**, **DB Browser for SQLite**.
Today's Timeline was one SQLite database with a WAL; browsers are a dozen of them. Tomorrow: history, downloads, cookies and cache, and how to read them without changing them.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
