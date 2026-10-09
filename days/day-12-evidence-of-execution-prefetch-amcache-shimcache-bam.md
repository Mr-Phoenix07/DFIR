# Day 12: Evidence of Execution: Prefetch, Amcache, Shimcache and BAM/DAM

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~3–4 hours (reading + labs) · **Posted:** 2026-10-09
>
> **Tools today:** 🛠️ PECmd · 🛠️ AmcacheParser · 🛠️ AppCompatCacheParser

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Name the four classic Windows **evidence-of-execution** artifacts, where each lives, and **exactly what each one proves** (and doesn't).
2. Read a **Prefetch** file: run count, last eight run times, files and volumes referenced, and how its name is derived from the program's path.
3. Interpret **Shimcache** (AppCompatCache) correctly: its timestamp is the file's *modification* time, its order matters, and it's written only at shutdown.
4. Use **Amcache** for SHA-1 hashes and first-seen times, and **BAM/DAM** for per-user last-run times.
5. **Correlate** all four into one execution timeline, and spot anti-forensics such as timestomping, deleted Prefetch and renamed binaries.

---

## Part 1: The lesson

"Did this program run, when, how often, and as whom?" is one of the most common questions in an investigation. No single artifact answers all of it. Windows keeps several overlapping records, each built for a different purpose (performance, compatibility, inventory, power management), and each with its own blind spots.

### 1.1 The four artifacts at a glance

| | **Prefetch** | **Shimcache** (AppCompatCache) | **Amcache** | **BAM / DAM** |
|---|---|---|---|---|
| **Where** | `C:\Windows\Prefetch\*.pf` | SYSTEM: `ControlSet00N\Control\Session Manager\AppCompatCache\AppCompatCache` | `C:\Windows\AppCompat\Programs\Amcache.hve` | SYSTEM: `ControlSet00N\Services\bam\State\UserSettings\<SID>` (and `dam`) |
| **Built for** | Faster program start-up | Application compatibility checks | Program/file inventory (Compatibility Appraiser) | Background activity moderation (power) |
| **Proves execution?** | **Yes** | **No** on Windows 10/11 (presence only; see §1.3) | **No** on its own (inventory) | **Yes** |
| **Key times** | Up to **8 last-run times** (Win8+), file created ≈ first run | File's **last-modified** time, *not* run time | Key last-write ≈ when the file was inventoried | **Last run time** |
| **Counts** | **Run count** | No | No | No |
| **Who?** | No | No | No | **Yes**: per user SID |
| **Hash** | No (path hash only) | No | **SHA-1** of the file | No |
| **Coverage** | 1,024 files on Win8+ (128 earlier); off by default on Windows Server | Up to 1,024 entries (Win10/11); updated in memory, **written at shutdown** | Long history; survives the file's deletion | Recent activity only; old entries are removed |

The rule of thumb: **Prefetch and BAM show execution, Amcache gives you the hash, and Shimcache shows the file existed on the system.** Combine them.

### 1.2 Prefetch in depth

When a program starts, the Windows cache manager watches the first ~10 seconds of its file activity and saves it in `C:\Windows\Prefetch\<EXE>-<HASH>.pf`, so the next start can preload those files.

**File name.** `<EXE>` is the executable's name. `<HASH>` is computed from the program's **full device path** (for example `\DEVICE\HARDDISKVOLUME3\USERS\ALICE\APPDATA\LOCAL\TEMP\RC\RCLONE.EXE`). The same program run from two folders or two volumes therefore gets **two** `.pf` files, which is useful when malware is copied around. Hosting processes (`svchost.exe`, `dllhost.exe`, `rundll32.exe`, `mmc.exe`) also mix their command line into the hash, so they have many `.pf` files.

**Format versions:**

| Version | Windows | Notes |
|---|---|---|
| 17 | XP, Server 2003 | 1 last-run time |
| 23 | Vista, 7, Server 2008 | 1 last-run time |
| 26 | 8, 8.1, Server 2012 | **8 last-run times** |
| 30 (31) | 10, 11 | 8 run times; **compressed** with Xpress Huffman ("MAM" signature) |

**Inside the file:** the executable name, run count, last-run times; **file metrics** (every file loaded in those first 10 seconds: DLLs, but also **data files** the program opened, such as configs and documents); **volume information** (device path, creation time and **serial number** of every volume touched, so runs from USB drives stand out) and the **directories** referenced.

**What it proves and how to read the times:**

- A `.pf` file for a program means it **ran** (at least once) on this system.
- Last-run times are recorded a few seconds after start. The `.pf` file's own creation time (in the $MFT) is roughly the **first** run, and its modification time roughly the **last** run.
- Near-simultaneous runs can appear slightly out of order in the run-time array (you'll see that in Lab 1).

**Pitfalls and anti-forensics:**

- Prefetch can be **disabled**: `SYSTEM\…\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` = 0. It's off by default on Windows Server, so "no Prefetch" there means nothing.
- Attackers delete `.pf` files. The $MFT, `$J` and `$I30` slack (Day 10) still remember their names.
- Programs that exit before the prefetcher writes the file may leave no `.pf`.

### 1.3 Shimcache (AppCompatCache) in depth

The Application Compatibility engine keeps a cache of executables it has checked. It's held in memory and **serialised into the SYSTEM hive at shutdown or reboot**. A hive collected from a running system contains the cache as it was at the **last shutdown**; anything since then is in memory only (Phase 3 shows how to get it).

Each Windows 10/11 entry (signature `10ts`) holds the **path**, the file's **last-modified time** (from `$STANDARD_INFORMATION`) and a data blob. Entries are stored **most recent first**, so the **position** is your only clue to order.

- **The timestamp is not the run time.** It's when the *file* was last modified. A tool extracted from a zip often keeps the archive's time, and a timestomped file shows the forged time (Lab 3).
- **Presence isn't proof of execution on Windows 10/11.** Files can be added when they're merely examined (for example when Explorer shows a folder). AppCompatCacheParser reports an `Executed` flag from the last 4 bytes of the entry data. Treat it as a lead and confirm it elsewhere.
- **Still very valuable:** it records executables that were *on the system*, including ones since deleted, with their full paths.

### 1.4 Amcache in depth

`Amcache.hve` is a registry hive (Day 11 format) maintained by the Compatibility Appraiser and related tasks. On Windows 10/11 the key parts are:

| Key under `Root\` | Contents |
|---|---|
| `InventoryApplicationFile` | One subkey per executable: `LowerCaseLongPath`, **`FileId` = "0000" + SHA-1**, `Size`, `Version`, `ProductName`, `Publisher`, `LinkDate` (the PE compile time), `BinaryType`, `IsOsComponent`, `Usn` |
| `InventoryApplication` | Installed programs (name, publisher, install date, uninstall string) |
| `InventoryDriverBinary`, `InventoryDevicePnp` | Drivers and devices |
| `InventoryApplicationShortcut` | Start-menu shortcuts |

Use it for:

- The **SHA-1**, even when the file is long gone. Look it up in threat intel, or compare it with a sample. For large files, only the first part of the file is hashed (about the first 30 MB), so the SHA-1 won't match a full-file hash of a big binary.
- The subkey's **last-write time**, which is roughly when the file was **first inventoried**. That's often close to its first execution, but not proof of it. The Appraiser also inventories files that never ran.
- **Publisher, version and compile time**, to spot fakes (an unsigned `svchost.exe` in a user's Temp folder, a "Microsoft" binary with no version info).

### 1.5 BAM and DAM

The **Background Activity Moderator** (Windows 10 1709 and later) keeps, for each user **SID**, the last time each executable ran:

- Path: `SYSTEM\ControlSet00N\Services\bam\State\UserSettings\<SID>`. On 1709/1803 it's `…\bam\UserSettings\<SID>`. **DAM** (Desktop Activity Moderator, used on modern-standby devices) has the same layout under `…\dam\…`.
- Each **value name** is the program's device path (`\Device\HarddiskVolume3\…\rclone.exe`); the first 8 bytes of the data are a **FILETIME**.
- It's the only one of the four that answers **"as whom?"**: a program run by a service shows up under `S-1-5-18` (SYSTEM), and one run by alice under her SID.
- It covers **recent** activity only; old entries are cleaned up.

### 1.6 Putting it together

| Question | Best source | Confirm with |
|---|---|---|
| Did it run? | Prefetch, BAM | Event logs (4688, Sysmon 1), SRUM (Day 17) |
| When (first / last)? | Prefetch run times; `.pf` created/modified; BAM | Amcache key time (first seen), `$J` |
| How many times? | Prefetch run count | — |
| Who ran it? | BAM (SID) | Event logs, UserAssist (Day 13) |
| What is it (hash)? | Amcache SHA-1 | The file itself, VirusTotal |
| Was it ever on disk, even if deleted? | Shimcache, Amcache | $MFT/$J, `$I30` slack |
| What did it touch? | Prefetch file list | LNK/Jump Lists, $J |

**Anti-forensics cheat sheet:** deleting Prefetch (look at `$J`/$MFT for `.pf` deletions), disabling the prefetcher (check `EnablePrefetcher`), **renaming** a tool (Prefetch name changes, but Amcache SHA-1 doesn't), **timestomping** (Shimcache then shows the fake time, which can itself stand out), running from a USB drive (Prefetch volume serials, Shimcache path on another drive letter), and clearing the cache by never rebooting (Shimcache in the hive is old: say so).

---

## Part 2: Tools

---

### 🛠️ Tool 1: PECmd

| | |
|---|---|
| **What** | Eric Zimmerman's Prefetch parser: every version from XP (17) to Windows 11 (30/31), including the compressed format |
| **Why in DFIR** | Run counts, all run times, referenced files and volumes, keyword highlighting (`temp`, `tmp` by default), CSV plus a ready-made **timeline CSV**, VSS support |
| **Platforms** | **Windows only**: it uses Windows' own decompression routine (`RtlDecompressBufferEx` in `ntdll.dll`) for Windows 10/11 files |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/PECmd · downloads: https://ericzimmerman.github.io |

> ⚠️ **Not run here.** PECmd refuses to run on non-Windows systems. The version built from source for this lesson printed `Non-Windows platforms not supported due to the need to load decompression specific Windows libraries! Exiting...`. Its options below are from its own `--help`. The Linux labs parse the same Prefetch files with **`sccainfo`** (libscca), which handles both compressed and uncompressed files.

#### Requirements

Windows 10/11 with the .NET 9 runtime (Day 1). Run it elevated to read the live `C:\Windows\Prefetch`.

#### Installation (Windows)

```powershell
# With all EZ tools (Day 1); PECmd.exe sits directly in the net9 folder
C:\Tools\ZimmermanTools\Get-ZimmermanTools.ps1 -Dest C:\Tools\ZimmermanTools -NetVersion 9
C:\Tools\ZimmermanTools\net9\PECmd.exe --version
```

On Linux, install the libscca tools instead: `sudo apt install libscca-utils` (it provides `sccainfo`).

#### Configuration

From `PECmd --help`:

| Option | Meaning |
|---|---|
| `-f FILE` / `-d DIR` | One `.pf` file / every `.pf` under a folder (e.g. `C:\Windows\Prefetch` or a KAPE output) |
| `--csv DIR --csvf NAME` | CSV output; PECmd also writes a `…_Timeline.csv` with one row per run time |
| `--json`, `--html` | Other outputs |
| `-k WORDS` | Extra keywords to highlight in the referenced-file list (`temp` and `tmp` are always included) |
| `-q` | Quiet: don't print full details for every file (faster with `--csv`) |
| `-o FILE` | Save the (decompressed) prefetch bytes, for looking at Windows 10/11 files in a hex editor |
| `--mp` | Higher-precision timestamps |
| `--vss`, `--dedupe` | Include Volume Shadow Copies; de-duplicate by SHA-1 |

Default output names are `<yyyyMMddHHmmss>_PECmd_Output.csv` and `<yyyyMMddHHmmss>_PECmd_Output_Timeline.csv`.

#### Verify the installation

```powershell
C:\Tools\ZimmermanTools\net9\PECmd.exe -f C:\Windows\Prefetch\CMD.EXE-*.pf   # needs an elevated prompt
```

You should see the run count, up to eight run times, and the list of referenced files.

#### First use

```powershell
# A KAPE collection (Day 9): every prefetch file, highlighting the words 'rc' and 'rclone'
PECmd.exe -d E:\Cases\WS-ALICE\tout\C\Windows\prefetch -k rclone,rc --csv E:\Cases\WS-ALICE\prefetch -q
```

Open the `_Timeline.csv` in Timeline Explorer and filter around the incident.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `Non-Windows platforms not supported...` | Expected on Linux/macOS. Use a Windows VM, or `sccainfo` (libscca) |
| Access denied on `C:\Windows\Prefetch` | Run elevated, or parse a collected copy |
| No `.pf` for a program you know ran | Prefetch disabled (`EnablePrefetcher`), a server, the file was deleted (check `$J`), or the program exited too quickly |
| Two `.pf` files for the same program | It ran from two different paths or volumes (the hash is per path) |
| Run times look out of order | Near-simultaneous runs can be stored slightly out of order; use the run count and the `.pf` file's own MACB times too |

---

### 🛠️ Tool 2: AmcacheParser

| | |
|---|---|
| **What** | Eric Zimmerman's parser for `Amcache.hve` (Windows 7–8 "old" format and Windows 10/11 "new" format) |
| **Why in DFIR** | SHA-1, full path, size, product name, version, compile time and first-seen time of executables, plus installed programs, drivers, devices and shortcuts, in separate CSVs; SHA-1 allow/deny lists to cut noise |
| **Platforms** | Windows (.NET 9 / .NET 4.6.2 builds). **Built from source and run on Ubuntu 24.04** in this lesson |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/AmcacheParser |

#### Requirements

Windows with the .NET 9 runtime, or Linux with a .NET SDK (Ubuntu 24.04: `dotnet-sdk-10.0`). Collect `Amcache.hve` **with** its `.LOG1`/`.LOG2` files (it's a registry hive, so the Day 11 rules about dirty hives apply).

#### Installation

```powershell
C:\Tools\ZimmermanTools\net9\AmcacheParser.exe --version    # installed by Get-ZimmermanTools
```

```bash
# Linux (validated here)
sudo apt install -y dotnet-sdk-10.0 git
git clone -q --depth 1 https://github.com/EricZimmerman/AmcacheParser.git ~/tools/AmcacheParser-src
dotnet publish ~/tools/AmcacheParser-src/AmcacheParser/AmcacheParser.csproj -c Release -f net9.0 -o ~/tools/AmcacheParser -v quiet > /dev/null
echo 'amc() { DOTNET_ROLL_FORWARD=Major ~/tools/AmcacheParser/AmcacheParser "$@"; }' >> ~/.bashrc
```

#### Configuration

From `AmcacheParser --help`:

| Option | Meaning |
|---|---|
| `-f FILE` | `Amcache.hve` to parse (required) |
| `--csv DIR --csvf NAME` | Output folder / base name; one CSV per category (`…_UnassociatedFileEntries.csv`, `…_DriverBinaries.csv`, `…_DevicePnps.csv`, `…_ShortCuts.csv`, …) |
| `-i` | Include file entries for program entries |
| `-w FILE` / `-b FILE` | SHA-1 lists to **exclude** / **include** (exclusions win). Useful with a known-good hash set |
| `--nl` | Ignore transaction logs for a dirty hive (otherwise it replays them) |
| `--dt`, `--mp` | Timestamp format / precision |

#### Verify the installation

```bash
amc --version      # 2026.5.2+<commit> was used here
```

#### First use

```powershell
AmcacheParser.exe -f E:\Cases\WS-ALICE\tout\C\Windows\AppCompat\Programs\Amcache.hve --csv E:\Cases\WS-ALICE\amcache
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `Hive does not contain a Root\InventoryApplication key` | Only a warning: that part is missing or empty; the file entries are still parsed |
| Results missing recent entries | The hive is dirty and the logs weren't next to it. Copy `Amcache.hve.LOG1/.LOG2` alongside |
| Too many rows to review | Exclude known-good SHA-1s with `-w`, or filter `IsOsComponent = False` |
| A SHA-1 doesn't match the file you hashed | Large files: Amcache hashes only the first part of the file. Also check you have the same file version |

---

### 🛠️ Tool 3: AppCompatCacheParser

| | |
|---|---|
| **What** | Eric Zimmerman's Shimcache parser for every Windows version from XP to 11 |
| **Why in DFIR** | Decodes the binary `AppCompatCache` value from a SYSTEM hive (or the live registry) into a CSV with **cache position**, path, last-modified time and an `Executed` flag, for every control set |
| **Platforms** | Windows; **built from source and run on Ubuntu 24.04** in this lesson (with `-f`; the live-registry mode needs Windows) |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/AppCompatCacheParser |

#### Requirements

As AmcacheParser. Collect the SYSTEM hive **with** its logs.

#### Installation

```powershell
C:\Tools\ZimmermanTools\net9\AppCompatCacheParser.exe --version    # installed by Get-ZimmermanTools
```

```bash
# Linux (validated here)
git clone -q --depth 1 https://github.com/EricZimmerman/AppCompatCacheParser.git ~/tools/AppCompatCacheParser-src
dotnet publish ~/tools/AppCompatCacheParser-src/AppCompatCacheParser/AppCompatCacheParser.csproj -c Release -f net9.0 -o ~/tools/AppCompatCacheParser -v quiet > /dev/null
echo 'acc() { DOTNET_ROLL_FORWARD=Major ~/tools/AppCompatCacheParser/AppCompatCacheParser "$@"; }' >> ~/.bashrc
```

#### Configuration

From `AppCompatCacheParser --help`:

| Option | Meaning |
|---|---|
| `-f SYSTEM` | SYSTEM hive to process. **Without `-f` it reads the live registry** (Windows, elevated) |
| `--csv DIR --csvf NAME` | CSV output (required) |
| `-c N` | Only control set N (default: all) |
| `-t` | Sort by last-modified time, newest first (**loses the cache order**; use with care) |
| `--nl` | Ignore transaction logs for a dirty hive |
| `--dt` | Timestamp format |

CSV columns: `ControlSet`, `CacheEntryPosition`, `Path`, `LastModifiedTimeUTC`, `Executed`, `Duplicate`, `SourceFile`.

#### Verify the installation

```bash
acc --version      # 2026.5.0+<commit> was used here
```

#### First use

```powershell
AppCompatCacheParser.exe -f E:\Cases\WS-ALICE\tout\C\Windows\System32\config\SYSTEM --csv E:\Cases\WS-ALICE\shimcache
AppCompatCacheParser.exe --csv C:\Cases\live-shimcache       # live system: the cache as of the last boot
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Recent programs missing | Shimcache reaches the hive only at shutdown. Compare with `ShutdownTime`; recent entries are only in memory |
| "Unable to determine operating system!" | Not a Shimcache value you recognise (corrupt, or an unsupported build). Check the value's first bytes |
| Times far in the past or the future | They're file modification times (tool archives, timestomping), not run times |
| `-t` output reads as a timeline | It isn't: cache **position** is the order of insertion; `-t` sorts by modification time instead |
| RegRipper's `appcompatcache` plugin lists entries in a different order every run | It stores entries in a Perl hash and prints them in hash order (confirmed in this lab). Use AppCompatCacheParser's `CacheEntryPosition` for order |

---

## Part 3: Hands-on labs

First you'll read **real** Prefetch files from Windows 7 and Windows 10 (from the public test data of Eric Zimmerman's Prefetch library). Then you'll investigate **WS-ALICE** (Days 9–11) through its execution artifacts, generated by `scripts/mk_execution_artifacts.py`. Its Prefetch files are format version 30 but **uncompressed**, which Windows never writes, but `sccainfo` and PECmd accept. (Day 9's practice drive used placeholder Prefetch files with made-up names such as `RCLONE.EXE-5F3E1A2B.pf`; today's names are computed from the real path, so they differ.) The SYSTEM hive is a **second collection**, taken after alice **rebooted at 07:55** on 2026-09-29. Day 11's copy was taken before that reboot (last shutdown 2026-09-28 18:02:44), so its Shimcache couldn't contain the night's activity; this one does.

Run on Ubuntu 24.04 or SIFT.

```bash
sudo apt update && sudo apt install -y libscca-utils libparse-win32registry-perl git curl dotnet-sdk-10.0
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-012/{evidence,work,notes,samples} ~/tools && cd ~/cases/LAB-012
export TZ=UTC
```

Set up RegRipper (as on Day 11) and build the two parsers (about two minutes):

```bash
[ -d ~/tools/RegRipper3.0 ] || git clone -q --depth 1 https://github.com/keydet89/RegRipper3.0.git ~/tools/RegRipper3.0
mkdir -p ~/tools/RegRipper3.0/lib/Parse/Win32Registry/WinNT
cp ~/tools/RegRipper3.0/{Base,File,Key}.pm ~/tools/RegRipper3.0/lib/Parse/Win32Registry/WinNT/
rip() { PERL5LIB=~/tools/RegRipper3.0/lib perl ~/tools/RegRipper3.0/rip.pl "$@"; }
for t in AppCompatCacheParser AmcacheParser; do
  [ -d ~/tools/$t-src ] || git clone -q --depth 1 https://github.com/EricZimmerman/$t.git ~/tools/$t-src
  git -C ~/tools/$t-src log -1 --format="$t source %h %cs"
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet publish ~/tools/$t-src/$t/$t.csproj -c Release -f net9.0 -o ~/tools/$t -v quiet > /dev/null
done
acc() { DOTNET_ROLL_FORWARD=Major ~/tools/AppCompatCacheParser/AppCompatCacheParser "$@"; }
amc() { DOTNET_ROLL_FORWARD=Major ~/tools/AmcacheParser/AmcacheParser "$@"; }
acc --version
amc --version
sccainfo -V | head -n 1
```

```
AppCompatCacheParser source 0cf059f 2026-05-03
AmcacheParser source 2904455 2026-06-17
2026.5.0+0cf059f40c2f7b31acdccb142461945402217398
2026.5.2+2904455115443035934fbfdeb900162c6afba269
sccainfo 20200717
```

### Lab 1: Real Prefetch files, Windows 7 and Windows 10 (20 min)

```bash
cd ~/cases/LAB-012/samples
for f in Win10/CMD.EXE-D269B812.pf Win7/CMD.EXE-4A81B364.pf; do
  mkdir -p "$(dirname "$f")"
  curl -sSfL -o "$f" "https://raw.githubusercontent.com/EricZimmerman/Prefetch/master/Prefetch.Test/TestFiles/$f"
done
sha256sum Win10/*.pf Win7/*.pf | tee ../notes/prefetch-samples.sha256
xxd -l 16 Win7/CMD.EXE-4A81B364.pf
xxd -l 16 Win10/CMD.EXE-D269B812.pf
```

```
0ef6ce683365dac64191608b47a74665ddec28eaae530ce2622900130c404077  Win10/CMD.EXE-D269B812.pf
9f24326ee9e9f50dfcd79bc7ee80b248d66edf591b2a3fa02d294a1c83403c39  Win7/CMD.EXE-4A81B364.pf
00000000: 1700 0000 5343 4341 1100 0000 ba20 0000  ....SCCA..... ..
00000000: 4d41 4d04 3262 0000 9598 98a8 a9a8 aaba  MAM.2b..........
```

The Windows 7 file starts with version `0x17` (23) and `SCCA`. The Windows 10 file starts with `MAM\x04` and the uncompressed size (`0x6232` = 25,138 bytes): it's compressed, so a hex editor or `strings` shows nothing useful until it's decompressed. `sccainfo` does that for you:

```bash
sccainfo Win10/CMD.EXE-D269B812.pf | sed -n '3,15p'
sccainfo Win10/CMD.EXE-D269B812.pf | grep -E 'Number of filenames|CMDER|CLINK.LOG' | head -n 6
sccainfo Win10/CMD.EXE-D269B812.pf | sed -n '/^Volumes:/,$p' | grep -E 'Number|Device path|Creation|Serial'
```

```
Windows Prefetch File (PF) information:
	Format version			: 30
	Prefetch hash			: 0xd269b812
	Executable filename		: CMD.EXE
	Run count			: 55
	Last run time: 1		: Jan 12, 2016 20:07:03.981069400 UTC
	Last run time: 2		: Jan 10, 2016 02:29:02.788726500 UTC
	Last run time: 3		: Jan 04, 2016 23:27:28.405869800 UTC
	Last run time: 4		: Jan 04, 2016 23:27:28.726891200 UTC
	Last run time: 5		: Jan 04, 2016 18:38:10.935655400 UTC
	Last run time: 6		: Jan 04, 2016 18:38:11.344163400 UTC
	Last run time: 7		: Dec 31, 2015 21:42:29.667018300 UTC
	Last run time: 8		: Dec 17, 2015 22:34:21.579861500 UTC
	Number of filenames		: 62
	Filename: 2			: \VOLUME{01d12173f395296c-66f451bc}\CMDER129\VENDOR\CLINK\CLINK_DLL_X64.DLL
	Filename: 14			: \VOLUME{01d12173f395296c-66f451bc}\CMDER129\VENDOR\CONEMU-MAXIMUS5\CONEMU\CONEMUHK64.DLL
	Filename: 22			: \VOLUME{01d12173f395296c-66f451bc}\CMDER129\VENDOR\INIT.BAT
	Filename: 24			: \VOLUME{01d12173f395296c-66f451bc}\CMDER129\VENDOR\CLINK\CLINK_X64.EXE
	Filename: 37			: \VOLUME{01d1217a9c4c6779-8c9f49ec}\USERS\E\APPDATA\LOCAL\CLINK\CLINK.LOG
	Number of volumes		: 2
	Device path			: \VOLUME{01d12173f395296c-66f451bc}
	Creation time			: Nov 17, 2015 20:10:06.204964400 UTC
	Serial number			: 0x66f451bc
	Device path			: \VOLUME{01d1217a9c4c6779-8c9f49ec}
	Creation time			: Nov 17, 2015 20:57:46.243468100 UTC
	Serial number			: 0x8c9f49ec
```

What a real Windows 10 file tells you about this (anonymised) user:

- `cmd.exe` ran **55 times**; the last eight runs are listed, newest first. Look at runs 3/4 and 5/6: near-simultaneous runs can be stored **slightly out of order** (§1.2).
- Each referenced file is named `\VOLUME{<volume creation time>-<serial>}\path`. **Two volumes:** the system volume (serial `8c9f49ec`, holding `WINDOWS` and `USERS`) and a second one (serial `66f451bc`) that holds only a portable **Cmder** console, whose hooks (`clink`, `ConEmuHk64.dll`) were loaded into cmd. A tool on another volume, possibly removable media, identified by serial number.
- The user profile is `\USERS\E\…` (a data file, `CLINK.LOG`, was touched too).

Now prove the file-name hash. The Windows 7 file is `CMD.EXE-4A81B364.pf`; on that system Windows was on the second volume:

```bash
python3 ~/DFIR/scripts/prefetch_hash.py '\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CMD.EXE' '\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\CMD.EXE'
```

```
CMD.EXE-4A81B364.pf  <-  \DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\CMD.EXE
CMD.EXE-89305D47.pf  <-  \DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\CMD.EXE
```

The first matches the real Windows 7 file. The second, the same program on volume 1, gives `89305D47`, which is the name of the **Vista** test file in the same collection. Same program, different path, different `.pf`.

### Lab 2: WS-ALICE's Prefetch (15 min)

```bash
cd ~/cases/LAB-012
python3 ~/DFIR/scripts/mk_execution_artifacts.py evidence/WS-ALICE
sha256sum evidence/WS-ALICE/SYSTEM evidence/WS-ALICE/Amcache.hve evidence/WS-ALICE/Prefetch/* | tee notes/evidence.sha256
python3 ~/DFIR/scripts/prefetch_hash.py '\DEVICE\HARDDISKVOLUME3\USERS\ALICE\APPDATA\LOCAL\TEMP\RC\RCLONE.EXE'
sccainfo evidence/WS-ALICE/Prefetch/RCLONE.EXE-62468698.pf | sed -n '3,10p'
sccainfo evidence/WS-ALICE/Prefetch/RCLONE.EXE-62468698.pf | grep -E 'Filename: (2|8|9|10)\b'
sccainfo evidence/WS-ALICE/Prefetch/PSEXESVC.EXE-AD70946C.pf | grep -E 'Run count|Last run time: 1|Filename: 2\b'
```

```
   8192  SYSTEM
  12288  Amcache.hve
   3442  Prefetch/RCLONE.EXE-62468698.pf
   1856  Prefetch/PSEXESVC.EXE-AD70946C.pf
97a79724013a63d554910078a4d688db99fd50b2a021a21e37bf7c3d83324d1e  evidence/WS-ALICE/SYSTEM
3f757e44c610ce40a705ae3ad8d77c027d6b7723854fa888cc17edaf03b45758  evidence/WS-ALICE/Amcache.hve
bda4d909c13e4d8a94fc63811164fb44579ec9a61ab1743d3d40cedbe62b770b  evidence/WS-ALICE/Prefetch/PSEXESVC.EXE-AD70946C.pf
a3bb36326138eccafa945f218214e7dd6012690aaa6b7e86fe3330320c39702a  evidence/WS-ALICE/Prefetch/RCLONE.EXE-62468698.pf
RCLONE.EXE-62468698.pf  <-  \DEVICE\HARDDISKVOLUME3\USERS\ALICE\APPDATA\LOCAL\TEMP\RC\RCLONE.EXE
Windows Prefetch File (PF) information:
	Format version			: 30
	Prefetch hash			: 0x62468698
	Executable filename		: RCLONE.EXE
	Run count			: 3
	Last run time: 1		: Sep 29, 2026 07:58:21.441392000 UTC
	Last run time: 2		: Sep 29, 2026 01:22:11.302441700 UTC
	Last run time: 3		: Sep 29, 2026 01:12:47.662901500 UTC
	Filename: 2			: \VOLUME{01dcaa20560b4a30-6c2f3e1a}\USERS\ALICE\APPDATA\LOCAL\TEMP\RC\RCLONE.EXE
	Filename: 8			: \VOLUME{01dcaa20560b4a30-6c2f3e1a}\USERS\ALICE\APPDATA\LOCAL\TEMP\RC\RC.CONF
	Filename: 9			: \VOLUME{01dcaa20560b4a30-6c2f3e1a}\USERS\ALICE\DOCUMENTS\Q3-FORECAST.XLSX
	Filename: 10			: \VOLUME{01dcaa20560b4a30-6c2f3e1a}\USERS\ALICE\DOCUMENTS\PROJECTS\SPEC-01.TXT
	Run count			: 1
	Last run time: 1		: Sep 29, 2026 01:05:13.228013300 UTC
	Filename: 2			: \VOLUME{01dcaa20560b4a30-6c2f3e1a}\WINDOWS\PSEXESVC.EXE
```

The hash in the name proves which path `rclone.exe` ran from (the `Temp\rc` folder). It ran **three times**: 01:12:47, 01:22:11 (one second after the `OneDriveSync` service from Day 11 was created) and 07:58:21, just after the next boot. In its first seconds it read **`RC.CONF`** (the renamed rclone config from Day 9) and alice's **documents**: Prefetch shows what a program touched, not just that it ran. `PSEXESVC.EXE` ran once at 01:05:13, matching the deleted service key from Day 11.

### Lab 3: Shimcache (15 min)

```bash
acc -f evidence/WS-ALICE/SYSTEM --csv work/shimcache --csvf shimcache.csv | grep -E 'Found|saved'
cut -d, -f2-5 work/shimcache/shimcache.csv
rip -r evidence/WS-ALICE/SYSTEM -p appcompatcache | grep -E '^(LastWrite|C:)' | sort
```

```
Found 6 cache entries for Windows10C_11 in ControlSet001
Results saved to 'work/shimcache/shimcache.csv'
CacheEntryPosition,Path,LastModifiedTimeUTC,Executed
0,C:\Users\alice\AppData\Local\Temp\svchost.exe,2019-03-14 10:00:00,No
1,C:\Users\alice\AppData\Local\Temp\rc\rclone.exe,2025-11-14 16:05:00,Yes
2,C:\Windows\PSEXESVC.exe,2026-09-29 01:05:12,Yes
3,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,2026-08-12 03:14:55,Yes
4,C:\Windows\System32\cmd.exe,2026-08-12 03:14:52,Yes
5,C:\Program Files\Microsoft OneDrive\OneDrive.exe,2026-09-10 11:20:31,Yes
C:\Program Files\Microsoft OneDrive\OneDrive.exe  2026-09-10 11:20:31
C:\Users\alice\AppData\Local\Temp\rc\rclone.exe  2025-11-14 16:05:00
C:\Users\alice\AppData\Local\Temp\svchost.exe  2019-03-14 10:00:00
C:\Windows\PSEXESVC.exe  2026-09-29 01:05:12
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  2026-08-12 03:14:55
C:\Windows\System32\cmd.exe  2026-08-12 03:14:52
LastWrite Time: 2026-09-29 07:55:02Z
```

Read it like an examiner:

- **Position 0** (the newest entry) is `svchost.exe` **in alice's Temp folder**: a system binary name in the wrong place. Its time is **2019-03-14 10:00:00**, the **timestomped** modification time from Day 10. Shimcache faithfully records the forged time; the position says it was added most recently. `Executed = No`, and Lab 6 finds no Prefetch, BAM or Amcache record for it: it was dropped but there's no evidence it ran.
- `rclone.exe` shows **2025-11-14**: when the binary was built and zipped by its publisher, kept when it was extracted. Not when it ran.
- The key's last-write time (**07:55:02**) is the shutdown that wrote the cache (compare `ShutdownTime` in Lab 5). Without that reboot, none of the night's entries would be in the hive.
- RegRipper shows the same entries but **not in cache order** (its output order changes from run to run, which is why it's piped through `sort` here). For Shimcache, use the tool that keeps the position.

### Lab 4: Amcache (15 min)

```bash
amc -f evidence/WS-ALICE/Amcache.hve --csv work/amcache --csvf amcache.csv | grep -E 'file entries|unassociated'
ls work/amcache
python3 - work/amcache/amcache_UnassociatedFileEntries.csv <<'EOF'
import csv, sys
for r in csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")):
    print(f"{r['FileKeyLastWriteTimestamp']}  {r['SHA1']}  {r['FullPath']}")
    print(f"{'':21}product={r['ProductName']!r} version={r['Version']} linkdate={r['LinkDate'] or '(none)'} size={r['Size']} os={r['IsOsComponent']}")
EOF
```

```
Total file entries found: 3
Found 3 unassociated file entry
amcache_DeviceContainers.csv
amcache_DevicePnps.csv
amcache_DriverBinaries.csv
amcache_DriverPackages.csv
amcache_ShortCuts.csv
amcache_UnassociatedFileEntries.csv
2026-08-12 03:20:04  e5812100950ebca51f1f337ecea0a77a17de7d21  c:\windows\system32\windowspowershell\v1.0\powershell.exe
                     product='Microsoft® Windows® Operating System' version=10.0.26100.1 linkdate=2087-06-13 21:47:32 size=455680 os=True
2026-09-29 01:05:14  9f1886984a13cef21c508dfd6b0946457d67e060  c:\windows\psexesvc.exe
                     product='Sysinternals PsExec' version=2.43 linkdate=2023-04-11 14:13:17 size=199688 os=False
2026-09-29 01:12:49  4785d0d1a2c5c7196070b3e81b483e0f1a9628cd  c:\users\alice\appdata\local\temp\rc\rclone.exe
                     product='Rclone' version=1.68.2 linkdate=(none) size=8192 os=False
```

(The SHA-1 values hash this lab's stand-in content, not the real programs.) What each entry adds:

- **SHA-1s**: hand these to threat intelligence, or compare them with files recovered from other machines. `rclone.exe` and `PSEXESVC.exe` were both first inventoried within seconds of their first Prefetch run.
- **LinkDate** is the PE compile time. Windows' own binaries use reproducible builds whose "date" is effectively random (here 2087, a typical sight on `powershell.exe`). `rclone.exe` has **none**: Go binaries are normally built without a timestamp. A missing or odd compile time is normal for some toolchains, so don't over-read it.
- `PSEXESVC.exe` names its product **Sysinternals PsExec**, confirming the deleted service from Day 11 was PsExec.

### Lab 5: BAM, the "as whom?" artifact (10 min)

```bash
rip -r evidence/WS-ALICE/SYSTEM -p bam | tail -n +4
rip -r evidence/WS-ALICE/SYSTEM -p shutdown | grep ShutdownTime
```

```
S-1-5-18
  2026-09-29 07:58:21Z - \Device\HarddiskVolume3\Users\alice\AppData\Local\Temp\rc\rclone.exe

S-1-5-21-3623811015-3361044348-30300820-1001
  2026-09-29 01:09:31Z - \Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  2026-09-29 01:12:47Z - \Device\HarddiskVolume3\Users\alice\AppData\Local\Temp\rc\rclone.exe

ShutdownTime  : 2026-09-29 07:55:02Z
```

BAM separates the runs by **account**:

- alice's SID (`…-1001`, see ProfileList on Day 11) ran **PowerShell at 01:09:31** (the RunMRU entry from Day 11) and `rclone.exe` at 01:12:47: the interactive, manual run.
- **SYSTEM** (`S-1-5-18`) ran `rclone.exe` at 07:58:21, right after boot: the `OneDriveSync` auto-start service. Persistence working.
- BAM keeps only the **last** run per program and user. The service's first run at 01:22:11 (Prefetch run 2) was overwritten by its 07:58:21 run, which is why you still need Prefetch's run times and run count.

### Lab 6: One execution timeline (15 min)

Merge the four sources (keeping September 2026, the incident window):

```bash
python3 - <<'EOF'
import csv, glob, re, subprocess
ev = []
for pf in sorted(glob.glob("evidence/WS-ALICE/Prefetch/*.pf")):
    out = subprocess.run(["sccainfo", pf], capture_output=True, text=True).stdout
    exe = re.search(r"Executable filename\s+: (\S+)", out).group(1)
    for t in re.findall(r"Last run time: \d\s+: (\w{3} \d\d, \d{4} [\d:.]+) UTC", out):
        ev.append((t, "Prefetch", f"{exe} ran"))
for r in csv.DictReader(open("work/amcache/amcache_UnassociatedFileEntries.csv", encoding="utf-8-sig")):
    ev.append((r["FileKeyLastWriteTimestamp"], "Amcache", f"{r['FullPath']} inventoried (SHA-1 {r['SHA1'][:12]}...)"))
for r in csv.DictReader(open("work/shimcache/shimcache.csv", encoding="utf-8-sig")):
    ev.append((r["LastModifiedTimeUTC"], "Shimcache", f"{r['Path']} last MODIFIED (position {r['CacheEntryPosition']}, executed={r['Executed']})"))
out = subprocess.run(["bash", "-c", "PERL5LIB=~/tools/RegRipper3.0/lib perl ~/tools/RegRipper3.0/rip.pl -r evidence/WS-ALICE/SYSTEM -p bam"],
                     capture_output=True, text=True).stdout
sid = None
for line in out.splitlines():
    if line.startswith("S-1-"):
        sid = line.strip()
    m = re.match(r"\s+(\S+ \S+)Z - (.+)", line)
    if m:
        ev.append((m.group(1), "BAM", f"{m.group(2).split(chr(92))[-1]} last run by {sid}"))
import datetime as dt
def key(t):
    for fmt in ("%b %d, %Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return dt.datetime.strptime(t.split(".")[0], fmt)
        except ValueError:
            pass
for t, src, what in sorted(ev, key=lambda e: key(e[0])):
    if key(t).year == 2026 and key(t).month == 9:
        print(f"{key(t):%Y-%m-%d %H:%M:%S}  {src:<9} {what}")
EOF
```

```
2026-09-10 11:20:31  Shimcache C:\Program Files\Microsoft OneDrive\OneDrive.exe last MODIFIED (position 5, executed=Yes)
2026-09-29 01:05:12  Shimcache C:\Windows\PSEXESVC.exe last MODIFIED (position 2, executed=Yes)
2026-09-29 01:05:13  Prefetch  PSEXESVC.EXE ran
2026-09-29 01:05:14  Amcache   c:\windows\psexesvc.exe inventoried (SHA-1 9f1886984a13...)
2026-09-29 01:09:31  BAM       powershell.exe last run by S-1-5-21-3623811015-3361044348-30300820-1001
2026-09-29 01:12:47  Prefetch  RCLONE.EXE ran
2026-09-29 01:12:47  BAM       rclone.exe last run by S-1-5-21-3623811015-3361044348-30300820-1001
2026-09-29 01:12:49  Amcache   c:\users\alice\appdata\local\temp\rc\rclone.exe inventoried (SHA-1 4785d0d1a2c5...)
2026-09-29 01:22:11  Prefetch  RCLONE.EXE ran
2026-09-29 07:58:21  Prefetch  RCLONE.EXE ran
2026-09-29 07:58:21  BAM       rclone.exe last run by S-1-5-18
```

The night in one view: **01:05** PsExec service copied and run (Shimcache, Prefetch, Amcache within two seconds of each other); **01:09** hidden PowerShell as alice; **01:12** rclone's first, manual run as alice, hashed by Amcache two seconds later; **01:22** rclone run again via the new service; **07:58** rclone starts as SYSTEM after the reboot. Notice what's *not* here: the 2019 `svchost.exe` (filtered out by date, and with no run evidence anywhere), and the Shimcache line for rclone (its 2025 time is a file time). Record the conclusions with their sources; Day 21 builds this kind of timeline at scale.

---

## ✅ Knowledge check

1. Which two of the four artifacts prove execution on Windows 10/11, and which one tells you the user?
2. Why can the same `rclone.exe` have two different `.pf` files on one machine?
3. A Shimcache entry for `evil.exe` shows 2019-03-14. What does that date mean, and what doesn't it mean?
4. You collected the SYSTEM hive from a running server that hasn't been rebooted for 40 days. What does its Shimcache cover, and where are newer entries?
5. Why is Amcache valuable even after the attacker deleted the tool from disk?
6. A program ran yesterday but has no `.pf` file. Give three possible reasons.
7. In Lab 5, why does BAM show rclone under `S-1-5-18` at 07:58:21?
8. The Windows 10 `cmd.exe` Prefetch file references two volumes. What can you learn from the one that isn't the system volume?
9. Why should you be careful with AppCompatCacheParser's `-t` and RegRipper's `appcompatcache` output when building a timeline?

<details>
<summary><b>Answers</b></summary>

1. **Prefetch** and **BAM** (DAM on modern-standby devices). BAM, because its entries are stored per user SID.
2. The hash in the name comes from the program's full path, including the volume. A copy in another folder or run from another volume gets a different hash, so a different `.pf`.
3. It's the file's **last-modified** time (from `$STANDARD_INFORMATION`) when it was cached, possibly forged by timestomping. It is **not** when the program ran, and on Windows 10/11 the entry alone doesn't prove it ran.
4. The cache as it was at the **last shutdown/reboot**, 40 days ago. Newer entries exist only in memory until the next shutdown; capture memory (Phase 3) to get them.
5. It keeps the file's **SHA-1**, path, size, version, publisher and first-inventoried time, which you can use for threat-intel lookups and to link the same tool across machines, even when the file is gone.
6. Prefetch is disabled (`EnablePrefetcher` = 0) or it's a Windows Server; the `.pf` was deleted (check `$J`/$MFT); the program exited before the prefetcher wrote the file (or it's a hosted/script engine run under another process's name).
7. It was started by the `OneDriveSync` **service**, which runs as **LocalSystem** (S-1-5-18), at boot after the 07:55 reboot. BAM records it under the account that ran it.
8. Its device path (`\VOLUME{creation-time-serial}`) gives the volume's **serial number and creation time**, and the files on it (a portable Cmder install). You can match the serial against USB device history (Day 13+) or a seized drive.
9. Shimcache order is the cache **position** (insertion order). `-t` re-sorts by file modification time, and RegRipper's plugin prints in Perl-hash order, so neither shows the real order. Use `CacheEntryPosition`, and never treat Shimcache times as run times.

</details>

---

## 📚 Further reading

- libscca documentation, *Windows Prefetch File (PF) format* (https://github.com/libyal/libscca/tree/main/documentation)
- Blanche Lagny (ANSSI), *Analysis of the AmCache* (2019): what each Amcache key means and when it's written
- Mandiant, *Leveraging the Application Compatibility Cache in Forensic Investigations* (Andrew Davis), and later research on the Windows 10/11 cache format
- 13Cubed, *BAM and DAM* and *Prefetch* videos (YouTube), for visual walkthroughs
- SANS *Windows Forensic Analysis* poster, "Evidence of Execution" section

---

## ⏭️ Tomorrow: Day 13

**File and folder knowledge: LNK files, Jump Lists and ShellBags.** Tools: **LECmd**, **JLECmd**, **ShellBags Explorer (SBECmd)**.
Today answered "what ran"; tomorrow answers "what did the user open and browse", including files on USB drives and network shares that no longer exist.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
