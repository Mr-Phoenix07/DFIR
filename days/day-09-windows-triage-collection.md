# Day 09: Windows Triage Collection

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~3–4 hours (reading + labs) · **Posted:** 2026-10-06
>
> **Tools today:** 🛠️ KAPE · 🛠️ AChoirX · 🛠️ DFIR ORC

> 📝 **Tool change:** the curriculum listed **CyLR** for today. CyLR's last commit was on 12 October 2021. It targets .NET Core 3.1, which reached end of life in December 2022, and its README now leads with an open letter from its authors to the users of Skadi, CyLR and CDQR. It has been replaced with **AChoirX**: it is actively maintained (v10.01.85, May 2026), cross-platform like CyLR was, and it runs on Linux, so you can use it in today's lab. `CURRICULUM.md` has been updated.

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain when **triage collection** beats a full disk image, and what you give up by choosing it.
2. List the **Windows artifacts** a triage collection must contain, where each one lives, and which question it answers.
3. Describe the problems of **live** collection (locked files, Volume Shadow Copies, the collector's own footprint) and how triage tools deal with them.
4. Read, write and test **KAPE Targets** (`.tkape`), including compound Targets, `%user%` variables, masks and SHA-1 de-duplication.
5. Script a cross-platform collection with **AChoirX** and run it against a mounted Windows image on Linux.
6. Build, configure and dry-run **DFIR ORC**, ANSSI's collection framework, and explain how it encrypts what it collects.

---

## Part 1: The lesson

### 1.1 Triage collection vs. a full image

On Days 5 and 6 you imaged whole disks. That is still the gold standard, but in incident response it's often too slow. A 1 TB laptop takes hours to image and hours more to process, and an intrusion can touch fifty machines. **Triage collection** copies only the files that answer the usual questions: who logged on, what ran, what was opened, what changed, what left the network.

| | Full disk image | Triage collection |
|---|---|---|
| **What** | Every sector, including unallocated space | A chosen list of files (a few hundred MB to a few GB) |
| **Time** | Hours per machine | Minutes per machine |
| **Scale** | A handful of machines | Dozens to thousands |
| **Can you carve deleted data later?** | Yes | Only from the files you took ($MFT, $LogFile, $J help a lot) |
| **Risk** | Slow; may arrive too late | You can only analyse what you decided to collect |

The rule most teams use: **triage first, everywhere it matters; image the machines the triage shows are important.** Because triage forces you to decide in advance, the collection profile (your Targets or scripts) is now part of your method. Keep it under version control and record its version in your notes.

### 1.2 Live response or dead box?

- **Dead box:** you collect from an image or a disk attached to your workstation. Nothing is locked or changing, and the system's own clock and accounts don't matter.
- **Live:** you collect from the running system, usually because you can't take it offline or need it fast. This brings three problems:
  1. **Locked files.** Windows holds the registry hives, event logs and NTFS metadata files (`$MFT`, `$LogFile`, `$UsnJrnl:$J`) open, so a normal copy fails. Triage tools get around this by **reading the NTFS structures directly from the volume**. KAPE's copy log marks those files `DeferredCopy = True`. DFIR ORC's tools read through the device rather than the Windows file API. AChoirX has `NCP:`, a raw NTFS copy.
  2. **Volume Shadow Copies (VSS).** Older versions of files may sit in shadow copies (Day 20). KAPE can search them with `--vss true`, and DFIR ORC's default configuration has shadow-copy commands such as `NTFSInfo_Quick_Shadows`.
  3. **Your own footprint.** Running a collector creates evidence: Prefetch for `kape.exe`, Amcache entries, process-creation events, files in `%TEMP%`. You can't avoid that, but you can **explain it**. Run from external media or a share, write the output off the suspect disk, and note the exact time and tool. Tomorrow's examiner (maybe you) will see those traces.

**Order of volatility** (RFC 3227): capture the most volatile data first. Memory comes before triage files. Memory forensics is Phase 3; on a live system, a memory capture is usually step one, and both AChoirX and DFIR ORC can do it as part of a run.

### 1.3 The Windows triage map

These are the artifacts every Windows triage collection should contain. You will parse each of them in the next two weeks.

| Artifact | Where (default) | What it answers | Deep dive |
|---|---|---|---|
| System hives `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT` **plus `.LOG1`/`.LOG2`** | `C:\Windows\System32\config\` | Configuration, services, accounts, USB devices, networks, autostarts | Day 11 |
| User hives `NTUSER.DAT`, `UsrClass.dat` **plus logs** | `C:\Users\<user>\` and `...\AppData\Local\Microsoft\Windows\` | Per-user activity: RecentDocs, UserAssist, ShellBags, typed paths | Days 11–13 |
| `Amcache.hve` | `C:\Windows\AppCompat\Programs\` | Programs present or run, with their SHA-1 | Day 12 |
| Prefetch `*.pf` | `C:\Windows\Prefetch\` | Program execution: run count and the last run times | Day 12 |
| Event logs `*.evtx` | `C:\Windows\System32\winevt\Logs\` | Logons, services, PowerShell, scheduled tasks, RDP | Days 14–16 |
| `$MFT`, `$LogFile`, `$UsnJrnl:$J`, `$Secure:$SDS`, `$Boot` | Volume root and `$Extend` | The file-system timeline, deleted files, renames | Day 10 |
| LNK files and Jump Lists | `...\AppData\Roaming\Microsoft\Windows\Recent\` | Files and folders the user opened, even on USB or network drives | Day 13 |
| SRUM `SRUDB.dat` | `C:\Windows\System32\sru\` | Hourly network and resource use per application | Day 17 |
| Recycle Bin `$I`/`$R` | `C:\$Recycle.Bin\<SID>\` | What was deleted, when, and from where | Day 17 |
| Scheduled tasks | `C:\Windows\System32\Tasks\` | Persistence | Day 22 |
| PowerShell history | `...\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Commands the user typed | Days 14, 22 |
| Browser history | e.g. `...\AppData\Local\Microsoft\Edge\User Data\Default\History` | Web activity and downloads | Day 18 |

Two details that catch beginners:

- **Always collect a hive together with its transaction logs.** If Windows didn't flush recent changes into the hive, they are only in `.LOG1`/`.LOG2`. Without them your registry is out of date (Day 11).
- **Windows paths are case-insensitive; Linux mounts usually aren't.** Targets say `C:\Windows\prefetch\` but the folder is `Prefetch`. A Windows collector doesn't care; a script on a Linux mount must (Lab 1 shows this).

### 1.4 Collect it soundly

A triage collection is evidence, so the Day 2 rules apply:

- **Hash at collection time.** KAPE writes a SHA-1 for every source file to its copy log. AChoirX writes an MD5 list (`ACQHash.txt`) and checks each copy against its source. DFIR ORC puts everything into 7z archives. Add a SHA-256 manifest of your own for the package you hand over.
- **Keep the original timestamps.** Copies get new creation times on the destination file system. Good tools record the source's times (KAPE: `CreatedOnUtc`, `ModifiedOnUtc`, `LastAccessedOnUtc` in the copy log) and keep the modified time on the copy.
- **Understand de-duplication.** KAPE skips files whose SHA-1 it has already copied (`--tdd`, default on). That saves space, but two different paths with the same content become **one** copy. The skip log is then the only record of the second path (Lab 3).
- **Record versions.** Write down the tool version and the version of its Targets/configuration (for KapeFiles, the Git commit). Targets change often.
- **Protect the output.** Triage packages contain passwords, personal data and sometimes malware. Encrypt them and transfer them securely (KAPE: `--zpw`, SFTP/S3/Azure; DFIR ORC: certificate encryption, BITS; AChoirX: `ENC:`, SFTP, S3). The DFIR ORC configuration README reminds you that collections may contain personal data covered by the GDPR.

### 1.5 Choosing a collector

| | KAPE | AChoirX | DFIR ORC |
|---|---|---|---|
| **Made by** | Kroll (Eric Zimmerman) | OMENScan (D0n Quixote), open source | ANSSI, the French national cybersecurity agency |
| **Runs on** | Windows (.NET Framework) | Windows, Linux, macOS, Android (beta) | Windows (XP SP2 to Windows 10 / Server 2019 listed as tested) |
| **What to collect is defined by** | Targets (`.tkape` YAML) and Modules (`.mkape`) | ACQ scripts | XML configurations embedded in the executable |
| **Locked files** | Raw NTFS reads (`DeferredCopy`) | `NCP:` raw copy (Windows only) | Its tools read NTFS directly |
| **Output** | Folders, VHD/VHDX/ZIP; SFTP, S3, Azure | Folder with MD5 list and HTML index; ZIP; SFTP, S3 | 7z archives, optionally encrypted to certificates; BITS upload |
| **Licence** | Free for government, education, research and internal company use; **no commercial use since 1 January 2026** | GPL-2.0 | LGPL-2.1 (code), Licence Ouverte 2.0 (configurations) |
| **Best at** | Fast collection with community Targets, then processing with Modules | One script for every OS; easy custom collectors | Deployment across large estates, encrypted output, low-level NTFS tools |

Remote collection at scale with Velociraptor, GRR and osquery is Day 49.

---

## Part 2: Tools

---

### 🛠️ Tool 1: KAPE (Kroll Artifact Parser and Extractor)

| | |
|---|---|
| **What** | A Windows triage program with two halves. **Targets** find and copy files. **Modules** run programs on what was copied (for example Eric Zimmerman's parsers) |
| **Why in DFIR** | One of the most widely used Windows triage tools. Hundreds of community Targets, raw reads of locked files, VSS support, containers (VHDX/ZIP), and uploads |
| **Platforms** | Windows only. Needs **Administrator** rights and **.NET Framework 4.5.2** or newer (per the docs) |
| **Licence** | Free for government agencies and for educational, research and internal company use. Per the KAPE FAQ, **as of 1 January 2026 it is no longer available for commercial use** (third-party networks or paid engagements) |
| **Home** | https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape · Docs: https://ericzimmerman.github.io/KapeDocs/ · Targets/Modules: https://github.com/EricZimmerman/KapeFiles |

> ⚠️ **Not run here.** KAPE is a Windows program, so the steps in this section weren't run in this lesson's Linux lab. The commands follow the official KapeDocs. In Labs 2–4 you work with the **real KAPE Target files** using `scripts/tkape_collect.py`, a small re-implementation of KAPE's Target logic that runs on Linux.

#### Installation (Windows)

KAPE doesn't need installing; you unzip it.

1. Fill in the form on the Kroll KAPE page (link above). You'll receive a download link for `kape.zip`.
2. If Windows marks the download as "from the Internet", unblock it before extracting, then extract it to a tools folder or a USB drive:

   ```powershell
   Unblock-File -Path .\kape.zip
   Expand-Archive .\kape.zip -DestinationPath E:\
   Get-ChildItem E:\ -Recurse -Filter kape.exe      # where it landed; below we assume E:\KAPE
   ```

   The folder holds `kape.exe`, `gkape.exe`, `Get-KAPEUpdate.ps1`, `Targets\`, `Modules\` and `Documentation\`.

3. Update the program and its Targets and Modules (from an **elevated** PowerShell):

   ```powershell
   cd E:\KAPE
   .\Get-KAPEUpdate.ps1      # updates kape.exe itself if a newer version exists
   .\kape.exe --sync         # pulls the latest Targets/Modules from the KapeFiles repo
   ```

> Keep KAPE on the drive you collect **to**, not on the suspect system. If you collect to the same USB drive, size it for the output: a `KapeTriage` run is usually a few hundred MB to a few GB.

#### Configuration

**Folders:**

| Folder | Purpose |
|---|---|
| `Targets\` | `.tkape` files: *what to copy*. Sub-folders (`Windows`, `Apps`, `Browsers`, `Compound`, …) are just organisation |
| `Targets\!Local\` | **Your own Targets.** `--sync` moves Targets that aren't in the public repo here, so they survive updates |
| `Targets\!Disabled\` | Targets you want hidden from KAPE |
| `Modules\` and `Modules\bin\` | `.mkape` files: *what to run*; the programs they call go in `bin` (KAPE never downloads them for you) |

**Anatomy of a Target**, from `Targets\Windows\Prefetch.tkape`:

```yaml
Description: Prefetch files          # required
Author: Eric Zimmerman               # required
Version: 1.0                         # required, increase it when you change the file
Id: f6715d3f-b8ca-4cc2-9e5e-4ed18e88abbe   # required, a unique GUID (kape.exe --guids makes ten)
RecreateDirectories: true            # required, keep the source folder structure in --tdest
Targets:
    -
        Name: Prefetch               # a label, not used to find files
        Category: Prefetch
        Path: C:\Windows\prefetch\   # always written as C:\; KAPE swaps in --tsource
        FileMask: '*.pf'             # default '*'; 'regex:...' for a regular expression
```

Other optional fields per entry: `Recursive`, `AlwaysAddToQueue` (queue a path even if the OS says it doesn't exist, used for `$MFT`, `$LogFile` and the like), `SaveAsFileName` (for streams such as `$UsnJrnl:$J` → `$J`), `MinSize`, `MaxSize` and `Comment`.

A **compound Target** points `Path` at other Targets (`Path: Prefetch.tkape`), or at a whole folder (`Path: Antivirus\*`). `KapeTriage` is a compound Target that expands to about 1,200 file specifications. KAPE uses each Target's `Id` so that a Target included twice runs once.

**Variables:** `%user%` in a path matches every profile, unless you pass `--tvars user:alice` to collect a single user.

**The switches you'll use most** (from *Using KAPE* in KapeDocs):

| Switch | Meaning |
|---|---|
| `--tsource C:` | Drive or UNC path to collect **from** |
| `--target KapeTriage` | Target(s), comma-separated, or a Targets sub-folder name |
| `--tdest E:\Cases\%m_%d\tout` | Where to copy to (`%m` = machine name, `%d` = timestamp) |
| `--tlist .` / `--tdetail` | List Targets / with their paths |
| `--vss true` | Also search Volume Shadow Copies |
| `--tdd false` | Turn off SHA-1 de-duplication (default on) |
| `--hex hashes.txt` | Don't copy files whose SHA-1 is in the list (logged as "Excluded") |
| `--vhdx NAME` / `--vhd NAME` / `--zip NAME` | Package the output (the VHD(X) is zipped unless `--zv false`) |
| `--zpw PASSWORD` | Password for the zip options |
| `--scs`, `--scp`, `--scu`, `--scpw`, `--scd` | SFTP upload |
| `--debug`, `--trace` | More logging |
| `--sync` | Update Targets and Modules |
| `--guids` | Print 10 new GUIDs for your own Targets |

**Batch mode:** put full command lines (without `kape.exe`) in a file named `_kape.cli` next to `kape.exe`. Running `kape.exe` as Administrator then runs each line. This is handy when you ask a remote colleague to "right-click, Run as administrator".

**gkape.exe** is a GUI that builds the same command line. It's a good way to learn the switches.

#### First use (Windows, as Administrator)

```powershell
cd E:\KAPE
.\kape.exe --tlist .                                   # Targets in .\Targets
.\kape.exe --tsource C: --target KapeTriage --tdest E:\Cases\%m_%d\tout --vhdx WS-ALICE
```

KAPE writes these files into `--tdest`:

- `<timestamp>_KapeTriage_CopyLog.csv`: `SourceFile`, `DestinationFile`, `FileSize`, `SourceFileSha1`, `DeferredCopy`, and the source's created, modified and accessed times (UTC).
- `<timestamp>_KapeTriage_SkipLog.csv`: files not copied, with the reason `Deduped` or `Excluded`.
- A console log: everything that was shown on screen, at the `--debug`/`--trace` level you chose.

To collect from a **mounted image** instead of the live C: drive, mount the E01 with **Arsenal Image Mounter** (Day 6) and use its drive letter as `--tsource`. KapeDocs warns against FTK Imager and Dokan mounts for KAPE, and recommends AIM because it exposes shadow copies too.

#### Verify the installation

```powershell
.\kape.exe --tlist .                                     # lists Targets: the Targets folder is in place
.\kape.exe --tsource C: --target Prefetch --tdest C:\Temp\kape-test
Get-ChildItem C:\Temp\kape-test\*CopyLog.csv            # a copy log with one row per .pf file
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| KAPE exits immediately or says it needs rights | Run it from an **elevated** prompt. On some systems running as SYSTEM (for example `PsExec64.exe -s`) avoids remaining access errors (KapeDocs tips) |
| Security software deletes `kape.exe` or a module binary | Add an exclusion for your KAPE folder's hashes on that host, or use the EDR's own collection feature to launch KAPE |
| Nothing collected from a mounted E01 | Remount with Arsenal Image Mounter (not FTK Imager or Dokan), and point `--tsource` at the right letter |
| `DeferredCopy = True` in the copy log | Normal. The file was locked and KAPE read it raw from the volume |
| A file you expected is missing | Check the SkipLog (`Deduped`), run `--tdetail` to see the Target's real paths, and update with `--sync` |
| Very long paths in a VHDX or ZIP | KAPE moves them into `LongFileNames` with a text file holding the original path |
| You're doing paid work for a client | KAPE can't be used for that any more. Use another tool (AChoirX, DFIR ORC, Velociraptor) |

---

### 🛠️ Tool 2: AChoirX

| | |
|---|---|
| **What** | A Go program and a small scripting language for **live response and triage collection** ("ACQ" scripts). One script can collect the right artifacts on Windows, Linux and macOS. It is also used to process mounted images |
| **Why in DFIR** | One executable, no runtime, every major OS. Scripts are readable text, it hashes and verifies every copy, and you can bundle your own tools and scripts into a custom collector |
| **Platforms** | Windows (64- and 32-bit), Linux (amd64), macOS (Intel and Apple silicon), Android (beta) |
| **Licence** | GPL-2.0 (`LICENSE`). Bundled third-party tools keep their own licences |
| **Home** | https://github.com/OMENScan/AChoirX (read `WhatIsAChoirX.txt` for the full language reference) |

#### Installation

**Linux** (run in Lab 5): the repository ships a ready-made static binary.

```bash
mkdir -p ~/tools/achoirx && cd ~/tools/achoirx
curl -fL -o AChoirX https://raw.githubusercontent.com/OMENScan/AChoirX/master/Lin/AChoirX
sha256sum AChoirX          # record it: v10.01.85 = 986b392a594f7a7338ece986214807fd18d9f5c47236fff456435cdf9c4b24d3
chmod +x AChoirX
./AChoirX /HELP | head -n 3
```

**macOS** (not run here): download `OSX/AChoirX-ARM` (Apple silicon) or `OSX/AChoirX-AMD` (Intel) from the same repository the same way, then `chmod +x`. If Gatekeeper blocks it, remove the quarantine attribute with `xattr -d com.apple.quarantine AChoirX-ARM`.

**Windows** (not run here), in an elevated PowerShell:

```powershell
New-Item -ItemType Directory E:\AChoirX | Out-Null; cd E:\AChoirX
Invoke-WebRequest https://raw.githubusercontent.com/OMENScan/AChoirX/master/Win/AChoirX.exe -OutFile AChoirX.exe
Get-FileHash AChoirX.exe -Algorithm SHA256
.\AChoirX.exe /HELP
```

The README also describes an installer, `AChoirX-inst.exe` (run it as administrator). It unpacks AChoirX with its scripts and source, then runs the builder script, which downloads extra free tools and builds `AChWinAll.exe`, a bigger Windows collector. You can run the same builder later with `AChoirX.exe /BLD`. At the time of writing, the installer isn't in the source tree, so look for it on the project's Releases page.

**From source** (not run here): `Compile/AChLin.bat` in the repository shows the build: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build AChoirX.go only_linux.go` (use `only_windows.go` or `only_OSX.go` for the other platforms).

#### Configuration

AChoirX does what its **ACQ script** says. Without options it runs its embedded default `AChoir.ACQ`, which picks the right collection for the OS (on Windows it captures memory first, then the triage files; `NoMem.ACQ` skips memory).

**Command-line options** (from `/HELP` and `WhatIsAChoirX.txt`):

| Option | Meaning |
|---|---|
| `/RUN` | Run the default `AChoir.ACQ` collection. Creates `ACQ-IR-<name>-<YYYYMMDD>-<HHMM>` in the **current directory** |
| `/INI:<file>` | Run your own script instead (it doesn't create the folder until the script runs `ACQ:`) |
| `/NAM:<name>` | Use `<name>` in the output folder name instead of the host name |
| `/VR0:` … `/VR9:` | Pass values into the script as `&VR0` … `&VR9` |
| `/DRV:<x:>` | Set `&Drv` to a drive letter (Windows; for mounted images) |
| `/CSE` | Ask for case, evidence and examiner details and log them |
| `/CON` | Interactive console mode |
| `/BLD` | Run `Build.ACQ` (download tools and build `AChWinAll.exe`) |
| `/PKR:<zip>` | Make a new executable with your toolkit `.zip` (scripts and tools) appended |
| `/XTR` | Extract the embedded toolkit |
| `/DBG:min\|std\|max\|debug` | Console detail level |
| `/SRV:` / `/CLI:` | Multi-handler server / client for remote control (shared `/PWD:` password, encrypted) |

**Script language basics:** an *action* is three letters and a colon at the start of a line; an *object* (variable) is `&` plus three letters.

| Action | Does |
|---|---|
| `ACQ:\Reg` | Create the acquisition folder (`ACQ:\`) or a sub-folder, and set `&Acq` to it |
| `CPY:"<from>" "<to>"` | Copy files. `*` matches in one folder, `**` searches all sub-folders. It verifies each copy by MD5 and size |
| `SET:CopyPath=None\|Part\|Full` | Flatten / keep the path after the first wildcard / keep the full source path |
| `NCP:` | Raw NTFS copy for locked or hidden files such as `$MFT` (Windows only) |
| `CKY:` / `CKN:` … `END:` | Run the block if a file exists / doesn't exist |
| `VER:Windows` … `END:` | Run the block only on that OS |
| `SYS:` / `EXE:` | Run a command / a program from the toolkit (`--exestdout=<file>` saves its output) |
| `REG:` | Export a registry key and its sub-keys to a tab-separated file (Windows only) |
| `HSH:ACQ` | MD5 every collected file into `ACQHash.txt` |
| `ZIP:`, `SFU:`, `S3U:`, `ENC:` | Zip / upload by SFTP / upload to S3 / encrypt |
| `SAY:`, `INC:`, `BYE:` | Print and log / include another script / exit |

Useful objects: `&Acq` (current output folder), `&Acn` (collection name), `&Drv`, `&Win` (Windows folder), `&VR0`–`&VR9`, `&FOR` with `&FO0`–`&FOP` (looping over files), `&Hst` (host name).

The repository's `Scripts/` folder has many ready-made pieces (`Scripts/Win/WinReg.ACQ`, `WinEvt.ACQ`, `WinPrf.ACQ`, …) and `Scripts/Mounted.ACQ`, which collects from a Windows image mounted as a drive letter. Read them before writing your own.

#### Verify the installation

```bash
./AChoirX /HELP | head -n 3     # prints the version: AChoirX ver: v10.01.85, Argument/Options:
```

On Windows, run `.\AChoirX.exe /RUN` as Administrator on a test VM. You should get an `ACQ-IR-<host>-<date>-<time>` folder containing `ACQHash.txt`, `Index.htm` and a log.

#### First use

Lab 5 runs a custom script against a mounted Windows image. On a live Windows host the simplest collection is:

```powershell
cd E:\AChoirX
.\AChoirX.exe /RUN /NAM:WS-ALICE        # elevated prompt; output goes under E:\AChoirX
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| Linux/macOS: `[!] Could not Open Log File.` and nothing collected | Run it with `sudo`. AChoirX creates its folders with mode 0644 (no execute bit), so only root can write into them. This was confirmed in this lesson's lab |
| You can't open the output afterwards | AChoirX sets artifacts and folders read-only when it finishes. Read them with `sudo`, or add read access with `sudo chmod -R a+rX ACQ-IR-*` (permissions only; the contents are unchanged) |
| `CPY:` copied one folder but not its sub-folders | Use `**` to recurse: `CPY:"&VR0/Windows/System32/Tasks/**/*" "&Acq"` |
| A path works on Windows but finds nothing on a Linux mount | Linux mounts are case-sensitive. Match the real case (`Prefetch`), or use classes like `[Pp]refetch` as `Mounted.ACQ` does |
| Locked files fail on live Windows | Use `NCP:` for `$MFT`, `$LogFile` and hives |
| Antivirus flags the collector | The default toolkit includes memory dumpers. Allow-list your build's hash, or build your own toolkit with `/PKR:` |
| You need SHA-256, not MD5 | `ACQHash.txt` is MD5 only. Add a SHA-256 manifest afterwards (Lab 6) |

---

### 🛠️ Tool 3: DFIR ORC

| | |
|---|---|
| **What** | ANSSI's **framework for collecting forensic artifacts** on Windows. A single executable runs a set of embedded tools (NTFSInfo, USNInfo, GetThis, GetSamples, RegInfo, FastFind, …) and external ones (Sysinternals) according to an embedded XML configuration, and writes 7z archives |
| **Why in DFIR** | Built for **deployment at scale** by people who aren't forensic specialists: one configured binary, low-level NTFS access, resource limits, encryption of the output to your certificates, and upload by BITS or SMB |
| **Platforms** | Windows (the docs list Windows XP SP2 up to Windows 10 and Server 2019 as tested). Building it needs Windows with Visual Studio 2022–2026 |
| **Licence** | LGPL-2.1 (code). Example configurations: Licence Ouverte 2.0 |
| **Home** | https://github.com/DFIR-ORC/dfir-orc · Docs: https://dfir-orc.github.io · Configurations: https://github.com/DFIR-ORC/dfir-orc-config |

> ⚠️ **Not run here.** DFIR ORC builds and runs only on Windows, so none of this section ran in the lab. The commands come from the project's README, its tutorial and its command-line documentation (release tag `v10.3.4` at the time of writing).

#### Installation: build (Windows)

DFIR ORC is shipped as source, and you build it once:

```powershell
winget install Microsoft.Git
git clone --recursive https://github.com/dfir-orc/dfir-orc.git
cd dfir-orc
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--passive --config .vsconfig"
Import-Module "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools" -SkipAutomaticLocation
.\Build-Orc.ps1          # PowerShell 5.1+; result: .\build\MinSizeRel\DFIR-ORC.exe
```

- Visual Studio must have the **English language pack only** (a vcpkg limitation), with the *Desktop development with C++* workload.
- `DFIR-ORC.exe` is a "capsule" that contains both the 32-bit and 64-bit builds and picks the right one when it runs.
- This **unconfigured** binary already contains the embedded tools, but no collection plan.

#### Configuration: embed a collection plan

```powershell
git clone https://github.com/dfir-orc/dfir-orc-config.git
cd dfir-orc-config
# Put these in .\tools (from Sysinternals, Magnet DumpIt and PersistenceSniper):
#   autorunsc.exe handle.exe Tcpvcon.exe Listdlls.exe DumpIt.exe PersistenceSniper.psm1
Copy-Item ..\dfir-orc\build\MinSizeRel\DFIR-ORC.exe .
.\Build.cmd              # elevated; runs DFIR-ORC.exe ToolEmbed and writes .\output\Orc.exe
```

(You can also do it in one step when building: `.\Build-Orc.ps1 -ToolEmbed .\config` writes `DFIR-ORC-ready.exe`.)

The files that matter in `config\`:

| File | Role |
|---|---|
| `ORC_config.xml` | The **WolfLauncher** plan: which archives to create (`..._General.7z`, `..._Memory.7z`, `..._FastFind.7z`) and the commands in each. Each has a **keyword**, and some are `optional="yes"` |
| `GetThis_*.xml`, `NTFSInfo_*.xml`, … | Settings for the individual tools (what GetThis collects, size limits, …) |
| `Embed.xml` | What `ToolEmbed` packs into the executable |

Next to `Orc.exe`, **`Orc.xml`** is the local configuration. A configured binary reads the XML file with its own base name from its folder. Use it to set the output folder, uploads and, most importantly, **recipients**:

```xml
<dfir-orc priority="low" powerstate="SystemRequired,AwayMode">
    <output>E:\ORC</output>
    <recipient name="SOC" archive="*">
-----BEGIN CERTIFICATE-----
(your PEM certificate; the collected archives are encrypted to it)
-----END CERTIFICATE-----
    </recipient>
</dfir-orc>
```

The shipped `Orc.xml` states that encryption is mandatory for security reasons. Only the holder of the private key can open the archives, so the collection is safe even on an untrusted share.

**Command-line options** (from the DFIR ORC docs):

| Option | Meaning |
|---|---|
| `/keys` | **Dry run.** Show which archives and commands would run |
| `/key=<kw>[,<kw>]` | Run only these archives or commands |
| `/+key=<kw>` / `/-key=<kw>` | Add an optional one / remove a default one (`/key+=` and `/key-=` also work) |
| `/out=<folder or share>` | Output location |
| `/overwrite`, `/once`, `/createnew` | What to do if the archives already exist |
| `/Compression=Fast` | `None`, `Fastest`, `Fast`, `Normal`, `Maximum`, `Ultra` |
| `/Priority=low` | Process priority |
| `/nolimits[:<cmd>]` | Lift GetThis/GetSamples size limits (careful: can fill the disk) |
| `/local=<file.xml>` | Use a specific local configuration file |

#### Verify the installation

```powershell
.\output\Orc.exe /keys
```

It prints a banner (version, computer, output folder, log file) and then the plan: one `[X] Archive: …` line per archive, with the file name it will write (the default configuration names them `ORC_<SystemType>_<Computer>_General.7z` and so on), followed by its commands. `[X]` means it will run, and `[ ]` means it's optional and off. If you see the plan, the configuration is embedded.

#### First use

```powershell
.\output\Orc.exe /keys /+key=GetYara /-key=GetSamples      # check your selection first
.\output\Orc.exe /out=E:\ORC                                # full default collection
.\output\Orc.exe /key=SystemInfo /out=E:\ORC\test /overwrite # one quick command, for testing
.\output\Orc.exe NTFSInfo /out=C_drive.csv C:\              # run one embedded tool directly: an $MFT listing as CSV
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| The build fails while fetching packages | Visual Studio needs the **English** language pack only; use a Developer PowerShell (`Enter-VsDevShell`) |
| `Build.cmd` fails | Run it elevated, with `DFIR-ORC.exe` next to it and all the files listed in `tools\` present |
| A second run does nothing | The archives already exist. Add `/overwrite` or choose another `/out` |
| Security software removes `Orc.exe` or tools | It embeds Sysinternals tools and a memory dumper. Allow-list your build's hash on the hosts you collect from |
| Collection takes too long on file servers | Use the `*_system_noshadow` keys described in `Orc.xml` (they limit some commands to the system volume and skip shadow copies), and `/Priority=low` |
| Process-launch errors on Windows 7/2008 inside a job object | Those versions can't nest job objects. Run it outside the restricting job (see *Requirements* in the docs) |

---

## Part 3: Hands-on labs

You'll build a small fake Windows system drive, mount it read-only, and collect from it three ways: with the real KAPE Target definitions, with your own Targets, and with AChoirX. The scenario: user **alice** on workstation **WS-ALICE** downloaded `rclone`, copied her Documents to a cloud drive, set up a scheduled task and deleted a staging script.

Run on **SIFT** or Ubuntu with `sudo`. The files in the image are stand-ins (correct signatures, fake contents), and tomorrow's tools need real ones, so don't try to parse them.

```bash
sudo apt update && sudo apt install -y ntfs-3g python3-yaml git curl
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-009/{evidence,work,notes,tools} && cd ~/cases/LAB-009
export TZ=UTC
```

### Lab 1: Build and mount the "suspect" drive (15 min)

```bash
cd ~/cases/LAB-009
python3 ~/DFIR/scripts/mk_win_triage_lab.py work/winroot
truncate -s 64M evidence/WS-ALICE-C.img
mkntfs -F -Q -L WS-ALICE evidence/WS-ALICE-C.img > /dev/null 2>&1
sudo mkdir -p /mnt/build /mnt/ws-alice
sudo ntfs-3g evidence/WS-ALICE-C.img /mnt/build
sudo cp -r --preserve=timestamps work/winroot/. /mnt/build/
sudo umount /mnt/build
sha256sum evidence/WS-ALICE-C.img | tee notes/WS-ALICE-C.img.sha256
```

```
wrote 40 files (426220 bytes) under work/winroot
687f715b41aaae2544a79d4ba1017df22e7010cc57e1c73a6f350f7e94d5c8e9  evidence/WS-ALICE-C.img
```

Your image hash **will differ**: `mkntfs` writes a random volume serial number and the current time. Every file inside the image is the same on every run, so the file hashes later in the lab will match.

Now mount it the way you'd mount evidence: **read-only**, with NTFS system files visible (`show_sys_files`) and alternate data streams reachable as `file:stream` (`streams_interface=windows`):

```bash
sudo ntfs-3g -o ro,show_sys_files,streams_interface=windows evidence/WS-ALICE-C.img /mnt/ws-alice
ls -A /mnt/ws-alice
ls -l '/mnt/ws-alice/$MFT' '/mnt/ws-alice/$Secure:$SDS'
ls /mnt/ws-alice/Windows/prefetch
ls /mnt/ws-alice/Windows/Prefetch
```

```
$AttrDef
$BadClus
$Bitmap
$Boot
$Extend
$LogFile
$MFT
$MFTMirr
$Recycle.Bin
$Secure
$UpCase
$Volume
Program Files
Users
Windows
-rwxrwxrwx  1 root root 148480 Jan  1  1601 /mnt/ws-alice/$MFT
-rwxrwxrwx? 1 root root 262396 Oct  6 09:06 /mnt/ws-alice/$Secure:$SDS
ls: cannot access '/mnt/ws-alice/Windows/prefetch': No such file or directory
CMD.EXE-0BD30981.pf
POWERSHELL.EXE-CA1AE517.pf
RCLONE.EXE-5F3E1A2B.pf
```

What you just learned:

- **NTFS metadata files are ordinary files** on this mount: `$MFT`, `$LogFile`, `$Boot`, and the `$SDS` stream of `$Secure`. On a live Windows system they're hidden and locked, which is why collectors need raw reads.
- The time on `$Secure:$SDS` is when *you* built the image. The `Jan 1 1601` date on `$MFT` is not a real time. ntfs-3g reports zero for it, and zero in Windows `FILETIME` is 1601-01-01.
- **The mount is case-sensitive:** `prefetch` fails and `Prefetch` works. Windows (and KAPE) don't care about case; anything you script on Linux must.

### Lab 2: Read KAPE Targets (15 min)

KAPE's Targets live in a public repository. You don't need KAPE to read them, and they are the best documentation of *where Windows keeps things*.

```bash
cd ~/cases/LAB-009/tools
git clone -q --depth 1 https://github.com/EricZimmerman/KapeFiles.git
git -C KapeFiles log -1 --format='KapeFiles %h %cs' | tee ../notes/kapefiles-version.txt
find KapeFiles/Targets -name '*.tkape' | wc -l
grep -v '^#' KapeFiles/Targets/Windows/Prefetch.tkape
```

```
KapeFiles ed0f9c7 2026-09-18
426
Description: Prefetch files
Author: Eric Zimmerman
Version: 1.0
Id: f6715d3f-b8ca-4cc2-9e5e-4ed18e88abbe
RecreateDirectories: true
Targets:
    -
        Name: Prefetch
        Category: Prefetch
        Path: C:\Windows\prefetch\
        FileMask: '*.pf'
    -
        Name: Prefetch
        Category: Prefetch
        Path: C:\Windows.old\Windows\prefetch\
        FileMask: '*.pf'

```

Your commit, count and later numbers may be a little different: KapeFiles changes often. That's why you saved the version to your notes.

`scripts/tkape_collect.py` implements KAPE's **Target** processing (not Modules, VSS or raw reads) so you can practise on Linux. It uses the same ideas: `--tlist`, `--tdetail`, `--tsource`, `--target`, `--tdest`, `--tvars` and `--tdd`.

```bash
T=~/cases/LAB-009/tools/KapeFiles/Targets
python3 ~/DFIR/scripts/tkape_collect.py --targets "$T" --tlist triage | cut -c1-110
python3 ~/DFIR/scripts/tkape_collect.py --targets "$T" --tdetail KapeTriage 2>/dev/null | wc -l
python3 ~/DFIR/scripts/tkape_collect.py --targets "$T" --tdetail KapeTriage 2>/dev/null | grep -E '^(Prefetch|EventLogs|RecycleBin_InfoFiles) '
```

```
!SANS_Triage                             SANS Triage Collection
KapeTriage                               KapeTriage collects most of the files needed for a DFIR Investigation
ProgramExecution                         Program Execution Triage Collection
ServerTriage                             A compound target for gathering artifacts common to servers.
1200
EventLogs              EventLogs      C:\Windows\System32\config\  *.evt
EventLogs              EventLogs      C:\Windows\System32\winevt\logs\  *.evtx
EventLogs              EventLogs      C:\Windows.old\Windows\System32\winevt\logs\  *.evtx
Prefetch               Prefetch       C:\Windows\prefetch\  *.pf
Prefetch               Prefetch       C:\Windows.old\Windows\prefetch\  *.pf
RecycleBin_InfoFiles   FileDeletion   C:\$Recycle.Bin\  $I* (recursive)
RecycleBin_InfoFiles   FileDeletion   C:\RECYCLE*\  INFO2 (recursive)
```

The compound Target **KapeTriage** expands to **1,200** file specifications across dozens of leaf Targets, with XP (`*.evt`, `INFO2`) and `Windows.old` paths included. Note that **RecycleBin_InfoFiles** takes only the `$I` files (who deleted what, when, from where), not the `$R` files (the deleted content), to keep triage small.

### Lab 3: Collect with KapeTriage and check the collection (20 min)

Preview first, then collect:

```bash
cd ~/cases/LAB-009
python3 ~/DFIR/scripts/tkape_collect.py --targets "$T" --tsource /mnt/ws-alice --target KapeTriage --tdest work/tout --dry-run 2>/dev/null | head -12
python3 ~/DFIR/scripts/tkape_collect.py --targets "$T" --tsource /mnt/ws-alice --target KapeTriage --tdest work/tout
ls work/tout
find work/tout/C -type f | sort
cat work/tout/*_SkipLog.csv
```

```
1200 file specifications from 1 Target(s); 35 files queued
  [EventLogs] C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
  [EventLogs] C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx
  [EventLogs] C:\Windows\System32\winevt\Logs\Security.evtx
  [EventLogs] C:\Windows\System32\winevt\Logs\System.evtx
  [ApplicationCompatibility] C:\Windows\AppCompat\Programs\Amcache.hve
  [Prefetch] C:\Windows\Prefetch\CMD.EXE-0BD30981.pf
  [Prefetch] C:\Windows\Prefetch\POWERSHELL.EXE-CA1AE517.pf
  [Prefetch] C:\Windows\Prefetch\RCLONE.EXE-5F3E1A2B.pf
  [FileSystem] C:\$MFT
  [FileSystem] C:\$LogFile
  [FileSystem] C:\$Secure:$SDS
WARN   Bitdefender SQLite DB Files: bad regex FileMask 'regex:*.+\\.(db|db-wal|db-shm)' (nothing to repeat at position 5); entry skipped
1200 file specifications from 1 Target(s); 35 files queued
Copied 33 files (2918169 bytes), skipped 2 (see SkipLog) -> work/tout
2026-10-06T09_06_31_412880_KapeTriage_CopyLog.csv
2026-10-06T09_06_31_412880_KapeTriage_SkipLog.csv
C
work/tout/C/$Boot
work/tout/C/$LogFile
work/tout/C/$MFT
work/tout/C/$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001/$I7Q2KD1.ps1
work/tout/C/$Secure_$SDS
work/tout/C/Users/alice/AppData/Local/Microsoft/Edge/User Data/Default/History
work/tout/C/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat
work/tout/C/Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
work/tout/C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/f01b4d95cf55d32a.automaticDestinations-ms
work/tout/C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/Q3-forecast.xlsx.lnk
work/tout/C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/rc.zip.lnk
work/tout/C/Users/alice/NTUSER.DAT
work/tout/C/Users/alice/NTUSER.DAT.LOG1
work/tout/C/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat
work/tout/C/Users/bob/NTUSER.DAT
work/tout/C/Windows/AppCompat/Programs/Amcache.hve
work/tout/C/Windows/Prefetch/CMD.EXE-0BD30981.pf
work/tout/C/Windows/Prefetch/POWERSHELL.EXE-CA1AE517.pf
work/tout/C/Windows/Prefetch/RCLONE.EXE-5F3E1A2B.pf
work/tout/C/Windows/System32/Tasks/OneDriveUpdate
work/tout/C/Windows/System32/config/DEFAULT
work/tout/C/Windows/System32/config/SAM
work/tout/C/Windows/System32/config/SECURITY
work/tout/C/Windows/System32/config/SOFTWARE
work/tout/C/Windows/System32/config/SOFTWARE.LOG1
work/tout/C/Windows/System32/config/SYSTEM
work/tout/C/Windows/System32/config/SYSTEM.LOG1
work/tout/C/Windows/System32/config/SYSTEM.LOG2
work/tout/C/Windows/System32/sru/SRUDB.dat
work/tout/C/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx
work/tout/C/Windows/System32/winevt/Logs/Microsoft-Windows-TaskScheduler%4Operational.evtx
work/tout/C/Windows/System32/winevt/Logs/Security.evtx
work/tout/C/Windows/System32/winevt/Logs/System.evtx
SourceFile,SourceFileSha1,Reason
C:\Users\alice\NTUSER.DAT.LOG2,DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,Deduped
C:\Users\bob\NTUSER.DAT.LOG2,DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,Deduped
```

(The log names start with the time *you* ran it, like KAPE's.) Points to notice:

- **Case-insensitive matching worked.** The Target says `prefetch` and `winevt\logs`; the disk has `Prefetch` and `winevt\Logs`.
- **`$Secure:$SDS` was saved as `$Secure_$SDS`.** That's the Target's `SaveAsFileName`, because `:` can't appear in a Windows file name.
- **Two files were de-duplicated.** Both `NTUSER.DAT.LOG2` files are empty, so their SHA-1 is `DA39A3EE…0709` (the SHA-1 of nothing). That's the same as `SYSTEM.LOG2`, which was copied first. The skip log is now your only record that those two paths existed. Use `--tdd false` when that matters.
- **The WARN line** is an upstream Target whose regular expression starts with `*`, which Python can't compile. The mini engine skips that entry; KAPE's own handling may differ. In a real case, that's a Target you'd report or fix.

**Check the collection** before you trust it. Re-hash every copy and compare it with the SHA-1 in the copy log, and confirm the modified times survived:

```bash
tail -n +2 work/tout/*_CopyLog.csv | while IFS=, read -r _ src dst size sha1 _; do
  [ "$(sha1sum "$dst" | cut -c1-40 | tr a-f A-F)" = "$sha1" ] && echo OK || echo "BAD $src"
done | sort | uniq -c
stat -c '%y  %n' work/tout/C/Windows/Prefetch/*.pf
```

```
     33 OK
2026-09-28 10:14:31.000000000 +0000  work/tout/C/Windows/Prefetch/CMD.EXE-0BD30981.pf
2026-09-28 10:14:31.000000000 +0000  work/tout/C/Windows/Prefetch/POWERSHELL.EXE-CA1AE517.pf
2026-09-29 01:03:44.000000000 +0000  work/tout/C/Windows/Prefetch/RCLONE.EXE-5F3E1A2B.pf
```

Now the important question: **what did triage *not* take?**

```bash
comm -23 <(cd work/winroot && find . -type f | sort) <(cd work/tout/C && find . -type f | sort)
```

```
./$Recycle.Bin/S-1-5-21-3623811015-3361044348-30300820-1001/$R7Q2KD1.ps1
./Program Files/Common Files/readme.txt
./Users/alice/AppData/Local/Temp/rc.zip
./Users/alice/AppData/Local/Temp/rc/rc.conf
./Users/alice/AppData/Local/Temp/rc/rclone.exe
./Users/alice/Documents/Q3-forecast.xlsx
./Users/alice/NTUSER.DAT.LOG2
./Users/alice/Pictures/holiday.jpg
./Users/bob/NTUSER.DAT.LOG2
./Windows/System32/drivers/etc/hosts
./Windows/System32/notepad.exe
```

Most of that is correctly left behind: documents, pictures, programs. But look at `Temp\rc\`. The task and the PowerShell history you *did* collect point to `rclone.exe` with a config file called **`rc.conf`**, and that config holds the attacker's cloud account. KapeTriage includes `RcloneConf.tkape`, but that Target looks for files named `rclone.conf` or `.rclone.conf`. A renamed config falls through. Generic Targets miss case-specific evidence; that's why you write your own.

### Lab 4: Write, lint and run your own Targets (20 min)

Your Targets go in `!Local` so that a KAPE `--sync` doesn't touch them. (The `LOCAL` variable avoids typing `!` inside double quotes, which an interactive bash treats as history expansion.)

```bash
LOCAL="$T/"'!Local'
mkdir -p "$LOCAL"
cat > "$LOCAL/RcloneStaging.tkape" <<'EOF'
Description: Renamed rclone configs, rclone binaries and archives staged in user Temp folders
Author: Your Name
Version: 1.0
Id: GUID-HERE
RecreateDirectories: true
Targets:
    -
        Name: Config files in user Temp folders
        Category: Exfiltration
        Path: C:\Users\%user%\AppData\Local\Temp\
        FileMask: '*.conf'
        Recursive: true
    -
        Name: rclone binaries in user Temp folders
        Category: Exfiltration
        Path: C:\Users\%user%\AppData\Local\Temp\
        FileMask: 'rclone*.exe'
        Recursive: true
    -
        Name: Archives staged in user Temp folders
        Category: Exfiltration
        Path: C:\Users\%user%\AppData\Local\Temp\
        FileMask: 'regex:.+\.(zip|7z|rar)'
        MaxSize: 104857600
# Documentation
# Day 09 lab: the attacker renamed rclone.conf to rc.conf, so RcloneConf.tkape misses it.
EOF
cat > "$LOCAL/Day09_Triage.tkape" <<'EOF'
Description: Day 09 lab - KapeTriage plus rclone staging artifacts
Author: Your Name
Version: 1.0
Id: GUID-HERE
RecreateDirectories: true
Targets:
    -
        Name: KapeTriage
        Category: Compound
        Path: KapeTriage.tkape
    -
        Name: Rclone staging
        Category: Exfiltration
        Path: RcloneStaging.tkape
EOF
for f in "$LOCAL"/RcloneStaging.tkape "$LOCAL"/Day09_Triage.tkape; do
  sed -i "s/GUID-HERE/$(python3 -c 'import uuid; print(uuid.uuid4())')/" "$f"
  python3 ~/DFIR/scripts/tkape_collect.py --targets "$T" --check "$f"
done
```

```
RcloneStaging.tkape: 3 entries, 0 error(s), 0 warning(s)
Day09_Triage.tkape: 2 entries, 0 error(s), 0 warning(s)
```

The quoted heredoc (`<<'EOF'`) matters: in an unquoted one, a `\` at the end of a line such as `...\Temp\` would join it to the next line. Every Target needs its own GUID; on Windows, `kape.exe --guids` prints ten. The archive entry's `MaxSize` (100 MB) stops a triage run from swallowing a huge archive.

See what the linter catches in a broken Target:

```bash
cat > work/Broken.tkape <<'EOF'
Description: A target with three mistakes
Author: Your Name
Version: 1.0
Id: 1234
Targets:
    -
        Name: Desktop scripts
        Category: Execution
        Path: Users\%user%\Desktop\
        FileMask: 'regex:*.ps1'
EOF
python3 ~/DFIR/scripts/tkape_collect.py --targets "$T" --check work/Broken.tkape; echo "exit code: $?"
```

```
ERROR  missing required field 'RecreateDirectories'
ERROR  Id 1234 is not a GUID
ERROR  entry 1: Path should start with C:\ (got 'Users\\%user%\\Desktop\\')
ERROR  entry 1: FileMask regex does not compile (nothing to repeat at position 0)
Broken.tkape: 1 entries, 4 error(s), 0 warning(s)
exit code: 1
```

(It promised three mistakes and found four: `regex:*.ps1` is a glob written as a regex. The regex you want is `regex:.+\.ps1`, or simply the mask `'*.ps1'`.)

Now run your compound Target, **for alice only**:

```bash
python3 ~/DFIR/scripts/tkape_collect.py --targets "$T" --tsource /mnt/ws-alice --target Day09_Triage \
  --tdest work/tout-alice --tvars user:alice 2>/dev/null
grep -c '\\Users\\bob\\' work/tout-alice/*_CopyLog.csv
cut -d, -f2,4 work/tout-alice/*_CopyLog.csv | grep -i -E 'temp'
```

```
1203 file specifications from 1 Target(s); 35 files queued
Copied 34 files (2912115 bytes), skipped 1 (see SkipLog) -> work/tout-alice
0
C:\Users\alice\AppData\Local\Temp\rc\rc.conf,90
C:\Users\alice\AppData\Local\Temp\rc\rclone.exe,8192
C:\Users\alice\AppData\Local\Temp\rc.zip,2048
```

KapeTriage's 1,200 specifications plus your 3. `%user%` became `alice`, so bob's two hives weren't queued (0 rows) and the renamed config was caught. On Windows the same files work unchanged: copy them to `KAPE\Targets\!Local\` and run `kape.exe --target Day09_Triage --tvars user:alice …`.

### Lab 5: The same job with AChoirX (20 min)

```bash
mkdir -p ~/cases/LAB-009/tools/achoirx && cd ~/cases/LAB-009/tools/achoirx
curl -sSfL -o AChoirX https://raw.githubusercontent.com/OMENScan/AChoirX/master/Lin/AChoirX
sha256sum AChoirX | tee ../../notes/AChoirX.sha256
chmod +x AChoirX
./AChoirX /HELP | head -n 3
```

```
986b392a594f7a7338ece986214807fd18d9f5c47236fff456435cdf9c4b24d3  AChoirX

AChoirX ver: v10.01.85, Argument/Options:
 /Help - This Description
```

(A different hash means a newer build. Record whatever you downloaded.)

Write a collection script. `&VR0` will hold the mount point. Paths use the **real case**, because this mount is case-sensitive:

```bash
cat > Day09.ACQ <<'EOF'
*********************************************************
* Day 09 lab: collect Windows triage artifacts from an  *
* image mounted on Linux/macOS. Mount point = &VR0      *
*********************************************************
ACQ:\
SET:CopyPath=Part
SAY:[+] Collecting from Windows image mounted at: &VR0
CKN:&VR0/Windows/System32/config/SYSTEM
  SAY:[!] No SYSTEM hive under &VR0 - is that the right mount point?
  BYE:
END:
SAY:[+] Registry hives and transaction logs
ACQ:\Reg
CPY:"&VR0/Windows/System32/config/S*" "&Acq"
CPY:"&VR0/Windows/System32/config/DEFAULT*" "&Acq"
CPY:"&VR0/Windows/AppCompat/Programs/Amcache.hve*" "&Acq"
CPY:"&VR0/Users/*/NTUSER.DAT*" "&Acq"
CPY:"&VR0/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat*" "&Acq"
SAY:[+] Event logs
ACQ:\Evt
CPY:"&VR0/Windows/System32/winevt/Logs/*.evtx" "&Acq"
SAY:[+] Evidence of execution, persistence, PowerShell
ACQ:\Prf
CPY:"&VR0/Windows/Prefetch/*.pf" "&Acq"
ACQ:\Sch
CPY:"&VR0/Windows/System32/Tasks/**/*" "&Acq"
ACQ:\Psh
CPY:"&VR0/Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/*" "&Acq"
SAY:[+] NTFS metadata (visible because of show_sys_files)
ACQ:\NTFS
CPY:"&VR0/$MFT" "&Acq"
CPY:"&VR0/$LogFile" "&Acq"
SAY:[+] Hashing everything collected
HSH:ACQ
BYE:
EOF
```

Run it as root (see *Troubleshooting* above for why). The full console output lists every copy with source and destination metadata and MD5s; here we keep only the script's own messages:

```bash
sudo ./AChoirX /INI:Day09.ACQ /VR0:/mnt/ws-alice /NAM:WS-ALICE | grep -E '^\[\+\] (Collecting|Registry hives|Event logs|Evidence|NTFS metadata|Hashing everything|Acquisition Completed)'
sudo chmod -R a+rX ACQ-IR-WS-ALICE-*
find ACQ-IR-WS-ALICE-* -type f | sort
```

```
[+] Collecting from Windows image mounted at: /mnt/ws-alice
[+] Registry hives and transaction logs
[+] Event logs
[+] Evidence of execution, persistence, PowerShell
[+] NTFS metadata (visible because of show_sys_files)
[+] Hashing everything collected
[+] Acquisition Completed: 10/06/2026 - 09:06:41
ACQ-IR-WS-ALICE-20261006-0906/ACQ-IR-WS-ALICE-20261006-0906.Log
ACQ-IR-WS-ALICE-20261006-0906/ACQHash.txt
ACQ-IR-WS-ALICE-20261006-0906/Evt/Microsoft-Windows-PowerShell%4Operational.evtx
ACQ-IR-WS-ALICE-20261006-0906/Evt/Microsoft-Windows-TaskScheduler%4Operational.evtx
ACQ-IR-WS-ALICE-20261006-0906/Evt/Security.evtx
ACQ-IR-WS-ALICE-20261006-0906/Evt/System.evtx
ACQ-IR-WS-ALICE-20261006-0906/Index.htm
ACQ-IR-WS-ALICE-20261006-0906/NTFS/ws-alice/$LogFile
ACQ-IR-WS-ALICE-20261006-0906/NTFS/ws-alice/$MFT
ACQ-IR-WS-ALICE-20261006-0906/Prf/CMD.EXE-0BD30981.pf
ACQ-IR-WS-ALICE-20261006-0906/Prf/POWERSHELL.EXE-CA1AE517.pf
ACQ-IR-WS-ALICE-20261006-0906/Prf/RCLONE.EXE-5F3E1A2B.pf
ACQ-IR-WS-ALICE-20261006-0906/Psh/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt
ACQ-IR-WS-ALICE-20261006-0906/Reg/Amcache.hve
ACQ-IR-WS-ALICE-20261006-0906/Reg/DEFAULT
ACQ-IR-WS-ALICE-20261006-0906/Reg/SAM
ACQ-IR-WS-ALICE-20261006-0906/Reg/SECURITY
ACQ-IR-WS-ALICE-20261006-0906/Reg/SOFTWARE
ACQ-IR-WS-ALICE-20261006-0906/Reg/SOFTWARE.LOG1
ACQ-IR-WS-ALICE-20261006-0906/Reg/SYSTEM
ACQ-IR-WS-ALICE-20261006-0906/Reg/SYSTEM.LOG1
ACQ-IR-WS-ALICE-20261006-0906/Reg/SYSTEM.LOG2
ACQ-IR-WS-ALICE-20261006-0906/Reg/alice/AppData/Local/Microsoft/Windows/UsrClass.dat
ACQ-IR-WS-ALICE-20261006-0906/Reg/alice/NTUSER.DAT
ACQ-IR-WS-ALICE-20261006-0906/Reg/alice/NTUSER.DAT.LOG1
ACQ-IR-WS-ALICE-20261006-0906/Reg/alice/NTUSER.DAT.LOG2
ACQ-IR-WS-ALICE-20261006-0906/Reg/bob/AppData/Local/Microsoft/Windows/UsrClass.dat
ACQ-IR-WS-ALICE-20261006-0906/Reg/bob/NTUSER.DAT
ACQ-IR-WS-ALICE-20261006-0906/Reg/bob/NTUSER.DAT.LOG2
ACQ-IR-WS-ALICE-20261006-0906/Sch/OneDriveUpdate
```

The date and time in the folder name are when *you* ran it. How AChoirX laid things out:

- `SET:CopyPath=Part` kept the path **after the first wildcard**, so `Users/*/NTUSER.DAT*` became `Reg/alice/…` and `Reg/bob/…`. Without it, the two `NTUSER.DAT` files would collide.
- A copy with no wildcard (`$MFT`) keeps the source's parent folder name (`ws-alice`).
- AChoirX **doesn't de-duplicate**: both empty `.LOG2` files are here.

Check its hash list against an independent tool, look at the permissions it left, and test the safety check with a wrong mount point:

```bash
grep 'RCLONE' ACQ-IR-WS-ALICE-*/ACQHash.txt | sed 's|.*/Prf/|Prf/|'
md5sum ACQ-IR-WS-ALICE-*/Prf/RCLONE* | cut -d' ' -f1
ls -ld ACQ-IR-WS-ALICE-*/Prf/RCLONE* | cut -c1-10
sudo ./AChoirX /INI:Day09.ACQ /VR0:/mnt/nothing-here /NAM:WRONG | grep '^\[!\]'
```

```
Prf/RCLONE.EXE-5F3E1A2B.pf - MD5: 6a15ec670ef59eec58f5ee25ba723923
6a15ec670ef59eec58f5ee25ba723923
-r--r--r--
[!] No SYSTEM hive under /mnt/nothing-here - is that the right mount point?
```

The MD5s agree, AChoirX left the artifacts read-only, and the `CKN:` block stopped the run before it collected nothing. (The `ACQ:\` line had already created an `ACQ-IR-WRONG-…` folder holding only a log and an index page; delete it with `sudo rm -r ACQ-IR-WRONG-*` when you're done.)

Compare this script with Lab 4: AChoirX gives you full control and works on any OS, but **you** have to know every path. KAPE Targets carry years of community knowledge about where things live. Many teams use both: Targets as the reference, scripts where KAPE can't run.

### Lab 6: Package, hash and unmount (10 min)

Hand-over package: a SHA-256 manifest of every collected file, then one archive with its own hash.

```bash
cd ~/cases/LAB-009
( cd work/tout && find C -type f -print0 | sort -z | xargs -0 sha256sum ) > notes/WS-ALICE_KapeTriage.sha256
wc -l < notes/WS-ALICE_KapeTriage.sha256
grep -i 'rclone' notes/WS-ALICE_KapeTriage.sha256
tar -C work -czf evidence/WS-ALICE_KapeTriage.tar.gz tout
tar -tzf evidence/WS-ALICE_KapeTriage.tar.gz | wc -l
sha256sum evidence/WS-ALICE_KapeTriage.tar.gz | tee notes/WS-ALICE_KapeTriage.tar.gz.sha256 | cut -c1-16
(cd work/tout && sha256sum -c --quiet ../../notes/WS-ALICE_KapeTriage.sha256) && echo "manifest OK"
sudo umount /mnt/ws-alice
mountpoint -q /mnt/ws-alice || echo "unmounted"
```

```
33
24f3b7c14cc1c1ebbf98c3d3e9060c90cf60b408f69645efc694d7990ec9d538  C/Windows/Prefetch/RCLONE.EXE-5F3E1A2B.pf
70
14a8bad26691b225
manifest OK
unmounted
```

The archive's hash is different on every run (the copy logs inside contain collection times), which is why you record it at hand-over. The per-file manifest is stable, and anyone can re-check every file with it later, as the `sha256sum -c` line just did (`--quiet` prints only failures).

Finish your notes for the case: the tools and their versions (`notes/kapefiles-version.txt`, `notes/AChoirX.sha256`), the Targets you wrote, the command lines, and the times you ran them.

### Optional: on a Windows VM (not run here)

If you have a Windows 10/11 VM that you can break:

1. Run KAPE `--target KapeTriage` against `C:` to a second disk. Open the CopyLog and find the rows with `DeferredCopy = True`. Those are the locked files KAPE read raw.
2. Copy your two `!Local` Targets into `KAPE\Targets\!Local\` and run `Day09_Triage`.
3. Run `AChoirX.exe /RUN` and compare its output folder with KAPE's.
4. Build DFIR ORC, run `Orc.exe /keys`, then collect with a test certificate in `Orc.xml` and confirm the archives can't be opened without the private key.

---

## ✅ Knowledge check

1. Give two reasons to choose triage collection over a full image, and one thing you lose.
2. Why must `NTUSER.DAT` be collected together with `NTUSER.DAT.LOG1` and `.LOG2`?
3. On a live system, a normal copy of `C:\Windows\System32\config\SYSTEM` fails. Why, and how do KAPE, AChoirX and DFIR ORC get around it?
4. In Lab 3, two `NTUSER.DAT.LOG2` files weren't copied. Why, where is the proof they existed, and which switch changes the behaviour?
5. What does `%user%` mean in a Target path, and how do you collect a single user?
6. KapeTriage includes an rclone Target, yet `rc.conf` wasn't collected. Explain, and describe the fix.
7. Your AChoirX script runs perfectly on Windows but finds no Prefetch files on a Linux mount of the same disk. What's the likely cause?
8. What do `Orc.exe /keys` and the `<recipient>` element in `Orc.xml` do, and why does the second matter for a collection written to a network share?

<details>
<summary><b>Answers</b></summary>

1. Speed (minutes instead of hours) and scale (many machines at once); you can also start analysing sooner. You lose everything you didn't decide to collect: unallocated space, other files, and the chance to carve the whole disk later.
2. Windows may not yet have written recent changes into the hive file; they're in the transaction logs. Without the logs, the hive you analyse can be missing the latest (often the most important) changes.
3. The registry hives are open and locked by Windows. The tools read the file's data directly from the NTFS volume instead of through the Windows file API: KAPE does a raw read (`DeferredCopy = True` in the copy log), AChoirX has `NCP:`, and DFIR ORC's tools access the volume device directly.
4. They're empty, so their SHA-1 is the same as `SYSTEM.LOG2`'s, which was already copied, and SHA-1 de-duplication (`--tdd`, on by default) skipped them. The SkipLog lists both paths with the reason `Deduped`. `--tdd false` copies everything.
5. It's a placeholder for each user profile folder (it becomes `*`). `--tvars user:alice` collects only alice's.
6. `RcloneConf.tkape` looks for the file names `rclone.conf` and `.rclone.conf`. The attacker passed a renamed config (`--config ...\rc.conf`), so no name matched. The fix is a case-specific Target (by folder and extension, as in Lab 4), driven by leads from the artifacts you already have (the scheduled task and PowerShell history).
7. Case sensitivity. Windows ignores case, but the Linux mount doesn't, so a path written as `Windows/prefetch` doesn't match the real `Prefetch`. Use the real case, or a character class like `[Pp]refetch`.
8. `/keys` is a dry run that shows which archives and commands would run with the current options. `<recipient>` holds a public certificate; DFIR ORC encrypts the archives to it, so only the holder of the private key can read them. A share may be readable by others (including an attacker on the network), but encrypted archives are useless to them.

</details>

---

## 📚 Further reading

- KAPE documentation (Targets, switches, log files, batch mode, FAQ): https://ericzimmerman.github.io/KapeDocs/ (source: https://github.com/EricZimmerman/KapeDocs)
- KapeFiles: `Targets/TargetGuide.guide` and `CompoundTargetGuide.guide` explain how to write good Targets
- AChoirX: `WhatIsAChoirX.txt` and the `Scripts/` folder in https://github.com/OMENScan/AChoirX
- DFIR ORC documentation, especially the *Tutorial*, *Command-line options* and *Local configuration* pages: https://dfir-orc.github.io
- RFC 3227, *Guidelines for Evidence Collection and Archiving* (order of volatility)
- SANS, *Windows Forensic Analysis* poster: where each artifact lives and what it proves
- NCC Group, *Detecting Rclone: An Effective Tool for Exfiltration* (2021), on today's scenario

---

## ⏭️ Tomorrow: Day 10

**NTFS deep dive: `$MFT`, `$UsnJrnl:$J`, `$LogFile` and `$I30`.** Tools: **MFTECmd**, **NTFS Log Tracker**, **analyzeMFT**.
Today you collected the NTFS metadata files; tomorrow you learn their structure and turn them into a timeline of file creation, renames and deletions, including files that no longer exist.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
