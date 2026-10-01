# Day 03: Storage Media, Partitions (MBR/GPT), Hex & File Signatures

> **Phase 1: Foundations** · **Level:** 🟢 Beginner · **Time:** ~3–4 hours (reading + labs) · **Posted:** 2026-09-30
>
> **Tools today:** 🛠️ HxD · 🛠️ ImHex · 🛠️ TestDisk

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain how HDDs, SSDs and flash media store data, and why SSDs change what you can recover.
2. Convert between sectors, LBAs and byte offsets, and read little-endian values in a hex dump.
3. Decode an **MBR** and a **GPT** partition table by hand, byte by byte.
4. Find the places data can hide outside partitions: gaps, slack, HPA/DCO, deleted partitions.
5. Identify files by their **signatures (magic bytes)** instead of trusting extensions.
6. Install and use **HxD**, **ImHex** and **TestDisk**, and recover a deleted partition.

---

## Part 1: The lesson

### 1.1 Storage media: what's actually on the disk

| Media | How it stores data | Forensic consequences |
|-------|--------------------|-----------------------|
| **HDD** (spinning disk) | Magnetic platters; the OS addresses **sectors** by LBA and the drive maps them to physical locations | Deleted data usually stays until it's overwritten, so carving (Day 7) works well |
| **SSD (SATA/NVMe)** | NAND flash behind a **Flash Translation Layer (FTL)** that remaps blocks for **wear levelling** | When the OS sends **TRIM** for deleted files, the controller may erase those blocks. Deleted data often reads back as zeros within minutes |
| **USB sticks, SD cards** | NAND flash with a simpler controller | TRIM support varies; recovery is often better than on SSDs |
| **eMMC / UFS** (phones, tablets, cheap laptops) | Flash soldered to the board | Usually acquired logically or via the device (Days 39–41) |
| **Optical, tape** | Write-once or sequential media | Rare today, but still found in archives and older cases |

**Sector sizes.** Traditional drives use **512-byte** sectors. Modern drives use 4096-byte physical sectors, either presented as 512-byte logical sectors (**512e**) or natively (**4Kn**). Always check the sector size before you do offset maths:

```bash
sudo blockdev --getss --getpbsz /dev/sdb     # logical and physical sector size
sudo fdisk -l /dev/sdb | head -n 4
```

**SSD reality check.** On a modern SSD with TRIM, "deleted" can mean "gone within minutes". This is also why SSD images must be hashed and preserved immediately (Day 2, §1.7).

### 1.2 Addressing: sectors, LBAs and byte offsets

- A **sector** is the smallest addressable unit on the disk.
- **LBA** (Logical Block Address) numbers sectors from **0**. (Old CHS, cylinder-head-sector, addressing only survives as legacy fields.)
- **Byte offset = LBA × sector size.** With 512-byte sectors, LBA 2048 = byte 1,048,576 = exactly **1 MiB**. That's where the first partition starts on almost every modern disk (1 MiB alignment).
- File systems group sectors into **clusters** (FAT, NTFS) or **blocks** (ext4). You'll meet those on Day 4.

### 1.3 Reading hex

Everything on a disk is bytes, and a **hex editor** shows them as two hexadecimal digits each (00–FF).

```
offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   ASCII
000001b0: .. .. .. .. .. .. .. .. 26 20 1a df 00 00 80 20   ........& ..... 
```

**Endianness.** x86 systems and most on-disk structures (MBR, GPT, FAT, NTFS, ext4) store multi-byte numbers **little-endian**: least significant byte first.

| Bytes on disk | Read as | Value |
|---------------|---------|-------|
| `00 08 00 00` | `0x00000800` | 2048 |
| `00 a0 00 00` | `0x0000a000` | 40960 |
| `00 58 01 00` | `0x00015800` | 88064 |

Network protocols and some formats (PNG, JPEG, JPEG EXIF "MM") are **big-endian**. Always check which one a structure uses.

**Text encodings** you'll see constantly: ASCII/UTF-8 (one byte per Latin character) and **UTF-16LE** (Windows: `E.F.I. .s.y.s.` with a `00` after each ASCII character).

### 1.4 The Master Boot Record (MBR)

The MBR is **sector 0** (512 bytes) of an MBR-partitioned disk:

| Offset | Size | Field |
|-------:|-----:|-------|
| `0x000` | 446 | Boot code (bootstrap loader); a place **bootkits** hide |
| `0x1B8` | 4 | **Disk signature** (Windows uses it to identify disks; useful for matching a disk to registry artifacts) |
| `0x1BC` | 2 | Usually `00 00` |
| `0x1BE` | 16 | **Partition entry 1** |
| `0x1CE` | 16 | Partition entry 2 |
| `0x1DE` | 16 | Partition entry 3 |
| `0x1EE` | 16 | Partition entry 4 |
| `0x1FE` | 2 | **Boot signature `55 AA`** |

**Each 16-byte partition entry:**

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | Boot flag: `0x80` = active/bootable, `0x00` = not |
| 1 | 3 | CHS start (legacy) |
| 4 | 1 | **Partition type** |
| 5 | 3 | CHS end (legacy) |
| 8 | 4 | **Starting LBA** (little-endian) |
| 12 | 4 | **Number of sectors** (little-endian) |

**Common partition type bytes:**

| Type | Meaning |
|------|---------|
| `0x04` / `0x06` / `0x0E` | FAT16 variants |
| `0x07` | NTFS or exFAT (check the boot sector to tell them apart) |
| `0x0B` / `0x0C` | FAT32 (CHS / LBA) |
| `0x05` / `0x0F` | **Extended** partition (contains logical partitions) |
| `0x27` | Windows recovery (hidden NTFS) |
| `0x82` / `0x83` / `0x8E` | Linux swap / Linux / Linux LVM |
| `0xEE` | **GPT protective MBR**: the real table is GPT |

**Extended partitions.** MBR has only four slots. To have more partitions, one slot becomes an *extended* partition. It holds a chain of **Extended Boot Records (EBRs)**, each describing one *logical* partition and pointing to the next EBR. If that chain is broken, logical partitions "disappear", which is a classic job for TestDisk.

**Limits:** 32-bit LBAs mean MBR can address at most **2 TiB** with 512-byte sectors, and only four primary partitions. That's why GPT exists.

### 1.5 The GUID Partition Table (GPT)

```
LBA 0          LBA 1         LBA 2 … 33                         …        last-33 … last-1     last LBA
┌────────────┬─────────────┬──────────────────┬───────────────────────┬──────────────────┬─────────────┐
│ Protective │ GPT header  │ Partition entries│  partitions …         │ Backup partition │ Backup GPT  │
│ MBR (0xEE) │ "EFI PART"  │ 128 × 128 bytes  │                       │ entries          │ header      │
└────────────┴─────────────┴──────────────────┴───────────────────────┴──────────────────┴─────────────┘
```

**GPT header (LBA 1), key fields:**

| Offset | Size | Field |
|-------:|-----:|-------|
| `0x00` | 8 | Signature `EFI PART` |
| `0x08` | 4 | Revision (`00 00 01 00` = 1.0) |
| `0x0C` | 4 | Header size (92) |
| `0x10` | 4 | **CRC32 of the header** (with this field set to zero while calculating) |
| `0x18` | 8 | This header's LBA (1) |
| `0x20` | 8 | **Backup header LBA** (the last sector of the disk) |
| `0x28` / `0x30` | 8 + 8 | First / last usable LBA |
| `0x38` | 16 | **Disk GUID** |
| `0x48` | 8 | Partition entries start LBA (usually 2) |
| `0x50` / `0x54` | 4 + 4 | Number of entries (128) / entry size (128) |
| `0x58` | 4 | CRC32 of the partition entry array |

**Each 128-byte partition entry:** type GUID (16 bytes) · unique partition GUID (16) · first LBA (8) · last LBA (8, *inclusive*) · attribute flags (8) · **name** (72 bytes, UTF-16LE).

**GUIDs are stored "mixed-endian"**: the first three groups are little-endian and the last two are stored as-is. For example, `12345678-9ABC-DEF0-1122-334455667788` is stored on disk as `78 56 34 12 BC 9A F0 DE 11 22 33 44 55 66 77 88`.

**Partition type GUIDs you should recognise:**

| Type GUID | Meaning |
|-----------|---------|
| `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` | EFI System Partition (FAT32; bootloaders live here, and so do bootkits) |
| `E3C9E316-0B5C-4DB8-817D-F92DF00215AE` | Microsoft Reserved (MSR) |
| `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7` | Microsoft basic data (NTFS, exFAT, FAT) |
| `DE94BBA4-06D1-4D40-A16A-BFD50179D6AC` | Windows Recovery Environment |
| `0FC63DAF-8483-4772-8E79-3D69D8477DE4` | Linux filesystem |
| `0657FD6D-A4AB-43C4-84E5-0933C84B4F4F` | Linux swap |
| `E6D6D379-F507-44C2-A23C-238F2A3DF928` | Linux LVM |
| `7C3457EF-0000-11AA-AA11-00306543ECAC` | Apple APFS container |

**Why it matters:** GPT has CRC32 checksums and a **backup header and backup table at the end of the disk**. If the start of a disk is wiped or corrupted, the backup copy often lets you rebuild the whole layout.

### 1.6 Where data hides outside partitions

| Location | What it is | How to check |
|----------|------------|--------------|
| **MBR boot code / post-MBR gap** | Sectors 1–2047 before the first partition, used by bootloaders and **bootkits** | `mmls` shows it as *Unallocated*. Look for non-zero bytes |
| **Unpartitioned space** | Gaps between or after partitions | `mmls` *Unallocated* rows. Examine them with `dd` or a hex editor |
| **Volume slack** | The partition is bigger than the file system inside it | Compare the partition size (`mmls`) with the file-system size (`fsstat`) |
| **Deleted / overwritten partition entries** | The data is still on disk, but no table entry points to it | TestDisk, or a search for boot-sector signatures |
| **HPA** (Host Protected Area) | Sectors hidden from the OS by an ATA command | `sudo hdparm -N /dev/sdX` shows *max sectors* vs *native max* |
| **DCO** (Device Configuration Overlay) | Reduces the drive's reported size | `sudo hdparm --dco-identify /dev/sdX` |
| **GPT backup area** | Can differ from the primary table after tampering | Compare the primary and backup headers and entries |
| **File slack** | The unused end of a file's last cluster | Day 4 |

Good acquisition tools detect and include HPA/DCO areas (Day 5). Always record the drive's native size in your notes.

### 1.7 File signatures (magic numbers)

Extensions are just part of the file name, and anyone can rename a file. The **first bytes of a file** usually identify its real type:

| Type | Offset | Signature (hex) | ASCII |
|------|-------:|-----------------|-------|
| PDF | 0 | `25 50 44 46` | `%PDF` |
| PNG | 0 | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` |
| JPEG | 0 | `FF D8 FF` (ends with `FF D9`) | |
| GIF | 0 | `47 49 46 38 37 61` / `…39 61` | `GIF87a` / `GIF89a` |
| ZIP, DOCX/XLSX/PPTX, JAR, APK | 0 | `50 4B 03 04` | `PK..` |
| Legacy Office (DOC/XLS/PPT), Outlook MSG | 0 | `D0 CF 11 E0 A1 B1 1A E1` | OLE2 compound file |
| RAR / 7-Zip / gzip | 0 | `52 61 72 21 1A 07` / `37 7A BC AF 27 1C` / `1F 8B` | `Rar!` / `7z..` |
| Windows PE (EXE, DLL, SYS) | 0 | `4D 5A` | `MZ` (plus `PE\0\0` at the offset stored in `0x3C`) |
| Linux ELF | 0 | `7F 45 4C 46` | `.ELF` |
| SQLite database | 0 | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | `SQLite format 3.` |
| Windows registry hive | 0 | `72 65 67 66` | `regf` |
| Windows event log (EVTX) | 0 | `45 6C 66 46 69 6C 65 00` | `ElfFile.` |
| EnCase image (E01) | 0 | `45 56 46 09 0D 0A FF 00` | `EVF...` |
| MP4 / MOV / HEIC | **4** | `66 74 79 70` | `ftyp` |
| NTFS volume boot record | **3** | `4E 54 46 53 20 20 20 20` | `NTFS    ` |
| FAT volume boot record | 0 / 510 | jump `EB xx 90` … `55 AA` | |
| ext2/3/4 superblock | 1024 + `0x38` | `53 EF` | magic `0xEF53` |

**In an investigation:**

- A mismatch between signature and extension (`invoice.pdf` that's really a PNG, or `readme.txt` that's really an executable) is a classic sign of hiding or of malware.
- Container formats (DOCX, XLSX, APK, JAR) are **ZIP files**. To know what's *inside*, you have to open the container.
- Encrypted or compressed data has no recognisable structure and looks random. High entropy (close to 8 bits per byte) is itself a clue.
- Signatures also drive **file carving** (Day 7): searching raw sectors for headers and footers.

**Built-in tools:**

```bash
file suspicious.bin              # libmagic identification
xxd -l 32 suspicious.bin         # first 32 bytes in hex
hexdump -C -n 64 suspicious.bin
```

On Windows, PowerShell can do the same:

```powershell
Format-Hex -Path .\suspicious.bin -Count 32      # PowerShell 7+ (in Windows PowerShell 5.1, pipe through Select-Object -First 3)
```

---

## Part 2: Tools

---

### 🛠️ Tool 1: HxD

| | |
|---|---|
| **What** | A fast, free hex editor for Windows that also opens **physical and logical disks** and **process memory** (RAM). It has a data inspector, search, file compare and checksums |
| **Why in DFIR** | Quick, reliable byte-level inspection on a Windows analysis VM: read partition tables, check signatures, jump to sectors, compare two files, and hash selected ranges |
| **Platforms** | Windows (7 to 11, 32/64-bit). Installer and portable editions |
| **Licence** | Freeware (by Maël Hörz) |
| **Home** | https://mh-nexus.de/en/hxd/ |

#### Installation

1. Download the **installable** or **portable** edition from https://mh-nexus.de/en/hxd/ (choose your language).
2. Record the download's hash in your tool log: `Get-FileHash .\HxDSetup.zip -Algorithm SHA256` (use your actual file name).
3. Either run the installer, or extract the portable edition to `C:\Tools\HxD`.

**Package managers** (community-maintained; confirm the package ID first):

```powershell
winget search HxD
winget install --id MHNexus.HxD -e      # if the ID above matches
# or: choco install hxd
```

#### Configuration

- **Tools → Options:** set *bytes per row* (16 is standard), the offset base (hexadecimal) and the character set (Windows/ANSI). Consider turning off automatic backups for evidence work, since you shouldn't be saving anyway.
- **Data inspector** (the panel on the right): shows the bytes at the cursor as Int8/16/32/64, little- or big-endian, FILETIME, DOS date/time, GUID and more. It does the endianness maths for you.
- **Evidence safety:**
  - Open disks with **Tools → Open disk…** and keep **"Open as Readonly"** ticked (it's the default). Opening physical disks needs an elevated (admin) HxD.
  - For image files, make the file read-only at the OS level first (`attrib +R C:\Cases\LAB-003\evidence\disk.img`), and use HxD's read-only mode.
- **Sector view:** when you open a disk or disk image (**Tools → Open disk image…**, sector size 512), HxD separates sectors visually, and **Search → Go to** (Ctrl+G) accepts sector numbers as well as offsets.

#### Verify the installation

Create a file containing `abc` (as on Day 2) and open it in HxD. You should see `61 62 63`. Then run **Analysis → Checksums → SHA-256** on it: the result should be `BA7816BF…15AD`.

#### First use: decode a partition entry

1. **Tools → Open disk image…**, pick `disk-mbr.img` from Lab 1 (see Part 3) and set the sector size to 512.
2. **Search → Go to** → offset `1BE` (hex).
3. Select 16 bytes and read them with the data inspector: byte 0 (boot flag), byte 4 (type), then put the cursor on byte 8 and read **UInt32 (little-endian)**. That's the starting LBA.
4. **Search → Go to** → sector `2048`. You're now at the first byte of partition 1 (its volume boot record).

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| Physical disks aren't listed in *Open disk* | Run HxD as Administrator |
| You changed a byte by accident | Close **without saving**. Afterwards, verify the evidence hash (Day 2) |
| Numbers look wrong | Check the data inspector's byte order setting (little- vs big-endian) |

---

### 🛠️ Tool 2: ImHex

| | |
|---|---|
| **What** | A modern, open-source hex editor for reverse engineers and forensic analysts. Its **pattern language** (`.hexpat`) decodes binary structures and highlights them, and it has a data inspector, bookmarks, entropy and byte-distribution graphs, hashing, diffing, YARA scanning and a disassembler |
| **Why in DFIR** | Load a pattern and ImHex colours and names every field of an MBR, GPT, FAT, NTFS, PE or PNG structure. That's ideal for learning structures and for checking your manual decoding. Entropy graphs show encrypted or compressed regions at a glance |
| **Platforms** | Windows, macOS, Linux |
| **Licence** | GPL-2.0 |
| **Home** | https://github.com/WerWolv/ImHex · https://imhex.werwolv.net · patterns: https://github.com/WerWolv/ImHex-Patterns |

#### Requirements

ImHex uses GPU rendering (OpenGL). In virtual machines without 3D acceleration, download the **"NoGPU"** build from the releases page. It's made for exactly this situation.

#### Installation

Official releases: https://github.com/WerWolv/ImHex/releases/latest

**Windows:**

```powershell
winget install WerWolv.ImHex
# or: choco install imhex
# or: download the installer (.msi) or the portable .zip from the releases page
```

**macOS:** download the `.dmg` from the releases page and drag ImHex to *Applications* (you may need to allow it under *System Settings → Privacy & Security*).

**Linux (SIFT / Ubuntu):**

```bash
# Option A: Flatpak (works on any distro)
sudo apt install -y flatpak
flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install -y flathub net.werwolv.ImHex
flatpak run net.werwolv.ImHex

# Option B: the Ubuntu .deb from the releases page (pick the one matching your Ubuntu version)
sudo apt install ./imhex-*.deb

# Option C: AppImage
chmod +x imhex-*.AppImage && ./imhex-*.AppImage
```

Other options from the official install guide: Fedora `sudo dnf install imhex`, Arch AUR `yay -S imhex-bin`.

#### Configuration

- **Patterns:** ImHex ships with the community **ImHex-Patterns** library. When you open a file, it offers patterns that match the detected type. Useful ones for today:
  - `fs/pattern.hexpat` (*Drive File System*): MBR/GPT and FAT/exFAT/NTFS partitions
  - `DFIR/DISK_PARSER.hexpat`: recursive disk, volume and file-system parser from the DFIR collection
  - `png.hexpat`, `pe.hexpat`, `zip.hexpat` for file formats

  If a pattern isn't offered automatically, load it from the **Pattern Editor** view. You can update or download extra patterns and themes through ImHex's built-in **Content Store**. (Menu names can differ slightly between versions.)
- **Settings:** set the byte row width, the default endianness in the Data Inspector, and the theme.
- **Evidence safety:** open image files read-only. Set the file read-only at the OS level too (`chmod 444 image.img`), and never save back to evidence.
- **Raw disks:** ImHex can open raw disks and process memory as data sources (under *File → Open Other…* in current versions). On Linux, run it with the privileges needed to read `/dev/sdX`, or better, work on an image.

#### Verify the installation

Open any PNG file. ImHex should detect `image/png` and offer the **PNG** pattern. After you accept it, the header, `IHDR`, `IDAT` and `IEND` chunks are highlighted and named in the Pattern Data view.

#### First use

1. Open `disk-gpt.img` (Lab 2). Accept or load `fs/pattern.hexpat`.
2. Expand the pattern tree: protective MBR → GPT header → partition entries. Compare each field with your manual decoding.
3. Open the **Information** view and run the analysis. The entropy graph shows long flat zero regions (empty space) and any high-entropy blocks.

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| Black or garbled window in a VM | Use the **NoGPU** build, or enable 3D acceleration for the VM |
| No pattern offered | Load it manually in the Pattern Editor, or get the latest patterns from the Content Store |
| Pattern errors on a disk image | Some DFIR patterns are marked partially working (ext4, APFS). Cross-check with TSK (`mmls`, `fsstat`) |

---

### 🛠️ Tool 3: TestDisk

| | |
|---|---|
| **What** | An open-source partition-recovery tool by Christophe Grenier (CGSecurity). It analyses and rebuilds MBR, EBR and GPT partition tables, finds lost partitions by scanning for file-system signatures, repairs FAT/NTFS boot sectors from backups, lists and undeletes files (FAT, exFAT, NTFS, ext2), and can create a disk image |
| **Why in DFIR** | Recover partitions that were deleted or wiped (by accident or as anti-forensics), and show where they were, with a log you can put in your notes. Its companion **PhotoRec** is a file carver (Day 7) |
| **Platforms** | Linux, Windows, macOS, BSD. Text (ncurses) interface |
| **Licence** | GPL-2.0-or-later |
| **Home** | https://www.cgsecurity.org/wiki/TestDisk · downloads: https://www.cgsecurity.org/wiki/TestDisk_Download |

> ⚠️ **Forensic rule:** TestDisk **writes** to the disk or image you give it when you choose *Write*. Never run it in write mode on evidence. Work on a **copy** of the image, and hash both the original and the copy (Day 2).

#### Installation

**SIFT / Ubuntu / Debian:**

```bash
sudo apt update && sudo apt install -y testdisk      # installs testdisk and photorec
testdisk /version
```

Ubuntu 24.04 packages **TestDisk 7.1**, built **without libewf** (`ewf lib: none` in `testdisk /version`), so it can't open E01 files directly. Mount the E01 as a raw image first (Day 6), or use the upstream build, which is newer (7.2 at the time of writing).

**Windows:**

1. Download the Windows 64-bit zip from https://www.cgsecurity.org/wiki/TestDisk_Download.
2. Extract it to `C:\Tools\testdisk`.
3. Run `testdisk_win.exe` **as Administrator** to access physical disks. (`photorec_win.exe` and the GUI `qphotorec_win.exe` are included.)

**macOS:**

```bash
brew install testdisk
sudo testdisk            # raw disk access needs sudo; disk images don't
```

#### Configuration

TestDisk is configured through its menus and a few command-line options:

| Option / menu | Purpose |
|---------------|---------|
| `testdisk /log image.dd` | Writes **`testdisk.log`** to the current directory. Always use it: it's your record of what TestDisk found and did |
| `testdisk /list image.dd` | Prints the current partition table and exits (read-only) |
| `testdisk /debug` | More detail in the log |
| **Options** menu | *Expert mode* (manual editing of partition fields), cylinder-boundary alignment, *Dump* (show sector contents) |
| **Geometry** menu | Change the CHS geometry or sector size (for example, 4096 for 4Kn disks) |
| **Advanced** menu | Per-partition tools: *Boot* (rebuild or restore a FAT/NTFS boot sector from its backup), *List/Undelete* files, *Image Creation* |

In the partition list after a search, these keys matter:

| Key | Action |
|-----|--------|
| ↑ / ↓ | Select a partition |
| ← / → | Change its status: `*` primary bootable, `P` primary, `L` logical, `E` extended, `D` deleted (not written) |
| `P` | **List files** in the selected partition. Use this to confirm it's the right one before writing anything |
| `A` / `T` | Add a partition manually / change its type |
| Enter | Continue to the *Quit / Return / Deeper Search / Write* menu |

#### Verify the installation

```bash
testdisk /version | head -n 6         # shows the version and the libraries it was built with (ext2fs, ntfs, ewf)
testdisk /list disk-mbr.img           # after Lab 1: should list PART1 (FAT16) and PART2 (Linux)
```

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| No disks listed | Run with `sudo` (Linux/macOS) or as Administrator (Windows), or pass an image file path |
| "Partition table type" guess is wrong | Choose **Intel** for MBR, **EFI GPT** for GPT. Never pick *None* for a normal disk |
| Quick Search misses a partition | Use **Deeper Search** (slower; scans every cylinder or sector) |
| Warnings about geometry mismatch | Common with images and USB media. Recovery usually still works; check the found partitions with `P` (list files) |
| Can't open an `.E01` | The build lacks libewf. Use `ewfmount` (Day 6) or the upstream build |

---

## Part 3: Hands-on labs

All the labs run on **SIFT** or any Ubuntu with these packages:

```bash
sudo apt install -y fdisk gdisk dosfstools mtools e2fsprogs testdisk sleuthkit xxd file
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR   # for scripts/parttable.py and scripts/sigcheck.py
```

### Lab 1: Build an MBR disk and decode it by hand (25 min)

```bash
mkdir -p ~/cases/LAB-003/{evidence,work,notes,output} && cd ~/cases/LAB-003/evidence

# A 64 MiB "disk" with two primary partitions: FAT16 (bootable) and Linux
truncate -s 64M disk-mbr.img
printf 'label: dos\nlabel-id: 0xdf1a2026\nstart=2048, size=40960, type=6, bootable\nstart=43008, size=88064, type=83\n' \
  | sfdisk -q disk-mbr.img

# Create file systems inside the partitions (the offsets are in sectors for FAT, bytes for ext4)
mkfs.vfat -F 16 --offset=2048 -h 2048 -n PART1 disk-mbr.img 20480 >/dev/null 2>&1
mkfs.ext4 -q -F -L PART2 -E offset=$((43008*512)) disk-mbr.img 44032k

# Put a file into partition 1 (mtools can address a partition at an offset: @@1M)
printf 'Q3 bonus list - CONFIDENTIAL\n' > /tmp/bonus.txt
mcopy -i disk-mbr.img@@1M /tmp/bonus.txt ::/

sha256sum disk-mbr.img | tee ../notes/disk-mbr.img.sha256
chmod 444 disk-mbr.img
```

**Read the partition table bytes:**

```bash
xxd -s 0x1b8 -l 72 disk-mbr.img
```

Expected output:

```
000001b8: 2620 1adf 0000 8020 2100 06ac 2a02 0008  & ..... !...*...
000001c8: 0000 00a0 0000 00ac 2b02 8328 2008 00a8  ........+..( ...
000001d8: 0000 0058 0100 0000 0000 0000 0000 0000  ...X............
000001e8: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001f8: 0000 0000 0000 55aa                      ......U.
```

**Decode it yourself before reading on:**

| Field | Bytes | Value |
|-------|-------|-------|
| Disk signature (`0x1B8`) | `26 20 1a df` | `0xdf1a2026` (little-endian) |
| Entry 1 boot flag (`0x1BE`) | `80` | Active / bootable |
| Entry 1 type (`0x1C2`) | `06` | FAT16 |
| Entry 1 start LBA (`0x1C6`) | `00 08 00 00` | 2048, so byte offset 1,048,576 |
| Entry 1 sectors (`0x1CA`) | `00 a0 00 00` | 40960 (20 MiB) |
| Entry 2 type (`0x1D2`) | `83` | Linux |
| Entry 2 start LBA (`0x1D6`) | `00 a8 00 00` | 43008 |
| Entry 2 sectors (`0x1DA`) | `00 58 01 00` | 88064 |
| Boot signature (`0x1FE`) | `55 aa` | Valid |

**Check your work with three independent tools:**

```bash
mmls disk-mbr.img                                  # The Sleuth Kit
python3 ~/DFIR/scripts/parttable.py disk-mbr.img   # this repo's decoder
testdisk /list disk-mbr.img | tail -n 5            # TestDisk (read-only)
```

Expected `parttable.py` output:

```
Disk signature: 0xdf1a2026
MBR #1: boot=0x80 type=0x06 (FAT16) start LBA=2048 sectors=40960 -> byte offset 1048576
MBR #2: boot=0x00 type=0x83 (Linux) start LBA=43008 sectors=88064 -> byte offset 22020096
```

**Look at the first sector of each partition:**

```bash
xxd -s $((2048*512)) -l 64 disk-mbr.img            # FAT16 volume boot record
xxd -s $((2048*512+510)) -l 2 disk-mbr.img         # -> 55aa
xxd -s $((43008*512+1024+0x38)) -l 2 disk-mbr.img  # ext4 superblock magic -> 53ef (0xEF53 little-endian)
```

The FAT boot record starts with `eb3c 90` (a jump instruction), then the OEM name `mkfs.fat`, and further on the label `PART1` and `FAT16   `. (The 4-byte volume serial number before the label differs on every run.)

### Lab 2: Decode a GPT disk (20 min)

```bash
cd ~/cases/LAB-003/evidence
truncate -s 64M disk-gpt.img
printf 'label: gpt\nlabel-id: 12345678-9ABC-DEF0-1122-334455667788\nstart=2048, size=40960, type=U, name="EFI system", uuid=AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\nstart=43008, type=L, name="Linux data", uuid=0F0F0F0F-1E1E-2D2D-3C3C-4B4B4B4B4B4B\n' \
  | sfdisk -q disk-gpt.img
chmod 444 disk-gpt.img

xxd -s 446 -l 16 disk-gpt.img          # protective MBR entry: type 0xEE
xxd -s 512 -l 92 disk-gpt.img          # GPT header (LBA 1)
xxd -s 1024 -l 128 disk-gpt.img        # first partition entry (LBA 2)
```

Expected GPT header:

```
00000200: 4546 4920 5041 5254 0000 0100 5c00 0000  EFI PART....\...
00000210: 4b74 d83b 0000 0000 0100 0000 0000 0000  Kt.;............
00000220: ffff 0100 0000 0000 0008 0000 0000 0000  ................
00000230: deff 0100 0000 0000 7856 3412 bc9a f0de  ........xV4.....
00000240: 1122 3344 5566 7788 0200 0000 0000 0000  ."3DUfw.........
00000250: 8000 0000 8000 0000 148c e9ec            ............
```

Find these fields in the dump:

- **Signature** `EFI PART`, **revision** `0x00010000`, **header size** `0x5c` = 92.
- **Backup header LBA** at `0x220`: `ff ff 01 00 …` = `0x1FFFF` = 131071, the last sector of a 64 MiB disk.
- **Disk GUID** at `0x238`: `78 56 34 12 bc 9a f0 de 11 22 33 44 55 66 77 88`. That's `12345678-9ABC-DEF0-1122-334455667788` in **mixed-endian** form.
- **Entries** start at LBA 2 (`0x248`), 128 entries × 128 bytes (`0x250`, `0x254`).

The first partition entry starts with `28 73 2a c1 1f f8 d2 11 ba 4b 00 a0 c9 3e c9 3b`: the **EFI System** type GUID `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` in mixed-endian form. At offset `0x38` inside the entry, the name `E.F.I. .s.y.s.t.e.m.` is in UTF-16LE.

```bash
python3 ~/DFIR/scripts/parttable.py disk-gpt.img
xxd -s $(( (131072-1)*512 )) -l 16 disk-gpt.img   # backup header at the last LBA: also "EFI PART"
mmls disk-gpt.img
```

Expected `parttable.py` output (it also checks the header CRC32):

```
Disk signature: 0x00000000
MBR #1: boot=0x00 type=0xee (GPT protective) start LBA=1 sectors=131071 -> byte offset 512
GPT header: signature=b'EFI PART' revision=0x00010000 size=92 crc32=0x3bd8744b (OK)
  this LBA=1 backup LBA=131071 usable LBAs 2048-131038
  disk GUID=12345678-9abc-def0-1122-334455667788 entries at LBA 2: 128 x 128 bytes
GPT #1: 'EFI system' type=EFI System LBA 2048-43007 unique GUID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
GPT #2: 'Linux data' type=Linux filesystem LBA 43008-129023 unique GUID=0f0f0f0f-1e1e-2d2d-3c3c-4b4b4b4b4b4b
```

`mmls` also shows **1,024 KiB unallocated after the last partition** (sectors 129024–131071), which includes the backup GPT. That's a gap worth checking in real cases.

> 💡 In this image the first usable LBA is 2048 because `sfdisk` reserves space for alignment. Many tools use 34 (1 protective MBR + 1 header + 32 entry sectors).

### Lab 3: Recover a deleted partition table with TestDisk (20 min)

Simulate a suspect wiping the partition table to hide the data:

```bash
cd ~/cases/LAB-003
cp evidence/disk-mbr.img work/disk-wiped.img && chmod 644 work/disk-wiped.img   # always work on a COPY
dd if=/dev/zero of=work/disk-wiped.img bs=1 seek=446 count=64 conv=notrunc status=none   # zero all 4 entries
xxd -s 446 -l 66 work/disk-wiped.img     # entries are all zeros; 55aa is still there
mmls work/disk-wiped.img; echo "mmls exit code: $?"   # prints nothing and returns 1: no partitions
```

The data is all still there. Only the "map" is gone. Now recover it:

```bash
cd ~/cases/LAB-003/work
testdisk /log disk-wiped.img
```

Follow the menus:

1. Select `disk-wiped.img` → **[Proceed]**.
2. Partition table type: **[Intel]** (TestDisk detects it).
3. **[Analyse]**. *Current partition structure* is empty.
4. **[Quick Search]**. TestDisk finds:
   ```
   * FAT16 <32M      0  32 33     2 172 42      40960 [PART1]
   P Linux           2 172 43     8  40 32      88064 [PART2]
   ```
5. With PART1 selected, press **`P`** to list its files. You should see `BONUS.TXT`. Press `q` to go back.
6. Press **Enter**, then use → to select **[ Write ]** and press Enter. Answer **Y** to *"Write partition table, confirm ? (Y/N)"*, then **[Ok]** and **[Quit]** out of the menus.

Verify the recovery:

```bash
mmls disk-wiped.img
fls -o 2048 disk-wiped.img            # bonus.txt is back
python3 ~/DFIR/scripts/parttable.py disk-wiped.img
cmp -l disk-wiped.img ../evidence/disk-mbr.img
```

Expected `cmp` output: exactly **one** differing byte:

```
451   4   6
```

`cmp` counts bytes from 1, so this is offset **0x1C2**: the partition **type** of entry 1. TestDisk wrote `0x04` ("FAT16 <32M", chosen from the file-system size) where the original had `0x06`. The start, size and all the data are identical.

**Lessons:**

- A recovered structure is a **reconstruction**, not the original. Record exactly what the tool changed; `testdisk.log` is part of your notes.
- This is why you never run recovery tools on the evidence itself: the image's hash changed.

### Lab 4: Catch files with the wrong extension (15 min)

```bash
mkdir -p ~/cases/LAB-003/work/sigs && cd ~/cases/LAB-003/work/sigs
python3 - <<'EOF'
import zlib, struct, zipfile, sqlite3, shutil
def png(path):   # a valid 1x1 PNG
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    open(path, "wb").write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
                           + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))
png("holiday.png")
png("invoice.pdf")                                                        # PNG disguised as PDF
open("report.pdf", "wb").write(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")
with zipfile.ZipFile("notes.docx", "w") as z: z.writestr("word/document.xml", "<w:document/>")
with zipfile.ZipFile("budget.xlsx.txt", "w") as z: z.writestr("secret.txt", "exfil list")   # ZIP disguised as TXT
con = sqlite3.connect("contacts.db"); con.execute("create table c(name)"); con.commit(); con.close()
shutil.copy("/bin/true", "readme.txt")                                    # ELF executable disguised as TXT
EOF

file *
python3 ~/DFIR/scripts/sigcheck.py .
```

Expected `sigcheck.py` output:

```
MISMATCH  ./budget.xlsx.txt  ->  ZIP container
ok        ./contacts.db  ->  SQLite database
ok        ./holiday.png  ->  PNG image
MISMATCH  ./invoice.pdf  ->  PNG image
ok        ./notes.docx  ->  ZIP container
MISMATCH  ./readme.txt  ->  ELF executable
ok        ./report.pdf  ->  PDF document
```

Now open `invoice.pdf` in **HxD** or **ImHex**. The first 8 bytes are `89 50 4E 47 0D 0A 1A 0A`, and ImHex offers the **PNG** pattern despite the `.pdf` name.

**Think about it:** `notes.docx` is "ok" as a ZIP container, but a ZIP signature alone doesn't prove it's a *Word document*. Open it and check that it contains `word/document.xml` (`unzip -l notes.docx`).

### Lab 5: The same structures in HxD and ImHex (15 min)

Copy `disk-mbr.img` and `disk-gpt.img` to your Windows VM (or use ImHex on SIFT):

1. **HxD:** open `disk-mbr.img` → Ctrl+G → offset `1C6` → read the start LBA in the data inspector (UInt32 LE = 2048). Then Ctrl+G → sector `2048` and find `FAT16` in the boot sector.
2. **ImHex:** open `disk-gpt.img` and load `fs/pattern.hexpat` (or `DFIR/DISK_PARSER.hexpat`). Find the GPT header and the two partition entries in the pattern tree, and compare the disk GUID with your manual decoding from Lab 2.
3. **ImHex:** run the **Information** analysis on `disk-mbr.img`. Where is the data? (Near 1 MiB and at the start of partition 2; everything else is zeros.)

Record in your notes which tool showed what, including tool versions.

---

## ✅ Knowledge check

1. What's the byte offset of LBA 43008 on a disk with 512-byte sectors? And with 4096-byte sectors?
2. Decode this MBR partition entry: `00 20 21 00 07 fe ff ff 00 08 00 00 00 f8 ff 03`.
3. Why can't an MBR disk use more than 2 TiB (with 512-byte sectors)?
4. The first sectors of a GPT disk are wiped. What structure might still let you rebuild the partition layout, and where is it?
5. Write the type GUID `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7` as it appears on disk.
6. Name four places data can hide on a disk outside the partitions' file systems.
7. A file called `holiday.jpg` starts with `4D 5A`. What is it, and why does it matter?
8. After TestDisk recovered the partitions in Lab 3, the image hash changed. Why, and what should your notes say?

<details>
<summary><b>Answers</b></summary>

1. 43008 × 512 = **22,020,096** bytes. With 4096-byte sectors, 43008 × 4096 = **176,160,768** bytes. Always confirm the sector size first.
2. Not bootable (`00`), type `0x07` (NTFS or exFAT), start LBA `00 08 00 00` = **2048**, sectors `00 f8 ff 03` = `0x03FFF800` = **67,106,816** sectors (≈ 32 GiB).
3. The start LBA and sector count are 32-bit fields: at most 2³² sectors × 512 bytes = 2 TiB.
4. The **backup GPT header** at the **last LBA** of the disk, and the backup partition-entry array just before it.
5. `A2 A0 D0 EB E5 B9 33 44 87 C0 68 B6 B7 26 99 C7`. The first three groups are little-endian; the last two are stored as written.
6. Any four of: MBR boot code or the post-MBR gap, unpartitioned space between or after partitions, volume slack, deleted partitions, HPA, DCO, the GPT backup area, file slack.
7. `MZ` is a **Windows executable (PE)** disguised as an image. It could be malware, or a tool the suspect hid. Flag it, hash it, and analyse it safely (Days 42–43).
8. Writing the table changed the image (here, one type byte at `0x1C2`). The notes should say it was done on a **working copy**, give the tool and version, what was written (attach `testdisk.log`), and the before and after hashes. The original evidence stays untouched.

</details>

---

## 📚 Further reading

- Brian Carrier, *File System Forensic Analysis*, chapters 4–6 (volume analysis, PC-based partitions, server partitions)
- UEFI Specification, *GUID Partition Table (GPT) Disk Layout* chapter: https://uefi.org/specifications
- Gary Kessler, *File Signatures Table*: https://www.garykessler.net/library/file_sigs.html
- Wikipedia's *List of file signatures* and *GUID Partition Table* articles (good quick references)
- CGSecurity, *TestDisk Step By Step*: https://www.cgsecurity.org/wiki/TestDisk_Step_By_Step
- ImHex pattern language documentation: https://docs.werwolv.net/pattern-language
- Bell & Boddington, *Solid State Drives: The Beginning of the End for Current Practice in Digital Forensic Recovery?* (2010), on SSD self-erasure

---

## ⏭️ Tomorrow: Day 04

**File system fundamentals: FAT/exFAT, NTFS, ext4, APFS and timestamps (MACB)**. Tools: **The Sleuth Kit**, **Autopsy**, **fatcat**.
We'll go inside the partitions you built today: directory entries, the MFT, inodes, clusters, slack space and the four timestamps that drive every timeline.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
