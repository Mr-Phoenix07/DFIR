# Day 07: Data Recovery & File Carving

> **Phase 1: Foundations** · **Level:** 🟡 Intermediate · **Time:** ~3–4 hours (reading + labs) · **Posted:** 2026-10-04
>
> **Tools today:** 🛠️ PhotoRec · 🛠️ Foremost · 🛠️ Scalpel

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain when to use **file-system-based recovery** and when to use **file carving**, and what evidence you lose with carving.
2. Describe the main carving techniques: **header/footer, header + size, structure-aware validation**, and why **fragmentation** defeats them.
3. Recognise and reduce **false positives and duplicates** (embedded headers, carving allocated space).
4. Carve a quick-formatted drive with **PhotoRec**, **Foremost** and **Scalpel**, and verify the results against known hashes.
5. Carve **only unallocated space** and map every hit back to its location on the disk.
6. Rebuild a **fragmented** file by hand when every carver fails.

---

## Part 1: The lesson

### 1.1 Two ways to get deleted data back

| | **File-system-based recovery** (Day 4) | **File carving** (today) |
|---|---|---|
| Uses | Leftover metadata: FAT `0xE5` entries, unallocated MFT records, inodes | Only the **content**: known byte patterns (signatures) and file structure |
| Works when | The metadata still exists | Metadata is gone: formatted, re-partitioned, ext4 deletes, corrupted file systems, unallocated space, memory dumps, pagefiles |
| You get | **Name, path, timestamps, size**, and all fragments (the metadata says where they are) | The **data only**. Names become offsets (`f0004067.jpg`), with no original path or timestamps |
| Fragmented files | ✅ handled | ❌ usually truncated or corrupt |

**Always try file-system-based recovery first** (TSK `fls -d`, `tsk_recover`, Autopsy). Carve afterwards, ideally only the **unallocated** space so you don't re-carve files you already have.

> ⚖️ **Evidence value:** a carved file proves that *this content existed on the medium at this offset*. On its own it doesn't prove who created it, when, or what it was called. Corroborate with other artifacts, and report it accurately ("recovered by carving from unallocated space at byte offset 2,082,304").

### 1.2 What happens on deletion and formatting

- **Delete:** metadata is marked free. The content stays until it's overwritten (Day 4, §1.7).
- **Quick format:** writes a new, empty file system structure: boot sector, an empty FAT/MFT, an empty root directory. **Most data clusters are untouched**, so carving works well. (That's today's lab.)
- **Full format:** on modern Windows (Vista and later), a full format **writes zeros** over the volume, so there's nothing left to carve.
- **SSD + TRIM:** freed blocks may read back as zeros almost immediately (Day 3).
- **Wiping tools:** zeros or patterns overwrite the data, so nothing is recoverable (but the wipe itself is evidence: Day 12, Day 54).

### 1.3 Carving techniques

| Technique | How it works | Strengths | Weaknesses |
|-----------|--------------|-----------|------------|
| **Header / footer** | Find the start signature, carve until the end signature: JPEG `FF D8 FF` … `FF D9`, PNG `89 50 4E 47` … `IEND`, PDF `%PDF-` … `%%EOF` | Simple and fast | Fragmentation; embedded footers (a JPEG thumbnail's `FF D9` inside a photo) truncate the file |
| **Header + maximum size** | Carve a fixed maximum number of bytes after the header | Works when there's no footer | Produces oversized files containing junk from other files |
| **Header + embedded length** | Read the size from the file's own header (BMP, RIFF/AVI/WAV, PNG chunk lengths, ZIP central directory) | Exact sizes | Needs format knowledge for each type |
| **Structure-aware validation** | Parse the file while carving, and reject or fix files that break the format (PhotoRec) | Fewer false positives; finds the right end even without a footer | Slower; corrupt but valuable files may be rejected (check the logs) |
| **Fragment recovery** | Bifragment gap carving, SmartCarving, statistical classification of clusters | Can rebuild fragmented files | Research-grade; only some tools, some file types |
| **Record carving** | Carve *records* rather than files: EVTX records, SQLite rows, MFT entries, `$I30` entries, browser history | Recovers activity data from fragments | Format-specific tools (Days 41, 54) |

### 1.4 Fragmentation: the carver's enemy

File systems try to store files contiguously, but they can't always:

- Free space is in pieces, the disk is nearly full, or a file grows over time (logs, mailboxes, databases).
- Simson Garfinkel's 2007 study found that most files on real drives were contiguous, but a significant share were fragmented. Fragmentation was much more common for **large and frequently appended files** (PST/OST mailboxes, logs, databases, videos).
- Fragments can even be **out of order**: the second part of a file may sit *before* the first part on the disk.

In Lab 2 you'll build exactly that: a JPEG whose first 17 clusters are at the **end** of the disk and whose last 8 clusters are near the **start**. All three carvers fail on it, and you'll rebuild it by hand in Lab 6.

**After carving, always validate:**

| Type | Validation |
|------|------------|
| JPEG | `djpeg file.jpg > /dev/null` (libjpeg-turbo-progs), or open it in a viewer |
| PNG | `pngcheck file.png` (checks every chunk CRC) |
| ZIP / DOCX / XLSX | `unzip -t file.zip` |
| PDF | `pdfinfo file.pdf` (poppler-utils) |
| Anything | Hash it and compare with known files (`sha256deep -m`, Day 2) |

### 1.5 False positives and duplicates

| Cause | Example | Mitigation |
|-------|---------|------------|
| **Embedded headers** | Each file inside a ZIP/DOCX starts with `PK\x03\x04`; JPEG EXIF thumbnails start with `FF D8` | Structure-aware carvers; dedupe by hash; check carved offsets that fall inside other carved files |
| **Carving allocated space** | Every existing file is "recovered" again | Carve **unallocated** only (`blkls`, Lab 7), or dedupe against the allocated files' hashes |
| **Same content, many copies** | Browser caches, thumbnails, backups | Dedupe by hash; keep the offset list |
| **Signature only** | Random bytes that happen to match `FF D8 FF` | Validation; minimum-size rules |

**Cluster alignment:** files on a file system start at a cluster boundary. Carving only headers that are cluster-aligned (Scalpel `-q`, Foremost `-q` for sectors) removes most embedded-header false positives. But it **misses** files embedded in other files, in slack, in memory dumps, and inside archives. Choose deliberately, and document the choice.

### 1.6 A carving workflow

```
 image (verified) ─▶ FS-based recovery first (fls -d, tsk_recover)
                 └─▶ extract unallocated:  blkls -o OFFSET image > unalloc.bin
                         └─▶ carve (PhotoRec + one other carver for cross-checking)
                                 └─▶ hash every result → dedupe → NSRL/known-good filter → known-bad match (Day 2)
                                         └─▶ validate (djpeg/pngcheck/unzip -t/pdfinfo)
                                                 └─▶ map offsets back to the image (blkcalc) → report
```

### 1.7 Legal and ethical notes

- Carving recovers **everything**, including personal data unrelated to the case. Stay within your scope and minimise what you review.
- If you encounter **illegal content** (e.g., child sexual abuse material), **stop**, don't copy or view further, and follow your legal escalation procedure. In many jurisdictions, continuing without authority is itself an offence.

---

## Part 2: Tools

---

### 🛠️ Tool 1: PhotoRec

| | |
|---|---|
| **What** | CGSecurity's signature- and structure-based carver, the companion of TestDisk (Day 3). It recognises **hundreds of file formats**, validates their structure while carving, ignores the file system (it reads it only to learn the block size and, optionally, to restrict the search to free space), and writes a **DFXML `report.xml`** |
| **Why in DFIR** | Excellent recovery rates with few false positives. Free, scriptable, and cross-platform; there's also a GUI (QPhotoRec) |
| **Platforms** | Linux, Windows, macOS, BSD |
| **Licence** | GPL-2.0-or-later |
| **Home** | https://www.cgsecurity.org/wiki/PhotoRec · downloads: https://www.cgsecurity.org/wiki/TestDisk_Download |

#### Installation

PhotoRec is part of the **testdisk** package:

```bash
# SIFT / Ubuntu / Debian
sudo apt update && sudo apt install -y testdisk
photorec /version | head -n 1         # Ubuntu 24.04: PhotoRec 7.1

# macOS
brew install testdisk
```

**Windows:**

1. Download the 64-bit TestDisk & PhotoRec zip from the CGSecurity download page.
2. Extract it to `C:\Tools\testdisk`.
3. Run `photorec_win.exe` (text interface) or `qphotorec_win.exe` (GUI) **as Administrator** for physical drives.

#### Configuration

**Interactive menus** (`photorec image.raw`):

| Menu | Choices |
|------|---------|
| **Disk / partition** | Pick the image, then a partition or *No partition / Whole disk* |
| **[File Opt]** | Enable or disable individual file families (`s` toggles all). Fewer types = faster and less noise |
| **[Options]** | **Paranoid** = Yes (default: validate files) · *Brute force* (try harder on fragmented JPEGs; slow) · **Keep corrupted files** (keep partial files: useful in investigations) · *Expert mode* · *Low memory* |
| **[Search]** | File system family (*ext2/ext3/ext4* or *Other*) and **Free** (unallocated only) vs **Whole** (the entire partition) |
| Destination | A directory **on a different disk** from the source. Output goes to `recup_dir.1`, `recup_dir.2`, … (500 files each) |

**Scripted mode** (repeatable, so it belongs in your notes). The syntax was checked against PhotoRec 7.1 in Lab 3:

```bash
mkdir -p out    # the parent of the /d prefix must exist
photorec /log /d out/recup /cmd image.raw \
  partition_none,options,keep_corrupted_file,fileopt,everything,disable,jpg,enable,png,enable,pdf,enable,zip,enable,search
```

| Part | Meaning |
|------|---------|
| `/log` | Writes **`photorec.log`** to the current directory |
| `/d out/recup` | Output prefix, so results go to `out/recup.1/` |
| `partition_none` | Treat the image as one area (or give a partition number) |
| `options,keep_corrupted_file` | Keep partial files |
| `fileopt,everything,disable,jpg,enable,…` | Disable all types, then enable the ones listed |
| `search` | Start |

**Output naming:**

- `f<sector>.<ext>`: a file that starts at that **sector** (relative to the searched area).
- `b<sector>.<ext>`: a "broken" (fragmented or corrupt) file.
- `report.xml`: DFXML with the image offset and length of every carved file (`<byte_run img_offset=… len=…>`).

#### Verify the installation

```bash
photorec /version | head -n 3
```

Then run Lab 3. Four files should be recovered, and their hashes must match the originals.

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Cannot create file …: No such file or directory` | The parent directory of the `/d` prefix doesn't exist. Run `mkdir` first |
| `File too small (…), reject it` in the log | Usually a **fragmented** file: PhotoRec found the header but the structure ends early. Note the sector and consider manual reconstruction (Lab 6) |
| Thousands of tiny `.txt` files | Text detection is enabled. Disable `txt` in **[File Opt]** unless you need it |
| Output on the same disk as the source | Never do this with live media: you'd overwrite what you're recovering |

---

### 🛠️ Tool 2: Foremost

| | |
|---|---|
| **What** | A classic header/footer carver, originally written at the US Air Force Office of Special Investigations by Jesse Kornblum, Kris Kendall and Nick Mikus. It has built-in carving logic for common types (including **OOXML/ODF detection** inside ZIPs) and writes an **`audit.txt`** report |
| **Why in DFIR** | Fast, simple and predictable. A good second opinion next to PhotoRec, and its audit file lists every hit with its offset |
| **Platforms** | Linux, macOS (Windows via WSL) |
| **Licence** | Public domain (US Government work) |
| **Home** | https://foremost.sourceforge.net |

#### Installation

```bash
# SIFT / Ubuntu / Debian
sudo apt update && sudo apt install -y foremost
foremost -V | head -n 1          # Ubuntu 24.04: 1.5.7

# macOS
brew install foremost
```

#### Configuration: the options that matter

| Option | Meaning |
|--------|---------|
| `-t jpg,png,pdf,zip` | Built-in types to carve (`all` for everything built in: jpg, gif, png, bmp, avi, exe, mpg, wav, riff, wmv, mov, pdf, ole, doc, zip, rar, htm, cpp) |
| `-c file.conf` | Use a config file for extra types (`/etc/foremost.conf` ships with every rule commented out) |
| `-i image` / `-o dir` | Input / output (the output directory must not exist, or must be empty) |
| `-q` | **Quick mode**: only check for headers at 512-byte boundaries |
| `-Q` / `-v` | Quiet / verbose |
| `-a` | Write all headers and do no error detection (more partial files, more false positives) |
| `-w` | Audit only: list hits without writing files |
| `-d` | Indirect-block detection (ext2/3) |
| `-b` / `-k` / `-s` / `-T` | Block size / chunk size / skip blocks / timestamped output directory (see the foremost documentation) |

**Output:** one sub-directory per type (`jpg/`, `png/`, `docx/` …) and `audit.txt`. File names are the **offset in 512-byte blocks**, e.g. `00004067.jpg` starts at byte 4067 × 512 = 2,082,304.

#### Verify the installation

Run `foremost -V`, then Lab 4. Four files should be carved, and `docx/` should exist (Foremost recognised the ZIP as a Word document).

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ERROR: … is not empty` | Use a new `-o` directory each run |
| Binary garbage printed on screen | Foremost echoes some ZIP internals. Use `-Q`, or redirect stdout, and read `audit.txt` |
| A type you need isn't built in | Add a rule to a copy of `/etc/foremost.conf` and run with `-c` |

---

### 🛠️ Tool 3: Scalpel

| | |
|---|---|
| **What** | A fast, configurable header/footer carver by Golden G. Richard III, based on Foremost 0.69. It uses a two-pass design (index all headers and footers, then carve) and fully configurable rules (`FORWARD_NEXT`, `REVERSE`, `NEXT`, maximum sizes, wildcards) |
| **Why in DFIR** | You control exactly what is carved. That's ideal for unusual formats, proprietary file types and custom signatures (e.g., a malware config header) |
| **Platforms** | Linux, macOS (Windows via WSL) |
| **Licence** | GPL-2.0-or-later (per the Debian/Ubuntu package) |
| **Home** | https://github.com/sleuthkit/scalpel |

#### Installation

```bash
# SIFT / Ubuntu / Debian
sudo apt update && sudo apt install -y scalpel
scalpel -V | head -n 1          # Ubuntu 24.04: Scalpel version 1.60

# macOS: there's no Homebrew formula; build from source following the README at
# https://github.com/sleuthkit/scalpel (autotools), or run it in a Linux VM or container
```

#### Configuration: rules are everything

`/etc/scalpel/scalpel.conf` ships with **every rule commented out**, so Scalpel carves nothing until you enable rules. Write a small, explicit config for each job:

```
# ext  case  max_size  header                    footer                     [keyword]
jpg    y     200000    \xff\xd8\xff\xe0??JFIF    \xff\xd9
png    y     200000    \x89PNG\x0d\x0a\x1a\x0a   IEND\xae\x42\x60\x82
pdf    y     500000    %PDF-                     %%EOF\x0a
zip    y     500000    PK\x03\x04                PK\x05\x06??????????????????
```

| Element | Meaning |
|---------|---------|
| `\xNN`, `?` | A hex byte; `?` is a single-byte wildcard |
| *(no keyword)* = `FORWARD_NEXT` | Carve from the header to the **first** footer after it (footer included) |
| `REVERSE` | Carve to the **last** footer within `max_size` (the stock JPEG and PDF rules use it, which can swallow neighbouring files) |
| `NEXT` | Carve up to (but not including) the next footer, e.g. the next header of the same type |
| `max_size` | Carve at most this many bytes. Keep it realistic to limit junk |

**Command-line options** (from `scalpel -h`):

| Option | Meaning |
|--------|---------|
| `-c conf` / `-o dir` | Config file / output directory |
| `-q <clustersize>` | Carve only **cluster-aligned** headers (removes embedded-header false positives) |
| `-b` | Carve even without a footer (up to `max_size`) |
| `-p` | Preview: audit only, write nothing |
| `-O` | Don't organise output into per-type sub-directories |
| `-r` | Find only the first of overlapping headers and footers |
| `-v` | Verbose |

#### Verify the installation

`scalpel -V`, then Lab 5. Six files are carved: four genuine, plus two false positives explained in the lab.

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `files carved = 0` with the default config | Every rule in `/etc/scalpel/scalpel.conf` is commented out. Use your own config |
| Huge carved files full of junk | `REVERSE` rules or a large `max_size`. Use `FORWARD_NEXT` and a realistic size |
| Many overlapping ZIP/Office carves | Embedded `PK\x03\x04` headers. Try `-q <clustersize>` and dedupe by hash |

---

## Part 3: Hands-on labs

Run these on **SIFT** or Ubuntu. Set the VM to **UTC** so all the hashes match.

```bash
sudo apt install -y testdisk foremost scalpel sleuthkit dosfstools mtools hashdeep libjpeg-turbo-progs pngcheck
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-007/{evidence,originals,carved,notes,work} && cd ~/cases/LAB-007
export TZ=UTC
```

### Lab 1: Ground truth: the files we'll try to recover (5 min)

```bash
cd ~/cases/LAB-007
python3 ~/DFIR/scripts/mk_carving_samples.py originals
(cd originals && sha256sum *) | tee notes/originals.sha256
```

Expected output:

```
cd3a76ab13042856c1fb405d8fd7ad1d19421fdf86344f0ca88aa95a66a4052d  diagram.png
e43de8072208e47788184faca7ed51506d9df54ac957e3f9b32849f9719cb1b1  notes.docx
e6f74799709bd61cdd246815292c259454d229d4384a89b865aed86c9d0e71da  photo.jpg
4ed50a4b04bed7e2894ff74e251703c03a2e0fadcb0a1596e0494dc131d442ae  report.pdf
589cb2e59aac9efb8cbefe5a064a701cfb8f5ccaf21a6a2165dac38f8b787481  vacation.jpg
```

The script (standard library only) writes a valid JPEG, PNG, PDF and DOCX. `vacation.jpg` will be **fragmented** on purpose.

### Lab 2: Build a USB stick, fragment a file, then quick-format it (15 min)

```bash
cd ~/cases/LAB-007/evidence
truncate -s 64M usb.raw
printf 'label: dos\nlabel-id: 0x7c0ffee7\nstart=2048, type=c\n' | sfdisk -q usb.raw
mkfs.vfat -F 32 --invariant -i 2026CA7E --offset=2048 -h 2048 -n EVIDENCE usb.raw 64512 >/dev/null 2>&1
I="-i usb.raw@@1M"
O=~/cases/LAB-007/originals
touch -d "2026-09-30 17:45:10 UTC" $O/*
mcopy -m $I $O/photo.jpg $O/diagram.png $O/report.pdf $O/notes.docx ::/

# Create a gap, fill the rest of the disk, then write vacation.jpg: it must split across the gap
head -c 4096 /dev/zero | tr '\0' 'A' > /tmp/filler1.bin
head -c 8192 /dev/zero | tr '\0' 'B' > /tmp/filler2.bin
touch -d "2026-09-30 17:45:10 UTC" /tmp/filler1.bin /tmp/filler2.bin
mcopy -m $I /tmp/filler1.bin /tmp/filler2.bin ::/
mdel $I ::/filler1.bin                                            # 8-cluster gap
FREE=$(mdir $I ::/ | awk '/bytes free/{gsub(/ /,""); sub(/bytesfree/,""); print}')
head -c $(( FREE - 25*512 )) /dev/zero | tr '\0' 'C' > /tmp/filler3.bin    # leave 17 clusters free at the end
touch -d "2026-09-30 17:45:10 UTC" /tmp/filler3.bin
mcopy -m $I /tmp/filler3.bin ::/
mcopy -m $I $O/vacation.jpg ::/                                   # 25 clusters: 17 at the end + 8 in the gap

N=$(fls -o 2048 usb.raw | awk '/vacation/{print $2}' | tr -d ':')
istat -o 2048 usb.raw "$N" | sed -n '/^Sectors:/,$p' | tr '\n' ' '; echo
```

Expected output (sector numbers within the volume):

```
Sectors: 129007 129008 … 129023 2061 2062 2063 2064 2065 2066 2067 2068
```

**Out-of-order fragmentation:** the first 17 clusters are at the end of the volume, and the last 8 are near the start.

Now the "suspect" **quick-formats** the stick:

```bash
mkfs.vfat -F 32 --invariant -i 2026CA7E --offset=2048 -h 2048 -n EVIDENCE usb.raw 64512 >/dev/null 2>&1
fls -r -o 2048 usb.raw          # only the volume label is left, and fls -d finds nothing
sha256sum usb.raw | tee ../notes/usb.raw.sha256
chmod 444 usb.raw
```

Expected SHA-256 of the formatted image:

```
7d93d28d1498ad833f31b05f1fb0a68830ba46fac93062cccaeb1841f07399a6  usb.raw
```

### Lab 3: Carve with PhotoRec (10 min)

```bash
cd ~/cases/LAB-007/carved && mkdir -p photorec
photorec /log /d photorec/recup /cmd ../evidence/usb.raw \
  partition_none,options,keep_corrupted_file,fileopt,everything,disable,jpg,enable,png,enable,pdf,enable,zip,enable,search
ls photorec/recup.1/
sed -n '/^Pass 2/,$p' photorec.log
sha256deep -r -l -w -m ../notes/originals.sha256 photorec
```

Expected output:

```
f0004067.jpg  f0004080.png  f0004105.pdf  f0004107.docx  report.xml

Pass 2 (blocksize=512) STATUS_EXT2_OFF_SAVE_EVERYTHING
photorec/recup.1/b0131055.jpg File too small ( 8704 < 9272), reject it
...
jpg: 1/2 recovered
pdf: 1/1 recovered
png: 1/1 recovered
zip: 1/1 recovered
Total: 4 files found

photorec/recup.1/f0004105.pdf matched report.pdf
photorec/recup.1/f0004067.jpg matched photo.jpg
photorec/recup.1/f0004080.png matched diagram.png
photorec/recup.1/f0004107.docx matched notes.docx
```

- (The order of `sha256deep`'s "matched" lines can vary between runs; it's multi-threaded.)
- **Four exact recoveries.** The hashes prove they're bit-identical to the originals. PhotoRec even named the ZIP `.docx`.
- `b0131055.jpg … reject it`: PhotoRec **found the fragmented `vacation.jpg`** at sector 131,055 (2048 + 129,007, the end of the disk), but only 17 sectors (8,704 bytes) were left before the end of the disk, so it rejected the file. **Read your logs**: that line is the lead you'll follow in Lab 6.
- `report.xml` (DFXML) records each file's image offset, e.g. `<byte_run offset='0' img_offset='2082304' len='6656'/>` for `f0004067.jpg`.

### Lab 4: Carve with Foremost (5 min)

```bash
cd ~/cases/LAB-007/carved
foremost -q -t jpg,png,pdf,zip -i ../evidence/usb.raw -o foremost > /dev/null 2>&1
sed -n '/^Num/,/^Finish/p' foremost/audit.txt
sha256deep -r -l -w -m ../notes/originals.sha256 foremost
```

Expected output:

```
Num	 Name (bs=512)	       Size	 File Offset	 Comment

0:	00004067.jpg 	       6 KB 	    2082304
1:	00004080.png 	      12 KB 	    2088960 	  (64 x 64)
2:	00004105.pdf 	      612 B 	    2101760
3:	00004107.docx 	      893 B 	    2102784
Finish: …

foremost/png/00004080.png matched diagram.png
foremost/docx/00004107.docx matched notes.docx
foremost/pdf/00004105.pdf matched report.pdf
foremost/jpg/00004067.jpg matched photo.jpg
```

The same four files at the **same offsets** as PhotoRec, so two independent tools corroborate each other. `vacation.jpg` doesn't appear at all: Foremost found its header but no footer before the end of the disk.

### Lab 5: Carve with Scalpel, and meet false positives (10 min)

```bash
cd ~/cases/LAB-007/carved
cat > ../notes/lab.scalpel.conf <<'EOF'
# ext   case  max_size  header                      footer
jpg     y     200000    \xff\xd8\xff\xe0??JFIF      \xff\xd9
png     y     200000    \x89PNG\x0d\x0a\x1a\x0a     IEND\xae\x42\x60\x82
pdf     y     500000    %PDF-                       %%EOF\x0a
zip     y     500000    PK\x03\x04                  PK\x05\x06??????????????????
EOF
scalpel -c ../notes/lab.scalpel.conf -o scalpel ../evidence/usb.raw > /dev/null 2>&1
sed -n '/^File/,/^$/p' scalpel/audit.txt
sha256deep -r -l -x ../notes/originals.sha256 scalpel | grep -v audit.txt      # carved files that match NO original
```

Expected output:

```
File		  Start			Chop		Length		Extracted From
00000005.zip      2103260		NO              417		usb.raw
00000004.zip      2103057		NO              620		usb.raw
00000003.zip      2102784		NO              893		usb.raw
00000002.pdf      2101760		NO              612		usb.raw
00000001.png      2088960		NO            12420		usb.raw
00000000.jpg      2082304		NO             6327		usb.raw

scalpel/zip-3-0/00000004.zip
scalpel/zip-3-0/00000005.zip
```

`00000004.zip` and `00000005.zip` are **false positives**. They start *inside* `notes.docx` (offsets 2,103,057 and 2,103,260 are within 2,102,784 + 893): they're the DOCX's second and third internal entries, each beginning with `PK\x03\x04`. Now restrict carving to cluster-aligned headers:

```bash
scalpel -q 512 -c ../notes/lab.scalpel.conf -o scalpel-aligned ../evidence/usb.raw > /dev/null 2>&1
find scalpel-aligned -type f ! -name audit.txt | sort
```

Expected output: only the four genuine files (`00000000.jpg`, `00000001.png`, `00000002.pdf`, `00000003.zip`). The price: anything embedded or unaligned (e.g., a JPEG inside a document) would be missed too.

### Lab 6: Rebuild the fragmented file by hand (20 min)

Every carver failed on `vacation.jpg`. PhotoRec's log gave the lead: a JPEG header at **sector 131055** with only 17 sectors before the end of the disk.

**1. Look at the clue inside the file.** The JPEG contains numbered comment blocks. Find all of them on the disk:

```bash
cd ~/cases/LAB-007/work
LC_ALL=C grep -abo "vacation photo 00[0-9][0-9]" ../evidence/usb.raw | awk -F: '{printf "%s  byte %s  sector %d\n",$2,$1,$1/512}'
```

Expected output:

```
vacation photo 0009  byte 2104380  sector 4110
vacation photo 0010  byte 2105408  sector 4112
vacation photo 0011  byte 2106436  sector 4114
vacation photo 0000  byte 67100184  sector 131055
...
vacation photo 0008  byte 67108408  sector 131071
```

Blocks `0000`–`0008` are at the very end of the disk. `0009`–`0011` continue near sector 4110. The second fragment therefore starts in the cluster just before it: block `0008` began in the last sector and needs 568 more bytes, which puts the start at sector 4109.

**2. Join the fragments and cut at the JPEG end marker:**

```bash
dd if=../evidence/usb.raw bs=512 skip=131055 count=17 status=none >  joined.bin   # fragment 1: to end of disk
dd if=../evidence/usb.raw bs=512 skip=4109   count=16 status=none >> joined.bin   # fragment 2 (+ some spare)
END=$(python3 -c "d=open('joined.bin','rb').read(); print(d.find(b'\xff\xd9') + 2)")
head -c "$END" joined.bin > vacation_rebuilt.jpg
djpeg vacation_rebuilt.jpg > /dev/null && echo "decodes OK"
sha256sum vacation_rebuilt.jpg
```

Expected output:

```
decodes OK
589cb2e59aac9efb8cbefe5a064a701cfb8f5ccaf21a6a2165dac38f8b787481  vacation_rebuilt.jpg
```

That's identical to the original `vacation.jpg` (Lab 1). In real cases you rarely have such convenient clues, but the method is the same: **find the header, work out where the content breaks, look for the continuation by structure or content, and prove the result by validating it.** Document every offset you used.

(Why Python and not `grep -P '\xff\xd9'`? In a UTF-8 locale, GNU grep can silently fail to match raw bytes like `\xff`. Use `LC_ALL=C` or a small script for binary searches.)

### Lab 7: Carve only unallocated space and map hits back (10 min)

On a real disk, carve the **unallocated** space so allocated files aren't recovered twice:

```bash
cd ~/cases/LAB-007/work
blkls -o 2048 ../evidence/usb.raw > unalloc.bin              # all unallocated FS blocks, concatenated
ls -l unalloc.bin
foremost -q -t jpg -i unalloc.bin -o fm-unalloc > /dev/null 2>&1
sed -n '/^Num/,/^Finish/p' fm-unalloc/audit.txt               # -> 00000000.jpg at offset 0
blkcalc -o 2048 -u 0 ../evidence/usb.raw                      # unalloc unit 0 -> FS block
```

Expected output:

```
-rw-r--r-- 1 … 65026560 … unalloc.bin
0:	00000000.jpg 	       6 KB 	          0
2019
```

Offsets in `unalloc.bin` are **not** disk offsets. `blkcalc -u` converts an unallocated-unit number (offset ÷ block size) into the real file-system block: **2019**. Add the partition start: 2048 + 2019 = **sector 4067**, exactly where PhotoRec and Foremost found `photo.jpg` (`f0004067.jpg`, `00004067.jpg`). Always report the **image** offset, not the offset in a derived file.

---

## ✅ Knowledge check

1. What evidence do you lose when you recover a file by carving instead of through the file system?
2. Why does a Windows full format usually defeat carving, but a quick format doesn't?
3. Explain `FORWARD_NEXT` vs `REVERSE` in Scalpel, and why the stock JPEG rule can produce oversized files.
4. Scalpel carved two extra ZIPs from inside `notes.docx`. Why? Give two ways to reduce such false positives, and the cost of one of them.
5. In PhotoRec's naming, what do `f0004067.jpg` and `b0131055.jpg` tell you?
6. Why carve `blkls` output instead of the whole image, and what must you do before reporting an offset found in `unalloc.bin`?
7. A carved PNG opens with a grey bottom half. What happened, and how would you confirm it?
8. During carving you find what appears to be illegal content. What do you do?

<details>
<summary><b>Answers</b></summary>

1. The original **file name, path and timestamps** (and often its exact size and owner). You get content plus an offset, so other artifacts are needed to show who, when and what it was called.
2. A full format on modern Windows writes zeros over the volume. A quick format only writes new, empty file-system structures and leaves the data clusters untouched.
3. `FORWARD_NEXT` carves from the header to the **first** footer that follows. `REVERSE` carves to the **last** footer within `max_size`. With JPEGs, `REVERSE` and a 5 MB maximum can run past the real end and include the following files' data.
4. Each entry inside a ZIP/DOCX starts with `PK\x03\x04`, so every inner entry looks like a new ZIP. Mitigations: cluster-aligned carving (`-q`), structure-aware carvers (PhotoRec), and deduplication or hash comparison. Cost of `-q`: you miss files embedded in other files, slack or memory, which are never cluster-aligned.
5. `f0004067.jpg`: a complete file starting at sector 4067 of the searched area. `b0131055.jpg`: a broken (fragmented or corrupt) candidate at sector 131055. Check the log for whether it was kept or rejected.
6. To avoid re-carving allocated files (duplicates and noise). Convert `unalloc.bin` offsets to real file-system blocks with `blkcalc -u` (then add the partition offset) before reporting.
7. It's probably **fragmented**: the data after the first fragment came from unrelated clusters, and the decoder filled the rest with grey. Confirm with `pngcheck` (CRC errors) and by comparing its length with the structure. Then look for the continuation (Lab 6 method).
8. Stop. Don't view, copy or distribute it further. Preserve what you have, and escalate immediately according to your legal procedure and jurisdiction.

</details>

---

## 📚 Further reading

- Simson Garfinkel, *Carving contiguous and fragmented files with fast object validation* (DFRWS 2007), the classic fragmentation study
- Pal & Memon, *The evolution of file carving* (IEEE Signal Processing Magazine, 2009)
- CGSecurity, *PhotoRec Step By Step* and the *Scripted run* documentation: https://www.cgsecurity.org/wiki/PhotoRec
- Scalpel README and `scalpel.conf` comments: https://github.com/sleuthkit/scalpel
- DFRWS 2006/2007 carving challenges (test images with known answers): https://dfrws.org
- NIST CFTT *Forensic File Carving Tool* test reports

---

## ⏭️ Tomorrow: Day 08

**Metadata, file-type identification & bulk feature extraction**. Tools: **ExifTool**, **TrID**, **bulk_extractor**.
We'll pull EXIF, GPS and document metadata out of recovered files, identify unknown file types, and sweep entire images for emails, URLs, credit-card numbers and more, without any file system at all.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
