# Day 08: Metadata, File-Type Identification & Bulk Feature Extraction

> **Phase 1: Foundations** · **Level:** 🟡 Intermediate · **Time:** ~3–4 hours (reading + labs) · **Posted:** 2026-10-05
>
> **Tools today:** 🛠️ ExifTool · 🛠️ TrID · 🛠️ bulk_extractor

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain the difference between **file-system metadata** and **embedded (application) metadata**, and what each can prove.
2. Extract and interpret **EXIF/GPS**, **Office (OOXML)** and **PDF** metadata with **ExifTool**, including how easily it can be forged, and how forgery can leave traces.
3. Identify unknown files by content with **TrID**, `file` and **Magika**, and recognise when identification tools disagree or are wrong.
4. Run **bulk_extractor** across a whole disk image to find emails, URLs, phone numbers, card numbers, EXIF and more, **without a file system**, including data that's deleted, compressed or base64-encoded.
5. Read bulk_extractor's **forensic paths** and **histograms**, and map a hit back to the file it came from.

---

## Part 1: The lesson

### 1.1 Two kinds of metadata

| | **File-system metadata** (Day 4) | **Embedded / application metadata** (today) |
|---|---|---|
| Where | MFT, inodes, FAT directory entries | **Inside** the file: EXIF in JPEGs, `docProps/*.xml` in DOCX, the PDF Info dictionary and XMP |
| Examples | MACB timestamps, size, owner | Camera make/model/serial, GPS, author, last-modified-by, editing time, software, template, printer, revision |
| Travels with the file? | ❌ It changes when the file is copied, emailed or downloaded | ✅ It survives copying, email, USB, cloud sync (unless stripped) |
| Written by | The OS | The application that created or edited the file |

**Why embedded metadata matters:** a photo emailed three times has new file-system timestamps at every hop, but its EXIF `DateTimeOriginal` and camera serial number stay the same. That's often what links a file to a **device** and a **person**.

### 1.2 Images: EXIF, GPS, XMP, IPTC

| Group | Key tags | What it can show |
|-------|----------|------------------|
| EXIF IFD0 | `Make`, `Model`, `Software`, `Artist`, `ModifyDate` | Device and editing software (`Adobe Photoshop …` = edited) |
| EXIF SubIFD | `DateTimeOriginal`, `CreateDate`, `OffsetTimeOriginal`, `SerialNumber` / `BodySerialNumber`, `LensModel` | **When** it was taken (camera clock!), on **which** device |
| GPS IFD | `GPSLatitude`/`Ref`, `GPSLongitude`/`Ref`, `GPSAltitude`, `GPSTimeStamp`, `GPSDateStamp` | **Where** it was taken. GPS time is UTC from the satellites |
| Thumbnail | `ThumbnailImage` | A preview that may **still show the original** after the main image was cropped or edited |
| XMP / IPTC | Creator, rights, keywords, edit history | Editing workflow (Adobe tools write rich XMP history) |
| MakerNotes | Vendor-specific: shutter count, internal serials | Linking photos to one specific camera |

**Time traps:**

- `DateTimeOriginal` has **no time zone** unless `OffsetTimeOriginal` (EXIF 2.31+) is present. It's the camera's clock, which may be wrong.
- Compare it with `GPSDateStamp`/`GPSTimeStamp` (UTC) to estimate clock offset and time zone.

**Privacy and OPSEC:** many social networks strip EXIF on upload, but messaging apps, email attachments and cloud links often keep it. That's evidence for you, and a risk for anyone who shares photos.

### 1.3 Documents: OOXML (DOCX/XLSX/PPTX) and PDF

**OOXML** files are ZIP containers (Day 3). The metadata lives in:

| File inside the ZIP | Tags | Value |
|---------------------|------|-------|
| `docProps/core.xml` | `dc:creator`, `cp:lastModifiedBy`, `dcterms:created`, `dcterms:modified`, `cp:revision`, `dc:title` | **Who** created and last edited it, and **when** (UTC, written by the application) |
| `docProps/app.xml` | `Application`, `AppVersion`, `Company`, `Template`, `TotalTime` (minutes of editing), page/word counts | The organisation's Office installation, the template, how long it was edited |
| `docProps/custom.xml` | Custom properties | Document-management IDs, classification labels |
| `word/settings.xml` | `w:rsid` values | Edit-session identifiers. Matching RSIDs across documents suggest a common origin |

**PDF** has two places for metadata:

- The **Info dictionary**: `/Title /Author /Creator /Producer /CreationDate /ModDate`. `Creator` is the authoring application; `Producer` is the PDF engine, e.g. "Microsoft: Print To PDF".
- **XMP** metadata streams, which can disagree with the Info dictionary. That disagreement is itself a clue.

PDF supports **incremental updates**: edits are *appended*, and the old objects stay in the file. Earlier versions of the metadata, or of the content, may still be inside. You'll see this in Lab 3.

### 1.4 Metadata is evidence, not proof

Anyone can edit metadata. ExifTool, the very tool used to read it, can write any value (you'll do it in Lab 1). Treat metadata as a **claim to corroborate**:

| Check | Example |
|-------|---------|
| Internal consistency | `ModifyDate` earlier than `DateTimeOriginal`? A `Software` value the claimed camera can't produce? |
| Cross-format consistency | PDF Info vs XMP; EXIF vs XMP; thumbnail vs main image |
| External consistency | GPS vs the person's phone location data; author name vs the user account that saved it (Day 13: LNK/Jump Lists) |
| Traces of editing | Incremental PDF updates, Photoshop `Software`, `_original` backup files left by ExifTool, missing MakerNotes |

### 1.5 File-type identification

You've used magic bytes (Day 3). Real investigations add:

| Approach | Tool | Strengths | Weaknesses |
|----------|------|-----------|------------|
| Magic rules (libmagic) | `file` | On every Linux; fast | Only knows the formats in its rules |
| Statistical byte-pattern definitions | **TrID** (~thousands of definitions, community-contributed) | Very broad coverage, ranked guesses with percentages, good for obscure and proprietary formats | Probabilistic; the definitions must be kept up to date |
| Machine learning | **Magika** (Google) | Good on text-like formats (code, configs, scripts), where magic rules fail | Can be confidently **wrong** (Lab 4), and it's a model, not a specification |
| Format registries | Siegfried (PRONOM) | Archival-grade, versioned identification | Less focused on security artifacts |

**Rule:** when tools disagree, **look at the bytes** (Day 3) and try to open or parse the file with its real application.

### 1.6 Bulk feature extraction

**bulk_extractor** (Simson Garfinkel) ignores the file system completely. It reads every byte of an image (or file, or directory) in parallel **pages**, and runs **scanners** that:

1. **Find features**: emails, URLs, domains, IPs, phone numbers, payment card numbers, EXIF, JSON, Windows artifacts (PE headers, LNK, Prefetch, MFT, EVTX, USN records), network packets and more.
2. **Decode and recurse**: when a scanner finds compressed or encoded data (ZIP, GZIP, RAR, base64, PDF text, hibernation files…), it decodes it and **runs every scanner again on the result**.

That's why it finds evidence in **deleted, unallocated, compressed and encoded** data that a file-system view never shows.

**Feature files** are tab-separated:

```
offset-or-forensic-path   feature   context
2083328-ZIP-61            dropbox.owner@example.net   …t/drop and tell dropbox.owner@example.net…
```

- **Forensic path** `2083328-ZIP-61`: at byte **2,083,328** of the image there's a ZIP. Inside its **decompressed** data, the feature is at offset **61**. Paths can chain, e.g. `2085578-ZIP-0-MSXML-24` (ZIP → Office XML text → offset 24) or `…-BASE64-25`.
- **Histograms** (`email_histogram.txt`, `url_histogram.txt` …) count how often each feature occurs. The most frequent emails usually belong to the device owner.
- `report.xml` (DFXML) records the run: version, scanners, timing, and every option. Keep it with your notes.

---

## Part 2: Tools

---

### 🛠️ Tool 1: ExifTool

| | |
|---|---|
| **What** | Phil Harvey's Perl library and command-line tool for **reading, writing and editing metadata** in a huge range of file types: images (EXIF, GPS, XMP, IPTC, MakerNotes), video, audio, PDF, Office documents and more |
| **Why in DFIR** | The reference tool for embedded metadata. Bulk CSV/JSON export, consistent tag names, raw values, and the ability to extract embedded thumbnails and previews |
| **Platforms** | Windows, macOS, Linux (any OS with Perl; stand-alone Windows executable) |
| **Licence** | Perl Artistic License / GPL (same terms as Perl) |
| **Home** | https://exiftool.org · https://github.com/exiftool/exiftool |

#### Installation

```bash
# SIFT / Ubuntu / Debian (Ubuntu 24.04 packages 12.76; exiftool.org has newer 13.x releases)
sudo apt update && sudo apt install -y libimage-exiftool-perl
exiftool -ver

# macOS
brew install exiftool

# Any Unix, latest version from source (per the README):
#   download Image-ExifTool-<VER>.tar.gz from https://exiftool.org, then
#   perl Makefile.PL && make && make test && sudo make install
```

**Windows** (from the official install instructions):

1. Download the 64-bit **Windows Executable** zip from https://exiftool.org.
2. Extract it to `C:\Tools\exiftool`.
3. Rename **`exiftool(-k).exe`** to **`exiftool.exe`**. (The `(-k)` name only makes it pause, for double-click use.)
4. Keep the **`exiftool_files`** folder next to `exiftool.exe`. If you move one, move both.
5. Add `C:\Tools\exiftool` to your PATH. Then `exiftool -ver` works in any prompt.

#### Configuration: the options that matter

| Option | Meaning |
|--------|---------|
| `-a -G1 -s` | Show **all** tags (including duplicates), with their **group** (`[IFD0]`, `[GPS]`, `[XMP-dc]`…), using short tag **names** |
| `-n` | Numeric (raw) values, e.g. decimal GPS coordinates |
| `-c "%.6f"` | GPS coordinate format (with `-n`, or for display) |
| `-time:all` / `-gps:all` / `-xmp:all` | Only one family of tags |
| `-r` / `-ext jpg` | Recurse / only these extensions |
| **`-csv`** / **`-json`** | Bulk export for spreadsheets or scripts |
| `-ee` | Extract embedded data (e.g., video timed metadata) |
| `-b -ThumbnailImage` | Extract the embedded thumbnail (binary output) |
| `-api LargeFileSupport=1` | Large files |
| Writing: `-TAG=value`, `-all=` | **Writes create `file_original` backups** unless you add `-overwrite_original`. **Never write to evidence**: work on copies |

**Configuration file:** `~/.ExifTool_config` (custom tags and shortcuts, Perl syntax). You don't need one for analysis.

#### Verify the installation

```bash
exiftool -ver
exiftool -listf | head -n 3        # supported file types
```

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| GPS shows as `48 deg 51' 30.13" N` | Add `-n` (or `-c "%.6f"`) for decimal degrees |
| Windows: `exiftool_files` not found | Keep the folder next to `exiftool.exe` |
| A `*_original` file appeared | You **wrote** metadata. Restore from the backup and use read-only commands on evidence |
| Times look off | EXIF has no time zone. Check `OffsetTime*` and GPS times; FileModifyDate is from the file system, not the file |

---

### 🛠️ Tool 2: TrID

| | |
|---|---|
| **What** | Marco Pontello's **file identifier**. It matches files against a large, community-maintained database of format definitions (`triddefs.trd`) and prints **ranked guesses with percentages** |
| **Why in DFIR** | Identifies obscure, proprietary and extension-less files that `file` doesn't know: carved fragments, malware droppers' payloads, app databases |
| **Platforms** | Windows (CLI; **TrIDNet** GUI), Linux (x86/x64 CLI) |
| **Licence** | Freeware for personal / non-commercial use (check the site for commercial terms) |
| **Home** | https://mark0.net/soft-trid-e.html |

> ⚠️ The TrID website was **not reachable** from the environment used to test this lesson, so the TrID commands below **weren't run here**. They follow the documented usage. Run `trid` with no arguments to print the exact options for your version.

#### Installation

From https://mark0.net/soft-trid-e.html, download the program for your OS **and** the definitions package (`triddefs.zip`). Put the definitions file next to the program.

**Linux / SIFT:**

```bash
mkdir -p ~/tools/trid && cd ~/tools/trid
# place the downloaded zips here, then:
unzip trid_linux_64.zip && unzip triddefs.zip     # file names as published on the TrID page
chmod +x trid
./trid                                            # prints usage and options
sudo ln -s ~/tools/trid/trid /usr/local/bin/trid  # optional: put it on PATH
```

**Windows:**

```powershell
Expand-Archive "$env:USERPROFILE\Downloads\trid_w32.zip" -DestinationPath C:\Tools\trid -Force
Expand-Archive "$env:USERPROFILE\Downloads\triddefs.zip" -DestinationPath C:\Tools\trid -Force
C:\Tools\trid\trid.exe          # prints usage
```

#### Configuration

- **Keep the definitions current**: download a fresh `triddefs.zip` regularly. The site also offers an update script; see the TrID page.
- Commonly used switches (confirm with `trid` on your version):
  - `trid file` (identify)
  - `trid -ae files…` (**append** the guessed extension to the file name)
  - `trid -ce files…` (**change** the extension)
  - `-d:<path>` to point at a specific definitions file
- ⚠️ `-ae` and `-ce` **rename files**. Only use them on working copies, such as carver output, never on evidence.

#### Verify and first use

```bash
trid ~/cases/LAB-008/samples/mystery.bin
```

Expect a ranked list with **PNG** at or near the top, as a percentage. Compare it with `file` and `magika` (Lab 4).

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Error: found no file definitions!` | `triddefs.trd` isn't next to the program, or pass it with `-d:` |
| Everything is "Unknown" | The definitions are outdated, the file is encrypted/compressed (high entropy), or it's a fragment |
| Linux binary won't run | Check the architecture (`uname -m`) and run `chmod +x` |

---

### 🛠️ Tool 3: bulk_extractor

| | |
|---|---|
| **What** | Simson Garfinkel's high-performance **feature extractor**. It scans every byte of disk images, files or directories with dozens of scanners (email, URLs, card numbers, phone numbers, EXIF, JSON, network packets, Windows artifacts…), **decompresses and decodes recursively**, and writes feature files, histograms and a DFXML report |
| **Why in DFIR** | A "get evidence" button for triage. It finds identities, contacts, URLs and artifacts in allocated, deleted, slack, compressed and encoded data, regardless of the file system (or with no file system) |
| **Platforms** | Linux, macOS; Windows via a MinGW cross-build (see the docs) |
| **Licence** | **GPL-3.0-or-later** for current code. The original NPS-era code is a US Government work, and third-party components keep their own licences (see `COPYING`) |
| **Home** | https://github.com/simsong/bulk_extractor · https://forensics.wiki/bulk_extractor |

#### Installation

**SIFT:** bulk_extractor is usually preinstalled. Check with `bulk_extractor -V`.

**Ubuntu 24.04: there's no apt package, so build from source.** These steps were tested for this lesson; the dependency list comes from the official `doc/installation.md`, plus `libewf-dev` for E01 support:

```bash
sudo apt-get update
sudo apt-get install --yes autoconf automake build-essential flex git libabsl-dev libexpat1-dev \
  libgcrypt20-dev libgpg-error-dev libre2-dev libssl-dev libtool make pkg-config procps python3 \
  zlib1g-dev libewf-dev
git clone --recursive https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh && ./configure && make -j"$(nproc)"
sudo make install
bulk_extractor -V
```

For production, the README recommends a **tested release** archive from https://github.com/simsong/bulk_extractor/releases. Release archives already contain `configure`, so skip `./bootstrap.sh`.

**macOS:**

```bash
brew install bulk_extractor
```

**Windows:** native builds aren't supported. The project maintains a MinGW cross-build (see `doc/mingw_notes.md`). Running it in WSL2 or on SIFT is usually simpler.

#### Configuration: the options that matter

From `bulk_extractor -h` (2.2):

| Option | Meaning |
|--------|---------|
| **`-o outdir`** | Output directory (**required**; must not exist, or use `-Z` to wipe it) |
| `-R` | Treat the input as a **directory** and scan its files recursively |
| `-E scanner` | Run **only** this scanner (`-E email`) |
| `-e` / `-x scanner` | Enable / disable a scanner (`-x aes`, `-e base16`, `-e wordlist`) |
| `-f regex` / `-F file` | **Find** your own patterns (case-insensitive by default; `--find-case-sensitive`) → `find.txt` |
| `-S name=value` | Scanner options (listed by `bulk_extractor -H`), e.g. `-S min_phone_digits=7` |
| `-j N` | Threads (default 4) |
| `-w stoplist` / `-r alertlist` | Suppress known features / flag features of interest |
| `-C N` | Context window around each feature (bytes) |
| `-Y start-end` | Scan only part of the image |
| `-M N` | Maximum recursion depth (default 12) |
| `-H` | List all scanners, their feature files, and their `-S` options |

Disabled by default (enable when needed): `base16` (hex), `wordlist` (builds a password-cracking wordlist), `outlook`, `xor`, `hiberfile`.

#### Verify the installation

```bash
bulk_extractor -V                     # e.g. bulk_extractor 2.2.x
bulk_extractor -H | grep "Scanner Name" | head
```

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `outdir … already exists` | Use a new `-o` directory, or `-Z` to wipe it |
| E01 not accepted | Built without libewf. Install `libewf-dev`, re-run `./configure` (it reports `libewf is yes`), and rebuild |
| `ccn.txt` is empty, but you know a card number is there | The card scanner applies plausibility filters and silently skips many patterns (Lab 5). **An empty feature file isn't proof of absence.** Search for specific values with `-f` |
| `-p` (print a forensic path) fails with `<NO-OUTDIR>` | Seen with the 2.2.1-dev build tested here. Map the offset with TSK instead (Lab 6) |
| Slow | More threads (`-j`), a faster disk, `-x` for scanners you don't need |

---

## Part 3: Hands-on labs

Run on **SIFT** or Ubuntu with bulk_extractor installed (see above). Set the VM to **UTC** so the hashes match.

```bash
sudo apt install -y libimage-exiftool-perl sleuthkit dosfstools mtools
sudo apt install -y pipx && pipx install magika && pipx ensurepath   # Magika (Ubuntu 24.04 blocks 'pip install --user')
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-008/{samples,evidence,work,notes} && cd ~/cases/LAB-008
export TZ=UTC
```

### Lab 1: Write, then read, photo metadata (15 min)

```bash
cd ~/cases/LAB-008
python3 ~/DFIR/scripts/mk_metadata_samples.py samples
# Give the photo a camera, an owner, a time and a location (and see how easy forging is)
exiftool -q -overwrite_original -Make="Canon" -Model="Canon EOS 250D" -Artist="M. Rivera" \
  -SerialNumber="032021004521" -Software="Adobe Photoshop 25.0 (Windows)" \
  -DateTimeOriginal="2026:09:28 21:14:07" -OffsetTimeOriginal="+02:00" \
  -GPSLatitude=48.858370 -GPSLatitudeRef=N -GPSLongitude=2.294481 -GPSLongitudeRef=E samples/IMG_2041.jpg
sha256sum samples/IMG_2041.jpg       # -> af38138908b3927d1591bd475f0e09c0de898c969aacc6fa410fba561cd4fe31
```

Now read it as an examiner:

```bash
exiftool -a -G1 -s -IFD0:all -ExifIFD:all -GPS:all samples/IMG_2041.jpg
exiftool -n -s -GPSLatitude -GPSLongitude samples/IMG_2041.jpg
```

Expected output (an extract):

```
[IFD0]          Make                            : Canon
[IFD0]          Model                           : Canon EOS 250D
[IFD0]          Software                        : Adobe Photoshop 25.0 (Windows)
[IFD0]          Artist                          : M. Rivera
[ExifIFD]       DateTimeOriginal                : 2026:09:28 21:14:07
[ExifIFD]       OffsetTimeOriginal              : +02:00
[ExifIFD]       SerialNumber                    : 032021004521
[GPS]           GPSLatitudeRef                  : North
[GPS]           GPSLatitude                     : 48 deg 51' 30.13"
[GPS]           GPSLongitudeRef                 : East
[GPS]           GPSLongitude                    : 2 deg 17' 40.13"

GPSLatitude                     : 48.85837
GPSLongitude                    : 2.29448100008889
```

**Interpretation:**

- Taken **2026-09-28 21:14:07 at UTC+02:00**, i.e. **19:14:07 UTC**.
- At 48.85837 N, 2.294481 E (paste the coordinates into a map: that's the Eiffel Tower).
- With camera serial **032021004521**, the same serial you'd look for on other photos or on a seized camera.
- `Software: Adobe Photoshop` says the file was **edited** after capture, so the pixels may not be original.
- And you **wrote** all of it ten seconds ago. Metadata is a *claim* (§1.4).

### Lab 2: Who wrote this document? (10 min)

```bash
exiftool -a -G1 -s samples/contract.docx | grep -E "XMP|XML"
exiftool -s -PDF:all samples/invoice.pdf
```

Expected output:

```
[XMP-dc]        Title                           : Supply agreement - DRAFT
[XMP-dc]        Creator                         : M. Rivera
[XML]           LastModifiedBy                  : J. Chen
[XML]           RevisionNumber                  : 7
[XML]           CreateDate                      : 2026:09:14 08:02:00Z
[XML]           ModifyDate                      : 2026:09:29 23:41:00Z
[XML]           Template                        : Normal.dotm
[XML]           TotalEditTime                   : 6.9 hours
[XML]           Application                     : Microsoft Office Word
[XML]           Company                         : Northwind Traders
[XML]           AppVersion                      : 16.0000

PDFVersion                      : 1.4
Linearized                      : No
PageCount                       : 1
Title                           : Invoice 2026-0412
Author                          : M. Rivera
Creator                         : Microsoft Word
Producer                        : Microsoft: Print To PDF
CreateDate                      : 2026:09:30 10:15:00+02:00
ModifyDate                      : 2026:09:30 10:15:00+02:00
```

Questions an examiner asks:

- Created by **M. Rivera**, last saved by **J. Chen** at **23:41 UTC** the night before the deadline. Which user accounts and devices match those names (Days 11–13)?
- **Company: Northwind Traders**: the Office installation was licensed to that organisation.
- The invoice was "printed" to PDF from Word on **2026-09-30 10:15 (UTC+2)**.

You can also read OOXML metadata without ExifTool, because it's just XML inside a ZIP:

```bash
unzip -p samples/contract.docx docProps/core.xml | sed 's/></>\n</g'
```

### Lab 3: Forged PDF metadata leaves a trail (10 min)

The "suspect" changes the invoice's author and creation date:

```bash
cp samples/invoice.pdf work/invoice-edited.pdf
exiftool -q -Author="Accounts Payable" -CreateDate="2026:08:01 09:00:00+02:00" work/invoice-edited.pdf
ls work/                                         # note: invoice-edited.pdf_original (ExifTool's backup)
exiftool -s -Author -CreateDate work/invoice-edited.pdf
LC_ALL=C grep -a -o "/Author ([^)]*)" work/invoice-edited.pdf
```

Expected output:

```
invoice-edited.pdf  invoice-edited.pdf_original
Author                          : Accounts Payable
CreateDate                      : 2026:08:01 09:00:00+02:00
/Author (M. Rivera)
/Author (Accounts Payable)
```

**Both authors are in the file.** ExifTool, like many PDF editors, writes changes as an **incremental update** appended to the end. The original Info dictionary is still there. ExifTool can even roll the edit back:

```bash
exiftool -q -overwrite_original -PDF-update:all= work/invoice-edited.pdf
exiftool -s -Author -CreateDate work/invoice-edited.pdf
sha256sum work/invoice-edited.pdf samples/invoice.pdf          # identical again
```

Expected output: `Author: M. Rivera`, `CreateDate: 2026:09:30 10:15:00+02:00`, and **two identical SHA-256 values** (`bc6153f8…a5ad`).

Lessons:

1. A leftover `*_original` file is itself evidence of metadata editing.
2. For PDFs, always check for **multiple revisions**: `%%EOF` appears more than once (`grep -c %%EOF file.pdf`).

### Lab 4: What is this file? (10 min)

```bash
cd ~/cases/LAB-008/samples
file *
magika *
python3 ~/DFIR/scripts/sigcheck.py .          # Day 3 helper: extension vs magic bytes
trid mystery.bin blob.b64                     # if TrID is installed (not run by the author)
```

Expected `magika` output:

```
IMG_2041.jpg: JPEG image data (image)
backup.zip: Zip archive data (archive)
blob.b64: CSV document (code)
contract.docx: Microsoft Word 2007+ document (document)
invoice.pdf: PDF document (document)
mystery.bin: PNG image (image)
notes.txt: Generic text document (text)
```

- `mystery.bin` is a **PNG** by content (all three methods agree).
- `blob.b64`: `file` says *ASCII text*, while Magika says ***CSV document***, which is **wrong**. It's base64. No tool says "base64". You recognise it by eye (only `A–Z a–z 0–9 + /` and `=` padding), then decode it:

  ```bash
  base64 -d blob.b64 | head -n 1      # -> hidden contact: courier.contact@example.com, meet 02:00 at pier 9
  ```

  (CyberChef's *From Base64* from Day 1 works too.) Identification tools are aids, not oracles.

### Lab 5: Sweep a whole disk with bulk_extractor (20 min)

Put the samples on a USB image, then **delete** two of them:

```bash
cd ~/cases/LAB-008/evidence
truncate -s 64M usb.raw
printf 'label: dos\nlabel-id: 0x0b5e55ed\nstart=2048, type=c\n' | sfdisk -q usb.raw
mkfs.vfat -F 32 --invariant -i 2026B0B0 --offset=2048 -h 2048 -n EVIDENCE usb.raw 64512 >/dev/null 2>&1
touch -d "2026-09-30 17:45:10 UTC" ../samples/*
mcopy -m -i usb.raw@@1M ../samples/* ::/
mdel -i usb.raw@@1M ::/notes.txt ::/backup.zip
fls -r -o 2048 usb.raw | grep '\*'          # the two deleted files
sha256sum usb.raw | tee ../notes/usb.raw.sha256 && chmod 444 usb.raw
```

Expected output: `r/r * 5: _ackup.zip`, `r/r * 11: _otes.txt`, and the SHA-256 `f200ace5afa01d67077393263b2fbd2760648ca275e6c09cedb2b78b5e8d5c1b`.

Run bulk_extractor on the **raw image**, with no file system involved:

```bash
cd ~/cases/LAB-008
bulk_extractor -o work/be evidence/usb.raw > work/be.log 2>&1; tail -n 1 work/be.log
ls work/be | head -n 20
grep -v '^#' work/be/email_histogram.txt
grep -v '^#' work/be/email.txt | cut -f1,2
```

Expected output:

```
n=3	courier.contact@example.com
n=3	dropbox.owner@example.net
n=2	j.chen@northwind-traders.com
n=1	m.rivera.private@example.org
n=1	maria.rivera@northwind-traders.com

2091041	maria.rivera@northwind-traders.com
2091086	m.rivera.private@example.org
2083917-BASE64-25	courier.contact@example.com
2083917-BASE64-91	courier.contact@example.com
2083917-BASE64-157	courier.contact@example.com
2083328-ZIP-61	dropbox.owner@example.net
2083328-ZIP-148	dropbox.owner@example.net
2083328-ZIP-235	dropbox.owner@example.net
2085578-ZIP-168	j.chen@northwind-traders.com
2085578-ZIP-0-MSXML-24	j.chen@northwind-traders.com
```

Read the **forensic paths**:

| Hit | Came from |
|-----|-----------|
| `2091041`, `2091086` | Plain text at those byte offsets: the **deleted** `notes.txt` |
| `2083917-BASE64-25` | Inside **base64** data at byte 2,083,917 (`blob.b64`), decoded automatically |
| `2083328-ZIP-61` | Inside the **compressed** member of the **deleted** `backup.zip` |
| `2085578-ZIP-0-MSXML-24` | Inside `contract.docx` (a ZIP), extracted as Office XML text |

None of the deleted or encoded hits would appear with a simple `strings | grep`, and the ZIP and base64 ones wouldn't even appear in a file-system view.

More feature files:

```bash
grep -v '^#' work/be/url_histogram.txt | grep -v schemas.openxmlformats
grep -v '^#' work/be/telephone.txt | cut -f1,2
grep -v '^#' work/be/ccn.txt | cut -f1,2
grep -v '^#' work/be/exif.txt | grep -o '<ifd0[.a-z]*\.\(Model\|DateTimeOriginal\|BodySerialNumber\|GPSLatitude\|GPSLongitude\)>[^<]*'
```

Expected output (the purl.org/w3.org URLs are XML namespaces inside the DOCX):

```
n=3	https://files.example.net/drop
n=1	http://203.0.113.50/upload.php
n=1	http://purl.org/dc/elements/1.1/
n=1	http://purl.org/dc/terms/
n=1	http://www.w3.org/2001/XMLSchema-instance
n=1	https://portal.northwind-traders.com/login?next=/payments

2091125	(555) 010-4477

2091323	6011000990139424

<ifd0.tiff.Model>Canon EOS 250D
<ifd0.exif.DateTimeOriginal>2026:09:28 21:14:07
<ifd0.exif.BodySerialNumber>032021004521
<ifd0.gps.GPSLatitude>48/1 51/1 7533/250
<ifd0.gps.GPSLongitude>2/1 17/1 49402/1231
```

bulk_extractor found the EXIF block without parsing any file system. GPS values are stored as EXIF **rationals** (degrees/minutes/seconds): `48/1 51/1 7533/250` = 48° 51′ 30.132″ = **48.85837°**, the same as ExifTool reported in Lab 1.

⚠️ `notes.txt` contained **two** published test card numbers, but `ccn.txt` reports only `6011000990139424`. The card scanner applies plausibility filters, and the spaced `4000 0566 5566 5556` was skipped. **An empty or short feature file isn't proof of absence.** When you're looking for specific values, search for them explicitly:

```bash
bulk_extractor -o work/be-find -E find -f '4000[ -]?0566[ -]?5566[ -]?5556' evidence/usb.raw > /dev/null
grep -v '^#' work/be-find/find.txt | cut -f1,2      # -> 2091381	4000 0566 5566 5556
```

### Lab 6: Map a hit back to its file (10 min)

The email `maria.rivera@northwind-traders.com` was found at byte **2,091,041**. Which file was it in?

```bash
cd ~/cases/LAB-008
echo $(( 2091041 / 512 ))                       # -> sector 4084 of the image
echo $(( 2091041 / 512 - 2048 ))                # -> block 2036 of the FAT32 volume (partition starts at 2048)
ifind -o 2048 -d 2036 evidence/usb.raw          # which directory entry owns that block?
istat -o 2048 evidence/usb.raw 11 | head -n 6
```

Expected output:

```
4084
2036
11
Directory Entry: 11
Not Allocated
File Attributes: File, Archive
Size: 393
Name: _otes.txt
```

The hit belongs to the **deleted** `notes.txt` (entry 11). You can now report it accurately:

> "The email address maria.rivera@northwind-traders.com was found at byte offset 2,091,041 of image `usb.raw` (SHA-256 f200ace5…5c1b), within the content of the deleted file `NOTES.TXT` (FAT directory entry 11)."

---

## ✅ Knowledge check

1. Why can a photo's EXIF `DateTimeOriginal` be more useful than its file-system timestamps, and what are its weaknesses?
2. Which DOCX file and tags tell you who created and who last edited a document, and when?
3. What does `Producer: Microsoft: Print To PDF` tell you that `Creator` doesn't?
4. After an ExifTool edit, how could you tell that a PDF's metadata was changed?
5. `file` says "ASCII text", Magika says "CSV", and the content is `aGlkZGVu…`. What is it, and what's the lesson?
6. Explain the bulk_extractor forensic path `2085578-ZIP-0-MSXML-24`.
7. `ccn.txt` is empty. Can you report "no payment card numbers were present"? What should you do?
8. Why does bulk_extractor find content from deleted files and inside ZIPs, when `fls`/Explorer don't?

<details>
<summary><b>Answers</b></summary>

1. It's embedded in the file, so it survives copying, emailing and downloading, and it records when the **camera** took the photo. Weaknesses: the camera's clock may be wrong, there's no time zone unless `OffsetTimeOriginal` exists, and it's trivially editable.
2. `docProps/core.xml`: `dc:creator` (creator), `cp:lastModifiedBy` (last editor), `dcterms:created` / `dcterms:modified` (UTC), and `cp:revision`. `docProps/app.xml` adds Application, Company, Template and TotalTime.
3. `Producer` is the **PDF engine** that wrote the file (here, Windows' built-in PDF printer). `Creator` is the authoring application (Word). Together they show the workflow: written in Word, printed to PDF on Windows.
4. The PDF contains **multiple revisions**: more than one `%%EOF`, and older Info dictionaries with the previous values. ExifTool may also leave a `*_original` backup file.
5. Base64-encoded text. Identification tools (magic rules or ML) can be wrong, especially for text formats. Look at the bytes, recognise the encoding, and decode it.
6. At byte 2,085,578 of the image there's a ZIP (the DOCX). Its first decompressed member (offset 0 in the ZIP stream) was parsed as Office XML (MSXML), and the feature is at offset 24 of the extracted text.
7. No. The scanner filters many numbers (it reported only one of two test numbers here). Report what was searched and found, and use `-f`/`-F` to look for specific values if you need to.
8. It reads every byte of the image regardless of allocation, and recursively decodes compressed and encoded data (ZIP, base64, …), then rescans the result.

</details>

---

## 📚 Further reading

- ExifTool documentation and tag names: https://exiftool.org/TagNames/ and the FAQ (https://exiftool.org/faq.html)
- CIPA DC-008, *Exchangeable image file format for digital still cameras (Exif)*, for the meaning of each tag
- ECMA-376 (Office Open XML), *Part 2: Open Packaging Conventions*, on `docProps/core.xml`
- PDF 1.7 / ISO 32000: *incremental updates* and the document information dictionary
- Simson Garfinkel, *Digital media triage with bulk data analysis and bulk_extractor* (Computers & Security, 2013)
- bulk_extractor manuals: https://simsong.github.io/bulk_extractor/
- Google Magika: https://github.com/google/magika

---

## ⏭️ Tomorrow: Day 09 (Phase 2: Windows Forensics begins)

**Windows triage collection**. Tools: **KAPE**, **CyLR**, **DFIR ORC**.
We move from general foundations to Windows: which artifacts to collect from a live or dead Windows system, how to collect them quickly and soundly, and how to build repeatable collection profiles.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
