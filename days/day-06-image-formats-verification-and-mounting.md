# Day 06: Forensic Image Formats, Verification & Mounting Images Safely

> **Phase 1: Foundations** · **Level:** 🟡 Intermediate · **Time:** ~3–4 hours (reading + labs) · **Posted:** 2026-10-03
>
> **Tools today:** 🛠️ libewf (ewf-tools) · 🛠️ Arsenal Image Mounter · 🛠️ xmount

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain how an **E01 (EWF)** image is built (segments, sections, chunks, checksums, stored hashes) and what that means for verification.
2. Create, inspect, verify and convert E01 images with **ewfacquire, ewfinfo, ewfverify, ewfexport and ewfmount**.
3. Turn any image into a **read-only raw view**, then reach partitions and file systems inside it, layer by layer.
4. Mount file systems **without changing the evidence**, and explain the journal-replay trap.
5. Present an image as a **virtual disk** (VDI, VMDK, VHD) with a write cache using **xmount**, for example to boot it in a VM.
6. Mount images as **real disks on Windows** with **Arsenal Image Mounter**, including Volume Shadow Copy access.

---

## Part 1: The lesson

### 1.1 From image file to evidence: the layers

```
 ┌──────────────────────────┐  container layer   ewfmount · xmount · Arsenal Image Mounter · qemu-nbd · affuse
 │ LAB006_EV001.E01 (+.E02…)│ ───────────────────────────────────────────────────────────────────────┐
 └──────────────────────────┘                                                                        ▼
                                                     ┌──────────────────────────────────────────────────────┐
                                                     │ raw device view: /mnt/ewf/ewf1 (= every sector)      │
                                                     └──────────────────────────────────────────────────────┘
   volume layer      mmls (Day 3) → partition start × sector size = byte offset                       │
                                                                                                       ▼
                                                     ┌──────────────────────────────────────────────────────┐
                                                     │ partition: losetup -r -o OFFSET  /  TSK -o SECTORS    │
                                                     └──────────────────────────────────────────────────────┘
   file-system layer   TSK directly (no mount)   or   mount -o ro,… (careful!)                         │
                                                                                                       ▼
                                                               files, metadata, unallocated space
```

You don't always have to **mount** anything. The Sleuth Kit and Autopsy read file systems straight from the raw view, which is the safest option. Mount when you need ordinary tools (antivirus, `grep -r`, viewers, parsers that expect a path), and then do it **read-only, the right way** (§1.5).

### 1.2 Inside an E01 (EWF)

An E01 is a set of **segment files**: `.E01`, `.E02` … `.E99`, then `.EAA`, `.EAB` …. Each segment contains **sections**:

| Section | Contents |
|---------|----------|
| `header` / `header2` | Case metadata: case number, evidence number, examiner, notes, acquisition date, OS, software |
| `volume` / `disk` | Media information: sector count, bytes per sector, sectors per chunk, media type (fixed, removable…) |
| `sectors` | The data, in **chunks** (default **64 sectors = 32 KiB**), each compressed (zlib/deflate) or stored with an **Adler-32 checksum** |
| `table` / `table2` | Offsets of the chunks (two copies) |
| `hash` / `digest` | The **MD5** (and optionally **SHA-1**) of the *whole acquired media* |
| `error2` | Sectors that couldn't be read during acquisition |
| `done` / `next` | End of the image / continued in the next segment |

**What that means in practice** (all shown in today's labs):

- **Two levels of integrity:** a per-chunk checksum (catches damage and **localises it to a 64-sector range**) plus a stored whole-media hash.
- **E01 (EnCase 6 format) stores MD5 and SHA-1, not SHA-256.** If you hash with SHA-256 during acquisition, that value lives **only in your acquisition log**. Keep the log with the image!
- **The hash of the `.E01` *file* is meaningless as evidence integrity.** Two E01s of the same disk, made seconds apart, have different file hashes (different acquisition dates in the header) but identical *data* hashes.
- **Ex01 (EWF2)** is the newer EnCase format (bzip2, encryption). libewf supports it only partly. **L01 / Lx01** are *logical* evidence files (selected files, not a disk); libewf can read them.

### 1.3 Other formats you'll mount

| Format | Read with / mount with |
|--------|------------------------|
| Raw, split raw (`.dd`, `.001`…) | Directly (`losetup`, TSK); split sets: `cat`, `affuse`, xmount (`--in raw` with all the parts), TSK (lists all parts) |
| E01 / Ex01 / L01 | libewf (`ewfmount`), xmount (`--in ewf` or `aewf`), Arsenal Image Mounter, FTK Imager |
| AFF4 | `aff4imager` / pyaff4, Arsenal Image Mounter |
| VMDK, VHD/VHDX, VDI, QCOW2 | `qemu-img convert -O raw in.vmdk out.raw`, `qemu-nbd`, TSK (VMDK/VHD), Windows `Mount-DiskImage` (VHD/VHDX), Arsenal Image Mounter |
| DMG (macOS) | Day 37 |

### 1.4 Verification: which hash, from where?

| What you have | How to verify | What must match |
|---------------|---------------|-----------------|
| E01 | `ewfverify -d sha256 image.E01` | *MD5 stored* = *MD5 calculated*, and no validation errors (`SUCCESS`). Compare the SHA-256 with your acquisition log |
| Raw `.dd` | `sha256sum image.dd` | The source hash in the acquisition log |
| Split raw | `cat image.0* \| sha256sum` | The source hash |
| A raw view (FUSE mount) | `sha256sum /mnt/ewf/ewf1` | The source hash. This proves the *container* serves the right data |
| A converted image | Hash the result | The original **data** hash (`ewfexport` prints MD5) |

### 1.5 Mounting without changing evidence

**Rule 1: make the block device read-only first, then mount read-only.**

```bash
LOOP=$(sudo losetup -f --show -r -o $((2048*512)) /mnt/ewf/ewf1)    # read-only loop at the partition offset
sudo mount -o ro,noload "$LOOP" /mnt/evidence                         # ext3/ext4
```

**Rule 2: journaling file systems may "fix themselves" on mount.** ext3/ext4, XFS, NTFS and Btrfs keep journals. If an image was taken from a **running** system, its journal often contains unapplied transactions (`needs_recovery`). Mounting with plain `-o ro` on a **writable** device makes the kernel **replay the journal and write to your image**. Lab 5 shows the SHA-256 changing.

| File system | Safe read-only mount |
|-------------|----------------------|
| ext3 / ext4 | `-o ro,noload` (`noload` = don't touch the journal) |
| XFS | `-o ro,norecovery` |
| NTFS (ntfs-3g) | `-o ro,show_sys_files,streams_interface=windows` (shows `$MFT` & co. and ADS) |
| NTFS (kernel `ntfs3`) | `-o ro` |
| FAT / exFAT | `-o ro` (add `uid=$(id -u)` for access as your user) |
| Btrfs | `-o ro,rescue=nologreplay` |

Even with these options, use a **read-only loop device** (`losetup -r`) or a read-only FUSE view (`ewfmount`). That way a mistake can't reach the evidence. Then hash before and after.

> ⚠️ `noload` shows the file system **as it was on disk**, *without* the journal's pending changes. The most recent activity may be missing. If you need it, replay the journal on a **copy** and document that you did.

**On Windows:**

- Never let Windows auto-mount evidence read-write. Use **Arsenal Image Mounter** or **FTK Imager → Image Mounting** in read-only mode.
- For VHD/VHDX: `Mount-DiskImage -ImagePath C:\Cases\x.vhdx -Access ReadOnly`.

### 1.6 Why boot an image?

Sometimes you need to *see* the system as the user saw it: desktop layout, application state, a password manager, how malware behaves on start-up. Booting an image is a **derivative** activity:

- Boot from a **write cache or differencing disk** (xmount `--cache`, Arsenal *write-temporary*, VM snapshots). The image itself must never change.
- **Isolate the network** (no adapter, or a host-only network).
- Windows may need driver or boot-configuration fixes to boot on virtual hardware (Arsenal Image Mounter and other tools can help).
- Whatever happens in the VM is **not evidence** of what the suspect did. Use it to understand and illustrate, and prove your findings from the image.

---

## Part 2: Tools

---

### 🛠️ Tool 1: libewf (ewf-tools)

| | |
|---|---|
| **What** | Joachim Metz's library for the **Expert Witness Compression Format**, plus command-line tools to **acquire** (`ewfacquire`, `ewfacquirestream`), **inspect** (`ewfinfo`), **verify** (`ewfverify`), **convert** (`ewfexport`), **mount** (`ewfmount`) and **repair** (`ewfrecover`) E01 images |
| **Why in DFIR** | It's the open-source engine behind E01 support in TSK, Autopsy, Plaso, Guymager, xmount and many others. Knowing the CLI lets you verify any E01 independently of the tool that created it |
| **Platforms** | Linux, macOS, BSD; Windows via WSL (on native Windows, use FTK Imager or Arsenal Image Mounter for E01s) |
| **Licence** | LGPL-3.0-or-later |
| **Home** | https://github.com/libyal/libewf |

#### Installation

**SIFT / Ubuntu / Debian:**

```bash
sudo apt update && sudo apt install -y ewf-tools
ewfinfo -V | head -n 1             # Ubuntu 24.04 packages libewf 20140814 (old, but stable for E01)
sudo apt install -y python3-libewf # optional: Python bindings (pyewf)
```

**Newer upstream version** (needed for better Ex01/L01 support; the README marks the project "experimental"):

```bash
sudo apt install -y build-essential autoconf automake libtool pkg-config zlib1g-dev libssl-dev libfuse-dev
# Download libewf-experimental-<VER>.tar.gz from https://github.com/libyal/libewf/releases, then:
tar xzf libewf-experimental-<VER>.tar.gz && cd libewf-<VER>
./configure && make -j"$(nproc)" && sudo make install && sudo ldconfig
```

**macOS:**

```bash
brew install libewf          # then: ewfinfo -V
# ewfmount additionally needs macFUSE
```

**Windows:** use WSL2 (`sudo apt install ewf-tools` inside Ubuntu), or rely on FTK Imager / Arsenal Image Mounter for E01 handling.

#### The tools and options that matter

From the tools' own `-h` output (20140814):

| Tool | Key options |
|------|-------------|
| `ewfacquire` | `-t target` (no extension) · `-f encase6\|encase7\|ftk\|…` · `-c deflate:fast\|best\|none` · `-S 2GiB` (segment size) · `-d sha1` / `-d sha256` (extra hashes) · `-C` case · `-E` evidence no. · `-D` description · `-e` examiner · `-N` notes · `-m fixed\|removable` · `-l logfile` · `-r` read retries · `-w` zero sectors on read error · `-2` second target · **`-u` unattended** |
| `ewfinfo` | `-i` acquisition info only · `-m` media info only · `-e` read errors only · `-d iso8601` date format · `-f dfxml` |
| `ewfverify` | `-d sha256` (also calculate SHA-256) · `-l logfile` · `-q` quiet · `-w` zero chunks on checksum error |
| `ewfexport` | `-t target` · `-f raw` (default) or another EWF format · `-S` segment size · `-u` unattended · `-l` log |
| `ewfmount` | `ewfmount image.E01 /mnt/ewf` → `/mnt/ewf/ewf1` (read-only raw view) · `-X allow_other` passes FUSE options |

**Exit codes:** `ewfverify` returns **0 on success and 1 on failure** (tested in Lab 3), so it's safe to use in scripts, unlike dc3dd's (Day 5).

**FUSE:** to let other users (or VirtualBox running as you) read a FUSE mount made by root, uncomment `user_allow_other` in `/etc/fuse.conf` and mount with `-X allow_other`.

#### Verify the installation

```bash
ewfacquire -V; ewfverify -V; ewfmount -V
```

Then run Lab 1. `ewfacquire: SUCCESS` with the expected MD5 confirms it works.

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ewfmount: unable to create fuse` / permission errors | Install `fuse`/`fuse3`, run it with `sudo`, check that `/dev/fuse` exists |
| Other users can't see the mounted files | Mount with `-X allow_other` after enabling `user_allow_other` |
| `SHA256 hash stored in file: N/A` | Normal for E01 (EnCase 6): only MD5/SHA-1 are stored. Use the SHA-256 from your acquisition log |
| `ewfverify: FAILURE` with *Sector validation errors* | Corrupted segment (storage or copy error). Restore from your second copy, then re-verify |
| Ex01 bzip2 / encrypted images fail | Not supported by libewf yet. Use the vendor's tool |

---

### 🛠️ Tool 2: Arsenal Image Mounter (AIM)

| | |
|---|---|
| **What** | Windows software that mounts the **contents of disk images as complete "real" SCSI disks**, through its own Storport miniport driver. Windows treats them like physical disks: they appear in Disk Management, and their **Volume Shadow Copies** are accessible |
| **Why in DFIR** | Many Windows tools only work on real disks or drive letters. Mounting the *whole disk* (not just one volume) gives you VSS, BitLocker handling, and the ability to boot or virtualise the image, without changing the image |
| **Platforms** | Windows 10/11 and Windows Server |
| **Licence** | **Free Mode** (core functionality) or **Professional Mode** with a subscription. The source code and APIs are dual-licensed (AGPL v3 for compatible open-source projects, commercial otherwise) |
| **Home** | https://ArsenalRecon.com/weapons/image-mounter · source: https://github.com/ArsenalRecon/Arsenal-Image-Mounter |

#### Installation (Windows analysis VM)

1. Download Arsenal Image Mounter from https://ArsenalRecon.com/downloads (zip) and **record its hash**.
2. Extract it to `C:\Tools\ArsenalImageMounter`.
3. Run `ArsenalImageMounter.exe` **as Administrator**. On the first run it offers to install its virtual SCSI adapter driver. Accept.
4. Without a licence, it runs in **Free Mode**. The vendor's product page lists which features need **Professional Mode** (e.g., some write-temporary, boot and advanced options). Check it for your version.

#### Configuration and use

1. **File → Mount disk image** (or the *Mount disk image* button) → select `LAB006_EV001.E01` (raw, E01/Ex01, AFF4, VHD/VHDX, VMDK and other formats are supported; see the product page for the current list).
2. In the mount options, choose **Read only**. That's the forensic default for evidence.
   - Other options appear depending on your mode: *write temporary* (changes go to a separate differencing file), *fake disk signatures* (avoid conflicts when mounting several images of cloned disks), *removable disk emulation*, and so on. Use only what your procedure allows, and document it.
3. The image appears as a new disk. Check it in PowerShell:

   ```powershell
   Get-Disk | Format-Table Number, FriendlyName, IsReadOnly, Size, PartitionStyle
   Get-Volume | Format-Table DriveLetter, FileSystemLabel, FileSystem, Size
   ```

4. **Volume Shadow Copies** (Day 20): because Windows sees a real disk, its VSS snapshots are visible:

   ```powershell
   vssadmin list shadows /for=E:          # E: = the mounted evidence volume
   ```

5. Unmount from the AIM window (*Remove* / *Dismount*) before closing.

AIM also ships command-line tooling for scripted mounting (see the files in the download and the GitHub repository). Run it with `--help` to check the syntax for your version.

#### Verify the installation

Mount `LAB006_EV001.E01` (Lab 1) **read-only**:

- `Get-Disk` shows a new 64 MB disk with `IsReadOnly = True`.
- Explorer shows the **SUSPECT** volume containing `payroll.csv`.

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| The driver won't install | Run as Administrator. Check Windows security prompts (Core Isolation / driver block messages) and the AIM documentation |
| The disk appears but has no drive letter | Assign one in Disk Management (this doesn't write to a read-only image), or check whether the volume is BitLocker-encrypted |
| No shadow copies listed | The volume has none, or you mounted a single partition image instead of the full disk |
| A feature is greyed out | It needs Professional Mode |

---

### 🛠️ Tool 3: xmount

| | |
|---|---|
| **What** | A FUSE tool that **converts disk images on the fly** between input formats (`raw`/`dd`, `ewf`/`aewf`, `aff`/`aaff`) and output formats (`raw`, `vdi`, `vhd`, `vmdk`, `vmdks`, `dmg`). It has an optional **write cache**, so the virtual disk can be written to (e.g., booted) while the original image stays untouched |
| **Why in DFIR** | Boot an E01 in VirtualBox/VMware without converting 500 GB first; present split or EWF images as one raw device; extract *unallocated* space via a morphing module |
| **Platforms** | Linux (and macOS with macFUSE) |
| **Licence** | GPL-3.0-or-later |
| **Home** | https://www.pinguin.lu/xmount (the project page referenced by the tool) |

#### Installation

```bash
sudo apt update && sudo apt install -y xmount
xmount --version 2>&1 | head -n 3          # Ubuntu 24.04: xmount v0.7.6
```

xmount uses FUSE. For **VMDK output** or access by non-root users, uncomment `user_allow_other` in `/etc/fuse.conf`, or run it as root (as the tool's own help says).

#### Configuration: the options that matter

From `xmount -h` (v0.7.6):

| Option | Meaning |
|--------|---------|
| `--in <type> <file(s)>` | Input format: `raw`, `dd`, `ewf`, `aewf` (Guymager's fast EWF reader), `aff`, `aaff`. **List every part** of a split image |
| `--out <type>` | Output format: `raw` (default), `vdi`, `vhd`, `vmdk`, `vmdks`, `dmg` |
| `--cache <file>` | Enable **virtual writes**, which go to `<file>`, never to the image (`--owcache` overwrites an existing cache) |
| `--offset <bytes>` / `--sizelimit <bytes>` | Expose only part of the input (e.g., one partition) |
| `--morph unallocated` + `--morphopts unallocated_fs=fat` | Present only the **unallocated** blocks of a FAT or HFS file system |
| `--inopts aewfthreads=8` | Tune the `aewf` reader |
| `-o ro` / `-o allow_other` | FUSE options |

Mounting creates two files: the converted image (e.g., `NAME.dd` or `NAME.vdi`) and `NAME.info`, which contains the case metadata and MD5 from the E01.

#### Verify the installation

```bash
sudo xmount --in ewf LAB006_EV001.E01 /mnt/xm && ls -l /mnt/xm && sha256sum /mnt/xm/*.dd
```

The SHA-256 should be `9f9a1291…ed4a6` (Lab 6).

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Unknown command line option "--help"` | Use `xmount -h` |
| VirtualBox can't open the `.vdi` (permission denied) | The FUSE mount was made by root without `allow_other`. Enable `user_allow_other` and mount with `-o allow_other` |
| Writes fail on the virtual disk | You didn't use `--cache` (the output is read-only without it) |
| Split image shows the wrong size | You forgot some parts after `--in raw`. List them all (`--in raw image.0*`) |

---

## Part 3: Hands-on labs

Run on **SIFT** or Ubuntu (FUSE and loop devices need `sudo`). Set the VM to **UTC** so the Lab 1 hashes match.

```bash
sudo apt install -y ewf-tools xmount sleuthkit dosfstools mtools e2fsprogs
mkdir -p ~/cases/LAB-006/{evidence,images,work,notes} && cd ~/cases/LAB-006
sudo mkdir -p /mnt/ewf /mnt/xm /mnt/lab6
```

### Lab 1: Acquire to E01 with case metadata (10 min)

Rebuild Day 5's deterministic "suspect USB" (the same commands as Day 5, Lab 1) and attach it read-only:

```bash
cd ~/cases/LAB-006/evidence
truncate -s 64M suspect-usb.raw
printf 'label: dos\nlabel-id: 0x5005b00c\nstart=2048, type=c\n' | sfdisk -q suspect-usb.raw
mkfs.vfat -F 32 --invariant -i 2026DF1A --offset=2048 -h 2048 -n SUSPECT suspect-usb.raw 129024 >/dev/null 2>&1
printf 'employee,amount\nalice,4200\nbob,3900\n' > /tmp/payroll.csv
touch -d "2026-09-30 17:45:10 UTC" /tmp/payroll.csv
TZ=UTC mcopy -m -i suspect-usb.raw@@1M /tmp/payroll.csv ::/
sha256sum suspect-usb.raw                     # -> 9f9a1291…ed4a6 (same as Day 5)
DEV=$(sudo losetup -f --show -r suspect-usb.raw)
```

Acquire it to E01, unattended, with case metadata and an extra SHA-256:

```bash
cd ~/cases/LAB-006/images
sudo ewfacquire -u -t LAB006_EV001 -f encase6 -c deflate:fast -S 16MiB -d sha256 \
  -C "LAB-006" -E "EV001" -D "Suspect USB (simulated)" -e "A. Analyst" \
  -N "Acquired via read-only loop device" -m removable -l LAB006_EV001.acq.log "$DEV"
sudo losetup -d "$DEV"
sudo chown "$USER": LAB006_EV001.*
ls -l LAB006_EV001.*
```

Expected output (the end):

```
Written: 64 MiB (67110180 bytes) in 1 second(s) with 64 MiB/s (67110180 bytes/second).
MD5 hash calculated over data:		3296a7680ec04f493a57ec50b4dbfd9e
SHA256 hash calculated over data:	9f9a1291cbb96c0262c58627bf3b047f6044d121130a0c169ff21272576ed4a6
ewfacquire: SUCCESS
```

A 64 MiB disk becomes a roughly **350 KB** `.E01` (empty space compresses very well), plus `LAB006_EV001.acq.log`, which holds the hashes. **Keep that log.**

### Lab 2: Inspect and verify (10 min)

```bash
ewfinfo LAB006_EV001.E01
```

Expected output (an extract):

```
Acquiry information
	Case number:		LAB-006
	Description:		Suspect USB (simulated)
	Examiner name:		A. Analyst
	Evidence number:	EV001
	Notes:			Acquired via read-only loop device
	Acquisition date:	Sat Oct  3 08:47:38 2026
	...
EWF information
	File format:		EnCase 6
	Sectors per chunk:	64
	Compression method:	deflate
Media information
	Media type:		removable disk
	Bytes per sector:	512
	Number of sectors:	131072
Digest hash information
	MD5:			3296a7680ec04f493a57ec50b4dbfd9e
```

```bash
ewfverify -d sha256 LAB006_EV001.E01
```

Expected output (an extract):

```
MD5 hash stored in file:		3296a7680ec04f493a57ec50b4dbfd9e
MD5 hash calculated over data:		3296a7680ec04f493a57ec50b4dbfd9e
SHA256 hash stored in file:		N/A
SHA256 hash calculated over data:	9f9a1291cbb96c0262c58627bf3b047f6044d121130a0c169ff21272576ed4a6
ewfverify: SUCCESS
```

Three things to notice:

1. **`SHA256 hash stored in file: N/A`**: E01 (EnCase 6) can't store SHA-256. Compare the calculated value with your **acquisition log**. (Acquire with `-d sha1` and `ewfinfo` will show a stored SHA1 as well.)
2. Run `sha256sum LAB006_EV001.E01`: it's a completely different value, and **meaningless** for evidence integrity (Day 2, §1.7).
3. The data hashes are identical to Day 5's raw dc3dd image. **Same evidence, different container.**

### Lab 3: Detect a damaged E01 (10 min)

Damage a **copy** (simulating bit rot or a bad copy) and verify it:

```bash
cp LAB006_EV001.E01 ../work/damaged.E01
SZ=$(stat -c %s ../work/damaged.E01)
printf '\xff\xff\xff\xff' | dd of=../work/damaged.E01 bs=1 seek=$((SZ/2)) conv=notrunc status=none
ewfverify ../work/damaged.E01; echo "exit code: $?"
```

Expected output (the sector numbers may differ):

```
Sector validation errors:
	total number: 1
	at sector(s): 68544 - 68607 (number: 64) in segment file(s): …/damaged.E01
MD5 hash stored in file:		3296a7680ec04f493a57ec50b4dbfd9e
MD5 hash calculated over data:		3296a7680ec04f493a57ec50b4dbfd9e
Unable to verify input.
ewfverify: FAILURE
exit code: 1
```

- The damage is pinned to **one 64-sector chunk**, thanks to the per-chunk checksums.
- Here the **overall MD5 still matches**: this practice disk is mostly empty, so the damaged chunk only held zeros. ewfverify still says **FAILURE**. Trust the verdict and the validation-error list, not just a matching MD5.
- `exit code: 1`, so ewfverify is safe to use in scripts (unlike dc3dd, Day 5).

### Lab 4: Mount the E01 as a raw view and convert it (10 min)

```bash
cd ~/cases/LAB-006/images
sudo ewfmount LAB006_EV001.E01 /mnt/ewf
ls -l /mnt/ewf                                 # -r--r--r-- … ewf1  (read-only, 67108864 bytes)
sudo sha256sum /mnt/ewf/ewf1                   # -> 9f9a1291…ed4a6
sudo mmls /mnt/ewf/ewf1                        # partition at sector 2048
sudo fls -o 2048 /mnt/ewf/ewf1                 # -> r/r 4: payroll.csv
sudo mtype -i /mnt/ewf/ewf1@@1M ::/payroll.csv # read a file without mounting the FS
sudo dd if=/dev/zero of=/mnt/ewf/ewf1 bs=512 count=1 conv=notrunc   # try to write
```

Expected output of the write attempt:

```
dd: failed to open '/mnt/ewf/ewf1': Permission denied
```

The FUSE view is read-only, even for root.

On SIFT you can also mount the FAT32 file system for ordinary tools:

```bash
LOOP=$(sudo losetup -f --show -r -o $((2048*512)) /mnt/ewf/ewf1)
sudo mount -o ro,uid=$(id -u) "$LOOP" /mnt/lab6 && ls -l /mnt/lab6 && sudo umount /mnt/lab6
sudo losetup -d "$LOOP"
```

(The test environment for this lesson couldn't mount vfat in the kernel, so this step was checked with TSK and mtools instead.)

```bash
sudo umount /mnt/ewf
```

Convert the E01 back to raw (for tools that can't read E01):

```bash
ewfexport -u -t ../work/LAB006_EV001_export -f raw LAB006_EV001.E01
sha256sum ../work/LAB006_EV001_export.raw      # -> 9f9a1291…ed4a6
```

### Lab 5: The journal-replay trap (15 min)

Build an ext4 "server disk" and copy it **while it's mounted**, as you would with a live server. Its journal is left dirty:

```bash
cd ~/cases/LAB-006/work
mkfs.ext4 -q -F -L SERVER srv.img 32M
sudo mkdir -p /mnt/srv && sudo mount -o loop srv.img /mnt/srv
sudo mkdir -p /mnt/srv/var/log
for i in $(seq 1 200); do echo "line $i: sshd accepted password for root from 203.0.113.50" | sudo tee -a /mnt/srv/var/log/auth.log >/dev/null; done
sync && cp --sparse=never srv.img srv-live-copy.img     # "image" taken while mounted
sudo umount /mnt/srv
dumpe2fs -h srv-live-copy.img 2>/dev/null | grep features      # contains: needs_recovery
sha256sum srv-live-copy.img | tee srv-live-copy.sha256
```

**The wrong way:** a *writable* loop device mounted with `-o ro`:

```bash
cp srv-live-copy.img victim.img && sha256sum victim.img
L=$(sudo losetup -f --show victim.img)          # NOT read-only!
sudo mount -o ro "$L" /mnt/lab6 && sudo dmesg | tail -n 3
sudo umount /mnt/lab6 && sudo losetup -d "$L"
sha256sum victim.img                             # different!
dumpe2fs -h victim.img 2>/dev/null | grep features   # needs_recovery is gone
```

Expected `dmesg` output:

```
EXT4-fs (loop0): write access will be enabled during recovery
EXT4-fs (loop0): recovery complete
EXT4-fs (loop0): mounted filesystem … ro with ordered data mode.
```

The mount said `ro`, but the kernel **wrote to the image** to replay the journal. In a real case, the hash in your report would no longer match the evidence.

**The right way:** a read-only loop device plus `noload`:

```bash
L=$(sudo losetup -f --show -r srv-live-copy.img)
sudo mount -o ro,noload "$L" /mnt/lab6
wc -l /mnt/lab6/var/log/auth.log                 # -> 200 /mnt/lab6/var/log/auth.log
sudo umount /mnt/lab6 && sudo losetup -d "$L"
sha256sum -c srv-live-copy.sha256                # -> srv-live-copy.img: OK
```

Modern `mount -o ro,loop` creates a read-only loop device by itself. Then the kernel *refuses* to mount (`write access unavailable, cannot proceed (try mounting with noload)`), which is safe but confusing the first time you see it. `noload` is the fix.

### Lab 6: xmount: one E01, many virtual formats (15 min)

```bash
cd ~/cases/LAB-006/images
sha256sum LAB006_EV001.E01 > ../notes/e01-file.sha256       # container hash, to prove xmount never changes it

# 1. Raw view
sudo xmount --in ewf LAB006_EV001.E01 /mnt/xm
ls -l /mnt/xm                                     # LAB006_EV001.dd + LAB006_EV001.info
sudo sha256sum /mnt/xm/LAB006_EV001.dd            # -> 9f9a1291…ed4a6
sudo cat /mnt/xm/LAB006_EV001.info                # case metadata and MD5 from the E01
sudo umount /mnt/xm

# 2. A VirtualBox disk with a write cache (what you'd attach to an isolated VM)
sudo xmount --in ewf LAB006_EV001.E01 --out vdi --cache ../work/LAB006.cache /mnt/xm
file /mnt/xm/LAB006_EV001.vdi                     # -> VirtualBox Disk Image … 67108864 bytes
sudo umount /mnt/xm

# 3. Write to the virtual disk: the change lands in the cache, not in the E01
sudo xmount --in ewf LAB006_EV001.E01 --out raw --cache ../work/LAB006.cache /mnt/xm
printf 'TAMPER' | sudo dd of=/mnt/xm/LAB006_EV001.dd bs=1 seek=$((2048*512+3)) conv=notrunc status=none
sudo sha256sum /mnt/xm/LAB006_EV001.dd            # changed (virtual view only)
sudo umount /mnt/xm
sha256sum -c ../notes/e01-file.sha256             # -> LAB006_EV001.E01: OK
ls -l ../work/LAB006.cache                        # the write went here
```

To boot a real Windows image the same way, create a VirtualBox VM with **no network**, attach `/mnt/xm/<name>.vdi` as an existing disk, and boot. Every change stays in the cache file. (Mount with `-o allow_other` and enable `user_allow_other` so VirtualBox, running as your user, can open the file.)

### Lab 7: Arsenal Image Mounter on Windows (15 min, not run by the author)

1. Copy `LAB006_EV001.E01` to `C:\Cases\LAB-006\` on the Windows VM.
2. In AIM, **Mount disk image** → `LAB006_EV001.E01` → **Read only**.
3. Run `Get-Disk | Format-Table Number,FriendlyName,IsReadOnly,Size` to see the new read-only 64 MB disk, and open the **SUSPECT** volume in Explorer.
4. Compare with **FTK Imager → File → Image Mounting** (mount type *Physical & Logical*, method *Block Device / Read Only*). Which tool exposes the whole disk? Which only volumes?
5. Dismount everything and re-verify the E01 (`ewfverify` on SIFT, or FTK Imager *Verify Drive/Image*). It must still say SUCCESS.

*Labs 1–6 were run on Ubuntu 24.04 and their output above is real (except the vfat kernel mount, as noted). Lab 7 wasn't run.*

---

## ✅ Knowledge check

1. Name three sections of an E01 file and what each holds.
2. Your acquisition used SHA-256, but `ewfverify` shows `SHA256 hash stored in file: N/A`. Is something wrong? Where's the SHA-256?
3. `ewfverify` reports `FAILURE` but the stored and calculated MD5 are equal. How is that possible, and what do you do?
4. Why is `mount -o ro` on a writable loop device dangerous for an ext4 image? Give the safe command sequence.
5. Which mount options make NTFS (ntfs-3g) show `$MFT` and Alternate Data Streams?
6. What does xmount's `--cache` do, and why is it essential for booting an image?
7. Why can Arsenal Image Mounter expose Volume Shadow Copies when mounting just a volume often can't?
8. Converting E01 → raw with `ewfexport`: which hash proves the conversion is faithful?

<details>
<summary><b>Answers</b></summary>

1. Any three: `header`/`header2` (case metadata), `volume`/`disk` (media info), `sectors` (chunk data), `table`/`table2` (chunk offsets), `hash`/`digest` (MD5/SHA-1 of the media), `error2` (read errors), `done`/`next`.
2. Nothing's wrong: the E01 (EnCase 6) format stores only MD5 and SHA-1. The SHA-256 is in the **acquisition log** (and ewfverify recalculates it for you to compare).
3. One or more chunks failed their **checksum** (damage localised to a sector range). In this case the damaged chunk held zeros, so the overall hash didn't change. Treat the image as damaged: restore from your second copy and re-verify, and document it.
4. The kernel can **replay the journal** (`needs_recovery`) and write to the image, changing its hash. Safe: `losetup -f --show -r image` (add `-o OFFSET` for a partition), then `mount -o ro,noload /dev/loopX /mnt/x`, and hash before and after.
5. `-o ro,show_sys_files,streams_interface=windows`.
6. It redirects every write to a separate cache file, so the virtual disk appears writable while the image never changes. Operating systems write constantly while booting.
7. AIM mounts the **entire disk** as a real SCSI disk, so Windows recognises the volumes and their shadow-copy storage, just as with a physical disk.
8. The **data hash**: `ewfexport` prints the MD5 calculated over the data, and `sha256sum` of the raw output must equal the acquisition SHA-256.

</details>

---

## 📚 Further reading

- libewf documentation, *Expert Witness Compression Format (EWF)* and *EWF2* specifications: https://github.com/libyal/libewf/tree/main/documentation
- libyal wiki, *Building* libewf: https://github.com/libyal/libewf/wiki/Building
- Arsenal Image Mounter product page and FAQ: https://ArsenalRecon.com/weapons/image-mounter
- `man mount`, the ext4 options `noload` / `norecovery`; the kernel docs `Documentation/filesystems/ext4.rst`
- SANS DFIR blog posts on mounting E01s and dealing with dirty journals
- xmount project page: https://www.pinguin.lu/xmount

---

## ⏭️ Tomorrow: Day 07

**Data recovery & file carving**. Tools: **PhotoRec**, **Foremost**, **Scalpel**.
When the file system can't help (ext4 deletes, formatted drives, unallocated space), we carve files straight out of raw sectors using their signatures (Day 3), and learn about fragmentation, false positives and validation.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
