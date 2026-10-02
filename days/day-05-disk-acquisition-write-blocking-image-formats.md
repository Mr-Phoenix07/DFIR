# Day 05: Disk Acquisition: Physical vs Logical, Write Blocking & Image Formats (raw/E01/AFF4)

> **Phase 1: Foundations** · **Level:** 🟢 Beginner → 🟡 Intermediate · **Time:** ~3–4 hours (reading + labs) · **Posted:** 2026-10-02
>
> **Tools today:** 🛠️ FTK Imager · 🛠️ Guymager · 🛠️ dc3dd

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Choose between **physical, logical, targeted and live** acquisition, and justify the choice.
2. Explain how **hardware and software write blockers** work, and what they *don't* protect against.
3. Compare **raw (dd), E01/Ex01, AFF/AFF4, SMART and AD1** image formats.
4. Prepare destination media, document the source drive, and **verify** an acquisition with hashes.
5. Handle the difficult cases: **bad sectors, HPA/DCO, SSDs, encryption, RAID and very large disks**.
6. Acquire images with **FTK Imager**, **Guymager** and **dc3dd**, and read their logs like an examiner.

---

## Part 1: The lesson

### 1.1 What "acquisition" means

**Acquisition** creates a forensically sound copy of evidence: **complete**, **verified by hashes**, **documented**, and made **without changing the source** (or with every unavoidable change recorded).

```
 ┌──────────────┐   write    ┌────────────────┐   read-only   ┌──────────────┐     ┌───────────────┐
 │ Source drive │──blocker──▶│ Imaging host   │──────────────▶│ Image file(s)│────▶│ Verify hashes │
 │ (evidence)   │            │ (SIFT/FTK etc.)│  hash on the  │ on a clean   │     │ source=image  │
 └──────────────┘            └────────────────┘  fly          │ target drive │     └───────────────┘
        │                            │                        └──────────────┘             │
        └── photos, labels, serial ──┴── acquisition log, tool + version, times (UTC) ─────┘
```

### 1.2 Types of acquisition

| Type | What you get | When to use it | Trade-offs |
|------|--------------|----------------|------------|
| **Physical** (full disk) | Every sector, from LBA 0 to the last: partitions, unallocated space, slack, deleted data | The default for computers and removable media you can seize | Slow for large disks; may be useless if the disk is encrypted and locked |
| **Logical** (volume / partition) | One volume as the OS sees it, e.g. `C:` | A **mounted encrypted** volume (BitLocker, FileVault, VeraCrypt) on a live system; servers you can't shut down | No unallocated space outside the volume; done on a live system |
| **Targeted / triage** | Selected files and artifacts (registry, logs, `$MFT`…) | Large-scale IR, very large servers, cloud, time pressure (Day 9: KAPE) | You can't go back for what you didn't collect |
| **Live** | Data from a running system (RAM, open files, unlocked volumes) | Running machines, encryption, malware in memory (Day 23) | Changes the system; must be documented carefully |
| **Remote** | Images or collections over the network (Velociraptor, F-Response, cloud snapshots) | Enterprise and cloud | Depends on agents and permissions; network bandwidth |

### 1.3 Write blockers

A **write blocker** lets the imaging host **read** from the evidence drive while **blocking any command that would change it**.

| Kind | Examples | Strengths | Weaknesses |
|------|----------|-----------|------------|
| **Hardware** (in-line bridge) | Tableau (OpenText), WiebeTech (CRU), CRU UltraDock | OS-independent; tested and documented; accepted in court; many show HPA/DCO and the drive's identity | Costs money; one per interface (SATA, NVMe, USB, SAS) |
| **Software (OS-level)** | Linux `blockdev --setro`, `losetup -r`, read-only udev rules; Windows `StorageDevicePolicies\WriteProtect` | Free, fast, good for USB media and images | Must be applied *before* the device mounts; OS bugs or misconfiguration can leak writes |
| **Forensic boot environments** | Paladin, CAINE, Tsurugi (booted from USB, nothing auto-mounted) | Image a machine's internal disk in place | Must be validated; the BIOS/UEFI still runs |

**Rules:**

- **Test your write blocker** regularly. NIST CFTT publishes test reports, and you can check yourself: try to write, then confirm the hash is unchanged.
- A write blocker **doesn't stop the drive itself**. SSD controllers still run garbage collection internally, and failing drives keep degrading. Image once, image fast, and hash.
- On Windows, enable USB write-protect **before** plugging in the device:

  ```powershell
  # Software write-protect for USB mass storage (run as Administrator; reconnect the device afterwards)
  New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' -Force | Out-Null
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' -Name WriteProtect -Value 1 -Type DWord
  # Remove it afterwards: set the value to 0 (or delete it)
  ```

  Then **test** it with a non-evidence USB stick first.

- On Linux, stop desktop auto-mounting on the imaging host and set the device read-only **before** anything touches it:

  ```bash
  sudo blockdev --setro /dev/sdX
  sudo blockdev --getro /dev/sdX      # 1 = read-only
  ```

### 1.4 Image formats

| Format | Extension(s) | Compression | Embedded metadata and hashes | Notes |
|--------|--------------|:-----------:|------------------------------|-------|
| **Raw / dd** | `.dd`, `.raw`, `.img`, `.001` (split) | ❌ | ❌ (keep a separate log and hash files) | Universal: every tool reads it. Same size as the disk. Hash of the image = hash of the disk |
| **E01** (EnCase Expert Witness / EWF) | `.E01`, `.E02` … | ✅ | ✅ case info, examiner, notes, **MD5 (+SHA-1)** of the acquired data, **per-chunk checksums** | The de-facto standard. Read by almost every tool (libewf). Segmented |
| **Ex01** (EWF2) | `.Ex01` | ✅ | ✅ (and optional encryption) | Newer EnCase format; less universal tool support |
| **AFF / AFF4** | `.aff`, `.aff4` | ✅ | ✅ | Open formats. Classic AFF is **deprecated** (its author recommends against it, and Guymager disables it by default). AFF4 is used by some tools for disk and memory images |
| **SMART** | `.s01` | ✅ | ✅ | Legacy (ASR Data); FTK Imager can still write it |
| **AD1** | `.ad1` | ✅ | ✅ | FTK **logical** "custom content" container: selected files only. **Not a disk image** |
| **VMDK / VHD(X)** | | | | Virtual disks from VMs or cloud. Analysable directly (TSK supports VMDK/VHD) or convert to raw |

**Remember from Day 2:** an E01's internal MD5 is the hash of the *acquired data*, not of the `.E01` file. Verify E01s with tools that read the stored hash (`ewfverify`, FTK Imager *Verify Drive/Image*, Autopsy's *Data Source Integrity*), never by hashing the file.

### 1.5 The acquisition procedure

1. **Authorisation and scope** confirmed (Day 1).
2. **Photograph** the device: labels, serial number, connectors and damage.
3. **Prepare destination media:**
   - Use a known-clean, **wiped and verified** drive (Lab 5), or a dedicated evidence NAS.
   - Format it with exFAT or NTFS (FAT32 can't hold files over 4 GiB), and give it enough space (≥ source size for raw).
4. **Connect through a write blocker.** Record its make, model and firmware.
5. **Identify the source:**

   ```bash
   lsblk -o NAME,SIZE,RO,TYPE,MODEL,SERIAL,TRAN
   sudo hdparm -I /dev/sdX | grep -E 'Model|Serial|Firmware|sectors'
   sudo smartctl -i /dev/sdX        # also SMART health: a failing drive changes your plan
   ```

6. **Check for hidden areas:**

   ```bash
   sudo hdparm -N /dev/sdX            # "max sectors = A/B": A < B means an HPA is set
   sudo hdparm --dco-identify /dev/sdX
   ```

   If an HPA or DCO is present, document it. Use a tool or blocker that can image the full native size, or temporarily expose the hidden area (a **volatile** change, e.g., `hdparm -N` without the `p` prefix) and record exactly what you did.

7. **Acquire** with hashing enabled (two algorithms), logging, and the correct sector size.
8. **Verify:** the image hash must equal the source hash. Then re-verify the image before analysis (Day 2).
9. **Document:** tool and version, command or settings, start and end times (UTC), hashes, errors and bad sectors, and the chain of custody.

### 1.6 Difficult cases

| Problem | What to do |
|---------|------------|
| **Bad sectors** | Forensic imagers record them and fill them with zeros (dc3dd logs `N bad sectors replaced by zeros`). For badly failing drives, use **GNU ddrescue** with a map file (`ddrescue -d -r3 /dev/sdX image.dd image.map`) and document that source and image hashes can't match |
| `dd conv=noerror,sync` with a large `bs` | One unreadable sector zero-fills the **whole block** (e.g., 4 MiB), so you lose good data. Use forensic tools, or a small block size |
| **SSD / NVMe** | Image immediately (TRIM and garbage collection, Day 3). NVMe needs an NVMe-capable write blocker or a forensic boot environment. Watch the sector size (`ssz=`) |
| **Encryption** (BitLocker, FileVault, VeraCrypt, LUKS) | If the machine is running and unlocked: capture RAM (keys!) and take a **logical** image of the mounted volume. If it's off: take a physical image, then look for recovery keys (AD, Entra ID, MDM, the user's printout) |
| **RAID / hardware arrays** | Image each member disk *and*, if possible, the logical array presented by the controller. Record the controller settings |
| **Very large disks / time pressure** | Targeted collection first (Day 9), physical image later; compressed E01; image in parallel to two destinations (Lab 3) |
| **Apple T2 / Apple silicon Macs** | Internal storage is hardware-encrypted and tied to the Mac. Acquisition is usually logical (Day 37) |
| **Cloud / virtual machines** | Disk snapshots, exported VHD/VMDK files, provider APIs (Days 55–57) |

### 1.7 What a good acquisition log contains

Every forensic imager writes one. Keep it with the image and quote it in your report:

- Tool name and **version**, the exact command line or settings, and the operating system.
- Source identity (model, serial, size, sector size) and destination path(s).
- Start and end time (with time zone).
- Sectors read and written, **bad sectors**, and errors.
- **Hashes** (source, and each output verified: `[ok]` or `[MISMATCH]`).
- Case metadata: case number, evidence number, examiner, notes.

---

## Part 2: Tools

---

### 🛠️ Tool 1: FTK Imager

| | |
|---|---|
| **What** | Exterro's (formerly AccessData's) free imaging and preview tool. It creates **raw, E01, SMART and AFF** images of physical drives, logical drives and folders, makes **AD1** custom-content images, **captures RAM**, verifies images, mounts images read-only, and previews file systems |
| **Why in DFIR** | The most widely used free imager on Windows. It's simple, well documented and accepted by courts and teams worldwide. Its image summary `.txt` files are the classic acquisition record |
| **Platforms** | Windows (64-bit). A macOS edition is also offered |
| **Licence** | Freeware (proprietary) |
| **Home** | https://www.exterro.com/digital-forensics-software/ftk-imager |

#### Installation (Windows analysis or imaging workstation)

1. Go to the FTK Imager page above and fill in the short download form. You get a download link by email or on the page.
2. **Record the installer's SHA-256** in your tool log (`Get-FileHash .\<installer>.exe -Algorithm SHA256`).
3. Run the installer as Administrator and accept the defaults.
4. Start **FTK Imager** as **Administrator**; it needs raw access to drives.

> Installing tools on a *suspect* machine changes it. For live acquisition, run FTK Imager from **external media** (prepared on your workstation) and document that you did so, including its version and when you ran it.

#### Configuration and key options

FTK Imager has few global settings. The important choices are made in the **Create Image** wizard:

| Wizard step | Recommended choice |
|-------------|--------------------|
| **Select Source** | *Physical Drive* (full disk) · *Logical Drive* (one volume, e.g. an unlocked BitLocker `C:`) · *Image File* (convert or verify) · *Contents of a Folder* (logical) |
| **Image Type** | **E01** (compressed, with metadata and embedded hash) or **Raw (dd)** for maximum compatibility |
| **Evidence Item Information** | Case number, evidence number, unique description, examiner, notes. These are stored inside the E01 |
| **Image Destination** | Folder on the clean target drive; file name `CASEID_EVxxx`. *Image Fragment Size* (MB): split size for the segments (set it to fit the target file system). *Compression* 0–9 (E01: 6 is a good balance) |
| **Options** | ✅ **Verify images after they are created** · ✅ *Precalculate Progress Statistics* · optionally *Create directory listings of all files in the image* |

When it finishes, FTK Imager shows the **verification result** (computed vs. stored MD5/SHA-1) and writes a **`<image>.txt`** summary next to the image with the case information, source drive details, hashes and any bad sectors. Keep that file with the image.

#### Other features you'll use

- **File → Capture Memory:** RAM to a `.mem` file, optionally with `pagefile.sys` (Day 23).
- **File → Verify Drive/Image:** re-verifies an E01 against its embedded hashes.
- **File → Image Mounting:** mounts an image **read-only** as a drive letter (Day 6).
- **File → Add Evidence Item:** previews a drive or image read-only and exports files, with their hashes listed in the export summary.

#### Verify the installation

Plug in a **non-evidence** USB stick and:

1. **File → Create Disk Image → Physical Drive** → the USB stick → Raw (dd), with *Verify images after they are created* ticked.
2. The verification window must show **Match** for MD5 and SHA-1.
3. Open the generated `.txt` summary. It should list the drive model, serial number, sector count and the hashes.

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| The drive isn't listed | Run as Administrator; check the write blocker's power and cable; try *Logical Drive* if the physical drive is locked by encryption |
| The image is much smaller than expected | You chose *Logical Drive* or *Contents of a Folder* instead of *Physical Drive* |
| Verification **mismatch** | Failing source drive (check the `.txt` for bad sectors), an unstable USB connection, or a changing source (live system, SSD). Re-image to a different target, and document both attempts |
| The target fills up | Use E01 compression, a bigger target, or a smaller fragment size on file systems with file-size limits |

---

### 🛠️ Tool 2: Guymager

| | |
|---|---|
| **What** | A fast, open-source **graphical imager for Linux**, by Guy Voncken (Bundeskriminalamt). It writes **raw (dd), EWF/E01** (and AFF if enabled), uses multi-threaded compression, calculates **MD5/SHA-1/SHA-256**, verifies the source and the image, detects **HPA/DCO**, and writes a detailed `.info` acquisition report |
| **Why in DFIR** | The standard GUI imager on forensic Linux distributions (SIFT, CAINE, Paladin). It's very fast thanks to parallel compression and hashing, and it's simple to use under pressure |
| **Platforms** | Linux (Qt GUI) |
| **Licence** | GPL-2.0 |
| **Home** | https://guymager.sourceforge.io |

#### Installation

**SIFT / Ubuntu / Debian / Kali:**

```bash
sudo apt update && sudo apt install -y guymager
dpkg -l guymager | tail -n 1        # Ubuntu 24.04: 0.8.13
```

Other distributions: use the distro package if available, or build from the SourceForge sources.

#### Configuration

Guymager reads **`/etc/guymager/guymager.cfg`**. Don't edit that file; put your changes in **`/etc/guymager/local.cfg`** (or `./local.cfg`), which overrides it. Useful settings, with names taken from the shipped config file:

```bash
sudo tee /etc/guymager/local.cfg >/dev/null <<'EOF'
REM Local overrides for Guymager (this file overrides /etc/guymager/guymager.cfg)
Language        = 'en'
DefaultFormat   = EWF
EwfCompression  = FAST
REM Never let anyone image the examiner's own disks by mistake:
TABLE LocalDevices NoName
   '/dev/nvme0n1'
ENDTABLE
EOF
```

| Setting | Meaning |
|---------|---------|
| `DefaultFormat` | `EWF` (default) or `DD` |
| `EwfFormat` | `Guymager` (its own fast E01 writer, the default) or, if built with libewf, `Encase6`, `FTK`, … |
| `EwfCompression` | `FAST` / `BEST` / `NONE` |
| `EwfNaming` | Segment naming once `.E99` is passed (`FTK` style by default) |
| `AffEnabled` | `false` by default. AFF is deprecated, so leave it off |
| `TABLE LocalDevices` | Devices that are **marked and blocked** from acquisition (your own disks) |
| `TABLE HiddenDevices` | Devices that are hidden completely |
| `QueryDeviceMediaInfo` | `on`: queries HPA/DCO information (shown in the *HiddenAreas* column) |
| `DirectIO` | `off` by default. Guymager switches to direct I/O automatically around bad sectors |

#### Using Guymager

```bash
sudo guymager          # needs root for raw device access
```

1. The main window lists the block devices with model, serial, size and **HiddenAreas** (HPA/DCO). Your `LocalDevices` entries are coloured and can't be acquired.
2. Right-click the evidence drive → **Acquire image**.
3. In the dialog, choose:
   - **File format:** *Expert Witness Format (EWF/E01)* (split size, e.g., 2 GiB) or *Linux dd raw image* (optionally split).
   - **Case and evidence fields:** case number, evidence number, examiner, description, notes.
   - **Destination** directory and image/info file names.
   - **Hash calculation:** tick MD5 and **SHA-256**.
   - ✅ *Re-read source after acquisition for verification* · ✅ *Verify image after acquisition*.
4. Watch the progress, speed and state columns. When it finishes, the state shows **Finished – verified & ok** (or a clear error).
5. Open the **`.info`** file next to the image: device details, HPA/DCO, bad sectors, start and end times, and hashes for the source, the image and the verification.

#### Verify the installation

```bash
guymager --help 2>&1 | head -n 3 || true    # the GUI may not print help; just make sure it launches:
sudo guymager &
```

Then acquire a **non-evidence** USB stick to E01 with both verification options ticked, and check that the `.info` file reports matching hashes.

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| No devices shown | Start it with `sudo`; press *Rescan*; check `DeviceScanMethod` (default `libudev`) |
| A device is greyed out or can't be acquired | It's listed in `LocalDevices`, or another program holds it open |
| "Can't write" to the destination | Destination permissions, or a FAT32 target with a split size over 4 GiB |
| No HPA/DCO information | The USB bridge doesn't pass ATA commands through. Use a forensic bridge or a direct SATA connection |
| Slow | Use `EwfCompression = FAST`; check the USB 3 link; consider `DirectIO` (slower on some SSDs) |

---

### 🛠️ Tool 3: dc3dd

| | |
|---|---|
| **What** | A forensic version of GNU `dd` developed by the US DoD Cyber Crime Center (DC3). It adds **on-the-fly hashing** (MD5, SHA-1, SHA-256, SHA-512), **verification of the output** (`hof=`), **split output**, multiple simultaneous outputs, **bad-sector handling and logging**, piecewise hashes, and **verified wiping** |
| **Why in DFIR** | Scriptable, transparent command-line acquisition with a clear log. It runs on any Linux, including forensic boot USBs, servers and headless systems |
| **Platforms** | Linux (and other Unix-like systems via source) |
| **Licence** | GPL-3.0-or-later |
| **Home** | https://sourceforge.net/projects/dc3dd/ |

#### Installation

**SIFT / Ubuntu / Debian / Kali:**

```bash
sudo apt update && sudo apt install -y dc3dd
dc3dd --version | head -n 1          # Ubuntu 24.04: dc3dd 7.2.646
```

**Related tools** (same package manager): `dcfldd` (another forensic dd: `hash=`, `hashlog=`, split output) and `gddrescue` (GNU ddrescue, for failing drives).

#### Configuration: the options that matter

All options are `key=value` and listed in `dc3dd --help`:

| Option | Meaning |
|--------|---------|
| `if=DEVICE` | Input device or file |
| `of=FILE` | Plain output |
| **`hof=FILE`** | Output **plus hashing and verification against the input hash**. Use this instead of `of=` |
| `ofs=BASE.000` / **`hofs=BASE.000`** + `ofsz=2G` | **Split** output (`.000`, `.001`, …), verified with `hofs=` |
| `hash=md5 hash=sha256` | Hash algorithms (repeat for more than one: `md5`, `sha1`, `sha256`, `sha512`) |
| **`log=FILE`** | Write the acquisition log (statistics, bad sectors, hashes) |
| `hlog=FILE` / `mlog=FILE` | Hash-only log / machine-readable log |
| `ssz=4096` | Force the sector size (otherwise it's probed; 512 for files) |
| `rec=off` | Stop at the first bad sector instead of zero-filling it |
| `iskip=`, `cnt=` | Skip or limit sectors (to work around unreadable regions) |
| `wipe=DEV` / **`hwipe=DEV`** | Wipe a device with zeros (or `pat=` / `tpat=`); `hwipe` also **verifies** the wipe |
| `verb=on` | Per-file detail for split sets |
| `corruptoutput=on` | **Demo only:** deliberately corrupt the output to show a verification failure |

> ⚠️ **Check the log, not just the exit code.** In testing, dc3dd 7.2.646 exited with status **0** even when it reported `[MISMATCH]` (Lab 4). Always read the `output results` section.

#### Verify the installation

```bash
dc3dd --version | head -n 1
dc3dd if=/dev/zero cnt=2048 hof=/tmp/zero.dd hash=sha256 log=/tmp/zero.log 2>/dev/null; grep -A3 "output results" /tmp/zero.log
```

You should see `[ok] 30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58 (sha256)`, the SHA-256 of 1 MiB of zeros.

#### Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Permission denied` on `/dev/sdX` | Use `sudo`. Disk devices are root- or disk-group-only |
| `[MISMATCH]` in the output results | Bad target media, an unstable connection, or a changing source. Re-image to different media and record both attempts |
| `N bad sectors replaced by zeros` | Expected on failing drives. Record it; for severe damage, switch to ddrescue with a map file |
| Wrong size for 4Kn disks | Add `ssz=4096` |
| You need E01 instead of raw | Use Guymager or `ewfacquire` (Day 6), or convert the raw image later |

---

## Part 3: Hands-on labs

These labs run on **SIFT** or Ubuntu (they use loop devices, so `sudo` is needed). Set your VM to **UTC** (Day 1) so your hashes match the ones shown.

```bash
sudo apt install -y dc3dd dcfldd dosfstools mtools sleuthkit
mkdir -p ~/cases/LAB-005/{evidence,images,notes,work} && cd ~/cases/LAB-005
```

### Lab 1: Build a "suspect USB" and write-block it (15 min)

The image below is **deterministic**. Built on a UTC system, it always has the same SHA-256, so you can check every step against the expected output.

```bash
cd ~/cases/LAB-005/evidence
truncate -s 64M suspect-usb.raw
printf 'label: dos\nlabel-id: 0x5005b00c\nstart=2048, type=c\n' | sfdisk -q suspect-usb.raw
mkfs.vfat -F 32 --invariant -i 2026DF1A --offset=2048 -h 2048 -n SUSPECT suspect-usb.raw 129024 >/dev/null 2>&1
printf 'employee,amount\nalice,4200\nbob,3900\n' > /tmp/payroll.csv
touch -d "2026-09-30 17:45:10 UTC" /tmp/payroll.csv
TZ=UTC mcopy -m -i suspect-usb.raw@@1M /tmp/payroll.csv ::/
sha256sum suspect-usb.raw
```

Expected output:

```
9f9a1291cbb96c0262c58627bf3b047f6044d121130a0c169ff21272576ed4a6  suspect-usb.raw
```

Attach it as a **read-only block device**, the software equivalent of plugging the stick into a write blocker:

```bash
DEV=$(sudo losetup -f --show -r suspect-usb.raw); echo "$DEV"     # e.g. /dev/loop0
sudo blockdev --getro "$DEV"                                       # -> 1 (read-only)
lsblk -o NAME,SIZE,RO,TYPE "$DEV"
sudo dd if=/dev/zero of="$DEV" bs=512 count=1                      # try to write...
```

Expected output of the write attempt:

```
dd: error writing '/dev/loop0': Operation not permitted
```

Record the device details in `notes/` (on real drives, also run `hdparm -I`, `smartctl -i`, `hdparm -N` and `hdparm --dco-identify`).

### Lab 2: Acquire with dc3dd and read the log (15 min)

```bash
cd ~/cases/LAB-005
sudo dc3dd if="$DEV" hof=images/LAB005_EV001.dd hash=md5 hash=sha256 log=images/LAB005_EV001.log
sudo chown "$USER": images/*
cat images/LAB005_EV001.log
```

Expected log (the times and the `/dev/loop` number will differ):

```
dc3dd 7.2.646 started at 2026-10-02 08:48:42 +0000
compiled options:
command line dc3dd if=/dev/loop0 hof=images/LAB005_EV001.dd hash=md5 hash=sha256 log=images/LAB005_EV001.log
device size: 131072 sectors (probed),       67,108,864 bytes
sector size: 512 bytes (probed)
    67108864 bytes ( 64 M ) copied ( 100% ), 1.00424 s, 64 M/s
    67108864 bytes ( 64 M ) hashed ( 100% ), 0.40089 s, 160 M/s

input results for device `/dev/loop0':
   131072 sectors in
   0 bad sectors replaced by zeros
   3296a7680ec04f493a57ec50b4dbfd9e (md5)
   9f9a1291cbb96c0262c58627bf3b047f6044d121130a0c169ff21272576ed4a6 (sha256)

output results for file `images/LAB005_EV001.dd':
   131072 sectors out
   [ok] 3296a7680ec04f493a57ec50b4dbfd9e (md5)
   [ok] 9f9a1291cbb96c0262c58627bf3b047f6044d121130a0c169ff21272576ed4a6 (sha256)
```

Read it like an examiner:

- **Sector size probed** as 512, and **131,072 sectors** in = 131,072 out.
- **0 bad sectors**.
- **Input hash = output hash**, and both are marked `[ok]`.
- The input SHA-256 equals the hash of the original `suspect-usb.raw` from Lab 1, so the "device" was never changed.

Prove you can analyse the image (and not the device):

```bash
chmod 444 images/LAB005_EV001.dd
mmls images/LAB005_EV001.dd
fls -o 2048 images/LAB005_EV001.dd      # -> r/r 4: payroll.csv
```

### Lab 3: Split images and two destinations at once (10 min)

For large cases, image to two drives at the same time (a working copy and a master copy), splitting one of them into 16 MiB pieces (2 GiB or more in real life):

```bash
mkdir -p images/split images/copy2
sudo dc3dd if="$DEV" hofs=images/split/LAB005_EV001.000 ofsz=16M hof=images/copy2/LAB005_EV001.dd \
     hash=sha256 log=images/LAB005_EV001-split.log
sudo chown -R "$USER": images
sed -n '/input results/,$p' images/LAB005_EV001-split.log
```

Expected output:

```
input results for device `/dev/loop0':
   131072 sectors in
   0 bad sectors replaced by zeros
   9f9a1291cbb96c0262c58627bf3b047f6044d121130a0c169ff21272576ed4a6 (sha256)
      277f29f8c0d938810e3443c11e281d70196b22c777baeac8ce699478ca7ae598, sectors 0 - 32767
      080acf35a507ac9849cfcba47dc2ad83e01b75663a516279c8b9d243b719643e, sectors 32768 - 65535
      080acf35a507ac9849cfcba47dc2ad83e01b75663a516279c8b9d243b719643e, sectors 65536 - 98303
      080acf35a507ac9849cfcba47dc2ad83e01b75663a516279c8b9d243b719643e, sectors 98304 - 131071

output results for files `images/split/LAB005_EV001.000':
   131072 sectors out
   [ok] 9f9a1291cbb96c0262c58627bf3b047f6044d121130a0c169ff21272576ed4a6 (sha256)
      [ok] 277f29f8…, sectors 0 - 32767, `images/split/LAB005_EV001.000'
      [ok] 080acf35…, sectors 32768 - 65535, `images/split/LAB005_EV001.001'
      ...
output results for file `images/copy2/LAB005_EV001.dd':
   131072 sectors out
   [ok] 9f9a1291cbb96c0262c58627bf3b047f6044d121130a0c169ff21272576ed4a6 (sha256)
```

Two things to notice:

- **Piecewise hashes** for each split file (Day 2, §1.10).
- Pieces 2–4 have the **same** hash: they're all zeros (empty space). Identical hashes mean identical content.

Reassemble the split image and confirm it's identical to the device:

```bash
cat images/split/LAB005_EV001.0* | sha256sum      # -> 9f9a1291…ed4a6
```

TSK can also read split raw images directly: `mmls images/split/LAB005_EV001.0*`.

### Lab 4: What a failed verification looks like (5 min)

dc3dd has a demonstration switch that deliberately corrupts the output:

```bash
sudo dc3dd if="$DEV" hof=work/corrupt.dd hash=sha256 corruptoutput=on log=work/corrupt.log; echo "exit code: $?"
sed -n '/output results/,$p' work/corrupt.log
```

Expected output:

```
exit code: 0
output results for file `work/corrupt.dd':
   131072 sectors out
   [MISMATCH] 9606bd29d3d973d95da5f35d9fee1a1f39700fbcc57c555a0f9f2828afa4a2ed (sha256)
```

The **exit code is 0** even though verification failed. A script that only checks `$?` would report success. Always check the log, for example:

```bash
grep -q MISMATCH work/corrupt.log && echo "VERIFICATION FAILED - do not use this image"
```

### Lab 5: Wipe and verify destination media (10 min)

Before imaging, prove your target media holds no leftover data from previous cases (cross-contamination). Here a file stands in for the target drive:

```bash
cd ~/cases/LAB-005/work
head -c 8M /dev/urandom > old-target.raw                 # "used" media full of old data
T=$(sudo losetup -f --show old-target.raw)
sudo dc3dd hwipe="$T" hash=sha256 log=wipe.log
sed -n '/input results/,$p' wipe.log
sudo losetup -d "$T"
```

Expected output:

```
input results for pattern `00':
   16384 sectors in
   2daeb1f36095b44b318410b3f4e8b5d989dcc7bb023d1426c492dab0a3053e74 (sha256)

output results for device `/dev/loop1':
   16384 sectors out
   [ok] 2daeb1f36095b44b318410b3f4e8b5d989dcc7bb023d1426c492dab0a3053e74 (sha256)
```

`2daeb1f3…3e74` is the SHA-256 of **8 MiB of zeros**. The `[ok]` proves every sector now reads back as zero. Keep `wipe.log` as your media-preparation record.

**Clean up:**

```bash
sudo losetup -d "$DEV"
```

### Lab 6: GUI imagers (20 min, not run by the author)

1. **Guymager (SIFT):** `sudo losetup -f --show -r ~/cases/LAB-005/evidence/suspect-usb.raw`, then `sudo guymager`. If the loop device is listed, acquire it as **E01** with MD5 and SHA-256 and both verification options ticked. (Some setups don't list loop devices; use a spare USB stick instead.) Compare the SHA-256 in the `.info` file with Lab 1's. For raw data they must match; for E01, compare the hash of the *acquired data*, which Guymager reports.
2. **FTK Imager (Windows):** copy `suspect-usb.raw` to the Windows VM and use **File → Create Disk Image → Image File** (converting raw to E01 with case details), or image a spare USB stick. Tick *Verify images after they are created*, then open the `.txt` summary.

*Lab 6 wasn't run by the author; Labs 1–5 were run, and their output above is real.*

---

## ✅ Knowledge check

1. A laptop is running with BitLocker unlocked. Which acquisition types do you perform, and in what order?
2. Give one advantage and one weakness of a software write blocker compared with a hardware one.
3. Why is hashing an `.E01` file with `sha256sum` *not* a valid way to verify the evidence?
4. What does `hof=` do in dc3dd that `of=` doesn't?
5. Why can `dd conv=noerror,sync bs=4M` lose good data on a drive with one bad sector?
6. `hdparm -N` shows `max sectors = 976771055/976773168`. What does it mean, and what do you do?
7. In Lab 3, why did three split pieces have the same SHA-256?
8. Why should you never rely on dc3dd's exit code alone?
9. Why wipe and verify destination media before imaging?

<details>
<summary><b>Answers</b></summary>

1. Capture RAM first (encryption keys, processes), then take a **logical** image of the unlocked volume. If policy allows, also take a physical image after shutdown (it will be encrypted, but complete). Document the order and the reasons.
2. Advantage: free and quick, good for USB media and images. Weakness: it depends on the OS behaving correctly, must be applied before mounting, and is harder to defend than a tested hardware device.
3. The E01 file contains headers, compression and metadata. Its internal MD5/SHA-1 is the hash of the *acquired data*. Use `ewfverify`, FTK Imager *Verify*, or Autopsy *Data Source Integrity*.
4. It hashes what was written to the output and **compares it with the input hash** (`[ok]` / `[MISMATCH]`).
5. With `sync`, an unreadable read is padded with zeros for the **whole block size**, so up to 4 MiB of readable data around the bad sector is replaced by zeros.
6. An **HPA** is hiding 2,113 sectors. Document it, then acquire the full native size (a tool or blocker that supports HPA, or a volatile `hdparm -N` change, recorded) so the hidden area is included.
7. Those pieces contain only zeros (empty space). Identical content always gives identical hashes.
8. Version 7.2.646 exited with status 0 even after reporting `[MISMATCH]`. Verification status is only in the log.
9. To prevent **cross-contamination**: leftover data from an old case could end up in, or be confused with, the new evidence. A verified wipe log proves the media was clean.

</details>

---

## 📚 Further reading

- NIST **Computer Forensics Tool Testing (CFTT)**: test reports for disk imagers and hardware and software write blockers: https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt
- SWGDE, *Best Practices for Computer Forensic Acquisitions*: https://www.swgde.org
- ISO/IEC 27037: acquisition and preservation of digital evidence
- libewf documentation, *Expert Witness Compression Format* specification: https://github.com/libyal/libewf/tree/main/documentation
- Guymager homepage and FAQ: https://guymager.sourceforge.io
- GNU ddrescue manual: https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html
- Bell & Boddington (2010) on SSDs, and the "contagious errors" paper referenced in Guymager's config, on imaging drives with bad sectors

---

## ⏭️ Tomorrow: Day 06

**Forensic image formats, verification & mounting images**. Tools: **libewf (ewf-tools)**, **Arsenal Image Mounter**, **xmount**.
We'll create and verify E01 images on the command line, inspect their metadata, and mount raw and E01 images read-only on Linux and Windows.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
