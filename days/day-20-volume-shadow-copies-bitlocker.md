# Day 20: Volume Shadow Copies & BitLocker Volumes

> **Phase 2: Windows Forensics** · **Level:** 🟡 Intermediate · **Time:** ~3.5 hours (reading + labs) · **Posted:** 2026-10-17
>
> **Tools today:** 🛠️ libvshadow (vshadowinfo, vshadowmount) · 🛠️ dislocker · 🛠️ ShadowExplorer

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Explain how **Volume Shadow Copies** (VSS) work, where they're stored, who creates and deletes them, and what an old snapshot can prove.
2. Find the shadow copies in a disk image and read each one **as a complete, read-only volume** on Linux.
3. Explain how **BitLocker** protects a volume (FVEK, VMK and key protectors), recognise BitLocker and BitLocker To Go volumes, and read their metadata without a key.
4. Unlock a BitLocker volume on Linux with a password, a **recovery password** or a **startup key (.BEK)**, and check the result against a second tool.
5. Know where recovery keys are kept, and what to do differently when you meet an encrypted machine that is still running.

---

## Part 1: The lesson

Two Windows features change what "the disk" means. **Shadow copies** keep earlier versions of a whole volume, so a single image can hold the same files at several points in time: before they were edited, deleted or timestomped. **BitLocker** encrypts volumes, so without the right key an image is random bytes. Both are on by default on many machines, and both are targets for attackers: ransomware deletes shadow copies, and an encrypted drive with no recovery key is a dead end.

### 1.1 Volume Shadow Copies

The **Volume Shadow Copy Service** (since Windows XP/Server 2003; the on-disk format libvshadow reads is the one used since Vista) takes **snapshots** of a volume. It doesn't copy the volume: it's **copy-on-write**. After a snapshot, before Windows overwrites a block of the live volume, the old contents of that block are saved in a **store**. Reading a snapshot means "the live volume, except for the blocks that changed since, which come from the stores of this and newer snapshots".

| Where | What |
|---|---|
| Volume offset 0x1E00 | The VSS volume header, starting with the identifier GUID `{3808876b-c176-4e48-b7ae-04046e6cc752}` (stored little-endian: `6b87 0838 76c1 484e ...`) |
| `System Volume Information\{3808876b-c176-4e48-b7ae-04046e6cc752}` | The **catalog**: one entry per snapshot, with its creation time (FILETIME, UTC) |
| `System Volume Information\{<store GUID>}{3808876b-c176-4e48-b7ae-04046e6cc752}` | One **store file** per snapshot: the saved blocks and their map |

**Who creates them:** System Restore restore points (before updates, driver and software installs, and on a schedule), Windows Backup and backup software, "Previous Versions" on file servers, administrators (`vssadmin create shadow` on servers, `wmic shadowcopy call create Volume=C:\` or PowerShell on clients). **Who removes them:** the storage limit (`vssadmin list shadowstorage`: when the area is full, the oldest snapshots go), turning System Protection off, and people:

| Command | Seen in |
|---|---|
| `vssadmin delete shadows /all /quiet` | Ransomware, almost always |
| `wmic shadowcopy delete`, PowerShell `Get-CimInstance Win32_ShadowCopy \| Remove-CimInstance` | Ransomware, wipers |
| `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB` | Shrinking the storage area deletes the snapshots that no longer fit |
| `wbadmin delete catalog -quiet`, `bcdedit /set {default} recoveryenabled No` | Often in the same script |

Look for them in process-creation events (4688, Sysmon 1: Days 14–16; Sigma has rules for each). A deleted store's blocks may still be on disk until overwritten: **vss_carver** (https://github.com/mnrkbys/vss_carver) tries to recover them.

**What a snapshot gives you:** the entire volume as it was: deleted and overwritten files, older registry hives, event logs that have since rolled over or been cleared, earlier `$MFT`, `$LogFile` and `$UsnJrnl` (Day 10), earlier versions of documents. Comparing a file's timestamps across snapshots is one of the best tests for **timestomping**: a file can't have been "created in 2019" if a snapshot from last week doesn't contain it. On WS-ALICE, a restore point taken before 2026-09-28 would show `Documents` before rclone copied it and `AppData\Local\Temp` before `rc.zip` arrived. (KAPE can collect from every shadow copy of a live volume with `--vss`.)

**Limits:** a snapshot contains only the **volume** it was taken of; files excluded from snapshots (listed under `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`, and the page and hibernation files) aren't in it; and a snapshot's time is when it was taken, not when any file in it was written.

### 1.2 BitLocker

BitLocker encrypts a whole volume, sector by sector:

| Key | Role |
|---|---|
| **FVEK** (Full Volume Encryption Key) | Encrypts the sectors. Algorithm by version: AES-CBC 128/256 **with the Elephant diffuser** (Vista, 7), AES-CBC 128/256 (8, 8.1), **AES-XTS 128/256** (Windows 10 1511 and later) |
| **VMK** (Volume Master Key) | Encrypts the FVEK. Stored several times, each copy encrypted by a different **key protector** |
| **Key protectors** | TPM (with optional PIN or startup key), **password** (data and removable drives), **recovery password** (48 digits in 8 groups of 6), **startup key / recovery key file** (`<GUID>.BEK`, often on a USB stick), **clear key** (BitLocker *suspended*: the VMK is stored unprotected) |

Any one protector unlocks the volume. In the metadata, each protector has an **identifier** (a GUID); the recovery screen shows the start of it as the "recovery key ID", and the `.BEK` file is named after it. That's how you find the right key in a list.

**Recognising it:**

| Volume | Signature | What else is there |
|---|---|---|
| BitLocker (internal drives) | `-FVE-FS-` at offset 3 (instead of `NTFS    `) | Three copies of the **FVE metadata** block (dislocker `-F 1/2/3` picks one) |
| **BitLocker To Go** (removable drives, Windows 7+) | A valid **FAT32** volume (`MSWIN4.1`): the "discovery volume" | `BitLockerToGo.exe` (a reader for old Windows versions), `autorun.inf`, `Read Me.url` and large `COV 0000. BL`-style cover files holding the encrypted volume |

The metadata, readable **without** a key, records the encryption method, the volume GUID, the creation time and a **description** such as `DESKTOP-NPM7RCA H: 7/4/2019`: the **computer name**, the drive letter and the date the drive was encrypted. For a USB drive found on a suspect, that names the machine that encrypted it.

**Where recovery keys are:** Active Directory (the `msFVE-RecoveryInformation` objects under the computer account), Microsoft Entra ID / Intune (the device's recovery keys), the user's Microsoft account (`https://account.microsoft.com/devices/recoverykey`: Windows 11 "device encryption" backs up there automatically), MBAM/Configuration Manager, and files users save or print (`BitLocker Recovery Key <ID>.TXT`). On a **running** machine with an administrator: `manage-bde -status` and `manage-bde -protectors -get C:` show the protectors and the recovery password.

**A running machine changes the plan.** While the volume is unlocked the FVEK is in memory, and the file system is readable through Windows. Capture **memory first** (Phase 3), then image the **logical** (decrypted) volume or record the recovery password, and only then shut down. Pull the plug first and you may be left with an encrypted disk and a TPM that only unlocks it inside that machine.

**Pitfalls:** "used space only" encryption leaves sectors that were free at encryption time unencrypted until they're reused (deleted data from before encryption can still be carved there); a volume in the middle of encrypting or decrypting is partly plaintext; suspended BitLocker ("clear key") can be read with no key at all.

---

## Part 2: Tools

libvshadow reads shadow copies from images on any OS; dislocker unlocks BitLocker on Linux and macOS; ShadowExplorer browses the shadow copies of a live Windows machine. Two cross-checking tools appear in the labs: **The Sleuth Kit** (Day 4) reads the file systems inside, and **libbde** (`bdeinfo`, `bdemount`) is a second, independent BitLocker implementation.

---

### 🛠️ Tool 1: libvshadow (vshadowinfo, vshadowmount)

| | |
|---|---|
| **What** | Joachim Metz's library for the VSS format, with `vshadowinfo` (lists the snapshots: IDs, creation times, sizes) and `vshadowmount` (a FUSE file system that shows each snapshot as a raw volume file, `vss1`, `vss2`...) |
| **Why in DFIR** | Reads shadow copies straight from an image, on Linux or macOS, without Windows and without changing anything; each snapshot can then go through any volume tool (TSK, ntfs-3g, Plaso) |
| **Platforms** | Linux, macOS (FUSE), Windows (Dokan support is "work in progress"); Python bindings `pyvshadow` (PyPI `libvshadow-python`) |
| **Licence** | LGPL-3.0-or-later; status "alpha" |
| **Home** | https://github.com/libyal/libvshadow |

#### Requirements

FUSE (`fuse3` or `fuse`) for `vshadowmount`; read access to the image. Ubuntu 24.04 packages version **20190323**; newer code is on GitHub and PyPI (`libvshadow-python` 20260714 at the time of writing).

#### Installation

```bash
# Ubuntu / Debian / SIFT (validated here: 20190323)
sudo apt install -y libvshadow-utils fuse3
# Newer version from source (Linux/macOS): a release tarball from https://github.com/libyal/libvshadow/releases
tar xzf libvshadow-alpha-VER.tar.gz && cd libvshadow-VER && ./configure && make && sudo make install
# Python bindings only
python3 -m pip install libvshadow-python
```

On macOS, install macFUSE first, then build from source. On Windows, mount the image with Arsenal Image Mounter (Day 6) and use Windows' own tools, or use WSL.

#### Configuration

| Option | Meaning |
|---|---|
| `-o OFFSET` | Byte offset of the NTFS volume inside a disk image (from `mmls`: start sector × 512) |
| `vshadowinfo -a` | Also show allocation information |
| `vshadowmount -X OPTS` | Extra FUSE options, e.g. `-X allow_root` so root (or another user) can read the mount |
| `-v` | Verbose; `vshadowmount -v` also stays in the foreground |

The input can be a raw image, a device, or the raw file exposed by `ewfmount` (E01, Day 6).

#### Verify the installation

```bash
vshadowinfo -V | head -n 1        # vshadowinfo 20190323
```

#### First use

```bash
mmls disk.raw                                          # find the NTFS partition, e.g. start 2048
vshadowinfo -o $((2048 * 512)) disk.raw
mkdir -p /mnt/vss && vshadowmount -o $((2048 * 512)) disk.raw /mnt/vss
fls -r -p /mnt/vss/vss1 | less                         # or: sudo ntfs-3g -o ro /mnt/vss/vss1 /mnt/vss1
fusermount -u /mnt/vss                                 # when done
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| No stores listed, or an error opening the volume | Wrong offset (point `-o` at the NTFS volume, not the disk), or there really are none: check `System Volume Information` and the event logs for deletion |
| `fuse: device not found` / permission denied | Install `fuse3`, load the module (`modprobe fuse`), add your user to the `fuse` group if your distribution needs it |
| Root can't read your mount | Mount with `-X allow_root` (needs `user_allow_other` in `/etc/fuse.conf`) |
| ntfs-3g refuses to mount `vssN` | Use `-o ro`; if NTFS is "dirty", read it with TSK (`fls`/`icat`) instead |
| Mount point busy on unmount | Unmount anything mounted on top of it first (e.g. the ntfs-3g mount of `vss1`) |

---

### 🛠️ Tool 2: dislocker

| | |
|---|---|
| **What** | Romain Coltel's BitLocker driver for Linux, macOS and FreeBSD: `dislocker` (= `dislocker-fuse`) exposes the decrypted volume as a file named `dislocker-file`; `dislocker-file` writes a decrypted copy instead; `dislocker-metadata` and `dislocker-bek` print metadata and `.BEK` contents |
| **Why in DFIR** | Unlocks BitLocker and BitLocker To Go volumes (Windows Vista, 7, 8, 8.1 and 10 per its README; AES-CBC with or without the diffuser, AES-XTS) with a password, recovery password, `.BEK` file, FVEK/VMK from memory or a clear key, **read-only** with `-r` |
| **Platforms** | Linux (packaged), macOS (Homebrew + macFUSE, from the source tree), FreeBSD |
| **Licence** | GPL-2.0 |
| **Home** | https://github.com/Aorimn/dislocker |

#### Requirements

FUSE; the BitLocker volume (or its offset in a disk image) and one key protector. Note the version shown by the program (`v0.7.2`) differs from Ubuntu 24.04's package version (`0.7.3-3.1build2`): record both in your notes.

#### Installation

```bash
# Ubuntu / Debian / SIFT (validated here)
sudo apt install -y dislocker fuse3
# Fedora (per INSTALL.md)
sudo dnf install dislocker fuse-dislocker
# From source (Linux): gcc, cmake, make, libfuse3-dev, libmbedtls-dev, ruby-dev, pkgconf, then
git clone https://github.com/Aorimn/dislocker.git && cd dislocker && cmake . && make && sudo make install
```

```bash
# macOS (per INSTALL.md, from inside the cloned source tree)
brew update && brew install Caskroom/cask/macfuse && brew install src/dislocker.rb
```

#### Configuration

| Option | Meaning |
|---|---|
| `-V VOLUME` | The BitLocker volume: a device, a partition or an image file |
| `-O OFFSET` | The volume's byte offset inside a disk image |
| `-u[PASSWORD]` | User password (prompts if empty) |
| `-p[RECOVERY_PASSWORD]` | 48-digit recovery password (prompts if empty) |
| `-f FILE.BEK` | Startup key / recovery key file |
| `-k FVEK_FILE`, `-K VMK_FILE` | The FVEK or VMK directly (e.g. extracted from memory) |
| `-c` | Clear key: a suspended BitLocker volume |
| `-r` | **Read-only**: always, on evidence |
| `-F[N]` | Use metadata block N (1, 2 or 3) |
| `-l LOG`, `-v`, `-q` | Log file; more verbose; quiet |
| `-- MOUNTPOINT` | Everything after `--` goes to FUSE; the mount point is required |

#### Verify the installation

```bash
dislocker -h 2>&1 | head -n 1        # dislocker by Romain Coltel, v0.7.2 (compiled for Linux/x86_64)
```

#### First use

```bash
mkdir -p /mnt/bl /mnt/win
dislocker -r -V disk.raw -O $((2048 * 512)) -p -- /mnt/bl        # type the recovery password at the prompt
sudo ntfs-3g -o ro /mnt/bl/dislocker-file /mnt/win               # or fls/icat on /mnt/bl/dislocker-file
# or a decrypted copy (needs as much free space as the volume):
dislocker-file -V disk.raw -O $((2048 * 512)) -p -- decrypted.ntfs
```

#### Troubleshooting

| Symptom | Fix |
|---|---|
| `Program designed only for BitLocker version 2 and less, the version here is <random number>` | Seen in Lab 3 on a Windows 7 BitLocker To Go volume: dislocker read the wrong metadata. Force a metadata block with `-F1` (or 2, 3), then cross-check the result with libbde (`bdemount`) |
| Wrong recovery password | Check you have the key for **this** volume: match the protector identifier (`bdeinfo`, `dislocker-metadata`) with the key ID |
| `dislocker-file` appears but ntfs-3g won't mount it | Mount read-only; check the NTFS boot sector (`xxd -l 16`); a partly encrypted volume is partly garbage |
| Need the image unchanged | Always `-r`; without it, writes to `dislocker-file` change the BitLocker volume |
| TPM-only system drive | The key is sealed in that machine's TPM: get the recovery password from AD/Entra/the user's account, or capture memory from the running machine |

---

### 🛠️ Tool 3: ShadowExplorer

| | |
|---|---|
| **What** | A free Windows GUI to browse the shadow copies of the machine's own volumes and export files or folders from them |
| **Why in DFIR** | The quickest way to look at and export earlier versions on a **live Windows system**, or on an image that Windows itself has mounted (for example with Arsenal Image Mounter, Day 6), without command-line work |
| **Platforms** | **Windows only** (not run in this lesson's Linux labs) |
| **Licence** | Freeware, closed source |
| **Home** | https://www.shadowexplorer.com/ |
| **Status** | Version **0.9** is the latest and has not been updated for years. It still lists Windows 10 and 11, but treat it as unmaintained, and confirm what it shows with Windows' own commands (below) |

#### Requirements

Windows Vista to 11, an **administrator** account, and shadow copies on the volume (System Protection on).

#### Installation

```powershell
# Installer or portable version from https://www.shadowexplorer.com/downloads.html, or with Chocolatey:
choco install shadowexplorer
```

#### Configuration

Choose the drive and the snapshot (by date) from the two drop-down lists at the top. Right-click a file or folder and choose **Export** to copy it out: export to your case folder, never back to the source volume.

#### Verify the installation

Start it as administrator: the date list should show the same snapshots as `vssadmin list shadows`.

#### First use

The same thing with Windows' built-in commands, which also work when ShadowExplorer can't be installed (run as administrator):

```powershell
vssadmin list shadows                                   # IDs, creation times, \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
vssadmin list shadowstorage                             # how much space they may use
mklink /d C:\vsc1 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
dir C:\vsc1\Users\alice\Documents                       # read-only view of snapshot 1; rmdir C:\vsc1 when done
```

(`mklink` is a `cmd.exe` built-in: in PowerShell run it as `cmd /c mklink ...`. The trailing backslash on the device path matters.)

#### Troubleshooting

| Symptom | Fix |
|---|---|
| The date list is empty | No shadow copies (System Protection off, deleted, or storage full): check `vssadmin list shadows` and the event logs |
| "Access denied" or nothing shows | Run as administrator |
| Export fails on long paths | Export a parent folder to a short target path (`C:\Cases\x`) |
| Doubts about what it shows | Compare with `vssadmin list shadows` and a `mklink` view, or with vshadowinfo on an image |

---

## Part 3: Hands-on labs

Real test images, pinned to fixed commits: an **NTFS volume with two shadow copies** and a **Windows 7 BitLocker To Go** volume from the dfvfs project's test data, and **BitLocker volumes made by Windows 10** (password, recovery password, startup key) from cryptsetup's test suite, with their published SHA-256 sums after decryption. Everything runs unprivileged with FUSE.

Run on Ubuntu 24.04 or SIFT.

```bash
sudo apt update && sudo apt install -y git curl xz-utils xxd sleuthkit libvshadow-utils libbde-utils dislocker fuse3
git -C ~/DFIR pull 2>/dev/null || git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR
mkdir -p ~/cases/LAB-020/{samples,work,notes,mnt} && cd ~/cases/LAB-020
export TZ=UTC
```

Check the tools (dislocker's help goes to stderr):

```bash
vshadowinfo -V | head -n 1
bdeinfo -V | head -n 1
dislocker -h 2>&1 | head -n 1
fls -V
```

```
vshadowinfo 20190323
bdeinfo 20190102
dislocker by Romain Coltel, v0.7.2 (compiled for Linux/x86_64)
The Sleuth Kit ver 4.12.1
```

### Lab 1: Find the shadow copies (15 min)

```bash
DFVFS=https://raw.githubusercontent.com/log2timeline/dfvfs/917cefc9426d6ded2687d2b55164ded25b44fcb7/test_data
curl -sSfL -o samples/vss.raw $DFVFS/vss.raw
curl -sSfL -o samples/bdetogo.raw $DFVFS/bdetogo.raw
(cd samples && sha256sum *.raw | cut -c1-16,65- | tee ../notes/samples.sha256)
fsstat samples/vss.raw | grep -E '^(File System Type|Volume Name|Version):'
xxd -s 0x1e00 -l 16 samples/vss.raw
vshadowinfo samples/vss.raw | grep -E 'Number of stores|^Store|Creation time|Shadow copy ID'
fls -r -p samples/vss.raw | grep 'System Volume Information/'
```

```
ed7982a1f9263e4e  bdetogo.raw
e633f0be5fb9ee9a  vss.raw
File System Type: NTFS
Volume Name: TestVolume
Version: Windows XP
00001e00: 6b87 0838 76c1 484e b7ae 0404 6e6c c752  k..8v.HN....nl.R
	Number of stores:	2
Store: 1
	Creation time		: May 01, 2021 17:40:03.223030400 UTC
	Shadow copy ID		: 2c6c6cc8-2b97-41da-a030-4add838ae8f6
Store: 2
	Creation time		: May 01, 2021 17:41:28.224986300 UTC
	Shadow copy ID		: 19e1881a-c184-4ec4-908e-766ba3373e8a
r/r 37-128-1:	System Volume Information/WPSettings.dat
r/r 44-128-1:	System Volume Information/{3808876b-c176-4e48-b7ae-04046e6cc752}
r/r 43-128-1:	System Volume Information/{de81cc22-aa8b-11eb-9339-8cdcd4557abc}{3808876b-c176-4e48-b7ae-04046e6cc752}
r/r 46-128-1:	System Volume Information/{de81cc2b-aa8b-11eb-9339-8cdcd4557abc}{3808876b-c176-4e48-b7ae-04046e6cc752}
```

- The VSS header is at 0x1E00, starting with the identifier GUID in little-endian byte order.
- Two snapshots, taken 85 seconds apart on 2021-05-01, and their **store files** plus the **catalog** in `System Volume Information`.

### Lab 2: Each snapshot is a whole volume (25 min)

```bash
mkdir -p mnt/vss && vshadowmount samples/vss.raw mnt/vss > /dev/null
ls -l mnt/vss | awk 'NR > 1 {print $1, $5, $9}'
for v in mnt/vss/vss1 mnt/vss/vss2 samples/vss.raw; do
  fls -r -p $v | grep -v -E '\$|System Volume Information' | cut -f2 | sort > work/$(basename $v).files
done
wc -l work/*.files
diff work/vss1.files work/vss2.files; diff work/vss2.files work/vss.raw.files
for i in 45 47; do echo "inode $i: $(istat samples/vss.raw $i | grep -m 1 'Created')"; done
for v in mnt/vss/vss1 mnt/vss/vss2 samples/vss.raw; do
  printf '%-18s passwords.txt %s   vss1 marker: %s\n' $v "$(icat $v 40 | sha256sum | cut -c1-16)" "$(icat $v 45 2> /dev/null | tr -d '\r\n')"
done
```

```
-r--r--r-- 82771968 vss1
-r--r--r-- 82771968 vss2
  7 work/vss.raw.files
  5 work/vss1.files
  6 work/vss2.files
 18 total
5a6
> vss1
6a7
> vss2
inode 45: Created:	2021-05-01 17:40:10.359644800 (UTC)
inode 47: Created:	2021-05-01 17:41:35.330255900 (UTC)
mnt/vss/vss1       passwords.txt 677ff39b3f70e717   vss1 marker: 
mnt/vss/vss2       passwords.txt 677ff39b3f70e717   vss1 marker: VSS1 
samples/vss.raw    passwords.txt 677ff39b3f70e717   vss1 marker: VSS1 
```

- `vshadowmount` presents each snapshot as a 78 MiB raw NTFS volume, read-only; TSK reads them like any image.
- The file lists differ by exactly one file each: `vss1` was created **after** snapshot 1 (17:40:03) and before snapshot 2 (17:41:28): its creation time is 17:40:10. `vss2` came after snapshot 2 (17:41:35). Snapshots **bracket** events in time: whatever is in snapshot 2 but not in snapshot 1 appeared in those 85 seconds.
- `passwords.txt` has the same hash in all three: unchanged. In a real case, a file whose hash differs between snapshots was edited in between, and you can recover every earlier version.

### Lab 3: A BitLocker To Go drive (25 min)

The image as Windows sees it before unlocking, and its metadata:

```bash
fsstat samples/bdetogo.raw | grep -E '^(File System Type|OEM Name):'
fls -p samples/bdetogo.raw | grep -v '\.mui$'
echo "$(fls -p samples/bdetogo.raw | grep -c '\.mui$') language files (*.mui)"
icat samples/bdetogo.raw 7 | tr -d '\r'
bdeinfo samples/bdetogo.raw 2>&1 | grep -E 'Encryption method|Creation time|Description|Number of key|Type|Unable'
```

```
File System Type: FAT32
OEM Name: MSWIN4.1
r/r 7:	autorun.inf
r/r 14:	BitLockerToGo.exe
r/r 104:	Read Me.url
r/r 150:	COV 0000. BL
v/v 2080387:	$MBR
v/v 2080388:	$FAT1
V/V 2080389:	$OrphanFiles
35 language files (*.mui)
[autorun]
action=BitLocker To Go Reader
icon=BitLockerToGo.exe,-1
ShellExecute=BitLockerToGo.exe
UseAutoPlay=1
	Encryption method		: AES-CBC 128-bit with Diffuser
	Creation time			: Jun 02, 2014 12:40:49.728112200 UTC
	Description			: TESTBOX1 H: 6/2/2014
	Number of key protectors	: 2
	Type				: Password
	Type				: Recovery password
Unable to unlock volume.
```

- What's visible without a key is a small **FAT32 discovery volume**: the BitLocker To Go Reader (`BitLockerToGo.exe` and 35 language files), an `autorun.inf` that starts it, and the `COV 0000. BL` cover file. None of the data.
- The metadata is readable without a key: **AES-CBC 128 with the diffuser** (a Windows 7 drive), created 2014-06-02, description **`TESTBOX1 H: 6/2/2014`**: encrypted on a computer named TESTBOX1, where it was drive H:. Two protectors: a password and a recovery password.

Unlock it with dislocker and with libbde, and compare:

```bash
mkdir -p mnt/togo-dl mnt/togo-bde
dislocker -r -V samples/bdetogo.raw -ubde-TEST -- mnt/togo-dl 2>&1 | grep -o 'designed only for BitLocker version 2 and less'
ls mnt/togo-dl | wc -l
dislocker -r -F1 -V samples/bdetogo.raw -ubde-TEST -- mnt/togo-dl
bdemount -p bde-TEST samples/bdetogo.raw mnt/togo-bde > /dev/null
ls -l mnt/togo-dl mnt/togo-bde | awk '$5 {print $5, $9}'
sha256sum mnt/togo-dl/dislocker-file mnt/togo-bde/bde1 | cut -c1-16,65-
fsstat mnt/togo-bde/bde1 | grep -a -E '^(File System Type|OEM Name):' | tr -d '\000'
fls -r -p mnt/togo-bde/bde1
icat mnt/togo-bde/bde1 8
```

```
designed only for BitLocker version 2 and less
0
67108864 bde1
67108864 dislocker-file
6c1f7f02f08528ec  mnt/togo-dl/dislocker-file
6c1f7f02f08528ec  mnt/togo-bde/bde1
File System Type: FAT16
OEM Name: mkdosfs
d/d 4:	a_directory
r/r 582:	a_directory/another_file
r/r 584:	a_directory/a_file
d/d 6:	lost+found
r/r 8:	passwords.txt
d/d 11:	System Volume Information
r/r 521:	System Volume Information/FVE2.{e40ad34d-dae9-4bc7-95bd-b16218c10f72}.1
r/r 526:	System Volume Information/FVE2.{e40ad34d-dae9-4bc7-95bd-b16218c10f72}.2
r/r 531:	System Volume Information/FVE2.{e40ad34d-dae9-4bc7-95bd-b16218c10f72}.3
r/r * 536:	System Volume Information/TEMP{24e6f0ae-6a00-4f73-984b-75ce9942852d}
r/r 541:	System Volume Information/FVE2.{24e6f0ae-6a00-4f73-984b-75ce9942852d}
r/r * 546:	System Volume Information/TEMP{c9ca54a3-6983-46b7-8684-a7e5e23499e3}
r/r * 551:	System Volume Information/FVE2.{c9ca54a3-6983-46b7-8684-a7e5e23499e3}
r/r * 556:	System Volume Information/FVE2.{9ef82dfa-1239-4a30-83e6-3b3e9b8fed08}
v/v 2092995:	$MBR
v/v 2092996:	$FAT1
v/v 2092997:	$FAT2
V/V 2092998:	$OrphanFiles
place,user,password
bank,joesmith,superrich
alarm system,-,1234
treasure chest,-,1111
uber secret laire,admin,admin
```

- dislocker's default run **failed** on this volume ("version 2 and less", with a random number that changes between runs) and mounted nothing. Forcing the first metadata block (`-F1`) worked.
- dislocker and libbde produced **byte-identical** decrypted volumes. When a tool needs coaxing, a second implementation agreeing to the byte is what makes the result defensible.
- Inside: a FAT16 file system with the test files and BitLocker's own `FVE2.{GUID}` files in `System Volume Information`.

### Lab 4: Windows 10 volumes and their key protectors (20 min)

```bash
CS=https://raw.githubusercontent.com/mbroz/cryptsetup/102e91cb0fee849bb86fb1ec4d6ea218e45563cd/tests
curl -sSfL -o samples/bitlk-images.tar.xz $CS/bitlk-images.tar.xz
sha256sum samples/bitlk-images.tar.xz | cut -c1-16,65- | tee -a notes/samples.sha256
BL=samples/bitlk && mkdir -p $BL
tar xJf samples/bitlk-images.tar.xz -C $BL --strip-components=1 bitlk-images/images.conf bitlk-images/bitlk-aes-xts-128.img \
  bitlk-images/bitlk-aes-xts-128-startup-key.img bitlk-images/4381F759-C4F8-4DE0-BB61-FC33A831BDA5.BEK
conf() { sed -n "/^\[$1\]/,/^$/p" $BL/images.conf | sed -n "s/^$2=//p"; }
xxd -l 16 $BL/bitlk-aes-xts-128.img
for img in bitlk-aes-xts-128 bitlk-aes-xts-128-startup-key; do
  echo "== $img"; bdeinfo $BL/$img.img 2>&1 | grep -E 'Encryption method|Creation time|Description|Number of key|Identifier|Type|Unable'
done
ls $BL/*.BEK | sed 's#.*/##'
dislocker-bek -f $BL/4381F759-C4F8-4DE0-BB61-FC33A831BDA5.BEK | grep -E 'Dataset GUID|Recovery Key GUID|Epoch Timestamp' | sed 's/.*\[INFO\] *//'
```

```
68bf5669f7776681  samples/bitlk-images.tar.xz
00000000: eb58 902d 4656 452d 4653 2d00 0208 0000  .X.-FVE-FS-.....
== bitlk-aes-xts-128
	Encryption method		: AES-XTS 128-bit
	Creation time			: Jul 04, 2019 07:01:55.156235200 UTC
	Description			: DESKTOP-NPM7RCA H: 7/4/2019
	Number of key protectors	: 2
	Identifier			: 3e55195c-8811-4d9b-97b4-2b9e5f8f5384
	Type				: Password
	Identifier			: 64311dea-4587-4029-924a-ba299647998e
	Type				: Recovery password
Unable to unlock volume.
== bitlk-aes-xts-128-startup-key
	Encryption method		: AES-XTS 128-bit
	Creation time			: Sep 15, 2020 07:22:33.342463100 UTC
	Description			: DESKTOP-LG39GVP E: 15/09/2020
	Number of key protectors	: 3
	Identifier			: 4f6ae327-f4cf-470b-a6f6-9de8fdb7c051
	Type				: Password
	Identifier			: 294bc732-f82f-404c-a2ce-d1094ed59506
	Type				: Recovery password
	Identifier			: 4381f759-c4f8-4de0-bb61-fc33a831bda5
	Type				: Startup key
Unable to unlock volume.
4381F759-C4F8-4DE0-BB61-FC33A831BDA5.BEK
Dataset GUID: '4381F759-C4F8-4DE0-BB61-FC33A831BDA5'
Epoch Timestamp: 1600154989 sec, that to say Tue Sep 15 07:29:49 2020
Recovery Key GUID: '4381F759-C4F8-4DE0-BB61-FC33A831BDA5'
Epoch Timestamp: 1600154643 sec, being Tue Sep 15 07:24:03 2020
```

- A normal BitLocker volume starts with `-FVE-FS-`. Both are **AES-XTS 128** (Windows 10). The descriptions name the machines: `DESKTOP-NPM7RCA` and `DESKTOP-LG39GVP`.
- The second volume has three protectors; the startup key's identifier `4381f759-...` is the **name of the `.BEK` file**, and `dislocker-bek` shows the same GUID inside it, with times a few minutes after the volume was created. That's how you match a USB key's `.BEK` file to a drive.

Unlock with each kind of protector:

```bash
mkdir -p mnt/pw mnt/rp mnt/sk
dislocker -r -V $BL/bitlk-aes-xts-128.img -u"$(conf bitlk-aes-xts-128 PW)" -- mnt/pw
dislocker -r -V $BL/bitlk-aes-xts-128.img -p"$(conf bitlk-aes-xts-128 RP)" -- mnt/rp
dislocker -r -V $BL/bitlk-aes-xts-128-startup-key.img -f $BL/4381F759-C4F8-4DE0-BB61-FC33A831BDA5.BEK -- mnt/sk
for m in pw rp sk; do echo "unlocked with $m: $(sha256sum < mnt/$m/dislocker-file | cut -c1-16)"; done
echo "expected: $(conf bitlk-aes-xts-128 SHA256SUM | cut -c1-16) and $(conf bitlk-aes-xts-128-startup-key SHA256SUM | cut -c1-16)"
xxd -l 16 mnt/pw/dislocker-file
mkdir -p mnt/rp-bde && bdemount -r "$(conf bitlk-aes-xts-128 RP)" $BL/bitlk-aes-xts-128.img mnt/rp-bde > /dev/null
echo "libbde with the recovery password: $(sha256sum < mnt/rp-bde/bde1 | cut -c1-16)"
```

```
unlocked with pw: 674e3a976927fd62
unlocked with rp: 674e3a976927fd62
unlocked with sk: bbb68369d8f7badb
expected: 674e3a976927fd62 and bbb68369d8f7badb
00000000: eb52 904e 5446 5320 2020 2000 0208 0000  .R.NTFS    .....
libbde with the recovery password: 674e3a976927fd62
```

- The password and the recovery password unlock the **same** volume (same hash), because each decrypts its own copy of the same VMK. The startup key unlocks the other volume. All three match the SHA-256 sums cryptsetup published, and libbde agrees on the recovery-password unlock.
- The decrypted volume starts with a normal NTFS boot sector. (cryptsetup keeps only the metadata of these test images and zeroes the data area, so the rest decrypts to random-looking bytes: fine for testing keys, not for browsing files.)

### Lab 5: Clean up (2 min)

```bash
for m in mnt/*/; do fusermount -u $m; done
echo "FUSE mounts left: $(grep -c "$PWD/mnt" /proc/mounts)"
```

```
FUSE mounts left: 0
```

Always unmount FUSE mounts before you move or hash an image, and record in your notes which tool and version produced each decrypted copy.

---

## ✅ Knowledge check

1. A shadow copy was taken at 09:00. A file appears in the live volume but not in that snapshot. What can you say about when it was created, and what would make you doubt its `$STANDARD_INFORMATION` creation time?
2. Where are a volume's shadow copies stored, and how do you find out how many there are from a Linux workstation?
3. Name three commands an attacker might use to destroy shadow copies, and where you'd see them.
4. What's the difference between the FVEK, the VMK and a key protector? Why do a password and a recovery password produce the same decrypted volume?
5. You find a USB drive whose first sector says `MSWIN4.1` and that contains `BitLockerToGo.exe`. What is it, and what can you learn before you have any key?
6. You have a recovery-key list from Active Directory with 20 entries. How do you pick the right one for a drive?
7. You arrive at a running laptop with BitLocker on its system drive. What do you do before shutting it down, and why?
8. dislocker gives an error on a volume, but `-F2` makes it work. What do you do before you rely on the decrypted copy?

<details>
<summary><b>Answers</b></summary>

1. It was created **after 09:00** (or recreated, or restored, after it). If its `$STANDARD_INFORMATION` creation time is earlier than 09:00, the timestamp is wrong: suspect timestomping (Day 10), or a copy that kept an old time; check `$FILE_NAME` times and the `$UsnJrnl`.
2. In the volume's `System Volume Information` folder: the catalog `{3808876b-c176-4e48-b7ae-04046e6cc752}` and one `{GUID}{3808876b-...}` store file per snapshot, with the VSS header at offset 0x1E00. `vshadowinfo [-o offset] image` lists them; `vshadowmount` exposes them.
3. Any three of: `vssadmin delete shadows /all /quiet`; `wmic shadowcopy delete`; PowerShell removing `Win32_ShadowCopy` instances; `vssadmin resize shadowstorage` to a tiny size; `wbadmin delete catalog`. You'd see them in process-creation events (Security 4688 with command lines, Sysmon event 1), EDR telemetry, and Sigma detections.
4. The **FVEK** encrypts the sectors; the **VMK** encrypts the FVEK; each **key protector** (password, recovery password, TPM, startup key...) encrypts its own copy of the VMK. Any protector yields the same VMK, so the same FVEK, so the same plaintext.
5. A **BitLocker To Go** removable drive: the FAT32 part is a discovery volume with a reader program; the data is in the encrypted part. Without a key, the metadata gives the encryption method, the volume GUID, the creation time, the **description** (computer name, drive letter, date) and the list of key protectors with their identifiers.
6. Read the protector identifiers from the drive (`bdeinfo`, `dislocker-metadata`, or the BitLocker recovery screen's key ID) and pick the recovery password whose ID matches.
7. Capture **memory** first (the FVEK and VMK are in it while the volume is unlocked), then image the logical, decrypted volume or record the recovery password (`manage-bde -protectors -get C:` as administrator). After a shutdown, a TPM-protected drive may only unlock inside that machine, and only if you have the PIN or recovery password.
8. Cross-check it with an independent implementation (libbde's `bdemount`, or cryptsetup's BitLocker support) and compare hashes of the decrypted volumes; record the tool versions and options you used.

</details>

---

## 📚 Further reading

- Joachim Metz, *Windowless Shadow Snapshots* (OSDFC 2012) and the libvshadow format documentation (https://github.com/libyal/libvshadow/wiki)
- libbde: *BitLocker Drive Encryption (BDE) format specification* (https://github.com/libyal/libbde)
- Microsoft, *Volume Shadow Copy Service* and *BitLocker overview / BitLocker recovery guide* (learn.microsoft.com)
- dislocker `README.md` and `INSTALL.md` (https://github.com/Aorimn/dislocker)
- cryptsetup, BitLocker (BITLK) support and its test images (https://gitlab.com/cryptsetup/cryptsetup)
- vss_carver (https://github.com/mnrkbys/vss_carver): recovering deleted shadow-copy stores

---

## ⏭️ Tomorrow: Day 21

**Super timelines: building and analysing.** Tools: **Plaso (log2timeline)**, **Timeline Explorer**, **Timesketch**.
For twelve days you've read Windows artifacts one at a time, and today learned that a single image can hold several points in time. Tomorrow: putting all of it into one timeline, and searching it without drowning.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
