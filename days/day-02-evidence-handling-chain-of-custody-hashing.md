# Day 02: Evidence Handling, Chain of Custody, Integrity & Hashing

> **Phase 1: Foundations** · **Level:** 🟢 Beginner · **Time:** ~3 hours (reading + labs) · **Posted:** 2026-09-29
>
> **Tools today:** 🛠️ hashdeep · 🛠️ ssdeep · 🛠️ HashMyFiles

---

## 🎯 Learning objectives

By the end of today you will be able to:

1. Seize, package, label, transport and store digital evidence correctly.
2. Create and maintain a chain-of-custody record that will stand up to challenge.
3. Explain how cryptographic hashes prove integrity, and choose the right algorithm.
4. Use hash sets to filter known-good files and detect known-bad ones.
5. Use fuzzy hashing to find files that are *similar* but not identical.
6. Install, configure and use **hashdeep**, **ssdeep** and **HashMyFiles**.

---

## Part 1: The lesson

### 1.1 The evidence lifecycle

```
 ┌─────────┐   ┌────────────┐   ┌───────────┐   ┌─────────┐   ┌──────────────┐   ┌─────────┐   ┌──────────────┐
 │  Seize  │──▶│ Package &  │──▶│ Transport │──▶│  Store  │──▶│  Acquire &   │──▶│ Analyse │──▶│ Return /     │
 │         │   │   label    │   │           │   │         │   │   verify     │   │ (copies)│   │ dispose      │
 └─────────┘   └────────────┘   └───────────┘   └─────────┘   └──────────────┘   └─────────┘   └──────────────┘
      │               │                │              │               │                │               │
      └───────────────┴──── chain of custody entry + hash verification at every hand-off ──────────────┘
```

Every arrow is a hand-off. Every hand-off is a chance for a defence lawyer, an opposing expert or an auditor to ask: *"How do you know nothing changed here?"* Today is about being able to answer that question.

### 1.2 At the scene: seizure and collection

**First, secure and document the scene.**

- Photograph everything before touching it: screens, cables and ports, serial-number labels, the surrounding desk (sticky notes with passwords are real).
- Write down who is present, the time (UTC), and the **power state** of each device.
- Check the device clock against a trusted source and record the **clock skew** (for example, "system clock 3 min 12 s fast").

**Then decide: live or dead?**

| Situation | Recommended action | Why |
|-----------|--------------------|-----|
| Computer **running** | Capture **RAM first** (Day 23), then check for encryption (BitLocker, FileVault, VeraCrypt, LUKS). If a volume is unlocked, consider a logical image or recovering the keys *before* shutting down. | Pulling the plug loses memory and may leave you with an encrypted disk you cannot open |
| Computer **powered off** | Leave it off. Remove the drive and image it through a write-blocker (Day 5). | Booting it changes hundreds of files and timestamps |
| **Mobile phone** | Isolate it from networks (Faraday bag or airplane mode), keep it charged, and note the lock state. | Stops remote wipe and incoming data overwriting evidence |
| **Server / virtual machine** | Snapshot the VM, including memory where possible, and collect logs. Coordinate with the business before shutting anything down. | Downtime has a business cost; hypervisors give you forensically useful snapshots |
| **Cloud / SaaS** | Preserve through the provider: legal hold, audit-log exports, disk snapshots (Days 55–57). | You can't physically seize a data centre |

**Label every item** with a unique ID that follows a consistent scheme, for example `CASE-2026-001-EV-003`. The label goes on the **evidence bag** or a tie-on tag, not on a surface of the device you might later need to examine.

**Package it correctly:**

| Item | Packaging |
|------|-----------|
| Hard drives, SSDs, circuit boards | **Anti-static bag**, padded box |
| Phones, tablets, anything with a radio | **Faraday bag** (and keep it powered if it is on) |
| Everything | **Tamper-evident bag** with a printed serial number. Sign and date across the seal |

**Transport:** keep items away from magnets, heat and moisture, and keep them in your custody the whole way. If you ship an item, the courier becomes part of the chain of custody, so use tracked, signed-for delivery.

**Storage:**

- *Physical:* a locked evidence room or locker with an access log and stable temperature and humidity.
- *Digital (images and exports):* read-only, encrypted at rest, access-controlled, backed up, and hashed so that you can re-verify at any time.

### 1.3 Chain of custody

The **chain of custody** is the documented, unbroken history of an evidence item: **who** had it, **when**, **where**, **why**, and **what** they did to it, from seizure to final disposal. If there is a gap, the other side will argue that the evidence could have been altered during that gap.

**A good record contains:**

- A unique evidence ID and a detailed description (make, model, serial number, capacity, condition).
- Seizure details: who, when (UTC), where, the legal authority, the power state, and a witness.
- Integrity data: acquisition tool and version, write-blocker, image file names, **hash values**.
- A **transfer log**: every change of hands or location, with both parties' signatures, the purpose, and whether the seal was intact and the hash re-verified.
- The final disposition: returned, destroyed (for example, NIST SP 800-88 media sanitisation) or archived.

📄 A ready-to-use form is in this repo: **[`templates/chain-of-custody-form.md`](../templates/chain-of-custody-form.md)**. You'll fill it in during Lab 1.

**Common ways the chain gets broken:**

| Mistake | Consequence | Prevention |
|---------|-------------|------------|
| An undocumented hand-off ("I left it on your desk") | A gap in custody that the other side can attack | Log every transfer, even inside the team |
| No hash recorded at acquisition | Nothing to prove the image matches the original | Hash source and image, and write both down |
| Working directly on the original image | Changes can't be ruled out | Work on verified copies and keep the master read-only |
| Times recorded in mixed time zones | Timeline disputes | Always use UTC and state it |
| Corrections made by overwriting | Looks like tampering | Never erase; add a dated correction entry |

For digital evidence, the "item" is often a **file** (an image, a log export, a cloud archive). Treat it the same way: record its hash when you receive it, re-verify the hash before and after analysis, and log every copy you make.

### 1.4 Hash functions: the foundation of integrity

A **cryptographic hash function** turns any amount of data into a short, fixed-length "fingerprint".

| Property | Meaning | Why it matters in forensics |
|----------|---------|------------------------------|
| **Deterministic** | The same input always gives the same hash | Anyone can re-compute and verify it |
| **Fixed length** | 1 byte or 10 TB in, e.g. 256 bits out | Easy to record and compare |
| **Avalanche effect** | Changing one bit changes about half the output bits | Any modification is obvious |
| **Pre-image resistance** | You can't work back from a hash to the data | Hashes can be shared safely (e.g., IOC lists) |
| **Second pre-image resistance** | Given a file, you can't make a *different* file with the same hash | Nobody can swap in fake evidence that matches your hash |
| **Collision resistance** | You can't find *any* two inputs with the same hash | Protects against someone preparing two versions in advance |

**See the avalanche effect.** Change one letter's case:

```bash
$ printf 'DFIR' | sha256sum
0c28edff874a43ef242328c540780b2e7dd8dd201c0fd821b91c4156fbd85290  -
$ printf 'DFIr' | sha256sum
870a1cd75cf611fb91ef8fe02e4b0487e5f17fe0331b0d41596f080256d302fa  -
```

The two outputs share no visible pattern.

### 1.5 Choosing an algorithm

| Algorithm | Output size | Status | Use in DFIR |
|-----------|------------:|--------|-------------|
| CRC32 | 32 bits | **Not cryptographic.** An error-detecting checksum; trivial to forge | Checking for transmission errors only. Never use it to prove integrity |
| MD5 | 128 bits | **Collisions are practical**: first found in 2004, chosen-prefix collisions in 2007, abused by the Flame malware in 2012 to forge a Microsoft code-signing certificate. Pre-image attacks are still impractical | Still everywhere: E01 images, NSRL, older tools and reports. Record it for compatibility, **alongside** SHA-256 |
| SHA-1 | 160 bits | **Collisions are practical**: SHAttered (2017), chosen-prefix "SHA-1 is a Shambles" (2020). NIST is phasing it out by 2030 | Legacy compatibility only |
| **SHA-256** (SHA-2) | 256 bits | Secure; no practical attacks | ✅ **The default for evidence integrity today** |
| SHA-512 (SHA-2) | 512 bits | Secure; often faster than SHA-256 on 64-bit CPUs | Fine alternative |
| SHA-3, BLAKE3 | 256+ bits | Secure, modern | Less tool support in DFIR so far |

> 💡 **Best practice:** record **SHA-256 and MD5** for every acquisition. SHA-256 carries the integrity argument. MD5 keeps you compatible with older tools, hash sets and other examiners' reports.
>
> Does MD5 collision weakness really matter for evidence? For *proving your image hasn't changed*, the attacker would need a second pre-image, which is still impractical for MD5. But arguing that point in court wastes time, and using SHA-256 avoids the argument altogether.

### 1.6 Where hashing fits in an investigation

| Moment | What to hash | Why |
|--------|--------------|-----|
| Acquisition | The **source** (device) and the **image** | Proves the image is an exact copy |
| Receiving evidence from someone else | Every file you receive | Proves what you were given |
| Before and after analysis | Your working copy | Proves your analysis didn't change it |
| Exporting files from an image | Each exported file (hashdeep makes this easy) | Lets anyone locate the same file in the image later |
| Your tools | The tool binaries you used | Supports reproducibility and helps detect tampered tools |
| Reports | The final PDF | Proves the report you delivered hasn't been edited since |

In US federal courts, **FRE 902(14)** lets electronic data be *self-authenticating* when it is identified by a hash and backed by a written certification. Hashes aren't just good practice; they are part of how evidence gets admitted.

### 1.7 Pitfalls every examiner hits once

1. **The E01 container is not the evidence.** An E01 (EnCase Evidence File) stores the acquired data *plus* metadata and compression. The MD5/SHA stored **inside** the E01 is the hash of the *acquired media*. Hashing the `.E01` file itself gives a completely different value. Compare like with like (Day 6).
2. **Bad sectors change hashes.** If a failing drive returns different data on each read, source and image hashes won't match. Document it using the acquisition log, which lists the unreadable sectors.
3. **SSDs can change themselves.** Even behind a write-blocker, an SSD controller's background garbage collection can erase blocks that were already marked unused (TRIM). Re-hashing the *physical SSD* later may give a different value. That's exactly why you hash, keep and work from the **image**.
4. **Mounting read-write changes the image.** Journaling file systems (NTFS, ext4) may replay their journal when mounted. Always mount read-only (Day 6).
5. **A hash proves content, not origin.** A matching hash shows two files are identical. It doesn't show *who* created them or *when*. File names and timestamps aren't part of the content hash.
6. **One changed byte means no match.** A cryptographic hash can't tell you that two files are 99% the same. That's what **fuzzy hashing** (§1.9) is for.

### 1.8 Hash sets: filtering known-good and finding known-bad

A typical Windows disk has hundreds of thousands of files, and most of them are unmodified operating-system or application files. **Hash sets** let you set those aside and focus on the rest:

| Hash set type | Example | How you use it |
|---------------|---------|----------------|
| **Known-good** (ignorable) | **NIST NSRL RDS**: hashes of commercial software files, published as SQLite databases (RDSv3) | *Negative matching*: hide every file that matches, then analyse what's left |
| **Known-bad** (alert) | Malware hashes from MalwareBazaar, VirusTotal, CISA/vendor advisories, your own previous cases | *Positive matching*: flag every file that matches |
| **Case-specific** | Hashes of stolen documents, leaked source code | Find copies of the same file on other devices, USB sticks or cloud accounts |
| **Law-enforcement-only** | Project VIC / CAID (child-abuse material) | Automatic identification without an examiner having to view the material |

hashdeep does both: `-m` (positive) and `-x` (negative) matching. You'll try both in Lab 3.

### 1.9 Fuzzy hashing (similarity hashing)

What if the attacker recompiled their malware with one byte changed, or the stolen document was edited slightly? The cryptographic hashes will be completely different. **Fuzzy hashing** gives *similar inputs similar hashes*.

**How ssdeep works** (Context-Triggered Piecewise Hashing, CTPH, by Jesse Kornblum, 2006):

```
file data ─▶ a rolling hash slides over the bytes
             │ whenever its value hits a "trigger" pattern, the current piece ends
             ▼
  [piece 1][piece 2][piece 3] ... each piece is hashed and reduced to 1 base64 character
             ▼
  ssdeep hash = blocksize : chars-for-blocksize : chars-for-2×blocksize
  e.g.  384:G2Ss3vyhnbzKMDh79JU6R...:dN3vyhnbzKMDh79JU6Rn51eC...
```

Because piece boundaries depend on the **content** rather than fixed offsets, inserting or deleting data only changes the pieces around the edit. Comparing two ssdeep hashes gives a **score from 0 to 100**, based on how similar the two character strings are.

| Use case | Example |
|----------|---------|
| Malware triage | Group samples from the same family or builder; find variants of a known sample |
| Data-leak investigations | Find edited versions of a confidential document |
| Spotting duplicates | Near-duplicate files across a large evidence set |

**Limitations:**

- Files under ~4 KB don't produce meaningful hashes.
- Two hashes can only be compared when their block sizes are equal, or one is double the other.
- Compressed or encrypted content defeats it: a small change to the plaintext changes the whole compressed output.
- A score is **evidence of similarity, not proof** of common origin. Always confirm with other analysis.
- Different implementations can score slightly differently (ssdeep 2.14 and the Python *ppdeep* library can differ by a few points for the same pair).

**Related tools you'll meet later:** **TLSH** (Trend Micro locality-sensitive hash; more robust than ssdeep for many file types), **sdhash**, and **imphash** (a hash of a PE executable's import table, used to cluster malware; Day 43).

### 1.10 Piecewise hashing

Instead of one hash for a whole file, **piecewise hashing** produces one hash per fixed-size chunk (for example, every 1 MB).

- If an image fails verification, piecewise hashes show *which* chunk changed.
- They can identify fragments of a known file inside unallocated space or a memory dump.

hashdeep does this with `-p <size>`.

---

## Part 2: Tools

---

### 🛠️ Tool 1: hashdeep

| | |
|---|---|
| **What** | A recursive, multi-algorithm hashing tool from the **md5deep** suite, by Jesse Kornblum and Simson Garfinkel. It computes MD5, SHA-1, SHA-256, Tiger and Whirlpool; builds hash baselines; **audits** a folder against a baseline; does positive and negative **matching** against hash sets; supports **piecewise** hashing; and can output **DFXML** |
| **Why in DFIR** | One command gives you a signed-off inventory of an entire evidence set, and a second command proves later that nothing was added, removed, moved or modified |
| **Platforms** | Linux, macOS, Windows (32- and 64-bit binaries) |
| **Licence** | Public domain (the Tiger code is GPL) |
| **Home** | https://github.com/jessek/hashdeep (current release: 4.4) |

The suite also installs single-algorithm tools: `md5deep`, `sha1deep`, `sha256deep`, `tigerdeep` and `whirlpooldeep`. They share most options, and they accept `md5sum`/`sha256sum`-style hash lists for matching (see Lab 3).

#### Requirements

Almost none: a few MB of disk space. Hashing speed is usually limited by the disk, not the CPU.

#### Installation

**SIFT Workstation:** already installed. Check with `hashdeep -V`.

**Ubuntu / Debian / Kali:**

```bash
sudo apt update
sudo apt install -y hashdeep        # provides hashdeep, md5deep, sha1deep, sha256deep, tigerdeep, whirlpooldeep
```

**macOS (Homebrew):**

```bash
brew install md5deep                # the formula is named md5deep; it installs hashdeep too
```

**Windows:**

1. Download **`md5deep-4.4.zip`** from https://github.com/jessek/hashdeep/releases.
2. Extract it and use the **64-bit** binaries (`hashdeep64.exe`, `sha256deep64.exe`, …).

```powershell
New-Item -ItemType Directory -Path C:\Tools\hashdeep -Force | Out-Null
Expand-Archive "$env:USERPROFILE\Downloads\md5deep-4.4.zip" -DestinationPath C:\Tools\hashdeep -Force
Get-ChildItem C:\Tools\hashdeep -Recurse -Filter *64.exe | Select-Object FullName

# Add the folder that contains hashdeep64.exe to your user PATH (adjust if the zip created a sub-folder)
$dir = (Get-ChildItem C:\Tools\hashdeep -Recurse -Filter hashdeep64.exe | Select-Object -First 1).DirectoryName
[Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path','User') + ";$dir"), 'User')
```

**Build from source** (any Unix-like OS):

```bash
sudo apt install -y build-essential autoconf automake git
git clone https://github.com/jessek/hashdeep.git && cd hashdeep
sh bootstrap.sh          # runs autoconf and automake
./configure              # optionally: --prefix=$HOME/.local
make && sudo make install
```

#### Configuration: the options that matter

hashdeep has no config file. Everything is set with command-line options:

| Option | What it does |
|--------|--------------|
| `-c md5,sha256` | Which algorithms to compute (default: **MD5 and SHA-256**). Choose from `md5, sha1, sha256, tiger, whirlpool` |
| `-r` | Recurse into sub-directories |
| `-l` | Record **relative** paths. Use this so a baseline still works after you move the evidence folder |
| `-b` | Bare file names only (no paths) |
| `-k <file>` | Load a file of known hashes (**hashdeep format**) for `-a`, `-m` and `-x` |
| `-a` | **Audit mode**: compare files against `-k`. Prints *Audit passed* or *Audit failed* |
| `-v` / `-vv` / `-vvv` | More detail in audit mode (`-vv` lists every discrepancy) |
| `-m` / `-x` | Positive / negative matching against `-k` |
| `-w` | With `-m`, show *which* known file matched |
| `-p <size>` | Piecewise hashing, e.g. `-p 1m` |
| `-o f` | Only process certain file types (`f` = regular files, `b` = block devices, …) |
| `-j <n>` | Number of hashing threads (default 4). Use `-j 1` if you want output in a stable order |
| `-e` | Show the estimated time remaining for large files |
| `-d` | Output **DFXML** (Digital Forensics XML) for tool pipelines |
| `-s` | Silent: suppress error messages |

**Output format.** A hashdeep file begins with a header that records the algorithms used, the working directory and the exact command. It's self-documenting evidence of how the baseline was made:

```
%%%% HASHDEEP-1.0
%%%% size,sha256,filename
## Invoked from: /home/sansforensics/cases/LAB-002
## # hashdeep -c sha256 -r -l evidence
##
16,e392387f4e0e8013815feaabd7a06f24cf8ff3114756c0ddfedb5665ea3365e6,evidence/chat.log
...
```

**Recommended habit:** save baselines in the case `notes/` folder, then hash the baseline file itself and record that hash in your case notes.

#### Verify the installation

```bash
hashdeep -V                      # -> 4.4
printf 'abc' | hashdeep -c sha256 | tail -n 1
# -> 3,ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad,stdin
```

`ba7816bf…15ad` is the official SHA-256 test vector for `abc`. If you get that value, the tool is computing correctly. (This is the tool validation habit from Day 1.)

#### First use

```bash
# Hash a whole evidence folder (MD5 + SHA-256), relative paths
hashdeep -r -l evidence/ > notes/evidence.hashdeep

# Hash a disk image and show progress
hashdeep -e -c md5,sha256 evidence/usb-sim.img

# Hash a physical device (Linux, needs root): use sha256sum/md5sum, NOT hashdeep (see the warning below)
sudo sha256sum /dev/sdb
```

> ⚠️ **Tool validation in action.** While testing this lesson on Ubuntu 24.04, `hashdeep` 4.4 reported a **block device** (`/dev/loop0`, a 32 MB image attached read-only) as **size 0**, with the **empty-file hash** `e3b0c442…b855`. `sha256sum /dev/loop0` and `dd if=/dev/loop0 | sha256sum` both returned the correct hash of the 32 MB image. Use hashdeep for **files and image files**. For devices, use `sha256sum`/`md5sum`, `dc3dd` or your imaging tool's built-in hashing (Day 5). This is exactly why you validate tools against known data before you rely on them.

#### Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `Audit failed` with no details | Add `-vv` to list every discrepancy |
| Every file shows as *new* and *not found* during an audit | The baseline used absolute paths and the folder moved, or you ran it from a different directory. Use `-l` consistently and run from the same parent directory |
| `Unable to identify file format` with `-k` | `hashdeep -k` needs a **hashdeep-format** file. For `sha256sum`-style lists, use `sha256deep -m list.txt` instead (Lab 3) |
| `Permission denied` on some files | Run with `sudo` (Linux) or an elevated prompt (Windows), or add `-s` to hide the errors (and note it) |
| Output order changes between runs | That's multi-threading. Use `-j 1` for a stable order, or sort the output |
| A device (`/dev/sdX`) shows size 0 and hash `e3b0c442…b855` | hashdeep isn't reading the device contents. Hash devices with `sha256sum` or your imager instead |

---

### 🛠️ Tool 2: ssdeep

| | |
|---|---|
| **What** | The reference implementation of **fuzzy hashing** (Context-Triggered Piecewise Hashing). It computes similarity hashes and compares files or hash lists, scoring each pair from 0 to 100 |
| **Why in DFIR** | Finding malware variants, edited copies of leaked documents and near-duplicates, all of which cryptographic hashes miss. VirusTotal, MalwareBazaar and MISP publish ssdeep hashes, so you can pivot on them |
| **Platforms** | Linux, macOS, Windows; Python bindings are available |
| **Licence** | GPL-2.0 |
| **Home** | https://github.com/ssdeep-project/ssdeep (current release: 2.14.1) · https://ssdeep-project.github.io/ssdeep/ |

#### Installation

**SIFT Workstation:** usually preinstalled. Check with `ssdeep -V`.

**Ubuntu / Debian / Kali:**

```bash
sudo apt update
sudo apt install -y ssdeep
```

**macOS (Homebrew):**

```bash
brew install ssdeep
```

**Windows:**

1. Download **`ssdeep-2.14.1-win32-binary.zip`** from https://github.com/ssdeep-project/ssdeep/releases.
2. Extract it to `C:\Tools\ssdeep`. Keep `ssdeep.exe` and `fuzzy.dll` together in the same folder.
3. Add `C:\Tools\ssdeep` to your PATH.

```powershell
Expand-Archive "$env:USERPROFILE\Downloads\ssdeep-2.14.1-win32-binary.zip" -DestinationPath C:\Tools\ssdeep -Force
Get-ChildItem C:\Tools\ssdeep -Recurse -Include ssdeep.exe, fuzzy.dll | Select-Object FullName
```

**Python (for scripting your own triage):**

```bash
# Option A: pure-Python implementation, no compiler needed
python3 -m pip install ppdeep

# Option B: bindings to the C library (needs build tools)
sudo apt install -y libfuzzy-dev build-essential python3-dev
python3 -m pip install ssdeep
```

```python
import ppdeep
h1 = ppdeep.hash_from_file("samples/report-v1.txt")
h2 = ppdeep.hash_from_file("samples/report-v2.txt")
print(h1)
print(ppdeep.compare(h1, h2))   # similarity score 0-100
```

> 💡 Use a virtual environment (`python3 -m venv ~/venvs/dfir && source ~/venvs/dfir/bin/activate`) so you don't clash with system Python packages. Recent Ubuntu releases block system-wide `pip install` by default.

#### Configuration: the options that matter

| Option | What it does |
|--------|--------------|
| *(no option)* | Print the ssdeep hash of each file |
| `-r` | Recurse into directories |
| `-l` / `-b` | Relative paths / bare file names |
| `-d` | **Directory mode**: compare every file with every *other* file given, and show matches |
| `-p` | **Pretty mode**: like `-d`, but shows each match in both directions |
| `-g` | **Cluster** matching files into groups (use with `-d`) |
| `-m <file>` | Match files against a list of known **ssdeep hashes** |
| `-k <file>` | Match *signature files* given as input against the signatures in `<file>` |
| `-x` | Treat the inputs as signature files and compare them with each other |
| `-t <n>` | Only show matches with a score above `n` |
| `-a` | Show all comparisons, even score 0 |
| `-c` | CSV output |
| `-s` | Silent (suppress errors) |

A good starting threshold is **`-t 50`** for documents, then tune it for your data. Always confirm matches by looking at the files themselves.

#### Verify the installation

```bash
ssdeep -V                              # -> 2.14.1
printf 'hello world\n' > /tmp/small.txt
ssdeep /tmp/small.txt                  # warns: "Did not process files large enough to produce meaningful results"
```

That warning is expected. It proves you've read the limitation about small files, and it proves the tool runs.

#### First use

```bash
ssdeep -r -l samples/ > known.ssdeep         # build a hash list
ssdeep -l -p samples/*                       # which files resemble each other?
ssdeep -l -m known.ssdeep suspicious.bin     # does a new file resemble anything known?
```

#### Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `Did not process files large enough…` | The file is under ~4 KB. Fuzzy hashing isn't meaningful there; use cryptographic hashes |
| Two obviously similar files score 0 | Their block sizes aren't compatible (for example, very different file sizes), or the content is compressed or encrypted. Compare the decompressed or unpacked content instead |
| Windows: "fuzzy.dll was not found" | Keep `fuzzy.dll` in the same folder as `ssdeep.exe` |
| Score differs between tools | Implementations differ slightly (ssdeep vs ppdeep). Use the same tool across a case and state which one in your report |

---

### 🛠️ Tool 3: HashMyFiles (NirSoft)

| | |
|---|---|
| **What** | A small, portable Windows GUI that calculates **MD5, SHA-1, CRC32, SHA-256, SHA-384 and SHA-512** for files and folders. It highlights identical files and exports reports to CSV, HTML, XML or text |
| **Why in DFIR** | Fast visual hashing on a Windows analysis box: verify a downloaded tool, spot duplicate files, check a folder of exports, and produce an HTML hash report for non-technical readers |
| **Platforms** | Windows (32-bit and x64 builds). Portable, no installer |
| **Licence** | Freeware (NirSoft) |
| **Home** | https://www.nirsoft.net/utils/hash_my_files.html |

#### Installation (Windows analysis VM)

1. Go to https://www.nirsoft.net/utils/hash_my_files.html and download the **x64** zip (a 32-bit zip is also offered).
2. **Record the zip's hash** in your tool log:
   ```powershell
   Get-FileHash "$env:USERPROFILE\Downloads\hashmyfiles-x64.zip" -Algorithm SHA256
   ```
3. Extract it to `C:\Tools\HashMyFiles`:
   ```powershell
   Expand-Archive "$env:USERPROFILE\Downloads\hashmyfiles-x64.zip" -DestinationPath C:\Tools\HashMyFiles -Force
   Start-Process C:\Tools\HashMyFiles\HashMyFiles.exe
   ```

> ⚠️ Some antivirus products flag **all** NirSoft downloads as "potentially unwanted" or "HackTool", because a few other NirSoft utilities recover passwords. HashMyFiles only computes hashes. If Defender blocks it on your **analysis VM**, add an exclusion for `C:\Tools` there (as on Day 1). Never do this on your host.

#### Configuration

Settings are saved automatically to `HashMyFiles.cfg` next to the executable, so copy that file along with the exe to keep your settings on a USB toolkit.

- **Options → Hash Types:** tick **MD5** and **SHA-256** (add SHA-1 if a partner needs it). Untick CRC32 so nobody mistakes it for an integrity hash.
- **Options → Mark Identical Hashes:** colours files with the same content, which is great for spotting duplicates and renamed copies.
- **Options → Mark Hashes in Clipboard:** copy a known hash (from an IOC report, for example), and any matching file is highlighted.
- **Options → Enable Explorer Context Menu:** adds *HashMyFiles* to the right-click menu. This needs admin rights, so decide whether you want it on your analysis VM.
- **View → Choose Columns:** show *Full Path, File Size, Modified Time, Created Time, Identical* and the hash columns you chose.
- Set the VM time zone to **UTC** (Day 1) so the file times shown are UTC.

#### Verify the installation

Create a file containing exactly `abc`, with no newline, then compare the two hashing methods:

```powershell
New-Item -ItemType Directory -Path C:\Cases\LAB-002 -Force | Out-Null
[IO.File]::WriteAllText('C:\Cases\LAB-002\abc.txt', 'abc')
Get-FileHash C:\Cases\LAB-002\abc.txt -Algorithm SHA256
# -> BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD
```

Drag `abc.txt` into HashMyFiles. The **SHA-256** column should show the same value, and **MD5** should be `900150983cd24fb0d6963f7d28e17f72`.

#### First use

1. **File → Add Folder…**, pick a folder, and tick the option to include sub-folders.
2. Sort by a hash column. With *Mark Identical Hashes* on, duplicates are coloured together.
3. Select all (Ctrl+A), then **File → Save Selected Items** and choose **CSV** for your case folder, or **View → HTML Report – All Items** for a readable report.
4. Right-click a file to copy its hash, open its properties, or look the hash up online.

HashMyFiles can also run from the **command line** (for example, to load a folder and save a CSV without opening the GUI). The switches are listed under *Command-Line Options* on the NirSoft page; check them for your version. For scripted, repeatable hashing on Windows, the tools below are the better choice.

> 🔒 **OPSEC:** Looking up a *hash* online doesn't upload the file. **Uploading** a file to VirusTotal or a similar service shares it with the service's paying customers, who may include the attacker. Never upload case files that might contain sensitive or personal data.

#### Built-in Windows alternatives (useful for scripts)

```powershell
# One file
Get-FileHash .\evidence.E01 -Algorithm SHA256
certutil -hashfile .\evidence.E01 SHA256

# A whole folder, recursively, to CSV
Get-ChildItem C:\Cases\LAB-002\evidence -Recurse -File |
  Get-FileHash -Algorithm SHA256 |
  Select-Object Hash, Path |
  Export-Csv C:\Cases\LAB-002\output\sha256.csv -NoTypeInformation
```

#### Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Download blocked or file deleted | The AV "HackTool/PUA" false positive: add an exclusion on the analysis VM only |
| Some files show errors or no hash | The files are locked by the OS (`pagefile.sys`, live registry hives). Collect them with forensic tools that read the raw disk (KAPE, Day 9) and hash the copies |
| Times look wrong | The VM isn't set to UTC, or you're comparing with a tool that shows local time |
| Hash differs from `Get-FileHash` | You hashed different files (check the full path) or a different algorithm column. Recheck carefully, because a real mismatch means one tool is wrong |

---

## Part 3: Hands-on labs

All the Linux labs run on **SIFT** (or any Linux with `hashdeep` and `ssdeep`). Log every step in your case notes, as on Day 1.

### Lab 1: Chain of custody for your Day 1 evidence (10 min)

```bash
git clone https://github.com/Mr-Phoenix07/DFIR.git ~/DFIR          # if you don't have this repo locally yet
cp ~/DFIR/templates/chain-of-custody-form.md ~/cases/LAB-001/notes/coc-EV-001-usb-sim.md
sha256sum ~/cases/LAB-001/evidence/usb-sim.img
md5sum    ~/cases/LAB-001/evidence/usb-sim.img
```

Fill in the form for `usb-sim.img` (evidence ID `LAB-001-EV-001`):

- A description ("32 MB FAT16 test image, label EVIDENCE").
- The collection time (the time you created it yesterday).
- Both hashes.
- A transfer log entry for moving it into `evidence/`.

The SHA-256 must match `notes/usb-sim.img.sha256` from Day 1. If it doesn't, that's an integrity failure: work out why.

### Lab 2: Baseline and audit an evidence set with hashdeep (20 min)

```bash
mkdir -p ~/cases/LAB-002/{evidence/docs,evidence/images,notes,output,ioc} && cd ~/cases/LAB-002

# 1. Build a small "evidence set"
printf 'Quarterly revenue: 4.2M\n'      > evidence/docs/finance-q3.txt
printf 'Project Falcon design notes\n'  > evidence/docs/falcon.txt
head -c 20000 /dev/zero | tr '\0' 'A'   > evidence/images/photo001.raw
printf 'meeting at noon\n'              > evidence/chat.log

# 2. Baseline (SHA-256, relative paths), then hash the baseline itself
hashdeep -c sha256 -r -l evidence > notes/baseline.hashdeep
cat notes/baseline.hashdeep
sha256sum notes/baseline.hashdeep | tee -a notes/case-notes.txt

# 3. Audit: nothing has changed yet
hashdeep -a -k notes/baseline.hashdeep -r -l evidence
```

Expected output: `hashdeep: Audit passed`

Now **tamper** with the evidence, as a careless colleague or a malicious insider might:

```bash
printf 'Quarterly revenue: 9.9M\n' > evidence/docs/finance-q3.txt       # modify
rm evidence/chat.log                                                   # delete
printf 'new file\n' > evidence/docs/planted.txt                        # add
mv evidence/docs/falcon.txt evidence/docs/falcon-renamed.txt           # rename / move

hashdeep -a -vv -k notes/baseline.hashdeep -r -l evidence
```

Expected output (the line order may vary; summary lines with a count of 0 are omitted here):

```
evidence/docs/planted.txt: No match
evidence/docs/falcon-renamed.txt: Moved from evidence/docs/falcon.txt
evidence/docs/finance-q3.txt: No match
evidence/chat.log: Known file not used
evidence/docs/finance-q3.txt: Known file not used
hashdeep: Audit failed
          Files matched: 1
            Files moved: 1
        New files found: 2
  Known files not found: 2
```

Read it like an examiner:

- **Moved:** same content, new name or path. Hashes ignore file names, so hashdeep recognises the file.
- **No match** for `finance-q3.txt` *and* **Known file not used** for its old hash: the file was **modified**.
- `planted.txt`: a **new** file. `chat.log`: **deleted**.

### Lab 3: Known-bad sweep and known-good filtering (10 min)

```bash
cd ~/cases/LAB-002

# A threat-intel report gives you two SHA-256 IOCs (hash values only, no file names)
printf '%s\n' \
  0f15384d18789b1ebf3043dc7b6bc27273c8576373fbeb6f3e15854b588141c0 \
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 > ioc/iocs.txt

# sha256deep needs "hash  name" lines, so add a placeholder name to each hash
sed 's/$/  ioc/' ioc/iocs.txt > ioc/iocs.sha256sum

# Positive match: which evidence files are known-bad?
sha256deep -r -l -w -m ioc/iocs.sha256sum evidence
```

Expected output:

```
evidence/docs/planted.txt matched ioc
```

(The first IOC is the SHA-256 of `new file\n`, the content of the planted file. The second is the hash of an **empty file**, `e3b0c442…b855`. That one is worth memorising, because you'll see it constantly.)

```bash
# Negative match: hide everything that's in the original (known-good) baseline
hashdeep -c sha256 -r -l -x -k notes/baseline.hashdeep evidence
```

Expected output: only the files that are new or changed since the baseline:

```
evidence/docs/finance-q3.txt
evidence/docs/planted.txt
```

That is exactly how NSRL filtering works on a real disk, at the scale of millions of files.

### Lab 4: Find similar documents with ssdeep (15 min)

```bash
mkdir -p ~/cases/LAB-002/fuzzy/samples && cd ~/cases/LAB-002/fuzzy
cat > make_samples.py <<'EOF'
import random
words = ("evidence analyst memory disk registry timeline network packet artifact volume "
         "sector cluster journal process thread handle token beacon payload loader config").split()
def doc(seed, n=3000):
    r = random.Random(seed)
    return " ".join(r.choice(words) for _ in range(n)) + "\n"
base = doc(1)
open("samples/report-v1.txt", "w").write(base)
v2 = base.replace("beacon payload", "BEACON PAYLOAD", 3)            # a few edits...
mid = len(v2) // 2
v2 = v2[:mid] + "\nNEW SECTION: exfiltration observed via HTTPS to 203.0.113.50\n" + v2[mid:]  # ...and an insertion
open("samples/report-v2.txt", "w").write(v2)
open("samples/unrelated.txt", "w").write(doc(99))
EOF
python3 make_samples.py

sha256sum samples/*          # three completely different SHA-256 values
ssdeep -l samples/* | tee known.ssdeep
ssdeep -l -p samples/*       # pretty matching
```

Expected output (the exact hashes may vary, but the score should be in the 90s):

```
samples/report-v1.txt matches samples/report-v2.txt (94)

samples/report-v2.txt matches samples/report-v1.txt (94)
```

`unrelated.txt` matches nothing, even though it's the same size and uses the same vocabulary.

```bash
cp samples/report-v1.txt samples/report-v1-copy.txt
ssdeep -l -g -d samples/*    # cluster view
```

Expected output: one cluster of 3 (`v1`, `v1-copy` and `v2`) and one cluster of 1 (`unrelated`).

**Think about it:** SHA-256 says `report-v1` and `report-v2` are simply *different*. ssdeep tells you `report-v2` is an **edited version** of `report-v1`. In a data-leak case, that's the difference between "no match found" and "the suspect had a modified copy of the confidential report".

### Lab 5: HashMyFiles cross-check on Windows (10 min)

1. Copy your `LAB-002\evidence` folder to the Windows VM at `C:\Cases\LAB-002\evidence` (or create a few test files there).
2. In HashMyFiles: **File → Add Folder** → `C:\Cases\LAB-002\evidence`, including sub-folders.
3. Compare the SHA-256 of `finance-q3.txt` with:
   ```powershell
   Get-FileHash C:\Cases\LAB-002\evidence\docs\finance-q3.txt -Algorithm SHA256
   ```
   Two independent tools, same result: that's tool validation.
4. Make a copy of any file with a different name, press **F5** (refresh), and watch *Mark Identical Hashes* colour the pair.
5. Export an **HTML report** of all items to `C:\Cases\LAB-002\output\hash-report.html`, then record the report's own SHA-256 in your notes.

---

## ✅ Knowledge check

1. You find a laptop running with a VeraCrypt volume mounted. What do you do before powering it off, and why?
2. List five things a chain-of-custody transfer entry should record.
3. Why is CRC32 unsuitable for proving evidence integrity?
4. MD5 collisions are practical. Does that mean an MD5-verified image can't be trusted? What's the best-practice answer?
5. An E01's embedded MD5 doesn't match the MD5 you computed of the `.E01` file. Is the evidence corrupt?
6. In a hashdeep audit, what does *"Moved from"* mean? And what does it mean when one file shows both *"No match"* and *"Known file not used"*?
7. What's the difference between `-m` and `-x` matching, and which one would you use with the NSRL?
8. Why can't ssdeep usefully compare a 2 KB file?
9. You receive the SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` as an "IOC". What's wrong with it?

<details>
<summary><b>Answers</b></summary>

1. Capture RAM, then acquire the *mounted* (decrypted) volume logically, or recover the keys. If you power it off, the volume locks, and without the password you may never get the data back.
2. Any five of: date/time (UTC), released by, received by (with signatures), purpose, from location, to location, seal intact, hash re-verified.
3. It's an error-detecting checksum, not a cryptographic hash. It's only 32 bits and trivial to forge deliberately.
4. The integrity claim relies on second pre-image resistance, which is still intact for MD5, so the image isn't automatically untrustworthy. Best practice is to also record SHA-256 so the question never arises.
5. Not necessarily. The embedded hash covers the *acquired media data*, while the file hash covers the *container* (headers, compression, metadata). Verify the image with `ewfverify` (Day 6) and compare that result with the embedded hash.
6. *Moved from*: identical content, now at a different path or name. *No match* plus *Known file not used* for the same path means the file's content was **modified**.
7. `-m` shows files that **match** the known set (known-bad hunting). `-x` shows files that **don't** match (filtering out known-good). Use `-x` with the NSRL.
8. CTPH needs enough data to create enough content-defined pieces. Under ~4 KB the signature is too short for a meaningful comparison.
9. It's the SHA-256 of an **empty file**. It would "match" every zero-byte file on the disk. Push back on the source and exclude it from your IOC sweep.

</details>

---

## 📚 Further reading

- NIST SP 800-86 §3.1 (data collection) and **NIST SP 800-88 Rev. 1** (media sanitisation, for final disposition)
- ISO/IEC 27037: identification, collection, acquisition and preservation of digital evidence
- SWGDE *Best Practices for Computer Forensic Acquisitions* and *Best Practices for Digital Evidence Collection* (https://www.swgde.org)
- Jesse Kornblum, *Identifying almost identical files using context triggered piecewise hashing* (DFRWS 2006): the original ssdeep paper
- NIST **National Software Reference Library (NSRL)**: https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl
- Stevens et al., *The first collision for full SHA-1* (SHAttered, 2017); Leurent & Peyrin, *SHA-1 is a Shambles* (2020)
- US Federal Rules of Evidence 902(13) and 902(14): certified records and hash-based authentication

---

## ⏭️ Tomorrow: Day 03

**Storage media, partitions (MBR/GPT), sectors, hex and file signatures**. Tools: **HxD**, **ImHex**, **TestDisk**.
We'll open a disk image in a hex editor, decode an MBR and a GPT header by hand, identify files by their magic bytes, and recover a deleted partition.

---

<sub>Part of the <a href="../README.md">DFIR Daily</a> series · <a href="../CURRICULUM.md">Full 60-day curriculum</a> · For educational and authorised use only.</sub>
